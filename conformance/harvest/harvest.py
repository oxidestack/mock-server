#!/usr/bin/env python3
"""Turns harvested category-B cases (target/harvest/*.jsonl, written by harvest.Recorder) into oracle scenarios.

  harvest.py [--out DIR]     writes DIR/<tranche>-<TestClass>.json (default tests/scenarios/upstream) and prints a
                             summary: distinct cases, converted, unconvertible (by reason). Default kinds:
                             deserialize, validate, jackson, match, serialize, export (the last two:
                             `ExpectationSerializer`/`HttpRequestAndHttpResponseSerializer.serialize` and
                             `ExpectationExportSerializer.serializeAsOpenApi`, each re-serialised by its advice with a
                             fresh, unmocked serializer — see `SerializeAdvice`/`ExportAdvice`)
  harvest.py --kinds template,openapi [--in target/harvest-b3]
                             B3 boundaries, each harvested by a
                             run of its own into <in>/<kind>/ (see pom.xml): writes only DIR/B3-<kind>-<TestClass>.json
                             for those kinds and leaves every other file alone (the B1/B2/B4 files are partly adapted
                             by hand after recording). Kinds helper, configured, forward and render read the template
                             run (KIND_SOURCES); never re-run --kinds template, whose run is not reproducible byte for
                             byte. Kind render writes its templates under
                             <files>/harvest/render (--files; default tests/files for the default --out, else
                             <out>/files) and removes only those its rewritten files referred to
  harvest.py ... --classes A,B
                             a narrowed run: converts only those simple test class names and replaces or
                             removes only the owned files whose `source` names one of them, with their render files;
                             without it every owned file of the kinds is replaced or removed
  harvest.py --kinds bodymatch [--in target/harvest-b4]
                             B4 boundaries, the same way: each
                             run into <in>/<kind>/, written only to DIR/B4-<kind>-<TestClass>.json
  harvest.py --kinds wasm    WASM runtime, body matcher and response shaping: one file per test class and
                             server configuration, DIR/B4-wasm-<TestClass>-<label>.json with the case's `properties`
  harvest.py --kinds handle  control-plane sequences through HttpState.handle: one case per test method
                             (its calls in order), one file per test class and server configuration,
                             DIR/B4-handle-<TestClass>-<label>.json (`default` when the file has no `properties`)

A rewritten file keeps what was added to its previous version by hand (step options such as `diverge`, document keys
such as `isolated`; see carry_over), and a hand-authored file (`source` not "harvested from …") is never replaced or
removed. `python3 test_harvest.py` checks both.

A kind lives in a module of its own under kinds/ (see Kind): a new kind adds a file there and edits nothing in this
one. B4 kinds and `har` already do; the template family, the other B3 kinds and the default mode are converted here.

Inventory §4.2: the inputs come from mockserver-core's tests, the expected output comes from the oracle
(`make record`), never from the Java assertions. One case = a reset plus the control-plane / data-plane steps that
put the same input through the server; cases are deduplicated by their steps across the whole harvest, and at most
PER_METHOD distinct cases are kept per upstream test method (concurrency and index stress tests otherwise contribute
thousands of cases that differ only in a counter).

The Maven runs (pom.xml) compile upstream/mockserver's tests, pinned to the oracle's commit, against the mockserver jars
of `mockserver.version`, whose default is oracle.env's `ORACLE_VERSION`: a re-pin moves it too, and
test_harvest.py fails while the two differ.
"""
import argparse
import collections
import glob
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))


def oracle_revision():
    """The upstream version and revision the cases are harvested from: mockserver-core's tests are compiled from
    `upstream/mockserver`, pinned to the oracle's commit, so a file's `source` names oracle.env's pin."""
    env = {}
    with open(os.path.join(ROOT, "oracle.env"), encoding="utf-8") as f:
        for line in f:
            key, sep, value = line.strip().partition("=")
            if sep and not key.startswith("#"):
                env[key] = value
    return f"{env['ORACLE_VERSION']} ({env['ORACLE_REVISION'][:9]})"


# Validator class -> the control-plane endpoint that validates its input the same way.
VALIDATOR_ENDPOINTS = {
    "JsonSchemaExpectationValidator": "/mockserver/expectation",
    "JsonSchemaRequestDefinitionValidator": "/mockserver/retrieve?type=REQUESTS",
    "JsonSchemaHttpRequestValidator": "/mockserver/retrieve?type=REQUESTS",
    "JsonSchemaVerificationValidator": "/mockserver/verify",
    "JsonSchemaVerificationSequenceValidator": "/mockserver/verifySequence",
    "JsonSchemaOpenAPIExpectationValidator": "/mockserver/openapi",
    "JsonSchemaExpectationIdValidator": "/mockserver/clear",
}

DESERIALIZER_ENDPOINTS = {
    "ExpectationSerializer.deserialize": "/mockserver/expectation",
    "ExpectationSerializer.deserializeArray": "/mockserver/expectation",
    "HttpRequestSerializer.deserialize": "/mockserver/retrieve?type=REQUESTS",
    "RequestDefinitionSerializer.deserialize": "/mockserver/retrieve?type=REQUESTS",
    "VerificationSerializer.deserialize": "/mockserver/verify",
    "VerificationSequenceSerializer.deserialize": "/mockserver/verifySequence",
    # sentinel: converted by combined_steps (import + REQUEST_RESPONSES), not a single PUT + echo.
    "HttpRequestAndHttpResponseSerializer.deserialize": "COMBINED",
    # Real, unmocked deserialize() calls in ConfigurationSerializerTest, PortBindingSerializerSchemaValidationTest,
    # SloCriteriaSerializerTest (the criteria direction only — deserializeVerdict has no endpoint of its own).
    "ConfigurationSerializer.deserialize": "/mockserver/configuration",
    "PortBindingSerializer.deserialize": "/mockserver/bind",
    "SloCriteriaSerializer.deserialize": "/mockserver/verifySLO",
    # sentinel: converted by loadscenario_steps (PUT /mockserver/loadScenario + GET .../<name> echo) — a plain
    # "PUT /mockserver/load" would be wrong, the real endpoint is /mockserver/loadScenario (src/load/mod.rs), and its
    # round trip needs a second step to read the stored scenario back (the PUT response is a status wrapper, not
    # the scenario echo the Java serializer test checks).
    "LoadScenarioSerializer.deserialize": "LOADSCENARIO",
}

PER_METHOD = 25

# Master's allocation and linear-time tests (HttpStateRetrieveAllocationTest, LogEntryRedactionSurfacesTest)
# push multi-megabyte bodies through the boundaries; at most this many bytes of steps (as JSON) make a case, so a
# scenario file stays reviewable (the largest case before them was 119 KB) and its lines stay within the regex checks of
# tests/oracle.rs.
MAX_CASE_BYTES = 128 * 1024

# serde_json, which reads the scenario files in tests/oracle.rs, refuses nesting deeper than 128 (its recursion limit);
# a scenario document adds 3 levels (document, steps, step) above a case's own values. Master's
# LogEntryRedactionSurfacesTest nests a body hundreds deep.
MAX_CASE_DEPTH = 128 - 3


def depth(value):
    """The nesting depth of a JSON value (a scalar is 0); iterative, since the values in question outnest Python's
    own recursion limit."""
    deepest, stack = 0, [(value, 0)]
    while stack:
        v, d = stack.pop()
        if isinstance(v, (dict, list)):
            deepest = max(deepest, d + 1)
            stack.extend((c, d + 1) for c in (v.values() if isinstance(v, dict) else v))
    return deepest

# Upstream's tests load some resources from the class path, so they reach the server as paths into this harvest's
# build directory, which the oracle container and other checkouts do not have. Each is copied into tests/files/harvest/
# (in every checkout, and mounted into the oracle by `make oracle`) and referred to as `{{files}}/harvest/<path>`.
TEST_CLASSES = re.compile(re.escape(os.path.join(HERE, "target", "test-classes")) + r"/([^\"\\\s`]+)")
HARVEST_FILES = os.path.join(ROOT, "tests", "files", "harvest")

# Two upstream tests (JsonSchemaOpenAPIExpectationValidatorTest, JsonSchemaRequestDefinitionValidatorTest) hardcode
# `specUrlOrPayload` literals that reach the real internet (offline rewrite): `example.com/spec.json` always 404s
# (any IO failure gets the same "Unable to read location" wrapper, so a refused local connection records the same
# golden text) and the raw.githubusercontent.com petstore example is a real, successful fetch (vendored instead as
# `tests/files/harvest/openapi_petstore_example.json`, copied from the pinned `upstream/mockserver` submodule —
# confirmed byte-identical to the live file). Rewritten so neither the harvest nor the recorded scenario ever touch
# the network; `{{deadhost}}` is this repo's placeholder for "an address that always refuses" (a
# fixed port like the repo's old `localhost:18999` convention is not safe with parallel worktrees, see
# `tests/scenarios/forward_connect_refused_log.json` and `tests/oracle.rs`'s `Target.deadhost`).
OFFLINE_SPEC_REWRITES = {
    "https://example.com/spec.json": "https://{{deadhost}}/spec.json",
    "https://raw.githubusercontent.com/mock-server/mockserver-monorepo/master/mockserver/mockserver-integration-testing/src/main/resources/org/mockserver/openapi/openapi_petstore_example.json": "{{files}}/harvest/openapi_petstore_example.json",
}

TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
FIELD_VALUE = re.compile(r"[\t\x20-\x7e]*")

RETRIEVE_ACTIVE = "/mockserver/retrieve?type=ACTIVE_EXPECTATIONS&format=JSON"

# Request fields that cannot be reproduced by a plain HTTP/1.1 client on loopback.
NOT_ON_THE_WIRE = ("socketAddress", "clientCertificateChain", "localAddress", "remoteAddress")


def tranche(test_class):
    """B1..B4 by package, following inventory §4.1."""
    pkg = test_class.rsplit(".", 1)[0].replace("org.mockserver.", "")
    name = test_class.rsplit(".", 1)[1]
    if pkg.startswith(("serialization.java", "serialization.curl", "serialization.har", "serialization.code", "templates", "openapi")):
        return "B3"
    if pkg.startswith(("serialization", "validator")):
        return "B2"
    b4_words = ("Llm", "Grpc", "GraphQL", "Jwt", "JsonRpc", "Wasm", "Scim", "Oidc", "Saml", "Pact", "Wsdl", "Crud", "Breakpoint",
                "Drift", "Dns", "Mcp", "Chaos", "Load", "RateLimit", "Fallback", "Sse", "Cassette", "Scenario", "A2a", "Mqtt",
                "Kafka", "AsyncApi", "Semantic", "Fuzzy", "Namespace")
    if pkg.startswith(("matchers", "mock", "log", "verify", "codec", "cors", "responseheaders", "url")):
        if any(w in name for w in b4_words) or re.match(r"mock\.(pact|wsdl|crud|breakpoint|drift|dns|mcp|diff|audit)", pkg):
            return "B4"
        return "B1"
    return "B4"


def reset():
    return {"method": "PUT", "path": "/mockserver/reset"}


# `PUT /mockserver/bind` really opens listeners. The upstream tests name fixed ports (`1`-`5`, `1090`), which
# with parallel worktrees would take well-known ports on the machine (localhost:1 is a dead host other scenarios rely
# on). Every non-zero port of a bind body becomes `{{bindport:N}}`; `tests/oracle.rs` binds a port of its own in place
# of it (outside the ephemeral range) and normalises the answer back to `N`, so the golden still shows `N`.
BIND_PORTS = re.compile(r'("ports"\s*:\s*\[)([^\]]*)(\])')


def bind_ports(body):
    def ports(m):
        return m.group(1) + re.sub(r"\b[1-9][0-9]*\b", lambda n: "{{bindport:" + n.group(0) + "}}", m.group(2)) + m.group(3)
    return BIND_PORTS.sub(ports, body)


def control(path, body, note):
    if path == "/mockserver/bind" and isinstance(body, str):
        body = bind_ports(body)
    return {"method": "PUT", "path": path, "body": body, "note": note}


def request_steps(actual):
    """The data-plane request for a harvested request JSON, or (None, reason)."""
    for field in NOT_ON_THE_WIRE:
        if field in actual:
            return None, "request field " + field
    if actual.get("secure") or actual.get("keepAlive") is False or actual.get("protocol", "HTTP_1_1") != "HTTP_1_1":
        return None, "secure/keepAlive/protocol"
    if isinstance(actual.get("path"), dict) or isinstance(actual.get("method"), dict):
        return None, "matcher-shaped request"
    path = actual.get("path", "/")
    method = actual.get("method", "GET")
    if not re.fullmatch(r"[A-Za-z]+", method):
        return None, "method not a token"
    query = []
    for name, values in multi(actual.get("queryStringParameters")):
        for v in values:
            if not isinstance(v, str):
                return None, "matcher-shaped query"
            query.append((name, v))
    target = urllib.parse.quote(path, safe="/%:@!$&'()*+,;=-._~")
    if query:
        target += "?" + urllib.parse.urlencode(query)
    headers = collections.OrderedDict()
    for name, values in multi(actual.get("headers")):
        if not all(isinstance(v, str) for v in values):
            return None, "matcher-shaped header"
        if not TOKEN.fullmatch(name) or not all(FIELD_VALUE.fullmatch(v) for v in values):
            return None, "header not valid on the wire"
        if name.lower() in ("content-length", "transfer-encoding"):
            continue
        headers[name] = values if len(values) > 1 else values[0]
    cookies = [(n, vs[0]) for n, vs in multi(actual.get("cookies"))]
    if cookies:
        if not all(isinstance(v, str) for _, v in cookies):
            return None, "matcher-shaped cookie"
        if not all(FIELD_VALUE.fullmatch(f"{n}={v}") for n, v in cookies):
            return None, "cookie not valid on the wire"
        headers["Cookie"] = "; ".join(f"{n}={v}" for n, v in cookies)
    step = {"method": method, "path": target}
    if headers:
        step["headers"] = headers
    body = actual.get("body")
    if body is not None:
        if isinstance(body, str):
            step["body"] = body
        elif isinstance(body, dict):
            if body.get("not"):
                return None, "negated body"
            t = body.get("type")
            if t == "BINARY":
                step["bodyBase64"] = body.get("base64Bytes", "")
            elif t in ("STRING", "XML", "JSON", "REGEX", None) and any(k in body for k in ("string", "xml", "json")):
                value = body.get("string", body.get("xml", body.get("json")))
                step["body"] = value if isinstance(value, str) else json.dumps(value)
                if body.get("contentType") and not any(h.lower() == "content-type" for h in headers):
                    step.setdefault("headers", {})["Content-Type"] = body["contentType"]
            elif t == "PARAMETERS":
                pairs = [(n, v) for n, vs in multi(body.get("parameters")) for v in vs]
                step["body"] = urllib.parse.urlencode(pairs)
                if not any(h.lower() == "content-type" for h in headers):
                    step.setdefault("headers", {})["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                return None, "body type " + str(t)
        else:
            step["body"] = json.dumps(body)
    return step, None


def multi(value):
    """A MockServer multi-value field (array of {name, values} or map form) as (name, [values])."""
    if not value:
        return []
    if isinstance(value, dict):
        return [(k, v if isinstance(v, list) else [v]) for k, v in value.items()]
    out = []
    for entry in value:
        name = entry.get("name")
        values = entry.get("values", [entry.get("value")])
        out.append((name if isinstance(name, str) else json.dumps(name), values if isinstance(values, list) else [values]))
    return out


def adapt_relative_path(matcher, actual):
    """Harvested requests often use `somePath`; HTTP needs `/somePath`. Adapt when both are plain literals."""
    mp, ap = matcher.get("path"), actual.get("path")
    if ap is None or (isinstance(ap, str) and ap.startswith("/")):
        return True
    if not isinstance(ap, str):
        return False
    if mp is None:
        actual["path"] = "/" + ap
        return True
    if isinstance(mp, str) and not mp.startswith("/") and re.fullmatch(r"[A-Za-z0-9_\-]+", mp):
        matcher["path"] = "/" + mp
        actual["path"] = "/" + ap
        return True
    return False


def convert_match(case):
    if "unserialisable" in case or case.get("actual") is None:
        return None, "unserialisable"
    try:
        matcher, actual = json.loads(case["matcher"]), json.loads(case["actual"])
    except (ValueError, TypeError):
        return None, "unserialisable"
    if not isinstance(matcher, dict) or not isinstance(actual, dict):
        return None, "unserialisable"
    if case.get("controlPlaneMatcher"):
        # HttpState.retrieve: the filter is the matcher, the stored expectation's request is matched against it.
        return [
            control("/mockserver/expectation", {"httpRequest": actual, "httpResponse": {"statusCode": 200}}, "store"),
            control(RETRIEVE_ACTIVE, matcher, "filter"),
        ], None
    if not adapt_relative_path(matcher, actual):
        return None, "relative path"
    step, reason = request_steps(actual)
    if step is None:
        return None, reason
    step["note"] = "request"
    return [
        control("/mockserver/expectation", {"httpRequest": matcher, "httpResponse": {"statusCode": 200, "body": "matched"}}, "matcher"),
        step,
    ], None


def jackson_kind(type_name):
    """What the JSON of a model / DTO class is on the wire, by the class's simple name."""
    simple = type_name.rsplit(".", 1)[-1].removesuffix("DTO")
    if simple in ("Expectation",):
        return "expectation"
    if simple in ("OpenAPIExpectation",):
        return "openapi"
    if simple in ("HttpRequest", "RequestDefinition", "OpenAPIDefinition"):
        return "request"
    if simple == "HttpResponse":
        return "response"
    if simple.endswith("Body") or simple == "Body":
        return "body"
    # Cookies/Headers/Parameters (de)serializer tests call ObjectMapperFactory.createObjectMapper()
    # directly, the same "jackson" boundary as the body-DTO family above — just wire fields of their own.
    if simple == "Cookies":
        return "cookies"
    if simple == "Headers":
        return "headers"
    if simple == "Parameters":
        return "parameters"
    # VerificationTimes(DTO) is the "times" field of a verify payload; TimeToLive(DTO) is the
    # "timeToLive" field of an expectation. Both (de)serializer tests use the same direct ObjectMapper boundary.
    if simple == "VerificationTimes":
        return "times"
    if simple == "TimeToLive":
        return "timeToLive"
    # `Times` (org.mockserver.matchers.Times, distinct from VerificationTimes above) is an
    # expectation's own `times` field — how many more times it can match, not a verify-payload count.
    # `HttpResponseModifier` is the `responseModifier` field of `httpOverrideForwardedRequest` (and the
    # top-level `responseModifier` definition the DTO test round-trips directly, same wire shape).
    if simple == "Times":
        return "expectationTimes"
    if simple == "HttpResponseModifier":
        return "responseModifier"
    # GrpcStreamResponse(DTO) and HttpWebSocketResponse(DTO) are each their own top-level field on an
    # expectation (src/canonical.rs handles both already — grpcStreamResponse by plain alphabetical-sort, the
    # webSocketResponse's nested matchers/text-matcher with their own canonical shape).
    if simple == "GrpcStreamResponse":
        return "grpcStreamResponse"
    if simple == "HttpWebSocketResponse":
        return "httpWebSocketResponse"
    return None


def convert_jackson(case):
    steps, reason = _convert_jackson(case)
    for step, following in zip(steps or [], (steps or [])[1:]):
        # A finite timeToLive (1 SECONDS in upstream's tests) can run out between the input and its echo on a loaded
        # host: both go out in one write.
        body = step.get("body")
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except ValueError:
                body = None
        ttl = body.get("timeToLive") if isinstance(body, dict) else None
        if step["path"] == "/mockserver/expectation" and isinstance(ttl, dict) and "timeUnit" in ttl and following.get("note") == "echo":
            step["pipelinePut"] = True
    return steps, reason


def _convert_jackson(case):
    kind = jackson_kind(case["type"])
    if kind is None:
        return None, "no endpoint for " + case["type"].rsplit(".", 1)[-1]
    text = case["input"]
    try:
        value = json.loads(text)
    except ValueError:
        value = None
    if kind == "expectation":
        return [control("/mockserver/expectation", text, "input"), control(RETRIEVE_ACTIVE, "", "echo")], None
    if kind == "openapi":
        return [control("/mockserver/openapi", text, "input"), control(RETRIEVE_ACTIVE, "", "echo")], None
    if value is None:
        return None, "not JSON"
    if kind == "times":
        # No echo step: the value is exercised by /mockserver/verify itself — an unparsed/misparsed `times` changes
        # the pass/fail outcome and the `times.describe()` text in the failure message (src/verify.rs), which is
        # enough to catch a serialization divergence without a retrieve round trip (verify has no stored state).
        return [control("/mockserver/verify", {"httpRequest": {"path": "/harvested"}, "times": value}, "input")], None
    if kind == "timeToLive":
        wrapped = {"httpRequest": {"path": "/harvested"}, "httpResponse": {"statusCode": 200}, "timeToLive": value}
        return [control("/mockserver/expectation", wrapped, "input"), control(RETRIEVE_ACTIVE, "", "echo")], None
    if kind == "expectationTimes":
        wrapped = {"httpRequest": {"path": "/harvested"}, "httpResponse": {"statusCode": 200}, "times": value}
        return [control("/mockserver/expectation", wrapped, "input"), control(RETRIEVE_ACTIVE, "", "echo")], None
    if kind == "responseModifier":
        wrapped = {"httpRequest": {"path": "/harvested"}, "httpOverrideForwardedRequest": {"responseModifier": value}}
        return [control("/mockserver/expectation", wrapped, "input"), control(RETRIEVE_ACTIVE, "", "echo")], None
    if kind == "grpcStreamResponse":
        wrapped = {"httpRequest": {"path": "/harvested"}, "grpcStreamResponse": value}
        return [control("/mockserver/expectation", wrapped, "input"), control(RETRIEVE_ACTIVE, "", "echo")], None
    if kind == "httpWebSocketResponse":
        wrapped = {"httpRequest": {"path": "/harvested"}, "httpWebSocketResponse": value}
        return [control("/mockserver/expectation", wrapped, "input"), control(RETRIEVE_ACTIVE, "", "echo")], None
    wrapped = {
        "request": {"httpRequest": value, "httpResponse": {"statusCode": 200}},
        "response": {"httpRequest": {"path": "/harvested"}, "httpResponse": value},
        "body": {"httpRequest": {"path": "/harvested", "body": value}, "httpResponse": {"statusCode": 200}},
        "cookies": {"httpRequest": {"path": "/harvested", "cookies": value}, "httpResponse": {"statusCode": 200}},
        "headers": {"httpRequest": {"path": "/harvested", "headers": value}, "httpResponse": {"statusCode": 200}},
        "parameters": {"httpRequest": {"path": "/harvested", "queryStringParameters": value}, "httpResponse": {"statusCode": 200}},
    }[kind]
    steps = [control("/mockserver/expectation", wrapped, "input"), control(RETRIEVE_ACTIVE, "", "echo")]
    if kind == "response" and delay_millis(value) < STEP_TIMEOUT_MILLIS:
        steps.append({"method": "GET", "path": "/harvested", "note": "response"})
    return steps, None


# tests/oracle.rs gives up on a step's answer after 10 s (`maxMillis`'s default). Master's tests serialise
# responses delayed by 30 s or a minute; their data-plane step could only record that timeout, and the abandoned
# request kept the replay server (and the shared oracle, whose late log entries land in the next recorded file) busy
# past the file's last step. Such a response is echoed, not requested.
STEP_TIMEOUT_MILLIS = 10_000
TIME_UNIT_MILLIS = {"NANOSECONDS": 1e-6, "MICROSECONDS": 1e-3, "MILLISECONDS": 1, "SECONDS": 1000, "MINUTES": 60_000,
                    "HOURS": 3_600_000, "DAYS": 86_400_000}


def delay_millis(response):
    """The fixed `delay` of a response DTO in milliseconds (0 when it has none or it is not a plain delay)."""
    delay = response.get("delay") if isinstance(response, dict) else None
    if not isinstance(delay, dict) or not isinstance(delay.get("value"), (int, float)):
        return 0
    return delay["value"] * TIME_UNIT_MILLIS.get(str(delay.get("timeUnit", "MILLISECONDS")), 1)


# Template engine class -> httpResponseTemplate.templateType.
TEMPLATE_TYPES = {"VelocityTemplateEngine": "VELOCITY", "MustacheTemplateEngine": "MUSTACHE", "JavaScriptTemplateEngine": "JAVASCRIPT"}

# Velocity names each template it parses `t<N>`, N counting every template that server parsed before, and a failing template's answer quotes the name (`... at t13[line 1, column 5]`): on the shared replay server it
# depends on the scenarios that ran first. A Velocity request step whose case threw in the Java run gets this mask
# (see template_name_mask); a failure only the server sees (case 26bfaf980193: no path groups without a path matcher)
# is masked by hand, and carry_over keeps that.
TEMPLATE_NAME_MASK = {"regex": " at t\\d+\\[line ", "replace": " at t<n>[line ",
                      "reason": "the Velocity engine names each template by how many it rendered before: on a shared server that counts earlier scenarios' templates too"}


def template_name_mask(step, case, template_type):
    """`step` (a template case's request) with TEMPLATE_NAME_MASK when its answer names a Velocity template: the
    engine is Velocity and the template threw under the Java test, so the oracle answers with its failure."""
    if template_type == "VELOCITY" and "thrown" in case:
        step.setdefault("mask", []).append(dict(TEMPLATE_NAME_MASK))
    return step


# The kinds harvested per B3 boundary, each written to B3-<kind>-<Class>.json.
# Kinds converted in this file; kinds/*.py add theirs (see Kind).
B3_KINDS = ("template", "openapi", "code", "example", "validation", "expression", "helper", "configured", "forward", "render")

# The kinds harvested per B4 boundary, each written to B4-<kind>-<Class>.json: all in kinds/*.py.
B4_KINDS = ()

# Where a kind's cases come from when it is not <in>/<kind>/<kind>.jsonl: (run directory, jsonl name). The template
# run (pom.xml) records executeTemplate calls once; `template`, `configured` and `forward` each convert their share.
KIND_SOURCES = {"configured": ("template", "template"), "forward": ("template", "template"),
                "helper": ("template", "helper"), "render": ("template", "render")}

class Kind:
    """A harvest kind converted by a module of its own: `kinds/<name>.py` defines `KINDS = [Kind(…), …]` and is found
    by its file name, so that a new kind edits no shared list (a kind is found by its file name). A module imports the
    helpers it shares with this file with `from harvest import …`.

      name        the `--kinds` name; files are <tranche>-<name>-<TestClass>[…].json
      tranche     "B3" or "B4" (B3 and B4 kinds are harvested by separate runs); "B1"/"B2" for a kind of those tranches,
                  run and converted like a B4 kind (`--in` names its run)
      convert     case -> (steps, None) or (None, reason)
      source      (run directory, jsonl name) when not (<name>, <name>)
      group       jsonl lines -> cases (e.g. one case per test method), when a case is not one line
      properties  case -> the `mockserver.*` properties its file's server starts with, or None
      per_test    unconvertible cases are counted per test method (a grouped case's input is the method's calls)
      own_file    a case without properties goes to <tranche>-<name>-<TestClass><own_file>.json, so that no file name
                  is a prefix of another (MOCK_SERVER_SCENARIO); None: <tranche>-<name>-<TestClass>.json
    """

    def __init__(self, name, tranche, convert, source=None, group=None, properties=None, per_test=False, own_file=None):
        self.name, self.tranche, self.convert = name, tranche, convert
        self.source, self.group, self.properties, self.per_test, self.own_file = source, group, properties, per_test, own_file


KINDS = {}


def load_kinds():
    """Registers every kinds/*.py module's KINDS (files starting with `_` are helpers, not kinds)."""
    global B3_KINDS, B4_KINDS
    sys.modules.setdefault("harvest", sys.modules[__name__])
    for path in sorted(glob.glob(os.path.join(HERE, "kinds", "*.py"))):
        name = os.path.splitext(os.path.basename(path))[0]
        if name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location("harvest_kinds." + name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for kind in module.KINDS:
            assert kind.name not in KINDS and kind.name not in B3_KINDS + B4_KINDS, "kind registered twice: " + kind.name
            KINDS[kind.name] = kind
            if kind.tranche == "B3":
                B3_KINDS += (kind.name,)
            else:
                B4_KINDS += (kind.name,)
            if kind.source:
                KIND_SOURCES[kind.name] = kind.source

# Template-related Configuration getters (Recorder.TEMPLATE_CONFIGURATION) are `mockserver.<getter>` properties.
TEMPLATE_PROPERTIES = ("javascriptDisallowedClasses", "javascriptAllowedClasses", "javascriptDisallowedText",
                       "javascriptTemplateExecutionTimeout", "velocityDisallowClassLoading", "velocityDisallowedText",
                       "mustacheDisallowedText", "templateFakerSeed")

# Expectation code serialisers -> retrieve `format`.
CODE_FORMATS = {"ExpectationToJavaSerializer": "JAVA", "ExpectationToJavaScriptSerializer": "JAVASCRIPT",
                "ExpectationToPythonSerializer": "PYTHON", "ExpectationToGoSerializer": "GO", "ExpectationToCSharpSerializer": "CSHARP",
                "ExpectationToRubySerializer": "RUBY", "ExpectationToRustSerializer": "RUST", "ExpectationToPhpSerializer": "PHP"}


def java_fragment_expectation(serializer, model):
    """A `*ToJavaSerializer` fragment lifted into the smallest expectation that holds it (its Java code is part of
    that expectation's `format=JAVA`), or None."""
    name = serializer.removesuffix("ToJavaSerializer")
    request = {"path": "/harvested"}
    lifts = {
        "HttpRequest": lambda m: {"httpRequest": m, "httpResponse": {"statusCode": 200}},
        "HttpResponse": lambda m: {"httpRequest": request, "httpResponse": m},
        "HttpForward": lambda m: {"httpRequest": request, "httpForward": m},
        "HttpError": lambda m: {"httpRequest": request, "httpError": m},
        "HttpClassCallback": lambda m: {"httpRequest": request, "httpResponseClassCallback": m},
        "HttpOverrideForwardedRequest": lambda m: {"httpRequest": request, "httpOverrideForwardedRequest": m},
        "HttpResponseModifier": lambda m: {"httpRequest": request, "httpOverrideForwardedRequest": {"responseModifier": m}},
        "HttpTemplate": lambda m: {"httpRequest": request, "httpResponseTemplate": m},
        "Delay": lambda m: {"httpRequest": request, "httpResponse": {"statusCode": 200, "delay": m}},
        "ConnectionOptions": lambda m: {"httpRequest": request, "httpResponse": {"statusCode": 200, "connectionOptions": m}},
        "Times": lambda m: {"httpRequest": request, "httpResponse": {"statusCode": 200}, "times": m},
        "TimeToLive": lambda m: {"httpRequest": request, "httpResponse": {"statusCode": 200}, "timeToLive": m},
        "SocketAddress": lambda m: {"httpRequest": dict(request, socketAddress=m), "httpResponse": {"statusCode": 200}},
        "Header": lambda m: {"httpRequest": dict(request, headers=m if isinstance(m, list) else [m]), "httpResponse": {"statusCode": 200}},
        "Cookie": lambda m: {"httpRequest": dict(request, cookies=m if isinstance(m, list) else [m]), "httpResponse": {"statusCode": 200}},
        "Parameter": lambda m: {"httpRequest": dict(request, queryStringParameters=m if isinstance(m, list) else [m]), "httpResponse": {"statusCode": 200}},
        "NottableString": lambda m: {"httpRequest": {"path": m}, "httpResponse": {"statusCode": 200}},
    }
    lift = lifts.get(name)
    return None if lift is None or model is None else lift(model)


def convert_code(case):
    """Retrieve formats: the expectation (or fragment) stored, then `retrieve?type=ACTIVE_EXPECTATIONS&format=…`;
    a curl case is its request sent, then `retrieve?type=REQUESTS&format=CURL`."""
    if "unserialisable" in case:
        return None, "unserialisable"
    serializer = case["serializer"]
    model = json.loads(case["model"]) if case.get("model") is not None else None
    if serializer == "HttpRequestToCurlSerializer":
        if not isinstance(model, dict):
            return None, "curl of " + str(case.get("modelType"))
        # every request on the wire carries a Host header, which toCurl prefers to the remote address
        step, reason = request_steps(model)
        if step is None:
            return None, reason
        step["note"] = "request"
        return [step, control("/mockserver/retrieve?type=REQUESTS&format=CURL", "", "curl")], None
    if serializer in CODE_FORMATS:
        expectations = model if isinstance(model, list) else [model] if model is not None else []
        steps = [control("/mockserver/expectation", expectations, "expectations")] if expectations else []
        return steps + [control(f"/mockserver/retrieve?type=ACTIVE_EXPECTATIONS&format={CODE_FORMATS[serializer]}", "", "code")], None
    expectation = java_fragment_expectation(serializer, model)
    if expectation is None:
        return None, f"{serializer} of {case.get('modelType')}"
    return [control("/mockserver/expectation", expectation, "fragment"),
            control("/mockserver/retrieve?type=ACTIVE_EXPECTATIONS&format=JAVA", "", "code")], None

CLASS_PATH_RESOURCE = re.compile(r"[\w./-]+\.(json|yaml|yml)")


def convert_openapi(case):
    """`OpenAPIConverter.buildExpectations(spec, operationsAndResponses[, contextPathPrefix])`: `PUT /mockserver/openapi`,
    then the expectations it created."""
    if "unserialisable" in case:
        return None, "unserialisable"
    if case.get("generateRealisticExampleValues"):
        return None, "generateRealisticExampleValues"
    spec = case["specUrlOrPayload"]
    if spec and CLASS_PATH_RESOURCE.fullmatch(spec) and os.path.exists(os.path.join(HERE, "target", "test-classes", spec)):
        # a class-path resource of the test module: the oracle's class path does not have it, so it becomes a file
        spec = os.path.join(HERE, "target", "test-classes", spec)
    body = {"specUrlOrPayload": spec}
    if case.get("operationsAndResponses") is not None:
        body["operationsAndResponses"] = case["operationsAndResponses"]
    if case.get("contextPathPrefix") is not None:
        body["contextPathPrefix"] = case["contextPathPrefix"]
    return [control("/mockserver/openapi", body, "openapi"), control(RETRIEVE_ACTIVE, "", "expectations")], None


def mentions(value, keys):
    """True when a JSON value holds any of `keys` as an object key, at any depth."""
    if isinstance(value, dict):
        return any(k in value for k in keys) or any(mentions(v, keys) for v in value.values())
    if isinstance(value, list):
        return any(mentions(v, keys) for v in value)
    return False


def harvested_spec(case, operation):
    """A minimal OpenAPI document around a harvested schema: `operation` on `/harvested`, the definitions as components."""
    spec = {"openapi": "3.1.0" if case.get("specVersion") == "V31" else "3.0.3", "info": {"title": "harvested", "version": "1"},
            "paths": {"/harvested": operation}}
    if case.get("definitions"):
        spec["components"] = {"schemas": case["definitions"]}
    return spec


def convert_example(case):
    """`ExampleBuilder.fromSchema(schema, definitions, options, direction, configuration)`: the schema as the only
    response of a minimal spec (`PUT /mockserver/openapi`, then the operation on the data plane; generation options
    under `operationsAndResponses.__generationOptions__`), or, for the REQUEST direction, as its request body
    (`PUT /mockserver/loadScenario/generateFromOpenAPI`). `JsonSchemaResponseSynthesizer.synthesizeResponse(schema)`:
    an `httpResponse.generateFromSchema`."""
    if "unserialisable" in case:
        return None, "unserialisable"
    if case["boundary"].startswith("JsonSchemaResponseSynthesizer"):
        if case.get("jsonSchema") is None:
            return None, "no schema"
        expectation = {"httpRequest": {"path": "/harvested"}, "httpResponse": {"statusCode": 200, "generateFromSchema": case["jsonSchema"]}}
        return [control("/mockserver/expectation", expectation, "expectation"), {"method": "GET", "path": "/harvested", "note": "response"}], None
    schema = case.get("schema")
    if schema is None:
        return None, "no schema"
    options = dict(case.get("generationOptions") or {})
    if case.get("generateRealisticExampleValues") and "realisticValues" not in options:
        # the configuration default, made explicit for this run (GenerationOptions.fromOperationsMap)
        options["realisticValues"] = True
    direction = case.get("direction")
    if direction == "REQUEST":
        if options:
            return None, "REQUEST direction with generation options"
        operation = {"post": {"operationId": "harvested", "requestBody": {"content": {"application/json": {"schema": schema}}},
                              "responses": {"200": {"description": "ok"}}}}
        body = {"name": "harvested", "specUrlOrPayload": harvested_spec(case, operation)}
        return [control("/mockserver/loadScenario/generateFromOpenAPI", body, "load scenario")], None
    if direction == "UNSPECIFIED" and mentions([schema, case.get("definitions")], ("readOnly", "writeOnly")):
        return None, "UNSPECIFIED direction with readOnly/writeOnly"
    content_type = "application/xml" if case["test"].startswith("org.mockserver.openapi.examples.XmlExampleSerializerTest#") else "application/json"
    operation = {"get": {"operationId": "harvested",
                         "responses": {"200": {"description": "ok", "content": {content_type: {"schema": schema}}}}}}
    body = {"specUrlOrPayload": harvested_spec(case, operation)}
    if options:
        # openAPIExpectation.json requires a `statusCode` in every object value; GenerationOptions ignores it
        body["operationsAndResponses"] = {"harvested": "200", "__generationOptions__": dict(options, statusCode="200")}
    return [control("/mockserver/openapi", body, "openapi"), {"method": "GET", "path": "/harvested", "note": "example"}], None


def spec_source(spec):
    """A spec that names a class-path resource of the test module becomes a file (the oracle's class path lacks it)."""
    if spec and CLASS_PATH_RESOURCE.fullmatch(spec) and os.path.exists(os.path.join(HERE, "target", "test-classes", spec)):
        return os.path.join(HERE, "target", "test-classes", spec)
    return spec


TRAFFIC_VALIDATE = "/mockserver/trafficValidate"


def traffic_steps(pairs):
    """Each (request JSON, response JSON or None) pair as recorded traffic: an expectation answering the request once
    with the response (none for a None response, so the server's 404 is recorded), then the request itself."""
    steps = []
    for request, response in pairs:
        actual = json.loads(request)
        if isinstance(actual.get("path"), str) and not actual["path"].startswith("/"):
            actual["path"] = "/" + actual["path"]
        step, reason = request_steps(actual)
        if step is None:
            return None, reason
        if response is not None:
            matcher = {"method": actual.get("method", "GET"), "path": actual.get("path", "/")}
            steps.append(control("/mockserver/expectation", {"httpRequest": matcher, "httpResponse": json.loads(response),
                                                             "times": {"remainingTimes": 1}}, "traffic"))
        step["note"] = "request"
        steps.append(step)
    return steps, None


def convert_validation(case):
    """`OpenAPIRequestValidator.validate`, `OpenAPIResponseValidator.validate` and `OpenApiTrafficValidator.validate`:
    the traffic they validate recorded on the server, then `PUT /mockserver/trafficValidate` with the spec (its report
    carries each pair's request and response errors)."""
    if "unserialisable" in case:
        return None, "unserialisable"
    boundary = case["boundary"]
    if boundary.startswith("OpenAPIRequestValidator"):
        if case.get("request") is None:
            return None, "no request"
        pairs = [(case["request"], None)]
    elif boundary.startswith("OpenAPIResponseValidator"):
        if case.get("response") is None:
            return None, "no response"
        if case.get("operationSection") != "paths":
            # the traffic validator maps requests onto `paths` only
            return None, "operation not under paths"
        path = re.sub(r"\{[^}]+}", "1", case["operationPath"])
        pairs = [(json.dumps({"method": case["operationMethod"], "path": path}), case["response"])]
    else:
        pairs = [(p["request"], p["response"]) for p in case["pairs"]]
        if any(r is None for r, _ in pairs):
            return None, "pair without a request"
    steps, reason = traffic_steps(pairs)
    if steps is None:
        return None, reason
    return steps + [control(TRAFFIC_VALIDATE, {"specUrlOrPayload": spec_source(case["specUrlOrPayload"])}, "trafficValidate")], None


ABSOLUTE_URL = re.compile(r"https?://[^/\"\\\s]+")


def convert_expression(case):
    """`OpenApiRuntimeExpressionResolver.resolve(afterAction, triggering)`: an expectation answering the triggering
    request once with the after-action as a webhook, the triggering request, then the requests the server received
    (the webhook among them). Adapted so the webhook reaches the server itself: every absolute URL in either request
    becomes `http://{{host}}`, the after-action's `Host` is `{{host}}`, and a secure triggering request is sent plain."""
    if "unserialisable" in case or case.get("afterAction") is None or case.get("triggering") is None:
        return None, "no after-action or triggering request"
    after = json.loads(ABSOLUTE_URL.sub("http://{{host}}", case["afterAction"]))
    trigger = json.loads(ABSOLUTE_URL.sub("http://{{host}}", case["triggering"]))
    trigger.pop("secure", None)
    trigger.pop("pathParameters", None)
    trigger.setdefault("path", "/")
    headers = [(n, vs) for n, vs in multi(after.get("headers")) if n.lower() != "host"]
    after["headers"] = [{"name": "Host", "values": ["{{host}}"]}] + [{"name": n, "values": vs} for n, vs in headers]
    step, reason = request_steps(trigger)
    if step is None:
        return None, reason
    step["note"] = "trigger"
    expectation = {"httpRequest": {"method": trigger.get("method", "GET"), "path": trigger["path"]},
                   "httpResponse": {"statusCode": 200, "body": "triggered"}, "times": {"remainingTimes": 1},
                   "afterActions": [{"httpRequest": after}]}
    received = control("/mockserver/retrieve?type=REQUESTS&format=JSON", "", "received")
    # the bodies carry {{host}}, whose port has a different number of digits in the oracle
    received["mask"] = [{"regex": "\"content-length\" : \\[ \"\\d+\" \\]", "replace": "\"content-length\" : [ \"<varies with the port>\" ]"}]
    return [control("/mockserver/expectation", expectation, "expectation"), step, {"sleepMillis": 500}, received], None


def configured(case):
    """True for a Velocity/Mustache case recorded from an engine built with a non-default Configuration (converted by
    kind `configured`, in a file whose `"properties"` start the server with that configuration). The oracle has no
    GraalJS: every JavaScript template fails before the engine reads its configuration, so those stay in `template`."""
    return bool(case.get("configuration")) and TEMPLATE_TYPES.get(case.get("engine")) != "JAVASCRIPT"


# Simple `Configuration` getters the recorder reads that are no `mockserver.*` property: master's
# `serverTLSContextGeneration()` counts configuration changes in the JVM, so it differs between any two tests and split
# one class's cases into a file per test.
NOT_PROPERTIES = {"serverTLSContextGeneration"}


def case_properties(case, kind):
    """The `mockserver.*` properties a case's file must be started with, or None."""
    if kind in KINDS:
        props = KINDS[kind].properties(case) if KINDS[kind].properties else None
        props = {name: value for name, value in props.items() if name not in NOT_PROPERTIES} if props else None
        return props or None
    if kind in ("configured", "render") and configured(case):
        return {name: case["configuration"][name] for name in TEMPLATE_PROPERTIES if name in case["configuration"]}
    return None


def template_request(case):
    """The data-plane request step of a template case's request JSON, or (None, reason)."""
    actual = json.loads(case["request"])
    if isinstance(actual.get("path"), str) and not actual["path"].startswith("/"):
        actual["path"] = "/" + actual["path"]
    body = actual.get("body")
    if isinstance(body, dict) and "type" not in body and not any(k in body for k in ("string", "xml", "json")):
        # a JsonBody with its default content type serialises as the bare JSON value
        actual["body"] = {"type": "JSON", "json": body, "contentType": "application/json"}
    step, reason = request_steps(actual)
    if step is not None:
        step["note"] = "request"
    return step, reason


def convert_template(case, kind="template"):
    """`TemplateEngine.executeTemplate(template, request, dtoClass)`: the template as a response template, then the request.
    Kind `template` takes the default-configuration response templates, `configured` the others (see `configured`)."""
    if "unserialisable" in case or case.get("request") is None:
        return None, "unserialisable"
    template_type = TEMPLATE_TYPES.get(case["engine"])
    if template_type is None:
        return None, "engine " + case["engine"]
    if not case["dto"].endswith(".HttpResponseDTO"):
        # converted by kind `forward`
        return None, "dto " + case["dto"].rsplit(".", 1)[-1]
    if configured(case) != (kind == "configured"):
        return None, "non-default configuration " + ",".join(sorted(case["configuration"])) if kind == "template" else "default configuration"
    step, reason = template_request(case)
    if step is None:
        return None, reason
    template_name_mask(step, case, template_type)
    expectation = {"httpRequest": {}, "httpResponseTemplate": {"templateType": template_type, "template": case["template"]}}
    return [control("/mockserver/expectation", expectation, "template"), step], None


def convert_forward(case):
    """`executeTemplate(template, request, HttpRequestDTO)`: a forward template. The template as an `httpForwardTemplate`
    answering the request once (so the forwarded request, when it comes back to this server, is not forwarded again),
    the request, then the requests the server received."""
    if "unserialisable" in case or case.get("request") is None:
        return None, "unserialisable"
    template_type = TEMPLATE_TYPES.get(case["engine"])
    if template_type is None:
        return None, "engine " + case["engine"]
    if not case["dto"].endswith(".HttpRequestDTO"):
        return None, "dto " + case["dto"].rsplit(".", 1)[-1]
    if configured(case):
        return None, "forward template with non-default configuration"
    step, reason = template_request(case)
    if step is None:
        return None, reason
    template_name_mask(step, case, template_type)
    expectation = {"httpRequest": {"path": json.loads(case["request"]).get("path", "/")},
                   "httpForwardTemplate": {"templateType": template_type, "template": case["template"]},
                   "times": {"remainingTimes": 1}}
    return [control("/mockserver/expectation", expectation, "forward template"), step,
            control("/mockserver/retrieve?type=REQUESTS&format=JSON", "", "received")], None


# Template helper class -> its binding in every template (TemplateFunctions.BUILT_IN_HELPERS).
HELPER_BINDINGS = {"JwtTemplateHelper": "jwt", "StringTemplateHelper": "strings", "JsonTemplateHelper": "jsonTransform",
                   "DateTemplateHelper": "dates", "MathTemplateHelper": "calc", "CryptoTemplateHelper": "crypto",
                   "RegexTemplateHelper": "regex", "HtmlTemplateHelper": "html", "CsvTemplateHelper": "csv",
                   "XmlXPathTemplateHelper": "xpath", "YamlTemplateHelper": "yaml"}


def velocity_literal(value, java_type):
    """A Velocity literal for a helper argument of declared type `java_type`, or None when there is none."""
    if value is None:
        return "$harvestedNull"  # an undefined reference: Velocity passes null
    if java_type in ("double", "float", "java.lang.Double", "java.lang.Float"):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        text = repr(float(value))
        return text if re.fullmatch(r"-?\d+\.\d+", text) else None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value) if -2**63 <= value < 2**63 else None
    if isinstance(value, float):
        text = repr(value)
        return text if re.fullmatch(r"-?\d+\.\d+", text) else None
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    if isinstance(value, list):
        items = [velocity_literal(v, "java.lang.Object") for v in value]
        return None if any(i is None for i in items) else "[" + ", ".join(items) + "]"
    if isinstance(value, dict):
        items = [(velocity_literal(k, "java.lang.String"), velocity_literal(v, "java.lang.Object")) for k, v in value.items()]
        return None if any(k is None or v is None for k, v in items) else "{" + ", ".join(f"{k}: {v}" for k, v in items) + "}"
    return None


def convert_helper(case):
    """A template helper called directly (`StringTemplateHelper.trim("  hello  ")`): a Velocity response template that
    calls it through its binding (`$strings.trim('  hello  ')`) and returns the result, Java-escaped, as the body."""
    if "unserialisable" in case:
        return None, "unserialisable"
    if not case["test"].startswith("org.mockserver.templates.engine.helpers."):
        return None, "helper called by a template (kind template)"
    binding = HELPER_BINDINGS.get(case["helper"])
    if binding is None:
        return None, "helper " + case["helper"]
    literals = [velocity_literal(v, t) for v, t in zip(case["args"], case["parameterTypes"])]
    if any(l is None for l in literals):
        return None, "argument without a Velocity literal"
    call = f"${binding}.{case['method']}({', '.join(literals)})"
    template = '{"statusCode": 200, "body": "$!esc.java(' + call + ')"}'
    expectation = {"httpRequest": {"path": "/harvested"}, "httpResponseTemplate": {"templateType": "VELOCITY", "template": template}}
    request = {"method": "GET", "path": "/harvested", "note": "request"}
    if case["helper"] == "JwtTemplateHelper":
        # the signing key pair is generated per process (JwtTemplateHelper's static RSA key, its kid a random UUID):
        # the JWT header (the kid) and signature, and the JWKS modulus, differ between any two servers
        request["mask"] = [{"regex": "^[\\w-]+\\.([\\w-]+)\\.[\\w-]+$", "replace": "<per-process key>.$1.<signature>"},
                           {"regex": "\"n\" : \"[^\"]+\"", "replace": "\"n\" : \"<per-process key>\""}]
    template_name_mask(request, case, "VELOCITY")
    return [control("/mockserver/expectation", expectation, "template"), request], None


# render templates by file name, written (for the cases kept) once the files are known, under <--files>/harvest/render
RENDER_PENDING = {}
RENDER_REFERENCE = re.compile(r"harvest/render/([\w.-]+)")


def render_references(document):
    """The render file names a scenario document's steps refer to (`{{files}}/harvest/render/<name>`)."""
    return set(RENDER_REFERENCE.findall(json.dumps(document.get("steps") or []))) if isinstance(document, dict) else set()


def write_render_files(render_dir, kept, previous, out):
    """Writes the render templates of the cases kept, and removes only the render files that the owned
    scenario files this run rewrote or removed (`previous`) referred to and no scenario file in `out` refers to now.
    A narrowed run (one test class's cases) leaves every other render file in place."""
    os.makedirs(render_dir, exist_ok=True)
    for name in sorted(kept):
        with open(os.path.join(render_dir, name), "w", encoding="utf-8") as f:
            f.write(RENDER_PENDING[name])
    stale = set().union(*(render_references(d) for d in previous.values())) - set(kept)
    for name in os.listdir(out):
        if stale and name.endswith(".json") and not name.endswith(".golden.json"):
            with open(os.path.join(out, name), encoding="utf-8") as f:
                stale -= render_references(json.load(f))
    for name in sorted(stale):
        if os.path.exists(os.path.join(render_dir, name)):
            os.remove(os.path.join(render_dir, name))


def convert_render(case):
    """`TemplateEngine.renderTemplate(template, request)`: the template as a file, served as a templated FILE body to
    the request (FileBodyMaterialiser renders it with renderTemplate). Load iterations (`$iteration`) are not reachable
    this way."""
    if "unserialisable" in case or case.get("request") is None:
        return None, "unserialisable"
    template_type = TEMPLATE_TYPES.get(case["engine"])
    if template_type not in ("VELOCITY", "MUSTACHE"):
        return None, "engine " + case["engine"]
    if case.get("iteration"):
        return None, "load iteration context"
    step, reason = template_request(case)
    if step is None:
        return None, reason
    template_name_mask(step, case, template_type)
    name = hashlib.sha1(case["template"].encode()).hexdigest()[:12] + (".vm" if template_type == "VELOCITY" else ".mustache")
    RENDER_PENDING[name] = case["template"]
    path = json.loads(case["request"]).get("path", "/")
    expectation = {"httpRequest": {"path": path if path.startswith("/") else "/" + path},
                   "httpResponse": {"statusCode": 200, "body": {"type": "FILE", "filePath": "{{files}}/harvest/render/" + name,
                                                                "templateType": template_type, "contentType": "text/plain; charset=utf-8"}}}
    return [control("/mockserver/expectation", expectation, "file body"), step], None


def loadscenario_steps(text):
    """`PUT /mockserver/loadScenario` with the scenario body, then `GET /mockserver/loadScenario/<name>`
    to read the stored (re-serialised) definition back — the PUT response is only a `{status, name, state}` wrapper
    (`src/load/mod.rs::put`), not an echo of the scenario itself, so the round trip needs the GET step too."""
    try:
        parsed = json.loads(text)
    except ValueError:
        return None, "not JSON"
    name = parsed.get("name") if isinstance(parsed, dict) else None
    if not name:
        return None, "no name"
    return [control("/mockserver/loadScenario", text, "input"),
            {"method": "GET", "path": "/mockserver/loadScenario/" + urllib.parse.quote(str(name), safe=""), "note": "echo"}], None


def combined_steps(text):
    """`text` (one `HttpRequestAndHttpResponse` object, or a JSON array of them) as NDJSON lines to
    `PUT /mockserver/import?format=recording` (the same archive format
    `RecordedRequestsFileSystemPersistence`/`RecordedTrafficImporter` round-trip on disk), then read back with
    `retrieve?type=REQUEST_RESPONSES`. The re-importer re-serialises on the way out, so the exact formatting of the
    import body does not need to match Jackson's pretty print byte for byte."""
    try:
        parsed = json.loads(text)
    except ValueError:
        return None, "not JSON"
    pairs = parsed if isinstance(parsed, list) else [parsed]
    if not pairs:
        return None, "empty"
    body = "\n".join(json.dumps(p, ensure_ascii=False) for p in pairs)
    return [control("/mockserver/import?format=recording&redactSensitiveData=false", body, "import"),
            control("/mockserver/retrieve?type=REQUEST_RESPONSES", "", "echo")], None


# `serialize`-kind class -> the single endpoint that accepts that exact class as its PUT body (the
# recorded `input` is real, canonical JSON from a fresh, unmocked serializer — same steps shape as DESERIALIZER_ENDPOINTS).
SERIALIZE_ENDPOINTS = {
    "Configuration": "/mockserver/configuration",
    "PortBinding": "/mockserver/bind",
    "Verification": "/mockserver/verify",
    "VerificationSequence": "/mockserver/verifySequence",
    "SloCriteria": "/mockserver/verifySLO",
    "OpenAPIExpectation": "/mockserver/openapi",
    "OpenAPIExpectation[]": "/mockserver/openapi",
}


def convert_serialize(case):
    """Kind `serialize`: `ExpectationSerializer.serialize`/
    `HttpRequestAndHttpResponseSerializer.serialize` and `ConfigurationSerializer`,
    `PortBindingSerializer`, `LoadScenarioSerializer`, `VerificationSerializer`, `VerificationSequenceSerializer`,
    `SloCriteriaSerializer.serialize(SloCriteria)`, top-level `OpenAPIExpectationSerializer` — each re-serialised by
    the advice with a fresh, unmocked serializer (see `SerializeAdvice`) — converted exactly like the generic
    `deserialize` kind's matching endpoint, since the recorded `input` is already real, canonical JSON."""
    if "unserialisable" in case:
        return None, "unserialisable"
    cls = case.get("class", "")
    if cls.startswith("Expectation"):
        return [control("/mockserver/expectation", case["input"], "input"), control(RETRIEVE_ACTIVE, "", "echo")], None
    if cls.startswith("HttpRequestAndHttpResponse"):
        return combined_steps(case["input"])
    if cls == "LoadScenario":
        return loadscenario_steps(case["input"])
    endpoint = SERIALIZE_ENDPOINTS.get(cls)
    if endpoint is not None:
        return [control(endpoint, case["input"], "input")], None
    return None, "class " + cls


def convert_export(case):
    """Kind `export`: `ExpectationExportSerializer.serializeAsOpenApi` — the expectations it was given
    (re-serialised by `ExportAdvice` with a fresh `ExpectationSerializer`) PUT as an array, then read back with
    `retrieve?type=ACTIVE_EXPECTATIONS&format=OPENAPI` (`src/control.rs` already implements that retrieve format)."""
    if "unserialisable" in case:
        return None, "unserialisable"
    items = case.get("expectations") or []
    if not items:
        return None, "empty"
    try:
        parsed = [json.loads(e) for e in items]
    except ValueError:
        return None, "not JSON"
    return [control("/mockserver/expectation", parsed, "input"),
            control("/mockserver/retrieve?type=ACTIVE_EXPECTATIONS&format=OPENAPI", "", "echo")], None


def convert(case, kind):
    boundary = case["boundary"]
    if kind in KINDS:
        return KINDS[kind].convert(case)
    if kind in ("template", "configured"):
        return convert_template(case, kind)
    if kind == "forward":
        return convert_forward(case)
    if kind == "helper":
        return convert_helper(case)
    if kind == "render":
        return convert_render(case)
    if kind == "openapi":
        return convert_openapi(case)
    if kind == "code":
        return convert_code(case)
    if kind == "example":
        return convert_example(case)
    if kind == "validation":
        return convert_validation(case)
    if kind == "expression":
        return convert_expression(case)
    if kind == "match":
        return convert_match(case)
    if kind == "jackson":
        return convert_jackson(case)
    if kind == "serialize":
        return convert_serialize(case)
    if kind == "export":
        return convert_export(case)
    if kind == "validate":
        endpoint = VALIDATOR_ENDPOINTS.get(boundary.rsplit(".", 1)[1])
    else:
        endpoint = DESERIALIZER_ENDPOINTS.get(".".join(boundary.rsplit(".", 2)[1:]))
    if endpoint is None:
        return None, "no endpoint for " + boundary.rsplit(".", 1)[1]
    if endpoint == "COMBINED":
        return combined_steps(case["input"])
    if endpoint == "LOADSCENARIO":
        return loadscenario_steps(case["input"])
    steps = [control(endpoint, case["input"], "input")]
    if endpoint == "/mockserver/expectation":
        steps.append(control(RETRIEVE_ACTIVE, "", "echo"))
    return steps, None


def portable(step):
    """`step` with its test-classes paths moved to tests/files/harvest/ (see TEST_CLASSES)."""
    def move(m):
        target = os.path.join(HARVEST_FILES, m.group(1))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(os.path.join(HERE, "target", "test-classes", m.group(1)), target)
        return "{{files}}/harvest/" + m.group(1)
    return json.loads(TEST_CLASSES.sub(move, json.dumps(step, ensure_ascii=False)))


def offline_spec(step):
    """`step` with any hardcoded internet-reaching `specUrlOrPayload` literal swapped for an offline-safe
    equivalent (see OFFLINE_SPEC_REWRITES), so a re-harvest keeps the offline rewrite instead of reintroducing
    a live network dependency."""
    text = json.dumps(step, ensure_ascii=False)
    for needle, replacement in OFFLINE_SPEC_REWRITES.items():
        text = text.replace(needle, replacement)
    text = TEST_SERVER_SPEC.sub(lambda m: m.group(1) + "{{deadhost}}", text)
    return json.loads(text)


# Master's HttpStateOpenAPISpecLoadThreadTest serves its spec from a server of its own on an ephemeral port,
# gone (or anybody's) by the time a scenario runs: such a `specUrlOrPayload` is sent to `{{deadhost}}`, which always
# refuses, as the unreadable spec it is. `localhost:1080` (the oracle's own address, see OWN_HOST) is left alone.
TEST_SERVER_SPEC = re.compile(r'(\\*"specUrlOrPayload\\*"\s*:\s*\\*"https?://)localhost:(?!1080\b)\d+')


def dead_port80(step, kind):
    """`step` with every way it reaches port 80 of the machine sent to `{{deadhost}}` instead. Inside the oracle's
    container nothing listens on 80, so upstream's `Host: localhost:80` and forward templates without a host (which
    `HttpRequest.socketAddressFromHostHeader` sends to port 80) fail with 502; on a developer machine port 80 is often
    taken (a local git server answered 200). The case id is computed before this rewrite, so ids stay stable."""
    headers = step.get("headers")
    if isinstance(headers, dict):
        for name, value in headers.items():
            if name.lower() == "host" and value == "localhost:80":
                headers[name] = "{{deadhost}}"
    template = ((step.get("body") or {}).get("httpForwardTemplate") or {}) if isinstance(step.get("body"), dict) else {}
    text = template.get("template")
    if kind == "forward" and isinstance(text, str) and text.startswith("{\n") and "'headers'" not in text and "\"headers\"" not in text:
        template["template"] = "{\n    'headers': {'host': ['{{deadhost}}']}," + text[1:]
    return step


# `localhost:1080` is the oracle's own address inside its container (upstream's default port). The harness normalises
# it to `<host>` in the golden, but a server on another port (mock-server on an ephemeral one) reads it as a foreign
# address, so a harvested input writes the server's own address as `{{host}}` (B1-HttpStateTest.json was changed the same
# way by hand). Base64 or other encodings of the literal are left as they are.
OWN_HOST = "localhost:1080"


# The ports (tests/oracle.rs `scenarios_name_no_fixed_listening_port`): `1`-`5`, `1090`, `18999` and `3111x`
# may be listening in a parallel worktree, so no scenario names one as a `"port"`. Master's tests forward to
# `localhost:1090` and `localhost:1`; a harvested `"port"` of those is written `{{deadport}}` (inside a JSON string) or
# `"{{deadport}}"` (a JSON number of the step itself, which the harness turns back into a number). Applied after the
# case id is computed, like own_host. `1080` too: the oracle's own port inside its container, which the harness
# normalises in the oracle's answer only (`<port>`), so an echoed forward to it could never match a replay.
FIXED_PORT = re.compile(r'(\\*"port\\*"\s*:\s*)(?:[1-5]|1080|1090|18999|3111\d)\b')


def fixed_ports(step):
    """`step` with every fixed `"port"` (see FIXED_PORT) sent to `{{deadport}}`."""
    text = json.dumps(step, ensure_ascii=False)
    if not FIXED_PORT.search(text):
        return step
    return json.loads(FIXED_PORT.sub(lambda m: m.group(1) + ("{{deadport}}" if "\\" in m.group(1) else '"{{deadport}}"'), text))


# A `TimeToLive.exactly(unit, n)` serialises the `endDate` it computed when the test ran (now + n), so a
# case holding one expires an hour or so after its harvest, and its echo flips from the expectation to `[]` between
# recording and replay. An `endDate` no older than a day before the harvest run (the newest .jsonl's time) is such a
# live one and is dropped: the server computes the same "now + n" when the case runs. Older ones are kept as given
# (an already expired expectation is deterministic). Applied after the case id is computed, like own_host.
HARVEST_TIME_MILLIS = 0
END_DATE = re.compile(r',(?:\\n|\s)*(\\*"endDate\\*"\s*:\s*)(\d{12,})')


def live_end_dates(step):
    """`step` without the live `endDate`s of its time-to-lives (see END_DATE)."""
    text = json.dumps(step, ensure_ascii=False)
    cutoff = HARVEST_TIME_MILLIS - 86_400_000
    stripped = END_DATE.sub(lambda m: "" if int(m.group(2)) >= cutoff else m.group(0), text)
    return step if stripped == text else json.loads(stripped)


def changes_configuration(step):
    """Whether `step` changes the server's configuration, which survives `reset` (tests/oracle.rs
    `changes_configuration`): such a file replays on a server of its own, `"isolated": true` (master's
    ConfigurationDTO tests are the first new files to need it)."""
    path = str(step.get("path", "")).split("?")[0]
    op = path[len("/mockserver"):] if path.startswith("/mockserver") else path
    return step.get("method") not in (None, "GET") and op in ("/configuration", "/mode")


def own_host(step):
    """`step` with every `localhost:1080` in it written as `{{host}}` (see OWN_HOST). Applied after the case id is
    computed, like dead_port80, so ids stay stable."""
    text = json.dumps(step, ensure_ascii=False)
    return json.loads(text.replace(OWN_HOST, "{{host}}")) if OWN_HOST in text else step


# B files are partly adapted by hand after recording: step options the harness reads (`diverge`, `compare`, `mask`, `sleepMillis`, …) and document keys (`"isolated": true`). A re-harvest writes each file from
# scratch, so it carries those over from the file's previous version (`carry_over`). These step keys are the request
# a converter builds; the harvest owns them, so a hand edit to one of them is not kept.
HARVESTED_STEP_KEYS = ("method", "path", "headers", "body", "bodyBase64", "note", "case")


def harvested(document):
    """True for a file the harvest wrote (its `source` says so); a hand-authored file in the same directory and with
    the same name pattern (`B2-AbstractSchemaSerializerTest.json`, `source` "… hand-authored …") is never replaced."""
    return isinstance(document, dict) and str(document.get("source", "")).startswith("harvested from")


def source_classes(document):
    """The names a harvested file's `source` carries after the revision ("harvested from mockserver-core <rev>
    [<kind>-]<Class>[-<label>] (conformance/…"), split at the hyphens; empty when it names none. A file belongs to a
    narrowed run when one of them is a class of the run."""
    found = re.match(r"harvested from \S+ .*?\) ([\w-]+) \(conformance", str(document.get("source", "")))
    return set(found.group(1).split("-")) if found else set()


def merged(previous, fresh, kept):
    """`fresh` with the keys of `previous` that `kept(key)` allows and `fresh` lacks, in `previous`'s key order (a
    re-harvest that changes nothing rewrites the file byte for byte); keys only `fresh` has follow."""
    out = {}
    for key, value in previous.items():
        if key in fresh:
            out[key] = fresh[key]
        elif kept(key):
            out[key] = value
    for key, value in fresh.items():
        out.setdefault(key, value)
    return out


def step_slots(steps):
    """Each step keyed by (case id, ordinal within its case): case ids are stable across harvests (computed before the
    rewrites, see dead_port80), and a case's steps come out in the same order every time."""
    ordinal = collections.Counter()
    slots = []
    for step in steps:
        case = step.get("case")
        slots.append((case, ordinal[case]))
        ordinal[case] += 1
    return slots


def carry_over(previous, fresh, name="", warn=None):
    """`fresh` (a newly harvested file's document) with the hand-added keys of `previous` (the same file's document
    before this harvest) carried over: document keys `fresh` lacks, and step options the harvest does not write (keys
    outside HARVESTED_STEP_KEYS) onto the step of the same case and ordinal, when it has the same method and path.
    Options that find no such step (the case is gone or changed) are reported through `warn`, never placed elsewhere."""
    warn = warn or (lambda message: print("  " + message, file=sys.stderr))
    document = merged(previous, fresh, lambda key: key != "steps")
    previous_steps = previous.get("steps") or []
    by_slot = dict(zip(step_slots(previous_steps), previous_steps))
    steps = []
    placed = set()
    for slot, step in zip(step_slots(fresh["steps"]), fresh["steps"]):
        old = by_slot.get(slot)
        if old is not None and slot[0] is not None and (old.get("method"), old.get("path")) == (step.get("method"), step.get("path")):
            fresh_mask = step.get("mask")
            step = merged(old, step, lambda key: key not in HARVESTED_STEP_KEYS)
            if isinstance(old.get("mask"), list) and isinstance(fresh_mask, list):
                # a mask the harvest writes (TEMPLATE_NAME_MASK) adds to the hand-added ones, never replaces them
                step["mask"] = old["mask"] + [m for m in fresh_mask if m not in old["mask"]]
            placed.add(slot)
        steps.append(step)
    document["steps"] = steps
    for slot, old in by_slot.items():
        lost = [key for key in old if key not in HARVESTED_STEP_KEYS]
        if lost and slot not in placed:
            warn(f"{name}: hand-added {', '.join(lost)} of case {slot[0]} step {slot[1]} ({old.get('note', '')}) "
                 "has no matching step in this harvest: not carried over")
    return document


def main():
    load_kinds()
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="indir", default=os.path.join(HERE, "target", "harvest"))
    parser.add_argument("--out", default=os.path.join(ROOT, "tests", "scenarios", "upstream"))
    parser.add_argument("--files", help="the scenarios' {{files}} directory, which kind render writes harvest/render/ "
                        "under (default: tests/files for the default --out, else <out>/files)")
    parser.add_argument("--kinds", help="comma-separated B3 or B4 kinds: " + ", ".join(B3_KINDS + B4_KINDS))
    parser.add_argument("--classes", help="comma-separated simple test class names: a narrowed run converts "
                        "only those classes' cases and replaces or removes only the owned files of those classes")
    args = parser.parse_args()
    classes = set(args.classes.split(",")) if args.classes else None
    kinds = ("deserialize", "validate", "jackson", "match", "serialize", "export")
    if args.kinds:
        kinds = tuple(args.kinds.split(","))
        unknown = [k for k in kinds if k not in B3_KINDS + B4_KINDS]
        if unknown:
            parser.error("unknown kinds: " + ", ".join(unknown))
        if any(k in B4_KINDS for k in kinds) and any(k in B3_KINDS for k in kinds):
            parser.error("B3 and B4 kinds are harvested by separate runs")
        if args.indir == parser.get_default("indir"):
            args.indir = os.path.join(HERE, "target", "harvest-b4" if kinds[0] in B4_KINDS else "harvest-b3")
    # a module's kind names its own tranche (the B1 kinds decode and encode run like the B4 ones)
    kind_file = re.compile(r"B[1-4]-(" + "|".join(B3_KINDS + B4_KINDS) + r")-")
    kind_tranche = lambda kind: KINDS[kind].tranche if kind in KINDS else "B4" if kind in B4_KINDS else "B3"  # noqa: E731

    seen = set()
    files = collections.defaultdict(list)
    file_properties = {}
    stats = collections.Counter()
    per_method = collections.Counter()
    unconvertible = collections.Counter()
    for kind in kinds:
        source_dir, source = KIND_SOURCES.get(kind, (kind, kind))
        path = os.path.join(args.indir, source_dir, source + ".jsonl") if args.kinds else os.path.join(args.indir, kind + ".jsonl")
        if not os.path.exists(path):
            continue
        global HARVEST_TIME_MILLIS
        HARVEST_TIME_MILLIS = max(HARVEST_TIME_MILLIS, int(os.path.getmtime(path) * 1000))
        # streamed: master's stress tests put ~10^6 calls into one run (jackson.jsonl is 1.5 GB)
        f = open(path, encoding="utf-8")
        lines = (json.loads(line) for line in f)
        if kind in KINDS and KINDS[kind].group:
            lines = KINDS[kind].group(list(lines))
        for case in lines:
            stats["recorded"] += 1
            test_class, _, method = case["test"].partition("#")
            if classes is not None and (test_class.rsplit(".", 1)[-1] or "Unknown") not in classes:
                continue
            steps, reason = convert(case, kind)
            if steps is not None and len(json.dumps(steps)) > MAX_CASE_BYTES:
                steps, reason = None, f"case over {MAX_CASE_BYTES // 1024} KiB of steps (stress-test payload)"
            elif steps is not None and max((depth(step) for step in steps), default=0) > MAX_CASE_DEPTH:
                steps, reason = None, f"JSON nested deeper than the scenario reader allows ({MAX_CASE_DEPTH} levels in a step)"
            if steps is None:
                key = ("unconvertible", kind, case["test"] if kind in KINDS and KINDS[kind].per_test else None, case.get("input") or case.get("matcher") or case.get("template") or case.get("model") or json.dumps(case.get("schema")) or case.get("response"),
                       case.get("actual") or case.get("request"), json.dumps(case.get("configuration"), sort_keys=True))
                if key not in seen:
                    seen.add(key)
                    unconvertible[reason] += 1
                continue
            props = case_properties(case, kind) if args.kinds else None
            key = json.dumps([steps, props] if props else steps, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            per_method[case["test"]] += 1
            if per_method[case["test"]] > PER_METHOD:
                stats["capped"] += 1
                continue
            simple = test_class.rsplit(".", 1)[-1] or "Unknown"
            if props:
                # one file per configuration: a file's "properties" start its server
                label = hashlib.sha1(json.dumps(props, sort_keys=True).encode()).hexdigest()[:8]
                files[(kind_tranche(kind), kind + "-" + simple + "-" + label)].append((method, kind, steps))
                file_properties[(kind_tranche(kind), kind + "-" + simple + "-" + label)] = props
            elif args.kinds and kind in KINDS and KINDS[kind].own_file:
                # WASM off, or a default server: its own file name, so that no file name is a prefix of another
                # (MOCK_SERVER_SCENARIO)
                files[(kind_tranche(kind), kind + "-" + simple + KINDS[kind].own_file)].append((method, kind, steps))
            elif args.kinds:
                files[(kind_tranche(kind), kind + "-" + simple)].append((method, kind, steps))
            else:
                files[(tranche(test_class) if test_class else "B4", simple)].append((method, kind, steps))
            stats["cases"] += 1
        f.close()

    os.makedirs(args.out, exist_ok=True)
    # the owned files as they were before this harvest, by file name, for carry_over
    previous = {}
    for old in sorted(os.listdir(args.out)):
        if not old.endswith(".json") or old.endswith(".golden.json"):
            continue
        owned = any(old.startswith(f"{kind_tranche(k)}-{k}-") for k in kinds) if args.kinds else re.match(r"B\d-", old) and not kind_file.match(old)
        if owned:
            with open(os.path.join(args.out, old), encoding="utf-8") as f:
                document = json.load(f)
            if not harvested(document):
                continue
            if classes is not None and not (source_classes(document) & classes):
                continue  # A narrowed run leaves the other classes' files alone
            previous[old] = document
            os.remove(os.path.join(args.out, old))
    # every owned file, rewritten below or not, before carry_over consumes `previous`
    rewritten = dict(previous)
    per_tranche = collections.Counter()
    for (tr, simple), cases in sorted(files.items()):
        steps = []
        for method, kind, case_steps in cases:
            # A stable case id: skips-rs.txt and the per-case results refer to it.
            props = file_properties.get((tr, simple))
            case_id = hashlib.sha1(json.dumps([case_steps, props] if props else case_steps, sort_keys=True).encode()).hexdigest()[:12]
            for s in [reset()] + case_steps:
                s = live_end_dates(fixed_ports(own_host(dead_port80(offline_spec(portable(s)), kind))))
                s["case"] = case_id
                s["note"] = f"{method} ({kind}): {s.get('note', 'reset')}"
                steps.append(s)
        name = f"{tr}-{simple}.json"
        if os.path.exists(os.path.join(args.out, name)):
            # still there after the clean-up above: hand-authored (see harvested)
            print(f"  {name}: hand-authored, not replaced by its {len(cases)} harvested cases", file=sys.stderr)
            continue
        file_kind = cases[0][1]
        document = {"source": f"harvested from mockserver-core {oracle_revision()} {simple} (conformance/harvest)"}
        if (tr, simple) in file_properties:
            document["properties"] = file_properties[(tr, simple)]
        elif any(changes_configuration(s) for s in steps):
            document["isolated"] = True
        document["steps"] = steps
        if name in previous:
            document = carry_over(previous.pop(name), document, name)
        with open(os.path.join(args.out, name), "w", encoding="utf-8") as f:
            json.dump(document, f, indent=1, ensure_ascii=False)
            f.write("\n")
        per_tranche[tr] += len(cases)
    if "render" in kinds:
        kept = {name for cases in files.values() for _, kind, steps in cases if kind == "render"
                for name in RENDER_PENDING if name in json.dumps(steps)}
        files_dir = args.files or (os.path.join(ROOT, "tests", "files") if args.out == parser.get_default("out")
                                   else os.path.join(args.out, "files"))
        write_render_files(os.path.join(files_dir, "harvest", "render"), kept, rewritten, args.out)
    for name, document in sorted(previous.items()):
        # a file this harvest no longer writes: say what of it was adapted by hand
        hand = [key for key in document if key not in ("source", "properties", "steps")]
        hand += sorted({key for step in document.get("steps") or [] for key in step if key not in HARVESTED_STEP_KEYS})
        if hand:
            print(f"  {name}: no longer harvested; its hand-added {', '.join(hand)} went with it", file=sys.stderr)
    print(f"recorded calls: {stats['recorded']}, distinct convertible cases: {stats['cases']}, "
          f"distinct unconvertible: {sum(unconvertible.values())}, over the per-method cap: {stats['capped']}")
    for tr, n in sorted(per_tranche.items()):
        print(f"  {tr}: {n} cases in {sum(1 for k in files if k[0] == tr)} files")
    for reason, n in unconvertible.most_common():
        print(f"  unconvertible: {n:5d}  {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

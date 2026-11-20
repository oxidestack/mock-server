"""Kind `idp` (B4): the OIDC, SCIM and SAML providers, one case per test method (its calls in order).

The tests call the generators and the class callbacks directly, and sometimes plant state in the provider stores by
hand. On the wire a case is:

- `*ProviderGenerator.generate(config)` -> `PUT /mockserver/oidc|scim|saml` with the configuration's non-default fields,
  then a retrieve of the active expectations (what the generator built);
- `OidcAuthorizationStore.registerProvider` / `ScimResourceStore.registerProvider` with a hand-built provider -> the
  same `PUT`, with the provider's paths and flags as configuration;
- a callback's `handle(request)` -> that request sent to the data plane, where the generated expectation hands it to
  the same callback;
- `putCode(code, …)` -> `GET <authorize>` with the code's redirect URI, scope, nonce and PKCE challenge, and the code the
  oracle mints captured from its `location`; `putDeviceCode` -> `POST <device_authorization>` (its pending-poll count
  set on the provider's configuration), the device code captured from the answer; `OidcTokenMinter.mintTokenResponse`
  -> a `client_credentials` `POST <token>` with the same scope, its tokens captured;
- a store `reset()` between wire calls -> `PUT /mockserver/reset` (which resets the stores too).

Values a later request reuses from an earlier answer (tokens, codes, SCIM ids and versions) become `{{capture:…}}`.
Other in-process calls (the stores' and helpers' own API, the minter's verification, SCIM filter/sort/patch/shaper,
the SAML builders) have no wire form: a case of only those is unconvertible, and one made after the last wire call is
an assertion and is dropped.
"""
import json
import re
import urllib.parse

from harvest import Kind, RETRIEVE_ACTIVE, control, request_steps, reset

# Answers carry per-process values: key material, signatures, ids, codes and instants.
MASKS = [
    "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    {"regex": "content-length: \\d+", "replace": "content-length: <varies>"},
    {"regex": "\"(created|lastModified)\" ?: ?\"[^\"]+\"", "replace": "\"${1}\" : \"<timestamp>\""},
    {"regex": "W/\\\\\"[0-9a-f-]+\\\\\"", "replace": "W/\\\"<version>\\\""},
    {"regex": "^etag: .*$", "replace": "etag: <version>"},
    {"regex": "\"user_code\" ?: ?\"[A-Z]{4}-[A-Z]{4}\"", "replace": "\"user_code\" : \"<code>\""},
    {"regex": "user_code=[A-Z]{4}-[A-Z]{4}", "replace": "user_code=<code>"},
    {"regex": "eyJ[\\w-]+\\.[\\w-]+\\.[\\w-]*", "replace": "<jwt>"},
    # claims of the decoded tokens (decodeJwt) that depend on the clock or on another per-process value
    {"regex": "\"(iat|nbf|exp|auth_time)\" ?: ?\\d+", "replace": "\"${1}\" : <epoch>"},
    {"regex": "\"(at_hash|c_hash)\" ?: ?\"[\\w-]+\"", "replace": "\"${1}\" : \"<hash>\""},
    # JWKS key material (generated per provider unless the configuration supplies a key)
    {"regex": "(\\\\?\"(n|x|y|kid|x5t#S256)\\\\?\" ?: ?\\\\?\")[\\w-]+", "replace": "${1}<key>"},
    {"regex": "<ds:DigestValue>[^<]*</ds:DigestValue>", "replace": "<ds:DigestValue><masked></ds:DigestValue>"},
    {"regex": "<ds:SignatureValue>[^<]*</ds:SignatureValue>", "replace": "<ds:SignatureValue><masked></ds:SignatureValue>"},
    {"regex": "<ds:X509Certificate>[^<]*</ds:X509Certificate>", "replace": "<ds:X509Certificate><masked></ds:X509Certificate>"},
    {"regex": "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z", "replace": "<instant>"},
    {"regex": "(ID|InResponseTo|SessionIndex)=\"_[0-9a-f]+\"", "replace": "${1}=\"_<id>\""},
]
# SAML's default entity ids name `localhost:1080`, the oracle's own address, which the harness normalises on the
# oracle's side only
SAML_MASKS = MASKS + [{"regex": "localhost:(<port>|1080)", "replace": "localhost:<p>"}]
# the SSO answer's auto-post form carries the signed Response as base64
DECODE = "name=\"SAMLResponse\" value=\"([^\"]*)\""

CALLBACK_METHODS = {"OidcTokenCallback": "POST", "OidcIntrospectionCallback": "POST", "OidcRevocationCallback": "POST",
                    "OidcDeviceAuthorizationCallback": "POST"}
# values in an answer that later requests present, and how to find each again in the oracle's answer
BODY_KEYS = ("access_token", "id_token", "refresh_token", "device_code", "user_code", "id")
SCIM_DEFAULTS = {"basePath": "/scim/v2", "idStrategy": "UUID", "requireBearerToken": False, "expectedBearerToken": None,
                 "enforceFilter": True, "enforcePatch": True}
OIDC_DEFAULT_PATHS = {"authorizePath": "/authorize", "tokenPath": "/token", "deviceAuthorizationPath": "/device_authorization"}
WIRE = ("generate", "registerProvider", "callback", "scimPatch", "scimQuery", "resolveKeyPair", "parseAlgorithm", "bearerGate")
TOKEN_CHARS = "A-Za-z0-9._~-"


def group_idp(lines):
    cases = []
    for call in lines:
        if cases and cases[-1]["test"] == call["test"]:
            cases[-1]["calls"].append(call)
        else:
            cases.append({"boundary": "idp", "test": call["test"], "calls": [call]})
    return cases


def response_body(response):
    body = response.get("body")
    if isinstance(body, dict):
        for k in ("json", "string", "xml"):
            if k in body:
                v = body[k]
                return v if isinstance(v, str) else json.dumps(v)
        return None
    return body


def walk_strings(value, key=None):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from walk_strings(v, k)
    elif isinstance(value, list):
        for v in value:
            yield from walk_strings(v, key)
    elif isinstance(value, str) and key is not None:
        yield key, value


def header(response, name):
    for n, values in (response.get("headers") or {}).items() if isinstance(response.get("headers"), dict) else \
            [(h["name"], h["values"]) for h in response.get("headers") or []]:
        if n.lower() == name:
            return values[0] if isinstance(values, list) else values
    return None


def candidates(response, step):
    """(value, capture spec) pairs from a JVM answer that later requests may present."""
    out = []
    body = response_body(response)
    if body:
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        for key, value in walk_strings(parsed):
            if key in BODY_KEYS and len(value) >= 4:
                regex = "\"" + key + "\"\\s*:\\s*\"([^\"]+)\""
                first = re.search(regex, body)
                if first and first.group(1) == value:
                    out.append((value, {"bodyRegex": regex}))
    location = header(response, "location")
    if location:
        m = re.search(r"[?&#]code=([^&#]+)", location)
        if m:
            out.append((urllib.parse.unquote(m.group(1)), {"headerRegex": ["location", "[?&#]code=([^&#]+)"]}))
    etag = header(response, "etag")
    if etag:
        out.append((etag, {"headerRegex": ["etag", "^(.*)$"]}))
    return out


class Case:
    def __init__(self):
        self.steps = []
        self.known = []  # (value, producing step, spec)
        self.keys = 0
        self.oidc_config = None  # the body of the latest PUT /mockserver/oidc
        self.notes = []
        self.saml = False

    def produce(self, value, step, spec):
        self.known.append((value, step, spec))

    def substitute(self, step):
        """Earlier answers' values in `step` as captures, longest first."""
        for value, producer, spec in sorted(self.known, key=lambda k: -len(k[0])):
            pattern = re.compile("(?<![" + TOKEN_CHARS + "])" + re.escape(value) + "(?![" + TOKEN_CHARS + "])")
            fields = [("path", step.get("path")), ("body", step.get("body"))]
            hits = any(isinstance(v, str) and pattern.search(v) for _, v in fields) or \
                any(isinstance(v, str) and pattern.search(v) for v in (step.get("headers") or {}).values())
            if not hits:
                continue
            key = None
            for c in producer.get("capture", []):
                if {k: v for k, v in c.items() if k != "as"} == spec:
                    key = c["as"]
            if key is None:
                key = f"idp{self.keys}"
                self.keys += 1
                producer.setdefault("capture", []).append(dict(spec, **{"as": key}))
            token = "{{capture:" + key + "}}"
            for name, v in fields:
                if isinstance(v, str):
                    step[name] = pattern.sub(lambda _: token, v)
            for name, v in list((step.get("headers") or {}).items()):
                if isinstance(v, str):
                    step["headers"][name] = pattern.sub(lambda _: token, v)

    def add(self, step):
        step["mask"] = SAML_MASKS if self.saml else MASKS
        step["decodeJwt"] = True
        step["decodeBase64"] = DECODE
        if keygen(step):
            step["maxMillis"] = KEYGEN_MILLIS
        self.steps.append(step)
        return step


# a 3072- or 4096-bit RSA key generated while the step waits: 0.4 s on average for 4096 bits, but well over the
# harness's 10 s step timeout on a loaded machine; the answer itself still compares in full
SLOW_KEYS = {"RS384", "RS512"}
KEYGEN_MILLIS = 60000


def keygen(step):
    body = step.get("body")
    return step.get("method") == "PUT" and step.get("path") in ("/mockserver/oidc", "/mockserver/saml") \
        and isinstance(body, dict) and body.get("signingAlgorithm") in SLOW_KEYS


def oidc_put(case, configuration, note):
    body = dict(configuration or {})
    step = case.add(control("/mockserver/oidc", body, note))
    case.oidc_config = body
    return step


def scim_queries(calls):
    """`ScimFilter.parse(f)` / `ScimSort.parse(by, order)` and the `apply(resources)` that follows as one list query."""
    out = []
    for call in calls:
        if call["call"] == "scimApply" and out and out[-1]["call"] == "scimQuery" and "resources" not in out[-1]:
            out[-1]["resources"] = call["resources"]
        elif call["call"] in ("scimFilter", "scimSort"):
            out.append(dict(call, call="scimQuery", via=call["call"]))
        elif call["call"] == "scimApply":
            out.append(dict(call, call="inProcess", method="ScimFilter/ScimSort.apply"))
        else:
            out.append(call)
    return out


def scim_seed(out, resources, note):
    body = {"initialUsers": resources} if resources else {}
    out.add(control("/mockserver/scim", body, note))


def convert_idp(case):
    calls = case["calls"]
    if any("unserialisable" in c for c in calls):
        return None, "unserialisable"
    calls = scim_queries(calls)
    wire = [i for i, c in enumerate(calls) if c["call"] in WIRE]
    if not wire:
        methods = sorted({c.get("method") or c["call"] for c in calls if not (c.get("method") or "").endswith(".reset")})
        return None, "no wire form: " + (", ".join(methods) if methods else "store reset only")
    first, last = wire[0], wire[-1]
    out = Case()
    out.saml = any(c.get("provider") == "saml" or "saml" in (c.get("callback") or "") for c in calls)
    threads = {c.get("thread") for c in calls[first:last + 1]}
    for i, call in enumerate(calls[:last + 1]):
        kind = call["call"]
        if kind == "generate":
            provider = call["provider"]
            config = call.get("configuration")
            body = "null" if config is None else config
            if provider == "oidc":
                step = oidc_put(out, config, "generate")
                if config is None:
                    step["body"] = "null"
            else:
                out.add(control("/mockserver/" + provider, body, "generate"))
            out.add(control(RETRIEVE_ACTIVE, "", "the generated expectations"))
        elif kind == "registerProvider":
            config = dict(call.get("configuration") or {})
            if call["provider"] == "oidc":
                for name, default in OIDC_DEFAULT_PATHS.items():
                    if call.get(name) != config.get(name, default):
                        config[name] = call.get(name)
                oidc_put(out, config, "registerProvider (a provider built by hand)")
            else:
                if call.get("seeded"):
                    return None, "SCIM provider seeded by hand"
                config = {k: v for k, v in config.items() if SCIM_DEFAULTS.get(k, object()) != v}
                out.add(control("/mockserver/scim", config, "registerProvider (a provider built by hand)"))
        elif kind == "callback":
            request = json.loads(call["request"])
            simple = call["callback"].rsplit(".", 1)[1]
            note = simple + ".handle"
            if "method" not in request and simple in CALLBACK_METHODS:
                request["method"] = CALLBACK_METHODS[simple]
                note += " (method of the expectation that serves it)"
            step, reason = request_steps(request)
            if step is None:
                return None, reason
            step["note"] = note
            out.substitute(step)
            out.add(step)
            if call.get("response"):
                for value, spec in candidates(json.loads(call["response"]), step):
                    out.produce(value, step, spec)
        elif kind in ("resolveKeyPair", "parseAlgorithm"):
            # the generator resolves the signing key the same way; the JWKS publishes the result
            config = call.get("configuration") if kind == "resolveKeyPair" else {"signingAlgorithm": call.get("algorithm")}
            if config is None:
                return None, "null configuration passed to OidcKeyProvider"
            oidc_put(out, config, "OidcKeyProvider." + kind + " -> PUT /mockserver/oidc")
            out.add({"method": "GET", "path": config.get("jwksPath", "/.well-known/jwks.json"), "note": "the published key"})
        elif kind == "bearerGate":
            if call.get("configuration") is None:
                return None, "bearerGate without a provider (no wire form: the request would match no expectation)"
            if call.get("seeded"):
                return None, "SCIM provider seeded by hand"
            config = {k: v for k, v in call["configuration"].items() if SCIM_DEFAULTS.get(k, object()) != v}
            out.add(control("/mockserver/scim", config, "ScimCallbackSupport.bearerGate: the provider"))
            step, reason = request_steps(json.loads(call["request"]))
            if step is None:
                return None, reason
            step["note"] = "ScimCallbackSupport.bearerGate -> the request"
            out.add(step)
        elif kind == "scimPatch":
            resource = call.get("resource")
            if not isinstance(resource, dict) or not isinstance(resource.get("id"), str):
                return None, "patched resource without an id"
            scim_seed(out, [resource], "ScimPatchApplier.apply: the resource seeded")
            patch = call.get("patch")
            out.add({"method": "PATCH", "path": "/scim/v2/Users/" + urllib.parse.quote(resource["id"], safe=""),
                     "headers": {"Content-Type": "application/scim+json"}, "body": "null" if patch is None else patch,
                     "note": "ScimPatchApplier.apply -> PATCH"})
        elif kind == "scimQuery":
            scim_seed(out, call.get("resources"), call["via"].replace("scim", "Scim") + ".apply: the resources seeded")
            if call["via"] == "scimFilter":
                query = [] if call.get("filter") is None else [("filter", call["filter"])]
            else:
                query = [(k, call[k]) for k in ("sortBy", "sortOrder") if call.get(k) is not None]
            path = "/scim/v2/Users" + ("?" + urllib.parse.urlencode(query, quote_via=urllib.parse.quote) if query else "")
            out.add({"method": "GET", "path": path, "note": call["via"].replace("scim", "Scim") + ".parse -> list query"})
        elif kind == "putCode":
            if i > last:
                continue
            if not call.get("redirectUri"):
                return None, "authorization code planted without a redirect_uri (authorize requires one)"
            config = out.oidc_config if out.oidc_config is not None else {}
            query = [("response_type", "code"), ("client_id", config.get("clientId", "mock-client")), ("redirect_uri", call["redirectUri"])]
            for name, param in (("scope", "scope"), ("nonce", "nonce"), ("codeChallenge", "code_challenge"),
                                ("codeChallengeMethod", "code_challenge_method")):
                if call.get(name) is not None:
                    query.append((param, call[name]))
            path = config.get("authorizePath", "/authorize") + "?" + urllib.parse.urlencode(query)
            step = out.add({"method": "GET", "path": path, "note": "putCode -> authorize"})
            out.produce(call["code"], step, {"headerRegex": ["location", "[?&#]code=([^&#]+)"]})
        elif kind == "putDeviceCode":
            if out.oidc_config is None:
                return None, "device code planted without a provider"
            polls = int(call.get("pendingPolls") or 0)
            if polls != out.oidc_config.get("deviceCodePendingPolls", 0):
                out.oidc_config["deviceCodePendingPolls"] = polls
            form = urllib.parse.urlencode([("scope", call["scope"])]) if call.get("scope") else ""
            step = out.add({"method": "POST", "path": out.oidc_config.get("deviceAuthorizationPath", "/device_authorization"),
                            "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": form,
                            "note": "putDeviceCode -> device_authorization"})
            out.produce(call["deviceCode"], step, {"bodyRegex": "\"device_code\"\\s*:\\s*\"([^\"]+)\""})
            if call.get("userCode"):
                out.produce(call["userCode"], step, {"bodyRegex": "\"user_code\"\\s*:\\s*\"([^\"]+)\""})
        elif kind == "mint":
            config = call.get("configuration") or {}
            form = [("grant_type", "client_credentials")]
            if call.get("scope"):
                form.append(("scope", call["scope"]))
            if config.get("enforceClientAuthentication"):
                form += [("client_id", config.get("clientId", "mock-client")), ("client_secret", config.get("clientSecret", "mock-client-secret"))]
            step = {"method": "POST", "path": config.get("tokenPath", "/token"),
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "body": urllib.parse.urlencode(form), "note": "mintTokenResponse -> client_credentials token"}
            if call.get("issuer") and not config.get("issuer"):
                step["headers"]["Host"] = urllib.parse.urlparse(call["issuer"]).netloc
            out.add(step)
            try:
                minted = json.loads(call.get("result") or "{}")
            except ValueError:
                minted = {}
            for key in ("access_token", "id_token", "refresh_token"):
                if isinstance(minted.get(key), str):
                    out.produce(minted[key], step, {"bodyRegex": "\"" + key + "\"\\s*:\\s*\"([^\"]+)\""})
        elif kind == "inProcess":
            method = call["method"]
            if i < first:
                continue
            if method.endswith(".reset"):
                out.add(dict(reset(), note=method + " (between calls)"))
                out.oidc_config = None
                continue
            name = method.split(".", 1)[1]
            if re.match(r"(get|is|providerFor|latestProvider|peek|lookup|parseObject|\w*Count$)", name) or method.startswith("SamlSigningCredential."):
                continue
            return None, "in-process call between wire calls: " + method
        else:
            return None, "unknown call " + kind
    if len(threads) > 1:
        for step in out.steps:
            step["note"] = step.get("note", "") + " (called from a pool in the test, in completion order here)"
    return out.steps, None


KINDS = [Kind("idp", "B4", convert_idp, group=group_idp, per_test=True, own_file="-default")]

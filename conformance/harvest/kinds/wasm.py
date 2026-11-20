"""Kind `wasm` (B4): the WASM runtime, body matcher and response shaping."""
import os
import urllib.parse

from harvest import Kind, RETRIEVE_ACTIVE, ROOT, control, request_steps


# The prebuilt example modules the WASM tests load, by content: referenced as tests/files/wasm fixtures, not inlined.
WASM_FILES = os.path.join(ROOT, "tests", "files", "wasm")


def wasm_fixture(b64):
    """`wasm/<file>` under tests/files for module bytes identical to a committed fixture, else None."""
    import base64
    data = base64.b64decode(b64)
    for name in sorted(os.listdir(WASM_FILES)):
        if not name.endswith(".wasm"):
            continue
        with open(os.path.join(WASM_FILES, name), "rb") as f:
            if f.read() == data:
                return "wasm/" + name
    return None


def wasm_upload(name, b64):
    """`PUT /mockserver/wasm/modules?name=` with the module's bytes (a fixture file when there is one)."""
    step = {"method": "PUT", "path": "/mockserver/wasm/modules?name=" + urllib.parse.quote(name, safe=""), "note": "load module"}
    fixture = wasm_fixture(b64) if b64 else None
    if fixture:
        step["bodyFile"] = fixture
    elif b64:
        step["bodyBase64"] = b64
    return step


def wasm_module_field(b64):
    """The dry run's `module`: a fixture placeholder or the base64 itself."""
    fixture = wasm_fixture(b64)
    return "{{base64:" + fixture + "}}" if fixture else b64


def wasm_sample(request):
    """A WasmRequest as the dry run's `request` object, empty fields left out."""
    sample = {}
    for k in ("method", "path", "headers", "queryStringParameters", "cookies", "body"):
        v = request.get(k)
        if v not in (None, {}, ""):
            sample[k] = v
    return sample


def wasm_http_request(request):
    """A WasmRequest as the data-plane request that builds the same envelope."""
    actual = {"method": request.get("method") or "POST", "path": request.get("path") or "/harvested"}
    for k in ("headers", "queryStringParameters", "cookies"):
        if request.get(k):
            actual[k] = request[k]
    if request.get("body") is not None:
        actual["body"] = request["body"]
    return request_steps(actual)


def wasm_response(response):
    out = {}
    if response.get("statusCode") is not None:
        out["statusCode"] = response["statusCode"]
    if response.get("headers"):
        out["headers"] = response["headers"]
    if response.get("body") is not None:
        out["body"] = response["body"]
    return out


def convert_wasm(case):
    """The WASM boundaries. A `WasmRuntime` call is `POST /mockserver/wasm/test` with the module inline
    (empty bytes are loaded first: the endpoint reads a blank `module` as absent); `WasmBodyMatcher.matches` is the
    module loaded under its name, a WASM body expectation and the request; the shapers are the same with the
    expectation's response, plus a dry run with that response."""
    if "unserialisable" in case:
        return None, "unserialisable"
    if case.get("interrupted"):
        return None, "caller thread interrupted (no wire form)"
    kind = case["kind"]
    if kind == "shaper":
        # the shaper has no gate of its own; on the wire it runs behind wasmEnabled
        case = dict(case, wasmEnabled=True)
    if kind == "runtime":
        body = {}
        steps = []
        if case["module"]:
            body["module"] = wasm_module_field(case["module"])
        else:
            steps.append(wasm_upload("harvested", case["module"]))
            body["moduleName"] = "harvested"
        if case["call"] == "callMatchBody":
            if case.get("body") is not None:
                body["request"] = {"body": case["body"]}
        else:
            body["request"] = wasm_sample(case["request"])
        if case.get("response") is not None:
            body["response"] = wasm_response(case["response"])
        steps.append({"method": "POST", "path": "/mockserver/wasm/test", "body": body, "note": case["call"]})
        return steps, None
    request, reason = wasm_http_request(case["request"])
    if request is None:
        return None, reason
    request["note"] = "request"
    steps = []
    name = case.get("moduleName")
    if case.get("wasmEnabled") and name is not None and case.get("module") is not None:
        steps.append(wasm_upload(name, case["module"]))
    matcher = {"type": "WASM"}
    if name is not None:
        matcher["moduleName"] = name
    if case.get("not"):
        matcher["not"] = True
    if kind == "matcher":
        http_request = {"body": matcher}
        http_response = {"statusCode": 200, "body": "matched"}
    else:
        http_request = {"method": request["method"], "path": case["request"]["path"] or "/harvested"}
        if "matchedPath" in case:
            http_request = {"path": case["matchedPath"]} if case["matchedPath"] else {}
        else:
            http_request["body"] = matcher
        http_response = wasm_response(case["response"])
    steps += [control("/mockserver/expectation", {"httpRequest": http_request, "httpResponse": http_response}, "expectation"),
              control(RETRIEVE_ACTIVE, "", "echo"),
              request]
    if kind != "matcher" and case.get("wasmEnabled") and name is not None:
        steps.append({"method": "POST", "path": "/mockserver/wasm/test", "note": "dry run with the response",
                      "body": {"moduleName": name, "request": wasm_sample(case["request"]), "response": wasm_response(case["response"])}})
    return steps, None


def wasm_properties(case):
    """A WASM case's server: `wasmEnabled` (runtime cases need it for the endpoint) and non-default limits."""
    props = {}
    if case["kind"] in ("runtime", "shaper") or case.get("wasmEnabled"):
        props["wasmEnabled"] = "true"
    if case.get("maxMemoryPages", 256) != 256:
        props["wasmMaxMemoryPages"] = str(case["maxMemoryPages"])
    if case.get("executionTimeoutMillis", 5000) != 5000:
        props["wasmExecutionTimeoutMillis"] = str(case["executionTimeoutMillis"])
    return props or None


KINDS = [Kind("wasm", "B4", convert_wasm, properties=wasm_properties, own_file="-disabled")]

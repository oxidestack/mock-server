"""Kind `sse` (B4): `HttpSseResponseActionHandler.handle` and `formatSseEvent`, one case per call."""
import json

from harvest import Kind, RETRIEVE_ACTIVE, control, request_steps

EXPECTATION_ID = "harvested-sse"


def convert_sse(case):
    """The `httpSseResponse` as the only expectation (on the request's path, `/harvested` when it has none) and the
    request: `formatSseEvent(event)` is a response with that one event; a request that arrived on an HTTP/2 stream is
    sent over cleartext HTTP/2, one that is not keep-alive with `Connection: close`."""
    if "unserialisable" in case:
        return None, "unserialisable: " + case["unserialisable"]
    if case["call"] == "handle" and case.get("format") != "SSE":
        return None, "streaming format " + str(case.get("format")) + " (reached through httpLlmResponse, kind llmhandler)"
    request = json.loads(case["request"]) if case.get("request") else {}
    request.setdefault("path", "/harvested")
    if not request["path"].startswith("/"):
        request["path"] = "/" + request["path"]
    keep_alive = request.pop("keepAlive", None)
    step, reason = request_steps(request)
    if step is None:
        return None, reason
    if keep_alive is False:
        step.setdefault("headers", {})["Connection"] = "close"
    if case.get("streamId") is not None:
        step["h2"] = True
    step["note"] = "formatSseEvent" if case["call"] == "format" else "handle"
    expectation = {"id": EXPECTATION_ID, "httpRequest": {"path": request["path"]}, "httpSseResponse": case["sse"]}
    return [control("/mockserver/expectation", expectation, "httpSseResponse"), control(RETRIEVE_ACTIVE, "", "echo"), step], None


def sse_properties(case):
    return case.get("configuration") or None


KINDS = [Kind("sse", "B4", convert_sse, properties=sse_properties, own_file="-default")]

"""Kind `metricshandler` (B4): `MetricsHandler.renderMetrics(ctx, request)` of MetricsHandlerTest, the
handler behind `GET /mockserver/metrics`, one case per call: the request's headers sent to `/mockserver/metrics` (as
cleartext HTTP/2 when it carried a stream id), on a server with `metricsEnabled` when the handler had it."""
from harvest import Kind

# the exposition holds every registered metric with values the server's own traffic moves (timings, request counts);
# what the handler decides is the status, the content type and the CORS headers, not the figures
# (a mask applies to each header line too, which never starts with `# `)
EXPOSITION = {"regex": "(?s)\\A# .*\\z", "replace": "<the exposition>"}
EXPOSITION_LENGTH = {"regex": "^content-length: \\d+$", "replace": "content-length: <the whole exposition>"}


def convert_metricshandler(case):
    """`renderMetrics(ctx, request)` -> the request to `/mockserver/metrics`; a stream id makes it an HTTP/2 request
    (the handler answers on the request's stream, which the step's answer arriving at all shows)."""
    if "unserialisable" in case:
        return None, "unserialisable: " + case["unserialisable"]
    if case.get("keepAlive") is False:
        return None, "keepAlive false (the handler closes the connection)"
    headers = {}
    for name, value in case.get("headers", []):
        if name in headers:
            return None, "a header with several values"
        headers[name] = value
    step = {"method": case.get("method") or "GET", "path": "/mockserver/metrics", "note": "MetricsHandler.renderMetrics"}
    if headers:
        step["headers"] = headers
    if "streamId" in case:
        step["h2"] = True
        step["note"] += " (HTTP/2 stream {} in the test)".format(case["streamId"])
    if case.get("metricsEnabled"):
        step["mask"] = [EXPOSITION, EXPOSITION_LENGTH]
    return [step], None


def metricshandler_properties(case):
    return {"metricsEnabled": "true"} if case.get("metricsEnabled") else None


KINDS = [Kind("metricshandler", "B4", convert_metricshandler, source=("obs", "metricshandler"),
              properties=metricshandler_properties, own_file="-default")]

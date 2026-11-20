"""Kind `traceparent` (B4): `W3CTraceContext.parse(traceparent, tracestate)` of W3CTraceContextTest, the
parser `TraceContextHandler` runs on each inbound request's headers. One case per call: a data-plane request carrying
the arguments as its `traceparent` and `tracestate` headers, on a server with `otelPropagateTraceContext`, which puts a
valid parsed context back on the response (`toTraceparent()`, and the trace state) and nothing for one it rejects."""
from harvest import Kind

PROPAGATE = {"otelPropagateTraceContext": "true"}


def convert_traceparent(case):
    """`parse(traceparent, tracestate)` -> an unmatched request (404) with those headers; a null argument is an absent
    header. The tests that build a context with its constructor (the `*FailsValidation` ones) parse nothing and have no
    case."""
    if "thrown" in case:
        return None, "parse threw " + case["thrown"]
    headers = {}
    if "traceparent" in case:
        headers["traceparent"] = case["traceparent"]
    if "tracestate" in case:
        headers["tracestate"] = case["tracestate"]
    step = {"method": "GET", "path": "/w3c_trace_context", "note": "W3CTraceContext.parse: the request's trace headers"}
    if headers:
        step["headers"] = headers
    return [step], None


KINDS = [Kind("traceparent", "B4", convert_traceparent, source=("obs", "traceparent"),
              properties=lambda case: dict(PROPAGATE))]

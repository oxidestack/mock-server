"""Kind `drift` (B4): the traffic-diff and drift-analysis calls of TrafficDiffEngineTest, BaselineDifferTest,
DriftAnalyzerTest and DriftEndToEndAssemblyTest, one case per test method, through `PUT /mockserver/diff`,
`PUT /mockserver/baseline/compare`, and a forward next to the analysed expectation read back with
`GET /mockserver/drift`."""
import json

from harvest import Kind, control, request_steps

UPSTREAM_ID = "harvested-upstream"
FORWARD_ID = "harvested-forward"
# the forwarded request reaches the server itself with `Host: localhost:<port>`; the client's request carries this one,
# so that only the forwarded request reaches the upstream stub (kind `action` does the same)
CLIENT_HOST = "harvest.client"
EPOCH = {"regex": "\"epochTimeMs\" : \\d+", "replace": "\"epochTimeMs\" : <millis>"}
# headers the upstream stub cannot serve as given: a fixed length or chunking would not describe the body it writes
# (DriftAnalyzer skips both, so the drift is the same without them)
FRAMING = ("content-length", "transfer-encoding")


def group_drift(lines):
    """The recorded calls of one test method, in order, as one case."""
    cases = []
    for call in lines:
        if cases and cases[-1]["test"] == call["test"]:
            cases[-1]["calls"].append(call)
        else:
            cases.append({"boundary": "drift", "test": call["test"], "calls": [call]})
    return cases


def as_expectation(interaction):
    """A raw `BaselineDiffer.Interaction` as the expectation `toInteractions` would read the same pair from."""
    if interaction.get("httpResponse") is None:
        return None
    return {"httpRequest": interaction["httpRequest"], "httpResponse": interaction["httpResponse"]}


def baseline_set(items, raw):
    out = []
    for item in items:
        if item is None:
            return None, "a null expectation in a set (skipped by toInteractions, refused by the endpoint's deserialiser)"
        if raw:
            item = as_expectation(item)
            if item is None:
                return None, "an interaction without a response (no expectation carries it)"
        out.append(item)
    return out, None


def without_framing(response):
    response = json.loads(json.dumps(response))
    headers = response.get("headers")
    if isinstance(headers, dict):
        response["headers"] = {k: v for k, v in headers.items() if k.lower() not in FRAMING}
        if not response["headers"]:
            del response["headers"]
    elif isinstance(headers, list):
        response["headers"] = [h for h in headers if str(h.get("name", "")).lower() not in FRAMING]
    return response


def analyse_steps(call, index):
    """`DriftAnalyzer.analyse(expectation, real)`: the expectation under its id, a forward of its request (priority above
    it) to the server itself, where a stub answers the forwarded request with the real response; then the request and
    the drift recorded for the expectation."""
    expectation, real = call.get("expectation"), call.get("response")
    if expectation is None or real is None:
        return None, "a null expectation or response (the analyser returns at once)"
    if not call.get("responseAction"):
        return None, "an expectation without a response action (an expectation without an action cannot be created)"
    matcher = expectation.get("httpRequest") or {}
    request = {k: v for k, v in matcher.items() if k in ("method", "path", "headers", "queryStringParameters", "cookies")}
    if set(matcher) - set(request):
        return None, "a request matcher with more than method, path, headers, query and cookies"
    request["path"] = request.get("path") or "/"
    request.setdefault("headers", {})["Host"] = [CLIENT_HOST]
    probe, reason = request_steps(request)
    if probe is None:
        return None, reason
    upstream = {"id": UPSTREAM_ID, "priority": 1000, "httpRequest": {"headers": {"Host": ["localhost:[0-9]+"]}},
                "httpResponse": without_framing(real)}
    forward = {"id": FORWARD_ID, "priority": 999, "httpRequest": matcher, "httpForward": {"host": "localhost", "port": "{{port}}"}}
    expectation = dict(expectation, priority=0)
    probe["note"] = "DriftAnalyzer.analyse (the request, forwarded)"
    return [
        control("/mockserver/expectation", upstream, "upstream (the real response the analyser is given)"),
        control("/mockserver/expectation", json.dumps(forward, indent=1).replace('"{{port}}"', "{{port}}"), "a forward of the expectation's request"),
        control("/mockserver/expectation", expectation, "the analysed expectation"),
        probe,
        {"sleepMillis": 300},
        {"method": "GET", "path": "/mockserver/drift?expectationId=" + expectation["id"], "note": "DriftStore records of the expectation",
         "mask": [EPOCH]},
    ], None


def convert_drift(case):
    """A `TrafficDiffEngine.diff` is `PUT /mockserver/diff` (a null side has no wire form: the endpoint requires both), a
    `BaselineDiffer` comparison `PUT /mockserver/baseline/compare` with both sets (raw interactions as the expectations
    carrying them), a `DriftAnalyzer.analyse` a forward next to the expectation and `GET /mockserver/drift` for it (one
    store per server: a test's own store is the server's, cleared between cases)."""
    steps = []
    skipped = None
    for index, call in enumerate(case["calls"]):
        if "unserialisable" in call:
            return None, "unserialisable: " + call["unserialisable"]
        kind = call["call"]
        if kind == "diff":
            if call["expected"] is None or call["actual"] is None:
                return None, "a null request (the endpoint requires both)"
            steps.append(control("/mockserver/diff", {"expected": call["expected"], "actual": call["actual"]}, "TrafficDiffEngine.diff"))
        elif kind == "baseline":
            if call["baseline"] is None or call["current"] is None:
                return None, "a null set"
            baseline, reason = baseline_set(call["baseline"], call["raw"])
            current, reason2 = baseline_set(call["current"], call["raw"]) if baseline is not None else (None, None)
            if baseline is None or current is None:
                return None, reason or reason2
            note = "BaselineDiffer.diff" if call["raw"] else "BaselineDiffer.diffExpectations"
            steps.append(control("/mockserver/baseline/compare", {"baseline": baseline, "current": current}, note))
        elif kind == "analyse":
            more, reason = analyse_steps(call, index)
            if more is None:
                # an analysis the server cannot be given has no step (the analyser stores nothing for it either)
                skipped = reason
                continue
            steps.extend(more)
        else:
            return None, "unknown call " + kind
    if not steps:
        return None, skipped or "no call with a wire form"
    return steps, None


KINDS = [Kind("drift", "B4", convert_drift, group=group_drift, per_test=True)]

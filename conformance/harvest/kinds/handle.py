"""Kind `handle` (B4): control-plane sequences through HttpState.handle, one case per test method."""
import json
import re

from harvest import Kind, control, request_steps, reset


# a cassette's last use, epoch millis
LAST_USED = {"regex": "\"lastUsed\" : \\d+", "replace": "\"lastUsed\" : <millis>"}
RECORDED_LENGTH = {"regex": "^content-length: \\d+$", "replace": "content-length: <varies with the socket addresses>"}
_RUN_FIELDS = ("elapsedMillis|currentVus|requestsSent|succeeded|failed|droppedIterations|errorRate|startedAt|endedAt"
               "|startedAtEpochMillis|endedAtEpochMillis|durationMillis|p50|p95|p99|p999|p50Millis|p95Millis|p99Millis|p999Millis")
LOAD_RUN = [
    {"regex": '"(' + _RUN_FIELDS + ')" : -?[0-9][0-9.E-]*', "replace": '"$1" : <run>'},
    {"regex": '(<property name="(' + _RUN_FIELDS + ')" value=")[^"]*"', "replace": '$1<run>"'},
    {"regex": '(<testsuite [^>]*time=")[^"]*"', "replace": '$1<run>"'},
    {"regex": "\\b(" + _RUN_FIELDS + ")=[0-9][0-9.E-]*", "replace": "$1=<run>"},
]
ORACLE_PORT_TARGET = re.compile(r'("port"\s*:\s*)1080\b')


def group_handle(lines):
    """Kind `handle`: the recorded calls of one test method, in order, as one case."""
    cases = []
    for call in lines:
        if cases and cases[-1]["test"] == call["test"]:
            cases[-1]["calls"].append(call)
        else:
            cases.append({"boundary": "HttpState.handle", "test": call["test"], "calls": [call]})
    return cases


def convert_handle(case):
    """A test method's sequence against one HttpState: each `handle(request)` is that request sent to the server, a
    direct `reset()` is `PUT /mockserver/reset`, `CassetteRegistry.register(path, filename, count, origin)` is
    `PUT /mockserver/cassettes` with those fields, and a RECEIVED_REQUEST the test adds to the event log is the same
    request sent to the data plane (which logs it on arrival)."""
    steps = []
    for call in case["calls"]:
        if "unserialisable" in call:
            return None, "unserialisable"
        kind = call["call"]
        if kind == "reset":
            steps.append(dict(reset(), note="HttpState.reset()"))
        elif kind == "registerCassette":
            body = {"path": call["path"]}
            if call.get("filename") is not None:
                body["filename"] = call["filename"]
            body["expectationCount"] = call["expectationCount"]
            if call.get("origin") is not None:
                body["origin"] = call["origin"]
            steps.append(dict(control("/mockserver/cassettes", body, "CassetteRegistry.register"), mask=[LAST_USED]))
        elif kind in ("handle", "receivedRequest"):
            if call.get("authenticationHandler"):
                return None, "control-plane authentication handler installed by the test (no wire form)"
            if call.get("warDeployment"):
                return None, "WAR deployment"
            step, reason = request_steps(json.loads(call["request"]))
            if step is None:
                return None, reason
            step["note"] = "handle" if kind == "handle" else "recorded request (event log)"
            if isinstance(step.get("body"), str) and ORACLE_PORT_TARGET.search(step["body"]):
                # a target on port 1080 is the oracle's own container port, which the harness turns into `<port>` in
                # the oracle's answers only; any other port checks the same override
                step["body"] = ORACLE_PORT_TARGET.sub(r"\g<1>1081", step["body"])
                step["note"] += " (target port 1080 -> 1081)"
            if re.fullmatch(r"(/mockserver)?/cassettes", step["path"]):
                step["mask"] = [LAST_USED]
            elif re.match(r"(/mockserver)?/loadScenario(/[^/?]+(/report)?)?(\?|$)", step["path"]) and step["method"] == "GET":
                # a started run's live measurements (the oracle's load runs send real traffic)
                step["mask"] = LOAD_RUN
            elif step["path"].endswith("/generateFromRecording"):
                # the scenario carries the recorded requests' socket addresses, whose lengths differ between the
                # oracle's container and a local server (the body compares them as `<address>`)
                step["mask"] = [RECORDED_LENGTH]
            steps.append(step)
        else:
            return None, "unknown call " + kind
    return steps, None


def handle_properties(case):
    """The server a `handle` case runs on: the configuration differences of its `handle` calls after the first, a
    property keeping the value of the first call that has it. The first call is usually a setUp clean-up on the class's
    usual server, made before the test rebuilds its HttpState or changes a static property; a tearDown that restores a
    property runs after the calls that needed it."""
    handles = [c for c in case["calls"] if c["call"] == "handle" and c.get("configuration") is not None]
    props = {}
    for call in handles[1:] or handles:
        for name, value in call["configuration"].items():
            props.setdefault(name, value)
    return props or None


KINDS = [Kind("handle", "B4", convert_handle, group=group_handle, properties=handle_properties, per_test=True, own_file="-default")]

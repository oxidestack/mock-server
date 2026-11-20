"""Kind `action` (B4): requests put through `HttpActionHandler.processAction` by the action handler tests
(HTTP, forward and GraphQL chaos, rate limits, recover-after, drift), one case per test method."""
import json
import re

from harvest import Kind, control, request_steps

EXPECTATION_ID = "harvested-action-{}"
UPSTREAM_ID = "harvested-upstream"
# the forwarded request reaches the server itself with `Host: localhost:<port>` (HttpForwardActionHandler replaces it);
# a client request without a Host header of its own is sent with this one, so that only forwarded requests reach the
# upstream stub
CLIENT_HOST = "harvest.client"
# a rate limit's reset instant, epoch seconds
RATE_LIMIT_RESET = {"regex": "x-ratelimit-reset: \\d+", "replace": "x-ratelimit-reset: <epoch seconds>"}
# a 60 s window's Retry-After is the seconds left, rounded: 60 or 59 depending on when the request lands
RATE_LIMIT_RETRY = {"regex": "^retry-after: (59|60)$", "replace": "retry-after: <seconds left in the window>"}


def group_action(lines):
    """The recorded calls of one test method, in order, as one case."""
    cases = []
    for call in lines:
        if cases and cases[-1]["test"] == call["test"]:
            cases[-1]["calls"].append(call)
        else:
            cases.append({"boundary": "HttpActionHandler.processAction", "test": call["test"], "calls": [call]})
    return cases


def absolute(path):
    """Upstream's tests use `some_path`; HTTP needs `/some_path`."""
    return path if not isinstance(path, str) or path.startswith("/") else "/" + path


def has_host(request):
    headers = request.get("headers") or {}
    names = headers.keys() if isinstance(headers, dict) else [h.get("name") for h in headers]
    return any(isinstance(n, str) and n.lower() == "host" for n in names)


def convert_action(case):
    """A test method's calls against one server: a `ServiceChaosRegistry.put` is `PUT /mockserver/serviceChaos`, a
    `TimeService.advance` a pause before the next request, and each `processAction(request)` the expectation the
    test's stubbed HttpState returned for it (upserted under a stable id when it is new or changed) and the request.
    A forward action is pointed at the server itself, where a stub answers the forwarded request (`Host:
    localhost:<port>`) with the upstream response the test gave its mocked forward handler; an upstream the test
    made fail, or none, is a dead port."""
    steps = []
    seen = {}
    sent = {}
    upstream = None
    pause = 0
    stub = None
    for call in case["calls"]:
        if "unserialisable" in call:
            return None, "unserialisable: " + call["unserialisable"]
        kind = call["call"]
        if kind == "upstream":
            upstream = call
        elif kind == "advance":
            pause += call["millis"]
        elif kind == "serviceChaos":
            body = {"host": call["host"], "chaos": call["chaos"]}
            if call.get("ttlMillis"):
                body["ttlMillis"] = call["ttlMillis"]
            steps.append(control("/mockserver/serviceChaos", body, "ServiceChaosRegistry.put"))
        elif kind == "process":
            request = json.loads(call["request"])
            request["path"] = absolute(request.get("path", "/"))
            expectation = json.loads(call["expectation"]) if call.get("expectation") else None
            forward = expectation is not None and "httpForward" in expectation
            if expectation is not None:
                identity = call["expectationIdentity"]
                if identity not in seen:
                    seen[identity] = EXPECTATION_ID.format(len(seen) + 1)
                expectation["id"] = seen[identity]
                matcher = expectation.get("httpRequest") or {}
                if isinstance(matcher.get("path"), str) and re.fullmatch(r"[A-Za-z0-9_\-]+", matcher["path"]):
                    matcher["path"] = "/" + matcher["path"]
                if forward:
                    target = expectation["httpForward"]
                    if upstream is not None and upstream.get("response"):
                        target["host"], target["port"] = "localhost", "{{port}}"
                        target.pop("scheme", None)
                        wanted = {"id": UPSTREAM_ID, "priority": 1000,
                                  "httpRequest": {"headers": {"Host": ["localhost:[0-9]+"]}},
                                  "httpResponse": json.loads(upstream["response"])}
                        if wanted != stub:
                            stub = wanted
                            steps.append(control("/mockserver/expectation", wanted, "upstream (the mocked forward handler's response)"))
                    else:
                        target["host"], target["port"] = "localhost", "{{deadport}}"  # a quoted `{{deadport}}` becomes a number
                        target.pop("scheme", None)
                    if not has_host(request):
                        request.setdefault("headers", {})["Host"] = [CLIENT_HOST]
                text = json.dumps(expectation, sort_keys=True)
                if sent.get(identity) != text:
                    sent[identity] = text
                    body = expectation
                    if forward:
                        # `{{port}}` is substituted as text: a JSON number only outside quotes
                        body = json.dumps(expectation, indent=1).replace('"{{port}}"', "{{port}}")
                    steps.append(control("/mockserver/expectation", body, "the expectation HttpState returned"))
            step, reason = request_steps(request)
            if step is None:
                return None, reason
            step["note"] = "processAction"
            step["mask"] = [RATE_LIMIT_RESET, RATE_LIMIT_RETRY]
            if pause:
                step["sleepMillis"] = pause
                pause = 0
            steps.append(step)
        else:
            return None, "unknown call " + kind
    if not any(s.get("note") == "processAction" for s in steps):
        return None, "no processAction"
    return steps, None


def action_properties(case):
    """The handler's configuration values that differ from the run's startup values."""
    props = {}
    for call in case["calls"]:
        for name, value in (call.get("configuration") or {}).items():
            props.setdefault(name, value)
    return props or None


KINDS = [Kind("action", "B4", convert_action, group=group_action, properties=action_properties, per_test=True, own_file="-default")]

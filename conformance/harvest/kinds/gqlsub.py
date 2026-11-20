"""Kind `gqlsub` (B4): `GraphQLSubscriptionHandler` driven by inbound WebSocket frames."""
import json

from harvest import Kind, control

PATH = "/graphql-subscription"


def group_gqlsub(lines):
    """The handler a test method builds and the frames it reads, as one case."""
    cases = []
    for call in lines:
        if cases and cases[-1]["test"] == call["test"]:
            cases[-1]["calls"].append(call)
        else:
            cases.append({"boundary": "GraphQLSubscriptionHandler", "test": call["test"], "calls": [call]})
    return cases


def convert_gqlsub(case):
    """The handler's filter and payloads as an `httpWebSocketResponse` expectation (`graphqlSubscriptionFilter`,
    `messages`, and the subprotocol: the negotiated one, `graphql-transport-ws` when the test negotiated none, which
    speaks the same vocabulary), a WebSocket opened offering that subprotocol, the inbound frames sent in order, then
    the frames the server writes, read until one more read times out. A test that builds a handler and sends it no
    frame checks a static helper (`buildNextMessage`, `normaliseSubscriptionBody`): no wire form.

    Adapted by hand after recording: a read the oracle answered with a frame or a close waits up to 5 s
    (`waitMillis` 5000) instead of 1 s, so a delayed frame (`shouldPassDelaysToFrameSender`'s 500 ms) arrives in time
    on a loaded machine; a read it answered with a timeout keeps 1 s. Re-apply it after a re-harvest."""
    constructs = [c for c in case["calls"] if c["call"] == "construct"]
    frames = [c for c in case["calls"] if c["call"] == "frame"]
    if len(constructs) != 1:
        return None, "not one handler per test"
    handler = constructs[0]
    if "unserialisable" in handler:
        return None, "unserialisable"
    if not frames:
        return None, "handler without inbound frames (a static helper's test, no wire form)"
    if any(f["handler"] != handler["handler"] or f.get("text") is None for f in frames):
        return None, "non-text frame or another handler"
    if handler.get("inboundStreamId") is not None:
        return None, "inbound breakpoint stream"
    protocol = handler.get("subprotocol") or "graphql-transport-ws"
    payloads = json.loads(handler["payloads"]) if handler.get("payloads") else []
    response = {"subprotocol": protocol, "graphqlSubscriptionFilter": json.loads(handler["filter"]), "messages": payloads}
    steps = [control("/mockserver/expectation", [{"httpRequest": {"path": PATH}, "httpWebSocketResponse": response}], "the handler's expectation"),
             {"wsOpen": "g", "path": PATH, "headers": {"Sec-WebSocket-Protocol": protocol}, "note": "WebSocket offering " + protocol}]
    for f in frames:
        steps.append({"wsSend": "g", "text": f["text"], "note": "inbound frame"})
    subscribes = sum(1 for f in frames if '"subscribe"' in f["text"] or '"start"' in f["text"])
    for _ in range(len(frames) + subscribes * (len(payloads) + 1)):
        steps.append({"wsRead": "g", "waitMillis": 1000, "note": "outbound frame"})
    steps.append({"wsRead": "g", "waitMillis": 300, "note": "nothing more"})
    steps.append({"wsClose": "g", "note": "close"})
    return steps, None


KINDS = [Kind("gqlsub", "B4", convert_gqlsub, group=group_gqlsub, per_test=True)]

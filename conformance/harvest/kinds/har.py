"""Kind `har` (B3): `HarConverter.serialize`, the recorded exchanges as HAR."""
from harvest import Kind, control, traffic_steps


def convert_har(case):
    """`HarConverter.serialize(entries)`: each entry's request answered once with its response, the requests sent,
    then `retrieve?type=REQUEST_RESPONSES&format=HAR` (the recorded exchanges as HAR)."""
    if "unserialisable" in case:
        return None, "unserialisable"
    if not case["entries"]:
        return [control("/mockserver/retrieve?type=REQUEST_RESPONSES&format=HAR", "", "har")], None
    if any(e.get("request") is None for e in case["entries"]):
        return None, "entry without a request"
    pairs = [(e["request"], e.get("response")) for e in case["entries"]]
    steps, reason = traffic_steps(pairs)
    if steps is None:
        return None, reason
    har = control("/mockserver/retrieve?type=REQUEST_RESPONSES&format=HAR", "", "har")
    # the client's address as the server saw it (Docker's gateway for the oracle), as in retrieve_har
    har["mask"] = ["\"serverIPAddress\" : \"[^\"]*\""]
    return steps + [har], None


KINDS = [Kind("har", "B3", convert_har)]

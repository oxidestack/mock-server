"""Kind `bodymatch` (B4): body matchers called directly (GraphQL, JSON-RPC, fuzzy)."""
from harvest import Kind, RETRIEVE_ACTIVE, control


def convert_bodymatch(case):
    """A body matcher's `matches(…, string)` (GraphQL, JSON-RPC, fuzzy): an expectation whose request body is the
    matcher, its echo, then a request carrying the string as its body (none for `null`)."""
    if "unserialisable" in case or not isinstance(case.get("matcher"), dict):
        return None, "unserialisable"
    request = {"method": "POST", "path": "/harvested", "note": "request"}
    if case.get("actual") is not None:
        request["body"] = case["actual"]
    return [
        control("/mockserver/expectation", {"httpRequest": {"path": "/harvested", "body": case["matcher"]},
                                            "httpResponse": {"statusCode": 200, "body": "matched"}}, "matcher"),
        control(RETRIEVE_ACTIVE, "", "echo"),
        request,
    ], None


KINDS = [Kind("bodymatch", "B4", convert_bodymatch)]

"""Kind `fieldmatch` (B1): the field matchers of `org.mockserver.matchers` called by a test directly.

`FieldmatchAdvice` lifts each call to the request (or response) field that builds the same matcher; a case replays it
as the matcher's expectation, the actual request on the data plane, a verification with the matcher (its difference
text, `MatchDifferenceFormatter`) and `debugMismatch` with the request (its differences and `MismatchRemediation`
hints). Control-plane matchers are a stored expectation and a retrieve filter, as kind `match`."""
import json

from harvest import Kind, RETRIEVE_ACTIVE, control, convert_match, request_steps

# debugMismatch answers carry the expectations' creation times
TIMESTAMP_MASK = ["\\d{4}-\\d{2}-\\d{2}T[0-9:.]+Z"]


def verify(body):
    return control("/mockserver/verify", body, "verify")


def debug_mismatch(request):
    return {"method": "PUT", "path": "/mockserver/debugMismatch", "body": request, "note": "debugMismatch", "compare": "json",
            "mask": TIMESTAMP_MASK}


def convert_request(case):
    steps, reason = convert_match(case)
    if steps is None or case.get("controlPlaneMatcher"):
        return steps, reason
    matcher = steps[0]["body"]["httpRequest"]
    actual = json.loads(case["actual"])
    if isinstance(actual.get("path"), str) and isinstance(matcher.get("path"), str) and matcher["path"].startswith("/") \
            and not actual["path"].startswith("/"):
        actual["path"] = "/" + actual["path"]
    return steps + [verify({"httpRequest": matcher, "times": {"atLeast": 1}}), debug_mismatch(actual)], None


def convert_response(case):
    """`HttpResponseMatcher`/`StatusCodeMatcher`: an expectation answering with the actual response, the request it
    serves, then a response verification with the template."""
    if case.get("template") is None:
        return None, "no response template"
    template = json.loads(case["template"])
    steps = []
    if case.get("response") is not None:
        steps += [control("/mockserver/expectation", {"httpRequest": {"path": "/harvested"}, "httpResponse": json.loads(case["response"])},
                          "response"),
                  {"method": "GET", "path": "/harvested", "note": "request"}]
    return steps + [verify({"httpResponse": template, "times": {"atLeast": 1}})], None


def convert_path_groups(case):
    """`PathGroupExtractor.extract(pattern, path, caseSensitive)`: an expectation on the pattern whose template prints
    the groups the match extracted, and the path."""
    pattern, path = case.get("pattern"), case.get("path")
    if pattern is None or path is None:
        return None, "null pattern or path"
    if not path.startswith("/"):
        if pattern.startswith("^"):
            return None, "relative path"
        pattern, path = "/" + pattern, "/" + path
    step, reason = request_steps({"path": path})
    if step is None:
        return None, reason
    step["note"] = "request"
    template = "{'statusCode': 200, 'body': \"{{request.pathGroups}}|{{request.namedPathGroups}}\"}"
    return [control("/mockserver/expectation", {"httpRequest": {"path": pattern},
                                                "httpResponseTemplate": {"templateType": "MUSTACHE", "template": template}}, "pattern"),
            step], None


def convert_similarity(case):
    """`StringSimilarity.jaroWinkler(a, b)`: a fuzzy body on `a` whose threshold is the similarity, and `b`."""
    if case.get("fuzzy") is None or case.get("actualBody") is None or case.get("similarity") is None:
        return None, "null similarity input"
    matcher = {"path": "/harvested", "body": {"type": "FUZZY", "fuzzy": case["fuzzy"], "threshold": case["similarity"]}}
    steps = [control("/mockserver/expectation", {"httpRequest": matcher, "httpResponse": {"statusCode": 200, "body": "matched"}}, "matcher"),
             {"method": "POST", "path": "/harvested", "body": case["actualBody"], "note": "request"}]
    return steps, None


def convert_fieldmatch(case):
    if "unserialisable" in case:
        return None, case["unserialisable"]
    return {"request": convert_request, "response": convert_response, "pathgroups": convert_path_groups,
            "similarity": convert_similarity}.get(case.get("mode"), lambda c: (None, "unknown mode"))(case)


def fieldmatch_properties(case):
    """A case-sensitive matcher (`matchExactCase`) or a regex timeout of its own runs on a server started with it."""
    props = {}
    if case.get("caseSensitive"):
        props["matchExactCase"] = "true"
    if case.get("regexMatchingTimeoutMillis") is not None:
        props["regexMatchingTimeoutMillis"] = str(case["regexMatchingTimeoutMillis"])
    return props or None


KINDS = [Kind("fieldmatch", "B1", convert_fieldmatch, properties=fieldmatch_properties, own_file="-default")]

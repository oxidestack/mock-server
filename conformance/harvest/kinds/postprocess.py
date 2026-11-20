"""Kind `postprocess`: `RecordedExpectationPostProcessor` (`persistence/RecordedExpectationPostProcessorTest`),
harvested by a run of its own:

  mvn -q test -Dharvest.tests='org/mockserver/persistence/RecordedExpectationPostProcessorTest.java' \
      -Dharvest.dir=target/harvest-b4/postprocess

The expectations a call is given are recorded exchanges (an `httpRequest` and its `httpResponse`, unlimited, priority
0), so the case imports them as a recording archive (`PUT /mockserver/import?format=recording`, one
`HttpRequestAndHttpResponse` line each, redaction off) and retrieves the recorded expectations the way `HttpState`
reaches the call: `consolidate(list, parameterize)` is `?consolidate=true` (with `&parameterize=true` when set), and
`deduplicateAndTemplatize(list, templatize)` is a server started with `deduplicateRecordedExpectations` (and
`templatizeRecordedValues` when set)."""
import json

from harvest import Kind, control

RETRIEVE = "/mockserver/retrieve?type=RECORDED_EXPECTATIONS&format=JSON"


def _exchanges(case):
    lines = []
    for text in case["expectations"]:
        e = json.loads(text)
        extra = set(e) - {"id", "priority", "times", "timeToLive", "httpRequest", "httpResponse"}
        if extra:
            return None, "expectation with " + ", ".join(sorted(extra)) + " (not a recorded exchange)"
        if e.get("priority", 0) != 0 or e.get("times", {"unlimited": True}) != {"unlimited": True} \
                or e.get("timeToLive", {"unlimited": True}) != {"unlimited": True}:
            return None, "expectation with times, time to live or priority (not a recorded exchange)"
        if "specUrlOrPayload" in e["httpRequest"]:
            return None, "OpenAPI request definition (not a recorded exchange)"
        line = {"httpRequest": e["httpRequest"]}
        if "httpResponse" in e:
            line["httpResponse"] = e["httpResponse"]
        lines.append(json.dumps(line, ensure_ascii=False, separators=(",", ":")))
    return lines, None


def convert_postprocess(case):
    if "unserialisable" in case:
        return None, "unserialisable"
    if case.get("expectations") is None:
        return None, "null list (no wire form)"
    lines, reason = _exchanges(case)
    if lines is None:
        return None, reason
    steps = []
    if lines:
        steps.append({"method": "PUT", "path": "/mockserver/import?format=recording&redactSensitiveData=false",
                      "body": "\n".join(lines) + "\n", "note": f"{len(lines)} recorded exchanges"})
    if case["call"] == "consolidate":
        path = RETRIEVE + "&consolidate=true" + ("&parameterize=true" if case["flag"] else "")
        steps.append({"method": "PUT", "path": path, "note": f"consolidate(…, {str(case['flag']).lower()})"})
    else:
        steps.append({"method": "PUT", "path": RETRIEVE, "note": f"deduplicateAndTemplatize(…, {str(case['flag']).lower()})"})
    return steps, None


def postprocess_properties(case):
    if case["call"] != "deduplicateAndTemplatize":
        return None
    props = {"deduplicateRecordedExpectations": "true"}
    if case["flag"]:
        props["templatizeRecordedValues"] = "true"
    return props


KINDS = [Kind("postprocess", "B4", convert_postprocess, properties=postprocess_properties, own_file="-default")]

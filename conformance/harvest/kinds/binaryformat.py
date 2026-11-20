"""Kind `binaryformat` (B4): `BinaryArrayFormatter.byteArrayToString(bytes)` of BinaryArrayFormatterTest,
which renders both sides of a `BinaryMatcher` difference (`binary match failed expected:{}found:{}`). One case per call:
the bytes as the body of a request a BINARY body expectation does not match, so they are the difference's `found`
side, read back whole from the event log (the closest-match hint header folds the line breaks the formatter puts in)."""
from harvest import Kind, control

# one zero byte: matches none of the recorded inputs, and a non-empty matcher (an empty one matches anything)
EXPECTED = "AA=="


def convert_binaryformat(case):
    """`byteArrayToString(bytes)` -> an expectation whose body is a one-byte BINARY matcher, a request with the bytes as
    its body (none for a null or empty array) and `retrieve?type=LOGS`."""
    if "thrown" in case:
        return None, "byteArrayToString threw " + case["thrown"]
    expectation = {"httpRequest": {"path": "/binary_array_formatter", "body": {"type": "BINARY", "base64Bytes": EXPECTED}},
                   "httpResponse": {"statusCode": 200}}
    request = {"method": "POST", "path": "/binary_array_formatter", "headers": {"content-type": "application/octet-stream"},
               "note": "BinaryArrayFormatter.byteArrayToString: the bytes are the request body"}
    if case.get("bytes"):
        request["bodyBase64"] = case["bytes"]
    return [control("/mockserver/expectation", expectation, "a BINARY body expectation the request does not match"), request,
            control("/mockserver/retrieve?type=LOGS", "", "the event log: the difference rendered by the formatter")], None


KINDS = [Kind("binaryformat", "B4", convert_binaryformat, source=("obs", "binaryformat"))]

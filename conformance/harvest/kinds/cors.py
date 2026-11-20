"""Kind `cors` (B1): `CORSHeaders.addCORSHeaders(request, response)` and
`CORSHeaders.isPreflightRequest(configuration, request)` of CORSHeadersTest (and ServletResponseWriterTest).

Run: mvn -q -o test -Dharvest.tests='org/mockserver/cors/*Test.java,org/mockserver/responseheaders/*Test.java,org/mockserver/url/*Test.java,org/mockserver/server/ServletResponseWriterTest.java'
     -Dharvest.dir=<abs>/target/harvest-b1/small
Convert: harvest.py --kinds cors,responseheaders,url --in target/harvest-b1
"""
import json

from harvest import Kind, TOKEN, control

# the setting a case's CORSHeaders instance held -> its default, which the file's server is not given
DEFAULTS = {"corsAllowOrigin": "", "corsAllowHeaders": "", "corsAllowMethods": "", "corsAllowCredentials": "false",
            "corsMaxAgeInSeconds": "0"}


def wire_headers(case):
    """The recorded request headers as a step's map, or (None, reason)."""
    headers = {}
    for header in case.get("headers", []):
        if len(header) != 2:
            return None, "a header without a value"
        name, value = header
        if not TOKEN.fullmatch(name) or any(c in value for c in "\r\n\0"):
            return None, "header not valid on the wire"
        if name.lower() in (n.lower() for n in headers):
            return None, "a header with several values"
        headers[name] = value
    return headers, None


def convert_cors(case):
    """`addCORSHeaders`: an expectation answering the recorded response, then the recorded request to it, on a server
    adding the CORS headers to every response with the instance's settings. `isPreflightRequest`: the recorded request
    alone (a preflight is answered by the CORS handler, anything else is not matched)."""
    if "unserialisable" in case:
        return None, "unserialisable: " + case["unserialisable"]
    headers, reason = wire_headers(case)
    if headers is None:
        return None, reason
    method = case.get("method") or "GET"
    if not TOKEN.fullmatch(method):
        return None, "method not a token"
    step = {"method": method, "path": "/harvested", "note": "request"}
    if headers:
        step["headers"] = headers
    if case["boundary"] == "CORSHeaders.isPreflightRequest":
        step["note"] = "request (preflight: {})".format(case.get("preflight"))
        return [step], None
    response = case.get("response")
    if not response:
        return None, "no response"
    return [control("/mockserver/expectation", {"httpRequest": {"path": "/harvested"}, "httpResponse": json.loads(response)},
                    "response"), step], None


def cors_properties(case):
    properties = {"enableCORSForAllResponses": "true"}
    for name, value in (case.get("settings") or {}).items():
        if value is not None and value != DEFAULTS[name]:
            properties[name] = value
    return properties


KINDS = [Kind("cors", "B1", convert_cors, source=("small", "cors"), properties=cors_properties)]

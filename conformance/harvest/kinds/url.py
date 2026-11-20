"""Kind `url` (B1): `URLParser.returnPath(uri)` and `URLParser.isFullUrl(uri)` of URLParserTest. The
request decoder takes a request's path from `returnPath(uri)` of its request target, which strips the scheme, host
and port only when `isFullUrl`, so both show as the path of the received request. Harvested by the same run as kind `cors`
(kinds/cors.py).
"""
import re

from harvest import Kind, control

# a catch-all, so that a request target naming another host is answered, not proxied (as kinds/decode.py)
CATCH_ALL = {"httpRequest": {}, "httpResponse": {"statusCode": 200}}
RETRIEVE_REQUESTS = "/mockserver/retrieve?type=REQUESTS&format=JSON"
URI = re.compile(r"[\x21-\x7e]+")


def convert_url(case):
    """The catch-all expectation, a raw HTTP/1.1 request with the URI as its request target, then the recorded
    requests, whose `path` is what `returnPath` made of it."""
    uri = case.get("uri")
    if not uri:
        return None, "no URI (null or empty)"
    if not URI.fullmatch(uri) or "{{" in uri:
        return None, "URI not valid on the wire (whitespace, control or non-ASCII characters)"
    if re.match(r"(?:[a-z]+://[^/]*)?/mockserver(?:/|$)", uri):
        return None, "control-plane path"
    request = "GET " + uri + " HTTP/1.1\r\nhost: {{host}}\r\nconnection: close\r\n\r\n"
    return [control("/mockserver/expectation", CATCH_ALL, "catch-all"),
            {"tcp": [{"text": request}], "text": True, "note": "request " + uri},
            control(RETRIEVE_REQUESTS, "", "recorded requests")], None


KINDS = [Kind("url", "B1", convert_url, source=("small", "url"))]

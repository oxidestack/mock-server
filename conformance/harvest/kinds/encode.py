"""Kind `encode` (B1): `MockServerHttpResponseToFullHttpResponse.mapMockServerResponseToNettyResponse`, the
server-side encoding of an `HttpResponse` into the bytes a client reads. Harvested by the codec run (see kinds/decode.py).
"""
import json

from harvest import Kind, control

REQUEST = "GET /harvested HTTP/1.1\r\nhost: {{host}}\r\nconnection: close\r\n\r\n"


def binary(response):
    body = response.get("body")
    return isinstance(body, dict) and body.get("type") == "BINARY"


def convert_encode(case):
    """An expectation answering `GET /harvested` with the recorded response, then that request as raw bytes, the
    answer read whole (as text, or base64 for a binary body), so header order, framing and body bytes all compare."""
    if "unserialisable" in case or not case.get("response"):
        return None, "unserialisable"
    try:
        response = json.loads(case["response"])
    except ValueError:
        return None, "unserialisable"
    if not isinstance(response, dict):
        return None, "unserialisable"
    send = {"tcp": [{"text": REQUEST}], "note": "request"}
    if not binary(response):
        send["text"] = True
    return [control("/mockserver/expectation", {"httpRequest": {"path": "/harvested"}, "httpResponse": response}, "response"),
            send], None


KINDS = [Kind("encode", "B1", convert_encode, source=("codec", "encode"))]

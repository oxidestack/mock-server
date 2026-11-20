"""Kind `decode` (B1): `FullHttpRequestToMockServerHttpRequest.mapFullHttpRequestToMockServerRequest`, the
server-side mapping of a request Netty decoded into the `HttpRequest` a received log entry shows.

Run: mvn -q -o test -Dharvest.tests='org/mockserver/codec/**/*Test.java,org/mockserver/mappers/**/*Test.java,…'
     -Dharvest.dir=<abs>/target/harvest-b1/codec   (the codec, mappers, streams, xml and formatting tests, without the Netty
     aggregator and buffer-pinning classes: category C, they never reach either boundary)
Convert: harvest.py --kinds decode,encode --in target/harvest-b1 (both read the codec run, KINDS source)
"""
import base64
import re

from harvest import Kind, TOKEN, control

# The answer every harvested request gets: a catch-all expectation, so that a request whose Host names another server
# is answered, not proxied (the oracle would forward it from inside its container), and the decoding is what differs.
CATCH_ALL = {"httpRequest": {}, "httpResponse": {"statusCode": 200}}
RETRIEVE_REQUESTS = "/mockserver/retrieve?type=REQUESTS&format=JSON"
URI = re.compile(r"[\x21-\x7e]+")


def latin1(text):
    """A header line as the bytes Netty's HTTP/1.1 decoder reads back to the same characters (one byte per char)."""
    try:
        return text.encode("latin-1")
    except UnicodeEncodeError:
        return None


def chunk(data):
    """A `tcp` step chunk: readable text when it survives the step's placeholder substitution and UTF-8 encoding,
    base64 otherwise."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return base64.b64encode(data).decode()
    if "{{" in text:
        return base64.b64encode(data).decode()
    return {"text": text}


def wire_request(case):
    """The raw HTTP/1.1 bytes of the recorded Netty request, or (None, reason). Headers keep their case and order; the
    headers the codec removed (`preservedHeaders`) are sent after them and the body as received (`originalRawBody`);
    a body is framed by its own `content-length` or `transfer-encoding: chunked` header, else by an added
    `content-length`; `connection: close` is added (unless a `connection` header is there) so the answer ends with
    the connection."""
    method, uri, version = case["method"], case["uri"], case["version"]
    if not TOKEN.fullmatch(method):
        return None, "method not a token"
    if method == "CONNECT":
        return None, "CONNECT (a proxy tunnel, not a decoded request)"
    if version not in ("HTTP/1.1", "HTTP/1.0"):
        return None, "version " + version
    if not URI.fullmatch(uri):
        return None, "URI not valid on the wire"
    if re.match(r"(?:[a-z]+://[^/]*)?/mockserver(?:/|$)", uri) or uri.split("?")[0] in ("/expectation", "/reset", "/clear", "/retrieve", "/verify", "/verifySequence", "/status", "/bind", "/stop"):
        return None, "control-plane path"
    headers = [tuple(h) for h in case["headers"]]
    live = {n.lower() for n, _ in headers}
    headers += [tuple(h) for h in case.get("preservedHeaders") or [] if h[0].lower() not in live]
    names = [n.lower() for n, _ in headers]
    for name, value in headers:
        if not TOKEN.fullmatch(name) or re.search(r"[\r\n\x00]", value):
            return None, "header not valid on the wire"
    if "upgrade" in names:
        return None, "upgrade header (switches protocol)"
    body = base64.b64decode(case.get("body") or "")
    if case.get("originalRawBody") is not None:
        body = base64.b64decode(case["originalRawBody"])
    elif "content-encoding" in names and body and "content-encoding" not in live:
        return None, "content-encoding the codec removed, without the bytes received"
    chunked = any(n == "transfer-encoding" and "chunked" in v.lower() for n, v in headers)
    lengths = [v.strip() for n, v in headers if n.lower() == "content-length"]
    if chunked:
        headers = [(n, v) for n, v in headers if n.lower() != "content-length"]
        payload = (f"{len(body):x}\r\n".encode() + body + b"\r\n" if body else b"") + b"0\r\n\r\n"
    elif lengths:
        if len(set(lengths)) != 1 or lengths[0] != str(len(body)):
            return None, "content-length disagrees with the body"
        payload = body
    else:
        if body:
            headers.append(("content-length", str(len(body))))
        payload = body
    if "connection" not in names and version == "HTTP/1.1":
        headers.append(("connection", "close"))
    head = f"{method} {uri} {version}\r\n".encode()
    for name, value in headers:
        line = latin1(f"{name}: {value}\r\n")
        if line is None:
            return None, "header value beyond Latin-1"
        head += line
    return head + b"\r\n" + payload, None


def convert_decode(case):
    """The catch-all expectation, the request as raw HTTP/1.1 bytes (over TLS when the mapper was `isSecure`), then
    the recorded requests (`retrieve?type=REQUESTS`), which show how the server decoded it."""
    if "unserialisable" in case:
        return None, "unserialisable"
    if case.get("protocol") not in (None, "HTTP_1_1"):
        return None, "protocol " + case["protocol"]
    if case.get("clientCertificates"):
        return None, "client certificates"
    raw, reason = wire_request(case)
    if raw is None:
        return None, reason
    send = {"tcp": [chunk(raw)], "text": True, "note": "request"}
    if case.get("secure"):
        send["tls"] = True
    return [control("/mockserver/expectation", CATCH_ALL, "catch-all"), send,
            control(RETRIEVE_REQUESTS, "", "recorded requests")], None


KINDS = [Kind("decode", "B1", convert_decode, source=("codec", "decode"))]

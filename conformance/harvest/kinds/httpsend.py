"""Kind `httpsend` (B4): `NettyHttpClient.sendRequest(request[, remoteAddress, …])`, the forwarding client."""
import json
import re

from harvest import Kind, control

TRIGGER = "/harvested-httpsend"
PORT = "{{port}}"
# Test classes whose upstream is an EchoServer, which answers whatever arrives: elsewhere the upstream is a closed port,
# a raw socket faking a fault or a TLS server, and the request sent to it is no input this replay can give.
ECHO_UPSTREAM = ("org.mockserver.httpclient.netty.NettyHttpClientTest",)


def convert_httpsend(case):
    """The request as the client sent it to the test's local upstream, sent instead to the server itself: an
    `httpForwardTemplate` (Mustache, the request JSON as its literal text, so the request is forwarded as recorded and
    not merged with the trigger) answering a trigger request once, a catch-all answering the forwarded request once (its
    Host may name another host, which an unmatched request would be proxied to), then the requests the server received.
    The upstream's port, in the address and the Host header, becomes the server's own."""
    if "unserialisable" in case:
        return None, "unserialisable: " + case["unserialisable"]
    if case["test"].partition("#")[0] not in ECHO_UPSTREAM:
        return None, "the test's upstream is no echo server"
    if case.get("proxied"):
        return None, "client with proxy configurations (the upstream is a proxy)"
    request = json.loads(case["request"])
    if request.get("secure"):
        return None, "secure (the test's upstream is a TLS server of its own)"
    if request.get("protocol", "HTTP_1_1") != "HTTP_1_1":
        return None, "protocol " + request["protocol"]
    headers = request.get("headers") or {}
    if not isinstance(headers, dict):
        return None, "headers not in map form"
    host_values = next((v for k, v in headers.items() if k.lower() == "host"), None)
    port = case.get("remotePort")
    if port is None:
        if not host_values or not re.search(r":\d+$", host_values[0]):
            return None, "no destination port"
        port = int(host_values[0].rsplit(":", 1)[1])
    target_host = case.get("remoteHost")
    if target_host is None:
        target_host = host_values[0].rsplit(":", 1)[0]
    if target_host not in ("localhost", "127.0.0.1", "0.0.0.0"):
        return None, "destination " + target_host + " is not the test's local upstream"
    for name in list(headers):
        if name.lower() == "host":
            headers[name] = [re.sub(r":%d$" % port, ":" + PORT, v) for v in headers[name]]
    request.pop("socketAddress", None)
    request["socketAddress"] = {"host": target_host, "port": "PORT_PLACEHOLDER", "scheme": "HTTP"}
    template = json.dumps(request, indent=2).replace("\"PORT_PLACEHOLDER\"", PORT)
    if "{{" in template.replace(PORT, ""):
        return None, "request text holds a Mustache tag"
    trigger = {"httpRequest": {"path": TRIGGER},
               "httpForwardTemplate": {"templateType": "MUSTACHE", "template": template},
               "times": {"remainingTimes": 1}}
    target = {"httpRequest": {}, "httpResponse": {"statusCode": 200, "body": "received"}, "times": {"remainingTimes": 1}}
    return [control("/mockserver/expectation", [trigger, target], "forward template and target"),
            {"method": "GET", "path": TRIGGER, "note": "sendRequest"},
            control("/mockserver/retrieve?type=REQUESTS&format=JSON", "", "received")], None


KINDS = [Kind("httpsend", "B4", convert_httpsend)]

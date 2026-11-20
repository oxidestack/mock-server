"""Kind `fixture` (B4): `FixtureRedactor.redact`, `SseAwareExpectationConverter.convert` and
`SseBodyParser.parse`, through the MCP fixture tools."""
import hashlib
import json

from harvest import Kind, RETRIEVE_ACTIVE, control

DEFAULT_HEADERS = {"authorization", "x-api-key", "api-key", "cookie", "set-cookie", "proxy-authorization"}
DEFAULT_QUERY = {"key", "api_key", "apikey", "access_token", "token", "signature", "x-amz-signature", "x-amz-security-token", "sig"}
# the parser's fixed delay of the converter `record_llm_fixtures` builds (`new SseAwareExpectationConverter()`)
DEFAULT_DELAY = 50
MCP = "/mockserver/mcp"
SESSION_MASK = ["[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "content-length: \\d+"]


def mcp(body, note, **extra):
    step = {"method": "POST", "path": MCP, "headers": {"Mcp-Session-Id": ["{{capture:s}}"]}, "body": body, "note": note}
    step.update(extra)
    return step


def tool(name, arguments, note):
    return mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": arguments}}, note,
               compare="json")


def header_names(headers):
    if isinstance(headers, dict):
        return [n.lower() for n in headers]
    if isinstance(headers, list):
        return [str(h.get("name", "")).lower() for h in headers if isinstance(h, dict)]
    return []


def sse_text(events):
    """An `httpSseResponse`'s events as the stream the SSE handler writes."""
    blocks = []
    for e in events or []:
        lines = []
        for field in ("event", "id", "retry"):
            if e.get(field) is not None:
                lines.append(f"{field}: {e[field]}")
        if e.get("data") is not None:
            lines.extend("data: " + line for line in str(e["data"]).split("\n"))
        blocks.append("\n".join(lines) + "\n\n")
    return "".join(blocks)


def exchange(expectation):
    """The recorded exchange whose recorded expectation is `expectation`: its request, and its response (an SSE
    response as the `text/event-stream` capture it was recorded from), or (None, reason)."""
    request = expectation.get("httpRequest")
    if request is None:
        return None, "expectation without a request"
    if "httpResponse" in expectation:
        response = expectation["httpResponse"]
    elif "httpSseResponse" in expectation:
        sse = expectation["httpSseResponse"]
        response = {k: v for k, v in sse.items() if k in ("statusCode", "reasonPhrase", "headers", "cookies")}
        headers = response.get("headers") or {}
        if isinstance(headers, dict):
            headers = dict(headers, **{"Content-Type": ["text/event-stream"]})
        else:
            headers = headers + [{"name": "Content-Type", "values": ["text/event-stream"]}]
        response["headers"] = headers
        response["body"] = sse_text(sse.get("events"))
    else:
        return None, "expectation without a response action"
    return {"httpRequest": request, "httpResponse": response}, None


def convert_fixture(case):
    """The inputs as recorded traffic (`PUT /mockserver/import?format=recording&redactSensitiveData=false`, so the
    importer stores them as given), then MCP `record_llm_fixtures` to a file of the case's own (which converts SSE
    captures with the default parser and redacts with the default headers plus the redactor's body fields),
    `load_expectations_from_file` and the active expectations. A redactor with other headers is only replayed when
    no header of the inputs is in the difference; other query parameters or a parser with another fixed delay have no
    wire form."""
    if "unserialisable" in case:
        return None, "unserialisable"
    call = case["call"]
    body_fields = []
    if call.startswith("SseBodyParser."):
        if case["interEventDelayMs"] != DEFAULT_DELAY:
            return None, "parser with a non-default inter-event delay (no wire form)"
        delays = case.get("perChunkDelaysMs")
        if delays is not None and any(d is None for d in delays):
            return None, "null per-chunk delay"
        headers = {"Content-Type": ["text/event-stream"]}
        if delays:
            headers["x-mockserver-chunk-delays-ms"] = [",".join(delays)]
        response = {"statusCode": 200, "headers": headers}
        if case.get("text") is not None:
            response["body"] = case["text"]
        exchanges = [{"httpRequest": {"method": "GET", "path": "/sse"}, "httpResponse": response}]
    else:
        if call.startswith("SseAwareExpectationConverter.") and case["interEventDelayMs"] != DEFAULT_DELAY:
            return None, "converter with a non-default inter-event delay (no wire form)"
        expectations = [json.loads(e) if e is not None else None for e in case["expectations"] or []]
        if any(e is None for e in expectations):
            return None, "null expectation in the array"
        if call.startswith("FixtureRedactor."):
            if {q.lower() for q in case["sensitiveQueryParams"]} != DEFAULT_QUERY:
                return None, "redactor with other sensitive query parameters (no wire form)"
            difference = {h.lower() for h in case["sensitiveHeaders"]} ^ DEFAULT_HEADERS
            for e in expectations:
                names = header_names((e.get("httpRequest") or {}).get("headers"))
                for action in ("httpResponse", "httpSseResponse"):
                    names += header_names((e.get(action) or {}).get("headers"))
                if difference & set(names):
                    return None, "redactor with other sensitive headers, present in the input (no wire form)"
            body_fields = list(case["sensitiveBodyFields"])
        exchanges = []
        for e in expectations:
            pair, reason = exchange(e)
            if pair is None:
                return None, reason
            exchanges.append(pair)
    ndjson = "".join(json.dumps(p, separators=(",", ":")) + "\n" for p in exchanges)
    name = hashlib.sha1(json.dumps([ndjson, body_fields]).encode()).hexdigest()[:12]
    path = f"/tmp/msrs-fixture-{name}.json"
    steps = [
        {"method": "POST", "path": MCP, "body": {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
         "capture": [{"headerRegex": ["Mcp-Session-Id", "(.+)"], "as": "s"}], "mask": SESSION_MASK, "note": "MCP session"},
        mcp({"jsonrpc": "2.0", "method": "notifications/initialized"}, "MCP initialized"),
    ]
    if exchanges:
        steps.append(control("/mockserver/import?format=recording&redactSensitiveData=false", ndjson, "the inputs as recorded traffic"))
    arguments = {"path": path}
    if body_fields:
        arguments["redactBodyFields"] = body_fields
    steps.append(tool("record_llm_fixtures", arguments, call))
    if exchanges:
        steps.append(tool("load_expectations_from_file", {"path": path}, "the fixture read back"))
        steps.append(control(RETRIEVE_ACTIVE, "", "the fixture's expectations"))
        steps.append({"deleteFile": path, "note": "clean up"})
    return steps, None


KINDS = [Kind("fixture", "B4", convert_fixture)]

"""Kinds `llmreport`, `llmsniff`, `llmdecode` (B4): captured LLM traffic as the optimisation report sees
it. Each case re-imports its exchanges into the event log (`PUT /mockserver/import?format=recording`, which records
them as forwarded exchanges, the latency as the logged response's `x-mockserver-response-time-ms`) and reads them
back through `GET /mockserver/llm/optimisationReport`:

  llmreport  `LlmOptimisationReportService.build`, `LlmOptimisationReportBuilder.build`, `LlmDatasetExporter.export`
             (advice/LlmReportAdvice.java): the exchanges, then the report as JSON, Markdown brief, CSV and the
             fine-tune dataset (an exporter call: its own dataset format), with the service's filter as the query
  llmsniff   the public static `LlmProviderSniffer` detection methods: one exchange built from the arguments (a host
             as the `Host` header, a path as the path), then the JSON report, whose calls name the detected provider
             (`detectForAnalysis`: the host, then the path, then the body shapes) and the model
  llmdecode  `ProviderCodec.decode(request)` calls of llmcodec.jsonl: the request, completed with its provider's
             endpoint path and host when it has none, then the JSON report (message count, system prompt
             fingerprint, tool calls, defined tools) and the fine-tune dataset (the decoded messages)
"""
import json

from harvest import Kind

REPORT = "/mockserver/llm/optimisationReport"
IMPORT = "/mockserver/import?format=recording"
REPORT_MASKS = [
    "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    {"regex": "\"generatedAt\" : \"[^\"]+\"", "replace": "\"generatedAt\" : \"<time>\""},
    {"regex": "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z", "replace": "<ts>"},
]
DATASET_FORMATS = {"OPENAI_EVALS": "openai-evals", "FINE_TUNE": "fine-tune", "PROMPTFOO": "promptfoo"}

# Where a provider's request goes (`LlmProviderSniffer.sniffByHostAndPath` / `sniffByPath`), for a decoded request
# that names neither: (path, Host header or None). Ollama has no well-known host; its path alone is detected.
ENDPOINTS = {
    "OPENAI": ("/v1/chat/completions", "api.openai.com"),
    "OPENAI_RESPONSES": ("/v1/responses", "api.openai.com"),
    "ANTHROPIC": ("/v1/messages", "api.anthropic.com"),
    "AZURE_OPENAI": ("/openai/deployments/gpt-4o/chat/completions?api-version=2024-06-01", "harvested.openai.azure.com"),
    "GEMINI": ("/v1beta/models/gemini-2.0-flash:generateContent", "generativelanguage.googleapis.com"),
    "OLLAMA": ("/api/chat", None),
    "BEDROCK": ("/model/anthropic.claude-3-5-sonnet-20240620-v1:0/invoke", "bedrock-runtime.us-east-1.amazonaws.com"),
    "COHERE": ("/v2/chat", "api.cohere.com"),
    "MISTRAL": ("/v1/chat/completions", "api.mistral.ai"),
    "XAI": ("/v1/chat/completions", "api.x.ai"),
    "DEEPSEEK": ("/chat/completions", "api.deepseek.com"),
    "GROQ": ("/openai/v1/chat/completions", "api.groq.com"),
    "OPENROUTER": ("/api/v1/chat/completions", "openrouter.ai"),
    "ORCAROUTER": ("/v1/chat/completions", "api.orcarouter.ai"),
    "VOYAGE": ("/v1/rerank", "api.voyageai.com"),
}


def has_header(message, name):
    headers = message.get("headers")
    if isinstance(headers, dict):
        return any(k.lower() == name.lower() for k in headers)
    if isinstance(headers, list):
        return any(str(h.get("name", "")).lower() == name.lower() for h in headers)
    return False


def add_header(message, name, value):
    headers = message.get("headers")
    if headers is None:
        message["headers"] = {name: [value]}
    elif isinstance(headers, dict):
        message["headers"] = dict(headers, **{name: [value]})
    else:
        message["headers"] = headers + [{"name": name, "values": [value]}]


def exchange_line(request, response, latency=None):
    """One NDJSON line of the recorded-traffic archive."""
    if latency is not None and not has_header(response, "x-mockserver-response-time-ms"):
        response = dict(response)
        add_header(response, "x-mockserver-response-time-ms", str(latency))
    return json.dumps({"httpRequest": request, "httpResponse": response}, ensure_ascii=False, separators=(",", ":"))


def import_step(lines):
    return {"method": "PUT", "path": IMPORT, "body": "\n".join(lines) + "\n", "note": "import",
            "mask": [{"regex": "\"x-mockserver-response-time-ms\" : \\[ \"\\d+\" \\]", "replace": "\"x-mockserver-response-time-ms\" : [ \"<n>\" ]"}]}


def report_step(fmt, query=None):
    params = ([("format", fmt)] if fmt != "json" else []) + list(query or [])
    path = REPORT + ("?" + "&".join(f"{k}={v}" for k, v in params) if params else "")
    return {"method": "GET", "path": path, "note": fmt, "mask": REPORT_MASKS}


def properties(case):
    return dict(case["configuration"]) if case.get("configuration") else None


def convert_llmreport(case):
    if "unserialisable" in case:
        return None, "unserialisable"
    if case.get("customRedactor"):
        return None, "a redactor with non-default sensitive headers (the configuration sets body fields only)"
    if case.get("exchanges") is None:
        return None, "null exchanges"
    lines = []
    for x in case["exchanges"]:
        # the service, the builder and the exporter all skip an exchange without a request or a response
        if x.get("null") or x.get("request") is None or x.get("response") is None:
            continue
        lines.append(exchange_line(json.loads(x["request"]), json.loads(x["response"]), x.get("latencyMs")))
    steps = [import_step(lines)] if lines else []
    if case["call"] == "dataset":
        if case.get("format") is None:
            return None, "null dataset format"
        return steps + [report_step(DATASET_FORMATS[case["format"]])], None
    query = []
    for name, value in (case.get("filter") or {}).items():
        if value is not None and value.strip():
            if not all(c.isalnum() or c in ".-_:" for c in value):
                return None, "filter value not plain"
            query.append((name, value))
    return steps + [report_step(f, query) for f in ("json", "markdown", "csv", "fine-tune")], None


def convert_llmsniff(case):
    if "unserialisable" in case:
        return None, "unserialisable"
    call = case["call"]
    response = {"statusCode": 200}
    if call == "extractModelFromResponse":
        return None, "extractModelFromResponse (the report reads a response's model only for a detected request)"
    if call in ("sniffByHost", "sniffByHostAndPath"):
        request = {"method": "POST", "path": case.get("path") or "/"}
        if case.get("host"):
            request["headers"] = {"Host": [case["host"]]}
    else:
        if case.get("request") is None:
            return None, "null request"
        request = json.loads(case["request"])
        request.setdefault("method", "POST")
        request.setdefault("path", "/")
        if case.get("response"):
            response = json.loads(case["response"])
    return [import_step([exchange_line(request, response)]), report_step("json")], None


def convert_llmdecode(case):
    if "unserialisable" in case:
        return None, "unserialisable"
    if case.get("call") != "decode":
        return None, "not decode"
    if case.get("request") is None:
        return None, "null request"
    request = json.loads(case["request"])
    path, host = ENDPOINTS.get(case["provider"], (None, None))
    if path is None:
        return None, "no endpoint for " + case["provider"]
    request.setdefault("method", "POST")
    if "path" not in request:
        request["path"] = path
        if host and not has_header(request, "Host") and "socketAddress" not in request:
            add_header(request, "Host", host)
    return [import_step([exchange_line(request, {"statusCode": 200})]), report_step("json"), report_step("fine-tune")], None


KINDS = [
    Kind("llmreport", "B4", convert_llmreport, source=("llm", "llmreport"), properties=properties, own_file="-default"),
    Kind("llmsniff", "B4", convert_llmsniff, source=("llm", "llmsniff"), properties=properties, own_file="-default"),
    Kind("llmdecode", "B4", convert_llmdecode, source=("llm", "llmcodec"), properties=properties, own_file="-default",
         group=lambda lines: [line for line in lines if line.get("call") == "decode"]),
]

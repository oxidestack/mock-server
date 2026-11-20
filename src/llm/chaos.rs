//! `httpLlmResponse.chaos` and `contentFilter`: provider-shaped injected errors (`LlmErrorBody`, `LlmErrorBodies`),
//! stateful request and token quotas (`LlmQuotaRegistry`), provider rate-limit headers (`LlmRateLimitHeaders`),
//! content-filter blocks and Azure annotations (`LlmContentFilterBodies`), and streaming truncation.

use std::collections::HashMap;

use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use crate::action::SseEvent;

/// `LlmChaosProfile`.
#[derive(Debug, Clone, Default)]
pub struct Chaos {
    pub error_status: Option<i64>,
    pub retry_after: Option<String>,
    pub error_probability: Option<f64>,
    pub truncate_mid_stream: bool,
    pub truncate_at_fraction: Option<f64>,
    pub malformed_sse: bool,
    pub seed: Option<i64>,
    pub quota_name: Option<String>,
    pub quota_limit: Option<i64>,
    pub quota_window_millis: Option<i64>,
    pub quota_error_status: Option<i64>,
    pub token_quota_limit: Option<i64>,
    pub token_quota_window_millis: Option<i64>,
    pub error_kind: Option<String>,
    pub content_filter_block_probability: Option<f64>,
}

impl Chaos {
    pub fn parse(v: &Value) -> Chaos {
        let int = |k: &str| v.get(k).and_then(Value::as_i64);
        let float = |k: &str| v.get(k).and_then(Value::as_f64);
        let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        Chaos {
            error_status: int("errorStatus"),
            retry_after: text("retryAfter"),
            error_probability: float("errorProbability"),
            truncate_mid_stream: v.get("truncateMode").and_then(Value::as_str) == Some("MID_STREAM"),
            truncate_at_fraction: float("truncateAtFraction"),
            malformed_sse: v.get("malformedSse").and_then(Value::as_bool) == Some(true),
            seed: int("seed"),
            quota_name: text("quotaName"),
            quota_limit: int("quotaLimit"),
            quota_window_millis: int("quotaWindowMillis"),
            quota_error_status: int("quotaErrorStatus"),
            token_quota_limit: int("tokenQuotaLimit"),
            token_quota_window_millis: int("tokenQuotaWindowMillis"),
            error_kind: text("errorKind"),
            content_filter_block_probability: float("contentFilterBlockProbability"),
        }
    }
}

/// `LlmContentFilter`: a severity per category.
#[derive(Debug, Clone, Default)]
pub struct ContentFilter {
    hate: Option<String>,
    sexual: Option<String>,
    violence: Option<String>,
    self_harm: Option<String>,
}

impl ContentFilter {
    pub fn parse(v: &Value) -> ContentFilter {
        let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        ContentFilter { hate: text("hate"), sexual: text("sexual"), violence: text("violence"), self_harm: text("selfHarm") }
    }

    /// `azureFilterResults`.
    fn azure_results(&self) -> Value {
        let category = |severity: &Option<String>| {
            let severity = severity.as_deref().filter(|s| !s.is_empty()).unwrap_or("safe");
            json!({"filtered": severity.eq_ignore_ascii_case("medium") || severity.eq_ignore_ascii_case("high"), "severity": severity})
        };
        json!({
            "hate": category(&self.hate),
            "self_harm": category(&self.self_harm),
            "sexual": category(&self.sexual),
            "violence": category(&self.violence),
        })
    }
}

/// A response decided before the completion is encoded.
pub struct ErrorResponse {
    pub status: u32,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// A content-filter block (`LlmContentFilterBodies.Block`), which a streaming completion may stream instead.
    pub content_filter_block: bool,
}

impl ErrorResponse {
    fn json(status: i64, body: String) -> ErrorResponse {
        ErrorResponse { status: status as u32, headers: vec![("content-type".into(), "application/json".into())], body, content_filter_block: false }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// LlmQuotaRegistry: fixed windows, one registry per server (upstream: one per JVM, one server per JVM), cleared by reset
// ---------------------------------------------------------------------------------------------------------------

/// `LlmQuotaRegistry`: each named window's start and count.
#[derive(Default)]
pub struct Quotas(Mutex<HashMap<String, (i64, i64)>>);

fn now_millis() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

/// `tryAcquire`: counts `amount` into the window (opened on first use or expiry) and whether it still fits.
fn try_acquire(quotas: &Quotas, name: &str, limit: i64, window_millis: i64, amount: i64) -> bool {
    if limit < 0 || window_millis <= 0 || amount < 0 {
        return true;
    }
    let now = now_millis();
    let mut quotas = quotas.0.lock();
    let window = quotas.entry(name.to_string()).or_insert((now, 0));
    if now - window.0 >= window_millis {
        *window = (now, 0);
    }
    window.1 += amount;
    window.1 <= limit
}

impl Quotas {
    pub fn reset(&self) {
        self.0.lock().clear();
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Error bodies
// ---------------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Overload,
    RateLimit,
    ServerError,
}

fn parse_kind(kind: Option<&str>) -> Option<Kind> {
    match kind?.trim().to_uppercase().as_str() {
        "OVERLOAD" => Some(Kind::Overload),
        "RATE_LIMIT" => Some(Kind::RateLimit),
        "SERVER_ERROR" => Some(Kind::ServerError),
        _ => None,
    }
}

/// `LlmErrorBody.bodyFor`: the provider's canned error for a kind.
fn error_shape(provider: &str, kind: Kind) -> Option<(i64, &'static str)> {
    Some(match (provider, kind) {
        ("ANTHROPIC", Kind::Overload) => (529, r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#),
        ("ANTHROPIC", Kind::RateLimit) => {
            (429, r#"{"type":"error","error":{"type":"rate_limit_error","message":"Number of requests has exceeded your rate limit. Please try again later."}}"#)
        }
        ("ANTHROPIC", Kind::ServerError) => (500, r#"{"type":"error","error":{"type":"api_error","message":"Internal server error."}}"#),
        ("BEDROCK", Kind::Overload) => (503, r#"{"__type":"ServiceUnavailableException","message":"The service is currently unavailable. Please try again later."}"#),
        ("BEDROCK", Kind::RateLimit) => (429, r#"{"__type":"ThrottlingException","message":"Too many requests, please wait before trying again."}"#),
        ("BEDROCK", Kind::ServerError) => (500, r#"{"__type":"InternalServerException","message":"An internal server error occurred."}"#),
        ("OPENAI" | "OPENAI_RESPONSES" | "AZURE_OPENAI", Kind::Overload) => {
            (503, r#"{"error":{"message":"The server is overloaded or not ready yet.","type":"server_error","param":null,"code":null}}"#)
        }
        ("OPENAI" | "OPENAI_RESPONSES" | "AZURE_OPENAI", Kind::RateLimit) => (
            429,
            r#"{"error":{"message":"Rate limit reached for requests. Please try again later.","type":"rate_limit_exceeded","param":null,"code":"rate_limit_exceeded"}}"#,
        ),
        ("OPENAI" | "OPENAI_RESPONSES" | "AZURE_OPENAI", Kind::ServerError) => {
            (500, r#"{"error":{"message":"The server had an error while processing your request.","type":"server_error","param":null,"code":null}}"#)
        }
        ("GEMINI", Kind::Overload) => (503, r#"{"error":{"code":503,"message":"The model is overloaded. Please try again later.","status":"UNAVAILABLE"}}"#),
        ("GEMINI", Kind::RateLimit) => (429, r#"{"error":{"code":429,"message":"Resource has been exhausted (e.g. check quota).","status":"RESOURCE_EXHAUSTED"}}"#),
        ("GEMINI", Kind::ServerError) => (500, r#"{"error":{"code":500,"message":"An internal error has occurred.","status":"INTERNAL"}}"#),
        ("OLLAMA", Kind::Overload) => (500, r#"{"error":"server busy, please try again"}"#),
        ("OLLAMA", Kind::RateLimit) => (429, r#"{"error":"too many requests"}"#),
        ("OLLAMA", Kind::ServerError) => (500, r#"{"error":"internal server error"}"#),
        _ => return None,
    })
}

/// `LlmErrorBodies.kindForStatus`.
fn kind_for_status(status: i64) -> Kind {
    match status {
        429 => Kind::RateLimit,
        529 => Kind::Overload,
        _ => Kind::ServerError,
    }
}

/// `LlmErrorBodies.escape`.
fn escape(message: &str) -> String {
    let mut out = String::new();
    for c in message.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// `LlmErrorBodies.bodyFor`: a provider-shaped error for a status, carrying `message`.
pub fn error_body(provider: &str, status: i64, message: &str) -> Option<String> {
    let kind = kind_for_status(status);
    let message = escape(message);
    Some(match provider {
        "ANTHROPIC" => {
            let kind = match kind {
                Kind::Overload => "overloaded_error",
                Kind::RateLimit => "rate_limit_error",
                Kind::ServerError => "api_error",
            };
            format!(r#"{{"type":"error","error":{{"type":"{kind}","message":"{message}"}}}}"#)
        }
        // `bedrockBody`: Bedrock Runtime's error names by status (InvokeModel and Converse API references).
        "BEDROCK" => {
            let kind = match status {
                400 => "ValidationException",
                403 => "AccessDeniedException",
                404 => "ResourceNotFoundException",
                408 => "ModelTimeoutException",
                424 => "ModelErrorException",
                429 => "ThrottlingException",
                503 => "ServiceUnavailableException",
                _ => match kind {
                    Kind::Overload => "ServiceUnavailableException",
                    Kind::RateLimit => "ThrottlingException",
                    Kind::ServerError => "InternalServerException",
                },
            };
            format!(r#"{{"__type":"{kind}","message":"{message}"}}"#)
        }
        "OPENAI" | "OPENAI_RESPONSES" | "AZURE_OPENAI" => {
            let (kind, code) = match kind {
                Kind::RateLimit => ("rate_limit_exceeded", "\"rate_limit_exceeded\"".to_string()),
                _ => ("server_error", status.to_string()),
            };
            format!(r#"{{"error":{{"message":"{message}","type":"{kind}","param":null,"code":{code}}}}}"#)
        }
        "GEMINI" => {
            let google = match kind {
                Kind::Overload => "UNAVAILABLE",
                Kind::RateLimit => "RESOURCE_EXHAUSTED",
                Kind::ServerError => "INTERNAL",
            };
            format!(r#"{{"error":{{"code":{status},"message":"{message}","status":"{google}"}}}}"#)
        }
        "OLLAMA" => format!(r#"{{"error":"{message}"}}"#),
        _ => return None,
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Rate-limit headers
// ---------------------------------------------------------------------------------------------------------------

/// `applyRateLimitHeaders`: the provider's rate-limit headers, and `Retry-After` on a limited response; nothing
/// without a provider (`provider` is empty).
pub fn rate_limit_headers(provider: &str, limited: bool, chaos: &Chaos) -> Vec<(String, String)> {
    if provider.is_empty() {
        // no provider, no headers (not even `Retry-After`)
        return Vec::new();
    }
    let reset = chaos
        .quota_window_millis
        .or(chaos.token_quota_window_millis)
        .map(|w| (w / 1000).max(1))
        .or_else(|| chaos.retry_after.as_deref().filter(|r| !r.is_empty()).and_then(|r| r.parse::<i64>().ok()));
    let remaining = limited.then_some(0);
    let mut headers = Vec::new();
    match provider {
        "OPENAI" | "OPENAI_RESPONSES" | "AZURE_OPENAI" => {
            if let Some(limit) = chaos.quota_limit {
                headers.push(("x-ratelimit-limit-requests".into(), limit.to_string()));
            }
            if let Some(r) = remaining {
                headers.push(("x-ratelimit-remaining-requests".into(), r.to_string()));
            }
            if let Some(reset) = reset {
                headers.push(("x-ratelimit-reset-requests".into(), format!("{reset}s")));
            }
        }
        "ANTHROPIC" => {
            if let Some(limit) = chaos.quota_limit {
                headers.push(("anthropic-ratelimit-requests-limit".into(), limit.to_string()));
            }
            if let Some(r) = remaining {
                headers.push(("anthropic-ratelimit-requests-remaining".into(), r.to_string()));
            }
            if let Some(reset) = reset {
                let at = chrono::DateTime::from_timestamp(now_millis() / 1000 + reset, 0).unwrap_or_default();
                headers.push(("anthropic-ratelimit-requests-reset".into(), at.format("%Y-%m-%dT%H:%M:%SZ").to_string()));
            }
        }
        _ => {}
    }
    if limited {
        let retry_after = chaos.retry_after.clone().filter(|r| !r.is_empty()).or_else(|| reset.map(|r| r.to_string()));
        if let Some(retry_after) = retry_after {
            headers.push(("Retry-After".into(), retry_after));
        }
    }
    headers
}

// ---------------------------------------------------------------------------------------------------------------
// chaosErrorResponseOrNull
// ---------------------------------------------------------------------------------------------------------------

const GENERIC_CHAOS_BODY: &str = r#"{"error":{"type":"chaos_injected","message":"injected chaos error"}}"#;

/// `chaosErrorResponseOrNull`: a quota breach, a content-filter block or a probabilistic provider error, in that
/// order. `request_tokens` is `estimateTokenCount` of the configured completion.
pub fn error_response(
    quotas: &Quotas,
    provider: &str,
    chaos: &Chaos,
    content_filter: Option<&ContentFilter>,
    request_tokens: i64,
    request: &crate::request::HttpRequest,
) -> Option<ErrorResponse> {
    if let Some(quota) = quota_error(quotas, provider, chaos, request_tokens) {
        return Some(quota);
    }
    if chaos.content_filter_block_probability.is_some() && crate::chaos::http::should_inject(chaos.content_filter_block_probability, chaos.seed) {
        let (status, body) = content_filter_block(provider, content_filter, request);
        return Some(ErrorResponse { content_filter_block: true, ..ErrorResponse::json(status, body) });
    }
    let kind = parse_kind(chaos.error_kind.as_deref());
    if chaos.error_status.is_none() && kind.is_none() {
        return None;
    }
    if !crate::chaos::http::should_inject(chaos.error_probability, chaos.seed) {
        return None;
    }
    let explicit = chaos.error_status;
    let (status, body) = match kind.and_then(|k| error_shape(provider, k)) {
        Some((status, body)) => (explicit.unwrap_or(status), body.to_string()),
        None => match explicit.filter(|_| kind.is_none()).and_then(|s| error_body(provider, s, "injected chaos error")) {
            Some(body) => (explicit.unwrap_or(500), body),
            None => (explicit.unwrap_or(500), GENERIC_CHAOS_BODY.to_string()),
        },
    };
    let mut response = ErrorResponse::json(status, body);
    response.headers.extend(rate_limit_headers(provider, true, chaos));
    Some(response)
}

fn quota_error(quotas: &Quotas, provider: &str, chaos: &Chaos, request_tokens: i64) -> Option<ErrorResponse> {
    let name = chaos.quota_name.as_deref()?;
    if let (Some(limit), Some(window)) = (chaos.quota_limit, chaos.quota_window_millis) && !try_acquire(quotas, name, limit, window, 1) {
        return Some(quota_response(provider, chaos, "quota_exceeded", "LLM request quota exceeded"));
    }
    if let (Some(limit), Some(window)) = (chaos.token_quota_limit, chaos.token_quota_window_millis) && !try_acquire(quotas, &format!("{name}:tokens"), limit, window, request_tokens) {
        return Some(quota_response(provider, chaos, "token_quota_exceeded", "LLM token quota exceeded"));
    }
    None
}

fn quota_response(provider: &str, chaos: &Chaos, error_type: &str, message: &str) -> ErrorResponse {
    let (status, body) = match parse_kind(chaos.error_kind.as_deref()).and_then(|k| error_shape(provider, k)) {
        Some((status, body)) => (chaos.quota_error_status.unwrap_or(status), body.to_string()),
        None => {
            let status = chaos.quota_error_status.unwrap_or(429);
            let body = error_body(provider, status, message).unwrap_or_else(|| format!(r#"{{"error":{{"type":"{error_type}","message":"{message}"}}}}"#));
            (status, body)
        }
    };
    let mut response = ErrorResponse::json(status, body);
    response.headers.extend(rate_limit_headers(provider, true, chaos));
    response
}

/// A Converse response whose output was removed by a content filter.
const BEDROCK_CONVERSE_CONTENT_FILTERED_BODY: &str =
    r#"{"output":{"message":{"role":"assistant","content":[]}},"stopReason":"content_filtered","usage":{"inputTokens":0,"outputTokens":0,"totalTokens":0},"metrics":{"latencyMs":0}}"#;

/// `LlmRefusalPresets.refusalBody(claudeApi)`: every field of the real API's `Usage`, zeroed, in its order; Bedrock
/// InvokeModel (`claude_api` false) sends no `diagnostics` and no `usage.inference_geo`.
fn refusal_body(claude_api: bool) -> String {
    let (geo, diagnostics) = if claude_api { (",\"inference_geo\":\"global\"", ",\"diagnostics\":null") } else { ("", "") };
    format!(
        "{{\"id\":\"msg_refusal\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude\",\"content\":[],\"container\":null,\"stop_reason\":\"refusal\",\"stop_sequence\":null,\"stop_details\":{},\"usage\":{{\"input_tokens\":0,\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":0,\"cache_creation\":{{\"ephemeral_5m_input_tokens\":0,\"ephemeral_1h_input_tokens\":0}},\"output_tokens\":0,\"service_tier\":\"standard\"{geo}}}{diagnostics}}}",
        super::codec::REFUSAL_STOP_DETAILS
    )
}

/// `LlmContentFilterBodies.blockFor(provider, filter, request)`: a Bedrock Converse request gets a Converse body.
fn content_filter_block(provider: &str, filter: Option<&ContentFilter>, request: &crate::request::HttpRequest) -> (i64, String) {
    match provider {
        "BEDROCK" if super::converse::is_converse(request) => (200, BEDROCK_CONVERSE_CONTENT_FILTERED_BODY.into()),
        "ANTHROPIC" | "BEDROCK" => (200, refusal_body(provider == "ANTHROPIC")),
        "AZURE_OPENAI" => {
            let default = ContentFilter { hate: Some("high".into()), ..ContentFilter::default() };
            let filter = filter.unwrap_or(&default);
            let body = json!({"error": {
                "message": "The response was filtered due to the prompt triggering Azure OpenAI's content management policy. Please modify your prompt and retry.",
                "type": null,
                "param": "prompt",
                "code": "content_filter",
                "status": 400,
                "innererror": {"code": "ResponsibleAIPolicyViolation", "content_filter_result": filter.azure_results()},
            }});
            (400, body.to_string())
        }
        "OPENAI" | "OPENAI_RESPONSES" | "MISTRAL" | "XAI" | "DEEPSEEK" | "GROQ" | "OPENROUTER" | "ORCAROUTER" => (
            400,
            r#"{"error":{"message":"The response was filtered due to the prompt triggering content management policy. Please modify your prompt and retry.","type":"invalid_request_error","param":"prompt","code":"content_filter"}}"#.into(),
        ),
        "GEMINI" => (
            200,
            r#"{"candidates":[{"finishReason":"SAFETY","index":0,"safetyRatings":[{"category":"HARM_CATEGORY_SEXUALLY_EXPLICIT","probability":"NEGLIGIBLE"},{"category":"HARM_CATEGORY_HATE_SPEECH","probability":"HIGH","blocked":true},{"category":"HARM_CATEGORY_HARASSMENT","probability":"NEGLIGIBLE"},{"category":"HARM_CATEGORY_DANGEROUS_CONTENT","probability":"NEGLIGIBLE"}]}],"usageMetadata":{"promptTokenCount":0,"totalTokenCount":0}}"#.into(),
        ),
        _ => (400, r#"{"error":{"type":"content_filter","message":"content blocked by content filter"}}"#.into()),
    }
}

/// `applyAzureContentFilterAnnotations`: Azure completions carry per-choice and prompt filter results.
pub fn annotate_azure(body: &str, filter: &ContentFilter) -> Option<String> {
    let Ok(Value::Object(mut root)) = serde_json::from_str::<Value>(body) else { return None };
    let results = filter.azure_results();
    if let Some(Value::Array(choices)) = root.get_mut("choices") {
        for choice in choices.iter_mut().filter_map(Value::as_object_mut) {
            choice.insert("content_filter_results".into(), results.clone());
        }
    }
    let mut prompt = Map::new();
    prompt.insert("prompt_index".into(), json!(0));
    prompt.insert("content_filter_results".into(), results);
    root.insert("prompt_filter_results".into(), Value::Array(vec![Value::Object(prompt)]));
    Some(Value::Object(root).to_string())
}

/// `applyStreamingChaos`: mid-stream truncation, then a malformed trailing chunk.
pub fn apply_streaming(mut events: Vec<SseEvent>, chaos: &Chaos) -> Vec<SseEvent> {
    if events.is_empty() {
        return events;
    }
    if chaos.truncate_mid_stream {
        let fraction = chaos.truncate_at_fraction.unwrap_or(0.5).clamp(0.0, 1.0);
        events.truncate((events.len() as f64 * fraction).floor() as usize);
    }
    if chaos.malformed_sse {
        events.push(SseEvent { data: Some("{\"malformed\":true".into()), ..SseEvent::default() });
    }
    events
}

/// Whether the streaming chaos changes the stream (`LLM_CHAOS_INJECTED_COUNT`).
pub fn alters_stream(chaos: &Chaos) -> bool {
    chaos.truncate_mid_stream || chaos.malformed_sse
}

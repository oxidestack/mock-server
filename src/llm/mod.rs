//! `httpLlmResponse` (`HttpLlmResponseActionHandler`): a completion encoded by the provider's codec (`codec`), as
//! one response or as its stream (SSE, NDJSON for Ollama, the AWS event stream for Bedrock), paced by the streaming
//! physics (`StreamingPhysicsExpander`), under the action's `chaos` and `contentFilter` (`chaos`); or a moderation
//! verdict, an embedding or rerank results (`vectors`).

pub mod analysis;
pub mod budget;
pub mod chaos;
pub mod client;
pub mod codec;
pub mod conversation;
pub mod converse;
pub mod report;
pub mod drift;
pub mod redact;
pub mod sigv4;
pub mod stream_usage;
pub mod responses;
pub mod service;
pub mod vectors;

use std::time::Duration;

use serde_json::Value;

use crate::action::SseEvent;

/// An `httpLlmResponse` this server can answer.
#[derive(Debug, Clone)]
pub struct Llm {
    /// `Provider`, as named in the action (`None` when it names none).
    pub provider: Option<String>,
    pub model: Option<String>,
    pub completion: Completion,
    pub chaos: Option<chaos::Chaos>,
    pub content_filter: Option<chaos::ContentFilter>,
    pub moderation: Option<vectors::Moderation>,
    pub embedding: Option<vectors::Vectors>,
    pub rerank: Option<vectors::Vectors>,
    /// The action configures a `completion` (else `completion` is empty).
    pub has_completion: bool,
}

/// `ToolUse`: a tool call the completion makes; `id` fixes the call id a client sends back.
#[derive(Debug, Clone, Default)]
pub struct ToolUse {
    pub name: String,
    pub arguments: Option<String>,
    pub id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Completion {
    pub text: Option<String>,
    pub tool_calls: Vec<ToolUse>,
    pub stop_reason: Option<String>,
    pub tool_choice: Option<String>,
    pub usage: Option<Value>,
    pub streaming: bool,
    pub physics: Option<Physics>,
    pub reasoning_text: Option<String>,
    pub reasoning_signature: Option<String>,
    pub output_schema: Option<String>,
    pub enforce_output_schema: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Physics {
    pub time_to_first_token: Option<Duration>,
    pub tokens_per_second: Option<i64>,
    pub jitter: Option<f64>,
    pub seed: Option<i64>,
    pub subword_streaming: Option<bool>,
}

impl Llm {
    /// `None` (with what is missing) when the action needs what this server does not serve.
    pub fn compile(v: &Value) -> Result<Llm, String> {
        let provider = v.get("provider").and_then(Value::as_str).map(str::to_string);
        let present = |k: &str| v.get(k).filter(|x| x.is_object());
        let empty = Value::Object(serde_json::Map::new());
        let c = present("completion").unwrap_or(&empty);
        let text = |o: &Value, k: &str| o.get(k).and_then(Value::as_str).map(str::to_string);
        let physics = c.get("streamingPhysics").filter(|p| p.is_object()).map(|p| Physics {
            time_to_first_token: p.get("timeToFirstToken").and_then(crate::action::delay).map(|d| d.fixed),
            tokens_per_second: p.get("tokensPerSecond").and_then(Value::as_i64),
            jitter: p.get("jitter").and_then(Value::as_f64),
            seed: p.get("seed").and_then(Value::as_i64),
            subword_streaming: p.get("subwordStreaming").and_then(Value::as_bool),
        });
        Ok(Llm {
            provider,
            model: text(v, "model"),
            chaos: v.get("chaos").filter(|c| c.is_object()).map(chaos::Chaos::parse),
            moderation: present("moderation").map(vectors::Moderation::parse),
            embedding: present("embedding").map(vectors::Vectors::parse),
            rerank: present("rerank").map(vectors::Vectors::parse),
            has_completion: present("completion").is_some(),
            content_filter: v.get("contentFilter").filter(|c| c.is_object()).map(chaos::ContentFilter::parse),
            completion: Completion {
                reasoning_text: text(c, "reasoningText"),
                reasoning_signature: text(c, "reasoningSignature"),
                output_schema: text(c, "outputSchema"),
                enforce_output_schema: c.get("enforceOutputSchema").and_then(Value::as_bool).unwrap_or(false),
                text: text(c, "text"),
                tool_calls: c
                    .get("toolCalls")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|t| ToolUse { name: text(t, "name").unwrap_or_default(), arguments: text(t, "arguments"), id: text(t, "id") })
                    .collect(),
                stop_reason: text(c, "stopReason"),
                tool_choice: text(c, "toolChoice"),
                usage: c.get("usage").cloned(),
                streaming: c.get("streaming").and_then(Value::as_bool).unwrap_or(false),
                physics,
            },
        })
    }

    /// `estimateTokenCount`: the configured usage, else a quarter of the text's length (the token quota's cost).
    fn configured_tokens(&self) -> i64 {
        let usage = |k: &str| self.completion.usage.as_ref().and_then(|u| u.get(k)).and_then(Value::as_i64).unwrap_or(0);
        let (input, output) = (usage("inputTokens"), usage("outputTokens"));
        if input > 0 || output > 0 {
            return input + output;
        }
        self.completion.text.as_deref().filter(|t| !t.is_empty()).map_or(0, |t| (t.encode_utf16().count() as f64 / 4.0).ceil() as i64)
    }

    /// `preEmptiveErrorResponse`: a chaos error (`true`), else a structured-output enforcement error, answered
    /// instead of the completion, and as a plain response even for a stream.
    pub fn preemptive(&self, quotas: &chaos::Quotas, request: &crate::request::HttpRequest) -> Option<(chaos::ErrorResponse, bool)> {
        let provider = self.provider.as_deref().unwrap_or_default();
        if let Some(c) = &self.chaos && let Some(error) = chaos::error_response(quotas, provider, c, self.content_filter.as_ref(), self.configured_tokens(), request) {
            return Some((error, true));
        }
        if !self.completion.enforce_output_schema || self.model_management(request) {
            return None;
        }
        let error = self.structured_output_error()?;
        let message = "structured-output enforcement failed: configured response does not conform to the declared outputSchema";
        let body = chaos::error_body(provider, 502, message)
            .unwrap_or_else(|| format!(r#"{{"error":{{"type":"structured_output_enforcement_failed","message":"{message}"}}}}"#));
        let headers = vec![("content-type".into(), "application/json".into()), (STRUCTURED_OUTPUT_INVALID_HEADER.into(), compact_header_value(&error))];
        Some((chaos::ErrorResponse { status: 502, headers, body, content_filter_block: false }, false))
    }

    /// `streamedBlockOrNull`: for a streaming completion, a content-filter block answered with HTTP 200 as the
    /// provider's stream. Anthropic and Bedrock (InvokeModel and Converse) stream an empty message whose stop reason
    /// is the refusal; Gemini streams the block body as its only chunk; any other provider answers the block whole.
    pub fn streamed_block(&self, error: &chaos::ErrorResponse, request: &crate::request::HttpRequest) -> Option<(Vec<SseEvent>, codec::Format)> {
        if !error.content_filter_block || error.status != 200 || !self.completion.streaming {
            return None;
        }
        let provider = self.provider.as_deref()?;
        let refusal = Completion { stop_reason: Some("refusal".into()), streaming: true, ..Completion::default() };
        let events = match provider {
            "ANTHROPIC" | "BEDROCK" => codec::encode_streaming(provider, &refusal, self.model_name(), request).ok()?,
            "GEMINI" => vec![SseEvent { data: Some(error.body.clone()), ..SseEvent::default() }],
            _ => return None,
        };
        let delays = physics_delays(events.len(), self.completion.physics.as_ref());
        let mut events: Vec<SseEvent> = events
            .into_iter()
            .zip(delays)
            .map(|(mut e, delay)| {
                e.delay = delay.map(|d| crate::action::Delay { fixed: d, template: None, distribution: None });
                e
            })
            .collect();
        codec::with_invocation_metrics(provider, &refusal, request, &mut events);
        Some((events, codec::streaming_format(provider, request)))
    }

    /// `structuredOutputError`: why the completion text does not conform to its `outputSchema`.
    fn structured_output_error(&self) -> Option<String> {
        let schema = self.completion.output_schema.as_deref().filter(|s| !s.trim().is_empty())?;
        let text = self.completion.text.as_deref()?;
        let schema: Value = crate::json::parse_lenient(schema.as_bytes()).ok()?;
        let validator = crate::matcher::string::validator(&schema).ok()?;
        if text.trim().is_empty() {
            return None;
        }
        let report = schema_report(&validator, &schema, text);
        (!report.is_empty()).then_some(report)
    }

    /// `withInferredUsageIfEnabled`: under `llmInferUsageEnabled`, a completion without token counts reports ones
    /// estimated from the request's conversation and its own text and tool calls.
    pub fn with_inferred_usage(&self, enabled: bool, request: &crate::request::HttpRequest) -> Option<Llm> {
        if !enabled || self.model_management(request) {
            return None;
        }
        let usage = |k: &str| self.completion.usage.as_ref().and_then(|u| u.get(k)).and_then(Value::as_i64).unwrap_or(0);
        if usage("inputTokens") > 0 || usage("outputTokens") > 0 {
            return None;
        }
        let messages = conversation::decode(self.provider.as_deref().unwrap_or_default(), request);
        let prompt: i64 = messages
            .iter()
            .map(|m| {
                3 + estimate_tokens(&m.text)
                    + m.tool_calls.iter().map(|t| estimate_tokens(&t.name) + estimate_tokens(&t.arguments)).sum::<i64>()
                    + m.tool_results.iter().map(|(_, r)| estimate_tokens(r)).sum::<i64>()
            })
            .sum();
        let completion = estimate_tokens(self.completion.text.as_deref().unwrap_or_default())
            + self.completion.tool_calls.iter().map(|t| estimate_tokens(&t.name) + estimate_tokens(t.arguments.as_deref().unwrap_or_default())).sum::<i64>();
        let mut inferred = self.clone();
        let mut usage = match &self.completion.usage {
            Some(Value::Object(o)) => o.clone(),
            _ => serde_json::Map::new(),
        };
        usage.insert("inputTokens".into(), prompt.max(0).into());
        usage.insert("outputTokens".into(), completion.into());
        inferred.completion.usage = Some(Value::Object(usage));
        Some(inferred)
    }

    /// `handle` for a non-streaming completion: the encoded body with the Azure content-filter annotations, the
    /// structured-output warning header and the chaos profile's rate-limit headers.
    pub fn respond(&self, request: &crate::request::HttpRequest, limits: vectors::Limits) -> (u32, Vec<(String, String)>, String) {
        let json_reply = |result: Result<String, String>| match result {
            Ok(body) => (200, vec![("content-type".to_string(), "application/json".to_string())], body),
            Err(e) => (400, Vec::new(), format!("{{\"error\":\"{e}\"}}")),
        };
        if let Some(provider) = self.provider.as_deref().filter(|p| codec::PROVIDERS.contains(p)) {
            if let Some(moderation) = &self.moderation {
                return json_reply(Ok(vectors::encode_moderation(moderation)));
            }
            let refused = |refusal: vectors::Refusal| match refusal {
                vectors::Refusal::Unsupported(e) => (400, Vec::new(), format!("{{\"error\":\"{e}\"}}")),
                vectors::Refusal::Invalid(e) => vectors::invalid_request(provider, &e),
            };
            if let Some(embedding) = &self.embedding {
                return vectors::encode_embedding(provider, embedding, request, self.model.as_deref(), limits).map_or_else(refused, |(body, headers)| {
                    let (status, mut all, body) = json_reply(Ok(body));
                    all.extend(headers);
                    (status, all, body)
                });
            }
            if let Some(rerank) = &self.rerank {
                return vectors::encode_rerank(provider, rerank, &vectors::request_documents(&request.body_str()), request).map_or_else(refused, |body| json_reply(Ok(body)));
            }
            if !self.has_completion {
                return (400, Vec::new(), r#"{"error":"httpLlmResponse must have either a completion, embedding, or rerank configured"}"#.into());
            }
        }
        let (status, mut body) = self.encode(request);
        if status != 200 {
            return (status, Vec::new(), body);
        }
        let provider = self.provider.as_deref().unwrap_or_default();
        let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
        headers.extend(codec::token_count_headers(provider, &self.completion, request));
        if let (Some(filter), "AZURE_OPENAI") = (&self.content_filter, provider) && let Some(annotated) = chaos::annotate_azure(&body, filter) {
            body = annotated;
        }
        if let Some(error) = self.structured_output_error().filter(|_| !self.model_management(request)) {
            headers.push((STRUCTURED_OUTPUT_INVALID_HEADER.into(), compact_header_value(&error)));
        }
        if let Some(c) = &self.chaos {
            headers.extend(chaos::rate_limit_headers(provider, false, c));
        }
        (status, headers, body)
    }

    /// `isModelManagementRequest`: an Ollama model load or unload, not traced, counted, inferred or checked.
    pub fn model_management(&self, request: &crate::request::HttpRequest) -> bool {
        codec::is_model_management(self.provider.as_deref().unwrap_or_default(), request)
    }

    fn model_name(&self) -> &str {
        self.model.as_deref().unwrap_or("unknown")
    }

    /// `handle`: the status and JSON body answering a non-streaming completion.
    pub fn encode(&self, request: &crate::request::HttpRequest) -> (u32, String) {
        let Some(provider) = self.provider.as_deref() else {
            return (400, format!("{{\"error\":\"unsupported LLM provider: null\",\"supported\":{}}}", supported_json()));
        };
        if !codec::PROVIDERS.contains(&provider) {
            return (400, format!("{{\"error\":\"unsupported LLM provider: {provider}\",\"supported\":{}}}", supported_json()));
        }
        match codec::encode(provider, &self.completion, self.model_name(), request) {
            Ok(body) => (200, body),
            Err(e) => (400, format!("{{\"error\":\"{e}\"}}")),
        }
    }

    /// `handleStreaming`: the events and their framing, paced by the physics.
    pub fn encode_streaming(&self, request: &crate::request::HttpRequest) -> Result<(Vec<SseEvent>, codec::Format), (u32, String)> {
        let provider = self.provider.as_deref().ok_or_else(|| (400, format!("{{\"error\":\"unsupported LLM provider: null\",\"supported\":{}}}", supported_json())))?;
        let events = codec::encode_streaming(provider, &self.completion, self.model_name(), request).map_err(|e| (400, format!("{{\"error\":\"{e}\"}}")))?;
        let delays = physics_delays(events.len(), self.completion.physics.as_ref());
        let mut events: Vec<SseEvent> = events
            .into_iter()
            .zip(delays)
            .map(|(mut e, delay)| {
                e.delay = delay.map(|d| crate::action::Delay { fixed: d, template: None, distribution: None });
                e
            })
            .collect();
        codec::with_invocation_metrics(provider, &self.completion, request, &mut events);
        Ok((events, codec::streaming_format(provider, request)))
    }
}

/// `JsonSchemaValidator.isValid(text, false)`: the validation report for `text`, empty when it conforms.
pub(crate) fn schema_report(validator: &jsonschema::Validator, schema: &Value, text: &str) -> String {
    match checked_schema_report(validator, schema, text) {
        Ok(report) | Err(report) => report,
    }
}

/// [`schema_report`], `Err` where `text` does not parse (upstream then logs `exception validating JSON`).
pub(crate) fn checked_schema_report(validator: &jsonschema::Validator, schema: &Value, text: &str) -> Result<String, String> {
    let lenient = jackson::json::ReadFeatures { allow_unquoted_field_names: true, allow_single_quotes: true, allow_non_numeric_numbers: true, ..Default::default() };
    match (jackson::json::read_tree(text, lenient), crate::json::parse_lenient(text.as_bytes())) {
        (Err(e), _) => Err(format!("{} - {}", e.class.rsplit('.').next().unwrap_or_default(), e.message)),
        (Ok(_), Ok(instance)) => Ok(crate::schema::value_report(Some(validator), schema, &instance)),
        (Ok(_), Err(e)) => Err(format!("JsonParseException - {e}")),
    }
}

const STRUCTURED_OUTPUT_INVALID_HEADER: &str = "x-mockserver-structured-output-invalid";

/// `compactHeaderValue`: line breaks become `; `.
fn compact_header_value(message: &str) -> String {
    let mut out = String::new();
    let mut in_break = false;
    for c in message.chars() {
        if c == '\r' || c == '\n' {
            if !in_break {
                out.push_str("; ");
            }
            in_break = true;
        } else {
            out.push(c);
            in_break = false;
        }
    }
    out.trim().to_string()
}

fn is_kana(c: char) -> bool {
    matches!(c as u32, 0x3041..=0x309F | 0x30A0..=0x30FF | 0x31F0..=0x31FF | 0xFF66..=0xFF9D)
}

/// `TokenCounter.estimateTokens`: whitespace is free but line breaks and tabs, CJK characters weigh 1.2 (kana
/// 0.5), words cost one token per five characters of each camelCase/letter/digit run, other characters one each;
/// never less than 1 for non-empty text.
pub(crate) fn estimate_tokens(text: &str) -> i64 {
    if text.is_empty() {
        return 0;
    }
    let chars: Vec<char> = text.chars().collect();
    let sub_run = |len: usize| 1.0 + (len.saturating_sub(5) as f64 / 5.0).floor();
    let connector = |c: char| matches!(c, '-' | '\'' | '\u{2019}' | '_');
    let mut tokens = 0.0;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            while i < chars.len() && chars[i].is_whitespace() {
                if matches!(chars[i], '\n' | '\t' | '\r' | '\x0C') {
                    tokens += 1.0;
                }
                i += 1;
            }
        } else if is_cjk(c) {
            while i < chars.len() && is_cjk(chars[i]) {
                tokens += if is_kana(chars[i]) { 0.5 } else { 1.2 };
                i += 1;
            }
        } else if is_word_char(c) {
            let mut prev: i32 = -1;
            let mut sub_len = 0;
            while i < chars.len() && is_word_char(chars[i]) {
                let c = chars[i];
                let kind = if connector(c) {
                    3
                } else if c.is_numeric() {
                    2
                } else if c.is_uppercase() {
                    1
                } else {
                    0
                };
                let boundary = !(prev == -1 || kind == 3 || prev == 3) && ((prev == 0 && kind == 1) || (prev <= 1 && kind == 2) || (prev == 2 && kind <= 1));
                if boundary && sub_len > 0 {
                    tokens += sub_run(sub_len);
                    sub_len = 0;
                }
                sub_len += 1;
                prev = kind;
                i += 1;
            }
            if sub_len > 0 {
                tokens += sub_run(sub_len);
            }
        } else {
            while i < chars.len() && !(chars[i].is_whitespace() || is_word_char(chars[i]) || is_cjk(chars[i])) {
                tokens += 1.0;
                i += 1;
            }
        }
    }
    ((tokens + 0.5).floor() as i64).max(1)
}

/// `supportedProvidersJson`: the registered providers by name (the registry's keys, sorted).
fn supported_json() -> String {
    let mut providers = codec::PROVIDERS.to_vec();
    providers.sort_unstable();
    Value::Array(providers.into_iter().map(|p| Value::String(p.into())).collect()).to_string()
}

fn random_id(length: usize) -> String {
    let mut id = String::new();
    while id.len() < length {
        id.push_str(&uuid::Uuid::new_v4().simple().to_string());
    }
    id.truncate(length);
    id
}

/// `JsonEscape.escape`.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 16);
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// `TokenCounter.streamingTextTokens`: subword pieces unless the physics turns `subwordStreaming` off, then each
/// word and each whitespace run on its own.
fn streaming_tokens(text: &str, physics: Option<&Physics>) -> Vec<String> {
    if physics.and_then(|p| p.subword_streaming) != Some(false) {
        return segment(text);
    }
    // `split("(?<=\\s)|(?=\\s)")`: every whitespace char alone, the runs between them whole.
    let mut out = Vec::new();
    let mut current = String::new();
    for c in text.chars() {
        if c.is_whitespace() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            out.push(c.to_string());
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

const SUBWORD_LEN: usize = 4;

fn is_cjk(c: char) -> bool {
    matches!(c as u32, 0x2E80..=0x2FDF | 0x3005 | 0x3007 | 0x3021..=0x3029 | 0x3038..=0x303B | 0x3041..=0x309F | 0x30A0..=0x30FF | 0x3100..=0x312F
        | 0x3131..=0x318E | 0x31F0..=0x31FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xA960..=0xA97F | 0xAC00..=0xD7FF | 0xF900..=0xFAFF
        | 0xFF66..=0xFFDC | 0x1100..=0x11FF | 0x20000..=0x3FFFF)
}

fn is_word_char(c: char) -> bool {
    (c.is_alphanumeric() && !is_cjk(c)) || matches!(c, '-' | '\'' | '’' | '_')
}

/// `TokenCounter.segmentForStreaming`: leading whitespace joins the next piece, words go in four-character units
/// (Java `String` units), CJK and punctuation characters one by one.
fn segment(text: &str) -> Vec<String> {
    let mut pieces = Vec::new();
    let mut pending = String::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            pending.push(c);
            i += 1;
        } else if is_word_char(c) {
            let start = i;
            while i < chars.len() && is_word_char(chars[i]) {
                i += 1;
            }
            let word: Vec<u16> = chars[start..i].iter().collect::<String>().encode_utf16().collect();
            let mut first = true;
            for unit in word.chunks(SUBWORD_LEN) {
                let unit = String::from_utf16_lossy(unit);
                if first {
                    pieces.push(format!("{}{unit}", std::mem::take(&mut pending)));
                    first = false;
                } else {
                    pieces.push(unit);
                }
            }
        } else {
            pieces.push(format!("{}{c}", std::mem::take(&mut pending)));
            i += 1;
        }
    }
    if !pending.is_empty() {
        pieces.push(pending);
    }
    pieces
}

/// `StreamingPhysicsExpander.applyPhysics`: the first event after the time to first token, the others after
/// `1000 / tokensPerSecond` ms with jitter (`java.util.Random` seeded as upstream), the sub-millisecond remainder
/// carried forward. No delays without physics.
fn physics_delays(n: usize, physics: Option<&Physics>) -> Vec<Option<Duration>> {
    let Some(p) = physics.filter(|p| p.time_to_first_token.is_some() || p.tokens_per_second.is_some() || p.jitter.is_some() || p.seed.is_some()) else {
        return vec![None; n];
    };
    let tps = p.tokens_per_second.filter(|t| *t > 0).unwrap_or(50);
    let jitter = p.jitter.unwrap_or(0.0).clamp(0.0, 1.0);
    let seed = p.seed.unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0));
    let mut random = crate::random::JavaRandom::new(seed);
    let base = 1000.0 / tps as f64;
    let mut carried = 0.0f64;
    (0..n)
        .map(|i| {
            let ms = if i == 0 {
                p.time_to_first_token.map(|d| d.as_millis() as i64).unwrap_or(0)
            } else {
                let factor = 1.0 + (random.next_double() * 2.0 * jitter - jitter);
                carried += (base * factor).max(0.0);
                let delay = carried.round() as i64;
                carried -= delay as f64;
                delay
            };
            Some(Duration::from_millis(ms.max(0) as u64))
        })
        .collect()
}


//! The provider codecs (`org.mockserver.llm.codec`): a completion encoded as each provider's response body, or as
//! its stream of events, in the key order and escaping protobuf-free Jackson writes them. Some codecs read the
//! inbound request too (`encode(completion, model, request)`): the OpenAI Responses API echoes request fields,
//! Ollama answers `/api/generate` and model loads in their own shapes, and the Chat Completions stream reports usage
//! when the request asks for it.

use serde_json::{Map, Value, json};

use super::{Completion, ToolUse, escape, random_id, streaming_tokens};
use crate::action::SseEvent;
use crate::request::HttpRequest;

/// `StreamingFormat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Sse,
    Ndjson,
    AwsEventStream,
    /// The same framing as Bedrock ConverseStream writes it: each frame's `:event-type` is the event name and its
    /// payload the event's JSON (`AWS_CONVERSE_EVENT_STREAM`).
    AwsConverseEventStream,
    /// One JSON array written incrementally: `[`, the chunks separated by `,\r\n`, then `]` (Gemini
    /// `streamGenerateContent` without `alt=sse`).
    JsonArray,
}

impl Format {
    pub fn content_type(self) -> &'static str {
        match self {
            Format::Sse => "text/event-stream",
            Format::Ndjson => "application/x-ndjson",
            Format::AwsEventStream | Format::AwsConverseEventStream => "application/vnd.amazon.eventstream",
            Format::JsonArray => "application/json",
        }
    }
}

/// `ProviderCodecRegistry`: every provider with a codec, in registration order.
pub const PROVIDERS: &[&str] =
    &["OPENAI", "OPENAI_RESPONSES", "ANTHROPIC", "AZURE_OPENAI", "BEDROCK", "GEMINI", "OLLAMA", "COHERE", "VOYAGE", "MISTRAL", "XAI", "DEEPSEEK", "GROQ", "OPENROUTER", "ORCAROUTER"];

/// The OpenAI Chat Completions wire format, which the OpenAI-compatible providers share.
fn chat_compatible(provider: &str) -> bool {
    matches!(provider, "OPENAI" | "AZURE_OPENAI" | "MISTRAL" | "XAI" | "DEEPSEEK" | "GROQ" | "OPENROUTER" | "ORCAROUTER")
}

/// `streamingFormat(request)`.
pub fn streaming_format(provider: &str, request: &HttpRequest) -> Format {
    match provider {
        "OLLAMA" => Format::Ndjson,
        "BEDROCK" if super::converse::is_converse(request) => Format::AwsConverseEventStream,
        "BEDROCK" => Format::AwsEventStream,
        "GEMINI" if request.path.contains(":streamGenerateContent") => {
            if crate::request::first(&request.query, "alt").is_some_and(|alt| alt.eq_ignore_ascii_case("sse")) { Format::Sse } else { Format::JsonArray }
        }
        _ => Format::Sse,
    }
}

fn tokens(c: &Completion, key: &str) -> Option<i64> {
    c.usage.as_ref().and_then(|u| u.get(key)).and_then(Value::as_i64)
}

fn nonzero(c: &Completion, key: &str) -> Option<i64> {
    tokens(c, key).filter(|n| *n != 0)
}

fn event(name: Option<&str>, data: String) -> SseEvent {
    SseEvent { event: name.map(str::to_string), data: Some(data), id: None, retry: None, delay: None }
}

/// A Java `double` as Jackson writes it (`Double.toString`).
fn double(v: f64) -> Value {
    crate::model::number(&java_compat::double_to_string(v))
}

/// The configured `ToolUse.id`, else a generated one with `prefix`.
fn tool_id(tool: &ToolUse, prefix: &str) -> String {
    tool.id.clone().filter(|id| !id.is_empty()).unwrap_or_else(|| format!("{prefix}{}", random_id(24)))
}

/// The request body as a JSON object, else an empty object (`EmbeddingWire.body`).
pub(crate) fn request_object(request: &HttpRequest) -> Map<String, Value> {
    match serde_json::from_str::<Value>(&request.body_str()) {
        Ok(Value::Object(o)) => o,
        _ => Map::new(),
    }
}

/// `encode`: the whole completion as the provider's JSON body; `Err` with the codec's refusal.
pub fn encode(provider: &str, c: &Completion, model: &str, request: &HttpRequest) -> Result<String, String> {
    let body = match provider {
        p if chat_compatible(p) => openai_chat(p, c, model),
        "BEDROCK" if super::converse::is_converse(request) => return Ok(super::converse::encode(c)),
        "ANTHROPIC" | "BEDROCK" => anthropic(c, model, provider == "ANTHROPIC"),
        "OPENAI_RESPONSES" => openai_responses(c, model, &request_object(request)),
        "GEMINI" => gemini(c, model),
        "OLLAMA" => return Ok(ollama::encode(c, model, request).to_string()),
        other => return Err(format!("encode not implemented for provider {other}")),
    };
    Ok(body.to_string())
}

/// `encodeStreaming`: the provider's stream events (physics not yet applied).
pub fn encode_streaming(provider: &str, c: &Completion, model: &str, request: &HttpRequest) -> Result<Vec<SseEvent>, String> {
    Ok(match provider {
        p if chat_compatible(p) => openai_chat_stream(p, c, model, include_usage_requested(request)),
        "BEDROCK" if super::converse::is_converse(request) => super::converse::encode_streaming(c),
        "ANTHROPIC" | "BEDROCK" => anthropic_stream(c, model, provider == "ANTHROPIC"),
        "OPENAI_RESPONSES" => openai_responses_stream(c, model, &request_object(request)),
        "GEMINI" => gemini_stream(c, model),
        "OLLAMA" => ollama::encode_streaming(c, model, request),
        other => return Err(format!("encodeStreaming not implemented for provider {other}")),
    })
}

// ------------------------------------------------------------ OpenAI Chat Completions (and compatible providers)

fn openai_finish_reason(c: &Completion) -> String {
    let has_tools = !c.tool_calls.is_empty();
    if has_tools && c.tool_choice.as_deref().is_some_and(|t| t.eq_ignore_ascii_case("required")) {
        return "tool_calls".into();
    }
    match c.stop_reason.as_deref() {
        None if has_tools => "tool_calls".into(),
        None => "stop".into(),
        Some("end_turn") => "stop".into(),
        Some("tool_use") => "tool_calls".into(),
        Some("max_tokens") => "length".into(),
        Some(other) => other.into(),
    }
}

/// `emitsChoiceLogprobs`: OpenAI and Azure OpenAI always; of the compatible providers DeepSeek, Groq and OpenRouter.
fn emits_logprobs(provider: &str) -> bool {
    matches!(provider, "OPENAI" | "AZURE_OPENAI" | "DEEPSEEK" | "GROQ" | "OPENROUTER")
}

/// `reasoningField`: the message and delta field carrying the reasoning text.
fn reasoning_field(provider: &str) -> Option<&'static str> {
    match provider {
        "DEEPSEEK" | "XAI" => Some("reasoning_content"),
        "GROQ" | "OPENROUTER" => Some("reasoning"),
        _ => None,
    }
}

/// `OpenRouterCodec.normalise`: the other providers' stop reasons as OpenRouter's values.
fn openrouter_normalise(reason: &str) -> String {
    match reason {
        "end_turn" | "stop_sequence" | "STOP" | "completed" => "stop",
        "max_tokens" | "MAX_TOKENS" | "model_context_window_exceeded" => "length",
        "tool_use" | "function_call" => "tool_calls",
        "refusal" | "content_filtered" | "guardrail_intervened" | "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII" => "content_filter",
        other => other,
    }
    .to_string()
}

fn chat_finish_reason(provider: &str, c: &Completion) -> String {
    let reason = openai_finish_reason(c);
    if provider == "OPENROUTER" { openrouter_normalise(&reason) } else { reason }
}

/// `OpenRouterCodec.nativeFinishReason`: the configured stop reason when it normalises to the one sent.
fn native_finish_reason(c: &Completion, finish: &str) -> String {
    match c.stop_reason.as_deref().filter(|r| !r.is_empty()) {
        Some(configured) if openrouter_normalise(configured) == finish => configured.to_string(),
        _ => finish.to_string(),
    }
}

/// `streamChoiceFields`: members added after `finish_reason` to every streamed choice.
fn stream_choice_fields(provider: &str, c: &Completion, finish: Option<&str>) -> String {
    if provider != "OPENROUTER" {
        return String::new();
    }
    match finish {
        None => ",\"native_finish_reason\":null".into(),
        Some(f) => format!(",\"native_finish_reason\":\"{}\"", escape(&native_finish_reason(c, f))),
    }
}

/// `includeUsageRequested`: the request body sets `stream_options.include_usage` to JSON `true`.
fn include_usage_requested(request: &HttpRequest) -> bool {
    request_object(request).get("stream_options").and_then(|o| o.get("include_usage")).and_then(Value::as_bool) == Some(true)
}

fn int_at(usage: &Map<String, Value>, path: &[&str]) -> i64 {
    let mut v = usage.get(path[0]);
    for key in &path[1..] {
        v = v.and_then(|x| x.get(*key));
    }
    v.and_then(Value::as_i64).unwrap_or(0)
}

/// `usageNode`, with the provider's `addUsageFields`.
fn chat_usage(provider: &str, c: &Completion, model: &str) -> Map<String, Value> {
    let (prompt, completion) = (tokens(c, "inputTokens").unwrap_or(0), tokens(c, "outputTokens").unwrap_or(0));
    let mut usage = Map::new();
    usage.insert("prompt_tokens".into(), prompt.into());
    usage.insert("completion_tokens".into(), completion.into());
    usage.insert("total_tokens".into(), (prompt + completion).into());
    if let Some(cached) = nonzero(c, "cachedInputTokens") {
        usage.insert("prompt_tokens_details".into(), json!({"cached_tokens": cached}));
    }
    if let Some(reasoning) = nonzero(c, "reasoningTokens") {
        usage.insert("completion_tokens_details".into(), json!({"reasoning_tokens": reasoning}));
    }
    match provider {
        "DEEPSEEK" => {
            let cache_hit = prompt.min(int_at(&usage, &["prompt_tokens_details", "cached_tokens"]));
            usage.insert("prompt_tokens_details".into(), json!({"cached_tokens": cache_hit}));
            usage.insert("prompt_cache_hit_tokens".into(), cache_hit.into());
            usage.insert("prompt_cache_miss_tokens".into(), (prompt - cache_hit).into());
        }
        "XAI" => {
            let reasoning = int_at(&usage, &["completion_tokens_details", "reasoning_tokens"]);
            let cached = int_at(&usage, &["prompt_tokens_details", "cached_tokens"]);
            let completion_tokens = (completion - reasoning).max(0);
            usage.insert("completion_tokens".into(), completion_tokens.into());
            usage.insert("total_tokens".into(), (prompt + completion_tokens + reasoning).into());
            usage.insert("prompt_tokens_details".into(), json!({"text_tokens": prompt, "audio_tokens": 0, "image_tokens": 0, "cached_tokens": cached}));
            usage.insert(
                "completion_tokens_details".into(),
                json!({"reasoning_tokens": reasoning, "audio_tokens": 0, "accepted_prediction_tokens": 0, "rejected_prediction_tokens": 0}),
            );
            usage.insert("num_sources_used".into(), 0.into());
        }
        "GROQ" => {
            let mut prompt_time = 0.0;
            let mut completion_time = 0.0;
            if let Some(p) = &c.physics {
                if let Some(ttft) = p.time_to_first_token {
                    prompt_time = ttft.as_millis() as f64 / 1000.0;
                }
                if let Some(tps) = p.tokens_per_second.filter(|t| *t > 0) {
                    completion_time = completion as i32 as f64 / tps as i32 as f64;
                }
            }
            usage.insert("queue_time".into(), double(0.0));
            usage.insert("prompt_time".into(), double(prompt_time));
            usage.insert("completion_time".into(), double(completion_time));
            usage.insert("total_time".into(), double(prompt_time + completion_time));
        }
        "OPENROUTER" => {
            if let Some(cost) = super::report::estimate_cost("OPENROUTER", Some(model), prompt, completion) {
                usage.insert("cost".into(), double(cost));
            }
            usage.insert("is_byok".into(), false.into());
            let cached = int_at(&usage, &["prompt_tokens_details", "cached_tokens"]);
            let reasoning = int_at(&usage, &["completion_tokens_details", "reasoning_tokens"]);
            usage.insert("prompt_tokens_details".into(), json!({"cached_tokens": cached}));
            usage.insert("completion_tokens_details".into(), json!({"reasoning_tokens": reasoning}));
        }
        _ => {}
    }
    usage
}

fn openai_chat(provider: &str, c: &Completion, model: &str) -> Value {
    let has_tools = !c.tool_calls.is_empty();
    let mut root = Map::new();
    root.insert("id".into(), format!("chatcmpl-{}", random_id(29)).into());
    root.insert("object".into(), "chat.completion".into());
    root.insert("created".into(), chrono::Utc::now().timestamp().into());
    root.insert("model".into(), model.into());
    if provider == "DEEPSEEK" {
        root.insert("system_fingerprint".into(), format!("fp_{}", random_id(10)).into());
    }
    let mut message = Map::new();
    message.insert("role".into(), "assistant".into());
    message.insert("content".into(), if c.text.is_none() && has_tools { Value::Null } else { c.text.clone().unwrap_or_default().into() });
    if let (Some(field), Some(reasoning)) = (reasoning_field(provider), c.reasoning_text.as_deref().filter(|r| !r.is_empty())) {
        message.insert(field.into(), reasoning.into());
    }
    if has_tools {
        let calls: Vec<Value> = c
            .tool_calls
            .iter()
            .map(|t| json!({"id": tool_id(t, "call_"), "type": "function", "function": {"name": t.name, "arguments": t.arguments.clone().unwrap_or_else(|| "{}".into())}}))
            .collect();
        message.insert("tool_calls".into(), Value::Array(calls));
    }
    let mut choice = Map::new();
    choice.insert("index".into(), 0.into());
    choice.insert("message".into(), Value::Object(message));
    if emits_logprobs(provider) {
        choice.insert("logprobs".into(), Value::Null);
    }
    let finish = chat_finish_reason(provider, c);
    choice.insert("finish_reason".into(), finish.clone().into());
    if provider == "OPENROUTER" {
        choice.insert("native_finish_reason".into(), native_finish_reason(c, &finish).into());
    }
    root.insert("choices".into(), Value::Array(vec![Value::Object(choice)]));
    root.insert("usage".into(), Value::Object(chat_usage(provider, c, model)));
    if provider == "GROQ" {
        root.insert("x_groq".into(), json!({"id": format!("req_{}", random_id(26))}));
    }
    Value::Object(root)
}

fn openai_chat_stream(provider: &str, c: &Completion, model: &str, include_usage_requested: bool) -> Vec<SseEvent> {
    let include_usage = match provider {
        "MISTRAL" => false,
        "OPENROUTER" => true,
        _ => include_usage_requested,
    };
    // `streamsUsageOnFinishChunk`: DeepSeek always sends the usage on its finish chunk and no separate usage chunk;
    // `include_usage` only adds `"usage": null` to the other chunks
    let usage_on_finish_chunk = provider == "DEEPSEEK";
    let id = format!("chatcmpl-{}", random_id(29));
    let request_id = (provider == "GROQ").then(|| format!("req_{}", random_id(26)));
    let fingerprint = (provider == "DEEPSEEK").then(|| format!("fp_{}", random_id(10)));
    let created = chrono::Utc::now().timestamp();
    let mut prefix = format!("{{\"id\":\"{id}\",\"object\":\"chat.completion.chunk\",\"created\":{created},\"model\":\"{}\",", escape(model));
    if let Some(fp) = &fingerprint {
        prefix.push_str(&format!("\"system_fingerprint\":\"{}\",", escape(fp)));
    }
    let usage = Value::Object(chat_usage(provider, c, model));
    let chunk = |delta: &str, finish: Option<&str>, choice_fields: &str, extra: &str| {
        let usage_null = if include_usage && !(usage_on_finish_chunk && finish.is_some()) { ",\"usage\":null" } else { "" };
        let finish = finish.map(|f| format!("\"{}\"", escape(f))).unwrap_or_else(|| "null".into());
        format!("{prefix}\"choices\":[{{\"index\":0,\"delta\":{delta},\"finish_reason\":{finish}{choice_fields}}}]{usage_null}{extra}}}")
    };
    let open_fields = stream_choice_fields(provider, c, None);
    let first_extra = request_id.as_ref().map(|r| format!(",\"x_groq\":{{\"id\":\"{r}\"}}")).unwrap_or_default();
    let mut data = vec![chunk("{\"role\":\"assistant\",\"content\":\"\"}", None, &open_fields, &first_extra)];
    if let (Some(field), Some(reasoning)) = (reasoning_field(provider), c.reasoning_text.as_deref().filter(|r| !r.is_empty())) {
        for token in streaming_tokens(reasoning, c.physics.as_ref()).into_iter().filter(|t| !t.is_empty()) {
            data.push(chunk(&format!("{{\"{field}\":\"{}\"}}", escape(&token)), None, &open_fields, ""));
        }
    }
    if let Some(text) = c.text.as_deref().filter(|t| !t.is_empty()) {
        for token in streaming_tokens(text, c.physics.as_ref()).into_iter().filter(|t| !t.is_empty()) {
            data.push(chunk(&format!("{{\"content\":\"{}\"}}", escape(&token)), None, &open_fields, ""));
        }
    }
    for (i, tool) in c.tool_calls.iter().enumerate() {
        let args = tool.arguments.clone().unwrap_or_else(|| "{}".into());
        data.push(chunk(
            &format!(
                "{{\"tool_calls\":[{{\"index\":{i},\"id\":\"{}\",\"type\":\"function\",\"function\":{{\"name\":\"{}\",\"arguments\":\"{}\"}}}}]}}",
                escape(&tool_id(tool, "call_")),
                escape(&tool.name),
                escape(&args)
            ),
            None,
            &open_fields,
            "",
        ));
    }
    let finish = chat_finish_reason(provider, c);
    let finish_extra = match provider {
        "MISTRAL" => format!(",\"usage\":{usage}"),
        "GROQ" => format!(",\"x_groq\":{{\"id\":\"{}\",\"usage\":{usage}}}", request_id.as_deref().unwrap_or_default()),
        "DEEPSEEK" => format!(",\"usage\":{usage}"),
        _ => String::new(),
    };
    data.push(chunk("{}", Some(&finish), &stream_choice_fields(provider, c, Some(&finish)), &finish_extra));
    if include_usage && !usage_on_finish_chunk {
        let choices = if provider == "OPENROUTER" {
            format!(
                "[{{\"index\":0,\"delta\":{{\"content\":\"\",\"role\":\"assistant\"}},\"finish_reason\":\"{}\"{}}}]",
                escape(&finish),
                stream_choice_fields(provider, c, Some(&finish))
            )
        } else {
            "[]".into()
        };
        data.push(format!("{prefix}\"choices\":{choices},\"usage\":{usage}}}"));
    }
    data.push("[DONE]".into());
    data.into_iter().map(|d| event(None, d)).collect()
}

// ------------------------------------------------------------ Anthropic (and Bedrock)

/// `AnthropicCodec.mapStopReason`: the other providers' values as Anthropic's.
fn anthropic_stop(c: &Completion) -> String {
    match c.stop_reason.as_deref() {
        None if c.tool_calls.is_empty() => "end_turn",
        None => "tool_use",
        Some("stop" | "STOP") => "end_turn",
        Some("length" | "MAX_TOKENS") => "max_tokens",
        Some("tool_calls" | "function_call") => "tool_use",
        Some("content_filter" | "content_filtered" | "guardrail_intervened" | "SAFETY") => "refusal",
        Some(other) => other,
    }
    .to_string()
}

/// `AnthropicCodec.REFUSAL_STOP_DETAILS`.
pub(crate) const REFUSAL_STOP_DETAILS: &str = "{\"type\":\"refusal\",\"category\":null,\"explanation\":null}";

/// `readTree(args)`, else the text itself.
fn json_or_text(args: &str) -> Value {
    // Jackson's readTree of blank text is a MissingNode, which the response prints as `null`
    if args.trim_matches([' ', '\t', '\r', '\n']).is_empty() {
        return Value::Null;
    }
    serde_json::from_str::<Value>(args).unwrap_or_else(|_| Value::String(args.to_string()))
}

fn anthropic(c: &Completion, model: &str, claude_api: bool) -> Value {
    let mut content = Vec::new();
    if let Some(reasoning) = c.reasoning_text.as_deref().filter(|r| !r.is_empty()) {
        let mut block = Map::new();
        block.insert("type".into(), "thinking".into());
        block.insert("thinking".into(), reasoning.into());
        if let Some(sig) = c.reasoning_signature.as_deref().filter(|s| !s.is_empty()) {
            block.insert("signature".into(), sig.into());
        }
        content.push(Value::Object(block));
    }
    if let Some(text) = c.text.as_deref().filter(|t| !t.is_empty()) {
        content.push(json!({"type": "text", "text": text}));
    }
    for tool in &c.tool_calls {
        let input = tool.arguments.as_deref().map_or_else(|| json!({}), json_or_text);
        content.push(json!({"type": "tool_use", "id": tool_id(tool, "toolu_"), "name": tool.name, "input": input}));
    }
    let stop = anthropic_stop(c);
    let stop_details: Value = if stop == "refusal" { serde_json::from_str(REFUSAL_STOP_DETAILS).expect("constant JSON") } else { Value::Null };
    let mut root = Map::new();
    root.insert("id".into(), format!("msg_{}", random_id(24)).into());
    root.insert("type".into(), "message".into());
    root.insert("role".into(), "assistant".into());
    root.insert("model".into(), model.into());
    root.insert("content".into(), Value::Array(content));
    root.insert("container".into(), Value::Null);
    root.insert("stop_reason".into(), stop.into());
    root.insert("stop_sequence".into(), Value::Null);
    root.insert("stop_details".into(), stop_details);
    root.insert("usage".into(), Value::Object(anthropic_message_usage(c, tokens(c, "outputTokens").unwrap_or(0), true, claude_api)));
    if claude_api {
        root.insert("diagnostics".into(), Value::Null);
    }
    Value::Object(root)
}

/// `AnthropicCodec.putInputUsage`: the input count and both cache counts, 0 when unset.
fn anthropic_input_usage(usage: &mut Map<String, Value>, c: &Completion) {
    usage.insert("input_tokens".into(), tokens(c, "inputTokens").unwrap_or(0).into());
    usage.insert("cache_creation_input_tokens".into(), tokens(c, "cacheCreationTokens").unwrap_or(0).into());
    usage.insert("cache_read_input_tokens".into(), tokens(c, "cachedInputTokens").unwrap_or(0).into());
}

/// `AnthropicCodec.putOutputTokensDetails`: present only when the completion sets `reasoningTokens`.
fn anthropic_output_details(usage: &mut Map<String, Value>, c: &Completion) {
    if let Some(n) = tokens(c, "reasoningTokens") {
        usage.insert("output_tokens_details".into(), json!({"thinking_tokens": n}));
    }
}

/// `AnthropicCodec.messageUsage`: the `Usage` of a whole message, or of the message in `message_start` (no output
/// details), in the real API's field order; every cache write goes to the default 5-minute TTL. Only the Claude API
/// (`claude_api`) sends `inference_geo`.
fn anthropic_message_usage(c: &Completion, output_tokens: i64, with_output_details: bool, claude_api: bool) -> Map<String, Value> {
    let mut usage = Map::new();
    anthropic_input_usage(&mut usage, c);
    usage.insert(
        "cache_creation".into(),
        json!({"ephemeral_5m_input_tokens": tokens(c, "cacheCreationTokens").unwrap_or(0), "ephemeral_1h_input_tokens": 0}),
    );
    usage.insert("output_tokens".into(), output_tokens.into());
    if with_output_details {
        anthropic_output_details(&mut usage, c);
    }
    usage.insert("service_tier".into(), "standard".into());
    if claude_api {
        usage.insert("inference_geo".into(), "global".into());
    }
    usage
}

/// `AnthropicCodec.messageDeltaUsage`: the cumulative usage on `message_delta`.
fn anthropic_delta_usage(c: &Completion) -> Map<String, Value> {
    let mut usage = Map::new();
    anthropic_input_usage(&mut usage, c);
    usage.insert("output_tokens".into(), tokens(c, "outputTokens").unwrap_or(0).into());
    anthropic_output_details(&mut usage, c);
    usage
}

fn anthropic_stream(c: &Completion, model: &str, claude_api: bool) -> Vec<SseEvent> {
    let mut events = Vec::new();
    let start_usage = Value::Object(anthropic_message_usage(c, 1, false, claude_api));
    events.push(event(
        Some("message_start"),
        format!(
            "{{\"type\":\"message_start\",\"message\":{{\"id\":\"msg_{}\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"container\":null,\"model\":\"{}\",\"stop_reason\":null,\"stop_sequence\":null,\"stop_details\":null,\"usage\":{start_usage}{}}}}}",
            random_id(24),
            escape(model),
            if claude_api { ",\"diagnostics\":null" } else { "" }
        ),
    ));
    let mut index = 0;
    let block_start = |i: usize, block: &str| event(Some("content_block_start"), format!("{{\"type\":\"content_block_start\",\"index\":{i},\"content_block\":{block}}}"));
    let block_delta = |i: usize, delta: &str| event(Some("content_block_delta"), format!("{{\"type\":\"content_block_delta\",\"index\":{i},\"delta\":{delta}}}"));
    let block_stop = |i: usize| event(Some("content_block_stop"), format!("{{\"type\":\"content_block_stop\",\"index\":{i}}}"));
    if let Some(reasoning) = c.reasoning_text.as_deref().filter(|r| !r.is_empty()) {
        events.push(block_start(index, "{\"type\":\"thinking\",\"thinking\":\"\"}"));
        events.push(block_delta(index, &format!("{{\"type\":\"thinking_delta\",\"thinking\":\"{}\"}}", escape(reasoning))));
        if let Some(sig) = c.reasoning_signature.as_deref().filter(|s| !s.is_empty()) {
            events.push(block_delta(index, &format!("{{\"type\":\"signature_delta\",\"signature\":\"{}\"}}", escape(sig))));
        }
        events.push(block_stop(index));
        index += 1;
    }
    if let Some(text) = c.text.as_deref().filter(|t| !t.is_empty()) {
        events.push(block_start(index, "{\"type\":\"text\",\"text\":\"\"}"));
        for token in streaming_tokens(text, c.physics.as_ref()).into_iter().filter(|t| !t.is_empty()) {
            events.push(block_delta(index, &format!("{{\"type\":\"text_delta\",\"text\":\"{}\"}}", escape(&token))));
        }
        events.push(block_stop(index));
        index += 1;
    }
    for tool in &c.tool_calls {
        events.push(block_start(index, &format!("{{\"type\":\"tool_use\",\"id\":\"{}\",\"name\":\"{}\",\"input\":{{}}}}", escape(&tool_id(tool, "toolu_")), escape(&tool.name))));
        let args = tool.arguments.clone().unwrap_or_else(|| "{}".into());
        events.push(block_delta(index, &format!("{{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}", escape(&args))));
        events.push(block_stop(index));
        index += 1;
    }
    let stop = anthropic_stop(c);
    let stop_details = if stop == "refusal" { REFUSAL_STOP_DETAILS } else { "null" };
    events.push(event(
        Some("message_delta"),
        format!(
            "{{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"{}\",\"stop_sequence\":null,\"stop_details\":{stop_details},\"container\":null}},\"usage\":{}}}",
            escape(&stop),
            Value::Object(anthropic_delta_usage(c))
        ),
    ));
    events.push(event(Some("message_stop"), "{\"type\":\"message_stop\"}".into()));
    events
}

// ------------------------------------------------------------ Bedrock InvokeModel token counts

pub(crate) const BEDROCK_INPUT_TOKEN_COUNT: &str = "X-Amzn-Bedrock-Input-Token-Count";
const BEDROCK_OUTPUT_TOKEN_COUNT: &str = "X-Amzn-Bedrock-Output-Token-Count";
const BEDROCK_CACHE_READ_INPUT_TOKEN_COUNT: &str = "X-Amzn-Bedrock-Cache-Read-Input-Token-Count";
const BEDROCK_CACHE_WRITE_INPUT_TOKEN_COUNT: &str = "X-Amzn-Bedrock-Cache-Write-Input-Token-Count";

/// Whether the usage sets a cache read or a cache write count (a configured 0 included).
fn has_cache_counts(c: &Completion) -> bool {
    tokens(c, "cachedInputTokens").is_some() || tokens(c, "cacheCreationTokens").is_some()
}

/// `BedrockCodec.encode`: a non-streaming InvokeModel answer carries its token counts as headers, and the cache read
/// and write counts when the usage has either; Converse and every other provider carry none.
pub fn token_count_headers(provider: &str, c: &Completion, request: &HttpRequest) -> Vec<(String, String)> {
    if provider != "BEDROCK" || super::converse::is_converse(request) {
        return Vec::new();
    }
    let count = |key: &str| tokens(c, key).unwrap_or(0).to_string();
    let mut headers = vec![(BEDROCK_INPUT_TOKEN_COUNT.to_string(), count("inputTokens")), (BEDROCK_OUTPUT_TOKEN_COUNT.to_string(), count("outputTokens"))];
    if has_cache_counts(c) {
        headers.push((BEDROCK_CACHE_READ_INPUT_TOKEN_COUNT.to_string(), count("cachedInputTokens")));
        headers.push((BEDROCK_CACHE_WRITE_INPUT_TOKEN_COUNT.to_string(), count("cacheCreationTokens")));
    }
    headers
}

/// `BedrockCodec.encodeStreaming`: an InvokeModel stream's last event (`message_stop`) carries
/// `amazon-bedrock-invocationMetrics`: the token counts, the cache counts when the usage has either, and latencies
/// from the events' delays (the physics already applied), each at least 1 ms.
pub fn with_invocation_metrics(provider: &str, c: &Completion, request: &HttpRequest, events: &mut [SseEvent]) {
    if provider != "BEDROCK" || super::converse::is_converse(request) || events.is_empty() {
        return;
    }
    let millis = |e: &SseEvent| e.delay.as_ref().map_or(0, |d| d.fixed.as_millis() as i64);
    let first_byte = millis(&events[0]).max(1);
    let invocation = events.iter().map(millis).sum::<i64>().max(first_byte);
    let count = |key: &str| tokens(c, key).unwrap_or(0);
    let mut metrics = format!(
        "{{\"inputTokenCount\":{},\"outputTokenCount\":{},\"invocationLatency\":{invocation},\"firstByteLatency\":{first_byte}",
        count("inputTokens"),
        count("outputTokens")
    );
    if has_cache_counts(c) {
        metrics.push_str(&format!(",\"cacheReadInputTokenCount\":{},\"cacheWriteInputTokenCount\":{}", count("cachedInputTokens"), count("cacheCreationTokens")));
    }
    let last = events.len() - 1;
    events[last].data = Some(format!("{{\"type\":\"message_stop\",\"amazon-bedrock-invocationMetrics\":{metrics}}}}}"));
}

// ------------------------------------------------------------ OpenAI Responses

/// `OpenAiResponsesCodec.usageNode`.
fn responses_usage(c: &Completion) -> Value {
    let (input, output) = (tokens(c, "inputTokens").unwrap_or(0), tokens(c, "outputTokens").unwrap_or(0));
    json!({
        "input_tokens": input,
        "input_tokens_details": {"cached_tokens": tokens(c, "cachedInputTokens").unwrap_or(0), "cache_write_tokens": tokens(c, "cacheCreationTokens").unwrap_or(0)},
        "output_tokens": output,
        "output_tokens_details": {"reasoning_tokens": tokens(c, "reasoningTokens").unwrap_or(0)},
        "total_tokens": input + output,
    })
}

/// `toolChoiceNode`.
fn tool_choice_node(tool_choice: Option<&str>) -> Value {
    let Some(trimmed) = tool_choice.map(str::trim).filter(|t| !t.is_empty()) else { return "auto".into() };
    let lower = trimmed.to_lowercase();
    if matches!(lower.as_str(), "auto" | "none" | "required") {
        return lower.into();
    }
    json!({"type": "function", "name": trimmed})
}

/// `responseObject`: the Response object, echoing the request fields the real API echoes.
#[allow(clippy::too_many_arguments, reason = "one argument per field of the Response object, as `responseObject` takes them")]
fn response_object(id: &str, created_at: i64, model: &str, status: &str, output: Vec<Value>, usage: Option<Value>, tool_choice: Option<&str>, echo: &Map<String, Value>) -> Value {
    let mut root = Map::new();
    root.insert("id".into(), id.into());
    root.insert("object".into(), "response".into());
    root.insert("access_programs".into(), Value::Null);
    root.insert("created_at".into(), created_at.into());
    root.insert("status".into(), status.into());
    if status == "completed" {
        root.insert("completed_at".into(), created_at.into());
    }
    root.insert("error".into(), Value::Null);
    root.insert("incomplete_details".into(), Value::Null);
    root.insert("instructions".into(), echo.get("instructions").filter(|v| v.is_string()).cloned().unwrap_or(Value::Null));
    root.insert("model".into(), model.into());
    root.insert("output".into(), Value::Array(output));
    root.insert("parallel_tool_calls".into(), echo.get("parallel_tool_calls").and_then(Value::as_bool).unwrap_or(true).into());
    root.insert("previous_response_id".into(), echo.get("previous_response_id").filter(|v| v.is_string()).cloned().unwrap_or(Value::Null));
    let echo_tool_choice = tool_choice.is_none_or(|t| t.trim().is_empty()) && echo.get("tool_choice").is_some_and(|t| t.is_string() || t.is_object());
    root.insert("tool_choice".into(), if echo_tool_choice { echo["tool_choice"].clone() } else { tool_choice_node(tool_choice) });
    root.insert("tools".into(), echo.get("tools").filter(|v| v.is_array()).cloned().unwrap_or_else(|| json!([])));
    root.insert("temperature".into(), echo.get("temperature").filter(|v| v.is_number()).cloned().unwrap_or(Value::Null));
    root.insert("top_p".into(), echo.get("top_p").filter(|v| v.is_number()).cloned().unwrap_or(Value::Null));
    root.insert("usage".into(), usage.unwrap_or(Value::Null));
    root.insert("metadata".into(), echo.get("metadata").filter(|v| v.is_object()).cloned().unwrap_or_else(|| json!({})));
    Value::Object(root)
}

/// One `OutputItem`: reasoning, the assistant message, or a function call.
enum OutputItem {
    Reasoning { id: String, text: String },
    Message { id: String, text: String },
    FunctionCall { id: String, call_id: String, name: String, arguments: String },
}

fn summary_part(text: &str) -> Value {
    json!({"type": "summary_text", "text": text})
}

fn output_text(text: &str) -> Value {
    json!({"type": "output_text", "text": text, "annotations": [], "logprobs": []})
}

impl OutputItem {
    fn id(&self) -> &str {
        match self {
            OutputItem::Reasoning { id, .. } | OutputItem::Message { id, .. } | OutputItem::FunctionCall { id, .. } => id,
        }
    }

    fn in_progress(&self) -> Value {
        match self {
            OutputItem::Reasoning { id, .. } => json!({"id": id, "type": "reasoning", "summary": []}),
            OutputItem::Message { id, .. } => json!({"id": id, "type": "message", "status": "in_progress", "role": "assistant", "content": []}),
            OutputItem::FunctionCall { id, call_id, name, .. } => {
                json!({"id": id, "type": "function_call", "status": "in_progress", "arguments": "", "call_id": call_id, "name": name})
            }
        }
    }

    fn completed(&self) -> Value {
        match self {
            OutputItem::Reasoning { id, text } => json!({"id": id, "type": "reasoning", "summary": [summary_part(text)]}),
            OutputItem::Message { id, text } => json!({"id": id, "type": "message", "status": "completed", "role": "assistant", "content": [output_text(text)]}),
            OutputItem::FunctionCall { id, call_id, name, arguments } => {
                json!({"id": id, "type": "function_call", "status": "completed", "arguments": arguments, "call_id": call_id, "name": name})
            }
        }
    }
}

/// `outputItems`: optional reasoning, then the assistant message, then one per tool call.
fn output_items(c: &Completion) -> Vec<OutputItem> {
    let mut items = Vec::new();
    if let Some(reasoning) = c.reasoning_text.as_deref().filter(|r| !r.is_empty()) {
        items.push(OutputItem::Reasoning { id: format!("rs_{}", random_id(24)), text: reasoning.to_string() });
    }
    if let Some(text) = c.text.as_deref().filter(|t| !t.is_empty()) {
        items.push(OutputItem::Message { id: format!("msg_{}", random_id(24)), text: text.to_string() });
    }
    for tool in &c.tool_calls {
        let call_id = tool_id(tool, "call_");
        items.push(OutputItem::FunctionCall {
            id: format!("fc_{}", random_id(24)),
            call_id,
            name: tool.name.clone(),
            arguments: tool.arguments.clone().unwrap_or_else(|| "{}".into()),
        });
    }
    items
}

fn openai_responses(c: &Completion, model: &str, echo: &Map<String, Value>) -> Value {
    let created_at = chrono::Utc::now().timestamp();
    let output = output_items(c).iter().map(OutputItem::completed).collect();
    response_object(&format!("resp_{}", random_id(24)), created_at, model, "completed", output, Some(responses_usage(c)), c.tool_choice.as_deref(), echo)
}

/// `EventSink`: each event's members after its `type`, then its `sequence_number`.
struct EventSink {
    events: Vec<SseEvent>,
    sequence: i64,
}

impl EventSink {
    fn emit(&mut self, kind: &str, members: Vec<(&str, Value)>) {
        let mut data = Map::new();
        data.insert("type".into(), kind.into());
        for (k, v) in members {
            data.insert(k.into(), v);
        }
        data.insert("sequence_number".into(), self.sequence.into());
        self.sequence += 1;
        self.events.push(event(Some(kind), Value::Object(data).to_string()));
    }
}

fn openai_responses_stream(c: &Completion, model: &str, echo: &Map<String, Value>) -> Vec<SseEvent> {
    let id = format!("resp_{}", random_id(24));
    let created_at = chrono::Utc::now().timestamp();
    let tool_choice = c.tool_choice.as_deref();
    let mut sink = EventSink { events: Vec::new(), sequence: 0 };
    sink.emit("response.created", vec![("response", response_object(&id, created_at, model, "in_progress", Vec::new(), None, tool_choice, echo))]);
    sink.emit("response.in_progress", vec![("response", response_object(&id, created_at, model, "in_progress", Vec::new(), None, tool_choice, echo))]);
    let mut output = Vec::new();
    for (index, item) in output_items(c).iter().enumerate() {
        sink.emit("response.output_item.added", vec![("output_index", index.into()), ("item", item.in_progress())]);
        let item_id = || Value::from(item.id());
        match item {
            OutputItem::Reasoning { text, .. } => {
                sink.emit("response.reasoning_summary_part.added", vec![("item_id", item_id()), ("output_index", index.into()), ("summary_index", 0.into()), ("part", summary_part(""))]);
                sink.emit("response.reasoning_summary_text.delta", vec![("item_id", item_id()), ("output_index", index.into()), ("summary_index", 0.into()), ("delta", text.as_str().into())]);
                sink.emit("response.reasoning_summary_text.done", vec![("item_id", item_id()), ("output_index", index.into()), ("summary_index", 0.into()), ("text", text.as_str().into())]);
                sink.emit("response.reasoning_summary_part.done", vec![("item_id", item_id()), ("output_index", index.into()), ("summary_index", 0.into()), ("part", summary_part(text))]);
            }
            OutputItem::Message { text, .. } => {
                sink.emit("response.content_part.added", vec![("item_id", item_id()), ("output_index", index.into()), ("content_index", 0.into()), ("part", output_text(""))]);
                for token in streaming_tokens(text, c.physics.as_ref()).into_iter().filter(|t| !t.is_empty()) {
                    sink.emit(
                        "response.output_text.delta",
                        vec![("item_id", item_id()), ("output_index", index.into()), ("content_index", 0.into()), ("delta", token.into()), ("logprobs", json!([]))],
                    );
                }
                sink.emit(
                    "response.output_text.done",
                    vec![("item_id", item_id()), ("output_index", index.into()), ("content_index", 0.into()), ("text", text.as_str().into()), ("logprobs", json!([]))],
                );
                sink.emit("response.content_part.done", vec![("item_id", item_id()), ("output_index", index.into()), ("content_index", 0.into()), ("part", output_text(text))]);
            }
            OutputItem::FunctionCall { arguments, .. } => {
                for piece in streaming_tokens(arguments, c.physics.as_ref()) {
                    sink.emit("response.function_call_arguments.delta", vec![("item_id", item_id()), ("output_index", index.into()), ("delta", piece.into())]);
                }
                sink.emit("response.function_call_arguments.done", vec![("item_id", item_id()), ("output_index", index.into()), ("arguments", arguments.as_str().into())]);
            }
        }
        sink.emit("response.output_item.done", vec![("output_index", index.into()), ("item", item.completed())]);
        output.push(item.completed());
    }
    sink.emit("response.completed", vec![("response", response_object(&id, created_at, model, "completed", output, Some(responses_usage(c)), tool_choice, echo))]);
    sink.events
}

// ------------------------------------------------------------ Gemini

fn gemini_finish(c: &Completion) -> String {
    match c.stop_reason.as_deref() {
        None | Some("end_turn" | "stop" | "tool_use" | "tool_calls") => "STOP".into(),
        Some("max_tokens" | "length") => "MAX_TOKENS".into(),
        Some(other) => other.into(),
    }
}

/// Gemini's `args`: the arguments object, else `{"value": text}`.
fn object_args(args: Option<&str>) -> Value {
    match args {
        None => json!({}),
        Some(a) => match serde_json::from_str::<Value>(a) {
            Ok(v) if v.is_object() => v,
            _ => json!({"value": a}),
        },
    }
}

/// `usageMetadata`: `candidatesTokenCount` excludes the thinking tokens, `totalTokenCount` counts them.
fn gemini_usage(c: &Completion) -> Map<String, Value> {
    let prompt = tokens(c, "inputTokens").unwrap_or(0);
    let thoughts = tokens(c, "reasoningTokens").unwrap_or(0);
    let candidates = (tokens(c, "outputTokens").unwrap_or(0) - thoughts).max(0);
    let mut usage = Map::new();
    usage.insert("promptTokenCount".into(), prompt.into());
    usage.insert("candidatesTokenCount".into(), candidates.into());
    usage.insert("totalTokenCount".into(), (prompt + candidates + thoughts).into());
    if let Some(n) = nonzero(c, "cachedInputTokens") {
        usage.insert("cachedContentTokenCount".into(), n.into());
    }
    if thoughts != 0 {
        usage.insert("thoughtsTokenCount".into(), thoughts.into());
    }
    usage
}

fn gemini(c: &Completion, model: &str) -> Value {
    let mut parts = Vec::new();
    if let Some(reasoning) = c.reasoning_text.as_deref().filter(|r| !r.is_empty()) {
        parts.push(json!({"text": reasoning, "thought": true}));
    }
    if let Some(text) = c.text.as_deref().filter(|t| !t.is_empty()) {
        parts.push(json!({"text": text}));
    }
    for tool in &c.tool_calls {
        let mut call = Map::new();
        if let Some(id) = tool.id.as_deref().filter(|id| !id.is_empty()) {
            call.insert("id".into(), id.into());
        }
        call.insert("name".into(), tool.name.clone().into());
        call.insert("args".into(), object_args(tool.arguments.as_deref()));
        parts.push(json!({"functionCall": Value::Object(call)}));
    }
    json!({
        "candidates": [{"content": {"parts": parts, "role": "model"}, "finishReason": gemini_finish(c), "index": 0}],
        "usageMetadata": Value::Object(gemini_usage(c)),
        "modelVersion": model,
    })
}

fn gemini_stream(c: &Completion, model: &str) -> Vec<SseEvent> {
    let mut events = Vec::new();
    let m = escape(model);
    if let Some(reasoning) = c.reasoning_text.as_deref().filter(|r| !r.is_empty()) {
        events.push(event(None, format!("{{\"candidates\":[{{\"content\":{{\"parts\":[{{\"text\":\"{}\",\"thought\":true}}],\"role\":\"model\"}},\"index\":0}}],\"modelVersion\":\"{m}\"}}", escape(reasoning))));
    }
    if let Some(text) = c.text.as_deref().filter(|t| !t.is_empty()) {
        for token in streaming_tokens(text, c.physics.as_ref()).into_iter().filter(|t| !t.is_empty()) {
            events.push(event(None, format!("{{\"candidates\":[{{\"content\":{{\"parts\":[{{\"text\":\"{}\"}}],\"role\":\"model\"}},\"index\":0}}],\"modelVersion\":\"{m}\"}}", escape(&token))));
        }
    }
    for tool in &c.tool_calls {
        let args = tool.arguments.clone().unwrap_or_else(|| "{}".into());
        let safe = match serde_json::from_str::<Value>(&args) {
            Ok(v) if v.is_object() => v.to_string(),
            _ => format!("{{\"value\":\"{}\"}}", escape(&args)),
        };
        let call_id = tool.id.as_deref().filter(|id| !id.is_empty()).map(|id| format!("\"id\":\"{}\",", escape(id))).unwrap_or_default();
        events.push(event(
            None,
            format!(
                "{{\"candidates\":[{{\"content\":{{\"parts\":[{{\"functionCall\":{{{call_id}\"name\":\"{}\",\"args\":{safe}}}}}],\"role\":\"model\"}},\"index\":0}}],\"modelVersion\":\"{m}\"}}",
                escape(&tool.name)
            ),
        ));
    }
    events.push(event(
        None,
        format!(
            "{{\"candidates\":[{{\"content\":{{\"parts\":[],\"role\":\"model\"}},\"finishReason\":\"{}\",\"index\":0}}],\"usageMetadata\":{},\"modelVersion\":\"{m}\"}}",
            escape(&gemini_finish(c)),
            Value::Object(gemini_usage(c))
        ),
    ));
    events
}

// ------------------------------------------------------------ Ollama

/// `ProviderCodec.isModelManagementRequest`: the request only loads or unloads a model, which the provider answers
/// without generating anything (Ollama), so there is no completion to trace, count or check.
pub fn is_model_management(provider: &str, request: &HttpRequest) -> bool {
    provider == "OLLAMA" && ollama::model_management("", request).is_some()
}

mod ollama {
    use serde_json::{Map, Value, json};

    use super::{Completion, SseEvent, event, object_args, request_object, streaming_tokens, tokens};
    use crate::request::HttpRequest;

    /// `Instant.now().toString()`: seconds, then 3, 6 or 9 fractional digits as the nanoseconds need.
    fn now_instant() -> String {
        let now = chrono::Utc::now();
        let nanos = now.timestamp_subsec_nanos();
        let fraction = if nanos == 0 {
            String::new()
        } else if nanos.is_multiple_of(1_000_000) {
            format!(".{:03}", nanos / 1_000_000)
        } else if nanos.is_multiple_of(1_000) {
            format!(".{:06}", nanos / 1_000)
        } else {
            format!(".{nanos:09}")
        };
        format!("{}{fraction}Z", now.format("%Y-%m-%dT%H:%M:%S"))
    }

    /// `mapDoneReason`.
    fn done_reason(c: &Completion) -> &'static str {
        match c.stop_reason.as_deref() {
            Some("length" | "max_tokens" | "MAX_TOKENS" | "model_context_window_exceeded") => "length",
            Some("load") => "load",
            Some("unload") => "unload",
            _ => "stop",
        }
    }

    /// `writeToolCalls`.
    fn tool_calls(c: &Completion) -> Value {
        Value::Array(
            c.tool_calls
                .iter()
                .map(|t| {
                    let mut call = Map::new();
                    if let Some(id) = t.id.as_deref().filter(|id| !id.is_empty()) {
                        call.insert("id".into(), id.into());
                    }
                    call.insert("function".into(), json!({"name": t.name, "arguments": object_args(t.arguments.as_deref())}));
                    Value::Object(call)
                })
                .collect(),
        )
    }

    /// `putMetrics`.
    fn metrics(root: &mut Map<String, Value>, c: &Completion) {
        root.insert("total_duration".into(), 1_234_567_890i64.into());
        root.insert("load_duration".into(), 12_345i64.into());
        root.insert("prompt_eval_count".into(), tokens(c, "inputTokens").unwrap_or(0).into());
        root.insert("prompt_eval_duration".into(), 67_890i64.into());
        root.insert("eval_count".into(), tokens(c, "outputTokens").unwrap_or(0).into());
        root.insert("eval_duration".into(), 12_345i64.into());
    }

    fn lower_path(request: &HttpRequest) -> String {
        request.path.to_lowercase()
    }

    fn is_generate(request: &HttpRequest) -> bool {
        lower_path(request).ends_with("/api/generate")
    }

    fn message(model: &str, content: &str) -> Map<String, Value> {
        let mut root = Map::new();
        root.insert("model".into(), model.into());
        root.insert("created_at".into(), now_instant().into());
        root.insert("message".into(), json!({"role": "assistant", "content": content}));
        root
    }

    fn generate_object(model: &str, response: &str) -> Map<String, Value> {
        let mut root = Map::new();
        root.insert("model".into(), model.into());
        root.insert("created_at".into(), now_instant().into());
        root.insert("response".into(), response.into());
        root
    }

    /// A Go `time.ParseDuration` string whose value is zero (`ZERO_GO_DURATION`).
    fn zero_go_duration(text: &str) -> bool {
        let s = text.strip_prefix(['-', '+']).unwrap_or(text);
        if s == "0" {
            return true;
        }
        if s.is_empty() {
            return false;
        }
        let mut rest = s;
        while !rest.is_empty() {
            let digits = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(rest.len());
            let number = &rest[..digits];
            let valid_zero = !number.is_empty()
                && number != "."
                && number.matches('.').count() <= 1
                && number.chars().all(|c| c == '0' || c == '.')
                && (number.starts_with('0') || number.starts_with('.') && number.len() > 1);
            if !valid_zero {
                return false;
            }
            rest = &rest[digits..];
            let unit = ["ns", "us", "\u{b5}s", "\u{3bc}s", "ms", "s", "m", "h"].into_iter().find(|u| rest.starts_with(u));
            match unit {
                Some(u) => rest = &rest[u.len()..],
                None => return false,
            }
        }
        true
    }

    /// `isZeroKeepAlive`.
    fn zero_keep_alive(keep_alive: Option<&Value>) -> bool {
        match keep_alive {
            Some(Value::Number(n)) => n.as_f64().is_some_and(|seconds| seconds >= 0.0 && (seconds * 1_000_000_000.0) as i64 == 0),
            Some(Value::String(s)) => zero_go_duration(s),
            _ => false,
        }
    }

    /// `modelManagementReply`: a request that only loads or unloads the model.
    pub(super) fn model_management(model: &str, request: &HttpRequest) -> Option<Map<String, Value>> {
        let path = lower_path(request);
        let generate = path.ends_with("/api/generate");
        if !generate && !path.ends_with("/api/chat") {
            return None;
        }
        let body = match serde_json::from_str::<Value>(&request.body_str()) {
            Ok(Value::Object(o)) => o,
            _ => return None,
        };
        let input = body.get(if generate { "prompt" } else { "messages" });
        let nothing = match input {
            None | Some(Value::Null) => true,
            Some(Value::String(s)) if generate => s.is_empty(),
            Some(Value::Array(a)) if !generate => a.is_empty(),
            _ => false,
        };
        if !nothing {
            return None;
        }
        let model = Some(model).filter(|m| !m.is_empty()).map(str::to_string).or_else(|| body.get("model").and_then(Value::as_str).filter(|m| !m.is_empty()).map(str::to_string)).unwrap_or_else(|| "unknown".into());
        let mut reply = if generate { generate_object(&model, "") } else { message(&model, "") };
        reply.insert("done".into(), true.into());
        reply.insert("done_reason".into(), if zero_keep_alive(body.get("keep_alive")) { "unload" } else { "load" }.into());
        Some(reply)
    }

    /// `putGenerateFinalFields`.
    fn generate_final(root: &mut Map<String, Value>, c: &Completion, request: &HttpRequest) {
        root.insert("done".into(), true.into());
        root.insert("done_reason".into(), done_reason(c).into());
        if request_object(request).get("raw").and_then(Value::as_bool) != Some(true) {
            root.insert("context".into(), json!([1, 2, 3]));
        }
        metrics(root, c);
        if !c.tool_calls.is_empty() {
            root.insert("tool_calls".into(), tool_calls(c));
        }
    }

    pub(super) fn encode(c: &Completion, model: &str, request: &HttpRequest) -> Value {
        if let Some(reply) = model_management(model, request) {
            return Value::Object(reply);
        }
        if is_generate(request) {
            let mut root = generate_object(model, c.text.as_deref().unwrap_or_default());
            if let Some(reasoning) = c.reasoning_text.as_deref().filter(|r| !r.is_empty()) {
                root.insert("thinking".into(), reasoning.into());
            }
            generate_final(&mut root, c, request);
            return Value::Object(root);
        }
        let mut msg = Map::new();
        msg.insert("role".into(), "assistant".into());
        msg.insert("content".into(), c.text.clone().unwrap_or_default().into());
        if let Some(reasoning) = c.reasoning_text.as_deref().filter(|r| !r.is_empty()) {
            msg.insert("thinking".into(), reasoning.into());
        }
        if !c.tool_calls.is_empty() {
            msg.insert("tool_calls".into(), tool_calls(c));
        }
        let mut root = Map::new();
        root.insert("model".into(), model.into());
        root.insert("created_at".into(), now_instant().into());
        root.insert("message".into(), Value::Object(msg));
        root.insert("done".into(), true.into());
        root.insert("done_reason".into(), done_reason(c).into());
        metrics(&mut root, c);
        Value::Object(root)
    }

    pub(super) fn encode_streaming(c: &Completion, model: &str, request: &HttpRequest) -> Vec<SseEvent> {
        if let Some(reply) = model_management(model, request) {
            return vec![event(None, Value::Object(reply).to_string())];
        }
        let mut events = Vec::new();
        let text_tokens = || c.text.as_deref().filter(|t| !t.is_empty()).map(|t| streaming_tokens(t, c.physics.as_ref())).unwrap_or_default().into_iter().filter(|t| !t.is_empty());
        if is_generate(request) {
            if let Some(reasoning) = c.reasoning_text.as_deref().filter(|r| !r.is_empty()) {
                let mut chunk = generate_object(model, "");
                chunk.insert("thinking".into(), reasoning.into());
                chunk.insert("done".into(), false.into());
                events.push(event(None, Value::Object(chunk).to_string()));
            }
            for token in text_tokens() {
                let mut chunk = generate_object(model, &token);
                chunk.insert("done".into(), false.into());
                events.push(event(None, Value::Object(chunk).to_string()));
            }
            let mut last = generate_object(model, "");
            generate_final(&mut last, c, request);
            events.push(event(None, Value::Object(last).to_string()));
            return events;
        }
        if let Some(reasoning) = c.reasoning_text.as_deref().filter(|r| !r.is_empty()) {
            let mut chunk = message(model, "");
            chunk.insert("message".into(), json!({"role": "assistant", "content": "", "thinking": reasoning}));
            chunk.insert("done".into(), false.into());
            events.push(event(None, Value::Object(chunk).to_string()));
        }
        for token in text_tokens() {
            let mut chunk = message(model, &token);
            chunk.insert("done".into(), false.into());
            events.push(event(None, Value::Object(chunk).to_string()));
        }
        if !c.tool_calls.is_empty() {
            let mut chunk = message(model, "");
            chunk.insert("message".into(), json!({"role": "assistant", "content": "", "tool_calls": tool_calls(c)}));
            chunk.insert("done".into(), false.into());
            events.push(event(None, Value::Object(chunk).to_string()));
        }
        let mut last = message(model, "");
        last.insert("done".into(), true.into());
        last.insert("done_reason".into(), done_reason(c).into());
        metrics(&mut last, c);
        events.push(event(None, Value::Object(last).to_string()));
        events
    }
}

// ------------------------------------------------------------ AWS event stream

/// `BedrockEventStreamEncoder.encodeChunk`: the chunk JSON base64'd into `{"bytes":…}`, framed as a `chunk` event.
pub fn event_stream_chunk(chunk: &str) -> Vec<u8> {
    use base64::Engine;
    let payload = format!("{{\"bytes\":\"{}\"}}", base64::engine::general_purpose::STANDARD.encode(chunk.as_bytes()));
    event_stream_message("chunk", payload.as_bytes())
}

/// `BedrockEventStreamEncoder.encodeEvent`: one event-stream message, `:event-type` `event_type`, framed with its
/// prelude, headers and CRC32s.
pub fn event_stream_message(event_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut headers = Vec::new();
    for (name, value) in [(":event-type", event_type), (":content-type", "application/json"), (":message-type", "event")] {
        headers.push(name.len() as u8);
        headers.extend_from_slice(name.as_bytes());
        headers.push(7);
        headers.extend_from_slice(&(value.len() as u16).to_be_bytes());
        headers.extend_from_slice(value.as_bytes());
    }
    let total = 8 + 4 + headers.len() + payload.len() + 4;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u32).to_be_bytes());
    out.extend_from_slice(&(headers.len() as u32).to_be_bytes());
    let crc = |bytes: &[u8]| {
        let mut crc = flate2::Crc::new();
        crc.update(bytes);
        crc.sum()
    };
    let prelude = crc(&out);
    out.extend_from_slice(&prelude.to_be_bytes());
    out.extend_from_slice(&headers);
    out.extend_from_slice(payload);
    let message = crc(&out);
    out.extend_from_slice(&message.to_be_bytes());
    out
}

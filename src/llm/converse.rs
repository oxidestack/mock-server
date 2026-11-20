//! `BedrockConverseCodec`: the AWS Bedrock Runtime Converse (`/model/{id}/converse`) and ConverseStream
//! (`/model/{id}/converse-stream`) wire shape, which `BedrockCodec` selects per request (`is_converse`) instead of
//! the Anthropic InvokeModel shape. ConverseStream is framed as AWS event-stream messages whose `:event-type` is the
//! event name and whose payload is the event's JSON (`Format::AwsConverseEventStream`).

use serde_json::{Map, Value, json};

use super::conversation::{Message, Role, ToolCall};
use super::{Completion, ToolUse, random_id, streaming_tokens};
use crate::action::SseEvent;
use crate::request::HttpRequest;

/// Converse `ContentBlock` union members that may appear in a request message.
const CONTENT_BLOCK_MEMBERS: &[&str] =
    &["text", "image", "document", "video", "audio", "toolUse", "toolResult", "guardContent", "cachePoint", "reasoningContent", "citationsContent", "searchResult"];

/// Top-level request fields that exist only in the Converse request shape.
const CONVERSE_ONLY_REQUEST_FIELDS: &[&str] =
    &["inferenceConfig", "toolConfig", "additionalModelRequestFields", "additionalModelResponseFieldPaths", "guardrailConfig", "promptVariables", "performanceConfig", "outputConfig"];

/// The AWS Converse `StopReason` enum.
const CONVERSE_STOP_REASONS: &[&str] =
    &["end_turn", "tool_use", "max_tokens", "stop_sequence", "guardrail_intervened", "content_filtered", "malformed_model_output", "malformed_tool_use", "model_context_window_exceeded"];

/// `BedrockCodec.isConverse`: the path decides when it names either API (`…/converse[-stream]` or
/// `…/invoke[-with-response-stream]`, trailing slashes allowed); otherwise a Converse-shaped body selects Converse.
pub fn is_converse(request: &HttpRequest) -> bool {
    let path = request.path.to_lowercase();
    let path = path.trim_end_matches('/');
    if path.ends_with("/converse") || path.ends_with("/converse-stream") {
        return true;
    }
    if path.ends_with("/invoke") || path.ends_with("/invoke-with-response-stream") {
        return false;
    }
    let body = request.body_str();
    !body.is_empty() && serde_json::from_str::<Value>(&body).is_ok_and(|root| is_converse_shaped(&root))
}

/// `isConverseShaped`: a Converse-only top-level field, or (without `anthropic_version`) a `system` or
/// `messages[].content` block keyed by its union member instead of carrying a `type`.
fn is_converse_shaped(root: &Value) -> bool {
    let Some(object) = root.as_object() else { return false };
    if CONVERSE_ONLY_REQUEST_FIELDS.iter().any(|f| object.contains_key(*f)) {
        return true;
    }
    if object.contains_key("anthropic_version") {
        return false;
    }
    let union_keyed = |block: &Value| block.as_object().is_some_and(|b| !b.contains_key("type") && b.keys().any(|k| CONTENT_BLOCK_MEMBERS.contains(&k.as_str())));
    if object.get("system").and_then(Value::as_array).is_some_and(|blocks| blocks.iter().any(union_keyed)) {
        return true;
    }
    object
        .get("messages")
        .and_then(Value::as_array)
        .is_some_and(|messages| messages.iter().filter_map(|m| m.get("content").and_then(Value::as_array)).flatten().any(union_keyed))
}

/// `mapStopReason`: always a Converse `StopReason` value (AWS SDKs read it as an enum).
fn stop_reason(c: &Completion) -> &str {
    match c.stop_reason.as_deref() {
        None if c.tool_calls.is_empty() => "end_turn",
        None => "tool_use",
        Some(native) if CONVERSE_STOP_REASONS.contains(&native) => native,
        Some("length" | "MAX_TOKENS") => "max_tokens",
        Some("tool_calls") => "tool_use",
        Some("content_filter" | "refusal" | "SAFETY") => "content_filtered",
        Some(_) => "end_turn",
    }
}

/// `usageNode`: `totalTokens` adds the cache read/write counts; those are present only when non-zero.
fn usage(c: &Completion) -> Value {
    let get = |k: &str| c.usage.as_ref().and_then(|u| u.get(k)).and_then(Value::as_i64).unwrap_or(0) as i32;
    let (input, output, read, write) = (get("inputTokens"), get("outputTokens"), get("cachedInputTokens"), get("cacheCreationTokens"));
    let mut node = Map::new();
    node.insert("inputTokens".into(), input.into());
    node.insert("outputTokens".into(), output.into());
    node.insert("totalTokens".into(), input.wrapping_add(output).wrapping_add(read).wrapping_add(write).into());
    if read != 0 {
        node.insert("cacheReadInputTokens".into(), read.into());
    }
    if write != 0 {
        node.insert("cacheWriteInputTokens".into(), write.into());
    }
    Value::Object(node)
}

/// `toolInput`: the arguments as JSON, `{}` when blank or `null`, else the text itself.
fn tool_input(arguments: Option<&str>) -> Value {
    let Some(arguments) = arguments.filter(|a| !a.trim_matches(|c: char| c <= ' ').is_empty()) else { return json!({}) };
    match serde_json::from_str::<Value>(arguments) {
        Ok(Value::Null) => json!({}),
        Ok(parsed) => parsed,
        Err(_) => Value::String(arguments.to_string()),
    }
}

/// `toolUseId`: the configured id, else `tooluse_` and 22 random hex digits.
fn tool_use_id(tool: &ToolUse) -> String {
    tool.id.clone().filter(|id| !id.is_empty()).unwrap_or_else(|| format!("tooluse_{}", random_id(22)))
}

/// `encode`: the Converse response body.
pub fn encode(c: &Completion) -> String {
    let mut content = Vec::new();
    if let Some(reasoning) = c.reasoning_text.as_deref().filter(|r| !r.is_empty()) {
        let mut text = Map::new();
        text.insert("text".into(), reasoning.into());
        if let Some(signature) = c.reasoning_signature.as_deref().filter(|s| !s.is_empty()) {
            text.insert("signature".into(), signature.into());
        }
        content.push(json!({"reasoningContent": {"reasoningText": Value::Object(text)}}));
    }
    if let Some(text) = c.text.as_deref().filter(|t| !t.is_empty()) {
        content.push(json!({"text": text}));
    }
    for tool in &c.tool_calls {
        content.push(json!({"toolUse": {"toolUseId": tool_use_id(tool), "name": tool.name, "input": tool_input(tool.arguments.as_deref())}}));
    }
    json!({
        "output": {"message": {"role": "assistant", "content": content}},
        "stopReason": stop_reason(c),
        "usage": usage(c),
        "metrics": {"latencyMs": 0},
    })
    .to_string()
}

fn event(name: &str, payload: Value) -> SseEvent {
    SseEvent { event: Some(name.to_string()), data: Some(payload.to_string()), id: None, retry: None, delay: None }
}

/// `encodeStreaming`: `messageStart`, the blocks (text and reasoning as deltas only, tool uses opened by a
/// `contentBlockStart`), `messageStop`, `metadata`.
pub fn encode_streaming(c: &Completion) -> Vec<SseEvent> {
    let mut events = vec![event("messageStart", json!({"role": "assistant"}))];
    let delta = |index: usize, delta: Value| event("contentBlockDelta", json!({"contentBlockIndex": index, "delta": delta}));
    let stop = |index: usize| event("contentBlockStop", json!({"contentBlockIndex": index}));
    let mut index = 0;
    if let Some(reasoning) = c.reasoning_text.as_deref().filter(|r| !r.is_empty()) {
        events.push(delta(index, json!({"reasoningContent": {"text": reasoning}})));
        if let Some(signature) = c.reasoning_signature.as_deref().filter(|s| !s.is_empty()) {
            events.push(delta(index, json!({"reasoningContent": {"signature": signature}})));
        }
        events.push(stop(index));
        index += 1;
    }
    if let Some(text) = c.text.as_deref().filter(|t| !t.is_empty()) {
        for token in streaming_tokens(text, c.physics.as_ref()).into_iter().filter(|t| !t.is_empty()) {
            events.push(delta(index, json!({"text": token})));
        }
        events.push(stop(index));
        index += 1;
    }
    for tool in &c.tool_calls {
        events.push(event("contentBlockStart", json!({"contentBlockIndex": index, "start": {"toolUse": {"toolUseId": tool_use_id(tool), "name": tool.name}}})));
        // `ToolUseBlockDelta.input` is the tool input as a JSON string
        events.push(delta(index, json!({"toolUse": {"input": tool.arguments.as_deref().unwrap_or("{}")}})));
        events.push(stop(index));
        index += 1;
    }
    events.push(event("messageStop", json!({"stopReason": stop_reason(c)})));
    events.push(event("metadata", json!({"usage": usage(c), "metrics": {"latencyMs": 0}})));
    events
}

/// `BedrockEventStreamEncoder.encodeEvent` as `formatChunkBytes` calls it: a nameless event is framed as
/// `contentBlockDelta`, so AWS SDKs do not drop it.
pub fn framed(event: &SseEvent) -> Vec<u8> {
    let event_type = event.event.as_deref().filter(|e| !e.is_empty()).unwrap_or("contentBlockDelta");
    super::codec::event_stream_message(event_type, event.data.as_deref().unwrap_or_default().as_bytes())
}

/// `decode`: the `system` text blocks as one system message, then each message's text, images, audio, tool uses and
/// tool results; a message carrying a `toolResult` is the tool turn.
pub fn decode(root: &Value) -> Vec<Message> {
    let Some(messages) = root.get("messages").and_then(Value::as_array) else { return Vec::new() };
    let mut out = Vec::new();
    let system: String = root.get("system").and_then(Value::as_array).into_iter().flatten().filter_map(|b| b.get("text").and_then(Value::as_str)).collect();
    if !system.is_empty() {
        out.push(Message { role: Role::System, text: system, tool_calls: Vec::new(), tool_results: Vec::new() });
    }
    for m in messages {
        let (mut text, mut tool_calls, mut tool_results) = (String::new(), Vec::new(), Vec::new());
        for block in m.get("content").and_then(Value::as_array).into_iter().flatten() {
            let has = |k: &str| block.get(k).is_some();
            if let Some(t) = block.get("text").and_then(Value::as_str) {
                text.push_str(t);
            } else if has("image") || has("audio") {
                // `ImagePart`/`AudioPart`: not part of our `Message`
            } else if let Some(tool_use) = block.get("toolUse") {
                let arguments = match tool_use.get("input") {
                    None | Some(Value::Null) => String::new(),
                    Some(Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                };
                let id = as_text(tool_use.get("toolUseId"));
                tool_calls.push(ToolCall { id: (!id.is_empty()).then_some(id), name: as_text(tool_use.get("name")), arguments });
            } else if let Some(result) = block.get("toolResult") {
                let id = as_text(result.get("toolUseId"));
                let content = tool_result_text(result.get("content"));
                match tool_results.iter_mut().find(|e: &&mut (String, String)| e.0 == id) {
                    Some(entry) => entry.1 = content,
                    None => tool_results.push((id, content)),
                }
            }
        }
        let role = if !tool_results.is_empty() {
            Role::Tool
        } else if as_text(m.get("role")).eq_ignore_ascii_case("assistant") {
            Role::Assistant
        } else {
            Role::User
        };
        out.push(Message { role, text, tool_calls, tool_results });
    }
    out
}

/// `JsonNode.asText("")` of a field that may be absent: a value node's text, empty for a container or null.
fn as_text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

/// `toolResultText`: the `text` and `json` members of the result's content blocks.
fn tool_result_text(content: Option<&Value>) -> String {
    match content {
        None | Some(Value::Null) => String::new(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| match (p.get("text"), p.get("json")) {
                (Some(t), _) => Some(as_text(Some(t))),
                (None, Some(j)) => Some(j.to_string()),
                _ => None,
            })
            .collect(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

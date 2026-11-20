//! The conversation in an LLM request (`ProviderCodec.decode` → `ParsedConversation`) and the `conversationPredicates`
//! an `httpLlmResponse` expectation matches it with (`LlmConversationMatcher`), after the optional
//! `PromptNormalizer`.

use serde_json::Value;

use crate::request::HttpRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
    Tool,
    System,
}

impl Role {
    fn parse(name: &str) -> Option<Role> {
        match name.to_uppercase().as_str() {
            "USER" => Some(Role::User),
            "ASSISTANT" => Some(Role::Assistant),
            "TOOL" => Some(Role::Tool),
            "SYSTEM" => Some(Role::System),
            _ => None,
        }
    }
}

/// A tool call: its id (when the wire carries one), name and arguments.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub id: Option<String>,
    pub name: String,
    pub arguments: String,
}

/// `ParsedMessage`.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub role: Role,
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
    /// Tool result content by the call id (or tool name) it answers.
    pub tool_results: Vec<(String, String)>,
}

fn text_of(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn str_field(v: &Value, k: &str) -> String {
    v.get(k).map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_string)).unwrap_or_default()
}

/// `decode` for `provider`: empty when the body is not the provider's request shape.
pub fn decode(provider: &str, request: &HttpRequest) -> Vec<Message> {
    let Ok(root) = serde_json::from_str::<Value>(&request.body_str()) else { return Vec::new() };
    if !root.is_object() {
        return Vec::new();
    }
    match provider {
        "BEDROCK" if super::converse::is_converse(request) => super::converse::decode(&root),
        "ANTHROPIC" | "BEDROCK" => anthropic(&root),
        "OPENAI_RESPONSES" => responses(&root, &request.body_str()),
        "GEMINI" => gemini(&root),
        "OLLAMA" => ollama(&root),
        _ => openai(&root),
    }
}

fn openai_role(role: &str) -> Role {
    match role.to_lowercase().as_str() {
        "assistant" => Role::Assistant,
        "tool" => Role::Tool,
        "system" | "developer" => Role::System,
        _ => Role::User,
    }
}

/// `asArray`: a repeated field, which the Gemini REST API also accepts as a single object.
fn as_array(v: Option<&Value>) -> Option<Vec<Value>> {
    match v {
        Some(Value::Array(items)) => Some(items.clone()),
        Some(o @ Value::Object(_)) => Some(vec![o.clone()]),
        _ => None,
    }
}

fn openai(root: &Value) -> Vec<Message> {
    let Some(messages) = root.get("messages").and_then(Value::as_array) else { return Vec::new() };
    messages
        .iter()
        .map(|m| {
            let role = str_field(m, "role");
            let text = match m.get("content") {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Array(parts)) => parts.iter().filter(|p| p.get("type").and_then(Value::as_str) == Some("text")).map(|p| str_field(p, "text")).collect(),
                _ => String::new(),
            };
            let tool_calls = m
                .get("tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|tc| {
                    let f = tc.get("function")?;
                    Some(ToolCall {
                        id: tc.get("id").and_then(Value::as_str).filter(|i| !i.is_empty()).map(str::to_string),
                        name: str_field(f, "name"),
                        arguments: f.get("arguments").map_or_else(|| "{}".into(), |a| text_of(Some(a))),
                    })
                })
                .collect();
            let mut tool_results = Vec::new();
            if role.eq_ignore_ascii_case("tool") {
                let id = str_field(m, "tool_call_id");
                if !id.is_empty() {
                    tool_results.push((id, text.clone()));
                }
            }
            Message { role: openai_role(&role), text, tool_calls, tool_results }
        })
        .collect()
}

fn anthropic(root: &Value) -> Vec<Message> {
    let Some(messages) = root.get("messages").and_then(Value::as_array) else { return Vec::new() };
    let mut out = Vec::new();
    let system = match root.get("system") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(blocks)) => blocks.iter().filter(|b| b.get("type").and_then(Value::as_str) == Some("text")).map(|b| str_field(b, "text")).collect(),
        _ => String::new(),
    };
    if !system.is_empty() {
        out.push(Message { role: Role::System, text: system, tool_calls: Vec::new(), tool_results: Vec::new() });
    }
    for m in messages {
        let (mut text, mut tool_calls, mut tool_results, mut has_result) = (String::new(), Vec::new(), Vec::new(), false);
        match m.get("content") {
            Some(Value::String(s)) => text = s.clone(),
            Some(Value::Array(blocks)) => {
                for block in blocks {
                    match block.get("type").and_then(Value::as_str).unwrap_or_default() {
                        "text" => text.push_str(&str_field(block, "text")),
                        "tool_use" => tool_calls.push(ToolCall {
                            id: block.get("id").and_then(Value::as_str).filter(|i| !i.is_empty()).map(str::to_string),
                            name: str_field(block, "name"),
                            arguments: text_of(block.get("input")),
                        }),
                        "tool_result" => {
                            has_result = true;
                            let content = match block.get("content") {
                                Some(Value::String(s)) => s.clone(),
                                Some(Value::Array(parts)) => parts.iter().filter(|p| p.get("type").and_then(Value::as_str) == Some("text")).map(|p| str_field(p, "text")).collect(),
                                Some(other) => other.to_string(),
                                None => String::new(),
                            };
                            tool_results.push((str_field(block, "tool_use_id"), content));
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        let role = if has_result {
            Role::Tool
        } else {
            match str_field(m, "role").to_lowercase().as_str() {
                "assistant" => Role::Assistant,
                "tool" => Role::Tool,
                _ => Role::User,
            }
        };
        out.push(Message { role, text, tool_calls, tool_results });
    }
    out
}

fn responses(root: &Value, body: &str) -> Vec<Message> {
    let mut out = Vec::new();
    // `instructionsMessage`: the request's `instructions`, a leading system message.
    let instructions = root.get("instructions").and_then(Value::as_str).filter(|i| !i.is_empty()).map(|i| Message { role: Role::System, text: i.to_string(), tool_calls: Vec::new(), tool_results: Vec::new() });
    match root.get("input") {
        Some(Value::String(s)) => out.push(Message { role: Role::User, text: s.clone(), tool_calls: Vec::new(), tool_results: Vec::new() }),
        Some(Value::Array(items)) => {
            for item in items {
                match item.get("type").and_then(Value::as_str).unwrap_or_default() {
                    "function_call_output" => {
                        let output = str_field(item, "output");
                        out.push(Message { role: Role::Tool, text: output.clone(), tool_calls: Vec::new(), tool_results: vec![(str_field(item, "call_id"), output)] });
                    }
                    // `function_call_output` answers a call by its `call_id`, else by the item `id`.
                    "function_call" => out.push(Message {
                        role: Role::Assistant,
                        text: String::new(),
                        tool_calls: vec![ToolCall {
                            id: Some(str_field(item, "call_id")).filter(|i| !i.is_empty()).or_else(|| Some(str_field(item, "id")).filter(|i| !i.is_empty())),
                            name: str_field(item, "name"),
                            arguments: item.get("arguments").map_or_else(|| "{}".into(), |a| text_of(Some(a))),
                        }],
                        tool_results: Vec::new(),
                    }),
                    _ => {
                        let text = match item.get("content") {
                            Some(Value::String(s)) => s.clone(),
                            Some(Value::Array(parts)) => parts
                                .iter()
                                .filter(|p| matches!(p.get("type").and_then(Value::as_str), Some("output_text" | "input_text" | "text")))
                                .map(|p| str_field(p, "text"))
                                .collect(),
                            _ => String::new(),
                        };
                        let role = item.get("role").and_then(Value::as_str).unwrap_or("user");
                        out.push(Message { role: openai_role(role), text, tool_calls: Vec::new(), tool_results: Vec::new() });
                    }
                }
            }
        }
        _ => return Vec::new(),
    }
    let mut conversation: Vec<Message> = instructions.into_iter().collect();
    conversation.extend(super::responses::prior_messages(body));
    conversation.extend(out);
    conversation
}

fn gemini(root: &Value) -> Vec<Message> {
    let Some(contents) = as_array(root.get("contents")) else { return Vec::new() };
    let mut out = Vec::new();
    // The system prompt is a top-level `Content` (`systemInstruction`, or `system_instruction`).
    let system_instruction = if root.get("systemInstruction").is_some() { root.get("systemInstruction") } else { root.get("system_instruction") };
    let system: String = match system_instruction.filter(|s| s.is_object()) {
        Some(s) => as_array(s.get("parts")).unwrap_or_default().iter().filter_map(|p| p.get("text").and_then(Value::as_str)).collect(),
        None => String::new(),
    };
    if !system.is_empty() {
        out.push(Message { role: Role::System, text: system, tool_calls: Vec::new(), tool_results: Vec::new() });
    }
    out.extend(contents.iter().map(|content| {
            let (mut text, mut tool_calls, mut tool_results, mut has_result) = (String::new(), Vec::new(), Vec::new(), false);
            for (i, part) in as_array(content.get("parts")).unwrap_or_default().iter().enumerate() {
                if let Some(t) = part.get("text") {
                    text.push_str(&text_of(Some(t)));
                } else if let Some(fc) = part.get("functionCall") {
                    let name = str_field(fc, "name");
                    tool_calls.push(ToolCall { id: Some(format!("{name}_{i}")), name, arguments: fc.get("args").map(|a| text_of(Some(a))).unwrap_or_default() });
                } else if let Some(fr) = part.get("functionResponse") {
                    has_result = true;
                    tool_results.push((str_field(fr, "name"), fr.get("response").map(|r| text_of(Some(r))).unwrap_or_default()));
                }
            }
            let role = if has_result {
                Role::Tool
            } else if str_field(content, "role").eq_ignore_ascii_case("model") {
                Role::Assistant
            } else {
                Role::User
            };
            Message { role, text, tool_calls, tool_results }
        }));
    out
}

fn ollama(root: &Value) -> Vec<Message> {
    let Some(messages) = root.get("messages").and_then(Value::as_array) else {
        // `decodeGenerate`: `/api/generate` has an optional `system` prompt and one `prompt`.
        let Some(prompt) = root.get("prompt").and_then(Value::as_str) else { return Vec::new() };
        let mut out = Vec::new();
        if let Some(system) = root.get("system").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            out.push(Message { role: Role::System, text: system.to_string(), tool_calls: Vec::new(), tool_results: Vec::new() });
        }
        out.push(Message { role: Role::User, text: prompt.to_string(), tool_calls: Vec::new(), tool_results: Vec::new() });
        return out;
    };
    messages
        .iter()
        .map(|m| {
            let role = str_field(m, "role");
            let text = m.get("content").and_then(Value::as_str).unwrap_or_default().to_string();
            let tool_calls = m
                .get("tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|tc| {
                    let f = tc.get("function")?;
                    Some(ToolCall { id: None, name: str_field(f, "name"), arguments: f.get("arguments").map_or_else(|| "{}".into(), |a| text_of(Some(a))) })
                })
                .collect();
            let tool_results = if role.eq_ignore_ascii_case("tool") { vec![(String::new(), text.clone())] } else { Vec::new() };
            // `mapOllamaRole`: Ollama has no `developer` role.
            let role = if role.eq_ignore_ascii_case("developer") { Role::User } else { openai_role(&role) };
            Message { role, text, tool_calls, tool_results }
        })
        .collect()
}

// ------------------------------------------------------------ predicates

/// `PromptNormalizer.normalize`: nothing without options; with them whitespace collapsed and JSON keys sorted by
/// default.
pub fn normalize(text: &str, options: Option<&Value>) -> String {
    let Some(o) = options.filter(|o| o.is_object()) else { return text.to_string() };
    let flag = |k: &str, default: bool| o.get(k).and_then(Value::as_bool).unwrap_or(default);
    let drop_fields: Vec<String> = o.get("dropVolatileFields").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
    let mut result = text.to_string();
    if flag("lowercase", false) {
        result = result.to_lowercase();
    }
    let sort = flag("sortJsonKeys", true);
    if (sort || !drop_fields.is_empty()) && let Ok(root) = crate::json::parse_lenient(result.as_bytes()) && (root.is_object() || root.is_array()) {
        result = transform(&root, sort, &drop_fields).to_string();
    }
    if flag("dropBuiltInVolatileFields", false) {
        static PATTERNS: std::sync::LazyLock<[regex::Regex; 3]> = std::sync::LazyLock::new(|| {
            [
                regex::Regex::new(r"\d{4}-\d{2}-\d{2}([Tt ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?([Zz]|[+-]\d{2}:?\d{2})?)?").expect("valid"),
                regex::Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}").expect("valid"),
                regex::Regex::new(r"\b(?:req|msg|call|tool|toolu|chatcmpl|run|resp|asst|thread)_[A-Za-z0-9]{6,}\b").expect("valid"),
            ]
        });
        for p in PATTERNS.iter() {
            result = p.replace_all(&result, "").into_owned();
        }
    }
    if flag("collapseWhitespace", true) {
        result = collapse_whitespace(&result);
    }
    result
}

/// `PromptNormalizer`'s `replaceAll("\\s+", " ").trim()`: Java's `\s` is exactly the six ASCII whitespace
/// characters matched here and `trim()` drops anything up to `' '` at either end, so every input comes out as
/// upstream's (Unicode whitespace is left alone, as in Java).
pub fn collapse_whitespace(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_space = false;
    for c in text.chars() {
        if matches!(c, ' ' | '\t' | '\n' | '\x0B' | '\x0C' | '\r') {
            if !in_space {
                out.push(' ');
            }
            in_space = true;
        } else {
            out.push(c);
            in_space = false;
        }
    }
    out.trim_matches(|c: char| c <= ' ').to_string()
}

fn transform(v: &Value, sort: bool, drop: &[String]) -> Value {
    match v {
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().filter(|k| !drop.contains(k)).collect();
            if sort {
                keys.sort();
            }
            Value::Object(keys.into_iter().map(|k| (k.clone(), transform(&o[k], sort, drop))).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(|i| transform(i, sort, drop)).collect()),
        other => other.clone(),
    }
}

/// `hasToolResultForName`: a tool result answering a call to `tool` (by id, or by name).
fn has_tool_result_for(messages: &[Message], tool: &str) -> bool {
    let mut id_to_name: Vec<(String, String)> = Vec::new();
    let mut names: Vec<&str> = Vec::new();
    let mut called = false;
    for m in messages.iter().filter(|m| m.role == Role::Assistant) {
        for tc in &m.tool_calls {
            if let Some(id) = &tc.id {
                id_to_name.push((id.clone(), tc.name.clone()));
            }
            if !names.contains(&tc.name.as_str()) {
                names.push(&tc.name);
            }
            called |= tc.name == tool;
        }
    }
    for m in messages.iter().filter(|m| m.role == Role::Tool && !m.tool_results.is_empty()) {
        for (id, _) in &m.tool_results {
            if id_to_name.iter().any(|(i, n)| i == id && n == tool) || id == tool {
                return true;
            }
        }
        if called && id_to_name.is_empty() && names == [tool] {
            return true;
        }
    }
    false
}

/// `LlmConversationMatcher.matches` for the expectation's `httpLlmResponse`: `true` when it has no predicates.
/// `semantic` is the server's `SemanticMatching` judge, when installed.
pub fn matches(expectation: &Value, request: &HttpRequest, max_body: usize, semantic: Option<&crate::store::SemanticJudge>) -> bool {
    let Some(llm) = expectation.get("httpLlmResponse") else { return true };
    let Some(p) = llm.get("conversationPredicates").filter(|p| p.is_object()) else { return true };
    let text = |k: &str| p.get(k).and_then(Value::as_str).map(str::to_string);
    let turn = p.get("turnIndex").and_then(Value::as_i64);
    let (contains, matches_re, role, tool, semantic_text) = (text("latestMessageContains"), text("latestMessageMatches"), text("latestMessageRole"), text("containsToolResultFor"), text("semanticMatchAgainst"));
    if turn.is_none() && contains.is_none() && matches_re.is_none() && role.is_none() && tool.is_none() && semantic_text.is_none() {
        return true;
    }
    let Some(provider) = llm.get("provider").and_then(Value::as_str) else { return false };
    if request.body.len() > max_body {
        return false;
    }
    let messages = decode(provider, request);
    let Some(last) = messages.last() else { return false };
    let normalization = p.get("normalization");
    if let Some(turn) = turn && messages.iter().filter(|m| m.role == Role::Assistant).count() as i64 != turn {
        return false;
    }
    if let Some(expected) = contains && !normalize(&last.text, normalization).contains(&normalize(&expected, normalization)) {
        return false;
    }
    if let Some(pattern) = matches_re {
        let subject = normalize(&last.text, normalization);
        // Bounded by `regexMatchingTimeoutMillis` as `matchesWithRegexTimeout` does, silently (a null logger).
        let found = || crate::matcher::java_pattern::compile(&pattern).is_ok_and(|r| r.find(&subject));
        if !crate::matcher::string::find_within_budget(&pattern, &subject, found) {
            return false;
        }
    }
    if let Some(role) = role && Role::parse(&role) != Some(last.role) {
        return false;
    }
    if let Some(tool) = tool && !has_tool_result_for(&messages, &tool) {
        return false;
    }
    // `semanticMatchAgainst` is ignored unless semantic matching is installed (deterministic fallback); then the
    // judge must say yes.
    if let (Some(meaning), Some(judge)) = (semantic_text, semantic) && !judge(&last.text, &meaning) {
        return false;
    }
    true
}

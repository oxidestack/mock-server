//! `AgentRunAnalyzer` and `AgentRunDiff`: a recorded agent run reconstructed from its LLM requests (the richest
//! decoded conversation), summarised, drawn as a call graph, searched for tool calls, or diffed against another run
//! at the message level after `PromptNormalizer`. Pure: no network, no LLM.

use serde_json::{Map, Value, json};

use super::conversation::{self, Message, Role};
use crate::request::HttpRequest;

/// `Role.name()`.
pub fn role_name(role: Role) -> &'static str {
    match role {
        Role::User => "USER",
        Role::Assistant => "ASSISTANT",
        Role::Tool => "TOOL",
        Role::System => "SYSTEM",
    }
}

/// `ProviderCodec.decode`: `None` where the provider's codec does not decode requests (Cohere and Voyage rerank).
pub fn decode(provider: &str, request: &HttpRequest) -> Option<Vec<Message>> {
    match provider {
        "COHERE" | "VOYAGE" => None,
        _ => Some(conversation::decode(provider, request)),
    }
}

/// `canonicalConversation`: the decoded conversation with the most messages, the later one on a tie.
pub fn canonical(requests: &[HttpRequest], provider: &str) -> Option<Vec<Message>> {
    let mut richest: Option<Vec<Message>> = None;
    for request in requests {
        if let Some(parsed) = decode(provider, request) && richest.as_ref().is_none_or(|r| parsed.len() >= r.len()) {
            richest = Some(parsed);
        }
    }
    richest
}

/// `inspectToolCalls`: the assistant tool calls named `tool` whose arguments `arguments_regex` finds.
pub fn inspect_tool_calls(requests: &[HttpRequest], provider: &str, tool: Option<&str>, arguments_regex: Option<&str>) -> Result<Vec<(String, String)>, String> {
    let pattern = match arguments_regex.filter(|r| !r.is_empty()) {
        Some(r) => Some(crate::matcher::java_pattern::compile(r).map_err(|_| format!("invalid argumentsRegex: {r}"))?),
        None => None,
    };
    let mut matches = Vec::new();
    for message in canonical(requests, provider).unwrap_or_default().iter().filter(|m| m.role == Role::Assistant) {
        for call in &message.tool_calls {
            if tool.is_some_and(|t| t != call.name) {
                continue;
            }
            if let Some(p) = &pattern && !p.find(&call.arguments) {
                continue;
            }
            matches.push((call.name.clone(), call.arguments.clone()));
        }
    }
    Ok(matches)
}

/// `explain_agent_run`'s answer after the provider: `summarise` and `buildCallGraph` over the canonical run.
pub fn explain(requests: &[HttpRequest], provider: &str) -> Value {
    let mut o = Map::new();
    o.insert("provider".into(), json!(provider));
    let messages = canonical(requests, provider).unwrap_or_default();
    if messages.is_empty() {
        o.insert("message".into(), json!(format!("no decodable {provider} conversation found in recorded requests")));
        o.insert("messageCount".into(), json!(0));
        return Value::Object(o);
    }
    let mut tool_sequence = Vec::new();
    let mut results_for: Vec<String> = Vec::new();
    for m in &messages {
        if m.role == Role::Assistant {
            tool_sequence.extend(m.tool_calls.iter().map(|c| json!(c.name)));
        }
        if m.role == Role::Tool {
            for (id, _) in &m.tool_results {
                if !results_for.contains(id) {
                    results_for.push(id.clone());
                }
            }
        }
    }
    o.insert("messageCount".into(), json!(messages.len()));
    o.insert("assistantTurnCount".into(), json!(messages.iter().filter(|m| m.role == Role::Assistant).count()));
    o.insert("toolCallSequence".into(), Value::Array(tool_sequence));
    o.insert("toolResultsFor".into(), json!(results_for));
    o.insert("latestMessageRole".into(), json!(role_name(messages[messages.len() - 1].role)));
    let (mut nodes, mut edges) = (Vec::new(), Vec::new());
    let mut call_nodes: Vec<(String, String)> = Vec::new();
    for (i, m) in messages.iter().enumerate() {
        let id = format!("m{i}");
        nodes.push(json!({"id": id, "kind": role_name(m.role), "label": label(m)}));
        if i > 0 {
            edges.push(json!({"from": format!("m{}", i - 1), "to": id, "kind": "NEXT"}));
        }
        if m.role == Role::Assistant {
            for (t, call) in m.tool_calls.iter().enumerate() {
                let call_node = format!("{id}_tc{t}");
                nodes.push(json!({"id": call_node, "kind": "TOOL_CALL", "label": call.name}));
                edges.push(json!({"from": id, "to": call_node, "kind": "INVOKES"}));
                if let Some(call_id) = &call.id {
                    call_nodes.retain(|(k, _)| k != call_id);
                    call_nodes.push((call_id.clone(), call_node));
                }
            }
        }
        if m.role == Role::Tool {
            for (result_id, _) in &m.tool_results {
                if let Some((_, node)) = call_nodes.iter().find(|(k, _)| k == result_id) {
                    edges.push(json!({"from": node, "to": id, "kind": "RESULT"}));
                }
            }
        }
    }
    o.insert("callGraph".into(), json!({"nodes": nodes, "edges": edges}));
    Value::Object(o)
}

/// A graph node's label: the text's first 40 code points (then `…`), whitespace collapsed, or the role.
fn label(m: &Message) -> String {
    if m.text.is_empty() {
        return role_name(m.role).into();
    }
    let trimmed = if m.text.chars().count() > 40 { m.text.chars().take(40).collect::<String>() + "…" } else { m.text.clone() };
    conversation::collapse_whitespace(&trimmed)
}

/// `AgentRunDiff.RunSide`: a run's requests, its provider, and the report's token and cost totals.
pub struct RunSide {
    pub requests: Vec<HttpRequest>,
    pub provider: Option<String>,
    pub totals: Option<(i64, i64, f64)>,
}

impl RunSide {
    /// `runSide`/`diffRunSide`: the report's included exchanges, redacted, with the first one's detected provider.
    pub fn from_report(state: &crate::state::State, built: &super::report::Built) -> RunSide {
        let requests = built.exchanges.iter().map(|x| super::report::redacted_for_export(state, &x.request)).collect();
        RunSide { requests, provider: built.exchanges.first().map(|x| x.provider.clone()), totals: Some(built.report.token_totals()) }
    }

    fn messages(&self) -> Vec<Message> {
        match &self.provider {
            Some(p) => canonical(&self.requests, p).unwrap_or_default(),
            None => Vec::new(),
        }
    }
}

/// `NormalizationOptions` bound from JSON as Jackson would (`Boolean` fields coerced from integers and
/// `"true"`/`"false"`, a lone value accepted as the field list); `Err` carries the binding exception's message.
pub fn bind_normalization(node: &Value) -> Result<Value, String> {
    const AT: &str = "\n at [Source: UNKNOWN; byte offset: #UNKNOWN] (through reference chain: org.mockserver.model.NormalizationOptions[";
    let token = |v: &Value| match v {
        Value::Object(_) => "Object value (token `JsonToken.START_OBJECT`)".to_string(),
        Value::Array(_) => "Array value (token `JsonToken.START_ARRAY`)".to_string(),
        _ => "Floating-point value (token `JsonToken.VALUE_NUMBER_FLOAT`)".to_string(),
    };
    let Some(o) = node.as_object() else { return Err("Cannot deserialize value of type `org.mockserver.model.NormalizationOptions`".into()) };
    let mut bound = Map::new();
    for key in ["collapseWhitespace", "lowercase", "sortJsonKeys", "dropBuiltInVolatileFields"] {
        let fail = |from: String| format!("Cannot deserialize value of type `java.lang.Boolean` from {from}{AT}\"{key}\"])");
        let value = match o.get(key) {
            None | Some(Value::Null) => None,
            Some(Value::Bool(b)) => Some(*b),
            Some(Value::Number(n)) if n.is_i64() || n.is_u64() => Some(n.as_i64() != Some(0)),
            Some(Value::String(s)) => match s.as_str() {
                "true" | "True" | "TRUE" => Some(true),
                "false" | "False" | "FALSE" => Some(false),
                "" => None,
                other => return Err(fail(format!("String \"{other}\": only \"true\" or \"false\" recognized"))),
            },
            Some(other) => return Err(fail(token(other))),
        };
        if let Some(b) = value {
            bound.insert(key.into(), json!(b));
        }
    }
    let element = |i: usize, v: &Value| match v {
        Value::String(s) => Ok(Value::String(s.clone())),
        Value::Null => Ok(Value::Null),
        Value::Bool(_) | Value::Number(_) => Ok(Value::String(crate::jnode::from_value(v).as_text())),
        other => Err(format!("Cannot deserialize value of type `java.lang.String` from {}{AT}\"dropVolatileFields\"]->java.util.ArrayList[{i}])", token(other))),
    };
    match o.get("dropVolatileFields") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            let fields = items.iter().enumerate().map(|(i, v)| element(i, v)).collect::<Result<Vec<_>, _>>()?;
            bound.insert("dropVolatileFields".into(), Value::Array(fields));
        }
        Some(other) => {
            bound.insert("dropVolatileFields".into(), Value::Array(vec![element(0, other)?]));
        }
    }
    Ok(Value::Object(bound))
}

/// `AgentRunDiff.diff` as `serializeDiff` writes it. `options` are bound `NormalizationOptions` (`None`: defaults).
pub fn diff(before: &RunSide, after: &RunSide, options: Option<&Value>) -> Value {
    let defaults = json!({});
    let options = Some(options.unwrap_or(&defaults));
    let (before_messages, after_messages) = (before.messages(), after.messages());
    let normalize = |messages: &[Message]| -> Vec<(&'static str, String)> {
        messages
            .iter()
            .map(|m| {
                let text = if m.text.is_empty() && m.role == Role::Tool { m.tool_results.iter().map(|(_, v)| v.as_str()).collect::<Vec<_>>().join("\n") } else { m.text.clone() };
                (role_name(m.role), super::report::mask_secrets(&conversation::normalize(&text, options)))
            })
            .collect()
    };
    let (b, a) = (normalize(&before_messages), normalize(&after_messages));
    let (n, m) = (b.len(), a.len());
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if b[i] == a[j] { lcs[i + 1][j + 1] + 1 } else { lcs[i + 1][j].max(lcs[i][j + 1]) };
        }
    }
    // (change type, role, before text, after text)
    let mut raw: Vec<(&str, &str, Option<&str>, Option<&str>)> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if b[i] == a[j] {
            raw.push(("UNCHANGED", b[i].0, Some(&b[i].1), Some(&a[j].1)));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            raw.push(("REMOVED", b[i].0, Some(&b[i].1), None));
            i += 1;
        } else {
            raw.push(("ADDED", a[j].0, None, Some(&a[j].1)));
            j += 1;
        }
    }
    raw.extend(b[i..].iter().map(|x| ("REMOVED", x.0, Some(x.1.as_str()), None)));
    raw.extend(a[j..].iter().map(|x| ("ADDED", x.0, None, Some(x.1.as_str()))));
    let mut diffs = Vec::new();
    let mut k = 0;
    while k < raw.len() {
        let current = raw[k];
        if current.0 == "REMOVED" && raw.get(k + 1).is_some_and(|next| next.0 == "ADDED" && next.1 == current.1) {
            diffs.push(("CHANGED", current.1, current.2, raw[k + 1].3));
            k += 2;
            continue;
        }
        diffs.push(current);
        k += 1;
    }
    let fingerprints = |messages: &[Message]| -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for call in messages.iter().filter(|m| m.role == Role::Assistant).flat_map(|m| &m.tool_calls) {
            let fingerprint = format!("{}({})", call.name, conversation::normalize(&call.arguments, options));
            if !out.contains(&fingerprint) {
                out.push(fingerprint);
            }
        }
        out
    };
    let (before_tools, after_tools) = (fingerprints(&before_messages), fingerprints(&after_messages));
    let mut o = Map::new();
    o.insert("promptChanged".into(), json!(diffs.iter().any(|d| d.0 != "UNCHANGED")));
    o.insert("messageCountBefore".into(), json!(before_messages.len()));
    o.insert("messageCountAfter".into(), json!(after_messages.len()));
    let text = |t: Option<&str>| t.map_or(Value::Null, |t| json!(t));
    o.insert(
        "messageDiffs".into(),
        Value::Array(diffs.iter().map(|d| json!({"changeType": d.0, "role": d.1, "beforeText": text(d.2), "afterText": text(d.3)})).collect()),
    );
    o.insert("toolCallsAdded".into(), json!(after_tools.iter().filter(|t| !before_tools.contains(t)).collect::<Vec<_>>()));
    o.insert("toolCallsRemoved".into(), json!(before_tools.iter().filter(|t| !after_tools.contains(t)).collect::<Vec<_>>()));
    if let (Some((bi, bo, bc)), Some((ai, ao, ac))) = (before.totals, after.totals) {
        let double = |v: f64| crate::model::number(&java_compat::double_to_string(v));
        let mut t = Map::new();
        t.insert("inputTokensBefore".into(), json!(bi));
        t.insert("inputTokensAfter".into(), json!(ai));
        t.insert("inputTokensDelta".into(), json!(ai - bi));
        t.insert("outputTokensBefore".into(), json!(bo));
        t.insert("outputTokensAfter".into(), json!(ao));
        t.insert("outputTokensDelta".into(), json!(ao - bo));
        t.insert("costUsdBefore".into(), double(bc));
        t.insert("costUsdAfter".into(), double(ac));
        t.insert("costUsdDelta".into(), double(ac - bc));
        o.insert("tokenDelta".into(), Value::Object(t));
    }
    Value::Object(o)
}

/// `LlmOptimisationReportService.Filter` from a `before`/`after` node (`emptyToNull` on each field).
pub fn filter_from(node: Option<&Value>) -> super::report::Filter {
    let field = |k: &str| {
        node.and_then(|n| n.get(k)).and_then(|v| match v {
            Value::Null | Value::Object(_) | Value::Array(_) => None,
            Value::String(s) => Some(s.clone()),
            other => Some(other.to_string()),
        })
    };
    super::report::Filter::new(field("session").as_deref(), field("host").as_deref(), field("provider").as_deref())
}

/// `diff_agent_runs` and `PUT /mockserver/llm/diffRuns`: each side's report, then the diff; `Err` when the
/// normalization options do not bind (the binding exception's message).
/// The recorded pairs are retrieved (and that retrieve logged, with `retrieve_filter` as its body) once the
/// options bind.
pub fn diff_runs(state: &std::sync::Arc<crate::state::State>, body: &Value, retrieve_filter: Option<&Value>) -> Result<Value, String> {
    let options = match body.get("normalization") {
        Some(n) if n.is_object() => Some(bind_normalization(n)?),
        _ => None,
    };
    crate::mcp::logged_retrieve(state, "REQUEST_RESPONSES", retrieve_filter);
    let before = super::report::build(state, &filter_from(body.get("before")));
    let after = super::report::build(state, &filter_from(body.get("after")));
    Ok(diff(&RunSide::from_report(state, &before), &RunSide::from_report(state, &after), options.as_ref()))
}

//! `MockoonImporter`: each http route of an environment becomes expectations, `:param`/`*` endpoint tokens
//! become regex segments, and the route's `responseMode` decides between rule-gated expectations (descending
//! priority) and one cycling SEQUENTIAL/RANDOM expectation.

use jackson::JsonNode;
use serde_json::Value;

use super::{Affix, Ctx, Imported, Options, Req, Resp, affix_regex, expectation, parse, set};
use crate::java_text::quote;
use super::TextOrNull;

pub fn import(document: &str, options: &Options) -> Result<Imported, String> {
    if document.trim().is_empty() {
        return Err("Mockoon environment JSON body is required".into());
    }
    let root = parse(document).map_err(|e| format!("failed to parse Mockoon environment JSON: {e}"))?;
    let Some(routes) = root.path("routes").as_array().cloned() else { return Err("not a valid Mockoon environment — missing top-level 'routes' array".into()) };
    let mut expectations = Vec::new();
    let mut warnings = Vec::new();
    for (index, route) in routes.iter().enumerate() {
        build_route(route, index, &mut expectations, &mut warnings);
    }
    Ok(Imported { expectations: super::redact::redact_preserving_actions(expectations, options), warnings: Some(warnings) })
}

fn build_route(route: &JsonNode, index: usize, expectations: &mut Vec<Value>, warnings: &mut Vec<super::Warning>) {
    let method = route.value_text("method");
    let endpoint = route.value_text("endpoint");
    let locator = format!("route {} /{}", method.as_deref().map_or_else(|| "?".to_string(), str::to_uppercase), endpoint.as_deref().unwrap_or(""));
    let mut ctx = Ctx::new(locator, warnings);
    if let Some(kind) = route.value_text("type").filter(|k| !k.eq_ignore_ascii_case("http")) {
        ctx.warn("route.type", format!("route type '{kind}' is not mapped — only 'http' routes are importable"));
        return;
    }
    let Some(responses) = route.path("responses").as_array().filter(|a| !a.is_empty()).cloned() else {
        ctx.warn("route.responses", "route has no responses — skipped");
        return;
    };
    let mode = route.value_text("responseMode").map(|m| m.to_uppercase());
    let base = || base_request(method.as_deref(), endpoint.as_deref());
    let id = route_id(route, index);
    match mode.as_deref() {
        Some(mode @ ("SEQUENTIAL" | "RANDOM")) => {
            if responses.iter().any(|r| r.path("rules").as_array().is_some_and(|a| !a.is_empty())) {
                ctx.warn("route.responseMode", format!("{mode} mode ignores per-response rules — the rules were not converted to matchers"));
            }
            let mapped: Vec<Resp> = responses
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    let locator = format!("{} response[{i}]", ctx.locator);
                    map_response(r, &mut ctx.at(locator))
                })
                .collect();
            let mut e = expectation(Some(&id), &base());
            super::respond_all(&mut e, &mapped, mode);
            expectations.push(Value::Object(e));
            return;
        }
        Some("DISABLE_RULES") => {
            ctx.warn("route.responseMode", "DISABLE_RULES always serves the first/default response — response rules were not converted to matchers");
            let mut e = expectation(Some(&format!("{id}-0")), &base());
            super::respond(&mut e, &map_response(&responses[0], &mut ctx));
            expectations.push(Value::Object(e));
            return;
        }
        Some("FALLBACK") => ctx.warn(
            "route.responseMode",
            "FALLBACK mode proxies unmatched requests upstream — the proxy fallback is not reproduced; rule-based responses are still mapped",
        ),
        _ => {}
    }
    // Rules-based: one expectation per response, earlier ones (with rules) at higher priority.
    let total = responses.len();
    for (i, response) in responses.iter().enumerate() {
        let locator = format!("{} response[{i}]", ctx.locator);
        let mut ctx = ctx.at(locator);
        let mut req = base();
        let mut rules_applied = false;
        if let Some(rules) = response.path("rules").as_array().filter(|a| !a.is_empty()) {
            let or = response.value_text("rulesOperator").is_some_and(|o| o.eq_ignore_ascii_case("OR"));
            if or && rules.len() > 1 {
                ctx.warn("response.rulesOperator", "OR-combined rules cannot be expressed as a single AND matcher — only the first rule was applied");
                rules_applied = apply_rule(&mut req, &rules[0], &mut ctx);
            } else {
                for rule in rules {
                    rules_applied |= apply_rule(&mut req, rule, &mut ctx);
                }
            }
        }
        let is_default = response.path("default").as_boolean_or(false);
        let priority = if rules_applied && !is_default { (total - i) as i64 } else { 0 };
        let mut e = expectation(Some(&format!("{id}-{i}")), &req);
        e.insert("priority".into(), priority.into());
        super::respond(&mut e, &map_response(response, &mut ctx));
        expectations.push(Value::Object(e));
    }
}

fn base_request(method: Option<&str>, endpoint: Option<&str>) -> Req {
    let mut req = Req::default();
    if let Some(m) = method.filter(|m| !m.eq_ignore_ascii_case("all")) {
        req.method = Some(m.to_uppercase());
    }
    req.path = Some(convert_endpoint(endpoint));
    req
}

/// `:param` segments as `[^/]+`, `*` as `.*`, the literal spans between them regex-escaped.
fn convert_endpoint(endpoint: Option<&str>) -> String {
    let Some(endpoint) = endpoint.filter(|e| !e.is_empty()) else { return "/".into() };
    let path = if endpoint.starts_with('/') { endpoint.to_string() } else { format!("/{endpoint}") };
    let word = |c: &char| c.is_ascii_alphanumeric() || *c == '_';
    let mut out = String::new();
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ':' && chars.peek().is_some_and(word) {
            while chars.peek().is_some_and(word) {
                chars.next();
            }
            out.push_str("[^/]+");
        } else if c == '*' {
            out.push_str(".*");
        } else {
            if "\\.[]{}()+?^$|".contains(c) {
                out.push('\\');
            }
            out.push(c);
        }
    }
    out
}

fn apply_rule(req: &mut Req, rule: &JsonNode, ctx: &mut Ctx) -> bool {
    let Some(target) = rule.value_text("target") else { return false };
    let modifier = rule.value_text("modifier");
    let value = rule.value_text("value");
    let operator = rule.value_text("operator").map(|o| o.to_lowercase());
    if let Some(op) = rule.value_text("operator").filter(|o| o.eq_ignore_ascii_case("null") || o.eq_ignore_ascii_case("empty_array")) {
        ctx.warn("response.rules.operator", format!("rule operator '{op}' has no MockServer analogue — omitted"));
        return false;
    }
    let v = value.clone().unwrap_or_default();
    let regex = match operator.as_deref() {
        Some("regex_i") => format!("(?i){v}"),
        Some("regex") => v.clone(),
        _ => quote(&v),
    };
    let matcher = if rule.path("invert").as_boolean_or(false) { format!("!{regex}") } else { regex };
    match target.to_lowercase().as_str() {
        kind @ ("query" | "header") => {
            let Some(name) = modifier else {
                let what = if kind == "query" { "parameter" } else { "header" };
                ctx.warn(format!("response.rules.{kind}"), format!("{kind} rule has no 'modifier' ({what} name) — the rule was dropped"));
                return false;
            };
            super::add(if kind == "query" { &mut req.query } else { &mut req.headers }, &name, vec![matcher]);
            true
        }
        "body" => {
            if let Some(m) = modifier.filter(|m| !m.is_empty()) {
                req.body = Some(super::json_path_body(&if m.starts_with('$') { m } else { format!("$.{m}") }));
                if let Some(v) = value.filter(|v| !v.is_empty()) {
                    ctx.warn("response.rules.body", format!("body rule value '{v}' is not compared; only the JSONPath existence is matched"));
                }
                return true;
            }
            let Some(v) = value else { return false };
            req.body = Some(super::regex_body(&if operator.as_deref() == Some("regex") { v } else { affix_regex(Affix::Contains, "", &v) }));
            true
        }
        "params" => {
            ctx.warn("response.rules.params", "path/route-parameter rules are not mapped; the parameter is already matched by the path segment");
            false
        }
        "cookie" => {
            ctx.warn("response.rules.cookie", "cookie rules are not mapped — add an explicit cookie matcher if needed");
            false
        }
        "method" | "path" => {
            ctx.warn(format!("response.rules.{target}"), format!("'{target}' rules are not mapped (the route already fixes method/path)"));
            false
        }
        _ => {
            ctx.warn("response.rules.target", format!("rule target '{target}' is not mapped — omitted"));
            false
        }
    }
}

fn map_response(response: &JsonNode, ctx: &mut Ctx) -> Resp {
    let mut resp = Resp::status(response.path("statusCode").as_int_or(200) as i64);
    if let Some(headers) = response.path("headers").as_array() {
        set(&mut resp.headers, headers.iter().filter_map(|h| Some((h.value_text("key")?, vec![h.value_text("value")?]))).collect());
    }
    let body = response.value_text("body");
    if let Some(b) = body.as_ref().filter(|b| !b.is_empty()) {
        resp.body = Some(Value::String(b.clone()));
    }
    if let latency @ (JsonNode::Int(_) | JsonNode::Long(_)) = response.path("latency") && latency.long_value() > 0 {
        resp.delay_millis = Some(latency.long_value());
    }
    if response.path("bodyType").text_value().is_some_and(|t| t.eq_ignore_ascii_case("FILE")) {
        ctx.warn("response.filePath", "file-backed response bodies reference an external file that is not resolved on import; inline the body instead");
    }
    if response.path("databucketID").text_value().is_some_and(|d| !d.is_empty()) {
        ctx.warn("response.databucketID", "data-bucket references are not mapped; the response body is used verbatim");
    }
    if body.as_ref().is_some_and(|b| b.contains("{{") || b.contains("}}")) {
        ctx.warn("response.body", "the body contains Mockoon/Handlebars templating ({{...}}) which is served verbatim — MockServer templating syntax differs");
    }
    resp
}

fn route_id(route: &JsonNode, index: usize) -> String {
    match route.value_text("uuid").filter(|u| !u.is_empty()) {
        Some(uuid) => format!("mockoon-{uuid}"),
        None => format!("mockoon-route-{index}"),
    }
}

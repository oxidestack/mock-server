//! `MountebankImporter`: the stubs of http/https imposters become expectations (predicates AND-combined into one
//! matcher, `is`/`proxy`/`fault` responses, `_behaviors.wait` as a delay); the rest becomes warnings.

use jackson::JsonNode;
use serde_json::{Map, Value};

use super::{Affix, Ctx, Imported, Options, Req, Resp, affix_regex, expectation, parse, set, url_parts};
use super::{TextOrNull, field_names};

pub fn import(document: &str, options: &Options) -> Result<Imported, String> {
    if document.trim().is_empty() {
        return Err("Mountebank imposter JSON body is required".into());
    }
    let root = parse(document).map_err(|e| format!("failed to parse Mountebank imposter JSON: {e}"))?;
    let imposters: Vec<JsonNode> = match &root {
        JsonNode::Array(items) => items.to_vec(),
        JsonNode::Object(_) if root.path("imposters").is_array() => root.path("imposters").as_array().cloned().unwrap_or_default(),
        JsonNode::Object(o) if o.contains_key("stubs") || o.contains_key("protocol") => vec![root.clone()],
        _ => {
            return Err("not a valid Mountebank imposter document — expected an imposter object with 'protocol'/'stubs', an 'imposters' array, or a JSON array of imposters".into());
        }
    };
    let mut expectations = Vec::new();
    let mut warnings = Vec::new();
    for (imposter_index, imposter) in imposters.iter().enumerate() {
        let protocol = imposter.value_text("protocol");
        let port = imposter.get("port").map_or_else(|| "?".to_string(), JsonNode::as_text);
        let mut ctx = Ctx::new(format!("imposter {}:{port}", protocol.as_deref().unwrap_or("?")), &mut warnings);
        if let Some(p) = protocol.as_deref().filter(|p| !p.eq_ignore_ascii_case("http") && !p.eq_ignore_ascii_case("https")) {
            ctx.warn("imposter.protocol", format!("only http/https imposters are importable — this {p} imposter was skipped"));
            continue;
        }
        let Some(stubs) = imposter.path("stubs").as_array().cloned() else {
            ctx.warn("imposter.stubs", "no 'stubs' array present — nothing to import for this imposter");
            continue;
        };
        for (stub_index, stub) in stubs.iter().enumerate() {
            let locator = format!("{} stub[{stub_index}]", ctx.locator);
            expectations.push(build(stub, &format!("mountebank-{imposter_index}-{stub_index}"), &mut ctx.at(locator)));
        }
    }
    Ok(Imported { expectations: super::redact::redact_preserving_actions(expectations, options), warnings: Some(warnings) })
}

fn build(stub: &JsonNode, id: &str, ctx: &mut Ctx) -> Value {
    let mut req = Req::default();
    for predicate in stub.path("predicates").as_array().into_iter().flatten() {
        apply_predicate(&mut req, predicate, ctx);
    }
    let responses: Vec<JsonNode> = stub.path("responses").as_array().cloned().unwrap_or_default();
    if responses.is_empty() {
        ctx.warn("stub.responses", "stub has no responses — a default 200 response was generated");
        let mut e = expectation(Some(id), &req);
        super::respond(&mut e, &Resp::status(200));
        return Value::Object(e);
    }
    if responses.len() == 1 {
        return single(&req, &responses[0], id, ctx);
    }
    if responses.iter().all(|r| r.get("is").is_some()) {
        let mut mapped = Vec::new();
        let mut repeat_seen = false;
        for r in &responses {
            let mut resp = map_is(&r.path("is"), ctx);
            apply_wait(&mut resp, r, ctx);
            repeat_seen |= r.path("_behaviors").path("repeat").is_int();
            warn_unmapped_behaviors(r, ctx);
            mapped.push(resp);
        }
        if repeat_seen {
            ctx.warn("responses._behaviors.repeat", "per-response 'repeat' is not supported for a cycling multi-response expectation — each response is served once per cycle");
        }
        let mut e = expectation(Some(id), &req);
        super::respond_all(&mut e, &mapped, "SEQUENTIAL");
        return Value::Object(e);
    }
    ctx.warn("stub.responses", "stub has multiple responses of mixed/non-'is' type — only the first response was mapped (MockServer binds one action per expectation)");
    single(&req, &responses[0], id, ctx)
}

fn single(req: &Req, response: &JsonNode, id: &str, ctx: &mut Ctx) -> Value {
    warn_unmapped_behaviors(response, ctx);
    if let JsonNode::Int(repeat) = response.path("_behaviors").path("repeat") && repeat > 0 {
        ctx.warn(
            "response._behaviors.repeat",
            "'repeat' is dropped for a single-response stub — Mountebank serves a single response indefinitely, so the response stays available for every matching request",
        );
    }
    let mut e = expectation(Some(id), req);
    if let Some(is) = response.get("is") {
        let mut resp = map_is(is, ctx);
        apply_wait(&mut resp, response, ctx);
        super::respond(&mut e, &resp);
    } else if let Some(proxy) = response.get("proxy") {
        map_proxy(&mut e, proxy, ctx);
    } else if let Some(fault) = response.get("fault") {
        let fault = fault.as_text();
        if fault.eq_ignore_ascii_case("CONNECTION_RESET_BY_PEER") {
            e.insert("httpError".into(), serde_json::json!({"resetConnection": true}));
        } else {
            if fault.eq_ignore_ascii_case("RANDOM_DATA_THEN_CLOSE") {
                ctx.warn("response.fault.RANDOM_DATA_THEN_CLOSE", "approximated as an immediate connection drop; the random bytes are not reproduced");
            } else {
                ctx.warn(format!("response.fault.{fault}"), "unknown fault type — approximated as a dropped connection");
            }
            super::drop_connection(&mut e);
        }
    } else if response.get("inject").is_some() {
        ctx.warn("response.inject", "JavaScript inject responses are not mapped — a placeholder 501 response was generated");
        super::respond(&mut e, &Resp { body: Some("inject response not imported".into()), ..Resp::status(501) });
    } else {
        ctx.warn("response", format!("unrecognised response type {} — a default 200 response was generated", field_names(response)));
        super::respond(&mut e, &Resp::status(200));
    }
    Value::Object(e)
}

/// A predicate's operator and whether it matches case-insensitively (Mountebank's default).
struct Predicate {
    operator: String,
    case_insensitive: bool,
}

impl Predicate {
    fn flags(&self) -> &'static str {
        if self.case_insensitive { "(?i)" } else { "" }
    }

    /// `toMatcher`: the matcher value for a method, path, query or header predicate.
    fn matcher(&self, value: &str, field: &str, ctx: &mut Ctx) -> String {
        let flags = self.flags();
        match self.operator.as_str() {
            "equals" | "deepEquals" => value.to_string(),
            "matches" => format!("{flags}{value}"),
            "contains" => affix_regex(Affix::Contains, flags, value),
            "startsWith" => affix_regex(Affix::StartsWith, flags, value),
            "endsWith" => affix_regex(Affix::EndsWith, flags, value),
            op => {
                ctx.warn(format!("predicate.{op}.{field}"), format!("predicate operator '{op}' is not mapped for {field} — treated as exact match"));
                value.to_string()
            }
        }
    }
}

fn apply_predicate(req: &mut Req, predicate: &JsonNode, ctx: &mut Ctx) {
    let has = |k: &str| predicate.get(k).is_some();
    if has("and") || has("or") || has("not") {
        ctx.warn(format!("predicate.{}", field_names(predicate)), "compound predicates (and/or/not) are not mapped — omitted");
        return;
    }
    if has("inject") {
        ctx.warn("predicate.inject", "JavaScript inject predicates are not mapped — omitted");
        return;
    }
    let Some(operator) = predicate.field_names().into_iter().find(|k| k != "caseSensitive" && k != "except") else { return };
    let Some(fields) = predicate.path(&operator).as_object().cloned() else {
        ctx.warn(format!("predicate.{operator}"), "unsupported predicate shape — omitted");
        return;
    };
    if has("except") {
        ctx.warn(format!("predicate.{operator}"), "'except' predicate modifier is not mapped — matching uses MockServer defaults");
    }
    let predicate = Predicate { case_insensitive: !predicate.path("caseSensitive").as_boolean_or(false), operator };
    if predicate.case_insensitive && (predicate.operator == "equals" || predicate.operator == "deepEquals") {
        ctx.warn(
            format!("predicate.{}", predicate.operator),
            "Mountebank matches case-insensitively by default but MockServer matches these exact values case-sensitively — set caseSensitive:true upstream or adjust the values if case-insensitive matching is required",
        );
    }
    for (field, value) in &fields {
        match field.to_lowercase().as_str() {
            "method" => req.method = Some(predicate.matcher(&value.as_text(), "method", ctx)),
            "path" => req.path = Some(predicate.matcher(&value.as_text(), "path", ctx)),
            "query" => apply_map(req, value, &predicate, Target::Query, ctx),
            "headers" => apply_map(req, value, &predicate, Target::Headers, ctx),
            "body" => apply_body(req, value, &predicate, ctx),
            _ => ctx.warn(format!("predicate.{}.{field}", predicate.operator), format!("request field '{field}' is not mapped — omitted")),
        }
    }
}

#[derive(Clone, Copy)]
enum Target {
    Query,
    Headers,
}

fn apply_map(req: &mut Req, map: &JsonNode, predicate: &Predicate, target: Target, ctx: &mut Ctx) {
    let Some(map) = map.as_object() else { return };
    let field = match target {
        Target::Query => "query",
        Target::Headers => "headers",
    };
    let mut entries = Vec::new();
    for (key, v) in map {
        if predicate.operator == "exists" {
            if v.as_boolean_or(true) {
                entries.push((key.clone(), ".*".to_string()));
            } else {
                ctx.warn(format!("predicate.exists.{field}.{key}"), "'exists:false' (must-be-absent) has no direct MockServer analogue on a named key — omitted");
            }
            continue;
        }
        entries.push((key.clone(), predicate.matcher(&v.as_text(), &format!("{field}.{key}"), ctx)));
    }
    let entries_of = match target {
        Target::Query => &mut req.query,
        Target::Headers => &mut req.headers,
    };
    for (name, value) in entries {
        super::add(entries_of, &name, vec![value]);
    }
}

fn apply_body(req: &mut Req, value: &JsonNode, predicate: &Predicate, ctx: &mut Ctx) {
    if value.is_object() || value.is_array() {
        req.body = Some(super::json_body(&value.to_java_string(), if predicate.operator == "deepEquals" { "STRICT" } else { "ONLY_MATCHING_FIELDS" }));
        return;
    }
    let text = value.as_text();
    let flags = predicate.flags();
    req.body = Some(match predicate.operator.as_str() {
        "equals" | "deepEquals" => Value::String(text),
        "contains" if predicate.case_insensitive => super::regex_body(&affix_regex(Affix::Contains, flags, &text)),
        "contains" => super::substring_body(&text),
        "matches" => super::regex_body(&format!("{flags}{text}")),
        "startsWith" => super::regex_body(&affix_regex(Affix::StartsWith, flags, &text)),
        "endsWith" => super::regex_body(&affix_regex(Affix::EndsWith, flags, &text)),
        op => {
            ctx.warn(format!("predicate.{op}.body"), format!("body predicate operator '{op}' is not mapped — omitted"));
            return;
        }
    });
}

fn map_is(is: &JsonNode, ctx: &mut Ctx) -> Resp {
    let mut resp = Resp::status(is.path("statusCode").as_int_or(200) as i64);
    set(&mut resp.headers, super::header_object(&is.path("headers")));
    match is.path("body") {
        b if b.is_object() || b.is_array() => resp.body = Some(super::string_body_with_type(&b.to_java_string(), "application/json")),
        JsonNode::Missing | JsonNode::Null => {}
        b => {
            let text = b.as_text();
            if !text.is_empty() {
                resp.body = Some(Value::String(text));
            }
        }
    }
    if is.get("_mode").is_some_and(|m| m.as_text().eq_ignore_ascii_case("binary")) {
        ctx.warn("response.is._mode", "binary response mode is not mapped; the body is treated as text");
    }
    resp
}

fn map_proxy(e: &mut Map<String, Value>, proxy: &JsonNode, ctx: &mut Ctx) {
    let mut url = None;
    if let Some(to) = proxy.value_text("to") {
        url = url_parts(&to);
        if url.is_none() {
            ctx.warn("response.proxy.to", format!("could not parse proxy target '{to}' — forward may be incomplete"));
        }
    }
    if let Some(mode) = proxy.value_text("mode").filter(|m| !m.eq_ignore_ascii_case("proxyTransparent")) {
        ctx.warn("response.proxy.mode", format!("proxy mode '{mode}' (record/replay) is not reproduced; MockServer forwards every matching request"));
    }
    if proxy.get("predicateGenerators").is_some() {
        ctx.warn("response.proxy.predicateGenerators", "proxy predicateGenerators (record-and-replay stub generation) are not mapped");
    }
    super::forward(e, url.as_ref());
}

fn apply_wait(resp: &mut Resp, response: &JsonNode, ctx: &mut Ctx) {
    match response.path("_behaviors").path("wait") {
        wait @ (JsonNode::Int(_) | JsonNode::Long(_)) => resp.delay_millis = Some(wait.long_value()),
        JsonNode::Text(_) => ctx.warn("response._behaviors.wait", "a function-valued 'wait' (JavaScript) is not mapped; no delay applied"),
        _ => {}
    }
}

fn warn_unmapped_behaviors(response: &JsonNode, ctx: &mut Ctx) {
    let behaviors = response.path("_behaviors");
    let Some(behaviors) = behaviors.as_object() else { return };
    for key in ["decorate", "copy", "lookup", "shellTransform"] {
        if behaviors.contains_key(key) {
            ctx.warn(format!("response._behaviors.{key}"), format!("'{key}' post-processing behaviour is not mapped — omitted"));
        }
    }
}

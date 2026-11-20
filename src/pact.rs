//! Pact contracts (`org.mockserver.mock.pact.PactExporter`): `PUT /mockserver/pact` writes the active expectations
//! as a Pact v3 contract, one interaction per expectation with a request matcher and a response, regex and schema
//! matchers carried over as matching rules. The expectations are read in the form they were given, which keeps the
//! order of their headers and parameters.

use serde_json::{Map, Value, json};

use crate::state::State;

/// A `NottableString` as the expectation JSON writes it: `!` for not, `?` for optional, `{"schema": …}` for a schema.
struct Nottable {
    value: String,
    not: bool,
    optional: bool,
    schema: bool,
    /// A date-time comparison (`NottableDateTimeString`), whose value is its description.
    date_time: bool,
}

fn nottable(v: &Value) -> Nottable {
    if let Value::Object(o) = v
        && let Some(Ok(date_time)) = crate::model::DateTimeValue::read(o)
    {
        let not = o.get("not").and_then(Value::as_bool).unwrap_or(false);
        return Nottable { value: date_time.describe(), not, optional: false, schema: false, date_time: true };
    }
    match v {
        Value::String(s) => {
            if let Some(rest) = s.strip_prefix('!') {
                Nottable { value: rest.to_string(), not: true, optional: false, schema: false, date_time: false }
            } else if let Some(rest) = s.strip_prefix('?') {
                Nottable { value: rest.to_string(), not: false, optional: true, schema: false, date_time: false }
            } else {
                Nottable { value: s.clone(), not: false, optional: false, schema: false, date_time: false }
            }
        }
        Value::Object(o) if o.contains_key("schema") => Nottable {
            value: crate::json::pretty(&o["schema"]),
            not: o.get("not").and_then(Value::as_bool).unwrap_or(false),
            optional: o.get("optional").and_then(Value::as_bool).unwrap_or(false),
            schema: true,
            date_time: false,
        },
        Value::Object(o) => Nottable {
            value: o.get("value").map(text).unwrap_or_default(),
            not: o.get("not").and_then(Value::as_bool).unwrap_or(false),
            optional: o.get("optional").and_then(Value::as_bool).unwrap_or(false),
            schema: false,
            date_time: false,
        },
        other => Nottable { value: text(other), not: false, optional: false, schema: false, date_time: false },
    }
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// `looksLikeRegex`.
fn looks_like_regex(s: &str) -> bool {
    s.chars().any(|c| matches!(c, '\\' | '.' | '[' | ']' | '{' | '}' | '(' | ')' | '*' | '+' | '?' | '^' | '$' | '|'))
}

fn regex_rule(regex: &str) -> Value {
    json!({"match": "regex", "regex": regex})
}

/// `typeRule`.
fn type_rule(schema_type: Option<&str>) -> Value {
    let matcher = match schema_type.map(str::to_lowercase).as_deref() {
        Some("integer") => "integer",
        Some("number") => "number",
        Some("boolean") => "boolean",
        _ => "type",
    };
    json!({"match": matcher})
}

/// `ruleForValue`.
fn rule_for(value: &Nottable) -> Option<Value> {
    if value.optional || value.value.trim().is_empty() {
        return None;
    }
    if value.schema {
        let parsed: Option<Value> = serde_json::from_str(&value.value).ok();
        return Some(type_rule(parsed.as_ref().and_then(|s| s.get("type")).and_then(Value::as_str)));
    }
    if value.date_time {
        // Pact has no date-time comparison, so the closest rule is "any value of this type"
        return Some(type_rule(None));
    }
    looks_like_regex(&value.value).then(|| regex_rule(&value.value))
}

#[derive(Default)]
struct Rules {
    path: Option<Vec<Value>>,
    query: Map<String, Value>,
    header: Map<String, Value>,
    body: Map<String, Value>,
}

impl Rules {
    fn is_empty(&self) -> bool {
        self.path.is_none() && self.query.is_empty() && self.header.is_empty() && self.body.is_empty()
    }

    fn json(self) -> Value {
        let mut o = Map::new();
        if let Some(path) = self.path {
            o.insert("path".into(), json!({"matchers": path}));
        }
        if !self.query.is_empty() {
            o.insert("query".into(), Value::Object(self.query));
        }
        if !self.header.is_empty() {
            o.insert("header".into(), Value::Object(self.header));
        }
        if !self.body.is_empty() {
            o.insert("body".into(), Value::Object(self.body));
        }
        Value::Object(o)
    }
}

/// Entries of a multimap as the expectation JSON writes it: `{name: [values]}` or `[{name, values}]`.
fn entries(v: Option<&Value>) -> Vec<(Value, Vec<Value>)> {
    match v {
        Some(Value::Object(o)) => o.iter().map(|(k, v)| (Value::String(k.clone()), values(v))).collect(),
        Some(Value::Array(items)) => items.iter().filter_map(|i| Some((i.get("name")?.clone(), values(i.get("values").unwrap_or(&Value::Null))))).collect(),
        _ => Vec::new(),
    }
}

fn values(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(items) => items.clone(),
        Value::Null => Vec::new(),
        other => vec![other.clone()],
    }
}

/// `headersToNode` / `queryToNode`.
fn multimap(v: Option<&Value>, rules: &mut Map<String, Value>, key: impl Fn(&str, usize) -> String) -> Option<Value> {
    let entries = entries(v);
    if entries.is_empty() {
        return None;
    }
    let mut node = Map::new();
    for (name, values) in entries {
        let name = nottable(&name);
        if name.not {
            continue;
        }
        let mut out = Vec::new();
        for value in values.iter().map(nottable).filter(|v| !v.not) {
            if let Some(rule) = rule_for(&value) {
                rules.insert(key(&name.value, out.len()), json!({"matchers": [rule]}));
            }
            out.push(Value::String(value.value));
        }
        node.insert(name.value, Value::Array(out));
    }
    Some(Value::Object(node))
}

/// `setBody`: a JSON-schema body gives type rules, an XPath body a regex rule; any other body its text, as JSON when
/// it parses.
fn body(node: &mut Map<String, Value>, body: Option<&Value>, rules: &mut Map<String, Value>) {
    let Some(body) = body.filter(|b| !b.is_null()) else { return };
    let kind = body.get("type").and_then(Value::as_str);
    let text = match (body, kind) {
        (Value::Object(o), Some("JSON_SCHEMA")) => {
            let schema = match o.get("jsonSchema") {
                Some(Value::String(s)) => serde_json::from_str(s).ok(),
                other => other.cloned(),
            };
            match schema.as_ref().and_then(|s| s.get("properties")).and_then(Value::as_object).filter(|p| !p.is_empty()) {
                Some(properties) => {
                    for (name, property) in properties {
                        rules.insert(format!("$.{name}"), json!({"matchers": [type_rule(property.get("type").and_then(Value::as_str))]}));
                    }
                }
                None => {
                    rules.insert("$".into(), json!({"matchers": [type_rule(schema.as_ref().and_then(|s| s.get("type")).and_then(Value::as_str))]}));
                }
            }
            return;
        }
        (Value::Object(o), Some("XPATH")) => {
            let xpath = o.get("xpath").map(self::text).unwrap_or_default();
            if !xpath.trim().is_empty() {
                rules.insert(xpath.clone(), json!({"matchers": [regex_rule(&xpath)]}));
            }
            return;
        }
        (Value::String(s), _) => s.clone(),
        (Value::Object(o), Some("JSON")) => match o.get("json") {
            Some(Value::String(s)) => s.clone(),
            Some(v) => v.to_string(),
            None => String::new(),
        },
        (Value::Object(o), Some(kind)) => {
            let field = match kind {
                "STRING" => "string",
                "REGEX" => "regex",
                "XML" => "xml",
                "JSON_PATH" => "jsonPath",
                "BINARY" => "base64Bytes",
                "XML_SCHEMA" => "xmlSchema",
                _ => "",
            };
            match o.get(field) {
                Some(v) => self::text(v),
                None => body.to_string(),
            }
        }
        (other, _) => other.to_string(),
    };
    if text.trim().is_empty() {
        return;
    }
    let parsed = crate::json::parse_lenient(text.as_bytes()).ok().filter(|v| !matches!(v, Value::String(_)) || text.trim_start().starts_with('"'));
    node.insert("body".into(), parsed.unwrap_or(Value::String(text)));
}

fn is_uuid(id: &str) -> bool {
    id.len() == 36 && id.char_indices().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { c == '-' } else { c.is_ascii_hexdigit() })
}

/// `PactExporter.export`.
pub fn export(state: &State, consumer: Option<&str>, provider: Option<&str>) -> String {
    let blank = |v: Option<&str>, fallback: &str| v.filter(|s| !s.trim().is_empty()).unwrap_or(fallback).to_string();
    let mut interactions = Vec::new();
    for expectation in state.store.active() {
        let input = &expectation.input;
        let Some(request) = input.get("httpRequest").and_then(Value::as_object) else { continue };
        if request.contains_key("specUrlOrPayload") {
            continue;
        }
        let method = request.get("method").map(nottable);
        let path = request.get("path").map(nottable);
        if method.as_ref().is_some_and(|m| m.not) || path.as_ref().is_some_and(|p| p.not) {
            continue;
        }
        let response = match (input.get("httpResponse"), input.get("httpResponses")) {
            (Some(r), _) if !r.is_null() => r,
            (_, Some(Value::Array(items))) if !items.is_empty() => &items[0],
            _ => continue,
        };
        let method_text = method.as_ref().map(|m| m.value.clone()).unwrap_or_default();
        let path_text = path.as_ref().map(|p| p.value.clone()).unwrap_or_else(|| "/".into());
        let mut interaction = Map::new();
        let description = if is_uuid(&expectation.id) { format!("{method_text} {path_text}") } else { expectation.id.clone() };
        interaction.insert("description".into(), description.into());
        if input.get("scenarioName").and_then(Value::as_str) == Some("pact-provider-state") && let Some(state) = input.get("scenarioState").filter(|s| !s.is_null()) {
            interaction.insert("providerStates".into(), json!([{"name": text(state)}]));
        }
        let mut request_rules = Rules::default();
        let mut request_node = Map::new();
        request_node.insert("method".into(), method_text.into());
        request_node.insert("path".into(), path_text.into());
        if let Some(rule) = path.as_ref().and_then(rule_for) {
            request_rules.path = Some(vec![rule]);
        }
        if let Some(query) = multimap(request.get("queryStringParameters"), &mut request_rules.query, |name, i| format!("$.{name}[{i}]")) {
            request_node.insert("query".into(), query);
        }
        if let Some(headers) = multimap(request.get("headers"), &mut request_rules.header, |name, i| format!("$['{name}'][{i}]")) {
            request_node.insert("headers".into(), headers);
        }
        body(&mut request_node, request.get("body"), &mut request_rules.body);
        let mut response_rules = Rules::default();
        let mut response_node = Map::new();
        response_node.insert("status".into(), response.get("statusCode").cloned().filter(|s| !s.is_null()).unwrap_or_else(|| 200.into()));
        if let Some(headers) = multimap(response.get("headers"), &mut response_rules.header, |name, i| format!("$['{name}'][{i}]")) {
            response_node.insert("headers".into(), headers);
        }
        body(&mut response_node, response.get("body"), &mut response_rules.body);
        interaction.insert("request".into(), Value::Object(request_node));
        interaction.insert("response".into(), Value::Object(response_node));
        if !request_rules.is_empty() || !response_rules.is_empty() {
            let mut matching = Map::new();
            if !request_rules.is_empty() {
                matching.insert("request".into(), request_rules.json());
            }
            if !response_rules.is_empty() {
                matching.insert("response".into(), response_rules.json());
            }
            interaction.insert("matchingRules".into(), Value::Object(matching));
        }
        interactions.push(Value::Object(interaction));
    }
    let root = json!({
        "consumer": {"name": blank(consumer, "consumer")},
        "provider": {"name": blank(provider, "provider")},
        "interactions": interactions,
        "metadata": {"pactSpecification": {"version": "3.0.0"}},
    });
    crate::json::pretty(&root)
}

// ---------------------------------------------------------------------------------------------------------------
// `PUT /mockserver/pact/verify` (`PactVerifier`)
// ---------------------------------------------------------------------------------------------------------------

/// `PactProviderStates.gatingStateOf`: the first provider state an interaction declares.
fn gating_state(interaction: &Value) -> Option<String> {
    let mut names: Vec<String> = Vec::new();
    if let Some(Value::Array(states)) = interaction.get("providerStates") {
        for state in states {
            let name = if state.is_object() { state.get("name").map(text) } else { Some(text(state)) };
            if let Some(name) = name.filter(|n| !n.trim().is_empty()) && !names.contains(&name) {
                names.push(name);
            }
        }
    }
    if let Some(Value::String(name)) = interaction.get("providerState") && !name.trim().is_empty() && !names.contains(name) {
        names.push(name.clone());
    }
    names.into_iter().next()
}

/// `JsonNode.asText`.
fn as_text(v: &Value) -> String {
    crate::jnode::from_value(v).as_text()
}

/// `buildHttpRequest`: the request an interaction describes.
fn pact_request(node: &Value) -> crate::request::HttpRequest {
    let mut request = crate::request::HttpRequest { method: node.get("method").map(as_text).unwrap_or_default(), path: node.get("path").map(as_text).unwrap_or_default(), ..Default::default() };
    let values = |v: &Value| match v {
        Value::Array(items) => items.iter().map(as_text).collect::<Vec<_>>(),
        other => vec![as_text(other)],
    };
    if let Some(Value::Object(query)) = node.get("query") {
        for (name, v) in query {
            for value in values(v) {
                crate::request::push(&mut request.query, name, value);
            }
        }
    }
    if let Some(Value::Object(headers)) = node.get("headers") {
        for (name, v) in headers {
            for value in values(v) {
                crate::request::push(&mut request.headers, name, value);
            }
        }
    }
    if let Some(body) = node.get("body") {
        request.body = match body {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        }
        .into_bytes()
        .into();
    }
    request.cookies = crate::request::parse_cookies(&request.headers);
    request
}

/// Header fields, each with its values.
type Headers = Vec<(String, Vec<String>)>;

/// The response a matched expectation serves, when it is a static one: status, headers, body text.
fn static_response(expectation: &crate::store::Expectation) -> Option<(i64, Headers, String)> {
    let response = match (expectation.input.get("httpResponse"), expectation.input.get("httpResponses")) {
        (Some(r), _) if !r.is_null() => r,
        (_, Some(Value::Array(items))) if !items.is_empty() => &items[0],
        _ => return None,
    };
    let status = response.get("statusCode").and_then(Value::as_i64).unwrap_or(200);
    let headers = entries(response.get("headers")).into_iter().map(|(n, vs)| (text(&n), vs.iter().map(text).collect())).collect();
    let mut discard = Map::new();
    let mut node = Map::new();
    body(&mut node, response.get("body"), &mut discard);
    let body_text = match node.get("body") {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => String::new(),
    };
    Some((status, headers, body_text))
}

/// `compareResponses`.
fn compare(pact: &Value, (status, headers, body_text): &(i64, Vec<(String, Vec<String>)>, String)) -> Option<String> {
    if let Some(expected) = pact.get("status") {
        let expected = expected.as_i64().unwrap_or(0);
        if expected != *status {
            return Some(format!("status code mismatch: expected {expected} but was {status}"));
        }
    }
    if let Some(Value::Object(expected_headers)) = pact.get("headers") {
        for (name, expected) in expected_headers {
            let actual: Vec<String> = headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).flat_map(|(_, vs)| vs.clone()).collect();
            if actual.is_empty() {
                return Some(format!("header mismatch: expected header '{name}' not found in response"));
            }
            let expected_values = match expected {
                Value::Array(items) => items.iter().map(as_text).collect::<Vec<_>>(),
                other => vec![as_text(other)],
            };
            for value in expected_values {
                if !actual.contains(&value) {
                    return Some(format!("header mismatch: header '{name}' expected value '{value}' not found (actual values: [{}])", actual.join(", ")));
                }
            }
        }
    }
    if let Some(expected) = pact.get("body").filter(|b| !b.is_null()) {
        if body_text.trim().is_empty() {
            return Some("body mismatch: expected body but response has no body".into());
        }
        match expected {
            Value::String(expected) => {
                if expected != body_text {
                    let truncate = |s: &str| if s.chars().count() > 100 { format!("{}...", s.chars().take(100).collect::<String>()) } else { s.to_string() };
                    return Some(format!("body mismatch: expected '{}' but was '{}'", truncate(expected), truncate(body_text)));
                }
            }
            other => match crate::json::parse_lenient(body_text.as_bytes()) {
                Ok(actual) if actual == *other => {}
                Ok(_) => return Some("body mismatch: JSON bodies are not equal".into()),
                Err(_) => return Some("body mismatch: expected JSON body but response body is not valid JSON".into()),
            },
        }
    }
    None
}

/// `PactVerifier.verify`: whether every interaction is served by a matching expectation, and why not.
pub fn verify(state: &State, body: &str) -> Result<(bool, Value), String> {
    if body.trim().is_empty() {
        return Err("Pact contract JSON must not be empty".into());
    }
    let root = crate::chaos::read_tree(body, true).map_err(|e| format!("Pact contract JSON is malformed: {e}"))?;
    let Some(interactions) = root.get("interactions").and_then(Value::as_array).filter(|i| !i.is_empty()) else {
        return Err("Pact contract must contain at least one interaction".into());
    };
    const SCENARIO: &str = "pact-provider-state";
    let prior = state.scenarios().get(SCENARIO);
    let mut results = Vec::new();
    let mut all = true;
    for interaction in interactions {
        let description = interaction.get("description").map(as_text).unwrap_or_else(|| "(unnamed interaction)".into());
        let mut result = |verified: bool, reason: Option<String>| {
            all &= verified;
            let mut o = Map::new();
            o.insert("description".into(), description.clone().into());
            o.insert("verified".into(), verified.into());
            if let Some(reason) = reason {
                o.insert("reason".into(), reason.into());
            }
            results.push(Value::Object(o));
        };
        let Some(request_node) = interaction.get("request").filter(|r| !r.is_null()) else {
            result(false, Some("interaction has no request definition".into()));
            continue;
        };
        let request = pact_request(request_node);
        let provider_state = gating_state(interaction);
        if let Some(s) = provider_state.as_deref().filter(|s| !s.trim().is_empty()) {
            state.scenarios().set(SCENARIO, s);
        }
        let matching: Vec<_> = state.store.evaluate_all(&request).into_iter().filter(|e| e.matched).map(|e| e.expectation).collect();
        let satisfied = |e: &crate::store::Expectation| {
            e.input.get("scenarioName").and_then(Value::as_str) != Some(SCENARIO)
                || e.input.get("scenarioState").and_then(Value::as_str).is_none_or(|required| Some(required) == provider_state.as_deref())
        };
        let Some(matched) = matching.iter().find(|e| satisfied(e)) else {
            let reason = if matching.is_empty() {
                "no matching expectation found".to_string()
            } else if let Some(s) = &provider_state {
                format!("no matching expectation found for provider state '{s}'")
            } else {
                "matching expectation found but it requires a provider state not declared by this interaction".to_string()
            };
            result(false, Some(reason));
            continue;
        };
        let Some(served) = static_response(matched) else {
            result(false, Some("unverifiable (non-static action) — only response expectations can be verified against a Pact contract".into()));
            continue;
        };
        let Some(response_node) = interaction.get("response").filter(|r| !r.is_null()) else {
            result(false, Some("interaction has no response definition".into()));
            continue;
        };
        match compare(response_node, &served) {
            Some(reason) => result(false, Some(reason)),
            None => result(true, None),
        }
    }
    if prior == crate::scenario::STARTED {
        state.scenarios().clear(SCENARIO);
    } else {
        state.scenarios().set(SCENARIO, &prior);
    }
    Ok((all, json!({"verified": all, "interactions": results})))
}

// ---------------------------------------------------------------------------------------------------------------
// `PUT /mockserver/import?format=pact` and `PUT /mockserver/pact/import` (`PactImporter`)
// ---------------------------------------------------------------------------------------------------------------

/// A request multimap an interaction fills, with its matching-rule category.
#[derive(Clone, Copy)]
enum Multimap {
    Query,
    Headers,
}

/// One expectation per interaction (input form, redacted), gated on its first provider state.
pub fn import(pact: &str, options: &crate::import::Options) -> Result<Vec<Value>, String> {
    use crate::import::{Req, Resp, TextOrNull};
    use jackson::JsonNode;
    if pact.trim().is_empty() {
        return Err("Pact contract JSON body is required".into());
    }
    let root = crate::import::parse(pact).map_err(|e| format!("failed to parse Pact JSON: {e}"))?;
    let Some(interactions) = root.path("interactions").as_array().filter(|a| !a.is_empty()).cloned() else {
        return Err("not a valid Pact contract — missing or empty 'interactions' array".into());
    };
    let mut expectations = Vec::new();
    for (index, interaction) in interactions.iter().enumerate() {
        let Some(request) = interaction.get("request") else { continue };
        let rules = interaction.path("matchingRules").path("request");
        let mut req = Req::default();
        if let Some(method) = request.text_or_null("method") {
            req.method = Some(method.to_uppercase());
        }
        if let Some(path) = request.text_or_null("path") {
            req.path = Some(match_value(&path, import_rule(&rules.path("path"), None)));
        }
        for target in [Multimap::Query, Multimap::Headers] {
            let (key, category) = match target {
                Multimap::Query => ("query", "query"),
                Multimap::Headers => ("headers", "header"),
            };
            for (name, v) in request.path(key).as_object().into_iter().flatten() {
                for value in values_of(v) {
                    let matched = match_value(&value, import_rule(&rules.path(category), Some(name)));
                    let entries = match target {
                        Multimap::Query => &mut req.query,
                        Multimap::Headers => &mut req.headers,
                    };
                    crate::import::add(entries, name, vec![matched]);
                }
            }
        }
        match request.path("body") {
            JsonNode::Missing | JsonNode::Null => {}
            b if b.is_object() || b.is_array() => req.body = Some(json!({"type": "JSON", "json": b.to_java_string()})),
            b => req.body = Some(Value::String(body_text(&b))),
        }
        let mut resp = Resp::status(200);
        if let Some(response) = interaction.get("response") {
            resp.status = response.path("status").as_int_or(200) as i64;
            crate::import::set(&mut resp.headers, response.path("headers").as_object().map(|o| o.iter().map(|(n, v)| (n.clone(), values_of(v))).collect()).unwrap_or_default());
            match response.path("body") {
                JsonNode::Missing | JsonNode::Null => {}
                b => resp.body = Some(Value::String(body_text(&b))),
            }
        }
        let description = interaction.path("description").as_text_or("");
        let id = if description.trim().is_empty() { format!("pact-{index}") } else { description };
        let mut e = crate::import::expectation(Some(&id), &req);
        crate::import::respond(&mut e, &resp);
        let as_value: Value = serde_json::from_str(&interaction.to_java_string()).unwrap_or(Value::Null);
        if let Some(state) = gating_state(&as_value) {
            e.insert("scenarioName".into(), "pact-provider-state".into());
            e.insert("scenarioState".into(), state.into());
        }
        expectations.push(Value::Object(e));
    }
    Ok(crate::import::redact::redact(expectations, options))
}

/// `ruleFor`: the first matcher of a category (the lone rule of `path`, else the first key naming the field).
fn import_rule(category: &jackson::JsonNode, field: Option<&str>) -> Option<jackson::JsonNode> {
    let rules = category.as_object()?;
    match field {
        None => first_matcher(category),
        Some(field) => rules.iter().find(|(key, _)| key_matches_field(key, field)).and_then(|(_, rule)| first_matcher(rule)),
    }
}

fn key_matches_field(key: &str, field: &str) -> bool {
    if key == field || key.contains(&format!("'{field}'")) {
        return true;
    }
    let Some(dot) = key.find(&format!(".{field}")) else { return false };
    match key[dot + 1 + field.len()..].chars().next() {
        None => true,
        Some(next) => next == '[' || next == ']',
    }
}

fn first_matcher(rule: &jackson::JsonNode) -> Option<jackson::JsonNode> {
    match rule.path("matchers").as_array() {
        Some(matchers) if !matchers.is_empty() => matchers.first().cloned(),
        _ => rule.get("match").is_some().then(|| rule.clone()),
    }
}

/// A Pact example value and its rule as a MockServer matcher value (a regex with exact fallback).
fn match_value(example: &str, rule: Option<jackson::JsonNode>) -> String {
    let Some(rule) = rule else { return example.to_string() };
    let kind = rule.path("match").as_text_or(&rule.path("type").as_text_or(""));
    match kind.as_str() {
        "regex" => rule.path("regex").as_text_or(example),
        "include" => format!(".*{}.*", crate::java_text::quote(&rule.path("value").as_text_or(example))),
        "type" | "number" | "integer" | "decimal" | "boolean" => ".+".to_string(),
        _ => example.to_string(),
    }
}

fn values_of(v: &jackson::JsonNode) -> Vec<String> {
    match v {
        jackson::JsonNode::Null => Vec::new(),
        jackson::JsonNode::Array(items) => items.iter().map(jackson::JsonNode::as_text).collect(),
        other => vec![other.as_text()],
    }
}

/// `bodyToString`: text as is, anything else as compact JSON.
fn body_text(b: &jackson::JsonNode) -> String {
    b.text_value().map_or_else(|| b.to_java_string(), str::to_string)
}

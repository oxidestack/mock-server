//! `RecordedExpectationPostProcessor.consolidate`: expectations sharing a request shape (method, path with id-like
//! segments as wildcards, body) collapse into one unlimited mock; id segments become `{id}` path parameters when
//! the group spans several paths, volatile request headers are stripped, differing responses are sequenced, and
//! `parameterize` also generalises volatile-looking query, header and JSON body values.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::LazyLock;

use base64::Engine;
use jackson::JsonNode;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::redact::{entry_list, text};
use super::{add, entries_json};
use crate::request::MultiMap;

static NUMERIC_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]+$").unwrap());
static UUID_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$").unwrap());
static LONG_NUMERIC_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]{6,}$").unwrap());
static ISO_8601: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}([Tt ][0-9]{2}:[0-9]{2}(:[0-9]{2})?(\.[0-9]{1,9})?([Zz]|[+-][0-9]{2}:?[0-9]{2})?)?$").unwrap());
static EPOCH_MILLIS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^1[0-9]{12}$").unwrap());
static JWT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$").unwrap());
static OPAQUE_TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_=+/-]{24,}$").unwrap());

const VOLATILE_HEADER_NAMES: &[&str] = &[
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-request-id", "x-correlation-id", "x-amz-date",
    "x-amz-security-token", "x-csrf-token", "x-xsrf-token",
];

const ANY_VALUE: &str = ".+";

/// One expectation of a post-processed list: an input expectation kept as it was (by index), or a new one.
pub enum Processed {
    Kept(usize),
    Built(Value),
}

/// [`consolidate_indexed`], each output as its expectation.
pub fn consolidate(expectations: &[Value], parameterize: bool) -> Vec<Value> {
    consolidate_indexed(expectations, parameterize)
        .into_iter()
        .map(|p| match p {
            Processed::Kept(i) => expectations[i].clone(),
            Processed::Built(v) => v,
        })
        .collect()
}

/// `consolidate`: groups emitted where they first appear, ineligible expectations kept in place.
pub fn consolidate_indexed(expectations: &[Value], parameterize: bool) -> Vec<Processed> {
    let (signatures, groups) = group(expectations);
    let mut emitted: HashSet<&str> = HashSet::new();
    let mut out = Vec::new();
    for (i, signature) in signatures.iter().enumerate() {
        match signature {
            None => out.push(Processed::Kept(i)),
            Some(signature) if emitted.insert(signature) => {
                let members: Vec<&Value> = groups[signature.as_str()].iter().map(|&m| &expectations[m]).collect();
                out.push(Processed::Built(consolidate_group(&members, parameterize)));
            }
            Some(_) => {}
        }
    }
    out
}

/// `deduplicateAndTemplatize`: each signature group is partitioned by response (equal responses only ever
/// merge); a partition spanning several concrete paths with an id segment becomes one `{id}` expectation, any
/// other partition keeps its first member. Recorded `times`, `timeToLive` and priority are kept. With
/// `templatize_values`, volatile query, header and JSON body values of every emitted expectation become
/// regex matchers.
pub fn deduplicate_and_templatize(expectations: &[Value], templatize_values: bool) -> Vec<Processed> {
    let (signatures, groups) = group(expectations);
    let mut emitted: HashSet<&str> = HashSet::new();
    let mut out = Vec::new();
    for (i, signature) in signatures.iter().enumerate() {
        match signature {
            None => out.push(Processed::Kept(i)),
            Some(signature) if emitted.insert(signature) => {
                for collapsed in collapse_group(expectations, &groups[signature.as_str()]) {
                    out.push(if templatize_values { templatize_values_of(expectations, collapsed) } else { collapsed });
                }
            }
            Some(_) => {}
        }
    }
    out
}

/// Each expectation's structural signature (`None` when ineligible) and the eligible ones' indices by
/// signature, in input order.
fn group(expectations: &[Value]) -> (Vec<Option<String>>, HashMap<String, Vec<usize>>) {
    let signatures: Vec<Option<String>> = expectations.iter().map(|e| eligible(e).then(|| signature(&e["httpRequest"]))).collect();
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, signature) in signatures.iter().enumerate() {
        if let Some(signature) = signature {
            groups.entry(signature.clone()).or_default().push(i);
        }
    }
    (signatures, groups)
}

/// `collapseGroup`: a lone member as it is; otherwise one expectation per distinct response, first seen first.
fn collapse_group(expectations: &[Value], members: &[usize]) -> Vec<Processed> {
    if members.len() == 1 {
        return vec![Processed::Kept(members[0])];
    }
    let mut partitions: Vec<(String, Vec<usize>)> = Vec::new();
    for &m in members {
        let key = response_key(&expectations[m]["httpResponse"]);
        match partitions.iter_mut().find(|(k, _)| *k == key) {
            Some((_, partition)) => partition.push(m),
            None => partitions.push((key, vec![m])),
        }
    }
    partitions
        .into_iter()
        .map(|(_, partition)| {
            let representative = &expectations[partition[0]];
            let members: Vec<&Value> = partition.iter().map(|&m| &expectations[m]).collect();
            if has_variable_segment(&representative["httpRequest"]) && spans_multiple_paths(&members) {
                Processed::Built(rebuild(representative, Value::Object(templatized(&representative["httpRequest"]))))
            } else {
                // No templatization: exact-duplicate dedup keeps the first.
                Processed::Kept(partition[0])
            }
        })
        .collect()
}

/// `rebuild`: a new expectation (new id) with `request`, the source's response, times, time to live and priority.
fn rebuild(source: &Value, request: Value) -> Value {
    let mut o = Map::new();
    o.insert("httpRequest".into(), request);
    o.insert("httpResponse".into(), source["httpResponse"].clone());
    for key in ["times", "timeToLive", "priority"] {
        if let Some(v) = source.get(key).filter(|v| !v.is_null()) {
            o.insert(key.into(), v.clone());
        }
    }
    Value::Object(o)
}

/// `templatizeValues`: the expectation rebuilt with volatile values generalised, or as it was when none are.
fn templatize_values_of(expectations: &[Value], collapsed: Processed) -> Processed {
    let source = match &collapsed {
        Processed::Kept(i) => &expectations[*i],
        Processed::Built(v) => v,
    };
    let mut request = source["httpRequest"].as_object().cloned().unwrap_or_default();
    let mut changed = generalize_entries(&mut request, "queryStringParameters", |_| false);
    changed |= generalize_entries(&mut request, "headers", |name| VOLATILE_HEADER_NAMES.contains(&name.to_lowercase().as_str()));
    changed |= generalize_json_body(&mut request);
    if changed { Processed::Built(rebuild(source, Value::Object(request))) } else { collapsed }
}

/// An HTTP request matcher with one concrete response.
fn eligible(e: &Value) -> bool {
    e.get("httpRequest").and_then(Value::as_object).is_some_and(|r| !r.contains_key("specUrlOrPayload")) && e.get("httpResponse").is_some_and(|r| !r.is_null())
}

fn consolidate_group(group: &[&Value], parameterize: bool) -> Value {
    let representative = &group[0]["httpRequest"];
    let mut request = if has_variable_segment(representative) && spans_multiple_paths(group) {
        templatized(representative)
    } else {
        representative.as_object().cloned().unwrap_or_default()
    };
    strip_volatile_headers(&mut request);
    if parameterize {
        generalize_entries(&mut request, "queryStringParameters", |_| false);
        generalize_entries(&mut request, "headers", |name| VOLATILE_HEADER_NAMES.contains(&name.to_lowercase().as_str()));
        generalize_json_body(&mut request);
    }
    // `LinkedHashSet<HttpResponse>`: distinct by the model's `equals`, first seen first.
    let mut seen = HashSet::new();
    let responses: Vec<Value> = group.iter().map(|e| &e["httpResponse"]).filter(|r| seen.insert(response_key(r))).cloned().collect();
    let mut o = Map::new();
    o.insert("httpRequest".into(), Value::Object(request));
    if responses.len() == 1 {
        o.insert("httpResponse".into(), responses[0].clone());
    } else {
        o.insert("responseMode".into(), "SEQUENTIAL".into());
        o.insert("httpResponses".into(), Value::Array(responses));
    }
    o.insert("times".into(), json!({"unlimited": true}));
    o.insert("timeToLive".into(), json!({"unlimited": true}));
    o.insert("priority".into(), 0.into());
    Value::Object(o)
}

// ----- capture headers, repeats as scenarios ------------------------------------------------------------------

/// `captureHeaders`: each HTTP request matcher keeps only the named headers (names compared ignoring case; none
/// named removes every header). An expectation with nothing removed is kept as it was; a changed one keeps its id,
/// times, time to live and everything else (`cloneWith`).
pub fn capture_headers(expectations: &[Value], names: &[String]) -> Vec<Processed> {
    let keep: HashSet<String> = names.iter().map(|n| n.to_lowercase()).collect();
    expectations
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let Some(request) = e.get("httpRequest").and_then(Value::as_object).filter(|r| http_request(r)) else { return Processed::Kept(i) };
            let Some(list) = request.get("headers").map(entry_list) else { return Processed::Kept(i) };
            let kept: MultiMap = list.iter().filter(|(n, _)| keep.contains(&n.trim_start_matches('!').to_lowercase())).cloned().collect();
            if kept.len() == list.len() {
                return Processed::Kept(i);
            }
            let mut request = request.clone();
            if kept.is_empty() {
                request.remove("headers");
            } else {
                request.insert("headers".into(), entries_json(&kept));
            }
            let mut copy = e.clone();
            copy["httpRequest"] = Value::Object(request);
            Processed::Built(copy)
        })
        .collect()
}

/// `sequenceRepeats` (WireMock's `repeatsAsScenarios`): requests recorded several times with different responses
/// (compared without the volatile response headers and the parsed cookies) become one unlimited `SWITCH` response
/// sequence at the first one's position, with its request and priority. Requests are the same only when every
/// matched property is equal (stream id and socket addresses aside); everything else is kept as it was.
pub fn sequence_repeats(expectations: &[Value]) -> Vec<Processed> {
    let keys: Vec<Option<String>> = expectations
        .iter()
        .map(|e| {
            let request = e.get("httpRequest").and_then(Value::as_object).filter(|r| http_request(r))?;
            e.get("httpResponse").filter(|r| !r.is_null())?;
            Some(request_key(request))
        })
        .collect();
    let mut groups: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, key) in keys.iter().enumerate() {
        if let Some(key) = key {
            groups.entry(key.as_str()).or_default().push(i);
        }
    }
    let mut emitted: HashSet<&str> = HashSet::new();
    let mut out = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let Some(key) = key.as_deref() else {
            out.push(Processed::Kept(i));
            continue;
        };
        let members = &groups[key];
        if !has_different_responses(expectations, members) {
            out.push(Processed::Kept(i));
        } else if emitted.insert(key) {
            let first = &expectations[members[0]];
            let mut o = Map::new();
            o.insert("httpRequest".into(), first["httpRequest"].clone());
            o.insert("httpResponses".into(), Value::Array(members.iter().map(|&m| expectations[m]["httpResponse"].clone()).collect()));
            o.insert("responseMode".into(), "SWITCH".into());
            o.insert("times".into(), json!({"unlimited": true}));
            o.insert("timeToLive".into(), json!({"unlimited": true}));
            o.insert("priority".into(), first.get("priority").filter(|p| !p.is_null()).cloned().unwrap_or_else(|| 0.into()));
            out.push(Processed::Built(Value::Object(o)));
        }
    }
    out
}

/// The recorded request is an `HttpRequest` (not an OpenAPI, DNS, binary or conditional definition).
fn http_request(request: &Map<String, Value>) -> bool {
    let definition = Value::Object(request.clone());
    !request.contains_key("specUrlOrPayload") && !crate::canonical::is_dns_request(&definition) && !crate::canonical::is_binary_request(&definition)
        && !crate::canonical::is_conditional_request(&definition)
}

fn has_different_responses(expectations: &[Value], members: &[usize]) -> bool {
    if members.len() < 2 {
        return false;
    }
    let stable = |m: usize| {
        let mut response = expectations[m]["httpResponse"].clone();
        if let Some(o) = response.as_object_mut() {
            if let Some(list) = o.get("headers").map(entry_list) {
                let kept: MultiMap = list.into_iter().filter(|(n, _)| !super::har::VOLATILE_RESPONSE_HEADERS.contains(&n.to_lowercase().as_str())).collect();
                if kept.is_empty() {
                    o.remove("headers");
                } else {
                    o.insert("headers".into(), entries_json(&kept));
                }
            }
            o.remove("cookies");
        }
        response_key(&response)
    };
    let first = stable(members[0]);
    members[1..].iter().any(|&m| stable(m) != first)
}

/// `HttpRequest.equals` as a key, without the stream id and socket addresses: multimaps as maps of value lists,
/// cookies as maps, the body by its `equals` fields, every other property as it is.
fn request_key(request: &Map<String, Value>) -> String {
    let mut key = Map::new();
    for (name, value) in request {
        let value = match name.as_str() {
            "streamId" | "localAddress" | "remoteAddress" => continue,
            "headers" | "queryStringParameters" | "pathParameters" => multimap_key(Some(value)),
            "cookies" => json!(entry_list(value).into_iter().collect::<BTreeMap<_, _>>()),
            "body" => body_key(value),
            _ => value.clone(),
        };
        key.insert(name.clone(), value);
    }
    let sorted: BTreeMap<_, _> = key.into_iter().collect();
    json!(sorted).to_string()
}

// ----- model equality -----------------------------------------------------------------------------------------

/// `HttpResponse.equals` as a key: multimaps compared as maps of value lists (the order of names is irrelevant,
/// the order of a name's values is not), cookies as maps, bodies by type, value, bytes, content type and flags
/// (so `"x"` equals `{"type": "STRING", "string": "x"}`), plus delay and `primary`.
fn response_key(response: &Value) -> String {
    let field = |k: &str| response.get(k).cloned().unwrap_or(Value::Null);
    let key = json!({
        "statusCode": field("statusCode"),
        "statusCodeRange": field("statusCodeRange"),
        "reasonPhrase": field("reasonPhrase"),
        "body": response.get("body").map_or(Value::Null, body_key),
        "generateFromSchema": field("generateFromSchema"),
        "headers": multimap_key(response.get("headers")),
        "trailers": multimap_key(response.get("trailers")),
        "cookies": response.get("cookies").map_or(Value::Null, |c| json!(entry_list(c).into_iter().collect::<BTreeMap<_, _>>())),
        "connectionOptions": field("connectionOptions"),
        "recoverAfter": field("recoverAfter"),
        "streamId": field("streamId"),
        "delay": field("delay"),
        "primary": response.get("primary").and_then(Value::as_bool).unwrap_or(false),
    });
    key.to_string()
}

/// `LinkedListMultimap.equals`: names to their value lists.
fn multimap_key(v: Option<&Value>) -> Value {
    let Some(v) = v else { return Value::Null };
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, values) in entry_list(v) {
        map.entry(name).or_default().extend(values);
    }
    if map.is_empty() { Value::Null } else { json!(map) }
}

/// A body's `equals` fields: type, value, bytes, content type, `optional`, `not` and the type's own flags.
fn body_key(body: &Value) -> Value {
    let o = match body {
        Value::String(s) => return json!(["STRING", s, base64(s.as_bytes()), null, null, null, false]),
        Value::Object(o) if o.contains_key("type") => o,
        // A JSON body in shorthand.
        other => {
            let value = other.to_string();
            return json!(["JSON", value, base64(value.as_bytes()), null, null, null, "ONLY_MATCHING_FIELDS", null]);
        }
    };
    let kind = o.get("type").and_then(Value::as_str).unwrap_or("STRING");
    let content_type = o.get("contentType").map(text);
    let bytes = |value: &str| o.get("rawBytes").map(text).unwrap_or_else(|| base64(&crate::canonical::encode(value, content_type.as_deref())));
    let flags = |k: &str| o.get(k).cloned().unwrap_or(Value::Null);
    match kind {
        "STRING" => {
            let value = o.get("string").map(text).unwrap_or_default();
            json!(["STRING", value, bytes(&value), content_type, flags("optional"), flags("not"), o.get("subString").and_then(Value::as_bool).unwrap_or(false)])
        }
        "JSON" => {
            let value = o.get("json").map(text).unwrap_or_default();
            let match_type = o.get("matchType").map_or_else(|| "ONLY_MATCHING_FIELDS".to_string(), text);
            json!(["JSON", value, bytes(&value), content_type, flags("optional"), flags("not"), match_type, flags("matchNumbersAsStrings")])
        }
        "BINARY" => json!(["BINARY", o.get("base64Bytes").map(text), content_type, flags("optional"), flags("not")]),
        _ => Value::Object(o.clone()),
    }
}

fn base64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ----- request shape ------------------------------------------------------------------------------------------

fn path_of(request: &Value) -> String {
    match request.get("path") {
        Some(Value::String(s)) => s.trim_start_matches('!').to_string(),
        Some(Value::Object(o)) => o.get("value").map(text).unwrap_or_default(),
        _ => String::new(),
    }
}

fn segments(request: &Value) -> Vec<String> {
    path_of(request).split('/').map(str::to_string).collect()
}

fn variable(segment: &str) -> bool {
    !segment.is_empty() && (NUMERIC_ID.is_match(segment) || UUID_ID.is_match(segment))
}

fn has_variable_segment(request: &Value) -> bool {
    segments(request).iter().any(|s| variable(s))
}

fn ends_with_slash(request: &Value) -> bool {
    let p = path_of(request);
    p.len() > 1 && p.ends_with('/')
}

fn spans_multiple_paths(group: &[&Value]) -> bool {
    let first = path_of(&group[0]["httpRequest"]);
    group.iter().any(|e| path_of(&e["httpRequest"]) != first)
}

/// `structuralSignature`: method, path with variable segments as a placeholder, body shape.
fn signature(request: &Value) -> String {
    let method = match request.get("method") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(o)) => {
            let value = o.get("value").map(text).unwrap_or_default();
            if o.get("not").and_then(Value::as_bool).unwrap_or(false) { format!("!{value}") } else { value }
        }
        _ => String::new(),
    };
    let path: Vec<String> = segments(request).into_iter().map(|s| if variable(&s) { "\u{0}".to_string() } else { s }).collect();
    let mut out = format!("M:{method}\nP:{}", path.join("/"));
    if ends_with_slash(request) {
        out.push('/');
    }
    out.push_str("\nB:");
    out.push_str(&body_shape(request.get("body")));
    out
}

/// `body.getType() + ":" + body.getValue()`. A binary body's value is a `byte[]`, whose `toString` is its
/// identity, so no two binary bodies share a shape.
fn body_shape(body: Option<&Value>) -> String {
    static BINARY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    match body {
        None | Some(Value::Null) => "<none>".into(),
        Some(Value::String(s)) => format!("STRING:{s}"),
        Some(Value::Object(o)) => {
            let kind = o.get("type").and_then(Value::as_str).unwrap_or("STRING").to_string();
            let field = |k: &str| o.get(k).map(text).unwrap_or_default();
            let value = match kind.as_str() {
                "STRING" => field("string"),
                "JSON" => field("json"),
                "REGEX" => field("regex"),
                "JSON_PATH" => field("jsonPath"),
                "XML" => field("xml"),
                "BINARY" => format!("[B@{}", BINARY.fetch_add(1, std::sync::atomic::Ordering::Relaxed)),
                _ => Value::Object(o.clone()).to_string(),
            };
            format!("{kind}:{value}")
        }
        Some(other) => format!("JSON:{other}"),
    }
}

/// Variable segments as `{id}`, `{id1}`, … declared as `.*` path parameters.
fn templatized(original: &Value) -> Map<String, Value> {
    let mut templated = original.as_object().cloned().unwrap_or_default();
    let mut names: Vec<String> = Vec::new();
    let mut rendered: Vec<String> = Vec::new();
    for segment in segments(original) {
        if variable(&segment) {
            let name = if names.is_empty() { "id".to_string() } else { format!("id{}", names.len()) };
            rendered.push(format!("{{{name}}}"));
            names.push(name);
        } else {
            rendered.push(segment);
        }
    }
    if rendered.first().is_some_and(String::is_empty) {
        rendered.remove(0);
    }
    if rendered.last().is_some_and(String::is_empty) {
        rendered.pop();
    }
    let leading = if path_of(original).starts_with('/') { "/" } else { "" };
    let mut joined = format!("{leading}{}", rendered.join("/"));
    if ends_with_slash(original) && !joined.ends_with('/') {
        joined.push('/');
    }
    templated.insert("path".into(), joined.into());
    let mut parameters = templated.get("pathParameters").map(entry_list).unwrap_or_default();
    for name in names {
        add(&mut parameters, &name, vec![".*".into()]);
    }
    templated.insert("pathParameters".into(), entries_json(&parameters));
    templated
}

fn strip_volatile_headers(request: &mut Map<String, Value>) {
    let Some(list) = request.get("headers").map(entry_list) else { return };
    let volatile = |name: &str| {
        super::har::VOLATILE_REQUEST_HEADERS.contains(&name.trim_start_matches('!').to_lowercase().as_str()) || crate::transport_headers::is_transport_header(name)
    };
    let kept: MultiMap = list.into_iter().filter(|(n, _)| !volatile(n)).collect();
    if kept.is_empty() {
        request.remove("headers");
    } else {
        request.insert("headers".into(), entries_json(&kept));
    }
}

fn generalize_entries(request: &mut Map<String, Value>, key: &str, volatile_name: impl Fn(&str) -> bool) -> bool {
    let Some(list) = request.get(key).map(entry_list) else { return false };
    let mut changed = false;
    let mut rebuilt = MultiMap::new();
    for (name, values) in list {
        let name_volatile = volatile_name(name.trim_start_matches('!'));
        let values = values
            .into_iter()
            .map(|v| {
                if !v.starts_with('!') && (name_volatile || volatile_value(&v)) {
                    changed = true;
                    ANY_VALUE.to_string()
                } else {
                    v
                }
            })
            .collect();
        add(&mut rebuilt, &name, values);
    }
    if changed {
        request.insert(key.into(), entries_json(&rebuilt));
    }
    changed
}

fn generalize_json_body(request: &mut Map<String, Value>) -> bool {
    let text = match request.get("body") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(o)) => match o.get("type").and_then(Value::as_str) {
            Some("STRING") => o.get("string").map(text).unwrap_or_default(),
            Some("JSON") => o.get("json").map(text).unwrap_or_default(),
            _ => return false,
        },
        _ => return false,
    };
    let text = text.trim();
    if !(text.starts_with('{') || text.starts_with('[')) {
        return false;
    }
    let Ok(mut root) = crate::jnode::read_tree(text) else { return false };
    let changed = generalize_node(&mut root);
    if changed {
        request.insert("body".into(), json!({"type": "JSON", "json": root.to_java_string(), "contentType": "application/json"}));
    }
    changed
}

fn generalize_node(node: &mut JsonNode) -> bool {
    let children: Vec<&mut JsonNode> = match node {
        JsonNode::Object(o) => std::sync::Arc::make_mut(o).values_mut().collect(),
        JsonNode::Array(items) => std::sync::Arc::make_mut(items).iter_mut().collect(),
        _ => return false,
    };
    let mut changed = false;
    for child in children {
        match child.text_value().map(volatile_value) {
            Some(true) => {
                *child = JsonNode::text(format!("${{json-unit.regex}}{ANY_VALUE}"));
                changed = true;
            }
            Some(false) => {}
            None => changed |= generalize_node(child),
        }
    }
    changed
}

/// `isVolatileValue`: a UUID, JWT, epoch-millis, long numeric id, ISO-8601 timestamp or opaque token (after a
/// `Bearer`/`Basic`/`Digest` scheme).
pub fn volatile_value(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let mut token = trimmed;
    if let Some(space) = trimmed.find(' ') && space > 0 && space < trimmed.len() - 1 && ["bearer", "basic", "digest"].contains(&trimmed[..space].to_lowercase().as_str()) {
        token = trimmed[space + 1..].trim();
    }
    UUID_ID.is_match(token) || JWT.is_match(token) || EPOCH_MILLIS.is_match(token) || LONG_NUMERIC_ID.is_match(token) || ISO_8601.is_match(token) || opaque_token(token)
}

fn opaque_token(token: &str) -> bool {
    if !OPAQUE_TOKEN.is_match(token) {
        return false;
    }
    let lower = token.chars().any(|c| c.is_ascii_lowercase());
    let upper = token.chars().any(|c| c.is_ascii_uppercase());
    let digit = token.chars().any(|c| c.is_ascii_digit());
    lower || ((upper || lower) && digit)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::Processed;

    fn recorded(method: &str, path: &str, response: Value) -> Value {
        json!({"httpRequest": {"method": method, "path": path}, "httpResponse": response, "times": {"remainingTimes": 1}, "timeToLive": {"unlimited": true}})
    }

    fn recorded_request(request: Value, response: Value) -> Value {
        json!({"httpRequest": request, "httpResponse": response})
    }

    fn dedup(expectations: &[Value], templatize_values: bool) -> Vec<Value> {
        super::deduplicate_and_templatize(expectations, templatize_values)
            .into_iter()
            .map(|p| match p {
                Processed::Kept(i) => expectations[i].clone(),
                Processed::Built(v) => v,
            })
            .collect()
    }

    fn path(e: &Value) -> &str {
        e["httpRequest"]["path"].as_str().unwrap_or_default()
    }

    /// The first value of `name` in a request's `key` multimap, in map or list form.
    fn first(e: &Value, key: &str, name: &str) -> String {
        super::entry_list(&e["httpRequest"][key]).into_iter().find(|(n, _)| n == name).and_then(|(_, v)| v.into_iter().next()).unwrap_or_default()
    }

    /// `RecordedExpectationPostProcessorTest.shouldTemplatizeNumericIdSegmentsToSingleExpectation`.
    #[test]
    fn should_templatize_numeric_id_segments_to_single_expectation() {
        let shared = json!({"statusCode": 200, "body": "{\"name\":\"x\"}"});
        let result = dedup(&[recorded("GET", "/users/1", shared.clone()), recorded("GET", "/users/2", shared.clone()), recorded("GET", "/users/3", shared)], false);
        assert_eq!(result.len(), 1);
        assert_eq!(path(&result[0]), "/users/{id}");
        assert_eq!(first(&result[0], "pathParameters", "id"), ".*");
        assert!(result[0]["httpResponse"]["body"].as_str().unwrap().contains("\"name\":\"x\""));
        // `rebuild` keeps the recorded times and time to live.
        assert_eq!(result[0]["times"], json!({"remainingTimes": 1}));
        assert_eq!(result[0]["timeToLive"], json!({"unlimited": true}));
    }

    /// `RecordedExpectationPostProcessorTest.shouldTemplatizeUuidSegments`.
    #[test]
    fn should_templatize_uuid_segments() {
        let shared = json!({"statusCode": 200});
        let result = dedup(
            &[
                recorded("GET", "/orders/123e4567-e89b-12d3-a456-426614174000", shared.clone()),
                recorded("GET", "/orders/123e4567-e89b-12d3-a456-426614174001", shared),
            ],
            false,
        );
        assert_eq!(result.len(), 1);
        assert_eq!(path(&result[0]), "/orders/{id}");
    }

    /// `RecordedExpectationPostProcessorTest.shouldNotMergeGenuinelyDifferentPaths`.
    #[test]
    fn should_not_merge_genuinely_different_paths() {
        let shared = json!({"statusCode": 200});
        let result = dedup(&[recorded("GET", "/users/1", shared.clone()), recorded("GET", "/orders/2", shared.clone()), recorded("GET", "/products/3", shared)], false);
        assert_eq!(result.len(), 3);
    }

    /// `RecordedExpectationPostProcessorTest.shouldNotMergeDifferentMethodsUnderSameTemplate`.
    #[test]
    fn should_not_merge_different_methods_under_same_template() {
        let result = dedup(&[recorded("GET", "/users/1", json!({"statusCode": 200})), recorded("DELETE", "/users/2", json!({"statusCode": 204}))], false);
        assert_eq!(result.len(), 2);
    }

    /// `RecordedExpectationPostProcessorTest.shouldNotCollapseDifferingResponsesUnderOneTemplate`.
    #[test]
    fn should_not_collapse_differing_responses_under_one_template() {
        let result = dedup(
            &[
                recorded("GET", "/users/1", json!({"statusCode": 200, "body": "alice"})),
                recorded("GET", "/users/2", json!({"statusCode": 200, "body": "bob"})),
                recorded("GET", "/users/3", json!({"statusCode": 404})),
            ],
            false,
        );
        assert_eq!(result.iter().map(path).collect::<Vec<_>>(), ["/users/1", "/users/2", "/users/3"]);
        assert_eq!(result[0]["httpResponse"]["body"], "alice");
        assert_eq!(result[1]["httpResponse"]["body"], "bob");
        assert_eq!(result[2]["httpResponse"]["statusCode"], 404);
    }

    /// `RecordedExpectationPostProcessorTest.shouldPreserveOriginalOrderWithMixedEligibleAndIneligible`.
    #[test]
    fn should_preserve_original_order_with_mixed_eligible_and_ineligible() {
        let ineligible = json!({"httpRequest": {"method": "GET", "path": "/forward/path"}});
        let input = [
            recorded("GET", "/users/1", json!({"statusCode": 200, "body": "shared"})),
            ineligible.clone(),
            recorded("GET", "/users/2", json!({"statusCode": 200, "body": "shared"})),
        ];
        let processed = super::deduplicate_and_templatize(&input, false);
        assert_eq!(processed.len(), 2);
        assert!(matches!(&processed[0], Processed::Built(e) if path(e) == "/users/{id}"));
        assert!(matches!(processed[1], Processed::Kept(1)));
    }

    /// `RecordedExpectationPostProcessorTest.shouldNotOverWidenSingleIdPartitionWhenGroupSpansMultipleIds`.
    #[test]
    fn should_not_over_widen_single_id_partition_when_group_spans_multiple_ids() {
        let result = dedup(
            &[
                recorded("GET", "/users/1", json!({"statusCode": 200})),
                recorded("GET", "/users/2", json!({"statusCode": 200})),
                recorded("GET", "/users/1", json!({"statusCode": 404})),
            ],
            false,
        );
        assert_eq!(result.len(), 2);
        assert_eq!((result[0]["httpResponse"]["statusCode"].as_i64(), path(&result[0])), (Some(200), "/users/{id}"));
        assert_eq!((result[1]["httpResponse"]["statusCode"].as_i64(), path(&result[1])), (Some(404), "/users/1"));
    }

    /// `RecordedExpectationPostProcessorTest.shouldDeduplicateExactDuplicatesToOne`.
    #[test]
    fn should_deduplicate_exact_duplicates_to_one() {
        let shared = json!({"statusCode": 200, "body": "same"});
        let input = [recorded("GET", "/health", shared.clone()), recorded("GET", "/health", shared.clone()), recorded("GET", "/health", shared)];
        let processed = super::deduplicate_and_templatize(&input, false);
        assert_eq!(processed.len(), 1);
        assert!(matches!(processed[0], Processed::Kept(0)));
    }

    /// `RecordedExpectationPostProcessorTest.shouldNotTemplatizeSingleRecordedIdWithNoOtherIds`.
    #[test]
    fn should_not_templatize_single_recorded_id_with_no_other_ids() {
        let input = [recorded("GET", "/users/1", json!({"statusCode": 200}))];
        let processed = super::deduplicate_and_templatize(&input, false);
        assert!(matches!(processed[..], [Processed::Kept(0)]));
    }

    /// `RecordedExpectationPostProcessorTest.shouldPassThroughNonHttpRequestExpectationsUnchanged`.
    #[test]
    fn should_pass_through_non_http_request_expectations_unchanged() {
        let forward_only = json!({"httpRequest": {"method": "GET", "path": "/users/1"}});
        let result = dedup(&[forward_only.clone(), recorded("GET", "/users/2", json!({"statusCode": 200})), recorded("GET", "/users/3", json!({"statusCode": 200}))], false);
        assert!(result.contains(&forward_only));
        assert_eq!(result.len(), 2);
    }

    /// `RecordedExpectationPostProcessorTest.shouldReturnEmptyListForNullOrEmptyInput` (no null in Rust).
    #[test]
    fn should_return_empty_list_for_null_or_empty_input() {
        assert!(dedup(&[], false).is_empty());
        assert!(dedup(&[], true).is_empty());
    }

    /// `RecordedExpectationPostProcessorTest.shouldNotTemplatizeValuesWhenFlagOff`.
    #[test]
    fn should_not_templatize_values_when_flag_off() {
        let input = [recorded_request(
            json!({"method": "GET", "path": "/orders", "queryStringParameters": {"traceId": ["123e4567-e89b-12d3-a456-426614174000"]}}),
            json!({"statusCode": 200}),
        )];
        let result = dedup(&input, false);
        assert_eq!(result.len(), 1);
        assert_eq!(first(&result[0], "queryStringParameters", "traceId"), "123e4567-e89b-12d3-a456-426614174000");
    }

    /// `RecordedExpectationPostProcessorTest.shouldTemplatizeVolatileQueryParameterValue`.
    #[test]
    fn should_templatize_volatile_query_parameter_value() {
        let input = [recorded_request(
            json!({"method": "GET", "path": "/orders", "queryStringParameters": {"traceId": ["123e4567-e89b-12d3-a456-426614174000"], "page": ["2"]}}),
            json!({"statusCode": 200}),
        )];
        let result = dedup(&input, true);
        assert_eq!(first(&result[0], "queryStringParameters", "traceId"), ".+");
        assert_eq!(first(&result[0], "queryStringParameters", "page"), "2");
    }

    /// `RecordedExpectationPostProcessorTest.shouldTemplatizeVolatileHeaderValuesAndByVolatileHeaderName`.
    #[test]
    fn should_templatize_volatile_header_values_and_by_volatile_header_name() {
        let input = [recorded_request(
            json!({"method": "GET", "path": "/orders", "headers": {
                "Authorization": ["Bearer eyJhbGci.payloadsegment.signaturesegment"],
                "X-Request-Id": ["987654321098765"],
                "Accept": ["application/json"],
            }}),
            json!({"statusCode": 200}),
        )];
        let result = dedup(&input, true);
        assert_eq!(first(&result[0], "headers", "Authorization"), ".+");
        assert_eq!(first(&result[0], "headers", "X-Request-Id"), ".+");
        assert_eq!(first(&result[0], "headers", "Accept"), "application/json");
    }

    /// `RecordedExpectationPostProcessorTest.shouldTemplatizeVolatileJsonBodyLeavesAndPreserveStableOnes`.
    #[test]
    fn should_templatize_volatile_json_body_leaves_and_preserve_stable_ones() {
        let body = r#"{"id":"123e4567-e89b-12d3-a456-426614174000","createdAt":"2026-06-20T12:34:56Z","status":"ACTIVE","count":3}"#;
        let result = dedup(&[recorded_request(json!({"method": "POST", "path": "/orders", "body": body}), json!({"statusCode": 200}))], true);
        let body = &result[0]["httpRequest"]["body"];
        assert_eq!(body["type"], "JSON");
        let generalised = body["json"].as_str().unwrap();
        assert!(generalised.contains("${json-unit.regex}"));
        assert!(generalised.contains("ACTIVE"));
        assert!(generalised.contains("\"count\":3"));
        assert!(!generalised.contains("123e4567-e89b-12d3-a456-426614174000"));
        assert!(!generalised.contains("2026-06-20T12:34:56Z"));
    }

    /// `RecordedExpectationPostProcessorTest.shouldLeaveStableValuesAndNonJsonBodyUntouched`.
    #[test]
    fn should_leave_stable_values_and_non_json_body_untouched() {
        let input = [recorded_request(
            json!({"method": "POST", "path": "/orders", "queryStringParameters": {"type": ["standard"]}, "body": "plain text body, not json"}),
            json!({"statusCode": 200}),
        )];
        let processed = super::deduplicate_and_templatize(&input, true);
        assert!(matches!(processed[..], [Processed::Kept(0)]));
    }

    /// `RecordedExpectationPostProcessorTest.volatilityHeuristicClassifiesValuesConservatively`.
    #[test]
    fn volatility_heuristic_classifies_values_conservatively() {
        for v in [
            "123e4567-e89b-12d3-a456-426614174000",
            "1718885696123",
            "2026-06-20T12:34:56Z",
            "2026-06-20",
            "123456789",
            "Bearer aaaaaaaa.bbbbbbbb.cccccccc",
            "abcdefABCDEF0123456789xyzw",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
        ] {
            assert!(super::volatile_value(v), "{v} is volatile");
        }
        for v in ["42", "200", "ACTIVE", "application/json", "true", "standard", "", "SUBSCRIPTION_CANCELLED_BY_USER", "ANOTHERVERYLONGUPPERCASEWORD"] {
            assert!(!super::volatile_value(v), "{v} is stable");
        }
    }
}

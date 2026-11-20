//! `PUT /mockserver/openapi`: `OpenAPIConverter.buildExpectations` turns each operation of a spec into an
//! expectation matching that operation (`specUrlOrPayload` + `operationId`) and answering one of its responses
//! with an example: the media type's own example, else the schema's inline examples, else a generated one
//! (`openapi_examples`). Ids are stable (`openapi:<specKey>:<operationId>`), so re-importing a spec replaces
//! its expectations.

use jackson::JavaObject;
use serde_json::{Map, Value, json};
use swagger_parser::models::{ApiResponse, ApiResponses, OpenAPI, Operation, Schema, SchemaKind};

use crate::openapi_examples::{self as examples, Direction};

pub const ID_PREFIX: &str = "openapi:";

/// What one `OpenAPIExpectation` produces: expectations in input form. `realistic_default` is the converter's
/// `generateRealisticExampleValues` (the instance configuration's for `PUT /mockserver/openapi` and initialisation
/// files, the static store's for an OpenAPI item of `PUT /mockserver/expectation`); `__generationOptions__` in
/// `operationsAndResponses` can override it per run.
pub fn build(openapi_expectation: &Map<String, Value>, realistic_default: bool) -> Result<Vec<Map<String, Value>>, String> {
    build_with_problems(openapi_expectation, realistic_default).map(|(built, _)| built)
}

/// The expectations built from a spec, and its advisory load problems.
type Generated = (Vec<Map<String, Value>>, Vec<crate::openapi_load_problems::Problem>);

/// [`build`], with the spec's advisory load problems (`HttpState.addOpenAPI`'s `OpenAPIImport`, 9.1.0).
pub fn build_with_problems(
    openapi_expectation: &Map<String, Value>,
    realistic_default: bool,
) -> Result<Generated, String> {
    let spec_value = openapi_expectation.get("specUrlOrPayload").cloned().unwrap_or(Value::Null);
    let spec = crate::openapi::spec_text(&spec_value).unwrap_or_default();
    let operations_and_responses = openapi_expectation.get("operationsAndResponses").and_then(Value::as_object);
    let prefix = openapi_expectation.get("contextPathPrefix").and_then(Value::as_str).filter(|p| !p.trim().is_empty());
    let loaded = crate::openapi::load_spec(&spec)?;
    let openapi = loaded.openapi;
    add_missing_operation_ids(&openapi);
    let spec_key = spec_key(openapi.get_info().and_then(|i| i.get_title()).as_deref(), &spec);
    let definitions = openapi.get_components().and_then(|c| c.get_schemas());
    let generation = Generation { options: examples::GenerationOptions::from_operations_map(operations_and_responses), realistic_default };
    let mut counts: std::collections::HashMap<String, usize> = Default::default();
    let mut out = Vec::new();
    for operation in operations(&openapi) {
        let id = operation.get_operation_id().unwrap_or_default();
        let choice = match operations_and_responses {
            Some(map) => match map.get(&id) {
                None => continue,
                Some(Value::String(key)) => (Some(key.clone()), None),
                Some(Value::Object(rich)) => (
                    rich.get("statusCode").map(java_string),
                    rich.get("exampleName").map(java_string),
                ),
                Some(_) => (None, None),
            },
            None => (None, None),
        };
        let mut request = Map::new();
        request.insert("specUrlOrPayload".into(), spec_value.clone());
        request.insert("operationId".into(), Value::String(id.clone()));
        if let Some(p) = prefix {
            request.insert("contextPathPrefix".into(), Value::String(p.to_string()));
        }
        let response =
            http_response(&openapi, definitions.as_ref(), operation.get_responses(), choice.0.as_deref(), choice.1.as_deref(), &generation);
        let count = counts.entry(id.clone()).and_modify(|c| *c += 1).or_insert(1);
        let mut stable_id = format!("{ID_PREFIX}{spec_key}:{id}");
        if *count > 1 {
            stable_id.push_str(&format!(":{count}"));
        }
        let mut expectation = Map::new();
        expectation.insert("id".into(), Value::String(stable_id));
        expectation.insert("httpRequest".into(), Value::Object(request));
        expectation.insert("httpResponse".into(), Value::Object(response));
        let after_actions = after_actions(definitions.as_ref(), &operation, &generation);
        if !after_actions.is_empty() {
            expectation.insert("afterActions".into(), Value::Array(after_actions));
        }
        out.push(expectation);
    }
    Ok((out, loaded.problems))
}

/// `buildAfterActions`: each callback operation becomes an after-action request. A URL with runtime expressions
/// (`{$…`) is kept verbatim as the path for fire-time resolution; an absolute `http(s)` URL becomes path, `Host` and
/// `secure`; anything else is the path. The request body is an example of the callback's first request content.
/// The run's `GenerationOptions` and the configuration's realistic-values default.
struct Generation {
    options: Option<examples::GenerationOptions>,
    realistic_default: bool,
}

impl Generation {
    fn example(&self, schema: &Schema, definitions: Option<&swagger_parser::java::JMap<Schema>>, direction: Direction) -> Option<examples::Example> {
        examples::from_schema_with(schema, definitions, self.options.as_ref(), direction, self.realistic_default)
    }
}

fn after_actions(definitions: Option<&swagger_parser::java::JMap<Schema>>, operation: &Operation, generation: &Generation) -> Vec<Value> {
    let mut out = Vec::new();
    for (_, callback) in operation.get_callbacks().map(|c| c.entries()).unwrap_or_default() {
        for (url, item) in callback.entries() {
            for (method, callback_operation) in item.read_operations_map() {
                let mut request = Map::new();
                request.insert("method".into(), Value::String(method.as_str().to_string()));
                let mut headers = Map::new();
                if url.contains("{$") {
                    request.insert("path".into(), Value::String(url.clone()));
                } else if url.starts_with("http://") || url.starts_with("https://") {
                    // `new URI(url)` failing skips this callback (upstream logs a warning)
                    let Ok(uri) = crate::java_uri::parse(&url) else { continue };
                    request.insert("path".into(), Value::String(crate::java_uri::path(&uri).unwrap_or_else(|| "/".into())));
                    let host = uri.host.clone().unwrap_or_else(|| "null".into());
                    let host = if uri.port > 0 { format!("{host}:{}", uri.port) } else { host };
                    headers.insert("Host".into(), json!([host]));
                    request.insert("secure".into(), Value::Bool(url.starts_with("https://")));
                } else {
                    request.insert("path".into(), Value::String(url.clone()));
                }
                let content = callback_operation.get_request_body().and_then(|b| b.get_content()).and_then(|c| c.entries().into_iter().next());
                if let Some((content_type, media)) = content {
                    headers.insert("Content-Type".into(), json!([content_type]));
                    if let Some(example) = media.get_schema().and_then(|schema| generation.example(&schema, definitions, Direction::Request)) {
                        request.insert("body".into(), Value::String(examples::to_json(&example)));
                    }
                }
                if !headers.is_empty() {
                    request.insert("headers".into(), Value::Object(headers));
                }
                out.push(json!({"httpRequest": request}));
            }
        }
    }
    out
}

/// The `openapi:<specKey>:` namespace of a generated id.
pub fn namespace(id: &str) -> Option<&str> {
    let rest = id.strip_prefix(ID_PREFIX)?;
    let colon = rest.find(':')?;
    Some(&id[..ID_PREFIX.len() + colon + 1])
}

fn java_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `OpenApiSyncPlanner.deriveSpecKey`: the lower-cased title with non-alphanumerics as `_`, then the first 8
/// bytes of the SHA-256 of the spec as given, in hex.
fn spec_key(title: Option<&str>, spec: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, spec.as_bytes());
    let hash: String = digest.as_ref()[..8].iter().map(|b| format!("{b:02x}")).collect();
    match title.filter(|t| !t.trim().is_empty()) {
        Some(t) => format!("{}_{hash}", t.to_lowercase().chars().map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() { c } else { '_' }).collect::<String>()),
        None => hash,
    }
}

/// `pathItem.readOperations()` of every path, then of every webhook.
fn operations(openapi: &OpenAPI) -> Vec<Operation> {
    let mut out: Vec<Operation> = openapi.get_paths().map(|p| p.values()).unwrap_or_default().iter().flat_map(|item| item.read_operations()).collect();
    if let Some(webhooks) = openapi.get_webhooks() {
        out.extend(webhooks.values().iter().flat_map(|item| item.read_operations()));
    }
    out
}

/// `OpenAPIParser.mapOperations` on the model: a path item's operations as `(METHOD, operation)`, in method order.
pub(crate) fn map_operations(item: &swagger_parser::models::PathItem) -> Vec<(&'static str, Operation)> {
    [
        ("GET", item.get_get()),
        ("PUT", item.get_put()),
        ("POST", item.get_post()),
        ("PATCH", item.get_patch()),
        ("DELETE", item.get_delete()),
        ("HEAD", item.get_head()),
        ("OPTIONS", item.get_options()),
        ("TRACE", item.get_trace()),
    ]
    .into_iter()
    .filter_map(|(m, o)| o.map(|o| (m, o)))
    .collect()
}

/// `OpenAPIParser.addMissingOperationIds` on the model (see `openapi::add_missing_operation_ids`).
pub(crate) fn add_missing_operation_ids(openapi: &OpenAPI) {
    for (operation, id, _) in assigned_operation_ids(openapi) {
        operation.set_operation_id(id);
    }
}

/// The renames `addMissingOperationIds` logs at WARN (`ensureUnique`), as `(candidate, disambiguated)`, in its order.
pub(crate) fn duplicate_operation_ids(openapi: &OpenAPI) -> Vec<(String, String)> {
    assigned_operation_ids(openapi).into_iter().filter_map(|(_, id, renamed)| renamed.map(|candidate| (candidate, id))).collect()
}

/// The id `addMissingOperationIds` gives each operation it sets one on, and the candidate it renamed when that one
/// was taken; the model is left as it is.
fn assigned_operation_ids(openapi: &OpenAPI) -> Vec<(Operation, String, Option<String>)> {
    let mut seen = std::collections::HashSet::new();
    let unique = |candidate: String, seen: &mut std::collections::HashSet<String>| {
        if seen.insert(candidate.clone()) {
            return (candidate, None);
        }
        let id = (2..).map(|n| format!("{candidate} ({n})")).find(|c| seen.insert(c.clone())).expect("unbounded");
        (id, Some(candidate))
    };
    let mut sections: Vec<(String, swagger_parser::models::PathItem, bool)> = Vec::new();
    for (name, item) in openapi.get_paths().map(|p| p.entries()).unwrap_or_default() {
        sections.push((name, item, false));
    }
    for (name, item) in openapi.get_webhooks().map(|w| w.entries()).unwrap_or_default() {
        sections.push((name, item, true));
    }
    let mut assigned = Vec::new();
    for (_, item, _) in &sections {
        for (_, operation) in map_operations(item) {
            if let Some(id) = operation.get_operation_id().filter(|s| !s.trim().is_empty()) {
                let (id, renamed) = unique(id, &mut seen);
                assigned.push((operation, id, renamed));
            }
        }
    }
    for (name, item, webhook) in &sections {
        for (method, operation) in map_operations(item) {
            if operation.get_operation_id().is_none_or(|s| s.trim().is_empty()) {
                let candidate = if *webhook { format!("{method} webhook:{name}") } else { format!("{method} {name}") };
                let (id, renamed) = unique(candidate, &mut seen);
                assigned.push((operation, id, renamed));
            }
        }
    }
    assigned
}

/// `buildHttpResponse`
fn http_response(
    openapi: &OpenAPI,
    definitions: Option<&swagger_parser::java::JMap<Schema>>,
    responses: Option<ApiResponses>,
    key: Option<&str>,
    example_name: Option<&str>,
    generation: &Generation,
) -> Map<String, Value> {
    let mut response = Map::new();
    let Some((status_key, api_response)) = responses.and_then(|r| select_response(&r, key)) else { return response };
    if let Some(status) = status_code(&status_key) {
        response.insert("statusCode".into(), json!(status));
    }
    let mut headers: Vec<(String, String)> = Vec::new();
    for (name, header) in api_response.get_headers().map(|h| h.entries()).unwrap_or_default() {
        if let Some(example) = header_example(openapi, &header, example_name) {
            headers.push((name, example.to_java_string()));
        } else if let Some(schema) = header.get_schema() && let Some(generated) = generation.example(&schema, definitions, Direction::Response) {
            let value = match &generated.value {
                examples::Value::String(s) => s.clone(),
                _ => examples::to_json(&generated),
            };
            headers.push((name, value));
        }
    }
    let mut body: Option<Value> = None;
    if let Some((content_type, media)) = api_response.get_content().and_then(|c| c.entries().into_iter().next()) {
        headers.push(("content-type".into(), content_type.clone()));
        let json_type = crate::media_type::MediaType::parse(Some(&content_type)).is_json();
        if let Some(example) = media_example(&media, example_name).and_then(|e| resolve_example_refs(openapi, e)) {
            body = Some(if json_type { json_body(&examples::java_object_to_json(&example)) } else { Value::String(example.to_java_string()) });
        } else if let Some(schema) = media.get_schema() {
            if let Some(schema_example) = schema_example(openapi, &schema, &mut Vec::new()) {
                let text = crate::json::pretty(&schema_example);
                body = Some(if json_type { json_body(&text) } else { Value::String(text) });
            } else if let Some(generated) = generation.example(&schema, definitions, Direction::Response) {
                body = Some(match (&generated.value, json_type) {
                    (examples::Value::String(s), true) => json_body(&examples::to_json(&examples_string(s))),
                    (examples::Value::String(s), false) => Value::String(s.clone()),
                    (_, true) => json_body(&examples::to_json(&generated)),
                    (_, false) if is_xml(&content_type) => Value::String(examples::to_xml(&generated)),
                    (_, false) => Value::String(examples::to_json(&generated)),
                });
            }
        }
    }
    if !headers.is_empty() {
        let mut map = Map::new();
        for (name, value) in headers {
            match map.get_mut(&name) {
                Some(Value::Array(values)) => values.push(Value::String(value)),
                _ => {
                    map.insert(name, json!([value]));
                }
            }
        }
        response.insert("headers".into(), Value::Object(map));
    }
    if let Some(body) = body {
        response.insert("body".into(), body);
    }
    response
}

fn examples_string(s: &str) -> examples::Example {
    examples::Example {
        value: examples::Value::String(s.to_string()),
        name: None,
        namespace: None,
        prefix: None,
        attribute: false,
        wrapped: false,
        wrapped_name: None,
    }
}

/// `json(serialise(example))`: a JSON body kept as the text upstream serialised.
fn json_body(text: &str) -> Value {
    json!({"type": "JSON", "json": text})
}

/// `selectApiResponse`: the named response, else (blank or unknown key) the first one.
fn select_response(responses: &ApiResponses, key: Option<&str>) -> Option<(String, ApiResponse)> {
    let entries = responses.entries();
    if let Some(key) = key.filter(|k| !k.trim().is_empty()) && let Some(found) = entries.iter().find(|(k, _)| k == key) {
        return Some(found.clone());
    }
    entries.into_iter().next()
}

/// `parseResponseStatusCode`: `"200"` → 200, `"2XX"` → 200, `"default"` and anything else → none.
fn status_code(key: &str) -> Option<u16> {
    if key.len() == 3 && key.bytes().all(|b| b.is_ascii_digit()) {
        return key.parse().ok();
    }
    let b = key.as_bytes();
    if b.len() == 3 && (b'1'..=b'5').contains(&b[0]) && b[1].eq_ignore_ascii_case(&b'x') && b[2].eq_ignore_ascii_case(&b'x') {
        return Some((b[0] - b'0') as u16 * 100);
    }
    None
}

fn is_xml(content_type: &str) -> bool {
    let base = content_type.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    let Some((t, s)) = base.split_once('/') else { return false };
    (t == "application" || t == "text") && s == "xml" || s.ends_with("+xml")
}

/// `findHeaderExample`: a named or first `examples` entry falls back to its literal value when its `$ref`s do not
/// resolve; a plain `example` does not.
fn header_example(openapi: &OpenAPI, header: &swagger_parser::models::Header, example_name: Option<&str>) -> Option<JavaObject> {
    let resolved_or_literal = |value: Option<JavaObject>| value.and_then(|v| resolve_example_refs(openapi, v.clone()).or(Some(v)));
    if let (Some(name), Some(named)) = (example_name, header.get_examples()) && let Some(example) = named.get(name) {
        return resolved_or_literal(example.get_value());
    }
    if let Some(example) = header.get_example() {
        return resolve_example_refs(openapi, example);
    }
    resolved_or_literal(header.get_examples().and_then(|e| e.values().into_iter().next()).and_then(|e| e.get_value()))
}

const MAX_REF_DEPTH: usize = 100;
const MAX_STRUCTURE_DEPTH: usize = 1000;

/// `resolveExampleRefs`: every `{"$ref": "#/components/examples/…"}` inside an example value replaced by what it
/// points to (recursively); an unresolvable one becomes `null` (at the top: no example), a cyclic or too deep one
/// stays literal.
fn resolve_example_refs(openapi: &OpenAPI, value: JavaObject) -> Option<JavaObject> {
    resolve_refs(openapi, value, &mut Vec::new(), 0, 0)
}

fn single_ref(value: &JavaObject) -> Option<String> {
    match value {
        JavaObject::Map(m) if m.len() == 1 => m.get("$ref").map(JavaObject::to_java_string),
        JavaObject::Node(jackson::JsonNode::Object(o)) if o.len() == 1 => o.get("$ref").map(|r| match r {
            jackson::JsonNode::Text(t) => t.to_string(),
            other => other.to_string(),
        }),
        _ => None,
    }
}

fn resolve_refs(openapi: &OpenAPI, value: JavaObject, chain: &mut Vec<String>, ref_depth: usize, depth: usize) -> Option<JavaObject> {
    if depth >= MAX_STRUCTURE_DEPTH {
        return Some(value);
    }
    if let Some(reference) = single_ref(&value) {
        if chain.contains(&reference) || ref_depth >= MAX_REF_DEPTH {
            return Some(value);
        }
        let resolved = resolve_ref(openapi, &reference)?;
        chain.push(reference);
        let result = resolve_refs(openapi, resolved, chain, ref_depth + 1, depth + 1);
        chain.pop();
        return result;
    }
    let mut item = |v: JavaObject| resolve_refs(openapi, v, chain, ref_depth, depth + 1).unwrap_or(JavaObject::Null);
    Some(match value {
        JavaObject::Map(m) => JavaObject::Map(std::sync::Arc::new(m.iter().map(|(k, v)| (k.clone(), item(v.clone()))).collect())),
        JavaObject::List(l) => JavaObject::List(std::sync::Arc::new(l.iter().map(|v| item(v.clone())).collect())),
        JavaObject::Node(jackson::JsonNode::Object(o)) => JavaObject::Node(jackson::JsonNode::Object(std::sync::Arc::new(
            o.iter().map(|(k, v)| (k.clone(), node(item(JavaObject::Node(v.clone()))))).collect(),
        ))),
        JavaObject::Node(jackson::JsonNode::Array(a)) => {
            JavaObject::Node(jackson::JsonNode::Array(std::sync::Arc::new(a.iter().map(|v| node(item(JavaObject::Node(v.clone())))).collect())))
        }
        other => other,
    })
}

/// A resolved value put back into a Jackson tree (`set` for a node, `putPOJO` for anything else).
fn node(value: JavaObject) -> jackson::JsonNode {
    match value {
        JavaObject::Node(n) => n,
        JavaObject::Null => jackson::JsonNode::Null,
        other => jackson::JsonNode::Pojo(std::sync::Arc::new(other)),
    }
}

/// `resolveRef`: `#/components/examples/<name>` plus any JSON-pointer suffix (a `value` segment right after the name
/// addresses the example's value itself).
fn resolve_ref(openapi: &OpenAPI, reference: &str) -> Option<JavaObject> {
    let path = reference.strip_prefix("#/components/examples/")?;
    let parts: Vec<&str> = path.split('/').collect();
    let name = parts.first().filter(|p| !p.trim().is_empty())?;
    let example = openapi.get_components()?.get_examples()?.get(name)?;
    let mut current = example.get_value()?;
    let from = if parts.get(1) == Some(&"value") { 2 } else { 1 };
    for segment in &parts[from.min(parts.len())..] {
        let segment = segment.replace("~1", "/").replace("~0", "~");
        current = match &current {
            JavaObject::Node(n) => match n {
                jackson::JsonNode::Object(o) => JavaObject::Node(o.get(&segment)?.clone()),
                jackson::JsonNode::Array(a) => JavaObject::Node(a.get(segment.parse::<usize>().ok()?)?.clone()),
                _ => return None,
            },
            JavaObject::Map(m) => m.get(&segment)?.clone(),
            JavaObject::List(l) => l.get(segment.parse::<usize>().ok()?)?.clone(),
            _ => return None,
        };
    }
    // `navigatePointer` returns null for a missing field (Jackson's `get`), and a null resolution is unresolvable
    (!current.is_null()).then_some(current)
}

/// `findExample`
fn media_example(media: &swagger_parser::models::MediaType, example_name: Option<&str>) -> Option<JavaObject> {
    if let (Some(name), Some(named)) = (example_name, media.get_examples()) && let Some(example) = named.get(name) {
        return example.get_value();
    }
    if let Some(example) = media.get_example() {
        return Some(example);
    }
    media.get_examples().and_then(|e| e.values().into_iter().next()).and_then(|e| e.get_value())
}

/// `resolveSchemaExample`: the schema's own inline examples, as a whole; `None` as soon as one property has none.
fn schema_example(openapi: &OpenAPI, schema: &Schema, active: &mut Vec<usize>) -> Option<Value> {
    let key = schema.0.as_ref() as *const _ as usize;
    if active.contains(&key) {
        return None;
    }
    active.push(key);
    let result = schema_example_inner(openapi, schema, active);
    active.pop();
    result
}

fn schema_example_inner(openapi: &OpenAPI, schema: &Schema, active: &mut Vec<usize>) -> Option<Value> {
    if let Some(example) = schema.get_example() {
        let example = examples::normalize_flattened_example(example, schema);
        let example = match (&example, schema.kind()) {
            (JavaObject::Date(_), SchemaKind::Date) | (JavaObject::OffsetDateTime(_), SchemaKind::DateTime) => {
                return Some(Value::String(match &example {
                    JavaObject::Date(ms) => {
                        let days = ms.div_euclid(86_400_000);
                        (chrono::NaiveDate::from_ymd_opt(1970, 1, 1).expect("epoch") + chrono::Duration::days(days)).format("%Y-%m-%d").to_string()
                    }
                    other => other.to_java_string(),
                }));
            }
            _ => example,
        };
        let example = resolve_example_refs(openapi, example)?;
        return serde_json::from_str(&examples::java_object_to_json(&example)).ok();
    }
    let d = schema.read();
    let (all_of, any_of, one_of, properties, items) = (d.all_of.clone(), d.any_of.clone(), d.one_of.clone(), d.properties.clone(), d.items.clone());
    let composed = d.kind == SchemaKind::Composed;
    drop(d);
    if composed {
        if let Some(all_of) = all_of {
            let mut merged = Map::new();
            for sub in all_of.to_vec() {
                if let Some(Value::Object(o)) = schema_example(openapi, &sub, active) {
                    merged.extend(o);
                }
            }
            if let Some(properties) = &properties {
                for (k, v) in properties.entries() {
                    merged.insert(k, schema_example(openapi, &v, active)?);
                }
            }
            return (!merged.is_empty()).then_some(Value::Object(merged));
        }
        for members in [any_of, one_of].into_iter().flatten() {
            for sub in members.to_vec() {
                if let Some(example) = schema_example(openapi, &sub, active) {
                    return Some(example);
                }
            }
        }
    }
    if let Some(properties) = properties {
        let mut result = Map::new();
        for (k, v) in properties.entries() {
            result.insert(k, schema_example(openapi, &v, active)?);
        }
        return (!result.is_empty()).then_some(Value::Object(result));
    }
    if schema.kind() == SchemaKind::Array && let Some(items) = items {
        return schema_example(openapi, &items, active).map(|e| Value::Array(vec![e]));
    }
    None
}

/// An operation of a spec as a load step's request (`LoadScenarioFromOpenAPI`).
pub struct LoadOperation {
    pub request: Value,
    pub operation_id: Option<String>,
}

pub struct LoadRequests {
    pub operations: Vec<LoadOperation>,
    /// The first server's URL, which targets the requests when no target is given.
    pub first_server: Option<String>,
}

/// `LoadScenarioFromOpenAPI.generate`: every operation as method + path, with the first request content type and an
/// example body generated from its schema (`ExampleBuilder.fromSchema`, `Direction.REQUEST`, no configuration: realistic
/// per the static store's `generateRealisticExampleValues`, `realistic`).
pub fn load_requests(spec: &str, realistic: bool) -> Result<LoadRequests, String> {
    let mut json = crate::openapi::load(spec)?;
    crate::openapi::add_missing_operation_ids(&mut json);
    let model = crate::openapi::load_model(spec)?;
    let definitions = model.get_components().and_then(|c| c.get_schemas());
    let first_server = json.pointer("/servers/0/url").and_then(Value::as_str).filter(|u| !u.trim().is_empty()).map(str::to_string);
    let mut operations = Vec::new();
    for (path, method, operation) in crate::openapi::all_operations(&json) {
        let mut request = Map::new();
        request.insert("method".into(), Value::String(method.clone()));
        request.insert("path".into(), Value::String(path.clone()));
        if let Some((content_type, media)) = operation.pointer("/requestBody/content").and_then(Value::as_object).and_then(|c| c.iter().next()) {
            request.insert("headers".into(), json!({"Content-Type": [content_type]}));
            if media.get("schema").is_some() {
                let schema = model_request_schema(&model, &operation, content_type);
                if let Some(generated) = schema.and_then(|s| examples::from_schema_with(&s, definitions.as_ref(), None, Direction::Request, realistic)) {
                    match &generated.value {
                        examples::Value::String(s) => {
                            request.insert("body".into(), Value::String(s.clone()));
                        }
                        _ => {
                            let body = examples::to_json(&generated);
                            if !body.trim().is_empty() {
                                let json_type = crate::media_type::MediaType::parse(Some(content_type)).is_json();
                                request.insert("body".into(), if json_type { json_body(&body) } else { Value::String(body) });
                            }
                        }
                    }
                }
            }
        }
        let operation_id = operation.get("operationId").and_then(Value::as_str).map(str::to_string);
        operations.push(LoadOperation { request: Value::Object(request), operation_id });
    }
    Ok(LoadRequests { operations, first_server })
}

/// The model schema of `operation`'s request body for `content_type`, found by operation id.
fn model_request_schema(model: &OpenAPI, operation: &Value, content_type: &str) -> Option<Schema> {
    add_missing_operation_ids(model);
    let id = operation.get("operationId").and_then(Value::as_str)?;
    let found = operations(model).into_iter().find(|o| o.get_operation_id().as_deref() == Some(id))?;
    found.get_request_body()?.get_content()?.get(content_type)?.get_schema()
}

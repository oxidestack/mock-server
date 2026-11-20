//! SCIM 2.0 providers (`org.mockserver.scim`): `PUT /mockserver/scim` registers a provider under its base path and
//! adds expectations for its Users and Groups endpoints (answered by the built-in callback classes
//! `ScimCollectionCallback` and `ScimResourceCallback`) and its discovery documents. Resources live in per-provider
//! stores until `reset`.

use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use crate::class_callback::{CallbackClass, CallbackError, ResponseCallback};
use crate::recorded::Failure;
use crate::request::HttpRequest;
use crate::state::State;

pub const COLLECTION_CALLBACK: &str = "org.mockserver.scim.ScimCollectionCallback";
pub const RESOURCE_CALLBACK: &str = "org.mockserver.scim.ScimResourceCallback";

const CONTENT_TYPE: &str = "application/scim+json";
const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const SERVICE_PROVIDER_CONFIG_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
/// `CrudDataStore.DEFAULT_MAX_ITEMS`.
const MAX_ITEMS: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    User,
    Group,
}

impl Kind {
    fn segment(self) -> &'static str {
        match self {
            Kind::User => "Users",
            Kind::Group => "Groups",
        }
    }

    fn schema(self) -> &'static str {
        match self {
            Kind::User => USER_SCHEMA,
            Kind::Group => GROUP_SCHEMA,
        }
    }

    fn singular(self) -> &'static str {
        match self {
            Kind::User => "User",
            Kind::Group => "Group",
        }
    }

    fn required(self) -> &'static str {
        match self {
            Kind::User => "userName",
            Kind::Group => "displayName",
        }
    }
}

/// A stored resource: its id and its JSON.
type Resource = (String, Map<String, Value>);

/// `CrudDataStore` keyed by `id`.
struct Store {
    auto_increment: bool,
    inner: Mutex<(Vec<Resource>, i64)>,
}

impl Store {
    fn new(auto_increment: bool, initial: &[Map<String, Value>]) -> Store {
        let mut items = Vec::new();
        let mut counter = 0;
        for item in initial {
            let Some(id) = id_text(item.get("id")) else { continue };
            if auto_increment && let Ok(n) = id.parse::<i64>() {
                counter = counter.max(n);
            }
            // `items.put` + `insertionOrder.addLast`: a repeated id is listed twice, with the last value.
            items.push((id.clone(), item.clone()));
            for entry in items.iter_mut().filter(|(k, _)| *k == id) {
                entry.1 = item.clone();
            }
        }
        Store { auto_increment, inner: Mutex::new((items, counter)) }
    }

    fn all(&self) -> Vec<Map<String, Value>> {
        self.inner.lock().0.iter().map(|(_, v)| v.clone()).collect()
    }

    fn get(&self, id: &str) -> Option<Map<String, Value>> {
        self.inner.lock().0.iter().find(|(k, _)| k == id).map(|(_, v)| v.clone())
    }

    fn create(&self, mut item: Map<String, Value>) -> Option<Map<String, Value>> {
        let mut inner = self.inner.lock();
        let distinct = inner.0.iter().map(|(k, _)| k).collect::<std::collections::HashSet<_>>().len();
        if distinct >= MAX_ITEMS {
            return None;
        }
        let id = if self.auto_increment {
            inner.1 += 1;
            item.insert("id".into(), inner.1.into());
            inner.1.to_string()
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            item.insert("id".into(), id.clone().into());
            id
        };
        inner.0.push((id, item.clone()));
        Some(item)
    }

    /// `updateAtomically`: `transform` sees the stored resource; the result is stored with the path's id.
    fn update(&self, id: &str, transform: impl FnOnce(&Map<String, Value>) -> Result<Map<String, Value>, PatchError>) -> Result<Option<Map<String, Value>>, PatchError> {
        let mut inner = self.inner.lock();
        let Some(existing) = inner.0.iter().find(|(k, _)| k == id).map(|(_, v)| v.clone()) else { return Ok(None) };
        let mut replacement = transform(&existing)?;
        let id_value = if self.auto_increment { id.parse::<i64>().map(Value::from).unwrap_or_else(|_| id.into()) } else { id.into() };
        replacement.insert("id".into(), id_value);
        for entry in inner.0.iter_mut().filter(|(k, _)| k == id) {
            entry.1 = replacement.clone();
        }
        Ok(Some(replacement))
    }

    fn delete(&self, id: &str) -> bool {
        let mut inner = self.inner.lock();
        let before = inner.0.len();
        if let Some(i) = inner.0.iter().position(|(k, _)| k == id) {
            inner.0.remove(i);
        }
        before != inner.0.len()
    }
}

/// `extractId`: text of a present, non-null `id`.
fn id_text(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

/// `ScimResourceStore.Provider`.
struct Provider {
    base_path: String,
    users: Store,
    groups: Store,
    require_bearer: bool,
    expected_bearer: Option<String>,
    enforce_filter: bool,
    enforce_patch: bool,
}

/// `ScimResourceStore`.
#[derive(Default)]
pub struct Scim {
    providers: Mutex<Vec<Arc<Provider>>>,
}

impl Scim {
    pub fn reset(&self) {
        self.providers.lock().clear();
    }

    /// `providerForRequestPath`: the provider with the longest base path under which `path` falls.
    fn provider_for(&self, path: &str) -> Option<Arc<Provider>> {
        self.providers
            .lock()
            .iter()
            .filter(|p| path == p.base_path || path.starts_with(&format!("{}/", p.base_path)))
            .max_by_key(|p| p.base_path.len())
            .cloned()
    }
}

/// The built-in SCIM callback classes, answering from `scim`'s providers.
pub fn callback_class(scim: &Arc<Scim>, class: &str) -> Option<CallbackClass> {
    let collection = match class {
        COLLECTION_CALLBACK => true,
        RESOURCE_CALLBACK => false,
        _ => return None,
    };
    Some(CallbackClass::new().with_response(Callback { scim: scim.clone(), collection }))
}

struct Callback {
    scim: Arc<Scim>,
    collection: bool,
}

impl ResponseCallback for Callback {
    fn handle(&self, request: &Value) -> Result<Value, CallbackError> {
        let request = crate::forward::request_from_json(request);
        Ok(if self.collection { collection(&self.scim, &request) } else { resource(&self.scim, &request) })
    }
}

/// `ScimCallbackSupport.json`.
fn reply(status: u32, body: &Value, extra: Vec<(&str, String)>) -> Value {
    let mut headers = Map::new();
    headers.insert("content-type".into(), json!([CONTENT_TYPE]));
    for (name, value) in extra {
        headers.insert(name.into(), json!([value]));
    }
    json!({"statusCode": status, "headers": headers, "body": crate::json::pretty(body)})
}

/// `ScimShaper.error`.
fn error(status: u32, detail: &str, scim_type: Option<&str>) -> Value {
    let mut o = Map::new();
    o.insert("schemas".into(), json!([ERROR_SCHEMA]));
    if let Some(t) = scim_type {
        o.insert("scimType".into(), t.into());
    }
    o.insert("detail".into(), detail.into());
    o.insert("status".into(), status.to_string().into());
    reply(status, &Value::Object(o), Vec::new())
}

/// `bearerGate`.
fn bearer_gate(request: &HttpRequest, provider: &Provider) -> Option<Value> {
    if !provider.require_bearer {
        return None;
    }
    let token = request
        .first_header("authorization")
        .filter(|a| a.len() >= 7 && a[..7].eq_ignore_ascii_case("Bearer "))
        .map(|a| a[7..].trim().to_string())
        .filter(|t| !t.is_empty());
    let valid = match (token, provider.expected_bearer.as_deref().filter(|e| !e.is_empty())) {
        (Some(token), Some(expected)) => crate::auth::constant_time_eq(expected.as_bytes(), token.as_bytes()),
        _ => false,
    };
    if valid {
        return None;
    }
    let mut unauthorized = error(401, "Unauthorized", None);
    unauthorized["headers"]["WWW-Authenticate"] = json!(["Bearer"]);
    Some(unauthorized)
}

/// `publicBaseUrl`.
fn public_base_url(request: &HttpRequest) -> String {
    match request.first_header("host").filter(|h| !h.is_empty()) {
        Some(host) => format!("{}://{host}", if request.secure { "https" } else { "http" }),
        None => String::new(),
    }
}

fn kind_of(request: &HttpRequest, provider: &Provider) -> Kind {
    let groups = format!("{}/Groups", provider.base_path);
    if request.path == groups || request.path.starts_with(&format!("{groups}/")) { Kind::Group } else { Kind::User }
}

fn store(provider: &Provider, kind: Kind) -> &Store {
    match kind {
        Kind::User => &provider.users,
        Kind::Group => &provider.groups,
    }
}

/// `parseObject`.
fn parse_object(request: &HttpRequest) -> Option<Map<String, Value>> {
    let body = request.body_str();
    if body.trim().is_empty() {
        return None;
    }
    match crate::json::parse_lenient(body.as_bytes()) {
        Ok(Value::Object(o)) => Some(o),
        _ => None,
    }
}

/// `Instant.now().toString()`.
pub(crate) fn now_text() -> String {
    let now = chrono::Utc::now();
    let text = now.format("%Y-%m-%dT%H:%M:%S%.9f").to_string();
    let trimmed = text.trim_end_matches('0');
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    // `Instant.toString` prints the fraction in groups of three digits.
    let formatted = match trimmed.split_once('.') {
        Some((head, fraction)) => {
            let digits = fraction.len().div_ceil(3) * 3;
            format!("{head}.{fraction:0<digits$}")
        }
        None => trimmed.to_string(),
    };
    format!("{formatted}Z")
}

/// `ScimShaper.shapeResource`.
fn shape(stored: &Map<String, Value>, kind: Kind, public_base: &str, base_path: &str, created: bool) -> Map<String, Value> {
    let mut resource = stored.clone();
    let has_schemas = resource.get("schemas").and_then(Value::as_array).is_some_and(|a| !a.is_empty());
    if !has_schemas {
        resource.insert("schemas".into(), json!([kind.schema()]));
    }
    let id = resource.get("id").map(|v| crate::chaos::as_text(Some(v)).unwrap_or_default());
    let now = now_text();
    let mut meta = match resource.get("meta") {
        Some(Value::Object(m)) => m.clone(),
        _ => Map::new(),
    };
    meta.insert("resourceType".into(), kind.singular().into());
    let empty_created = meta.get("created").is_some_and(|c| crate::chaos::as_text(Some(c)).unwrap_or_default().is_empty());
    if !meta.contains_key("created") || (created && empty_created) {
        meta.insert("created".into(), now.clone().into());
    }
    meta.insert("lastModified".into(), now.clone().into());
    if let Some(id) = &id {
        meta.insert("location".into(), format!("{public_base}{base_path}/{}/{id}", kind.segment()).into());
    }
    let hash = java_compat::lang::string_hash(&format!("{now}{}", id.clone().unwrap_or_default()));
    meta.insert("version".into(), format!("W/\"{:x}\"", hash as u32).into());
    resource.insert("meta".into(), Value::Object(meta));
    resource
}

/// `ScimShaper.listResponse`.
fn list_response(resources: Vec<Value>, total: usize, start_index: i64) -> Value {
    json!({
        "schemas": [LIST_RESPONSE_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    })
}

fn query<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    request.query.iter().find(|(k, _)| k == name).and_then(|(_, v)| v.first()).map(String::as_str)
}

/// `ScimCollectionCallback.handle`.
fn collection(scim: &Scim, request: &HttpRequest) -> Value {
    let Some(provider) = scim.provider_for(&request.path) else { return error(404, "no SCIM provider registered for this path", None) };
    if let Some(unauthorized) = bearer_gate(request, &provider) {
        return unauthorized;
    }
    let kind = kind_of(request, &provider);
    if request.method.eq_ignore_ascii_case("POST") {
        return create(request, &provider, kind);
    }
    let mut stored = store(&provider, kind).all();
    if let Some(filter) = query(request, "filter").filter(|f| !f.is_empty()) {
        if !provider.enforce_filter {
            return error(501, "filtering is not supported", None);
        }
        match Filter::parse(filter) {
            Ok(Some(f)) => stored.retain(|r| f.matches(r)),
            Ok(None) => {}
            Err(message) => return error(400, &message, Some("invalidFilter")),
        }
    }
    match sort(query(request, "sortBy"), query(request, "sortOrder")) {
        Ok(Some((path, descending))) => {
            let key = |r: &Map<String, Value>| value_at(r, &path);
            // `List.sort` is stable; missing values sort last whatever the order.
            stored.sort_by(|a, b| match (key(a), key(b)) {
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (Some(_), None) => std::cmp::Ordering::Less,
                (Some(x), Some(y)) => {
                    let c = compare_ignore_case(&x, &y);
                    if descending { c.reverse() } else { c }
                }
            });
        }
        Ok(None) => {}
        Err(message) => return error(400, &message, Some("invalidValue")),
    }
    let total = stored.len();
    let start_index = query(request, "startIndex").filter(|v| !v.is_empty()).and_then(|v| v.trim().parse::<i32>().ok()).unwrap_or(1).max(1);
    let count = query(request, "count").filter(|v| !v.is_empty()).and_then(|v| v.trim().parse::<i32>().ok()).map(|c| c.max(0) as usize);
    let base = public_base_url(request);
    let page: Vec<Value> = stored
        .iter()
        .skip((start_index - 1) as usize)
        .take(count.unwrap_or(usize::MAX))
        .map(|r| Value::Object(shape(r, kind, &base, &provider.base_path, false)))
        .collect();
    reply(200, &list_response(page, total, i64::from(start_index)), Vec::new())
}

/// `String.compareToIgnoreCase`.
fn compare_ignore_case(a: &str, b: &str) -> std::cmp::Ordering {
    let fold = |c: char| c.to_uppercase().next().unwrap_or(c).to_lowercase().next().unwrap_or(c);
    a.chars().map(fold).cmp(b.chars().map(fold))
}

fn value_at(resource: &Map<String, Value>, path: &[String]) -> Option<String> {
    let mut node: Option<&Value> = None;
    let mut object = Some(resource);
    for segment in path {
        let o = object?;
        node = o.get(segment);
        object = node.and_then(Value::as_object);
    }
    match node? {
        Value::Null | Value::Object(_) | Value::Array(_) => None,
        v => crate::chaos::as_text(Some(v)),
    }
}

/// `ScimSort.parse`: the attribute path and whether descending.
fn sort(sort_by: Option<&str>, order: Option<&str>) -> Result<Option<(Vec<String>, bool)>, String> {
    let Some(attribute) = sort_by.map(str::trim).filter(|s| !s.is_empty()) else { return Ok(None) };
    let valid = attribute.split('.').all(|segment| {
        let mut chars = segment.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && chars.all(|c| c.is_alphanumeric() || c == '_' || c == '$' || c == '-')
    });
    if !valid {
        return Err(format!("invalid sortBy attribute path: {}", sort_by.unwrap_or_default()));
    }
    let descending = match order.map(str::trim).filter(|o| !o.is_empty()) {
        None => false,
        Some(o) if o.eq_ignore_ascii_case("descending") => true,
        Some(o) if o.eq_ignore_ascii_case("ascending") => false,
        Some(_) => return Err(format!("sortOrder must be 'ascending' or 'descending' but was: {}", order.unwrap_or_default())),
    };
    Ok(Some((attribute.split('.').map(str::to_string).collect(), descending)))
}

/// `ScimFilter`: `attr pr`, or `attr eq|co|sw "value"`.
struct Filter {
    attribute: String,
    operator: String,
    value: String,
}

impl Filter {
    fn parse(filter: &str) -> Result<Option<Filter>, String> {
        if filter.trim().is_empty() {
            return Ok(None);
        }
        static PRESENCE: std::sync::LazyLock<fancy_regex::Regex> = std::sync::LazyLock::new(|| fancy_regex::Regex::new(r"(?i)^\s*([A-Za-z][\w$.-]*)\s+pr\s*$").expect("regex"));
        static COMPARISON: std::sync::LazyLock<fancy_regex::Regex> =
            std::sync::LazyLock::new(|| fancy_regex::Regex::new(r#"(?i)^\s*([A-Za-z][\w$.-]*)\s+(eq|co|sw)\s+"((?:[^"\\]|\\.)*)"\s*$"#).expect("regex"));
        if let Ok(Some(c)) = PRESENCE.captures(filter) {
            return Ok(Some(Filter { attribute: c[1].to_string(), operator: "pr".into(), value: String::new() }));
        }
        if let Ok(Some(c)) = COMPARISON.captures(filter) {
            let value = c[3].replace("\\\"", "\"").replace("\\\\", "\\");
            return Ok(Some(Filter { attribute: c[1].to_string(), operator: c[2].to_lowercase(), value }));
        }
        Err(format!("unsupported or malformed SCIM filter: {filter}"))
    }

    fn matches(&self, resource: &Map<String, Value>) -> bool {
        let node = resource.get(&self.attribute);
        if self.operator == "pr" {
            return match node {
                None | Some(Value::Null) => false,
                Some(Value::String(s)) => !s.is_empty(),
                Some(_) => true,
            };
        }
        let Some(node) = node.filter(|n| !n.is_null()) else { return false };
        let actual = match node {
            Value::Object(_) | Value::Array(_) => String::new(),
            v => crate::chaos::as_text(Some(v)).unwrap_or_default(),
        };
        match self.operator.as_str() {
            "eq" => actual.to_lowercase() == self.value.to_lowercase(),
            "co" => actual.to_lowercase().contains(&self.value.to_lowercase()),
            "sw" => actual.to_lowercase().starts_with(&self.value.to_lowercase()),
            _ => false,
        }
    }
}

fn required_missing(payload: &Map<String, Value>, kind: Kind) -> bool {
    match payload.get(kind.required()) {
        None | Some(Value::Null) => true,
        Some(v) => crate::chaos::as_text(Some(v)).unwrap_or_default().is_empty(),
    }
}

fn create(request: &HttpRequest, provider: &Provider, kind: Kind) -> Value {
    let Some(mut payload) = parse_object(request) else { return error(400, "request body must be a JSON object", Some("invalidSyntax")) };
    if required_missing(&payload, kind) {
        return error(400, &format!("{} is required", kind.required()), Some("invalidValue"));
    }
    payload.shift_remove("id");
    let mut meta = match payload.get("meta") {
        Some(Value::Object(m)) => m.clone(),
        _ => Map::new(),
    };
    meta.insert("created".into(), now_text().into());
    payload.insert("meta".into(), Value::Object(meta));
    let Some(created) = store(provider, kind).create(payload) else { return error(500, "resource store is full", None) };
    let shaped = shape(&created, kind, &public_base_url(request), &provider.base_path, true);
    let location = shaped.get("meta").and_then(|m| m.get("location")).map(|l| crate::chaos::as_text(Some(l)).unwrap_or_default());
    reply(201, &Value::Object(shaped), location.map(|l| vec![("Location", l)]).unwrap_or_default())
}

/// `ScimResourceCallback.handle`.
fn resource(scim: &Scim, request: &HttpRequest) -> Value {
    let Some(provider) = scim.provider_for(&request.path) else { return error(404, "no SCIM provider registered for this path", None) };
    if let Some(unauthorized) = bearer_gate(request, &provider) {
        return unauthorized;
    }
    let kind = kind_of(request, &provider);
    let prefix = format!("{}/{}/", provider.base_path, kind.segment());
    let Some(id) = request.path.strip_prefix(&prefix).filter(|r| !r.is_empty() && !r.contains('/')).map(crate::chaos::url_decode) else {
        return error(404, "resource not found", None);
    };
    let store = store(&provider, kind);
    let base = public_base_url(request);
    let not_found = || error(404, &format!("{} {id} not found", kind.singular()), None);
    let shaped = |r: Map<String, Value>| reply(200, &Value::Object(shape(&r, kind, &base, &provider.base_path, false)), Vec::new());
    let failed = |(status, message, scim_type): (u32, String, Option<&'static str>)| error(status, &message, scim_type);
    match request.method.to_ascii_uppercase().as_str() {
        "GET" => store.get(&id).map_or_else(not_found, shaped),
        "PUT" => {
            let Some(mut payload) = parse_object(request) else { return error(400, "request body must be a JSON object", Some("invalidSyntax")) };
            if required_missing(&payload, kind) {
                return error(400, &format!("{} is required", kind.required()), Some("invalidValue"));
            }
            let result = store.update(&id, |existing| {
                if let Some(created) = existing.get("meta").and_then(Value::as_object).and_then(|m| m.get("created")) {
                    let mut meta = match payload.get("meta") {
                        Some(Value::Object(m)) => m.clone(),
                        _ => Map::new(),
                    };
                    meta.insert("created".into(), crate::chaos::as_text(Some(created)).unwrap_or_default().into());
                    payload.insert("meta".into(), Value::Object(meta));
                }
                Ok(payload)
            });
            match result {
                Ok(Some(updated)) => shaped(updated),
                Ok(None) => not_found(),
                Err(e) => failed(e),
            }
        }
        "PATCH" => {
            if !provider.enforce_patch {
                return error(501, "PATCH is not supported", None);
            }
            let Some(patch_op) = parse_object(request) else { return error(400, "request body must be a JSON object", Some("invalidSyntax")) };
            match store.update(&id, |existing| apply_patch(existing, &patch_op)) {
                Ok(Some(updated)) => shaped(updated),
                Ok(None) => not_found(),
                Err(e) => failed(e),
            }
        }
        "DELETE" => {
            if store.delete(&id) {
                json!({"statusCode": 204})
            } else {
                error(404, "resource not found", None)
            }
        }
        _ => error(405, "method not allowed", None),
    }
}

type PatchError = (u32, String, Option<&'static str>);

fn syntax(message: impl Into<String>) -> PatchError {
    (400, message.into(), Some("invalidSyntax"))
}

fn reserved(attribute: &str) -> bool {
    matches!(attribute, "id" | "meta" | "schemas")
}

/// `ScimPatchApplier.splitPath`.
fn split_path(path: &str) -> Result<Vec<String>, PatchError> {
    let segments = crate::java_text::split(path, ".");
    if segments.is_empty() || segments.len() > 2 {
        return Err(syntax(format!("unsupported PATCH path: {path}")));
    }
    if segments.iter().any(|s| s.is_empty()) {
        return Err(syntax(format!("malformed PATCH path: {path}")));
    }
    Ok(segments.into_iter().map(str::to_string).collect())
}

fn merge_into(target: &mut Map<String, Value>, source: &Map<String, Value>) {
    for (field, value) in source {
        if !reserved(field) {
            target.insert(field.clone(), value.clone());
        }
    }
}

fn set_at_path(resource: &mut Map<String, Value>, path: &str, value: &Value) -> Result<(), PatchError> {
    let segments = split_path(path)?;
    if reserved(&segments[0]) {
        return Ok(());
    }
    if segments.len() == 1 {
        resource.insert(segments[0].clone(), value.clone());
    } else {
        if !resource.get(&segments[0]).is_some_and(Value::is_object) {
            resource.insert(segments[0].clone(), Value::Object(Map::new()));
        }
        if let Some(Value::Object(parent)) = resource.get_mut(&segments[0]) {
            parent.insert(segments[1].clone(), value.clone());
        }
    }
    Ok(())
}

/// `ScimPatchApplier.apply`.
fn apply_patch(resource: &Map<String, Value>, patch_op: &Map<String, Value>) -> Result<Map<String, Value>, PatchError> {
    let Some(Value::Array(operations)) = patch_op.get("Operations") else { return Err(syntax("PatchOp must contain an Operations array")) };
    let mut result = resource.clone();
    for operation in operations {
        let Value::Object(operation) = operation else { return Err(syntax("each Operation must be an object")) };
        let Some(op) = operation.get("op").and_then(Value::as_str) else { return Err(syntax("each Operation must have an op")) };
        let op = op.to_lowercase();
        let path = operation.get("path").filter(|p| !p.is_null()).map(|p| crate::chaos::as_text(Some(p)).unwrap_or_default());
        let value = operation.get("value");
        match op.as_str() {
            "replace" | "add" => match path {
                None => match value {
                    Some(Value::Object(v)) => merge_into(&mut result, v),
                    _ => return Err(syntax(format!("{op} without a path requires an object value"))),
                },
                Some(path) => {
                    let Some(value) = value else { return Err(syntax(format!("{op} requires a value"))) };
                    if op == "add" {
                        let segments = split_path(&path)?;
                        if reserved(&segments[0]) {
                            continue;
                        }
                        if segments.len() == 1 && let Some(Value::Array(existing)) = result.get_mut(&segments[0]) {
                            match value {
                                Value::Array(items) => existing.extend(items.iter().cloned()),
                                v => existing.push(v.clone()),
                            }
                            continue;
                        }
                    }
                    set_at_path(&mut result, &path, value)?;
                }
            },
            "remove" => {
                let Some(path) = path else { return Err(syntax("remove requires a path")) };
                let segments = split_path(&path)?;
                if reserved(&segments[0]) {
                    continue;
                }
                if segments.len() == 1 {
                    result.shift_remove(&segments[0]);
                } else if let Some(Value::Object(parent)) = result.get_mut(&segments[0]) {
                    parent.shift_remove(&segments[1]);
                }
            }
            other => return Err(syntax(format!("unsupported op: {other}"))),
        }
    }
    Ok(result)
}

// ---------------------------------------------------------------------------------------------------------------
// `PUT /mockserver/scim` (`ScimProviderGenerator`)
// ---------------------------------------------------------------------------------------------------------------

/// `normalizeBasePath`.
fn normalize_base_path(base_path: Option<&str>) -> Result<String, String> {
    let raw = base_path.unwrap_or_default();
    let mut value = raw.trim().to_string();
    if value.is_empty() {
        value = "/scim/v2".into();
    }
    if !value.starts_with('/') {
        return Err(format!("SCIM basePath must start with '/': {raw}"));
    }
    if value.len() > 1 && value.ends_with('/') {
        value.pop();
    }
    if value == "/mockserver" || value.starts_with("/mockserver/") {
        return Err(format!("SCIM basePath must not overlap the /mockserver control plane: {raw}"));
    }
    Ok(value)
}

/// The expectations (input form) a provider configuration generates; the provider is registered. A failure is the
/// generator's `IllegalArgumentException` or the exception `ObjectMapper` throws binding the configuration.
pub fn generate(state: &State, body: &str) -> Result<Vec<Value>, Failure> {
    let config = if body.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        crate::chaos::read_tree(body, false).map_err(|e| crate::chaos::bind::parse_failure(body, &e))?
    };
    if config.is_null() {
        // Jackson reads a `null` body as a null configuration, which the generator rejects
        return Err("SCIM provider configuration is required".into());
    }
    let source = |e: crate::chaos::bind::BindError| e.failure(body);
    let bean = crate::chaos::bind::Bean::of(&config, "org.mockserver.scim.ScimProviderConfiguration").map_err(source)?;
    let base_path = normalize_base_path(bean.string("basePath").map_err(source)?.as_deref())?;
    let auto_increment = bean.enumeration("idStrategy", "org.mockserver.model.CrudExpectationsDefinition$IdStrategy", &["AUTO_INCREMENT", "UUID"]).map_err(source)? == Some(0);
    let objects = |name: &str| -> Result<Vec<Map<String, Value>>, Failure> {
        Ok(bean.object_list(name).map_err(source)?.unwrap_or_default().into_iter().cloned().collect())
    };
    let users = objects("initialUsers")?;
    let groups = objects("initialGroups")?;
    // primitive `boolean` fields
    let enforce_filter = bean.primitive_boolean("enforceFilter").map_err(source)?.unwrap_or(true);
    let enforce_patch = bean.primitive_boolean("enforcePatch").map_err(source)?.unwrap_or(true);
    let require_bearer = bean.primitive_boolean("requireBearerToken").map_err(source)?.unwrap_or(false);
    let expected_bearer = bean.string("expectedBearerToken").map_err(source)?;
    let provider = Provider {
        base_path: base_path.clone(),
        users: Store::new(auto_increment, &users),
        groups: Store::new(auto_increment, &groups),
        require_bearer,
        expected_bearer,
        enforce_filter,
        enforce_patch,
    };
    {
        let mut providers = state.scim.providers.lock();
        providers.retain(|p| p.base_path != base_path);
        providers.push(Arc::new(provider));
    }
    let id_prefix = format!("scim{}", base_path.replace('/', "."));
    let mut expectations = Vec::new();
    for kind in [Kind::User, Kind::Group] {
        let collection = format!("{base_path}/{}", kind.segment());
        for (method, suffix) in [("GET", "list"), ("POST", "create")] {
            expectations.push(json!({
                "id": format!("{id_prefix}.{}.{suffix}", kind.segment()),
                "httpRequest": {"method": method, "path": collection},
                "httpResponseClassCallback": {"callbackClass": COLLECTION_CALLBACK},
            }));
        }
        for method in ["GET", "PUT", "PATCH", "DELETE"] {
            expectations.push(json!({
                "id": format!("{id_prefix}.{}.{}", kind.segment(), method.to_lowercase()),
                "httpRequest": {"method": method, "path": format!("{collection}/{{id}}"), "pathParameters": {"id": [".*"]}},
                "httpResponseClassCallback": {"callbackClass": RESOURCE_CALLBACK},
            }));
        }
    }
    let discovery = |path: &str, id: &str, body: Value| {
        json!({
            "id": format!("{id_prefix}.{id}"),
            "httpRequest": {"method": "GET", "path": format!("{base_path}/{path}")},
            "httpResponse": {"statusCode": 200, "headers": {"content-type": [CONTENT_TYPE]}, "body": crate::json::pretty(&body)},
        })
    };
    expectations.push(discovery("ServiceProviderConfig", "serviceProviderConfig", service_provider_config(enforce_filter, enforce_patch)));
    let resource_type = |id: &str, endpoint: String, schema: &str| {
        json!({"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": id, "name": id, "endpoint": endpoint, "schema": schema})
    };
    let types = vec![resource_type("User", format!("{base_path}/Users"), USER_SCHEMA), resource_type("Group", format!("{base_path}/Groups"), GROUP_SCHEMA)];
    expectations.push(discovery("ResourceTypes", "resourceTypes", list_response(types, 2, 1)));
    let schemas = vec![schema(USER_SCHEMA, "User", "User Account", &["userName", "externalId"]), schema(GROUP_SCHEMA, "Group", "Group", &["displayName"])];
    expectations.push(discovery("Schemas", "schemas", list_response(schemas, 2, 1)));
    Ok(expectations)
}

fn service_provider_config(filter: bool, patch: bool) -> Value {
    json!({
        "schemas": [SERVICE_PROVIDER_CONFIG_SCHEMA],
        "documentationUri": "https://www.mock-server.com/mock_server/mocking_scim.html",
        "patch": {"supported": patch},
        "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": filter, "maxResults": MAX_ITEMS},
        "changePassword": {"supported": false},
        "sort": {"supported": true},
        "etag": {"supported": false},
        "authenticationSchemes": [{"type": "oauthbearertoken", "name": "OAuth Bearer Token", "description": "Authentication scheme using the OAuth Bearer Token Standard", "primary": true}],
    })
}

fn schema(id: &str, name: &str, description: &str, attributes: &[&str]) -> Value {
    let attributes: Vec<Value> = attributes
        .iter()
        .map(|a| {
            json!({"name": a, "type": "string", "multiValued": false, "required": *a == "userName" || *a == "displayName", "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"})
        })
        .collect();
    json!({"id": id, "name": name, "description": description, "attributes": attributes})
}

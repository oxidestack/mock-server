//! CRUD resources (`PUT /mockserver/crud`, `CrudDispatcher` / `CrudActionHandler` / `CrudDataStore` /
//! `CrudListQuery`): a registered base path serves list/create on itself and get/update/patch/delete on
//! `<basePath>/<id>`, from an in-memory store, ahead of expectation matching.

use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use serde_json::{Map, Value, json};

use crate::reply::Reply;
use crate::request::HttpRequest;

/// `CrudDataStore.DEFAULT_MAX_ITEMS`
const MAX_ITEMS: usize = 10_000;

#[derive(Default)]
pub struct Registry {
    handlers: RwLock<Vec<(String, Arc<Store>)>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IdStrategy {
    AutoIncrement,
    Uuid,
}

pub struct Store {
    id_field: String,
    id_strategy: IdStrategy,
    inner: Mutex<Items>,
}

#[derive(Default)]
struct Items {
    /// In insertion order.
    items: Vec<(String, Map<String, Value>)>,
    counter: i64,
}

impl Registry {
    /// `CrudDispatcher.register`: `Err` carries the validation message.
    pub fn register(&self, base_path: &str, store: Store) -> Result<(), String> {
        let normalized = normalize(base_path);
        validate(&normalized)?;
        let mut handlers = self.handlers.write();
        handlers.retain(|(p, _)| *p != normalized);
        handlers.push((normalized, Arc::new(store)));
        Ok(())
    }

    pub fn reset(&self) {
        self.handlers.write().clear();
    }

    /// `CrudDispatcher.dispatch`: the CRUD response, or `None` when no resource handles the request.
    pub fn dispatch(&self, request: &HttpRequest) -> Option<Reply> {
        let path = request.path.strip_suffix('/').unwrap_or(&request.path);
        let method = request.method.to_ascii_uppercase();
        let handlers = self.handlers.read().clone();
        for (base, store) in &handlers {
            if path == base {
                return match method.as_str() {
                    "GET" => Some(store.list(request)),
                    "POST" => Some(store.create(request)),
                    _ => None,
                };
            }
            if let Some(id) = path.strip_prefix(base.as_str()).and_then(|r| r.strip_prefix('/')).filter(|r| !r.contains('/')) {
                return match method.as_str() {
                    "GET" => Some(store.get(id)),
                    "PUT" => Some(store.update(id, request)),
                    "PATCH" => Some(store.patch(id, request)),
                    "DELETE" => Some(store.delete(id)),
                    _ => None,
                };
            }
        }
        None
    }
}

fn normalize(base_path: &str) -> String {
    base_path.strip_suffix('/').unwrap_or(base_path).to_string()
}

/// `CrudDispatcher.validateBasePath`
fn validate(base_path: &str) -> Result<(), String> {
    if base_path.is_empty() {
        return Err("basePath must not be empty".into());
    }
    if !base_path.starts_with('/') {
        return Err("basePath must start with /".into());
    }
    if base_path.contains("..") {
        return Err("basePath must not contain path traversal (..)".into());
    }
    let lower = base_path.to_lowercase();
    if lower == "/mockserver" || lower.starts_with("/mockserver/") {
        return Err("basePath must not overlap with the /mockserver control plane".into());
    }
    Ok(())
}

fn json_reply(status: u32, body: String) -> Reply {
    let mut reply = Reply::status(status);
    reply.headers.push(("content-type".into(), "application/json; charset=utf-8".into()));
    reply.body = body.into();
    reply
}

fn error(status: u32, message: &str) -> Reply {
    json_reply(status, json!({"error": message}).to_string())
}

/// `ObjectMapper.writeValueAsString`: compact, numbers as Jackson reads and prints them.
fn compact(v: &Value) -> String {
    serde_json::to_string(&crate::model::jackson_echo_tree(v)).unwrap_or_default()
}

/// `ObjectMapper.readTree` of a body that must be a JSON object; `Err` is the 400's message.
fn object_body(request: &HttpRequest) -> Result<Map<String, Value>, &'static str> {
    let body = request.body_str();
    if body.is_empty() {
        return Err("request body is required");
    }
    match crate::json::parse_lenient(body.as_bytes()) {
        Ok(Value::Object(o)) => Ok(o),
        _ => Err("invalid request body"),
    }
}

impl Store {
    pub fn new(id_field: String, id_strategy: IdStrategy, initial: &[Value]) -> Store {
        let mut items = Items::default();
        for item in initial.iter().filter_map(Value::as_object) {
            let Some(id) = extract_id(item, &id_field) else { continue };
            if id_strategy == IdStrategy::AutoIncrement && let Ok(n) = id.parse::<i64>() {
                items.counter = items.counter.max(n);
            }
            match items.items.iter_mut().find(|(k, _)| *k == id) {
                Some(existing) => existing.1 = item.clone(),
                None => items.items.push((id, item.clone())),
            }
        }
        Store { id_field, id_strategy, inner: Mutex::new(items) }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().items.len()
    }

    fn list(&self, request: &HttpRequest) -> Reply {
        let query = match ListQuery::parse(request) {
            Ok(q) => q,
            Err(message) => return error(400, &message),
        };
        let all: Vec<Map<String, Value>> = self.inner.lock().items.iter().map(|(_, v)| v.clone()).collect();
        let selected = query.filter_and_sort(all);
        let total = selected.len();
        let page = query.paginate(selected);
        let mut reply = json_reply(200, compact(&Value::Array(page.into_iter().map(Value::Object).collect())));
        if query.is_active() {
            reply.headers.push(("X-Total-Count".into(), total.to_string()));
            reply.headers.push(("X-Page".into(), query.page.to_string()));
            if let Some(size) = query.size {
                reply.headers.push(("X-Page-Size".into(), size.to_string()));
            }
        }
        reply
    }

    fn get(&self, id: &str) -> Reply {
        match self.inner.lock().items.iter().find(|(k, _)| k == id) {
            Some((_, item)) => json_reply(200, compact(&Value::Object(item.clone()))),
            None => error(404, "not found"),
        }
    }

    fn create(&self, request: &HttpRequest) -> Reply {
        let mut item = match object_body(request) {
            Ok(o) => o,
            Err(message) => return error(400, message),
        };
        let mut inner = self.inner.lock();
        if inner.items.len() >= MAX_ITEMS {
            return error(507, &format!("data store is full (max {MAX_ITEMS} items)"));
        }
        let id = match self.id_strategy {
            IdStrategy::AutoIncrement => {
                inner.counter += 1;
                item.insert(self.id_field.clone(), inner.counter.into());
                inner.counter.to_string()
            }
            IdStrategy::Uuid => {
                let id = uuid::Uuid::new_v4().to_string();
                item.insert(self.id_field.clone(), id.clone().into());
                id
            }
        };
        inner.items.push((id, item.clone()));
        json_reply(201, compact(&Value::Object(item)))
    }

    fn update(&self, id: &str, request: &HttpRequest) -> Reply {
        let mut item = match object_body(request) {
            Ok(o) => o,
            Err(message) => return error(400, message),
        };
        let mut inner = self.inner.lock();
        let Some(slot) = inner.items.iter_mut().find(|(k, _)| k == id) else { return error(404, "not found") };
        let id_value = match (self.id_strategy, id.parse::<i64>()) {
            (IdStrategy::AutoIncrement, Ok(n)) => Value::from(n),
            _ => Value::from(id),
        };
        item.insert(self.id_field.clone(), id_value);
        slot.1 = item.clone();
        json_reply(200, compact(&Value::Object(item)))
    }

    fn patch(&self, id: &str, request: &HttpRequest) -> Reply {
        let partial = match object_body(request) {
            Ok(o) => o,
            Err(message) => return error(400, message),
        };
        let mut inner = self.inner.lock();
        let Some(slot) = inner.items.iter_mut().find(|(k, _)| k == id) else { return error(404, "not found") };
        for (k, v) in partial {
            if k != self.id_field {
                slot.1.insert(k, v);
            }
        }
        json_reply(200, compact(&Value::Object(slot.1.clone())))
    }

    fn delete(&self, id: &str) -> Reply {
        let mut inner = self.inner.lock();
        let before = inner.items.len();
        inner.items.retain(|(k, _)| k != id);
        if inner.items.len() == before {
            return error(404, "not found");
        }
        // A 204 goes out without `Content-Length`.
        Reply { suppress_content_length: true, ..Reply::status(204) }
    }
}

/// `CrudDataStore.extractId`: a number's `asLong`, otherwise the value's text.
fn extract_id(item: &Map<String, Value>, id_field: &str) -> Option<String> {
    match item.get(id_field)? {
        Value::Number(n) => Some(n.as_i64().unwrap_or_else(|| n.as_f64().unwrap_or_default() as i64).to_string()),
        Value::String(s) => Some(s.clone()),
        Value::Null => Some("null".into()),
        other => Some(if other.is_boolean() { other.to_string() } else { String::new() }),
    }
}

/// `CrudListQuery`
struct ListQuery {
    filter: Option<(String, String)>,
    sort_by: Option<String>,
    descending: bool,
    page: i64,
    size: Option<i64>,
}

impl ListQuery {
    fn parse(request: &HttpRequest) -> Result<ListQuery, String> {
        let param = |name: &str| crate::request::first(&request.query, name).map(str::trim).filter(|v| !v.is_empty()).map(str::to_string);
        let (field, value) = (param("filterField"), param("filterValue"));
        if field.is_some() != value.is_some() {
            return Err("'filterField' and 'filterValue' must be supplied together".into());
        }
        let sort_by = param("sortBy");
        let sort_order = param("sortOrder");
        let descending = match sort_order.as_deref() {
            None => false,
            Some(o) if o.eq_ignore_ascii_case("descending") || o.eq_ignore_ascii_case("desc") => true,
            Some(o) if o.eq_ignore_ascii_case("ascending") || o.eq_ignore_ascii_case("asc") => false,
            Some(o) => return Err(format!("'sortOrder' must be 'ascending'/'asc' or 'descending'/'desc' but was: {o}")),
        };
        if sort_order.is_some() && sort_by.is_none() {
            return Err("'sortOrder' requires 'sortBy'".into());
        }
        let int = |name: &str| -> Result<i64, String> {
            match param(name) {
                None => Ok(0),
                Some(v) => v.parse::<i32>().map(i64::from).map_err(|_| format!("'{name}' must be an integer but was: {v}")),
            }
        };
        let page = int("page")?;
        if page < 0 {
            return Err(format!("'page' must not be negative but was: {page}"));
        }
        let size = if param("size").is_some() { Some(int("size")?).filter(|s| *s > 0) } else { None };
        Ok(ListQuery { filter: field.zip(value), sort_by, descending, page, size })
    }

    fn filter_and_sort(&self, mut items: Vec<Map<String, Value>>) -> Vec<Map<String, Value>> {
        if let Some((field, value)) = &self.filter {
            items.retain(|item| value_at(item, field).is_some_and(|v| v.to_lowercase() == value.to_lowercase()));
        }
        if let Some(sort_by) = &self.sort_by {
            items.sort_by(|a, b| match (value_at(a, sort_by), value_at(b, sort_by)) {
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (Some(_), None) => std::cmp::Ordering::Less,
                (Some(x), Some(y)) => {
                    let ordering = compare_ignore_case(&x, &y);
                    if self.descending { ordering.reverse() } else { ordering }
                }
            });
        }
        items
    }

    fn paginate(&self, items: Vec<Map<String, Value>>) -> Vec<Map<String, Value>> {
        let Some(size) = self.size else { return items };
        let from = ((self.page * size) as usize).min(items.len());
        let to = ((self.page * size + size) as usize).min(items.len());
        items[from..to].to_vec()
    }

    fn is_active(&self) -> bool {
        self.filter.is_some() || self.sort_by.is_some() || self.size.is_some() || self.page > 0
    }
}

/// `String.compareToIgnoreCase`: char by char, upper-cased then lower-cased.
fn compare_ignore_case(a: &str, b: &str) -> std::cmp::Ordering {
    let fold = |c: char| c.to_uppercase().next().unwrap_or(c).to_lowercase().next().unwrap_or(c);
    a.chars().map(fold).cmp(b.chars().map(fold))
}

/// `CrudListQuery.valueAt`: a dot-separated path to a scalar, as its text.
fn value_at(item: &Map<String, Value>, path: &str) -> Option<String> {
    let mut node: Option<&Value> = None;
    let mut current = item;
    let segments: Vec<&str> = path.split('.').collect();
    for (i, segment) in segments.iter().enumerate() {
        let next = current.get(*segment)?;
        if i + 1 < segments.len() {
            current = next.as_object()?;
        } else {
            node = Some(next);
        }
    }
    match node? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(crate::model::jackson_echo_tree(&Value::Number(n.clone())).to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

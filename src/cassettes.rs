//! `CassetteRegistry` and `/mockserver/cassettes`: metadata about cassette files, the expectation files that the MCP
//! tools `record_llm_fixtures` and `load_expectations_from_file` write and load. The registry keeps only the file's
//! path, name, expectation count, origin and last use, most recently used first, and `reset` empties it.

use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use crate::reply::Reply;
use crate::request::HttpRequest;

#[derive(Clone)]
struct Entry {
    path: String,
    filename: String,
    expectation_count: i64,
    origin: String,
    last_used: i64,
    /// Breaks ties between entries used in the same millisecond: the later one first.
    sequence: u64,
}

impl Entry {
    fn json(&self) -> Value {
        let mut o = Map::new();
        o.insert("path".into(), json!(self.path));
        o.insert("filename".into(), json!(self.filename));
        o.insert("expectationCount".into(), json!(self.expectation_count));
        o.insert("origin".into(), json!(self.origin));
        o.insert("lastUsed".into(), json!(self.last_used));
        Value::Object(o)
    }
}

#[derive(Default)]
pub struct Registry {
    entries: Mutex<(Vec<Entry>, u64)>,
}

impl Registry {
    /// `register`: an upsert by trimmed path; the file name defaults to the path's last segment, and the origin is
    /// `recorded` or else `loaded`.
    pub fn register(&self, path: &str, filename: Option<&str>, expectation_count: i64, origin: Option<&str>) -> Option<Value> {
        let path = path.trim();
        if path.is_empty() {
            return None;
        }
        let filename = filename.map(str::trim).filter(|f| !f.is_empty()).map(str::to_string).unwrap_or_else(|| path.rsplit(['/', '\\']).next().unwrap_or(path).to_string());
        let origin = if origin == Some("recorded") { "recorded" } else { "loaded" };
        let mut guard = self.entries.lock();
        guard.1 += 1;
        let entry = Entry { path: path.to_string(), filename, expectation_count, origin: origin.into(), last_used: crate::clock::now_millis(), sequence: guard.1 };
        guard.0.retain(|e| e.path != path);
        guard.0.push(entry.clone());
        Some(entry.json())
    }

    fn remove(&self, path: &str) -> bool {
        let path = path.trim();
        let mut guard = self.entries.lock();
        let before = guard.0.len();
        guard.0.retain(|e| e.path != path);
        guard.0.len() != before
    }

    fn list(&self) -> Vec<Value> {
        let mut entries = self.entries.lock().0.clone();
        entries.sort_by(|a, b| b.last_used.cmp(&a.last_used).then(b.sequence.cmp(&a.sequence)));
        entries.iter().map(Entry::json).collect()
    }

    pub fn reset(&self) {
        self.entries.lock().0.clear();
    }
}

fn error(message: &str) -> Reply {
    Reply::api_body(400, "application/json", json!({"error": message}).to_string())
}

fn pretty(status: u32, v: &Value) -> Reply {
    Reply::api_body(status, "application/json", crate::json::pretty(v))
}

/// `handleCassettesGet` / `Put` / `Delete`.
pub fn route(registry: &Registry, request: &HttpRequest) -> Option<Reply> {
    let body = request.body_json_or_xml_str();
    Some(match request.method.as_str() {
        "GET" => pretty(200, &json!({"cassettes": registry.list()})),
        "PUT" => {
            if body.trim().is_empty() {
                return Some(error("request body is required with a 'path' field"));
            }
            // MockServer's `ObjectMapper` reads leniently (`ObjectMapperFactory`).
            let lenient = jackson::json::ReadFeatures { allow_unquoted_field_names: true, allow_single_quotes: true, ..Default::default() };
            if let Err(e) = jackson::json::read_tree(&body, lenient) {
                return Some(error(&format!("failed to register cassette: {e}")));
            }
            let v: Value = crate::json::parse_lenient(body.as_bytes()).unwrap_or(Value::Null);
            let text = |k: &str| v.get(k).filter(|x| !x.is_null()).map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_string));
            let Some(path) = text("path").filter(|p| !p.trim().is_empty()) else { return Some(error("'path' field is required")) };
            // `asInt(-1)`: a number, or a numeric string; anything else is -1.
            let count = match v.get("expectationCount") {
                Some(Value::Number(n)) => n.as_f64().map_or(-1, |f| f as i64),
                Some(Value::String(s)) => s.trim().parse().unwrap_or(-1),
                _ => -1,
            };
            match registry.register(&path, text("filename").as_deref(), count, text("origin").as_deref()) {
                Some(entry) => pretty(201, &entry),
                None => error("'path' field is required"),
            }
        }
        "DELETE" => {
            let from_query = request.query.iter().find(|(k, _)| k == "path").and_then(|(_, v)| v.first()).cloned().filter(|p| !p.trim().is_empty());
            let from_body = || crate::json::parse_lenient(body.as_bytes()).ok().and_then(|v| v.get("path").and_then(Value::as_str).map(str::to_string)).filter(|p| !p.trim().is_empty());
            match from_query.or_else(from_body) {
                Some(path) => Reply::api_body(200, "application/json", json!({"removed": registry.remove(&path)}).to_string()),
                None => error("'path' is required (query parameter or body field)"),
            }
        }
        _ => return None,
    })
}

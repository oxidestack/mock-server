//! `retrieve` export formats (`HarConverter`, and later `ExpectationExportSerializer`): requests, request-response
//! pairs and expectations read into one neutral shape, each format written from it.

pub mod bruno;
pub mod har;
pub mod openapi;
pub mod postman;

use base64::Engine;
use serde_json::Value;

use crate::request::HttpRequest;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub const COLLECTION_NAME: &str = "MockServer Exported Expectations";
pub const COLLECTION_DESCRIPTION: &str =
    "Generated from MockServer's active expectations via the /mockserver/retrieve endpoint. Matcher semantics (NottableString.not, regex bodies, etc.) are not exported.";

/// An expectation as `ExpectationExportSerializer` reads it: its id, its HTTP request definition (`None` for any
/// other kind) and its `httpResponse` action, in JSON.
pub struct Expectation {
    pub id: String,
    pub request: Option<Value>,
    pub response: Option<Value>,
}

impl Expectation {
    /// `new Expectation(request)`: a synthetic expectation, with a fresh id.
    pub fn synthetic(request: Value, response: Option<Value>) -> Expectation {
        Expectation { id: uuid::Uuid::new_v4().to_string(), request: Some(request), response }
    }
}

/// `Body.getType()` of a body in JSON.
pub fn body_type(b: &Value) -> &'static str {
    match b {
        Value::String(_) => "STRING",
        Value::Object(o) => match o.get("type").and_then(Value::as_str) {
            Some("JSON") => "JSON",
            Some("XML") => "XML",
            Some("BINARY") => "BINARY",
            Some("PARAMETERS") => "PARAMETERS",
            Some("STRING") => "STRING",
            Some("REGEX") => "REGEX",
            Some("FUZZY") => "FUZZY",
            Some("JSON_SCHEMA") => "JSON_SCHEMA",
            Some("JSON_PATH") => "JSON_PATH",
            Some("XPATH") => "XPATH",
            Some("XML_SCHEMA") => "XML_SCHEMA",
            Some(_) => "OTHER",
            None if o.contains_key("json") && o.keys().all(|k| ["json", "contentType", "matchType", "not", "optional"].contains(&k.as_str())) => "JSON",
            None => "JSON",
        },
        _ => "JSON",
    }
}

/// `getBodyAsText()` (`BinaryBody.matchableString`) of a body in JSON, given its message's first `Content-Type`
/// header: a binary body with no content type of its own and no header is its bytes read as UTF-8; any other body
/// is its text, `getBodyAsString()` (a binary body's as base64).
pub fn body_text(b: &Value, content_type_header: Option<&str>) -> String {
    match json_body(b, None) {
        Some(body) if body.binary && body.content_type.is_none() && content_type_header.is_none_or(|h| h.trim().is_empty()) => {
            B64.decode(&body.text).map(|bytes| String::from_utf8_lossy(&bytes).into_owned()).unwrap_or_default()
        }
        Some(body) => body.text,
        None => String::new(),
    }
}

/// `Body.getContentType()` of a body in JSON. A JSON body that states `"contentType": null` (a modifier's bare
/// `JsonBody`) has none.
pub fn body_content_type(b: &Value) -> Option<String> {
    if b.get("type").and_then(Value::as_str) == Some("JSON") && b.get("contentType").is_some_and(Value::is_null) {
        return None;
    }
    json_body(b, None).and_then(|b| b.content_type)
}

/// The first value of the header `name` (case-insensitive) in a JSON multimap (map form or list form).
pub fn first_header_value(headers: Option<&Value>, name: &str) -> Option<String> {
    entries(headers).into_iter().find(|(k, _)| plain(k).is_some_and(|k| k.eq_ignore_ascii_case(name))).and_then(|(_, vs)| vs.first().and_then(plain))
}

/// `detectContentType`.
pub fn detect_content_type(body: &str) -> &'static str {
    let trimmed = body.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        "application/json"
    } else if trimmed.starts_with('<') {
        "application/xml"
    } else {
        "text/plain"
    }
}

/// A request as the export formats read it: a received request or an expectation's request definition.
#[derive(Default)]
pub struct Request {
    /// `None`: the definition names no method.
    pub method: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    /// `socketAddress` host and port.
    pub socket: Option<(Option<String>, Option<i64>)>,
    pub query: Vec<(String, Vec<String>)>,
    pub headers: Vec<(String, Vec<String>)>,
    pub cookies: Vec<(String, String)>,
    pub body: Option<Body>,
    pub protocol: Option<String>,
    pub remote_address: Option<String>,
    pub stream_id: Option<String>,
}

/// A response as the export formats read it.
#[derive(Default)]
pub struct Response {
    pub status: Option<i64>,
    pub reason: Option<String>,
    pub headers: Vec<(String, Vec<String>)>,
    pub cookies: Vec<(String, String)>,
    pub body: Option<Body>,
    /// The client's `timing`, for a forwarded response.
    pub timing: Option<Value>,
}

/// A body: `getContentType()`, `toString()` (base64 for a binary body) and `getRawBytes()`'s length.
pub struct Body {
    pub content_type: Option<String>,
    pub text: String,
    pub binary: bool,
    pub raw_len: usize,
    /// A `PARAMETERS` body's name-values.
    pub parameters: Option<Vec<(String, Vec<String>)>>,
}

impl Body {
    /// A JSON body keeps its original text in the model: take it, and its UTF-8 length, from the body in input form
    /// (`{"type": "JSON", "json": "<text>"}`, as `recorded::input_body` writes it), leaving the content type as it is
    /// unless the input form marks it absent (`"contentType": null`, a patched body without one).
    pub fn with_raw_json(mut self, input: Option<&Value>) -> Body {
        if input.filter(|b| b.get("type").and_then(Value::as_str) == Some("JSON")).and_then(|b| b.get("contentType")).is_some_and(Value::is_null) {
            self.content_type = None;
        }
        let raw = input.filter(|b| b.get("type").and_then(Value::as_str) == Some("JSON")).and_then(|b| b.get("json")).and_then(Value::as_str);
        if let (Some(raw), false) = (raw, self.binary || self.parameters.is_some()) {
            self.raw_len = if has_charset(self.content_type.as_deref()) { crate::canonical::encode(raw, self.content_type.as_deref()).len() } else { raw.len() };
            self.text = raw.to_string();
        }
        self
    }
}

/// A request-response pair (`LogEventRequestAndResponse`), with its log timestamp when it was recorded.
pub struct Pair {
    pub request: Option<Request>,
    pub response: Option<Response>,
    pub timestamp: Option<String>,
}

impl Request {
    /// A received request: headers, query and cookies in the order they arrived.
    pub fn received(request: &HttpRequest) -> Request {
        let content_type = request.first_header("content-type");
        let body = received_body(&request.body, content_type);
        Request {
            method: Some(request.method.clone()),
            path: Some(request.path.clone()),
            secure: request.secure,
            socket: request.socket_address.as_ref().map(|(h, p, _)| (Some(h.clone()), Some(i64::from(*p)))),
            query: request.query.clone(),
            headers: request.headers.clone(),
            cookies: request.cookies.clone(),
            body,
            protocol: Some(request.protocol.to_string()),
            remote_address: Some(request.remote_address.clone()).filter(|a| !a.is_empty()),
            stream_id: None,
        }
    }

    /// A request definition in JSON (an expectation's `httpRequest`, input or canonical form).
    pub fn definition(v: &Value) -> Request {
        let socket = v.get("socketAddress").map(|s| (s.get("host").and_then(Value::as_str).map(str::to_string), s.get("port").and_then(Value::as_i64)));
        Request {
            method: v.get("method").and_then(string_value).filter(|m| !m.is_empty()),
            path: v.get("path").and_then(string_value),
            secure: v.get("secure").and_then(Value::as_bool).unwrap_or(false),
            socket,
            query: multimap(v.get("queryStringParameters")),
            headers: multimap(v.get("headers")),
            cookies: pairs(v.get("cookies")),
            body: v.get("body").and_then(|b| json_body(b, None)),
            protocol: v.get("protocol").and_then(Value::as_str).map(str::to_string),
            remote_address: v.get("remoteAddress").and_then(Value::as_str).map(str::to_string),
            stream_id: v.get("streamId").map(|s| s.as_str().map_or_else(|| s.to_string(), str::to_string)),
        }
    }

    pub fn first_header(&self, name: &str) -> Option<&str> {
        first(&self.headers, name)
    }
}

impl Response {
    /// A response in JSON (an expectation's `httpResponse`, or a recorded one).
    pub fn json(v: &Value) -> Response {
        Response {
            status: v.get("statusCode").and_then(Value::as_i64),
            reason: v.get("reasonPhrase").and_then(Value::as_str).map(str::to_string),
            headers: multimap(v.get("headers")),
            cookies: pairs(v.get("cookies")),
            body: v.get("body").and_then(|b| json_body(b, None)),
            timing: v.get("timing").cloned(),
        }
    }

    pub fn first_header(&self, name: &str) -> Option<&str> {
        first(&self.headers, name)
    }
}

/// `URLEncoder.encode(value, UTF_8)`.
pub fn url_encode(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn first<'a>(headers: &'a [(String, Vec<String>)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).and_then(|(_, vs)| vs.first()).map(String::as_str)
}

/// A matcher value as its plain string: a string, or a `NottableString`'s `value`.
fn string_value(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => o.get("value").and_then(Value::as_str).map(str::to_string),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// A multimap in map form (`{"name": ["value"]}`) or list form (`[{"name", "values"}]`).
fn multimap(v: Option<&Value>) -> Vec<(String, Vec<String>)> {
    let values = |vs: Option<&Value>| -> Vec<String> {
        match vs {
            Some(Value::Array(items)) => items.iter().filter_map(string_value).collect(),
            Some(other) => string_value(other).into_iter().collect(),
            None => Vec::new(),
        }
    };
    match v {
        Some(Value::Object(o)) => o.iter().map(|(k, vs)| (k.clone(), values(Some(vs)))).collect(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|i| Some((i.get("name").and_then(string_value)?, values(i.get("values").or_else(|| i.get("value"))))))
            .collect(),
        _ => Vec::new(),
    }
}

/// Cookies in map form (`{"name": "value"}`) or list form (`[{"name", "value"}]`).
fn pairs(v: Option<&Value>) -> Vec<(String, String)> {
    match v {
        Some(Value::Object(o)) => o.iter().filter_map(|(k, v)| Some((k.clone(), string_value(v)?))).collect(),
        Some(Value::Array(items)) => items.iter().filter_map(|i| Some((i.get("name").and_then(string_value)?, i.get("value").and_then(string_value)?))).collect(),
        _ => Vec::new(),
    }
}

/// A received body as the request decoder types it (`BodyDecoderEncoder`): binary media types and undecodable bytes
/// make a binary body; the content type is the request's header.
fn received_body(body: &[u8], content_type: Option<&str>) -> Option<Body> {
    let typed = crate::recorded::body_json(body, content_type, crate::recorded::BodyForm::Recorded)?;
    let binary = typed.get("type").and_then(Value::as_str) == Some("BINARY");
    let text = if binary {
        B64.encode(body)
    } else {
        match typed.get("type").and_then(Value::as_str) {
            Some("STRING") => typed.get("string").and_then(Value::as_str).unwrap_or_default().to_string(),
            Some("XML") => typed.get("xml").and_then(Value::as_str).unwrap_or_default().to_string(),
            _ => String::from_utf8_lossy(body).into_owned(),
        }
    };
    Some(Body { content_type: content_type.map(str::to_string), text, binary, raw_len: body.len(), parameters: None })
}

/// Whether a content type names a charset.
fn has_charset(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|ct| ct.split(';').any(|p| p.trim().to_ascii_lowercase().starts_with("charset=")))
}

/// A body in JSON (the body serialisers' forms). `default_type` overrides a typed body's own default content type.
fn json_body(b: &Value, default_type: Option<&str>) -> Option<Body> {
    // A string body's `getRawBytes()`: the text in the content type's charset, else ISO-8859-1 (one byte per char). A
    // JSON body's bytes are UTF-8 unless its content type names a charset.
    let string = |text: String, content_type: Option<String>| {
        let json = content_type.as_deref().is_some_and(|ct| ct.to_ascii_lowercase().contains("json"));
        let raw_len = if has_charset(content_type.as_deref()) {
            crate::canonical::encode(&text, content_type.as_deref()).len()
        } else if json {
            text.len()
        } else {
            crate::canonical::encode(&text, Some("text/plain; charset=iso-8859-1")).len()
        };
        Some(Body { content_type, text, binary: false, raw_len, parameters: None })
    };
    let o = match b {
        Value::String(s) => return string(s.clone(), None),
        Value::Object(o) => o,
        Value::Null => return None,
        other => return string(crate::json::pretty(other), Some("application/json; charset=utf-8".into())),
    };
    let content_type = o.get("contentType").and_then(Value::as_str).map(str::to_string);
    // A body without its `type` is typed by the field it carries.
    // A body without its `type`: the input's `{"json": …}` shorthand, else a JSON body written as its bare value.
    let kind = match o.get("type").and_then(Value::as_str) {
        Some(kind) => Some(kind),
        None if o.contains_key("json") && o.keys().all(|k| ["json", "contentType", "matchType", "not", "optional"].contains(&k.as_str())) => Some("JSON"),
        None => return string(crate::json::pretty(b), Some(default_type.unwrap_or("application/json; charset=utf-8").to_string())),
    };
    let typed_default = |default: &str| content_type.clone().or_else(|| Some(default_type.unwrap_or(default).to_string()));
    match kind {
        Some("JSON") => {
            let text = match o.get("json") {
                Some(Value::String(s)) => s.clone(),
                Some(v) => crate::json::pretty(v),
                None => String::new(),
            };
            string(text, typed_default("application/json; charset=utf-8"))
        }
        Some("XML") => string(o.get("xml").and_then(Value::as_str).unwrap_or_default().to_string(), typed_default("application/xml; charset=utf-8")),
        Some("BINARY") => {
            let encoded = o.get("base64Bytes").and_then(Value::as_str).unwrap_or_default().to_string();
            let raw_len = B64.decode(&encoded).map(|b| b.len()).unwrap_or(0);
            Some(Body { content_type, text: encoded, binary: true, raw_len, parameters: None })
        }
        Some("PARAMETERS") => {
            let parameters = multimap(o.get("parameters"));
            let text = parameters
                .iter()
                .flat_map(|(k, vs)| vs.iter().map(move |v| format!("{}={}", url_encode(k), url_encode(v))))
                .collect::<Vec<_>>()
                .join("&");
            let raw_len = text.len();
            Some(Body { content_type: typed_default("application/x-www-form-urlencoded"), text, binary: false, raw_len, parameters: Some(parameters) })
        }
        Some("STRING") | None => string(o.get("string").and_then(Value::as_str).unwrap_or_default().to_string(), content_type),
        Some(_) => {
            let text = ["regex", "value", "jsonSchema", "jsonPath", "xpath", "xmlSchema", "json", "xml"]
                .iter()
                .find_map(|k| o.get(*k).map(|v| v.as_str().map_or_else(|| crate::json::pretty(v), str::to_string)))
                .unwrap_or_default();
            string(text, content_type)
        }
    }
}

/// A multimap's entries, names and values as their JSON (map form or list form).
pub fn entries(v: Option<&Value>) -> Vec<(Value, Vec<Value>)> {
    let values = |vs: Option<&Value>| match vs {
        Some(Value::Array(items)) => items.clone(),
        Some(other) => vec![other.clone()],
        None => Vec::new(),
    };
    match v {
        Some(Value::Object(o)) => o.iter().map(|(k, vs)| (Value::String(k.clone()), values(Some(vs)))).collect(),
        Some(Value::Array(items)) => items.iter().filter_map(|i| Some((i.get("name")?.clone(), values(i.get("values").or_else(|| i.get("value")))))).collect(),
        _ => Vec::new(),
    }
}

/// A `NottableString`'s value.
pub fn plain(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.strip_prefix('!').unwrap_or(s).to_string()),
        Value::Object(o) => o.get("value").and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

/// `isNegatedOrSchema`: `{"not": true}`, the `!` shorthand, or a schema matcher.
pub fn negated_or_schema(v: &Value) -> bool {
    match v {
        Value::String(s) => s.starts_with('!'),
        Value::Object(o) => o.get("not").and_then(Value::as_bool).unwrap_or(false) || o.contains_key("schema"),
        _ => false,
    }
}

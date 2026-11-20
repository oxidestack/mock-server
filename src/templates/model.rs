//! `HttpRequestTemplateObject` and `HttpResponseTemplateObject`: the `request` / `response` a template sees, as Java
//! objects with the same getters, map flavours and `toString()` (bean JSON).

use std::cell::RefCell;
use std::sync::{Arc, OnceLock};

use java_compat::lang::{JError, JList, JMap, JObject, JValue, ListKind, MapKind};
use serde_json::{Map, Value};

use crate::media_type::DecodedBody;
use crate::recorded::{Level, LogEntry};
use crate::request::HttpRequest;

type Invocation = Option<Result<Option<JValue>, JError>>;

fn ok(v: JValue) -> Invocation {
    Some(Ok(Some(v)))
}

fn opt_str(v: &Option<String>) -> JValue {
    v.as_ref().map(|s| JValue::str(s.as_str())).unwrap_or(JValue::Null)
}

fn opt_bool(v: Option<bool>) -> JValue {
    v.map(JValue::Bool).unwrap_or(JValue::Null)
}

/// A `Map<String, List<String>>` of the given flavour.
fn multi_map(kind: MapKind, entries: &[(String, Vec<String>)]) -> JMap {
    let map = JMap::new(kind);
    for (k, vs) in entries {
        let values = JValue::string_list(vs.iter().map(String::as_str));
        match (kind, map.get_str(k)) {
            // `CaseInsensitiveHeaderMap.put`: a differently-cased name merges into the first-seen entry.
            (MapKind::CaseInsensitive, Some(JValue::List(existing))) => {
                let merged = JList::array_list(existing.items().into_iter().chain(vs.iter().map(|v| JValue::str(v.as_str()))).collect());
                map.put(JValue::str(k.as_str()), JValue::List(merged));
            }
            _ => {
                map.put(JValue::str(k.as_str()), values);
            }
        }
    }
    map
}

/// `String.equalsIgnoreCase`: same length in UTF-16 units, each character pair equal after upper-casing, or after
/// upper- then lower-casing.
fn equals_ignore_case(a: &str, b: &str) -> bool {
    let fold = |c: char, f: fn(char) -> Option<char>| f(c).unwrap_or(c);
    let upper = |c: char| {
        let mut u = c.to_uppercase();
        if u.len() == 1 { u.next() } else { None }
    };
    let lower = |c: char| {
        let mut l = c.to_lowercase();
        if l.len() == 1 { l.next() } else { None }
    };
    a.encode_utf16().count() == b.encode_utf16().count()
        && a.chars().zip(b.chars()).all(|(x, y)| {
            if x == y {
                return true;
            }
            let (ux, uy) = (fold(x, upper), fold(y, upper));
            ux == uy || fold(ux, lower) == fold(uy, lower)
        })
}

/// `org.mockserver.templates.engine.model.CaseInsensitiveHeaderMap`, the request header map Velocity sees: a
/// `LinkedHashMap<String, List<String>>` with exact keys whose `put`, `get`, `containsKey`, `getOrDefault` and
/// `remove` try the exact key first and then the first key equal ignoring case; `put` under another casing merges
/// the values into that first-seen entry. Every other method is `HashMap`'s own, on the exact key (`putIfAbsent`,
/// `putAll`, `merge` and `compute*` bypass the overrides, as upstream's javadoc notes).
pub struct HeaderMap {
    map: JMap,
}

impl HeaderMap {
    fn new(entries: &[(String, Vec<String>)]) -> HeaderMap {
        let headers = HeaderMap { map: JMap::new(MapKind::Linked) };
        for (k, vs) in entries {
            headers.put(JValue::str(k.as_str()), JValue::string_list(vs.iter().map(String::as_str)));
        }
        headers
    }

    /// `canonicalKeyFor`: the stored key equal to `key` ignoring case, for a `String` key.
    fn canonical_key(&self, key: &JValue) -> Option<JValue> {
        let wanted = key.as_str()?;
        self.map.entries().into_iter().map(|(k, _)| k).find(|k| k.as_str().is_some_and(|k| equals_ignore_case(k, wanted)))
    }

    fn put(&self, key: JValue, value: JValue) -> JValue {
        if self.map.contains_key(&key) {
            return self.map.put(key, value);
        }
        let Some(canonical) = self.canonical_key(&key) else { return self.map.put(key, value) };
        let mut merged = match self.map.get(&canonical) {
            Some(JValue::List(existing)) => existing.items(),
            _ => Vec::new(),
        };
        if let JValue::List(added) = &value {
            merged.extend(added.items());
        }
        self.map.put(canonical, JValue::List(JList::array_list(merged)))
    }

    fn get(&self, key: &JValue) -> JValue {
        if self.map.contains_key(key) {
            return self.map.get(key).unwrap_or(JValue::Null);
        }
        self.canonical_key(key).and_then(|k| self.map.get(&k)).unwrap_or(JValue::Null)
    }

    fn contains_key(&self, key: &JValue) -> bool {
        self.map.contains_key(key) || self.canonical_key(key).is_some()
    }

    fn remove(&self, key: &JValue) -> JValue {
        if self.map.contains_key(key) {
            return self.map.remove(key);
        }
        self.canonical_key(key).map(|k| self.map.remove(&k)).unwrap_or(JValue::Null)
    }
}

/// The bridge method's cast of an argument to `String` or `List`: `null` passes, anything else throws.
fn cast(v: &JValue, class: &str) -> Result<(), JError> {
    let fits = match v {
        JValue::Null => true,
        JValue::Str(_) => class == "java.lang.String",
        JValue::List(l) => class == "java.util.List" && matches!(l.kind(), ListKind::ArrayList | ListKind::Fixed | ListKind::JsonArray),
        _ => false,
    };
    if fits {
        return Ok(());
    }
    let from = v.class_name();
    let module = |c: &str| if c.starts_with("java.") { "module java.base of loader 'bootstrap'".to_string() } else { "unnamed module of loader 'app'".to_string() };
    let detail = if module(&from) == module(class) { format!("{from} and {class} are in {}", module(class)) } else { format!("{from} is in {}; {class} is in {}", module(&from), module(class)) };
    Err(JError::new("java.lang.ClassCastException", format!("class {from} cannot be cast to class {class} ({detail})")))
}

impl JObject for HeaderMap {
    fn class_name(&self) -> String {
        "org.mockserver.templates.engine.model.CaseInsensitiveHeaderMap".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        match (name, args) {
            ("put", [k, v]) => Some(cast(k, "java.lang.String").and_then(|_| cast(v, "java.util.List")).map(|_| Some(self.put(k.clone(), v.clone())))),
            ("get", [k]) => ok(self.get(k)),
            ("containsKey", [k]) => ok(JValue::Bool(self.contains_key(k))),
            ("getOrDefault", [k, d]) => Some(cast(d, "java.util.List").map(|_| Some(if self.contains_key(k) { self.get(k) } else { d.clone() }))),
            ("remove", [k]) => ok(self.remove(k)),
            // `AbstractMap.equals`: any map with the same entries.
            ("equals", [JValue::Object(o)]) => ok(JValue::Bool(
                o.as_any().downcast_ref::<HeaderMap>().is_some_and(|other| java_compat::lang::java_equals(&JValue::Map(self.map.clone()), &JValue::Map(other.map.clone()))),
            )),
            _ => java_compat::methods::invoke(&JValue::Map(self.map.clone()), name, args),
        }
    }

    fn to_java_string(&self) -> String {
        JValue::Map(self.map.clone()).to_java_string()
    }

    /// `#foreach` over a map walks its values.
    fn iterate(&self) -> Option<Vec<JValue>> {
        Some(self.map.entries().into_iter().map(|(_, v)| v).collect())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// The JSON of a Java value as Jackson writes a bean property (maps, lists, strings, booleans, numbers).
fn to_json(v: &JValue) -> Value {
    match v {
        JValue::Null => Value::Null,
        JValue::Bool(b) => Value::Bool(*b),
        JValue::Int(i) => Value::from(*i),
        JValue::Long(l) => Value::from(*l),
        JValue::Str(s) => Value::String(s.to_string()),
        JValue::List(l) => Value::Array(l.items().iter().map(to_json).collect()),
        JValue::Object(o) if o.class_name() == "org.mockserver.model.X509Certificate" => {
            o.as_any().downcast_ref::<CertificateObject>().map(|c| c.model.clone()).unwrap_or(Value::Null)
        }
        JValue::Map(m) => Value::Object(m.entries().iter().map(|(k, v)| (k.to_java_string(), to_json(v))).collect()),
        other => Value::String(other.to_java_string()),
    }
}

/// Jackson's `NON_EMPTY` inclusion: null, empty strings, maps and lists are left out.
fn non_empty(v: &JValue) -> bool {
    match v {
        JValue::Null => false,
        JValue::Str(s) => !s.is_empty(),
        JValue::List(l) => !l.is_empty(),
        JValue::Map(m) => !m.is_empty(),
        _ => true,
    }
}

/// `org.mockserver.templates.engine.model.HttpRequestTemplateObject`.
pub struct RequestObject {
    method: String,
    path: String,
    path_parameters: JMap,
    path_groups: JList,
    named_path_groups: JMap,
    query: JMap,
    headers: JMap,
    /// What `getHeaders()` returns: `headers` itself, or the [`HeaderMap`] over it.
    headers_value: JValue,
    cookies: JMap,
    body: String,
    secure: Option<bool>,
    local_address: Option<String>,
    remote_address: Option<String>,
    keep_alive: Option<bool>,
    json_rpc_id: Option<String>,
    json_rpc_raw_id: Option<String>,
    json_rpc_method: Option<String>,
    /// `clientCertificateChain`: a list of [`CertificateObject`], `null` when the client sent none.
    client_certificate_chain: JValue,
    /// `getId()`: the log correlation id.
    id: Option<String>,
    /// The derived fields 9.2.0 added (`@JsonIgnore`, so `toString()` leaves them out).
    derived: Derived,
}

/// `HttpRequestTemplateObject`'s derived fields: `host`, `port`, `baseUrl` from the `Host` header (else the local
/// address), and `bodyAsBase64`, `formData` and `parts` from the raw body, decoded when first read.
struct Derived {
    host: Option<String>,
    port: Option<i32>,
    host_header: Option<String>,
    body: bytes::Bytes,
    content_type: Option<String>,
    form_data: OnceLock<JMap>,
    parts: OnceLock<JMap>,
}

/// `HttpRequest.splitHostPort`: a bracketed IPv6 host and its port, else `String.split(":")` (trailing empty parts
/// dropped).
fn split_host_port(host_port: &str) -> Vec<String> {
    if let Some(rest) = host_port.strip_prefix('[') && let Some(end) = rest.find(']') {
        let host = rest[..end].to_string();
        return match host_port[end + 1..].find(':') {
            Some(colon) => vec![host, host_port[end + 1 + colon + 1..].to_string()],
            None => vec![host],
        };
    }
    let mut parts: Vec<String> = host_port.split(':').map(str::to_string).collect();
    while parts.len() > 1 && parts.last().is_some_and(String::is_empty) {
        parts.pop();
    }
    if parts.len() == 1 && parts[0].is_empty() && !host_port.is_empty() {
        parts.clear();
    }
    parts
}

/// `splitHostAndPort`: `[host]` or `[host, port]`; an unbracketed IPv6 address (or an empty host) is all host.
fn host_and_port(host_port: &str) -> Option<Vec<String>> {
    if host_port.is_empty() {
        return None;
    }
    let parts = split_host_port(host_port);
    if parts.is_empty() || parts.len() > 2 || parts[0].is_empty() {
        return Some(vec![host_port.to_string()]);
    }
    Some(parts)
}

/// `parsePort`: `Integer.parseInt` of the trimmed text, kept only in 0-65535.
fn parse_port(port: &str) -> Option<i32> {
    let port = port.trim_matches(|c: char| c <= ' ');
    let digits = port.strip_prefix(['+', '-']).unwrap_or(port);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port.parse::<i32>().ok().filter(|p| (0..=65535).contains(p))
}

impl Derived {
    fn new(request: &HttpRequest) -> Derived {
        let host_header = request.headers.iter().find(|(k, _)| equals_ignore_case(k, "host")).and_then(|(_, vs)| vs.first().cloned());
        let (mut host, mut port) = (None, None);
        match host_header.as_deref().map(|h| h.trim_matches(|c: char| c <= ' ')).filter(|h| !h.is_empty()).and_then(host_and_port) {
            Some(parts) => {
                host = Some(parts[0].clone());
                port = match parts.get(1) {
                    Some(p) => parse_port(p),
                    None => Some(if request.secure { 443 } else { 80 }),
                };
            }
            None => {
                let local = request.local_address.as_str();
                let address = local[local.rfind('/').map_or(0, |i| i + 1)..].trim();
                if let Some(parts) = host_and_port(address) {
                    host = Some(parts[0].clone());
                    port = parts.get(1).and_then(|p| parse_port(p));
                }
            }
        }
        Derived {
            host,
            port,
            host_header: host_header.filter(|h| !h.trim().is_empty()),
            body: request.body.clone(),
            content_type: request.first_header("content-type").map(str::to_string),
            form_data: OnceLock::new(),
            parts: OnceLock::new(),
        }
    }

    fn base_url(&self, scheme: &str) -> Option<String> {
        if let Some(header) = &self.host_header {
            return Some(format!("{scheme}://{}", header.trim_matches(|c: char| c <= ' ')));
        }
        let host = self.host.as_ref()?;
        let host = if host.contains(':') { format!("[{host}]") } else { host.clone() };
        Some(format!("{scheme}://{host}{}", self.port.map(|p| format!(":{p}")).unwrap_or_default()))
    }

    /// `bodyBytesWithinCap`: the body when it is within [`MAX_PARSED_BODY_BYTES`] and not empty; an oversized body
    /// warns with `oversize`.
    fn body_within_cap(&self, oversize: &str) -> Option<&[u8]> {
        if self.body.len() > MAX_PARSED_BODY_BYTES {
            warn(LogEntry::at(Level::Warn, oversize).args([MAX_PARSED_BODY_BYTES.to_string()]));
            return None;
        }
        Some(self.body.as_ref()).filter(|b| !b.is_empty())
    }

    /// `decodeFormData`: an `application/x-www-form-urlencoded` body as Netty's `QueryStringDecoder` reads it.
    fn form_data(&self) -> JMap {
        let map = JMap::new(MapKind::Linked);
        let media = crate::media_type::MediaType::parse(self.content_type.as_deref());
        if !media.is("application", "x-www-form-urlencoded") {
            return map;
        }
        let Some(bytes) = self.body_within_cap("request.formData is empty because the request body is larger than{}bytes, the most a template decodes") else { return map };
        let charset = media.charset().unwrap_or("utf-8").to_string();
        let form = crate::media_type::decode(bytes, Some(&charset));
        if form.matches('&').count() >= MAX_FORM_FIELDS {
            warn(LogEntry::at(Level::Warn, "request.formData read only the first{}fields of the request body").args([MAX_FORM_FIELDS.to_string()]));
        }
        let mut fields: Vec<(String, Vec<String>)> = Vec::new();
        for pair in form.split('&').take(MAX_FORM_FIELDS) {
            if pair.is_empty() {
                continue;
            }
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            if name.is_empty() {
                continue;
            }
            let (Some(name), Some(value)) = (decode_component(name, &charset), decode_component(value, &charset)) else { return JMap::new(MapKind::Linked) };
            match fields.iter_mut().find(|(k, _)| *k == name) {
                Some((_, values)) => values.push(value),
                None => fields.push((name, vec![value])),
            }
        }
        for (name, values) in fields {
            map.put(JValue::str(name), JValue::List(JList::array_list(values.into_iter().map(JValue::str).collect())));
        }
        map
    }

    /// `decodeParts`: a `multipart/form-data` body's parts by name, in body order.
    fn parts(&self) -> JMap {
        let map = JMap::new(MapKind::Linked);
        let media = crate::media_type::MediaType::parse(self.content_type.as_deref());
        if !media.is("multipart", "form-data") {
            return map;
        }
        let Some(bytes) = self.body_within_cap("request.parts is empty because the request body is larger than{}bytes, the most a template decodes") else { return map };
        let Some(parts) = crate::matcher::multipart_parts(self.content_type.as_deref(), bytes) else { return map };
        if parts.len() > MAX_MULTIPART_PARTS {
            warn(LogEntry::at(Level::Warn, "request.parts is empty because the request body has more than{}parts").args([MAX_MULTIPART_PARTS.to_string()]));
            return map;
        }
        for part in parts {
            let key = JValue::str(part.name.as_str());
            let list = match map.get(&key) {
                Some(JValue::List(list)) => list,
                _ => {
                    let list = JList::array_list(Vec::new());
                    map.put(key, JValue::List(list.clone()));
                    list
                }
            };
            list.push(JValue::Object(Arc::new(PartObject::new(part))));
        }
        map
    }
}

thread_local! {
    /// The WARN entries the request objects of the render in progress on this thread logged, while [`collect_warnings`]
    /// runs it.
    static WARNINGS: RefCell<Option<Vec<LogEntry>>> = const { RefCell::new(None) };
}

/// `HttpRequestTemplateObject.warn`: a WARN entry when a size cap stops `formData` or `parts` reading the whole body.
/// Outside [`collect_warnings`] (no logger) it is dropped.
fn warn(entry: LogEntry) {
    WARNINGS.with(|w| {
        if let Some(list) = w.borrow_mut().as_mut() {
            list.push(entry);
        }
    });
}

/// Runs `render`, returning the WARN entries its request objects logged, in order; the caller logs them about the
/// request (`setHttpRequest(source)`), or a dry run reports them as warnings.
pub fn collect_warnings<T>(render: impl FnOnce() -> T) -> (T, Vec<LogEntry>) {
    let outer = WARNINGS.with(|w| w.borrow_mut().replace(Vec::new()));
    let out = render();
    let warnings = WARNINGS.with(|w| std::mem::replace(&mut *w.borrow_mut(), outer)).unwrap_or_default();
    (out, warnings)
}

/// `HttpRequestTemplateObject.MAX_FORM_FIELDS`, `MAX_MULTIPART_PARTS` and `MAX_PARSED_BODY_BYTES`.
const MAX_FORM_FIELDS: usize = 1000;
const MAX_MULTIPART_PARTS: usize = 100;
const MAX_PARSED_BODY_BYTES: usize = 10 * 1024 * 1024;

/// `QueryStringDecoder.decodeComponent`: `+` is a space and `%xx` sequences are bytes in `charset`; `None` for a
/// malformed escape (Netty throws, and the whole map is empty).
fn decode_component(text: &str, charset: &str) -> Option<String> {
    if !text.contains(['%', '+']) {
        return Some(text.to_string());
    }
    let mut out = String::new();
    let mut bytes: Vec<u8> = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '%' {
            let hex = text.get(i + 1..i + 3)?;
            bytes.push(u8::from_str_radix(hex, 16).ok()?);
            chars.next();
            chars.next();
            continue;
        }
        if !bytes.is_empty() {
            out.push_str(&crate::media_type::decode(&bytes, Some(charset)));
            bytes.clear();
        }
        out.push(if c == '+' { ' ' } else { c });
    }
    if !bytes.is_empty() {
        out.push_str(&crate::media_type::decode(&bytes, Some(charset)));
    }
    Some(out)
}

/// `org.mockserver.templates.engine.model.MultipartPartTemplateObject`.
pub struct PartObject {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    charset: Option<String>,
    bytes: Vec<u8>,
    headers: OnceLock<JValue>,
}

impl PartObject {
    fn new(part: crate::matcher::MultipartPart) -> PartObject {
        PartObject { name: part.name, filename: part.filename, content_type: part.content_type, charset: part.charset, bytes: part.bytes, headers: OnceLock::new() }
    }

    fn body(&self) -> String {
        crate::media_type::decode(&self.bytes, Some(self.charset.as_deref().unwrap_or("utf-8")))
    }

    fn headers(&self) -> JValue {
        self.headers
            .get_or_init(|| {
                let quoted = |v: &str| format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""));
                let mut disposition = format!("form-data; name={}", quoted(&self.name));
                if let Some(filename) = &self.filename {
                    disposition.push_str(&format!("; filename={}", quoted(filename)));
                }
                let mut entries = vec![("Content-Disposition".to_string(), vec![disposition])];
                if let Some(content_type) = &self.content_type {
                    entries.push(("Content-Type".to_string(), vec![content_type.clone()]));
                }
                JValue::Object(Arc::new(HeaderMap::new(&entries)))
            })
            .clone()
    }
}

impl JObject for PartObject {
    fn class_name(&self) -> String {
        "org.mockserver.templates.engine.model.MultipartPartTemplateObject".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        if !args.is_empty() {
            return None;
        }
        match name {
            "getName" => ok(JValue::str(self.name.as_str())),
            "getFilename" => ok(opt_str(&self.filename)),
            "getContentType" => ok(opt_str(&self.content_type)),
            "getHeaders" => ok(self.headers()),
            "getBody" | "toString" => ok(JValue::str(self.body())),
            "getBodyAsBase64" => {
                use base64::Engine;
                ok(JValue::str(base64::engine::general_purpose::STANDARD.encode(&self.bytes)))
            }
            _ => None,
        }
    }

    fn to_java_string(&self) -> String {
        self.body()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// `org.mockserver.model.X509Certificate`: a `ObjectWithJsonToString` over four bean properties.
pub struct CertificateObject {
    model: Value,
}

impl CertificateObject {
    fn text(&self, key: &str) -> JValue {
        self.model.get(key).and_then(Value::as_str).map(JValue::str).unwrap_or(JValue::Null)
    }
}

impl JObject for CertificateObject {
    fn class_name(&self) -> String {
        "org.mockserver.model.X509Certificate".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        if !args.is_empty() {
            return None;
        }
        match name {
            "getSerialNumber" => ok(self.text("serialNumber")),
            "getIssuerDistinguishedName" => ok(self.text("issuerDistinguishedName")),
            "getSubjectDistinguishedName" => ok(self.text("subjectDistinguishedName")),
            "getSignatureAlgorithmName" => ok(self.text("signatureAlgorithmName")),
            "toString" => ok(JValue::str(self.to_java_string())),
            _ => None,
        }
    }

    fn to_java_string(&self) -> String {
        crate::json::pretty(&self.model)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// What the matcher learned about the request's path: template parameters and regex capture groups.
#[derive(Debug, Clone, Default)]
pub struct PathMatch {
    pub parameters: Vec<(String, Vec<String>)>,
    /// Group 0 (the whole path) first; `None` for a group that did not participate.
    pub groups: Vec<Option<String>>,
    pub named_groups: Vec<(String, String)>,
}

impl RequestObject {
    /// `velocity`: the headers are a [`HeaderMap`], whose overrides Velocity's method calls reach. Mustache only
    /// reads a map (`containsKey`, then `get`), so it gets a plain map with the same case-insensitive lookups.
    pub fn new(request: &HttpRequest, path: &PathMatch, velocity: bool) -> RequestObject {
        let (headers, headers_value) = if velocity {
            let map = HeaderMap::new(&request.headers);
            (map.map.clone(), JValue::Object(Arc::new(map)))
        } else {
            let map = multi_map(MapKind::CaseInsensitive, &request.headers);
            (map.clone(), JValue::Map(map))
        };
        let body = DecodedBody::decode(&request.body, request.first_header("content-type"));
        let (json_rpc_id, json_rpc_raw_id, json_rpc_method) = json_rpc(body.as_ref());
        RequestObject {
            method: request.method.clone(),
            path: request.path.clone(),
            path_parameters: multi_map(MapKind::Hash, &path.parameters),
            path_groups: JList::array_list(path.groups.iter().map(|g| g.as_deref().map(JValue::str).unwrap_or(JValue::Null)).collect()),
            named_path_groups: put_all_into_hash_map(&path.named_groups),
            query: multi_map(MapKind::Hash, &request.query),
            headers,
            headers_value,
            cookies: JMap::from_entries(MapKind::Hash, request.cookies.iter().map(|(k, v)| (JValue::str(k.as_str()), JValue::str(v.as_str())))),
            body: body.map(|b| b.template_string()).unwrap_or_default(),
            secure: Some(request.secure),
            local_address: Some(request.local_address.clone()).filter(|a| !a.is_empty()),
            remote_address: Some(request.remote_address.clone()).filter(|a| !a.is_empty()),
            keep_alive: request.keep_alive_flag(),
            json_rpc_id,
            json_rpc_raw_id,
            json_rpc_method,
            client_certificate_chain: if request.client_certificates.is_empty() {
                JValue::Null
            } else {
                JValue::List(JList::array_list(
                    request.client_certificates.iter().map(|c| JValue::Object(Arc::new(CertificateObject { model: c.model.clone() }))).collect(),
                ))
            },
            id: Some(request.log_correlation_id.clone()).filter(|id| !id.is_empty()),
            derived: Derived::new(request),
        }
    }

    /// `getScheme()`.
    fn scheme(&self) -> &'static str {
        if self.secure == Some(true) { "https" } else { "http" }
    }

    /// The request object Mustache sees.
    pub fn value(request: &HttpRequest, path: &PathMatch) -> JValue {
        JValue::Object(Arc::new(RequestObject::new(request, path, false)))
    }

    /// The request object Velocity sees.
    pub fn velocity_value(request: &HttpRequest, path: &PathMatch) -> JValue {
        JValue::Object(Arc::new(RequestObject::new(request, path, true)))
    }

    /// The bean properties, alphabetically, as `ObjectWithJsonToString.toString()` serialises them.
    fn properties(&self) -> Vec<(&'static str, JValue)> {
        vec![
            ("body", JValue::str(self.body.as_str())),
            ("bodyAsString", JValue::str(self.body.as_str())),
            ("clientCertificateChain", self.client_certificate_chain.clone()),
            ("cookies", JValue::Map(self.cookies.clone())),
            ("headers", JValue::Map(self.headers.clone())),
            ("jsonRpcId", opt_str(&self.json_rpc_id)),
            ("jsonRpcMethod", opt_str(&self.json_rpc_method)),
            ("jsonRpcRawId", opt_str(&self.json_rpc_raw_id)),
            ("keepAlive", opt_bool(self.keep_alive)),
            ("localAddress", opt_str(&self.local_address)),
            ("method", JValue::str(self.method.as_str())),
            ("namedPathGroups", JValue::Map(self.named_path_groups.clone())),
            ("not", JValue::Null),
            ("path", JValue::str(self.path.as_str())),
            ("pathGroups", JValue::List(self.path_groups.clone())),
            ("pathParameters", JValue::Map(self.path_parameters.clone())),
            ("queryStringParameters", JValue::Map(self.query.clone())),
            ("remoteAddress", opt_str(&self.remote_address)),
            ("secure", opt_bool(self.secure)),
        ]
    }
}

/// `extractJsonRpcFields`: id (text or JSON), raw id (JSON, `null` for a notification) and method.
fn json_rpc(body: Option<&DecodedBody>) -> (Option<String>, Option<String>, Option<String>) {
    let Some(text) = body.map(DecodedBody::template_string) else { return (None, None, None) };
    if !text.trim().starts_with('{') {
        return (None, None, None);
    }
    let Ok(Value::Object(root)) = crate::json::parse_lenient(text.as_bytes()) else { return (None, None, None) };
    if !(root.contains_key("jsonrpc") && root.contains_key("method")) {
        return (None, None, None);
    }
    let (id, raw) = match root.get("id") {
        Some(Value::String(s)) => (Some(s.clone()), Some(serde_json::to_string(s).unwrap_or_default())),
        Some(other) => (Some(other.to_string()), Some(other.to_string())),
        None => (None, Some("null".to_string())),
    };
    let method = root.get("method").map(|m| match m {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    });
    (id, raw, method)
}

impl JObject for RequestObject {
    fn class_name(&self) -> String {
        "org.mockserver.templates.engine.model.HttpRequestTemplateObject".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        if !args.is_empty() {
            return None;
        }
        match name {
            "getMethod" => ok(JValue::str(self.method.as_str())),
            "getPath" => ok(JValue::str(self.path.as_str())),
            "getPathParameters" => ok(JValue::Map(self.path_parameters.clone())),
            "getPathGroups" => ok(JValue::List(self.path_groups.clone())),
            "getNamedPathGroups" => ok(JValue::Map(self.named_path_groups.clone())),
            "getQueryStringParameters" => ok(JValue::Map(self.query.clone())),
            "getHeaders" => ok(self.headers_value.clone()),
            "getCookies" => ok(JValue::Map(self.cookies.clone())),
            "getBody" | "getBodyAsString" => ok(JValue::str(self.body.as_str())),
            "getSecure" => ok(opt_bool(self.secure)),
            "getClientCertificateChain" => ok(self.client_certificate_chain.clone()),
            "getNot" => ok(JValue::Null),
            "getLocalAddress" => ok(opt_str(&self.local_address)),
            "getRemoteAddress" => ok(opt_str(&self.remote_address)),
            "getKeepAlive" => ok(opt_bool(self.keep_alive)),
            "getJsonRpcId" => ok(opt_str(&self.json_rpc_id)),
            "getJsonRpcRawId" => ok(opt_str(&self.json_rpc_raw_id)),
            "getJsonRpcMethod" => ok(opt_str(&self.json_rpc_method)),
            "isNot" => ok(JValue::Bool(false)),
            "getId" => ok(opt_str(&self.id)),
            "getScheme" => ok(JValue::str(self.scheme())),
            "getHost" => ok(opt_str(&self.derived.host)),
            "getPort" => ok(self.derived.port.map(JValue::Int).unwrap_or(JValue::Null)),
            "getBaseUrl" => ok(opt_str(&self.derived.base_url(self.scheme()))),
            "getBodyAsBase64" => {
                use base64::Engine;
                ok(JValue::str(base64::engine::general_purpose::STANDARD.encode(&self.derived.body)))
            }
            "getFormData" => ok(JValue::Map(self.derived.form_data.get_or_init(|| self.derived.form_data()).clone())),
            "getParts" => ok(JValue::Map(self.derived.parts.get_or_init(|| self.derived.parts()).clone())),
            "toString" => ok(JValue::str(self.to_java_string())),
            _ => None,
        }
    }

    fn to_java_string(&self) -> String {
        let o: Map<String, Value> = self.properties().into_iter().filter(|(_, v)| non_empty(v)).map(|(k, v)| (k.to_string(), to_json(&v))).collect();
        crate::json::pretty(&Value::Object(o))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// `org.mockserver.templates.engine.model.HttpResponseTemplateObject`, from a response in input JSON form.
pub struct ResponseObject {
    status_code: Option<i64>,
    reason_phrase: Option<String>,
    headers: JMap,
    cookies: JMap,
    body: String,
}

impl ResponseObject {
    pub fn value(response: &Value) -> JValue {
        let headers: Vec<(String, Vec<String>)> = response
            .get("headers")
            .map(crate::model::multi_values)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, vs)| Some((k.value?, vs.into_iter().flatten().filter_map(|v| v.value).collect())))
            .collect();
        let cookies = response.get("cookies").map(crate::model::key_values).unwrap_or_default();
        let body = match response.get("body").and_then(crate::model::response_body) {
            Some(crate::model::ResponseBody::Text(t)) => t,
            Some(crate::model::ResponseBody::Binary(b)) => {
                use base64::Engine;
                b.map(|b| base64::engine::general_purpose::STANDARD.encode(b)).unwrap_or_default()
            }
            None => String::new(),
        };
        JValue::Object(Arc::new(ResponseObject {
            status_code: response.get("statusCode").and_then(Value::as_i64),
            reason_phrase: response.get("reasonPhrase").and_then(Value::as_str).map(str::to_string),
            headers: multi_map(MapKind::Linked, &headers),
            cookies: JMap::from_entries(
                MapKind::Hash,
                cookies.into_iter().filter_map(|(k, vs)| Some((JValue::str(k.value?), JValue::str(vs.into_iter().flatten().next()?.value?)))),
            ),
            body,
        }))
    }
}

impl JObject for ResponseObject {
    fn class_name(&self) -> String {
        "org.mockserver.templates.engine.model.HttpResponseTemplateObject".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        if !args.is_empty() {
            return None;
        }
        match name {
            "getStatusCode" => ok(self.status_code.map(|s| JValue::Int(s as i32)).unwrap_or(JValue::Null)),
            "getReasonPhrase" => ok(opt_str(&self.reason_phrase)),
            "getHeaders" => ok(JValue::Map(self.headers.clone())),
            "getCookies" => ok(JValue::Map(self.cookies.clone())),
            "getBody" => ok(JValue::str(self.body.as_str())),
            "toString" => ok(JValue::str(self.to_java_string())),
            _ => None,
        }
    }

    fn to_java_string(&self) -> String {
        let props = [
            ("body", JValue::str(self.body.as_str())),
            ("cookies", JValue::Map(self.cookies.clone())),
            ("headers", JValue::Map(self.headers.clone())),
            ("reasonPhrase", opt_str(&self.reason_phrase)),
            ("statusCode", self.status_code.map(|s| JValue::Int(s as i32)).unwrap_or(JValue::Null)),
        ];
        let o: Map<String, Value> = props.into_iter().filter(|(_, v)| non_empty(v)).map(|(k, v)| (k.to_string(), to_json(&v))).collect();
        crate::json::pretty(&Value::Object(o))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// `new HashMap<>().putAll(map)` of String keys (`HttpRequestTemplateObject.namedPathGroups`): `putAll` on an empty
/// `HashMap` sizes its table for the source (`tableSizeFor(size / 0.75 + 1)`), not the default 16, so two entries
/// share a 4-bucket table and keep the source's order where a 16-bucket one would separate them. The entries in that
/// iteration order, as a map that keeps it.
fn put_all_into_hash_map(entries: &[(String, String)]) -> JMap {
    let wanted = (entries.len() as f32 / 0.75 + 1.0) as usize;
    let mut capacity = wanted.max(1).next_power_of_two();
    while entries.len() as f64 > capacity as f64 * 0.75 {
        capacity *= 2;
    }
    let bucket = |key: &str| {
        let h = key.encode_utf16().fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(c as i32));
        ((h ^ ((h as u32) >> 16) as i32) as u32 as usize) & (capacity - 1)
    };
    let mut ordered: Vec<(usize, usize)> = entries.iter().enumerate().map(|(i, (k, _))| (bucket(k), i)).collect();
    ordered.sort();
    JMap::from_entries(MapKind::Linked, ordered.into_iter().map(|(_, i)| (JValue::str(entries[i].0.as_str()), JValue::str(entries[i].1.as_str()))))
}

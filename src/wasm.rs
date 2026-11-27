//! WASM custom rules (`wasmEnabled`), as upstream's `org.mockserver.wasm` implements them:
//! - modules uploaded over the control plane (`/mockserver/wasm/modules`, `/mockserver/wasm/test`);
//! - the `WASM` body matcher: `match_request` with the request envelope (v2), else `match` with the body;
//! - optional `shape_response` (ABI v3), which rewrites a matched static response.
//!
//! Every call runs in a fresh instance with no host imports. Linear memory is capped at `wasmMaxMemoryPages`. Any
//! failure fails closed: no match, or the response left unshaped. Upstream's wall-clock budget
//! (`wasmExecutionTimeoutMillis`, zero or less for none) is kept by running a call on slices of fuel and checking
//! the clock between them, because a `wasmi` call cannot be interrupted from outside. It spans the whole invocation,
//! as `callWithinBudget` does: instantiation, the module's start function (run as a resumable call, see
//! [`defer_start`]) and the exported call.

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;

pub const DISABLED: &str = "WASM support is disabled; set wasmEnabled=true to enable";
const SHAPE_MAX_RETURN_BYTES: usize = 1024 * 1024;
const PAGE: usize = 64 * 1024;
/// Fuel per slice of a budgeted call: the clock is read between slices.
const FUEL_SLICE: u64 = 1_000_000;

/// `WasmStore`: module bytes by name, in upload order; cleared by `reset`.
#[derive(Default)]
pub struct Modules {
    modules: Mutex<Vec<(String, Arc<Vec<u8>>)>>,
    /// Modules whose shaping already failed once (`WasmResponseShaper`'s warn-once set).
    shape_warned: Mutex<HashSet<String>>,
}

impl Modules {
    fn put(&self, name: &str, bytes: Vec<u8>) {
        let mut modules = self.modules.lock();
        match modules.iter_mut().find(|(n, _)| n == name) {
            Some(existing) => existing.1 = Arc::new(bytes),
            None => modules.push((name.to_string(), Arc::new(bytes))),
        }
    }

    pub fn get(&self, name: &str) -> Option<Arc<Vec<u8>>> {
        self.modules.lock().iter().find(|(n, _)| n == name).map(|(_, b)| b.clone())
    }

    fn remove(&self, name: &str) -> bool {
        let mut modules = self.modules.lock();
        let before = modules.len();
        modules.retain(|(n, _)| n != name);
        modules.len() != before
    }

    /// Names in `ConcurrentHashMap` iteration order.
    fn names(&self) -> Vec<String> {
        let names: Vec<String> = self.modules.lock().iter().map(|(n, _)| n.clone()).collect();
        crate::recorded::java_hashmap_order(&names).into_iter().map(|i| names[i].clone()).collect()
    }

    pub fn clear(&self) {
        self.modules.lock().clear();
    }
}

tokio::task_local! {
    /// The server a request is being handled for, so the `WASM` body matcher can reach its modules.
    static SERVER: ServerRef;
    /// The `WASM` body matcher's verdicts within one request: (module bytes, request envelope, matched).
    static VERDICTS: std::cell::RefCell<Vec<(Arc<Vec<u8>>, String, bool)>>;
}

/// The server a scope runs for, borrowed (from its `Arc`) for as long as the scope: every request sets one, and a
/// clone wrote the server's reference count, which every request worker shares, twice per request.
#[derive(Clone, Copy)]
struct ServerRef(*const State);

// SAFETY: a `ServerRef` stands for a `&Arc<State>` (`State` is `Sync`), read only while the scope that borrows it runs.
unsafe impl Send for ServerRef {}
unsafe impl Sync for ServerRef {}

/// Runs `work` with `state` as the server WASM matchers consult. The returned future captures the borrow
/// (`use<'a, …>`), so it cannot outlive the server. Not an `async fn`, which would move `work` (a request's whole
/// handling) into a future of its own.
pub fn scope<'a, F: std::future::Future>(state: &'a Arc<State>, work: F) -> impl std::future::Future<Output = F::Output> + use<'a, F> {
    SERVER.scope(ServerRef(Arc::as_ptr(state)), VERDICTS.scope(Default::default(), work))
}

/// The server the current request is handled for, outside a request `None` (also read by `XML_SCHEMA` compiles,
/// for the server's [`crate::xsd::Reported`] namespaces).
pub fn current_server() -> Option<Arc<State>> {
    // SAFETY: set only by `scope`, from an `Arc` its future holds borrowed while the scope runs: a new strong reference
    // to it is taken
    SERVER
        .try_with(|server| unsafe {
            Arc::increment_strong_count(server.0);
            Arc::from_raw(server.0)
        })
        .ok()
}

pub fn enabled(state: &State) -> bool {
    state.config.bool_property("wasmEnabled", false)
}

/// `WasmRequest`: the parts a module sees.
#[derive(Default, Clone)]
pub struct Envelope {
    pub method: Option<String>,
    pub path: Option<String>,
    pub query: Vec<(String, Vec<String>)>,
    pub headers: Vec<(String, Vec<String>)>,
    pub cookies: Vec<(String, String)>,
    pub body: Option<String>,
}

impl Envelope {
    pub fn of(request: &HttpRequest) -> Envelope {
        Envelope {
            method: Some(request.method.clone()),
            path: Some(request.path.clone()),
            query: request.query.clone(),
            headers: request.headers.clone(),
            cookies: request.cookies.clone(),
            body: Some(request.body_str().into_owned()),
        }
    }

    /// The request envelope (version 2), in upstream's key order.
    fn json(&self) -> Value {
        let multi = |m: &[(String, Vec<String>)]| Value::Object(m.iter().map(|(k, v)| (k.clone(), json!(v))).collect());
        let mut o = Map::new();
        o.insert("version".into(), json!(2));
        o.insert("method".into(), self.method.clone().map_or(Value::Null, Value::String));
        o.insert("path".into(), self.path.clone().map_or(Value::Null, Value::String));
        o.insert("queryStringParameters".into(), multi(&self.query));
        o.insert("headers".into(), multi(&self.headers));
        o.insert("cookies".into(), Value::Object(self.cookies.iter().map(|(k, v)| (k.clone(), json!(v))).collect()));
        o.insert("body".into(), self.body.clone().map_or(Value::Null, Value::String));
        Value::Object(o)
    }
}

/// `WasmResponse`: what a shaper reads and rewrites; absent parts mean "unchanged" in a shaper's output.
#[derive(Default, Clone, Debug)]
pub struct Shape {
    pub status: Option<u32>,
    pub headers: Option<Vec<(String, Vec<String>)>>,
    pub body: Option<String>,
}

impl Shape {
    fn json(&self) -> Value {
        let mut o = Map::new();
        o.insert("statusCode".into(), self.status.map_or(Value::Null, |s| json!(s)));
        let headers = self.headers.clone().unwrap_or_default();
        o.insert("headers".into(), Value::Object(headers.into_iter().map(|(k, v)| (k, json!(v))).collect()));
        o.insert("body".into(), self.body.clone().map_or(Value::Null, Value::String));
        Value::Object(o)
    }

    /// `parseShapedResponse`.
    fn parse(text: &[u8]) -> Result<Shape, String> {
        let v: Value = serde_json::from_slice(text).map_err(|_| "shape_response returned invalid JSON".to_string())?;
        let o = v.as_object().ok_or("shape_response must return a JSON object")?;
        let headers = o.get("headers").and_then(Value::as_object).map(|h| {
            h.iter()
                .map(|(k, v)| {
                    let values = match v {
                        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
                        Value::Null => Vec::new(),
                        other => vec![other.as_str().map_or_else(|| other.to_string(), str::to_string)],
                    };
                    (k.clone(), values)
                })
                .collect()
        });
        Ok(Shape {
            status: o.get("statusCode").and_then(Value::as_u64).map(|s| s as u32),
            headers,
            body: o.get("body").and_then(Value::as_str).map(str::to_string),
        })
    }
}

/// The export [`defer_start`] gives a module's start function.
const DEFERRED_START: &str = "\0mock-server:start";

/// The module with its start section turned into the export [`DEFERRED_START`], `None` when it has no start section
/// (or is not a binary this reads, which `wasmi` then rejects itself). `wasmi` runs a start function inside
/// instantiation, which cannot be resumed, so the budget could not interrupt it; called afterwards as an export it
/// runs on the same fuel slices as any other call. Its semantics are kept: a start function runs after the
/// instance's tables and memories are initialised, and its trap fails the instantiation.
fn defer_start(bytes: &[u8]) -> Option<Vec<u8>> {
    fn leb(bytes: &[u8], at: &mut usize) -> Option<u32> {
        let mut value = 0u32;
        for shift in (0..35).step_by(7) {
            let byte = *bytes.get(*at)?;
            *at += 1;
            value |= u32::from(byte & 0x7f).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }
    fn put_leb(out: &mut Vec<u8>, mut value: u32) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }
    const HEADER: &[u8] = b"\0asm\x01\0\0\0";
    if !bytes.starts_with(HEADER) {
        return None;
    }
    let mut sections = Vec::new();
    let mut at = HEADER.len();
    while at < bytes.len() {
        let id = bytes[at];
        at += 1;
        let len = leb(bytes, &mut at)? as usize;
        let end = at.checked_add(len).filter(|&end| end <= bytes.len())?;
        sections.push((id, at..end));
        at = end;
    }
    let mut starts = sections.iter().filter(|(id, _)| *id == 8);
    let (_, range) = starts.next()?;
    if starts.next().is_some() {
        return None;
    }
    let mut at = range.start;
    let start = leb(bytes, &mut at)?;
    if at != range.end {
        return None;
    }
    let mut entry = Vec::new();
    put_leb(&mut entry, DEFERRED_START.len() as u32);
    entry.extend_from_slice(DEFERRED_START.as_bytes());
    entry.push(0x00);
    put_leb(&mut entry, start);
    let has_exports = sections.iter().any(|(id, _)| *id == 7);
    let mut out = HEADER.to_vec();
    for (id, range) in &sections {
        let content = match id {
            7 => {
                let mut at = range.start;
                let count = leb(bytes, &mut at)?.checked_add(1)?;
                let mut content = Vec::new();
                put_leb(&mut content, count);
                content.extend_from_slice(&bytes[at..range.end]);
                content.extend_from_slice(&entry);
                content
            }
            // Where a module without exports gets its export section: the start section's place is after any
            // section an export section must follow.
            8 if has_exports => continue,
            8 => {
                let mut content = vec![1];
                content.extend_from_slice(&entry);
                content
            }
            _ => bytes[range.clone()].to_vec(),
        };
        out.push(if *id == 8 { 7 } else { *id });
        put_leb(&mut out, content.len() as u32);
        out.extend_from_slice(&content);
    }
    Some(out)
}

/// `wasmMaxMemoryPages` and `wasmExecutionTimeoutMillis` (zero or less: no budget) of one invocation.
#[derive(Clone, Copy)]
struct Limits {
    pages: usize,
    millis: u64,
}

impl Limits {
    /// The live configuration, as `new WasmRuntime(bytes, configuration)` reads it (the body matcher, the shaper).
    fn live(state: &State) -> Limits {
        Limits::of(state.config.int_property("wasmMaxMemoryPages", 256), state.config.int_property("wasmExecutionTimeoutMillis", 5000))
    }

    /// The startup values, as `new WasmRuntime(bytes)` reads the static `ConfigurationProperties` (`POST /wasm/test`):
    /// a `PUT /mockserver/configuration` does not reach them.
    fn startup(state: &State) -> Limits {
        let read = |name: &str, default: i64| state.config.startup_property(name).and_then(|v| v.trim().parse().ok()).unwrap_or(default);
        Limits::of(read("wasmMaxMemoryPages", 256), read("wasmExecutionTimeoutMillis", 5000))
    }

    fn of(pages: i64, millis: i64) -> Limits {
        Limits { pages: usize::try_from(pages.max(1)).unwrap_or(256), millis: u64::try_from(millis).unwrap_or(0) }
    }
}

/// Why an invocation failed: its budget ran out (`WasmExecutionBudgetException`), or anything else.
#[derive(Debug)]
enum Failure {
    Budget(u64),
    Other,
}

impl Failure {
    fn other(_: impl std::fmt::Display) -> Failure {
        Failure::Other
    }
}

/// One instance of a module, limited as the configuration says.
struct Instance {
    store: wasmi::Store<wasmi::StoreLimits>,
    instance: wasmi::Instance,
    /// `wasmExecutionTimeoutMillis` and the instant it runs out, from the start of the invocation; `None` when it is
    /// zero or less (no budget).
    deadline: Option<(u64, std::time::Instant)>,
}

impl Instance {
    fn new(limits: Limits, bytes: &[u8]) -> Result<Instance, Failure> {
        let millis = limits.millis;
        let deadline = (millis > 0).then(|| (millis, std::time::Instant::now() + std::time::Duration::from_millis(millis)));
        let deferred = defer_start(bytes);
        let bytes = deferred.as_ref().map_or(bytes, |d| d.as_slice());
        let mut config = wasmi::Config::default();
        config.consume_fuel(true);
        let engine = wasmi::Engine::new(&config);
        let module = wasmi::Module::new(&engine, bytes).map_err(Failure::other)?;
        let store_limits = wasmi::StoreLimitsBuilder::new().memory_size(limits.pages * PAGE).build();
        let mut store = wasmi::Store::new(&engine, store_limits);
        store.limiter(|l| l);
        store.set_fuel(u64::MAX).map_err(Failure::other)?;
        let instance = wasmi::Linker::<wasmi::StoreLimits>::new(&engine).instantiate_and_start(&mut store, &module).map_err(Failure::other)?;
        let mut instance = Instance { store, instance, deadline };
        if deferred.is_some() {
            let start = instance.instance.get_typed_func::<(), ()>(&instance.store, DEFERRED_START).map_err(Failure::other)?;
            instance.call_budgeted(&start, ())?;
        }
        Ok(instance)
    }

    /// Calls `f` within what is left of the invocation's wall-clock budget: fuel is handed out in slices and the call
    /// fails once a slice runs out after the deadline (`callWithinBudget`).
    fn call_budgeted<P: wasmi::WasmParams, R: wasmi::WasmResults>(&mut self, f: &wasmi::TypedFunc<P, R>, params: P) -> Result<R, Failure> {
        let deadline = self.deadline;
        self.store.set_fuel(FUEL_SLICE).map_err(Failure::other)?;
        let mut call = f.call_resumable(&mut self.store, params).map_err(Failure::other)?;
        loop {
            match call {
                wasmi::TypedResumableCall::Finished(results) => return Ok(results),
                wasmi::TypedResumableCall::HostTrap(_) => return Err(Failure::other("host trap")),
                wasmi::TypedResumableCall::OutOfFuel(pending) => {
                    if let Some((ms, at)) = deadline
                        && std::time::Instant::now() >= at
                    {
                        return Err(Failure::Budget(ms));
                    }
                    self.store.set_fuel(FUEL_SLICE).map_err(Failure::other)?;
                    call = pending.resume(&mut self.store).map_err(Failure::other)?;
                }
            }
        }
    }

    fn has(&self, name: &str) -> bool {
        self.instance.get_func(&self.store, name).is_some()
    }

    /// Writes `input` at offset 0, as upstream does.
    fn write(&mut self, input: &[u8]) -> Result<wasmi::Memory, Failure> {
        let memory = self.instance.get_memory(&self.store, "memory").ok_or_else(|| Failure::other("the module exports no memory"))?;
        memory.write(&mut self.store, 0, input).map_err(Failure::other)?;
        Ok(memory)
    }

    fn call_i32(&mut self, name: &str, input: &[u8]) -> Result<i32, Failure> {
        self.write(input)?;
        let f = self.instance.get_typed_func::<(i32, i32), i32>(&self.store, name).map_err(Failure::other)?;
        self.call_budgeted(&f, (0, input.len() as i32))
    }
}

/// `WasmRuntime.callMatch`: whether the module matches, `false` on any failure.
pub fn call_match(state: &State, bytes: &[u8], envelope: &Envelope) -> bool {
    match_within(Limits::live(state), bytes, envelope)
}

fn match_within(limits: Limits, bytes: &[u8], envelope: &Envelope) -> bool {
    let run = || -> Result<bool, Failure> {
        let mut instance = Instance::new(limits, bytes)?;
        let result = if instance.has("match_request") {
            instance.call_i32("match_request", envelope.json().to_string().as_bytes())?
        } else {
            instance.call_i32("match", envelope.body.clone().unwrap_or_default().as_bytes())?
        };
        Ok(result != 0)
    };
    run().unwrap_or(false)
}

/// `WasmRuntime.callShape`: `Ok(None)` when the module does not shape or opts out; an error is the
/// `WasmShapeException`'s `getMessage()`.
fn call_shape(limits: Limits, bytes: &[u8], envelope: &Envelope, response: &Shape) -> Result<Option<Shape>, String> {
    // `callShape` wraps a spent budget, wherever it ran out, as "WASM shape_response failed: <message>".
    let budget = |ms: u64| format!("WASM shape_response failed: WASM shape_response exceeded the {ms}ms execution budget");
    let mut instance = match Instance::new(limits, bytes) {
        Ok(instance) => instance,
        Err(Failure::Budget(ms)) => return Err(budget(ms)),
        Err(Failure::Other) => return Err("failed to instantiate WASM module for response shaping".into()),
    };
    if !instance.has("shape_response") {
        return Ok(None);
    }
    let input = json!({"version": 3, "request": envelope.json(), "response": response.json()}).to_string();
    let mut call = || {
        let memory = instance.write(input.as_bytes())?;
        let f = instance.instance.get_typed_func::<(i32, i32), i64>(&instance.store, "shape_response").map_err(Failure::other)?;
        Ok((memory, instance.call_budgeted(&f, (0, input.len() as i32))?))
    };
    let (memory, packed) = match call() {
        Ok(called) => called,
        Err(Failure::Budget(ms)) => return Err(budget(ms)),
        Err(Failure::Other) => return Err("WASM shape_response trapped".into()),
    };
    // `readShapedResult`: the pointer and the length are Java ints.
    if packed == 0 {
        return Ok(None);
    }
    let (ptr, len) = ((packed >> 32) as i32, packed as i32);
    if ptr < 0 || len < 0 {
        return Err("shape_response returned an invalid pointer/length".into());
    }
    let (ptr, len) = (ptr as usize, len as usize);
    if len > SHAPE_MAX_RETURN_BYTES {
        return Err(format!("shape_response returned {len} bytes, exceeding the {SHAPE_MAX_RETURN_BYTES}-byte cap"));
    }
    let mut out = vec![0; len];
    memory.read(&instance.store, ptr, &mut out).map_err(|_| "shape_response returned an out-of-bounds memory region".to_string())?;
    Shape::parse(&out).map(Some)
}

/// `WasmBodyMatcher.matches`, for the server whose request is being handled.
pub fn body_matches(module: &str, request: &HttpRequest) -> bool {
    SERVER
        .try_with(|state| {
            // SAFETY: set only by `scope`, whose future holds the server borrowed while the scope runs
            let state: &State = unsafe { &*state.0 };
            if !enabled(state) {
                return false;
            }
            let Some(bytes) = state.wasm.get(module) else { return false };
            let envelope = Envelope::of(request);
            // A module is a pure function of the envelope (a fresh instance, no host imports), so the re-evaluations
            // of one request (the scan, its log entries, the closest expectation, the hint) cost its budget once.
            let key = envelope.json().to_string();
            let known = VERDICTS.try_with(|v| v.borrow().iter().find(|(b, k, _)| Arc::ptr_eq(b, &bytes) && *k == key).map(|(_, _, m)| *m));
            if let Ok(Some(matched)) = known {
                return matched;
            }
            // Upstream runs a module on a worker of its own (`mockserver-wasm-exec`) while the caller waits; here the
            // tokio worker hands its other tasks on first, so they are not held for the module's budget.
            let matched = crate::blocking::off_worker(|| call_match(state, &bytes, &envelope));
            let _ = VERDICTS.try_with(|v| v.borrow_mut().push((bytes, key, matched)));
            matched
        })
        .unwrap_or(false)
}

/// `WasmResponseShaper.shape`: rewrites a matched static response in place, when the expectation's body matcher
/// is a loaded WASM module that shapes; a failure leaves it unchanged and warns once per module.
pub fn shape(state: &State, module: &str, request: &HttpRequest, reply: &mut Reply) {
    if !enabled(state) {
        return;
    }
    let Some(bytes) = state.wasm.get(module) else { return };
    let mut headers: Vec<(String, Vec<String>)> = Vec::new();
    for (k, v) in &reply.headers {
        match headers.iter_mut().find(|(e, _)| e.eq_ignore_ascii_case(k)) {
            Some(existing) => existing.1.push(v.clone()),
            None => headers.push((k.clone(), vec![v.clone()])),
        }
    }
    let current = Shape { status: Some(reply.status), headers: Some(headers), body: Some(String::from_utf8_lossy(&reply.body).into_owned()) };
    let envelope = Envelope::of(request);
    match crate::blocking::off_worker(|| call_shape(Limits::live(state), &bytes, &envelope, &current)) {
        Ok(Some(shaped)) => apply(reply, shaped),
        Ok(None) => {}
        Err(e) => {
            // `warnOnce`: a WARN in the event log, once per module name for the life of the server (a reset keeps it).
            if state.wasm.shape_warned.lock().insert(module.to_string()) {
                let format = "WASM module \"{}\" shape_response failed, falling back to the unshaped response (this is logged once per module) because:{}";
                crate::log::warn_event(state, crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, format).args([module, e.as_str()]));
            }
        }
    }
}

/// Status and body replaced, headers merged: an empty value list removes the header.
fn apply(reply: &mut Reply, shaped: Shape) {
    if let Some(status) = shaped.status {
        reply.status = status;
        reply.reason = None;
    }
    for (name, values) in shaped.headers.unwrap_or_default() {
        reply.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&name));
        for v in values {
            reply.headers.push((name.clone(), v));
        }
    }
    if let Some(body) = shaped.body {
        reply.body = bytes::Bytes::from(body);
    }
}

fn json_reply(status: u32, body: Value) -> Reply {
    Reply::api_body(status, "application/json", body.to_string())
}

fn text(status: u32, message: String) -> Reply {
    Reply::api_header(status, "text/plain", message)
}

/// The `/mockserver/wasm/*` control-plane routes.
pub fn route(state: &State, request: &HttpRequest, path: &str) -> Option<Reply> {
    let known = matches!((request.method.as_str(), path), ("GET" | "PUT" | "DELETE", "/wasm/modules") | ("POST", "/wasm/test"));
    if !known {
        return None;
    }
    if !enabled(state) {
        return Some(text(403, DISABLED.into()));
    }
    let name = request.query.iter().find(|(k, _)| k == "name").and_then(|(_, v)| v.first()).cloned().filter(|n| !n.trim().is_empty());
    Some(match (request.method.as_str(), path) {
        ("GET", _) => Reply::api_body(200, "application/json", crate::json::pretty(&json!(state.wasm.names()))),
        ("PUT", _) => match name {
            None => text(400, "query parameter 'name' is required".into()),
            Some(_) if request.body.is_empty() => text(400, "WASM module body is empty".into()),
            Some(name) => {
                state.wasm.put(&name, request.body.to_vec());
                json_reply(201, json!({"status": "loaded", "moduleName": name}))
            }
        },
        ("DELETE", _) => match name {
            None => text(400, "query parameter 'name' is required".into()),
            Some(name) if state.wasm.remove(&name) => Reply::api(200),
            Some(name) => text(404, format!("WASM module '{name}' not found")),
        },
        _ => test(state, request),
    })
}

/// `POST /mockserver/wasm/test`: a module against a sample request, and optionally a response to shape.
fn test(state: &State, request: &HttpRequest) -> Reply {
    if request.body_str().trim().is_empty() {
        return json_reply(400, json!({"error": "request body is required with a 'module' field"}));
    }
    let body: Value = crate::json::parse_lenient(&request.body).unwrap_or(Value::Null);
    let module = body.get("module").and_then(as_text).filter(|m| !m.trim().is_empty());
    let bytes = match (module, body.get("moduleName").and_then(as_text)) {
        (Some(b64), _) => {
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
                Ok(bytes) => bytes,
                Err(_) => return json_reply(400, json!({"error": "'module' must be base64-encoded WASM bytes"})),
            }
        }
        (None, Some(name)) => match state.wasm.get(&name) {
            Some(bytes) => bytes.to_vec(),
            None => return json_reply(404, json!({"error": format!("WASM module '{name}' not found")})),
        },
        (None, None) => return json_reply(400, json!({"error": "either 'module' (base64) or 'moduleName' (loaded module) is required"})),
    };
    let sample = body.get("request").cloned().unwrap_or(Value::Null);
    let envelope = sample_envelope(&sample);
    // `new WasmRuntime(bytes)`: the static properties, not the live configuration.
    let limits = Limits::startup(state);
    let matched = crate::blocking::off_worker(|| match_within(limits, &bytes, &envelope));
    let mut out = Map::new();
    out.insert("matched".into(), json!(matched));
    if let Some(response) = body.get("response").filter(|r| r.is_object()) {
        let current = Shape {
            status: response.get("statusCode").and_then(Value::as_u64).map(|s| s as u32),
            headers: response.get("headers").map(multi),
            body: response.get("body").and_then(Value::as_str).map(str::to_string),
        };
        let shaped = crate::blocking::off_worker(|| call_shape(limits, &bytes, &envelope, &current)).ok().flatten();
        out.insert("shaped".into(), shaped.map_or(Value::Null, |s| s.json()));
    }
    json_reply(200, Value::Object(out))
}

/// Names to an array of values, or a single scalar per name.
fn multi(v: &Value) -> Vec<(String, Vec<String>)> {
    v.as_object()
        .map(|o| {
            o.iter()
                .map(|(k, v)| {
                    let values = match v {
                        Value::Array(a) => a.iter().map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_string)).collect(),
                        other => vec![other.as_str().map_or_else(|| other.to_string(), str::to_string)],
                    };
                    (k.clone(), values)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Jackson's `JsonNode.asText()` of a present, non-null value.
fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

/// The `request` of a dry run; absent means an empty, body-only request (`WasmRequest.ofBody(null)`), present
/// fills a missing method or path with "".
fn sample_envelope(sample: &Value) -> Envelope {
    if !sample.is_object() {
        return Envelope { method: Some(String::new()), path: Some(String::new()), ..Envelope::default() };
    }
    let text = |k: &str| sample.get(k).and_then(as_text);
    Envelope {
        method: Some(text("method").unwrap_or_default()),
        path: Some(text("path").unwrap_or_default()),
        query: sample.get("queryStringParameters").map(multi).unwrap_or_default(),
        headers: sample.get("headers").map(multi).unwrap_or_default(),
        cookies: sample
            .get("cookies")
            .and_then(Value::as_object)
            .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().map_or_else(|| v.to_string(), str::to_string))).collect())
            .unwrap_or_default(),
        body: text("body"),
    }
}

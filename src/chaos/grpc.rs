//! `GrpcChaosProfile` and `GrpcChaosRegistry` (`/mockserver/grpcChaos`): gRPC faults by service name, with `""` as
//! the global fallback. `decide` is `GrpcChaosDecision`: the quota (RESOURCE_EXHAUSTED), then a probabilistic error
//! status. [`fault`] is the chaos branch of `GrpcToHttpRequestHandler`, applied by `grpc_plane` to gRPC and gRPC-Web
//! calls over HTTP/1.1 and HTTP/2 before they are matched: `abortAfterMessages` (ABORTED), the decision, then the
//! standalone `omitGrpcStatus`/`corruptGrpcStatus`/`customTrailers` fault (INTERNAL), each answered with a body-less
//! response delayed by `latencyMs`. Upstream has no gRPC chaos on HTTP/3 (`Http3MockServerHandler`) nor on
//! rule-driven bidi streams (`GrpcBidiRouterHandler` routes them past the handler), and none mid-stream: no stream
//! resets, dropped messages or metrics; faulted calls are neither logged nor recorded.

use std::collections::HashMap;

use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use super::bind::Bean;
use super::http::Quotas;
use super::{ProfileError, as_boolean, as_long, error, log, now_millis, pretty, read_tree};
use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;

/// `GrpcStatusMapper.GrpcStatusCode`, in code order.
pub const STATUS_CODES: &[&str] = &[
    "OK",
    "CANCELLED",
    "UNKNOWN",
    "INVALID_ARGUMENT",
    "DEADLINE_EXCEEDED",
    "NOT_FOUND",
    "ALREADY_EXISTS",
    "PERMISSION_DENIED",
    "RESOURCE_EXHAUSTED",
    "FAILED_PRECONDITION",
    "ABORTED",
    "OUT_OF_RANGE",
    "UNIMPLEMENTED",
    "INTERNAL",
    "UNAVAILABLE",
    "DATA_LOSS",
    "UNAUTHENTICATED",
];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct GrpcChaosProfile {
    pub error_status_code: Option<String>,
    pub error_message: Option<String>,
    pub error_probability: Option<f64>,
    pub seed: Option<i64>,
    pub latency_ms: Option<i64>,
    pub succeed_first: Option<i32>,
    pub fail_request_count: Option<i32>,
    pub quota_name: Option<String>,
    pub quota_limit: Option<i32>,
    pub quota_window_millis: Option<i64>,
    pub omit_grpc_status: Option<bool>,
    pub corrupt_grpc_status: Option<bool>,
    pub custom_trailers: Option<Vec<(String, Option<String>)>>,
    pub abort_after_messages: Option<i32>,
}

fn is_token(key: &str) -> bool {
    key.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "!#$%&'*+-.^_`|~".contains(c))
}

impl GrpcChaosProfile {
    /// [`GrpcChaosProfile::from_json`] with the error as its message.
    pub fn parse(v: &Value) -> Result<GrpcChaosProfile, String> {
        GrpcChaosProfile::from_json(v).map_err(|e| match e {
            ProfileError::Invalid(m) => m,
            other => other.text(),
        })
    }

    /// `GrpcChaosProfileDTO` bound from JSON, then `buildObject`'s checks in setter order.
    pub fn from_json(v: &Value) -> Result<GrpcChaosProfile, ProfileError> {
        let dto = Bean::of(v, "org.mockserver.serialization.model.GrpcChaosProfileDTO")?;
        let p = GrpcChaosProfile {
            error_status_code: dto.string("errorStatusCode")?,
            error_message: dto.string("errorMessage")?,
            error_probability: dto.double("errorProbability")?,
            seed: dto.long("seed")?,
            latency_ms: dto.long("latencyMs")?,
            succeed_first: dto.int("succeedFirst")?,
            fail_request_count: dto.int("failRequestCount")?,
            quota_name: dto.string("quotaName")?,
            quota_limit: dto.int("quotaLimit")?,
            quota_window_millis: dto.long("quotaWindowMillis")?,
            omit_grpc_status: dto.boolean("omitGrpcStatus")?,
            corrupt_grpc_status: dto.boolean("corruptGrpcStatus")?,
            custom_trailers: dto.string_map("customTrailers")?,
            abort_after_messages: dto.int("abortAfterMessages")?,
        };
        let invalid = |m: String| Err(ProfileError::Invalid(m));
        if let Some(code) = &p.error_status_code && !STATUS_CODES.contains(&code.to_uppercase().as_str()) {
            return invalid(format!("errorStatusCode must be a valid gRPC status code name, got '{code}'"));
        }
        if let Some(f) = p.error_probability.filter(|f| f.is_nan() || !(0.0..=1.0).contains(f)) {
            return invalid(format!("errorProbability must be between 0.0 and 1.0, got {}", java_compat::double_to_string(f)));
        }
        let at_least = |name: &str, v: Option<i64>, min: i64| match v {
            Some(n) if n < min => Err(ProfileError::Invalid(format!("{name} must be >= {min}, got {n}"))),
            _ => Ok(()),
        };
        at_least("latencyMs", p.latency_ms, 0)?;
        at_least("succeedFirst", p.succeed_first.map(i64::from), 0)?;
        at_least("failRequestCount", p.fail_request_count.map(i64::from), 1)?;
        at_least("quotaLimit", p.quota_limit.map(i64::from), 1)?;
        at_least("quotaWindowMillis", p.quota_window_millis, 1)?;
        for (key, value) in p.custom_trailers.iter().flatten() {
            if key.is_empty() {
                return invalid("customTrailers key must not be null or empty".into());
            }
            if key.contains(['\r', '\n']) {
                return invalid(format!("customTrailers key must not contain CR or LF characters, got '{key}'"));
            }
            if !is_token(key) {
                return invalid(format!("customTrailers key must be a valid lowercase HTTP/2 header token ([a-z0-9!#$%&'*+\\-.^_`|~]), got '{key}'"));
            }
            if value.as_deref().is_some_and(|v| v.contains(['\r', '\n'])) {
                return invalid(format!("customTrailers value must not contain CR or LF characters, got value for key '{key}'"));
            }
        }
        at_least("abortAfterMessages", p.abort_after_messages.map(i64::from), 1)?;
        Ok(p)
    }

    /// `GrpcChaosProfileDTO` as Jackson writes it: non-null properties, alphabetical.
    pub fn to_json(&self) -> Value {
        let mut o = Map::new();
        let mut put = |k: &str, v: Option<Value>| {
            if let Some(v) = v {
                o.insert(k.to_string(), v);
            }
        };
        put("abortAfterMessages", self.abort_after_messages.map(Value::from));
        put("corruptGrpcStatus", self.corrupt_grpc_status.map(Value::from));
        put("customTrailers", self.custom_trailers.as_ref().map(|t| Value::Object(t.iter().map(|(k, v)| (k.clone(), v.clone().map_or(Value::Null, Value::from))).collect())));
        put("errorMessage", self.error_message.clone().map(Value::from));
        put("errorProbability", self.error_probability.map(|f| crate::model::number(&java_compat::double_to_string(f))));
        put("errorStatusCode", self.error_status_code.clone().map(Value::from));
        put("failRequestCount", self.fail_request_count.map(Value::from));
        put("latencyMs", self.latency_ms.map(Value::from));
        put("omitGrpcStatus", self.omit_grpc_status.map(Value::from));
        put("quotaLimit", self.quota_limit.map(Value::from));
        put("quotaName", self.quota_name.clone().map(Value::from));
        put("quotaWindowMillis", self.quota_window_millis.map(Value::from));
        put("seed", self.seed.map(Value::from));
        put("succeedFirst", self.succeed_first.map(Value::from));
        Value::Object(o)
    }

    fn merge(&self, patch: &GrpcChaosProfile) -> GrpcChaosProfile {
        fn pick<T: Clone>(patch: &Option<T>, base: &Option<T>) -> Option<T> {
            patch.clone().or_else(|| base.clone())
        }
        GrpcChaosProfile {
            error_status_code: pick(&patch.error_status_code, &self.error_status_code),
            error_message: pick(&patch.error_message, &self.error_message),
            error_probability: pick(&patch.error_probability, &self.error_probability),
            seed: pick(&patch.seed, &self.seed),
            latency_ms: pick(&patch.latency_ms, &self.latency_ms),
            succeed_first: pick(&patch.succeed_first, &self.succeed_first),
            fail_request_count: pick(&patch.fail_request_count, &self.fail_request_count),
            quota_name: pick(&patch.quota_name, &self.quota_name),
            quota_limit: pick(&patch.quota_limit, &self.quota_limit),
            quota_window_millis: pick(&patch.quota_window_millis, &self.quota_window_millis),
            omit_grpc_status: pick(&patch.omit_grpc_status, &self.omit_grpc_status),
            corrupt_grpc_status: pick(&patch.corrupt_grpc_status, &self.corrupt_grpc_status),
            custom_trailers: pick(&patch.custom_trailers, &self.custom_trailers),
            abort_after_messages: pick(&patch.abort_after_messages, &self.abort_after_messages),
        }
    }

    /// `hasAnyFault`.
    pub fn has_any_fault(&self) -> bool {
        self.error_probability.is_some_and(|p| p > 0.0)
            || self.error_status_code.is_some()
            || self.latency_ms.is_some_and(|l| l > 0)
            || (self.quota_name.is_some() && self.quota_limit.is_some() && self.quota_window_millis.is_some())
            || self.omit_grpc_status == Some(true)
            || self.corrupt_grpc_status == Some(true)
            || self.custom_trailers.as_ref().is_some_and(|t| !t.is_empty())
            || self.abort_after_messages.is_some()
    }

    fn count_window_eligible(&self, match_count: u32) -> bool {
        if self.succeed_first.is_none() && self.fail_request_count.is_none() {
            return true;
        }
        let after = self.succeed_first.unwrap_or(0) as i64;
        let n = match_count as i64;
        n > after && self.fail_request_count.is_none_or(|f| n <= after + f as i64)
    }
}

struct Entry {
    profile: GrpcChaosProfile,
    expires_at: i64,
}

/// `GrpcChaosRegistry`.
#[derive(Default)]
pub struct Registry {
    by_service: Mutex<HashMap<String, Entry>>,
    match_counts: Mutex<HashMap<String, u32>>,
    backing: super::Backing,
}

/// `BACKEND_NAMESPACE` of `GrpcChaosRegistry`.
pub const NAMESPACE: &str = "chaos-grpc";

fn normalize(service: &str) -> String {
    service.trim().to_lowercase()
}

impl Registry {
    pub fn put(&self, service: &str, profile: GrpcChaosProfile, ttl_millis: i64) {
        let expires_at = if ttl_millis > 0 { now_millis().saturating_add(ttl_millis) } else { 0 };
        let key = normalize(service);
        let json = self.backing.active().then(|| profile.to_json());
        self.by_service.lock().insert(key.clone(), Entry { profile, expires_at });
        if let Some(json) = json {
            self.backing.write(&key, json, expires_at);
        }
    }

    /// `setStateBackend`: mutations write through to the clustered backend from now on.
    pub fn set_state_backend(&self, backend: &dyn crate::state_backend::StateBackend) {
        self.backing.attach(backend, NAMESPACE);
    }

    /// `reconcileFromBackend`: the local profiles become what the backend holds (those it lacks are dropped; an entry
    /// that cannot be read is skipped). A no-op single-node.
    pub fn reconcile_from_backend(&self) {
        let Some(stored) = self.backing.read() else { return };
        let fresh: HashMap<String, Entry> = stored.into_iter().filter_map(|(key, profile, expires_at)| Some((key, Entry { profile: GrpcChaosProfile::from_json(&profile).ok()?, expires_at }))).collect();
        let mut map = self.by_service.lock();
        map.retain(|k, _| fresh.contains_key(k));
        map.extend(fresh);
    }

    fn entry(&self, key: &str) -> Option<GrpcChaosProfile> {
        let mut map = self.by_service.lock();
        let entry = map.get(key)?;
        if entry.expires_at > 0 && now_millis() >= entry.expires_at {
            map.remove(key);
            return None;
        }
        Some(entry.profile.clone())
    }

    /// `get`: the service's profile, else the global (`""`) one.
    pub fn get(&self, service: &str) -> Option<GrpcChaosProfile> {
        let key = normalize(service);
        self.entry(&key).or_else(|| if key.is_empty() { None } else { self.entry("") })
    }

    fn patch(&self, service: &str, partial: &GrpcChaosProfile) -> Option<GrpcChaosProfile> {
        let key = normalize(service);
        let now = now_millis();
        let mut map = self.by_service.lock();
        let entry = match map.get(&key).filter(|e| e.expires_at == 0 || now < e.expires_at) {
            Some(existing) => Entry { profile: existing.profile.merge(partial), expires_at: existing.expires_at },
            None => Entry { profile: partial.clone(), expires_at: 0 },
        };
        let (profile, expires_at) = (entry.profile.clone(), entry.expires_at);
        map.insert(key.clone(), entry);
        drop(map);
        if self.backing.active() {
            self.backing.write(&key, profile.to_json(), expires_at);
        }
        Some(profile)
    }

    pub fn remove(&self, service: &str) {
        let key = normalize(service);
        self.by_service.lock().remove(&key);
        self.match_counts.lock().remove(&key);
        self.backing.remove(&key);
    }

    fn live(&self) -> Vec<(String, GrpcChaosProfile, i64)> {
        let now = now_millis();
        self.by_service.lock().iter().filter(|(_, e)| e.expires_at == 0 || now < e.expires_at).map(|(k, e)| (k.clone(), e.profile.clone(), e.expires_at)).collect()
    }

    /// `incrementMatchCount`.
    pub fn next_match(&self, service: &str) -> u32 {
        let mut counts = self.match_counts.lock();
        let n = counts.entry(normalize(service)).or_default();
        *n += 1;
        *n
    }

    pub fn reset(&self) {
        self.by_service.lock().clear();
        self.match_counts.lock().clear();
        self.backing.clear();
    }
}

/// `GrpcChaosDecision.GrpcFault`.
#[derive(Debug, Clone, PartialEq)]
pub struct GrpcFault {
    /// The `GrpcStatusCode` name.
    pub status_code: &'static str,
    pub message: Option<String>,
}

/// `GrpcChaosDecision.evaluate`: the status code and message to fail the call with. Upstream's `quotaRegistry` may
/// be null; here the quotas always exist (they are the server's `HttpQuotaRegistry`).
pub fn decide(quotas: &Quotas, profile: &GrpcChaosProfile, match_count: u32) -> Option<GrpcFault> {
    if !profile.count_window_eligible(match_count) {
        return None;
    }
    if let (Some(name), Some(limit), Some(window)) = (&profile.quota_name, profile.quota_limit, profile.quota_window_millis) && !quotas.try_acquire(name, limit as i64, window) {
        return Some(GrpcFault { status_code: "RESOURCE_EXHAUSTED", message: Some(profile.error_message.clone().unwrap_or_else(|| "quota exceeded".into())) });
    }
    let p = profile.error_probability.filter(|p| *p > 0.0)?;
    if !super::http::should_inject(Some(p), profile.seed) {
        return None;
    }
    let code = profile.error_status_code.as_deref().and_then(|c| STATUS_CODES.iter().find(|s| s.eq_ignore_ascii_case(c)).copied()).unwrap_or("UNAVAILABLE");
    Some(GrpcFault { status_code: code, message: profile.error_message.clone() })
}

/// A fault response from [`fault`].
pub struct Fault {
    pub(crate) reply: Reply,
    pub latency_ms: u64,
    /// The `Trailer` header when a null-valued custom trailer is announced without being written.
    pub announced: Option<String>,
}

impl Fault {
    /// The response's trailers: `grpc-status`, `grpc-message` and the custom ones, as written.
    pub fn trailers(&self) -> &[(String, String)] {
        &self.reply.trailers
    }

    /// A trailer's value.
    pub fn trailer(&self, name: &str) -> Option<&str> {
        self.reply.trailers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

/// A gRPC chaos registry with quotas of its own: `GrpcToHttpRequestHandler`'s chaos branch and `GrpcChaosDecision`
/// without a server, for the ports of their unit tests (`tests/upstream/grpc_chaos.rs`).
#[derive(Default)]
pub struct GrpcChaos {
    registry: Registry,
    quotas: Quotas,
}

impl GrpcChaos {
    pub fn new() -> GrpcChaos {
        GrpcChaos::default()
    }

    /// `GrpcChaosRegistry.put` of a profile given as JSON; `Err` carries the validation message.
    pub fn put(&self, service: &str, profile: &Value) -> Result<(), String> {
        self.registry.put(service, GrpcChaosProfile::parse(profile)?, 0);
        Ok(())
    }

    /// [`fault`] against this registry.
    pub fn fault(&self, service: &str, messages: impl FnOnce() -> usize) -> Option<Fault> {
        fault_with(&self.registry, &self.quotas, service, messages)
    }

    /// [`decide`] against these quotas.
    pub fn decide(&self, profile: &GrpcChaosProfile, match_count: u32) -> Option<GrpcFault> {
        decide(&self.quotas, profile, match_count)
    }
}

/// The chaos branch of `GrpcToHttpRequestHandler.channelRead0`: for a gRPC request whose service has a profile with
/// any fault, the fault response (`buildFaultResponse`, before `tagGrpcWebResponse`) and the `latencyMs` its write
/// is delayed by (`scheduleFaultResponse`), or `None` to serve the call normally. `messages` counts the request's
/// messages, only asked for when `abortAfterMessages` is in play (an undecodable body is 0 messages).
pub fn fault(state: &State, service: &str, messages: impl FnOnce() -> usize) -> Option<Fault> {
    fault_with(&state.chaos.grpc, &state.chaos.quotas, service, messages)
}

fn fault_with(registry: &Registry, quotas: &Quotas, service: &str, messages: impl FnOnce() -> usize) -> Option<Fault> {
    let profile = registry.get(service).filter(GrpcChaosProfile::has_any_fault)?;
    let match_count = registry.next_match(service);
    let message_or = |fallback: String| profile.error_message.clone().unwrap_or(fallback);
    let mut chosen: Option<(&str, String)> = None;
    if let Some(threshold) = profile.abort_after_messages.filter(|_| profile.count_window_eligible(match_count)) {
        let count = messages();
        if count >= threshold.max(0) as usize {
            chosen = Some(("ABORTED", message_or(format!("aborted after {count} messages"))));
        }
    }
    if chosen.is_none() {
        chosen = decide(quotas, &profile, match_count).map(|f| (f.status_code, f.message.unwrap_or_else(|| f.status_code.to_string())));
    }
    if chosen.is_none()
        && profile.count_window_eligible(match_count)
        && (profile.omit_grpc_status == Some(true) || profile.corrupt_grpc_status == Some(true) || profile.custom_trailers.as_ref().is_some_and(|t| !t.is_empty()))
    {
        chosen = Some(("INTERNAL", message_or("chaos fault".into())));
    }
    let (code, message) = chosen?;
    let mut reply = Reply::status(200);
    reply.headers.push(("content-type".into(), crate::grpc_plane::CONTENT_TYPE.into()));
    if profile.omit_grpc_status == Some(true) {
        // no grpc-status: a broken, incomplete RPC
    } else {
        let status = if profile.corrupt_grpc_status == Some(true) {
            "malformed".to_string()
        } else {
            STATUS_CODES.iter().position(|c| *c == code).unwrap_or(0).to_string()
        };
        reply.trailers.push(("grpc-status".into(), status));
        reply.trailers.push(("grpc-message".into(), crate::grpc_plane::percent_encode(&message)));
    }
    // A null value is announced in the `Trailer` header but not written (`setTrailers` skips it).
    let mut announced: Vec<String> = reply.trailers.iter().map(|(n, _)| n.clone()).collect();
    let mut null_valued = false;
    for (key, value) in profile.custom_trailers.iter().flatten() {
        if key.is_empty() || key.contains(['\r', '\n']) || value.as_deref().is_some_and(|v| v.contains(['\r', '\n'])) {
            continue;
        }
        announced.push(key.clone());
        match value {
            Some(v) => reply.trailers.push((key.clone(), v.clone())),
            None => null_valued = true,
        }
    }
    let announced = if null_valued && !reply.trailers.is_empty() { Some(announced.join(", ")) } else { None };
    Some(Fault { reply, latency_ms: profile.latency_ms.filter(|l| *l > 0).unwrap_or(0) as u64, announced })
}

/// `handleGrpcChaosPut` / `Patch` / `Get`.
pub fn route(state: &State, request: &HttpRequest) -> Option<Reply> {
    let registry = &state.chaos.grpc;
    let body = request.body_json_or_xml_str();
    let service_of = |node: &Value| node.get("service").map(|s| match s {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    });
    Some(match request.method.as_str() {
        "PUT" => {
            if body.trim().is_empty() {
                return Some(error("request body is required with a 'service' field (and a 'chaos' object), or 'clear':true to clear all"));
            }
            let node = match read_tree(&body, true) {
                Ok(v) => v,
                Err(e) => return Some(error(&format!("failed to process gRPC chaos request: {e}"))),
            };
            let clear = as_boolean(node.get("clear"));
            let service = service_of(&node);
            if clear && service.is_some() {
                return Some(error("cannot specify both 'clear' and 'service'"));
            }
            if clear {
                registry.reset();
                log(state, request, crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, "cleared all gRPC chaos"));
                return Some(pretty(&json!({"status": "cleared"})));
            }
            let Some(service) = service else { return Some(error("'service' field is required")) };
            let chaos = node.get("chaos").filter(|c| !c.is_null());
            if as_boolean(node.get("remove")) || chaos.is_none() {
                registry.remove(&service);
                log(state, request, crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, "removed gRPC chaos for service:{}").args([&service]));
                return Some(pretty(&json!({"status": "removed", "service": service})));
            }
            let mut ttl = 0;
            if node.get("ttlMillis").is_some_and(|t| !t.is_null()) {
                ttl = as_long(node.get("ttlMillis"));
                if ttl < 1 {
                    return Some(error("'ttlMillis' must be >= 1 when supplied"));
                }
            }
            let profile = match GrpcChaosProfile::from_json(chaos.unwrap()) {
                Ok(p) => p,
                Err(ProfileError::Invalid(e)) => return Some(error(&format!("invalid gRPC chaos profile: {e}"))),
                Err(e) => return Some(error(&format!("failed to process gRPC chaos request: {}", e.text()))),
            };
            registry.put(&service, profile, ttl);
            if ttl > 0 {
                log(state, request, crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, format!("registered gRPC chaos (ttl {ttl}ms) for service:{{}}")).args([&service]));
                pretty(&json!({"status": "registered", "service": service, "ttlMillis": ttl}))
            } else {
                log(state, request, crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, "registered gRPC chaos for service:{}").args([&service]));
                pretty(&json!({"status": "registered", "service": service}))
            }
        }
        "PATCH" => {
            if body.trim().is_empty() {
                return Some(error("request body is required with 'service' and 'chaos' fields"));
            }
            let node = match read_tree(&body, true) {
                Ok(v) => v,
                Err(e) => return Some(error(&format!("failed to process gRPC chaos patch: {e}"))),
            };
            let Some(service) = service_of(&node) else { return Some(error("'service' field is required")) };
            let Some(chaos) = node.get("chaos").filter(|c| !c.is_null()) else {
                return Some(error("'chaos' field is required with at least one field to patch"));
            };
            let partial = match GrpcChaosProfile::from_json(chaos) {
                Ok(p) => p,
                Err(ProfileError::Invalid(e)) => return Some(error(&format!("invalid gRPC chaos profile: {e}"))),
                Err(e) => return Some(error(&format!("failed to process gRPC chaos patch: {}", e.text()))),
            };
            let updated = registry.patch(&service, &partial);
            log(state, request, crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, "patched gRPC chaos for service:{}").args([&service]));
            let mut o = Map::new();
            o.insert("status".into(), json!("patched"));
            o.insert("service".into(), json!(service));
            if let Some(p) = updated {
                o.insert("chaos".into(), p.to_json());
            }
            pretty(&Value::Object(o))
        }
        "GET" => {
            let now = now_millis();
            let live = super::in_hashmap_order(registry.live().into_iter().map(|(k, p, e)| (k, (p, e))).collect());
            let services: Map<String, Value> = live.iter().map(|(k, (p, _))| (k.clone(), p.to_json())).collect();
            let ttl: Map<String, Value> = live.iter().filter(|(_, (_, e))| *e > 0).map(|(k, (_, e))| (k.clone(), json!(e - now))).collect();
            let mut o = Map::new();
            o.insert("services".into(), Value::Object(services));
            if !ttl.is_empty() {
                o.insert("ttlRemainingMillis".into(), Value::Object(ttl));
            }
            pretty(&Value::Object(o))
        }
        _ => return None,
    })
}

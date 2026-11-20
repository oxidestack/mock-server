//! Chaos (`docs/code/chaos.md`): host-scoped TCP chaos (`TcpChaosRegistry`, `/mockserver/tcpChaos`), host-scoped
//! HTTP chaos for forwards (`ServiceChaosRegistry`, `/mockserver/serviceChaos`), per-expectation HTTP chaos, the
//! preemption simulation (`/mockserver/preemption`) and the auto-halt circuit-breaker.
//!
//! A TCP chaos profile is registered per host. Connect-time faults (`TcpChaosHandler`, [`io`]) look it up by the
//! client's address; response-path faults (`resetMidResponse`, `slowCloseDelay`, `http2GoAway`, in
//! `NettyResponseWriter`) look it up by the request's `Host` header, and only while `connectionLifecycleChaosEnabled`.
//! The preemption simulation cordons the data plane: new exchanges get a 503 (`reject503`), an HTTP/2 GOAWAY
//! (`goaway`), or both.

pub mod bind;
pub mod experiment;
pub mod grpc;
pub mod http;
pub mod io;
pub mod preemption;
pub mod tcp;

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use bind::BindError;
pub use http::HttpChaosProfile;
pub use preemption::Preemption;
pub use tcp::{TcpChaosProfile, apply_lifecycle, lifecycle_profile};

use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state_backend::{KeyValueStore, StateBackend};
use crate::state::State;

/// `TimeService.currentTimeMillis()`: the current server's clock.
pub(crate) fn now_millis() -> i64 {
    crate::clock::now_millis()
}

pub enum ProfileError {
    /// A `withX` range check (`IllegalArgumentException`).
    Invalid(String),
    /// Jackson could not bind the value.
    Mapping(BindError),
}

impl From<BindError> for ProfileError {
    fn from(e: BindError) -> ProfileError {
        ProfileError::Mapping(e)
    }
}

impl ProfileError {
    /// The message as `ObjectMapper.treeToValue` (mapping) or the setter (range) words it.
    pub fn text(&self) -> String {
        match self {
            ProfileError::Invalid(m) => m.clone(),
            ProfileError::Mapping(e) => e.tree_text(),
        }
    }
}

/// How a host-scoped registry's endpoint words its messages.
pub struct Wording {
    /// "TCP-layer chaos" / "service-scoped chaos", in the log lines.
    pub what: &'static str,
    /// Prefix of a range-check error.
    pub invalid: &'static str,
    /// "TCP chaos" / "service chaos", in "failed to process … request".
    pub failed: &'static str,
    /// The `GET` body's map of profiles by host.
    pub list_key: &'static str,
}

/// The clustered half of a chaos registry (`setStateBackend`, `writeToBackend`, `removeFromBackend`, `clearBackend`):
/// with a clustered backend, mutations write through to its `crudEntities(<namespace>)` store as
/// `{"profile": <DTO>, "expiresAtMillis": n}`, and [`Backing::read`] is what `reconcileFromBackend` rebuilds from. A
/// registry never reads the backend on a lookup, so a profile registered on another node is only seen once the
/// invalidation listener has reconciled.
#[derive(Default)]
pub struct Backing {
    store: OnceLock<Arc<dyn KeyValueStore<Value>>>,
}

impl Backing {
    /// `setStateBackend`: a no-op unless the backend is clustered.
    pub fn attach(&self, backend: &dyn StateBackend, namespace: &str) {
        if backend.is_clustered() {
            let _ = self.store.set(backend.crud_entities(namespace));
        }
    }

    /// `true` once a clustered backend is attached.
    pub(crate) fn active(&self) -> bool {
        self.store.get().is_some()
    }

    fn write(&self, key: &str, profile: Value, expires_at: i64) {
        if let Some(store) = self.store.get() {
            let node = json!({"profile": profile, "expiresAtMillis": expires_at});
            if let Err(e) = store.try_put(key, node) {
                eprintln!("WARN failed to write chaos to backend for key={key}: {e}");
            }
        }
    }

    fn remove(&self, key: &str) {
        if let Some(store) = self.store.get() {
            store.remove(key);
        }
    }

    fn clear(&self) {
        if let Some(store) = self.store.get() {
            store.clear();
        }
    }

    /// The stored entries as `(key, profile DTO, expiresAtMillis)`; `None` single-node. An entry without a `profile`
    /// node is skipped, as upstream's failed deserialisation is.
    fn read(&self) -> Option<Vec<(String, Value, i64)>> {
        let store = self.store.get()?;
        Some(
            store
                .entries()
                .into_iter()
                .filter_map(|(key, entry)| {
                    let profile = entry.value.get("profile").filter(|p| !p.is_null())?.clone();
                    Some((key, profile, as_long(entry.value.get("expiresAtMillis"))))
                })
                .collect(),
        )
    }
}

/// A profile a [`HostRegistry`] holds.
pub trait HostProfile: Clone {
    const WORDING: Wording;
    /// `BACKEND_NAMESPACE` of the registry.
    const NAMESPACE: &'static str;
    fn from_json(v: &Value) -> Result<Self, ProfileError>;
    fn to_json(&self) -> Value;
    /// `merge`: each field `patch` sets replaces this one's.
    fn merge(&self, patch: &Self) -> Self;
    /// `hasAnyFault`, which `activeCount` counts.
    fn has_any_fault(&self) -> bool;
}

struct Entry<P> {
    profile: P,
    /// 0: never expires.
    expires_at: i64,
}

impl<P> Entry<P> {
    fn expired(&self, now: i64) -> bool {
        self.expires_at > 0 && now >= self.expires_at
    }
}

/// `TcpChaosRegistry` / `ServiceChaosRegistry`: profiles by normalised host, each with an optional TTL.
pub struct HostRegistry<P> {
    by_host: Mutex<HashMap<String, Entry<P>>>,
    backing: Backing,
}

impl<P> Default for HostRegistry<P> {
    fn default() -> Self {
        HostRegistry { by_host: Mutex::default(), backing: Backing::default() }
    }
}

/// `normalizeHost`: trimmed, the port stripped (`HttpRequest.splitHostPort`), lower-cased.
pub fn normalize_host(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some(rest) = trimmed.strip_prefix('[') && let Some(end) = rest.find(']').filter(|e| *e > 0) {
        return rest[..end].to_lowercase();
    }
    // `String.split(":")` drops trailing empty parts; when nothing is left the whole string is used.
    let parts: Vec<&str> = trimmed.split(':').collect();
    let kept = parts.iter().rposition(|p| !p.is_empty()).map_or(0, |i| i + 1);
    if kept == 0 { trimmed.to_lowercase() } else { parts[0].to_lowercase() }
}

impl<P: HostProfile> HostRegistry<P> {
    pub fn put(&self, host: &str, profile: P, ttl_millis: i64) {
        let key = normalize_host(host);
        if key.is_empty() {
            return;
        }
        let expires_at = if ttl_millis > 0 { now_millis().saturating_add(ttl_millis) } else { 0 };
        let json = self.backing.active().then(|| profile.to_json());
        self.by_host.lock().insert(key.clone(), Entry { profile, expires_at });
        if let Some(json) = json {
            self.backing.write(&key, json, expires_at);
        }
    }

    /// `setStateBackend`: mutations write through to the clustered backend from now on.
    pub fn set_state_backend(&self, backend: &dyn StateBackend) {
        self.backing.attach(backend, P::NAMESPACE);
    }

    /// `reconcileFromBackend`: the local profiles become what the backend holds (those it lacks are dropped; an entry
    /// that cannot be read is skipped). A no-op single-node.
    pub fn reconcile_from_backend(&self) {
        let Some(stored) = self.backing.read() else { return };
        let fresh: HashMap<String, Entry<P>> = stored.into_iter().filter_map(|(key, profile, expires_at)| Some((key, Entry { profile: P::from_json(&profile).ok()?, expires_at }))).collect();
        let mut map = self.by_host.lock();
        map.retain(|k, _| fresh.contains_key(k));
        map.extend(fresh);
    }

    /// The live profile for `host`; an expired one is dropped.
    pub fn get(&self, host: &str) -> Option<P> {
        let key = normalize_host(host);
        let mut map = self.by_host.lock();
        let entry = map.get(&key)?;
        if entry.expired(now_millis()) {
            map.remove(&key);
            return None;
        }
        Some(entry.profile.clone())
    }

    /// `patch`: merges into a live profile (keeping its expiry), or registers `partial` without a TTL.
    pub fn patch(&self, host: &str, partial: &P) -> Option<P> {
        let key = normalize_host(host);
        if key.is_empty() {
            return None;
        }
        let now = now_millis();
        let mut map = self.by_host.lock();
        let entry = match map.get(&key).filter(|e| !e.expired(now)) {
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

    pub fn remove(&self, host: &str) {
        let key = normalize_host(host);
        self.by_host.lock().remove(&key);
        self.backing.remove(&key);
    }

    /// Live entries, in `java.util.HashMap` iteration order.
    pub fn entries(&self) -> Vec<(String, P)> {
        let now = now_millis();
        let map = self.by_host.lock();
        let live: Vec<(String, P)> = map.iter().filter(|(_, e)| !e.expired(now)).map(|(k, e)| (k.clone(), e.profile.clone())).collect();
        in_hashmap_order(live)
    }

    pub fn is_empty(&self) -> bool {
        let now = now_millis();
        !self.by_host.lock().values().any(|e| !e.expired(now))
    }

    /// Remaining TTL of each live entry that has one, in `java.util.HashMap` iteration order.
    pub fn ttl_remaining_millis(&self) -> Vec<(String, i64)> {
        let now = now_millis();
        let map = self.by_host.lock();
        let live: Vec<(String, i64)> = map.iter().filter(|(_, e)| e.expires_at > 0 && !e.expired(now)).map(|(k, e)| (k.clone(), e.expires_at - now)).collect();
        in_hashmap_order(live)
    }

    /// `activeCount`: live entries with at least one fault.
    pub fn active_count(&self) -> usize {
        let now = now_millis();
        self.by_host.lock().values().filter(|e| !e.expired(now) && e.profile.has_any_fault()).count()
    }

    pub fn reset(&self) {
        self.by_host.lock().clear();
        self.backing.clear();
    }
}

fn in_hashmap_order<T>(mut items: Vec<(String, T)>) -> Vec<(String, T)> {
    // Keys are unique, so sorting first makes collisions within a bucket deterministic.
    items.sort_by(|a, b| a.0.cmp(&b.0));
    let keys: Vec<String> = items.iter().map(|(k, _)| k.clone()).collect();
    let order = crate::recorded::java_hashmap_order(&keys);
    let mut slots: Vec<Option<(String, T)>> = items.into_iter().map(Some).collect();
    order.into_iter().filter_map(|i| slots[i].take()).collect()
}

/// Everything chaos keeps; `reset` clears all of it.
#[derive(Default)]
pub struct Chaos {
    pub tcp: HostRegistry<TcpChaosProfile>,
    pub service: HostRegistry<HttpChaosProfile>,
    pub quotas: http::Quotas,
    /// `RecoveryAttemptRegistry` (`recoverAfter` with an idempotency header).
    pub recovery: http::RecoveryAttempts,
    pub auto_halt: http::AutoHalt,
    pub preemption: Preemption,
    pub experiments: experiment::Experiments,
    pub grpc: grpc::Registry,
}

impl Chaos {
    /// `HttpState.reset`: the experiment stops and its history goes; saved profiles stay.
    pub fn reset(&self, state: &State) {
        self.experiments.reset(state);
        self.grpc.reset();
        self.tcp.reset();
        self.service.reset();
        self.quotas.reset();
        self.recovery.reset();
        self.auto_halt.reset();
        self.preemption.uncordon();
    }
}

// --- Jackson `JsonNode` accessors -------------------------------------------------------------------------------

/// `JsonNode.asText(null)`: scalars as text, containers as "", missing or null as `None`.
pub(crate) fn as_text(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => Some(String::new()),
    }
}

/// `JsonNode.asBoolean(false)`.
pub(crate) fn as_boolean(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_i64().is_some_and(|i| i != 0),
        Some(Value::String(s)) => s.trim() == "true",
        _ => false,
    }
}

/// `JsonNode.asLong(0)`.
pub(crate) fn as_long(v: Option<&Value>) -> i64 {
    match v {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        Some(Value::Bool(b)) => *b as i64,
        _ => 0,
    }
}

/// `ObjectMapper.readTree(String)` (`tree`) or the bean path of `readValue`, which word a misplaced `}` differently.
pub(crate) fn read_tree(body: &str, tree: bool) -> Result<Value, String> {
    let lenient = jackson::json::ReadFeatures {
        allow_unquoted_field_names: true,
        allow_single_quotes: true,
        tree_member_values: tree,
        allow_non_numeric_numbers: true,
        ..Default::default()
    };
    jackson::json::read_tree(body, lenient).map_err(|e| e.to_string())?;
    crate::json::parse_lenient(body.as_bytes()).map_err(|e| e.to_string())
}

pub(crate) fn pretty(v: &Value) -> Reply {
    Reply::api_body(200, "application/json", crate::json::pretty(v))
}

pub(crate) fn error(message: &str) -> Reply {
    Reply::api_body(400, "application/json", crate::json::pretty(&json!({"error": message})))
}

/// A `SERVER_CONFIGURATION` INFO event about `request`.
pub(crate) fn log(state: &State, request: &HttpRequest, entry: crate::recorded::LogEntry) {
    if state.info_enabled() {
        crate::log::entry_as(state, crate::recorded::Level::Info, &entry);
        state.log.message_about(entry.request(request), crate::recorded::Subject::Request(std::sync::Arc::new(request.clone())));
    }
}

fn log_host(state: &State, request: &HttpRequest, format: &str, host: &str) {
    log(state, request, crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, format).args([host]));
}

/// The control-plane routes chaos owns, with their bare aliases.
pub fn route(state: &std::sync::Arc<State>, request: &HttpRequest, op: &str) -> Option<Reply> {
    if let Some(reply) = experiment_route(state, request, op) {
        return Some(reply);
    }
    if op == "/grpcChaos" {
        return grpc::route(state, request);
    }
    Some(match (request.method.as_str(), op) {
        ("PUT", "/tcpChaos") => host_put(state, request, &state.chaos.tcp),
        ("GET", "/tcpChaos") => host_get(&state.chaos.tcp),
        ("PATCH", "/tcpChaos") => host_patch(state, request, &state.chaos.tcp),
        ("PUT", "/serviceChaos") => host_put(state, request, &state.chaos.service),
        ("GET", "/serviceChaos") => host_get(&state.chaos.service),
        ("PATCH", "/serviceChaos") => host_patch(state, request, &state.chaos.service),
        ("PUT", "/preemption") => preemption::put(state, request),
        ("GET", "/preemption") => pretty(&state.chaos.preemption.status(state)),
        ("DELETE", "/preemption") => {
            state.chaos.preemption.uncordon();
            Reply::api_body(200, "application/json", r#"{"state":"inactive"}"#)
        }
        _ => return None,
    })
}

/// Whether `route` answers this method and operation.
pub fn owns(method: &str, op: &str) -> bool {
    matches!((method, op), ("PUT" | "GET" | "PATCH", "/tcpChaos" | "/serviceChaos" | "/grpcChaos") | ("PUT" | "GET" | "DELETE", "/preemption"))
        || matches!((method, op), ("PUT" | "GET" | "DELETE", "/chaosExperiment") | ("GET", "/chaosExperiment/profiles" | "/chaosExperiment/history"))
        || (matches!(method, "PUT" | "GET" | "DELETE") && profile_name(op, "/chaosExperiment/profiles/").is_some())
        || (method == "POST" && profile_name(op, "/chaosExperiment/apply/").is_some())
}

/// `chaosProfileName`: the URL-decoded segment after `prefix`, when it is one non-empty segment.
fn profile_name(op: &str, prefix: &str) -> Option<String> {
    let rest = op.strip_prefix(prefix).filter(|r| !r.is_empty() && !r.contains('/'))?;
    Some(url_decode(rest))
}

/// `URLDecoder.decode` (UTF-8), or the raw text when its escapes are malformed (the callers catch the
/// `IllegalArgumentException`).
pub(crate) fn url_decode(s: &str) -> String {
    crate::java_text::url_decode(s, crate::java_text::UrlCharset::Utf8).unwrap_or_else(|_| s.to_string())
}

/// `/mockserver/chaosExperiment` and its profile library.
fn experiment_route(state: &std::sync::Arc<State>, request: &HttpRequest, op: &str) -> Option<Reply> {
    let experiments = &state.chaos.experiments;
    let method = request.method.as_str();
    let not_found = |name: &str| Reply::api_body(404, "application/json", crate::json::pretty(&json!({"error": format!("no chaos profile named '{name}'")})));
    let started = |d: &experiment::Definition| pretty(&json!({"status": "started", "name": d.name, "stages": d.stage_count(), "loop": d.loop_}));
    Some(match (method, op) {
        ("PUT", "/chaosExperiment") => {
            let body = request.body_json_or_xml_str();
            if body.trim().is_empty() {
                return Some(error("request body is required with an experiment definition"));
            }
            let definition = match read_tree(&body, true).map_err(|e| format!("failed to process chaos experiment request: {e}")).and_then(|node| {
                experiment::Definition::from_json(&node).map_err(|e| format!("invalid experiment definition: {e}"))
            }) {
                Ok(d) => d,
                Err(e) => return Some(error(&e)),
            };
            if let Err(e) = experiments.start(state, definition.clone()) {
                return Some(error(&e));
            }
            log(state, request, crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, "started chaos experiment:{}").args([definition.name.as_deref().unwrap_or("null")]));
            started(&definition)
        }
        ("GET", "/chaosExperiment") => pretty(&experiments.status().unwrap_or_else(|| json!({"status": "none"}))),
        ("GET", "/chaosExperiment/history") => {
            let history = experiments.history();
            pretty(&json!({"count": history.len(), "history": history}))
        }
        ("DELETE", "/chaosExperiment") => {
            experiments.stop(state);
            if state.info_enabled() {
                crate::log::info(state, "stopped chaos experiment");
                state.log.message(crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, "stopped chaos experiment"));
            }
            pretty(&json!({"status": "stopped"}))
        }
        ("GET", "/chaosExperiment/profiles") => pretty(&json!({"profiles": experiments.profile_names()})),
        _ => {
            if method == "POST" {
                let name = profile_name(op, "/chaosExperiment/apply/")?;
                let Some(saved) = experiments.profile(&name) else { return Some(not_found(&name)) };
                let definition = match experiment::Definition::from_json(&saved) {
                    Ok(d) => d,
                    Err(e) => return Some(error(&format!("invalid saved chaos profile: {e}"))),
                };
                if let Err(e) = experiments.start(state, definition.clone()) {
                    return Some(error(&e));
                }
                log(state, request, crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, "applied saved chaos profile:{}").args([&name]));
                return Some(started(&definition));
            }
            let name = profile_name(op, "/chaosExperiment/profiles/")?;
            match method {
                "PUT" => {
                    let body = request.body_json_or_xml_str();
                    if body.trim().is_empty() {
                        return Some(error("request body is required with a chaos profile (experiment) definition"));
                    }
                    let node = match read_tree(&body, true) {
                        Ok(n) => n,
                        Err(e) => return Some(error(&format!("failed to save chaos profile: {e}"))),
                    };
                    if let Err(e) = experiment::Definition::from_json(&node).and_then(|_| experiments.save_profile(&name, &node)) {
                        return Some(error(&format!("invalid chaos profile: {e}")));
                    }
                    log(state, request, crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, "saved chaos profile:{}").args([&name]));
                    pretty(&json!({"status": "saved", "name": name}))
                }
                "GET" => match experiments.profile(&name) {
                    Some(p) => pretty(&p),
                    None => not_found(&name),
                },
                "DELETE" => {
                    let removed = experiments.delete_profile(&name);
                    pretty(&json!({"status": if removed { "deleted" } else { "absent" }, "name": name}))
                }
                _ => return None,
            }
        }
    })
}

/// `handleTcpChaosPut` / `handleServiceChaosPut`.
fn host_put<P: HostProfile>(state: &State, request: &HttpRequest, registry: &HostRegistry<P>) -> Reply {
    let w = P::WORDING;
    let body = request.body_json_or_xml_str();
    if body.trim().is_empty() {
        return error("request body is required with a 'host' field (and a 'chaos' object), or 'clear':true to clear all");
    }
    let node = match read_tree(&body, true) {
        Ok(v) => v,
        Err(e) => return error(&format!("failed to process {} request: {e}", w.failed)),
    };
    let clear = as_boolean(node.get("clear"));
    let host = as_text(node.get("host")).filter(|h| !h.trim().is_empty());
    if clear && host.is_some() {
        return error("cannot specify both 'clear' and 'host'");
    }
    if clear {
        registry.reset();
        log(state, request, crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, format!("cleared all {}", w.what)));
        return pretty(&json!({"status": "cleared"}));
    }
    let Some(host) = host else { return error("'host' field is required") };
    let chaos = node.get("chaos").filter(|c| !c.is_null());
    if as_boolean(node.get("remove")) || chaos.is_none() {
        registry.remove(&host);
        log_host(state, request, &format!("removed {} for host:{{}}", w.what), &host);
        return pretty(&json!({"status": "removed", "host": host}));
    }
    let mut ttl_millis = 0;
    if node.get("ttlMillis").is_some_and(|t| !t.is_null()) {
        ttl_millis = as_long(node.get("ttlMillis"));
        if ttl_millis < 1 {
            return error("'ttlMillis' must be >= 1 when supplied");
        }
    }
    let profile = match P::from_json(chaos.unwrap()) {
        Ok(p) => p,
        Err(ProfileError::Invalid(e)) => return error(&format!("{}: {e}", w.invalid)),
        Err(e @ ProfileError::Mapping(_)) => return error(&format!("failed to process {} request: {}", w.failed, e.text())),
    };
    registry.put(&host, profile, ttl_millis);
    if ttl_millis > 0 {
        log_host(state, request, &format!("registered {} (ttl {ttl_millis}ms) for host:{{}}", w.what), &host);
        pretty(&json!({"status": "registered", "host": host, "ttlMillis": ttl_millis}))
    } else {
        log_host(state, request, &format!("registered {} for host:{{}}", w.what), &host);
        pretty(&json!({"status": "registered", "host": host}))
    }
}

/// `handleTcpChaosPatch` / `handleServiceChaosPatch`.
fn host_patch<P: HostProfile>(state: &State, request: &HttpRequest, registry: &HostRegistry<P>) -> Reply {
    let w = P::WORDING;
    let body = request.body_json_or_xml_str();
    if body.trim().is_empty() {
        return error("request body is required with 'host' and 'chaos' fields");
    }
    let node = match read_tree(&body, true) {
        Ok(v) => v,
        Err(e) => return error(&format!("failed to process {} patch: {e}", w.failed)),
    };
    let Some(host) = as_text(node.get("host")).filter(|h| !h.trim().is_empty()) else { return error("'host' field is required") };
    let Some(chaos) = node.get("chaos").filter(|c| !c.is_null()) else {
        return error("'chaos' field is required with at least one field to patch");
    };
    let partial = match P::from_json(chaos) {
        Ok(p) => p,
        Err(ProfileError::Invalid(e)) => return error(&format!("{}: {e}", w.invalid)),
        Err(e @ ProfileError::Mapping(_)) => return error(&format!("failed to process {} patch: {}", w.failed, e.text())),
    };
    let updated = registry.patch(&host, &partial);
    log_host(state, request, &format!("patched {} for host:{{}}", w.what), &host);
    let mut o = Map::new();
    o.insert("status".into(), json!("patched"));
    o.insert("host".into(), json!(host));
    if let Some(p) = updated {
        o.insert("chaos".into(), p.to_json());
    }
    pretty(&Value::Object(o))
}

/// `handleTcpChaosGet` / `handleServiceChaosGet`.
fn host_get<P: HostProfile>(registry: &HostRegistry<P>) -> Reply {
    let mut hosts = Map::new();
    for (host, profile) in registry.entries() {
        hosts.insert(host, profile.to_json());
    }
    let mut o = Map::new();
    o.insert(P::WORDING.list_key.into(), Value::Object(hosts));
    let ttl = registry.ttl_remaining_millis();
    if !ttl.is_empty() {
        o.insert("ttlRemainingMillis".into(), Value::Object(ttl.into_iter().map(|(k, v)| (k, json!(v))).collect()));
    }
    pretty(&Value::Object(o))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_hosts_like_split_host_port() {
        assert_eq!(normalize_host(" Payments.SVC:8443 "), "payments.svc");
        assert_eq!(normalize_host("[::1]:80"), "::1");
        assert_eq!(normalize_host("::1"), "");
        assert_eq!(normalize_host("::"), "::");
        assert_eq!(normalize_host("a:"), "a");
    }

    #[test]
    fn patch_keeps_expiry_and_merges() {
        let r = HostRegistry::<TcpChaosProfile>::default();
        r.put("h", TcpChaosProfile { latency_ms: Some(5), down: Some(true), ..Default::default() }, 60_000);
        let merged = r.patch("H:1", &TcpChaosProfile { down: Some(false), ..Default::default() }).unwrap();
        assert_eq!(merged.latency_ms, Some(5));
        assert_eq!(merged.down, Some(false));
        assert_eq!(r.ttl_remaining_millis().len(), 1);
    }
}

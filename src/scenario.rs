//! Scenario states (`ScenarioManager`): an expectation with a `scenarioName` and `scenarioState` matches only while
//! the scenario is in that state, and moves it to `newScenarioState` when it serves. States start as `Started`, can
//! be read and set over `/mockserver/scenario`, and are what `scenario.get` sees in templates.
//!
//! One [`Scenarios`] and one [`CrossProtocolBus`] per server (`RequestMatchers`' `ScenarioManager` and the
//! `CrossProtocolEventBus` `HttpState` wires to it), owned by the expectation store. With a clustered state backend the states are the backend's replicated
//! `scenarioStates` and the bus's registrations replicate through `crud-cross-protocol-bus`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;
use crate::state_backend::{KeyValueStore, StateBackend};

pub const STARTED: &str = "Started";

#[derive(Default)]
struct States {
    /// `ScenarioKey.toString()` → state, in insertion order.
    states: Vec<(String, String)>,
}

/// `CrossProtocolTrigger`: the events that can move a scenario. DNS and gRPC events are never fired here (no DNS
/// server; upstream fires none for gRPC either), so their registrations stay inert as upstream's would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    DnsQuery,
    WebSocketConnect,
    GrpcRequest,
    HttpRequest,
}

impl Trigger {
    fn parse(name: &str) -> Option<Trigger> {
        Some(match name {
            "DNS_QUERY" => Trigger::DnsQuery,
            "WEBSOCKET_CONNECT" => Trigger::WebSocketConnect,
            "GRPC_REQUEST" => Trigger::GrpcRequest,
            "HTTP_REQUEST" => Trigger::HttpRequest,
            _ => return None,
        })
    }

    /// The enum constant's name (`CrossProtocolTrigger.name()`).
    pub fn name(self) -> &'static str {
        match self {
            Trigger::DnsQuery => "DNS_QUERY",
            Trigger::WebSocketConnect => "WEBSOCKET_CONNECT",
            Trigger::GrpcRequest => "GRPC_REQUEST",
            Trigger::HttpRequest => "HTTP_REQUEST",
        }
    }
}

/// A `CrossProtocolEventBus` registration (`CrossProtocolScenario`): on its trigger's event, when the event's
/// identifier contains `matchPattern` (always without one), the scenario moves to `targetState`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossProtocolScenario {
    pub trigger: Trigger,
    pub scenario_name: Option<String>,
    pub target_state: Option<String>,
    pub match_pattern: Option<String>,
}

impl CrossProtocolScenario {
    fn build(trigger: Trigger, pattern: Option<&str>, scenario: &str, target: &str) -> Self {
        CrossProtocolScenario { trigger, scenario_name: Some(scenario.into()), target_state: Some(target.into()), match_pattern: pattern.map(str::to_string) }
    }

    /// `CrossProtocolScenario.onDnsQuery`.
    pub fn on_dns_query(query_name: &str, scenario: &str, target: &str) -> Self {
        Self::build(Trigger::DnsQuery, Some(query_name), scenario, target)
    }

    /// `CrossProtocolScenario.onWebSocketConnect`.
    pub fn on_web_socket_connect(scenario: &str, target: &str) -> Self {
        Self::build(Trigger::WebSocketConnect, None, scenario, target)
    }

    /// `CrossProtocolScenario.onGrpcRequest`.
    pub fn on_grpc_request(service: &str, scenario: &str, target: &str) -> Self {
        Self::build(Trigger::GrpcRequest, Some(service), scenario, target)
    }

    /// `CrossProtocolScenario.onHttpPath`.
    pub fn on_http_path(path_pattern: &str, scenario: &str, target: &str) -> Self {
        Self::build(Trigger::HttpRequest, Some(path_pattern), scenario, target)
    }

    /// `CrossProtocolEventBus.backendKey`: `<trigger>|<len>:<name>:<len>:<state>:<len>:<pattern>`, lengths in UTF-16
    /// units, a null component as the empty string.
    pub fn backend_key(&self) -> String {
        let part = |v: &Option<String>| {
            let v = v.as_deref().unwrap_or("");
            format!("{}:{v}", v.encode_utf16().count())
        };
        format!("{}|{}:{}:{}", self.trigger.name(), part(&self.scenario_name), part(&self.target_state), part(&self.match_pattern))
    }

    /// The `ObjectNode` `writeToBackend` stores.
    fn backend_node(&self) -> Value {
        let mut node = serde_json::Map::new();
        node.insert("trigger".into(), self.trigger.name().into());
        node.insert("scenarioName".into(), self.scenario_name.clone().map_or(Value::Null, Value::from));
        if let Some(t) = &self.target_state {
            node.insert("targetState".into(), t.clone().into());
        }
        if let Some(p) = &self.match_pattern {
            node.insert("matchPattern".into(), p.clone().into());
        }
        Value::Object(node)
    }

    /// `reconcileFromBackend`'s read of one stored node (`None`: it would throw, upstream warns and skips the entry).
    fn from_backend_node(node: &Value) -> Option<Self> {
        let trigger = Trigger::parse(node.get("trigger")?.as_str()?)?;
        let text = |v: &Value| crate::chaos::as_text(Some(v)).unwrap_or_default();
        // `JsonNode.asText()` of a null node is "null"
        let scenario_name = Some(match node.get("scenarioName")? {
            Value::Null => "null".to_string(),
            v => text(v),
        });
        Some(CrossProtocolScenario { trigger, scenario_name, target_state: node.get("targetState").map(text), match_pattern: node.get("matchPattern").map(text) })
    }
}

/// `ScenarioManager`: one per server. Single-node, the states live here; with a clustered state backend they are
/// read from and written to the backend's replicated `scenarioStates` store with no node-local copy, so a
/// transition is a compare-and-set across the fleet.
#[derive(Default)]
pub struct Scenarios {
    local: Mutex<States>,
    /// `pendingTransitions`: the one pending timed transition per scenario, by a never-reused id, and its task.
    pending: Mutex<HashMap<String, (u64, Option<tokio::task::AbortHandle>)>>,
    /// The id of the next scheduled transition.
    next_transition: std::sync::atomic::AtomicU64,
    /// The clustered backend whose `scenarioStates` the states are.
    cluster: OnceLock<Arc<dyn StateBackend>>,
    /// Counts the writes to `scenarioStates`, each of which fires the state backend's invalidation listener (also the
    /// expectation store's: `Store` trims its unbacked expectations when this moves).
    writes: std::sync::atomic::AtomicU64,
}

/// `CrossProtocolEventBus`: protocol events moving scenario states, one per server (upstream's is a JVM singleton
/// that `HttpState` points at its own `ScenarioManager`). Clustered, its registrations replicate through the
/// backend's `cross-protocol-bus` CRUD store.
#[derive(Default)]
pub struct CrossProtocolBus {
    listeners: Mutex<Vec<CrossProtocolScenario>>,
    scenarios: Mutex<Option<Arc<Scenarios>>>,
    store: OnceLock<Arc<dyn KeyValueStore<Value>>>,
}

/// `BACKEND_NAMESPACE` of `CrossProtocolEventBus`.
pub const BUS_NAMESPACE: &str = "cross-protocol-bus";

thread_local! {
    /// The scenarios the template being rendered on this thread reads and writes (`scenario.get`, `scenario.set`).
    /// Rendering is synchronous, so the scope of [`Scenarios::scope`] is exactly one render.
    static CURRENT: RefCell<Option<Arc<Scenarios>>> = const { RefCell::new(None) };
}

/// The scenarios of the render in progress on this thread.
pub fn current() -> Option<Arc<Scenarios>> {
    CURRENT.with(|c| c.borrow().clone())
}

/// `ScenarioKey.toString()`: `<len>:<name>:N`, or `<len>:<name>:V<len>:<isolation>` for an isolated scenario, the
/// lengths in UTF-16 units.
pub fn key_isolated(name: &str, isolation: Option<&str>) -> String {
    match isolation {
        None => format!("{}:{name}:N", name.encode_utf16().count()),
        Some(iso) => format!("{}:{name}:V{}:{iso}", name.encode_utf16().count(), iso.encode_utf16().count()),
    }
}

/// `extractIsolationKey`: with `__iso=<kind>:<name>` in the scenario name, the request's header, query parameter or
/// cookie of that name (the shared key when it is absent).
fn isolation(scenario: &str, request: &HttpRequest) -> Option<String> {
    let encoded = &scenario[scenario.find("__iso=")? + "__iso=".len()..];
    let (kind, name) = encoded.split_once(':').filter(|(_, n)| !n.is_empty())?;
    let value = match kind {
        "header" => request.first_header(name).map(str::to_string),
        "query_parameter" => crate::request::first(&request.query, name).map(str::to_string),
        "cookie" => request.cookies.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()),
        _ => None,
    };
    value.filter(|v| !v.is_empty())
}

/// The scenario name a key was made from.
fn name_of(key: &str) -> Option<&str> {
    let (length, rest) = key.split_once(':')?;
    let length: usize = length.parse().ok()?;
    let mut units = 0;
    for (i, c) in rest.char_indices() {
        if units == length {
            return Some(&rest[..i]);
        }
        units += c.len_utf16();
    }
    (units == length).then_some(rest)
}

/// `getAllStates`' display key: the scenario name, with `[<isolation>]` appended for an isolated key.
fn display_of(key: &str) -> String {
    let Some(name) = name_of(key) else { return key.to_string() };
    let flag = key.split_once(':').map_or("", |(_, rest)| &rest[name.len()..]);
    match flag.strip_prefix(":V").and_then(|v| v.split_once(':')) {
        Some((_, isolation)) => format!("{name}[{isolation}]"),
        None => name.to_string(),
    }
}

/// `matchesAndTransition` over a replicated store: the CAS loop of `ScenarioManager` (at most 100 attempts), a missing
/// key being the implicit `Started`.
fn cas_transition(store: &dyn KeyValueStore<String>, key: &str, required: &str, new: &str) -> bool {
    for _ in 0..100 {
        match store.get(key) {
            Some(current) => {
                if current.value != required {
                    return false;
                }
                match store.try_compare_and_set(key, current.version, new.to_string()) {
                    Ok(true) => return true,
                    Ok(false) => continue,
                    Err(e) => {
                        eprintln!("ERROR state backend: scenario transition: {e}");
                        return false;
                    }
                }
            }
            None => {
                if required != STARTED {
                    return false;
                }
                match store.try_put_if_absent(key, new.to_string()) {
                    Ok(None) => return true,
                    Ok(Some(_)) => continue,
                    Err(e) => {
                        eprintln!("ERROR state backend: scenario transition: {e}");
                        return false;
                    }
                }
            }
        }
    }
    false
}

impl Scenarios {
    /// `RequestMatchers.setStateBackend` for a clustered backend: from now on the states are the backend's. A
    /// non-clustered backend leaves everything local.
    pub fn attach_backend(&self, backend: Arc<dyn StateBackend>) {
        if backend.is_clustered() {
            let _ = self.cluster.set(backend);
        }
    }

    /// Runs `f` with these scenarios as the ones templates see.
    pub fn scope<R>(self: &Arc<Self>, f: impl FnOnce() -> R) -> R {
        struct Restore(Option<Arc<Scenarios>>);
        impl Drop for Restore {
            fn drop(&mut self) {
                CURRENT.with(|c| *c.borrow_mut() = self.0.take());
            }
        }
        let _restore = Restore(CURRENT.with(|c| c.borrow_mut().replace(self.clone())));
        f()
    }

    fn store(&self) -> Option<&dyn KeyValueStore<String>> {
        self.cluster.get().map(|backend| backend.scenario_states())
    }

    fn written(&self) {
        self.writes.fetch_add(1, std::sync::atomic::Ordering::Release);
    }

    /// How many writes `scenarioStates` has seen (see `writes`).
    pub fn writes(&self) -> u64 {
        self.writes.load(std::sync::atomic::Ordering::Acquire)
    }

    /// `ScenarioManager.getState(name, isolation)`: `Started` until a state is set.
    pub fn get_with_isolation(&self, name: &str, isolation: Option<&str>) -> String {
        let k = key_isolated(name, isolation);
        if let Some(store) = self.store() {
            return store.get(&k).map_or_else(|| STARTED.to_string(), |v| v.value);
        }
        self.local.lock().states.iter().find(|(s, _)| *s == k).map_or_else(|| STARTED.to_string(), |(_, v)| v.clone())
    }

    /// `ScenarioManager.setState(name, isolation, state)`.
    pub fn set_with_isolation(&self, name: &str, isolation: Option<&str>, state: &str) {
        self.written();
        let k = key_isolated(name, isolation);
        if let Some(store) = self.store() {
            if let Err(e) = store.try_put(&k, state.to_string()) {
                eprintln!("ERROR state backend: scenario state: {e}");
            }
            return;
        }
        let mut local = self.local.lock();
        match local.states.iter_mut().find(|(s, _)| *s == k) {
            Some(entry) => entry.1 = state.to_string(),
            None => local.states.push((k, state.to_string())),
        }
    }

    /// `ScenarioManager.getState`.
    pub fn get(&self, name: &str) -> String {
        self.get_with_isolation(name, None)
    }

    /// `ScenarioManager.setState`.
    pub fn set(&self, name: &str, state: &str) {
        self.set_with_isolation(name, None, state);
    }

    /// `matchesState`.
    pub fn matches(&self, name: &str, required: &str) -> bool {
        self.get(name) == required
    }

    /// `matchesAndTransition`: atomically, when the scenario is in `required`, move it to `new`.
    pub fn matches_and_transition(&self, name: &str, required: &str, new: &str) -> bool {
        self.matches_and_transition_isolated(name, None, required, new)
    }

    /// `matchesAndTransition(name, isolation, required, new)`.
    pub fn matches_and_transition_isolated(&self, name: &str, isolation: Option<&str>, required: &str, new: &str) -> bool {
        let moved = self.transition_isolated(name, isolation, required, new);
        if moved {
            self.written();
        }
        moved
    }

    fn transition_isolated(&self, name: &str, isolation: Option<&str>, required: &str, new: &str) -> bool {
        let k = key_isolated(name, isolation);
        if let Some(store) = self.store() {
            return cas_transition(store, &k, required, new);
        }
        let mut local = self.local.lock();
        match local.states.iter_mut().find(|(s, _)| *s == k) {
            Some(entry) if entry.1 == required => {
                entry.1 = new.to_string();
                true
            }
            Some(_) => false,
            None if required == STARTED => {
                local.states.push((k, new.to_string()));
                true
            }
            None => false,
        }
    }

    /// `clear`: forget the scenario, every isolation of it (back to `Started`).
    pub fn clear(&self, name: &str) {
        if let Some(store) = self.store() {
            for (k, _) in store.entries() {
                if name_of(&k) == Some(name) {
                    store.remove(&k);
                    self.written();
                }
            }
            return;
        }
        let mut local = self.local.lock();
        let before = local.states.len();
        local.states.retain(|(k, _)| name_of(k) != Some(name));
        if local.states.len() != before {
            self.written();
        }
    }

    /// `ScenarioManager.reset`: every state forgotten (in the backend when clustered).
    pub fn reset(&self) {
        self.written();
        match self.store() {
            Some(store) => store.clear(),
            None => self.local.lock().states.clear(),
        }
    }

    /// `getAllStates`: display key (`name`, or `name[isolation]`) and state, in the `ConcurrentHashMap` order of the
    /// keys single-node and in the replicated store's order clustered.
    pub fn all(&self) -> Vec<(String, String)> {
        if let Some(store) = self.store() {
            return store.entries().into_iter().map(|(k, v)| (display_of(&k), v.value)).collect();
        }
        let local = self.local.lock();
        let keys: Vec<String> = local.states.iter().map(|(k, _)| k.clone()).collect();
        crate::recorded::java_hashmap_order(&keys).into_iter().map(|i| (display_of(&local.states[i].0), local.states[i].1.clone())).collect()
    }

    // --- expectations ---

    /// The gate an expectation's scenario fields apply when it matches: `false` when it must not serve.
    /// `getState(scenarioName, extractIsolationKey(expectation, request))`: the state scenario `name` is in for
    /// `request`.
    pub fn state_for(&self, name: &str, request: &HttpRequest) -> String {
        self.get_with_isolation(name, isolation(name, request).as_deref())
    }

    pub fn gate(&self, expectation: &Value, request: &HttpRequest) -> bool {
        match (expectation.get("scenarioName").and_then(Value::as_str), expectation.get("scenarioState").and_then(Value::as_str)) {
            (Some(name), Some(required)) => self.get_with_isolation(name, isolation(name, request).as_deref()) == required,
            _ => true,
        }
    }

    /// After the expectation's use is consumed: the transition to `newScenarioState` (`false` when a concurrent change
    /// moved the scenario on first).
    pub fn transition(&self, expectation: &Value, request: &HttpRequest) -> bool {
        let name = expectation.get("scenarioName").and_then(Value::as_str);
        let required = expectation.get("scenarioState").and_then(Value::as_str);
        let new = expectation.get("newScenarioState").and_then(Value::as_str);
        let iso = name.and_then(|n| isolation(n, request));
        match (name, required, new) {
            (Some(name), Some(required), Some(new)) => self.matches_and_transition_isolated(name, iso.as_deref(), required, new),
            (Some(name), None, Some(new)) => {
                self.set_with_isolation(name, iso.as_deref(), new);
                true
            }
            _ => true,
        }
    }

    /// `cancelAllPendingTransitions` (`HttpState.reset`): every pending transition is cancelled.
    pub fn cancel_all_pending_transitions(&self) {
        for (_, (_, task)) in self.pending.lock().drain() {
            if let Some(task) = task {
                task.abort();
            }
        }
    }

    /// `scheduleTransition`: a transition fires only if it is still the scenario's pending one when its delay
    /// elapses; scheduling another for the same scenario cancels it. `counted` is its `scheduleCancellable` count in
    /// the pending delayed tasks, held until it fires or is cancelled.
    fn schedule(self: &Arc<Self>, name: String, current: String, next: String, after: Duration, counted: crate::overload::Permit) {
        let id = self.next_transition.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some((_, Some(replaced))) = self.pending.lock().insert(name.clone(), (id, None)) {
            replaced.abort();
        }
        let this = self.clone();
        let key = name.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(after).await;
            drop(counted);
            let fire = {
                let mut pending = this.pending.lock();
                let still = pending.get(&key).is_some_and(|(pending_id, _)| *pending_id == id);
                if still {
                    pending.remove(&key);
                }
                still
            };
            if fire {
                this.matches_and_transition(&key, &current, &next);
            }
        });
        if let Some((pending_id, slot)) = self.pending.lock().get_mut(&name) && *pending_id == id {
            *slot = Some(task.abort_handle());
        }
    }
}

impl CrossProtocolBus {
    /// `CrossProtocolEventBus.setScenarioManager`.
    pub fn set_scenario_manager(&self, scenarios: Arc<Scenarios>) {
        *self.scenarios.lock() = Some(scenarios);
    }

    /// `CrossProtocolEventBus.setStateBackend` for a clustered backend: registrations replicate from now on.
    pub fn attach_backend(&self, backend: &Arc<dyn StateBackend>) {
        if backend.is_clustered() {
            let _ = self.store.set(backend.crud_entities(BUS_NAMESPACE));
        }
    }

    /// `CrossProtocolEventBus.reset`: every registration dropped, in the backend too when clustered.
    pub fn reset(&self) {
        self.listeners.lock().clear();
        if let Some(store) = self.store.get() {
            store.clear();
        }
    }

    /// `CrossProtocolEventBus.register`: appends (re-sending an expectation registers it again) and stays until
    /// reset; clustered, the registration is also written to the backend.
    pub fn register(&self, scenario: CrossProtocolScenario) {
        self.listeners.lock().push(scenario.clone());
        if let Some(store) = self.store.get() && let Err(e) = store.try_put(&scenario.backend_key(), scenario.backend_node()) {
            eprintln!("ERROR state backend: cross-protocol registration for scenario {:?}: {e}", scenario.scenario_name);
        }
    }

    /// `CrossProtocolEventBus.unregister`: the first equal registration goes, locally and from the backend.
    pub fn unregister(&self, scenario: &CrossProtocolScenario) {
        {
            let mut bus = self.listeners.lock();
            if let Some(i) = bus.iter().position(|s| s == scenario) {
                bus.remove(i);
            }
        }
        if let Some(store) = self.store.get() {
            store.remove(&scenario.backend_key());
        }
    }

    /// The registrations of an expectation's `crossProtocolScenarios`, as `ExpectationDTO.buildObject` makes them.
    fn cross_protocol_of(expectation: &Value) -> Vec<CrossProtocolScenario> {
        let Some(items) = expectation.get("crossProtocolScenarios").and_then(Value::as_array) else { return Vec::new() };
        let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        items
            .iter()
            .filter_map(|item| {
                let trigger = item.get("trigger").and_then(Value::as_str).and_then(Trigger::parse)?;
                Some(CrossProtocolScenario { trigger, scenario_name: text(item, "scenarioName"), target_state: text(item, "targetState"), match_pattern: text(item, "matchPattern") })
            })
            .collect()
    }

    /// `CrossProtocolEventBus.register`, for each of an expectation's `crossProtocolScenarios`.
    pub fn register_cross_protocol(&self, expectation: &Value) {
        for scenario in Self::cross_protocol_of(expectation) {
            self.register(scenario);
        }
    }

    /// [`CrossProtocolBus::register_cross_protocol`] without the backend write, for an expectation a reconcile adopted from
    /// another node (the node that added it wrote the registrations).
    pub fn register_cross_protocol_local(&self, expectation: &Value) {
        self.listeners.lock().extend(Self::cross_protocol_of(expectation));
    }

    /// `CrossProtocolEventBus.fire`: every registration for `trigger` whose pattern the identifier contains.
    pub fn fire(&self, trigger: Trigger, identifier: &str) {
        let Some(scenarios) = self.scenarios.lock().clone() else { return };
        let moves: Vec<(String, String)> = self
            .listeners
            .lock()
            .iter()
            .filter(|l| l.trigger == trigger && l.match_pattern.as_deref().is_none_or(|p| p.is_empty() || identifier.contains(p)))
            .filter_map(|l| Some((l.scenario_name.clone()?, l.target_state.clone()?)))
            .collect();
        for (scenario, target) in moves {
            scenarios.set(&scenario, &target);
        }
    }

    /// `HttpActionHandler.fireCrossProtocolEvents`: a matched expectation with cross-protocol scenarios fires
    /// `HTTP_REQUEST` with the request's path.
    pub fn fire_for_http_request(&self, expectation: &Value, request: &HttpRequest) {
        if expectation.get("crossProtocolScenarios").and_then(Value::as_array).is_some_and(|a| !a.is_empty()) {
            self.fire(Trigger::HttpRequest, &request.path);
        }
    }

    /// `CrossProtocolEventBus.reconcileFromBackend`: the local registrations of every trigger the backend holds
    /// become what it holds, the triggers it holds none of lose theirs (an entry that cannot be read is skipped).
    /// A no-op single-node.
    pub fn reconcile_bus(&self) {
        let Some(store) = self.store.get() else { return };
        let fresh: Vec<CrossProtocolScenario> = store.entries().into_iter().filter_map(|(_, entry)| CrossProtocolScenario::from_backend_node(&entry.value)).collect();
        let mut bus = self.listeners.lock();
        bus.clear();
        bus.extend(fresh);
    }

    /// The registrations held locally, in order.
    pub fn registrations(&self) -> Vec<CrossProtocolScenario> {
        self.listeners.lock().clone()
    }
}

fn error(message: &str) -> Reply {
    Reply::api_body(400, "application/json", crate::json::pretty(&json!({"error": message})))
}

fn log(state: &State, request: &HttpRequest, format: &str, args: &[&str]) {
    crate::chaos::log(state, request, crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, format).args(args.iter().copied()));
}

/// `GET /mockserver/scenario[/name]` and `PUT /mockserver/scenario/name[/trigger]`.
pub fn route(state: &State, request: &HttpRequest, op: &str) -> Option<Reply> {
    let path = op.strip_prefix("/scenario/");
    match request.method.as_str() {
        "GET" if op == "/scenario" || path.is_some() => {
            let name = path.unwrap_or_default();
            if name.trim().is_empty() {
                let scenarios: Vec<Value> = state.scenarios().all().into_iter().map(|(n, s)| json!({"scenarioName": n, "currentState": s})).collect();
                return Some(Reply::api_body(200, "application/json", crate::json::pretty(&json!({"scenarios": scenarios}))));
            }
            Some(Reply::api_body(200, "application/json", crate::json::pretty(&json!({"scenarioName": name, "currentState": state.scenarios().get(name)}))))
        }
        "PUT" if path.is_some() => Some(put(state, request, path.unwrap_or_default())),
        _ => None,
    }
}

fn put(state: &State, request: &HttpRequest, path: &str) -> Reply {
    if path.trim().is_empty() {
        return error("scenario name is required in the path");
    }
    let trigger = path.ends_with("/trigger");
    let name = if trigger { &path[..path.len() - "/trigger".len()] } else { path };
    if name.trim().is_empty() {
        return error("scenario name is required in the path");
    }
    let body = request.body_json_or_xml_str();
    let field = |node: &Value, key: &str| node.get(key).filter(|v| !v.is_null()).map(|v| crate::chaos::as_text(Some(v)).unwrap_or_default()).filter(|v| !v.trim().is_empty());
    let parse = || crate::chaos::read_tree(&body, true).map_err(|e| format!("failed to process scenario request: {e}"));
    if trigger {
        if body.trim().is_empty() {
            return error("request body is required with 'newState' field");
        }
        let node = match parse() {
            Ok(n) => n,
            Err(message) => return error(&message),
        };
        let Some(new) = field(&node, "newState") else { return error("'newState' field is required") };
        state.scenarios().set(name, &new);
        log(state, request, "triggered scenario state transition for scenario:{} to state:{}", &[name, &new]);
        return Reply::api_body(200, "application/json", crate::json::pretty(&json!({"scenarioName": name, "currentState": new})));
    }
    if body.trim().is_empty() {
        return error("request body is required with 'state' field");
    }
    let node = match parse() {
        Ok(n) => n,
        Err(message) => return error(&message),
    };
    let Some(current) = field(&node, "state") else { return error("'state' field is required") };
    state.scenarios().set(name, &current);
    log(state, request, "set scenario state for scenario:{} to state:{}", &[name, &current]);
    let after = node.get("transitionAfterMs").filter(|v| !v.is_null()).map(|v| crate::chaos::as_long(Some(v)));
    let next = field(&node, "nextState");
    let mut result = json!({"scenarioName": name, "currentState": current});
    if let (Some(after), Some(next)) = (after.filter(|a| *a > 0), next) {
        state.scenarios().schedule(name.to_string(), current.clone(), next.clone(), Duration::from_millis(after as u64), state.overload.unbounded_delayed());
        log(state, request, "scheduled timed transition for scenario:{} from state:{} to state:{} after {}ms", &[name, &current, &next, &after.to_string()]);
        result["nextState"] = next.into();
        result["transitionAfterMs"] = after.into();
    }
    Reply::api_body(200, "application/json", crate::json::pretty(&result))
}

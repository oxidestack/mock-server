//! `stateBackend=infinispan` in **CLUSTERED mode** (`clusterEnabled=true`): `InfinispanStateBackend`,
//! `InfinispanKeyValueStore` and `InfinispanBlobStore` over the infinispan-rs crate's `ClusterNode` — a JGroups
//! channel, the topology managers and one REPL_SYNC cache engine per cache — instead of the LOCAL-mode
//! stand-in (`super::infinispan`).
//!
//! What it reproduces of `InfinispanStateBackend.java`:
//! - the caches `expectations` (bounded by `maxExpectations`, REMOVE when full), `scenarioStates`, `blobs`, all
//!   started when the backend is built, and `crud-<namespace>` on first use;
//! - the stack from `clusterTransportConfig`, `jgroups-loopback.xml` (SHARED_LOOPBACK, in-process) when unset;
//! - `JavaSerializationMarshaller` values and the explicit allow-list of ten regexps ([`codec`]);
//! - the invalidation policy: a clustered cache listener (post events only) on `expectations`,
//!   `scenarioStates` and every `crud-*` cache, never on `blobs`, registered once per cache and bridged to the
//!   shared list of [`InvalidationListener`]s; local writes also fire the store's own `fireChanged`, and in a
//!   replicated cache the clustered listener sees local writes too (§4.5's correction), so a local write notifies
//!   twice, exactly as upstream does;
//! - `cluster_info` from the live view, and the `ISPN000094: Received new cluster view for channel ...` line on
//!   every view change, which the upstream container cases grep for.
//!
//! The SPI is synchronous and the crate asynchronous, so the backend owns a small Tokio runtime and blocks the
//! calling thread on it ([`Bridge::call`]).
//!
//! Where Java throws, the SPI's infallible methods panic and the `try_*` forms return a [`StateError`]; core
//! wiring uses the `try_*` forms.

pub mod codec;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use infinispan::cache::cluster_node::ClusterNode;
use infinispan::cache::encoder_cache::Cache;
use infinispan::cache::write_pipeline::CacheConfig;
use infinispan::commands::compute_function::CacheLambda;
use infinispan::commands::object::CacheObject;
use infinispan::notify::event::{Event, EventKind};
use infinispan::notify::listener_registration::{ListenerAttrs, ListenerDefinition, ListenerMethod};
use infinispan::topology::transport::TopologyTransport;
use jgroups::wire::address::Address as JAddress;
use parking_lot::Mutex;

use self::codec::{ValueCodec, clustered_allow_list};
use super::{Blob, BlobStore, ClusterInfo, ClusterMember, ExpectationEntry, InvalidationListener, KeyValueStore, StateBackend, StateError, Versioned};

pub const EXPECTATIONS_CACHE: &str = "expectations";
pub const SCENARIO_STATES_CACHE: &str = "scenarioStates";
/// `SHARED_TIMES_CACHE`: the clustered limited-`Times` counters, bounded like the expectations cache.
pub const SHARED_TIMES_CACHE: &str = "sharedTimesCounters";
pub const BLOBS_CACHE: &str = "blobs";
pub const CRUD_CACHE_PREFIX: &str = "crud-";

/// `jgroups-loopback.xml` and `jgroups-kubernetes.xml`, embedded verbatim: upstream's own files
/// (`mockserver-state-infinispan/src/main/resources`), as the jgroups crate's `resources/` also carries them.
pub const JGROUPS_LOOPBACK_XML: &str = include_str!("jgroups-loopback.xml");
pub const JGROUPS_KUBERNETES_XML: &str = include_str!("jgroups-kubernetes.xml");

// ---------------------------------------------------------------------------------------------------------
// sync/async bridge
// ---------------------------------------------------------------------------------------------------------

/// The runtime the cluster node and its caches live on, and the way a synchronous caller waits for it.
pub struct Bridge {
    runtime: Option<tokio::runtime::Runtime>,
}

impl Bridge {
    fn new() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(4).thread_name("state-backend-cluster").enable_all().build()?;
        Ok(Bridge { runtime: Some(runtime) })
    }

    fn rt(&self) -> &tokio::runtime::Runtime {
        self.runtime.as_ref().expect("the runtime lives until the bridge is dropped")
    }

    /// Runs `fut` on the cluster runtime and waits for it. Safe to call from inside another runtime: a
    /// multi-threaded caller hands its worker over with `block_in_place`; a single-threaded one is simply held
    /// (the cluster runtime makes the progress).
    pub fn call<T: Send + 'static>(&self, fut: impl Future<Output = T> + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        self.rt().spawn(async move {
            let _ = tx.send(fut.await);
        });
        let wait = move || rx.recv().expect("the cluster task answers");
        match tokio::runtime::Handle::try_current() {
            Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(wait),
            _ => wait(),
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// invalidation listeners
// ---------------------------------------------------------------------------------------------------------

/// The shared `CopyOnWriteArrayList<InvalidationListener>` of the backend.
#[derive(Clone, Default)]
struct Listeners(Arc<Mutex<Vec<Arc<dyn InvalidationListener>>>>);

impl Listeners {
    fn snapshot(&self) -> Vec<Arc<dyn InvalidationListener>> {
        self.0.lock().clone()
    }
    fn push(&self, l: Arc<dyn InvalidationListener>) {
        self.0.lock().push(l);
    }
    fn fire_changed(&self, key: &str) {
        for l in self.snapshot() {
            l.on_changed(key);
        }
    }
}

/// `InfinispanCacheListener`: `@Listener(clustered = true)`, `@CacheEntryCreated/Modified/Removed` post events
/// call `onChanged(key)`; `@CacheEntriesEvicted` is retained but Infinispan 14 never delivers it to a clustered
/// listener.
fn cache_listener(listeners: Listeners) -> Arc<ListenerDefinition> {
    let fire = {
        let listeners = listeners.clone();
        move |e: &Event| {
            if !e.pre && let Some(key) = e.key.as_str() {
                listeners.fire_changed(key);
            }
        }
    };
    let evicted = move |e: &Event| {
        for (k, _) in &e.entries {
            if let Some(key) = k.as_str() {
                listeners.fire_changed(key);
            }
        }
    };
    ListenerDefinition::new(
        "org.mockserver.state.infinispan.InfinispanCacheListener",
        ListenerAttrs::clustered(),
        vec![
            ListenerMethod::new("onCreated", &[EventKind::CacheEntryCreated], fire.clone()),
            ListenerMethod::new("onModified", &[EventKind::CacheEntryModified], fire.clone()),
            ListenerMethod::new("onRemoved", &[EventKind::CacheEntryRemoved], fire),
            ListenerMethod::new("onEvicted", &[EventKind::CacheEntriesEvicted], evicted),
        ],
    )
}

// ---------------------------------------------------------------------------------------------------------
// InfinispanKeyValueStore
// ---------------------------------------------------------------------------------------------------------

fn state_error(what: &str, e: impl std::fmt::Display) -> StateError {
    StateError(format!("{what}: {e}"))
}

/// `InfinispanKeyValueStore<V>`: a `Cache<String, VersionedWrapper<V>>` as a [`KeyValueStore`].
pub struct ClusterKeyValueStore<V: ValueCodec> {
    cache: Cache,
    bridge: Arc<Bridge>,
    listeners: Mutex<Vec<Arc<dyn InvalidationListener>>>,
    _value: PhantomData<fn() -> V>,
}

impl<V: ValueCodec> ClusterKeyValueStore<V> {
    fn new(cache: Cache, bridge: Arc<Bridge>) -> Self {
        ClusterKeyValueStore { cache, bridge, listeners: Mutex::new(Vec::new()), _value: PhantomData }
    }

    fn key(key: &str) -> CacheObject {
        CacheObject::string(key)
    }

    fn read(&self, object: &CacheObject) -> Result<Versioned<V>, StateError> {
        let (value, version) = codec::unwrap::<V>(object, Some(clustered_allow_list())).map_err(|e| state_error("cannot read the cache value", e))?;
        Ok(Versioned { value, version })
    }

    fn fire_changed(&self, key: &str) {
        let listeners = self.listeners.lock().clone();
        for l in listeners {
            l.on_changed(key);
        }
    }

    fn fire_cleared(&self) {
        let listeners = self.listeners.lock().clone();
        for l in listeners {
            l.on_cleared();
        }
    }

    fn current(&self, key: &str) -> Result<Option<(CacheObject, Versioned<V>)>, StateError> {
        let cache = self.cache.clone();
        let k = Self::key(key);
        match self.bridge.call(async move { cache.get(&k).await }).map_err(|e| state_error("get", e))? {
            None => Ok(None),
            Some(object) => {
                let read = self.read(&object)?;
                Ok(Some((object, read)))
            }
        }
    }

    /// `get`, with the error Java would throw.
    pub fn try_get(&self, key: &str) -> Result<Option<Versioned<V>>, StateError> {
        Ok(self.current(key)?.map(|(_, v)| v))
    }

    /// `entries()` of this node's copy (a replicated cache holds every entry), undecodable values reported.
    pub fn try_entries(&self) -> Result<Vec<(String, Versioned<V>)>, StateError> {
        let mut out = Vec::new();
        for (k, v) in self.cache.entries() {
            if let Some(key) = k.as_str() {
                out.push((key.to_string(), self.read(&v)?));
            }
        }
        Ok(out)
    }
}

impl<V: ValueCodec> KeyValueStore<V> for ClusterKeyValueStore<V> {
    fn get(&self, key: &str) -> Option<Versioned<V>> {
        self.try_get(key).unwrap_or_else(|e| panic!("{e}"))
    }

    fn put(&self, key: &str, value: V) -> u64 {
        self.try_put(key, value).unwrap_or_else(|e| panic!("{e}"))
    }

    /// `cache.compute(key, (k, existing) -> new VersionedWrapper<>(value, existing != null ? existing.getVersion() + 1 : 1L))`.
    fn try_put(&self, key: &str, value: V) -> Result<u64, StateError> {
        let captured = codec::captured_value(&value).map_err(|e| state_error("cannot marshal the value", e))?;
        let cache = self.cache.clone();
        let k = Self::key(key);
        let result = self.bridge.call(async move { cache.compute(&k, CacheLambda::mockserver_put(captured)).await }).map_err(|e| state_error("put", e))?;
        let wrapper = result.ok_or_else(|| StateError("put: compute returned no value".into()))?;
        let version = self.read(&wrapper)?.version;
        self.fire_changed(key);
        Ok(version)
    }

    fn put_if_absent(&self, key: &str, value: V) -> Option<Versioned<V>> {
        self.try_put_if_absent(key, value).unwrap_or_else(|e| panic!("{e}"))
    }

    fn try_put_if_absent(&self, key: &str, value: V) -> Result<Option<Versioned<V>>, StateError> {
        let wrapper = codec::wrap(&value, 1).map_err(|e| state_error("cannot marshal the value", e))?;
        let cache = self.cache.clone();
        let k = Self::key(key);
        match self.bridge.call(async move { cache.put_if_absent(&k, &wrapper).await }).map_err(|e| state_error("putIfAbsent", e))? {
            Some(existing) => Ok(Some(self.read(&existing)?)),
            None => {
                self.fire_changed(key);
                Ok(None)
            }
        }
    }

    /// `get` for the version, then `cache.replace(key, current, updated)`: the wrapper's `equals` compares
    /// version and value, so the swap fails when anything changed in between.
    fn compare_and_set(&self, key: &str, expected_version: u64, value: V) -> bool {
        self.try_compare_and_set(key, expected_version, value).unwrap_or_else(|e| panic!("{e}"))
    }

    fn try_compare_and_set(&self, key: &str, expected_version: u64, value: V) -> Result<bool, StateError> {
        let Some((current, read)) = self.current(key)? else { return Ok(false) };
        if read.version != expected_version {
            return Ok(false);
        }
        let updated = codec::wrap(&value, expected_version + 1).map_err(|e| state_error("cannot marshal the value", e))?;
        let cache = self.cache.clone();
        let k = Self::key(key);
        let success = self.bridge.call(async move { cache.replace_if(&k, &current, &updated).await }).map_err(|e| state_error("replace", e))?;
        if success {
            self.fire_changed(key);
        }
        Ok(success)
    }

    fn compare_and_remove(&self, key: &str, expected_version: u64) -> bool {
        let Some((current, read)) = self.current(key).unwrap_or_else(|e| panic!("{e}")) else { return false };
        if read.version != expected_version {
            return false;
        }
        let cache = self.cache.clone();
        let k = Self::key(key);
        let success = self.bridge.call(async move { cache.remove_if(&k, &current).await }).unwrap_or_else(|e| panic!("remove: {e}"));
        if success {
            self.fire_changed(key);
        }
        success
    }

    fn remove(&self, key: &str) -> bool {
        let cache = self.cache.clone();
        let k = Self::key(key);
        let removed = self.bridge.call(async move { cache.remove(&k).await }).unwrap_or_else(|e| panic!("remove: {e}")).is_some();
        if removed {
            self.fire_changed(key);
        }
        removed
    }

    /// A value the allow-list refuses (or that is not a `VersionedWrapper<V>`) is reported and left out, so one bad
    /// entry cannot stop a reconcile; [`ClusterKeyValueStore::try_entries`] is the strict form.
    fn entries(&self) -> Vec<(String, Versioned<V>)> {
        self.cache
            .entries()
            .into_iter()
            .filter_map(|(k, v)| {
                let key = k.as_str()?.to_string();
                match self.read(&v) {
                    Ok(read) => Some((key, read)),
                    Err(e) => {
                        eprintln!("ERROR state backend: cache entry {key}: {e}; skipped");
                        None
                    }
                }
            })
            .collect()
    }

    fn size(&self) -> usize {
        self.cache.size()
    }

    fn clear(&self) {
        let cache = self.cache.clone();
        self.bridge.call(async move { cache.clear().await }).unwrap_or_else(|e| panic!("clear: {e}"));
        self.fire_cleared();
    }

    fn add_invalidation_listener(&self, listener: Arc<dyn InvalidationListener>) {
        self.listeners.lock().push(listener);
    }
}

// ---------------------------------------------------------------------------------------------------------
// InfinispanBlobStore
// ---------------------------------------------------------------------------------------------------------

/// `InfinispanBlobStore`: serialized `Blob`s in the REPL_SYNC `blobs` cache.
pub struct ClusterBlobStore {
    cache: Cache,
    bridge: Arc<Bridge>,
}

impl ClusterBlobStore {
    pub fn try_put(&self, key: &str, data: Vec<u8>, metadata: HashMap<String, String>) -> Result<(), StateError> {
        let value = codec::blob_value(&Blob { key: key.to_string(), data, metadata });
        let cache = self.cache.clone();
        let k = CacheObject::string(key);
        self.bridge.call(async move { cache.put(&k, &value).await }).map(|_| ()).map_err(|e| state_error("put", e))
    }

    pub fn try_get(&self, key: &str) -> Result<Option<Blob>, StateError> {
        let cache = self.cache.clone();
        let k = CacheObject::string(key);
        match self.bridge.call(async move { cache.get(&k).await }).map_err(|e| state_error("get", e))? {
            None => Ok(None),
            Some(object) => codec::read_blob(&object, Some(clustered_allow_list())).map(Some).map_err(|e| state_error("cannot read the blob", e)),
        }
    }
}

impl BlobStore for ClusterBlobStore {
    fn put(&self, key: &str, data: Vec<u8>, metadata: HashMap<String, String>) {
        self.try_put(key, data, metadata).unwrap_or_else(|e| panic!("{e}"))
    }

    fn get(&self, key: &str) -> Option<Blob> {
        self.try_get(key).unwrap_or_else(|e| panic!("{e}"))
    }

    fn list(&self, prefix: &str) -> Vec<String> {
        self.cache.keys().iter().filter_map(|k| k.as_str()).filter(|k| k.starts_with(prefix)).map(str::to_string).collect()
    }

    fn delete(&self, key: &str) -> bool {
        let cache = self.cache.clone();
        let k = CacheObject::string(key);
        self.bridge.call(async move { cache.remove(&k).await }).unwrap_or_else(|e| panic!("remove: {e}")).is_some()
    }
}

// ---------------------------------------------------------------------------------------------------------
// InfinispanStateBackend (CLUSTERED)
// ---------------------------------------------------------------------------------------------------------

/// How a clustered backend is configured (`Configuration.clusterName()`, `clusterTransportConfig()`,
/// `maxExpectations()`).
pub struct ClusterOptions {
    pub cluster_name: String,
    /// The JGroups XML; `None` is the built-in loopback stack.
    pub transport_xml: Option<String>,
    pub max_expectations: usize,
    /// Receives the INFO lines (`ISPN000094`, the start line). Defaults to standard output.
    pub log: Arc<dyn Fn(String) + Send + Sync>,
    /// How long joining may wait for the coordinator and the initial state transfer.
    pub join_timeout: Duration,
}

impl ClusterOptions {
    pub fn new(cluster_name: &str, max_expectations: usize) -> Self {
        ClusterOptions { cluster_name: cluster_name.into(), transport_xml: None, max_expectations, log: Arc::new(|line| crate::log::console_line(&line)), join_timeout: Duration::from_secs(30) }
    }

    /// From `clusterName`, `clusterTransportConfig` (a file, or the name of one of the two bundled stacks) and
    /// `maxExpectations`.
    pub fn from_config(config: &crate::Config) -> Result<Self, String> {
        let name = config.property("clusterName").filter(|n| !n.is_empty()).unwrap_or_else(|| "mockserver-cluster".into());
        let mut options = ClusterOptions::new(&name, config.int_property("maxExpectations", crate::config::default_max_expectations(config)).max(0) as usize);
        options.transport_xml = match config.property("clusterTransportConfig").filter(|t| !t.is_empty()) {
            None => None,
            Some(t) if t == "jgroups-loopback.xml" => None,
            Some(t) if t == "jgroups-kubernetes.xml" => Some(JGROUPS_KUBERNETES_XML.to_string()),
            Some(path) => Some(std::fs::read_to_string(&path).map_err(|e| format!("clusterTransportConfig {path}: {e}"))?),
        };
        Ok(options)
    }
}

pub struct ClusterStateBackend {
    // the node and the stores go before the bridge so they are dropped while the runtime still exists
    node: Arc<ClusterNode>,
    expectations: ClusterKeyValueStore<ExpectationEntry>,
    scenario_states: ClusterKeyValueStore<String>,
    shared_times: ClusterKeyValueStore<i32>,
    crud: Mutex<HashMap<String, Arc<ClusterKeyValueStore<serde_json::Value>>>>,
    blobs: ClusterBlobStore,
    listeners: Listeners,
    registered_cluster_listeners: Mutex<HashSet<String>>,
    cluster_name: String,
    node_id: String,
    closed: std::sync::atomic::AtomicBool,
    log: Arc<dyn Fn(String) + Send + Sync>,
    bridge: Arc<Bridge>,
}

impl ClusterStateBackend {
    /// `createClusteredCacheManager` + the three `getCache` calls of the constructor.
    pub fn start(options: ClusterOptions) -> Result<Self, String> {
        let bridge = Arc::new(Bridge::new().map_err(|e| format!("cluster runtime: {e}"))?);
        let xml = options.transport_xml.clone().unwrap_or_else(|| JGROUPS_LOOPBACK_XML.to_string());
        let (name, join) = (options.cluster_name.clone(), options.join_timeout);
        let node = bridge.call(async move { ClusterNode::start(&xml, &name, join).await }).map_err(|e| format!("cannot join cluster {}: {e:?}", options.cluster_name))?;
        install_view_logging(&bridge, &node, &options);

        let start_cache = |cfg: CacheConfig| -> Result<Cache, String> {
            let (node, cfg) = (node.clone(), cfg);
            let name = cfg.name.clone();
            bridge.call(async move { node.start_cache(cfg).await.map(|(cache, _)| cache) }).map_err(|e| format!("cannot start cache {name}: {e}"))
        };
        let mut expectations = CacheConfig::new(EXPECTATIONS_CACHE);
        expectations.state_transfer_timeout = options.join_timeout;
        if options.max_expectations > 0 {
            expectations = expectations.with_max_count(options.max_expectations as i64);
        }
        let mut scenarios = CacheConfig::new(SCENARIO_STATES_CACHE);
        scenarios.state_transfer_timeout = options.join_timeout;
        let mut shared_times = CacheConfig::new(SHARED_TIMES_CACHE);
        shared_times.state_transfer_timeout = options.join_timeout;
        if options.max_expectations > 0 {
            shared_times = shared_times.with_max_count(options.max_expectations as i64);
        }
        let mut blobs = CacheConfig::new(BLOBS_CACHE);
        blobs.state_transfer_timeout = options.join_timeout;
        // started in the constructor's order: expectations, scenarioStates, sharedTimesCounters, blobs
        let backend = ClusterStateBackend {
            expectations: ClusterKeyValueStore::new(start_cache(expectations)?, bridge.clone()),
            scenario_states: ClusterKeyValueStore::new(start_cache(scenarios)?, bridge.clone()),
            shared_times: ClusterKeyValueStore::new(start_cache(shared_times)?, bridge.clone()),
            blobs: ClusterBlobStore { cache: start_cache(blobs)?, bridge: bridge.clone() },
            crud: Mutex::new(HashMap::new()),
            listeners: Listeners::default(),
            registered_cluster_listeners: Mutex::new(HashSet::new()),
            cluster_name: options.cluster_name.clone(),
            node_id: crate::state_backend::new_node_id(),
            closed: std::sync::atomic::AtomicBool::new(false),
            log: options.log.clone(),
            node,
            bridge,
        };
        (options.log)(format!("InfinispanStateBackend started (mode=CLUSTERED, nodeId={}, clusterName={})", backend.node_id, backend.cluster_name));
        Ok(backend)
    }

    /// `registerClusterListenerOnce`: one listener per cache, bridged to the shared list.
    fn register_cluster_listener_once(&self, cache_name: &str, cache: &Cache) {
        if self.registered_cluster_listeners.lock().insert(cache_name.to_string()) {
            cache.add_cache_listener(&cache_listener(self.listeners.clone())).expect("the clustered listener is valid");
        }
    }

    /// The listener-bearing caches' names, for tests: `blobs` is never among them.
    pub fn caches_with_cluster_listener(&self) -> Vec<String> {
        let mut names: Vec<String> = self.registered_cluster_listeners.lock().iter().cloned().collect();
        names.sort();
        names
    }

    pub fn expectations_cache(&self) -> &Cache {
        &self.expectations.cache
    }

    pub fn shared_times_cache(&self) -> &Cache {
        &self.shared_times.cache
    }

    pub fn shared_times_store(&self) -> &ClusterKeyValueStore<i32> {
        &self.shared_times
    }

    pub fn blobs_cache(&self) -> &Cache {
        &self.blobs.cache
    }

    pub fn expectation_store(&self) -> &ClusterKeyValueStore<ExpectationEntry> {
        &self.expectations
    }

    pub fn scenario_state_store(&self) -> &ClusterKeyValueStore<String> {
        &self.scenario_states
    }

    pub fn blob_store(&self) -> &ClusterBlobStore {
        &self.blobs
    }

    /// The crud store for `namespace`, with the error a failed cache start would be.
    pub fn try_crud_entities(&self, namespace: &str) -> Result<Arc<ClusterKeyValueStore<serde_json::Value>>, StateError> {
        if let Some(existing) = self.crud.lock().get(namespace) {
            return Ok(existing.clone());
        }
        let cache_name = format!("{CRUD_CACHE_PREFIX}{namespace}");
        let (node, cfg) = (self.node.clone(), CacheConfig::new(&cache_name));
        let cache = self.bridge.call(async move { node.start_cache(cfg).await.map(|(cache, _)| cache) }).map_err(|e| state_error(&format!("cannot start cache {cache_name}"), e))?;
        let mut crud = self.crud.lock();
        // a racing caller may have defined it first (`computeIfAbsent`): its cache stays
        if let Some(existing) = crud.get(namespace) {
            return Ok(existing.clone());
        }
        let store = Arc::new(ClusterKeyValueStore::new(cache.clone(), self.bridge.clone()));
        // G11: remote writes to a crud cache must notify too, and the listeners added so far hear local writes
        self.register_cluster_listener_once(&cache_name, &cache);
        for l in self.listeners.snapshot() {
            store.add_invalidation_listener(l);
        }
        crud.insert(namespace.to_string(), store.clone());
        Ok(store)
    }

    pub fn members(&self) -> Vec<String> {
        self.node.transport.members().iter().map(address_name).collect()
    }
}

impl Drop for ClusterStateBackend {
    fn drop(&mut self) {
        StateBackend::close(self);
    }
}

impl StateBackend for ClusterStateBackend {
    fn expectations(&self) -> &dyn KeyValueStore<ExpectationEntry> {
        &self.expectations
    }

    fn scenario_states(&self) -> &dyn KeyValueStore<String> {
        &self.scenario_states
    }

    /// Deliberately not wired to the invalidation listeners: a decrement must not reconcile the matchers.
    fn shared_times_counters(&self) -> Option<&dyn KeyValueStore<i32>> {
        Some(&self.shared_times)
    }

    fn crud_entities(&self, namespace: &str) -> Arc<dyn KeyValueStore<serde_json::Value>> {
        self.try_crud_entities(namespace).unwrap_or_else(|e| panic!("{e}"))
    }

    fn blobs(&self) -> &dyn BlobStore {
        &self.blobs
    }

    fn add_invalidation_listener(&self, listener: Arc<dyn InvalidationListener>) {
        self.listeners.push(listener.clone());
        // local invalidation (fires for local puts)
        self.expectations.add_invalidation_listener(listener.clone());
        self.scenario_states.add_invalidation_listener(listener);
        // clustered invalidation, once per cache; it bridges to the shared list
        self.register_cluster_listener_once(EXPECTATIONS_CACHE, &self.expectations.cache);
        self.register_cluster_listener_once(SCENARIO_STATES_CACHE, &self.scenario_states.cache);
    }

    fn node_id(&self) -> &str {
        &self.node_id
    }

    fn is_clustered(&self) -> bool {
        true
    }

    /// `close()`: stops the cache engines and leaves the channel, so the other members install a view without
    /// this node (and log `ISPN000094` for it).
    fn close(&self) {
        if !self.closed.swap(true, std::sync::atomic::Ordering::SeqCst) {
            (self.log)(format!("stopping InfinispanStateBackend (mode=CLUSTERED, nodeId={})", self.node_id));
            let node = self.node.clone();
            self.bridge.call(async move { node.stop().await });
        }
    }

    fn cluster_info(&self) -> ClusterInfo {
        let transport = &self.node.transport;
        let members = transport.members();
        let local = transport.address();
        if members.is_empty() {
            return ClusterInfo::single_node(&self.node_id);
        }
        let coordinator = transport.coordinator();
        ClusterInfo {
            clustered: true,
            node_id: address_name(&local),
            coordinator: address_name(&coordinator),
            cluster_name: Some(self.cluster_name.clone()),
            members: members.iter().map(|a| ClusterMember { id: address_name(a), coordinator: *a == coordinator, local: *a == local }).collect(),
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// member names and the view log line
// ---------------------------------------------------------------------------------------------------------

/// `Address.toString()` of a JGroups member: its logical name when the `NameCache` has one (`UUID.toString`), else the
/// canonical UUID text (`UUID.toStringLong`).
pub fn address_name(a: &infinispan::ch::address::Address) -> String {
    match a {
        infinispan::ch::address::Address::JGroups(j) => j.print_name(),
        infinispan::ch::address::Address::Persistent { msb, lsb } => jgroups::util::name_cache::uuid_text(*msb, *lsb),
    }
}

/// `View.toString()`: `[creator|id] (n) [member, member]`.
fn view_text(view: &jgroups::wire::view::View) -> String {
    let creator = view.view_id.creator.as_ref().map(JAddress::print_name).unwrap_or_else(|| "null".into());
    let members: Vec<String> = view.members.iter().map(JAddress::print_name).collect();
    format!("[{creator}|{}] ({}) [{}]", view.view_id.id, members.len(), members.join(", "))
}

/// `ISPN000094: Received new cluster view for channel <cluster>: [<coord>|<id>] (<n>) [<members>]` for a regular view
/// (`Log.receivedClusterView`, `JGroupsTransport.receiveClusterView`), and `ISPN000093: Received new, MERGED cluster
/// view for channel <cluster>: MergeView::[<coord>|<id>] (<n>) [<members>], <k> subgroups: <views>` for a `MergeView`
/// (`Log.receivedMergedView`). `MergeView.toString` appends the subgroups only when there are any.
pub fn view_change_line(cluster: &str, view: &jgroups::wire::view::View, subgroups: Option<&[jgroups::wire::view::View]>) -> String {
    let base = view_text(view);
    match subgroups {
        None => format!("ISPN000094: Received new cluster view for channel {cluster}: {base}"),
        Some(groups) => {
            let mut text = format!("MergeView::{base}");
            if !groups.is_empty() {
                let groups: Vec<String> = groups.iter().map(view_text).collect();
                text.push_str(&format!(", {} subgroups: {}", groups.len(), groups.join(", ")));
            }
            format!("ISPN000093: Received new, MERGED cluster view for channel {cluster}: {text}")
        }
    }
}

struct ViewLogger {
    cluster: String,
    log: Arc<dyn Fn(String) + Send + Sync>,
}

impl jgroups::protocols::gms::MembershipListener for ViewLogger {
    fn view_accepted<'a>(&'a self, view: &'a jgroups::wire::view::View, subgroups: Option<&'a [jgroups::wire::view::View]>) -> jgroups::stack::BoxFuture<'a, ()> {
        Box::pin(async move { (self.log)(view_change_line(&self.cluster, view, subgroups)) })
    }
}

fn install_view_logging(bridge: &Bridge, node: &Arc<ClusterNode>, options: &ClusterOptions) {
    let logger = Arc::new(ViewLogger { cluster: options.cluster_name.clone(), log: options.log.clone() });
    let transport = node.transport.transport().clone();
    transport.add_membership_listener(logger.clone());
    // the view this node joined with was installed before the listener was; report it too
    bridge.call(async move {
        if let Some(view) = transport.view().await {
            jgroups::protocols::gms::MembershipListener::view_accepted(&*logger, &view, None).await;
        }
    });
}

#[cfg(test)]
mod tests;

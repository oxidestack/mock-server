//! The state-backend SPI: a pluggable backend for expectations, scenario
//! states, on-demand CRUD-entity registries and blobs, matching upstream's own SPI —
//! `MS/mockserver-core/src/main/java/org/mockserver/state/{StateBackend,KeyValueStore,BlobStore,Versioned,
//! ExpectationEntry,Blob,ClusterInfo,InvalidationListener}.java` — closely enough to build the clustered
//! backend on top of it without reshaping it.
//!
//! This module name deliberately avoids `state` (`src/state.rs` already is that name, for the unrelated
//! per-connection `State` struct — "everything shared between connections"; upstream's `org.mockserver.state`
//! package is a different concern entirely, the pluggable storage layer under it).
//!
//! Two implementations exist: [`memory`] (`stateBackend=memory`, the default, unchanged from before this
//! SPI) and [`infinispan`] (`stateBackend=infinispan`) — but only its **LOCAL mode**
//! (`clusterEnabled=false`, the only mode this backend has). Upstream's own LOCAL-mode cache manager
//! (`InfinispanStateBackend.createLocalCacheManager`) is `global.nonClusteredDefault()`: no JGroups transport, no
//! network marshalling, heap-only caches — behaviourally the same plain local map `memory` already is. So
//! [`infinispan::InfinispanStateBackend`] is a thin wrapper around [`memory::InMemoryStateBackend`], not a
//! second engine; that is upstream's own specified behaviour, not a shortcut (see that module's doc comment).
//!
//! **What this module does NOT do**: wire the live dataplane (`src/store.rs`'s `Store`, `src/scenario.rs`) to
//! read or write through this SPI. `Store` keeps being the authoritative expectation store for request
//! matching, exactly as before. Three things make that the correct scope, not a shortfall:
//! (1) LOCAL-mode Infinispan is specified to be behaviourally identical to `memory` (this doc comment says so); (2) no oracle scenario changes with it, which a
//! live-dataplane rewrite would risk; (3) the SPI exists for the clustered backend to plug a real JGroups/Infinispan
//! transport into — the rewiring is that later work, once there is a distributed backend for it to matter for. What
//! this module proves instead: the SPI's
//! own contract (get/put/putIfAbsent/CAS/remove/entries/clear, bounded eviction, blob round-trips, on-demand
//! CRUD namespaces, invalidation listeners) is correct for both backends, and the server boots and resolves
//! `stateBackend`/`clusterEnabled` correctly at startup ([`resolve`], wired into `Server::start`).

pub mod cluster;
pub mod infinispan;
pub mod memory;
pub mod registry;

use std::collections::HashMap;
use std::sync::Arc;

/// A failed backend operation where Java would throw: a value that cannot be marshalled (an expectation whose
/// JSON is over 65,535 modified-UTF-8 bytes, `UTFDataFormatException`), a cache that cannot replicate, a stored
/// value the allow-list refuses. Only a clustered backend produces one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateError(pub String);

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StateError {}

/// A fresh node identifier (`UUIDService.getUUID()`).
pub fn new_node_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// A value paired with an optimistic-concurrency version number (`org.mockserver.state.Versioned`). The version
/// increments on every mutation; [`KeyValueStore::compare_and_set`]/[`KeyValueStore::compare_and_remove`] use it
/// to detect concurrent updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Versioned<V> {
    pub value: V,
    pub version: u64,
}

/// What the `expectations` store holds (`org.mockserver.state.ExpectationEntry`): the sort fields that
/// determine matching order, plus the shared remaining-times counter a clustered backend CASes across nodes,
/// alongside the expectation itself. Upstream keeps the live `Expectation` object as a transient field
/// (populated in-process; only its `ExpectationDTO` JSON is what actually crosses the wire, via a custom
/// `writeObject`). This module does not wire the live dataplane's `crate::store::Expectation` through this SPI
/// (see this module's doc comment), so `expectation_json` holds that same JSON form directly — upstream's own
/// wire representation — rather than a premature commitment to `Arc<crate::store::Expectation>` before a
/// consumer exists to need it.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpectationEntry {
    pub id: String,
    pub priority: i64,
    pub created: u64,
    /// `-1` means unlimited (matches `crate::store::Expectation`'s own `remaining` field's sentinel).
    pub remaining_times: i64,
    pub expectation_json: serde_json::Value,
}

/// An opaque blob with key and metadata (`org.mockserver.state.Blob`), stored in a [`BlobStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub key: String,
    pub data: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

/// Notified of mutations on any store a [`StateBackend`] manages (`org.mockserver.state.InvalidationListener`).
/// In-memory and LOCAL-mode Infinispan backends fire it for every local write (upstream's own comment notes the
/// listener fires for local writes too, despite suggesting otherwise elsewhere); a clustered
/// backend also fires it for remote writes.
pub trait InvalidationListener: Send + Sync {
    fn on_changed(&self, key: &str);
    fn on_cleared(&self);
}

/// Versioned key-value store abstraction for shared MockServer state (`org.mockserver.state.KeyValueStore<V>`).
/// `put` is last-writer-wins; `compare_and_set`/`compare_and_remove` are the CAS primitives a clustered backend's
/// shared-Times consumption needs.
pub trait KeyValueStore<V: Clone + PartialEq + Send + Sync>: Send + Sync {
    fn get(&self, key: &str) -> Option<Versioned<V>>;
    /// Unconditional last-writer-wins put; returns the new version.
    fn put(&self, key: &str, value: V) -> u64;
    /// Inserts only if absent. `None` on success; `Some(existing)` (unmodified) if the key was already present.
    fn put_if_absent(&self, key: &str, value: V) -> Option<Versioned<V>>;
    fn compare_and_set(&self, key: &str, expected_version: u64, value: V) -> bool;
    /// [`put`](Self::put) reporting the failure Java would throw. Infallible stores never fail.
    fn try_put(&self, key: &str, value: V) -> Result<u64, StateError> {
        Ok(self.put(key, value))
    }
    /// [`put_if_absent`](Self::put_if_absent) reporting the failure Java would throw.
    fn try_put_if_absent(&self, key: &str, value: V) -> Result<Option<Versioned<V>>, StateError> {
        Ok(self.put_if_absent(key, value))
    }
    /// [`compare_and_set`](Self::compare_and_set) reporting the failure Java would throw.
    fn try_compare_and_set(&self, key: &str, expected_version: u64, value: V) -> Result<bool, StateError> {
        Ok(self.compare_and_set(key, expected_version, value))
    }
    fn compare_and_remove(&self, key: &str, expected_version: u64) -> bool;
    /// Unconditional remove; `true` if the key was present.
    fn remove(&self, key: &str) -> bool;
    fn entries(&self) -> Vec<(String, Versioned<V>)>;
    fn size(&self) -> usize;
    fn clear(&self);
    /// Resizes a bounded store's capacity, evicting the eldest entries immediately if the new capacity is
    /// smaller than the current entry count (`maxExpectations` changed via `PUT /mockserver/configuration`).
    /// A no-op for an unbounded store.
    fn set_max_size(&self, _max_size: usize) {}
    fn add_invalidation_listener(&self, listener: Arc<dyn InvalidationListener>);
}

/// Binary large-object store abstraction (`org.mockserver.state.BlobStore`): the Infinispan `blobs` cache
/// (late-joiner restore in clustered mode), the memory backend's store, or the cloud store
/// `blobStoreType` selects (`src/blob/`). Persisted expectations go to it unless it is upstream's
/// `FilesystemBlobStore` (`src/persistence.rs`).
pub trait BlobStore: Send + Sync {
    fn put(&self, key: &str, data: Vec<u8>, metadata: HashMap<String, String>);
    fn get(&self, key: &str) -> Option<Blob>;
    /// Keys starting with `prefix`.
    fn list(&self, prefix: &str) -> Vec<String>;
    fn delete(&self, key: &str) -> bool;
    /// [`put`](Self::put) reporting the failure Java would throw (a cloud store's request failing). Stores that cannot
    /// fail keep the default.
    fn try_put(&self, key: &str, data: Vec<u8>, metadata: HashMap<String, String>) -> Result<(), StateError> {
        self.put(key, data, metadata);
        Ok(())
    }
    fn try_get(&self, key: &str) -> Result<Option<Blob>, StateError> {
        Ok(self.get(key))
    }
    fn try_list(&self, prefix: &str) -> Result<Vec<String>, StateError> {
        Ok(self.list(prefix))
    }
    fn try_delete(&self, key: &str) -> Result<bool, StateError> {
        Ok(self.delete(key))
    }
}

/// One cluster member (`org.mockserver.state.ClusterInfo.Member`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMember {
    pub id: String,
    pub coordinator: bool,
    pub local: bool,
}

/// Cluster membership snapshot (`org.mockserver.state.ClusterInfo`), served by `GET /mockserver/cluster`
/// (`control::cluster`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterInfo {
    pub clustered: bool,
    pub node_id: String,
    pub coordinator: String,
    pub cluster_name: Option<String>,
    /// Never empty: always contains at least this node.
    pub members: Vec<ClusterMember>,
}

impl ClusterInfo {
    /// The degenerate single-node snapshot every non-clustered backend reports.
    pub fn single_node(node_id: &str) -> Self {
        ClusterInfo {
            clustered: false,
            node_id: node_id.to_string(),
            coordinator: node_id.to_string(),
            cluster_name: None,
            members: vec![ClusterMember { id: node_id.to_string(), coordinator: true, local: true }],
        }
    }
}

/// Pluggable backend for all shared MockServer state (`org.mockserver.state.StateBackend`). One instance per
/// server. Upstream extends `Closeable`; this port has no `close`/`Drop` method — both backends here
/// hold no resource that needs releasing (no file handles, no network connections in LOCAL mode), so
/// Rust's ordinary drop glue already does upstream's `close()` for free. A future backend that opens a real
/// connection (a clustered Infinispan/JGroups transport) can implement `Drop` itself without
/// this trait needing a method for it.
pub trait StateBackend: Send + Sync {
    fn expectations(&self) -> &dyn KeyValueStore<ExpectationEntry>;
    /// Keys are composite scenario-name + isolation strings; values are state strings.
    fn scenario_states(&self) -> &dyn KeyValueStore<String>;
    /// `sharedTimesCounters()`: the remaining uses of each clustered limited-`Times` expectation, consumed by a
    /// compare-and-set on this small counter rather than on the whole `ExpectationEntry`. `None` (upstream's default
    /// `null`) keeps the legacy on-entry path; only the clustered backend reads it (`isClusteredLimitedTimes`).
    fn shared_times_counters(&self) -> Option<&dyn KeyValueStore<i32>> {
        None
    }
    /// A CRUD entity store for `namespace`, created on first use and shared by every later call with the same
    /// namespace (`cross-protocol-bus`, `chaos-service`, `chaos-tcp`, `chaos-grpc`, `chaos-profiles`,
    /// `load-scenarios`, as upstream's backend creates them — none of those registries are
    /// rewired to this SPI yet; `crud_entities` exists for the work that does).
    fn crud_entities(&self, namespace: &str) -> Arc<dyn KeyValueStore<serde_json::Value>>;
    fn blobs(&self) -> &dyn BlobStore;
    /// Adds a listener notified by every store this backend manages.
    fn add_invalidation_listener(&self, listener: Arc<dyn InvalidationListener>);
    /// A unique identifier for this node/instance.
    fn node_id(&self) -> &str;
    /// `true` for a multi-node backend. Both backends here are single-node.
    fn is_clustered(&self) -> bool {
        false
    }
    fn cluster_info(&self) -> ClusterInfo {
        ClusterInfo::single_node(self.node_id())
    }
    /// Whether [`StateBackend::blobs`] is not upstream's `FilesystemBlobStore`: the Infinispan backends hand out their
    /// `blobs` cache (local or replicated), so `persistExpectations` writes the document there and leaves the file as
    /// created. The memory backend's store follows `blobStoreType` instead (see `persistence::uses_blobs`).
    fn blobs_replace_files(&self) -> bool {
        self.is_clustered()
    }
    /// `StateBackend.close()`: releases what the backend holds (a clustered one leaves its cluster). Idempotent;
    /// a no-op for the backends that hold nothing.
    fn close(&self) {}
}

/// Which backend `stateBackend` selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Memory,
    /// `infinispan`, `clusterEnabled=false`: [`infinispan::InfinispanStateBackend`] (LOCAL mode).
    Infinispan,
    /// `infinispan`, `clusterEnabled=true`: [`cluster::ClusterStateBackend`] (REPL_SYNC over JGroups).
    InfinispanClustered,
}

/// Resolves `stateBackend` (default `memory`) against `clusterEnabled`, the way
/// `StateBackendFactory.create` does (`StateBackendFactory.java:133-140`): only the value `infinispan`
/// (case-insensitively — upstream uses `equalsIgnoreCase`) is special-cased; every other value, including an
/// unrecognised one, resolves to `memory` (upstream never validates `stateBackend` beyond that one check — a
/// typo silently runs in-memory, matching the real behaviour rather than a validation this port would be
/// inventing).
///
/// `clusterEnabled=true` with `stateBackend=memory` is likewise not an error upstream: the default factory
/// ignores `clusterEnabled` entirely (only the `infinispan`-classpath-discovery path reads it), so this port
/// does the same. With `stateBackend=infinispan` it selects the clustered backend.
pub fn resolve(config: &crate::Config) -> Result<Kind, String> {
    let name = config.property("stateBackend").unwrap_or_default();
    if name.trim().eq_ignore_ascii_case("infinispan") {
        if config.bool_property("clusterEnabled", false) { Ok(Kind::InfinispanClustered) } else { Ok(Kind::Infinispan) }
    } else {
        Ok(Kind::Memory)
    }
}

/// Builds the non-clustered backend `kind` selects, bounding the `expectations` store at `max_expectations`
/// (`mockserver.maxExpectations`, default 15000). The clustered kind needs [`create`]: it joins a cluster.
pub fn build(kind: Kind, max_expectations: usize) -> Arc<dyn StateBackend> {
    match kind {
        Kind::Memory => Arc::new(memory::InMemoryStateBackend::new(max_expectations)),
        Kind::Infinispan => Arc::new(infinispan::InfinispanStateBackend::new(max_expectations)),
        Kind::InfinispanClustered => panic!("the clustered backend joins a cluster: build it with state_backend::create"),
    }
}

/// `StateBackendFactory.create(configuration)`: the backend the configuration selects. A clustered one joins its
/// cluster before this returns (the initial state transfer included), so call it before binding any port; it
/// fails when the transport configuration is unreadable or the cluster cannot be joined.
pub fn create(config: &crate::Config) -> Result<Arc<dyn StateBackend>, String> {
    let max_expectations = config.int_property("maxExpectations", crate::config::default_max_expectations(config)).max(0) as usize;
    match resolve(config)? {
        Kind::InfinispanClustered => Ok(Arc::new(cluster::ClusterStateBackend::start(cluster::ClusterOptions::from_config(config)?)?)),
        // `DEFAULT_FACTORY`: `new InMemoryStateBackend(maxExpectations, createBlobStore(configuration))`; the
        // Infinispan factory has its own `blobs` cache and never reads `blobStoreType`.
        Kind::Memory => match crate::blob::create(config)? {
            crate::blob::Selected::Cloud(store) => Ok(Arc::new(memory::InMemoryStateBackend::with_blob_store(max_expectations, store))),
            crate::blob::Selected::Filesystem | crate::blob::Selected::Memory => Ok(build(Kind::Memory, max_expectations)),
        },
        kind => Ok(build(kind, max_expectations)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(properties: &[(&str, &str)]) -> crate::Config {
        properties.iter().fold(crate::Config::for_tests(), |c, (k, v)| c.with_property(k, v))
    }

    #[test]
    fn defaults_to_memory() {
        assert_eq!(resolve(&config(&[])), Ok(Kind::Memory));
    }

    #[test]
    fn unrecognised_value_falls_back_to_memory_like_upstream() {
        assert_eq!(resolve(&config(&[("stateBackend", "banana")])), Ok(Kind::Memory));
    }

    #[test]
    fn cluster_enabled_with_memory_backend_is_ignored_like_upstream() {
        assert_eq!(resolve(&config(&[("stateBackend", "memory"), ("clusterEnabled", "true")])), Ok(Kind::Memory));
    }

    #[test]
    fn infinispan_local_mode_resolves() {
        assert_eq!(resolve(&config(&[("stateBackend", "infinispan")])), Ok(Kind::Infinispan));
        assert_eq!(resolve(&config(&[("stateBackend", "InfiniSpan")])), Ok(Kind::Infinispan));
        assert_eq!(resolve(&config(&[("stateBackend", "infinispan"), ("clusterEnabled", "false")])), Ok(Kind::Infinispan));
    }

    #[test]
    fn infinispan_with_cluster_enabled_resolves_to_the_clustered_backend() {
        assert_eq!(resolve(&config(&[("stateBackend", "infinispan"), ("clusterEnabled", "true")])), Ok(Kind::InfinispanClustered));
    }
}

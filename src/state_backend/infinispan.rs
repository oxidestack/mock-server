//! `stateBackend=infinispan`, **LOCAL mode only** (`clusterEnabled=false`).
//! `org.mockserver.state.infinispan.InfinispanStateBackend`.
//!
//! Upstream's LOCAL-mode cache manager (`InfinispanStateBackend.createLocalCacheManager`,
//! `InfinispanStateBackend.java:150-173`) is `global.nonClusteredDefault()` with a permissive
//! deserialisation allow-list "because caches are heap-only with no network marshalling exposure" (upstream's
//! own doc comment, `InfinispanStateBackend.java:27-30`): no JGroups transport, no network I/O, no
//! marshalling — just a heap `Cache` per name (`expectations` bounded by `maxCount`/`whenFull(REMOVE)`,
//! `scenarioStates` and `blobs` unbounded). That is exactly what [`super::memory::InMemoryStateBackend`]
//! already is, so this type wraps one rather than re-implementing an equivalent engine — not a shortcut, but
//! upstream's own specified LOCAL-mode behaviour (LOCAL mode is behaviourally identical to memory, so no
//! oracle scenario differs).
//!
//! **CLUSTERED mode** (`clusterEnabled=true`) needs a real JGroups-transported, REPL_SYNC-replicated engine —
//! the jgroups and infinispan-rs crates (the clustered backend). `state_backend::resolve`
//! rejects that combination today rather than this type silently standing in for it.

use std::sync::Arc;

use super::memory::InMemoryStateBackend;
use super::{BlobStore, ExpectationEntry, InvalidationListener, KeyValueStore, StateBackend};

pub struct InfinispanStateBackend {
    inner: InMemoryStateBackend,
}

impl InfinispanStateBackend {
    /// `new InfinispanStateBackend(int maxExpectations)`: upstream's own "backward-compatible constructor for
    /// tests and single-node usage" — LOCAL mode, which is the only mode this type has.
    pub fn new(max_expectations: usize) -> Self {
        InfinispanStateBackend { inner: InMemoryStateBackend::new(max_expectations) }
    }
}

impl StateBackend for InfinispanStateBackend {
    fn expectations(&self) -> &dyn KeyValueStore<ExpectationEntry> {
        self.inner.expectations()
    }

    fn scenario_states(&self) -> &dyn KeyValueStore<String> {
        self.inner.scenario_states()
    }

    fn shared_times_counters(&self) -> Option<&dyn KeyValueStore<i32>> {
        self.inner.shared_times_counters()
    }

    fn crud_entities(&self, namespace: &str) -> Arc<dyn KeyValueStore<serde_json::Value>> {
        self.inner.crud_entities(namespace)
    }

    fn blobs(&self) -> &dyn BlobStore {
        self.inner.blobs()
    }

    fn add_invalidation_listener(&self, listener: Arc<dyn InvalidationListener>) {
        self.inner.add_invalidation_listener(listener)
    }

    /// LOCAL mode still hands out `InfinispanBlobStore` (a heap-only cache), not the `FilesystemBlobStore`.
    fn blobs_replace_files(&self) -> bool {
        true
    }

    fn node_id(&self) -> &str {
        self.inner.node_id()
    }

    // `is_clustered`/`cluster_info`: the trait's defaults (`false` / `ClusterInfo::single_node`) are exactly
    // right for LOCAL mode — no override needed.
}

#[cfg(test)]
mod tests {
    //! Port of `InfinispanStateBackendTest` (10 `@Test`, all
    //! LOCAL mode — the class never constructs a clustered backend). One adaptation throughout: upstream asserts
    //! `instanceof InfinispanKeyValueStore`/`InfinispanBlobStore` to prove each store came from the Infinispan
    //! backend rather than being `null`; Rust has no such runtime type check to port, so these assert the store
    //! is reachable and functional instead (the type system already guarantees it is the right Rust type).
    //!
    //! `InfinispanStateBackendRegistrarTest` (2 `@Test`) is **not applicable**: it tests
    //! `StateBackendFactory`'s reflective classpath discovery of a separately-compiled Infinispan module
    //! (`Class.forName(INFINISPAN_REGISTRAR_CLASS)`, `StateBackendFactory.java:220-237`) and a
    //! register/deregister toggle on that factory. This port has no reflective plugin loading and no separate
    //! Infinispan module to discover — both backends are compiled into one binary, and `state_backend::resolve`
    //! (this module's parent) selects between them directly from `stateBackend` at startup. There is no
    //! `StateBackendFactory`-shaped registry for a Rust test to exercise; `resolve`'s own tests
    //! (`state_backend::tests`) are the counterpart proof that the selection itself is correct.

    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct CountingListener {
        changed: AtomicUsize,
    }

    impl InvalidationListener for CountingListener {
        fn on_changed(&self, _key: &str) {
            self.changed.fetch_add(1, Ordering::Relaxed);
        }
        fn on_cleared(&self) {}
    }

    fn backend() -> InfinispanStateBackend {
        InfinispanStateBackend::new(100)
    }

    /// `shouldReturnExpectationsStore`.
    #[test]
    fn returns_expectations_store() {
        let backend = backend();
        assert_eq!(backend.expectations().size(), 0);
    }

    /// `shouldReturnScenarioStatesStore`.
    #[test]
    fn returns_scenario_states_store() {
        let backend = backend();
        backend.scenario_states().put("scenario1", "Started".to_string());
        let result = backend.scenario_states().get("scenario1").unwrap();
        assert_eq!(result.value, "Started");
    }

    /// `shouldReturnCrudEntitiesStore`.
    #[test]
    fn returns_crud_entities_store_scoped_by_namespace() {
        let backend = backend();
        let store1 = backend.crud_entities("ns1");
        let store2 = backend.crud_entities("ns2");
        store1.put("item1", serde_json::json!({"id": "1"}));
        assert!(store2.get("item1").is_none());
        assert!(store1.get("item1").is_some());
    }

    /// `shouldReturnSameStoreForSameNamespace`.
    #[test]
    fn returns_same_store_for_same_namespace() {
        let backend = backend();
        let store1 = backend.crud_entities("ns1");
        let store2 = backend.crud_entities("ns1");
        assert!(Arc::ptr_eq(&store1, &store2));
    }

    /// `shouldReturnBlobStore` + `shouldStoreAndRetrieveBlobs`.
    #[test]
    fn stores_and_retrieves_blobs() {
        let backend = backend();
        backend.blobs().put("test/blob1", vec![1, 2, 3], Default::default());
        let blob = backend.blobs().get("test/blob1").unwrap();
        assert_eq!(blob.data, vec![1, 2, 3]);
    }

    /// `shouldReturnNodeId`.
    #[test]
    fn returns_a_non_empty_node_id() {
        let backend = backend();
        assert!(!backend.node_id().is_empty());
    }

    /// `shouldReportSingleNodeClusterInfoInLocalMode`.
    #[test]
    fn reports_single_node_cluster_info_in_local_mode() {
        let backend = backend();
        let info = backend.cluster_info();
        assert!(!info.clustered);
        assert_eq!(info.node_id, backend.node_id());
        assert_eq!(info.coordinator, backend.node_id());
        assert_eq!(info.members.len(), 1);
        let member = &info.members[0];
        assert_eq!(member.id, backend.node_id());
        assert!(member.coordinator);
        assert!(member.local);
    }

    /// `shouldFireInvalidationListenerOnExpectationChange` (upstream's method name notwithstanding, the
    /// assertion is on `scenarioStates().put` — ported as written).
    #[test]
    fn fires_invalidation_listener_on_change() {
        let backend = backend();
        let listener = Arc::new(CountingListener { changed: AtomicUsize::new(0) });
        backend.add_invalidation_listener(listener.clone());
        backend.scenario_states().put("s1", "state1".to_string());
        assert_eq!(listener.changed.load(Ordering::Relaxed), 1);
    }
}

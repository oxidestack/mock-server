//! `stateBackend=memory` (the default): `InMemoryKeyValueStore`, `InMemoryExpectationKeyValueStore`,
//! `InMemoryBlobStore` and `InMemoryStateBackend` (`MS/mockserver-core/src/main/java/org/mockserver/state/
//! InMemory*.java`), ported 1:1 — upstream's implementation is already a small, self-contained
//! `ConcurrentHashMap`/version-counter design with no JVM-specific behaviour to adapt.
//!
//! One divergence from upstream's `ConcurrentHashMap` + `synchronized(entry)` + `AtomicLong` design: each entry
//! here is one `RwLock<Slot<V>>`, so a read/write of a single entry is one lock acquisition instead of two
//! (a `ConcurrentHashMap` read plus a `synchronized` block). Observably identical — both are last-writer-wins
//! on `put`, and both make `compare_and_set`/`compare_and_remove` atomic against concurrent mutation of the
//! same key.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use super::{Blob, BlobStore, ExpectationEntry, InvalidationListener, KeyValueStore, StateBackend};

struct Slot<V> {
    value: V,
    version: u64,
}

/// General-purpose in-memory `KeyValueStore` (`InMemoryKeyValueStore<V>`): unordered, unbounded. Used for
/// `scenarioStates` and on-demand `crud-<ns>` stores. NOT used for `expectations` — see
/// [`InMemoryExpectationStore`], which needs insertion-order eviction `InMemoryKeyValueStore` does not have.
pub struct InMemoryKeyValueStore<V> {
    map: RwLock<HashMap<String, Arc<RwLock<Slot<V>>>>>,
    listeners: Mutex<Vec<Arc<dyn InvalidationListener>>>,
}

impl<V> Default for InMemoryKeyValueStore<V> {
    fn default() -> Self {
        InMemoryKeyValueStore { map: RwLock::new(HashMap::new()), listeners: Mutex::new(Vec::new()) }
    }
}

impl<V> InMemoryKeyValueStore<V> {
    pub fn new() -> Self {
        Self::default()
    }

    fn fire_changed(&self, key: &str) {
        for listener in self.listeners.lock().iter() {
            listener.on_changed(key);
        }
    }

    fn fire_cleared(&self) {
        for listener in self.listeners.lock().iter() {
            listener.on_cleared();
        }
    }
}

impl<V: Clone + PartialEq + Send + Sync> KeyValueStore<V> for InMemoryKeyValueStore<V> {
    fn get(&self, key: &str) -> Option<super::Versioned<V>> {
        let slot = self.map.read().get(key).cloned()?;
        let slot = slot.read();
        Some(super::Versioned { value: slot.value.clone(), version: slot.version })
    }

    fn put(&self, key: &str, value: V) -> u64 {
        // Existing key: update in place under its own lock (the common, fast path).
        if let Some(slot) = self.map.read().get(key).cloned() {
            let mut slot = slot.write();
            slot.value = value;
            slot.version += 1;
            let version = slot.version;
            drop(slot);
            self.fire_changed(key);
            return version;
        }
        // New key: insert under the map lock (a concurrent racer may have inserted first).
        let mut map = self.map.write();
        if let Some(slot) = map.get(key).cloned() {
            drop(map);
            let mut slot = slot.write();
            slot.value = value;
            slot.version += 1;
            let version = slot.version;
            drop(slot);
            self.fire_changed(key);
            return version;
        }
        map.insert(key.to_string(), Arc::new(RwLock::new(Slot { value, version: 1 })));
        drop(map);
        self.fire_changed(key);
        1
    }

    fn put_if_absent(&self, key: &str, value: V) -> Option<super::Versioned<V>> {
        let mut map = self.map.write();
        if let Some(slot) = map.get(key) {
            let slot = slot.read();
            return Some(super::Versioned { value: slot.value.clone(), version: slot.version });
        }
        map.insert(key.to_string(), Arc::new(RwLock::new(Slot { value, version: 1 })));
        drop(map);
        self.fire_changed(key);
        None
    }

    fn compare_and_set(&self, key: &str, expected_version: u64, value: V) -> bool {
        let Some(slot) = self.map.read().get(key).cloned() else { return false };
        {
            let mut slot = slot.write();
            if slot.version != expected_version {
                return false;
            }
            slot.value = value;
            slot.version += 1;
        }
        self.fire_changed(key);
        true
    }

    fn compare_and_remove(&self, key: &str, expected_version: u64) -> bool {
        let mut map = self.map.write();
        match map.get(key) {
            Some(slot) if slot.read().version == expected_version => {
                map.remove(key);
                drop(map);
                self.fire_changed(key);
                true
            }
            _ => false,
        }
    }

    fn remove(&self, key: &str) -> bool {
        let removed = self.map.write().remove(key).is_some();
        if removed {
            self.fire_changed(key);
        }
        removed
    }

    fn entries(&self) -> Vec<(String, super::Versioned<V>)> {
        self.map
            .read()
            .iter()
            .map(|(k, slot)| {
                let slot = slot.read();
                (k.clone(), super::Versioned { value: slot.value.clone(), version: slot.version })
            })
            .collect()
    }

    fn size(&self) -> usize {
        self.map.read().len()
    }

    fn clear(&self) {
        self.map.write().clear();
        self.fire_cleared();
    }

    fn add_invalidation_listener(&self, listener: Arc<dyn InvalidationListener>) {
        self.listeners.lock().push(listener);
    }
}

struct ExpEntry {
    value: ExpectationEntry,
    version: u64,
}

#[derive(Default)]
struct ExpInner {
    map: HashMap<String, ExpEntry>,
    /// Insertion order of currently-present keys, oldest first — eviction order on overflow
    /// (`InMemoryExpectationKeyValueStore`'s `CircularPriorityQueue`: the eviction victim is always the oldest
    /// by original insertion time, regardless of later in-place updates; an in-place `put` never moves a key
    /// within this order, matching upstream's COR-01 fix).
    order: VecDeque<String>,
}

/// `expectations`: bounded by `maxExpectations`, oldest-by-insertion-time evicted on overflow
/// (`InMemoryExpectationKeyValueStore`). The exact eviction *policy* upstream uses in clustered mode is
/// Caffeine's W-TinyLFU (the caffeine-rs crate; not wire-visible, so it need not be bit-exact); LOCAL
/// mode's own bound is this simpler oldest-first order (LOCAL-mode semantics = in-memory with a Caffeine-sized
/// bound: the *size* bound, not Caffeine's frequency-aware victim choice).
pub struct InMemoryExpectationStore {
    inner: RwLock<ExpInner>,
    max_size: AtomicUsize,
    listeners: Mutex<Vec<Arc<dyn InvalidationListener>>>,
}

impl InMemoryExpectationStore {
    pub fn new(max_size: usize) -> Self {
        InMemoryExpectationStore { inner: RwLock::new(ExpInner::default()), max_size: AtomicUsize::new(max_size), listeners: Mutex::new(Vec::new()) }
    }

    fn fire_changed(&self, key: &str) {
        for listener in self.listeners.lock().iter() {
            listener.on_changed(key);
        }
    }

    fn fire_cleared(&self) {
        for listener in self.listeners.lock().iter() {
            listener.on_cleared();
        }
    }

    /// Evicts the oldest entries while over `max_size`. `max_size == 0` means unbounded (never evicts) — this
    /// port's own extension for tests that want no bound; upstream's `maxExpectations` is never configured to 0.
    fn evict_over_capacity(inner: &mut ExpInner, max_size: usize) {
        while max_size > 0 && inner.map.len() > max_size {
            let Some(oldest) = inner.order.pop_front() else { break };
            inner.map.remove(&oldest);
        }
    }
}

impl KeyValueStore<ExpectationEntry> for InMemoryExpectationStore {
    fn get(&self, key: &str) -> Option<super::Versioned<ExpectationEntry>> {
        self.inner.read().map.get(key).map(|e| super::Versioned { value: e.value.clone(), version: e.version })
    }

    fn put(&self, key: &str, value: ExpectationEntry) -> u64 {
        let mut inner = self.inner.write();
        if let Some(e) = inner.map.get_mut(key) {
            e.value = value;
            e.version += 1;
            let version = e.version;
            drop(inner);
            self.fire_changed(key);
            return version;
        }
        inner.map.insert(key.to_string(), ExpEntry { value, version: 1 });
        inner.order.push_back(key.to_string());
        Self::evict_over_capacity(&mut inner, self.max_size.load(Ordering::Relaxed));
        drop(inner);
        self.fire_changed(key);
        1
    }

    fn put_if_absent(&self, key: &str, value: ExpectationEntry) -> Option<super::Versioned<ExpectationEntry>> {
        let mut inner = self.inner.write();
        if let Some(e) = inner.map.get(key) {
            return Some(super::Versioned { value: e.value.clone(), version: e.version });
        }
        inner.map.insert(key.to_string(), ExpEntry { value, version: 1 });
        inner.order.push_back(key.to_string());
        Self::evict_over_capacity(&mut inner, self.max_size.load(Ordering::Relaxed));
        drop(inner);
        self.fire_changed(key);
        None
    }

    fn compare_and_set(&self, key: &str, expected_version: u64, value: ExpectationEntry) -> bool {
        let mut inner = self.inner.write();
        let Some(e) = inner.map.get_mut(key) else { return false };
        if e.version != expected_version {
            return false;
        }
        e.value = value;
        e.version += 1;
        drop(inner);
        self.fire_changed(key);
        true
    }

    fn compare_and_remove(&self, key: &str, expected_version: u64) -> bool {
        let mut inner = self.inner.write();
        match inner.map.get(key) {
            Some(e) if e.version == expected_version => {
                inner.map.remove(key);
                inner.order.retain(|k| k != key);
                drop(inner);
                self.fire_changed(key);
                true
            }
            _ => false,
        }
    }

    fn remove(&self, key: &str) -> bool {
        let mut inner = self.inner.write();
        let removed = inner.map.remove(key).is_some();
        if removed {
            inner.order.retain(|k| k != key);
        }
        drop(inner);
        if removed {
            self.fire_changed(key);
        }
        removed
    }

    fn entries(&self) -> Vec<(String, super::Versioned<ExpectationEntry>)> {
        self.inner.read().map.iter().map(|(k, e)| (k.clone(), super::Versioned { value: e.value.clone(), version: e.version })).collect()
    }

    fn size(&self) -> usize {
        self.inner.read().map.len()
    }

    fn clear(&self) {
        let mut inner = self.inner.write();
        inner.map.clear();
        inner.order.clear();
        drop(inner);
        self.fire_cleared();
    }

    fn set_max_size(&self, max_size: usize) {
        self.max_size.store(max_size, Ordering::Relaxed);
        let mut inner = self.inner.write();
        Self::evict_over_capacity(&mut inner, max_size);
    }

    fn add_invalidation_listener(&self, listener: Arc<dyn InvalidationListener>) {
        self.listeners.lock().push(listener);
    }
}

/// `InMemoryBlobStore`: blobs held entirely in memory, lost on process exit.
#[derive(Default)]
pub struct InMemoryBlobStore {
    blobs: RwLock<HashMap<String, Blob>>,
}

impl BlobStore for InMemoryBlobStore {
    fn put(&self, key: &str, data: Vec<u8>, metadata: HashMap<String, String>) {
        self.blobs.write().insert(key.to_string(), Blob { key: key.to_string(), data, metadata });
    }

    fn get(&self, key: &str) -> Option<Blob> {
        self.blobs.read().get(key).cloned()
    }

    fn list(&self, prefix: &str) -> Vec<String> {
        self.blobs.read().keys().filter(|k| k.starts_with(prefix)).cloned().collect()
    }

    fn delete(&self, key: &str) -> bool {
        self.blobs.write().remove(key).is_some()
    }
}

/// The default `StateBackend` (`InMemoryStateBackend`): every store node-local, no network I/O.
pub struct InMemoryStateBackend {
    expectations: InMemoryExpectationStore,
    scenario_states: InMemoryKeyValueStore<String>,
    /// `sharedTimesCounters`: unbounded, as upstream's `new InMemoryKeyValueStore<>()`.
    shared_times: InMemoryKeyValueStore<i32>,
    crud_stores: RwLock<HashMap<String, Arc<dyn KeyValueStore<serde_json::Value>>>>,
    blobs: Arc<dyn BlobStore>,
    /// The blob store came from `blobStoreType` (a cloud module's), not the backend's own in-memory one.
    external_blobs: bool,
    node_id: String,
}

impl InMemoryStateBackend {
    pub fn new(max_expectations: usize) -> Self {
        Self::build(max_expectations, Arc::new(InMemoryBlobStore::default()), false)
    }

    /// `new InMemoryStateBackend(maxExpectations, blobStore)` with a cloud module's store (`src/blob/`).
    pub fn with_blob_store(max_expectations: usize, blobs: Arc<dyn BlobStore>) -> Self {
        Self::build(max_expectations, blobs, true)
    }

    fn build(max_expectations: usize, blobs: Arc<dyn BlobStore>, external_blobs: bool) -> Self {
        InMemoryStateBackend {
            expectations: InMemoryExpectationStore::new(max_expectations),
            scenario_states: InMemoryKeyValueStore::new(),
            shared_times: InMemoryKeyValueStore::new(),
            crud_stores: RwLock::new(HashMap::new()),
            blobs,
            external_blobs,
            node_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

impl StateBackend for InMemoryStateBackend {
    fn expectations(&self) -> &dyn KeyValueStore<ExpectationEntry> {
        &self.expectations
    }

    fn scenario_states(&self) -> &dyn KeyValueStore<String> {
        &self.scenario_states
    }

    fn shared_times_counters(&self) -> Option<&dyn KeyValueStore<i32>> {
        Some(&self.shared_times)
    }

    fn crud_entities(&self, namespace: &str) -> Arc<dyn KeyValueStore<serde_json::Value>> {
        if let Some(store) = self.crud_stores.read().get(namespace) {
            return store.clone();
        }
        self.crud_stores.write().entry(namespace.to_string()).or_insert_with(|| Arc::new(InMemoryKeyValueStore::new())).clone()
    }

    fn blobs(&self) -> &dyn BlobStore {
        &*self.blobs
    }

    /// A cloud store holds the persisted document; the backend's own in-memory store follows `blobStoreType=memory`.
    fn blobs_replace_files(&self) -> bool {
        self.external_blobs
    }

    fn add_invalidation_listener(&self, listener: Arc<dyn InvalidationListener>) {
        self.expectations.add_invalidation_listener(listener.clone());
        self.scenario_states.add_invalidation_listener(listener);
    }

    fn node_id(&self) -> &str {
        &self.node_id
    }
}

#[cfg(test)]
mod tests {
    //! Port of `KeyValueStoreContract`/`InMemoryKeyValueStoreTest`-shaped cases
    //! (upstream's `KeyValueStoreContract` and its ContractTest runner, 22
    //! `@Test`): get/put/putIfAbsent/CAS/remove/entries/clear against [`InMemoryKeyValueStore`], plus the
    //! bounded-eviction behaviour specific to [`InMemoryExpectationStore`].

    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct CountingListener {
        changed: AtomicUsize,
        cleared: AtomicUsize,
    }

    impl InvalidationListener for CountingListener {
        fn on_changed(&self, _key: &str) {
            self.changed.fetch_add(1, Ordering::Relaxed);
        }
        fn on_cleared(&self) {
            self.cleared.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn put_then_get_round_trips_with_version_one() {
        let store = InMemoryKeyValueStore::<String>::new();
        let version = store.put("k", "v1".to_string());
        assert_eq!(version, 1);
        let got = store.get("k").unwrap();
        assert_eq!(got.value, "v1");
        assert_eq!(got.version, 1);
    }

    #[test]
    fn put_again_increments_version_last_writer_wins() {
        let store = InMemoryKeyValueStore::<String>::new();
        store.put("k", "v1".to_string());
        let version = store.put("k", "v2".to_string());
        assert_eq!(version, 2);
        assert_eq!(store.get("k").unwrap().value, "v2");
    }

    #[test]
    fn put_if_absent_creates_once_and_reports_existing_after() {
        let store = InMemoryKeyValueStore::<String>::new();
        assert!(store.put_if_absent("k", "first".to_string()).is_none());
        let existing = store.put_if_absent("k", "second".to_string()).unwrap();
        assert_eq!(existing.value, "first");
        assert_eq!(store.get("k").unwrap().value, "first");
    }

    #[test]
    fn compare_and_set_succeeds_only_on_matching_version() {
        let store = InMemoryKeyValueStore::<String>::new();
        store.put("k", "v1".to_string());
        assert!(!store.compare_and_set("k", 99, "v2".to_string()));
        assert!(store.compare_and_set("k", 1, "v2".to_string()));
        assert_eq!(store.get("k").unwrap().value, "v2");
        assert_eq!(store.get("k").unwrap().version, 2);
    }

    #[test]
    fn compare_and_remove_succeeds_only_on_matching_version() {
        let store = InMemoryKeyValueStore::<String>::new();
        store.put("k", "v1".to_string());
        assert!(!store.compare_and_remove("k", 99));
        assert!(store.compare_and_remove("k", 1));
        assert!(store.get("k").is_none());
    }

    #[test]
    fn remove_reports_presence() {
        let store = InMemoryKeyValueStore::<String>::new();
        assert!(!store.remove("missing"));
        store.put("k", "v".to_string());
        assert!(store.remove("k"));
        assert!(!store.remove("k"));
    }

    #[test]
    fn entries_size_and_clear() {
        let store = InMemoryKeyValueStore::<String>::new();
        store.put("a", "1".to_string());
        store.put("b", "2".to_string());
        assert_eq!(store.size(), 2);
        let mut keys: Vec<String> = store.entries().into_iter().map(|(k, _)| k).collect();
        keys.sort();
        assert_eq!(keys, vec!["a".to_string(), "b".to_string()]);
        store.clear();
        assert_eq!(store.size(), 0);
    }

    #[test]
    fn invalidation_listener_fires_on_changed_and_cleared() {
        let store = InMemoryKeyValueStore::<String>::new();
        let listener = Arc::new(CountingListener { changed: AtomicUsize::new(0), cleared: AtomicUsize::new(0) });
        store.add_invalidation_listener(listener.clone());
        store.put("k", "v".to_string());
        store.put("k", "v2".to_string());
        store.remove("k");
        assert_eq!(listener.changed.load(Ordering::Relaxed), 3);
        store.put("k2", "v".to_string());
        store.clear();
        assert_eq!(listener.cleared.load(Ordering::Relaxed), 1);
    }

    fn entry(id: &str, priority: i64, created: u64) -> ExpectationEntry {
        ExpectationEntry { id: id.to_string(), priority, created, remaining_times: -1, expectation_json: serde_json::json!({"id": id}) }
    }

    #[test]
    fn expectation_store_evicts_oldest_by_insertion_on_overflow() {
        let store = InMemoryExpectationStore::new(2);
        store.put("a", entry("a", 0, 1));
        store.put("b", entry("b", 0, 2));
        store.put("c", entry("c", 0, 3));
        assert_eq!(store.size(), 2);
        assert!(store.get("a").is_none(), "the oldest insertion is evicted first");
        assert!(store.get("b").is_some());
        assert!(store.get("c").is_some());
    }

    #[test]
    fn expectation_store_in_place_update_does_not_move_insertion_order() {
        let store = InMemoryExpectationStore::new(2);
        store.put("a", entry("a", 0, 1));
        store.put("b", entry("b", 0, 2));
        // Updating "a" in place must NOT make it "newer" for eviction purposes (COR-01): the next overflow
        // still evicts "a", not "b".
        store.put("a", entry("a", 5, 1));
        store.put("c", entry("c", 0, 3));
        assert!(store.get("a").is_none());
        assert!(store.get("b").is_some());
        assert!(store.get("c").is_some());
    }

    #[test]
    fn expectation_store_set_max_size_shrinks_immediately() {
        let store = InMemoryExpectationStore::new(0);
        store.put("a", entry("a", 0, 1));
        store.put("b", entry("b", 0, 2));
        store.put("c", entry("c", 0, 3));
        assert_eq!(store.size(), 3);
        store.set_max_size(1);
        assert_eq!(store.size(), 1);
        assert!(store.get("c").is_some(), "the newest survives a shrink");
    }

    #[test]
    fn blob_store_round_trips_and_lists_by_prefix() {
        let store = InMemoryBlobStore::default();
        store.put("expectations/1", vec![1, 2, 3], HashMap::new());
        store.put("expectations/2", vec![4, 5], HashMap::new());
        store.put("other/1", vec![9], HashMap::new());
        let blob = store.get("expectations/1").unwrap();
        assert_eq!(blob.data, vec![1, 2, 3]);
        let mut listed = store.list("expectations/");
        listed.sort();
        assert_eq!(listed, vec!["expectations/1".to_string(), "expectations/2".to_string()]);
        assert!(store.delete("expectations/1"));
        assert!(store.get("expectations/1").is_none());
        assert!(!store.delete("expectations/1"));
    }

    #[test]
    fn state_backend_crud_entities_share_the_same_store_per_namespace() {
        let backend = InMemoryStateBackend::new(100);
        let ns1 = backend.crud_entities("ns1");
        let ns2 = backend.crud_entities("ns2");
        ns1.put("item1", serde_json::json!({"id": "1"}));
        assert!(ns2.get("item1").is_none());
        assert!(ns1.get("item1").is_some());
        let ns1_again = backend.crud_entities("ns1");
        assert!(Arc::ptr_eq(&ns1, &ns1_again), "the same namespace returns the same store instance");
    }

    #[test]
    fn state_backend_add_invalidation_listener_covers_expectations_and_scenario_states() {
        let backend = InMemoryStateBackend::new(100);
        let listener = Arc::new(CountingListener { changed: AtomicUsize::new(0), cleared: AtomicUsize::new(0) });
        backend.add_invalidation_listener(listener.clone());
        backend.scenario_states().put("s1", "Started".to_string());
        backend.expectations().put("e1", entry("e1", 0, 1));
        assert_eq!(listener.changed.load(Ordering::Relaxed), 2);
    }
}

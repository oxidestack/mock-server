//! A named registry of JSON definitions kept in one of the state backend's CRUD stores: what upstream's
//! `ChaosProfileLibrary` (`chaos-profiles`) and `LoadScenarioRegistry` (`load-scenarios`) both are. Unlike the chaos
//! registries, which attach a backend only when it is clustered, these always use the backend's store
//! (`HttpState` builds them on `stateBackend` single-node too), so a clustered fleet shares them and a reset leaves
//! them alone.

use std::sync::{Arc, OnceLock};

use serde_json::Value;

use super::memory::InMemoryKeyValueStore;
use super::{KeyValueStore, StateBackend, StateError};

/// The definitions of one CRUD namespace, keyed by name.
#[derive(Default)]
pub struct Registry {
    store: OnceLock<Arc<dyn KeyValueStore<Value>>>,
}

impl Registry {
    /// Uses `backend`'s `crudEntities(namespace)` from now on (once; before it, a store of the registry's own).
    pub fn attach(&self, backend: &dyn StateBackend, namespace: &str) {
        let _ = self.store.set(backend.crud_entities(namespace));
    }

    fn store(&self) -> &Arc<dyn KeyValueStore<Value>> {
        self.store.get_or_init(|| Arc::new(InMemoryKeyValueStore::new()))
    }

    /// `store.put(name, definition)`; `Err` where a clustered backend would throw.
    pub fn put(&self, name: &str, definition: Value) -> Result<(), StateError> {
        self.store().try_put(name, definition).map(|_| ())
    }

    pub fn get(&self, name: &str) -> Option<Value> {
        self.store().get(name).map(|v| v.value)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.store().get(name).is_some()
    }

    /// The names, in `String.compareTo` order (UTF-16 code units).
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.store().entries().into_iter().map(|(k, _)| k).collect();
        names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        names
    }

    /// `true` when `name` was present.
    pub fn remove(&self, name: &str) -> bool {
        self.store().remove(name)
    }

    pub fn clear(&self) {
        self.store().clear();
    }
}

#[cfg(test)]
mod tests {
    //! The storage cases of `ChaosProfileLibraryTest` and `LoadScenarioRegistryTest` (validation is the callers').

    use serde_json::json;

    use super::*;
    use crate::state_backend::memory::InMemoryStateBackend;

    fn registry() -> (Arc<InMemoryStateBackend>, Registry) {
        let backend = Arc::new(InMemoryStateBackend::new(1000));
        let registry = Registry::default();
        registry.attach(&*backend, "chaos-profiles");
        (backend, registry)
    }

    #[test]
    fn save_list_get_and_delete_round_trip() {
        let (_, r) = registry();
        r.put("p1", json!({"name": "p1", "stages": []})).unwrap();
        assert_eq!(r.names(), vec!["p1"]);
        assert_eq!(r.get("p1"), Some(json!({"name": "p1", "stages": []})));
        assert!(r.remove("p1"));
        assert!(r.names().is_empty());
        assert_eq!(r.get("p1"), None);
    }

    #[test]
    fn list_is_sorted_by_name() {
        let (_, r) = registry();
        for name in ["zeta", "alpha", "Mid", "beta"] {
            r.put(name, json!({})).unwrap();
        }
        assert_eq!(r.names(), vec!["Mid", "alpha", "beta", "zeta"]);
    }

    #[test]
    fn put_replaces() {
        let (_, r) = registry();
        r.put("p", json!({"v": 1})).unwrap();
        r.put("p", json!({"v": 2})).unwrap();
        assert_eq!(r.names(), vec!["p"]);
        assert_eq!(r.get("p"), Some(json!({"v": 2})));
    }

    #[test]
    fn unknown_names() {
        let (_, r) = registry();
        assert_eq!(r.get("missing"), None);
        assert!(!r.contains("missing"));
        assert!(!r.remove("missing"));
    }

    #[test]
    fn clear_removes_all() {
        let (_, r) = registry();
        r.put("a", json!({})).unwrap();
        r.put("b", json!({})).unwrap();
        r.clear();
        assert!(r.names().is_empty());
    }

    #[test]
    fn the_definitions_are_the_backends() {
        let (backend, r) = registry();
        r.put("shared", json!({"k": true})).unwrap();
        assert_eq!(backend.crud_entities("chaos-profiles").get("shared").map(|v| v.value), Some(json!({"k": true})));
        backend.crud_entities("chaos-profiles").put("other", json!({}));
        assert_eq!(r.names(), vec!["other", "shared"]);
    }
}

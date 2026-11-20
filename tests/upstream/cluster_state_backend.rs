//! Rust ports of the `mockserver-state-infinispan` suite, run against the CLUSTERED backend — `ClusterStateBackend`, two nodes in this process on the embedded
//! SHARED_LOOPBACK stack (`jgroups-loopback.xml`, the stack upstream's own tests use), REPL_SYNC caches.
//!
//! Ported here (the upstream class, its `@Test` count, and what was adapted):
//! - `KeyValueStoreContract` (22): all of them, against node A's `scenarioStates` store while node B is a member
//!   (upstream's `InfinispanKeyValueStoreContractTest` runs it on a LOCAL cache; this is the clustered run).
//! - `InfinispanBlobStoreTest` (14): all, on the clustered `blobs` cache. `shouldHandleNullMetadataGracefully`
//!   passes no metadata (Rust has no null map).
//! - `InfinispanStateBackendTest` (10, CLUSTERED mode): the LOCAL-only case `shouldReportSingleNodeClusterInfo
//!   InLocalMode` becomes the two-member `clusterInfo` case, and the invalidation-listener case counts the extra
//!   notification the clustered listener raises for a local write in a replicated cache (§4.5).
//! - `DeserializationAllowListTest` (18): the allow-list cases run against the infinispan-rs crate's `ClassAllowList`
//!   with this repo's constant, the round-trips against the Java serialization codec.
//! - `JGroupsKubernetesStackTest` (6): against the embedded stack and the crate's XML parser.
//! - `InfinispanKeyValueStoreConcurrencyTest` (1): on the clustered store.
//! - `ClusteredTwoNodeTest` (33): the 12 cases that need only the backend; the 14 through `RequestMatchers`
//!   (matchability, shared Times, scenario serving) are the core wiring over two real servers; the 6 `ScenarioManager`
//!   cases run on `scenario::Scenarios` attached to each node, the 7th (served exactly once) is in
//!   the core wiring. The shared-`Times` cases run on the `sharedTimesCounters` cache, with
//!   `sharedTimesCounterEnforcesExactlyNAcrossTwoNodesUnderContention`; `Cache::evict` in infinispan-rs
//!   (<https://github.com/oxidestack/infinispan-rs>) carries the two cases that evict a live counter on one node or
//!   both (node-local).
//! - `ClusteredTwoNodeCrossProtocolBusTest` (4) and `ClusteredTwoNodeChaosTest` (10): on `scenario::CrossProtocolBus`
//!   and the chaos registries (`chaos::HostRegistry`, `chaos::grpc::Registry`), fresh per-test instances wired to each
//!   node's backend as upstream's tests do.
//!
//! Not applicable: `InfinispanStateBackendRegistrarTest` (2) — `StateBackendFactory`'s reflective classpath
//! discovery; this binary has no plugin registry (see `src/state_backend/infinispan.rs`'s test module).
//!
//! `ClusteredExpectationPersistenceReloadTest` (2): through two real servers and a fleet keeper
//! (`core_wiring`), which also pin the HTTP answer of a failing clustered put and `GET /mockserver/cluster`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use mock_server::state_backend::cluster::codec::{CLUSTERED_ALLOW_LIST_PATTERNS, clustered_allow_list};
use mock_server::state_backend::cluster::{ClusterOptions, ClusterStateBackend, JGROUPS_KUBERNETES_XML, JGROUPS_LOOPBACK_XML, view_change_line};
use mock_server::state_backend::{Blob, ExpectationEntry, InvalidationListener, KeyValueStore, StateBackend};
use serde_json::json;

/// `ControlPlaneFailureResponse.UNEXPECTED_FAILURE_MESSAGE`, followed by the correlation id.
const UNEXPECTED_FAILURE: &str = "unexpected error processing request, see the MockServer log for correlation id: ";

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Unique per test: a name reused across tests races SHARED_LOOPBACK channel teardown, as upstream's own comment notes.
fn unique_cluster() -> String {
    format!("mockserver-test-cluster-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))
}

fn options(cluster: &str) -> ClusterOptions {
    let mut options = ClusterOptions::new(cluster, 100);
    options.log = Arc::new(|_| {});
    options
}

fn start(cluster: &str) -> ClusterStateBackend {
    ClusterStateBackend::start(options(cluster)).expect("the node joins")
}

fn eventually(what: &str, timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("{what}");
}

/// Two nodes of one cluster; `b` first so it leaves first.
struct Pair {
    b: ClusterStateBackend,
    a: ClusterStateBackend,
    cluster: String,
}

fn pair() -> Pair {
    let cluster = unique_cluster();
    let a = start(&cluster);
    let b = start(&cluster);
    eventually("the 2-node cluster forms", Duration::from_secs(30), || a.members().len() == 2 && b.members().len() == 2);
    Pair { b, a, cluster }
}

fn entry(id: &str, path: &str) -> ExpectationEntry {
    ExpectationEntry { id: id.into(), priority: 0, created: 1000, remaining_times: -1, expectation_json: json!({"id": id, "httpRequest": {"path": path}, "httpResponse": {"body": "OK"}}) }
}

#[derive(Default)]
struct Counting {
    changed: AtomicUsize,
    cleared: AtomicUsize,
    last: parking_lot::Mutex<Option<String>>,
}

impl InvalidationListener for Counting {
    fn on_changed(&self, key: &str) {
        self.changed.fetch_add(1, Ordering::SeqCst);
        *self.last.lock() = Some(key.to_string());
    }
    fn on_cleared(&self) {
        self.cleared.fetch_add(1, Ordering::SeqCst);
    }
}

// =========================================================================================================
// KeyValueStoreContract (22)
// =========================================================================================================

mod key_value_store_contract {
    use super::*;

    fn with_store(test: impl FnOnce(&dyn KeyValueStore<String>)) {
        let p = pair();
        test(p.a.scenario_states());
    }

    #[test]
    fn should_put_and_get() {
        with_store(|store| {
            let version = store.put("key1", "value1".into());
            assert!(version >= 1);
            let result = store.get("key1").expect("present");
            assert_eq!(result.value, "value1");
            assert!(result.version >= 1);
        });
    }

    #[test]
    fn should_return_empty_for_missing_key() {
        with_store(|store| assert!(store.get("missing").is_none()));
    }

    #[test]
    fn should_increment_version_on_update() {
        with_store(|store| {
            let v1 = store.put("key1", "v1".into());
            let v2 = store.put("key1", "v2".into());
            assert!(v2 > v1);
            let result = store.get("key1").unwrap();
            assert_eq!((result.value.as_str(), result.version), ("v2", v2));
        });
    }

    #[test]
    fn should_compare_and_set_successfully() {
        with_store(|store| {
            let v1 = store.put("key1", "v1".into());
            assert!(store.compare_and_set("key1", v1, "v2".into()));
            let result = store.get("key1").unwrap();
            assert_eq!(result.value, "v2");
            assert!(result.version > v1);
        });
    }

    #[test]
    fn should_fail_compare_and_set_with_wrong_version() {
        with_store(|store| {
            store.put("key1", "v1".into());
            assert!(!store.compare_and_set("key1", 999, "v2".into()));
            assert_eq!(store.get("key1").unwrap().value, "v1");
        });
    }

    #[test]
    fn should_fail_compare_and_set_for_missing_key() {
        with_store(|store| assert!(!store.compare_and_set("missing", 1, "v1".into())));
    }

    #[test]
    fn should_compare_and_remove_successfully() {
        with_store(|store| {
            let v1 = store.put("key1", "v1".into());
            assert!(store.compare_and_remove("key1", v1));
            assert!(store.get("key1").is_none());
        });
    }

    #[test]
    fn should_fail_compare_and_remove_with_wrong_version() {
        with_store(|store| {
            store.put("key1", "v1".into());
            assert!(!store.compare_and_remove("key1", 999));
            assert!(store.get("key1").is_some());
        });
    }

    #[test]
    fn should_remove_unconditionally() {
        with_store(|store| {
            store.put("key1", "v1".into());
            assert!(store.remove("key1"));
            assert!(store.get("key1").is_none());
        });
    }

    #[test]
    fn should_return_false_for_removing_missing_key() {
        with_store(|store| assert!(!store.remove("missing")));
    }

    #[test]
    fn should_return_correct_size() {
        with_store(|store| {
            assert_eq!(store.size(), 0);
            store.put("a", "1".into());
            store.put("b", "2".into());
            assert_eq!(store.size(), 2);
        });
    }

    #[test]
    fn should_clear() {
        with_store(|store| {
            store.put("a", "1".into());
            store.put("b", "2".into());
            store.clear();
            assert_eq!(store.size(), 0);
            assert!(store.get("a").is_none());
            assert!(store.get("b").is_none());
        });
    }

    #[test]
    fn should_stream_entries() {
        with_store(|store| {
            for (k, v) in [("a", "1"), ("b", "2"), ("c", "3")] {
                store.put(k, v.into());
            }
            let mut keys: Vec<String> = store.entries().into_iter().map(|(k, _)| k).collect();
            keys.sort();
            assert_eq!(keys, ["a", "b", "c"]);
        });
    }

    #[test]
    fn should_stream_entries_with_correct_values() {
        with_store(|store| {
            store.put("x", "hello".into());
            store.put("y", "world".into());
            let mut entries = store.entries();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].1.value, "hello");
            assert_eq!(entries[1].1.value, "world");
        });
    }

    #[test]
    fn should_have_monotonically_increasing_versions() {
        with_store(|store| {
            let v1 = store.put("k", "a".into());
            let v2 = store.put("k", "b".into());
            let v3 = store.put("k", "c".into());
            assert!(v2 > v1 && v3 > v2);
        });
    }

    #[test]
    fn should_assign_fresh_version_after_remove_and_reinsert() {
        with_store(|store| {
            store.put("k", "a".into());
            store.remove("k");
            assert!(store.put("k", "b".into()) >= 1);
        });
    }

    #[test]
    fn should_put_if_absent_when_key_does_not_exist() {
        with_store(|store| {
            assert!(store.put_if_absent("newKey", "value1".into()).is_none(), "putIfAbsent on a missing key returns empty");
            let result = store.get("newKey").unwrap();
            assert_eq!(result.value, "value1");
            assert!(result.version >= 1);
        });
    }

    #[test]
    fn should_not_overwrite_existing_on_put_if_absent() {
        with_store(|store| {
            store.put("existingKey", "original".into());
            let existing = store.put_if_absent("existingKey", "shouldNotReplace".into()).expect("returns the existing value");
            assert_eq!(existing.value, "original");
            assert_eq!(store.get("existingKey").unwrap().value, "original");
        });
    }

    #[test]
    fn should_put_if_absent_concurrently_with_exactly_one_creator() {
        with_store(|store| {
            let creators = AtomicUsize::new(0);
            let barrier = std::sync::Barrier::new(10);
            std::thread::scope(|scope| {
                for i in 0..10 {
                    let (creators, barrier) = (&creators, &barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        if store.put_if_absent("raceKey", format!("thread-{i}")).is_none() {
                            creators.fetch_add(1, Ordering::SeqCst);
                        }
                    });
                }
            });
            assert_eq!(creators.load(Ordering::SeqCst), 1, "exactly one thread should be the creator");
            assert!(store.get("raceKey").is_some());
        });
    }

    /// A stale `expectedVersion=0` against version 1 must not "succeed" because 1 == 0 + 1.
    #[test]
    fn should_not_falsely_succeed_compare_and_set_when_existing_version_equals_expected_plus_one() {
        with_store(|store| {
            assert_eq!(store.put("k", "a".into()), 1);
            assert!(!store.compare_and_set("k", 0, "x".into()), "compareAndSet with stale version 0 must fail");
            let result = store.get("k").unwrap();
            assert_eq!((result.value.as_str(), result.version), ("a", 1));
        });
    }

    /// Upstream asserts `lastKey == "a"`: the store's own `fireChanged` runs after the put returns.
    #[test]
    fn should_fire_invalidation_listener_on_put() {
        with_store(|store| {
            let listener = Arc::new(Counting::default());
            store.add_invalidation_listener(listener.clone());
            store.put("a", "1".into());
            assert_eq!(listener.last.lock().as_deref(), Some("a"));
        });
    }

    #[test]
    fn should_fire_invalidation_listener_on_clear() {
        with_store(|store| {
            let listener = Arc::new(Counting::default());
            store.add_invalidation_listener(listener.clone());
            store.put("a", "1".into());
            store.clear();
            assert_eq!(listener.cleared.load(Ordering::SeqCst), 1);
        });
    }
}

// =========================================================================================================
// InfinispanBlobStoreTest (14), on the clustered `blobs` cache
// =========================================================================================================

mod blob_store {
    use super::*;

    fn with_blobs(test: impl FnOnce(&dyn mock_server::state_backend::BlobStore, &ClusterStateBackend)) {
        let p = pair();
        test(p.a.blobs(), &p.b);
    }

    fn none() -> HashMap<String, String> {
        HashMap::new()
    }

    #[test]
    fn should_put_and_get_round_trip_byte_identical() {
        with_blobs(|store, _| {
            store.put("test/blob1", b"hello world".to_vec(), none());
            let blob = store.get("test/blob1").expect("present after put");
            assert_eq!(blob.key, "test/blob1");
            assert_eq!(blob.data, b"hello world");
        });
    }

    #[test]
    fn should_preserve_metadata() {
        with_blobs(|store, _| {
            let meta = HashMap::from([("type".to_string(), "expectations".to_string()), ("source".to_string(), "api".to_string())]);
            store.put("meta/blob1", b"payload".to_vec(), meta);
            let blob = store.get("meta/blob1").unwrap();
            assert_eq!(blob.metadata.get("type").map(String::as_str), Some("expectations"));
            assert_eq!(blob.metadata.get("source").map(String::as_str), Some("api"));
        });
    }

    #[test]
    fn should_overwrite_existing_blob() {
        with_blobs(|store, _| {
            store.put("overwrite", b"v1".to_vec(), none());
            store.put("overwrite", b"v2".to_vec(), none());
            assert_eq!(store.get("overwrite").unwrap().data, b"v2");
        });
    }

    #[test]
    fn should_return_empty_for_missing_key() {
        with_blobs(|store, _| assert!(store.get("nonexistent").is_none()));
    }

    #[test]
    fn should_list_by_prefix() {
        with_blobs(|store, _| {
            store.put("expectations/e1.json", b"{}".to_vec(), none());
            store.put("expectations/e2.json", b"{}".to_vec(), none());
            store.put("cassettes/c1.json", b"{}".to_vec(), none());
            let mut keys = store.list("expectations/");
            keys.sort();
            assert_eq!(keys, ["expectations/e1.json", "expectations/e2.json"]);
        });
    }

    #[test]
    fn should_return_empty_list_for_non_matching_prefix() {
        with_blobs(|store, _| {
            store.put("a/b.json", b"data".to_vec(), none());
            assert!(store.list("x/").is_empty());
        });
    }

    #[test]
    fn should_list_all_keys_with_empty_prefix() {
        with_blobs(|store, _| {
            store.put("a", b"1".to_vec(), none());
            store.put("b", b"2".to_vec(), none());
            let mut keys = store.list("");
            keys.sort();
            assert_eq!(keys, ["a", "b"]);
        });
    }

    #[test]
    fn should_delete_blob() {
        with_blobs(|store, _| {
            store.put("delete-me", b"data".to_vec(), none());
            assert!(store.delete("delete-me"));
            assert!(store.get("delete-me").is_none());
        });
    }

    #[test]
    fn should_return_false_when_deleting_missing_key() {
        with_blobs(|store, _| assert!(!store.delete("nonexistent")));
    }

    #[test]
    fn should_not_affect_other_blobs_on_delete() {
        with_blobs(|store, _| {
            store.put("keep", b"keep-data".to_vec(), none());
            store.put("remove", b"remove-data".to_vec(), none());
            assert!(store.delete("remove"));
            assert_eq!(store.get("keep").unwrap().data, b"keep-data");
        });
    }

    #[test]
    fn should_handle_empty_data() {
        with_blobs(|store, _| {
            store.put("empty", Vec::new(), none());
            assert_eq!(store.get("empty").unwrap().data.len(), 0);
        });
    }

    #[test]
    fn should_handle_large_data() {
        with_blobs(|store, _| {
            let large = vec![b'x'; 1024 * 1024];
            store.put("large.bin", large.clone(), none());
            assert_eq!(store.get("large.bin").unwrap().data, large);
        });
    }

    #[test]
    fn should_handle_null_metadata_gracefully() {
        with_blobs(|store, _| {
            store.put("null-meta", b"data".to_vec(), Default::default());
            assert_eq!(store.get("null-meta").unwrap().metadata.len(), 0);
        });
    }

    #[test]
    fn should_preserve_binary_data_exactly() {
        with_blobs(|store, _| {
            let binary: Vec<u8> = (0..=255u8).collect();
            store.put("binary", binary.clone(), none());
            assert_eq!(store.get("binary").unwrap().data, binary, "binary data survives the round-trip");
        });
    }

    /// The clustered part: a blob written on one node is read on the other, and `blobs` never raises a listener.
    #[test]
    fn blobs_replicate_and_never_raise_invalidation() {
        let p = pair();
        let (on_a, on_b) = (Arc::new(Counting::default()), Arc::new(Counting::default()));
        p.a.add_invalidation_listener(on_a.clone());
        p.b.add_invalidation_listener(on_b.clone());
        p.a.blobs().put("expectations/x.json", vec![1, 2, 3], none());
        assert_eq!(p.b.blobs().get("expectations/x.json").map(|b: Blob| b.data), Some(vec![1, 2, 3]));
        assert!(p.b.blobs().delete("expectations/x.json"));
        assert!(p.a.blobs().get("expectations/x.json").is_none());
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(on_a.changed.load(Ordering::SeqCst) + on_b.changed.load(Ordering::SeqCst), 0, "blobs has no listener");
    }
}

// =========================================================================================================
// InfinispanStateBackendTest (10), CLUSTERED mode
// =========================================================================================================

mod state_backend {
    use super::*;

    #[test]
    fn should_return_expectations_store() {
        let p = pair();
        assert_eq!(p.a.expectations().size(), 0);
        p.a.expectations().put("e", entry("e", "/x"));
        assert_eq!(p.a.expectations().size(), 1);
    }

    #[test]
    fn should_return_scenario_states_store() {
        let p = pair();
        p.a.scenario_states().put("scenario1", "Started".into());
        assert_eq!(p.a.scenario_states().get("scenario1").unwrap().value, "Started");
    }

    #[test]
    fn should_return_crud_entities_store() {
        let p = pair();
        let store1 = p.a.crud_entities("ns1");
        let store2 = p.a.crud_entities("ns2");
        store1.put("item1", json!({"id": "1"}));
        assert!(store2.get("item1").is_none());
        assert!(store1.get("item1").is_some());
    }

    #[test]
    fn should_return_same_store_for_same_namespace() {
        let p = pair();
        assert!(Arc::ptr_eq(&p.a.crud_entities("ns1"), &p.a.crud_entities("ns1")));
    }

    #[test]
    fn should_store_and_retrieve_blobs() {
        let p = pair();
        p.a.blobs().put("test/blob1", vec![1, 2, 3], Default::default());
        assert_eq!(p.a.blobs().get("test/blob1").unwrap().data, vec![1, 2, 3]);
    }

    #[test]
    fn should_return_node_id() {
        let p = pair();
        assert!(!p.a.node_id().is_empty());
    }

    /// Replaces `shouldReportSingleNodeClusterInfoInLocalMode`: a CLUSTERED node reports the real membership.
    #[test]
    fn should_report_both_members_in_clustered_mode() {
        let p = pair();
        let info = p.a.cluster_info();
        assert!(info.clustered);
        assert_eq!(info.members.len(), 2);
        assert_eq!(info.cluster_name.as_deref(), Some(p.cluster.as_str()));
        assert!(p.a.is_clustered());
    }

    #[test]
    fn should_close_without_error() {
        let p = pair();
        p.a.close();
        p.a.close();
    }

    /// `shouldFireInvalidationListenerOnExpectationChange`: a LOCAL backend notifies once; a replicated cache's
    /// clustered listener also sees the local write (§4.5), so the same call notifies twice here.
    #[test]
    fn should_fire_invalidation_listener_on_change() {
        let p = pair();
        let listener = Arc::new(Counting::default());
        p.a.add_invalidation_listener(listener.clone());
        p.a.scenario_states().put("s1", "state1".into());
        eventually("the store's own fireChanged and the clustered listener both fire", Duration::from_secs(5), || listener.changed.load(Ordering::SeqCst) == 2);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(listener.changed.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn local_mode_is_still_the_in_memory_wrapper() {
        let backend = mock_server::state_backend::infinispan::InfinispanStateBackend::new(100);
        assert!(!backend.is_clustered());
        assert_eq!(backend.cluster_info().members.len(), 1);
    }
}

// =========================================================================================================
// ClusteredTwoNodeTest (26): the cases that need only the backend (12)
// =========================================================================================================

mod two_node {
    use super::*;

    #[test]
    fn expectation_written_on_node_a_should_be_visible_on_node_b() {
        let p = pair();
        let e = entry("test-id", "/test-path");
        p.a.expectations().put(&e.id, e.clone());
        let result = p.b.expectations().get(&e.id).expect("expectation should be visible on node B");
        assert_eq!(result.value.id, e.id);
        assert_eq!(result.value.expectation_json["httpRequest"], e.expectation_json["httpRequest"]);
        assert_eq!(result.value, e, "every field survives the Java serialization round trip");
    }

    #[test]
    fn expectation_removed_on_node_b_should_disappear_from_node_a() {
        let p = pair();
        p.a.expectations().put("to-remove", entry("to-remove", "/to-remove"));
        assert!(p.b.expectations().get("to-remove").is_some());
        p.b.expectations().remove("to-remove");
        assert!(p.a.expectations().get("to-remove").is_none(), "removed expectation should disappear from node A");
    }

    #[test]
    fn expectation_updated_on_node_a_should_reflect_on_node_b() {
        let p = pair();
        let v1 = p.a.expectations().put("u", entry("u", "/update-test"));
        let mut updated = entry("u", "/update-test");
        updated.expectation_json["httpResponse"]["body"] = json!("v2");
        let v2 = p.a.expectations().put("u", updated);
        assert!(v2 > v1);
        let result = p.b.expectations().get("u").unwrap();
        assert_eq!(result.version, v2);
        assert_eq!(result.value.expectation_json["httpResponse"]["body"], "v2");
    }

    #[test]
    fn scenario_state_written_on_node_a_should_be_visible_on_node_b() {
        let p = pair();
        p.a.scenario_states().put("scenario1", "Started".into());
        assert_eq!(p.b.scenario_states().get("scenario1").expect("visible on node B").value, "Started");
    }

    #[test]
    fn scenario_state_cas_on_node_a_should_be_visible_on_node_b() {
        let p = pair();
        let v1 = p.a.scenario_states().put("cas-scenario", "Started".into());
        assert!(p.a.scenario_states().compare_and_set("cas-scenario", v1, "Step1".into()));
        assert_eq!(p.b.scenario_states().get("cas-scenario").unwrap().value, "Step1");
    }

    #[test]
    fn cas_from_the_other_node_uses_the_replicated_version() {
        let p = pair();
        let v1 = p.a.scenario_states().put("k", "Started".into());
        assert!(p.b.scenario_states().compare_and_set("k", v1, "FromB".into()));
        assert!(!p.a.scenario_states().compare_and_set("k", v1, "Stale".into()), "the version moved on node B's swap");
        assert_eq!(p.a.scenario_states().get("k").unwrap().value, "FromB");
        assert!(p.a.scenario_states().compare_and_remove("k", v1 + 1));
        assert!(p.b.scenario_states().get("k").is_none());
    }

    #[test]
    fn crud_entity_written_on_node_a_should_be_visible_on_node_b() {
        let p = pair();
        p.a.crud_entities("testNs").put("entity1", json!({"name": "test-entity", "value": 42}));
        // node B defines the cache when it first uses it, and receives what node A wrote through state transfer
        let result = p.b.crud_entities("testNs").get("entity1").expect("CRUD entity should be visible on node B");
        assert_eq!(result.value["name"], "test-entity");
        assert_eq!(result.value["value"], 42);
    }

    #[test]
    fn invalidation_listener_on_node_b_should_fire_when_node_a_puts_expectation() {
        let p = pair();
        let listener = Arc::new(Counting::default());
        p.b.add_invalidation_listener(listener.clone());
        p.a.expectations().put("inv", entry("inv", "/invalidation-test"));
        eventually("invalidation listener on node B should have fired", Duration::from_secs(5), || listener.changed.load(Ordering::SeqCst) > 0);
        assert_eq!(listener.last.lock().as_deref(), Some("inv"));
    }

    #[test]
    fn both_nodes_should_be_clustered() {
        let p = pair();
        assert!(p.a.is_clustered() && p.b.is_clustered());
    }

    #[test]
    fn nodes_should_have_different_ids() {
        let p = pair();
        assert_ne!(p.a.node_id(), p.b.node_id());
    }

    #[test]
    fn cluster_info_should_report_both_members_with_single_coordinator() {
        let p = pair();
        let (a, b) = (p.a.cluster_info(), p.b.cluster_info());
        assert!(a.clustered && b.clustered);
        assert_eq!((a.members.len(), b.members.len()), (2, 2));
        assert_eq!(a.members.iter().filter(|m| m.coordinator).count(), 1);
        assert_eq!(b.members.iter().filter(|m| m.coordinator).count(), 1);
        assert_eq!(a.coordinator, b.coordinator, "both nodes agree on the coordinator");
        assert_eq!(a.members.iter().filter(|m| m.local).count(), 1);
        assert_eq!(b.members.iter().filter(|m| m.local).count(), 1);
        let local_a = a.members.iter().find(|m| m.local).unwrap().id.clone();
        let local_b = b.members.iter().find(|m| m.local).unwrap().id.clone();
        assert_ne!(local_a, local_b, "each node's local member is its own address");
        assert_eq!(a.node_id, local_a);
        assert_eq!(b.node_id, local_b);
        assert_eq!(a.cluster_name.as_deref(), Some(p.cluster.as_str()));
    }

    #[test]
    fn clear_on_node_a_should_clear_node_b() {
        let p = pair();
        p.a.scenario_states().put("s1", "v1".into());
        p.a.scenario_states().put("s2", "v2".into());
        assert!(p.b.scenario_states().get("s1").is_some() && p.b.scenario_states().get("s2").is_some());
        p.a.scenario_states().clear();
        assert!(p.b.scenario_states().get("s1").is_none() && p.b.scenario_states().get("s2").is_none());
        assert_eq!(p.b.scenario_states().size(), 0);
    }

    #[test]
    fn entries_stream_on_node_b_should_include_node_a_writes() {
        let p = pair();
        for (k, v) in [("a", "1"), ("b", "2"), ("c", "3")] {
            p.a.scenario_states().put(k, v.into());
        }
        assert_eq!(p.b.scenario_states().entries().len(), 3);
    }
}

// =========================================================================================================
// acceptance quirks
// =========================================================================================================

mod acceptance {
    use super::*;

    /// §2.2: an expectation whose JSON is over 65,535 modified-UTF-8 bytes fails the clustered `put`
    /// (`UTFDataFormatException` out of `ExpectationEntry.writeObject`), and nothing is stored anywhere.
    #[test]
    fn an_expectation_json_over_65535_bytes_fails_the_clustered_put() {
        let p = pair();
        let big = ExpectationEntry { id: "big".into(), priority: 0, created: 1, remaining_times: -1, expectation_json: json!({"id": "big", "httpResponse": {"body": "x".repeat(70_000)}}) };
        let err = p.a.expectations().try_put("big", big.clone()).unwrap_err();
        assert!(err.to_string().contains("UTFDataFormatException"), "{err}");
        assert!(p.a.expectations().get("big").is_none());
        assert!(p.b.expectations().get("big").is_none());
        assert!(p.a.expectations().try_put_if_absent("big", big).is_err());
        // the same entry just under the limit is accepted
        let ok = ExpectationEntry { id: "ok".into(), priority: 0, created: 1, remaining_times: -1, expectation_json: json!({"id": "ok", "httpResponse": {"body": "x".repeat(60_000)}}) };
        assert!(p.a.expectations().try_put("ok", ok).is_ok());
        assert!(p.b.expectations().get("ok").is_some());
    }

    /// Only `expectations`, `scenarioStates` and `crud-*` get the cluster listener; `blobs` never does.
    #[test]
    fn only_expectations_scenario_states_and_crud_caches_get_the_cluster_listener() {
        let p = pair();
        assert!(p.a.caches_with_cluster_listener().is_empty(), "none before a listener is added");
        p.a.add_invalidation_listener(Arc::new(Counting::default()));
        p.a.add_invalidation_listener(Arc::new(Counting::default()));
        assert_eq!(p.a.caches_with_cluster_listener(), ["expectations", "scenarioStates"], "once per cache, however many listeners");
        p.a.crud_entities("chaos-service");
        assert_eq!(p.a.caches_with_cluster_listener(), ["crud-chaos-service", "expectations", "scenarioStates"]);
        assert!(!p.a.caches_with_cluster_listener().iter().any(|c| c == "blobs"));
        assert_eq!(p.a.blobs_cache().cache_listeners().len(), 0);
        assert_eq!(p.a.expectations_cache().cache_listeners().len(), 1);
    }

    /// A crud cache's remote writes notify too (G11).
    #[test]
    fn crud_cache_remote_writes_notify() {
        let p = pair();
        p.a.crud_entities("chaos-profiles");
        let on_a = Arc::new(Counting::default());
        p.a.add_invalidation_listener(on_a.clone());
        let b_store = p.b.crud_entities("chaos-profiles");
        b_store.put("p1", json!({"a": 1}));
        eventually("node A hears node B's crud write", Duration::from_secs(5), || on_a.changed.load(Ordering::SeqCst) > 0);
        assert_eq!(on_a.last.lock().as_deref(), Some("p1"));
    }

    /// ISPN000094: `Received new cluster view for channel <cluster>: [<coord>|<id>] (<n>) [<members>]` on every
    /// view change, on the node that was there and on the one that joined.
    #[test]
    fn a_view_change_line_is_logged_on_every_view_change() {
        let cluster = unique_cluster();
        let (log_a, log_b) = (Arc::new(parking_lot::Mutex::new(Vec::<String>::new())), Arc::new(parking_lot::Mutex::new(Vec::<String>::new())));
        let opts = |log: &Arc<parking_lot::Mutex<Vec<String>>>| {
            let log = log.clone();
            let mut o = options(&cluster);
            o.log = Arc::new(move |line| log.lock().push(line));
            o
        };
        let a = ClusterStateBackend::start(opts(&log_a)).unwrap();
        assert!(log_a.lock().iter().any(|l| l.contains("(1) [")), "the first view has one member: {:?}", log_a.lock());
        let b = ClusterStateBackend::start(opts(&log_b)).unwrap();
        eventually("both log the two-member view", Duration::from_secs(10), || {
            log_a.lock().iter().any(|l| l.contains("(2) [")) && log_b.lock().iter().any(|l| l.contains("(2) ["))
        });
        let line = log_a.lock().iter().find(|l| l.contains("(2) [")).cloned().unwrap();
        let prefix = format!("ISPN000094: Received new cluster view for channel {cluster}: [");
        assert!(line.starts_with(&prefix), "{line}");
        let members = a.members();
        assert!(members.iter().all(|m| line.contains(m.as_str())), "{line} lists {members:?}");
        let coordinator = a.cluster_info().coordinator;
        assert!(line.starts_with(&format!("{prefix}{coordinator}|")), "the creator is the coordinator: {line}");
        drop(b);
        eventually("A logs the view without B", Duration::from_secs(20), || log_a.lock().iter().filter(|l| l.contains("(1) [")).count() >= 2);
        drop(a);
        // the shape alone, from the formatter
        let view = jgroups::wire::view::View::create(jgroups::wire::address::Address::uuid(0, 1), 7, vec![jgroups::wire::address::Address::uuid(0, 1), jgroups::wire::address::Address::uuid(0, 2)]);
        assert_eq!(
            view_change_line("c", &view, None),
            "ISPN000094: Received new cluster view for channel c: [00000000-0000-0000-0000-000000000001|7] (2) [00000000-0000-0000-0000-000000000001, 00000000-0000-0000-0000-000000000002]"
        );
        // a MergeView is ISPN000093 (Log.java:395-397, JGroupsTransport.java:785-788) with MergeView.toString (MergeView.java:96-103)
        let other = jgroups::wire::view::View::create(jgroups::wire::address::Address::uuid(0, 3), 4, vec![jgroups::wire::address::Address::uuid(0, 3)]);
        let (u1, u2, u3) = ("00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000003");
        assert_eq!(
            view_change_line("c", &view, Some(&[view.clone(), other])),
            format!("ISPN000093: Received new, MERGED cluster view for channel c: MergeView::[{u1}|7] (2) [{u1}, {u2}], 2 subgroups: [{u1}|7] (2) [{u1}, {u2}], [{u3}|4] (1) [{u3}]")
        );
        assert_eq!(
            view_change_line("c", &view, Some(&[])),
            format!("ISPN000093: Received new, MERGED cluster view for channel c: MergeView::[{u1}|7] (2) [{u1}, {u2}]")
        );
    }

    #[test]
    fn the_listener_policy_does_not_notify_for_a_cache_nobody_listens_to() {
        let p = pair();
        // no invalidation listener added: nothing to notify, and writes still work
        p.a.expectations().put("e", entry("e", "/x"));
        assert!(p.b.expectations().get("e").is_some());
    }
}

// =========================================================================================================
// InfinispanKeyValueStoreConcurrencyTest (1)
// =========================================================================================================

mod concurrency {
    use super::*;

    #[test]
    fn should_handle_concurrent_puts_to_same_key_without_error_or_hang() {
        const THREADS: usize = 8;
        const PUTS: usize = 50;
        let p = pair();
        let store = p.a.scenario_states();
        let versions = parking_lot::Mutex::new(Vec::new());
        let values = parking_lot::Mutex::new(Vec::new());
        let barrier = std::sync::Barrier::new(THREADS);
        let started = Instant::now();
        std::thread::scope(|scope| {
            for t in 0..THREADS {
                let (versions, values, barrier) = (&versions, &values, &barrier);
                scope.spawn(move || {
                    barrier.wait();
                    for i in 0..PUTS {
                        let value = format!("thread-{t}-put-{i}");
                        let version = store.put("contended-key", value.clone());
                        versions.lock().push(version);
                        values.lock().push(value);
                    }
                });
            }
        });
        assert!(started.elapsed() < Duration::from_secs(30), "possible hang");
        let total = (THREADS * PUTS) as u64;
        let last = store.get("contended-key").unwrap();
        assert_eq!(last.version, total, "final version should equal total puts");
        let mut sorted = versions.lock().clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (1..=total).collect::<Vec<_>>(), "unique and contiguous from 1");
        assert!(values.lock().contains(&last.value));
        assert_eq!(p.b.scenario_states().get("contended-key").unwrap().version, total, "the other node agrees");
    }
}

// =========================================================================================================
// DeserializationAllowListTest (18)
// =========================================================================================================

mod allow_list {
    use super::*;
    use infinispan::commands::object::CacheObject;
    use infinispan::marshall::java_serial::{ClassDesc, JavaValue, ObjectLevel, SC_SERIALIZABLE, encode_one};
    use mock_server::state_backend::cluster::codec;
    use std::rc::Rc;

    fn class(name: &str) -> bool {
        clustered_allow_list().is_safe_class(name)
    }

    // ExpectationEntry writeObject/readObject round trips (3)

    #[test]
    fn should_round_trip_expectation_entry_through_java_serialization() {
        let original = entry("test-id-1", "/test");
        let bytes = codec::wrap(&original, 1).unwrap();
        let (back, _): (ExpectationEntry, u64) = codec::unwrap(&bytes, Some(clustered_allow_list())).unwrap();
        assert_eq!((back.id.as_str(), back.priority, back.created, back.remaining_times), ("test-id-1", 0, 1000, -1));
        assert_eq!(back.expectation_json["httpRequest"]["path"], "/test", "the expectation is rebuilt from its JSON");
    }

    #[test]
    fn should_round_trip_expectation_entry_with_limited_times() {
        let original = ExpectationEntry { id: "limited-id".into(), priority: 10, created: 7, remaining_times: 5, expectation_json: json!({"id": "limited-id", "httpRequest": {"path": "/limited"}, "times": {"remainingTimes": 5}}) };
        let (back, _): (ExpectationEntry, u64) = codec::unwrap(&codec::wrap(&original, 1).unwrap(), Some(clustered_allow_list())).unwrap();
        assert_eq!((back.id.as_str(), back.priority, back.remaining_times), ("limited-id", 10, 5));
    }

    #[test]
    fn should_round_trip_expectation_entry_with_unlimited_times() {
        let (back, _): (ExpectationEntry, u64) = codec::unwrap(&codec::wrap(&entry("unlimited-id", "/unlimited"), 1).unwrap(), Some(clustered_allow_list())).unwrap();
        assert_eq!(back.remaining_times, -1);
    }

    // allowed (8)

    #[test]
    fn should_allow_versioned_wrapper() {
        assert!(class("org.mockserver.state.infinispan.VersionedWrapper"));
    }

    #[test]
    fn should_allow_expectation_entry() {
        assert!(class("org.mockserver.state.ExpectationEntry"));
    }

    #[test]
    fn should_allow_expectation() {
        assert!(class("org.mockserver.mock.Expectation"));
    }

    #[test]
    fn should_allow_http_request() {
        assert!(class("org.mockserver.model.HttpRequest"));
    }

    #[test]
    fn should_allow_jackson_object_node() {
        assert!(class("com.fasterxml.jackson.databind.node.ObjectNode"));
    }

    #[test]
    fn should_allow_java_lang_string() {
        assert!(class("java.lang.String"));
    }

    #[test]
    fn should_allow_java_util_hash_map() {
        assert!(class("java.util.HashMap"));
    }

    #[test]
    fn should_allow_byte_array() {
        assert!(class("[B"));
    }

    // rejected (5)

    #[test]
    fn should_reject_apache_commons_collections() {
        assert!(!class("org.apache.commons.collections4.functors.InvokerTransformer"));
    }

    #[test]
    fn should_reject_spring_framework_types() {
        assert!(!class("org.springframework.beans.factory.config.MethodInvokingBean"));
    }

    #[test]
    fn should_reject_random_unknown_gadget_class() {
        assert!(!class("com.evil.GadgetChainEntry"));
    }

    #[test]
    fn should_reject_javax_naming_context() {
        assert!(!class("javax.naming.InitialContext"));
    }

    #[test]
    fn should_reject_java_rmi_types() {
        assert!(!class("java.rmi.server.RemoteObject"));
    }

    // the marshaller (2)

    #[test]
    fn should_marshal_and_unmarshal_allowed_type() {
        let bytes = codec::wrap(&"hello".to_string(), 1).unwrap();
        let (value, version): (String, u64) = codec::unwrap(&bytes, Some(clustered_allow_list())).unwrap();
        assert_eq!((value.as_str(), version), ("hello", 1));
    }

    /// `java.net.URL` is `Serializable` but `java.net` is not on the list: the tight list refuses it on read.
    #[test]
    fn should_reject_disallowed_type_during_deserialization() {
        let url = JavaValue::Object {
            class: Rc::new(ClassDesc { name: "java.net.URL".into(), serial_version_uid: -7627629688361524110, flags: SC_SERIALIZABLE, fields: vec![], super_desc: None }),
            levels: vec![ObjectLevel::default()],
        };
        let hostile = CacheObject::User(infinispan::commands::object::UserValue::new(encode_one(&url)));
        let err = codec::unwrap::<String>(&hostile, Some(clustered_allow_list())).unwrap_err();
        assert!(err.to_string().contains("allow"), "{err}");
        // and the permissive (LOCAL mode) reading has no such gate
        assert!(infinispan::marshall::java_serial::decode_stream(match &hostile { CacheObject::User(u) => u.bytes(), _ => unreachable!() }).is_ok());
    }

    #[test]
    fn the_constant_is_the_ten_upstream_patterns_verbatim() {
        assert_eq!(CLUSTERED_ALLOW_LIST_PATTERNS.len(), 10);
        assert_eq!(CLUSTERED_ALLOW_LIST_PATTERNS[0], r"org\.mockserver\.state\.infinispan\..*");
        assert_eq!(CLUSTERED_ALLOW_LIST_PATTERNS[9], r"\[B");
        let upstream = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/upstream/mockserver/mockserver/mockserver-state-infinispan/src/main/java/org/mockserver/state/infinispan/InfinispanStateBackend.java")).unwrap();
        for pattern in CLUSTERED_ALLOW_LIST_PATTERNS {
            let as_java = format!("\"{}\"", pattern.replace('\\', "\\\\"));
            assert!(upstream.contains(&as_java), "{as_java} is in InfinispanStateBackend.java");
        }
    }
}

// =========================================================================================================
// JGroupsKubernetesStackTest (6)
// =========================================================================================================

mod kubernetes_stack {
    use super::*;

    const UPSTREAM_RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/upstream/mockserver/mockserver/mockserver-state-infinispan/src/main/resources");

    #[test]
    fn should_exist_on_classpath() {
        let shipped = std::fs::read_to_string(format!("{UPSTREAM_RESOURCES}/jgroups-kubernetes.xml")).expect("upstream ships jgroups-kubernetes.xml");
        assert_eq!(JGROUPS_KUBERNETES_XML, shipped, "embedded verbatim");
    }

    #[test]
    fn should_parse_as_valid_jgroups_configuration() {
        let protocols = jgroups::conf::parse(JGROUPS_KUBERNETES_XML).unwrap();
        assert!(!protocols.is_empty());
    }

    #[test]
    fn should_use_tcp_transport() {
        let protocols = jgroups::conf::parse(JGROUPS_KUBERNETES_XML).unwrap();
        assert_eq!(protocols[0].short_name(), "TCP");
    }

    #[test]
    fn should_use_dns_ping_discovery() {
        let protocols = jgroups::conf::parse(JGROUPS_KUBERNETES_XML).unwrap();
        assert!(protocols.iter().any(|p| p.fully_qualified_name() == "org.jgroups.protocols.dns.DNS_PING"));
    }

    #[test]
    fn should_have_dns_query_property() {
        let protocols = jgroups::conf::parse(JGROUPS_KUBERNETES_XML).unwrap();
        let dns_ping = protocols.iter().find(|p| p.short_name() == "DNS_PING").expect("dns.DNS_PING");
        assert!(dns_ping.get("dns_query").unwrap().contains("JGROUPS_DNS_QUERY"));
    }

    #[test]
    fn loopback_stack_should_also_exist() {
        let shipped = std::fs::read_to_string(format!("{UPSTREAM_RESOURCES}/jgroups-loopback.xml")).expect("upstream ships jgroups-loopback.xml");
        assert_eq!(JGROUPS_LOOPBACK_XML, shipped, "embedded verbatim");
    }
}

// =========================================================================================================
// ClusteredTwoNodeTest through the data plane: two servers of one cluster in this process (the core wiring)
// =========================================================================================================

mod core_wiring {
    use super::*;
    use crate::common;

    /// Two servers, `stateBackend=infinispan`, `clusterEnabled=true`, one cluster name, plus an observer node that
    /// holds a replica of the backend's caches and lets a test read the shared counter.
    struct Fleet {
        a: common::Running,
        b: common::Running,
        observer: ClusterStateBackend,
        cluster: String,
        /// The backends of `a` and `b` when the fleet was started with [`Fleet::start_sharing_backends`].
        backends: Option<[Arc<ClusterStateBackend>; 2]>,
    }

    impl Fleet {
        async fn start() -> Fleet {
            Self::start_with(&[]).await
        }

        /// `a_properties` apply to node A only.
        async fn start_with(a_properties: &[(&str, &str)]) -> Fleet {
            let cluster = unique_cluster();
            let mut props: Vec<(&str, &str)> = vec![("stateBackend", "infinispan"), ("clusterEnabled", "true"), ("clusterName", cluster.as_str())];
            props.extend_from_slice(a_properties);
            let a = common::start(&props).await;
            let b = common::start(&[("stateBackend", "infinispan"), ("clusterEnabled", "true"), ("clusterName", cluster.as_str())]).await;
            let observer = start(&cluster);
            eventually("three members", Duration::from_secs(30), || observer.members().len() == 3);
            Fleet { a, b, observer, cluster, backends: None }
        }

        /// As [`Fleet::start`], but each server runs on a backend this test holds too (`Server::start_with_state_backend`),
        /// so it can reach the node's own caches (`cache.evict`, upstream's `nodeA.getCacheManager().getCache(..)`).
        async fn start_sharing_backends() -> Fleet {
            let cluster = unique_cluster();
            let mut servers = Vec::new();
            let mut backends = Vec::new();
            for _ in 0..2 {
                let backend = Arc::new(start(&cluster));
                let config = mock_server::Config::for_tests().with_property("stateBackend", "infinispan").with_property("clusterEnabled", "true").with_property("clusterName", &cluster);
                crate::scratch_cwd::enter();
                let server = mock_server::Server::start_with_state_backend(config, backend.clone()).await.expect("server starts");
                let port = server.ports()[0];
                servers.push(common::Running { server, port });
                backends.push(backend);
            }
            let observer = start(&cluster);
            eventually("three members", Duration::from_secs(30), || observer.members().len() == 3);
            let b = servers.pop().unwrap();
            let a = servers.pop().unwrap();
            let [ba, bb]: [Arc<ClusterStateBackend>; 2] = backends.try_into().ok().unwrap();
            Fleet { a, b, observer, cluster, backends: Some([ba, bb]) }
        }

        /// `cache.evict(id)` on a node's `sharedTimesCounters` cache: node-local, not replicated.
        fn evict_counter(backend: &ClusterStateBackend, id: &str) {
            backend.shared_times_cache().evict(&infinispan::commands::object::CacheObject::string(id));
        }

        async fn stop(self) {
            drop(self.observer);
            self.a.server.shutdown().await;
            self.b.server.shutdown().await;
            drop(self.backends);
        }
    }

    async fn status(port: u16, path: &str) -> u16 {
        common::send(port, "GET", path, "").await.status
    }

    async fn eventually_status(port: u16, path: &str, expected: u16) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let got = status(port, path).await;
            if got == expected {
                return;
            }
            assert!(Instant::now() < deadline, "{path} on port {port} answered {got}, expected {expected}");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn expectation(path: &str, body: &str) -> serde_json::Value {
        json!({"httpRequest": {"path": path}, "httpResponse": {"statusCode": 200, "body": body}})
    }

    fn limited(path: &str, times: u32) -> serde_json::Value {
        json!({"httpRequest": {"path": path}, "httpResponse": {"statusCode": 200, "body": "limited"}, "times": {"remainingTimes": times, "unlimited": false}})
    }

    /// `expectationCreatedOnNodeAShouldBeMatchableOnNodeBViaRequestMatchers`, through HTTP.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn expectation_created_on_node_a_should_be_matchable_on_node_b() {
        let fleet = Fleet::start().await;
        common::expect(fleet.a.port, &expectation("/cross-node-match", "cross-node-ok")).await;
        eventually_status(fleet.b.port, "/cross-node-match", 200).await;
        assert_eq!(common::send(fleet.b.port, "GET", "/cross-node-match", "").await.body, "cross-node-ok");
        fleet.stop().await;
    }

    /// Recorded from a JVM `mockserver:clustered-8.0.0` pair: an expectation whose JSON is over 65,535
    /// modified-UTF-8 bytes makes the clustered `put` throw (`MarshallingException`, no message); this node's view
    /// keeps it (the local mutation precedes the put), the peer never receives it. Since the re-pin that
    /// exception is no client error, so `PUT /mockserver/expectation` answers 500 with the correlation-id message
    /// (`ControlPlaneFailureResponse`) where 8.0.0 answered 400 with an empty body.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_put_over_65535_bytes_answers_400_with_an_empty_body_and_stays_on_the_local_node() {
        let fleet = Fleet::start().await;
        let big = json!({"httpRequest": {"path": "/big"}, "httpResponse": {"body": "x".repeat(70_000)}});
        let r = common::send(fleet.a.port, "PUT", "/mockserver/expectation", &big.to_string()).await;
        assert_eq!(r.status, 500, "{}", r.head);
        assert!(r.body.starts_with(UNEXPECTED_FAILURE), "{}", r.body);
        assert!(r.head.lines().any(|l| l.eq_ignore_ascii_case("content-type: text/plain; charset=utf-8")), "{}", r.head);
        assert_eq!(status(fleet.a.port, "/big").await, 200, "the local view keeps it");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(status(fleet.b.port, "/big").await, 404, "the peer never receives it");
        assert_eq!(fleet.observer.expectation_store().size(), 0, "nothing is stored in the backend");
        // just under the limit is accepted and replicates
        let ok = json!({"httpRequest": {"path": "/ok"}, "httpResponse": {"body": "x".repeat(60_000)}});
        assert_eq!(common::send(fleet.a.port, "PUT", "/mockserver/expectation", &ok.to_string()).await.status, 201);
        eventually_status(fleet.b.port, "/ok", 200).await;
        fleet.stop().await;
    }

    /// Checked against a JVM `mockserver:clustered-8.0.0` pair (TRACE log, `persistExpectations=true`):
    /// `HttpState.add` takes the expectations of one `PUT` one at a time, so when the second one's clustered put
    /// throws, the first was already announced to the persistence (the failure answer follows, 500 since the 9.2.0 re-pin), the third is never added.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_multi_expectation_put_that_fails_partway_keeps_the_earlier_ones_and_persists_them() {
        let file = std::env::temp_dir().join(format!("partialPut-{}-{}.json", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&file, "").unwrap();
        let path = file.to_string_lossy().into_owned();
        let fleet = Fleet::start_with(&[("persistExpectations", "true"), ("persistedExpectationsPath", path.as_str())]).await;
        let batch = json!([
            expectation("/ok1", "1"),
            {"httpRequest": {"path": "/big"}, "httpResponse": {"body": "x".repeat(70_000)}},
            expectation("/ok2", "2"),
        ]);
        let r = common::send(fleet.a.port, "PUT", "/mockserver/expectation", &batch.to_string()).await;
        assert_eq!(r.status, 500, "{}", r.head);
        assert!(r.body.starts_with(UNEXPECTED_FAILURE), "{}", r.body);
        assert_eq!(status(fleet.a.port, "/ok1").await, 200);
        assert_eq!(status(fleet.a.port, "/big").await, 200, "the failing one stays in the local view");
        assert_eq!(status(fleet.a.port, "/ok2").await, 404, "the one after the failure is never added");
        eventually_status(fleet.b.port, "/ok1", 200).await;
        assert_eq!(status(fleet.b.port, "/big").await, 404);
        let key = file.file_name().unwrap().to_string_lossy().into_owned();
        eventually("the earlier expectation reaches the persisted blob", Duration::from_secs(30), || {
            fleet.observer.blobs().get(&key).is_some_and(|b| String::from_utf8_lossy(&b.data).contains("/ok1"))
        });
        let blob = fleet.observer.blobs().get(&key).unwrap();
        assert!(!String::from_utf8_lossy(&blob.data).contains("/ok2"));
        fleet.stop().await;
        let _ = std::fs::remove_file(&file);
    }

    /// Recorded from `mockserver:clustered-8.0.0` (scenario `persistence_infinispan_local`):
    /// `stateBackend=infinispan` without clustering hands `ExpectationFileSystemPersistence` the in-memory
    /// `InfinispanBlobStore`, so the persisted file is created at start and never written.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn local_infinispan_persists_to_its_blob_cache_and_leaves_the_file_empty() {
        let file = std::env::temp_dir().join(format!("localInfinispan-{}-{}.json", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let _ = std::fs::remove_file(&file);
        let path = file.to_string_lossy().into_owned();
        let node = common::start(&[("stateBackend", "infinispan"), ("persistExpectations", "true"), ("persistedExpectationsPath", path.as_str())]).await;
        common::expect(node.port, &expectation("/local", "x")).await;
        assert_eq!(std::fs::metadata(&file).unwrap().len(), 0);
        node.server.shutdown().await;
        let _ = std::fs::remove_file(&file);
    }

    /// `ExpectationFileSystemPersistence.writeOrderLock`: of concurrent changes the later snapshot is the
    /// later write, so the file always ends as the final state.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_changes_leave_the_persisted_file_holding_the_final_state() {
        let file = std::env::temp_dir().join(format!("concurrentPersist-{}-{}.json", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let _ = std::fs::remove_file(&file);
        let path = file.to_string_lossy().into_owned();
        let node = common::start(&[("persistExpectations", "true"), ("persistedExpectationsPath", path.as_str())]).await;
        let port = node.port;
        let puts: Vec<_> = (0..24).map(|i| tokio::spawn(async move { common::expect(port, &expectation(&format!("/c{i}"), "x")).await })).collect();
        for p in puts {
            p.await.unwrap();
        }
        let text = std::fs::read_to_string(&file).unwrap();
        for i in 0..24 {
            assert!(text.contains(&format!("\"/c{i}\"")), "/c{i} missing from the persisted file");
        }
        node.server.shutdown().await;
        let _ = std::fs::remove_file(&file);
    }

    /// `GET /mockserver/cluster` on each node of a three-member cluster (two servers and the observer)
    /// lists every member once, the same coordinator, and marks its own address `local`; the shape matches a JVM
    /// pair's (`coordinator` is the coordinator's id, `clusterName` present).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn get_cluster_lists_the_members_the_coordinator_and_the_local_node() {
        let fleet = Fleet::start().await;
        let mut ids = Vec::new();
        let mut coordinators = Vec::new();
        for port in [fleet.a.port, fleet.b.port] {
            let r = common::send(port, "GET", "/mockserver/cluster", "").await;
            assert_eq!(r.status, 200, "{}", r.head);
            let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
            assert_eq!(v["clustered"], true);
            assert_eq!(v["clusterName"], fleet.cluster.as_str());
            assert_eq!(v["memberCount"], 3);
            let members = v["members"].as_array().unwrap();
            assert_eq!(members.len(), 3);
            assert_eq!(members.iter().filter(|m| m["local"] == true).count(), 1);
            let local = members.iter().find(|m| m["local"] == true).unwrap();
            assert_eq!(local["id"], v["nodeId"]);
            // Every id is a JGroups logical name, `<host>-<n>` (Util.generateLocalName), as a JVM prints it
            for m in members {
                let id = m["id"].as_str().unwrap();
                assert!(id.rsplit_once('-').is_some_and(|(host, n)| !host.is_empty() && n.parse::<u32>().is_ok() && id.len() != 36), "not a logical name: {id}");
            }
            let coordinator = members.iter().find(|m| m["coordinator"] == true).unwrap();
            assert_eq!(coordinator["id"], v["coordinator"]);
            ids.push(v["nodeId"].as_str().unwrap().to_string());
            coordinators.push(v["coordinator"].as_str().unwrap().to_string());
        }
        assert_ne!(ids[0], ids[1]);
        assert_eq!(coordinators[0], coordinators[1]);
        fleet.stop().await;
    }

    // -----------------------------------------------------------------------------------------------------
    // ClusteredExpectationPersistenceReloadTest (2): the late joiner restores from `blobs`
    // -----------------------------------------------------------------------------------------------------

    /// A fleet keeper (a bare backend that holds the replicated caches while the server restarts), the persisted
    /// file (the same path for both nodes) and its blob key (the file name: `BlobKeys.forPersistedFile`).
    struct Reload {
        cluster: String,
        keeper: ClusterStateBackend,
        file: std::path::PathBuf,
    }

    impl Reload {
        fn new() -> Reload {
            let cluster = unique_cluster();
            let file = std::env::temp_dir().join(format!("clusteredPersistedExpectations-{}-{}.json", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            std::fs::write(&file, "").unwrap();
            Reload { keeper: start(&cluster), cluster, file }
        }

        async fn node(&self, restore_timeout_seconds: &str) -> common::Running {
            let path = self.file.to_string_lossy().into_owned();
            common::start(&[
                ("stateBackend", "infinispan"),
                ("clusterEnabled", "true"),
                ("clusterName", self.cluster.as_str()),
                ("persistExpectations", "true"),
                ("persistedExpectationsPath", path.as_str()),
                ("blobStoreRestoreTimeoutSeconds", restore_timeout_seconds),
            ])
            .await
        }

        fn blob_key(&self) -> String {
            self.file.file_name().unwrap().to_string_lossy().into_owned()
        }

        fn blob_body(&self) -> String {
            self.keeper.blobs().get(&self.blob_key()).map(|b| String::from_utf8_lossy(&b.data).into_owned()).unwrap_or_default()
        }
    }

    impl Drop for Reload {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.file);
        }
    }

    /// `shouldRestoreClusterPersistedExpectationsOnANodeThatStartsAfterwards`: the expectation made on node A is
    /// written to the clustered blob, A stops, and a fresh node B against the same cluster and path serves it
    /// although the local file is empty.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn should_restore_cluster_persisted_expectations_on_a_node_that_starts_afterwards() {
        let reload = Reload::new();
        let a = reload.node("60").await;
        eventually("the node joins the keeper", Duration::from_secs(30), || reload.keeper.members().len() == 2);
        common::expect(a.port, &expectation("/persisted", "restored-from-cluster")).await;
        assert_eq!(common::send(a.port, "GET", "/persisted", "").await.body, "restored-from-cluster", "it serves on the original node");
        eventually("the persisted document reaches the clustered blob", Duration::from_secs(30), || reload.blob_body().contains("/persisted"));

        a.server.shutdown().await;
        assert_eq!(std::fs::metadata(&reload.file).unwrap().len(), 0, "only the clustered blob cache holds the state, the local file stays empty");

        let b = reload.node("60").await;
        assert_eq!(common::send(b.port, "GET", "/persisted", "").await.body, "restored-from-cluster");
        b.server.shutdown().await;
    }

    /// `shouldNotRestoreClusterPersistedExpectationsWhenTheBlobStoreRestoreIsDisabled`, the negative control:
    /// `blobStoreRestoreTimeoutSeconds=0` skips the restore, the blob is still in the cluster.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn should_not_restore_cluster_persisted_expectations_when_the_blob_store_restore_is_disabled() {
        let reload = Reload::new();
        let a = reload.node("60").await;
        eventually("the node joins the keeper", Duration::from_secs(30), || reload.keeper.members().len() == 2);
        common::expect(a.port, &expectation("/persisted", "restored-from-cluster")).await;
        eventually("the persisted document reaches the clustered blob", Duration::from_secs(30), || reload.blob_body().contains("/persisted"));
        a.server.shutdown().await;

        let b = reload.node("0").await;
        let r = common::send(b.port, "GET", "/persisted", "").await;
        assert_eq!((r.status, r.body.as_str()), (404, ""), "with the restore disabled the fresh node does not have the expectation");
        assert!(reload.blob_body().contains("/persisted"), "the blob is still in the cluster, only the restore was skipped");
        b.server.shutdown().await;
    }

    /// `clear` propagates: cleared on A, gone on B (and cleared on B, gone on A).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn clear_propagates_across_nodes() {
        let fleet = Fleet::start().await;
        common::expect(fleet.a.port, &expectation("/to-clear", "x")).await;
        common::expect(fleet.b.port, &expectation("/to-clear-too", "y")).await;
        eventually_status(fleet.b.port, "/to-clear", 200).await;
        eventually_status(fleet.a.port, "/to-clear-too", 200).await;

        let r = common::send(fleet.a.port, "PUT", "/mockserver/clear", r#"{"path": "/to-clear"}"#).await;
        assert_eq!(r.status, 200);
        eventually_status(fleet.b.port, "/to-clear", 404).await;
        assert_eq!(status(fleet.b.port, "/to-clear-too").await, 200, "only the cleared expectation went");

        let r = common::send(fleet.b.port, "PUT", "/mockserver/clear", r#"{"path": "/to-clear-too"}"#).await;
        assert_eq!(r.status, 200);
        eventually_status(fleet.a.port, "/to-clear-too", 404).await;
        fleet.stop().await;
    }

    /// `reset` on one node clears the other's expectations.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reset_on_node_a_clears_node_b() {
        let fleet = Fleet::start().await;
        common::expect(fleet.a.port, &expectation("/r1", "1")).await;
        common::expect(fleet.a.port, &expectation("/r2", "2")).await;
        eventually_status(fleet.b.port, "/r1", 200).await;
        eventually_status(fleet.b.port, "/r2", 200).await;
        assert_eq!(common::send(fleet.a.port, "PUT", "/mockserver/reset", "").await.status, 200);
        eventually_status(fleet.b.port, "/r1", 404).await;
        eventually_status(fleet.b.port, "/r2", 404).await;
        assert_eq!(fleet.observer.expectation_store().size(), 0);
        fleet.stop().await;
    }

    /// `expectationUpdatedOnNodeAShouldReflectOnNodeB`: the same id, a new response, a newer backend version.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_update_on_node_a_reaches_node_b() {
        let fleet = Fleet::start().await;
        let mut e = expectation("/update-test", "v1");
        e["id"] = json!("update-me");
        common::expect(fleet.a.port, &e).await;
        eventually_status(fleet.b.port, "/update-test", 200).await;
        assert_eq!(common::send(fleet.b.port, "GET", "/update-test", "").await.body, "v1");
        e["httpResponse"]["body"] = json!("v2");
        common::expect(fleet.a.port, &e).await;
        let deadline = Instant::now() + Duration::from_secs(10);
        while common::send(fleet.b.port, "GET", "/update-test", "").await.body != "v2" {
            assert!(Instant::now() < deadline, "node B never saw v2");
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert_eq!(fleet.observer.expectation_store().get("update-me").map(|v| v.version), Some(2));
        fleet.stop().await;
    }

    /// `timesOnceShouldBeServedExactlyOnceAcrossTwoNodes`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn times_once_should_be_served_exactly_once_across_two_nodes() {
        let fleet = Fleet::start().await;
        common::expect(fleet.a.port, &limited("/times-once", 1)).await;
        view_of_b_is_current(&fleet).await;
        let (pa, pb) = (fleet.a.port, fleet.b.port);
        let (x, y) = tokio::join!(tokio::spawn(async move { status(pa, "/times-once").await }), tokio::spawn(async move { status(pb, "/times-once").await }));
        let served = [x.unwrap(), y.unwrap()].iter().filter(|s| **s == 200).count();
        assert_eq!(served, 1, "Times.once() should produce exactly 1 match across 2 nodes");
        fleet.stop().await;
    }

    /// `timesExactlyNShouldBeServedExactlyNTimesAcrossTwoNodes`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn times_exactly_n_should_be_served_exactly_n_times_across_two_nodes() {
        const N: u32 = 3;
        let fleet = Fleet::start().await;
        common::expect(fleet.a.port, &limited("/times-n", N)).await;
        view_of_b_is_current(&fleet).await;
        let mut served = 0;
        for i in 0..N + 4 {
            let port = if i % 2 == 0 { fleet.a.port } else { fleet.b.port };
            if status(port, "/times-n").await == 200 {
                served += 1;
            }
        }
        assert_eq!(served, N, "Times.exactly({N}) should produce exactly {N} matches across 2 nodes");
        fleet.stop().await;
    }

    /// `timesExactlyUnderHighConcurrencyShouldNotDoubleServe`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn times_exactly_under_high_concurrency_should_not_double_serve() {
        const N: u32 = 5;
        const THREADS_PER_NODE: usize = 4;
        let fleet = Fleet::start().await;
        common::expect(fleet.a.port, &limited("/times-concurrent", N)).await;
        view_of_b_is_current(&fleet).await;
        let mut tasks = Vec::new();
        for i in 0..THREADS_PER_NODE * 2 {
            let port = if i < THREADS_PER_NODE { fleet.a.port } else { fleet.b.port };
            tasks.push(tokio::spawn(async move {
                let mut served = 0;
                for _ in 0..N {
                    if status(port, "/times-concurrent").await == 200 {
                        served += 1;
                    }
                }
                served
            }));
        }
        let mut total = 0;
        for t in tasks {
            total += t.await.unwrap();
        }
        assert_eq!(total, N, "Times.exactly({N}) should produce exactly {N} total matches under high concurrency");
        fleet.stop().await;
    }

    fn eventually_probe(fleet: &Fleet, path: &str) {
        let probe = fleet.observer.expectation_store();
        eventually("replicated", Duration::from_secs(10), || probe.entries().iter().any(|(_, v)| v.value.expectation_json["httpRequest"]["path"] == path));
    }

    /// Node B's view holds everything written before this call: a sentinel written afterwards is visible on B only
    /// once B's reconcile (a full scan of the backend) has run past it.
    async fn view_of_b_is_current(fleet: &Fleet) {
        let sentinel = format!("/sentinel-{}", NEXT.fetch_add(1, Ordering::Relaxed));
        common::expect(fleet.a.port, &expectation(&sentinel, "s")).await;
        eventually_status(fleet.b.port, &sentinel, 200).await;
    }

    /// `sharedTimesCasBypassedWhenSharedTimesDisabled`: with `clusterSharedTimesEnabled=false` on node A, a served
    /// match decrements A's own count and never touches the replicated counter.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_times_cas_is_bypassed_when_shared_times_is_disabled() {
        const N: u32 = 3;
        let fleet = Fleet::start_with(&[("clusterSharedTimesEnabled", "false")]).await;
        let mut e = limited("/times-no-cas", N);
        e["id"] = json!("no-cas");
        common::expect(fleet.a.port, &e).await;
        eventually_probe(&fleet, "/times-no-cas");
        assert_eq!(status(fleet.a.port, "/times-no-cas").await, 200);
        let store = fleet.observer.expectation_store();
        assert_eq!(store.get("no-cas").map(|v| v.value.remaining_times), Some(N as i64), "the shared counter is untouched");
        assert_eq!(store.get("no-cas").map(|v| v.version), Some(1), "and no write happened");
        fleet.stop().await;
    }

    /// `scenarioStepShouldBeServedExactlyOnceAcrossTwoNodes`: two servers racing the same `Started` -> `Step1`
    /// expectation through the data plane; the loser's commit-point compare-and-set fails and it falls through.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn scenario_step_should_be_served_exactly_once_across_two_nodes() {
        let fleet = Fleet::start().await;
        let mut e = expectation("/scenario-step", "step1-served");
        e["scenarioName"] = json!("raceScenario");
        e["scenarioState"] = json!("Started");
        e["newScenarioState"] = json!("Step1");
        common::expect(fleet.a.port, &e).await;
        view_of_b_is_current(&fleet).await;
        let (pa, pb) = (fleet.a.port, fleet.b.port);
        let (x, y) = tokio::join!(tokio::spawn(async move { status(pa, "/scenario-step").await }), tokio::spawn(async move { status(pb, "/scenario-step").await }));
        let served = [x.unwrap(), y.unwrap()].iter().filter(|s| **s == 200).count();
        assert_eq!(served, 1, "Started->Step1 should be served by exactly 1 node");
        for port in [fleet.a.port, fleet.b.port] {
            let r = common::send(port, "GET", "/mockserver/scenario/raceScenario", "").await;
            assert!(r.body.contains("\"currentState\" : \"Step1\""), "the scenario advanced exactly once, visible on both nodes: {}", r.body);
        }
        fleet.stop().await;
    }

    /// `unlimitedTimesShouldNotBeLimitedUnderClustering`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unlimited_times_should_not_be_limited_under_clustering() {
        let fleet = Fleet::start().await;
        common::expect(fleet.a.port, &expectation("/unlimited", "unlimited")).await;
        eventually_status(fleet.b.port, "/unlimited", 200).await;
        let mut matches = 0;
        for i in 0..20 {
            let port = if i % 2 == 0 { fleet.a.port } else { fleet.b.port };
            if status(port, "/unlimited").await == 200 {
                matches += 1;
            }
        }
        assert_eq!(matches, 20, "unlimited Times should produce matches on every attempt");
        assert_eq!(fleet.observer.expectation_store().entries().iter().map(|(_, v)| v.version).max(), Some(1), "no CAS write for unlimited Times");
        fleet.stop().await;
    }

    /// `backendRemainingTimesShouldReachZeroWhenExhausted` (adapted: upstream's mocked scheduler never runs the
    /// removal of an exhausted matcher, so its counter stays at 0; here the counter is read at 0 after the last
    /// use, and the request after it, which finds the counter at zero, removes the expectation and its counter).
    /// The counter drops across the wire as a bare `Integer`; the `ExpectationEntry` keeps its seed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn backend_remaining_times_should_reach_zero_when_exhausted() {
        const N: u32 = 2;
        let fleet = Fleet::start().await;
        let mut e = limited("/backend-counter", N);
        e["id"] = json!("counter");
        common::expect(fleet.a.port, &e).await;
        let (store, counters) = (fleet.observer.expectation_store(), fleet.observer.shared_times_store());
        eventually("replicated", Duration::from_secs(10), || store.get("counter").is_some());
        assert_eq!(counters.get("counter").map(|v| v.value), Some(N as i32), "the counter is seeded before the put");
        assert_eq!(status(fleet.a.port, "/backend-counter").await, 200);
        assert_eq!(counters.get("counter").map(|v| v.value), Some(1), "one use consumed through the shared counter");
        assert_eq!(status(fleet.a.port, "/backend-counter").await, 200);
        assert_eq!(counters.get("counter").map(|v| v.value), Some(0), "the shared-times counter is 0 after exhaustion");
        assert_eq!(store.get("counter").map(|v| v.value.remaining_times), Some(N as i64), "ExpectationEntry remainingTimes stays at the immutable seed");
        for _ in 0..2 {
            assert_eq!(status(fleet.a.port, "/backend-counter").await, 404);
        }
        eventually("the exhausted expectation and its counter are removed", Duration::from_secs(10), || store.get("counter").is_none() && counters.get("counter").is_none());
        fleet.stop().await;
    }

    /// `sharedTimesCounterEnforcesExactlyNAcrossTwoNodesUnderContention`: both nodes hammer one `Times.exactly(N)`
    /// expectation at once; the dedicated counter's compare-and-set serves exactly N fleet-wide and never goes below
    /// 0, and the `ExpectationEntry` seed is never rewritten. (Adapted as the case above: upstream's mocked scheduler
    /// keeps the drained counter; here the request that finds it at 0 removes the expectation and the counter.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_times_counter_enforces_exactly_n_across_two_nodes_under_contention() {
        const N: usize = 10;
        const THREADS: usize = 8;
        const ATTEMPTS_PER_THREAD: usize = 5;
        let fleet = Fleet::start().await;
        let mut e = limited("/times-counter-contention", N as u32);
        e["id"] = json!("contended");
        common::expect(fleet.a.port, &e).await;
        view_of_b_is_current(&fleet).await;
        let (store, counters) = (fleet.observer.expectation_store(), fleet.observer.shared_times_store());
        let mut tasks = Vec::new();
        for i in 0..THREADS {
            let port = if i % 2 == 0 { fleet.a.port } else { fleet.b.port };
            tasks.push(tokio::spawn(async move {
                let mut served = 0;
                for _ in 0..ATTEMPTS_PER_THREAD {
                    if status(port, "/times-counter-contention").await == 200 {
                        served += 1;
                    }
                }
                served
            }));
        }
        let mut total = 0;
        for t in tasks {
            total += t.await.unwrap();
        }
        assert_eq!(total, N, "Times.exactly({N}) must never be served more than {N} times across two nodes");
        if let Some(counter) = counters.get("contended") {
            assert_eq!(counter.value, 0, "the shared-times counter drained to exactly 0 (never negative)");
        }
        if let Some(entry) = store.get("contended") {
            assert_eq!(entry.value.remaining_times, N as i64, "ExpectationEntry remainingTimes stays at the immutable seed");
        }
        fleet.stop().await;
    }

    /// `sharedTimesCounterEvictedOnAllNodesMustNotOverServe`: a live counter evicted on every node (node-local, so the
    /// key is absent at its primary owner whichever node that is) must never let `Times.exactly(N)` serve more than N
    /// fleet-wide. The observer, a third member of the replicated cache, loses its copy too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_times_counter_evicted_on_all_nodes_must_not_over_serve() {
        const N: usize = 5;
        let fleet = Fleet::start_sharing_backends().await;
        let [ba, bb] = fleet.backends.clone().unwrap();
        let mut e = limited("/times-evict-all", N as u32);
        e["id"] = json!("evict-all");
        common::expect(fleet.a.port, &e).await;
        view_of_b_is_current(&fleet).await;
        let mut served = 0;
        if status(fleet.a.port, "/times-evict-all").await == 200 {
            served += 1;
        }
        let counter = |b: &ClusterStateBackend| b.shared_times_store().get("evict-all").map(|v| v.value);
        assert_eq!(counter(&ba), Some(N as i32 - 1), "counter is live before eviction");
        for node in [&*ba, &*bb, &fleet.observer] {
            Fleet::evict_counter(node, "evict-all");
        }
        assert_eq!(counter(&ba), None, "node A counter replica evicted");
        assert_eq!(counter(&bb), None, "node B counter replica evicted");
        for i in 0..N * 2 {
            let port = if i % 2 == 0 { fleet.a.port } else { fleet.b.port };
            if status(port, "/times-evict-all").await == 200 {
                served += 1;
            }
        }
        assert!(served <= N, "Times.exactly({N}) must NEVER serve more than N fleet-wide, even after eviction of a live counter, got {served}");
        assert!(served >= 1, "at least the pre-eviction match served");
        fleet.stop().await;
    }

    /// `nodeLocalCounterEvictionIsNotReplicatedToPeer`: evicting the counter on node A leaves node B holding the live
    /// value (`evict` is node-local); hammering both nodes then stays within N whoever owns the key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn node_local_counter_eviction_is_not_replicated_to_peer() {
        const N: usize = 5;
        let fleet = Fleet::start_sharing_backends().await;
        let [ba, bb] = fleet.backends.clone().unwrap();
        let mut e = limited("/times-evict-one", N as u32);
        e["id"] = json!("evict-one");
        common::expect(fleet.a.port, &e).await;
        view_of_b_is_current(&fleet).await;
        let mut served = 0;
        if status(fleet.a.port, "/times-evict-one").await == 200 {
            served += 1;
        }
        let counter = |b: &ClusterStateBackend| b.shared_times_store().get("evict-one").map(|v| v.value);
        assert_eq!(counter(&ba), Some(N as i32 - 1), "counter live before eviction");
        Fleet::evict_counter(&ba, "evict-one");
        assert_eq!(counter(&ba), None, "node A lost its replica");
        assert_eq!(counter(&bb), Some(N as i32 - 1), "node B (peer) retains the live value: evict is node-local");
        for i in 0..N * 2 {
            let port = if i % 2 == 0 { fleet.a.port } else { fleet.b.port };
            if status(port, "/times-evict-one").await == 200 {
                served += 1;
            }
        }
        assert!(served <= N, "Times.exactly({N}) must NEVER serve more than N fleet-wide, got {served}");
        fleet.stop().await;
    }

    /// A node that joins later has the entries through state transfer, but state transfer fires no listener event, so
    /// its matchers are not rebuilt from them (upstream restores such a node from `blobs`, never from live events);
    /// the first change anywhere in the fleet brings its view up to date.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_late_joiner_is_not_populated_by_state_transfer_events() {
        let fleet = Fleet::start().await;
        common::expect(fleet.a.port, &expectation("/early", "early")).await;
        eventually_status(fleet.b.port, "/early", 200).await;
        let late = common::start(&[("stateBackend", "infinispan"), ("clusterEnabled", "true"), ("clusterName", fleet.cluster.as_str())]).await;
        eventually("the late node has the entry in the backend", Duration::from_secs(10), || fleet.observer.expectation_store().size() == 1);
        assert_eq!(status(late.port, "/early").await, 404, "no listener event fired for state transfer: the matchers are still empty");
        common::expect(fleet.a.port, &expectation("/trigger", "t")).await;
        eventually_status(late.port, "/trigger", 200).await;
        assert_eq!(status(late.port, "/early").await, 200, "the reconcile scan adds everything the backend holds");
        late.server.shutdown().await;
        fleet.stop().await;
    }

    /// Scenario states belong to one server (they were once process-wide): two unclustered servers in
    /// this process neither share a state nor clear each other's on `reset`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn scenario_states_belong_to_one_server() {
        let one = common::start(&[]).await;
        let two = common::start(&[]).await;
        let put = common::send(one.port, "PUT", "/mockserver/scenario/mine", r#"{"state": "Step1"}"#).await;
        assert_eq!(put.status, 200);
        let seen_by = |port: u16| async move { common::send(port, "GET", "/mockserver/scenario/mine", "").await.body };
        assert!(seen_by(one.port).await.contains("Step1"));
        assert!(seen_by(two.port).await.contains("Started"), "the other server still has the implicit state");
        assert_eq!(common::send(two.port, "PUT", "/mockserver/reset", "").await.status, 200);
        assert!(seen_by(one.port).await.contains("Step1"), "a reset of the other server leaves it alone");
        one.server.shutdown().await;
        two.server.shutdown().await;
    }

    /// Raw bytes to `port`; what comes back before the server closes or goes quiet for a second.
    async fn binary_exchange(port: u16, bytes: &[u8]) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream.write_all(bytes).await.unwrap();
        let mut answer = Vec::new();
        let mut buffer = [0u8; 1024];
        while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer)).await {
            if n == 0 {
                break;
            }
            answer.extend_from_slice(&buffer[..n]);
        }
        answer
    }

    /// A binary request is matched by `firstMatchingExpectation` like an HTTP one, so a limited binary expectation's
    /// `Times` are the fleet's shared counter: served once across both nodes, never once per node.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn binary_times_once_is_served_once_across_two_nodes() {
        let fleet = Fleet::start().await;
        let request = [0x30u8, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39];
        let once = json!({"httpRequest": {"binaryData": "MDEyMzQ1Njc4OQ=="}, "binaryResponse": {"binaryData": "AQIDBA=="}, "times": {"remainingTimes": 1, "unlimited": false}});
        common::expect(fleet.a.port, &once).await;
        view_of_b_is_current(&fleet).await;
        assert_eq!(binary_exchange(fleet.b.port, &request).await, vec![1, 2, 3, 4], "node B serves the one use");
        assert_ne!(binary_exchange(fleet.a.port, &request).await, vec![1, 2, 3, 4], "node A sees it used up");
        fleet.stop().await;
    }

    /// `ChaosProfileLibrary` is built on the state backend's `chaos-profiles` store: a profile saved on node A is listed,
    /// read and deleted on node B, and a reset of either node leaves it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn saved_chaos_profiles_are_shared_across_the_fleet() {
        let fleet = Fleet::start().await;
        let profile = json!({"stages": [{"durationMillis": 600000, "profiles": {"p.svc": {"errorStatus": 502}}}], "name": "ignored"});
        let saved = common::send(fleet.a.port, "PUT", "/mockserver/chaosExperiment/profiles/nightly%20storm", &profile.to_string()).await;
        assert_eq!(saved.status, 200, "{}", saved.body);
        let listed = common::send(fleet.b.port, "GET", "/mockserver/chaosExperiment/profiles", "").await;
        assert_eq!(serde_json::from_str::<serde_json::Value>(&listed.body).unwrap(), json!({"profiles": ["nightly storm"]}));
        let read = common::send(fleet.b.port, "GET", "/mockserver/chaosExperiment/profiles/nightly%20storm", "").await;
        assert_eq!(serde_json::from_str::<serde_json::Value>(&read.body).unwrap()["name"], "nightly storm");
        assert_eq!(common::send(fleet.b.port, "PUT", "/mockserver/reset", "").await.status, 200);
        assert_eq!(common::send(fleet.a.port, "GET", "/mockserver/chaosExperiment/profiles/nightly%20storm", "").await.status, 200, "a reset leaves saved profiles");
        let deleted = common::send(fleet.b.port, "DELETE", "/mockserver/chaosExperiment/profiles/nightly%20storm", "").await;
        assert!(deleted.body.contains("\"deleted\""), "{}", deleted.body);
        assert_eq!(common::send(fleet.a.port, "GET", "/mockserver/chaosExperiment/profiles/nightly%20storm", "").await.status, 404);
        fleet.stop().await;
    }

    /// `LoadScenarioRegistry` is built on the state backend's `load-scenarios` store: a scenario loaded on node A is
    /// listed and read on node B, survives a reset, and a clear on node B removes it fleet-wide.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn load_scenarios_are_shared_across_the_fleet() {
        let fleet = Fleet::start().await;
        let scenario = json!({"name": "shared-load", "steps": [{"request": {"method": "GET", "path": "/x"}}], "profile": {"stages": [{"vus": 1, "durationMillis": 1000}]}});
        let loaded = common::send(fleet.a.port, "PUT", "/mockserver/loadScenario", &scenario.to_string()).await;
        assert_eq!(loaded.status, 200, "{}", loaded.body);
        let read = common::send(fleet.b.port, "GET", "/mockserver/loadScenario/shared-load", "").await;
        assert_eq!(read.status, 200, "{}", read.body);
        assert_eq!(serde_json::from_str::<serde_json::Value>(&read.body).unwrap()["definition"]["name"], "shared-load");
        let listed = common::send(fleet.b.port, "GET", "/mockserver/loadScenario", "").await;
        assert!(listed.body.contains("shared-load"), "{}", listed.body);
        assert_eq!(common::send(fleet.a.port, "PUT", "/mockserver/reset", "").await.status, 200);
        assert_eq!(common::send(fleet.b.port, "GET", "/mockserver/loadScenario/shared-load", "").await.status, 200, "a reset leaves loaded scenarios");
        assert_eq!(common::send(fleet.b.port, "DELETE", "/mockserver/loadScenario", "").await.status, 200);
        assert_eq!(common::send(fleet.a.port, "GET", "/mockserver/loadScenario/shared-load", "").await.status, 404);
        fleet.stop().await;
    }

    /// Without `clusterEnabled` nothing of this applies: the store has no cluster link and behaves as before.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_local_mode_server_has_no_cluster_link() {
        let r = common::start(&[("stateBackend", "infinispan")]).await;
        common::expect(r.port, &limited("/local", 2)).await;
        assert_eq!(status(r.port, "/local").await, 200);
        assert_eq!(status(r.port, "/local").await, 200);
        assert_eq!(status(r.port, "/local").await, 404);
        r.server.shutdown().await;
    }
}

// =========================================================================================================
// ClusteredTwoNodeTest, scenario cases through `ScenarioManager` (6 of 7; the seventh is in `core_wiring`)
// =========================================================================================================

mod scenario_states {
    use super::*;
    use mock_server::scenario::Scenarios;

    struct Nodes {
        b: Arc<ClusterStateBackend>,
        a: Arc<ClusterStateBackend>,
    }

    fn nodes() -> Nodes {
        let cluster = unique_cluster();
        let a = Arc::new(start(&cluster));
        let b = Arc::new(start(&cluster));
        eventually("the 2-node cluster forms", Duration::from_secs(30), || a.members().len() == 2 && b.members().len() == 2);
        Nodes { b, a }
    }

    /// `new ScenarioManager(node.scenarioStates())`.
    fn manager(node: &Arc<ClusterStateBackend>) -> Scenarios {
        let manager = Scenarios::default();
        manager.attach_backend(node.clone());
        manager
    }

    #[test]
    fn scenario_transition_on_node_a_should_be_visible_on_node_b() {
        let n = nodes();
        let (a, b) = (manager(&n.a), manager(&n.b));
        assert_eq!(a.get("myScenario"), "Started");
        assert_eq!(b.get("myScenario"), "Started");
        assert!(a.matches_and_transition("myScenario", "Started", "Step1"), "transition from Started to Step1 should succeed on node A");
        assert_eq!(b.get("myScenario"), "Step1", "REPL_SYNC = synchronous replication");
    }

    #[test]
    fn multi_step_scenario_transition_across_nodes_should_work() {
        let n = nodes();
        let (a, b) = (manager(&n.a), manager(&n.b));
        assert!(a.matches_and_transition("multiStep", "Started", "Step1"));
        assert_eq!(b.get("multiStep"), "Step1");
        assert!(b.matches_and_transition("multiStep", "Step1", "Step2"));
        assert_eq!(a.get("multiStep"), "Step2");
        assert!(a.matches_and_transition("multiStep", "Step2", "Done"));
        assert_eq!(b.get("multiStep"), "Done");
    }

    #[test]
    fn two_nodes_cannot_double_transition_same_scenario() {
        let n = nodes();
        let (a, b) = (Arc::new(manager(&n.a)), Arc::new(manager(&n.b)));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let won = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = [a.clone(), b.clone()]
            .into_iter()
            .map(|m| {
                let (barrier, won) = (barrier.clone(), won.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    if m.matches_and_transition("onceScenario", "Started", "Step1") {
                        won.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().expect("no exceptions expected");
        }
        assert_eq!(won.load(Ordering::SeqCst), 1, "exactly one node should win the Started->Step1 transition");
        assert_eq!(a.get("onceScenario"), "Step1");
        assert_eq!(b.get("onceScenario"), "Step1");
    }

    #[test]
    fn scenario_clear_on_node_a_should_be_visible_on_node_b() {
        let n = nodes();
        let (a, b) = (manager(&n.a), manager(&n.b));
        a.set("clearMe", "Step1");
        assert_eq!(b.get("clearMe"), "Step1");
        a.clear("clearMe");
        assert_eq!(b.get("clearMe"), "Started", "after clear, the state reverts to the implicit STARTED default");
    }

    #[test]
    fn scenario_reset_on_node_a_should_clear_all_states_on_node_b() {
        let n = nodes();
        let (a, b) = (manager(&n.a), manager(&n.b));
        a.set("s1", "Step1");
        a.set("s2", "Step2");
        assert_eq!(b.get("s1"), "Step1");
        assert_eq!(b.get("s2"), "Step2");
        a.reset();
        assert_eq!(b.get("s1"), "Started");
        assert_eq!(b.get("s2"), "Started");
    }

    #[test]
    fn isolated_scenario_transition_should_replicate_across_nodes() {
        let n = nodes();
        let (a, b) = (manager(&n.a), manager(&n.b));
        assert!(a.matches_and_transition_isolated("conv", Some("session-1"), "Started", "turn_1"));
        assert_eq!(b.get_with_isolation("conv", Some("session-1")), "turn_1");
        assert!(b.matches_and_transition_isolated("conv", Some("session-2"), "Started", "turn_1"));
        assert_eq!(a.get_with_isolation("conv", Some("session-2")), "turn_1");
        assert_eq!(a.get_with_isolation("conv", Some("session-1")), "turn_1", "original isolation unchanged");
    }
}

// =========================================================================================================
// ClusteredTwoNodeCrossProtocolBusTest (4)
// =========================================================================================================

mod cross_protocol_bus {
    use super::*;
    use mock_server::scenario::{CrossProtocolBus, CrossProtocolScenario, Scenarios, Trigger};

    struct Node {
        _backend: Arc<ClusterStateBackend>,
        bus: Arc<CrossProtocolBus>,
        /// Upstream's `new ScenarioManager()`: a standalone, node-local one.
        scenarios: Arc<Scenarios>,
    }

    struct Reconcile(Arc<CrossProtocolBus>);

    impl InvalidationListener for Reconcile {
        fn on_changed(&self, _key: &str) {
            self.0.reconcile_bus();
        }
        fn on_cleared(&self) {
            self.0.reconcile_bus();
        }
    }

    /// `busX.setStateBackend(nodeX)`, `busX.setScenarioManager(scenarioX)`, and, where the test wires one, the
    /// invalidation listener that reconciles the bus.
    fn node(backend: Arc<ClusterStateBackend>, reconcile: bool) -> Node {
        let bus = Arc::new(CrossProtocolBus::default());
        let scenarios = Arc::new(Scenarios::default());
        let as_backend: Arc<dyn StateBackend> = backend.clone();
        bus.attach_backend(&as_backend);
        bus.set_scenario_manager(scenarios.clone());
        if reconcile {
            backend.add_invalidation_listener(Arc::new(Reconcile(bus.clone())));
        }
        Node { _backend: backend, bus, scenarios }
    }

    /// Node B always reconciles; node A only where the test says so.
    fn two_nodes(reconcile_a: bool) -> (Node, Node) {
        let cluster = unique_cluster();
        let a = Arc::new(start(&cluster));
        let b = Arc::new(start(&cluster));
        eventually("the 2-node cluster forms", Duration::from_secs(30), || a.members().len() == 2 && b.members().len() == 2);
        (node(a, reconcile_a), node(b, true))
    }

    #[test]
    fn registration_on_node_a_should_be_visible_on_node_b() {
        let (a, b) = two_nodes(false);
        a.bus.register(CrossProtocolScenario::on_dns_query("api.example.com", "DnsScenario", "DnsObserved"));
        eventually("firing DNS_QUERY on node B should transition DnsScenario to DnsObserved", Duration::from_secs(5), || {
            b.bus.fire(Trigger::DnsQuery, "api.example.com");
            b.scenarios.get("DnsScenario") == "DnsObserved"
        });
        assert_eq!(b.scenarios.get("DnsScenario"), "DnsObserved");
    }

    #[test]
    fn unregister_on_node_b_should_remove_from_node_a() {
        let (a, b) = two_nodes(true);
        let scenario = CrossProtocolScenario::on_http_path("/api/", "ApiScenario", "ApiCalled");
        a.bus.register(scenario.clone());
        eventually("node A should have the registration active", Duration::from_secs(5), || {
            a.bus.fire(Trigger::HttpRequest, "/api/test");
            a.scenarios.get("ApiScenario") == "ApiCalled"
        });
        a.scenarios.set("ApiScenario", "Started");
        eventually("node B should have the registration", Duration::from_secs(5), || !b.bus.registrations().is_empty());
        b.bus.unregister(&scenario);
        eventually("after unregister on node B, firing on node A should not transition the scenario", Duration::from_secs(5), || {
            a.bus.reconcile_bus();
            a.scenarios.set("ApiScenario", "Started");
            a.bus.fire(Trigger::HttpRequest, "/api/test");
            a.scenarios.get("ApiScenario") == "Started"
        });
    }

    #[test]
    fn reset_on_node_a_should_clear_node_b() {
        let (a, b) = two_nodes(false);
        a.bus.register(CrossProtocolScenario::on_dns_query("a.com", "S1", "State1"));
        a.bus.register(CrossProtocolScenario::on_grpc_request("SvcX", "S2", "State2"));
        eventually("node B should see both registrations", Duration::from_secs(5), || {
            b.bus.fire(Trigger::DnsQuery, "a.com");
            b.bus.fire(Trigger::GrpcRequest, "SvcX");
            b.scenarios.get("S1") == "State1" && b.scenarios.get("S2") == "State2"
        });
        a.bus.reset();
        eventually("after reset on A, node B should have no registrations", Duration::from_secs(5), || {
            b.bus.reconcile_bus();
            b.scenarios.set("S1", "Started");
            b.scenarios.set("S2", "Started");
            b.bus.fire(Trigger::DnsQuery, "a.com");
            b.bus.fire(Trigger::GrpcRequest, "SvcX");
            b.scenarios.get("S1") == "Started" && b.scenarios.get("S2") == "Started"
        });
    }

    #[test]
    fn multiple_trigger_types_replicate_independently() {
        let (a, b) = two_nodes(false);
        a.bus.register(CrossProtocolScenario::on_dns_query("dns.example.com", "DnsSc", "DnsState"));
        a.bus.register(CrossProtocolScenario::on_web_socket_connect("WsSc", "WsState"));
        a.bus.register(CrossProtocolScenario::on_grpc_request("UserSvc", "GrpcSc", "GrpcState"));
        a.bus.register(CrossProtocolScenario::on_http_path("/v1/", "HttpSc", "HttpState"));
        eventually("all four trigger types should replicate to node B", Duration::from_secs(10), || {
            b.bus.fire(Trigger::DnsQuery, "dns.example.com");
            b.bus.fire(Trigger::WebSocketConnect, "/ws");
            b.bus.fire(Trigger::GrpcRequest, "/com.example.UserSvc/Get");
            b.bus.fire(Trigger::HttpRequest, "/v1/users");
            [("DnsSc", "DnsState"), ("WsSc", "WsState"), ("GrpcSc", "GrpcState"), ("HttpSc", "HttpState")].iter().all(|(s, v)| b.scenarios.get(s) == *v)
        });
    }
}

// =========================================================================================================
// ClusteredTwoNodeChaosTest (10)
// =========================================================================================================

mod chaos {
    use super::*;
    use mock_server::GrpcChaosProfile;
    use mock_server::chaos::grpc::Registry as GrpcRegistry;
    use mock_server::chaos::{HostRegistry, HttpChaosProfile, TcpChaosProfile};

    struct Fleet {
        a: Arc<ClusterStateBackend>,
        b: Arc<ClusterStateBackend>,
    }

    fn fleet() -> Fleet {
        let cluster = unique_cluster();
        let a = Arc::new(start(&cluster));
        let b = Arc::new(start(&cluster));
        eventually("the 2-node cluster forms", Duration::from_secs(30), || a.members().len() == 2 && b.members().len() == 2);
        Fleet { a, b }
    }

    struct Reconcile(Box<dyn Fn() + Send + Sync>);

    impl InvalidationListener for Reconcile {
        fn on_changed(&self, _key: &str) {
            (self.0)();
        }
        fn on_cleared(&self) {
            (self.0)();
        }
    }

    /// What upstream's tests register on a node: an invalidation listener that reconciles the registries.
    fn reconciling(node: &ClusterStateBackend, f: impl Fn() + Send + Sync + 'static) {
        node.add_invalidation_listener(Arc::new(Reconcile(Box::new(f))));
    }

    fn service(backend: &ClusterStateBackend) -> Arc<HostRegistry<HttpChaosProfile>> {
        let registry = Arc::new(HostRegistry::<HttpChaosProfile>::default());
        registry.set_state_backend(backend);
        registry
    }

    fn tcp(backend: &ClusterStateBackend) -> Arc<HostRegistry<TcpChaosProfile>> {
        let registry = Arc::new(HostRegistry::<TcpChaosProfile>::default());
        registry.set_state_backend(backend);
        registry
    }

    fn grpc(backend: &ClusterStateBackend) -> Arc<GrpcRegistry> {
        let registry = Arc::new(GrpcRegistry::default());
        registry.set_state_backend(backend);
        registry
    }

    fn http_profile(status: i32) -> HttpChaosProfile {
        HttpChaosProfile { error_status: Some(status), ..Default::default() }
    }

    fn grpc_profile(code: &str, probability: f64) -> GrpcChaosProfile {
        GrpcChaosProfile { error_status_code: Some(code.into()), error_probability: Some(probability), ..Default::default() }
    }

    const FIVE: Duration = Duration::from_secs(5);

    #[test]
    fn service_chaos_registered_on_node_a_should_be_visible_on_node_b() {
        let f = fleet();
        let (a, b) = (service(&f.a), service(&f.b));
        let for_b = b.clone();
        reconciling(&f.b, move || for_b.reconcile_from_backend());
        a.put("api.example.com", HttpChaosProfile { error_status: Some(503), error_probability: Some(0.75), ..Default::default() }, 0);
        eventually("node B should see the service chaos profile registered on node A", FIVE, || b.get("api.example.com").is_some());
        let resolved = b.get("api.example.com").expect("resolved");
        assert_eq!(resolved.error_status, Some(503));
        assert_eq!(resolved.error_probability, Some(0.75));
    }

    #[test]
    fn service_chaos_removed_on_node_b_should_disappear_from_node_a() {
        let f = fleet();
        let (a, b) = (service(&f.a), service(&f.b));
        let (for_a, for_b) = (a.clone(), b.clone());
        reconciling(&f.a, move || for_a.reconcile_from_backend());
        reconciling(&f.b, move || for_b.reconcile_from_backend());
        a.put("api.example.com", http_profile(500), 0);
        eventually("node B should see the profile", FIVE, || b.get("api.example.com").is_some());
        b.remove("api.example.com");
        eventually("node A should no longer see the removed profile", FIVE, || a.get("api.example.com").is_none());
    }

    #[test]
    fn service_chaos_reset_on_node_a_should_clear_node_b() {
        let f = fleet();
        let (a, b) = (service(&f.a), service(&f.b));
        let for_b = b.clone();
        reconciling(&f.b, move || for_b.reconcile_from_backend());
        a.put("a.svc", http_profile(503), 0);
        a.put("b.svc", http_profile(500), 0);
        eventually("node B should see both profiles", FIVE, || b.entries().len() == 2);
        a.reset();
        eventually("node B should be empty after reset on node A", FIVE, || b.entries().is_empty());
    }

    #[test]
    fn tcp_chaos_registered_on_node_a_should_be_visible_on_node_b() {
        let f = fleet();
        let (a, b) = (tcp(&f.a), tcp(&f.b));
        let for_b = b.clone();
        reconciling(&f.b, move || for_b.reconcile_from_backend());
        a.put("db.example", TcpChaosProfile { latency_ms: Some(500), down: Some(false), ..Default::default() }, 0);
        eventually("node B should see the TCP chaos profile registered on node A", FIVE, || b.get("db.example").is_some());
        let resolved = b.get("db.example").expect("resolved");
        assert_eq!(resolved.latency_ms, Some(500));
        assert_eq!(resolved.down, Some(false));
    }

    #[test]
    fn tcp_chaos_removed_on_node_b_should_disappear_from_node_a() {
        let f = fleet();
        let (a, b) = (tcp(&f.a), tcp(&f.b));
        let (for_a, for_b) = (a.clone(), b.clone());
        reconciling(&f.a, move || for_a.reconcile_from_backend());
        reconciling(&f.b, move || for_b.reconcile_from_backend());
        a.put("db.example", TcpChaosProfile { reset_peer: Some(true), ..Default::default() }, 0);
        eventually("node B should see the TCP profile", FIVE, || b.get("db.example").is_some());
        b.remove("db.example");
        eventually("node A should no longer see the removed TCP profile", FIVE, || a.get("db.example").is_none());
    }

    #[test]
    fn grpc_chaos_registered_on_node_a_should_be_visible_on_node_b() {
        let f = fleet();
        let (a, b) = (grpc(&f.a), grpc(&f.b));
        let for_b = b.clone();
        reconciling(&f.b, move || for_b.reconcile_from_backend());
        a.put("greeter.GreeterService", grpc_profile("UNAVAILABLE", 1.0), 0);
        eventually("node B should see the gRPC chaos profile registered on node A", FIVE, || b.get("greeter.greeterservice").is_some());
        let resolved = b.get("greeter.GreeterService").expect("resolved");
        assert_eq!(resolved.error_status_code.as_deref(), Some("UNAVAILABLE"));
        assert_eq!(resolved.error_probability, Some(1.0));
    }

    #[test]
    fn grpc_chaos_default_profile_should_replicate_across_nodes() {
        let f = fleet();
        let (a, b) = (grpc(&f.a), grpc(&f.b));
        let for_b = b.clone();
        reconciling(&f.b, move || for_b.reconcile_from_backend());
        a.put("", grpc_profile("INTERNAL", 0.5), 0);
        eventually("node B should see the default gRPC chaos profile via fallback", FIVE, || b.get("any.Service").is_some());
        let resolved = b.get("any.Service").expect("resolved");
        assert_eq!(resolved.error_status_code.as_deref(), Some("INTERNAL"));
        assert_eq!(resolved.error_probability, Some(0.5));
    }

    #[test]
    fn grpc_chaos_removed_on_node_a_should_disappear_from_node_b() {
        let f = fleet();
        let (a, b) = (grpc(&f.a), grpc(&f.b));
        let for_b = b.clone();
        reconciling(&f.b, move || for_b.reconcile_from_backend());
        a.put("greeter.GreeterService", grpc_profile("DEADLINE_EXCEEDED", 1.0), 0);
        eventually("node B should see the gRPC profile", FIVE, || b.get("greeter.greeterservice").is_some());
        a.remove("greeter.GreeterService");
        eventually("node B should no longer see the removed gRPC profile", FIVE, || b.get("greeter.greeterservice").is_none());
    }

    #[test]
    fn all_three_chaos_types_replicate_independently() {
        let f = fleet();
        let (svc_a, svc_b) = (service(&f.a), service(&f.b));
        let (tcp_a, tcp_b) = (tcp(&f.a), tcp(&f.b));
        let (grpc_a, grpc_b) = (grpc(&f.a), grpc(&f.b));
        let (s, t, g) = (svc_b.clone(), tcp_b.clone(), grpc_b.clone());
        reconciling(&f.b, move || {
            s.reconcile_from_backend();
            t.reconcile_from_backend();
            g.reconcile_from_backend();
        });
        svc_a.put("web.svc", http_profile(503), 0);
        tcp_a.put("db.example", TcpChaosProfile { down: Some(true), ..Default::default() }, 0);
        grpc_a.put("auth.AuthService", grpc_profile("UNAUTHENTICATED", 1.0), 0);
        eventually("node B should see all three chaos types", Duration::from_secs(10), || {
            svc_b.get("web.svc").is_some() && tcp_b.get("db.example").is_some() && grpc_b.get("auth.authservice").is_some()
        });
        assert_eq!(svc_b.get("web.svc").and_then(|p| p.error_status), Some(503));
        assert_eq!(tcp_b.get("db.example").and_then(|p| p.down), Some(true));
        assert_eq!(grpc_b.get("auth.authservice").and_then(|p| p.error_status_code).as_deref(), Some("UNAUTHENTICATED"));
    }

    #[test]
    fn chaos_types_use_distinct_backend_namespaces() {
        let f = fleet();
        let (svc, tcp, grpc) = (service(&f.a), tcp(&f.a), grpc(&f.a));
        svc.put("shared-key", http_profile(503), 0);
        tcp.put("shared-key", TcpChaosProfile { down: Some(true), ..Default::default() }, 0);
        grpc.put("shared-key", grpc_profile("INTERNAL", 1.0), 0);
        assert_eq!(svc.get("shared-key").and_then(|p| p.error_status), Some(503));
        assert_eq!(tcp.get("shared-key").and_then(|p| p.down), Some(true));
        assert_eq!(grpc.get("shared-key").and_then(|p| p.error_status_code).as_deref(), Some("INTERNAL"));
        for namespace in ["chaos-service", "chaos-tcp", "chaos-grpc"] {
            assert_eq!(f.b.crud_entities(namespace).size(), 1, "{namespace} holds its own entry on the other node");
        }
    }
}

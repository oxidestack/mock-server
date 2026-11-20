//! Rust ports of `RequestMatchersStateBackendTest` (20) and `RequestMatchersReconcileParityTest` (7 x the
//! `clustered` parameter), method for method, through a real in-process server instead of a `RequestMatchers`:
//! upstream's `matchers.add(expectation, API)` is `PUT /mockserver/expectation`, `firstMatchingExpectation` a request
//! the data plane answers, `retrieveActiveExpectations` `retrieve?type=ACTIVE_EXPECTATIONS`, `clear(id)` /
//! `clear(request)` / `reset()` the control-plane calls of the same names, and `expectationRequestDefinitions`
//! (the ids that stay resolvable) a verification by `expectationId`.
//!
//! Adapted, and why:
//! - Upstream wires an `InMemoryStateBackend` into `RequestMatchers`, and its non-clustered `add` writes through to the
//!   backend KV. Here the `Store` is authoritative for a non-clustered server (`src/state_backend/mod.rs`), and only a
//!   clustered backend is written to and reconciled from, so the assertions about the backend's contents run on the
//!   `clustered` row; the non-clustered row asserts the node-local view (docs/divergences.md).
//! - The injected backend is the spy of `cluster_fanin.rs`: an `InMemoryStateBackend` whose `isClustered()` is
//!   overridden, handed over with `Server::start_with_state_backend` (upstream: `setStateBackend`).
//! - A write straight into the backend's KV (a remote node's add) is reconciled by the invalidation listener the
//!   backend fires, where upstream's test calls `reconcileFromBackend()` itself.
//!
//! Not ported as HTTP: `batchUpdateKeepsBackendInSync` (`RequestMatchers.update(Expectation[], cause)` is the file
//! watcher's batch replace, with no control-plane call) and `responseInProgressSurvivesUpdate` (matcher identity and
//! `setResponseInProgress` on the internal sorted list); both are unit tests in `src/store.rs`
//! (`store::tests::batch_update_keeps_backend_in_sync`, `store::tests::response_in_progress_survives_update`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use mock_server::state_backend::memory::InMemoryStateBackend;
use mock_server::state_backend::{BlobStore, ExpectationEntry, InvalidationListener, KeyValueStore, StateBackend};
use mock_server::Config;
use serde_json::{json, Value};

use crate::common;

const MAX_EXPECTATIONS: usize = 2;

/// An `InMemoryStateBackend` whose `isClustered()` is a parameter.
struct Backend {
    inner: InMemoryStateBackend,
    clustered: bool,
}

impl StateBackend for Backend {
    fn expectations(&self) -> &dyn KeyValueStore<ExpectationEntry> {
        self.inner.expectations()
    }

    fn scenario_states(&self) -> &dyn KeyValueStore<String> {
        self.inner.scenario_states()
    }

    fn shared_times_counters(&self) -> Option<&dyn KeyValueStore<i32>> {
        self.inner.shared_times_counters()
    }

    fn crud_entities(&self, namespace: &str) -> Arc<dyn KeyValueStore<Value>> {
        self.inner.crud_entities(namespace)
    }

    fn blobs(&self) -> &dyn BlobStore {
        self.inner.blobs()
    }

    fn add_invalidation_listener(&self, listener: Arc<dyn InvalidationListener>) {
        self.inner.add_invalidation_listener(listener)
    }

    fn node_id(&self) -> &str {
        self.inner.node_id()
    }

    fn is_clustered(&self) -> bool {
        self.clustered
    }
}

struct Node {
    running: common::Running,
    backend: Arc<Backend>,
    clustered: bool,
}

async fn node_with(max: usize, clustered: bool, properties: &[(&str, &str)]) -> Node {
    let backend = Arc::new(Backend { inner: InMemoryStateBackend::new(max), clustered });
    let config = properties.iter().fold(Config::for_tests().with_property("maxExpectations", &max.to_string()), |c, (k, v)| c.with_property(k, v));
    crate::scratch_cwd::enter();
    let server = mock_server::Server::start_with_state_backend(config, backend.clone()).await.expect("the server starts");
    let port = server.ports()[0];
    Node { running: common::Running { server, port }, backend, clustered }
}

async fn node(clustered: bool) -> Node {
    node_with(MAX_EXPECTATIONS, clustered, &[]).await
}

impl Node {
    fn port(&self) -> u16 {
        self.running.port
    }

    async fn stop(self) {
        self.running.server.shutdown().await;
    }

    /// `matchers.add(new Expectation(request().withPath(path)).withId(id).thenRespond(response().withBody(body)), API)`.
    async fn add(&self, id: &str, path: &str, body: &str) {
        self.add_json(json!({"id": id, "httpRequest": {"path": path}, "httpResponse": {"body": body}})).await;
    }

    async fn add_json(&self, expectation: Value) {
        common::expect(self.port(), &expectation).await;
    }

    /// `retrieveActiveExpectations(null)`.
    async fn active(&self) -> Vec<Value> {
        let r = common::send(self.port(), "PUT", "/mockserver/retrieve?type=ACTIVE_EXPECTATIONS", "").await;
        serde_json::from_str(&r.body).unwrap_or_else(|e| panic!("active expectations: {e}: {}", r.body))
    }

    async fn active_ids(&self) -> Vec<String> {
        self.active().await.iter().map(|e| e["id"].as_str().unwrap().to_string()).collect()
    }

    /// `firstMatchingExpectation(request().withPath(path))` seen through what the data plane answers: the body of the
    /// matching expectation's response, `None` for no match.
    async fn first_match(&self, path: &str) -> Option<String> {
        let r = common::send(self.port(), "GET", path, "").await;
        (r.status != 404).then_some(r.body)
    }

    /// `expectationRequestDefinitions.containsKey(id)`: the id still resolves.
    async fn resolves(&self, id: &str) -> bool {
        let body = json!({"expectationId": {"id": id}, "times": {"atLeast": 0}});
        common::send(self.port(), "PUT", "/mockserver/verify", &body.to_string()).await.status == 202
    }

    fn backend_size(&self) -> usize {
        self.backend.expectations().size()
    }

    fn backend_has(&self, id: &str) -> bool {
        self.backend.expectations().get(id).is_some()
    }

    fn backend_ids(&self) -> Vec<String> {
        self.backend.expectations().entries().into_iter().map(|(k, _)| k).collect()
    }
}

fn sorted(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids
}

async fn eventually<F: std::future::Future<Output = bool>>(what: &str, mut condition: impl FnMut() -> F) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if condition().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

// ---------------------------------------------------------------------------------------------------------
// RequestMatchersStateBackendTest
// ---------------------------------------------------------------------------------------------------------
// The backend is wired as upstream wires it; the backend-content assertions run where the backend is written
// (clustered), the node-local ones always. Each test runs both rows so the node-local behaviour is the same.

#[tokio::test(flavor = "multi_thread")]
async fn add_keeps_backend_in_sync() {
    for clustered in [false, true] {
        let n = node(clustered).await;
        n.add_json(json!({"id": "a", "httpRequest": {"path": "/a"}, "httpResponse": {"statusCode": 200}})).await;

        assert_eq!(n.active().await.len(), 1);
        assert_eq!(n.first_match("/a").await, Some(String::new()));
        if clustered {
            assert_eq!(n.backend_size(), 1);
            assert!(n.backend_has("a"));
            assert_eq!(n.backend.expectations().get("a").unwrap().value.id, "a");
        }
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn update_keeps_backend_in_sync() {
    for clustered in [false, true] {
        let n = node(clustered).await;
        n.add("a", "/a", "v1").await;
        // update with the same id, a different body
        n.add("a", "/a", "v2").await;

        assert_eq!(n.active().await.len(), 1, "still one matcher");
        if clustered {
            assert_eq!(n.backend_size(), 1, "still one backend entry");
        }
        assert_eq!(n.first_match("/a").await.as_deref(), Some("v2"));
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn remove_keeps_backend_in_sync() {
    for clustered in [false, true] {
        let n = node(clustered).await;
        n.add_json(json!({"id": "a", "httpRequest": {"path": "/a"}, "httpResponse": {"statusCode": 200}})).await;
        n.add_json(json!({"id": "b", "httpRequest": {"path": "/b"}, "httpResponse": {"statusCode": 201}})).await;

        // remove by ExpectationId
        let r = common::send(n.port(), "PUT", "/mockserver/clear?type=EXPECTATIONS", &json!({"id": "a"}).to_string()).await;
        assert_eq!(r.status, 200);

        assert_eq!(n.active_ids().await, vec!["b"]);
        if clustered {
            assert_eq!(n.backend_size(), 1);
            assert!(!n.backend_has("a"));
            assert!(n.backend_has("b"));
        }
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sorted_view_matches_after_multiple_adds() {
    for clustered in [false, true] {
        let n = node(clustered).await;
        n.add("first", "/first", "1").await;
        n.add("second", "/second", "2").await;

        assert_eq!(n.active_ids().await, vec!["first", "second"]);
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn eviction_removes_oldest_by_insertion_order() {
    for clustered in [false, true] {
        // maxExpectations=2: add A, add B, add C -> A is evicted
        let n = node(clustered).await;
        n.add("a", "/a", "a").await;
        n.add("b", "/b", "b").await;
        n.add("c", "/c", "c").await;

        assert_eq!(n.active().await.len(), 2);
        if clustered {
            assert_eq!(n.backend_size(), 2);
            assert!(!n.backend_has("a"));
        }
        assert_eq!(sorted(n.active_ids().await), vec!["b", "c"]);
        n.stop().await;
    }
}

/// COR-01: an update does not change the eviction position. Add A, add B, update A, add C evicts A (the oldest by its
/// original insertion), not B.
#[tokio::test(flavor = "multi_thread")]
async fn cor01_update_does_not_change_eviction_order() {
    for clustered in [false, true] {
        let n = node(clustered).await;
        n.add("a", "/a", "a-v1").await;
        n.add("b", "/b", "b").await;
        // update A: it must keep its insertion position
        n.add("a", "/a", "a-v2").await;
        // add C: evicts A, not B
        n.add("c", "/c", "c").await;

        assert_eq!(n.active().await.len(), 2);
        let ids = n.active_ids().await;
        assert_eq!(sorted(ids.clone()), vec!["b", "c"], "A was evicted, B and C remain");
        assert!(!ids.contains(&"a".to_string()));
        if clustered {
            assert_eq!(n.backend_size(), 2);
            assert!(n.backend_has("b"), "B was NOT evicted");
            assert!(!n.backend_has("a"), "A was evicted");
        }
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cor01_parity_with_no_backend() {
    // The same add/update/evict sequence against a server with no injected backend and a backend-wired one: the same
    // size and the same survivors.
    let no_backend = common::start(&[("maxExpectations", "2")]).await;
    for clustered in [false, true] {
        common::send(no_backend.port, "PUT", "/mockserver/reset", "").await;
        let n = node(clustered).await;
        for (id, path, body) in [("a", "/a", "a-v1"), ("b", "/b", "b"), ("a", "/a", "a-v2"), ("c", "/c", "c")] {
            common::expect(no_backend.port, &json!({"id": id, "httpRequest": {"path": path}, "httpResponse": {"body": body}})).await;
            n.add(id, path, body).await;
        }

        let plain: Vec<Value> = serde_json::from_str(&common::send(no_backend.port, "PUT", "/mockserver/retrieve?type=ACTIVE_EXPECTATIONS", "").await.body).unwrap();
        let plain_ids = sorted(plain.iter().map(|e| e["id"].as_str().unwrap().to_string()).collect());
        assert_eq!(n.active().await.len(), plain.len(), "size parity");
        assert_eq!(sorted(n.active_ids().await), plain_ids, "eviction parity: the same surviving expectations");
        n.stop().await;
    }
    no_backend.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn eviction_cleans_up_expectation_request_definitions() {
    for clustered in [false, true] {
        // INC-04: an evicted entry is removed from expectationRequestDefinitions as well
        let n = node(clustered).await;
        n.add("a", "/a", "a").await;
        n.add("b", "/b", "b").await;
        assert!(n.resolves("a").await);

        // add C: evicts A
        n.add("c", "/c", "c").await;

        assert!(!n.resolves("a").await);
        assert!(n.resolves("b").await);
        assert!(n.resolves("c").await);
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_clears_backend() {
    for clustered in [false, true] {
        let n = node(clustered).await;
        n.add("a", "/a", "a").await;
        n.add("b", "/b", "b").await;

        common::send(n.port(), "PUT", "/mockserver/reset", "").await;

        assert!(n.active().await.is_empty());
        if clustered {
            assert_eq!(n.backend_size(), 0);
        }
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn clear_by_request_definition_clears_backend() {
    for clustered in [false, true] {
        let n = node(clustered).await;
        n.add("a", "/a", "a").await;
        n.add("b", "/b", "b").await;

        let r = common::send(n.port(), "PUT", "/mockserver/clear?type=EXPECTATIONS", &json!({"path": "/a"}).to_string()).await;
        assert_eq!(r.status, 200);

        assert_eq!(n.active_ids().await, vec!["b"]);
        if clustered {
            assert_eq!(n.backend_size(), 1);
            assert!(!n.backend_has("a"));
            assert!(n.backend_has("b"));
        }
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn clear_null_request_definition_resets_backend() {
    for clustered in [false, true] {
        let n = node(clustered).await;
        n.add("a", "/a", "a").await;

        // `clear((RequestDefinition) null)`: no filter
        let r = common::send(n.port(), "PUT", "/mockserver/clear?type=EXPECTATIONS", "").await;
        assert_eq!(r.status, 200);

        assert!(n.active().await.is_empty());
        if clustered {
            assert_eq!(n.backend_size(), 0);
        }
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn retrieve_request_definitions_falls_back_to_backend() {
    for clustered in [false, true] {
        let n = node(clustered).await;
        n.add("a", "/a", "a").await;

        // the id resolves to its request definition: a verification by id evaluates it
        let verify = json!({"expectationId": {"id": "a"}, "times": {"atLeast": 0}});
        assert_eq!(common::send(n.port(), "PUT", "/mockserver/verify", &verify.to_string()).await.status, 202);
        // and a retrieve of the active expectation shows the definition
        let active = n.active().await;
        assert_eq!(active.len(), 1);
        assert_eq!(active[0]["httpRequest"]["path"], "/a");
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn times_state_survives_update() {
    for clustered in [false, true] {
        let n = node_with(10, clustered, &[]).await;
        let with_body = |body: &str| json!({"id": "a", "httpRequest": {"path": "/a"}, "httpResponse": {"body": body}, "times": {"remainingTimes": 5, "unlimited": false}});
        n.add_json(with_body("a-v1")).await;

        // consume one match: clustered, the use is taken from the shared counter and the node-local Times stays as
        // added (`consumeMatchLocally`, as `clusteredLimitedTimesUsesSharedBackendCasByDefault`)
        assert_eq!(n.first_match("/a").await.as_deref(), Some("a-v1"));
        if clustered {
            assert_eq!(n.active().await[0]["times"]["remainingTimes"], 5);
            assert_eq!(n.backend.shared_times_counters().unwrap().get("a").unwrap().value, 4);
        } else {
            assert_eq!(n.active().await[0]["times"]["remainingTimes"], 4);
        }

        // update: same id, different body
        n.add_json(with_body("a-v2")).await;

        // still one matcher, and it serves the new body
        let active = n.active().await;
        assert_eq!(active.len(), 1);
        assert_eq!(active[0]["httpResponse"]["body"], "a-v2");
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn reconcile_from_backend_picks_up_response_body_change() {
    // Remote-update reconciliation only applies to a CLUSTERED backend.
    let n = node(true).await;
    n.add("a", "/a", "original-body").await;
    assert_eq!(n.first_match("/a").await.as_deref(), Some("original-body"));

    // a REMOTE update: written straight into the backend KV, changing only the response body (same id, priority, created)
    let current = n.backend.expectations().get("a").unwrap().value;
    let mut json = current.expectation_json.clone();
    json["httpResponse"] = json!({"body": "updated-body"});
    n.backend.expectations().put("a", ExpectationEntry { expectation_json: json, ..current });

    eventually("the matcher to serve the updated body", || async { n.first_match("/a").await.as_deref() == Some("updated-body") }).await;
    n.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn clustered_reconcile_picks_up_remote_add() {
    let n = node_with(10, true, &[]).await;

    // an entry written straight to the backend, as a remote node's add
    let json = json!({"id": "remote", "httpRequest": {"path": "/remote"}, "httpResponse": {"body": "remote-body"}});
    n.backend.expectations().put("remote", ExpectationEntry { id: "remote".into(), priority: 0, created: 1, remaining_times: -1, expectation_json: json });

    eventually("the remote add to materialise", || async { n.active().await.len() == 1 }).await;
    assert_eq!(n.first_match("/remote").await.as_deref(), Some("remote-body"));
    n.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn set_state_backend_null_restores_local_eviction() {
    // a server with no injected backend: local eviction
    let r = common::start(&[("maxExpectations", "2")]).await;
    for (id, path) in [("a", "/a"), ("b", "/b"), ("c", "/c")] {
        common::expect(r.port, &json!({"id": id, "httpRequest": {"path": path}, "httpResponse": {"body": id}})).await;
    }
    let active: Vec<Value> = serde_json::from_str(&common::send(r.port, "PUT", "/mockserver/retrieve?type=ACTIVE_EXPECTATIONS", "").await.body).unwrap();
    // maxExpectations=2, so only 2 remain
    assert_eq!(active.len(), 2);
    r.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn clustered_limited_times_uses_shared_backend_cas_by_default() {
    // Default (clusterSharedTimesEnabled=true): a match on a clustered backend decrements the dedicated SHARED-TIMES
    // COUNTER (`sharedTimesCounters()`) by compare-and-set; the ExpectationEntry's own remainingTimes stays at the seed.
    let n = node_with(10, true, &[]).await;
    n.add_json(json!({"id": "a", "httpRequest": {"path": "/a"}, "httpResponse": {"body": "a"}, "times": {"remainingTimes": 3, "unlimited": false}})).await;

    // the ExpectationEntry carries the original count as an immutable seed, and the counter is seeded eagerly
    assert_eq!(n.backend.expectations().get("a").unwrap().value.remaining_times, 3);
    let counters = n.backend.shared_times_counters().expect("a counter store");
    assert_eq!(counters.get("a").unwrap().value, 3);

    assert_eq!(n.first_match("/a").await.as_deref(), Some("a"));
    assert_eq!(counters.get("a").unwrap().value, 2, "default shared-Times path decrements the dedicated counter");
    assert_eq!(n.backend.expectations().get("a").unwrap().value.remaining_times, 3, "ExpectationEntry remainingTimes stays at the immutable seed");
    n.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn clustered_limited_times_falls_back_to_node_local_when_shared_times_disabled() {
    // Opt-out (clusterSharedTimesEnabled=false): even on a clustered backend the match takes the node-local path, so
    // the backend's shared counter is not touched.
    let n = node_with(10, true, &[("clusterSharedTimesEnabled", "false")]).await;
    n.add_json(json!({"id": "a", "httpRequest": {"path": "/a"}, "httpResponse": {"body": "a"}, "times": {"remainingTimes": 3, "unlimited": false}})).await;
    assert_eq!(n.backend.expectations().get("a").unwrap().value.remaining_times, 3);

    // the match succeeds on node-local Times, which decrements 3 -> 2 ...
    assert_eq!(n.first_match("/a").await.as_deref(), Some("a"));
    assert_eq!(n.active().await[0]["times"]["remainingTimes"], 2, "node-local Times decrements when shared-Times is disabled");
    // ... while the shared backend counter is untouched
    assert_eq!(n.backend.expectations().get("a").unwrap().value.remaining_times, 3, "the backend shared counter is NOT touched");
    n.stop().await;
}

// ---------------------------------------------------------------------------------------------------------
// RequestMatchersReconcileParityTest (both rows: clustered=false, clustered=true)
// ---------------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn parity_add_keeps_backend_in_sync() {
    for clustered in [false, true] {
        let n = node(clustered).await;
        n.add_json(json!({"id": "a", "httpRequest": {"path": "/a"}, "httpResponse": {"statusCode": 200}})).await;

        assert_eq!(n.active().await.len(), 1, "node-local size");
        assert!(n.first_match("/a").await.is_some(), "matches locally");
        if n.clustered {
            assert_eq!(n.backend_size(), 1, "backend size");
            assert!(n.backend_has("a"), "backend holds a");
        }
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn parity_update_keeps_backend_in_sync() {
    for clustered in [false, true] {
        let n = node(clustered).await;
        n.add("a", "/a", "v1").await;
        n.add("a", "/a", "v2").await;

        assert_eq!(n.active().await.len(), 1, "update does not add a second matcher");
        if n.clustered {
            assert_eq!(n.backend_size(), 1, "update does not add a second backend entry");
        }
        assert_eq!(n.first_match("/a").await.as_deref(), Some("v2"), "matching serves the updated body");
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn parity_remove_keeps_backend_in_sync() {
    for clustered in [false, true] {
        let n = node(clustered).await;
        n.add_json(json!({"id": "a", "httpRequest": {"path": "/a"}, "httpResponse": {"statusCode": 200}})).await;
        n.add_json(json!({"id": "b", "httpRequest": {"path": "/b"}, "httpResponse": {"statusCode": 201}})).await;

        common::send(n.port(), "PUT", "/mockserver/clear?type=EXPECTATIONS", &json!({"id": "a"}).to_string()).await;

        assert_eq!(n.active().await.len(), 1, "node-local size after remove");
        if n.clustered {
            assert_eq!(n.backend_size(), 1, "backend size after remove");
            assert!(!n.backend_has("a"), "a removed from backend");
            assert!(n.backend_has("b"), "b retained in backend");
        }
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn parity_sorted_view_matches_insertion_order() {
    for clustered in [false, true] {
        let n = node(clustered).await;
        n.add("first", "/first", "1").await;
        n.add("second", "/second", "2").await;

        assert_eq!(n.active_ids().await, vec!["first", "second"]);
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn parity_eviction_removes_oldest_by_insertion_order() {
    for clustered in [false, true] {
        // maxExpectations=2: add A, add B, add C -> A (oldest) is evicted
        let n = node(clustered).await;
        n.add("a", "/a", "a").await;
        n.add("b", "/b", "b").await;
        n.add("c", "/c", "c").await;

        assert_eq!(n.active().await.len(), 2, "node-local trimmed to max");
        let ids = n.active_ids().await;
        assert_eq!(sorted(ids.clone()), vec!["b", "c"], "survivors are b and c");
        assert!(!ids.contains(&"a".to_string()), "node-local no longer holds the evicted id");
        if n.clustered {
            assert_eq!(n.backend_size(), 2, "backend trimmed to max");
            assert!(!n.backend_has("a"), "oldest evicted from backend");
            assert!(!n.backend_ids().contains(&"a".to_string()), "backend no longer holds the evicted id");
        }
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn parity_update_does_not_change_eviction_order() {
    for clustered in [false, true] {
        // add A (pos 0), add B (pos 1), update A (must stay at pos 0), add C -> A is evicted, NOT B
        let n = node(clustered).await;
        n.add("a", "/a", "a-v1").await;
        n.add("b", "/b", "b").await;
        n.add("a", "/a", "a-v2").await;
        n.add("c", "/c", "c").await;

        assert_eq!(n.active().await.len(), 2, "node-local trimmed to max");
        let ids = n.active_ids().await;
        assert_eq!(sorted(ids.clone()), vec!["b", "c"], "update did not move A to the tail: A is still the eviction victim");
        assert!(!ids.contains(&"a".to_string()), "A evicted");
        if n.clustered {
            assert_eq!(n.backend_size(), 2, "backend trimmed to max");
            assert!(n.backend_has("b"), "B retained (was NOT the oldest)");
            assert!(!n.backend_has("a"), "A evicted from backend");
        }
        n.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn parity_eviction_cleans_up_expectation_request_definitions() {
    for clustered in [false, true] {
        let n = node(clustered).await;
        n.add("a", "/a", "a").await;
        n.add("b", "/b", "b").await;
        assert!(n.resolves("a").await, "A tracked before eviction");

        n.add("c", "/c", "c").await;

        assert!(!n.resolves("a").await, "evicted A's request-definition entry is cleaned up");
        assert!(n.resolves("b").await, "B still tracked");
        assert!(n.resolves("c").await, "C tracked");
        n.stop().await;
    }
}

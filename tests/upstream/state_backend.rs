//! `mockserver.stateBackend=infinispan` in LOCAL mode (`clusterEnabled` unset/`false`) boots a
//! server that behaves identically to `stateBackend=memory` from the client's point of view — the acceptance
//! criterion, proved at the real HTTP seam rather than against the SPI directly (`src/state_backend/`'s own
//! `#[cfg(test)]` units, run by `cargo test --lib`, prove the SPI's contract: `KeyValueStoreContract`-shaped
//! cases in `memory.rs`, the ported `InfinispanStateBackendTest` in `infinispan.rs`, and `resolve`'s
//! config-resolution matrix in `mod.rs`).
//!
//! This is also the in-process counterpart of `docker_variant_smoke_clustered`
//! (`conformance/containers/cases/docker_variant_smoke_clustered/`): that container case boots our image with
//! `MOCKSERVER_STATE_BACKEND=infinispan` and checks `PUT /mockserver/status` answers 200; this file boots the
//! same configuration in-process and goes further (expectations and scenario-state transitions round-trip).
//!
//! `InfinispanStateBackendRegistrarTest` (2 `@Test`, reflective classpath discovery) has no counterpart here —
//! documented not-applicable in `src/state_backend/infinispan.rs`'s own test module doc.
//! The clustered mode's own port suite is `cluster_state_backend.rs`.

use serde_json::json;

use crate::common;

/// `stateBackend=infinispan`, LOCAL mode: an expectation created and matched exactly as under `memory`.
#[tokio::test]
async fn infinispan_local_mode_serves_expectations_like_memory() {
    let running = common::start(&[("stateBackend", "infinispan")]).await;
    common::expect(
        running.port,
        &json!({
            "httpRequest": {"path": "/state-backend-140"},
            "httpResponse": {"statusCode": 200, "body": "ok"},
        }),
    )
    .await;
    let r = common::send(running.port, "GET", "/state-backend-140", "").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, "ok");
}

/// `stateBackend=infinispan`, LOCAL mode: scenario-state gating and transition (`scenarioName`/`scenarioState`/
/// `newScenarioState`) work exactly as under `memory` — the clearest client-visible proof that
/// `scenarioStates` (the second of the three caches) round-trips correctly.
#[tokio::test]
async fn infinispan_local_mode_serves_scenario_state_transitions_like_memory() {
    let running = common::start(&[("stateBackend", "infinispan")]).await;
    common::expect(
        running.port,
        &json!({
            "httpRequest": {"path": "/cart"},
            "httpResponse": {"body": "empty"},
            "scenarioName": "checkout-140",
            "scenarioState": "Started",
            "newScenarioState": "Filled",
        }),
    )
    .await;
    common::expect(
        running.port,
        &json!({
            "httpRequest": {"path": "/cart"},
            "httpResponse": {"body": "one item"},
            "scenarioName": "checkout-140",
            "scenarioState": "Filled",
        }),
    )
    .await;

    let first = common::send(running.port, "GET", "/cart", "").await;
    assert_eq!(first.body, "empty", "starts in the scenario's initial state");
    let second = common::send(running.port, "GET", "/cart", "").await;
    assert_eq!(second.body, "one item", "the first match transitioned the scenario to Filled");
}

/// `stateBackend=infinispan` with `clusterEnabled=true`: the server joins its cluster before it binds
/// a port, answers, and leaves the cluster when it stops. (An earlier version rejected this combination at startup.)
#[tokio::test(flavor = "multi_thread")]
async fn infinispan_clustered_mode_starts_serves_and_stops() {
    let cluster = format!("state-backend-156-{}", std::process::id());
    let running = common::start(&[("stateBackend", "infinispan"), ("clusterEnabled", "true"), ("clusterName", cluster.as_str())]).await;
    let status = common::send(running.port, "PUT", "/mockserver/status", "").await;
    assert_eq!(status.status, 200, "{}", status.body);
    running.server.shutdown().await;
}

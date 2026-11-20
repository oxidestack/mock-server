//! One configuration for the whole server: upstream's fix 0e8566814 ("share one Configuration so runtime
//! PUTs reach enforcement on the CLI path") and 62930129c, adopted ahead of the oracle. The 8.0.0 server
//! process held two `Configuration`s, so `PUT /mockserver/configuration` and `PUT /mockserver/mode` each reached only
//! some readers; these tests pass on upstream only in the test's JVM, where one instance is shared, and here over the
//! wire.
//!
//! - `OperatingModeDataPlaneIntegrationTest`: both methods
//! - `ConfigurationRestApiEnforcementIntegrationTest`: `shouldEnforceRedactSecretsInLogSetOverTheConfigurationEndpoint`,
//!   `shouldEnforceWasmEnabledSetOverTheConfigurationEndpoint`
//! - `RuntimeConfigurationEveryConstructionPathIntegrationTest` (added with the fix, after 8.0.0): runtime control-plane
//!   mTLS, event-log shrink, redaction and `globalResponseDelayMillis`, over the one construction shape a process has
//!   (its runtime `proxyRemoteHost` case is not ported: the 8.0.0 oracle honours that `PUT` too, and mock-server
//!   does not yet — a divergence from the oracle itself, outside this fix)

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::common;

/// One request with `headers` and a raw `body` on its own connection; the status and the body.
async fn send(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: Vec<u8>) -> (u16, String) {
    let mut head = format!("{method} {path} HTTP/1.1\r\n");
    if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
        head.push_str(&format!("Host: 127.0.0.1:{port}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n", body.len()));
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    tokio::task::spawn_blocking(move || {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        s.write_all(head.as_bytes()).unwrap();
        s.write_all(&body).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        (head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0), body.to_string())
    })
    .await
    .unwrap()
}

/// `applyConfiguration`: `PUT /mockserver/configuration`, accepted.
async fn apply_configuration(port: u16, json: &str) {
    let r = common::send(port, "PUT", "/mockserver/configuration", json).await;
    assert!(r.status < 300, "PUT /mockserver/configuration should be accepted, body: {}", r.body);
}

/// `retrieveRecordedExpectations(request().withPath(path))`.
async fn recorded_expectations(port: u16, path: &str) -> Vec<Value> {
    let r = common::send(port, "PUT", "/mockserver/retrieve?type=RECORDED_EXPECTATIONS&format=JSON", &json!({"path": path}).to_string()).await;
    assert_eq!(r.status, 200, "{}", r.body);
    serde_json::from_str::<Value>(&r.body).unwrap().as_array().cloned().unwrap_or_default()
}

/// `retrieve?type=REQUESTS&format=JSON`.
async fn recorded_requests(port: u16) -> String {
    common::send(port, "PUT", "/mockserver/retrieve?type=REQUESTS&format=JSON", "").await.body
}

// --- OperatingModeDataPlaneIntegrationTest --------------------------------------------------------------------------

/// `assertModeDrivesProxyAndRecord`: an unmatched request with the upstream's `Host` is a 404 in SIMULATE and is
/// proxied and recorded once `mode` is set.
async fn assert_mode_drives_proxy_and_record(mode: &str, path: &str, upstream_body: &str) {
    let upstream = common::start(&[]).await;
    let mode_server = common::start(&[]).await;
    // `resetServers`: reset does not reset the operating mode, so the test starts from SIMULATE
    assert_eq!(common::send(mode_server.port, "PUT", "/mockserver/mode?mode=SIMULATE", "").await.status, 200);
    common::expect(upstream.port, &json!({"httpRequest": {"path": path}, "httpResponse": {"body": upstream_body}})).await;
    let upstream_host = format!("localhost:{}", upstream.port);

    // baseline - in SIMULATE mode the unmatched request is not proxied
    let (status, body) = send(mode_server.port, "GET", path, &[("Host", &upstream_host)], Vec::new()).await;
    assert_eq!(status, 404, "unmatched request in SIMULATE mode should return 404 (not proxied): {body}");
    assert!(!body.contains(upstream_body), "unmatched request in SIMULATE mode should NOT return the upstream body");
    assert_eq!(recorded_expectations(mode_server.port, path).await.len(), 0, "no exchange should be recorded in SIMULATE mode");

    // when - the server is switched to the proxying mode and the same unmatched request is sent
    assert_eq!(common::send(mode_server.port, "PUT", &format!("/mockserver/mode?mode={mode}"), "").await.status, 200);
    let (status, body) = send(mode_server.port, "GET", path, &[("Host", &upstream_host)], Vec::new()).await;
    assert_eq!(status, 200, "unmatched request in {mode} mode should be proxied: {body}");
    assert!(body.contains(upstream_body), "unmatched request in {mode} mode should return the upstream body: {body}");

    // and - the proxied exchange is recorded and retrievable as exactly one expectation
    let deadline = Instant::now() + Duration::from_secs(5);
    let recorded = loop {
        let recorded = recorded_expectations(mode_server.port, path).await;
        if !recorded.is_empty() || Instant::now() > deadline {
            break recorded;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(recorded.len(), 1, "exactly one recorded expectation should exist for {path} in {mode} mode: {recorded:?}");
    assert_eq!(recorded[0]["httpRequest"]["path"], json!(path));
    mode_server.server.shutdown().await;
    upstream.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_proxy_and_record_unmatched_request_in_spy_mode() {
    assert_mode_drives_proxy_and_record("SPY", "/spy-unmatched", "spy-upstream-body").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_proxy_and_record_unmatched_request_in_capture_mode() {
    assert_mode_drives_proxy_and_record("CAPTURE", "/capture-unmatched", "capture-upstream-body").await;
}

// --- ConfigurationRestApiEnforcementIntegrationTest -----------------------------------------------------------------

const SENSITIVE_CREDENTIAL: &str = "Bearer super-secret-token-value";

#[tokio::test(flavor = "multi_thread")]
async fn should_enforce_redact_secrets_in_log_set_over_the_configuration_endpoint() {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"method": "POST", "path": "/redaction-probe"}, "httpResponse": {"statusCode": 200, "body": "ok"}})).await;
    // BEFORE: with redaction off (the default) the credential is retrievable verbatim
    let (status, _) = send(server.port, "POST", "/redaction-probe", &[("Authorization", SENSITIVE_CREDENTIAL)], b"{}".to_vec()).await;
    assert_eq!(status, 200);
    assert!(recorded_requests(server.port).await.contains(SENSITIVE_CREDENTIAL), "baseline: the Authorization value is retrievable verbatim");
    // enable redaction over the REST control plane only
    apply_configuration(server.port, r#"{"redactSecretsInLog": true}"#).await;
    // AFTER: a newly recorded request renders with the credential masked
    let (status, _) = send(server.port, "POST", "/redaction-probe", &[("Authorization", SENSITIVE_CREDENTIAL)], b"{}".to_vec()).await;
    assert_eq!(status, 200);
    let after = recorded_requests(server.port).await;
    assert!(!after.contains(SENSITIVE_CREDENTIAL), "redactSecretsInLog=true set via PUT must mask the Authorization header: {after}");
    assert!(after.contains("***REDACTED***"), "{after}");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_enforce_wasm_enabled_set_over_the_configuration_endpoint() {
    // start with WASM on so the module can be uploaded and the expectation can match
    let server = common::start(&[("wasmEnabled", "true")]).await;
    let module = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/wasm/match-request.wasm")).unwrap();
    let (status, body) = send(server.port, "PUT", "/mockserver/wasm/modules?name=orders", &[], module).await;
    assert_eq!(status, 201, "WASM module upload should succeed while wasmEnabled=true: {body}");
    // the module matches POST /orders carrying header X-Tenant: acme
    common::expect(server.port, &json!({
        "httpRequest": {"method": "POST", "path": "/orders", "body": {"type": "WASM", "moduleName": "orders"}},
        "httpResponse": {"statusCode": 200, "body": "wasm-matched"}
    }))
    .await;
    // BEFORE: the WASM-matched expectation matches
    let (status, body) = send(server.port, "POST", "/orders", &[("X-Tenant", "acme")], b"{}".to_vec()).await;
    assert_eq!(status, 200, "baseline: the WASM-matched expectation should match while wasmEnabled=true");
    assert!(body.contains("wasm-matched"), "{body}");
    // disable WASM over the REST control plane only
    apply_configuration(server.port, r#"{"wasmEnabled": false}"#).await;
    // AFTER: the matcher consults the configuration per match attempt, so it stops matching
    let (status, _) = send(server.port, "POST", "/orders", &[("X-Tenant", "acme")], b"{}".to_vec()).await;
    assert_ne!(status, 200, "wasmEnabled=false set via PUT must stop the WASM-matched expectation from matching");
    // and the upload gate follows a runtime enable too (on the 8.0.0 process it kept its startup value)
    let off = common::start(&[]).await;
    apply_configuration(off.port, r#"{"wasmEnabled": true}"#).await;
    let module = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/wasm/match-request.wasm")).unwrap();
    let (status, body) = send(off.port, "PUT", "/mockserver/wasm/modules?name=orders", &[], module).await;
    assert_eq!(status, 201, "a runtime wasmEnabled=true opens the upload: {body}");
    off.server.shutdown().await;
    server.server.shutdown().await;
}

// --- RuntimeConfigurationEveryConstructionPathIntegrationTest (upstream 62930129c) ----------------------------------

fn probe_expectation(path: &str) -> Value {
    json!({"httpRequest": {"path": path}, "httpResponse": {"statusCode": 200, "body": "ok"}})
}

#[tokio::test(flavor = "multi_thread")]
async fn a_runtime_put_cannot_enable_control_plane_mutual_tls() {
    let server = common::start(&[]).await;
    assert_eq!(common::send(server.port, "PUT", "/mockserver/clear", "").await.status, 200, "baseline: the control plane is open by default");
    // `aRuntimePutCannotEnableControlPlaneMutualTls` (9.2.0): control-plane mTLS is fixed at startup, so the PUT is
    // ignored and the value in force is enforced and reported
    let chain = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/auth/mtls-control-plane-ca-cert.pem");
    let r = common::send(server.port, "PUT", "/mockserver/configuration", &json!({"controlPlaneTLSMutualAuthenticationRequired": true, "controlPlaneTLSMutualAuthenticationCAChain": chain}).to_string()).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(serde_json::from_str::<Value>(&r.body).unwrap()["controlPlaneTLSMutualAuthenticationRequired"], json!(false));
    assert_eq!(common::send(server.port, "PUT", "/mockserver/clear", "").await.status, 200, "the control plane keeps the authentication it started with");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shrinking_the_event_log_at_runtime_must_evict() {
    let server = common::start(&[]).await;
    common::expect(server.port, &probe_expectation("/log-probe")).await;
    let body = "x".repeat(500);
    for _ in 0..40 {
        assert_eq!(common::send(server.port, "POST", "/log-probe", &body).await.status, 200);
    }
    let count = |text: String| serde_json::from_str::<Value>(&text).unwrap().as_array().map_or(0, Vec::len);
    assert!(count(recorded_requests(server.port).await) >= 40, "baseline: all 40 probes are retained under the startup limits");
    apply_configuration(server.port, r#"{"maxEventLogSizeInBytes": 5000, "maxLogEntries": 10}"#).await;
    let retained = count(recorded_requests(server.port).await);
    assert!(retained <= 10, "retrieval must see the evicted log, not the startup-sized one: {retained}");
    // and the budget holds for what comes next
    for _ in 0..20 {
        assert_eq!(common::send(server.port, "POST", "/log-probe", &body).await.status, 200);
    }
    let retained = count(recorded_requests(server.port).await);
    assert!(retained <= 10, "{retained}");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn enabling_secret_redaction_at_runtime_must_mask_credentials_in_the_retrieved_log() {
    let server = common::start(&[]).await;
    common::expect(server.port, &probe_expectation("/redaction-probe")).await;
    let (status, _) = send(server.port, "POST", "/redaction-probe", &[("Authorization", SENSITIVE_CREDENTIAL)], b"{}".to_vec()).await;
    assert_eq!(status, 200);
    assert!(recorded_requests(server.port).await.contains(SENSITIVE_CREDENTIAL), "baseline: the credential is retrievable verbatim");
    apply_configuration(server.port, r#"{"redactSecretsInLog": true}"#).await;
    // the entry recorded before the change is masked too: redaction applies when the log is rendered
    let retrieved = recorded_requests(server.port).await;
    assert!(!retrieved.contains(SENSITIVE_CREDENTIAL), "redactSecretsInLog=true set at runtime must mask the recorded credential: {retrieved}");
    assert!(retrieved.contains("***REDACTED***"), "{retrieved}");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_runtime_global_response_delay_must_delay_a_mocked_response() {
    const RUNTIME_DELAY_MILLIS: u64 = 750;
    let server = common::start(&[]).await;
    common::expect(server.port, &probe_expectation("/delay-probe")).await;
    apply_configuration(server.port, &format!(r#"{{"globalResponseDelayMillis": {RUNTIME_DELAY_MILLIS}}}"#)).await;
    let start = Instant::now();
    assert_eq!(common::send(server.port, "GET", "/delay-probe", "").await.status, 200);
    assert!(start.elapsed() >= Duration::from_millis(RUNTIME_DELAY_MILLIS), "the runtime globalResponseDelayMillis must apply: {:?}", start.elapsed());
    server.server.shutdown().await;
}

// --- the rest of the one-configuration contract, checked against the snapshot image of upstream master -------------

#[tokio::test(flavor = "multi_thread")]
async fn the_mode_and_the_proxy_flag_are_one_value() {
    let server = common::start(&[]).await;
    let mode = |body: String| serde_json::from_str::<Value>(&body).unwrap()["mode"].clone();
    assert_eq!(common::send(server.port, "PUT", "/mockserver/mode?mode=SIMULATE", "").await.status, 200);
    let configuration: Value = serde_json::from_str(&common::send(server.port, "GET", "/mockserver/configuration", "").await.body).unwrap();
    assert_eq!(configuration["attemptToProxyIfNoMatchingExpectation"], json!(false), "the mode writes the flag GET /configuration reports");
    assert_eq!(common::send(server.port, "PUT", "/mockserver/mode?mode=CAPTURE", "").await.status, 200);
    apply_configuration(server.port, r#"{"attemptToProxyIfNoMatchingExpectation": false}"#).await;
    assert_eq!(mode(common::send(server.port, "GET", "/mockserver/mode", "").await.body), json!("SIMULATE"), "the flag decides the mode reported");
    apply_configuration(server.port, r#"{"attemptToProxyIfNoMatchingExpectation": true}"#).await;
    assert_eq!(mode(common::send(server.port, "GET", "/mockserver/mode", "").await.body), json!("CAPTURE"), "the mode last set, once it agrees with the flag again");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn capacities_and_init_only_properties_follow_an_update() {
    let server = common::start(&[]).await;
    // maxExpectations: a shrink evicts the oldest at once
    for i in 0..5 {
        common::expect(server.port, &probe_expectation(&format!("/e{i}"))).await;
    }
    apply_configuration(server.port, r#"{"maxExpectations": 2}"#).await;
    let active: Value = serde_json::from_str(&common::send(server.port, "PUT", "/mockserver/retrieve?type=ACTIVE_EXPECTATIONS&format=JSON", "").await.body).unwrap();
    let paths: Vec<&Value> = active.as_array().unwrap().iter().map(|e| &e["httpRequest"]["path"]).collect();
    assert_eq!(paths, vec![&json!("/e3"), &json!("/e4")]);
    // ringBufferSize is init-only: the value in force is kept and the update is warned about
    let before: Value = serde_json::from_str(&common::send(server.port, "GET", "/mockserver/configuration", "").await.body).unwrap();
    let answer = common::send(server.port, "PUT", "/mockserver/configuration", r#"{"ringBufferSize": 64}"#).await;
    let answer: Value = serde_json::from_str(&answer.body).unwrap();
    assert_eq!(answer["ringBufferSize"], before["ringBufferSize"]);
    let logs = common::logs(server.port).await;
    assert!(logs.contains(&format!("ringBufferSize is fixed at startup and cannot be changed on a running server (the log event ring buffer is a fixed-size array allocated when the server started) - the supplied value 64 has been IGNORED and ringBufferSize remains {}", before["ringBufferSize"])), "{logs}");
    // maxLoggedBodyBytes: the next entries are cut
    apply_configuration(server.port, r#"{"maxLoggedBodyBytes": 5}"#).await;
    common::send(server.port, "POST", "/cut", "0123456789abcdef").await;
    let requests: Value = serde_json::from_str(&recorded_requests(server.port).await).unwrap();
    let cut = requests.as_array().unwrap().iter().find(|r| r["path"] == json!("/cut")).unwrap();
    assert_eq!(cut["body"], json!({"type": "BINARY", "base64Bytes": "MDEyMzQ="}), "{cut}");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn match_exact_case_follows_an_update_and_control_plane_jwt_does_not() {
    let server = common::start(&[]).await;
    common::expect(server.port, &probe_expectation("/Before")).await;
    apply_configuration(server.port, r#"{"matchExactCase": true}"#).await;
    common::expect(server.port, &probe_expectation("/After")).await;
    // read when an expectation is compiled: the one created before the change still ignores case
    assert_eq!(common::send(server.port, "GET", "/before", "").await.status, 200);
    assert_eq!(common::send(server.port, "GET", "/after", "").await.status, 404);
    // 9.2.0 (`ControlPlaneAuthenticationRuntimePutTest.aPutCannotSwitchControlPlaneAuthenticationOn`): control-plane JWT
    // settings are fixed at startup, so the PUT is ignored and the control plane stays open
    apply_configuration(server.port, r#"{"controlPlaneJWTAuthenticationRequired": true}"#).await;
    assert_eq!(common::send(server.port, "PUT", "/mockserver/clear", "").await.status, 200);
    server.server.shutdown().await;
}

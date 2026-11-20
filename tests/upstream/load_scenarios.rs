//! `LoadScenarioIntegrationTest`'s case that changes `ConfigurationProperties` in the test JVM after the server
//! started: here `Server::set_property`.

use crate::common;

#[tokio::test(flavor = "multi_thread")]
async fn load_allowed_but_start_returns403_when_disabled() {
    let target = common::start(&[]).await;
    let driver = common::start(&[("loadGenerationEnabled", "true")]).await;
    driver.server.set_property("loadGenerationEnabled", "false");
    let scenario = serde_json::json!({
        "name": "disabled",
        "profile": {"stages": [{"type": "VU", "vus": 1, "durationMillis": 1000}]},
        "steps": [{"request": {"path": "/x", "socketAddress": {"host": "localhost", "port": target.port, "scheme": "HTTP"}}}],
    });
    // Loading is allowed even when generation is disabled…
    let put = common::send(driver.port, "PUT", "/mockserver/loadScenario", &scenario.to_string()).await;
    assert_eq!(put.status, 200, "{}", put.body);
    // …but triggering a start is forbidden.
    let start = common::send(driver.port, "PUT", "/mockserver/loadScenario/start", r#"{ "name": "disabled" }"#).await;
    assert_eq!(start.status, 403, "{}", start.body);
    driver.server.shutdown().await;
    target.server.shutdown().await;
}

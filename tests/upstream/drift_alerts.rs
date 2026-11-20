//! `DriftAlertNotifierTest` and `DriftAlertSeverityThresholdTest` (mockserver-core) on the wire. Upstream drives the
//! notifier with a fake synchronous sender and clock; here the webhook (`driftAlertWebhook*`, as
//! `LifeCycle.installDriftAlertWebhook` configures it) posts to a second in-process server, which also plays the
//! upstream a forward next to a response stub drifts from: a STATUS drift (BREAKING), a changed header (WARNING) and
//! an added one (INFORMATIONAL). The scenario harness cannot replay these: a webhook URL naming the replayed server's
//! own ephemeral port cannot be written into its startup properties.

use serde_json::{Value, json};

use crate::common;

/// The sink (webhook receiver and upstream) and the server under test, started with the webhook properties; one
/// forward through it.
async fn drifted(properties: &[(&str, &str)], forwards: usize) -> (common::Running, common::Running) {
    let sink = common::start(&[]).await;
    common::expect(sink.port, &json!({"httpRequest": {"path": "/hook"}, "httpResponse": {"statusCode": 200}})).await;
    common::expect(sink.port, &json!({"httpRequest": {"path": "/api"}, "httpResponse": {"statusCode": 500, "headers": {"X-Version": ["2.0"], "X-Extra": ["1"]}}})).await;
    let url = format!("http://localhost:{}/hook?token=secret", sink.port);
    let mut all: Vec<(&str, &str)> = vec![("driftAlertWebhookUrl", url.as_str())];
    all.extend_from_slice(properties);
    let server = common::start(&all).await;
    common::expect(server.port, &json!({"id": "stub", "httpRequest": {"path": "/api"}, "httpResponse": {"statusCode": 200, "headers": {"X-Version": ["1.0"]}}})).await;
    common::expect(server.port, &json!({"id": "forward", "priority": 10, "httpRequest": {"path": "/api"}, "httpForward": {"host": "localhost", "port": sink.port}})).await;
    for _ in 0..forwards {
        assert_eq!(common::send(server.port, "GET", "/api", "").await.status, 500);
    }
    (sink, server)
}

/// The alert envelopes the sink received, in arrival order.
async fn alerts(sink: &common::Running) -> Vec<Value> {
    let body = common::send(sink.port, "PUT", "/mockserver/retrieve?type=REQUESTS", r#"{"path": "/hook"}"#).await.body;
    let requests: Value = serde_json::from_str(&body).unwrap_or(Value::Array(vec![]));
    requests
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let body = r.get("body")?;
            // A compact JSON body of the default content type is retrieved bare, as `JsonBodyDTOSerializer` writes a
            // body with only default values (forward_json_response_logged).
            if body.is_object() && body.get("type").is_none() {
                return Some(body.clone());
            }
            let text = match body.get("json").or_else(|| body.get("string")) {
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => body.as_str()?.to_string(),
            };
            serde_json::from_str(&text).ok()
        })
        .collect()
}

/// The sink's alerts once `expected` have arrived (or what arrived in five seconds), then a pause for any extra one.
async fn settled(sink: &common::Running, expected: usize) -> Vec<Value> {
    common::eventually_async(|| async { Some(alerts(sink).await).filter(|a| a.len() >= expected) }).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    alerts(sink).await
}

fn kinds(alerts: &[Value]) -> Vec<(String, String)> {
    let mut kinds: Vec<(String, String)> =
        alerts.iter().map(|a| (a["severity"].as_str().unwrap_or_default().to_string(), a["drift"]["driftType"].as_str().unwrap_or_default().to_string())).collect();
    kinds.sort();
    kinds
}

async fn stop(sink: common::Running, server: common::Running) {
    server.server.shutdown().await;
    sink.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn breaking_drift_fires_correct_payload() {
    let (sink, server) = drifted(&[("driftAlertWebhookEnabled", "true")], 1).await;
    let alerts = settled(&sink, 1).await;
    assert_eq!(kinds(&alerts), vec![("BREAKING".to_string(), "STATUS".to_string())], "{alerts:?}");
    let alert = &alerts[0];
    assert_eq!(alert["event"], "mockserver.drift.alert");
    assert!(alert["epochTimeMs"].as_i64().is_some_and(|t| t > 0));
    assert_eq!(alert["drift"]["expectationId"], "stub");
    assert_eq!(alert["drift"]["field"], "statusCode");
    assert_eq!((alert["drift"]["expectedValue"].as_str(), alert["drift"]["actualValue"].as_str()), (Some("200"), Some("500")));
    // the POST: the URL's path and query, a JSON body
    let body = common::send(sink.port, "PUT", "/mockserver/retrieve?type=REQUESTS", r#"{"path": "/hook"}"#).await.body;
    let requests: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(requests[0]["method"], "POST");
    assert_eq!(requests[0]["queryStringParameters"]["token"], json!(["secret"]));
    stop(sink, server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn warning_threshold_alerts_breaking_and_warning_but_not_informational() {
    let (sink, server) = drifted(&[("driftAlertWebhookEnabled", "true"), ("driftAlertSeverityThreshold", "warning")], 1).await;
    let alerts = settled(&sink, 2).await;
    assert_eq!(kinds(&alerts), vec![("BREAKING".into(), "STATUS".into()), ("WARNING".into(), "HEADER_CHANGED".into())], "{alerts:?}");
    stop(sink, server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn informational_threshold_alerts_every_severity() {
    let (sink, server) = drifted(&[("driftAlertWebhookEnabled", "true"), ("driftAlertSeverityThreshold", "INFORMATIONAL")], 1).await;
    let alerts = settled(&sink, 3).await;
    assert_eq!(
        kinds(&alerts),
        vec![("BREAKING".into(), "STATUS".into()), ("INFORMATIONAL".into(), "HEADER_ADDED".into()), ("WARNING".into(), "HEADER_CHANGED".into())],
        "{alerts:?}"
    );
    stop(sink, server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cooldown_de_dupes_the_same_signature() {
    let (sink, server) = drifted(&[("driftAlertWebhookEnabled", "true")], 2).await;
    assert_eq!(settled(&sink, 2).await.len(), 1, "the second STATUS drift of `stub` is within the cooldown");
    stop(sink, server).await;
    let (sink, server) = drifted(&[("driftAlertWebhookEnabled", "true"), ("driftAlertCooldownMillis", "0")], 2).await;
    assert_eq!(settled(&sink, 2).await.len(), 2, "no cooldown");
    stop(sink, server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_clears_the_cooldown() {
    let (sink, server) = drifted(&[("driftAlertWebhookEnabled", "true")], 1).await;
    assert_eq!(settled(&sink, 1).await.len(), 1);
    // `DriftStore.clear` resets the notifier's cooldowns, not its configuration
    assert_eq!(common::send(server.port, "PUT", "/mockserver/drift/clear", "").await.status, 200);
    assert_eq!(common::send(server.port, "GET", "/api", "").await.status, 500);
    assert_eq!(settled(&sink, 2).await.len(), 2);
    stop(sink, server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_or_misconfigured_webhook_alerts_nothing() {
    for properties in [vec![], vec![("driftAlertWebhookEnabled", "true"), ("driftAlertSeverityThreshold", "SEVERE")]] {
        let (sink, server) = drifted(&properties, 1).await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(alerts(&sink).await.is_empty(), "{properties:?}");
        // the drift is still recorded
        let drift: Value = serde_json::from_str(&common::send(server.port, "GET", "/mockserver/drift", "").await.body).unwrap();
        assert_eq!(drift["count"], 3, "{drift}");
        stop(sink, server).await;
    }
}

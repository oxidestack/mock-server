//! `StatefulScenarioExamples` (examples/java). `sequentialCycling` cannot pass unmodified on any target, the oracle
//! included: `ForwardChainExpectation.withHttpResponses` only sets the client-side expectation's responses and
//! nothing calls `respond()`, so the expectation is never sent and every call is 404. The port registers the
//! expectation the example means (`httpResponses` with `responseMode: SEQUENTIAL`) and checks its comment: four
//! calls cycle through the three responses, the fourth wrapping back to the first (the oracle wraps the same way,
//! `tests/scenarios/http_responses.golden.json`, `/seq`).

use serde_json::json;

use crate::common;

#[tokio::test]
async fn sequential_cycling() {
    let running = common::start(&[]).await;
    common::expect(running.port, &json!({
        "httpRequest": {"method": "GET", "path": "/api/status"},
        "httpResponses": [
            {"statusCode": 200, "body": {"type": "JSON", "json": {"status": "ok"}}},
            {"statusCode": 503, "body": {"type": "JSON", "json": {"status": "degraded"}}},
            {"statusCode": 200, "body": {"type": "JSON", "json": {"status": "ok"}}}
        ],
        "responseMode": "SEQUENTIAL"
    }))
    .await;
    let mut statuses = Vec::new();
    for _ in 0..4 {
        statuses.push(common::send(running.port, "GET", "/api/status", "").await.status);
    }
    assert_eq!(statuses, [200, 503, 200, 200], "calls 1-3 follow the responses, call 4 cycles back to the first");
}

//! `maxOpenAiResponsesSizeInBytes` over HTTP: `HttpState` sets `OpenAiResponsesStore`'s byte budget
//! from the configuration at start and on every `PUT /mockserver/configuration`, and `GET /v1/responses/{id}` stops
//! serving an evicted response. The expected statuses are the oracle's, probed on the pinned image with the same
//! requests: a budget of 3000 keeps only the newest of three ~1.6 KB responses, the default keeps all three, and
//! lowering the budget to 1 evicts all but the newest at once. The store's own accounting is ported from
//! `OpenAiResponsesStoreByteBudgetTest` in `src/llm/responses.rs`.
//!
//! The store is one per process, as upstream's, and every server in the process reaches it: a `PUT /mockserver/reset`
//! on any server clears it (`HttpState.reset`), and a server's start or configuration update sets its budget. So this
//! is the only test in its binary (in `tests/upstream` the other ports' resets cleared it mid-test), and
//! both cases run in one test.

#[path = "support/scratch_cwd.rs"]
mod scratch_cwd;
#[path = "support/udp_port.rs"]
mod udp_port;
#[path = "upstream/common.rs"]
#[allow(dead_code)]
mod common;

use serde_json::{Value, json};

/// Three stored Responses API turns, each echoing 1000 characters of `instructions`; their ids, oldest first.
async fn three_responses(port: u16) -> Vec<String> {
    let instructions = "x".repeat(1000);
    let mut ids = Vec::new();
    for _ in 0..3 {
        let r = common::send(port, "POST", "/v1/responses", &json!({"model": "m", "input": "hello", "instructions": instructions}).to_string()).await;
        assert_eq!(r.status, 200, "{}", r.body);
        let body: Value = serde_json::from_str(&r.body).expect("a JSON response");
        ids.push(body["id"].as_str().expect("an id").to_string());
    }
    ids
}

async fn statuses(port: u16, ids: &[String]) -> Vec<u16> {
    let mut statuses = Vec::new();
    for id in ids {
        statuses.push(common::send(port, "GET", &format!("/v1/responses/{id}"), "").await.status);
    }
    statuses
}

async fn configure(port: u16, max_bytes: u64) {
    let r = common::send(port, "PUT", "/mockserver/configuration", &json!({"maxOpenAiResponsesSizeInBytes": max_bytes}).to_string()).await;
    assert_eq!(r.status, 200, "{}", r.body);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_configured_byte_budget_evicts_least_recently_used_responses() {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({
        "httpRequest": {"method": "POST", "path": "/v1/responses"},
        "httpLlmResponse": {"provider": "OPENAI_RESPONSES", "model": "m", "completion": {"text": "answer"}}
    }))
    .await;

    // the default budget keeps every response; lowering it evicts all but the newest at once
    let ids = three_responses(server.port).await;
    assert_eq!(statuses(server.port, &ids).await, [200, 200, 200]);
    configure(server.port, 1).await;
    assert_eq!(statuses(server.port, &ids).await, [404, 404, 200]);

    // a budget set before the turns are stored bounds them as they arrive
    common::send(server.port, "PUT", "/mockserver/reset", "").await;
    common::expect(server.port, &json!({
        "httpRequest": {"method": "POST", "path": "/v1/responses"},
        "httpLlmResponse": {"provider": "OPENAI_RESPONSES", "model": "m", "completion": {"text": "answer"}}
    }))
    .await;
    configure(server.port, 3000).await;
    let ids = three_responses(server.port).await;
    assert_eq!(statuses(server.port, &ids).await, [404, 404, 200]);
}

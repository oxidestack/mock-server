//! `McpStreamableHttpHandlerTest.shouldSendMcpResponseDownTheRequestHttp2Stream` and
//! `shouldNotAddStreamIdHeaderToMcpResponseOnHttp1`: an MCP POST over HTTP/2 is answered on its own stream, and the
//! `x-http2-stream-id` conversion header never reaches a response (on HTTP/2 the stream is the routing, on HTTP/1.1
//! there is none). The Java tests drive an `EmbeddedChannel` with a hand-set stream id; on the wire the observable
//! facts are these. Confirmed against the oracle with `curl --http2-prior-knowledge` (200, `mcp-session-id`, no
//! `x-http2-stream-id`); the scenario harness has no HTTP/2 step, hence a port here.

use serde_json::Value;

use crate::common::{self, Transport};

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}"#;

async fn initialize(transport: Transport) -> common::Exchange {
    let server = common::start(&[]).await;
    common::exchange(server.port, transport, "POST", "/mockserver/mcp", &[("content-type", "application/json")], INITIALIZE).await
}

#[tokio::test(flavor = "multi_thread")]
async fn should_send_mcp_response_down_the_request_http2_stream() {
    let response = initialize(Transport::Http2).await;
    assert_eq!(response.status, 200);
    let json: Value = serde_json::from_str(&response.text()).expect("the answer is JSON");
    assert_eq!(json["id"], 1);
    assert!(json["result"]["protocolVersion"].is_string());
    assert!(response.header("mcp-session-id").is_some(), "the session id is on the HTTP/2 response");
    assert_eq!(response.header("x-http2-stream-id"), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_add_stream_id_header_to_mcp_response_on_http1() {
    let response = initialize(Transport::Http).await;
    assert_eq!(response.status, 200);
    assert!(response.header("mcp-session-id").is_some());
    assert_eq!(response.header("x-http2-stream-id"), None);
}

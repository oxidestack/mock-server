//! `PortUnificationH2cPipelineTest` / `Http2RequestExtensionHeadersIntegrationTest` (inbound capture): the request
//! MockServer records for an HTTP/2 exchange. At the pinned oracle it carries none of Netty's `x-http2-` extension
//! headers (8.0.0 recorded `x-http2-stream-id` and `x-http2-scheme`), and a request that ended with its
//! HEADERS frame has no aggregator-added `Content-Length: 0`. Confirmed against the oracle with curl (`--http2` over
//! TLS, `--http2-prior-knowledge` in clear) and by the scenario `h2_request_model`.

use serde_json::{Value, json};

use crate::common::{self, Transport};

async fn recorded(port: u16) -> Vec<Value> {
    let response = common::send(port, "PUT", "/mockserver/retrieve?type=REQUESTS", "").await;
    serde_json::from_str(&response.body).expect("recorded requests are JSON")
}

fn header<'a>(request: &'a Value, name: &str) -> Option<&'a Value> {
    request["headers"].as_object().and_then(|h| h.iter().find(|(k, _)| k.eq_ignore_ascii_case(name))).map(|(_, v)| v)
}

fn extension_headers(request: &Value) -> Vec<String> {
    let names = request["headers"].as_object().map(|h| h.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
    names.into_iter().filter(|k| k.to_ascii_lowercase().starts_with("x-http2-")).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_http2_request_is_recorded_without_extension_headers() {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/p"}, "httpResponse": {"body": "ok"}})).await;
    common::exchange(server.port, Transport::Http2, "GET", "/p", &[], "").await;
    let requests = recorded(server.port).await;
    let request = requests.iter().find(|r| r["path"] == "/p").expect("the exchange is recorded");
    assert_eq!(request["protocol"], "HTTP_2");
    assert_eq!(extension_headers(request), Vec::<String>::new());
    assert_eq!(header(request, "content-length"), None, "a request that ended with its HEADERS frame gets no Content-Length");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_http2_request_with_a_body_keeps_the_content_length_it_sent() {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/p"}, "httpResponse": {"body": "ok"}})).await;
    common::exchange(server.port, Transport::Http2, "POST", "/p", &[("content-type", "text/plain")], "hello").await;
    let requests = recorded(server.port).await;
    let request = requests.iter().find(|r| r["path"] == "/p").expect("the exchange is recorded");
    assert_eq!(extension_headers(request), Vec::<String>::new());
    assert_eq!(header(request, "content-length"), Some(&json!(["5"])));
}

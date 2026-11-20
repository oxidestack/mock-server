//! Upstream fix cb56f3115 (after 8.0.0, item 420), adopted as a divergence from the 8.0.0 oracle
//! (`docs/divergences.md`): a response to `HEAD` over HTTP/3 is the header section a `GET` is sent, its
//! `content-length` included, ending the stream with no DATA frame and no trailers; a streamed body is discarded.
//! 8.0.0 writes the body and trailers whatever the method (seen on the 8.0.0 image given its QUIC native under the
//! shaded name, 2026-10-07). Port of `Http3HeadResponseIntegrationTest` (a mocked response, one with an explicit
//! `content-length`, one with trailers, a forwarded response, an MCP error and a 413) and of the streamed cases of
//! `Http3ResponseWriterTest` (a streamed response to `HEAD` is its headers alone).

use std::sync::Arc;

use bytes::Buf;
use serde_json::json;

use crate::common;

const BODY: &str = "served";
const MAX_REQUEST_BODY: usize = 1024;

/// What one exchange delivered: the header section (sorted, repeated names joined), the body, the DATA frames
/// carrying it, and whether a trailing HEADERS frame arrived.
#[derive(Debug)]
struct Exchange {
    status: u16,
    headers: std::collections::BTreeMap<String, String>,
    body: String,
    data_frames: usize,
    trailers: Option<Vec<String>>,
}

/// One request on a fresh QUIC connection, with `body` as its DATA.
async fn send(port: u16, method: &str, path: &str, body: &[u8]) -> Exchange {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::http3_mcp::TrustAll))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let connection = endpoint.connect(([127, 0, 0, 1], port).into(), "localhost").unwrap().await.unwrap();
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection)).await.unwrap();
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let request = http::Request::builder().method(method).uri(format!("https://127.0.0.1:{port}{path}")).body(()).unwrap();
    let mut stream = sender.send_request(request).await.unwrap();
    if !body.is_empty() {
        let _ = stream.send_data(bytes::Bytes::copy_from_slice(body)).await;
    }
    let _ = stream.finish().await;
    let exchange = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let response = stream.recv_response().await.unwrap();
        let mut body = Vec::new();
        let mut data_frames = 0;
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            data_frames += 1;
            while chunk.has_remaining() {
                let piece = chunk.chunk().to_vec();
                chunk.advance(piece.len());
                body.extend(piece);
            }
        }
        let trailers = stream.recv_trailers().await.unwrap().map(|t| t.iter().map(|(k, v)| format!("{k}: {}", v.to_str().unwrap())).collect());
        let mut headers = std::collections::BTreeMap::new();
        for (name, value) in response.headers() {
            if name != "date" {
                headers.entry(name.to_string()).and_modify(|v: &mut String| *v = format!("{v}, {}", value.to_str().unwrap())).or_insert_with(|| value.to_str().unwrap().to_string());
            }
        }
        Exchange { status: response.status().as_u16(), headers, body: String::from_utf8_lossy(&body).into_owned(), data_frames, trailers }
    })
    .await
    .expect("the response's stream ends");
    drop(sender);
    drive.abort();
    endpoint.close(0u32.into(), b"");
    exchange
}

/// The server under test (`maxRequestBodySize` 1024, no proxying of unmatched requests) with upstream's expectations,
/// and the upstream it forwards `/forwarded` to.
async fn servers() -> (common::Running, u16, common::Running) {
    let upstream = common::start(&[]).await;
    common::expect(upstream.port, &json!({"httpRequest": {"path": "/forwarded"}, "httpResponse": {"body": BODY}})).await;
    common::expect(upstream.port, &json!({"httpRequest": {"path": "/events"}, "httpSseResponse": {"events": [{"data": "one"}, {"data": "two"}]}})).await;
    let max = MAX_REQUEST_BODY.to_string();
    let (server, h3) = common::start_with_http3(&[("attemptToProxyIfNoMatchingExpectation", "false"), ("maxRequestBodySize", &max)]).await;
    common::expect(
        server.port,
        &json!([
            {"httpRequest": {"path": "/mocked"}, "httpResponse": {"headers": {"x-mocked": ["yes"]}, "body": BODY}},
            {"httpRequest": {"path": "/mocked-with-length"}, "httpResponse": {"headers": {"content-length": [BODY.len().to_string()]}, "body": BODY}},
            {"httpRequest": {"path": "/mocked-with-trailers"}, "httpResponse": {"body": BODY, "trailers": {"x-checksum": ["abc123"]}}},
            {"httpRequest": {"path": "/forwarded"}, "httpForward": {"host": "127.0.0.1", "port": upstream.port, "scheme": "HTTP"}},
            {"httpRequest": {"path": "/events"}, "httpForward": {"host": "127.0.0.1", "port": upstream.port, "scheme": "HTTP"}}
        ]),
    )
    .await;
    (server, h3, upstream)
}

async fn assert_head_is_sent_the_headers_of_get_alone(h3: u16, path: &str) {
    let get = send(h3, "GET", path, b"").await;
    assert_eq!(get.body, BODY, "a GET is sent the body: {get:?}");
    let head = send(h3, "HEAD", path, b"").await;
    assert_eq!(head.body, "", "a HEAD is sent no body, and its stream ends: {head:?}");
    assert_eq!(head.data_frames, 0, "a HEAD is sent no DATA frame: {head:?}");
    assert_eq!(head.headers, get.headers, "a HEAD is sent the header section a GET is sent");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_send_a_mocked_response_to_head_without_its_body() {
    let (_server, h3, _upstream) = servers().await;
    assert_head_is_sent_the_headers_of_get_alone(h3, "/mocked").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_keep_the_content_length_of_a_mocked_response_to_head() {
    let (_server, h3, _upstream) = servers().await;
    let head = send(h3, "HEAD", "/mocked-with-length", b"").await;
    assert_eq!(head.body, "");
    assert_eq!(head.headers.get("content-length").map(String::as_str), Some("6"));
    assert_head_is_sent_the_headers_of_get_alone(h3, "/mocked-with-length").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_send_a_mocked_response_to_head_without_its_body_or_trailers() {
    let (_server, h3, _upstream) = servers().await;
    let get = send(h3, "GET", "/mocked-with-trailers", b"").await;
    assert_eq!(get.body, BODY);
    assert_eq!(get.trailers, Some(vec!["x-checksum: abc123".to_string()]), "a GET is sent the trailers");
    let head = send(h3, "HEAD", "/mocked-with-trailers", b"").await;
    assert_eq!(head.body, "");
    assert_eq!(head.data_frames, 0, "a HEAD is sent no DATA frame");
    assert_eq!(head.trailers, None, "a HEAD is sent no trailers");
    assert_eq!(head.headers, get.headers);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_send_a_forwarded_response_to_head_without_a_body() {
    let (_server, h3, _upstream) = servers().await;
    assert_head_is_sent_the_headers_of_get_alone(h3, "/forwarded").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_send_an_mcp_error_to_head_without_its_body() {
    let (_server, h3, _upstream) = servers().await;
    let head = send(h3, "HEAD", "/mockserver/mcp", b"").await;
    assert_eq!(head.status, 405);
    assert_eq!(head.body, "");
    assert_eq!(head.data_frames, 0, "a HEAD is sent no DATA frame");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_send_a_413_to_head_without_its_body() {
    let (_server, h3, _upstream) = servers().await;
    let head = send(h3, "HEAD", "/mocked", &[0u8; MAX_REQUEST_BODY + 1]).await;
    assert_eq!(head.status, 413);
    assert_eq!(head.body, "");
    assert_eq!(head.data_frames, 0, "a HEAD is sent no DATA frame");
    assert!(head.headers.contains_key("content-length"), "the length a GET is sent is kept: {head:?}");
}

/// `shouldEndAStreamedResponseToHeadWithItsHeadersAndDiscardTheBody`: a streamed response (server-sent events relayed
/// from an upstream) reaches `HEAD` as its headers alone, ending the stream, with no trailers. Upstream's writer test
/// also streams a mocked SSE body through `Http3ResponseWriter`, which a real mocked `httpSseResponse` never reaches:
/// 8.0.0 (and upstream after it) writes it as HTTP/1.1 objects the HTTP/3 codec refuses, so the stream ends empty
/// for GET and HEAD alike (scenario `http3_sse_response`); that case is left out here.
#[tokio::test(flavor = "multi_thread")]
async fn should_end_a_streamed_response_to_head_with_its_headers_and_discard_the_body() {
    let (_server, h3, _upstream) = servers().await;
    for path in ["/events"] {
        let get = send(h3, "GET", path, b"").await;
        assert!(get.body.contains("data: one"), "a GET to {path} is sent the events: {get:?}");
        let head = send(h3, "HEAD", path, b"").await;
        assert_eq!(head.status, get.status, "{path}");
        assert_eq!(head.body, "", "{path}: {head:?}");
        assert_eq!(head.data_frames, 0, "a HEAD to {path} is sent no DATA frame: {head:?}");
        assert_eq!(head.trailers, None, "{path}");
        assert_eq!(head.headers.get("content-type"), get.headers.get("content-type"), "{path}");
    }
    // the server still answers on the same listener once the discarded streams are gone
    assert_eq!(send(h3, "GET", "/mocked", b"").await.body, BODY);
}

//! Upstream fix 40939d794 (after 8.0.0), adopted as a divergence from the 8.0.0 oracle
//! (`docs/divergences.md`): a cleartext CONNECT tunnel is classified by its first bytes, as the SOCKS path already was
//! (a TLS record is terminated and its ALPN read, the h2c preface is served as cleartext HTTP/2, anything else as
//! HTTP/1.1); 8.0.0 assumed TLS and closed a cleartext tunnel without an answer. Port of
//! `NettyHttpProxyConnectHttp2IntegrationTest`: the mocked response served over each tunnelled protocol, the HTTP/2
//! ones with a body past the 65,535-byte flow-control window, compared byte for byte.

use std::pin::Pin;

use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common;

trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

/// Upstream's `FAKE_HOST`: never resolved, the tunnel is served by the server itself.
const FAKE_HOST: &str = "mocked.example.test";
const TLS_PORT: u16 = 443;
const CLEARTEXT_PORT: u16 = 80;

/// `Http2FlowControlBodies.body(OVER_WINDOW, marker)`: 256 KB stamped with the marker throughout.
fn over_window_body(marker: &str) -> String {
    let mut body = String::with_capacity(256 * 1024);
    let mut line = 0;
    while body.len() < 256 * 1024 {
        body.push_str(&format!("{marker}-{line:08}\n"));
        line += 1;
    }
    body.truncate(256 * 1024);
    body
}

/// A CONNECT to `FAKE_HOST:target_port` through the server, answered `200`.
async fn connect(port: u16, target_port: u16) -> tokio::net::TcpStream {
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let authority = format!("{FAKE_HOST}:{target_port}");
    socket.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(socket.read_u8().await.unwrap());
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"), "CONNECT accepted: {}", String::from_utf8_lossy(&head));
    socket
}

async fn tls(socket: tokio::net::TcpStream, alpn: &[u8]) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let name = rustls_pki_types::ServerName::try_from(FAKE_HOST).unwrap();
    tokio_rustls::TlsConnector::from(common::tls_client_config(alpn)).connect(name, socket).await.unwrap()
}

/// One HTTP/2 GET of `/hello` on its own stream: the status and the whole body.
async fn http2_get(io: Pin<Box<dyn Io>>, scheme: &str, target_port: u16) -> (u16, String) {
    let (sender, connection) = h2::client::handshake(io).await.unwrap();
    tokio::spawn(connection);
    let mut sender = sender.ready().await.unwrap();
    let request = http::Request::builder().uri(format!("{scheme}://{FAKE_HOST}:{target_port}/hello")).body(()).unwrap();
    let (response, _) = sender.send_request(request, true).unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(20), response).await.expect("a response").unwrap();
    let status = response.status().as_u16();
    let mut body_stream = response.into_body();
    let mut body = Vec::new();
    while let Some(chunk) = tokio::time::timeout(std::time::Duration::from_secs(20), body_stream.data()).await.expect("the stream ends") {
        let chunk = chunk.unwrap();
        let _ = body_stream.flow_control().release_capacity(chunk.len());
        body.extend_from_slice(&chunk);
    }
    (status, String::from_utf8(body).unwrap())
}

/// One HTTP/1.1 GET of `/hello`: the status line's code and the body (by `content-length`), or `None` when the
/// connection ends first.
async fn http11_get(mut io: Pin<Box<dyn Io>>, target_port: u16) -> Option<(u16, String)> {
    io.write_all(format!("GET /hello HTTP/1.1\r\nHost: {FAKE_HOST}:{target_port}\r\n\r\n").as_bytes()).await.ok()?;
    let read = async {
        let mut buf = Vec::new();
        loop {
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..end]).to_string();
                let length: usize = head
                    .lines()
                    .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("content-length")).map(|(_, v)| v.trim().parse().unwrap()))
                    .unwrap_or(0);
                if buf.len() >= end + 4 + length {
                    let status = head.split(' ').nth(1)?.parse().ok()?;
                    return Some((status, String::from_utf8_lossy(&buf[end + 4..end + 4 + length]).to_string()));
                }
            }
            let mut chunk = [0u8; 8192];
            match io.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(20), read).await.expect("an answer or a close")
}

async fn server_with(body: &str) -> common::Running {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/hello"}, "httpResponse": {"statusCode": 201, "body": body}})).await;
    server
}

/// `mockServerClient.verify(request().withPath("/hello"))`
async fn assert_received(port: u16) {
    let verified = common::send(port, "PUT", "/mockserver/verify", &json!({"httpRequest": {"path": "/hello"}}).to_string()).await;
    assert_eq!(verified.status, 202, "/hello was received: {}", verified.body);
}

/// `shouldServeLargeMockedResponseOverConnectCleartextHttp2PriorKnowledge`: the fix.
#[tokio::test(flavor = "multi_thread")]
async fn should_serve_large_mocked_response_over_connect_cleartext_http2_prior_knowledge() {
    let body = over_window_body("connect-h2c");
    let server = server_with(&body).await;
    let socket = connect(server.port, CLEARTEXT_PORT).await;
    let (status, received) = http2_get(Box::pin(socket), "http", CLEARTEXT_PORT).await;
    assert_eq!(status, 201, "status over connect cleartext h2c");
    assert_eq!(received.len(), body.len(), "body length over connect cleartext h2c");
    assert!(received == body, "body over connect cleartext h2c");
    assert_received(server.port).await;
}

/// `shouldServeLargeMockedResponseOverConnectTlsHttp2`: worked before the fix, must still.
#[tokio::test(flavor = "multi_thread")]
async fn should_serve_large_mocked_response_over_connect_tls_http2() {
    let body = over_window_body("connect-tls-h2");
    let server = server_with(&body).await;
    let socket = tls(connect(server.port, TLS_PORT).await, b"h2").await;
    assert_eq!(socket.get_ref().1.alpn_protocol(), Some(&b"h2"[..]), "h2 negotiated");
    let (status, received) = http2_get(Box::pin(socket), "https", TLS_PORT).await;
    assert_eq!(status, 201, "status over connect+tls+h2");
    assert!(received == body, "body over connect+tls+h2 ({} bytes)", received.len());
    assert_received(server.port).await;
}

/// `shouldServeMockedResponseOverConnectTlsHttp11`: worked before the fix, must still.
#[tokio::test(flavor = "multi_thread")]
async fn should_serve_mocked_response_over_connect_tls_http11() {
    let server = server_with("hello").await;
    let socket = tls(connect(server.port, TLS_PORT).await, b"http/1.1").await;
    assert_eq!(http11_get(Box::pin(socket), TLS_PORT).await, Some((201, "hello".to_string())), "over connect+tls+h1.1");
    assert_received(server.port).await;
}

/// `shouldServeMockedResponseOverConnectCleartextHttp11`: the fix (8.0.0 closed the tunnel unanswered).
#[tokio::test(flavor = "multi_thread")]
async fn should_serve_mocked_response_over_connect_cleartext_http11() {
    let server = server_with("hello").await;
    let socket = connect(server.port, CLEARTEXT_PORT).await;
    assert_eq!(http11_get(Box::pin(socket), CLEARTEXT_PORT).await, Some((201, "hello".to_string())), "over connect cleartext h1.1");
    assert_received(server.port).await;
}

/// `RelayTlsDetectionHandler` gates the h2c preface on `http2Enabled`, as `PortUnificationHandler` does: with HTTP/2
/// off the preface is read as an HTTP/1.1 request, so the client gets no HTTP/2 answer.
#[tokio::test(flavor = "multi_thread")]
async fn should_not_serve_http2_over_connect_cleartext_when_http2_is_disabled() {
    let server = common::start(&[("http2Enabled", "false")]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/hello"}, "httpResponse": {"statusCode": 201, "body": "hello"}})).await;
    let mut socket = connect(server.port, CLEARTEXT_PORT).await;
    socket.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00").await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), socket.read_to_end(&mut answer)).await;
    assert!(!answer.starts_with(&[0, 0]), "no HTTP/2 frames: {:?}", String::from_utf8_lossy(&answer));
}

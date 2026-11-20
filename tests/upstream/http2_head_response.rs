//! Upstream fix c4e2b8985 (after 8.0.0), adopted as a divergence from the 8.0.0 oracle
//! (`docs/divergences.md`): a response to `HEAD` over HTTP/2 is its header block alone, which ends the stream, with the
//! `content-length` a `GET` is sent; 8.0.0 sends the body (and trailers) in DATA frames after it. Port of
//! `Http2HeadResponseIntegrationTest` (a mocked response, and responses forwarded over HTTP/1.1 and HTTP/2, on a
//! connection made straight to the server, through a CONNECT tunnel and through a SOCKS5 tunnel), plus the outcomes
//! `LenientInboundHttp2StreamFrameCodecTest` covers at the codec: a response with trailers and streamed responses
//! (a dribbled body with trailers, server-sent events).

use std::pin::Pin;

use bytes::Bytes;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common;

const BODY: &str = "served";

trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

/// Upstream's routes, and h2c through a cleartext CONNECT, which serves since upstream fix 40939d794.
#[derive(Clone, Copy, Debug)]
enum Route {
    DirectTls,
    DirectH2c,
    ConnectTls,
    ConnectH2c,
    Socks5Tls,
    Socks5H2c,
}

const ROUTES: [Route; 6] = [Route::DirectTls, Route::DirectH2c, Route::ConnectTls, Route::ConnectH2c, Route::Socks5Tls, Route::Socks5H2c];

impl Route {
    fn tls(self) -> bool {
        matches!(self, Route::DirectTls | Route::ConnectTls | Route::Socks5Tls)
    }

    async fn open(self, port: u16) -> h2::client::SendRequest<Bytes> {
        let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let [high, low] = port.to_be_bytes();
        match self {
            Route::DirectTls | Route::DirectH2c => {}
            Route::ConnectTls | Route::ConnectH2c => {
                socket.write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(socket.read_u8().await.unwrap());
                }
                assert!(String::from_utf8_lossy(&head).contains(" 200"), "{self:?}: CONNECT accepted");
            }
            Route::Socks5Tls | Route::Socks5H2c => {
                // version 5, one method offered: no authentication
                socket.write_all(&[5, 1, 0]).await.unwrap();
                let mut method = [0u8; 2];
                socket.read_exact(&mut method).await.unwrap();
                assert_eq!(method, [5, 0], "{self:?}: SOCKS5 method");
                // version 5, CONNECT, reserved, IPv4 127.0.0.1, port
                socket.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, high, low]).await.unwrap();
                let mut reply = [0u8; 5];
                socket.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[1], 0, "{self:?}: SOCKS5 success");
                let rest = match reply[3] {
                    3 => reply[4] as usize,
                    1 => 3,
                    _ => 15,
                };
                let mut bound = vec![0u8; rest + 2];
                socket.read_exact(&mut bound).await.unwrap();
            }
        }
        let io: Pin<Box<dyn Io>> = if self.tls() {
            let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
            Box::pin(tokio_rustls::TlsConnector::from(common::tls_client_config(b"h2")).connect(name, socket).await.unwrap())
        } else {
            Box::pin(socket)
        };
        let (sender, connection) = h2::client::handshake(io).await.unwrap();
        tokio::spawn(connection);
        sender.ready().await.unwrap()
    }
}

/// What reached the client for one request.
#[derive(Debug)]
struct Answer {
    /// The response's header block, `:status` first, without Netty's in-process `x-http2-` headers.
    header_block: Vec<(String, String)>,
    /// Whether the header block ended the stream (END_STREAM on its HEADERS frame).
    ended_by_header_block: bool,
    body: Vec<u8>,
    trailers: Option<Vec<(String, String)>>,
}

async fn ask(sender: &mut h2::client::SendRequest<Bytes>, route: Route, port: u16, method: &str, path: &str) -> Answer {
    let scheme = if route.tls() { "https" } else { "http" };
    let request = http::Request::builder().method(method).uri(format!("{scheme}://localhost:{port}{path}")).body(()).unwrap();
    let (response, _) = sender.send_request(request, true).unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(10), response).await.expect("a response").unwrap();
    let mut header_block = vec![(":status".to_string(), response.status().as_u16().to_string())];
    header_block.extend(
        response
            .headers()
            .iter()
            .filter(|(name, _)| !name.as_str().starts_with("x-http2-"))
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or_default().to_string())),
    );
    let mut body_stream = response.into_body();
    let ended_by_header_block = body_stream.is_end_stream();
    let mut body = Vec::new();
    while let Some(chunk) = tokio::time::timeout(std::time::Duration::from_secs(10), body_stream.data()).await.expect("the stream ends") {
        let chunk = chunk.unwrap();
        let _ = body_stream.flow_control().release_capacity(chunk.len());
        body.extend_from_slice(&chunk);
    }
    let trailers = body_stream.trailers().await.unwrap().map(|t| {
        t.iter().map(|(name, value)| (name.to_string(), value.to_str().unwrap_or_default().to_string())).collect()
    });
    Answer { header_block, ended_by_header_block, body, trailers }
}

async fn servers() -> (common::Running, common::Running) {
    // the forward keeps the inbound protocol, so a forward over TLS reaches the upstream as HTTP/2
    let server = common::start(&[("forwardProxyHttp2Enabled", "true")]).await;
    let upstream = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/mocked"}, "httpResponse": {"body": BODY}})).await;
    for (path, scheme) in [("/forwarded-over-http1", "HTTP"), ("/forwarded-over-http2", "HTTPS")] {
        common::expect(
            server.port,
            &json!({"httpRequest": {"path": path}, "httpForward": {"host": "localhost", "port": upstream.port, "scheme": scheme}}),
        )
        .await;
    }
    common::expect(upstream.port, &json!({"httpRequest": {"path": "/forwarded-.*"}, "httpResponse": {"body": BODY}})).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/trailers"}, "httpResponse": {"body": BODY, "trailers": {"t1": ["v"]}}})).await;
    common::expect(
        server.port,
        &json!({"httpRequest": {"path": "/dribbled"}, "httpResponse": {"body": BODY, "trailers": {"t1": ["v"]},
            "connectionOptions": {"chunkSize": 2, "chunkDelay": {"timeUnit": "MILLISECONDS", "value": 5}}}}),
    )
    .await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/sse"}, "httpSseResponse": {"events": [{"data": "one"}, {"data": "two"}]}})).await;
    (server, upstream)
}

/// `assertHeadIsSentTheHeadersOfGetWithoutTheBody`: a GET gets the body; a HEAD on the same connection gets the
/// GET's header block, ending the stream, and nothing after it.
async fn assert_head_is_sent_the_headers_of_get_without_the_body(port: u16, path: &str, get_body: Option<&str>) {
    for route in ROUTES {
        let mut sender = route.open(port).await;
        let get = ask(&mut sender, route, port, "GET", path).await;
        match get_body {
            Some(body) => {
                assert_eq!(String::from_utf8_lossy(&get.body), body, "{route:?} {path}: a GET is sent the body");
                assert!(
                    get.header_block.contains(&("content-length".to_string(), body.len().to_string())),
                    "{route:?} {path}: a GET is sent the length of the body: {:?}",
                    get.header_block
                );
            }
            None => assert!(!get.body.is_empty(), "{route:?} {path}: a GET is sent a body"),
        }
        let head = ask(&mut sender, route, port, "HEAD", path).await;
        assert_eq!(String::from_utf8_lossy(&head.body), "", "{route:?} {path}: a HEAD is sent no body");
        assert_eq!(head.header_block, get.header_block, "{route:?} {path}: a HEAD is sent the header block a GET is sent");
        assert!(head.ended_by_header_block, "{route:?} {path}: the header block ends the HEAD's stream");
        assert_eq!(head.trailers, None, "{route:?} {path}: a HEAD is sent no trailers");
    }
}

/// `Http2HeadResponseIntegrationTest.shouldSendAMockedResponseToHeadWithoutItsBody`
#[tokio::test(flavor = "multi_thread")]
async fn should_send_a_mocked_response_to_head_without_its_body() {
    let (server, _upstream) = servers().await;
    assert_head_is_sent_the_headers_of_get_without_the_body(server.port, "/mocked", Some(BODY)).await;
}

/// `Http2HeadResponseIntegrationTest.shouldSendAResponseForwardedOverHttp1ToHeadWithoutItsBody`
#[tokio::test(flavor = "multi_thread")]
async fn should_send_a_response_forwarded_over_http1_to_head_without_its_body() {
    let (server, _upstream) = servers().await;
    assert_head_is_sent_the_headers_of_get_without_the_body(server.port, "/forwarded-over-http1", Some(BODY)).await;
}

/// `Http2HeadResponseIntegrationTest.shouldSendAResponseForwardedOverHttp2ToHeadWithoutItsBody`
#[tokio::test(flavor = "multi_thread")]
async fn should_send_a_response_forwarded_over_http2_to_head_without_its_body() {
    let (server, _upstream) = servers().await;
    assert_head_is_sent_the_headers_of_get_without_the_body(server.port, "/forwarded-over-http2", Some(BODY)).await;
}

/// `LenientInboundHttp2StreamFrameCodecTest`, a whole response: its trailers are not sent to a HEAD either.
#[tokio::test(flavor = "multi_thread")]
async fn should_send_a_response_with_trailers_to_head_without_its_body_or_trailers() {
    let (server, _upstream) = servers().await;
    assert_head_is_sent_the_headers_of_get_without_the_body(server.port, "/trailers", None).await;
}

/// `LenientInboundHttp2StreamFrameCodecTest`, a streamed response with trailers: what follows the header block is
/// dropped.
#[tokio::test(flavor = "multi_thread")]
async fn should_send_a_streamed_response_to_head_without_its_body_or_trailers() {
    let (server, _upstream) = servers().await;
    assert_head_is_sent_the_headers_of_get_without_the_body(server.port, "/dribbled", None).await;
    assert_head_is_sent_the_headers_of_get_without_the_body(server.port, "/sse", None).await;
}

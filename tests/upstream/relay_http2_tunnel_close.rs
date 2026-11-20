//! Port of `RelayHttp2TunnelCloseIntegrationTest`: an HTTP/2 CONNECT tunnel (cleartext, or TLS the relay
//! terminates) whose client leaves while MockServer still owes it a response. Both legs close promptly, a request the
//! client had sent in full is still received, and nothing is logged at WARN or above. Upstream waits for its tunnel's
//! two legs through `getInboundConnectionCount()`; the stand-in behind the rs-process run counts the server's sockets,
//! and mock-server relays a tunnel in-process with no loopback socket, so these run here against
//! `Server::inbound_connection_count()`.

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common;

const PROMPTLY: Duration = Duration::from_secs(10);

trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

async fn start() -> common::Running {
    let server = common::start(&[("logLevel", "WARN"), ("startupWarmup", "false"), ("proxySetup", "false")]).await;
    let port = server.port;
    // answered with nothing, and the stream left open
    common::expect(port, &json!({"httpRequest": {"path": "/held"}, "httpError": {}})).await;
    common::expect(port, &json!({"httpRequest": {"path": "/upload"}, "httpError": {}})).await;
    common::expect(port, &json!({"httpRequest": {"path": "/answered"}, "httpResponse": {"body": "answered"}})).await;
    common::expect(port, &json!({"httpRequest": {"path": "/large"}, "httpResponse": {"body": "x".repeat(200_000)}})).await;
    server
}

/// Speaks HTTP/2 through a CONNECT tunnel: it grants each stream `stream_window` and never extends it.
struct TunnelClient {
    sender: h2::client::SendRequest<Bytes>,
    connection: tokio::task::JoinHandle<()>,
    data_bytes: Arc<AtomicUsize>,
    scheme: &'static str,
}

impl TunnelClient {
    async fn open(port: u16, stream_window: u32, tls: bool) -> TunnelClient {
        let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        socket.write_all(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n").await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.unwrap());
        }
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
        let io: Pin<Box<dyn Io>> = if tls {
            let name = rustls_pki_types::ServerName::try_from("127.0.0.1").unwrap();
            Box::pin(tokio_rustls::TlsConnector::from(common::tls_client_config(b"h2")).connect(name, socket).await.unwrap())
        } else {
            Box::pin(socket)
        };
        let (sender, connection) = h2::client::Builder::new().initial_window_size(stream_window).handshake(io).await.unwrap();
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        TunnelClient { sender, connection, data_bytes: Arc::new(AtomicUsize::new(0)), scheme: if tls { "https" } else { "http" } }
    }

    async fn request(&mut self, path: &str) {
        let request = http::Request::builder().method("GET").uri(format!("{}://127.0.0.1:443{path}", self.scheme)).body(()).unwrap();
        let (response, _) = self.sender.clone().ready().await.unwrap().send_request(request, true).unwrap();
        let data_bytes = self.data_bytes.clone();
        tokio::spawn(async move {
            let Ok(response) = response.await else { return };
            let mut body = response.into_body();
            // never released: the stream's window is never extended
            while let Some(Ok(chunk)) = body.data().await {
                data_bytes.fetch_add(chunk.len(), Ordering::SeqCst);
            }
        });
    }

    /// A request with a body, the connection closed as soon as the last of it has been handed to the connection.
    async fn post_then_leave(self, path: &str, body_bytes: usize) {
        let request = http::Request::builder().method("POST").uri(format!("{}://127.0.0.1:443{path}", self.scheme)).body(()).unwrap();
        let (_response, mut stream) = self.sender.clone().ready().await.unwrap().send_request(request, false).unwrap();
        let mut left = body_bytes;
        while left > 0 {
            stream.reserve_capacity(left.min(16_384));
            let granted = std::future::poll_fn(|cx| stream.poll_capacity(cx)).await.expect("capacity").unwrap();
            let n = granted.min(left);
            left -= n;
            stream.send_data(Bytes::from(vec![b'x'; n]), left == 0).unwrap();
        }
        // what was granted last is written by the connection task at once
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.connection.abort();
        let _ = self.connection.await;
    }

    async fn close(self) {
        self.connection.abort();
        let _ = self.connection.await;
    }
}

async fn request_received(port: u16, path: &str) -> bool {
    common::send(port, "PUT", "/mockserver/retrieve?type=REQUESTS&format=JSON", &json!({"path": path}).to_string()).await.body.contains(&format!("\"{path}\""))
}

async fn logged_at_warn_or_above(port: u16) -> Vec<String> {
    let entries = common::send(port, "PUT", "/mockserver/retrieve?type=LOGS&format=LOG_ENTRIES", "").await.body;
    let entries: serde_json::Value = serde_json::from_str(&entries).unwrap_or(serde_json::Value::Array(vec![]));
    entries
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| matches!(e["logLevel"].as_str(), Some("WARN" | "ERROR")))
        .map(|e| format!("{} {}", e["logLevel"], e["messageFormat"]))
        .collect()
}

/// Waits past Netty's 30 s graceful-shutdown timeout, so a leg that closes only then fails on how long it took.
async fn await_async<F: std::future::Future<Output = bool>>(reason: &str, mut condition: impl FnMut() -> F) {
    let deadline = Instant::now() + Duration::from_secs(40);
    while !condition().await && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(condition().await, "{reason}");
}

async fn await_count(server: &common::Running, reason: &str, count: usize) {
    await_async(reason, || std::future::ready(server.server.inbound_connection_count() == count)).await;
}

async fn leave_with_a_request_in_flight(tls: bool) {
    let server = start().await;
    let port = server.port;
    let mut client = TunnelClient::open(port, 65_535, tls).await;
    client.request("/held").await;
    await_async("the request reached MockServer", || request_received(port, "/held")).await;
    await_count(&server, "only the client's leg and the loopback leg are open", 2).await;
    let before = logged_at_warn_or_above(port).await;

    let left = Instant::now();
    client.close().await;

    await_count(&server, "both legs closed", 0).await;
    assert!(left.elapsed() < PROMPTLY);
    assert_eq!(logged_at_warn_or_above(port).await, before, "nothing logged at WARN or above for a client that left");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_the_loopback_with_the_client_that_leaves_with_a_request_in_flight() {
    leave_with_a_request_in_flight(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_the_loopback_of_a_tls_tunnel_with_the_client_that_leaves_with_a_request_in_flight() {
    leave_with_a_request_in_flight(true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_the_loopback_with_the_client_that_leaves_with_response_data_queued_and_another_request_in_flight() {
    let server = start().await;
    let port = server.port;
    // a stream window far below the response, which the client never extends
    let mut client = TunnelClient::open(port, 1024, false).await;
    client.request("/held").await;
    client.request("/large").await;
    let data = client.data_bytes.clone();
    await_async("the start of the response reached the client", || std::future::ready(data.load(Ordering::SeqCst) == 1024)).await;
    await_async("the other request reached MockServer", || request_received(port, "/held")).await;
    await_count(&server, "only the client's leg and the loopback leg are open", 2).await;
    let before = logged_at_warn_or_above(port).await;

    let left = Instant::now();
    client.close().await;

    await_count(&server, "both legs closed", 0).await;
    assert!(left.elapsed() < PROMPTLY);
    assert_eq!(logged_at_warn_or_above(port).await, before, "nothing logged at WARN or above for a client that left");
}

async fn leave_as_soon_as_a_large_request_is_sent(tls: bool) {
    let server = start().await;
    let port = server.port;
    let mut client = TunnelClient::open(port, 65_535, tls).await;
    client.request("/answered").await;
    let data = client.data_bytes.clone();
    await_async("the tunnel has carried a whole exchange", || std::future::ready(data.load(Ordering::SeqCst) == "answered".len())).await;
    await_count(&server, "only the client's leg and the loopback leg are open", 2).await;
    let before = logged_at_warn_or_above(port).await;

    // many times the 65,535 bytes MockServer lets a stream send before it extends the window
    client.post_then_leave("/upload", 1_000_000).await;
    let left = Instant::now();

    await_async("the request reached MockServer", || request_received(port, "/upload")).await;
    await_count(&server, "both legs closed", 0).await;
    assert!(left.elapsed() < PROMPTLY);
    assert_eq!(logged_at_warn_or_above(port).await, before, "nothing logged at WARN or above for a client that left");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_a_large_request_from_a_client_that_leaves_as_soon_as_it_has_sent_it() {
    leave_as_soon_as_a_large_request_is_sent(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_a_large_request_over_a_tls_tunnel_from_a_client_that_leaves_as_soon_as_it_has_sent_it() {
    leave_as_soon_as_a_large_request_is_sent(true).await;
}

async fn leave_with_a_response_still_being_written_as_soon_as_a_large_request_is_sent(tls: bool) {
    let server = start().await;
    let port = server.port;
    // the rest of the response stays queued for the client, and fails when the client leaves
    let mut client = TunnelClient::open(port, 1024, tls).await;
    client.request("/large").await;
    let data = client.data_bytes.clone();
    await_async("the start of the response reached the client", || std::future::ready(data.load(Ordering::SeqCst) == 1024)).await;
    await_count(&server, "only the client's leg and the loopback leg are open", 2).await;
    let before = logged_at_warn_or_above(port).await;

    client.post_then_leave("/upload", 2_000_000).await;
    let left = Instant::now();

    await_async("the request reached MockServer", || request_received(port, "/upload")).await;
    await_count(&server, "both legs closed", 0).await;
    assert!(left.elapsed() < PROMPTLY);
    assert_eq!(logged_at_warn_or_above(port).await, before, "nothing logged at WARN or above for a client that left");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_a_request_from_a_client_that_leaves_with_a_response_on_another_stream_still_being_written() {
    leave_with_a_response_still_being_written_as_soon_as_a_large_request_is_sent(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_a_request_over_a_tls_tunnel_from_a_client_that_leaves_with_a_response_on_another_stream_still_being_written() {
    leave_with_a_response_still_being_written_as_soon_as_a_large_request_is_sent(true).await;
}

//! `InboundConnectionLimitIntegrationTest` and `InboundConnectionIdleTimeoutIntegrationTest` (b765b8271)
//! over an in-process server: the cases that read the in-JVM `Metrics` counters or the server's own connection count
//! (`MockServer.getInboundConnectionCount`, which counts a tunnel's loopback leg), here
//! `mock_server_inbound_connections_*_total` and `Server::inbound_connection_count`.

use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::common;

const IDLE_MILLIS: u64 = 400;

async fn connect(port: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", port)).await.unwrap()
}

/// The response head, up to and including its blank line.
async fn read_head(socket: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tokio::time::timeout(Duration::from_secs(10), socket.read(&mut byte)).await {
            Ok(Ok(1)) => head.push(byte[0]),
            other => panic!("connection ended reading a head ({other:?}): {}", String::from_utf8_lossy(&head)),
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// A `PUT /mockserver/status` answered on `socket`, which stays open.
async fn open_and_exchange(port: u16) -> TcpStream {
    let mut socket = connect(port).await;
    socket.write_all(format!("PUT /mockserver/status HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.unwrap();
    let head = read_head(&mut socket).await;
    assert!(head.contains("200"), "{head}");
    let length: usize = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
    let mut body = vec![0u8; length];
    socket.read_exact(&mut body).await.unwrap();
    socket
}

/// `new Socket` then `assertClosedByServer`: a request on a new connection reads end of stream or a reset. The reset
/// can reach the connect itself, the refusal being made as the connection is accepted.
async fn assert_refused(port: u16) {
    if let Ok(mut socket) = TcpStream::connect(("127.0.0.1", port)).await {
        assert_closed_by_server(&mut socket).await;
    }
}

/// `assertClosedByServer`: a request on `socket` reads end of stream or a reset.
async fn assert_closed_by_server(socket: &mut TcpStream) {
    let _ = socket.write_all(b"PUT /mockserver/status HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n").await;
    let mut byte = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(10), socket.read(&mut byte)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("expected the refused connection to be closed, but it answered: {other:?}"),
    }
}

/// Reads until the server closes `socket`: what arrived, and whether it closed within `within`.
async fn read_until_closed(socket: &mut TcpStream, within: Duration) -> (String, bool) {
    let mut read = Vec::new();
    let closed = tokio::time::timeout(within, socket.read_to_end(&mut read)).await.is_ok();
    (String::from_utf8_lossy(&read).into_owned(), closed)
}

async fn counter(port: u16, name: &str) -> f64 {
    let metrics = common::send(port, "GET", "/mockserver/metrics", "").await.body;
    metrics.lines().find_map(|l| l.strip_prefix(name).and_then(|v| v.trim().parse().ok())).unwrap_or_else(|| panic!("{name} in {metrics}"))
}

async fn await_count(server: &common::Running, count: usize) {
    assert!(common::eventually(|| server.server.inbound_connection_count() == count).await, "inbound connections {} not {count}", server.server.inbound_connection_count());
}

async fn limited(max: &str) -> common::Running {
    common::start(&[("maxInboundConnections", max), ("metricsEnabled", "true"), ("startupWarmup", "false"), ("logLevel", "WARN")]).await
}

#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_connection_beyond_limit_and_recover_when_one_closes() {
    let server = limited("2").await;
    let mut admitted = vec![open_and_exchange(server.port).await, open_and_exchange(server.port).await];
    assert_eq!(server.server.inbound_connection_count(), 2);
    let started = Instant::now();
    assert_refused(server.port).await;
    assert!(started.elapsed() < Duration::from_secs(5), "refused at once, not accepted and left hanging");
    assert_eq!(server.server.inbound_connection_count(), 2);
    drop(admitted.remove(0));
    await_count(&server, 1).await;
    admitted.push(open_and_exchange(server.port).await);
    assert_eq!(server.server.inbound_connection_count(), 2);
    drop(admitted);
    await_count(&server, 0).await;
    assert_eq!(counter(server.port, "mock_server_inbound_connections_rejected_total").await, 1.0);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_log_refusal() {
    let server = limited("2").await;
    let first = open_and_exchange(server.port).await;
    let second = open_and_exchange(server.port).await;
    assert_refused(server.port).await;
    drop((first, second));
    await_count(&server, 0).await;
    let logs = common::logs(server.port).await;
    assert!(logs.contains("refused inbound connection"), "{logs}");
    assert!(logs.contains("maxInboundConnections"), "{logs}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fail_connect_tunnel_promptly_when_its_loopback_leg_is_refused() {
    let server = limited("1").await;
    let mut socket = connect(server.port).await;
    let port = server.port;
    socket.write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
    // the tunnel's loopback leg to the server itself is the second connection, so it is refused
    assert!(read_head(&mut socket).await.contains("502"));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_limit_connections_by_default() {
    let server = limited("0").await;
    let mut sockets = Vec::new();
    for _ in 0..20 {
        sockets.push(open_and_exchange(server.port).await);
    }
    assert_eq!(server.server.inbound_connection_count(), 20);
}

async fn idle_server(millis: u64) -> common::Running {
    let millis = millis.to_string();
    common::start(&[("inboundConnectionIdleTimeoutMillis", &millis), ("metricsEnabled", "true"), ("startupWarmup", "false")]).await
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_connection_that_never_sends_anything() {
    let server = idle_server(IDLE_MILLIS).await;
    let before = Instant::now();
    let mut socket = connect(server.port).await;
    let (_, closed) = read_until_closed(&mut socket, Duration::from_secs(10)).await;
    assert!(closed);
    assert!(before.elapsed() >= Duration::from_millis(IDLE_MILLIS - 50), "closed after {:?}", before.elapsed());
    assert!(counter(server.port, "mock_server_inbound_connections_idle_closed_total").await >= 1.0);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_keep_alive_connection_once_idle_after_its_response() {
    let server = idle_server(IDLE_MILLIS).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/simple"}, "httpResponse": {"body": "simple"}})).await;
    let mut socket = connect(server.port).await;
    let request = format!("GET /simple HTTP/1.1\r\nHost: localhost:{}\r\n\r\n", server.port);
    socket.write_all(request.as_bytes()).await.unwrap();
    assert!(read_head(&mut socket).await.contains("200"));
    let mut body = [0u8; 6];
    socket.read_exact(&mut body).await.unwrap();
    let before = Instant::now();
    socket.write_all(request.as_bytes()).await.unwrap();
    assert!(read_head(&mut socket).await.contains("200"), "keep-alive is honoured while the client is active");
    socket.read_exact(&mut body).await.unwrap();
    let (_, closed) = read_until_closed(&mut socket, Duration::from_secs(10)).await;
    assert!(closed);
    assert!(before.elapsed() >= Duration::from_millis(IDLE_MILLIS - 50));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_close_connection_when_timeout_disabled() {
    let server = idle_server(0).await;
    let mut socket = connect(server.port).await;
    let (_, closed) = read_until_closed(&mut socket, Duration::from_millis(3 * IDLE_MILLIS)).await;
    assert!(!closed);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_close_connection_while_response_is_delayed() {
    let server = idle_server(IDLE_MILLIS).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/slow"}, "httpResponse": {"body": "slow but sure", "delay": {"timeUnit": "MILLISECONDS", "value": 3 * IDLE_MILLIS}}})).await;
    let mut socket = connect(server.port).await;
    socket.write_all(format!("GET /slow HTTP/1.1\r\nHost: localhost:{}\r\n\r\n", server.port).as_bytes()).await.unwrap();
    let (read, _) = read_until_closed(&mut socket, Duration::from_secs(10)).await;
    assert!(read.contains("slow but sure"), "{read}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_both_legs_of_a_connect_tunnel_that_never_carries_anything() {
    let server = idle_server(IDLE_MILLIS).await;
    let port = server.port;
    let mut socket = connect(port).await;
    let before = Instant::now();
    socket.write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
    assert!(read_head(&mut socket).await.contains("200"));
    assert_eq!(server.server.inbound_connection_count(), 2, "the client's leg and the loopback leg");
    let (_, closed) = read_until_closed(&mut socket, Duration::from_secs(10)).await;
    assert!(closed);
    assert!(before.elapsed() >= Duration::from_millis(IDLE_MILLIS - 50));
    await_count(&server, 0).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_both_legs_of_a_connect_tunnel_once_idle_after_its_response() {
    let server = idle_server(IDLE_MILLIS).await;
    let port = server.port;
    common::expect(port, &json!({"httpRequest": {"path": "/through-tunnel"}, "httpResponse": {"body": "tunnelled"}})).await;
    let idle_closed = counter(port, "mock_server_inbound_connections_idle_closed_total").await;
    let mut socket = connect(port).await;
    socket.write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
    assert!(read_head(&mut socket).await.contains("200"));
    let before = Instant::now();
    socket.write_all(format!("GET /through-tunnel HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
    assert!(read_head(&mut socket).await.contains("200"));
    let (read, closed) = read_until_closed(&mut socket, Duration::from_secs(10)).await;
    assert_eq!(read, "tunnelled");
    assert!(closed);
    assert!(before.elapsed() >= Duration::from_millis(IDLE_MILLIS - 50));
    await_count(&server, 0).await;
    assert!(counter(port, "mock_server_inbound_connections_idle_closed_total").await > idle_closed);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_the_loopback_leg_of_a_tunnel_whose_client_leaves_before_sending_anything() {
    let server = idle_server(0).await;
    let port = server.port;
    let mut socket = connect(port).await;
    socket.write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
    assert!(read_head(&mut socket).await.contains("200"));
    assert_eq!(server.server.inbound_connection_count(), 2, "the client's leg and the loopback leg");
    drop(socket);
    await_count(&server, 0).await;
    let mut socket = connect(port).await;
    socket.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0u8; 2];
    socket.read_exact(&mut greeting).await.unwrap();
    socket.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, (port >> 8) as u8, port as u8]).await.unwrap();
    let mut reply = [0u8; 4];
    socket.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS success");
    assert!(common::eventually(|| server.server.inbound_connection_count() == 2).await);
    drop(socket);
    await_count(&server, 0).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_connection_whose_tls_client_hello_never_completes() {
    let server = idle_server(IDLE_MILLIS).await;
    let mut socket = connect(server.port).await;
    let before = Instant::now();
    // a TLS record header announcing a 512-byte ClientHello, then a byte at a time, each well inside the timeout
    socket.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03]).await.unwrap();
    let mut closed = false;
    for _ in 0..40 {
        let mut byte = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(3 * IDLE_MILLIS / 16), socket.read(&mut byte)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {
                closed = true;
                break;
            }
            Ok(Ok(_)) => panic!("answered a partial ClientHello"),
            Err(_) => {
                if socket.write_all(&[0]).await.is_err() {
                    closed = true;
                    break;
                }
            }
        }
    }
    assert!(closed, "closed while the ClientHello was still arriving");
    assert!(before.elapsed() >= Duration::from_millis(IDLE_MILLIS - 50));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_log_an_idle_close_at_debug() {
    let server = common::start(&[("inboundConnectionIdleTimeoutMillis", "300"), ("logLevel", "DEBUG"), ("startupWarmup", "false")]).await;
    let mut socket = connect(server.port).await;
    let (_, closed) = read_until_closed(&mut socket, Duration::from_secs(10)).await;
    assert!(closed);
    let logs = common::logs(server.port).await;
    assert!(logs.contains("closing idle inbound connection from:"), "{logs}");
    assert!(logs.contains(" with nothing in progress"), "{logs}");
}

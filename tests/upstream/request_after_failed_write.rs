//! Port of `RequestAfterFailedWriteIntegrationTest`: a request sent just before the client resets its
//! connection, behind a response the server is still writing (the client stopped reading it) or with the last flight
//! of a TLS 1.3 handshake. The server's write to the reset connection fails before the request is decoded; the request
//! must still be received, once, and matched (its expectation is used up), every connection must close, and nothing is
//! logged at WARN or above (`ReadAfterFailedWrite`, after 8.0.0). Upstream holds the server's event loops while the
//! client writes and resets; here the server is simply not reading while its write is blocked.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde_json::json;

use crate::common;

const LARGE_BODY_BYTES: usize = 2 * 1024 * 1024;
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

async fn start() -> common::Running {
    let server = common::start(&[("logLevel", "WARN"), ("startupWarmup", "false"), ("proxySetup", "false")]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/large"}, "httpResponse": {"body": "x".repeat(LARGE_BODY_BYTES)}})).await;
    // once: the request read after the failed write uses it up, so it was matched
    common::expect(server.port, &json!({"httpRequest": {"path": "/next"}, "httpResponse": {"body": "answered"}, "times": {"remainingTimes": 1}})).await;
    server
}

/// A client socket with a small receive buffer, set before it connects, so the large response fills it.
fn connect(port: u16) -> TcpStream {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    socket.connect(&std::net::SocketAddr::from(([127, 0, 0, 1], port)).into()).unwrap();
    let socket: TcpStream = socket.into();
    socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    socket
}

fn read_exact(socket: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; n];
    socket.read_exact(&mut bytes).unwrap();
    bytes
}

fn open_connect_tunnel(socket: &mut TcpStream, port: u16) {
    socket.write_all(format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes()).unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.extend(read_exact(socket, 1));
    }
    assert!(String::from_utf8_lossy(&head).contains("200"));
}

fn open_socks5_tunnel(socket: &mut TcpStream, port: u16) {
    socket.write_all(&[5, 1, 0]).unwrap();
    assert_eq!(read_exact(socket, 2), vec![5, 0]);
    socket.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, (port >> 8) as u8, port as u8]).unwrap();
    let reply = read_exact(socket, 5);
    assert_eq!(reply[1], 0, "SOCKS5 success");
    let rest = if reply[3] == 3 { reply[4] as usize } else if reply[3] == 1 { 3 } else { 15 };
    read_exact(socket, rest + 2);
}

fn http1_get(port: u16, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes()
}

fn frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    out.extend(&(payload.len() as u32).to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend(stream.to_be_bytes());
    out.extend(payload);
}

/// HEADERS ending the stream: indexed `:method: GET` and `:scheme`, literal `:path` and `:authority`.
fn http2_get(port: u16, stream: u32, scheme: &str, path: &str) -> Vec<u8> {
    let mut headers = vec![0x82, if scheme == "https" { 0x87 } else { 0x86 }];
    for (index, value) in [(0x04u8, path.to_string()), (0x01, format!("127.0.0.1:{port}"))] {
        headers.push(index);
        headers.push(value.len() as u8);
        headers.extend(value.as_bytes());
    }
    let mut out = Vec::new();
    frame(&mut out, 0x1, 0x5, stream, &headers);
    out
}

/// The preface; SETTINGS and a WINDOW_UPDATE opening every window as far as it goes, so only the sockets hold the
/// response back; and a GET on stream 1.
fn http2_preface_and_get(port: u16, scheme: &str, path: &str) -> Vec<u8> {
    let mut out = PREFACE.to_vec();
    frame(&mut out, 0x4, 0, 0, &[0x0, 0x4, 0x7f, 0xff, 0xff, 0xff]);
    frame(&mut out, 0x8, 0, 0, &(0x7fff_ffffu32 - 65_535).to_be_bytes());
    out.extend(http2_get(port, 1, scheme, path));
    out
}

async fn requests_received(port: u16, path: &str) -> usize {
    let received = common::send(port, "PUT", "/mockserver/retrieve?type=REQUESTS&format=JSON", &json!({"path": path}).to_string()).await.body;
    if received.trim().is_empty() {
        return 0;
    }
    serde_json::from_str::<serde_json::Value>(&received).unwrap().as_array().map_or(0, |a| a.len())
}

async fn logged_at_warn_or_above(port: u16) -> Vec<String> {
    let entries = common::send(port, "PUT", "/mockserver/retrieve?type=LOGS&format=LOG_ENTRIES", "").await.body;
    let entries: serde_json::Value = serde_json::from_str(&entries).unwrap_or(serde_json::Value::Array(vec![]));
    entries
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| matches!(e["logLevel"].as_str(), Some("WARN" | "ERROR")))
        .filter(|e| !e["messageFormat"].as_str().unwrap_or_default().contains("configured to trust ALL X.509 certificates"))
        .map(|e| format!("{} {}", e["logLevel"], e["messageFormat"]))
        .collect()
}

async fn await_until<F: std::future::Future<Output = bool>>(reason: &str, mut condition: impl FnMut() -> F) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition().await && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(condition().await, "{reason}");
}

async fn await_received_once(server: &common::Running, path: &str) {
    let port = server.port;
    let deadline = Instant::now() + Duration::from_secs(10);
    while requests_received(port, path).await < 1 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // and a little longer, for a second copy to show
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(requests_received(port, path).await, 1, "the request sent before the reset was received, once");
    assert_eq!(common::send(port, "GET", path, "").await.status, 404, "the request was matched, using up its expectation");
    await_until("every connection closed", || std::future::ready(server.server.inbound_connection_count() == 0)).await;
}

/// The client: the raw TCP socket (reset at the end) and what the requests are written through.
enum Client {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Client {
    fn write(&mut self, bytes: &[u8]) {
        match self {
            Client::Plain(s) => s.write_all(bytes).unwrap(),
            Client::Tls(s) => {
                s.write_all(bytes).unwrap();
                s.flush().unwrap();
            }
        }
    }

    fn raw(&self) -> &TcpStream {
        match self {
            Client::Plain(s) => s,
            Client::Tls(s) => s.get_ref(),
        }
    }
}

fn start_tls_with_h2(socket: TcpStream) -> Client {
    let name = rustls_pki_types::ServerName::try_from("127.0.0.1").unwrap();
    let mut connection = rustls::ClientConnection::new(common::tls_client_config(b"h2"), name).unwrap();
    let mut socket = socket;
    while connection.is_handshaking() {
        connection.complete_io(&mut socket).unwrap();
    }
    assert_eq!(connection.alpn_protocol(), Some(&b"h2"[..]), "ALPN");
    Client::Tls(Box::new(rustls::StreamOwned::new(connection, socket)))
}

/// Waits until the client has stopped taking the response: the server's write is blocked on the full buffers.
fn await_stalled() {
    std::thread::sleep(Duration::from_millis(1500));
}

async fn send_behind_a_stalled_response_then_reset(server: &common::Running, open: impl FnOnce(TcpStream) -> Client + Send + 'static, first: Vec<u8>, next: Vec<u8>) {
    let port = server.port;
    let before = logged_at_warn_or_above(port).await;
    let socket = tokio::task::spawn_blocking(move || connect(port)).await.unwrap();
    let mut client = tokio::task::spawn_blocking(move || {
        let mut client = open(socket);
        client.write(&first);
        client
    })
    .await
    .unwrap();
    await_until("the first request was received", || async { requests_received(port, "/large").await == 1 }).await;
    tokio::task::spawn_blocking(move || {
        await_stalled();
        client.write(&next);
        socket2::SockRef::from(client.raw()).set_linger(Some(Duration::ZERO)).unwrap();
        drop(client);
    })
    .await
    .unwrap();
    await_received_once(server, "/next").await;
    assert_eq!(requests_received(port, "/large").await, 1, "the first request was received once");
    assert_eq!(logged_at_warn_or_above(port).await, before, "nothing logged at WARN or above for a client that reset");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http1_request_on_a_direct_connection() {
    let server = start().await;
    let port = server.port;
    send_behind_a_stalled_response_then_reset(&server, Client::Plain, http1_get(port, "/large"), http1_get(port, "/next")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http1_request_through_a_connect_tunnel() {
    let server = start().await;
    let port = server.port;
    let open = move |mut socket: TcpStream| {
        open_connect_tunnel(&mut socket, port);
        Client::Plain(socket)
    };
    send_behind_a_stalled_response_then_reset(&server, open, http1_get(port, "/large"), http1_get(port, "/next")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_h2c_request_on_a_direct_connection() {
    let server = start().await;
    let port = server.port;
    send_behind_a_stalled_response_then_reset(&server, Client::Plain, http2_preface_and_get(port, "http", "/large"), http2_get(port, 3, "http", "/next")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_h2c_request_through_a_connect_tunnel() {
    let server = start().await;
    let port = server.port;
    let open = move |mut socket: TcpStream| {
        open_connect_tunnel(&mut socket, port);
        Client::Plain(socket)
    };
    send_behind_a_stalled_response_then_reset(&server, open, http2_preface_and_get(port, "http", "/large"), http2_get(port, 3, "http", "/next")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_h2_request_on_a_direct_tls_connection() {
    let server = start().await;
    let port = server.port;
    send_behind_a_stalled_response_then_reset(&server, start_tls_with_h2, http2_preface_and_get(port, "https", "/large"), http2_get(port, 3, "https", "/next")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_h2_request_through_a_connect_tunnel_with_tls() {
    let server = start().await;
    let port = server.port;
    let open = move |mut socket: TcpStream| {
        open_connect_tunnel(&mut socket, port);
        start_tls_with_h2(socket)
    };
    send_behind_a_stalled_response_then_reset(&server, open, http2_preface_and_get(port, "https", "/large"), http2_get(port, 3, "https", "/next")).await;
}

/// A TLS 1.3 client's last handshake flight (its Finished) needs nothing more from the server, so it is held back and
/// sent with the request, and the connection reset at once.
async fn send_with_the_last_handshake_message_then_reset(open: fn(&mut TcpStream, u16)) {
    let server = start().await;
    let port = server.port;
    let before = logged_at_warn_or_above(port).await;
    tokio::task::spawn_blocking(move || {
        let mut socket = connect(port);
        open(&mut socket, port);
        let name = rustls_pki_types::ServerName::try_from("127.0.0.1").unwrap();
        let mut connection = rustls::ClientConnection::new(common::tls_client_config_for(b"h2", &[&rustls::version::TLS13]), name).unwrap();
        let mut server_heard = false;
        while connection.is_handshaking() {
            if connection.wants_write() && !server_heard {
                connection.write_tls(&mut socket).unwrap();
                continue;
            }
            if connection.read_tls(&mut socket).unwrap() == 0 {
                panic!("connection closed during the TLS handshake");
            }
            connection.process_new_packets().unwrap();
            server_heard = true;
        }
        assert_eq!(connection.alpn_protocol(), Some(&b"h2"[..]), "ALPN");
        connection.writer().write_all(&http2_preface_and_get(port, "https", "/next")).unwrap();
        let mut last_flight_and_request = Vec::new();
        while connection.wants_write() {
            connection.write_tls(&mut last_flight_and_request).unwrap();
        }
        socket.write_all(&last_flight_and_request).unwrap();
        socket2::SockRef::from(&socket).set_linger(Some(Duration::ZERO)).unwrap();
        drop(socket);
    })
    .await
    .unwrap();
    await_received_once(&server, "/next").await;
    assert_eq!(logged_at_warn_or_above(port).await, before, "nothing logged at WARN or above for a client that reset");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_h2_request_sent_with_the_last_tls_handshake_message_on_a_direct_connection() {
    send_with_the_last_handshake_message_then_reset(|_, _| {}).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_h2_request_sent_with_the_last_tls_handshake_message_through_a_connect_tunnel() {
    send_with_the_last_handshake_message_then_reset(open_connect_tunnel).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_h2_request_sent_with_the_last_tls_handshake_message_through_a_socks_tunnel() {
    send_with_the_last_handshake_message_then_reset(open_socks5_tunnel).await;
}

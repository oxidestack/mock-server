//! Port of `RelayTunnelFirstBytesIntegrationTest`: a whole request sent as the first bytes of a CONNECT
//! or SOCKS tunnel, or of a direct connection, in one write, by a client that leaves (FIN) or resets (`SO_LINGER` 0)
//! as soon as it has written it. MockServer must receive the request, both legs of a tunnel must close, and nothing is
//! logged at WARN or above. Upstream counts the tunnel's loopback leg as an open inbound connection; the stand-in
//! behind the rs-process run counts the server's sockets, and mock-server relays a tunnel in-process with no
//! loopback socket, so the cases that wait for two legs run here against `Server::inbound_connection_count()`.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::common;

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HTTP2_MAX_FRAME_SIZE: usize = 16_384;
const HTTP2_SETTINGS: u8 = 0x4;
const ATTEMPTS: usize = 10;

#[derive(Clone, Copy)]
enum Opener {
    Direct,
    Connect,
    Socks5,
}

async fn start() -> common::Running {
    let server = common::start(&[("logLevel", "WARN"), ("startupWarmup", "false"), ("proxySetup", "false")]).await;
    common::expect(server.port, &serde_json::json!({"httpRequest": {"path": "/first"}, "httpResponse": {"body": "answered"}})).await;
    server
}

async fn read_exact<R: AsyncRead + Unpin>(io: &mut R, n: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(10), io.read_exact(&mut bytes)).await.expect("read within 10s").expect("read");
    bytes
}

async fn open(opener: Opener, socket: &mut TcpStream, port: u16) {
    match opener {
        Opener::Direct => {}
        Opener::Connect => {
            socket.write_all(format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes()).await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.extend(read_exact(socket, 1).await);
            }
            assert!(String::from_utf8_lossy(&head).contains("200"), "{}", String::from_utf8_lossy(&head));
        }
        Opener::Socks5 => {
            socket.write_all(&[5, 1, 0]).await.unwrap();
            assert_eq!(read_exact(socket, 2).await, vec![5, 0]);
            socket.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, (port >> 8) as u8, port as u8]).await.unwrap();
            let reply = read_exact(socket, 5).await;
            assert_eq!(reply[1], 0, "SOCKS5 success");
            let rest = if reply[3] == 3 { reply[4] as usize } else if reply[3] == 1 { 3 } else { 15 };
            read_exact(socket, rest + 2).await;
        }
    }
}

fn frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    out.extend(&(payload.len() as u32).to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend(stream.to_be_bytes());
    out.extend(payload);
}

fn http1_request(port: u16, body: usize) -> Vec<u8> {
    let mut request = format!("POST /first HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {body}\r\n\r\n").into_bytes();
    request.extend(vec![b'x'; body]);
    request
}

/// The client preface, an empty SETTINGS frame, and one POST on stream 1: HEADERS, then DATA frames ending the stream.
fn http2_request(port: u16, body: usize) -> Vec<u8> {
    let mut request = HTTP2_PREFACE.to_vec();
    frame(&mut request, HTTP2_SETTINGS, 0, 0, &[]);
    let mut headers = vec![0x83, 0x86];
    for (index, value) in [(0x04u8, "/first".to_string()), (0x01, format!("127.0.0.1:{port}"))] {
        headers.push(index);
        headers.push(value.len() as u8);
        headers.extend(value.as_bytes());
    }
    frame(&mut request, 0x1, if body == 0 { 0x5 } else { 0x4 }, 1, &headers);
    let mut sent = 0;
    while sent < body {
        let length = HTTP2_MAX_FRAME_SIZE.min(body - sent);
        sent += length;
        frame(&mut request, 0x0, if sent == body { 0x1 } else { 0x0 }, 1, &vec![b'x'; length]);
    }
    request
}

async fn control_plane(port: u16, path: &str, body: &str) -> String {
    common::send(port, "PUT", path, body).await.body
}

async fn requests_received(port: u16) -> usize {
    let received = control_plane(port, "/mockserver/retrieve?type=REQUESTS&format=JSON", r#"{"path":"/first"}"#).await;
    if received.trim().is_empty() {
        return 0;
    }
    serde_json::from_str::<serde_json::Value>(&received).unwrap().as_array().map_or(0, |a| a.len())
}

async fn logged_at_warn_or_above(port: u16) -> Vec<String> {
    let entries = control_plane(port, "/mockserver/retrieve?type=LOGS&format=LOG_ENTRIES", "").await;
    let entries: serde_json::Value = serde_json::from_str(&entries).unwrap_or(serde_json::Value::Array(vec![]));
    entries
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| matches!(e["logLevel"].as_str(), Some("WARN" | "ERROR")))
        .map(|e| format!("{} {}", e["logLevel"], e["messageFormat"]))
        .collect()
}

async fn await_count(server: &common::Running, reason: &str, count: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while server.server.inbound_connection_count() != count && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(server.server.inbound_connection_count(), count, "{reason}");
}

async fn send_as_first_bytes_and_leave(opener: Opener, request: impl Fn(u16) -> Vec<u8>) {
    let server = start().await;
    let port = server.port;
    let before = logged_at_warn_or_above(port).await;
    {
        let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        open(opener, &mut socket, port).await;
        await_count(&server, "only the client's leg and the loopback leg are open", 2).await;
        socket.write_all(&request(port)).await.unwrap();
        socket.flush().await.unwrap();
        // closed with nothing unread, so the client sends a FIN and not a reset
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while requests_received(port).await == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(requests_received(port).await, 1, "the request reached MockServer");
    await_count(&server, "both legs closed", 0).await;
    assert_eq!(logged_at_warn_or_above(port).await, before, "nothing logged at WARN or above for a client that left");
}

async fn send_as_first_bytes_and_reset_each_time(opener: Opener, connections_open: usize, request: impl Fn(u16) -> Vec<u8>) {
    let server = start().await;
    let port = server.port;
    let before = logged_at_warn_or_above(port).await;
    for _ in 0..ATTEMPTS {
        {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            open(opener, &mut socket, port).await;
            await_count(&server, "the connection is open, with its tunnel's loopback if it has one", connections_open).await;
            socket.write_all(&request(port)).await.unwrap();
            socket.flush().await.unwrap();
            socket2::SockRef::from(&socket).set_linger(Some(Duration::ZERO)).unwrap();
        }
        await_count(&server, "every leg closed", 0).await;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while requests_received(port).await < ATTEMPTS && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(requests_received(port).await, ATTEMPTS, "requests received of {ATTEMPTS}");
    assert_eq!(logged_at_warn_or_above(port).await, before, "nothing logged at WARN or above for a client that reset");
}

/// Reads frames until a SETTINGS frame that is not an acknowledgement.
async fn await_server_settings<R: AsyncRead + Unpin>(input: &mut R) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let header = read_exact(input, 9).await;
        let length = (header[0] as usize) << 16 | (header[1] as usize) << 8 | header[2] as usize;
        read_exact(input, length).await;
        if header[3] == HTTP2_SETTINGS && header[4] & 0x1 == 0 {
            return;
        }
    }
    panic!("no SETTINGS from the server within 10 seconds");
}

async fn start_tls_with_h2<S: AsyncRead + AsyncWrite + Unpin>(socket: S) -> tokio_rustls::client::TlsStream<S> {
    let name = rustls_pki_types::ServerName::try_from("127.0.0.1").unwrap();
    let tls = tokio_rustls::TlsConnector::from(common::tls_client_config(b"h2")).connect(name, socket).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]), "ALPN");
    tls
}

fn h2(body: usize) -> impl Fn(u16) -> Vec<u8> {
    move |port| http2_request(port, body)
}

fn h1(body: usize) -> impl Fn(u16) -> Vec<u8> {
    move |port| http1_request(port, body)
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http2_request_sent_as_the_first_bytes_of_a_connect_tunnel_by_a_client_that_leaves_at_once() {
    send_as_first_bytes_and_leave(Opener::Connect, h2(16_000)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http2_request_sent_as_the_first_bytes_of_a_socks_tunnel_by_a_client_that_leaves_at_once() {
    send_as_first_bytes_and_leave(Opener::Socks5, h2(60_000)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http1_request_sent_as_the_first_bytes_of_a_connect_tunnel_by_a_client_that_leaves_at_once() {
    send_as_first_bytes_and_leave(Opener::Connect, h1(16_000)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http1_request_sent_as_the_first_bytes_of_a_socks_tunnel_by_a_client_that_leaves_at_once() {
    send_as_first_bytes_and_leave(Opener::Socks5, h1(16_000)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http2_request_with_no_body_sent_on_a_direct_connection_by_a_client_that_resets() {
    send_as_first_bytes_and_reset_each_time(Opener::Direct, 1, h2(0)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http2_request_sent_on_a_direct_connection_by_a_client_that_resets() {
    send_as_first_bytes_and_reset_each_time(Opener::Direct, 1, h2(16_000)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http2_request_with_several_data_frames_sent_on_a_direct_connection_by_a_client_that_resets() {
    send_as_first_bytes_and_reset_each_time(Opener::Direct, 1, h2(60_000)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http2_request_with_no_body_sent_through_a_connect_tunnel_by_a_client_that_resets() {
    send_as_first_bytes_and_reset_each_time(Opener::Connect, 2, h2(0)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http2_request_sent_through_a_connect_tunnel_by_a_client_that_resets() {
    send_as_first_bytes_and_reset_each_time(Opener::Connect, 2, h2(16_000)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http2_request_with_several_data_frames_sent_through_a_connect_tunnel_by_a_client_that_resets() {
    send_as_first_bytes_and_reset_each_time(Opener::Connect, 2, h2(60_000)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http2_request_with_no_body_sent_through_a_socks_tunnel_by_a_client_that_resets() {
    send_as_first_bytes_and_reset_each_time(Opener::Socks5, 2, h2(0)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http2_request_sent_through_a_socks_tunnel_by_a_client_that_resets() {
    send_as_first_bytes_and_reset_each_time(Opener::Socks5, 2, h2(16_000)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http2_request_with_several_data_frames_sent_through_a_socks_tunnel_by_a_client_that_resets() {
    send_as_first_bytes_and_reset_each_time(Opener::Socks5, 2, h2(60_000)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http1_request_sent_through_a_connect_tunnel_by_a_client_that_resets() {
    send_as_first_bytes_and_reset_each_time(Opener::Connect, 2, h1(16_000)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_receive_an_http1_request_sent_through_a_socks_tunnel_by_a_client_that_resets() {
    send_as_first_bytes_and_reset_each_time(Opener::Socks5, 2, h1(16_000)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_send_settings_when_the_tls_handshake_of_a_connect_tunnel_completes_before_the_client_sends_anything() {
    let server = start().await;
    let port = server.port;
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    open(Opener::Connect, &mut socket, port).await;
    let mut tls = start_tls_with_h2(socket).await;
    // the tunnel's HTTP/2 handler is added as the handshake completes, before any request bytes
    await_server_settings(&mut tls).await;
}

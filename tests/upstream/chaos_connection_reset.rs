//! Port of `ChaosConnectionResetIntegrationTest` (9.2.0): the TCP chaos faults `resetPeer` and
//! `resetMidResponse` reach the client as a TCP RST, not a clean close, `resetMidResponse` only after the whole
//! response: over plain HTTP, over TLS (no `close_notify` before the RST) and through CONNECT and SOCKS tunnels.

use std::io::ErrorKind;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common;
use crate::reset_connection::{connect_tunnel, raw_after_tls, tls};

async fn server() -> common::Running {
    let server = common::start(&[("connectionLifecycleChaosEnabled", "true")]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/ok"}, "httpResponse": {"body": "hello-world"}})).await;
    server
}

/// Sends `GET /ok` and reads until the connection ends, which must be with a reset, never cleanly: what arrived first.
async fn read_until_reset<S: AsyncRead + AsyncWrite + Unpin>(socket: &mut S, port: u16) -> String {
    socket.write_all(format!("GET /ok HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
    socket.flush().await.unwrap();
    let mut received = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match tokio::time::timeout(Duration::from_secs(10), socket.read(&mut chunk)).await.expect("the connection must end") {
            Ok(0) => panic!("expected a connection reset but the connection ended cleanly after: {}", String::from_utf8_lossy(&received)),
            Ok(n) => received.extend_from_slice(&chunk[..n]),
            Err(e) => {
                assert_eq!(e.kind(), ErrorKind::ConnectionReset, "{e:?} after {}", String::from_utf8_lossy(&received));
                return String::from_utf8_lossy(&received).into_owned();
            }
        }
    }
}

async fn assert_connection_reset<S: AsyncRead + AsyncWrite + Unpin>(socket: &mut S, port: u16) {
    assert_eq!(read_until_reset(socket, port).await, "", "nothing is answered before the reset");
}

async fn assert_response_then_reset<S: AsyncRead + AsyncWrite + Unpin>(socket: &mut S, port: u16) {
    let received = read_until_reset(socket, port).await;
    assert!(received.starts_with("HTTP/1.1 200"), "{received}");
    assert!(received.contains("hello-world"), "{received}");
}

/// Over TLS the response is read raw (`reset_connection::raw_after_tls`): the whole response is written (an application
/// record), then a RST with no `close_notify` before it.
async fn assert_tls_response_then_reset(socket: tokio_rustls::client::TlsStream<tokio::net::TcpStream>, port: u16) {
    let (bytes, end, alert) = raw_after_tls(socket, port, "/ok").await;
    assert!(bytes > 0, "the response is written before the reset");
    assert_eq!(end, Err(ErrorKind::ConnectionReset));
    assert!(!alert, "no close_notify before the RST");
}

/// Registered once the tunnel is open, so it is the loopback leg, not the client's own connection, that resets.
fn reset_peer_on_relay_loopback(server: &common::Running) {
    for host in ["127.0.0.1", "0:0:0:0:0:0:0:1"] {
        server.server.put_tcp_chaos(host, &json!({"resetPeer": true}), 0).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_peer_over_http() {
    let s = server().await;
    s.server.put_tcp_chaos("127.0.0.1", &json!({"resetPeer": true}), 0).unwrap();
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", s.port)).await.unwrap();
    assert_connection_reset(&mut socket, s.port).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_peer_over_tls_without_close_notify() {
    let s = server().await;
    s.server.put_tcp_chaos("127.0.0.1", &json!({"resetPeer": true}), 0).unwrap();
    let mut socket = tls(tokio::net::TcpStream::connect(("127.0.0.1", s.port)).await.unwrap()).await;
    assert_connection_reset(&mut socket, s.port).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_peer_of_tunnelled_client() {
    let s = server().await;
    let mut socket = connect_tunnel(s.port).await;
    reset_peer_on_relay_loopback(&s);
    assert_connection_reset(&mut socket, s.port).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_peer_of_tunnelled_tls_client() {
    let s = server().await;
    let socket = connect_tunnel(s.port).await;
    reset_peer_on_relay_loopback(&s);
    let mut socket = tls(socket).await;
    assert_connection_reset(&mut socket, s.port).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_mid_response_over_http() {
    let s = server().await;
    s.server.put_tcp_chaos("localhost", &json!({"resetMidResponse": true}), 0).unwrap();
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", s.port)).await.unwrap();
    assert_response_then_reset(&mut socket, s.port).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_mid_response_over_tls_without_close_notify() {
    let s = server().await;
    s.server.put_tcp_chaos("localhost", &json!({"resetMidResponse": true}), 0).unwrap();
    let socket = tls(tokio::net::TcpStream::connect(("127.0.0.1", s.port)).await.unwrap()).await;
    assert_tls_response_then_reset(socket, s.port).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_mid_response_of_tunnelled_client() {
    let s = server().await;
    s.server.put_tcp_chaos("localhost", &json!({"resetMidResponse": true}), 0).unwrap();
    let mut socket = connect_tunnel(s.port).await;
    assert_response_then_reset(&mut socket, s.port).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_mid_response_of_tunnelled_tls_client() {
    let s = server().await;
    s.server.put_tcp_chaos("localhost", &json!({"resetMidResponse": true}), 0).unwrap();
    let socket = connect_tunnel(s.port).await;
    assert_tls_response_then_reset(tls(socket).await, s.port).await;
}

async fn socks5_tunnel(port: u16) -> tokio::net::TcpStream {
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    socket.read_exact(&mut method).await.unwrap();
    assert_eq!(method[1], 0);
    socket.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, (port >> 8) as u8, port as u8]).await.unwrap();
    let mut reply = [0u8; 5];
    socket.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS5 connect must succeed");
    let mut rest = vec![0u8; usize::from(reply[4]) + 2];
    socket.read_exact(&mut rest).await.unwrap();
    socket
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_mid_response_of_socks5_tunnelled_client() {
    let s = server().await;
    s.server.put_tcp_chaos("localhost", &json!({"resetMidResponse": true}), 0).unwrap();
    let mut socket = socks5_tunnel(s.port).await;
    assert_response_then_reset(&mut socket, s.port).await;
}

/// An h2 client by hand that writes nothing after its request (not even a SETTINGS ack): the reset can then only be
/// read, after every frame sent before it. The response HEADERS and DATA must arrive before it.
async fn assert_http2_response_then_reset(tunnel: tokio::net::TcpStream, port: u16) {
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(common::tls_client_config(b"h2")).connect(name, tunnel).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let authority = format!("localhost:{port}");
    let mut headers = vec![0x82u8, 0x87, 0x44, 3];
    headers.extend_from_slice(b"/ok");
    headers.extend_from_slice(&[0x41, authority.len() as u8]);
    headers.extend_from_slice(authority.as_bytes());
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&[0, 0, headers.len() as u8, 1, 5, 0, 0, 0, 1]);
    out.extend_from_slice(&headers);
    tls.write_all(&out).await.unwrap();
    tls.flush().await.unwrap();
    let mut response_headers = false;
    let mut data = Vec::new();
    loop {
        let mut header = [0u8; 9];
        let read = tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut header)).await.expect("the connection must end");
        if let Err(e) = read {
            assert_eq!(e.kind(), ErrorKind::ConnectionReset, "expected a reset, not a clean end: {e:?} after {}", String::from_utf8_lossy(&data));
            break;
        }
        let length = (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
        let stream = u32::from_be_bytes([header[5] & 0x7f, header[6], header[7], header[8]]);
        let mut payload = vec![0u8; length];
        if let Err(e) = tls.read_exact(&mut payload).await {
            assert_eq!(e.kind(), ErrorKind::ConnectionReset, "{e:?}");
            break;
        }
        match (stream, header[3]) {
            (1, 1) => response_headers = true,
            (1, 0) => data.extend_from_slice(&payload),
            _ => {}
        }
    }
    assert!(response_headers, "the response HEADERS arrive before the reset");
    assert_eq!(String::from_utf8_lossy(&data), "hello-world");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_mid_response_of_tunnelled_http2_tls_client() {
    let s = server().await;
    s.server.put_tcp_chaos("localhost", &json!({"resetMidResponse": true}), 0).unwrap();
    let tunnel = connect_tunnel(s.port).await;
    assert_http2_response_then_reset(tunnel, s.port).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_mid_response_of_socks5_tunnelled_http2_tls_client() {
    let s = server().await;
    s.server.put_tcp_chaos("localhost", &json!({"resetMidResponse": true}), 0).unwrap();
    let tunnel = socks5_tunnel(s.port).await;
    assert_http2_response_then_reset(tunnel, s.port).await;
}

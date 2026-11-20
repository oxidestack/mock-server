//! Port of upstream 9f8deba46's `TlsHandshakeTimeoutIntegrationTest` (after 8.0.0, adopted ahead of the oracle): a TLS handshake the server terminates, on its own port or inside a CONNECT tunnel, is bounded by
//! `socketConnectionTimeoutInMillis`. A client sends a real ClientHello and then stalls; the server closes the
//! connection at the configured bound, not at Netty's fixed 10 s default (8.0.0's bound whatever the setting, and the
//! fallback for a non-positive value). Neither image writes or logs anything at the close.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::common;

const CONFIGURED_BOUND: Duration = Duration::from_millis(1500);
/// Above the configured bound, well below the 10 s default.
const READ_CEILING: Duration = Duration::from_millis(6000);

/// The first flight of a TLS client: a ClientHello for `localhost`.
fn client_hello() -> Vec<u8> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut client = rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    hello
}

/// Reads and discards what the server sends (its first flight) until it closes; how long that took from `started`.
fn time_until_closed(socket: &mut TcpStream, started: Instant) -> Duration {
    socket.set_read_timeout(Some(READ_CEILING + Duration::from_secs(2))).unwrap();
    let mut buffer = [0u8; 4096];
    while let Ok(n) = socket.read(&mut buffer) {
        if n == 0 {
            break;
        }
    }
    started.elapsed()
}

fn assert_bounded(elapsed: Duration) {
    assert!(elapsed >= CONFIGURED_BOUND - Duration::from_millis(300), "ended before the configured bound: {elapsed:?}");
    assert!(elapsed < READ_CEILING, "not bounded by the configured connection timeout: {elapsed:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_inbound_tls_handshake_is_bounded_by_the_configured_connection_timeout() {
    let server = common::start(&[("socketConnectionTimeoutInMillis", "1500")]).await;
    let port = server.port;
    let elapsed = tokio::task::spawn_blocking(move || {
        let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        socket.write_all(&client_hello()).unwrap();
        let started = Instant::now();
        time_until_closed(&mut socket, started)
    })
    .await
    .unwrap();
    assert_bounded(elapsed);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_tunnel_inbound_tls_handshake_is_bounded_by_the_configured_connection_timeout() {
    let server = common::start(&[("socketConnectionTimeoutInMillis", "1500")]).await;
    // the tunnel's target: never reached, the server terminates the tunnelled TLS itself
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let (port, target_port) = (server.port, target.local_addr().unwrap().port());
    let elapsed = tokio::task::spawn_blocking(move || {
        let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        socket.write_all(format!("CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n").as_bytes()).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && socket.read(&mut byte).unwrap() == 1 {
            head.push(byte[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 200 OK"), "{}", String::from_utf8_lossy(&head));
        socket.write_all(&client_hello()).unwrap();
        let started = Instant::now();
        time_until_closed(&mut socket, started)
    })
    .await
    .unwrap();
    drop(target);
    assert_bounded(elapsed);
    server.server.shutdown().await;
}

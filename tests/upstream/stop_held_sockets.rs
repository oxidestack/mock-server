//! Stopping closes the sockets TCP `timeout` and `slowClose` chaos hold back. Not a port of an upstream
//! test: the oracle answers it. `TcpChaosHandler.close` swallows (`timeout`) or postpones (`slowClose`) the close of a
//! channel, but the channel stays registered with the worker event loop, whose `shutdownGracefully` at the end of
//! `LifeCycle.stopAsync` closes it through `Channel.Unsafe`, past the handler. Asked of `mockserver/mockserver:8.0.0`
//! with a raw-socket client in the oracle's network namespace: a `timeout`-held socket read EOF 0.15 s after
//! `PUT /mockserver/stop`, a `slowClose`-held one 0.38 s after it, before its 2 s delay ran out.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::common;

/// One keep-alive exchange; the response read up to its content-length.
async fn exchange(stream: &mut TcpStream, method: &str, path: &str, body: &str) -> String {
    stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    let mut response = Vec::new();
    loop {
        let mut chunk = [0u8; 8192];
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "the control connection closed");
        response.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&response).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let length = text[..end].lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length: ").map(|v| v.trim().parse::<usize>().unwrap())).unwrap_or(0);
            if response.len() >= end + 4 + length {
                return text;
            }
        }
    }
}

/// Whether the peer closes `stream` within `wait`: EOF or a reset, after any bytes still in flight.
async fn closes_within(stream: &mut TcpStream, wait: Duration) -> bool {
    tokio::time::timeout(wait, async {
        let mut sink = [0u8; 4096];
        while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
    })
    .await
    .is_ok()
}

/// A server whose fresh connections from 127.0.0.1 carry `chaos`, and one such connection after a `Connection: close`
/// exchange whose close the chaos holds back. Chaos goes over a control connection accepted before it, so that one
/// is unarmed.
async fn held_socket(chaos: &str) -> (common::Running, TcpStream) {
    let server = common::start(&[]).await;
    let mut control = TcpStream::connect(("127.0.0.1", server.port)).await.unwrap();
    assert!(exchange(&mut control, "PUT", "/mockserver/expectation", r#"{"httpRequest":{"path":"/held"},"httpResponse":{"statusCode":202}}"#).await.starts_with("HTTP/1.1 201"));
    assert!(exchange(&mut control, "PUT", "/mockserver/tcpChaos", &format!(r#"{{"host":"127.0.0.1","chaos":{chaos}}}"#)).await.starts_with("HTTP/1.1 200"));
    let mut held = TcpStream::connect(("127.0.0.1", server.port)).await.unwrap();
    held.write_all(b"GET /held HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut head = [0u8; 12];
    held.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 202");
    (server, held)
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_closes_a_socket_timeout_chaos_holds() {
    let (server, mut held) = held_socket(r#"{"timeout":true}"#).await;
    assert!(!closes_within(&mut held, Duration::from_millis(500)).await, "`timeout` holds the socket open");
    tokio::time::timeout(Duration::from_secs(15), server.server.stop_async()).await.expect("stop finishes").unwrap();
    assert!(closes_within(&mut held, Duration::from_secs(5)).await, "stopping closes the socket `timeout` holds");
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_closes_a_socket_slow_close_chaos_holds_before_its_delay() {
    let (server, mut held) = held_socket(r#"{"slowClose":true}"#).await;
    let response = tokio::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(15), server.server.stop_async()).await.expect("stop finishes").unwrap();
    assert!(closes_within(&mut held, Duration::from_millis(1500)).await, "stopping closes the socket `slowClose` holds");
    assert!(response.elapsed() < Duration::from_millis(1800), "closed by the stop, not by the 2 s slow close: {:?}", response.elapsed());
}

//! `RespondBeforeBodyIntegrationTest.shouldRespondBeforeConsumingLargeRequestBody`, repeated: a `respondBeforeBody`
//! expectation answers a POST from its head while the client has sent only part of its body, then closes. The
//! client must read the whole response and then an end of stream, never a connection reset. The
//! reset was intermittent: it happened when the body bytes reached the server after it read the head, so the
//! server closed with them unread in its receive buffer, and the kernel answered the close with a RST.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::common;

/// One run of the upstream test's socket exchange; `pause` separates the head from the preamble, which widens
/// the window in which the preamble arrives after the server has read the head. Before the fix 3 of 4 runs
/// reset (every run with a pause).
fn exchange(port: u16, pause: Duration) -> Result<(), String> {
    let mut socket = std::net::TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    socket.set_nodelay(true).unwrap();
    let start = Instant::now();
    let head = "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 50000000\r\nConnection: keep-alive\r\n\r\n";
    socket.write_all(head.as_bytes()).map_err(|e| format!("writing the head: {e}"))?;
    if !pause.is_zero() {
        std::thread::sleep(pause);
    }
    socket.write_all(&[0u8; 1024]).map_err(|e| format!("writing the preamble: {e}"))?;
    // Upstream's client runs its assertions (and loads their classes) between writing and reading the end of
    // stream; reading late lets a RST arrive first.
    std::thread::sleep(Duration::from_millis(30));
    let mut buf = [0u8; 8192];
    let read = socket.read(&mut buf).map_err(|e| format!("reading the response: {e}"))?;
    let text = String::from_utf8_lossy(&buf[..read]);
    if !(text.contains("403") && text.contains("forbidden")) {
        return Err(format!("unexpected response: {text:?}"));
    }
    if start.elapsed() >= Duration::from_secs(5) {
        return Err(format!("response took {:?}", start.elapsed()));
    }
    let mut next = [0u8; 1];
    match socket.read(&mut next) {
        Ok(0) => Ok(()),
        Ok(_) => Err("data after the response".into()),
        Err(e) => Err(format!("reading the end of stream: {e}")),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_respond_before_consuming_large_request_body_without_reset() {
    let running = common::start(&[]).await;
    common::expect(
        running.port,
        &json!({
            "httpRequest": {"method": "POST", "path": "/upload", "respondBeforeBody": true},
            "httpResponse": {"statusCode": 403, "body": "forbidden", "connectionOptions": {"closeSocket": true}}
        }),
    )
    .await;
    let port = running.port;
    let failures = tokio::task::spawn_blocking(move || {
        let pauses = [Duration::ZERO, Duration::from_millis(1), Duration::from_millis(5), Duration::from_millis(20)];
        (0..80)
            .filter_map(|i| exchange(port, pauses[i % pauses.len()]).err().map(|e| format!("run {i}: {e}")))
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    assert!(failures.is_empty(), "{} of 80 exchanges failed, first: {:?}", failures.len(), failures.first());
}

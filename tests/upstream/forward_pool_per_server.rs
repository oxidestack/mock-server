//! The forward connection pool belongs to each server, as upstream's `HttpForwardConnectionPool` belongs
//! to the `NettyHttpClient` of each MockServer's `HttpActionHandler`, its channels on that server's event loop group:
//! two in-process servers never reuse each other's upstream connections, and stopping a server closes the idle
//! connections its pool holds.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::common;

/// A keep-alive HTTP/1.1 upstream on an ephemeral port that counts the connections it accepts and those its peer
/// closed.
struct CountingUpstream {
    port: u16,
    accepted: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
}

impl CountingUpstream {
    fn start() -> CountingUpstream {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted, closed) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let (on_accept, on_close) = (accepted.clone(), closed.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                on_accept.fetch_add(1, Ordering::SeqCst);
                let on_close = on_close.clone();
                std::thread::spawn(move || {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while let Ok(1) = stream.read(&mut byte) {
                        head.push(byte[0]);
                        if head.ends_with(b"\r\n\r\n") {
                            head.clear();
                            if stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").is_err() {
                                break;
                            }
                        }
                    }
                    on_close.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        CountingUpstream { port, accepted, closed }
    }
}

async fn forward_everything_to(port: u16, upstream: u16) {
    common::expect(port, &json!({ "httpRequest": { "path": "/pooled" }, "httpForward": { "host": "127.0.0.1", "port": upstream } })).await;
}

async fn wait_for(what: &str, counter: &AtomicUsize, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while counter.load(Ordering::SeqCst) != expected {
        assert!(Instant::now() < deadline, "{what}: {} instead of {expected}", counter.load(Ordering::SeqCst));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn each_server_forwards_on_its_own_pool_and_closes_it_on_stop() {
    let upstream = CountingUpstream::start();
    let first = common::start(&[]).await;
    let second = common::start(&[]).await;
    forward_everything_to(first.port, upstream.port).await;
    forward_everything_to(second.port, upstream.port).await;

    // the first server opens a connection and keeps it, then reuses it
    assert_eq!(common::send(first.port, "GET", "/pooled", "").await.status, 200);
    assert_eq!(common::send(first.port, "GET", "/pooled", "").await.status, 200);
    wait_for("connections after the first server's forwards", &upstream.accepted, 1).await;

    // the second server does not take the first one's idle connection: it opens one of its own, then reuses it
    assert_eq!(common::send(second.port, "GET", "/pooled", "").await.status, 200);
    assert_eq!(common::send(second.port, "GET", "/pooled", "").await.status, 200);
    wait_for("connections after the second server's forwards", &upstream.accepted, 2).await;
    assert_eq!(upstream.closed.load(Ordering::SeqCst), 0, "both pooled connections still open");

    // stopping the first server closes its idle connection, and only that one
    first.server.shutdown().await;
    wait_for("connections closed after the first server stopped", &upstream.closed, 1).await;
    assert_eq!(common::send(second.port, "GET", "/pooled", "").await.status, 200);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(upstream.accepted.load(Ordering::SeqCst), 2, "the second server still reuses its own connection");
    assert_eq!(upstream.closed.load(Ordering::SeqCst), 1);

    second.server.shutdown().await;
    wait_for("connections closed after the second server stopped", &upstream.closed, 2).await;
}

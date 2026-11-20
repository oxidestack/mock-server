//! `NettyAssymetricBinaryForwardingIntegrationTest`: non-HTTP bytes relayed to a port-forward target, which never
//! answers, told to a `binaryProxyListener`.
//! Upstream's listener is a Java lambda in the test JVM; here it is a Rust closure on the embedded server.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::common;

/// Upstream's `FlexibleServer`: each accepted connection is read until it closes. What it has received is every
/// connection's bytes, joined in the order the connections were accepted (each client connection is relayed on one
/// upstream connection).
struct Upstream {
    port: u16,
    received: Arc<Mutex<std::collections::BTreeMap<usize, String>>>,
}

impl Upstream {
    fn received(&self) -> String {
        self.received.lock().unwrap().values().map(String::as_str).collect()
    }

    /// `connectionsThatReceivedData`.
    fn connections_that_received_data(&self) -> usize {
        self.received.lock().unwrap().values().filter(|t| !t.is_empty()).count()
    }
}

fn upstream() -> Upstream {
    // 127.0.0.1 itself, where MockServer connects
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let received: Arc<Mutex<std::collections::BTreeMap<usize, String>>> = Arc::default();
    let r = received.clone();
    std::thread::spawn(move || {
        for (index, socket) in listener.incoming().flatten().enumerate() {
            let r = r.clone();
            r.lock().unwrap().insert(index, String::new());
            std::thread::spawn(move || {
                let mut socket = socket;
                let mut buffer = vec![0; 10_000];
                // `readUntilClosed`
                while let Ok(n) = socket.read(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    r.lock().unwrap().get_mut(&index).unwrap().push_str(&String::from_utf8_lossy(&buffer[..n]));
                }
            });
        }
    });
    Upstream { port, received }
}

struct Counters {
    requests: Arc<AtomicUsize>,
    responses: Arc<AtomicUsize>,
}

/// `executeTestRun`: a port-forwarding server to the upstream with the listener installed.
async fn proxy(upstream: &Upstream, wait_for_response: bool) -> (common::Running, Counters) {
    let counters = Counters { requests: Arc::default(), responses: Arc::default() };
    let (requests, responses) = (counters.requests.clone(), counters.responses.clone());
    let mut config = mock_server::Config::for_tests()
        .with_binary_proxy_listener(move |exchange| {
            if !exchange.request.is_empty() {
                requests.fetch_add(1, Ordering::SeqCst);
            }
            if wait_for_response && exchange.response.wait(Duration::from_secs(10)).is_some() {
                responses.fetch_add(1, Ordering::SeqCst);
            }
        });
    config.port_forward = Some(("127.0.0.1".into(), upstream.port));
    crate::scratch_cwd::enter();
    let server = mock_server::Server::start(config).await.unwrap();
    let port = server.ports()[0];
    (common::Running { server, port }, counters)
}

fn send(port: u16, messages: &[&str]) {
    let mut socket = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    for m in messages {
        socket.write_all(m.as_bytes()).unwrap();
        socket.flush().unwrap();
        std::thread::sleep(Duration::from_millis(100));
    }
}

async fn until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !condition() {
        assert!(std::time::Instant::now() < deadline, "timed out waiting: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

const MESSAGE: &str = "Hello not world!\n";

#[tokio::test(flavor = "multi_thread")]
async fn send_non_http_traffic_without_response_from_server() {
    let upstream = upstream();
    let (server, _) = proxy(&upstream, true).await;
    let port = server.port;
    tokio::task::spawn_blocking(move || send(port, &[MESSAGE, MESSAGE])).await.unwrap();
    until("the upstream receives both messages", || upstream.received() == format!("{MESSAGE}{MESSAGE}")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn send_non_http_traffic_with_long_message_without_response_from_server() {
    let upstream = upstream();
    let (server, _) = proxy(&upstream, false).await;
    let message = format!("{}\n", "LongMessage".repeat(1000));
    let (port, m) = (server.port, message.clone());
    tokio::task::spawn_blocking(move || send(port, &[&m, &m])).await.unwrap();
    let expected = format!("{message}{message}");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while upstream.received() != expected && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let got = upstream.received();
    assert!(got == expected, "got {} bytes in {} connections, expected {}", got.len(), upstream.connections_that_received_data(), expected.len());
}

#[tokio::test(flavor = "multi_thread")]
async fn send_non_http_traffic_with_long_message_without_response_and_with_socket_close_between_each_message() {
    let upstream = upstream();
    let (server, _) = proxy(&upstream, true).await;
    let port = server.port;
    tokio::task::spawn_blocking(move || send(port, &[MESSAGE])).await.unwrap();
    until("the upstream receives the first message", || upstream.received() == MESSAGE).await;
    tokio::task::spawn_blocking(move || send(port, &[MESSAGE])).await.unwrap();
    until("the upstream receives the second message", || upstream.received() == format!("{MESSAGE}{MESSAGE}")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn send_non_http_traffic_without_response_and_with_socket_close_between_each_message() {
    let upstream = upstream();
    let (server, counters) = proxy(&upstream, true).await;
    let port = server.port;
    tokio::task::spawn_blocking(move || {
        send(port, &[MESSAGE]);
        send(port, &[MESSAGE]);
    })
    .await
    .unwrap();
    until("the upstream is called twice", || upstream.connections_that_received_data() == 2).await;
    until("the listener hears of two requests", || counters.requests.load(Ordering::SeqCst) == 2).await;
    assert_eq!(counters.responses.load(Ordering::SeqCst), 0, "the upstream never answers");
}

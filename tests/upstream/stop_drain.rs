//! `StopDrainIntegrationTest`: stopping drains in-flight requests for up to `stopDrainMillis`
//! (`LifeCycle.stopAsync`). Upstream drives the in-JVM server's counter directly
//! (`requestProcessingStarted/Complete`); these drive `Server`'s. Upstream's two configuration stores map onto
//! mock-server's sources: the `Configuration` instance becomes a property (`-Dmockserver.stopDrainMillis`), and
//! the static `ConfigurationProperties` store becomes the environment (`MOCKSERVER_STOP_DRAIN_MILLIS`), which
//! the property outranks as the instance outranks the static store.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::json;

use crate::common;

/// A server with `stopDrainMillis` from the property (`instance`) and/or the environment (`store`).
async fn server(instance: Option<u64>, store: Option<u64>) -> mock_server::Server {
    // `Config::from_args` is the CLI path, which turns proxySetupLogging on and would write
    // mockserver-ca.pem into the working directory, i.e. the repository.
    let mut args = vec!["-serverPort".to_string(), "0".to_string(), "-Dmockserver.proxySetupLogging=false".to_string()];
    if let Some(ms) = instance {
        args.push(format!("-Dmockserver.stopDrainMillis={ms}"));
    }
    let env: HashMap<String, String> = store.map(|ms| ("MOCKSERVER_STOP_DRAIN_MILLIS".to_string(), ms.to_string())).into_iter().collect();
    let config = mock_server::Config::from_args(&args, env).expect("config");
    crate::scratch_cwd::enter();
    mock_server::Server::start(config).await.expect("server starts")
}

/// `ConfigurationProperties.stopDrainMillis(ms)` then `new MockServer(0)`.
async fn new_server(drain: u64) -> mock_server::Server {
    server(None, Some(drain)).await
}

async fn stop_elapsed(server: &mock_server::Server) -> Duration {
    let start = Instant::now();
    tokio::time::timeout(Duration::from_secs(15), server.stop_async()).await.expect("stop finishes").unwrap();
    start.elapsed()
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_returns_promptly_when_nothing_in_flight() {
    let server = new_server(15_000).await;
    assert_eq!(server.requests_in_flight(), 0);
    let elapsed = stop_elapsed(&server).await;
    assert!(!server.is_running());
    assert!(elapsed < Duration::from_secs(10), "stop with nothing in flight should return promptly, took {elapsed:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_waits_for_in_flight_request_until_it_completes() {
    let server = new_server(30_000).await;
    server.request_processing_started();
    assert_eq!(server.requests_in_flight(), 1);
    let mut stop = server.stop_async();
    assert!(tokio::time::timeout(Duration::from_millis(750), &mut stop).await.is_err(), "stop should block while a request is still in flight");
    assert!(server.is_running());
    server.request_processing_complete();
    assert_eq!(server.requests_in_flight(), 0);
    tokio::time::timeout(Duration::from_secs(10), stop).await.expect("stop finishes").unwrap();
    assert!(!server.is_running());
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_proceeds_after_drain_timeout_when_request_never_completes() {
    let server = new_server(500).await;
    server.request_processing_started();
    assert_eq!(server.requests_in_flight(), 1);
    let elapsed = stop_elapsed(&server).await;
    assert!(elapsed >= Duration::from_millis(400), "should have waited at least the drain timeout, took {elapsed:?}");
    assert!(!server.is_running());
}

#[tokio::test(flavor = "multi_thread")]
async fn drain_disabled_when_timeout_zero() {
    let server = new_server(0).await;
    server.request_processing_started();
    assert_eq!(server.requests_in_flight(), 1);
    let elapsed = stop_elapsed(&server).await;
    assert!(elapsed < Duration::from_secs(5), "drain disabled should not wait, took {elapsed:?}");
    assert!(!server.is_running());
}

#[tokio::test(flavor = "multi_thread")]
async fn counter_returns_to_zero_after_start_and_complete() {
    let server = new_server(15_000).await;
    assert_eq!(server.requests_in_flight(), 0);
    for _ in 0..25 {
        server.request_processing_started();
    }
    assert_eq!(server.requests_in_flight(), 25);
    for _ in 0..25 {
        server.request_processing_complete();
    }
    assert_eq!(server.requests_in_flight(), 0);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn counter_never_goes_negative_on_double_complete() {
    let server = new_server(15_000).await;
    server.request_processing_started();
    assert_eq!(server.requests_in_flight(), 1);
    server.request_processing_complete();
    server.request_processing_complete();
    assert_eq!(server.requests_in_flight(), 0);
    server.request_processing_started();
    assert_eq!(server.requests_in_flight(), 1);
    server.request_processing_complete();
    assert_eq!(server.requests_in_flight(), 0);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn drain_unblocks_when_request_completes_from_another_thread() {
    let server = std::sync::Arc::new(new_server(30_000).await);
    server.request_processing_started();
    let completed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop = server.stop_async();
    let (s, c) = (server.clone(), completed.clone());
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        c.store(true, std::sync::atomic::Ordering::SeqCst);
        s.request_processing_complete();
    });
    tokio::time::timeout(Duration::from_secs(10), stop).await.expect("stop finishes").unwrap();
    assert!(completed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(!server.is_running());
}

/// The real request path: a delayed response holds its request in flight, and stop waits for it.
#[tokio::test(flavor = "multi_thread")]
async fn drain_waits_for_real_in_flight_request_with_response_delay() {
    let server = new_server(30_000).await;
    let port = server.ports()[0];
    common::expect(port, &json!({"httpRequest": {"path": "/slow"}, "httpResponse": {"body": "drained", "delay": {"timeUnit": "SECONDS", "value": 2}}})).await;
    let requester = tokio::spawn(async move { common::send(port, "GET", "/slow", "").await });
    let wait_start = Instant::now();
    while server.requests_in_flight() == 0 && wait_start.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(server.requests_in_flight() >= 1, "request should be in flight before stop");
    let elapsed = stop_elapsed(&server).await;
    assert!(elapsed >= Duration::from_secs(1), "stop should have waited for the ~2s delayed response to drain, took {elapsed:?}");
    let response = tokio::time::timeout(Duration::from_secs(20), requester).await.expect("response").unwrap();
    assert_eq!(response.body, "drained");
    assert_eq!(server.requests_in_flight(), 0);
    assert!(!server.is_running());
}

/// On 8.0.0 a delayed response's in-flight token completes in `NettyResponseWriter.sendResponse`, which the
/// delay's scheduled task reaches only after the delay, together with the "returning response" entry (the oracle
/// logs none 0.6 s and 1.5 s into a 3 s delay). So until the delay has passed the request is in flight, the entry is
/// absent, and a stop drains it.
#[tokio::test(flavor = "multi_thread")]
async fn a_delayed_response_is_in_flight_and_unlogged_until_its_delay_passes() {
    let server = new_server(30_000).await;
    let port = server.ports()[0];
    common::expect(port, &json!({"httpRequest": {"path": "/slow"}, "httpResponse": {"body": "late", "delay": {"timeUnit": "MILLISECONDS", "value": 1500}}})).await;
    let started = Instant::now();
    let requester = tokio::spawn(async move { common::send(port, "GET", "/slow", "").await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let logs = common::send(port, "PUT", "/mockserver/retrieve?type=LOGS", "").await.body;
    assert!(logs.contains("received request"), "{logs}");
    assert!(!logs.contains("returning response"), "logged before the delay passed: {logs}");
    assert_eq!(server.requests_in_flight(), 1);
    let elapsed = stop_elapsed(&server).await;
    assert!(started.elapsed() >= Duration::from_millis(1400), "stop returned {elapsed:?} after it began, before the delay passed");
    assert_eq!(tokio::time::timeout(Duration::from_secs(10), requester).await.expect("response").unwrap().body, "late");
    assert_eq!(server.requests_in_flight(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn counter_returns_to_zero_after_real_normal_request() {
    let server = new_server(15_000).await;
    let port = server.ports()[0];
    common::expect(port, &json!({"httpRequest": {"path": "/fast"}, "httpResponse": {"body": "ok"}})).await;
    assert_eq!(common::send(port, "GET", "/fast", "").await.body, "ok");
    let wait_start = Instant::now();
    while server.requests_in_flight() != 0 && wait_start.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(server.requests_in_flight(), 0, "counter should return to zero after a normal request");
    server.shutdown().await;
}

/// `PUT /mockserver/stop` over a kept-alive connection must not wait for its own request.
#[tokio::test(flavor = "multi_thread")]
async fn stop_over_keep_alive_connection_drains_promptly() {
    let server = new_server(30_000).await;
    let port = server.ports()[0];
    assert_eq!(server.requests_in_flight(), 0);
    let start = Instant::now();
    let r = common::exchange(port, common::Transport::Http, "PUT", "/mockserver/stop", &[("Connection", "keep-alive")], "").await;
    assert_eq!(r.status, 200);
    while server.is_running() && start.elapsed() < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(15), "stop over a keep-alive connection should drain promptly, took {elapsed:?}");
    assert!(!server.is_running());
    assert_eq!(server.requests_in_flight(), 0, "the /stop request's own in-flight token must clear promptly");
}

/// A dropped connection writes no response; the request still leaves the count.
#[tokio::test(flavor = "multi_thread")]
async fn counter_returns_to_zero_after_dropped_request() {
    let server = new_server(15_000).await;
    let port = server.ports()[0];
    common::expect(port, &json!({"httpRequest": {"path": "/drop"}, "httpError": {"dropConnection": true}})).await;
    let _ = common::send(port, "GET", "/drop", "").await;
    let wait_start = Instant::now();
    while server.requests_in_flight() != 0 && wait_start.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(server.requests_in_flight(), 0, "counter should return to zero after a dropped request");
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn instance_stop_drain_millis_is_honoured_by_shutdown_drain() {
    let server = server(Some(500), Some(30_000)).await;
    server.request_processing_started();
    let elapsed = stop_elapsed(&server).await;
    assert!(elapsed >= Duration::from_millis(400), "should have waited at least the instance drain budget, took {elapsed:?}");
    assert!(elapsed < Duration::from_secs(10), "should NOT have waited the static store's 30s budget, took {elapsed:?}");
    assert!(!server.is_running());
}

#[tokio::test(flavor = "multi_thread")]
async fn instance_stop_drain_millis_is_honoured_when_static_store_disables_draining() {
    let server = server(Some(1_000), Some(0)).await;
    server.request_processing_started();
    let elapsed = stop_elapsed(&server).await;
    assert!(elapsed >= Duration::from_millis(800), "instance budget must enable draining even though the static store disables it, took {elapsed:?}");
    assert!(!server.is_running());
}

#[tokio::test(flavor = "multi_thread")]
async fn static_stop_drain_millis_is_honoured_when_configuration_leaves_it_unset() {
    let server = server(None, Some(500)).await;
    server.request_processing_started();
    let elapsed = stop_elapsed(&server).await;
    assert!(elapsed >= Duration::from_millis(400), "static store must still bound the drain, took {elapsed:?}");
    assert!(elapsed < Duration::from_secs(10), "static store must not be ignored in favour of a hard-coded default, took {elapsed:?}");
    assert!(!server.is_running());
}

/// `StopAcceptingConnectionsIntegrationTest.shouldRefuseNewConnectionsWhileDrainingInFlightRequests`: once stopping
/// has begun, the listener is closed while the in-flight request is still draining.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_new_connections_while_draining_in_flight_requests() {
    let server = new_server(30_000).await;
    let port = server.ports()[0];
    common::expect(port, &json!({"httpRequest": {"path": "/slow"}, "httpResponse": {"body": "drained", "delay": {"timeUnit": "SECONDS", "value": 10}}})).await;
    let requester = tokio::spawn(async move { common::send(port, "GET", "/slow", "").await });
    let wait_start = Instant::now();
    while server.requests_in_flight() == 0 && wait_start.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(server.requests_in_flight() >= 1, "precondition: a request must be in flight before stop begins");
    let stop = server.stop_async();
    // Polled for much less than the 10s delay, so a refusal can only mean "refused while draining".
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut refused = false;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), tokio::net::TcpStream::connect(("127.0.0.1", port))).await {
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                refused = true;
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    assert!(refused, "a new connection must be refused while the server drains");
    assert!(server.is_running(), "still draining the in-flight request");
    tokio::time::timeout(Duration::from_secs(20), stop).await.expect("stop finishes").unwrap();
    assert_eq!(tokio::time::timeout(Duration::from_secs(20), requester).await.expect("response").unwrap().body, "drained");
}

/// A kept-alive HTTP/1.1 connection that sends `GET <path>` and reads one response (status line and body).
struct KeptAlive(tokio::net::TcpStream);

impl KeptAlive {
    async fn open(port: u16) -> KeptAlive {
        KeptAlive(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.expect("connects"))
    }

    async fn get(&mut self, path: &str) -> Option<(String, String)> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        self.0.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.ok()?;
        let mut data = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&data[..end]).to_string();
                let length = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap())).unwrap_or(0);
                if data.len() >= end + 4 + length {
                    let body = String::from_utf8_lossy(&data[end + 4..end + 4 + length]).to_string();
                    return Some((head.lines().next().unwrap().to_string(), body));
                }
            }
            match self.0.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => data.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Whether the server closed the connection (end of stream or reset) within `within`.
    async fn closed_within(&mut self, within: Duration) -> bool {
        use tokio::io::AsyncReadExt;
        let mut chunk = [0u8; 64];
        matches!(tokio::time::timeout(within, self.0.read(&mut chunk)).await, Ok(Ok(0) | Err(_)))
    }
}

/// `LifeCycle.stopAsync` ends by shutting the worker event loop group down, which closes every channel it still
/// carries: a kept-alive connection that is idle when the server stops is closed, not left answering.
#[tokio::test(flavor = "multi_thread")]
async fn stop_closes_an_idle_keep_alive_connection() {
    let server = new_server(15_000).await;
    let port = server.ports()[0];
    common::expect(port, &json!({"httpRequest": {"path": "/fast"}, "httpResponse": {"body": "fast"}})).await;
    let mut idle = KeptAlive::open(port).await;
    assert_eq!(idle.get("/fast").await.expect("answered").1, "fast");
    stop_elapsed(&server).await;
    assert!(idle.closed_within(Duration::from_secs(3)).await, "an idle keep-alive connection must be closed by stop");
}

/// While stop drains, the channels are still registered and served: a request on an idle keep-alive connection is
/// answered; once the drain is over, that connection and the drained request's are closed.
#[tokio::test(flavor = "multi_thread")]
async fn idle_connection_is_served_while_draining_and_closed_after() {
    let server = new_server(30_000).await;
    let port = server.ports()[0];
    common::expect(port, &json!({"httpRequest": {"path": "/fast"}, "httpResponse": {"body": "fast"}})).await;
    common::expect(port, &json!({"httpRequest": {"path": "/slow"}, "httpResponse": {"body": "drained", "delay": {"timeUnit": "SECONDS", "value": 2}}})).await;
    let mut idle = KeptAlive::open(port).await;
    assert_eq!(idle.get("/fast").await.expect("answered").1, "fast");
    let mut slow = KeptAlive::open(port).await;
    let requester = tokio::spawn(async move {
        let answer = slow.get("/slow").await;
        (answer, slow)
    });
    assert!(common::eventually(|| server.requests_in_flight() >= 1).await, "a request must be in flight before stop");
    let stop = server.stop_async();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(server.is_running(), "still draining");
    assert_eq!(idle.get("/fast").await.expect("served while draining").1, "fast");
    tokio::time::timeout(Duration::from_secs(15), stop).await.expect("stop finishes").unwrap();
    let (answer, mut slow) = requester.await.unwrap();
    assert_eq!(answer.expect("the in-flight request drains").1, "drained");
    assert!(idle.closed_within(Duration::from_secs(3)).await, "the idle connection must be closed once stopped");
    assert!(slow.closed_within(Duration::from_secs(3)).await, "the drained connection must be closed once stopped");
}

/// A request still in flight when the drain budget runs out loses its connection with the rest: the stop proceeds
/// and the event loops close every channel, so no response arrives later.
#[tokio::test(flavor = "multi_thread")]
async fn request_in_flight_past_the_drain_budget_loses_its_connection() {
    let server = new_server(500).await;
    let port = server.ports()[0];
    common::expect(port, &json!({"httpRequest": {"path": "/slow"}, "httpResponse": {"body": "late", "delay": {"timeUnit": "SECONDS", "value": 10}}})).await;
    let mut slow = KeptAlive::open(port).await;
    let started = Instant::now();
    let requester = tokio::spawn(async move { slow.get("/slow").await });
    assert!(common::eventually(|| server.requests_in_flight() >= 1).await, "a request must be in flight before stop");
    stop_elapsed(&server).await;
    let answer = tokio::time::timeout(Duration::from_secs(5), requester).await.expect("the connection is closed, not left waiting").unwrap();
    assert!(answer.is_none(), "no response after the drain budget ran out, got {answer:?}");
    assert!(started.elapsed() < Duration::from_secs(8));
}

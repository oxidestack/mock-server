//! Ports of `LifeCycleBindRetryTest` (mockserver-netty `lifecycle/`): `LifeCycle.bindPort`'s shadow
//! handling driven through the `BindVerifier` seam ([`Server::set_bind_verifier`]), so the retry and failure paths
//! run on every operating system, not only where the kernel allows a shadowed bind. Upstream calls
//! `bindServerPorts` in the JVM; here the same call is `PUT /mockserver/bind`, whose 400 body is the
//! `RuntimeException`'s message with `" port already in use: " + cause` when the cause is a `BindException`
//! (`HttpRequestHandler`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mock_server::loopback_probe::{self, Accepted, BindVerifier};
use mock_server::Config;

/// The test's `BindVerifier`: records each listener probed (by its address) and the accept timeout it was given.
#[derive(Default)]
struct Verifier {
    probed: Mutex<Vec<SocketAddr>>,
    accept_timeouts: Mutex<Vec<u128>>,
    calls: AtomicUsize,
    /// How many probes report a shadow before later probes report none.
    shadowed_calls: usize,
    /// Ports returned, in order, by `next_candidate_port` (0 once exhausted).
    candidates: Vec<u16>,
    next_candidate: AtomicUsize,
    /// The check fails with this error instead of answering.
    fails_with: Option<std::io::ErrorKind>,
}

impl Verifier {
    fn shadowing(shadowed_calls: usize, candidates: Vec<u16>) -> Arc<Verifier> {
        Arc::new(Verifier { shadowed_calls, candidates, ..Verifier::default() })
    }

    fn failing(kind: std::io::ErrorKind) -> Arc<Verifier> {
        Arc::new(Verifier { fails_with: Some(kind), ..Verifier::default() })
    }

    fn probed(&self) -> Vec<SocketAddr> {
        self.probed.lock().unwrap().clone()
    }

    fn accept_timeouts(&self) -> Vec<u128> {
        self.accept_timeouts.lock().unwrap().clone()
    }

    fn candidate_requests(&self) -> usize {
        self.next_candidate.load(Ordering::SeqCst)
    }
}

impl BindVerifier for Verifier {
    fn find_shadowed_loopback(&self, listener: &TcpListener, accept_timeout: Duration, _others: &mut Accepted) -> std::io::Result<Option<SocketAddr>> {
        let bound = listener.local_addr()?;
        self.probed.lock().unwrap().push(bound);
        self.accept_timeouts.lock().unwrap().push(accept_timeout.as_millis());
        if let Some(kind) = self.fails_with {
            return Err(std::io::Error::new(kind, "check failed"));
        }
        if self.calls.fetch_add(1, Ordering::SeqCst) + 1 > self.shadowed_calls {
            return Ok(None);
        }
        Ok(Some(SocketAddr::from((Ipv4Addr::LOCALHOST, bound.port()))))
    }

    fn next_candidate_port(&self) -> u16 {
        let index = self.next_candidate.fetch_add(1, Ordering::SeqCst);
        self.candidates.get(index).copied().unwrap_or(0)
    }
}

/// `@Before startServer`: the server is bound with the real probe; the test's verifier is installed afterwards, as
/// upstream sets `bindVerifier` on a started `MockServer`.
async fn started_with(verifier: &Arc<Verifier>) -> crate::common::Running {
    let running = crate::common::start_with(Config::for_tests(), &[]).await;
    running.server.set_bind_verifier(Some(verifier.clone() as Arc<dyn BindVerifier>));
    running
}

/// `bindServerPorts(ports)` as `PUT /mockserver/bind`.
async fn bind_server_ports(port: u16, ports: &[u16]) -> crate::common::Response {
    crate::common::send(port, "PUT", "/mockserver/bind", &serde_json::json!({ "ports": ports }).to_string()).await
}

/// `getLocalPorts()`.
async fn local_ports(port: u16) -> Vec<u16> {
    let status = crate::common::send(port, "PUT", "/mockserver/status", "").await;
    ports_of(&serde_json::from_str(&status.body).unwrap_or_else(|_| panic!("status: {}", status.body)))
}

fn ports_of(port_binding: &serde_json::Value) -> Vec<u16> {
    port_binding["ports"].as_array().expect("ports").iter().map(|p| p.as_u64().unwrap() as u16).collect()
}

/// The ports `PUT /mockserver/status` answers on `[::1]:port`.
async fn status_over_ipv6_loopback(port: u16) -> Vec<u16> {
    tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect((Ipv6Addr::LOCALHOST, port)).expect("the listener accepts");
        write!(s, "PUT /mockserver/status HTTP/1.1\r\nHost: [::1]:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).unwrap();
        let body = raw.split_once("\r\n\r\n").map(|(_, body)| body).unwrap_or_default();
        let binding: serde_json::Value = serde_json::from_str(body).unwrap_or_else(|_| panic!("status over [::1]:{port}: {raw}"));
        // only the newly bound ports are this call's; status lists them all
        let all = ports_of(&binding);
        all.into_iter().filter(|p| *p == port).collect()
    })
    .await
    .unwrap()
}

/// `channel.closeFuture().await(..)` / `isOpen() == false`: the listener the probe was given is closed, so a
/// dual-stack wildcard listener can be bound on its port again (a `TcpListener` binds `[::]` with `IPV6_V6ONLY` off
/// on macOS and Linux by default).
///
/// The tests of this binary run in parallel, and a closed ephemeral port goes back to the pool at once: another test's
/// `bind(0)` can take it before the rebind. A failed rebind is therefore excused only when the port's new holder is a live
/// server: an unaccepted probe listener never answers a request, while another test's server does.
fn assert_closed(probed: SocketAddr) {
    // A child this process forks (a test's `lsof` or `docker`, the server's `protoc`) holds a copy of every
    // descriptor until it runs its program, the closed listener's included, so the rebind can fail for that long alone.
    // The check therefore waits out such a window; a listener that was really left open still fails it, at the deadline.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let rebound = TcpListener::bind((Ipv6Addr::UNSPECIFIED, probed.port())).or_else(|_| TcpListener::bind((Ipv4Addr::UNSPECIFIED, probed.port())));
        let Err(error) = &rebound else { return };
        if error.kind() == std::io::ErrorKind::AddrInUse && answers_http(probed.port()) {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "the listener probed on {probed} must have been closed: {rebound:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Whether something on loopback `port` answers an HTTP request, as a server that was bound there after the probe
/// listener closed does, and a listener nobody accepts from never does.
fn answers_http(port: u16) -> bool {
    use std::io::{Read, Write};
    [IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)].into_iter().any(|ip| {
        let Ok(mut stream) = std::net::TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_secs(2)) else { return false };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let request = format!("GET /mockserver/status HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n");
        let mut head = [0u8; 5];
        stream.write_all(request.as_bytes()).is_ok() && stream.read_exact(&mut head).is_ok() && &head == b"HTTP/"
    })
}

async fn shutdown(running: crate::common::Running) {
    running.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_give_up_on_ephemeral_port_after_max_attempts_with_escalating_timeouts_and_close_every_shadowed_channel() {
    let verifier = Verifier::shadowing(usize::MAX, Vec::new());
    let running = started_with(&verifier).await;

    let refused = bind_server_ports(running.port, &[0]).await;

    assert_eq!(refused.status, 400, "{}", refused.body);
    let start = format!(
        "Exception while binding MockServer to port 0 port already in use: no usable free port found after {} attempts, the last one because port ",
        loopback_probe::MAX_EPHEMERAL_ATTEMPTS
    );
    assert!(refused.body.starts_with(&start), "{}", refused.body);
    let probed = verifier.probed();
    assert_eq!(probed.len(), loopback_probe::MAX_EPHEMERAL_ATTEMPTS as usize);
    assert_eq!(verifier.accept_timeouts(), vec![250, 500, 1000, 2000, 4000, 5000, 5000, 5000, 5000, 5000]);
    for listener in probed {
        assert_closed(listener);
    }
    assert_eq!(local_ports(running.port).await, vec![running.port]);
    shutdown(running).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_retry_ephemeral_bind_when_the_retry_candidate_port_is_already_taken() {
    // the first candidate is this server's own port, so binding it fails; the second lets the OS choose
    let running = crate::common::start_with(Config::for_tests(), &[]).await;
    let verifier = Verifier::shadowing(1, vec![running.port, 0]);
    running.server.set_bind_verifier(Some(verifier.clone() as Arc<dyn BindVerifier>));

    let bound = bind_server_ports(running.port, &[0]).await;

    assert_eq!(bound.status, 200, "{}", bound.body);
    let body: serde_json::Value = serde_json::from_str(&bound.body).unwrap();
    let ports = ports_of(&body);
    assert_eq!(ports.len(), 1);
    assert_ne!(ports[0], running.port);
    let probed = verifier.probed();
    assert_eq!(probed.len(), 2, "{probed:?}");
    assert_closed(probed[0]);
    assert_eq!(probed[1].port(), ports[0], "the listener kept is the second one probed");
    // `isOpen()`: asked over `[::1]`, since this test's verifier reports no shadow whatever holds `127.0.0.1` on
    // the port the IPv6 allocator chose
    assert_eq!(status_over_ipv6_loopback(ports[0]).await, ports_of(&body), "the listener kept is open and served");
    assert_eq!(local_ports(running.port).await, vec![running.port, ports[0]]);
    // `bindPort`'s INFO for the port it gave up (upstream logs it through the server's logger on every bind)
    let shadowed = probed[0].port();
    let retried = format!(
        "port {shadowed} is already in use by another application listening on 127.0.0.1:{shadowed}, so requests to localhost:{shadowed} would reach that application instead of MockServer; binding a different port"
    );
    let logs = crate::common::logs(running.port).await;
    assert!(logs.contains(&retried), "{logs}");
    shutdown(running).await;
}

/// `PortFactory.findFreePort()` then `bindServerPorts`: the port is probed and released before the server binds
/// it, so another process can take it meanwhile (`tcp_port.rs`); a bind that failed before any check runs is
/// tried again with a fresh port and a fresh verifier.
async fn bind_explicit_port(running: &crate::common::Running, verifier: impl Fn() -> Arc<Verifier>) -> (u16, Arc<Verifier>, crate::common::Response) {
    for _ in 0..crate::tcp_port::START_ATTEMPTS {
        let explicit_port = crate::tcp_port::free_tcp_port();
        let verifier = verifier();
        running.server.set_bind_verifier(Some(verifier.clone() as Arc<dyn BindVerifier>));
        let response = bind_server_ports(running.port, &[explicit_port]).await;
        if !verifier.probed().is_empty() || response.status == 200 {
            return (explicit_port, verifier, response);
        }
    }
    panic!("no free port could be bound in {} attempts", crate::tcp_port::START_ATTEMPTS);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fail_explicit_port_on_first_shadow_without_retrying() {
    let running = crate::common::start_with(Config::for_tests(), &[]).await;

    let (explicit_port, verifier, refused) = bind_explicit_port(&running, || Verifier::shadowing(usize::MAX, Vec::new())).await;

    assert_eq!(refused.status, 400, "{}", refused.body);
    assert_eq!(
        refused.body,
        format!(
            "Exception while binding MockServer to port {explicit_port} port already in use: port {explicit_port} is already in use by another application listening on 127.0.0.1:{explicit_port}, so requests to localhost:{explicit_port} would reach that application instead of MockServer; stop that application or choose a different port (to find it run: lsof -nP -iTCP:{explicit_port} -sTCP:LISTEN)"
        )
    );
    let probed = verifier.probed();
    assert_eq!(probed.len(), 1);
    assert_eq!(verifier.accept_timeouts(), vec![5000]);
    assert_eq!(verifier.candidate_requests(), 0);
    assert_closed(probed[0]);
    assert_eq!(local_ports(running.port).await, vec![running.port]);
    shutdown(running).await;
}

/// The check is interrupted: Rust has no thread interrupt to restore, so the port keeps the rest, a check that ends
/// with `ErrorKind::Interrupted` closes the new listener and fails the bind.
#[tokio::test(flavor = "multi_thread")]
async fn should_close_the_new_channel_and_restore_the_interrupt_when_the_check_is_interrupted() {
    let verifier = Verifier::failing(std::io::ErrorKind::Interrupted);
    let running = started_with(&verifier).await;

    let refused = bind_server_ports(running.port, &[0]).await;

    assert_eq!(refused.status, 400, "{}", refused.body);
    assert_eq!(refused.body, "Exception while binding MockServer to port 0");
    let probed = verifier.probed();
    assert_eq!(probed.len(), 1);
    assert_closed(probed[0]);
    assert_eq!(local_ports(running.port).await, vec![running.port]);
    shutdown(running).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_the_new_channel_when_the_check_fails() {
    let running = crate::common::start_with(Config::for_tests(), &[]).await;

    let (explicit_port, verifier, refused) = bind_explicit_port(&running, || Verifier::failing(std::io::ErrorKind::Other)).await;

    // an `IllegalStateException`, not a `BindException`: nothing is appended
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert_eq!(refused.body, format!("Exception while binding MockServer to port {explicit_port}"));
    let probed = verifier.probed();
    assert_eq!(probed.len(), 1);
    assert_eq!(local_ports(running.port).await, vec![running.port]);
    // the port was released, so it can be bound again
    assert_closed(probed[0]);
    shutdown(running).await;
}

#[test]
fn should_bracket_ipv6_addresses_in_the_conflict_message() {
    let ipv6 = loopback_probe::explicit_port_conflict(1080, SocketAddr::from((Ipv6Addr::LOCALHOST, 1080))).to_string();
    assert!(
        ipv6.starts_with("port 1080 is already in use by another application listening on [::1]:1080, so requests to localhost:1080 would reach that application instead of MockServer"),
        "{ipv6}"
    );
    let ipv4 = loopback_probe::explicit_port_conflict(1080, SocketAddr::from((Ipv4Addr::LOCALHOST, 1080))).to_string();
    assert!(ipv4.starts_with("port 1080 is already in use by another application listening on 127.0.0.1:1080, so"), "{ipv4}");
}

/// [`assert_closed`] outlasts a descriptor copy a forked child holds for a moment, and still fails a
/// listener that is never closed.
#[test]
fn assert_closed_waits_out_a_listener_held_by_a_child_for_a_moment() {
    let listener = TcpListener::bind((Ipv6Addr::UNSPECIFIED, 0)).unwrap();
    let probed = listener.local_addr().unwrap();
    let holder = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(listener);
    });
    assert_closed(probed);
    holder.join().unwrap();
}

#[test]
#[should_panic(expected = "must have been closed")]
fn assert_closed_fails_a_listener_that_is_never_closed() {
    let listener = TcpListener::bind((Ipv6Addr::UNSPECIFIED, 0)).unwrap();
    assert_closed(listener.local_addr().unwrap());
}

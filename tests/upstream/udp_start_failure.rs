//! Ports of `DnsStartFailureTest`, `Http3StartFailureTest` and `MainTest`'s start-failure cases (mockserver-netty):
//! a DNS or HTTP/3 listener that cannot start stops what the server had started and refuses its start
//! with `DnsStartupException` / `Http3StartupException` ([`mock_server::UdpStartFailure`]). Also the ports of
//! `DnsPortTakenAfterProbeTest` and `DnsLocalBoundIpTest`: the DNS listener's `Ipv4UdpPortProbe` and
//! its bind of `localBoundIP`, and of `Http3ServerIpv4PortConflictTest`: the same probe on the HTTP/3
//! listener.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mock_server::{BindFailure, Config, Server, UdpListener, UdpStartFailure};

use crate::udp_port::UdpHolders;
use serde_json::json;

/// `DUAL_STACK_MAC_OS`: only a dual-stack bind on macOS succeeds on a port another socket holds on the IPv4
/// wildcard; elsewhere that bind fails with its own error.
const DUAL_STACK_MAC_OS: bool = cfg!(target_os = "macos");

async fn refused_start(properties: &[(&str, &str)]) -> UdpStartFailure {
    refused_start_with(Config::for_tests(), properties).await
}

async fn refused_start_with(config: Config, properties: &[(&str, &str)]) -> UdpStartFailure {
    udp_start_failure(start_error(config, properties).await)
}

fn udp_start_failure(error: std::io::Error) -> UdpStartFailure {
    let failure = error.into_inner().expect("a start failure with its cause");
    *failure.downcast::<UdpStartFailure>().unwrap_or_else(|other| panic!("not a UDP listener's start failure: {other}"))
}

async fn start_error(config: Config, properties: &[(&str, &str)]) -> std::io::Error {
    match start_or_error(config, properties).await {
        Some(e) => e,
        None => panic!("{properties:?}: the server started"),
    }
}

/// The error of a refused start, or `None` once a server that started is shut down again.
async fn start_or_error(config: Config, properties: &[(&str, &str)]) -> Option<std::io::Error> {
    crate::scratch_cwd::enter();
    let config = properties.iter().fold(config, |c, (k, v)| c.with_property(k, v));
    match Server::start(config).await {
        Ok(server) => {
            server.shutdown().await;
            None
        }
        Err(e) => Some(e),
    }
}

/// `DnsStartFailureTest.portCouldNotBeOpenedOrBound`: how the message of a DNS port that could not be bound starts.
fn port_could_not_be_opened_or_bound(udp_port: u16) -> String {
    format!(
        "DNS mocking is enabled (dnsEnabled=true, dnsPort={udp_port}) but UDP port {udp_port} could not be opened or bound, so MockServer cannot start: free the port if another application holds it, choose a different dnsPort (0 picks a free port, and a port below 1024 can need extra privileges), or set dnsEnabled=false to run without DNS mocking (underlying error: "
    )
}

/// The end of the message of a DNS port refused because another socket holds it on `0.0.0.0` (macOS).
fn ipv4_wildcard_conflict(udp_port: u16) -> String {
    format!(
        "BindException: UDP port {udp_port} is already in use by another socket listening on 0.0.0.0:{udp_port}, so DNS queries to localhost:{udp_port} would reach that socket instead of MockServer; stop the application that holds it or choose a different dnsPort (to find it run: lsof -nP -iUDP:{udp_port}))"
    )
}

/// `DnsStartFailureTest.heldUdpPort`: a socket on `127.0.0.1` fails the server's bind of that port on every address,
/// on every platform.
fn held_udp_port() -> UdpSocket {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a UDP port on 127.0.0.1")
}

fn port_of(socket: &UdpSocket) -> u16 {
    socket.local_addr().unwrap().port()
}

/// `Ipv4UdpPortProbe.heldOnIpv4`.
fn held_on_ipv4(port: u16) -> bool {
    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).is_err()
}

/// `Ipv4UdpPortProbe.dualStackBindSucceeds`: a dual-stack wildcard bind of `port`, as the server makes.
fn dual_stack_bind_succeeds(port: u16) -> bool {
    use socket2::{Domain, Protocol, Socket, Type};
    let v6 = || -> std::io::Result<()> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(false)?;
        socket.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())
    };
    v6().is_ok()
}

/// Whether `refused`, a start refused on a `port` the test holds on the IPv4 wildcard through this call, is
/// not the conflict the test set up but another process holding the port's IPv6 side. On macOS a dual-stack `[::]:0`
/// bind can be handed a port another socket holds on `0.0.0.0` (any process's, this binary's `free_udp_port` too), and
/// the server's dual-stack bind then fails with plain `EADDRINUSE`. With the test's own IPv4 socket alone, a dual-stack
/// bind of the port succeeds there (what the conflict tests rely on), so its failure names someone else. Any other
/// refusal, or the plain one with the IPv6 side free, stays a failure; a caller retries a new port only on `true`.
fn other_stack_taken_meanwhile(refused: &UdpStartFailure, port: u16) -> bool {
    let taken = DUAL_STACK_MAC_OS && refused.port_unavailable && refused.message().ends_with("Address already in use)") && !dual_stack_bind_succeeds(port);
    if taken {
        eprintln!("UDP port {port}: another process holds its IPv6 side, so a new port is tried");
    }
    taken
}

/// Whether a refusal [`other_stack_taken_meanwhile`] counts as the race is retried: only while this process
/// holds no socket on the port besides the test's own `socket` there (a socket the server's probe or listener left open
/// would be one); otherwise it fails the test, naming the holders.
fn retry_besides(socket: &UdpSocket, attempt: usize, refused: &UdpStartFailure) -> bool {
    let port = port_of(socket);
    let own = std::os::fd::AsRawFd::as_raw_fd(socket);
    crate::udp_port::retry_taken_port(port, &[own], attempt, &format!("the start on UDP port {port} was refused: {}", refused.message()))
}

/// `portFreeOnBothStacks`: free on IPv4 and for a dual-stack bind (on macOS another process occasionally holds an
/// IPv4-allocated port on IPv6, which would fail the server's bind for a reason of its own).
fn port_free_on_both_stacks() -> u16 {
    for _ in 0..20 {
        let port = crate::udp_port::free_udp_port();
        if !held_on_ipv4(port) && dual_stack_bind_succeeds(port) {
            return port;
        }
    }
    panic!("no UDP port free on both IPv4 and a dual-stack bind in 20 attempts");
}

/// `LocalBoundIpAddresses.anotherAddressOfThisHost`: an IPv4 address of this host other than the loopback (the one
/// the default route leaves from; a connected UDP socket sends nothing). Fails the test if there is none.
fn another_address_of_this_host() -> Ipv4Addr {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    socket.connect(("192.0.2.1", 53)).expect("this test needs an IPv4 address of this host other than the loopback");
    match socket.local_addr().unwrap().ip() {
        std::net::IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() => ip,
        other => panic!("this test needs an IPv4 address of this host other than the loopback, and there is none ({other})"),
    }
}

/// `MOCK_SERVER_LAN_UDP_TESTS=1` runs, on macOS, the tests that need a datagram sent to
/// [`another_address_of_this_host`] to reach a socket of this test process (see [`lan_udp_observable`]).
const LAN_UDP_TESTS: &str = "MOCK_SERVER_LAN_UDP_TESTS";

/// Whether a test may expect a datagram sent to [`another_address_of_this_host`] to reach a socket of this process;
/// when not, the reason is printed and the calling test skips.
///
/// On macOS that depends on the host: the application firewall, when enabled, filters the UDP datagrams arriving on a
/// non-loopback address, silently (no ICMP). It knows an ad-hoc signed binary by its signing identifier, which the
/// linker takes from the file name (`upstream-<hash>`, stable across rebuilds): a binary never allowed gets nothing,
/// and an allowed one gets the datagrams of a new socket only once the firewall has decided on it. Measured with
/// fresh socket pairs of the test process, each sent to once and waited on for 3 s: under 1 s for one test alone, and
/// from 0.7 s to 158 s inside a full `cargo test --test upstream` (8 runs: 0.7, 0.8, 1.0, 1.9, 10, 16, 82 and 158 s,
/// the three probes of one process let through at the same moment); pairs given up on after 0.5 s were never let
/// through in 20 full runs. `DnsQueries`' single query with a 5 s timeout failed in about one full run in three.
/// Datagrams to the loopback, and the ICMP refusal of one sent to a port nothing holds, are not delayed, so only a test
/// expecting an answer on another address is opted out. Elsewhere (Linux CI) it runs unconditionally.
fn lan_udp_observable(test: &str) -> bool {
    if !cfg!(target_os = "macos") || std::env::var(LAN_UDP_TESTS).is_ok_and(|v| v == "1") {
        return true;
    }
    eprintln!(
        "{test}: skipped on macOS, whose application firewall can hold back datagrams sent to this host's other address for minutes; {LAN_UDP_TESTS}=1 runs it (allow the test binary when prompted)"
    );
    false
}

/// How long a query to [`another_address_of_this_host`] that must be answered is sent again: the answer comes in
/// milliseconds unless the host holds it back (see [`lan_udp_observable`]).
const DELIVERY_WAIT: Duration = Duration::from_secs(300);

/// `DnsQueries.QUERY_TIMEOUT_MILLIS`.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// `DnsQueries.addressAnsweredFor`: the address of the one A record answered for `name` at `server`, or `None` when
/// nothing answers in [`QUERY_TIMEOUT`].
async fn address_answered_for(name: &str, server: SocketAddr) -> Option<String> {
    address_answered_within(name, server, QUERY_TIMEOUT).await
}

/// [`address_answered_for`] waiting up to `wait`, the query sent again each second from the same socket, so a query
/// or an answer the host's filter dropped (see [`lan_udp_observable`]) is asked for again.
async fn address_answered_within(name: &str, server: SocketAddr, wait: Duration) -> Option<String> {
    let mut query = vec![0x05, 0x56, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.').filter(|l| !l.is_empty()) {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    tokio::task::spawn_blocking(move || {
        // from a socket bound to the server's address and connected, so a port nothing listens on refuses at once
        let socket = UdpSocket::bind((server.ip(), 0)).unwrap();
        socket.connect(server).unwrap();
        let deadline = std::time::Instant::now() + wait;
        let mut buf = [0u8; 512];
        let n = loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return None;
            }
            socket.send(&query).ok()?;
            socket.set_read_timeout(Some(left.min(Duration::from_secs(1)))).unwrap();
            match socket.recv(&mut buf) {
                Ok(n) => break n,
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                Err(_) => return None,
            }
        };
        // one answer, its name uncompressed and its data the last four bytes
        (n >= 16 && u16::from_be_bytes([buf[6], buf[7]]) == 1).then(|| Ipv4Addr::new(buf[n - 4], buf[n - 3], buf[n - 2], buf[n - 1]).to_string())
    })
    .await
    .unwrap()
}

async fn expect_a_record(control_port: u16, name: &str, address: &str) {
    let answer = json!({"name": name, "type": "A", "value": address});
    crate::common::expect(control_port, &json!({"httpRequest": {"dnsName": name}, "dnsResponse": {"answerRecords": [answer]}})).await;
}

/// `DnsLocalBoundIpTest.portTaken`: a refusal a fresh port cures, as either transport reports a taken port.
fn port_taken(refused: &UdpStartFailure) -> bool {
    let text = refused.to_string();
    text.contains("java.net.BindException") || text.contains("Address already in use")
}

/// Whether `port` is free again on the wildcard addresses the listeners bind: a socket the refused server left there
/// would hold it.
fn udp_port_free(port: u16) -> bool {
    std::net::UdpSocket::bind(("::", port)).or_else(|_| std::net::UdpSocket::bind(("0.0.0.0", port))).is_ok()
}

/// Whether a post-release check of UDP `port` (`what`, which found the port `free` or taken) is tried
/// again with a fresh port: only when it found the port taken, this process holds no socket on it right after, and
/// `attempt` is not the last. Otherwise a taken port fails the test, naming its holders: a socket of this process there
/// is one the server left behind (or, rarely, another test's of this binary, which fails safe).
fn retry_unless_released(port: u16, free: bool, attempt: usize, what: &str) -> bool {
    !free && crate::udp_port::retry_taken_port(port, &[], attempt, what)
}

/// A start with `http3Port` on a `port` the test released or found free, as a post-release check: the server, or
/// `None` when the port is taken and [`retry_unless_released`] retries it; any other failure fails the test.
async fn started_on_released_http3_port(port: u16, attempt: usize, what: &str) -> Option<Server> {
    crate::scratch_cwd::enter();
    match Server::start(Config::for_tests().with_property("http3Port", &port.to_string())).await {
        Ok(server) => {
            assert_eq!(server.http3_port(), Some(port));
            Some(server)
        }
        Err(e) if crate::udp_port::taken_meanwhile(&e) => {
            // a taken port is retried or fails the test there
            retry_unless_released(port, false, attempt, &format!("{what}: {}", udp_start_failure(e).message()));
            None
        }
        Err(e) => panic!("{what}: {e:?}"),
    }
}

/// `DnsStartFailureTest.shouldRefuseASecondMockServerGivenTheDnsPortOfTheFirst`.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_a_second_mock_server_given_the_dns_port_of_the_first() {
    let first = crate::common::start(&[("dnsEnabled", "true"), ("dnsPort", "0")]).await;
    let udp_port = first.server.dns_port().expect("the port the operating system chose");

    let refused = refused_start(&[("dnsEnabled", "true"), ("dnsPort", &udp_port.to_string())]).await;

    assert_eq!(refused.listener, UdpListener::Dns);
    assert!(
        refused.message().starts_with(&format!(
            "DNS mocking is enabled (dnsEnabled=true, dnsPort={udp_port}) but UDP port {udp_port} could not be opened or bound, so MockServer cannot start:"
        )),
        "{}",
        refused.message()
    );
    assert!(refused.message().ends_with("Address already in use)"), "{}", refused.message());
    assert!(!refused.message().contains('\n'), "one line");
    assert!(refused.port_unavailable);
    assert_eq!(first.server.dns_port(), Some(udp_port), "the first server keeps the port");
    assert!(first.server.is_running());
    first.server.shutdown().await;
}

/// `DnsStartFailureTest.shouldRefuseToStartWhenTheDnsPortIsNotAPort`.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_to_start_when_the_dns_port_is_not_a_port() {
    let refused = refused_start(&[("dnsEnabled", "true"), ("dnsPort", "70000")]).await;

    assert_eq!(
        refused.message(),
        "DNS mocking is enabled (dnsEnabled=true, dnsPort=70000) but its server could not start on UDP port 70000, so MockServer cannot start: fix the underlying error or set dnsEnabled=false to run without DNS mocking (underlying error: IllegalArgumentException: port out of range:70000)"
    );
    assert!(refused.to_string().contains("\nCaused by: java.lang.IllegalArgumentException: port out of range:70000"), "{refused}");
    assert!(!refused.port_unavailable);
}

/// `Http3StartFailureTest.shouldRefuseToStartWhenTheHttp3PortIsNotAPort`.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_to_start_when_the_http3_port_is_not_a_port() {
    let refused = refused_start(&[("http3Port", "70000")]).await;

    assert_eq!(refused.listener, UdpListener::Http3);
    assert_eq!(
        refused.message(),
        "HTTP/3 is enabled (http3Port=70000) but its server could not start on UDP port 70000, so MockServer cannot start: fix the underlying error or remove http3Port to run without HTTP/3 (underlying error: IllegalArgumentException: port out of range:70000)"
    );
    assert!(!refused.port_unavailable);
}

/// `Http3StartFailureTest.shouldReleaseTheDnsPortItHadBoundWhenHttp3IsRefused`: the server's own DNS listener, which
/// starts first, holds the port; the refused server leaves neither its DNS socket nor its TCP listener behind.
#[tokio::test(flavor = "multi_thread")]
async fn should_release_the_dns_port_it_had_bound_when_http3_is_refused() {
    let mut attempt = 1;
    loop {
        let udp_port = crate::udp_port::free_udp_port();
        let port = udp_port.to_string();
        let refused = refused_start(&[("dnsEnabled", "true"), ("dnsPort", &port), ("http3Port", &port)]).await;
        // another process took the probed port before the DNS listener bound it (tests/support/udp_port.rs); a socket
        // of this process there fails the test, naming it
        if refused.listener == UdpListener::Dns && refused.port_unavailable {
            crate::udp_port::retry_taken_port(udp_port, &[], attempt, &format!("the DNS listener was refused: {}", refused.message()));
            attempt += 1;
            continue;
        }

        assert_eq!(refused.listener, UdpListener::Http3);
        assert_eq!(
            refused.message(),
            format!(
                "HTTP/3 is enabled (http3Port={udp_port}) but UDP port {udp_port} could not be bound, so MockServer cannot start: free the port if another application holds it, choose a different http3Port, or remove http3Port to run without HTTP/3 (underlying error: BindException: Address already in use)"
            )
        );
        assert!(refused.port_unavailable);
        let what = format!("the refused server must hold no socket on its DNS port {udp_port}");
        if retry_unless_released(udp_port, udp_port_free(udp_port), attempt, &what) {
            attempt += 1;
            continue;
        }
        break;
    }
}

/// `MainTest.shouldPrintTheMessageAloneWhenTheDnsPortCannotBeBound` and `shouldPrintTheStackTraceOfAnyOtherDnsStartFailure`:
/// which failures `Main.logStartupFailure` prints with their message alone (`mock-server`'s `main` logs it under the
/// format).
#[tokio::test(flavor = "multi_thread")]
async fn should_print_the_message_alone_when_the_dns_port_cannot_be_bound() {
    let first = crate::common::start(&[("dnsEnabled", "true"), ("dnsPort", "0")]).await;
    let udp_port = first.server.dns_port().expect("the port the operating system chose").to_string();

    let held = refused_start(&[("dnsEnabled", "true"), ("dnsPort", &udp_port)]).await;
    let not_a_port = refused_start(&[("dnsEnabled", "true"), ("dnsPort", "70000")]).await;

    assert_eq!(held.explained_format(), Some("DNS start-up failed:{}"));
    assert_eq!(not_a_port.explained_format(), None, "logged as `exception while starting:{{}}` with the exception");
    first.server.shutdown().await;
}

/// `DnsStartFailureTest.shouldRefuseToStartWhenTheDnsPortIsHeldNamingThePortAndTheCauseOnOneLine`.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_to_start_when_the_dns_port_is_held_naming_the_port_and_the_cause_on_one_line() {
    let other_application = held_udp_port();
    let udp_port = port_of(&other_application);

    let refused = refused_start(&[("dnsEnabled", "true"), ("dnsPort", &udp_port.to_string())]).await;

    assert_eq!(refused.listener, UdpListener::Dns);
    assert!(refused.message().starts_with(&port_could_not_be_opened_or_bound(udp_port)), "{}", refused.message());
    // the operating system's own words for the port being in use, under the exception of the transport in use
    assert!(refused.message().ends_with("Address already in use)"), "{}", refused.message());
    assert!(!refused.message().contains('\n'), "one line");
    assert!(refused.to_string().contains("\nCaused by: ") && refused.to_string().ends_with("Address already in use"), "{refused}");
    assert!(refused.port_unavailable);
}

/// `DnsStartFailureTest.shouldRefuseToStartWhenTheDnsPortIsHeldOnTheIpv4Wildcard`: on macOS the server's own bind
/// succeeds there, and the other socket would then get the queries sent to 127.0.0.1.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_to_start_when_the_dns_port_is_held_on_the_ipv4_wildcard() {
    let mut attempt = 1;
    loop {
        let other_application = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let udp_port = port_of(&other_application);
        let refused = refused_start(&[("dnsEnabled", "true"), ("dnsPort", &udp_port.to_string())]).await;
        if other_stack_taken_meanwhile(&refused, udp_port) && retry_besides(&other_application, attempt, &refused) {
            attempt += 1;
            continue;
        }

        assert_eq!(refused.listener, UdpListener::Dns);
        assert!(refused.message().starts_with(&port_could_not_be_opened_or_bound(udp_port)), "{}", refused.message());
        assert!(refused.port_unavailable);
        if DUAL_STACK_MAC_OS {
            assert!(refused.message().ends_with(&ipv4_wildcard_conflict(udp_port)), "{}", refused.message());
        }
        drop(other_application);
        let what = format!("the refused server must hold no socket on UDP port {udp_port}");
        if retry_unless_released(udp_port, dual_stack_bind_succeeds(udp_port), attempt, &what) {
            attempt += 1;
            continue;
        }
        break;
    }
}

/// `DnsStartFailureTest.shouldHaveClosedItsTcpListenerAndHoldNoUdpSocketWhenTheConstructorThrows`: the TCP listener
/// the refused server had bound is closed, and only the other application held the UDP port.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::await_holding_lock, reason = "the guard holds off child spawns across the refused start and its checks, on purpose")]
async fn should_have_closed_its_tcp_listener_and_hold_no_udp_socket_when_the_constructor_throws() {
    let mut udp_attempt = 1;
    loop {
        let other_application = held_udp_port();
        let udp_port = port_of(&other_application);
        let udp_port_text = udp_port.to_string();
        let dns = [("dnsEnabled", "true"), ("dnsPort", udp_port_text.as_str())];
        let mut attempt = 1;
        let no_spawn = crate::udp_port::no_spawn_meanwhile();
        let tcp_port = loop {
            let tcp_port = crate::tcp_port::free_tcp_port();
            let mut config = Config::for_tests();
            config.ports = vec![tcp_port];
            let error = start_error(config, &dns).await;
            // another process took the probed TCP port first (tests/support/tcp_port.rs)
            if error.get_ref().is_some_and(|e| e.is::<BindFailure>()) && attempt < crate::tcp_port::START_ATTEMPTS {
                attempt += 1;
                continue;
            }
            assert_eq!(udp_start_failure(error).listener, UdpListener::Dns);
            break tcp_port;
        };

        // `RefusedStart.assertStopped`: the stop is complete when the start returns, not merely begun
        let connected = std::net::TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port)), Duration::from_secs(5));
        assert_eq!(connected.map(drop).map_err(|e| e.kind()), Err(std::io::ErrorKind::ConnectionRefused), "the TCP listener on port {tcp_port} must be closed");
        drop(no_spawn);
        // only the other application held the port, so with it gone a socket left there is the server's, unless
        // another process took the released port
        drop(other_application);
        let rebound = UdpSocket::bind((Ipv4Addr::LOCALHOST, udp_port));
        let what = format!("the refused server holds no UDP socket: {rebound:?}");
        if retry_unless_released(udp_port, rebound.is_ok(), udp_attempt, &what) {
            udp_attempt += 1;
            continue;
        }
        break;
    }
}

/// The other application's bind of the first port probed, once the probe ran: its socket, or why the bind failed and
/// who held the port right then.
type OtherApplication = Arc<Mutex<Option<Result<UdpSocket, (std::io::Error, UdpHolders)>>>>;

/// Binds the other application's socket on `0.0.0.0` just after the server's first probe of a DNS port
/// (`DnsPortTakenAfterProbeTest.TakenAfterTheFirstProbe`); the bind, once made, is in the returned slot. A failed bind
/// is kept there rather than panicking inside the server's start (see [`taken_after_the_probe_by_another_process`]),
/// with the port's holders listed at once, before the server binds the port: a probe that left its socket open would be
/// this process's.
fn taken_after_the_first_probe() -> (Config, OtherApplication) {
    let other_application = Arc::new(Mutex::new(None));
    let slot = other_application.clone();
    let config = Config::for_tests().with_udp_port_probed(move |probed: SocketAddr| {
        let mut slot = slot.lock().unwrap();
        if slot.is_none() {
            let bound = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, probed.port()));
            *slot = Some(bound.map_err(|e| (e, UdpHolders::of(probed.port()))));
        }
    });
    (config, other_application)
}

/// The address the other application bound in [`taken_after_the_first_probe`], or why it bound none.
fn taken_address(other_application: &OtherApplication) -> Result<SocketAddr, String> {
    match &*other_application.lock().unwrap() {
        Some(Ok(socket)) => Ok(socket.local_addr().unwrap()),
        Some(Err((e, holders))) => Err(format!("its bind failed ({e}): {holders}")),
        None => Err("the server probed no port".to_owned()),
    }
}

/// [`other_stack_taken_meanwhile`] for a port [`taken_after_the_first_probe`]: with the test's socket on `0.0.0.0`, a
/// failing dual-stack bind names another process; and when the test's own bind at the probe found the port in use and
/// this process holding no socket on it (the server binds only after the probe), another process took the whole port after it was
/// found free, and the server's plain `EADDRINUSE` refusal is that process's doing.
fn taken_after_the_probe_by_another_process(refused: &UdpStartFailure, port: u16, other_application: &OtherApplication, attempt: usize) -> bool {
    match &*other_application.lock().unwrap() {
        Some(Ok(socket)) if socket.local_addr().is_ok_and(|a| a == SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))) => {
            other_stack_taken_meanwhile(refused, port) && retry_besides(socket, attempt, refused)
        }
        Some(Err((e, holders)))
            if e.kind() == std::io::ErrorKind::AddrInUse && holders.none_of_this_process() && refused.port_unavailable && refused.message().ends_with("Address already in use)") =>
        {
            eprintln!("{holders} since before the probe's bind, so a new port is tried");
            true
        }
        _ => false,
    }
}

/// A start of a server that was to be refused after the probe succeeded. On macOS another process that
/// took the whole port on `0.0.0.0` after the probe fails the hook's own bind ([`taken_after_the_first_probe`]) yet
/// leaves the server's dual-stack bind to succeed, so there is no refusal to attribute: a fresh port is tried only
/// while this process holds no socket on the port (the hook's holders, listed at once), and not on the last attempt.
/// Otherwise this panics naming the holders: a probe that left a socket open, a hook that bound the port, or a hook
/// that never ran.
fn started_after_the_probe(other_application: &OtherApplication, port: u16, attempt: usize) -> bool {
    let why = match &*other_application.lock().unwrap() {
        Some(Err((e, holders))) if holders.none_of_this_process() && attempt < crate::udp_port::START_ATTEMPTS => {
            eprintln!("the server started on UDP port {port} although the hook's bind failed ({e}): {holders}, so a new port is tried");
            return true;
        }
        Some(Err((e, holders))) => format!("although the hook's bind failed ({e}): {holders}"),
        Some(Ok(socket)) => format!("after the other application took {:?}", socket.local_addr()),
        None => "but the server probed no port".to_owned(),
    };
    panic!("the server started on UDP port {port} {why}")
}

/// `DnsPortTakenAfterProbeTest.shouldRefuseAnExplicitPortTakenOnTheIpv4WildcardAfterTheProbe`: on macOS the bind
/// then succeeds and the port is refused after it; on Linux the bind itself fails.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_an_explicit_port_taken_on_the_ipv4_wildcard_after_the_probe() {
    let mut attempt = 1;
    let (refused, dns_port, other_application) = loop {
        let dns_port = port_free_on_both_stacks();
        let (config, other_application) = taken_after_the_first_probe();
        let Some(error) = start_or_error(config, &[("dnsEnabled", "true"), ("dnsPort", &dns_port.to_string())]).await else {
            started_after_the_probe(&other_application, dns_port, attempt);
            attempt += 1;
            continue;
        };
        let refused = udp_start_failure(error);
        if taken_after_the_probe_by_another_process(&refused, dns_port, &other_application, attempt) && attempt < crate::udp_port::START_ATTEMPTS {
            attempt += 1;
            continue;
        }
        break (refused, dns_port, other_application);
    };

    let taken = taken_address(&other_application);
    assert_eq!(taken, Ok(SocketAddr::from((Ipv4Addr::UNSPECIFIED, dns_port))), "the other application took the port");
    assert_eq!(refused.listener, UdpListener::Dns);
    assert!(refused.port_unavailable);
    let start = format!("DNS mocking is enabled (dnsEnabled=true, dnsPort={dns_port}) but UDP port {dns_port} could not be opened or bound");
    assert!(refused.message().starts_with(&start), "{}", refused.message());
    if DUAL_STACK_MAC_OS {
        assert!(refused.message().ends_with(&ipv4_wildcard_conflict(dns_port)), "{}", refused.message());
    }
}

/// `DnsPortTakenAfterProbeTest.shouldPassOverAChosenPortTakenOnTheIpv4WildcardAfterTheProbe`.
#[tokio::test(flavor = "multi_thread")]
async fn should_pass_over_a_chosen_port_taken_on_the_ipv4_wildcard_after_the_probe() {
    const SERVED_NAME: &str = "served.dns-port-taken.example.";
    let mut attempt = 1;
    loop {
        let (config, other_application) = taken_after_the_first_probe();
        let running = crate::common::start_with(config, &[("dnsEnabled", "true"), ("dnsPort", "0")]).await;
        let dns_port = running.server.dns_port().expect("the DNS listener");

        let taken_port = match taken_address(&other_application) {
            Ok(taken) => taken.port(),
            // another process held the port the server chose when the hook bound it
            Err(why) if matches!(&*other_application.lock().unwrap(), Some(Err((_, holders))) if holders.none_of_this_process()) && attempt < crate::udp_port::START_ATTEMPTS => {
                eprintln!("the other application took no port: {why}, so the server starts again");
                running.server.shutdown().await;
                attempt += 1;
                continue;
            }
            Err(why) => panic!("the other application took the first port probed: {why}"),
        };
        assert!(taken_port > 0);
        assert_ne!(dns_port, taken_port, "the port the other application took");
        expect_a_record(running.port, SERVED_NAME, "10.9.8.5").await;
        let answered = address_answered_for(SERVED_NAME, SocketAddr::from((Ipv4Addr::LOCALHOST, dns_port))).await;
        assert_eq!(answered.as_deref(), Some("10.9.8.5"), "the answer to a query sent to the port the server reported");
        other_application.lock().unwrap().take();
        let what = "the server must hold no socket on the port it passed over";
        let retry = retry_unless_released(taken_port, dual_stack_bind_succeeds(taken_port), attempt, what);
        running.server.shutdown().await;
        if retry {
            attempt += 1;
            continue;
        }
        break;
    }
}

const LOCAL_BOUND_NAME: &str = "served.dns-local-bound-ip.example.";
const LOCAL_BOUND_ADDRESS: &str = "10.9.8.7";

/// `DnsLocalBoundIpTest.assertAnsweredOnlyOnTheLoopback`.
async fn assert_answered_only_on_the_loopback(running: crate::common::Running, another_address: Ipv4Addr) {
    let dns_port = running.server.dns_port().expect("the DNS listener");
    expect_a_record(running.port, LOCAL_BOUND_NAME, LOCAL_BOUND_ADDRESS).await;

    let on_loopback = address_answered_for(LOCAL_BOUND_NAME, SocketAddr::from((Ipv4Addr::LOCALHOST, dns_port))).await;
    assert_eq!(on_loopback.as_deref(), Some(LOCAL_BOUND_ADDRESS), "a query to the local bound IP");
    let elsewhere = address_answered_for(LOCAL_BOUND_NAME, SocketAddr::from((another_address, dns_port))).await;
    assert_eq!(elsewhere, None, "a query to {another_address}");
    running.server.shutdown().await;
}

/// `DnsLocalBoundIpTest.shouldAnswerOnlyOnTheLocalBoundIpOnAPortItChose`.
#[tokio::test(flavor = "multi_thread")]
async fn should_answer_only_on_the_local_bound_ip_on_a_port_it_chose() {
    let another_address = another_address_of_this_host();
    let running = crate::common::start(&[("localBoundIP", "127.0.0.1"), ("dnsEnabled", "true"), ("dnsPort", "0")]).await;
    assert_answered_only_on_the_loopback(running, another_address).await;
}

/// `DnsLocalBoundIpTest.shouldAnswerOnlyOnTheLocalBoundIpOnAnExplicitPort`: a found port can be taken before the
/// server binds it, so another is tried (`startOnAFoundDnsPort`).
#[tokio::test(flavor = "multi_thread")]
async fn should_answer_only_on_the_local_bound_ip_on_an_explicit_port() {
    let another_address = another_address_of_this_host();
    let mut last_refusal = None;
    for _ in 0..5 {
        let udp_port = crate::udp_port::free_udp_port();
        let dns_port = udp_port.to_string();
        let properties = [("localBoundIP", "127.0.0.1"), ("dnsEnabled", "true"), ("dnsPort", dns_port.as_str())];
        crate::scratch_cwd::enter();
        let config = properties.iter().fold(Config::for_tests(), |c, (k, v)| c.with_property(k, v));
        match Server::start(config).await {
            Ok(server) => {
                let port = server.ports()[0];
                assert_eq!(server.dns_port().map(|p| p.to_string()), Some(dns_port));
                return assert_answered_only_on_the_loopback(crate::common::Running { server, port }, another_address).await;
            }
            Err(e) => {
                let refused = udp_start_failure(e);
                assert!(port_taken(&refused), "{refused}");
                // another process took the port found; a socket of this process there fails the test
                let holders = UdpHolders::of(udp_port);
                assert!(holders.none_of_this_process(), "{}: {holders}", refused.message());
                eprintln!("{}: {holders}, so a new port is tried", refused.message());
                last_refusal = Some(refused);
            }
        }
    }
    panic!("another socket took each of the UDP ports found: {last_refusal:?}");
}

/// `DnsLocalBoundIpTest.shouldTryAnotherFoundPortWhenTheOneFoundIsTakenOnEitherTransport`.
#[test]
fn should_try_another_found_port_when_the_one_found_is_taken_on_either_transport() {
    let in_use = std::io::Error::from(std::io::ErrorKind::AddrInUse);
    assert!(port_taken(&UdpStartFailure::bind(UdpListener::Http3, 53, &in_use)), "NIO");
    assert!(port_taken(&UdpStartFailure::bind(UdpListener::Dns, 53, &in_use)), "epoll");
    assert!(!port_taken(&UdpStartFailure::bind(UdpListener::Dns, 53, &std::io::Error::from(std::io::ErrorKind::PermissionDenied))));
    assert!(!port_taken(&UdpStartFailure::other(UdpListener::Dns, 53, "refused")));
}

/// `DnsLocalBoundIpTest.shouldAnswerOnEveryAddressWithoutALocalBoundIp`. Opted out on macOS unless
/// `MOCK_SERVER_LAN_UDP_TESTS=1`: its application firewall can hold the answer back for minutes, which made this
/// test flaky (see [`lan_udp_observable`]); the query is sent again for up to [`DELIVERY_WAIT`].
#[tokio::test(flavor = "multi_thread")]
async fn should_answer_on_every_address_without_a_local_bound_ip() {
    if !lan_udp_observable("should_answer_on_every_address_without_a_local_bound_ip") {
        return;
    }
    let another_address = another_address_of_this_host();
    let running = crate::common::start(&[("dnsEnabled", "true"), ("dnsPort", "0")]).await;
    let dns_port = running.server.dns_port().expect("the DNS listener");
    expect_a_record(running.port, LOCAL_BOUND_NAME, LOCAL_BOUND_ADDRESS).await;

    let answered = address_answered_within(LOCAL_BOUND_NAME, SocketAddr::from((another_address, dns_port)), DELIVERY_WAIT).await;
    assert_eq!(answered.as_deref(), Some(LOCAL_BOUND_ADDRESS), "a query to {another_address}");
    running.server.shutdown().await;
}

// `Http3ServerIpv4PortConflictTest`: the HTTP/3 listener's `Ipv4UdpPortProbe` handling, through
// `Server::start` with `http3Port` (upstream starts `Http3Server` on its own, which MockServer does for `http3Port`).

/// `Http3ServerIpv4PortConflictTest.REBIND_ITERATIONS`: a refusal or stop that left the socket to the runtime would fail
/// the rebind on most iterations.
const REBIND_ITERATIONS: usize = 25;

/// The end of the message of an HTTP/3 port refused because another socket holds it on `0.0.0.0` (macOS): the
/// `BindException` upstream's test reads, as the refusal's underlying error.
fn http3_ipv4_wildcard_conflict(port: u16) -> String {
    format!(
        "BindException: UDP port {port} is already in use by another socket listening on 0.0.0.0:{port}, so HTTP/3 requests to localhost:{port} would reach that socket instead of MockServer; stop the application that holds it or choose a different http3Port (to find it run: lsof -nP -iUDP:{port}))"
    )
}

/// `assertThat(thrown, instanceOf(BindException.class))` and `getPort() == -1`: refused by the HTTP/3 listener for its
/// port, the cause a `java.net.BindException`.
fn assert_http3_bind_refused(refused: &UdpStartFailure, port: u16) {
    assert_eq!(refused.listener, UdpListener::Http3, "{refused}");
    assert_eq!(refused.port, i64::from(port));
    assert!(refused.port_unavailable, "{refused}");
    assert!(refused.to_string().contains("\nCaused by: java.net.BindException: "), "{refused}");
}

/// `Http3ServerIpv4PortConflictTest.shouldRefuseAPortHeldOnTheIpv4Wildcard`.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_a_port_held_on_the_ipv4_wildcard() {
    let mut attempt = 1;
    loop {
        let other_application = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = port_of(&other_application);
        let refused = refused_start(&[("http3Port", &port.to_string())]).await;
        if other_stack_taken_meanwhile(&refused, port) && retry_besides(&other_application, attempt, &refused) {
            attempt += 1;
            continue;
        }

        assert_http3_bind_refused(&refused, port);
        if DUAL_STACK_MAC_OS {
            assert!(refused.message().ends_with(&http3_ipv4_wildcard_conflict(port)), "{}", refused.message());
        }
        drop(other_application);
        let what = format!("the refused server must hold no socket on UDP port {port}");
        if retry_unless_released(port, dual_stack_bind_succeeds(port), attempt, &what) {
            attempt += 1;
            continue;
        }
        break;
    }
}

/// `Http3ServerIpv4PortConflictTest.shouldRefuseAPortTakenOnTheIpv4WildcardAfterTheProbe`: another application takes
/// the port between the probe and the bind; on macOS the bind then succeeds and the port is refused after it, on Linux
/// the bind itself fails.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_a_port_taken_on_the_ipv4_wildcard_after_the_probe() {
    let mut attempt = 1;
    loop {
        let port = port_free_on_both_stacks();
        let (config, other_application) = taken_after_the_first_probe();
        let Some(error) = start_or_error(config, &[("http3Port", &port.to_string())]).await else {
            started_after_the_probe(&other_application, port, attempt);
            attempt += 1;
            continue;
        };
        let refused = udp_start_failure(error);
        if taken_after_the_probe_by_another_process(&refused, port, &other_application, attempt) && attempt < crate::udp_port::START_ATTEMPTS {
            attempt += 1;
            continue;
        }

        let taken = taken_address(&other_application);
        assert_eq!(taken, Ok(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))), "the other application took the port");
        assert_http3_bind_refused(&refused, port);
        if DUAL_STACK_MAC_OS {
            assert!(refused.message().ends_with(&http3_ipv4_wildcard_conflict(port)), "{}", refused.message());
        }
        other_application.lock().unwrap().take();
        let what = format!("the refused server must hold no socket on UDP port {port}");
        if retry_unless_released(port, dual_stack_bind_succeeds(port), attempt, &what) {
            attempt += 1;
            continue;
        }
        break;
    }
}

/// `Http3ServerIpv4PortConflictTest.shouldReleaseARefusedPort`. Each iteration starts again on a fresh port while other
/// processes alone took the one it found or released.
#[tokio::test(flavor = "multi_thread")]
async fn should_release_a_refused_port() {
    for i in 0..REBIND_ITERATIONS {
        let mut attempt = 1;
        let server = loop {
            let port = port_free_on_both_stacks();
            let other_application = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)) {
                Ok(socket) => socket,
                Err(e) => {
                    retry_unless_released(port, false, attempt, &format!("iteration {i}: the other application binds the port: {e}"));
                    attempt += 1;
                    continue;
                }
            };
            let refused = refused_start(&[("http3Port", &port.to_string())]).await;
            assert_http3_bind_refused(&refused, port);
            drop(other_application);

            match started_on_released_http3_port(port, attempt, &format!("iteration {i}: start on the refused port {port}")).await {
                Some(server) => break server,
                None => attempt += 1,
            }
        };
        server.shutdown().await;
    }
}

/// `Http3ServerIpv4PortConflictTest.shouldReleaseAStoppedPortForAnImmediateRestart`. Each iteration starts again on a
/// fresh port while other processes alone took the one it found or released.
#[tokio::test(flavor = "multi_thread")]
async fn should_release_a_stopped_port_for_an_immediate_restart() {
    for i in 0..REBIND_ITERATIONS {
        let mut attempt = 1;
        let server = loop {
            let port = port_free_on_both_stacks();
            let Some(first) = started_on_released_http3_port(port, attempt, &format!("iteration {i}: start on UDP port {port}")).await else {
                attempt += 1;
                continue;
            };
            first.shutdown().await;

            match started_on_released_http3_port(port, attempt, &format!("iteration {i}: restart on UDP port {port}")).await {
                Some(server) => break server,
                None => attempt += 1,
            }
        };
        server.shutdown().await;
    }
}

/// `Http3ServerIpv4PortConflictTest.shouldStartOnAFreeExplicitPort` (`Http3TestServer.startWithHttp3`: a found port,
/// another tried while one is taken meanwhile).
#[tokio::test(flavor = "multi_thread")]
async fn should_start_on_a_free_explicit_port() {
    let (running, port) = crate::common::start_with_http3(&[]).await;

    assert_eq!(running.server.http3_port(), Some(port));
    running.server.shutdown().await;
}

/// `Http3ServerIpv4PortConflictTest.shouldStartOnAnEphemeralPort`: `Http3Server.start(0)` binds a port the operating
/// system chooses, but MockServer starts no HTTP/3 listener for `http3Port` 0 (`MockServer`: `http3Port > 0`), and
/// `alt-svc` echoes the configured port. What `Server::start` can reach: the server starts, without HTTP/3.
#[tokio::test(flavor = "multi_thread")]
async fn should_start_on_an_ephemeral_port() {
    let running = crate::common::start(&[("http3Port", "0")]).await;

    assert_eq!(running.server.http3_port(), None);
    running.server.shutdown().await;
}

/// Set, in the child process [`should_tell_another_process_holding_a_released_port_from_a_socket_left_behind`] starts
/// to run [`hold_a_udp_port_for_the_parent_test`], to the file the child writes its port to (its output is the test
/// harness's).
const HOLD_UDP_PORT: &str = "MOCK_SERVER_HOLD_UDP_PORT";

/// Not a test of its own: in a child process, holds a dual-stack UDP socket, writes its port to the file
/// [`HOLD_UDP_PORT`] names and keeps the socket until its standard input closes.
#[test]
#[ignore = "run by should_tell_another_process_holding_a_released_port_from_a_socket_left_behind in a child process"]
fn hold_a_udp_port_for_the_parent_test() {
    let Ok(port_file) = std::env::var(HOLD_UDP_PORT) else { return };
    let held = held_udp_port_on_both_stacks();
    let written = format!("{port_file}.tmp");
    std::fs::write(&written, port_of(&held).to_string()).unwrap();
    std::fs::rename(&written, &port_file).unwrap();
    std::io::Read::read_to_end(&mut std::io::stdin(), &mut Vec::new()).unwrap();
    drop(held);
}

/// [`retry_unless_released`]: a port this process holds fails the check naming this process, one another
/// process holds is retried (naming it) but for the last attempt, and a free port passes.
#[test]
fn should_tell_another_process_holding_a_released_port_from_a_socket_left_behind() {
    let message = |result: std::thread::Result<bool>| result.expect_err("a panic").downcast_ref::<String>().cloned().unwrap_or_default();

    // a socket of this process: left behind by the server, never retried
    let own = held_udp_port_on_both_stacks();
    let own_port = port_of(&own);
    let held_here = message(std::panic::catch_unwind(|| retry_unless_released(own_port, false, 1, "left behind")));
    let fd = std::os::fd::AsRawFd::as_raw_fd(&own);
    assert!(held_here.starts_with(&format!("left behind: UDP port {own_port} is held by this test process (pid {}): fd {fd} on ", std::process::id())), "{held_here}");
    assert!(held_here.contains("the system lists this test process"), "{held_here}");
    assert!(!held_here.contains("another process"), "{held_here}");
    drop(own);
    assert!(!retry_unless_released(own_port, true, 1, "released"), "a check that found the port free passes");
    // this process's descriptors that could not be read prove nothing: the failed check stands
    assert!(!UdpHolders { port: own_port, own: Err("/dev/fd: denied".to_owned()), listed: Ok(Vec::new()) }.none_of_this_process());

    // another process's socket: retried, but not on the last attempt
    let port_file = crate::scratch_cwd::enter().join(format!("held-udp-port-{}", std::process::id()));
    drop(std::fs::remove_file(&port_file));
    let spawning = crate::udp_port::spawning();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "udp_start_failure::hold_a_udp_port_for_the_parent_test", "--ignored", "--test-threads=1"])
        .env(HOLD_UDP_PORT, &port_file)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    drop(spawning);
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let other_port: u16 = loop {
        if let Ok(port) = std::fs::read_to_string(&port_file) {
            break port.parse().unwrap();
        }
        assert!(child.try_wait().unwrap().is_none(), "the child process exited before it held a port");
        if std::time::Instant::now() > deadline {
            drop(child.kill());
            panic!("the child process held no port in 60 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let holders = UdpHolders::of(other_port);
    let retried = std::panic::catch_unwind(|| retry_unless_released(other_port, false, 1, "taken"));
    let last = message(std::panic::catch_unwind(|| retry_unless_released(other_port, false, crate::udp_port::START_ATTEMPTS, "taken")));
    drop(child.stdin.take());
    child.wait().unwrap();
    drop(std::fs::remove_file(&port_file));

    assert!(holders.none_of_this_process(), "{holders}");
    assert!(
        holders.to_string().starts_with(&format!("this test process (pid {}) holds no socket on UDP port {other_port}; the system lists another process (pid {}", std::process::id(), child.id())),
        "{holders}"
    );
    assert!(retried.is_ok_and(|retried| retried));
    assert!(last.starts_with(&format!("taken: this test process (pid {}) holds no socket on UDP port {other_port}", std::process::id())), "{last}");
}

/// [`crate::udp_port::retry_taken_meanwhile`]: a start refused on a port taken between the probe and the
/// bind is retried only while this process holds no socket on it; a socket of this process there (a probe or listener
/// that leaked it) fails the start naming this process, and a refusal that is not about a taken port is never retried.
/// The refusals are built as `Server::start` returns them.
#[test]
fn should_fail_a_start_on_a_port_taken_meanwhile_by_this_process_naming_it() {
    let message = |result: std::thread::Result<bool>| result.expect_err("a panic").downcast_ref::<String>().cloned().unwrap_or_default();
    let refused = |failure: UdpStartFailure| std::io::Error::other(failure);
    let in_use = std::io::Error::from(std::io::ErrorKind::AddrInUse);
    let leaked = held_udp_port_on_both_stacks();
    let port = port_of(&leaked);
    let fd = std::os::fd::AsRawFd::as_raw_fd(&leaked);
    for listener in [UdpListener::Http3, UdpListener::Dns] {
        let error = refused(UdpStartFailure::bind(listener, i64::from(port), &in_use));
        assert!(crate::udp_port::taken_meanwhile(&error), "{error}");
        let failed = message(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| crate::udp_port::retry_taken_meanwhile(&error, 1))));
        assert!(failed.contains(&format!("UDP port {port} is held by this test process (pid {}): fd {fd} on ", std::process::id())), "{listener:?}: {failed}");
    }
    drop(leaked);
    assert!(!crate::udp_port::retry_taken_meanwhile(&refused(UdpStartFailure::out_of_range(UdpListener::Http3, 70000)), 1), "not about a taken port");
    assert!(!crate::udp_port::retry_taken_meanwhile(&refused(UdpStartFailure::other(UdpListener::Dns, i64::from(port), "refused")), 1));
    assert!(!crate::udp_port::retry_taken_meanwhile(&std::io::Error::from(std::io::ErrorKind::AddrInUse), 1), "not a UDP listener's refusal");
}

/// [`other_stack_taken_meanwhile`]: only a plain bind failure while another socket holds the port's IPv6 side counts as
/// the race, never the conflict the test set up, and never a plain bind failure with the IPv6 side free.
#[test]
fn should_tell_another_process_on_the_ipv6_side_from_a_wrong_refusal() {
    use socket2::{Domain, Protocol, Socket, Type};
    // Another process can take the port's IPv6 side while the test runs (the very race the classifier is for): then a
    // fresh port is tried, but only while this process holds no socket on the port besides the test's own.
    let taken_by_another_process = |port: u16, own: &UdpSocket, attempt: usize, what: &str| {
        crate::udp_port::retry_taken_port(port, &[std::os::fd::AsRawFd::as_raw_fd(own)], attempt, what);
    };
    for attempt in 1.. {
        // a port whose IPv6 side no other process holds when the test starts
        let (own, port) = (0..20)
            .map(|_| UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap())
            .map(|own| {
                let port = port_of(&own);
                (own, port)
            })
            .find(|(_, port)| !DUAL_STACK_MAC_OS || dual_stack_bind_succeeds(*port))
            .expect("a port held on 0.0.0.0 whose IPv6 side is free in 20 attempts");
        let in_use = UdpStartFailure::bind(UdpListener::Http3, i64::from(port), &std::io::Error::from(std::io::ErrorKind::AddrInUse));
        let conflict = UdpStartFailure::ipv4_wildcard_conflict(UdpListener::Http3, port);

        if other_stack_taken_meanwhile(&in_use, port) {
            taken_by_another_process(port, &own, attempt, "the IPv6 side is free: the refusal is wrong");
            continue;
        }
        assert!(!other_stack_taken_meanwhile(&conflict, port));

        // another process's dual-stack socket on the same port, which macOS lets it bind over the IPv4 wildcard
        let another = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        another.set_only_v6(false).unwrap();
        if another.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into()).is_err() {
            if DUAL_STACK_MAC_OS {
                taken_by_another_process(port, &own, attempt, "macOS binds a dual-stack socket over the IPv4 wildcard");
                continue;
            }
            return;
        }
        assert!(other_stack_taken_meanwhile(&in_use, port));
        assert!(!other_stack_taken_meanwhile(&conflict, port), "the conflict the test set up is never retried");
        return;
    }
}

/// [`started_after_the_probe`]: a server that started after the hook's bind failed is retried (with a
/// fresh port) only while this process holds no socket on the port, and not on the last attempt; a started server
/// whose hook bound, or whose hook never ran, or a port this process holds, fails naming it.
#[test]
fn should_retry_a_start_after_a_failed_hook_bind_only_while_this_process_holds_no_socket() {
    let message = |result: std::thread::Result<bool>| result.expect_err("a panic").downcast_ref::<String>().cloned().unwrap_or_default();
    let failed = |own: Vec<(std::os::fd::RawFd, SocketAddr)>| -> OtherApplication {
        let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 4242));
        let _ = address;
        Arc::new(Mutex::new(Some(Err((std::io::Error::from(std::io::ErrorKind::AddrInUse), UdpHolders { port: 4242, own: Ok(own), listed: Ok(Vec::new()) })))))
    };
    // another process alone held the port when the hook bound: retried, but not on the last attempt
    assert!(started_after_the_probe(&failed(Vec::new()), 4242, 1));
    let last = message(std::panic::catch_unwind(|| started_after_the_probe(&failed(Vec::new()), 4242, crate::udp_port::START_ATTEMPTS)));
    assert!(last.starts_with("the server started on UDP port 4242 although the hook's bind failed"), "{last}");
    assert!(last.contains("holds no socket on UDP port 4242"), "{last}");
    // a socket of this process: a probe left it open, never retried
    let own = failed(vec![(7, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 4242)))]);
    let held = message(std::panic::catch_unwind(|| started_after_the_probe(&own, 4242, 1)));
    assert!(held.contains(&format!("held by this test process (pid {}): fd 7 on 0.0.0.0:4242", std::process::id())), "{held}");
    // the hook bound the port, or never ran: the server's start is the failure
    let bound: OtherApplication = Arc::new(Mutex::new(Some(Ok(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap()))));
    assert!(message(std::panic::catch_unwind(|| started_after_the_probe(&bound, 4242, 1))).starts_with("the server started on UDP port 4242"));
    let never: OtherApplication = Arc::new(Mutex::new(None));
    assert!(message(std::panic::catch_unwind(|| started_after_the_probe(&never, 4242, 1))).contains("the server probed no port"));
}

/// `Http3ServerIpv4PortConflictTest.shouldReportAPortHeldOnIpv4`.
#[test]
fn should_report_a_port_held_on_ipv4() {
    let other_application = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();

    assert!(mock_server::udp_port_held_on_ipv4(port_of(&other_application)));
}

/// `Http3ServerIpv4PortConflictTest.shouldReportAFreePortAsNotHeldOnIpv4`.
#[test]
fn should_report_a_free_port_as_not_held_on_ipv4() {
    assert!(!mock_server::udp_port_held_on_ipv4(crate::udp_port::free_udp_port()));
}

// The rest of `DnsStartFailureTest` and `Http3StartFailureTest`. Their in-JVM-only cases (a thread's
// interrupt, non-daemon threads, a buffer leak, a `Configuration` subclass that throws) are listed in
// conformance/upstream's `skips/in-jvm/`.

/// `Http3StartFailureTest`'s start of the refusal: the port could not be bound.
fn http3_port_could_not_be_bound(udp_port: u16) -> String {
    format!(
        "HTTP/3 is enabled (http3Port={udp_port}) but UDP port {udp_port} could not be bound, so MockServer cannot start: free the port if another application holds it, choose a different http3Port, or remove http3Port to run without HTTP/3 (underlying error: BindException: "
    )
}

/// `Http3StartFailureTest`'s start of the refusal: the HTTP/3 server failed for a reason other than its port.
fn http3_server_could_not_start(udp_port: u16) -> String {
    format!(
        "HTTP/3 is enabled (http3Port={udp_port}) but its server could not start on UDP port {udp_port}, so MockServer cannot start: fix the underlying error or remove http3Port to run without HTTP/3 (underlying error: "
    )
}

/// `Http3StartFailureTest.heldUdpPortOnBothStacks`: held by a dual-stack socket, which fails the server's own bind on
/// every platform as a held port does on Linux.
fn held_udp_port_on_both_stacks() -> UdpSocket {
    for _ in 0..20 {
        if let Ok(socket) = UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, crate::udp_port::free_udp_port())) {
            return socket;
        }
    }
    panic!("no UDP port free for a dual-stack bind in 20 attempts");
}

/// `RefusedStart.assertStopped`: the TCP listener the refused server had bound on `tcp_port` is closed. The caller holds
/// [`crate::udp_port::no_spawn_meanwhile`] from the start to this check: a child spawned meanwhile would hold the
/// listener open.
fn assert_tcp_listener_closed(tcp_port: u16) {
    let connected = std::net::TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_port)), Duration::from_secs(5));
    assert_eq!(connected.map(drop).map_err(|e| e.kind()), Err(std::io::ErrorKind::ConnectionRefused), "the TCP listener on port {tcp_port} must be closed");
}

/// A start with `properties` on a TCP port found free, refused by a UDP listener; another TCP port is tried while the
/// one found is taken meanwhile (tests/support/tcp_port.rs). Returns the refusal and the TCP port the server had bound.
async fn refused_start_on_a_tcp_port(properties: &[(&str, &str)]) -> (UdpStartFailure, u16) {
    let mut attempt = 1;
    loop {
        let tcp_port = crate::tcp_port::free_tcp_port();
        let mut config = Config::for_tests();
        config.ports = vec![tcp_port];
        let error = start_error(config, properties).await;
        if error.get_ref().is_some_and(|e| e.is::<BindFailure>()) && attempt < crate::tcp_port::START_ATTEMPTS {
            attempt += 1;
            continue;
        }
        return (udp_start_failure(error), tcp_port);
    }
}

/// `Http3StartFailureTest.shouldRefuseToStartWhenTheHttp3PortIsHeldNamingThePortAndTheCauseOnOneLine`: held on the IPv4
/// wildcard, which MockServer refuses on macOS, and whose bind fails elsewhere.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_to_start_when_the_http3_port_is_held_naming_the_port_and_the_cause_on_one_line() {
    let other_application = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let udp_port = port_of(&other_application);

    let refused = refused_start(&[("http3Port", &udp_port.to_string())]).await;

    assert_eq!(refused.listener, UdpListener::Http3);
    assert!(refused.message().starts_with(&http3_port_could_not_be_bound(udp_port)), "{}", refused.message());
    assert!(refused.message().ends_with(')'), "{}", refused.message());
    assert!(!refused.message().contains('\n'), "one line");
    assert!(refused.to_string().contains("\nCaused by: java.net.BindException: "), "{refused}");
    assert!(refused.port_unavailable);
}

/// `Http3StartFailureTest.shouldRefuseToStartWhenTheBindItselfFails`. Its check that no non-daemon thread is left
/// running has no counterpart here: what a refused `Server::start` spawned is stopped with it
/// (`should_have_closed_its_tcp_listener_and_hold_no_udp_socket_when_http3_is_refused`).
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_to_start_when_the_bind_itself_fails() {
    let other_application = held_udp_port_on_both_stacks();
    let udp_port = port_of(&other_application);

    let refused = refused_start(&[("http3Port", &udp_port.to_string())]).await;

    assert_eq!(refused.listener, UdpListener::Http3);
    assert!(refused.message().starts_with(&http3_port_could_not_be_bound(udp_port)), "{}", refused.message());
    assert!(!refused.message().contains("would reach that socket instead of MockServer"), "{}", refused.message());
    assert!(refused.to_string().contains("\nCaused by: java.net.BindException: "), "{refused}");
}

/// `Http3StartFailureTest.shouldHaveClosedItsTcpListenerAndHoldNoUdpSocketWhenTheConstructorThrows`.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::await_holding_lock, reason = "the guard holds off child spawns across the refused start and its checks, on purpose")]
async fn should_have_closed_its_tcp_listener_and_hold_no_udp_socket_when_http3_is_refused() {
    let mut attempt = 1;
    loop {
        let other_application = held_udp_port_on_both_stacks();
        let udp_port = port_of(&other_application);

        let no_spawn = crate::udp_port::no_spawn_meanwhile();
        let (refused, tcp_port) = refused_start_on_a_tcp_port(&[("http3Port", &udp_port.to_string())]).await;

        assert_eq!(refused.listener, UdpListener::Http3);
        assert_tcp_listener_closed(tcp_port);
        drop(no_spawn);
        // only the other application held the port on both stacks, so with it gone a socket left there is the
        // server's, unless another process took the released port
        drop(other_application);
        let what = format!("the refused server must hold no socket on UDP port {udp_port}");
        if retry_unless_released(udp_port, dual_stack_bind_succeeds(udp_port), attempt, &what) {
            attempt += 1;
            continue;
        }
        break;
    }
}

/// A `tlsMutualAuthenticationCertificateChain` file holding `content`, in this process's scratch directory.
fn mutual_authentication_chain(name: &str, content: Option<&str>) -> String {
    let path = crate::scratch_cwd::enter().join(name);
    match content {
        Some(content) => std::fs::write(&path, content).unwrap(),
        None => drop(std::fs::remove_file(&path)),
    }
    path.to_string_lossy().into_owned()
}

/// `Http3StartFailureTest.shouldRefuseToStartWhenTheTlsContextForQuicCannotBeBuilt`: `Http3Server.buildQuicSslContext`
/// reads the chain before the UDP port is bound. The underlying error is the root cause, as the oracle prints it
/// (`IOException: Invalid lenByte`), and the cause names the file.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_to_start_when_the_tls_context_for_quic_cannot_be_built() {
    let not_a_certificate = mutual_authentication_chain("not-a-certificate.pem", Some("-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n"));
    let mut attempt = 1;
    loop {
        // held through the start, which refuses before the port is checked (see `refused_fixed_pair`)
        let other_application = held_udp_port_on_both_stacks();
        let udp_port = port_of(&other_application);

        let refused = refused_start(&[
            ("tlsMutualAuthenticationRequired", "true"),
            ("tlsMutualAuthenticationCertificateChain", &not_a_certificate),
            ("http3Port", &udp_port.to_string()),
        ])
        .await;

        assert_eq!(refused.listener, UdpListener::Http3);
        assert_eq!(refused.message(), format!("{}IOException: Invalid lenByte)", http3_server_could_not_start(udp_port)));
        assert!(
            refused.to_string().contains(&format!("\nCaused by: java.lang.RuntimeException: Exception reading X509 from PEM file {not_a_certificate}\n")),
            "{refused}"
        );
        assert!(refused.to_string().ends_with("\nCaused by: java.io.IOException: Invalid lenByte"), "{refused}");
        assert!(!refused.port_unavailable);
        drop(other_application);
        let what = format!("the refused server must hold no socket on UDP port {udp_port}");
        if retry_unless_released(udp_port, dual_stack_bind_succeeds(udp_port), attempt, &what) {
            attempt += 1;
            continue;
        }
        break;
    }
}

/// The chain read as the TCP path reads it, without `tlsMutualAuthenticationRequired`: a missing file refuses the start
/// with `FileInputStream`'s words (the oracle's).
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_to_start_when_the_mutual_authentication_chain_for_quic_is_missing() {
    let missing = mutual_authentication_chain("missing-chain.pem", None);
    let udp_port = crate::udp_port::free_udp_port();

    let refused = refused_start(&[("tlsMutualAuthenticationCertificateChain", &missing), ("http3Port", &udp_port.to_string())]).await;

    assert_eq!(refused.listener, UdpListener::Http3);
    assert_eq!(refused.message(), format!("{}FileNotFoundException: {missing} (No such file or directory))", http3_server_could_not_start(udp_port)));
    assert!(
        refused.to_string().ends_with(&format!(
            ": java.lang.RuntimeException: Exception reading X509 from PEM file {missing}\nCaused by: java.io.FileNotFoundException: {missing} (No such file or directory)"
        )),
        "{refused}"
    );
}

fn tls_fixture(name: &str) -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/tls").join(name).display().to_string()
}

/// The HTTP/3 start refused with the fixed pair `key` / `cert`. The pair is read before the UDP port is
/// checked, so the port is held on both stacks through the start: no other socket of the test run can
/// take it meanwhile, a refusal for the port would fail `!port_unavailable`, and once the holder is gone a socket left
/// there is the server's, unless another process took the released port (then a fresh one is tried).
async fn refused_fixed_pair(key: &str, cert: &str) -> (UdpStartFailure, u16) {
    let mut attempt = 1;
    loop {
        let other_application = held_udp_port_on_both_stacks();
        let udp_port = port_of(&other_application);
        let refused = refused_start(&[("privateKeyPath", key), ("x509CertificatePath", cert), ("http3Port", &udp_port.to_string())]).await;
        assert_eq!(refused.listener, UdpListener::Http3);
        assert!(!refused.port_unavailable, "{refused}");
        drop(other_application);
        let what = format!("the refused server must hold no socket on UDP port {udp_port}");
        if retry_unless_released(udp_port, dual_stack_bind_succeeds(udp_port), attempt, &what) {
            attempt += 1;
            continue;
        }
        return (refused, udp_port);
    }
}

/// `Http3Server.buildQuicSslContext` reads a fixed pair eagerly (`BCKeyAndCertificateFactory.privateKey`, then
/// `certificateChain`), where the TCP path builds its context at the first handshake. Each refusal below was read off
/// the HTTP/3 oracle, one container per pair: a key file that is missing or holds no PEM object.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_to_start_when_the_fixed_private_key_for_quic_cannot_be_read() {
    let missing = mutual_authentication_chain("missing-fixed-key.pem", None);
    let (refused, udp_port) = refused_fixed_pair(&missing, &tls_fixture("fixed-ok-cert.pem")).await;

    assert_eq!(refused.message(), format!("{}FileNotFoundException: {missing} (No such file or directory))", http3_server_could_not_start(udp_port)));
    assert!(
        refused.to_string().ends_with(&format!(
            "\nCaused by: java.lang.RuntimeException: Exception reading private key from PEM file\nCaused by: java.lang.RuntimeException: Exception while loading \"{missing}\"\nCaused by: java.io.FileNotFoundException: {missing} (No such file or directory)"
        )),
        "{refused}"
    );

    let (refused, udp_port) = refused_fixed_pair(&tls_fixture("invalid.pem"), &tls_fixture("fixed-ok-cert.pem")).await;
    let npe = "Cannot invoke \"shaded_package.org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getPrivateKeyAlgorithm()\" because \"<parameter1>\" is null";
    assert_eq!(refused.message(), format!("{}NullPointerException: {npe})", http3_server_could_not_start(udp_port)));
    assert!(
        refused.to_string().ends_with(&format!(
            "\nCaused by: java.lang.RuntimeException: Exception reading private key from PEM file\nCaused by: java.lang.RuntimeException: Exception reading private key from PEM file\nCaused by: shaded_package.org.bouncycastle.openssl.PEMException: unable to convert key pair: {npe}\nCaused by: java.lang.NullPointerException: {npe}"
        )),
        "{refused}"
    );
}

/// A PEM block whose base64 does not decode: BouncyCastle's decoder failure is the root cause (the oracle's words).
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_to_start_when_the_fixed_private_key_for_quic_is_malformed_pem() {
    let malformed = mutual_authentication_chain("malformed-fixed-key.pem", Some("-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n"));
    let (refused, udp_port) = refused_fixed_pair(&malformed, &tls_fixture("fixed-ok-cert.pem")).await;

    assert_eq!(refused.message(), format!("{}StringIndexOutOfBoundsException: Index 9 out of bounds for length 9)", http3_server_could_not_start(udp_port)));
    assert!(
        refused.to_string().contains("\nCaused by: java.io.IOException: malformed PEM data: unable to decode base64 string: Index 9 out of bounds for length 9\n"),
        "{refused}"
    );
}

/// A certificate file that is missing, holds no certificate data, or holds no certificate at all.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_to_start_when_the_fixed_certificate_for_quic_cannot_be_read() {
    let key = tls_fixture("fixed-ok-key.pem");
    let missing = mutual_authentication_chain("missing-fixed-cert.pem", None);
    let (refused, udp_port) = refused_fixed_pair(&key, &missing).await;
    assert_eq!(refused.message(), format!("{}FileNotFoundException: {missing} (No such file or directory))", http3_server_could_not_start(udp_port)));
    assert!(
        refused.to_string().ends_with(&format!(
            "\nCaused by: java.lang.RuntimeException: Exception reading X509 from PEM file {missing}\nCaused by: java.io.FileNotFoundException: {missing} (No such file or directory)"
        )),
        "{refused}"
    );

    let invalid = tls_fixture("invalid.pem");
    let (refused, udp_port) = refused_fixed_pair(&key, &invalid).await;
    assert_eq!(refused.message(), format!("{}CertificateException: No certificate data found)", http3_server_could_not_start(udp_port)));
    assert!(
        refused.to_string().ends_with(&format!(
            "\nCaused by: java.lang.RuntimeException: Exception reading X509 from PEM file {invalid}\nCaused by: java.lang.RuntimeException: Exception creating X509 from PEM\nCaused by: java.security.cert.CertificateException: No certificate data found"
        )),
        "{refused}"
    );

    let empty = mutual_authentication_chain("empty-fixed-cert.pem", Some(""));
    let (refused, udp_port) = refused_fixed_pair(&key, &empty).await;
    let none = format!("The file '{empty}' does not contain any valid PEM-encoded certificates");
    assert_eq!(refused.message(), format!("{}RuntimeException: {none})", http3_server_could_not_start(udp_port)));
    assert!(refused.to_string().ends_with(&format!("\nCaused by: java.lang.RuntimeException: {none}")), "{refused}");
}

/// The chain handed to `QuicSslContextBuilder.forServer` is the file's certificates and the CA after them, which
/// `PKCS12KeyStore.setKeyEntry` checks by name: a leaf the CA did not issue (here a self-signed one) is refused.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_to_start_when_the_fixed_certificate_for_quic_does_not_chain_to_the_ca() {
    let (refused, udp_port) = refused_fixed_pair(&tls_fixture("foreign-leaf-key.pem"), &tls_fixture("foreign-leaf-cert.pem")).await;

    assert_eq!(refused.message(), format!("{}KeyStoreException: Certificate chain is not valid)", http3_server_could_not_start(udp_port)));
    assert!(
        refused.to_string().ends_with(
            "\nCaused by: java.lang.IllegalArgumentException: java.security.KeyStoreException: Certificate chain is not valid\nCaused by: java.security.KeyStoreException: Certificate chain is not valid"
        ),
        "{refused}"
    );
}

/// What the oracle does not check when HTTP/3 starts: the key against the certificate, the validity dates and the CA's
/// signature (the chain check is by name only). A leaf followed by the CA in its file chains as well.
#[tokio::test(flavor = "multi_thread")]
async fn should_start_http3_with_a_fixed_pair_the_key_store_accepts() {
    for (key, cert) in [
        ("fixed-ok-key.pem", "fixed-ok-cert.pem"),
        ("fixed-ok-key.pem", "fixed-ok-chain-cert.pem"),
        ("fixed-rotated-key.pem", "fixed-ok-cert.pem"),
        ("fixed-expired-key.pem", "fixed-expired-cert.pem"),
        ("fixed-ok-key.pem", "fixed-badsig-cert.pem"),
    ] {
        // another socket of the test run can take the port found before the server binds it
        let (running, udp_port) = crate::common::start_with_http3(&[("privateKeyPath", &tls_fixture(key)), ("x509CertificatePath", &tls_fixture(cert))]).await;
        assert_eq!(running.server.http3_port(), Some(udp_port), "{key} / {cert}: HTTP/3 started");
        running.server.shutdown().await;
    }
}

/// `Http3StartFailureTest.shouldRefuseToStartAndStopWhenTheHttp3StartThrowsAnError`: an HTTP/3 start that fails for a
/// reason other than its port stops what was started. Upstream injects a `LinkageError` through a `Configuration`
/// subclass; the failure `Server::start` can reach is the QUIC TLS context's.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::await_holding_lock, reason = "the guard holds off child spawns across the refused start and its checks, on purpose")]
async fn should_refuse_to_start_and_stop_when_the_http3_start_fails_otherwise() {
    let not_a_certificate = mutual_authentication_chain("not-a-certificate-stop.pem", Some("not a certificate"));
    let udp_port = crate::udp_port::free_udp_port().to_string();

    let _no_spawn = crate::udp_port::no_spawn_meanwhile();
    let (refused, tcp_port) = refused_start_on_a_tcp_port(&[("tlsMutualAuthenticationCertificateChain", &not_a_certificate), ("http3Port", &udp_port)]).await;

    assert_eq!(refused.listener, UdpListener::Http3);
    assert!(refused.message().contains("but its server could not start on UDP port"), "{}", refused.message());
    assert_tcp_listener_closed(tcp_port);
}

/// `DnsStartFailureTest.shouldStartWithoutDnsAndLeaveTheDnsPortAloneWhenDnsIsDisabled`.
#[tokio::test(flavor = "multi_thread")]
async fn should_start_without_dns_and_leave_the_dns_port_alone_when_dns_is_disabled() {
    let other_application = held_udp_port();
    let running = crate::common::start(&[("dnsEnabled", "false"), ("dnsPort", &port_of(&other_application).to_string())]).await;

    assert!(running.server.is_running());
    assert_eq!(running.server.dns_port(), None, "no DNS port is bound");
    running.server.shutdown().await;
}

/// `DnsStartFailureTest.privilegedPortNotPermitted`.
fn privileged_port_not_permitted(udp_port: u16) -> String {
    format!(
        "DNS mocking is enabled (dnsEnabled=true, dnsPort={udp_port}) but this process is not permitted to bind UDP port {udp_port}, a port below 1024, so MockServer cannot start: choose a dnsPort of 1024 or above (in Docker, publish it as port {udp_port}, for example -p {udp_port}:5053/udp with dnsPort=5053), run MockServer as root, or lower the sysctl net.ipv4.ip_unprivileged_port_start to {udp_port} (adding the NET_BIND_SERVICE capability to a container does not give it to a non-root user), or set dnsEnabled=false to run without DNS mocking (underlying error: "
    )
}

fn os_error(kind: std::io::ErrorKind) -> std::io::Error {
    std::io::Error::from(kind)
}

/// `DnsStartFailureTest.shouldTellAProcessThatMayNotBindAPortBelow1024HowToGetOne` and `...HowToGetOneOnEpoll`: the DNS
/// listener's bind fails as the oracle's native epoll transport reports it (`NativeIoException`), never as NIO's
/// `BindException`.
#[test]
fn should_tell_a_process_that_may_not_bind_a_port_below_1024_how_to_get_one() {
    let refused = UdpStartFailure::bind(UdpListener::Dns, 53, &os_error(std::io::ErrorKind::PermissionDenied));

    assert_eq!(refused.message(), format!("{}NativeIoException: bind(..) failed with error(-13): Permission denied)", privileged_port_not_permitted(53)));
    assert!(refused.port_unavailable);
}

/// `DnsStartFailureTest.shouldNotBlamePrivilegesForAPortBelow1024ThatIsHeld`.
#[test]
fn should_not_blame_privileges_for_a_port_below_1024_that_is_held() {
    let refused = UdpStartFailure::bind(UdpListener::Dns, 53, &os_error(std::io::ErrorKind::AddrInUse));

    assert_eq!(refused.message(), format!("{}NativeIoException: bind(..) failed with error(-98): Address already in use)", port_could_not_be_opened_or_bound(53)));
}

/// `DnsStartFailureTest.shouldNotBlameThePortNumberForAPermissionDeniedOnAPortFrom1024`.
#[test]
fn should_not_blame_the_port_number_for_a_permission_denied_on_a_port_from_1024() {
    let refused = UdpStartFailure::bind(UdpListener::Dns, 1024, &os_error(std::io::ErrorKind::PermissionDenied));

    assert_eq!(refused.message(), format!("{}NativeIoException: bind(..) failed with error(-13): Permission denied)", port_could_not_be_opened_or_bound(1024)));
}

/// `DnsStartFailureTest.shouldNotBlameThePortNumberWhenNoChosenPortCouldBeBound`: dnsPort 0, every port MockServer chose
/// was refused, so no port below 1024 is to blame.
#[test]
fn should_not_blame_the_port_number_when_no_chosen_port_could_be_bound() {
    let refused = UdpStartFailure::bind(UdpListener::Dns, 53, &os_error(std::io::ErrorKind::PermissionDenied)).no_chosen_port();

    assert_eq!(
        refused.message(),
        "DNS mocking is enabled (dnsEnabled=true, dnsPort=0) but its server could not start on UDP port 0, so MockServer cannot start: fix the underlying error or set dnsEnabled=false to run without DNS mocking (underlying error: NativeIoException: bind(..) failed with error(-13): Permission denied)"
    );
    assert!(!refused.port_unavailable);
}

/// `DnsStartFailureTest.shouldNameAPortWhoseBindFailedWithAnyException`: the epoll transport reports a failed bind with
/// an `IOException` of its own.
#[test]
fn should_name_a_port_whose_bind_failed_with_any_exception() {
    let refused = UdpStartFailure::bind(UdpListener::Dns, 5353, &os_error(std::io::ErrorKind::AddrInUse));

    assert_eq!(refused.message(), format!("{}NativeIoException: bind(..) failed with error(-98): Address already in use)", port_could_not_be_opened_or_bound(5353)));
    assert!(refused.port_unavailable);
    assert!(refused.to_string().ends_with("\nCaused by: shaded_package.io.netty.channel.unix.Errors$NativeIoException: bind(..) failed with error(-98): Address already in use"), "{refused}");
}

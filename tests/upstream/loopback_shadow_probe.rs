//! Ports of `LoopbackShadowProbeTest` (mockserver-netty `lifecycle/`) against
//! [`mock_server::loopback_probe`]. Upstream's run unmodified on rs-process too, but there they test the Java
//! class, not ours. Three of its cases have no counterpart here: ours probes synchronously on the binding thread
//! before the listener's accept loop exists, so there is no Netty event loop to stall or keep busy
//! (`shouldNotReportShadowWhenTheEventLoopStalls…`, `shouldNotLeaveTheProbeHandlerInstalled…`) and no
//! `AUTO_READ`-off channel (`shouldReportShadowWhenTheConnectionIsEstablishedButNeverAccepted…`, whose timing is
//! checked by the shadowed case below); and it dials with a raw socket, which no JVM-wide `ProxySelector` can route
//! (`shouldNotRouteTheProbeThroughAJvmWideProxy`).

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use mock_server::loopback_probe;

/// A listener bound as `server::bind_std_listener` binds a blank `localBoundIP`: `[::]` dual-stack, address reuse
/// on, non-blocking.
fn dual_stack_listener(port: u16) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

fn accepted_within(listener: &TcpListener, timeout: Duration) -> Option<(TcpStream, SocketAddr)> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok(accepted) => return Some(accepted),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => return None,
        }
    }
}

#[test]
fn should_find_no_shadow_for_an_uncontested_wildcard_server_without_disturbing_its_child_pipeline() {
    let server = dual_stack_listener(0).expect("a dual-stack listener");
    let port = server.local_addr().unwrap().port();
    // a client that connected before the check is handed back to be served, not taken for a probe
    let mut early = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    let early_source = early.local_addr().unwrap();
    let mut others = Vec::new();

    assert_eq!(loopback_probe::find_shadowed_loopback(&server, Duration::from_secs(5), &mut others), None);

    // the probe connections are consumed by the check, the other client is not
    assert_eq!(others.iter().map(|(_, remote)| *remote).collect::<Vec<_>>(), vec![early_source]);
    let (mut served, _) = others.pop().unwrap();
    served.set_nonblocking(false).unwrap();
    early.write_all(b"ping").unwrap();
    let mut read = [0u8; 4];
    served.read_exact(&mut read).unwrap();
    assert_eq!(&read, b"ping", "the connection handed back is the client's, still open");
    // nothing of the probe is left behind: the next connection reaches the listener
    let later = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    let (_, remote) = accepted_within(&server, Duration::from_secs(5)).expect("a later connection is accepted");
    assert!(loopback_probe::same_endpoint(remote, later.local_addr().unwrap()));
}

#[test]
fn should_find_shadow_when_another_listener_holds_the_same_port_on_ipv4_loopback() {
    let other = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let held_port = other.local_addr().unwrap().port();
    // Linux refuses the wildcard bind outright, so the shadow cannot arise there
    let Ok(server) = dual_stack_listener(held_port) else { return };
    let mut others = Vec::new();

    let start = Instant::now();
    let shadowed = loopback_probe::find_shadowed_loopback(&server, Duration::from_millis(200), &mut others);

    assert_eq!(shadowed, Some(SocketAddr::from((Ipv4Addr::LOCALHOST, held_port))));
    let elapsed = start.elapsed();
    // the connection was established with the other listener but never accepted by this one
    assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    assert!(others.is_empty());
}

#[test]
fn should_probe_the_loopback_addresses_the_bound_address_covers() {
    let ipv4_loopback = IpAddr::from(Ipv4Addr::LOCALHOST);
    let ipv6_loopback = IpAddr::from(Ipv6Addr::LOCALHOST);
    let targets = |ip: IpAddr| loopback_probe::loopback_targets(SocketAddr::new(ip, 1080));
    assert_eq!(targets(Ipv6Addr::UNSPECIFIED.into()), vec![ipv4_loopback, ipv6_loopback]);
    assert_eq!(targets(Ipv4Addr::UNSPECIFIED.into()), vec![ipv4_loopback]);
    assert_eq!(targets(ipv4_loopback), vec![ipv4_loopback]);
    assert_eq!(targets(ipv6_loopback), vec![ipv6_loopback]);
    assert_eq!(targets(Ipv4Addr::new(192, 0, 2, 10).into()), Vec::<IpAddr>::new());
}

#[test]
fn should_match_the_probe_source_including_ipv4_mapped_ipv6_form() {
    let probe_source = SocketAddr::from((Ipv4Addr::LOCALHOST, 50123));
    let mapped_source = SocketAddr::from((Ipv4Addr::LOCALHOST.to_ipv6_mapped(), 50123));

    assert!(loopback_probe::same_endpoint(probe_source, probe_source));
    assert!(loopback_probe::same_endpoint(mapped_source, probe_source));
    assert!(!loopback_probe::same_endpoint(SocketAddr::from((Ipv4Addr::LOCALHOST, 50124)), probe_source));
    assert!(!loopback_probe::same_endpoint(SocketAddr::from((Ipv6Addr::LOCALHOST, 50123)), probe_source));
}

/// The probes a server's start and `PUT /mockserver/bind` make never reach a
/// connection handler, so neither the event log nor the request metrics see them.
#[tokio::test(flavor = "multi_thread")]
async fn a_probe_never_reaches_the_event_log_or_the_metrics() {
    let running = crate::common::start(&[("metricsEnabled", "true")]).await;
    let bound = crate::common::send(running.port, "PUT", "/mockserver/bind", r#"{"ports":[0]}"#).await;
    assert_eq!(bound.status, 200, "{}", bound.body);

    // the two control-plane requests above are all the server received
    assert_eq!(running.server.metric("REQUESTS_RECEIVED_COUNT"), Some(2));
    let logs = crate::common::logs(running.port).await;
    let received: Vec<&str> = logs.lines().filter(|l| l.contains("received request:")).collect();
    assert!(received.is_empty(), "{logs}");
    running.server.shutdown().await;
}

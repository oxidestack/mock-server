//! `Ipv4UdpPortProbe` (mockserver-netty `lifecycle/`), for the DNS and HTTP/3 listeners. On macOS a dual-stack UDP
//! bind succeeds on a port another socket holds on `0.0.0.0` (or `127.0.0.1`), which then receives the datagrams sent
//! to localhost. The probe runs before the listener binds: on macOS and Linux an IPv4 bind also fails against the same
//! process's own dual-stack socket, so a later probe could not tell the two apart. A socket that takes the port between
//! the probe and the bind is caught after the bind by [`loopback_reaches_another_socket`], which sends a datagram
//! instead. No probe sets `SO_REUSEADDR`.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::config::Config;

/// `DUAL_STACK_BIND_CAN_SHARE_AN_IPV4_PORT`: only macOS lets a dual-stack bind share a port held on IPv4.
const DUAL_STACK_BIND_CAN_SHARE_AN_IPV4_PORT: bool = cfg!(target_os = "macos");
const PROBE_PAYLOAD: &[u8] = b"mockserver udp port probe";
const PROBE_DATAGRAMS: usize = 3;
const PROBE_TIMEOUT: Duration = Duration::from_millis(200);

/// `Configuration.udpPortProbed`: told of each address a DNS or HTTP/3 listener's probe checked, just after the check and before
/// the bind (the `dnsPortShadowedOnIpv4` and `Http3Server.shadowedOnIpv4` seams upstream's `DnsPortTakenAfterProbeTest`
/// and `Http3ServerIpv4PortConflictTest` override).
#[derive(Clone)]
pub struct UdpPortProbed(pub std::sync::Arc<dyn Fn(SocketAddr) + Send + Sync>);

impl std::fmt::Debug for UdpPortProbed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UdpPortProbed")
    }
}

/// `listenerAddress`: `localBoundIP` when it is set, as the TCP listeners bind it, otherwise every address (`None`:
/// the dual-stack wildcard, [`crate::http3::udp_socket`]). A host name that does not resolve fails the bind.
pub fn listener_address(config: &Config, port: u16) -> std::io::Result<Option<SocketAddr>> {
    if config.property("localBoundIP").unwrap_or_default().trim().is_empty() {
        return Ok(None);
    }
    crate::server::bind_address(config, port).map(Some)
}

/// The address a listener of `address` is bound to, as the probe reports it: the wildcard for `None`.
pub fn probed_address(address: Option<SocketAddr>, port: u16) -> SocketAddr {
    address.unwrap_or_else(|| SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)))
}

/// Binds `address` (`None`: the dual-stack wildcard) as a UDP listener does. A wildcard `localBoundIP`, `0.0.0.0` as
/// well as `::`, is the dual-stack wildcard too: the JDK binds IPv4's any-local address as `in6addr_any`.
pub fn bind(address: Option<SocketAddr>, port: u16) -> std::io::Result<UdpSocket> {
    match address {
        Some(address) if !address.ip().is_unspecified() => UdpSocket::bind(address),
        _ => crate::http3::udp_socket(port),
    }
}

/// `MockServer.dnsPortShadowedOnIpv4` and `Http3Server.shadowedOnIpv4`, the seam a test takes the port through after
/// the probe: [`shadowed_on_ipv4`], then `config`'s [`Config::with_udp_port_probed`] hook is told of the address.
pub fn shadowed_on_ipv4_probed(config: &Config, address: Option<SocketAddr>, port: u16) -> bool {
    let shadowed = shadowed_on_ipv4(address, port);
    if let Some(probed) = &config.udp_port_probed {
        (probed.0)(probed_address(address, port));
    }
    shadowed
}

/// `shadowedOnIpv4(listenerAddress)`: only a wildcard bind is checked, since a bind of one address fails against a
/// socket on `0.0.0.0:port`, and a socket on one address is sent every datagram for that address.
pub fn shadowed_on_ipv4(address: Option<SocketAddr>, port: u16) -> bool {
    address.is_none_or(|a| a.ip().is_unspecified()) && held_on_ipv4(port) && dual_stack_bind_succeeds(port)
}

/// `heldOnIpv4`: binding `0.0.0.0:port` fails as a `BindException` does (the port held on IPv4, or not bindable at
/// all, which the server's own bind then reports); false when it was free or IPv4 is unavailable.
pub fn held_on_ipv4(port: u16) -> bool {
    match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)) {
        Ok(_) => false,
        Err(e) => matches!(e.kind(), ErrorKind::AddrInUse | ErrorKind::PermissionDenied | ErrorKind::AddrNotAvailable),
    }
}

/// `dualStackBindSucceeds`: a dual-stack wildcard bind of `port`, as the server makes, succeeds (and is released).
pub fn dual_stack_bind_succeeds(port: u16) -> bool {
    crate::http3::udp_socket(port).is_ok()
}

/// `portFreeOnIpv4`: a port the IPv4 allocator chose, so no socket held it on IPv4 when it was chosen; 0 if IPv4 is
/// unavailable.
pub fn port_free_on_ipv4() -> u16 {
    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).and_then(|s| s.local_addr()).map(|a| a.port()).unwrap_or(0)
}

/// `loopbackReachesAnotherSocket`, the check after the bind for a socket that took the port on `0.0.0.0` between
/// [`shadowed_on_ipv4`] and the bind: a datagram sent to `127.0.0.1` on the bound port must arrive on `bound`. Made
/// only on macOS and for a wildcard bind. Runs before the listener serves, so it reads `bound` itself: datagrams from
/// anyone else that arrive meanwhile are handed back in `others`, for the listener to serve first.
pub fn loopback_reaches_another_socket(bound: &UdpSocket, others: &mut Vec<(Vec<u8>, SocketAddr)>) -> bool {
    if !DUAL_STACK_BIND_CAN_SHARE_AN_IPV4_PORT {
        return false;
    }
    let Ok(local) = bound.local_addr() else { return false };
    if !local.ip().is_unspecified() {
        return false;
    }
    reaches_another_socket(bound, SocketAddr::from((Ipv4Addr::LOCALHOST, local.port())), others).unwrap_or(false)
}

fn reaches_another_socket(bound: &UdpSocket, target: SocketAddr, others: &mut Vec<(Vec<u8>, SocketAddr)>) -> std::io::Result<bool> {
    let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    // connected, so an ICMP port unreachable (nothing listens on the IPv4 loopback) fails the next write
    probe.connect(target)?;
    let source = probe.local_addr()?;
    let restore = bound.read_timeout()?;
    let mut buf = vec![0u8; 2048];
    let mut received = |timeout: Duration| -> std::io::Result<bool> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Ok(false);
            }
            bound.set_read_timeout(Some(left))?;
            match bound.recv_from(&mut buf) {
                Ok((_, peer)) if same_endpoint(peer, source) => return Ok(true),
                Ok((n, peer)) => others.push((buf[..n].to_vec(), peer)),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Ok(false),
                Err(_) => continue,
            }
        }
    };
    let outcome = (|| {
        for _ in 0..PROBE_DATAGRAMS {
            match probe.send(PROBE_PAYLOAD) {
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::ConnectionRefused => return Ok(false),
                Err(e) => return Err(e),
            }
            if received(PROBE_TIMEOUT)? {
                return Ok(false);
            }
        }
        Ok(!received(PROBE_TIMEOUT)?)
    })();
    bound.set_read_timeout(restore)?;
    outcome
}

/// `LoopbackShadowProbe.sameEndpoint`: an IPv4-mapped IPv6 sender is the IPv4 address it maps.
fn same_endpoint(sender: SocketAddr, expected: SocketAddr) -> bool {
    let ip = match sender.ip() {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(sender.ip()),
        ip => ip,
    };
    ip == expected.ip() && sender.port() == expected.port()
}

/// `ipv4WildcardConflict`'s message: `traffic` is what reaches the other socket (`DNS queries`), `port_property` the
/// property that set the port.
pub fn ipv4_wildcard_conflict(port: u16, traffic: &str, port_property: &str) -> String {
    format!(
        "UDP port {port} is already in use by another socket listening on 0.0.0.0:{port}, so {traffic} to localhost:{port} would reach that socket instead of MockServer; stop the application that holds it or choose a different {port_property} (to find it run: lsof -nP -iUDP:{port})"
    )
}

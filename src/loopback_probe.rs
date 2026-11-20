//! `LoopbackShadowProbe` (mockserver-netty `lifecycle/`) and the retry of `LifeCycle.bindPort` around it: a TCP
//! listener just bound must receive the connections made to the loopback address(es) it covers. On macOS a wildcard
//! bind, the dual-stack `[::]` one above all, succeeds on a port another socket already holds on
//! `0.0.0.0` or `127.0.0.1`, and the kernel then hands that socket the connections to `127.0.0.1:port`; the IPv6
//! ephemeral allocator even picks such a port for port 0. Linux refuses those binds, so there the probe always finds
//! its connection at once.
//!
//! Each probe connects from a pre-bound loopback source address and is recognised by it when this listener accepts
//! it, then closed with `SO_LINGER 0`: it never reaches a connection handler, the event log or any metrics. Other
//! connections accepted meanwhile are handed back for the listener to serve first.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(1000);
/// `SHADOW_PROBE_ACCEPT_TIMEOUT_EXPLICIT_MILLIS`, also the ceiling of the ephemeral timeout's doubling.
const ACCEPT_TIMEOUT_EXPLICIT: Duration = Duration::from_millis(5000);
/// `SHADOW_PROBE_ACCEPT_TIMEOUT_EPHEMERAL_INITIAL_MILLIS`, doubled on each further attempt.
const ACCEPT_TIMEOUT_EPHEMERAL_INITIAL: Duration = Duration::from_millis(250);
/// `SHADOW_PROBE_MAX_EPHEMERAL_ATTEMPTS`.
pub const MAX_EPHEMERAL_ATTEMPTS: u32 = 10;
const ACCEPT_POLL: Duration = Duration::from_millis(2);

/// Connections accepted while probing that were not a probe's own.
pub type Accepted = Vec<(TcpStream, SocketAddr)>;

/// How long a probe of attempt `attempt` (from 1) waits for its connection: `5 s` for an explicit port, `250 ms`
/// doubling up to `5 s` for one the operating system chose.
pub fn accept_timeout(operating_system_chooses_port: bool, attempt: u32) -> Duration {
    if operating_system_chooses_port {
        ACCEPT_TIMEOUT_EXPLICIT.min(ACCEPT_TIMEOUT_EPHEMERAL_INITIAL * (1u32 << (attempt - 1).min(16)))
    } else {
        ACCEPT_TIMEOUT_EXPLICIT
    }
}

/// `loopbackTargets`: `127.0.0.1` for a wildcard, and `::1` too for the IPv6 (dual-stack) wildcard; a loopback
/// address itself; nothing for any other address.
pub fn loopback_targets(bound: SocketAddr) -> Vec<IpAddr> {
    match bound.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => vec![Ipv4Addr::LOCALHOST.into()],
        IpAddr::V6(ip) if ip.is_unspecified() => vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()],
        ip if ip.is_loopback() => vec![ip],
        _ => Vec::new(),
    }
}

/// `findShadowedLoopback`: the loopback endpoint whose connections reach another listener than `listener` (a bound,
/// listening, non-blocking socket), or `None` when every covered loopback address reaches it (or the check could not
/// be made). Connections from anyone else that `listener` accepts meanwhile are pushed onto `others`.
pub fn find_shadowed_loopback(listener: &TcpListener, accept_timeout: Duration, others: &mut Accepted) -> Option<SocketAddr> {
    let bound = listener.local_addr().ok()?;
    loopback_targets(bound).into_iter().map(|ip| SocketAddr::new(ip, bound.port())).find(|&target| reaches_another_listener(listener, target, accept_timeout, others))
}

fn reaches_another_listener(listener: &TcpListener, target: SocketAddr, accept_timeout: Duration, others: &mut Accepted) -> bool {
    use socket2::{Domain, Socket, Type};
    let probe = || -> std::io::Result<(Socket, SocketAddr)> {
        let socket = Socket::new(Domain::for_address(target), Type::STREAM, None)?;
        socket.set_linger(Some(Duration::ZERO))?;
        socket.bind(&SocketAddr::new(target.ip(), 0).into())?;
        let source = socket.local_addr()?.as_socket().ok_or_else(|| std::io::Error::other("not an inet address"))?;
        socket.connect_timeout(&target.into(), CONNECT_TIMEOUT)?;
        Ok((socket, source))
    };
    // address family unavailable or nothing listening for it: nothing is being shadowed
    let Ok((_socket, source)) = probe() else { return false };
    let deadline = Instant::now() + accept_timeout;
    loop {
        match listener.accept() {
            Ok((stream, remote)) => {
                let remote = crate::server::canonical(remote);
                if same_endpoint(remote, source) {
                    let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
                    return false;
                }
                others.push((stream, remote));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::Interrupted => {
                if Instant::now() >= deadline {
                    return true;
                }
                std::thread::sleep(ACCEPT_POLL);
            }
            Err(_) => return false,
        }
    }
}

/// `sameEndpoint`: whether a connection accepted from `remote` is the probe's own from `source`, an IPv4 address and
/// its IPv4-mapped IPv6 form (how a dual-stack listener reports an IPv4 peer) being the same.
pub fn same_endpoint(remote: SocketAddr, source: SocketAddr) -> bool {
    crate::server::canonical(remote) == crate::server::canonical(source)
}

/// `portFreeOnIpv4`: unlike the IPv6 wildcard allocator, the IPv4 one does not hand out a port another socket holds
/// on `127.0.0.1`, so it makes a better next candidate after a shadowed ephemeral bind; 0 if none could be had.
pub fn port_free_on_ipv4() -> u16 {
    TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).and_then(|l| l.local_addr()).map(|a| a.port()).unwrap_or(0)
}

/// `loopbackConflict`.
pub fn loopback_conflict(port: u16, shadowed: SocketAddr) -> String {
    let address = match shadowed.ip() {
        IpAddr::V4(ip) => format!("{ip}:{port}"),
        IpAddr::V6(ip) => format!("[{ip}]:{port}"),
    };
    format!("port {port} is already in use by another application listening on {address}, so requests to localhost:{port} would reach that application instead of MockServer")
}

/// `LifeCycle.explicitPortConflict`: an explicitly requested port shadowed on loopback.
pub fn explicit_port_conflict(port: u16, shadowed: SocketAddr) -> BindException {
    BindException(format!("{}; stop that application or choose a different port (to find it run: lsof -nP -iTCP:{port} -sTCP:LISTEN)", loopback_conflict(port, shadowed)))
}

/// `LifeCycle.BindVerifier`: the two steps of `bindPort`'s shadow handling, the seam upstream's
/// `LifeCycleBindRetryTest` drives the retry and failure paths through on every operating system (installed with
/// [`crate::Server::set_bind_verifier`]).
pub trait BindVerifier: Send + Sync {
    /// [`find_shadowed_loopback`] on a listener just bound; an error fails the bind after the listener is closed.
    fn find_shadowed_loopback(&self, listener: &TcpListener, accept_timeout: Duration, others: &mut Accepted) -> std::io::Result<Option<SocketAddr>>;
    /// The port to try after an ephemeral port was given up ([`port_free_on_ipv4`]); 0 lets the system choose.
    fn next_candidate_port(&self) -> u16;
}

/// `LifeCycle.DEFAULT_BIND_VERIFIER`: the real probe and candidates.
pub struct LoopbackShadowProbe;

impl BindVerifier for LoopbackShadowProbe {
    fn find_shadowed_loopback(&self, listener: &TcpListener, accept_timeout: Duration, others: &mut Accepted) -> std::io::Result<Option<SocketAddr>> {
        Ok(find_shadowed_loopback(listener, accept_timeout, others))
    }

    fn next_candidate_port(&self) -> u16 {
        port_free_on_ipv4()
    }
}

/// Where `Config` keeps an installed [`BindVerifier`], shared by its clones; [`LoopbackShadowProbe`] when none is.
#[derive(Clone, Default)]
pub struct BindVerifierSlot(std::sync::Arc<parking_lot::RwLock<Option<std::sync::Arc<dyn BindVerifier>>>>);

impl BindVerifierSlot {
    pub fn set(&self, verifier: Option<std::sync::Arc<dyn BindVerifier>>) {
        *self.0.write() = verifier;
    }

    pub fn get(&self) -> std::sync::Arc<dyn BindVerifier> {
        self.0.read().clone().unwrap_or_else(|| std::sync::Arc::new(LoopbackShadowProbe))
    }
}

impl std::fmt::Debug for BindVerifierSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.read().is_some() { "BindVerifierSlot(installed)" } else { "BindVerifierSlot(default)" })
    }
}

/// A `java.net.BindException` the probe's retry throws, by its message.
#[derive(Debug)]
pub struct BindException(pub String);

impl std::fmt::Display for BindException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BindException {}

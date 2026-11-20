//! A UDP listener the configuration asks for (`dnsEnabled`, `http3Port`) that cannot start refuses the server's start
//! (`MockServer.startDnsServer`, `startHttp3Server`): everything already started is stopped and the start fails with
//! upstream's `DnsStartupException` / `Http3StartupException`, whose one-line message names the port, the fix and the
//! root cause. `Main.logStartupFailure` prints a port that could not be bound with its message alone, any other
//! failure as `exception while starting:{}` with the exception.

use std::io::ErrorKind;

/// Which listener failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpListener {
    Dns,
    Http3,
}

/// `DnsStartupException` or `Http3StartupException`.
#[derive(Debug)]
pub struct UdpStartFailure {
    pub listener: UdpListener,
    /// The configured port, as upstream's `int` holds it (an out-of-range one included).
    pub port: i64,
    /// `isPortUnavailable`: the port could not be opened or bound, which the message alone explains.
    pub port_unavailable: bool,
    /// The root cause's fully qualified class name.
    cause_class: String,
    /// The root cause's message.
    cause_message: String,
    /// The causes between the exception and its root cause, outermost first, as `Throwable.toString` prints them.
    outer_causes: Vec<String>,
}

impl UdpStartFailure {
    /// `InetSocketAddress.checkPort`: a port above 65535 (the cause of `DnsStartupException.serverCouldNotStart` and of
    /// an `Http3StartupException` that is not about a refused bind).
    pub fn out_of_range(listener: UdpListener, port: i64) -> UdpStartFailure {
        UdpStartFailure { listener, port, port_unavailable: false, cause_class: "java.lang.IllegalArgumentException".into(), cause_message: format!("port out of range:{port}"), outer_causes: Vec::new() }
    }

    /// The bind of `port` failed with `error`. The DNS listener binds with Netty's native epoll transport in the oracle's
    /// image, whose failure is a `NativeIoException` with Linux's negated errno, and any failure of its bind counts as the
    /// port being unavailable (`portCouldNotBeOpenedOrBound`); HTTP/3 binds with the NIO transport, whose refused bind is a
    /// `java.net.BindException`, the only cause it takes for an unavailable port.
    pub fn bind(listener: UdpListener, port: i64, error: &std::io::Error) -> UdpStartFailure {
        let (errno, reason) = match error.kind() {
            ErrorKind::AddrInUse => (98, "Address already in use".to_string()),
            ErrorKind::PermissionDenied => (13, "Permission denied".to_string()),
            ErrorKind::AddrNotAvailable => (99, "Cannot assign requested address".to_string()),
            _ => (error.raw_os_error().unwrap_or(0), error.to_string().split(" (os error").next().unwrap_or_default().to_string()),
        };
        match listener {
            UdpListener::Dns => UdpStartFailure {
                listener,
                port,
                port_unavailable: true,
                cause_class: "shaded_package.io.netty.channel.unix.Errors$NativeIoException".into(),
                cause_message: format!("bind(..) failed with error(-{errno}): {reason}"),
                outer_causes: Vec::new(),
            },
            UdpListener::Http3 => {
                let refused = matches!(error.kind(), ErrorKind::AddrInUse | ErrorKind::PermissionDenied | ErrorKind::AddrNotAvailable);
                let class = if refused { "java.net.BindException" } else { "java.io.IOException" };
                UdpStartFailure { listener, port, port_unavailable: refused, cause_class: class.into(), cause_message: reason, outer_causes: Vec::new() }
            }
        }
    }

    /// `Ipv4UdpPortProbe.ipv4WildcardConflict`: another socket holds `port` on the IPv4 wildcard and would get the
    /// listener's localhost traffic (a `java.net.BindException`, so the port counts as unavailable).
    pub fn ipv4_wildcard_conflict(listener: UdpListener, port: u16) -> UdpStartFailure {
        let (traffic, property) = match listener {
            UdpListener::Dns => ("DNS queries", "dnsPort"),
            UdpListener::Http3 => ("HTTP/3 requests", "http3Port"),
        };
        let cause_message = crate::udp_probe::ipv4_wildcard_conflict(port, traffic, property);
        UdpStartFailure { listener, port: i64::from(port), port_unavailable: true, cause_class: "java.net.BindException".into(), cause_message, outer_causes: Vec::new() }
    }

    /// `DnsStartupException.serverCouldNotStart(0, lastFailure)`: no port the server chose could be bound, so the
    /// failure names port 0 and is not about one unavailable port; the last candidate's cause is kept.
    pub fn no_chosen_port(mut self) -> UdpStartFailure {
        self.port = 0;
        self.port_unavailable = false;
        self
    }

    /// Any other failure (`serverCouldNotStart`, an `Http3StartupException` with another cause).
    pub fn other(listener: UdpListener, port: i64, message: impl Into<String>) -> UdpStartFailure {
        UdpStartFailure { listener, port, port_unavailable: false, cause_class: "java.lang.IllegalStateException".into(), cause_message: message.into(), outer_causes: Vec::new() }
    }

    /// A failure whose exception chain is `causes`, outermost first, each as `Throwable.toString` prints it
    /// (`Http3Server.buildQuicSslContext` reading `tlsMutualAuthenticationCertificateChain`); the last is the root cause.
    pub fn caused_by(listener: UdpListener, port: i64, causes: &[String]) -> UdpStartFailure {
        let (root, outer) = causes.split_last().map_or(("java.lang.IllegalStateException", &[][..]), |(root, outer)| (root.as_str(), outer));
        let (cause_class, cause_message) = root.split_once(": ").unwrap_or((root, ""));
        UdpStartFailure { listener, port, port_unavailable: false, cause_class: cause_class.into(), cause_message: cause_message.into(), outer_causes: outer.to_vec() }
    }

    fn exception_class(&self) -> &'static str {
        match self.listener {
            UdpListener::Dns => "org.mockserver.netty.dns.DnsStartupException",
            UdpListener::Http3 => "org.mockserver.netty.http3.Http3StartupException",
        }
    }

    /// `underlyingError`: the root cause's simple class name and the first line of its message.
    fn underlying_error(&self) -> String {
        let simple = self.cause_class.rsplit(['.', '$']).next().unwrap_or(&self.cause_class);
        let message = self.cause_message.trim();
        if message.is_empty() { simple.to_string() } else { format!("{simple}: {}", message.lines().next().unwrap_or_default()) }
    }

    /// The exception's message (`DnsStartupException.message`, `Http3StartupException.message`).
    pub fn message(&self) -> String {
        let (port, cause) = (self.port, self.underlying_error());
        match self.listener {
            UdpListener::Dns => {
                let start = format!("DNS mocking is enabled (dnsEnabled=true, dnsPort={port}) but ");
                let end = format!(" set dnsEnabled=false to run without DNS mocking (underlying error: {cause})");
                if self.port_unavailable && port < 1024 && self.cause_message.to_lowercase().contains("permission denied") {
                    format!(
                        "{start}this process is not permitted to bind UDP port {port}, a port below 1024, so MockServer cannot start: choose a dnsPort of 1024 or above (in Docker, publish it as port {port}, for example -p {port}:5053/udp with dnsPort=5053), run MockServer as root, or lower the sysctl net.ipv4.ip_unprivileged_port_start to {port} (adding the NET_BIND_SERVICE capability to a container does not give it to a non-root user), or{end}"
                    )
                } else if self.port_unavailable {
                    format!("{start}UDP port {port} could not be opened or bound, so MockServer cannot start: free the port if another application holds it, choose a different dnsPort (0 picks a free port, and a port below 1024 can need extra privileges), or{end}")
                } else {
                    format!("{start}its server could not start on UDP port {port}, so MockServer cannot start: fix the underlying error or{end}")
                }
            }
            UdpListener::Http3 => {
                let start = format!("HTTP/3 is enabled (http3Port={port}) but ");
                let end = format!(" or remove http3Port to run without HTTP/3 (underlying error: {cause})");
                if self.port_unavailable {
                    format!("{start}UDP port {port} could not be bound, so MockServer cannot start: free the port if another application holds it, choose a different http3Port,{end}")
                } else {
                    format!("{start}its server could not start on UDP port {port}, so MockServer cannot start: fix the underlying error{end}")
                }
            }
        }
    }

    /// `Main.logStartupFailure`'s message format for a failure its message explains (`HTTP/3 start-up failed:{}`,
    /// `DNS start-up failed:{}`), `None` for one it logs as `exception while starting:{}` with the exception.
    pub fn explained_format(&self) -> Option<&'static str> {
        match (self.port_unavailable, self.listener) {
            (false, _) => None,
            (true, UdpListener::Dns) => Some("DNS start-up failed:{}"),
            (true, UdpListener::Http3) => Some("HTTP/3 start-up failed:{}"),
        }
    }
}

/// The exception as the console prints it, without the JVM's stack frames.
impl std::fmt::Display for UdpStartFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.exception_class(), self.message())?;
        for cause in &self.outer_causes {
            write!(f, "\nCaused by: {cause}")?;
        }
        write!(f, "\nCaused by: {}: {}", self.cause_class, self.cause_message)
    }
}

impl std::error::Error for UdpStartFailure {}


//! A fixed UDP port (`http3Port`, a replayed scenario's `dnsPort`) for an in-process server. `http3Port`
//! cannot be 0 (0 means no HTTP/3, as upstream, and `alt-svc` echoes the configured port), so a test probes a free
//! port, releases it and hands the number to the server; another process (another worktree's `cargo test`) can take
//! it in between. The server's start then fails, as upstream's does (`Server::start` returns a
//! [`mock_server::UdpStartFailure`] for the port it could not bind, see [`taken_meanwhile`]). Every caller therefore
//! starts again with a fresh port, up to [`START_ATTEMPTS`] times, but only while this process holds no socket on the
//! port ([`retry_taken_meanwhile`]): a probe or listener of this process that left its socket open would
//! otherwise be retried away. Included with `#[path]` by the test binaries that start servers in-process.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// How many times a server is started with a freshly probed UDP port before its failed start is left to fail the
/// test.
pub const START_ATTEMPTS: usize = 10;

/// A UDP port free right now on the wildcard addresses the server binds: `[::]` dual-stack (else `0.0.0.0`), which
/// is how both `http3Port` and `dnsPort` bind (`http3::udp_socket`). Released before it returns: see the module
/// comment for the retry every caller owes. A port this process already holds on another socket is passed over (on
/// macOS a dual-stack `[::]:0` bind can be handed a port held on `0.0.0.0`), so a socket of this process found on the
/// port later was opened after the probe.
pub fn free_udp_port() -> u16 {
    loop {
        let probe = std::net::UdpSocket::bind("[::]:0").or_else(|_| std::net::UdpSocket::bind("0.0.0.0:0")).expect("a free UDP port");
        let port = probe.local_addr().expect("a free UDP port").port();
        let probe_fd = std::os::fd::AsRawFd::as_raw_fd(&probe);
        if own_udp_sockets(port).map_or(true, |own| own.iter().all(|(fd, _)| *fd == probe_fd)) {
            return port;
        }
    }
}

/// Whether `Server::start` failed because a UDP listener's port could not be bound: the race the module comment
/// describes, which a fresh port cures when another process caused it ([`retry_taken_meanwhile`]).
pub fn taken_meanwhile(error: &std::io::Error) -> bool {
    error.get_ref().and_then(|e| e.downcast_ref::<mock_server::UdpStartFailure>()).is_some_and(|f| f.port_unavailable)
}

/// Whether `Server::start`'s `error` (attempt `attempt`) is tried again with a fresh port: only when it
/// is [`taken_meanwhile`] and [`retry_taken_port`] finds no socket of this process on the refused port. A taken port
/// held by this process, or one still taken on the last attempt, fails the test there, naming its holders; any other
/// error is `false`, for the caller to fail with.
pub fn retry_taken_meanwhile(error: &std::io::Error, attempt: usize) -> bool {
    let Some(refused) = error.get_ref().and_then(|e| e.downcast_ref::<mock_server::UdpStartFailure>()).filter(|f| f.port_unavailable) else {
        return false;
    };
    let port = u16::try_from(refused.port).unwrap_or_else(|_| panic!("a taken port out of range: {refused}"));
    retry_taken_port(port, &[], attempt, &format!("start attempt {attempt} refused: {}", refused.message()))
}

/// Whether a check that found UDP `port` taken (`what`) is tried again with a fresh port: only when
/// this process holds no socket on it right after, besides the descriptors `besides` (a socket the test holds there
/// itself), and `attempt` is not the last. Otherwise it panics with `what` and the holders: a socket of this process
/// there is one a probe or listener left open (or, rarely, another test's of this binary, which fails safe).
pub fn retry_taken_port(port: u16, besides: &[RawFd], attempt: usize, what: &str) -> bool {
    let holders = UdpHolders::of(port);
    if holders.none_of_this_process_besides(besides) && attempt < START_ATTEMPTS {
        eprintln!("{what}: {holders}, so a new port is tried");
        return true;
    }
    panic!("{what}: {holders}");
}

/// A process's UDP socket on a port: `pid` is `None` for a socket no process visible to this one holds (Linux).
#[derive(Debug)]
pub struct UdpHolder {
    pub pid: Option<u32>,
    pub command: String,
    pub socket: String,
}

/// A child process this one spawns holds a copy of each of its descriptors until it runs its program, a
/// TCP listener a refused server has just closed included, so a connection to that port is still accepted meanwhile.
/// The spawns of the tests that check holders ([`UdpHolders::of`]'s `lsof`) take this lock shared, for the spawn alone;
/// a check that a closed listener refuses connections takes it exclusively ([`no_spawn_meanwhile`]).
static SPAWNS: RwLock<()> = RwLock::new(());

/// Held while this process spawns a child (see [`SPAWNS`]).
pub fn spawning() -> RwLockReadGuard<'static, ()> {
    SPAWNS.read().unwrap_or_else(PoisonError::into_inner)
}

/// Held from a server's refused start until the check that its closed listener refuses connections (see [`SPAWNS`]).
pub fn no_spawn_meanwhile() -> RwLockWriteGuard<'static, ()> {
    SPAWNS.write().unwrap_or_else(PoisonError::into_inner)
}

/// Who holds a UDP port that a check found taken: a post-release check (a rebind, or a start on
/// the released port), or a start on a probed port ([`retry_taken_meanwhile`]). A released port is free for every process, and on macOS a dual-stack `[::]:0` bind of any process can be
/// handed a port another socket holds on `0.0.0.0`, so the failed check alone cannot tell another process's socket from
/// one the server or a probe left behind. This process's own descriptors can, read at once: a socket left behind is
/// one of them (the server runs in this process, and closing a UDP socket's last descriptor frees its port). The
/// system's socket table (`lsof` on macOS, `/proc` on Linux) is read after, to name the holders; a holder that lives
/// for less than that read takes (under a second) is gone from it by then.
#[derive(Debug)]
pub struct UdpHolders {
    pub port: u16,
    /// This process's UDP sockets on the port (descriptor and address), or why its descriptors could not be read.
    pub own: Result<Vec<(RawFd, SocketAddr)>, String>,
    /// Every process's holders, as the system lists them, or why they could not be listed.
    pub listed: Result<Vec<UdpHolder>, String>,
}

impl UdpHolders {
    pub fn of(port: u16) -> Self {
        let own = own_udp_sockets(port);
        UdpHolders { port, own, listed: udp_holders(port) }
    }

    /// Whether this process held no socket on the port: then the failed check was another process's doing.
    pub fn none_of_this_process(&self) -> bool {
        self.none_of_this_process_besides(&[])
    }

    /// Whether this process held no socket on the port but the descriptors `besides` (a socket the caller holds there
    /// itself); descriptors that could not be read prove nothing, so that is `false` too.
    pub fn none_of_this_process_besides(&self, besides: &[RawFd]) -> bool {
        self.own.as_ref().is_ok_and(|own| own.iter().all(|(fd, _)| besides.contains(fd)))
    }
}

impl std::fmt::Display for UdpHolders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (port, pid) = (self.port, std::process::id());
        match &self.own {
            Err(why) => write!(f, "the sockets of this test process (pid {pid}) could not be read ({why}); ")?,
            Ok(own) if own.is_empty() => write!(f, "this test process (pid {pid}) holds no socket on UDP port {port}; ")?,
            Ok(own) => {
                let own: Vec<String> = own.iter().map(|(fd, address)| format!("fd {fd} on {address}")).collect();
                write!(f, "UDP port {port} is held by this test process (pid {pid}): {}; ", own.join(", "))?;
            }
        }
        let holders = match &self.listed {
            Err(why) => return write!(f, "the system's holders could not be listed ({why})"),
            Ok(holders) if holders.is_empty() => return write!(f, "the system lists no holder any more"),
            Ok(holders) => holders,
        };
        write!(f, "the system lists")?;
        for (i, holder) in holders.iter().enumerate() {
            let separator = if i == 0 { " " } else { "; " };
            match holder.pid {
                Some(pid) if pid == std::process::id() => write!(f, "{separator}this test process ({}): {}", holder.command, holder.socket)?,
                Some(pid) => write!(f, "{separator}another process (pid {pid}, {}): {}", holder.command, holder.socket)?,
                None => write!(f, "{separator}a process this one cannot see: {}", holder.socket)?,
            }
        }
        Ok(())
    }
}

/// This process's UDP sockets bound to `port`: each open descriptor (`/dev/fd` on macOS, `/proc/self/fd` on Linux) that
/// is a datagram socket, by its local address.
pub fn own_udp_sockets(port: u16) -> Result<Vec<(RawFd, SocketAddr)>, String> {
    let directory = if cfg!(target_os = "linux") { "/proc/self/fd" } else { "/dev/fd" };
    let entries = std::fs::read_dir(directory).map_err(|e| format!("{directory}: {e}"))?;
    let fds: Vec<RawFd> = entries.filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok()).collect();
    Ok(fds
        .into_iter()
        .filter_map(|fd| {
            // SAFETY: the descriptor is only asked for its type and address. One another thread closes meanwhile
            // answers with an error, and one reused since answers for what it is now.
            let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
            let socket = socket2::SockRef::from(&borrowed);
            if socket.r#type().ok()? != socket2::Type::DGRAM {
                return None;
            }
            let address = socket.local_addr().ok()?.as_socket()?;
            (address.port() == port).then_some((fd, address))
        })
        .collect())
}

/// The UDP sockets on `port`, every process's, as `lsof -nP -iUDP:<port>` lists them (the command the server's own
/// conflict message names). `lsof` lists the processes of this user, this test process among them.
#[cfg(not(target_os = "linux"))]
fn udp_holders(port: u16) -> Result<Vec<UdpHolder>, String> {
    let lsof = {
        let _spawning = spawning();
        let mut command = std::process::Command::new("lsof");
        command.args(["-nP", &format!("-iUDP:{port}"), "-Fpcfn"]).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        command.spawn().map_err(|e| format!("lsof: {e}"))?
    };
    let out = lsof.wait_with_output().map_err(|e| format!("lsof: {e}"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    // `lsof` exits with 1, silently, when nothing matches
    if !out.status.success() && !(out.status.code() == Some(1) && out.stdout.is_empty() && stderr.trim().is_empty()) {
        return Err(format!("lsof: {} {}", out.status, stderr.trim()));
    }
    let (mut holders, mut pid, mut command) = (Vec::new(), None, String::new());
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let (tag, value) = line.split_at(line.len().min(1));
        match tag {
            "p" => pid = Some(value.parse().map_err(|_| format!("lsof: not a pid: {line}"))?),
            "c" => command = value.to_owned(),
            "f" => holders.push(UdpHolder { pid, command: command.clone(), socket: format!("fd {value}") }),
            "n" => {
                if let Some(last) = holders.last_mut() {
                    last.socket.push_str(&format!(" UDP {value}"));
                }
            }
            _ => {}
        }
    }
    Ok(holders)
}

/// The UDP sockets on `port` in this network namespace (`/proc/net/udp`, `/proc/net/udp6`), each attributed to the
/// visible process whose descriptor names its inode; this process's own descriptors are always visible.
#[cfg(target_os = "linux")]
fn udp_holders(port: u16) -> Result<Vec<UdpHolder>, String> {
    let mut inodes = Vec::new();
    for table in ["/proc/net/udp", "/proc/net/udp6"] {
        let text = match std::fs::read_to_string(table) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("{table}: {e}")),
        };
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let local_port = fields.get(1).and_then(|address| address.rsplit(':').next()).and_then(|p| u16::from_str_radix(p, 16).ok());
            if let (Some(p), Some(inode)) = (local_port, fields.get(9))
                && p == port
                && *inode != "0"
            {
                inodes.push((format!("socket:[{inode}]"), fields[1].to_owned()));
            }
        }
    }
    let mut holders = Vec::new();
    let processes = std::fs::read_dir("/proc").map_err(|e| format!("/proc: {e}"))?;
    let pids = processes.filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok());
    for pid in pids {
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
        for fd in fds.filter_map(Result::ok) {
            let Ok(link) = std::fs::read_link(fd.path()) else { continue };
            if let Some(i) = inodes.iter().position(|(socket, _)| std::path::Path::new(socket) == link) {
                let (socket, address) = inodes.remove(i);
                let command = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default().trim().to_owned();
                holders.push(UdpHolder { pid: Some(pid), command, socket: format!("fd {} {socket} on {address}", fd.file_name().to_string_lossy()) });
            }
        }
    }
    holders.extend(inodes.into_iter().map(|(socket, address)| UdpHolder { pid: None, command: String::new(), socket: format!("{socket} on {address}") }));
    Ok(holders)
}

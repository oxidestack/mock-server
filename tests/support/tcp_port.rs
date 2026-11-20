//! TCP ports for in-process tests, the TCP side of `udp_port.rs`. Included with `#[path]` by
//! the test binaries.
//!
//! - [`free_tcp_port`]: a port a test hands to a server it cannot give `0` (a `{{bindport:N}}` of `PUT
//!   /mockserver/bind`, the binary's `-serverPort` of a `pickPort` process scenario, a Docker-published broker port).
//!   It is probed and released, so another process (another worktree's `cargo test`, or one of this process's own
//!   `bind(0)`s) can take it before the server binds it. Every caller therefore tries again with a fresh port while
//!   the bind fails as "already in use", up to [`START_ATTEMPTS`] times.
//! - [`dead_port`]: a port that refuses every connection, for a test that needs a dead target. A bound-then-released
//!   ephemeral port is not one: the OS hands it out again (see the function).

#![allow(dead_code)]

/// How many times a test binds again with a freshly probed TCP port before a lost port is left to fail the test.
pub const START_ATTEMPTS: usize = 10;

/// A TCP port free right now on `0.0.0.0`, the address mock-server listens on (`server::bind`, `Server::start`).
/// Released before it returns: see the module comment for the retry every caller owes.
pub fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("0.0.0.0:0").and_then(|l| l.local_addr()).expect("a free TCP port").port()
}

/// `{{deadhost}}`'s port — a real address that must refuse every connection, with no coordination
/// needed between whatever worktrees happen to be running at once. Two earlier designs both turned out to pick a
/// port something could actually bind:
/// - A fixed literal (`localhost:18999`) is not safe with several worktrees running: any of them can land a real
///   listener on that exact port (an ephemeral test server, or — this sandbox lets an unprivileged process bind
///   privileged ports too — a harvested upstream test that deliberately binds `1`).
/// - Binding an OS-assigned ephemeral port then closing it (freeing the number, keeping only the value) looked
///   safe in isolation, but this *same test run* starts many replay servers, each on its own `bind(0)`; measured
///   on the main tree, the OS handed the just-freed number straight back to one of them within the same run,
///   turning the "dead" host into a live server.
///
/// Both failures share a cause: the ephemeral range (macOS: 49152-65535) is exactly where the OS's own anonymous
/// allocator, and every `bind(0)` our own replay servers make, draw from. The fix is to pick a number *outside*
/// that range — `ORACLE_PORT + 10000` (so `18080` → `28080`, `18117` → `28117`). `ORACLE_PORT` is the same env var
/// `make oracle`/`make record` already read (every worktree gets its own, by
/// convention, no extra coordination) — GNU Make auto-exports a variable set on its own command line
/// (`make record ORACLE_PORT=18117 …`) into the recipe's environment, so `cargo test`/`make record` run that way
/// already see it; default `18080` matches the Makefile's own default for a plain `cargo test`. Nothing — not the
/// OS, not our own servers, not another worktree with its own distinct `ORACLE_PORT` — will ever be handed this
/// number to bind.
///
/// A number outside the ephemeral range can still belong to an unrelated listener (another project's
/// container published on `28080`, so `{{deadhost}}` answered and four cases saw an SSL error instead of the
/// refusal). The derived number is therefore probed once per process, on IPv4 and IPv6 loopback (`localhost` may
/// resolve to either), and while something accepts there the next number is tried (`ORACLE_PORT + 10001`, …, staying
/// below the ephemeral range). Nothing needs coordinating: the first refusing number is the answer, and a probe
/// that fails for any reason other than a refusal counts as occupied.
pub fn dead_port() -> u16 {
    static PORT: std::sync::LazyLock<u16> = std::sync::LazyLock::new(|| {
        let base = std::env::var("ORACLE_PORT").ok().and_then(|p| p.parse::<u16>().ok()).unwrap_or(18080) + 10000;
        pick_refusing_port(base, 100, port_refuses)
    });
    *PORT
}

/// The first port from `base` (at most `tries` of them, never into the ephemeral range) for which `refuses` holds.
pub fn pick_refusing_port(base: u16, tries: u16, refuses: impl Fn(u16) -> bool) -> u16 {
    for port in base..base.saturating_add(tries).min(49152) {
        if refuses(port) {
            return port;
        }
        eprintln!("note: {{{{deadhost}}}} candidate port {port} is occupied by a foreign listener; trying the next one");
    }
    panic!("no refusing port for {{{{deadhost}}}} in {base}..{}: a foreign listener holds them all", base.saturating_add(tries));
}

/// Whether a direct connection to loopback `port` is refused on both address families.
pub fn port_refuses(port: u16) -> bool {
    ["127.0.0.1", "::1"].iter().all(|ip| {
        let addr = std::net::SocketAddr::new(ip.parse().unwrap(), port);
        match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2)) {
            // EADDRNOTAVAIL (49 on macOS, 99 on Linux): no IPv6 loopback on this host, nothing to refuse.
            Err(e) => e.kind() == std::io::ErrorKind::ConnectionRefused || matches!(e.raw_os_error(), Some(49 | 99)),
            Ok(_) => false,
        }
    })
}

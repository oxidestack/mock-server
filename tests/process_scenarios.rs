//! Process-level scenarios: a seam for behaviour visible only in how a process is *launched* —
//! argv parsing, env/property-file handling, startup log lines, exit codes — which `tests/oracle.rs` cannot
//! express (it drives an already-running server over HTTP; see that file's own header for the five HTTP-scenario
//! seams this one sits alongside).
//!
//! Each `tests/process_scenarios/<name>.json` describes one process to launch and what to expect from it:
//!
//! ```json
//! {
//!   "target": "oracleDocker" | "binary",
//!   "args": ["-serverPort"],
//!   "env": {"MOCKSERVER_FOO": "bar"},
//!   "propertyFile": "mockserver.foo=bar\n",
//!   "readiness": {"logContains": "started on port"},
//!   "timeoutSecs": 20,
//!   "expect": {
//!     "running": true,
//!     "exitCode": 2,
//!     "stdoutContains": ["..."],
//!     "stdoutNotContains": ["..."],
//!     "stderrContains": ["..."],
//!     "stderrNotContains": ["..."],
//!     "caCertificateInCwd": true
//!   }
//! }
//! ```
//!
//! `expect.caCertificateInCwd` (a `"binary"`-target scenario only) asserts that
//! `mockserver-ca.pem` exists in the child's scratch cwd once the scenario's assertions are otherwise taken —
//! opt-in proof that a scenario which enables `proxySetupLogging` actually exercises the CA write, alongside the
//! harness's own unconditional guard that no `mockserver-ca*` in the repository root is added or changed (a stray one is tolerated).
//!
//! `"target": "both"` is one scenario for the oracle and our binary: replay runs the binary only;
//! `MOCK_SERVER_PROCESS_ORACLE=1` also runs the oracle against the same expectations; `MOCK_SERVER_PROCESS_RECORD=1`
//! with `MOCK_SERVER_SCENARIO=<name>` runs the oracle alone and writes the golden `<name>.stdout` / `<name>.stderr`
//! under `tests/process_scenarios/golden/` that `"compareOutput": true` in `expect` compares exactly (after masking
//! timestamps, UUIDs and the scenario's own `"mask"` regexes). The oracle's exit code is printed while recording; the
//! scenario's `exitCode` must equal it.
//!
//! `"containerMemoryBytes": n`: the oracle container runs with `--memory n` and our binary is pinned to `n` as
//! its container memory, for a heap ceiling the JVM sizes from the memory (`-XX:MaxRAMPercentage`, the non-server-class
//! ergonomics); without it the heap-derived defaults follow the recording machine's memory.
//!
//! `expect.stdoutInOrder` lists strings that must appear in stdout in that order.
//!
//! The `stdout*` and `stderr*` string assertions (`stdoutContains`, `stdoutNotContains`, `stdoutInOrder`,
//! `stdoutOccurrences`, `stderrContains`, `stderrNotContains`) read
//! a format-neutral view of the stream, the same for the oracle and our binary ([`console_view`]): a log line
//! reads `[WARN] <message>`, with no timestamp, version, target or port, and every line has one trailing space less. Our console
//! is Rust-native (`src/log.rs`); the view keeps what the oracle and we must share, the events and their levels.
//!
//! What the config and TLS scenarios need:
//! - `{{serverPort}}` / `{{serverPort2}}` in `args`, `env` and `propertyFile`: 1080 / 1081 for the oracle container (the
//!   one port Docker publishes), 0 / 0 (any free port) for our binary. `{{scratch}}` is the run's own directory under
//!   `target/scratch/process-fixtures/`, made writable for the container and mounted at the same path.
//! - `"files": {"relative/path": "content"}` are written into the scratch directory before the start (a
//!   `{"from": "path under tests/files"}` value copies that fixture, for one the server rewrites);
//!   `{{scratch}}` is also substituted in the `expect` string lists;
//!   `"certificates": [{"name", "notBeforeSecs", "notAfterSecs", "late"}]` generates a self-signed ECDSA certificate for
//!   `localhost` as `<scratch>/<name>-key.pem` and `-cert.pem` (a `late` one only when an `afterReady` step asks).
//! - `"afterReady": [steps]` run once the readiness condition holds: `{"tls": N, "label", "sni", "warmup"}` makes N HTTPS
//!   `PUT /mockserver/status` requests (any server certificate accepted; a `warmup` one is not recorded, because the first
//!   handshake of a fresh oracle is sometimes closed whatever the configuration), `{"http": {"method", "path", "body",
//!   "expectStatus"}}` one plain-HTTP request, `{"sleepMillis": n}`, `{"certificate": {..}}` a certificate written now,
//!   `{"tcp": base64}` raw bytes on a connection of their own (a binary request), `{"exitWithinMillis": n}`
//!   waits up to n ms for the process to end on its own, `{"awaitAnswerMillis": n}` repeats `PUT
//!   /mockserver/status` on the server's own port until it gets an HTTP answer, for up to n ms (a server
//!   that prints nothing once it listens).
//! - `{"http": {..., "background": label}}` sends the request on a thread of its own and goes on; `expect.background`
//!   `{label: {"answered": bool}}` then checks whether any answer came back before the connection closed.
//! - `{"http": {..., "ownHost": true}}` addresses the request to the port the server listens on itself (1080 inside the oracle
//!   container, whose published port is ephemeral), so that an unmatched request is answered 404 instead of being proxied.
//!   `{{ownPort}}` in an http step's body is that same port (1080 for the oracle, the binary's own port otherwise),
//!   for a forward the server sends to itself. `"expectBodyContains"` checks the answer's text, `"compareBody": label` compares its body with the
//!   oracle's golden `golden/<name>.<label>.body`, written by recording like `compareOutput`'s ([`compare_body`];
//!   the scenario's `"bodyMask"` `[{"regex", "replace"}]` masks what the oracle image sets itself). `"readTimeoutMillis"` (default 20000) bounds the wait for an
//!   answer, for a request the server never answers. `"clientCertificate": {"cert", "key"}` (PEM files under `tests/files`)
//!   sends the request over TLS presenting that certificate, any server certificate accepted.
//! - `expect.tls` `{label: "served" | "refused"}`, `expect.sameCertificate` / `differentCertificate` `[[labelA, labelB]]`
//!   (the last leaf certificate each label saw), `expect.fileModes` `{path: "rw-------"}`, `expect.fileContent`
//!   `{path: text}` and `expect.stdoutOccurrences` `{text: n}` (an exact count). `expect.fileLines` `{path: [regex]}`
//!   matches a file line by line, with a `*` in the file name and per-target lists (see `run_target`);
//!   `expect.absentFiles` `[path]` asserts that no file matches such a path.
//! - A `propertyFile` is written under `target/scratch/process-properties/`, not the system temp directory: the Docker VM shares
//!   only `$HOME` with its VM, so a file in `/var/folders` reached the oracle container as an empty directory.
//!
//! `"oracleImage": "http3"` runs the oracle's HTTP/3 image (`ORACLE_HTTP3_IMAGE`) instead of the default one,
//! which has no QUIC native.
//!
//! `readiness.settleMillis` sleeps that long after the readiness condition, before the output is taken.
//!
//! `"pickPort": true` replaces the binary's `{{serverPort}}` 0 by a free port the runner picks, which its
//! `http` steps then use: for a server that logs no `started on port` line (`disableLogging`, `disableSystemOut`).
//! The port is probed and released, so another process can take it first; a binary that then exits on "Exception
//! while binding MockServer to port" is launched again with a fresh one ([`lost_picked_port`]).
//!
//! `"target": "oracleDocker"` launches the oracle image pinned in `oracle.env` in Docker (`docker run -d --name
//! <unique>`, an ephemeral host port, `tests/files` mounted read-only like `make oracle`), `args` as the
//! container's command, `env` as `-e` flags, `propertyFile` (if given) mounted read-only at
//! `/config/mockserver.properties`, upstream's own default location. `"target": "binary"` spawns our own built
//! binary (`env!("CARGO_BIN_EXE_mock-server")`) with `args` and `env` directly, and its own working directory
//! set to a fresh `target/scratch/process-scenarios/<uuid>/`: the binary writes
//! `mockserver-ca.pem` relative to its cwd whenever `proxySetupLogging` is in effect (as upstream does, into
//! *its* cwd — confirmed live: a bare `mockserver/mockserver:8.0.0` container logs `CA certificate:
//! <home>/mockserver-ca.pem` on every default start), and without this a spawned-in-place binary would
//! write it into the repository root, since `cargo test` sets the test binary's own cwd to the package root.
//! `propertyFile` (if given) is written to a temp file and appended as `-Dmockserver.propertyFile=<path>` (the
//! flag `Config::from_args` already reads, `src/config.rs`).
//!
//! `{{files}}` in `args`, `env` values and `propertyFile` is the absolute path of `tests/files`; the
//! `oracleDocker` target mounts it at that same path, so one scenario file serves both targets.
//!
//! `"readiness"` decides how long the runner waits before asserting: `{"logContains": s}` polls combined
//! stdout+stderr until `s` appears — use this when `expect.running` is `true`, the process is meant to keep
//! running past that point. `{"exit": true}` waits for the process to exit on its own — use this when
//! `expect.running` is `false`, with `expect.exitCode` given. Either way `timeoutSecs` (default 20) bounds the
//! wait. The process (Docker container or host child) is always torn down once the scenario's assertions are
//! taken, pass or fail (`Handle`'s `Drop`).
//!
//! One `#[test]` walks every file under `tests/process_scenarios/`, in name order; `MOCK_SERVER_SCENARIO=<sub>`
//! filters to file stems containing `<sub>`, the same convention `tests/oracle.rs` uses. There is no
//! record/replay step here (unlike the HTTP scenario harness): a process scenario asserts directly against the
//! oracle or our own binary, so there is nothing to keep a golden copy of.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

#[path = "support/tcp_port.rs"]
mod tcp_port;
#[path = "support/docker_bind.rs"]
mod docker_bind;
#[path = "support/image_analytics.rs"]
mod image_analytics;

fn scenarios_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/process_scenarios")
}

/// A fresh, empty directory for one `"binary"`-target child process's cwd: under `target/`, so
/// whatever the binary writes relative to its cwd (`mockserver-ca.pem` under `proxySetupLogging`, `.tmp`
/// siblings while it's being written atomically) never lands in the repository tree the way it would if the
/// child inherited the test binary's own cwd (`cargo test` sets that to the package root).
fn scratch_cwd() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/scratch/process-scenarios").join(uuid::Uuid::new_v4().simple().to_string());
    fs::create_dir_all(&dir).expect("create scratch cwd");
    dir
}

/// Name, length and mtime of every `mockserver-ca*` entry in the repository root: a stray one left by
/// a hand-started server is tolerated, a scenario that changes or adds one is not.
fn root_ca_snapshot() -> Vec<(String, u64, Option<std::time::SystemTime>)> {
    let mut entries: Vec<_> = fs::read_dir(env!("CARGO_MANIFEST_DIR"))
        .expect("read repo root")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("mockserver-ca"))
        .map(|e| {
            let meta = e.metadata().ok();
            (e.file_name().to_string_lossy().into_owned(), meta.as_ref().map_or(0, |m| m.len()), meta.and_then(|m| m.modified().ok()))
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

/// `tests/process_scenarios/skips-rs.txt`: compared outputs that do not match the oracle's golden yet,
/// `<scenario> <stdout|stderr|body:<label>>  # <reason>` per line (`body:<label>` a `compareBody` answer); a to-do list like the oracle scenarios' `skips-rs.txt`.
fn output_skips() -> HashMap<(String, String), String> {
    fs::read_to_string(scenarios_dir().join("skips-rs.txt"))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (entry, reason) = l.split_once('#').unwrap_or_else(|| panic!("skips-rs.txt: no `# <reason>` on {l:?}"));
            let mut parts = entry.split_whitespace();
            let (name, stream) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
            assert!(stream == "stdout" || stream == "stderr" || stream.strip_prefix("body:").is_some_and(|l| !l.is_empty()), "skips-rs.txt: {l:?} names no stream");
            ((name.to_string(), stream.to_string()), reason.trim().to_string())
        })
        .collect()
}

fn scenario_files() -> Vec<PathBuf> {
    let filter = std::env::var("MOCK_SERVER_SCENARIO").ok();
    let mut files: Vec<PathBuf> = fs::read_dir(scenarios_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .filter(|p| filter.as_ref().is_none_or(|f| p.file_stem().unwrap().to_string_lossy().contains(f.as_str())))
        .collect();
    files.sort();
    files
}

/// stdout/stderr captured from the process, kept separately (upstream's own logging mixes INFO/WARNING lines
/// into what Docker reports as stdout; our binary's `eprintln!` diagnostics land on stderr).
#[derive(Default, Clone)]
struct Captured {
    stdout: String,
    stderr: String,
}

enum Handle {
    Docker { name: String },
    /// `picked`: the port `"pickPort"` chose for `{{serverPort}}`, for a server that does not log `started on port`.
    Binary { child: Child, out: Arc<Mutex<String>>, err: Arc<Mutex<String>>, cwd: PathBuf, readers: Arc<AtomicUsize>, picked: Option<u16> },
}

impl Handle {
    /// Combined stdout+stderr seen so far, for readiness matching (upstream's own log lines aren't reliably on
    /// one stream or the other either).
    fn combined_log(&self) -> String {
        let c = self.captured();
        format!("{}{}", c.stdout, c.stderr)
    }

    fn captured(&self) -> Captured {
        match self {
            Handle::Docker { name } => {
                let out = Command::new("docker").args(["logs", name]).output().expect("docker logs");
                Captured { stdout: String::from_utf8_lossy(&out.stdout).into_owned(), stderr: String::from_utf8_lossy(&out.stderr).into_owned() }
            }
            Handle::Binary { out, err, .. } => Captured { stdout: out.lock().unwrap().clone(), stderr: err.lock().unwrap().clone() },
        }
    }

    fn running(&mut self) -> bool {
        match self {
            Handle::Docker { name } => {
                let out = Command::new("docker").args(["inspect", "-f", "{{.State.Running}}", name]).output().expect("docker inspect");
                String::from_utf8_lossy(&out.stdout).trim() == "true"
            }
            Handle::Binary { child, readers, .. } => {
                if child.try_wait().expect("try_wait").is_none() {
                    return true;
                }
                // exited: its pipes are at end of file, but the reader threads may lag by a few milliseconds; let
                // them drain before anyone reads what was captured
                let deadline = Instant::now() + Duration::from_secs(2);
                while readers.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                false
            }
        }
    }

    /// The exit code, once the process is confirmed not running; `None` while it is still running.
    fn exit_code(&mut self) -> Option<i32> {
        if self.running() {
            return None;
        }
        match self {
            Handle::Docker { name } => {
                let out = Command::new("docker").args(["inspect", "-f", "{{.State.ExitCode}}", name]).output().expect("docker inspect");
                String::from_utf8_lossy(&out.stdout).trim().parse().ok()
            }
            Handle::Binary { child, .. } => child.try_wait().expect("try_wait").and_then(|s| s.code()),
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        match self {
            Handle::Docker { name } => {
                let _ = Command::new("docker").args(["rm", "-f", name]).output();
            }
            Handle::Binary { child, .. } => {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

/// Whether a `pickPort` binary has exited because its port was taken. `Main` logs "Exception while
/// binding MockServer to port N" and exits 1, but with logging disabled only the usage text is left; so a binary that
/// exited counts as having lost its port also while the port is still taken. Does not wait.
fn exited_on_lost_port(handle: &mut Handle) -> bool {
    let Handle::Binary { picked: Some(port), .. } = handle else { return false };
    let port = *port;
    if handle.running() {
        return false;
    }
    let taken = std::net::TcpListener::bind(("0.0.0.0", port)).is_err_and(|e| e.kind() == std::io::ErrorKind::AddrInUse);
    taken || handle.combined_log().contains(&format!("Exception while binding MockServer to port {port}"))
}

/// [`exited_on_lost_port`], once the outcome is known: a readiness line can come before the bind (the
/// property file dump), so this waits (up to `deadline`) until the binary has exited or is itself listening on its
/// port ([`listens_on`]). Where that cannot be asked, a port that accepts is taken for bound, and since a port held by
/// another process accepts at once, it then waits a little longer for the binary that lost it to exit; at load ~90 a
/// binary can take longer than that to reach its bind, which the listener check does not depend on.
fn lost_picked_port(handle: &mut Handle, deadline: Instant) -> bool {
    let Handle::Binary { picked: Some(port), child, .. } = handle else { return false };
    let (port, pid) = (*port, child.id());
    while handle.running() && Instant::now() < deadline {
        match listens_on(pid, port) {
            Some(true) => return false,
            Some(false) => {}
            None => {
                if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    std::thread::sleep(Duration::from_millis(500));
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    exited_on_lost_port(handle)
}

/// Whether process `pid` itself has a TCP socket listening on `port`, so that a port another process
/// holds is not taken for the binary's: `/proc/<pid>/fd` against `/proc/<pid>/net/tcp{,6}` on Linux, `lsof` elsewhere.
/// `None` when this cannot be asked.
#[cfg(target_os = "linux")]
fn listens_on(pid: u32, port: u16) -> Option<bool> {
    let inodes: Vec<String> = fs::read_dir(format!("/proc/{pid}/fd"))
        .ok()?
        .filter_map(|e| fs::read_link(e.ok()?.path()).ok())
        .filter_map(|target| target.to_str()?.strip_prefix("socket:[")?.strip_suffix(']').map(str::to_string))
        .collect();
    let mut asked = false;
    for table in ["tcp", "tcp6"] {
        let Ok(text) = fs::read_to_string(format!("/proc/{pid}/net/{table}")) else { continue };
        asked = true;
        // `sl local_address rem_address st … inode`: the local port in hex after the colon, `0A` is LISTEN
        let listening = text.lines().skip(1).any(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            cols.len() > 9
                && cols[3] == "0A"
                && cols[1].rsplit(':').next().and_then(|p| u16::from_str_radix(p, 16).ok()) == Some(port)
                && inodes.iter().any(|i| i == cols[9])
        });
        if listening {
            return Some(true);
        }
    }
    asked.then_some(false)
}

/// See the Linux variant: `lsof` exits 0 with the pids that have a matching listening socket, 1 when none has. On
/// macOS the binary's dual-stack bind succeeds on a port another process holds on IPv4, and the binary
/// listens there until its loopback probe finds the port shadowed and it exits: while another process listens on
/// the port too, the binary's own listener is not taken for its bind.
#[cfg(not(target_os = "linux"))]
fn listens_on(pid: u32, port: u16) -> Option<bool> {
    let out = Command::new("lsof").args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"]).output().ok()?;
    match out.status.code() {
        Some(0) => {
            let pids: Vec<String> = String::from_utf8_lossy(&out.stdout).split_whitespace().map(str::to_string).collect();
            Some(pids.iter().any(|p| *p == pid.to_string()) && pids.iter().all(|p| *p == pid.to_string()))
        }
        Some(1) => Some(false),
        _ => None,
    }
}

/// The host port a started process answers on: the container's published 1080, or the port our binary logged.
fn host_port(handle: &Handle) -> Option<u16> {
    match handle {
        Handle::Docker { name } => {
            let out = Command::new("docker").args(["port", name, "1080/tcp"]).output().expect("docker port");
            String::from_utf8_lossy(&out.stdout).lines().next()?.rsplit(':').next()?.trim().parse().ok()
        }
        Handle::Binary { picked, .. } => {
            let log = handle.combined_log();
            // "started on port: N", or "started on ports: [N, M]" for several: the first one
            let at = match log.find("started on port: ") {
                Some(at) => at + "started on port: ".len(),
                None => match log.find("started on ports: [") {
                    Some(at) => at + "started on ports: [".len(),
                    None => return *picked,
                },
            };
            log[at..].chars().take_while(char::is_ascii_digit).collect::<String>().parse().ok()
        }
    }
}

#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &[rustls_pki_types::CertificateDer<'_>],
        _: &rustls_pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, m: &[u8], c: &rustls_pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, m: &[u8], c: &rustls_pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// What one HTTPS request saw: whether the TLS handshake completed and the answer was `HTTP/1.1 200`, and the DER of
/// the leaf certificate the server presented.
#[derive(Clone, Debug)]
struct TlsOutcome {
    answered: bool,
    certificate: Option<Vec<u8>>,
}

/// One HTTPS `PUT /mockserver/status` (SNI `sni`, any server certificate accepted). A server that refuses its
/// configured certificate closes the connection at the handshake (`afterReady` `tls` steps).
fn tls_status_answered(port: u16, sni: &str) -> TlsOutcome {
    let none = TlsOutcome { answered: false, certificate: None };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let Ok(name) = rustls_pki_types::ServerName::try_from(sni.to_string()) else { return none };
    let Ok(conn) = rustls::ClientConnection::new(Arc::new(config), name) else { return none };
    let Ok(tcp) = std::net::TcpStream::connect(("127.0.0.1", port)) else { return none };
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(10)));
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let request = format!("PUT /mockserver/status HTTP/1.1\r\nHost: {sni}:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    if tls.write_all(request.as_bytes()).is_err() {
        return none;
    }
    let mut answer = [0u8; 12];
    let answered = tls.read_exact(&mut answer).is_ok() && answer.starts_with(b"HTTP/1.1 200");
    let certificate = tls.conn.peer_certificates().and_then(|c| c.first()).map(|c| c.as_ref().to_vec());
    TlsOutcome { answered, certificate }
}

/// [`plain_http_as`] over TLS presenting the client certificate `cert` with its key `key` (PEM files under `tests/files`),
/// any server certificate accepted (an http step's `clientCertificate`). A refused handshake answers "".
fn https_as(port: u16, host_port: u16, method: &str, path: &str, body: &str, timeout: Duration, (cert, key): (&str, &str)) -> String {
    use rustls_pki_types::pem::PemObject;
    let files = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/files");
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_file_iter(files.join(cert)).expect("clientCertificate.cert").map(|c| c.expect("clientCertificate.cert")).collect();
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(files.join(key)).expect("clientCertificate.key");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_client_auth_cert(certs, key)
        .expect("client certificate and key");
    let conn = rustls::ClientConnection::new(Arc::new(config), rustls_pki_types::ServerName::try_from("localhost").expect("name")).expect("tls client");
    let tcp = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect for https");
    let _ = tcp.set_read_timeout(Some(timeout));
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let request = format!("{method} {path} HTTP/1.1\r\nHost: localhost:{host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    if tls.write_all(request.as_bytes()).is_err() {
        return String::new();
    }
    let mut answer = Vec::new();
    let _ = tls.read_to_end(&mut answer);
    String::from_utf8_lossy(&answer).into_owned()
}

/// One plain-HTTP request to the started server, for a step that changes its configuration between TLS requests, with
/// the `Host` port the server itself listens on (`host_port`): the oracle container publishes an ephemeral port, so its
/// own port is 1080 and a request addressed to the published one counts as proxied.
fn plain_http_as(port: u16, host_port: u16, method: &str, path: &str, body: &str, timeout: Duration) -> String {
    let mut tcp = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect for plain http");
    let _ = tcp.set_read_timeout(Some(timeout));
    let request = format!("{method} {path} HTTP/1.1\r\nHost: localhost:{host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    tcp.write_all(request.as_bytes()).expect("write plain http");
    let mut answer = String::new();
    let _ = tcp.read_to_string(&mut answer);
    answer
}

/// A `{"tcp": base64}` step: the bytes on a fresh connection, whatever comes back read for up to a second
/// (a binary request nothing answers leaves the connection open), then closed.
fn raw_tcp(port: u16, bytes: &str) {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD.decode(bytes).expect("tcp step: base64");
    let mut tcp = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect for tcp");
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(1)));
    tcp.write_all(&bytes).expect("write tcp");
    let mut answer = Vec::new();
    let _ = tcp.read_to_end(&mut answer);
}

/// A self-signed ECDSA certificate for `localhost` with a validity window relative to now, written as
/// `<dir>/<name>-key.pem` (PKCS#8) and `<dir>/<name>-cert.pem`.
fn write_certificate(dir: &std::path::Path, spec: &Value) {
    let name = spec["name"].as_str().expect("certificate needs a name");
    let now = time::OffsetDateTime::now_utc();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("certificate params");
    params.not_before = now + time::Duration::seconds(spec["notBeforeSecs"].as_i64().unwrap_or(-3600));
    params.not_after = now + time::Duration::seconds(spec["notAfterSecs"].as_i64().unwrap_or(86_400));
    params.distinguished_name.push(rcgen::DnType::CommonName, "localhost");
    let key = rcgen::KeyPair::generate().expect("key pair");
    let cert = params.self_signed(&key).expect("self-signed certificate");
    fs::write(dir.join(format!("{name}-key.pem")), key.serialize_pem()).expect("write key");
    fs::write(dir.join(format!("{name}-cert.pem")), cert.pem()).expect("write certificate");
}

/// `files` of a scenario (`{"relative/path": "content"}`) written under `dir`; a `{"from": "path"}` value copies
/// `tests/files/<path>` instead, so a checked-in fixture the server rewrites is only ever touched as a copy.
fn write_files(dir: &std::path::Path, files: &Value) {
    for (name, content) in files.as_object().into_iter().flatten() {
        let path = dir.join(name);
        fs::create_dir_all(path.parent().unwrap()).expect("create file directory");
        match content["from"].as_str() {
            Some(from) => {
                let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/files").join(from);
                fs::copy(&source, &path).unwrap_or_else(|e| panic!("copy {} to {}: {e}", source.display(), path.display()));
            }
            None => fs::write(&path, content.as_str().unwrap_or_default()).expect("write scenario file"),
        }
    }
}

/// The Unix mode of `path` as `rwxr-xr-x`, read on the host (the scratch directory is shared with the container).
fn mode_string(path: &std::path::Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path).ok()?.permissions().mode();
    Some((0..9).map(|i| if mode & (0o400 >> i) != 0 { b"rwxrwxrwx"[i] as char } else { '-' }).collect())
}

fn spawn_reader(mut pipe: impl Read + Send + 'static, buf: Arc<Mutex<String>>, readers: Arc<AtomicUsize>) {
    readers.fetch_add(1, Ordering::SeqCst);
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.lock().unwrap().push_str(&String::from_utf8_lossy(&chunk[..n])),
            }
        }
        readers.fetch_sub(1, Ordering::SeqCst);
    });
}

/// An `expect` string list, with `{{files}}` and `{{scratch}}` substituted like in `args` and `env`.
/// `path` itself, or, when its file name has a `*`, the one file in its directory whose name matches with `*` as any text.
fn resolve_glob(path: &Path) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if !name.contains('*') {
        return path.to_path_buf();
    }
    let dir = path.parent().expect("a directory");
    let pattern = regex::Regex::new(&format!("^{}$", name.split('*').map(regex::escape).collect::<Vec<_>>().join(".*"))).expect("glob");
    let found: Vec<PathBuf> = fs::read_dir(dir).into_iter().flatten().flatten().filter(|e| pattern.is_match(&e.file_name().to_string_lossy())).map(|e| e.path()).collect();
    assert_eq!(found.len(), 1, "want one file matching {} in {}, found {found:?}", name, dir.display());
    found.into_iter().next().unwrap()
}

fn expected_strings(v: &Value, scratch: &std::path::Path) -> Vec<String> {
    let files_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/files").to_string_lossy().into_owned();
    let scratch_dir = scratch.to_string_lossy();
    string_array(v).into_iter().map(|s| s.replace("{{files}}", &files_dir).replace("{{scratch}}", &scratch_dir)).collect()
}

fn write_property_file(content: &str) -> PathBuf {
    // under `target/scratch`, not the system temp directory: the Docker VM shares only `$HOME` with its VM, so a bind mount of
    // a file in `/var/folders` reaches the oracle container as an empty directory
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/scratch/process-properties");
    fs::create_dir_all(&dir).expect("create property file directory");
    let path = dir.join(format!("{}.properties", uuid::Uuid::new_v4()));
    fs::write(&path, content).expect("write property file");
    path
}

fn string_map(v: &Value) -> HashMap<String, String> {
    v.as_object().map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect()).unwrap_or_default()
}

fn string_array(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().map(|s| s.as_str().unwrap_or_default().to_string()).collect()).unwrap_or_default()
}

/// Starts the process a scenario describes; returns its handle and the temp property file to clean up, if any.
fn launch(scenario: &Value, target: &str, scratch: &std::path::Path) -> (Handle, Option<PathBuf>) {
    // `{{files}}`: the absolute path of `tests/files`, which the `oracleDocker` target mounts at the same path.
    let files_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/files").to_string_lossy().into_owned();
    // `{{serverPort}}`: 1080 for the oracle container (the one port Docker publishes), 0 (any free port) for our binary.
    // `"pickPort": true` gives the binary a free ephemeral port instead, chosen here, for a scenario whose
    // server logs nothing (`disableLogging`) so the port cannot be read from `started on port`.
    let picked = (target == "binary" && scenario["pickPort"].as_bool() == Some(true))
        .then(tcp_port::free_tcp_port);
    let picked_text = picked.map(|p| p.to_string());
    let (server_port, server_port2) = if target == "oracleDocker" { ("1080", "1081") } else { (picked_text.as_deref().unwrap_or("0"), "0") };
    // `{{scratch}}`: this run's own directory (shared with the container at the same path), for `files`, generated
    // certificates and whatever the server writes.
    let scratch_dir = scratch.to_string_lossy().into_owned();
    let sub = |text: &str| text.replace("{{files}}", &files_dir).replace("{{serverPort}}", server_port).replace("{{serverPort2}}", server_port2).replace("{{scratch}}", &scratch_dir);
    let args: Vec<String> = string_array(&scenario["args"]).into_iter().map(|a| sub(&a)).collect();
    let env: HashMap<String, String> = string_map(&scenario["env"]).into_iter().map(|(k, v)| (k, sub(&v))).collect();
    let property_file = scenario["propertyFile"].as_str().map(|p| write_property_file(&sub(p)));

    match target {
        "oracleDocker" => {
            let name = format!("mock-server-process-scenario-{}", uuid::Uuid::new_v4());
            let files = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/files");
            let mut cmd = Command::new("docker");
            // no `--rm`: a scenario that expects the process to exit still needs its logs and exit code;
            // `Handle`'s `Drop` removes the container
            cmd.args(["run", "-d", "--name", &name, "-p", "127.0.0.1::1080"]).args(docker_bind::bind_same(&files, true));
            // The memory the JVM sees, for a ceiling sized from it (`-XX:MaxRAMPercentage`); the Docker VM's own is not pinned
            if let Some(bytes) = scenario["containerMemoryBytes"].as_u64() {
                cmd.arg("--memory").arg(bytes.to_string());
            }
            cmd.args(docker_bind::bind_same(scratch, false));
            if let Some(p) = &property_file {
                cmd.args(docker_bind::bind(p, Path::new("/config/mockserver.properties"), true));
            }
            // the processors and heap the oracle sizes its defaults from, as `make oracle` pins them
            let pin = |key: &str| include_str!("../oracle.env").lines().find_map(|line| line.strip_prefix(key)?.strip_prefix('=')).unwrap_or_else(|| panic!("oracle.env has no {key}"));
            // A scenario that sets a heap flag in a JVM options variable keeps it: the launcher's
            // `JDK_JAVA_OPTIONS` would override one in `JAVA_TOOL_OPTIONS`, so the pinned `-Xmx` is left out; a
            // scenario's own `JDK_JAVA_OPTIONS` follows the pins, where its tokens win.
            // `-XX:MaxRAM`, `-XX:MaxRAMPercentage` and `-XX:MinRAMPercentage` size the ceiling from the memory too: the pin
            // would beat them
            let heap_flag = |v: &String| v.split_whitespace().any(|t| ["-Xmx", "-XX:MaxHeapSize=", "-XX:MaxRAM", "-XX:MinRAMPercentage="].iter().any(|p| t.starts_with(p)));
            // a scenario that fixes the container's memory has the JVM size the heap from it, so the pin stays out as well
            let sets_heap = scenario["containerMemoryBytes"].is_u64() || ["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"].iter().any(|k| env.get(*k).is_some_and(heap_flag));
            let mut jdk_options = format!("-XX:ActiveProcessorCount={}", pin("ORACLE_ACTIVE_PROCESSORS"));
            if !sets_heap {
                jdk_options.push_str(&format!(" -Xmx{}", pin("ORACLE_MAX_HEAP_BYTES")));
            }
            if let Some(own) = env.get("JDK_JAVA_OPTIONS") {
                jdk_options.push_str(&format!(" {own}"));
            }
            cmd.arg("-e").arg(format!("JDK_JAVA_OPTIONS={jdk_options}"));
            for (k, v) in env.iter().filter(|(k, _)| k.as_str() != "JDK_JAVA_OPTIONS") {
                cmd.arg("-e").arg(format!("{k}={v}"));
            }
            cmd.arg(oracle_image(scenario)).args(&args);
            let out = cmd.output().expect("docker run");
            assert!(out.status.success(), "docker run: {}", String::from_utf8_lossy(&out.stderr));
            (Handle::Docker { name }, property_file)
        }
        "binary" => {
            let mut all_args = args;
            if let Some(p) = &property_file {
                all_args.push(format!("-Dmockserver.propertyFile={}", p.display()));
            }
            let cwd = scratch_cwd();
            let mut command = Command::new(env!("CARGO_BIN_EXE_mock-server"));
            {
                // the oracle container writes with umask 022; a host's own umask (002 on Ubuntu) must not change the modes asserted
                use std::os::unix::process::CommandExt;
                // SAFETY: `umask` is async-signal-safe and touches no memory of the forked child.
                unsafe {
                    command.pre_exec(|| {
                        libc::umask(0o022);
                        Ok(())
                    });
                }
            }
            let mut child = command
                .args(&all_args)
                // the console's own filter: a developer's `RUST_LOG` must not hide what a scenario asserts
                .env_remove("RUST_LOG")
                // the heap- and processor-derived defaults as the recording oracle's machine sized them
                .env(mock_server::CONTAINER_MEMORY_ENV, scenario["containerMemoryBytes"].as_u64().unwrap_or(mock_server::ORACLE_CONTAINER_MEMORY_BYTES).to_string())
                .env(mock_server::ACTIVE_PROCESSOR_COUNT_ENV, mock_server::ORACLE_ACTIVE_PROCESSORS.to_string())
                .envs(&env)
                .current_dir(&cwd)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn binary");
            let out = Arc::new(Mutex::new(String::new()));
            let err = Arc::new(Mutex::new(String::new()));
            let readers = Arc::new(AtomicUsize::new(0));
            spawn_reader(child.stdout.take().expect("piped stdout"), out.clone(), readers.clone());
            spawn_reader(child.stderr.take().expect("piped stderr"), err.clone(), readers.clone());
            (Handle::Binary { child, out, err, cwd, readers, picked }, property_file)
        }
        other => panic!("unknown target {other:?} (want \"oracleDocker\" or \"binary\")"),
    }
}

/// What a run does with `expect.compareOutput`: check the captured output against the golden files, or write them.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Check,
    Record,
}

fn golden_path(file: &std::path::Path, stream: &str) -> PathBuf {
    scenarios_dir().join("golden").join(format!("{}.{stream}", file.file_stem().unwrap().to_string_lossy()))
}

/// A stream as the `stdout*`/`stderr*` assertions read it: each log line's header, the oracle's
/// `java.util.logging` one (`2026-10-12 14:01:00 8.0.1-SNAPSHOT WARNING 1080 `) and ours (`2026-10-12T14:01:00.123456Z  WARN
/// mock_server::server: port=1080 `), becomes `[LEVEL] ` with the SLF4J level name, and every line loses one
/// trailing space (`java.util.logging` ends a message with one, before its throwable or the line's end). Timestamps, version, target and port are
/// dropped: the console's format is our own, while which events it shows, at which level, with which text, is what
/// a scenario checks. Other lines (usage text, the proxy setup block) are kept as they are.
fn console_view(text: &str) -> String {
    static HEADERS: std::sync::OnceLock<(regex::Regex, regex::Regex)> = std::sync::OnceLock::new();
    let (oracle, ours) = HEADERS.get_or_init(|| {
        (
            regex::Regex::new(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \d+\.\d+\.\d+(?:-SNAPSHOT)? (FINEST|FINE|INFO|WARNING|SEVERE) (?:\d+ )?").unwrap(),
            regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z +(TRACE|DEBUG|INFO|WARN|ERROR) mock_server::\w+: (?:port=\d+ )?").unwrap(),
        )
    });
    let mut view = String::with_capacity(text.len());
    for line in text.lines() {
        let line = line.strip_suffix(' ').unwrap_or(line);
        let header = oracle.captures(line).or_else(|| ours.captures(line));
        match header {
            Some(c) => {
                let level = match &c[1] {
                    "FINEST" => "TRACE",
                    "FINE" => "DEBUG",
                    "WARNING" => "WARN",
                    "SEVERE" => "ERROR",
                    other => other,
                };
                view.push_str(&format!("[{level}] {}", &line[c.get(0).unwrap().end()..]));
            }
            None => view.push_str(line),
        }
        view.push('\n');
    }
    view
}

/// An http step's `"compareBody": label`: the answer's body, a JSON array one element per line (an object one
/// `name: value` per line), with this run's scratch directory read as `{{scratch}}`, `tests/files` as `{{files}}`, the two
/// `GET /mockserver/config` entries the oracle image sets itself masked, and each of the scenario's `"bodyMask"` `[{"regex", "replace"}]` applied per line. Recording writes `golden/<stem>.<label>.body` from the oracle;
/// a check run compares it line by line and names every line that differs.
fn compare_body(file: &Path, scenario: &Value, label: &str, answer: &str, scratch: &Path, mode: Mode, target: &str) {
    let (head, body) = answer.split_once("\r\n\r\n").unwrap_or_else(|| panic!("{}: compareBody {label}: no HTTP answer: {answer:?}", file.display()));
    assert!(head.starts_with("HTTP/1.1 200"), "{}: compareBody {label}: answered {head:?}", file.display());
    // the image's dashboard analytics values read as ours in the `Configuration` JSON as it comes (its
    // `"name" : "value"` shape is gone once an object is printed one `name: value` per line below)
    let body = image_analytics::as_ours(body);
    let lines: Vec<String> = match serde_json::from_str::<Value>(&body) {
        Ok(Value::Array(items)) => items.iter().map(|item| item.to_string()).collect(),
        Ok(Value::Object(fields)) => fields.iter().map(|(name, value)| format!("{name}: {value}")).collect(),
        _ => body.lines().map(str::to_string).collect(),
    };
    let files_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/files").to_string_lossy().into_owned();
    // what the oracle image sets itself, in `GET /mockserver/config`: `-Dmockserver.propertyFile=/config/mockserver.properties`
    // in its `JAVA_TOOL_OPTIONS` (the harness hands our binary a temp file instead) and
    // `MOCKSERVER_DASHBOARD_ANALYTICS_DISTRIBUTION=docker-standard` in its environment (our binary's default there)
    let image = [
        (r#"^\{"name":"mockserver\.propertyFile",.*\}$"#, "<image: propertyFile>"),
        (r#"^\{"name":"mockserver\.dashboardAnalyticsDistribution","value":"(?:docker-standard|\(default\)|)","source":"(?:environment-variable|default)"(?:,"default":"[^"]*")?\}$"#, "<image: dashboardAnalyticsDistribution>"),
    ];
    let masks: Vec<(regex::Regex, String)> = image
        .iter()
        .map(|(regex, replace)| (regex::Regex::new(regex).unwrap(), replace.to_string()))
        .chain(scenario["bodyMask"].as_array().into_iter().flatten().map(|m| {
            (regex::Regex::new(m["regex"].as_str().expect("bodyMask regex")).expect("bodyMask regex"), m["replace"].as_str().unwrap_or("<masked>").to_string())
        }))
        .collect();
    let mut got = String::new();
    for line in lines {
        let mut line = line.replace(&*scratch.to_string_lossy(), "{{scratch}}").replace(&files_dir, "{{files}}");
        for (regex, replace) in &masks {
            line = regex.replace_all(&line, replace.as_str()).into_owned();
        }
        got.push_str(&line);
        got.push('\n');
    }
    // the image's dashboard analytics endpoint and key read as ours, in a recording and in a golden made before
    let got = image_analytics::as_ours(&got).into_owned();
    let path = scenarios_dir().join("golden").join(format!("{}.{label}.body", file.file_stem().unwrap().to_string_lossy()));
    if mode == Mode::Record {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &got).unwrap();
        return;
    }
    let want = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: golden {}: {e}", file.display(), path.display()));
    let want = image_analytics::as_ours(&want).into_owned();
    // `skips-rs.txt`: a listed body that does not match the oracle yet, a to-do that must still differ
    let name = file.file_stem().unwrap().to_string_lossy();
    if let Some(reason) = output_skips().get(&(name.to_string(), format!("body:{label}"))) {
        assert_ne!(got, want, "{}: {target} body {label} matches now: remove it from skips-rs.txt ({reason})", file.display());
        return;
    }
    if got != want {
        let (got_lines, want_lines): (Vec<&str>, Vec<&str>) = (got.lines().collect(), want.lines().collect());
        let mut report = String::new();
        for i in 0..got_lines.len().max(want_lines.len()) {
            let (g, w) = (got_lines.get(i).copied().unwrap_or("<none>"), want_lines.get(i).copied().unwrap_or("<none>"));
            if g != w {
                report.push_str(&format!("  line {}:\n    want {w}\n    got  {g}\n", i + 1));
            }
        }
        panic!("{}: {target} body {label} differs from {}:\n{report}", file.display(), path.display());
    }
}

/// Masks what differs between runs (timestamps, UUIDs) and what a scenario's `mask` list names.
fn normalise_output(text: &str, scenario: &Value) -> String {
    // The JVM's own notice that the image's `JAVA_TOOL_OPTIONS` (or ours `JDK_JAVA_OPTIONS`, which the launcher announces
    // as `NOTE: Picked up …`) applies: the oracle image's launch environment, not MockServer's output.
    let mut out: String = text
        .split_inclusive('\n')
        .filter(|line| !line.trim_start_matches("NOTE: ").starts_with("Picked up ") || !line.contains("_OPTIONS: "))
        .collect();
    // `tests/files` as `{{files}}` (`lint` names each file it read), so a golden holds no checkout's path
    out = out.replace(&*PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/files").to_string_lossy(), "{{files}}");
    let mut masks: Vec<(String, &str)> = vec![
        (r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}".into(), "<time>"),
        (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}".into(), "<uuid>"),
    ];
    masks.extend(string_array(&scenario["mask"]).into_iter().map(|m| (m, "<masked>")));
    for (pattern, replacement) in masks {
        out = regex::Regex::new(&pattern).expect("mask regex").replace_all(&out, replacement).into_owned();
    }
    // the image's dashboard analytics endpoint and key read as ours, so a recording never holds them
    image_analytics::as_ours(&out).into_owned()
}

/// A `"target": "both"` scenario runs our binary on every replay; with `MOCK_SERVER_PROCESS_ORACLE=1` it also runs the
/// oracle image against the same expectations (so a golden is proven to be the oracle's), and with
/// `MOCK_SERVER_PROCESS_RECORD=1` plus `MOCK_SERVER_SCENARIO=<name>` it runs only the oracle and writes the golden
/// `expect.compareOutput` files (`tests/process_scenarios/golden/<name>.stdout` / `.stderr`).
fn run_scenario(file: &Path, scenario: &Value) {
    let target = scenario["target"].as_str().expect("scenario needs a \"target\"");
    if target != "both" {
        run_target(file, scenario, target, Mode::Check);
        return;
    }
    if std::env::var("MOCK_SERVER_PROCESS_RECORD").is_ok_and(|v| !v.is_empty()) {
        assert!(std::env::var("MOCK_SERVER_SCENARIO").is_ok_and(|v| !v.is_empty()), "MOCK_SERVER_PROCESS_RECORD needs MOCK_SERVER_SCENARIO=<name>");
        run_target(file, scenario, "oracleDocker", Mode::Record);
        return;
    }
    run_target(file, scenario, "binary", Mode::Check);
    if std::env::var("MOCK_SERVER_PROCESS_ORACLE").is_ok_and(|v| !v.is_empty()) {
        run_target(file, scenario, "oracleDocker", Mode::Check);
    }
}

fn run_target(file: &Path, scenario: &Value, target: &str, mode: Mode) {
    let root_before = root_ca_snapshot();
    let scratch = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/scratch/process-fixtures").join(uuid::Uuid::new_v4().simple().to_string());
    fs::create_dir_all(&scratch).expect("create scenario scratch directory");
    {
        // the oracle container runs as `nonroot`; the shared directory has to be writable for it
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&scratch, fs::Permissions::from_mode(0o777)).expect("chmod scratch");
    }
    write_files(&scratch, &scenario["files"]);
    for spec in scenario["certificates"].as_array().into_iter().flatten().filter(|c| c["late"].as_bool() != Some(true)) {
        write_certificate(&scratch, spec);
    }
    let (mut handle, mut property_file) = launch(scenario, target, &scratch);
    let timeout = Duration::from_secs(scenario["timeoutSecs"].as_u64().unwrap_or(20));
    let mut deadline = Instant::now() + timeout;
    let readiness = &scenario["readiness"];

    let mut attempt = 1;
    loop {
        // a `pickPort` port another process took first: launch again with a fresh one
        let retry = attempt < tcp_port::START_ATTEMPTS;
        if let Some(needle) = readiness["logContains"].as_str() {
            loop {
                if handle.combined_log().contains(needle) || (retry && exited_on_lost_port(&mut handle)) {
                    break;
                }
                assert!(Instant::now() < deadline, "{}: timed out waiting for log to contain {needle:?}; log so far:\n{}", file.display(), handle.combined_log());
                std::thread::sleep(Duration::from_millis(200));
            }
        } else if readiness["exit"].as_bool() == Some(true) {
            loop {
                if !handle.running() {
                    break;
                }
                assert!(Instant::now() < deadline, "{}: timed out waiting for the process to exit; log so far:\n{}", file.display(), handle.combined_log());
                std::thread::sleep(Duration::from_millis(200));
            }
        } else {
            panic!("{}: \"readiness\" needs \"logContains\" or \"exit\"", file.display());
        }
        if !(retry && lost_picked_port(&mut handle, deadline)) {
            break;
        }
        eprintln!("{}: the picked port was taken before the binary bound it; launching again with a fresh one", file.display());
        drop(handle);
        if let Some(p) = property_file.take() {
            let _ = fs::remove_file(p);
        }
        (handle, property_file) = launch(scenario, target, &scratch);
        deadline = Instant::now() + timeout;
        attempt += 1;
    }
    // `readiness.settleMillis`: keep waiting after readiness, for a scenario whose point is a line that
    // must *not* appear (hidden by `logLevelOverrides`), so a late line cannot slip past the assertions.
    if let Some(ms) = readiness["settleMillis"].as_u64() {
        std::thread::sleep(Duration::from_millis(ms));
    }

    // `afterReady`: steps run against the started server, in order. `{"tls": N, "label": l, "sni": host}` makes
    // N HTTPS requests recorded under `l` (`"warmup": true` records nothing: the first request of a fresh oracle is
    // sometimes closed whatever the configuration, see tests/upstream/tls_fixed_certificate_validation.rs);
    // `{"http": {"method", "path", "body"}}` is one plain-HTTP request; `{"sleepMillis": n}`; `{"certificate": spec}`
    // writes a certificate now (a `late` entry of `certificates`).
    let mut tls_outcomes: HashMap<String, Vec<TlsOutcome>> = HashMap::new();
    let mut background: HashMap<String, std::thread::JoinHandle<String>> = HashMap::new();
    for step in scenario["afterReady"].as_array().into_iter().flatten() {
        if let Some(n) = step["tls"].as_u64() {
            let port = host_port(&handle).unwrap_or_else(|| panic!("{}: a tls step needs a started server; log:\n{}", file.display(), handle.combined_log()));
            let sni = step["sni"].as_str().unwrap_or("localhost");
            for _ in 0..n {
                let outcome = tls_status_answered(port, sni);
                if step["warmup"].as_bool() != Some(true) {
                    tls_outcomes.entry(step["label"].as_str().unwrap_or("tls").to_string()).or_default().push(outcome);
                }
            }
        } else if let Some(http) = step.get("http") {
            let port = host_port(&handle).expect("an http step needs a started server");
            let own = if http["ownHost"].as_bool() == Some(true) && !matches!(handle, Handle::Binary { .. }) { 1080 } else { port };
            // `{{ownPort}}` in a body: the port the server listens on itself (1080 inside the oracle container), so a
            // forward to `localhost:{{ownPort}}` reaches the server from either target.
            let own_port = if matches!(handle, Handle::Binary { .. }) { port } else { 1080 };
            let body = http["body"].as_str().unwrap_or("").replace("{{ownPort}}", &own_port.to_string());
            let timeout = Duration::from_millis(http["readTimeoutMillis"].as_u64().unwrap_or(20_000));
            let method = http["method"].as_str().unwrap_or("PUT").to_string();
            let path = http["path"].as_str().expect("http.path").to_string();
            // `"background": label`: sent on a thread of its own, its answer checked by `expect.background`
            if let Some(label) = http["background"].as_str() {
                background.insert(label.to_string(), std::thread::spawn(move || plain_http_as(port, own, &method, &path, &body, timeout)));
                continue;
            }
            let answer = match http.get("clientCertificate") {
                Some(client) => {
                    let (cert, key) = (client["cert"].as_str().expect("clientCertificate.cert"), client["key"].as_str().expect("clientCertificate.key"));
                    https_as(port, own, &method, &path, &body, timeout, (cert, key))
                }
                None => plain_http_as(port, own, &method, &path, &body, timeout),
            };
            if let Some(want) = http["expectStatus"].as_u64() {
                assert!(answer.starts_with(&format!("HTTP/1.1 {want}")), "{} ({target}): http step {} {} answered {answer:?}; log so far:\n{}", file.display(), http["method"], http["path"], handle.combined_log());
            }
            if let Some(want) = http["expectBodyContains"].as_str() {
                assert!(answer.contains(want), "{}: http step {} {} answered {answer:?}, want {want:?} in it", file.display(), http["method"], http["path"]);
            }
            if let Some(label) = http["compareBody"].as_str() {
                compare_body(file, scenario, label, &answer, &scratch, mode, target);
            }
        } else if let Some(bytes) = step["tcp"].as_str() {
            let port = host_port(&handle).expect("a tcp step needs a started server");
            raw_tcp(port, bytes);
        } else if let Some(ms) = step["awaitAnswerMillis"].as_u64() {
            // A server whose last console line comes before its listener binds (`disableSystemOut`: the
            // property file dump, then nothing) is ready once a `PUT /mockserver/status` gets any HTTP answer. Docker's
            // port forward accepts and closes a connection before the container listens, so connecting proves nothing.
            let port = host_port(&handle).expect("an awaitAnswerMillis step needs a started server");
            let own = if matches!(handle, Handle::Binary { .. }) { port } else { 1080 };
            let deadline = Instant::now() + Duration::from_millis(ms);
            loop {
                let request = format!("PUT /mockserver/status HTTP/1.1\r\nHost: localhost:{own}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                let mut answer = String::new();
                if let Ok(mut tcp) = std::net::TcpStream::connect(("127.0.0.1", port)) {
                    let _ = tcp.set_read_timeout(Some(Duration::from_secs(2)));
                    if tcp.write_all(request.as_bytes()).is_ok() {
                        let _ = tcp.read_to_string(&mut answer);
                    }
                }
                if answer.starts_with("HTTP/") {
                    break;
                }
                assert!(Instant::now() < deadline, "{}: no HTTP answer within {ms} ms; log so far:\n{}", file.display(), handle.combined_log());
                std::thread::sleep(Duration::from_millis(250));
            }
        } else if let Some(ms) = step["sleepMillis"].as_u64() {
            std::thread::sleep(Duration::from_millis(ms));
        } else if let Some(ms) = step["exitWithinMillis"].as_u64() {
            // The process ends on its own within `ms` of the previous step
            let deadline = Instant::now() + Duration::from_millis(ms);
            while handle.running() {
                assert!(Instant::now() < deadline, "{}: still running {ms} ms after the previous step; log so far:\n{}", file.display(), handle.combined_log());
                std::thread::sleep(Duration::from_millis(50));
            }
        } else if let Some(spec) = step.get("certificate") {
            write_certificate(&scratch, spec);
        } else {
            panic!("{}: unknown afterReady step {step}", file.display());
        }
    }
    if scenario["afterReady"].as_array().is_some_and(|steps| steps.iter().any(|s| s["tls"].is_u64())) {
        // let the server's log lines for the last request land
        std::thread::sleep(Duration::from_millis(1500));
    }

    let expect = &scenario["expect"];
    let running = expect["running"].as_bool().expect("expect.running");
    let captured = handle.captured();
    // `expect.tls` {label: "served" | "refused"}: every request recorded under the label.
    for (label, want) in expect["tls"].as_object().into_iter().flatten() {
        let served = want.as_str() == Some("served");
        let seen = tls_outcomes.get(label).cloned().unwrap_or_default();
        assert!(
            !seen.is_empty() && seen.iter().all(|o| o.answered == served),
            "{}: expected the TLS requests {label:?} {want}, got {seen:?}\nstdout:\n{}",
            file.display(),
            captured.stdout
        );
    }
    // `expect.sameCertificate` [[a, b], ..] / `differentCertificate`: the last leaf certificate recorded under label a vs b.
    for (key, same) in [("sameCertificate", true), ("differentCertificate", false)] {
        for pair in expect[key].as_array().into_iter().flatten() {
            let last = |i: usize| pair[i].as_str().and_then(|l| tls_outcomes.get(l)).and_then(|v| v.last()).and_then(|o| o.certificate.clone());
            let (a, b) = (last(0), last(1));
            assert!(a.is_some() && b.is_some(), "{}: {key} {pair}: a label has no certificate ({tls_outcomes:?})", file.display());
            assert_eq!(a == b, same, "{}: {key} {pair}\nstdout:\n{}", file.display(), captured.stdout);
        }
    }
    // `expect.background` {label: {"answered": bool}}: whether a background http step got any answer.
    for (label, want) in expect["background"].as_object().into_iter().flatten() {
        let answer = background.remove(label).unwrap_or_else(|| panic!("{}: no background http step {label:?}", file.display())).join().expect("background http step");
        let answered = want["answered"].as_bool().expect("expect.background.<label>.answered");
        assert_eq!(!answer.is_empty(), answered, "{}: background request {label:?} answered {answer:?}", file.display());
    }
    // `expect.fileModes` {path: "rw-------"}: modes of files the server wrote into the scratch directory.
    for (path, want) in expect["fileModes"].as_object().into_iter().flatten() {
        let path = PathBuf::from(path.replace("{{scratch}}", &scratch.to_string_lossy()));
        assert_eq!(mode_string(&path).as_deref(), want.as_str(), "{}: mode of {}\nstdout:\n{}", file.display(), path.display(), captured.stdout);
    }
    // `expect.fileUnchanged` {path: content}: a file still holds exactly what the scenario wrote there.
    for (path, want) in expect["fileContent"].as_object().into_iter().flatten() {
        let path = PathBuf::from(path.replace("{{scratch}}", &scratch.to_string_lossy()));
        assert_eq!(fs::read_to_string(&path).ok().as_deref(), want.as_str(), "{}: content of {}", file.display(), path.display());
    }
    // `expect.fileLines` {path: [regex, ..]}: the file has exactly that many lines, each matching its regex
    // whole. A `*` in the path's file name stands for any text (one file must match), e.g. a date the server puts in
    // the name. The value may instead be `{"binary": [..], "oracleDocker": [..]}`, for lines that differ by design.
    // `{{serverPort}}` in a regex is the port the server listens on itself (1080 inside the oracle container).
    let own_port = match &handle {
        Handle::Binary { .. } => host_port(&handle).map(|p| p.to_string()).unwrap_or_default(),
        _ => "1080".to_string(),
    };
    for (path, want) in expect["fileLines"].as_object().into_iter().flatten() {
        let path = resolve_glob(&PathBuf::from(path.replace("{{scratch}}", &scratch.to_string_lossy())));
        let want = if want.is_object() { &want[target] } else { want };
        let patterns: Vec<String> = string_array(want).into_iter().map(|p| p.replace("{{serverPort}}", &own_port)).collect();
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {}: {e}", file.display(), path.display()));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), patterns.len(), "{}: {target} lines of {}:\n{text}", file.display(), path.display());
        for (line, pattern) in lines.iter().zip(&patterns) {
            let re = regex::Regex::new(&format!("^(?:{pattern})$")).expect("fileLines regex");
            assert!(re.is_match(line), "{}: {target} line {line:?} of {} does not match {pattern:?}", file.display(), path.display());
        }
    }
    // `expect.absentFiles` [path, ..]: no file matches the path, whose file name may hold `*` as in fileLines.
    for path in expected_strings(&expect["absentFiles"], &scratch) {
        let path = PathBuf::from(path);
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let pattern = regex::Regex::new(&format!("^{}$", name.split('*').map(regex::escape).collect::<Vec<_>>().join(".*"))).expect("glob");
        let dir = path.parent().expect("a directory");
        let found: Vec<PathBuf> = fs::read_dir(dir).into_iter().flatten().flatten().filter(|e| pattern.is_match(&e.file_name().to_string_lossy())).map(|e| e.path()).collect();
        assert!(found.is_empty(), "{}: {target} wrote {found:?}, expected no file matching {}", file.display(), path.display());
    }
    // the stdout string assertions read the format-neutral console view
    let console = console_view(&captured.stdout);
    // `expect.stdoutOccurrences` {needle: n}: the exact number of times a string occurs in stdout.
    for (needle, n) in expect["stdoutOccurrences"].as_object().into_iter().flatten() {
        let needle = needle.replace("{{scratch}}", &scratch.to_string_lossy());
        assert_eq!(console.matches(&needle).count() as u64, n.as_u64().expect("count"), "{}: occurrences of {needle:?}\nstdout (console view):\n{console}", file.display());
    }
    if mode == Mode::Record && !running {
        eprintln!("{}: oracle exit code {:?}, expect.exitCode is {:?}", file.display(), handle.exit_code(), expect["exitCode"].as_i64());
    }
    if running {
        assert!(handle.running(), "{}: expected the process still running, but it exited\nstdout:\n{}\nstderr:\n{}", file.display(), captured.stdout, captured.stderr);
    } else {
        let code = handle.exit_code();
        let want = expect["exitCode"].as_i64().map(|c| c as i32);
        assert_eq!(code, want, "{}: exit code\nstdout:\n{}\nstderr:\n{}", file.display(), captured.stdout, captured.stderr);
    }
    if expect["compareOutput"].as_bool() == Some(true) {
        for (stream, text) in [("stdout", &captured.stdout), ("stderr", &captured.stderr)] {
            let got = normalise_output(text, scenario);
            let path = golden_path(file, stream);
            if mode == Mode::Record {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, &got).unwrap();
            } else {
                let want = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: golden {}: {e}", file.display(), path.display()));
                // a golden recorded before analytics values were normalised holds the image's analytics endpoint and key: read as ours
                let want = image_analytics::as_ours(&want).into_owned();
                // `skips-rs.txt`: a listed output that does not match the oracle yet, a to-do that must
                // still differ.
                let name = file.file_stem().unwrap().to_string_lossy();
                if let Some(reason) = output_skips().get(&(name.to_string(), stream.to_string())) {
                    assert_ne!(got, want, "{}: {target} {stream} matches now: remove it from skips-rs.txt ({reason})", file.display());
                    continue;
                }
                assert_eq!(got, want, "{}: {target} {stream} differs from {}", file.display(), path.display());
            }
        }
    }
    // `stdoutInOrder`: each string occurs, the first after the start and every next one after the previous.
    let mut from = 0;
    for needle in expected_strings(&expect["stdoutInOrder"], &scratch) {
        match console[from..].find(&needle) {
            Some(at) => from += at + needle.len(),
            None => panic!("{}: stdout lacks {needle:?} after offset {from} (in order)\nstdout (console view):\n{console}", file.display()),
        }
    }
    for needle in expected_strings(&expect["stdoutContains"], &scratch) {
        assert!(console.contains(&needle), "{}: stdout missing {needle:?}\nstdout (console view):\n{console}", file.display());
    }
    for needle in expected_strings(&expect["stdoutNotContains"], &scratch) {
        assert!(!console.contains(&needle), "{}: stdout unexpectedly contains {needle:?}\nstdout (console view):\n{console}", file.display());
    }
    let errors = console_view(&captured.stderr);
    for needle in expected_strings(&expect["stderrContains"], &scratch) {
        assert!(errors.contains(&needle), "{}: stderr missing {needle:?}\nstderr (console view):\n{errors}", file.display());
    }
    for needle in expected_strings(&expect["stderrNotContains"], &scratch) {
        assert!(!errors.contains(&needle), "{}: stderr unexpectedly contains {needle:?}\nstderr (console view):\n{errors}", file.display());
    }

    // A "binary" target's cwd is the scratch directory `launch` made for it, never the repository
    // root, however the child behaves. Guard that invariant here (not just by construction) so a future change
    // to `launch` that drops `.current_dir(...)` fails loudly instead of quietly reintroducing the leak.
    let binary_cwd = if let Handle::Binary { cwd, .. } = &handle { Some(cwd.clone()) } else { None };
    if let Some(cwd) = &binary_cwd {
        let leaked = root_ca_snapshot();
        assert!(
            leaked == root_before,
            "{}: the binary changed {leaked:?} (before: {root_before:?}) in the repository root; it should have landed in its scratch cwd {} instead",
            file.display(),
            cwd.display()
        );
        // Opt-in positive proof (`"expect": {"caCertificateInCwd": true}`) that the write actually happened,
        // relative to the child's own cwd, the same way the oracle writes it relative to *its* cwd (confirmed
        // live: a bare `mockserver/mockserver:8.0.0` container logs `CA certificate: <home>/mockserver-
        // ca.pem` on every default start, `<home>` being the image's `WorkingDir`).
        if expect["caCertificateInCwd"].as_bool() == Some(true) {
            let ca = cwd.join("mockserver-ca.pem");
            assert!(
                ca.exists(),
                "{}: expected {} to exist (proxySetupLogging should have written the CA certificate there)\nstdout:\n{}\nstderr:\n{}",
                file.display(),
                ca.display(),
                captured.stdout,
                captured.stderr
            );
        }
    }

    drop(handle);
    let _ = fs::remove_dir_all(&scratch);
    if let Some(p) = property_file {
        let _ = fs::remove_file(p);
    }
    if let Some(cwd) = binary_cwd {
        let _ = fs::remove_dir_all(cwd);
    }
}

#[test]
fn process_scenarios_match_expectations() {
    let files = scenario_files();
    assert!(!files.is_empty(), "no files under {}", scenarios_dir().display());
    for file in files {
        let scenario: Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        run_scenario(&file, &scenario);
    }
}

/// Every property of upstream's `ConfigurationProperties` (its `MOCKSERVER_*` constants: the value is the
/// system-property and properties-file key, the name the environment variable) is set by some process scenario,
/// through `-D`, `env` or `propertyFile`, or is listed in `tests/process_scenarios/config_properties.txt` with the
/// reason no process scenario sets it. A listed name must be a property. `conformance/config_properties.py tally`
/// counts the same.
#[test]
fn every_configuration_property_is_set_by_a_process_scenario_or_listed() {
    let java = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("upstream/mockserver/mockserver/mockserver-core/src/main/java/org/mockserver/configuration/ConfigurationProperties.java"),
    )
    .expect("ConfigurationProperties.java (git submodule update --init upstream/mockserver)");
    let constant = regex::Regex::new(r#"String (MOCKSERVER_[A-Z_0-9]+) = "(mockserver\.[^"]+)""#).unwrap();
    // the javadoc's placeholder, not a property
    let properties: Vec<(String, String)> = constant.captures_iter(&java).map(|c| (c[2].to_string(), c[1].to_string())).filter(|(p, _)| p != "mockserver.xxx").collect();
    assert!(properties.len() > 300, "found only {} properties", properties.len());
    let by_env: HashMap<&str, &str> = properties.iter().map(|(p, e)| (e.as_str(), p.as_str())).collect();
    let system_property = regex::Regex::new(r"^-D(mockserver\.[A-Za-z0-9]+)=").unwrap();
    let file_key = regex::Regex::new(r"^\s*(mockserver\.[A-Za-z0-9]+)\s*[=:]").unwrap();
    let mut set = std::collections::HashSet::new();
    for path in fs::read_dir(scenarios_dir()).unwrap().map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|e| e == "json")) {
        let scenario: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        set.extend(string_array(&scenario["args"]).iter().filter_map(|a| system_property.captures(a)).map(|c| c[1].to_string()));
        set.extend(string_map(&scenario["env"]).keys().filter_map(|k| by_env.get(k.as_str())).map(|p| p.to_string()));
        set.extend(scenario["propertyFile"].as_str().unwrap_or("").lines().filter_map(|l| file_key.captures(l)).map(|c| c[1].to_string()));
    }
    let listed: HashMap<String, String> = fs::read_to_string(scenarios_dir().join("config_properties.txt"))
        .expect("config_properties.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (name, reason) = l.split_once(' ').unwrap_or((l, ""));
            assert!(!reason.trim().is_empty(), "config_properties.txt: {name} has no reason");
            (name.to_string(), reason.trim().to_string())
        })
        .collect();
    for name in listed.keys() {
        assert!(properties.iter().any(|(p, _)| p == name), "config_properties.txt lists {name}, which is not a ConfigurationProperties property");
    }
    let missing: Vec<&str> = properties.iter().map(|(p, _)| p.as_str()).filter(|p| !set.contains(*p) && !listed.contains_key(*p)).collect();
    assert!(missing.is_empty(), "properties no process scenario sets and config_properties.txt does not list: {missing:?}");
}

/// A `pickPort` binary whose port another process took first exits on the failed bind, with logging or
/// `System.out` disabled too, and [`lost_picked_port`] sees it (so the runner launches it again); one on a free port
/// is not taken for lost.
#[test]
fn a_binary_that_lost_its_picked_port_is_seen() {
    let scratch = scratch_cwd();
    for env in ["MOCKSERVER_DISABLE_LOGGING", "MOCKSERVER_DISABLE_SYSTEM_OUT"] {
        let taken = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        let scenario = serde_json::json!({"args": ["-serverPort", port.to_string()], "env": {env: "true"}});
        let (mut handle, _) = launch(&scenario, "binary", &scratch);
        if let Handle::Binary { picked, .. } = &mut handle {
            *picked = Some(port);
        }
        assert!(lost_picked_port(&mut handle, Instant::now() + Duration::from_secs(20)), "{env}: log:\n{}", handle.combined_log());
        drop(taken);
        let scenario = serde_json::json!({"args": ["-serverPort", "{{serverPort}}"], "pickPort": true, "env": {env: "true"}});
        let (mut handle, _) = launch(&scenario, "binary", &scratch);
        assert!(!lost_picked_port(&mut handle, Instant::now() + Duration::from_secs(20)), "{env}: log:\n{}", handle.combined_log());
        assert!(handle.running(), "{env}: log:\n{}", handle.combined_log());
    }
}

/// The category-C inventories `conformance/category-c/<area>/<Class>.txt` list every `@Test` of the upstream
/// class their first line names (`# <package>.<Class> (<module>): …`) exactly once, and every reference resolves: a
/// `process:` scenario here, an `http:` scenario under `tests/scenarios/`, a `rust:<file>::<fn>` function. An `n/a` or
/// `gap` line gives its reason after `#`.
#[test]
fn category_c_inventories_cover_every_upstream_test() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let header = regex::Regex::new(r"^# ([\w.]+)\.(\w+) \(([\w-]+)\):").unwrap();
    let test = regex::Regex::new(r"@Test(?:\([^)]*\))?\s+public\s+void\s+(\w+)\s*\(").unwrap();
    let mut inventories: Vec<PathBuf> = fs::read_dir(root.join("conformance/category-c"))
        .expect("conformance/category-c")
        .flat_map(|area| fs::read_dir(area.unwrap().path()).unwrap())
        .map(|f| f.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .collect();
    inventories.sort();
    assert!(!inventories.is_empty());
    let mut problems = Vec::new();
    for inventory in inventories {
        let text = fs::read_to_string(&inventory).unwrap();
        let name = inventory.strip_prefix(&root).unwrap().display().to_string();
        let Some(h) = text.lines().next().and_then(|l| header.captures(l)) else {
            problems.push(format!("{name}: the first line must be `# <package>.<Class> (<module>): ...`"));
            continue;
        };
        let source = root.join("upstream/mockserver/mockserver").join(&h[3]).join("src/test/java").join(h[1].replace('.', "/")).join(format!("{}.java", &h[2]));
        let java = fs::read_to_string(&source).unwrap_or_else(|e| panic!("{name}: {}: {e}", source.display()));
        let upstream: Vec<String> = test.captures_iter(&java).map(|c| c[1].to_string()).collect();
        let mut listed = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
            let (entry, note) = line.split_once('#').map_or((line, ""), |(e, n)| (e, n.trim()));
            let (method, refs) = entry.trim().split_once(char::is_whitespace).unwrap_or((entry.trim(), ""));
            listed.push(method.to_string());
            let refs = refs.trim();
            if refs == "n/a" || refs == "gap" {
                if note.is_empty() {
                    problems.push(format!("{name}: {method}: {refs} without a reason"));
                }
                continue;
            }
            if refs.is_empty() {
                problems.push(format!("{name}: {method}: no reference"));
            }
            for r in refs.split(',').map(str::trim) {
                let found = if let Some(s) = r.strip_prefix("process:") {
                    scenarios_dir().join(format!("{s}.json")).is_file()
                } else if let Some(s) = r.strip_prefix("http:") {
                    root.join("tests/scenarios").join(format!("{s}.json")).is_file()
                } else if let Some((file, function)) = r.strip_prefix("rust:").and_then(|s| s.split_once("::")) {
                    fs::read_to_string(root.join(file)).is_ok_and(|src| src.contains(&format!("fn {function}(")))
                } else {
                    false
                };
                if !found {
                    problems.push(format!("{name}: {method}: {r} does not resolve"));
                }
            }
        }
        for method in &upstream {
            match listed.iter().filter(|m| *m == method).count() {
                1 => {}
                n => problems.push(format!("{name}: {method} listed {n} times")),
            }
        }
        for method in listed.iter().filter(|m| !upstream.contains(m)) {
            problems.push(format!("{name}: {method} is not a @Test of {}", &h[2]));
        }
    }
    assert!(problems.is_empty(), "category-C inventories:\n{}", problems.join("\n"));
}

/// The oracle image pinned in `oracle.env`; `"oracleImage": "http3"` picks the HTTP/3 one, the
/// only image with the QUIC native.
fn oracle_image(scenario: &Value) -> &'static str {
    let key = match scenario["oracleImage"].as_str() {
        None => "ORACLE_IMAGE=",
        Some("http3") => "ORACLE_HTTP3_IMAGE=",
        Some(other) => panic!("unknown oracleImage {other:?} (want \"http3\")"),
    };
    include_str!("../oracle.env").lines().find_map(|line| line.strip_prefix(key)).unwrap_or_else(|| panic!("oracle.env has no {key}"))
}

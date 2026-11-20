//! Differential conformance against the MockServer oracle, pinned in `oracle.env`.
//!
//! Each `tests/scenarios/<name>.json` is a list of HTTP steps. With `MOCK_SERVER_RECORD_ORACLE=http://host:port`
//! (a running `ORACLE_IMAGE` of `oracle.env` whose container port is 1080) the steps are sent to the oracle and its
//! answers written to `<name>.golden.json`. Without it, the steps are replayed against an in-process mock-server and
//! compared with the goldens.
//!
//! Replay is concurrent: the top-level scenarios over `MOCK_SERVER_REPLAY_WORKERS` servers (see
//! [`replay_workers`]), the harvested files over 8, both tests at once; a scenario that reaches process-wide state
//! replays alone (see [`process_wide`]). Recording is one scenario at a time against the one oracle.
//!
//! Placeholders in step paths, headers and bodies:
//! - `{{host}}`: an address the server treats as itself (`localhost:<its own port>`), the default `Host`;
//! - `{{deadhost}}`: a foreign address nothing listens on, which is what a Testcontainers-mapped port looks like
//!   from inside the container (see [`dead_host`]/[`dead_port`] for how that is kept true with several worktrees
//!   running at once);
//! - `{{deadport}}`: only the port of `{{deadhost}}`, for a `host` and `port` given separately; in a JSON body a number
//!   is written `"port": "{{deadport}}"` (the quoted placeholder becomes a bare number);
//! - `{{bindport:N}}`: a port to bind in place of the fixed `N`, quoted in a JSON body the same way; a
//!   replay that loses one to another process is replayed again with fresh ports ([`lost_bind_ports`]);
//! - `{{port}}`: the port the server listens on (inside its container), for expectations that forward to itself;
//! - `{{ownport}}`: in a startup value (`"properties"`), the same port, known before the server starts;
//! - `{{files}}`: the absolute path of `tests/files`, which `make oracle` mounts at the same path in the container;
//! - `{{root}}`: the absolute path of the checkout. Answers get it back in its place (see [`normalise`]), so goldens
//!   hold no checkout path and replay in any checkout.
//!
//! `"properties": {"name": "value", …}` on a scenario starts the server with those `mockserver.*` properties
//! (`{{files}}` allowed in values): recorded from an oracle container of its own, replayed on a server of its own.
//!
//! `"env": {"MOCKSERVER_X": "value"}` and `"propertiesFile": [lines]` start that same server with those
//! environment variables and that properties file (a string, or an array of lines): `docker run -e` and a file mounted at
//! `/config/mockserver.properties` for the oracle, `Config::with_env` and `Config::with_property_file_text` on replay.
//! `"jvmOptions": ["-Dio.netty.maxDirectMemory=8388608"]` adds JVM options to the oracle's
//! `JDK_JAVA_OPTIONS` (after its pinned processors and heap) and, on replay, to the same variable of our `Config`.
//! Either alone also gives the scenario a server of its own; `{{files}}`, `{{scratch}}`, `{{deadhost}}`, `{{deadport}}`
//! are substituted as in `"properties"`.
//!
//! `"peer": true` on a scenario with `"properties"` starts a second, plain node next to the scenario's server and
//! substitutes its address for `{{peerurl}}` (`{{peerhttpsurl}}`: the same over `https`) in the properties (a cluster fan-in peer): an oracle container
//! reached over the Docker bridge when recording, a mock-server server on replay. A step with `"node": "peer"`
//! is sent to that node instead; it starts empty, and the scenario's `reset` covers only the first node.
//! `"peerProperties": {…}` starts that node with those `mockserver.*` properties (a proxy that demands credentials).
//! `"peerNetwork": "shared"` runs the peer in the first node's network namespace, so `{{peerurl}}` names it as
//! `localhost` (a dotless host, which a JDK client names in no SNI); see [`shared_peer_network`].
//! `{{peeraddress}}` in a step is the `host:port` the first node reaches the peer at (a `Host` header that makes the
//! first node proxy to it); `{{peeripaddress}}` is the same with an IP address for the host (replay's `localhost` as
//! `127.0.0.1`: a TLS name check differs between a name and an address). `{{peerhost}}` and `{{peerport}}` are the same address split (`proxyRemoteHost`/`proxyRemotePort`, which the replay
//! turns into the server's port forwarding, as `Main` does: a proxied binary exchange needs an upstream that answers).
//!
//! `"image": "clustered"` on a scenario with `"properties"` records it on the oracle's clustered variant (Infinispan,
//! `stateBackend=infinispan`) instead of the standard image, and `recordedFrom` names the image.
//!
//! `"startupLog": true` on a scenario with `"properties"` skips its opening `reset`, for entries logged at startup.
//!
//! `"warmEventLoops": true` on a scenario with `"properties"` replays it on a server whose worker event loops have each
//! handled an HTTP request, as a shared server's are ([`warm_event_loops`]): a property-scoped oracle container is
//! reached by readiness polls and the Docker port proxy's probes before the first step, so an entry logged on a
//! connection's loop outside any request (`GrpcToHttpRequestHandler`'s `gRPC request error`) carries the port there.
//!
//! `"isolated": true` on a scenario marks state that `reset` does not clear (bound ports, configuration: see
//! [`scenarios_changing_configuration_replay_on_their_own_server`], the forward connection pool: see
//! [`scenarios_logging_forward_timing_have_their_own_oracle`]): it is replayed on a server of its own (a harvested file
//! too) and recorded after every other scenario — still on the shared oracle, unless it has `"properties"`.
//!
//! `"settleMillis": n` on a scenario that gives up on a delayed answer makes the recorder wait `n` ms after
//! its last step before the next file on the shared oracle, which reports nothing about requests in progress; replay
//! fails a file that keeps its shared server busy past its last step without declaring it (see [`settle_millis`]).
//!
//! A step's `"capture": {"header": name, "as": key}` keeps that response header's value, which later steps use as
//! `{{capture:key}}` (an MCP session id, say); `"capture": {"body": true, "as": key}` keeps the whole body (an
//! exported document to import again); `"capture": {"bodyRegex": regex, "as": key}` keeps the regex's first capture
//! group from the body (a correlation id out of a log entry). A list of `bodyRegex`/`headerRegex` specs keeps several
//! values from one answer (see [`capture_list`]).
//!
//! A step's `"h2": true` sends it as HTTP/2 with prior knowledge over cleartext TCP, through the `h2`
//! crate directly, so nothing is added or dropped on the way: `:authority` is `{{host}}`, and the headers are exactly
//! the step's (no automatic `content-length`, `transfer-encoding` allowed). The response is shaped as for HTTP/1.1,
//! and `"trailers": true` also lists its HTTP/2 trailers (see [`send_h2`]). Its `"dataFrames": [base64, …]` sends
//! the body as one DATA frame per entry (`{"base64": …, "repeat": n}` is n of them), for frame boundaries a decoder must reassemble across (see [`data_frames`]).
//!
//! A step's `"h2raw": {"headers": [[name, value], …], "body": text}` writes hand-built HTTP/2 frames (see
//! [`send_h2raw`]) and records the frames that come back as readable lines.
//!
//! A step's `"trailers": true` records the response's HTTP/1.1 trailers (chunked trailer fields) as well.
//!
//! A step's `"binaryBody": true` records the response body as base64 (see [`binary_body`]).
//!
//! An `"h3": true` step sends the step as one HTTP/3 request to the server's `http3Port` (a scenario with
//! `"quic": true`) and records the request stream's raw frames (see [`send_h3`]).
//!
//! A `"udp": base64` step sends that datagram to the server's DNS listener (a scenario with `dnsEnabled` and a fixed
//! `dnsPort` in its properties) and records the answer (see [`send_udp`]). A `"tcp": [base64, …]` step writes raw
//! bytes (a SOCKS handshake, say) to the server's port and records what comes back (see [`send_tcp`]); its `"mask"`
//! applies to that base64 answer, and its `"minMillis"` to the time until the server closed the connection; with
//! `"text": true` the answer is recorded as text (`tcpText`), for header order, which the other steps sort away; with
//! `"tls": true` the bytes go through a TLS client (any certificate trusted, ALPN `http/1.1`) first, e.g. a CONNECT
//! sent over TLS.
//!
//! A step's `"decodeBase64": regex` decodes the base64 in the regex's first capture group before normalising and
//! masking (see [`decode_base64`]); `"decodeJwt": true` decodes the claims of each JWT in the answer (see [`decode_jwts`]). A step's `"mask": [regex, …]` blanks out values that differ run to run (see [`mask`]); `"minMillis": n` asserts
//! (when recording and when replaying) that the answer took at least `n` milliseconds, for delays.
//!
//! A step's `"diverge": {"row": …, "status": n, "contains": […], "lacks": […]}` marks an answer an adopted post-8.0.0
//! upstream fix changes: recording keeps the oracle's answer in the golden, replay checks ours against the
//! step's status and body texts instead, and `row` must name a `docs/divergences.md` row (see [`diverged`]); also
//! `"headers"`/`"lacksHeaders"` (whole header lines) and, for a `tcp` step (whose answer is its body), `"closed"`.
//!
//! A step's `"compare": "status"` marks a body as a recorded divergence (`docs/divergences.md`): only its status
//! is checked. `"compare": "json"` is for a body whose object key order the oracle does not keep stable (a Java
//! `HashMap` keyed by identity-hashed enums, or fields collected in parallel): status, headers and the body,
//! parsed as JSON, must still agree, key order aside — and, recursively, so must any string value found anywhere
//! in that JSON that itself looks like a JSON object/array (see [`deep_parse_embedded_json`]), which is how an
//! MCP `tools/call` response's `"text"` field — a JSON document embedded as a string — gets the same tolerance.
//! `"compare": "unordered"` is for a log whose entries racing threads write in either order: status, headers and
//! the body's entries as a multiset (see [`unordered_body`]).
//!
//! A `"readFile": path` step (placeholders substituted, `{{scratch}}` included) reads that file and records
//! `{"fileContent": <normalised text>}` (`null` if it does not exist yet) — for asserting what the server wrote
//! to `persistedExpectationsPath` (see [`read_file`]). A `"writeFile": {"path": …, "content": …}` step (both
//! substituted) writes `content` to `path`, creating parent directories as needed, and records `{"wrote": true}`
//! — for simulating an external edit of a watched file (see [`write_file`]). A `"deleteFile": path` step removes a
//! file (an absent one is fine) and records `{"deleted": true}` (see [`delete_file`]); a `"listFiles": path` step
//! records the names a `*` pattern matches (see [`list_files`]); a `readFile` step takes `"mask"`
//! like any step, applied to its `fileContent`. `{{scratch}}` is a writable
//! directory (`target/scratch`, unlike the read-only `{{files}}`), bind-mounted at the same absolute path into
//! a `"properties"`-scoped oracle container, so a `persistedExpectationsPath` under it is written by the
//! container and read back by the test process at the identical path.
//!
//! A step's `"pipelinePut": true` writes it and the step right after it onto the same connection in
//! one `write_all`, before reading either response — real HTTP/1.1 pipelining, not two round trips. A step racing
//! a server-side real-time timer (e.g. a scenario's `transitionAfterMs`) cannot be made to win that race reliably
//! by trimming milliseconds off an ordinary two-round-trip exchange; a loaded machine can always delay it past
//! the deadline. Pipelining removes the client-side round trip between the two requests entirely (both are on
//! the wire, and usually in the server's read buffer together, before either response comes back), leaving only
//! the server's own back-to-back handling of them as the real-time budget the timer has to beat (see
//! [`send_pipelined`]). `"pipeline": n` does the same for the n steps starting at it, e.g. a token bucket's
//! acquisitions that the upstream test makes at one instant of its own clock; each pipelined step's `"mask"` applies.
//!
//! WebSocket steps (see [`Session::step`]): `"wsOpen": name` upgrades a connection on `"path"` (default the
//! callback WebSocket, `/_mockserver_callback_websocket`; `"headers"` such as `X-CLIENT-REGISTRATION-ID` fix the client
//! id) and keeps it under `name`; `"wsRead": name` records the next text message (a callback envelope as its `type` and
//! its `value` as the body; `"until"` skips messages that do not match, `"waitMillis"` bounds the wait and a silent socket
//! records `"timeout": true`); `"wsSend": name` sends `"text"`, `"binary"` (base64) or an `"envelope"` (`{"type",
//! "value"}`, the value sent as a JSON string); `"wsClose": name` closes it. An HTTP step with `"async": key` is sent
//! without waiting for its answer (a request a breakpoint holds answers only after the client's decision), and
//! `{"await": key}` records that answer where it stands. With `"capture"` on a `wsRead` (`bodyRegex`, or `body` for the
//! whole held request; or the list form), a later step uses `{{capture:key}}`. `"wsDrain": name` discards what
//! arrives within `"waitMillis"` without recording it or its count (the dashboard's racy pushes), or until a message
//! matches `"until"`; `"countSkipped": false` on a `wsRead` leaves out its `"skipped"` count.
//!
//! `tests/scenarios/upstream/` holds category-B cases harvested from mockserver-core's own tests (`conformance/harvest`). Their steps carry a `"case"` id; a case passes when all its steps match. They are
//! recorded twice, and a case the oracle answers differently the second time is kept out of the comparison
//! (`"unstable"` in the golden). `skips-rs.txt` lists the ids of cases that do not match yet, each with its reason;
//! a listed case that starts matching must be removed from it. A harvested file with `"properties"` is recorded on
//! an oracle container started with them and replayed on a server of its own, like a top-level scenario. Per-case results go to
//! `target/upstream-scenario-results.tsv`, the first difference of each non-matching case to
//! `target/upstream-scenario-diffs.txt`; a `MOCK_SERVER_SCENARIO` replay merges its files' rows into both and says
//! so on their first line ([`write_upstream_results`]).


#[path = "support/scratch_cwd.rs"]
mod scratch_cwd;
#[path = "support/tcp_port.rs"]
mod tcp_port;
#[path = "support/udp_port.rs"]
mod udp_port;
#[path = "support/h3_step.rs"]
mod h3_step;
#[path = "support/docker_bind.rs"]
mod docker_bind;
#[path = "support/image_analytics.rs"]
mod image_analytics;

use tcp_port::{dead_port, pick_refusing_port, port_refuses};

use std::fs;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use futures_util::FutureExt;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use serde_json::{Map, Value, json};
use tokio::net::TcpStream;

/// Headers whose values legitimately differ between oracle and mock-server (see `docs/divergences.md`).
const IGNORED_HEADERS: &[&str] = &["date"];

#[derive(Clone)]
struct Target {
    addr: String,
    host: String,
    deadhost: String,
    port: u16,
    /// Where `"udp"` steps send their datagrams (the DNS listener), when the server has one.
    udp: Option<Udp>,
    /// Where `"h3"` steps send their requests (the HTTP/3 listener), when the server has one.
    http3: Option<Udp>,
    /// `{{peeraddress}}` in a step: `host:port` at which the scenario's first node reaches its
    /// `"peer": true` node — the peer container's Docker bridge address when recording, `localhost:<port>` of the
    /// replayed peer. Empty without a peer.
    peer_address: String,
    /// The replayed ports of a `"peer": true` scenario's two nodes, each masked like the server's own in the other's
    /// answers (what a proxy node records names the forwarding node's port). Empty without a peer.
    node_ports: Vec<u16>,
    /// Values kept by steps' `capture`, by key: one map per scenario run (see [`run_scenario_with_peer`]), shared by
    /// the run's two nodes, so scenarios replayed at the same time never read each other's.
    captures: Captures,
    /// The replayed server itself, for a `"sleepMillis"` step with `"awaitIdle": true`; `None` when
    /// recording (the oracle reports no requests in progress) and for the harvested files' servers.
    server: Option<std::sync::Weak<mock_server::Server>>,
}

type Captures = std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>;

impl Target {
    /// A server reached at `addr` that calls itself `host`, listening on `port` (inside its container, for the
    /// oracle), with no DNS listener, no peer and no captures yet.
    fn new(addr: String, host: String, port: u16) -> Target {
        Target { addr, host, deadhost: dead_host(), port, udp: None, http3: None, peer_address: String::new(), node_ports: Vec::new(), captures: Captures::default(), server: None }
    }

    /// An in-process replay server on `127.0.0.1:port`.
    fn local(port: u16) -> Target {
        Target::new(format!("127.0.0.1:{port}"), format!("localhost:{port}"), port)
    }

    /// An oracle container published at `addr` (its port inside the container is 1080).
    fn oracle(addr: String) -> Target {
        Target::new(addr, "localhost:1080".into(), 1080)
    }

    /// `Target::local` for a replay server the harness holds, so `"awaitIdle"` can see its requests in flight.
    fn replayed(server: &std::sync::Arc<mock_server::Server>) -> Target {
        Target { server: Some(std::sync::Arc::downgrade(server)), ..Target::local(server.ports()[0]) }
    }
}

/// A UDP listener of the server under test.
#[derive(Clone)]
enum Udp {
    /// On this host.
    Local(String),
    /// Inside an oracle container, on this port: Docker on macOS forwards no UDP to published ports, so datagrams are
    /// sent from a sidecar container sharing the oracle's network namespace (`MOCK_SERVER_UDP_IMAGE`, a Python
    /// image, default `python:3-alpine`).
    Container { id: String, port: u16 },
}

/// The sidecar's sender: one datagram (base64) to `host:port`, the answer (base64) or `-` on stdout.
const UDP_SCRIPT: &str = "import socket,sys,base64\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.settimeout(2)\ns.sendto(base64.b64decode(sys.argv[3]),(sys.argv[1],int(sys.argv[2])))\ntry: print(base64.b64encode(s.recvfrom(65535)[0]).decode())\nexcept socket.timeout: print('-')\n";

/// A `"udp": base64` step: the datagram sent to the server's UDP listener, and the answer, base64-encoded, or
/// `"no answer"` after two seconds of silence.
async fn send_udp(t: &Target, step: &Value) -> Value {
    use base64::Engine;
    let datagram = step["udp"].as_str().expect("udp: base64");
    let answer = match t.udp.as_ref().expect("a udp step needs a server with a UDP listener (dnsEnabled)") {
        Udp::Local(addr) => {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
            socket.send_to(&base64::engine::general_purpose::STANDARD.decode(datagram).expect("udp base64"), addr).await.expect("send udp");
            let mut buf = vec![0u8; 65535];
            match tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf)).await {
                Ok(Ok(n)) => Some(base64::engine::general_purpose::STANDARD.encode(&buf[..n])),
                _ => None,
            }
        }
        Udp::Container { id, port } => {
            let image = std::env::var("MOCK_SERVER_UDP_IMAGE").unwrap_or_else(|_| "python:3-alpine".into());
            let out = std::process::Command::new("docker")
                .args(["run", "--rm", "--name", &container_name("udp"), "--network", &format!("container:{id}"), &image, "python", "-c", UDP_SCRIPT, "127.0.0.1", &port.to_string(), datagram])
                .output()
                .expect("docker run (udp sidecar)");
            assert!(out.status.success(), "udp sidecar: {}", String::from_utf8_lossy(&out.stderr));
            let answer = String::from_utf8_lossy(&out.stdout).trim().to_string();
            (answer != "-").then_some(answer)
        }
    };
    json!({"udp": answer.unwrap_or_else(|| "no answer".into())})
}

/// The `"h3"` sidecar's image: `MOCK_SERVER_H3_IMAGE`, else `mock-server-h3client` (`python:3-alpine` with
/// aioquic), built here once when absent.
fn h3_image() -> String {
    if let Ok(image) = std::env::var("MOCK_SERVER_H3_IMAGE") {
        return image;
    }
    static BUILT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let image = "mock-server-h3client".to_string();
            let present = std::process::Command::new("docker").args(["image", "inspect", &image]).output().is_ok_and(|o| o.status.success());
            if !present {
                use std::io::Write;
                let mut build = std::process::Command::new("docker")
                    .args(["build", "-q", "-t", &image, "-"])
                    .stdin(std::process::Stdio::piped())
                    .spawn()
                    .expect("docker build (h3 sidecar)");
                let dockerfile = "FROM python:3-alpine\nRUN pip install --no-cache-dir --root-user-action=ignore aioquic==1.3.0\n";
                build.stdin.take().unwrap().write_all(dockerfile.as_bytes()).unwrap();
                assert!(build.wait().expect("docker build (h3 sidecar)").success(), "docker build of {image} failed");
            }
            image
        })
        .clone()
}

/// An `"h3": true` step: the step's `method`, `path`, `headers` and body sent as one HTTP/3 request on a
/// fresh QUIC connection to the server's `http3Port` (a scenario with `"quic": true`), and the request stream's frames
/// read raw (see `tests/support/h3_step.rs`): `{"frames": ["HEADERS", "DATA", …], "status", "headers", "body",
/// "trailers", "end"}`. Consecutive DATA frames count as one (their split is timing); `status` and `headers` come from
/// a first HEADERS frame, `trailers` from a second; `end` is `fin`, `reset <code>`, `connection closed` or `timeout`
/// (after `maxMillis`, default 10 s). Recording sends it from a sidecar in the oracle's network namespace, since Docker
/// on macOS forwards no UDP.
async fn send_h3(t: &Target, step: &Value) -> Value {
    use base64::Engine;
    let timeout = step.get("maxMillis").and_then(Value::as_u64).map(Duration::from_millis).unwrap_or(Duration::from_secs(10));
    if let Some(streams) = step.get("streams").and_then(Value::as_array) {
        return send_h3_streams(t, step, streams, timeout).await;
    }
    let path = substitute(step["path"].as_str().expect("step.path"), t);
    let method = step["method"].as_str().unwrap_or("GET");
    let mut headers = Vec::new();
    if let Some(map) = step["headers"].as_object() {
        for (k, v) in map {
            for v in v.as_array().cloned().unwrap_or_else(|| vec![v.clone()]) {
                headers.push((k.clone(), substitute(v.as_str().unwrap(), t)));
            }
        }
    }
    let body = step_body(step, t);
    // `trailers` (an object, like `headers`): a trailer section after the body; `repeatHeader`: `[name,
    // value, count]`, that field count times after `headers` (sent compactly to the recording sidecar).
    let mut trailers = Vec::new();
    if let Some(map) = step.get("trailers").and_then(Value::as_object) {
        for (k, v) in map {
            trailers.push((k.clone(), substitute(v.as_str().expect("trailers: string values"), t)));
        }
    }
    let repeat = step.get("repeatHeader").and_then(Value::as_array).map(|r| {
        (r[0].as_str().expect("repeatHeader name").to_string(), r[1].as_str().expect("repeatHeader value").to_string(), r[2].as_u64().expect("repeatHeader count") as usize)
    });
    // `authority` (substituted): the request's `:authority`, e.g. a CONNECT-UDP target; default `localhost:<port>`.
    let authority = step.get("authority").and_then(Value::as_str).map(|a| substitute(a, t));
    // `closeError`: wait up to 2 s after the stream ended for the server to close the connection
    let close_wait = if step.get("closeError").and_then(Value::as_bool) == Some(true) { Duration::from_secs(2) } else { Duration::ZERO };
    // `stallMillis`: the client grants the stream 64 KiB and no more for that long, then reads as usual
    let stall = step.get("stallMillis").and_then(Value::as_u64).map(Duration::from_millis);
    let started = std::time::Instant::now();
    let exchange = match t.http3.as_ref().expect("an h3 step needs a server with an HTTP/3 listener (\"quic\": true and http3Port)") {
        Udp::Local(addr) => {
            let port: u16 = addr.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).expect("http3 port");
            let mut tls = (*trust_all_tls_client()).clone();
            tls.alpn_protocols.clear();
            let mut headers = headers;
            if let Some((name, value, count)) = &repeat {
                headers.extend(std::iter::repeat_n((name.clone(), value.clone()), *count));
            }
            let request = h3_step::Request { method, path: &path, authority: &authority.unwrap_or_else(|| format!("localhost:{port}")), headers, body, trailers, close_wait, stall };
            h3_step::exchange(port, tls, &request, timeout).await
        }
        Udp::Container { id, port } => {
            let spec = json!({
                "host": "127.0.0.1", "port": port, "method": method, "path": path, "authority": authority.unwrap_or_else(|| format!("localhost:{port}")),
                "headers": headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
                "body": base64::engine::general_purpose::STANDARD.encode(&body), "timeout": timeout.as_secs_f64(),
                "stall": stall.map(|s| s.as_secs_f64()),
                "trailers": trailers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
                "repeat": repeat.as_ref().map(|(n, v, c)| json!([n, v, c])),
                "closeWait": close_wait.as_secs_f64(),
            });
            let image = h3_image();
            let out = h3_sidecar(id, &image, &spec);
            assert!(out.status.success(), "h3 sidecar: {}", String::from_utf8_lossy(&out.stderr));
            serde_json::from_slice(&out.stdout).expect("h3 sidecar: JSON")
        }
    };
    if let Some(min) = step.get("minMillis").and_then(Value::as_u64) {
        let took = started.elapsed().as_millis() as u64;
        assert!(took >= min, "{}: the stream ended after {took} ms, expected at least {min} ms", step["note"]);
    }
    h3_result(t, step, &exchange)
}

/// Runs `tests/support/h3_step.py` in the oracle's network namespace with `spec` on its stdin (a body of megabytes
/// outgrows the argument list).
fn h3_sidecar(id: &str, image: &str, spec: &Value) -> std::process::Output {
    use std::io::Write;
    tokio::task::block_in_place(|| {
        let mut child = std::process::Command::new("docker")
            .args(["run", "-i", "--rm", "--name", &container_name("h3"), "--network", &format!("container:{id}"), image, "python", "-c", include_str!("support/h3_step.py"), "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("docker run (h3 sidecar)");
        child.stdin.take().expect("h3 sidecar: stdin").write_all(spec.to_string().as_bytes()).expect("h3 sidecar: stdin");
        child.wait_with_output().expect("docker run (h3 sidecar)")
    })
}

/// An `"h3"` step with `"streams": [{"method", "path", "headers", "body"}, …]`: each request on one QUIC
/// connection, the next sent 50 ms after the first bytes of the one before (see `h3_step::exchange_streams`);
/// `stallMillis` makes the client grant the connection 96 KiB and each stream 1 MiB and no more for that long, timed
/// from the first request. `{"streams": [<an h3 step's result>, …]}`, a stream's `body` kept only when it ended `fin`.
async fn send_h3_streams(t: &Target, step: &Value, streams: &[Value], timeout: Duration) -> Value {
    use base64::Engine;
    let stall = step.get("stallMillis").and_then(Value::as_u64).map(Duration::from_millis);
    let mut requests = Vec::new();
    for stream in streams {
        let mut headers = Vec::new();
        if let Some(map) = stream["headers"].as_object() {
            for (k, v) in map {
                for v in v.as_array().cloned().unwrap_or_else(|| vec![v.clone()]) {
                    headers.push((k.clone(), substitute(v.as_str().unwrap(), t)));
                }
            }
        }
        let method = stream["method"].as_str().unwrap_or("GET").to_string();
        let path = substitute(stream["path"].as_str().expect("streams[].path"), t);
        requests.push((method, path, headers, step_body(stream, t)));
    }
    let exchange = match t.http3.as_ref().expect("an h3 step needs a server with an HTTP/3 listener (\"quic\": true and http3Port)") {
        Udp::Local(addr) => {
            let port: u16 = addr.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).expect("http3 port");
            let mut tls = (*trust_all_tls_client()).clone();
            tls.alpn_protocols.clear();
            let authority = format!("localhost:{port}");
            let requests: Vec<_> = requests
                .iter()
                .map(|(method, path, headers, body)| h3_step::Request { method, path, authority: &authority, headers: headers.clone(), body: body.clone(), trailers: Vec::new(), close_wait: Duration::ZERO, stall: None })
                .collect();
            h3_step::exchange_streams(port, tls, &requests, stall, timeout).await
        }
        Udp::Container { id, port } => {
            let spec = json!({
                "host": "127.0.0.1", "port": port, "timeout": timeout.as_secs_f64(), "stall": stall.map(|s| s.as_secs_f64()),
                "streams": requests.iter().map(|(method, path, headers, body)| json!({
                    "method": method, "path": path, "authority": format!("localhost:{port}"),
                    "headers": headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
                    "body": base64::engine::general_purpose::STANDARD.encode(body),
                })).collect::<Vec<_>>(),
            });
            let image = h3_image();
            let out = h3_sidecar(id, &image, &spec);
            assert!(out.status.success(), "h3 sidecar: {}", String::from_utf8_lossy(&out.stderr));
            serde_json::from_slice(&out.stdout).expect("h3 sidecar: JSON")
        }
    };
    let results = exchange["streams"]
        .as_array()
        .expect("h3 streams: results")
        .iter()
        .zip(streams)
        .map(|(exchange, stream)| {
            // what a stream that did not end was sent is the server's flow control, not its answer
            let mut stream = stream.clone();
            if exchange["end"] != "fin" {
                stream["stallMillis"] = json!(0);
            }
            h3_result(t, &stream, exchange)
        })
        .collect::<Vec<_>>();
    let mut result = json!({"streams": results});
    if let Some(masks) = step.get("mask").and_then(Value::as_array) {
        mask(&mut result, masks);
    }
    result
}

/// An `"h3"` step's [`h3_step::Exchange`] as its result (see [`send_h3`]), normalised like an HTTP/1.1 answer.
fn h3_result(t: &Target, step: &Value, exchange: &Value) -> Value {
    use base64::Engine;
    let frames = exchange["frames"].as_array().cloned().unwrap_or_default();
    let mut kinds: Vec<String> = Vec::new();
    let mut sections = Vec::new();
    let mut data = Vec::new();
    for frame in &frames {
        let kind = if let Some(fields) = frame.get("headers").and_then(Value::as_array) {
            sections.push(fields.iter().map(|f| (f[0].as_str().unwrap_or_default().to_string(), f[1].as_str().unwrap_or_default().to_string())).collect::<Vec<_>>());
            "HEADERS".to_string()
        } else if let Some(b64) = frame.get("data").and_then(Value::as_str) {
            data.extend(base64::engine::general_purpose::STANDARD.decode(b64).expect("h3 data base64"));
            "DATA".to_string()
        } else {
            format!("frame {}", frame["frame"])
        };
        if !(kind == "DATA" && kinds.last().is_some_and(|k| k == "DATA")) {
            kinds.push(kind);
        }
    }
    let mut result = json!({"frames": kinds});
    let out = result.as_object_mut().unwrap();
    let first_headers = kinds.first().is_some_and(|k| k == "HEADERS");
    if first_headers {
        let section = &sections[0];
        if let Some((_, status)) = section.iter().find(|(k, _)| k == ":status") {
            out.insert("status".into(), json!(status.parse::<u16>().unwrap_or(0)));
        }
        let raw_body = String::from_utf8_lossy(&data);
        let mut headers: Vec<String> = section
            .iter()
            .filter(|(k, _)| !k.starts_with(':') && !IGNORED_HEADERS.contains(&k.as_str()))
            .map(|(k, v)| header_line(k, v, t, &raw_body))
            .collect();
        headers.sort();
        out.insert("headers".into(), json!(headers));
    }
    let body = if binary_body(step) { base64_body(&data) } else { normalise(&String::from_utf8_lossy(&data), t) };
    let length_varies = body.contains("<port>");
    // how much of the response a stalled client was sent is the server's flow control, not its answer
    if step.get("stallMillis").is_none() {
        out.insert("body".into(), json!(body));
    }
    if let Some(trailers) = sections.get(usize::from(first_headers)) {
        out.insert("trailers".into(), json!(trailers.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>()));
    }
    out.insert("end".into(), exchange["end"].clone());
    // `"closeError": true` keeps how the server closed the connection; `"settings": [id, …]` keeps those
    // entries of the server's SETTINGS frame.
    if step.get("closeError").and_then(Value::as_bool) == Some(true) {
        let closed = exchange.get("closed").cloned().unwrap_or(Value::Null);
        out.insert("closed".into(), closed);
    }
    if let Some(ids) = step.get("settings").and_then(Value::as_array) {
        let settings: serde_json::Map<String, Value> = ids.iter().map(|id| (id.to_string(), exchange["settings"].get(id.to_string()).cloned().unwrap_or(Value::Null))).collect();
        out.insert("settings".into(), Value::Object(settings));
    }
    if let Some(masks) = step.get("mask").and_then(Value::as_array) {
        mask(&mut result, masks);
    } else if length_varies {
        for h in result["headers"].as_array_mut().into_iter().flatten() {
            if h.as_str().is_some_and(|h| h.starts_with("content-length: ")) {
                *h = "content-length: <varies>".into();
            }
        }
    }
    result
}

/// A `"tcp": [base64, …]` step: one connection to the server's port, each chunk written 200 ms (`chunkMillis`) after the one before,
/// then everything read until the server closes the connection or two seconds pass: `{"tcp": base64, "closed": bool}`.
/// Its `minMillis` asserts how long the server took, from connecting, to close the connection (`closeSocketDelay`).
async fn send_tcp(t: &Target, step: &Value) -> Value {
    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let started = std::time::Instant::now();
    let tcp = connect(&t.addr).await;
    // A `{"raw": hex}` chunk needs the socket under any TLS session.
    let chunks = step["tcp"].as_array().expect("tcp: [base64, …]");
    let mut raw = chunks.iter().any(|c| c.get("raw").is_some()).then(|| {
        use std::os::fd::AsFd;
        std::net::TcpStream::from(tcp.as_fd().try_clone_to_owned().expect("duplicate the step's socket"))
    });
    // `"tls": true`: the chunks are application data of a TLS connection to the server's port.
    let mut negotiation: Option<Value> = None;
    let mut stream: Box<dyn TcpStepIo> = if step.get("tls").and_then(Value::as_bool) == Some(true) {
        // `"sni"`: the server name the ClientHello carries (default `localhost`)
        let sni = step.get("sni").and_then(Value::as_str).unwrap_or("localhost").to_string();
        let name = rustls_pki_types::ServerName::try_from(sni).unwrap();
        // `"signatureSchemes": [rustls name, …]`: the client's `signature_algorithms`, in that order, in
        // place of rustls's; `"tls12": true` offers TLS 1.2 only.
        // `"negotiated": true`: the answer also records the protocol version, cipher suite and handshake
        // signature scheme the server picked; `"cipherSuites": [rustls name, …]` is the client's offer, in that order.
        let negotiated = step.get("negotiated").and_then(Value::as_bool) == Some(true);
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let client = if negotiated {
            let schemes = step.get("signatureSchemes").and_then(Value::as_array).map(|n| n.iter().map(|n| signature_scheme(n.as_str().expect("signatureSchemes: [name, …]"))).collect());
            let suites = step.get("cipherSuites").and_then(Value::as_array).map(|n| n.iter().map(|n| n.as_str().expect("cipherSuites: [name, …]").to_string()).collect());
            negotiating_tls_client(schemes, suites, step.get("tls12").and_then(Value::as_bool) == Some(true), seen.clone())
        } else {
            match step.get("signatureSchemes").and_then(Value::as_array) {
            Some(names) => {
                let schemes = names.iter().map(|n| signature_scheme(n.as_str().expect("signatureSchemes: [name, …]"))).collect();
                scheme_tls_client(schemes, step.get("tls12").and_then(Value::as_bool) == Some(true))
            }
            None => trust_all_tls_client(),
            }
        };
        match tokio_rustls::TlsConnector::from(client).connect(name, tcp).await {
            Ok(tls) => {
                if negotiated {
                    let connection = tls.get_ref().1;
                    negotiation = Some(json!({
                        "version": format!("{:?}", connection.protocol_version().expect("negotiated version")),
                        "cipherSuite": format!("{:?}", connection.negotiated_cipher_suite().expect("negotiated suite").suite()),
                        "signatureScheme": seen.lock().unwrap().map(|s| format!("{s:?}")),
                    }));
                }
                Box::new(tls)
            }
            // a refused handshake is the answer: how it ended, a close or an alert
            Err(e) => return json!({"tlsHandshakeFailed": e.to_string()}),
        }
    } else {
        Box::new(tcp)
    };
    // `"chunkMillis"`: a longer pause between chunks, where the server must have read one before the next arrives
    // (a SOCKS greeting and its command coalesced into one read are not SOCKS) and the oracle's event loop can stall.
    let pause = Duration::from_millis(step.get("chunkMillis").and_then(Value::as_u64).unwrap_or(200));
    let mut read = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        // `{"await": n}` reads, up to 10 s, until the answer has n bytes (then the client reads no more
        // until the step's end), so the next chunk lands while the server is part way through writing its answer.
        if let Some(n) = chunk.get("await").and_then(Value::as_u64) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            let mut buf = [0u8; 4096];
            while (read.len() as u64) < n {
                match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
                    Ok(Ok(got)) if got > 0 => read.extend_from_slice(&buf[..got]),
                    _ => break,
                }
            }
            continue;
        }
        if i > 0 {
            tokio::time::sleep(pause).await;
        }
        // `{"raw": hex}` writes the bytes on the socket itself, under a `"tls"` step's TLS session, e.g. a record no
        // TLS library would send (a corrupt one).
        if let Some(hex) = chunk.get("raw").and_then(Value::as_str) {
            use std::io::Write;
            let bytes: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("raw hex chunk")).collect();
            if raw.as_mut().unwrap().write_all(&bytes).is_err() {
                break;
            }
            continue;
        }
        // `{"starttls": n}`: the next n bytes of the answer are read in the clear, as a client that asked
        // to turn TLS on reads its server's yes, then TLS starts on the same connection (no ALPN, no server name: a
        // JDK `SSLSocket` layered over a socket to 127.0.0.1); `"tls12": true` offers TLS 1.2 only. The chunks after it
        // go through TLS, and what is read through it is appended to the answer.
        if let Some(clear) = chunk.get("starttls").and_then(Value::as_u64) {
            let mut yes = vec![0u8; clear as usize];
            if !matches!(tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut yes)).await, Ok(Ok(_))) {
                return json!({"tcp": base64::engine::general_purpose::STANDARD.encode(&read), "starttls": "no answer to read in the clear"});
            }
            read.extend_from_slice(&yes);
            let mut config = (*trust_all_tls_client()).clone();
            if chunk.get("tls12").and_then(Value::as_bool) == Some(true) {
                let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
                config = rustls::ClientConfig::builder_with_provider(provider.clone())
                    .with_protocol_versions(&[&rustls::version::TLS12])
                    .unwrap()
                    .dangerous()
                    .with_custom_certificate_verifier(std::sync::Arc::new(TrustAll(provider)))
                    .with_no_client_auth();
            }
            config.alpn_protocols.clear();
            let name = rustls_pki_types::ServerName::try_from("127.0.0.1").unwrap();
            stream = match tokio_rustls::TlsConnector::from(std::sync::Arc::new(config)).connect(name, stream).await {
                Ok(tls) => Box::new(tls),
                Err(e) => return json!({"tcp": base64::engine::general_purpose::STANDARD.encode(&read), "tlsHandshakeFailed": e.to_string()}),
            };
            continue;
        }
        // A chunk is base64, or `{"text": …}` / `{"hex": …}` with placeholders substituted (`{{deadporthex}}`: the
        // dead port as four hex digits, for a binary header carrying it, e.g. PROXY protocol v2).
        let bytes = match chunk {
            Value::String(b64) => base64::engine::general_purpose::STANDARD.decode(b64).expect("tcp base64"),
            Value::Object(o) if o.contains_key("text") => substitute(o["text"].as_str().expect("tcp text chunk"), t).into_bytes(),
            Value::Object(o) => {
                let dead = t.deadhost.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).expect("deadhost port");
                let hex = substitute(o["hex"].as_str().expect("tcp chunk: base64, {\"text\"} or {\"hex\"}"), t).replace("{{deadporthex}}", &format!("{dead:04x}"));
                (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("tcp hex chunk")).collect()
            }
            other => panic!("tcp chunk: {other}"),
        };
        if stream.write_all(&bytes).await.is_err() {
            break;
        }
    }
    // `"stallMillis": n`: the client reads nothing for n ms after its last chunk, as one that stopped
    // reading a large response does, then reads what the server left it until it closes the connection or ten seconds
    // pass. The answer is summarised, the bytes being too many and their count set by socket buffers:
    // `{"tcpHead": status line, "complete": whether the whole content-length body arrived, "closed": bool}`.
    // The last response read is summarised, so a CONNECT's `200` before the tunnelled response is
    // skipped (a response is skipped when its whole body arrived and more bytes follow it).
    // The stall starts once that response has begun to arrive, not when the request is sent, so a server slow to
    // render it under load is not read in full before it was ever stalled.
    if let Some(stall) = step.get("stallMillis").and_then(Value::as_u64) {
        let last_response_start = |read: &[u8]| {
            let mut start = 0;
            loop {
                let rest = &read[start..];
                let head_end = rest.windows(4).position(|w| w == b"\r\n\r\n");
                let head = String::from_utf8_lossy(&rest[..head_end.unwrap_or(0)]).into_owned();
                let length = head.lines().find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.trim().parse::<usize>().ok()));
                match (head_end, length) {
                    (Some(at), Some(length)) if rest.len() - at - 4 >= length => start += at + 4 + length,
                    _ => return start,
                }
            }
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut chunk = [0u8; 4096];
        while last_response_start(&read) == read.len() {
            match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
                Ok(Ok(got)) if got > 0 => read.extend_from_slice(&chunk[..got]),
                _ => break,
            }
        }
        tokio::time::sleep(Duration::from_millis(stall)).await;
        let closed = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut read)).await.is_ok();
        let mut start = 0;
        loop {
            let rest = &read[start..];
            let head_end = rest.windows(4).position(|w| w == b"\r\n\r\n");
            let head = String::from_utf8_lossy(&rest[..head_end.unwrap_or(0)]).into_owned();
            let length = head.lines().find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.trim().parse::<usize>().ok()));
            let complete = match (head_end, length) {
                (Some(at), Some(length)) => rest.len() - at - 4 >= length,
                _ => false,
            };
            match (head_end, length) {
                (Some(at), Some(length)) if rest.len() - at - 4 > length => start += at + 4 + length,
                _ => return json!({"tcpHead": head.lines().next().unwrap_or_default(), "complete": complete, "closed": closed}),
            }
        }
    }
    // `"awaitBytes": n`: first wait (up to 10 s) for the answer's first n bytes, then the two-second window as usual, for
    // an answer that is late but not wrong under load, e.g. the first TLS use minting the leaf key. What is
    // read and whether the connection closes are compared as before.
    let mut ended = false;
    if let Some(n) = step.get("awaitBytes").and_then(Value::as_u64) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while (read.len() as u64) < n {
            let mut chunk = [0u8; 4096];
            match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
                Ok(Ok(0)) | Ok(Err(_)) => {
                    ended = true;
                    break;
                }
                Ok(Ok(got)) => read.extend_from_slice(&chunk[..got]),
                Err(_) => break,
            }
        }
    }
    let end = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut read)).await;
    let closed = ended || end.is_ok();
    // `"tlsEnd": true`: how a TLS connection ended, `close_notify` (the server's alert before its FIN)
    // or `eof` (a FIN alone, which rustls reads as an unexpected end), so an idle close shows what it sends
    let tls_end = (step.get("tlsEnd").and_then(Value::as_bool) == Some(true)).then(|| match &end {
        Ok(Ok(_)) => "close_notify".to_string(),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => "eof".to_string(),
        Ok(Err(e)) => format!("error: {e}"),
        Err(_) => "open".to_string(),
    });
    if let Some(min) = step.get("minMillis").and_then(Value::as_u64) {
        let took = started.elapsed().as_millis() as u64;
        assert!(took >= min, "{}: closed after {took} ms, expected at least {min} ms", step["note"]);
    }
    if step.get("text").and_then(Value::as_bool) == Some(true) {
        // `"text": true`: the answer as text, where header order shows and declared ports are restored.
        let mut answer = json!({"tcpText": String::from_utf8_lossy(&read), "closed": closed});
        if let Some(negotiation) = negotiation {
            answer["negotiated"] = negotiation;
        }
        if let Some(tls_end) = tls_end {
            answer["tlsEnd"] = json!(tls_end);
        }
        return answer;
    }
    if let Some(tls_end) = tls_end {
        return json!({"tcp": base64::engine::general_purpose::STANDARD.encode(&read), "closed": closed, "tlsEnd": tls_end});
    }
    json!({"tcp": base64::engine::general_purpose::STANDARD.encode(&read), "closed": closed})
}

/// An `"h2raw": {"headers": [[name, value], …], "body": text, "method": "POST", "path": "/p"}` step: a request, written as raw HTTP/2
/// frames (preface, SETTINGS, HEADERS with literal HPACK fields, DATA ending the stream; no `body` key: HEADERS ending it), so header names and values
/// no client library would send can be tried. Records the frames the server sends back as readable lines (HPACK
/// blocks are opaque: only their stream and flags, unless the spec has `"decode": true`, which appends each block's
/// fields as `name: value` lines, e.g. a `:status` no client library accepts): `{"frames": [...], "closed": bool}`.
/// Header values of any length (split into CONTINUATION frames at 16 KiB) taking placeholders,
/// `"open": true`, `"trailers"` and `"indexedRepeat"`, see the comments below.
async fn send_h2raw(t: &Target, step: &Value) -> Value {
    // An overall deadline for the whole step (connect, write, the wait for HEADERS, the stall and the
    // read), so a server that stops reading or never answers fails the file instead of hanging the recorder. It is
    // the step's own stall and read times plus 30 s for the header wait plus a margin (`"marginMillis"`, default
    // 30 s). The expiry panics, which the recorder lists as a failed file and a replay as a failed scenario.
    let spec = &step["h2raw"];
    let stall = spec["stallMillis"].as_u64();
    let read = spec["readMillis"].as_u64().unwrap_or(if stall.is_some() { 10_000 } else { 2000 });
    let margin = spec["marginMillis"].as_u64().unwrap_or(30_000);
    let budget = Duration::from_millis(stall.unwrap_or(0) + read + margin) + Duration::from_secs(if stall.is_some() { 30 } else { 0 });
    match tokio::time::timeout(budget, send_h2raw_inner(t, step)).await {
        Ok(answer) => answer,
        Err(_) => panic!("h2raw step to {} did not finish within {budget:?} (stallMillis {stall:?}, readMillis {read})", t.addr),
    }
}

async fn send_h2raw_inner(t: &Target, step: &Value) -> Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        out.extend([kind, flags]);
        out.extend(stream.to_be_bytes());
        out.extend(payload);
        out
    }
    /// An HPACK integer with an `n`-bit prefix, the bits above it in `first` (RFC 7541 section 5.1).
    fn integer(out: &mut Vec<u8>, n: u32, first: u8, value: usize) {
        let max = (1usize << n) - 1;
        if value < max {
            out.push(first | value as u8);
            return;
        }
        out.push(first | max as u8);
        let mut rest = value - max;
        while rest >= 128 {
            out.push((rest % 128 + 128) as u8);
            rest /= 128;
        }
        out.push(rest as u8);
    }
    /// A literal field without indexing (`indexed`: with incremental indexing), name and value not Huffman-coded.
    fn literal_as(out: &mut Vec<u8>, name: &str, value: &str, indexed: bool) {
        if indexed {
            out.push(0x40);
        } else {
            out.push(0);
        }
        integer(out, 7, 0, name.len());
        out.extend(name.as_bytes());
        integer(out, 7, 0, value.len());
        out.extend(value.as_bytes());
    }
    fn literal(out: &mut Vec<u8>, name: &str, value: &str) {
        literal_as(out, name, value, false);
    }
    /// A header block as HEADERS (`flags`, END_HEADERS added on the last frame) and CONTINUATION frames of at most
    /// 16 KiB, the frame size a server reads before its own SETTINGS are acknowledged.
    fn header_frames(stream: u32, flags: u8, block: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut chunks: Vec<&[u8]> = block.chunks(16_384).collect();
        if chunks.is_empty() {
            chunks.push(&[]);
        }
        let last = chunks.len() - 1;
        for (i, chunk) in chunks.into_iter().enumerate() {
            let end_headers = if i == last { 4 } else { 0 };
            out.extend(if i == 0 { frame(1, flags | end_headers, stream, chunk) } else { frame(9, end_headers, stream, chunk) });
        }
        out
    }
    let spec = &step["h2raw"];
    let mut block = Vec::new();
    for (k, v) in [(":method", spec["method"].as_str().unwrap_or("POST")), (":scheme", "http"), (":path", spec["path"].as_str().unwrap_or("/p"))] {
        literal(&mut block, k, v);
    }
    // `"authority"`: a fixed `:authority`, so a header list's size is the same on every server
    literal(&mut block, ":authority", spec["authority"].as_str().unwrap_or(&t.host));
    // header values take placeholders, e.g. `{{repeat:N:a}}` for a header list of a given size
    for pair in spec["headers"].as_array().cloned().unwrap_or_default() {
        literal(&mut block, pair[0].as_str().expect("header name"), &substitute(pair[1].as_str().expect("header value"), t));
    }
    // `"indexedRepeat": {"name", "value", "count"}`: the field once with incremental indexing, then
    // `count - 1` one-byte references to it (dynamic table index 62), a header list that decodes far larger than it is
    if let Some(repeat) = spec.get("indexedRepeat") {
        literal_as(&mut block, repeat["name"].as_str().expect("indexedRepeat.name"), &substitute(repeat["value"].as_str().expect("indexedRepeat.value"), t), true);
        for _ in 1..repeat["count"].as_u64().expect("indexedRepeat.count") {
            block.push(0x80 | 62);
        }
    }
    let body = spec["body"].as_str().unwrap_or_default().as_bytes();
    // `"trailers": [[name, value], …]`: a header block after the body, which then ends the stream
    let trailers = spec.get("trailers").and_then(Value::as_array).map(|pairs| {
        let mut block = Vec::new();
        for pair in pairs {
            literal(&mut block, pair[0].as_str().expect("trailer name"), &substitute(pair[1].as_str().expect("trailer value"), t));
        }
        block
    });
    let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    // `"openWindows": true`: every window as wide as HTTP/2 allows (SETTINGS_INITIAL_WINDOW_SIZE and a
    // connection WINDOW_UPDATE), so nothing but the socket holds the response back
    let open_windows = spec["openWindows"].as_bool().unwrap_or(false);
    const MAX_WINDOW: u32 = (1 << 31) - 1;
    if open_windows {
        let mut settings = 4u16.to_be_bytes().to_vec();
        settings.extend(MAX_WINDOW.to_be_bytes());
        bytes.extend(frame(4, 0, 0, &settings));
        bytes.extend(frame(8, 0, 0, &(MAX_WINDOW - 65_535).to_be_bytes()));
    } else {
        bytes.extend(frame(4, 0, 0, &[]));
    }
    // `"open": true`: neither the HEADERS frame nor a DATA frame ends the stream
    let open = spec["open"].as_bool().unwrap_or(false);
    if let Some(trailers) = &trailers {
        bytes.extend(header_frames(1, 0, &block));
        if spec.get("body").is_some() {
            bytes.extend(frame(0, 0, 1, body));
        }
        bytes.extend(header_frames(1, 1, trailers));
    } else if spec.get("body").is_some() {
        bytes.extend(header_frames(1, 0, &block));
        bytes.extend(frame(0, if open { 0 } else { 1 }, 1, body));
    } else {
        // END_STREAM: a request without a body
        bytes.extend(header_frames(1, if open { 0 } else { 1 }, &block));
    }
    // `"streams": [{"method", "path"}, …]`: more bodiless requests on the same connection, streams 3, 5,
    // …, written with the first
    for (i, more) in spec["streams"].as_array().cloned().unwrap_or_default().iter().enumerate() {
        let mut block = Vec::new();
        for (k, v) in [(":method", more["method"].as_str().unwrap_or("GET")), (":scheme", "http"), (":path", more["path"].as_str().unwrap_or("/p"))] {
            literal(&mut block, k, v);
        }
        literal(&mut block, ":authority", &t.host);
        bytes.extend(frame(1, 5, 3 + 2 * i as u32, &block));
    }
    let mut stream = connect(&t.addr).await;
    // `"socks5": "host:port"`: the frames go through a SOCKS5 tunnel to that target (no authentication,
    // a domain-name CONNECT), so it is the tunnel's HTTP/2 that reads them
    if let Some(target) = spec["socks5"].as_str() {
        let (host, port) = target.rsplit_once(':').expect("socks5: host:port");
        // the greeting alone first: a server that reads it with the request behind it takes the bytes for a binary request
        let _ = stream.write_all(&[5, 1, 0]).await;
        let mut method = [0u8; 2];
        let _ = stream.read_exact(&mut method).await;
        let mut hello = vec![5, 1, 0, 3, host.len() as u8];
        hello.extend(host.as_bytes());
        hello.extend(port.parse::<u16>().expect("socks5 port").to_be_bytes());
        let _ = stream.write_all(&hello).await;
        // the CONNECT reply's version, status, reserved byte and address type; the bound address and port follow
        let mut head = [0u8; 4];
        let _ = stream.read_exact(&mut head).await;
        let rest = match head[3] {
            1 => 4 + 2,
            4 => 16 + 2,
            _ => {
                let mut length = [0u8; 1];
                let _ = stream.read_exact(&mut length).await;
                length[0] as usize + 2
            }
        };
        let mut address = vec![0u8; rest];
        let _ = stream.read_exact(&mut address).await;
    }
    let _ = stream.write_all(&bytes).await;
    let mut read = Vec::new();
    // `"stallMillis": n`: the client reads nothing for n ms, as one that stopped reading, then up to 10 s
    // once the response's HEADERS have arrived, so a server slow to render it is not read in full before the stall
    let stall = spec["stallMillis"].as_u64();
    if let Some(stall) = stall {
        let has_headers = |read: &[u8]| {
            let mut at = 0;
            while at + 9 <= read.len() {
                if read[at + 3] == 1 {
                    return true;
                }
                at += 9 + u32::from_be_bytes([0, read[at], read[at + 1], read[at + 2]]) as usize;
            }
            false
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut chunk = [0u8; 4096];
        while !has_headers(&read) {
            match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
                Ok(Ok(got)) if got > 0 => read.extend_from_slice(&chunk[..got]),
                _ => break,
            }
        }
        tokio::time::sleep(Duration::from_millis(stall)).await;
    }
    // `"readMillis"`: how long to read before giving up on a close, default 2 s; the client never
    // returns flow-control window, so a response larger than the initial window waits on it for as long
    let read_for = Duration::from_millis(spec["readMillis"].as_u64().unwrap_or(if stall.is_some() { 10_000 } else { 2000 }));
    let closed = tokio::time::timeout(read_for, stream.read_to_end(&mut read)).await.is_ok();
    // `"dataLengths": true`: a DATA frame shows its length, not its payload, for a large body
    let data_lengths = spec["dataLengths"].as_bool().unwrap_or(false);
    if stall.is_some() {
        // how many DATA frames arrived before the cut is set by socket buffers: the other frames, and whether a DATA
        // frame ended the response
        let (mut frames, mut ended, mut at) = (Vec::new(), false, 0);
        while at + 9 <= read.len() {
            let len = u32::from_be_bytes([0, read[at], read[at + 1], read[at + 2]]) as usize;
            if at + 9 + len > read.len() {
                break;
            }
            let (kind, flags) = (read[at + 3], read[at + 4]);
            let sid = u32::from_be_bytes([read[at + 5] & 0x7f, read[at + 6], read[at + 7], read[at + 8]]);
            match kind {
                0 => ended |= flags & 1 != 0,
                1 => frames.push(format!("HEADERS stream={sid} flags={flags:#x}")),
                3 => frames.push(format!("RST_STREAM stream={sid} code={}", u32::from_be_bytes(read[at + 9..at + 13].try_into().unwrap()))),
                4 if flags & 1 != 0 => frames.push("SETTINGS ack".to_string()),
                4 => frames.push("SETTINGS".to_string()),
                k => frames.push(format!("frame {k} stream={sid} flags={flags:#x} len={len}")),
            }
            at += 9 + len;
        }
        return json!({"frames": frames, "complete": ended, "closed": closed});
    }
    let mut frames = Vec::new();
    let mut decoder = spec["decode"].as_bool().unwrap_or(false).then(loona_hpack::Decoder::new);
    let mut at = 0;
    while at + 9 <= read.len() {
        let len = u32::from_be_bytes([0, read[at], read[at + 1], read[at + 2]]) as usize;
        let (kind, flags) = (read[at + 3], read[at + 4]);
        let sid = u32::from_be_bytes([read[at + 5] & 0x7f, read[at + 6], read[at + 7], read[at + 8]]);
        let payload = &read[(at + 9).min(read.len())..(at + 9 + len).min(read.len())];
        let u32_at = |i: usize| payload.get(i..i + 4).map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        frames.push(match kind {
            0 if data_lengths => format!("DATA stream={sid} flags={flags:#x} len={len}"),
            0 => format!("DATA stream={sid} flags={flags:#x} {:?}", String::from_utf8_lossy(payload)),
            // a tunnel's HEADERS carry Netty's default priority fields (PRIORITY flag), ahead of the header block
            1 => match decoder.as_mut().map(|d| d.decode(if flags & 0x20 != 0 { payload.get(5..).unwrap_or_default() } else { payload })) {
                None => format!("HEADERS stream={sid} flags={flags:#x}"),
                Some(Err(e)) => format!("HEADERS stream={sid} flags={flags:#x} undecodable {e:?}"),
                Some(Ok(fields)) => {
                    let fields = fields.iter().map(|(n, v)| format!("{}: {}", String::from_utf8_lossy(n), String::from_utf8_lossy(v)));
                    format!("HEADERS stream={sid} flags={flags:#x} {}", fields.collect::<Vec<_>>().join(", "))
                }
            },
            3 => format!("RST_STREAM stream={sid} code={}", u32_at(0)),
            4 if flags & 1 != 0 => "SETTINGS ack".to_string(),
            4 => format!(
                "SETTINGS {}",
                payload.chunks(6).filter(|c| c.len() == 6).map(|c| format!("{}={}", u16::from_be_bytes([c[0], c[1]]), u32::from_be_bytes([c[2], c[3], c[4], c[5]]))).collect::<Vec<_>>().join(" ")
            ),
            7 => format!("GOAWAY last={} code={} debug={:?}", u32_at(0) & 0x7fff_ffff, u32_at(4), String::from_utf8_lossy(payload.get(8..).unwrap_or_default())),
            8 => format!("WINDOW_UPDATE stream={sid} increment={}", u32_at(0)),
            k => format!("frame {k} stream={sid} flags={flags:#x} len={len}"),
        });
        at += 9 + len;
    }
    json!({"frames": frames, "closed": closed})
}

/// A `"writeFile": {"path": …, "content": …}` step: writes `content` (placeholders substituted, `""` if
/// omitted) to `path` (placeholders substituted), creating parent directories as needed — simulating an
/// external edit of a file the server watches (`ExpectationFileWatcherTest`). `{"wrote": true}`.
/// With `"replace": true` the file is replaced whole instead of rewritten in place.
fn write_file(t: &Target, step: &Value) -> Value {
    let path = substitute(step["writeFile"]["path"].as_str().expect("writeFile.path"), t);
    let content = substitute(step["writeFile"]["content"].as_str().unwrap_or_default(), t);
    if let Some(parent) = Path::new(&path).parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| panic!("writeFile {path}: create parent dirs: {e}"));
    }
    // `"replace": true`: written beside it and renamed over it, so a watcher polling the file never reads
    // it truncated or half written, which counts as a change of its own (`FileWatcher` hashes whatever it reads).
    // Otherwise written in place, as a file the server holds open (an archive it appends to) needs.
    if step["writeFile"]["replace"].as_bool() == Some(true) {
        let staged = format!("{path}.writing");
        fs::write(&staged, content).unwrap_or_else(|e| panic!("writeFile {staged}: {e}"));
        fs::rename(&staged, &path).unwrap_or_else(|e| panic!("writeFile {path}: {e}"));
    } else {
        fs::write(&path, content).unwrap_or_else(|e| panic!("writeFile {path}: {e}"));
    }
    json!({"wrote": true})
}

/// A `"deleteFile": path` step (placeholders substituted): removes the file (a missing one is not an error), so a
/// watcher can be observed on a file that disappears or never existed. `{"deleted": true}`.
/// A `*` in the file name removes every match (backups named after a timestamp), and an empty
/// directory is removed too (one the server created).
fn delete_file(t: &Target, step: &Value) -> Value {
    let path = substitute(step["deleteFile"].as_str().expect("deleteFile: path"), t);
    for path in glob_matches(&path) {
        let removed = if Path::new(&path).is_dir() { fs::remove_dir(&path) } else { fs::remove_file(&path) };
        match removed {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("deleteFile {path}: {e}"),
        }
    }
    json!({"deleted": true})
}

/// `path` itself, or, when its file name holds a `*`, every existing file of its directory whose name matches it
/// (each `*` any run of characters), sorted.
fn glob_matches(path: &str) -> Vec<String> {
    let (dir, name) = path.rsplit_once('/').unwrap_or((".", path));
    if !name.contains('*') {
        return vec![path.to_string()];
    }
    let pattern = format!("^{}$", name.split('*').map(regex::escape).collect::<Vec<_>>().join(".*"));
    let pattern = regex::Regex::new(&pattern).unwrap();
    let mut matches: Vec<String> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| pattern.is_match(n))
        .map(|n| format!("{dir}/{n}"))
        .collect();
    matches.sort();
    matches
}

/// A `"listFiles": path` step: the names of the files `path` names (a `*` in its file name matches any
/// run of characters), sorted, as `{"files": [...]}`; a `"mask"` applies to each name (a timestamp in a backup's).
fn list_files(t: &Target, step: &Value) -> Value {
    let path = substitute(step["listFiles"].as_str().expect("listFiles: path"), t);
    let names: Vec<String> =
        glob_matches(&path).into_iter().filter(|p| Path::new(p).exists()).map(|p| p.rsplit_once('/').map_or(p.clone(), |(_, n)| n.to_string())).collect();
    let mut names: Vec<Value> = names
        .into_iter()
        .map(|n| {
            let mut v = json!({"fileContent": n});
            if let Some(masks) = step.get("mask").and_then(Value::as_array) {
                mask(&mut v, masks);
            }
            v["fileContent"].clone()
        })
        .collect();
    names.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    json!({"files": names})
}

/// A `"readFile": path` step (placeholders substituted): the file's content, normalised like a response body
/// (see [`normalise`]), or `null` if it does not exist (yet). Used to assert what the server persisted
/// (`persistedExpectationsPath`) or to observe a reload after [`write_file`].
fn read_file(t: &Target, step: &Value) -> Value {
    let path = substitute(step["readFile"].as_str().expect("readFile: path"), t);
    let content = fs::read_to_string(&path).ok().map(|c| normalise(&c, t));
    json!({"fileContent": content})
}

/// A server property: name and value.
type Property = (String, String);

/// Replay starts a scenario's server on this host, where a fixed UDP port (`http3Port`, `dnsPort`) may be held by
/// another worktree's `cargo test`: each is moved to a free port. Returns the
/// properties to start with and the `(free, declared)` ports for [`declared_ports`]. Recording keeps the declared
/// ports: they are inside the oracle's container. The free port is probed and released, so the caller starts again
/// with fresh ones while the start fails on one another process took in between ([`udp_port::taken_meanwhile`]).
///
/// [`normalise`] rewrites the replay server's own TCP port (and a peer's, a `{{bindport}}` stand-in, the
/// dead port) in every step's answer, before [`declared_ports`] maps the free UDP port back. TCP and UDP port numbers
/// are separate, so the server's ephemeral TCP port could be the probed UDP number (about 1 in 16384 on macOS), and
/// `alt-svc: h3=":19443"` then came back as `h3=":<port>"`. Each free port is therefore one whose TCP twin could be
/// bound here: the returned listeners hold it (dual-stack `[::]`) while the caller keeps them, so no ephemeral TCP
/// bind of this process can be handed that number; numbers [`normalise`] rewrites anyway are skipped.
fn free_udp_ports(properties: Vec<Property>) -> (Vec<Property>, Vec<Property>, Vec<std::net::TcpListener>) {
    let mut moved = Vec::new();
    let mut twins = Vec::new();
    let properties = properties
        .into_iter()
        .map(|(k, v)| {
            if !matches!(k.as_str(), "http3Port" | "dnsPort") || v.parse::<u16>().map_or(true, |p| p == 0) {
                return (k, v);
            }
            let (free, twin) = free_udp_port_with_tcp_twin();
            twins.push(twin);
            moved.push((free.to_string(), v));
            (k, free.to_string())
        })
        .collect();
    (properties, moved, twins)
}

/// A free UDP port ([`udp_port::free_udp_port`]) and a TCP listener holding the same number (see [`free_udp_ports`]).
fn free_udp_port_with_tcp_twin() -> (u16, std::net::TcpListener) {
    loop {
        let port = udp_port::free_udp_port();
        if !usable_bind_port(port, &BIND_PORTS.lock().unwrap(), &LOST_BIND_PORTS.lock().unwrap()) {
            continue;
        }
        if let Ok(twin) = std::net::TcpListener::bind(("::", port)).or_else(|_| std::net::TcpListener::bind(("0.0.0.0", port))) {
            return (port, twin);
        }
    }
}

/// `results` with each free port of [`free_udp_ports`] written as the port the scenario declared (e.g. `alt-svc`).
fn declared_ports(results: Vec<Value>, moved: &[(String, String)]) -> Vec<Value> {
    if moved.is_empty() {
        return results;
    }
    let mut text = serde_json::to_string(&results).unwrap();
    for (free, declared) in moved {
        text = cached_regex(&format!(r"\b{free}\b")).unwrap().replace_all(&text, declared.as_str()).into_owned();
    }
    serde_json::from_str(&text).unwrap()
}

/// The UDP listener a scenario's properties configure (`dnsEnabled` with a fixed `dnsPort`).
fn udp_port(properties: &[(String, String)]) -> Option<u16> {
    let enabled = properties.iter().any(|(k, v)| k == "dnsEnabled" && v == "true");
    properties.iter().find(|(k, _)| k == "dnsPort").and_then(|(_, v)| v.parse().ok()).filter(|_| enabled)
}

fn scenarios_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/scenarios")
}

/// A writable directory for scenarios that need a real file on disk (e.g. `persistedExpectationsPath`),
/// substituted as `{{scratch}}` and created on first use. Unlike `tests/files` (read-only, checked in), this is
/// `target/scratch` (gitignored, throwaway) so a `"properties"`-scoped oracle container can bind-mount it `:rw`
/// at the same absolute path (see [`ConfiguredOracle::start`]) and write into it.
fn scratch_dir() -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/scratch");
    fs::create_dir_all(&dir).expect("create {{scratch}} dir");
    dir
}

/// `{{deadhost}}`'s value: see [`dead_port`].
fn dead_host() -> String {
    format!("localhost:{}", dead_port())
}

/// `{{bindport:N}}` — a port for `PUT /mockserver/bind` to open in place of the fixed `N` an upstream
/// test names (`1`-`5`, `1090`), which would take well-known ports (`localhost:1`, say) from every other tree on the
/// machine. It is a port the OS hands out free at first use (a probe `bind(0)`, released at once), distinct from
/// every other one this process handed out: a port derived from `ORACLE_PORT` was the same in every tree running
/// with the default, so two concurrent replays of `bind` collided ("port already in use"). [`normalise`] writes it
/// back as `N`, so goldens keep the ports the upstream test names.
static BIND_PORTS: std::sync::LazyLock<std::sync::Mutex<Vec<(u16, u16)>>> = std::sync::LazyLock::new(Default::default);

/// The port standing in for `declared` (assigned on first use, stable for the process until [`rebind_ports`]).
fn bind_port(declared: u16) -> u16 {
    let mut ports = BIND_PORTS.lock().unwrap();
    if let Some((_, actual)) = ports.iter().find(|(d, _)| *d == declared) {
        return *actual;
    }
    let actual = fresh_bind_port(&ports);
    ports.push((declared, actual));
    actual
}

/// Ports [`rebind_ports`] took back: another process held them, so they are not handed out again.
static LOST_BIND_PORTS: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());

/// A free port ([`tcp_port::free_tcp_port`]) that [`usable_bind_port`] accepts.
fn fresh_bind_port(ports: &[(u16, u16)]) -> u16 {
    let lost = LOST_BIND_PORTS.lock().unwrap();
    loop {
        let port = tcp_port::free_tcp_port();
        if usable_bind_port(port, ports, &lost) {
            return port;
        }
    }
}

/// Whether `port` may stand in for a `{{bindport:N}}`: neither `{{deadport}}` nor handed out already nor lost, nor a
/// number any scenario or golden spells out ([`literal_numbers`]). [`normalise`] writes the port back as `N` in every
/// scenario this process replays afterwards, not only the binding one, so a literal would be rewritten wherever it
/// appears: `{{bindport:4}}` got port 60000 and every later configuration answer read
/// `"chaosAutoHaltWindowMillis" : 4` instead of its default `60000`.
fn usable_bind_port(port: u16, ports: &[(u16, u16)], lost: &[u16]) -> bool {
    port != dead_port() && !ports.iter().any(|(_, a)| *a == port) && !lost.contains(&port) && !literal_numbers().contains(&port)
}

/// The `N`s of `{{bindport:N}}` in `scenario`, in order of appearance (repeats kept).
fn declared_bind_ports(text: &str) -> Vec<u16> {
    text.match_indices("{{bindport:").filter_map(|(at, _)| text[at + 11..].split("}}").next()?.parse().ok()).collect()
}

/// The declared ports a replay lost to another process. A `{{bindport:N}}` port is probed and released
/// ([`bind_port`]), so another worktree's `cargo test` (or one of this process's own `bind(0)`s) can take it before
/// `PUT /mockserver/bind` binds it, and the step answers `400 Exception while binding MockServer to port N`
/// (normalised to `N`; since the 9.2.0 re-pin, the text no longer names the cause, so any bind failure reads so,
/// except that on macOS a port taken on `0.0.0.0` or `127.0.0.1` is found by the loopback shadow probe, whose
/// `BindException` adds ` port already in use: …` as upstream's does).
/// That answer is the expected one only for a port this run has bound already: one a `200` answer listed
/// (`"ports" : [ … ]`), or one named before the failing port in the same request (upstream binds one after the other
/// and stops at the first failure). Any other `N` it names was lost.
fn lost_bind_ports(scenario: &Value, results: &[Value]) -> Vec<u16> {
    static IN_USE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^Exception while binding MockServer to port (\d+)(?: port already in use: .*)?$").unwrap());
    static PORTS: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r#""ports" : \[([^\]]*)\]"#).unwrap());
    let declared = declared_bind_ports(&scenario.to_string());
    let mut bound: Vec<u16> = Vec::new();
    let mut lost = Vec::new();
    for (step, result) in scenario["steps"].as_array().into_iter().flatten().zip(results) {
        if !step["path"].as_str().is_some_and(|p| p == "/mockserver/bind" || p == "/bind") {
            continue;
        }
        let body = result["body"].as_str().unwrap_or_default();
        match result["status"].as_u64() {
            Some(200) => {
                let ports = PORTS.captures(body).map(|c| c[1].to_string()).unwrap_or_default();
                bound.extend(ports.split(',').filter_map(|p| p.trim().parse::<u16>().ok()));
            }
            Some(400) => {
                let Some(port) = IN_USE.captures(body).and_then(|c| c[1].parse::<u16>().ok()) else { continue };
                let requested = declared_bind_ports(&step["body"].to_string());
                bound.extend(requested.iter().take_while(|p| **p != port));
                if declared.contains(&port) && !bound.contains(&port) && !lost.contains(&port) {
                    lost.push(port);
                }
            }
            _ => {}
        }
    }
    lost
}

/// Gives every `{{bindport:N}}` of `scenario` a fresh port, for a replay that lost one of them
/// ([`lost_bind_ports`]). All of them, not only the lost ones: the ports the failed run did bind are still held by
/// a server that outlives it (a harvested file's shared server), or by the server the next run replaces. The old
/// ports are never handed out again.
fn rebind_ports(scenario: &Value) {
    let declared = declared_bind_ports(&scenario.to_string());
    let mut ports = BIND_PORTS.lock().unwrap();
    let old: Vec<u16> = ports.iter().filter(|(d, _)| declared.contains(d)).map(|(_, a)| *a).collect();
    LOST_BIND_PORTS.lock().unwrap().extend(&old);
    ports.retain(|(d, _)| !declared.contains(d));
    for n in declared {
        if !ports.iter().any(|(d, _)| *d == n) {
            let actual = fresh_bind_port(&ports);
            ports.push((n, actual));
        }
    }
}

/// Runs `replay` (one replay of `scenario`) again with fresh `{{bindport:N}}` ports while it lost one to
/// another process ([`lost_bind_ports`]), up to [`tcp_port::START_ATTEMPTS`] times.
async fn replay_binding_ports<F: Future<Output = Vec<Value>>>(scenario: &Value, mut replay: impl FnMut() -> F) -> Vec<Value> {
    let mut attempt = 1;
    loop {
        let results = replay().await;
        let lost = lost_bind_ports(scenario, &results);
        if lost.is_empty() || attempt >= tcp_port::START_ATTEMPTS {
            return results;
        }
        eprintln!("note: {{{{bindport:N}}}} port(s) for {lost:?} taken by another process before the bind; replaying with fresh ports");
        rebind_ports(scenario);
        attempt += 1;
    }
}

/// Whether `s` holds a port [`bind_port`] handed out (its normalised length then differs from the wire's).
/// The ports are copied out first: holding `BIND_PORTS` while a multi-megabyte body was scanned parked
/// every other worker in `normalise` on the lock, which stalled the replay runtime, timers included, for seconds.
fn holds_bind_port(s: &str) -> bool {
    let ports: Vec<u16> = BIND_PORTS.lock().unwrap().iter().map(|(_, actual)| *actual).collect();
    off_worker_when_large(s.len(), || ports.iter().any(|actual| cached_regex(&format!(r"\b{actual}\b")).unwrap().is_match(s)))
}

fn substitute(s: &str, t: &Target) -> String {
    let files = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files");
    let mut s = s.to_string();
    if s.contains("{{capture:") {
        for (key, value) in t.captures.lock().unwrap().iter() {
            s = s.replace(&format!("{{{{capture:{key}}}}}"), value);
        }
    }
    while let Some(start) = s.find("{{bindport:") {
        let end = s[start..].find("}}").map(|e| start + e).expect("unterminated {{bindport:…}}");
        let declared: u16 = s[start + 11..end].parse().expect("{{bindport:N}} takes a port number");
        s.replace_range(start..end + 2, &bind_port(declared).to_string());
    }
    let mut s = s
        .replace("{{host}}", &t.host)
        .replace("{{deadhost}}", &t.deadhost)
        .replace("{{deadport}}", t.deadhost.rsplit_once(':').map_or(t.deadhost.as_str(), |(_, p)| p))
        .replace("{{peeraddress}}", &t.peer_address)
        // The peer by an IP address: the oracle's is its container's, the replay's `localhost` is `127.0.0.1`
        .replace("{{peeripaddress}}", &t.peer_address.replacen("localhost:", "127.0.0.1:", 1))
        // The same address split, for an `httpForward`'s `host` and `port` (`"port": "{{peerport}}"`)
        .replace("{{peerhost}}", t.peer_address.rsplit_once(':').map_or(t.peer_address.as_str(), |(h, _)| h))
        .replace("{{peerport}}", t.peer_address.rsplit_once(':').map_or("", |(_, p)| p))
        .replace("{{port}}", &t.port.to_string())
        .replace("{{files}}", &files.to_string_lossy())
        .replace("{{scratch}}", &scratch_dir().to_string_lossy())
        .replace("{{root}}", env!("CARGO_MANIFEST_DIR"));
    // `{{repeat:N:text}}`: `text` (up to the closing braces) N times, for a large file or body.
    while let Some(start) = s.find("{{repeat:") {
        let end = s[start..].find("}}").map(|e| start + e).expect("unterminated {{repeat:…}}");
        let (n, text) = s[start + 9..end].split_once(':').expect("{{repeat:N:text}}");
        let repeated = text.repeat(n.parse().expect("{{repeat:N:text}} takes a count"));
        s.replace_range(start..end + 2, &repeated);
    }
    // `{{base64:<path under tests/files>}}`: that file's bytes, base64-encoded.
    while let Some(start) = s.find("{{base64:") {
        let end = s[start..].find("}}").map(|e| start + e).expect("unterminated {{base64:…}}");
        let bytes = fs::read(files.join(&s[start + 9..end])).unwrap_or_else(|e| panic!("{}: {e}", &s[start + 9..end]));
        use base64::Engine;
        s.replace_range(start..end + 2, &base64::engine::general_purpose::STANDARD.encode(bytes));
    }
    s
}

/// A step's body: `bodyFile` (a file under `tests/files`), `bodyBase64`, a JSON `body` (string sent as-is, any
/// other value stringified first), or empty. Shared by [`send`] and [`send_pipelined`].
fn step_body(step: &Value, t: &Target) -> Vec<u8> {
    match &step["body"] {
        // `bodyFile`: a file under tests/files, sent as its bytes.
        Value::Null if step.get("bodyFile").is_some() => {
            fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files").join(step["bodyFile"].as_str().unwrap())).expect("bodyFile")
        }
        Value::Null if step.get("bodyBase64").is_some() => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(step["bodyBase64"].as_str().unwrap()).unwrap()
        }
        Value::Null => Vec::new(),
        Value::String(s) => substitute(s, t).into_bytes(),
        // A JSON number placeholder is written as a string (`"{{deadport}}"`), which is only valid JSON that way.
        other => substitute(&unquote_number_placeholders(&other.to_string()), t).into_bytes(),
    }
}

/// `"{{deadport}}"` / `"{{bindport:N}}"` (a whole JSON string) -> the bare placeholder, so it becomes a JSON number.
fn unquote_number_placeholders(s: &str) -> String {
    let mut out = s.replace("\"{{deadport}}\"", "{{deadport}}");
    let mut from = 0;
    while let Some(start) = out[from..].find("\"{{bindport:").map(|i| i + from) {
        match out[start..].find("}}\"") {
            Some(e) => {
                let inner = out[start + 1..start + e + 2].to_string();
                out.replace_range(start..start + e + 3, &inner);
                from = start + inner.len();
            }
            None => break,
        }
    }
    out
}

/// `"binaryBody": true`: the response body is recorded as base64 rather than as (lossy) UTF-8 text, for protobuf
/// and other binary bodies whose bytes would otherwise compare only up to replacement characters.
fn binary_body(step: &Value) -> bool {
    step.get("binaryBody").and_then(Value::as_bool) == Some(true)
}

fn base64_body(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// An `"h2": true` step's `"dataFrames": [base64, …]`: the request body as one DATA frame per entry, in
/// order, the last one ending the stream (an empty entry is an empty DATA frame). The h2 crate queues each as a frame
/// of its own and never merges them, so the server reads one chunk per entry (an entry over the peer's
/// SETTINGS_MAX_FRAME_SIZE, 16 KiB by default, is split further). It replaces the step's body; `None` without it.
fn data_frames(step: &Value) -> Option<Vec<Vec<u8>>> {
    use base64::Engine;
    let frames = step.get("dataFrames")?.as_array().expect("dataFrames: a list of base64 strings");
    assert!(!frames.is_empty(), "dataFrames: at least one frame");
    // An entry is a base64 string or `{"base64": …, "repeat": n}`, n frames of the same bytes (a message
    // of megabytes without megabytes of base64 in the scenario).
    let decode = |f: &str| base64::engine::general_purpose::STANDARD.decode(f).expect("dataFrames base64");
    let mut out = Vec::new();
    for f in frames {
        match f.as_object() {
            Some(o) => {
                let bytes = decode(o["base64"].as_str().expect("dataFrames entry: base64"));
                for _ in 0..o.get("repeat").and_then(Value::as_u64).unwrap_or(1) {
                    out.push(bytes.clone());
                }
            }
            None => out.push(decode(f.as_str().expect("dataFrames entry"))),
        }
    }
    Some(out)
}

/// An `"h2": true` step: one HTTP/2 prior-knowledge connection, one stream (see the module doc comment).
async fn send_h2(t: &Target, step: &Value) -> Value {
    let max = step.get("maxMillis").and_then(Value::as_u64).map(Duration::from_millis).unwrap_or(Duration::from_secs(10));
    let path = substitute(step["path"].as_str().expect("step.path"), t);
    let frames = data_frames(step);
    let body = step_body(step, t);
    let mut req = Request::builder().method(step["method"].as_str().unwrap_or("GET")).uri(format!("http://{}{path}", t.host));
    if let Some(headers) = step["headers"].as_object() {
        for (k, v) in headers {
            for v in v.as_array().cloned().unwrap_or_else(|| vec![v.clone()]) {
                req = req.header(k, substitute(v.as_str().unwrap(), t));
            }
        }
    }
    let req = req.body(()).expect("h2 request");
    let exchange = async {
        let stream = connect(&t.addr).await;
        let (mut client, conn) = h2::client::handshake(stream).await.ok()?;
        tokio::spawn(conn);
        let (response, mut out) = client.send_request(req, body.is_empty() && frames.is_none()).ok()?;
        if let Some(frames) = frames {
            let last = frames.len().saturating_sub(1);
            for (i, frame) in frames.into_iter().enumerate() {
                out.send_data(Bytes::from(frame), i == last).ok()?;
            }
        } else if !body.is_empty() {
            out.send_data(Bytes::from(body), true).ok()?;
        }
        let response = response.await.ok()?;
        let (parts, mut incoming) = response.into_parts();
        let mut data = Vec::new();
        while let Some(chunk) = incoming.data().await {
            let chunk = chunk.ok()?;
            let _ = incoming.flow_control().release_capacity(chunk.len());
            data.extend_from_slice(&chunk);
        }
        let trailers = incoming.trailers().await.ok()?;
        Some((parts, data, trailers))
    };
    let Ok(answer) = tokio::time::timeout(max, exchange).await else { return json!({"timeout": true}) };
    let Some((parts, data, trailers)) = answer else { return json!({"connectionError": true}) };
    let mut headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter(|(k, _)| !IGNORED_HEADERS.contains(&k.as_str()))
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("<binary>").to_string()))
        .collect();
    headers.sort();
    let raw_body = String::from_utf8_lossy(&data).into_owned();
    let body = if binary_body(step) { base64_body(&data) } else { normalise(&raw_body, t) };
    // As in [`send`]: a body carrying a port has no comparable length.
    let length_varies = body.contains("<port>");
    let mut result = json!({
        "status": parts.status.as_u16(),
        "headers": headers.into_iter().map(|(k, v)| header_line(&k, &v, t, &raw_body)).collect::<Vec<_>>(),
        "body": body,
    });
    if let Some(masks) = step.get("mask").and_then(Value::as_array) {
        mask(&mut result, masks);
    } else if length_varies {
        for h in result["headers"].as_array_mut().unwrap() {
            if h.as_str().is_some_and(|h| h.starts_with("content-length: ")) {
                *h = "content-length: <varies>".into();
            }
        }
    }
    if step.get("trailers").and_then(Value::as_bool) == Some(true) {
        let trailers: Vec<String> = trailers.map(|t| t.iter().map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or("<binary>"))).collect()).unwrap_or_default();
        result.as_object_mut().unwrap().insert("trailers".into(), json!(trailers));
    }
    result
}

async fn send(t: &Target, step: &Value) -> Value {
    // `"pollUntil": regex`: the step is sent again (every 200 ms, for up to 30 s) until its body matches, and the last
    // answer is what compares, whole. It waits for an event the scenario cannot otherwise observe, such as a request
    // still in flight being counted; a server that never gets there still fails with its last answer.
    if let Some(pattern) = step.get("pollUntil").and_then(Value::as_str) {
        let until = cached_fancy_regex(pattern).expect("pollUntil regex");
        let mut once = step.clone();
        once.as_object_mut().unwrap().remove("pollUntil");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let result = Box::pin(send(t, &once)).await;
            // a `readFile` step polls its file's content
            let body = result.get("body").or_else(|| result.get("fileContent")).and_then(Value::as_str).unwrap_or_default();
            if until.is_match(body).unwrap_or(false) || std::time::Instant::now() >= deadline {
                return result;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    if step.get("udp").is_some() {
        return send_udp(t, step).await;
    }
    if step.get("h3").and_then(Value::as_bool) == Some(true) {
        return send_h3(t, step).await;
    }
    if step.get("tcp").is_some() {
        let mut result = send_tcp(t, step).await;
        if let Some(masks) = step.get("mask").and_then(Value::as_array) {
            mask(&mut result, masks);
        }
        return result;
    }
    if step.get("h2raw").is_some() {
        return send_h2raw(t, step).await;
    }
    if step.get("h2").and_then(Value::as_bool) == Some(true) {
        return send_h2(t, step).await;
    }
    if step.get("writeFile").is_some() {
        return write_file(t, step);
    }
    if step.get("deleteFile").is_some() {
        return delete_file(t, step);
    }
    if step.get("listFiles").is_some() {
        return list_files(t, step);
    }
    if step.get("readFile").is_some() {
        let mut result = read_file(t, step);
        if let Some(masks) = step.get("mask").and_then(Value::as_array) {
            mask(&mut result, masks);
        }
        return result;
    }
    let method = step["method"].as_str().unwrap_or("GET");
    let path = substitute(step["path"].as_str().expect("step.path"), t);
    let body = step_body(step, t);
    let mut req = Request::builder().method(method).uri(path);
    let mut has_host = false;
    if let Some(headers) = step["headers"].as_object() {
        for (k, v) in headers {
            has_host |= k.eq_ignore_ascii_case("host");
            for v in v.as_array().cloned().unwrap_or_else(|| vec![v.clone()]) {
                req = req.header(k, substitute(v.as_str().unwrap(), t));
            }
        }
    }
    if !has_host {
        req = req.header("host", &t.host);
    }
    let Ok(req) = req.body(Full::new(Bytes::from(body))) else {
        return json!({"unsendable": true}); // not a valid HTTP/1.1 request; the same for every target
    };

    // `"maxMillis"`: raises the per-step response timeout above the 10 s default. A handler that itself reaches
    // the network (an OpenAPI `specUrlOrPayload` fetch) can legitimately take as long as `RemoteUrl`'s own
    // connect/read timeouts (30 s / 60 s, matching upstream) before it answers — most often much sooner, but a
    // network that silently drops packets instead of refusing them stalls for the full bound. So can a step that
    // moves a body of ten mebibytes or more (replay_body_cap): seconds when quiet, past 10 s at load ~90.
    // 10 s is otherwise ample margin for every other step, so raising it is opt-in per step, not a
    // global change.
    let max = step.get("maxMillis").and_then(Value::as_u64).map(Duration::from_millis).unwrap_or(Duration::from_secs(10));
    let started = std::time::Instant::now();
    let mut stream = connect(&t.addr).await;
    // `"awaitClose": true`: a second handle on the socket, read once the answer is in (see below)
    let mut close_watch = None;
    if step.get("awaitClose").and_then(Value::as_bool) == Some(true) {
        let own = stream.into_std().expect("tcp stream into std");
        close_watch = Some(own.try_clone().expect("tcp stream clone"));
        stream = TcpStream::from_std(own).expect("tcp stream from std");
    }
    let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
        .await
        .expect("handshake");
    tokio::spawn(conn);
    let sent = tokio::time::timeout(max, sender.send_request(req)).await;
    let resp = match sent {
        Ok(Ok(resp)) => resp,
        Ok(Err(_)) => return json!({"connectionError": true}),
        Err(_) => return json!({"timeout": true}),
    };
    let status = resp.status().as_u16();
    if t.server.is_none() && let Some(session) = resp.headers().get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        MCP_SESSIONS.lock().unwrap().push((t.addr.clone(), session.to_string()));
    }
    if let (Some(name), Some(key)) = (step.pointer("/capture/header").and_then(Value::as_str), step.pointer("/capture/as").and_then(Value::as_str)) && let Some(value) = resp.headers().get(name).and_then(|v| v.to_str().ok()) {
        t.captures.lock().unwrap().insert(key.to_string(), value.to_string());
    }
    // hyper only exposes the reason phrase when it differs from its own canonical one.
    let reason = resp.extensions().get::<hyper::ext::ReasonPhrase>().map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned());
    let mut headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter(|(k, _)| !IGNORED_HEADERS.contains(&k.as_str()))
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("<binary>").to_string()))
        .collect();
    headers.sort();
    let (body, trailers) = match tokio::time::timeout(max, resp.into_body().collect()).await {
        Ok(Ok(collected)) => {
            let trailers: Vec<String> = collected.trailers().map(|t| t.iter().map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or("<binary>"))).collect()).unwrap_or_default();
            (collected.to_bytes(), trailers)
        }
        Ok(Err(_)) => (Bytes::new(), Vec::new()),
        Err(_) => return json!({"status": status, "bodyTimeout": true}),
    };
    // `"awaitClose": true`: after the answer, wait (up to 10 s) for the server to close the connection, for a step
    // whose close the server logs just before closing (`disconnected and closed socket`): a later log
    // read then finds the entry however late the closing task runs under load. The answer is all read by now, so the
    // second handle reads only the end of the stream; hyper may have finished with the connection already (an answer
    // with `connection: close`). Nothing about the answer changes.
    if let Some(mut watch) = close_watch {
        let _ = tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let _ = watch.set_nonblocking(false);
            let _ = watch.set_read_timeout(Some(Duration::from_secs(10)));
            let mut sink = [0u8; 4096];
            while matches!(watch.read(&mut sink), Ok(n) if n > 0) {}
        })
        .await;
    }
    if let Some(min) = step.get("minMillis").and_then(Value::as_u64) {
        let took = started.elapsed().as_millis() as u64;
        assert!(took >= min, "{}: answered after {took} ms, expected at least {min} ms", step["note"]);
    }
    if let (Some(true), Some(key)) = (step.pointer("/capture/body").and_then(Value::as_bool), step.pointer("/capture/as").and_then(Value::as_str)) {
        t.captures.lock().unwrap().insert(key.to_string(), String::from_utf8_lossy(&body).into_owned());
    }
    if let (Some(pattern), Some(key)) = (step.pointer("/capture/bodyRegex").and_then(Value::as_str), step.pointer("/capture/as").and_then(Value::as_str)) {
        let text = String::from_utf8_lossy(&body);
        // A capture that misses aborts the file: say what answered, and what the server logged last (an
        // idp_pem_signing_failure /token answered 404 in 28 ms in full runs only, which a bare "matched nothing" hid).
        let logged = if cached_regex(pattern).expect("capture.bodyRegex").captures(&text).is_none() { logged_tail(t).await } else { String::new() };
        let value = cached_regex(pattern)
            .expect("capture.bodyRegex")
            .captures(&text)
            .and_then(|c| c.get(1))
            .unwrap_or_else(|| panic!("{} ({}): capture.bodyRegex {pattern:?} matched nothing in the {status} answer after {:?}, headers {headers:?}: {text}\nthe server's log ends:\n{logged}", step["note"], key, started.elapsed()))
            .as_str()
            .to_string();
        t.captures.lock().unwrap().insert(key.to_string(), value);
    }
    capture_list(t, step, &headers, &body);
    // `"unzip": true`: a ZIP body is compared by its entries (names and contents, in order), not by its bytes, which
    // carry the time it was written and the compressor's choices.
    let unzipped = step.get("unzip").and_then(Value::as_bool) == Some(true);
    let raw_body = String::from_utf8_lossy(&body).into_owned();
    let body = if unzipped { unzip(&body) } else if binary_body(step) { base64_body(&body) } else { String::from_utf8_lossy(&body).into_owned() };
    let body = decode_base64(&body, step.get("decodeBase64").and_then(Value::as_str));
    let body = if step.get("decodeJwt").and_then(Value::as_bool) == Some(true) { decode_jwts(&body) } else { body };
    let has_bind_port = holds_bind_port(&body);
    let body = normalise(&body, t);
    // The port's digit count differs between oracle and mock-server, and the checkout path between checkouts, so
    // the length is only comparable without them. The same holds for a `{{bindport:N}}` written back as `N`.
    let length_varies = unzipped || has_bind_port || body.contains("<port>") || body.contains("{{root}}");
    let mut result = json!({
        "status": status,
        "headers": headers.into_iter().map(|(k, v)| header_line(&k, &v, t, &raw_body)).collect::<Vec<_>>(),
        "body": body,
    });
    if let Some(masks) = step.get("mask").and_then(Value::as_array) {
        mask(&mut result, masks);
    } else if length_varies {
        for h in result["headers"].as_array_mut().unwrap() {
            if h.as_str().is_some_and(|h| h.starts_with("content-length: ")) {
                *h = "content-length: <varies>".into();
            }
        }
    }
    if let Some(reason) = reason {
        result.as_object_mut().unwrap().insert("reason".into(), reason.into());
    }
    // `"trailers": true`: the HTTP/1.1 chunked trailers, in the order received.
    if step.get("trailers").and_then(Value::as_bool) == Some(true) {
        result.as_object_mut().unwrap().insert("trailers".into(), json!(trailers));
    }
    result
}

/// `"capture": [spec, …]`: several values from one answer, each `{"bodyRegex": regex, "as": key}` (the
/// regex's first group in the body) or `{"headerRegex": [name, regex], "as": key}` (in that header's value). Unlike
/// the single-object form, a spec that matches nothing keeps no value instead of failing the step: a later
/// `{{capture:key}}` then stays as written, and the difference shows in that later step's answer.
fn capture_list(t: &Target, step: &Value, headers: &[(String, String)], body: &[u8]) {
    let Some(specs) = step.get("capture").and_then(Value::as_array) else { return };
    let text = String::from_utf8_lossy(body);
    for spec in specs {
        let key = spec["as"].as_str().expect("capture.as");
        let (pattern, haystack) = if let Some(p) = spec["bodyRegex"].as_str() {
            (p, Some(text.to_string()))
        } else if let (Some(name), Some(p)) = (spec.pointer("/headerRegex/0").and_then(Value::as_str), spec.pointer("/headerRegex/1").and_then(Value::as_str)) {
            (p, headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()))
        } else {
            panic!("{}: capture spec {spec} has neither bodyRegex nor headerRegex", step["note"]);
        };
        let value = haystack.and_then(|h| cached_regex(pattern).expect("capture regex").captures(&h).and_then(|c| c.get(1)).map(|m| m.as_str().to_string()));
        let mut captures = t.captures.lock().unwrap();
        match value {
            Some(v) => captures.insert(key.to_string(), v),
            None => captures.remove(key),
        };
    }
}

/// The list-form captures of a harvested case's step under keys of that case, `<case>/<key>`: a file's cases
/// share one run's captures ([`Target::captures`]), so two cases' `idp0` must not meet.
fn scope_captures(step: &Value) -> Value {
    let Some(case) = step.get("case").and_then(Value::as_str) else { return step.clone() };
    let listed = step.get("capture").is_some_and(Value::is_array);
    let text = step.to_string();
    if !listed && !text.contains("{{capture:") {
        return step.clone();
    }
    let mut scoped: Value = serde_json::from_str(&text.replace("{{capture:", &format!("{{{{capture:{case}/"))).unwrap();
    if let Some(specs) = scoped.get_mut("capture").and_then(Value::as_array_mut) {
        for spec in specs {
            if let Some(key) = spec.get("as").and_then(Value::as_str).map(str::to_string) {
                spec["as"] = Value::String(format!("{case}/{key}"));
            }
        }
    }
    scoped
}

/// Builds one HTTP/1.1 request's raw bytes the same way [`send`] would (method, path, `step["headers"]`,
/// a default `host`, and the body from [`step_body`], with an explicit `content-length`).
fn raw_request(step: &Value, t: &Target) -> Vec<u8> {
    let method = step["method"].as_str().unwrap_or("GET");
    let path = substitute(step["path"].as_str().expect("step.path"), t);
    let body = step_body(step, t);
    let mut head = format!("{method} {path} HTTP/1.1\r\n");
    let mut has_host = false;
    if let Some(headers) = step["headers"].as_object() {
        for (k, v) in headers {
            has_host |= k.eq_ignore_ascii_case("host");
            for v in v.as_array().cloned().unwrap_or_else(|| vec![v.clone()]) {
                head.push_str(&format!("{k}: {}\r\n", substitute(v.as_str().unwrap(), t)));
            }
        }
    }
    if !has_host {
        head.push_str(&format!("host: {}\r\n", t.host));
    }
    head.push_str(&format!("content-length: {}\r\n\r\n", body.len()));
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(&body);
    bytes
}

/// Reads one HTTP/1.1 response (status line, headers to the blank line, then exactly `content-length` body
/// bytes — every control-plane JSON response takes this shape) out of `buf`, topping it up from `stream` as
/// needed, and returns it with whatever bytes were read past it (the next response already waiting, if the
/// steps were pipelined).
async fn read_response(stream: &mut TcpStream, mut buf: Vec<u8>) -> (u16, Vec<(String, String)>, Option<String>, Bytes, Vec<u8>) {
    use tokio::io::AsyncReadExt;
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            let mut lines = head.split("\r\n");
            let mut parts = lines.next().unwrap_or_default().splitn(3, ' ');
            let status: u16 = parts.nth(1).unwrap_or("0").parse().unwrap_or(0);
            let reason = parts.next().filter(|r| !r.is_empty()).map(str::to_string);
            let mut headers = Vec::new();
            let mut content_length = 0usize;
            for line in lines {
                if let Some((k, v)) = line.split_once(':') {
                    let (k, v) = (k.trim().to_string(), v.trim().to_string());
                    if k.eq_ignore_ascii_case("content-length") {
                        content_length = v.parse().unwrap_or(0);
                    }
                    headers.push((k, v));
                }
            }
            let body_start = end + 4;

            while buf.len() < body_start + content_length {
                let mut chunk = [0u8; 4096];
                let n = stream.read(&mut chunk).await.expect("read pipelined response body");
                assert!(n > 0, "connection closed mid-response");
                buf.extend_from_slice(&chunk[..n]);
            }
            let body = Bytes::copy_from_slice(&buf[body_start..body_start + content_length]);
            let rest = buf[body_start + content_length..].to_vec();
            return (status, headers, reason, body, rest);
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await.expect("read pipelined response head");
        assert!(n > 0, "connection closed before response headers");
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Shapes a raw-parsed response into the same `{status, headers, body}` form [`send`] returns, so the golden
/// comparison cannot tell the two apart.
fn shape_response(step: &Value, t: &Target, status: u16, raw_headers: Vec<(String, String)>, reason: Option<String>, body: Bytes) -> Value {
    let mut headers: Vec<(String, String)> =
        raw_headers.into_iter().map(|(k, v)| (k.to_ascii_lowercase(), v)).filter(|(k, _)| !IGNORED_HEADERS.contains(&k.as_str())).collect();
    headers.sort();
    let raw_body = String::from_utf8_lossy(&body).into_owned();
    let body = normalise(&raw_body, t);
    let mut result = json!({
        "status": status,
        "headers": headers.into_iter().map(|(k, v)| header_line(&k, &v, t, &raw_body)).collect::<Vec<_>>(),
        "body": body,
    });
    // [`send`] (via hyper) only ever sees a reason phrase when it differs from the canonical one for the status.
    let canonical = hyper::StatusCode::from_u16(status).ok().and_then(|s| s.canonical_reason());
    if let Some(reason) = reason.filter(|r| Some(r.as_str()) != canonical) {
        result.as_object_mut().unwrap().insert("reason".into(), reason.into());
    }
    if let Some(note) = step.get("note") {
        result.as_object_mut().unwrap().insert("note".into(), note.clone());
    }
    result
}

/// `"pipelinePut": true` on a step: writes it and the step right after it onto one fresh connection in a single
/// `write_all`, before reading either response back — real HTTP/1.1 pipelining. See the module doc comment for
/// why: a step racing a server-side real-time timer needs the client-side round trip between the two requests
/// off its budget entirely, not just shortened, and an ordinary two-round-trip exchange can never guarantee
/// that under enough machine load.
async fn send_pipelined(t: &Target, steps: &[Value]) -> Vec<Value> {
    use tokio::io::AsyncWriteExt;
    let bytes: Vec<u8> = steps.iter().flat_map(|step| raw_request(step, t)).collect();
    let mut stream = connect(&t.addr).await;
    stream.write_all(&bytes).await.expect("write pipelined requests");
    let mut rest = Vec::new();
    let mut results = Vec::new();
    for step in steps {
        let (status, headers, reason, body, left) = read_response(&mut stream, rest).await;
        rest = left;
        let mut result = shape_response(step, t, status, headers, reason, body);
        if let Some(masks) = step.get("mask").and_then(Value::as_array) {
            mask(&mut result, masks);
        }
        results.push(result);
    }
    results
}

// --- WebSocket steps and HTTP steps that do not wait -----------------------------------
//
// A breakpoint holds a request until its client decides, and the client is a WebSocket: a scenario has to open that
// socket, send the request without waiting for it, read what the server holds, send a decision, and only then read
// the answer. The steps below are what [`Session::step`] handles; every other step goes to [`send`] as before.

/// A scenario's open WebSockets by name, and its HTTP steps in flight by key.
#[derive(Default)]
struct Session {
    sockets: std::collections::HashMap<String, Socket>,
    pending: std::collections::HashMap<String, tokio::task::JoinHandle<Value>>,
}

type Socket = tokio_tungstenite::WebSocketStream<TcpStream>;

/// How long a `"wsRead"` waits for a message by default.
const WS_READ_WAIT: Duration = Duration::from_secs(5);

impl Session {
    /// The result of a step this session handles, `None` for any other step:
    /// - `"wsOpen": name` (`"path"`, default `/_mockserver_callback_websocket`; `"headers"`, e.g. the callback socket's
    ///   `X-CLIENT-REGISTRATION-ID` to fix the client id): upgrades a fresh connection and keeps it under `name`, with
    ///   a fixed `Sec-WebSocket-Key` (the upgrade request is logged).
    ///   `{"ws": name, "status": 101, "headers": [...]}` (`sec-websocket-accept` shown as `<accept>`: the key is
    ///   random), or the refusal's status and body.
    /// - `"wsRead": name`: the next text message within `"waitMillis"` (default 5000). An envelope (`{"type": t,
    ///   "value": "<json>"}`, the callback socket's form) is recorded as `{"ws", "type", "body": <value>}`, any other
    ///   text as `{"ws", "body"}`, a binary message as `{"ws", "binary": base64}`; `{"ws", "timeout": true}` when
    ///   nothing came (the way to assert that nothing is held), `{"ws", "closed": true, "code"?, "reason"?}` once the
    ///   server closed it. `"until": regex` skips text messages that do not match, counting them as `"skipped"` (for
    ///   periodic pushes). `"capture"` (`bodyRegex`, or `body`: the held request itself, to send back unchanged) and
    ///   `"mask"` work on the body as on an HTTP step.
    /// - `"wsSend": name` with `"text"` (placeholders substituted), `"envelope": {"type": t, "value": object or
    ///   string}` (the value sent as a JSON string, as the callback socket expects), or `"binary": base64`:
    ///   `{"ws", "sent": bool}`; `"repeat": n` sends it n times in one write.
    /// - `"wsClose": name`: a close frame, then the socket is forgotten: `{"ws", "closed": true}`.
    /// - `"async": key` on an HTTP step: sends it without waiting (a held request answers only after its decision):
    ///   `{"async": key}`. `"await": key` waits for that step's answer and records it here, shaped as [`send`] shapes
    ///   it (the `"async"` step's own `"mask"`, `"capture"` and other options apply).
    async fn step(&mut self, t: &Target, step: &Value) -> Option<Value> {
        if let Some(name) = step.get("wsOpen").and_then(Value::as_str) {
            return Some(self.open(t, step, name).await);
        }
        if let Some(name) = step.get("wsRead").and_then(Value::as_str) {
            let mut result = self.read(step, name, t).await;
            if let Some(masks) = step.get("mask").and_then(Value::as_array) {
                mask(&mut result, masks);
            }
            return Some(result);
        }
        if let Some(name) = step.get("wsSend").and_then(Value::as_str) {
            return Some(self.send(t, step, name).await);
        }
        if let Some(name) = step.get("wsDrain").and_then(Value::as_str) {
            return Some(self.drain(step, name).await);
        }
        if let Some(name) = step.get("wsClose").and_then(Value::as_str) {
            if let Some(mut socket) = self.sockets.remove(name) {
                let _ = tokio::time::timeout(Duration::from_secs(2), socket.close(None)).await;
            }
            return Some(json!({"ws": name, "closed": true}));
        }
        if let Some(key) = step.get("async").and_then(Value::as_str) {
            let (t, mut step) = (t.clone(), step.clone());
            step.as_object_mut().unwrap().remove("async");
            self.pending.insert(key.to_string(), tokio::spawn(async move { send(&t, &step).await }));
            return Some(json!({"async": key}));
        }
        if let Some(key) = step.get("await").and_then(Value::as_str) {
            let pending = self.pending.remove(key).unwrap_or_else(|| panic!("\"await\": {key} names no \"async\" step before it"));
            return Some(pending.await.expect("async step"));
        }
        None
    }

    async fn open(&mut self, t: &Target, step: &Value, name: &str) -> Value {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let path = substitute(step.get("path").and_then(Value::as_str).unwrap_or("/_mockserver_callback_websocket"), t);
        let mut request = format!("ws://{}{path}", t.host).into_client_request().expect("websocket request");
        // A fixed key (RFC 6455's sample nonce): the upgrade request is logged, and a random key would differ run to run.
        request.headers_mut().insert("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==".parse().unwrap());
        if let Some(headers) = step["headers"].as_object() {
            for (k, v) in headers {
                let name = hyper::header::HeaderName::from_bytes(k.as_bytes()).expect("header name");
                request.headers_mut().insert(name, substitute(v.as_str().expect("header value"), t).parse().expect("header value"));
            }
        }
        let stream = connect(&t.addr).await;
        let shown = |headers: &hyper::HeaderMap| -> Vec<String> {
            let mut lines: Vec<String> = headers
                .iter()
                .filter(|(k, _)| !IGNORED_HEADERS.contains(&k.as_str()))
                .map(|(k, v)| match k.as_str() {
                    "sec-websocket-accept" => format!("{k}: <accept>"),
                    _ => format!("{k}: {}", normalise(v.to_str().unwrap_or("<binary>"), t)),
                })
                .collect();
            lines.sort();
            lines
        };
        match tokio::time::timeout(Duration::from_secs(10), tokio_tungstenite::client_async(request, stream)).await {
            Ok(Ok((socket, response))) => {
                self.sockets.insert(name.to_string(), socket);
                json!({"ws": name, "status": response.status().as_u16(), "headers": shown(response.headers())})
            }
            Ok(Err(tokio_tungstenite::tungstenite::Error::Http(response))) => {
                let body = response.body().as_ref().map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
                json!({"ws": name, "status": response.status().as_u16(), "headers": shown(response.headers()), "body": normalise(&body, t)})
            }
            Ok(Err(e)) => json!({"ws": name, "connectionError": e.to_string()}),
            Err(_) => json!({"ws": name, "timeout": true}),
        }
    }

    async fn read(&mut self, step: &Value, name: &str, t: &Target) -> Value {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;
        let socket = self.sockets.get_mut(name).unwrap_or_else(|| panic!("\"wsRead\": {name} is not open"));
        let wait = step.get("waitMillis").and_then(Value::as_u64).map(Duration::from_millis).unwrap_or(WS_READ_WAIT);
        let until = step.get("until").and_then(Value::as_str).map(|r| cached_regex(r).expect("until regex"));
        let deadline = tokio::time::Instant::now() + wait;
        let mut skipped = 0;
        let mut result = loop {
            let message = match tokio::time::timeout_at(deadline, socket.next()).await {
                Err(_) => break json!({"ws": name, "timeout": true}),
                Ok(None) | Ok(Some(Err(_))) => break json!({"ws": name, "closed": true}),
                Ok(Some(Ok(message))) => message,
            };
            match message {
                Message::Text(text) => {
                    let text = text.as_str();
                    if until.as_ref().is_some_and(|u| !u.is_match(text)) {
                        skipped += 1;
                        continue;
                    }
                    let envelope = serde_json::from_str::<Value>(text).ok().filter(|v| v.as_object().is_some_and(|o| o.len() == 2 && o.get("type").is_some_and(Value::is_string) && o.get("value").is_some_and(Value::is_string)));
                    let (kind, body) = match &envelope {
                        Some(e) => (Some(e["type"].clone()), e["value"].as_str().unwrap().to_string()),
                        None => (None, text.to_string()),
                    };
                    if let (Some(pattern), Some(key)) = (step.pointer("/capture/bodyRegex").and_then(Value::as_str), step.pointer("/capture/as").and_then(Value::as_str)) {
                        let value = cached_regex(pattern)
                            .expect("capture.bodyRegex")
                            .captures(&body)
                            .and_then(|c| c.get(1))
                            .unwrap_or_else(|| panic!("{}: capture.bodyRegex {pattern:?} matched nothing in {body}", step["note"]))
                            .as_str()
                            .to_string();
                        t.captures.lock().unwrap().insert(key.to_string(), value);
                    }
                    if let (Some(true), Some(key)) = (step.pointer("/capture/body").and_then(Value::as_bool), step.pointer("/capture/as").and_then(Value::as_str)) {
                        t.captures.lock().unwrap().insert(key.to_string(), body.clone());
                    }
                    // the list form (several log entry ids from one dashboard frame)
                    capture_list(t, step, &[], body.as_bytes());
                    let mut result = json!({"ws": name});
                    if let Some(kind) = kind {
                        result["type"] = kind;
                    }
                    result["body"] = json!(normalise(&body, t));
                    break result;
                }
                Message::Binary(bytes) => {
                    use base64::Engine;
                    break json!({"ws": name, "binary": base64::engine::general_purpose::STANDARD.encode(&bytes)});
                }
                Message::Close(frame) => {
                    let mut result = json!({"ws": name, "closed": true});
                    if let Some(frame) = frame {
                        result["code"] = json!(u16::from(frame.code));
                        result["reason"] = json!(frame.reason.as_str());
                    }
                    break result;
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        };
        // `"countSkipped": false`: how many were skipped is the server's own timing race (the dashboard).
        if skipped > 0 && step.get("countSkipped").and_then(Value::as_bool) != Some(false) {
            result["skipped"] = json!(skipped);
        }
        result
    }

    /// `"wsDrain": name` discards every message that arrives within `"waitMillis"` (default 1500) and
    /// records neither them nor how many there were: `{"ws", "drained": true}`, or `{"ws", "closed": true}` once the
    /// server closed it. For a socket whose server pushes a number of frames that is its own timing race (the
    /// dashboard's first frame comes late or not at all on the oracle), before the step that reads what is compared.
    /// With `"until": regex` it stops at the first text message that matches: `{"ws", "matched": true}` (a push that
    /// came without being asked for), or `{"ws", "timeout": true}` when none did.
    async fn drain(&mut self, step: &Value, name: &str) -> Value {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;
        let socket = self.sockets.get_mut(name).unwrap_or_else(|| panic!("\"wsDrain\": {name} is not open"));
        let wait = step.get("waitMillis").and_then(Value::as_u64).unwrap_or(1500);
        let until = step.get("until").and_then(Value::as_str).map(|r| cached_regex(r).expect("until regex"));
        let deadline = tokio::time::Instant::now() + Duration::from_millis(wait);
        loop {
            match tokio::time::timeout_at(deadline, socket.next()).await {
                Err(_) if until.is_some() => return json!({"ws": name, "timeout": true}),
                Err(_) => return json!({"ws": name, "drained": true}),
                Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return json!({"ws": name, "closed": true}),
                Ok(Some(Ok(Message::Text(text)))) if until.as_ref().is_some_and(|u| u.is_match(text.as_str())) => {
                    return json!({"ws": name, "matched": true})
                }
                Ok(Some(Ok(_))) => {}
            }
        }
    }

    async fn send(&mut self, t: &Target, step: &Value, name: &str) -> Value {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        let socket = self.sockets.get_mut(name).unwrap_or_else(|| panic!("\"wsSend\": {name} is not open"));
        let message = if let Some(text) = step.get("text").and_then(Value::as_str) {
            Message::text(substitute(text, t))
        } else if let Some(envelope) = step.get("envelope") {
            let value = match &envelope["value"] {
                Value::String(s) => substitute(s, t),
                other => substitute(&other.to_string(), t),
            };
            Message::text(json!({"type": envelope["type"], "value": value}).to_string())
        } else if let Some(binary) = step.get("binary").and_then(Value::as_str) {
            use base64::Engine;
            Message::binary(base64::engine::general_purpose::STANDARD.decode(substitute(binary, t)).expect("binary: base64"))
        } else {
            panic!("\"wsSend\" needs \"text\", \"envelope\" or \"binary\"")
        };
        // `"repeat": n` queues the message n times and writes them in one flush (frames the server decodes together).
        let repeat = step.get("repeat").and_then(Value::as_u64).unwrap_or(1);
        let mut sent = true;
        for _ in 0..repeat {
            sent &= socket.feed(message.clone()).await.is_ok();
        }
        json!({"ws": name, "sent": sent && socket.flush().await.is_ok()})
    }
}

/// What a `tcp` step talks over: the TCP stream itself, or a TLS client on it.
trait TcpStepIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TcpStepIo for T {}

/// Accepts any server certificate: a `"tls": true` step talks to MockServer's own leaves.
#[derive(Debug)]
struct TrustAll(std::sync::Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for TrustAll {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A TLS client trusting any server certificate, offering ALPN `http/1.1`.
fn trust_all_tls_client() -> std::sync::Arc<rustls::ClientConfig> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(TrustAll(provider)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    std::sync::Arc::new(config)
}

/// The signature scheme rustls names `name` (its `Debug` form, e.g. `ED448`, `RSA_PKCS1_SHA256`).
fn signature_scheme(name: &str) -> rustls::SignatureScheme {
    const KNOWN: [u16; 14] = [0x0201, 0x0203, 0x0401, 0x0403, 0x0501, 0x0503, 0x0601, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808, 0x0809];
    KNOWN.iter().map(|&v| rustls::SignatureScheme::from(v)).find(|s| format!("{s:?}") == name).unwrap_or_else(|| panic!("signatureSchemes: unknown {name}"))
}

/// Accepts any server certificate and offers `schemes` as its `signature_algorithms`. A handshake signature rustls's
/// provider cannot check (an `ed448` one) is accepted unchecked: the Ed448 signer is checked against OpenSSL's
/// signatures in `src/tls/ed448.rs`.
#[derive(Debug)]
struct TrustAllSchemes(TrustAll, Vec<rustls::SignatureScheme>);

impl rustls::client::danger::ServerCertVerifier for TrustAllSchemes {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &rustls_pki_types::ServerName<'_>,
        ocsp: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.0.verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        match dss.scheme {
            rustls::SignatureScheme::ED448 => Ok(rustls::client::danger::HandshakeSignatureValid::assertion()),
            _ => self.0.verify_tls12_signature(message, cert, dss),
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        match dss.scheme {
            rustls::SignatureScheme::ED448 => Ok(rustls::client::danger::HandshakeSignatureValid::assertion()),
            _ => self.0.verify_tls13_signature(message, cert, dss),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.1.clone()
    }
}

/// Accepts any server certificate like [`TrustAllSchemes`] and remembers the scheme of the server's handshake signature.
#[derive(Debug)]
struct RecordingSchemes(TrustAllSchemes, std::sync::Arc<std::sync::Mutex<Option<rustls::SignatureScheme>>>);

impl rustls::client::danger::ServerCertVerifier for RecordingSchemes {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &rustls_pki_types::ServerName<'_>,
        ocsp: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.0.verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        *self.1.lock().unwrap() = Some(dss.scheme);
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        *self.1.lock().unwrap() = Some(dss.scheme);
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// A TLS client trusting any server certificate that records the signature scheme the server signed with.
/// `schemes` are its `signature_algorithms` (rustls's own when `None`), `suites` the names of the cipher
/// suites it offers, in that order (rustls's own when `None`), `tls12` TLS 1.2 only.
fn negotiating_tls_client(
    schemes: Option<Vec<rustls::SignatureScheme>>,
    suites: Option<Vec<String>>,
    tls12: bool,
    seen: std::sync::Arc<std::sync::Mutex<Option<rustls::SignatureScheme>>>,
) -> std::sync::Arc<rustls::ClientConfig> {
    let mut provider = rustls::crypto::ring::default_provider();
    if let Some(names) = suites {
        provider.cipher_suites = names
            .iter()
            .map(|n| *provider.cipher_suites.iter().find(|s| format!("{:?}", s.suite()) == *n).unwrap_or_else(|| panic!("cipherSuites: unknown {n}")))
            .collect();
    }
    let provider = std::sync::Arc::new(provider);
    let schemes = schemes.unwrap_or_else(|| provider.signature_verification_algorithms.supported_schemes());
    let versions: &[&rustls::SupportedProtocolVersion] = if tls12 { &[&rustls::version::TLS12] } else { rustls::DEFAULT_VERSIONS };
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(RecordingSchemes(TrustAllSchemes(TrustAll(provider), schemes), seen)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    std::sync::Arc::new(config)
}

/// A TLS client trusting any server certificate, offering ALPN `http/1.1`, the signature schemes `schemes` and, with
/// `tls12`, TLS 1.2 only.
fn scheme_tls_client(schemes: Vec<rustls::SignatureScheme>, tls12: bool) -> std::sync::Arc<rustls::ClientConfig> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] = if tls12 { &[&rustls::version::TLS12] } else { rustls::DEFAULT_VERSIONS };
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(TrustAllSchemes(TrustAll(provider), schemes)))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    std::sync::Arc::new(config)
}

/// A TLS client with no trusted roots: it rejects any server certificate with a fatal `unknown_ca` alert.
fn trust_none_tls_client() -> std::sync::Arc<rustls::ClientConfig> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    std::sync::Arc::new(config)
}

/// One connection per step; thousands of harvested steps can exhaust the ephemeral ports (TIME_WAIT), so a
/// failed connect is retried for a while before giving up.
///
/// The step's connection lingers 0 s, so closing it sends a RST and leaves no TIME_WAIT behind. The
/// harness closes first (after reading the whole answer), so each step used to park its ephemeral port for 2 MSL
/// (30 s on macOS): about 8,600 at once in a full parallel replay, enough that binding the next replay server's port 0
/// failed with "Cannot assign requested address". A step that waits for the server's close (`awaitClose`, `tcp`)
/// still sees it; the RST only replaces the FIN of a connection the step is done with.
/// The last 6000 characters of `PUT /mockserver/retrieve?type=LOGS` from `t`, for a failure message; empty when it
/// cannot be read.
async fn logged_tail(t: &Target) -> String {
    let addr = t.addr.clone();
    tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut logs = String::new();
        if let Ok(mut s) = std::net::TcpStream::connect(&addr) {
            let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = s.write_all(b"PUT /mockserver/retrieve?type=LOGS HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = s.read_to_string(&mut logs);
        }
        let skip = logs.chars().count().saturating_sub(6000);
        logs.chars().skip(skip).collect()
    })
    .await
    .unwrap_or_default()
}

async fn connect(addr: &str) -> TcpStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
                return stream;
            }
            Err(e) if std::time::Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => panic!("connect {addr}: {e}"),
        }
    }
}

/// A ZIP archive as its entries, read from the central directory: `== name ==` then the (inflated) content.
fn unzip(zip: &[u8]) -> String {
    use std::io::Read;
    let u16_at = |i: usize| u16::from_le_bytes([zip[i], zip[i + 1]]) as usize;
    let u32_at = |i: usize| u32::from_le_bytes([zip[i], zip[i + 1], zip[i + 2], zip[i + 3]]) as usize;
    let Some(end) = (0..zip.len().saturating_sub(21)).rev().find(|&i| zip[i..].starts_with(&[0x50, 0x4b, 0x05, 0x06])) else {
        return format!("<not a zip: {} bytes>", zip.len());
    };
    let (count, mut at) = (u16_at(end + 10), u32_at(end + 16));
    let mut out = String::new();
    for _ in 0..count {
        let (method, compressed, name_len, extra_len, comment_len, offset) =
            (u16_at(at + 10), u32_at(at + 20), u16_at(at + 28), u16_at(at + 30), u16_at(at + 32), u32_at(at + 42));
        let name = String::from_utf8_lossy(&zip[at + 46..at + 46 + name_len]).into_owned();
        at += 46 + name_len + extra_len + comment_len;
        let data_at = offset + 30 + u16_at(offset + 26) + u16_at(offset + 28);
        let data = &zip[data_at..data_at + compressed];
        let content = match method {
            8 => {
                let mut inflated = Vec::new();
                flate2::read::DeflateDecoder::new(data).read_to_end(&mut inflated).expect("inflate zip entry");
                inflated
            }
            _ => data.to_vec(),
        };
        out.push_str(&format!("== {name} ==\n{}\n", String::from_utf8_lossy(&content)));
    }
    out
}

/// `"decodeBase64": regex`: the first capture group of each match, when it is base64 of UTF-8 text, is replaced by
/// that text, so what is encoded inside a body (a signed SAML message in a form, say) is normalised and compared,
/// and masks can blank only its parts that differ.
fn decode_base64(body: &str, regex: Option<&str>) -> String {
    use base64::Engine;
    let Some(regex) = regex else { return body.to_string() };
    let regex = cached_regex(regex).expect("decodeBase64 regex");
    regex
        .replace_all(body, |c: &regex::Captures| {
            let whole = c.get(0).unwrap();
            let Some(group) = c.get(1) else { return whole.as_str().to_string() };
            let decoded = base64::engine::general_purpose::STANDARD.decode(group.as_str()).ok().and_then(|b| String::from_utf8(b).ok());
            match decoded {
                Some(text) => format!("{}{text}{}", &body[whole.start()..group.start()], &body[group.end()..whole.end()]),
                None => whole.as_str().to_string(),
            }
        })
        .into_owned()
}

/// `"decodeJwt": true`: each compact JWS (`eyJ….….…`) becomes `<jwt header=… payload=…>` with its
/// header and payload decoded (base64url), the signature dropped: tokens are signed with a per-process key, so the
/// claims are what both servers can be compared on (masks then apply to them, e.g. `iat`).
fn decode_jwts(body: &str) -> String {
    use base64::Engine;
    static JWT: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let jwt = JWT.get_or_init(|| regex::Regex::new(r"eyJ[\w-]+\.[\w-]+\.[\w-]*").unwrap());
    let segment = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok().and_then(|b| String::from_utf8(b).ok());
    jwt.replace_all(body, |c: &regex::Captures| {
        let whole = c.get(0).unwrap().as_str();
        let mut parts = whole.split('.');
        match (parts.next().and_then(segment), parts.next().and_then(segment)) {
            (Some(header), Some(payload)) => format!("<jwt header={header} payload={payload}>"),
            _ => whole.to_string(),
        }
    })
    .into_owned()
}

/// Masks the value of `"localAddress" : "<ip>:<port>"` and `remoteAddress` wherever the key turns up. Linear time:
/// one plain regex per quoting form instead of a backreference, which made fancy-regex exceed its backtrack limit
/// on multi-megabyte bodies. The forms: `""` (the C# code format doubles every quote), `&quot;` (a template's
/// HTML-escaped `{{request}}`), plain `"`, and JSON text embedded in a JSON string, where each quote carries one to
/// three backslashes (`\"`, `\\"`, `\\\"`). The embedded forms become `<masked>`, the token the per-step `mask`s of
/// the scenarios that already carried such text produce, so those goldens stay as recorded; the others become
/// `<address>`.
fn mask_addresses(s: &str) -> String {
    use std::sync::OnceLock;
    static FORMS: OnceLock<Vec<(regex::Regex, &'static str)>> = OnceLock::new();
    let forms = FORMS.get_or_init(|| {
        [("\"\"", "<address>"), ("&quot;", "<address>"), ("\"", "<address>"), ("\\\"", "<masked>"), ("\\\\\"", "<masked>"), ("\\\\\\\"", "<masked>")]
            .iter()
            .map(|(q, token)| {
                let q = regex::escape(q);
                (regex::Regex::new(&format!(r#"({q})(local|remote)Address{q}( ?: ?){q}[^"]*?{q}"#)).unwrap(), *token)
            })
            .collect()
    });
    forms.iter().fold(s.to_string(), |acc, (re, token)| {
        re.replace_all(&acc, format!("${{1}}${{2}}Address${{1}}${{3}}${{1}}{token}${{1}}").as_str()).into_owned()
    })
}

/// The OpenAPI id hashes (`openapi_expectations::spec_key`: SHA-256 of the location, first 8 bytes) of every file under
/// `tests/files`, named by its absolute path: an id built from such a spec differs per checkout.
fn checkout_file_hashes() -> &'static std::collections::HashSet<String> {
    static HASHES: std::sync::OnceLock<std::collections::HashSet<String>> = std::sync::OnceLock::new();
    HASHES.get_or_init(|| {
        let mut hashes = std::collections::HashSet::new();
        let mut pending = vec![std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/files"))];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let digest = ring::digest::digest(&ring::digest::SHA256, path.to_string_lossy().as_bytes());
                    hashes.insert(digest.as_ref()[..8].iter().map(|b| format!("{b:02x}")).collect());
                }
            }
        }
        hashes
    })
}

/// The harness's patterns built at run time (a port's `\b<n>\b`, a step's mask, `pollUntil` or capture),
/// compiled once per pattern. Compiling them per call, in an unoptimised test build, was a third of the replay
/// runtime's worker time in `sample`s taken while its timers lagged by up to 2 s under load (`normalise` alone
/// compiled three or more per string it was handed), enough to starve the replayed servers' own timers.
static REGEXES: std::sync::LazyLock<std::sync::RwLock<std::collections::HashMap<String, regex::Regex>>> = std::sync::LazyLock::new(Default::default);
static FANCY_REGEXES: std::sync::LazyLock<std::sync::RwLock<std::collections::HashMap<String, fancy_regex::Regex>>> = std::sync::LazyLock::new(Default::default);

/// `regex::Regex::new(pattern)`, compiled once (see [`REGEXES`]).
fn cached_regex(pattern: &str) -> Result<regex::Regex, regex::Error> {
    if let Some(r) = REGEXES.read().unwrap().get(pattern) {
        return Ok(r.clone());
    }
    let r = regex::Regex::new(pattern)?;
    REGEXES.write().unwrap().insert(pattern.to_string(), r.clone());
    Ok(r)
}

/// `fancy_regex::Regex::new(pattern)`, compiled once (see [`REGEXES`]).
fn cached_fancy_regex(pattern: &str) -> Result<fancy_regex::Regex, fancy_regex::Error> {
    if let Some(r) = FANCY_REGEXES.read().unwrap().get(pattern) {
        return Ok(r.clone());
    }
    let r = fancy_regex::Regex::new(pattern)?;
    FANCY_REGEXES.write().unwrap().insert(pattern.to_string(), r.clone());
    Ok(r)
}

/// Replaces values that differ run to run: generated UUIDs, log timestamps, the server's own port and the checkout
/// path (`{{root}}`).
/// Every pattern here is a plain (linear-time) `regex`: a backreference made fancy-regex exceed its
/// backtrack limit on multi-megabyte bodies, so a pattern that must repeat a quote is one regex per quoting form.
fn normalise(s: &str, t: &Target) -> String {
    off_worker_when_large(s.len(), || normalise_here(s, t))
}

/// Work on a body over 16 KiB (a log, a recorded exchange list) runs with the replay runtime's worker
/// handed to another thread (`block_in_place`), so the servers' timers and other scenarios' tasks keep running.
/// With the regexes compiled once ([`REGEXES`]), running `normalise`'s and the masks' regexes over such bodies in an
/// unoptimised build was the largest share of busy worker time left in `sample`s taken while the timers lagged.
fn off_worker_when_large<R>(len: usize, f: impl FnOnce() -> R) -> R {
    let multi_thread = tokio::runtime::Handle::try_current().is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
    if len >= 16 * 1024 && multi_thread { tokio::task::block_in_place(f) } else { f() }
}

/// [`normalise`] on the calling thread.
fn normalise_here(s: &str, t: &Target) -> String {
    use std::sync::LazyLock;
    // An OpenAPI expectation's id hashes its spec location, which is then a path in the checkout.
    static LOCATION_HASH: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\b(openapi:(?:[a-z0-9_]*_)?)[0-9a-f]{16}\b").unwrap());
    static UUID: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap());
    static TS: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}").unwrap());
    // The response-time header's value: `""` (the C# code format doubles every quote), then plain `"`, then the
    // compact JSON of the recorded-requests archive.
    static TIMING: LazyLock<Vec<(regex::Regex, String)>> = LazyLock::new(|| {
        let mut masks: Vec<(regex::Regex, String)> = ["\"\"", "\""]
            .iter()
            .map(|q| {
                let e = regex::escape(q);
                (regex::Regex::new(&format!(r"{e}x-mockserver-response-time-ms{e} : \[ {e}\d+{e} \]")).unwrap(), format!("{q}x-mockserver-response-time-ms{q} : [ {q}<ms>{q} ]"))
            })
            .collect();
        masks.push((regex::Regex::new(r#""x-mockserver-response-time-ms":\["\d+"\]"#).unwrap(), r#""x-mockserver-response-time-ms":["<ms>"]"#.to_string()));
        masks
    });
    // The same header in generated Java code.
    static JAVA_TIMING: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r#""x-mockserver-response-time-ms", "\d+""#).unwrap());
    // Generated client code always targets `localhost:1080`, whatever port the server listens on: `"` or `'`.
    static CLIENT: LazyLock<Vec<(regex::Regex, String)>> = LazyLock::new(|| {
        ["\"", "'"].iter().map(|q| (regex::Regex::new(&format!(r"{q}localhost{q}, 1080\b")).unwrap(), format!("{q}localhost{q}, <port>"))).collect()
    });
    let number = |n: &dyn std::fmt::Display| cached_regex(&format!(r"\b{n}\b")).unwrap();
    let mut s = s.replace(env!("CARGO_MANIFEST_DIR"), "{{root}}");
    if s.contains("{{root}}") {
        s = LOCATION_HASH.replace_all(&s, "${1}<location hash>").into_owned();
    } else if s.contains("openapi:") {
        // A text that names an id without its spec's path (a closest-match hint header): only the hashes
        // of files in the checkout are masked, so an inline spec's hash is still compared.
        s = LOCATION_HASH
            .replace_all(&s, |c: &regex::Captures| {
                let hash = &c[0][c[1].len()..];
                if checkout_file_hashes().contains(hash) { format!("{}<location hash>", &c[1]) } else { c[0].to_string() }
            })
            .into_owned();
    }
    let s = mask_addresses(&s);
    // the oracle image's dashboard analytics endpoint and key read as ours, so a recording never holds them
    let s = image_analytics::as_ours(&s).into_owned();
    let s = TIMING.iter().fold(s, |s, (re, with)| re.replace_all(&s, regex::NoExpand(with)).into_owned());
    let s = JAVA_TIMING.replace_all(&s, "\"x-mockserver-response-time-ms\", \"<ms>\"");
    let s = CLIENT.iter().fold(s.into_owned(), |s, (re, with)| re.replace_all(&s, regex::NoExpand(with)).into_owned());
    let s = UUID.replace_all(&s, "<uuid>");
    // after the UUIDs, so `MockServer_<uuid>` is left alone
    let s = mask_instance_ids(&s);
    let s = TS.replace_all(&s, "<timestamp>");
    let s = number(&t.port).replace_all(&s, "<port>").into_owned();
    // `{{deadhost}}`'s own port: derived from `ORACLE_PORT` (see `dead_port`), so it differs between
    // worktrees/machines with a different one. It turns up verbatim in echoed config (`"Host" : [ "localhost:<N>"
    // ]`), in a fetch URL (`https://localhost:<N>/spec.json`) and in Netty's own exception text (`Connection
    // refused: localhost/127.0.0.1:<N>`) — normalised here, the same way in every one of those shapes, so a
    // golden recorded on one worktree's `ORACLE_PORT` matches a replay on another's. Anchored to
    // `localhost`/`127.0.0.1` (not a bare `\b<N>\b`) so an unrelated scenario's own literal port number
    // (`tests/scenarios/bind.json`'s `31113`, say) is never mistaken for it just because it happens to match.
    let s = match t.deadhost.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()) {
        Some(n) if n != t.port => {
            let s = cached_regex(&format!(r"\b(?:localhost(?:/127\.0\.0\.1)?|127\.0\.0\.1):{n}\b")).unwrap().replace_all(&s, "<deadhost>").into_owned();
            // The bare number too (`"port" : <N>` of a forward to `{{deadport}}`, Java `.withPort(<N>)`).
            number(&n).replace_all(&s, "<deadport>").into_owned()
        }
        _ => s,
    };
    // The port of a scenario's other node, which one node's answers (a merged retrieve) can carry.
    let s = t.node_ports.iter().filter(|n| **n != t.port).fold(s, |s, n| number(n).replace_all(&s, "<port>").into_owned());
    // `{{bindport:N}}` back to the port `N` the upstream test declared.
    let bound = BIND_PORTS.lock().unwrap().clone();
    bound.iter().fold(s, |s, (declared, actual)| number(actual).replace_all(&s, regex::NoExpand(&declared.to_string())).into_owned())
}

/// `normalise` stays linear on a multi-megabyte body (a large LOG_ENTRIES answer), and still masks the
/// response-time header in both quoting forms and generated client code's `localhost, 1080` in both quote kinds,
/// however far into the body they sit.
#[test]
fn normalise_masks_timing_and_client_port_in_a_multi_megabyte_body() {
    let t = Target::new(String::new(), String::new(), 65000);
    let filler = "  \"message\" : \"a \\\"quoted\\\" line of log text\",\n".repeat(100_000);
    assert!(filler.len() > 4_000_000);
    let tail = concat!(
        "\"x-mockserver-response-time-ms\" : [ \"17\" ]\n",
        "\"\"x-mockserver-response-time-ms\"\" : [ \"\"2345\"\" ]\n",
        "\"x-mockserver-response-time-ms\", \"9\"\n",
        "{\"x-mockserver-response-time-ms\":[\"255\"]}\n",
        "new MockServerClient(\"localhost\", 1080)\n",
        "Client('localhost', 1080)\n",
        "\"localhost', 1080\n",
    );
    let out = normalise(&format!("{filler}{tail}{filler}{tail}"), &t);
    let expected = concat!(
        "\"x-mockserver-response-time-ms\" : [ \"<ms>\" ]\n",
        "\"\"x-mockserver-response-time-ms\"\" : [ \"\"<ms>\"\" ]\n",
        "\"x-mockserver-response-time-ms\", \"<ms>\"\n",
        "{\"x-mockserver-response-time-ms\":[\"<ms>\"]}\n",
        "new MockServerClient(\"localhost\", <port>)\n",
        "Client('localhost', <port>)\n",
        "\"localhost', 1080\n",
    );
    assert_eq!(out, format!("{filler}{expected}{filler}{expected}"));
}

/// A golden step result with the oracle image's dashboard analytics endpoint and key read as ours
/// ([`image_analytics::as_ours`]) in its body, its `content-length` shortened by what that removed; `None` when the
/// step shows neither.
fn golden_analytics_as_ours(step: &Value) -> Option<Value> {
    let body = step.get("body")?.as_str()?;
    let ours = image_analytics::as_ours(body);
    if ours == body {
        return None;
    }
    let removed = body.len() - ours.len();
    let mut step = step.clone();
    step["body"] = Value::String(ours.into_owned());
    if let Some(headers) = step.get_mut("headers").and_then(Value::as_array_mut) {
        for header in headers.iter_mut() {
            let length = header.as_str().and_then(|h| h.strip_prefix("content-length: ")).and_then(|n| n.parse::<usize>().ok());
            if let Some(n) = length.filter(|n| *n >= removed) {
                *header = Value::String(format!("content-length: {}", n - removed));
            }
        }
    }
    Some(step)
}

/// Upstream's analytics values (recognised by digest) become our empty defaults in every dump shape; any
/// other value of the two properties is kept. Every golden is recorded through `as_ours`, so none holds
/// upstream's values any more: the shapes are checked with stand-in values recognised by their own digests, and the
/// digests of upstream's values by every replayed configuration dump of the oracle image.
#[test]
fn image_analytics_values_read_as_our_defaults() {
    let (endpoint, key) = ("https://image-analytics.example.com".to_string(), "phc_image_stand_in_key".to_string());
    let digests = [image_analytics::sha256_hex(&endpoint), image_analytics::sha256_hex(&key)];
    let image = |value: &str| digests.contains(&image_analytics::sha256_hex(value));
    let as_ours = |text: &str| image_analytics::as_ours_recognising(text, image).into_owned();
    let dto = format!("{{\n  \"dashboardAnalyticsEnabled\" : true,\n  \"dashboardAnalyticsEndpoint\" : \"{endpoint}\",\n  \"dashboardAnalyticsKey\" : \"{key}\",\n  \"x\" : \"{key}\"\n}}");
    assert_eq!(as_ours(&dto), "{\n  \"dashboardAnalyticsEnabled\" : true,\n  \"dashboardAnalyticsEndpoint\" : \"\",\n  \"dashboardAnalyticsKey\" : \"\",\n  \"x\" : \"".to_string() + &key + "\"\n}");
    let escaped = dto.replace('"', "\\\"");
    assert_eq!(as_ours(&escaped), as_ours(&dto).replace('"', "\\\""));
    let own = "\"dashboardAnalyticsEndpoint\" : \"https://analytics.example.com\", \"dashboardAnalyticsKey\" : \"phc_test_key\"";
    assert_eq!(as_ours(own), own);
    let config = format!(concat!(
        r#"[{{"name":"mockserver.dashboardAnalyticsEndpoint","value":"{}","source":"environment-variable","default":""}},"#,
        r#"{{"name":"mockserver.dashboardAnalyticsKey","value":"***REDACTED***","source":"environment-variable","default":"***REDACTED***"}}]"#
    ), endpoint);
    assert_eq!(
        as_ours(&config),
        r#"[{"name":"mockserver.dashboardAnalyticsEndpoint","value":"","source":"default"},{"name":"mockserver.dashboardAnalyticsKey","value":"***REDACTED***","source":"default"}]"#
    );
    // the key's redacted environment entry alone is a scenario's own setting, not the image's
    let key_only = r#"{"name":"mockserver.dashboardAnalyticsKey","value":"***REDACTED***","source":"environment-variable","default":"***REDACTED***"}"#;
    assert_eq!(as_ours(key_only), key_only);
    let cli = format!(
        "  mockserver.dashboardAnalyticsEndpoint = {endpoint}   [environment-variable]   (default: )\n  mockserver.dashboardAnalyticsKey = ***REDACTED***   [environment-variable]   (default: ***REDACTED***)\n"
    );
    assert_eq!(as_ours(&cli), "  mockserver.dashboardAnalyticsEndpoint =    [default]\n  mockserver.dashboardAnalyticsKey = ***REDACTED***   [default]\n");
}

/// `"mask": [regex, …]`: replaces each match in the body and header lines with `<masked>`, for values that
/// legitimately differ run to run (the current time, random numbers).
/// A mask is a regex whose matches become `<masked>`, or `{"regex", "replace"}` with a replacement of its own
/// (`""` removes what differs by design, such as a whole block of series one side has and the other lacks).
/// A masked step's `content-length` is masked too: what a mask hides may differ in length (a duration that gains a
/// digit under load), and the body itself is still compared. That includes a length the port normalisation already
/// turned into `<port>` (forward_override_body_formats step 151: the oracle's body was as long as its port number).
fn mask(result: &mut Value, masks: &[Value]) {
    let regexes: Vec<(fancy_regex::Regex, String)> = masks
        .iter()
        .filter_map(|m| match m {
            Value::String(r) => Some((r.clone(), "<masked>".to_string())),
            Value::Object(o) => Some((o.get("regex")?.as_str()?.to_string(), o.get("replace").and_then(Value::as_str).unwrap_or("<masked>").to_string())),
            _ => None,
        })
        .map(|(r, with)| (cached_fancy_regex(&r).expect("mask regex"), with))
        .collect();
    let apply = |s: &str| regexes.iter().fold(s.to_string(), |s, (r, with)| r.replace_all(&s, with.as_str()).into_owned());
    if let Some(Value::String(body)) = result.get_mut("body") {
        *body = off_worker_when_large(body.len(), || apply(body));
    }
    // a tcp step's answer, base64 (a TLS server flight is random, only its first bytes compare)
    if let Some(Value::String(read)) = result.get_mut("tcp") {
        *read = apply(read);
    }
    if let Some(Value::String(read)) = result.get_mut("tcpText") {
        *read = apply(read);
    }
    // a readFile step's result
    if let Some(Value::String(content)) = result.get_mut("fileContent") {
        *content = apply(content);
    }
    if let Some(Value::Array(headers)) = result.get_mut("headers") {
        for h in headers.iter_mut() {
            if let Value::String(line) = h {
                *line = apply(line);
                // (a length that happened to equal the recording's port was normalised to `<port>` already)
                if line.strip_prefix("content-length: ").is_some_and(|n| n == "<port>" || n.bytes().all(|b| b.is_ascii_digit())) {
                    *line = "content-length: <masked>".into();
                }
            }
        }
    }
}

// --- date-shaped masks are day-independent -----------------------------------------
//
// `B3-helper-DateTemplateHelperTest` (case `8a49378db81e`, `$dates.format('yyyy-MM-dd')`) and
// `B3-template-VelocityTemplateEngineTest` (case `e07005de9f1a`, `$date.day $date.month
// $date.year`) render the current date at day grain, coarser than the existing timestamp
// normalisation in `normalise()` (which only strips sub-second log timestamps). Recording twice
// on the same day never caught this: both recordings agree, so the case was never marked
// `unstable`, yet the golden goes stale the moment the calendar date changes (seen 2026-10-01).
// Both steps now carry a `"mask"` (see the `"mask"` step option) whose regex matches any
// date shaped like the helper's output, not a specific value — so this test fakes "today" as
// both the day before and the day after a midnight rollover (and a year rollover) and checks the
// same mask still reduces every one of them to the same placeholder, which is what makes the
// oracle comparison day-independent without weakening what the case checks (upstream's own
// `DateTemplateHelperTest.shouldFormatWithPattern` and
// `VelocityTemplateEngineTest.shouldHandleHttpRequestsWithVelocityTemplateWithDateTool` assert
// the same shape/arithmetic, never the literal value either).
#[test]
fn date_shaped_masks_are_stable_across_midnight() {
    let iso_date_mask = json!("^\\d{4}-\\d{2}-\\d{2}$");
    let day_month_year_mask = json!("^\\d{1,2} \\d{1,2} \\d{4}$");

    let masked_body = |body: &str, masks: &[Value]| -> String {
        let mut result = json!({"status": 200, "headers": [], "body": body});
        mask(&mut result, masks);
        result["body"].as_str().unwrap().to_string()
    };

    // `$dates.format('yyyy-MM-dd')`: both sides of a day rollover, and of a year rollover.
    for today in ["2026-09-30", "2026-10-01", "2026-12-31", "2027-01-01"] {
        assert_eq!(masked_body(today, std::slice::from_ref(&iso_date_mask)), "<masked>", "today = {today}");
    }

    // `$date.day $date.month $date.year` (Java `Calendar.MONTH` is 0-indexed): the day before and
    // the day after the same two rollovers, which also change how many digits the body has.
    for today in ["30 8 2026", "1 9 2026", "31 11 2026", "1 0 2027"] {
        assert_eq!(masked_body(today, std::slice::from_ref(&day_month_year_mask)), "<masked>", "today = {today}");
    }

    // Neither mask reaches past its own case: an unrelated body of the same rough shape is left alone.
    assert_eq!(masked_body("not a date", &[iso_date_mask]), "not a date");
    assert_eq!(masked_body("20260930", &[day_month_year_mask]), "20260930");
}

async fn run_scenario(t: &Target, scenario: &Value) -> Vec<Value> {
    run_scenario_with_peer(t, None, scenario).await
}

async fn run_scenario_with_peer(t: &Target, peer: Option<&Target>, scenario: &Value) -> Vec<Value> {
    // Each run keeps its own captures, shared by its two nodes: a worker's server is reused by the scenarios it
    // replays, and other workers replay theirs at the same time.
    let captures = Captures::default();
    let t = &Target { captures: captures.clone(), ..t.clone() };
    let peer = peer.map(|p| Target { captures: captures.clone(), ..p.clone() });
    let peer = peer.as_ref();
    // Every scenario starts from a clean server, except one that reads what its own server logged while starting.
    if startup_log(scenario) {
        assert!(properties(scenario).is_some(), "\"startupLog\" needs a server of its own: give the scenario \"properties\"");
    } else {
        send(t, &json!({"method": "PUT", "path": "/mockserver/reset"})).await;
    }
    let mut results = Vec::new();
    let steps = scenario["steps"].as_array().expect("steps");
    // The scenario's open WebSockets and its HTTP steps still in flight (see [`Session`]).
    let mut session = Session::default();
    let mut i = 0;
    while i < steps.len() {
        let scoped = scope_captures(&steps[i]);
        let step = &scoped;
        let target = if step.get("node").and_then(Value::as_str) == Some("peer") { peer.expect("\"node\": \"peer\" needs \"peer\": true") } else { t };
        if let Some(mut result) = session.step(target, step).await {
            if let Some(note) = step.get("note") {
                result.as_object_mut().unwrap().insert("note".into(), note.clone());
            }
            results.push(result);
            i += 1;
            continue;
        }
        if let Some(ms) = step["sleepMillis"].as_u64() {
            await_idle_or_sleep(target, step, ms).await;
            i += 1;
            continue;
        }
        let pipelined = if step.get("pipelinePut").and_then(Value::as_bool) == Some(true) { 2 } else { step.get("pipeline").and_then(Value::as_u64).unwrap_or(0) as usize };
        if pipelined > 0 {
            let group = steps.get(i..i + pipelined).expect("\"pipelinePut\"/\"pipeline\" needs that many steps from it");
            results.extend(send_pipelined(t, group).await);
            i += pipelined;
            continue;
        }
        let target = if step.get("node").and_then(Value::as_str) == Some("peer") { peer.expect("\"node\": \"peer\" needs \"peer\": true") } else { t };
        let mut result = send(target, step).await;
        if let Some(note) = step.get("note") {
            result.as_object_mut().unwrap().insert("note".into(), note.clone());
        }
        results.push(result);
        i += 1;
    }
    results
}

/// A `"sleepMillis"` step. With `"awaitIdle": true`, replay instead waits until the server has no
/// request in flight (up to 30 s): for a step that gave up on a delayed answer (a forward's read timeout against a
/// slower upstream on the same server), so the answer and its log entries land before the next step, however long a
/// loaded host takes, and not among the next step's. Recording sleeps, as the oracle reports no requests in progress.
/// With `"awaitCounts": {name: n, …}`, replay instead waits (up to 30 s) until each of the server's
/// scheduler counts ([`mock_server::Server::scheduler_count`]) is `n`: for a sleep that stands for "the server has
/// admitted the request sent before it" (a delayed response holding its slot, a render holding the template thread),
/// which a fixed sleep does not ensure on a loaded host. A count that never gets there is left to the next compared
/// step to show.
async fn await_idle_or_sleep(t: &Target, step: &Value, ms: u64) {
    if let (Some(counts), Some(server)) = (step.get("awaitCounts").and_then(Value::as_object), t.server.as_ref()) {
        let reached = |s: &mock_server::Server| {
            counts.iter().all(|(name, n)| s.scheduler_count(name).unwrap_or_else(|| panic!("awaitCounts: no count {name}")) as u64 == n.as_u64().expect("awaitCounts: a number"))
        };
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(30) && server.upgrade().is_some_and(|s| !reached(&s)) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        return;
    }
    let server = t.server.as_ref().filter(|_| step.get("awaitIdle").and_then(Value::as_bool) == Some(true));
    let Some(server) = server else {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        return;
    };
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(30) && server.upgrade().is_some_and(|s| s.requests_in_flight() > 0) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// `"startupLog": true`: the scenario's server (it has `"properties"`, so it is its own) is not reset first, so the
/// first steps see the event log as starting left it.
fn startup_log(scenario: &Value) -> bool {
    scenario.get("startupLog").and_then(Value::as_bool) == Some(true)
}

/// Top-level scenarios, isolated ones last (see the module comment).
fn scenario_files() -> Vec<PathBuf> {
    let mut files = json_files(&scenarios_dir());
    files.sort_by_key(|f| is_isolated(&load(f)));
    files
}

fn is_isolated(scenario: &Value) -> bool {
    scenario.get("isolated").and_then(Value::as_bool).unwrap_or(false) || properties(scenario).is_some() || callback_classes(scenario)
}

/// A harvested file replayed on a server of its own rather than its worker's shared one: one with `"properties"` or
/// `"isolated": true` (callback classes are a top-level scenario feature only).
fn upstream_own_server(scenario: &Value) -> bool {
    properties(scenario).is_some() || scenario.get("isolated").and_then(Value::as_bool) == Some(true)
}

/// Whether a step changes the server's configuration, which `PUT /mockserver/reset` keeps on the oracle as on ours
/// (8.0.0 probe): `PUT /mockserver/configuration` or `PUT /mockserver/mode` (which sets
/// `attemptToProxyIfNoMatchingExpectation`), bare legacy aliases included; and a CORS preflight, an
/// `OPTIONS` with `Origin` and `Access-Control-Request-Method`, which the oracle answers by turning `enableCORSForAPI`
/// on for good (`CORSHeaders.isPreflightRequest`, reached from `HttpActionHandler` for a preflight no expectation takes).
fn changes_configuration(scenario: &Value) -> bool {
    scenario["steps"].as_array().into_iter().flatten().any(|step| {
        let path = step["path"].as_str().unwrap_or_default().split('?').next().unwrap_or_default();
        let op = path.strip_prefix("/mockserver").unwrap_or(path);
        let header = |name: &str| step["headers"].as_object().is_some_and(|h| h.keys().any(|k| k.eq_ignore_ascii_case(name)));
        let preflight = step["method"].as_str() == Some("OPTIONS") && header("origin") && header("access-control-request-method");
        (step["method"].as_str().is_some_and(|m| m != "GET") && (op == "/configuration" || op == "/mode")) || preflight
    })
}

/// Configuration survives `reset`, so a scenario or harvested file that changes it must replay on a server
/// of its own; on the shared server of its replay worker it would leave non-default configuration to every scenario
/// replayed there after it (as `B2-ConfigurationSerializerTest`, harvested files then ignoring `"isolated"`, did).
#[test]
fn scenarios_changing_configuration_replay_on_their_own_server() {
    let shared: Vec<String> = scenario_files()
        .into_iter()
        .filter(|f| {
            let scenario = load(f);
            changes_configuration(&scenario) && !is_isolated(&scenario)
        })
        .chain(upstream_files().into_iter().filter(|f| {
            let scenario = load(f);
            changes_configuration(&scenario) && !upstream_own_server(&scenario)
        }))
        .map(|f| f.display().to_string())
        .collect();
    assert!(shared.is_empty(), "change configuration on a shared replay server (add \"isolated\": true): {shared:#?}");
    assert!(changes_configuration(&json!({"steps": [{"method": "PUT", "path": "/mockserver/configuration", "body": {}}]})));
    assert!(changes_configuration(&json!({"steps": [{"method": "PUT", "path": "/mode?mode=SIMULATE"}]})));
    assert!(!changes_configuration(&json!({"steps": [{"method": "GET", "path": "/mockserver/configuration"}]})));
    assert!(changes_configuration(&json!({"steps": [{"method": "OPTIONS", "path": "/x", "headers": {"Origin": "http://a.b", "Access-Control-Request-Method": "POST"}}]})));
    assert!(!changes_configuration(&json!({"steps": [{"method": "OPTIONS", "path": "/x", "headers": {"Origin": "http://a.b"}}]})));
    assert!(upstream_own_server(&load(&scenarios_dir().join("upstream/B2-ConfigurationSerializerTest.json"))));
    // And is recorded on an oracle of its own, not on the shared one
    assert_eq!(records_on_own_oracle(&load(&scenarios_dir().join("auth_mtls_configuration_refused.json"))), Some(Vec::new()));
    assert_eq!(records_on_own_oracle(&json!({"steps": [{"method": "GET", "path": "/mockserver/configuration"}]})), None);
}

/// `"callbackClasses": "integration-testing"`: the oracle gets mockserver-integration-testing at `ORACLE_VERSION` in `/libs`
/// (from `MOCK_SERVER_ORACLE_LIBS`, default the local Maven repository), mock-server the Rust
/// counterparts of its callback classes (`plugins/integration-testing`), registered in-process.
fn callback_classes(scenario: &Value) -> bool {
    scenario.get("callbackClasses").and_then(Value::as_str) == Some("integration-testing")
}

/// The integration-testing callback classes built as plugins: `(native library, WASM module)`. The WASM build
/// needs a rustup toolchain with the `wasm32-unknown-unknown` target: `stable`, or the one named in
/// `MOCK_SERVER_WASM_TOOLCHAIN` (CI names the image's own, which has no `stable`).
fn callback_plugins() -> (String, String) {
    static BUILT: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"));
            let crate_name = "mock-server-integration-testing-callbacks";
            // Cargo names the library it built, wherever `CARGO_TARGET_DIR` / `build.target-dir` put it
            let built = std::process::Command::new(env!("CARGO"))
                .args(["build", "-p", crate_name, "--message-format=json-render-diagnostics"])
                .current_dir(root)
                .stderr(std::process::Stdio::inherit())
                .output()
                .expect("cargo build");
            assert!(built.status.success(), "building the native callback plugin failed");
            let library = format!("{}mock_server_integration_testing_callbacks{}", std::env::consts::DLL_PREFIX, std::env::consts::DLL_SUFFIX);
            let native = String::from_utf8_lossy(&built.stdout)
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|message| message["reason"] == "compiler-artifact")
                .flat_map(|message| message["filenames"].as_array().cloned().unwrap_or_default())
                .filter_map(|file| file.as_str().map(PathBuf::from))
                .find(|file| file.file_name().is_some_and(|name| *name == *library))
                .expect("cargo reported no native callback plugin library");
            let toolchain = std::env::var("MOCK_SERVER_WASM_TOOLCHAIN").unwrap_or_else(|_| "stable".into());
            let toolchain = std::process::Command::new("rustup").args(["which", "rustc", "--toolchain", &toolchain]).output().expect("rustup (for the WASM callback plugin)");
            let rustc = PathBuf::from(String::from_utf8_lossy(&toolchain.stdout).trim());
            let cargo = rustc.with_file_name("cargo");
            let wasm = std::process::Command::new(&cargo)
                .args(["build", "-p", crate_name, "--release", "--target", "wasm32-unknown-unknown", "--target-dir", "target/wasm"])
                .env("RUSTC", &rustc)
                .current_dir(root)
                .status()
                .expect("cargo build --target wasm32-unknown-unknown");
            assert!(wasm.success(), "building the WASM callback plugin failed (rustup target add wasm32-unknown-unknown)");
            let wasm = root.join("target/wasm/wasm32-unknown-unknown/release/mock_server_integration_testing_callbacks.wasm");
            (native.display().to_string(), wasm.display().to_string())
        })
        .clone()
}

fn oracle_libs() -> PathBuf {
    std::env::var("MOCK_SERVER_ORACLE_LIBS").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(std::env::var("HOME").unwrap_or_default())
            .join(".m2/repository/org/mock-server/mockserver-integration-testing")
            .join(oracle_pin("ORACLE_VERSION"))
    })
}

/// A value of `oracle.env`, the oracle's pinned revision and images.
fn oracle_pin(key: &str) -> &'static str {
    include_str!("../oracle.env")
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("oracle.env has no {key}"))
}

/// The launcher options that pin the processors and heap an oracle container sizes its defaults from
/// (`ORACLE_ACTIVE_PROCESSORS`, `ORACLE_MAX_HEAP_BYTES` of `oracle.env`), as `make oracle` passes them:
/// `actionHandlerThreadCount` and the heap-derived sizes then read the same on any Docker VM.
fn oracle_jvm_options() -> [String; 2] {
    [format!("-XX:ActiveProcessorCount={}", oracle_pin("ORACLE_ACTIVE_PROCESSORS")), format!("-Xmx{}", oracle_pin("ORACLE_MAX_HEAP_BYTES"))]
}

/// The standard oracle image.
fn oracle_image() -> &'static str {
    oracle_pin("ORACLE_IMAGE")
}

/// `"quic": true`: the scenario's `"h3"` steps reach its `http3Port`. Only the oracle's `http3` image
/// variant carries the QUIC native (the standard image refuses to start with an `http3Port`), so recording uses it.
fn quic(scenario: &Value) -> bool {
    scenario.get("quic").and_then(Value::as_bool) == Some(true)
}

/// The HTTP/3 port a `"quic"` scenario's properties set (`http3Port`).
fn http3_port(scenario: &Value, properties: &[(String, String)]) -> Option<u16> {
    quic(scenario).then(|| properties.iter().find(|(k, _)| k == "http3Port").and_then(|(_, v)| v.parse().ok())).flatten()
}

/// The image a `"properties"` scenario is recorded on: the variant `"image"` names, for a feature the standard image
/// does not carry (`"clustered"` has the Infinispan state backend), else the standard oracle; both pinned in
/// `oracle.env`. `"quic"` scenarios and those with an `http3Port` were recorded on the `http3` variant until 9.2.0,
/// whose standard image serves HTTP/3 itself (upstream #2869, 8d28d6f4f).
fn image(scenario: &Value) -> String {
    match scenario.get("image").and_then(Value::as_str) {
        Some("clustered") => oracle_pin("ORACLE_CLUSTERED_IMAGE"),
        Some(other) => panic!("unknown oracle image variant {other:?} (oracle.env names \"clustered\")"),
        None => oracle_image(),
    }
    .to_string()
}

/// A scenario's `"properties"`, with `{{files}}`, `{{scratch}}`, `{{deadhost}}` and `{{deadport}}` substituted.
fn properties(scenario: &Value) -> Option<Vec<(String, String)>> {
    properties_with_peer(scenario, "")
}

fn has_peer(scenario: &Value) -> bool {
    scenario.get("peer").and_then(Value::as_bool) == Some(true)
}

/// `"peerImage"`, the image a `"peer": true` node is recorded on (default the oracle's), for an upstream
/// whose behaviour only a later image has, e.g. an HTTP/2 answer to HEAD that ends at its HEADERS (upstream c4e2b8985,
/// which replay's mock-server peer has too). The golden names it as `peerRecordedFrom`.
fn peer_image(scenario: &Value) -> String {
    scenario.get("peerImage").and_then(Value::as_str).unwrap_or(oracle_image()).to_string()
}

/// `"peerProperties"`, the `mockserver.*` properties the peer node starts with (none by default), with the
/// startup placeholders other than the peer's own address substituted.
fn peer_properties(scenario: &Value) -> Vec<(String, String)> {
    scenario.get("peerProperties").and_then(Value::as_object).map_or_else(Vec::new, |o| {
        o.iter().map(|(k, v)| (k.clone(), substitute_startup(&value_text(v), ""))).collect()
    })
}

/// As [`properties`], with `{{peerurl}}` (the address of the scenario's second node) substituted.
/// A scenario with `"env"` or `"propertiesFile"` and no `"properties"` still gets a server of its own (an empty set).
fn properties_with_peer(scenario: &Value, peer_url: &str) -> Option<Vec<(String, String)>> {
    let Some(o) = scenario.get("properties").and_then(Value::as_object) else {
        return (scenario.get("env").is_some() || scenario.get("propertiesFile").is_some() || scenario.get("jvmOptions").is_some()).then(Vec::new);
    };
    Some(o.iter().map(|(k, v)| (k.clone(), substitute_startup(&value_text(v), peer_url))).collect())
}

fn value_text(v: &Value) -> String {
    v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())
}

/// The placeholders a startup value (`"properties"`, `"env"`, `"propertiesFile"`) may carry.
fn substitute_startup(v: &str, peer_url: &str) -> String {
    let files = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files");
    // `{{peerhost}}` and `{{peerport}}`: the peer node's address split, for `proxyRemoteHost`/`proxyRemotePort`.
    let peer_address = peer_url.split_once("://").map_or(peer_url, |(_, rest)| rest);
    let (peer_host, peer_port) = peer_address.rsplit_once(':').unwrap_or((peer_address, ""));
    v.replace("{{peerhost}}", peer_host)
        .replace("{{peerport}}", peer_port)
        .replace("{{deadhost}}", &dead_host())
        .replace("{{deadport}}", &dead_port().to_string())
        .replace("{{peerhttpsurl}}", &peer_url.replacen("http://", "https://", 1))
        .replace("{{peerurl}}", peer_url)
        .replace("{{files}}", &files.to_string_lossy())
        .replace("{{scratch}}", &scratch_dir().to_string_lossy())
}

/// The environment variables and the properties file a scenario's server starts with (besides its `-D` properties):
/// `"env"` is an object of `NAME: value`; `"propertiesFile"` is the file's text, or an array of its lines.
#[derive(Default)]
struct Startup {
    env: Vec<(String, String)>,
    /// The scenario's `"jvmOptions"`, after the oracle's pinned ones in `JDK_JAVA_OPTIONS`.
    jvm: Vec<String>,
    file: Option<String>,
    /// Container ports published besides 1080 (`"peerNetwork": "shared"`: the peer's port, in this container's
    /// network namespace).
    publish: Vec<u16>,
    /// `--network container:<id>` instead of a port of its own: the container whose network namespace this one joins,
    /// and the host address at which that container publishes this one's port.
    network: Option<(String, String)>,
}

impl Startup {
    fn of(scenario: &Value) -> Startup {
        let env = match scenario.get("env").and_then(Value::as_object) {
            Some(o) => o.iter().map(|(k, v)| (k.clone(), substitute_startup(&value_text(v), ""))).collect(),
            None => Vec::new(),
        };
        let file = scenario.get("propertiesFile").map(|f| {
            let text = match f {
                Value::Array(lines) => lines.iter().map(value_text).collect::<Vec<_>>().join("\n") + "\n",
                other => value_text(other),
            };
            substitute_startup(&text, "")
        });
        let jvm = scenario.get("jvmOptions").and_then(Value::as_array).map(|o| o.iter().map(value_text).collect()).unwrap_or_default();
        Startup { env, jvm, file, ..Startup::default() }
    }
}

/// The configuration a replayed scenario's own server starts with: its `-D` properties, `"env"` and `"propertiesFile"`.
fn replay_config(properties: &[(String, String)], scenario: &Value) -> mock_server::Config {
    let startup = Startup::of(scenario);
    let config = properties.iter().fold(mock_server::Config::for_tests(), |c, (k, v)| c.with_property(k, v));
    let mut config = startup.env.iter().fold(config, |c, (k, v)| c.with_env(k, v));
    if !startup.jvm.is_empty() {
        config = config.with_env("JDK_JAVA_OPTIONS", &oracle_jvm_options().into_iter().chain(startup.jvm.iter().cloned()).collect::<Vec<_>>().join(" "));
    }
    // `proxyRemoteHost`/`proxyRemotePort` are read by `Main` (the command line's own port forwarding), not by
    // the library's `Config`, which the replay builds directly.
    let property = |name: &str| properties.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    if let Some(port) = property("proxyRemotePort").and_then(|p| p.trim().parse::<u16>().ok()) {
        config.port_forward = Some((property("proxyRemoteHost").unwrap_or_else(|| "localhost".into()), port));
    }
    match &startup.file {
        Some(text) => config.with_property_file_text(text),
        None => config,
    }
}

/// A `-D` option for `JDK_JAVA_OPTIONS`. The launcher splits that variable on blanks and honours quotes but no escapes
/// (a backslash stays a backslash and a `"` only toggles quoting), so the value goes in single quotes, inside which
/// everything is literal, JSON included; a single quote closes the quoting, is written as `"'"`, and reopens it.
fn jdk_option(name: &str, value: &str) -> String {
    format!("-Dmockserver.{name}='{}'", value.replace('\'', "'\"'\"'"))
}

/// The name of a container recording starts besides the oracle (`role` `cfg`: a property-scoped oracle, `udp`: a UDP
/// sidecar): `<MOCK_SERVER_ORACLE_NAME>-<role>-<pid>-<n>`, the oracle's name as `make record` passes it (default
/// `mock-server-oracle`), so that each worktree's containers carry its own oracle's name. Their host ports are
/// ephemeral (`-p 127.0.0.1::1080`) or absent (the sidecar shares the oracle's network namespace), so two worktrees
/// recording at once never collide.
fn container_name(role: &str) -> String {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let oracle = std::env::var("MOCK_SERVER_ORACLE_NAME").unwrap_or_else(|_| "mock-server-oracle".into());
    format!("{oracle}-{role}-{}-{}", std::process::id(), NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
}

/// An oracle container started with `properties` (as quoted `-Dmockserver.*` options in `JDK_JAVA_OPTIONS`, after
/// [`oracle_jvm_options`]), removed on drop.
struct ConfiguredOracle {
    id: String,
    addr: String,
}

impl ConfiguredOracle {
    async fn start(properties: &[(String, String)], libs: Option<&Path>, image: &str) -> ConfiguredOracle {
        ConfiguredOracle::start_with(properties, libs, image, &Startup::default()).await
    }

    /// As [`start`](Self::start), with the scenario's `"env"` as `docker run -e` variables and its `"propertiesFile"`
    /// mounted at the image's `/config/mockserver.properties` (what its `-Dmockserver.propertyFile` names).
    async fn start_with(properties: &[(String, String)], libs: Option<&Path>, image: &str, startup: &Startup) -> ConfiguredOracle {
        let files = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files");
        let scratch = scratch_dir();
        let options: Vec<String> = oracle_jvm_options().into_iter().chain(startup.jvm.iter().cloned()).chain(properties.iter().map(|(k, v)| jdk_option(k, &v.replace("{{ownport}}", "1080")))).collect();
        let props_file = startup.file.as_ref().map(|text| {
            let path = scratch.join(format!("{}.properties", container_name("file")));
            fs::write(&path, text).expect("write the properties file");
            path
        });
        let ports: Vec<String> = match &startup.network {
            Some((id, _)) => vec!["--network".into(), format!("container:{id}")],
            None => std::iter::once(1080).chain(startup.publish.iter().copied()).flat_map(|p| ["-p".to_string(), format!("127.0.0.1::{p}")]).collect(),
        };
        let out = std::process::Command::new("docker")
            // `--no-healthcheck`: the image's HEALTHCHECK (a `PUT /mockserver/status` every 10 s) is a request like any
            // other to `mock_server_request_duration_seconds`, so a recording that spans a tick counts one more.
            .args(["run", "-d", "--rm", "--no-healthcheck", "--name", &container_name("cfg")])
            .args(&ports)
            .args(docker_bind::bind_same(&files, true))
            // {{scratch}}, writable: unlike tests/files, a "properties" scenario may need the container itself
            // to write a file here (e.g. persistedExpectationsPath) that the test process then reads back.
            .args(docker_bind::bind_same(&scratch, false))
            .args(libs.map(|l| docker_bind::bind(l, Path::new("/libs"), true)).into_iter().flatten())
            .args(props_file.iter().flat_map(|p| docker_bind::bind(p, Path::new("/config/mockserver.properties"), true)))
            .args(startup.env.iter().flat_map(|(k, v)| ["-e".to_string(), format!("{k}={v}")]))
            .arg("-e")
            .arg(format!("JDK_JAVA_OPTIONS={}", options.join(" ")))
            .arg(image)
            .output()
            .expect("docker run");
        assert!(out.status.success(), "docker run: {}", String::from_utf8_lossy(&out.stderr));
        let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let addr = match &startup.network {
            Some((_, addr)) => addr.clone(),
            None => published(&id, 1080),
        };
        let oracle = ConfiguredOracle { id, addr };
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut answered = 0;
        loop {
            let t = Target::oracle(oracle.addr.clone());
            // 426: both mTLS flags answer even the status probe in the clear (`PortUnificationHandler`): it is up.
            let status = send(&t, &json!({"method": "PUT", "path": "/mockserver/status"})).await;
            answered += u64::from(status.get("status").is_some());
            if status.get("status") == Some(&json!(200)) || status.get("status") == Some(&json!(426)) {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "configured oracle did not start");
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        oracle.await_started(properties, startup, answered).await;
        oracle
    }

    /// The oracle answers the readiness probe as soon as it is bound, but `LifeCycle.startedServer` goes on
    /// after the bind on a thread of its own: `started on port`, then (under `proxySetupLogging`, which the image's
    /// CLI turns on unless configured) the CA load (`loaded CA X509 from path`) and the `MockServer proxy setup`
    /// banner, then the `startupWarmup` thread's `PUT /mockserver/status`. At the pinned commit that tail often
    /// finishes after the scenario's first reset, so the goldens caught the startup entries (and, with
    /// `metricsEnabled`, the warm-up in `REQUESTS_RECEIVED_COUNT`) in some recordings and not in others. Recording
    /// waits for all of it, which leaves nothing of start-up for the first reset to race; the server under test logs
    /// it all before it starts listening. The console (`docker logs`) shows each entry just before the event log
    /// takes it (`MockServerEventLog.processLogEntry`), and is read rather than the event log so that a `"startupLog"`
    /// scenario's log holds no request of the recorder's.
    async fn await_started(&self, properties: &[(String, String)], startup: &Startup, probes: u64) {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let banner = proxy_setup_logged(properties, startup);
        loop {
            let out = std::process::Command::new("docker").args(["logs", &self.id]).output().expect("docker logs");
            let console = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
            if console.contains("started on port") && (!banner || console.contains("MockServer proxy setup")) {
                break;
            }
            if std::time::Instant::now() >= deadline {
                eprintln!("{}: no start-up banner within 20 s, recording on", self.id);
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        if !configured(properties, startup, "metricsEnabled", "MOCKSERVER_METRICS_ENABLED").is_some_and(|v| v == "true") {
            return;
        }
        // The warm-up is visible only as a count: each retrieval counts itself, so once the warm-up is counted the
        // k-th retrieval reads the answered probes, k and one more.
        let t = Target::oracle(self.addr.clone());
        static COUNT: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r#""REQUESTS_RECEIVED_COUNT"\s*:\s*(\d+)"#).unwrap());
        for k in 1.. {
            let metrics = send(&t, &json!({"method": "PUT", "path": "/mockserver/retrieve?type=METRICS"})).await;
            let body = metrics.get("body").and_then(Value::as_str).unwrap_or_default();
            let count = COUNT.captures(body).and_then(|c| c[1].parse::<u64>().ok()).unwrap_or(0);
            if count > probes + k || std::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// A `mockserver.<name>` setting as the scenario's server starts with it: from its `-D` properties, its `"env"`
/// (`env`) or its `"propertiesFile"`, in that order of precedence.
fn configured(properties: &[(String, String)], startup: &Startup, name: &str, env: &str) -> Option<String> {
    let property = format!("mockserver.{name}");
    let from_file = || {
        startup.file.as_deref().and_then(|text| {
            text.lines().find_map(|l| l.split_once('=').filter(|(k, _)| k.trim() == property).map(|(_, v)| v.trim().to_string()))
        })
    };
    properties
        .iter()
        .find(|(k, _)| k == name || *k == property)
        .map(|(_, v)| v.clone())
        .or_else(|| startup.env.iter().find(|(k, _)| k == env).map(|(_, v)| v.clone()))
        .or_else(from_file)
}

/// Whether the oracle's start-up logs the `MockServer proxy setup` banner: its CLI turns `proxySetupLogging` on unless
/// it is configured (`Main`), and the banner is a WARN with the default CA, an INFO with another.
fn proxy_setup_logged(properties: &[(String, String)], startup: &Startup) -> bool {
    let enabled = configured(properties, startup, "proxySetupLogging", "MOCKSERVER_PROXY_SETUP_LOGGING").is_none_or(|v| v.eq_ignore_ascii_case("true"));
    let quiet = configured(properties, startup, "logLevel", "MOCKSERVER_LOG_LEVEL").is_some_and(|l| matches!(l.to_ascii_uppercase().as_str(), "ERROR" | "OFF"));
    let silent = ["disableSystemOut", "disableLogging"]
        .iter()
        .zip(["MOCKSERVER_DISABLE_SYSTEM_OUT", "MOCKSERVER_DISABLE_LOGGING"])
        .any(|(name, env)| configured(properties, startup, name, env).is_some_and(|v| v == "true"));
    enabled && !quiet && !silent
}

impl ConfiguredOracle {
    /// The container's address on the Docker bridge, where another container (the scenario's first node) reaches it.
    fn bridge_url(&self) -> String {
        let out = std::process::Command::new("docker")
            .args(["inspect", "-f", "{{.NetworkSettings.IPAddress}}", &self.id])
            .output()
            .expect("docker inspect");
        format!("http://{}:1080", String::from_utf8_lossy(&out.stdout).trim())
    }
}

/// The host address at which container `id` publishes its port `port`.
fn published(id: &str, port: u16) -> String {
    let out = std::process::Command::new("docker").args(["port", id, &port.to_string()]).output().expect("docker port");
    String::from_utf8_lossy(&out.stdout).lines().next().unwrap_or_default().trim().to_string()
}

/// `"peerNetwork": "shared"` on a `"peer": true` scenario runs the peer in the first node's network
/// namespace (`--network container:<first>`, listening on [`SHARED_PEER_PORT`]), so the first node reaches it as
/// `localhost` (`{{peerurl}}` is `http://localhost:<port>`): a dotless host name, which the JDK names in no SNI. On
/// replay the peer is `localhost:<its port>` too.
fn shared_peer_network(scenario: &Value) -> bool {
    scenario.get("peerNetwork").and_then(Value::as_str) == Some("shared")
}

/// The port a `"peerNetwork": "shared"` peer listens on inside the first node's network namespace.
const SHARED_PEER_PORT: u16 = 1081;

impl Drop for ConfiguredOracle {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker").args(["rm", "-f", &self.id]).output();
    }
}

fn upstream_dir() -> PathBuf {
    scenarios_dir().join("upstream")
}

fn upstream_files() -> Vec<PathBuf> {
    if upstream_dir().is_dir() { json_files(&upstream_dir()) } else { Vec::new() }
}

fn json_files(dir: &Path) -> Vec<PathBuf> {
    let filter = std::env::var("MOCK_SERVER_SCENARIO").ok();
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .filter(|p| !p.to_string_lossy().ends_with(".golden.json"))
        // a filter ending in `$` names one file exactly (`metrics$` records `metrics` without `metrics_load`)
        .filter(|p| {
            filter.as_ref().is_none_or(|f| {
                let stem = p.file_stem().unwrap().to_string_lossy();
                match f.strip_suffix('$') {
                    Some(exact) => stem == exact,
                    None => stem.contains(f.as_str()),
                }
            })
        })
        .collect();
    files.sort();
    files
}

fn golden_path(scenario: &Path) -> PathBuf {
    scenario.with_extension("golden.json")
}

/// Where a recording writes a file's golden: beside the scenario, or, under `MOCK_SERVER_RECORD_TO=<dir>`, at the same path relative to `tests/scenarios` inside `<dir>`, leaving the tree's goldens as they are (a
/// whole shared-oracle pass compared with fresh file-by-file records).
fn recorded_golden_path(scenario: &Path) -> PathBuf {
    let golden = golden_path(scenario);
    match std::env::var_os("MOCK_SERVER_RECORD_TO") {
        Some(dir) => {
            let path = Path::new(&dir).join(golden.strip_prefix(scenarios_dir()).expect("a scenario under tests/scenarios"));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            path
        }
        None => golden,
    }
}

fn load(path: &Path) -> Value {
    // Goldens recorded before the forward loop guard's instance id was normalised hold the instance ids as the oracle sent them: each step's `content-length`
    // is first counted at full width ([`instance_id_shortfall`]), as a replayed answer's is.
    let text = fs::read_to_string(path).unwrap();
    let parse = |text: &str| serde_json::from_str::<Value>(text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let text = match parse(&text) {
        mut golden if golden["results"].as_array().is_some_and(|r| r.iter().any(|r| r["body"].as_str().is_some_and(|b| instance_id_shortfall(b) > 0))) => {
            for result in golden["results"].as_array_mut().unwrap() {
                let shortfall = result["body"].as_str().map_or(0, instance_id_shortfall);
                for header in result.get_mut("headers").and_then(Value::as_array_mut).into_iter().flatten() {
                    let length = header.as_str().and_then(|h| h.strip_prefix("content-length: ")).and_then(|n| n.parse::<usize>().ok());
                    if let Some(n) = length {
                        *header = Value::String(format!("content-length: {}", n + shortfall));
                    }
                }
            }
            golden.to_string()
        }
        _ => text,
    };
    parse(&mask_instance_ids(&text))
}

/// The forward loop guard's instance id (`ForwardLoopGuard`, `"MockServer_" + Long.toHexString(…) +
/// Long.toHexString(…)`) as `MockServer_<instance id>`: random per server, and not a UUID. A `MockServer_<uuid>`
/// (the `x-forwarded-by` value) is not one, once [`normalise`] has masked its UUID.
fn mask_instance_ids(s: &str) -> std::borrow::Cow<'_, str> {
    static INSTANCE_ID: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"\bMockServer_[0-9a-f]{2,32}\b").unwrap());
    INSTANCE_ID.replace_all(s, "MockServer_<instance id>")
}

/// How many hex digits the instance ids in `raw` lack of a full 32. `Long.toHexString` drops leading
/// zeros, so one id in eight or so is shorter, and [`mask_instance_ids`] hides that from the body but not from the
/// `content-length`, which [`header_line`] and [`load`] therefore count as if every id had all 32 digits. A
/// `MockServer_<uuid>` (its first group of hex digits ends at a `-`) is not an instance id.
fn instance_id_shortfall(raw: &str) -> usize {
    static INSTANCE_ID: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r"\bMockServer_([0-9a-f]{2,32})\b").unwrap());
    INSTANCE_ID.captures_iter(raw).filter(|c| !raw[c.get(0).unwrap().end()..].starts_with('-')).map(|c| 32 - c[1].len()).sum()
}

/// A response header as a result's line, its value normalised, except `content-length`: a length is
/// never a port, so one that happens to equal it stays a number (else a step's `content-length: \d+` mask misses it,
/// metrics_overload step 9), and it counts the instance ids in `raw_body` (the body as received) at full width. The
/// oracle image's dashboard analytics values, which [`normalise`] reads as ours, are not counted either
/// (a recording's body is read as ours, so its length must be too).
fn header_line(name: &str, value: &str, t: &Target, raw_body: &str) -> String {
    match value.parse::<usize>() {
        Ok(n) if name.eq_ignore_ascii_case("content-length") => {
            let image_analytics = raw_body.len() - image_analytics::as_ours(raw_body).len();
            format!("{name}: {}", (n + instance_id_shortfall(raw_body)).saturating_sub(image_analytics))
        }
        _ => format!("{name}: {}", normalise(value, t)),
    }
}

/// An instance id with fewer hex digits (31 here: a leading zero nibble that `Long.toHexString` drops)
/// gives the same `content-length` line as a full 32-digit one, in a replayed answer and in a golden that holds the
/// raw id; a `MockServer_<uuid>` (the `x-forwarded-by` value) is not counted.
#[test]
fn content_length_counts_instance_ids_at_full_width() {
    let body = |id: &str| format!("{{ \"x-mockserver-forwarded-by\" : [ \"MockServer_{id}\" ], \"x-forwarded-by\" : \"MockServer_0123abcd-0000-0000-0000-000000000000\" }}");
    let full = body("28615e61592792475d8af7e4fc99b025");
    let short = body("8615e61592792475d8af7e4fc99b025");
    let line = |raw: &str| header_line("content-length", &raw.len().to_string(), &Target::new(String::new(), String::new(), 1), raw);
    assert_eq!(line(&short), line(&full));
    assert_eq!(line(&full), format!("content-length: {}", full.len()));
    let golden = |raw: &str| {
        let text = json!({"results": [{"headers": [format!("content-length: {}", raw.len())], "body": raw}]}).to_string();
        let path = std::env::temp_dir().join(format!("mock-server-instance-id-{}-{}.golden.json", std::process::id(), raw.len()));
        fs::write(&path, text).unwrap();
        let loaded = load(&path);
        fs::remove_file(&path).unwrap();
        loaded["results"][0]["headers"][0].clone()
    };
    assert_eq!(golden(&short), golden(&full));
    assert_eq!(golden(&full), json!(format!("content-length: {}", full.len())));
}

/// A `content-length` that happens to equal the server's port stays a number, so a step's
/// `content-length: \d+` mask still hides it (metrics_overload step 9); other headers still read the port as `<port>`.
#[test]
fn content_length_is_never_read_as_the_port() {
    let t = Target::new(String::new(), String::new(), 54321);
    assert_eq!(header_line("content-length", "54321", &t, ""), "content-length: 54321");
    assert_eq!(header_line("location", "http://localhost:54321/x", &t, ""), "location: http://localhost:<port>/x");
}

/// Every number written as a whole word (`\b<n>\b`, as [`normalise`] matches the port) in any scenario
/// or golden under `tests/scenarios`. [`normalise`] turns the replay server's own port into `<port>` wherever it
/// appears, so a server that happened to get, say, port 60000 masked `llm_chaos`'s literal `"quotaWindowMillis":
/// 60000` on our side only. Few of these numbers fall in the ephemeral range the OS hands out.
fn literal_numbers() -> &'static std::collections::HashSet<u16> {
    static NUMBERS: std::sync::OnceLock<std::collections::HashSet<u16>> = std::sync::OnceLock::new();
    NUMBERS.get_or_init(|| {
        fn walk(dir: &Path, out: &mut std::collections::HashSet<u16>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "json") {
                    let bytes = fs::read(&path).unwrap();
                    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
                    let mut i = 0;
                    while i < bytes.len() {
                        if bytes[i].is_ascii_digit() && (i == 0 || !word(bytes[i - 1])) {
                            let start = i;
                            while i < bytes.len() && bytes[i].is_ascii_digit() {
                                i += 1;
                            }
                            if (i == bytes.len() || !word(bytes[i])) && i - start <= 5 && let Ok(n) = std::str::from_utf8(&bytes[start..i]).unwrap().parse::<u16>() {
                                out.insert(n);
                            }
                        }
                        i += 1;
                    }
                }
            }
        }
        let mut out = std::collections::HashSet::new();
        walk(&scenarios_dir(), &mut out);
        out
    })
}

/// The oracle image's `HEALTHCHECK` (`/mockserver-healthcheck`: Go's `PUT /mockserver/status` to
/// `localhost:1080`, which dials ::1) has connected over ::1 before any scenario recorded on a healthchecked oracle
/// (the shared one; a `"properties"` oracle runs with `--no-healthcheck`) reaches it. The first connection on a local
/// address renders `localAddress` with the address's host name (`PortUnificationHandler.getLocalAddresses`), so a
/// replay server standing in for that oracle has the same connection made first, as our image's healthcheck makes it.
async fn image_healthcheck(port: u16) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let check = async {
        let mut stream = tokio::net::TcpStream::connect((std::net::Ipv6Addr::LOCALHOST, port)).await?;
        let request = format!("PUT /mockserver/status HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).await?;
        Ok::<_, std::io::Error>(())
    };
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), check).await;
}

/// Starts a replay server on a port no scenario or golden spells out (see [`literal_numbers`]). A rejected server
/// stays up until a good one has started, so the OS cannot hand the same port straight back.
async fn start_replay_server(config: mock_server::Config) -> mock_server::Server {
    try_start_replay_server(config).await.unwrap_or_else(|e| panic!("start mock-server: {e}"))
}

/// [`start_replay_server`], with the first start's failure returned (a fixed UDP port another process took).
async fn try_start_replay_server(config: mock_server::Config) -> std::io::Result<mock_server::Server> {
    // The first call reads every scenario and golden (about 150 MB, unoptimised), seconds during which
    // every worker that starts a server waits on the `OnceLock`; on a blocking thread the runtime's timers keep running.
    let literal_numbers = tokio::task::spawn_blocking(literal_numbers).await.expect("literal_numbers");
    let mut rejected: Vec<mock_server::Server> = Vec::new();
    let server = loop {
        let server = match mock_server::Server::start(config.clone()).await {
            Ok(server) => server,
            // A port the scenario itself fixes cannot be bound twice: keep the first server.
            Err(_) if !rejected.is_empty() => break rejected.remove(0),
            Err(e) => return Err(e),
        };
        if rejected.len() >= 20 || !literal_numbers.contains(&server.ports()[0]) {
            break server;
        }
        rejected.push(server);
    };
    for s in rejected {
        s.shutdown().await;
    }
    Ok(server)
}

/// A shared server is handed to the next file only once the requests the last one left in flight have
/// completed. A step that gives up on a delayed answer (a client's read timeout, an MCP tool's 10 s timeout on an
/// 11 s delay) leaves the server holding it; when the delay ends the server logs `returning response` and the
/// exchange (`REQUEST_RESPONSES`), as the oracle does, into whichever file's log is current by then, after that
/// file's leading reset. Waits up to `SETTLE_LIMIT`, then names what is still in flight and goes on. Measured: only
/// `mcp_contract_http_url_connection` leaves one (about 1 s). Returns how long the file kept the server busy, which
/// [`undeclared_abandon`] holds against the file's `"settleMillis"`.
async fn settle(server: &mock_server::Server, file: &Path) -> Duration {
    const SETTLE_LIMIT: Duration = Duration::from_secs(30);
    let started = std::time::Instant::now();
    while server.requests_in_flight() > 0 && started.elapsed() < SETTLE_LIMIT {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let left = server.requests_in_flight();
    if left > 0 {
        eprintln!("{}: {left} request(s) still in flight after {SETTLE_LIMIT:?}; the next file may see their log entries", file.file_stem().unwrap().to_string_lossy());
    }
    started.elapsed()
}

/// `"settleMillis": n` on a scenario: it leaves a request in flight on purpose (a step that gives up on a
/// delayed answer), so the recorder waits `n` ms after its last step before the next file on the shared oracle, which
/// reports nothing about requests in progress: else the late `returning response` and exchange land in the next
/// recorded golden. Replay needs no declaration ([`settle`] sees the server's own count).
fn settle_millis(scenario: &Value) -> u64 {
    scenario.get("settleMillis").and_then(Value::as_u64).unwrap_or(0)
}

/// After a scenario recorded on the shared oracle: wait out the requests it abandoned ([`settle_millis`]).
async fn settle_oracle(scenario: &Value) {
    let millis = settle_millis(scenario);
    if millis > 0 {
        tokio::time::sleep(Duration::from_millis(millis)).await;
    }
}

/// A file that kept its shared replay server busy for `waited` after its last step abandoned a request; it
/// must declare `"settleMillis"` covering that, or recording on the shared oracle would leak the late entries into the
/// next golden. Requests a file waited for complete within milliseconds of their answer, so the grace is generous.
fn undeclared_abandon(file: &Path, scenario: &Value, waited: Duration) -> Option<String> {
    const GRACE: Duration = Duration::from_millis(500);
    (waited > GRACE && Duration::from_millis(settle_millis(scenario)) < waited).then(|| {
        format!("{}: left a request in flight for {waited:?} after its last step; declare \"settleMillis\" above that", file.file_stem().unwrap().to_string_lossy())
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_server_port_is_never_a_scenario_literal() {
    // `llm_chaos`'s `"quotaWindowMillis": 60000`, inside macOS's ephemeral range: the failure that range once caused.
    assert!(literal_numbers().contains(&60000));
    let server = start_replay_server(mock_server::Config::for_tests()).await;
    let port = server.ports()[0];
    server.shutdown().await;
    assert!(!literal_numbers().contains(&port), "replay port {port} is spelled out in a scenario");
}

/// A step that gives up on a delayed answer leaves the shared server holding it; [`settle`] keeps the next
/// file off the server until it has been answered, so its exchange and `returning response` entries stay out of the
/// next file's logs (they reached `templates_mustache` from `mcp_contract_http_url_connection`'s 11 s `/slow`).
#[tokio::test(flavor = "multi_thread")]
async fn shared_server_settles_before_the_next_file() {
    let server = start_replay_server(mock_server::Config::for_tests()).await;
    let t = Target::local(server.ports()[0]);
    let delayed = json!({"httpRequest": {"path": "/abandoned"}, "httpResponse": {"body": "late", "delay": {"timeUnit": "MILLISECONDS", "value": 1500}}});
    let leaving = json!({"steps": [
        {"method": "PUT", "path": "/mockserver/expectation", "body": delayed},
        {"method": "GET", "path": "/abandoned", "maxMillis": 200}
    ]});
    run_scenario(&t, &leaving).await;
    settle(&server, Path::new("leaving")).await;
    // the next file's leading reset comes first, then the delay ends
    let next = json!({"steps": [
        {"sleepMillis": 1600},
        {"method": "PUT", "path": "/mockserver/retrieve?type=REQUEST_RESPONSES"},
        {"method": "PUT", "path": "/mockserver/retrieve?type=LOGS"}
    ]});
    let logs = run_scenario(&t, &next).await;
    server.shutdown().await;
    assert_eq!(logs[0]["body"], json!("[]"), "{logs:?}");
    assert!(!logs[1]["body"].as_str().unwrap().contains("late"), "{logs:?}");
}

/// Replay names a file that kept its shared server busy past its last step unless its `"settleMillis"`
/// covers the wait, which the recorder then sleeps on the shared oracle.
#[tokio::test(flavor = "multi_thread")]
async fn abandoning_a_request_needs_settle_millis() {
    let server = start_replay_server(mock_server::Config::for_tests()).await;
    let t = Target::local(server.ports()[0]);
    let delayed = json!({"httpRequest": {"path": "/abandoned"}, "httpResponse": {"body": "late", "delay": {"timeUnit": "MILLISECONDS", "value": 1500}}});
    let leaving = json!({"steps": [
        {"method": "PUT", "path": "/mockserver/expectation", "body": delayed},
        {"method": "GET", "path": "/abandoned", "maxMillis": 200}
    ]});
    run_scenario(&t, &leaving).await;
    let waited = settle(&server, Path::new("leaving")).await;
    let quiet = settle(&server, Path::new("leaving")).await;
    server.shutdown().await;
    assert!(undeclared_abandon(Path::new("leaving"), &leaving, waited).is_some(), "waited {waited:?}");
    // a declaration covering the wait clears it: 2 s covers the 1.5 s delay on a quiet machine, and the measured wait
    // where load stretched it (3.0 s at load ~300)
    let covering = (waited.as_millis() as u64 + 1).max(2000);
    let mut declared = leaving.clone();
    declared["settleMillis"] = json!(covering);
    assert_eq!(undeclared_abandon(Path::new("leaving"), &declared, waited), None);
    assert_eq!(undeclared_abandon(Path::new("leaving"), &leaving, quiet), None, "a settled server waits {quiet:?}");
    let started = std::time::Instant::now();
    settle_oracle(&declared).await;
    assert!(started.elapsed() >= Duration::from_millis(covering));
}

/// A `{{bindport:N}}` port is written back as `N` in every later scenario's answers, so it must not be a
/// number a scenario or golden spells out. 60000 (`chaosAutoHaltWindowMillis`'s default, in every configuration
/// golden) as `{{bindport:4}}`'s port turned it into `4` across the rest of the run.
#[test]
fn bind_port_is_never_a_scenario_literal() {
    assert!(literal_numbers().contains(&60000));
    assert!(!usable_bind_port(60000, &[], &[]), "a scenario literal would be handed out as a bind port");
    let port = fresh_bind_port(&[]);
    assert!(!literal_numbers().contains(&port), "bind port {port} is spelled out in a scenario");
}

/// A moved UDP port another process took between the probe and the bind fails the server's
/// start, which [`udp_port::taken_meanwhile`] must recognise so replay starts again with a fresh port.
#[tokio::test(flavor = "multi_thread")]
async fn replay_sees_a_start_a_taken_udp_port_refused() {
    let taken = std::net::UdpSocket::bind("[::]:0").or_else(|_| std::net::UdpSocket::bind("0.0.0.0:0")).unwrap();
    let port = taken.local_addr().unwrap().port().to_string();
    for props in [vec![("http3Port", port.as_str())], vec![("dnsEnabled", "true"), ("dnsPort", port.as_str())]] {
        let props: Vec<(String, String)> = props.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let refused = try_start_replay_server(replay_config(&props, &json!({}))).await.err().unwrap_or_else(|| panic!("{props:?}: the taken port was bound"));
        assert!(udp_port::taken_meanwhile(&refused), "{props:?}: {refused}");
        let (free, _, _twins) = free_udp_ports(props);
        let server = try_start_replay_server(replay_config(&free, &json!({}))).await.unwrap_or_else(|e| panic!("{free:?}: a free port was not bound: {e}"));
        assert!(server.http3_port().is_some() || server.dns_port().is_some(), "{free:?}: no UDP listener");
        server.shutdown().await;
    }
}

/// While its TCP twin is held, a moved UDP port's number is never handed to an ephemeral TCP bind like
/// the replay server's own (`SO_REUSEADDR`, `0.0.0.0:0`), which [`normalise`] would rewrite to `<port>`. Without the
/// twins about 30 of these binds land on one of the 100 numbers.
#[test]
fn a_moved_udp_port_is_never_an_ephemeral_tcp_port() {
    let held: Vec<(u16, std::net::TcpListener)> = (0..100).map(|_| free_udp_port_with_tcp_twin()).collect();
    let numbers: std::collections::HashSet<u16> = held.iter().map(|(p, _)| *p).collect();
    for _ in 0..5000 {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        socket.set_reuse_address(true).unwrap();
        socket.bind(&std::net::SocketAddr::from(([0, 0, 0, 0], 0)).into()).unwrap();
        let port = socket.local_addr().unwrap().as_socket().unwrap().port();
        assert!(!numbers.contains(&port), "ephemeral TCP port {port} is a moved UDP port");
    }
}

/// A bind's "already in use" names a lost `{{bindport:N}}` port only when no earlier step bound `N`.
#[test]
fn lost_bind_ports_names_only_a_port_no_earlier_step_bound() {
    let bind = |ports: &str| json!({"method": "PUT", "path": "/mockserver/bind", "body": format!("{{\"ports\": [{ports}]}}")});
    let ok = |ports: &str| json!({"status": 200, "body": format!("{{\n  \"ports\" : [ {ports} ]\n}}")});
    let in_use = |port: u16| json!({"status": 400, "body": format!("Exception while binding MockServer to port {port}")});
    let scenario = json!({"steps": [
        bind("{{bindport:31191}}"),
        bind("{{bindport:31191}}"),
        bind("{{bindport:31192}}, {{bindport:31193}}"),
        bind("{{bindport:31192}}"),
        {"method": "PUT", "path": "/bind", "body": "{\"ports\": [{{bindport:31194}}]}"},
    ]});
    let results = [ok("31191"), in_use(31191), in_use(31193), in_use(31192), in_use(31194)];
    // 31191: bound by step 0; 31192: bound by step 2 before 31193 failed; 31193 and 31194: never bound
    assert_eq!(lost_bind_ports(&scenario, &results), vec![31193, 31194]);
    assert_eq!(lost_bind_ports(&scenario, &results[..2]), Vec::<u16>::new());
    // a port the scenario does not declare is the scenario's own business
    assert_eq!(lost_bind_ports(&scenario, &[ok("31191"), in_use(31191), in_use(31195)]), Vec::<u16>::new());
}

/// A `{{bindport:N}}` port another process took between the probe and the bind fails the bind ("port
/// already in use"); the replay sees it and replays the scenario again with a fresh port.
#[tokio::test(flavor = "multi_thread")]
async fn replay_rebinds_a_bindport_port_another_process_took() {
    let taken = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    BIND_PORTS.lock().unwrap().push((31198, port));
    let scenario = json!({"isolated": true, "steps": [{"method": "PUT", "path": "/mockserver/bind", "body": {"ports": ["{{bindport:31198}}"]}}]});
    // the bare run loses the port
    let server = start_replay_server(mock_server::Config::for_tests()).await;
    let lost = run_scenario(&Target::local(server.ports()[0]), &scenario).await;
    server.shutdown().await;
    assert_eq!(lost[0]["status"], json!(400), "{lost:?}");
    assert_eq!(lost_bind_ports(&scenario, &lost), vec![31198]);
    // the replay binds a fresh one
    let runs = replay_scenario(&Target::local(0), &scenario).await;
    let rebound = BIND_PORTS.lock().unwrap().iter().find(|(d, _)| *d == 31198).map(|(_, a)| *a);
    BIND_PORTS.lock().unwrap().retain(|(d, _)| *d != 31198);
    assert_eq!(runs[0].1[0]["status"], json!(200), "{runs:?}");
    assert!(runs[0].1[0]["body"].as_str().unwrap().contains("\"ports\" : [ 31198 ]"), "{runs:?}");
    assert!(rebound.is_some_and(|p| p != port), "{rebound:?}");
    drop(taken);
}

/// The two replay tests run at the same time, and the top-level scenarios replay over a pool of servers
/// ([`replay_workers`]) as the harvested files already did. They coordinate only where a scenario reaches state that
/// is not per server: such a scenario holds this lock exclusively while it replays (one at a time, nothing else
/// running), every other scenario and harvested file holds it shared (see [`process_wide`] for the groups and why).
/// Recording takes no lock: `upstream_scenarios_match_the_oracle` returns at once when recording, and
/// `scenarios_match_the_oracle` records every file, one after the other, against the one oracle.
static PROCESS_WIDE: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

/// Held exclusively by a harvested file that touches scenario states, shared by every other one.
static SCENARIO_STATES: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

/// Why a scenario (top-level or harvested) must replay alone, holding [`PROCESS_WIDE`] exclusively, or `None` when
/// it can replay next to any other. Everything else a scenario touches is per server or per run: its server (reset
/// first, or its own), its captures ([`Target::captures`]), its peer ([`Target::peer_address`],
/// [`Target::node_ports`]), its fixed `http3Port`/`dnsPort` (moved to free ports, [`free_udp_ports`]), and its
/// `{{scratch}}` and `/tmp` files (named after the scenario, no two scenarios share one). The groups, each measured or
/// read from `src/`:
fn process_wide(scenario: &Value) -> Option<&'static str> {
    let text = scenario.to_string();
    // `grpc_plane::HEALTH` is one table for the process: a scenario setting (`PUT /mockserver/grpc/health`) or reading
    // (`grpc.health.v1.Health/Check`) gRPC health statuses would see another server's reset clear them, or another
    // scenario's statuses (measured: `grpc_health` lost its statuses to a concurrent reset).
    if text.contains("grpc.health") || text.contains("/grpc/health") {
        return Some("gRPC health statuses are process-wide (grpc_plane::HEALTH) and every server's reset clears them");
    }
    // `llm::responses::STORE` (the Responses API's stored responses) is one store for the process, cleared by every
    // server's reset.
    if text.contains("/responses") {
        return Some("the LLM Responses store is process-wide (llm::responses::STORE) and every server's reset clears it");
    }
    // `{{bindport:N}}` is one port per declared `N` for the whole process ([`bind_port`]): two scenarios binding the
    // same `N` at once (`bind` and the harvested `B2-PortBindingSerializerTest`) would collide.
    if text.contains("{{bindport:") {
        return Some("{{bindport:N}} is one port per process, so two scenarios binding the same N at once collide");
    }
    // A dynamic CA is written to and read back from `directoryToSaveDynamicSSLCertificate`, which two scenarios name
    // alike (`/tmp`): one could load the CA the other just wrote.
    if text.contains("directoryToSaveDynamicSSLCertificate") {
        return Some("its dynamic CA lives in a directory named in the scenario, which another scenario names too");
    }
    // A write-stall scenario renders, logs and sends 30-40 MB, which takes the process's CPU from the
    // servers beside it (measured: the timed steps of metrics_overload and overload_template_queue timed out), and its
    // own cut needs the server to fill the socket within its stall.
    if text.contains("\"stallMillis\"") {
        return Some("a write stall moves tens of MB, starving the timed steps of scenarios replayed beside it");
    }
    None
}

/// A scenario's fixed `/tmp` names (an MCP fixture or cassette it writes, reads back and deletes, a
/// dynamic CA directory) are the same file for every worktree replaying that scenario on this machine at once, and
/// [`process_wide`] only orders scenarios inside one process. Each name (`/tmp` itself, or its first component under
/// `/tmp`) is a machine-wide lock file, held exclusively (`File::lock`, released when the file closes) while the
/// scenario replays. Taken after [`PROCESS_WIDE`] and before [`SCENARIO_STATES`], in name order, so no two holders
/// wait on each other.
fn tmp_name_locks(scenario: &Value) -> Vec<fs::File> {
    static NAME: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let name = NAME.get_or_init(|| regex::Regex::new(r"(?:^|[^A-Za-z0-9_.-])(/tmp(?:/[A-Za-z0-9_.-]+)?)").unwrap());
    let text = scenario.to_string();
    let names: std::collections::BTreeSet<&str> = name.captures_iter(&text).map(|c| c.get(1).unwrap().as_str()).collect();
    if names.is_empty() {
        return Vec::new();
    }
    // always `/tmp`, whatever `TMPDIR` says: every worktree must agree on the lock's path
    let dir = Path::new("/tmp/mock-server-replay-locks");
    fs::create_dir_all(dir).expect("create the /tmp lock directory");
    tokio::task::block_in_place(|| {
        names
            .into_iter()
            .map(|n| {
                let path = dir.join(format!("{}.lock", n.replace('/', "_")));
                let file = fs::OpenOptions::new().create(true).truncate(false).write(true).open(path).expect("open a /tmp name lock");
                file.lock().expect("lock a /tmp name");
                file
            })
            .collect()
    })
}

/// Each TLS context's CA is loaded, and logged, once per server: the server context's on its first inbound
/// TLS connection, the forwarding client's on its first TLS connection. A long-lived oracle went through both long
/// before most goldens were recorded, so a shared server (replay's, or the oracle a recording shares) goes through
/// them too before any scenario: one TLS handshake, and one TLS forward to a refusing port, then a reset. A scenario
/// whose golden shows those loads runs on a server of its own (`"isolated"` or `"properties"`).
/// After a file recorded on the shared oracle, a `reset` must leave it answering the control plane and an
/// unmatched data-plane request (404). A file whose configuration changes outlive `reset` (data-plane or control-plane
/// authentication, say) would otherwise record every later file against that state; such a file needs a server of
/// its own (`"properties"`).
/// The MCP sessions recording opened, by the address of the server that opened them.
static MCP_SESSIONS: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());

/// MCP sessions outlive `reset`, and `McpSessionManager` keeps at most 100, evicting the least recently
/// used with a WARN (`MCP session limit reached (100), evicted …`) into the log of whichever file opens the 101st. A
/// recording pass opens hundreds on the shared oracle, so each file's are ended (`DELETE /mockserver/mcp`) after it,
/// and every file starts with none.
async fn close_mcp_sessions(t: &Target) {
    let sessions: Vec<String> = {
        let mut all = MCP_SESSIONS.lock().unwrap();
        let (own, others) = std::mem::take(&mut *all).into_iter().partition::<Vec<_>, _>(|(addr, _)| *addr == t.addr);
        *all = others;
        own.into_iter().map(|(_, session)| session).collect()
    };
    for session in sessions {
        send(t, &json!({"method": "DELETE", "path": "/mockserver/mcp", "headers": {"mcp-session-id": session}})).await;
    }
}

async fn assert_shared_oracle_clean(t: &Target) {
    let reset = send(t, &json!({"method": "PUT", "path": "/mockserver/reset"})).await;
    let probe = send(t, &json!({"method": "GET", "path": "/mock-server-shared-oracle-probe"})).await;
    assert!(
        reset["status"] == 200 && probe["status"] == 404,
        "left the shared oracle in a state reset does not clear (reset answered {}, an unmatched request {}): give the file a server of its own",
        reset["status"],
        probe["status"],
    );
    assert_shared_oracle_configuration(t).await;
}

/// The shared oracle's configuration as the recording pass found it (after `warm_tls_contexts`).
static SHARED_ORACLE_CONFIGURATION: std::sync::OnceLock<Value> = std::sync::OnceLock::new();

/// `GET /mockserver/configuration` as JSON, without the subject alternative names an expectation's `Host` header adds
/// to the TLS leaf for good (`HttpState.add`): on the shared oracle they only grow, and nothing a golden holds reads
/// them back.
async fn oracle_configuration(t: &Target) -> Value {
    let answer = send(t, &json!({"method": "GET", "path": "/mockserver/configuration"})).await;
    let mut configuration = match &answer["body"] {
        Value::String(text) => serde_json::from_str(text).unwrap_or(Value::Null),
        body => body.clone(),
    };
    assert!(answer["status"] == 200 && configuration.is_object(), "GET /mockserver/configuration on the shared oracle: {answer}");
    let object = configuration.as_object_mut().unwrap();
    object.remove("sslSubjectAlternativeNameDomains");
    object.remove("sslSubjectAlternativeNameIps");
    configuration
}

/// Configuration survives `reset`, so a file that changes it on the shared oracle changes every file
/// recorded there after it (on 9.2.0, `auth_mtls_configuration_refused` left `maxExpectations: 7`, and `PUT
/// /mockserver/oidc` kept only its last 7 expectations, dropping discovery and JWKS). A file that changes configuration
/// is recorded on an oracle of its own ([`records_on_own_oracle`]); this fails any other file that leaves the shared
/// oracle's configuration other than the pass found it.
async fn assert_shared_oracle_configuration(t: &Target) {
    let now = oracle_configuration(t).await;
    let Some(before) = SHARED_ORACLE_CONFIGURATION.get() else { return };
    let changed: Vec<String> = before
        .as_object()
        .unwrap()
        .iter()
        .chain(now.as_object().unwrap())
        .filter(|(key, _)| before.get(key.as_str()) != now.get(key.as_str()))
        .map(|(key, _)| format!("{key}: {} -> {}", before.get(key.as_str()).unwrap_or(&Value::Null), now.get(key.as_str()).unwrap_or(&Value::Null)))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    assert!(
        changed.is_empty(),
        "left the shared oracle's configuration changed, which reset does not undo ({}): give the file a server of its own",
        changed.join("; "),
    );
}

/// A file recorded on an oracle container of its own rather than the shared one: one with `"properties"`
/// (or `"env"`, `"propertiesFile"`), callback classes, or steps that change the configuration (`changes_configuration`),
/// whose changes would outlive its `reset` into every later file on the shared oracle.
fn records_on_own_oracle(scenario: &Value) -> Option<Vec<(String, String)>> {
    properties(scenario).or_else(|| changes_configuration(scenario).then(Vec::new))
}

async fn warm_tls_contexts(t: &Target) {
    if let Ok(tcp) = tokio::time::timeout(Duration::from_secs(5), connect(&t.addr)).await {
        let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(30), tokio_rustls::TlsConnector::from(trust_all_tls_client()).connect(name, tcp)).await;
    }
    // A client's failed handshake is logged at WARN once per client address and server, later ones at
    // DEBUG (`ClientTlsHandshakeFailureLog`). The harness is one address, whose handshake had failed on the long-lived
    // oracle before most goldens were recorded: a client that trusts no CA, failing with an `unknown_ca` alert.
    if let Ok(tcp) = tokio::time::timeout(Duration::from_secs(5), connect(&t.addr)).await {
        let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(30), tokio_rustls::TlsConnector::from(trust_none_tls_client()).connect(name, tcp)).await;
    }
    let forward = json!({"httpRequest": {"path": "/warm-tls-contexts"}, "httpForward": {"host": "localhost", "port": 1, "scheme": "HTTPS"}});
    send(t, &json!({"method": "PUT", "path": "/mockserver/expectation", "body": forward})).await;
    send(t, &json!({"method": "GET", "path": "/warm-tls-contexts", "maxMillis": 30000})).await;
    send(t, &json!({"method": "PUT", "path": "/mockserver/reset"})).await;
}

/// The shared oracle has served HTTP on every one of its worker event loops long before a file is
/// recorded, so every entry a binary connection logs there carries the port (`HttpState`'s thread-local port is set
/// on a loop's thread by the first HTTP request it handles). A shared replay server gets there the same way: one HTTP
/// request on each of its `nioEventLoopThreadCount` (5) loops, which take connections in turn, one connection a step.
async fn warm_event_loops(t: &Target) {
    for _ in 0..5 {
        send(t, &json!({"method": "PUT", "path": "/mockserver/reset"})).await;
    }
}

/// `MOCK_SERVER_REPLAY_WORKERS`: how many servers replay the top-level scenarios at once. Default: the
/// available parallelism, at most 8 (as many as the harvested replay's servers). `1` replays them one after the
/// other on one server, with the harvested replay held off until they are done, as before the pool.
fn replay_workers() -> usize {
    std::env::var("MOCK_SERVER_REPLAY_WORKERS")
        .ok()
        .map(|n| n.trim().parse::<usize>().ok().filter(|n| *n > 0).expect("MOCK_SERVER_REPLAY_WORKERS: a positive number"))
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, |n| n.get()).min(8))
}

/// The oracle's `java.io.tmpdir` is `/tmp`; so is ours on Linux, and this makes it so on macOS too (MCP file tools,
/// harvested MCP fixture cases). Set once, by whichever replay test gets here first, before it starts a
/// server; the other waits for it.
fn replay_environment() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: set before either replay test starts a server thread that reads the environment.
    ONCE.call_once(|| unsafe { std::env::set_var("TMPDIR", "/tmp") });
}

/// Replays one top-level scenario: on the worker's shared server `t` (its leading reset clears what the previous
/// scenario left), or on a server of its own (an isolated scenario), once per callback provider for a callback-class
/// scenario. Returns each variant's results.
async fn replay_scenario(t: &Target, scenario: &Value) -> Vec<(&'static str, Vec<Value>)> {
    // A callback-class scenario runs once per callback provider: in-process, native plugin, WASM plugin.
    let variants: Vec<(&str, Option<String>)> = if callback_classes(scenario) {
        // builds the plugins once (`cargo build`), off the runtime's worker threads
        let (native, wasm) = tokio::task::block_in_place(callback_plugins);
        vec![("in-process", None), ("native plugin", Some(native)), ("WASM plugin", Some(wasm))]
    } else {
        vec![("", None)]
    };
    let mut runs = Vec::new();
    for (variant, plugin) in variants {
        // A lost `{{bindport:N}}` port replays the scenario again, on a fresh server when it is isolated.
        let plugin = &plugin;
        let actual = replay_binding_ports(scenario, move || async move {
            if is_isolated(scenario) {
                let peer = if has_peer(scenario) { Some(start_replay_server(replay_config(&peer_properties(scenario), &json!({}))).await) } else { None };
                // `"peerNetwork": "shared"`: the peer by a host name, as the recording's first node reaches it.
                let peer_host = if shared_peer_network(scenario) { "localhost" } else { "127.0.0.1" };
                let peer_url = peer.as_ref().map(|p| format!("http://{peer_host}:{}", p.ports()[0])).unwrap_or_default();
                let mut attempt = 1;
                let (own, props, moved, _twins) = loop {
                    let (props, moved, twins) = free_udp_ports(properties_with_peer(scenario, &peer_url).unwrap_or_default());
                    // `{{ownport}}` in a startup value is the server's own port (1080 inside the oracle's
                    // container); the replay server listens on a free one it names before it starts.
                    let own_port = props.iter().any(|(_, v)| v.contains("{{ownport}}")).then(|| fresh_bind_port(&BIND_PORTS.lock().unwrap()));
                    let props: Vec<(String, String)> = match own_port {
                        Some(p) => props.into_iter().map(|(k, v)| (k, v.replace("{{ownport}}", &p.to_string()))).collect(),
                        None => props,
                    };
                    let mut config = replay_config(&props, scenario);
                    if let Some(p) = own_port {
                        config.ports = vec![p];
                    }
                    match (&plugin, callback_classes(scenario)) {
                        (Some(path), _) => config = config.with_property("callbackPlugins", path),
                        (None, true) => {
                            for (name, class) in mock_server_integration_testing_callbacks::classes() {
                                config = config.with_callback_class(&name, class);
                            }
                        }
                        (None, false) => {}
                    }
                    // A moved UDP port another process took between the probe and the bind fails the start: start again,
                    // unless this process holds a socket on it.
                    match try_start_replay_server(config).await {
                        Ok(own) => break (own, props, moved, twins),
                        Err(e) if !moved.is_empty() && udp_port::retry_taken_meanwhile(&e, attempt) => attempt += 1,
                        Err(e) => panic!("start mock-server: {e}"),
                    }
                };
                let own = std::sync::Arc::new(own);
                let port = own.ports()[0];
                if properties(scenario).is_none() {
                    image_healthcheck(port).await;
                }
                let mut t = Target::replayed(&own);
                if scenario.get("warmEventLoops").and_then(Value::as_bool) == Some(true) {
                    assert!(properties(scenario).is_some(), "\"warmEventLoops\" needs a server of its own: give the scenario \"properties\"");
                    warm_event_loops(&t).await;
                }
                t.udp = own.dns_port().map(|port| Udp::Local(format!("127.0.0.1:{port}")));
                t.http3 = own.http3_port().filter(|_| quic(scenario)).map(|port| Udp::Local(format!("127.0.0.1:{port}")));
                if props.iter().any(|(k, v)| k == "metricsEnabled" && v == "true") {
                    // The oracle's container counts two `PUT /mockserver/status` before a scenario's first step: its
                    // `startupWarmup` request and the recording harness's readiness poll (`ConfiguredOracle::start`).
                    // They sit in `mock_server_request_duration_seconds` and its by-method twin; ours sends the warm-up
                    // itself, and the readiness poll is sent here.
                    send(&t, &json!({"method": "PUT", "path": "/mockserver/status"})).await;
                    // ...and `ConfiguredOracle::await_started`'s retrieval that sees the warm-up counted.
                    send(&t, &json!({"method": "PUT", "path": "/mockserver/retrieve?type=METRICS"})).await;
                }
                let mut peer_target = peer.as_ref().map(|p| Target::local(p.ports()[0]));
                if let Some(p) = &mut peer_target {
                    let ports = vec![p.port, port];
                    let address = p.host.clone();
                    p.node_ports = ports.clone();
                    p.peer_address = address.clone();
                    t.node_ports = ports;
                    t.peer_address = address;
                }
                let actual = run_scenario_with_peer(&t, peer_target.as_ref(), scenario).await;
                std::sync::Arc::into_inner(own).expect("the replay server is held only here").shutdown().await;
                if let Some(p) = peer {
                    p.shutdown().await;
                }
                declared_ports(actual, &moved)
            } else {
                run_scenario(t, scenario).await
            }
        })
        .await;
        runs.push((variant, actual));
    }
    runs
}

#[tokio::test(flavor = "multi_thread")]
async fn scenarios_match_the_oracle() {
    scratch_cwd::enter();
    if let Ok(oracle) = std::env::var("MOCK_SERVER_RECORD_ORACLE") {
        let addr = oracle.trim_start_matches("http://").trim_end_matches('/').to_string();
        let t = Target::oracle(addr);
        if !scenario_files().is_empty() {
            warm_tls_contexts(&t).await;
        }
        if !scenario_files().is_empty() || !upstream_files().is_empty() {
            SHARED_ORACLE_CONFIGURATION.set(oracle_configuration(&t).await).unwrap();
        }
        // `MOCK_SERVER_RECORD_RESUME`: skip a file whose golden the same image already recorded (a re-pin's
        // interrupted pass). A file whose recording panics (e.g. an oracle that refuses to start with its
        // properties) is listed at the end instead of ending the pass.
        let resume = std::env::var_os("MOCK_SERVER_RECORD_RESUME").is_some();
        let mut failed: Vec<String> = Vec::new();
        for file in scenario_files() {
            let scenario = load(&file);
            if resume && recorded_from(&file).as_deref() == Some(image(&scenario).as_str()) {
                continue;
            }
            let libs = callback_classes(&scenario).then(oracle_libs);
            let recorded = AssertUnwindSafe(async { match records_on_own_oracle(&scenario).or_else(|| libs.as_ref().map(|_| Vec::new())) {
                Some(_) if has_peer(&scenario) && shared_peer_network(&scenario) => {
                    // The first node starts first, publishing the peer's port as well; the peer joins its network.
                    let peer_url = format!("http://localhost:{SHARED_PEER_PORT}");
                    let properties = properties_with_peer(&scenario, &peer_url).unwrap_or_default();
                    let startup = Startup { publish: vec![SHARED_PEER_PORT], ..Startup::of(&scenario) };
                    let oracle = ConfiguredOracle::start_with(&properties, libs.as_deref(), &image(&scenario), &startup).await;
                    let mut peer_props = peer_properties(&scenario);
                    peer_props.push(("serverPort".into(), SHARED_PEER_PORT.to_string()));
                    let joined = Startup { network: Some((oracle.id.clone(), published(&oracle.id, SHARED_PEER_PORT))), ..Startup::default() };
                    let peer = ConfiguredOracle::start_with(&peer_props, None, &peer_image(&scenario), &joined).await;
                    let peer_address = format!("localhost:{SHARED_PEER_PORT}");
                    let mut own = Target::oracle(oracle.addr.clone());
                    own.peer_address = peer_address.clone();
                    let peer_target = Target { peer_address, ..Target::new(peer.addr.clone(), format!("localhost:{SHARED_PEER_PORT}"), SHARED_PEER_PORT) };
                    let results = run_scenario_with_peer(&own, Some(&peer_target), &scenario).await;
                    drop(peer);
                    results
                }
                Some(properties) => {
                    let peer = if has_peer(&scenario) { Some(ConfiguredOracle::start(&peer_properties(&scenario), None, &peer_image(&scenario)).await) } else { None };
                    let properties = match &peer {
                        Some(p) => properties_with_peer(&scenario, &p.bridge_url()).unwrap_or_default(),
                        None => properties,
                    };
                    let oracle = ConfiguredOracle::start_with(&properties, libs.as_deref(), &image(&scenario), &Startup::of(&scenario)).await;
                    let peer_address = peer.as_ref().map(|p| p.bridge_url().trim_start_matches("http://").to_string()).unwrap_or_default();
                    let mut own = Target::oracle(oracle.addr.clone());
                    own.udp = udp_port(&properties).map(|port| Udp::Container { id: oracle.id.clone(), port });
                    own.http3 = http3_port(&scenario, &properties).map(|port| Udp::Container { id: oracle.id.clone(), port });
                    own.peer_address = peer_address.clone();
                    let peer_target = peer.as_ref().map(|p| Target { peer_address: peer_address.clone(), ..Target::oracle(p.addr.clone()) });
                    run_scenario_with_peer(&own, peer_target.as_ref(), &scenario).await
                }
                None => {
                    let results = run_scenario(&t, &scenario).await;
                    settle_oracle(&scenario).await;
                    close_mcp_sessions(&t).await;
                    assert_shared_oracle_clean(&t).await;
                    results
                }
            } })
            .catch_unwind()
            .await;
            let results = match recorded {
                Ok(results) => results,
                Err(panic) => {
                    failed.push(format!("{}: {}", file.display(), panic_text(&panic)));
                    continue;
                }
            };
            let mut golden = Map::new();
            golden.insert("recordedFrom".into(), json!(image(&scenario)));
            if scenario.get("peerImage").is_some() {
                golden.insert("peerRecordedFrom".into(), json!(peer_image(&scenario)));
            }
            golden.insert("results".into(), Value::Array(results));
            fs::write(recorded_golden_path(&file), serde_json::to_string_pretty(&golden).unwrap() + "\n").unwrap();
            eprintln!("recorded {}", file.display());
        }
        // Harvested cases: recorded twice; cases whose answers differ are the oracle's own nondeterminism.
        for file in upstream_files() {
            let scenario = load(&file);
            if resume && recorded_from(&file).as_deref() == Some(oracle_image()) {
                continue;
            }
            let recorded = AssertUnwindSafe(async {
            // A harvested file with `"properties"` (a case recorded from an engine built with a non-default
            // Configuration) is recorded on an oracle container started with them.
            let mut configured = match records_on_own_oracle(&scenario) {
                Some(properties) => Some(ConfiguredOracle::start(&properties, None, oracle_image()).await),
                None => None,
            };
            let t = match &configured {
                Some(oracle) => Target::oracle(oracle.addr.clone()),
                None => Target::new(t.addr.clone(), t.host.clone(), t.port),
            };
            let first = run_scenario(&t, &scenario).await;
            settle_oracle(&scenario).await;
            close_mcp_sessions(&t).await;
            if configured.is_none() {
                assert_shared_oracle_configuration(&t).await;
            }
            // a configured file is replayed on a fresh server of its own, so its second recording is too
            let second = match configured.take() {
                Some(oracle) => {
                    drop(oracle);
                    let fresh = ConfiguredOracle::start(&records_on_own_oracle(&scenario).unwrap_or_default(), None, oracle_image()).await;
                    let t = Target::oracle(fresh.addr.clone());
                    run_scenario(&t, &scenario).await
                }
                None => {
                    let results = run_scenario(&t, &scenario).await;
                    settle_oracle(&scenario).await;
                    close_mcp_sessions(&t).await;
                    assert_shared_oracle_configuration(&t).await;
                    results
                }
            };
            (first, second)
            })
            .catch_unwind()
            .await;
            let (first, second) = match recorded {
                Ok(runs) => runs,
                Err(panic) => {
                    failed.push(format!("{}: {}", file.display(), panic_text(&panic)));
                    continue;
                }
            };
            let ids = case_ids(&scenario);
            let mut unstable: Vec<String> = ids.iter().zip(first.iter().zip(&second)).filter(|(_, (a, b))| a != b).map(|(id, _)| id.clone()).collect();
            unstable.dedup();
            let mut golden = Map::new();
            golden.insert("recordedFrom".into(), json!(oracle_image()));
            golden.insert("unstable".into(), json!(unstable));
            golden.insert("results".into(), Value::Array(first));
            fs::write(recorded_golden_path(&file), serde_json::to_string_pretty(&golden).unwrap() + "\n").unwrap();
            eprintln!("recorded {} ({} unstable cases)", file.display(), unstable.len());
        }
        assert!(failed.is_empty(), "{} file(s) not recorded:\n{}", failed.len(), failed.join("\n"));
        return;
    }

    replay_environment();
    let workers = replay_workers();
    // One worker: the scenarios one after the other on one server, and nothing of the harvested replay meanwhile.
    let _alone = if workers == 1 { Some(PROCESS_WIDE.write().await) } else { None };
    // Each worker replays the next scenario in file order (isolated ones last) on its own shared server; results are
    // compared below in file order, so the failure report reads as it did when they ran one after the other.
    let skips = scenario_skips();
    let whole_skipped = |file: &PathBuf| skips.contains_key(&(stem(file), None));
    let queue = std::sync::Arc::new(std::sync::Mutex::new(
        scenario_files().into_iter().filter(|f| !whole_skipped(f)).enumerate().collect::<std::collections::VecDeque<_>>(),
    ));
    let mut handles = Vec::new();
    for _ in 0..workers {
        let queue = queue.clone();
        handles.push(tokio::spawn(async move {
            let server = std::sync::Arc::new(start_replay_server(mock_server::Config::for_tests()).await);
            image_healthcheck(server.ports()[0]).await;
            let t = Target::replayed(&server);
            // the warm-ups reset the server, which clears process-wide state (the LLM Responses store) a scenario
            // replaying alone on another worker may be using
            {
                let _shared = if workers > 1 { Some(PROCESS_WIDE.read().await) } else { None };
                warm_tls_contexts(&t).await;
                warm_event_loops(&t).await;
            }
            let mut done = Vec::new();
            loop {
                let Some((index, file)) = queue.lock().unwrap().pop_front() else { break };
                let scenario = load(&file);
                let alone = workers > 1 && process_wide(&scenario).is_some();
                let replayed = async {
                    let _exclusive = if alone { Some(PROCESS_WIDE.write().await) } else { None };
                    let _shared = if workers > 1 && !alone { Some(PROCESS_WIDE.read().await) } else { None };
                    let _tmp_names = tmp_name_locks(&scenario);
                    let runs = replay_scenario(&t, &scenario).await;
                    // still under the scenario's locks: what it left in flight belongs to it
                    let waited = settle(&server, &file).await;
                    (runs, undeclared_abandon(&file, &scenario, waited))
                };
                match futures_util::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(replayed)).await {
                    Ok((runs, abandon)) => done.push((index, file, runs, abandon)),
                    Err(panic) => {
                        eprintln!("{}: replay panicked", file.file_stem().unwrap().to_string_lossy());
                        std::sync::Arc::into_inner(server).expect("the replay server is held only here").shutdown().await;
                        std::panic::resume_unwind(panic);
                    }
                }
            }
            std::sync::Arc::into_inner(server).expect("the replay server is held only here").shutdown().await;
            done
        }));
    }
    let mut replayed = Vec::new();
    let mut panicked = None;
    for handle in handles {
        match handle.await {
            Ok(done) => replayed.extend(done),
            Err(e) if e.is_panic() => panicked = panicked.or(Some(e.into_panic())),
            Err(e) => panic!("replay worker: {e}"),
        }
    }
    if let Some(panic) = panicked {
        std::panic::resume_unwind(panic);
    }
    replayed.sort_by_key(|r| r.0);

    let mut failures = Vec::new();
    for (_, file, runs, abandon) in replayed {
        failures.extend(abandon);
        let golden = load(&golden_path(&file));
        let expected = golden["results"].as_array().unwrap();
        for (_variant, actual) in runs {
            // `MOCK_SERVER_DUMP=<dir>`: writes each scenario's actual results there, shaped like its golden.
            if let Ok(dir) = std::env::var("MOCK_SERVER_DUMP") {
                let path = Path::new(&dir).join(golden_path(&file).file_name().unwrap());
                fs::write(path, serde_json::to_string_pretty(&json!({"results": actual})).unwrap() + "\n").unwrap();
            }
            let steps = load(&file)["steps"].as_array().unwrap().iter().filter(|s| s.get("sleepMillis").is_none()).cloned().collect::<Vec<_>>();
            for (i, (e, a)) in expected.iter().zip(actual.iter()).enumerate() {
                // `"compare": "status"` marks a step whose body is a recorded divergence (docs/divergences.md).
                // `"compare": "json"`: a body whose object key order the oracle does not keep stable (a Java `HashMap` keyed
                // by identity-hashed enums, or fields collected from a parallel/unordered source, e.g. `debugMismatch`
                // differences reached through an MCP `tools/call` wrapper); status, headers and the body as JSON must
                // still agree. [`deep_parse_embedded_json`] also re-parses any string value that looks like a JSON
                // object/array (recursively), so a JSON document embedded as a string inside the body — an MCP
                // `tools/call` response's `"content"[0]."text"`, say — is compared as JSON too, not byte-for-byte
                // (confirmed unstable by recording the same scenario against the oracle 5 times).
                let compare = steps.get(i).and_then(|s| s.get("compare")).and_then(Value::as_str);
                // `"diverge"`: an adopted post-8.0.0 upstream fix (a `docs/divergences.md` row) changes this
                // step's answer. The golden keeps what the 8.0.0 oracle said; replay checks ours against the step's
                // own expectation instead (see [`diverged`]).
                if let Some(diverge) = steps.get(i).and_then(|s| s.get("diverge")) {
                    if let Some(reason) = diverged(diverge, a) {
                        failures.push(format!("{} step {i} (diverge): {reason}\nactual: {a}", file.file_stem().unwrap().to_string_lossy()));
                    }
                    continue;
                }
                // A golden recorded before analytics values were normalised holds the oracle image's analytics endpoint and key: read as ours.
                let analytics_golden = golden_analytics_as_ours(e);
                let e = analytics_golden.as_ref().unwrap_or(e);
                // A masked step's golden recorded before [`mask`] took a `<port>`-normalised `content-length` as a length.
                let masked_golden;
                let e = match steps.get(i).filter(|s| s.get("mask").is_some()) {
                    Some(_) if e["headers"].as_array().is_some_and(|h| h.iter().any(|l| l == "content-length: <port>")) => {
                        masked_golden = {
                            let mut e = e.clone();
                            mask(&mut e, &[]);
                            e
                        };
                        &masked_golden
                    }
                    _ => e,
                };
                let differs = match compare {
                    Some("status") => e.get("status") != a.get("status"),
                    Some("json") => {
                        let body = |r: &Value| r.get("body").and_then(Value::as_str).and_then(|b| serde_json::from_str::<Value>(b).ok()).map(deep_parse_embedded_json);
                        e.get("status") != a.get("status") || e.get("headers") != a.get("headers") || body(e).is_none() || body(e) != body(a)
                    }
                    // `"compare": "unordered"`, for a log whose entries come from racing threads (the oracle's
                    // binary-forward failure WARNs are logged by the event loop and the scheduler, in either order): the
                    // body's entries (a JSON array's elements, or the text log's `---` separated blocks) as a multiset.
                    Some("unordered") => e.get("status") != a.get("status") || e.get("headers") != a.get("headers") || unordered_body(e).is_none() || unordered_body(e) != unordered_body(a),
                    Some(other) => panic!("unknown \"compare\": {other}"),
                    _ => e != a,
                };
                // `tests/scenarios/skips-rs.txt`: a step listed there is a to-do that must still differ.
                if let Some(reason) = skips.get(&(stem(&file), Some(i))) {
                    if !differs {
                        failures.push(format!("{} step {i} matches now: remove it from skips-rs.txt ({reason})", stem(&file)));
                    }
                    continue;
                }
                if differs {
                    failures.push(format!(
                        "{} step {i}{}:\n{}",
                        file.file_stem().unwrap().to_string_lossy(),
                        e.get("note").map(|n| format!(" ({n})")).unwrap_or_default(),
                        describe_difference(e, a),
                    ));
                }
            }
        }
    }
    scratch_cwd::assert_repository_root_untouched();
    assert!(failures.is_empty(), "{} mismatches:\n\n{}", failures.len(), failures.join("\n\n"));
}

/// A `"diverge": {"row": …, "status": n, "contains": [text, …], "lacks": [text, …], "headers": [line, …],
/// "lacksHeaders": [line, …], "closed": bool}` step's check of our answer: its status, texts its body (a tcp step's
/// answer) must and must not contain, header lines it must and must not have, and whether a tcp step's connection closed. `row` names the `docs/divergences.md` row; it must be
/// there. `None` when the answer agrees.
fn diverged(diverge: &Value, actual: &Value) -> Option<String> {
    let row = diverge.get("row").and_then(Value::as_str).unwrap_or_default();
    if row.is_empty() || !fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/divergences.md")).unwrap_or_default().contains(row) {
        return Some(format!("\"row\" {row:?} names no docs/divergences.md row"));
    }
    if let Some(status) = diverge.get("status") && actual.get("status") != Some(status) {
        return Some(format!("status {:?}, expected {status}", actual.get("status")));
    }
    // a tcp step's answer is its body: `tcpText`, or the `tcp` base64 decoded (lossily) as text
    let body = match (actual.get("body"), actual.get("tcpText"), actual.get("tcp").and_then(Value::as_str)) {
        (Some(b), _, _) => b.as_str().map(str::to_string).unwrap_or_else(|| b.to_string()),
        (None, Some(text), _) => text.as_str().unwrap_or_default().to_string(),
        (None, None, Some(b64)) => {
            use base64::Engine;
            String::from_utf8_lossy(&base64::engine::general_purpose::STANDARD.decode(b64).unwrap_or_default()).into_owned()
        }
        _ => String::new(),
    };
    let texts = |key: &str| diverge.get(key).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>();
    if let Some(missing) = texts("contains").into_iter().find(|t| !body.contains(t)) {
        return Some(format!("body lacks {missing:?}"));
    }
    if let Some(present) = texts("lacks").into_iter().find(|t| body.contains(t)) {
        return Some(format!("body contains {present:?}"));
    }
    // `"headers"` / `"lacksHeaders"`: whole response header lines (`name: value`, as recorded) ours must and must not
    // have (an adopted fix that changes a header, not the body)
    let lines = actual.get("headers").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect::<Vec<_>>();
    if let Some(missing) = texts("headers").into_iter().find(|h| !lines.contains(h)) {
        return Some(format!("no header line {missing:?}"));
    }
    if let Some(present) = texts("lacksHeaders").into_iter().find(|h| lines.contains(h)) {
        return Some(format!("header line {present:?}"));
    }
    // `"closed"`: for a tcp step, whether the server must have closed the connection within the read
    if let Some(closed) = diverge.get("closed") && actual.get("closed") != Some(closed) {
        return Some(format!("closed {:?}, expected {closed}", actual.get("closed")));
    }
    None
}

/// `{{deadhost}}` must never again be a port anything could plausibly bind. Three designs have failed
/// this test in turn: the literal `localhost:18999` (a parallel worktree's own ephemeral test server could
/// coincidentally bind it); the privileged `localhost:1` (this sandbox lets an unprivileged process bind
/// privileged ports too — a harvested upstream test, `PUT /mockserver/bind {"ports":[1,2,3,4,5]}` in
/// `B2-PortBindingSerializerTest`, really listens on port 1 here); and an OS-assigned ephemeral port freed right
/// after reading it (this same test run's own many replay servers, each on its own `bind(0)`, can get handed that
/// exact number back before `{{deadhost}}` is ever dialled — observed for real on the main tree). `{{deadhost}}`
/// is now [`dead_host`]/[`dead_port`] — derived from `ORACLE_PORT`, outside the ephemeral range entirely. This is
/// a cheap, static guard against reintroducing any of the three.
#[test]
fn dead_host_is_not_a_historically_fixed_port() {
    let dead = dead_host();
    assert_ne!(dead, "localhost:18999", "must not be the old fixed port — unsafe with several worktrees running at once");
    assert_ne!(dead, "localhost:1", "must not be a fixed privileged port either — this sandbox lets unprivileged binds claim those too");
}

/// Proves [`dead_port`]'s actual mechanism: a real, direct connection to it is refused (`ECONNREFUSED`), not
/// accepted and not silently dropped.
#[tokio::test]
async fn dead_host_refuses_a_direct_connection() {
    if std::env::var("MOCK_SERVER_RECORD_ORACLE").is_ok() {
        return; // nothing to record; this only exercises our own client against our own derived port
    }
    let addr = format!("127.0.0.1:{}", dead_port());
    match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await {
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
        Ok(Err(e)) => panic!("expected {addr} to refuse the connection, got a different error: {e}"),
        Ok(Ok(_)) => panic!("connected to {addr} — the derived dead port must refuse every connection"),
        Err(_) => panic!("connecting to {addr} timed out instead of being refused"),
    }
}

/// An `h2raw` step has an overall deadline. The peer here accepts and never reads, so a request body
/// larger than the socket buffers blocks the write for good; the step must panic once its budget is spent.
#[test]
fn h2raw_step_never_outlives_its_deadline() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a silent peer");
    let port = listener.local_addr().unwrap().port();
    let t = Target::new(format!("127.0.0.1:{port}"), "localhost".to_string(), port);
    let step = json!({"h2raw": {"method": "POST", "path": "/p", "body": "a".repeat(64 << 20), "readMillis": 200, "marginMillis": 500}});
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let started = std::time::Instant::now();
    let outcome = runtime.block_on(async { tokio::time::timeout(Duration::from_secs(20), std::panic::AssertUnwindSafe(send_h2raw(&t, &step)).catch_unwind()).await });
    let outcome = outcome.expect("the h2raw step outlived its own deadline by far");
    assert!(outcome.is_err(), "a stuck h2raw step must fail, not return an answer");
    assert!(started.elapsed() < Duration::from_secs(10), "failed after {:?}", started.elapsed());
    drop(listener);
}

/// A foreign listener on the derived port moves `{{deadhost}}` to a refusing one instead of turning
/// into a live dead host.
#[test]
fn dead_port_skips_an_occupied_port() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a probe listener");
    let busy = listener.local_addr().unwrap().port();
    assert!(!port_refuses(busy), "a listening port must not count as refusing");
    assert_eq!(pick_refusing_port(30000, 3, |p| p != 30000), 30001);
    assert_eq!(pick_refusing_port(30000, 3, |_| true), 30000);
    assert!(std::panic::catch_unwind(|| pick_refusing_port(30000, 3, |_| false)).is_err());
    let dead = dead_port();
    assert!(port_refuses(dead), "dead_port() {dead} must refuse");
}

/// No scenario may dial or bind a fixed port that something on this machine could be listening on.
/// A scenario that forwards or connects to a dead address uses `{{deadhost}}`/`{{deadport}}`; one that binds a port
/// uses `{{bindport:N}}`. A literal `1`-`5`, `1090`, `18999` or `3111x` is taken from a parallel worktree's replay
/// (the port-binding cases once bound 1-5 for real), after which the "dead" host answers.
/// The harvested `upstream/` scenarios are checked for the `"port"`/`"ports"` JSON fields only: two of them name
/// `localhost:1090` inside a template's text, which is echoed, never dialled.
#[test]
fn scenarios_name_no_fixed_listening_port() {
    let fixed = r"(?:[1-5]|1090|18999|3111\d)";
    let port_field = fancy_regex::Regex::new(&format!(r#"\\*"port\\*"\s*:\s*{fixed}\b"#)).unwrap();
    let address = fancy_regex::Regex::new(&format!(r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]):{fixed}\b")).unwrap();
    let ports_field = fancy_regex::Regex::new(r#"\\*"ports\\*"\s*:\s*\[([^\]]*)\]"#).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/scenarios");
    let mut offences = Vec::new();
    for (dir, harvested) in [(root.clone(), false), (root.join("upstream"), true)] {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !name.ends_with(".json") || name.ends_with(".golden.json") {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            for (n, line) in text.lines().enumerate() {
                let mut hits: Vec<String> = Vec::new();
                if port_field.is_match(line).unwrap() {
                    hits.push("a literal \"port\"".into());
                }
                if !harvested && address.is_match(line).unwrap() {
                    hits.push("a literal host:port".into());
                }
                for caps in ports_field.captures_iter(line).flatten() {
                    // Escaped JSON inside a string body (`\"ports\" : [ 0, 9 ]`, `\n` between items) too.
                    let list = caps[1].replace("\\n", " ").replace('\\', "");
                    for item in list.split(',').map(|i| i.trim().trim_matches('"')) {
                        if !item.is_empty() && item != "0" && !item.starts_with("{{bindport:") {
                            hits.push(format!("a literal bound port {item}"));
                        }
                    }
                }
                for h in hits {
                    offences.push(format!("{name}:{}: {h}; use {{{{deadhost}}}}/{{{{deadport}}}}/{{{{bindport:N}}}}", n + 1));
                }
            }
        }
    }
    assert!(offences.is_empty(), "{} fixed ports:\n{}", offences.len(), offences.join("\n"));
}

/// A forward's logged `timing` carries `timeToFirstByteInMillis` only when it went out on a new upstream connection
/// (`Timing::json`): one on a pooled keep-alive connection has none. The forward connection pool survives `reset` on
/// the oracle too: on a shared server, an earlier scenario's self-forward leaves a pooled connection to
/// the same `localhost:<port>` for up to `forwardConnectionPoolIdleTimeoutMillis`. So a golden that logs a forward's
/// timing must be recorded and replayed on a server of its own: `"properties"`, because an `"isolated"` file without
/// them is replayed on a fresh server but recorded on the shared oracle (`log_entries_typed` and
/// `path_parameters_log_entries` were, at the re-pin, and lost the field).
#[test]
fn scenarios_logging_forward_timing_have_their_own_oracle() {
    let mut offences = Vec::new();
    for path in json_files(&scenarios_dir()) {
        let golden = golden_path(&path);
        let logs_it = fs::read_to_string(&golden).is_ok_and(|text| text.contains("connectionTimeInMillis"));
        if logs_it && properties(&load(&path)).is_none() {
            offences.push(path.file_name().unwrap().to_string_lossy().to_string());
        }
    }
    assert!(offences.is_empty(), "golden logs a forward's timing but the scenario has no \"properties\": {}", offences.join(", "));
}

/// The `"case"` id of each non-sleep step.
fn case_ids(scenario: &Value) -> Vec<String> {
    scenario["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s.get("sleepMillis").is_none())
        .map(|s| s["case"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// `skips-rs.txt`: `<case id>  # <reason>` per line.
fn upstream_skips() -> std::collections::BTreeMap<String, String> {
    let text = fs::read_to_string(upstream_dir().join("skips-rs.txt")).unwrap_or_default();
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (id, reason) = l.split_once('#').unwrap_or((l, ""));
            (id.trim().to_string(), reason.trim().to_string())
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_scenarios_match_the_oracle() {
    scratch_cwd::enter();
    if std::env::var("MOCK_SERVER_RECORD_ORACLE").is_ok() {
        return; // recorded by scenarios_match_the_oracle, one oracle client at a time
    }
    let files = upstream_files();
    if files.is_empty() {
        return;
    }
    replay_environment();
    // Files are independent (every case starts with a reset), so they are spread over several servers.
    let queue = std::sync::Arc::new(std::sync::Mutex::new(files.into_iter().enumerate().collect::<Vec<_>>()));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let queue = queue.clone();
        workers.push(tokio::spawn(async move {
            let server = start_replay_server(mock_server::Config::for_tests()).await;
            let port = server.ports()[0];
            let t = Target::local(port);
            let mut done = Vec::new();
            loop {
                let Some((index, file)) = queue.lock().unwrap().pop() else { break };
                let scenario = load(&file);
                let golden = load(&golden_path(&file));
                // Next to the top-level scenarios replaying at the same time: see [`process_wide`].
                let alone = process_wide(&scenario).is_some();
                let _exclusive = if alone { Some(PROCESS_WIDE.write().await) } else { None };
                let _shared = if alone { None } else { Some(PROCESS_WIDE.read().await) };
                let _tmp_names = tmp_name_locks(&scenario);
                // Scenario states are process-wide, like upstream's JVM-wide `CrossProtocolEventBus` ScenarioManager,
                // so the servers of this replay share them: a file that uses them runs alone (every other file's
                // leading reset would clear them).
                let states = scenario.to_string().to_ascii_lowercase().contains("scenario");
                let actual = if upstream_own_server(&scenario) {
                    // Replayed on a server of its own, started with the file's properties. An `"isolated"` file changes
                    // state `reset` does not clear (configuration, bound ports), which the worker's server would carry
                    // into the files replayed on it after this one.
                    let _states_alone = if states { Some(SCENARIO_STATES.write().await) } else { None };
                    let _states_shared = if states { None } else { Some(SCENARIO_STATES.read().await) };
                    let scenario = &scenario;
                    // a lost `{{bindport:N}}` port replays the file again, on a fresh server
                    replay_binding_ports(scenario, move || async move {
                        // a fresh `Config` each time: clones of one share its runtime (`PUT /mockserver/configuration`) values
                        let config = replay_config(&properties(scenario).unwrap_or_default(), scenario);
                        let own = start_replay_server(config).await;
                        let t = Target::local(own.ports()[0]);
                        let actual = run_scenario(&t, scenario).await;
                        own.shutdown().await;
                        actual
                    })
                    .await
                } else if states {
                    let _alone = SCENARIO_STATES.write().await;
                    run_scenario(&t, &scenario).await
                } else {
                    let _shared = SCENARIO_STATES.read().await;
                    // a lost `{{bindport:N}}` port replays the file again
                    let (t, scenario) = (&t, &scenario);
                    replay_binding_ports(scenario, move || run_scenario(t, scenario)).await
                };
                let abandon = undeclared_abandon(&file, &scenario, settle(&server, &file).await);
                done.push((index, file, scenario, golden, actual, abandon));
            }
            server.shutdown().await;
            done
        }));
    }
    let mut runs = Vec::new();
    for worker in workers {
        runs.extend(worker.await.expect("worker"));
    }
    runs.sort_by_key(|r| r.0);

    let skips = upstream_skips();
    let mut problems = Vec::new();
    let mut tally: std::collections::BTreeMap<String, [usize; 4]> = Default::default(); // cases, passing, skipped-rs, unstable
    let mut replayed = Vec::new(); // the stems of the files this run replayed
    let mut report = Vec::new(); // (stem, tally row)
    let mut diffs = Vec::new(); // (stem, the first difference of every case that does not match, listed or not)
    for (_, file, scenario, golden, actual, abandon) in runs {
        problems.extend(abandon);
        let stem = file.file_stem().unwrap().to_string_lossy().into_owned();
        // `MOCK_SERVER_DUMP=<dir>`, as for the top-level scenarios: each file's actual results, shaped like its golden.
        if let Ok(dir) = std::env::var("MOCK_SERVER_DUMP") {
            let path = Path::new(&dir).join(golden_path(&file).file_name().unwrap());
            fs::write(path, serde_json::to_string_pretty(&json!({"results": actual})).unwrap() + "\n").unwrap();
        }
        replayed.push(stem.clone());
        let unstable: Vec<&str> = golden["unstable"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        let expected = golden["results"].as_array().unwrap();
        let ids = case_ids(&scenario);
        let steps: Vec<&Value> = scenario["steps"].as_array().unwrap().iter().filter(|s| s.get("sleepMillis").is_none()).collect();
        let mut cases: Vec<(String, bool, String)> = Vec::new(); // id, matches, first difference
        for (i, id) in ids.iter().enumerate() {
            if cases.last().is_none_or(|c| &c.0 != id) {
                cases.push((id.clone(), true, String::new()));
            }
            let analytics_golden = golden_analytics_as_ours(&expected[i]);
            let (e, a) = (analytics_golden.as_ref().unwrap_or(&expected[i]), &actual[i]);
            let case = cases.last_mut().unwrap();
            // `"diverge"` as in [`scenarios_match_the_oracle`]: an adopted post-8.0.0 fix changes this step's answer
            let difference = match steps.get(i).and_then(|s| s.get("diverge")) {
                Some(diverge) => diverged(diverge, a).map(|reason| format!("diverge: {reason}")),
                None => (e != a).then(|| describe_difference(e, a)),
            };
            if let (true, Some(difference)) = (case.1, difference) {
                case.1 = false;
                case.2 = format!("step {i}{}:\n{difference}", e.get("note").map(|n| format!(" ({n})")).unwrap_or_default());
            }
        }
        let counts = tally.entry(stem.split('-').next().unwrap_or("B?").to_string()).or_default();
        for (id, matches, difference) in cases {
            counts[0] += 1;
            if !matches {
                diffs.push((stem.clone(), format!("== {stem} case {id} {difference}\n")));
            }
            let result = if unstable.contains(&id.as_str()) {
                counts[3] += 1;
                "unstable"
            } else if let Some(reason) = skips.get(&id) {
                counts[2] += 1;
                if matches {
                    problems.push(format!("{stem} case {id} matches now: remove it from skips-rs.txt ({reason})"));
                }
                "skip-rs"
            } else if matches {
                counts[1] += 1;
                "pass"
            } else {
                problems.push(format!("{stem} case {id} {difference}"));
                "fail"
            };
            report.push((stem.clone(), format!("{stem}\t{id}\t{result}\n")));
        }
    }
    write_upstream_results(&replayed, report, diffs);
    for (tranche, [cases, passing, skipped, unstable]) in &tally {
        eprintln!("{tranche}: {cases} cases, {passing} passing, {skipped} skipped-rs, {unstable} oracle-unstable");
    }
    scratch_cwd::assert_repository_root_untouched();
    assert!(problems.is_empty(), "{} upstream case problems:\n\n{}", problems.len(), problems.join("\n\n"));
}

/// Writes `target/upstream-scenario-results.tsv` and `target/upstream-scenario-diffs.txt`, each under a
/// first line naming the replay that wrote it, which `conformance/coverage.py` checks. An unfiltered replay replaces
/// both (`# replay full <ts>`). A `MOCK_SERVER_SCENARIO` replay merges into them by file: the rows of every file it
/// replayed replace that file's rows, the other files' rows stay, and the line becomes `# replay filtered <ts>
/// MOCK_SERVER_SCENARIO=<f> files=<n> base=full <ts0>`. Rows are kept only when both files name the same full run
/// as their base; otherwise the merge starts empty and says `base=none`.
fn write_upstream_results(replayed: &[String], report: Vec<(String, String)>, diffs: Vec<(String, String)>) {
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
    let (tsv, txt) = (target.join("upstream-scenario-results.tsv"), target.join("upstream-scenario-diffs.txt"));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let (marker, mut report, mut diffs) = match std::env::var("MOCK_SERVER_SCENARIO") {
        Err(_) => (format!("# replay full {now}"), report, diffs),
        Ok(filter) => {
            let (old_tsv, old_txt) = (fs::read_to_string(&tsv).unwrap_or_default(), fs::read_to_string(&txt).unwrap_or_default());
            let base = |text: &str| -> Option<String> {
                let line = text.lines().next()?.strip_prefix("# replay ")?;
                if line.starts_with("full ") { Some(line.to_string()) } else { line.rsplit(" base=").next().map(str::to_string) }
            };
            let base = match (base(&old_tsv), base(&old_txt)) {
                (Some(a), Some(b)) if a == b && a.starts_with("full ") => a,
                _ => "none".to_string(),
            };
            let mut kept_rows = Vec::new();
            let mut kept_diffs: Vec<(String, String)> = Vec::new();
            if base != "none" {
                for line in old_tsv.split_inclusive('\n').skip(2) {
                    kept_rows.push((line.split('\t').next().unwrap_or_default().to_string(), line.to_string()));
                }
                for line in old_txt.split_inclusive('\n').skip(1) {
                    match line.strip_prefix("== ") {
                        Some(rest) => kept_diffs.push((rest.split(' ').next().unwrap_or_default().to_string(), line.to_string())),
                        None => kept_diffs.last_mut().into_iter().for_each(|(_, block)| block.push_str(line)),
                    }
                }
            }
            let ran: std::collections::HashSet<&String> = replayed.iter().collect();
            kept_rows.retain(|(stem, _)| !ran.contains(stem));
            kept_diffs.retain(|(stem, _)| !ran.contains(stem));
            kept_rows.extend(report);
            kept_diffs.extend(diffs);
            (format!("# replay filtered {now} MOCK_SERVER_SCENARIO={filter} files={} base={base}", replayed.len()), kept_rows, kept_diffs)
        }
    };
    // file order, as an unfiltered replay writes them (stable: a file's cases keep their order)
    report.sort_by_key(|(stem, _)| format!("{stem}.json"));
    diffs.sort_by_key(|(stem, _)| format!("{stem}.json"));
    let report: String = report.into_iter().map(|(_, row)| row).collect();
    let diffs: String = diffs.into_iter().map(|(_, block)| block).collect();
    let _ = fs::write(&tsv, format!("{marker}\nfile\tcase\tresult\n{report}"));
    let _ = fs::write(&txt, format!("{marker}\n{diffs}"));
}

/// For `"compare": "unordered"`: the body's entries, sorted — the objects of a pretty-printed JSON array (split as
/// text, because masks leave it no longer valid JSON), else the text log's blocks.
fn unordered_body(result: &Value) -> Option<Vec<String>> {
    let body = result.get("body").and_then(Value::as_str)?;
    let mut entries: Vec<String> = match body.strip_prefix("[\n  {\n").and_then(|b| b.strip_suffix("\n  }\n]")) {
        Some(objects) => objects.split("\n  },\n  {\n").map(str::to_string).collect(),
        None => body.split("------------------------------------\n").map(str::to_string).collect(),
    };
    entries.sort();
    Some(entries)
}

/// For `"compare": "json"`: recursively re-parses any string value that looks like a JSON object or array (starts,
/// once trimmed, with `{` or `[`) into its parsed form, so a JSON document embedded as a string inside the body —
/// an MCP `tools/call` response's `"content"[0]."text"`, wrapping e.g. `debugMismatch`'s own JSON — is compared as
/// JSON too, not byte-for-byte. A string that fails to parse, or does not look like JSON, is left as a string.
/// Applied identically to both sides of the comparison, so it cannot make two genuinely different bodies equal —
/// only unordered-object-key noise, at any nesting depth, is absorbed.
fn deep_parse_embedded_json(v: Value) -> Value {
    match v {
        Value::String(s) => match s.trim_start().chars().next() {
            Some('{') | Some('[') => match serde_json::from_str::<Value>(&s) {
                Ok(parsed) => deep_parse_embedded_json(parsed),
                Err(_) => Value::String(s),
            },
            _ => Value::String(s),
        },
        Value::Array(items) => Value::Array(items.into_iter().map(deep_parse_embedded_json).collect()),
        Value::Object(map) => Value::Object(map.into_iter().map(|(k, v)| (k, deep_parse_embedded_json(v))).collect()),
        other => other,
    }
}

/// Status and headers side by side, then the first differing body lines with context.
fn describe_difference(expected: &Value, actual: &Value) -> String {
    let mut out = String::new();
    for key in ["status", "connectionError", "timeout"] {
        if expected.get(key) != actual.get(key) {
            out.push_str(&format!("  {key}: expected {} actual {}\n", expected.get(key).unwrap_or(&Value::Null), actual.get(key).unwrap_or(&Value::Null)));
        }
    }
    let lines = |v: &Value, k: &str| -> Vec<String> {
        match v.get(k) {
            Some(Value::Array(items)) => items.iter().map(|i| i.as_str().unwrap_or_default().to_string()).collect(),
            Some(Value::String(s)) => s.lines().map(str::to_string).collect(),
            _ => Vec::new(),
        }
    };
    for (key, label) in [("headers", "header"), ("trailers", "trailer")] {
        let (eh, ah) = (lines(expected, key), lines(actual, key));
        for h in eh.iter().filter(|h| !ah.contains(h)) {
            out.push_str(&format!("  - {label} {h}\n"));
        }
        for h in ah.iter().filter(|h| !eh.contains(h)) {
            out.push_str(&format!("  + {label} {h}\n"));
        }
    }
    let (eb, ab) = (lines(expected, "body"), lines(actual, "body"));
    if eb != ab {
        let first = eb.iter().zip(&ab).position(|(e, a)| e != a).unwrap_or(eb.len().min(ab.len()));
        let from = first.saturating_sub(3);
        out.push_str(&format!("  body differs from line {}:\n", first + 1));
        for l in eb.iter().skip(from).take(8) {
            out.push_str(&format!("    - {l}\n"));
        }
        for l in ab.iter().skip(from).take(8) {
            out.push_str(&format!("    + {l}\n"));
        }
    }
    // Every other recorded field (a tcp step's `tcp`/`closed`, `udp`, `frames`, `fileContent`, …) printed as it is,
    // so a mismatch never prints an empty diff.
    let handled = ["status", "connectionError", "timeout", "headers", "trailers", "body"];
    let keys = |v: &Value| v.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
    let mut other: Vec<String> = keys(expected).into_iter().chain(keys(actual)).filter(|k| !handled.contains(&k.as_str())).collect();
    other.sort();
    other.dedup();
    let shown = |v: Option<&Value>| {
        let s = v.map(Value::to_string).unwrap_or_else(|| "(absent)".into());
        if s.chars().count() > 400 { format!("{}…", s.chars().take(400).collect::<String>()) } else { s }
    };
    for k in other.iter().filter(|k| expected.get(k.as_str()) != actual.get(k.as_str())) {
        out.push_str(&format!("  {k}: expected {} actual {}\n", shown(expected.get(k.as_str())), shown(actual.get(k.as_str()))));
    }
    if out.is_empty() && expected != actual {
        out.push_str(&format!("  expected {}\n  actual   {}\n", shown(Some(expected)), shown(Some(actual))));
    }
    out
}

/// The version and upstream commit we report are the pinned oracle's (`oracle.env`).
#[test]
fn reported_version_is_the_pinned_oracles() {
    assert_eq!(mock_server::MOCKSERVER_VERSION, oracle_pin("ORACLE_VERSION"));
    assert_eq!(mock_server::UPSTREAM_GIT_HASH, &oracle_pin("ORACLE_REVISION")[..8]);
}

/// The image a golden names as `recordedFrom`, if it exists.
fn recorded_from(file: &Path) -> Option<String> {
    let golden: Value = serde_json::from_str(&fs::read_to_string(golden_path(file)).ok()?).ok()?;
    golden.get("recordedFrom")?.as_str().map(str::to_string)
}

/// A caught panic's message.
fn panic_text(panic: &Box<dyn std::any::Any + Send>) -> String {
    panic.downcast_ref::<String>().cloned().or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_else(|| "panic".into())
}

/// A scenario file's name without `.json`.
fn stem(file: &Path) -> String {
    file.file_stem().unwrap().to_string_lossy().into_owned()
}

/// `tests/scenarios/skips-rs.txt`: top-level scenario steps that do not match the oracle yet, a to-do
/// list like the harvested cases' `skips-rs.txt`. `<scenario> <step>  # <reason>` lists one step (its index
/// among the steps compared, as failures name it); `<scenario> *  # …` a scenario not replayed at all yet. Every line
/// gives its reason.
fn scenario_skips() -> std::collections::HashMap<(String, Option<usize>), String> {
    let text = fs::read_to_string(scenarios_dir().join("skips-rs.txt")).unwrap_or_default();
    let mut skips = std::collections::HashMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let (entry, reason) = line.split_once('#').unwrap_or_else(|| panic!("skips-rs.txt: no `# <reason>` on {line:?}"));
        let reason = reason.trim();
        assert!(!reason.is_empty(), "skips-rs.txt: {line:?} gives no reason");
        let mut parts = entry.split_whitespace();
        let (Some(name), Some(step), None) = (parts.next(), parts.next(), parts.next()) else { panic!("skips-rs.txt: {line:?} is not `<scenario> <step|*>`") };
        assert!(scenarios_dir().join(format!("{name}.json")).exists(), "skips-rs.txt: no scenario {name}");
        let step = (step != "*").then(|| step.parse().unwrap_or_else(|_| panic!("skips-rs.txt: bad step in {line:?}")));
        skips.insert((name.to_string(), step), reason.to_string());
    }
    skips
}

//! Ports of master's `WebSocketProxyHandshakeHeaderLimitIntegrationTest` and
//! `WebSocketProxyHandshakeTimeoutIntegrationTest`: an unmatched upgrade relayed to its `Host`
//! (`WebSocketProxyRelayHandler`). The upstream's handshake response is read as a forward's response head is (status
//! line under Netty's 4096 bytes, header lines under `maxHeaderSize`) and waited for as long as a forward's response
//! (`maxSocketTimeout`, capped by `maxFutureTimeout`), the TLS handshake bounded by `socketConnectionTimeout`; a client
//! that gives up waiting ends the upstream connection; the client's `101` carries the upstream's response headers but
//! the hop-by-hop and handshake ones. Each failure is answered `502` with its reason and logged once.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::common;

const LIMIT: usize = 32 * 1024;
const SMALL_LIMIT: usize = 4 * 1024;
const FAILURE: &str = "WebSocket proxy passthrough failed";
const NOT_READ: &str = "upstream WebSocket handshake response could not be read: ";
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/// `HandshakeUpstream`: answers each upgrade as its path says, then echoes text frames; records how each connection
/// ended (`<path> closed after <n> frame(s)`, or `<path> received the upgrade` first).
#[derive(Clone)]
struct Upstream {
    port: u16,
    events: Arc<Mutex<Vec<String>>>,
}

fn accept_of(head: &str) -> String {
    let key = head.lines().find_map(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:").then(|| l[l.find(':').unwrap() + 1..].trim().to_string())).unwrap();
    tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes())
}

fn pause() {
    std::thread::sleep(Duration::from_millis(300));
}

impl Upstream {
    fn start() -> Upstream {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let events = Arc::new(Mutex::new(Vec::new()));
        let upstream = Upstream { port, events: events.clone() };
        std::thread::spawn(move || {
            for socket in listener.incoming() {
                let Ok(socket) = socket else { return };
                let events = events.clone();
                std::thread::spawn(move || serve(socket, events));
            }
        });
        upstream
    }

    fn await_event(&self, event: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.events.lock().unwrap().iter().any(|e| e == event) {
            assert!(Instant::now() < deadline, "upstream saw {:?} and not {event}", self.events.lock().unwrap());
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn serve(mut socket: TcpStream, events: Arc<Mutex<Vec<String>>>) {
    socket.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match socket.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    if head.starts_with(&[0x16]) {
        // a ClientHello: never answered
        std::thread::sleep(Duration::from_secs(30));
        return;
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let path = head["GET ".len()..head.find(" HTTP/1.1").unwrap()].to_string();
    let size = || path.rsplit('/').next().unwrap().parse::<usize>().unwrap();
    let mut frames = 0;
    let handshake = format!("upgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-accept: {}\r\nx-served-by: test\r\n", accept_of(&head));
    events.lock().unwrap().push(format!("{path} received the upgrade"));
    let mut serve_frames = |socket: &mut TcpStream| -> std::io::Result<()> {
        loop {
            let mut header = [0u8; 2];
            if socket.read_exact(&mut header).is_err() {
                return Ok(());
            }
            let length = (header[1] & 0x7f) as usize;
            let mut mask = [0u8; 4];
            socket.read_exact(&mut mask)?;
            let mut payload = vec![0u8; length];
            socket.read_exact(&mut payload)?;
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
            frames += 1;
            if header[0] == 0x88 {
                socket.write_all(&[0x88, 0])?;
                return Ok(());
            }
            let echo = format!("echo:{}", String::from_utf8_lossy(&payload));
            socket.write_all(&[0x81, echo.len() as u8])?;
            socket.write_all(echo.as_bytes())?;
        }
    };
    let result = (|| -> std::io::Result<()> {
        if path.starts_with("/silent/") {
            let _ = socket.read(&mut [0u8; 1]);
            return Ok(());
        }
        if path.starts_with("/part-head/") {
            socket.write_all(b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\n")?;
            let _ = socket.read(&mut [0u8; 1]);
            return Ok(());
        }
        if path.starts_with("/closed-in-headers/") {
            return socket.write_all(format!("HTTP/1.1 101 Switching Protocols\r\n{handshake}x-last: 1\r\n").as_bytes());
        }
        if path.starts_with("/bare-line-feed/") {
            socket.write_all(format!("HTTP/1.1 101 Switching Protocols\r\n{handshake}x-bare: 1\n").as_bytes())?;
            pause();
            socket.write_all(b"x-last: 1\r\n\r\n\x81\x05hello")?;
        } else if path.starts_with("/headers/") {
            let protocol = head.lines().find_map(|l| l.to_ascii_lowercase().starts_with("sec-websocket-protocol:").then(|| format!("sec-websocket-protocol: {}\r\n", l[l.find(':').unwrap() + 1..].trim()))).unwrap_or_default();
            socket.write_all(
                format!(
                    "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade, X-Hop\r\nsec-websocket-accept: {}\r\n{protocol}Sec-WebSocket-Extensions: permessage-deflate\r\nset-cookie: session=abc; Path=/; HttpOnly\r\nset-cookie: theme=dark\r\nx-custom: one\r\nX-MockServer-WebSocket-Frames: 999\r\nx-mockserver-websocket-transcript-truncated: true\r\nx-hop: 1\r\nKeep-Alive: timeout=5\r\nproxy-connection: keep-alive\r\nProxy-Authenticate: Basic realm=\"upstream\"\r\ntransfer-encoding: gzip\r\nte: trailers\r\ntrailer: x-checksum\r\ncontent-length: 0\r\n\r\n",
                    accept_of(&head)
                )
                .as_bytes(),
            )?;
        } else {
            let large = format!("set-cookie: session={}\r\n", "a".repeat(size() - 124));
            let mut status_line = "HTTP/1.1 101 Switching Protocols".to_string();
            let headers = match () {
                _ if path.starts_with("/first/") => format!("{large}{handshake}"),
                _ if path.starts_with("/status-line/") => {
                    status_line.push_str(&"s".repeat(size() - status_line.len()));
                    handshake.clone()
                }
                _ => format!("{handshake}{large}"),
            };
            let response = format!("{status_line}\r\n{headers}\r\n").into_bytes();
            if path.starts_with("/split/") {
                let after_last_cr = response.len() - 3;
                socket.write_all(&response[..after_last_cr])?;
                pause();
                socket.write_all(&response[after_last_cr..])?;
            } else {
                socket.write_all(&response)?;
            }
        }
        serve_frames(&mut socket)
    })();
    let _ = result;
    events.lock().unwrap().push(format!("{path} closed after {frames} frame(s)"));
}

struct Exchange {
    status: u16,
    head: String,
    body: String,
    echo: Option<String>,
}

/// Sends the upgrade for `path` (to the upstream, by its `Host`) through `server`; after a `101`, a text frame
/// `hello` and its echo.
fn upgrade(server: u16, upstream: &Upstream, path: &str, extra: &str) -> Exchange {
    let mut socket = TcpStream::connect(("127.0.0.1", server)).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(socket, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n", upstream.port).unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(socket.read(&mut byte).unwrap(), 1, "closed after: {}", String::from_utf8_lossy(&head));
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let status = head[9..12].parse().unwrap();
    if status != 101 {
        let mut body = Vec::new();
        let _ = socket.read_to_end(&mut body);
        return Exchange { status, head, body: String::from_utf8_lossy(&body).into_owned(), echo: None };
    }
    socket.write_all(&[0x81, 0x85, 1, 2, 3, 4]).unwrap();
    socket.write_all(&b"hello".iter().enumerate().map(|(i, b)| b ^ [1, 2, 3, 4][i % 4]).collect::<Vec<_>>()).unwrap();
    let mut frame = [0u8; 2];
    socket.read_exact(&mut frame).unwrap();
    let mut payload = vec![0u8; (frame[1] & 0x7f) as usize];
    socket.read_exact(&mut payload).unwrap();
    socket.write_all(&[0x88, 0x80, 1, 2, 3, 4]).unwrap();
    Exchange { status, head, body: String::new(), echo: Some(String::from_utf8_lossy(&payload).into_owned()) }
}

fn header_values(head: &str, name: &str) -> Vec<String> {
    head.split("\r\n").skip(1).filter(|l| l.to_ascii_lowercase().starts_with(&format!("{name}:"))).map(|l| l[l.find(':').unwrap() + 1..].trim().to_string()).collect()
}

/// The log's entries about a failed relay (or any exception).
async fn failures(port: u16) -> Vec<String> {
    common::logs(port).await.split("------------------------------------\n").filter(|e| e.contains(FAILURE) || e.to_lowercase().contains("exception")).map(str::to_string).collect()
}

async fn relaying(properties: &[(&str, &str)]) -> common::Running {
    let mut all = vec![("logLevel", "WARN"), ("attemptToProxyIfNoMatchingExpectation", "true")];
    all.extend_from_slice(properties);
    common::start(&all).await
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

async fn assert_failed_with_one_warning(server: u16, exchange: Exchange, reason: &str) {
    assert_eq!((exchange.status, exchange.body.as_str()), (502, reason), "{}", exchange.head);
    let entries = failures(server).await;
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert!(entries[0].contains(reason), "{entries:?}");
}

// --- WebSocketProxyHandshakeHeaderLimitIntegrationTest ---------------------------------------------------------

/// `shouldRelayAHandshakeResponseWithHeadersOfExactlyMaxHeaderSizeAndFailLargerOnes`
#[tokio::test(flavor = "multi_thread")]
async fn should_relay_a_handshake_response_with_headers_of_exactly_max_header_size_and_fail_larger_ones() {
    let upstream = Upstream::start();
    let limit = LIMIT.to_string();
    let limited = relaying(&[("maxHeaderSize", limit.as_str())]).await;
    for path in [format!("/first/{}", LIMIT - 1), format!("/first/{LIMIT}"), format!("/last/{LIMIT}"), format!("/split/{LIMIT}")] {
        let (port, u) = (limited.port, upstream.clone());
        let within = blocking(move || upgrade(port, &u, &path, "")).await;
        assert_eq!((within.status, within.echo.as_deref()), (101, Some("echo:hello")), "{}", within.body);
    }
    for order in ["first", "last", "split"] {
        common::send(limited.port, "PUT", "/mockserver/reset", "").await;
        let path = format!("/{order}/{}", LIMIT + 1);
        let (port, u) = (limited.port, upstream.clone());
        let over = blocking(move || upgrade(port, &u, &path, "")).await;
        assert_failed_with_one_warning(limited.port, over, &format!("upstream WebSocket handshake response headers are larger than maxHeaderSize ({LIMIT} bytes)")).await;
    }
    let (port, u) = (limited.port, upstream.clone());
    assert_eq!(blocking(move || upgrade(port, &u, "/first/1000", "")).await.echo.as_deref(), Some("echo:hello"));
    limited.server.shutdown().await;
}

/// `shouldApplyAMaxHeaderSizeBelowNettysDefaultLimit` and `shouldPassAHandshakeResponseHeaderOfUpToMaxHeaderSizeToTheClient`
#[tokio::test(flavor = "multi_thread")]
async fn should_apply_a_max_header_size_below_nettys_default_limit() {
    let upstream = Upstream::start();
    let small_limit = SMALL_LIMIT.to_string();
    let small = relaying(&[("maxHeaderSize", small_limit.as_str())]).await;
    let (port, u) = (small.port, upstream.clone());
    let at_limit = blocking(move || upgrade(port, &u, &format!("/last/{SMALL_LIMIT}"), "")).await;
    assert_eq!((at_limit.status, at_limit.echo.as_deref()), (101, Some("echo:hello")));
    assert_eq!(header_values(&at_limit.head, "set-cookie"), [format!("session={}", "a".repeat(SMALL_LIMIT - 124))]);
    assert_eq!(header_values(&at_limit.head, "x-served-by"), ["test"]);
    let (port, u) = (small.port, upstream.clone());
    let over = blocking(move || upgrade(port, &u, &format!("/last/{}", SMALL_LIMIT + 1), "")).await;
    assert_failed_with_one_warning(small.port, over, &format!("upstream WebSocket handshake response headers are larger than maxHeaderSize ({SMALL_LIMIT} bytes)")).await;
    small.server.shutdown().await;
}

/// `shouldFailAHandshakeResponseItCannotDecodeAfterTheHandshakesOwnHeaders`
#[tokio::test(flavor = "multi_thread")]
async fn should_fail_a_handshake_response_it_cannot_decode_after_the_handshakes_own_headers() {
    let upstream = Upstream::start();
    let defaults = relaying(&[]).await;
    for path in ["/bare-line-feed/0", "/closed-in-headers/0"] {
        common::send(defaults.port, "PUT", "/mockserver/reset", "").await;
        let (port, u) = (defaults.port, upstream.clone());
        let exchange = blocking(move || upgrade(port, &u, path, "")).await;
        assert_eq!(exchange.status, 502, "{path} {}", exchange.body);
        assert!(exchange.body.starts_with(NOT_READ) && !exchange.body.ends_with("null"), "{path} {}", exchange.body);
        let u = upstream.clone();
        blocking(move || u.await_event(&format!("{path} closed after 0 frame(s)"))).await;
        let entries = failures(defaults.port).await;
        assert!(entries.len() == 1 && entries[0].contains(&exchange.body), "{path} {entries:?}");
    }
    defaults.server.shutdown().await;
}

/// `shouldKeepNettysLimitForTheStatusLineWhateverMaxHeaderSizeIs`
#[tokio::test(flavor = "multi_thread")]
async fn should_keep_nettys_limit_for_the_status_line_whatever_max_header_size_is() {
    let upstream = Upstream::start();
    let limit = LIMIT.to_string();
    let limited = relaying(&[("maxHeaderSize", limit.as_str())]).await;
    let (port, u) = (limited.port, upstream.clone());
    assert_eq!(blocking(move || upgrade(port, &u, "/status-line/4096", "")).await.echo.as_deref(), Some("echo:hello"));
    let (port, u) = (limited.port, upstream.clone());
    let over = blocking(move || upgrade(port, &u, "/status-line/4097", "")).await;
    assert_eq!((over.status, over.body.as_str()), (502, "upstream WebSocket handshake response could not be read: An HTTP line is larger than 4096 bytes."));
    limited.server.shutdown().await;
}

/// `shouldPassTheUpstreamsHandshakeResponseHeadersToTheClientButNotItsHopByHopOrHandshakeHeaders`
#[tokio::test(flavor = "multi_thread")]
async fn should_pass_the_upstreams_handshake_response_headers_to_the_client_but_not_its_hop_by_hop_or_handshake_headers() {
    let upstream = Upstream::start();
    let defaults = relaying(&[]).await;
    let (port, u) = (defaults.port, upstream.clone());
    let exchange = blocking(move || upgrade(port, &u, "/headers/0", "Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Extensions: permessage-deflate\r\n")).await;
    assert_eq!((exchange.status, exchange.echo.as_deref()), (101, Some("echo:hello")), "{}", exchange.head);
    assert_eq!(header_values(&exchange.head, "set-cookie"), ["session=abc; Path=/; HttpOnly", "theme=dark"], "{}", exchange.head);
    assert_eq!(header_values(&exchange.head, "x-custom"), ["one"]);
    assert_eq!(header_values(&exchange.head, "sec-websocket-protocol"), ["chat"]);
    assert_eq!(header_values(&exchange.head, "sec-websocket-accept"), [ACCEPT]);
    assert_eq!(header_values(&exchange.head, "upgrade"), ["websocket"]);
    assert_eq!(header_values(&exchange.head, "connection"), ["upgrade"]);
    for not_relayed in ["sec-websocket-extensions", "x-hop", "keep-alive", "proxy-connection", "proxy-authenticate", "transfer-encoding", "te", "trailer", "content-length"] {
        assert!(header_values(&exchange.head, not_relayed).is_empty(), "{not_relayed} in {}", exchange.head);
    }

    let recorded = await_recorded_upgrade(defaults.port, "/headers/0").await;
    let values = |name: &str| recorded_header(&recorded, name);
    assert_eq!(values("set-cookie"), ["session=abc; Path=/; HttpOnly", "theme=dark"], "{recorded}");
    assert_eq!(values("x-custom"), ["one"], "{recorded}");
    assert!(values("keep-alive").is_empty(), "{recorded}");
    // the relay's own recording headers keep the relay's values alone
    let frames = values("x-mockserver-websocket-frames");
    assert!(frames.len() == 1 && frames[0] != "999", "{recorded}");
    assert_eq!(values("x-mockserver-websocket-transcript-truncated"), ["false"], "{recorded}");
    defaults.server.shutdown().await;
}

/// `awaitRecordedUpgrade`: the first recorded exchange's response for `path`, within 10 seconds.
async fn await_recorded_upgrade(port: u16, path: &str) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let r = common::send(port, "PUT", "/mockserver/retrieve?type=REQUEST_RESPONSES", &serde_json::json!({"path": path}).to_string()).await;
        let exchanges: Vec<serde_json::Value> = serde_json::from_str(&r.body).unwrap_or_default();
        if let Some(first) = exchanges.first() {
            return first["httpResponse"].clone();
        }
        assert!(Instant::now() < deadline, "the upgrade to {path} is recorded");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// `HttpResponse.getHeader`: the values of every header named `name`, ignoring case, in the map or list form.
fn recorded_header(response: &serde_json::Value, name: &str) -> Vec<String> {
    let strings = |v: &serde_json::Value| match v {
        serde_json::Value::Array(values) => values.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        v => v.as_str().map(|s| vec![s.to_string()]).unwrap_or_default(),
    };
    match &response["headers"] {
        serde_json::Value::Object(map) => map.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).flat_map(|(_, v)| strings(v)).collect(),
        serde_json::Value::Array(list) => list.iter().filter(|h| h["name"].as_str().is_some_and(|k| k.eq_ignore_ascii_case(name))).flat_map(|h| strings(&h["values"])).collect(),
        _ => Vec::new(),
    }
}

// --- WebSocketProxyHandshakeTimeoutIntegrationTest -------------------------------------------------------------

async fn assert_timed_out_with_one_warning(server: &common::Running, upstream: &Upstream, path: &'static str, reason: &str, at_least: Duration) {
    let started = Instant::now();
    let (port, u) = (server.port, upstream.clone());
    let exchange = blocking(move || upgrade(port, &u, path, "")).await;
    assert!(started.elapsed() >= at_least, "waited {:?}", started.elapsed());
    let u = upstream.clone();
    blocking(move || u.await_event(&format!("{path} closed after 0 frame(s)"))).await;
    assert_failed_with_one_warning(server.port, exchange, reason).await;
}

/// `shouldAnswer502WhenTheUpstreamNeverAnswersTheUpgrade` and `shouldAnswer502WhenTheUpstreamStopsPartWayThroughItsResponseHead`
#[tokio::test(flavor = "multi_thread")]
async fn should_answer_502_when_the_upstream_does_not_answer_the_upgrade_within_max_socket_timeout() {
    let upstream = Upstream::start();
    let bounded = relaying(&[("maxSocketTimeoutInMillis", "2000")]).await;
    let reason = "upstream WebSocket handshake response was not received within maxSocketTimeout (2000 ms)";
    assert_timed_out_with_one_warning(&bounded, &upstream, "/silent/0", reason, Duration::from_millis(2000)).await;
    common::send(bounded.port, "PUT", "/mockserver/reset", "").await;
    assert_timed_out_with_one_warning(&bounded, &upstream, "/part-head/0", reason, Duration::from_millis(2000)).await;
    bounded.server.shutdown().await;
}

/// `shouldNeverWaitLongerThanMaxFutureTimeout`
#[tokio::test(flavor = "multi_thread")]
async fn should_never_wait_longer_than_max_future_timeout() {
    let upstream = Upstream::start();
    let reason = "upstream WebSocket handshake response was not received within maxFutureTimeout (2000 ms)";
    for socket_timeout in ["0", "300000"] {
        let server = relaying(&[("maxFutureTimeoutInMillis", "2000"), ("maxSocketTimeoutInMillis", socket_timeout)]).await;
        let path = if socket_timeout == "0" { "/silent/2" } else { "/silent/3" };
        assert_timed_out_with_one_warning(&server, &upstream, path, reason, Duration::from_millis(2000)).await;
        server.server.shutdown().await;
    }
}

/// `shouldEndAWssHandshakeThatStallsAtTheConfiguredConnectionTimeout`: an upstream that never answers the ClientHello.
#[tokio::test(flavor = "multi_thread")]
async fn should_end_a_wss_handshake_that_stalls_at_the_configured_connection_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let held: Vec<TcpStream> = listener.incoming().take(1).filter_map(Result::ok).collect();
        std::thread::sleep(Duration::from_secs(30));
        drop(held);
    });
    let server = relaying(&[("socketConnectionTimeoutInMillis", "1000"), ("maxSocketTimeoutInMillis", "300000")]).await;
    let expectation = serde_json::json!({"httpRequest": {"path": "/tls-stalled"}, "httpForward": {"host": "127.0.0.1", "port": port, "scheme": "HTTPS"}});
    common::expect(server.port, &expectation).await;
    let started = Instant::now();
    let upstream = Upstream { port, events: Arc::default() };
    let mock_server = server.port;
    let exchange = blocking(move || upgrade(mock_server, &upstream, "/tls-stalled", "")).await;
    let elapsed = started.elapsed();
    let reason = "TLS with the upstream failed: SslHandshakeTimeoutException: handshake timed out after 1000ms";
    assert!(elapsed >= Duration::from_millis(800) && elapsed < Duration::from_secs(6), "{elapsed:?}");
    assert_failed_with_one_warning(server.port, exchange, reason).await;
    server.server.shutdown().await;
}

/// `shouldCloseTheUpstreamConnectionWhenTheClientGivesUpWaiting`
#[tokio::test(flavor = "multi_thread")]
async fn should_close_the_upstream_connection_when_the_client_gives_up_waiting() {
    let upstream = Upstream::start();
    let patient = relaying(&[("maxSocketTimeoutInMillis", "300000")]).await;
    let (port, u) = (patient.port, upstream.clone());
    blocking(move || {
        let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(socket, "GET /silent/1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n", u.port).unwrap();
        u.await_event("/silent/1 received the upgrade");
        drop(socket);
        u.await_event("/silent/1 closed after 0 frame(s)");
    })
    .await;
    assert!(failures(patient.port).await.is_empty());
    patient.server.shutdown().await;
}

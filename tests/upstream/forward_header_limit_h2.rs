//! `ForwardHeaderLimitIntegrationTest` (master b765b8271): the cases about HTTP/2 forwards and an
//! upstream proxy's `CONNECT` reply. A client sends plain HTTP/1.1 to the server, which forwards over TLS to an HTTP/2
//! upstream that counts its connections and records the GOAWAY codes, resets, requests and connection errors it sees,
//! directly or through a `forwardHttpsProxy` that answers `CONNECT` with headers of a chosen size.
//!
//! What master does that these pin: HTTP/2 connections are pooled (a new stream per request) and an idempotent request
//! that fails on a reused one before any answer is sent once more on a new connection; a response header list over
//! `maxHeaderSize` resets the stream and closes the connection with `GOAWAY(NO_ERROR)`, a block more than a quarter
//! over it is a connection error, `GOAWAY(PROTOCOL_ERROR)`; HTTP/2 is negotiated inside a `CONNECT` tunnel.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::{Buf, BytesMut};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common;

const LIMIT: usize = 32 * 1024;
const UPSTREAM_REQUEST_LIMIT: usize = 16 * 1024;
const FIELD_OVERHEAD: usize = 32;

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const CONTINUATION: u8 = 0x9;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PROTOCOL_ERROR: u32 = 0x1;

/// What an [`H2Upstream`] saw, in the shape of the Java test's `HTTP2_EVENTS`.
type Events = Arc<Mutex<Vec<String>>>;

/// An HTTP/2 upstream over TLS (ALPN `h2` only), answering with a header list, or trailers, of the size the path
/// asks for as RFC 9113 section 6.5.2 counts it. With `max_header_list` it announces that limit and treats a request
/// as Netty's server does: a block more than a quarter over it is a connection error (GOAWAY `PROTOCOL_ERROR`, the
/// connection closed), a decoded list over it is answered `431`.
struct H2Upstream {
    port: u16,
    connections: Arc<AtomicUsize>,
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    out.extend_from_slice(&[kind, flags]);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A header block as HEADERS and CONTINUATION frames of at most 16,384 bytes.
fn header_frames(stream: u32, block: &[u8], end_stream: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let pieces: Vec<&[u8]> = if block.is_empty() { vec![block] } else { block.chunks(16_384).collect() };
    for (i, piece) in pieces.iter().enumerate() {
        let last = i + 1 == pieces.len();
        let kind = if i == 0 { HEADERS } else { CONTINUATION };
        let flags = (if last { END_HEADERS } else { 0 }) | (if i == 0 && end_stream { END_STREAM } else { 0 });
        out.extend(frame(kind, flags, stream, piece));
    }
    out
}

fn size_in(path: &str) -> usize {
    path.rsplit('/').next().and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn tls_file(name: &str) -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/tls").join(name).display().to_string()
}

impl H2Upstream {
    async fn start(events: Events, max_header_list: Option<usize>) -> H2Upstream {
        use rustls_pki_types::pem::PemObject;
        let chain = rustls_pki_types::CertificateDer::pem_file_iter(tls_file("foreign-leaf-cert.pem")).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        let key = rustls_pki_types::PrivateKeyDer::from_pem_file(tls_file("foreign-leaf-key.pem")).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(chain, key).unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, events, counted) = (acceptor.clone(), events.clone(), counted.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else { return };
                    counted.fetch_add(1, Ordering::SeqCst);
                    serve_h2(tls, events, max_header_list).await;
                });
            }
        });
        H2Upstream { port, connections }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

async fn serve_h2<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut io: S, events: Events, max_header_list: Option<usize>) {
    let mut buf = BytesMut::new();
    while buf.len() < 24 {
        if io.read_buf(&mut buf).await.unwrap_or(0) == 0 {
            return;
        }
    }
    buf.advance(24);
    let mut settings = Vec::new();
    if let Some(max) = max_header_list {
        settings.extend_from_slice(&0x6u16.to_be_bytes());
        settings.extend_from_slice(&(max as u32).to_be_bytes());
    }
    if io.write_all(&frame(SETTINGS, 0, 0, &settings)).await.is_err() {
        return;
    }
    let mut decoder = loona_hpack::Decoder::new();
    let mut block: Vec<u8> = Vec::new();
    let (mut block_stream, mut block_ends, mut path) = (0u32, false, String::new());
    loop {
        while buf.len() < 9 {
            if io.read_buf(&mut buf).await.unwrap_or(0) == 0 {
                return;
            }
        }
        let length = ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | buf[2] as usize;
        while buf.len() < 9 + length {
            if io.read_buf(&mut buf).await.unwrap_or(0) == 0 {
                return;
            }
        }
        let (kind, flags) = (buf[3], buf[4]);
        let stream = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
        buf.advance(9);
        let payload = buf.split_to(length);
        let mut out = Vec::new();
        let mut respond = false;
        match kind {
            SETTINGS if flags & 0x1 == 0 => out.extend(frame(SETTINGS, 0x1, 0, &[])),
            PING if flags & 0x1 == 0 => out.extend(frame(PING, 0x1, 0, &payload)),
            GOAWAY if payload.len() >= 8 => events.lock().unwrap().push(format!("goaway:{}", u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]))),
            RST_STREAM if payload.len() >= 4 => events.lock().unwrap().push(format!("reset:{}", u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]))),
            HEADERS | CONTINUATION => {
                if kind == HEADERS {
                    block.clear();
                    block_stream = stream;
                    block_ends = flags & END_STREAM != 0;
                }
                block.extend_from_slice(&payload);
                if flags & END_HEADERS != 0 {
                    if let Some(max) = max_header_list.filter(|max| block.len() > max + (max >> 2)) {
                        // `Http2CodecUtil.headerListSizeExceeded(long)`: a connection error
                        events.lock().unwrap().push(format!("connection-error:Header size exceeded max allowed size ({max})"));
                        let mut goaway = block_stream.to_be_bytes().to_vec();
                        goaway.extend_from_slice(&PROTOCOL_ERROR.to_be_bytes());
                        goaway.extend_from_slice(format!("Header size exceeded max allowed size ({max})").as_bytes());
                        let _ = io.write_all(&frame(GOAWAY, 0, 0, &goaway)).await;
                        let _ = io.flush().await;
                        let _ = io.shutdown().await;
                        return;
                    }
                    let Ok(fields) = decoder.decode(&block) else { return };
                    let size: usize = fields.iter().map(|(n, v)| FIELD_OVERHEAD + n.len() + v.len()).sum();
                    if max_header_list.is_some_and(|max| size > max) {
                        // `Http2ConnectionHandler.handleServerHeaderDecodeSizeError`: 431, then the stream reset
                        let answer = loona_hpack::Encoder::new().encode([(&b":status"[..], &b"431"[..])]);
                        out.extend(header_frames(block_stream, &answer, true));
                        out.extend(frame(RST_STREAM, 0, block_stream, &PROTOCOL_ERROR.to_be_bytes()));
                    } else {
                        path = fields.iter().find(|(n, _)| n == b":path").map(|(_, v)| String::from_utf8_lossy(v).into_owned()).unwrap_or_default();
                        let large = fields.iter().find(|(n, _)| n == b"x-large").map(|(_, v)| format!(":x-large:{}", v.len())).unwrap_or_default();
                        events.lock().unwrap().push(format!("request:{path}{large}"));
                        respond = block_ends;
                    }
                }
            }
            DATA => respond = flags & END_STREAM != 0,
            _ => {}
        }
        if respond {
            out.extend(answer(stream, &path));
        }
        if !out.is_empty() && (io.write_all(&out).await.is_err() || io.flush().await.is_err()) {
            return;
        }
    }
}

/// `Http2UpstreamStream.respond`.
fn answer(stream: u32, path: &str) -> Vec<u8> {
    let encode = |fields: &[(&str, String)]| loona_hpack::Encoder::new().encode(fields.iter().map(|(k, v)| (k.as_bytes(), v.as_bytes())));
    let status = (":status", "200".to_string());
    let mut out = Vec::new();
    if path.contains("/trailers/") {
        out.extend(header_frames(stream, &encode(&[status]), false));
        out.extend(frame(DATA, 0, stream, b"ok"));
        // "x-trailer" is 9 bytes
        out.extend(header_frames(stream, &encode(&[("x-trailer", "a".repeat(size_in(path) - 9 - FIELD_OVERHEAD))]), true));
    } else {
        // ":status" and "200" are 10 bytes, "set-cookie" 10 and "session=" 8
        let cookie = format!("session={}", "a".repeat(size_in(path) - 10 - FIELD_OVERHEAD - 18 - FIELD_OVERHEAD));
        out.extend(header_frames(stream, &encode(&[status, ("set-cookie", cookie)]), false));
        out.extend(frame(DATA, END_STREAM, stream, b"ok"));
    }
    out
}

/// An HTTP proxy that answers `CONNECT` with `200` and an `x-proxy` header making the reply's header section the size
/// asked for, then relays bytes between the two connections.
struct ConnectProxy {
    port: u16,
    tunnels: Arc<AtomicUsize>,
    response_header_bytes: Arc<AtomicUsize>,
    split_at_last_cr: Arc<AtomicBool>,
}

impl ConnectProxy {
    fn start() -> ConnectProxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let proxy = ConnectProxy { port, tunnels: Arc::default(), response_header_bytes: Arc::default(), split_at_last_cr: Arc::default() };
        let (tunnels, bytes, split) = (proxy.tunnels.clone(), proxy.response_header_bytes.clone(), proxy.split_at_last_cr.clone());
        std::thread::spawn(move || {
            for client in listener.incoming().flatten() {
                let (tunnels, bytes, split) = (tunnels.clone(), bytes.clone(), split.clone());
                std::thread::spawn(move || tunnel(client, &tunnels, bytes.load(Ordering::SeqCst), split.load(Ordering::SeqCst)));
            }
        });
        proxy
    }
}

fn tunnel(mut client: TcpStream, tunnels: &AtomicUsize, response_header_bytes: usize, split_at_last_cr: bool) {
    client.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if client.read(&mut byte).unwrap_or(0) == 0 {
            return;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let target = &head["CONNECT ".len()..head.find(" HTTP/1.1").unwrap()];
    let port: u16 = target.rsplit(':').next().unwrap().parse().unwrap();
    let Ok(upstream) = TcpStream::connect(("127.0.0.1", port)) else { return };
    tunnels.fetch_add(1, Ordering::SeqCst);
    // "x-proxy: " is 9 bytes
    let filler = if response_header_bytes > 9 { format!("x-proxy: {}\r\n", "a".repeat(response_header_bytes - 9)) } else { String::new() };
    let response = format!("HTTP/1.1 200 Connection established\r\n{filler}\r\n").into_bytes();
    // with split_at_last_cr the last header line's LF, and the blank line, arrive after its CR
    let first = if split_at_last_cr { response.len() - 3 } else { response.len() };
    let _ = client.write_all(&response[..first]);
    let _ = client.flush();
    if first < response.len() {
        std::thread::sleep(Duration::from_millis(300));
        let _ = client.write_all(&response[first..]);
        let _ = client.flush();
    }
    let (mut from_client, mut to_upstream) = (client.try_clone().unwrap(), upstream.try_clone().unwrap());
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut from_client, &mut to_upstream);
        let _ = to_upstream.shutdown(std::net::Shutdown::Both);
    });
    let (mut from_upstream, mut to_client) = (upstream, client);
    let _ = std::io::copy(&mut from_upstream, &mut to_client);
    let _ = to_client.shutdown(std::net::Shutdown::Both);
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> String {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()).unwrap_or_default()
    }
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "status {}", self.status)?;
        for (k, v) in &self.headers {
            if v.len() > 60 { write!(f, ", {k}: {} bytes", v.len())? } else { write!(f, ", {k}: {v}")? }
        }
        if self.body.len() > 300 { write!(f, ", body {} bytes", self.body.len()) } else { write!(f, ", body {}", self.body) }
    }
}

/// One request on its own connection, as the Java test's raw socket sends it.
async fn exchange(port: u16, method: &str, path: &str, extra_headers: &str) -> Response {
    let raw = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{extra_headers}Content-Length: 0\r\nConnection: close\r\n\r\n");
    tokio::task::spawn_blocking(move || {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        s.write_all(raw.as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        let text: String = out.iter().map(|&b| b as char).collect();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let mut lines = head.split("\r\n");
        let status = lines.next().filter(|l| l.len() >= 12).and_then(|l| l[9..12].parse().ok()).unwrap_or(0);
        let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string())).collect();
        Response { status, headers, body: body.to_string() }
    })
    .await
    .unwrap()
}

async fn get(port: u16, path: &str) -> Response {
    exchange(port, "GET", path, "").await
}

async fn forwarding(extra: &[(&str, &str)]) -> common::Running {
    let mut properties = vec![("logLevel", "WARN"), ("forwardProxyHttp2Upgrade", "true")];
    properties.extend_from_slice(extra);
    common::start(&properties).await
}

/// `forgetLogAndForward`: a reset, then `/http2/.*` and `/small/.*` forwarded over HTTPS.
async fn forget_log_and_forward(port: u16, http2: u16, small: Option<u16>) {
    common::send(port, "PUT", "/mockserver/reset", "").await;
    let forward = |path: &str, upstream: u16| json!({"httpRequest": {"path": path}, "httpForward": {"host": "127.0.0.1", "port": upstream, "scheme": "HTTPS"}});
    common::expect(port, &forward("/http2/.*", http2)).await;
    if let Some(small) = small {
        common::expect(port, &forward("/small/.*", small)).await;
    }
}

/// `assertFailedWithOneWarning`.
async fn assert_failed_with_one_warning(port: u16, response: &Response, reason: &str) {
    assert_eq!(response.status, 502, "{response:?}");
    assert_eq!(response.body, reason);
    let logs = common::logs(port).await;
    let entries: Vec<&str> = logs.split("------------------------------------\n").filter(|e| e.contains("failing forward") || e.to_lowercase().contains("exception")).collect();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert!(entries[0].contains("failing forward to") && entries[0].contains(reason), "{entries:?}");
}

fn count(events: &Events, prefix: &str) -> usize {
    events.lock().unwrap().iter().filter(|e| e.starts_with(prefix)).count()
}

async fn await_event(events: &Events, event: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !events.lock().unwrap().iter().any(|e| e == event) {
        assert!(Instant::now() < deadline, "upstream saw {:?} and not {event}", events.lock().unwrap());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_relay_a_header_list_of_exactly_max_header_size_over_http2_and_fail_larger_ones() {
    let events = Events::default();
    let upstream = H2Upstream::start(events.clone(), None).await;
    let limited = forwarding(&[("maxHeaderSize", &LIMIT.to_string())]).await;
    forget_log_and_forward(limited.port, upstream.port, None).await;
    let at_limit = get(limited.port, &format!("/http2/headers/{LIMIT}")).await;
    assert_eq!(at_limit.status, 200, "{at_limit:?}");
    assert_eq!(at_limit.header("set-cookie").len(), "session=".len() + LIMIT - 92);
    assert_eq!(at_limit.body, "ok");

    events.lock().unwrap().clear();
    let path = format!("/http2/headers/{}", LIMIT + 1);
    let over_limit = get(limited.port, &path).await;
    assert_failed_with_one_warning(limited.port, &over_limit, &format!("upstream response headers are larger than maxHeaderSize ({LIMIT} bytes)")).await;
    // a stream error; the server then closes the connection, which carried only this forward
    await_event(&events, "goaway:0").await;
    assert!(!events.lock().unwrap().iter().any(|e| e == "goaway:1"), "{:?}", events.lock().unwrap());
    assert_eq!(count(&events, &format!("request:{path}")), 1, "sent once");
    assert_eq!(get(limited.port, "/http2/headers/1000").await.status, 200, "the next forward is served");
    limited.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fail_a_response_whose_header_block_is_more_than_a_quarter_over_over_http2() {
    let events = Events::default();
    let upstream = H2Upstream::start(events.clone(), None).await;
    let limited = forwarding(&[("maxHeaderSize", &LIMIT.to_string())]).await;
    forget_log_and_forward(limited.port, upstream.port, None).await;
    // a pooled connection, on which a failure that looks like a stale connection is retried
    assert_eq!(get(limited.port, "/http2/headers/1000").await.status, 200);

    let path = format!("/http2/headers/{}", 3 * LIMIT);
    let far_over = get(limited.port, &path).await;
    let reason = format!("an upstream response header block is more than a quarter larger than maxHeaderSize ({LIMIT} bytes)");
    assert_failed_with_one_warning(limited.port, &far_over, &reason).await;
    await_event(&events, "goaway:1").await;
    assert_eq!(count(&events, &format!("request:{path}")), 1, "sent once");
    assert_eq!(get(limited.port, "/http2/headers/1000").await.status, 200, "the next forward is served");
    limited.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_limit_http2_response_trailers_by_max_header_size() {
    let upstream = H2Upstream::start(Events::default(), None).await;
    let limited = forwarding(&[("maxHeaderSize", &LIMIT.to_string())]).await;
    forget_log_and_forward(limited.port, upstream.port, None).await;
    let within = get(limited.port, &format!("/http2/trailers/{LIMIT}")).await;
    assert_eq!(within.status, 200, "{within:?}");
    assert_eq!(within.body, "ok");

    let over_limit = get(limited.port, &format!("/http2/trailers/{}", LIMIT + 1)).await;
    assert_failed_with_one_warning(limited.port, &over_limit, &format!("upstream response trailers are larger than maxHeaderSize ({LIMIT} bytes)")).await;
    assert_eq!(get(limited.port, "/http2/headers/1000").await.status, 200, "the next forward is served");
    limited.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reuse_a_pooled_http2_connection_after_a_large_response_head() {
    let upstream = H2Upstream::start(Events::default(), None).await;
    let defaults = forwarding(&[]).await;
    forget_log_and_forward(defaults.port, upstream.port, None).await;
    assert_eq!(get(defaults.port, "/http2/headers/1000").await.status, 200);
    let before = upstream.connections();
    for _ in 0..3 {
        let response = get(defaults.port, &format!("/http2/headers/{}", 100 * 1024)).await;
        assert_eq!(response.status, 200, "{response:?}");
        assert_eq!(response.body, "ok");
    }
    assert_eq!(upstream.connections() - before, 0);
    defaults.server.shutdown().await;
}

async fn through_proxy(proxy: &ConnectProxy) -> common::Running {
    forwarding(&[("maxHeaderSize", &LIMIT.to_string()), ("forwardHttpsProxy", &format!("127.0.0.1:{}", proxy.port))]).await
}

#[tokio::test(flavor = "multi_thread")]
async fn should_relay_a_response_through_an_upstream_proxy_whose_connect_response_has_large_headers() {
    let upstream = H2Upstream::start(Events::default(), None).await;
    let proxy = ConnectProxy::start();
    let server = through_proxy(&proxy).await;
    forget_log_and_forward(server.port, upstream.port, None).await;
    proxy.response_header_bytes.store(LIMIT, Ordering::SeqCst);
    let before = proxy.tunnels.load(Ordering::SeqCst);

    let response = get(server.port, &format!("/http2/headers/{}", 20 * 1024)).await;

    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.header("set-cookie").len(), "session=".len() + 20 * 1024 - 92);
    assert_eq!(response.body, "ok");
    assert_eq!(proxy.tunnels.load(Ordering::SeqCst) - before, 1);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_limit_the_upstream_proxys_connect_response_headers_exactly_when_their_last_line_end_arrives_split() {
    let upstream = H2Upstream::start(Events::default(), None).await;
    let proxy = ConnectProxy::start();
    let server = through_proxy(&proxy).await;
    forget_log_and_forward(server.port, upstream.port, None).await;
    proxy.split_at_last_cr.store(true, Ordering::SeqCst);
    proxy.response_header_bytes.store(LIMIT, Ordering::SeqCst);

    let response = get(server.port, "/http2/headers/1000").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.body, "ok");

    proxy.response_header_bytes.store(LIMIT + 1, Ordering::SeqCst);
    let reason = format!("the upstream proxy's CONNECT response headers are larger than maxHeaderSize ({LIMIT} bytes)");
    assert_failed_with_one_warning(server.port, &get(server.port, "/http2/headers/1000").await, &reason).await;
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fail_a_forward_when_the_upstream_proxys_connect_response_headers_are_over_the_limit() {
    let upstream = H2Upstream::start(Events::default(), None).await;
    let proxy = ConnectProxy::start();
    let server = through_proxy(&proxy).await;
    forget_log_and_forward(server.port, upstream.port, None).await;
    proxy.response_header_bytes.store(LIMIT + 1, Ordering::SeqCst);
    let started = Instant::now();

    let response = get(server.port, "/http2/headers/1000").await;

    let reason = format!("the upstream proxy's CONNECT response headers are larger than maxHeaderSize ({LIMIT} bytes)");
    assert_failed_with_one_warning(server.port, &response, &reason).await;
    assert!(started.elapsed() < Duration::from_secs(5), "without waiting out the proxy connect timeout");
    server.server.shutdown().await;
}

/// RFC 9113 section 6.5.2 makes `SETTINGS_MAX_HEADER_LIST_SIZE` advisory, so the forward client does not apply an
/// upstream's to the requests it sends: the upstream answers for itself (431), whether the request went on a new
/// connection or on a pooled one that had already read the upstream's settings.
#[tokio::test(flavor = "multi_thread")]
async fn should_send_a_request_over_the_limit_an_http2_upstream_announced_and_relay_its_answer() {
    let events = Events::default();
    let http2 = H2Upstream::start(events.clone(), None).await;
    let small = H2Upstream::start(events.clone(), Some(UPSTREAM_REQUEST_LIMIT)).await;
    let large = format!("x-large: {}\r\n", "a".repeat(20 * 1024));
    for method in ["GET", "POST"] {
        let server = forwarding(&[]).await;
        forget_log_and_forward(server.port, http2.port, Some(small.port)).await;
        let before = small.connections();

        let on_a_new_connection = exchange(server.port, method, "/small/headers/1000", &large).await;

        assert_eq!(on_a_new_connection.status, 431, "{method} {on_a_new_connection:?}");
        assert_eq!(small.connections() - before, 1, "{method} went on a new connection");

        assert_eq!(get(server.port, "/small/headers/1000").await.status, 200);
        let before = small.connections();

        let on_a_pooled_connection = exchange(server.port, method, "/small/headers/1000", &large).await;

        assert_eq!(on_a_pooled_connection.status, 431, "{method} {on_a_pooled_connection:?}");
        assert_eq!(small.connections() - before, 0, "{method} went on the pooled connection");
        assert_eq!(on_a_pooled_connection.body, on_a_new_connection.body);
        assert_eq!(get(server.port, "/small/headers/1000").await.status, 200, "the upstream is still served");
        server.server.shutdown().await;
    }
}

/// An upstream that reads a header block more than a quarter over the limit it announced treats it as a connection
/// error and closes the connection without an answer: the client is answered 502. On a pooled connection that is what
/// a stale connection looks like, so an idempotent request is sent once more on a new connection, where it meets the
/// same end; any other request is sent once.
#[tokio::test(flavor = "multi_thread")]
async fn should_answer_502_when_an_http2_upstream_closes_the_connection_for_a_request_far_over_its_limit() {
    let events = Events::default();
    let http2 = H2Upstream::start(Events::default(), None).await;
    let small = H2Upstream::start(events.clone(), Some(UPSTREAM_REQUEST_LIMIT)).await;
    // 'a' takes 5 bits in HPACK's Huffman code, so this block is about 1.5 times the upstream's limit
    let far_over = format!("x-large: {}\r\n", "a".repeat(40 * 1024));
    let refused = |events: &Events| count(events, "connection-error:Header size exceeded max allowed size");
    for method in ["GET", "POST"] {
        let server = forwarding(&[]).await;
        forget_log_and_forward(server.port, http2.port, Some(small.port)).await;
        events.lock().unwrap().clear();
        let before = small.connections();

        let on_a_new_connection = exchange(server.port, method, "/small/headers/1000", &far_over).await;

        assert_eq!(on_a_new_connection.status, 502, "{method} {on_a_new_connection:?}");
        assert_eq!(on_a_new_connection.body, "");
        assert_eq!(refused(&events), 1, "{method} sent once");
        assert_eq!(small.connections() - before, 1);

        assert_eq!(get(server.port, "/small/headers/1000").await.status, 200);
        events.lock().unwrap().clear();
        let before = small.connections();

        let on_a_pooled_connection = exchange(server.port, method, "/small/headers/1000", &far_over).await;

        let idempotent = method == "GET";
        assert_eq!(on_a_pooled_connection.status, 502, "{method} {on_a_pooled_connection:?}");
        // upstream 48b7e14d2 (9.1.0): a request that is not sent again names the pooled connection the upstream closed
        let pooled = "upstream closed the pooled keep-alive connection the request was sent on without answering, and a POST is not sent again in case the upstream acted on it: if the upstream closes idle connections, set forwardConnectionPoolIdleTimeoutMillis below its keep-alive timeout or set forwardConnectionPoolEnabled to false; otherwise the upstream may have closed the connection to reject the request";
        assert_eq!(on_a_pooled_connection.body, if idempotent { "" } else { pooled });
        assert_eq!(refused(&events), if idempotent { 2 } else { 1 }, "{method} sent again only if idempotent");
        assert_eq!(small.connections() - before, if idempotent { 1 } else { 0 }, "{method} on a new connection only for the second attempt");
        assert_eq!(get(server.port, "/small/headers/1000").await.status, 200, "the upstream is still served");
        server.server.shutdown().await;
    }
}

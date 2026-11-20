//! The CONNECT relay's loopback leg on compressed and streamed responses: what MockServer writes into a
//! CONNECT tunnel is read back through `BoundedZstdHttpContentDecompressor` and `StreamingAwareHttpObjectAggregator`
//! (HTTP/1.1) or `LoopbackHttp2ResponseStreamer` and `LoopbackAggregatingListener` (HTTP/2) before the client gets it.
//! Ports of:
//! - `ConnectRelayStreamErrorIntegrationTest`: `shouldAnswerA502WhenAnAggregatedHttp1ResponseFailsToDecode`,
//!   `shouldCloseWithoutTheTerminatingChunkWhenAStreamedHttp1ResponseFailsToDecode`,
//!   `shouldResetTheClientStreamWhenTheGzipResponseIsCorrupt`, `shouldResetTheClientStreamWhenTheResponseFailsToDecode`;
//! - `Http2TunnelStreamedResponseIntegrationTest.shouldRelayACompressedResponseOfDeclaredLengthAsBefore` (CONNECT and
//!   SOCKS5, TLS and h2c);
//! - `ConnectProxyStreamingResponseIntegrationTest`: `shouldStreamThroughConnectProxyWhenAGzipRequestBodyAsksForStream`,
//!   `...WhenAZstdRequestBodyAsksForStream`, `...WhenALargeGzipRequestBodyAsksForStreamAtItsEnd`,
//!   `shouldRelayAlikeThroughAnHttp2ConnectTunnelWhetherTheStreamingRequestIsGzippedOrNot`, and the aggregated controls;
//! - `StreamedResponseDecodeBoundIntegrationTest.shouldAbortAZstdStreamDecodedByTheConnectRelayOverHttp1`.

use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common;

trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

const CORRUPT_GZIP: [u8; 14] = [0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff];
const CORRUPT_ZSTD: [u8; 9] = [0x28, 0xB5, 0x2F, 0xFD, 0x20, 0x05, 0x07, 0x00, 0x00];
/// How long [`sse_upstream`] withholds its late event when the test does not release it: only a client that never
/// sees the early event (an aggregated response) waits it out.
const LATE_EVENT_HOLD: Duration = Duration::from_secs(20);
/// How long a streamed response's client waits for its first byte before releasing the late event: well inside
/// [`LATE_EVENT_HOLD`], so a byte that came only because the hold ran out is never taken for a streamed one.
const STREAMED_WATCH: Duration = Duration::from_secs(15);
/// How long an aggregated response's client watches for a byte before it releases the late event (upstream's own
/// tests: the late event 2 s after the early one, an aggregated first byte at 1.5 s or later).
const AGGREGATED_WATCH: Duration = Duration::from_millis(1500);

fn base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

/// 2 GiB of zeros in zstd in 64 KiB: one frame of 16384 RLE blocks of 128 KiB each.
fn zstd_bomb() -> Vec<u8> {
    let mut bomb = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x38];
    for i in 0..16384 {
        let header: u32 = (128 * 1024) << 3 | 1 << 1 | u32::from(i == 16383);
        bomb.extend_from_slice(&header.to_le_bytes()[..3]);
        bomb.push(0);
    }
    bomb
}

/// Over-the-window text, so the HTTP/2 flow control is exercised as upstream's `Http2FlowControlBodies.OVER_WINDOW`.
fn over_window(tag: &str) -> String {
    let mut text = String::new();
    for i in 0.. {
        if text.len() > 70 * 1024 {
            break;
        }
        text.push_str(&format!("{tag}-{i};"));
    }
    text
}

async fn read_head<S: AsyncRead + Unpin>(io: &mut S) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(io.read_u8().await.unwrap());
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// A CONNECT (or, `socks`, a SOCKS5 CONNECT) to `localhost:443` through the server; then TLS offering `alpn`, or the
/// bare tunnel when `alpn` is `None`.
async fn tunnel(port: u16, socks: bool, alpn: Option<&[u8]>) -> Box<dyn Io> {
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    if socks {
        socket.write_all(&[5, 1, 0]).await.unwrap();
        let mut choice = [0u8; 2];
        socket.read_exact(&mut choice).await.unwrap();
        let mut connect = vec![5, 1, 0, 3, 9];
        connect.extend_from_slice(b"localhost");
        connect.extend_from_slice(&443u16.to_be_bytes());
        socket.write_all(&connect).await.unwrap();
        let mut reply = [0u8; 4];
        socket.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0, "the SOCKS5 CONNECT succeeded");
        let address = match reply[3] {
            1 => 4,
            4 => 16,
            _ => usize::from(socket.read_u8().await.unwrap()),
        };
        let mut bound = vec![0u8; address + 2];
        socket.read_exact(&mut bound).await.unwrap();
    } else {
        socket.write_all(b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n").await.unwrap();
        let head = read_head(&mut socket).await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    }
    let Some(alpn) = alpn else { return Box::new(socket) };
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let tls = tokio_rustls::TlsConnector::from(common::tls_client_config(alpn)).connect(name, socket).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(alpn));
    Box::new(tls)
}

struct H1 {
    status: u16,
    head: String,
    /// The terminating chunk (or the declared length) arrived.
    complete: bool,
}

/// One HTTP/1.1 exchange over `io`, read to the end of the response or of the connection.
async fn h1(mut io: Box<dyn Io>, request: &[u8]) -> H1 {
    io.write_all(request).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), io.read_to_end(&mut raw)).await;
    let at = raw.windows(4).position(|w| w == b"\r\n\r\n").map_or(raw.len(), |i| i + 4);
    let head = String::from_utf8_lossy(&raw[..at]).into_owned();
    let status = head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let rest = &raw[at..];
    if !head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        let declared = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok()));
        return H1 { status, head, complete: declared.is_none_or(|n| n == rest.len()) };
    }
    let (mut at, mut complete) = (0, false);
    while let Some(line) = rest[at..].windows(2).position(|w| w == b"\r\n") {
        let size = usize::from_str_radix(String::from_utf8_lossy(&rest[at..at + line]).trim(), 16).unwrap_or(0);
        at += line + 2;
        if size == 0 {
            complete = rest[at..].starts_with(b"\r\n");
            break;
        }
        if rest.len() < at + size {
            break;
        }
        at += size + 2;
    }
    H1 { status, head, complete }
}

fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: localhost:443\r\nConnection: close\r\n\r\n").into_bytes()
}

/// How an HTTP/2 stream ended: its status and body, or the code of the reset that ended it.
#[derive(Debug)]
enum H2 {
    Answered { status: u16, headers: http::HeaderMap, body: Vec<u8> },
    Reset(h2::Reason),
}

async fn h2_send(sender: &h2::client::SendRequest<bytes::Bytes>, request: http::Request<()>, body: Option<Vec<u8>>) -> (H2, Duration) {
    let started = Instant::now();
    let mut sender = sender.clone().ready().await.unwrap();
    let (response, mut upload) = sender.send_request(request, body.is_none()).unwrap();
    if let Some(body) = body {
        upload.send_data(body.into(), true).unwrap();
    }
    let response = match tokio::time::timeout(Duration::from_secs(20), response).await.expect("an answer") {
        Ok(response) => response,
        Err(e) => return (H2::Reset(e.reason().expect("a reset")), started.elapsed()),
    };
    let elapsed = started.elapsed();
    let (parts, mut stream) = response.into_parts();
    let mut body = Vec::new();
    while let Some(chunk) = tokio::time::timeout(Duration::from_secs(20), stream.data()).await.expect("the stream ends") {
        match chunk {
            Ok(chunk) => {
                let _ = stream.flow_control().release_capacity(chunk.len());
                body.extend_from_slice(&chunk);
            }
            Err(e) => return (H2::Reset(e.reason().expect("a reset")), elapsed),
        }
    }
    (H2::Answered { status: parts.status.as_u16(), headers: parts.headers, body }, elapsed)
}

async fn h2_client(io: Box<dyn Io>) -> h2::client::SendRequest<bytes::Bytes> {
    let (sender, connection) = h2::client::handshake(io).await.unwrap();
    tokio::spawn(connection);
    sender
}

fn h2_get(path: &str) -> http::Request<()> {
    http::Request::builder().uri(format!("https://localhost:443{path}")).body(()).unwrap()
}

/// `ConnectRelayStreamErrorIntegrationTest`: a response the loopback cannot decode reaches the client at once, as a 502
/// (HTTP/1.1, aggregated), a response closed before its terminating chunk (HTTP/1.1, streamed), or a reset stream
/// with INTERNAL_ERROR alongside a healthy one (HTTP/2).
#[tokio::test(flavor = "multi_thread")]
async fn a_response_the_loopback_cannot_decode_fails_promptly() {
    let server = common::start(&[]).await;
    let port = server.port;
    let healthy = over_window("relay-stream-error-healthy");
    let mock = |path: &str, headers: serde_json::Value, body: serde_json::Value| json!({"httpRequest": {"path": path}, "httpResponse": {"headers": headers, "body": body}});
    common::expect(port, &mock("/healthy", json!({}), json!(healthy))).await;
    common::expect(port, &json!({"httpRequest": {"path": "/slow"}, "httpResponse": {"body": healthy, "delay": {"timeUnit": "MILLISECONDS", "value": 500}}})).await;
    let binary = |bytes: &[u8]| json!({"type": "BINARY", "base64Bytes": base64(bytes)});
    common::expect(port, &mock("/corrupt-gzip", json!({"content-encoding": ["gzip"]}), binary(&CORRUPT_GZIP))).await;
    common::expect(port, &mock("/corrupt-gzip-stream", json!({"content-type": ["text/event-stream"], "content-encoding": ["gzip"]}), binary(&CORRUPT_GZIP))).await;
    common::expect(port, &mock("/corrupt-zstd", json!({"content-encoding": ["zstd"]}), binary(&CORRUPT_ZSTD))).await;

    // shouldAnswerA502WhenAnAggregatedHttp1ResponseFailsToDecode
    let started = Instant::now();
    let answer = h1(tunnel(port, false, Some(b"http/1.1")).await, &get("/corrupt-gzip")).await;
    assert_eq!(answer.status, 502, "{}", answer.head);
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    // shouldCloseWithoutTheTerminatingChunkWhenAStreamedHttp1ResponseFailsToDecode
    let started = Instant::now();
    let answer = h1(tunnel(port, false, Some(b"http/1.1")).await, &get("/corrupt-gzip-stream")).await;
    assert!(!answer.complete, "{}", answer.head);
    assert!(answer.head.starts_with("HTTP/1.1 200"), "{}", answer.head);
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());

    // shouldResetTheClientStreamWhenTheGzipResponseIsCorrupt, shouldResetTheClientStreamWhenTheResponseFailsToDecode
    for path in ["/corrupt-gzip", "/corrupt-zstd"] {
        let sender = h2_client(tunnel(port, false, Some(b"h2")).await).await;
        let in_flight = tokio::spawn({
            let sender = sender.clone();
            async move { h2_send(&sender, h2_get("/slow"), None).await }
        });
        let (failed, elapsed) = h2_send(&sender, h2_get(path), None).await;
        assert!(matches!(failed, H2::Reset(h2::Reason::INTERNAL_ERROR)), "{path}: {failed:?}");
        assert!(elapsed < Duration::from_secs(2), "{path}: {elapsed:?}");
        for (outcome, _) in [in_flight.await.unwrap(), h2_send(&sender, h2_get("/healthy"), None).await] {
            assert!(matches!(&outcome, H2::Answered { status: 200, body, .. } if *body == healthy.as_bytes()), "{path}: {outcome:?}");
        }
    }
    server.server.shutdown().await;
}

/// `Http2TunnelStreamedResponseIntegrationTest.shouldRelayACompressedResponseOfDeclaredLengthAsBefore`, each route: a
/// gzip response MockServer mocks reaches the tunnel's HTTP/2 client decoded, with its decoded length.
#[tokio::test(flavor = "multi_thread")]
async fn a_compressed_response_of_declared_length_is_decoded_in_an_http2_tunnel() {
    let server = common::start(&[]).await;
    let port = server.port;
    for (route, socks, tls) in [("CONNECT_TLS", false, true), ("CONNECT_H2C", false, false), ("SOCKS5_TLS", true, true), ("SOCKS5_H2C", true, false)] {
        let text = over_window(&format!("compressed-through-{route}"));
        common::expect(port, &json!({"httpRequest": {"path": "/compressed"}, "httpResponse": {"headers": {"content-encoding": ["gzip"]}, "body": {"type": "BINARY", "base64Bytes": base64(&gzip(text.as_bytes()))}}})).await;
        let io = tunnel(port, socks, tls.then_some(b"h2".as_slice())).await;
        let (answer, _) = h2_send(&h2_client(io).await, h2_get("/compressed"), None).await;
        let H2::Answered { status, headers, body } = answer else { panic!("{route}: {answer:?}") };
        assert_eq!(status, 200, "{route}");
        assert!(body == text.as_bytes(), "{route}: {} bytes", body.len());
        assert_eq!(headers.get("content-length").and_then(|v| v.to_str().ok()), Some(text.len().to_string().as_str()), "{route}");
        assert!(headers.get("content-encoding").is_none(), "{route}");
        common::send(port, "PUT", "/mockserver/reset", "").await;
    }
    server.server.shutdown().await;
}

/// `NoContentTypeSseUpstreamHandler`: a server-sent event stream without a content type, its late event withheld
/// until the test adds a permit to the returned semaphore (or [`LATE_EVENT_HOLD`] passes). Upstream withholds it for a
/// fixed 2 s and times the client's first byte against that; holding it until the client has read (or watched for)
/// its first byte makes "the early event reached the client before the late one existed" a fact rather than a race
/// with the machine's load (the 300 KB gzip case's first byte took 1.6-2.1 s in full runs).
async fn sse_upstream() -> (u16, Arc<tokio::sync::Semaphore>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let releases = release.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { return };
            let release = releases.clone();
            tokio::spawn(async move {
                let head = read_head(&mut socket).await;
                let length = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                let mut body = vec![0u8; length];
                socket.read_exact(&mut body).await.unwrap();
                let _ = socket.write_all(b"HTTP/1.1 200 OK\r\ncache-control: no-cache\r\ntransfer-encoding: chunked\r\n\r\nd\r\ndata: early\n\n\r\n").await;
                if let Ok(Ok(permit)) = tokio::time::timeout(LATE_EVENT_HOLD, release.acquire()).await {
                    permit.forget();
                }
                let _ = socket.write_all(b"c\r\ndata: late\n\n\r\n0\r\n\r\n").await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, release)
}

fn streaming_body(messages: &str) -> Vec<u8> {
    format!("{{\"model\":\"x\",\"messages\":[{messages}{{\"role\":\"user\",\"content\":\"hi\"}}],\"stream\": true}}").into_bytes()
}

fn compressed_json_request(coding: &str, body: &[u8]) -> Vec<u8> {
    let mut request = format!("POST /codex-stream HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Encoding: {coding}\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    request.extend_from_slice(body);
    request
}

/// Sends `request` through a TLS CONNECT tunnel to [`sse_upstream`]: whether its answer's first byte came while the
/// upstream still withheld the late event (`watch`: how long to wait for that byte before releasing it), and the text
/// read until `data: late` (or the end).
async fn over_tunnel(port: u16, release: &tokio::sync::Semaphore, request: &[u8], watch: Duration) -> (bool, String) {
    let mut io = tunnel(port, false, Some(b"http/1.1")).await;
    io.write_all(request).await.unwrap();
    let early = tokio::time::timeout(watch, io.read_u8()).await;
    release.add_permits(1);
    let (before_late, first) = match early {
        Ok(first) => (true, first.unwrap()),
        Err(_) => (false, tokio::time::timeout(Duration::from_secs(15), io.read_u8()).await.unwrap().unwrap()),
    };
    let mut text = vec![first];
    let mut buffer = [0u8; 4096];
    while !String::from_utf8_lossy(&text).contains("data: late") {
        match tokio::time::timeout(Duration::from_secs(15), io.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => text.extend_from_slice(&buffer[..n]),
            _ => break,
        }
    }
    (before_late, String::from_utf8_lossy(&text).into_owned())
}

/// `ConnectProxyStreamingResponseIntegrationTest`'s compressed requests: a gzip or zstd JSON body asking for a stream
/// (also one whose `"stream": true` comes after 300 KB of history) is relayed through the tunnel as it arrives; one not
/// asking is aggregated; over an HTTP/2 tunnel a gzipped streaming request is relayed as promptly as a plain one.
#[tokio::test(flavor = "multi_thread")]
async fn a_compressed_request_asking_for_a_stream_streams_through_a_tunnel() {
    let (upstream, release) = sse_upstream().await;
    let server = common::start(&[]).await;
    let port = server.port;
    common::expect(port, &json!({"httpRequest": {}, "httpForward": {"host": "127.0.0.1", "port": upstream}})).await;
    // a streamed answer's first byte arrives while the late event is withheld, however long the server takes to read
    // and inflate the request; the hold's own bound is the only clock
    let streamed = |(before_late, text): (bool, String), case: &str| {
        assert!(text.contains("200") && text.contains("data: late"), "{case}: {text}");
        assert!(before_late, "{case}: no byte before the late event was released ({STREAMED_WATCH:?})");
    };
    let over = |request: Vec<u8>, watch: Duration| {
        let release = release.clone();
        async move { over_tunnel(port, &release, &request, watch).await }
    };
    streamed(over(compressed_json_request("gzip", &gzip(&streaming_body(""))), STREAMED_WATCH).await, "gzip");
    let zstd = zstd::bulk::compress(&streaming_body(""), 3).unwrap();
    streamed(over(compressed_json_request("zstd", &zstd), STREAMED_WATCH).await, "zstd");
    let mut history = String::new();
    for i in 0.. {
        if history.len() >= 300_000 {
            break;
        }
        history.push_str(&format!("{{\"role\":\"user\",\"content\":\"message {i} {:x}\"}},", i * 7919));
    }
    streamed(over(compressed_json_request("gzip", &gzip(&streaming_body(&history))), STREAMED_WATCH).await, "large gzip");
    // shouldAggregateThroughConnectProxyWhenAGzipRequestBodyDoesNotAskForStream: nothing comes while the late event is
    // withheld (load only delays a byte, so it cannot fake this), then both events together
    let (before_late, text) = over(compressed_json_request("gzip", &gzip(b"{\"stream\":false,\"model\":\"x\"}")), AGGREGATED_WATCH).await;
    assert!(text.contains("data: early") && text.contains("data: late"), "{text}");
    assert!(!before_late, "aggregated: a byte came before the late event was released: {text}");

    // shouldRelayAlikeThroughAnHttp2ConnectTunnelWhetherTheStreamingRequestIsGzippedOrNot
    let mut prompt = Vec::new();
    for coding in [None, Some("gzip")] {
        let sender = h2_client(tunnel(port, false, Some(b"h2")).await).await;
        let mut request = http::Request::builder().method("POST").uri("https://127.0.0.1:443/codex-stream").header("content-type", "application/json");
        let body = match coding {
            Some(coding) => {
                request = request.header("content-encoding", coding);
                gzip(&streaming_body(""))
            }
            None => streaming_body(""),
        };
        // prompt: the response head came while the late event was withheld
        let mut sender = sender.ready().await.unwrap();
        let (response, mut upload) = sender.send_request(request.body(()).unwrap(), false).unwrap();
        upload.send_data(body.into(), true).unwrap();
        let mut response = Box::pin(response);
        let head = tokio::time::timeout(STREAMED_WATCH, &mut response).await;
        release.add_permits(1);
        prompt.push(head.is_ok());
        let response = match head {
            Ok(response) => response,
            Err(_) => tokio::time::timeout(Duration::from_secs(20), response).await.expect("an answer"),
        };
        let mut stream = response.unwrap_or_else(|e| panic!("{coding:?}: {e}")).into_body();
        let mut text = Vec::new();
        while let Some(chunk) = tokio::time::timeout(Duration::from_secs(20), stream.data()).await.expect("the stream ends") {
            let chunk = chunk.unwrap_or_else(|e| panic!("{coding:?}: {e}"));
            let _ = stream.flow_control().release_capacity(chunk.len());
            text.extend_from_slice(&chunk);
        }
        assert!(String::from_utf8_lossy(&text).contains("data: late"), "{coding:?}: {}", String::from_utf8_lossy(&text));
    }
    assert_eq!(prompt[0], prompt[1], "a gzipped streaming request is relayed as promptly as an uncompressed one");
    server.server.shutdown().await;
}

/// `StreamedResponseDecodeBoundIntegrationTest.shouldAbortAZstdStreamDecodedByTheConnectRelayOverHttp1`: a mocked
/// `text/event-stream` response of 2 GiB of zeros in zstd, through a cleartext CONNECT tunnel to a client that does not
/// read: the loopback decodes past the bound (`maxRequestBodySize`, 1 MiB) in its first read and aborts, so the client's
/// response ends incomplete, and the server still serves.
#[tokio::test(flavor = "multi_thread")]
async fn a_zstd_stream_decoded_by_the_connect_relay_is_aborted_past_the_bound() {
    let server = common::start(&[("streamingResponsesEnabled", "true"), ("maxResponseBodySize", "1048576"), ("maxRequestBodySize", "1048576")]).await;
    let port = server.port;
    let bomb = zstd_bomb();
    common::expect(port, &json!({"httpRequest": {"path": "/mock/stream/zstd-bomb"}, "httpResponse": {"headers": {"content-type": ["text/event-stream"], "content-encoding": ["zstd"]}, "body": {"type": "BINARY", "base64Bytes": base64(&bomb)}}})).await;
    // the tunnel's target, never reached: the response is MockServer's own
    let target = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap().local_addr().unwrap().port();
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket.write_all(format!("CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n").as_bytes()).await.unwrap();
    let head = read_head(&mut socket).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    socket.write_all(format!("GET /mock/stream/zstd-bomb HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\nAccept: text/event-stream\r\n\r\n").as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut received = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    while received.len() < 64 * 1024 * 1024 {
        match tokio::time::timeout(Duration::from_secs(10), socket.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => received.extend_from_slice(&buffer[..n]),
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&received[..received.len().min(200)]).into_owned();
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(received.len() < 64 * 1024 * 1024, "{} bytes", received.len());
    assert!(!received.ends_with(b"0\r\n\r\n"), "the response has no terminating chunk");
    assert_eq!(common::send(port, "PUT", "/mockserver/status", "").await.status, 200);
    server.server.shutdown().await;
}

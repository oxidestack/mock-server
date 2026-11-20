//! Forwarding fixes upstream made after 8.0.0 and adopted here as divergences (`docs/divergences.md`),
//! each against a raw-socket upstream so both legs are seen as bytes:
//! - d639e3622 `NoContentTypeBinaryBodyIntegrationTest`: a body with no `Content-Type` forwarded and recorded byte
//!   for byte;
//! - cc8fb880a `ForwardContentEncodingIntegrationTest` / `ForwardedRequestContentEncodingTest`: a content-encoded
//!   request body forwarded as received, a changed one encoded again;
//! - dc39a6a11 `FullHttpResponseToMockServerHttpResponseTest`: an upstream response header named `!foo` or valued `?x`
//!   recorded literally;
//! - 89d8a61c9 `HttpActionHandlerForwardTimeoutTest`: a silent upstream with `maxSocketTimeout` 0 answered 502 after
//!   `maxFutureTimeout`;
//! - a78886b4d `ForwardHeaderLimitIntegrationTest`: upstream response headers read up to `maxHeaderSize`;
//! - 7a8b8c424 `NettyHttpClientTlsFailureTest` / `HttpActionHandlerForwardFailureTest`: a TLS failure named in the 502;
//! - the log entries of the a78886b4d and 7a8b8c424 failures, as the fixed snapshot image logs them;
//! - 4180cbdb4 `NettyHttpClientTlsHandshakeTimeoutTest`: the handshake bounded by `socketConnectionTimeoutInMillis`,
//!   and the JDK texts of expired, not yet valid and badly signed certificates;
//! - 8.0.0's own behaviour where no scenario can pin it: the binary proxy's TLS failure,
//!   HTTP/2 aggregation limits, a streamed zstd response;
//! - c990e4a20 `ForwardUndecodableResponseIntegrationTest`: an HTTP/1.1 response the client cannot decode answered 502
//!   with the reason, its connection closed;
//! - c9fb69fd5 `StreamedResponseAbandonIntegrationTest` and its siblings: a stream cut by its upstream, the idle
//!   timeout or undecodable content ends without its terminating chunk.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::common;

/// What the upstream does with each connection.
#[derive(Clone)]
enum Answer {
    /// Reads one request, records it and writes these bytes.
    Bytes(Vec<u8>),
    /// Reads one request, records it and never answers (the connection stays open).
    Silent,
    /// Writes these bytes as soon as the connection is accepted, before reading anything.
    Immediately(Vec<u8>),
    /// Closes the connection as soon as it is accepted.
    Close,
    /// Resets the connection (`SO_LINGER` 0) as soon as it is accepted.
    Reset,
    /// Reads what the client sends first (a ClientHello) and closes the connection (a FIN).
    ReadThenClose,
    /// Accepts the connection and neither reads nor writes for 15 seconds.
    Hold,
    /// Reads one request, records it, writes these bytes and keeps the connection open for 15 seconds.
    BytesHeld(Vec<u8>),
}

/// A raw-socket upstream on an ephemeral port that records the bytes of each request it reads.
struct RawUpstream {
    port: u16,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl RawUpstream {
    fn start(answer: Answer) -> RawUpstream {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let log = received.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let (answer, log) = (answer.clone(), log.clone());
                std::thread::spawn(move || match answer {
                    Answer::Close => drop(stream),
                    Answer::Reset => {
                        let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
                        drop(stream);
                    }
                    Answer::ReadThenClose => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.read(&mut [0u8; 4096]);
                        drop(stream);
                    }
                    Answer::Hold => {
                        std::thread::sleep(Duration::from_secs(15));
                        drop(stream);
                    }
                    Answer::Immediately(bytes) => {
                        let _ = stream.write_all(&bytes);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = stream.read(&mut [0u8; 4096]);
                    }
                    Answer::Bytes(bytes) => {
                        if let Some(request) = read_message(&mut stream) {
                            log.lock().unwrap().push(request);
                            let _ = stream.write_all(&bytes);
                        }
                    }
                    Answer::BytesHeld(bytes) => {
                        if let Some(request) = read_message(&mut stream) {
                            log.lock().unwrap().push(request);
                            let _ = stream.write_all(&bytes);
                            std::thread::sleep(Duration::from_secs(15));
                        }
                    }
                    Answer::Silent => {
                        if let Some(request) = read_message(&mut stream) {
                            log.lock().unwrap().push(request);
                            std::thread::sleep(Duration::from_secs(60));
                        }
                    }
                });
            }
        });
        RawUpstream { port, received }
    }

    fn requests(&self) -> Vec<Vec<u8>> {
        self.received.lock().unwrap().clone()
    }
}

/// One HTTP/1.1 message with a `Content-Length` body (or none), read whole.
fn read_message(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut data = Vec::new();
    let mut chunk = [0u8; 65536];
    let head_end = loop {
        if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        let n = stream.read(&mut chunk).ok().filter(|n| *n > 0)?;
        data.extend_from_slice(&chunk[..n]);
    };
    let length = header_of(&data[..head_end], "content-length").and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(0);
    while data.len() < head_end + length {
        let n = stream.read(&mut chunk).ok().filter(|n| *n > 0)?;
        data.extend_from_slice(&chunk[..n]);
    }
    Some(data)
}

fn header_of(head: &[u8], name: &str) -> Option<String> {
    String::from_utf8_lossy(head)
        .split("\r\n")
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
}

fn body_of(message: &[u8]) -> Vec<u8> {
    let at = message.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    message[at..].to_vec()
}

struct Sent {
    status: u16,
    head: String,
    body: Vec<u8>,
}

/// One request on its own connection: `headers` as written, then `content-length` and `connection: close`.
async fn send(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Sent {
    let mut raw = format!("{method} {path} HTTP/1.1\r\nHost: localhost:{port}\r\n").into_bytes();
    for (k, v) in headers {
        raw.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    raw.extend_from_slice(format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes());
    raw.extend_from_slice(body);
    tokio::task::spawn_blocking(move || {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        s.write_all(&raw).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        let at = out.windows(4).position(|w| w == b"\r\n\r\n").map_or(out.len(), |i| i + 4);
        let head = String::from_utf8_lossy(&out[..at]).into_owned();
        let status = head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        Sent { status, head, body: out[at..].to_vec() }
    })
    .await
    .unwrap()
}

async fn put(port: u16, path: &str, body: &Value) -> Value {
    let r = common::send(port, "PUT", path, &body.to_string()).await;
    serde_json::from_str(&r.body).unwrap_or(Value::Null)
}

fn forward_to(path: &str, upstream: u16) -> Value {
    json!({"httpRequest": {"path": path}, "httpForward": {"host": "127.0.0.1", "port": upstream}})
}

fn gzip(bytes: &[u8], level: u32) -> Vec<u8> {
    // a header MockServer never writes (a modification time, the best compression), so a re-encoded body would show
    let mut e = flate2::GzBuilder::new().mtime(1_700_000_000).write(Vec::new(), flate2::Compression::new(level));
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}

fn gunzip(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(bytes).read_to_end(&mut out).unwrap();
    out
}

const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

// --- cc8fb880a: a Content-Encoding request body forwarded intact -------------------------------------------------

/// `shouldForwardGzipRequestBodyByteIdentical` and the other codings of `ForwardContentEncodingIntegrationTest`: the
/// upstream gets the bytes, `content-encoding` and length that were sent, for codings the server decodes (gzip,
/// x-gzip, deflate, snappy as a raw block or framed) and for those it never decodes (a coding list, br); zstd in `zstd_request_body_is_decoded`.
#[tokio::test(flavor = "multi_thread")]
async fn content_encoded_request_body_is_forwarded_as_received() {
    let upstream = RawUpstream::start(Answer::Bytes(OK.to_vec()));
    let server = common::start(&[]).await;
    common::expect(server.port, &forward_to("/encoded", upstream.port)).await;
    let text = b"{\"metric\":\"remote write\",\"samples\":[1,2,3,4,5,6,7,8,9]}".repeat(20);
    let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    zlib.write_all(&text).unwrap();
    let deflated = zlib.finish().unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("gzip", gzip(&text, 9)),
        ("x-gzip", gzip(&text, 1)),
        ("deflate", deflated),
        ("gzip, br", text.clone()),
        ("br", text.clone()),
        ("snappy", vec![0x05, 0x10, b'h', b'e', b'l', b'l', b'o']),
        ("snappy", snappy_framed(&text)),
    ];
    for (coding, body) in &cases {
        let r = send(server.port, "POST", "/encoded", &[("Content-Type", "application/octet-stream"), ("Content-Encoding", coding)], body).await;
        assert_eq!(r.status, 200, "{coding}: {}", r.head);
        let received = upstream.requests().pop().unwrap();
        let head = &received[..received.windows(4).position(|w| w == b"\r\n\r\n").unwrap()];
        assert_eq!(header_of(head, "content-encoding").as_deref(), Some(*coding), "{coding}");
        assert_eq!(header_of(head, "content-length"), Some(body.len().to_string()), "{coding}");
        assert_eq!(&body_of(&received), body, "{coding}: the bytes as sent");
    }
    server.server.shutdown().await;
}

/// `shouldReEncodeABodyChangedByAnOverride`: a body an override replaces goes out gzipped again under the request's
/// `Content-Encoding`, and a matched forward that leaves the body alone still sends the received bytes.
#[tokio::test(flavor = "multi_thread")]
async fn changed_body_is_encoded_again_by_its_content_encoding() {
    let upstream = RawUpstream::start(Answer::Bytes(OK.to_vec()));
    let server = common::start(&[]).await;
    let socket = json!({"host": "127.0.0.1", "port": upstream.port});
    common::expect(server.port, &json!({"httpRequest": {"path": "/changed"}, "httpOverrideForwardedRequest": {"requestOverride": {"body": "changed body", "socketAddress": socket}}})).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/kept"}, "httpOverrideForwardedRequest": {"requestOverride": {"headers": {"x-added": ["1"]}, "socketAddress": socket}}})).await;
    let sent = gzip(b"original body", 9);

    let r = send(server.port, "POST", "/changed", &[("Content-Encoding", "gzip")], &sent).await;
    assert_eq!(r.status, 200, "{}", r.head);
    let received = upstream.requests().pop().unwrap();
    assert_eq!(gunzip(&body_of(&received)), b"changed body", "the override's body, gzipped");

    let r = send(server.port, "POST", "/kept", &[("Content-Encoding", "gzip")], &sent).await;
    assert_eq!(r.status, 200, "{}", r.head);
    let received = upstream.requests().pop().unwrap();
    assert!(String::from_utf8_lossy(&received).contains("x-added: 1"), "{}", String::from_utf8_lossy(&received));
    assert_eq!(body_of(&received), sent, "an unchanged body goes out as received");
    server.server.shutdown().await;
}

fn snappy_framed(bytes: &[u8]) -> Vec<u8> {
    let mut e = snap::write::FrameEncoder::new(Vec::new());
    e.write_all(bytes).unwrap();
    e.into_inner().unwrap()
}

/// `shouldReEncodeABodyChangedByAnOverride`, snappy: a changed body goes out as one raw block (what
/// `SnappyBlock` writes) when the request's body was a block, and in the framing format when it was framed.
#[tokio::test(flavor = "multi_thread")]
async fn changed_snappy_body_is_encoded_again_as_a_block_or_in_frames() {
    let upstream = RawUpstream::start(Answer::Bytes(OK.to_vec()));
    let server = common::start(&[]).await;
    let socket = json!({"host": "127.0.0.1", "port": upstream.port});
    common::expect(server.port, &json!({"httpRequest": {"path": "/changed"}, "httpOverrideForwardedRequest": {"requestOverride": {"body": "changed body", "socketAddress": socket}}})).await;

    let block = snap::raw::Encoder::new().compress_vec(b"original body").unwrap();
    let r = send(server.port, "POST", "/changed", &[("Content-Encoding", "snappy")], &block).await;
    assert_eq!(r.status, 200, "{}", r.head);
    let received = body_of(&upstream.requests().pop().unwrap());
    assert_eq!(snap::raw::Decoder::new().decompress_vec(&received).unwrap(), b"changed body", "a raw block");

    let r = send(server.port, "POST", "/changed", &[("Content-Encoding", "snappy")], &snappy_framed(b"original body")).await;
    assert_eq!(r.status, 200, "{}", r.head);
    let received = body_of(&upstream.requests().pop().unwrap());
    assert!(received.starts_with(b"\xff\x06\x00\x00sNaPpY"), "framed: {received:?}");
    let mut decoded = Vec::new();
    snap::read::FrameDecoder::new(&received[..]).read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, b"changed body");
    server.server.shutdown().await;
}

/// A zstd request body (scenario `request_decoding_codings`): decoded, matched on its decoded body,
/// and forwarded as received.
#[tokio::test(flavor = "multi_thread")]
async fn zstd_request_body_is_decoded() {
    let upstream = RawUpstream::start(Answer::Bytes(OK.to_vec()));
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/zstd", "body": "hello"}, "httpForward": {"host": "127.0.0.1", "port": upstream.port}})).await;
    let zstd = [0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0x29, 0, 0, b'h', b'e', b'l', b'l', b'o', 0xa3, 0x6d, 0x9f, 0x88];
    let r = send(server.port, "POST", "/zstd", &[("Content-Encoding", "zstd")], &zstd).await;
    assert_eq!(r.status, 200, "{}", r.head);
    let received = upstream.requests().pop().expect("forwarded");
    assert_eq!(body_of(&received), zstd, "the bytes as sent");
    let logs = common::send(server.port, "PUT", "/mockserver/retrieve?type=LOGS", "").await.body;
    assert!(!logs.contains("decoder fault") && !logs.contains("ended with its connection before it was complete"), "{logs}");
    server.server.shutdown().await;
}

/// cc8fb880a's relay half: a request through a CONNECT tunnel reaches MockServer in its coding, so it
/// is decoded, recorded and forwarded as a direct one; 8.0.0's relay decompressed it and dropped its coding.
#[tokio::test(flavor = "multi_thread")]
async fn tunnelled_encoded_request_is_forwarded_as_received() {
    let upstream = RawUpstream::start(Answer::Bytes(OK.to_vec()));
    let server = common::start(&[]).await;
    common::expect(server.port, &forward_to("/tunnelled", upstream.port)).await;
    let sent = gzip(b"tunnelled body", 9);
    let port = server.port;
    let request = sent.clone();
    let answer = tokio::task::spawn_blocking(move || {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        s.write_all(b"CONNECT mocked.example.test:80 HTTP/1.1\r\nHost: mocked.example.test:80\r\n\r\n").unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && s.read(&mut byte).unwrap() == 1 {
            head.push(byte[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
        let mut raw = format!("POST /tunnelled HTTP/1.1\r\nHost: mocked.example.test:80\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", request.len()).into_bytes();
        raw.extend_from_slice(&request);
        s.write_all(&raw).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    })
    .await
    .unwrap();
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    let received = upstream.requests().pop().unwrap();
    let head = &received[..received.windows(4).position(|w| w == b"\r\n\r\n").unwrap()];
    assert_eq!(header_of(head, "content-encoding").as_deref(), Some("gzip"));
    assert_eq!(body_of(&received), sent, "the bytes as sent");
    let recorded = put(server.port, "/mockserver/retrieve?type=REQUESTS", &json!({"path": "/tunnelled"})).await;
    assert_eq!(recorded[0]["body"], json!("tunnelled body"), "{recorded}");
    assert_eq!(recorded[0]["headers"]["content-encoding"], json!(["gzip"]), "{recorded}");
    server.server.shutdown().await;
}

// --- dc39a6a11: an upstream's response header and cookie names and values recorded literally ---------------------

/// `shouldMapHeaderNamedWithLeadingBangLiterally`, `shouldMapHeaderValueWithLeadingQuestionMarkLiterally` and the
/// cookie case: the relayed response and the recorded copies keep `!foo`, `?x` and `!s=?t` as they arrived, in the
/// object form (`{"not": false, "value": …}`) that reads back literally.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_response_markers_are_recorded_literally() {
    let answer = b"HTTP/1.1 200 OK\r\n!foo: bar\r\nx-q: ?x\r\nSet-Cookie: !s=?t\r\nContent-Length: 2\r\n\r\nok".to_vec();
    let upstream = RawUpstream::start(Answer::Bytes(answer));
    let server = common::start(&[]).await;
    common::expect(server.port, &forward_to("/markers", upstream.port)).await;
    let r = send(server.port, "GET", "/markers", &[], b"").await;
    assert_eq!(r.status, 200, "{}", r.head);
    assert!(r.head.contains("\r\n!foo: bar\r\n") && r.head.contains("\r\nx-q: ?x\r\n"), "relayed as received: {}", r.head);

    let literal = |v: &str| json!({"not": false, "value": v});
    let exchanges = put(server.port, "/mockserver/retrieve?type=REQUEST_RESPONSES", &json!({"path": "/markers"})).await;
    let recorded = put(server.port, "/mockserver/retrieve?type=RECORDED_EXPECTATIONS", &json!({"path": "/markers"})).await;
    for (what, response) in [("REQUEST_RESPONSES", &exchanges[0]["httpResponse"]), ("RECORDED_EXPECTATIONS", &recorded[0]["httpResponse"])] {
        let headers = response["headers"].as_array().unwrap_or_else(|| panic!("{what}: the list form, a name needs the object form: {response}"));
        let named = |name: &Value| headers.iter().find(|h| &h["name"] == name).map(|h| h["values"].clone());
        assert_eq!(named(&literal("!foo")), Some(json!(["bar"])), "{what}: {response}");
        assert_eq!(named(&json!("x-q")), Some(json!([literal("?x")])), "{what}: {response}");
        assert_eq!(response["cookies"], json!([{"name": literal("!s"), "value": literal("?t")}]), "{what}: {response}");
    }
    let java = common::send(server.port, "PUT", "/mockserver/retrieve?type=RECORDED_EXPECTATIONS&format=JAVA", &json!({"path": "/markers"}).to_string()).await.body;
    assert!(java.contains("new Header(string(\"!foo\", false), string(\"bar\"))") && java.contains("new Header(\"x-q\", string(\"?x\", false))"), "{java}");
    server.server.shutdown().await;
}

// --- 89d8a61c9: a silent upstream with maxSocketTimeout 0 does not hang the forward -------------------------------

/// `shouldReturnBadGatewayWhenMatchedForwardUpstreamIsSilentAndSocketTimeoutDisabled`: with no read timeout the wait
/// for the response is bounded by `maxFutureTimeout`, then answered 502 and logged as the `TimeoutException`.
#[tokio::test(flavor = "multi_thread")]
async fn silent_upstream_without_read_timeout_is_bounded_by_max_future_timeout() {
    let upstream = RawUpstream::start(Answer::Silent);
    let server = common::start(&[("maxSocketTimeoutInMillis", "0"), ("maxFutureTimeoutInMillis", "2000")]).await;
    common::expect(server.port, &forward_to("/silent", upstream.port)).await;
    let started = Instant::now();
    let r = send(server.port, "GET", "/silent", &[], b"").await;
    let took = started.elapsed();
    assert_eq!(r.status, 502, "{}", r.head);
    assert!(took >= Duration::from_millis(1900) && took < Duration::from_secs(15), "answered after {took:?}");
    assert_eq!(upstream.requests().len(), 1, "the request reached the upstream");
    let logs = common::logs(server.port).await;
    assert!(logs.contains("java.util.concurrent.TimeoutException"), "{logs}");
    server.server.shutdown().await;
}

// --- a78886b4d: upstream response headers read up to maxHeaderSize ------------------------------------------------

fn answer_with_headers(headers: &[(String, String)]) -> Vec<u8> {
    let mut out = b"HTTP/1.1 200 OK\r\n".to_vec();
    for (k, v) in headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(b"Content-Length: 4\r\n\r\nbody");
    out
}

/// `shouldForwardResponseHeadersLargerThanNettysDefault`: by default (`maxHeaderSize` `Integer.MAX_VALUE`) a 16 KiB
/// `Set-Cookie` and 300 headers are relayed with the body; Netty's decoder counts bytes, not headers.
#[tokio::test(flavor = "multi_thread")]
async fn large_upstream_response_headers_are_forwarded_by_default() {
    let mut headers = vec![("Set-Cookie".to_string(), format!("session={}", "a".repeat(16 * 1024)))];
    headers.extend((0..300).map(|i| (format!("x-h{i}"), i.to_string())));
    let upstream = RawUpstream::start(Answer::Bytes(answer_with_headers(&headers)));
    let server = common::start(&[]).await;
    common::expect(server.port, &forward_to("/large", upstream.port)).await;
    let r = send(server.port, "GET", "/large", &[], b"").await;
    assert_eq!((r.status, r.body.as_slice()), (200, b"body".as_slice()), "{}", &r.head[..200.min(r.head.len())]);
    assert!(r.head.contains(&"a".repeat(16 * 1024)) && r.head.contains("\r\nx-h299: 299\r\n"));
    server.server.shutdown().await;
}

/// `shouldAnswerBadGatewayWhenResponseHeadersExceedMaxHeaderSize`: headers over `maxHeaderSize` fail the forward with
/// a 502 whose body is the reason; a response within it is relayed.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_response_headers_over_max_header_size_answer_bad_gateway() {
    let over = RawUpstream::start(Answer::Bytes(answer_with_headers(&[("Set-Cookie".into(), format!("s={}", "a".repeat(5000)))])));
    let within = RawUpstream::start(Answer::Bytes(answer_with_headers(&[("Set-Cookie".into(), format!("s={}", "a".repeat(3000)))])));
    let server = common::start(&[("maxHeaderSize", "4096")]).await;
    common::expect(server.port, &forward_to("/over", over.port)).await;
    common::expect(server.port, &forward_to("/within", within.port)).await;
    let r = send(server.port, "GET", "/over", &[], b"").await;
    assert_eq!(r.status, 502, "{}", r.head);
    assert_eq!(String::from_utf8_lossy(&r.body), "upstream response headers are larger than maxHeaderSize (4096 bytes)");
    let r = send(server.port, "GET", "/within", &[], b"").await;
    assert_eq!((r.status, r.body.as_slice()), (200, b"body".as_slice()), "{}", r.head);
    let exchanges = put(server.port, "/mockserver/retrieve?type=REQUEST_RESPONSES", &json!({"path": "/over"})).await;
    assert_eq!(exchanges[0]["httpResponse"]["body"], "upstream response headers are larger than maxHeaderSize (4096 bytes)", "{exchanges}");
    server.server.shutdown().await;
}

// The rest of a78886b4d, read off the fixed snapshot image with `maxHeaderSize` 4096 against a raw
// upstream; the 8.0.0 oracle relays each (its limit is 8 KiB).

/// A chunked 200 with `headers`, the body `body` and `trailers` after its last chunk.
fn chunked_answer(headers: &[(&str, String)], trailers: &[(&str, String)]) -> Vec<u8> {
    let mut out = b"HTTP/1.1 200 OK\r\n".to_vec();
    for (k, v) in headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\nb\r\ndata: one\n\n\r\n0\r\n");
    for (k, v) in trailers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

const TOGETHER_OVER: &str = "upstream response headers and trailers are together larger than maxHeaderSize (4096 bytes)";

/// `ForwardHeaderLimit.Http1Response`: Netty's `HttpClientCodec` counts a response's trailers on top of its headers,
/// so trailers that fit alone fail beside large headers, with the reason naming both.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_trailers_count_on_top_of_headers_against_max_header_size() {
    let big = ("X-Big", "a".repeat(3000));
    let over = RawUpstream::start(Answer::Bytes(chunked_answer(std::slice::from_ref(&big), &[("X-T", "b".repeat(2000))])));
    let alone = RawUpstream::start(Answer::Bytes(chunked_answer(&[], &[("X-T", "b".repeat(5000))])));
    let within = RawUpstream::start(Answer::Bytes(chunked_answer(&[big], &[("X-T", "tt".into())])));
    let server = common::start(&[("maxHeaderSize", "4096")]).await;
    for (path, upstream) in [("/over", &over), ("/alone", &alone), ("/within", &within)] {
        common::expect(server.port, &forward_to(path, upstream.port)).await;
    }
    for path in ["/over", "/alone"] {
        let r = send(server.port, "GET", path, &[], b"").await;
        assert_eq!((r.status, String::from_utf8_lossy(&r.body).as_ref()), (502, TOGETHER_OVER), "{path}: {}", r.head);
    }
    let r = send(server.port, "GET", "/within", &[], b"").await;
    assert_eq!((r.status, r.body.as_slice()), (200, b"data: one\n\n".as_slice()), "{}", &r.head[..200.min(r.head.len())]);
    assert!(r.head.contains("X-T: tt\r\n"), "{}", &r.head[3000..]);
    let entries = failure_entries(server.port).await;
    assert_eq!(entries[0].3, [json!(format!("127.0.0.1/<unresolved>:{}", over.port)), json!(TOGETHER_OVER)], "{entries:?}");
    server.server.shutdown().await;
}

/// A streamed (SSE) response whose trailers are over the limit: the chunks already relayed stay, the refusal is
/// logged, and the stream ends aborted, recorded as truncated: the connection closes without the terminating chunk, as
/// on the snapshot (8.0.0 relays the stream whole).
#[tokio::test(flavor = "multi_thread")]
async fn streamed_response_whose_trailers_exceed_max_header_size_ends_truncated() {
    let headers = [("Content-Type", "text/event-stream".to_string())];
    let upstream = RawUpstream::start(Answer::Bytes(chunked_answer(&headers, &[("X-T", "b".repeat(5000))])));
    let server = common::start(&[("maxHeaderSize", "4096")]).await;
    common::expect(server.port, &forward_to("/sse", upstream.port)).await;
    let r = send(server.port, "GET", "/sse", &[], b"").await;
    assert_eq!((r.status, String::from_utf8_lossy(&r.body).as_ref()), (200, "b\r\ndata: one\n\n\r\n"), "{}", r.head);
    let entries = failure_entries(server.port).await;
    let shape: Vec<_> = entries.iter().map(|(l, t, f, _)| (l.as_str(), t.as_str(), f.as_str())).collect();
    assert_eq!(shape, [("WARN", "WARN", "failing forward to:{}because:{}")], "{entries:?}");
    assert_eq!(entries[0].3, [json!(format!("127.0.0.1/<unresolved>:{}", upstream.port)), json!(TOGETHER_OVER)]);
    let exchanges = put(server.port, "/mockserver/retrieve?type=REQUEST_RESPONSES", &json!({"path": "/sse"})).await;
    assert_eq!(exchanges[0]["httpResponse"]["headers"]["x-mockserver-stream-truncated"], json!(["true"]), "{exchanges}");
    server.server.shutdown().await;
}

/// c9fb69fd5 `StreamedResponseAbandonIntegrationTest` (adopted): a streamed body whose upstream closes
/// before its last chunk relays what came and ends without the terminating chunk, recorded truncated. 8.0.0 ends it
/// with the terminating chunk.
#[tokio::test(flavor = "multi_thread")]
async fn streamed_body_whose_upstream_closes_mid_stream_ends_without_the_terminating_chunk() {
    let answer = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nb\r\ndata: one\n\n\r\n".to_vec();
    let upstream = RawUpstream::start(Answer::Bytes(answer));
    let server = common::start(&[]).await;
    common::expect(server.port, &forward_to("/sse-cut", upstream.port)).await;
    let r = send(server.port, "GET", "/sse-cut", &[], b"").await;
    assert_eq!((r.status, String::from_utf8_lossy(&r.body).as_ref()), (200, "b\r\ndata: one\n\n\r\n"), "{}", r.head);
    let exchanges = put(server.port, "/mockserver/retrieve?type=REQUEST_RESPONSES", &json!({"path": "/sse-cut"})).await;
    assert_eq!(exchanges[0]["httpResponse"]["headers"]["x-mockserver-stream-truncated"], json!(["true"]), "{exchanges}");
    server.server.shutdown().await;
}

// --- c990e4a20: an HTTP/1.1 response the client cannot decode fails the forward -----------------------------------

/// An upstream that answers each request on a connection with the bytes its last path segment names, keeps the
/// connection open, and counts the connections it accepted (`ForwardUndecodableResponseIntegrationTest.RawUpstream`).
struct PathUpstream {
    port: u16,
    connections: Arc<std::sync::atomic::AtomicUsize>,
}

impl PathUpstream {
    fn start() -> PathUpstream {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = connections.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                std::thread::spawn(move || {
                    while let Some(request) = read_message(&mut stream) {
                        let line = String::from_utf8_lossy(&request).lines().next().unwrap_or_default().to_string();
                        let path = line.split(' ').nth(1).unwrap_or_default();
                        if stream.write_all(&undecodable_answer(path.rsplit('/').next().unwrap_or_default())).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        PathUpstream { port, connections }
    }

    fn connections(&self) -> usize {
        self.connections.load(std::sync::atomic::Ordering::SeqCst)
    }
}

fn undecodable_answer(name: &str) -> Vec<u8> {
    let text = match name {
        "invalid-header" => "HTTP/1.1 200 OK\r\nx-bad(header): value\r\ncontent-length: 2\r\n\r\nok".to_string(),
        "not-http" => "some_random_bytes\r\n".to_string(),
        "long-status" => format!("HTTP/1.1 200 {}\r\ncontent-length: 2\r\n\r\nok", "a".repeat(5000)),
        "invalid-chunk" => "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nzz\r\nok\r\n0\r\n\r\n".to_string(),
        "http10-te" => "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_string(),
        "length-and-chunked-gzip" | "length-and-chunked-zstd" => {
            let coding = &name["length-and-chunked-".len()..];
            format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: {coding}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        }
        "sse-length-and-chunked" => "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_string(),
        _ => "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_string(),
    };
    text.into_bytes()
}

const UNDECODABLE: &str = "response from the upstream could not be decoded: ";

/// Every `LOGS` entry about the failure: those saying `could not be decoded` or `exception` (8.0.0's `exception decoding
/// response` among them).
async fn decoding_entries(port: u16) -> Vec<String> {
    let logs = common::logs(port).await;
    logs.split("------------------------------------\n").filter(|e| e.contains("could not be decoded") || e.to_lowercase().contains("exception")).map(str::to_string).collect()
}

/// `assertFailedOnce`: a 502 whose body is the reason, one entry about it (the ERROR naming the request), and the next
/// forward to the same upstream answered at once on a new connection, the failed one being closed rather than pooled.
async fn assert_failed_once(name: &str, cause: &str) {
    let upstream = PathUpstream::start();
    // as upstream's test: at WARN, so the 502's own INFO entry is not among them
    let server = common::start(&[("logLevel", "WARN")]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/forward/.*"}, "httpForward": {"host": "127.0.0.1", "port": upstream.port}})).await;
    assert_eq!(send(server.port, "GET", "/forward/ok", &[], b"").await.status, 200);
    let before = upstream.connections();
    let r = send(server.port, "GET", &format!("/forward/{name}"), &[], b"").await;
    let body = String::from_utf8_lossy(&r.body).into_owned();
    assert_eq!(r.status, 502, "{name}: {}", r.head);
    assert!(body.starts_with(&format!("{UNDECODABLE}{cause}")), "{name}: {body}");
    let entries = decoding_entries(server.port).await;
    assert_eq!(entries.len(), 1, "{name}: {entries:?}");
    assert!(entries[0].contains("failed to forward request") && entries[0].contains(&body), "{name}: {entries:?}");
    let started = Instant::now();
    let next = send(server.port, "GET", "/forward/ok", &[], b"").await;
    assert_eq!((next.status, next.body.as_slice()), (200, b"ok".as_slice()), "{name}: {}", next.head);
    assert!(started.elapsed() < Duration::from_secs(10), "{name}: answered after {:?}", started.elapsed());
    assert_eq!(upstream.connections() - before, 1, "{name}: the connection the response arrived on was closed, not pooled");
    server.server.shutdown().await;
}

/// `shouldAnswer502ForAResponseWithAnInvalidHeaderAndForwardTheNextOnANewConnection`; 8.0.0 answered 200 with no body
/// and pooled the connection, the next forward on it waiting out the read timeout (`probe/fwd4-8.0.0.out`).
#[tokio::test(flavor = "multi_thread")]
async fn response_with_an_invalid_header_answers_bad_gateway_and_the_next_forward_a_new_connection() {
    assert_failed_once("invalid-header", "IllegalArgumentException: a header name can only contain \"token\" characters, but found invalid character 0x28 at index 5 of header 'x-bad(header)'.").await;
}

/// `shouldAnswer502ForAStatusLineThatIsNotHttp`, `…LongerThanTheDecoderReads`, `…ForAChunkSizeThatIsNotANumber`; 8.0.0
/// answered 999 `Unknown` for the first two and 200 with no body for the last (`probe/fwd-8.0.0.out`, `fwd4-8.0.0.out`).
#[tokio::test(flavor = "multi_thread")]
async fn status_line_not_http_or_too_long_and_chunk_size_not_a_number_answer_bad_gateway() {
    assert_failed_once("not-http", "IllegalArgumentException: invalid version format: SOME_RANDOM_BYTES").await;
    assert_failed_once("long-status", "TooLongHttpLineException: An HTTP line is larger than 4096 bytes.").await;
    assert_failed_once("invalid-chunk", "NumberFormatException: Invalid character in chunk size").await;
}

/// `HttpClientInitializer` puts an `HttpLineEndSplitGuard` around the client codec: a status line of
/// exactly 4096 bytes whose read ends between its CR and LF is forwarded, one byte longer fails as when read whole.
/// The oracle answers the same.
#[tokio::test(flavor = "multi_thread")]
async fn status_line_of_the_limit_split_between_cr_and_lf_is_forwarded() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            std::thread::spawn(move || {
                while let Some(request) = read_message(&mut stream) {
                    let line = String::from_utf8_lossy(&request).lines().next().unwrap_or_default().to_string();
                    let length: usize = line.split(' ').nth(1).and_then(|p| p.rsplit('/').next()?.parse().ok()).unwrap_or(4096);
                    let status = format!("HTTP/1.1 200 {}\r", "a".repeat(length - "HTTP/1.1 200 ".len()));
                    let _ = stream.write_all(status.as_bytes()).and_then(|_| stream.flush());
                    std::thread::sleep(Duration::from_millis(300));
                    if stream.write_all(b"\ncontent-length: 2\r\n\r\nok").is_err() {
                        return;
                    }
                }
            });
        }
    });
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/split/.*"}, "httpForward": {"host": "127.0.0.1", "port": port}})).await;
    let r = send(server.port, "GET", "/split/4096", &[], b"").await;
    assert_eq!((r.status, r.body.as_slice()), (200, b"ok".as_slice()), "{}", r.head);
    let r = send(server.port, "GET", "/split/4097", &[], b"").await;
    assert_eq!((r.status, String::from_utf8_lossy(&r.body).as_ref()), (502, "response from the upstream could not be decoded: TooLongHttpLineException: An HTTP line is larger than 4096 bytes."), "{}", r.head);
    server.server.shutdown().await;
}

/// A head `readHeaders` refuses (an HTTP/1.0 request with `Transfer-Encoding` too, whose message is the
/// request decoder's): 502 with the reason whatever the coding (zstd's decoder is never reached) and when it would
/// have streamed; 8.0.0 relayed the edited head with no body (scenario `forward_upstream_invalid_heads`).
#[tokio::test(flavor = "multi_thread")]
async fn heads_the_decoder_refuses_answer_bad_gateway_streamed_or_not() {
    let length_and_chunked = "ContentLengthNotAllowedException: Content-Length are not allowed in HTTP/1.1 messages that contains a Transfer-Encoding header.";
    for name in ["length-and-chunked-gzip", "length-and-chunked-zstd", "sse-length-and-chunked"] {
        assert_failed_once(name, length_and_chunked).await;
    }
    assert_failed_once("http10-te", "TransferEncodingNotAllowedException: The Transfer-Encoding header is only allowed in HTTP/1.1 or newer").await;
}

/// `shouldAnswer502WhenProxyingByHostHeader`: the unmatched proxy route answers the reason too, logged once as
/// `failed to proxy request`.
#[tokio::test(flavor = "multi_thread")]
async fn proxying_an_undecodable_response_by_host_header_answers_bad_gateway() {
    let upstream = PathUpstream::start();
    // as upstream's test: at WARN, so the 502's own INFO entry is not among them
    let server = common::start(&[("logLevel", "WARN")]).await;
    let port = server.port;
    let raw = format!("GET /proxied/invalid-header HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", upstream.port);
    let out = tokio::task::spawn_blocking(move || {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        s.write_all(raw.as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    })
    .await
    .unwrap();
    assert!(out.starts_with("HTTP/1.1 502 "), "{out}");
    assert!(out.split_once("\r\n\r\n").is_some_and(|(_, body)| body.starts_with(&format!("{UNDECODABLE}IllegalArgumentException: "))), "{out}");
    let entries = decoding_entries(server.port).await;
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert!(entries[0].contains("failed to proxy request"), "{entries:?}");
    server.server.shutdown().await;
}

/// An HTTP/2 upstream over TLS that sends `frames` (after its SETTINGS) on the client's stream 3.
async fn h2_frames(frames: &[(u8, u8, Vec<u8>)]) -> u16 {
    let mut out = h2_frame(4, 0, 0, &[]);
    for (kind, flags, payload) in frames {
        out.extend(h2_frame(*kind, *flags, 3, payload));
    }
    h2_upstream(out).await
}

fn hpack(fields: &[(&str, &str)]) -> Vec<u8> {
    loona_hpack::Encoder::new().encode(fields.iter().map(|(k, v)| (k.as_bytes(), v.as_bytes())))
}

/// `ForwardHeaderLimit.Http2Stream` / `Http2Connection` on a streamed HTTP/2 response (the snapshot's
/// answers): a trailer block over `maxHeaderSize` (or more than
/// a quarter over it, encoded) aborts the stream after the chunks already relayed, without the terminating chunk; the
/// refusal is logged and the exchange recorded truncated. 8.0.0 relays it whole and drops the trailers, as a stream
/// within the limit still does.
#[tokio::test(flavor = "multi_thread")]
async fn streamed_http2_response_whose_trailers_exceed_max_header_size_ends_aborted() {
    let server = common::start(&[("maxHeaderSize", "4096"), ("forwardProxyHttp2Upgrade", "true"), ("forwardProxyTLSX509CertificatesTrustManagerType", "ANY")]).await;
    let head = hpack(&[(":status", "200"), ("content-type", "text/event-stream")]);
    let (b4500, b6000) = ("b".repeat(4500), "b".repeat(6000));
    let cases = [
        ("/h2-within", hpack(&[("x-t", "tt")]), None),
        ("/h2-trailers", hpack(&[("x-t", &b4500)]), Some("upstream response trailers are larger than maxHeaderSize (4096 bytes)")),
        ("/h2-block", hpack(&[("x-t", &b6000)]), Some("an upstream response header block is more than a quarter larger than maxHeaderSize (4096 bytes)")),
    ];
    for (path, trailers, refusal) in cases {
        let port = h2_frames(&[(1, 0x4, head.clone()), (0, 0, b"data: one\n\n".to_vec()), (1, 0x4 | 0x1, trailers)]).await;
        let expectation = json!({"httpRequest": {"path": path}, "httpForward": {"host": "localhost", "port": port, "scheme": "HTTPS"}});
        common::expect(server.port, &expectation).await;
        let r = send(server.port, "GET", path, &[], b"").await;
        let expected = if refusal.is_some() { "b\r\ndata: one\n\n\r\n" } else { "b\r\ndata: one\n\n\r\n0\r\n\r\n" };
        assert_eq!((r.status, String::from_utf8_lossy(&r.body).as_ref()), (200, expected), "{path}: {}", r.head);
        let exchanges = put(server.port, "/mockserver/retrieve?type=REQUEST_RESPONSES", &json!({"path": path})).await;
        let truncated = exchanges[0]["httpResponse"]["headers"]["x-mockserver-stream-truncated"].clone();
        assert_eq!(truncated, if refusal.is_some() { json!(["true"]) } else { Value::Null }, "{path}: {exchanges}");
        if let Some(reason) = refusal {
            let logs = common::logs(server.port).await;
            assert!(logs.contains(&format!("failing forward to:\n\n  localhost/<unresolved>:{port}\n\n because:\n\n  {reason}\n")), "{path}: {logs}");
        }
    }
    server.server.shutdown().await;
}

/// 8.0.0's `HttpObjectAggregator` on an HTTP/2 stream at `maxResponseBodySize` (the snapshot the same): the stream codec's `x-http2-stream-id` is
/// in the reported head; a `content-length` over the limit fails on the head, otherwise the first DATA frame that would
/// take the aggregate (decoded, under a `content-encoding`) past the limit fails it. A streamed body is not limited by
/// the aggregator; a read of it that decodes past the limit aborts it (`StreamingBody`'s bound on decoded bytes waiting
/// for the client, as over HTTP/1.1; the same bound applies to HTTP/2 streams).
#[tokio::test(flavor = "multi_thread")]
async fn http2_response_over_max_response_body_size_answers_bad_gateway() {
    let server = common::start(&[("maxResponseBodySize", "500"), ("forwardProxyHttp2Upgrade", "true"), ("forwardProxyTLSX509CertificatesTrustManagerType", "ANY")]).await;
    let a1000 = vec![b'a'; 1000];
    let gzipped = gzip(&[b'a'; 2000], 6);
    let sse = gzip(&b"data: aaaaaaaaaa\n\n".repeat(200), 6);
    let too_large = "shaded_package.io.netty.handler.codec.http.TooLongHttpContentException: Response entity too large: ";
    let aggregated = "HttpObjectAggregator$AggregatedFullHttpResponse(decodeResult: success, version: HTTP/1.1, content: CompositeByteBuf(ridx: 0, widx: 0, cap: 0, components=0))";
    let cases = [
        ("/plain", vec![(1, 0x4, hpack(&[(":status", "200"), ("content-type", "text/plain")])), (0, 0, a1000.clone()), (0, 1, a1000.clone())], format!("{too_large}{aggregated}\nHTTP/1.1 200 OK\ncontent-type: text/plain\nx-http2-stream-id: 3")),
        (
            "/declared",
            vec![(1, 0x4, hpack(&[(":status", "200"), ("content-type", "text/plain"), ("content-length", "2000")])), (0, 0, a1000.clone()), (0, 1, a1000.clone())],
            format!("{too_large}DefaultHttpResponse(decodeResult: success, version: HTTP/1.1)\nHTTP/1.1 200 OK\ncontent-type: text/plain\ncontent-length: 2000\nx-http2-stream-id: 3"),
        ),
        ("/gzip", vec![(1, 0x4, hpack(&[(":status", "200"), ("content-type", "text/plain"), ("content-encoding", "gzip")])), (0, 1, gzipped)], format!("{too_large}{aggregated}\nHTTP/1.1 200 OK\ncontent-type: text/plain\nx-http2-stream-id: 3")),
    ];
    for (path, frames, error) in cases {
        let port = h2_frames(&frames).await;
        let expectation = json!({"httpRequest": {"path": path}, "httpForward": {"host": "localhost", "port": port, "scheme": "HTTPS"}});
        common::expect(server.port, &expectation).await;
        let r = send(server.port, "GET", path, &[], b"").await;
        assert_eq!((r.status, r.body.as_slice()), (502, b"".as_slice()), "{path}: {}", r.head);
        let entries = failure_entries(server.port).await;
        let failed = entries.iter().rev().find(|(_, t, _, _)| t == "NO_MATCH_RESPONSE").expect("a failed forward entry");
        assert_eq!(failed.3[1], json!(error), "{path}: {entries:?}");
    }
    let port = h2_frames(&[(1, 0x4, hpack(&[(":status", "200"), ("content-type", "text/event-stream"), ("content-encoding", "gzip")])), (0, 0, sse[..sse.len() / 2].to_vec()), (0, 1, sse[sse.len() / 2..].to_vec())]).await;
    let expectation = json!({"httpRequest": {"path": "/sse"}, "httpForward": {"host": "localhost", "port": port, "scheme": "HTTPS"}});
    common::expect(server.port, &expectation).await;
    let r = send(server.port, "GET", "/sse", &[], b"").await;
    let body = String::from_utf8_lossy(&r.body).into_owned();
    assert_eq!(r.status, 200, "{}", r.head);
    assert!(!body.ends_with("\r\n0\r\n\r\n"), "each half decodes past the bound, so the stream is aborted: {body}");
    // undecoded DATA frames of 360 bytes each, 3600 in all: past the aggregator's limit, relayed whole
    let events = b"data: aaaaaaaaaa\n\n".repeat(200);
    let mut frames = vec![(1, 0x4, hpack(&[(":status", "200"), ("content-type", "text/event-stream")]))];
    for (i, piece) in events.chunks(360).enumerate() {
        frames.push((0, if i == 9 { 1 } else { 0 }, piece.to_vec()));
    }
    let port = h2_frames(&frames).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/sse-plain"}, "httpForward": {"host": "localhost", "port": port, "scheme": "HTTPS"}})).await;
    let r = send(server.port, "GET", "/sse-plain", &[], b"").await;
    let body = String::from_utf8_lossy(&r.body).into_owned();
    assert_eq!(r.status, 200, "{}", r.head);
    assert!(body.ends_with("\r\n0\r\n\r\n") && body.matches("data: aaaaaaaaaa").count() == 200, "{body}");
    server.server.shutdown().await;
}

/// An HTTP/2 upstream over TLS that answers with these header blocks around a `body` DATA frame: `head` on stream 1,
/// then `trailers` ending the stream.
async fn h2_answer(head: &[(&str, String)], trailers: &[(&str, String)]) -> u16 {
    let block = |fields: &[(&str, String)]| loona_hpack::Encoder::new().encode(fields.iter().map(|(k, v)| (k.as_bytes(), v.as_bytes())));
    let frames = [
        h2_frame(4, 0, 0, &[]),
        h2_frame(1, 0x4, 1, &block(head)),
        h2_frame(0, 0, 1, b"body"),
        h2_frame(1, 0x4 | 0x1, 1, &block(trailers)),
    ];
    h2_upstream(frames.concat()).await
}

/// `ForwardHeaderLimit.Http2Stream` and `Http2Connection`: over HTTP/2 each header block is measured on its own; a
/// trailer block over the limit is named as trailers, and a block more than a quarter over it (encoded) is a
/// connection error named as such.
#[tokio::test(flavor = "multi_thread")]
async fn http2_trailers_and_oversized_header_blocks_over_max_header_size_answer_bad_gateway() {
    let server = common::start(&[("maxHeaderSize", "4096"), ("forwardProxyHttp2Upgrade", "true"), ("forwardProxyTLSX509CertificatesTrustManagerType", "ANY")]).await;
    let status = (":status", "200".to_string());
    let cases = [
        (h2_answer(&[status.clone(), ("x-big", "a".repeat(3000))], &[("x-t", "b".repeat(2000))]).await, None),
        (h2_answer(std::slice::from_ref(&status), &[("x-t", "b".repeat(4500))]).await, Some("upstream response trailers are larger than maxHeaderSize (4096 bytes)")),
        (h2_answer(&[status.clone(), ("x-big", "a".repeat(4500))], &[]).await, Some("upstream response headers are larger than maxHeaderSize (4096 bytes)")),
        (h2_answer(&[status.clone(), ("x-big", "a".repeat(6000))], &[]).await, Some("an upstream response header block is more than a quarter larger than maxHeaderSize (4096 bytes)")),
    ];
    for (i, (port, refusal)) in cases.into_iter().enumerate() {
        let path = format!("/h2-{i}");
        let expectation = json!({"httpRequest": {"path": path}, "httpForward": {"host": "localhost", "port": port, "scheme": "HTTPS"}});
        common::expect(server.port, &expectation).await;
        let r = send(server.port, "GET", &path, &[], b"").await;
        match refusal {
            None => assert_eq!((r.status, r.body.as_slice()), (200, b"body".as_slice()), "{path}: {}", &r.head[..200.min(r.head.len())]),
            Some(reason) => assert_eq!((r.status, String::from_utf8_lossy(&r.body).as_ref()), (502, reason), "{path}: {}", r.head),
        }
    }
    server.server.shutdown().await;
}

/// `HttpConnectProxyHandler`: an upstream HTTPS proxy's CONNECT reply is read up to `maxHeaderSize`; over it the
/// forward fails with the reason as the 502's body, and the failed future is logged as the `ProxyConnectException`
/// that carries the refusal.
#[tokio::test(flavor = "multi_thread")]
async fn upstream_proxy_connect_reply_over_max_header_size_answers_bad_gateway() {
    let reply = format!("HTTP/1.1 200 Connection established\r\nX-Big: {}\r\n\r\n", "a".repeat(5000));
    let proxy = RawUpstream::start(Answer::Bytes(reply.into_bytes()));
    let proxy_address = format!("127.0.0.1:{}", proxy.port);
    let server = common::start(&[("maxHeaderSize", "4096"), ("forwardHttpsProxy", &proxy_address)]).await;
    let target = RawUpstream::start(Answer::Close);
    common::expect(server.port, &forward_tls_to("/tunnelled", target.port)).await;
    let r = send(server.port, "GET", "/tunnelled", &[], b"").await;
    let reason = "the upstream proxy's CONNECT response headers are larger than maxHeaderSize (4096 bytes)";
    assert_eq!((r.status, String::from_utf8_lossy(&r.body).as_ref()), (502, reason), "{}", r.head);
    assert!(String::from_utf8_lossy(&proxy.requests()[0]).starts_with(&format!("CONNECT 127.0.0.1:{0} HTTP/1.1\r\nhost: 127.0.0.1:{0}\r\n", target.port)));
    let entries = failure_entries(server.port).await;
    let connect_failure = format!("http, none, /127.0.0.1:{} => 127.0.0.1/<unresolved>:{}, org.mockserver.httpclient.HeaderLimitExceededException: {reason}", proxy.port, target.port);
    let shape: Vec<_> = entries.iter().map(|(l, t, f, _)| (l.as_str(), t.as_str(), f.as_str())).collect();
    assert_eq!(shape, [("WARN", "WARN", "failing forward to:{}because:{}"), ("INFO", "WARN", connect_failure.as_str()), ("INFO", "NO_MATCH_RESPONSE", FAILED)], "{entries:?}");
    assert_eq!(entries[0].3, [json!(format!("127.0.0.1/<unresolved>:{}", target.port)), json!(reason)]);
    assert_eq!(entries[2].3[1], reason);
    server.server.shutdown().await;
}

/// `handleProxyPass`'s `returnedHeaderLimitFailure`: a proxy-pass forward refused for its headers answers the reason
/// (not `proxy pass forwarding failed for …`), after the client's WARN naming the mapping's target unresolved.
#[tokio::test(flavor = "multi_thread")]
async fn header_limit_refusal_of_a_proxy_pass_answers_the_reason() {
    let upstream = RawUpstream::start(Answer::Bytes(over_limit_answer()));
    let mapping = json!([{"pathPrefix": "/pp", "targetUri": format!("http://127.0.0.1:{}/t", upstream.port)}]).to_string();
    let server = common::start(&[("maxHeaderSize", "4096"), ("proxyPass", &mapping)]).await;
    let r = send(server.port, "GET", "/pp/over", &[], b"").await;
    assert_eq!((r.status, String::from_utf8_lossy(&r.body).as_ref()), (502, OVER_LIMIT), "{}", r.head);
    let entries = failure_entries(server.port).await;
    let shape: Vec<_> = entries.iter().map(|(l, t, f, _)| (l.as_str(), t.as_str(), f.as_str())).collect();
    assert_eq!(shape, [("WARN", "WARN", "failing forward to:{}because:{}"), ("INFO", "NO_MATCH_RESPONSE", FAILED)], "{entries:?}");
    assert_eq!(entries[0].3, [json!(format!("127.0.0.1/<unresolved>:{}", upstream.port)), json!(OVER_LIMIT)]);
    assert_eq!(entries[1].3[1], OVER_LIMIT);
    server.server.shutdown().await;
}

/// 8.0.0's own behaviour, here because no scenario can pin it: a streamed gzip body that fails to
/// decode after its first chunk relays the decoded part, ends, and is recorded truncated. Observed on the 8.0.0 oracle
/// against an upstream that closes after the bad chunk; against one that
/// keeps the connection open the oracle's record depends on its read timeout.
#[tokio::test(flavor = "multi_thread")]
async fn streamed_body_that_fails_to_decode_mid_stream_is_recorded_truncated() {
    let mut deflater = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    deflater.write_all(b"data: one\n\n").unwrap();
    deflater.flush().unwrap();
    let good = deflater.get_ref().clone();
    let mut answer = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    answer.extend_from_slice(format!("{:x}\r\n", good.len()).as_bytes());
    answer.extend_from_slice(&good);
    answer.extend_from_slice(b"\r\n4\r\n\xff\xff\xff\xff\r\n0\r\n\r\n");
    let upstream = RawUpstream::start(Answer::Bytes(answer));
    let server = common::start(&[]).await;
    common::expect(server.port, &forward_to("/sse-bad", upstream.port)).await;
    let r = send(server.port, "GET", "/sse-bad", &[], b"").await;
    // without the terminating chunk: the decoding failure aborts the stream (upstream c9fb69fd5, adopted)
    assert_eq!((r.status, String::from_utf8_lossy(&r.body).as_ref()), (200, "b\r\ndata: one\n\n\r\n"), "{}", r.head);
    let exchanges = put(server.port, "/mockserver/retrieve?type=REQUEST_RESPONSES", &json!({"path": "/sse-bad"})).await;
    assert_eq!(exchanges[0]["httpResponse"]["headers"]["x-mockserver-stream-truncated"], json!(["true"]), "{exchanges}");
    assert_eq!(exchanges[0]["httpResponse"]["body"], "data: one\n\n", "{exchanges}");
    server.server.shutdown().await;
}

/// `handleProxyPassFailure` on master (b765b8271; the 7a8b8c424 snapshot still answered an
/// empty 502): a failure upstream names is answered as the forward route answers it, through
/// `returnedUpstreamFailureReason`: one ERROR `failed to proxy pass request{}to{}because:{}` naming the mapping's
/// target and the reason, then `returnBadGateway`'s entry, the reason the 502's body. A refused connection is still
/// the cause's `toString` after `proxy pass forwarding failed for <target>: ` (scenario `proxy_pass_failure_log`).
#[tokio::test(flavor = "multi_thread")]
async fn named_tls_failure_of_a_proxy_pass_is_answered_with_its_reason() {
    let upstream = RawUpstream::start(Answer::Immediately(plain_http_answer()));
    let target = format!("https://127.0.0.1:{}/t", upstream.port);
    let mapping = json!([{"pathPrefix": "/pp", "targetUri": target}]).to_string();
    let server = common::start(&[("proxyPass", &mapping)]).await;
    let r = send(server.port, "GET", "/pp/tls", &[], b"").await;
    assert_eq!((r.status, String::from_utf8_lossy(&r.body).as_ref()), (502, NOT_TLS), "{}", r.head);
    let entries = failure_entries(server.port).await;
    let shape: Vec<_> = entries.iter().map(|(l, t, f, _)| (l.as_str(), t.as_str(), f.as_str())).collect();
    assert_eq!(shape, [("ERROR", "ERROR", "failed to proxy pass request{}to{}because:{}"), ("INFO", "NO_MATCH_RESPONSE", FAILED)], "{entries:?}");
    assert_eq!((&entries[0].3[1], &entries[0].3[2], &entries[1].3[1]), (&json!(target), &json!(NOT_TLS), &json!(NOT_TLS)), "{entries:?}");
    server.server.shutdown().await;
}

/// `ForwardUndecodableResponseIntegrationTest.shouldAnswer502AsTheForwardRouteDoesForAProxyPassMapping`: an undecodable response to a proxy-pass forward is answered `502` with the reason and logged once, by the
/// ERROR about the request (the test runs at `logLevel` WARN, so `returnBadGateway`'s INFO entry is not kept).
#[tokio::test(flavor = "multi_thread")]
async fn undecodable_response_to_a_proxy_pass_is_answered_with_its_reason() {
    let upstream = RawUpstream::start(Answer::Bytes(b"HTTP/1.1 200 OK\r\nx-bad(header): value\r\ncontent-length: 2\r\n\r\nok".to_vec()));
    let mapping = json!([{"pathPrefix": "/pass", "targetUri": format!("http://127.0.0.1:{}", upstream.port)}]).to_string();
    let server = common::start(&[("proxyPass", &mapping), ("logLevel", "WARN")]).await;
    let r = send(server.port, "GET", "/pass/invalid-header", &[], b"").await;
    let body = String::from_utf8_lossy(&r.body).into_owned();
    assert_eq!(r.status, 502, "{}", r.head);
    assert!(body.starts_with("response from the upstream could not be decoded: IllegalArgumentException: "), "{body}");
    // `retrieveLogMessagesArray`: the plain-text log split at its separator
    let logs = common::logs(server.port).await;
    let decoding: Vec<String> = logs
        .split("------------------------------------\n")
        .filter(|m| m.contains("could not be decoded") || m.to_lowercase().contains("exception"))
        .map(str::to_string)
        .collect();
    assert_eq!(decoding.len(), 1, "{decoding:?}");
    assert!(decoding[0].contains("failed to proxy pass request") && decoding[0].contains(&body), "{decoding:?}");
    server.server.shutdown().await;
}

// --- 7a8b8c424: the TLS cause of a failed forward named in the 502 ------------------------------------------------

fn forward_tls_to(path: &str, upstream: u16) -> Value {
    json!({"httpRequest": {"path": path}, "httpForward": {"host": "127.0.0.1", "port": upstream, "scheme": "HTTPS"}})
}

/// `shouldNameNonTlsUpstream` (`NettyHttpClientTlsFailureTest`) with `HttpActionHandlerForwardFailureTest`'s body: an
/// upstream that answers a ClientHello in plain HTTP is a `NotSslRecordException`, bounded to its byte count.
#[tokio::test(flavor = "multi_thread")]
async fn plain_http_upstream_behind_https_forward_is_named_in_the_bad_gateway() {
    let plain = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
    assert_eq!(plain.len(), 66);
    let upstream = RawUpstream::start(Answer::Immediately(plain));
    let server = common::start(&[]).await;
    common::expect(server.port, &forward_tls_to("/plain", upstream.port)).await;
    let r = send(server.port, "GET", "/plain", &[], b"").await;
    assert_eq!(r.status, 502, "{}", r.head);
    assert_eq!(String::from_utf8_lossy(&r.body), "TLS with the upstream failed: NotSslRecordException: not an SSL/TLS record: 66 bytes");
    assert!(!r.head.to_ascii_lowercase().contains("content-type"), "{}", r.head);
    server.server.shutdown().await;
}

/// A handshake the upstream ends by resetting the connection stays a connection failure, an empty 502 (8.0.0 and
/// after: an `IOException` under the handshake is "left to the teardown", `ExceptionHandling.tlsFailure`).
#[tokio::test(flavor = "multi_thread")]
async fn upstream_resetting_during_handshake_is_a_connection_failure() {
    let upstream = RawUpstream::start(Answer::Reset);
    let server = common::start(&[]).await;
    common::expect(server.port, &forward_tls_to("/closed", upstream.port)).await;
    let r = send(server.port, "GET", "/closed", &[], b"").await;
    assert_eq!((r.status, r.body.as_slice()), (502, b"".as_slice()), "{}", r.head);
    let logs = common::logs(server.port).await;
    assert!(logs.contains("failed to connect to remote socket while forwarding request") && !logs.contains("TLS handshake exception"), "{logs}");
    server.server.shutdown().await;
}

/// An upstream that reads the ClientHello and closes the connection is named in the 502
/// (`ExceptionHandling.upstreamHandshakeFailure`), as the oracle answers a forward to a server whose TLS context
/// cannot be built (`tls_data_plane_chain_unparseable_*`).
#[tokio::test(flavor = "multi_thread")]
async fn upstream_closing_after_the_client_hello_is_named_in_the_bad_gateway() {
    let upstream = RawUpstream::start(Answer::ReadThenClose);
    let server = common::start(&[]).await;
    common::expect(server.port, &forward_tls_to("/closed", upstream.port)).await;
    let r = send(server.port, "GET", "/closed", &[], b"").await;
    assert_eq!(r.status, 502, "{}", r.head);
    assert_eq!(String::from_utf8_lossy(&r.body), "TLS with the upstream failed: SSLHandshakeException: upstream closed the connection during the TLS handshake");
    server.server.shutdown().await;
}

// The remaining reasons of 7a8b8c424, each read off the fixed snapshot image against an upstream on a
// Docker network; the 8.0.0 oracle answers each with an empty 502.

fn tls_file(name: &str) -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/tls").join(name).display().to_string()
}

/// A forward over HTTPS to `host:port` on a server with `properties`: the 502's body, and the shape of the entries
/// it logged (the ERROR about the request naming the reason, then `returnBadGateway`'s).
async fn named_failure(properties: &[(&str, &str)], host: &str, port: u16) -> String {
    let server = common::start(properties).await;
    let expectation = json!({"httpRequest": {"path": "/named"}, "httpForward": {"host": host, "port": port, "scheme": "HTTPS"}});
    common::expect(server.port, &expectation).await;
    let r = send(server.port, "GET", "/named", &[], b"").await;
    assert_eq!(r.status, 502, "{}", r.head);
    let body = String::from_utf8_lossy(&r.body).into_owned();
    let entries = failure_entries(server.port).await;
    let shape: Vec<_> = entries.iter().map(|(l, t, f, _)| (l.as_str(), t.as_str(), f.as_str())).collect();
    assert_eq!(shape, [("ERROR", "ERROR", "failed to forward request{}for action{}because:{}"), ("INFO", "NO_MATCH_RESPONSE", FAILED)], "{entries:?}");
    assert_eq!((entries[0].3[2].as_str(), entries[1].3[1].as_str()), (Some(body.as_str()), Some(body.as_str())), "{entries:?}");
    server.server.shutdown().await;
    body
}

/// A MockServer serving `tests/files/tls/foreign-leaf-cert.pem` (self-signed, for `foreign.example` and `localhost`).
async fn foreign_target() -> common::Running {
    let (cert, key) = (tls_file("foreign-leaf-cert.pem"), tls_file("foreign-leaf-key.pem"));
    common::start(&[("x509CertificatePath", &cert), ("privateKeyPath", &key), ("certificateAuthorityCertificate", &cert)]).await
}

/// `shouldNameUntrustedCertificate`: the JDK's PKIX failure, whose root cause it already quotes.
#[tokio::test(flavor = "multi_thread")]
async fn untrusted_upstream_certificate_is_named_in_the_bad_gateway() {
    let target = foreign_target().await;
    let body = named_failure(&[("forwardProxyTLSX509CertificatesTrustManagerType", "JVM")], "localhost", target.port).await;
    assert_eq!(
        body,
        "TLS with the upstream failed: SSLHandshakeException: (certificate_unknown) PKIX path building failed: \
         sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target"
    );
    target.server.shutdown().await;
}

/// `shouldNameCertificateForAnotherHost`: a trusted certificate that names no such IP address (the snapshot, for a
/// host name: `No subject alternative DNS name matching upstream312 found.`).
#[tokio::test(flavor = "multi_thread")]
async fn certificate_for_another_host_is_named_in_the_bad_gateway() {
    let target = foreign_target().await;
    let trusted = tls_file("foreign-leaf-cert.pem");
    let custom = [("forwardProxyTLSX509CertificatesTrustManagerType", "CUSTOM"), ("forwardProxyTLSCustomTrustX509Certificates", trusted.as_str())];
    let body = named_failure(&custom, "127.0.0.1", target.port).await;
    assert_eq!(body, "TLS with the upstream failed: SSLHandshakeException: (certificate_unknown) No subject alternative names matching IP address 127.0.0.1 found");
    target.server.shutdown().await;
}

/// A TLS upstream serving `cert` (with `key`, both under `tests/files/tls`) that answers any request `200 ok`.
async fn tls_upstream(cert: &str, key: &str) -> u16 {
    use rustls_pki_types::pem::PemObject;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let chain = rustls_pki_types::CertificateDer::pem_file_iter(tls_file(cert)).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(tls_file(key)).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(chain, key).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let _ = tls.read(&mut [0u8; 65536]).await;
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok").await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

/// `CUSTOM` trust of MockServer's own certificate authority, which issued the `fixed-*` certificates.
fn custom_trust() -> [(&'static str, String); 2] {
    let ca = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tls/CertificateAuthorityCertificate.pem").display().to_string();
    [("forwardProxyTLSX509CertificatesTrustManagerType", "CUSTOM".into()), ("forwardProxyTLSCustomTrustX509Certificates", ca)]
}

/// Certificates the JDK's PKIX validation refuses after building the path, as the fixed snapshot names
/// them (8.0.0 answers each with an empty 502): the message,
/// then the root cause it does not quote, its date as `java.util.Date` prints it in GMT. A valid one is relayed.
#[tokio::test(flavor = "multi_thread")]
async fn expired_not_yet_valid_and_badly_signed_upstream_certificates_are_named_in_the_bad_gateway() {
    let trust = custom_trust();
    let custom: Vec<(&str, &str)> = trust.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let valid = tls_upstream("fixed-ok-cert.pem", "fixed-ok-key.pem").await;
    let server = common::start(&custom).await;
    let expectation = json!({"httpRequest": {"path": "/valid"}, "httpForward": {"host": "localhost", "port": valid, "scheme": "HTTPS"}});
    common::expect(server.port, &expectation).await;
    let r = send(server.port, "GET", "/valid", &[], b"").await;
    assert_eq!((r.status, r.body.as_slice()), (200, b"ok".as_slice()), "{}", r.head);
    server.server.shutdown().await;
    let validation = "PKIX path validation failed: java.security.cert.CertPathValidatorException";
    let cases = [
        ("fixed-expired-cert.pem", format!("(certificate_expired) {validation}: validity check failed; caused by CertificateExpiredException: NotAfter: Thu Oct 01 15:26:28 GMT 2026")),
        ("fixed-future-cert.pem", format!("(bad_certificate) {validation}: validity check failed; caused by CertificateNotYetValidException: NotBefore: Wed Nov 21 15:26:28 GMT 2108")),
        ("fixed-badsig-cert.pem", format!("(bad_certificate) {validation}: signature check failed; caused by SignatureException: Signature does not match.")),
    ];
    for (cert, reason) in cases {
        let key = if cert == "fixed-badsig-cert.pem" { "fixed-ok-key.pem".to_string() } else { cert.replace("-cert", "-key") };
        let upstream = tls_upstream(cert, &key).await;
        let body = named_failure(&custom, "localhost", upstream).await;
        assert_eq!(body, format!("TLS with the upstream failed: SSLHandshakeException: {reason}"), "{cert}");
    }
}

/// The binary proxy (the oracle's `BinaryRelay`, one upstream connection per client
/// connection): a TLS connection's bytes go to the remote over TLS, and a certificate the JDK refuses fails the relay's
/// handshake, whose future's cause, the JDK's `SSLHandshakeException`, `upstreamTlsFailed` names (no root cause appended).
#[tokio::test(flavor = "multi_thread")]
async fn binary_proxy_names_the_jdk_handshake_exception_of_a_refused_upstream_certificate() {
    let upstream = tls_upstream("fixed-expired-cert.pem", "fixed-expired-key.pem").await;
    let mut config = custom_trust().iter().fold(mock_server::Config::for_tests(), |c, (k, v)| c.with_property(k, v));
    config.port_forward = Some(("localhost".into(), upstream));
    crate::scratch_cwd::enter();
    let server = mock_server::Server::start(config).await.expect("server starts");
    let server = common::Running { port: server.ports()[0], server };
    let _ = send_raw(server.port, "\u{0}\u{1}\u{2}\u{3}binary339".to_string(), true).await;
    let jdk = "(certificate_expired) PKIX path validation failed: java.security.cert.CertPathValidatorException: validity check failed";
    let logs = common::logs(server.port).await;
    assert!(logs.contains("unable to start TLS with upstream:\n\n  localhost/127.0.0.1:"), "{logs}");
    assert!(logs.contains(&format!(" closing both:\n\n  {jdk}\n")), "{logs}");
    server.server.shutdown().await;
}

/// `shouldNameHandshakeTimeout` with 4180cbdb4's `NettyHttpClientTlsHandshakeTimeoutTest`: an upstream that never
/// answers the ClientHello fails the handshake after `socketConnectionTimeoutInMillis` (the snapshot
/// answers `… after 1500ms` at 1.5 s), not after Netty's
/// fixed 10 s, which is what 8.0.0 waits whatever the setting (`handshake-oracle.out`).
#[tokio::test(flavor = "multi_thread")]
async fn handshake_timeout_is_bounded_by_the_connection_timeout_and_named_in_the_bad_gateway() {
    let upstream = RawUpstream::start(Answer::Hold);
    let started = Instant::now();
    let body = named_failure(&[("socketConnectionTimeoutInMillis", "1500")], "127.0.0.1", upstream.port).await;
    assert_eq!(body, "TLS with the upstream failed: SslHandshakeTimeoutException: handshake timed out after 1500ms");
    assert!(started.elapsed() >= Duration::from_millis(1500) && started.elapsed() < Duration::from_secs(6), "{:?}", started.elapsed());
}

/// An upstream that agrees to `h2` and, once the request's HEADERS frame has come, sends `frames`; it then reads until
/// the client closes. Answering on the first read alone raced the client: its preface and SETTINGS come
/// in one write and the request's HEADERS in a later one, and frames for a stream the client has not opened yet are
/// dropped as another request's, so under load the forward waited for an answer that had already gone by and failed
/// with a 502 when the upstream closed.
async fn h2_upstream(frames: Vec<u8>) -> u16 {
    use rustls_pki_types::pem::PemObject;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let chain = rustls_pki_types::CertificateDer::pem_file_iter(tls_file("foreign-leaf-cert.pem")).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(tls_file("foreign-leaf-key.pem")).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(chain, key).unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, frames) = (acceptor.clone(), frames.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let mut received = Vec::new();
                let mut chunk = [0u8; 65536];
                while !has_headers_frame(&received) {
                    match tokio::time::timeout(Duration::from_secs(30), tls.read(&mut chunk)).await {
                        Ok(Ok(n)) if n > 0 => received.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
                let _ = tls.write_all(&frames).await;
                let _ = tls.flush().await;
                while matches!(tokio::time::timeout(Duration::from_secs(30), tls.read(&mut chunk)).await, Ok(Ok(n)) if n > 0) {}
            });
        }
    });
    port
}

/// Whether the bytes a client sent (the connection preface, then frames) hold a HEADERS frame yet.
fn has_headers_frame(received: &[u8]) -> bool {
    let mut at = 24; // "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    while received.len() >= at + 9 {
        if received[at + 3] == 1 {
            return true;
        }
        at += 9 + (usize::from(received[at]) << 16 | usize::from(received[at + 1]) << 8 | usize::from(received[at + 2]));
    }
    false
}

fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut frame = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    frame.extend_from_slice(&[kind, flags]);
    frame.extend_from_slice(&stream.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// `Http2ForwardConnectionExceptionHandler` (7a8b8c424): an HTTP/2 connection error the client raises on what the
/// upstream sent, named with its error code and Netty's message.
#[tokio::test(flavor = "multi_thread")]
async fn http2_connection_error_is_named_in_the_bad_gateway() {
    let upgrade = [("forwardProxyHttp2Upgrade", "true")];
    let settings = h2_upstream(h2_frame(4, 0, 0, &[0; 5])).await;
    assert_eq!(named_failure(&upgrade, "127.0.0.1", settings).await, "HTTP/2 error from the upstream: FRAME_SIZE_ERROR: Frame length 5 invalid.");
    let oversize = h2_upstream([h2_frame(4, 0, 0, &[]), h2_frame(0, 0, 1, &[b'x'; 20_000])].concat()).await;
    assert_eq!(named_failure(&upgrade, "127.0.0.1", oversize).await, "HTTP/2 error from the upstream: FRAME_SIZE_ERROR: Frame length: 20000 exceeds maximum: 16384");
}

/// `ClientConfigurationException` (7a8b8c424): a forward-proxy key and chain that are not PEM fail the forward before
/// the upstream is reached, naming only the top-level cause.
#[tokio::test(flavor = "multi_thread")]
async fn forward_proxy_key_that_is_not_pem_is_named_in_the_bad_gateway() {
    let upstream = RawUpstream::start(Answer::Close);
    let dir = std::env::temp_dir().join(format!("forward-pem-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad.pem");
    std::fs::write(&bad, "not a pem\n").unwrap();
    let bad = bad.display().to_string();
    let properties = [("forwardProxyPrivateKey", bad.as_str()), ("forwardProxyCertificateChain", bad.as_str())];
    let body = named_failure(&properties, "127.0.0.1", upstream.port).await;
    assert_eq!(body, "connection to the upstream could not be set up: RuntimeException: Exception creating SSL context for client");
    let _ = std::fs::remove_dir_all(&dir);
}

// --- the log entries of a78886b4d and 7a8b8c424 ----------------------------------------------------
// Observed on the fixed snapshot image (mockserver 8.0.1-SNAPSHOT, `retrieve?type=LOGS&format=LOG_ENTRIES`): a
// header-limit refusal is the client's WARN `failing forward to:{}because:{}` about no request (the remote socket
// unresolved for an expectation's forward, resolved for an unmatched proxy), then, for an expectation's forward only,
// the scheduler's entry for the failed future, then `returnBadGateway`'s entry with the reason as its error; a named
// TLS failure is one ERROR about the request (`failed to forward request{}for action{}because:{}`, unmatched `failed to
// proxy request{}to remote address{}because:{}`), then `returnBadGateway`'s. No other entry names the exception.

const OVER_LIMIT: &str = "upstream response headers are larger than maxHeaderSize (4096 bytes)";
const NOT_TLS: &str = "TLS with the upstream failed: NotSslRecordException: not an SSL/TLS record: 66 bytes";
const FAILED: &str = "failed to forward request:{}error:{}returning response:{}";

/// The entries a failed forward adds: `(logLevel, type, messageFormat, arguments)` of every WARN, ERROR, EXCEPTION
/// and NO_MATCH_RESPONSE entry from the request's arrival on, in order.
async fn failure_entries(port: u16) -> Vec<(String, String, String, Vec<Value>)> {
    let body = common::send(port, "PUT", "/mockserver/retrieve?type=LOGS&format=LOG_ENTRIES", "").await.body;
    let entries: Vec<Value> = serde_json::from_str(&body).unwrap();
    entries
        .into_iter()
        .skip_while(|e| e["type"] != "RECEIVED_REQUEST")
        .filter(|e| ["WARN", "ERROR", "EXCEPTION", "NO_MATCH_RESPONSE"].contains(&e["type"].as_str().unwrap_or_default()))
        .map(|e| {
            let text = |k: &str| e[k].as_str().unwrap_or_default().to_string();
            (text("logLevel"), text("type"), text("messageFormat"), e["arguments"].as_array().cloned().unwrap_or_default())
        })
        .collect()
}

fn plain_http_answer() -> Vec<u8> {
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
}

fn over_limit_answer() -> Vec<u8> {
    answer_with_headers(&[("Set-Cookie".into(), format!("s={}", "a".repeat(5000)))])
}

/// `raw` on its own connection, over TLS when `tls`; the status and body of the answer.
async fn send_raw(port: u16, raw: String, tls: bool) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut out = Vec::new();
    if tls {
        let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let mut s = tokio_rustls::TlsConnector::from(common::tls_client_config(b"http/1.1")).connect(name, tcp).await.unwrap();
        s.write_all(raw.as_bytes()).await.unwrap();
        let _ = s.read_to_end(&mut out).await;
    } else {
        let mut s = tcp;
        s.write_all(raw.as_bytes()).await.unwrap();
        let _ = s.read_to_end(&mut out).await;
    }
    let text = String::from_utf8_lossy(&out).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0), body.to_string())
}

/// `ForwardHeaderLimit.refuse` then `returnedHeaderLimitFailure` (a78886b4d), for an expectation's forward.
#[tokio::test(flavor = "multi_thread")]
async fn header_limit_refusal_of_a_forward_is_logged_as_upstream_logs_it() {
    let upstream = RawUpstream::start(Answer::Bytes(over_limit_answer()));
    let server = common::start(&[("maxHeaderSize", "4096")]).await;
    common::expect(server.port, &forward_to("/over", upstream.port)).await;
    assert_eq!(send(server.port, "GET", "/over", &[], b"").await.status, 502);
    let entries = failure_entries(server.port).await;
    let shape: Vec<_> = entries.iter().map(|(l, t, f, _)| (l.as_str(), t.as_str(), f.as_str())).collect();
    assert_eq!(shape, [("WARN", "WARN", "failing forward to:{}because:{}"), ("INFO", "WARN", OVER_LIMIT), ("INFO", "NO_MATCH_RESPONSE", FAILED)], "{entries:?}");
    assert_eq!(entries[0].3, [json!(format!("127.0.0.1/<unresolved>:{}", upstream.port)), json!(OVER_LIMIT)]);
    assert_eq!(entries[2].3[1], OVER_LIMIT);
    let logs = common::logs(server.port).await;
    assert!(logs.contains(&format!("failing forward to:\n\n  127.0.0.1/<unresolved>:{}\n\n because:\n\n  {OVER_LIMIT}\n", upstream.port)), "{logs}");
    assert!(!logs.contains("HeaderLimitExceededException"), "{logs}");
    server.server.shutdown().await;
}

/// `ForwardHeaderLimit.refuse` then `handleUnmatchedForwardFailure`'s `returnedHeaderLimitFailure` (a78886b4d), for
/// an unmatched request proxied by its `Host`: no scheduler entry, and the remote socket resolved.
#[tokio::test(flavor = "multi_thread")]
async fn header_limit_refusal_of_an_unmatched_proxy_is_logged_as_upstream_logs_it() {
    let upstream = RawUpstream::start(Answer::Bytes(over_limit_answer()));
    let server = common::start(&[("maxHeaderSize", "4096")]).await;
    let raw = format!("GET http://127.0.0.1:{0}/uover HTTP/1.1\r\nHost: 127.0.0.1:{0}\r\nConnection: close\r\n\r\n", upstream.port);
    assert_eq!(send_raw(server.port, raw, false).await, (502, OVER_LIMIT.to_string()));
    let entries = failure_entries(server.port).await;
    let shape: Vec<_> = entries.iter().map(|(l, t, f, _)| (l.as_str(), t.as_str(), f.as_str())).collect();
    assert_eq!(shape, [("WARN", "WARN", "failing forward to:{}because:{}"), ("INFO", "NO_MATCH_RESPONSE", FAILED)], "{entries:?}");
    assert_eq!(entries[1].3[1], OVER_LIMIT);
    let logs = common::logs(server.port).await;
    assert!(logs.contains(&format!("failing forward to:\n\n  /127.0.0.1:{}\n\n because:\n\n  {OVER_LIMIT}\n", upstream.port)), "{logs}");
    server.server.shutdown().await;
}

/// `handleExceptionDuringForwardingRequest`'s `upstreamFailureReason` branch (7a8b8c424): one ERROR about the request
/// naming the action and the reason, no scheduler entry, then the 502's entry with the reason.
#[tokio::test(flavor = "multi_thread")]
async fn named_tls_failure_of_a_forward_is_logged_as_upstream_logs_it() {
    let upstream = RawUpstream::start(Answer::Immediately(plain_http_answer()));
    let server = common::start(&[]).await;
    common::expect(server.port, &forward_tls_to("/plain", upstream.port)).await;
    assert_eq!(send(server.port, "GET", "/plain", &[], b"").await.status, 502);
    let entries = failure_entries(server.port).await;
    let shape: Vec<_> = entries.iter().map(|(l, t, f, _)| (l.as_str(), t.as_str(), f.as_str())).collect();
    assert_eq!(shape, [("ERROR", "ERROR", "failed to forward request{}for action{}because:{}"), ("INFO", "NO_MATCH_RESPONSE", FAILED)], "{entries:?}");
    assert_eq!(entries[0].3[2], NOT_TLS);
    assert_eq!(entries[1].3[1], NOT_TLS);
    let logs = common::logs(server.port).await;
    let action = format!("for action\n\n  {{\n    \"host\" : \"127.0.0.1\",\n    \"port\" : {},\n    \"scheme\" : \"HTTPS\"\n  }}\n\n because:\n\n  {NOT_TLS}\n", upstream.port);
    assert!(logs.contains(&action), "{logs}");
    server.server.shutdown().await;
}

/// `handleUnmatchedForwardFailure`'s `upstreamFailureReason` branch (7a8b8c424), for a request over TLS proxied by its
/// `Host`: the remote address is null (no remote socket), an empty argument.
#[tokio::test(flavor = "multi_thread")]
async fn named_tls_failure_of_an_unmatched_proxy_is_logged_as_upstream_logs_it() {
    let upstream = RawUpstream::start(Answer::Immediately(plain_http_answer()));
    let server = common::start(&[]).await;
    let raw = format!("GET /uplain HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", upstream.port);
    assert_eq!(send_raw(server.port, raw, true).await, (502, NOT_TLS.to_string()));
    let entries = failure_entries(server.port).await;
    let shape: Vec<_> = entries.iter().map(|(l, t, f, _)| (l.as_str(), t.as_str(), f.as_str())).collect();
    assert_eq!(shape, [("ERROR", "ERROR", "failed to proxy request{}to remote address{}because:{}"), ("INFO", "NO_MATCH_RESPONSE", FAILED)], "{entries:?}");
    assert_eq!((&entries[0].3[1], &entries[0].3[2]), (&json!(""), &json!(NOT_TLS)));
    assert_eq!(entries[1].3[1], NOT_TLS);
    let logs = common::logs(server.port).await;
    // an empty argument as the 8.0.0 oracle prints one (scenario `w2_forward_timeouts`); the snapshot's JDK indents it
    assert!(logs.contains(&format!(" to remote address\n\n\n\n because:\n\n  {NOT_TLS}\n")), "{logs}");
    server.server.shutdown().await;
}

// --- d639e3622: a body with no Content-Type forwarded and recorded byte for byte -----------------------------------

fn random_bytes(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (state >> 56) as u8
        })
        .collect()
}

/// `shouldForwardOverHttp1ByteIdentical`: random bytes (not UTF-8) with no `Content-Type` reach the upstream and the
/// client unchanged, with no `Content-Type` added, and both recorded copies are the same bytes as `BINARY`.
#[tokio::test(flavor = "multi_thread")]
async fn body_without_content_type_is_forwarded_and_recorded_byte_identical() {
    use base64::Engine;
    let (request_bytes, response_bytes) = (random_bytes(50_000, 17), random_bytes(100_000, 29));
    assert!(std::str::from_utf8(&request_bytes).is_err() && std::str::from_utf8(&response_bytes).is_err());
    let mut answer = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", response_bytes.len()).into_bytes();
    answer.extend_from_slice(&response_bytes);
    let upstream = RawUpstream::start(Answer::Bytes(answer));
    let server = common::start(&[]).await;
    common::expect(server.port, &forward_to("/forward-h1", upstream.port)).await;
    let r = send(server.port, "POST", "/forward-h1", &[], &request_bytes).await;
    assert_eq!(r.status, 200, "{}", r.head);
    assert!(r.body == response_bytes, "response received by client");
    assert!(!r.head.to_ascii_lowercase().contains("content-type"), "{}", r.head);
    assert!(body_of(&upstream.requests()[0]) == request_bytes, "request received upstream");

    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let exchanges = put(server.port, "/mockserver/retrieve?type=REQUEST_RESPONSES", &json!({"path": "/forward-h1"})).await;
    assert_eq!(exchanges[0]["httpRequest"]["body"], json!({"type": "BINARY", "base64Bytes": b64(&request_bytes)}));
    assert_eq!(exchanges[0]["httpResponse"]["body"], json!({"type": "BINARY", "base64Bytes": b64(&response_bytes)}));
    let requests = put(server.port, "/mockserver/retrieve?type=REQUESTS", &json!({"path": "/forward-h1"})).await;
    assert_eq!(requests[0]["body"], json!({"type": "BINARY", "base64Bytes": b64(&request_bytes)}));
    server.server.shutdown().await;
}

// --- a streamed zstd response ------------------------------------------------------------------------

/// A streamed (SSE) zstd response: decoded as it arrives, without its `Content-Encoding`, a
/// flushed block passed on at once.
#[tokio::test(flavor = "multi_thread")]
async fn streamed_zstd_response_is_decoded_as_it_arrives() {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
    encoder.write_all(b"first").unwrap();
    encoder.flush().unwrap();
    let first = encoder.get_ref().clone();
    let mut answer = format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: zstd\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n", first.len()).into_bytes();
    answer.extend_from_slice(&first);
    answer.extend_from_slice(b"\r\n");
    let upstream = RawUpstream::start(Answer::BytesHeld(answer));
    let server = common::start(&[("streamIdleTimeoutSeconds", "1")]).await;
    common::expect(server.port, &forward_to("/sse-zstd", upstream.port)).await;
    let started = Instant::now();
    let r = send(server.port, "GET", "/sse-zstd", &[], b"").await;
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    // the upstream then goes quiet, so the idle timeout ends the stream aborted (c9fb69fd5)
    assert_eq!((r.status, String::from_utf8_lossy(&r.body).as_ref()), (200, "5\r\nfirst\r\n"), "{}", r.head);
    assert!(!r.head.to_ascii_lowercase().contains("content-encoding"), "{}", r.head);
    server.server.shutdown().await;
}

// --- c9fb69fd5: a cut stream ends aborted ----------------------------------------------------------------------------

/// c9fb69fd5 `StreamIdleTimeoutBackpressureIntegrationTest` and `StreamedResponseFramingIntegrationTest` (adopted ahead of the oracle): an upstream that goes quiet after one event is closed by the idle timeout and the response ends without its
/// terminating chunk; so does one whose chunk framing is invalid; a body the upstream delimits by closing its
/// connection completes. 8.0.0 ends all three with the terminating chunk (scenario `forward_stream_idle_timeout`).
#[tokio::test(flavor = "multi_thread")]
async fn idle_and_invalid_framing_abort_a_stream_and_a_close_delimited_one_completes() {
    let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n";
    let quiet = RawUpstream::start(Answer::BytesHeld(format!("{head}Transfer-Encoding: chunked\r\n\r\nb\r\ndata: one\n\n\r\n").into_bytes()));
    let framing = RawUpstream::start(Answer::BytesHeld(format!("{head}Transfer-Encoding: chunked\r\n\r\nb\r\ndata: one\n\n\r\nzz\r\n").into_bytes()));
    let delimited = RawUpstream::start(Answer::Bytes(format!("{head}Connection: close\r\n\r\ndata: one\n\n").into_bytes()));
    let server = common::start(&[("streamIdleTimeoutSeconds", "1")]).await;
    for (path, upstream, body) in [("/quiet", &quiet, "b\r\ndata: one\n\n\r\n"), ("/framing", &framing, "b\r\ndata: one\n\n\r\n"), ("/delimited", &delimited, "b\r\ndata: one\n\n\r\n0\r\n\r\n")] {
        common::expect(server.port, &forward_to(path, upstream.port)).await;
        let r = send(server.port, "GET", path, &[], b"").await;
        assert_eq!((r.status, String::from_utf8_lossy(&r.body).as_ref()), (200, body), "{path}: {}", r.head);
    }
    server.server.shutdown().await;
}

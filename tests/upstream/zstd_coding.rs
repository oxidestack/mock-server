//! zstd content coding: zstd-jni over libzstd, its decoder bounded to 64 KiB buffers
//! (`BoundedZstdHttpContentDecompressor`, `BoundedZstdDecompressorFrameListener`). Ports of:
//! - `ZstdResponseAllocationBoundIntegrationTest`: a frame declaring 2 GiB is decoded without allocating it, a
//!   legitimate response byte for byte, forwarded over HTTP/1.1 and HTTP/2 (aggregated and streamed) and through a
//!   CONNECT tunnel over HTTP/1.1 and HTTP/2;
//! - `ForwardContentEncodingIntegrationTest`'s zstd cases: a zstd request body forwarded byte-identical, a changed one
//!   encoded again in zstd;
//! - `StreamedResponseDecodeBoundIntegrationTest.shouldAbortAZstdStreamForwardedOverHttp2`: a zstd bomb streamed over
//!   HTTP/2 aborts the client's response and drops the upstream stream.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common;

trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

// magic, frame header (8-byte content size, not single-segment), 1 KiB window, content size 2^31 - 1, one empty last raw block
const DECLARES_TWO_GIB: [u8; 17] = [0x28, 0xB5, 0x2F, 0xFD, 0xC0, 0x00, 0xFF, 0xFF, 0xFF, 0x7F, 0, 0, 0, 0, 0x01, 0x00, 0x00];
const EVENT: &[u8] = b"data: hello\n\n";

fn plain() -> Vec<u8> {
    (0..300 * 1024).map(|i: usize| b'a' + ((i * 7 + i / 1024) % 26) as u8).collect()
}

fn zstd(bytes: &[u8]) -> Vec<u8> {
    zstd::bulk::compress(bytes, 3).unwrap()
}

fn unzstd(bytes: &[u8]) -> Vec<u8> {
    zstd::stream::decode_all(bytes).unwrap()
}

/// 2 GiB of zeros in zstd (`zstdOfZeros`), written directly: a frame with a 128 KiB window and no declared size, then
/// 16384 RLE blocks of 128 KiB zeros (4 bytes each), the last one ending the frame: 64 KiB in all.
fn zstd_bomb() -> Vec<u8> {
    let mut bomb = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x38];
    for i in 0..16384 {
        let header: u32 = (128 * 1024) << 3 | 1 << 1 | u32::from(i == 16383);
        bomb.extend_from_slice(&header.to_le_bytes()[..3]);
        bomb.push(0);
    }
    bomb
}

/// `ZstdUpstreamHandler`: `.../declared`, `.../declared-event`, `.../zstd-bomb` or else the legitimate body, in zstd,
/// as `text/event-stream` for a path containing `/stream/`. Which protocol each path came in on is kept.
fn upstream_body(path: &str) -> (Vec<u8>, &'static str) {
    let body = if path.ends_with("/declared") {
        DECLARES_TWO_GIB.to_vec()
    } else if path.ends_with("/declared-event") {
        [DECLARES_TWO_GIB.to_vec(), zstd(EVENT)].concat()
    } else if path.ends_with("/zstd-bomb") {
        zstd_bomb()
    } else {
        zstd(&plain())
    };
    (body, if path.contains("/stream/") { "text/event-stream" } else { "application/octet-stream" })
}

type Seen = Arc<Mutex<HashMap<String, &'static str>>>;

/// A plain HTTP/1.1 upstream answering each request by [`upstream_body`].
async fn http1_upstream(seen: Seen) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(serve_http1(Box::new(socket), seen.clone()));
        }
    });
    port
}

async fn serve_http1(mut io: Box<dyn Io>, seen: Seen) {
    let mut buf = Vec::new();
    loop {
        let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            let mut chunk = [0u8; 8192];
            match io.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
            continue;
        };
        let head = String::from_utf8_lossy(&buf[..end]).to_string();
        buf.drain(..end + 4);
        let path = head.split(' ').nth(1).unwrap_or_default().to_string();
        seen.lock().unwrap().insert(path.clone(), "HTTP/1.1");
        let (body, content_type) = upstream_body(&path);
        let answer = format!("HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-encoding: zstd\r\ncontent-length: {}\r\n\r\n", body.len());
        if io.write_all(&[answer.into_bytes(), body].concat()).await.is_err() {
            return;
        }
    }
}

/// A TLS upstream offering `h2` and `http/1.1`, answering each request by [`upstream_body`]; for HTTP/2 also the paths
/// whose connection the client closed (`closed`).
async fn tls_upstream(seen: Seen, closed: Arc<Mutex<Vec<String>>>) -> u16 {
    use rustls_pki_types::pem::PemObject;
    let file = |name: &str| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/tls").join(name);
    let chain = rustls_pki_types::CertificateDer::pem_file_iter(file("foreign-leaf-cert.pem")).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(file("foreign-leaf-key.pem")).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(chain, key).unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, seen, closed) = (acceptor.clone(), seen.clone(), closed.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
                    return serve_http1(Box::new(tls), seen).await;
                }
                let Ok(mut connection) = h2::server::handshake(tls).await else { return };
                let mut paths = Vec::new();
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let path = request.uri().path().to_string();
                    seen.lock().unwrap().insert(path.clone(), "HTTP/2");
                    paths.push(path.clone());
                    tokio::spawn(async move {
                        let (body, content_type) = upstream_body(&path);
                        let response = http::Response::builder().status(200).header("content-type", content_type).header("content-encoding", "zstd").header("content-length", body.len()).body(()).unwrap();
                        let Ok(mut stream) = respond.send_response(response, false) else { return };
                        let mut at = 0;
                        while at < body.len() {
                            stream.reserve_capacity(body.len() - at);
                            // capacity already assigned is not announced again by `poll_capacity`
                            let granted = match stream.capacity() {
                                0 => match std::future::poll_fn(|cx| stream.poll_capacity(cx)).await {
                                    Some(Ok(n)) => n,
                                    _ => return,
                                },
                                n => n,
                            };
                            let n = granted.min(16384).min(body.len() - at);
                            let end = at + n == body.len();
                            if stream.send_data(Bytes::copy_from_slice(&body[at..at + n]), end).is_err() {
                                return;
                            }
                            at += n;
                        }
                    });
                }
                closed.lock().unwrap().extend(paths);
            });
        }
    });
    port
}

struct Answer {
    status: u16,
    head: String,
    body: Vec<u8>,
    /// The chunked body ended with its terminating chunk (or the body was length-delimited and complete).
    complete: bool,
}

impl Answer {
    fn has_header(&self, name: &str) -> bool {
        self.head.lines().skip(1).any(|l| l.split_once(':').is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(name)))
    }
}

/// An HTTP/1.1 GET of `path` over `io`, read to the end of the response or of the connection.
async fn get(mut io: Box<dyn Io>, host: &str, path: &str) -> Answer {
    io.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(30), io.read_to_end(&mut raw)).await.expect("the response ends");
    parse(&raw)
}

fn parse(raw: &[u8]) -> Answer {
    let at = raw.windows(4).position(|w| w == b"\r\n\r\n").map_or(raw.len(), |i| i + 4);
    let head = String::from_utf8_lossy(&raw[..at]).into_owned();
    let status = head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let rest = &raw[at..];
    let chunked = head.to_ascii_lowercase().contains("transfer-encoding: chunked");
    if !chunked {
        return Answer { status, head, body: rest.to_vec(), complete: true };
    }
    let (mut body, mut at, mut complete) = (Vec::new(), 0, false);
    while let Some(line) = rest[at..].windows(2).position(|w| w == b"\r\n") {
        let size = usize::from_str_radix(String::from_utf8_lossy(&rest[at..at + line]).trim(), 16).unwrap_or(0);
        at += line + 2;
        if size == 0 {
            complete = rest[at..].starts_with(b"\r\n");
            break;
        }
        if rest.len() < at + size {
            body.extend_from_slice(&rest[at..]);
            break;
        }
        body.extend_from_slice(&rest[at..at + size]);
        at += size + 2;
    }
    Answer { status, head, body, complete }
}

/// An HTTP/2 GET of `uri` over `io`: the status, whether `content-encoding` came, and the body.
async fn get_h2(io: Box<dyn Io>, uri: &str) -> (u16, bool, Vec<u8>) {
    let (sender, connection) = h2::client::handshake(io).await.unwrap();
    tokio::spawn(connection);
    let mut sender = sender.ready().await.unwrap();
    let (response, _) = sender.send_request(http::Request::builder().uri(uri).body(()).unwrap(), true).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(30), response).await.expect("a response").unwrap();
    let status = response.status().as_u16();
    let encoded = response.headers().contains_key("content-encoding");
    let mut stream = response.into_body();
    let mut body = Vec::new();
    while let Some(chunk) = tokio::time::timeout(Duration::from_secs(30), stream.data()).await.expect("the stream ends") {
        let chunk = chunk.unwrap();
        let _ = stream.flow_control().release_capacity(chunk.len());
        body.extend_from_slice(&chunk);
    }
    (status, encoded, body)
}

async fn plain_connection(port: u16) -> Box<dyn Io> {
    Box::new(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap())
}

/// A CONNECT to `127.0.0.1:target` through the server, then TLS over the tunnel offering `alpn`.
async fn tunnel(port: u16, target: u16, alpn: &[u8]) -> Box<dyn Io> {
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket.write_all(format!("CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(socket.read_u8().await.unwrap());
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
    let name = rustls_pki_types::ServerName::try_from("127.0.0.1").unwrap();
    let tls = tokio_rustls::TlsConnector::from(common::tls_client_config(alpn)).connect(name, socket).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(alpn), "the tunnel carried {}", String::from_utf8_lossy(alpn));
    Box::new(tls)
}

struct Fixture {
    server: common::Running,
    tls: u16,
    seen: Seen,
    closed: Arc<Mutex<Vec<String>>>,
}

/// `startServers` and `resetExpectations`.
async fn fixture() -> Fixture {
    let (seen, closed): (Seen, Arc<Mutex<Vec<String>>>) = (Arc::default(), Arc::default());
    let plain_port = http1_upstream(seen.clone()).await;
    let tls = tls_upstream(seen.clone(), closed.clone()).await;
    let server = common::start(&[("forwardProxyHttp2Upgrade", "true"), ("forwardProxyTLSX509CertificatesTrustManagerType", "ANY"), ("maxResponseBodySize", "1048576")]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/forward-h1/.*"}, "httpForward": {"host": "127.0.0.1", "port": plain_port}})).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/forward-h2/.*"}, "httpForward": {"host": "127.0.0.1", "port": tls, "scheme": "HTTPS"}})).await;
    let declared = base64(&DECLARES_TWO_GIB);
    let legitimate = base64(&zstd(&plain()));
    common::expect(server.port, &json!({"httpRequest": {"path": "/mock/declared"}, "httpResponse": {"headers": {"content-encoding": ["zstd"]}, "body": {"type": "BINARY", "base64Bytes": declared}}})).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/mock/legitimate"}, "httpResponse": {"headers": {"content-encoding": ["zstd"]}, "body": {"type": "BINARY", "base64Bytes": legitimate}}})).await;
    Fixture { server, tls, seen, closed }
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn assert_decoded_to_nothing(answer: &Answer, case: &str) {
    assert_eq!((answer.status, answer.body.len()), (200, 0), "{case}: {}", answer.head);
    assert!(!answer.has_header("content-encoding"), "{case}: {}", answer.head);
}

fn assert_decoded_byte_for_byte(answer: &Answer, case: &str) {
    assert_eq!(answer.status, 200, "{case}: {}", answer.head);
    assert!(answer.body == plain(), "{case}: {} bytes", answer.body.len());
    assert!(!answer.has_header("content-encoding"), "{case}: {}", answer.head);
}

/// `ZstdResponseAllocationBoundIntegrationTest`, the forward client: `shouldBoundADeclaredSizeForwardedOverHttp1/2`,
/// `shouldDecodeALegitimateResponseForwardedOverHttp1/2`, `shouldBoundADeclaredSizeStreamedOverHttp1/2` and
/// `shouldDecodeALegitimateResponseStreamedOverHttp1/2`.
#[tokio::test(flavor = "multi_thread")]
async fn zstd_responses_are_decoded_bounded_by_the_forward_client() {
    let f = fixture().await;
    let port = f.server.port;
    let host = format!("localhost:{port}");
    for (protocol, prefix) in [("HTTP/1.1", "/forward-h1"), ("HTTP/2", "/forward-h2")] {
        let path = format!("{prefix}/declared");
        assert_decoded_to_nothing(&get(plain_connection(port).await, &host, &path).await, &path);
        let path = format!("{prefix}/legitimate");
        assert_decoded_byte_for_byte(&get(plain_connection(port).await, &host, &path).await, &path);
        let path = format!("{prefix}/stream/declared-event");
        let answer = get(plain_connection(port).await, &host, &path).await;
        assert_eq!((answer.status, String::from_utf8_lossy(&answer.body).as_ref()), (200, "data: hello\n\n"), "{path}: {}", answer.head);
        let path = format!("{prefix}/stream/legitimate");
        assert_decoded_byte_for_byte(&get(plain_connection(port).await, &host, &path).await, &path);
        for path in ["declared", "legitimate", "stream/declared-event", "stream/legitimate"] {
            assert_eq!(f.seen.lock().unwrap().get(&format!("{prefix}/{path}")).copied(), Some(protocol), "{prefix}/{path}");
        }
    }
    f.server.server.shutdown().await;
}

/// `ZstdResponseAllocationBoundIntegrationTest`, the CONNECT relay: `shouldBoundADeclaredSizeDecodedByTheConnectRelayOverHttp1/2`,
/// `shouldDecodeALegitimateResponseInTheConnectRelayOverHttp1/2` (a response the server mocks itself) and
/// `shouldBoundADeclaredSizeFromAnUpstreamProxiedThroughAConnectTunnel` (no expectation matches, so the request is
/// forwarded to the tunnel's target, over HTTP/2 whatever the tunnel carries).
#[tokio::test(flavor = "multi_thread")]
async fn zstd_responses_are_decoded_bounded_in_a_connect_tunnel() {
    let f = fixture().await;
    let port = f.server.port;
    let host = format!("127.0.0.1:{}", f.tls);
    assert_decoded_to_nothing(&get(tunnel(port, f.tls, b"http/1.1").await, &host, "/mock/declared").await, "h1 /mock/declared");
    assert_decoded_byte_for_byte(&get(tunnel(port, f.tls, b"http/1.1").await, &host, "/mock/legitimate").await, "h1 /mock/legitimate");
    let uri = |path: &str| format!("https://{host}{path}");
    let (status, encoded, body) = get_h2(tunnel(port, f.tls, b"h2").await, &uri("/mock/declared")).await;
    assert_eq!((status, encoded, body.len()), (200, false, 0), "h2 /mock/declared");
    let (status, encoded, body) = get_h2(tunnel(port, f.tls, b"h2").await, &uri("/mock/legitimate")).await;
    assert_eq!((status, encoded), (200, false), "h2 /mock/legitimate");
    assert!(body == plain(), "h2 /mock/legitimate: {} bytes", body.len());
    assert_decoded_to_nothing(&get(tunnel(port, f.tls, b"http/1.1").await, &host, "/connect/declared").await, "h1 /connect/declared");
    let (status, encoded, body) = get_h2(tunnel(port, f.tls, b"h2").await, &uri("/connect/h2/declared")).await;
    assert_eq!((status, encoded, body.len()), (200, false, 0), "h2 /connect/h2/declared");
    assert_eq!(f.seen.lock().unwrap().get("/connect/declared").copied(), Some("HTTP/2"));
    assert_eq!(f.seen.lock().unwrap().get("/connect/h2/declared").copied(), Some("HTTP/2"));
    f.server.server.shutdown().await;
}

/// `StreamedResponseDecodeBoundIntegrationTest.shouldAbortAZstdStreamForwardedOverHttp2`: 2 GiB of zeros in zstd,
/// streamed by an HTTP/2 upstream, decodes past the bound of decoded bytes waiting for the client (1 MiB here) in its
/// first read: the client's response ends incomplete, without the terminating chunk, and the upstream connection is
/// closed (`awaitUpstreamClosed`); the server still serves.
#[tokio::test(flavor = "multi_thread")]
async fn zstd_bomb_streamed_over_http2_aborts_the_stream() {
    let f = fixture().await;
    let port = f.server.port;
    let started = std::time::Instant::now();
    let answer = get(plain_connection(port).await, &format!("localhost:{port}"), "/forward-h2/stream/zstd-bomb").await;
    assert!(started.elapsed() < Duration::from_secs(20), "{:?}", started.elapsed());
    assert_eq!(answer.status, 200, "{}", answer.head);
    assert!(answer.body.len() < 64 * 1024 * 1024, "{} bytes", answer.body.len());
    assert!(!answer.complete, "no terminating chunk");
    assert_eq!(f.seen.lock().unwrap().get("/forward-h2/stream/zstd-bomb").copied(), Some("HTTP/2"));
    assert!(common::eventually(|| f.closed.lock().unwrap().iter().any(|p| p == "/forward-h2/stream/zstd-bomb")).await, "the upstream connection was closed");
    assert_eq!(common::send(port, "PUT", "/mockserver/status", "").await.status, 200);
    f.server.server.shutdown().await;
}

// --- ForwardContentEncodingIntegrationTest, zstd ------------------------------------------------------------------

/// An upstream that records each request's head and body (by `content-length`) and answers `200 ok`.
async fn capturing_upstream() -> (u16, tokio::sync::mpsc::UnboundedReceiver<(String, Vec<u8>)>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 65536];
                let end = loop {
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break end;
                    }
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                let head = String::from_utf8_lossy(&buf[..end]).to_string();
                let length: usize = head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.trim().parse().ok())).unwrap_or(0);
                while buf.len() < end + 4 + length {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = tx.send((head, buf[end + 4..end + 4 + length].to_vec()));
                let _ = socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await;
            });
        }
    });
    (port, rx)
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).filter_map(|l| l.split_once(':')).find(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string())
}

async fn post(port: u16, path: &str, content_type: &str, coding: &str, body: &[u8]) -> Answer {
    let mut io = plain_connection(port).await;
    let head = format!("POST {path} HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Type: {content_type}\r\nContent-Encoding: {coding}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    io.write_all(&[head.into_bytes(), body.to_vec()].concat()).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(30), io.read_to_end(&mut raw)).await.expect("an answer");
    parse(&raw)
}

/// `shouldForwardEveryCodingByteIdenticalOverHttp1`, zstd (Netty's `ZstdEncoder`: one frame per 64 KiB block): the
/// request is decoded (matched, recorded decoded) and the upstream gets the bytes as sent.
#[tokio::test(flavor = "multi_thread")]
async fn zstd_request_body_is_decoded_and_forwarded_byte_identical() {
    let (upstream, mut received) = capturing_upstream().await;
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/forward_coding"}, "httpForward": {"host": "127.0.0.1", "port": upstream}})).await;
    let wire: Vec<u8> = plain().chunks(64 * 1024).flat_map(zstd).collect();
    let answer = post(server.port, "/forward_coding", "text/plain", "zstd", &wire).await;
    assert_eq!(answer.status, 200, "{}", answer.head);
    let (head, body) = received.recv().await.unwrap();
    assert_eq!(header(&head, "content-encoding").as_deref(), Some("zstd"), "{head}");
    assert_eq!(header(&head, "content-length"), Some(wire.len().to_string()), "{head}");
    assert!(body == wire, "forwarded byte-identical: {} bytes of {}", body.len(), wire.len());
    let recorded = common::send(server.port, "PUT", "/mockserver/retrieve?type=REQUESTS&format=JSON", &json!({"path": "/forward_coding"}).to_string()).await.body;
    assert!(recorded.contains("ahovcjqx"), "recorded decoded: {}", &recorded[..recorded.len().min(500)]);
    server.server.shutdown().await;
}

/// `shouldReencodeAChangedBodyOverHttp1`, zstd: a body an override changes goes out zstd-encoded again under the
/// request's `Content-Encoding`.
#[tokio::test(flavor = "multi_thread")]
async fn changed_zstd_body_is_encoded_again() {
    let (upstream, mut received) = capturing_upstream().await;
    let server = common::start(&[]).await;
    let changed = br#"{"changed":"by an override"}"#;
    common::expect(server.port, &json!({"httpRequest": {"path": "/forward_changed"}, "httpOverrideForwardedRequest": {"requestOverride": {"body": {"type": "BINARY", "base64Bytes": base64(changed)}, "socketAddress": {"host": "127.0.0.1", "port": upstream}}}})).await;
    let answer = post(server.port, "/forward_changed", "application/json", "zstd", &zstd(&plain())).await;
    assert_eq!(answer.status, 200, "{}", answer.head);
    let (head, body) = received.recv().await.unwrap();
    assert_eq!(header(&head, "content-encoding").as_deref(), Some("zstd"), "{head}");
    assert_eq!(unzstd(&body), changed, "the override's body, in zstd");
    assert_eq!(body, zstd(changed), "as Netty's ZstdEncoder writes it");
    server.server.shutdown().await;
}

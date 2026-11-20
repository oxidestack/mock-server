//! Ports of the `responseWriteStallTimeoutMillis` cases found failing on rs-process
//! (`ResponseWriteStallTimeoutIntegrationTest`, `Http3ResponseWriteStallTimeoutIntegrationTest`), and of the
//! `ConnectRelayHttp2InterleavedUploadIntegrationTest` case of DATA after a request's end (seen on the oracle on a
//! direct h2c connection as through a CONNECT tunnel: `RST_STREAM STREAM_CLOSED` on that stream alone).
//! - A streamed response (`/trickle`: about 100 KB of events, then nothing, the upstream left open) whose HTTP/2
//!   client grants no window is reset with CANCEL, and its quiet upstream is closed with it, not at its idle timeout;
//!   over HTTP/3, with 64 KiB of stream credit, its upstream is closed too.
//! - On Linux, an HTTP/2 reader that keeps draining its socket in small bursts, too small for the kernel to wake the
//!   writer within the timeout, gets its whole response: the kernel's `tcpi_last_data_sent` shows its progress, as
//!   `EpollTcpInfo` does upstream (on NIO, macOS, upstream cuts such a reader).
//! - A SETTINGS_INITIAL_WINDOW_SIZE rise that takes a stream's window past 2^31-1 closes the connection with
//!   GOAWAY FLOW_CONTROL_ERROR (RFC 9113 section 6.9.2).

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::common;

const STALL_MILLIS: u64 = 1000;
const CUT_WITHIN: Duration = Duration::from_millis(3 * STALL_MILLIS + 5000);

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;

/// The size of `/forward/large`, upstream's `fixedBody`: far more than the socket buffers between MockServer and a
/// client with a 32 KiB receive buffer.
const LARGE_BODY_BYTES: usize = 16 * 1024 * 1024;

/// An HTTP/1.1 upstream: `/fixed…` is a 1 MiB body with a `content-length`, `/large…` the same with 16 MiB; anything else is about 100 KB of
/// server-sent events, chunked, after which the connection is left open. Each connection's close is reported.
async fn upstream() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (closed_tx, closed) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let closed_tx = closed_tx.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 8192];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let uri = String::from_utf8_lossy(&head).split(' ').nth(1).unwrap_or_default().to_string();
                let mut out = Vec::new();
                if uri.starts_with("/forward/fixed") || uri.starts_with("/forward/large") {
                    let body = vec![b'x'; if uri.starts_with("/forward/large") { LARGE_BODY_BYTES } else { 1024 * 1024 }];
                    out.extend(format!("HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\n\r\n", body.len()).as_bytes());
                    out.extend(body);
                } else {
                    out.extend(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n");
                    let (mut written, mut id) = (0, 0);
                    while written < 100_000 {
                        let event = format!("id: {id}\ndata: {}\n\n", "x".repeat(800));
                        out.extend(format!("{:x}\r\n{event}\r\n", event.len()).as_bytes());
                        written += event.len();
                        id += 1;
                    }
                }
                let _ = socket.write_all(&out).await;
                while matches!(socket.read(&mut buf).await, Ok(n) if n > 0) {}
                let _ = closed_tx.send(uri);
            });
        }
    });
    (port, closed)
}

async fn start() -> (common::Running, u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let stall = STALL_MILLIS.to_string();
    let server = common::start(&[
        ("logLevel", "WARN"),
        ("streamingResponsesEnabled", "true"),
        ("streamIdleTimeoutSeconds", "120"),
        ("responseWriteStallTimeoutMillis", &stall),
    ])
    .await;
    let (port, closed) = upstream().await;
    common::expect(server.port, &serde_json::json!({"httpRequest": {"path": "/forward/.*"}, "httpForward": {"host": "127.0.0.1", "port": port}})).await;
    (server, port, closed)
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    out.extend([kind, flags]);
    out.extend(stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A request's HEADERS frame ending the stream: literal fields without indexing or Huffman coding.
fn request(stream: u32, path: &str, accept: &str, end_stream: bool) -> Vec<u8> {
    let mut block = Vec::new();
    for (name, value) in [(":method", "GET"), (":scheme", "http"), (":authority", "localhost"), (":path", path), ("accept", accept)] {
        block.push(0x00);
        block.push(name.len() as u8);
        block.extend(name.as_bytes());
        block.push(value.len() as u8);
        block.extend(value.as_bytes());
    }
    frame(HEADERS, 0x4 | if end_stream { 0x1 } else { 0 }, stream, &block)
}

/// A cleartext HTTP/2 client with prior knowledge that never returns window, reading frames as they come.
struct H2 {
    socket: TcpStream,
    buf: Vec<u8>,
}

impl H2 {
    async fn open(port: u16) -> H2 {
        let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        hello.extend(frame(SETTINGS, 0, 0, &[]));
        socket.write_all(&hello).await.unwrap();
        H2 { socket, buf: Vec::new() }
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.socket.write_all(bytes).await.unwrap();
    }

    /// The next frame `(type, flags, stream, payload)`, `None` once the connection has closed.
    async fn next(&mut self) -> Option<(u8, u8, u32, Vec<u8>)> {
        loop {
            if self.buf.len() >= 9 {
                let length = u32::from_be_bytes([0, self.buf[0], self.buf[1], self.buf[2]]) as usize;
                if self.buf.len() >= 9 + length {
                    let head: Vec<u8> = self.buf.drain(..9).collect();
                    let payload = self.buf.drain(..length).collect();
                    let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
                    if head[3] == SETTINGS && head[4] & 0x1 == 0 {
                        self.send(&frame(SETTINGS, 0x1, 0, &[])).await;
                    }
                    return Some((head[3], head[4], stream, payload));
                }
            }
            let mut chunk = [0u8; 16 * 1024];
            match self.socket.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_a_stalled_http2_stream_of_a_streamed_response_and_close_its_quiet_upstream() {
    let (server, _, mut closed) = start().await;
    let uri = "/forward/trickle?test=http2-streamed-stalled";
    let mut client = H2::open(server.port).await;
    client.send(&request(1, uri, "text/event-stream", true)).await;
    let reset = tokio::time::timeout(CUT_WITHIN, async {
        loop {
            match client.next().await {
                Some((RST_STREAM, _, 1, payload)) => return Some(u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])),
                Some(_) => {}
                None => return None,
            }
        }
    })
    .await
    .expect("the stream ended");
    assert_eq!(reset, Some(0x8), "the stream was reset with CANCEL");
    // the upstream has sent everything and is quiet, so only closing it with the stream frees it before its idle timeout
    let upstream = tokio::time::timeout(Duration::from_secs(5), closed.recv()).await;
    assert_eq!(upstream.ok().flatten().as_deref(), Some(uri), "the upstream was closed");
}

/// `shouldNotResetAnHttp2StreamOfASlowReaderWhoseSocketIsProgressing`, which upstream runs only on its epoll transport.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn should_not_reset_an_http2_stream_of_a_slow_reader_whose_socket_is_progressing() {
    const STALL_MILLIS: u64 = 3000;
    let stall = STALL_MILLIS.to_string();
    let server = common::start(&[("logLevel", "WARN"), ("streamIdleTimeoutSeconds", "120"), ("responseWriteStallTimeoutMillis", &stall)]).await;
    let (port, _closed) = upstream().await;
    common::expect(server.port, &serde_json::json!({"httpRequest": {"path": "/forward/.*"}, "httpForward": {"host": "127.0.0.1", "port": port}})).await;
    // `openWithOpenWindows`: the largest stream and connection windows, read through a 32 KiB receive buffer
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(32 * 1024).unwrap();
    let socket = socket.connect(([127, 0, 0, 1], server.port).into()).await.unwrap();
    let mut client = H2 { socket, buf: Vec::new() };
    let mut hello = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    let mut settings = 4u16.to_be_bytes().to_vec();
    settings.extend(0x7fff_ffffu32.to_be_bytes());
    hello.extend(frame(SETTINGS, 0, 0, &settings));
    hello.extend(frame(WINDOW_UPDATE, 0, 0, &(0x7fff_ffffu32 - 65_535).to_be_bytes()));
    hello.extend(request(1, "/forward/large?test=http2-slow-socket-reader", "*/*", true));
    client.send(&hello).await;
    // the slow phase: at most 8 KiB of the socket every 200 ms for three timeouts
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_millis(3 * STALL_MILLIS) {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut chunk = [0u8; 8 * 1024];
        match client.socket.try_read(&mut chunk) {
            Ok(0) => panic!("MockServer closed the connection during the slow phase"),
            Ok(n) => client.buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("MockServer cut the connection during the slow phase: {e}"),
        }
    }
    let mut body_bytes = 0;
    let ended = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match client.next().await {
                Some((DATA, flags, 1, payload)) => {
                    body_bytes += payload.len();
                    if flags & 0x1 != 0 {
                        return Ok(());
                    }
                }
                Some((RST_STREAM, _, 1, payload)) => return Err(format!("reset with {:?}", &payload[..4])),
                Some(_) => {}
                None => return Err("the connection closed".to_string()),
            }
        }
    })
    .await;
    assert_eq!(ended, Ok(Ok(())), "the stream ended");
    assert_eq!(body_bytes, LARGE_BODY_BYTES);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_an_http2_connection_whose_client_overflows_an_earlier_streams_window_with_its_initial_window() {
    let (server, _, _closed) = start().await;
    let mut client = H2::open(server.port).await;
    client.send(&request(1, "/forward/fixed?test=http2-overflow-holder", "application/octet-stream", true)).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while !matches!(client.next().await, Some((DATA, _, 1, _)) | None) {}
    })
    .await
    .expect("the holder's response is flowing");
    // the holder took the whole connection window, which is never returned, so the streams opened next are sent nothing
    client.send(&request(3, "/forward/fixed?test=http2-overflow-overflowing", "application/octet-stream", true)).await;
    client.send(&frame(WINDOW_UPDATE, 0, 3, &(0x7fff_ffffu32 - 65_535).to_be_bytes())).await;
    client.send(&request(5, "/forward/fixed?test=http2-overflow-stalled", "application/octet-stream", true)).await;
    let mut settings = 4u16.to_be_bytes().to_vec();
    settings.extend(65_536u32.to_be_bytes());
    client.send(&frame(SETTINGS, 0, 0, &settings)).await;
    let (mut go_away, mut stalled_bytes) = (None, 0);
    let closed = tokio::time::timeout(CUT_WITHIN, async {
        while let Some((kind, _, stream, payload)) = client.next().await {
            match (kind, stream) {
                (GOAWAY, 0) => go_away = Some(u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]])),
                (DATA, 5) => stalled_bytes += payload.len(),
                _ => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "MockServer closed the connection");
    assert_eq!(go_away, Some(0x3), "its GOAWAY named the overflow");
    assert_eq!(stalled_bytes, 0, "the client was sent none of the stalled stream");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_a_stream_sent_data_after_its_request_ended_and_keep_the_connection() {
    let server = common::start(&[("logLevel", "WARN")]).await;
    let delayed = serde_json::json!({"body": "answer for /held", "delay": {"timeUnit": "MILLISECONDS", "value": 1000}});
    common::expect(server.port, &serde_json::json!({"httpRequest": {"path": "/held"}, "httpResponse": delayed})).await;
    common::expect(server.port, &serde_json::json!({"httpRequest": {"path": "/get"}, "httpResponse": {"body": "answer for /get"}})).await;
    let mut client = H2::open(server.port).await;
    client.send(&request(1, "/held", "*/*", true)).await;
    client.send(&request(3, "/held", "*/*", true)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    // DATA after the request's end is a stream error, not a reset from the client
    client.send(&frame(DATA, 0, 3, b"after the end")).await;
    let mut seen = Vec::new();
    let mut kept_body = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match client.next().await.expect("the connection stays open") {
                (RST_STREAM, _, stream, payload) => seen.push(format!("reset {stream} {}", u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]))),
                (HEADERS, _, stream, _) => seen.push(format!("headers {stream}")),
                (DATA, flags, 1, payload) => {
                    kept_body.extend(payload);
                    if flags & 0x1 != 0 {
                        return;
                    }
                }
                (DATA, _, stream, _) => seen.push(format!("data {stream}")),
                _ => {}
            }
        }
    })
    .await
    .expect("the kept stream was answered");
    assert_eq!(seen, ["reset 3 5", "headers 1"], "the broken stream is reset with STREAM_CLOSED, the kept one answered");
    assert_eq!(String::from_utf8_lossy(&kept_body), "answer for /held");
    // past the delay of the answer MockServer was preparing for the broken stream
    tokio::time::sleep(Duration::from_millis(1200)).await;
    client.send(&request(5, "/get", "*/*", true)).await;
    let mut late = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match client.next().await.expect("the connection stays open") {
                (DATA, flags, 5, payload) => {
                    late.extend(payload);
                    if flags & 0x1 != 0 {
                        return;
                    }
                }
                (kind, _, 3, _) if kind != WINDOW_UPDATE => panic!("a frame on the reset stream: {kind}"),
                _ => {}
            }
        }
    })
    .await
    .expect("a later stream is answered");
    assert_eq!(String::from_utf8_lossy(&late), "answer for /get");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_a_stalled_http3_stream_of_a_streamed_response_and_close_its_quiet_upstream() {
    let stall = STALL_MILLIS.to_string();
    let (server, h3_port) = common::start_with_http3(&[
        ("logLevel", "WARN"),
        ("http3MaxIdleTimeout", "60000"),
        ("streamingResponsesEnabled", "true"),
        ("streamIdleTimeoutSeconds", "120"),
        ("responseWriteStallTimeoutMillis", &stall),
    ])
    .await;
    let (port, mut closed) = upstream().await;
    common::expect(server.port, &serde_json::json!({"httpRequest": {"path": "/forward/.*"}, "httpForward": {"host": "127.0.0.1", "port": port}})).await;

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::http3_mcp::TrustAll))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut transport = quinn::TransportConfig::default();
    // quinn grants a stream more credit only as the application reads it, and this client reads nothing
    transport.stream_receive_window((64u32 * 1024).into());
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(config);
    let connection = endpoint.connect(([127, 0, 0, 1], h3_port).into(), "localhost").unwrap().await.unwrap();
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection)).await.unwrap();
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let uri = "/forward/trickle?test=http3-streamed-stalled";
    let request = http::Request::builder().uri(format!("https://127.0.0.1:{h3_port}{uri}")).header("accept", "text/event-stream").body(()).unwrap();
    let mut stream = sender.send_request(request).await.unwrap();
    let _ = stream.finish().await;

    // the upstream has sent everything and is quiet, so only closing it with the stream frees it before its idle timeout
    let upstream = tokio::time::timeout(CUT_WITHIN, closed.recv()).await;
    assert_eq!(upstream.ok().flatten().as_deref(), Some(uri), "the upstream was closed");
    drop(stream);
    drop(sender);
    drive.abort();
    endpoint.close(0u32.into(), b"");
}

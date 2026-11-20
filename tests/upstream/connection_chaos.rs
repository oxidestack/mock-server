//! Connection-lifecycle chaos driven through the server object, as upstream drives the in-JVM `TcpChaosRegistry` and
//! `PreemptionSimulator` singletons: `ConnectionLifecycleChaosIntegrationTest` (mid-response RST over raw sockets),
//! `Http2MultiplexGoAwayIntegrationTest` and `Http2MultiplexResetMidResponseIntegrationTest` (an h2c client that
//! sees connection-level frames).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::common;

async fn seeded() -> common::Running {
    let server = common::start(&[("connectionLifecycleChaosEnabled", "true")]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/ok"}, "httpResponse": {"statusCode": 200, "body": "hello-world"}})).await;
    server
}

struct SocketResult {
    response: String,
    threw_connection_reset: bool,
}

/// `rawHttpExchange`: the request over a plain socket, read to EOF, noting whether reading ended in a reset.
async fn raw_http_exchange(port: u16, request: &str) -> SocketResult {
    let request = request.to_string();
    tokio::task::spawn_blocking(move || {
        let mut socket = std::net::TcpStream::connect(("localhost", port)).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket.write_all(request.as_bytes()).unwrap();
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut reset = false;
        loop {
            match socket.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                Err(e) => {
                    reset = e.kind() == std::io::ErrorKind::ConnectionReset;
                    break;
                }
            }
        }
        SocketResult { response: String::from_utf8_lossy(&buffer).into_owned(), threw_connection_reset: reset }
    })
    .await
    .unwrap()
}

const GET_OK: &str = "GET /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_connection_mid_response_when_profile_active() {
    let server = seeded().await;
    server.server.put_tcp_chaos("localhost", &json!({"resetMidResponse": true}), 0).unwrap();
    let result = raw_http_exchange(server.port, GET_OK).await;
    assert!(result.threw_connection_reset, "expected a TCP RST, not a clean close: {:?}", result.response);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_still_accept_new_connections_after_mid_response_rst_on_http1() {
    let server = seeded().await;
    server.server.put_tcp_chaos("localhost", &json!({"resetMidResponse": true}), 0).unwrap();
    let reset = raw_http_exchange(server.port, GET_OK).await;
    assert!(reset.threw_connection_reset, "the chaos RST must reset the client's own connection");
    server.server.reset_chaos();
    let served = raw_http_exchange(server.port, GET_OK).await;
    assert!(!served.threw_connection_reset, "server must still accept new connections after a mid-response RST");
    assert!(served.response.contains("200"), "{}", served.response);
    assert!(served.response.contains("hello-world"), "{}", served.response);
    server.server.shutdown().await;
}

// ----- an h2c (prior knowledge) client that sees connection-level frames -----

#[derive(Debug)]
enum Event {
    Status(u32, u16),
    GoAway(u32),
    Closed,
}

struct H2c {
    writer: tokio::io::WriteHalf<tokio::net::TcpStream>,
    encoder: loona_hpack::Encoder<'static>,
    next_stream: u32,
    events: mpsc::UnboundedReceiver<Event>,
    statuses: HashMap<u32, u16>,
    go_away: Option<u32>,
    closed: bool,
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

impl H2c {
    async fn connect(port: u16) -> H2c {
        let stream = tokio::net::TcpStream::connect(("localhost", port)).await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);
        writer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
        writer.write_all(&frame(0x4, 0, 0, &[])).await.unwrap();
        let (tx, events) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut decoder = loona_hpack::Decoder::new();
            let mut head = [0u8; 9];
            loop {
                if reader.read_exact(&mut head).await.is_err() {
                    break;
                }
                let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
                let (kind, stream) = (head[3], u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff);
                let mut payload = vec![0u8; length];
                if reader.read_exact(&mut payload).await.is_err() {
                    break;
                }
                match kind {
                    // HEADERS (the server sends no padding or priority).
                    0x1 => {
                        let fields = decoder.decode(&payload).unwrap_or_default();
                        if let Some((_, status)) = fields.iter().find(|(n, _)| n == b":status") {
                            let _ = tx.send(Event::Status(stream, String::from_utf8_lossy(status).parse().unwrap_or(0)));
                        }
                    }
                    0x7 if payload.len() >= 8 => {
                        let _ = tx.send(Event::GoAway(u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]])));
                    }
                    _ => {}
                }
            }
            let _ = tx.send(Event::Closed);
        });
        H2c { writer, encoder: loona_hpack::Encoder::new(), next_stream: 1, events, statuses: HashMap::new(), go_away: None, closed: false }
    }

    /// Opens a stream with a `GET` for `path`; returns its id.
    async fn get(&mut self, path: &str, authority: &str) -> u32 {
        let stream = self.next_stream;
        self.next_stream += 2;
        let fields: [(&[u8], &[u8]); 4] = [(b":method", b"GET"), (b":scheme", b"http"), (b":authority", authority.as_bytes()), (b":path", path.as_bytes())];
        let block = self.encoder.encode(fields.iter().copied());
        // END_STREAM | END_HEADERS
        self.writer.write_all(&frame(0x1, 0x5, stream, &block)).await.unwrap();
        stream
    }

    /// Takes events until `done` holds or `timeout` passes; whether `done` held.
    async fn until(&mut self, timeout: Duration, done: impl Fn(&H2c) -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        while !done(self) {
            match tokio::time::timeout_at(deadline, self.events.recv()).await {
                Ok(Some(Event::Status(stream, status))) => {
                    self.statuses.entry(stream).or_insert(status);
                }
                Ok(Some(Event::GoAway(code))) => {
                    self.go_away.get_or_insert(code);
                }
                Ok(Some(Event::Closed)) | Ok(None) => {
                    self.closed = true;
                    return done(self);
                }
                Err(_) => return false,
            }
        }
        true
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_emit_http2_go_away_chaos_on_multiplex_stream() {
    let server = seeded().await;
    let authority = format!("localhost:{}", server.port);
    server.server.put_tcp_chaos(&authority, &json!({"http2GoAway": true, "http2GoAwayErrorCode": 0xb}), 0).unwrap();
    let mut client = H2c::connect(server.port).await;
    client.get("/ok", &authority).await;
    assert!(client.until(Duration::from_secs(15), |c| c.go_away.is_some()).await, "no GOAWAY observed");
    assert_eq!(client.go_away, Some(0xb), "the GOAWAY carries the configured error code");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_emit_preemption_drain_go_away_on_multiplex_stream() {
    let server = seeded().await;
    server.server.start_preemption(&json!({"mode": "goaway", "ttlMillis": 60_000})).unwrap();
    let authority = format!("localhost:{}", server.port);
    let mut client = H2c::connect(server.port).await;
    let stream = client.get("/ok", &authority).await;
    assert!(client.until(Duration::from_secs(15), |c| c.go_away.is_some()).await, "no preemption-drain GOAWAY observed");
    assert_eq!(client.go_away, Some(0), "a graceful (NO_ERROR) GOAWAY");
    client.until(Duration::from_secs(2), |c| c.statuses.contains_key(&stream)).await;
    assert_eq!(client.statuses.get(&stream), Some(&200), "the request is still served in goaway-only mode");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_mid_response_chaos_must_abort_the_whole_connection_including_sibling_stream() {
    let server = seeded().await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/slow"}, "httpResponse": {"statusCode": 200, "body": "slow-done", "delay": {"timeUnit": "SECONDS", "value": 60}}})).await;
    let authority = format!("localhost:{}", server.port);
    server.server.put_tcp_chaos(&authority, &json!({"resetMidResponse": true}), 0).unwrap();
    let mut client = H2c::connect(server.port).await;
    let sibling = client.get("/slow", &authority).await;
    client.get("/ok", &authority).await;
    assert!(client.until(Duration::from_secs(15), |c| c.closed).await, "the resetMidResponse chaos must abort the whole TCP connection");
    assert_eq!(client.statuses.get(&sibling), None, "the sibling stream must be killed by the connection RST, not served");
    server.server.reset_chaos();
    server.server.shutdown().await;
}

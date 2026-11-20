//! Streamed responses to an HTTP/2 client that reaches MockServer through a CONNECT or SOCKS5 tunnel, TLS or h2c.
//! Ports of `Http2TunnelStreamedResponseIntegrationTest`:
//! `shouldRelayAStreamedResponseThatFollowsAnInterimResponse`,
//! `shouldStopTheUpstreamWhenTheClientResetsAStreamedResponse` and
//! `shouldStopTheUpstreamWhenTheTunnelClosesDuringAStreamedResponse`, each over the four routes; and of
//! `Http2TunnelStreamedResponseBackpressureIntegrationTest` (CONNECT_TLS and SOCKS5_H2C):
//! `shouldHoldBackOnlyTheUpstreamOfAStreamItsClientIsNotTaking`,
//! `shouldResetAStreamedResponseItsClientStopsTakingAndCloseItsUpstream` and
//! `shouldResetTheStreamOfAMockedInformationalResponseAndCloseItsTunnelAsIdle`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common;

trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

const EVENTS: usize = 16;
const EVENT_GAP_MILLIS: u64 = 200;
const STREAM_MILLIS: u64 = (EVENTS as u64 - 1) * EVENT_GAP_MILLIS;
const ROUTES: [(&str, bool, bool); 4] = [("CONNECT_TLS", false, true), ("CONNECT_H2C", false, false), ("SOCKS5_TLS", true, true), ("SOCKS5_H2C", true, false)];

/// `StreamingUpstream`'s `/tokens`: a chunked `text/event-stream` of `count` tokens `gap` ms apart, each request named
/// by its `id`, whose connection the test can watch close.
#[derive(Clone, Default)]
struct Upstream {
    closed: Arc<Mutex<HashMap<String, bool>>>,
    written: Arc<Mutex<HashMap<String, u64>>>,
}

const FLOOD_CHUNK_BYTES: u64 = 8 * 1024;

/// `StreamingUpstream.floodChunk`: the flood's chunk at `offset`, its offset label repeated.
fn flood_chunk(offset: u64) -> Vec<u8> {
    let label = format!("[{offset}]").into_bytes();
    (0..FLOOD_CHUNK_BYTES as usize).map(|i| label[i % label.len()]).collect()
}

fn flood_bytes(total: u64) -> Vec<u8> {
    (0..total).step_by(FLOOD_CHUNK_BYTES as usize).flat_map(flood_chunk).collect()
}

fn token(index: usize) -> String {
    format!("data: {{\"token\":\"t{index}\"}}\n\n")
}

impl Upstream {
    async fn start() -> (Upstream, u16) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let upstream = Upstream::default();
        let state = upstream.clone();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else { return };
                let state = state.clone();
                tokio::spawn(async move { state.serve(socket).await });
            }
        });
        (upstream, port)
    }

    async fn serve(&self, socket: tokio::net::TcpStream) {
        let (mut read, mut write) = socket.into_split();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let Ok(byte) = read.read_u8().await else { return };
            head.push(byte);
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        let target = head.split(' ').nth(1).unwrap_or("").to_string();
        let query: HashMap<&str, &str> = target.split_once('?').map(|(_, q)| q).unwrap_or("").split('&').filter_map(|p| p.split_once('=')).collect();
        let id = query.get("id").unwrap_or(&"none").to_string();
        let count: usize = query.get("count").and_then(|v| v.parse().ok()).unwrap_or(10);
        let gap: u64 = query.get("gap").and_then(|v| v.parse().ok()).unwrap_or(100);
        self.closed.lock().unwrap().insert(id.clone(), false);
        let closed = self.closed.clone();
        let watched = id.clone();
        // the connection is closed once its peer's end is read
        let watcher = tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            while matches!(read.read(&mut buffer).await, Ok(n) if n > 0) {}
            closed.lock().unwrap().insert(watched, true);
        });
        if write.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n").await.is_err() {
            return;
        }
        if target.contains("/flood") {
            let total: u64 = query.get("bytes").and_then(|v| v.parse().ok()).unwrap_or(0);
            let mut offset = 0;
            while offset < total {
                let chunk = flood_chunk(offset);
                offset += FLOOD_CHUNK_BYTES;
                let mut framed = format!("{:x}\r\n", chunk.len()).into_bytes();
                framed.extend_from_slice(&chunk);
                framed.extend_from_slice(b"\r\n");
                if write.write_all(&framed).await.is_err() {
                    return;
                }
                *self.written.lock().unwrap().entry(id.clone()).or_default() += FLOOD_CHUNK_BYTES;
            }
            let _ = write.write_all(b"0\r\n\r\n").await;
            return;
        }
        for i in 0..count {
            let token = token(i);
            if write.write_all(format!("{:x}\r\n{token}\r\n", token.len()).as_bytes()).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(gap)).await;
            if watcher.is_finished() {
                return;
            }
        }
        let _ = write.write_all(b"0\r\n\r\n").await;
    }

    fn written(&self, id: &str) -> u64 {
        self.written.lock().unwrap().get(id).copied().unwrap_or(0)
    }

    fn is_open(&self, id: &str) -> bool {
        self.closed.lock().unwrap().get(id) == Some(&false)
    }

    /// `writtenOnceStandingStill`: the bytes taken from the upstream once the count has not moved for 1.5 s.
    async fn written_once_standing_still(&self, id: &str) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(30);
        let (mut last, mut moved) = (u64::MAX, Instant::now());
        loop {
            let written = self.written(id);
            if written != last {
                (last, moved) = (written, Instant::now());
            } else if written > 0 && moved.elapsed() > Duration::from_millis(1500) {
                return written;
            }
            assert!(Instant::now() < deadline, "the upstream stops being read within 30s (written so far: {written})");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn closed_within(&self, id: &str, seconds: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while Instant::now() < deadline {
            if self.closed.lock().unwrap().get(id) == Some(&true) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }
}

/// A CONNECT (or SOCKS5 CONNECT) to `localhost:443` (TLS, then HTTP/2 by ALPN) or `localhost:80` (h2c); an I/O
/// failure is returned, a refused tunnel fails.
async fn tunnel(port: u16, socks: bool, tls: bool) -> std::io::Result<Box<dyn Io>> {
    let target: u16 = if tls { 443 } else { 80 };
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    if socks {
        socket.write_all(&[5, 1, 0]).await?;
        let mut choice = [0u8; 2];
        socket.read_exact(&mut choice).await?;
        let mut connect = vec![5, 1, 0, 3, 9];
        connect.extend_from_slice(b"localhost");
        connect.extend_from_slice(&target.to_be_bytes());
        socket.write_all(&connect).await?;
        let mut reply = [0u8; 4];
        socket.read_exact(&mut reply).await?;
        assert_eq!(reply[1], 0, "the SOCKS5 CONNECT succeeded");
        let address = match reply[3] {
            1 => 4,
            4 => 16,
            _ => usize::from(socket.read_u8().await?),
        };
        let mut bound = vec![0u8; address + 2];
        socket.read_exact(&mut bound).await?;
    } else {
        socket.write_all(format!("CONNECT localhost:{target} HTTP/1.1\r\nHost: localhost:{target}\r\n\r\n").as_bytes()).await?;
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await?);
        }
        assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
    }
    if !tls {
        return Ok(Box::new(socket));
    }
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let tls = tokio_rustls::TlsConnector::from(common::tls_client_config(b"h2")).connect(name, socket).await?;
    Ok(Box::new(tls))
}

struct Client {
    sender: h2::client::SendRequest<bytes::Bytes>,
    connection: tokio::task::JoinHandle<()>,
    tls: bool,
}

impl Client {
    async fn through(port: u16, socks: bool, tls: bool) -> Client {
        Client::with_window(port, socks, tls, None).await
    }

    /// `streamWindow`: the client's initial stream window, when not the default.
    async fn with_window(port: u16, socks: bool, tls: bool, window: Option<u32>) -> Client {
        Client::connect(port, socks, tls, window, false).await.unwrap()
    }

    /// A tunnel to `timing_server`. It closes a tunnel as idle when nothing arrives for `IDLE_MILLIS` after the CONNECT
    /// 200 or the SOCKS reply, a ClientHello or an h2c preface still to come included, as the oracle does; a client starved that long under load is not what these tests check, so its tunnel is set up again.
    /// That close cannot come sooner than `IDLE_MILLIS` after the connect, so any earlier failure fails, as does a
    /// fifth. A PING answered shows the server took the HTTP/2 connection: an h2c client is ready before it is sent.
    async fn timed(port: u16, socks: bool, tls: bool, window: Option<u32>) -> Client {
        let mut attempt = 1;
        loop {
            let started = Instant::now();
            match Client::connect(port, socks, tls, window, true).await {
                Ok(client) => return client,
                Err(e) => {
                    let after = started.elapsed();
                    assert!(after >= Duration::from_millis(IDLE_MILLIS) && attempt < 5, "the tunnel is set up (attempt {attempt}, failed after {after:?}): {e}");
                }
            }
            attempt += 1;
        }
    }

    async fn connect(port: u16, socks: bool, tls: bool, window: Option<u32>, ping: bool) -> Result<Client, String> {
        let mut builder = h2::client::Builder::new();
        if let Some(window) = window {
            builder.initial_window_size(window);
        }
        let io = tunnel(port, socks, tls).await.map_err(|e| format!("tunnel: {e:?}"))?;
        let (sender, mut connection) = builder.handshake(io).await.map_err(|e| format!("HTTP/2 handshake: {e:?}"))?;
        let ping_pong = if ping { connection.ping_pong() } else { None };
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        if let Some(mut ping_pong) = ping_pong {
            match tokio::time::timeout(Duration::from_secs(15), ping_pong.ping(h2::Ping::opaque())).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(format!("PING: {e:?}")),
                Err(_) => return Err("PING: no answer within 15s".to_string()),
            }
        }
        Ok(Client { sender, connection, tls })
    }

    fn request(&self, method: &str, path: &str) -> http::request::Builder {
        let authority = if self.tls { "localhost:443" } else { "localhost:80" };
        let scheme = if self.tls { "https" } else { "http" };
        http::Request::builder().method(method).uri(format!("{scheme}://{authority}{path}"))
    }

    async fn send(&self, request: http::Request<()>, end: bool) -> (h2::client::ResponseFuture, h2::SendStream<bytes::Bytes>) {
        let mut sender = self.sender.clone().ready().await.unwrap();
        sender.send_request(request, end).unwrap()
    }

    async fn get(&self, path: &str) -> Streamed {
        let (response, upload) = self.send(self.request("GET", path).header("accept", "text/event-stream").body(()).unwrap(), true).await;
        Streamed::read(response, upload)
    }

    fn is_open(&self) -> bool {
        !self.connection.is_finished()
    }
}

/// A response read as it arrives: its status, the bytes so far, when the first and last came, and how it ended.
#[derive(Default)]
struct Received {
    status: Option<u16>,
    body: Vec<u8>,
    first_data: Option<Instant>,
    ended: Option<Instant>,
    reset: Option<h2::Reason>,
}

struct Streamed {
    received: Arc<Mutex<Received>>,
    upload: h2::SendStream<bytes::Bytes>,
    reader: tokio::task::JoinHandle<()>,
}

impl Streamed {
    fn read(response: h2::client::ResponseFuture, upload: h2::SendStream<bytes::Bytes>) -> Streamed {
        Streamed::read_after(response, upload, None)
    }

    /// `sendReadingOnlyTheResponseHeaders`: the head is read at once, the body only once `gate` is notified.
    fn read_after(response: h2::client::ResponseFuture, upload: h2::SendStream<bytes::Bytes>, gate: Option<Arc<tokio::sync::Notify>>) -> Streamed {
        let received = Arc::new(Mutex::new(Received::default()));
        let state = received.clone();
        let reader = tokio::spawn(async move {
            let response = match response.await {
                Ok(response) => response,
                Err(e) => {
                    state.lock().unwrap().reset = e.reason();
                    return;
                }
            };
            state.lock().unwrap().status = Some(response.status().as_u16());
            let mut body = response.into_body();
            // frames are read as they come, but none of the window is returned until the gate opens
            let (mut taking, mut unreturned) = (gate.is_none(), 0);
            loop {
                let chunk = tokio::select! {
                    chunk = body.data() => chunk,
                    _ = async { gate.as_ref().expect("not taking only behind a gate").notified().await }, if !taking => {
                        taking = true;
                        let _ = body.flow_control().release_capacity(std::mem::take(&mut unreturned));
                        continue;
                    }
                };
                let Some(chunk) = chunk else { break };
                match chunk {
                    Ok(chunk) => {
                        if taking {
                            let _ = body.flow_control().release_capacity(chunk.len());
                        } else {
                            unreturned += chunk.len();
                        }
                        let mut state = state.lock().unwrap();
                        state.first_data.get_or_insert_with(Instant::now);
                        state.body.extend_from_slice(&chunk);
                    }
                    Err(e) => {
                        state.lock().unwrap().reset = e.reason();
                        return;
                    }
                }
            }
            state.lock().unwrap().ended = Some(Instant::now());
        });
        Streamed { received, upload, reader }
    }

    async fn status(&self) -> Option<u16> {
        for _ in 0..1500 {
            {
                let received = self.received.lock().unwrap();
                if received.status.is_some() || received.reset.is_some() {
                    return received.status;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        None
    }

    /// The code of the reset that ended the stream, waited for up to `seconds`.
    async fn reset_within(&self, seconds: u64) -> Option<h2::Reason> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while Instant::now() < deadline {
            if let Some(reason) = self.received.lock().unwrap().reset {
                return Some(reason);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        None
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.received.lock().unwrap().body).into_owned()
    }

    async fn received_within(&self, text: &str, seconds: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while Instant::now() < deadline {
            if self.text().contains(text) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    /// The whole body, once the response ends (within 30 s).
    async fn body(&mut self) -> String {
        let _ = tokio::time::timeout(Duration::from_secs(30), &mut self.reader).await;
        let received = self.received.lock().unwrap();
        assert!(received.ended.is_some(), "the response ended (reset: {:?})", received.reset);
        String::from_utf8_lossy(&received.body).into_owned()
    }

    fn millis_from_first_data_to_end(&self) -> u64 {
        let received = self.received.lock().unwrap();
        match (received.first_data, received.ended) {
            (Some(first), Some(end)) => end.duration_since(first).as_millis() as u64,
            _ => 0,
        }
    }
}

fn sse_body(name: &str, count: usize) -> String {
    (0..count).map(|i| format!("data: {name}_{i}\n\n")).collect()
}

async fn reset_server(port: u16, upstream: u16) {
    common::send(port, "PUT", "/mockserver/reset", "").await;
    common::expect(port, &json!({"httpRequest": {"path": "/upstream/.*"}, "httpForward": {"host": "127.0.0.1", "port": upstream}})).await;
    common::expect(port, &json!({"httpRequest": {"path": "/plain"}, "httpResponse": {"body": "served"}})).await;
    let events: Vec<_> = (0..EVENTS)
        .map(|i| json!({"data": format!("tick_{i}"), "delay": {"timeUnit": "MILLISECONDS", "value": if i == 0 { 0 } else { EVENT_GAP_MILLIS }}}))
        .collect();
    common::expect(port, &json!({"httpRequest": {"path": "/sse"}, "httpSseResponse": {"events": events}})).await;
}

/// `warningsAndErrors`: what the server logged since the reset other than received requests, responses returned and
/// forwarded requests.
async fn warnings_and_errors(port: u16) -> Vec<String> {
    // `retrieveLogMessagesArray`: the messages split at `HttpState.LOG_SEPARATOR`
    let logs = common::logs(port).await;
    logs.split("\n------------------------------------\n")
        .filter(|m| !m.trim().is_empty())
        .map(|m| m.split_once(" - ").map_or(m.to_string(), |(_, rest)| rest.to_string()))
        .filter(|m| !m.starts_with("received request") && !m.starts_with("returning ") && !m.starts_with("forwarded request"))
        .collect()
}

async fn start() -> (common::Running, Upstream, u16) {
    let (upstream, upstream_port) = Upstream::start().await;
    let server = common::start(&[("logLevel", "WARN")]).await;
    (server, upstream, upstream_port)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_response_that_follows_an_interim_response_is_relayed() {
    let (server, _upstream, upstream_port) = start().await;
    let port = server.port;
    for (route, socks, tls) in ROUTES {
        reset_server(port, upstream_port).await;
        let tunnel = Client::through(port, socks, tls).await;
        let (mut response, mut upload) = tunnel.send(tunnel.request("POST", "/sse").header("expect", "100-continue").body(()).unwrap(), false).await;
        let interim = tokio::time::timeout(Duration::from_secs(15), std::future::poll_fn(|cx| response.poll_informational(cx))).await;
        let status = match interim {
            Ok(Some(Ok(interim))) => interim.status().as_u16(),
            other => panic!("{route}: no interim response: {:?}", other.map(|o| o.map(|r| r.map(|r| r.status())))),
        };
        assert_eq!(status, 100, "{route}");
        upload.send_data(bytes::Bytes::from_static(b"upload"), true).unwrap();
        let mut streamed = Streamed::read(response, upload);
        let body = streamed.body().await;
        assert_eq!(streamed.received.lock().unwrap().status, Some(200), "{route}");
        assert!(streamed.millis_from_first_data_to_end() >= STREAM_MILLIS / 2, "{route}: {} ms", streamed.millis_from_first_data_to_end());
        assert!(body.contains(&format!("tick_{}", EVENTS - 1)), "{route}: {body}");
    }
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_resetting_a_streamed_response_stops_the_upstream() {
    let (server, upstream, upstream_port) = start().await;
    let port = server.port;
    for (route, socks, tls) in ROUTES {
        reset_server(port, upstream_port).await;
        let id = format!("reset-{route}");
        let tunnel = Client::through(port, socks, tls).await;
        let mut other = tunnel.get("/sse").await;
        let mut abandoned = tunnel.get(&format!("/upstream/tokens?count=400&gap=100&id={id}")).await;
        assert!(abandoned.received_within(&token(2), 15).await, "{route}: {}", abandoned.text());

        abandoned.upload.send_reset(h2::Reason::CANCEL);

        assert!(upstream.closed_within(&id, 10).await, "{route}: the upstream is closed, not left to send its remaining tokens");
        assert_eq!(other.body().await, sse_body("tick", EVENTS), "{route}");
        let mut plain = tunnel.get("/plain").await;
        assert_eq!(plain.body().await, "served", "{route}: the tunnel carries on");
        assert!(tunnel.is_open(), "{route}");
        drop(tunnel);
        assert_eq!(warnings_and_errors(port).await, Vec::<String>::new(), "{route}: a client that gives up is not an error");
    }
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tunnel_closed_during_a_streamed_response_stops_the_upstream() {
    let (server, upstream, upstream_port) = start().await;
    let port = server.port;
    for (route, socks, tls) in ROUTES {
        reset_server(port, upstream_port).await;
        let id = format!("close-{route}");
        let tunnel = Client::through(port, socks, tls).await;
        let abandoned = tunnel.get(&format!("/upstream/tokens?count=400&gap=100&id={id}")).await;
        assert!(abandoned.received_within(&token(2), 15).await, "{route}: {}", abandoned.text());
        tunnel.connection.abort();
        drop(abandoned);
        drop(tunnel);

        assert!(upstream.closed_within(&id, 10).await, "{route}: the upstream is closed");
        let next = Client::through(port, socks, tls).await;
        let mut plain = next.get("/plain").await;
        assert_eq!(plain.body().await, "served", "{route}");
        drop(next);
        assert_eq!(warnings_and_errors(port).await, Vec::<String>::new(), "{route}: a client that leaves is not an error");
    }
    server.server.shutdown().await;
}

// `Http2TunnelStreamedResponseBackpressureIntegrationTest`: `shouldHoldBackOnlyTheUpstreamOfAStreamItsClientIsNotTaking`,
// `shouldResetAStreamedResponseItsClientStopsTakingAndCloseItsUpstream` and
// `shouldResetTheStreamOfAMockedInformationalResponseAndCloseItsTunnelAsIdle`, over its two routes.

const BACKPRESSURE_ROUTES: [(&str, bool, bool); 2] = [("CONNECT_TLS", false, true), ("SOCKS5_H2C", true, false)];
const MAX_BODY_BYTES: u64 = 1024 * 1024;
const FLOOD_BYTES: u64 = 32 * MAX_BODY_BYTES;
const CLIENT_STREAM_WINDOW: u32 = 16 * 1024;

/// `Http2FlowControlBodies.body(OVER_WINDOW, tag)`'s size: more than one default window.
fn over_window(tag: &str) -> String {
    let mut text = String::new();
    let mut i = 0;
    while text.len() <= 70 * 1024 {
        text.push_str(&format!("{tag}-{i};"));
        i += 1;
    }
    text
}

async fn backpressure_reset(port: u16, upstream: u16) {
    common::send(port, "PUT", "/mockserver/reset", "").await;
    common::expect(port, &json!({"httpRequest": {"path": "/upstream/.*"}, "httpForward": {"host": "127.0.0.1", "port": upstream}})).await;
    common::expect(port, &json!({"httpRequest": {"path": "/plain"}, "httpResponse": {"body": "served"}})).await;
}

/// A flood read only up to its head until the returned gate is notified.
async fn stalled_flood(tunnel: &Client, id: &str, bytes: u64) -> (Streamed, Arc<tokio::sync::Notify>) {
    let request = tunnel.request("GET", &format!("/upstream/flood?bytes={bytes}&id={id}")).header("accept", "text/event-stream").body(()).unwrap();
    let (response, upload) = tunnel.send(request, true).await;
    let gate = Arc::new(tokio::sync::Notify::new());
    (Streamed::read_after(response, upload, Some(gate.clone())), gate)
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_upstream_of_a_stream_its_client_is_not_taking_is_held_back() {
    let (upstream, upstream_port) = Upstream::start().await;
    let server = common::start(&[("logLevel", "WARN"), ("maxRequestBodySize", "1048576"), ("streamIdleTimeoutSeconds", "120")]).await;
    let port = server.port;
    for (route, socks, tls) in BACKPRESSURE_ROUTES {
        backpressure_reset(port, upstream_port).await;
        let whole = over_window(&format!("whole-beside-a-stalled-stream-{route}"));
        common::expect(port, &json!({"httpRequest": {"path": "/whole"}, "httpResponse": {"body": whole}})).await;
        let events = json!([{"data": "one"}, {"data": "two", "delay": {"timeUnit": "MILLISECONDS", "value": 200}}, {"data": "three", "delay": {"timeUnit": "MILLISECONDS", "value": 200}}]);
        common::expect(port, &json!({"httpRequest": {"path": "/sse"}, "httpSseResponse": {"events": events}})).await;
        let id = format!("hold-{route}");
        let tunnel = Client::with_window(port, socks, tls, Some(CLIENT_STREAM_WINDOW)).await;
        let (mut stalled, gate) = stalled_flood(&tunnel, &id, FLOOD_BYTES).await;
        assert_eq!(stalled.status().await, Some(200), "{route}");

        let held = upstream.written_once_standing_still(&id).await;
        assert!(held < FLOOD_BYTES, "{route}: the upstream is held back, far short of the whole response");

        assert_eq!(tunnel.get("/sse").await.body().await, "data: one\n\ndata: two\n\ndata: three\n\n", "{route}: a streamed response on the same tunnel");
        assert_eq!(tunnel.get("/whole").await.body().await, whole, "{route}: a whole response on the same tunnel");
        assert!(upstream.written(&id) < FLOOD_BYTES, "{route}: still held");
        assert!(stalled.received.lock().unwrap().reset.is_none(), "{route}");
        assert!(upstream.is_open(&id), "{route}");

        gate.notify_one();
        let _ = tokio::time::timeout(Duration::from_secs(120), &mut stalled.reader).await;
        {
            let received = stalled.received.lock().unwrap();
            assert!(received.ended.is_some() && received.reset.is_none(), "{route}: complete, received {} bytes, reset {:?}", received.body.len(), received.reset);
            assert_eq!(received.body.len() as u64, FLOOD_BYTES, "{route}");
            assert!(received.body == flood_bytes(FLOOD_BYTES), "{route}: every byte, in the order sent");
        }
        drop(tunnel);
        assert_eq!(warnings_and_errors(port).await, Vec::<String>::new(), "{route}");
    }
    server.server.shutdown().await;
}

const IDLE_MILLIS: u64 = 1500;

async fn timing_server() -> common::Running {
    let idle = IDLE_MILLIS.to_string();
    common::start(&[
        ("logLevel", "WARN"),
        ("maxRequestBodySize", "1048576"),
        ("streamIdleTimeoutSeconds", "120"),
        ("responseWriteStallTimeoutMillis", "2000"),
        ("inboundConnectionIdleTimeoutMillis", &idle),
    ])
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_response_its_client_stops_taking_is_reset_and_its_upstream_closed() {
    let (upstream, upstream_port) = Upstream::start().await;
    let server = timing_server().await;
    let port = server.port;
    for (route, socks, tls) in BACKPRESSURE_ROUTES {
        backpressure_reset(port, upstream_port).await;
        let id = format!("stall-{route}");
        let tunnel = Client::timed(port, socks, tls, Some(CLIENT_STREAM_WINDOW)).await;
        let (stalled, _gate) = stalled_flood(&tunnel, &id, FLOOD_BYTES).await;
        assert_eq!(stalled.status().await, Some(200), "{route}");

        assert_eq!(stalled.reset_within(15).await, Some(h2::Reason::CANCEL), "{route}");
        // sent at once: once the reset is written the tunnel has nothing in progress, and is closed after IDLE_MILLIS
        let mut plain = tunnel.get("/plain").await;
        assert!(upstream.closed_within(&id, 15).await, "{route}: MockServer stops taking the upstream's response");
        assert_eq!(plain.body().await, "served", "{route}: the tunnel carries on");
        assert!(tunnel.is_open(), "{route}");
        drop(tunnel);
        let logged = warnings_and_errors(port).await;
        assert!(logged.len() == 1 && logged[0].contains("because its client took none of the response waiting for it"), "{route}: {logged:?}");
    }
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_stream_of_a_mocked_informational_response_is_reset_and_its_tunnel_closed_as_idle() {
    let (_upstream, upstream_port) = Upstream::start().await;
    let server = timing_server().await;
    let port = server.port;
    for (route, socks, tls) in BACKPRESSURE_ROUTES {
        backpressure_reset(port, upstream_port).await;
        common::expect(port, &json!({"httpRequest": {"path": "/processing"}, "httpResponse": {"statusCode": 102}})).await;
        common::expect(port, &json!({"httpRequest": {"path": "/hints"}, "httpResponse": {"statusCode": 103, "headers": {"link": ["</style.css>; rel=preload"]}}})).await;
        for path in ["/processing", "/hints"] {
            let tunnel = Client::timed(port, socks, tls, None).await;
            let (mut response, _upload) = tunnel.send(tunnel.request("GET", path).body(()).unwrap(), true).await;
            let interim = tokio::time::timeout(Duration::from_secs(15), std::future::poll_fn(|cx| response.poll_informational(cx))).await;
            let status = match interim {
                Ok(Some(Ok(interim))) => interim.status().as_u16(),
                other => panic!("{route} {path}: no interim response: {:?}", other.map(|o| o.map(|r| r.map(|r| r.status())))),
            };
            assert_eq!(status, if path == "/hints" { 103 } else { 102 }, "{route} {path}");
            let ended = tokio::time::timeout(Duration::from_secs(15), response).await.expect("the stream ends");
            assert_eq!(ended.err().and_then(|e| e.reason()), Some(h2::Reason::NO_ERROR), "{route} {path}");
            let deadline = Instant::now() + Duration::from_secs(15);
            while tunnel.is_open() && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(!tunnel.is_open(), "{route} {path}: the tunnel is closed as idle");
        }
    }
    server.server.shutdown().await;
}

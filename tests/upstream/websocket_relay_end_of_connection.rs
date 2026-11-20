//! Port of master's `WebSocketRelayEndOfConnectionIntegrationTest`: when one side of a relayed
//! WebSocket leaves, the frames it sent just before reach the other side, followed by a close frame: the one it sent,
//! or 1001 (going away) for a side that left without one. What the other side sends from then on is read (and
//! dropped) rather than left unread.
//!
//! The side that leaves reads nothing while the other floods it, so the relay stops reading the other side and holds
//! bytes from it unread. The other side reads slowly from a small receive buffer, so when the first leaves the relay
//! still has frames on their way to it. Closed with input unread, a socket sends a reset, and the kernel discards what
//! it had not yet sent.

use std::io::{BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use crate::common;

const FRAMES: usize = 512;
const FRAME_BYTES: usize = 16 * 1024;
const SMALL_BUFFER: usize = 16 * 1024;
const NORMAL_CLOSURE: u16 = 1000;
const GOING_AWAY: u16 = 1001;

#[derive(Debug, PartialEq)]
struct Received {
    frames: usize,
    close_code: Option<u16>,
    frames_after_close: usize,
    read_on_after_leaving: bool,
}

fn expected(close_code: u16) -> Received {
    Received { frames: FRAMES, close_code: Some(close_code), frames_after_close: 0, read_on_after_leaving: true }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_deliver_a_clients_frames_and_its_close_frame_to_a_slow_upstream() {
    assert_eq!(client_leaves(true).await, expected(NORMAL_CLOSURE));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_deliver_a_clients_frames_and_going_away_to_a_slow_upstream_when_the_client_leaves_without_a_close_frame() {
    assert_eq!(client_leaves(false).await, expected(GOING_AWAY));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_deliver_an_upstreams_frames_and_its_close_frame_to_a_slow_client() {
    assert_eq!(upstream_leaves(true).await, expected(NORMAL_CLOSURE));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_deliver_an_upstreams_frames_and_going_away_to_a_slow_client_when_the_upstream_leaves_without_a_close_frame() {
    assert_eq!(upstream_leaves(false).await, expected(GOING_AWAY));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_the_clients_connection_within_the_linger_limit_when_the_upstream_leaves_and_the_client_never_reads() {
    let (server, upstream) = start().await;
    let port = server.port;
    let closed = tokio::task::spawn_blocking(move || {
        let flood = Flood::default();
        let (sender, upstream_socket) = mpsc::channel();
        let flood_up = flood.clone();
        std::thread::spawn(move || {
            let socket = accept_and_handshake(&upstream);
            sender.send(socket.try_clone().unwrap()).unwrap();
            let writer = socket.try_clone().unwrap();
            let flood_up = flood_up.clone();
            std::thread::spawn(move || flood_up.flood(writer, false));
            // what the client sends is taken, so that nothing backs up towards the upstream
            let mut input = socket;
            while read_frame(&mut input).ok().flatten().is_some() {}
        });
        let mut client = upgraded_client(port, upstream_port_of(port));
        await_stalled(&client);
        let leaving = upstream_socket.recv_timeout(Duration::from_secs(10)).unwrap();
        // `setSoLinger(true, 0)` and `close()`: the clones the upstream's reader and flood hold are ended too
        socket2::SockRef::from(&leaving).set_linger(Some(Duration::ZERO)).unwrap();
        let _ = leaving.shutdown(Shutdown::Both);
        drop(leaving);
        // the client goes on sending, which shows the relay that the upstream has gone and then whether it still holds
        // the client's connection open; it never reads what is queued for it, the close frame included
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut closed = false;
        while !closed && Instant::now() < deadline {
            if client.write_all(&frame(0x2, &[0u8; 16], true)).and_then(|_| client.flush()).is_err() {
                closed = true;
            } else {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        closed
    })
    .await
    .unwrap();
    assert!(closed, "the client's connection was closed within 20 seconds");
    drop(server);
}

/// The upstream port a test's client names in its `Host`, kept per server port.
fn upstream_port_of(server_port: u16) -> u16 {
    UPSTREAM_PORTS.lock().unwrap().iter().find(|(s, _)| *s == server_port).unwrap().1
}

static UPSTREAM_PORTS: std::sync::Mutex<Vec<(u16, u16)>> = std::sync::Mutex::new(Vec::new());

/// The upstream floods the client and reads its frames slowly; the client reads nothing, sends its frames and ends
/// its output.
async fn client_leaves(with_close_frame: bool) -> Received {
    let (server, upstream) = start().await;
    let port = server.port;
    let received = tokio::task::spawn_blocking(move || {
        let flood = Flood::default();
        let (sender, received) = mpsc::channel();
        let flood_up = flood.clone();
        std::thread::spawn(move || {
            let socket = accept_and_handshake(&upstream);
            let writer = socket.try_clone().unwrap();
            let flood_writer = flood_up.clone();
            std::thread::spawn(move || flood_writer.flood(writer, false));
            let _ = sender.send(read_until_closed(&mut paced(socket), &flood_up));
        });
        let client = upgraded_client(port, upstream_port_of(port));
        await_stalled(&client);
        leave(&client, true, with_close_frame, &flood);
        let received = received.recv_timeout(Duration::from_secs(60)).expect("the upstream read to its end within 60 seconds");
        drop(client);
        received
    })
    .await
    .unwrap();
    drop(server);
    received.unwrap_or_else(|e| panic!("{e}"))
}

/// The client floods the upstream and reads its frames slowly; the upstream reads nothing, sends its frames and ends
/// its output.
async fn upstream_leaves(with_close_frame: bool) -> Received {
    let (server, upstream) = start().await;
    let port = server.port;
    let received = tokio::task::spawn_blocking(move || {
        let flood = Flood::default();
        let flood_up = flood.clone();
        let (sender, upstream_socket) = mpsc::channel();
        std::thread::spawn(move || {
            let socket = accept_and_handshake(&upstream);
            await_stalled(&socket);
            leave(&socket, false, with_close_frame, &flood_up);
            // the socket stays open, with what it was sent unread
            let _ = sender.send(socket);
        });
        let client = upgraded_client(port, upstream_port_of(port));
        let writer = client.try_clone().unwrap();
        let flood_writer = flood.clone();
        std::thread::spawn(move || flood_writer.flood(writer, true));
        let received = read_until_closed(&mut paced(client), &flood);
        drop(upstream_socket);
        received
    })
    .await
    .unwrap();
    drop(server);
    received.unwrap_or_else(|e| panic!("{e}"))
}

async fn start() -> (common::Running, TcpListener) {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    // set before binding so that accepted sockets get it and the kernel does not grow it
    socket.set_recv_buffer_size(SMALL_BUFFER).unwrap();
    socket.bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into()).unwrap();
    socket.listen(50).unwrap();
    let upstream: TcpListener = socket.into();
    let server = common::start(&[
        ("logLevel", "WARN"),
        ("startupWarmup", "false"),
        ("proxySetup", "false"),
        ("attemptToProxyIfNoMatchingExpectation", "true"),
    ])
    .await;
    UPSTREAM_PORTS.lock().unwrap().push((server.port, upstream.local_addr().unwrap().port()));
    (server, upstream)
}

fn accept_and_handshake(upstream: &TcpListener) -> TcpStream {
    let (mut socket, _) = upstream.accept().unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let head = read_head(&mut socket).unwrap();
    let key = head
        .lines()
        .find_map(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:").then(|| l[l.find(':').unwrap() + 1..].trim().to_string()))
        .unwrap();
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    socket
        .write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes())
        .unwrap();
    socket.flush().unwrap();
    socket
}

fn upgraded_client(port: u16, upstream_port: u16) -> TcpStream {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    // set before connecting so that the kernel does not grow it
    socket.set_recv_buffer_size(SMALL_BUFFER).unwrap();
    socket.connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)).into(), Duration::from_secs(10)).unwrap();
    let mut client: TcpStream = socket.into();
    client.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    client
        .write_all(
            format!(
                "GET /relay HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
    client.flush().unwrap();
    let head = read_head(&mut client).unwrap();
    assert!(head.starts_with("HTTP/1.1 101"), "not upgraded: {head}");
    client
}

/// What each side's flood has written so far, and how far when the other side began to leave.
#[derive(Clone, Default)]
struct Flood {
    flooded: Arc<AtomicU64>,
    when_leaving: Arc<AtomicU64>,
}

impl Flood {
    /// Writes text frames until the connection fails or 64 MB have been written, which no socket buffers hold.
    fn flood(&self, mut socket: TcpStream, masked: bool) {
        let frame = frame(0x1, &vec![b'x'; 0xffff], masked);
        for _ in 0..1024 {
            if socket.write_all(&frame).is_err() {
                return;
            }
            self.flooded.fetch_add(frame.len() as u64, Ordering::SeqCst);
        }
    }
}

/// Sends binary frames, each starting with its sequence number, and if asked a close frame and one more frame, then
/// ends the output; the socket stays open, with what it was sent unread.
fn leave(socket: &TcpStream, masked: bool, with_close_frame: bool, flood: &Flood) {
    flood.when_leaving.store(flood.flooded.load(Ordering::SeqCst), Ordering::SeqCst);
    let mut output = socket;
    for sequence in 0..FRAMES {
        let mut payload = vec![0u8; FRAME_BYTES];
        payload[..4].copy_from_slice(&(sequence as u32).to_be_bytes());
        output.write_all(&frame(0x2, &payload, masked)).unwrap();
    }
    if with_close_frame {
        output.write_all(&frame(0x8, &NORMAL_CLOSURE.to_be_bytes(), masked)).unwrap();
        output.write_all(&frame(0x2, &vec![0u8; FRAME_BYTES], masked)).unwrap();
    }
    output.flush().unwrap();
    socket.shutdown(Shutdown::Write).unwrap();
}

fn frame(opcode: u8, payload: &[u8], masked: bool) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 8);
    frame.push(0x80 | opcode);
    let mask_bit = if masked { 0x80 } else { 0 };
    if payload.len() < 126 {
        frame.push(mask_bit | payload.len() as u8);
    } else {
        frame.push(mask_bit | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    let mask = [1u8, 2, 3, 4];
    if masked {
        frame.extend_from_slice(&mask);
    }
    frame.extend(payload.iter().enumerate().map(|(i, b)| if masked { b ^ mask[i % 4] } else { *b }));
    frame
}

/// Reads frames until a close frame or the end of the connection, checking that the binary frames arrive in order;
/// then counts the frames that follow up to the end of the connection, and waits for this side's own flood to be
/// taken further than when the other side left.
fn read_until_closed(input: &mut impl Read, flood: &Flood) -> Result<Received, String> {
    let mut frames = 0;
    let close_code = read_frames(input, &mut frames).map_err(|e| format!("after {frames} of {FRAMES} frames: {e}"))?;
    let mut frames_after_close = 0;
    if close_code.is_some() {
        while read_frame(input).map_err(|e| format!("after the close frame: {e}"))?.is_some() {
            frames_after_close += 1;
        }
    }
    let target = flood.when_leaving.load(Ordering::SeqCst) + 1024 * 1024;
    let deadline = Instant::now() + Duration::from_secs(4);
    while flood.flooded.load(Ordering::SeqCst) < target && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(Received { frames, close_code, frames_after_close, read_on_after_leaving: flood.flooded.load(Ordering::SeqCst) >= target })
}

/// The close frame's code, or `None` at the end of the connection.
fn read_frames(input: &mut impl Read, received: &mut usize) -> std::io::Result<Option<u16>> {
    loop {
        let Some((opcode, payload)) = read_frame(input)? else { return Ok(None) };
        if opcode == 0x8 {
            return Ok((payload.len() >= 2).then(|| u16::from_be_bytes([payload[0], payload[1]])));
        }
        let sequence = u32::from_be_bytes(payload[..4.min(payload.len())].try_into().unwrap_or([0; 4]));
        if opcode != 0x2 || payload.len() != FRAME_BYTES || sequence as usize != *received {
            return Err(std::io::Error::other(format!("frame {received} arrived as opcode {opcode}, {} bytes, sequence {sequence}", payload.len())));
        }
        *received += 1;
    }
}

/// The frame's opcode and its unmasked payload, or `None` at the end of the connection.
fn read_frame(input: &mut impl Read) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut first = [0u8; 1];
    if input.read(&mut first)? == 0 {
        return Ok(None);
    }
    let second = read_fully(input, 1)?[0];
    let mut length = (second & 0x7f) as usize;
    if length == 126 {
        let bytes = read_fully(input, 2)?;
        length = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    } else if length == 127 {
        return Err(std::io::Error::other("unexpected 64-bit frame length"));
    }
    let mask = read_fully(input, if second & 0x80 != 0 { 4 } else { 0 })?;
    let mut payload = read_fully(input, length)?;
    if mask.len() == 4 {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Ok(Some((first[0] & 0x0f, payload)))
}

fn read_fully(input: &mut impl Read, length: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    let mut read = 0;
    while read < length {
        match input.read(&mut bytes[read..])? {
            0 => return Err(std::io::Error::other(format!("connection ended part-way through a frame ({read} of {length} bytes)"))),
            n => read += n,
        }
    }
    Ok(bytes)
}

/// Reads at most a small buffer's worth at a time with a pause before each read, so that the relay writing to this
/// end falls behind.
fn paced(socket: TcpStream) -> BufReader<Paced> {
    BufReader::with_capacity(SMALL_BUFFER, Paced(socket))
}

struct Paced(TcpStream);

impl Read for Paced {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::thread::sleep(Duration::from_millis(1));
        let length = buf.len().min(SMALL_BUFFER);
        self.0.read(&mut buf[..length])
    }
}

/// Waits until the bytes waiting on this end stop growing: its receive buffer is full and the relay has stopped
/// reading the other side (`available()`, as a peek of everything queued).
fn await_stalled(socket: &TcpStream) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut before = None;
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    socket.set_nonblocking(true).unwrap();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        let now = socket.peek(&mut buf).unwrap_or(0);
        if now > 0 && before == Some(now) {
            socket.set_nonblocking(false).unwrap();
            return;
        }
        before = Some(now);
    }
    panic!("the connection did not stall within 20 seconds");
}

fn read_head(input: &mut TcpStream) -> std::io::Result<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if input.read(&mut byte)? == 0 {
            return Err(std::io::Error::other(format!("connection closed after: {}", String::from_utf8_lossy(&head))));
        }
        head.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

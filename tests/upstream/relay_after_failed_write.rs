//! Port of `RelayAfterFailedWriteIntegrationTest.shouldForwardABinaryMessageSentBeforeAResetOnOneUpstreamConnection`:
//! a port-forwarding server relays raw bytes to an upstream that floods the client; the client stops
//! reading, sends one more message and resets. The relay's write to the client fails, and the message must still
//! reach the upstream, on the one upstream connection (`ReadAfterFailedWrite`, after 8.0.0).

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common;

#[tokio::test(flavor = "multi_thread")]
async fn should_forward_a_binary_message_sent_before_a_reset_on_one_upstream_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::<u8>::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let (received_up, connections_up) = (received.clone(), connections.clone());
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            connections_up.fetch_add(1, Ordering::SeqCst);
            let received = received_up.clone();
            let (mut read, mut write) = socket.into_split();
            // answers the first bytes by sending more than the sockets' buffers hold
            tokio::spawn(async move {
                let flood = vec![0u8; 64 * 1024];
                while write.write_all(&flood).await.is_ok() {}
            });
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = read.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    received.lock().unwrap().extend_from_slice(&buf[..n]);
                }
            });
        }
    });
    let mut config = mock_server::Config::for_tests();
    config.port_forward = Some(("127.0.0.1".into(), upstream_port));
    let server = common::start_with(config, &[("logLevel", "WARN"), ("startupWarmup", "false"), ("proxySetup", "false")]).await;
    let port = server.port;
    tokio::task::spawn_blocking(move || {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        socket.connect(&std::net::SocketAddr::from(([127, 0, 0, 1], port)).into()).unwrap();
        let mut client: std::net::TcpStream = socket.into();
        client.set_nodelay(true).unwrap();
        client.write_all(b"first\n").unwrap();
        // the upstream floods, the client takes nothing: the relay's writes to it stall
        std::thread::sleep(Duration::from_millis(1500));
        client.write_all(b"last\n").unwrap();
        socket2::SockRef::from(&client).set_linger(Some(Duration::ZERO)).unwrap();
        drop(client);
    })
    .await
    .unwrap();
    let arrived = common::eventually(|| String::from_utf8_lossy(&received.lock().unwrap()).contains("last\n")).await;
    assert!(arrived, "the message sent before the reset reached the upstream: {:?}", String::from_utf8_lossy(&received.lock().unwrap()));
    assert_eq!(connections.load(Ordering::SeqCst), 1, "one upstream connection");
}

/// Port of `shouldRelayAWebSocketFrameSentBeforeAReset`: over the WebSocket relay, an upstream floods
/// the client after its first frame; the client stops reading, sends one more frame and resets. The relay's write to
/// the client fails, and the frame must still reach the upstream.
#[tokio::test(flavor = "multi_thread")]
async fn should_relay_a_websocket_frame_sent_before_a_reset() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let text_frames = Arc::new(Mutex::new(Vec::<String>::new()));
    let frames_up = text_frames.clone();
    std::thread::spawn(move || {
        while let Ok((socket, _)) = listener.accept() {
            let frames = frames_up.clone();
            std::thread::spawn(move || serve_websocket(socket, frames));
        }
    });
    let server = common::start(&[("logLevel", "WARN"), ("startupWarmup", "false"), ("proxySetup", "false"), ("attemptToProxyIfNoMatchingExpectation", "true")]).await;
    let port = server.port;
    tokio::task::spawn_blocking(move || {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        socket.connect(&std::net::SocketAddr::from(([127, 0, 0, 1], port)).into()).unwrap();
        let mut client: std::net::TcpStream = socket.into();
        client.set_nodelay(true).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        client
            .write_all(
                format!(
                    "GET /relay HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
                )
                .as_bytes(),
            )
            .unwrap();
        let head = read_head(&mut client);
        assert!(head.starts_with("HTTP/1.1 101"), "not upgraded: {head}");
        client.write_all(&masked_text_frame("first")).unwrap();
        // the upstream floods, the client takes nothing: the relay's writes to it stall
        std::thread::sleep(Duration::from_millis(1500));
        client.write_all(&masked_text_frame("last")).unwrap();
        socket2::SockRef::from(&client).set_linger(Some(Duration::ZERO)).unwrap();
        drop(client);
    })
    .await
    .unwrap();
    let arrived = common::eventually(|| text_frames.lock().unwrap().iter().any(|t| t == "last")).await;
    assert!(arrived, "the frame sent before the reset reached the upstream: {:?}", text_frames.lock().unwrap());
    assert!(text_frames.lock().unwrap().iter().any(|t| t == "first"));
}

fn read_head(input: &mut impl std::io::Read) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(input.read(&mut byte).unwrap(), 1, "connection closed after: {}", String::from_utf8_lossy(&head));
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

fn masked_text_frame(text: &str) -> Vec<u8> {
    let mask = [1u8, 2, 3, 4];
    // FIN, text; masked, a length under 126
    let mut frame = vec![0x81, 0x80 | text.len() as u8];
    frame.extend_from_slice(&mask);
    frame.extend(text.bytes().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    frame
}

/// `Upstream.serve` for a WebSocket: answers the handshake, records the first text frame, then floods the client with
/// binary frames while recording every text frame it receives.
fn serve_websocket(mut socket: std::net::TcpStream, frames: Arc<Mutex<Vec<String>>>) {
    use std::io::Read;
    let head = read_head(&mut socket);
    let key = head
        .lines()
        .find_map(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:").then(|| l[l.find(':').unwrap() + 1..].trim().to_string()))
        .unwrap();
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    socket
        .write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes())
        .unwrap();
    let read_text_frame = |input: &mut std::net::TcpStream| -> Option<String> {
        let mut header = [0u8; 2];
        input.read_exact(&mut header).ok()?;
        let mut length = (header[1] & 0x7f) as usize;
        if length == 126 {
            let mut extended = [0u8; 2];
            input.read_exact(&mut extended).ok()?;
            length = u16::from_be_bytes(extended) as usize;
        } else if length == 127 {
            let mut extended = [0u8; 8];
            input.read_exact(&mut extended).ok()?;
            length = u64::from_be_bytes(extended) as usize;
        }
        let mut mask = [0u8; 4];
        let masked = header[1] & 0x80 != 0;
        if masked {
            input.read_exact(&mut mask).ok()?;
        }
        let mut payload = vec![0u8; length];
        input.read_exact(&mut payload).ok()?;
        if masked {
            payload.iter_mut().enumerate().for_each(|(i, b)| *b ^= mask[i % 4]);
        }
        Some(if header[0] & 0x0f == 0x1 { String::from_utf8_lossy(&payload).into_owned() } else { format!("opcode {}", header[0] & 0x0f) })
    };
    let Some(first) = read_text_frame(&mut socket) else { return };
    frames.lock().unwrap().push(first);
    let mut writer = socket.try_clone().unwrap();
    std::thread::spawn(move || {
        let mut frame = vec![0x82u8, 126, 0xff, 0xff];
        frame.extend(std::iter::repeat_n(0u8, 0xffff));
        for _ in 0..1024 {
            if writer.write_all(&frame).is_err() {
                return;
            }
        }
    });
    while let Some(text) = read_text_frame(&mut socket) {
        frames.lock().unwrap().push(text);
    }
}

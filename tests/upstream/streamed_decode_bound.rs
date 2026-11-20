//! `StreamedResponseDecodeBoundIntegrationTest.shouldAbortAGzipStreamForwardedOverHttp1` (master): the
//! decoded bytes of a streamed (`text/event-stream`) response waiting for the client are bounded by
//! `maxResponseBodySize`, and the upstream is read again only once they drain, so only one read that decodes to more
//! than the bound can pass it: that read aborts the stream, closes the upstream and ends the client's response
//! without its terminating chunk. A legitimate gzip stream many times the bound still arrives whole.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::json;

use crate::common;

const BOUNDED: usize = 1024 * 1024;

fn gzip(plain: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(plain).unwrap();
    encoder.finish().unwrap()
}

/// `size` zeros, gzipped a MiB at a time (one read of it decodes to far more than the bound).
fn gzip_of_zeros(size: usize) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let zeros = vec![0u8; 1024 * 1024];
    for _ in 0..size / zeros.len() {
        encoder.write_all(&zeros).unwrap();
    }
    encoder.finish().unwrap()
}

/// An upstream answering one request with `body` (gzip, `text/event-stream`, length-delimited) in one write; the
/// receiver gets a message once the forwarding client has closed the connection.
fn upstream(body: Vec<u8>) -> (u16, mpsc::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (closed_tx, closed) = mpsc::channel();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else { return };
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buf) {
                Ok(n) if n > 0 => request.extend_from_slice(&buf[..n]),
                _ => return,
            }
        }
        let mut answer = format!("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-encoding: gzip\r\ncontent-length: {}\r\n\r\n", body.len()).into_bytes();
        answer.extend_from_slice(&body);
        let _ = stream.write_all(&answer);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
        // the client sends nothing more: a read ends only when it closes the connection (or after the timeout)
        if matches!(stream.read(&mut buf), Ok(0) | Err(_)) {
            let _ = closed_tx.send(());
        }
    });
    (port, closed)
}

async fn bounded_server(upstream: u16) -> common::Running {
    let bounded = BOUNDED.to_string();
    let server = common::start(&[("streamingResponsesEnabled", "true"), ("maxResponseBodySize", bounded.as_str()), ("maxRequestBodySize", bounded.as_str())]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/forward-h1/.*"}, "httpForward": {"host": "127.0.0.1", "port": upstream}})).await;
    server
}

fn request(port: u16, path: &str) -> TcpStream {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(socket, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: text/event-stream\r\n\r\n").unwrap();
    socket
}

/// Everything the socket holds until it is closed or quiet for two seconds.
fn read_available(socket: &mut TcpStream) -> Vec<u8> {
    socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut received = Vec::new();
    let mut buf = [0u8; 65536];
    while let Ok(n) = socket.read(&mut buf) {
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    received
}

/// `shouldAbortAGzipStreamForwardedOverHttp1`: a client that does not read until MockServer has closed the upstream.
#[tokio::test(flavor = "multi_thread")]
async fn should_abort_a_gzip_stream_forwarded_over_http1() {
    let (port, closed) = upstream(gzip_of_zeros(256 * 1024 * 1024));
    let server = bounded_server(port).await;
    let mock_server = server.port;
    let received = tokio::task::spawn_blocking(move || {
        let mut socket = request(mock_server, "/forward-h1/stream/gzip-bomb");
        assert!(closed.recv_timeout(Duration::from_secs(60)).is_ok(), "MockServer closed the upstream");
        read_available(&mut socket)
    })
    .await
    .unwrap();
    let text = String::from_utf8_lossy(&received);
    assert!(text.starts_with("HTTP/1.1 200"), "{}", &text[..text.len().min(200)]);
    assert!(received.len() < 64 * 1024 * 1024, "{} bytes", received.len());
    assert!(!text.ends_with("0\r\n\r\n"), "the response has no terminating chunk");
    assert_eq!(common::send(server.port, "PUT", "/mockserver/status", "").await.status, 200);
    server.server.shutdown().await;
}

/// A gzip stream of 16 MiB of events (random payloads, so each read decodes to about what it holds) reaches the client
/// whole.
#[tokio::test(flavor = "multi_thread")]
async fn should_deliver_a_gzip_stream_many_times_the_bound() {
    let mut events = Vec::new();
    let mut seed: u64 = 63;
    for id in 0.. {
        if events.len() >= 16 * 1024 * 1024 {
            break;
        }
        let payload: Vec<u8> = (0..600)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (seed >> 33) as u8
            })
            .collect();
        events.extend_from_slice(format!("id: {id}\ndata: {}\n\n", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, payload)).as_bytes());
    }
    let (port, _closed) = upstream(gzip(&events));
    let server = bounded_server(port).await;
    let mock_server = server.port;
    let body = tokio::task::spawn_blocking(move || {
        let mut socket = request(mock_server, "/forward-h1/stream/events");
        socket.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        let mut received = Vec::new();
        let mut buf = [0u8; 65536];
        while !received.ends_with(b"\r\n0\r\n\r\n") {
            let n = socket.read(&mut buf).unwrap();
            assert!(n > 0, "closed after {} bytes", received.len());
            received.extend_from_slice(&buf[..n]);
        }
        let start = received.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let (mut chunked, mut body) = (&received[start..], Vec::new());
        loop {
            let line = chunked.windows(2).position(|w| w == b"\r\n").unwrap();
            let size = usize::from_str_radix(std::str::from_utf8(&chunked[..line]).unwrap(), 16).unwrap();
            if size == 0 {
                break body;
            }
            body.extend_from_slice(&chunked[line + 2..line + 2 + size]);
            chunked = &chunked[line + 4 + size..];
        }
    })
    .await
    .unwrap();
    assert_eq!(body.len(), events.len());
    assert!(body == events);
    server.server.shutdown().await;
}

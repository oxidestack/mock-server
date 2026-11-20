//! Port of `ResetConnectionIntegrationTest` (9.2.0): `httpError.resetConnection` answers with a TCP RST,
//! so the client's read fails with "connection reset" where `dropConnection` is a clean end of stream, directly
//! (HTTP/1.1, TLS without a `close_notify`, HTTP/2 where the whole connection is reset) and through CONNECT and SOCKS5
//! tunnels, where the client's own connection is the one reset.

use std::io::ErrorKind;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common;

async fn server() -> common::Running {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/reset"}, "httpError": {"resetConnection": true}})).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/drop"}, "httpError": {"dropConnection": true}})).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/both"}, "httpError": {"resetConnection": true, "dropConnection": true, "streamError": 8}})).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/bytes"}, "httpError": {"resetConnection": true, "responseBytes": "SGVsbG8="}})).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/ok"}, "httpResponse": {"body": "still fine"}})).await;
    server
}

pub(crate) async fn send<S: AsyncWrite + Unpin>(socket: &mut S, port: u16, path: &str) {
    socket.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
    socket.flush().await.unwrap();
}

/// The first read after the request: the error kind a RST gives, or a description of what else was read.
pub(crate) async fn read_outcome<S: AsyncRead + Unpin>(socket: &mut S) -> Result<Vec<u8>, ErrorKind> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match tokio::time::timeout(Duration::from_secs(10), socket.read(&mut chunk)).await.expect("the connection must end") {
            Ok(0) => return Ok(data),
            Ok(n) => data.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(e.kind()),
        }
    }
}

async fn assert_reset<S: AsyncRead + AsyncWrite + Unpin>(socket: &mut S, port: u16, path: &str) {
    send(socket, port, path).await;
    assert_eq!(read_outcome(socket).await.map(|d| String::from_utf8_lossy(&d).into_owned()), Err(ErrorKind::ConnectionReset), "{path}");
}

pub(crate) async fn tls(socket: tokio::net::TcpStream) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    tokio_rustls::TlsConnector::from(common::tls_client_config(b"http/1.1")).connect(name, socket).await.unwrap()
}

pub(crate) async fn connect_tunnel(port: u16) -> tokio::net::TcpStream {
    let mut socket = tokio::net::TcpStream::connect(("localhost", port)).await.unwrap();
    let target = format!("localhost:{port}");
    socket.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(socket.read_u8().await.unwrap());
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
    socket
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_http1_connection() {
    let s = server().await;
    let mut socket = tokio::net::TcpStream::connect(("localhost", s.port)).await.unwrap();
    assert_reset(&mut socket, s.port, "/reset").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_tls_connection_without_close_notify() {
    let s = server().await;
    let mut socket = tls(tokio::net::TcpStream::connect(("localhost", s.port)).await.unwrap()).await;
    assert_reset(&mut socket, s.port, "/reset").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_over_a_stream_error_and_a_drop_it_takes_precedence_over() {
    let s = server().await;
    let mut socket = tokio::net::TcpStream::connect(("localhost", s.port)).await.unwrap();
    assert_reset(&mut socket, s.port, "/both").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_write_the_response_bytes_before_the_reset() {
    let s = server().await;
    let mut socket = tokio::net::TcpStream::connect(("localhost", s.port)).await.unwrap();
    send(&mut socket, s.port, "/bytes").await;
    let mut seen = Vec::new();
    let mut chunk = [0u8; 64];
    let outcome = loop {
        match tokio::time::timeout(Duration::from_secs(10), socket.read(&mut chunk)).await.unwrap() {
            Ok(0) => break Ok(()),
            Ok(n) => seen.extend_from_slice(&chunk[..n]),
            Err(e) => break Err(e.kind()),
        }
    };
    // the RST may discard bytes the client has not read yet; whatever arrived is the bytes written
    assert!(b"Hello".starts_with(&seen), "{seen:?}");
    assert_eq!(outcome, Err(ErrorKind::ConnectionReset));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_still_close_cleanly_on_drop_connection() {
    let s = server().await;
    let mut socket = tokio::net::TcpStream::connect(("localhost", s.port)).await.unwrap();
    send(&mut socket, s.port, "/drop").await;
    assert_eq!(read_outcome(&mut socket).await, Ok(Vec::new()), "dropConnection must stay a clean close");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_still_serve_ordinary_responses() {
    let s = server().await;
    let mut socket = tokio::net::TcpStream::connect(("localhost", s.port)).await.unwrap();
    send(&mut socket, s.port, "/ok").await;
    let mut seen = Vec::new();
    let mut chunk = [0u8; 1024];
    while !String::from_utf8_lossy(&seen).contains("still fine") {
        let n = socket.read(&mut chunk).await.unwrap();
        assert!(n > 0);
        seen.extend_from_slice(&chunk[..n]);
    }
    assert!(String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 200 OK"));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_whole_http2_connection() {
    let s = server().await;
    let socket = tokio::net::TcpStream::connect(("localhost", s.port)).await.unwrap();
    let (socket, end) = Tap::new(socket);
    assert_http2_reset(socket, s.port, &end).await;
}

/// The HTTP/2 client over `io`, whose socket is tapped by `end` ([`Tap`]): the connection must end in a reset. What the
/// client's library reports is not the test: `rustls` shows a RST that followed application data as `UnexpectedEof`
/// whenever a later read finds the end of stream, and a write that meets the RST first fails with `BrokenPipe`
/// (found under CPU load). The socket's first end is the evidence: a RST (3), or no end at all (0) with
/// the write that failed. A FIN (1) is a clean close.
pub(crate) async fn assert_http2_reset<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(io: T, port: u16, end: &std::sync::atomic::AtomicU8) {
    let (sender, connection) = h2::client::handshake(io).await.unwrap();
    let driver = tokio::spawn(connection);
    let mut sender = sender.ready().await.unwrap();
    let request = http::Request::builder().uri(format!("http://localhost:{port}/reset")).body(()).unwrap();
    let (response, _) = sender.send_request(request, true).unwrap();
    let answered = tokio::time::timeout(Duration::from_secs(10), response).await.expect("the connection must end");
    assert!(answered.is_err(), "no response is sent");
    let ended = tokio::time::timeout(Duration::from_secs(10), driver).await.expect("the connection must end").unwrap();
    let error = ended.expect_err("the connection ends with an error, not a clean close");
    let kind = error.get_io().map(std::io::Error::kind);
    let reset = match end.load(std::sync::atomic::Ordering::SeqCst) {
        3 => true,
        0 => matches!(kind, Some(ErrorKind::ConnectionReset | ErrorKind::BrokenPipe)),
        _ => false,
    };
    assert!(reset, "the client must see a reset, not a clean close or a stream error (socket end {}): {error:?}", end.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_client_connection_through_connect_tunnel() {
    let s = server().await;
    let mut socket = connect_tunnel(s.port).await;
    assert_reset(&mut socket, s.port, "/reset").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_client_tls_connection_through_connect_tunnel() {
    let s = server().await;
    let socket = connect_tunnel(s.port).await;
    let mut socket = tls(socket).await;
    assert_reset(&mut socket, s.port, "/reset").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_still_close_cleanly_on_drop_connection_through_connect_tunnel() {
    let s = server().await;
    let mut socket = connect_tunnel(s.port).await;
    send(&mut socket, s.port, "/drop").await;
    assert_eq!(read_outcome(&mut socket).await, Ok(Vec::new()));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_client_connection_through_socks5_tunnel() {
    let s = server().await;
    let mut socket = tokio::net::TcpStream::connect(("localhost", s.port)).await.unwrap();
    socket.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    socket.read_exact(&mut method).await.unwrap();
    assert_eq!(method[1], 0);
    let port = s.port;
    socket.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, (port >> 8) as u8, port as u8]).await.unwrap();
    let mut reply = [0u8; 5];
    socket.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS5 connect must succeed");
    // the bound address is a domain name: its length byte, the name, then the port
    let mut rest = vec![0u8; usize::from(reply[4]) + 2];
    socket.read_exact(&mut rest).await.unwrap();
    assert_reset(&mut socket, s.port, "/reset").await;
}

/// A socket that remembers how its first read to end ended, under whatever reads it (a TLS session): `0` still open,
/// `1` end of stream (a FIN), `2` an error, `3` a connection reset (a RST).
struct Tap<T> {
    inner: T,
    end: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

impl<T> Tap<T> {
    fn new(inner: T) -> (Tap<T>, std::sync::Arc<std::sync::atomic::AtomicU8>) {
        let end = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
        (Tap { inner, end: end.clone() }, end)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Tap<T> {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        let ended = match &polled {
            std::task::Poll::Ready(Ok(())) if buf.filled().len() == before => 1,
            std::task::Poll::Ready(Err(e)) => if e.kind() == ErrorKind::ConnectionReset { 3 } else { 2 },
            _ => 0,
        };
        // the first end is the one that counts: a read after a reset can report a plain end of stream
        if ended != 0 {
            let _ = self.end.compare_exchange(0, ended, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst);
        }
        polled
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Tap<T> {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_client_http2_connection_through_connect_tunnel() {
    let s = server().await;
    let socket = connect_tunnel(s.port).await;
    let (socket, end) = Tap::new(socket);
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let tls = tokio_rustls::TlsConnector::from(common::tls_client_config(b"h2")).connect(name, socket).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    assert_http2_reset(tls, s.port, &end).await;
}

/// After the TLS handshake the connection is read raw, past the session: `rustls` turns a reset that follows
/// application data into an `UnexpectedEof`, so only the socket tells a RST from a FIN. The bytes up to the end, the
/// end (`Err(kind)`, or `Ok` for a FIN) and whether a TLS alert record (`close_notify`, content type 21) was among them.
pub(crate) async fn raw_after_tls(socket: tokio_rustls::client::TlsStream<tokio::net::TcpStream>, port: u16, path: &str) -> (usize, Result<(), ErrorKind>, bool) {
    let mut socket = socket;
    send(&mut socket, port, path).await;
    let (mut raw, _) = socket.into_inner();
    let mut records = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        match tokio::time::timeout(Duration::from_secs(10), raw.read(&mut chunk)).await.expect("the connection must end") {
            Ok(0) => break Ok(()),
            Ok(n) => records.extend_from_slice(&chunk[..n]),
            Err(e) => break Err(e.kind()),
        }
    };
    // walk the records: type, version (2), length (2), body
    let (mut at, mut alert) = (0, false);
    while at + 5 <= records.len() {
        alert |= records[at] == 21;
        at += 5 + usize::from(u16::from_be_bytes([records[at + 3], records[at + 4]]));
    }
    (records.len(), end, alert)
}

#[tokio::test(flavor = "multi_thread")]
async fn should_write_the_response_bytes_before_the_reset_over_tls() {
    let s = server().await;
    let socket = tls(tokio::net::TcpStream::connect(("localhost", s.port)).await.unwrap()).await;
    let (bytes, end, alert) = raw_after_tls(socket, s.port, "/bytes").await;
    assert!(bytes > 0, "the application record is written before the reset");
    assert_eq!(end, Err(ErrorKind::ConnectionReset));
    assert!(!alert, "no close_notify before the RST");
}

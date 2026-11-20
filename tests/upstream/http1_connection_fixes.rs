//! Upstream's HTTP/1.1 connection fixes made after 8.0.0, adopted as divergences from the 8.0.0 oracle
//! (`docs/divergences.md`), each with its upstream test ported here over real sockets:
//! - b1bab35da, `RelayRawBytesErrorIntegrationTest`: a response after one no encoder wrote (an `error()`'s raw bytes,
//!   or a mocked final `1xx`) is encoded for its own request's method; 8.0.0 encodes it for the request before, so a
//!   GET after such a HEAD loses its body and a HEAD after such a GET gets one.
//! - 01c7517d2, `OversizedRequestBodyIntegrationTest`: a 413 that ends the connection says `connection: close` and
//!   lingers, so a client that sends its whole body before reading gets the 413 and an end of stream, not a reset.
//! - 88e72ebc7, `RespondBeforeBodyIntegrationTest`: an early (`respondBeforeBody`) response says `connection: close`
//!   and ends with the same lingering close, cut off after five seconds.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde_json::json;

use crate::common;

trait Conn: Read + Write + Send {}
impl<T: Read + Write + Send> Conn for T {}

fn start_tls(socket: TcpStream) -> Box<dyn Conn> {
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    // HTTP/1.1: no ALPN protocol is offered
    let mut connection = rustls::ClientConnection::new(common::tls_client_config(b""), name).unwrap();
    let mut socket = socket;
    while connection.is_handshaking() {
        connection.complete_io(&mut socket).expect("TLS handshake");
    }
    Box::new(rustls::StreamOwned::new(connection, socket))
}

fn read_bytes(input: &mut dyn Conn, length: usize, what: &str) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    let mut read = 0;
    while read < length {
        match input.read(&mut bytes[read..]) {
            Ok(0) => panic!("{what}: connection closed after {read} of {length} bytes"),
            Ok(n) => read += n,
            Err(e) => panic!("{what}: {e} after {read} of {length} bytes"),
        }
    }
    bytes
}

fn read_head(input: &mut dyn Conn, what: &str) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.extend(read_bytes(input, 1, what));
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Everything until the server ends the stream; a reset or a timeout fails, with what had arrived.
fn read_until_end_of_stream(input: &mut dyn Conn, what: &str) -> String {
    let mut received = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match input.read(&mut buf) {
            Ok(0) => return String::from_utf8_lossy(&received).into_owned(),
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(e) => panic!("{what}: connection failed after receiving {} bytes: [{}]: {e}", received.len(), String::from_utf8_lossy(&received)),
        }
    }
}

// --- b1bab35da: each response encoded for its own request ------------------------------------------------------

const WHOLE: &[u8] = b"HTTP/1.1 200 Fine By Me\r\nX-Mixed-CASE:   spaced  \r\ncontent-LENGTH: 3\r\n\r\nraw";

/// Upstream's routes: direct, a cleartext CONNECT with cleartext HTTP/1.1 (served since upstream fix 40939d794) or TLS inside it, and SOCKS4/SOCKS5 tunnels in cleartext and over TLS.
#[derive(Clone, Copy, Debug)]
enum Route {
    Direct,
    DirectTls,
    Connect,
    ConnectTls,
    Socks4,
    Socks4Tls,
    Socks5,
    Socks5Tls,
}

const ROUTES: [Route; 8] = [Route::Direct, Route::DirectTls, Route::Connect, Route::ConnectTls, Route::Socks4, Route::Socks4Tls, Route::Socks5, Route::Socks5Tls];

impl Route {
    fn open(self, port: u16) -> Box<dyn Conn> {
        let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let [high, low] = port.to_be_bytes();
        match self {
            Route::Direct | Route::DirectTls => {}
            Route::Connect | Route::ConnectTls => {
                socket.write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).unwrap();
                let mut boxed: Box<dyn Conn> = Box::new(socket.try_clone().unwrap());
                assert!(read_head(boxed.as_mut(), "CONNECT").contains("200"), "{self:?}: CONNECT accepted");
            }
            Route::Socks4 | Route::Socks4Tls => {
                // version 4, CONNECT, port, IPv4 127.0.0.1, empty user id
                socket.write_all(&[4, 1, high, low, 127, 0, 0, 1, 0]).unwrap();
                let mut boxed: Box<dyn Conn> = Box::new(socket.try_clone().unwrap());
                assert_eq!(read_bytes(boxed.as_mut(), 8, "SOCKS4 reply")[1], 90, "{self:?}: SOCKS4 request granted");
            }
            Route::Socks5 | Route::Socks5Tls => {
                // version 5, one method offered: no authentication
                socket.write_all(&[5, 1, 0]).unwrap();
                let mut boxed: Box<dyn Conn> = Box::new(socket.try_clone().unwrap());
                assert_eq!(read_bytes(boxed.as_mut(), 2, "SOCKS5 method"), [5, 0]);
                // version 5, CONNECT, reserved, IPv4 127.0.0.1, port
                socket.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, high, low]).unwrap();
                let reply = read_bytes(boxed.as_mut(), 5, "SOCKS5 reply");
                assert_eq!(reply[1], 0, "{self:?}: SOCKS5 success");
                let rest = match reply[3] {
                    3 => reply[4] as usize,
                    1 => 3,
                    _ => 15,
                };
                read_bytes(boxed.as_mut(), rest + 2, "SOCKS5 bound address");
            }
        }
        match self {
            Route::DirectTls | Route::ConnectTls | Route::Socks4Tls | Route::Socks5Tls => start_tls(socket),
            _ => Box::new(socket),
        }
    }
}

fn send(socket: &mut dyn Conn, port: u16, method: &str, path: &str) {
    socket.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).unwrap();
    socket.flush().unwrap();
}

async fn raw_bytes_server() -> common::Running {
    use base64::Engine;
    let running = common::start(&[]).await;
    let whole = base64::engine::general_purpose::STANDARD.encode(WHOLE);
    common::expect(running.port, &json!({"httpRequest": {"path": "/whole"}, "httpError": {"responseBytes": whole}})).await;
    common::expect(running.port, &json!({"httpRequest": {"path": "/simple"}, "httpResponse": {"body": "simple"}})).await;
    common::expect(running.port, &json!({"httpRequest": {"path": "/early"}, "httpResponse": {"statusCode": 103}})).await;
    running
}

fn read_simple_get(socket: &mut dyn Conn, route: Route) {
    assert!(read_head(socket, "the GET's head").starts_with("HTTP/1.1 200"), "{route:?}: the GET's head");
    assert_eq!(read_bytes(socket, 6, &format!("{route:?}: the GET's body")), b"simple", "{route:?}: the GET's body");
}

/// `RelayRawBytesErrorIntegrationTest.shouldSendAGetItsBodyAfterAHeadAnsweredWithRawBytes`
#[tokio::test(flavor = "multi_thread")]
async fn should_send_a_get_its_body_after_a_head_answered_with_raw_bytes() {
    let running = raw_bytes_server().await;
    let port = running.port;
    tokio::task::spawn_blocking(move || {
        for route in ROUTES {
            let mut socket = route.open(port);
            send(socket.as_mut(), port, "HEAD", "/whole");
            assert_eq!(read_bytes(socket.as_mut(), WHOLE.len(), &format!("{route:?}: the raw bytes")), WHOLE, "{route:?}: the raw bytes");
            send(socket.as_mut(), port, "GET", "/simple");
            read_simple_get(socket.as_mut(), route);
        }
    })
    .await
    .unwrap();
}

/// `RelayRawBytesErrorIntegrationTest.shouldSendAHeadNoBodyAfterAGetAnsweredWithRawBytes`
#[tokio::test(flavor = "multi_thread")]
async fn should_send_a_head_no_body_after_a_get_answered_with_raw_bytes() {
    let running = raw_bytes_server().await;
    let port = running.port;
    tokio::task::spawn_blocking(move || {
        for route in ROUTES {
            let mut socket = route.open(port);
            send(socket.as_mut(), port, "GET", "/whole");
            assert_eq!(read_bytes(socket.as_mut(), WHOLE.len(), &format!("{route:?}: the raw bytes")), WHOLE, "{route:?}: the raw bytes");
            send(socket.as_mut(), port, "HEAD", "/simple");
            assert!(read_head(socket.as_mut(), "the HEAD's head").contains("content-length: 6"), "{route:?}: the HEAD's head");
            send(socket.as_mut(), port, "GET", "/simple");
            // a body sent after the HEAD's head would be read here, ahead of the GET's head
            read_simple_get(socket.as_mut(), route);
        }
    })
    .await
    .unwrap();
}

/// `RelayRawBytesErrorIntegrationTest.shouldSendAGetItsBodyAfterAHeadAnsweredWithAFinal1xx`
#[tokio::test(flavor = "multi_thread")]
async fn should_send_a_get_its_body_after_a_head_answered_with_a_final_1xx() {
    let running = raw_bytes_server().await;
    let port = running.port;
    tokio::task::spawn_blocking(move || {
        for route in ROUTES {
            let mut socket = route.open(port);
            send(socket.as_mut(), port, "HEAD", "/early");
            assert!(read_head(socket.as_mut(), "the final 1xx").starts_with("HTTP/1.1 103"), "{route:?}: the final 1xx");
            send(socket.as_mut(), port, "GET", "/simple");
            read_simple_get(socket.as_mut(), route);
        }
    })
    .await
    .unwrap();
}

// --- 01c7517d2: a 413 that ends the connection lingers -----------------------------------------------------------

const MAX_REQUEST_BODY_SIZE: &str = "65536";
const BODY_LENGTH: usize = 20_000_000;

/// Sends a request head with a `Content-Length` over the limit, then the whole body before reading anything.
fn send_whole_body(socket: &mut dyn Conn, head: &str, what: &str) {
    socket.write_all(format!("{head}Content-Length: {BODY_LENGTH}\r\n\r\n").as_bytes()).unwrap();
    let chunk = [0u8; 16 * 1024];
    let mut written = 0;
    while written < BODY_LENGTH {
        let n = chunk.len().min(BODY_LENGTH - written);
        if let Err(e) = socket.write_all(&chunk[..n]) {
            panic!("{what}: connection failed while sending the body: {e}");
        }
        written += n;
    }
    socket.flush().unwrap();
}

fn assert_too_large_then_end_of_stream(socket: &mut dyn Conn, what: &str) {
    let response = read_until_end_of_stream(socket, what);
    assert!(response.starts_with("HTTP/1.1 413 "), "{what}: {response:?}");
    assert!(response.to_lowercase().contains("connection: close"), "{what}: {response:?}");
}

fn plain(port: u16) -> Box<dyn Conn> {
    let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    Box::new(socket)
}

fn tls(port: u16) -> Box<dyn Conn> {
    let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    start_tls(socket)
}

async fn oversized(check: impl FnOnce(u16) + Send + 'static) {
    let running = common::start(&[("maxRequestBodySize", MAX_REQUEST_BODY_SIZE)]).await;
    let port = running.port;
    tokio::task::spawn_blocking(move || check(port)).await.unwrap();
}

/// `OversizedRequestBodyIntegrationTest.shouldDeliverTooLargeToClientStillSendingBodyOfConnectionCloseRequest`
#[tokio::test(flavor = "multi_thread")]
async fn should_deliver_too_large_to_client_still_sending_body_of_connection_close_request() {
    oversized(|port| {
        for attempt in 0..3 {
            let what = format!("attempt {attempt}");
            let mut socket = plain(port);
            send_whole_body(socket.as_mut(), "POST /upload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n", &what);
            assert_too_large_then_end_of_stream(socket.as_mut(), &what);
        }
    })
    .await;
}

/// `OversizedRequestBodyIntegrationTest.shouldDeliverTooLargeToClientStillSendingBodyOfHttp10Request`
#[tokio::test(flavor = "multi_thread")]
async fn should_deliver_too_large_to_client_still_sending_body_of_http10_request() {
    oversized(|port| {
        let mut socket = plain(port);
        send_whole_body(socket.as_mut(), "POST /upload HTTP/1.0\r\nHost: localhost\r\n", "http/1.0");
        assert_too_large_then_end_of_stream(socket.as_mut(), "http/1.0");
    })
    .await;
}

/// `OversizedRequestBodyIntegrationTest.shouldDeliverTooLargeOverTlsToClientStillSendingBody`
#[tokio::test(flavor = "multi_thread")]
async fn should_deliver_too_large_over_tls_to_client_still_sending_body() {
    oversized(|port| {
        let mut socket = tls(port);
        send_whole_body(socket.as_mut(), "POST /upload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n", "tls");
        assert_too_large_then_end_of_stream(socket.as_mut(), "tls");
    })
    .await;
}

/// `OversizedRequestBodyIntegrationTest.shouldDeliverTooLargeToClientStillSendingChunkedBodyPastTheLimit`: no
/// `Content-Length`, so the limit is only passed part-way through the body, and the connection ends even though the
/// request is keep-alive, because the rest of the body cannot be told from the next request.
#[tokio::test(flavor = "multi_thread")]
async fn should_deliver_too_large_to_client_still_sending_chunked_body_past_the_limit() {
    oversized(|port| {
        let mut socket = plain(port);
        socket.write_all(b"POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        let chunk = [0u8; 16 * 1024];
        let mut written = 0;
        while written < BODY_LENGTH {
            let sent = socket
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .and_then(|_| socket.write_all(&chunk))
                .and_then(|_| socket.write_all(b"\r\n"));
            if let Err(e) = sent {
                panic!("chunked: connection failed while sending the body: {e}");
            }
            written += chunk.len();
        }
        socket.write_all(b"0\r\n\r\n").expect("chunked: the last chunk");
        socket.flush().unwrap();
        assert_too_large_then_end_of_stream(socket.as_mut(), "chunked");
    })
    .await;
}

/// `OversizedRequestBodyIntegrationTest.shouldKeepKeepAliveConnectionOpenAfterTooLarge`
#[tokio::test(flavor = "multi_thread")]
async fn should_keep_keep_alive_connection_open_after_too_large() {
    oversized(|port| {
        let mut socket = plain(port);
        send_whole_body(socket.as_mut(), "POST /upload HTTP/1.1\r\nHost: localhost\r\n", "keep-alive");
        socket.write_all(format!("GET /after HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
        socket.flush().unwrap();
        let responses = read_until_end_of_stream(socket.as_mut(), "keep-alive");
        assert!(responses.starts_with("HTTP/1.1 413 "), "{responses:?}");
        assert!(responses.contains("HTTP/1.1 404 "), "the next request on the connection is still answered: {responses:?}");
    })
    .await;
}

// --- 88e72ebc7: an early response says it closes, and lingers -----------------------------------------------------

async fn forbid_uploads_before_their_body(connection_options: Option<serde_json::Value>) -> common::Running {
    let running = common::start(&[]).await;
    let mut response = json!({"statusCode": 403, "body": "forbidden"});
    if let Some(options) = connection_options {
        response["connectionOptions"] = options;
    }
    common::expect(running.port, &json!({"httpRequest": {"method": "POST", "path": "/upload", "respondBeforeBody": true}, "httpResponse": response})).await;
    running
}

/// Sends a large body in full before reading the response, as okhttp does, so the server has answered and ended its
/// side of the connection while most of the body is still to arrive.
fn assert_early_response_read_after_whole_body_sent(socket: &mut dyn Conn, what: &str) {
    send_whole_body(socket, "POST /upload HTTP/1.1\r\nHost: localhost\r\n", what);
    let response = read_until_end_of_stream(socket, what);
    assert!(response.contains("403") && response.contains("forbidden"), "{what}: {response:?}");
}

/// `RespondBeforeBodyIntegrationTest.shouldDeliverEarlyResponseToClientStillSendingBody`
#[tokio::test(flavor = "multi_thread")]
async fn should_deliver_early_response_to_client_still_sending_body() {
    let running = forbid_uploads_before_their_body(None).await;
    let port = running.port;
    tokio::task::spawn_blocking(move || {
        for attempt in 0..3 {
            assert_early_response_read_after_whole_body_sent(plain(port).as_mut(), &format!("attempt {attempt}"));
        }
    })
    .await
    .unwrap();
}

/// `RespondBeforeBodyIntegrationTest.shouldDeliverEarlyResponseOverTlsToClientStillSendingBody`
#[tokio::test(flavor = "multi_thread")]
async fn should_deliver_early_response_over_tls_to_client_still_sending_body() {
    let running = forbid_uploads_before_their_body(None).await;
    let port = running.port;
    tokio::task::spawn_blocking(move || assert_early_response_read_after_whole_body_sent(tls(port).as_mut(), "tls")).await.unwrap();
}

/// A keep-alive request answered early: everything until the end of stream, and how long that took.
fn early_answer_to_keep_alive_request(port: u16) -> (String, Duration) {
    let mut socket = plain(port);
    socket.write_all(b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1024\r\nConnection: keep-alive\r\n\r\n").unwrap();
    socket.flush().unwrap();
    let start = Instant::now();
    let response = read_until_end_of_stream(socket.as_mut(), "keep-alive");
    (response, start.elapsed())
}

/// `RespondBeforeBodyIntegrationTest.shouldEndKeepAliveConnectionPromptlyAndSayItClosesAfterEarlyResponse`
#[tokio::test(flavor = "multi_thread")]
async fn should_end_keep_alive_connection_promptly_and_say_it_closes_after_early_response() {
    let running = forbid_uploads_before_their_body(None).await;
    let port = running.port;
    let (response, elapsed) = tokio::task::spawn_blocking(move || early_answer_to_keep_alive_request(port)).await.unwrap();
    // the server ends its side at once, not when it gives up waiting for the client
    assert!(elapsed < Duration::from_millis(2_500), "end of stream after {elapsed:?}");
    assert!(response.contains("403"), "{response:?}");
    assert!(response.to_lowercase().contains("connection: close"), "{response:?}");
    assert!(!response.to_lowercase().contains("keep-alive"), "{response:?}");
}

/// `EarlyNettyResponseWriter.addConnectionHeader`: connection options that decide the header still do.
#[tokio::test(flavor = "multi_thread")]
async fn early_response_connection_header_follows_connection_options_that_set_it() {
    for (options, expected) in [
        (json!({"keepAliveOverride": true}), Some("connection: keep-alive")),
        (json!({"keepAliveOverride": false}), Some("connection: close")),
        (json!({"suppressConnectionHeader": true}), None),
    ] {
        let running = forbid_uploads_before_their_body(Some(options.clone())).await;
        let port = running.port;
        let (response, _) = tokio::task::spawn_blocking(move || early_answer_to_keep_alive_request(port)).await.unwrap();
        let lower = response.to_lowercase();
        match expected {
            Some(header) => assert!(lower.contains(header), "{options}: {response:?}"),
            None => assert!(!lower.contains("connection:"), "{options}: {response:?}"),
        }
        running.server.shutdown().await;
    }
}

/// `RespondBeforeBodyIntegrationTest.shouldCloseConnectionOfClientThatKeepsItOpenAfterEarlyResponse`: a client that
/// neither closes nor stops sending is cut off once the lingering close gives up (five seconds; upstream asserts
/// under ten after 01c7517d2).
#[tokio::test(flavor = "multi_thread")]
async fn should_close_connection_of_client_that_keeps_it_open_after_early_response() {
    let running = forbid_uploads_before_their_body(None).await;
    let port = running.port;
    tokio::task::spawn_blocking(move || {
        let mut socket = plain(port);
        socket.write_all(b"POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 50000000\r\n\r\n").unwrap();
        socket.flush().unwrap();
        assert!(read_until_end_of_stream(socket.as_mut(), "early response").contains("403"));
        // when the client neither closes nor stops sending
        let start = Instant::now();
        let mut closed_by_server = false;
        while !closed_by_server && start.elapsed() < Duration::from_secs(30) {
            if socket.write_all(&[0u8; 1024]).and_then(|_| socket.flush()).is_err() {
                closed_by_server = true;
            } else {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        assert!(closed_by_server, "server should end the connection within its lingering limit");
        assert!(start.elapsed() < Duration::from_secs(10), "cut off after {:?}", start.elapsed());
    })
    .await
    .unwrap();
}

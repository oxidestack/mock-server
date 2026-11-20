//! `RelayRawBytesErrorIntegrationTest.shouldCloseTheTunnelAsIdleAfterAnEmptyRawResponse`: an `error()`
//! of no bytes, loaded through the test's `initializationClass` (`$EmptyRawBytes`, an integration-testing callback
//! class here), writes nothing, and the connection, direct or through a CONNECT or SOCKS tunnel, is closed by the
//! server once it has been idle for `inboundConnectionIdleTimeoutMillis`, with nothing logged at WARN or above.
//! The unmodified upstream test runs on rs-process with the class from the callback plugin; this checks the same
//! behaviour in-process over the plain routes.

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::common;

const IDLE_MILLIS: u64 = 400;
const EMPTY_RAW_BYTES: &str = "org.mockserver.netty.integration.proxy.http.RelayRawBytesErrorIntegrationTest$EmptyRawBytes";

#[derive(Clone, Copy, Debug)]
enum Route {
    Direct,
    Connect,
    Socks4,
    Socks5,
}

async fn read_exact(socket: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(10), socket.read_exact(&mut bytes)).await.expect("read within 10s").expect("read");
    bytes
}

async fn open(route: Route, port: u16) -> TcpStream {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    match route {
        Route::Direct => {}
        Route::Connect => {
            socket.write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.extend(read_exact(&mut socket, 1).await);
            }
            assert!(String::from_utf8_lossy(&head).contains("200"), "{}", String::from_utf8_lossy(&head));
        }
        Route::Socks4 => {
            socket.write_all(&[4, 1, (port >> 8) as u8, port as u8, 127, 0, 0, 1, 0]).await.unwrap();
            assert_eq!(read_exact(&mut socket, 8).await[1], 90, "SOCKS4 request granted");
        }
        Route::Socks5 => {
            socket.write_all(&[5, 1, 0]).await.unwrap();
            assert_eq!(read_exact(&mut socket, 2).await, vec![5, 0]);
            socket.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, (port >> 8) as u8, port as u8]).await.unwrap();
            let reply = read_exact(&mut socket, 5).await;
            assert_eq!(reply[1], 0, "SOCKS5 success");
            let rest = if reply[3] == 3 { reply[4] as usize } else if reply[3] == 1 { 3 } else { 15 };
            read_exact(&mut socket, rest + 2).await;
        }
    }
    socket
}

fn warnings(logs: &serde_json::Value) -> Vec<String> {
    logs.as_array()
        .into_iter()
        .flatten()
        .filter(|e| matches!(e["logLevel"].as_str(), Some("WARN" | "ERROR")))
        .map(|e| format!("{} {}", e["logLevel"], e["messageFormat"]))
        .collect()
}

async fn logged_at_warn_or_above(port: u16) -> Vec<String> {
    let r = common::send(port, "PUT", "/mockserver/retrieve?type=LOGS&format=LOG_ENTRIES", "").await;
    warnings(&serde_json::from_str(&r.body).unwrap_or_default())
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_the_tunnel_as_idle_after_an_empty_raw_response() {
    let idle = IDLE_MILLIS.to_string();
    let server = common::start_with_callback_classes(&[
        ("logLevel", "WARN"),
        ("inboundConnectionIdleTimeoutMillis", &idle),
        ("initializationClass", EMPTY_RAW_BYTES),
        ("startupWarmup", "false"),
        ("proxySetup", "false"),
    ])
    .await;
    let before = logged_at_warn_or_above(server.port).await;

    for route in [Route::Direct, Route::Connect, Route::Socks4, Route::Socks5] {
        let mut socket = open(route, server.port).await;
        let sent = Instant::now();
        socket.write_all(format!("GET /raw HTTP/1.1\r\nHost: localhost:{}\r\n\r\n", server.port).as_bytes()).await.unwrap();
        let mut received = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut received)).await;
        assert!(matches!(read, Ok(Ok(_))), "{route:?}: closed by MockServer, as an idle direct connection is: {read:?}");
        assert_eq!(String::from_utf8_lossy(&received), "", "{route:?}: the bytes a direct client receives");
        let waited = sent.elapsed().as_millis() as u64;
        assert!(waited >= IDLE_MILLIS - 50, "{route:?}: not closed before it had been idle ({waited} ms)");
    }
    assert_eq!(logged_at_warn_or_above(server.port).await, before, "nothing logged at WARN or above");
}

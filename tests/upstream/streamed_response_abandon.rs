//! Port of `StreamedResponseAbandonIntegrationTest.shouldCloseTheUpstreamOfAnEndlessStreamWhoseClientHasGone`: a forwarded event stream whose upstream never ends, read once by a client that then closes its connection.
//! MockServer stops relaying it and closes the upstream's connection, rather than draining the stream for nobody.

use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common;

/// Answers any request with a chunked `text/event-stream`, an event every 20 ms for as long as its connection takes
/// them; `closed` fires when a write fails.
async fn endless_upstream() -> (u16, tokio::sync::oneshot::Receiver<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (closed_tx, closed) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.unwrap());
        }
        let head = b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n";
        if socket.write_all(head).await.is_ok() {
            loop {
                let event = b"data: more\n\n";
                let chunk = [format!("{:x}\r\n", event.len()).into_bytes(), event.to_vec(), b"\r\n".to_vec()].concat();
                if socket.write_all(&chunk).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        let _ = closed_tx.send(());
    });
    (port, closed)
}

#[tokio::test(flavor = "multi_thread")]
async fn should_close_the_upstream_of_an_endless_stream_whose_client_has_gone() {
    let server = common::start(&[("streamingResponsesEnabled", "true"), ("streamIdleTimeoutSeconds", "1")]).await;
    let (upstream_port, closed) = endless_upstream().await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/forward/.*"}, "httpForward": {"host": "127.0.0.1", "port": upstream_port}})).await;
    {
        let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", server.port)).await.unwrap();
        socket
            .write_all(format!("GET /forward/endless HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nAccept: text/event-stream\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buffer = [0u8; 4096];
        let read = tokio::time::timeout(Duration::from_secs(20), socket.read(&mut buffer)).await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&buffer[..read]).starts_with("HTTP/1.1 200"));
        // the client closes its connection, while the upstream keeps sending
    }
    assert!(tokio::time::timeout(Duration::from_secs(8), closed).await.is_ok(), "MockServer closed the abandoned upstream within 8 s");
}

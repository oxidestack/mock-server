//! Port of `NettyHttpProxySOCKS4IntegrationTest`: a SOCKS4 and a SOCKS4a CONNECT to an echo server,
//! then a GET without `Host` through the tunnel. The echo (`EchoServer`) answers with the request's headers, the loop
//! header among them; that header comes off the response after the hop-by-hop filter counted it, so the framing
//! headers are the writer's, `connection` then `content-length`, as the oracle writes them (checked against it with
//! an echo of this shape).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::common;

/// An HTTP/1.1 server answering each request with `200`, the request's headers (`content-length` set to the body's
/// length in place) and its body; the request lines it received go to `received`.
async fn echo_server() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                        continue;
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                    buf.drain(..end + 4);
                    let mut lines = head.split("\r\n");
                    let _ = tx.send(lines.next().unwrap_or_default().to_string());
                    let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
                    let length = headers.iter().find(|(k, _)| k == "content-length").and_then(|(_, v)| v.parse().ok()).unwrap_or(0usize);
                    while buf.len() < length {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let body: Vec<u8> = buf.drain(..length).collect();
                    let mut response = b"HTTP/1.1 200 OK\r\n".to_vec();
                    for (k, v) in &headers {
                        response.extend(format!("{k}: {v}\r\n").as_bytes());
                    }
                    response.extend(b"\r\n");
                    response.extend(&body);
                    if socket.write_all(&response).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, rx)
}

async fn read_some(socket: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; n];
    let read = tokio::time::timeout(Duration::from_secs(15), socket.read(&mut bytes)).await.expect("answered").unwrap();
    bytes.truncate(read);
    bytes
}

async fn proxy_via_socks4(connect_request: impl Fn(u16) -> Vec<u8>, expected_reply: impl Fn(u16) -> Vec<u8>) {
    let server = common::start(&[]).await;
    let (echo_port, mut received) = echo_server().await;
    let mut socket = TcpStream::connect(("localhost", server.port)).await.unwrap();
    socket.write_all(&connect_request(echo_port)).await.unwrap();
    assert_eq!(read_some(&mut socket, 8).await, expected_reply(echo_port));
    socket.write_all(b"GET /some_path HTTP/1.1\r\nContent-Length: 0\r\n\r\n").await.unwrap();
    let response = String::from_utf8_lossy(&read_some(&mut socket, 125).await).into_owned();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\nconnection: keep-alive\r\ncontent-length: 0\r\n\r\n"), "{response:?}");
    let line = tokio::time::timeout(Duration::from_secs(5), received.recv()).await.unwrap().unwrap();
    assert_eq!(line, "GET /some_path HTTP/1.1");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_proxy_requests_using_socket_via_socks4() {
    let request = |port: u16| [&[4u8, 1][..], &port.to_be_bytes(), &[127, 0, 0, 1], &[0]].concat();
    let reply = |port: u16| [&[0u8, 0x5a][..], &port.to_be_bytes(), &[127, 0, 0, 1]].concat();
    proxy_via_socks4(request, reply).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_proxy_requests_using_socket_via_socks4a_with_hostname() {
    let request = |port: u16| [&[4u8, 1][..], &port.to_be_bytes(), &[0, 0, 0, 1, 0], b"localhost", &[0]].concat();
    // a hostname destination: the grant's DSTPORT and DSTIP are 0.0.0.0:0
    let reply = |_: u16| vec![0u8, 0x5a, 0, 0, 0, 0, 0, 0];
    proxy_via_socks4(request, reply).await;
}

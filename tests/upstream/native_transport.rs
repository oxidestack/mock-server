//! `EpollTransportIntegrationTest`: `useNativeTransport` picks Netty's epoll transport on Linux (true, the default)
//! or forces NIO (false). Upstream reads the transport classes of the in-JVM server's channels by reflection
//! (`LifeCycle.serverChannelFutures`, `MockServer.dnsChannel`); mock-server has no Netty transports, so a port
//! checks what those classes stand for: with either value the server boots, reports the configured value, and
//! serves its listener, and with `dnsEnabled` it also serves DNS.

use std::net::UdpSocket;
use std::time::Duration;

use serde_json::json;

use crate::common;

/// `new ClientAndServer(configuration().useNativeTransport(native), 0)`, an expectation for `path`, and one request.
async fn boots_and_serves(native: &str, path: &str, body: &str) {
    let running = common::start(&[("useNativeTransport", native)]).await;
    let configuration = common::send(running.port, "GET", "/mockserver/configuration", "").await;
    assert_eq!(configuration.status, 200, "{}", configuration.body);
    let reported: serde_json::Value = serde_json::from_str(&configuration.body).expect("configuration is JSON");
    assert_eq!(reported["useNativeTransport"], json!(native == "true"), "{}", configuration.body);
    common::expect(running.port, &json!({
        "httpRequest": {"path": path},
        "httpResponse": {"statusCode": 200, "body": body}
    }))
    .await;
    let response = common::send(running.port, "GET", path, "").await;
    assert_eq!(response.status, 200, "{}", response.head);
    assert_eq!(response.body, body);
}

#[tokio::test]
async fn should_use_epoll_server_channel_when_native_transport_enabled() {
    boots_and_serves("true", "/epoll-test", "epoll-ok").await;
}

#[tokio::test]
async fn should_use_nio_server_channel_when_native_transport_disabled_on_linux() {
    boots_and_serves("false", "/nio-test", "nio-ok").await;
}

/// Upstream asserts the server is running and its DNS channel is an `EpollDatagramChannel`; here the DNS listener
/// is bound and answers a query (A for `example.com`, no expectations: NXDOMAIN, as `dns.rs` pins against the oracle).
#[tokio::test]
async fn should_boot_with_dns_enabled_and_native_transport() {
    let running = common::start(&[("useNativeTransport", "true"), ("dnsEnabled", "true"), ("dnsPort", "0")]).await;
    let dns_port = running.server.dns_port().expect("DNS listener bound");
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["example", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    let answer = tokio::task::spawn_blocking(move || {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        socket.send_to(&query, ("127.0.0.1", dns_port)).unwrap();
        let mut buf = vec![0u8; 65535];
        socket.recv(&mut buf).ok().map(|n| buf[..n].to_vec())
    })
    .await
    .unwrap()
    .expect("the DNS listener answers");
    assert_eq!(&answer[..2], &[0x12, 0x34], "answer carries the query id");
    assert_ne!(answer[2] & 0x80, 0, "QR flag set");
    assert_eq!(answer[3] & 0x0f, 3, "NXDOMAIN without a matching expectation");
    let health = common::send(running.port, "PUT", "/mockserver/status", "").await;
    assert_eq!(health.status, 200, "the HTTP listener serves alongside DNS");
}

//! Upstream tests that change `ConfigurationProperties` while the server runs: only a server in the test's
//! JVM sees such a change, so against a separate process they cannot run unmodified. Here the change is
//! [`mock_server::Server::set_property`], the embedding API's `ConfigurationProperties.<name>(value)`, and everything
//! else happens over the wire as upstream's test does it. Each outcome was first read off the oracle
//! (`mockserver/mockserver:8.0.0`) with the same property set over `PUT /mockserver/configuration`.
//!
//! - `CassetteRegistryEndpointIntegrationTest.shouldRejectUnauthenticatedCassetteRequestsWhenControlPlaneAuthenticationRequired`
//! - `MultiplePortMockingIntegrationTest.shouldReturnStatusOnCustomPath`
//! - `HttpProxyViaLoadBalanceIntegrationTest.shouldNotAttemptToProxyWhenNoExpectationMatched`
//! - `NettyHttpProxyIntegrationTest`'s three proxy-authentication methods
//! - `NettyHttpsProxyIntegrationTest`'s three `CONNECT` proxy-authentication methods

use std::io::{Read, Write};

use base64::Engine;
use serde_json::{Value, json};

use crate::common;

/// Raw bytes on their own connection, the answer read until the server closes it (or a quiet second).
async fn raw(port: u16, request: String) -> String {
    tokio::task::spawn_blocking(move || {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            match s.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    raw.extend_from_slice(&buffer[..n]);
                    // a complete head with no body, or a body of the announced length, ends the answer
                    let text = String::from_utf8_lossy(&raw);
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let length = head
                            .lines()
                            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                            .unwrap_or(0);
                        if body.len() >= length {
                            break;
                        }
                    }
                }
            }
        }
        String::from_utf8_lossy(&raw).into_owned()
    })
    .await
    .unwrap()
}

fn status(answer: &str) -> u16 {
    answer.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// `readHttpInputStreamToString`: the answer with its line ends as `\n`.
fn lines(answer: &str) -> String {
    answer.replace("\r\n", "\n")
}

/// The header `name` of a raw answer.
fn header<'a>(answer: &'a str, name: &str) -> Option<&'a str> {
    let head = answer.split("\r\n\r\n").next().unwrap_or_default();
    head.lines().skip(1).find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
}

// --- CassetteRegistryEndpointIntegrationTest ------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_unauthenticated_cassette_requests_when_control_plane_authentication_required() {
    let server = common::start(&[]).await;
    // given - control-plane authentication is required and the caller presents no credentials
    server.server.set_property("controlPlaneJWTAuthenticationRequired", "true");
    // then - every cassette verb is refused rather than served
    assert_eq!(common::send(server.port, "GET", "/mockserver/cassettes", "").await.status, 401);
    assert_eq!(common::send(server.port, "PUT", "/mockserver/cassettes", r#"{"path":"/c/should-not-store.json"}"#).await.status, 401);
    assert_eq!(common::send(server.port, "DELETE", "/mockserver/cassettes?path=/c/should-not-store.json", "").await.status, 401);
    server.server.set_property("controlPlaneJWTAuthenticationRequired", "false");
    // then - the refused PUT stored nothing
    let listed = common::send(server.port, "GET", "/mockserver/cassettes", "").await;
    assert_eq!(listed.status, 200, "{}", listed.body);
    let listed: Value = serde_json::from_str(&listed.body).unwrap();
    assert_eq!(listed["cassettes"].as_array().map(Vec::len), Some(0), "{listed}");
    server.server.shutdown().await;
}

// --- MultiplePortMockingIntegrationTest -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn should_return_status_on_custom_path() {
    // `startClientAndServer(0, free, 0, free)`: four listeners, the liveness answer lists every one of them
    crate::scratch_cwd::enter();
    let mut config = mock_server::Config::for_tests();
    config.ports = vec![0, 0, 0, 0];
    let server = mock_server::Server::start(config).await.expect("server starts");
    let ports = server.ports().to_vec();
    assert_eq!(ports.len(), 4);
    server.set_property("livenessHttpGetPath", "/livenessProbe");
    for transport in [common::Transport::Http, common::Transport::Https] {
        for port in &ports {
            let r = common::exchange(*port, transport, "GET", "/livenessProbe", &[], "").await;
            assert_eq!((r.status, r.reason.as_deref()), (200, Some("OK")), "{transport:?} on {port}: {}", r.text());
            assert_eq!(r.header("content-type"), Some("application/json; charset=utf-8"));
            let body: Value = serde_json::from_str(&r.text()).unwrap();
            assert_eq!(body["ports"], json!(ports), "{transport:?} on {port}");
        }
    }
    server.shutdown().await;
}

// --- HttpProxyViaLoadBalanceIntegrationTest -------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn should_not_attempt_to_proxy_when_no_expectation_matched() {
    let target = common::start(&[]).await;
    let load_balancer = common::start(&[]).await;
    load_balancer.server.set_property("attemptToProxyIfNoMatchingExpectation", "false");
    common::expect(target.port, &json!({"httpRequest": {"path": "/target"}, "httpResponse": {"body": "target_response"}})).await;
    // when - the request reaches the load balancer with the target's Host
    let answer = raw(load_balancer.port, format!("GET /target HTTP/1.1\r\nHost: localhost:{}\r\nContent-Length: 0\r\n\r\n", target.port)).await;
    // then - returns a 404
    assert_eq!(status(&answer), 404, "{answer}");
    load_balancer.server.shutdown().await;
    target.server.shutdown().await;
}

// --- NettyHttpProxyIntegrationTest ----------------------------------------------------------------------------------

/// A target the proxy reaches (upstream's `EchoServer`): a second server answering `/somePath`.
async fn echo_target() -> common::Running {
    let target = common::start(&[]).await;
    common::expect(target.port, &json!({"httpRequest": {"path": "/somePath"}, "httpResponse": {"body": "echo"}})).await;
    target
}

/// `GET http://localhost:<target>/somePath` through the proxy, with `Proxy-Authorization` when given.
async fn proxied_get(proxy: u16, target: u16, credentials: Option<(&str, &str)>) -> String {
    let authorization = credentials
        .map(|(user, password)| {
            let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
            format!("Proxy-Authorization: Basic {token}\r\n")
        })
        .unwrap_or_default();
    raw(proxy, format!("GET http://localhost:{target}/somePath HTTP/1.1\r\nHost: localhost:{target}\r\n{authorization}Content-Length: 0\r\n\r\n")).await
}

/// A proxy whose credentials were set after it started.
async fn authenticating_proxy(realm: Option<&str>) -> (common::Running, String, String) {
    let proxy = common::start(&[]).await;
    let (username, password) = (uuid::Uuid::new_v4().to_string(), uuid::Uuid::new_v4().to_string());
    proxy.server.set_property("proxyAuthenticationUsername", &username);
    proxy.server.set_property("proxyAuthenticationPassword", &password);
    if let Some(realm) = realm {
        proxy.server.set_property("proxyAuthenticationRealm", realm);
    }
    (proxy, username, password)
}

#[tokio::test(flavor = "multi_thread")]
async fn should_allow_authenticated_proxied_request_with_valid_credentials_for_valid_target() {
    let target = echo_target().await;
    let (proxy, username, password) = authenticating_proxy(None).await;
    // `HttpURLConnection` sends without credentials, is challenged, and asks the `Authenticator` once
    let challenged = proxied_get(proxy.port, target.port, None).await;
    assert_eq!(status(&challenged), 407, "{challenged}");
    let answer = proxied_get(proxy.port, target.port, Some((&username, &password))).await;
    assert_eq!(status(&answer), 200, "{answer}");
    assert!(answer.ends_with("echo"), "{answer}");
    proxy.server.shutdown().await;
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_prevent_unauthenticated_proxied_request_due_to_invalid_password() {
    let target = echo_target().await;
    let (proxy, username, _) = authenticating_proxy(None).await;
    let answer = proxied_get(proxy.port, target.port, Some((&username, &uuid::Uuid::new_v4().to_string()))).await;
    assert_eq!(header(&answer, "proxy-authenticate"), Some(r#"Basic realm="MockServer HTTP Proxy", charset="UTF-8""#), "{answer}");
    assert_eq!(status(&answer), 407, "{answer}");
    proxy.server.shutdown().await;
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_prevent_unauthenticated_proxied_request_due_to_no_authenticator() {
    let target = echo_target().await;
    let (proxy, _, _) = authenticating_proxy(None).await;
    let answer = proxied_get(proxy.port, target.port, None).await;
    assert_eq!(header(&answer, "proxy-authenticate"), Some(r#"Basic realm="MockServer HTTP Proxy", charset="UTF-8""#), "{answer}");
    assert_eq!(status(&answer), 407, "{answer}");
    proxy.server.shutdown().await;
    target.server.shutdown().await;
}

// --- NettyHttpsProxyIntegrationTest ---------------------------------------------------------------------------------

/// `CONNECT 127.0.0.1:443` with the secure target's `Host`, as upstream writes it on a plain socket.
async fn connect_request(proxy: u16, target: u16) -> String {
    lines(&raw(proxy, format!("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n")).await)
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_connect_to_secure_port_requiring_authentication_with_custom_realm() {
    let target = common::start(&[]).await;
    let (proxy, _, _) = authenticating_proxy(Some("Some other random \"realm\"")).await;
    let answer = connect_request(proxy.port, target.port).await;
    assert!(
        answer.contains("HTTP/1.1 407 Proxy Authentication Required\nproxy-authenticate: Basic realm=\"Some other random \\\"realm\\\"\", charset=\"UTF-8\""),
        "{answer}"
    );
    proxy.server.shutdown().await;
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_connect_to_secure_port_requiring_authentication_with_default_realm() {
    let target = common::start(&[]).await;
    let (proxy, _, _) = authenticating_proxy(None).await;
    let answer = connect_request(proxy.port, target.port).await;
    assert!(answer.contains("HTTP/1.1 407 Proxy Authentication Required\nproxy-authenticate: Basic realm=\"MockServer HTTP Proxy\", charset=\"UTF-8\""), "{answer}");
    proxy.server.shutdown().await;
    target.server.shutdown().await;
}

/// Upstream's `NettyHttpClient` with an HTTPS proxy configuration opens the tunnel with `CONNECT <target>` and fails
/// with the proxy's `407 Proxy Authentication Required`: the wire exchange is that `CONNECT`.
#[tokio::test(flavor = "multi_thread")]
async fn should_prevent_unauthenticated_connect_request_when_client_configured_with_proxy_configuration() {
    let target = common::start(&[]).await;
    let (proxy, _, _) = authenticating_proxy(None).await;
    let answer = raw(proxy.port, format!("CONNECT 127.0.0.1:{0} HTTP/1.1\r\nHost: 127.0.0.1:{0}\r\n\r\n", target.port)).await;
    assert!(answer.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"), "{answer}");
    proxy.server.shutdown().await;
    target.server.shutdown().await;
}

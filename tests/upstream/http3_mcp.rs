//! `Http3McpIntegrationTest`'s tests that install a control-plane authentication handler into the in-JVM server
//! (`HttpState.setControlPlaneAuthenticationHandler`): here `Server::set_control_plane_authenticator`, with MCP
//! reached over HTTP/3 as upstream's quiche client reaches it.

use std::sync::Arc;

use bytes::{Buf, Bytes};
use serde_json::Value;

use crate::common;

/// `Http3ResponseCapture`.
struct Captured {
    status: u16,
    headers: http::HeaderMap,
    body: String,
}

/// `startMockServer`: a free UDP port for `http3Port`.
async fn start(properties: &[(&str, &str)]) -> (common::Running, u16) {
    common::start_with_http3(properties).await
}

#[derive(Debug)]
pub(crate) struct TrustAll;

impl rustls::client::danger::ServerCertVerifier for TrustAll {
    fn verify_server_cert(
        &self,
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &[rustls_pki_types::CertificateDer<'_>],
        _: &rustls_pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &rustls_pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(&self, _: &[u8], _: &rustls_pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// `doSendHttp3Request`: one request on a fresh QUIC connection, trusting any certificate.
async fn send(port: u16, method: &str, path: &str, body: Option<&str>, headers: &[(&str, &str)]) -> Captured {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAll))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let connection = endpoint.connect(([127, 0, 0, 1], port).into(), "localhost").unwrap().await.unwrap();
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection)).await.unwrap();
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let mut request = http::Request::builder().method(method).uri(format!("https://localhost:{port}{path}"));
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut stream = sender.send_request(request.body(()).unwrap()).await.unwrap();
    if let Some(body) = body {
        stream.send_data(Bytes::from(body.to_string())).await.unwrap();
    }
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    let mut received = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let piece = chunk.chunk();
            received.extend_from_slice(piece);
            let n = piece.len();
            chunk.advance(n);
        }
    }
    drop(sender);
    drive.abort();
    endpoint.close(0u32.into(), b"");
    Captured { status: response.status().as_u16(), headers: response.headers().clone(), body: String::from_utf8_lossy(&received).into_owned() }
}

async fn send_mcp(port: u16, method: &str, body: Option<&str>, session: Option<&str>) -> Captured {
    let headers: Vec<(&str, &str)> = session.map(|s| ("mcp-session-id", s)).into_iter().collect();
    send(port, method, "/mockserver/mcp", body, &headers).await
}

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_unauthenticated_mcp_post_over_http3() {
    let (server, port) = start(&[]).await;
    server.server.set_control_plane_authenticator(|_| None);
    let result = send_mcp(port, "POST", Some(INITIALIZE), None).await;
    assert_eq!(result.status, 401, "should return 401 when auth fails");
    let json: Value = serde_json::from_str(&result.body).unwrap();
    assert!(json["error"]["message"].as_str().unwrap_or_default().contains("Unauthorized"), "should have error about unauthorized: {json}");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_unauthenticated_mcp_get_over_http3() {
    let (server, port) = start(&[]).await;
    server.server.set_control_plane_authenticator(|_| None);
    let result = send_mcp(port, "GET", None, None).await;
    assert_eq!(result.status, 401, "GET should return 401 when auth fails");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_unauthenticated_mcp_delete_over_http3() {
    let (server, port) = start(&[]).await;
    server.server.set_control_plane_authenticator(|_| None);
    let result = send_mcp(port, "DELETE", None, Some("some-session")).await;
    assert_eq!(result.status, 401, "DELETE should return 401 when auth fails");
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_mutating_tool_when_authorization_enabled_and_caller_lacks_mutate_role_over_http3() {
    let (server, port) = start(&[("controlPlaneAuthorizationEnabled", "true"), ("controlPlaneScopeMapping", "readers=read,mutators=mutate")]).await;
    server.server.set_control_plane_authenticator(|_| Some(vec!["readers".to_string()]));

    let initialized = send_mcp(port, "POST", Some(INITIALIZE), None).await;
    let session = initialized.headers.get("mcp-session-id").and_then(|v| v.to_str().ok()).expect("session id").to_string();
    send_mcp(port, "POST", Some(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#), Some(&session)).await;

    let call = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_expectation","arguments":{"method":"GET","path":"/h3-forbidden","statusCode":201}}}"#;
    let result = send_mcp(port, "POST", Some(call), Some(&session)).await;
    assert_eq!(result.status, 200, "status should be 200 (JSON-RPC error transport)");
    let json: Value = serde_json::from_str(&result.body).unwrap();
    assert!(json["error"]["message"].as_str().unwrap_or_default().contains("Forbidden for control plane"), "denied mutating tool returns the forbidden JSON-RPC error: {json}");
    assert!(json.get("result").is_none_or(Value::is_null), "denied tool call produces no result");

    // `firstMatchingExpectation` finds nothing: the request falls through to a 404.
    assert_eq!(common::send(server.port, "GET", "/h3-forbidden", "").await.status, 404, "the forbidden tool must not have mutated state");
    server.server.shutdown().await;
}

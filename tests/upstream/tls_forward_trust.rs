//! `forwardProxyTLSX509CertificatesTrustManagerType` (`ANY`, `JVM`, `CUSTOM`) and
//! `forwardProxyTLSHostnameVerificationEnabled` of the forwarding client (`NettySslContextFactory.createClientSslContext`),
//! against a foreign TLS target: a MockServer serving `tests/files/tls/foreign-leaf-cert.pem`, a self-signed certificate
//! for `foreign.example` and `localhost` that no root of the JVM, nor MockServer's own CA, vouches for.
//!
//! Each outcome was first read off the oracle (`mockserver/mockserver:8.0.0`) with a second container as the target on
//! a Docker network: `ANY` forwards to any certificate; `JVM` refuses the self-signed one; `CUSTOM` trusts it only when
//! `forwardProxyTLSCustomTrustX509Certificates` names it, and then still refuses a host the certificate does not name;
//! switching `forwardProxyTLSHostnameVerificationEnabled` off changes nothing (the oracle answered 502, "No subject
//! alternative DNS name matching other.example found", with it off).

use std::path::Path;
use std::sync::Arc;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::tls_runtime_reconfiguration::AnyCertificate;

use crate::common;

fn tls_file(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/tls").join(name).display().to_string()
}

/// A MockServer serving the foreign certificate (self-signed, so its own CA), answering `/target`.
async fn foreign_target() -> common::Running {
    let (cert, key) = (tls_file("foreign-leaf-cert.pem"), tls_file("foreign-leaf-key.pem"));
    let target = common::start(&[("x509CertificatePath", &cert), ("privateKeyPath", &key), ("certificateAuthorityCertificate", &cert)]).await;
    common::expect(target.port, &json!({"httpRequest": {"path": "/target"}, "httpResponse": {"body": "reached foreign"}})).await;
    target
}

/// The status a forward to `https://<host>:<target port>/target` answers on a server with `properties`.
async fn forward_status(properties: &[(&str, &str)], host: &str, target_port: u16) -> u16 {
    let forwarder = common::start(properties).await;
    common::expect(
        forwarder.port,
        &json!({
            "httpRequest": {"path": "/forward"},
            "httpOverrideForwardedRequest": {"requestOverride": {"path": "/target", "secure": true, "socketAddress": {"host": host, "port": target_port, "scheme": "HTTPS"}}}
        }),
    )
    .await;
    let status = common::send(forwarder.port, "GET", "/forward", "").await.status;
    forwarder.server.shutdown().await;
    status
}

#[tokio::test(flavor = "multi_thread")]
async fn any_trust_manager_forwards_to_a_foreign_certificate() {
    let target = foreign_target().await;
    assert_eq!(forward_status(&[], "localhost", target.port).await, 200);
    assert_eq!(forward_status(&[], "127.0.0.1", target.port).await, 200, "ANY does not check the host name either");
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn jvm_trust_manager_refuses_a_certificate_no_root_vouches_for() {
    let target = foreign_target().await;
    let jvm = [("forwardProxyTLSX509CertificatesTrustManagerType", "JVM")];
    assert_eq!(forward_status(&jvm, "localhost", target.port).await, 502);
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn jvm_trust_manager_trusts_mockservers_own_certificate_authority() {
    // MockServer's leaves are issued by the bundled CA, which `JVM` adds to the JVM's roots.
    let target = common::start(&[]).await;
    common::expect(target.port, &json!({"httpRequest": {"path": "/target"}, "httpResponse": {"body": "reached"}})).await;
    let jvm = [("forwardProxyTLSX509CertificatesTrustManagerType", "JVM")];
    assert_eq!(forward_status(&jvm, "localhost", target.port).await, 200);
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn custom_trust_manager_trusts_the_named_certificates_and_still_checks_the_host_name() {
    let target = foreign_target().await;
    let trusted = tls_file("foreign-leaf-cert.pem");
    let custom = [("forwardProxyTLSX509CertificatesTrustManagerType", "CUSTOM"), ("forwardProxyTLSCustomTrustX509Certificates", trusted.as_str())];
    assert_eq!(forward_status(&custom, "localhost", target.port).await, 200, "trusted and named by the certificate");
    assert_eq!(forward_status(&custom, "127.0.0.1", target.port).await, 502, "the certificate names no IP address");
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn custom_trust_manager_without_certificates_trusts_nothing_foreign() {
    let target = foreign_target().await;
    let custom = [("forwardProxyTLSX509CertificatesTrustManagerType", "CUSTOM")];
    assert_eq!(forward_status(&custom, "localhost", target.port).await, 502);
    target.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn host_name_verification_switch_does_not_relax_a_validating_trust_manager() {
    let target = foreign_target().await;
    let trusted = tls_file("foreign-leaf-cert.pem");
    let custom_unverified = [
        ("forwardProxyTLSX509CertificatesTrustManagerType", "CUSTOM"),
        ("forwardProxyTLSCustomTrustX509Certificates", trusted.as_str()),
        ("forwardProxyTLSHostnameVerificationEnabled", "false"),
    ];
    assert_eq!(forward_status(&custom_unverified, "127.0.0.1", target.port).await, 502);
    assert_eq!(forward_status(&custom_unverified, "localhost", target.port).await, 200);
    target.server.shutdown().await;
}

/// The status line of `GET /target` sent through `forwarder` as a proxy: `CONNECT localhost:<target port>`, then TLS
/// inside the tunnel (the relay opens its own TLS connection to the target, `RelayConnectHandler`). Oracle: the
/// CONNECT itself is answered 200 whatever the trust manager says; the failure shows on the first request.
async fn status_through_connect(forwarder_port: u16, target_port: u16) -> String {
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", forwarder_port)).await.unwrap();
    tcp.write_all(format!("CONNECT localhost:{target_port} HTTP/1.1\r\nHost: localhost:{target_port}\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = [0u8; 1024];
    let n = tcp.read(&mut head).await.unwrap();
    assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"), "CONNECT: {}", String::from_utf8_lossy(&head[..n]));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await.unwrap();
    tls.write_all(format!("GET /target HTTP/1.1\r\nHost: localhost:{target_port}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tls.read_to_end(&mut answer).await;
    String::from_utf8_lossy(&answer).lines().next().unwrap_or_default().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_relay_applies_the_trust_manager_to_its_upstream_tls_connection() {
    // Oracle (a foreign target `foreign.example`, the relay as a proxy): ANY reaches it (200), JVM answers 502 once
    // the tunnel is up, CUSTOM trusting the foreign certificate reaches it (200).
    let target = foreign_target().await;
    let any = common::start(&[]).await;
    assert_eq!(status_through_connect(any.port, target.port).await, "HTTP/1.1 200 OK");
    any.server.shutdown().await;
    let jvm = common::start(&[("forwardProxyTLSX509CertificatesTrustManagerType", "JVM")]).await;
    assert_eq!(status_through_connect(jvm.port, target.port).await, "HTTP/1.1 502 Bad Gateway");
    jvm.server.shutdown().await;
    let trusted = tls_file("foreign-leaf-cert.pem");
    let custom = common::start(&[("forwardProxyTLSX509CertificatesTrustManagerType", "CUSTOM"), ("forwardProxyTLSCustomTrustX509Certificates", trusted.as_str())]).await;
    assert_eq!(status_through_connect(custom.port, target.port).await, "HTTP/1.1 200 OK");
    custom.server.shutdown().await;
    target.server.shutdown().await;
}

//! `MutualAuthenticationRuntimeReconfigurationTest`, `NettySslContextFactoryTest`'s ALPN methods and
//! `NettySslContextFactoryGlobalStateTest`'s rotation method (mockserver-core): what a TLS handshake does after
//! `PUT /mockserver/configuration` changed an input of the server's SSL context. The oracle-scenario format has no
//! TLS client step, so these are ports against the embedding API; each outcome was first read off the oracle
//! (`mockserver/mockserver:8.0.0`) with `openssl s_client` and curl.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common;

#[derive(Debug)]
pub(crate) struct AnyCertificate(pub(crate) Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
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

    fn verify_tls12_signature(&self, m: &[u8], c: &rustls_pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, m: &[u8], c: &rustls_pki_types::CertificateDer<'_>, d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// What one HTTPS connection without a client certificate saw.
pub(crate) struct Outcome {
    /// The ALPN protocol the server selected.
    pub(crate) alpn: Option<Vec<u8>>,
    /// The first bytes of the HTTP/1.1 answer; empty when the server closed or aborted the connection.
    pub(crate) answer: String,
    /// The DER of the certificate the server presented.
    pub(crate) certificate: Vec<u8>,
}

/// Connects offering `alpn`, and (when the server selected HTTP/1.1) sends `PUT /mockserver/status`. TLS 1.3 reports
/// a refused client certificate only on the first read, so a refusal is an empty `answer` or no `Outcome`.
pub(crate) async fn connect(port: u16, alpn: &[&[u8]]) -> Option<Outcome> {
    connect_with(port, alpn, &[&rustls::version::TLS13, &rustls::version::TLS12]).await
}

/// [`connect`] offering only the given protocol versions.
async fn connect_with(port: u16, alpn: &[&[u8]], versions: &[&'static rustls::SupportedProtocolVersion]) -> Option<Outcome> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let mut stream = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await.ok()?;
    let (_, session) = stream.get_ref();
    let alpn = session.alpn_protocol().map(<[u8]>::to_vec);
    let certificate = session.peer_certificates().and_then(|c| c.first()).map(|c| c.as_ref().to_vec()).unwrap_or_default();
    let mut answer = String::new();
    if alpn.as_deref() != Some(b"h2") {
        let request = format!("PUT /mockserver/status HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _ = stream.write_all(request.as_bytes()).await;
        let mut raw = vec![0u8; 64];
        let n = stream.read(&mut raw).await.unwrap_or(0);
        answer = String::from_utf8_lossy(&raw[..n]).into_owned();
    }
    Some(Outcome { alpn, answer, certificate })
}

async fn configure(port: u16, json: &str) {
    let r = common::send(port, "PUT", "/mockserver/configuration", json).await;
    assert_eq!(r.status, 200, "{}", r.body);
}

#[tokio::test(flavor = "multi_thread")]
async fn alpn_follows_http2_enabled_changed_at_runtime() {
    // Oracle: h2 by default; after `{"http2Enabled": false}` an h2-capable client is answered `http/1.1`; back on, `h2`.
    let server = common::start(&[]).await;
    let offer: [&[u8]; 2] = [b"h2", b"http/1.1"];
    assert_eq!(connect(server.port, &offer).await.unwrap().alpn.as_deref(), Some(&b"h2"[..]));
    configure(server.port, r#"{"http2Enabled": false}"#).await;
    assert_eq!(connect(server.port, &offer).await.unwrap().alpn.as_deref(), Some(&b"http/1.1"[..]));
    configure(server.port, r#"{"http2Enabled": true}"#).await;
    assert_eq!(connect(server.port, &offer).await.unwrap().alpn.as_deref(), Some(&b"h2"[..]));
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mutual_authentication_enabled_at_runtime_refuses_a_client_without_a_certificate() {
    // Oracle: a plain HTTPS client is served; with `tlsMutualAuthenticationRequired` on it is refused; off again, served.
    // 9.1.0 refuses data-plane mTLS on the bundled CA without the opt-in (upstream cb3817ce3, which adds it to
    // `MutualAuthenticationRuntimeReconfigurationTest`'s configuration).
    let server = common::start(&[("tlsMutualAuthenticationAllowBundledCa", "true")]).await;
    let offer: [&[u8]; 1] = [b"http/1.1"];
    assert!(connect(server.port, &offer).await.unwrap().answer.starts_with("HTTP/1.1 200"));
    configure(server.port, r#"{"tlsMutualAuthenticationRequired": true}"#).await;
    let refused = connect(server.port, &offer).await;
    assert!(refused.is_none_or(|o| o.answer.is_empty()), "a client without a certificate must be refused");
    configure(server.port, r#"{"tlsMutualAuthenticationRequired": false}"#).await;
    assert!(connect(server.port, &offer).await.unwrap().answer.starts_with("HTTP/1.1 200"));
    server.server.shutdown().await;
}

/// `MutualAuthenticationRuntimeReconfigurationIntegrationTest.shouldRefuseCertificatelessClientAfterEnablingMutualAuthenticationAtRuntime`
/// (mockserver-netty): the server's `Configuration` object gets `tlsMutualAuthenticationRequired(true)` while it
/// listens ([`mock_server::Server::set_property`] here), and a certificateless client pinned to TLS 1.2 — where a
/// missing client certificate aborts the handshake itself — is refused at the handshake.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_certificateless_client_after_enabling_mutual_authentication_at_runtime() {
    // 9.1.0: `tlsMutualAuthenticationAllowBundledCa(true)`, as upstream's test now configures (cb3817ce3)
    let server = common::start(&[("tlsMutualAuthenticationAllowBundledCa", "true"), ("tlsMutualAuthenticationRequired", "false")]).await;
    let offer: [&[u8]; 1] = [b"http/1.1"];
    let tls12 = [&rustls::version::TLS12];
    let accepted = connect_with(server.port, &offer, &tls12).await.expect("a certificateless TLS 1.2 handshake succeeds while mTLS is off");
    assert!(accepted.answer.starts_with("HTTP/1.1 200"), "{}", accepted.answer);
    server.server.set_property("tlsMutualAuthenticationRequired", "true");
    let refused = connect_with(server.port, &offer, &tls12).await;
    assert!(refused.is_none(), "the TLS 1.2 handshake must fail once mTLS is required, got {:?}", refused.map(|o| o.answer));
    server.server.shutdown().await;
}

/// The DER of a fixture certificate.
fn x509_pem(name: &str) -> Vec<u8> {
    let (pem, _) = certificate(name);
    x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes()).next().unwrap().unwrap().contents
}

/// A fixed server certificate and its key: `fixed-ok` and `fixed-rotated` in `tests/files/tls`, RSA leaves for
/// `localhost` that MockServer's bundled CA signed. The oracle refuses a fixed pair whose key is not of the
/// signature's family (an EC key under an RSA-signed certificate), so these cannot be generated on the fly.
fn certificate(name: &str) -> (String, String) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/tls");
    (std::fs::read_to_string(dir.join(format!("{name}-cert.pem"))).unwrap(), std::fs::read_to_string(dir.join(format!("{name}-key.pem"))).unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn rotated_fixed_certificate_is_served_without_a_restart() {
    // `NettySslContextFactoryGlobalStateTest`: a fixed server certificate replaced on disk is served after the
    // 60 s re-check interval (oracle: unchanged right after the swap, replaced after 60 s). The re-check clock is the
    // renewal-clock seam, so the test advances it instead of waiting.
    let dir = std::env::temp_dir().join(format!("mock-server-rotation-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert_path, key_path) = (dir.join("server.pem"), dir.join("server.key"));
    let write = |name: &str| {
        let (cert, key) = certificate(name);
        std::fs::write(&cert_path, cert).unwrap();
        std::fs::write(&key_path, key).unwrap();
    };
    let common_name = |der: &[u8]| {
        let (_, cert) = x509_parser::parse_x509_certificate(der).unwrap();
        cert.raw_serial_as_string()
    };
    write("fixed-ok");
    let before = common_name(&x509_pem("fixed-ok"));
    write("fixed-rotated");
    let after = common_name(&x509_pem("fixed-rotated"));
    write("fixed-ok");
    let (cert, key) = (cert_path.display().to_string(), key_path.display().to_string());
    let server = common::start(&[("x509CertificatePath", &cert), ("privateKeyPath", &key), ("sslCertificateRenewalClockSeconds", "1000")]).await;
    let offer: [&[u8]; 1] = [b"http/1.1"];
    assert_eq!(common_name(&connect(server.port, &offer).await.unwrap().certificate), before);
    write("fixed-rotated");
    assert_eq!(common_name(&connect(server.port, &offer).await.unwrap().certificate), before, "inside the interval");
    server.server.set_property("sslCertificateRenewalClockSeconds", "1061");
    assert_eq!(common_name(&connect(server.port, &offer).await.unwrap().certificate), after);
    server.server.shutdown().await;
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_certificate_not_signed_by_the_ca_fails_every_handshake_but_not_plain_http() {
    // Oracle (`CertificateConfigurationValidator`): a fixed leaf that the configured CA did not sign ("Signature does
    // not match") leaves the server up on plain HTTP while every TLS handshake is closed without a certificate.
    let files = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/tls");
    let (cert, key) = (files.join("foreign-leaf-cert.pem").display().to_string(), files.join("foreign-leaf-key.pem").display().to_string());
    let server = common::start(&[("x509CertificatePath", &cert), ("privateKeyPath", &key)]).await;
    assert_eq!(common::send(server.port, "PUT", "/mockserver/status", "").await.status, 200);
    let offer: [&[u8]; 1] = [b"http/1.1"];
    assert!(connect(server.port, &offer).await.is_none(), "the handshake must fail");
    // Naming the CA that did sign it makes the pair valid, and a runtime change is picked up.
    server.server.set_property("certificateAuthorityCertificate", &files.join("foreign-leaf-cert.pem").display().to_string());
    assert!(connect(server.port, &offer).await.unwrap().answer.starts_with("HTTP/1.1 200"));
    server.server.shutdown().await;
}

fn issuer_and_names(der: &[u8]) -> (String, Vec<String>) {
    let (_, cert) = x509_parser::parse_x509_certificate(der).unwrap();
    let names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| san.value.general_names.iter().map(|n| n.to_string()).collect())
        .unwrap_or_default();
    (cert.issuer().to_string(), names)
}

#[tokio::test(flavor = "multi_thread")]
async fn certificate_authority_changed_at_runtime_signs_the_next_leaf() {
    // Oracle: `PUT /mockserver/configuration` with `certificateAuthorityCertificate` / `certificateAuthorityPrivateKey`
    // makes the next handshake serve a leaf issued by that CA; naming the bundled paths again restores the old issuer.
    // An RSA CA: the oracle signs every leaf `SHA256WithRSAEncryption`, so a CA with another key fails each leaf
    // (scenario `log_ca_form_ec_p256`).
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/x509/forward-trust");
    let (cert_path, key_path) = (dir.join("ca.pem"), dir.join("ca-key.pem"));
    let server = common::start(&[]).await;
    let offer: [&[u8]; 1] = [b"http/1.1"];
    assert!(issuer_and_names(&connect(server.port, &offer).await.unwrap().certificate).0.contains("www.mockserver.com"));
    configure(
        server.port,
        &format!(r#"{{"certificateAuthorityCertificate": "{}", "certificateAuthorityPrivateKey": "{}"}}"#, cert_path.display(), key_path.display()),
    )
    .await;
    assert!(issuer_and_names(&connect(server.port, &offer).await.unwrap().certificate).0.contains("forward upstream ca"));
    configure(
        server.port,
        r#"{"certificateAuthorityCertificate": "org/mockserver/socket/CertificateAuthorityCertificate.pem", "certificateAuthorityPrivateKey": "org/mockserver/socket/PKCS8CertificateAuthorityPrivateKey.pem"}"#,
    )
    .await;
    assert!(issuer_and_names(&connect(server.port, &offer).await.unwrap().certificate).0.contains("www.mockserver.com"));
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_protocols_changed_at_runtime_decide_which_versions_are_served() {
    // Oracle: `tlsProtocols=TLSv1.2` answers a TLS 1.3 only client with a protocol_version alert (and still serves
    // 1.2); `TLSv1.3` the other way round; restoring the default serves both.
    let server = common::start(&[]).await;
    let offer: [&[u8]; 1] = [b"http/1.1"];
    let v12: [&'static rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS12];
    let v13: [&'static rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];
    assert!(connect_with(server.port, &offer, &v13).await.is_some());
    configure(server.port, r#"{"tlsProtocols": "TLSv1.2"}"#).await;
    assert!(connect_with(server.port, &offer, &v13).await.is_none(), "TLS 1.3 must be refused");
    assert!(connect_with(server.port, &offer, &v12).await.unwrap().answer.starts_with("HTTP/1.1 200"));
    configure(server.port, r#"{"tlsProtocols": "TLSv1.3"}"#).await;
    assert!(connect_with(server.port, &offer, &v12).await.is_none(), "TLS 1.2 must be refused");
    assert!(connect_with(server.port, &offer, &v13).await.unwrap().answer.starts_with("HTTP/1.1 200"));
    configure(server.port, r#"{"tlsProtocols": "TLSv1.2,TLSv1.3"}"#).await;
    assert!(connect_with(server.port, &offer, &v12).await.is_some());
    assert!(connect_with(server.port, &offer, &v13).await.is_some());
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn subject_alternative_name_list_changed_at_runtime_reaches_the_next_leaf() {
    // Oracle: `sslSubjectAlternativeNameDomains=["probe.example"]` put at runtime adds `DNS:probe.example` to the
    // next leaf.
    let server = common::start(&[]).await;
    let offer: [&[u8]; 1] = [b"http/1.1"];
    assert!(!issuer_and_names(&connect(server.port, &offer).await.unwrap().certificate).1.iter().any(|n| n.contains("probe.example")));
    configure(server.port, r#"{"sslSubjectAlternativeNameDomains": ["probe.example"]}"#).await;
    assert!(issuer_and_names(&connect(server.port, &offer).await.unwrap().certificate).1.iter().any(|n| n.contains("probe.example")));
    server.server.shutdown().await;
}

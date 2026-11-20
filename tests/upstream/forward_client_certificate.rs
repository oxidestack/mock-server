//! Ports of `ForwardWithCustomClientCertificateIntegrationTest` and
//! `ForwardWithCustomClientCertificateByHostIntegrationTest`: a forward presents the configured client
//! certificate (`forwardProxyPrivateKey`/`forwardProxyCertificateChain`, or the per-host
//! `forwardProxyClientCertificatesByHost`) at the handshake; an upstream requiring client authentication that does not
//! trust it rejects the handshake, which the forward answers `502` saying why (`TLS with the upstream failed: `), as
//! the oracle does. Over TLS 1.3 the upstream's rejection arrives after the client's own handshake has finished, as
//! the alert in the first record the client reads.

use std::sync::Arc;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common;

const TLS: &str = "upstream/mockserver/mockserver/mockserver-netty/src/test/resources/org/mockserver/netty/integration/tls";

fn tls(name: &str) -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(TLS).join(name).display().to_string()
}

/// The JDK trust manager of `trustManager(<dir>leaf-cert, <dir>ca)`, as far as these certificates need it: the
/// client's leaf is accepted when it is the trusted leaf itself. webpki cannot build the path through `ca.pem`, whose
/// subject is UTF8String-encoded while the leaf names its issuer in PrintableString (the JDK compares names
/// canonically, webpki byte for byte). The certificate request names the trusted certificates' subjects.
#[derive(Debug)]
struct TrustedLeaf {
    leaf: rustls_pki_types::CertificateDer<'static>,
    subjects: Vec<rustls::DistinguishedName>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::server::danger::ClientCertVerifier for TrustedLeaf {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &self.subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        match end_entity.as_ref() == self.leaf.as_ref() {
            true => Ok(rustls::server::danger::ClientCertVerified::assertion()),
            false => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// `new EchoServer(SslContextBuilder.forServer(<dir>leaf-key, <dir>leaf-cert, <dir>ca).trustManager(<dir>leaf-cert,
/// <dir>ca).clientAuth(REQUIRE))`: a TLS upstream requiring the client certificate of `dir` (`""` or
/// `"separateca/"`), echoing the request's `x-test` header and body.
async fn echo_requiring_client_certificate(dir: &str) -> u16 {
    use rustls_pki_types::pem::PemObject;
    let pem = |name: &str| rustls_pki_types::CertificateDer::pem_file_iter(tls(&format!("{dir}{name}"))).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(tls(&format!("{dir}leaf-key-pkcs8.pem"))).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let subject = |cert: &rustls_pki_types::CertificateDer<'_>| {
        let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
        rustls::DistinguishedName::from(parsed.subject().as_raw().to_vec())
    };
    let (leaf, ca) = (pem("leaf-cert.pem").remove(0), pem("ca.pem").remove(0));
    let verifier = Arc::new(TrustedLeaf { subjects: vec![subject(&leaf), subject(&ca)], leaf: leaf.clone(), provider: provider.clone() });
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![leaf, ca], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let mut raw = Vec::new();
                let mut buf = [0u8; 65536];
                let (head, body) = loop {
                    let Ok(n) = tls.read(&mut buf).await else { return };
                    if n == 0 {
                        return;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&raw).into_owned();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let length = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap()));
                        if body.len() >= length.unwrap_or(0) {
                            break (head.to_string(), body.to_string());
                        }
                    }
                };
                let x_test = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("x-test:").map(|v| v.trim().to_string())).unwrap_or_default();
                let answer = format!("HTTP/1.1 200 OK\r\nx-test: {x_test}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                let _ = tls.write_all(answer.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

async fn forward(server: u16, path: &str, host: &str, port: u16) {
    let expectation = json!({"httpRequest": {"path": path}, "httpForward": {"host": host, "port": port, "scheme": "HTTPS"}});
    common::expect(server, &expectation).await;
}

/// `POST <path>` over TLS (`withSecure(true)`) with `x-test: test_headers_and_body` and body
/// `an_example_body_http`: the status, the `x-test` header and the body.
async fn post(server: u16, path: &str) -> (u16, Option<String>, String) {
    let headers = [("x-test", "test_headers_and_body")];
    let r = common::exchange(server, common::Transport::Https, "POST", path, &headers, "an_example_body_http").await;
    (r.status, r.header("x-test").map(str::to_string), r.text())
}

fn assert_accepted((status, x_test, body): (u16, Option<String>, String)) {
    assert_eq!((status, x_test.as_deref(), body.as_str()), (200, Some("test_headers_and_body"), "an_example_body_http"));
}

fn assert_rejected((status, _, body): (u16, Option<String>, String)) {
    assert_eq!(status, 502, "{body}");
    assert!(body.starts_with("TLS with the upstream failed: "), "{body:?}");
}

/// `shouldForwardWithCustomClientAuthenticationCertificate`.
#[tokio::test(flavor = "multi_thread")]
async fn forward_presents_the_configured_client_certificate() {
    let (trust_custom, trust_none) = (echo_requiring_client_certificate("").await, echo_requiring_client_certificate("separateca/").await);
    let (key, chain) = (tls("leaf-key-pkcs8.pem"), tls("leaf-cert-chain.pem"));
    let server = common::start(&[("forwardProxyPrivateKey", key.as_str()), ("forwardProxyCertificateChain", chain.as_str())]).await;
    forward(server.port, "/trustNone", "127.0.0.1", trust_none).await;
    forward(server.port, "/trustCustom", "127.0.0.1", trust_custom).await;
    assert_rejected(post(server.port, "/trustNone").await);
    assert_accepted(post(server.port, "/trustCustom").await);
    server.server.shutdown().await;
}

/// `shouldPresentPerHostClientCertificateAtHandshake`: the certificate is chosen by the forward's host, whatever the
/// port.
#[tokio::test(flavor = "multi_thread")]
async fn forward_presents_the_client_certificate_configured_for_its_host() {
    client_certificate_by_host().await;
}

/// The worker stack the forward path must fit in: half of tokio's default 2 MiB, so a debug build keeps
/// at least 1 MiB spare on the deepest forward the suite knows, an inbound TLS connection forwarding over TLS with a
/// per-host client certificate parsed at the handshake. A stack overflow aborts the whole test binary.
const FORWARD_STACK_BUDGET: usize = 1024 * 1024;

/// The per-host case on workers of [`FORWARD_STACK_BUDGET`]. `MOCK_SERVER_PROBE_STACK=<bytes>` runs it on another
/// size instead, to measure the path's peak by bisection (the smallest size that does not overflow).
#[test]
fn forward_with_a_client_certificate_fits_in_half_a_worker_stack() {
    let size = std::env::var("MOCK_SERVER_PROBE_STACK").ok().and_then(|v| v.parse().ok()).unwrap_or(FORWARD_STACK_BUDGET);
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_stack_size(size).enable_all().build().unwrap();
    runtime.block_on(client_certificate_by_host());
}

async fn client_certificate_by_host() {
    let (server_a, server_b) = (echo_requiring_client_certificate("").await, echo_requiring_client_certificate("separateca/").await);
    let by_host = format!(
        "localhost={};{},127.0.0.1={};{}",
        tls("leaf-cert-chain.pem"),
        tls("leaf-key-pkcs8.pem"),
        tls("separateca/leaf-cert-chain.pem"),
        tls("separateca/leaf-key-pkcs8.pem")
    );
    let server = common::start(&[("forwardProxyClientCertificatesByHost", by_host.as_str())]).await;
    forward(server.port, "/certA_to_serverA", "localhost", server_a).await;
    forward(server.port, "/certB_to_serverB", "127.0.0.1", server_b).await;
    forward(server.port, "/certA_to_serverB", "localhost", server_b).await;
    forward(server.port, "/certB_to_serverA", "127.0.0.1", server_a).await;
    assert_accepted(post(server.port, "/certA_to_serverA").await);
    assert_accepted(post(server.port, "/certB_to_serverB").await);
    assert_rejected(post(server.port, "/certA_to_serverB").await);
    assert_rejected(post(server.port, "/certB_to_serverA").await);
    server.server.shutdown().await;
}

//! `CertificateConfigurationValidator` (mockserver-core) over a fixed server certificate (`privateKeyPath` +
//! `x509CertificatePath`): which configurations the server refuses (every TLS handshake is closed while plain HTTP
//! keeps answering) and which it serves. The oracle-scenario format has no TLS client step, so these are ports against
//! the embedding API; each outcome was read off the oracle (`mockserver/mockserver:8.0.0`), one container per case with
//! the properties as `-Dmockserver.*`, handshaking four times after the start (the first handshake of a fresh
//! oracle is sometimes closed whatever the configuration, so the first one is not evidence).
//!
//! The fixtures in `tests/files/tls` are signed by MockServer's bundled CA, which is what `certificateAuthorityCertificate`
//! names by default: `fixed-ok` (RSA, `serverAuth`), `fixed-expired`, `fixed-future` (valid from year 2108),
//! `fixed-clientauth-only` (extended key usage `clientAuth` alone), `fixed-ec` (an EC key under an RSA signature).
//!
//! Oracle findings the port pins:
//! - refused: an expired or not-yet-valid certificate, a key that is not the certificate's, a key or a certificate
//!   path alone, an unreadable or non-PEM key or certificate, a certificate authority certificate path that is
//!   missing or blank, and a missing certificate authority private key file;
//! - served: a blank `certificateAuthorityPrivateKey` (the validator skips it), and a certificate whose extended key
//!   usage leaves out `serverAuth`, which earns a WARN log entry;
//! - an EC key under an RSA-signed certificate is refused on the 8.0.0 oracle too (the key is proven with the
//!   certificate's signature algorithm, the issuer's: "Supplied key ... is not a RSAPrivateKey instance"); we serve it,
//!   adopting upstream 5853377b1 (`docs/divergences.md`), whose `CertificateConfigurationValidatorKeyMatchTest` is
//!   ported at the end of this file;
//! - every refused handshake logs a WARN "SSL or decoder fault caught by port unification handler -> closing pipeline
//!   [id: 0x…, L:/… - R:/…] (SNI: localhost)" (the number of entries per handshake varies from one to three, and
//!   nothing is logged at startup); the entry's throwable, the exception chain under the validator's verdict, is
//!   compared with the oracle's by the scenarios `tls_fixed_certificate_refused_*`.

use std::path::Path;

use super::tls_runtime_reconfiguration::connect;
use crate::common;

fn tls_file(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/tls").join(name).display().to_string()
}

/// Whether a TLS handshake against a server with `properties` completes, and its log.
async fn served(properties: &[(&str, &str)]) -> (bool, String) {
    let server = common::start(properties).await;
    assert_eq!(common::send(server.port, "PUT", "/mockserver/status", "").await.status, 200, "plain HTTP stays up");
    let offer: [&[u8]; 1] = [b"http/1.1"];
    let mut handshakes = Vec::new();
    for _ in 0..3 {
        handshakes.push(connect(server.port, &offer).await.is_some_and(|o| o.answer.starts_with("HTTP/1.1 200")));
    }
    assert!(handshakes.iter().all(|h| *h == handshakes[0]), "the outcome is the same for every handshake: {handshakes:?}");
    let logs = common::logs(server.port).await;
    server.server.shutdown().await;
    (handshakes[0], logs)
}

fn pair(name: &str) -> [(String, String); 2] {
    [("privateKeyPath".into(), tls_file(&format!("{name}-key.pem"))), ("x509CertificatePath".into(), tls_file(&format!("{name}-cert.pem")))]
}

async fn served_with(name: &str, more: &[(&str, &str)]) -> (bool, String) {
    let pair = pair(name);
    let mut properties: Vec<(&str, &str)> = pair.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    properties.extend_from_slice(more);
    served(&properties).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_valid_fixed_certificate_is_served() {
    let (ok, logs) = served_with("fixed-ok", &[]).await;
    assert!(ok);
    assert!(!logs.contains("SSL or decoder fault"), "{logs}");
    assert!(!logs.contains("serverAuth"), "{logs}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_or_not_yet_valid_certificate_is_refused() {
    assert!(!served_with("fixed-expired", &[]).await.0);
    assert!(!served_with("fixed-future", &[]).await.0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_that_is_not_the_certificates_is_refused() {
    let (cert, key) = (tls_file("fixed-ok-cert.pem"), tls_file("foreign-leaf-key.pem"));
    assert!(!served(&[("privateKeyPath", &key), ("x509CertificatePath", &cert)]).await.0);
}

/// Refused by the 8.0.0 oracle, served since upstream 5853377b1 (adopted): the key's own type decides, not the CA's.
#[tokio::test(flavor = "multi_thread")]
async fn an_ec_key_under_an_rsa_signed_certificate_is_served() {
    let (ok, logs) = served_with("fixed-ec", &[]).await;
    assert!(ok);
    assert!(!logs.contains("SSL or decoder fault"), "{logs}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_or_a_certificate_path_alone_is_refused() {
    assert!(!served(&[("privateKeyPath", &tls_file("fixed-ok-key.pem"))]).await.0);
    assert!(!served(&[("x509CertificatePath", &tls_file("fixed-ok-cert.pem"))]).await.0);
}

#[tokio::test(flavor = "multi_thread")]
async fn unreadable_or_non_pem_files_are_refused() {
    let (cert, key) = (tls_file("fixed-ok-cert.pem"), tls_file("fixed-ok-key.pem"));
    assert!(!served(&[("privateKeyPath", &cert), ("x509CertificatePath", &cert)]).await.0, "a certificate as the key");
    assert!(!served(&[("privateKeyPath", &key), ("x509CertificatePath", &key)]).await.0, "a key as the certificate");
    assert!(!served(&[("privateKeyPath", "/nonexistent/key.pem"), ("x509CertificatePath", "/nonexistent/cert.pem")]).await.0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_or_blank_certificate_authority_is_refused_but_a_blank_authority_key_is_not() {
    assert!(!served_with("fixed-ok", &[("certificateAuthorityCertificate", "/nonexistent/ca.pem")]).await.0);
    assert!(!served_with("fixed-ok", &[("certificateAuthorityCertificate", "")]).await.0, "blank names the working directory");
    assert!(!served_with("fixed-ok", &[("certificateAuthorityPrivateKey", "/nonexistent/cakey.pem")]).await.0);
    assert!(served_with("fixed-ok", &[("certificateAuthorityPrivateKey", "")]).await.0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_without_the_server_auth_usage_is_served_with_a_warning() {
    let (ok, logs) = served_with("fixed-clientauth-only", &[]).await;
    assert!(ok);
    let path = tls_file("fixed-clientauth-only-cert.pem");
    assert!(
        logs.contains(&format!("The certificate at '{path}' does not include the 'serverAuth' Extended Key Usage extension. Some strict TLS clients may reject it.")),
        "{logs}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_handshake_is_logged_as_an_ssl_or_decoder_fault() {
    let (ok, logs) = served_with("fixed-expired", &[]).await;
    assert!(!ok);
    assert!(logs.contains("SSL or decoder fault caught by port unification handler -> closing pipeline [id: 0x"), "{logs}");
    assert!(logs.contains(" (SNI: localhost)"), "{logs}");
}

// ---------------------------------------------------------------------------------------------------------------
// CertificateConfigurationValidatorKeyMatchTest (upstream 5853377b1, mockserver-core, after 8.0.0; adopted)
// ---------------------------------------------------------------------------------------------------------------
// The subject key type and the issuer key type are independent: every combination validates when the key is the
// certificate's, and every combination is still refused, as a mismatch, when an impostor key of the same type is
// configured. Upstream drives the validator directly and asserts the mismatch text; here the outcome is the server's
// (a handshake served or closed), and the in-process log carries only the SSL fault, so the mismatch text stays with
// the process scenario `certcfg_mismatched_key_and_cert_fails`. Red before the fix: exactly the three cross-type
// positive rows, as upstream reports. RSA keys come from the fixtures (ring cannot generate them).

/// A key pair of `algorithm` ("RSA" from the fixture `rsa_fixture`, "EC" P-256 or "Ed25519" freshly generated).
fn key_pair(algorithm: &str, rsa_fixture: &str) -> rcgen::KeyPair {
    match algorithm {
        "RSA" => {
            use rustls_pki_types::pem::PemObject;
            let pem = std::fs::read_to_string(tls_file(rsa_fixture)).unwrap();
            let der = rustls_pki_types::PrivatePkcs8KeyDer::from_pem_slice(pem.as_bytes()).unwrap();
            rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&der, &rcgen::PKCS_RSA_SHA256).unwrap()
        }
        "EC" => rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap(),
        "Ed25519" => rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap(),
        other => panic!("unhandled key algorithm {other}"),
    }
}

/// Writes `key.pem` (the configured private key), `cert.pem` (a `localhost` leaf for `subject`, signed by a CA whose
/// key is `issuer`) and `ca.pem` under a fresh directory, and returns the three properties naming them.
fn write_pair(case: &str, configured: &rcgen::KeyPair, subject: &rcgen::KeyPair, issuer: rcgen::KeyPair) -> Vec<(String, String)> {
    let dir = std::env::temp_dir().join(format!("mock-server-key-match-{case}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.distinguished_name.push(rcgen::DnType::CommonName, "Issuer");
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca.self_signed(&issuer).unwrap();
    let mut leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    leaf.distinguished_name.push(rcgen::DnType::CommonName, "Leaf");
    let leaf_cert = leaf.signed_by(subject, &rcgen::Issuer::new(ca, issuer)).unwrap();
    let write = |name: &str, pem: String| {
        let path = dir.join(name);
        std::fs::write(&path, pem).unwrap();
        path.display().to_string()
    };
    vec![
        ("privateKeyPath".into(), write("key.pem", configured.serialize_pem())),
        ("x509CertificatePath".into(), write("cert.pem", leaf_cert.pem())),
        ("certificateAuthorityCertificate".into(), write("ca.pem", ca_cert.pem())),
    ]
}

/// `shouldPassWhenKeyMatchesCertificate` and `shouldRejectWhenKeyDoesNotMatchCertificate` for one row of the matrix.
async fn key_match_row(subject_algorithm: &str, issuer_algorithm: &str) {
    let case = format!("{subject_algorithm}-{issuer_algorithm}");
    let subject = key_pair(subject_algorithm, "fixed-ok-key.pem");
    let impostor = key_pair(subject_algorithm, "foreign-leaf-key.pem");
    let issuer = || key_pair(issuer_algorithm, "fwd-client-key.pem");

    let properties = write_pair(&format!("{case}-match"), &subject, &subject, issuer());
    let properties: Vec<(&str, &str)> = properties.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (ok, logs) = served(&properties).await;
    assert!(ok, "subject {subject_algorithm} key, certificate issued by {issuer_algorithm} CA: served\n{logs}");

    let properties = write_pair(&format!("{case}-impostor"), &impostor, &subject, issuer());
    let properties: Vec<(&str, &str)> = properties.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (ok, logs) = served(&properties).await;
    assert!(!ok, "subject {subject_algorithm} key, certificate issued by {issuer_algorithm} CA, impostor key: refused");
    assert!(logs.contains("SSL or decoder fault caught by port unification handler"), "{logs}");
}

/// The reported bug (#2728): an RSA leaf under an EC CA reports `SHA256withECDSA`.
#[tokio::test(flavor = "multi_thread")]
async fn key_match_rsa_subject_under_an_ec_issuer() {
    key_match_row("RSA", "EC").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn key_match_rsa_subject_under_an_rsa_issuer() {
    key_match_row("RSA", "RSA").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn key_match_ec_subject_under_an_rsa_issuer() {
    key_match_row("EC", "RSA").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn key_match_ec_subject_under_an_ec_issuer() {
    key_match_row("EC", "EC").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn key_match_ed25519_subject_under_an_ec_issuer() {
    key_match_row("Ed25519", "EC").await;
}

//! `BCKeyAndCertificateFactoryBehaviourTest`, `BCKeyAndCertificateFactoryTest`,
//! `BCKeyAndCertificateFactoryCanonicalMonitorTest`, `BCKeyAndCertificateFactoryConcurrentCaGenerationTest`,
//! `CertificateHardeningResilienceTest`'s leaf-validity-clamp methods (mockserver-core): the *content* of the
//! certificate our TLS listener serves — SAN, serial, validity, chain, key usage — inspected over a real TLS
//! connection to an in-process `mock_server::Server`. The oracle-scenario JSON format has no step type that can
//! look inside a served certificate (it only ever compares the wire bytes exchanged), so this is a Rust port
//! against the embedding API instead (reachable, no oracle-scenario equivalent).

use std::net::IpAddr;
use std::sync::Arc;

use num_bigint::BigUint;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::*;

use crate::common;

/// A directory under the OS temp dir, unique per test, removed on drop. `directoryToSaveDynamicSSLCertificate`
/// needs a fresh (or at least server-writable) directory per test so servers in different tests never share a
/// dynamically generated CA.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn fresh() -> Self {
        TempDir(std::env::temp_dir().join(format!("mock-server-tls-content-{}", uuid::Uuid::new_v4())))
    }

    fn as_str(&self) -> String {
        self.0.display().to_string()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A server with a fresh dynamic Certificate Authority directory, plus any `extra` properties.
async fn start_dynamic_ca(extra: &[(&str, &str)]) -> (common::Running, TempDir) {
    let dir = TempDir::fresh();
    let dir_str = dir.as_str();
    let mut properties: Vec<(&str, &str)> =
        vec![("dynamicallyCreateCertificateAuthorityCertificate", "true"), ("directoryToSaveDynamicSSLCertificate", dir_str.as_str())];
    properties.extend_from_slice(extra);
    let server = common::start(&properties).await;
    (server, dir)
}

/// Trusts any server certificate: the point of these tests is to inspect the certificate's *content*, not to
/// exercise a client's validation of it.
#[derive(Debug)]
struct TrustAll;

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

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// One TLS handshake to `port` with SNI `sni`: the certificate chain the server presents, leaf first, as DER.
async fn served_chain(port: u16, sni: &str) -> Vec<Vec<u8>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(TrustAll))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let name = rustls_pki_types::ServerName::try_from(sni.to_string()).unwrap();
    let stream = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await.unwrap();
    stream.get_ref().1.peer_certificates().expect("server presents a certificate chain").iter().map(|c| c.as_ref().to_vec()).collect()
}

/// A raw `CONNECT` (as a forward proxy would receive it), which drives `Tls::add_subject_alternative_name` the
/// same way `src/http1.rs`'s CONNECT handling does; the connection is dropped as soon as the `200` is seen, since
/// these tests only care about the SAN side effect, not the tunnel that would follow.
async fn connect(port: u16, target: &str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head);
    assert!(text.starts_with("HTTP/1.1 200"), "CONNECT {target}: {text}");
}

/// A plain (non-TLS) HTTP/1.1 request carrying `host` as its `Host` header, driving
/// `Tls::add_subject_alternative_name` the same way `src/handler.rs::serve` does for every exchange
/// (`HttpRequestHandler.channelRead0`). The response (whatever it is — no expectation is registered) is drained
/// and discarded; only the SAN side effect is under test.
async fn plain_request(port: u16, host: &str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(format!("GET /no-such-path HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
}

fn parse(der: &[u8]) -> X509Certificate<'_> {
    X509Certificate::from_der(der).unwrap().1
}

fn dns_sans(cert: &X509Certificate) -> Vec<String> {
    cert.subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| ext.value.general_names.iter().filter_map(|n| if let GeneralName::DNSName(s) = n { Some(s.to_ascii_lowercase()) } else { None }).collect())
        .unwrap_or_default()
}

fn ip_sans(cert: &X509Certificate) -> Vec<IpAddr> {
    cert.subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::IPAddress(bytes) => match <[u8; 4]>::try_from(*bytes) {
                        Ok(v4) => Some(IpAddr::from(v4)),
                        Err(_) => <[u8; 16]>::try_from(*bytes).ok().map(IpAddr::from),
                    },
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `notBefore`/`notAfter` as whole days apart, rounded — `checkValidity` window comparisons in the upstream tests.
fn validity_window_days(cert: &X509Certificate) -> f64 {
    (cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp()) as f64 / 86400.0
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

// --- chain, DN, self-signed CA ---

/// `BCKeyAndCertificateFactoryBehaviourTest.shouldGenerateLeafCertSignedByCertificateAuthority` and the
/// "chain assembly without CA duplication" cases.
#[tokio::test]
async fn leaf_is_signed_by_the_certificate_authority_and_the_chain_has_no_duplication() {
    let (server, _dir) = start_dynamic_ca(&[]).await;
    let chain = served_chain(server.port, "localhost").await;
    assert_eq!(chain.len(), 2, "leaf + CA, no duplication");
    let (leaf, ca) = (parse(&chain[0]), parse(&chain[1]));

    assert_eq!(leaf.issuer().as_raw(), ca.subject().as_raw(), "leaf is issued by the CA");
    assert!(leaf.verify_signature(Some(ca.public_key())).is_ok(), "leaf's signature verifies against the CA's public key");
}

/// `BCKeyAndCertificateFactoryBehaviourTest`'s self-signed-CA and subject/issuer-DN cases.
#[tokio::test]
async fn certificate_authority_is_self_signed_with_the_root_common_name() {
    let (server, _dir) = start_dynamic_ca(&[]).await;
    let chain = served_chain(server.port, "localhost").await;
    let ca = parse(&chain[1]);

    assert_eq!(ca.subject().as_raw(), ca.issuer().as_raw(), "the CA is self-signed: subject == issuer");
    assert!(ca.verify_signature(None).is_ok(), "the CA's signature verifies against its own public key");
    let cn = ca.subject().iter_common_name().next().and_then(|a| a.as_str().ok()).unwrap_or_default();
    assert_eq!(cn, "www.mockserver.com", "CA common name");
    assert!(ca.is_ca(), "basicConstraints CA:TRUE");
}

/// The leaf's subject: `CN=<sslCertificateDomainName, default localhost>, O=MockServer, L=London, ST=England, C=UK`.
#[tokio::test]
async fn leaf_subject_uses_the_documented_organisation_and_domain_name() {
    let (server, _dir) = start_dynamic_ca(&[("sslCertificateDomainName", "custom.example.test")]).await;
    let chain = served_chain(server.port, "custom.example.test").await;
    let leaf = parse(&chain[0]);

    assert_eq!(leaf.subject().iter_common_name().next().and_then(|a| a.as_str().ok()), Some("custom.example.test"));
    assert_eq!(leaf.subject().iter_organization().next().and_then(|a| a.as_str().ok()), Some("MockServer"));
    assert!(!leaf.is_ca(), "the leaf is not itself a CA");
}

// --- SAN: defaults, IPv4/IPv6/mixed, growth via CONNECT ---

/// `BCKeyAndCertificateFactoryBehaviourTest`'s "SAN domains/IPv4" default case.
#[tokio::test]
async fn default_subject_alternative_names_include_localhost_and_the_loopback_addresses() {
    let (server, _dir) = start_dynamic_ca(&[]).await;
    let chain = served_chain(server.port, "localhost").await;
    let leaf = parse(&chain[0]);

    assert!(dns_sans(&leaf).contains(&"localhost".to_string()), "dns SANs: {:?}", dns_sans(&leaf));
    let ips = ip_sans(&leaf);
    assert!(ips.contains(&"127.0.0.1".parse().unwrap()), "ip SANs: {ips:?}");
    assert!(ips.contains(&"0.0.0.0".parse().unwrap()), "ip SANs: {ips:?}");
}

/// `BCKeyAndCertificateFactoryBehaviourTest`'s "SAN … IPv6 and mixed" case, corrected against the live oracle:
/// a CONNECT target grows the persistent SAN set (`Tls::add_subject_alternative_name`, driven from
/// `src/http1.rs`'s CONNECT handling) for a new domain. An *unbracketed* IPv6 literal is a different story —
/// upstream's `Configuration.addSubjectAlternativeName` re-strips a port with a naive "text before the first
/// colon" split on top of the bracket/port-stripping `HttpRequest.splitHostPort` already did, which mangles an
/// IPv6 literal (still full of colons) down to its first hextet and adds THAT as a bogus *domain* SAN — verified
/// directly against `mockserver/mockserver:8.0.0`: `CONNECT [2001:db8::42]:443` adds `DNS:2001`, never an IPv6 SAN.
/// (The original version of this test asserted the IPv6 literal WAS added as an IP SAN —
/// that was never checked against the oracle and is wrong; it was corrected after confirming the true
/// behaviour with a raw CONNECT over `nc` against the oracle container.)
#[tokio::test]
async fn subject_alternative_names_grow_with_connect_targets_including_a_domain_and_an_ipv6_literal() {
    let (server, _dir) = start_dynamic_ca(&[]).await;
    connect(server.port, "grown.san.test:443").await;
    connect(server.port, "[2001:db8::42]:443").await;

    let chain = served_chain(server.port, "localhost").await;
    let leaf = parse(&chain[0]);
    assert!(dns_sans(&leaf).contains(&"grown.san.test".to_string()), "dns SANs: {:?}", dns_sans(&leaf));
    let dns = dns_sans(&leaf);
    assert!(dns.contains(&"2001".to_string()), "dns SANs (mangled IPv6 literal): {dns:?}");
    let ips = ip_sans(&leaf);
    assert!(!ips.contains(&"2001:db8::42".parse().unwrap()), "ip SANs must NOT contain the IPv6 literal: {ips:?}");
}

// --- serial numbers ---

/// `BCKeyAndCertificateFactoryTest.shouldCreateLeafCertWithPositiveSerialNumber` /
/// `shouldCreateCACertWithPositiveSerialNumber` (RFC 5280 §4.1.2.2).
#[tokio::test]
async fn leaf_and_certificate_authority_serial_numbers_are_positive() {
    let (server, _dir) = start_dynamic_ca(&[]).await;
    let chain = served_chain(server.port, "localhost").await;
    let (leaf, ca) = (parse(&chain[0]), parse(&chain[1]));

    assert!(leaf.tbs_certificate.serial > BigUint::from(0u32), "leaf serial must be positive");
    assert!(ca.tbs_certificate.serial > BigUint::from(0u32), "CA serial must be positive");
    // `KeyAndCertificateFactory.positiveSerialNumber`: `new BigInteger(64, new SecureRandom())`
    assert!(leaf.tbs_certificate.serial.bits() <= 64, "leaf serial must be a 64-bit number");
    assert!(ca.tbs_certificate.serial.bits() <= 64, "CA serial must be a 64-bit number");
}

// --- key usage / extended key usage ---

/// `BCKeyAndCertificateFactoryTest.shouldSetCriticalTlsServerKeyUsageOnLeaf`.
#[tokio::test]
async fn leaf_key_usage_is_critical_and_asserts_digital_signature_and_key_encipherment() {
    let (server, _dir) = start_dynamic_ca(&[]).await;
    let chain = served_chain(server.port, "localhost").await;
    let leaf = parse(&chain[0]);

    let ku = leaf.key_usage().unwrap().expect("leaf declares a keyUsage extension");
    assert!(ku.critical, "keyUsage must be critical");
    assert!(ku.value.digital_signature());
    assert!(ku.value.key_encipherment());
}

/// `BCKeyAndCertificateFactoryTest.shouldSetServerAuthAndClientAuthExtendedKeyUsageOnLeaf`.
#[tokio::test]
async fn leaf_extended_key_usage_asserts_server_auth_and_client_auth() {
    let (server, _dir) = start_dynamic_ca(&[]).await;
    let chain = served_chain(server.port, "localhost").await;
    let leaf = parse(&chain[0]);

    let eku = leaf.extended_key_usage().unwrap().expect("leaf declares an extendedKeyUsage extension");
    assert!(eku.value.server_auth, "serverAuth");
    assert!(eku.value.client_auth, "clientAuth");
}

/// `BCKeyAndCertificateFactoryBehaviourTest`'s CA key-usage case and
/// `BCKeyAndCertificateFactoryTest.shouldNotSetExtendedKeyUsageOnCertificateAuthority`.
#[tokio::test]
async fn certificate_authority_key_usage_asserts_signing_purposes_and_carries_no_extended_key_usage() {
    let (server, _dir) = start_dynamic_ca(&[]).await;
    let chain = served_chain(server.port, "localhost").await;
    let ca = parse(&chain[1]);

    let ku = ca.key_usage().unwrap().expect("CA declares a keyUsage extension");
    assert!(ku.value.key_cert_sign());
    assert!(ku.value.crl_sign());
    assert!(ku.value.digital_signature());
    assert!(ku.value.key_encipherment());
    assert!(ku.value.data_encipherment());
    assert!(ca.extended_key_usage().unwrap().is_none(), "CA must carry no extendedKeyUsage");
}

/// `BCKeyAndCertificateFactoryTest.shouldSetAuthorityKeyIdentifierMatchingCertificateAuthoritySubjectKeyIdentifier`.
#[tokio::test]
async fn leaf_authority_key_identifier_matches_the_certificate_authoritys_subject_key_identifier() {
    let (server, _dir) = start_dynamic_ca(&[]).await;
    let chain = served_chain(server.port, "localhost").await;
    let (leaf, ca) = (parse(&chain[0]), parse(&chain[1]));

    let ski = ca.extensions().iter().find_map(|e| match e.parsed_extension() {
        ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0.to_vec()),
        _ => None,
    });
    let aki = leaf.extensions().iter().find_map(|e| match e.parsed_extension() {
        ParsedExtension::AuthorityKeyIdentifier(aki) => aki.key_identifier.as_ref().map(|id| id.0.to_vec()),
        _ => None,
    });
    assert!(ski.is_some(), "CA must carry a subjectKeyIdentifier");
    assert_eq!(aki, ski, "leaf authorityKeyIdentifier must equal the CA's subjectKeyIdentifier");
}

// --- validity: default, override clamp (the confirmed gap), CA lifetime ---

/// `BCKeyAndCertificateFactoryTest.shouldGenerateShortLivedLeafWithinAppleServerCertificateCap`: 397-day default
/// window, 5-day back-dated `notBefore` (`KeyAndCertificateFactory.notBefore()`).
#[tokio::test]
async fn default_leaf_validity_window_is_397_days_with_five_day_back_dating() {
    let (server, _dir) = start_dynamic_ca(&[]).await;
    let chain = served_chain(server.port, "localhost").await;
    let leaf = parse(&chain[0]);

    let now = now_secs();
    assert!(leaf.validity().not_before.timestamp() <= now, "notBefore must not be in the future");
    let back_dated_days = (now - leaf.validity().not_before.timestamp()) as f64 / 86400.0;
    assert!((4.5..=5.5).contains(&back_dated_days), "notBefore should be ~5 days back-dated, was {back_dated_days} days");
    let window = validity_window_days(&leaf);
    assert!((396.0..=398.0).contains(&window), "leaf validity window should be ~397 days, was {window}");
    assert!(leaf.validity().not_after.timestamp() >= now, "leaf must still be valid now");
}

/// `BCKeyAndCertificateFactoryTest.shouldGenerateLongLivedCertificateAuthority`: ~10-year CA lifetime, anchored to
/// generation time (not to the leaf's back-dated `notBefore`).
#[tokio::test]
async fn certificate_authority_validity_window_is_at_least_ten_years() {
    let (server, _dir) = start_dynamic_ca(&[]).await;
    let chain = served_chain(server.port, "localhost").await;
    let ca = parse(&chain[1]);

    let now = now_secs();
    assert!(ca.validity().not_before.timestamp() <= now, "CA notBefore must not be in the future");
    let window = validity_window_days(&ca);
    assert!(window >= 3649.0, "CA validity window should be ~10 years, was {window} days");
}

/// `CertificateHardeningResilienceTest.shouldClampBrokenlySmallLeafValidityUpToASafeFloorRatherThanMintAnExpiredOrSelfRenewingLeaf`.
/// Confirmed gap: `sslCertificateLeafValidityInDays` was once never read at all (a hardcoded
/// 397-day const), so this and the two tests below all failed until `src/tls/mod.rs` read it.
#[tokio::test]
async fn leaf_validity_override_below_the_floor_is_clamped_up_to_thirty_days() {
    for days in ["1", "5", "6", "29"] {
        let (server, _dir) = start_dynamic_ca(&[("sslCertificateLeafValidityInDays", days)]).await;
        let chain = served_chain(server.port, "localhost").await;
        let leaf = parse(&chain[0]);
        let now = now_secs();
        assert!(leaf.validity().not_before.timestamp() <= now && leaf.validity().not_after.timestamp() >= now, "days={days}: leaf must be valid now, not born expired");
        let window = validity_window_days(&leaf);
        assert!((29.5..=30.5).contains(&window), "days={days}: validity window should be clamped to 30 days, was {window}");
    }
}

/// `CertificateHardeningResilienceTest.shouldClampExcessiveLeafValidityDownToTheCeilingToStayWithinTheX509DateRange`.
#[tokio::test]
async fn leaf_validity_override_above_the_ceiling_is_clamped_down_to_3650_days() {
    let (server, _dir) = start_dynamic_ca(&[("sslCertificateLeafValidityInDays", "100000000")]).await;
    let chain = served_chain(server.port, "localhost").await;
    let leaf = parse(&chain[0]);

    let window = validity_window_days(&leaf);
    assert!((3649.0..=3650.5).contains(&window), "validity window should be clamped to 3650 days, was {window}");
    assert!(leaf.validity().not_after.timestamp() < 253_402_300_799, "notAfter must stay within the X.509 date range");
}

/// `CertificateHardeningResilienceTest.shouldHonourAnInRangeLeafValidityOverrideVerbatim`.
#[tokio::test]
async fn leaf_validity_override_within_range_is_honoured_verbatim() {
    let (server, _dir) = start_dynamic_ca(&[("sslCertificateLeafValidityInDays", "500")]).await;
    let chain = served_chain(server.port, "localhost").await;
    let leaf = parse(&chain[0]);

    let window = validity_window_days(&leaf);
    assert!((499.5..=500.5).contains(&window), "an in-range override must be honoured verbatim, was {window}");
}

// --- on-disk persistence, canonical directory dedup, concurrent generation ---

/// `BCKeyAndCertificateFactoryBehaviourTest`'s "stable on-disk file naming" case. The factory writes the CA when it
/// is first loaded, which a server does on its first TLS use (scenario `tls_dynamic_ca_lazy_files`).
#[tokio::test]
async fn dynamic_certificate_authority_is_persisted_under_the_stable_file_names() {
    let (server, dir) = start_dynamic_ca(&[]).await;
    served_chain(server.port, "localhost").await;
    assert!(dir.0.join("CertificateAuthorityCertificate.pem").is_file());
    assert!(dir.0.join("PKCS8CertificateAuthorityPrivateKey.pem").is_file());
}

/// `BCKeyAndCertificateFactoryConcurrentCaGenerationTest` (concurrent generation yields one consistent pair) and
/// `BCKeyAndCertificateFactoryCanonicalMonitorTest.differentlySpelledDirectoriesShareOneGenerationMonitor` /
/// `concurrentGenerationAcrossDifferentSpellingsYieldsConsistentPair` (`dir` and `dir/.` — different strings,
/// same physical directory — must resolve to ONE generation monitor): several servers start concurrently,
/// some pointed at the same directory under the plain spelling and some under the dotted one, and all must
/// converge on the SAME generated CA rather than each minting its own and racing to overwrite the files on disk.
#[tokio::test]
async fn concurrent_dynamic_certificate_authority_generation_converges_on_one_pair() {
    let dir = TempDir::fresh();
    let plain = dir.as_str();
    let dotted = format!("{plain}{}.", std::path::MAIN_SEPARATOR);
    let paths = vec![plain.clone(), dotted.clone(), plain.clone(), dotted];

    let handles: Vec<_> = paths
        .into_iter()
        .map(|path| {
            tokio::spawn(async move {
                let props = [("dynamicallyCreateCertificateAuthorityCertificate", "true"), ("directoryToSaveDynamicSSLCertificate", path.as_str())];
                common::start(&props).await
            })
        })
        .collect();
    let mut servers = Vec::with_capacity(handles.len());
    for handle in handles {
        servers.push(handle.await.unwrap());
    }

    let mut ca_bytes = Vec::new();
    for server in &servers {
        let chain = served_chain(server.port, "localhost").await;
        ca_bytes.push(chain[1].clone());
    }
    for (i, bytes) in ca_bytes.iter().enumerate().skip(1) {
        assert_eq!(&ca_bytes[0], bytes, "server {i} served a different CA than server 0 — the generation race was not serialised");
    }
}

// --- Host-header-driven SAN growth, cap/eviction, normalisation, SNI persistence, leaf renewal ---

/// Confirmed against the oracle (not just source reading): a plain HTTP request's `Host` header grows the leaf's
/// SAN set exactly like a CONNECT/SOCKS target does — not only on an explicit tunnel target
/// (`HttpRequestHandler.channelRead0` calls `configuration.addSubjectAlternativeName` unconditionally, for every
/// exchange). Earlier, `src/handler.rs` never called `Tls::add_subject_alternative_name` at all.
#[tokio::test]
async fn host_header_on_a_plain_request_grows_the_subject_alternative_names() {
    let (server, _dir) = start_dynamic_ca(&[]).await;
    plain_request(server.port, "grown.via.host.header.test").await;

    let chain = served_chain(server.port, "localhost").await;
    let leaf = parse(&chain[0]);
    assert!(dns_sans(&leaf).contains(&"grown.via.host.header.test".to_string()), "dns SANs: {:?}", dns_sans(&leaf));
}

/// `Configuration.boundedAdd`: past `maxSubjectAlternativeNames`, the oldest *dynamically discovered* entry is
/// evicted (FIFO) to make room; a configured/default entry (`localhost`) is never evicted. Confirmed against the
/// oracle with `maxSubjectAlternativeNames` left at its default 100 and 105 distinct Host headers (entries 1-5
/// evicted, entry 105 present, `localhost` present); this test uses a cap of 3 to stay fast.
#[tokio::test]
async fn subject_alternative_names_are_capped_with_fifo_eviction_protecting_defaults() {
    let (server, _dir) = start_dynamic_ca(&[("maxSubjectAlternativeNames", "3")]).await;
    for i in 1..=5 {
        plain_request(server.port, &format!("cap-test-{i}.example.com")).await;
    }

    let chain = served_chain(server.port, "localhost").await;
    let leaf = parse(&chain[0]);
    let dns = dns_sans(&leaf);
    assert!(dns.contains(&"localhost".to_string()), "the default must never be evicted: {dns:?}");
    for evicted in 1..=3 {
        assert!(!dns.contains(&format!("cap-test-{evicted}.example.com")), "cap-test-{evicted} should have been evicted: {dns:?}");
    }
    for kept in 4..=5 {
        assert!(dns.contains(&format!("cap-test-{kept}.example.com")), "cap-test-{kept} should still be present: {dns:?}");
    }
}

/// `Configuration.normaliseSubjectAlternativeNameDomain`, confirmed against the oracle: lowercased, one trailing
/// dot stripped, a leading `*` wildcard label accepted, and a label with a non-LDH character (e.g. `_`) dropped
/// entirely rather than baked into the leaf.
#[tokio::test]
async fn subject_alternative_name_domains_are_normalised_and_invalid_ones_rejected() {
    let (server, _dir) = start_dynamic_ca(&[]).await;
    plain_request(server.port, "UPPER-Case.Example.COM").await;
    plain_request(server.port, "trailing-dot.example.com.").await;
    plain_request(server.port, "*.wild.example.com").await;
    plain_request(server.port, "bad_underscore.example.com").await;

    let chain = served_chain(server.port, "localhost").await;
    let leaf = parse(&chain[0]);
    let dns = dns_sans(&leaf);
    assert!(dns.contains(&"upper-case.example.com".to_string()), "must be lowercased: {dns:?}");
    assert!(dns.contains(&"trailing-dot.example.com".to_string()), "trailing dot must be stripped: {dns:?}");
    assert!(dns.contains(&"*.wild.example.com".to_string()), "leading wildcard label must be accepted: {dns:?}");
    assert!(!dns.iter().any(|s| s.contains("bad_underscore")), "underscore is not LDH, must be rejected entirely: {dns:?}");
}

/// Confirmed against the oracle: an SNI hostname seen on one connection shows up on a LATER, unrelated
/// connection's leaf too (`SniHandler.lookup` calls the same persistent `configuration.addSubjectAlternativeName`
/// as a Host header or CONNECT target) — not merely baked ephemerally into the one handshake that triggered it.
#[tokio::test]
async fn sni_driven_growth_persists_across_unrelated_connections() {
    let (server, _dir) = start_dynamic_ca(&[]).await;
    let _ = served_chain(server.port, "sni-first.example.test").await;

    let chain = served_chain(server.port, "sni-second.example.test").await;
    let leaf = parse(&chain[0]);
    let dns = dns_sans(&leaf);
    assert!(dns.contains(&"sni-first.example.test".to_string()), "an earlier SNI name must persist onto a later, unrelated connection's leaf: {dns:?}");
}

/// `KeyAndCertificateFactory.isPastRenewalThreshold` / `BCKeyAndCertificateFactory.certificateNeedsRenewal`: a
/// cached leaf is served unchanged before 80% of its validity window has elapsed, and reminted (fresh serial)
/// once at or past it. Real wall-clock renewal cannot be exercised in a test (the default window is 397 days), so
/// this drives the resolver's clock seam (`sslCertificateRenewalClockSeconds`, a Rust-only test property — see
/// `src/tls/mod.rs::Resolver::now_secs`) instead; issuance itself (`notBefore`/`notAfter`) always anchors to real
/// wall-clock, exactly as upstream's `renewalClock` affects only the threshold check, never `notBefore()`/`notAfter()`.
#[tokio::test]
async fn leaf_is_reminted_once_past_the_renewal_threshold_via_the_clock_seam() {
    let (server, _dir) = start_dynamic_ca(&[("sslCertificateLeafValidityInDays", "30")]).await;
    let chain1 = served_chain(server.port, "renewal.test").await;
    let leaf1 = parse(&chain1[0]);
    let serial1 = leaf1.tbs_certificate.serial.clone();
    let (not_before, not_after) = (leaf1.validity().not_before.timestamp(), leaf1.validity().not_after.timestamp());
    let window = not_after - not_before;

    // Before the 80% threshold: the cached leaf is served unchanged.
    server.server.set_property("sslCertificateRenewalClockSeconds", &(not_before + (window as f64 * 0.5) as i64).to_string());
    let chain2 = served_chain(server.port, "renewal.test").await;
    let leaf2 = parse(&chain2[0]);
    assert_eq!(leaf2.tbs_certificate.serial, serial1, "leaf must be reused before the renewal threshold");

    // At/after the 80% threshold: a fresh leaf is minted.
    server.server.set_property("sslCertificateRenewalClockSeconds", &(not_before + (window as f64 * 0.81) as i64).to_string());
    let chain3 = served_chain(server.port, "renewal.test").await;
    let leaf3 = parse(&chain3[0]);
    assert_ne!(leaf3.tbs_certificate.serial, serial1, "leaf must be reminted once past the 80% renewal threshold");
    // `buildAndSavePrivateKeyAndX509Certificate` creates a new key pair for every leaf it generates
    assert_ne!(leaf3.public_key().raw, leaf1.public_key().raw, "a reminted leaf must carry a new key pair");
}

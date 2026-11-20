//! `WebhookServer.buildSslContext` and `loadPrivateKey`: the serving certificate chain and key from PEM files,
//! whatever unencrypted key form the chart's TLS bootstrap emits (PKCS#8, PKCS#1 RSA, SEC1 EC).

use crate::java::JavaException;
use base64::Engine;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use std::path::Path;
use std::sync::Arc;

/// A private key as `loadPrivateKey` returns it: the key and `PrivateKey.getAlgorithm()`.
#[derive(Debug)]
pub struct LoadedKey {
    pub der: PrivateKeyDer<'static>,
    pub algorithm: &'static str,
}

/// `buildSslContext(certPath, keyPath)`: a TLS server configuration (TLS 1.2 and 1.3, no client authentication, no
/// ALPN, as the JDK's `HttpsServer` offers).
pub fn build_tls_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>, JavaException> {
    let cert_pem = read_file(cert_path)?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| JavaException::new("java.security.cert.CertificateException", format!("Could not parse certificate: {e}")))?;
    if certs.is_empty() {
        return Err(JavaException::illegal_argument(format!("no certificates found in {}", cert_path.display())));
    }
    let key_pem = read_file(key_path)?;
    let key = load_private_key(&String::from_utf8_lossy(&key_pem))?;
    server_config(certs, key.der)
}

/// A TLS server configuration for a chain and key already in hand. As the JDK's `PKCS12` key store does, nothing
/// checks that the key belongs to the certificate: a key of the certificate's type signs the handshake (the client
/// then rejects the signature), and a key of another type (or one no TLS stack here signs with, such as DSA) resolves
/// no certificate, so each handshake ends with the connection closed (see `server::serve`).
pub fn server_config(certs: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result<Arc<ServerConfig>, JavaException> {
    let key_algorithm = match &key {
        PrivateKeyDer::Pkcs1(_) => "RSA",
        PrivateKeyDer::Sec1(_) => "EC",
        PrivateKeyDer::Pkcs8(der) => pkcs8_algorithm(der.secret_pkcs8_der()),
        _ => "unknown",
    };
    let cert_algorithm = certs.first().and_then(|c| certificate_key_algorithm(c));
    if cert_algorithm == Some("DSA") && matches!(key_algorithm, "DSA" | "RSA") {
        // the JDK serves a DSA key to a TLS 1.2 client offering a DHE-DSS suite
        let der = match &key {
            PrivateKeyDer::Pkcs1(der) => Some(der.secret_pkcs1_der()),
            PrivateKeyDer::Pkcs8(der) => Some(der.secret_pkcs8_der()),
            _ => None,
        };
        if let Some(dsa_key) = der.and_then(crate::dsa::DsaKey::from_der) {
            let config = ServerConfig::builder_with_provider(Arc::new(crate::dsa::provider()))
                .with_protocol_versions(&[&rustls::version::TLS12])
                .map_err(|e| JavaException::new("java.security.KeyStoreException", e.to_string()))?
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(crate::dsa::DsaKeyEntry::new(certs, dsa_key)));
            return Ok(Arc::new(config));
        }
    }
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).ok();
    let certified = match (signing_key, cert_algorithm) {
        (Some(signing_key), Some(cert_algorithm)) if cert_algorithm == key_algorithm => {
            Some(Arc::new(rustls::sign::CertifiedKey::new(certs, signing_key)))
        }
        _ => None,
    };
    let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| JavaException::new("java.security.KeyStoreException", e.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(KeyEntry(certified)));
    Ok(Arc::new(config))
}

/// The key store's single entry, whether or not its key can sign for its certificate.
#[derive(Debug)]
struct KeyEntry(Option<Arc<rustls::sign::CertifiedKey>>);

impl rustls::server::ResolvesServerCert for KeyEntry {
    fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.0.clone()
    }
}

/// The JCA algorithm name of a certificate's public key, from its `SubjectPublicKeyInfo`.
fn certificate_key_algorithm(cert: &CertificateDer<'_>) -> Option<&'static str> {
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version OPTIONAL, serialNumber, signature, issuer,
    // validity, subject, subjectPublicKeyInfo SEQUENCE { algorithm SEQUENCE { OID, ... }, ... }, ... }, ... }
    let (_, cert) = der_element(cert.as_ref(), 0x30)?;
    let (_, mut tbs) = der_element(cert, 0x30)?;
    if tbs.first() == Some(&0xA0) {
        tbs = der_element(tbs, 0xA0)?.0;
    }
    for tag in [0x02, 0x30, 0x30, 0x30, 0x30] {
        tbs = der_element(tbs, tag)?.0;
    }
    let (_, spki) = der_element(tbs, 0x30)?;
    let (_, alg) = der_element(spki, 0x30)?;
    let (_, oid) = der_element(alg, 0x06)?;
    algorithm_name(oid)
}

fn read_file(path: &Path) -> Result<Vec<u8>, JavaException> {
    std::fs::read(path).map_err(|e| {
        let class = match e.kind() {
            std::io::ErrorKind::NotFound => "java.nio.file.NoSuchFileException",
            std::io::ErrorKind::PermissionDenied => "java.nio.file.AccessDeniedException",
            _ => return JavaException::new("java.io.IOException", e.to_string()),
        };
        JavaException::new(class, path.display().to_string())
    })
}

/// `loadPrivateKey(String)`: the first PEM object, as BouncyCastle's `PEMParser.readObject()` finds it, must be an
/// unencrypted PKCS#8 (`PRIVATE KEY`), PKCS#1 (`RSA PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`) key.
pub fn load_private_key(pem: &str) -> Result<LoadedKey, JavaException> {
    let unsupported = |parsed: &str| {
        JavaException::illegal_argument(format!(
            "no supported PEM private key found (expected an unencrypted PKCS#8, PKCS#1 or SEC1 key); parsed object was {parsed}"
        ))
    };
    let Some(object) = read_pem_object(pem)? else {
        return Err(unsupported("null"));
    };
    let encrypted = object.headers.iter().any(|(k, v)| k == "Proc-Type" && v.starts_with("4,ENCRYPTED"));
    let (der, algorithm) = match object.label.as_str() {
        "PRIVATE KEY" => {
            let algorithm = pkcs8_algorithm(&object.der);
            (PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(object.der)), algorithm)
        }
        "RSA PRIVATE KEY" | "EC PRIVATE KEY" | "DSA PRIVATE KEY" if encrypted => {
            return Err(unsupported("org.bouncycastle.openssl.PEMEncryptedKeyPair"));
        }
        "RSA PRIVATE KEY" => (PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(object.der)), "RSA"),
        "EC PRIVATE KEY" => (PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(object.der)), "EC"),
        // a DSA key pair loads as in Java; PrivateKeyDer has no DSA form, so it is carried as PKCS#1 bytes and
        // server_config reads them as a DSA key when the certificate's key is DSA (`dsa.rs`)
        "DSA PRIVATE KEY" => (PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(object.der)), "DSA"),
        "ENCRYPTED PRIVATE KEY" => return Err(unsupported("org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo")),
        "CERTIFICATE" | "X509 CERTIFICATE" => return Err(unsupported("org.bouncycastle.cert.X509CertificateHolder")),
        "TRUSTED CERTIFICATE" => return Err(unsupported("org.bouncycastle.openssl.X509TrustedCertificateBlock")),
        "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => return Err(unsupported("org.bouncycastle.pkcs.PKCS10CertificationRequest")),
        "PUBLIC KEY" | "RSA PUBLIC KEY" => return Err(unsupported("org.bouncycastle.asn1.x509.SubjectPublicKeyInfo")),
        "X509 CRL" => return Err(unsupported("org.bouncycastle.cert.X509CRLHolder")),
        "PKCS7" | "CMS" => return Err(unsupported("org.bouncycastle.asn1.cms.ContentInfo")),
        "ATTRIBUTE CERTIFICATE" => return Err(unsupported("org.bouncycastle.cert.X509AttributeCertificateHolder")),
        "EC PARAMETERS" => return Err(unsupported("org.bouncycastle.asn1.ASN1ObjectIdentifier")),
        other => return Err(JavaException::new("java.io.IOException", format!("unrecognised object: {other}"))),
    };
    Ok(LoadedKey { der, algorithm })
}

struct PemBlock {
    label: String,
    headers: Vec<(String, String)>,
    der: Vec<u8>,
}

/// BouncyCastle's `PemReader.readPemObject()`: skips lines up to the first `-----BEGIN <type>-----`, then reads
/// `Name: value` headers and the base64 body up to `-----END <type>`.
fn read_pem_object(pem: &str) -> Result<Option<PemBlock>, JavaException> {
    let mut lines = pem.lines().map(|l| l.trim_end_matches('\r'));
    let label = loop {
        let Some(line) = lines.next() else {
            return Ok(None);
        };
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            let rest = rest.trim();
            match rest.find('-') {
                Some(index) if index > 0 && rest.ends_with("-----") && rest.len() - index == 5 => break rest[..index].to_string(),
                _ => return Ok(None),
            }
        }
    };
    let end = format!("-----END {label}");
    let mut headers = Vec::new();
    let mut body = String::new();
    loop {
        let Some(line) = lines.next() else {
            return Err(JavaException::new("java.io.IOException", format!("{end} not found")));
        };
        if line.starts_with(&end) {
            break;
        }
        if let Some(colon) = line.find(':') {
            headers.push((line[..colon].to_string(), line[colon + 1..].trim().to_string()));
        } else {
            body.push_str(line.trim());
        }
    }
    let der = base64::engine::general_purpose::STANDARD.decode(body.as_bytes()).map_err(|e| {
        JavaException::new("org.bouncycastle.util.encoders.DecoderException", format!("unable to decode base64 string: {e}"))
    })?;
    Ok(Some(PemBlock { label, headers, der }))
}

/// The JCA algorithm name of a PKCS#8 `PrivateKeyInfo`, from its algorithm identifier.
fn pkcs8_algorithm(der: &[u8]) -> &'static str {
    // PrivateKeyInfo ::= SEQUENCE { version INTEGER, privateKeyAlgorithm SEQUENCE { algorithm OID, ... }, ... }
    let oid = (|| {
        let (_, inner) = der_element(der, 0x30)?;
        let (rest, _) = der_element(inner, 0x02)?;
        let (_, alg) = der_element(rest, 0x30)?;
        let (_, oid) = der_element(alg, 0x06)?;
        Some(oid)
    })();
    oid.and_then(algorithm_name).unwrap_or("unknown")
}

/// The JCA name of a key algorithm OID.
fn algorithm_name(oid: &[u8]) -> Option<&'static str> {
    const OIDS: &[(&[u8], &str)] = &[
        (&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01], "RSA"),
        (&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A], "RSASSA-PSS"),
        (&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01], "EC"),
        (&[0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01], "DSA"),
        (&[0x2B, 0x65, 0x70], "EdDSA"),
        (&[0x2B, 0x65, 0x71], "EdDSA"),
    ];
    OIDS.iter().find(|(o, _)| *o == oid).map(|(_, name)| *name)
}

/// One DER element of the expected tag at the start of `data`: (what follows it, its contents).
fn der_element(data: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if *data.first()? != tag {
        return None;
    }
    let first = *data.get(1)? as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7F;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *data.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let contents = data.get(header..header + len)?;
    Some((&data[header + len..], contents))
}

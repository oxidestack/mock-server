//! `CertificateConfigurationValidator`: the checks `createServerSslContext` runs on a fixed server certificate
//! (`privateKeyPath` + `x509CertificatePath`) before it builds the context. A failure makes every TLS handshake fail
//! (the exception propagates out of the context factory) while the plain-text port keeps answering.

use x509_parser::prelude::*;

use super::{client_cert, BUNDLED_CA_CERT};
use crate::config::Config;

const DEFAULT_CA_CERT_PATH: &str = "org/mockserver/socket/CertificateAuthorityCertificate.pem";
const DEFAULT_CA_KEY_PATH: &str = "org/mockserver/socket/PKCS8CertificateAuthorityPrivateKey.pem";

/// The exception that refuses the configuration: the validator's `RuntimeException` message and the
/// `Throwable.toString` of each exception beneath it, outermost first (what the JDK, BouncyCastle or `PEMToFile`
/// threw), as the oracle's log entry carries them.
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    pub message: String,
    pub causes: Vec<String>,
}

impl Refusal {
    fn new(message: String) -> Refusal {
        Refusal { message, causes: Vec::new() }
    }

    fn caused(message: String, causes: Vec<String>) -> Refusal {
        Refusal { message, causes }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// The text of a file named by a configured path (`FileReader.readFileFromClassPathOrPath`): the bundled CA for
/// its classpath name, else the class path resource or the file.
fn read_path(path: &str) -> Result<String, String> {
    if path == DEFAULT_CA_CERT_PATH {
        return Ok(BUNDLED_CA_CERT.to_string());
    }
    crate::class_path::read_string_or_file(path.trim()).map_err(|e| format!("{path}: {e}"))
}

fn text(config: &Config, name: &str) -> String {
    config.property(name).map(|v| v.trim().to_string()).unwrap_or_default()
}

/// `PEMToFile.x509FromPEMFile`'s exception chain for a file it cannot read as one certificate
/// (`CertificateFactory.generateCertificate`).
fn x509_from_pem_file_causes(path: &str) -> Vec<String> {
    let reading = format!("java.lang.RuntimeException: Exception reading X509 from PEM file {path}");
    match crate::class_path::read_or_file(path.trim()) {
        Ok(bytes) => match super::x509::generate_certificate(&bytes) {
            Ok(_) => Vec::new(),
            Err(e) => [vec![reading, "java.lang.RuntimeException: Exception creating X509 from PEM".into()], e.chain()].concat(),
        },
        Err(e) => vec![reading, format!("java.io.FileNotFoundException: {path} ({})", super::java_io_reason(&e))],
    }
}

/// `Date.toString` in the oracle image's time zone (GMT), as `X509CertImpl.checkValidity` writes it.
fn java_date(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0).map(|d| d.format("%a %b %d %H:%M:%S GMT %Y").to_string()).unwrap_or_default()
}

/// The key families `Signature.initVerify` tells apart.
#[derive(Clone, Copy, PartialEq)]
enum Family {
    Rsa,
    Ec,
    EdDsa,
    Dsa,
}

impl Family {
    /// The class of the JDK's public key of the family, which an `initVerify` refusal names.
    fn public_key_class(self) -> &'static str {
        match self {
            Family::Rsa => "sun.security.rsa.RSAPublicKeyImpl",
            Family::Ec => "sun.security.ec.ECPublicKeyImpl",
            Family::EdDsa => "sun.security.ec.ed.EdDSAPublicKeyImpl",
            Family::Dsa => "sun.security.provider.DSAPublicKeyImpl",
        }
    }
}

/// The family of a public key (`SubjectPublicKeyInfo`) or of a signature algorithm, by OID.
fn family(oid: &str) -> Option<Family> {
    match oid {
        // rsaEncryption and the PKCS#1 v1.5 signatures (not RSASSA-PSS, .10)
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.4" | "1.2.840.113549.1.1.5" | "1.2.840.113549.1.1.11" | "1.2.840.113549.1.1.12" | "1.2.840.113549.1.1.13" | "1.2.840.113549.1.1.14" => Some(Family::Rsa),
        // id-ecPublicKey and ecdsa-with-SHA*
        "1.2.840.10045.2.1" => Some(Family::Ec),
        _ if oid.starts_with("1.2.840.10045.4.") => Some(Family::Ec),
        // Ed25519, Ed448
        "1.3.101.112" | "1.3.101.113" => Some(Family::EdDsa),
        // id-dsa, dsa-with-SHA1 and dsa-with-SHA224/256/384/512
        "1.2.840.10040.4.1" | "1.2.840.10040.4.3" | "2.16.840.1.101.3.4.3.1" | "2.16.840.1.101.3.4.3.2" | "2.16.840.1.101.3.4.3.3" | "2.16.840.1.101.3.4.3.4" => Some(Family::Dsa),
        _ => None,
    }
}

/// The exception `Signature.initVerify` throws when a signature of the `signature` family is verified with a public
/// key of the `key` family (read off the oracle's JDK for every pair of RSA, EC and Ed25519, and for DSA against RSA
/// and EC); `None` for the same family, whose verification just fails, and for a family not modelled.
fn init_verify_failure(signature: Option<Family>, key: Option<Family>) -> Option<String> {
    let (signature, key) = (signature?, key?);
    if signature == key {
        return None;
    }
    Some(match signature {
        Family::Rsa => format!("java.security.InvalidKeyException: Supplied key ({}) is not a RSAPublicKey instance", key.public_key_class()),
        Family::Ec => "java.security.InvalidKeyException: cannot identify EC public key.".into(),
        Family::EdDsa => "java.security.InvalidKeyException: Unsupported key type".into(),
        Family::Dsa => format!("java.security.InvalidKeyException: can't identify DSA public key: {}", key.public_key_class()),
    })
}

/// The family of the challenge signature `validateKeyMatchesCertificate` makes with the private key.
fn key_family(key: &dyn rustls::sign::SigningKey) -> Option<Family> {
    match key.algorithm() {
        rustls::SignatureAlgorithm::RSA => Some(Family::Rsa),
        rustls::SignatureAlgorithm::ECDSA => Some(Family::Ec),
        rustls::SignatureAlgorithm::ED25519 | rustls::SignatureAlgorithm::ED448 => Some(Family::EdDsa),
        _ => None,
    }
}

/// The configured private key as `validateKeyMatchesCertificate` uses it: one the TLS stack signs with, or a DSA or
/// Ed448 key, which BouncyCastle reads and the JDK signs the challenge with but this TLS stack cannot.
enum Key {
    Signing(std::sync::Arc<dyn rustls::sign::SigningKey>),
    Other(super::key_string::OtherPublic),
}

impl Key {
    fn read(pem: &str) -> Option<Key> {
        match super::signing_key(&super::pkcs8_pem(pem)) {
            Ok(key) => Some(Key::Signing(key)),
            Err(_) => super::key_string::dsa_or_ed448_public(pem).map(Key::Other),
        }
    }

    /// Whether the key's public half is the certificate's (`SubjectPublicKeyInfo` DER).
    fn matches(&self, spki: &[u8]) -> bool {
        match self {
            Key::Signing(key) => key.public_key().is_some_and(|own| own.as_ref() == spki),
            Key::Other(public) => super::key_string::certificate_dsa_or_ed448_public(spki).as_ref() == Some(public),
        }
    }

    fn family(&self) -> Option<Family> {
        match self {
            Key::Signing(key) => key_family(key.as_ref()),
            Key::Other(super::key_string::OtherPublic::Dsa { .. }) => Some(Family::Dsa),
            Key::Other(super::key_string::OtherPublic::Ed448(_)) => Some(Family::EdDsa),
        }
    }
}

/// `validate()`: the WARN texts when no fixed certificate is configured or every check passes; else the exception.
pub fn validate(config: &Config) -> Result<Vec<String>, Refusal> {
    let private_key_path = text(config, "privateKeyPath");
    let certificate_path = text(config, "x509CertificatePath");
    if private_key_path.is_empty() && certificate_path.is_empty() {
        return Ok(Vec::new());
    }
    if !private_key_path.is_empty() && certificate_path.is_empty() {
        return Err(Refusal::new(format!(
            "Both 'privateKeyPath' and 'x509CertificatePath' must be configured together. You set 'privateKeyPath' to '{private_key_path}' but 'x509CertificatePath' is not set."
        )));
    }
    if private_key_path.is_empty() {
        return Err(Refusal::new(format!(
            "Both 'privateKeyPath' and 'x509CertificatePath' must be configured together. You set 'x509CertificatePath' to '{certificate_path}' but 'privateKeyPath' is not set."
        )));
    }

    let key = read_path(&private_key_path).ok().and_then(|pem| Key::read(&pem)).ok_or_else(|| {
        Refusal::caused(
            format!(
                "The file '{private_key_path}' is not a valid PEM-encoded private key. Ensure the file contains a '-----BEGIN PRIVATE KEY-----' or '-----BEGIN RSA PRIVATE KEY-----' block."
            ),
            super::private_key_from_pem_file_causes(&private_key_path),
        )
    })?;
    let not_valid = || format!("The file '{certificate_path}' is not a valid PEM-encoded certificate. Ensure the file contains a '-----BEGIN CERTIFICATE-----' block.");
    // `x509ChainFromPEMFile`: a file `CertificateFactory.generateCertificates` cannot read fails, one it reads with
    // no certificate in it (an empty file) is an empty chain
    let chain = super::x509_chain_from_pem_file(&certificate_path).map_err(|causes| Refusal::caused(not_valid(), causes))?;
    let Some(leaf) = chain.first() else {
        return Err(Refusal::new(format!("The file '{certificate_path}' does not contain any valid PEM-encoded certificates.")));
    };
    let (_, leaf) = X509Certificate::from_der(&leaf.der).map_err(|_| Refusal::new(not_valid()))?;

    let validity = leaf.validity();
    // `checkValidity(new Date())`, with the dates as `Instant.toString` prints them
    let now = ::time::OffsetDateTime::now_utc().unix_timestamp();
    let instant = |seconds: i64| chrono::DateTime::from_timestamp(seconds, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_default();
    let (not_before, not_after) = (validity.not_before.timestamp(), validity.not_after.timestamp());
    if not_after < now {
        return Err(Refusal::caused(
            format!("The certificate at '{certificate_path}' expired on {}. Replace it with a valid certificate.", instant(not_after)),
            vec![format!("java.security.cert.CertificateExpiredException: NotAfter: {}", java_date(not_after))],
        ));
    }
    if not_before > now {
        return Err(Refusal::caused(
            format!("The certificate at '{certificate_path}' is not yet valid until {}. Replace it with a valid certificate.", instant(not_before)),
            vec![format!("java.security.cert.CertificateNotYetValidException: NotBefore: {}", java_date(not_before))],
        ));
    }

    // The key belongs to the certificate when their public keys are the same. 8.0.0 proved it by signing a challenge
    // with the certificate's `getSigAlgName()` - the issuing CA's algorithm - so an RSA leaf under an EC CA (or an EC
    // leaf under an RSA CA) was refused as a mismatch; upstream 5853377b1 picks the algorithm from the key instead,
    // which leaves only the key pair itself deciding (adopted, docs/divergences.md).
    if !key.matches(leaf.public_key().raw) {
        return Err(Refusal::caused(
            format!(
                "The private key at '{private_key_path}' does not match the certificate at '{certificate_path}'. The public key fingerprints differ. Regenerate the key pair or check that the files correspond to each other."
            ),
            init_verify_failure(key.family(), family(&leaf.public_key().algorithm.algorithm.to_id_string())).into_iter().collect(),
        ));
    }

    let ca_certificate_path = config.property("certificateAuthorityCertificate").unwrap_or_else(|| DEFAULT_CA_CERT_PATH.into());
    let ca_certificate_path = ca_certificate_path.trim();
    if ca_certificate_path.is_empty() {
        // The validator skips a blank path, but the leaf's set-up then reads the certificate authority from "" - the
        // working directory - and fails (`x509FromPEMFile`; "<working directory> (Is a directory)" on the oracle image).
        let directory = std::env::current_dir().map(|d| d.display().to_string()).unwrap_or_default();
        return Err(Refusal::caused("Exception reading X509 from PEM file ".into(), vec![format!("java.io.FileNotFoundException: {directory} (Is a directory)")]));
    }
    if !ca_certificate_path.is_empty() {
        let ca_der = read_path(ca_certificate_path).ok().and_then(|pem| client_cert::pem_chain(&pem).into_iter().next());
        let ca = ca_der.as_deref().and_then(|der| X509Certificate::from_der(der).ok()).map(|(_, c)| c);
        if ca.is_none() && ca_certificate_path != DEFAULT_CA_CERT_PATH {
            return Err(Refusal::caused(
                format!(
                    "The CA certificate file '{ca_certificate_path}' is not a valid PEM-encoded X.509 certificate. Check that the file path is correct and that it is not swapped with the private key."
                ),
                x509_from_pem_file_causes(ca_certificate_path),
            ));
        }
        if !ca.as_ref().is_some_and(|ca| leaf.verify_signature(Some(ca.public_key())).is_ok()) {
            return Err(Refusal::caused(
                format!(
                    "The certificate at '{certificate_path}' was not signed by the CA certificate at '{ca_certificate_path}'. Verify the certificate chain or update 'certificateAuthorityCertificate'."
                ),
                // `X509CertImpl.verify` with the CA's key, under the leaf's signature algorithm: a key of another family
                // is refused by `initVerify`, one of the same family fails the check
                ca.as_ref()
                    .map(|ca| {
                        let signature = family(&leaf.signature_algorithm.algorithm.to_id_string());
                        init_verify_failure(signature, family(&ca.public_key().algorithm.algorithm.to_id_string()))
                            .unwrap_or_else(|| "java.security.SignatureException: Signature does not match.".into())
                    })
                    .into_iter()
                    .collect(),
            ));
        }
    }

    let ca_key_path = text(config, "certificateAuthorityPrivateKey");
    if !ca_key_path.is_empty() && ca_key_path != DEFAULT_CA_KEY_PATH {
        let valid = read_path(&ca_key_path).ok().and_then(|pem| Key::read(&pem)).is_some();
        if !valid {
            return Err(Refusal::caused(
                format!(
                    "The CA private key file '{ca_key_path}' is not a valid PEM-encoded private key. Ensure the file contains a '-----BEGIN PRIVATE KEY-----' or '-----BEGIN RSA PRIVATE KEY-----' block."
                ),
                super::private_key_from_pem_file_causes(&ca_key_path),
            ));
        }
    }
    // A leaf with extended key usages that leave out `serverAuth` is served all the same, with a WARN.
    let mut warnings = Vec::new();
    if let Ok(Some(usage)) = leaf.extended_key_usage() && !usage.value.server_auth {
        warnings.push(format!(
            "The certificate at '{certificate_path}' does not include the 'serverAuth' Extended Key Usage extension. Some strict TLS clients may reject it."
        ));
    }
    Ok(warnings)
}

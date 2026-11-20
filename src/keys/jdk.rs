//! The JDK's `CertificateFactory.getInstance("X.509")` as the key readers meet it: `generateCertificate` over a PEM
//! text (`PEMToFile.x509FromPEM`) and the PKCS#1 tag check of RSA key bits, both delegated to [`crate::tls::x509`]
//! (one port of `X509Factory`, `DerValue` and `X509CertImpl`), with its [`Throwable`] chains turned into
//! the [`Failure`] beans the IdP providers print.

use crate::tls::x509::{self, Throwable};

use super::{throwable, Failure};

/// A Java throwable and its causes as a [`Failure`]. A `URISyntaxException` (of a URI general name) also has its
/// bean's `index`, `input` and `reason`, read back from its message (`reason[ at index N]: input`).
fn failure(t: &Throwable) -> Failure {
    const URI_SYNTAX: &str = "java.net.URISyntaxException";
    if let (URI_SYNTAX, Some(message), None) = (t.class, &t.message, &t.cause) && let Some((head, input)) = message.split_once(": ") {
        let (reason, index) = match head.rsplit_once(" at index ") {
            Some((reason, index)) => (reason, index.parse::<i64>().unwrap_or(-1)),
            None => (head, -1),
        };
        let fields = vec![("index", index.into()), ("input", input.into()), ("reason", reason.into())];
        return Failure::of(URI_SYNTAX, message.clone(), fields, &[]);
    }
    throwable(t.class, t.message.clone(), t.cause.as_deref().map(failure))
}

/// `CertificateFactory.generateCertificate` over `input`: the certificate's DER, or the CertificateException.
pub(super) fn generate_certificate(input: &[u8]) -> Result<Vec<u8>, Failure> {
    x509::generate_certificate(input).map(|c| c.encoded).map_err(|e| failure(&e))
}

/// `RSAPublicKeyImpl.parseKeyBits` up to its tag check: the IOException it throws, `None` for a SEQUENCE (whose
/// integers are not read here: the bits reaching this are an EC point).
pub(super) fn rsa_public_key_bits(bits: &[u8]) -> Option<Failure> {
    x509::pkcs1_sequence_failure(bits).map(|e| failure(&e))
}

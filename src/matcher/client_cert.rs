//! `ClientCertificateMatcher`: an expectation's `clientCertificate` criteria (`subject`, `issuer`,
//! `fingerprintSha256`) against the leaf of the TLS client certificate chain a request arrived with.

use serde_json::{Value, json};
use x509_parser::prelude::*;

use super::jwt::{java_list, matches_across_candidates};
use super::{Difference, StringMatcher, format_log_message};
use crate::tls::client_cert::ClientCertificate;

#[derive(Debug)]
pub struct ClientCertificateMatcher {
    subject: Option<StringMatcher>,
    issuer: Option<StringMatcher>,
    /// The fingerprint criterion with `:` and whitespace removed (`normaliseFingerprint`).
    fingerprint: Option<StringMatcher>,
    /// The fingerprint as given, which a mismatch prints.
    fingerprint_printed: String,
}

impl ClientCertificateMatcher {
    /// From the `clientCertificate` object of a request matcher; `None` for anything else (matches every request).
    pub fn compile(v: &Value) -> Option<ClientCertificateMatcher> {
        let o = v.as_object()?;
        let nottable = |k: &str| o.get(k).filter(|v| !v.is_null()).map(StringMatcher::compile);
        let given = nottable("fingerprintSha256");
        let fingerprint = given.as_ref().map(|f| {
            let normalised: String = f.value.chars().filter(|c| *c != ':' && !matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r')).collect();
            StringMatcher::compile(&json!({"value": normalised, "not": f.not}))
        });
        Some(ClientCertificateMatcher {
            subject: nottable("subject"),
            issuer: nottable("issuer"),
            fingerprint,
            fingerprint_printed: given.map(|f| f.printed()).unwrap_or_default(),
        })
    }

    pub fn is_blank(&self) -> bool {
        [&self.subject, &self.issuer, &self.fingerprint].iter().all(|m| m.as_ref().is_none_or(StringMatcher::is_blank))
    }

    /// `matches(context, chain)`: `None` when the chain's leaf satisfies every criterion, else the one difference
    /// upstream records.
    pub fn difference(&self, chain: &[ClientCertificate]) -> Option<Difference> {
        if self.is_blank() {
            return None;
        }
        let fail = |message: &str, arguments: &[&str]| Some(Difference::Text(format_log_message(1, message, arguments)));
        let Some(leaf) = chain.first() else {
            return fail("client certificate match failed - request presented no client certificate chain but expectation requires one", &[]);
        };
        let dn = |k: &str| leaf.model.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        if let Some(subject) = self.subject.as_ref().filter(|m| !m.is_blank()) {
            let mut candidates = name_candidates(&dn("subjectDistinguishedName"));
            candidates.extend(subject_alternative_names(&leaf.der));
            if !matches_across_candidates(subject, &candidates) {
                return fail("client certificate subject match failed expected:{}found:{}", &[&subject.printed(), &java_list(&candidates)]);
            }
        }
        if let Some(issuer) = self.issuer.as_ref().filter(|m| !m.is_blank()) {
            let candidates = name_candidates(&dn("issuerDistinguishedName"));
            if !matches_across_candidates(issuer, &candidates) {
                return fail("client certificate issuer match failed expected:{}found:{}", &[&issuer.printed(), &java_list(&candidates)]);
            }
        }
        if let Some(fingerprint) = self.fingerprint.as_ref().filter(|m| !m.is_blank()) {
            let actual = sha256_fingerprint(&leaf.der);
            if !fingerprint.matches(&actual, true) {
                return fail("client certificate fingerprint match failed expected:{}found:{}", &[&self.fingerprint_printed, &actual]);
            }
        }
        None
    }
}

/// A distinguished name's CN and the name itself, each when not blank (`subjectCandidates` / `issuerCandidates`).
fn name_candidates(dn: &str) -> Vec<String> {
    [extract_common_name(dn), Some(dn.to_string())].into_iter().flatten().filter(|s| !s.trim().is_empty()).collect()
}

/// `extractCommonName`: the CN of an RFC 2253 name, `\`-escapes resolved; `None` without one.
fn extract_common_name(dn: &str) -> Option<String> {
    if dn.trim().is_empty() {
        return None;
    }
    let chars: Vec<char> = dn.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let start = i;
        let mut attribute = String::new();
        while i < chars.len() && chars[i] != '=' {
            attribute.push(chars[i]);
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        i += 1;
        let mut value = String::new();
        while i < chars.len() {
            match chars[i] {
                '\\' if i + 1 < chars.len() => {
                    value.push(chars[i + 1]);
                    i += 2;
                }
                ',' => break,
                c => {
                    value.push(c);
                    i += 1;
                }
            }
        }
        if i < chars.len() && chars[i] == ',' {
            i += 1;
        }
        if attribute.trim().eq_ignore_ascii_case("CN") {
            return Some(value.trim().to_string());
        }
        if start == i {
            break;
        }
    }
    None
}

/// The string-valued entries of `X509Certificate.getSubjectAlternativeNames()`, in extension order: DNS names,
/// e-mail addresses, URIs, directory names (`X500Name.getRFC2253Name`, as `X500Principal.getName()` prints a
/// subject), IP addresses (IPv6 as `Inet6Address.getHostAddress` prints it) and registered ids.
fn subject_alternative_names(der: &[u8]) -> Vec<String> {
    let Ok((_, cert)) = X509Certificate::from_der(der) else { return Vec::new() };
    let Ok(Some(extension)) = cert.subject_alternative_name() else { return Vec::new() };
    extension
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(s) | GeneralName::RFC822Name(s) | GeneralName::URI(s) => Some(s.to_string()),
            GeneralName::IPAddress(bytes) => match bytes.len() {
                4 => Some(bytes.iter().map(u8::to_string).collect::<Vec<_>>().join(".")),
                16 => Some(bytes.chunks(2).map(|p| format!("{:x}", u16::from_be_bytes([p[0], p[1]]))).collect::<Vec<_>>().join(":")),
                _ => None,
            },
            GeneralName::RegisteredID(oid) => Some(oid.to_id_string()),
            GeneralName::DirectoryName(name) => Some(crate::tls::client_cert::rfc2253(name)),
            _ => None,
        })
        .collect()
}

/// `sha256Fingerprint`: the SHA-256 of the certificate's DER encoding, lower-case hex.
fn sha256_fingerprint(der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, der).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(v: Value) -> ClientCertificateMatcher {
        ClientCertificateMatcher::compile(&v).expect("an object")
    }

    fn leaf(subject: &str, issuer: &str, der: &[u8]) -> ClientCertificate {
        ClientCertificate { der: der.to_vec(), model: json!({"subjectDistinguishedName": subject, "issuerDistinguishedName": issuer}) }
    }

    #[test]
    fn blank_criteria_match_without_a_chain() {
        assert!(matcher(json!({})).difference(&[]).is_none());
        assert!(matcher(json!({"subject": ""})).difference(&[]).is_none());
    }

    #[test]
    fn a_criterion_needs_a_chain() {
        for v in [json!({"subject": "my-client"}), json!({"fingerprintSha256": "fe:e4"})] {
            assert_eq!(
                matcher(v).difference(&[]).unwrap().hint_reason(),
                "  client certificate match failed - request presented no client certificate chain but expectation requires one"
            );
        }
    }

    #[test]
    fn common_name_extraction() {
        assert_eq!(extract_common_name("CN=my-client,OU=test,O=MockServer").as_deref(), Some("my-client"));
        assert_eq!(extract_common_name("O=MockServer,CN=a\\,b").as_deref(), Some("a,b"));
        assert_eq!(extract_common_name("O=MockServer"), None);
        assert_eq!(extract_common_name(""), None);
    }

    #[test]
    fn subject_and_issuer_candidates() {
        let chain = [leaf("CN=my-client,O=MockServer", "CN=ca,O=MockServer", b"not a certificate")];
        assert!(matcher(json!({"subject": "my-client"})).difference(&chain).is_none());
        assert!(matcher(json!({"subject": "CN=my-client,O=MockServer"})).difference(&chain).is_none());
        // A negation must hold for the CN and the full name alike.
        assert!(matcher(json!({"subject": "!my-client"})).difference(&chain).is_some());
        assert!(matcher(json!({"subject": "!other"})).difference(&chain).is_none());
        assert_eq!(
            matcher(json!({"issuer": "other"})).difference(&chain).unwrap().hint_reason(),
            "  client certificate issuer match failed expected:     other    found:     [ca, CN=ca,O=MockServer] "
        );
    }

    #[test]
    fn fingerprint_ignores_colons_whitespace_and_case() {
        let der = b"der bytes";
        let hex = sha256_fingerprint(der);
        let chain = [leaf("CN=a", "CN=b", der)];
        let colons: String = hex.to_uppercase().as_bytes().chunks(2).map(|p| std::str::from_utf8(p).unwrap()).collect::<Vec<_>>().join(": ");
        assert!(matcher(json!({"fingerprintSha256": colons})).difference(&chain).is_none());
        assert!(matcher(json!({"fingerprintSha256": format!("!{hex}")})).difference(&chain).is_some());
        assert_eq!(
            matcher(json!({"fingerprintSha256": "ab:cd"})).difference(&chain).unwrap().hint_reason(),
            format!("  client certificate fingerprint match failed expected:     ab:cd    found:     {hex} ")
        );
    }
}

//! A TLS client's certificates as MockServer models them (`JDKCertificateToMockServerX509Certificate`): serial
//! number in decimal, issuer and subject as `X500Principal.getName()` (RFC 2253) prints them, and the JCA name of
//! the signature algorithm.

use serde_json::{Map, Value};
use x509_parser::prelude::*;

/// A TLS client's certificate: its DER bytes and its model, as `X509CertificateSerializer` writes it.
#[derive(Debug, Clone)]
pub struct ClientCertificate {
    pub der: Vec<u8>,
    pub model: Value,
}

/// `None` when the certificate does not parse (upstream skips it).
pub fn describe(der: &[u8]) -> Option<ClientCertificate> {
    Some(ClientCertificate { der: der.to_vec(), model: model(der)? })
}

fn model(der: &[u8]) -> Option<Value> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let mut o = Map::new();
    o.insert("serialNumber".into(), cert.tbs_certificate.serial.to_str_radix(10).into());
    o.insert("issuerDistinguishedName".into(), rfc2253(cert.issuer()).into());
    o.insert("subjectDistinguishedName".into(), rfc2253(cert.subject()).into());
    o.insert("signatureAlgorithmName".into(), signature_algorithm(&cert.signature_algorithm.algorithm.to_id_string()).into());
    Some(Value::Object(o))
}

/// A PKIX trust manager's check of a client's chain: `end_entity` allows client auth and leads, through `intermediates`
/// (CA certificates, each used once), to a certificate signed by, or equal to, one of `anchors`.
pub fn chain_validates(end_entity: &[u8], intermediates: &[&[u8]], anchors: &[Vec<u8>]) -> bool {
    let Ok((_, leaf)) = X509Certificate::from_der(end_entity) else { return false };
    let anchors: Vec<X509Certificate> = anchors.iter().filter_map(|a| X509Certificate::from_der(a).ok().map(|(_, c)| c)).collect();
    let intermediates: Vec<X509Certificate> =
        intermediates.iter().filter_map(|i| X509Certificate::from_der(i).ok().map(|(_, c)| c)).collect();
    allows_client_auth(&leaf) && leads_to_anchor(&leaf, &intermediates, &mut vec![false; intermediates.len()], &anchors)
}

/// `MTLSAuthenticationHandler.validateClientCertificate` (upstream eef1d8e8b, 9.1.0): the client's own certificate is
/// not a CA, not self-signed and not itself a trust anchor; its key usage, when present, permits digitalSignature and
/// its extended key usage, when present, clientAuth; and a PKIX path leads from it, through `intermediates` (each a CA,
/// used once), to one of `anchors` (dates checked on every certificate but the anchor's, no revocation).
pub fn leaf_validates(end_entity: &[u8], intermediates: &[&[u8]], anchors: &[Vec<u8>]) -> bool {
    let Ok((_, leaf)) = X509Certificate::from_der(end_entity) else { return false };
    // `getBasicConstraints() != -1`: CA=true
    if leaf.is_ca() {
        return false;
    }
    let self_signed = same_name(leaf.subject(), leaf.issuer()) && leaf.verify_signature(None).is_ok();
    if self_signed || anchors.iter().any(|a| a.as_slice() == end_entity) {
        return false;
    }
    match leaf.key_usage() {
        Ok(Some(usage)) if !usage.value.digital_signature() => return false,
        Err(_) => return false,
        _ => {}
    }
    let anchors: Vec<X509Certificate> = anchors.iter().filter_map(|a| X509Certificate::from_der(a).ok().map(|(_, c)| c)).collect();
    let intermediates: Vec<X509Certificate> =
        intermediates.iter().filter_map(|i| X509Certificate::from_der(i).ok().map(|(_, c)| c)).collect();
    allows_client_auth(&leaf) && leads_to_anchor(&leaf, &intermediates, &mut vec![false; intermediates.len()], &anchors)
}

fn leads_to_anchor(cert: &X509Certificate, intermediates: &[X509Certificate], used: &mut Vec<bool>, anchors: &[X509Certificate]) -> bool {
    if anchors.iter().any(|a| a.as_raw() == cert.as_raw() || issued_by(cert, a)) {
        return true;
    }
    for (i, next) in intermediates.iter().enumerate() {
        if used[i] || !next.is_ca() || !issued_by(cert, next) {
            continue;
        }
        used[i] = true;
        if leads_to_anchor(next, intermediates, used, anchors) {
            return true;
        }
        used[i] = false;
    }
    false
}

/// Issuer name (compared as `X500Principal.equals` does), validity and signature.
fn issued_by(cert: &X509Certificate, issuer: &X509Certificate) -> bool {
    same_name(cert.issuer(), issuer.subject()) && cert.validity().is_valid() && cert.verify_signature(Some(issuer.public_key())).is_ok()
}

/// No extended key usage extension allows any use; otherwise clientAuth or anyExtendedKeyUsage is needed.
fn allows_client_auth(cert: &X509Certificate) -> bool {
    match cert.extended_key_usage() {
        Ok(Some(eku)) => eku.value.client_auth || eku.value.any,
        Ok(None) => true,
        Err(_) => false,
    }
}

/// `X500Principal.equals`: the RFC 2253 canonical forms match, so a PrintableString and a UTF8String with the same
/// text are the same attribute, and case and repeated spaces do not matter.
pub(crate) fn same_name(a: &X509Name, b: &X509Name) -> bool {
    fn canonical(name: &X509Name) -> Vec<Vec<(String, String)>> {
        name.iter()
            .map(|rdn| {
                let mut attrs: Vec<(String, String)> = rdn
                    .iter()
                    .map(|attr| {
                        let value = match attr.as_str() {
                            Ok(text) => text.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase(),
                            Err(_) => format!("#{}", der_hex(attr.attr_value())),
                        };
                        (attr.attr_type().to_id_string(), value)
                    })
                    .collect();
                attrs.sort();
                attrs
            })
            .collect()
    }
    a.as_raw() == b.as_raw() || canonical(a) == canonical(b)
}

/// The certificates of a PEM file, as DER.
pub fn pem_chain(text: &str) -> Vec<Vec<u8>> {
    x509_parser::pem::Pem::iter_from_buffer(text.as_bytes()).filter_map(Result::ok).filter(|p| p.label == "CERTIFICATE").map(|p| p.contents).collect()
}

/// `X500Principal.getName()` (`X500Name.getRFC2253Name`): RDNs last to first, multi-valued ones joined with `+`,
/// known attribute types by keyword and others, or values that are not strings, as `OID=#<DER hex>`.
pub(crate) fn rfc2253(name: &X509Name) -> String {
    let rdns: Vec<String> = name
        .iter()
        .map(|rdn| {
            rdn.iter()
                .map(|attr| {
                    let oid = attr.attr_type().to_id_string();
                    match (keyword(&oid), attr.as_str()) {
                        (Some(k), Ok(value)) => format!("{k}={}", escape(value)),
                        (k, _) => format!("{}=#{}", k.unwrap_or(&oid), der_hex(attr.attr_value())),
                    }
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect();
    rdns.into_iter().rev().collect::<Vec<_>>().join(",")
}

fn keyword(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "STREET",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "0.9.2342.19200300.100.1.25" => "DC",
        "0.9.2342.19200300.100.1.1" => "UID",
        _ => return None,
    })
}

/// `AVA.toRFC2253String` escaping: `,=+<>#;"\` anywhere, NUL as `\00`, and every leading and trailing space or CR.
fn escape(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let lead = chars.iter().position(|c| !matches!(c, ' ' | '\r')).unwrap_or(chars.len());
    let trail = chars.iter().rposition(|c| !matches!(c, ' ' | '\r'));
    let mut out = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if c == '\0' {
            out.push_str("\\00");
            continue;
        }
        if ",=+<>#;\"\\".contains(c) || i < lead || trail.is_none_or(|t| i > t) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The attribute value's whole DER encoding (tag, length and contents) in hex, as `DerValue.toByteArray` gives it.
fn der_hex(value: &x509_parser::asn1_rs::Any) -> String {
    let header = &value.header;
    let mut der = Vec::new();
    match header.raw_tag() {
        Some(raw) => der.extend_from_slice(raw),
        None => der.push(((header.class() as u8) << 6) | if header.is_constructed() { 0x20 } else { 0 } | (header.tag().0 as u8 & 0x1f)),
    }
    let length = value.data.len();
    if length < 0x80 {
        der.push(length as u8);
    } else {
        let bytes: Vec<u8> = length.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
        der.push(0x80 | bytes.len() as u8);
        der.extend(bytes);
    }
    der.extend_from_slice(value.data);
    der.iter().map(|b| format!("{b:02x}")).collect()
}

/// `X509Certificate.getSigAlgName()` for the algorithms certificates are signed with.
fn signature_algorithm(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.5" => "SHA1withRSA",
        "1.2.840.113549.1.1.11" => "SHA256withRSA",
        "1.2.840.113549.1.1.12" => "SHA384withRSA",
        "1.2.840.113549.1.1.13" => "SHA512withRSA",
        "1.2.840.113549.1.1.14" => "SHA224withRSA",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.4.1" => "SHA1withECDSA",
        "1.2.840.10045.4.3.2" => "SHA256withECDSA",
        "1.2.840.10045.4.3.3" => "SHA384withECDSA",
        "1.2.840.10045.4.3.4" => "SHA512withECDSA",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        other => return other.to_string(),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(name: &str) -> Vec<u8> {
        let pem = std::fs::read_to_string(format!("{}/tests/files/tls/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        pem_chain(&pem).remove(0)
    }

    #[test]
    fn issuer_matches_subject_across_string_encodings() {
        // leaf-cert.pem's issuer is PrintableString, ca.pem's subject UTF8String (upstream fixtures, Apache-2.0).
        assert!(leaf_validates(&der("leaf-cert.pem"), &[], &[der("ca.pem")]));
        assert!(!leaf_validates(&der("leaf-cert.pem"), &[], &[der("separate-ca.pem")]));
    }

    #[test]
    fn chains_to_an_anchor_directly_through_an_intermediate_or_as_the_anchor() {
        let (leaf, ca, other) = (der("leaf-cert.pem"), der("ca.pem"), der("separate-ca.pem"));
        assert!(chain_validates(&leaf, &[], std::slice::from_ref(&ca)));
        assert!(chain_validates(&leaf, &[&ca], &[other.clone(), ca.clone()]));
        assert!(chain_validates(&leaf, &[], std::slice::from_ref(&leaf)));
        assert!(!chain_validates(&leaf, &[], std::slice::from_ref(&other)));
        assert!(!chain_validates(&der("separate-leaf-cert.pem"), &[&other], &[ca]));
    }
}

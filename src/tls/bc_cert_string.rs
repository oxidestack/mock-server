//! A generated leaf's `toString` as MockServer's TRACE `created new X509{}with SAN Domain Names{}and IPs{}` entry
//! prints it: `BCKeyAndCertificateFactory` signs the leaf with BouncyCastle 1.86's `JcaX509CertificateConverter`, so
//! the object is BouncyCastle's `X509CertificateObject` (`X509CertificateImpl.toString`), with `X509Principal` names,
//! `Date.toString` in the image's GMT, a `BCRSAPublicKey` and `ASN1Dump` for the extensions it has no class for.
//! Checked against `tests/files/x509/bc-tostring` (a leaf the 8.0.0 oracle served, and the text it
//! logged for it).
//!
//! Ported: what a leaf MockServer generates carries (RSA keys, RSA and ECDSA signatures, the ASN.1 forms of its
//! extensions). Another key type gives `None`.

use super::cert_string::{date, items, oid, tlv, Tlv};
use num_bigint::{BigInt, BigUint};

/// `X509Name.DefaultSymbols`' names for the attribute types, else the dotted identifier.
fn symbol(id: &str) -> String {
    match id {
        "2.5.4.6" => "C",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "T",
        "2.5.4.3" => "CN",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.5" => "SERIALNUMBER",
        "2.5.4.9" => "STREET",
        "1.2.840.113549.1.9.1" => "E",
        "0.9.2342.19200300.100.1.25" => "DC",
        "0.9.2342.19200300.100.1.1" => "UID",
        _ => return id.to_string(),
    }
    .to_string()
}

/// `IETFUtils.valueToString` of a string value: the special characters escaped with a backslash, as are a leading
/// `#` or space and a trailing space.
fn escaped(value: &str) -> String {
    let mut out = String::new();
    for c in value.chars() {
        if matches!(c, ',' | '"' | '\\' | '+' | '=' | '<' | '>' | ';') {
            out.push('\\');
        }
        out.push(c);
    }
    if out.starts_with('#') || out.starts_with(' ') {
        out.insert(0, '\\');
    }
    if out.len() > 1 && out.ends_with(' ') && !out.ends_with("\\ ") {
        out.insert(out.len() - 1, '\\');
    }
    out
}

/// `X509Name.toString`: the RDNs in encoding order, `,`-separated (`+` within one).
fn x509_name(content: &[u8]) -> Option<String> {
    let mut rdns = Vec::new();
    for rdn in items(content)? {
        let mut avas = Vec::new();
        for ava in items(rdn.content)? {
            let parts = items(ava.content)?;
            let id = oid(parts.first()?.content)?;
            let value = parts.get(1)?;
            let text = match value.tag {
                0x0c | 0x13 | 0x16 | 0x14 => escaped(&String::from_utf8_lossy(value.content)),
                _ => format!("#{}", hex(value.raw)),
            };
            avas.push(format!("{}={text}", symbol(&id)));
        }
        rdns.push(avas.join("+"));
    }
    Some(rdns.join(","))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `X509SignatureUtil.getSignatureName`.
fn signature_name(id: &str) -> String {
    match id {
        "1.2.840.113549.1.1.5" => "SHA1WITHRSA",
        "1.2.840.113549.1.1.11" => "SHA256WITHRSA",
        "1.2.840.113549.1.1.12" => "SHA384WITHRSA",
        "1.2.840.113549.1.1.13" => "SHA512WITHRSA",
        "1.2.840.10045.4.3.2" => "SHA256WITHECDSA",
        "1.2.840.10045.4.3.3" => "SHA384WITHECDSA",
        "1.2.840.10045.4.3.4" => "SHA512WITHECDSA",
        _ => return id.to_string(),
    }
    .to_string()
}

/// `BCRSAPublicKey.toString`, `None` for another key type.
fn public_key(info: &Tlv) -> Option<String> {
    let parts = items(info.content)?;
    let algorithm = items(parts.first()?.content)?;
    if oid(algorithm.first()?.content)? != "1.2.840.113549.1.1.1" {
        return None;
    }
    let (sequence, _) = tlv(parts.get(1)?.content.get(1..)?)?;
    let numbers = items(sequence.content)?;
    let modulus = BigUint::from_bytes_be(numbers.first()?.content);
    let exponent = BigUint::from_bytes_be(numbers.get(1)?.content);
    Some(format!(
        "RSA Public Key [{}],[{}]\n        modulus: {}\npublic exponent: {}\n",
        // `RSAUtil.generateKeyFingerprint` / `generateExponentFingerprint`: `BigInteger.toByteArray`, sign byte included
        super::key_string::fingerprint(&BigInt::from(modulus.clone()).to_signed_bytes_be(), 20),
        super::key_string::fingerprint(&BigInt::from(exponent.clone()).to_signed_bytes_be(), 4),
        modulus.to_str_radix(16),
        exponent.to_str_radix(16),
    ))
}

/// `ASN1Util.getTagText`.
fn tag_text(tag: u8) -> String {
    let class = match tag & 0xc0 {
        0x00 => "UNIVERSAL",
        0x40 => "APPLICATION",
        0x80 => "CONTEXT",
        _ => "PRIVATE",
    };
    format!("[{class} {}]", tag & 0x1f)
}

/// `ASN1Dump.dumpAsString` (not verbose) of one element, at `indent`.
fn dump(indent: &str, item: &Tlv, out: &mut String) {
    const TAB: &str = "    ";
    let deeper = format!("{indent}{TAB}");
    let children = |out: &mut String, content: &[u8]| {
        for child in items(content).unwrap_or_default() {
            dump(&deeper, &child, out);
        }
    };
    if item.tag & 0xc0 != 0 {
        // `ASN1InputStream`: an implicitly tagged primitive is read as an octet string; a constructed tag holding one
        // element as that element explicitly tagged, else (implicitly) as a sequence of its elements
        let elements = if item.tag & 0x20 != 0 { items(item.content).unwrap_or_default() } else { Vec::new() };
        if elements.len() == 1 {
            out.push_str(&format!("{indent}Tagged {}\n", tag_text(item.tag)));
            dump(&deeper, &elements[0], out);
        } else {
            out.push_str(&format!("{indent}Tagged {} IMPLICIT\n", tag_text(item.tag)));
            if item.tag & 0x20 != 0 {
                out.push_str(&format!("{deeper}Sequence\n"));
                for element in &elements {
                    dump(&format!("{deeper}{TAB}"), element, out);
                }
            } else {
                out.push_str(&format!("{deeper}DER Octet String[{}]\n", item.content.len()));
            }
        }
        return;
    }
    match item.tag {
        0x30 => {
            out.push_str(&format!("{indent}Sequence\n"));
            children(out, item.content);
        }
        0x31 => {
            out.push_str(&format!("{indent}Set\n"));
            children(out, item.content);
        }
        0x06 => out.push_str(&format!("{indent}ObjectIdentifier({})\n", oid(item.content).unwrap_or_default())),
        0x04 => out.push_str(&format!("{indent}DER Octet String[{}]\n", item.content.len())),
        0x02 => out.push_str(&format!("{indent}Integer({})\n", BigInt::from_signed_bytes_be(item.content))),
        0x01 => out.push_str(&format!("{indent}Boolean({})\n", item.content.first().is_some_and(|&b| b != 0))),
        0x05 => out.push_str(&format!("{indent}NULL\n")),
        0x03 => {
            let pad = item.content.first().copied().unwrap_or(0);
            out.push_str(&format!("{indent}DER Bit String[{}, {pad}] \n", item.content.len().saturating_sub(1)));
        }
        0x0c => out.push_str(&format!("{indent}UTF8String({}) \n", String::from_utf8_lossy(item.content))),
        0x13 => out.push_str(&format!("{indent}PrintableString({}) \n", String::from_utf8_lossy(item.content))),
        0x16 => out.push_str(&format!("{indent}IA5String({}) \n", String::from_utf8_lossy(item.content))),
        tag => out.push_str(&format!("{indent}Unknown {tag:#x}\n")),
    }
}

/// One extension's line(s): `critical(…) ` then BasicConstraints and KeyUsage by their classes' `toString`, any other
/// as its identifier and `value = ` its dump.
fn extension(item: &Tlv) -> Option<String> {
    let parts = items(item.content)?;
    let id = oid(parts.first()?.content)?;
    let (critical, value) = match (parts.get(1), parts.get(2)) {
        (Some(b), Some(v)) if b.tag == 0x01 => (b.content.first().is_some_and(|&x| x != 0), v),
        (Some(v), None) => (false, v),
        _ => return None,
    };
    let (inner, _) = tlv(value.content)?;
    let text = match id.as_str() {
        "2.5.29.19" => {
            let fields = items(inner.content)?;
            let ca = fields.first().filter(|f| f.tag == 0x01).is_some_and(|f| f.content.first().is_some_and(|&b| b != 0));
            match fields.iter().find(|f| f.tag == 0x02) {
                Some(length) => format!("BasicConstraints: isCa({ca}), pathLenConstraint = {}", BigInt::from_signed_bytes_be(length.content)),
                None => format!("BasicConstraints: isCa({ca})"),
            }
        }
        "2.5.29.15" => {
            // `DERBitString.getBytes`: the unused bits cleared
            let pad = *inner.content.first()?;
            let mut data = inner.content.get(1..)?.to_vec();
            if let Some(last) = data.last_mut() {
                *last &= 0xffu8 << pad.min(7);
            }
            match data.as_slice() {
                [one] => format!("KeyUsage: 0x{one:x}"),
                [first, second, ..] => format!("KeyUsage: 0x{:x}", (u32::from(*second) << 8) | u32::from(*first)),
                [] => "KeyUsage: 0x0".to_string(),
            }
        }
        _ => {
            let mut dumped = String::new();
            dump("", &inner, &mut dumped);
            format!("{id} value = {dumped}")
        }
    };
    Some(format!("                       critical({critical}) {text}\n"))
}

/// `X509CertificateImpl.toString` of a DER certificate, `None` when it does not parse or its key is not RSA.
pub fn certificate_to_string(der: &[u8]) -> Option<String> {
    let (certificate, _) = tlv(der)?;
    let outer = items(certificate.content)?;
    let tbs = items(outer.first()?.content)?;
    let signature_algorithm = signature_name(&oid(items(outer.get(1)?.content)?.first()?.content)?);
    let signature = outer.get(2)?.content.get(1..)?;
    let mut at = 0;
    let version = match tbs.first()? {
        v if v.tag == 0xa0 => {
            at = 1;
            BigInt::from_signed_bytes_be(tlv(v.content)?.0.content) + 1
        }
        _ => BigInt::from(1),
    };
    let serial = BigInt::from_signed_bytes_be(tbs.get(at)?.content);
    let issuer = x509_name(tbs.get(at + 2)?.content)?;
    let validity = items(tbs.get(at + 3)?.content)?;
    let subject = x509_name(tbs.get(at + 4)?.content)?;
    let key = public_key(tbs.get(at + 5)?)?;
    let mut out = format!(
        "  [0]         Version: {version}\n         SerialNumber: {serial}\n             IssuerDN: {issuer}\n           Start Date: {}\n           Final Date: {}\n            SubjectDN: {subject}\n           Public Key: {key}\n  Signature Algorithm: {signature_algorithm}\n",
        date(validity.first()?)?,
        date(validity.get(1)?)?,
    );
    // `X509SignatureUtil.prettyPrintSignature`: 20 bytes a line
    for (i, line) in signature.chunks(20).enumerate() {
        out.push_str(if i == 0 { "            Signature: " } else { "                       " });
        out.push_str(&hex(line));
        out.push('\n');
    }
    for part in &tbs[at + 6..] {
        if part.tag == 0xa3 {
            let (sequence, _) = tlv(part.content)?;
            let extensions = items(sequence.content)?;
            if !extensions.is_empty() {
                out.push_str("       Extensions: \n");
            }
            for item in &extensions {
                out.push_str(&extension(item)?);
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A leaf the 8.0.0 oracle generated and served, against the text its TRACE entry logged for it.
    #[test]
    fn matches_bouncycastle() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/x509/bc-tostring");
        let der = super::super::client_cert::pem_chain(&std::fs::read_to_string(dir.join("leaf.pem")).expect("pem")).remove(0);
        let expected = std::fs::read_to_string(dir.join("leaf.txt")).expect("expected text");
        assert_eq!(certificate_to_string(&der).as_deref(), Some(expected.as_str()));
    }
}

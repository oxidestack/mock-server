//! `X509Certificate.toString` as the oracle's JDK (Temurin 26.0.2, SUN provider) prints it: `X509CertImpl` over
//! `X509CertInfo`, with Sun's key classes, `X500Name`, `Date.toString` in the image's GMT and the extension classes
//! `OIDMap` names. MockServer's DEBUG `loaded CA X509 from path{}containing PEM{}as{}` carries it.
//!
//! Ported: RSA, RSASSA-PSS and DSA keys, EC keys on every `CurveDB` curve (each also under the alias OIDs the JDK
//! reads, and the ECDH/ECMQV OIDs it refuses), EdDSA and other keys as `X509Key` prints them, RSASSA-PSS,
//! DSA and OAEP parameters, every name and string form `X500Name`/`AVA` prints, and the
//! extension classes `OIDMap` names (among them PrivateKeyUsage, NameConstraints, PolicyMappings,
//! PolicyConstraints, InhibitAnyPolicy, NetscapeCertType, OCSPNoCheck and the CRL-only classes a certificate can carry).
//! Other parameters print as `params unparsed` (listed in docs/divergences.md). An extension its class refuses (the
//! constructor's exception from `x509::extension`) is left out of `Certificate Extensions` and listed under
//! `Unparseable certificate extensions` as `UnparseableExtension.toString` when non-critical; a critical one fails the
//! certificate. Checked against `tests/files/x509/tostring` (`ToStringGen.java` on OpenJDK 25, whose
//! layout is 26.0.2's).

use num_bigint::{BigInt, BigUint};
use std::collections::BTreeMap;

/// One DER element: its tag, its content and its whole encoding.
#[derive(Clone, Copy)]
pub(super) struct Tlv<'a> {
    pub(super) tag: u8,
    pub(super) content: &'a [u8],
    pub(super) raw: &'a [u8],
}

/// The first element of `input` (definite lengths only) and what follows it.
pub(super) fn tlv(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *input.first()?;
    let first = *input.get(1)? as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let count = first & 0x7f;
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for &b in input.get(2..2 + count)? {
            len = (len << 8) | b as usize;
        }
        (len, 2 + count)
    };
    let end = header.checked_add(len)?;
    let content = input.get(header..end)?;
    Some((Tlv { tag, content, raw: &input[..end] }, &input[end..]))
}

/// The elements of a constructed value's content.
pub(super) fn items(mut content: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (item, rest) = tlv(content)?;
        out.push(item);
        content = rest;
    }
    Some(out)
}

/// The dotted form of an OBJECT IDENTIFIER's content (`ObjectIdentifier.toString`).
pub(super) fn oid(content: &[u8]) -> Option<String> {
    let mut arcs: Vec<BigUint> = Vec::new();
    let mut current = BigUint::from(0u8);
    for &b in content {
        current = (current << 7) | BigUint::from(b & 0x7f);
        if b & 0x80 == 0 {
            arcs.push(std::mem::take(&mut current));
        }
    }
    let first = arcs.first()?.clone();
    let (a, b) = if first < BigUint::from(40u8) {
        (BigUint::from(0u8), first)
    } else if first < BigUint::from(80u8) {
        (BigUint::from(1u8), first - 40u8)
    } else {
        (BigUint::from(2u8), first - 80u8)
    };
    let mut out = format!("{a}.{b}");
    for arc in &arcs[1..] {
        out.push('.');
        out.push_str(&arc.to_string());
    }
    Some(out)
}

/// `HexDumpEncoder.encodeBuffer`: 16 bytes a line, offset, hex pairs split after eight, the printable ASCII.
pub fn hex_dump(data: &[u8]) -> String {
    let mut out = String::new();
    for (line, chunk) in data.chunks(16).enumerate() {
        out.push_str(&format!("{:04X}: ", (line * 16) & 0xffff));
        for (i, b) in chunk.iter().enumerate() {
            out.push_str(&format!("{b:02X} "));
            if i == 7 {
                out.push_str("  ");
            }
        }
        for i in chunk.len()..16 {
            out.push_str("   ");
            if i == 7 {
                out.push_str("  ");
            }
        }
        out.push(' ');
        for &b in chunk {
            // signed bytes: anything below ' ' (negative included) or above 'z' prints as '.'
            out.push(if (b as i8) < b' ' as i8 || b > b'z' { '.' } else { b as char });
        }
        out.push('\n');
    }
    out
}

/// `Debug.toString(BigInteger)`: the two's-complement bytes, lower-case hex, colon-separated.
fn colon_hex(value: &BigInt) -> String {
    value.to_signed_bytes_be().iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// Java's `List.toString`.
fn list(items: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", items.into_iter().collect::<Vec<_>>().join(", "))
}

/// `AlgorithmId.toString`: the KnownOIDs name (or the OID) and, for parameters other than NULL, the parsed form the
/// name's `AlgorithmParameters` print: `PSSParameterSpec.toString` for RSASSA-PSS, `DSAParameters.toString` for DSA
/// (OIW's DSA OID too), `OAEPParameters.toString` for OAEP, else `params unparsed`.
fn algorithm(item: &Tlv) -> Option<(String, String)> {
    let parts = items(item.content)?;
    let id = oid(parts.first()?.content)?;
    let name = algorithm_name(&id);
    let params = match parts.get(1) {
        None => String::new(),
        Some(p) if p.tag == 0x05 => String::new(),
        Some(p) => {
            let parsed = match name.as_str() {
                "RSASSA-PSS" => pss_parameters(p),
                "DSA" => dsa_parameters(p).map(|(p, q, g)| format!("\n\tp: {}\n\tq: {}\n\tg: {}\n", debug_hex(&p), debug_hex(&q), debug_hex(&g))),
                "OAEP" => oaep_parameters(p),
                _ => None,
            };
            format!(", {}", parsed.as_deref().unwrap_or("params unparsed"))
        }
    };
    Some((format!("{name}{params}"), id))
}

/// `AlgorithmId.getName`: the KnownOIDs name, else the OID.
fn algorithm_name(id: &str) -> String {
    // BouncyCastle's provider names the SLH-DSA signature algorithms
    if let Some((name, _)) = super::key_math::slh_dsa(id) {
        return name.to_string();
    }
    super::known_oids::std_name(id).map_or_else(|| id.to_string(), str::to_string)
}

/// `PSSParameters.engineInit` (the PKCS #1 defaults SHA-1, MGF1 with SHA-1, salt 20, trailer 1, overridden by the
/// fields present), printed as `PSSParameterSpec.toString`; `None` for parameters the JDK refuses.
fn pss_parameters(params: &Tlv) -> Option<String> {
    const MGF1_DIGESTS: [&str; 11] = [
        "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256", "SHA3-224", "SHA3-256",
        "SHA3-384", "SHA3-512",
    ];
    if params.tag != 0x30 {
        return None;
    }
    let digest = |item: &Tlv| -> Option<String> { Some(algorithm_name(&oid(items(item.content)?.first()?.content)?)) };
    let (mut hash, mut mgf, mut salt, mut trailer) = ("SHA-1".to_string(), "SHA-1".to_string(), BigInt::from(20), BigInt::from(1));
    for field in items(params.content)? {
        let (inner, _) = tlv(field.content)?;
        match field.tag {
            0xa0 => hash = digest(&inner)?,
            0xa1 => {
                let parts = items(inner.content)?;
                if oid(parts.first()?.content)? != "1.2.840.113549.1.1.8" {
                    return None;
                }
                mgf = digest(parts.get(1)?)?;
                if !MGF1_DIGESTS.contains(&mgf.as_str()) {
                    return None;
                }
            }
            0xa2 => salt = BigInt::from_signed_bytes_be(inner.content),
            0xa3 => trailer = BigInt::from_signed_bytes_be(inner.content),
            _ => return None,
        }
    }
    if salt < BigInt::from(0) || salt > BigInt::from(i32::MAX) || trailer != BigInt::from(1) {
        return None;
    }
    Some(format!("PSSParameterSpec[hashAlgorithm={hash}, maskGenAlgorithm=MGF1ParameterSpec[hashAlgorithm={mgf}], saltLength={salt}, trailerField={trailer}]"))
}

/// `OAEPParameters.engineInit` (the PKCS #1 defaults SHA-1, MGF1 with SHA-1 and an empty `PSpecified` label,
/// overridden by the fields present), printed as `OAEPParameters.engineToString`; `None` for parameters it refuses.
fn oaep_parameters(params: &Tlv) -> Option<String> {
    const MGF1_DIGESTS: [&str; 11] = [
        "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256", "SHA3-224", "SHA3-256",
        "SHA3-384", "SHA3-512",
    ];
    if params.tag != 0x30 {
        return None;
    }
    let (mut hash, mut mgf, mut label) = ("SHA-1".to_string(), "SHA-1".to_string(), Vec::new());
    for field in items(params.content)? {
        let (inner, _) = tlv(field.content)?;
        let parts = items(inner.content)?;
        let id = oid(parts.first()?.content)?;
        match field.tag {
            0xa0 => hash = algorithm_name(&id),
            0xa1 => {
                (id == "1.2.840.113549.1.1.8").then_some(())?;
                mgf = algorithm_name(&oid(items(parts.get(1)?.content)?.first()?.content)?);
                MGF1_DIGESTS.contains(&mgf.as_str()).then_some(())?;
            }
            0xa2 => {
                (id == "1.2.840.113549.1.1.9").then_some(())?;
                let value = parts.get(1).filter(|v| v.tag == 0x04)?;
                label = value.content.to_vec();
            }
            _ => return None,
        }
    }
    let label = if label.is_empty() { String::new() } else { debug_hex(&BigInt::from_signed_bytes_be(&label)) };
    Some(format!("MD: {hash}\nMGF: MGF1{mgf}\nPSource: PSpecified {label}\n"))
}

/// The p, q and g of DSA parameters (`Dss-Parms`).
fn dsa_parameters(params: &Tlv) -> Option<(BigInt, BigInt, BigInt)> {
    let parts = items(params.content)?;
    let int = |i: usize| -> Option<BigInt> { parts.get(i).filter(|p| p.tag == 0x02).map(|p| BigInt::from_signed_bytes_be(p.content)) };
    Some((int(0)?, int(1)?, int(2)?))
}

/// `sun.security.util.Debug.toHexString(BigInteger)`: four spaces (or `   -`), the hex digits in eight-digit words,
/// eight words a line.
fn debug_hex(value: &BigInt) -> String {
    let text = value.magnitude().to_str_radix(16);
    let text = if text.len() % 2 == 1 { format!("0{text}") } else { text };
    let mut out = String::from(if value.sign() == num_bigint::Sign::Minus { "   -" } else { "    " });
    let mut i = 0;
    while i < text.len() {
        out.push_str(&text[i..i + 2]);
        i += 2;
        if i != text.len() {
            if i % 64 == 0 {
                out.push_str("\n    ");
            } else if i % 8 == 0 {
                out.push(' ');
            }
        }
    }
    out
}

/// `java.util.Date.toString` in GMT of an UTCTime or GeneralizedTime.
pub(super) fn date(item: &Tlv) -> Option<String> {
    let text = std::str::from_utf8(item.content).ok()?;
    let text = text.strip_suffix('Z')?;
    let (year, rest) = if item.tag == 0x17 {
        let yy: i32 = text.get(..2)?.parse().ok()?;
        (if yy < 50 { 2000 + yy } else { 1900 + yy }, text.get(2..)?)
    } else {
        (text.get(..4)?.parse().ok()?, text.get(4..)?)
    };
    let field = |i: usize| -> Option<u32> { rest.get(i..i + 2)?.parse().ok() };
    let seconds = if rest.len() >= 10 { field(8)? } else { 0 };
    let at = chrono::NaiveDate::from_ymd_opt(year, field(0)?, field(2)?)?.and_hms_opt(field(4)?, field(6)?, seconds)?;
    Some(at.format("%a %b %d %H:%M:%S GMT %Y").to_string())
}

/// `AVAKeyword.getKeyword(oid, DEFAULT)`.
fn keyword(id: &str) -> String {
    match id {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "T",
        "1.3.6.1.4.1.42.2.11.2.1" => "IP",
        "2.5.4.9" => "STREET",
        "0.9.2342.19200300.100.1.25" => "DC",
        "2.5.4.46" => "DNQ",
        "2.5.4.4" => "SURNAME",
        "2.5.4.42" => "GIVENNAME",
        "2.5.4.43" => "INITIALS",
        "2.5.4.44" => "GENERATION",
        "1.2.840.113549.1.9.1" => "EMAILADDRESS",
        "0.9.2342.19200300.100.1.1" => "UID",
        "2.5.4.5" => "SERIALNUMBER",
        other => return format!("OID.{other}"),
    }
    .to_string()
}

/// `DerValue.getAsString`: the directory string types, decoded as the JDK does.
fn der_string(value: &Tlv) -> Option<String> {
    let latin1 = || value.content.iter().map(|&b| b as char).collect::<String>();
    Some(match value.tag {
        0x0c => String::from_utf8_lossy(value.content).into_owned(),
        0x13 | 0x14 | 0x16 | 0x1b => latin1(),
        0x1e => {
            let units: Vec<u16> = value.content.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])).collect();
            String::from_utf16_lossy(&units)
        }
        0x1c => value
            .content
            .chunks(4)
            .map(|c| {
                let mut b = [0u8; 4];
                b[..c.len()].copy_from_slice(c);
                char::from_u32(u32::from_be_bytes(b)).unwrap_or('\u{fffd}')
            })
            .collect(),
        _ => return None,
    })
}

fn printable(c: char) -> bool {
    c.is_ascii_alphanumeric() || " '()+,-./:=?".contains(c)
}

/// `AVA.toString` (`toKeywordValueString` without the `ava` debug option).
fn ava(item: &Tlv) -> Option<String> {
    let parts = items(item.content)?;
    let mut out = keyword(&oid(parts.first()?.content)?);
    out.push('=');
    let value = parts.get(1)?;
    let Some(text) = der_string(value) else {
        out.push('#');
        out.extend(value.raw.iter().map(|b| format!("{b:02x}")));
        return Some(out);
    };
    let escapees = ",+=\n<>#;\\\"";
    let chars: Vec<char> = text.encode_utf16().map(|u| char::from_u32(u as u32).unwrap_or('\u{fffd}')).collect();
    // `text` as UTF-16 code units, as Java walks it (a surrogate is neither printable nor an escapee)
    let units: Vec<u16> = text.encode_utf16().collect();
    let length = units.len();
    let already_quoted = length > 1 && units[0] == b'"' as u16 && units[length - 1] == b'"' as u16;
    let mut quote_needed = false;
    let mut previous_white = false;
    let mut buffer: Vec<u16> = Vec::new();
    for (i, &unit) in units.iter().enumerate() {
        let c = chars[i];
        if already_quoted && (i == 0 || i == length - 1) {
            buffer.push(unit);
            continue;
        }
        let ascii = unit < 0x80;
        if ascii && (printable(c) || escapees.contains(c)) {
            if !quote_needed && ((i == 0 && (c == ' ' || c == '\n')) || escapees.contains(c)) {
                quote_needed = true;
            }
            if !(c == ' ' || c == '\n') {
                if c == '"' || c == '\\' {
                    buffer.push(b'\\' as u16);
                }
                previous_white = false;
            } else {
                if !quote_needed && previous_white {
                    quote_needed = true;
                }
                previous_white = true;
            }
            buffer.push(unit);
        } else {
            previous_white = false;
            buffer.push(unit);
        }
    }
    if let Some(&last) = buffer.last() && (last == b' ' as u16 || last == b'\n' as u16) {
        quote_needed = true;
    }
    let body = String::from_utf16_lossy(&buffer);
    if !already_quoted && quote_needed {
        out.push('"');
        out.push_str(&body);
        out.push('"');
    } else {
        out.push_str(&body);
    }
    Some(out)
}

/// `RDN.toString`: its assertions joined by ` + `.
fn rdn(item: &Tlv) -> Option<String> {
    Some(items(item.content)?.iter().map(ava).collect::<Option<Vec<_>>>()?.join(" + "))
}

/// `X500Name.toString`: the RDNs in reverse order, joined by `, `.
fn x500_name(content: &[u8]) -> Option<String> {
    let rdns = items(content)?.iter().map(rdn).collect::<Option<Vec<_>>>()?;
    Some(rdns.into_iter().rev().collect::<Vec<_>>().join(", "))
}

/// `InetAddress.getHostAddress` of four or sixteen bytes.
fn host_address(bytes: &[u8]) -> String {
    if bytes.len() == 4 {
        bytes.iter().map(u8::to_string).collect::<Vec<_>>().join(".")
    } else {
        bytes.chunks(2).map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]]))).collect::<Vec<_>>().join(":")
    }
}

/// `GeneralName.toString`.
fn general_name(item: &Tlv) -> Option<String> {
    let text = |content: &[u8]| content.iter().map(|&b| b as char).collect::<String>();
    Some(match item.tag {
        0xa0 => format!("Other-Name: Unrecognized ObjectIdentifier: {}", oid(items(item.content)?.first()?.content)?),
        0x81 => format!("RFC822Name: {}", text(item.content)),
        0x82 => format!("DNSName: {}", text(item.content)),
        0xa3 => "X400Address: <DER-encoded value>".to_string(),
        0xa4 => x500_name(tlv(item.content)?.0.content)?,
        0x86 => format!("URIName: {}", text(item.content)),
        0x87 => {
            let a = item.content;
            let name = match a.len() {
                4 | 16 => host_address(a),
                8 => format!("{}/{}", host_address(&a[..4]), host_address(&a[4..])),
                32 => {
                    let prefix = a[16..].iter().map(|b| b.leading_ones()).scan(true, |go, ones| {
                        let take = if *go { ones } else { 0 };
                        *go = *go && ones == 8;
                        Some(take)
                    });
                    format!("{}/{}", host_address(&a[..16]), prefix.sum::<u32>())
                }
                _ => return None,
            };
            format!("IPAddress: {name}")
        }
        0x88 => format!("OIDName: {}", oid(item.content)?),
        0xa5 => edi_party_name(item.content)?,
        _ => return None,
    })
}

/// `EDIPartyName.toString` of a `[5]` name's content: `[0]` nameAssigner and `[1]` partyName, each a string its
/// `getAsString` reads (null for another type); the `[1]` check runs on what the `[0]` branch read, as the JDK's does.
fn edi_party_name(content: &[u8]) -> Option<String> {
    let (mut assigner, mut party) = (None, None);
    for mut opt in items(content)? {
        if opt.tag == 0x80 {
            opt = tlv(opt.content)?.0;
            assigner = der_string(&opt);
        }
        if opt.tag == 0x81 {
            opt = tlv(opt.content)?.0;
            party = der_string(&opt);
        }
    }
    let mut out = "EDIPartyName: ".to_string();
    if let Some(assigner) = assigner {
        out.push_str(&format!("  nameAssigner = {assigner},"));
    }
    out.push_str(&format!("  partyName = {}", party?));
    Some(out)
}

/// `GeneralNames.toString` (a `List`).
fn general_names(content: &[u8]) -> Option<Vec<String>> {
    items(content)?.iter().map(general_name).collect()
}

/// `BitArray.toBooleanArray` of a BIT STRING's content (its first byte the unused bit count).
fn bits(content: &[u8]) -> Vec<bool> {
    let Some((&unused, data)) = content.split_first() else { return Vec::new() };
    let length = (data.len() * 8).saturating_sub(unused as usize);
    (0..length).map(|i| data[i / 8] & (0x80 >> (i % 8)) != 0).collect()
}

/// `KeyIdentifier.toString`.
fn key_identifier(id: &[u8]) -> String {
    format!("KeyIdentifier [\n{}]\n", hex_dump(id))
}

/// The `OIDMap` name of an extension (the `CertificateExtensions` map key), `None` for one it does not know.
fn extension_name(id: &str) -> Option<&'static str> {
    Some(match id {
        "2.5.29.14" => "SubjectKeyIdentifier",
        "2.5.29.15" => "KeyUsage",
        "2.5.29.16" => "PrivateKeyUsage",
        "2.5.29.17" => "SubjectAlternativeName",
        "2.5.29.18" => "IssuerAlternativeName",
        "2.5.29.19" => "BasicConstraints",
        "2.5.29.20" => "CRLNumber",
        "2.5.29.21" => "CRLReasonCode",
        "2.5.29.30" => "NameConstraints",
        "2.5.29.33" => "PolicyMappings",
        "2.5.29.35" => "AuthorityKeyIdentifier",
        "2.5.29.36" => "PolicyConstraints",
        "2.16.840.1.113730.1.1" => "NetscapeCertType",
        "2.5.29.32" => "CertificatePolicies",
        "2.5.29.37" => "ExtendedKeyUsage",
        "2.5.29.54" => "InhibitAnyPolicy",
        "2.5.29.31" => "CRLDistributionPoints",
        "2.5.29.29" => "CertificateIssuer",
        "1.3.6.1.5.5.7.1.11" => "SubjectInfoAccess",
        "1.3.6.1.5.5.7.1.1" => "AuthorityInfoAccess",
        "2.5.29.28" => "IssuingDistributionPoint",
        "2.5.29.27" => "DeltaCRLIndicator",
        "2.5.29.46" => "FreshestCRL",
        "1.3.6.1.5.5.7.48.1.5" => "OCSPNoCheck",
        _ => return None,
    })
}

/// The body of a ported extension class's `toString`, after `Extension.toString`'s header; `None` for an
/// extension printed in the unknown form.
fn extension_body(id: &str, value: &[u8]) -> Option<String> {
    if id == "1.3.6.1.5.5.7.48.1.5" {
        // `OCSPNoCheckExtension` ignores its value and keeps `Extension.toString`: the header alone
        return Some(String::new());
    }
    let (top, _) = tlv(value)?;
    Some(match id {
        "2.5.29.19" => {
            let parts = items(top.content)?;
            let (ca, path_len) = match parts.first() {
                Some(b) if b.tag == 0x01 => {
                    let ca = b.content.first().is_some_and(|&v| v != 0);
                    match parts.get(1) {
                        None => (ca, " no limit".to_string()),
                        Some(n) => {
                            let n = BigInt::from_signed_bytes_be(n.content);
                            (ca, if n < BigInt::from(0) { " undefined".into() } else { n.to_string() })
                        }
                    }
                }
                _ => (false, " undefined".to_string()),
            };
            format!("BasicConstraints:[\n  CA:{ca}\n  PathLen:{path_len}\n]\n")
        }
        "2.5.29.15" => {
            let set = bits(top.content);
            let names = [
                "DigitalSignature", "Non_repudiation", "Key_Encipherment", "Data_Encipherment", "Key_Agreement",
                "Key_CertSign", "Crl_Sign", "Encipher_Only", "Decipher_Only",
            ];
            let mut out = "KeyUsage [\n".to_string();
            for (i, name) in names.iter().enumerate() {
                if set.get(i).copied().unwrap_or(false) {
                    out.push_str(&format!("  {name}\n"));
                }
            }
            out.push_str("]\n");
            out
        }
        "2.5.29.37" => {
            let usages = items(top.content)?
                .iter()
                .map(|u| oid(u.content).map(|o| super::known_oids::std_name(&o).map_or(o, str::to_string)))
                .collect::<Option<Vec<_>>>()?;
            format!("ExtendedKeyUsages [\n  {}\n]\n", usages.join("\n  "))
        }
        "2.5.29.14" => format!("SubjectKeyIdentifier [\n{}]\n", key_identifier(top.content)),
        "2.5.29.35" => {
            let mut out = "AuthorityKeyIdentifier [\n".to_string();
            for part in items(top.content)? {
                match part.tag {
                    0x80 => out.push_str(&key_identifier(part.content)),
                    0xa1 => out.push_str(&format!("{}\n", list(general_names(part.content)?))),
                    0x82 => out.push_str(&format!("SerialNumber: {}\n", colon_hex(&BigInt::from_signed_bytes_be(part.content)))),
                    _ => return None,
                }
            }
            out.push_str("]\n");
            out
        }
        "2.5.29.17" | "2.5.29.18" => {
            let title = if id == "2.5.29.17" { "SubjectAlternativeName" } else { "IssuerAlternativeName" };
            let mut out = format!("{title} [\n");
            for name in general_names(top.content)? {
                out.push_str(&format!("  {name}\n"));
            }
            out.push_str("]\n");
            out
        }
        "1.3.6.1.5.5.7.1.1" | "1.3.6.1.5.5.7.1.11" => {
            let title = if id == "1.3.6.1.5.5.7.1.1" { "AuthorityInfoAccess" } else { "SubjectInfoAccess" };
            let descriptions = items(top.content)?
                .iter()
                .map(|d| {
                    let parts = items(d.content)?;
                    let method = oid(parts.first()?.content)?;
                    let method = match method.as_str() {
                        "1.3.6.1.5.5.7.48.2" => "caIssuers".to_string(),
                        "1.3.6.1.5.5.7.48.5" => "caRepository".to_string(),
                        "1.3.6.1.5.5.7.48.3" => "timeStamping".to_string(),
                        "1.3.6.1.5.5.7.48.1" => "ocsp".to_string(),
                        _ => method,
                    };
                    Some(format!("\n   accessMethod: {method}\n   accessLocation: {}\n", general_name(parts.get(1)?)?))
                })
                .collect::<Option<Vec<_>>>()?;
            format!("{title} [\n  {}\n]\n", list(descriptions))
        }
        "2.5.29.31" | "2.5.29.46" => {
            let title = if id == "2.5.29.31" { "CRLDistributionPoints" } else { "FreshestCRL" };
            let points = items(top.content)?.iter().map(distribution_point).collect::<Option<Vec<_>>>()?;
            format!("{title} [\n  {}]\n", list(points))
        }
        "2.5.29.32" => {
            let mut out = "CertificatePolicies [\n".to_string();
            for info in items(top.content)? {
                let parts = items(info.content)?;
                let policy = oid(parts.first()?.content)?;
                let qualifiers = match parts.get(1) {
                    None => Vec::new(),
                    Some(q) => items(q.content)?
                        .iter()
                        .map(|q| {
                            let parts = items(q.content)?;
                            let qualifier = parts.get(1).map_or_else(|| "null".to_string(), |d| hex_dump(d.raw));
                            Some(format!("PolicyQualifierInfo: [\n  qualifierID: {}\n  qualifier: {qualifier}\n]", oid(parts.first()?.content)?))
                        })
                        .collect::<Option<Vec<_>>>()?,
                };
                out.push_str(&format!("  [CertificatePolicyId: [{policy}]\n{}  ]\n", list(qualifiers)));
            }
            out.push_str("]\n");
            out
        }
        "2.5.29.16" => {
            let (mut from, mut to) = (None, None);
            for part in items(top.content)? {
                let slot = match part.tag {
                    0x80 => &mut from,
                    0x81 => &mut to,
                    _ => return None,
                };
                if slot.is_some() {
                    return None;
                }
                *slot = Some(date(&Tlv { tag: 0x18, ..part })?);
            }
            let mut out = "PrivateKeyUsage: [\n".to_string();
            if let Some(from) = &from {
                out.push_str(&format!("From: {from}"));
                if to.is_some() {
                    out.push_str(", ");
                }
            }
            if let Some(to) = &to {
                out.push_str(&format!("To: {to}"));
            }
            out.push_str("]\n");
            out
        }
        "2.5.29.30" => {
            if top.tag != 0x30 {
                return None;
            }
            let (mut permitted, mut excluded) = (None, None);
            for part in items(top.content)? {
                let slot = match part.tag {
                    0xa0 => &mut permitted,
                    0xa1 => &mut excluded,
                    _ => return None,
                };
                if slot.is_some() {
                    return None;
                }
                *slot = Some(general_subtrees(part.content)?);
            }
            let mut out = "NameConstraints: [".to_string();
            if let Some(permitted) = permitted {
                out.push_str(&format!("\n    Permitted:{permitted}"));
            }
            if let Some(excluded) = excluded {
                out.push_str(&format!("\n    Excluded:{excluded}"));
            }
            out.push_str("   ]\n");
            out
        }
        "2.5.29.33" => {
            if top.tag != 0x30 {
                return None;
            }
            let maps = items(top.content)?
                .iter()
                .map(|map| {
                    let parts = items(map.content).filter(|_| map.tag == 0x30)?;
                    let policy = |i: usize| parts.get(i).filter(|p| p.tag == 0x06).and_then(|p| oid(p.content));
                    Some(format!(
                        "CertificatePolicyMap: [\nIssuerDomain:CertificatePolicyId: [{}]\nSubjectDomain:CertificatePolicyId: [{}]\n]\n",
                        policy(0)?,
                        policy(1)?
                    ))
                })
                .collect::<Option<Vec<_>>>()?;
            format!("PolicyMappings [\n{}]\n", list(maps))
        }
        "2.5.29.36" => {
            if top.tag != 0x30 {
                return None;
            }
            let (mut require, mut inhibit) = (None, None);
            for part in items(top.content)? {
                let slot = match part.tag {
                    0x80 => &mut require,
                    0x81 => &mut inhibit,
                    _ => return None,
                };
                if slot.is_some() {
                    return None;
                }
                *slot = Some(java_int(part.content)?);
            }
            let shown = |v: Option<i32>| v.filter(|&v| v != -1).map_or_else(|| "unspecified".to_string(), |v| v.to_string());
            format!("PolicyConstraints: [  Require: {};\tInhibit: {} ]\n", shown(require), shown(inhibit))
        }
        "2.5.29.54" => {
            let skip = java_int(top.content).filter(|_| top.tag == 0x02 && !top.content.is_empty())?;
            match skip {
                -1 => format!("InhibitAnyPolicy: {}\n", i32::MAX),
                s if s < -1 => return None,
                s => format!("InhibitAnyPolicy: {s}\n"),
            }
        }
        "2.16.840.1.113730.1.1" => {
            if top.tag != 0x03 {
                return None;
            }
            let set = bits(top.content);
            let mut out = "NetscapeCertType [\n".to_string();
            for (i, name) in [(0, "   SSL client\n"), (1, "   SSL server\n"), (2, "   S/MIME\n"), (3, "   Object Signing\n"), (5, "   SSL CA\n"), (6, "   S/MIME CA\n"), (7, "   Object Signing CA")] {
                if set.get(i).copied().unwrap_or(false) {
                    out.push_str(name);
                }
            }
            out.push_str("]\n");
            out
        }
        "2.5.29.20" | "2.5.29.27" => {
            if top.tag != 0x02 || top.content.is_empty() {
                return None;
            }
            let label = if id == "2.5.29.20" { "CRL Number" } else { "Base CRL Number" };
            format!("{label}: {}\n", debug_hex(&BigInt::from_signed_bytes_be(top.content)))
        }
        "2.5.29.21" => {
            // `CRLReasonCodeExtension.getReasonCode`: `CRLReason.values()[code]`, UNSPECIFIED out of range
            const REASONS: [&str; 11] = [
                "UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "AFFILIATION_CHANGED", "SUPERSEDED",
                "CESSATION_OF_OPERATION", "CERTIFICATE_HOLD", "UNUSED", "REMOVE_FROM_CRL", "PRIVILEGE_WITHDRAWN",
                "AA_COMPROMISE",
            ];
            if top.tag != 0x0a {
                return None;
            }
            let code = java_int(top.content)?;
            let reason = usize::try_from(code).ok().filter(|&c| c > 0).and_then(|c| REASONS.get(c)).unwrap_or(&REASONS[0]);
            format!("    Reason Code: {reason}")
        }
        "2.5.29.29" => {
            if top.tag != 0x30 {
                return None;
            }
            format!("Certificate Issuer [\n{}]\n", list(general_names(top.content)?))
        }
        "2.5.29.28" => {
            if top.tag != 0x30 {
                return None;
            }
            let mut point = String::new();
            let mut reasons = String::new();
            let mut flags = [false; 4];
            for part in items(top.content)? {
                match part.tag {
                    0xa0 => {
                        let (name, _) = tlv(part.content)?;
                        let name = match name.tag {
                            0xa0 => list(general_names(name.content)?),
                            0xa1 => rdn(&name)?,
                            _ => return None,
                        };
                        point = format!("DistributionPointName:\n     {name}\n");
                    }
                    0x83 => {
                        const FLAGS: [&str; 9] = [
                            "Unused", "Key Compromise", "CA Compromise", "Affiliation_Changed", "Superseded",
                            "Cessation Of Operation", "Certificate Hold", "Privilege Withdrawn", "AA Compromise",
                        ];
                        let set = bits(part.content);
                        reasons = "Reason Flags [\n".to_string();
                        for (i, flag) in FLAGS.iter().enumerate() {
                            if set.get(i).copied().unwrap_or(false) {
                                reasons.push_str(&format!("  {flag}\n"));
                            }
                        }
                        reasons.push_str("]\n");
                    }
                    tag @ (0x81 | 0x82 | 0x84 | 0x85) => {
                        let [value] = part.content else { return None };
                        let slot = match tag {
                            0x81 => 0,
                            0x82 => 1,
                            0x85 => 2,
                            _ => 3,
                        };
                        flags[slot] = *value != 0;
                    }
                    _ => return None,
                }
            }
            format!(
                "IssuingDistributionPoint [\n  {point}{reasons}  Only contains user certs: {}\n  Only contains CA certs: {}\n  Only contains attribute certs: {}\n  Indirect CRL: {}\n]\n",
                flags[0], flags[1], flags[2], flags[3]
            )
        }
        _ => return None,
    })
}

/// `DerValue.getInteger` of an INTEGER's content: `None` for one that does not fit an `int`.
fn java_int(content: &[u8]) -> Option<i32> {
    if content.is_empty() {
        return None;
    }
    i32::try_from(BigInt::from_signed_bytes_be(content)).ok()
}

/// `GeneralSubtrees.toString` of the subtrees in a `[0]`/`[1]` field's content.
fn general_subtrees(content: &[u8]) -> Option<String> {
    let trees = items(content)?
        .iter()
        .map(|tree| {
            if tree.tag != 0x30 {
                return None;
            }
            let mut parts = items(tree.content)?.into_iter();
            let name = general_name(&parts.next()?)?;
            let (mut minimum, mut maximum) = (0, -1);
            for part in parts {
                match part.tag {
                    0x80 => minimum = java_int(part.content)?,
                    0x81 => maximum = java_int(part.content)?,
                    _ => return None,
                }
            }
            let maximum = if maximum == -1 { "undefined".to_string() } else { maximum.to_string() };
            Some(format!("\n   GeneralSubtree: [\n    GeneralName: {name}\n    Minimum: {minimum}\n    Maximum: {maximum}    ]\n"))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(format!("   GeneralSubtrees:\n{}\n", list(trees)))
}

/// `DistributionPoint.toString`.
fn distribution_point(point: &Tlv) -> Option<String> {
    let mut out = "DistributionPoint:\n     ".to_string();
    let mut reasons = None;
    let mut issuer = None;
    for part in items(point.content)? {
        match part.tag {
            0xa0 => {
                let (name, _) = tlv(part.content)?;
                match name.tag {
                    0xa0 => out.push_str(&list(general_names(name.content)?)),
                    0xa1 => out.push_str(&rdn(&name)?),
                    _ => return None,
                }
            }
            0x81 => reasons = Some(bits(part.content)),
            0xa2 => issuer = Some(list(general_names(part.content)?)),
            _ => return None,
        }
    }
    out.push('\n');
    if let Some(reasons) = reasons {
        const REASONS: [&str; 9] = [
            "", "key compromise", "CA compromise", "affiliation changed", "superseded", "cessation of operation",
            "certificate hold", "privilege withdrawn", "AA compromise",
        ];
        out.push_str("   ReasonFlags:\n");
        for (i, set) in reasons.iter().enumerate() {
            if *set {
                let reason = if i > 0 && i < REASONS.len() { REASONS[i].to_string() } else { format!("Unknown reason {i}") };
                out.push_str(&format!("    {reason}\n"));
            }
        }
    }
    if let Some(issuer) = issuer {
        out.push_str(&format!("   CRLIssuer:{issuer}\n"));
    }
    Some(out)
}

/// Where `CertificateExtensions.parseExtension` puts an extension.
enum Parsed {
    /// In the map `getAllExtensions` lists, under its key: the `OIDMap` name, or the OID for an unknown extension.
    Listed(String, String),
    /// Among `getUnparseableExtensions`, under its OID: a non-critical extension its class refused.
    Unparseable(String, String),
}

/// One extension as `X509CertInfo.toString` lists it; `None` when the certificate does not parse (a critical
/// extension its class refuses).
fn extension(item: &Tlv) -> Option<Parsed> {
    let parts = items(item.content)?;
    let id = oid(parts.first()?.content)?;
    let (critical, value) = match (parts.get(1), parts.get(2)) {
        (Some(b), Some(v)) if b.tag == 0x01 => (b.content.first().is_some_and(|&x| x != 0), v),
        (Some(v), None) => (false, v),
        _ => return None,
    };
    let header = format!("ObjectId: {id} Criticality={critical}\n");
    let Some(name) = extension_name(&id) else {
        let text = format!("{header}Extension unknown: DER encoded OCTET string =\n{}\n", hex_dump(value.raw));
        return Some(Parsed::Listed(id, text));
    };
    if let Err(why) = super::x509::extension(&id, critical, value.content) {
        if critical {
            return None;
        }
        // `UnparseableExtension.toString`: the class's `NAME`, the exception and the value
        let text = format!("{header}Unparseable {name} extension due to\n{}\n\n{}", why.line(), hex_dump(value.content));
        return Some(Parsed::Unparseable(id, text));
    }
    // the class read the value as BER (`new DerValue(byte[])`): print its definite form
    let definite = definite(value.content);
    let body = extension_body(&id, definite.as_deref().unwrap_or(value.content));
    // a value the class accepts but this printer does not cover keeps the unknown form
    let text = match body {
        Some(body) => format!("{header}{body}"),
        None => format!("{header}Extension unknown: DER encoded OCTET string =\n{}\n", hex_dump(value.raw)),
    };
    Some(Parsed::Listed(name.to_string(), text))
}

/// The BER elements of `input` re-encoded with definite lengths (`DerIndefLenConverter`, and the minimal length forms
/// `DerValue.toByteArray` writes), recursing into constructed ones; `None` for input that is not a sequence of whole
/// elements.
fn definite(mut input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    while !input.is_empty() {
        let (encoded, rest) = definite_element(input)?;
        out.extend(encoded);
        input = rest;
    }
    Some(out)
}

/// One element of [`definite`] and what follows it.
fn definite_element(input: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let tag = *input.first()?;
    let constructed = tag & 0x20 != 0;
    let (content, rest) = if *input.get(1)? == 0x80 {
        if !constructed {
            return None;
        }
        // indefinite: elements up to the end-of-contents octets
        let mut at = &input[2..];
        let mut content = Vec::new();
        loop {
            if at.starts_with(&[0, 0]) {
                break;
            }
            let (encoded, rest) = definite_element(at)?;
            content.extend(encoded);
            at = rest;
        }
        (content, &at[2..])
    } else {
        let (element, rest) = tlv(input)?;
        let content = if constructed { definite(element.content)? } else { element.content.to_vec() };
        (content, rest)
    };
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().into_iter().skip_while(|&b| b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend(content);
    Some((out, rest))
}

/// The key as its Sun class prints it (`RSAPublicKeyImpl` for RSA and RSASSA-PSS, `DSAPublicKeyImpl`,
/// `ECPublicKeyImpl` on a `CurveDB` curve), else `X509Key.toString` (EdDSA keys among them).
fn public_key(info: &Tlv) -> Option<String> {
    let parts = items(info.content)?;
    let algorithm_item = parts.first()?;
    let key_bits = parts.get(1)?.content.get(1..)?;
    let alg_parts = items(algorithm_item.content)?;
    let alg = oid(alg_parts.first()?.content)?;
    let params = alg_parts.get(1).filter(|p| p.tag != 0x05);
    match alg.as_str() {
        // `RSAPublicKeyImpl` reads X.500's RSA OID as a plain RSA key
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" | super::key_string::RSA_X500 => {
            let (sequence, _) = tlv(key_bits)?;
            let numbers = items(sequence.content)?;
            let n = BigInt::from_signed_bytes_be(numbers.first()?.content);
            let e = BigInt::from_signed_bytes_be(numbers.get(1)?.content);
            // `RSAUtil.KeyType.keyAlgo` and the key's `AlgorithmParameterSpec` (none for plain RSA)
            let pss = alg == "1.2.840.113549.1.1.10";
            let (kind, key_params) = match (pss, params) {
                (false, _) | (_, None) => (if pss { "RSASSA-PSS" } else { "RSA" }, "null".to_string()),
                (_, Some(p)) => ("RSASSA-PSS", pss_parameters(p)?),
            };
            Some(format!("Sun {kind} public key, {} bits\n  params: {key_params}\n  modulus: {n}\n  public exponent: {e}", n.bits()))
        }
        // `DSAPublicKeyImpl` reads OIW's DSA OID too
        "1.2.840.10040.4.1" | "1.3.14.3.2.12" => {
            let (y, _) = tlv(key_bits)?;
            let y = BigInt::from_signed_bytes_be(y.content);
            let (name, _) = algorithm(algorithm_item)?;
            Some(format!("Sun DSA Public Key\n    Parameters:{name}\n  y:\n{}\n", debug_hex(&y)))
        }
        // `DHPublicKey.toString` (SunJCE) of a PKCS #3 key: y, p, g and, when present, l
        // (the X9.42 OID is read the same way: its third INTEGER is taken as `l`, which a real subprime `q` overflows,
        // "Integer exceeds maximum valid value", so the JDK refuses such a certificate)
        "1.2.840.113549.1.3.1" | "1.2.840.10046.2.1" => {
            let (y, _) = tlv(key_bits)?;
            let y = BigInt::from_signed_bytes_be(y.content);
            let numbers = items(params?.content)?;
            let int = |i: usize| numbers.get(i).filter(|n| n.tag == 0x02).map(|n| BigInt::from_signed_bytes_be(n.content));
            let (p, g) = (int(0)?, int(1)?);
            let l = match int(2) {
                Some(l) if l > BigInt::from(i32::MAX) => return None,
                Some(l) if l != BigInt::from(0) => format!("\nl:\n    {l}"),
                _ => String::new(),
            };
            Some(format!("SunJCE Diffie-Hellman Public Key:\ny:\n{}\np:\n{}\ng:\n{}{l}", debug_hex(&y), debug_hex(&p), debug_hex(&g)))
        }
        // BouncyCastle's key classes, which MockServer registers as a provider, read the keys the JDK does not
        "1.2.643.2.2.19" | "1.2.643.2.2.98" | "1.2.643.7.1.1.1.1" | "1.2.643.7.1.1.1.2" | "1.2.643.7.1.1.6.1" | "1.2.643.7.1.1.6.2" => {
            // the factory BouncyCastle registers refuses a key it cannot read, and the JDK refuses the certificate (`refusal`)
            let (parameters, refused) = (params?, |p: &Tlv| super::key_string::gost_refusal(&alg, p, key_bits).is_some());
            super::key_string::gost_public(&alg, parameters, key_bits).or_else(|| if refused(parameters) { None } else { x509_key(algorithm_item, key_bits) })
        }
        "1.3.14.7.2.1.1" => super::key_string::elgamal_public(params?, key_bits).or_else(|| x509_key(algorithm_item, key_bits)),
        // `BCGOST3410PublicKey` on a CryptoPro set BouncyCastle holds; any other set is refused (`refusal`)
        super::key_string::GOST94 => match super::key_string::gost94_refusal(params) {
            Some(_) => None,
            None => params.and_then(|p| super::key_string::gost94_public(p, key_bits)).or_else(|| x509_key(algorithm_item, key_bits)),
        },
        "1.2.804.2.1.1.1.1.3.1.1" | "1.2.804.2.1.1.1.1.3.1.1.1.1" => {
            super::key_string::dstu_public(&alg, params?, key_bits).or_else(|| x509_key(algorithm_item, key_bits))
        }
        id if super::key_math::slh_dsa(id).is_some() => super::key_string::slh_public(id, key_bits).or_else(|| x509_key(algorithm_item, key_bits)),
        // BouncyCastle's `BCMLDSAPublicKey` and `BCSLHDSAPublicKey` read the pre-hash OIDs the JDK does not
        id if super::key_math::pre_hash(id).is_some() => super::key_string::pre_hash_public(id, key_bits).or_else(|| x509_key(algorithm_item, key_bits)),
        // the classes printing `Object.toString` or their key, and the JDK's `HSS$HSSPublicKey`
        id if super::pqc_keys::class(id).is_some() => super::pqc_keys::public(id, params, key_bits),
        // ML-DSA and ML-KEM keys print their parameter set only
        "2.16.840.1.101.3.4.3.17" => Some("ML-DSA-44 public key".into()),
        "2.16.840.1.101.3.4.3.18" => Some("ML-DSA-65 public key".into()),
        "2.16.840.1.101.3.4.3.19" => Some("ML-DSA-87 public key".into()),
        "2.16.840.1.101.3.4.4.1" => Some("ML-KEM-512 public key".into()),
        "2.16.840.1.101.3.4.4.2" => Some("ML-KEM-768 public key".into()),
        "2.16.840.1.101.3.4.4.3" => Some("ML-KEM-1024 public key".into()),
        // BouncyCastle's factory for these refuses the key, and the JDK the certificate (`refusal`)
        id if EC_REFUSED.contains(&id) => None,
        id if id == "1.2.840.10045.2.1" || EC_ALIASES.contains(&id) => {
            let curve = params.filter(|c| c.tag == 0x06).and_then(|c| oid(c.content));
            let named = curve.as_deref().and_then(super::named_curves::by_oid);
            match named {
                Some(&(_, size, name, _)) => {
                    let len = size.div_ceil(8) as usize;
                    if key_bits.len() == 1 + 2 * len && key_bits[0] == 0x04 {
                        let x = BigUint::from_bytes_be(&key_bits[1..1 + len]);
                        let y = BigUint::from_bytes_be(&key_bits[1 + len..]);
                        return Some(format!("Sun EC public key, {size} bits\n  public x coord: {x}\n  public y coord: {y}\n  parameters: {name}"));
                    }
                    x509_key(algorithm_item, key_bits)
                }
                // `ECPublicKeyImpl`: only a named curve of `CurveDB` ("Only named ECParameters supported", "Unknown
                // named curve"); the factory refuses the certificate otherwise
                None => None,
            }
        }
        _ => x509_key(algorithm_item, key_bits),
    }
}

/// The ECDH scheme OIDs of SEC 1 and X9.63 the JDK reads an EC key under, as `ECPublicKeyImpl`.
const EC_ALIASES: [&str; 10] = [
    "1.3.132.1.11.0", "1.3.132.1.11.1", "1.3.132.1.11.2", "1.3.132.1.11.3", "1.3.132.1.14.0", "1.3.132.1.14.1",
    "1.3.132.1.14.2", "1.3.132.1.14.3", "1.3.133.16.840.63.0.2", "1.3.133.16.840.63.0.3",
];

/// The ECDH and ECMQV OIDs BouncyCastle's provider names a `KeyFactory` for that refuses every key, so the JDK's
/// `CertificateFactory` refuses a certificate carrying one.
const EC_REFUSED: [&str; 6] = ["1.3.132.1.12", "1.3.132.1.15.0", "1.3.132.1.15.1", "1.3.132.1.15.2", "1.3.132.1.15.3", "1.3.133.16.840.63.0.16"];

/// The modulus and public exponent of a DER certificate's key when the JDK reads it as an RSA key (`RSAPublicKeyImpl`);
/// `None` for any other key.
pub(super) fn rsa_public(der: &[u8]) -> Option<(BigUint, BigUint)> {
    let (certificate, _) = tlv(der)?;
    let tbs = items(items(certificate.content)?.first()?.content)?;
    let at = usize::from(tbs.first()?.tag == 0xa0);
    let parts = items(tbs.get(at + 5)?.content)?;
    let alg = oid(items(parts.first()?.content)?.first()?.content)?;
    matches!(alg.as_str(), "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" | super::key_string::RSA_X500).then_some(())?;
    let (sequence, _) = tlv(parts.get(1).filter(|b| b.tag == 0x03)?.content.get(1..)?)?;
    let numbers = items(sequence.content)?;
    Some((BigUint::from_bytes_be(numbers.first()?.content), BigUint::from_bytes_be(numbers.get(1)?.content)))
}

/// `X509Key.toString`: the algorithm and a hex dump of the key bits.
fn x509_key(algorithm_item: &Tlv, key_bits: &[u8]) -> Option<String> {
    let (name, _) = algorithm(algorithm_item)?;
    Some(format!("algorithm = {name}, unparsed keybits = \n{}", hex_dump(key_bits)))
}

/// The message of the `IOException` the JDK's `CertificateFactory` refuses the certificate with when its public key
/// cannot be read: an EC key whose parameters are not a named `CurveDB` curve (`ECPublicKeyImpl`), a Diffie-Hellman
/// key whose parameters the DH key class cannot take (an X9.42 subprime). `None` for a certificate it takes (or one
/// refused for another reason).
pub fn refusal(der: &[u8]) -> Option<String> {
    let (certificate, _) = tlv(der)?;
    let tbs = items(items(certificate.content)?.first()?.content)?;
    let at = usize::from(tbs.first()?.tag == 0xa0);
    let info = tbs.get(at + 5)?;
    let parts = items(info.content)?;
    let alg_parts = items(parts.first()?.content)?;
    let alg = oid(alg_parts.first()?.content)?;
    let params = alg_parts.get(1);
    match alg.as_str() {
        id if EC_REFUSED.contains(&id) => Some(format!("subject key, encoded key spec not recognized: algorithm identifier {id} in key not recognised")),
        id if id == "1.2.840.10045.2.1" || EC_ALIASES.contains(&id) => match params {
            Some(p) if p.tag == 0x06 => {
                let curve = oid(p.content)?;
                super::named_curves::by_oid(&curve).is_none().then(|| format!("Unknown named curve: {curve}"))
            }
            Some(p) if p.tag == 0x30 => Some("Only named ECParameters supported".to_string()),
            _ => None,
        },
        "1.2.643.2.2.19" | "1.2.643.2.2.98" | "1.2.643.7.1.1.1.1" | "1.2.643.7.1.1.1.2" => {
            let bits = parts.get(1).filter(|b| b.tag == 0x03)?.content.get(1..)?;
            let message = super::key_string::gost_refusal(&alg, params?, bits)?;
            Some(format!("subject key, encoded key spec not recognized: {message}"))
        }
        super::key_string::GOST94 => super::key_string::gost94_refusal(params),
        super::pqc_keys::HSS_LMS | super::pqc_keys::XMSS_LEGACY | super::pqc_keys::XMSSMT_LEGACY => {
            super::pqc_keys::refusal(&alg, params, parts.get(1).filter(|b| b.tag == 0x03)?.content.get(1..)?)
        }
        "1.2.840.113549.1.3.1" | "1.2.840.10046.2.1" => {
            let numbers = items(params?.content)?;
            let l = numbers.get(2).filter(|n| n.tag == 0x02)?;
            (BigInt::from_signed_bytes_be(l.content) > BigInt::from(i32::MAX)).then(|| "Integer exceeds maximum valid value".to_string())
        }
        _ => None,
    }
}

/// `X509Certificate.toString` of a DER certificate, `None` when it does not parse.
pub fn certificate_to_string(der: &[u8]) -> Option<String> {
    let (certificate, _) = tlv(der)?;
    let outer = items(certificate.content)?;
    let tbs = items(outer.first()?.content)?;
    let (signature_algorithm, _) = algorithm(outer.get(1)?)?;
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
    let (algorithm_name, algorithm_oid) = algorithm(tbs.get(at + 1)?)?;
    let issuer = x500_name(tbs.get(at + 2)?.content)?;
    let validity = items(tbs.get(at + 3)?.content)?;
    let subject = x500_name(tbs.get(at + 4)?.content)?;
    let key = public_key(tbs.get(at + 5)?)?;
    let mut out = format!(
        "[\n[\n  Version: V{version}\n  Subject: {subject}\n  Signature Algorithm: {algorithm_name}, OID = {algorithm_oid}\n\n  Key:  {key}\n  Validity: [From: {},\n               To: {}]\n  Issuer: {issuer}\n  SerialNumber: {}\n",
        date(validity.first()?)?,
        date(validity.get(1)?)?,
        colon_hex(&serial),
    );
    for part in &tbs[at + 6..] {
        if part.tag == 0xa3 {
            let (sequence, _) = tlv(part.content)?;
            // both `TreeMap`s: the listed ones by key, the unparseable ones by OID
            let (mut extensions, mut unparseable) = (BTreeMap::new(), BTreeMap::new());
            for item in items(sequence.content)? {
                match extension(&item)? {
                    Parsed::Listed(key, text) => {
                        if extensions.insert(key, text).is_some() {
                            // `Duplicate extensions not allowed`
                            return None;
                        }
                    }
                    Parsed::Unparseable(id, text) => {
                        unparseable.insert(id, text);
                    }
                }
            }
            out.push_str(&format!("\nCertificate Extensions: {}", extensions.len()));
            for (i, text) in extensions.values().enumerate() {
                out.push_str(&format!("\n[{}]: {text}", i + 1));
            }
            if !unparseable.is_empty() {
                out.push_str(&format!("\nUnparseable certificate extensions: {}", unparseable.len()));
                for (i, text) in unparseable.values().enumerate() {
                    out.push_str(&format!("\n[{}]: {text}", i + 1));
                }
            }
        }
    }
    out.push_str(&format!("\n]\n  Algorithm: [{signature_algorithm}]\n  Signature:\n{}\n]", hex_dump(signature)));
    Some(out)
}

/// What `NettySslContextFactory.logUsedCertificateData` prints of a certificate: `getSerialNumber()` (decimal),
/// `getIssuerX500Principal()` and `getSubjectX500Principal()` (both `X500Name.toString`).
pub fn serial_issuer_subject(der: &[u8]) -> Option<(String, String, String)> {
    let (certificate, _) = tlv(der)?;
    let tbs = items(items(certificate.content)?.first()?.content)?;
    let at = usize::from(tbs.first()?.tag == 0xa0);
    let serial = BigInt::from_signed_bytes_be(tbs.get(at)?.content);
    Some((serial.to_string(), x500_name(tbs.get(at + 2)?.content)?, x500_name(tbs.get(at + 4)?.content)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each certificate of `tests/files/x509/tostring` and its `ca-forms` (the CAs of other key forms, beside their
    /// `-key.pem` keys) against the text OpenJDK 25 printed for it, or none where it refused the certificate.
    #[test]
    fn matches_the_jdk() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/x509/tostring");
        let entries = std::fs::read_dir(&dir).expect("vectors").chain(std::fs::read_dir(dir.join("ca-forms")).expect("ca-forms"));
        let mut checked = 0;
        for entry in entries {
            let path = entry.expect("entry").path();
            if path.to_string_lossy().ends_with("-key.pem") {
                continue;
            }
            let der = match path.extension().and_then(|e| e.to_str()) {
                Some("der") => std::fs::read(&path).expect("der"),
                Some("pem") => super::super::client_cert::pem_chain(&std::fs::read_to_string(&path).expect("pem")).remove(0),
                _ => continue,
            };
            // `<name>.err`: the JDK refuses the certificate (a critical extension its class rejects), so no text
            let expected = std::fs::read_to_string(path.with_extension("txt")).ok();
            assert!(expected.is_some() || path.with_extension("err").exists(), "no expected text for {}", path.display());
            assert_eq!(certificate_to_string(&der), expected, "{}", path.display());
            checked += 1;
        }
        assert!(checked >= 18, "only {checked} vectors");
    }

    #[test]
    fn hex_dump_lines() {
        assert_eq!(hex_dump(b"ab"), "0000: 61 62                                              ab\n");
        assert_eq!(hex_dump(&[]), "");
    }
}

//! The BC provider's key factories for keys of other algorithms than RSA and EC, as `JcaPEMKeyConverter.getPrivateKey`
//! reaches them with a `PRIVATE KEY`: DSA (`BCDSAPrivateKey`), Ed25519/Ed448 (`BCEdDSAPrivateKey`),
//! X25519/X448 (`BCXDHPrivateKey`), DH and X9.42 DH (`BCDHPrivateKey`), GOST R 34.10-2001 and -2012
//! (`BCECGOST3410PrivateKey`, `BCECGOST3410_2012PrivateKey`), and through `PrivateKeyFactory` ML-DSA, ML-KEM and
//! SLH-DSA; and ElGamal, GOST R 34.10-94, DSTU 4145, HSS/LMS, Falcon, NTRU, FrodoKEM, Classic
//! McEliece, composite ML-DSA/ML-KEM and the EXTERNAL factory, with GOST's and DSTU's X9.62 parameters. Each reads the
//! key as BouncyCastle 1.86 does (checked against the oracle's own shaded jar)
//! and fails with its exception; a key read is a
//! [`Signer::Other`], which MockServer cannot sign a JWT with. DSTU 4145's `DSTU4145ECBinary` curves and the explicit
//! X9.62 parameters of any shape are read as BouncyCastle reads them. A
//! `DSA PRIVATE KEY` pair's public key goes through the DSA key factory too (`getKeyPair`).

use num_bigint::{BigInt, Sign};

use super::bc::{self, Asn1};
use super::jca::{not_recognized, npe, unable};
use super::{iae, java_string, throwable, Failure, OtherKey, Signer, SunEc};

const INVALID_KEY_SPEC: &str = "java.security.spec.InvalidKeySpecException";
const BC: &str = "shaded_package.org.bouncycastle";

/// `getPrivateKey` of a PrivateKeyInfo whose algorithm is `dotted`, if one of the modelled key factories takes it.
pub(super) fn private_key(dotted: &str, info: &bc::PrivateKeyInfo) -> Option<Result<Option<Signer>, Failure>> {
    let key = |algorithm: &str, class: &'static str| Signer::Other(OtherKey { algorithm: Some(algorithm.into()), class, gost: None, sun_ec: SunEc::Encoding });
    Some(match dotted {
        "1.2.840.10040.4.1" | "1.2.840.10040.4.3" | "1.3.14.3.2.27" => dsa(info).map(|()| Some(key("DSA", "jcajce.provider.asymmetric.dsa.BCDSAPrivateKey"))).map_err(not_recognized),
        "1.3.101.112" | "1.3.101.113" => {
            let (name, size) = if dotted == "1.3.101.112" { ("Ed25519", 32) } else { ("Ed448", 57) };
            octets(info).and_then(|k| buf(&k, size)).map(|()| Some(key(name, "jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey"))).map_err(not_recognized)
        }
        "1.3.101.110" | "1.3.101.111" => {
            let (name, size) = if dotted == "1.3.101.110" { ("X25519", 32) } else { ("X448", 56) };
            // the exact length of a Java 11 X25519/X448 secret is taken as the raw key
            let raw = if info.key.len() == 32 || info.key.len() == 56 { Ok(info.key.clone()) } else { octets(info) };
            raw.and_then(|k| buf(&k, size)).map(|()| Some(key(name, "jcajce.provider.asymmetric.edec.BCXDHPrivateKey"))).map_err(not_recognized)
        }
        "1.2.840.113549.1.3.1" | "1.2.840.10046.2.1" => {
            dh(info, dotted == "1.2.840.10046.2.1").map(|()| Some(key("DH", "jcajce.provider.asymmetric.dh.BCDHPrivateKey"))).map_err(not_recognized)
        }
        "1.2.643.2.2.19" | "1.2.643.2.2.98" => {
            gost(info, false).map(|d| d.map(|d| gost_key("ECGOST3410", "jcajce.provider.asymmetric.ecgost.BCECGOST3410PrivateKey", d))).map_err(not_recognized)
        }
        "1.2.643.7.1.1.1.1" | "1.2.643.7.1.1.1.2" | "1.2.643.7.1.1.6.1" | "1.2.643.7.1.1.6.2" => gost(info, true)
            .map(|d| d.map(|d| gost_key("ECGOST3410-2012", "jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PrivateKey", d)))
            .map_err(not_recognized),
        "1.3.14.7.2.1.1" => elgamal(info).map(|()| Some(key("ElGamal", "jcajce.provider.asymmetric.elgamal.BCElGamalPrivateKey"))).map_err(not_recognized),
        "1.2.643.2.2.20" => gost94(info).map(|()| Some(key("GOST3410", "jcajce.provider.asymmetric.gost.BCGOST3410PrivateKey"))).map_err(not_recognized),
        "1.2.804.2.1.1.1.1.3.1.1" | "1.2.804.2.1.1.1.1.3.1.1.1.1" => {
            dstu(info).map(|d| d.map(|d| gost_key("DSTU4145", "jcajce.provider.asymmetric.dstu.BCDSTU4145PrivateKey", d))).map_err(not_recognized)
        }
        _ => {
            if let Some((name, level)) = ml_dsa(dotted) {
                ml_dsa_key(info, name, level).map(|()| Some(key(&name.to_uppercase(), "jcajce.provider.asymmetric.mldsa.BCMLDSAPrivateKey"))).map_err(pqc)
            } else if let Some(k) = ml_kem(dotted) {
                let name = format!("ML-KEM-{}", [512, 768, 1024][k - 2]);
                ml_kem_key(info, k, &name).map(|()| Some(key(&name, "jcajce.provider.asymmetric.mlkem.BCMLKEMPrivateKey"))).map_err(pqc)
            } else if let Some((name, n)) = slh_dsa(dotted) {
                slh_dsa_key(info, n).map(|()| Some(key(&format!("SLH-DSA-{}", name.to_uppercase()), "jcajce.provider.asymmetric.slhdsa.BCSLHDSAPrivateKey"))).map_err(slh)
            } else if dotted == "1.2.840.113549.1.9.16.3.17" {
                lms_key(info).map(|read| read.then(|| key("LMS", "pqc.jcajce.provider.lms.BCLMSPrivateKey"))).map_err(|e| {
                    unable(throwable(INVALID_KEY_SPEC, Some(java_string(&e)), Some(e)))
                })
            } else if let Some(name) = falcon(dotted) {
                falcon_key(info).map(|()| Some(key(name, "pqc.jcajce.provider.falcon.BCFalconPrivateKey"))).map_err(slh)
            } else if dotted.starts_with("1.3.6.1.4.1.22554.5.5") {
                ntru_key(info, dotted).map(|()| Some(key("NTRU", "pqc.jcajce.provider.ntru.BCNTRUPrivateKey"))).map_err(|e| unable(throwable(INVALID_KEY_SPEC, Some(java_string(&e)), None)))
            } else if let Some((name, size)) = frodo(dotted) {
                sized_key(info, size, "'privateKey' has invalid length").map(|()| Some(key(name, "jcajce.provider.asymmetric.frodokem.BCFrodoKEMPrivateKey"))).map_err(pqc)
            } else if let Some((name, size)) = cmce(dotted) {
                sized_key(info, size, "'privateKey' has invalid length").map(|()| Some(key(name, "jcajce.provider.asymmetric.cmce.BCCMCEPrivateKey"))).map_err(pqc)
            } else if dotted == "1.3.6.1.4.1.22554.4.2" {
                // `EXTERNAL`'s converter reads public keys only
                Err(not_recognized(throwable("java.io.IOException", Some("no support for private key".into()), None)))
            } else if let Some(composite) = composite(dotted) {
                composite_key(info, composite).map_err(not_recognized)
            } else if dotted == "1.3.6.1.4.1.18227.2.1" || dotted == "2.16.840.1.114027.80.4.1" {
                generic_composite_key(info).map_err(not_recognized)
            } else {
                return None;
            }
        }
    })
}

/// The BC key class, as `getClass().getName()` prints it.
pub(super) fn class_name(class: &str) -> String {
    format!("{BC}.{class}")
}

fn gost_key(algorithm: &str, class: &'static str, (key, sun_ec): CurveKey) -> Signer {
    Signer::Other(OtherKey { algorithm: Some(algorithm.into()), class, gost: key.map(Box::new), sun_ec })
}

/// The curve key BouncyCastle's ECDSA signs with (`None` where it is not modelled) and SunEC's translation.
type CurveKey = (Option<super::ecdsa::EcDomainKey>, SunEc);

// ---------------------------------------------------------------------------------------------------------------
// ASN.1 helpers, as BouncyCastle's `getInstance` methods fail
// ---------------------------------------------------------------------------------------------------------------

fn illegal(object: &Asn1) -> Failure {
    iae(format!("illegal object in getInstance: {}", object.class()))
}

fn unknown(object: &Asn1) -> Failure {
    iae(format!("unknown object in getInstance: {}", object.class()))
}

/// `ASN1Integer.getInstance(Object)`.
fn integer(object: &Asn1) -> Result<BigInt, Failure> {
    match object {
        Asn1::Integer(v) => Ok(BigInt::from_signed_bytes_be(v)),
        other => Err(illegal(other)),
    }
}

/// `(ASN1Integer) object`: a null passes the cast.
fn cast_integer(object: Option<&Asn1>) -> Result<Option<BigInt>, Failure> {
    match object {
        None => Ok(None),
        Some(Asn1::Integer(v)) => Ok(Some(BigInt::from_signed_bytes_be(v))),
        Some(other) => Err(bc::cast(other, "ASN1Integer")),
    }
}

/// `ASN1Sequence.getInstance(Object)`: null for null.
fn sequence(object: Option<&Asn1>) -> Result<Option<&[Asn1]>, Failure> {
    match object {
        None => Ok(None),
        Some(Asn1::Sequence(items, _)) => Ok(Some(items)),
        Some(other) => Err(unknown(other)),
    }
}

/// `info.parsePrivateKey()`.
fn parse_private_key(info: &bc::PrivateKeyInfo) -> Result<Option<Asn1>, Failure> {
    bc::from_byte_array(&info.key)
}

/// `ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets()`.
fn octets(info: &bc::PrivateKeyInfo) -> Result<Vec<u8>, Failure> {
    match parse_private_key(info)? {
        Some(Asn1::OctetString(_, octets)) => Ok(octets),
        Some(other) => Err(illegal(&other)),
        None => Err(null_octets()),
    }
}

fn null_octets() -> Failure {
    npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.ASN1OctetString.getOctets()\" because the return value of \"shaded_package.org.bouncycastle.asn1.ASN1OctetString.getInstance(Object)\" is null")
}

/// `Ed25519PrivateKeyParameters(byte[])` and its kin: the encoding's length.
fn buf(key: &[u8], size: usize) -> Result<(), Failure> {
    if key.len() == size { Ok(()) } else { Err(iae(format!("'buf' must have length {size}"))) }
}

/// `BigInteger.bitLength`.
fn bit_length(x: &BigInt) -> u64 {
    if x.sign() == Sign::Minus { (-x - BigInt::from(1)).bits() } else { x.bits() }
}

/// `BigInteger.intValue`: the low 32 bits, two's complement.
fn int_value(x: &BigInt) -> i64 {
    let low = x & BigInt::from(0xffff_ffffu32);
    i64::from(u32::try_from(low).expect("32 bits") as i32)
}

// ---------------------------------------------------------------------------------------------------------------
// DSA, DH
// ---------------------------------------------------------------------------------------------------------------

/// `BCDSAPrivateKey(PrivateKeyInfo)`: `DSAParameter.getInstance` of the parameters, the private key cast to an
/// INTEGER, then the parameters' and the key's values.
fn dsa(info: &bc::PrivateKeyInfo) -> Result<(), Failure> {
    let parameters = match sequence(info.parameters.as_ref())? {
        None => None,
        Some(items) => {
            if items.len() != 3 {
                return Err(iae(format!("Bad sequence size: {}", items.len())));
            }
            for item in items {
                integer(item)?;
            }
            Some(())
        }
    };
    let key = parse_private_key(info)?;
    if cast_integer(key.as_ref())?.is_none() {
        return Err(npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.ASN1Integer.getValue()\" because \"<local3>\" is null"));
    }
    parameters.ok_or_else(|| npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.x509.DSAParameter.getP()\" because \"<local2>\" is null"))
}

/// `getKeyPair` of a `DSA PRIVATE KEY` (its p, q, g, y and x): the DSA key factory's public key first, whose
/// `DSAPublicKeyParameters` validate y, then the private key, which `BCDSAPrivateKey` takes as it is. `DSAParameter`
/// reads p and q unsigned (`getPositiveValue`), y signed.
pub(super) fn dsa_key_pair(ints: &[Vec<u8>]) -> Result<Signer, Failure> {
    let unsigned = |i: usize| BigInt::from_bytes_be(Sign::Plus, &ints[i]);
    dsa_public_key(&unsigned(0), &unsigned(1), &BigInt::from_signed_bytes_be(&ints[3])).map_err(not_recognized)?;
    Ok(Signer::Other(OtherKey { algorithm: Some("DSA".into()), class: "jcajce.provider.asymmetric.dsa.BCDSAPrivateKey", gost: None, sun_ec: SunEc::Encoding }))
}

/// `DSAPublicKeyParameters.validate(y, params)`: the modulus at most `DSA_MAX_SIZE` (16384) bits, then
/// `2 <= y <= p - 2` and `y.modPow(q, p)` one (p is at least 4 there, q not negative).
fn dsa_public_key(p: &BigInt, q: &BigInt, y: &BigInt) -> Result<(), Failure> {
    if bit_length(p) > 16384 {
        return Err(iae("DSA modulus out of range"));
    }
    let two = BigInt::from(2);
    if &two <= y && &(p - &two) >= y && y.modpow(q, p) == BigInt::from(1) {
        return Ok(());
    }
    Err(iae("y value does not appear to be in correct group"))
}

/// `BCDHPrivateKey(PrivateKeyInfo)`: PKCS#3 `DHParameter` or X9.42 `DomainParameters`, then BouncyCastle's
/// `DHParameters` checks of `p` and `l`.
fn dh(info: &bc::PrivateKeyInfo, x942: bool) -> Result<(), Failure> {
    const DEFAULT_MINIMUM_LENGTH: i64 = 160;
    let items = sequence(info.parameters.as_ref())?;
    let key = parse_private_key(info)?;
    if cast_integer(key.as_ref())?.is_none() {
        return Err(npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.ASN1Integer.getValue()\" because \"<local3>\" is null"));
    }
    let (p, l) = if x942 {
        let Some(items) = items else {
            return Err(npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.x9.DomainParameters.getP()\" because \"<local5>\" is null"));
        };
        if items.len() < 3 || items.len() > 5 {
            return Err(iae(format!("Bad sequence size: {}", items.len())));
        }
        let p = integer(&items[0])?;
        integer(&items[1])?;
        integer(&items[2])?;
        let mut rest = items[3..].iter().peekable();
        if let Some(Asn1::Integer(_)) = rest.peek() {
            rest.next();
        }
        if let Some(next) = rest.next() {
            // `ValidationParams.getInstance`: a SEQUENCE of a BIT STRING and an INTEGER
            let validation = sequence(Some(next))?.expect("an object");
            if validation.len() != 2 {
                return Err(iae(format!("Bad sequence size: {}", validation.len())));
            }
            if !matches!(validation[0], Asn1::BitString(..)) {
                return Err(illegal(&validation[0]));
            }
            integer(&validation[1])?;
        }
        (p, 0)
    } else {
        let Some(items) = items else {
            return Err(npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.pkcs.DHParameter.getL()\" because \"<local5>\" is null"));
        };
        let mut elements = items.iter();
        let p = integer(elements.next().ok_or_else(bc::no_such_element)?)?;
        integer(elements.next().ok_or_else(bc::no_such_element)?)?;
        let l = cast_integer(elements.next())?.map_or(0, |l| int_value(&l));
        (p, l)
    };
    // `DHParameters(p, g, q, getDefaultMParam(l), l, ...)`
    let m = if l == 0 { DEFAULT_MINIMUM_LENGTH } else { l.min(DEFAULT_MINIMUM_LENGTH) };
    let bits = bit_length(&p) as i64;
    if l != 0 {
        if l >= bits {
            return Err(iae("when l value specified, it must be less than bitlength(p)"));
        }
        if l < m {
            return Err(iae("when l value specified, it may not be less than m value"));
        }
    }
    if m >= bits {
        return Err(iae("unsafe p value so small specific l required"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// GOST R 34.10-2001 and -2012
// ---------------------------------------------------------------------------------------------------------------

/// `ECGOST3410NamedCurves`: each parameter set's curve (p, a, b, n, h, x, y), by its OID.
const GOST_CURVES: &[(&str, [&str; 7])] = &[
    ("1.2.643.2.2.35.1", CRYPTO_PRO_A),
    ("1.2.643.2.2.35.2", CRYPTO_PRO_B),
    ("1.2.643.2.2.35.3", CRYPTO_PRO_C),
    ("1.2.643.2.2.36.0", CRYPTO_PRO_A),
    ("1.2.643.2.2.36.1", CRYPTO_PRO_C),
    ("1.2.643.7.1.2.1.1.1", TC26_256_A),
    ("1.2.643.7.1.2.1.1.2", CRYPTO_PRO_A),
    ("1.2.643.7.1.2.1.1.3", CRYPTO_PRO_B),
    ("1.2.643.7.1.2.1.1.4", CRYPTO_PRO_C),
    ("1.2.643.7.1.2.1.2.1", TC26_512_A),
    ("1.2.643.7.1.2.1.2.2", TC26_512_B),
    ("1.2.643.7.1.2.1.2.3", TC26_512_C),
];

const CRYPTO_PRO_A: [&str; 7] = [
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
    "A6",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
    "1",
    "1",
    "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
];
const CRYPTO_PRO_B: [&str; 7] = [
    "8000000000000000000000000000000000000000000000000000000000000C99",
    "8000000000000000000000000000000000000000000000000000000000000C96",
    "3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B",
    "800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F",
    "1",
    "1",
    "3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC",
];
const CRYPTO_PRO_C: [&str; 7] = [
    "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B",
    "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598",
    "805A",
    "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9",
    "1",
    "0",
    "41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67",
];
const TC26_256_A: [&str; 7] = [
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
    "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
    "295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513",
    "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67",
    "4",
    "91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28",
    "32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C",
];
const TC26_512_A: [&str; 7] = [
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4",
    "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275",
    "1",
    "3",
    "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4",
];
const TC26_512_B: [&str; 7] = [
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F",
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C",
    "687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116",
    "800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD",
    "1",
    "2",
    "1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD",
];
const TC26_512_C: [&str; 7] = [
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
    "DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3",
    "B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1",
    "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED",
    "4",
    "E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148",
    "F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F",
];

/// The domain parameters (p, a, b, n, h, Gx, Gy in hex) of a GOST parameter set by its dotted OID: the curve the CA key
/// strings of `tls::key_string` and `tls::cert_string` print.
pub(crate) fn gost_set(oid: &str) -> Option<&'static [&'static str; 7]> {
    GOST_CURVES.iter().find(|(o, _)| *o == oid).map(|(_, params)| params)
}

/// The curve of a GOST parameter set and the scalar `d` on it.
fn gost_curve(set: &str, d: &BigInt) -> Option<super::ecdsa::EcDomainKey> {
    let (_, [p, a, b, n, h, x, y]) = GOST_CURVES.iter().find(|(o, _)| *o == set)?;
    let hex = |s: &str| num_bigint::BigUint::parse_bytes(s.as_bytes(), 16).expect("hex");
    let int = |s: &str| {
        let v = hex(s).to_bytes_be();
        Asn1::Integer(if v[0] & 0x80 != 0 { [vec![0], v].concat() } else { v })
    };
    let len = hex(p).to_bytes_be().len();
    let fixed = |s: &str| super::fixed_len(&hex(s).to_bytes_be(), len).expect("an element of the field");
    let point = [vec![4], fixed(x), fixed(y)].concat();
    const PRIME_FIELD: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01];
    let domain = vec![
        Asn1::Integer(vec![1]),
        Asn1::Sequence(vec![Asn1::Oid(PRIME_FIELD.to_vec()), int(p)], false),
        Asn1::Sequence(vec![Asn1::OctetString("DEROctetString", fixed(a)), Asn1::OctetString("DEROctetString", fixed(b))], false),
        Asn1::OctetString("DEROctetString", point),
        int(n),
        int(h),
    ];
    let d = d.magnitude().to_bytes_be();
    super::ecdsa::EcDomainKey::explicit(&domain, &d)
}

/// `BCECGOST3410PrivateKey` (`twenty_twelve`: `BCECGOST3410_2012PrivateKey`) `populateFromPrivKeyInfo`: GOST
/// parameters (`GOST3410PublicKeyAlgParameters`, a named parameter set) and a little-endian OCTET STRING or an
/// INTEGER key, else X9.62 parameters ([`x962_key`]). The key's curve and scalar, which BouncyCastle's ECDSA signs
/// with (`None` where they are not modelled); `Ok(None)` for X9.62 parameters that are not modelled.
fn gost(info: &bc::PrivateKeyInfo, twenty_twelve: bool) -> Result<Option<CurveKey>, Failure> {
    let Some(parameters) = info.parameters.as_ref() else {
        return Err(npe(if twenty_twelve {
            "Cannot invoke \"shaded_package.org.bouncycastle.asn1.ASN1Encodable.toASN1Primitive()\" because the return value of \"shaded_package.org.bouncycastle.asn1.x509.AlgorithmIdentifier.getParameters()\" is null"
        } else {
            "Cannot invoke \"shaded_package.org.bouncycastle.asn1.ASN1Encodable.toASN1Primitive()\" because \"<local3>\" is null"
        }));
    };
    match parameters {
        Asn1::Sequence(items, _) if (twenty_twelve && items.len() <= 3) || (!twenty_twelve && (items.len() == 2 || items.len() == 3)) => {
            let set = gost_parameters(items)?;
            if !GOST_CURVES.iter().any(|(o, _)| *o == set) {
                return Err(npe("Cannot invoke \"Object.hashCode()\" because \"<parameter1>\" is null"));
            }
            let d = if twenty_twelve && (info.key.len() == 32 || info.key.len() == 64) {
                little_endian(&info.key)
            } else {
                match parse_private_key(info)? {
                    Some(Asn1::Integer(v)) => BigInt::from_bytes_be(Sign::Plus, &v),
                    Some(Asn1::OctetString(_, octets)) => little_endian(&octets),
                    Some(other) => return Err(illegal(&other)),
                    None => return Err(null_octets()),
                }
            };
            Ok(Some((gost_curve(&set, &d), SunEc::Encoding)))
        }
        _ => {
            // `ECUtil.getNamedCurveByOid`, then (2001) an IllegalStateException without a message, or (2012)
            // `ECGOST3410NamedCurves.getByOIDX9`, null for any other curve
            // (GOST's curves are among `ECUtil`'s)
            let unknown_curve = |_: &[u8]| {
                Err(if twenty_twelve {
                    npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.x9.X9ECParameters.getCurve()\" because \"<local6>\" is null")
                } else {
                    throwable("java.lang.IllegalStateException", None, None)
                })
            };
            x962_key(info, parameters, unknown_curve, if twenty_twelve { "<local5>" } else { "<local7>" })
        }
    }
}

/// The X9.62 branch of the EC-style key classes (GOST R 34.10 for backwards compatibility, DSTU 4145):
/// `X962Parameters.getInstance` of the parameters (a named curve, implicitlyCA, or explicit `X9ECParameters`), then
/// the key, an INTEGER or an `ECPrivateKey` (`local`: the variable a missing key's NullPointerException names). The
/// curve key BouncyCastle signs with (`None` for implicitlyCA, a negative scalar, or a curve not modelled); `Ok(None)`
/// for explicit parameters [`super::ecdsa::EcDomainKey::read`] does not model. `unknown_curve`: the failure for a
/// named curve `ECUtil` does not know, `Ok` where the key class finds it in a table of its own (DSTU's).
fn x962_key(
    info: &bc::PrivateKeyInfo,
    parameters: &Asn1,
    unknown_curve: impl Fn(&[u8]) -> Result<(), Failure>,
    local: &str,
) -> Result<Option<CurveKey>, Failure> {
    enum Curve {
        Named(Vec<u8>),
        Implicit,
        Explicit(Vec<Asn1>),
    }
    let curve = match parameters {
        Asn1::Other("DERNull") => Curve::Implicit,
        Asn1::Oid(oid) => {
            if !super::jca::bc_named_curve(oid) {
                unknown_curve(oid)?;
            }
            Curve::Named(oid.clone())
        }
        Asn1::Sequence(items, _) => {
            if x9_parameters(items)?.is_none() {
                return Ok(None);
            }
            Curve::Explicit(items.clone())
        }
        other => return Err(unknown(other)),
    };
    let d = super::jca::ec_scalar(parse_private_key(info)?, local)?;
    // SunEC finds a NIST curve by its parameters, named or explicit, and refuses any other by its spec's text
    let nist = match &curve {
        Curve::Named(oid) => super::jca::nist_named(oid),
        Curve::Explicit(domain) => super::jca::nist_explicit(domain),
        Curve::Implicit => None,
    };
    let sun_ec = match (&curve, nist) {
        (Curve::Implicit, _) => SunEc::Implicit,
        (_, Some(c)) => match super::jca::nist_key(c, &d) {
            Some(key) => SunEc::Nist(Box::new(key)),
            None => SunEc::Encoding,
        },
        (Curve::Named(_), None) => SunEc::Unsupported(super::identity("shaded_package.org.bouncycastle.jce.spec.ECNamedCurveSpec")),
        (Curve::Explicit(_), None) => SunEc::Unsupported(super::identity("java.security.spec.ECParameterSpec")),
    };
    let Some(d) = d.to_biguint().map(|d| d.to_bytes_be()) else { return Ok(Some((None, sun_ec))) };
    let key = match curve {
        Curve::Implicit => None,
        Curve::Named(oid) => named_curve_key(&oid, &d),
        Curve::Explicit(domain) => super::ecdsa::EcDomainKey::explicit(&domain, &d),
    };
    Ok(Some((key, sun_ec)))
}

/// The key `d` on the named curve `oid` as BouncyCastle's ECDSA signs on it: NIST's, the curves of
/// [`super::curves`], GOST's and DSTU's.
fn named_curve_key(oid: &[u8], d: &[u8]) -> Option<super::ecdsa::EcDomainKey> {
    const NIST: [(&[u8], &str); 3] = [
        (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07], NIST_DOMAINS[0]),
        (&[0x2b, 0x81, 0x04, 0x00, 0x22], NIST_DOMAINS[1]),
        (&[0x2b, 0x81, 0x04, 0x00, 0x23], NIST_DOMAINS[2]),
    ];
    if let Some((_, hex)) = NIST.iter().find(|(o, _)| *o == oid) {
        let der: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex")).collect();
        return super::ecdsa::EcDomainKey::explicit(&bc::sequence(&der).ok()?, d);
    }
    let dotted = super::dotted(oid);
    if GOST_CURVES.iter().any(|(o, _)| *o == dotted) {
        return gost_curve(&dotted, &BigInt::from_bytes_be(Sign::Plus, d));
    }
    if let Some(domain) = dstu_domain(oid) {
        return super::ecdsa::EcDomainKey::explicit(&domain, d);
    }
    super::ecdsa::EcDomainKey::named(oid, d)
}

/// `X9ECParameters.getInstance` of explicit parameters as the EC-style key classes read them, then their
/// `getH().intValue()`: the version, the order and the cofactor cast to INTEGERs, then
/// [`super::ecdsa::EcDomainKey::read`]'s checks of the field, curve and base. `Ok(None)` for parameters `read`
/// does not model.
fn x9_parameters(items: &[Asn1]) -> Result<Option<()>, Failure> {
    if items.is_empty() {
        return Err(super::out_of_bounds("java.lang.ArrayIndexOutOfBoundsException", 0, 0));
    }
    if !matches!(items.first(), Some(Asn1::Integer(v)) if v.as_slice() == [1]) {
        return Err(iae("bad version in X9ECParameters"));
    }
    match items.get(4) {
        None => return Err(super::out_of_bounds("java.lang.ArrayIndexOutOfBoundsException", 4, items.len())),
        Some(Asn1::Integer(_)) => {}
        Some(other) => return Err(bc::cast(other, "ASN1Integer")),
    }
    match items.get(5) {
        Some(other) if items.len() == 6 && !matches!(other, Asn1::Integer(_)) => return Err(bc::cast(other, "ASN1Integer")),
        _ => {}
    }
    x9_shape(items)?;
    // the base point is read after the curve: a placeholder octet string lets the curve's own checks come first
    let mut domain = items.to_vec();
    if !matches!(items[3], Asn1::OctetString(..)) {
        domain[3] = Asn1::OctetString("DEROctetString", Vec::new());
    }
    let Some((mut key, base, h)) = super::ecdsa::EcDomainKey::read_curve(&domain).map_err(iae)? else { return Ok(None) };
    // `X9Curve`'s seed, then `X9ECParameters`' base point
    if let Asn1::Sequence(curve, _) = &items[2] && let Some(seed) = curve.get(2).filter(|_| curve.len() == 3) && !matches!(seed, Asn1::BitString("DERBitString", ..)) {
        return Err(bc::cast(seed, "DERBitString"));
    }
    if !matches!(items[3], Asn1::OctetString(..)) {
        return Err(bc::cast(&items[3], "ASN1OctetString"));
    }
    key.decode_base(&base, h.as_ref()).map_err(iae)?;
    if items.len() != 6 {
        return Err(npe("Cannot invoke \"java.math.BigInteger.intValue()\" because the return value of \"shaded_package.org.bouncycastle.asn1.x9.X9ECParameters.getH()\" is null"));
    }
    // the JDK's `ECParameterSpec`: a positive order and cofactor (`getH().intValue()` keeps the low 32 bits)
    if let Asn1::Integer(n) = &items[4] && BigInt::from_signed_bytes_be(n).sign() != Sign::Plus {
        return Err(iae("n is not positive"));
    }
    if let Asn1::Integer(h) = &items[5] {
        let low = BigInt::from_signed_bytes_be(h) & BigInt::from(0xffff_ffffu32);
        if low == BigInt::from(0) || low >= BigInt::from(0x8000_0000u32) {
            return Err(iae("h is not positive"));
        }
    }
    Ok(Some(()))
}

/// `X9FieldID.getInstance` of the field, `ASN1Sequence.getInstance` of the curve and `X9Curve`'s reading of the
/// field's parameters and the curve's elements: each cast and `getInstance` with the exception it throws, in
/// BouncyCastle's order, up to `new ECCurve.Fp(...)` / `ECCurve.F2m(...)` (whose own checks follow in
/// [`super::ecdsa::EcDomainKey::read_curve`], for degrees and exponents that fit its model: those that do not give
/// the field's own refusal here).
fn x9_shape(items: &[Asn1]) -> Result<(), Failure> {
    const PRIME_FIELD: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01];
    const BINARY_FIELD: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x02];
    const TRINOMIAL: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x02, 0x03, 0x02];
    const PENTANOMIAL: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x02, 0x03, 0x03];
    let oob = |index: usize, length: usize| super::out_of_bounds("java.lang.ArrayIndexOutOfBoundsException", index, length);
    let field = bc::sequence_of(&items[1])?;
    let id = match field.first() {
        None => return Err(oob(0, 0)),
        Some(Asn1::Oid(id)) => id,
        Some(other) => return Err(illegal(other)),
    };
    let Some(parameters) = field.get(1) else { return Err(oob(1, field.len())) };
    let curve = bc::sequence_of(&items[2])?;
    // `ASN1OctetString.getInstance(seq.getObjectAt(i))`
    let octets = |i: usize| match curve.get(i) {
        None => Err(oob(i, curve.len())),
        Some(Asn1::OctetString(..)) => Ok(()),
        Some(other) => Err(illegal(other)),
    };
    if id == PRIME_FIELD {
        if !matches!(parameters, Asn1::Integer(_)) {
            return Err(bc::cast(parameters, "ASN1Integer"));
        }
        octets(0)?;
        return octets(1);
    }
    if id != BINARY_FIELD {
        return Err(iae("This type of ECCurve is not implemented"));
    }
    let parameters = bc::sequence_of(parameters)?;
    let m = match parameters.first() {
        None => return Err(oob(0, 0)),
        Some(Asn1::Integer(m)) => bc::int_value_exact(m)?,
        Some(other) => return Err(bc::cast(other, "ASN1Integer")),
    };
    let representation = match parameters.get(1) {
        None => return Err(oob(1, parameters.len())),
        Some(Asn1::Oid(representation)) => representation,
        Some(other) => return Err(bc::cast(other, "ASN1ObjectIdentifier")),
    };
    // `ASN1Integer.getInstance(object).intValueExact()`
    let int = |object: Option<&Asn1>, i: usize, length: usize| match object {
        None => Err(oob(i, length)),
        Some(Asn1::Integer(v)) => bc::int_value_exact(v),
        Some(other) => Err(illegal(other)),
    };
    let mut k = [0i64; 3];
    if representation == TRINOMIAL {
        k[0] = int(parameters.get(2), 2, parameters.len())?;
    } else if representation == PENTANOMIAL {
        let Some(pentanomial) = parameters.get(2) else { return Err(oob(2, parameters.len())) };
        let pentanomial = bc::sequence_of(pentanomial)?;
        for (i, slot) in k.iter_mut().enumerate() {
            *slot = int(pentanomial.get(i), i, pentanomial.len())?;
        }
    } else {
        return Err(iae("This type of EC basis is not implemented"));
    }
    octets(0)?;
    octets(1)?;
    // `ECCurve.AbstractF2m.buildField`
    if m > 1142 {
        return Err(iae(format!("field size out of range: {m}")));
    }
    let exponents: Vec<i64> = if k[1] | k[2] == 0 { vec![0, k[0], m] } else { vec![0, k[0], k[1], k[2], m] };
    if exponents.windows(2).any(|w| w[1] <= w[0]) {
        return Err(iae("Polynomial exponents must be monotonically increasing"));
    }
    Ok(())
}

/// The explicit `SpecifiedECDomain` parameters of P-256, P-384 and P-521 (`openssl ecparam -param_enc explicit`).
const NIST_DOMAINS: [&str; 3] = [
    "3081f7020101302c06072a8648ce3d0101022100ffffffff00000001000000000000000000000000ffffffffffffffffffffffff305b0420ffffffff00000001000000000000000000000000fffffffffffffffffffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b031500c49d360886e704936a6678e1139d26b7819f7e900441046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551020101",
    "30820157020101303c06072a8648ce3d0101023100fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff307b0430fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc0430b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef031500a335926aa319a27a1d00896a6773a4827acdac73046104aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f023100ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973020101",
    "308201c3020101304d06072a8648ce3d0101024201ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff30819f044201fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc04420051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00031500d09e8800291cb85396cc6717393284aaa0da64ba0481850400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650024201fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409020101",
];

/// `GOST3410PublicKeyAlgParameters(ASN1Sequence)`: the public key parameter set's OID (dotted).
fn gost_parameters(items: &[Asn1]) -> Result<String, Failure> {
    let first = items.first().ok_or_else(|| super::out_of_bounds("java.lang.ArrayIndexOutOfBoundsException", 0, 0))?;
    let Asn1::Oid(set) = first else { return Err(illegal(first)) };
    let set = super::dotted(set);
    let absent_digest = ["1.2.643.7.1.2.1.1.2", "1.2.643.7.1.2.1.1.3", "1.2.643.7.1.2.1.1.4"];
    if items.len() > 1 {
        if absent_digest.contains(&set.as_str()) {
            return Err(iae("digestParamSet expected to be absent"));
        }
        if !matches!(items[1], Asn1::Oid(_)) {
            return Err(illegal(&items[1]));
        }
    }
    if items.len() > 2 && !matches!(items[2], Asn1::Oid(_)) {
        return Err(bc::cast(&items[2], "ASN1ObjectIdentifier"));
    }
    Ok(set)
}

fn little_endian(octets: &[u8]) -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, octets)
}

// ---------------------------------------------------------------------------------------------------------------
// ElGamal, GOST R 34.10-94, DSTU 4145
// ---------------------------------------------------------------------------------------------------------------

/// `BCElGamalPrivateKey(PrivateKeyInfo)`: `ElGamalParameter.getInstance` of the parameters (its p and g cast to
/// INTEGERs), `ASN1Integer.getInstance` of the key, then their values.
fn elgamal(info: &bc::PrivateKeyInfo) -> Result<(), Failure> {
    let parameters = sequence(info.parameters.as_ref())?;
    if let Some(items) = parameters {
        let mut elements = items.iter();
        for _ in 0..2 {
            match elements.next() {
                None => return Err(bc::no_such_element()),
                Some(Asn1::Integer(_)) => {}
                Some(other) => return Err(bc::cast(other, "ASN1Integer")),
            }
        }
    }
    match parse_private_key(info)? {
        None => return Err(npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.ASN1Integer.getValue()\" because \"<local3>\" is null")),
        Some(Asn1::Integer(_)) => {}
        Some(other) => return Err(illegal(&other)),
    }
    match parameters {
        Some(_) => Ok(()),
        None => Err(npe("Cannot invoke \"shaded_package.org.bouncycastle.internal.asn1.oiw.ElGamalParameter.getP()\" because \"<local2>\" is null")),
    }
}

/// `BCGOST3410PrivateKey(PrivateKeyInfo)`: `GOST3410PublicKeyAlgParameters`, an INTEGER or a little-endian OCTET
/// STRING key, then `GOST3410ParameterSpec.fromPublicKeyAlg`, which knows the CryptoPro A, B and XchA parameter sets.
fn gost94(info: &bc::PrivateKeyInfo) -> Result<(), Failure> {
    const SETS: [&str; 3] = ["1.2.643.2.2.32.2", "1.2.643.2.2.32.3", "1.2.643.2.2.33.1"];
    let set = match sequence(info.parameters.as_ref())? {
        None => None,
        Some(items) => Some(gost_parameters(items)?),
    };
    match parse_private_key(info)? {
        Some(Asn1::Integer(_) | Asn1::OctetString(..)) => {}
        Some(other) => return Err(illegal(&other)),
        None => return Err(npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.ASN1OctetString.getOctets()\" because \"<local4>\" is null")),
    }
    let Some(set) = set else {
        return Err(npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters.getEncryptionParamSet()\" because \"<parameter1>\" is null"));
    };
    if !SETS.contains(&set.as_str()) {
        return Err(iae("no key parameter set for passed in name/OID."));
    }
    Ok(())
}

/// `BCDSTU4145PrivateKey.populateFromPrivKeyInfo`: X9.62 parameters ([`x962_key`], a named curve looked up in
/// `ECUtil`, then in `DSTU4145NamedCurves`), or `DSTU4145Params` (a named curve or a `DSTU4145ECBinary` curve, and an
/// optional 64-byte DKE), then the key. The curve key BouncyCastle's ECDSA signs with.
fn dstu(info: &bc::PrivateKeyInfo) -> Result<Option<CurveKey>, Failure> {
    let Some(parameters) = info.parameters.as_ref() else {
        return Err(npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.x9.X962Parameters.isNamedCurve()\" because \"<local2>\" is null"));
    };
    let unknown_curve = |local: &str| {
        npe(&format!("Cannot invoke \"shaded_package.org.bouncycastle.crypto.params.ECDomainParameters.getCurve()\" because \"{local}\" is null"))
    };
    match parameters {
        Asn1::Sequence(items, _) if !matches!(items.first(), Some(Asn1::Integer(_))) => {
            let first = items.first().ok_or_else(|| super::out_of_bounds("java.lang.ArrayIndexOutOfBoundsException", 0, 0))?;
            let binary = match first {
                Asn1::Oid(_) => None,
                other => Some(ec_binary(other)?),
            };
            if items.len() == 2 {
                match &items[1] {
                    Asn1::OctetString(_, dke) if dke.len() != 64 => return Err(iae("object parse error")),
                    Asn1::OctetString(..) => {}
                    other => return Err(illegal(other)),
                }
            }
            let Some(binary) = binary else {
                let Asn1::Oid(oid) = first else { unreachable!("a named curve") };
                let domain = dstu_domain(oid).ok_or_else(|| unknown_curve("<local7>"))?;
                let d = super::jca::ec_scalar(parse_private_key(info)?, "<local4>")?;
                return Ok(Some((d.to_biguint().and_then(|d| super::ecdsa::EcDomainKey::explicit(&domain, &d.to_bytes_be())), SunEc::Encoding)));
            };
            // under dstu4145le the curve's b and base point are little-endian
            let little = super::dotted(&info.algorithm) == "1.2.804.2.1.1.1.1.3.1.1";
            let (mut b, mut g) = (binary.b.clone(), binary.g.clone());
            if little {
                b.reverse();
                g.reverse();
            }
            let mut key = super::ecdsa::EcDomainKey::dstu_binary(binary.m, binary.k, &binary.a, &b).map_err(iae)?;
            if g.is_empty() {
                return Err(throwable("java.lang.ArrayIndexOutOfBoundsException", Some("Index -1 out of bounds for length 0".into()), None));
            }
            key.set_dstu_base(&g).map_err(iae)?;
            // the JDK's `ECParameterSpec` wants a positive order
            let Some(order) = binary.n.to_biguint().filter(|n| n.bits() > 0).map(|n| n.to_bytes_be()) else { return Err(iae("n is not positive")) };
            let d = super::jca::ec_scalar(parse_private_key(info)?, "<local4>")?;
            let Some(d) = d.to_biguint() else { return Ok(Some((None, SunEc::Encoding))) };
            key.set_order_and_key(&order, &d.to_bytes_be());
            Ok(Some((Some(key), SunEc::Encoding)))
        }
        _ => x962_key(info, parameters, |oid| if dstu_domain(oid).is_some() { Ok(()) } else { Err(unknown_curve("<local5>")) }, "<local4>"),
    }
}

/// A `DSTU4145ECBinary`: the binary field's degree and `k1`..`k3` (a trinomial's `k2` and `k3` are 0), a, b, the
/// order and the base point's octets (big-endian in the parameters).
struct EcBinary {
    m: i64,
    k: [i64; 3],
    a: BigInt,
    b: Vec<u8>,
    n: BigInt,
    g: Vec<u8>,
}

/// `ASN1Integer.intPositiveValueExact`: up to four octets and, at four, not negative; any shorter value is read as
/// unsigned octets (`-1` is 255).
fn int_positive_exact(bytes: &[u8]) -> Result<i64, Failure> {
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] as i8 == (bytes[start + 1] as i8) >> 7 {
        start += 1;
    }
    let value = &bytes[start..];
    if value.len() > 4 || (value.len() == 4 && value[0] & 0x80 != 0) {
        return Err(throwable("java.lang.ArithmeticException", Some("ASN.1 Integer out of positive int range".into()), None));
    }
    Ok(value.iter().fold(0, |acc, b| (acc << 8) | i64::from(*b)))
}

/// `DSTU4145ECBinary.getInstance`: an optional `[0]` version (a tagged object BouncyCastle 1.86 cannot read as an
/// INTEGER), the `DSTU4145BinaryField`, a, b, n and the base point.
fn ec_binary(object: &Asn1) -> Result<EcBinary, Failure> {
    let items = bc::sequence_of(object)?;
    let at = |i: usize| items.get(i).ok_or_else(|| super::out_of_bounds("java.lang.ArrayIndexOutOfBoundsException", i, items.len()));
    let mut index = 0;
    if let tagged @ Asn1::Tagged { no, .. } = at(0)? {
        // `getLoadedObject()` is the tagged object itself: `ASN1Integer.getInstance` refuses it
        if tagged.explicit().is_some() && *no == 0 {
            return Err(illegal(tagged));
        }
        return Err(iae("object parse error"));
    }
    // `DSTU4145BinaryField.getInstance`
    let field = bc::sequence_of(at(index)?)?;
    let field_at = |i: usize| field.get(i).ok_or_else(|| super::out_of_bounds("java.lang.ArrayIndexOutOfBoundsException", i, field.len()));
    let m = match field_at(0)? {
        Asn1::Integer(m) => int_positive_exact(m)?,
        other => return Err(illegal(other)),
    };
    let mut k = [0i64; 3];
    match field_at(1)? {
        Asn1::Integer(v) => k[0] = int_positive_exact(v)?,
        Asn1::Sequence(coefficients, _) => {
            for (i, slot) in k.iter_mut().enumerate() {
                match coefficients.get(i) {
                    None => return Err(super::out_of_bounds("java.lang.ArrayIndexOutOfBoundsException", i, coefficients.len())),
                    Some(Asn1::Integer(v)) => *slot = int_positive_exact(v)?,
                    Some(other) => return Err(illegal(other)),
                }
            }
        }
        _ => return Err(iae("object parse error")),
    }
    index += 1;
    let a = integer(at(index)?)?;
    let octet_string = |object: &Asn1| match object {
        Asn1::OctetString(_, octets) => Ok(octets.clone()),
        other => Err(illegal(other)),
    };
    let b = octet_string(at(index + 1)?)?;
    let n = integer(at(index + 2)?)?;
    let g = octet_string(at(index + 3)?)?;
    Ok(EcBinary { m, k, a, b, n, g })
}

/// A DSTU 4145 curve as [`DSTU_CURVES`] lists it.
type DstuCurve = (usize, &'static [usize], u8, &'static str, &'static str, &'static str, &'static str, u8);

/// `DSTU4145NamedCurves`: each curve's degree, the exponents of its reduction polynomial below it, a, b, the base
/// point's x and y, the order and the cofactor (hex), by the last arc of `1.2.804.2.1.1.1.1.3.1.1.2.<i>`.
const DSTU_CURVES: [DstuCurve; 10] = [
    (163, &[3, 6, 7], 1, "5FF6108462A2DC8210AB403925E638A19C1455D21", "2E2F85F5DD74CE983A5C4237229DAF8A3F35823BE", "3826F008A8C51D7B95284D9D03FF0E00CE2CD723A", "400000000000000000002BEC12BE2262D39BCF14D", 2),
    (167, &[6], 1, "6EE3CEEB230811759F20518A0930F1A4315A827DAC", "7A1F6653786A68192803910A3D30B2A2018B21CD54", "5F49EB26781C0EC6B8909156D98ED435E45FD59918", "3FFFFFFFFFFFFFFFFFFFFFB12EBCC7D7F29FF7701F", 2),
    (173, &[1, 2, 10], 0, "108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", "4D41A619BCC6EADF0448FA22FAD567A9181D37389CA", "10B51CC12849B234C75E6DD2028BF7FF5C1CE0D991A1", "800000000000000000000189B4E67606E3825BB2831", 4),
    (179, &[1, 2, 4], 1, "4A6E0856526436F2F88DD07A341E32D04184572BEB710", "6BA06FE51464B2BD26DC57F48819BA9954667022C7D03", "25FBC363582DCEC065080CA8287AAFF09788A66DC3A9E", "3FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236EF", 2),
    (191, &[9], 1, "7BC86E2102902EC4D5890E8B6B4981ff27E0482750FEFC03", "714114B762F2FF4A7912A6D2AC58B9B5C2FCFE76DAEB7129", "29C41E568B77C617EFE5902F11DB96FA9613CD8D03DB08DA", "40000000000000000000000069A779CAC1DABC6788F7474F", 2),
    (233, &[1, 4, 9], 1, "06973B15095675534C7CF7E64A21BD54EF5DD3B8A0326AA936ECE454D2C", "3FCDA526B6CDF83BA1118DF35B3C31761D3545F32728D003EEB25EFE96", "9CA8B57A934C54DEEDA9E54A7BBAD95E3B2E91C54D32BE0B9DF96D8D35", "1000000000000000000000000000013E974E72F8A6922031D2603CFE0D7", 2),
    (257, &[12], 0, "1CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10", "02A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7", "10686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF", "800000000000000000000000000000006759213AF182E987D3E17714907D470D", 4),
    (307, &[2, 4, 8], 1, "393C7F7D53666B5054B5E6C6D3DE94F4296C0C599E2E2E241050DF18B6090BDC90186904968BB", "216EE8B189D291A0224984C1E92F1D16BF75CCD825A087A239B276D3167743C52C02D6E7232AA", "5D9306BACD22B7FAEB09D2E049C6E2866C5D1677762A8F2F2DC9A11C7F7BE8340AB2237C7F2A0", "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC079C2F3825DA70D390FBBA588D4604022B7B7", 2),
    (367, &[21], 1, "43FC8AD242B0B7A6F3D1627AD5654447556B47BF6AA4A64B0C2AFE42CADAB8F93D92394C79A79755437B56995136", "324A6EDDD512F08C49A99AE0D3F961197A76413E7BE81A400CA681E09639B5FE12E59A109F78BF4A373541B3B9A1", "1AB597A5B4477F59E39539007C7F977D1A567B92B043A49C6B61984C3FE3481AAF454CD41BA1F051626442B3C10", "40000000000000000000000000000000000000000000009C300B75A3FA824F22428FD28CE8812245EF44049B2D49", 2),
    (431, &[1, 3, 5], 1, "03CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66BAC536B18AE2DC312CA493117DAA469C640CAF3", "1A62BA79D98133A16BBAE7ED9A8E03C32E0824D57AEF72F88986874E5AAE49C27BED49A2A95058068426C2171E99FD3B43C5947C857D", "70B5E1E14031C1F70BBEFE96BDDE66F451754B4CA5F48DA241F331AA396B8D1839A855C1769B1EA14BA53308B5E2723724E090E02DB9", "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF", 2),
];

/// The `SpecifiedECDomain` elements of the DSTU 4145 named curve `oid` (its content octets), as
/// [`super::ecdsa::EcDomainKey::read`] reads them; `None` for any other OID (`DSTU4145NamedCurves.getByOID`).
fn dstu_domain(oid: &[u8]) -> Option<Vec<Asn1>> {
    let i: usize = super::dotted(oid).strip_prefix("1.2.804.2.1.1.1.1.3.1.1.2.")?.parse().ok()?;
    let (m, ks, a, b, x, y, n, h) = DSTU_CURVES.get(i)?;
    const BINARY_FIELD: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x02];
    const TRINOMIAL: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x02, 0x03, 0x02];
    const PENTANOMIAL: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x02, 0x03, 0x03];
    let len = m.div_ceil(8);
    let hex = |s: &str| num_bigint::BigUint::parse_bytes(s.as_bytes(), 16).expect("hex");
    let element = |s: &str| super::fixed_len(&hex(s).to_bytes_be(), len).expect("an element of the field");
    let int = |v: num_bigint::BigUint| {
        let v = v.to_bytes_be();
        Asn1::Integer(if v[0] & 0x80 != 0 { [vec![0], v].concat() } else { v })
    };
    let basis = if ks.len() == 1 {
        vec![Asn1::Oid(TRINOMIAL.to_vec()), int(ks[0].into())]
    } else {
        vec![Asn1::Oid(PENTANOMIAL.to_vec()), Asn1::Sequence(ks.iter().map(|k| int((*k).into())).collect(), false)]
    };
    let field = Asn1::Sequence(vec![Asn1::Oid(BINARY_FIELD.to_vec()), Asn1::Sequence([vec![int((*m).into())], basis].concat(), false)], false);
    let a = super::fixed_len(&[*a], len).expect("0 or 1");
    Some(vec![
        Asn1::Integer(vec![1]),
        field,
        Asn1::Sequence(vec![Asn1::OctetString("DEROctetString", a), Asn1::OctetString("DEROctetString", element(b))], false),
        Asn1::OctetString("DEROctetString", [vec![4], element(x), element(y)].concat()),
        int(hex(n)),
        int((*h).into()),
    ])
}

// ---------------------------------------------------------------------------------------------------------------
// ML-DSA, ML-KEM, SLH-DSA (`PrivateKeyFactory.createKey`)
// ---------------------------------------------------------------------------------------------------------------

/// `BasePQCKeyFactorySpi.engineGeneratePrivate`: an IllegalStateException's message, any other exception's
/// `toString`, without a cause.
fn pqc(e: Failure) -> Failure {
    let message = if e.classes[0] == "java.lang.IllegalStateException" { e.message.clone() } else { java_string(&e) };
    unable(throwable(INVALID_KEY_SPEC, Some(message), None))
}

/// The pqc `BaseKeyFactorySpi.engineGeneratePrivate`: `SecurityExceptions.invalidKeySpecException` of the
/// exception's `toString` (an IllegalStateException's message), the exception its cause.
fn slh(e: Failure) -> Failure {
    let message = if e.classes[0] == "java.lang.IllegalStateException" { e.message.clone() } else { java_string(&e) };
    unable(throwable(INVALID_KEY_SPEC, Some(message), Some(e)))
}

/// An ML-DSA OID's parameter set name and security level (its `k`).
fn ml_dsa(dotted: &str) -> Option<(&'static str, usize)> {
    Some(match dotted {
        "2.16.840.1.101.3.4.3.17" => ("ml-dsa-44", 44),
        "2.16.840.1.101.3.4.3.18" => ("ml-dsa-65", 65),
        "2.16.840.1.101.3.4.3.19" => ("ml-dsa-87", 87),
        "2.16.840.1.101.3.4.3.32" => ("ml-dsa-44-with-sha512", 44),
        "2.16.840.1.101.3.4.3.33" => ("ml-dsa-65-with-sha512", 65),
        "2.16.840.1.101.3.4.3.34" => ("ml-dsa-87-with-sha512", 87),
        _ => return None,
    })
}

/// An ML-KEM OID's `k`.
fn ml_kem(dotted: &str) -> Option<usize> {
    Some(match dotted {
        "2.16.840.1.101.3.4.4.1" => 2,
        "2.16.840.1.101.3.4.4.2" => 3,
        "2.16.840.1.101.3.4.4.3" => 4,
        _ => return None,
    })
}

/// An SLH-DSA OID's parameter set name and `n`.
fn slh_dsa(dotted: &str) -> Option<(&'static str, usize)> {
    const NAMES: [(&str, usize); 12] = [
        ("sha2-128s", 16), ("sha2-128f", 16), ("sha2-192s", 24), ("sha2-192f", 24), ("sha2-256s", 32), ("sha2-256f", 32),
        ("shake-128s", 16), ("shake-128f", 16), ("shake-192s", 24), ("shake-192f", 24), ("shake-256s", 32), ("shake-256f", 32),
    ];
    const HASHED: [&str; 12] = [
        "sha2-128s-with-sha256", "sha2-128f-with-sha256", "sha2-192s-with-sha512", "sha2-192f-with-sha512",
        "sha2-256s-with-sha512", "sha2-256f-with-sha512", "shake-128s-with-shake128", "shake-128f-with-shake128",
        "shake-192s-with-shake256", "shake-192f-with-shake256", "shake-256s-with-shake256", "shake-256f-with-shake256",
    ];
    let arc: usize = dotted.strip_prefix("2.16.840.1.101.3.4.3.")?.parse().ok()?;
    match arc {
        20..=31 => Some(NAMES[arc - 20]),
        35..=46 => Some((HASHED[arc - 35], NAMES[arc - 35].1)),
        _ => None,
    }
}

/// `Utils.readLen` over the bytes after the tag: `ByteArrayInputStream.read` is -1 past the end.
fn is_raw(data: &[u8]) -> bool {
    let mut pos = 0usize;
    let mut read = || -> i64 {
        let b = data.get(pos).map_or(-1, |b| i64::from(*b));
        pos += 1;
        b
    };
    read();
    let mut length = read();
    if length >= 0 && length != (length & 0x7f) {
        let mut count = length & 0x7f;
        length = 0;
        while count != 0 {
            length = (length << 8).wrapping_add(read());
            count -= 1;
        }
    }
    let available = data.len().saturating_sub(pos) as i64;
    length != available
}

/// `ASN1OctetString.getInstance(byte[])`.
fn octet_string_of(data: &[u8]) -> Result<Vec<u8>, Failure> {
    match bc::from_byte_array(data) {
        Err(e) if e.classes[0] != "java.lang.IllegalArgumentException" => {
            Err(iae(format!("failed to construct OCTET STRING from byte[]: {}", e.message)))
        }
        Err(e) => Err(e),
        Ok(Some(Asn1::OctetString(_, octets))) => Ok(octets),
        Ok(Some(other)) => Err(illegal(&other)),
        Ok(None) => Err(null_octets()),
    }
}

/// A decoded key: its raw octets, or a SEQUENCE's elements.
enum PqcKey {
    Octets(Vec<u8>),
    Sequence(Vec<Asn1>),
}

/// `PrivateKeyFactory.parsePrimitiveString`: the octets as they are at the raw length, else an inner OCTET
/// STRING, SEQUENCE or `[0]` IMPLICIT OCTET STRING when the octets are one well-formed object.
fn primitive_string(data: &[u8], raw_length: usize) -> Result<PqcKey, Failure> {
    if data.len() == raw_length || data.is_empty() || is_raw(data) {
        return Ok(PqcKey::Octets(data.to_vec()));
    }
    match data[0] {
        0x30 => bc::sequence(data).map(PqcKey::Sequence),
        0x04 => octet_string_of(data).map(PqcKey::Octets),
        0x80 => match bc::from_byte_array(data) {
            Ok(Some(Asn1::Tagged { .. })) => Ok(PqcKey::Octets(data[header_len(data)..].to_vec())),
            Ok(_) => Ok(PqcKey::Octets(data.to_vec())),
            Err(e) => Err(iae(format!("failed to construct tagged object from byte[]: {}", e.message))),
        },
        _ => Ok(PqcKey::Octets(data.to_vec())),
    }
}

/// The length of a DER object's tag and length octets.
fn header_len(data: &[u8]) -> usize {
    match data.get(1) {
        Some(l) if l & 0x80 != 0 => 2 + usize::from(l & 0x7f),
        _ => 2,
    }
}

/// `ASN1Sequence.getObjectAt(i)` cast by `ASN1OctetString.getInstance`.
fn element_octets(items: &[Asn1], i: usize) -> Result<Vec<u8>, Failure> {
    match items.get(i) {
        None => Err(super::out_of_bounds("java.lang.ArrayIndexOutOfBoundsException", i, items.len())),
        Some(Asn1::OctetString(_, octets)) => Ok(octets.clone()),
        Some(other) => Err(illegal(other)),
    }
}

/// `MLDSAPrivateKeyParameters(params, encoding, null)`: a 32-byte seed (expanded) or the expanded key.
fn ml_dsa_encoding(level: usize, encoding: &[u8]) -> Result<Option<Vec<u8>>, Failure> {
    let expanded = match level {
        44 => 2560,
        65 => 4032,
        _ => 4896,
    };
    if encoding.len() != 32 && encoding.len() != expanded {
        return Err(iae("'encoding' has invalid length"));
    }
    if encoding.len() != 32 {
        return Ok(None);
    }
    use aws_lc_rs::encoding::AsRawBytes;
    use aws_lc_rs::signature::{PqdsaKeyPair, ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING};
    let algorithm = match level {
        44 => &ML_DSA_44_SIGNING,
        65 => &ML_DSA_65_SIGNING,
        _ => &ML_DSA_87_SIGNING,
    };
    let pair = PqdsaKeyPair::from_seed(algorithm, encoding).expect("a 32-byte seed");
    Ok(Some(pair.private_key().as_raw_bytes().expect("an expanded key").as_ref().to_vec()))
}

fn ml_dsa_key(info: &bc::PrivateKeyInfo, name: &str, level: usize) -> Result<(), Failure> {
    match primitive_string(&info.key, 32)? {
        PqcKey::Octets(encoding) => ml_dsa_encoding(level, &encoding).map(|_| ()),
        PqcKey::Sequence(items) => {
            let seed = element_octets(&items, 0)?;
            let encoding = element_octets(&items, 1)?;
            // the seed's expanded key against the one given (`MLDSAPrivateKeyParameters.getEncoded`)
            let expanded = match ml_dsa_encoding(level, &seed)? {
                Some(expanded) => expanded,
                None => seed,
            };
            if expanded != encoding {
                return Err(iae(format!("inconsistent {name} private key")));
            }
            Ok(())
        }
    }
}

/// `MLKEMPrivateKeyParameters(params, encoding, null)`: a 64-byte seed (expanded) or the expanded key, which must
/// pass the hash check.
fn ml_kem_encoding(k: usize, encoding: &[u8]) -> Result<Vec<u8>, Failure> {
    if encoding.len() != 64 && encoding.len() != 768 * k + 96 {
        return Err(iae("'encoding' has invalid length"));
    }
    let expanded = if encoding.len() == 64 { super::mlkem::expand(k, encoding) } else { encoding.to_vec() };
    if !super::mlkem::hash_check(k, &expanded) {
        return Err(iae("'encoding' fails hash check"));
    }
    Ok(expanded)
}

fn ml_kem_key(info: &bc::PrivateKeyInfo, k: usize, name: &str) -> Result<(), Failure> {
    match primitive_string(&info.key, 64)? {
        PqcKey::Octets(encoding) => ml_kem_encoding(k, &encoding).map(|_| ()),
        PqcKey::Sequence(items) => {
            let seed = element_octets(&items, 0)?;
            let encoding = element_octets(&items, 1)?;
            let expanded = ml_kem_encoding(k, &seed)?;
            if expanded != encoding {
                return Err(iae(format!("inconsistent {name} private key")));
            }
            Ok(())
        }
    }
}

/// `Utils.parseOctetString`: the raw octets at `expected` octets, else an inner OCTET STRING where they are one.
fn parse_octet_string(data: &[u8], expected: usize) -> Result<Vec<u8>, Failure> {
    if data.len() == expected || data.is_empty() || is_raw(data) || data[0] != 0x04 { Ok(data.to_vec()) } else { octet_string_of(data) }
}

/// `Utils.parseOctetString` and `SLHDSAPrivateKeyParameters`' length check.
fn slh_dsa_key(info: &bc::PrivateKeyInfo, n: usize) -> Result<(), Failure> {
    let key = parse_octet_string(&info.key, 4 * n)?;
    if key.len() != 4 * n {
        return Err(iae("private key encoding does not match parameters"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Falcon, NTRU, FrodoKEM, Classic McEliece (`PrivateKeyFactory.createKey`)
// ---------------------------------------------------------------------------------------------------------------

/// A Falcon OID's algorithm name.
fn falcon(dotted: &str) -> Option<&'static str> {
    match dotted {
        "1.3.9999.3.11" => Some("FALCON-512"),
        "1.3.9999.3.14" => Some("FALCON-1024"),
        _ => None,
    }
}

/// `FalconPrivateKey.getInstance` of the key (a version 0, f, g and F, and with a fifth element the
/// `FalconPublicKey`), then its `getf()` and `getPublicKey().getH()`.
fn falcon_key(info: &bc::PrivateKeyInfo) -> Result<(), Failure> {
    let items = match parse_private_key(info)? {
        None => return Err(npe("Cannot invoke \"shaded_package.org.bouncycastle.pqc.asn1.FalconPrivateKey.getf()\" because \"<local3>\" is null")),
        Some(Asn1::Sequence(items, _)) => items,
        Some(other) => return Err(unknown(&other)),
    };
    let version = items.first().ok_or_else(|| super::out_of_bounds("java.lang.ArrayIndexOutOfBoundsException", 0, 0))?;
    let Asn1::Integer(version) = version else { return Err(illegal(version)) };
    if bc::int_value_exact(version)? != 0 {
        return Err(iae("unrecognized version"));
    }
    for i in 1..4 {
        element_octets(&items, i)?;
    }
    if items.len() != 5 {
        return Err(npe("Cannot invoke \"shaded_package.org.bouncycastle.pqc.asn1.FalconPublicKey.getH()\" because the return value of \"shaded_package.org.bouncycastle.pqc.asn1.FalconPrivateKey.getPublicKey()\" is null"));
    }
    let public = sequence(Some(&items[4]))?.expect("an object");
    element_octets(public, 0).map(|_| ())
}

/// `NTRUPrivateKeyParameters`: the key's octets of the parameter set's length; the bare NTRU OID has no parameter
/// set.
fn ntru_key(info: &bc::PrivateKeyInfo, dotted: &str) -> Result<(), Failure> {
    const LENGTHS: [usize; 6] = [935, 1234, 1590, 1450, 2366, 2983];
    let set = dotted.strip_prefix("1.3.6.1.4.1.22554.5.5.").and_then(|s| s.parse::<usize>().ok()).filter(|i| (1..=6).contains(i));
    let Some(set) = set else {
        return Err(throwable("java.io.IOException", Some(format!("algorithm identifier in private key not recognised: {dotted}")), None));
    };
    sized_key(info, LENGTHS[set - 1], "'key' has invalid length")
}

/// A FrodoKEM OID's algorithm name and private key length.
fn frodo(dotted: &str) -> Option<(&'static str, usize)> {
    const NAMES: [&str; 8] = [
        "frodokem976shake", "frodokem1344shake", "efrodokem976shake", "efrodokem1344shake", "frodokem976aes", "frodokem1344aes",
        "efrodokem976aes", "efrodokem1344aes",
    ];
    let i: usize = dotted.strip_prefix("1.0.18033.2.2.7.")?.parse().ok()?;
    let name = NAMES.get(i.checked_sub(1)?)?;
    Some((name, if name.contains("976") { 31296 } else { 43088 }))
}

/// A Classic McEliece OID's algorithm name and private key length.
fn cmce(dotted: &str) -> Option<(&'static str, usize)> {
    const SETS: [(&str, usize); 16] = [
        ("mceliece460896", 13608), ("mceliece460896f", 13608), ("mceliece460896pc", 13608), ("mceliece460896pcf", 13608),
        ("mceliece6688128", 13932), ("mceliece6688128f", 13932), ("mceliece6688128pc", 13932), ("mceliece6688128pcf", 13932),
        ("mceliece6960119", 13948), ("mceliece6960119f", 13948), ("mceliece6960119pc", 13948), ("mceliece6960119pcf", 13948),
        ("mceliece8192128", 14120), ("mceliece8192128f", 14120), ("mceliece8192128pc", 14120), ("mceliece8192128pcf", 14120),
    ];
    let i: usize = dotted.strip_prefix("1.0.18033.2.2.6.")?.parse().ok()?;
    SETS.get(i.checked_sub(1)?).copied()
}

/// `ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets()` of `size` octets.
fn sized_key(info: &bc::PrivateKeyInfo, size: usize, refusal: &str) -> Result<(), Failure> {
    if octets(info)?.len() != size {
        return Err(iae(refusal));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Composite ML-DSA and ML-KEM (`COMPOSITE$KeyFactory`)
// ---------------------------------------------------------------------------------------------------------------

/// A composite OID's algorithm name, whether it is a KEM (an ML-KEM seed of 64 bytes first, else an ML-DSA seed of
/// 32), its components' OIDs and parameters (`pairings`), and the traditional key factory's name.
struct Composite {
    name: &'static str,
    kem: bool,
    first: &'static str,
    second: (&'static str, Option<&'static [u8]>),
    traditional: &'static str,
}

/// `CompositeIndex` (signatures and KEMs) of BouncyCastle 1.86, read off its table.
fn composite(dotted: &str) -> Option<Composite> {
    const RSA: (&str, Option<&[u8]>) = ("1.2.840.113549.1.1.1", Some(&[0x05, 0x00]));
    const ED25519: (&str, Option<&[u8]>) = ("1.3.101.112", None);
    const ED448: (&str, Option<&[u8]>) = ("1.3.101.113", None);
    const X25519: (&str, Option<&[u8]>) = ("1.3.101.110", None);
    const X448: (&str, Option<&[u8]>) = ("1.3.101.111", None);
    const EC: &str = "1.2.840.10045.2.1";
    const P256: (&str, Option<&[u8]>) = (EC, Some(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]));
    const P384: (&str, Option<&[u8]>) = (EC, Some(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]));
    const P521: (&str, Option<&[u8]>) = (EC, Some(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]));
    const BP256: (&str, Option<&[u8]>) = (EC, Some(&[0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07]));
    const BP384: (&str, Option<&[u8]>) = (EC, Some(&[0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b]));
    // RSAES-OAEP with SHA-256 and MGF1-SHA-256
    const OAEP: (&str, Option<&[u8]>) = ("1.2.840.113549.1.1.7", Some(&[
        0x30, 0x2b, 0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0xa1, 0x1a, 0x30, 0x18, 0x06,
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01,
    ]));
    const MLDSA44: &str = "2.16.840.1.101.3.4.3.17";
    const MLDSA65: &str = "2.16.840.1.101.3.4.3.18";
    const MLDSA87: &str = "2.16.840.1.101.3.4.3.19";
    const MLKEM768: &str = "2.16.840.1.101.3.4.4.2";
    const MLKEM1024: &str = "2.16.840.1.101.3.4.4.3";
    let arc: usize = dotted.strip_prefix("1.3.6.1.5.5.7.6.")?.parse().ok()?;
    let (name, first, second, traditional) = match arc {
        37 => ("MLDSA44-RSA2048-PSS-SHA256", MLDSA44, RSA, "RSA"),
        38 => ("MLDSA44-RSA2048-PKCS15-SHA256", MLDSA44, RSA, "RSA"),
        39 => ("MLDSA44-Ed25519-SHA512", MLDSA44, ED25519, "Ed25519"),
        40 => ("MLDSA44-ECDSA-P256-SHA256", MLDSA44, P256, "EC"),
        41 => ("MLDSA65-RSA3072-PSS-SHA512", MLDSA65, RSA, "RSA"),
        42 => ("MLDSA65-RSA3072-PKCS15-SHA512", MLDSA65, RSA, "RSA"),
        43 => ("MLDSA65-RSA4096-PSS-SHA512", MLDSA65, RSA, "RSA"),
        44 => ("MLDSA65-RSA4096-PKCS15-SHA512", MLDSA65, RSA, "RSA"),
        45 => ("MLDSA65-ECDSA-P256-SHA512", MLDSA65, P256, "EC"),
        46 => ("MLDSA65-ECDSA-P384-SHA512", MLDSA65, P384, "EC"),
        47 => ("MLDSA65-ECDSA-brainpoolP256r1-SHA512", MLDSA65, BP256, "EC"),
        48 => ("MLDSA65-Ed25519-SHA512", MLDSA65, ED25519, "Ed25519"),
        49 => ("MLDSA87-ECDSA-P384-SHA512", MLDSA87, P384, "EC"),
        50 => ("MLDSA87-ECDSA-brainpoolP384r1-SHA512", MLDSA87, BP384, "EC"),
        51 => ("MLDSA87-Ed448-SHAKE256", MLDSA87, ED448, "Ed448"),
        52 => ("MLDSA87-RSA3072-PSS-SHA512", MLDSA87, RSA, "RSA"),
        53 => ("MLDSA87-RSA4096-PSS-SHA512", MLDSA87, RSA, "RSA"),
        54 => ("MLDSA87-ECDSA-P521-SHA512", MLDSA87, P521, "EC"),
        55 => ("MLKEM768-RSA2048-SHA3-256", MLKEM768, OAEP, "RSA"),
        56 => ("MLKEM768-RSA3072-SHA3-256", MLKEM768, OAEP, "RSA"),
        57 => ("MLKEM768-RSA4096-SHA3-256", MLKEM768, OAEP, "RSA"),
        58 => ("MLKEM768-X25519-SHA3-256", MLKEM768, X25519, "X25519"),
        59 => ("MLKEM768-ECDH-P256-SHA3-256", MLKEM768, P256, "EC"),
        60 => ("MLKEM768-ECDH-P384-SHA3-256", MLKEM768, P384, "EC"),
        61 => ("MLKEM768-ECDH-brainpoolP256r1-SHA3-256", MLKEM768, BP256, "EC"),
        62 => ("MLKEM1024-RSA3072-SHA3-256", MLKEM1024, OAEP, "RSA"),
        63 => ("MLKEM1024-ECDH-P384-SHA3-256", MLKEM1024, P384, "EC"),
        64 => ("MLKEM1024-ECDH-brainpoolP384r1-SHA3-256", MLKEM1024, BP384, "EC"),
        65 => ("MLKEM1024-X448-SHA3-256", MLKEM1024, X448, "X448"),
        66 => ("MLKEM1024-ECDH-P521-SHA3-256", MLKEM1024, P521, "EC"),
        _ => return None,
    };
    Some(Composite { name, kem: arc >= 55, first, second, traditional })
}

/// A component key through its own key factory, as `JcaPEMKeyConverter` reaches [`super::jca::private_key`]: the
/// `InvalidKeySpecException`'s (or `NoSuchAlgorithmException`'s) message where it fails; `Ok(None)` where the
/// component is not modelled.
fn component(info: &bc::PrivateKeyInfo) -> Result<Option<Signer>, String> {
    super::jca::private_key(info).map_err(|e| match e.bean.get("cause").and_then(|c| c.get("message")).and_then(|m| m.as_str()) {
        Some(message) => message.to_string(),
        None => e.message,
    })
}

fn io(message: String) -> Failure {
    throwable("java.io.IOException", Some(message), None)
}

/// The composite key factories' `generatePrivate` over the IANA OIDs: the body is the ML-DSA seed (32 octets) or the
/// ML-KEM seed (64) followed by the traditional key (an Ed25519/Ed448 key given the OCTET STRING header of its
/// size), each read by its own key factory under the pairing's algorithm identifier. A signature key's body is the
/// key's octets, or the octets of an OCTET STRING they encode.
fn composite_key(info: &bc::PrivateKeyInfo, c: Composite) -> Result<Option<Signer>, Failure> {
    let data = if c.kem {
        info.key.clone()
    } else {
        match parse_private_key(info) {
            Ok(Some(Asn1::OctetString(_, octets))) => octets,
            _ => info.key.clone(),
        }
    };
    let split = if c.kem { 64 } else { 32 };
    if data.len() < split {
        let seed = if c.kem { "ML-KEM" } else { "ML-DSA" };
        return Err(io(format!("malformed composite private key: body shorter than the {seed} seed")));
    }
    let traditional = match c.traditional {
        "Ed25519" if !c.kem => [&[0x04, 0x20][..], &data[split..]].concat(),
        "Ed448" if !c.kem => [&[0x04, 0x39][..], &data[split..]].concat(),
        _ => data[split..].to_vec(),
    };
    let oid = |dotted: &str| bc::oid_content(dotted);
    let parameters = |p: Option<&[u8]>| p.map(|der| bc::from_byte_array(der).expect("DER").expect("an object"));
    let parts = [(oid(c.first), None, data[..split].to_vec()), (oid(c.second.0), parameters(c.second.1), traditional)];
    for (algorithm, parameters, key) in parts {
        if component(&bc::PrivateKeyInfo { algorithm, parameters, key, public_key: None }).map_err(io)?.is_none() {
            return Ok(None);
        }
    }
    Ok(Some(Signer::Other(OtherKey { algorithm: Some(c.name.into()), class: "jcajce.CompositePrivateKey", gost: None, sun_ec: SunEc::Encoding })))
}

/// The generic composite OIDs: the body is a SEQUENCE of PrivateKeyInfos, each read by the key factory of its
/// algorithm (`cannot decode generic composite: <message>`). The key has no algorithm name.
fn generic_composite_key(info: &bc::PrivateKeyInfo) -> Result<Option<Signer>, Failure> {
    let items = match parse_private_key(info)? {
        Some(Asn1::Sequence(items, _)) => items,
        Some(other) => return Err(unknown(&other)),
        None => return Err(npe("Cannot invoke \"shaded_package.org.bouncycastle.asn1.ASN1Sequence.size()\" because \"<local3>\" is null")),
    };
    for item in &items {
        let element = sequence(Some(item))?.expect("an object");
        let component_info = bc::private_key_info_of(element)?;
        match component(&component_info) {
            Err(message) => return Err(io(format!("cannot decode generic composite: {message}"))),
            Ok(None) => return Ok(None),
            Ok(Some(_)) => {}
        }
    }
    if items.is_empty() {
        return Err(iae("at least one private key must be provided for the composite private key"));
    }
    Ok(Some(Signer::Other(OtherKey { algorithm: None, class: "jcajce.CompositePrivateKey", gost: None, sun_ec: SunEc::Encoding })))
}

// ---------------------------------------------------------------------------------------------------------------
// HSS/LMS (`LmsKeyUtil.createPrivateKey`)
// ---------------------------------------------------------------------------------------------------------------

/// A `DataInputStream` over a byte array.
struct Stream<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Stream<'a> {
    fn available(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_fully(&mut self, n: usize) -> Result<&'a [u8], Failure> {
        if n > self.available() {
            return Err(throwable("java.io.EOFException", None, None));
        }
        self.pos += n;
        Ok(&self.data[self.pos - n..self.pos])
    }

    fn read_int(&mut self) -> Result<i32, Failure> {
        Ok(i32::from_be_bytes(self.read_fully(4)?.try_into().expect("4 bytes")))
    }

    fn read_long(&mut self) -> Result<i64, Failure> {
        Ok(i64::from_be_bytes(self.read_fully(8)?.try_into().expect("8 bytes")))
    }
}

fn io_failure(message: String) -> Failure {
    throwable("java.io.IOException", Some(message), None)
}

/// `LMSigParameters.getParametersForType`: m, h and whether the tree hash is SHAKE256.
fn lms_parameters(code: i32) -> Option<(usize, u32, bool)> {
    let i = usize::try_from(code).ok()?.checked_sub(5).filter(|i| *i < 20)?;
    Some((if (i / 5) % 2 == 0 { 32 } else { 24 }, [5, 10, 15, 20, 25][i % 5], i >= 10))
}

/// `LMOtsParameters.getParametersForType`: n and p.
fn lm_ots_parameters(code: i32) -> Option<(usize, usize)> {
    let i = usize::try_from(code).ok()?.checked_sub(1).filter(|i| *i < 16)?;
    let n = if (i / 4) % 2 == 0 { 32 } else { 24 };
    Some((n, if n == 32 { [265, 133, 67, 34][i % 4] } else { [200, 101, 51, 26][i % 4] }))
}

/// A component LMS key as read: its tree's m, h and hash, I, q, and the root node where the tree cache holds it.
struct LmsKey {
    m: usize,
    h: u32,
    shake: bool,
    i: Vec<u8>,
    q: i32,
    root: Option<Vec<u8>>,
}

/// `LMSPrivateKeyParameters.readCoreKey`.
fn lms_core_key(s: &mut Stream) -> Result<LmsKey, Failure> {
    if s.read_int()? != 0 {
        return Err(io_failure("expected version 0 lms private key".into()));
    }
    let code = s.read_int()?;
    let (m, h, shake) = lms_parameters(code).ok_or_else(|| io_failure(format!("unknown LMS type code: {code}")))?;
    let ots = s.read_int()?;
    lm_ots_parameters(ots).ok_or_else(|| io_failure(format!("unknown LM-OTS type code: {ots}")))?;
    let i = s.read_fully(16)?.to_vec();
    let (q, max_q) = (s.read_int()?, s.read_int()?);
    let two_to_h = 1i32 << h;
    if q < 0 || max_q < 0 || max_q > two_to_h || q > max_q {
        return Err(io_failure(format!("LMS private key q/maxQ out of range: q={q} maxQ={max_q} 2^h={two_to_h}")));
    }
    let l = s.read_int()?;
    if l < m as i32 {
        return Err(io_failure(format!("secret length less than {m}: {l}")));
    }
    if l as usize > s.available() {
        return Err(io_failure(format!("secret length exceeded {}", s.available())));
    }
    s.read_fully(l as usize)?;
    Ok(LmsKey { m, h, shake, i, q, root: None })
}

/// `LMSPrivateKeyParameters.readTreeCache` and `validateTreeCache`: the top of the Merkle tree, each inner node the
/// hash of its children (`LMSEngine.computeNode`).
fn lms_tree_cache(s: &mut Stream, key: &mut LmsKey) -> Result<(), Failure> {
    let count = s.read_int()?;
    if !(0..64).contains(&count) {
        return Err(io_failure(format!("tree cache node count out of range: {count}")));
    }
    if count != 0 && (count < 3 || ((count + 1) & count) != 0) {
        return Err(io_failure(format!("tree cache node count is not a complete top of tree: {count}")));
    }
    let count = count as usize;
    if count * key.m > s.available() {
        return Err(io_failure(format!("tree cache length exceeded {}", s.available())));
    }
    let mut nodes = vec![Vec::new()];
    for _ in 0..count {
        nodes.push(s.read_fully(key.m)?.to_vec());
    }
    let mut r = 1usize;
    while r < (1usize << key.h) && 2 * r < count {
        let input = [&key.i[..], &(r as u32).to_be_bytes(), &[0x83, 0x83], &nodes[2 * r], &nodes[2 * r + 1]].concat();
        let node = if key.shake {
            crate::tls::key_string::keccak(136, 0x1f, &input, key.m)
        } else {
            ring::digest::digest(&ring::digest::SHA256, &input).as_ref()[..key.m].to_vec()
        };
        if node != nodes[r] {
            return Err(io_failure(format!("LMS private key tree cache inconsistent at node {r}")));
        }
        r += 1;
    }
    key.root = nodes.get(1).cloned();
    Ok(())
}

/// `LMSSignature.getInstance(DataInputStream)`: q, the LM-OTS signature (type, C, y) and the authentication path.
fn lms_signature(s: &mut Stream) -> Result<(), Failure> {
    s.read_int()?;
    let ots = s.read_int()?;
    let (n, p) = lm_ots_parameters(ots).ok_or_else(|| io_failure(format!("unknown LM-OTS type code: {ots}")))?;
    s.read_fully(n)?;
    s.read_fully(p * n)?;
    let code = s.read_int()?;
    let (m, h, _) = lms_parameters(code).ok_or_else(|| io_failure(format!("unknown LMS type code: {code}")))?;
    s.read_fully(h as usize * m)?;
    Ok(())
}

/// `HSSPrivateKeyParameters.getInstance(DataInputStream)`: the root key.
fn hss_private(data: &[u8]) -> Result<LmsKey, Failure> {
    let mut s = Stream { data, pos: 0 };
    let version = s.read_int()?;
    if version != 0 && version != 1 {
        return Err(io_failure("unknown version for hss private key".into()));
    }
    let d = s.read_int()?;
    if !(1..=8).contains(&d) {
        return Err(io_failure(format!("d value of HSS private key out of range: {d}")));
    }
    let (index, max_index) = (s.read_long()?, s.read_long()?);
    if index < 0 || max_index < 0 || index > max_index {
        return Err(io_failure(format!("HSS private key index out of range: index={index} maxIndex={max_index}")));
    }
    s.read_fully(1)?;
    let mut keys = Vec::new();
    for _ in 0..d {
        let mut key = lms_core_key(&mut s)?;
        if version != 0 {
            lms_tree_cache(&mut s, &mut key)?;
        }
        keys.push(key);
    }
    for _ in 1..d {
        lms_signature(&mut s)?;
    }
    // `checkIndexAgainstKeys`
    let d = keys.len();
    let mut implied = i64::from(keys[d - 1].q);
    let mut shift = 0u32;
    for i in (0..d - 1).rev() {
        shift += keys[i + 1].h;
        if shift >= 63 {
            return Ok(keys.swap_remove(0));
        }
        implied = implied.wrapping_add((i64::from(keys[i].q) - 1).wrapping_shl(shift));
    }
    if implied != index {
        return Err(io_failure(format!("HSS private key index {index} does not match the component key indices, which imply {implied}")));
    }
    Ok(keys.swap_remove(0))
}

/// `HSSPrivateKeyParameters.getInstance(byte[])`: an HSS key, else (for encodings predating HSS) a single LMS key
/// with an optional tree cache; the HSS failure where neither reads.
fn hss_or_lms(data: &[u8]) -> Result<LmsKey, Failure> {
    hss_private(data).or_else(|hss| {
        let mut s = Stream { data, pos: 0 };
        let mut key = lms_core_key(&mut s).map_err(|_| hss.clone())?;
        if s.available() > 0 {
            lms_tree_cache(&mut s, &mut key).map_err(|_| hss.clone())?;
        }
        Ok(key)
    })
}

/// `LmsKeyUtil.createPrivateKey`: `Utils.parseOctetString` of the key, its first four octets (L) dropped, read as an
/// HSS key, and checked against the PrivateKeyInfo's public key where there is one (`HSSPublicKeyParameters`: L,
/// then the root's LMS public key, nothing after it; its T1 the cached root where there is one). `false` for a
/// public key encoding that is not modelled.
fn lms_key(info: &bc::PrivateKeyInfo) -> Result<bool, Failure> {
    let encoding = parse_octet_string(&info.key, 64)?;
    if encoding.len() < 4 {
        return Err(iae(format!("4 > {}", encoding.len())));
    }
    let public = match &info.public_key {
        None => None,
        Some(Asn1::Tagged { body: bc::TagBody::Primitive(bits), .. }) if !bits.is_empty() => {
            if bits[0] != 0 {
                return Err(throwable("java.lang.IllegalStateException", Some("attempt to get non-octet aligned data from BIT STRING".into()), None));
            }
            Some(bits[1..].to_vec())
        }
        Some(_) => return Ok(false),
    };
    let root = hss_or_lms(&encoding[4..])?;
    let Some(public) = public else { return Ok(true) };
    let mut s = Stream { data: &public, pos: 0 };
    let l = s.read_int()?;
    if !(1..=8).contains(&l) {
        return Err(io_failure(format!("L value of HSS public key out of range: {l}")));
    }
    let code = s.read_int()?;
    let (m, _, _) = lms_parameters(code).ok_or_else(|| io_failure(format!("unknown LMS type code: {code}")))?;
    let ots = s.read_int()?;
    lm_ots_parameters(ots).ok_or_else(|| io_failure(format!("unknown LM-OTS type code: {ots}")))?;
    s.read_fully(16)?;
    let t1 = s.read_fully(m)?;
    if s.available() != 0 {
        return Err(io_failure("unexpected data found after HSS public key".into()));
    }
    if root.root.as_deref().is_some_and(|r| r != t1) {
        return Err(io_failure("HSS private key tree cache does not match the public key".into()));
    }
    Ok(true)
}

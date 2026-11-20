//! The CA key classes BouncyCastle 1.86 prints as `Object.toString` (the shaded class name, `@` and the hexadecimal
//! `hashCode()`), and the certificate keys of the same algorithms: Falcon, NTRU, FrodoKEM, Classic
//! McEliece, the composite ML-DSA and ML-KEM keys, XMSS, XMSS^MT, SM9 master keys and LMS/HSS. Each `hashCode` is ported from its class, all of them over
//! `org.bouncycastle.util.Arrays.hashCode`, not the JDK's; FrodoKEM and Classic McEliece certificate keys print their
//! key instead, and an LMS/HSS certificate key is read by the JDK's own `HSS$HSSPublicKey`.
//!
//! `BCLMSPrivateKey.hashCode` reaches `Objects.hashCode` of BouncyCastle's `LMSigParameters` and `LMOtsParameters`,
//! which do not override `hashCode`: an identity hash, which differs between JVMs (the oracle printed `ccc2be8b` where a
//! local BouncyCastle 1.86 printed `9440a723` for the same file). Ours prints a hash of the key's octets in its place;
//! the scenarios mask it.

use super::cert_string::{items, tlv};
use num_bigint::BigUint;

const SHADED: &str = "shaded_package.org.bouncycastle.";

/// `org.bouncycastle.util.Arrays.hashCode(byte[])`: from length + 1, ×257 and xor each signed byte, last first.
pub(super) fn bc_hash(data: &[u8]) -> i32 {
    let start = (data.len() as i32).wrapping_add(1);
    data.iter().rev().fold(start, |hc, &b| hc.wrapping_mul(257) ^ i32::from(b as i8))
}

/// `String.hashCode`.
fn string_hash(text: &str) -> i32 {
    text.encode_utf16().fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(i32::from(c)))
}

fn object(class: &str, hash: i32) -> String {
    format!("{SHADED}{class}@{:x}", hash as u32)
}

/// A DER element: the tag, the definite length, the content.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
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
    out
}

/// The content octets of a dotted OID.
fn oid_content(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().unwrap_or(0)).collect();
    let mut out = Vec::new();
    for arc in std::iter::once(arcs[0] * 40 + arcs[1]).chain(arcs[2..].iter().copied()) {
        let mut chunk = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            chunk.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        chunk.reverse();
        out.extend(chunk);
    }
    out
}

/// A SubjectPublicKeyInfo with an AlgorithmIdentifier of the bare OID and the key as the BIT STRING's octets, as
/// BouncyCastle's `SubjectPublicKeyInfoFactory` writes these keys: what their `getEncoded()` returns.
fn spki(algorithm: &str, key: &[u8]) -> Vec<u8> {
    let identifier = der(0x30, &der(0x06, &oid_content(algorithm)));
    let bits = der(0x03, &[&[0u8][..], key].concat());
    der(0x30, &[identifier, bits].concat())
}

/// The octets of an OCTET STRING (a PKCS #8 key's `parsePrivateKey()` for these algorithms).
fn octets(key: &[u8]) -> Option<&[u8]> {
    let inner = tlv(key)?.0;
    (inner.tag == 0x04).then_some(inner.content)
}

const FALCON: [(&str, u8); 2] = [("1.3.9999.3.11", 9), ("1.3.9999.3.14", 10)];

const NTRU: [&str; 6] = [
    "1.3.6.1.4.1.22554.5.5.1", "1.3.6.1.4.1.22554.5.5.2", "1.3.6.1.4.1.22554.5.5.3", "1.3.6.1.4.1.22554.5.5.4",
    "1.3.6.1.4.1.22554.5.5.5", "1.3.6.1.4.1.22554.5.5.6",
];

/// ISO/IEC 18033-2 FrodoKEM: the parameter set's name and n (976 or 1344).
fn frodo(algorithm: &str) -> Option<(&'static str, usize)> {
    let index = algorithm.strip_prefix("1.0.18033.2.2.7.")?.parse::<usize>().ok()?.checked_sub(1)?;
    [
        ("frodokem976shake", 976), ("frodokem1344shake", 1344), ("efrodokem976shake", 976), ("efrodokem1344shake", 1344),
        ("frodokem976aes", 976), ("frodokem1344aes", 1344), ("efrodokem976aes", 976), ("efrodokem1344aes", 1344),
    ]
    .get(index)
    .copied()
}

/// FrodoKEM's public key length (seedA ‖ b) and its secret s length, by n.
fn frodo_sizes(n: usize) -> (usize, usize) {
    let s = if n == 976 { 24 } else { 32 };
    (16 + n * 8 * 2, s)
}

/// ISO/IEC 18033-2 Classic McEliece: the parameter set's name.
fn cmce(algorithm: &str) -> Option<&'static str> {
    let index = algorithm.strip_prefix("1.0.18033.2.2.6.")?.parse::<usize>().ok()?.checked_sub(1)?;
    [
        "mceliece460896", "mceliece460896f", "mceliece460896pc", "mceliece460896pcf", "mceliece6688128",
        "mceliece6688128f", "mceliece6688128pc", "mceliece6688128pcf", "mceliece6960119", "mceliece6960119f",
        "mceliece6960119pc", "mceliece6960119pcf", "mceliece8192128", "mceliece8192128f", "mceliece8192128pc",
        "mceliece8192128pcf",
    ]
    .get(index)
    .copied()
}

/// RFC 9802's XMSS and XMSS^MT (`id-alg-xmss-hashsig`, `id-alg-xmssmt-hashsig`).
const XMSS: &str = "1.3.6.1.5.5.7.6.34";
const XMSSMT: &str = "1.3.6.1.5.5.7.6.35";
/// BouncyCastle's own XMSS and XMSS^MT OIDs (`PQCObjectIdentifiers.xmss`, `xmss_mt`), whose keys carry `XMSSKeyParams`
/// (a tree height with no RFC 8391 set has no parameter-set identifier, so BouncyCastle writes this form) and the ASN.1
/// `XMSSPrivateKey`/`XMSSPublicKey`.
pub(super) const XMSS_LEGACY: &str = "1.3.6.1.4.1.22554.2.2";
pub(super) const XMSSMT_LEGACY: &str = "1.3.6.1.4.1.22554.2.3";

const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const SHA512: &str = "2.16.840.1.101.3.4.2.3";
const SHAKE128: &str = "2.16.840.1.101.3.4.2.11";
const SHAKE256: &str = "2.16.840.1.101.3.4.2.12";
const SHAKE256_LEN: &str = "2.16.840.1.101.3.4.2.18";

/// One XMSS or XMSS^MT parameter set: the tree digest's OID content, n, the total height and the layers (1 for XMSS).
struct XmssSet {
    digest: Vec<u8>,
    n: usize,
    height: u32,
    layers: u32,
}

/// An XMSS (`mt` false) or XMSS^MT parameter set by its identifier (RFC 8391 and SP 800-208, `XMSSParameters` and
/// `XMSSMTParameters`'s tables): the RFC 8391 digests, SHA-256/192 and the SHAKE256/256 and SHAKE256/192 sets.
fn xmss_set(mt: bool, id: u32) -> Option<XmssSet> {
    const FAMILIES: [(&str, usize); 7] =
        [(SHA256, 32), (SHA512, 64), (SHAKE128, 32), (SHAKE256, 64), (SHA256, 24), (SHAKE256_LEN, 32), (SHAKE256_LEN, 24)];
    let (per_family, shapes): (u32, &[(u32, u32)]) = if mt {
        (8, &[(20, 2), (20, 4), (40, 2), (40, 4), (40, 8), (60, 3), (60, 6), (60, 12)])
    } else {
        (3, &[(10, 1), (16, 1), (20, 1)])
    };
    let id = id.checked_sub(1)?;
    let (digest, n) = FAMILIES.get((id / per_family) as usize)?;
    let (height, layers) = shapes[(id % per_family) as usize];
    Some(XmssSet { digest: oid_content(digest), n: *n, height, layers })
}

/// The identifier of the set with this digest, n, height and layers: nonzero for a set the legacy key form names too, as
/// `XMSSParameters` looks it up (`lookupXMSSOid`), and then the encoded public key starts with it.
fn xmss_set_id(mt: bool, digest: &[u8], n: usize, height: u32, layers: u32) -> u32 {
    let count = if mt { 56 } else { 21 };
    (1..=count)
        .find(|&id| xmss_set(mt, id).is_some_and(|s| s.digest == digest && s.n == n && s.height == height && s.layers == layers))
        .unwrap_or(0)
}

/// The tree digest a legacy `XMSSKeyParams` names and its n: `XMSSParameters(height, Digest)` takes n from the digest's
/// size (the SHAKE256/len OID of SP 800-208 is not written this way, which BouncyCastle's `lookupTreeAlgID` refuses).
fn legacy_digest(oid: &str) -> Option<(Vec<u8>, usize)> {
    let n = match oid {
        SHA256 | SHAKE128 => 32,
        SHA512 | SHAKE256 => 64,
        _ => return None,
    };
    Some((oid_content(oid), n))
}

/// A legacy `XMSSKeyParams` (version, height, tree digest) or `XMSSMTKeyParams` (version, height, layers, tree digest):
/// the digest, n, height and layers.
fn legacy_parameters(mt: bool, params: &super::cert_string::Tlv) -> Option<XmssSet> {
    (params.tag == 0x30).then_some(())?;
    let parts = items(params.content)?;
    let int = |i: usize| {
        let p = parts.get(i).filter(|p| p.tag == 0x02)?;
        (p.content.len() <= 4 && p.content.first().is_some_and(|b| b & 0x80 == 0)).then(|| p.content.iter().fold(0u32, |a, &b| a << 8 | u32::from(b)))
    };
    let last = if mt { 3 } else { 2 };
    let identifier = parts.get(last).filter(|p| p.tag == 0x30)?;
    let (digest, n) = legacy_digest(&super::cert_string::oid(items(identifier.content)?.first()?.content)?)?;
    Some(XmssSet { digest, n, height: int(1)?, layers: if mt { int(2)? } else { 1 } })
}

/// The ASN.1 `XMSSPrivateKey`/`XMSSMTPrivateKey` of a legacy key: the public seed and the root.
fn legacy_private_fields(key: &[u8], n: usize) -> Option<(&[u8], &[u8])> {
    let outer = tlv(key)?.0;
    (outer.tag == 0x30).then_some(())?;
    let fields = items(items(outer.content)?.get(1).filter(|k| k.tag == 0x30)?.content)?;
    let octet = |i: usize| fields.get(i).filter(|f| f.tag == 0x04).map(|f| f.content);
    let (prf, seed, root) = (octet(2)?, octet(3)?, octet(4)?);
    // `XMSSPrivateKeyParameters.Builder.build`: every n-byte field must be n bytes
    (octet(1)?.len() == n && prf.len() == n && seed.len() == n && root.len() == n).then_some((seed, root))
}

/// `BCXMSSPrivateKey`/`BCXMSSMTPrivateKey.hashCode` (`XMSSPrivateKeyCodec.hashCode`): the tree digest's OID, the root
/// and the public seed. The RFC 9802 key octets are the set's 4-byte identifier and the raw key: index, SK_SEED,
/// SK_PRF, PUB_SEED, root, the BDS state; the legacy form is the ASN.1 structure.
fn xmss_private(mt: bool, legacy: Option<&super::cert_string::Tlv>, key: &[u8]) -> Option<String> {
    let class = if mt { "pqc.jcajce.provider.xmss.BCXMSSMTPrivateKey" } else { "pqc.jcajce.provider.xmss.BCXMSSPrivateKey" };
    let (digest, seed, root);
    if let Some(parameters) = legacy {
        let set = legacy_parameters(mt, parameters)?;
        (seed, root) = legacy_private_fields(key, set.n)?;
        digest = set.digest;
    } else {
        let octets = octets(key)?;
        let id = u32::from_be_bytes(octets.get(..4)?.try_into().ok()?);
        let set = xmss_set(mt, id)?;
        let index = if mt { set.height.div_ceil(8) as usize } else { 4 };
        let at = 4 + index + 2 * set.n;
        (seed, root) = (octets.get(at..at + set.n)?, octets.get(at + set.n..at + 2 * set.n)?);
        digest = set.digest;
    }
    let hash = bc_hash(&digest).wrapping_mul(31).wrapping_add(bc_hash(root)).wrapping_mul(31).wrapping_add(bc_hash(seed));
    Some(object(class, hash))
}

/// `BCXMSSPublicKey`/`BCXMSSMTPublicKey.hashCode`: the tree digest's OID hash + 37 × the hash of the key's encoding
/// (`XMSSPublicKeyCodec.encode`: the set's identifier unless the parameters name none, the root, the public seed).
fn xmss_public(mt: bool, legacy: Option<&super::cert_string::Tlv>, bits: &[u8]) -> Option<String> {
    let class = if mt { "pqc.jcajce.provider.xmss.BCXMSSMTPublicKey" } else { "pqc.jcajce.provider.xmss.BCXMSSPublicKey" };
    let (digest, encoded);
    if let Some(parameters) = legacy {
        let set = legacy_parameters(mt, parameters)?;
        let (seed, root) = legacy_public_fields(bits, set.n).ok()?;
        let id = xmss_set_id(mt, &set.digest, set.n, set.height, set.layers);
        encoded = [if id == 0 { Vec::new() } else { id.to_be_bytes().to_vec() }, root.to_vec(), seed.to_vec()].concat();
        digest = set.digest;
    } else {
        let id = u32::from_be_bytes(bits.get(..4)?.try_into().ok()?);
        let set = xmss_set(mt, id)?;
        (bits.len() == 4 + 2 * set.n).then_some(())?;
        encoded = bits.to_vec();
        digest = set.digest;
    }
    let hash = bc_hash(&digest).wrapping_add(bc_hash(&encoded).wrapping_mul(37));
    Some(object(class, hash))
}

/// The public seed and root of a legacy `XMSSPublicKey` (version, public seed, root); the error is the message
/// `XMSSPublicKeyParameters.Builder` refuses a wrong-sized field with.
fn legacy_public_fields(bits: &[u8], n: usize) -> Result<(&[u8], &[u8]), String> {
    let fields = tlv(bits).filter(|(k, _)| k.tag == 0x30).and_then(|(k, _)| items(k.content)).ok_or_else(|| "malformed".to_string())?;
    let octet = |i: usize| fields.get(i).filter(|f| f.tag == 0x04).map(|f| f.content).ok_or_else(|| "malformed".to_string());
    let (seed, root) = (octet(1)?, octet(2)?);
    if root.len() != n {
        return Err("size of root needs to be equal to size of digest".into());
    }
    if seed.len() != n {
        return Err("size of publicSeed needs to be equal to size of digest".into());
    }
    Ok((seed, root))
}

/// GM/T 0044 SM9 master keys: signature (`sm9sign`) and encryption (`sm9encrypt`).
const SM9_SIGN: &str = "1.2.156.10197.1.302.1";
const SM9_ENCRYPT: &str = "1.2.156.10197.1.302.3";

/// The SM9 BN curve: the base field prime and the group order.
const SM9_Q: &str = "B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D";
const SM9_N: &str = "B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25";

/// An element a + b·u of F_q² = F_q[u]/(u² + 2).
#[derive(Clone, PartialEq)]
struct Fp2 {
    a: BigUint,
    b: BigUint,
}

struct Sm9Field {
    q: BigUint,
}

impl Sm9Field {
    fn sub(&self, x: &BigUint, y: &BigUint) -> BigUint {
        (x + &self.q - y % &self.q) % &self.q
    }

    fn add2(&self, x: &Fp2, y: &Fp2) -> Fp2 {
        Fp2 { a: (&x.a + &y.a) % &self.q, b: (&x.b + &y.b) % &self.q }
    }

    fn sub2(&self, x: &Fp2, y: &Fp2) -> Fp2 {
        Fp2 { a: self.sub(&x.a, &y.a), b: self.sub(&x.b, &y.b) }
    }

    /// (a + bu)(c + du) = ac - 2bd + (ad + bc)u.
    fn mul2(&self, x: &Fp2, y: &Fp2) -> Fp2 {
        let q = &self.q;
        let ac = &x.a * &y.a % q;
        let bd = &x.b * &y.b % q;
        Fp2 { a: self.sub(&ac, &(bd * 2u8 % q)), b: (&x.a * &y.b + &x.b * &y.a) % q }
    }

    fn scale2(&self, x: &Fp2, k: u8) -> Fp2 {
        Fp2 { a: &x.a * k % &self.q, b: &x.b * k % &self.q }
    }

    /// (a + bu)⁻¹ = (a - bu) / (a² + 2b²).
    fn inverse2(&self, x: &Fp2) -> Fp2 {
        let q = &self.q;
        let norm = (&x.a * &x.a + &x.b * &x.b * 2u8) % q;
        let inverse = norm.modpow(&(q - 2u8), q);
        Fp2 { a: &x.a * &inverse % q, b: self.sub(&BigUint::default(), &(&x.b * &inverse % q)) }
    }

    /// P + Q on y² = x³ + 5u (a = 0) over F_q²; `None` is the point at infinity.
    fn add(&self, left: &Option<(Fp2, Fp2)>, right: &Option<(Fp2, Fp2)>) -> Option<(Fp2, Fp2)> {
        let (Some((x1, y1)), Some((x2, y2))) = (left, right) else { return left.clone().or_else(|| right.clone()) };
        let zero = Fp2 { a: BigUint::default(), b: BigUint::default() };
        let slope = if x1 == x2 {
            if self.add2(y1, y2) == zero {
                return None;
            }
            self.mul2(&self.scale2(&self.mul2(x1, x1), 3), &self.inverse2(&self.scale2(y1, 2)))
        } else {
            self.mul2(&self.sub2(y2, y1), &self.inverse2(&self.sub2(x2, x1)))
        };
        let x3 = self.sub2(&self.sub2(&self.mul2(&slope, &slope), x1), x2);
        let y3 = self.sub2(&self.mul2(&slope, &self.sub2(x1, &x3)), y1);
        Some((x3, y3))
    }

    fn multiply(&self, k: &BigUint, g: &Option<(Fp2, Fp2)>) -> Option<(Fp2, Fp2)> {
        let mut out = None;
        for i in (0..k.bits()).rev() {
            out = self.add(&out, &out);
            if k.bit(i) {
                out = self.add(&out, g);
            }
        }
        out
    }
}

fn fixed(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    [vec![0u8; 32usize.saturating_sub(bytes.len())], bytes].concat()
}

/// The encoded SM9 master public key of a master private key: ks·P2 on the twist (`SM9G2Point.getEncoded`: 04, then
/// each coordinate's u-coefficient before its constant) or ke·P1 on the curve (uncompressed).
fn sm9_public(sign: bool, secret: &[u8]) -> Option<Vec<u8>> {
    let hex = |h: &str| BigUint::parse_bytes(h.as_bytes(), 16);
    let (q, n) = (hex(SM9_Q)?, hex(SM9_N)?);
    let k = BigUint::from_bytes_be(secret);
    // `SM9SigMasterPrivateKeyParameters`/`SM9EncMasterPrivateKeyParameters`: k in [1, N-1]
    (secret.len() == 32 && k > BigUint::default() && k < n).then_some(())?;
    if sign {
        let field = Sm9Field { q };
        let p2 = Some((
            Fp2 { a: hex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")?, b: hex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")? },
            Fp2 { a: hex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")?, b: hex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")? },
        ));
        let (x, y) = field.multiply(&k, &p2)?;
        Some([vec![0x04], fixed(&x.b), fixed(&x.a), fixed(&y.b), fixed(&y.a)].concat())
    } else {
        let p1 = Some((hex("93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD")?, hex("21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616")?));
        let (x, y) = super::key_string::weierstrass_multiply(&q, &BigUint::default(), &k, &p1)?;
        Some([vec![0x04], fixed(&x), fixed(&y)].concat())
    }
}

/// A composite key's post-quantum half: an ML-DSA or ML-KEM parameter set's OID.
#[derive(Clone, Copy)]
enum Pq {
    MlDsa(&'static str),
    MlKem(&'static str),
}

/// A composite key's traditional half; `Ec` names its curve's OID.
#[derive(Clone, Copy)]
enum Trad {
    Rsa,
    Ed25519,
    Ed448,
    X25519,
    X448,
    Ec(&'static str),
}

/// The composite signature and KEM algorithms (`id-alg` 37 to 66, `CompositeIndex`): their two halves.
fn composite(algorithm: &str) -> Option<(Pq, Trad)> {
    const DSA44: Pq = Pq::MlDsa("2.16.840.1.101.3.4.3.17");
    const DSA65: Pq = Pq::MlDsa("2.16.840.1.101.3.4.3.18");
    const DSA87: Pq = Pq::MlDsa("2.16.840.1.101.3.4.3.19");
    const KEM768: Pq = Pq::MlKem("2.16.840.1.101.3.4.4.2");
    const KEM1024: Pq = Pq::MlKem("2.16.840.1.101.3.4.4.3");
    const P256: Trad = Trad::Ec("1.2.840.10045.3.1.7");
    const P384: Trad = Trad::Ec("1.3.132.0.34");
    const P521: Trad = Trad::Ec("1.3.132.0.35");
    const BP256: Trad = Trad::Ec("1.3.36.3.3.2.8.1.1.7");
    const BP384: Trad = Trad::Ec("1.3.36.3.3.2.8.1.1.11");
    let index = algorithm.strip_prefix("1.3.6.1.5.5.7.6.")?.parse::<usize>().ok()?.checked_sub(37)?;
    [
        (DSA44, Trad::Rsa), (DSA44, Trad::Rsa), (DSA44, Trad::Ed25519), (DSA44, P256),
        (DSA65, Trad::Rsa), (DSA65, Trad::Rsa), (DSA65, Trad::Rsa), (DSA65, Trad::Rsa), (DSA65, P256), (DSA65, P384),
        (DSA65, BP256), (DSA65, Trad::Ed25519), (DSA87, P384), (DSA87, BP384), (DSA87, Trad::Ed448), (DSA87, Trad::Rsa),
        (DSA87, Trad::Rsa), (DSA87, P521), (KEM768, Trad::Rsa), (KEM768, Trad::Rsa), (KEM768, Trad::Rsa),
        (KEM768, Trad::X25519), (KEM768, P256), (KEM768, P384), (KEM768, BP256), (KEM1024, Trad::Rsa), (KEM1024, P384),
        (KEM1024, BP384), (KEM1024, Trad::X448), (KEM1024, P521),
    ]
    .get(index)
    .copied()
}

/// The post-quantum half's seed and public key lengths.
fn pq_sizes(pq: Pq) -> (usize, usize) {
    match pq {
        Pq::MlDsa(id) => (32, [1312, 1952, 2592][usize::from(id.as_bytes()[id.len() - 1] - b'7')]),
        Pq::MlKem(id) => (64, if id.ends_with(".2") { 1184 } else { 1568 }),
    }
}

/// The `hashCode` of the post-quantum half's key: `BCMLDSAPublicKey` hashes the raw key, `BCMLKEMPublicKey` its
/// SubjectPublicKeyInfo (the private key classes hash their public key).
fn pq_hash(pq: Pq, public: &[u8]) -> i32 {
    match pq {
        Pq::MlDsa(_) => bc_hash(public),
        Pq::MlKem(id) => bc_hash(&spki(id, public)),
    }
}

/// `ECPoint.hashCode`, `ECCurve.hashCode` and `ECParameterSpec.hashCode` of a key on a named prime curve, the curve
/// as `EC5Util.convertCurve` builds it: P-256, P-384 and P-521 become BouncyCastle's custom curves, whose field
/// elements hash their 32-bit limbs; other curves are `ECCurve.Fp`. `BCECPrivateKey` (d·G) and `BCECPublicKey` (Q)
/// both hash the point xor the spec.
fn ec_hash(curve: &str, q: &(BigUint, BigUint)) -> Option<i32> {
    let &(_, _, _, values) = super::named_curves::by_oid(curve)?;
    let [p, a, b, gx, gy] = values?.map(|h| BigUint::parse_bytes(h.as_bytes(), 16));
    let (p, a, b, gx, gy) = (p?, a?, b?, gx?, gy?);
    let java = |v: &BigUint| super::key_string::java_hash(&num_bigint::BigInt::from(v.clone()));
    let limbs = match curve {
        "1.2.840.10045.3.1.7" => Some(8),
        "1.3.132.0.34" => Some(12),
        "1.3.132.0.35" => Some(17),
        _ => None,
    };
    let element = |v: &BigUint| match limbs {
        Some(len) => {
            let mut words = v.to_u32_digits();
            words.resize(len, 0);
            let hash = words.iter().rev().fold((len as i32).wrapping_add(1), |hc, &w| hc.wrapping_mul(257) ^ w as i32);
            java(&p) ^ hash
        }
        None => java(&p) ^ java(v),
    };
    let curve_hash = java(&p) ^ java(&a).rotate_left(8) ^ java(&b).rotate_left(16);
    let point = |x: &BigUint, y: &BigUint| !curve_hash ^ element(x).wrapping_mul(17) ^ element(y).wrapping_mul(257);
    Some(point(&q.0, &q.1) ^ (curve_hash ^ point(&gx, &gy)))
}

/// d·G on a named prime curve.
fn ec_multiply(curve: &str, d: &BigUint) -> Option<(BigUint, BigUint)> {
    let &(_, _, _, values) = super::named_curves::by_oid(curve)?;
    let [p, a, _, gx, gy] = values?.map(|h| BigUint::parse_bytes(h.as_bytes(), 16));
    super::key_string::weierstrass_multiply(&p?, &a?, d, &Some((gx?, gy?)))
}

/// The `hashCode` of an Edwards or Montgomery key (`BCEdDSAPrivateKey`, `BCXDHPrivateKey`: the algorithm name's hash
/// and the raw public key; the public key classes: their SubjectPublicKeyInfo).
fn edwards_hash(trad: Trad, public: &[u8], private: bool) -> i32 {
    let (name, id) = match trad {
        Trad::Ed25519 => ("Ed25519", "1.3.101.112"),
        Trad::Ed448 => ("Ed448", "1.3.101.113"),
        Trad::X25519 => ("X25519", "1.3.101.110"),
        _ => ("X448", "1.3.101.111"),
    };
    if private {
        string_hash(name).wrapping_mul(31).wrapping_add(bc_hash(public))
    } else {
        bc_hash(&spki(id, public))
    }
}

/// `CompositePrivateKey.hashCode`: the `List` hash of its two keys. The privateKey octets are the post-quantum seed, then
/// the traditional private key (PKCS #1, SEC 1, or the raw Edwards/Montgomery key).
fn composite_private(algorithm: &str, key: &[u8]) -> Option<String> {
    let (pq, trad) = composite(algorithm)?;
    // the PKCS #8 privateKey octets themselves, with no inner OCTET STRING
    let octets = key;
    let (seed, _) = pq_sizes(pq);
    let (seed, rest) = (octets.get(..seed)?, &octets[seed..]);
    let public = match pq {
        Pq::MlDsa(id) => super::key_math::mldsa_public(id, 0x80, seed, None)?,
        Pq::MlKem(id) => super::key_math::mlkem_public(id, 0x80, seed, None)?,
    };
    let java = |v: &[u8]| super::key_string::java_hash(&num_bigint::BigInt::from_signed_bytes_be(v));
    let second = match trad {
        Trad::Rsa => {
            let numbers = items(tlv(rest)?.0.content)?;
            let (n, e) = (numbers.get(1).filter(|n| n.tag == 0x02)?, numbers.get(2).filter(|e| e.tag == 0x02)?);
            // `BCRSAPrivateCrtKey`
            java(n.content).wrapping_add(java(e.content).wrapping_mul(37))
        }
        Trad::Ec(curve) => {
            let parts = items(tlv(rest)?.0.content)?;
            let d = BigUint::from_bytes_be(parts.get(1).filter(|d| d.tag == 0x04)?.content);
            ec_hash(curve, &ec_multiply(curve, &d)?)?
        }
        Trad::Ed25519 => edwards_hash(trad, &super::key_string::ed25519_public(rest)?, true),
        Trad::Ed448 => edwards_hash(trad, &super::key_string::ed448_public(rest)?, true),
        Trad::X25519 => edwards_hash(trad, &super::key_math::x25519_public(rest)?, true),
        Trad::X448 => edwards_hash(trad, &super::key_math::x448_public(rest)?, true),
    };
    let hash = 31i32.wrapping_add(pq_hash(pq, &public)).wrapping_mul(31).wrapping_add(second);
    Some(object("jcajce.CompositePrivateKey", hash))
}

/// `CompositePublicKey.hashCode`: its AlgorithmIdentifier's hash (an `ASN1Sequence` of the bare OID) xor the `List`
/// hash of its two keys. The key bits are the post-quantum key, then the traditional one (PKCS #1 `RSAPublicKey`, the
/// uncompressed point, or the raw Edwards/Montgomery key).
fn composite_public(algorithm: &str, bits: &[u8]) -> Option<String> {
    let (pq, trad) = composite(algorithm)?;
    let (_, length) = pq_sizes(pq);
    let (public, rest) = (bits.get(..length)?, &bits[length..]);
    let java = |v: &[u8]| super::key_string::java_hash(&num_bigint::BigInt::from_signed_bytes_be(v));
    let second = match trad {
        Trad::Rsa => {
            let numbers = items(tlv(rest)?.0.content)?;
            // `BCRSAPublicKey`
            java(numbers.first()?.content) ^ java(numbers.get(1)?.content)
        }
        Trad::Ec(curve) => {
            let len = (rest.len().checked_sub(1)?) / 2;
            (rest.first() == Some(&0x04) && rest.len() == 1 + 2 * len).then_some(())?;
            ec_hash(curve, &(BigUint::from_bytes_be(&rest[1..=len]), BigUint::from_bytes_be(&rest[1 + len..])))?
        }
        _ => edwards_hash(trad, rest, false),
    };
    let keys = 31i32.wrapping_add(pq_hash(pq, public)).wrapping_mul(31).wrapping_add(second);
    let identifier = 514i32 ^ bc_hash(&oid_content(algorithm));
    Some(object("jcajce.CompositePublicKey", identifier ^ keys))
}

/// The JDK's HSS/LMS key algorithm (`id-alg-hss-lms-hashsig`).
pub(super) const HSS_LMS: &str = "1.2.840.113549.1.9.16.3.17";

/// The private key text of a key under one of these algorithms; `None` for another algorithm or a key BouncyCastle
/// does not read. `key` is the PKCS #8 privateKey's content.
pub(super) fn private(algorithm: &str, params: Option<&super::cert_string::Tlv>, key: &[u8]) -> Option<String> {
    if let Some(&(_, logn)) = FALCON.iter().find(|(o, _)| *o == algorithm) {
        // FalconPrivateKey: version, f, g, F, the public key { h }
        let parts = items(tlv(key)?.0.content)?;
        let public = items(parts.get(4).filter(|p| p.tag == 0x30)?.content)?;
        let h = public.first().filter(|h| h.tag == 0x04)?.content;
        // `getPublicKey().hashCode()`: the hash of the public key's SubjectPublicKeyInfo
        let hash = bc_hash(&spki(algorithm, &[&[logn][..], h].concat()));
        return Some(object("pqc.jcajce.provider.falcon.BCFalconPrivateKey", hash));
    }
    if NTRU.contains(&algorithm) {
        octets(key)?;
        // "NTRU private keys do not embed the public key": the algorithm name's hash
        return Some(object("pqc.jcajce.provider.ntru.BCNTRUPrivateKey", string_hash("NTRU")));
    }
    if let Some((_, n)) = frodo(algorithm) {
        let octets = octets(key)?;
        let (public, s) = frodo_sizes(n);
        (octets.len() == s + public + 2 * n * 8 + s).then_some(())?;
        let hash = bc_hash(&spki(algorithm, &octets[s..s + public]));
        return Some(object("jcajce.provider.asymmetric.frodokem.BCFrodoKEMPrivateKey", hash));
    }
    if let Some(name) = cmce(algorithm) {
        octets(key)?;
        return Some(object("jcajce.provider.asymmetric.cmce.BCCMCEPrivateKey", string_hash(name)));
    }
    if composite(algorithm).is_some() {
        return composite_private(algorithm, key);
    }
    match algorithm {
        XMSS => xmss_private(false, None, key),
        XMSSMT => xmss_private(true, None, key),
        XMSS_LEGACY => xmss_private(false, Some(params?), key),
        XMSSMT_LEGACY => xmss_private(true, Some(params?), key),
        SM9_SIGN | SM9_ENCRYPT => {
            let sign = algorithm == SM9_SIGN;
            let public = sm9_public(sign, octets(key)?)?;
            let class = if sign { "BCSM9SigMasterPrivateKey" } else { "BCSM9EncMasterPrivateKey" };
            Some(object(&format!("jcajce.provider.asymmetric.sm9.{class}"), bc_hash(&public)))
        }
        // an identity hash in BouncyCastle (see the module's note): a stand-in from the key's octets
        HSS_LMS => Some(object("pqc.jcajce.provider.lms.BCLMSPrivateKey", bc_hash(octets(key)?))),
        _ => None,
    }
}

/// The BouncyCastle private key class of these algorithms, for the failure of the leaves it cannot sign.
pub(super) fn class(algorithm: &str) -> Option<&'static str> {
    Some(match algorithm {
        a if FALCON.iter().any(|(o, _)| *o == a) => "shaded_package.org.bouncycastle.pqc.jcajce.provider.falcon.BCFalconPrivateKey",
        a if NTRU.contains(&a) => "shaded_package.org.bouncycastle.pqc.jcajce.provider.ntru.BCNTRUPrivateKey",
        a if frodo(a).is_some() => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.frodokem.BCFrodoKEMPrivateKey",
        a if cmce(a).is_some() => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.cmce.BCCMCEPrivateKey",
        a if composite(a).is_some() => "shaded_package.org.bouncycastle.jcajce.CompositePrivateKey",
        XMSS | XMSS_LEGACY => "shaded_package.org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPrivateKey",
        XMSSMT | XMSSMT_LEGACY => "shaded_package.org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSMTPrivateKey",
        SM9_SIGN => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.sm9.BCSM9SigMasterPrivateKey",
        SM9_ENCRYPT => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.sm9.BCSM9EncMasterPrivateKey",
        HSS_LMS => "shaded_package.org.bouncycastle.pqc.jcajce.provider.lms.BCLMSPrivateKey",
        _ => return None,
    })
}

/// A certificate key of these algorithms as the class reading it prints it; `None` for another algorithm or a key the
/// class refuses. `bits` are the BIT STRING's octets.
pub(super) fn public(algorithm: &str, params: Option<&super::cert_string::Tlv>, bits: &[u8]) -> Option<String> {
    if let Some(&(_, logn)) = FALCON.iter().find(|(o, _)| *o == algorithm) {
        (bits.first() == Some(&logn)).then_some(())?;
        return Some(object("pqc.jcajce.provider.falcon.BCFalconPublicKey", bc_hash(&spki(algorithm, bits))));
    }
    if NTRU.contains(&algorithm) {
        return Some(object("pqc.jcajce.provider.ntru.BCNTRUPublicKey", bc_hash(bits)));
    }
    if let Some((name, n)) = frodo(algorithm) {
        (bits.len() == frodo_sizes(n).0).then_some(())?;
        return Some(super::key_string::pq_public(name, bits));
    }
    if let Some(name) = cmce(algorithm) {
        return Some(super::key_string::pq_public(name, bits));
    }
    if composite(algorithm).is_some() {
        return composite_public(algorithm, bits);
    }
    match algorithm {
        XMSS => xmss_public(false, None, bits),
        XMSSMT => xmss_public(true, None, bits),
        XMSS_LEGACY => xmss_public(false, Some(params?), bits),
        XMSSMT_LEGACY => xmss_public(true, Some(params?), bits),
        SM9_SIGN | SM9_ENCRYPT => {
            let sign = algorithm == SM9_SIGN;
            (bits.len() == if sign { 129 } else { 65 } && bits[0] == 0x04).then_some(())?;
            let class = if sign { "BCSM9SigMasterPublicKey" } else { "BCSM9EncMasterPublicKey" };
            Some(object(&format!("jcajce.provider.asymmetric.sm9.{class}"), bc_hash(&spki(algorithm, bits))))
        }
        HSS_LMS => hss_public(bits).ok(),
        _ => None,
    }
}

/// The key octets the JDK's `HSS$HSSPublicKey.parseKeyBits` reads: an inner OCTET STRING (the pre-8347596 form) is
/// unwrapped.
fn hss_key(bits: &[u8]) -> &[u8] {
    if bits.len() >= 2 && bits[0] == 0x04 && usize::from(bits[1]) == bits.len() - 2 {
        &bits[2..]
    } else {
        bits
    }
}

/// `HSS$HSSPublicKey.toString`, or the `InvalidKeyException` message its parsing fails with (`LMSPublicKey`: the JDK
/// knows LMS_SHA256_M32_H5 to H25 and LMOTS_SHA256_N32_W1 to W8 only, and the key's exact length).
fn hss_public(bits: &[u8]) -> Result<String, String> {
    let key = hss_key(bits);
    if key.len() < 12 {
        return Err("LMS public key is too short".into());
    }
    let word = |at: usize| u32::from_be_bytes([key[at], key[at + 1], key[at + 2], key[at + 3]]);
    let (layers, lms, ots) = (word(0), word(4), word(8));
    let lms_name = match lms {
        5..=9 => ["LMS_SHA256_M32_H5", "LMS_SHA256_M32_H10", "LMS_SHA256_M32_H15", "LMS_SHA256_M32_H20", "LMS_SHA256_M32_H25"][lms as usize - 5],
        _ => return Err("Unsupported or bad LMS type".into()),
    };
    let ots_name = match ots {
        1..=4 => ["LMOTS_SHA256_N32_W1", "LMOTS_SHA256_N32_W2", "LMOTS_SHA256_N32_W4", "LMOTS_SHA256_N32_W8"][ots as usize - 1],
        _ => return Err("Unsupported or bad OTS Algorithm Identifier.".into()),
    };
    if key.len() - 4 != 24 + 32 {
        return Err("Wrong LMS public key length".into());
    }
    Ok(format!(
        "HSS/LMS public key, number of layers: {layers}, LMS type: {lms_name},\nOTS type: {ots_name}, byte array representation:\n{}",
        hex_dump_encode(key)
    ))
}

/// `HexDumpEncoder.encode` (not `encodeBuffer`): a last line shorter than 16 bytes ends after its hex, without the
/// padding, the ASCII column or the line break.
fn hex_dump_encode(data: &[u8]) -> String {
    let mut out = super::cert_string::hex_dump(data);
    let partial = data.len() % 16;
    if partial != 0 {
        let start = out[..out.len() - 1].rfind('\n').map_or(0, |i| i + 1);
        // "0000: " and three characters a byte, two more after the eighth
        let end = start + 6 + 3 * partial + if partial >= 8 { 2 } else { 0 };
        out.truncate(end);
    }
    out
}

/// Why the JDK refuses a certificate whose key is an HSS/LMS key its `HSS$HSSPublicKey` cannot read (the message of
/// the `IOException` the `CertificateFactory` wraps).
pub(super) fn refusal(algorithm: &str, params: Option<&super::cert_string::Tlv>, bits: &[u8]) -> Option<String> {
    match algorithm {
        HSS_LMS => hss_public(bits).err().map(|message| format!("subject key, java.security.InvalidKeyException: {message}")),
        // a legacy XMSS key whose root or public seed is not n bytes
        XMSS_LEGACY | XMSSMT_LEGACY => {
            let set = legacy_parameters(algorithm == XMSSMT_LEGACY, params?)?;
            let message = legacy_public_fields(bits, set.n).err().filter(|m| m.starts_with("size of"))?;
            Some(format!("subject key, java.io.IOException: malformed XMSS{} public key: {message}", if algorithm == XMSSMT_LEGACY { "^MT" } else { "" }))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bouncy_castle_array_hash() {
        assert_eq!(bc_hash(&[]), 1);
        assert_eq!(string_hash("NTRU") as u32, 0x24ba89);
        assert_eq!(oid_content("2.16.840.1.101.3.4.2.1"), [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
        assert_eq!(bc_hash(&oid_content("2.16.840.1.101.3.4.2.1")) as u32, 0xf57b73c4);
    }

    #[test]
    fn hex_dump_encode_lines() {
        assert_eq!(hex_dump_encode(b"ab"), "0000: 61 62 ");
        assert_eq!(hex_dump_encode(&[0u8; 9]), "0000: 00 00 00 00 00 00 00 00   00 ");
        assert_eq!(hex_dump_encode(&[0u8; 8]), "0000: 00 00 00 00 00 00 00 00   ");
        assert!(hex_dump_encode(&[0u8; 16]).ends_with("................\n"));
    }
}

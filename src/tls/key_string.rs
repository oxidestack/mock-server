//! A CA private key's `toString` as MockServer's TRACE `loaded CA private key from path{}containing PEM{}` entry
//! prints it: `PEMToFile.privateKeyFromPEM` reads the key through BouncyCastle 1.86's `JcaPEMKeyConverter`, so the
//! object is a `BCRSAPrivateCrtKey`, `BCECPrivateKey`, `BCDSAPrivateKey` or `BCEdDSAPrivateKey`, each printing a
//! SHAKE256 `Fingerprint` and its public values. Checked against `tests/files/x509/tostring/keys`
//! (`KeyToStringGen.java`).
//!
//! Ported: RSA and RSASSA-PSS keys (PKCS#8, under the OAEP and X.500 OIDs too, and PKCS#1), EC keys on the `CurveDB`
//! curves, on the curves BouncyCastle alone names and on explicit parameters (PKCS#8 and SEC1; implicit parameters are
//! refused), DSA keys (PKCS#8, under the dsa-with-sha1 OIDs too, and OpenSSL's traditional form) and
//! Ed25519/Ed448 keys. Other keys give `None`.

use super::cert_string::{items, oid, tlv, Tlv};
use super::key_math::{mldsa_public, mlkem_public, pre_hash, slh_dsa, x25519_public, x448_public};
use num_bigint::BigUint;

/// `org.bouncycastle.util.Fingerprint.toString`: the first `bytes` of SHAKE256 of `input`, colon-separated hex.
pub(super) fn fingerprint(input: &[u8], bytes: usize) -> String {
    shake256(input, bytes).iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b,
    0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008a, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000a, 0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];
const ROTATIONS: [u32; 25] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

/// Keccak-f[1600], the state indexed `x + 5y`.
fn keccak_f(a: &mut [u64; 25]) {
    for rc in ROUND_CONSTANTS {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(ROTATIONS[x + 5 * y]);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        a[0] ^= rc;
    }
}

/// SHAKE256 (rate 136 bytes, domain suffix 0x1f) with `out_len` bytes of output.
pub(super) fn shake256(input: &[u8], out_len: usize) -> Vec<u8> {
    keccak(136, 0x1f, input, out_len)
}

/// A Keccak[1600] sponge of `rate` bytes with the domain suffix `suffix` (SHA-3 `0x06`, SHAKE `0x1f`): `out_len`
/// bytes of output.
pub(crate) fn keccak(rate: usize, suffix: u8, input: &[u8], out_len: usize) -> Vec<u8> {
    let mut state = [0u64; 25];
    let absorb = |state: &mut [u64; 25], block: &[u8]| {
        for (i, lane) in block.chunks(8).enumerate() {
            let mut bytes = [0u8; 8];
            bytes[..lane.len()].copy_from_slice(lane);
            state[i] ^= u64::from_le_bytes(bytes);
        }
        keccak_f(state);
    };
    let mut chunks = input.chunks_exact(rate);
    for block in &mut chunks {
        absorb(&mut state, block);
    }
    let mut last = vec![0u8; rate];
    let rest = chunks.remainder();
    last[..rest.len()].copy_from_slice(rest);
    last[rest.len()] ^= suffix;
    last[rate - 1] ^= 0x80;
    absorb(&mut state, &last);
    let mut out = Vec::with_capacity(out_len);
    loop {
        for lane in &state[..rate / 8] {
            for b in lane.to_le_bytes() {
                if out.len() == out_len {
                    return out;
                }
                out.push(b);
            }
        }
        keccak_f(&mut state);
    }
}

/// `BCRSAPrivateCrtKey.toString`.
fn rsa(modulus: &BigUint, exponent: &BigUint) -> String {
    format!(
        "RSA Private CRT Key [{}],[{}]\n             modulus: {}\n     public exponent: {}\n",
        // `RSAUtil.generateKeyFingerprint`: `BigInteger.toByteArray`, sign byte included
        fingerprint(&num_bigint::BigInt::from(modulus.clone()).to_signed_bytes_be(), 20),
        fingerprint(&num_bigint::BigInt::from(exponent.clone()).to_signed_bytes_be(), 4),
        modulus.to_str_radix(16),
        exponent.to_str_radix(16),
    )
}

/// An RSAPrivateKey (PKCS#1) structure's modulus and public exponent.
fn rsa_numbers(der: &[u8]) -> Option<(BigUint, BigUint)> {
    let (sequence, _) = tlv(der)?;
    let parts = items(sequence.content)?;
    Some((BigUint::from_bytes_be(parts.get(1)?.content), BigUint::from_bytes_be(parts.get(2)?.content)))
}

/// A point on a short Weierstrass curve over GF(p) in affine coordinates; `None` is the point at infinity.
type Point = Option<(BigUint, BigUint)>;

/// `P + Q` on y² = x³ + ax + b over GF(p).
fn weierstrass_add(p: &BigUint, a: &BigUint, left: &Point, right: &Point) -> Point {
    let (Some((x1, y1)), Some((x2, y2))) = (left, right) else { return left.clone().or_else(|| right.clone()) };
    let sub = |u: &BigUint, v: &BigUint| (u + p - v % p) % p;
    let inverse = |u: &BigUint| u.modpow(&(p - 2u8), p);
    let slope = if x1 == x2 {
        if (y1 + y2) % p == BigUint::from(0u8) {
            return None;
        }
        (BigUint::from(3u8) * x1 * x1 + a) % p * inverse(&(BigUint::from(2u8) * y1 % p)) % p
    } else {
        sub(y2, y1) * inverse(&sub(x2, x1)) % p
    };
    let x3 = sub(&sub(&(&slope * &slope % p), x1), x2);
    let y3 = sub(&(&slope * sub(x1, &x3) % p), y1);
    Some((x3, y3))
}

/// `k·G`, double-and-add.
pub(super) fn weierstrass_multiply(p: &BigUint, a: &BigUint, k: &BigUint, g: &Point) -> Point {
    let mut out: Point = None;
    for i in (0..k.bits()).rev() {
        out = weierstrass_add(p, a, &out, &out);
        if k.bit(i) {
            out = weierstrass_add(p, a, &out, g);
        }
    }
    out
}

/// `BCECPrivateKey.toString` (`ECUtil.privateKeyToString`) of a scalar on a named curve: one of `CurveDB` or one
/// BouncyCastle alone names.
fn ec(curve: &str, scalar: &[u8]) -> Option<String> {
    if let Some(&(_, size, poly, a, b, gx, gy)) = super::named_curves::BINARY.iter().find(|c| c.0 == curve) {
        return ec_binary(size, [poly, a, b, gx, gy], scalar);
    }
    if let Some(&(_, size, binary, values)) = super::named_curves::bc_only_by_oid(curve) {
        return if binary { ec_binary(size, values, scalar) } else { ec_prime(size, values, scalar) };
    }
    let &(_, size, _, prime) = super::named_curves::by_oid(curve)?;
    ec_prime(size, prime?, scalar)
}

/// The key on X9.62 parameters as `BCECPrivateKey` reads them: a named curve's OID or explicit `ECParameters`.
/// Implicit parameters (`NULL`, or none at all) take the provider's `ecImplicitlyCa`, which MockServer never sets, so
/// BouncyCastle refuses the key whatever curve its `ECPrivateKey` names, and the oracle logs no key entry.
fn ec_on(parameters: Option<&Tlv>, scalar: &[u8]) -> Option<String> {
    let parameters = parameters?;
    match parameters.tag {
        0x06 => ec(&oid(parameters.content)?, scalar),
        0x30 => ec_explicit(parameters, scalar),
        _ => None,
    }
}

/// An EC private key's text on explicit X9.62 `ECParameters` (version, fieldID, curve, base, order, cofactor): a
/// prime field, the base point uncompressed or compressed (`ECCurve.decodePoint`), or a characteristic-two field
/// ([`x962_binary`]).
fn ec_explicit(parameters: &Tlv, scalar: &[u8]) -> Option<String> {
    let fields = items(parameters.content)?;
    let field_id = items(fields.get(1).filter(|f| f.tag == 0x30)?.content)?;
    let d = BigUint::from_bytes_be(scalar);
    match oid(field_id.first().filter(|f| f.tag == 0x06)?.content)?.as_str() {
        "1.2.840.10045.1.2" => binary_text("EC Private", &x962_binary(&fields)?, GostKey::Scalar(d)),
        "1.2.840.10045.1.1" => {
            let p = BigUint::from_bytes_be(field_id.get(1).filter(|p| p.tag == 0x02)?.content);
            let curve = items(fields.get(2).filter(|c| c.tag == 0x30)?.content)?;
            let (a, b) = (curve.first().filter(|a| a.tag == 0x04)?, curve.get(1).filter(|b| b.tag == 0x04)?);
            let (a, b) = (BigUint::from_bytes_be(a.content) % &p, BigUint::from_bytes_be(b.content) % &p);
            let base = fields.get(3).filter(|g| g.tag == 0x04)?.content;
            let len = (p.bits() as usize).div_ceil(8);
            let rhs = |x: &BigUint| (x.modpow(&BigUint::from(3u8), &p) + &a * x + &b) % &p;
            let (gx, gy) = match (*base.first()?, base.len()) {
                (0x04, n) if n == 1 + 2 * len => (BigUint::from_bytes_be(&base[1..=len]), BigUint::from_bytes_be(&base[1 + len..])),
                (prefix @ (0x02 | 0x03), n) if n == 1 + len => {
                    let x = BigUint::from_bytes_be(&base[1..]);
                    (x < p).then_some(())?;
                    let y = super::x509::sqrt_mod(&rhs(&x), &p)?;
                    let y = if y.bit(0) == (prefix == 0x03) { y } else { (&p - &y) % &p };
                    (x, y)
                }
                _ => return None,
            };
            (gy.modpow(&BigUint::from(2u8), &p) == rhs(&gx)).then_some(())?;
            prime_text(len, &p, &a, &b, (gx, gy), &d)
        }
        _ => None,
    }
}

/// [`ec`] on a prime-field curve given in hex (p, a, b, Gx, Gy) of `size` bits.
fn ec_prime(size: u32, values: [&str; 5], scalar: &[u8]) -> Option<String> {
    let [p, a, b, gx, gy] = values.map(|h| BigUint::parse_bytes(h.as_bytes(), 16));
    prime_text(size.div_ceil(8) as usize, &p?, &a?, &b?, (gx?, gy?), &BigUint::from_bytes_be(scalar))
}

/// `ECUtil.privateKeyToString` on y² = x³ + ax + b over GF(p): the fingerprint of the public point d·G, the curve's a
/// and b and the generator (`ECUtil.generateKeyFingerprint`, field elements at `len` bytes), then the point's
/// coordinates.
fn prime_text(len: usize, p: &BigUint, a: &BigUint, b: &BigUint, (gx, gy): (BigUint, BigUint), d: &BigUint) -> Option<String> {
    let field = |v: &BigUint| {
        let bytes = v.to_bytes_be();
        let mut out = vec![0u8; len.saturating_sub(bytes.len())];
        out.extend(bytes);
        out
    };
    let g = Some((gx, gy));
    let (x, y) = weierstrass_multiply(p, a, d, &g)?;
    let encoded = |x: &BigUint, y: &BigUint| [vec![0x04], field(x), field(y)].concat();
    let (gx, gy) = g?;
    let input = [encoded(&x, &y), field(a), field(b), encoded(&gx, &gy)].concat();
    Some(format!(
        "EC Private Key [{}]\n            X: {}\n            Y: {}\n",
        fingerprint(&input, 20),
        x.to_str_radix(16),
        y.to_str_radix(16),
    ))
}

/// What a GOST key string is built from: the private scalar (the point is d·G) or the public point itself.
enum GostKey {
    Scalar(BigUint),
    Point(BigUint, BigUint),
}

/// `ECUtil.privateKeyToString`/`publicKeyToString` of a key on a GOST parameter set (`p, a, b, n, h, Gx, Gy` in hex).
fn gost_text(label: &str, role: &str, set: &[&str; 7], key: GostKey) -> Option<String> {
    let [p, a, _, gx, gy] = [set[0], set[1], set[2], set[5], set[6]].map(|h| BigUint::parse_bytes(h.as_bytes(), 16));
    let (p, a, b, gx, gy) = (p?, a?, BigUint::parse_bytes(set[2].as_bytes(), 16)?, gx?, gy?);
    let len = p.to_bytes_be().len();
    let field = |v: &BigUint| {
        let bytes = v.to_bytes_be();
        let mut out = vec![0u8; len.saturating_sub(bytes.len())];
        out.extend(bytes);
        out
    };
    let g = Some((gx.clone(), gy.clone()));
    let (x, y) = match key {
        GostKey::Scalar(d) => weierstrass_multiply(&p, &a, &d, &g)?,
        GostKey::Point(x, y) => (x, y),
    };
    let encoded = |x: &BigUint, y: &BigUint| [vec![0x04], field(x), field(y)].concat();
    let input = [encoded(&x, &y), field(&a), field(&b), encoded(&gx, &gy)].concat();
    Some(format!("{label} {role} Key [{}]\n            X: {}\n            Y: {}\n", fingerprint(&input, 20), x.to_str_radix(16), y.to_str_radix(16)))
}

/// The name BouncyCastle gives a GOST R 34.10 key algorithm by its OID (2001 and 2012, the DH variants included).
fn gost_label(algorithm: &str) -> Option<&'static str> {
    match algorithm {
        "1.2.643.2.2.19" | "1.2.643.2.2.98" => Some("ECGOST3410"),
        "1.2.643.7.1.1.1.1" | "1.2.643.7.1.1.1.2" | "1.2.643.7.1.1.6.1" | "1.2.643.7.1.1.6.2" => Some("ECGOST3410-2012"),
        _ => None,
    }
}

/// The parameter set a GOST key's `GOST3410PublicKeyAlgParameters` names.
fn gost_set(parameters: &Tlv) -> Option<&'static [&'static str; 7]> {
    (parameters.tag == 0x30).then_some(())?;
    let first = items(parameters.content)?.into_iter().next()?;
    (first.tag == 0x06).then_some(())?;
    crate::keys::gost_set(&oid(first.content)?)
}

/// A GOST private key's `toString` (`BCECGOST3410PrivateKey`): the scalar is the 2012 key's raw 32 or 64
/// little-endian octets, an INTEGER, or a little-endian OCTET STRING.
fn gost_private(algorithm: &str, parameters: &Tlv, key: &[u8]) -> Option<String> {
    let label = gost_label(algorithm)?;
    let d = if label == "ECGOST3410-2012" && (key.len() == 32 || key.len() == 64) {
        BigUint::from_bytes_le(key)
    } else {
        let inner = tlv(key)?.0;
        match inner.tag {
            0x02 => BigUint::from_bytes_be(inner.content),
            0x04 => BigUint::from_bytes_le(inner.content),
            _ => return None,
        }
    };
    gost_text(label, "Private", gost_set(parameters)?, GostKey::Scalar(d))
}

/// A GOST public key's `toString` (`BCECGOST3410PublicKey`) from a certificate's SubjectPublicKeyInfo: the key is an
/// OCTET STRING of the little-endian x and y. The 2001 class also reads the parameter set's OID bare, without the
/// `GOST3410PublicKeyAlgParameters` sequence around it; the 2012 classes do not.
pub(super) fn gost_public(algorithm: &str, parameters: &Tlv, key_bits: &[u8]) -> Option<String> {
    let label = gost_label(algorithm)?;
    let set = gost_set(parameters).or_else(|| {
        (label == "ECGOST3410" && parameters.tag == 0x06).then(|| crate::keys::gost_set(&oid(parameters.content)?)).flatten()
    })?;
    let octets = tlv(key_bits)?.0;
    (octets.tag == 0x04 && octets.content.len() % 2 == 0).then_some(())?;
    let (x, y) = octets.content.split_at(octets.content.len() / 2);
    gost_text(label, "Public", set, GostKey::Point(BigUint::from_bytes_le(x), BigUint::from_bytes_le(y)))
}

/// Why BouncyCastle 1.86's GOST public key classes refuse a certificate's key, as the `InvalidKeySpecException`'s
/// message after `encoded key spec not recognized: `; `None` for a key they read and for a failure not probed.
/// The classes cannot read X9.62 parameters, a named curve or explicit ones: the 2001 class takes the
/// parameters as a parameter-set OID or a `GOST3410PublicKeyAlgParameters` (a named curve's OID is no set, and
/// `ECGOST3410NamedCurves` looks the null name up in a `Hashtable`), the 2012 classes only as the sequence. The 2012
/// classes read the key's x and y first, so an OCTET STRING shorter than two field elements fails at its end.
pub(super) fn gost_refusal(algorithm: &str, parameters: &Tlv, key_bits: &[u8]) -> Option<String> {
    let label = gost_label(algorithm)?;
    let shaded = |class: &str| format!("shaded_package.org.bouncycastle.asn1.{class}");
    let explicit = |parameters: &Tlv| {
        let first = items(parameters.content)?.into_iter().next()?;
        (first.tag == 0x02).then(|| format!("illegal object in getInstance: {}", shaded("ASN1Integer")))
    };
    if label == "ECGOST3410" {
        return match parameters.tag {
            0x06 => crate::keys::gost_set(&oid(parameters.content)?).is_none().then(|| "Cannot invoke \"Object.hashCode()\" because \"key\" is null".to_string()),
            0x30 => explicit(parameters),
            _ => None,
        };
    }
    let field = match algorithm {
        "1.2.643.7.1.1.1.1" => 32,
        "1.2.643.7.1.1.1.2" => 64,
        _ => return None,
    };
    let octets = tlv(key_bits)?.0;
    (octets.tag == 0x04).then_some(())?;
    let length = octets.content.len();
    if length < 2 * field {
        let index = if length < field { field - 1 } else { 2 * field - 1 };
        return Some(format!("Index {index} out of bounds for length {length}"));
    }
    match parameters.tag {
        0x06 => Some(format!("unknown object in getInstance: {}", shaded("ASN1ObjectIdentifier"))),
        0x30 => explicit(parameters),
        _ => None,
    }
}

/// An SLH-DSA public key's `toString` from a certificate's SubjectPublicKeyInfo (the raw pk.seed ‖ pk.root).
pub(super) fn slh_public(algorithm: &str, key_bits: &[u8]) -> Option<String> {
    let (name, length) = slh_dsa(algorithm)?;
    (key_bits.len() == length).then_some(())?;
    Some(pq_public(name, key_bits))
}

/// A HashML-DSA or HashSLH-DSA public key's `toString` (`BCMLDSAPublicKey`, `BCSLHDSAPublicKey`) from a certificate's
/// SubjectPublicKeyInfo: the pure set's raw public key, named with its pre-hash digest.
pub(super) fn pre_hash_public(algorithm: &str, key_bits: &[u8]) -> Option<String> {
    let (pure, digest) = pre_hash(algorithm)?;
    let (name, length) = match slh_dsa(&pure) {
        Some(set) => set,
        None => [("ML-DSA-44", 1312), ("ML-DSA-65", 1952), ("ML-DSA-87", 2592)][usize::from(pure.as_bytes()[pure.len() - 1] - b'7')],
    };
    (key_bits.len() == length).then_some(())?;
    Some(pq_public(&format!("{name}-WITH-{digest}"), key_bits))
}

/// `BCMLDSAPublicKey`/`BCSLHDSAPublicKey.toString`: the name, the fingerprint and the raw public key in hex.
pub(super) fn pq_public(name: &str, key_bits: &[u8]) -> String {
    let hex: String = key_bits.iter().map(|b| format!("{b:02x}")).collect();
    format!("{name} Public Key [{}]\n    public data: {hex}\n", fingerprint(key_bits, 20))
}

/// `java.math.BigInteger.hashCode`: 31·h + word over the magnitude's 32-bit words, most significant first, times the
/// sign.
pub(super) fn java_hash(value: &num_bigint::BigInt) -> i32 {
    let (sign, magnitude) = value.to_bytes_be();
    let mut padded = vec![0u8; (4 - magnitude.len() % 4) % 4];
    padded.extend(&magnitude);
    let hash = if magnitude == [0] { 0 } else { padded.chunks(4).fold(0u32, |h, w| h.wrapping_mul(31).wrapping_add(u32::from_be_bytes([w[0], w[1], w[2], w[3]]))) as i32 };
    if sign == num_bigint::Sign::Minus { hash.wrapping_neg() } else { hash }
}

/// BouncyCastle's ElGamal key classes (`id_elgamal`, `1.3.14.7.2.1.1`, parameters p and g) do not override
/// `toString`, so it is `Object.toString`: the class name, `@` and the hexadecimal `hashCode()`, which they do
/// override from the key's numbers, not from the object's identity: y, p, g for the public key (the
/// parameter spec's l is 0) and g^x mod p, p, g for the private one (`PrivateKeyHashUtil.elGamalHashCode`).
const ELGAMAL: &str = "1.3.14.7.2.1.1";

fn elgamal_parameters(parameters: &Tlv) -> Option<(num_bigint::BigInt, num_bigint::BigInt)> {
    let numbers = items(parameters.content)?;
    let int = |i: usize| numbers.get(i).filter(|n| n.tag == 0x02).map(|n| num_bigint::BigInt::from_signed_bytes_be(n.content));
    Some((int(0)?, int(1)?))
}

/// An ElGamal public key's `toString` from a certificate's SubjectPublicKeyInfo (the key bits an INTEGER y).
pub(super) fn elgamal_public(parameters: &Tlv, key_bits: &[u8]) -> Option<String> {
    let (p, g) = elgamal_parameters(parameters)?;
    let y = tlv(key_bits)?.0;
    (y.tag == 0x02).then_some(())?;
    let hash = java_hash(&num_bigint::BigInt::from_signed_bytes_be(y.content)) ^ java_hash(&p) ^ java_hash(&g);
    Some(format!("shaded_package.org.bouncycastle.jcajce.provider.asymmetric.elgamal.BCElGamalPublicKey@{:x}", hash as u32))
}

/// An ElGamal private key's `toString` (the key an INTEGER x in the PKCS #8 octets).
fn elgamal_private(parameters: &Tlv, key: &[u8]) -> Option<String> {
    let (p, g) = elgamal_parameters(parameters)?;
    let x = tlv(key)?.0;
    (x.tag == 0x02).then_some(())?;
    let x = num_bigint::BigInt::from_signed_bytes_be(x.content);
    let y = g.modpow(&x, &p);
    let hash = java_hash(&y) ^ java_hash(&p) ^ java_hash(&g);
    Some(format!("shaded_package.org.bouncycastle.jcajce.provider.asymmetric.elgamal.BCElGamalPrivateKey@{:x}", hash as u32))
}

/// GOST R 34.10-94 (`CryptoProObjectIdentifiers.gostR3410_94`): BouncyCastle's `BCGOST3410PrivateKey` and
/// `BCGOST3410PublicKey`, on the parameter sets `GOST3410NamedParameters` holds.
pub(super) const GOST94: &str = "1.2.643.2.2.20";

/// The p and a of the CryptoPro set the key's `GOST3410PublicKeyAlgParameters` name (CryptoPro-A, -B and -XchA: the
/// sets BouncyCastle 1.86 holds; it refuses C, D, XchB and XchC).
fn gost94_set(parameters: &Tlv) -> Option<(BigUint, BigUint)> {
    (parameters.tag == 0x30).then_some(())?;
    let set = items(parameters.content)?.into_iter().next().filter(|s| s.tag == 0x06)?;
    let (p, a) = match oid(set.content)?.as_str() {
        "1.2.643.2.2.32.2" => ("127021248288932417465907042777176443525787653508916535812817507265705031260985098497423188333483401180925999995120988934130659205614996724254121049274349357074920312769561451689224110579311248812610229678534638401693520013288995000362260684222750813532307004517341633685004541062586971416883686778842537820383",
            "100997906755055304772081815535925224869841082572053457874823515875577147990529272777244152852699298796483356699682842027972896052747173175480590485607134746852141928680912561502802222185647539190902656116367847270145019066794290930185446216399730872221732889830323194097355403213400972588322876850946740663962"),
        "1.2.643.2.2.32.3" => ("139454871199115825601409655107690713107041707059928031797758001454375765357722984094124368522288239833039114681648076688236921220737322672160740747771700911134550432053804647694904686120113087816240740184800477047157336662926249423571248823968542221753660143391485680840520336859458494803187341288580489525163",
            "42941826148615804143873447737955502392672345968607143066798112994089471231420027060385216699563848719957657284814898909770759462613437669456364882730370838934791080835932647976778601915343474400961034231316672578686920482194932878633360203384797092684342247621055760235016132614780652761028509445403338652341"),
        "1.2.643.2.2.33.1" => ("142011741597563481196368286022318089743276138395243738762872573441927459393512718973631166078467600360848946623567625795282774719212241929071046134208380636394084512691828894000571524625445295769349356752728956831541775441763139384457191755096847107846595662547942312293338483924514339614727760681880609734239",
            "133531813272720673433859519948319001217942375967847486899482359599369642528734712461590403327731821410328012529253871914788598993103310567744136196364803064721377826656898686468463277710150809401182608770201615324990468332931294920912776241137878030224355746606283971659376426832674269780880061631528163475887"),
        _ => return None,
    };
    Some((BigUint::parse_bytes(p.as_bytes(), 10)?, BigUint::parse_bytes(a.as_bytes(), 10)?))
}

/// `GOSTUtil.privateKeyToString`/`publicKeyToString`: y, fingerprinted with p and a (`generateKeyFingerprint`).
fn gost94_text(role: &str, y: &BigUint, p: &BigUint, a: &BigUint) -> String {
    let signed = |v: &BigUint| num_bigint::BigInt::from(v.clone()).to_signed_bytes_be();
    let input = [signed(y), signed(p), signed(a)].concat();
    let pad = if role == "Private" { "                  " } else { "                 " };
    format!("GOST3410 {role} Key [{}]\n{pad}Y: {}\n", fingerprint(&input, 20), y.to_str_radix(16))
}

/// A GOST R 34.10-94 public key's `toString` from a certificate's SubjectPublicKeyInfo (the key bits an OCTET STRING
/// of y, little-endian).
pub(super) fn gost94_public(parameters: &Tlv, key_bits: &[u8]) -> Option<String> {
    let (p, a) = gost94_set(parameters)?;
    let y = tlv(key_bits)?.0;
    (y.tag == 0x04).then_some(())?;
    Some(gost94_text("Public", &BigUint::from_bytes_le(y.content), &p, &a))
}

/// Why the JDK refuses a certificate whose GOST R 34.10-94 key names no set BouncyCastle holds: BC's
/// `AlgorithmParametersSpi.engineInit` fails while `AlgorithmId` decodes the parameters.
pub(super) fn gost94_refusal(parameters: Option<&Tlv>) -> Option<String> {
    let parameters = parameters.filter(|p| p.tag != 0x05)?;
    gost94_set(parameters).is_none().then(|| "Not a valid GOST3410 Parameter encoding.".to_string())
}

/// A GOST R 34.10-94 private key's `toString`: x is an OCTET STRING (little-endian, as BouncyCastle writes it) or an
/// INTEGER, and y = a^x mod p.
fn gost94_private(parameters: &Tlv, key: &[u8]) -> Option<String> {
    let (p, a) = gost94_set(parameters)?;
    let x = tlv(key)?.0;
    let x = match x.tag {
        0x04 => BigUint::from_bytes_le(x.content),
        0x02 => BigUint::from_bytes_be(x.content),
        _ => return None,
    };
    Some(gost94_text("Private", &a.modpow(&x, &p), &p, &a))
}

/// The DSTU 4145 key algorithm whose public key octets are little-endian (`UAObjectIdentifiers.dstu4145le`); the
/// big-endian one is `1.2.804.2.1.1.1.1.3.1.1.1.1`.
const DSTU4145_LE: &str = "1.2.804.2.1.1.1.1.3.1.1";

/// The curve of a DSTU 4145 key: the field GF(2^size) reduced by `poly`, the coefficients a and b, and the base point.
struct DstuDomain {
    size: u32,
    poly: BigUint,
    a: BigUint,
    b: BigUint,
    g: (BigUint, BigUint),
}

/// The curve a DSTU 4145 key's parameters select, as `BCDSTU4145PublicKey`/`BCDSTU4145PrivateKey` read them: a
/// `DSTU4145Params` SEQUENCE whose first element is a named curve's OID (a private key may carry the bare OID) or a
/// `DSTU4145ECBinary`, or X9.62 `ECParameters` on a binary field (what BouncyCastle writes for a key on an unnamed curve).
fn dstu_domain(algorithm: &str, parameters: &Tlv) -> Option<DstuDomain> {
    let first = match parameters.tag {
        0x06 => return dstu_named(parameters.content),
        0x30 => items(parameters.content)?,
        _ => return None,
    };
    match first.first()?.tag {
        0x06 => dstu_named(first[0].content),
        0x30 => dstu_binary(algorithm, &first[0]),
        0x02 => x962_binary(&first),
        _ => None,
    }
}

/// A curve of BouncyCastle's `DSTU4145NamedCurves`.
fn dstu_named(named: &[u8]) -> Option<DstuDomain> {
    let &(size, exponents, a, b, gx, gy) = super::named_curves::dstu_by_oid(&oid(named)?)?;
    let [a, b, gx, gy] = [a, b, gx, gy].map(|h| BigUint::parse_bytes(h.as_bytes(), 16));
    Some(DstuDomain { size, poly: dstu_polynomial(size, exponents), a: a?, b: b?, g: (gx?, gy?) })
}

/// The reduction polynomial of a binary field given as m and its middle exponents (a trinomial's k, or a pentanomial's
/// k1, k2, k3), checked as BouncyCastle's `ECCurve.F2m` constructor checks them.
fn binary_field(size: &BigUint, exponents: &[BigUint]) -> Option<(u32, BigUint)> {
    let size = u32::try_from(size).ok().filter(|&m| m > 0 && m <= 10_000)?;
    let ks = exponents.iter().map(|k| u32::try_from(k).ok()).collect::<Option<Vec<_>>>()?;
    let ok = match ks[..] {
        [k] => k > 0 && k < size,
        [k1, k2, k3] => k1 > 0 && k1 < k2 && k2 < k3 && k3 < size,
        _ => false,
    };
    ok.then_some(())?;
    let mut padded = [0u32; 3];
    padded[..ks.len()].copy_from_slice(&ks);
    Some((size, dstu_polynomial(size, padded)))
}

/// A `DSTU4145ECBinary`: SEQUENCE { version [0] INTEGER DEFAULT 0, field SEQUENCE { m, k | SEQUENCE { k1, k2, k3 } },
/// a INTEGER, b OCTET STRING, n INTEGER, bp OCTET STRING }; b and the compressed base point are little-endian under
/// the `dstu4145le` algorithm.
fn dstu_binary(algorithm: &str, binary: &Tlv) -> Option<DstuDomain> {
    let mut fields = items(binary.content)?;
    if fields.first()?.tag == 0xa0 {
        fields.remove(0);
    }
    let [field, a, b, _n, bp] = <[Tlv; 5]>::try_from(fields).ok()?;
    (field.tag == 0x30 && a.tag == 0x02 && b.tag == 0x04 && bp.tag == 0x04).then_some(())?;
    let field = items(field.content)?;
    let (m, basis) = (field.first().filter(|m| m.tag == 0x02)?, field.get(1)?);
    let exponents = match basis.tag {
        0x02 => vec![BigUint::from_bytes_be(basis.content)],
        0x30 => integers(basis.content)?,
        _ => return None,
    };
    let (size, poly) = binary_field(&BigUint::from_bytes_be(m.content), &exponents)?;
    let le = |bytes: &[u8]| {
        let mut bytes = bytes.to_vec();
        if algorithm == DSTU4145_LE {
            bytes.reverse();
        }
        bytes
    };
    let (a, b) = (BigUint::from_bytes_be(a.content), BigUint::from_bytes_be(&le(b.content)));
    let g = dstu_decode(size, &poly, &a, &b, &le(bp.content))?;
    Some(DstuDomain { size, poly, a, b, g })
}

/// X9.62 `ECParameters` on a characteristic-two field (trinomial or pentanomial basis), the base point uncompressed or
/// compressed (`ECCurve.AbstractF2m.decompressPoint`).
fn x962_binary(parameters: &[Tlv]) -> Option<DstuDomain> {
    let (field_id, curve, base) = (parameters.get(1)?, parameters.get(2)?, parameters.get(3)?);
    let field_id = items(field_id.content)?;
    (oid(field_id.first().filter(|t| t.tag == 0x06)?.content)? == "1.2.840.10045.1.2").then_some(())?;
    let characteristic = items(field_id.get(1).filter(|t| t.tag == 0x30)?.content)?;
    let m = characteristic.first().filter(|m| m.tag == 0x02)?;
    let basis = oid(characteristic.get(1).filter(|t| t.tag == 0x06)?.content)?;
    let exponents = match (basis.as_str(), characteristic.get(2)) {
        ("1.2.840.10045.1.2.3.2", Some(k)) if k.tag == 0x02 => vec![BigUint::from_bytes_be(k.content)],
        ("1.2.840.10045.1.2.3.3", Some(ks)) if ks.tag == 0x30 => integers(ks.content)?,
        _ => return None,
    };
    let (size, poly) = binary_field(&BigUint::from_bytes_be(m.content), &exponents)?;
    let curve = items(curve.content)?;
    let (a, b) = (curve.first().filter(|a| a.tag == 0x04)?, curve.get(1).filter(|b| b.tag == 0x04)?);
    let (a, b) = (BigUint::from_bytes_be(a.content), BigUint::from_bytes_be(b.content));
    (base.tag == 0x04).then_some(())?;
    let field = Gf2m { poly: &poly, degree: u64::from(size) };
    let len = size.div_ceil(8) as usize;
    let point = base.content;
    let g = match (point.first()?, point.len()) {
        (0x04, n) if n == 1 + 2 * len => (BigUint::from_bytes_be(&point[1..=len]), BigUint::from_bytes_be(&point[1 + len..])),
        (0x02 | 0x03, n) if n == 1 + len => {
            let x = BigUint::from_bytes_be(&point[1..]);
            let y = if x == BigUint::default() {
                (1..size).fold(b.clone(), |y, _| field.mul(&y, &y))
            } else {
                let beta = field.mul(&field.inverse(&field.mul(&x, &x)), &b) ^ &a ^ &x;
                let mut z = field.solve_quadratic(&beta)?;
                if z.bit(0) != (point[0] == 0x03) {
                    z ^= BigUint::from(1u8);
                }
                field.mul(&x, &z)
            };
            (x, y)
        }
        _ => return None,
    };
    on_binary_curve(&field, &a, &b, &g).then_some(())?;
    Some(DstuDomain { size, poly, a, b, g })
}

/// Whether (x, y) satisfies y² + xy = x³ + ax² + b (BouncyCastle's `validatePoint`).
fn on_binary_curve(field: &Gf2m, a: &BigUint, b: &BigUint, (x, y): &(BigUint, BigUint)) -> bool {
    let square = field.mul(x, x);
    field.mul(y, y) ^ field.mul(x, y) == field.mul(&square, x) ^ field.mul(a, &square) ^ b
}

/// The reduction polynomial x^m + x^k1 (+ x^k2 + x^k3) + 1 (a zero exponent is absent).
fn dstu_polynomial(size: u32, exponents: [u32; 3]) -> BigUint {
    let mut poly = BigUint::from(1u8) | (BigUint::from(1u8) << size);
    for exponent in exponents.into_iter().filter(|&e| e != 0) {
        poly |= BigUint::from(1u8) << exponent;
    }
    poly
}

/// `ECUtil.privateKeyToString`/`publicKeyToString` of a key on a binary-field `curve` (a DSTU 4145 key, or an EC key
/// on a binary curve), `prefix` its label and role: the scalar's point d·G, or the public point itself.
fn binary_text(prefix: &str, curve: &DstuDomain, key: GostKey) -> Option<String> {
    let DstuDomain { size, poly, a, b, g: (gx, gy) } = curve;
    let field = Gf2m { poly, degree: u64::from(*size) };
    let len = size.div_ceil(8) as usize;
    let fixed = |v: &BigUint| {
        let bytes = v.to_bytes_be();
        let mut out = vec![0u8; len.saturating_sub(bytes.len())];
        out.extend(bytes);
        out
    };
    let (x, y) = match key {
        GostKey::Scalar(d) => field.multiply(a, &d, &Some((gx.clone(), gy.clone())))?,
        GostKey::Point(x, y) => (x, y),
    };
    let encoded = |x: &BigUint, y: &BigUint| [vec![0x04], fixed(x), fixed(y)].concat();
    let input = [encoded(&x, &y), fixed(a), fixed(b), encoded(gx, gy)].concat();
    Some(format!("{prefix} Key [{}]\n            X: {}\n            Y: {}\n", fingerprint(&input, 20), x.to_str_radix(16), y.to_str_radix(16)))
}

/// A DSTU 4145 private key's `toString` (`BCDSTU4145PrivateKey`): the scalar is an INTEGER or the OCTET STRING of an
/// `ECPrivateKey`; the public half the key was generated with (`-d·G`) is not used.
fn dstu_private(algorithm: &str, parameters: &Tlv, key: &[u8]) -> Option<String> {
    let curve = dstu_domain(algorithm, parameters)?;
    let inner = tlv(key)?.0;
    let d = match inner.tag {
        0x02 => BigUint::from_bytes_be(inner.content),
        0x30 => {
            let octets = items(inner.content)?.into_iter().nth(1).filter(|o| o.tag == 0x04)?;
            BigUint::from_bytes_be(octets.content)
        }
        _ => return None,
    };
    binary_text("DSTU4145 Private", &curve, GostKey::Scalar(d))
}

/// `DSTU4145PointEncoder.decodePoint`: the x with its low bit replaced by the trace of a, y from the root of
/// z² + z = x + a + b/x² whose trace is the encoding's low bit; the point checked on the curve.
fn dstu_decode(size: u32, poly: &BigUint, a: &BigUint, b: &BigUint, bytes: &[u8]) -> Option<(BigUint, BigUint)> {
    let field = Gf2m { poly, degree: u64::from(size) };
    let one = BigUint::from(1u8);
    let k = bytes.last()? & 1 == 1;
    let mut x = BigUint::from_bytes_be(bytes);
    (x.bits() <= u64::from(size)).then_some(())?;
    // `trace(xp).equals(curve.getA())`: an a other than 0 or 1 never equals the trace, so x is always flipped
    if BigUint::from(u8::from(field.trace(&x))) != *a {
        x ^= &one;
    }
    let y = if x == BigUint::default() {
        (1..size).fold(b.clone(), |y, _| field.mul(&y, &y))
    } else {
        let alpha = field.mul(&field.inverse(&field.mul(&x, &x)), b) ^ a ^ &x;
        let mut z = field.solve_quadratic(&alpha)?;
        if field.trace(&z) != k {
            z ^= &one;
        }
        field.mul(&x, &z)
    };
    let point = (x, y);
    on_binary_curve(&field, a, b, &point).then_some(point)
}

/// A DSTU 4145 public key's `toString` (`BCDSTU4145PublicKey`) from a certificate's SubjectPublicKeyInfo: the key is an
/// OCTET STRING holding the compressed point (little-endian for the `dstu4145le` algorithm).
pub(super) fn dstu_public(algorithm: &str, parameters: &Tlv, key_bits: &[u8]) -> Option<String> {
    let curve = dstu_domain(algorithm, parameters)?;
    let octets = tlv(key_bits)?.0;
    (octets.tag == 0x04).then_some(())?;
    let mut bytes = octets.content.to_vec();
    if algorithm == DSTU4145_LE {
        bytes.reverse();
    }
    let (x, y) = dstu_decode(curve.size, &curve.poly, &curve.a, &curve.b, &bytes)?;
    binary_text("DSTU4145 Public", &curve, GostKey::Point(x, y))
}

/// A point on a curve over GF(2^m) in affine coordinates; `None` is the point at infinity.
type BinaryPoint = Option<(BigUint, BigUint)>;

/// The binary field GF(2^m) reduced by `poly`: carry-less multiplication, then reduction.
struct Gf2m<'a> {
    poly: &'a BigUint,
    degree: u64,
}

impl Gf2m<'_> {
    fn mul(&self, x: &BigUint, y: &BigUint) -> BigUint {
        let mut product = BigUint::default();
        for i in 0..y.bits() {
            if y.bit(i) {
                product ^= x << i;
            }
        }
        for i in (self.degree..product.bits()).rev() {
            if product.bit(i) {
                product ^= self.poly << (i - self.degree);
            }
        }
        product
    }

    /// The inverse of a non-zero `x`: the polynomial extended Euclidean algorithm.
    fn inverse(&self, x: &BigUint) -> BigUint {
        let (mut u, mut v) = (x.clone(), self.poly.clone());
        let (mut g1, mut g2) = (BigUint::from(1u8), BigUint::default());
        let one = BigUint::from(1u8);
        while u != one {
            if u.bits() < v.bits() {
                std::mem::swap(&mut u, &mut v);
                std::mem::swap(&mut g1, &mut g2);
            }
            let shift = u.bits() - v.bits();
            u ^= &v << shift;
            g1 ^= &g2 << shift;
        }
        g1
    }

    /// The sum of two points of y² + xy = x³ + ax² + b.
    fn add(&self, a: &BigUint, left: &BinaryPoint, right: &BinaryPoint) -> BinaryPoint {
        let (Some((x1, y1)), Some((x2, y2))) = (left, right) else { return left.clone().or_else(|| right.clone()) };
        let one = BigUint::from(1u8);
        let (lambda, x3);
        if x1 == x2 {
            if y1 != y2 || *x1 == BigUint::default() {
                return None;
            }
            lambda = x1 ^ self.mul(y1, &self.inverse(x1));
            x3 = self.mul(&lambda, &lambda) ^ &lambda ^ a;
        } else {
            lambda = self.mul(&(y1 ^ y2), &self.inverse(&(x1 ^ x2)));
            x3 = self.mul(&lambda, &lambda) ^ &lambda ^ x1 ^ x2 ^ a;
        }
        let y3 = if x1 == x2 { self.mul(x1, x1) ^ self.mul(&(&lambda ^ one), &x3) } else { self.mul(&lambda, &(x1 ^ &x3)) ^ &x3 ^ y1 };
        Some((x3, y3))
    }

    /// `k·G`, double-and-add.
    fn multiply(&self, a: &BigUint, k: &BigUint, g: &BinaryPoint) -> BinaryPoint {
        let mut point: BinaryPoint = None;
        for i in (0..k.bits()).rev() {
            point = self.add(a, &point, &point);
            if k.bit(i) {
                point = self.add(a, &point, g);
            }
        }
        point
    }

    /// The trace of `x`, as a bit: x + x² + x⁴ + ... + x^(2^(m-1)).
    fn trace(&self, x: &BigUint) -> bool {
        let mut t = x.clone();
        for _ in 1..self.degree {
            t = self.mul(&t, &t) ^ x;
        }
        t == BigUint::from(1u8)
    }

    /// A root z of z² + z = beta, `None` when beta has trace 1. On an odd degree the half-trace solves it (the caller
    /// fixes the root by trace or low bit). On an even degree the two roots z and z + 1 have the same trace, and
    /// `DSTU4145PointEncoder.solveQuadraticEquation` (X9.62 D.1.6 with a random t) ends on either at random, so a
    /// DSTU 4145 point decodes to P or -P run to run; this is the root D.1.6 gives for the smallest power
    /// of two t that yields one, one of the two outcomes.
    fn solve_quadratic(&self, beta: &BigUint) -> Option<BigUint> {
        if self.degree % 2 == 1 {
            let mut z = beta.clone();
            let mut w = beta.clone();
            for _ in 0..(self.degree - 1) / 2 {
                w = self.mul(&w, &w);
                w = self.mul(&w, &w);
                z ^= &w;
            }
            return (self.mul(&z, &z) ^ &z == *beta).then_some(z);
        }
        if *beta == BigUint::default() {
            return Some(BigUint::default());
        }
        (0..self.degree).find_map(|bit| {
            let t = BigUint::from(1u8) << bit;
            let (mut z, mut w) = (BigUint::default(), beta.clone());
            for _ in 1..self.degree {
                let w2 = self.mul(&w, &w);
                z = self.mul(&z, &z) ^ self.mul(&w2, &t);
                w = w2 ^ beta;
            }
            (w == BigUint::default() && self.mul(&z, &z) ^ &z == *beta).then_some(z)
        })
    }
}

/// `BCECPrivateKey.toString` on a binary-field curve of `size` bits given in hex (the reduction polynomial, a, b, Gx,
/// Gy).
fn ec_binary(size: u32, values: [&str; 5], scalar: &[u8]) -> Option<String> {
    let [poly, a, b, gx, gy] = values.map(|h| BigUint::parse_bytes(h.as_bytes(), 16));
    let curve = DstuDomain { size, poly: poly?, a: a?, b: b?, g: (gx?, gy?) };
    binary_text("EC Private", &curve, GostKey::Scalar(BigUint::from_bytes_be(scalar)))
}

/// `BCDSAPrivateKey.toString`: y = g^x mod p, fingerprinted with the parameters (`DSAUtil.generateKeyFingerprint`).
fn dsa(p: &BigUint, q: &BigUint, g: &BigUint, x: &BigUint) -> String {
    let y = g.modpow(x, p);
    // `BigInteger.toByteArray`, sign byte included
    let signed = |v: &BigUint| num_bigint::BigInt::from(v.clone()).to_signed_bytes_be();
    let input = [signed(&y), signed(p), signed(q), signed(g)].concat();
    format!("DSA Private Key [{}]\n            Y: {}\n", fingerprint(&input, 20), y.to_str_radix(16))
}

/// The unsigned INTEGERs of a sequence's content.
fn integers(content: &[u8]) -> Option<Vec<BigUint>> {
    items(content)?.iter().map(|i| (i.tag == 0x02).then(|| BigUint::from_bytes_be(i.content))).collect()
}

/// `BCEdDSAPrivateKey.toString` (`edec.Utils.keyToString`): the public key's fingerprint and hex.
fn eddsa(algorithm: &str, public: &[u8]) -> String {
    let hex: String = public.iter().map(|b| format!("{b:02x}")).collect();
    format!("{algorithm} Private Key [{}]\n    public data: {hex}\n", fingerprint(public, 20))
}

/// The Ed25519 public key of a 32-byte seed (RFC 8032 §5.1.5).
pub(super) fn ed25519_public(seed: &[u8]) -> Option<Vec<u8>> {
    use ring::signature::KeyPair;
    Some(ring::signature::Ed25519KeyPair::from_seed_unchecked(seed).ok()?.public_key().as_ref().to_vec())
}

/// The Ed448 public key of a 57-byte seed (RFC 8032 §5.2.5).
pub(super) fn ed448_public(seed: &[u8]) -> Option<Vec<u8>> {
    super::ed448::public(seed)
}

/// An ECPrivateKey (SEC1) structure's scalar and, when it carries them, its parameters (`[0]`).
fn ec_private_key(der: &[u8]) -> Option<(Vec<u8>, Option<Tlv<'_>>)> {
    let (sequence, _) = tlv(der)?;
    let parts = items(sequence.content)?;
    let scalar = parts.get(1)?.content.to_vec();
    let parameters = parts.iter().find(|p| p.tag == 0xa0).and_then(|p| tlv(p.content)).map(|(c, _)| c);
    Some((scalar, parameters))
}

/// RSAES-OAEP and X.500's `id-ea-rsa`: BouncyCastle reads an RSA key under either OID.
pub(super) const RSA_OAEP: &str = "1.2.840.113549.1.1.7";
pub(super) const RSA_X500: &str = "2.5.8.1.1";
/// dsa-with-sha1 and OIW's dsaWithSHA1, which BouncyCastle reads a DSA key under.
const DSA_WITH_SHA1: &str = "1.2.840.10040.4.3";
const OIW_DSA_WITH_SHA1: &str = "1.3.14.3.2.27";

/// The modulus and public exponent of an RSA private key in PEM (PKCS #1, or PKCS #8 under any OID BouncyCastle reads
/// as RSA); `None` for any other key.
pub(super) fn rsa_public(pem: &str) -> Option<(BigUint, BigUint)> {
    let block = x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes()).next()?.ok()?;
    match block.label.as_str() {
        "RSA PRIVATE KEY" => rsa_numbers(&block.contents),
        "PRIVATE KEY" => {
            let (sequence, _) = tlv(&block.contents)?;
            let parts = items(sequence.content)?;
            let id = oid(items(parts.get(1)?.content)?.first()?.content)?;
            matches!(id.as_str(), "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" | RSA_OAEP | RSA_X500).then_some(())?;
            rsa_numbers(parts.get(2)?.content)
        }
        _ => None,
    }
}

/// The `toString` of the private key in a PEM text, as BouncyCastle prints it; `None` for a key not ported.
pub fn private_key_to_string(pem: &str) -> Option<String> {
    let block = x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes()).next()?.ok()?;
    let der = &block.contents[..];
    match block.label.as_str() {
        "RSA PRIVATE KEY" => {
            let (n, e) = rsa_numbers(der)?;
            Some(rsa(&n, &e))
        }
        "EC PRIVATE KEY" => {
            let (scalar, parameters) = ec_private_key(der)?;
            ec_on(parameters.as_ref(), &scalar)
        }
        // OpenSSL's traditional form: version, p, q, g, y, x
        "DSA PRIVATE KEY" => {
            let numbers = integers(tlv(der)?.0.content)?;
            Some(dsa(numbers.get(1)?, numbers.get(2)?, numbers.get(3)?, numbers.get(5)?))
        }
        "PRIVATE KEY" => {
            let (sequence, _) = tlv(der)?;
            let parts = items(sequence.content)?;
            let algorithm = items(parts.get(1)?.content)?;
            let key = parts.get(2)?.content;
            match oid(algorithm.first()?.content)?.as_str() {
                // an RSASSA-PSS key reads as a `BCRSAPrivateCrtKey` too, as does one under the OAEP or X.500 RSA OID
                // (BouncyCastle's `Alg.Alias.KeyFactory` entries)
                "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" | RSA_OAEP | RSA_X500 => {
                    let (n, e) = rsa_numbers(key)?;
                    Some(rsa(&n, &e))
                }
                // the algorithm's parameters decide; a curve named inside the ECPrivateKey is not read
                "1.2.840.10045.2.1" => ec_on(algorithm.get(1), &ec_private_key(key)?.0),
                // a DSA key under dsa-with-sha1 or OIW's dsaWithSHA1 reads as a `BCDSAPrivateKey` too
                "1.2.840.10040.4.1" | DSA_WITH_SHA1 | OIW_DSA_WITH_SHA1 => {
                    let parameters = integers(algorithm.get(1)?.content)?;
                    let x = tlv(key)?.0;
                    (x.tag == 0x02).then_some(())?;
                    Some(dsa(parameters.first()?, parameters.get(1)?, parameters.get(2)?, &BigUint::from_bytes_be(x.content)))
                }
                "1.3.101.112" => Some(eddsa("Ed25519", &ed25519_public(tlv(key)?.0.content)?)),
                "1.3.101.113" => Some(eddsa("Ed448", &ed448_public(tlv(key)?.0.content)?)),
                "1.2.643.2.2.19" | "1.2.643.2.2.98" | "1.2.643.7.1.1.1.1" | "1.2.643.7.1.1.1.2" | "1.2.643.7.1.1.6.1" | "1.2.643.7.1.1.6.2" => {
                    gost_private(oid(algorithm.first()?.content)?.as_str(), algorithm.get(1)?, key)
                }
                "1.2.804.2.1.1.1.1.3.1.1" | "1.2.804.2.1.1.1.1.3.1.1.1.1" => dstu_private(oid(algorithm.first()?.content)?.as_str(), algorithm.get(1)?, key),
                ELGAMAL => elgamal_private(algorithm.get(1)?, key),
                GOST94 => gost94_private(algorithm.get(1)?, key),
                "1.3.101.110" => Some(eddsa("X25519", &x25519_public(tlv(key)?.0.content)?)),
                "1.3.101.111" => Some(eddsa("X448", &x448_public(tlv(key)?.0.content)?)),
                // PKCS #3 and X9.42 Diffie-Hellman: the parameters' p and g, the key an INTEGER
                "1.2.840.113549.1.3.1" | "1.2.840.10046.2.1" => {
                    let parameters = integers_prefix(algorithm.get(1)?.content)?;
                    let x = tlv(key)?.0;
                    (x.tag == 0x02).then_some(())?;
                    Some(dh(parameters.first()?, parameters.get(1)?, &BigUint::from_bytes_be(x.content)))
                }
                id @ ("2.16.840.1.101.3.4.4.1" | "2.16.840.1.101.3.4.4.2" | "2.16.840.1.101.3.4.4.3") => {
                    let (inner, first) = inner_key(key)?;
                    let public = mlkem_public(id, inner.tag, inner.content, first)?;
                    Some(eddsa(&format!("ML-KEM-{}", ["512", "768", "1024"][usize::from(id.as_bytes()[id.len() - 1] - b'1')]), &public))
                }
                // the classes printing `Object.toString`, and LMS/HSS
                id if super::pqc_keys::class(id).is_some() => super::pqc_keys::private(id, algorithm.get(1), key),
                // ML-DSA and SLH-DSA, pure or pre-hash: a HashML-DSA or HashSLH-DSA key is its pure set's key, named
                // with the digest
                id => match pre_hash(id) {
                    Some((pure, digest)) => {
                        let (name, public) = signature_key(&pure, key)?;
                        Some(eddsa(&format!("{name}-WITH-{digest}"), &public))
                    }
                    None => signature_key(id, key).map(|(name, public)| eddsa(name, &public)),
                },
            }
        }
        _ => None,
    }
}

/// The name of an ML-DSA or SLH-DSA private key's parameter set and its public key.
fn signature_key(id: &str, key: &[u8]) -> Option<(&'static str, Vec<u8>)> {
    if let Some(index) = ["2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.19"].iter().position(|&o| o == id) {
        let (inner, first) = inner_key(key)?;
        return Some((["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"][index], mldsa_public(id, inner.tag, inner.content, first)?));
    }
    let (name, length) = slh_dsa(id)?;
    // the four n-byte values (sk_seed, sk_prf, pk_seed, pk_root) are the key's octets themselves
    (key.len() == 2 * length).then_some(())?;
    Some((name, key[length..].to_vec()))
}

/// A post-quantum private key's inner element and, for the SEQUENCE form, the first OCTET STRING in it (the seed).
fn inner_key(key: &[u8]) -> Option<(Tlv<'_>, Option<&[u8]>)> {
    let inner = tlv(key)?.0;
    let first = if inner.tag == 0x30 { Some(items(inner.content)?.first()?.content) } else { None };
    Some((inner, first))
}

/// `DHPrivateKey.toString` of BouncyCastle (`DHUtil.privateKeyToString`): y = g^x mod p, fingerprinted with p and g.
fn dh(p: &BigUint, g: &BigUint, x: &BigUint) -> String {
    let y = g.modpow(x, p);
    let signed = |v: &BigUint| num_bigint::BigInt::from(v.clone()).to_signed_bytes_be();
    let input = [signed(&y), signed(p), signed(g)].concat();
    format!("DH Private Key [{}]\n              Y: {}\n", fingerprint(&input, 20), y.to_str_radix(16))
}

/// The leading INTEGERs of a sequence's content, ignoring what follows the first element that is not one (the
/// X9.42 `DomainParameters` carry optional structures after p, g and q).
fn integers_prefix(content: &[u8]) -> Option<Vec<BigUint>> {
    let parts = items(content)?;
    Some(parts.iter().take_while(|i| i.tag == 0x02).map(|i| BigUint::from_bytes_be(i.content)).collect())
}

/// The public half of a DSA or Ed448 private key, which the TLS stack cannot sign with but BouncyCastle's
/// `JcaPEMKeyConverter` reads.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum OtherPublic {
    /// y = g^x mod p, with the parameters p, q and g
    Dsa { y: BigUint, p: BigUint, q: BigUint, g: BigUint },
    /// the 57-byte encoded point
    Ed448(Vec<u8>),
}

/// [`OtherPublic`] of a DSA key (PKCS#8 or OpenSSL's traditional form) or a PKCS#8 Ed448 key; `None` for any other.
pub(super) fn dsa_or_ed448_public(pem: &str) -> Option<OtherPublic> {
    let block = x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes()).next()?.ok()?;
    let der = &block.contents[..];
    let dsa = |p: &BigUint, q: &BigUint, g: &BigUint, x: &BigUint| OtherPublic::Dsa { y: g.modpow(x, p), p: p.clone(), q: q.clone(), g: g.clone() };
    match block.label.as_str() {
        "DSA PRIVATE KEY" => {
            let numbers = integers(tlv(der)?.0.content)?;
            Some(dsa(numbers.get(1)?, numbers.get(2)?, numbers.get(3)?, numbers.get(5)?))
        }
        "PRIVATE KEY" => {
            let (sequence, _) = tlv(der)?;
            let parts = items(sequence.content)?;
            let algorithm = items(parts.get(1)?.content)?;
            let key = parts.get(2)?.content;
            match oid(algorithm.first()?.content)?.as_str() {
                "1.2.840.10040.4.1" => {
                    let parameters = integers(algorithm.get(1)?.content)?;
                    let x = tlv(key)?.0;
                    (x.tag == 0x02).then_some(())?;
                    Some(dsa(parameters.first()?, parameters.get(1)?, parameters.get(2)?, &BigUint::from_bytes_be(x.content)))
                }
                "1.3.101.113" => Some(OtherPublic::Ed448(ed448_public(tlv(key)?.0.content)?)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The 57-byte seed of a PKCS#8 Ed448 private key in PEM; `None` for any other key.
pub(super) fn ed448_seed(pem: &str) -> Option<Vec<u8>> {
    let block = x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes()).next()?.ok()?;
    (block.label == "PRIVATE KEY").then_some(())?;
    let (sequence, _) = tlv(&block.contents)?;
    let parts = items(sequence.content)?;
    let algorithm = items(parts.get(1)?.content)?;
    (oid(algorithm.first()?.content)? == "1.3.101.113").then_some(())?;
    let seed = tlv(parts.get(2)?.content)?.0.content;
    (seed.len() == 57).then(|| seed.to_vec())
}

/// [`OtherPublic`] of a certificate's `SubjectPublicKeyInfo` (DER) holding a DSA or Ed448 key; `None` for any other.
pub(super) fn certificate_dsa_or_ed448_public(spki: &[u8]) -> Option<OtherPublic> {
    let (sequence, _) = tlv(spki)?;
    let parts = items(sequence.content)?;
    let algorithm = items(parts.first()?.content)?;
    let bits = parts.get(1).filter(|b| b.tag == 0x03)?.content.get(1..)?;
    match oid(algorithm.first()?.content)?.as_str() {
        "1.2.840.10040.4.1" => {
            let parameters = integers(algorithm.get(1)?.content)?;
            let y = tlv(bits)?.0;
            (y.tag == 0x02).then_some(())?;
            Some(OtherPublic::Dsa { y: BigUint::from_bytes_be(y.content), p: parameters.first()?.clone(), q: parameters.get(1)?.clone(), g: parameters.get(2)?.clone() })
        }
        "1.3.101.113" => Some(OtherPublic::Ed448(bits.to_vec())),
        _ => None,
    }
}

/// The BouncyCastle class a CA private key reads as when it is not an RSA key (an RSASSA-PSS key reads as one), which
/// `SHA256WithRSAEncryption` refuses to sign with; `None` for an RSA key or one not recognised.
pub(super) fn non_rsa_class(pem: &str) -> Option<&'static str> {
    let block = x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes()).next()?.ok()?;
    let algorithm = match block.label.as_str() {
        "EC PRIVATE KEY" => "1.2.840.10045.2.1".to_string(),
        "DSA PRIVATE KEY" => "1.2.840.10040.4.1".to_string(),
        "PRIVATE KEY" => {
            let (sequence, _) = tlv(&block.contents)?;
            oid(items(items(sequence.content)?.get(1)?.content)?.first()?.content)?
        }
        _ => return None,
    };
    // a HashML-DSA or HashSLH-DSA key reads as its pure set's class
    let algorithm = pre_hash(&algorithm).map_or(algorithm, |(pure, _)| pure);
    Some(match algorithm.as_str() {
        "1.2.840.10045.2.1" => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey",
        "1.2.840.10040.4.1" | DSA_WITH_SHA1 | OIW_DSA_WITH_SHA1 => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPrivateKey",
        "1.3.101.112" | "1.3.101.113" => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey",
        "1.3.101.110" | "1.3.101.111" => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.edec.BCXDHPrivateKey",
        "1.2.840.113549.1.3.1" | "1.2.840.10046.2.1" => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.dh.BCDHPrivateKey",
        "2.16.840.1.101.3.4.3.17" | "2.16.840.1.101.3.4.3.18" | "2.16.840.1.101.3.4.3.19" => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.mldsa.BCMLDSAPrivateKey",
        "2.16.840.1.101.3.4.4.1" | "2.16.840.1.101.3.4.4.2" | "2.16.840.1.101.3.4.4.3" => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPrivateKey",
        "1.2.643.2.2.19" | "1.2.643.2.2.98" => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PrivateKey",
        "1.2.643.7.1.1.1.1" | "1.2.643.7.1.1.1.2" | "1.2.643.7.1.1.6.1" | "1.2.643.7.1.1.6.2" => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.ecgost12.BCECGOST3410_2012PrivateKey",
        "1.2.804.2.1.1.1.1.3.1.1" | "1.2.804.2.1.1.1.1.3.1.1.1.1" => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.dstu.BCDSTU4145PrivateKey",
        ELGAMAL => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.elgamal.BCElGamalPrivateKey",
        GOST94 => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.gost.BCGOST3410PrivateKey",
        id if slh_dsa(id).is_some() => "shaded_package.org.bouncycastle.jcajce.provider.asymmetric.slhdsa.BCSLHDSAPrivateKey",
        id => return super::pqc_keys::class(id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shake256_vectors() {
        assert_eq!(fingerprint(b"", 8), "46:b9:dd:2b:0b:a8:8d:13");
        let long = vec![0xa3u8; 200];
        assert_eq!(shake256(&long, 300).len(), 300);
    }

    /// Each key of `tests/files/x509/tostring/keys` and the `-key.pem` keys of its `ca-forms` against the text
    /// BouncyCastle 1.86 printed for it.
    #[test]
    fn matches_bouncy_castle() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/x509/tostring");
        let forms = std::fs::read_dir(dir.join("ca-forms")).expect("ca-forms").filter(|e| e.as_ref().is_ok_and(|e| e.path().to_string_lossy().ends_with("-key.pem")));
        let mut checked = 0;
        for entry in std::fs::read_dir(dir.join("keys")).expect("vectors").chain(forms) {
            let path = entry.expect("entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("pem") {
                continue;
            }
            // a key of a form whose certificate the oracle refuses (a `.err` beside it) is never loaded
            let certificate = path.to_string_lossy().replace("-key.pem", ".err");
            if std::path::Path::new(&certificate).exists() {
                continue;
            }
            let pem = std::fs::read_to_string(&path).expect("pem");
            // `<name>-key.err`: BouncyCastle's converter refuses the key (a GOST key beside parameters it reads in a
            // certificate but not in a private key), so there is no text
            if path.with_extension("err").exists() {
                assert_eq!(private_key_to_string(&pem), None, "{}", path.display());
                checked += 1;
                continue;
            }
            let expected = std::fs::read_to_string(path.with_extension("txt")).expect("expected text");
            let actual = private_key_to_string(&pem);
            // `BCLMSPrivateKey` hashes by identity, which differs run to run: the class only
            if let Some((class, _)) = expected.split_once(".BCLMSPrivateKey@") {
                assert!(actual.as_deref().is_some_and(|a| a.starts_with(&format!("{class}.BCLMSPrivateKey@"))), "{}", path.display());
                checked += 1;
                continue;
            }
            assert_eq!(actual.as_deref(), Some(expected.as_str()), "{}", path.display());
            checked += 1;
        }
        assert!(checked >= 22, "only {checked} vectors");
    }

    /// The fixed server certificate fixtures: each DSA/Ed448 key's public half is its certificate's,
    /// and not the other's.
    #[test]
    fn dsa_and_ed448_keys_match_their_certificates() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/tls");
        let read = |name: &str| std::fs::read_to_string(dir.join(name)).expect(name);
        let spki = |name: &str| {
            let pem = x509_parser::pem::Pem::iter_from_buffer(read(name).as_bytes()).next().expect("pem").expect("pem");
            let (_, certificate) = x509_parser::parse_x509_certificate(&pem.contents).expect("certificate");
            certificate.public_key().raw.to_vec()
        };
        let dsa = dsa_or_ed448_public(&read("fixed-dsa-key.pem")).expect("DSA key");
        let ed448 = dsa_or_ed448_public(&read("fixed-ed448-key.pem")).expect("Ed448 key");
        assert!(matches!(dsa, OtherPublic::Dsa { .. }) && matches!(ed448, OtherPublic::Ed448(_)));
        assert_eq!(certificate_dsa_or_ed448_public(&spki("fixed-dsa-cert.pem")), Some(dsa));
        assert_eq!(certificate_dsa_or_ed448_public(&spki("fixed-ed448-cert.pem")), Some(ed448));
        assert_eq!(certificate_dsa_or_ed448_public(&spki("fixed-ok-cert.pem")), None);
        assert_eq!(dsa_or_ed448_public(&read("fixed-ok-key.pem")), None);
    }
}

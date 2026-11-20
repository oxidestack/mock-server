//! ECDSA on any curve BouncyCastle's key factory accepts but SunEC does not sign on: the SAML IdP signs
//! through the JDK's XML-DSig, whose `Signature` falls over to BouncyCastle for these keys. Short Weierstrass curves
//! over a prime field and binary curves (`y² + xy = x³ + ax² + b` over GF(2^m), polynomial basis), in affine
//! coordinates: one scalar multiplication per signature.

use num_bigint::BigInt;
use rsa::BigUint;

use super::bc::{self, Asn1};

/// What [`EcDomainKey::read_curve`] reads: the domain without its base point, the base point's octets, the cofactor.
type DomainParts = (EcDomainKey, Vec<u8>, Option<BigUint>);

/// A curve's domain parameters and a private scalar on it.
pub struct EcDomainKey {
    field: Field,
    a: Element,
    b: Element,
    g: (Element, Element),
    n: BigUint,
    d: BigUint,
}

#[derive(Clone)]
enum Field {
    Prime(BigUint),
    /// GF(2^m) with its reduction polynomial (all terms, `x^m` included) and the exponents of its terms below `m`
    Binary { m: usize, poly: Poly, terms: Vec<usize> },
}

#[derive(Clone, PartialEq)]
enum Element {
    Prime(BigUint),
    Binary(Poly),
}

/// A polynomial over GF(2), little-endian 64-bit words.
#[derive(Clone, Debug)]
struct Poly(Vec<u64>);

/// Equal coefficients, whatever the number of zero words above them.
impl PartialEq for Poly {
    fn eq(&self, other: &Poly) -> bool {
        let n = self.0.len().max(other.0.len());
        (0..n).all(|i| self.0.get(i).unwrap_or(&0) == other.0.get(i).unwrap_or(&0))
    }
}

impl EcDomainKey {
    /// The key `d` on the named curve `oid` (its content octets), `None` for a curve not in [`super::curves`].
    pub(super) fn named(oid: &[u8], d: &[u8]) -> Option<EcDomainKey> {
        EcDomainKey::explicit(&EcDomainKey::named_domain(oid)?, d)
    }

    /// The key `d` on explicit `SpecifiedECDomain` parameters (version, fieldID, curve, base, order, ...): `None`
    /// for parameters [`EcDomainKey::read`] refuses or does not read.
    pub(super) fn explicit(domain: &[Asn1], d: &[u8]) -> Option<EcDomainKey> {
        let key = EcDomainKey::read(domain).ok()??;
        Some(EcDomainKey { d: BigUint::from_bytes_be(d), ..key })
    }

    /// BouncyCastle's `X9ECParameters` over explicit `SpecifiedECDomain` parameters and `ECCurve.decodePoint` of
    /// their base point, as the EC key factory reads them: the domain (with `d` = 0), or the message of
    /// the exception BouncyCastle throws (an IllegalArgumentException, or the converter's NullPointerException for a
    /// base at infinity). `Ok(None)` for shapes not modelled: another field type, a degree or exponent past 16 bits,
    /// elements of the wrong ASN.1 type where BouncyCastle casts.
    pub(super) fn read(domain: &[Asn1]) -> Result<Option<EcDomainKey>, String> {
        let Some((mut key, base, h)) = EcDomainKey::read_curve(domain)? else { return Ok(None) };
        // the order as unsigned octets, as the key factories' callers have always read it
        let Some(Asn1::Integer(n)) = domain.get(4) else { return Ok(None) };
        key.n = BigUint::from_bytes_be(n);
        if key.n.bits() < 2 {
            return Ok(None);
        }
        key.g = key.decode_point(&base, h.as_ref())?;
        Ok(Some(key))
    }

    /// [`EcDomainKey::read`] up to the curve: the domain without its base point, the base point's octets and the
    /// cofactor, or the message of the exception `X9ECParameters` and `ECCurve` throw before the base point is
    /// decoded. `Ok(None)` for shapes not modelled (the order is read as its magnitude, a negative one too).
    pub(super) fn read_curve(domain: &[Asn1]) -> Result<Option<DomainParts>, String> {
        const PRIME_FIELD: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01];
        const BINARY_FIELD: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x02];
        const TRINOMIAL: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x02, 0x03, 0x02];
        const PENTANOMIAL: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x02, 0x03, 0x03];
        // `X9ECParameters(ASN1Sequence)`: an INTEGER version of value 1 first
        if !matches!(domain.first(), Some(Asn1::Integer(v)) if v.as_slice() == [1]) {
            return Err("bad version in X9ECParameters".into());
        }
        let (Some(Asn1::Sequence(field_id, _)), Some(Asn1::Sequence(curve, _)), Some(Asn1::OctetString(_, base)), Some(Asn1::Integer(n))) =
            (domain.get(1), domain.get(2), domain.get(3), domain.get(4))
        else {
            return Ok(None);
        };
        let n = BigUint::from_bytes_be(&BigInt::from_signed_bytes_be(n).magnitude().to_bytes_be());
        let h = match domain.get(5) {
            None => None,
            Some(Asn1::Integer(h)) => Some(BigUint::from_bytes_be(h)),
            Some(_) => return Ok(None),
        };
        let int = |a: &Asn1| match a {
            Asn1::Integer(v) => Some(BigUint::from_bytes_be(v)),
            _ => None,
        };
        let field = match field_id.as_slice() {
            [Asn1::Oid(t), Asn1::Integer(p), ..] if t == PRIME_FIELD => {
                prime_field_check(p)?;
                Field::Prime(BigUint::from_bytes_be(p))
            }
            [Asn1::Oid(t), Asn1::Sequence(c2, _), ..] if t == BINARY_FIELD => {
                let (Some(m), Some(Asn1::Oid(basis)), Some(parameters)) = (c2.first().and_then(int), c2.get(1), c2.get(2)) else { return Ok(None) };
                let Some(m) = small(&m) else { return Ok(None) };
                // `ASN1Integer.getInstance` of a trinomial's k, `ASN1Sequence.getInstance` of a pentanomial's
                let ks = if basis == TRINOMIAL {
                    let Asn1::Integer(_) = parameters else { return Err(format!("illegal object in getInstance: {}", parameters.class())) };
                    vec![parameters]
                } else if basis == PENTANOMIAL {
                    let Asn1::Sequence(ks, _) = parameters else { return Err(format!("unknown object in getInstance: {}", parameters.class())) };
                    ks.iter().take(3).collect()
                } else {
                    return Err("This type of EC basis is not implemented".into());
                };
                let mut k = [0usize; 3];
                for (slot, value) in k.iter_mut().zip(ks) {
                    let Some(value) = int(value).as_ref().and_then(small) else { return Ok(None) };
                    *slot = value;
                }
                // `ECCurve.AbstractF2m.buildField` and `FiniteFields.getBinaryExtensionField`
                if m > 1142 {
                    return Err(format!("field size out of range: {m}"));
                }
                let exponents = if k[1] | k[2] == 0 { vec![0, k[0], m] } else { vec![0, k[0], k[1], k[2], m] };
                if exponents.windows(2).any(|w| w[1] <= w[0]) {
                    return Err("Polynomial exponents must be monotonically increasing".into());
                }
                Field::binary(m, &exponents)
            }
            _ => return Ok(None),
        };
        let (Some(Asn1::OctetString(_, a)), Some(Asn1::OctetString(_, b))) = (curve.first(), curve.get(1)) else { return Ok(None) };
        let (a, b) = (field.element_of(&BigUint::from_bytes_be(a))?, field.element_of(&BigUint::from_bytes_be(b))?);
        let zero = field.small(0);
        let key = EcDomainKey { field, a, b, g: (zero.clone(), zero), n, d: BigUint::from(0u8) };
        Ok(Some((key, base.clone(), h)))
    }

    /// `new ECCurve.F2m(m, k1, k2, k3, a, b, null, null)` as `BCDSTU4145PrivateKey` builds a `DSTU4145ECBinary` curve
    /// (the base point is [`EcDomainKey::decode_dstu_point`]'s): the domain without a base point (the order is set
    /// by the caller), or the message of the IllegalArgumentException (`m`, `k1`..`k3` are non-negative ints).
    pub(super) fn dstu_binary(m: i64, k: [i64; 3], a: &BigInt, b: &[u8]) -> Result<EcDomainKey, String> {
        // `ECCurve.AbstractF2m.buildField` and `FiniteFields.getBinaryExtensionField`
        if m > 1142 {
            return Err(format!("field size out of range: {m}"));
        }
        let exponents: Vec<i64> = if k[1] | k[2] == 0 { vec![0, k[0], m] } else { vec![0, k[0], k[1], k[2], m] };
        if exponents.windows(2).any(|w| w[1] <= w[0]) {
            return Err("Polynomial exponents must be monotonically increasing".into());
        }
        let field = Field::binary(m as usize, &exponents.iter().map(|e| *e as usize).collect::<Vec<_>>());
        let a = field.element_of(&BigUint::from_bytes_be(&a.to_biguint().ok_or("x value invalid in F2m field element")?.to_bytes_be()))?;
        let b = field.element_of(&BigUint::from_bytes_be(b))?;
        let zero = field.small(0);
        Ok(EcDomainKey { field, a, b, g: (zero.clone(), zero), n: BigUint::from(0u8), d: BigUint::from(0u8) })
    }

    /// `DSTU4145PointEncoder.decodePoint(curve, bytes)` (the base point is one octet shorter than an uncompressed
    /// x: the low bit of x carries the trace of y/x) and `validatePoint`: the point, or the exception's message. The
    /// root of the quadratic equation is either one for an even degree, where BouncyCastle's is random too.
    fn decode_dstu_point(&self, bytes: &[u8]) -> Result<(Element, Element), String> {
        let f = &self.field;
        let Some(&last) = bytes.last() else { return Err("Index -1 out of bounds for length 0".into()) };
        let k = last & 1 == 1;
        let mut x = f.element_of(&BigUint::from_bytes_be(bytes))?;
        // `trace(xp).equals(curve.getA())`
        if f.small(f.trace(&x) as u8) != self.a {
            x = f.add(&x, &f.small(1));
        }
        let y = if x.is_zero() {
            f.sqrt(&self.b).expect("every element of GF(2^m) is a square")
        } else {
            let x_inverse = f.inv(&x).expect("x is not zero");
            let beta = f.add(&f.add(&f.mul(&f.mul(&x_inverse, &x_inverse), &self.b), &self.a), &x);
            let mut z = f.solve_quadratic(&beta).ok_or("Invalid point compression")?;
            if f.trace(&z) != k {
                z = f.add(&z, &f.small(1));
            }
            f.mul(&x, &z)
        };
        let point = (x, y);
        if !self.on_curve(&point) {
            return Err("Invalid point coordinates".into());
        }
        Ok(point)
    }

    /// The domain's base point from a `DSTU4145ECBinary`'s octets ([`EcDomainKey::decode_dstu_point`]).
    pub(super) fn set_dstu_base(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.g = self.decode_dstu_point(bytes)?;
        Ok(())
    }

    /// The domain's order and private scalar.
    pub(super) fn set_order_and_key(&mut self, n: &[u8], d: &[u8]) {
        self.n = BigUint::from_bytes_be(n);
        self.d = BigUint::from_bytes_be(d);
    }

    /// [`EcDomainKey::decode_point`] of a base point of explicit `X9ECParameters`, the key's base point.
    pub(super) fn decode_base(&mut self, encoded: &[u8], h: Option<&BigUint>) -> Result<(), String> {
        self.g = self.decode_point(encoded, h)?;
        Ok(())
    }

    /// The `SpecifiedECDomain` elements of the named curve `oid` (its content octets), `None` for a curve not in
    /// [`super::curves`].
    pub(super) fn named_domain(oid: &[u8]) -> Option<Vec<Asn1>> {
        let (_, hex) = super::curves::NAMED_DOMAINS.iter().find(|(o, _)| *o == oid)?;
        let der: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex")).collect();
        bc::sequence(&der).ok()
    }

    /// The EC key factory's reading of a key pair's public point on the curve of `domain` (`BCECPublicKey`'s
    /// `populateFromPubKeyInfo`: a legacy OCTET STRING wrapping is unwrapped, then `ECCurve.decodePoint`): the
    /// exception's message; the point at infinity is `ECPublicKeyParameters`' refusal. Parameters
    /// [`EcDomainKey::read`] does not model pass. A named curve BouncyCastle implements as a custom curve
    /// (`CustomNamedCurves`) names its field element class in a coordinate's refusal.
    pub(super) fn check_public_point(domain: &[Asn1], data: &[u8], named: Option<&[u8]>) -> Result<(), String> {
        let Some(key) = EcDomainKey::read(domain)? else { return Ok(()) };
        let h = match domain.get(5) {
            Some(Asn1::Integer(h)) => Some(BigUint::from_bytes_be(h)),
            _ => None,
        };
        let at = |i: usize| data.get(i).copied().ok_or_else(|| format!("Index {i} out of bounds for length {}", data.len()));
        let mut encoded = data;
        if at(0)? == 0x04 && i64::from(at(1)? as i8) == data.len() as i64 - 2 && matches!(at(2)?, 2 | 3) && key.field.len() >= data.len() - 3 {
            encoded = &data[2..];
        }
        if encoded == [0x00] {
            return Err("Point at infinity".into());
        }
        key.decode_point(encoded, h.as_ref()).map(|_| ()).map_err(|m| match named.and_then(custom_field_element) {
            Some(element) if m == "x value invalid for Fp field element" || m == "x value invalid in F2m field element" => {
                format!("x value invalid for {element}")
            }
            _ => m,
        })
    }

    /// `ECCurve.decodePoint` of a base point on this curve (cofactor `h`): the point, or the exception's message.
    fn decode_point(&self, encoded: &[u8], h: Option<&BigUint>) -> Result<(Element, Element), String> {
        let f = &self.field;
        let len = f.len();
        let Some(&ty) = encoded.first() else { return Err("Index 0 out of bounds for length 0".into()) };
        let coordinate = |bytes: &[u8]| BigUint::from_bytes_be(bytes);
        let point = match ty {
            0x00 => {
                if encoded.len() != 1 {
                    return Err("Incorrect length for infinity encoding".into());
                }
                // `EC5Util.convertPoint` of the point at infinity
                return Err("Cannot invoke \"shaded_package.org.bouncycastle.math.ec.ECFieldElement.toBigInteger()\" because the return value of \"shaded_package.org.bouncycastle.math.ec.ECPoint.getAffineXCoord()\" is null".into());
            }
            0x02 | 0x03 => {
                if encoded.len() != len + 1 {
                    return Err("Incorrect length for compressed encoding".into());
                }
                let point = self.decompress(ty & 1 == 1, &coordinate(&encoded[1..]))?.ok_or("Invalid point compression")?;
                if !self.satisfies_order(&point, h) {
                    return Err("Invalid point".into());
                }
                point
            }
            0x04 | 0x06 | 0x07 => {
                if encoded.len() != 2 * len + 1 {
                    return Err(if ty == 0x04 { "Incorrect length for uncompressed encoding" } else { "Incorrect length for hybrid encoding" }.into());
                }
                let (x, y) = (coordinate(&encoded[1..=len]), coordinate(&encoded[len + 1..]));
                if ty != 0x04 && is_odd(&y) != (ty == 0x07) {
                    return Err("Inconsistent Y coordinate in hybrid encoding".into());
                }
                // `validatePoint`
                let point = (f.element_of(&x)?, f.element_of(&y)?);
                if !self.on_curve(&point) || !self.satisfies_order(&point, h) {
                    return Err("Invalid point coordinates".into());
                }
                point
            }
            // the BouncyCastle at the oracle's pin writes the type byte as two hex digits (saml_explicit_ec_keys)
            _ => return Err(format!("Invalid point encoding type: 0x{ty:02x}")),
        };
        Ok(point)
    }

    /// `decompressPoint`: the point of x coordinate `x` whose y (prime field) or y/x (binary field) has the low bit
    /// `odd`; `None` where there is none. Out-of-field x is the field's exception.
    fn decompress(&self, odd: bool, x: &BigUint) -> Result<Option<(Element, Element)>, String> {
        let f = &self.field;
        let x = f.element_of(x)?;
        Ok(match f {
            Field::Prime(p) => {
                let rhs = f.add(&f.mul(&f.add(&f.mul(&x, &x), &self.a), &x), &self.b);
                f.sqrt(&rhs).map(|y| {
                    let y = if is_odd(&y.integer()) != odd { Element::Prime((p - y.integer()) % p) } else { y };
                    (x, y)
                })
            }
            Field::Binary { .. } => {
                if x.is_zero() {
                    let y = f.sqrt(&self.b).expect("every element of GF(2^m) is a square");
                    return Ok(Some((x, y)));
                }
                let x_inverse = f.inv(&x).expect("x is not zero");
                let beta = f.add(&f.add(&f.mul(&f.mul(&x_inverse, &x_inverse), &self.b), &self.a), &x);
                f.solve_quadratic(&beta).map(|z| {
                    let z = if is_odd(&z.integer()) != odd { f.add(&z, &f.small(1)) } else { z };
                    let y = f.mul(&z, &x);
                    (x, y)
                })
            }
        })
    }

    /// `satisfiesCurveEquation` in affine coordinates.
    fn on_curve(&self, (x, y): &(Element, Element)) -> bool {
        let f = &self.field;
        match f {
            Field::Prime(_) => f.mul(y, y) == f.add(&f.mul(&f.add(&f.mul(x, x), &self.a), x), &self.b),
            Field::Binary { .. } => f.mul(&f.add(y, x), y) == f.add(&f.mul(&f.add(x, &self.a), &f.mul(x, x)), &self.b),
        }
    }

    /// `ECPoint.satisfiesOrder` (and `AbstractF2m`'s): a cofactor of 1 passes; on a binary curve a cofactor of 2
    /// needs `Tr(x) = 1`, of 4 a half point that halves again; anything else (no cofactor included) `n·P = ∞`.
    fn satisfies_order(&self, point: &(Element, Element), h: Option<&BigUint>) -> bool {
        let f = &self.field;
        let h = h.map(|h| h.to_bytes_be());
        match (f, h.as_deref()) {
            (_, Some([1])) => true,
            (Field::Binary { .. }, Some([2])) => f.trace(&point.0),
            (Field::Binary { .. }, Some([4])) => {
                let (x, y) = point;
                let Some(l) = f.solve_quadratic(&f.add(x, &self.a)) else { return false };
                !f.trace(&f.add(&f.mul(x, &l), y))
            }
            // `referenceMultiply(P, 0)` is the point at infinity
            _ if self.n.bits() == 0 => true,
            _ => {
                // On a binary field the x-only ladder (one inversion) rather than affine double-and-add (one per
                // step): c2pnb176v1's cofactor 0xff6e took 0.7 s of an unoptimised build per key read, past the
                // oracle harness's step timeout on a loaded host. The ladder's result is the point at
                // infinity exactly when Z ends 0, which its formulas keep for multiples of P's order on the way.
                let at_point = EcDomainKey { field: f.clone(), a: self.a.clone(), b: self.b.clone(), g: point.clone(), n: self.n.clone(), d: BigUint::from(0u8) };
                match f {
                    Field::Binary { .. } => at_point.x_of_multiple(&self.n).is_none(),
                    Field::Prime(_) => at_point.multiply(&self.n).is_none(),
                }
            }
        }
    }

    /// ECDSA over `digest` as `ECDSASigner` computes it (the digest's leftmost order-length bits, a random `k`), in
    /// the XML-DSig form `DOMSignatureMethod` writes: `r || s`, each of the order's length in bytes.
    pub fn sign_prehash(&self, digest: &[u8]) -> Option<Vec<u8>> {
        let n = &self.n;
        let n_bits = n.bits();
        if n_bits < 2 {
            return None;
        }
        let mut e = BigUint::from_bytes_be(digest);
        if digest.len() * 8 > n_bits {
            e >>= digest.len() * 8 - n_bits;
        }
        let zero = BigUint::from(0u8);
        let d = &self.d % n;
        for _ in 0..64 {
            let mut bytes = vec![0u8; n_bits.div_ceil(8) + 8];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
            let k = BigUint::from_bytes_be(&bytes) % n;
            if k == zero {
                continue;
            }
            let Some(x) = self.x_of_multiple(&k) else { continue };
            let r = x.integer() % n;
            if r == zero {
                continue;
            }
            let k_inverse = k.modpow(&(n - BigUint::from(2u8)), n);
            let s = (k_inverse * ((&e + &d * &r) % n)) % n;
            if s == zero {
                continue;
            }
            let len = n_bits.div_ceil(8);
            return Some([super::fixed_len(&r.to_bytes_be(), len)?, super::fixed_len(&s.to_bytes_be(), len)?].concat());
        }
        None
    }

    /// The x coordinate of `k·G`, `None` for the point at infinity: on a binary curve López and Dahab's Montgomery
    /// ladder in projective coordinates (`X⁴ + bZ⁴`, `X²Z²` doubling; one inversion at the end), on a prime curve
    /// [`EcDomainKey::multiply`].
    fn x_of_multiple(&self, k: &BigUint) -> Option<Element> {
        let Field::Binary { m, terms, .. } = &self.field else { return self.multiply(k).map(|(x, _)| x) };
        let (Element::Binary(x), Element::Binary(b)) = (&self.g.0, &self.b) else { unreachable!("elements of one field") };
        let (m, terms) = (*m, terms.as_slice());
        let mul = |a: &Poly, c: &Poly| a.mul_mod(c, m, terms);
        let sqr = |a: &Poly| a.sqr_mod(m, terms);
        let double = |(px, pz): (&Poly, &Poly)| {
            let (x2, z2) = (sqr(px), sqr(pz));
            (sqr(&x2).xor(&mul(b, &sqr(&z2))), mul(&x2, &z2))
        };
        // `(X1, Z1) + (X2, Z2)`, whose difference is G
        let add = |(x1, z1): (&Poly, &Poly), (x2, z2): (&Poly, &Poly)| {
            let (u, v) = (mul(x1, z2), mul(x2, z1));
            let z3 = sqr(&u.xor(&v));
            (mul(x, &z3).xor(&mul(&u, &v)), z3)
        };
        let bytes = k.to_bytes_be();
        let bits = k.bits();
        if bits == 0 {
            return None;
        }
        let one = Poly::from_bytes_be(&[1], m + 1);
        let (mut p1, mut p2) = ((x.clone(), one.clone()), double((x, &one)));
        for i in (0..bits - 1).rev() {
            if bytes[bytes.len() - 1 - i / 8] >> (i % 8) & 1 == 1 {
                p1 = add((&p1.0, &p1.1), (&p2.0, &p2.1));
                p2 = double((&p2.0, &p2.1));
            } else {
                p2 = add((&p1.0, &p1.1), (&p2.0, &p2.1));
                p1 = double((&p1.0, &p1.1));
            }
        }
        let (px, pz) = p1;
        let inverse = self.field.inv(&Element::Binary(pz))?;
        Some(self.field.mul(&Element::Binary(px), &inverse))
    }

    /// `k·G`, `None` for the point at infinity.
    fn multiply(&self, k: &BigUint) -> Option<(Element, Element)> {
        let mut result: Option<(Element, Element)> = None;
        let bytes = k.to_bytes_be();
        for i in (0..bytes.len() * 8).rev() {
            result = result.and_then(|p| self.double(&p));
            if bytes[bytes.len() - 1 - i / 8] >> (i % 8) & 1 == 1 {
                result = match result {
                    None => Some(self.g.clone()),
                    Some(p) => self.add(&p, &self.g),
                };
            }
        }
        result
    }

    fn add(&self, p: &(Element, Element), q: &(Element, Element)) -> Option<(Element, Element)> {
        let f = &self.field;
        let ((x1, y1), (x2, y2)) = (p, q);
        if x1 == x2 {
            return if y1 == y2 { self.double(p) } else { None };
        }
        let lambda = f.mul(&f.sub(y2, y1), &f.inv(&f.sub(x2, x1))?);
        match f {
            Field::Prime(_) => {
                let x3 = f.sub(&f.sub(&f.mul(&lambda, &lambda), x1), x2);
                let y3 = f.sub(&f.mul(&lambda, &f.sub(x1, &x3)), y1);
                Some((x3, y3))
            }
            Field::Binary { .. } => {
                let x3 = f.add(&f.add(&f.add(&f.add(&f.mul(&lambda, &lambda), &lambda), x1), x2), &self.a);
                let y3 = f.add(&f.add(&f.mul(&lambda, &f.add(x1, &x3)), &x3), y1);
                Some((x3, y3))
            }
        }
    }

    fn double(&self, p: &(Element, Element)) -> Option<(Element, Element)> {
        let f = &self.field;
        let (x, y) = p;
        match f {
            Field::Prime(_) => {
                if y.is_zero() {
                    return None;
                }
                let three_x2 = f.mul(&f.small(3), &f.mul(x, x));
                let lambda = f.mul(&f.add(&three_x2, &self.a), &f.inv(&f.add(y, y))?);
                let x3 = f.sub(&f.sub(&f.mul(&lambda, &lambda), x), x);
                let y3 = f.sub(&f.mul(&lambda, &f.sub(x, &x3)), y);
                Some((x3, y3))
            }
            Field::Binary { .. } => {
                if x.is_zero() {
                    return None;
                }
                let lambda = f.add(x, &f.mul(y, &f.inv(x)?));
                let x3 = f.add(&f.add(&f.mul(&lambda, &lambda), &lambda), &self.a);
                let y3 = f.add(&f.mul(x, x), &f.mul(&f.add(&lambda, &f.small(1)), &x3));
                Some((x3, y3))
            }
        }
    }

    #[cfg(test)]
    fn public_point(&self) -> Option<(Element, Element)> {
        self.multiply(&self.d)
    }

    #[cfg(test)]
    fn verify_prehash(&self, digest: &[u8], signature: &[u8]) -> bool {
        let n = &self.n;
        let len = n.bits().div_ceil(8);
        if signature.len() != 2 * len {
            return false;
        }
        let (r, s) = (BigUint::from_bytes_be(&signature[..len]), BigUint::from_bytes_be(&signature[len..]));
        let mut e = BigUint::from_bytes_be(digest);
        if digest.len() * 8 > n.bits() {
            e >>= digest.len() * 8 - n.bits();
        }
        let w = s.modpow(&(n - BigUint::from(2u8)), n);
        let (u1, u2) = ((&e * &w) % n, (&r * &w) % n);
        let Some(q) = self.public_point() else { return false };
        let generator = EcDomainKey { d: u1, ..self.clone_domain() };
        let public = EcDomainKey { d: u2, g: q, ..self.clone_domain() };
        let point = match (generator.public_point(), public.public_point()) {
            (Some(a), Some(b)) => self.add(&a, &b),
            (a, b) => a.or(b),
        };
        point.is_some_and(|(x, _)| x.integer() % n == r)
    }

    #[cfg(test)]
    fn clone_domain(&self) -> EcDomainKey {
        EcDomainKey { field: self.field.clone(), a: self.a.clone(), b: self.b.clone(), g: self.g.clone(), n: self.n.clone(), d: self.d.clone() }
    }
}

/// The field element class of the curve `CustomNamedCurves` defines for the named curve `oid` (its content octets;
/// P-256/384/521 are not read here), `None` for a curve on BouncyCastle's generic `ECCurve.Fp`/`F2m`.
fn custom_field_element(oid: &[u8]) -> Option<&'static str> {
    const SEC: &[u8] = &[0x2b, 0x81, 0x04, 0x00];
    const SECP192R1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01];
    const SM2P256V1: &[u8] = &[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d];
    Some(match oid {
        SECP192R1 => "SecP192R1FieldElement",
        SM2P256V1 => "SM2P256V1FieldElement",
        [s @ .., arc] if s == SEC => match arc {
            28 => "SecP128R1FieldElement",
            9 | 30 => "SecP160R2FieldElement",
            8 => "SecP160R1FieldElement",
            31 => "SecP192K1FieldElement",
            32 => "SecP224K1FieldElement",
            33 => "SecP224R1FieldElement",
            10 => "SecP256K1FieldElement",
            4 | 5 => "SecT113FieldElement",
            22 | 23 => "SecT131FieldElement",
            1 | 2 | 15 => "SecT163FieldElement",
            24 | 25 => "SecT193FieldElement",
            26 | 27 => "SecT233FieldElement",
            3 => "SecT239FieldElement",
            16 | 17 => "SecT283FieldElement",
            36 | 37 => "SecT409FieldElement",
            38 | 39 => "SecT571FieldElement",
            _ => return None,
        },
        _ => return None,
    })
}

/// `ECCurve.Fp`'s check of a prime field's `q` (the INTEGER's content octets) BouncyCastle has not met before: at
/// least 2 (`FiniteFields.getPrimeField`), at most 1042 bits (`fp_max_size`), then `Primes.hasAnySmallFactors` and a
/// Miller-Rabin test. The exception's message.
fn prime_field_check(q: &[u8]) -> Result<(), String> {
    let Some(q) = num_bigint::BigInt::from_signed_bytes_be(q).to_biguint().filter(|q| q.bits() >= 2) else {
        return Err("'characteristic' must be >= 2".into());
    };
    if q.bits() > 1042 {
        return Err("Fp q value out of range".into());
    }
    const SMALL_PRIMES: &[u32] = &[
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
        127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
    ];
    let zero = num_bigint::BigUint::from(0u8);
    if SMALL_PRIMES.iter().any(|p| &q % *p == zero) || !super::jca::probably_prime(&q) {
        return Err("Fp q value not prime".into());
    }
    Ok(())
}

/// A basis exponent or degree, `None` past 16 bits.
fn small(v: &BigUint) -> Option<usize> {
    (v.bits() <= 16).then(|| v.to_bytes_be().iter().fold(0, |acc, b| acc << 8 | usize::from(*b)))
}

/// `testBit(0)`.
fn is_odd(v: &BigUint) -> bool {
    v.to_bytes_be().last().is_some_and(|b| b & 1 == 1)
}

/// A square root of `a` modulo the odd prime `p` (Tonelli and Shanks), `None` for a non-residue; the root is
/// checked, so a composite `p` gives `None` rather than a wrong root.
fn prime_sqrt(a: &BigUint, p: &BigUint) -> Option<BigUint> {
    let (zero, one, two) = (BigUint::from(0u8), BigUint::from(1u8), BigUint::from(2u8));
    let a = a % p;
    if a == zero || *p == two {
        return Some(a);
    }
    let p1 = p - &one;
    let legendre = |x: &BigUint| x.modpow(&(&p1 >> 1), p);
    if legendre(&a) != one {
        return None;
    }
    let (mut q, mut s) = (p1.clone(), 0u32);
    while !is_odd(&q) {
        q >>= 1;
        s += 1;
    }
    let mut z = two;
    while legendre(&z) != p1 {
        z += 1u8;
        if z.bits() > 32 {
            return None;
        }
    }
    let (mut m, mut c, mut t, mut r) = (s, z.modpow(&q, p), a.modpow(&q, p), a.modpow(&((&q + &one) >> 1), p));
    while t != one {
        let mut i = 0;
        let mut t2 = t.clone();
        while t2 != one {
            t2 = &t2 * &t2 % p;
            i += 1;
            if i == m {
                return None;
            }
        }
        let mut b = c.clone();
        for _ in 0..m - i - 1 {
            b = &b * &b % p;
        }
        m = i;
        c = &b * &b % p;
        t = t * &c % p;
        r = r * b % p;
    }
    (&r * &r % p == a).then_some(r)
}

impl Field {
    /// GF(2^m) with the reduction polynomial of the given terms (ascending, `0` and `m` included).
    fn binary(m: usize, exponents: &[usize]) -> Field {
        let mut poly = Poly::zero(m + 1);
        for t in exponents {
            poly.flip(*t);
        }
        Field::Binary { m, poly, terms: exponents[..exponents.len() - 1].to_vec() }
    }

    /// An element's length in bytes.
    fn len(&self) -> usize {
        match self {
            Field::Prime(p) => p.bits().div_ceil(8),
            Field::Binary { m, .. } => m.div_ceil(8),
        }
    }

    fn small(&self, v: u8) -> Element {
        match self {
            Field::Prime(p) => Element::Prime(BigUint::from(v) % p),
            Field::Binary { m, .. } => Element::Binary(Poly::from_bytes_be(&[v], *m + 1)),
        }
    }

    fn add(&self, a: &Element, b: &Element) -> Element {
        match (self, a, b) {
            (Field::Prime(p), Element::Prime(a), Element::Prime(b)) => Element::Prime((a + b) % p),
            (_, Element::Binary(a), Element::Binary(b)) => Element::Binary(a.xor(b)),
            _ => unreachable!("elements of one field"),
        }
    }

    fn sub(&self, a: &Element, b: &Element) -> Element {
        match (self, a, b) {
            (Field::Prime(p), Element::Prime(a), Element::Prime(b)) => Element::Prime((a + p - b) % p),
            (_, Element::Binary(a), Element::Binary(b)) => Element::Binary(a.xor(b)),
            _ => unreachable!("elements of one field"),
        }
    }

    fn mul(&self, a: &Element, b: &Element) -> Element {
        match (self, a, b) {
            (Field::Prime(p), Element::Prime(a), Element::Prime(b)) => Element::Prime((a * b) % p),
            (Field::Binary { m, terms, .. }, Element::Binary(a), Element::Binary(b)) => Element::Binary(a.mul_mod(b, *m, terms)),
            _ => unreachable!("elements of one field"),
        }
    }

    /// `fromBigInteger`: the element `x`, or the field element's IllegalArgumentException message.
    fn element_of(&self, x: &BigUint) -> Result<Element, String> {
        match self {
            Field::Prime(p) if x >= p => Err("x value invalid for Fp field element".into()),
            Field::Prime(_) => Ok(Element::Prime(x.clone())),
            Field::Binary { m, .. } if x.bits() > *m => Err("x value invalid in F2m field element".into()),
            Field::Binary { m, .. } => Ok(Element::Binary(Poly::from_bytes_be(&x.to_bytes_be(), *m + 1))),
        }
    }

    /// A square root, `None` where there is none: Tonelli and Shanks' algorithm on a prime field (checked, so a
    /// composite modulus gives `None` rather than a wrong root); `a^(2^(m-1))` on a binary one.
    fn sqrt(&self, a: &Element) -> Option<Element> {
        match (self, a) {
            (Field::Prime(p), Element::Prime(a)) => prime_sqrt(a, p).map(Element::Prime),
            (Field::Binary { m, terms, .. }, Element::Binary(a)) => {
                let mut r = a.clone();
                for _ in 1..*m {
                    r = r.sqr_mod(*m, terms);
                }
                Some(Element::Binary(r))
            }
            _ => unreachable!("elements of one field"),
        }
    }

    /// The trace `Σ a^(2^i)`, `i < m`, of a binary-field element: `true` for 1.
    fn trace(&self, a: &Element) -> bool {
        let (Field::Binary { m, terms, .. }, Element::Binary(a)) = (self, a) else { unreachable!("a binary field") };
        let (mut t, mut sum) = (a.clone(), a.clone());
        for _ in 1..*m {
            t = t.sqr_mod(*m, terms);
            sum = sum.xor(&t);
        }
        sum.bit(0)
    }

    /// `ECCurve.AbstractF2m.solveQuadraticEquation`: a `z` with `z² + z = beta`, `None` where there is none; the
    /// half-trace for an odd degree, BouncyCastle's randomised method for an even one (either root: callers fix
    /// the low bit).
    fn solve_quadratic(&self, beta: &Element) -> Option<Element> {
        let Field::Binary { m, .. } = self else { unreachable!("a binary field") };
        let m = *m;
        let sqr = |a: &Element| self.mul(a, a);
        let is_root = |z: &Element| self.add(&self.add(&sqr(z), z), beta).is_zero();
        if m % 2 == 1 {
            let (mut t, mut r) = (beta.clone(), beta.clone());
            for _ in 0..(m - 1) / 2 {
                t = sqr(&sqr(&t));
                r = self.add(&r, &t);
            }
            return is_root(&r).then_some(r);
        }
        if beta.is_zero() {
            return Some(beta.clone());
        }
        for _ in 0..256 {
            let mut bytes = vec![0u8; m.div_ceil(8)];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
            if m % 8 != 0 {
                bytes[0] &= (1u8 << (m % 8)) - 1;
            }
            let t = self.element_of(&BigUint::from_bytes_be(&bytes)).expect("m bits");
            let (mut z, mut w) = (self.small(0), beta.clone());
            for _ in 1..m {
                let w2 = sqr(&w);
                z = self.add(&sqr(&z), &self.mul(&w2, &t));
                w = self.add(&w2, beta);
            }
            if !w.is_zero() {
                return None;
            }
            if !self.add(&sqr(&z), &z).is_zero() {
                return Some(z);
            }
        }
        None
    }

    /// The multiplicative inverse, `None` for zero.
    fn inv(&self, a: &Element) -> Option<Element> {
        if a.is_zero() {
            return None;
        }
        match (self, a) {
            (Field::Prime(p), Element::Prime(a)) => Some(Element::Prime(a.modpow(&(p - BigUint::from(2u8)), p))),
            (Field::Binary { m, poly, terms }, Element::Binary(a)) => Some(Element::Binary(a.inv_mod(*m, poly, terms))),
            _ => unreachable!("elements of one field"),
        }
    }
}

impl Element {
    fn is_zero(&self) -> bool {
        match self {
            Element::Prime(v) => *v == BigUint::from(0u8),
            Element::Binary(p) => p.degree().is_none(),
        }
    }

    /// The element as an integer (`toBigInteger`): a polynomial's coefficients as bits.
    fn integer(&self) -> BigUint {
        match self {
            Element::Prime(v) => v.clone(),
            Element::Binary(p) => BigUint::from_bytes_be(&p.to_bytes_be()),
        }
    }
}

impl Poly {
    /// Zero, with room for `bits` coefficients.
    fn zero(bits: usize) -> Poly {
        Poly(vec![0; bits.div_ceil(64)])
    }

    fn from_bytes_be(bytes: &[u8], bits: usize) -> Poly {
        let mut p = Poly::zero(bits.max(bytes.len() * 8));
        for (i, byte) in bytes.iter().rev().enumerate() {
            p.0[i / 8] |= u64::from(*byte) << (8 * (i % 8));
        }
        p
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        self.0.iter().rev().flat_map(|w| w.to_be_bytes()).collect()
    }

    fn bit(&self, i: usize) -> bool {
        self.0.get(i / 64).is_some_and(|w| w >> (i % 64) & 1 == 1)
    }

    fn flip(&mut self, i: usize) {
        if self.0.len() <= i / 64 {
            self.0.resize(i / 64 + 1, 0);
        }
        self.0[i / 64] ^= 1 << (i % 64);
    }

    fn degree(&self) -> Option<usize> {
        self.0.iter().enumerate().rev().find(|(_, w)| **w != 0).map(|(i, w)| 64 * i + 63 - w.leading_zeros() as usize)
    }

    fn xor(&self, other: &Poly) -> Poly {
        let mut out = self.0.clone();
        if out.len() < other.0.len() {
            out.resize(other.0.len(), 0);
        }
        for (o, w) in out.iter_mut().zip(&other.0) {
            *o ^= w;
        }
        Poly(out)
    }

    /// `self ^= other · x^shift`.
    fn xor_shifted(&mut self, other: &Poly, shift: usize) {
        let (words, bits) = (shift / 64, shift % 64);
        let needed = other.0.len() + words + 1;
        if self.0.len() < needed {
            self.0.resize(needed, 0);
        }
        for (i, w) in other.0.iter().enumerate() {
            self.0[i + words] ^= w << bits;
            if bits != 0 {
                self.0[i + words + 1] ^= w >> (64 - bits);
            }
        }
    }

    /// `self` reduced modulo `x^m + Σ x^t` (`terms`), trimmed to its words: each word at or above `x^m` is cleared
    /// and folded back once per term, top down, until nothing is left at or above `x^m`.
    fn reduce(mut self, m: usize, terms: &[usize]) -> Poly {
        let (mw, mb) = (m / 64, m % 64);
        while self.degree().is_some_and(|d| d >= m) {
            for j in (mw..self.0.len()).rev() {
                let high = if j == mw { self.0[j] >> mb << mb } else { self.0[j] };
                if high == 0 {
                    continue;
                }
                self.0[j] ^= high;
                for t in terms {
                    // the word's bit s lands at 64j + s - m + t
                    let at = 64 * j + t;
                    if at >= m {
                        self.xor_word_at(high, at - m);
                    } else {
                        self.xor_word_at(high >> (m - at), 0);
                    }
                }
            }
        }
        self.0.truncate(m.div_ceil(64).max(1));
        self
    }

    /// `self ^= word · x^at`.
    fn xor_word_at(&mut self, word: u64, at: usize) {
        let (i, s) = (at / 64, at % 64);
        if self.0.len() < i + 2 {
            self.0.resize(i + 2, 0);
        }
        self.0[i] ^= word << s;
        if s != 0 {
            self.0[i + 1] ^= word >> (64 - s);
        }
    }

    /// The product modulo `x^m + Σ x^t`: the left-to-right comb with a 4-bit window (Hankerson, Menezes and
    /// Vanstone, algorithm 2.36).
    fn mul_mod(&self, other: &Poly, m: usize, terms: &[usize]) -> Poly {
        let la = self.0.len();
        let mut table = vec![vec![0u64; la + 1]; 16];
        for (u, row) in table.iter_mut().enumerate().skip(1) {
            for bit in 0..4 {
                if u >> bit & 1 == 1 {
                    for (i, w) in self.0.iter().enumerate() {
                        row[i] ^= w << bit;
                        if bit != 0 {
                            row[i + 1] ^= w >> (64 - bit);
                        }
                    }
                }
            }
        }
        let mut product = vec![0u64; la + other.0.len() + 1];
        for k in (0..16).rev() {
            for (j, w) in other.0.iter().enumerate() {
                let u = (w >> (4 * k) & 15) as usize;
                if u != 0 {
                    for (i, t) in table[u].iter().enumerate() {
                        product[i + j] ^= t;
                    }
                }
            }
            if k != 0 {
                for i in (0..product.len()).rev() {
                    product[i] = product[i] << 4 | if i == 0 { 0 } else { product[i - 1] >> 60 };
                }
            }
        }
        Poly(product).reduce(m, terms)
    }

    /// The square modulo `x^m + Σ x^t`: each coefficient moves to twice its exponent.
    fn sqr_mod(&self, m: usize, terms: &[usize]) -> Poly {
        let spread = |half: u64| (0..32).fold(0u64, |acc, i| acc | (half >> i & 1) << (2 * i));
        let square = self.0.iter().flat_map(|w| [spread(w & 0xffff_ffff), spread(w >> 32)]).collect();
        Poly(square).reduce(m, terms)
    }

    /// The inverse modulo the irreducible `poly` (the extended Euclidean algorithm over GF(2)[x]); `self` is not zero.
    fn inv_mod(&self, m: usize, poly: &Poly, terms: &[usize]) -> Poly {
        let (mut u, mut v) = (self.clone().reduce(m, terms), poly.clone());
        let (mut g1, mut g2) = (Poly::from_bytes_be(&[1], m), Poly::zero(m));
        while u.degree() != Some(0) {
            let (du, dv) = (u.degree().expect("u is not zero"), v.degree().expect("v is not zero"));
            if du < dv {
                std::mem::swap(&mut u, &mut v);
                std::mem::swap(&mut g1, &mut g2);
                continue;
            }
            u.xor_shifted(&v, du - dv);
            g1.xor_shifted(&g2, du - dv);
        }
        g1.reduce(m, terms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> Vec<u8> {
        (0..n).map(|i| i.wrapping_mul(37).wrapping_add(11)).collect()
    }

    /// Every named curve signs, `r || s` of the order's length; a few small ones of each field kind also verify,
    /// in affine coordinates (probes against openssl cover the rest).
    #[test]
    fn every_named_curve_signs() {
        for (oid, _) in super::super::curves::NAMED_DOMAINS {
            let key = EcDomainKey::named(oid, &[0x12, 0x34, 0x56, 0x78, 0x9a]).expect("named curve");
            let signature = key.sign_prehash(&digest(32)).expect("signs");
            assert_eq!(signature.len(), 2 * key.n.bits().div_ceil(8), "{oid:02x?}");
        }
    }

    #[test]
    fn small_curves_verify() {
        // secp112r1, secp256k1, brainpoolP160t1, sect113r1, sect163k1, c2pnb163v1
        let oids: [&[u8]; 6] = [
            &[0x2b, 0x81, 0x04, 0x00, 0x06],
            &[0x2b, 0x81, 0x04, 0x00, 0x0a],
            &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x02],
            &[0x2b, 0x81, 0x04, 0x00, 0x04],
            &[0x2b, 0x81, 0x04, 0x00, 0x01],
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x01],
        ];
        for oid in oids {
            let key = EcDomainKey::named(oid, &[0x0f, 0xed, 0xcb, 0xa9]).unwrap();
            for hash in [32, 64] {
                let signature = key.sign_prehash(&digest(hash)).expect("signs");
                assert!(key.verify_prehash(&digest(hash), &signature), "{oid:02x?} {hash}");
                let mut wrong = digest(hash);
                wrong[0] ^= 0x80;
                assert!(!key.verify_prehash(&wrong, &signature), "{oid:02x?} {hash}");
            }
        }
    }

    /// The binary curves' Montgomery ladder agrees with affine double-and-add (sect233r1, c2tnb191v1).
    #[test]
    fn ladder_matches_affine_multiplication() {
        for oid in [&[0x2b, 0x81, 0x04, 0x00, 0x1b][..], &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x05]] {
            let key = EcDomainKey::named(oid, &[1]).unwrap();
            for k in [&[1u8][..], &[2], &[3], &[0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89]] {
                let k = BigUint::from_bytes_be(k);
                assert!(key.x_of_multiple(&k) == key.multiply(&k).map(|(x, _)| x), "{oid:02x?} {k}");
            }
        }
    }

    /// The generic cofactor check on a binary curve (c2pnb176v1, cofactor 0xff6e): the ladder's verdict on `n·P = ∞`
    /// agrees with affine double-and-add for the base, its negation and points outside the subgroup.
    #[test]
    fn binary_order_check_matches_affine_multiplication() {
        let oid = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x04];
        let key = EcDomainKey::named(&oid, &[1]).unwrap();
        let h = BigUint::from(0xff6eu32);
        let affine = |p: &(Element, Element)| {
            let at = EcDomainKey { field: key.field.clone(), a: key.a.clone(), b: key.b.clone(), g: p.clone(), n: key.n.clone(), d: BigUint::from(0u8) };
            at.multiply(&key.n).is_none()
        };
        let (mut inside, mut outside) = (0, 0);
        let mut points = vec![key.g.clone(), negate(&key, &key.g)];
        let mut x = key.g.0.integer();
        while points.len() < 12 {
            x += 1u8;
            if let Ok(Some(p)) = key.decompress(false, &x) {
                points.push(p);
            }
        }
        for p in &points {
            let verdict = key.satisfies_order(p, Some(&h));
            assert_eq!(verdict, affine(p), "{:?}", p.0.integer());
            if verdict { inside += 1 } else { outside += 1 }
        }
        assert!(inside >= 2 && outside > 0, "{inside} {outside}");
    }

    /// secp256k1's public key of d = 1 is its generator, and of d = 2 the generator doubled (a known vector).
    #[test]
    fn secp256k1_doubles_its_generator() {
        let key = EcDomainKey::named(&[0x2b, 0x81, 0x04, 0x00, 0x0a], &[2]).unwrap();
        let (x, _) = key.public_point().unwrap();
        assert_eq!(x.integer().to_bytes_be(), hex("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"));
    }

    /// sect163k1 (NIST K-163): `n·G` is the point at infinity, `(n - 1)·G` is `-G` (same x).
    #[test]
    fn sect163k1_order_annihilates_its_generator() {
        let oid = [0x2b, 0x81, 0x04, 0x00, 0x01];
        let probe = EcDomainKey::named(&oid, &[1]).unwrap();
        let n = probe.n.to_bytes_be();
        assert!(EcDomainKey::named(&oid, &n).unwrap().public_point().is_none());
        let minus_one = (&probe.n - BigUint::from(1u8)).to_bytes_be();
        let (x, y) = EcDomainKey::named(&oid, &minus_one).unwrap().public_point().unwrap();
        assert!(x == probe.g.0 && y != probe.g.1);
    }

    /// A named curve's explicit parameters with element `index` replaced.
    fn domain_with(oid: &[u8], index: usize, element: Asn1) -> Vec<Asn1> {
        let (_, text) = super::super::curves::NAMED_DOMAINS.iter().find(|(o, _)| *o == oid).unwrap();
        let mut domain = bc::sequence(&hex(text)).unwrap();
        domain[index] = element;
        domain
    }

    /// The base point `(x, y)` written compressed, with the low bit of y (prime field) or y/x (binary field) flipped
    /// when `flip`.
    fn compressed(key: &EcDomainKey, flip: bool) -> Vec<u8> {
        let (x, y) = &key.g;
        let bit = match &key.field {
            Field::Prime(_) => is_odd(&y.integer()),
            Field::Binary { .. } => is_odd(&key.field.mul(y, &key.field.inv(x).unwrap()).integer()),
        };
        let mut out = vec![if bit != flip { 0x03 } else { 0x02 }];
        out.extend(super::super::fixed_len(&x.integer().to_bytes_be(), key.field.len()).unwrap());
        out
    }

    fn negate(key: &EcDomainKey, (x, y): &(Element, Element)) -> (Element, Element) {
        match &key.field {
            Field::Prime(p) => (x.clone(), Element::Prime((p - y.integer()) % p)),
            Field::Binary { .. } => (x.clone(), key.field.add(x, y)),
        }
    }

    /// Point decompression on prime fields (secp256k1: p = 3 mod 4; secp224r1: p = 1 mod 4, Tonelli-Shanks) and
    /// binary fields (sect233k1: odd degree, the half-trace; c2pnb176v1: even degree, the randomised solver): the
    /// compressed base reads back as G, the other parity as -G, and both sign.
    #[test]
    fn compressed_bases_decompress() {
        let oids: [&[u8]; 4] = [
            &[0x2b, 0x81, 0x04, 0x00, 0x0a],
            &[0x2b, 0x81, 0x04, 0x00, 0x21],
            &[0x2b, 0x81, 0x04, 0x00, 0x1a],
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x00, 0x04],
        ];
        for oid in oids {
            let named = EcDomainKey::named(oid, &[1]).unwrap();
            assert!(named.on_curve(&named.g), "{oid:02x?}");
            for flip in [false, true] {
                let domain = domain_with(oid, 3, Asn1::OctetString("DEROctetString", compressed(&named, flip)));
                let key = EcDomainKey::read(&domain).unwrap().unwrap();
                let expected = if flip { negate(&named, &named.g) } else { named.g.clone() };
                assert!(key.g == expected, "{oid:02x?} flip {flip}");
                assert!(key.on_curve(&key.g));
                let signer = EcDomainKey::explicit(&domain, &[0x12, 0x34]).unwrap();
                assert!(signer.verify_prehash(&digest(32), &signer.sign_prehash(&digest(32)).unwrap()), "{oid:02x?}");
            }
        }
    }

    /// An x with no point is `Invalid point compression` on either field kind; out-of-field x is the field's message;
    /// a point outside the subgroup is `Invalid point`.
    #[test]
    fn compressed_bases_without_a_point() {
        for oid in [&[0x2b, 0x81, 0x04, 0x00, 0x0a][..], &[0x2b, 0x81, 0x04, 0x00, 0x21], &[0x2b, 0x81, 0x04, 0x00, 0x1a]] {
            let named = EcDomainKey::named(oid, &[1]).unwrap();
            let mut base = compressed(&named, false);
            let mut refused = 0;
            for _ in 0..8 {
                *base.last_mut().unwrap() ^= 1;
                let at = base.len() - 2;
                base[at] = base[at].wrapping_add(1);
                let domain = domain_with(oid, 3, Asn1::OctetString("DEROctetString", base.clone()));
                match EcDomainKey::read(&domain) {
                    // on sect233k1 (cofactor 4) a point outside the order-n subgroup is `Invalid point`
                    Err(m) if m == "Invalid point compression" => refused += 1,
                    Err(m) => assert!(m == "Invalid point" && oid == [0x2b, 0x81, 0x04, 0x00, 0x1a], "{oid:02x?}: {m}"),
                    Ok(key) => assert!(key.is_some_and(|k| k.on_curve(&k.g))),
                }
            }
            assert!(refused > 0, "{oid:02x?}");
        }
        let secp256k1 = [0x2b, 0x81, 0x04, 0x00, 0x0a];
        let p = EcDomainKey::named(&secp256k1, &[1]).unwrap();
        let Field::Prime(modulus) = &p.field else { unreachable!() };
        let base = [vec![0x02], modulus.to_bytes_be()].concat();
        assert_eq!(EcDomainKey::read(&domain_with(&secp256k1, 3, Asn1::OctetString("DEROctetString", base))).err().unwrap(), "x value invalid for Fp field element");
        let sect233k1 = [0x2b, 0x81, 0x04, 0x00, 0x1a];
        let wide = [vec![0x02, 0x80], vec![0; 29]].concat();
        assert_eq!(EcDomainKey::read(&domain_with(&sect233k1, 3, Asn1::OctetString("DEROctetString", wide))).err().unwrap(), "x value invalid in F2m field element");
        // (0, sqrt b) on sect233k1 has order 2, outside the cofactor-4 check
        let zero = [vec![0x02], vec![0; 30]].concat();
        assert_eq!(EcDomainKey::read(&domain_with(&sect233k1, 3, Asn1::OctetString("DEROctetString", zero))).err().unwrap(), "Invalid point");
    }

    #[test]
    fn prime_square_roots() {
        for p in [7u32, 13, 17, 41, 97, 65537] {
            let p = BigUint::from(p);
            for a in 0u32..40 {
                let a = BigUint::from(a) % &p;
                let residue = (0u32..65537).any(|x| BigUint::from(x) * BigUint::from(x) % &p == a);
                match prime_sqrt(&a, &p) {
                    Some(r) => assert!(&r * &r % &p == a),
                    None => assert!(!residue, "{a} mod {p}"),
                }
            }
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}

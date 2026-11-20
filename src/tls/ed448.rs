//! Ed448 (RFC 8032 §5.2, no context): the public key of a seed and the PureEdDSA signature, over
//! x² + y² = 1 − 39081·x²y² in projective coordinates on GF(2⁴⁴⁸ − 2²²⁴ − 1). The JDK serves a fixed server certificate's
//! Ed448 key, which ring cannot sign with. Not constant-time: the key is a test fixture's, never a secret
//! a mock server keeps from its own clients.

use num_bigint::BigUint;
use std::sync::OnceLock;

struct Curve {
    p: BigUint,
    d: BigUint,
    /// the order of the base point
    l: BigUint,
    base: Point,
}

/// (X : Y : Z), x = X/Z, y = Y/Z
#[derive(Clone)]
struct Point(BigUint, BigUint, BigUint);

fn curve() -> &'static Curve {
    static CURVE: OnceLock<Curve> = OnceLock::new();
    CURVE.get_or_init(|| {
        let p = (BigUint::from(1u8) << 448) - (BigUint::from(1u8) << 224) - 1u8;
        let d = &p - 39081u32;
        let decimal = |s: &[u8]| BigUint::parse_bytes(s, 10).expect("Ed448 constant");
        let l = (BigUint::from(1u8) << 446) - decimal(b"13818066809895115352007386748515426880336692474882178609894547503885");
        let base = Point(
            decimal(b"224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710"),
            decimal(b"298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660"),
            BigUint::from(1u8),
        );
        Curve { p, d, l, base }
    })
}

impl Point {
    /// RFC 8032 §5.2.4, addition
    fn add(&self, other: &Point, c: &Curve) -> Point {
        let p = &c.p;
        let sub = |a: &BigUint, b: &BigUint| (a + p - b) % p;
        let a = &self.2 * &other.2 % p;
        let b = &a * &a % p;
        let cc = &self.0 * &other.0 % p;
        let d = &self.1 * &other.1 % p;
        let e = &c.d * &cc % p * &d % p;
        let f = sub(&b, &e);
        let g = (&b + &e) % p;
        let h = (&self.0 + &self.1) * (&other.0 + &other.1) % p;
        let x = &a * &f % p * sub(&sub(&h, &cc), &d) % p;
        let y = &a * &g % p * sub(&d, &cc) % p;
        Point(x, y, f * g % p)
    }

    /// RFC 8032 §5.2.4, doubling
    fn double(&self, c: &Curve) -> Point {
        let p = &c.p;
        let sub = |a: &BigUint, b: &BigUint| (a + p - b) % p;
        let b = (&self.0 + &self.1) * (&self.0 + &self.1) % p;
        let cc = &self.0 * &self.0 % p;
        let d = &self.1 * &self.1 % p;
        let e = (&cc + &d) % p;
        let h = &self.2 * &self.2 % p;
        let j = sub(&e, &(&h * 2u8 % p));
        Point(sub(&b, &e) * &j % p, &e * sub(&cc, &d) % p, e * j % p)
    }

    fn times(&self, k: &BigUint, c: &Curve) -> Point {
        let mut out = Point(BigUint::from(0u8), BigUint::from(1u8), BigUint::from(1u8));
        for i in (0..k.bits()).rev() {
            out = out.double(c);
            if k.bit(i) {
                out = out.add(self, c);
            }
        }
        out
    }

    /// 57 bytes: y little-endian, x's parity in the top bit
    fn encode(&self, c: &Curve) -> Vec<u8> {
        let inverse = self.2.modpow(&(&c.p - 2u8), &c.p);
        let (x, y) = (&self.0 * &inverse % &c.p, &self.1 * &inverse % &c.p);
        let mut out = y.to_bytes_le();
        out.resize(57, 0);
        if x.bit(0) {
            out[56] |= 0x80;
        }
        out
    }
}

/// SHAKE256(seed, 114): the pruned secret scalar and the nonce prefix (RFC 8032 §5.2.5).
fn expand(seed: &[u8]) -> (BigUint, Vec<u8>) {
    let mut h = super::key_string::shake256(seed, 114);
    h[0] &= 0xfc;
    h[55] |= 0x80;
    h[56] = 0;
    (BigUint::from_bytes_le(&h[..57]), h[57..].to_vec())
}

/// The encoded public key of a 57-byte seed; `None` for another length.
pub(crate) fn public(seed: &[u8]) -> Option<Vec<u8>> {
    if seed.len() != 57 {
        return None;
    }
    let c = curve();
    Some(c.base.times(&expand(seed).0, c).encode(c))
}

/// The 114-byte Ed448 signature of `message` (RFC 8032 §5.2.6, an empty context); `None` for a seed not 57 bytes long.
pub(crate) fn sign(seed: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    if seed.len() != 57 {
        return None;
    }
    let c = curve();
    let (s, prefix) = expand(seed);
    let public = c.base.times(&s, c).encode(c);
    // dom4(0, "")
    const DOM4: &[u8] = b"SigEd448\x00\x00";
    let hash = |parts: &[&[u8]]| BigUint::from_bytes_le(&super::key_string::shake256(&parts.concat(), 114)) % &c.l;
    let r = hash(&[DOM4, &prefix, message]);
    let big_r = c.base.times(&r, c).encode(c);
    let k = hash(&[DOM4, &big_r, &public, message]);
    let mut big_s = ((r + k * s) % &c.l).to_bytes_le();
    big_s.resize(57, 0);
    Some([big_r, big_s].concat())
}

#[cfg(test)]
mod tests {
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// The fixture key `tests/files/tls/fixed-ed448-key.pem`, its public key and its signature of `abc` as OpenSSL 3.5
    /// prints them (`openssl pkey -text`, `openssl pkeyutl -sign -rawin`).
    #[test]
    fn signs_as_openssl() {
        let seed = hex("ff2b98a477b9c7b303ce74e4c12fc0ca3a0f089ddf3f9c0ae78b9e62afd4e6494d1dce9d0eb17c5fc3723ae345417d97345d8ef8f98f052de0");
        assert_eq!(super::public(&seed).unwrap(), hex("a123556327ecd8b137b3c7ce2a8182ce61399afad12317eb05026a37e0e65903ed70820d8e02173e5c0cbc26379e640f08572b280ac7b4d680"));
        let expected = "667d70cda6b967ac6122f9386fa791732de8a33d13c90f0e0eaafe28b953e7910c2c8068ad7ab8bf765eb3a2bb1428303e717c7e62b591b70033f6f9f6dc07dc2bdf36a574e435799ffddc4db456a2adc557d9e0e92c396a9fd828efd1398d508d4441cd277d6b30295f8e39e4b348ad3000";
        assert_eq!(super::sign(&seed, b"abc").unwrap(), hex(expected));
    }
}

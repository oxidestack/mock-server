//! The public halves BouncyCastle prints in a CA private key's `toString` (`key_string`) for the key types whose
//! private encoding does not carry them: X25519 and X448 (RFC 7748's ladder), ML-KEM (FIPS 203 key generation from a
//! seed, or the encapsulation key inside an expanded decapsulation key) and ML-DSA (FIPS 204 key generation from a
//! seed, or t1 recomputed from an expanded signing key's s1 and s2), and SLH-DSA (the key's last two values). Checked
//! against `tests/files/x509/tostring/ca-forms` (BouncyCastle 1.86's text).

use super::key_string::{keccak, shake256};
use num_bigint::BigUint;

/// `u`-coordinate of `k·base` on Curve25519 (`bits` 255) or Curve448 (`bits` 448), RFC 7748 §5, the scalar clamped.
fn montgomery(scalar: &[u8], len: usize, bits: u64, p: &BigUint, a24: u32, base: u32) -> Option<Vec<u8>> {
    if scalar.len() != len {
        return None;
    }
    let mut k = scalar.to_vec();
    if len == 32 {
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
    } else {
        k[0] &= 252;
        k[55] |= 128;
    }
    let k = BigUint::from_bytes_le(&k);
    let sub = |a: &BigUint, b: &BigUint| (a + p - b) % p;
    let a24 = BigUint::from(a24);
    let x1 = BigUint::from(base);
    let (mut x2, mut z2, mut x3, mut z3) = (BigUint::from(1u8), BigUint::default(), x1.clone(), BigUint::from(1u8));
    let mut swap = false;
    for t in (0..bits).rev() {
        let bit = k.bit(t);
        if swap != bit {
            std::mem::swap(&mut x2, &mut x3);
            std::mem::swap(&mut z2, &mut z3);
        }
        swap = bit;
        let a = (&x2 + &z2) % p;
        let aa = &a * &a % p;
        let b = sub(&x2, &z2);
        let bb = &b * &b % p;
        let e = sub(&aa, &bb);
        let c = (&x3 + &z3) % p;
        let d = sub(&x3, &z3);
        let da = &d * &a % p;
        let cb = &c * &b % p;
        let s = (&da + &cb) % p;
        x3 = &s * &s % p;
        let t = sub(&da, &cb);
        z3 = &x1 * (&t * &t % p) % p;
        x2 = &aa * &bb % p;
        z2 = &e * ((&aa + &a24 * &e) % p) % p;
    }
    if swap {
        std::mem::swap(&mut x2, &mut x3);
        std::mem::swap(&mut z2, &mut z3);
    }
    let u = x2 * z2.modpow(&(p - 2u8), p) % p;
    let mut out = u.to_bytes_le();
    out.resize(len, 0);
    Some(out)
}

/// The X25519 public key of a 32-byte private key.
pub(super) fn x25519_public(scalar: &[u8]) -> Option<Vec<u8>> {
    let p = (BigUint::from(1u8) << 255) - 19u8;
    montgomery(scalar, 32, 255, &p, 121665, 9)
}

/// The X448 public key of a 56-byte private key.
pub(super) fn x448_public(scalar: &[u8]) -> Option<Vec<u8>> {
    let p = (BigUint::from(1u8) << 448) - (BigUint::from(1u8) << 224) - 1u8;
    montgomery(scalar, 56, 448, &p, 39081, 5)
}

/// SHAKE128 with `out_len` bytes of output.
fn shake128(input: &[u8], out_len: usize) -> Vec<u8> {
    keccak(168, 0x1f, input, out_len)
}

fn bit_reverse(x: usize, bits: u32) -> usize {
    (0..bits).fold(0, |acc, i| acc | (((x >> i) & 1) << (bits - 1 - i)))
}

fn pow_mod(base: u64, mut exponent: u64, q: u64) -> u64 {
    let (mut result, mut base) = (1u64, base % q);
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * base % q;
        }
        base = base * base % q;
        exponent >>= 1;
    }
    result
}

/// The input of a rejection sampler grown until `accept` has taken 256 coefficients from it.
fn sample(mut out_len: usize, mut stream: impl FnMut(usize) -> Vec<u8>, mut accept: impl FnMut(&[u8]) -> Option<[i64; 256]>) -> [i64; 256] {
    loop {
        if let Some(poly) = accept(&stream(out_len)) {
            return poly;
        }
        out_len *= 2;
    }
}

// ML-KEM (FIPS 203)

const KEM_Q: u64 = 3329;

fn kem_ntt(f: &mut [i64; 256]) {
    let mut i = 1;
    let mut len = 128;
    while len >= 2 {
        for start in (0..256).step_by(2 * len) {
            let zeta = kem_zetas().0[i];
            i += 1;
            for j in start..start + len {
                let t = zeta * f[j + len] % KEM_Q as i64;
                f[j + len] = (f[j] - t).rem_euclid(KEM_Q as i64);
                f[j] = (f[j] + t) % KEM_Q as i64;
            }
        }
        len /= 2;
    }
}

/// `MultiplyNTTs` (algorithm 11), added into `acc`.
fn kem_multiply_add(acc: &mut [i64; 256], a: &[i64; 256], b: &[i64; 256]) {
    let q = KEM_Q as i64;
    for i in 0..128 {
        let gamma = kem_zetas().1[i];
        let (a0, a1, b0, b1) = (a[2 * i], a[2 * i + 1], b[2 * i], b[2 * i + 1]);
        acc[2 * i] = (acc[2 * i] + a0 * b0 % q + a1 * b1 % q * gamma) % q;
        acc[2 * i + 1] = (acc[2 * i + 1] + a0 * b1 + a1 * b0) % q;
    }
}

/// `SampleNTT` (algorithm 7) of `XOF(rho, j, i)`.
fn kem_sample_ntt(rho: &[u8], j: u8, i: u8) -> [i64; 256] {
    let seed = [rho, &[j, i]].concat();
    sample(504, |n| shake128(&seed, n), |bytes| {
        let mut poly = [0i64; 256];
        let mut count = 0;
        for c in bytes.as_chunks::<3>().0 {
            let d1 = i64::from(c[0]) + 256 * i64::from(c[1] % 16);
            let d2 = i64::from(c[1] / 16) + 16 * i64::from(c[2]);
            for d in [d1, d2] {
                if d < KEM_Q as i64 && count < 256 {
                    poly[count] = d;
                    count += 1;
                }
            }
            if count == 256 {
                return Some(poly);
            }
        }
        None
    })
}

/// `SamplePolyCBD` (algorithm 8) of `PRF_eta(sigma, n)`.
fn kem_cbd(sigma: &[u8], n: u8, eta: usize) -> [i64; 256] {
    let bytes = shake256(&[sigma, &[n]].concat(), 64 * eta);
    let bit = |i: usize| i64::from((bytes[i / 8] >> (i % 8)) & 1);
    let mut f = [0i64; 256];
    for (i, slot) in f.iter_mut().enumerate() {
        let x: i64 = (0..eta).map(|j| bit(2 * i * eta + j)).sum();
        let y: i64 = (0..eta).map(|j| bit(2 * i * eta + eta + j)).sum();
        *slot = (x - y).rem_euclid(KEM_Q as i64);
    }
    f
}

/// `ByteEncode_12` of a polynomial.
fn byte_encode_12(f: &[i64; 256]) -> Vec<u8> {
    f.chunks(2).flat_map(|p| [p[0] as u8, ((p[0] >> 8) | (p[1] << 4)) as u8, (p[1] >> 4) as u8]).collect()
}

/// The (k, eta1) of an ML-KEM parameter set by its OID.
fn kem_parameters(oid: &str) -> Option<(usize, usize)> {
    match oid {
        "2.16.840.1.101.3.4.4.1" => Some((2, 3)),
        "2.16.840.1.101.3.4.4.2" => Some((3, 2)),
        "2.16.840.1.101.3.4.4.3" => Some((4, 2)),
        _ => None,
    }
}

/// The encapsulation key of ML-KEM key generation from the seed d (`K-PKE.KeyGen`, algorithm 13).
fn kem_generate(k: usize, eta1: usize, d: &[u8]) -> Vec<u8> {
    let g = keccak(72, 0x06, &[d, &[k as u8]].concat(), 64);
    let (rho, sigma) = g.split_at(32);
    let mut s: Vec<[i64; 256]> = (0..k).map(|i| kem_cbd(sigma, i as u8, eta1)).collect();
    let mut e: Vec<[i64; 256]> = (0..k).map(|i| kem_cbd(sigma, (k + i) as u8, eta1)).collect();
    s.iter_mut().chain(e.iter_mut()).for_each(kem_ntt);
    let mut ek = Vec::new();
    for (i, e_i) in e.iter().enumerate() {
        let mut t = *e_i;
        for (j, s_j) in s.iter().enumerate() {
            kem_multiply_add(&mut t, &kem_sample_ntt(rho, j as u8, i as u8), s_j);
        }
        ek.extend(byte_encode_12(&t));
    }
    ek.extend_from_slice(rho);
    ek
}

/// The encapsulation key of an ML-KEM private key's inner encoding (`key`: OpenSSL's seed-only `[0]` seed d ‖ z, the
/// seed with the expanded key in a SEQUENCE, or the expanded decapsulation key alone) of the parameter set `oid`.
pub(super) fn mlkem_public(oid: &str, tag: u8, content: &[u8], first_item: Option<&[u8]>) -> Option<Vec<u8>> {
    let (k, eta1) = kem_parameters(oid)?;
    match tag {
        0x80 if content.len() == 64 => Some(kem_generate(k, eta1, &content[..32])),
        0x30 => {
            let seed = first_item.filter(|s| s.len() == 64)?;
            Some(kem_generate(k, eta1, &seed[..32]))
        }
        0x04 if content.len() == 768 * k + 96 => Some(content[384 * k..768 * k + 32].to_vec()),
        _ => None,
    }
}

// ML-DSA (FIPS 204)

const DSA_Q: i64 = 8380417;

fn dsa_zetas() -> &'static [i64; 256] {
    static ZETAS: std::sync::OnceLock<[i64; 256]> = std::sync::OnceLock::new();
    ZETAS.get_or_init(|| {
        let mut zetas = [0i64; 256];
        for (i, z) in zetas.iter_mut().enumerate() {
            *z = pow_mod(1753, bit_reverse(i, 8) as u64, DSA_Q as u64) as i64;
        }
        zetas
    })
}

/// ζ^BitRev7(i) and ζ^(2·BitRev7(i)+1) mod 3329 for i < 128 (ζ = 17).
fn kem_zetas() -> &'static ([i64; 128], [i64; 128]) {
    static ZETAS: std::sync::OnceLock<([i64; 128], [i64; 128])> = std::sync::OnceLock::new();
    ZETAS.get_or_init(|| {
        let (mut zetas, mut gammas) = ([0i64; 128], [0i64; 128]);
        for i in 0..128 {
            zetas[i] = pow_mod(17, bit_reverse(i, 7) as u64, KEM_Q) as i64;
            gammas[i] = pow_mod(17, 2 * bit_reverse(i, 7) as u64 + 1, KEM_Q) as i64;
        }
        (zetas, gammas)
    })
}

fn dsa_ntt(w: &mut [i64; 256]) {
    let zetas = dsa_zetas();
    let (mut m, mut len) = (0, 128);
    while len >= 1 {
        for start in (0..256).step_by(2 * len) {
            m += 1;
            let z = zetas[m];
            for j in start..start + len {
                let t = z * w[j + len] % DSA_Q;
                w[j + len] = (w[j] - t).rem_euclid(DSA_Q);
                w[j] = (w[j] + t) % DSA_Q;
            }
        }
        len /= 2;
    }
}

fn dsa_inverse_ntt(w: &mut [i64; 256]) {
    let zetas = dsa_zetas();
    let (mut m, mut len) = (256, 1);
    while len < 256 {
        for start in (0..256).step_by(2 * len) {
            m -= 1;
            let z = -zetas[m];
            for j in start..start + len {
                let t = w[j];
                w[j] = (t + w[j + len]) % DSA_Q;
                w[j + len] = (t - w[j + len]).rem_euclid(DSA_Q) * z.rem_euclid(DSA_Q) % DSA_Q;
            }
        }
        len *= 2;
    }
    let f = pow_mod(256, DSA_Q as u64 - 2, DSA_Q as u64) as i64;
    w.iter_mut().for_each(|c| *c = *c * f % DSA_Q);
}

/// (k, l, eta) of an ML-DSA parameter set by its OID.
fn dsa_parameters(oid: &str) -> Option<(usize, usize, i64)> {
    match oid {
        "2.16.840.1.101.3.4.3.17" => Some((4, 4, 2)),
        "2.16.840.1.101.3.4.3.18" => Some((6, 5, 4)),
        "2.16.840.1.101.3.4.3.19" => Some((8, 7, 2)),
        _ => None,
    }
}

/// `RejNTTPoly` (algorithm 30) of `SHAKE128(rho ‖ s ‖ r)`.
fn dsa_expand_a(rho: &[u8], s: u8, r: u8) -> [i64; 256] {
    let seed = [rho, &[s, r]].concat();
    sample(840, |n| shake128(&seed, n), |bytes| {
        let mut poly = [0i64; 256];
        let mut count = 0;
        for c in bytes.as_chunks::<3>().0 {
            let z = i64::from(c[0]) + 256 * i64::from(c[1]) + 65536 * i64::from(c[2] & 0x7f);
            if z < DSA_Q {
                poly[count] = z;
                count += 1;
                if count == 256 {
                    return Some(poly);
                }
            }
        }
        None
    })
}

/// `RejBoundedPoly` (algorithm 31) of `SHAKE256(rho' ‖ r)`.
fn dsa_bounded(rho_prime: &[u8], r: u16, eta: i64) -> [i64; 256] {
    let seed = [rho_prime, &r.to_le_bytes()].concat();
    sample(1088, |n| shake256(&seed, n), |bytes| {
        let mut poly = [0i64; 256];
        let mut count = 0;
        for byte in bytes {
            for half in [i64::from(byte & 15), i64::from(byte >> 4)] {
                let coefficient = match eta {
                    2 if half < 15 => Some(2 - half % 5),
                    4 if half < 9 => Some(4 - half),
                    _ => None,
                };
                if let Some(c) = coefficient && count < 256 {
                    poly[count] = c.rem_euclid(DSA_Q);
                    count += 1;
                }
            }
            if count == 256 {
                return Some(poly);
            }
        }
        None
    })
}

/// The public key rho ‖ SimpleBitPack(t1, 10) for `t = A·s1 + s2` (key generation, algorithm 6, steps 5-8).
fn dsa_public(k: usize, l: usize, rho: &[u8], s1: &[[i64; 256]], s2: &[[i64; 256]]) -> Vec<u8> {
    let s1_hat: Vec<[i64; 256]> = s1.iter().map(|p| { let mut p = *p; dsa_ntt(&mut p); p }).collect();
    let mut out = rho.to_vec();
    for (r, s2_r) in s2.iter().enumerate().take(k) {
        let mut acc = [0i64; 256];
        for (s, s1_s) in s1_hat.iter().enumerate().take(l) {
            let a = dsa_expand_a(rho, s as u8, r as u8);
            for n in 0..256 {
                acc[n] = (acc[n] + a[n] * s1_s[n]) % DSA_Q;
            }
        }
        dsa_inverse_ntt(&mut acc);
        let mut bits = Vec::with_capacity(2560);
        for n in 0..256 {
            let t = (acc[n] + s2_r[n]) % DSA_Q;
            let mut low = t & 8191;
            if low > 4096 {
                low -= 8192;
            }
            let t1 = (t - low) >> 13;
            bits.extend((0..10).map(|b| ((t1 >> b) & 1) as u8));
        }
        out.extend(bits.chunks(8).map(|c| c.iter().enumerate().fold(0u8, |byte, (i, b)| byte | (b << i))));
    }
    out
}

/// The public key of an ML-DSA private key's inner encoding (OpenSSL's seed-only `[0]` seed, the seed with the
/// expanded key in a SEQUENCE, or the expanded key alone) of the parameter set `oid`.
pub(super) fn mldsa_public(oid: &str, tag: u8, content: &[u8], first_item: Option<&[u8]>) -> Option<Vec<u8>> {
    let (k, l, eta) = dsa_parameters(oid)?;
    let from_seed = |xi: &[u8]| -> Option<Vec<u8>> {
        if xi.len() != 32 {
            return None;
        }
        let h = shake256(&[xi, &[k as u8, l as u8]].concat(), 128);
        let (rho, rho_prime) = (&h[..32], &h[32..96]);
        let s1: Vec<_> = (0..l).map(|r| dsa_bounded(rho_prime, r as u16, eta)).collect();
        let s2: Vec<_> = (0..k).map(|r| dsa_bounded(rho_prime, (l + r) as u16, eta)).collect();
        Some(dsa_public(k, l, rho, &s1, &s2))
    };
    match tag {
        0x80 => from_seed(content),
        0x30 => from_seed(first_item?),
        0x04 => {
            let width = if eta == 2 { 3 } else { 4 };
            let poly_len = 32 * width;
            if content.len() != 128 + (k + l) * poly_len + k * 416 {
                return None;
            }
            let unpack = |bytes: &[u8]| -> [i64; 256] {
                let mut poly = [0i64; 256];
                for (n, slot) in poly.iter_mut().enumerate() {
                    let v = (0..width).fold(0i64, |v, b| {
                        let bit = n * width + b;
                        v | (i64::from((bytes[bit / 8] >> (bit % 8)) & 1) << b)
                    });
                    *slot = (eta - v).rem_euclid(DSA_Q);
                }
                poly
            };
            let body = &content[128..];
            let s1: Vec<_> = (0..l).map(|i| unpack(&body[i * poly_len..(i + 1) * poly_len])).collect();
            let s2: Vec<_> = (0..k).map(|i| unpack(&body[(l + i) * poly_len..(l + i + 1) * poly_len])).collect();
            Some(dsa_public(k, l, &content[..32], &s1, &s2))
        }
        _ => None,
    }
}

/// The pure parameter set whose keys a HashML-DSA (`.32`-`.34`) or HashSLH-DSA (`.35`-`.46`) OID carries, and the
/// pre-hash digest BouncyCastle names after `-WITH-` (`ML-DSA-44-WITH-SHA512`).
pub(super) fn pre_hash(oid: &str) -> Option<(String, &'static str)> {
    let n: u8 = oid.strip_prefix("2.16.840.1.101.3.4.3.")?.parse().ok()?;
    let digest = match n {
        35 | 36 => "SHA256",
        32..=34 | 37..=40 => "SHA512",
        41 | 42 => "SHAKE128",
        43..=46 => "SHAKE256",
        _ => return None,
    };
    Some((format!("2.16.840.1.101.3.4.3.{}", n - 15), digest))
}

/// The name BouncyCastle prints for an SLH-DSA parameter set (`SLH-DSA-SHA2-128S`) and its public key's length.
pub(super) fn slh_dsa(oid: &str) -> Option<(&'static str, usize)> {
    const NAMES: [(&str, usize); 12] = [
        ("SLH-DSA-SHA2-128S", 32), ("SLH-DSA-SHA2-128F", 32), ("SLH-DSA-SHA2-192S", 48), ("SLH-DSA-SHA2-192F", 48),
        ("SLH-DSA-SHA2-256S", 64), ("SLH-DSA-SHA2-256F", 64), ("SLH-DSA-SHAKE-128S", 32), ("SLH-DSA-SHAKE-128F", 32),
        ("SLH-DSA-SHAKE-192S", 48), ("SLH-DSA-SHAKE-192F", 48), ("SLH-DSA-SHAKE-256S", 64), ("SLH-DSA-SHAKE-256F", 64),
    ];
    let n: usize = oid.strip_prefix("2.16.840.1.101.3.4.3.")?.parse().ok()?;
    NAMES.get(n.checked_sub(20)?).copied()
}

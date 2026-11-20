//! ML-KEM (FIPS 203) as far as BouncyCastle's `MLKEMPrivateKeyParameters` reads a key: the decapsulation key a
//! 64-byte seed `d || z` expands to (`ML-KEM.KeyGen_internal`), and the expanded key's hash check
//! (`MLKEMEngine.checkPrivateKey`). Nothing is encapsulated or decapsulated.

use crate::tls::key_string::keccak;

const Q: u32 = 3329;
const N: usize = 256;

fn sha3_256(input: &[u8]) -> Vec<u8> {
    keccak(136, 0x06, input, 32)
}

fn sha3_512(input: &[u8]) -> Vec<u8> {
    keccak(72, 0x06, input, 64)
}

/// 7-bit bit reversal.
fn bit_rev7(i: usize) -> u32 {
    (i as u8).reverse_bits() as u32 >> 1
}

fn pow_mod(base: u32, mut exp: u32) -> u32 {
    let (mut result, mut base) = (1u64, u64::from(base));
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % u64::from(Q);
        }
        base = base * base % u64::from(Q);
        exp >>= 1;
    }
    result as u32
}

type Poly = [u32; N];

/// `SampleNTT` over SHAKE128 of `rho || j || i`.
fn sample_ntt(rho: &[u8], j: u8, i: u8) -> Poly {
    let input = [rho, &[j, i]].concat();
    // 3 * 256 candidates are nearly always enough; the stream is extended until the polynomial is full
    let mut len = 168 * 5;
    loop {
        let stream = keccak(168, 0x1f, &input, len);
        let mut poly = [0u32; N];
        let mut count = 0;
        for c in stream.as_chunks::<3>().0 {
            let d1 = u32::from(c[0]) + 256 * (u32::from(c[1]) & 0x0f);
            let d2 = (u32::from(c[1]) >> 4) + 16 * u32::from(c[2]);
            for d in [d1, d2] {
                if d < Q && count < N {
                    poly[count] = d;
                    count += 1;
                }
            }
            if count == N {
                return poly;
            }
        }
        len *= 2;
    }
}

/// `SamplePolyCBD_eta` of `PRF_eta(sigma, n)` (SHAKE256).
fn sample_cbd(sigma: &[u8], n: u8, eta: usize) -> Poly {
    let bytes = keccak(136, 0x1f, &[sigma, &[n]].concat(), 64 * eta);
    let bit = |k: usize| u32::from((bytes[k / 8] >> (k % 8)) & 1);
    let mut poly = [0u32; N];
    for (i, coefficient) in poly.iter_mut().enumerate() {
        let x: u32 = (0..eta).map(|j| bit(2 * i * eta + j)).sum();
        let y: u32 = (0..eta).map(|j| bit(2 * i * eta + eta + j)).sum();
        *coefficient = (x + Q - y) % Q;
    }
    poly
}

fn ntt(f: &mut Poly) {
    let mut i = 1;
    let mut len = 128;
    while len >= 2 {
        for start in (0..N).step_by(2 * len) {
            let zeta = pow_mod(17, bit_rev7(i));
            i += 1;
            for j in start..start + len {
                let t = zeta * f[j + len] % Q;
                f[j + len] = (f[j] + Q - t) % Q;
                f[j] = (f[j] + t) % Q;
            }
        }
        len /= 2;
    }
}

/// `MultiplyNTTs`.
fn multiply(f: &Poly, g: &Poly) -> Poly {
    let mut h = [0u32; N];
    for i in 0..128 {
        let gamma = pow_mod(17, 2 * bit_rev7(i) + 1);
        let (a0, a1, b0, b1) = (f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]);
        h[2 * i] = (a0 * b0 % Q + a1 * b1 % Q * gamma) % Q;
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q;
    }
    h
}

/// `ByteEncode_12`.
fn encode12(poly: &Poly, out: &mut Vec<u8>) {
    for pair in poly.as_chunks::<2>().0 {
        let (a, b) = (pair[0], pair[1]);
        out.extend_from_slice(&[a as u8, ((a >> 8) | (b << 4)) as u8, (b >> 4) as u8]);
    }
}

/// The parameter set's `k` and `eta1`.
fn parameters(k: usize) -> usize {
    if k == 2 { 3 } else { 2 }
}

/// `ML-KEM.KeyGen_internal(d, z)`: the decapsulation key `dk_pke || ek || H(ek) || z`.
pub(super) fn expand(k: usize, seed: &[u8]) -> Vec<u8> {
    let (d, z) = seed.split_at(32);
    let g = sha3_512(&[d, &[k as u8]].concat());
    let (rho, sigma) = g.split_at(32);
    let eta1 = parameters(k);
    let mut n = 0u8;
    let mut noise = || {
        let mut poly = sample_cbd(sigma, n, eta1);
        n += 1;
        ntt(&mut poly);
        poly
    };
    let s: Vec<Poly> = (0..k).map(|_| noise()).collect();
    let e: Vec<Poly> = (0..k).map(|_| noise()).collect();
    let mut ek = Vec::with_capacity(384 * k + 32);
    for (i, e_i) in e.iter().enumerate() {
        let mut t = *e_i;
        for (j, s_j) in s.iter().enumerate() {
            let product = multiply(&sample_ntt(rho, j as u8, i as u8), s_j);
            for (c, p) in t.iter_mut().zip(product) {
                *c = (*c + p) % Q;
            }
        }
        encode12(&t, &mut ek);
    }
    ek.extend_from_slice(rho);
    let mut dk = Vec::with_capacity(768 * k + 96);
    for s_i in &s {
        encode12(s_i, &mut dk);
    }
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&sha3_256(&ek));
    dk.extend_from_slice(z);
    dk
}

/// `MLKEMEngine.checkPrivateKey` of an expanded key of the right length: `H(ek)` is the hash it carries.
pub(super) fn hash_check(k: usize, dk: &[u8]) -> bool {
    let (k384, k768) = (384 * k, 768 * k);
    sha3_256(&dk[k384..k768 + 32]) == dk[k768 + 32..k768 + 64]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Seeds and the SHA3-256 of the expanded keys OpenSSL 3.5 wrote for them (`genpkey -algorithm ML-KEM-*`).
    #[test]
    fn seeds_expand_as_openssl_expands_them() {
        for (k, seed, digest, len) in [
            (2, "b9362b5a1552c212ede258a81f2a24169aa78e58e1585b8739fa2c600557dd40137b8266dd2d978f35d238d67837d6c7ac111f407663f5e02392c6644e42c78d", "48b95d59cc4e9f34ed4c233cd7ed2718769119e7a4458ea7fd306b94b97033a8", 1632),
            (3, "4f5f49aa5885293f1359f5cbed5e9c584fcff762368c636180f550290e90ef384e8cc02f56948ef9b86f51086d021b414516553a4cd35b9b96ed5a4973b6acd2", "3abc20bf8eddea95d55ba38b36ec27efaf3589ad590acf7ec42115b20b241eec", 2400),
            (4, "b241083d5eaa3ef1728b3276da510c481fc79cc7e3f8d312e7a167ab792afa3d3a77756d19b832028fdd248ed9639af5e9773e0a9b3a74ea01a89b53aa7b7349", "d036c53a81964c4b05f824b411c97459d4337c8b2f7952f8b8f5fff662b6e596", 3168),
        ] {
            let dk = expand(k, &hex(seed));
            assert_eq!(dk.len(), len);
            assert_eq!(sha3_256(&dk), hex(digest), "k = {k}");
            assert!(hash_check(k, &dk));
            let mut bad = dk.clone();
            bad[384 * k + 5] ^= 1;
            assert!(!hash_check(k, &bad));
        }
    }
}

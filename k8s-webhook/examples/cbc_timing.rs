//! Timing measurement of the CBC record layer's decryption (`src/cbc.rs`): a dudect-style test
//! (Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?", 2017). Two classes of records of the same public
//! length are opened in random interleaved order, each call timed on its own; Welch's t-test compares the classes'
//! times. |t| > 4.5 is a timing leak, |t| < 4.5 means none was seen at this sample count (not a proof).
//!
//! Run on a release build, on a quiet machine:
//!   cargo run --release -p mock-server-k8s-webhook --example cbc_timing
//! Environment: `CBC_TIMING_SAMPLES` (samples per class and test, default 1000000), `CBC_TIMING_ONLY` (substring of a
//! test's name), `CBC_TIMING_SEED` (the order of the classes).
//!
//! Each test reports |t| over all samples (raw), the largest |t| over time-cropped sets (samples above the 90/95/99th
//! percentile of the pooled times dropped, as dudect does against outliers), and |t| of each half of the run (a real
//! leak shows in both halves with the same sign). The positive control times the `hmac` crate's variable-time MAC on
//! the same two data lengths; the harness must flag it.

use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use k8s_webhook::cbc::{AES_128_CBC_SHA, AES_128_CBC_SHA256, AES_256_CBC_SHA256, AesCbc};
use rustls::crypto::cipher::{InboundOpaqueMessage, make_tls12_aad};
use rustls::{ContentType, ProtocolVersion};
use std::hint::black_box;
use std::time::Instant;

const BLOCK: usize = 16;
/// Plaintext length of every record (data, MAC, padding): public and the same in both classes.
const PLAIN: usize = 2048;
const POOL: usize = 512;
const SEQ: u64 = 7;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn fill(&mut self, out: &mut [u8]) {
        for b in out {
            *b = (self.next() >> 32) as u8;
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    /// valid MAC, valid padding of this many bytes (1..=256)
    Valid(usize),
    /// valid MAC over the data the padding length implies, but the padding bytes are wrong
    BadPadding,
    /// valid padding of this many bytes, wrong MAC
    BadMac(usize),
    /// random plaintext whose last byte is this value: the MAC is wrong; the padding is valid only for 0 (almost surely)
    BadLast(u8),
}

struct Keys {
    alg: &'static AesCbc,
    mac_len: usize,
    mac_key: Vec<u8>,
    aes_key: Vec<u8>,
}

fn record(keys: &Keys, kind: Kind, rng: &mut Rng) -> Vec<u8> {
    if let Kind::BadLast(b) = kind {
        let mut plain = vec![0u8; PLAIN];
        rng.fill(&mut plain);
        plain[PLAIN - 1] = b;
        return encrypt(keys, &plain, rng);
    }
    let pad = match kind {
        Kind::Valid(p) | Kind::BadMac(p) => p,
        Kind::BadLast(_) => unreachable!(),
        // a plausible length, so the data and MAC are what a sender with that padding would have produced
        Kind::BadPadding => 1 + (rng.next() % 256) as usize,
    };
    let data_len = PLAIN - keys.mac_len - pad;
    let mut data = vec![0u8; data_len];
    rng.fill(&mut data);
    let aad = make_tls12_aad(SEQ, ContentType::ApplicationData, ProtocolVersion::TLSv1_2, data_len);
    let mut mac = keys.alg.reference_mac(&keys.mac_key, &aad, &data);
    if matches!(kind, Kind::BadMac(_)) {
        let at = (rng.next() % mac.len() as u64) as usize;
        mac[at] ^= 1 << (rng.next() % 8);
    }
    let mut plain = data;
    plain.extend_from_slice(&mac);
    plain.extend(std::iter::repeat_n((pad - 1) as u8, pad));
    if matches!(kind, Kind::BadPadding) {
        // the last byte stays, one byte before the end of the padding run differs (or, for padding 1, the last byte is
        // made to claim more padding than the bytes before it carry)
        let n = plain.len();
        if pad > 1 {
            plain[n - 2] ^= 0x55;
        } else {
            plain[n - 1] = 0xff;
        }
    }
    assert_eq!(plain.len(), PLAIN);

    encrypt(keys, &plain, rng)
}

/// CBC-encrypt a whole-block plaintext under a fresh random IV; the IV leads the record.
fn encrypt(keys: &Keys, plain: &[u8], rng: &mut Rng) -> Vec<u8> {
    let c128 = (keys.aes_key.len() == 16).then(|| Aes128::new_from_slice(&keys.aes_key).expect("16 bytes"));
    let c256 = (keys.aes_key.len() == 32).then(|| Aes256::new_from_slice(&keys.aes_key).expect("32 bytes"));
    let mut iv = [0u8; BLOCK];
    rng.fill(&mut iv);
    let mut wire = iv.to_vec();
    let mut previous = iv;
    for chunk in plain.chunks_exact(BLOCK) {
        let mut block = [0u8; BLOCK];
        for i in 0..BLOCK {
            block[i] = chunk[i] ^ previous[i];
        }
        let mut b = Array::from(block);
        match (&c128, &c256) {
            (Some(c), _) => c.encrypt_block(&mut b),
            (_, Some(c)) => c.encrypt_block(&mut b),
            _ => unreachable!(),
        }
        block.copy_from_slice(&b);
        wire.extend_from_slice(&block);
        previous = block;
    }
    wire
}

/// Welch's t of two sample sets.
fn welch(a: &[f64], b: &[f64]) -> f64 {
    fn mv(x: &[f64]) -> (f64, f64) {
        let n = x.len() as f64;
        let m = x.iter().sum::<f64>() / n;
        let v = x.iter().map(|v| (v - m) * (v - m)).sum::<f64>() / (n - 1.0);
        (m, v)
    }
    if a.len() < 2 || b.len() < 2 {
        return 0.0;
    }
    let (ma, va) = mv(a);
    let (mb, vb) = mv(b);
    (ma - mb) / (va / a.len() as f64 + vb / b.len() as f64).sqrt()
}

struct Report {
    raw: f64,
    cropped: f64,
    cropped_at: &'static str,
    half1: f64,
    half2: f64,
    mean0: f64,
    mean1: f64,
    n0: usize,
    n1: usize,
    /// per class: 10th percentile, median, 90th percentile, ns
    q0: [f64; 3],
    q1: [f64; 3],
    /// difference of the class means over the samples at or below the cropping cut, ns
    crop_diff: f64,
}

/// `run(class)` performs one operation of the class; samples are taken in a random interleaved order.
fn measure(samples_per_class: usize, mut run: impl FnMut(usize)) -> Report {
    let seed: u64 = std::env::var("CBC_TIMING_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    let mut rng = Rng(0x9E3779B97F4A7C15 ^ seed.wrapping_mul(0x1234567));
    let mut times: [Vec<(u32, f64)>; 2] = [Vec::with_capacity(samples_per_class), Vec::with_capacity(samples_per_class)];
    // warm up both classes
    for i in 0..20_000 {
        run(i & 1);
    }
    let mut seen = 0usize;
    let total = samples_per_class * 2;
    let mut left = [samples_per_class, samples_per_class];
    while seen < total {
        let mut class = (rng.next() >> 40) as usize & 1;
        if left[class] == 0 {
            class ^= 1;
        }
        left[class] -= 1;
        let t0 = Instant::now();
        run(class);
        let dt = t0.elapsed().as_nanos() as f64;
        times[class].push((seen as u32, dt));
        seen += 1;
    }
    let all = |c: usize| -> Vec<f64> { times[c].iter().map(|x| x.1).collect() };
    let (a, b) = (all(0), all(1));
    let raw = welch(&a, &b);
    let mut pooled: Vec<f64> = a.iter().chain(b.iter()).copied().collect();
    pooled.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let mut cropped = 0.0f64;
    let mut cropped_at = "raw";
    let mut crop_diff = 0.0f64;
    for (label, q) in [("p99", 0.99), ("p95", 0.95), ("p90", 0.90)] {
        let cut = pooled[((pooled.len() - 1) as f64 * q) as usize];
        let ca: Vec<f64> = a.iter().copied().filter(|v| *v <= cut).collect();
        let cb: Vec<f64> = b.iter().copied().filter(|v| *v <= cut).collect();
        let t = welch(&ca, &cb);
        if t.abs() > cropped.abs() {
            cropped = t;
            cropped_at = label;
            crop_diff = ca.iter().sum::<f64>() / ca.len() as f64 - cb.iter().sum::<f64>() / cb.len() as f64;
        }
    }
    let half = |lo: u32, hi: u32| {
        let pick = |c: usize| -> Vec<f64> { times[c].iter().filter(|x| x.0 >= lo && x.0 < hi).map(|x| x.1).collect() };
        welch(&pick(0), &pick(1))
    };
    let mid = (total / 2) as u32;
    Report {
        raw,
        cropped,
        cropped_at,
        half1: half(0, mid),
        half2: half(mid, total as u32),
        mean0: a.iter().sum::<f64>() / a.len() as f64,
        mean1: b.iter().sum::<f64>() / b.len() as f64,
        n0: a.len(),
        n1: b.len(),
        q0: quantiles(&a),
        q1: quantiles(&b),
        crop_diff,
    }
}

fn quantiles(x: &[f64]) -> [f64; 3] {
    let mut v = x.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    [0.1, 0.5, 0.9].map(|q| v[((v.len() - 1) as f64 * q) as usize])
}

fn print(name: &str, r: &Report) {
    let worst = r.raw.abs().max(r.cropped.abs());
    let verdict = if worst > 4.5 { "LEAK (|t| > 4.5)" } else { "no leak seen" };
    println!(
        "{name:<58} n={}+{}  mean {:>9.1} / {:>9.1} ns  t_raw {:>8.2}  t_crop({}) {:>8.2}  halves {:>7.2} {:>7.2}  {verdict}",
        r.n0, r.n1, r.mean0, r.mean1, r.raw, r.cropped_at, r.cropped, r.half1, r.half2
    );
    println!(
        "    p10/p50/p90 class0 {:.0}/{:.0}/{:.0} ns, class1 {:.0}/{:.0}/{:.0} ns; cropped-mean diff {:.1} ns",
        r.q0[0], r.q0[1], r.q0[2], r.q1[0], r.q1[1], r.q1[2], r.crop_diff
    );
}


/// Stage copies of `Decrypter::decrypt`'s steps (src/cbc.rs), each timed alone on the same two pools (CBC_TIMING_STAGES=1):
/// the AES-CBC pass, the padding check, the tag select, `constant_time_mac`. The bodies are copied from cbc.rs.
mod stages {
    use super::*;
    use aes::cipher::BlockCipherDecrypt;
    use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};

    /// the AES pass alone: decrypt every block, keep nothing (no XOR, no store into the record)
    pub fn aes_only(c: &Aes128, payload: &[u8]) -> u8 {
        let mut acc = 0u8;
        for i in (1..payload.len() / BLOCK).rev() {
            let mut b = Array::from(<[u8; BLOCK]>::try_from(&payload[i * BLOCK..(i + 1) * BLOCK]).expect("block"));
            c.decrypt_block(&mut b);
            acc ^= b[0];
        }
        acc
    }

    /// the XOR-with-previous-ciphertext and store pass alone, over already decrypted blocks `raw`
    pub fn xor_store(raw: &[u8], wire: &[u8], out: &mut [u8]) {
        for i in (1..raw.len() / BLOCK).rev() {
            for j in 0..BLOCK {
                out[i * BLOCK + j] = raw[i * BLOCK + j] ^ wire[(i - 1) * BLOCK + j];
            }
        }
    }

    /// the same pass out of place: read the ciphertext from `wire`, write the plaintext to `out`
    pub fn aes_cbc_oop(c: &Aes128, wire: &[u8], out: &mut [u8]) {
        for i in (1..wire.len() / BLOCK).rev() {
            let mut b = Array::from(<[u8; BLOCK]>::try_from(&wire[i * BLOCK..(i + 1) * BLOCK]).expect("block"));
            c.decrypt_block(&mut b);
            for j in 0..BLOCK {
                out[i * BLOCK + j] = b[j] ^ wire[(i - 1) * BLOCK + j];
            }
        }
    }

    pub fn aes_cbc(c: &Aes128, payload: &mut [u8]) {
        let total = payload.len();
        for i in (1..total / BLOCK).rev() {
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(&payload[i * BLOCK..(i + 1) * BLOCK]);
            let mut b = Array::from(block);
            c.decrypt_block(&mut b);
            block.copy_from_slice(&b);
            for j in 0..BLOCK {
                block[j] ^= payload[(i - 1) * BLOCK + j];
            }
            payload[i * BLOCK..(i + 1) * BLOCK].copy_from_slice(&block);
        }
    }

    /// returns the `padding` of cbc.rs
    pub fn padding_check(plain: &[u8], mac_len: usize) -> usize {
        let n = plain.len();
        let last = plain[n - 1];
        let fits = (last as u32 + 1 + mac_len as u32).ct_lt(&(n as u32 + 1));
        let mut good = fits;
        for i in 0..n.min(256) {
            let in_padding = (i as u32).ct_lt(&(last as u32 + 1));
            let same = plain[n - 1 - i].ct_eq(&last);
            good &= !in_padding | same;
        }
        u32::conditional_select(&0, &(last as u32 + 1), good) as usize
    }

    pub fn tag_select(plain: &[u8], mac_len: usize, data_len: usize) -> Vec<u8> {
        let n = plain.len();
        let mut received = vec![0u8; mac_len];
        for i in n.saturating_sub(mac_len + 256)..n {
            for (j, byte) in received.iter_mut().enumerate() {
                let here = (i as u32).ct_eq(&((data_len + j) as u32));
                *byte = u8::conditional_select(byte, &plain[i], here);
            }
        }
        received
    }

    pub fn tag_ct_eq(a: &[u8], b: &[u8]) -> Choice {
        a.ct_eq(b)
    }
}

fn run_stages(samples: usize, rng: &mut Rng) {
    use aes::cipher::BlockCipherDecrypt;
    let (mac_len, alg) = (20usize, &AES_128_CBC_SHA);
    let keys = Keys { alg, mac_len, mac_key: vec![0x5a; mac_len], aes_key: vec![0xa5; 16] };
    let c = Aes128::new_from_slice(&keys.aes_key).expect("16 bytes");
    let kinds = [("valid", [Kind::Valid(1), Kind::Valid(256)]), ("badmac", [Kind::BadMac(1), Kind::BadMac(256)])];
    for (kl, [k0, k1]) in kinds {
        let wire: [Vec<Vec<u8>>; 2] = [(0..POOL).map(|_| record(&keys, k0, rng)).collect(), (0..POOL).map(|_| record(&keys, k1, rng)).collect()];
        // decrypted pools for the stages after the AES pass
        let dec: [Vec<Vec<u8>>; 2] = std::array::from_fn(|c_| {
            wire[c_].iter().map(|w| { let mut b = w.clone(); stages::aes_cbc(&c, &mut b); b[BLOCK..].to_vec() }).collect()
        });
        // the raw AES-decrypt outputs (before the XOR with the previous ciphertext block)
        let raw: [Vec<Vec<u8>>; 2] = std::array::from_fn(|c_| {
            wire[c_].iter().map(|w| {
                let mut o = vec![0u8; w.len()];
                for i in 1..w.len() / BLOCK {
                    let mut b = Array::from(<[u8; BLOCK]>::try_from(&w[i * BLOCK..(i + 1) * BLOCK]).expect("block"));
                    c.decrypt_block(&mut b);
                    o[i * BLOCK..(i + 1) * BLOCK].copy_from_slice(&b);
                }
                o
            }).collect()
        });
        let pad = [1usize, 256];
        let aad = make_tls12_aad(SEQ, ContentType::ApplicationData, ProtocolVersion::TLSv1_2, 0);
        let mut buf = vec![0u8; wire[0][0].len()];
        let mut idx = [0usize; 2];
        let mut report = |name: &str, f: &mut dyn FnMut(usize, usize)| {
            let r = measure(samples, |cl| {
                idx[cl] = (idx[cl] + 1) % POOL;
                f(cl, idx[cl]);
            });
            print(&format!("STAGE {kl} pad1 vs pad256: {name}"), &r);
        };
        report("aes_cbc (copy + decrypt)", &mut |cl, i| {
            buf.copy_from_slice(&wire[cl][i]);
            stages::aes_cbc(&c, &mut buf);
            black_box(&buf);
        });
        let mut out = vec![0u8; wire[0][0].len()];
        report("aes_cbc_oop (out of place, no initial copy)", &mut |cl, i| {
            stages::aes_cbc_oop(&c, &wire[cl][i], &mut out);
            black_box(&out);
        });
        report("aes_only (decrypt_block, nothing stored)", &mut |cl, i| {
            black_box(stages::aes_only(&c, &wire[cl][i]));
        });
        report("xor_store (XOR + store, AES output precomputed)", &mut |cl, i| {
            stages::xor_store(&raw[cl][i], &wire[cl][i], &mut buf);
            black_box(&buf);
        });
        report("padding_check", &mut |cl, i| {
            black_box(stages::padding_check(&dec[cl][i], mac_len));
        });
        report("tag_select", &mut |cl, i| {
            let n = dec[cl][i].len();
            black_box(stages::tag_select(&dec[cl][i], mac_len, n - mac_len - pad[cl]));
        });
        report("tag_ct_eq", &mut |cl, i| {
            let n = dec[cl][i].len();
            black_box(stages::tag_ct_eq(&dec[cl][i][n - 20..], &dec[cl][i][n - 40..n - 20]));
        });
        report("constant_time_mac (data from decrypted record)", &mut |cl, i| {
            let n = dec[cl][i].len();
            black_box(alg.constant_time_mac(&keys.mac_key, &aad, &dec[cl][i][..n - mac_len], n - mac_len - pad[cl]));
        });
    }
}

fn main() {
    let samples: usize = std::env::var("CBC_TIMING_SAMPLES").ok().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let only = std::env::var("CBC_TIMING_ONLY").unwrap_or_default();
    println!("cbc_timing: {samples} samples per class per test, plaintext {PLAIN} bytes, pool {POOL} records per class");
    let mut rng = Rng(0xDEADBEEFCAFEF00D);
    if std::env::var("CBC_TIMING_STAGES").is_ok() {
        run_stages(samples, &mut rng);
        return;
    }

    let suites: [(&str, &'static AesCbc, usize); 3] =
        [("AES128-SHA", &AES_128_CBC_SHA, 20), ("AES128-SHA256", &AES_128_CBC_SHA256, 32), ("AES256-SHA256", &AES_256_CBC_SHA256, 32)];
    let mut pairs: Vec<(String, Kind, Kind)> = [
        // null tests: two pools of the same kind; any |t| here is the harness's own artefact (pools, cache, cropping)
        ("NULL valid pad 1 vs valid pad 1", Kind::Valid(1), Kind::Valid(1)),
        ("NULL valid pad 256 vs valid pad 256", Kind::Valid(256), Kind::Valid(256)),
        ("valid pad 1 vs valid pad 256", Kind::Valid(1), Kind::Valid(256)),
        ("valid pad 1 vs valid pad 17", Kind::Valid(1), Kind::Valid(17)),
        ("valid pad 1 vs valid pad 64", Kind::Valid(1), Kind::Valid(64)),
        ("valid pad 16 vs valid pad 128", Kind::Valid(16), Kind::Valid(128)),
        ("valid pad 1 vs bad padding", Kind::Valid(1), Kind::BadPadding),
        ("valid pad 256 vs bad padding", Kind::Valid(256), Kind::BadPadding),
        ("valid pad 1 vs bad MAC (pad 1)", Kind::Valid(1), Kind::BadMac(1)),
        ("bad MAC (pad 256) vs bad padding", Kind::BadMac(256), Kind::BadPadding),
        ("LAST-BYTE 0 (valid pad, bad MAC) vs 255", Kind::BadLast(0), Kind::BadLast(255)),
        ("LAST-BYTE 0 (valid pad, bad MAC) vs 100", Kind::BadLast(0), Kind::BadLast(100)),
        ("LAST-BYTE 100 vs 255 (both bad padding)", Kind::BadLast(100), Kind::BadLast(255)),
        ("LAST-BYTE 100 vs 200 (both bad padding)", Kind::BadLast(100), Kind::BadLast(200)),
        ("LAST-BYTE 100 vs 252 (both bad padding)", Kind::BadLast(100), Kind::BadLast(252)),
    ]
    .into_iter()
    .map(|(l, a, b)| (l.to_string(), a, b))
    .collect();
    // CBC_TIMING_SWEEP=2,16,255,256: only valid padding 1 against each of these
    if let Ok(list) = std::env::var("CBC_TIMING_SWEEP") {
        // CBC_TIMING_SWEEP_KIND=badmac: the same sweep with a WRONG MAC in both classes (what a chosen-ciphertext attacker sees)
        let bad = std::env::var("CBC_TIMING_SWEEP_KIND").map(|k| k == "badmac").unwrap_or(false);
        pairs = list
            .split(',')
            .filter_map(|p| p.parse::<usize>().ok())
            .map(|p| {
                if bad {
                    (format!("SWEEP bad MAC pad 1 vs bad MAC pad {p}"), Kind::BadMac(1), Kind::BadMac(p))
                } else {
                    (format!("SWEEP valid pad 1 vs valid pad {p}"), Kind::Valid(1), Kind::Valid(p))
                }
            })
            .collect();
    }
    let mut failures = 0;
    for (suite, alg, mac_len) in suites {
        let aes_key: Vec<u8> = if suite.starts_with("AES256") { vec![0xa5; 32] } else { vec![0xa5; 16] };
        let keys = Keys { alg, mac_len, mac_key: vec![0x5a; mac_len], aes_key: aes_key.clone() };
        for (label, k0, k1) in pairs.iter().map(|(l, a, b)| (l.as_str(), *a, *b)) {
            let name = format!("{suite}: {label}");
            if !only.is_empty() && !name.contains(&only) {
                continue;
            }
            let pools: [Vec<Vec<u8>>; 2] = [
                (0..POOL).map(|_| record(&keys, k0, &mut rng)).collect(),
                (0..POOL).map(|_| record(&keys, k1, &mut rng)).collect(),
            ];
            let mut opener = alg.opener(&keys.mac_key, &aes_key);
            let mut buf = vec![0u8; pools[0][0].len()];
            let mut idx = [0usize; 2];
            // sanity: the classes behave as intended
            for (c, kind) in [k0, k1].into_iter().enumerate() {
                buf.copy_from_slice(&pools[c][0]);
                let res = opener.decrypt(InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, &mut buf), SEQ);
                assert_eq!(res.is_ok(), matches!(kind, Kind::Valid(_)), "{name} class {c} {kind:?}");
            }
            let r = measure(samples, |c| {
                idx[c] = (idx[c] + 1) % POOL;
                buf.copy_from_slice(&pools[c][idx[c]]);
                let res = opener.decrypt(InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, &mut buf), SEQ);
                black_box(res.is_ok());
            });
            print(&name, &r);
            if r.raw.abs().max(r.cropped.abs()) > 4.5 {
                failures += 1;
            }
        }
    }

    // positive control: the variable-time MAC over the data lengths of padding 1 and padding 256
    if only.is_empty() || "control".contains(&only) {
        let keys = Keys { alg: &AES_128_CBC_SHA, mac_len: 20, mac_key: vec![0x5a; 20], aes_key: vec![0xa5; 16] };
        let mut data = vec![0u8; PLAIN];
        rng.fill(&mut data);
        let aad = make_tls12_aad(SEQ, ContentType::ApplicationData, ProtocolVersion::TLSv1_2, 0);
        let lens = [PLAIN - 20 - 1, PLAIN - 20 - 256];
        let r = measure(samples, |c| {
            black_box(keys.alg.reference_mac(&keys.mac_key, &aad, &data[..lens[c]]));
        });
        print("CONTROL variable-time hmac, data len pad1 vs pad256", &r);
        if r.raw.abs().max(r.cropped.abs()) <= 4.5 {
            println!("CONTROL NOT DETECTED: the harness cannot be trusted");
            failures += 1000;
        }
    }
    // the constant-time MAC alone (ct_hmac) over the data lengths of padding 1 and padding 256, same 2048-byte buffer
    if only.is_empty() || "ct_hmac".contains(&only) || only == "MAC-ONLY" {
        for (suite, alg, mac_len) in suites {
            let mac_key = vec![0x5a; mac_len];
            let mut data = vec![0u8; PLAIN];
            rng.fill(&mut data);
            let aad = make_tls12_aad(SEQ, ContentType::ApplicationData, ProtocolVersion::TLSv1_2, 0);
            let lens = [PLAIN - mac_len - 1, PLAIN - mac_len - 256];
            let r = measure(samples, |c| {
                black_box(alg.constant_time_mac(&mac_key, &aad, &data, lens[c]));
            });
            print(&format!("{suite}: constant_time_mac alone, data len pad1 vs pad256"), &r);
        }
    }
    println!("pairs with |t| > 4.5 among the CBC decrypt tests: {}", failures % 1000);
}

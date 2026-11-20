//! The TLS 1.3 prefix a DSA key's server runs for a client that offers TLS 1.3.
//!
//! The image's JDK cannot sign a TLS 1.3 CertificateVerify with a DSA key, but it runs the handshake as far as it can:
//! it settles suite and group, sends its ServerHello (and a ChangeCipherSpec when the client's session id is not
//! empty), an encrypted EncryptedExtensions and an encrypted fatal `handshake_failure`, then closes (probed against
//! `mockserver-webhook` 9.2.0 with OpenSSL 3.5 `s_client -msg -trace`). The server never completes a handshake here:
//! rustls cannot stop where the JDK does, so this module writes those records itself, from the client's key share on
//! (HKDF key schedule over ring, AEAD records over ring, the key agreement of every group the JDK serves).
//!
//! What the image does, and so what is reproduced:
//! * any client listing TLS 1.3 in `supported_versions` is answered as a TLS 1.3 client, with no fall back to TLS 1.2
//!   (also one that lists a DHE-DSS suite);
//! * no suite of TLS_AES_256_GCM_SHA384 > TLS_AES_128_GCM_SHA256 > TLS_CHACHA20_POLY1305_SHA256 in common, or no
//!   signature scheme TLS 1.3 allows (RSASSA-PSS, ECDSA over the three NIST curves, EdDSA): a `handshake_failure` in the
//!   clear before any ServerHello;
//! * the group is that of the first key share (client order) among the JDK's groups, x25519, x448, secp256r1,
//!   secp384r1, secp521r1, ffdhe2048..8192 and X25519MLKEM768; with none usable, a HelloRetryRequest naming the first
//!   group of the client's `supported_groups` the JDK serves (with a cookie), and after the second ClientHello the same
//!   flight (whatever group its first usable share is in; a second ClientHello that echoes the cookie must keep the first's
//!   random, session id and suites, or gets `unexpected_message`; one with no cookie is answered as a first ClientHello
//!   with its own suite, and with no usable share gets `handshake_failure`, never a second retry); with no common group at
//!   all, an `unexpected_message` in the clear; a share-bearing first ClientHello that carries a cookie (nothing to match
//!   it) gets `unexpected_message` once its signature schemes pass; an empty `supported_groups` or cookie is a
//!   `decode_error`, a cookie declaring more than it holds an `internal_error`;
//! * with no `key_share` extension at all, a `missing_extension` in the clear;
//! * a share the JDK cannot decode is a plain `internal_error` (`decode_error` for an empty one); one it decodes but
//!   cannot derive a secret from (x25519 zero, an ffdhe value of 0, 1, p-1 or p, a point off the curve) gets its
//!   ServerHello and then a plain `internal_error`;
//! * the encrypted records carry 16 bytes of zero padding.
//!
//! Key material (the shared secret, the traffic keys) lives in locals and is never logged.

use num_bigint::BigUint;
use ring::{aead, agreement, digest, hkdf, rand::SecureRandom, rand::SystemRandom};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The JDK's suite order: TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256.
const SUITE_ORDER: [u16; 3] = [0x1302, 0x1301, 0x1303];

/// rsa_pss_rsae_sha256/384/512, rsa_pss_pss_sha256/384/512, ecdsa_secp256r1/384r1/521r1, ed25519, ed448.
const TLS13_SCHEMES: [u16; 11] = [0x0804, 0x0805, 0x0806, 0x0809, 0x080a, 0x080b, 0x0403, 0x0503, 0x0603, 0x0807, 0x0808];

/// The groups the JDK serves, as its EncryptedExtensions' `supported_groups` lists them.
const GROUPS: [u16; 11] = [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x001e, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104];

const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// What the TLS 1.3 prefix reads off a ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// the handshake message as sent (type, length, body): the transcript's first input
    handshake: Vec<u8>,
    random: Vec<u8>,
    session_id: Vec<u8>,
    cookie: Option<Vec<u8>>,
    suites: Vec<u16>,
    versions: Vec<u16>,
    schemes: Vec<u16>,
    groups: Vec<u16>,
    /// whether a `key_share` extension is present, even an empty one
    has_key_share: bool,
    shares: Vec<(u16, Vec<u8>)>,
    /// the alert the JDK sends for the first extension it cannot decode: an empty `supported_groups` or cookie (50), a cookie
    /// that declares more than it holds (80)
    defect: Option<u8>,
}

fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, rest) = (data.get(..n)?, data.get(n..)?);
    *data = rest;
    Some(head)
}

fn len_prefixed<'a>(data: &mut &'a [u8], width: usize) -> Option<&'a [u8]> {
    let n = take(data, width)?.iter().fold(0usize, |a, b| (a << 8) | *b as usize);
    take(data, n)
}

fn u16_list(data: &[u8]) -> Vec<u16> {
    data.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes([c[0], c[1]])).collect()
}

impl ClientHello {
    /// Parses one whole ClientHello handshake message (type, length, body; the records it came in already joined, see
    /// `reassemble`); `None` when the bytes are not that.
    pub fn parse(message: &[u8]) -> Option<ClientHello> {
        let mut rest = message;
        if take(&mut rest, 1)? != [1] {
            return None;
        }
        let mut hello = len_prefixed(&mut rest, 3)?;
        let handshake = message[..message.len() - rest.len()].to_vec();
        let random = take(&mut hello, 2 + 32)?[2..].to_vec();
        let session_id = len_prefixed(&mut hello, 1)?.to_vec();
        let suites = u16_list(len_prefixed(&mut hello, 2)?);
        len_prefixed(&mut hello, 1)?;
        let mut out = ClientHello { handshake, random, session_id, cookie: None, suites, versions: Vec::new(), schemes: Vec::new(), groups: Vec::new(), has_key_share: false, shares: Vec::new(), defect: None };
        let mut extensions = len_prefixed(&mut hello, 2).unwrap_or_default();
        while !extensions.is_empty() {
            let kind = take(&mut extensions, 2)?;
            let mut data = len_prefixed(&mut extensions, 2)?;
            match u16::from_be_bytes([kind[0], kind[1]]) {
                0x002b => out.versions = u16_list(len_prefixed(&mut data, 1)?),
                0x002c => {
                    let declared = data.get(..2).map(|n| u16::from_be_bytes([n[0], n[1]]) as usize);
                    match declared {
                        Some(n) if n > 0 && n <= data.len() - 2 => out.cookie = Some(data[2..2 + n].to_vec()),
                        Some(n) if n > data.len() - 2 => out.defect = out.defect.or(Some(80)),
                        _ => out.defect = out.defect.or(Some(50)),
                    }
                }
                0x000d => out.schemes = u16_list(len_prefixed(&mut data, 2)?),
                0x000a => {
                    out.groups = u16_list(len_prefixed(&mut data, 2)?);
                    if out.groups.is_empty() {
                        out.defect = out.defect.or(Some(50));
                    }
                }
                0x0033 => {
                    out.has_key_share = true;
                    let mut shares = len_prefixed(&mut data, 2)?;
                    while !shares.is_empty() {
                        let group = take(&mut shares, 2)?;
                        let share = len_prefixed(&mut shares, 2)?;
                        out.shares.push((u16::from_be_bytes([group[0], group[1]]), share.to_vec()));
                    }
                }
                _ => {}
            }
        }
        Some(out)
    }

    /// Whether `supported_versions` lists TLS 1.3.
    pub fn offers_tls13(&self) -> bool {
        self.versions.contains(&0x0304)
    }
}

/// The largest handshake message body the JDK reads (`jdk.tls.maxHandshakeMessageSize`, 32768): a ClientHello that
/// declares more is an `unexpected_message` as soon as its length is read.
pub const MAX_MESSAGE_BODY: usize = 32768;

/// The largest TLS record payload the JDK reads (probed: 33088 is read, 33089 is an `unexpected_message` from the header).
pub const MAX_RECORD_PAYLOAD: usize = 33088;

/// The most bytes `reassemble` can ask for: the largest message in records of one byte (each costs 5 bytes of header, and
/// a record of no bytes is refused), then the last record at its largest.
pub const MAX_HELLO_BYTES: usize = 6 * (4 + MAX_MESSAGE_BODY) + 5 + MAX_RECORD_PAYLOAD;

/// What the records read so far say about a ClientHello that may be split over several handshake records.
#[derive(Debug, PartialEq, Eq)]
pub enum Reassembled {
    /// the records end before the message does (or inside a record)
    Incomplete,
    /// the whole message, and the bytes of the records it took (the last record whole, whatever follows the message in it)
    Hello { message: Vec<u8>, consumed: usize },
    /// what the JDK answers with a plain alert of this description
    Alert(u8),
    /// not a ClientHello in handshake records: the caller's other paths decide
    NotHello,
}

/// Joins the handshake records at the start of `buf` into the ClientHello they carry, as the JDK reads them (probed
/// against `mockserver-webhook` 9.2.0): the first record is a handshake record (any other first record is `NotHello`),
/// the pieces follow in handshake records only, none of them empty (`unexpected_message` otherwise), the record version
/// is not looked at, a record of more than 33088 bytes and a message of more than 32768 bytes are `unexpected_message`
/// as soon as their lengths are read, and what follows the message in its last record, or after it, is not read.
/// Bounded by construction: it needs at most `MAX_HELLO_BYTES` of `buf`, and never indexes past it.
pub fn reassemble(buf: &[u8]) -> Reassembled {
    let (mut at, mut message) = (0usize, Vec::new());
    loop {
        if message.len() >= 4 {
            let want = 4 + (message[1] as usize) * 65536 + (message[2] as usize) * 256 + message[3] as usize;
            if message.len() >= want {
                message.truncate(want);
                return Reassembled::Hello { message, consumed: at };
            }
        }
        let rest = &buf[at.min(buf.len())..];
        if rest.len() < 5 {
            return Reassembled::Incomplete;
        }
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        if at == 0 && rest[0] != 0x16 {
            return Reassembled::NotHello;
        }
        if rest[0] != 0x16 || len == 0 || len > MAX_RECORD_PAYLOAD {
            return Reassembled::Alert(10);
        }
        let available = (rest.len() - 5).min(len);
        message.extend_from_slice(&rest[5..5 + available]);
        if message.first().is_some_and(|kind| *kind != 1) {
            return Reassembled::NotHello;
        }
        if message.len() >= 4 {
            let body = (message[1] as usize) * 65536 + (message[2] as usize) * 256 + message[3] as usize;
            if body > MAX_MESSAGE_BODY {
                return Reassembled::Alert(10);
            }
        }
        if available < len {
            return Reassembled::Incomplete;
        }
        at += 5 + len;
    }
}

/// The record bytes of the plain `handshake_failure` / `unexpected_message` the JDK sends before any ServerHello.
pub fn plain_alert(description: u8) -> Vec<u8> {
    vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, description]
}

fn record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind, 0x03, 0x03];
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

fn ext(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn random(buf: &mut [u8]) -> Option<()> {
    SystemRandom::new().fill(buf).ok()
}

// ---- key agreement ----

/// What the JDK makes of a client's key share.
enum Agreement {
    /// the share cannot be decoded: a plain alert (`decode_error` for an empty one, `internal_error` for a malformed one),
    /// before any ServerHello
    Refused(u8),
    /// the JDK's ServerHello goes out, then the key derivation fails (a low-order or out-of-range value): a plain
    /// `internal_error`, no ChangeCipherSpec
    Failed(Vec<u8>),
    /// the server's key share and the shared secret
    Secret(Vec<u8>, Vec<u8>),
}

/// The server's side of a key agreement for a client's share, the JDK's leniency included (probed with hand-made
/// ClientHellos against `mockserver-webhook` 9.2.0): an x25519 or x448 value of any length is read as a little-endian
/// number (here padded or cut to the group's size), an ffdhe value of any length as a number, a point must be an
/// uncompressed one of its curve's length and a hybrid share exactly its 1216 bytes. `None` when no random bytes come.
fn agree(group: u16, client_share: &[u8]) -> Option<Agreement> {
    let rng = SystemRandom::new();
    let sized = |size: usize| {
        let mut value = client_share.to_vec();
        value.resize(size, 0);
        value
    };
    Some(match group {
        _ if client_share.is_empty() => Agreement::Refused(50),
        0x001d => ring_agree(&agreement::X25519, &sized(32)),
        0x0017 if client_share.len() == 65 && client_share[0] == 4 => ring_agree(&agreement::ECDH_P256, client_share),
        0x0018 if client_share.len() == 97 && client_share[0] == 4 => ring_agree(&agreement::ECDH_P384, client_share),
        0x0019 if client_share.len() == 133 && client_share[0] == 4 => agree_p521(client_share)?,
        0x001e => {
            let mut secret = [0u8; 56];
            rng.fill(&mut secret).ok()?;
            let public = x448(&secret, &X448_BASE).to_vec();
            let shared = x448(&secret, &sized(56).try_into().ok()?);
            // RFC 7748: an all-zero output is a low-order point, which TLS 1.3 forbids
            if shared.iter().any(|b| *b != 0) { Agreement::Secret(public, shared.to_vec()) } else { Agreement::Failed(public) }
        }
        0x0100..=0x0104 => agree_ffdhe(group, client_share)?,
        0x11ec if client_share.len() == 1184 + 32 => {
            // X25519MLKEM768: ML-KEM-768's encapsulation key then the X25519 share, answered with the ciphertext then the
            // X25519 share; the shared secrets joined the same way
            let (ek, x) = client_share.split_at(1184);
            let Ok(key) = ml_kem::Key::<ml_kem::EncapsulationKey<ml_kem::MlKem768>>::try_from(ek) else {
                return Some(Agreement::Refused(80));
            };
            let Ok(ek) = ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new(&key) else {
                return Some(Agreement::Refused(80));
            };
            let (ct, kem_secret) = ml_kem::kem::Encapsulate::encapsulate(&ek);
            let mut share = ct.as_slice().to_vec();
            match ring_agree(&agreement::X25519, x) {
                Agreement::Secret(x_public, x_secret) => {
                    share.extend_from_slice(&x_public);
                    let mut secret = kem_secret.as_slice().to_vec();
                    secret.extend_from_slice(&x_secret);
                    Agreement::Secret(share, secret)
                }
                Agreement::Failed(x_public) => {
                    share.extend_from_slice(&x_public);
                    Agreement::Failed(share)
                }
                refused => refused,
            }
        }
        _ => Agreement::Refused(80),
    })
}

fn ring_agree(algorithm: &'static agreement::Algorithm, client_share: &[u8]) -> Agreement {
    let Ok(private) = agreement::EphemeralPrivateKey::generate(algorithm, &SystemRandom::new()) else {
        return Agreement::Refused(80);
    };
    let Ok(public) = private.compute_public_key() else {
        return Agreement::Refused(80);
    };
    let public = public.as_ref().to_vec();
    match agreement::agree_ephemeral(private, &agreement::UnparsedPublicKey::new(algorithm, client_share), |secret| secret.to_vec()) {
        Ok(shared) => Agreement::Secret(public, shared),
        Err(_) => Agreement::Failed(public),
    }
}

fn agree_p521(client_share: &[u8]) -> Option<Agreement> {
    use p521::elliptic_curve::sec1::ToEncodedPoint;
    // a uniformly random 521-bit string below the group order (the odds of a retry are 2^-260)
    let secret = loop {
        let mut bytes = [0u8; 66];
        random(&mut bytes)?;
        bytes[0] &= 0x01;
        if let Ok(secret) = p521::SecretKey::from_slice(&bytes) {
            break secret;
        }
    };
    let public = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
    Some(match p521::PublicKey::from_sec1_bytes(client_share) {
        Ok(peer) => Agreement::Secret(public, p521::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine()).raw_secret_bytes().to_vec()),
        Err(_) => Agreement::Failed(public),
    })
}

fn agree_ffdhe(group: u16, client_share: &[u8]) -> Option<Agreement> {
    let named = match group {
        0x0100 => rustls::ffdhe_groups::FFDHE2048,
        0x0101 => rustls::ffdhe_groups::FFDHE3072,
        0x0102 => rustls::ffdhe_groups::FFDHE4096,
        0x0103 => rustls::ffdhe_groups::FFDHE6144,
        _ => rustls::ffdhe_groups::FFDHE8192,
    };
    let p = BigUint::from_bytes_be(named.p);
    let g = BigUint::from_bytes_be(named.g);
    let peer = BigUint::from_bytes_be(client_share);
    let mut buf = [0u8; 64];
    random(&mut buf)?;
    let x = BigUint::from_bytes_be(&buf) | BigUint::from(1u8);
    let pad = |n: &BigUint| {
        let bytes = n.to_bytes_be();
        let mut out = vec![0u8; named.p.len() - bytes.len()];
        out.extend(bytes);
        out
    };
    if peer < BigUint::from(2u8) || peer > &p - BigUint::from(2u8) {
        // refused before any exponentiation; the ServerHello still carries a share, any value below p looks like g^x
        let mut filler = vec![0u8; named.p.len()];
        random(&mut filler)?;
        return Some(Agreement::Failed(pad(&(BigUint::from_bytes_be(&filler) % &p))));
    }
    Some(Agreement::Secret(pad(&g.modpow(&x, &p)), pad(&peer.modpow(&x, &p))))
}

const X448_BASE: [u8; 56] = {
    let mut base = [0u8; 56];
    base[0] = 5;
    base
};

/// RFC 7748 section 5 `X448(k, u)` on big integers: the Montgomery ladder, with the scalar clamped. Not constant time;
/// the scalar is an ephemeral key of a handshake that never completes, and the ladder has no vetted crate under the
/// project's licence list that is not a pre-release.
pub fn x448(scalar: &[u8; 56], u: &[u8; 56]) -> [u8; 56] {
    let p = (BigUint::from(1u8) << 448) - (BigUint::from(1u8) << 224) - BigUint::from(1u8);
    let a24 = BigUint::from(39081u32);
    let mut k = *scalar;
    k[0] &= 252;
    k[55] |= 128;
    let k = BigUint::from_bytes_le(&k);
    let x1: BigUint = BigUint::from_bytes_le(u) % &p;
    let (mut x2, mut z2, mut x3, mut z3) = (BigUint::from(1u8), BigUint::from(0u8), x1.clone(), BigUint::from(1u8));
    let mut swap = false;
    let sub = |a: &BigUint, b: &BigUint| (a + &p - b) % &p;
    for t in (0..448).rev() {
        let bit = k.bit(t);
        if swap != bit {
            std::mem::swap(&mut x2, &mut x3);
            std::mem::swap(&mut z2, &mut z3);
        }
        swap = bit;
        let a = (&x2 + &z2) % &p;
        let aa = &a * &a % &p;
        let b = sub(&x2, &z2);
        let bb = &b * &b % &p;
        let e = sub(&aa, &bb);
        let c = (&x3 + &z3) % &p;
        let d = sub(&x3, &z3);
        let da = &d * &a % &p;
        let cb = &c * &b % &p;
        let sum = (&da + &cb) % &p;
        x3 = &sum * &sum % &p;
        let diff = sub(&da, &cb);
        z3 = &x1 * (&diff * &diff % &p) % &p;
        x2 = &aa * &bb % &p;
        z2 = &e * ((&aa + &a24 * &e) % &p) % &p;
    }
    if swap {
        std::mem::swap(&mut x2, &mut x3);
        std::mem::swap(&mut z2, &mut z3);
    }
    let inverse = z2.modpow(&(&p - BigUint::from(2u8)), &p);
    let result = (x2 * inverse % &p).to_bytes_le();
    let mut out = [0u8; 56];
    out[..result.len()].copy_from_slice(&result);
    out
}

// ---- key schedule and records ----

struct Suite {
    id: u16,
    hash: &'static digest::Algorithm,
    hkdf: hkdf::Algorithm,
    aead: &'static aead::Algorithm,
}

fn suite(id: u16) -> Suite {
    match id {
        0x1302 => Suite { id, hash: &digest::SHA384, hkdf: hkdf::HKDF_SHA384, aead: &aead::AES_256_GCM },
        0x1301 => Suite { id, hash: &digest::SHA256, hkdf: hkdf::HKDF_SHA256, aead: &aead::AES_128_GCM },
        _ => Suite { id, hash: &digest::SHA256, hkdf: hkdf::HKDF_SHA256, aead: &aead::CHACHA20_POLY1305 },
    }
}

struct Length(usize);

impl hkdf::KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}

/// `HKDF-Expand-Label` (RFC 8446 section 7.1).
fn expand_label(prk: &hkdf::Prk, label: &str, context: &[u8], out: &mut [u8]) -> Option<()> {
    let length = (out.len() as u16).to_be_bytes();
    let label_length = [(6 + label.len()) as u8];
    let context_length = [context.len() as u8];
    let info = [&length[..], &label_length, b"tls13 ", label.as_bytes(), &context_length, context];
    prk.expand(&info, Length(out.len())).ok()?.fill(out).ok()
}

impl Suite {
    fn hash_len(&self) -> usize {
        self.hash.output_len()
    }

    /// The server's handshake traffic key and IV for `transcript` (the messages from the ClientHello to the ServerHello).
    fn server_handshake_keys(&self, shared: &[u8], transcript: &[u8]) -> Option<(aead::LessSafeKey, [u8; 12])> {
        let zeros = vec![0u8; self.hash_len()];
        let early = hkdf::Salt::new(self.hkdf, &zeros).extract(&zeros);
        let mut derived = vec![0u8; self.hash_len()];
        expand_label(&early, "derived", digest::digest(self.hash, b"").as_ref(), &mut derived)?;
        let handshake = hkdf::Salt::new(self.hkdf, &derived).extract(shared);
        let mut traffic = vec![0u8; self.hash_len()];
        expand_label(&handshake, "s hs traffic", digest::digest(self.hash, transcript).as_ref(), &mut traffic)?;
        let traffic = hkdf::Prk::new_less_safe(self.hkdf, &traffic);
        let mut key = vec![0u8; self.aead.key_len()];
        expand_label(&traffic, "key", b"", &mut key)?;
        let mut iv = [0u8; 12];
        expand_label(&traffic, "iv", b"", &mut iv)?;
        Some((aead::LessSafeKey::new(aead::UnboundKey::new(self.aead, &key).ok()?), iv))
    }
}

/// One TLS 1.3 record: `content`, its type and 16 zero bytes of padding (as the JDK pads), sealed under sequence number `seq`.
fn seal(key: &aead::LessSafeKey, iv: &[u8; 12], seq: u64, kind: u8, content: &[u8]) -> Option<Vec<u8>> {
    let mut nonce = *iv;
    for (n, s) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
        *n ^= s;
    }
    let mut data = content.to_vec();
    data.push(kind);
    data.extend_from_slice(&[0u8; 16]);
    let header = [0x17, 0x03, 0x03, ((data.len() + 16) >> 8) as u8, (data.len() + 16) as u8];
    key.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::from(header), &mut data).ok()?;
    let mut out = header.to_vec();
    out.extend_from_slice(&data);
    Some(out)
}

/// The EncryptedExtensions message: `supported_groups` listing the JDK's groups.
fn encrypted_extensions() -> Vec<u8> {
    let list: Vec<u8> = GROUPS.iter().flat_map(|g| g.to_be_bytes()).collect();
    let mut data = (list.len() as u16).to_be_bytes().to_vec();
    data.extend_from_slice(&list);
    let extensions = ext(0x000a, &data);
    let mut body = (extensions.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(&extensions);
    handshake_message(8, &body)
}

fn server_hello(random: &[u8; 32], session_id: &[u8], suite: u16, extensions: &[u8]) -> Vec<u8> {
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&suite.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(extensions);
    handshake_message(2, &body)
}

/// What the JDK does with a ClientHello that offers TLS 1.3.
#[derive(Debug)]
pub enum Reply {
    /// a plain alert, nothing else
    Alert(Vec<u8>),
    /// the flight up to the encrypted alert
    Flight(Vec<u8>),
    /// a HelloRetryRequest, then the second ClientHello decides
    Retry { records: Vec<u8>, cookie: Vec<u8>, suite: u16 },
}

/// The suite and group choices for a ClientHello: the reply, with the ClientHello's own parts that the second round needs.
pub fn reply(hello: &ClientHello) -> Option<Reply> {
    if let Some(alert) = hello.defect {
        return Some(Reply::Alert(plain_alert(alert)));
    }
    let share = hello.shares.iter().find(|(g, _)| GROUPS.contains(g));
    let suite_of = || SUITE_ORDER.iter().copied().find(|s| hello.suites.contains(s));
    if share.is_some() || !hello.has_key_share {
        // probed with hand-made ClientHellos: the signature schemes, then the cookie (a first ClientHello has none to
        // match: unexpected_message), then the missing key share, then the suite
        let alert = if !hello.schemes.iter().any(|s| TLS13_SCHEMES.contains(s)) {
            Some(40)
        } else if hello.cookie.is_some() {
            Some(10)
        } else if !hello.has_key_share {
            Some(109)
        } else if suite_of().is_none() {
            Some(40)
        } else {
            None
        };
        if let Some(alert) = alert {
            return Some(Reply::Alert(plain_alert(alert)));
        }
        let (group, share) = share?;
        return flight(hello, suite_of()?, *group, share, &hello.handshake, None);
    }
    // key shares, but none of a group the JDK serves: the suite, then a retry (the cookie is not looked at)
    let Some(suite_id) = suite_of() else {
        return Some(Reply::Alert(plain_alert(40)));
    };
    let Some(group) = hello.groups.iter().copied().find(|g| GROUPS.contains(g)) else {
        return Some(Reply::Alert(plain_alert(10)));
    };
    // HelloRetryRequest: the JDK's cookie is opaque to the client
    let mut cookie = vec![0u8; 3 + 2 * suite(suite_id).hash_len()];
    random(&mut cookie)?;
    let mut extensions = ext(0x002b, &[0x03, 0x04]);
    extensions.extend(ext(0x002c, &{
        let mut data = (cookie.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&cookie);
        data
    }));
    extensions.extend(ext(0x0033, &group.to_be_bytes()));
    let message = server_hello(&HELLO_RETRY_REQUEST_RANDOM, &hello.session_id, suite_id, &extensions);
    let mut records = record(0x16, &message);
    if !hello.session_id.is_empty() {
        records.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    }
    Some(Reply::Retry { records, cookie, suite: suite_id })
}

/// The ServerHello (and a ChangeCipherSpec for a client with a session id), EncryptedExtensions and alert for a key share.
/// `transcript_prefix` is what precedes the ServerHello in the transcript (the ClientHello, or after a retry the
/// `message_hash`, the HelloRetryRequest and the second ClientHello); `retry` is that prefix then.
fn flight(hello: &ClientHello, suite_id: u16, group: u16, share: &[u8], client_hello: &[u8], retry: Option<&[u8]>) -> Option<Reply> {
    let (server_share, shared) = match agree(group, share)? {
        Agreement::Refused(alert) => return Some(Reply::Alert(plain_alert(alert))),
        Agreement::Failed(server_share) => (server_share, None),
        Agreement::Secret(server_share, shared) => (server_share, Some(shared)),
    };
    let suite = suite(suite_id);
    let mut server_random = [0u8; 32];
    random(&mut server_random)?;
    let mut key_share = group.to_be_bytes().to_vec();
    key_share.extend_from_slice(&(server_share.len() as u16).to_be_bytes());
    key_share.extend_from_slice(&server_share);
    let mut extensions = ext(0x002b, &[0x03, 0x04]);
    extensions.extend(ext(0x0033, &key_share));
    let server_hello = server_hello(&server_random, &hello.session_id, suite.id, &extensions);
    let mut transcript = retry.map(<[u8]>::to_vec).unwrap_or_default();
    transcript.extend_from_slice(client_hello);
    transcript.extend_from_slice(&server_hello);
    let mut out = record(0x16, &server_hello);
    let Some(shared) = shared else {
        // the JDK's key derivation fails after its ServerHello
        out.extend(plain_alert(80));
        return Some(Reply::Flight(out));
    };
    let (key, iv) = suite.server_handshake_keys(&shared, &transcript)?;
    // after a retry too: the JDK sends one after the HelloRetryRequest and one after the second ServerHello
    if !hello.session_id.is_empty() {
        out.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    }
    out.extend(seal(&key, &iv, 0, 0x16, &encrypted_extensions())?);
    out.extend(seal(&key, &iv, 1, 0x15, &[0x02, 0x28])?);
    Some(Reply::Flight(out))
}

/// Sends the plain alert and closes. The client may still be sending the rest of what the alert refuses (a message of
/// several records over the cap): the unread bytes are drained for a moment, bounded in time and size, or the close would
/// reset the connection and could take the alert with it.
pub async fn alert_and_close(tcp: &mut TcpStream, description: u8) -> std::io::Result<()> {
    tcp.write_all(&plain_alert(description)).await?;
    tcp.flush().await?;
    tcp.shutdown().await?;
    let mut sink = [0u8; 4096];
    let mut budget = 4 * MAX_HELLO_BYTES;
    let _ = tokio::time::timeout(std::time::Duration::from_millis(300), async {
        while budget > 0 {
            match tcp.read(&mut sink).await {
                Ok(n) if n > 0 => budget = budget.saturating_sub(n),
                _ => break,
            }
        }
    })
    .await;
    Ok(())
}

/// Reads one whole TLS record from the stream; `None` for a record longer than the JDK reads (its payload is not read).
async fn read_record(tcp: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 5];
    tcp.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > MAX_RECORD_PAYLOAD {
        return Ok(None);
    }
    let mut record = header.to_vec();
    record.resize(5 + len, 0);
    tcp.read_exact(&mut record[5..]).await?;
    Ok(Some(record))
}

/// What arrives after a HelloRetryRequest.
enum Second {
    Hello(Box<ClientHello>),
    Alert(u8),
}

/// Reads the second ClientHello: one ChangeCipherSpec (a single byte, 1) at most ahead of it, then handshake records
/// joined as `reassemble` does (probed with the image: a second ChangeCipherSpec or one of another body, an empty record,
/// another type between the pieces, a message or record over the caps are `unexpected_message`).
async fn read_second(tcp: &mut TcpStream) -> std::io::Result<Second> {
    let failed = || std::io::Error::other("a client offering TLS 1.3, and a DSA key");
    let (mut buf, mut change_cipher_spec) = (Vec::new(), false);
    loop {
        let Some(record) = read_record(tcp).await? else {
            return Ok(Second::Alert(10));
        };
        if buf.is_empty() && record[0] == 0x14 {
            if change_cipher_spec || record[5..] != [1] {
                return Ok(Second::Alert(10));
            }
            change_cipher_spec = true;
            continue;
        }
        buf.extend_from_slice(&record);
        match reassemble(&buf) {
            Reassembled::Incomplete => {}
            Reassembled::Alert(description) => return Ok(Second::Alert(description)),
            Reassembled::NotHello => return Err(failed()),
            Reassembled::Hello { message, .. } => return ClientHello::parse(&message).map(|hello| Second::Hello(Box::new(hello))).ok_or_else(failed),
        }
    }
}

/// Answers a client that offers TLS 1.3 as the JDK does with a DSA key, then closes the connection. `peeked` is the
/// ClientHello record the caller looked at without consuming it.
pub async fn answer(tcp: &mut TcpStream, hello: &ClientHello, peeked_len: usize) -> std::io::Result<()> {
    let mut consumed = vec![0u8; peeked_len];
    tcp.read_exact(&mut consumed).await?;
    let failed = || std::io::Error::other("a client offering TLS 1.3, and a DSA key");
    // the key agreement is CPU work (ffdhe8192 takes tens of milliseconds): off the async workers
    let first = hello.clone();
    let first_reply = tokio::task::spawn_blocking(move || reply(&first)).await.map_err(|_| failed())?;
    let bytes = match first_reply.ok_or_else(failed)? {
        Reply::Alert(bytes) | Reply::Flight(bytes) => bytes,
        Reply::Retry { records, cookie, suite: suite_id } => {
            tcp.write_all(&records).await?;
            tcp.flush().await?;
            // the client's ChangeCipherSpec, then its second ClientHello (in one record or several)
            let second = match read_second(tcp).await? {
                Second::Hello(second) => second,
                Second::Alert(description) => return alert_and_close(tcp, description).await,
            };
            // the JDK's checks of the second ClientHello (probed with hand-made ones): it compares random,
            // session id and suites with the first's only when it echoes the cookie, which carries them (a ClientHello
            // without one is checked and answered as a first one, with its own suite); a second retry is never sent; the
            // flight is for the first usable share, whatever group the retry asked for
            let alert = if let Some(defect) = second.defect {
                Some(defect)
            } else if (second.has_key_share && !second.shares.iter().any(|(g, _)| GROUPS.contains(g))) || !second.schemes.iter().any(|s| TLS13_SCHEMES.contains(s)) {
                Some(40)
            } else if second.cookie.as_ref().is_some_and(|c| *c != cookie || second.random != hello.random || second.session_id != hello.session_id || second.suites != hello.suites) {
                Some(10)
            } else if !second.has_key_share {
                Some(109)
            } else if !SUITE_ORDER.iter().any(|s| second.suites.contains(s)) {
                Some(40)
            } else {
                None
            };
            if let Some(alert) = alert {
                plain_alert(alert)
            } else {
                let Some((group, share)) = second.shares.iter().find(|(g, _)| GROUPS.contains(g)) else {
                    return Err(failed());
                };
                let suite_id = SUITE_ORDER.iter().copied().find(|s| second.suites.contains(s)).unwrap_or(suite_id);
                let suite = suite(suite_id);
                // the first ClientHello is replaced by a `message_hash` message in the transcript
                let mut retry = handshake_message(254, digest::digest(suite.hash, &hello.handshake).as_ref());
                retry.extend_from_slice(&records[5..5 + hello_len(&records)]);
                let (group, share, hello2) = (*group, share.clone(), second.clone());
                let second_reply = tokio::task::spawn_blocking(move || flight(&hello2, suite_id, group, &share, &hello2.handshake, Some(&retry))).await.map_err(|_| failed())?;
                match second_reply.ok_or_else(failed)? {
                    Reply::Flight(bytes) | Reply::Alert(bytes) => bytes,
                    Reply::Retry { .. } => return Err(failed()),
                }
            }
        }
    };
    tcp.write_all(&bytes).await?;
    tcp.flush().await?;
    tcp.shutdown().await
}

/// The length of the first record's payload.
fn hello_len(records: &[u8]) -> usize {
    u16::from_be_bytes([records[3], records[4]]) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn rec(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![kind, 3, 1];
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// A message of type 1 declaring `body` bytes, `have` of which are present.
    fn message(body: usize, have: usize) -> Vec<u8> {
        let mut m = vec![1, (body >> 16) as u8, (body >> 8) as u8, body as u8];
        m.resize(4 + have, 7);
        m
    }

    #[test]
    fn reassemble_joins_records_and_stops_at_the_caps() {
        let m = message(100, 100);
        // whole, in pieces, a header cut at every offset, one byte per record
        for cut in 1..m.len() {
            let two = [rec(22, &m[..cut]), rec(22, &m[cut..])].concat();
            assert_eq!(reassemble(&two), Reassembled::Hello { message: m.clone(), consumed: two.len() }, "cut {cut}");
            assert_eq!(reassemble(&two[..two.len() - 1]), Reassembled::Incomplete, "cut {cut}");
        }
        let tiny: Vec<u8> = m.iter().flat_map(|b| rec(22, &[*b])).collect();
        assert_eq!(reassemble(&tiny), Reassembled::Hello { message: m.clone(), consumed: tiny.len() });
        // what follows the message in its last record is consumed with the record and left out of the message
        let mut last = m[50..].to_vec();
        last.extend_from_slice(&[0x14, 0, 0, 0]);
        let with_tail = [rec(22, &m[..50]), rec(22, &last)].concat();
        assert_eq!(reassemble(&with_tail), Reassembled::Hello { message: m.clone(), consumed: with_tail.len() });
        // the refusals
        assert_eq!(reassemble(&[rec(22, &m[..50]), rec(22, &[]), rec(22, &m[50..])].concat()), Reassembled::Alert(10));
        assert_eq!(reassemble(&[rec(22, &m[..50]), rec(20, &[1]), rec(22, &m[50..])].concat()), Reassembled::Alert(10));
        assert_eq!(reassemble(&rec(22, &[])), Reassembled::Alert(10));
        assert_eq!(reassemble(&rec(23, &m)), Reassembled::NotHello);
        assert_eq!(reassemble(&rec(22, &[2, 0, 0, 0])), Reassembled::NotHello);
        // the caps: 32768 bytes of body are read, one more is refused from the header alone; 33088 bytes of record, one more
        assert_eq!(reassemble(&rec(22, &message(MAX_MESSAGE_BODY, 3))), Reassembled::Incomplete);
        assert_eq!(reassemble(&rec(22, &message(MAX_MESSAGE_BODY + 1, 0))), Reassembled::Alert(10));
        assert_eq!(reassemble(&[22, 3, 1, 0x81, 0x40, 1, 0]), Reassembled::Incomplete);
        assert_eq!(reassemble(&[22, 3, 1, 0x81, 0x41, 1, 0]), Reassembled::Alert(10));
        // the buffer a peek keeps is enough for the largest message in one-byte records
        let big = message(MAX_MESSAGE_BODY, MAX_MESSAGE_BODY);
        let tiny: Vec<u8> = big.iter().flat_map(|b| rec(22, &[*b])).collect();
        assert!(tiny.len() <= MAX_HELLO_BYTES);
        assert_eq!(reassemble(&tiny), Reassembled::Hello { message: big, consumed: tiny.len() });
    }

    /// Peer bytes never panic it, whatever their shape: truncations and mutations of valid input and plain noise.
    #[test]
    fn reassemble_survives_any_bytes() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let m = message(300, 300);
        let valid = [rec(22, &m[..7]), rec(22, &m[7..200]), rec(22, &m[200..])].concat();
        for round in 0..20000 {
            let mut bytes = valid.clone();
            match round % 3 {
                0 => bytes.truncate((next() as usize) % (bytes.len() + 1)),
                1 => {
                    for _ in 0..1 + next() % 4 {
                        let at = (next() as usize) % bytes.len();
                        bytes[at] = next() as u8;
                    }
                }
                _ => bytes = (0..(next() % 64) as usize).map(|_| next() as u8).collect(),
            }
            let _ = reassemble(&bytes);
        }
    }

    /// RFC 7748 section 5.2, the X448 test vectors, and section 6.2's Diffie-Hellman exchange.
    #[test]
    fn x448_matches_rfc_7748() {
        let scalar: [u8; 56] = hex("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3").try_into().unwrap();
        let u: [u8; 56] = hex("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086").try_into().unwrap();
        assert_eq!(x448(&scalar, &u).to_vec(), hex("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"));
        let scalar: [u8; 56] = hex("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f").try_into().unwrap();
        let u: [u8; 56] = hex("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db").try_into().unwrap();
        assert_eq!(x448(&scalar, &u).to_vec(), hex("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"));
        // section 6.2
        let alice: [u8; 56] = hex("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b").try_into().unwrap();
        let bob: [u8; 56] = hex("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d").try_into().unwrap();
        let (alice_public, bob_public) = (x448(&alice, &X448_BASE), x448(&bob, &X448_BASE));
        assert_eq!(alice_public.to_vec(), hex("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"));
        assert_eq!(x448(&alice, &bob_public), x448(&bob, &alice_public));
        assert_eq!(x448(&alice, &bob_public).to_vec(), hex("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"));
    }
}

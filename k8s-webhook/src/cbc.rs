//! TLS 1.2 AES-CBC record protection with HMAC-SHA1 / HMAC-SHA256 (RFC 5246 6.2.3.2, MAC-then-encrypt, explicit
//! per-record IV), as a rustls `Tls12AeadAlgorithm`: the `TLS_DHE_DSS_WITH_AES_{128,256}_CBC_SHA{,256}`
//! suites of the DHE-DSS path (`dsa.rs`), which the JDK behind upstream's webhook image serves.
//!
//! rustls splits a TLS 1.2 key block as `client_key, server_key, client_iv, server_iv` and has no MAC keys; a CBC
//! key block is `client_mac, server_mac, client_key, server_key` (no IVs: TLS 1.1+ sends them in each record). The
//! shape below reads the same bytes in rustls' slots: `enc_key_len` is the MAC key's length and `fixed_iv_len` is the
//! cipher key's, so the "key" handed to `encrypter`/`decrypter` is the MAC key and the "iv" is the AES key.
//!
//! Decryption does not tell a bad padding from a bad MAC (Lucky13, CVE-2013-0169): one error, `DecryptError`
//! (`bad_record_mac`), for every failure after the length checks, which depend only on the record's public length.
//! - The padding is checked in constant time over the last 256 bytes; a bad padding counts as zero padding.
//! - The MAC (`ct_hmac`) is computed with a hash of our own at block level (`compress` of the `sha1` / `sha2` crates):
//!   the inner hash always compresses the number of blocks the longest possible message needs, builds each block's
//!   bytes (data, the 0x80 marker, the length field, zeros) with constant-time selects, and keeps the state of the
//!   block that really is the last one by a constant-time select. The compression count and the memory access pattern
//!   therefore do not depend on the padding length (`compressions()` counts them; the tests compare the counts for a
//!   bad padding and every padding length). The outer hash and the key blocks are fixed-size.
//! - The received tag is picked out of the last `mac_len + 256` bytes with selects, not by a slice at a secret
//!   offset, and compared with `ConstantTimeEq`.
//!
//! What is not claimed: no timing measurement was made; the AES, `subtle` and compiler behaviour (a select may be
//! compiled to a branch) are taken on trust, and the encryption side is not hardened (it works on public lengths).

use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use hmac::{Hmac, Mac};
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, KeyBlockShape, MessageDecrypter, MessageEncrypter,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
};
use rustls::ConnectionTrafficSecrets;
use sha1::Sha1;
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};

const BLOCK: usize = 16;
/// The largest plaintext fragment (RFC 5246 6.2.1).
const MAX_FRAGMENT: usize = 16384;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hash {
    Sha1,
    Sha256,
}

impl Hash {
    fn len(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
        }
    }
}

/// AES-128 or AES-256 in CBC mode with an HMAC.
#[derive(Debug)]
pub struct AesCbc {
    mac: Hash,
    key_len: usize,
}

pub static AES_128_CBC_SHA: AesCbc = AesCbc { mac: Hash::Sha1, key_len: 16 };
pub static AES_256_CBC_SHA: AesCbc = AesCbc { mac: Hash::Sha1, key_len: 32 };
pub static AES_128_CBC_SHA256: AesCbc = AesCbc { mac: Hash::Sha256, key_len: 16 };
pub static AES_256_CBC_SHA256: AesCbc = AesCbc { mac: Hash::Sha256, key_len: 32 };

impl AesCbc {
    /// One direction's sealer from its MAC key and AES key (the key block's two slices, see the module comment).
    pub fn sealer(&self, mac_key: &[u8], aes_key: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(Encrypter { mac: self.mac, mac_key: mac_key.to_vec(), cipher: Cipher::new(aes_key) })
    }

    /// One direction's opener.
    pub fn opener(&self, mac_key: &[u8], aes_key: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Decrypter { mac: self.mac, mac_key: mac_key.to_vec(), cipher: Cipher::new(aes_key) })
    }
}

impl Tls12AeadAlgorithm for AesCbc {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _extra: &[u8]) -> Box<dyn MessageEncrypter> {
        self.sealer(key.as_ref(), iv)
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        self.opener(key.as_ref(), iv)
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape { enc_key_len: self.mac.len(), fixed_iv_len: self.key_len, explicit_nonce_len: 0 }
    }

    fn extract_keys(&self, _key: AeadKey, _iv: &[u8], _explicit: &[u8]) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }
}

enum Cipher {
    Aes128(Box<Aes128>),
    Aes256(Box<Aes256>),
}

impl Cipher {
    fn new(key: &[u8]) -> Cipher {
        match key.len() {
            16 => Cipher::Aes128(Box::new(Aes128::new_from_slice(key).expect("16 bytes"))),
            _ => Cipher::Aes256(Box::new(Aes256::new_from_slice(key).expect("32 bytes"))),
        }
    }

    fn encrypt(&self, block: &mut [u8; BLOCK]) {
        let mut b = Array::from(*block);
        match self {
            Cipher::Aes128(c) => c.encrypt_block(&mut b),
            Cipher::Aes256(c) => c.encrypt_block(&mut b),
        }
        block.copy_from_slice(&b);
    }

    fn decrypt(&self, block: &mut [u8; BLOCK]) {
        let mut b = Array::from(*block);
        match self {
            Cipher::Aes128(c) => c.decrypt_block(&mut b),
            Cipher::Aes256(c) => c.decrypt_block(&mut b),
        }
        block.copy_from_slice(&b);
    }
}

/// `HMAC(mac_key, aad || fragment)`.
fn compute_mac(mac: Hash, key: &[u8], aad: &[u8; 13], fragment: &[u8]) -> Vec<u8> {
    match mac {
        Hash::Sha1 => {
            let mut h = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
            h.update(aad);
            h.update(fragment);
            h.finalize().into_bytes().to_vec()
        }
        Hash::Sha256 => {
            let mut h = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
            h.update(aad);
            h.update(fragment);
            h.finalize().into_bytes().to_vec()
        }
    }
}

struct Encrypter {
    mac: Hash,
    mac_key: Vec<u8>,
    cipher: Cipher,
}

impl MessageEncrypter for Encrypter {
    fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let fragment = msg.payload.to_vec();
        let aad = make_tls12_aad(seq, msg.typ, msg.version, fragment.len());
        let mac = compute_mac(self.mac, &self.mac_key, &aad, &fragment);

        // fragment || mac || padding (each padding byte holds the padding length, the last one included)
        let mut plain = fragment;
        plain.extend_from_slice(&mac);
        let padding = BLOCK - plain.len() % BLOCK;
        plain.extend(std::iter::repeat_n((padding - 1) as u8, padding));

        let mut iv = [0u8; BLOCK];
        rustls::crypto::ring::default_provider().secure_random.fill(&mut iv).map_err(|_| rustls::Error::FailedToGetRandomBytes)?;

        let mut payload = PrefixedPayload::with_capacity(self.encrypted_payload_len(plain.len() - mac.len() - padding));
        payload.extend_from_slice(&iv);
        let mut previous = iv;
        for chunk in plain.as_chunks::<BLOCK>().0 {
            let mut block = [0u8; BLOCK];
            for i in 0..BLOCK {
                block[i] = chunk[i] ^ previous[i];
            }
            self.cipher.encrypt(&mut block);
            payload.extend_from_slice(&block);
            previous = block;
        }
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        BLOCK + (payload_len + self.mac.len() + 1).div_ceil(BLOCK) * BLOCK
    }
}


thread_local! {
    static COMPRESSIONS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The number of hash compression calls `ct_hmac` made on this thread (instrumentation for the tests).
pub fn compressions() -> u64 {
    COMPRESSIONS.get()
}

#[derive(Clone, Copy)]
enum State {
    Sha1([u32; 5]),
    Sha256([u32; 8]),
}

impl State {
    fn new(hash: Hash) -> State {
        match hash {
            Hash::Sha1 => State::Sha1([0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0]),
            Hash::Sha256 => State::Sha256([
                0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
            ]),
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        COMPRESSIONS.set(COMPRESSIONS.get() + 1);
        let block = GenericArray::clone_from_slice(block);
        match self {
            State::Sha1(s) => sha1::compress(s, std::slice::from_ref(&block)),
            State::Sha256(s) => sha2::compress256(s, std::slice::from_ref(&block)),
        }
    }

    fn select(a: &State, b: &State, pick_b: Choice) -> State {
        match (a, b) {
            (State::Sha1(x), State::Sha1(y)) => State::Sha1(std::array::from_fn(|i| u32::conditional_select(&x[i], &y[i], pick_b))),
            (State::Sha256(x), State::Sha256(y)) => State::Sha256(std::array::from_fn(|i| u32::conditional_select(&x[i], &y[i], pick_b))),
            _ => unreachable!("one hash"),
        }
    }

    fn to_bytes(self) -> Vec<u8> {
        match self {
            State::Sha1(s) => s.iter().flat_map(|w| w.to_be_bytes()).collect(),
            State::Sha256(s) => s.iter().flat_map(|w| w.to_be_bytes()).collect(),
        }
    }
}

/// `HMAC(key, m[..len])` where `len` is secret and lies in `m.len() - 256 ..= m.len()` (`m.len()` is public): the inner
/// hash compresses `(m.len() + 9).div_ceil(64)` blocks whatever `len` is. Keys up to 64 bytes.
fn ct_hmac(hash: Hash, key: &[u8], m: &[u8], len: usize) -> Vec<u8> {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    let mut state = State::new(hash);
    state.compress(&ipad);

    let len32 = len as u32;
    // the padded message is whole blocks: len + 0x80 + zeros + 8 length bytes; the bit length counts the ipad block
    let padded = (len + 9).div_ceil(64) * 64;
    let last_block = (padded >> 6) as u32 - 1;
    let bit_len = (len as u64 + 64) * 8;
    let mut result = state;
    for b in 0..(m.len() + 9).div_ceil(64) {
        let mut block = [0u8; 64];
        for (k, out) in block.iter_mut().enumerate() {
            let pos = b * 64 + k;
            let data = m.get(pos).copied().unwrap_or(0);
            let is_data = (pos as u32).ct_lt(&len32);
            let is_marker = (pos as u32).ct_eq(&len32);
            // distance from the end of the padded message, 0 for its last byte; huge past the end
            let from_end = (padded as u32).wrapping_sub(1).wrapping_sub(pos as u32);
            let in_length = from_end.ct_lt(&8);
            let length_byte = (bit_len >> ((from_end & 7) * 8)) as u8;
            let tail = u8::conditional_select(&0, &length_byte, in_length);
            let tail = u8::conditional_select(&tail, &0x80, is_marker);
            *out = u8::conditional_select(&tail, &data, is_data);
        }
        state.compress(&block);
        result = State::select(&result, &state, (b as u32).ct_eq(&last_block));
    }
    let inner = result.to_bytes();
    match hash {
        Hash::Sha1 => Sha1::new().chain_update(opad).chain_update(&inner).finalize().to_vec(),
        Hash::Sha256 => Sha256::new().chain_update(opad).chain_update(&inner).finalize().to_vec(),
    }
}

impl AesCbc {
    /// `HMAC(key, aad || fragment)` by the `hmac` crate, the reference the constant-time MAC is tested against.
    pub fn reference_mac(&self, key: &[u8], aad: &[u8; 13], fragment: &[u8]) -> Vec<u8> {
        compute_mac(self.mac, key, aad, fragment)
    }

    /// `HMAC(key, aad || data[..data_len])` with a compression count that does not depend on `data_len` (which must be
    /// within 256 of `data.len()`); exposed for the tests.
    pub fn constant_time_mac(&self, key: &[u8], aad: &[u8; 13], data: &[u8], data_len: usize) -> Vec<u8> {
        let mut m = aad.to_vec();
        m.extend_from_slice(data);
        ct_hmac(self.mac, key, &m, 13 + data_len)
    }
}

struct Decrypter {
    mac: Hash,
    mac_key: Vec<u8>,
    cipher: Cipher,
}

impl MessageDecrypter for Decrypter {
    fn decrypt<'a>(&mut self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let mac_len = self.mac.len();
        let total = msg.payload.len();
        // public lengths only: the explicit IV, whole blocks, room for the MAC and one padding byte
        if total < BLOCK + (mac_len + 1).div_ceil(BLOCK) * BLOCK || !(total - BLOCK).is_multiple_of(BLOCK) {
            return Err(rustls::Error::DecryptError);
        }

        // CBC decryption from the last block back, so each block's predecessor is still ciphertext
        // Timing note: on Apple silicon this in-place pass (not a branch of ours; cause in the CPU not proven) runs about one timer tick (35-40 ns of ~33 us) faster when
        // the padding is 254..256 bytes (the plaintext written back ends in 0xfd..0xff runs), also with a wrong MAC; the same pass out
        // of place, the AES block alone, the padding check, the tag select and the MAC are flat (examples/cbc_timing.rs, CBC_TIMING_STAGES=1).
        {
            let payload: &mut [u8] = &mut msg.payload;
            for i in (1..total / BLOCK).rev() {
                let mut block = [0u8; BLOCK];
                block.copy_from_slice(&payload[i * BLOCK..(i + 1) * BLOCK]);
                self.cipher.decrypt(&mut block);
                for j in 0..BLOCK {
                    block[j] ^= payload[(i - 1) * BLOCK + j];
                }
                payload[i * BLOCK..(i + 1) * BLOCK].copy_from_slice(&block);
            }
        }

        let plain = &msg.payload[BLOCK..];
        let n = plain.len();
        let last = plain[n - 1];

        // the padding is `last + 1` bytes all equal to `last`, and leaves room for the MAC; checked over the last 256
        // bytes whatever the claimed length, accumulating into one flag
        let fits = (last as u32 + 1 + mac_len as u32).ct_lt(&(n as u32 + 1));
        let mut good = fits;
        for i in 0..n.min(256) {
            let in_padding = (i as u32).ct_lt(&(last as u32 + 1));
            let same = plain[n - 1 - i].ct_eq(&last);
            good &= !in_padding | same;
        }
        // a bad padding counts as none: the MAC is then computed over everything before it
        let padding = u32::conditional_select(&0, &(last as u32 + 1), good) as usize;
        let data_len = n - mac_len - padding;

        let aad = make_tls12_aad(seq, msg.typ, msg.version, data_len);
        let mut m = aad.to_vec();
        m.extend_from_slice(&plain[..n - mac_len]);
        let expected = ct_hmac(self.mac, &self.mac_key, &m, 13 + data_len);
        // the received tag sits at `data_len`, a secret offset: pick it out of the last `mac_len + 256` bytes with selects
        let mut received = vec![0u8; mac_len];
        for (i, plain_byte) in plain.iter().enumerate().skip(n.saturating_sub(mac_len + 256)) {
            for (j, byte) in received.iter_mut().enumerate() {
                let here = (i as u32).ct_eq(&((data_len + j) as u32));
                *byte = u8::conditional_select(byte, plain_byte, here);
            }
        }
        let mac_ok: Choice = expected.as_slice().ct_eq(&received);

        if !bool::from(good & mac_ok) {
            return Err(rustls::Error::DecryptError);
        }
        if data_len > MAX_FRAGMENT {
            return Err(rustls::Error::PeerSentOversizedRecord);
        }
        Ok(msg.into_plain_message_range(BLOCK..BLOCK + data_len))
    }
}

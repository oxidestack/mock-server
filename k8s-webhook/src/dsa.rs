//! A DSA serving key and the TLS 1.2 DHE-DSS handshake that goes with it.
//!
//! The JDK behind upstream's webhook image signs a TLS 1.2 ServerKeyExchange with a DSA key (`dsa_sha224` and
//! `dsa_sha256`, the first the client lists) and agrees a finite-field Diffie-Hellman secret over ffdhe2048, so a client
//! offering a `TLS_DHE_DSS_*` suite is served. rustls has neither DSA signatures nor a DHE suite of its own, but its
//! provider traits allow both: this module is a DSA signer, an ffdhe2048 key exchange group and the six DHE-DSS suites
//! (two GCM, four CBC with `cbc.rs`' record layer).
//!
//! rustls knows no DSA scheme (`SignatureScheme::algorithm()` is `None` for them), and it drops such schemes from the
//! ClientHello list it hands the certificate resolver and the suite's signing step unless a TLS 1.3 suite is among the
//! ones in common. So:
//! - the ServerKeyExchange is signed with the scheme `server::handshake` read off the whole ClientHello and left in
//!   a thread-local (`remember_client_schemes`) for the synchronous `into_stream` call that follows, the first
//!   `dsa_sha224` / `dsa_sha256` the client lists, as the JDK takes it;
//! - the key presents itself as an Ed448 key, and the suites list every scheme the JDK knows in their `sign`, so
//!   rustls' own check passes for any client; stand-in TLS 1.3 suites with the TLS 1.2 suites' ids (`scheme_keepers`)
//!   keep the schemes rustls has no name for in the list, so a client listing only DSA schemes is served;
//! - a client with a DHE-DSS suite but no `dsa_sha224` / `dsa_sha256` gets what the JDK sends it: `internal_error` after
//!   the Certificate when it lists a scheme the JDK knows (the signer fails, and `server::handshake` writes the flight
//!   and the alert rustls cannot send), `handshake_failure` before the ServerHello otherwise (no suite is usable with the key).

use num_bigint::BigUint;
use rustls::crypto::{ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup};
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{CipherSuite, CipherSuiteCommon, NamedGroup, SignatureAlgorithm, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite};
use sha2::{Digest, Sha224, Sha256};
use std::sync::{Arc, OnceLock};

/// `dsa_sha224` (RFC 5246 hash 3, signature 2).
pub const DSA_SHA224: SignatureScheme = SignatureScheme::Unknown(0x0302);
/// `dsa_sha256`.
pub const DSA_SHA256: SignatureScheme = SignatureScheme::Unknown(0x0402);

/// A DSA private key with its domain parameters.
#[derive(Clone)]
pub struct DsaKey {
    p: BigUint,
    q: BigUint,
    g: BigUint,
    y: BigUint,
    x: BigUint,
}

impl std::fmt::Debug for DsaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DsaKey").field("p_bits", &self.p.bits()).field("q_bits", &self.q.bits()).finish_non_exhaustive()
    }
}

impl DsaKey {
    /// A traditional `DSA PRIVATE KEY` (`SEQUENCE { 0, p, q, g, y, x }`) or a PKCS#8 `PrivateKeyInfo` holding one.
    pub fn from_der(der: &[u8]) -> Option<DsaKey> {
        let (_, seq) = tlv(der, 0x30)?;
        let (rest, version) = tlv(seq, 0x02)?;
        if version != [0] {
            return None;
        }
        if rest.first() == Some(&0x30) {
            // PKCS#8: AlgorithmIdentifier { dsa OID, Dss-Parms { p, q, g } }, OCTET STRING { INTEGER x }
            let (rest, alg) = tlv(rest, 0x30)?;
            let (params, oid) = tlv(alg, 0x06)?;
            if oid != [0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01] {
                return None;
            }
            let (_, params) = tlv(params, 0x30)?;
            let (params, p) = tlv(params, 0x02)?;
            let (params, q) = tlv(params, 0x02)?;
            let (_, g) = tlv(params, 0x02)?;
            let (_, octets) = tlv(rest, 0x04)?;
            let (_, x) = tlv(octets, 0x02)?;
            let (p, q, g, x) = (BigUint::from_bytes_be(p), BigUint::from_bytes_be(q), BigUint::from_bytes_be(g), BigUint::from_bytes_be(x));
            let y = g.modpow(&x, &p);
            return DsaKey::checked(p, q, g, y, x);
        }
        let (rest, p) = tlv(rest, 0x02)?;
        let (rest, q) = tlv(rest, 0x02)?;
        let (rest, g) = tlv(rest, 0x02)?;
        let (rest, y) = tlv(rest, 0x02)?;
        let (rest, x) = tlv(rest, 0x02)?;
        if !rest.is_empty() {
            return None;
        }
        DsaKey::checked(
            BigUint::from_bytes_be(p),
            BigUint::from_bytes_be(q),
            BigUint::from_bytes_be(g),
            BigUint::from_bytes_be(y),
            BigUint::from_bytes_be(x),
        )
    }

    fn checked(p: BigUint, q: BigUint, g: BigUint, y: BigUint, x: BigUint) -> Option<DsaKey> {
        let one = BigUint::from(1u8);
        (q > one && p > q && g > one && g < p && x > BigUint::from(0u8) && x < q).then_some(DsaKey { p, q, g, y, x })
    }

    /// `sign` with the ring provider's randomness.
    pub fn sign_with_system_random(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let random = rustls::crypto::ring::default_provider().secure_random;
        let failed = std::cell::Cell::new(false);
        let signature = self.sign(scheme, message, &|buf| {
            if random.fill(buf).is_err() {
                failed.set(true);
            }
        });
        if failed.get() { Err(rustls::Error::FailedToGetRandomBytes) } else { Ok(signature) }
    }

    /// A DER `Dss-Sig-Value` over `message` hashed with the scheme's digest (FIPS 186-4: the digest's leftmost
    /// `bits(q)` bits).
    fn sign(&self, scheme: SignatureScheme, message: &[u8], random: &dyn Fn(&mut [u8])) -> Vec<u8> {
        let digest: Vec<u8> = if scheme == DSA_SHA224 { Sha224::digest(message).to_vec() } else { Sha256::digest(message).to_vec() };
        let mut z = BigUint::from_bytes_be(&digest);
        let digest_bits = digest.len() as u64 * 8;
        if digest_bits > self.q.bits() {
            z >>= digest_bits - self.q.bits();
        }
        let one = BigUint::from(1u8);
        let q_minus_1 = &self.q - &one;
        let q_minus_2 = &self.q - BigUint::from(2u8);
        loop {
            let mut buf = vec![0u8; (self.q.bits() as usize + 64).div_ceil(8)];
            random(&mut buf);
            let k = BigUint::from_bytes_be(&buf) % &q_minus_1 + &one;
            let r = self.g.modpow(&k, &self.p) % &self.q;
            if r == BigUint::from(0u8) {
                continue;
            }
            let k_inv = k.modpow(&q_minus_2, &self.q);
            let s = k_inv * ((&z + &self.x * &r) % &self.q) % &self.q;
            if s == BigUint::from(0u8) {
                continue;
            }
            let mut body = der_integer(&r);
            body.extend(der_integer(&s));
            return der_wrap(0x30, &body);
        }
    }

    /// Whether `signature` (a DER `Dss-Sig-Value`) is this key's over `message` (tests, and clients that check it).
    pub fn verify(&self, scheme: SignatureScheme, message: &[u8], signature: &[u8]) -> bool {
        let Some((_, seq)) = tlv(signature, 0x30) else { return false };
        let Some((rest, r)) = tlv(seq, 0x02) else { return false };
        let Some((_, s)) = tlv(rest, 0x02) else { return false };
        let (r, s) = (BigUint::from_bytes_be(r), BigUint::from_bytes_be(s));
        let zero = BigUint::from(0u8);
        if r == zero || s == zero || r >= self.q || s >= self.q {
            return false;
        }
        let digest: Vec<u8> = if scheme == DSA_SHA224 { Sha224::digest(message).to_vec() } else { Sha256::digest(message).to_vec() };
        let mut z = BigUint::from_bytes_be(&digest);
        let digest_bits = digest.len() as u64 * 8;
        if digest_bits > self.q.bits() {
            z >>= digest_bits - self.q.bits();
        }
        let w = s.modpow(&(&self.q - BigUint::from(2u8)), &self.q);
        let u1 = z * &w % &self.q;
        let u2 = &r * &w % &self.q;
        let v = (self.g.modpow(&u1, &self.p) * self.y.modpow(&u2, &self.p) % &self.p) % &self.q;
        v == r
    }
}

/// What the ClientHello's whole scheme list says to a DSA key: the DSA scheme the JDK signs with (the first
/// `dsa_sha224` / `dsa_sha256` listed) and whether the list names any scheme the JDK knows that is not a usable
/// DSA one (an RSA, RSASSA-PSS, ECDSA or EdDSA scheme; SHA-1 and the other DSA hashes are not among them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClientSchemes {
    dsa: Option<SignatureScheme>,
    jdk_knows_another: bool,
}

impl ClientSchemes {
    fn of(offered: &[SignatureScheme]) -> ClientSchemes {
        ClientSchemes {
            dsa: offered.iter().copied().find(|s| *s == DSA_SHA224 || *s == DSA_SHA256),
            jdk_knows_another: offered.iter().any(|s| JDK_KNOWN.contains(&u16::from(*s))),
        }
    }
}

/// The signature schemes of the image's JDK that are not DSA and not SHA-1 (probed against `mockserver-webhook` 9.2.0
/// with a DSA pair: a client listing a DHE-DSS suite and one of these but no `dsa_sha224` / `dsa_sha256` gets an
/// `internal_error` after the Certificate; with only SHA-1 schemes, `dsa_sha384`/`dsa_sha512` or brainpool ones, a
/// `handshake_failure` before the ServerHello).
const JDK_KNOWN: &[u16] = &[
    0x0301, 0x0401, 0x0501, 0x0601, // rsa_pkcs1_sha224/256/384/512
    0x0303, 0x0403, 0x0503, 0x0603, // ecdsa_sha224, ecdsa_secp256r1/384r1/521r1
    0x0804, 0x0805, 0x0806, 0x0809, 0x080a, 0x080b, // rsa_pss_rsae_*, rsa_pss_pss_*
    0x0807, 0x0808, // ed25519, ed448
];

/// The message of the error a DSA key's signer returns for a client the JDK answers with `internal_error`: rustls has
/// no way to send that alert, so `server::handshake` sends it itself after the flight rustls has already queued.
pub const INTERNAL_ERROR_MARKER: &str = "dsa: internal_error after the Certificate";

thread_local! {
    /// The ClientHello's schemes for the handshake being accepted on this thread.
    static CLIENT_DSA: std::cell::Cell<Option<ClientSchemes>> = const { std::cell::Cell::new(None) };
}

/// Whether a server config's certificate resolver is a DSA key's (`DsaKeyEntry`, whose `Debug` is its bare name).
pub fn is_dsa_resolver(resolver: &dyn rustls::server::ResolvesServerCert) -> bool {
    format!("{resolver:?}") == "DsaKeyEntry"
}

/// What the DSA path reads off the ClientHello record as the client sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloInfo {
    /// whether its `supported_versions` extension, if any, lists TLS 1.2 or older (no extension: a legacy
    /// `client_version`, which rustls answers itself)
    pub offers_tls12: bool,
    pub suites: Vec<u16>,
    /// the extension types, in the client's order
    pub extensions: Vec<u16>,
}

impl HelloInfo {
    /// Parses one whole ClientHello handshake message (the records it came in joined by `tls13::reassemble`); `None`
    /// when the bytes are not that.
    pub fn parse(message: &[u8]) -> Option<HelloInfo> {
        fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
            let (head, rest) = (data.get(..n)?, data.get(n..)?);
            *data = rest;
            Some(head)
        }
        fn len_prefixed<'a>(data: &mut &'a [u8], width: usize) -> Option<&'a [u8]> {
            let n = take(data, width)?.iter().fold(0usize, |a, b| (a << 8) | *b as usize);
            take(data, n)
        }
        let mut body = message;
        if take(&mut body, 1)? != [1] {
            return None;
        }
        let mut hello = len_prefixed(&mut body, 3)?;
        take(&mut hello, 2 + 32)?;
        len_prefixed(&mut hello, 1)?;
        let suites = len_prefixed(&mut hello, 2)?.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        len_prefixed(&mut hello, 1)?;
        let mut info = HelloInfo { offers_tls12: true, suites, extensions: Vec::new() };
        let mut extensions = len_prefixed(&mut hello, 2).unwrap_or_default();
        while !extensions.is_empty() {
            let kind = take(&mut extensions, 2)?;
            let mut data = len_prefixed(&mut extensions, 2)?;
            info.extensions.push(u16::from_be_bytes([kind[0], kind[1]]));
            if kind == [0x00, 0x2b] {
                let versions = len_prefixed(&mut data, 1)?;
                info.offers_tls12 = versions.as_chunks::<2>().0.iter().any(|v| v[0] == 0x03 && v[1] <= 0x03);
            }
        }
        Some(info)
    }

    /// The suite the handshake settles on: the first the client lists of the DHE-DSS ones served.
    fn chosen_suite(&self) -> Option<u16> {
        self.suites.iter().copied().find(|s| SERVED_SUITES.contains(s))
    }
}

/// `TLS_DHE_DSS_WITH_AES_128_CBC_SHA`, `_256_CBC_SHA`, `_128_CBC_SHA256`, `_256_CBC_SHA256`, `_128_GCM_SHA256`,
/// `_256_GCM_SHA384`.
const SERVED_SUITES: [u16; 6] = [0x0032, 0x0038, 0x0040, 0x006a, 0x00a2, 0x00a3];

/// The bytes the JDK sends a client it answers with `internal_error`: one handshake record holding its ServerHello and
/// Certificate, then the alert, all in the clear. rustls cannot send this alert and writes nothing of the flight when its
/// signing step fails, so `server::handshake` sends all of it (the ServerHello as the JDK builds it: a fresh random
/// session id, and of `extended_master_secret`, `session_ticket` and `renegotiation_info` those the client offered).
pub fn internal_error_flight(hello: &HelloInfo, chain: &[rustls_pki_types::CertificateDer<'static>]) -> Option<Vec<u8>> {
    let random = rustls::crypto::ring::default_provider().secure_random;
    let mut server_random = [0u8; 32];
    let mut session_id = [0u8; 32];
    random.fill(&mut server_random).ok()?;
    random.fill(&mut session_id).ok()?;

    let mut extensions = Vec::new();
    if hello.extensions.contains(&0x0017) {
        extensions.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
    }
    if hello.extensions.contains(&0x0023) {
        extensions.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);
    }
    if hello.extensions.contains(&0xff01) || hello.suites.contains(&0x00ff) {
        extensions.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);
    }
    let mut server_hello = vec![0x03, 0x03];
    server_hello.extend_from_slice(&server_random);
    server_hello.push(32);
    server_hello.extend_from_slice(&session_id);
    server_hello.extend_from_slice(&hello.chosen_suite()?.to_be_bytes());
    server_hello.push(0);
    if !extensions.is_empty() {
        server_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        server_hello.extend_from_slice(&extensions);
    }

    let mut certs = Vec::new();
    for cert in chain {
        certs.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
        certs.extend_from_slice(cert);
    }
    let mut certificate = (certs.len() as u32).to_be_bytes()[1..].to_vec();
    certificate.extend_from_slice(&certs);

    let mut handshake = Vec::new();
    for (kind, body) in [(2u8, &server_hello), (11u8, &certificate)] {
        handshake.push(kind);
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(body);
    }
    // handshake records hold at most 2^14 bytes; a long chain goes over several
    let mut out = Vec::new();
    for fragment in handshake.chunks(16384) {
        out.extend_from_slice(&[0x16, 0x03, 0x03]);
        out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(fragment);
    }
    out.extend_from_slice(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x50]);
    Some(out)
}

/// Notes the schemes for the handshake `into_stream` starts, from the ClientHello's whole scheme list.
pub fn remember_client_schemes(offered: &[SignatureScheme]) {
    CLIENT_DSA.set(Some(ClientSchemes::of(offered)));
}

/// Forgets it once `into_stream` has returned.
pub fn forget_client_schemes() {
    CLIENT_DSA.set(None);
}

/// The key store's entry for a DSA key whose certificate is a DSA one.
pub struct DsaKeyEntry {
    chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    key: DsaKey,
}

impl std::fmt::Debug for DsaKeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DsaKeyEntry")
    }
}

impl DsaKeyEntry {
    pub fn new(chain: Vec<rustls_pki_types::CertificateDer<'static>>, key: DsaKey) -> DsaKeyEntry {
        DsaKeyEntry { chain, key }
    }
}

impl rustls::server::ResolvesServerCert for DsaKeyEntry {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // outside `into_stream` (the acceptor's own check) the list is the client's whole one
        let schemes = CLIENT_DSA.get().unwrap_or_else(|| ClientSchemes::of(client_hello.signature_schemes()));
        let signing = DsaSigningKey { key: self.key.clone(), schemes };
        Some(Arc::new(CertifiedKey::new(self.chain.clone(), Arc::new(signing))))
    }
}

#[derive(Debug)]
struct DsaSigningKey {
    key: DsaKey,
    schemes: ClientSchemes,
}

impl SigningKey for DsaSigningKey {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        match self.schemes.dsa {
            Some(scheme) => Some(Box::new(DsaSigner { key: self.key.clone(), scheme })),
            // the JDK gets as far as the ServerKeyExchange and fails there
            None if self.schemes.jdk_knows_another => Some(Box::new(FailingSigner)),
            None => None,
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        // no suite signs with DSA in rustls' terms: with no scheme to sign with (and none the JDK would try), none is
        // usable and the handshake ends with `handshake_failure` before the ServerHello
        if self.schemes.dsa.is_some() || self.schemes.jdk_knows_another { SignatureAlgorithm::ED448 } else { SignatureAlgorithm::DSA }
    }
}

/// Signs nothing: the ServerKeyExchange of a client the JDK answers with `internal_error`.
#[derive(Debug)]
struct FailingSigner;

impl Signer for FailingSigner {
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Err(rustls::Error::General(INTERNAL_ERROR_MARKER.to_string()))
    }

    fn scheme(&self) -> SignatureScheme {
        DSA_SHA256
    }
}

#[derive(Debug)]
struct DsaSigner {
    key: DsaKey,
    scheme: SignatureScheme,
}

impl Signer for DsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.key.sign_with_system_random(self.scheme, message)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

// ---- ffdhe2048 key exchange ----

/// RFC 7919 ffdhe2048 as a key exchange group, offered under the name of every ffdhe group the JDK knows: the image
/// answers a client listing only ffdhe3072, 4096, 6144 or 8192 with ffdhe2048 parameters all the same (the
/// ServerKeyExchange carries the prime and generator, not the group's name), and rustls picks a group by its name.
#[derive(Debug)]
pub struct Ffdhe2048(NamedGroup);

static FFDHE_GROUPS: [Ffdhe2048; 5] = [
    Ffdhe2048(NamedGroup::FFDHE2048),
    Ffdhe2048(NamedGroup::FFDHE3072),
    Ffdhe2048(NamedGroup::FFDHE4096),
    Ffdhe2048(NamedGroup::FFDHE6144),
    Ffdhe2048(NamedGroup::FFDHE8192),
];

impl SupportedKxGroup for Ffdhe2048 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let group = rustls::ffdhe_groups::FFDHE2048;
        let p = BigUint::from_bytes_be(group.p);
        let g = BigUint::from_bytes_be(group.g);
        let mut buf = [0u8; 40];
        rustls::crypto::ring::default_provider().secure_random.fill(&mut buf).map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
        let x = BigUint::from_bytes_be(&buf) | BigUint::from(1u8);
        let public = pad(&g.modpow(&x, &p), group.p.len());
        Ok(Box::new(ActiveFfdhe { p, x, public, name: self.0 }))
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        Some(rustls::ffdhe_groups::FFDHE2048)
    }

    fn name(&self) -> NamedGroup {
        self.0
    }
}

struct ActiveFfdhe {
    p: BigUint,
    x: BigUint,
    public: Vec<u8>,
    name: NamedGroup,
}

impl ActiveKeyExchange for ActiveFfdhe {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let y = BigUint::from_bytes_be(peer_pub_key);
        if y < BigUint::from(2u8) || y > &self.p - BigUint::from(2u8) {
            return Err(rustls::Error::General("invalid Diffie-Hellman public value".to_string()));
        }
        let secret = pad(&y.modpow(&self.x, &self.p), self.public.len());
        Ok(SharedSecret::from(secret.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        Some(rustls::ffdhe_groups::FFDHE2048)
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}

fn pad(n: &BigUint, len: usize) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    let mut out = vec![0u8; len.saturating_sub(bytes.len())];
    out.extend(bytes);
    out
}

// ---- the provider ----

static SUITES: OnceLock<[&'static Tls12CipherSuite; 6]> = OnceLock::new();

/// `TLS_DHE_DSS_WITH_AES_{128,256}_GCM_*` (built from the ring provider's ECDHE_RSA suites: same AEAD and PRF) and the
/// four CBC ones (`cbc.rs`; TLS 1.2's PRF is HMAC-SHA256 for them all, so the SHA-256 GCM suite supplies it).
fn suites() -> &'static [&'static Tls12CipherSuite; 6] {
    SUITES.get_or_init(|| {
        let base = |suite: CipherSuite| -> &'static Tls12CipherSuite {
            match rustls::crypto::ring::default_provider().cipher_suites.iter().find(|s| s.suite() == suite) {
                Some(SupportedCipherSuite::Tls12(s)) => s,
                _ => unreachable!("the ring provider has {suite:?}"),
            }
        };
        // everything a client may list that the JDK knows, so that rustls' own check (a scheme in common) passes for
        // a client listing only DSA schemes, or only ones the JDK knows but rustls does not name
        const SIGN: &[SignatureScheme] = &[
            DSA_SHA224,
            DSA_SHA256,
            SignatureScheme::Unknown(0x0301),
            SignatureScheme::Unknown(0x0303),
            SignatureScheme::Unknown(0x0809),
            SignatureScheme::Unknown(0x080a),
            SignatureScheme::Unknown(0x080b),
            SignatureScheme::ED448,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ];
        let make = |from: CipherSuite, suite: CipherSuite| -> &'static Tls12CipherSuite {
            let b = base(from);
            Box::leak(Box::new(Tls12CipherSuite {
                common: CipherSuiteCommon { suite, hash_provider: b.common.hash_provider, confidentiality_limit: b.common.confidentiality_limit },
                prf_provider: b.prf_provider,
                kx: rustls::crypto::KeyExchangeAlgorithm::DHE,
                sign: SIGN,
                aead_alg: b.aead_alg,
            }))
        };
        let cbc = |suite: CipherSuite, aead_alg: &'static dyn rustls::crypto::cipher::Tls12AeadAlgorithm| -> &'static Tls12CipherSuite {
            let b = base(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
            Box::leak(Box::new(Tls12CipherSuite {
                common: CipherSuiteCommon { suite, hash_provider: b.common.hash_provider, confidentiality_limit: u64::MAX },
                prf_provider: b.prf_provider,
                kx: rustls::crypto::KeyExchangeAlgorithm::DHE,
                sign: SIGN,
                aead_alg,
            }))
        };
        [
            make(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite::TLS_DHE_DSS_WITH_AES_128_GCM_SHA256),
            make(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, CipherSuite::TLS_DHE_DSS_WITH_AES_256_GCM_SHA384),
            cbc(CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, &crate::cbc::AES_128_CBC_SHA256),
            cbc(CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, &crate::cbc::AES_256_CBC_SHA256),
            cbc(CipherSuite::TLS_DHE_DSS_WITH_AES_128_CBC_SHA, &crate::cbc::AES_128_CBC_SHA),
            cbc(CipherSuite::TLS_DHE_DSS_WITH_AES_256_CBC_SHA, &crate::cbc::AES_256_CBC_SHA),
        ]
    })
}

/// One TLS 1.3 suite per DHE-DSS suite id, never negotiated (the server config enables TLS 1.2 only, and a TLS 1.3 suite
/// is never picked for a TLS 1.2 handshake). rustls drops from the ClientHello's scheme list every scheme it has no name
/// for (`dsa_sha224`, `dsa_sha256`, `rsa_pkcs1_sha224`, ...) unless one of the suites in common is a TLS 1.3 one, and
/// then answers a client that lists only such schemes with `handshake_failure`; the JDK serves a client listing only
/// DSA schemes. These stand-ins carry the TLS 1.2 suites' ids, so a client offering a DHE-DSS suite has a "TLS 1.3
/// suite in common" and its DSA schemes reach the signing step.
fn scheme_keepers() -> &'static [&'static rustls::Tls13CipherSuite; 6] {
    static KEEPERS: OnceLock<[&'static rustls::Tls13CipherSuite; 6]> = OnceLock::new();
    KEEPERS.get_or_init(|| {
        let base = match rustls::crypto::ring::default_provider().cipher_suites.iter().find(|s| s.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256) {
            Some(SupportedCipherSuite::Tls13(s)) => *s,
            _ => unreachable!("the ring provider has TLS13_AES_128_GCM_SHA256"),
        };
        let keeper = |id: CipherSuite| -> &'static rustls::Tls13CipherSuite {
            Box::leak(Box::new(rustls::Tls13CipherSuite {
                common: CipherSuiteCommon { suite: id, hash_provider: base.common.hash_provider, confidentiality_limit: base.common.confidentiality_limit },
                hkdf_provider: base.hkdf_provider,
                aead_alg: base.aead_alg,
                quic: None,
            }))
        };
        let ids = (*suites()).map(|s| s.common.suite);
        [keeper(ids[0]), keeper(ids[1]), keeper(ids[2]), keeper(ids[3]), keeper(ids[4]), keeper(ids[5])]
    })
}

/// A TLS 1.2 provider with the DHE-DSS suites and ffdhe2048 only.
pub fn provider() -> CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = suites()
        .iter()
        .map(|s| SupportedCipherSuite::Tls12(s))
        .chain(scheme_keepers().iter().map(|s| SupportedCipherSuite::Tls13(s)))
        .collect();
    provider.kx_groups = FFDHE_GROUPS.iter().map(|g| g as &'static dyn SupportedKxGroup).collect();
    provider
}

// ---- DER ----

fn tlv(data: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if *data.first()? != tag {
        return None;
    }
    let first = *data.get(1)? as usize;
    let (len, header) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7F;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *data.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let contents = data.get(header..header.checked_add(len)?)?;
    Some((&data[header + len..], contents))
}

fn der_wrap(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 0x80 {
        out.push(body.len() as u8);
    } else {
        let len = body.len().to_be_bytes();
        let len: Vec<u8> = len.iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | len.len() as u8);
        out.extend(len);
    }
    out.extend_from_slice(body);
    out
}

fn der_integer(n: &BigUint) -> Vec<u8> {
    let mut bytes = n.to_bytes_be();
    if bytes.first().is_none_or(|b| b & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    der_wrap(0x02, &bytes)
}

//! TLS for broker clients: Java key stores (JKS and PKCS#12, told apart by content as the JDK's dual-format
//! `KeyStore` does) and the rustls client configuration a JSSE `SSLContext` with those stores amounts to.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use super::broker::{Error, ErrorKind};

/// A loaded key store: its trusted certificates and its private keys with their chains.
#[derive(Default)]
pub struct KeyStore {
    pub certificates: Vec<CertificateDer<'static>>,
    pub keys: Vec<(PrivateKeyDer<'static>, Vec<CertificateDer<'static>>)>,
    /// Private key entries the store password does not recover (a JKS key with a password of its own) or that
    /// were loaded without a password: what `SunX509`'s `KeyManagerFactory.init` fails on.
    pub unrecoverable_keys: usize,
    /// A JCEKS file.
    pub jceks: bool,
    /// A PKCS#12 file, whose unrecoverable keys fail `PKCS12KeyStore.engineGetKey` (`Get Key failed: …`) rather than
    /// JKS's `Cannot recover key`.
    pub pkcs12: bool,
    /// The private key entries in `KeyStore.aliases()` order, for a key manager's choice ([`KeyManager`]).
    pub entries: Vec<KeyEntry>,
}

/// A private key entry: its alias, the key (`None` when the password does not recover it) and its chain.
pub struct KeyEntry {
    pub alias: String,
    pub key: Option<PrivateKeyDer<'static>>,
    pub chain: Vec<CertificateDer<'static>>,
}

/// `KeyStore.load`: a JKS (`0xFEEDFEED`), JCEKS (`0xCECECECE`) or PKCS#12 file.
pub async fn load_keystore(path: &str, password: Option<&str>) -> Result<KeyStore, Error> {
    let data = tokio::fs::read(path).await.map_err(|e| Error::new(format!("{path} ({})", java_file_error(&e))))?;
    parse_keystore(&data, password)
}

/// `FileInputStream`'s `FileNotFoundException` reason: the OS error's text (`strerror`), without Rust's
/// `(os error N)` suffix.
fn java_file_error(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => "No such file or directory".into(),
        std::io::ErrorKind::PermissionDenied => "Permission denied".into(),
        std::io::ErrorKind::IsADirectory => "Is a directory".into(),
        std::io::ErrorKind::NotADirectory => "Not a directory".into(),
        _ => {
            let text = e.to_string();
            text.rsplit_once(" (os error ").map_or(text.clone(), |(message, _)| message.to_string())
        }
    }
}

/// A JDK `KeyStore` type as `KeyStore.getInstance(type)` finds it (case-insensitively) among the oracle image's
/// providers, by the formats its `load` reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreType {
    /// `JKS` and `PKCS12` (`KeyStore.getDefaultType()`): the dual-format stores (`keystore.type.compat`), reading
    /// JKS or PKCS#12. `DKS` loading a stream reads it as `JKS` does.
    Dual,
    /// `JCEKS`: JKS or JCEKS.
    Jceks,
    /// `CaseExactJKS`: JKS only.
    CaseExactJks,
}

impl StoreType {
    /// `KeyStore.getInstance(name)`: a `KeyStoreException` for a type no provider has (`BKS`, `PKCS11` without a
    /// configured token, an empty name).
    pub fn named(name: &str) -> Result<StoreType, Error> {
        match name.to_ascii_lowercase().as_str() {
            "jks" | "pkcs12" | "dks" => Ok(StoreType::Dual),
            "jceks" => Ok(StoreType::Jceks),
            "caseexactjks" => Ok(StoreType::CaseExactJks),
            _ => Err(Error::new(format!("{name} not found"))),
        }
    }

    pub fn reads(self, data: &[u8]) -> bool {
        let jks = data.get(..4) == Some(&[0xFE, 0xED, 0xFE, 0xED][..]);
        let jceks = data.get(..4) == Some(&[0xCE, 0xCE, 0xCE, 0xCE][..]);
        match self {
            StoreType::Dual => !jceks,
            StoreType::Jceks => jks || jceks,
            StoreType::CaseExactJks => jks,
        }
    }
}

/// `SSLContext.getInstance(protocol)` in SunJSSE (names case-insensitive): an unknown protocol is a
/// `NoSuchAlgorithmException`.
pub fn ssl_context_protocol(protocol: &str) -> Result<(), Error> {
    const PROTOCOLS: &[&str] = &["tls", "ssl", "tlsv1", "sslv3", "tlsv1.1", "tlsv1.2", "tlsv1.3", "default", "dtls", "dtlsv1.0", "dtlsv1.2"];
    if PROTOCOLS.contains(&protocol.to_ascii_lowercase().as_str()) {
        Ok(())
    } else {
        Err(Error::new(format!("{protocol} SSLContext not available")))
    }
}

/// What a client socket from a SunJSSE context of `protocol` (a name [`ssl_context_protocol`] accepts) fails on after
/// its key and trust stores have loaded: `Default` refuses `init`, the DTLS contexts have no `SSLSocket`, and the
/// image's `jdk.tls.disabledAlgorithms` leaves `TLSv1` (alias `SSLv3`) and `TLSv1.1` no protocol to handshake with.
pub fn unusable_ssl_context(protocol: &str) -> Result<(), Error> {
    match protocol.to_ascii_lowercase().as_str() {
        "default" => Err(Error::new("Default SSLContext is initialized automatically")),
        "dtls" | "dtlsv1.0" | "dtlsv1.2" => Err(Error::new("DTLS not supported with SSLSocket")),
        "tlsv1" | "sslv3" | "tlsv1.1" => Err(Error::of_kind(ErrorKind::Tls, "No appropriate protocol (protocol is disabled or cipher suites are inappropriate)")),
        _ => Ok(()),
    }
}

/// `KeyStore.getInstance(type).load(new FileInputStream(path), password)`: a format the type does not read fails.
pub async fn load_typed_keystore(path: &str, password: Option<&str>, store_type: StoreType) -> Result<KeyStore, Error> {
    let data = tokio::fs::read(path).await.map_err(|e| Error::new(format!("{path} ({})", java_file_error(&e))))?;
    if !store_type.reads(&data) {
        return Err(Error::new("Invalid keystore format"));
    }
    parse_keystore(&data, password)
}

pub fn parse_keystore(data: &[u8], password: Option<&str>) -> Result<KeyStore, Error> {
    parse_keystore_with_key_password(data, password, password)
}

/// [`parse_keystore`] with the JKS private keys recovered by `key_password` rather than the store password, as a
/// `KeyManagerFactory.init(keyStore, keyPassword)` recovers them.
pub fn parse_keystore_with_key_password(data: &[u8], password: Option<&str>, key_password: Option<&str>) -> Result<KeyStore, Error> {
    match data.get(..4) {
        Some([0xFE, 0xED, 0xFE, 0xED]) => parse_jks(data, password, key_password, false),
        Some([0xCE, 0xCE, 0xCE, 0xCE]) => parse_jks(data, password, key_password, true),
        _ => parse_pkcs12(data, password, key_password),
    }
}

fn tampered() -> Error {
    Error::new("Keystore was tampered with, or password was incorrect")
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let out = self.data.get(self.at..self.at + n).ok_or_else(|| Error::new("Invalid keystore format"))?;
        self.at += n;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn utf(&mut self) -> Result<String, Error> {
        let n = self.u16()? as usize;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }

    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

/// The key a JKS password yields for its integrity digest and key protection: the password's UTF-16BE bytes.
fn jks_password(password: &str) -> Vec<u8> {
    password.encode_utf16().flat_map(|c| c.to_be_bytes()).collect()
}

fn sha1(parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    for p in parts {
        ctx.update(p);
    }
    ctx.finish().as_ref().to_vec()
}

/// `sun.security.provider.JavaKeyStore.engineLoad`.
fn parse_jks(data: &[u8], password: Option<&str>, key_password: Option<&str>, jceks: bool) -> Result<KeyStore, Error> {
    let mut r = Reader { data, at: 4 };
    let version = r.u32()?;
    if version != 1 && version != 2 {
        return Err(Error::new("Invalid keystore format"));
    }
    let count = r.u32()?;
    let mut store = KeyStore { jceks, ..KeyStore::default() };
    let mut aliases = Vec::new();
    for _ in 0..count {
        let tag = r.u32()?;
        let alias = r.utf()?;
        aliases.push(alias.clone());
        r.take(8)?;
        match tag {
            1 => {
                let protected = r.bytes()?;
                let chain_len = r.u32()?;
                let mut chain = Vec::new();
                for _ in 0..chain_len {
                    if version == 2 {
                        r.utf()?;
                    }
                    chain.push(CertificateDer::from(r.bytes()?.to_vec()));
                }
                let mut recovered = None;
                match (jceks, key_password) {
                    (false, Some(key_password)) => match jks_recover_key(protected, key_password) {
                        Some(key) => {
                            recovered = Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone())));
                            store.keys.push((PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)), chain.clone()));
                        }
                        None => store.unrecoverable_keys += 1,
                    },
                    (_, None) => store.unrecoverable_keys += 1,
                    (true, Some(_)) => {}
                }
                store.entries.push(KeyEntry { alias, key: recovered, chain });
            }
            2 => {
                if version == 2 {
                    r.utf()?;
                }
                store.certificates.push(CertificateDer::from(r.bytes()?.to_vec()));
            }
            3 if jceks => {
                // A sealed secret key: a serialized Java object, of no use here.
                return Err(Error::new("Invalid keystore format"));
            }
            _ => return Err(Error::new("Unrecognized keystore entry: ".to_string() + &tag.to_string())),
        }
    }
    // `JavaKeyStore` keeps its entries in a `Hashtable`, which `aliases()` enumerates.
    let order = hashtable_order(&aliases);
    store.entries.sort_by_key(|e| order.iter().position(|a| aliases[*a] == e.alias));
    if let Some(password) = password {
        let body = &data[..r.at];
        let expected = r.take(20)?;
        if sha1(&[&jks_password(password), b"Mighty Aphrodite", body]) != expected {
            return Err(Error::caused(tampered().message, Error::new("Password verification failed")));
        }
    }
    Ok(store)
}

/// `KeyProtector.recover`: Sun's SHA-1 key stream over an `EncryptedPrivateKeyInfo`.
fn jks_recover_key(encrypted_info: &[u8], password: &str) -> Option<Vec<u8>> {
    // EncryptedPrivateKeyInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }
    let (_, seq) = der_element(encrypted_info, 0x30)?;
    let (rest, _alg) = der_element(seq, 0x30)?;
    let (_, protected) = der_element_after(rest, 0x04)?;
    if protected.len() < 40 {
        return None;
    }
    let (salt, rest) = protected.split_at(20);
    let (encrypted, check) = rest.split_at(rest.len() - 20);
    let password = jks_password(password);
    let mut digest = salt.to_vec();
    let mut key = Vec::with_capacity(encrypted.len());
    while key.len() < encrypted.len() {
        digest = sha1(&[&password, &digest]);
        for b in &digest {
            if key.len() < encrypted.len() {
                key.push(encrypted[key.len()] ^ b);
            }
        }
    }
    (sha1(&[&password, &key]) == check).then_some(key)
}

/// A DER element of `tag` at the start of `data`: what follows it, and its contents.
fn der_element(data: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if *data.first()? != tag {
        return None;
    }
    let (len, header) = match *data.get(1)? {
        n if n < 0x80 => (n as usize, 2),
        n => {
            let bytes = (n & 0x7F) as usize;
            let mut len = 0usize;
            for b in data.get(2..2 + bytes)? {
                len = (len << 8) | *b as usize;
            }
            (len, 2 + bytes)
        }
    };
    let contents = data.get(header..header + len)?;
    Some((&data[header + len..], contents))
}

fn der_element_after(data: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    der_element(data, tag)
}

fn parse_pkcs12(data: &[u8], password: Option<&str>, key_password: Option<&str>) -> Result<KeyStore, Error> {
    let Some(password) = password else {
        // `PKCS12KeyStore.engineLoad` without a password skips the encrypted safes (keytool's certificates) and the
        // integrity check; the private keys stay encrypted, unrecovered.
        if der_element(data, 0x30).is_none() {
            return Err(Error::new("Invalid keystore format"));
        }
        let unrecoverable_keys = pkcs12_key_bag_names(data).len();
        return Ok(KeyStore { pkcs12: true, unrecoverable_keys, ..KeyStore::default() });
    };
    let parsed = p12_keystore::KeyStore::from_pkcs12(data, password, p12_keystore::Pkcs12ImportPolicy::Relaxed).map_err(|e| match e {
        p12_keystore::error::Error::DerError(_) => Error::new("Invalid keystore format"),
        _ => pkcs12_wrong_password(data),
    })?;
    let mut store = KeyStore { pkcs12: true, ..KeyStore::default() };
    for (alias, entry) in parsed.entries() {
        match entry {
            p12_keystore::KeyStoreEntry::Certificate(c) => store.certificates.push(CertificateDer::from(c.as_der().to_vec())),
            p12_keystore::KeyStoreEntry::PrivateKeyChain(chain) => {
                let certs: Vec<CertificateDer<'static>> = chain.certs().iter().map(|c| CertificateDer::from(c.as_der().to_vec())).collect();
                store.keys.push((PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(chain.key().as_der().to_vec())), certs.clone()));
                store.entries.push(KeyEntry {
                    alias: alias.to_lowercase(),
                    key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(chain.key().as_der().to_vec()))),
                    chain: certs,
                });
            }
            p12_keystore::KeyStoreEntry::Secret(_) => {}
        }
    }
    // `PKCS12KeyStore` keeps its entries in a `LinkedHashMap`, in the order of the file's key bags.
    let bags = pkcs12_key_bag_names(data);
    store.entries.sort_by_key(|e| bags.iter().position(|b| *b == e.alias).unwrap_or(usize::MAX));
    // The keys were decrypted with the store password (keytool gives a PKCS#12 key no password of its own); another
    // key password does not recover them.
    if key_password != Some(password) && !store.keys.is_empty() {
        store.unrecoverable_keys = store.keys.len();
        store.keys.clear();
        store.entries.iter_mut().for_each(|e| e.key = None);
    }
    Ok(store)
}

/// `PKCS12KeyStore.engineLoad` with a wrong password: an encrypted safe (keytool's certificates) fails to decrypt
/// before the MAC is checked; a file without one fails the integrity check.
fn pkcs12_wrong_password(data: &[u8]) -> Error {
    // `encryptedData` ContentInfo's OID, 1.2.840.113549.1.7.6.
    const ENCRYPTED_DATA: &[u8] = &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06];
    if data.windows(ENCRYPTED_DATA.len()).any(|w| w == ENCRYPTED_DATA) {
        Error::caused(
            "keystore password was incorrect",
            Error::new(
                "failed to decrypt safe contents entry: javax.crypto.BadPaddingException: Given final block not properly padded. Such issues can \
                 arise if a bad key is used during decryption.",
            ),
        )
    } else {
        let cause = Error::new("Failed PKCS12 integrity checking");
        Error::caused(format!("Integrity check failed: java.security.UnrecoverableKeyException: {}", cause.message), cause)
    }
}

/// The JDK default trust (`cacerts` of the oracle image's Temurin 25): what a Java client uses without a trust store.
pub fn jdk_roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(crate::tls::client_cert::pem_chain(crate::client::JDK_CACERTS).into_iter().map(CertificateDer::from));
    roots
}

/// What a JSSE client context is built from.
#[derive(Default)]
pub struct ClientTls {
    /// The trust store's certificates, or `None` for the JDK's default trust (`cacerts`).
    pub trust: Option<Vec<CertificateDer<'static>>>,
    /// Trust every server certificate (RabbitMQ's `TrustEverythingTrustManager`).
    pub trust_all: bool,
    pub identity: Option<(PrivateKeyDer<'static>, Vec<CertificateDer<'static>>)>,
    /// A key manager choosing the identity per handshake, in place of `identity`.
    pub key_manager: Option<KeyManager>,
    /// `SSLContext.getInstance(protocol)`: `TLSv1.2` stops at 1.2.
    pub protocol: Option<String>,
    /// Enabled cipher suites by their IANA names.
    pub cipher_suites: Option<Vec<String>>,
    /// Notes a server certificate the trust refuses, for [`dial_alertless`].
    pub refusal: Option<Refusal>,
}

/// A key store file and its password, as a client configuration names them.
pub type StoreFile<'a> = (&'a str, Option<&'a str>);

impl ClientTls {
    /// The context a client configured with a trust store and a key store (each optional) builds: the trust
    /// store's certificates (the JDK's default trust without one) and the key store's keys, chosen per handshake by
    /// the default `SunX509` key manager.
    pub async fn from_stores(trust_store: Option<StoreFile<'_>>, key_store: Option<StoreFile<'_>>) -> Result<ClientTls, Error> {
        let mut tls = ClientTls::default();
        if let Some((path, password)) = trust_store {
            tls.trust = Some(load_keystore(path, password).await?.certificates);
        }
        if let Some((path, password)) = key_store {
            tls.key_manager = Some(KeyManager { kind: KeyManagerKind::SunX509, entries: load_keystore(path, password).await?.entries });
        }
        Ok(tls)
    }

    pub fn config(self) -> Result<Arc<rustls::ClientConfig>, Error> {
        let mut provider = rustls::crypto::ring::default_provider();
        if let Some(names) = &self.cipher_suites {
            let wanted: Vec<String> = names.iter().map(|n| n.trim().replace("TLS_AES", "TLS13_AES").replace("TLS_CHACHA20", "TLS13_CHACHA20")).collect();
            provider.cipher_suites.retain(|s| wanted.iter().any(|w| format!("{:?}", s.suite()) == *w));
        }
        let versions: &[&rustls::SupportedProtocolVersion] = match self.protocol.as_deref() {
            Some("TLSv1.2" | "TLSv1.1" | "TLSv1" | "SSLv3") => &[&rustls::version::TLS12],
            _ => &[&rustls::version::TLS13, &rustls::version::TLS12],
        };
        let provider = Arc::new(provider);
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .map_err(|e| Error::of_kind(ErrorKind::Tls, e.to_string()))?;
        let builder = if self.trust_all {
            builder.dangerous().with_custom_certificate_verifier(Arc::new(TrustAll(provider.clone())))
        } else {
            let mut roots = rustls::RootCertStore::empty();
            match self.trust {
                Some(certs) => {
                    for c in certs {
                        let _ = roots.add(c);
                    }
                }
                None => roots = jdk_roots(),
            }
            match self.refusal {
                Some(refusal) => {
                    let webpki = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                        .build()
                        .map_err(|e| Error::of_kind(ErrorKind::Tls, e.to_string()))?;
                    builder.dangerous().with_custom_certificate_verifier(Arc::new(NotingRefusal(webpki, refusal)))
                }
                None => builder.with_root_certificates(roots),
            }
        };
        let config = match (self.key_manager, self.identity) {
            (Some(manager), _) => builder.with_client_cert_resolver(Arc::new(manager.resolver(&provider))),
            (None, Some((key, chain))) => builder.with_client_auth_cert(chain, key).map_err(|e| Error::of_kind(ErrorKind::Tls, e.to_string()))?,
            (None, None) => builder.with_no_client_auth(),
        };
        Ok(Arc::new(config))
    }
}

/// Accepts any server certificate.
#[derive(Debug)]
struct TrustAll(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for TrustAll {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Whether a handshake's server certificate was refused, set by the verifier as it refuses it, before rustls queues
/// its fatal alert.
#[derive(Clone, Default, Debug)]
pub struct Refusal(Arc<std::sync::atomic::AtomicBool>);

impl Refusal {
    fn note(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn noted(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The webpki verifier, noting each refusal in its [`Refusal`]; the error is passed on unchanged.
#[derive(Debug)]
struct NotingRefusal(Arc<rustls::client::WebPkiServerVerifier>, Refusal);

impl rustls::client::danger::ServerCertVerifier for NotingRefusal {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let verified = self.0.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now);
        if verified.is_err() {
            self.1.note();
        }
        verified
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// A TCP connection that, once its [`Refusal`] is noted, swallows what is written to it: the fatal alert rustls
/// answers a refused certificate with never reaches the server.
struct AlertlessTcp(tokio::net::TcpStream, Refusal);

impl tokio::io::AsyncRead for AlertlessTcp {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for AlertlessTcp {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        if self.1.noted() {
            return std::task::Poll::Ready(Ok(buf.len()));
        }
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// [`dial`] as `java.net.http.HttpClient` dials (every name in SNI, [`Sni::Always`]): a server certificate its trust
/// refuses ends the handshake with the connection closed and no fatal alert sent. Its `SSLFlowDelegate` never writes
/// the alert its `SSLEngine` produced (a TLS listener the oracle's Schema Registry client refused read an
/// EOF), so a server refused this way, MockServer itself on a self-dial, logs no failed handshake.
pub async fn dial_alertless(host: &str, port: u16, timeout: std::time::Duration, tls: Option<(Arc<rustls::ClientConfig>, Refusal)>) -> Result<Box<dyn Stream>, DialError> {
    let tcp = dial_tcp(host, port, timeout).await?;
    let Some((config, refusal)) = tls else { return Ok(Box::new(tcp)) };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| DialError::Handshake(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
    let stream = tokio_rustls::TlsConnector::from(config).connect(name, AlertlessTcp(tcp, refusal)).await.map_err(DialError::Handshake)?;
    Ok(Box::new(stream))
}

/// `SSLContext.getDefault()` as a client with no trust store of its own uses it (RabbitMQ's `useSslProtocol()` since
/// 5.x): the JDK's `cacerts` ([`jdk_roots`]), HTTPS endpoint identification of the host, no client
/// certificate. A refused server certificate is answered with SunJSSE's alert (see [`JsseRejection`]).
pub fn jdk_default_context() -> Result<Arc<rustls::ClientConfig>, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let webpki = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(jdk_roots()), provider.clone())
        .build()
        .map_err(|e| Error::of_kind(ErrorKind::Tls, e.to_string()))?;
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| Error::of_kind(ErrorKind::Tls, e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(JsseVerifier(webpki)))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// A server certificate SunJSSE's trust manager refuses with `certificate_unknown` (no path to a trusted anchor, or
/// a host name it does not name), where rustls would send `unknown_ca` or `bad_certificate`: the alert the peer logs
/// (`(certificate_unknown) Received fatal alert: certificate_unknown`). Its text is the client's
/// `SSLHandshakeException` message.
#[derive(Debug)]
pub struct JsseRejection(String);

impl std::fmt::Display for JsseRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for JsseRejection {}

/// The webpki verifier, its trust and name failures re-raised as [`JsseRejection`]s.
#[derive(Debug)]
struct JsseVerifier(Arc<rustls::client::WebPkiServerVerifier>);

impl rustls::client::danger::ServerCertVerifier for JsseVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use rustls::CertificateError::{NotValidForName, NotValidForNameContext, Other, UnknownIssuer};
        const NO_PATH: &str = "(certificate_unknown) PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: \
            unable to find valid certification path to requested target";
        let rejected = |text: String| rustls::Error::InvalidCertificate(Other(rustls::OtherError(Arc::new(JsseRejection(text)))));
        self.0.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now).map_err(|e| match e {
            rustls::Error::InvalidCertificate(UnknownIssuer) => rejected(NO_PATH.into()),
            // webpki refuses a self-signed (CA) certificate as a leaf before looking for its issuer; the JDK finds no path.
            rustls::Error::InvalidCertificate(Other(ref other)) if format!("{other:?}") == "OtherError(CaUsedAsEndEntity)" => rejected(NO_PATH.into()),
            rustls::Error::InvalidCertificate(NotValidForName | NotValidForNameContext { .. }) => rejected(format!("(certificate_unknown) {e}")),
            other => other,
        })
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// A client's byte stream to a broker: plain TCP or TLS over it.
pub trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> Stream for T {}

/// Why [`dial`] failed, for each client to report as its Java counterpart does.
#[derive(Debug)]
pub enum DialError {
    /// The host did not resolve.
    Lookup(std::io::Error),
    /// No connection within the timeout.
    Timeout,
    /// Every address refused or failed.
    Connect(std::io::Error),
    /// The TLS handshake failed (or the host is not a valid TLS server name).
    Handshake(std::io::Error),
}

pub use crate::inet_address::is_cached_lookup_failure;

/// Connects to one resolved `address`, within `timeout`.
pub async fn dial_address(address: std::net::SocketAddr, timeout: std::time::Duration) -> Result<tokio::net::TcpStream, DialError> {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Ok(Err(e)) => Err(DialError::Connect(e)),
        Err(_) => Err(DialError::Timeout),
    }
}

/// Resolves `host` and connects to its addresses in turn, within `timeout` overall.
pub async fn dial_tcp(host: &str, port: u16, timeout: std::time::Duration) -> Result<tokio::net::TcpStream, DialError> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let connect = async {
        let addresses = crate::inet_address::lookup(host, port).await.map_err(DialError::Lookup)?;
        let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "no address");
        for address in addresses {
            match tokio::net::TcpStream::connect(address).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    return Ok(s);
                }
                Err(e) => last = e,
            }
        }
        Err(DialError::Connect(last))
    };
    tokio::time::timeout(timeout, connect).await.map_err(|_| DialError::Timeout)?
}

/// Which server names a broker client's ClientHello carries (`server_name`, SNI). The oracle was asked per
/// client (`tests/scenarios/tls_*_localhost_*sni.json`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sni {
    /// Every DNS name, `localhost` too: clients that set `SNIHostName(host)` themselves (Paho's
    /// `SSLNetworkModule.start`, the JDK's `java.net.http.HttpClient` behind the Schema Registry client).
    Always,
    /// The JDK's own `SSLSocket`/`SSLEngine` default (kafka-clients, RabbitMQ's amqp-client): the
    /// forwarding client's rule, `client::jdk_sni`.
    Jdk,
}

/// The TLS handshake over `tcp`, checking the certificate against `host` and naming it in SNI as `sni` says.
pub async fn handshake(
    tcp: tokio::net::TcpStream,
    host: &str,
    config: Arc<rustls::ClientConfig>,
    sni: Sni,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, std::io::Error> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let config = if sni == Sni::Jdk && config.enable_sni && !crate::client::jdk_sni(host) {
        let mut unnamed = (*config).clone();
        unnamed.enable_sni = false;
        Arc::new(unnamed)
    } else {
        config
    };
    tokio_rustls::TlsConnector::from(config).connect(name, tcp).await
}

/// [`dial_tcp`], then the TLS handshake when there is a TLS configuration.
pub async fn dial(host: &str, port: u16, timeout: std::time::Duration, tls: Option<Arc<rustls::ClientConfig>>, sni: Sni) -> Result<Box<dyn Stream>, DialError> {
    let tcp = dial_tcp(host, port, timeout).await?;
    match tls {
        Some(config) => Ok(Box::new(handshake(tcp, host, config, sni).await.map_err(DialError::Handshake)?)),
        None => Ok(Box::new(tcp)),
    }
}

/// Whether an I/O error from a TLS stream is a failed handshake (the JDK's `SSLHandshakeException`).
pub fn is_tls_failure(e: &std::io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some())
}

/// Whether an I/O error is the peer closing the connection before the handshake finished (rustls' `tls handshake
/// eof`; JSSE's `SSLHandshakeException: Remote host terminated the handshake`).
pub fn is_handshake_eof(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::UnexpectedEof && e.to_string() == "tls handshake eof"
}

/// The JSSE message for a failed handshake where it is a fixed text (a plaintext peer, a peer closing mid-handshake);
/// otherwise rustls' own.
pub fn jsse_message(e: &std::io::Error) -> String {
    if is_handshake_eof(e) {
        return "Remote host terminated the handshake".into();
    }
    match e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
        Some(rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType)) => "Unsupported or unrecognized SSL message".into(),
        Some(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other))) if other.0.downcast_ref::<JsseRejection>().is_some() => {
            other.0.to_string()
        }
        _ => e.to_string(),
    }
}

/// Writes a JKS trust store of `certificates` (for tests and tools that hand a Java trust store to a client).
pub fn write_jks_truststore(certificates: &[(&str, &[u8])], password: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0xFE, 0xED, 0xFE, 0xED]);
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&(certificates.len() as u32).to_be_bytes());
    for (alias, der) in certificates {
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&(alias.len() as u16).to_be_bytes());
        out.extend_from_slice(alias.as_bytes());
        out.extend_from_slice(&0u64.to_be_bytes());
        out.extend_from_slice(&5u16.to_be_bytes());
        out.extend_from_slice(b"X.509");
        out.extend_from_slice(&(der.len() as u32).to_be_bytes());
        out.extend_from_slice(der);
    }
    let digest = sha1(&[&jks_password(password), b"Mighty Aphrodite", &out]);
    out.extend_from_slice(&digest);
    out
}

/// `Hashtable<String, _>`'s enumeration order (`keys()`) for keys put in this order: 11 slots, `2n+1` when the count
/// reaches three quarters, new entries at the head of a chain, enumerated from the last slot.
fn hashtable_order(keys: &[String]) -> Vec<usize> {
    let slot = |key: &str, capacity: usize| (java_string_hash(key) as u32 & 0x7fff_ffff) as usize % capacity;
    let mut capacity = 11usize;
    let mut threshold = 8usize;
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); capacity];
    let mut count = 0usize;
    for (i, key) in keys.iter().enumerate() {
        if buckets.iter().flatten().any(|&e| keys[e] == *key) {
            continue;
        }
        if count >= threshold {
            let new_capacity = capacity * 2 + 1;
            let mut rehashed: Vec<Vec<usize>> = vec![Vec::new(); new_capacity];
            for old in (0..capacity).rev() {
                for &e in &buckets[old] {
                    rehashed[slot(&keys[e], new_capacity)].insert(0, e);
                }
            }
            capacity = new_capacity;
            threshold = capacity * 3 / 4;
            buckets = rehashed;
        }
        buckets[slot(key, capacity)].insert(0, i);
        count += 1;
    }
    buckets.iter().rev().flat_map(|chain| chain.iter().copied()).collect()
}

/// `String.hashCode`.
fn java_string_hash(s: &str) -> i32 {
    s.encode_utf16().fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(i32::from(c)))
}

/// The friendly names (lower-cased, as `PKCS12KeyStore` keys its entries) of a PKCS#12 file's key bags, in file
/// order: the bags of its unencrypted `data` contents, where the JDK's and OpenSSL's writers put keys.
fn pkcs12_key_bag_names(data: &[u8]) -> Vec<String> {
    const DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
    const KEY_BAG: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x01];
    const SHROUDED_KEY_BAG: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x02];
    const FRIENDLY_NAME: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x14];
    fn elements(mut data: &[u8]) -> Vec<(u8, &[u8])> {
        let mut out = Vec::new();
        while let Some(&tag) = data.first() {
            let Some((rest, contents)) = der_element(data, tag) else { break };
            out.push((tag, contents));
            data = rest;
        }
        out
    }
    // `data` ContentInfo: OID, [0] { OCTET STRING }
    fn data_content(content_info: &[u8]) -> Option<&[u8]> {
        let parts = elements(content_info);
        let (0x06, oid) = *parts.first()? else { return None };
        let (0xA0, explicit) = *parts.get(1)? else { return None };
        (oid == DATA).then_some(())?;
        der_element(explicit, 0x04).map(|(_, octets)| octets)
    }
    let mut names = Vec::new();
    let Some((_, pfx)) = der_element(data, 0x30) else { return names };
    let Some(&(0x30, auth_safe)) = elements(pfx).get(1) else { return names };
    let Some(Some((_, safes))) = data_content(auth_safe).map(|octets| der_element(octets, 0x30)) else { return names };
    for (_, content_info) in elements(safes) {
        let Some(Some((_, bags))) = data_content(content_info).map(|octets| der_element(octets, 0x30)) else { continue };
        for (_, bag) in elements(bags) {
            let parts = elements(bag);
            let Some(&(0x06, bag_id)) = parts.first() else { continue };
            if bag_id != KEY_BAG && bag_id != SHROUDED_KEY_BAG {
                continue;
            }
            let Some(&(0x31, attributes)) = parts.get(2) else { continue };
            for (_, attribute) in elements(attributes) {
                let attribute = elements(attribute);
                if let (Some(&(0x06, FRIENDLY_NAME)), Some(&(0x31, values))) = (attribute.first(), attribute.get(1)) && let Some(&(0x1E, bmp)) = elements(values).first() {
                    let units: Vec<u16> = bmp.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                    names.push(String::from_utf16_lossy(&units).to_lowercase());
                }
            }
        }
    }
    names
}

/// `KeyManagerFactory.getInstance(algorithm)`'s key manager, choosing the client's identity per handshake from the
/// certificate authorities and signature schemes the server's `CertificateRequest` names.
pub struct KeyManager {
    pub kind: KeyManagerKind,
    pub entries: Vec<KeyEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
///
/// Both rank as the oracle image's JDK 26 does (`X509KeyManagerCertChecking`, which `SunX509` uses too since
/// JDK-8353113; JDK 25's `SunX509` checked neither validity nor key usage): every alias whose leaf has one of the key
/// types (in the order the server's signature schemes name them) and whose chain has a certificate issued by a named
/// authority (any, when none is named), valid before expired before a key usage that does not allow client
/// authentication, then by key type; the first of the best rank wins. They differ in the order aliases are walked.
pub enum KeyManagerKind {
    /// `SunX509KeyManagerImpl`: the `HashMap` its `init` fills from `KeyStore.aliases()`.
    SunX509,
    /// `X509KeyManagerImpl` (`NewSunX509`, `PKIX`): `KeyStore.aliases()`.
    NewSunX509,
}

impl KeyManagerKind {
    /// The `keyManager` algorithm (`SunX509` or `NewSunX509`/`PKIX`, case-insensitively); others fail earlier.
    pub fn named(algorithm: &str) -> KeyManagerKind {
        if algorithm.eq_ignore_ascii_case("sunx509") { KeyManagerKind::SunX509 } else { KeyManagerKind::NewSunX509 }
    }
}

/// A JDK key algorithm name (`PublicKey.getAlgorithm()`) for a certificate's subject public key.
fn jdk_key_algorithm(cert: &x509_parser::certificate::X509Certificate) -> &'static str {
    match cert.public_key().algorithm.algorithm.to_id_string().as_str() {
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.2.1" => "EC",
        "1.3.101.112" | "1.3.101.113" => "EdDSA",
        "1.2.840.10040.4.1" => "DSA",
        _ => "",
    }
}

/// `SignatureScheme.keyAlgorithm`: the key type a scheme signs with.
fn scheme_key_algorithm(scheme: rustls::SignatureScheme) -> &'static str {
    match u16::from(scheme) {
        0x0809..=0x080B => "RSASSA-PSS",
        0x0807 | 0x0808 => "EdDSA",
        0x0804..=0x0806 => "RSA",
        code => match code & 0xFF {
            0x01 => "RSA",
            0x02 => "DSA",
            0x03 => "EC",
            _ => "",
        },
    }
}

/// `X509KeyManagerImpl.CheckResult`, best first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CheckResult {
    Ok,
    Expired,
    ExtensionMismatch,
}

/// `CheckType.CLIENT.check`: the extended key usage, the key usage, then the validity.
fn client_check(cert: &x509_parser::certificate::X509Certificate) -> CheckResult {
    match cert.extended_key_usage() {
        Ok(Some(eku)) if !eku.value.client_auth && !eku.value.any => return CheckResult::ExtensionMismatch,
        Err(_) => return CheckResult::ExtensionMismatch,
        _ => {}
    }
    match cert.key_usage() {
        Ok(Some(ku)) if !ku.value.digital_signature() && matches!(jdk_key_algorithm(cert), "RSA" | "EC" | "DSA") => {
            return CheckResult::ExtensionMismatch;
        }
        Err(_) => return CheckResult::ExtensionMismatch,
        _ => {}
    }
    if cert.validity().is_valid() { CheckResult::Ok } else { CheckResult::Expired }
}

/// `X509KeyManagerCertChecking.conformsToAlgorithmConstraints` against `jdk.certpath.disabledAlgorithms` of the oracle
/// image's JDK 26 (`MD2, MD5, RSA keySize < 1024, DSA keySize < 1024, EC keySize < 224`; its `SHA1` entries bind only
/// TLS servers' chains and signed JARs) and the `MD5withRSA` and `EC keySize < 224` entries of
/// `jdk.tls.disabledAlgorithms`: every certificate of the chain must be signed with neither MD2 nor MD5 and carry a key
/// of an allowed size. Not modelled: the check against the peer's `signature_algorithms_cert` (a scheme the server's
/// CertificateRequest does not list), which only a peer that advertises fewer schemes than the signing algorithms in
/// use could trip, and the DSA key size.
fn conforms_to_algorithm_constraints(chain: &[x509_parser::certificate::X509Certificate]) -> bool {
    use x509_parser::public_key::PublicKey;
    chain.iter().all(|cert| {
        let disabled_signature = matches!(
            cert.signature_algorithm.algorithm.to_id_string().as_str(),
            // md2WithRSAEncryption, md5WithRSAEncryption, and OIW's md5WithRSA
            "1.2.840.113549.1.1.2" | "1.2.840.113549.1.1.4" | "1.3.14.3.2.3"
        );
        let weak_key = match cert.public_key().parsed() {
            Ok(PublicKey::RSA(rsa)) => rsa.key_size() < 1024,
            Ok(PublicKey::EC(point)) => point.key_size() < 224,
            _ => false,
        };
        !disabled_signature && !weak_key
    })
}

impl KeyManager {
    /// The alias index the key manager chooses for these key types and authorities (empty: any issuer).
    fn choose(&self, key_types: &[&str], issuers: &[&[u8]]) -> Option<usize> {
        let issuers: Vec<x509_parser::x509::X509Name> =
            issuers.iter().filter_map(|i| <x509_parser::x509::X509Name as x509_parser::prelude::FromDer<_>>::from_der(i).ok().map(|(_, n)| n)).collect();
        let parsed: Vec<Vec<x509_parser::certificate::X509Certificate>> = self
            .entries
            .iter()
            .map(|e| e.chain.iter().filter_map(|c| x509_parser::parse_x509_certificate(c).ok().map(|(_, c)| c)).collect())
            .collect();
        let candidate = |i: usize, key_type: &str| {
            let chain = &parsed[i];
            chain.len() == self.entries[i].chain.len()
                && conforms_to_algorithm_constraints(chain)
                && chain.first().is_some_and(|leaf| jdk_key_algorithm(leaf) == key_type)
                && (issuers.is_empty()
                    || chain.iter().any(|c| issuers.iter().any(|n| crate::tls::client_cert::same_name(c.issuer(), n))))
        };
        let order: Vec<usize> = match self.kind {
            KeyManagerKind::SunX509 => {
                let aliases: Vec<String> = self.entries.iter().map(|e| e.alias.clone()).collect();
                crate::recorded::java_hashmap_order(&aliases)
            }
            KeyManagerKind::NewSunX509 => (0..self.entries.len()).collect(),
        };
        let mut ranked = Vec::new();
        for i in order {
            let Some(key_index) = key_types.iter().position(|t| candidate(i, t)) else { continue };
            ranked.push((client_check(&parsed[i][0]), key_index, i));
        }
        ranked.sort_by_key(|&(check, key_index, _)| (check, key_index));
        ranked.first().map(|&(_, _, i)| i)
    }

    pub fn resolver(self, provider: &rustls::crypto::CryptoProvider) -> KeyChoice {
        let keys = self
            .entries
            .iter()
            .map(|e| {
                let key = e.key.as_ref()?.clone_key();
                let signer = provider.key_provider.load_private_key(key).ok()?;
                Some(Arc::new(rustls::sign::CertifiedKey::new(e.chain.clone(), signer)))
            })
            .collect();
        KeyChoice { manager: self, keys }
    }
}

/// A [`KeyManager`] as rustls asks it: no certificate when it chooses none, or a key it cannot use.
pub struct KeyChoice {
    manager: KeyManager,
    keys: Vec<Option<Arc<rustls::sign::CertifiedKey>>>,
}

impl std::fmt::Debug for KeyChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyChoice").field("kind", &self.manager.kind).finish()
    }
}

impl rustls::client::ResolvesClientCert for KeyChoice {
    fn resolve(&self, root_hint_subjects: &[&[u8]], sigschemes: &[rustls::SignatureScheme]) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let mut key_types: Vec<&str> = Vec::new();
        for scheme in sigschemes {
            let key_type = scheme_key_algorithm(*scheme);
            if !key_type.is_empty() && !key_types.contains(&key_type) {
                key_types.push(key_type);
            }
        }
        self.keys.get(self.manager.choose(&key_types, root_hint_subjects)?)?.clone()
    }

    fn has_certs(&self) -> bool {
        !self.manager.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreadable_stores_fail_with_the_jdk_reason() {
        let load = |path: &std::path::Path| {
            let path = path.to_str().unwrap().to_string();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move { load_keystore(&path, None).await.err().unwrap().message })
        };
        let dir = std::env::temp_dir();
        let missing = dir.join("mock-server-no-such-store.jks");
        assert_eq!(load(&missing), format!("{} (No such file or directory)", missing.display()));
        assert_eq!(load(&dir), format!("{} (Is a directory)", dir.display()));
        let under_file = std::env::current_exe().unwrap().join("x.jks");
        assert_eq!(load(&under_file), format!("{} (Not a directory)", under_file.display()));
    }

    #[test]
    fn jks_round_trip_checks_the_password() {
        let data = write_jks_truststore(&[("ca", b"not really a certificate")], "changeit");
        let store = parse_keystore(&data, Some("changeit")).unwrap();
        assert_eq!(store.certificates.len(), 1);
        assert_eq!(store.certificates[0].as_ref(), b"not really a certificate");
        assert_eq!(parse_keystore(&data, Some("wrong")).err().unwrap().message, "Keystore was tampered with, or password was incorrect");
        assert_eq!(parse_keystore(&data, None).unwrap().certificates.len(), 1);
    }
}

#[cfg(test)]
mod jdk_trust_tests {
    use super::*;

    /// The default trust is the JDK's `cacerts`, not Mozilla's roots: each set holds anchors the other lacks, so a
    /// server certificate chaining to one of them is trusted by one set and refused by the other.
    #[test]
    fn default_trust_is_the_jdk_cacerts_not_webpki_roots() {
        let jdk = jdk_roots();
        assert_eq!(jdk.roots.len(), 118);
        let jdk_subjects: Vec<&[u8]> = jdk.roots.iter().map(|a| a.subject.as_ref()).collect();
        let mozilla_subjects: Vec<&[u8]> = webpki_roots::TLS_SERVER_ROOTS.iter().map(|a| a.subject.as_ref()).collect();
        assert!(jdk_subjects.iter().any(|s| !mozilla_subjects.contains(s)), "no anchor only the JDK trusts");
        assert!(mozilla_subjects.iter().any(|s| !jdk_subjects.contains(s)), "no anchor only Mozilla trusts");
    }
}

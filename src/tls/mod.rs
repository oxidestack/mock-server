//! Inbound TLS on the shared port, with leaf certificates signed by MockServer's bundled CA (§4.6), so clients
//! that trust MockServer's CA trust this server unchanged.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, Issuer, KeyPair,
    SerialNumber,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::Config;

pub mod bc_cert_string;
pub mod cert_string;
pub mod handshake_failures;
pub mod client_cert;
pub mod flush_on_read;
mod ed448;
pub mod key_string;
pub(super) mod key_math;
mod known_oids;
mod named_curves;
mod pqc_keys;
mod validator;
pub mod x509;

/// Apache-2.0, from `mockserver-core/src/main/resources/org/mockserver/socket/`.
const BUNDLED_CA_CERT: &str = include_str!("CertificateAuthorityCertificate.pem");
const BUNDLED_CA_KEY: &str = include_str!("PKCS8CertificateAuthorityPrivateKey.pem");

/// `sslCertificateLeafValidityInDays` default (`KeyAndCertificateFactory.LEAF_CERTIFICATE_VALIDITY_DAYS_DEFAULT`).
const LEAF_VALIDITY_DAYS_DEFAULT: i64 = 397;
/// `KeyAndCertificateFactory.LEAF_CERTIFICATE_VALIDITY_DAYS_MIN`: a positive override below this floor would mint an
/// already-expired (or immediately renewal-due) leaf, so it is clamped up to this instead.
const LEAF_VALIDITY_DAYS_MIN: i64 = 30;
/// `KeyAndCertificateFactory.LEAF_CERTIFICATE_VALIDITY_DAYS_MAX` (`CERTIFICATE_VALIDITY_YEARS * 365`): an override
/// above this ceiling is clamped down, so `notAfter` cannot be pushed unusably far out.
const LEAF_VALIDITY_DAYS_MAX: i64 = 3650;

/// `BCKeyAndCertificateFactory`'s `configuredLeafValidityDays` handling: non-positive is unset/invalid and falls
/// back to the default; a positive value outside `[LEAF_VALIDITY_DAYS_MIN, LEAF_VALIDITY_DAYS_MAX]` is clamped to
/// the nearer bound; an in-range value is honoured verbatim.
fn leaf_validity_days(config: &Config) -> i64 {
    let configured = config.int_property("sslCertificateLeafValidityInDays", LEAF_VALIDITY_DAYS_DEFAULT);
    if configured < 1 {
        LEAF_VALIDITY_DAYS_DEFAULT
    } else {
        configured.clamp(LEAF_VALIDITY_DAYS_MIN, LEAF_VALIDITY_DAYS_MAX)
    }
}

struct Authority {
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    key_pem: String,
}

/// What the certificate resolver and the fixed-certificate validator want logged, which only the connection
/// handling (it owns the server's log) can write: queued here, drained by [`Tls::take_warnings`] and
/// [`Tls::take_refused`].
#[derive(Default)]
struct Notices {
    /// `CertificateConfigurationValidator` WARN entries (a certificate without the `serverAuth` key usage) and the
    /// expiry WARN of a served fixed certificate.
    warnings: Vec<crate::log_entry::LogEntry>,
    /// The SNI name (if any) of each handshake that a refused fixed certificate left without a certificate.
    /// and the cause chain of the refusal.
    refused: std::collections::VecDeque<(Option<String>, String, Option<String>)>,
    /// Each leaf generated since the last handshake's context set-up (DER, then the SAN domains and IPs as
    /// `Configuration` iterates them): logged at TRACE as `created new X509{}with SAN Domain Names{}and IPs{}`.
    minted: std::collections::VecDeque<Minted>,
}

/// A generated leaf as its TRACE `created new X509{}with SAN Domain Names{}and IPs{}` entry shows it: DER, then the
/// SAN domains and IPs as `Configuration` iterates them.
/// The SAN sets themselves come along: upstream logs the live `Configuration` sets, which the event log renders when it
/// is read, so names added after the mint show too (oracle, scenario `log_created_new_x509`).
type Minted = (Vec<u8>, Vec<String>, Vec<String>, Arc<parking_lot::RwLock<SanSets>>);

pub struct Tls {
    notices: Arc<Mutex<Notices>>,
    /// Live handle on the server's configuration (its runtime values are `Arc`-shared).
    config: Config,
    /// The rustls server configuration, its certificate resolver and the inputs they were built from
    /// (`NettySslContextFactory.serverSslContext` with its `serverSslContextSignature`).
    current: parking_lot::RwLock<Built>,
    /// Whether the server's TLS context's and the forwarding client's `BCKeyAndCertificateFactory` have loaded (and
    /// logged) the CA yet: each does it once, when it first needs it ([`Tls::authority_needed_by`]).
    authority_loaded: [std::sync::atomic::AtomicBool; 2],
    /// What the server's TLS context was last built for, as `createServerSslContext` decides a rebuild (its
    /// signature, with the subject alternative names discovered since): each build logs the certificates in use.
    context_logged: Mutex<Option<String>>,
    /// The client addresses whose inbound handshake failed (`ClientTlsHandshakeFailureLog`), which a reset keeps.
    pub handshake_failures: handshake_failures::HandshakeFailures,
    /// The dynamic CA's key and certificate files `proactivelyInitialiseTLS` wrote at startup, until a context's
    /// first TLS use logs them (`created dynamic … file at{}`, [`write_dynamic_authority`]).
    created_pending: Mutex<Option<(String, String)>>,
    /// The forwarding client's own `BCKeyAndCertificateFactory` leaf (`createClientSslContext` generates one when its
    /// factory has none), which it presents when no forward-proxy key is configured; and its TRACE entry until the
    /// client's TLS context set-up logs it ([`Tls::client_context_needed`]).
    client_leaf: Mutex<(Option<Arc<CertifiedKey>>, Option<Minted>)>,
}

/// The TLS contexts whose key-and-certificate factory loads the CA lazily, each its own.
#[derive(Clone, Copy)]
pub enum AuthorityUser {
    /// `NettySslContextFactory.createServerSslContext`, on the first inbound TLS connection.
    Server,
    /// `NettySslContextFactory.createClientSslContext`, when the forwarding client's first TLS channel is set up (an HTTP
    /// forward, a binary request proxied over TLS or a wss WebSocket relay), before it connects.
    Client,
}

impl Tls {
    /// `user`'s context is built: the first time, its factory loads the CA and logs it ([`log_authority_loaded`]).
    /// The entries carry no port: `SniHandler.lookup` builds the server's context off the event loop, and the
    /// forwarding client's is built off it too (read off the oracle).
    pub fn authority_needed_by(&self, state: &crate::state::State, user: AuthorityUser) {
        if !self.authority_loaded[user as usize].swap(true, std::sync::atomic::Ordering::SeqCst) {
            log_authority_loaded(state, true);
        }
    }

    /// The dynamic CA files `proactivelyInitialiseTLS` wrote at startup, logged by the first context that uses the CA.
    pub fn created_dynamic_authority(&self, key: String, certificate: String) {
        *self.created_pending.lock() = Some((key, certificate));
    }

    /// The dynamic CA was written now, or found on disk: when another process wrote it first, the pair this server
    /// generated in memory is dropped ([`materialize_dynamic_authority`]) and the context is rebuilt on the one on disk.
    fn reload_dynamic_authority(&self) {
        let Ok((cert_pem, _)) = authority_pems(&self.config) else { return };
        let mut current = self.current.write();
        if current.resolver.authority.cert_pem == cert_pem {
            return;
        }
        match Tls::assemble(&self.config, Some(&current.resolver), &self.notices) {
            Ok((resolver, server)) => {
                let signature = current.signature.clone();
                *current = Built { signature, resolver, server };
                sans_changed();
            }
            Err(e) => eprintln!("ERROR TLS context not rebuilt: {e}"),
        }
    }

    /// A handshake needs the server's TLS context (`SniHandler` / `RelayConnectHandler` calling
    /// `createServerSslContext`): the CA is loaded once ([`Tls::authority_needed_by`]), and each (re)build of the
    /// context — the first, and one after its signature or the subject alternative names changed — logs at DEBUG
    /// `using certificate authority serial:{}…` (`logUsedCertificateData`) with the CA and the leaf in use.
    ///
    /// The context's set-up generates the leaf when there is none or the names grew: `SniHandler.lookup` adds the
    /// ClientHello's `sni` name first, and `buildAndSavePrivateKeyAndX509Certificate` logs each leaf at TRACE before
    /// the DEBUG entry.
    ///
    /// Returns whether the context was (re)built: `SniHandler.lookup` then provisions it off the event loop, so its
    /// `SslHandler` replaces the `SniHandler` only after the first unification pass ended (`cachedServerSslContext`
    /// answers a cached one at once).
    pub fn server_context_needed(&self, state: &crate::state::State, sni: Option<&str>) -> bool {
        // a configuration change since the last handshake restarts the sets from the new seeds
        let resolver = self.server_config_resolver();
        // `CertificateConfigurationValidator` refuses the fixed pair before the factory loads the CA
        if !resolver.fixed.lock().refused_by_validator {
            self.authority_needed_by(state, AuthorityUser::Server);
        }
        resolver.prepare(sni);
        self.log_minted(state);
        let mut key = context_signature(&self.config);
        if !self.config.bool_property("preventCertificateDynamicUpdate", false) {
            let (domains, ips) = self.subject_alternative_names();
            key.push_str(&format!("|{domains:?}|{ips:?}"));
        }
        {
            let mut logged = self.context_logged.lock();
            if logged.as_deref() == Some(key.as_str()) {
                return false;
            }
            *logged = Some(key);
        }
        if !crate::log::debug_enabled(state) {
            return true;
        }
        let authority = self.current.read().resolver.authority.cert_der.clone();
        let Some(leaf) = self.own_identity() else { return true };
        let Some(leaf) = leaf.cert.first() else { return true };
        let (Some(ca), Some(ee)) = (cert_string::serial_issuer_subject(&authority), cert_string::serial_issuer_subject(leaf)) else { return true };
        let entry = crate::recorded::LogEntry::at(
            crate::recorded::Level::Debug,
            "using certificate authority serial:{}issuer:{}subject:{}and certificate serial:{}issuer:{}subject:{}",
        )
        .args([ca.0, ca.1, ca.2, ee.0, ee.1, ee.2]);
        crate::log::entry(state, &entry);
        state.log.message(entry);
        true
    }
}

/// A `BCKeyAndCertificateFactory` loading the CA, as it logs it (`portless` while the server starts). A dynamic CA
/// is loaded as a pair (`ensureDynamicCertificateAuthorityLoaded`: key, then X509); otherwise the leaf's generation
/// reads the X509 and then the key (`buildAndSavePrivateKeyAndX509Certificate`), and a configured leaf only the X509
/// (`certificateChain`). At DEBUG the X509 entry carries the certificate's `toString` (`…as{}`, [`cert_string`]),
/// and at TRACE the key entry the key's BouncyCastle `toString` ([`key_string`]; a key type not ported logs no entry).
pub fn log_authority_loaded(state: &crate::state::State, portless: bool) {
    let config = &state.config;
    // `ensureDynamicCertificateAuthorityLoaded`: the CA's first use generates and writes it
    if dynamic_authority(config) {
        write_dynamic_authority(state, portless);
    }
    if !state.info_enabled() {
        return;
    }
    let set = |name: &str| config.property(name).is_some_and(|v| !v.trim().is_empty());
    let generates_leaf = !(set("privateKeyPath") && set("x509CertificatePath"));
    if dynamic_authority(config) {
        log_ca_private_key_loaded(state, portless);
        log_ca_x509_loaded(state, portless);
    } else {
        log_ca_x509_loaded(state, portless);
        if generates_leaf {
            log_ca_private_key_loaded(state, portless);
        }
    }
}

/// `buildAndSaveCertificateAuthorityPrivateKeyAndX509Certificate` on the dynamic CA's first use (a TLS context's
/// CA load, `proxySetupLogging`'s startup block, the proxy configuration endpoint): the files are written if absent,
/// and the write logged as `saveAsPEMFile` logs it (`created dynamic … file at{}`, key then certificate). A no-op
/// without a dynamic CA.
pub fn write_dynamic_authority(state: &crate::state::State, portless: bool) {
    use crate::recorded::{Level, LogEntry};
    if !dynamic_authority(&state.config) {
        return;
    }
    let written = materialize_dynamic_authority(&state.config);
    let created = written.or_else(|| state.tls.as_ref().and_then(|t| t.created_pending.lock().take()));
    if let Some(tls) = state.tls.as_ref() {
        tls.reload_dynamic_authority();
    }
    if let (Some((key_file, certificate_file)), true) = (created, state.info_enabled()) {
        log_ca_entry(state, portless, LogEntry::at(Level::Info, "created dynamic Certificate Authority Private Key PEM file at{}").args([key_file]));
        log_ca_entry(state, portless, LogEntry::at(Level::Info, "created dynamic Certificate Authority X509 Certificate PEM file at{}").args([certificate_file]));
    }
}

/// One CA load entry: INFO ones as events, DEBUG and TRACE ones on the console and in the event log.
fn log_ca_entry(state: &crate::state::State, portless: bool, entry: crate::recorded::LogEntry) {
    let entry = if portless { entry.without_port() } else { entry };
    if entry.level == crate::recorded::Level::Info {
        crate::log::info_event(state, entry);
    } else {
        crate::log::entry(state, &entry);
        state.log.message(entry);
    }
}

/// `BCKeyAndCertificateFactory.logCaPrivateKeyLoaded`: the key's path at INFO; at TRACE its path and the key's
/// BouncyCastle `toString` ([`key_string`]; a key type not ported logs no entry).
pub fn log_ca_private_key_loaded(state: &crate::state::State, portless: bool) {
    use crate::recorded::{Level, LogEntry};
    if !state.info_enabled() {
        return;
    }
    let config = &state.config;
    if authority_certificate_source(config).is_some_and(|(_, pem)| client_cert::pem_chain(&pem).first().is_some_and(|der| cert_string::refusal(der).is_some())) {
        return;
    }
    let path = authority_private_key_source(config).unwrap_or_else(|| BUNDLED_CA_KEY_PATH.into());
    if state.log_level == "TRACE" {
        let pem = authority_private_key_pem(config);
        if let Some(text) = pem.as_deref().and_then(key_string::private_key_to_string) {
            log_ca_entry(state, portless, LogEntry::at(Level::Trace, "loaded CA private key from path{}containing PEM{}").args([path, text]));
        }
        return;
    }
    log_ca_entry(state, portless, LogEntry::at(Level::Info, "loaded CA private key from path{}").args([path]));
}

/// `BCKeyAndCertificateFactory.logCaX509Loaded`: the certificate's path and PEM at INFO; at DEBUG also its
/// `toString` ([`cert_string`]).
pub fn log_ca_x509_loaded(state: &crate::state::State, portless: bool) {
    use crate::recorded::{Level, LogEntry};
    if !state.info_enabled() {
        return;
    }
    let Some((path, pem)) = authority_certificate_source(&state.config) else { return };
    // the JDK refuses the certificate before anything is logged
    if client_cert::pem_chain(&pem).first().is_some_and(|der| cert_string::refusal(der).is_some()) {
        return;
    }
    if crate::log::debug_enabled(state) {
        let text = client_cert::pem_chain(&pem).first().and_then(|der| cert_string::certificate_to_string(der)).unwrap_or_default();
        log_ca_entry(state, portless, LogEntry::at(Level::Debug, "loaded CA X509 from path{}containing PEM{}as{}").args([path, pem, text]));
    } else {
        log_ca_entry(state, portless, LogEntry::at(Level::Info, "loaded CA X509 from path{}containing PEM{}").args([path, pem]));
    }
}

/// The PEM text of the CA private key in effect (dynamic, configured or bundled).
fn authority_private_key_pem(config: &Config) -> Option<String> {
    match authority_private_key_source(config) {
        Some(path) => crate::class_path::read_string_or_file(&path).ok(),
        None => Some(BUNDLED_CA_KEY.to_string()),
    }
}

/// `FilePath.absolutePathFromClassPathOrPath` of the bundled CA key, inside the image's jar.
const BUNDLED_CA_KEY_PATH: &str = "file:/mockserver.jar!/org/mockserver/socket/PKCS8CertificateAuthorityPrivateKey.pem";

struct Built {
    signature: String,
    resolver: Arc<Resolver>,
    server: Arc<rustls::ServerConfig>,
}

/// `NettySslContextFactory.serverContextSignature`, restricted to the inputs this server's context bakes in: a change
/// of any of them at runtime (`PUT /mockserver/configuration`) rebuilds the context on the next handshake.
fn context_signature(config: &Config) -> String {
    let value = |name: &str| config.property(name).unwrap_or_default();
    let mut signature = format!(
        "mtls={}|mtlsChain={}|protocols={}|insecureProtocols={}|http2={}|caCert={}|caKey={}|dynamicCA={}|dir={}|keyPath={}|certPath={}",
        config.hot_bool(crate::config::Hot::TlsMutualAuthenticationRequired, false),
        value("tlsMutualAuthenticationCertificateChain"),
        config.property("tlsProtocols").unwrap_or_else(|| DEFAULT_TLS_PROTOCOLS.into()),
        config.bool_property("tlsAllowInsecureProtocols", false),
        config.bool_property("http2Enabled", true),
        value("certificateAuthorityCertificate"),
        value("certificateAuthorityPrivateKey"),
        config.bool_property("dynamicallyCreateCertificateAuthorityCertificate", false) || config.bool_property("proxySetup", false),
        value("directoryToSaveDynamicSSLCertificate"),
        value("privateKeyPath"),
        value("x509CertificatePath"),
    );
    // `preventCertificateDynamicUpdate` pins the SAN lists, so they stay out of the signature then.
    if !config.bool_property("preventCertificateDynamicUpdate", false) {
        signature.push_str(&format!(
            "|sanDomains={:?}|sanIps={:?}",
            san_seed(config, "sslSubjectAlternativeNameDomains", "localhost"),
            san_seed(config, "sslSubjectAlternativeNameIps", "127.0.0.1,0.0.0.0")
        ));
    }
    signature
}

const DEFAULT_TLS_PROTOCOLS: &str = "TLSv1.2,TLSv1.3";

/// The configured entries of a SAN list, verbatim (an update may hold a comma or a space inside one; a name no
/// certificate can carry is left out when a leaf is minted).
fn san_list(config: &Config, property: &str, default: &str) -> Vec<String> {
    match config.list_property(property) {
        Some(items) => items.into_iter().flatten().collect(),
        None => default.split(',').map(str::to_string).collect(),
    }
}

/// The configured SAN list, sorted (a `TreeSet` upstream): the entries that seed a resolver.
fn san_seed(config: &Config, property: &str, default: &str) -> Vec<String> {
    let mut list = san_list(config, property, default);
    list.sort();
    list.dedup();
    list
}

/// `effectiveTlsProtocols`: `tlsProtocols` without TLSv1 and TLSv1.1 unless `tlsAllowInsecureProtocols` (the
/// requested list when filtering would empty it), as the protocol versions rustls can speak (TLSv1.2, TLSv1.3).
fn protocol_versions(config: &Config) -> Vec<&'static rustls::SupportedProtocolVersion> {
    let listed = config.property("tlsProtocols").unwrap_or_else(|| DEFAULT_TLS_PROTOCOLS.into());
    let requested: Vec<&str> = listed.split(',').map(str::trim).filter(|p| !p.is_empty()).collect();
    let insecure = |p: &&str| p.eq_ignore_ascii_case("TLSv1") || p.eq_ignore_ascii_case("TLSv1.1");
    let filtered: Vec<&str> = requested.iter().copied().filter(|p| !insecure(p)).collect();
    let effective = if config.bool_property("tlsAllowInsecureProtocols", false) || filtered.is_empty() { requested } else { filtered };
    let mut versions = Vec::new();
    for protocol in effective {
        if protocol.eq_ignore_ascii_case("TLSv1.3") {
            versions.push(&rustls::version::TLS13);
        } else if protocol.eq_ignore_ascii_case("TLSv1.2") {
            versions.push(&rustls::version::TLS12);
        }
    }
    versions
}

/// The ring provider with the cipher suites the oracle's JDK engine enables, in the order it prefers them: TLS 1.3 AES-128, AES-256, ChaCha20, then TLS 1.2 ECDHE_ECDSA and ECDHE_RSA with the same three, nothing else
/// (probed with OpenSSL 3.5 against the oracle: no CBC, no static RSA, no DHE). rustls's own order puts AES-256 first.
fn jdk_provider() -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    // (TLS 1.2 key exchange is ECDSA before RSA; within each, 128-bit AES, 256-bit AES, ChaCha20)
    let rank = |suite: &rustls::SupportedCipherSuite| {
        let name = format!("{:?}", suite.suite());
        let strength = if name.contains("128") { 0 } else if name.contains("AES_256") { 1 } else { 2 };
        let family = if name.starts_with("TLS13") { 0 } else if name.contains("ECDSA") { 1 } else { 2 };
        (family, strength)
    };
    provider.cipher_suites.sort_by_key(rank);
    provider
}

/// A signing key that picks the handshake signature scheme in the order of the client's `signature_algorithms`, as the
/// JDK does: the first of `order` that rustls still offers (TLS 1.3 drops PKCS#1, TLS 1.2 narrows to the
/// suite's) and the key can sign with. rustls's own walk follows the key's list (an RSA key signs with RSASSA-PSS
/// SHA-512 whatever the client lists first) or the suite's, so the client's order is passed in from its ClientHello.
#[derive(Debug)]
struct ClientOrderKey {
    inner: Arc<dyn rustls::sign::SigningKey>,
    order: Vec<rustls::SignatureScheme>,
}

impl rustls::sign::SigningKey for ClientOrderKey {
    fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        self.order
            .iter()
            .filter(|scheme| offered.contains(scheme))
            .find_map(|scheme| self.inner.choose_scheme(&[*scheme]))
            .or_else(|| self.inner.choose_scheme(offered))
    }

    fn public_key(&self) -> Option<rustls_pki_types::SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.inner.algorithm()
    }
}

/// The rustls server configuration for the current values of `tlsMutualAuthenticationRequired`,
/// `tlsMutualAuthenticationCertificateChain` and `http2Enabled`.
fn build_server(config: &Config, resolver: &Arc<Resolver>) -> Result<Arc<rustls::ServerConfig>, String> {
    let client_certificates = ClientCertificates::new(config, &resolver.authority.cert_der)?;
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(jdk_provider()))
        .with_protocol_versions(&protocol_versions(config))
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(Arc::new(client_certificates))
        .with_cert_resolver(resolver.clone());
    // Netty's `SslContext` ciphers in the JDK engine, which applies the server's order (`useCipherSuitesOrder`).
    server.ignore_client_order = true;
    // `http2Enabled=false`: ALPN offers only HTTP/1.1.
    server.alpn_protocols = if config.bool_property("http2Enabled", true) {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    Ok(Arc::new(server))
}

/// The certificate authority's certificate in effect (dynamic, configured, or the bundled one), as DER.
/// Reading it is a use of a dynamic CA, which writes it first ([`materialize_dynamic_authority`]).
pub fn certificate_authority_der(config: &Config) -> Option<Vec<u8>> {
    materialize_dynamic_authority(config);
    let (pem, _) = authority_pems(config).ok()?;
    client_cert::pem_chain(&pem).into_iter().next()
}

/// `dynamicallyCreateCertificateAuthorityCertificate`, which `proxySetup` forces on.
pub fn dynamic_authority(config: &Config) -> bool {
    config.bool_property("proxySetup", false) || config.bool_property("dynamicallyCreateCertificateAuthorityCertificate", false)
}

/// `directoryToSaveDynamicSSLCertificate` (default the working directory).
pub fn dynamic_directory(config: &Config) -> std::path::PathBuf {
    std::path::PathBuf::from(config.property("directoryToSaveDynamicSSLCertificate").filter(|d| !d.trim().is_empty()).unwrap_or_else(|| ".".into()).trim())
}

/// Whether the public CA bundled with MockServer is in use (`ProxySetupInfo.isUsingDefaultCa`).
pub fn using_default_authority(config: &Config) -> bool {
    !dynamic_authority(config)
        && config.property("certificateAuthorityCertificate").is_none_or(|p| p.trim() == "org/mockserver/socket/CertificateAuthorityCertificate.pem")
}

/// The CA certificate bundled with MockServer, as DER.
pub fn bundled_authority_der() -> Vec<u8> {
    pem_der(BUNDLED_CA_CERT, "CERTIFICATE").map(|d| d.to_vec()).unwrap_or_default()
}

/// `BundledCertificateAuthority.isBundledCertificateAuthority`: `certificateAuthorityCertificate` (`None` is its
/// default) names the bundled CA, by its default path or as a file whose first certificate is for the bundled CA's key.
/// One that cannot be read is not (the server's own TLS set-up fails on it with its own message).
pub fn is_bundled_authority_certificate(path: Option<&str>) -> bool {
    let Some(path) = path else { return true };
    if path == "org/mockserver/socket/CertificateAuthorityCertificate.pem" {
        return true;
    }
    if path.trim().is_empty() {
        return false;
    }
    crate::class_path::read_string_or_file(path).ok().and_then(|pem| client_cert::pem_chain(&pem).into_iter().next()).is_some_and(|der| contains_bundled_authority(&[der]))
}

/// `BundledCertificateAuthority.containsBundledCertificateAuthority`: some certificate is for the bundled CA's key,
/// whatever its subject or encoding (`sameKeyMaterial`: RSA by modulus and exponent, under rsaEncryption or
/// RSASSA-PSS; any other key by its encoded bits).
pub fn contains_bundled_authority(certificates: &[Vec<u8>]) -> bool {
    let bundled = bundled_authority_der();
    let Ok((_, bundled)) = x509_parser::parse_x509_certificate(&bundled) else { return false };
    certificates
        .iter()
        .filter_map(|der| x509_parser::parse_x509_certificate(der).ok())
        .any(|(_, certificate)| same_key_material(bundled.public_key(), certificate.public_key()))
}

/// `BundledCertificateAuthority.chainContainsBundledCertificateAuthority`: the chain file (`x509ChainFromPEMFile`)
/// holds a certificate for the bundled CA's key; a blank name or a chain that cannot be read does not (it fails where
/// it is used, with its own message).
pub fn chain_contains_bundled_authority(path: Option<&str>) -> bool {
    let Some(path) = path.filter(|p| !p.trim().is_empty()) else { return false };
    // the bundled CA's own class path resource, in MockServer's jar
    if path.trim() == "org/mockserver/socket/CertificateAuthorityCertificate.pem" {
        return true;
    }
    x509_chain_from_pem_file(path).is_ok_and(|chain| contains_bundled_authority(&chain.into_iter().map(|c| c.der).collect::<Vec<_>>()))
}

/// `DataPlaneMutualTlsConfigurationException.MESSAGE` (upstream cb3817ce3, 9.1.0).
pub const DATA_PLANE_MTLS_REFUSED: &str = "tlsMutualAuthenticationRequired is enabled while MockServer's CA certificate is the default CA bundled with MockServer, whose private key is published in the MockServer jar, so anyone could create a client certificate MockServer accepts: configure your own CA with certificateAuthorityCertificate and certificateAuthorityPrivateKey, or set dynamicallyCreateCertificateAuthorityCertificate=true, or set tlsMutualAuthenticationCertificateChain to the CA chain that signs your client certificates; for a throwaway local test only, tlsMutualAuthenticationAllowBundledCa=true restores the old behaviour";

/// `DataPlaneMutualTlsConfigurationException.BUNDLED_CA_IN_CHAIN_MESSAGE`.
pub const DATA_PLANE_MTLS_BUNDLED_CA_IN_CHAIN: &str = "tlsMutualAuthenticationCertificateChain contains the default CA bundled with MockServer, whose private key is published in the MockServer jar, so anyone could create a client certificate MockServer accepts: remove it from tlsMutualAuthenticationCertificateChain and use the CA chain that signs your client certificates, configure your own CA with certificateAuthorityCertificate and certificateAuthorityPrivateKey, or set dynamicallyCreateCertificateAuthorityCertificate=true; for a throwaway local test only, tlsMutualAuthenticationAllowBundledCa=true restores the old behaviour";

/// `DataPlaneMutualTlsTrust.BUNDLED_CA_TRUSTED_WARNING`.
pub const BUNDLED_CA_TRUSTED_WARNING: &str = "tlsMutualAuthenticationAllowBundledCa is enabled, so mTLS trusts client certificates signed by the default CA bundled with MockServer, whose private key is published in the MockServer jar: ANYONE CAN CREATE A CLIENT CERTIFICATE MOCKSERVER ACCEPTS, with any subject, issuer or serial number, so mTLS does not authenticate clients and client certificate matchers can be satisfied by anyone; use this only for throwaway local tests";

/// `DataPlaneMutualTlsTrust.requireUsableDataPlaneMutualTls`'s WARN when a chain is set and MockServer's CA, the
/// bundled one, is left out of the trust set (`{}` is the chain).
pub const CHAIN_ONLY_TRUSTED_WARNING: &str = "mTLS trusts only tlsMutualAuthenticationCertificateChain:{}because MockServer's CA certificate is the default CA bundled with MockServer, whose private key is published, so client certificates signed by MockServer's CA, including the one MockServerClient presents by default, are not accepted; to trust MockServer's CA too, configure your own CA with certificateAuthorityCertificate and certificateAuthorityPrivateKey or set dynamicallyCreateCertificateAuthorityCertificate=true";

/// `DataPlaneMutualTlsTrust.Outcome`: whether data-plane mTLS would trust the bundled CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPlaneTrust {
    /// the bundled CA is not trusted
    NotTrusted,
    /// a chain is set, and MockServer's CA is left out because it is the bundled CA
    ChainLeavesOutAuthority,
    /// refused unless the opt-in is set: no chain, and MockServer's CA is the bundled CA
    AuthorityIsBundled,
    /// refused unless the opt-in is set: the chain contains the bundled CA
    ChainContainsBundled,
}

impl DataPlaneTrust {
    /// `DataPlaneMutualTlsTrust.outcome`, from the four values in force (`None` for a property never set).
    pub fn of(required: bool, chain: Option<&str>, dynamic_authority: bool, authority_certificate: Option<&str>) -> DataPlaneTrust {
        let authority_is_bundled = || !dynamic_authority && is_bundled_authority_certificate(authority_certificate);
        match chain.filter(|c| !c.trim().is_empty()) {
            Some(chain) if chain_contains_bundled_authority(Some(chain)) => DataPlaneTrust::ChainContainsBundled,
            Some(_) if authority_is_bundled() => DataPlaneTrust::ChainLeavesOutAuthority,
            Some(_) => DataPlaneTrust::NotTrusted,
            None if required && authority_is_bundled() => DataPlaneTrust::AuthorityIsBundled,
            None => DataPlaneTrust::NotTrusted,
        }
    }

    /// The outcome for a configuration as it stands.
    pub fn of_config(config: &Config) -> DataPlaneTrust {
        DataPlaneTrust::of(
            config.hot_bool(crate::config::Hot::TlsMutualAuthenticationRequired, false),
            config.property("tlsMutualAuthenticationCertificateChain").as_deref(),
            dynamic_authority(config),
            config.property("certificateAuthorityCertificate").as_deref(),
        )
    }

    /// `throwIfRefused`: the message the outcome is refused with, unless the opt-in is set.
    pub fn refusal(self) -> Option<&'static str> {
        match self {
            DataPlaneTrust::AuthorityIsBundled => Some(DATA_PLANE_MTLS_REFUSED),
            DataPlaneTrust::ChainContainsBundled => Some(DATA_PLANE_MTLS_BUNDLED_CA_IN_CHAIN),
            _ => None,
        }
    }
}

/// `tlsMutualAuthenticationAllowBundledCa`, fixed at startup (an update never applies it).
pub fn allow_bundled_authority(config: &Config) -> bool {
    config.bool_property("tlsMutualAuthenticationAllowBundledCa", false)
}

/// `DataPlaneMutualTlsTrust.requireUsableDataPlaneMutualTls(configuration)`: the message `MockServer` refuses to start
/// with, before anything is bound, when data-plane mTLS would trust the bundled CA without the opt-in.
pub fn unusable_data_plane_mtls(config: &Config) -> Option<&'static str> {
    if allow_bundled_authority(config) {
        return None;
    }
    DataPlaneTrust::of_config(config).refusal()
}

/// The WARN `requireUsableDataPlaneMutualTls(configuration)` logs at startup when it does not refuse: the opt-in in
/// use, or the chain trusted without the bundled CA (with the chain as its argument).
pub fn data_plane_mtls_startup_warning(config: &Config) -> Option<(&'static str, Option<String>)> {
    match DataPlaneTrust::of_config(config) {
        DataPlaneTrust::NotTrusted => None,
        _ if allow_bundled_authority(config) => Some((BUNDLED_CA_TRUSTED_WARNING, None)),
        DataPlaneTrust::ChainLeavesOutAuthority => Some((CHAIN_ONLY_TRUSTED_WARNING, Some(config.property("tlsMutualAuthenticationCertificateChain").unwrap_or_default()))),
        _ => None,
    }
}

fn same_key_material(a: &x509_parser::x509::SubjectPublicKeyInfo, b: &x509_parser::x509::SubjectPublicKeyInfo) -> bool {
    let rsa = |k: &x509_parser::x509::SubjectPublicKeyInfo| matches!(k.algorithm.algorithm.to_id_string().as_str(), "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10");
    if rsa(a) && rsa(b) {
        let numbers = rsa_numbers(a);
        return numbers.is_some() && numbers == rsa_numbers(b);
    }
    a.subject_public_key.data == b.subject_public_key.data
}

/// An RSA public key's modulus and public exponent, without leading zero bytes.
fn rsa_numbers(key: &x509_parser::x509::SubjectPublicKeyInfo) -> Option<(Vec<u8>, Vec<u8>)> {
    let (_, sequence) = x509_parser::der_parser::der::parse_der_sequence(&key.subject_public_key.data).ok()?;
    let items = sequence.as_sequence().ok()?;
    let number = |i: usize| -> Option<Vec<u8>> {
        let bytes = items.get(i)?.as_slice().ok()?;
        Some(bytes.iter().skip_while(|&&b| b == 0).copied().collect())
    };
    Some((number(0)?, number(1)?))
}

/// The WARN lines `NettySslContextFactory`'s constructor logs (`warnIfInsecureTlsProfileConfigured`, then, for the
/// server's factory, `warnIfBundledCertificateAuthorityInUse`).
pub fn context_warnings(config: &Config, for_server: bool) -> Vec<&'static str> {
    let mut warnings = Vec::new();
    let protocols = config.property("tlsProtocols").unwrap_or_else(|| "TLSv1.2,TLSv1.3".into());
    let insecure = protocols.split(',').map(str::trim).any(|p| p.eq_ignore_ascii_case("TLSv1") || p.eq_ignore_ascii_case("TLSv1.1"));
    if insecure && config.bool_property("tlsAllowInsecureProtocols", false) {
        warnings.push("TLS protocol list includes deprecated TLSv1 / TLSv1.1 (RFC 8996; vulnerable to BEAST and POODLE). Set mockserver.tlsAllowInsecureProtocols=false to drop them, or remove the entries from mockserver.tlsProtocols.");
    }
    if config.property("forwardProxyTLSX509CertificatesTrustManagerType").unwrap_or_else(|| "ANY".into()).trim() == "ANY" {
        warnings.push("Forward proxy is configured to trust ALL X.509 certificates (mockserver.forwardProxyTLSX509CertificatesTrustManagerType=ANY). Certificate validation is disabled — this should be used only in development; prefer JVM or CUSTOM in production.");
    }
    if for_server && using_bundled_authority(config) {
        warnings.push("MockServer is signing TLS traffic with the bundled default Certificate Authority, whose private key is published in the MockServer jar — anyone can forge certificates it trusts, so this must not be relied on as real interception security. To use a unique private CA set mockserver.dynamicallyCreateCertificateAuthorityCertificate=true (or run with --proxy-setup).");
    }
    warnings
}

/// `NettySslContextFactory.usingBundledDefaultCertificateAuthority`: no dynamic CA, no fixed server certificate, and
/// both CA paths the bundled defaults.
fn using_bundled_authority(config: &Config) -> bool {
    let set = |name: &str| config.property(name).is_some_and(|p| !p.trim().is_empty());
    let default = |name: &str, path: &str| config.property(name).is_none_or(|p| p == path);
    !config.bool_property("dynamicallyCreateCertificateAuthorityCertificate", false)
        && !(set("x509CertificatePath") && set("privateKeyPath"))
        && default("certificateAuthorityCertificate", "org/mockserver/socket/CertificateAuthorityCertificate.pem")
        && default("certificateAuthorityPrivateKey", "org/mockserver/socket/PKCS8CertificateAuthorityPrivateKey.pem")
}

/// Where the CA certificate in effect was read from, as `FilePath.absolutePathFromClassPathOrPath` names it (the
/// bundled one inside the image's jar), and its PEM text: the arguments of `loaded CA X509 from path{}containing PEM{}`.
pub fn authority_certificate_source(config: &Config) -> Option<(String, String)> {
    if dynamic_authority(config) {
        let absolute = java_absolute(dynamic_directory(config).join("CertificateAuthorityCertificate.pem"));
        let pem = std::fs::read_to_string(&absolute).ok()?;
        return Some((absolute.display().to_string(), pem));
    }
    match config.property("certificateAuthorityCertificate").filter(|p| !p.trim().is_empty() && !p.starts_with("org/mockserver/socket/")) {
        Some(path) => Some((crate::class_path::absolute_path(&path), crate::class_path::read_string_or_file(&path).ok()?)),
        None => Some(("file:/mockserver.jar!/org/mockserver/socket/CertificateAuthorityCertificate.pem".into(), BUNDLED_CA_CERT.into())),
    }
}

/// `File.getAbsolutePath`: a relative path is appended to the working directory as written, so `./x` stays `./x`
/// (the oracle logs `<working directory>/./CertificateAuthorityCertificate.pem`).
fn java_absolute(path: impl AsRef<std::path::Path>) -> std::path::PathBuf {
    let path = path.as_ref();
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir().map_or_else(|_| path.to_path_buf(), |dir| dir.join(path))
}

/// Where the CA private key in effect comes from, when `BCKeyAndCertificateFactory` logs `loaded CA private key from
/// path{}`: the dynamic or configured file. The bundled key is read from the classpath without that line.
pub fn authority_private_key_source(config: &Config) -> Option<String> {
    if dynamic_authority(config) {
        return Some(java_absolute(dynamic_directory(config).join("PKCS8CertificateAuthorityPrivateKey.pem")).display().to_string());
    }
    let path = config.property("certificateAuthorityPrivateKey").filter(|p| !p.trim().is_empty() && !p.starts_with("org/mockserver/socket/"))?;
    Some(crate::class_path::absolute_path(&path))
}

/// Dynamic CAs generated but not written yet, by directory ([`ca_generation_key`]): certificate and key PEMs. A server
/// builds its TLS context at startup, but upstream generates and writes the CA only when a context first uses it
/// (`ensureDynamicCertificateAuthorityLoaded`), so the pair waits here until [`materialize_dynamic_authority`].
static PENDING_AUTHORITIES: OnceLock<Mutex<HashMap<std::path::PathBuf, (String, String)>>> = OnceLock::new();

/// The pair generated for `directory` and not written yet, generated now if there is none. Called with the
/// directory's generation monitor held.
fn pending_authority(directory: &std::path::Path) -> Result<(String, String), String> {
    let mut pending = PENDING_AUTHORITIES.get_or_init(|| Mutex::new(HashMap::new())).lock();
    let key = ca_generation_key(directory);
    if let Some(pair) = pending.get(&key) {
        return Ok(pair.clone());
    }
    let pair = generate_authority()?;
    pending.insert(key, pair.clone());
    Ok(pair)
}

/// `buildAndSaveCertificateAuthorityPrivateKeyAndX509Certificate`: a dynamic CA absent on disk is written (the key
/// first, the certificate last) from the pair generated for its directory; its key and certificate files, as
/// `java_absolute` spells them, when this call wrote them. A CA already on disk (another server or process wrote it)
/// is kept and the pending pair dropped.
pub fn materialize_dynamic_authority(config: &Config) -> Option<(String, String)> {
    if !dynamic_authority(config) {
        return None;
    }
    let directory = dynamic_directory(config);
    let cert_path = directory.join("CertificateAuthorityCertificate.pem");
    let key_path = directory.join("PKCS8CertificateAuthorityPrivateKey.pem");
    let generation_lock = ca_generation_lock(&directory);
    let _generation = generation_lock.lock();
    let mut pending = PENDING_AUTHORITIES.get_or_init(|| Mutex::new(HashMap::new())).lock();
    let pending_key = ca_generation_key(&directory);
    if cert_path.exists() {
        pending.remove(&pending_key);
        return None;
    }
    let (cert_pem, key_pem) = match pending.get(&pending_key) {
        Some(pair) => pair.clone(),
        None => match generate_authority() {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("ERROR TLS could not generate the dynamic certificate authority: {e}");
                return None;
            }
        },
    };
    let written = std::fs::create_dir_all(&directory)
        .map_err(|e| format!("{}: {e}", directory.display()))
        .and_then(|_| write_private(&key_path, &key_pem))
        .and_then(|_| std::fs::write(&cert_path, &cert_pem).map_err(|e| format!("{}: {e}", cert_path.display())));
    if let Err(e) = written {
        eprintln!("ERROR TLS could not save the dynamic certificate authority: {e}");
        return None;
    }
    pending.remove(&pending_key);
    Some((java_absolute(key_path).display().to_string(), java_absolute(cert_path).display().to_string()))
}

/// Per-directory generation monitors (`BCKeyAndCertificateFactory`'s canonical-path-keyed static lock table):
/// concurrent `Tls::new` calls that target the same (possibly differently-spelled) directory serialise on
/// generation, so they converge on one written pair instead of racing to generate and overwrite each other's.
static CA_GENERATION_LOCKS: OnceLock<Mutex<HashMap<std::path::PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();

/// The canonical key a directory's generation monitor is stored under: its absolute, `.`/`..`-normalised form, so
/// differently-spelled equivalent paths (e.g. `./ca` and `<cwd>/ca`) resolve to the same monitor. Falls back to the
/// path as given when it cannot be made absolute (e.g. an invalid path); a stricter key only ever makes locking
/// more conservative, never less correct.
fn ca_generation_key(directory: &std::path::Path) -> std::path::PathBuf {
    std::path::absolute(directory).map(|p| p.components().collect()).unwrap_or_else(|_| directory.to_path_buf())
}

fn ca_generation_lock(directory: &std::path::Path) -> Arc<Mutex<()>> {
    let key = ca_generation_key(directory);
    CA_GENERATION_LOCKS.get_or_init(|| Mutex::new(HashMap::new())).lock().entry(key).or_insert_with(|| Arc::new(Mutex::new(()))).clone()
}

/// The CA certificate and private key PEMs: with a dynamic CA, the pair in `directoryToSaveDynamicSSLCertificate`,
/// or, while it is absent there, the pair generated for that directory and not written until its first use
/// ([`materialize_dynamic_authority`]); else the configured files or the bundled pair.
fn authority_pems(config: &Config) -> Result<(String, String), String> {
    if dynamic_authority(config) {
        let directory = dynamic_directory(config);
        let cert_path = directory.join("CertificateAuthorityCertificate.pem");
        let key_path = directory.join("PKCS8CertificateAuthorityPrivateKey.pem");
        if !cert_path.exists() {
            // Under the directory's monitor: concurrent servers on one directory share one generated pair, and one
            // that arrives after the write reads the file below.
            let generation_lock = ca_generation_lock(&directory);
            let _generation = generation_lock.lock();
            if !cert_path.exists() {
                return pending_authority(&directory);
            }
        }
        let cert_pem = std::fs::read_to_string(&cert_path).map_err(|e| format!("{}: {e}", cert_path.display()))?;
        if pem_der(&cert_pem, "CERTIFICATE").is_none() {
            return Err(format!(
                "certificate authority X509 certificate file '{}' exists but does not contain a valid PEM-encoded X.509 certificate; refusing to overwrite it — remove or repair the file, or point certificateAuthorityCertificate/directoryToSaveDynamicSSLCertificate elsewhere",
                cert_path.display()
            ));
        }
        let key_pem = std::fs::read_to_string(&key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
        return Ok((cert_pem, key_pem));
    }
    let read = |property: &str, default: &str| -> Result<String, String> {
        match config.property(property).filter(|p| !p.trim().is_empty() && !p.starts_with("org/mockserver/socket/")) {
            Some(path) => crate::class_path::read_string_or_file(&path).map_err(|e| format!("{property} {path}: {e}")),
            None => Ok(default.to_string()),
        }
    };
    Ok((read("certificateAuthorityCertificate", BUNDLED_CA_CERT)?, read("certificateAuthorityPrivateKey", BUNDLED_CA_KEY)?))
}

fn write_private(path: &std::path::Path, contents: &str) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(contents.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))
}

/// PEM in `JcaPEMWriter`'s layout: 64-column base64 between the armour lines.
fn pem(label: &str, der: &[u8]) -> String {
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// `generateCACert`: an RSA-2048 key and a self-signed CA certificate for `www.mockserver.com`, valid from five days
/// ago for ten years, the key as `JcaPEMWriter` writes an RSA key (PKCS#1).
fn generate_authority() -> Result<(String, String), String> {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    let pkcs8 = crate::keys::rsa_pkcs8(2048)?;
    let key = rsa::RsaPrivateKey::from_pkcs8_der(&pkcs8).map_err(|e| e.to_string())?;
    let pair = KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(pkcs8), &rcgen::PKCS_RSA_SHA256).map_err(|e| e.to_string())?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "www.mockserver.com");
    dn.push(DnType::OrganizationName, "MockServer");
    dn.push(DnType::LocalityName, "London");
    dn.push(DnType::StateOrProvinceName, "England");
    dn.push(DnType::CountryName, "UK");
    params.distinguished_name = dn;
    // `generateCACert`'s extensions, in its order: the subject key identifier (`BcX509ExtensionUtils`' SHA-1 of the
    // key bits), critical `BasicConstraints(true)`, and a non-critical key usage (digitalSignature, keyEncipherment,
    // dataEncipherment, keyCertSign, cRLSign); rcgen's own CA extensions (a SHA-256 identifier, a critical key usage)
    // are left out by keeping `is_ca` at `NoCa`
    params.custom_extensions = vec![
        extension(&[2, 5, 29, 14], false, der(0x04, &sha1(pair.public_key_raw()))),
        extension(&[2, 5, 29, 19], true, der(0x30, &der(0x01, &[0xff]))),
        extension(&[2, 5, 29, 15], false, der(0x03, &[0x01, 0xb6])),
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(5);
    params.not_after = now + time::Duration::days(365 * 10);
    params.serial_number = Some(positive_serial_number());
    let cert = params.self_signed(&pair).map_err(|e| e.to_string())?;
    let key_pem = key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).map_err(|e| e.to_string())?.to_string();
    Ok((pem("CERTIFICATE", cert.der()), key_pem))
}

/// A private key PEM as PKCS#8 (rcgen reads no PKCS#1).
fn pkcs8_pem(key_pem: &str) -> String {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;
    // an RSASSA-PSS key (PKCS#8 under id-RSASSA-PSS), or one under the OAEP or X.500 RSA OID that BouncyCastle reads
    // as RSA too, signs as the RSA key it carries
    let pss = || -> Option<rsa::RsaPrivateKey> {
        let block = x509_parser::pem::Pem::iter_from_buffer(key_pem.as_bytes()).next()?.ok()?;
        let (sequence, _) = cert_string::tlv(&block.contents)?;
        let parts = cert_string::items(sequence.content)?;
        let id = cert_string::oid(cert_string::items(parts.get(1)?.content)?.first()?.content)?;
        let aliased = matches!(id.as_str(), "1.2.840.113549.1.1.10" | key_string::RSA_OAEP | key_string::RSA_X500);
        (block.label == "PRIVATE KEY" && aliased).then_some(())?;
        rsa::RsaPrivateKey::from_pkcs1_der(parts.get(2)?.content).ok()
    };
    if let Some(key) = pss() && let Ok(pem) = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF) {
        return pem.to_string();
    }
    if !key_pem.contains("BEGIN RSA PRIVATE KEY") {
        return key_pem.to_string();
    }
    rsa::RsaPrivateKey::from_pkcs1_pem(key_pem)
        .ok()
        .and_then(|k| k.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).ok())
        .map(|p| p.to_string())
        .unwrap_or_else(|| key_pem.to_string())
}

/// `ProxySetupInfo`: what a client needs to use this server as an HTTPS proxy.
pub struct ProxySetup {
    pub ca_certificate_path: String,
    pub https_proxy: String,
    pub using_default_ca: bool,
}

pub const DEFAULT_CA_WARNING: &str = "The default CA private key is published in the MockServer repository — only safe for isolated local development. Re-run with --proxy-setup (or -Dmockserver.dynamicallyCreateCertificateAuthorityCertificate=true) to generate a unique private CA.";

impl ProxySetup {
    /// Writes the CA certificate out first, as both the startup block and the endpoint do.
    pub fn new(config: &Config, port: Option<u16>) -> Result<ProxySetup, String> {
        Ok(ProxySetup {
            ca_certificate_path: write_authority_certificate(config)?,
            https_proxy: format!("http://localhost:{}", port.unwrap_or(1080)),
            using_default_ca: using_default_authority(config),
        })
    }

    pub fn warning(&self) -> Option<&'static str> {
        self.using_default_ca.then_some(DEFAULT_CA_WARNING)
    }

    pub fn unix_env(&self) -> String {
        let (proxy, ca) = (&self.https_proxy, &self.ca_certificate_path);
        format!("export HTTPS_PROXY={proxy}\nexport NODE_EXTRA_CA_CERTS={ca}\nexport SSL_CERT_FILE={ca}\nexport REQUESTS_CA_BUNDLE={ca}")
    }

    pub fn powershell_env(&self) -> String {
        let (proxy, ca) = (&self.https_proxy, &self.ca_certificate_path);
        format!("$env:HTTPS_PROXY = \"{proxy}\"\n$env:NODE_EXTRA_CA_CERTS = \"{ca}\"\n$env:SSL_CERT_FILE = \"{ca}\"\n$env:REQUESTS_CA_BUNDLE = \"{ca}\"")
    }

    /// `copyPasteText` (this server never runs on Windows, so the Unix block).
    pub fn copy_paste_text(&self) -> String {
        let mut out = format!(
            "MockServer proxy setup\n======================\nCA certificate: {}\nHTTPS proxy:    {}\n\n{}\n\nNote: containerised clients must replace \"localhost\" with a host reachable from the container (e.g. host.docker.internal).",
            self.ca_certificate_path,
            self.https_proxy,
            self.unix_env()
        );
        if let Some(warning) = self.warning() {
            out.push_str(&format!("\n\nWARNING: {warning}"));
        }
        out
    }
}

/// `writeCertificateAuthorityToDisk`: the CA certificate in effect (never its key) to
/// `<directoryToSaveDynamicSSLCertificate>/mockserver-ca.pem`, written atomically; its absolute path.
pub fn write_authority_certificate(config: &Config) -> Result<String, String> {
    let der = certificate_authority_der(config).ok_or("no certificate authority certificate")?;
    let directory = dynamic_directory(config);
    std::fs::create_dir_all(&directory).map_err(|e| format!("{}: {e}", directory.display()))?;
    let target = std::path::absolute(directory.join("mockserver-ca.pem")).map_err(|e| e.to_string())?;
    let target: std::path::PathBuf = target.components().collect();
    let temporary = target.with_file_name(format!("mockserver-ca{}.pem.tmp", uuid::Uuid::new_v4().simple()));
    std::fs::write(&temporary, pem("CERTIFICATE", &der)).map_err(|e| format!("{}: {e}", temporary.display()))?;
    std::fs::rename(&temporary, &target).map_err(|e| format!("{}: {e}", target.display()))?;
    Ok(target.display().to_string())
}

/// Moved on, under the lock, by every change to a subject alternative name set or to the context that holds them, so
/// that what a worker last found held ([`LAST_SAN`]) is not trusted past it. Process-wide, so that a context built where
/// a dropped one was is not taken for it.
static SAN_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn sans_changed() {
    SAN_GENERATION.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
}

thread_local! {
    /// The `Host` this worker last found held: the context's address, the generation it was found in, the name.
    static LAST_SAN: std::cell::RefCell<(usize, u64, String)> = const { std::cell::RefCell::new((0, u64::MAX, String::new())) };
}

impl Tls {
    pub fn new(config: &Config) -> Result<Tls, String> {
        let notices = Arc::new(Mutex::new(Notices::default()));
        let (resolver, server) = Tls::assemble(config, None, &notices)?;
        let built = Built { signature: context_signature(config), resolver, server };
        sans_changed();
        Ok(Tls { notices, config: config.clone(), current: parking_lot::RwLock::new(built), authority_loaded: Default::default(), context_logged: Mutex::new(None), handshake_failures: Default::default(), created_pending: Mutex::new(None), client_leaf: Mutex::new((None, None)) })
    }

    /// The validator's WARN texts since the last call: logged by the first handshake after the context was built,
    /// as `createServerSslContext` builds it then.
    pub fn take_warnings(&self) -> Vec<crate::log_entry::LogEntry> {
        std::mem::take(&mut self.notices.lock().warnings)
    }

    /// The JDK's failure of a handshake whose ClientHello offers `offer` when the fixed server certificate's key is one
    /// it cannot serve that client, with the alert it sends. A DSA key ([`UnusableKey`]): in TLS 1.3
    /// `X509Authentication` finds no possession, in TLS 1.2 Netty's cipher suites have no DHE_DSS one. An Ed448 key
    /// ([`Ed448Key`]): the possession needs the chain's signature scheme among the client's
    /// `signature_algorithms_cert` (else `signature_algorithms`) and, in TLS 1.3, an EdDSA scheme, in TLS 1.2 an
    /// ECDHE_ECDSA suite; the CertificateVerify or ServerKeyExchange then needs `ed448`, or the JDK fails with an
    /// `internal_error`. `None` for another key, a client the key serves, or one that shares no version with the
    /// server (the engine refuses that first).
    pub fn unusable_key_failure(&self, offer: &ClientOffer) -> Option<KeyRefusal> {
        let limit = self.server_config_resolver().fixed.lock().limit;
        let limit = limit?;
        let enabled = protocol_versions(&self.config);
        let shared = |version: rustls::ProtocolVersion| offer.versions.contains(&u16::from(version)) && enabled.iter().any(|v| v.version == version);
        let (tls13, tls12) = (shared(rustls::ProtocolVersion::TLSv1_3), shared(rustls::ProtocolVersion::TLSv1_2));
        let handshake_failure = |message: &str| Some(KeyRefusal { alert: 40, reason: format!("javax.net.ssl.SSLHandshakeException: (handshake_failure) {message}") });
        let internal_error = |message: &str| Some(KeyRefusal { alert: 80, reason: format!("javax.net.ssl.SSLException: (internal_error) {message}") });
        const ED25519: u16 = 0x0807;
        const ED448: u16 = 0x0808;
        // the TLS 1.2 ECDHE_ECDSA suites the server enables
        const ECDHE_ECDSA: [u16; 3] = [0xc02b, 0xc02c, 0xcca9];
        match limit {
            KeyLimit::Dsa if tls13 => handshake_failure("No available authentication scheme"),
            KeyLimit::Dsa if tls12 => handshake_failure("no cipher suites in common"),
            KeyLimit::Dsa => None,
            KeyLimit::Ed448 { chain_scheme } => {
                let chain = offer.certificate_schemes.as_ref().unwrap_or(&offer.signature_schemes);
                let chain_accepted = chain_scheme.is_some_and(|scheme| chain.contains(&scheme));
                let signs = offer.signature_schemes.contains(&ED448);
                if tls13 {
                    if !chain_accepted || !offer.signature_schemes.iter().any(|s| matches!(*s, ED25519 | ED448)) {
                        handshake_failure("No available authentication scheme")
                    } else if !signs {
                        internal_error("No supported CertificateVerify signature algorithm for EdDSA  key")
                    } else {
                        None
                    }
                } else if tls12 {
                    if !chain_accepted || !offer.cipher_suites.iter().any(|s| ECDHE_ECDSA.contains(s)) {
                        handshake_failure("no cipher suites in common")
                    } else if !signs {
                        internal_error("No supported signature algorithm for EdDSA  key")
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        }
    }

    /// Whether a handshake was left without a certificate by a refused fixed certificate, and its SNI name: the
    /// failure `PortUnificationHandler` reports as "SSL or decoder fault".
    pub fn take_refused(&self) -> Option<(Option<String>, String, Option<String>)> {
        self.notices.lock().refused.pop_front()
    }

    /// Whether the server context cannot be built (a refused fixed certificate, a corrupt certificate authority, an
    /// unreadable `tlsMutualAuthenticationCertificateChain`): the SNI name and the cause chain, and the SEVERE entry
    /// logged first, for `SniHandler.onLookupComplete`, which fails the lookup before any `SslHandler` exists, so the
    /// connection closes without an alert.
    pub fn refusal(&self, sni: Option<&str>) -> Option<(Option<String>, String, Option<String>)> {
        let resolver = self.server_config_resolver();
        let fixed = resolver.fixed.lock();
        fixed.invalid.as_ref().map(|cause| (sni.map(str::to_ascii_lowercase), cause.clone(), fixed.severe.clone()))
    }

    /// The TRACE `created new X509{}with SAN Domain Names{}and IPs{}` entry of each leaf generated since the last call,
    /// with BouncyCastle's `toString` of it ([`bc_cert_string`]).
    fn log_minted(&self, state: &crate::state::State) {
        let minted = std::mem::take(&mut self.notices.lock().minted);
        if state.log_level != "TRACE" {
            return;
        }
        for minted in minted {
            log_minted_entry(state, minted);
        }
    }

    /// A certificate resolver and server configuration for the current configuration. `previous` lends the
    /// SAN names discovered at runtime, which a CA or protocol change does not forget (upstream
    /// keeps them in `Configuration`); a change of the configured SAN lists starts again from them.
    fn assemble(config: &Config, previous: Option<&Resolver>, notices: &Arc<Mutex<Notices>>) -> Result<(Arc<Resolver>, Arc<rustls::ServerConfig>), String> {
        let authority = authority_pems(config).and_then(|(c, k)| pem_der(&c, "CERTIFICATE").map(|d| (c, k, d)).ok_or_else(|| "certificate authority certificate is not PEM".to_string()));
        let mut broken: Option<(String, String)> = None;
        let (cert_pem, key_pem, cert_der) = match authority {
            Ok(authority) => authority,
            Err(e) => {
                // Upstream loads the authority when the first handshake builds the server context, where the
                // validator has refused a fixed pair for its authority already, or where a corrupt authority file
                // is refused rather than overwritten: the verdict is logged at the handshake, so the
                // bundled authority stands in until the configuration is fixed.
                let corrupt_dynamic = dynamic_authority(config) && e.contains("refusing to overwrite");
                if corrupt_dynamic {
                    broken = Some((Fixed::generation_failure(config, &e), format!("exception while generating private key and X509 certificate\njava.lang.RuntimeException: {e}")));
                } else if dynamic_authority(config) || validator::validate(config).is_ok() {
                    return Err(e);
                }
                let der = pem_der(BUNDLED_CA_CERT, "CERTIFICATE").ok_or(e)?;
                (BUNDLED_CA_CERT.to_string(), BUNDLED_CA_KEY.to_string(), der)
            }
        };
        // `signCertificate` signs every leaf `SHA256WithRSAEncryption` with the CA's private key: a CA
        // whose key is not RSA (BouncyCastle reads an RSASSA-PSS key as one) fails each leaf's generation, and with it
        // every handshake that needs a leaf.
        let set = |name: &str| config.property(name).is_some_and(|v| !v.trim().is_empty());
        let generates_leaf = !(set("privateKeyPath") && set("x509CertificatePath"));
        // a CA certificate the JDK's `CertificateFactory` refuses (a key `ECPublicKeyImpl` or the DH key class cannot
        // read) fails the same way, before any key is read
        if let (None, true, Some(message)) = (&broken, generates_leaf, cert_string::refusal(&cert_der)) {
            let path = authority_certificate_source(config).map(|(path, _)| path).unwrap_or_default();
            let reason = format!("Exception reading X509 from PEM file {path}\nCaused by: java.lang.RuntimeException: Exception creating X509 from PEM\nCaused by: java.security.cert.CertificateParsingException: java.io.IOException: {message}\nCaused by: java.io.IOException: {message}");
            broken = Some((Fixed::generation_failure(config, &reason), format!("exception while generating private key and X509 certificate\njava.lang.RuntimeException: Exception reading X509 from PEM file {path}")));
        }
        if let (None, true, Some(class)) = (&broken, generates_leaf, key_string::non_rsa_class(&key_pem)) {
            let reason = format!("shaded_package.org.bouncycastle.operator.OperatorCreationException: cannot create signer: Supplied key ({class}) is not a RSAPrivateKey instance");
            broken = Some((Fixed::generation_failure(config, &reason), format!("exception while generating private key and X509 certificate\n{reason}")));
        }
        // `generateCertificate` verifies each leaf with the CA certificate's public key: an RSA key that is not the
        // certificate's signs leaves the verification refuses
        if let (None, true, Some(public)) = (&broken, generates_leaf, key_string::rsa_public(&key_pem)) && cert_string::rsa_public(&cert_der).as_ref() != Some(&public) {
            let reason = "java.security.SignatureException: Signature does not match.";
            broken = Some((Fixed::generation_failure(config, reason), format!("exception while generating private key and X509 certificate\n{reason}")));
        }
        let key_pem = pkcs8_pem(&key_pem);
        let domain = config.property("sslCertificateDomainName").unwrap_or_else(|| "localhost".into());
        // Seeded (configured/default) entries are never normalised/validated and never evicted (upstream reads
        // them back verbatim from `sslSubjectAlternativeNameDomains`/`...Ips`; only a *dynamically discovered*
        // addition - Host header, CONNECT/SOCKS target, SNI - goes through `SanSet::add`).
        let list = |property: &str, default: &str| -> Vec<String> { san_list(config, property, default) };
        let domains_seed = list("sslSubjectAlternativeNameDomains", "localhost");
        let ips_seed = list("sslSubjectAlternativeNameIps", "127.0.0.1,0.0.0.0");
        // each set is replaced only when its own configured entries changed
        let sans = match previous {
            Some(previous) => {
                let kept = previous.sans.read();
                SanSets {
                    domains: if previous.seeds.0 == domains_seed { kept.domains.clone() } else { SanSet::seeded(domains_seed.clone()) },
                    ips: if previous.seeds.1 == ips_seed { kept.ips.clone() } else { SanSet::seeded(ips_seed.clone()) },
                }
            }
            None => SanSets { domains: SanSet::seeded(domains_seed.clone()), ips: SanSet::seeded(ips_seed.clone()) },
        };
        // `privateKeyPath` + `x509CertificatePath`: a fixed server certificate instead of minted leaves.
        let mut fixed = Fixed::load_checking_chain(config, &cert_der, fixed_clock_ms(config), notices)?;
        if let Some((chain, severe)) = broken {
            fixed.key = None;
            fixed.limit = None;
            fixed.invalid = Some(chain);
            fixed.severe = Some(severe);
            fixed.refused_by_validator = false;
        }
        let fixed = Mutex::new(fixed);
        let resolver = Arc::new(Resolver {
            fixed,
            authority: Authority { cert_pem, cert_der, key_pem },
            domain,
            leaf_validity_days: leaf_validity_days(config),
            config: config.clone(),
            seeds: (domains_seed, ips_seed),
            sans: Arc::new(parking_lot::RwLock::new(sans)),
            cache: Mutex::new(None),
            notices: notices.clone(),
        });
        let server = build_server(config, &resolver)?;
        Ok((resolver, server))
    }

    /// `createServerSslContext`: the cached server configuration while its signature holds, else a rebuilt one. A
    /// rebuild that fails keeps serving the previous configuration.
    fn server_config(&self) -> Arc<rustls::ServerConfig> {
        self.current.read().resolver.refresh_fixed();
        let signature = context_signature(&self.config);
        {
            let built = self.current.read();
            if built.signature == signature {
                return built.server.clone();
            }
        }
        let mut current = self.current.write();
        if current.signature != signature {
            match Tls::assemble(&self.config, Some(&current.resolver), &self.notices) {
                Ok((resolver, server)) => {
                    *current = Built { signature, resolver, server };
                    sans_changed();
                }
                Err(e) => eprintln!("ERROR TLS context not rebuilt: {e}"),
            }
        }
        current.server.clone()
    }

    /// `Configuration.addSubjectAlternativeName`: later leaves also name `host`; the cached ones are minted
    /// again. Driven from `src/http1.rs` (CONNECT), `src/socks.rs` (SOCKS) and `src/handler.rs` (every request's
    /// `Host` header, `HttpRequestHandler.channelRead0`); the TLS SNI path calls the `Resolver`-internal copy of
    /// this same logic directly (`Resolver::add_subject_alternative_name`).
    pub fn add_subject_alternative_name(&self, host: &str) {
        // Every request comes here with its `Host`, nearly always the one its worker saw last: while no subject
        // alternative name set changed since, that one is known held, and no lock shared with the other workers is
        // taken.
        let generation = SAN_GENERATION.load(std::sync::atomic::Ordering::Acquire);
        let me = self as *const Tls as usize;
        if LAST_SAN.with_borrow(|(tls, at, last)| *tls == me && *at == generation && last == host) {
            return;
        }
        // under the read lock rather than through a clone of the resolver
        if self.current.read().resolver.add_subject_alternative_name(host) {
            LAST_SAN.with_borrow_mut(|last| {
                last.0 = me;
                last.1 = generation;
                last.2.clear();
                last.2.push_str(host);
            });
        }
    }

    /// Rebuilds the TLS context if the configuration changed it, so the subject alternative name sets restart from the
    /// new seeds at once (as upstream replaces the sets when the configuration is updated) rather than at the next handshake.
    pub fn refresh(&self) {
        self.server_config();
    }

    /// An update that carries `sslSubjectAlternativeNameDomains`/`...Ips` replaces that set by the configured entries,
    /// dropping the names discovered so far, even when the entries are the ones already held.
    pub fn reset_subject_alternative_names(&self, domains: bool, ips: bool) {
        self.server_config();
        let resolver = self.current.read().resolver.clone();
        let mut sans = resolver.sans.write();
        if domains {
            sans.domains = SanSet::seeded(san_list(&self.config, "sslSubjectAlternativeNameDomains", "localhost"));
        }
        if ips {
            sans.ips = SanSet::seeded(san_list(&self.config, "sslSubjectAlternativeNameIps", "127.0.0.1,0.0.0.0"));
        }
        sans_changed();
        drop(sans);
        *resolver.cache.lock() = None;
    }

    /// The live subject alternative name sets (`Configuration.sslSubjectAlternativeNameDomains`/`Ips`): the configured
    /// entries plus every name discovered since (request `Host`, CONNECT/SOCKS targets, SNI), domains then IPs.
    pub fn subject_alternative_names(&self) -> (Vec<String>, Vec<String>) {
        // a configuration change since the last handshake restarts the sets from the new seeds
        self.server_config();
        let resolver = self.current.read().resolver.clone();
        let sans = resolver.sans.read();
        (sans.domains.ordered(), sans.ips.ordered())
    }

    /// `keyAndCertificateFactory.privateKey()` / `certificateChain()`: the server's own certificate.
    pub fn own_identity(&self) -> Option<Arc<CertifiedKey>> {
        let resolver = self.current.read().resolver.clone();
        resolver.resolve_name(None)
    }

    /// What the forwarding client presents when no forward-proxy key is configured: a fixed server certificate, else
    /// the client factory's own leaf, generated once (8.0.0 keeps a `NettySslContextFactory`, and with it a key and
    /// certificate factory, for the server and another for the client). Its TRACE entry waits for
    /// [`Tls::client_context_needed`].
    pub fn client_identity(&self) -> Option<Arc<CertifiedKey>> {
        let resolver = self.server_config_resolver();
        {
            let fixed = resolver.fixed.lock();
            if fixed.invalid.is_some() || fixed.key.is_some() {
                drop(fixed);
                return resolver.resolve_name(None);
            }
        }
        let mut client = self.client_leaf.lock();
        if let Some(key) = &client.0 {
            return Some(key.clone());
        }
        let (entry, minted) = resolver.mint_leaf()?;
        *client = (Some(entry.key.clone()), Some(minted));
        Some(entry.key)
    }

    /// The forwarding client's TLS context is built (`createClientSslContext`): its factory loads the CA the first
    /// time ([`Tls::authority_needed_by`]), then logs the leaf it generated, at once rather than at the next server
    /// handshake.
    pub fn client_context_needed(&self, state: &crate::state::State) {
        self.authority_needed_by(state, AuthorityUser::Client);
        let Some(minted) = self.client_leaf.lock().1.take() else { return };
        if state.log_level == "TRACE" {
            log_minted_entry(state, minted);
        }
    }

    /// The current resolver, after a configuration change since the last handshake rebuilt it.
    fn server_config_resolver(&self) -> Arc<Resolver> {
        self.server_config();
        self.current.read().resolver.clone()
    }

    /// The server configuration for QUIC: the same certificates and client-certificate policy, ALPN `h3`.
    pub fn quic_config(&self) -> Arc<rustls::ServerConfig> {
        let mut config = (*self.server_config()).clone();
        config.alpn_protocols = vec![b"h3".to_vec()];
        config.max_early_data_size = 0;
        Arc::new(config)
    }

    /// `Http3Server.buildQuicSslContext` over a fixed pair, which it reads at the start where the TCP path waits for a
    /// handshake: `BCKeyAndCertificateFactory.privateKey()`, `certificateChain()` (the file's certificates, then the CA
    /// unless the file holds it) and the PKCS12 key store of `QuicSslContextBuilder.forServer`. The exception chain that
    /// refuses the HTTP/3 start, outermost first; `None` when no fixed pair is set or it builds. The oracle checks
    /// neither the key against the certificate, nor the dates, nor the CA's signature here.
    pub(crate) fn quic_fixed_pair_causes(&self, config: &Config) -> Option<Vec<String>> {
        let (key_path, cert_path) = Fixed::paths(config)?;
        let key_causes = private_key_from_pem_file_causes(&key_path);
        if !key_causes.is_empty() {
            return Some(key_causes);
        }
        let mut chain: Vec<Vec<u8>> = match x509_chain_from_pem_file(&cert_path) {
            Ok(certificates) => certificates.into_iter().map(|c| c.der).collect(),
            Err(causes) => return Some(causes),
        };
        if chain.is_empty() {
            return Some(vec![format!("java.lang.RuntimeException: The file '{cert_path}' does not contain any valid PEM-encoded certificates")]);
        }
        let authority = self.server_config_resolver().authority.cert_der.to_vec();
        if !chain.contains(&authority) {
            chain.push(authority);
        }
        let invalid = "java.security.KeyStoreException: Certificate chain is not valid";
        (!key_store_chain_valid(&chain)).then(|| vec![format!("java.lang.IllegalArgumentException: {invalid}"), invalid.to_string()])
    }

    pub fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
        tokio_rustls::TlsAcceptor::from(self.server_config())
    }
}

/// The TRACE `created new X509{}with SAN Domain Names{}and IPs{}` entry of one leaf, with BouncyCastle's `toString`
/// of it ([`bc_cert_string`]).
fn log_minted_entry(state: &crate::state::State, (der, domains, ips, sans): Minted) {
    let Some(text) = bc_cert_string::certificate_to_string(&der) else { return };
    fn list(names: &[String]) -> crate::recorded::Arg {
        crate::recorded::Arg::list(names.iter().map(crate::recorded::Arg::from).collect())
    }
    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Trace, "created new X509{}with SAN Domain Names{}and IPs{}")
        .args([crate::recorded::Arg::from(text), list(&domains), list(&ips)])
        .live_arguments(move || {
            let sans = sans.read();
            vec![(1, list(&sans.domains.hash_order())), (2, list(&sans.ips.hash_order()))]
        });
    crate::log::entry(state, &entry);
    state.log.message(entry);
}

/// A PEM private key, PKCS#8, PKCS#1 (`RSA PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`), as a signing key.
fn signing_key(pem: &str) -> Result<Arc<dyn rustls::sign::SigningKey>, String> {
    use rustls_pki_types::pem::PemObject;
    let der = PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|_| "not a PEM private key".to_string())?;
    rustls::crypto::ring::sign::any_supported_type(&der).map_err(|e| e.to_string())
}

/// What a ClientHello offers that decides whether the fixed server certificate's key can serve it
/// ([`Tls::unusable_key_failure`]).
#[derive(Debug, Default)]
pub struct ClientOffer {
    /// `supported_versions`, else `legacy_version`
    pub versions: Vec<u16>,
    /// `signature_algorithms`
    pub signature_schemes: Vec<u16>,
    /// `signature_algorithms_cert`, when the client sends it
    pub certificate_schemes: Option<Vec<u16>>,
    pub cipher_suites: Vec<u16>,
}

/// The JDK's failure of a handshake the fixed key cannot serve: the alert description and the exception.
#[derive(Debug)]
pub struct KeyRefusal {
    pub alert: u8,
    pub reason: String,
}

/// A fixed key the JDK serves to some clients only, decided from the ClientHello before rustls reads it.
#[derive(Debug, Clone, Copy)]
enum KeyLimit {
    /// no client: [`UnusableKey`]
    Dsa,
    /// clients offering `ed448` and the chain's signature scheme (`None`: one no client can offer): [`Ed448Key`]
    Ed448 { chain_scheme: Option<u16> },
}

/// The TLS signature scheme of a certificate's signature algorithm, as the JDK matches it against a client's
/// `signature_algorithms_cert`; `None` for one without a fixed scheme (RSASSA-PSS, whose scheme its parameters name).
fn certificate_signature_scheme(der: &[u8]) -> Option<u16> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(match certificate.signature_algorithm.algorithm.to_id_string().as_str() {
        "1.2.840.113549.1.1.5" => 0x0201,
        "1.2.840.10045.4.1" => 0x0203,
        "1.2.840.113549.1.1.11" => 0x0401,
        "1.2.840.10045.4.3.2" => 0x0403,
        "1.2.840.113549.1.1.12" => 0x0501,
        "1.2.840.10045.4.3.3" => 0x0503,
        "1.2.840.113549.1.1.13" => 0x0601,
        "1.2.840.10045.4.3.4" => 0x0603,
        "1.3.101.112" => 0x0807,
        "1.3.101.113" => 0x0808,
        _ => return None,
    })
}

/// A fixed server certificate's DSA key, which the validator accepts but this TLS stack cannot sign
/// with, as the JDK cannot serve it: the connection refuses each handshake before rustls reads it
/// ([`Tls::unusable_key_failure`]); this key offers no signature scheme should one reach rustls all the same.
#[derive(Debug)]
struct UnusableKey;

impl rustls::sign::SigningKey for UnusableKey {
    fn choose_scheme(&self, _offered: &[rustls::SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        None
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::DSA
    }
}

/// A fixed server certificate's Ed448 key, signing with [`ed448`]. Which clients it serves is decided
/// before rustls reads the ClientHello ([`Tls::unusable_key_failure`]), so it signs with `ed448` whatever rustls
/// passes on: in TLS 1.2 rustls narrows the client's schemes to the suite's, which name no `ed448`. It reports
/// itself an Ed25519 key, the EdDSA key rustls's ECDHE_ECDSA suites take.
struct Ed448Key(Arc<Vec<u8>>);

impl std::fmt::Debug for Ed448Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ed448Key")
    }
}

impl rustls::sign::SigningKey for Ed448Key {
    fn choose_scheme(&self, _offered: &[rustls::SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        Some(Box::new(Ed448Signer(self.0.clone())))
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}

struct Ed448Signer(Arc<Vec<u8>>);

impl std::fmt::Debug for Ed448Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ed448Signer")
    }
}

impl rustls::sign::Signer for Ed448Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        ed448::sign(&self.0, message).ok_or_else(|| rustls::Error::General("Ed448 signing failed".into()))
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ED448
    }
}

/// A DSA or Ed448 private key in PEM, which ring cannot read: its signing key and what it limits.
fn other_signing_key(pem: &str) -> Option<(Arc<dyn rustls::sign::SigningKey>, bool)> {
    match key_string::dsa_or_ed448_public(pem)? {
        key_string::OtherPublic::Dsa { .. } => Some((Arc::new(UnusableKey), false)),
        key_string::OtherPublic::Ed448(_) => Some((Arc::new(Ed448Key(Arc::new(key_string::ed448_seed(pem)?))), true)),
    }
}

/// What the forwarding client offers to `host`.
#[derive(Debug)]
pub struct ForwardIdentity {
    pub key: Arc<CertifiedKey>,
}

/// `NettySslContextFactory.forwardProxyPrivateKey(host)` / `forwardProxyCertificateChain(host)`: what the forwarding
/// client presents to `host` — its `forwardProxyClientCertificatesByHost` pair, else `forwardProxyPrivateKey` with
/// `forwardProxyCertificateChain`, else the server's own certificate. `None` when the configured files cannot be read.
pub fn forward_identity(config: &Config, tls: Option<&Tls>, host: &str) -> Option<ForwardIdentity> {
    let (chain_path, key_path) = per_host_pair(&config.property("forwardProxyClientCertificatesByHost").unwrap_or_default(), host)
        .unwrap_or_else(|| (config.property("forwardProxyCertificateChain").unwrap_or_default(), config.property("forwardProxyPrivateKey").unwrap_or_default()));
    let (chain_path, key_path) = (chain_path.trim(), key_path.trim());
    if chain_path.is_empty() || key_path.is_empty() {
        return tls?.client_identity().map(|key| ForwardIdentity { key });
    }
    let chain: Vec<CertificateDer<'static>> = forward_chain(chain_path)?.into_iter().map(CertificateDer::from).collect();
    let signing = signing_key(&crate::class_path::read_string_or_file(key_path).ok()?).ok()?;
    Some(ForwardIdentity { key: Arc::new(CertifiedKey::new(chain, signing)) })
}

/// Whether the forward-proxy key and certificate chain configured for `host` cannot be loaded (a file that cannot be
/// read, or holds no certificate `CertificateFactory` reads): `createClientSslContext` then fails, and the forward with it (upstream 7a8b8c424, after 8.0.0).
pub fn forward_identity_unusable(config: &Config, host: &str) -> bool {
    let (chain_path, key_path) = per_host_pair(&config.property("forwardProxyClientCertificatesByHost").unwrap_or_default(), host)
        .unwrap_or_else(|| (config.property("forwardProxyCertificateChain").unwrap_or_default(), config.property("forwardProxyPrivateKey").unwrap_or_default()));
    let (chain_path, key_path) = (chain_path.trim(), key_path.trim());
    if chain_path.is_empty() || key_path.is_empty() {
        return false;
    }
    let chain = forward_chain(chain_path).unwrap_or_default();
    chain.is_empty() || crate::class_path::read_string_or_file(key_path).ok().and_then(|pem| signing_key(&pem).ok()).is_none()
}

/// `NettySslContextFactory.forwardProxyCertificateChain`: the chain file read as UTF-8 text
/// (`FileReader.readFileFromClassPathOrPath`) and its UTF-8 bytes handed to `CertificateFactory.generateCertificates`
/// (`PEMToFile.x509ChainFromPEM(String)`), as DER (`getEncoded`). A PEM file may hold certificates or a PKCS#7 bundle,
/// with indefinite lengths; a binary file does not survive the text round trip. `None` when it cannot be read or parsed.
fn forward_chain(path: &str) -> Option<Vec<Vec<u8>>> {
    let text = crate::class_path::read_string_or_file(path).ok()?;
    let certificates = x509::generate_certificates(text.as_bytes()).ok()?;
    Some(certificates.into_iter().map(|c| c.der).collect())
}

/// `resolveForwardProxyClientCertificate`: `host=certificateChainPath;privateKeyPath` entries, comma-separated, hosts
/// matched case-insensitively; malformed entries are skipped.
fn per_host_pair(mapping: &str, host: &str) -> Option<(String, String)> {
    if host.is_empty() {
        return None;
    }
    mapping.split(',').find_map(|entry| {
        let (mapped, pair) = entry.split_once('=').filter(|(h, _)| !h.is_empty())?;
        if !mapped.trim().eq_ignore_ascii_case(host) {
            return None;
        }
        let pair = pair.trim();
        let semicolon = pair.find(';').filter(|&i| i > 0 && i < pair.len() - 1)?;
        let (chain, key) = (pair[..semicolon].trim(), pair[semicolon + 1..].trim());
        (!chain.is_empty() && !key.is_empty()).then(|| (chain.to_string(), key.to_string()))
    })
}

fn pem_der(pem: &str, label: &str) -> Option<CertificateDer<'static>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = pem.split(&begin).nth(1)?.split(&end).next()?;
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body.split_whitespace().collect::<String>()).ok()?;
    Some(CertificateDer::from(bytes))
}

/// Fraction of a leaf's validity window that must elapse before it is proactively renewed
/// (`KeyAndCertificateFactory.RENEWAL_ELAPSED_FRACTION`).
const RENEWAL_ELAPSED_FRACTION: f64 = 0.8;

/// `Configuration.maxSubjectAlternativeNames` default: the cap on *dynamically discovered* SAN entries retained
/// per kind (domains, IPs — independently), past which the oldest dynamic entry is evicted.
const MAX_SUBJECT_ALTERNATIVE_NAMES_DEFAULT: i64 = 100;

/// One kind (domains, or IPs) of the growing, capped SAN set (`Configuration`'s `sslSubjectAlternativeNameDomains`
/// / `...Ips` plus the FIFO `dynamicSanDomainOrder` / `...IpOrder` that drives eviction).
#[derive(Default, Clone)]
struct SanSet {
    /// Fx-hashed: every request's `Host` is looked up here, and the set is bounded (`maxSubjectAlternativeNames`).
    members: rustc_hash::FxHashSet<String>,
    /// Insertion order of *dynamically added* members only — seeded (configured/default) members are never
    /// pushed here, so `bounded_add`'s eviction never removes one of them (`Configuration.boundedAdd`).
    dynamic_order: std::collections::VecDeque<String>,
    /// The configured members in the order they were given (the set a `PUT` or a property builds is iterated in
    /// insertion order within a hash bucket).
    seed_order: Vec<String>,
}

impl SanSet {
    fn seeded(initial: Vec<String>) -> Self {
        let mut seed_order: Vec<String> = Vec::new();
        for member in initial {
            if !seed_order.contains(&member) {
                seed_order.push(member);
            }
        }
        SanSet { members: seed_order.iter().cloned().collect(), dynamic_order: std::collections::VecDeque::new(), seed_order }
    }

    /// `Configuration.boundedAdd`: adds `value` (already normalised/validated by the caller), evicting the
    /// oldest dynamic entry first if already at `max` (a no-op once only protected entries remain — the set may
    /// then momentarily exceed `max`, exactly as upstream documents). Returns whether anything changed.
    fn bounded_add(&mut self, value: String, max: i64) -> bool {
        if value.is_empty() || self.members.contains(&value) {
            return false;
        }
        let max = if max <= 0 { i64::MAX } else { max };
        while self.members.len() as i64 >= max {
            let Some(evicted) = self.dynamic_order.pop_front() else { break };
            self.members.remove(&evicted);
        }
        self.dynamic_order.push_back(value.clone());
        self.members.insert(value);
        true
    }

    /// The members as `Sets.newConcurrentHashSet` iterates them: by `ConcurrentHashMap` bin (`spread(hashCode)`
    /// masked by the table, 16 bins doubled once the size reaches 3/4 of them), insertion order within a bin.
    fn hash_order(&self) -> Vec<String> {
        let ordered = self.ordered();
        let mut table = 16usize;
        while ordered.len() * 4 >= table * 3 {
            table *= 2;
        }
        let bin = |s: &str| {
            let h = s.encode_utf16().fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(i32::from(c))) as u32;
            ((h ^ (h >> 16)) & 0x7fff_ffff) as usize & (table - 1)
        };
        let mut keyed: Vec<(usize, usize, String)> = ordered.into_iter().enumerate().map(|(i, s)| (bin(&s), i, s)).collect();
        keyed.sort_by_key(|(b, i, _)| (*b, *i));
        keyed.into_iter().map(|(_, _, s)| s).collect()
    }

    /// The members in the order they entered the set: the configured entries as given, then the discovered ones.
    fn ordered(&self) -> Vec<String> {
        let mut ordered: Vec<String> = self.seed_order.iter().filter(|m| self.members.contains(*m)).cloned().collect();
        ordered.extend(self.dynamic_order.iter().filter(|m| self.members.contains(*m)).cloned());
        ordered
    }
}

#[derive(Default)]
struct SanSets {
    domains: SanSet,
    ips: SanSet,
}

/// `Configuration.normaliseSubjectAlternativeNameDomain`: lowercase, strip one trailing dot, require a non-empty
/// value of at most 253 characters made of dot-separated LDH labels (letters, digits, hyphen) of at most 63
/// characters each, optionally with a leading `*` wildcard label. `None` when invalid, so the caller drops it
/// rather than baking a bogus SAN into the leaf.
fn normalise_subject_alternative_name_domain(host: &str) -> Option<std::borrow::Cow<'_, str>> {
    let host = host.trim();
    let host = host.strip_suffix('.').unwrap_or(host);
    // a name already in lower case (nearly every `Host`) is borrowed as it is
    let normalised = if host.bytes().any(|b| b.is_ascii_uppercase()) { std::borrow::Cow::Owned(host.to_ascii_lowercase()) } else { std::borrow::Cow::Borrowed(host) };
    if normalised.is_empty() || normalised.len() > 253 {
        return None;
    }
    for (i, label) in normalised.split('.').enumerate() {
        if i == 0 && label == "*" {
            continue;
        }
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if !label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return None;
        }
    }
    Some(normalised)
}

/// A minted leaf, cached with the real-wall-clock validity window it was issued with, so a later lookup can
/// decide whether it has crossed its renewal threshold (`KeyAndCertificateFactory.isPastRenewalThreshold`)
/// independently of when "now" is read from (the clock seam only affects the *check*, never issuance).
struct CacheEntry {
    key: Arc<CertifiedKey>,
    not_before_secs: i64,
    not_after_secs: i64,
}

/// `NettySslContextFactory.FIXED_CERTIFICATE_RECHECK_INTERVAL_MS`.
const FIXED_CERTIFICATE_RECHECK_INTERVAL_MS: i64 = 60_000;

/// The clock of the fixed-certificate re-check, in milliseconds: the wall clock, or `sslCertificateRenewalClockSeconds`
/// (the Rust-only test seam of the renewal check) when set, as upstream's `fixedCertificateClock` is overridable.
fn fixed_clock_ms(config: &Config) -> i64 {
    config
        .property("sslCertificateRenewalClockSeconds")
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map(|seconds| seconds.saturating_mul(1000))
        .unwrap_or_else(|| (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64)
}

/// A fixed server certificate (`privateKeyPath` + `x509CertificatePath`) and what it was loaded from, so a rotated
/// file is picked up (`fixedServerCertificateChangedOnDisk`).
struct Fixed {
    key: Option<Arc<CertifiedKey>>,
    /// The two paths in effect when loaded.
    paths: Option<(String, String)>,
    /// Modification time and length of the certificate file when loaded.
    stamp: Option<(std::time::SystemTime, u64)>,
    last_check_ms: i64,
    /// `CertificateConfigurationValidator`'s verdict when it refused the pair: no certificate is served, so every
    /// handshake fails, until the configuration or the files change.
    invalid: Option<String>,
    /// An exception the log carries as a SEVERE entry before each refused handshake (a certificate authority or leaf
    /// that could not be generated).
    severe: Option<String>,
    /// `notAfter` of the served certificate in epoch milliseconds, and whether its expiry has been warned about.
    not_after_ms: Option<i64>,
    expiry_warned: bool,
    /// The values of a half-configured pair (only one path set), which is refused until they change.
    half: Option<(String, String)>,
    /// Whether `invalid` is `CertificateConfigurationValidator`'s verdict, which `createServerSslContext` reaches before
    /// its key-and-certificate factory loads the CA: such a handshake logs no CA load.
    refused_by_validator: bool,
    /// A key served to some clients only (DSA, Ed448), decided from each ClientHello.
    limit: Option<KeyLimit>,
}

impl Fixed {
    fn paths(config: &Config) -> Option<(String, String)> {
        let path = |name: &str| config.property(name).filter(|p| !p.trim().is_empty());
        Some((path("privateKeyPath")?, path("x509CertificatePath")?))
    }

    /// The two values when exactly one of `privateKeyPath` and `x509CertificatePath` is set.
    fn half_configured(config: &Config) -> Option<(String, String)> {
        let value = |name: &str| config.property(name).filter(|p| !p.trim().is_empty()).unwrap_or_default();
        let (key, cert) = (value("privateKeyPath"), value("x509CertificatePath"));
        (key.is_empty() != cert.is_empty()).then_some((key, cert))
    }

    /// The cause chain Netty's "SSL or decoder fault" entry carries when `NettySslContextFactory.createServerSslContext`
    /// fails on the validator's verdict (the Java frames are not reproduced).
    fn refusal(config: &Config, refused: &validator::Refusal) -> String {
        let value = |name: &str| config.property(name).unwrap_or_default();
        let authority = config.property("certificateAuthorityCertificate").unwrap_or_else(|| "org/mockserver/socket/CertificateAuthorityCertificate.pem".into());
        let reason = &refused.message;
        let mut chain = format!(
            "Caused by: java.lang.RuntimeException: Exception creating SSL context for server with privateKeyPath=\"{}\" and x509CertificatePath=\"{}\" and certificateAuthorityCertificate=\"{authority}\" - {reason}\nCaused by: java.lang.RuntimeException: {reason}",
            value("privateKeyPath"),
            value("x509CertificatePath")
        );
        for cause in &refused.causes {
            chain.push_str("\nCaused by: ");
            chain.push_str(cause);
        }
        chain
    }

    /// The cause chain of a certificate that `BCKeyAndCertificateFactory` failed to generate (`reason` is the innermost
    /// exception's text, which keeps any Java class prefix it carries).
    fn generation_failure(config: &Config, reason: &str) -> String {
        let reason = reason.strip_prefix("java.lang.RuntimeException: ").unwrap_or(reason);
        // a reason that starts with an exception's class name keeps it
        let (exception, text) = match reason.split_once(": ") {
            Some((class, rest)) if class.starts_with("shaded_package.") && !class.contains(' ') => (class, rest),
            _ => ("java.lang.RuntimeException", reason),
        };
        let authority = if dynamic_authority(config) {
            let directory = config.property("directoryToSaveDynamicSSLCertificate").filter(|d| !d.trim().is_empty());
            match directory {
                Some(directory) => format!("{}/CertificateAuthorityCertificate.pem", directory.trim_end_matches('/')),
                None => format!("{}/./CertificateAuthorityCertificate.pem", std::env::current_dir().map(|d| d.display().to_string()).unwrap_or_default()),
            }
        } else {
            config.property("certificateAuthorityCertificate").unwrap_or_else(|| "org/mockserver/socket/CertificateAuthorityCertificate.pem".into())
        };
        let value = |name: &str| config.property(name).unwrap_or_default();
        format!(
            "Caused by: java.lang.RuntimeException: Exception creating SSL context for server with privateKeyPath=\"{}\" and x509CertificatePath=\"{}\" and certificateAuthorityCertificate=\"{authority}\" - exception while generating private key and X509 certificate\nCaused by: java.lang.RuntimeException: exception while generating private key and X509 certificate\nCaused by: {exception}: {text}",
            value("privateKeyPath"),
            value("x509CertificatePath")
        )
    }

    fn stamp(cert_path: &str) -> Option<(std::time::SystemTime, u64)> {
        let metadata = std::fs::metadata(cert_path.trim()).ok().filter(|m| m.is_file())?;
        Some((metadata.modified().ok()?, metadata.len()))
    }

    /// [`Fixed::load`], then `createServerSslContext`'s next step, `trustCertificateChain`: a
    /// `tlsMutualAuthenticationCertificateChain` that cannot be read or holds no certificate data fails the context as a
    /// refused fixed pair does, so every handshake is refused, and the file is read again at the next one.
    fn load_checking_chain(config: &Config, authority: &CertificateDer<'static>, now_ms: i64, notices: &Mutex<Notices>) -> Result<Fixed, String> {
        let mut fixed = Fixed::load(config, authority, now_ms, notices)?;
        if fixed.invalid.is_none() && let Some(reason) = unreadable_mutual_authentication_chain(config) {
            let value = |name: &str| config.property(name).unwrap_or_default();
            let authority = config.property("certificateAuthorityCertificate").unwrap_or_else(|| "org/mockserver/socket/CertificateAuthorityCertificate.pem".into());
            fixed.key = None;
            fixed.limit = None;
            fixed.invalid = Some(format!(
                "Caused by: java.lang.RuntimeException: Exception creating SSL context for server with privateKeyPath=\"{}\" and x509CertificatePath=\"{}\" and certificateAuthorityCertificate=\"{authority}\" - {reason}",
                value("privateKeyPath"),
                value("x509CertificatePath")
            ));
        }
        Ok(fixed)
    }

    fn load(config: &Config, authority: &CertificateDer<'static>, now_ms: i64, notices: &Mutex<Notices>) -> Result<Fixed, String> {
        let Some((key_path, cert_path)) = Fixed::paths(config) else {
            // Only one of the two paths set: `CertificateConfigurationValidator` refuses it, as it refuses a bad pair.
            let invalid = validator::validate(config).err();
            if let Some(refused) = &invalid {
                eprintln!("ERROR TLS fixed certificate refused: {refused}");
            }
            let invalid = invalid.map(|refused| Fixed::refusal(config, &refused));
            let invalid_set = invalid.is_some();
            return Ok(Fixed { key: None, paths: None, stamp: None, last_check_ms: now_ms, invalid, severe: None, not_after_ms: None, expiry_warned: false, half: Fixed::half_configured(config), refused_by_validator: invalid_set, limit: None });
        };
        match validator::validate(config) {
            Ok(warnings) => notices.lock().warnings.extend(warnings.into_iter().map(|text| crate::log_entry::LogEntry::at(crate::log_entry::Level::Warn, text))),
            Err(refused) => {
            eprintln!("ERROR TLS fixed certificate refused: {refused}");
            let invalid = Some(Fixed::refusal(config, &refused));
            return Ok(Fixed { key: None, paths: Some((key_path, cert_path.clone())), stamp: Fixed::stamp(&cert_path), last_check_ms: now_ms, invalid, severe: None, not_after_ms: None, expiry_warned: false, half: None, refused_by_validator: true, limit: None });
            }
        }
        let key_pem = crate::class_path::read_string_or_file(key_path.trim()).map_err(|e| format!("privateKeyPath {key_path}: {e}"))?;
        let cert_pem = crate::class_path::read_string_or_file(cert_path.trim()).map_err(|e| format!("x509CertificatePath {cert_path}: {e}"))?;
        let (signing, ed448) = match signing_key(&key_pem) {
            Ok(signing) => (signing, None),
            Err(e) => other_signing_key(&key_pem).map(|(signing, ed448)| (signing, Some(ed448))).ok_or(e).map_err(|e| format!("privateKeyPath {key_path}: {e}"))?,
        };
        let mut chain: Vec<CertificateDer<'static>> = client_cert::pem_chain(&cert_pem).into_iter().map(CertificateDer::from).collect();
        let limit = ed448.map(|ed448| if ed448 { KeyLimit::Ed448 { chain_scheme: chain.first().and_then(|der| certificate_signature_scheme(der)) } } else { KeyLimit::Dsa });
        chain.push(authority.clone());
        let stamp = Fixed::stamp(&cert_path);
        let not_after_ms = chain.first().and_then(|der| x509_parser::parse_x509_certificate(der).ok()).map(|(_, c)| c.validity().not_after.timestamp() * 1000);
        Ok(Fixed {
            key: Some(Arc::new(CertifiedKey::new(chain, signing))),
            paths: Some((key_path, cert_path)),
            stamp,
            last_check_ms: now_ms,
            invalid: None,
            severe: None,
            not_after_ms,
            expiry_warned: false,
            half: None,
            refused_by_validator: false,
            limit,
        })
    }
}

struct Resolver {
    fixed: Mutex<Fixed>,
    authority: Authority,
    domain: String,
    /// `sslCertificateLeafValidityInDays`, resolved and clamped once at construction (§`leaf_validity_days`).
    leaf_validity_days: i64,
    /// Live handle on the server's configuration: `maxSubjectAlternativeNames` and the renewal clock seam are
    /// read fresh on every call (its mutable state is `Arc`-shared, so this clone sees runtime changes too).
    config: Config,
    /// Grows with `Host` headers, CONNECT/SOCKS targets and SNI hostnames (`Configuration.addSubjectAlternativeName`).
    sans: Arc<parking_lot::RwLock<SanSets>>,
    /// The configured SAN lists the resolver was seeded from.
    seeds: (Vec<String>, Vec<String>),
    /// The generated leaf (`BCKeyAndCertificateFactory`'s one `x509Certificate`), whatever the SNI name: every leaf
    /// carries the whole SAN set, so a new name clears it and the next handshake generates another.
    cache: Mutex<Option<CacheEntry>>,
    notices: Arc<Mutex<Notices>>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Resolver")
    }
}

impl Resolver {
    /// `createServerSslContext`'s fixed-certificate part: reloads when the configured paths changed, or (at most once
    /// per `FIXED_CERTIFICATE_RECHECK_INTERVAL_MS`, a stat only) when the certificate file's modification time or
    /// length changed. A reload that fails keeps serving the previous certificate.
    fn refresh_fixed(&self) {
        let now_ms = fixed_clock_ms(&self.config);
        let mut fixed = self.fixed.lock();
        let paths = Fixed::paths(&self.config);
        let changed = if paths != fixed.paths || (paths.is_none() && Fixed::half_configured(&self.config) != fixed.half) {
            true
        } else if fixed.invalid.is_some() && fixed.severe.is_none() {
            // `createServerSslContext` caches only a context it managed to build: a refused pair is validated again at
            // every handshake, so files that appear or are repaired are picked up at once
            true
        } else if let Some((_, cert_path)) = &paths {
            if now_ms - fixed.last_check_ms < FIXED_CERTIFICATE_RECHECK_INTERVAL_MS {
                false
            } else {
                fixed.last_check_ms = now_ms;
                let rotated = fixed.stamp.is_some() && Fixed::stamp(cert_path) != fixed.stamp;
                // unchanged on disk but past its `notAfter`: a single WARN (the certificate is still served)
                if !rotated && !fixed.expiry_warned && fixed.key.is_some() && let Some(not_after_ms) = fixed.not_after_ms.filter(|n| now_ms >= *n) {
                    fixed.expiry_warned = true;
                    let date = chrono::DateTime::from_timestamp_millis(not_after_ms).map(|d| d.format("%a %b %d %H:%M:%S GMT %Y").to_string()).unwrap_or_default();
                    self.notices.lock().warnings.push(
                        crate::log_entry::LogEntry::at(
                            crate::log_entry::Level::Warn,
                            "the configured fixed server certificate at {} has expired (notAfter {}) but is still being served; MockServer does not renew user-supplied certificates — replace the file at x509CertificatePath (and privateKeyPath) with a valid certificate",
                        )
                        .args([cert_path.clone(), date]),
                    );
                }
                rotated
            }
        } else {
            false
        };
        if changed {
            match Fixed::load_checking_chain(&self.config, &self.authority.cert_der, now_ms, &self.notices) {
                Ok(reloaded) => *fixed = reloaded,
                Err(e) => eprintln!("ERROR TLS fixed certificate not reloaded: {e}"),
            }
        }
    }

    /// `Configuration.addSubjectAlternativeName`: strips a port with a naive "text before the first colon" split
    /// (matches upstream's `substringBefore`, including its quirk of mangling an unbracketed IPv6 literal, which
    /// still contains colons after port-stripping — confirmed against the oracle: a CONNECT to `[2001:db8::42]:443`
    /// adds a bogus `2001` *domain* SAN, not an IPv6 SAN), then either bounded-adds it as an IP (no further
    /// validation, matching upstream) or normalises+validates it as a domain before bounded-adding it. Invalidates
    /// the leaf cache when anything actually changed, so a later handshake mints a leaf carrying the new name.
    /// Whether nothing changed (the name was held already, or is not one that is added).
    fn add_subject_alternative_name(&self, host: &str) -> bool {
        let host = host.trim();
        if host.is_empty() {
            return true;
        }
        let Some(host_without_port) = host.split(':').next().filter(|s| !s.is_empty()) else {
            return true;
        };
        // Every exchange's `Host` comes here, and nearly always it is a name already held: that is answered under the
        // read lock, with the normalising done before any lock (the one write lock every request worker
        // queued behind).
        let ip = host_without_port.parse::<std::net::IpAddr>().is_ok();
        let value = if ip { Some(std::borrow::Cow::Borrowed(host_without_port)) } else { normalise_subject_alternative_name_domain(host_without_port) };
        let Some(value) = value.filter(|v| !v.is_empty()) else { return true };
        {
            let sans = self.sans.read();
            if (if ip { &sans.ips } else { &sans.domains }).members.contains(value.as_ref()) {
                return true;
            }
        }
        let max = self.config.int_property("maxSubjectAlternativeNames", MAX_SUBJECT_ALTERNATIVE_NAMES_DEFAULT);
        let mut sans = self.sans.write();
        let value = value.into_owned();
        let added = if ip { sans.ips.bounded_add(value, max) } else { sans.domains.bounded_add(value, max) };
        sans_changed();
        drop(sans);
        if added {
            *self.cache.lock() = None;
        }
        false
    }

    /// "now" for the renewal-threshold check only (never for issuance — `mint`'s `not_before`/`not_after` always
    /// anchor to real wall-clock, exactly like upstream's `KeyAndCertificateFactory.notBefore`/`notAfter`).
    /// `sslCertificateRenewalClockSeconds` is a Rust-only test seam (not a real upstream property, mirroring
    /// `BCKeyAndCertificateFactory`'s package-private static `renewalClock`), settable live via
    /// `Server::set_property` so a test can cross the 80%-elapsed threshold without waiting real days.
    fn now_secs(&self) -> i64 {
        self.config
            .property("sslCertificateRenewalClockSeconds")
            .and_then(|v| v.trim().parse::<i64>().ok())
            .unwrap_or_else(|| time::OffsetDateTime::now_utc().unix_timestamp())
    }

    /// `buildAndSavePrivateKeyAndX509Certificate`: a leaf for the current subject alternative names, with what its
    /// TRACE `created new X509…` entry shows (DER, the SAN domains and IPs).
    fn mint_leaf(&self) -> Option<(CacheEntry, Minted)> {
        // `buildAndSavePrivateKeyAndX509Certificate`: a new RSA-2048 key pair for every leaf (`RSA2048_SHA256`)
        let leaf_der = &crate::keys::rsa_pkcs8(2048).ok()?;
        let signing = rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_der.clone()))).ok()?;
        let sans = self.sans.read();
        let (domains, ips) = (sans.domains.hash_order(), sans.ips.hash_order());
        drop(sans);
        let mut params = CertificateParams::default();
        // Encoded with the common name first (`CN=localhost,O=MockServer,L=London,ST=England,C=UK` as the oracle's
        // leaf is), so `X500Principal.getName()` prints it country first.
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, self.domain.as_str());
        dn.push(DnType::OrganizationName, "MockServer");
        dn.push(DnType::LocalityName, "London");
        dn.push(DnType::StateOrProvinceName, "England");
        dn.push(DnType::CountryName, "UK");
        params.distinguished_name = dn;
        let now = time::OffsetDateTime::now_utc();
        // `KeyAndCertificateFactory.notBefore()`: 5-day back-date, in case the clock goes back.
        params.not_before = now - time::Duration::days(5);
        params.not_after = params.not_before + time::Duration::days(self.leaf_validity_days);
        let (not_before_secs, not_after_secs) = (params.not_before.unix_timestamp(), params.not_after.unix_timestamp());
        params.serial_number = Some(positive_serial_number());

        let leaf_pair = KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(leaf_der.clone()), &rcgen::PKCS_RSA_SHA256).ok()?;
        let (_, authority) = x509_parser::parse_x509_certificate(&self.authority.cert_der).ok()?;
        // `createAuthorityKeyIdentifier`: SHA-1 of the CA's key bits, whatever identifier the CA itself carries
        let authority_id = sha1(&authority.public_key().subject_public_key.data);
        params.custom_extensions = leaf_extensions(&sha1(leaf_pair.public_key_raw()), &authority_id, &self.domain, &domains, &ips);
        // The CA key's own algorithm (RSA or EC) signs the leaf.
        let ca_key = KeyPair::from_pem(&self.authority.key_pem).ok()?;
        let issuer = Issuer::from_ca_cert_pem(&self.authority.cert_pem, ca_key).ok()?;
        let leaf = params.signed_by(&leaf_pair, &issuer).ok()?;
        // `BCKeyAndCertificateFactory`: under `preventCertificateDynamicUpdate` or `proactivelyInitialiseTLS` the leaf pair
        // is saved next to the certificate authority, the key readable by its owner alone.
        if self.config.bool_property("preventCertificateDynamicUpdate", false) || self.config.bool_property("proactivelyInitialiseTLS", false) {
            let directory = dynamic_directory(&self.config);
            let saved = std::fs::create_dir_all(&directory)
                .map_err(|e| e.to_string())
                .and_then(|_| write_private(&directory.join("PKCS8PrivateKey.pem"), &pem("PRIVATE KEY", leaf_der)))
                .and_then(|_| std::fs::write(directory.join("Certificate.pem"), leaf.pem()).map_err(|e| e.to_string()));
            if let Err(e) = saved {
                eprintln!("ERROR TLS could not save the dynamic certificate: {e}");
            }
        }
        let chain = vec![leaf.der().clone(), self.authority.cert_der.clone()];
        let entry = CacheEntry { key: Arc::new(CertifiedKey::new(chain, signing)), not_before_secs, not_after_secs };
        Some((entry, (leaf.der().to_vec(), domains, ips, self.sans.clone())))
    }

    /// The server factory's leaf ([`Resolver::mint_leaf`]), queued for the next handshake's context set-up to log.
    fn mint(&self) -> Option<CacheEntry> {
        let (entry, minted) = self.mint_leaf()?;
        let mut notices = self.notices.lock();
        // drained by each handshake; bounded in case none follows
        if notices.minted.len() >= 16 {
            notices.minted.pop_front();
        }
        notices.minted.push_back(minted);
        Some(entry)
    }
}

/// `generateLeafCert`'s extensions, in its order: subject key identifier, `BasicConstraints(false)`, authority key
/// identifier (`BcX509ExtensionUtils`' SHA-1 of the public key bits, `authority_id` the CA's), extended key usage (serverAuth,
/// clientAuth), critical key usage (digitalSignature, keyEncipherment), and the subject alternative names: the domain,
/// then the SAN domains and the IPs that parse, as the sets iterate.
fn leaf_extensions(leaf_id: &[u8], authority_id: &[u8], domain: &str, domains: &[String], ips: &[String]) -> Vec<rcgen::CustomExtension> {
    let mut names: Vec<u8> = std::iter::once(domain).chain(domains.iter().map(String::as_str)).flat_map(|n| der(0x82, n.as_bytes())).collect();
    for ip in ips {
        match ip.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(v4)) => names.extend(der(0x87, &v4.octets())),
            Ok(std::net::IpAddr::V6(v6)) => names.extend(der(0x87, &v6.octets())),
            Err(_) => {}
        }
    }
    const SERVER_AUTH: [u8; 8] = [0x2b, 6, 1, 5, 5, 7, 3, 1];
    const CLIENT_AUTH: [u8; 8] = [0x2b, 6, 1, 5, 5, 7, 3, 2];
    vec![
        extension(&[2, 5, 29, 14], false, der(0x04, leaf_id)),
        extension(&[2, 5, 29, 19], false, der(0x30, &[])),
        extension(&[2, 5, 29, 35], false, der(0x30, &der(0x80, authority_id))),
        extension(&[2, 5, 29, 37], false, der(0x30, &[der(0x06, &SERVER_AUTH), der(0x06, &CLIENT_AUTH)].concat())),
        extension(&[2, 5, 29, 15], true, der(0x03, &[0x05, 0xa0])),
        extension(&[2, 5, 29, 17], false, der(0x30, &names)),
    ]
}

/// A DER TLV.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len().to_be_bytes();
    let significant: Vec<u8> = length.iter().copied().skip_while(|b| *b == 0).collect();
    if content.len() < 0x80 {
        out.push(content.len() as u8);
    } else {
        out.push(0x80 | significant.len() as u8);
        out.extend(significant);
    }
    out.extend_from_slice(content);
    out
}

fn extension(oid: &[u64], critical: bool, content: Vec<u8>) -> rcgen::CustomExtension {
    let mut extension = rcgen::CustomExtension::from_oid_content(oid, content);
    extension.set_criticality(critical);
    extension
}

/// `KeyAndCertificateFactory.positiveSerialNumber`: `new BigInteger(64, new SecureRandom())`, or one when that is zero
/// (rcgen encodes the bytes as a positive INTEGER in its minimal form).
fn positive_serial_number() -> SerialNumber {
    let serial = rand_core::RngCore::next_u64(&mut rand_core::OsRng).max(1);
    SerialNumber::from_slice(&serial.to_be_bytes())
}

/// `BcX509ExtensionUtils`' key identifier: SHA-1 of a public key's bits.
fn sha1(bits: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, bits).as_ref().to_vec()
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let key = self.resolve_name(hello.server_name())?;
        // the handshake signs in the order of the client's `signature_algorithms`
        let order = hello.signature_schemes().to_vec();
        Some(Arc::new(CertifiedKey { cert: key.cert.clone(), key: Arc::new(ClientOrderKey { inner: key.key.clone(), order }), ocsp: key.ocsp.clone() }))
    }
}

/// `KeyAndCertificateFactory.isPastRenewalThreshold`: true once `now` is at or past
/// `notBefore + RENEWAL_ELAPSED_FRACTION * (notAfter - notBefore)`.
fn past_renewal_threshold(entry: &CacheEntry, now_secs: i64) -> bool {
    let window = entry.not_after_secs - entry.not_before_secs;
    if window <= 0 {
        return false;
    }
    let renew_at = entry.not_before_secs + (window as f64 * RENEWAL_ELAPSED_FRACTION) as i64;
    now_secs >= renew_at
}

impl Resolver {
    fn resolve_name(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        {
            let fixed = self.fixed.lock();
            if let Some(cause) = &fixed.invalid {
                self.notices.lock().refused.push_back((sni.map(str::to_ascii_lowercase), cause.clone(), fixed.severe.clone()));
                return None;
            }
            if let Some(key) = &fixed.key {
                return Some(key.clone());
            }
        }
        let sni = sni.map(str::to_ascii_lowercase);
        if let Some(name) = &sni {
            // `SniHandler.lookup`: the SNI hostname is persisted into the same growing, capped SAN set as a
            // `Host` header or CONNECT/SOCKS target, BEFORE minting, so it also shows up on a later, unrelated
            // connection's leaf (confirmed against the oracle) — not just ephemerally on this one.
            self.add_subject_alternative_name(name);
        }
        let now = self.now_secs();
        if let Some(found) = self.cache.lock().as_ref() && !past_renewal_threshold(found, now) {
            return Some(found.key.clone());
        }
        // `new X500Name("CN=" + domain + ...)` cannot parse a value that starts with `#` and is not hex-encoded DER:
        // the generation fails, the handshake is left without a certificate.
        if self.domain.starts_with('#') && !self.domain[1..].chars().all(|c| c.is_ascii_hexdigit()) {
            let reason = "shaded_package.org.bouncycastle.asn1.ASN1ParsingException: can't recode value for oid 2.5.4.3";
            let cause = Fixed::generation_failure(&self.config, reason);
            self.notices.lock().refused.push_back((sni, cause, Some(format!("exception while generating private key and X509 certificate\n{reason}"))));
            return None;
        }
        let minted = self.mint()?;
        let served = minted.key.clone();
        *self.cache.lock() = Some(minted);
        Some(served)
    }

    /// `SniHandler.lookup` before the handshake: the `sni` name joins the SAN set and the leaf is generated if there
    /// is none, so the context set-up logs it. A fixed certificate, or a domain the generation refuses, is left to the
    /// handshake, which reports it.
    fn prepare(&self, sni: Option<&str>) {
        {
            let fixed = self.fixed.lock();
            if fixed.invalid.is_some() || fixed.key.is_some() {
                return;
            }
        }
        if self.domain.starts_with('#') && !self.domain[1..].chars().all(|c| c.is_ascii_hexdigit()) {
            return;
        }
        if let Some(name) = sni {
            self.add_subject_alternative_name(&name.to_ascii_lowercase());
        }
        let _ = self.resolve_name(None);
    }
}

/// Netty's server context with `ClientAuth.OPTIONAL` (`REQUIRE` under `tlsMutualAuthenticationRequired`): a client
/// certificate is asked for and, when sent, recorded on the request. With `tlsMutualAuthenticationRequired` or a
/// `tlsMutualAuthenticationCertificateChain`, the chain must lead to one of those certificates or the CA
/// (`trustCertificateChain`); otherwise any certificate is accepted (`InsecureTrustManagerFactory`) and only the
/// handshake signature is checked.
#[derive(Debug)]
struct ClientCertificates {
    provider: Arc<rustls::crypto::CryptoProvider>,
    mandatory: bool,
    trust: Option<Trust>,
}

#[derive(Debug)]
struct ChainRejected;

impl std::fmt::Display for ChainRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("client certificate chain is not trusted")
    }
}

impl std::error::Error for ChainRejected {}

#[derive(Debug)]
struct Trust {
    anchors: Vec<Vec<u8>>,
    hints: Vec<rustls::DistinguishedName>,
}

/// Why `trustCertificateChain` fails on `tlsMutualAuthenticationCertificateChain` (`x509ChainFromPEMFile`'s exception and
/// its causes, as `Throwable.toString` lines), or `None` when it is unset or reads (an empty file reads as no
/// certificates, which trusts only the CA).
fn unreadable_mutual_authentication_chain(config: &Config) -> Option<String> {
    let path = config.property("tlsMutualAuthenticationCertificateChain").filter(|p| !p.trim().is_empty())?;
    let causes = x509_chain_from_pem_file(&path).err()?;
    Some(format!("Exception reading X509 from PEM file {path}\nCaused by: {}", causes.join("\nCaused by: ")))
}

/// `PEMToFile.x509ChainFromPEMFile`: the certificates in `path`, or the exception chain it throws (one
/// `Throwable.toString` each, outermost first).
fn x509_chain_from_pem_file(path: &str) -> Result<Vec<x509::Certificate>, Vec<String>> {
    let reading = format!("java.lang.RuntimeException: Exception reading X509 from PEM file {path}");
    match crate::class_path::read_or_file(path.trim()) {
        Ok(bytes) => x509::generate_certificates(&bytes).map_err(|e| [vec![reading, "java.lang.RuntimeException: Exception creating X509 from PEM".into()], e.chain()].concat()),
        // `FileInputStream`'s text names the path and the OS error
        Err(e) => Err(vec![reading, format!("java.io.FileNotFoundException: {path} ({})", java_io_reason(&e))]),
    }
}

/// `PEMToFile.privateKeyFromPEMFile`'s exception chain, outermost first, for a key file it cannot read; empty when
/// it reads. `privateKeyFromPEMFile` wraps `privateKeyFromPEM`'s exception; a key our own reader takes is not refused
/// over what the port of BouncyCastle's reader does not model.
fn private_key_from_pem_file_causes(key_path: &str) -> Vec<String> {
    const READING_KEY: &str = "java.lang.RuntimeException: Exception reading private key from PEM file";
    let key_pem = match crate::class_path::read_string_or_file(key_path.trim()) {
        Ok(pem) => pem,
        Err(e) => {
            let loading = format!("java.lang.RuntimeException: Exception while loading \"{key_path}\"");
            return vec![READING_KEY.into(), loading, format!("java.io.FileNotFoundException: {key_path} ({})", java_io_reason(&e))];
        }
    };
    match crate::keys::private_key_from_pem(&key_pem) {
        Err(failure) if signing_key(&key_pem).is_err() => [vec![READING_KEY.to_string()], crate::keys::exception_chain(&failure)].concat(),
        _ => Vec::new(),
    }
}

/// `PKCS12KeyStore.validateChain`, which `KeyStore.setKeyEntry` applies: each certificate's issuer is the next one's
/// subject (compared by name, never by signature) and no certificate repeats. A certificate we cannot parse is not held
/// against the chain.
fn key_store_chain_valid(chain: &[Vec<u8>]) -> bool {
    let names: Option<Vec<_>> = chain
        .iter()
        .map(|der| x509_parser::parse_x509_certificate(der).ok().map(|(_, c)| ((c.issuer().as_raw().to_vec(), c.issuer().to_string()), (c.subject().as_raw().to_vec(), c.subject().to_string()))))
        .collect();
    let Some(names) = names else { return true };
    // `X500Principal.equals` compares canonical names: the encodings, or the names ignoring case
    let same = |a: &(Vec<u8>, String), b: &(Vec<u8>, String)| a.0 == b.0 || a.1.eq_ignore_ascii_case(&b.1);
    let linked = names.windows(2).all(|pair| same(&pair[0].0, &pair[1].1));
    linked && chain.iter().enumerate().all(|(i, c)| !chain[..i].contains(c))
}

/// [`unreadable_mutual_authentication_chain`] as the exception chain `Http3Server.buildTrustCertificateChain` throws,
/// from `x509ChainFromPEMFile`'s exception to the root cause, one `Throwable.toString` each.
pub(crate) fn mutual_authentication_chain_causes(config: &Config) -> Option<Vec<String>> {
    let reason = unreadable_mutual_authentication_chain(config)?;
    Some(reason.lines().skip(1).map(|line| line.strip_prefix("Caused by: ").unwrap_or(line).to_string()).collect())
}

/// The OS error text `FileInputStream` puts in brackets after the path.
fn java_io_reason(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::NotFound => "No such file or directory",
        std::io::ErrorKind::PermissionDenied => "Permission denied",
        std::io::ErrorKind::IsADirectory => "Is a directory",
        _ => "Input/output error",
    }
}

impl ClientCertificates {
    fn new(config: &Config, authority: &CertificateDer<'static>) -> Result<ClientCertificates, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mandatory = config.hot_bool(crate::config::Hot::TlsMutualAuthenticationRequired, false);
        let chain_path = config.property("tlsMutualAuthenticationCertificateChain").filter(|p| !p.trim().is_empty());
        let trust = if mandatory || chain_path.is_some() {
            let mut anchors = match &chain_path {
                // `trustCertificateChain` reads the file through `x509ChainFromPEMFile`, a byte stream into
                // `CertificateFactory.generateCertificates`: PEM blocks, DER, a PKCS#7 bundle, indefinite lengths.
                // A file that cannot be read or is no certificate data refuses every handshake before this verifier is
                // asked ([`Fixed::load_checking_chain`]).
                Some(path) => crate::class_path::read_or_file(path.trim())
                    .ok()
                    .and_then(|bytes| x509::generate_certificates(&bytes).ok())
                    .map(|chain| chain.into_iter().map(|c| c.der).collect())
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            // `DataPlaneMutualTlsTrust.clientCertificateTrust` (upstream cb3817ce3, 9.1.0): the bundled CA is never
            // trusted without `tlsMutualAuthenticationAllowBundledCa`, so the chain alone is trusted when MockServer's
            // CA is the bundled one, and a context that would trust it is not built
            if allow_bundled_authority(config) {
                anchors.push(authority.to_vec());
            } else if contains_bundled_authority(&anchors) {
                return Err(DATA_PLANE_MTLS_BUNDLED_CA_IN_CHAIN.to_string());
            } else if !contains_bundled_authority(&[authority.to_vec()]) {
                anchors.push(authority.to_vec());
            } else if chain_path.is_none() {
                return Err(DATA_PLANE_MTLS_REFUSED.to_string());
            }
            // The certificate request names the trusted subjects, as the JDK's trust manager's accepted issuers do.
            let hints = anchors
                .iter()
                .filter_map(|a| x509_parser::parse_x509_certificate(a).ok().map(|(_, c)| rustls::DistinguishedName::from(c.subject().as_raw().to_vec())))
                .collect();
            Some(Trust { anchors, hints })
        } else {
            None
        };
        Ok(ClientCertificates { provider, mandatory, trust })
    }
}

impl rustls::server::danger::ClientCertVerifier for ClientCertificates {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.trust.as_ref().map_or(&[], |t| &t.hints)
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let Some(trust) = &self.trust else {
            return Ok(rustls::server::danger::ClientCertVerified::assertion());
        };
        let intermediates: Vec<&[u8]> = intermediates.iter().map(|c| c.as_ref()).collect();
        if client_cert::chain_validates(end_entity, &intermediates, &trust.anchors) {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        } else {
            // SunJSSE answers a rejected chain with `certificate_unknown`.
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(Arc::new(ChainRejected)))))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::per_host_pair;

    #[test]
    fn per_host_pairs_match_case_insensitively_and_skip_malformed_entries() {
        let mapping = "bad, nohost=;x ,API.example = a.pem ; a-key.pem,127.0.0.1=b.pem;b-key.pem";
        assert_eq!(per_host_pair(mapping, "api.EXAMPLE"), Some(("a.pem".into(), "a-key.pem".into())));
        assert_eq!(per_host_pair(mapping, "127.0.0.1"), Some(("b.pem".into(), "b-key.pem".into())));
        assert_eq!(per_host_pair(mapping, "nohost"), None);
        assert_eq!(per_host_pair(mapping, ""), None);
        assert_eq!(per_host_pair("", "api.example"), None);
    }

    /// `NettySslContextFactory.forwardProxyPrivateKey` / `forwardProxyCertificateChain` read the pair through
    /// `FileReader.readFileFromClassPathOrPath` (NettySslContextFactory.java:333,347): a class path resource, with no
    /// file of that name in the working directory.
    #[test]
    fn forward_proxy_client_pair_resolves_on_the_class_path() {
        let root = std::env::temp_dir().join(format!("mock-server-class-path-{}", uuid::Uuid::new_v4().simple()));
        let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/files/tls");
        std::fs::create_dir_all(root.join("cp-476")).unwrap();
        std::fs::copy(format!("{fixtures}/fwd-client-cert.pem"), root.join("cp-476/chain.pem")).unwrap();
        std::fs::copy(format!("{fixtures}/fwd-client-key.pem"), root.join("cp-476/key.pem")).unwrap();
        let config = crate::config::Config::for_tests()
            .with_property("forwardProxyCertificateChain", "cp-476/chain.pem")
            .with_property("forwardProxyPrivateKey", "cp-476/key.pem");
        let unusable_without = super::forward_identity_unusable(&config, "example.com");
        let previous = swagger_parser::java::classpath::classpath_roots();
        let mut roots = previous.clone();
        roots.push(root.display().to_string());
        swagger_parser::java::classpath::set_classpath_roots(roots);
        let unusable_with = super::forward_identity_unusable(&config, "example.com");
        let identity = super::forward_identity(&config, None, "example.com");
        swagger_parser::java::classpath::set_classpath_roots(previous);
        let _ = std::fs::remove_dir_all(&root);
        assert!(unusable_without, "no file of that name in the working directory");
        assert!(!unusable_with);
        assert_eq!(identity.map(|i| i.key.cert.len()), Some(1));
    }
}

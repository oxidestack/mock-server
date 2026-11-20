//! MQTT publishers and subscribers (`MqttMessagePublisher`, `Mqtt5MessagePublisher`, `MqttMessageSubscriber`,
//! `Mqtt5MessageSubscriber`) with `MqttSecurity`, over `rumqttc` where upstream uses Eclipse Paho.
//!
//! Paho's behaviour is kept where it shows: the broker URL is checked as Paho checks it (`tcp`, `ssl`, `ws`, `wss`),
//! a connect waits for the CONNACK (30 s), a publish waits until the broker has acknowledged it at its QoS, topic
//! names and filters are validated with Paho's messages, credentials go out only when not blank, and a lost
//! connection is not re-established (no automatic reconnect). MQTT 5 carries correlation headers as user
//! properties and records received user properties as headers.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::oneshot;

use super::broker::{BoxFuture, Counters, Error, ErrorKind, PublishOptions};
use super::store::{ConsumedMessage, ConsumedMessages, contains_wildcard};

/// `MqttConnectOptions.connectionTimeout`'s default.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// `MqttSecurity`: credentials and Paho SSL properties (`com.ibm.ssl.*`).
#[derive(Clone, Debug, Default)]
pub struct MqttSecurity {
    pub username: Option<String>,
    pub password: Option<String>,
    pub ssl_properties: Vec<(String, String)>,
}

impl MqttSecurity {
    pub fn is_empty(&self) -> bool {
        let blank = |s: &Option<String>| s.as_deref().is_none_or(|s| s.trim().is_empty());
        blank(&self.username) && blank(&self.password) && self.ssl_properties.is_empty()
    }

    fn ssl(&self, key: &str) -> Option<&str> {
        self.ssl_properties.iter().find(|(k, _)| k == &format!("com.ibm.ssl.{key}")).map(|(_, v)| v.as_str())
    }
}

/// What `MqttSecurityOptions.buildConnectOptions` (and `Mqtt5SecurityOptions`'s) sets on Paho's connect options:
/// the username and password when not blank, the SSL properties when there are any. The MQTT 5 client sends the
/// password as its UTF-8 bytes.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ConnectOptions {
    pub username: Option<String>,
    pub password: Option<String>,
    pub ssl_properties: Vec<(String, String)>,
}

/// `buildConnectOptions`: nothing (Paho's defaults) for no security or an empty one.
pub fn connect_options(security: Option<&MqttSecurity>) -> Option<ConnectOptions> {
    let security = security.filter(|s| !s.is_empty())?;
    let present = |v: &Option<String>| v.clone().filter(|v| !v.trim().is_empty());
    Some(ConnectOptions { username: present(&security.username), password: present(&security.password), ssl_properties: security.ssl_properties.clone() })
}

/// `SSLSocketFactoryFactory`'s property keys.
const SSL_KEYS: &[&str] = &[
    "protocol",
    "contextProvider",
    "keyStore",
    "keyStorePassword",
    "keyStoreType",
    "keyStoreProvider",
    "keyManager",
    "trustStore",
    "trustStorePassword",
    "trustStoreType",
    "trustStoreProvider",
    "trustManager",
    "enabledCipherSuites",
    "clientAuthentication",
];

/// The MQTT protocol version (`mqttProtocolVersion`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    V3,
    V5,
}

impl Version {
    fn broker(self) -> &'static str {
        match self {
            Version::V3 => "MQTT broker",
            Version::V5 => "MQTT 5 broker",
        }
    }

    fn topic(self) -> &'static str {
        match self {
            Version::V3 => "MQTT topic",
            Version::V5 => "MQTT 5 topic",
        }
    }
}

enum Scheme {
    Tcp,
    Ssl,
    Ws,
    Wss,
}

struct BrokerAddress {
    scheme: Scheme,
    host: String,
    port: u16,
    path: String,
}

/// `NetworkModuleService.validateURI` and the URI parts Paho connects with.
fn broker_address(url: &str) -> Result<BrokerAddress, Error> {
    let Some((scheme, rest)) = url.split_once(':').filter(|(s, _)| {
        s.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    }) else {
        if url.chars().any(|c| c.is_whitespace() || c == '"' || c == '<' || c == '>') {
            return Err(Error::illegal(format!("Can't parse string to URI \"{url}\"")));
        }
        return Err(Error::new(format!("missing scheme in broker URI: {url}")));
    };
    let scheme_kind = match scheme.to_ascii_lowercase().as_str() {
        "tcp" => Scheme::Tcp,
        "ssl" => Scheme::Ssl,
        "ws" => Scheme::Ws,
        "wss" => Scheme::Wss,
        _ => return Err(Error::illegal(format!("no NetworkModule installed for scheme \"{scheme}\" of URI \"{url}\""))),
    };
    let Some(hierarchical) = rest.strip_prefix("//") else {
        return match scheme_kind {
            Scheme::Tcp | Scheme::Ssl if !rest.is_empty() => Err(Error::illegal(format!("URI path must be empty \"{url}\""))),
            _ => Err(Error::illegal(format!("Can't parse string to URI \"{url}\""))),
        };
    };
    let (authority, path) = match hierarchical.find(['/', '?', '#']) {
        Some(i) => (&hierarchical[..i], &hierarchical[i..]),
        None => (hierarchical, ""),
    };
    if authority.is_empty() {
        return Err(Error::illegal(format!("Can't parse string to URI \"{url}\"")));
    }
    if matches!(scheme_kind, Scheme::Tcp | Scheme::Ssl) && !path.is_empty() {
        return Err(Error::illegal(format!("URI path must be empty \"{url}\"")));
    }
    // `applyRFC3986AuthorityPatch`: `((.+)@)?([^:]*)(:(\d+))?`.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, port) = match host_port.strip_prefix('[').and_then(|h| h.split_once(']')) {
        Some((v6, rest)) => (v6.to_string(), rest.strip_prefix(':')),
        None => match host_port.split_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (host_port.to_string(), None),
        },
    };
    let default_port = match scheme_kind {
        Scheme::Tcp => 1883,
        Scheme::Ssl => 8883,
        Scheme::Ws => 80,
        Scheme::Wss => 443,
    };
    let port = match port {
        Some(p) if !p
            .is_empty() => p
            .parse::<u32>()
            .ok()
            .filter(|p| *p <= 65535)
            .map(|p| p as u16)
            .ok_or_else(|| Error::illegal(format!("Can't parse string to URI \"{url}\"")))?,
        _ => default_port,
    };
    Ok(BrokerAddress { scheme: scheme_kind, host, port, path: if path.is_empty() { "/mqtt".into() } else { path.to_string() } })
}

/// `MqttTopic.validate(topic, wildcardAllowed)`.
pub fn validate_topic(topic: &str, wildcard_allowed: bool) -> Result<(), Error> {
    if topic.is_empty() || topic.len() > 65535 {
        return Err(Error::new("Invalid topic length, should be in range[1, 65535]!"));
    }
    if !wildcard_allowed {
        if topic.contains(['#', '+']) {
            return Err(Error::new("The topic name MUST NOT contain any wildcard characters (#+)"));
        }
        return Ok(());
    }
    if topic == "#" || topic == "+" {
        return Ok(());
    }
    if topic.matches('#').count() > 1 || (topic.contains('#') && !topic.ends_with("/#")) {
        return Err(Error::new(format!("Invalid usage of multi-level wildcard in topic string: {topic}")));
    }
    // `validateSubscribeFilter`: `+` only on its own between separators.
    let chars: Vec<char> = topic.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if *c == '+' {
            let before = i == 0 || chars[i - 1] == '/';
            let after = i + 1 == chars.len() || chars[i + 1] == '/';
            if !before || !after {
                return Err(Error::new(format!("Invalid usage of single-level wildcard in topic string '{topic}'!")));
            }
        }
    }
    Ok(())
}

/// `SSLSocketFactoryFactory.initialize`: every SSL property key must be one Paho knows.
fn check_ssl_keys(security: Option<&MqttSecurity>) -> Result<(), Error> {
    for (key, _) in security.map(|s| s.ssl_properties.as_slice()).unwrap_or_default() {
        if !key.strip_prefix("com.ibm.ssl.").is_some_and(|k| SSL_KEYS.contains(&k)) {
            return Err(Error::illegal(format!("{key} is not a valid IBM SSL property key.")));
        }
    }
    Ok(())
}

/// The provider of every JSSE service Paho looks up (`SSLContext`, `KeyManagerFactory`, `TrustManagerFactory`): in
/// the oracle image only SunJSSE has them.
const JSSE_PROVIDER: &str = "SunJSSE";

/// `KeyManagerFactory` algorithms and aliases in SunJSSE.
const KEY_MANAGERS: &[&str] = &["sunx509", "newsunx509", "pkix"];

/// `TrustManagerFactory` algorithms and aliases in SunJSSE.
const TRUST_MANAGERS: &[&str] = &["pkix", "sunx509", "sunpkix", "x509", "x.509"];

/// `<Service>.getInstance(algorithm, provider)`'s provider checks, before the algorithm is looked up: an empty name
/// is an `IllegalArgumentException`, which Paho does not catch; a provider is named exactly (case-sensitively).
fn jca_provider(provider: Option<&str>, service: &str, algorithm: &str) -> Result<(), Error> {
    match provider {
        None | Some(JSSE_PROVIDER) => Ok(()),
        Some("") => Err(Error::illegal("missing provider")),
        // A provider the image has without this service fails as `no such algorithm: <algorithm> for provider <p>`
        // instead: the same failure to the caller.
        Some(p) => Err(Error::new(format!("{service}: no such provider: {p} (for {algorithm})"))),
    }
}

/// `<Service>.getInstance(algorithm[, provider])` for a key or trust manager factory.
fn manager_factory(provider: Option<&str>, service: &str, algorithm: &str, known: &[&str]) -> Result<(), Error> {
    jca_provider(provider, service, algorithm)?;
    if known.contains(&algorithm.to_ascii_lowercase().as_str()) {
        Ok(())
    } else {
        Err(Error::new(format!("{algorithm} {service} not available")))
    }
}

/// A key store property group (`keyStore` or `trustStore` and their password, type, provider and manager algorithm)
/// loaded as `getSSLContext` does: the type, the file, then the manager factory.
async fn load_store(
    security: &MqttSecurity,
    path: &str,
    prefix: &str,
    manager: &str,
    service: &str,
    known: &[&str],
) -> Result<super::tls::KeyStore, Error> {
    let store_type = super::tls::StoreType::named(security.ssl(&format!("{prefix}Type")).unwrap_or("pkcs12"))?;
    let store = super::tls::load_typed_keystore(path, security.ssl(&format!("{prefix}Password")), store_type).await?;
    let algorithm = security.ssl(manager).unwrap_or(known[0]);
    manager_factory(security.ssl(&format!("{prefix}Provider")), service, algorithm, known)?;
    Ok(store)
}

/// `SSLSocketFactoryFactory.getSSLContext`: the `SSLContext` (protocol, `contextProvider`), the key store, then the
/// trust store, each with its type (`KeyStore.getInstance`), provider and manager algorithm, failing in that order
/// as the oracle image's JCA does; the JDK default trust without a trust store. Properties of a store that is not
/// named are not read, and `clientAuthentication` is read only for server sockets, so a client ignores it. MQTT
/// 3.1.1's Paho URL-decodes the trust store path (keeping it as it is when that fails); MQTT 5's does not.
async fn tls_config(security: Option<&MqttSecurity>, version: Version) -> Result<Arc<rustls::ClientConfig>, Error> {
    use super::tls::ClientTls;
    let Some(security) = security else { return ClientTls::default().config() };
    let protocol = security.ssl("protocol").unwrap_or("TLS");
    jca_provider(security.ssl("contextProvider"), "SSLContext", protocol)?;
    super::tls::ssl_context_protocol(protocol)?;
    let mut tls = ClientTls::default();
    if let Some(path) = security.ssl("keyStore") {
        let store = load_store(security, path, "keyStore", "keyManager", "KeyManagerFactory", KEY_MANAGERS).await?;
        // `SunX509`'s `init` recovers every key with the store password; `NewSunX509` (`PKIX`) only when it chooses
        // one, except from a JCEKS store loaded without a password.
        let sun_x509 = security.ssl("keyManager").is_none_or(|m| m.eq_ignore_ascii_case("sunx509"));
        let no_password = security.ssl("keyStorePassword").is_none();
        if store.unrecoverable_keys > 0 {
            match (sun_x509, store.jceks && no_password) {
                (true, true) => return Err(Error::illegal("password can't be null")),
                // `PKCS12KeyStore.engineGetKey` on a key left encrypted by a password-less load: the `Get Key failed`
                // wrapper of a NullPointerException.
                (true, false) if store.pkcs12 && no_password => {
                    let npe = "Cannot read the array length because \"<parameter2>\" is null";
                    return Err(Error::caused(format!("Get Key failed: {npe}"), Error::new(npe)));
                }
                (true, false) => return Err(Error::new("Cannot recover key")),
                (false, true) => return Err(Error::new("Get Key failed: password can't be null")),
                (false, false) => {}
            }
        }
        // `SSLContext.init` with the factory's key manager, which chooses a key in each handshake.
        let kind = super::tls::KeyManagerKind::named(security.ssl("keyManager").unwrap_or("SunX509"));
        tls.key_manager = Some(super::tls::KeyManager { kind, entries: store.entries });
    }
    if let Some(path) = security.ssl("trustStore") {
        let path = match version {
            Version::V3 => crate::java_text::url_decode(path, crate::java_text::UrlCharset::Utf8).unwrap_or_else(|_| path.to_string()),
            Version::V5 => path.to_string(),
        };
        tls.trust = Some(load_store(security, &path, "trustStore", "trustManager", "TrustManagerFactory", TRUST_MANAGERS).await?.certificates);
    }
    super::tls::unusable_ssl_context(protocol)?;
    tls.protocol = Some(protocol.to_string());
    tls.cipher_suites = security.ssl("enabledCipherSuites").map(|s| s.split(',').map(str::to_string).collect());
    tls.config()
}

/// A connect failure's cause, classified.
fn connect_cause(e: &str, tls: bool) -> Error {
    let lower = e.to_ascii_lowercase();
    let kind = if lower.contains("badusernamepassword") || lower.contains("notauthorized") {
        ErrorKind::Authentication
    } else if tls && (lower.contains("certificate") || lower.contains("tls") || lower.contains("handshake")) {
        ErrorKind::Tls
    } else {
        ErrorKind::Other
    };
    Error::of_kind(kind, e.to_string())
}

/// What the event loop reports, the same for both protocol versions.
enum Event {
    ConnAck(Result<(), String>),
    Publish { topic: String, payload: Bytes, properties: Vec<(String, String)> },
    OutgoingPublish(u16),
    PubAck(u16),
    PubComp(u16),
    SubAck(Vec<bool>),
    Disconnected(String),
    /// The connection failed: rumqttc's text, and the socket error itself when that is what failed.
    Failed(Failure),
    Other,
}

enum Client {
    V3(rumqttc::AsyncClient),
    V5(rumqttc::v5::AsyncClient),
}

enum Loop {
    V3(Box<rumqttc::EventLoop>),
    V5(Box<rumqttc::v5::EventLoop>),
}

impl Loop {
    async fn poll(&mut self) -> Event {
        match self {
            Loop::V3(l) => {
                use rumqttc::{Event as E, Incoming, Outgoing};
                match l.poll().await {
                    Ok(E::Incoming(Incoming::ConnAck(ack))) => Event::ConnAck(match ack.code {
                        rumqttc::ConnectReturnCode::Success => Ok(()),
                        code => Err(format!("{code:?}")),
                    }),
                    Ok(E::Incoming(Incoming::Publish(p))) => Event::Publish { topic: p.topic, payload: p.payload, properties: Vec::new() },
                    Ok(E::Incoming(Incoming::PubAck(a))) => Event::PubAck(a.pkid),
                    Ok(E::Incoming(Incoming::PubComp(a))) => Event::PubComp(a.pkid),
                    Ok(E::Incoming(Incoming::SubAck(a))) => {
                        Event::SubAck(a.return_codes.iter().map(|c| matches!(c, rumqttc::SubscribeReasonCode::Success(_))).collect())
                    }
                    Ok(E::Incoming(Incoming::Disconnect)) => Event::Disconnected("disconnected".into()),
                    Ok(E::Outgoing(Outgoing::Publish(pkid))) => Event::OutgoingPublish(pkid),
                    Ok(_) => Event::Other,
                    Err(e) => Event::Failed(Failure {
                        io: if let rumqttc::ConnectionError::Io(io) = &e { Some((io.kind(), io.to_string())) } else { None },
                        message: connection_error(&e.to_string(), matches!(e, rumqttc::ConnectionError::ConnectionRefused(_))),
                    }),
                }
            }
            Loop::V5(l) => {
                use rumqttc::v5::mqttbytes::v5::{ConnectReturnCode, Packet, SubscribeReasonCode};
                use rumqttc::Outgoing;
                use rumqttc::v5::Event as E;
                match l.poll().await {
                    Ok(E::Incoming(Packet::ConnAck(ack))) => Event::ConnAck(match ack.code {
                        ConnectReturnCode::Success => Ok(()),
                        code => Err(format!("{code:?}")),
                    }),
                    Ok(E::Incoming(Packet::Publish(p))) => Event::Publish {
                        topic: String::from_utf8_lossy(&p.topic).into_owned(),
                        payload: p.payload,
                        properties: p.properties.map(|p| p.user_properties).unwrap_or_default(),
                    },
                    Ok(E::Incoming(Packet::PubAck(a))) => Event::PubAck(a.pkid),
                    Ok(E::Incoming(Packet::PubComp(a))) => Event::PubComp(a.pkid),
                    Ok(E::Incoming(Packet::SubAck(a))) => Event::SubAck(a.return_codes.iter().map(|c| matches!(c, SubscribeReasonCode::Success(_))).collect()),
                    Ok(E::Incoming(Packet::Disconnect(d))) => Event::Disconnected(format!("{:?}", d.reason_code)),
                    Ok(E::Outgoing(Outgoing::Publish(pkid))) => Event::OutgoingPublish(pkid),
                    Ok(_) => Event::Other,
                    Err(e) => Event::Failed(Failure {
                        io: if let rumqttc::v5::ConnectionError::Io(io) = &e { Some((io.kind(), io.to_string())) } else { None },
                        message: connection_error(&e.to_string(), matches!(e, rumqttc::v5::ConnectionError::ConnectionRefused(_))),
                    }),
                }
            }
        }
    }
}

/// Why a connect attempt failed: rumqttc's text, and the socket error (its kind and text) when the dial failed.
struct Failure {
    message: String,
    io: Option<(std::io::ErrorKind, String)>,
}

impl Failure {
    fn text(message: impl Into<String>) -> Failure {
        Failure { message: message.into(), io: None }
    }
}

/// Paho's `MqttException(reasonCode, cause)`: the message is its catalog's text for the code (`MqttException` for
/// 0, `REASON_CODE_CLIENT_EXCEPTION`), and the bean carries `reasonCode`.
fn mqtt_exception(reason: i64, cause: Option<Error>) -> Error {
    let message = match reason {
        32000 => "Timed out waiting for a response from the server",
        32103 => "Unable to connect to server",
        32109 => "Connection lost",
        50002 => "Malformed Packet",
        _ => "MqttException",
    };
    let error = match cause {
        Some(cause) => Error { kind: cause.kind, ..Error::caused(message, cause) },
        None => Error::new(message),
    };
    error.with_field("reasonCode", reason)
}

/// What `MqttClient.connect` throws for a failed attempt, under the publisher's `Failed to connect to …`:
/// `TCPNetworkModule.start` turns a `ConnectException` into `MqttException(32103)`; any other socket error (an
/// `UnknownHostException`, a connect timeout) reaches `ExceptionHelper.createMqttException` as
/// `MqttException(0, cause)`; no CONNACK in time is `MqttException(32000)`. Other failures (CONNACK refusals, TLS)
/// keep rumqttc's classified text (only the socket failures were checked against the oracle).
fn connect_exception(failure: Failure, tls: bool, host: &str, version: Version) -> Error {
    if tls && failure.io.is_none() && is_required_certificate_alert(&failure.message) {
        // the server's fatal certificate_required alert (a client that picked no key under mutual TLS) is read by the
        // JDK client as an `SSLHandshakeException` under `MqttException("Connection lost")`; reason code 32109 for
        // both protocol versions (read off the oracle)
        let alert = Error::of_kind(ErrorKind::Tls, "(certificate_required) Received fatal alert: certificate_required");
        return mqtt_exception(32109, Some(alert));
    }
    if failure.io.is_none() && (is_not_a_connack(&failure.message) || (version == Version::V5 && is_undecodable_packet(&failure.message))) {
        // a peer that answers the CONNECT with bytes that are no CONNACK (the unknown-format text of a data plane with
        // no binary expectation, which then closes the connection): Paho's MQTT 3 client reads the stream to its end,
        // `MqttException("Connection lost")` over an `EOFException` without a message; its MQTT 5 client rejects the
        // text's first bytes as a packet, `MqttException("Malformed Packet")`, 50002 (read off the oracle)
        return match version {
            Version::V3 => mqtt_exception(32109, Some(Error::without_message())),
            Version::V5 => mqtt_exception(50002, None),
        };
    }
    match failure.io {
        Some((std::io::ErrorKind::ConnectionRefused, _)) => mqtt_exception(32103, Some(Error::new("Connection refused"))),
        Some((kind, text)) => mqtt_exception(0, Some(connect_cause(&super::broker::io_message(&std::io::Error::new(kind, text), host), tls))),
        None if failure.message == CONNACK_TIMEOUT => mqtt_exception(32000, None),
        None => {
            if let Some((reason, text)) = connack_refusal(&failure.message, version) {
                // a CONNACK that refuses the connection: the client throws an `MqttException`/`MqttSecurityException`
                // whose message is its catalog's text for the return or reason code, with no cause (read off the
                // oracle)
                let kind = if matches!((version, reason), (Version::V3, 4 | 5) | (Version::V5, 134 | 135)) { ErrorKind::Authentication } else { ErrorKind::Other };
                return Error { kind, ..Error::new(text) }.with_field("reasonCode", reason);
            }
            let cause = connect_cause(&failure.message, tls);
            if tls && cause.kind == ErrorKind::Tls {
                // the JSSE handshake failure reaches `connect` as `MqttException(0, SSLHandshakeException)`; MQTT 5's
                // client leaves it untranslated (read off the oracle)
                let cause = Error { message: jsse_message(&cause.message), ..cause };
                let mut wrapped = mqtt_exception(0, Some(cause));
                if version == Version::V5 {
                    wrapped.message = "Untranslated MqttException - RC: 0".to_string();
                }
                return wrapped;
            }
            cause
        }
    }
}

/// JSSE's text for a fatal alert the peer sent (`(handshake_failure) Received fatal alert: handshake_failure`), from
/// rustls's (`TLS: I/O: received fatal alert: HandshakeFailure`); any other text as it is.
fn jsse_message(message: &str) -> String {
    let Some((_, alert)) = message.split_once("received fatal alert: ") else { return message.to_string() };
    let mut name = String::new();
    for (i, c) in alert.trim().chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            name.push('_');
        }
        name.push(c.to_ascii_lowercase());
    }
    format!("({name}) Received fatal alert: {name}")
}

/// Paho's reason code and catalog text for a CONNACK refusal, from rumqttc's name of the return code.
fn connack_refusal(message: &str, version: Version) -> Option<(i64, &'static str)> {
    Some(match (version, message) {
        (Version::V3, "RefusedProtocolVersion") => (1, "Invalid protocol version"),
        (Version::V3, "BadClientId") => (2, "Invalid client ID"),
        (Version::V3, "ServiceUnavailable") => (3, "Broker unavailable"),
        (Version::V3, "BadUserNamePassword") => (4, "Bad user name or password"),
        (Version::V3, "NotAuthorized") => (5, "Not authorized to connect"),
        (Version::V5, "UnspecifiedError") => (128, "Unspecified error."),
        (Version::V5, "MalformedPacket") => (129, "Malformed packet."),
        (Version::V5, "ProtocolError") => (130, "Protocol error."),
        (Version::V5, "ImplementationSpecificError") => (131, "Implementation specific error."),
        (Version::V5, "UnsupportedProtocolVersion") => (132, "Unsupported protocol version."),
        (Version::V5, "ClientIdentifierNotValid") => (133, "Client identifier not valid."),
        (Version::V5, "BadUserNamePassword") => (134, "Bad User Name or Password."),
        (Version::V5, "NotAuthorized") => (135, "Not authorized."),
        (Version::V5, "ServerUnavailable") => (136, "Server unavailable."),
        (Version::V5, "ServerBusy") => (137, "Server busy."),
        (Version::V5, "Banned") => (138, "Banned."),
        (Version::V5, "BadAuthenticationMethod") => (140, "Bad authentication method."),
        (Version::V5, "TopicNameInvalid") => (144, "Topic Name invalid."),
        (Version::V5, "PacketTooLarge") => (149, "Packet too large."),
        (Version::V5, "QuotaExceeded") => (151, "Quota exceeded."),
        // the client's catalog has no text for these two reason codes
        (Version::V5, "PayloadFormatInvalid" | "QoSNotSupported") => (50001, "Invalid Return code"),
        (Version::V5, "RetainNotSupported") => (154, "Retain not supported."),
        (Version::V5, "UseAnotherServer") => (156, "Use another server."),
        (Version::V5, "ServerMoved") => (157, "Server moved."),
        (Version::V5, "ConnectionRateExceeded") => (159, "Connection rate exceeded."),
        _ => return None,
    })
}

/// How rumqttc reports a first packet that is no CONNACK.
fn is_not_a_connack(message: &str) -> bool {
    message.starts_with("Expected ConnAck packet")
}

/// How rumqttc reports bytes it cannot decode as a packet.
fn is_undecodable_packet(message: &str) -> bool {
    message.starts_with("Mqtt state: Mqtt serialization/deserialization error")
}

/// How rumqttc reports the alert: MQTT 5 names it, MQTT 3 sees the stream end (a TLS 1.3 alert read before any CONNACK).
fn is_required_certificate_alert(message: &str) -> bool {
    message == "Mqtt state: Connection closed by peer abruptly" || message.ends_with("received fatal alert: CertificateRequired")
}

const CONNACK_TIMEOUT: &str = "Timed out waiting for a response from the server";

fn connection_error(e: &str, refused: bool) -> String {
    if refused { e.replace("Connection refused, return code: ", "").replace('`', "") } else { e.to_string() }
}

/// A publish waiting for the broker: sent (QoS 0), acknowledged (QoS 1) or completed (QoS 2).
struct Pending {
    qos: u8,
    pkid: Option<u16>,
    done: oneshot::Sender<Result<(), Error>>,
}

/// Where the subscription's acknowledgements (one granted flag per topic) are awaited.
type SubscribeAcks = oneshot::Sender<Result<Vec<bool>, Error>>;

#[derive(Default)]
struct Shared {
    connected: AtomicBool,
    pending: Mutex<Option<Pending>>,
    subscribing: Mutex<Option<SubscribeAcks>>,
}

/// One Paho `MqttClient`: a connected client and the task driving its connection.
struct Connection {
    client: Client,
    version: Version,
    shared: Arc<Shared>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Serialises publishes, as Paho's blocking `publish` does for one caller.
    publishing: tokio::sync::Mutex<()>,
}

type OnMessage = Arc<dyn Fn(String, Bytes, Vec<(String, String)>) + Send + Sync>;

impl Connection {
    /// `new MqttClient(url, clientId)` then `connect(options)`: fails with `Failed to connect to <broker>: <url>`.
    async fn open(
        url: &str,
        client_id: &str,
        version: Version,
        security: Option<&MqttSecurity>,
        on_message: Option<OnMessage>,
        failure: String,
    ) -> Result<Connection, Error> {
        let address = broker_address(url)?;
        let security = security.filter(|s| !s.is_empty());
        let tls = match address.scheme {
            Scheme::Ssl | Scheme::Wss => {
                check_ssl_keys(security)?;
                // An `IllegalArgumentException` ("missing provider") escapes `connect` as it is.
                Some(tls_config(security, version).await.map_err(|e| {
                    if e.kind == ErrorKind::IllegalArgument {
                        return e;
                    }
                    // the key or trust store failing to load or init reaches `connect` as `MqttException(0, cause)` (MQTT 5's
                    // is untranslated; read off the oracle)
                    let mut wrapped = mqtt_exception(0, Some(e));
                    if version == Version::V5 {
                        wrapped.message = "Untranslated MqttException - RC: 0".to_string();
                    }
                    Error::caused(failure.clone(), wrapped)
                })?)
            }
            _ => None,
        };
        let transport = match (&address.scheme, tls.clone()) {
            (Scheme::Ssl, Some(config)) => rumqttc::Transport::tls_with_config(rumqttc::TlsConfiguration::Rustls(config)),
            (Scheme::Wss, Some(config)) => rumqttc::Transport::wss_with_config(rumqttc::TlsConfiguration::Rustls(config)),
            (Scheme::Ws, _) => rumqttc::Transport::ws(),
            _ => rumqttc::Transport::tcp(),
        };
        let broker = match address.scheme {
            Scheme::Ws => format!("ws://{}:{}{}", address.host, address.port, address.path),
            Scheme::Wss => format!("wss://{}:{}{}", address.host, address.port, address.path),
            _ => address.host.clone(),
        };
        // A missing username or password goes out as an empty one, which the client leaves out of the CONNECT.
        let credentials = connect_options(security)
            .filter(|o| o.username.is_some() || o.password.is_some())
            .map(|o| (o.username.unwrap_or_default(), o.password.unwrap_or_default()));
        let secure = matches!(address.scheme, Scheme::Ssl | Scheme::Wss);
        let failed = |cause: Failure| Error::caused(failure.clone(), connect_exception(cause, secure, &address.host, version));
        // Paho's socket factory resolves the host through `InetAddress` first, so a failed lookup feeds (or is
        // answered by) the JVM-wide negative cache before any connect: an `UnknownHostException` under
        // `MqttException(0)`.
        if let Err(e) = crate::inet_address::lookup(&address.host, address.port).await {
            let unknown = Error::new(super::broker::io_message(&e, &address.host));
            return Err(Error::caused(failure.clone(), mqtt_exception(0, Some(unknown))));
        }
        let (client, event_loop) = match attempt(client_id, version, &broker, address.port, transport, credentials.clone()).await {
            Ok(connected) => connected,
            Err(cause) if version == Version::V3 => {
                // `MQTT_VERSION_DEFAULT`: once more as MQTT 3.1, its error the one reported.
                let Some(port) = mqtt31_relay(&address, &broker, tls).await else { return Err(failed(cause)) };
                attempt(client_id, version, "127.0.0.1", port, rumqttc::Transport::tcp(), credentials).await.map_err(failed)?
            }
            Err(cause) => return Err(failed(cause)),
        };
        let shared = Arc::new(Shared { connected: AtomicBool::new(true), ..Shared::default() });
        let task = super::broker::spawn(drive(event_loop, shared.clone(), on_message));
        Ok(Connection { client, version, shared, task: Mutex::new(Some(task)), publishing: tokio::sync::Mutex::new(()) })
    }

    fn connected(&self) -> bool {
        self.shared.connected.load(Ordering::SeqCst)
    }

    async fn publish(&self, topic: &str, payload: &[u8], qos: u8, retain: bool, headers: &[(String, String)]) -> Result<(), Error> {
        validate_topic(topic, false)?;
        let failed = |cause: String| Error::caused(format!("Failed to publish to {}: {topic}", self.version.topic()), Error::new(cause));
        let _guard = self.publishing.lock().await;
        if !self.connected() {
            return Err(failed("Client is not connected".into()));
        }
        let (tx, rx) = oneshot::channel();
        *self.shared.pending.lock() = Some(Pending { qos, pkid: None, done: tx });
        let sent = match &self.client {
            Client::V3(c) => c.publish(topic, qos_of(qos), retain, payload.to_vec()).await.map_err(|e| e.to_string()),
            Client::V5(c) => {
                let result = if headers.is_empty() {
                    c.publish(topic, qos5_of(qos), retain, payload.to_vec()).await
                } else {
                    let properties = rumqttc::v5::mqttbytes::v5::PublishProperties { user_properties: headers.to_vec(), ..Default::default() };
                    c.publish_with_properties(topic, qos5_of(qos), retain, payload.to_vec(), properties).await
                };
                result.map_err(|e| e.to_string())
            }
        };
        if let Err(e) = sent {
            self.shared.pending.lock().take();
            return Err(failed(e));
        }
        match rx.await {
            Ok(result) => result.map_err(|e| failed(e.message)),
            Err(_) => Err(failed("Connection lost".into())),
        }
    }

    async fn subscribe(&self, filter: &str, qos: u8) -> Result<(), Error> {
        validate_topic(filter, true)?;
        let failed = |cause: String| Error::caused(format!("Failed to subscribe to {}: {filter}", self.version.topic()), Error::new(cause));
        if !self.connected() {
            return Err(failed("Client is not connected".into()));
        }
        let (tx, rx) = oneshot::channel();
        *self.shared.subscribing.lock() = Some(tx);
        let sent = match &self.client {
            Client::V3(c) => c.subscribe(filter, qos_of(qos)).await.map_err(|e| e.to_string()),
            Client::V5(c) => c.subscribe(filter, qos5_of(qos)).await.map_err(|e| e.to_string()),
        };
        if let Err(e) = sent {
            return Err(failed(e));
        }
        match rx.await {
            Ok(Ok(codes)) if codes.iter().all(|ok| *ok) => Ok(()),
            Ok(Ok(_)) => Err(failed("Error from subscribe".into())),
            Ok(Err(e)) => Err(failed(e.message)),
            Err(_) => Err(failed("Connection lost".into())),
        }
    }

    /// `disconnect()` when connected, then `close()`.
    async fn close(&self) {
        if self.connected() {
            let _ = match &self.client {
                Client::V3(c) => c.disconnect().await.map_err(|_| ()),
                Client::V5(c) => c.disconnect().await.map_err(|_| ()),
            };
        }
        let task = self.task.lock().take();
        super::broker::join_or_abort(task, Duration::from_secs(5)).await;
        self.shared.connected.store(false, Ordering::SeqCst);
    }
}

/// One `connect`: the client and its event loop once the broker accepted the CONNECT (30 s at most), else the cause.
async fn attempt(
    client_id: &str,
    version: Version,
    broker: &str,
    port: u16,
    transport: rumqttc::Transport,
    credentials: Option<(String, String)>,
) -> Result<(Client, Loop), Failure> {
    let (client, mut event_loop) = match version {
        Version::V3 => {
            let mut options = rumqttc::MqttOptions::new(client_id, broker, port);
            options.set_keep_alive(Duration::from_secs(60)).set_clean_session(true).set_transport(transport).set_max_packet_size(268_435_455, 268_435_455);
            if let Some((user, password)) = credentials {
                options.set_credentials(user, password);
            }
            let (client, mut event_loop) = rumqttc::AsyncClient::new(options, 64);
            event_loop.network_options.set_connection_timeout(CONNECT_TIMEOUT.as_secs());
            (Client::V3(client), Loop::V3(Box::new(event_loop)))
        }
        Version::V5 => {
            let mut options = rumqttc::v5::MqttOptions::new(client_id, broker, port);
            options.set_keep_alive(Duration::from_secs(60)).set_clean_start(true).set_transport(transport);
            if let Some((user, password)) = credentials {
                options.set_credentials(user, password);
            }
            options.set_connection_timeout(CONNECT_TIMEOUT.as_secs());
            let (client, event_loop) = rumqttc::v5::AsyncClient::new(options, 64);
            (Client::V5(client), Loop::V5(Box::new(event_loop)))
        }
    };
    let connected = tokio::time::timeout(CONNECT_TIMEOUT, async {
        loop {
            match event_loop.poll().await {
                Event::ConnAck(result) => return result.map_err(Failure::text),
                Event::Disconnected(e) => return Err(Failure::text(e)),
                Event::Failed(e) => return Err(e),
                _ => {}
            }
        }
    })
    .await;
    match connected {
        Ok(Ok(())) => Ok((client, event_loop)),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Failure::text(CONNACK_TIMEOUT)),
    }
}

/// The broker dialed again as the failed attempt dialed it, behind a relay that speaks MQTT 3.1 to it (`mqtt31`);
/// None when the broker cannot be reached that way either (the first attempt's failure stands, as the retry's
/// would be the same).
async fn mqtt31_relay(address: &BrokerAddress, broker_url: &str, tls: Option<Arc<rustls::ClientConfig>>) -> Option<u16> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, super::tls::dial(&address.host, address.port, CONNECT_TIMEOUT, tls, super::tls::Sni::Always)).await.ok()?.ok()?;
    let upstream = match address.scheme {
        Scheme::Ws | Scheme::Wss => tokio::time::timeout(CONNECT_TIMEOUT, super::mqtt31::websocket(stream, &broker_url.replacen("wss://", "ws://", 1))).await.ok()?.ok()?,
        Scheme::Tcp | Scheme::Ssl => super::mqtt31::Upstream::Raw(stream),
    };
    super::mqtt31::relay(upstream, CONNECT_TIMEOUT).await.ok()
}

fn qos_of(qos: u8) -> rumqttc::QoS {
    match qos {
        0 => rumqttc::QoS::AtMostOnce,
        2 => rumqttc::QoS::ExactlyOnce,
        _ => rumqttc::QoS::AtLeastOnce,
    }
}

fn qos5_of(qos: u8) -> rumqttc::v5::mqttbytes::QoS {
    match qos {
        0 => rumqttc::v5::mqttbytes::QoS::AtMostOnce,
        2 => rumqttc::v5::mqttbytes::QoS::ExactlyOnce,
        _ => rumqttc::v5::mqttbytes::QoS::AtLeastOnce,
    }
}

/// The connection's task: delivers messages, completes waiting publishes and subscriptions, and stops at the first
/// connection error (Paho's `connectionLost`; no automatic reconnect).
async fn drive(mut event_loop: Loop, shared: Arc<Shared>, on_message: Option<OnMessage>) {
    loop {
        match event_loop.poll().await {
            Event::Publish { topic, payload, properties } => {
                if let Some(f) = &on_message {
                    f(topic, payload, properties);
                }
            }
            Event::OutgoingPublish(pkid) => {
                let mut pending = shared.pending.lock();
                if pending.as_ref().is_some_and(|p| p.pkid.is_none()) {
                    if pending.as_ref().is_some_and(|p| p.qos == 0) {
                        if let Some(p) = pending.take() {
                            let _ = p.done.send(Ok(()));
                        }
                    } else if let Some(p) = pending.as_mut() {
                        p.pkid = Some(pkid);
                    }
                }
            }
            Event::PubAck(pkid) | Event::PubComp(pkid) => {
                let mut pending = shared.pending.lock();
                if pending.as_ref().is_some_and(|p| p.pkid == Some(pkid)) && let Some(p) = pending.take() {
                    let _ = p.done.send(Ok(()));
                }
            }
            Event::SubAck(codes) => {
                if let Some(tx) = shared.subscribing.lock().take() {
                    let _ = tx.send(Ok(codes));
                }
            }
            Event::Disconnected(e) | Event::Failed(Failure { message: e, .. }) => {
                shared.connected.store(false, Ordering::SeqCst);
                if let Some(p) = shared.pending.lock().take() {
                    let _ = p.done.send(Err(Error::new(format!("Connection lost ({e})"))));
                }
                if let Some(tx) = shared.subscribing.lock().take() {
                    let _ = tx.send(Err(Error::new(format!("Connection lost ({e})"))));
                }
                return;
            }
            Event::ConnAck(_) | Event::Other => {}
        }
    }
}

/// `MqttMessagePublisher` / `Mqtt5MessagePublisher`.
pub struct MqttPublisher {
    connection: Connection,
    qos: u8,
}

impl MqttPublisher {
    /// `new MqttMessagePublisher(brokerUrl, clientId, qos, security)` (or the MQTT 5 one).
    pub async fn connect(url: &str, client_id: &str, qos: u8, security: Option<&MqttSecurity>, version: Version) -> Result<Self, Error> {
        if qos > 2 {
            return Err(Error::illegal(format!("MQTT QoS must be 0, 1, or 2; got: {qos}")));
        }
        let failure = format!("Failed to connect to {}: {url}", version.broker());
        Ok(MqttPublisher { connection: Connection::open(url, client_id, version, security, None, failure).await?, qos })
    }

    /// `getQos`.
    pub fn qos(&self) -> u8 {
        self.qos
    }

    /// `isConnected` of the client: false once the connection is lost or closed.
    pub fn is_connected(&self) -> bool {
        self.connection.connected()
    }

    /// `publishBytes(channel, payload, options)`.
    pub async fn publish_bytes(&self, channel: &str, payload: &[u8], options: &PublishOptions) -> Result<(), Error> {
        let message = outgoing_message(payload, self.qos, options, self.connection.version);
        self.connection.publish(channel, &message.payload, message.qos, message.retained, &message.user_properties).await
    }
}

/// `MqttMessage` as a publisher hands it to the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutgoingMessage {
    pub payload: Vec<u8>,
    pub qos: u8,
    pub retained: bool,
    /// MQTT 5 user properties.
    pub user_properties: Vec<(String, String)>,
}

/// The message `publishBytes` sends: the options' QoS and retain flag override the publisher's QoS and "not
/// retained"; MQTT 5 carries the options' headers as user properties, MQTT 3 has nowhere to put them and drops them
/// (the Kafka key means nothing to MQTT).
pub fn outgoing_message(payload: &[u8], qos: u8, options: &PublishOptions, version: Version) -> OutgoingMessage {
    OutgoingMessage {
        payload: payload.to_vec(),
        qos: options.qos.unwrap_or(qos),
        retained: options.retain.unwrap_or(false),
        user_properties: if version == Version::V5 { options.headers.clone() } else { Vec::new() },
    }
}

impl super::broker::Publisher for MqttPublisher {
    fn publish<'a>(&'a self, channel: &'a str, payload: &'a str, options: &'a PublishOptions) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(self.publish_bytes(channel, payload.as_bytes(), options))
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(self.connection.close())
    }
}

/// `MqttMessageSubscriber` / `Mqtt5MessageSubscriber`: records every message under the concrete topic it arrived
/// on; retrieval by a wildcard filter matches those topics.
pub struct MqttSubscriber {
    connection: Connection,
    qos: u8,
    recorder: Arc<ConsumedMessages>,
    healthy: Arc<AtomicBool>,
}

impl MqttSubscriber {
    pub async fn connect(
        url: &str,
        client_id: &str,
        qos: u8,
        max_recorded: i64,
        security: Option<&MqttSecurity>,
        version: Version,
        counters: Counters,
    ) -> Result<Self, Error> {
        let recorder = Arc::new(ConsumedMessages::new(max_recorded));
        let sink = recorder.clone();
        let on_message: OnMessage = Arc::new(move |topic, payload, properties| {
            let payload = String::from_utf8_lossy(&payload).into_owned();
            let headers = properties.into_iter().map(|(k, v)| (k, Some(v))).collect();
            sink.record(ConsumedMessage::new(&topic, None, Some(payload), headers));
            counters.consumed(&topic);
        });
        let failure = format!("Failed to connect {} subscriber to broker: {url}", if version == Version::V5 { "MQTT 5" } else { "MQTT" });
        let connection = Connection::open(url, client_id, version, security, Some(on_message), failure).await?;
        Ok(MqttSubscriber { connection, qos, recorder, healthy: Arc::new(AtomicBool::new(true)) })
    }

    /// `isHealthy`: false once the connection is lost.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst) && self.connection.connected()
    }
}

impl super::broker::Subscriber for MqttSubscriber {
    /// `subscribe(channel)`: the store first, then the subscription at the subscriber's QoS.
    fn subscribe<'a>(&'a self, channel: &'a str) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            self.recorder.ensure(channel).map_err(Error::new)?;
            self.connection.subscribe(channel, self.qos).await
        })
    }

    fn recorded(&self, channel: &str) -> Vec<ConsumedMessage> {
        if contains_wildcard(channel) { self.recorder.matching(channel) } else { self.recorder.exact(channel) }
    }

    fn all_recorded(&self) -> Vec<ConsumedMessage> {
        self.recorder.all()
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.connection.close().await;
            self.recorder.clear();
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_urls_are_checked_as_paho_does() {
        let err = |u: &str| broker_address(u).err().unwrap().message;
        assert_eq!(err("localhost:1883"), "no NetworkModule installed for scheme \"localhost\" of URI \"localhost:1883\"");
        assert_eq!(err("foo://h"), "no NetworkModule installed for scheme \"foo\" of URI \"foo://h\"");
        assert_eq!(err("tcp:/h"), "URI path must be empty \"tcp:/h\"");
        assert_eq!(err("tcp://"), "Can't parse string to URI \"tcp://\"");
        assert_eq!(err("tcp://h/path"), "URI path must be empty \"tcp://h/path\"");
        let a = broker_address("tcp://h").unwrap();
        assert_eq!((a.host.as_str(), a.port), ("h", 1883));
        assert_eq!(broker_address("ssl://h").unwrap().port, 8883);
        assert!(broker_address("ws://h/x").is_ok());
    }

    #[test]
    fn topics_are_validated_as_paho_does() {
        let err = |t: &str, w: bool| validate_topic(t, w).err().unwrap().message;
        assert_eq!(err("a/+/b", false), "The topic name MUST NOT contain any wildcard characters (#+)");
        assert_eq!(err("", true), "Invalid topic length, should be in range[1, 65535]!");
        assert_eq!(err("a/#/b", true), "Invalid usage of multi-level wildcard in topic string: a/#/b");
        assert_eq!(err("a+/b", true), "Invalid usage of single-level wildcard in topic string 'a+/b'!");
        assert_eq!(err("a/b#", true), "Invalid usage of multi-level wildcard in topic string: a/b#");
        assert!(validate_topic("#", true).is_ok() && validate_topic("+", true).is_ok() && validate_topic("a/+", true).is_ok());
    }
}

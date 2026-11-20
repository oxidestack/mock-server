//! AMQP 0-9-1 publishers and subscribers (`AmqpMessagePublisher`, `AmqpMessageSubscriber`) over `lapin`, where
//! upstream uses RabbitMQ's Java client.
//!
//! The Java client's observable behaviour is kept: the URI is read as `ConnectionFactory.setUri` reads it (with
//! `java.net.URI`'s parsing and error texts), connecting times out after 5 s, `amqps` uses the JVM's default
//! `SSLContext` (`useSslProtocol()` in 5.x: the image's `cacerts`, the host name verified), a publish goes out `mandatory` on a confirm-mode channel and fails when the broker returns
//! it, and a channel-level error closes the channel for good: the failing call reports `null` (the Java client's
//! message-less `IOException`) and every later one `channel is already closed due to channel error; protocol
//! method: #method<channel.close>(…)`. A lost connection is recovered every 5 s, as the Java client's automatic
//! recovery does.

mod transport;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use lapin::options::{
    BasicConsumeOptions, BasicPublishOptions, ConfirmSelectOptions, ExchangeDeclareOptions, QueueBindOptions, QueueDeclareOptions,
};
use lapin::types::{AMQPValue, FieldTable, LongString, ShortString};
use lapin::{BasicProperties, Confirmation, ConnectionProperties, ExchangeKind};
use parking_lot::Mutex;

use super::broker::{BoxFuture, Counters, Error, PublishOptions};
use crate::java_text::{UrlCharset, split, url_decode};
use super::spec::{AmqpBinding, AmqpChannelType, Spec};
use super::store::{ConsumedMessage, ConsumedMessages};

const DEFAULT_EXCHANGE: &str = "";
const DEFAULT_EXCHANGE_TYPE: &str = "direct";
const CONNECTION_TIMEOUT: Duration = Duration::from_millis(5000);
const CONFIRM_TIMEOUT: Duration = Duration::from_millis(5000);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(10000);
const RECOVERY_INTERVAL: Duration = Duration::from_millis(5000);

/// `ConnectionFactory` after `setUri`: where and how to connect.
#[derive(Clone, Debug, PartialEq)]
pub struct Factory {
    pub host: String,
    pub port: i32,
    pub virtual_host: String,
    pub username: String,
    pub password: String,
    pub heartbeat: i32,
    pub channel_max: i32,
    pub ssl: bool,
}

impl Default for Factory {
    fn default() -> Self {
        Factory {
            host: "localhost".into(),
            port: -1,
            virtual_host: "/".into(),
            username: "guest".into(),
            password: "guest".into(),
            heartbeat: 60,
            channel_max: 2047,
            ssl: false,
        }
    }
}

/// `redactAmqpUri`: `user:password@` becomes `****@`.
fn redact(uri: &str) -> String {
    let re = regex::Regex::new(r"://[^@/]*@").expect("valid regex");
    re.replace_all(uri, "://****@").into_owned()
}

/// `buildFactoryFromUri`: `ConnectionFactory.setUri(uri)`; a `URISyntaxException` is reported with the redacted URI,
/// every other failure with its own message.
pub fn factory(uri: &str) -> Result<Factory, Error> {
    let parsed = crate::java_uri::parse(uri).map_err(|_| Error::new(format!("Invalid AMQP URI: {}", redact(uri))))?;
    let mut f = Factory::default();
    let Some(scheme) = parsed.scheme.as_deref() else {
        return Err(Error::new("Cannot invoke \"String.toLowerCase()\" because the return value of \"java.net.URI.getScheme()\" is null"));
    };
    match scheme.to_ascii_lowercase().as_str() {
        "amqp" => {}
        "amqps" => {
            f.port = 5671;
            f.ssl = true;
        }
        _ => return Err(Error::illegal(format!("Wrong scheme in AMQP URI: {scheme}"))),
    }
    if let Some(host) = &parsed.host {
        f.host = host.clone();
    }
    if parsed.port != -1 {
        f.port = parsed.port;
    }
    // `URLDecoder.decode(…, "US-ASCII")` of each part, a `+` kept as a `+`.
    let decode = |part: &str| url_decode(&part.replace('+', "%2B"), UrlCharset::Ascii).map_err(Error::new);
    if let Some(user_info) = &parsed.raw_user_info {
        let parts = split(user_info, ":");
        if parts.len() > 2 {
            return Err(Error::illegal("Bad user info in AMQP URI: user info contains more than one colon"));
        }
        let first = parts.first().ok_or_else(|| Error::new("Index 0 out of bounds for length 0"))?;
        f.username = decode(first)?;
        if parts.len() == 2 {
            f.password = decode(parts[1])?;
        }
    }
    if let Some(path) = parsed.raw_path.as_deref().filter(|p| !p.is_empty()) {
        // The path is one `/` and at most one segment.
        if path.char_indices().skip(1).any(|(_, c)| c == '/') {
            return Err(Error::illegal(format!("Multiple segments in path of AMQP URI: {path}")));
        }
        let decoded = crate::grpc_plane::percent_decode(path);
        let segment = decoded.char_indices().nth(1).map_or("", |(i, _)| &decoded[i..]);
        f.virtual_host = decode(segment)?;
    }
    if let Some(query) = parsed.raw_query.as_deref().filter(|q| !q.is_empty()) {
        let parameter = |part: &str| url_decode(part, UrlCharset::Ascii).map_err(|e| Error::new(format!("Cannot parse the query parameters: {e}")));
        for pair in split(query, "&") {
            let kv = split(pair, "=");
            let key = parameter(kv.first().ok_or_else(|| Error::new("Index 0 out of bounds for length 0"))?)?;
            let value = kv.get(1).map(|v| parameter(v)).transpose()?;
            let int = |message: &str| value.as_deref().and_then(|v| v.parse::<i32>().ok()).ok_or_else(|| Error::illegal(message));
            match key.as_str() {
                "heartbeat" => f.heartbeat = int("Requested heartbeat must an integer")?.clamp(0, 65535),
                "channel_max" => f.channel_max = int("Requested channel max must an integer")?,
                "connection_timeout" if int("TCP connection timeout must an integer")? < 0 => {
                    return Err(Error::illegal("TCP connection timeout cannot be negative"));
                }
                _ => {}
            }
        }
    }
    Ok(f)
}

/// What a closed channel reports afterwards (`AlreadyClosedException`), and what closed it.
#[derive(Clone, Debug)]
enum Closed {
    /// The `channel.close` method that closed the channel.
    Channel(String),
    /// Why the connection went away (`ShutdownSignalException`'s reason): `protocol method: …` or `cause: …`.
    Connection(String),
}

impl Closed {
    fn message(&self) -> String {
        match self {
            Closed::Channel(method) => format!("channel is already closed due to channel error; protocol method: {method}"),
            Closed::Connection(reason) => format!("connection is already closed due to connection error; {reason}"),
        }
    }
}

/// The class and method ids of the calls whose failure can close a channel.
#[derive(Clone, Copy)]
enum Call {
    ExchangeDeclare,
    QueueDeclare,
    QueueBind,
    BasicPublish,
    BasicConsume,
}

impl Call {
    fn ids(self) -> (u16, u16) {
        match self {
            Call::ExchangeDeclare => (40, 10),
            Call::QueueDeclare => (50, 10),
            Call::QueueBind => (50, 20),
            Call::BasicPublish => (60, 40),
            Call::BasicConsume => (60, 20),
        }
    }
}

/// One connection with one channel, as the Java adapters hold them.
struct Session {
    connection: lapin::Connection,
    channel: lapin::Channel,
    closed: Arc<Mutex<Option<Closed>>>,
    watcher: tokio::task::JoinHandle<()>,
    /// The broker's frames, for the reason it closed the connection.
    watch: Arc<transport::Watch>,
}

impl Session {
    /// A connection and its channel; losing the connection is remembered (`AlreadyClosedException` for every call
    /// until recovery replaces the session).
    async fn open(factory: &Factory) -> Result<Session, Error> {
        let (connection, watch) = connect(factory).await.map_err(|e| Error::caused(format!("Failed to connect to AMQP broker: {}", e.message), e))?;
        let channel = connection.create_channel().await.map_err(|e| Error::new(format!("Failed to connect to AMQP broker: {}", lapin_message(&e))))?;
        let closed = Arc::new(Mutex::new(None));
        let mut events = connection.events_listener();
        let watcher = super::broker::spawn({
            let (closed, watch) = (closed.clone(), watch.clone());
            async move {
                while let Some(event) = events.next().await {
                    // lapin reports a channel the broker closed (`channel.close`) here as well; that leaves the
                    // connection open (the failing call records it). A protocol error counts only with the broker's
                    // `connection.close`; any other error is the connection failing.
                    if let lapin::Event::Error(e) = event {
                        let channel_closed = matches!(e.kind(), lapin::ErrorKind::ProtocolError(_)) && watch.closed_by_broker().is_none();
                        if !channel_closed {
                            closed.lock().get_or_insert(Closed::Connection(shutdown_reason(&e, &watch)));
                        }
                    }
                }
            }
        });
        Ok(Session { connection, channel, closed, watcher, watch })
    }

    /// A channel call: fails at once when the channel is already closed; a broker error closes it.
    async fn call<T>(&self, call: Call, f: impl std::future::Future<Output = lapin::Result<T>>) -> Result<T, Error> {
        if let Some(closed) = self.closed.lock().clone() {
            return Err(Error::new(closed.message()));
        }
        match f.await {
            Ok(v) => Ok(v),
            Err(e) => {
                let (class, method) = call.ids();
                match e.kind() {
                    // The connection went away (a broker shutdown, a forced close): automatic recovery brings the
                    // channel back, so it is not marked closed.
                    lapin::ErrorKind::ProtocolError(amqp) if is_connection_error(amqp.get_id()) => {
                        Err(Error::new(Closed::Connection(shutdown_reason(&e, &self.watch)).message()))
                    }
                    lapin::ErrorKind::ProtocolError(amqp) => {
                        *self.closed.lock() = Some(Closed::Channel(format!(
                            "#method<channel.close>(reply-code={}, reply-text={}, class-id={class}, method-id={method})",
                            amqp.get_id(),
                            amqp.get_message()
                        )));
                        Err(Error::new("null"))
                    }
                    // The connection is gone: what took it.
                    _ if !self.connection.status().connected() => {
                        let closed = self.closed.lock().get_or_insert_with(|| Closed::Connection(shutdown_reason(&e, &self.watch))).clone();
                        Err(Error::new(closed.message()))
                    }
                    _ => Err(Error::new(lapin_message(&e))),
                }
            }
        }
    }

    async fn close(&self) {
        self.watcher.abort();
        if self.channel.status().connected() {
            let _ = self.channel.close(200, ShortString::from("OK")).await;
        }
        if self.connection.status().connected() {
            let _ = self.connection.close(200, ShortString::from("OK")).await;
        }
    }
}

/// `ShutdownSignalException`'s reason for a lost connection: the broker's `connection.close` (as the stream saw
/// it, else as lapin reports it), or the I/O failure
/// (`java.io.EOFException` for a connection that just ended).
fn shutdown_reason(e: &lapin::Error, watch: &transport::Watch) -> String {
    if let Some(close) = watch.closed_by_broker() {
        return format!(
            "protocol method: #method<connection.close>(reply-code={}, reply-text={}, class-id={}, method-id={})",
            close.code, close.text, close.class, close.method
        );
    }
    match e.kind() {
        lapin::ErrorKind::ProtocolError(amqp) => {
            format!("protocol method: #method<connection.close>(reply-code={}, reply-text={}, class-id=0, method-id=0)", amqp.get_id(), amqp.get_message())
        }
        lapin::ErrorKind::IOError(io) if io.kind() == std::io::ErrorKind::ConnectionReset => "cause: java.net.SocketException: Connection reset".into(),
        _ => "cause: java.io.EOFException".into(),
    }
}

/// Connection-level reply codes (AMQP 0-9-1 §1.9): 320, 402, 501–506, 530, 540, 541.
fn is_connection_error(code: u16) -> bool {
    matches!(code, 320 | 402 | 501..=506 | 530 | 540 | 541)
}

/// The message a Java client exception would carry for a lapin error.
fn lapin_message(e: &lapin::Error) -> String {
    match e.kind() {
        lapin::ErrorKind::IOError(io) => super::broker::io_message(io, ""),
        lapin::ErrorKind::ProtocolError(amqp) => amqp.get_message().to_string(),
        _ => "null".into(),
    }
}

/// `factory.newConnection()`: the host's addresses (`DnsRecordIpAddressResolver`, `InetAddress.getAllByName`) in
/// shuffled order (`AddressResolver.maybeShuffle`, `Collections.shuffle`), the whole connect on each until one
/// succeeds; every failure is caught and the last one thrown.
async fn connect(factory: &Factory) -> Result<(lapin::Connection, Arc<transport::Watch>), Error> {
    let port = if factory.port == -1 { if factory.ssl { 5671 } else { 5672 } } else { factory.port };
    if !(0..=65535).contains(&port) {
        return Err(Error::new(format!("port out of range:{port}")));
    }
    let host = factory.host.trim_start_matches('[').trim_end_matches(']').to_string();
    let mut addresses = crate::inet_address::lookup(&host, port as u16).await.map_err(|e| Error::new(dial_message(&super::tls::DialError::Lookup(e), &host)))?;
    shuffle(&mut addresses);
    let mut last = None;
    for address in addresses {
        match connect_to(factory, &host, port, address).await {
            Ok(connected) => return Ok(connected),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| Error::new(dial_message(&super::tls::DialError::Connect(std::io::Error::new(std::io::ErrorKind::NotFound, "no address")), &host))))
}

/// `Collections.shuffle`: a uniformly random order.
fn shuffle<T>(items: &mut [T]) {
    use rand_core::RngCore;
    for i in (1..items.len()).rev() {
        let j = (rand_core::OsRng.next_u64() % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

/// One attempt of [`connect`]: TCP to `address` (5 s), TLS for `amqps` (the JVM's default context), then the AMQP
/// handshake.
async fn connect_to(factory: &Factory, host: &str, port: i32, address: std::net::SocketAddr) -> Result<(lapin::Connection, Arc<transport::Watch>), Error> {
    let host = host.to_string();
    let tcp = super::tls::dial_address(address, CONNECTION_TIMEOUT).await.map_err(|e| Error::new(dial_message(&e, &host)))?;
    let tls = if factory.ssl { Some(super::tls::jdk_default_context()?) } else { None };
    let uri = lapin::uri::AMQPUri {
        scheme: if factory.ssl { lapin::uri::AMQPScheme::AMQPS } else { lapin::uri::AMQPScheme::AMQP },
        authority: lapin::uri::AMQPAuthority {
            userinfo: lapin::uri::AMQPUserInfo { username: factory.username.clone(), password: factory.password.clone() },
            host: host.clone(),
            port: port as u16,
        },
        vhost: factory.virtual_host.clone(),
        query: lapin::uri::AMQPQueryString {
            frame_max: Some(0),
            channel_max: Some(factory.channel_max.clamp(0, 65535) as u16),
            heartbeat: Some(factory.heartbeat as u16),
            connection_timeout: Some(CONNECTION_TIMEOUT.as_millis() as u64),
            auth_mechanism: None,
        },
    };
    let runtime = async_rs::Runtime::new(transport::Kit::current());
    let stream = Arc::new(Mutex::new(Some(tcp)));
    let properties = ConnectionProperties::default()
        .with_client_property("product".into(), LongString::from("RabbitMQ"))
        .with_client_property("version".into(), LongString::from("5.35.0"))
        .with_client_property("platform".into(), LongString::from("Java"));
    let reconnect_to = (host.clone(), port as u16);
    let handshake = Arc::new(transport::Watch::default());
    let watch = handshake.clone();
    let connector = lapin::Connection::connector(
        uri,
        runtime,
        async move |_uri, _runtime| {
            // The first connection is the one opened above; lapin opening another dials again.
            let first = stream.lock().take();
            let tcp = match first {
                Some(tcp) => tcp,
                None => super::tls::dial_tcp(&reconnect_to.0, reconnect_to.1, CONNECTION_TIMEOUT).await.map_err(|e| match e {
                    super::tls::DialError::Lookup(e) | super::tls::DialError::Connect(e) | super::tls::DialError::Handshake(e) => lapin::Error::from(e),
                    super::tls::DialError::Timeout => lapin::Error::from(std::io::Error::from(std::io::ErrorKind::TimedOut)),
                })?,
            };
            let stream = match &tls {
                Some(config) => transport::Stream::tls(super::tls::handshake(tcp, &reconnect_to.0, config.clone(), super::tls::Sni::Jdk).await?, Some(watch.clone())),
                None => transport::Stream::plain(tcp, Some(watch.clone())),
            };
            Ok(lapin::tcp::AsyncTcpStream::Plain(stream))
        },
        properties,
    );
    // The broker ending the handshake (`connection.close` after `connection.open`) fails it at once, as the Java
    // client's does; otherwise `handshakeTimeout` bounds it.
    let connection = tokio::select! {
        outcome = tokio::time::timeout(HANDSHAKE_TIMEOUT, connector) => outcome.map_err(|_| Error::new("null"))?,
        _ = handshake.refused() => return Err(Error::new("null")),
    };
    connection.map(|c| (c, handshake)).map_err(|e| match e.kind() {
        // `AuthenticationFailureException`: the broker's reply text.
        lapin::ErrorKind::ProtocolError(amqp) if amqp.get_id() == 403 => Error::of_kind(
            super::broker::ErrorKind::Authentication,
            amqp.get_message().to_string(),
        ),
        lapin::ErrorKind::IOError(io) if super::tls::is_tls_failure(io) => Error::of_kind(super::broker::ErrorKind::Tls, super::tls::jsse_message(io)),
        // The Java client wraps other handshake failures in a message-less `IOException`.
        _ => Error::new("null"),
    })
}

/// A failed dial as the Java client reports it: an `UnknownHostException` (the host and glibc's `gai_strerror`
/// text, or the host alone when the JDK's negative cache answered), a connect timeout, or the socket's error.
fn dial_message(e: &super::tls::DialError, host: &str) -> String {
    match e {
        super::tls::DialError::Lookup(e) if super::tls::is_cached_lookup_failure(e) => host.to_string(),
        super::tls::DialError::Lookup(_) => format!("{host}: Name or service not known"),
        super::tls::DialError::Timeout => "Connect timed out".into(),
        super::tls::DialError::Connect(e) | super::tls::DialError::Handshake(e) => super::broker::io_message(e, host),
    }
}

/// `AmqpMessagePublisher.Destination`: where a channel's messages go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destination {
    pub exchange: String,
    pub routing_key: String,
}

/// `resolveDestination`: no binding or `is: queue` → the default exchange with the queue (or channel) name;
/// `is: routingKey` → the binding's exchange with its routing key or the channel name.
pub fn resolve_destination(channel: &str, binding: Option<&AmqpBinding>) -> Destination {
    let Some(binding) = binding else { return Destination { exchange: DEFAULT_EXCHANGE.into(), routing_key: channel.into() } };
    if binding.channel_type == AmqpChannelType::Queue {
        return Destination { exchange: DEFAULT_EXCHANGE.into(), routing_key: binding.queue_name.clone().unwrap_or_else(|| channel.into()) };
    }
    Destination {
        exchange: binding.exchange_name.clone().unwrap_or_else(|| DEFAULT_EXCHANGE.into()),
        routing_key: binding.routing_key.clone().unwrap_or_else(|| channel.into()),
    }
}

/// The `BasicProperties` a publish carries: none (`null`) without headers, else the options' headers as the message
/// headers, each a long string. Upstream copies them into a `HashMap`; lapin's table is sorted by name. The order
/// cannot show: a publish carries at most one header (the orchestrator's correlation id).
pub fn message_properties(options: &PublishOptions) -> BasicProperties {
    if options.headers.is_empty() {
        return BasicProperties::default();
    }
    let table: std::collections::BTreeMap<ShortString, AMQPValue> =
        options.headers.iter().map(|(k, v)| (ShortString::from(k.as_str()), AMQPValue::LongString(LongString::from(v.as_str())))).collect();
    BasicProperties::default().with_headers(FieldTable::from(table))
}

/// `normaliseExchangeType`: a built-in type (any case), else `direct`.
fn exchange_kind(kind: &str) -> ExchangeKind {
    match kind.to_uppercase().as_str() {
        "DIRECT" => ExchangeKind::Direct,
        "FANOUT" => ExchangeKind::Fanout,
        "TOPIC" => ExchangeKind::Topic,
        "HEADERS" => ExchangeKind::Headers,
        _ => ExchangeKind::Direct,
    }
}

fn bindings(spec: Option<&Spec>) -> Vec<(String, AmqpBinding)> {
    spec.map(|s| s.channels.iter().filter_map(|c| c.amqp_binding.clone().map(|b| (c.name.clone(), b))).collect()).unwrap_or_default()
}

fn binding_of<'a>(bindings: &'a [(String, AmqpBinding)], channel: &str) -> Option<&'a AmqpBinding> {
    bindings.iter().rev().find(|(c, _)| c == channel).map(|(_, b)| b)
}

/// `AmqpMessagePublisher`.
pub struct AmqpPublisher {
    session: Arc<Mutex<Arc<Session>>>,
    bindings: Vec<(String, AmqpBinding)>,
    confirms: Arc<AtomicBool>,
    /// Exchanges declared (name, type, durable), recovered with the connection.
    declared_exchanges: Arc<Mutex<Vec<(String, String, bool)>>>,
    /// Queues declared (name, durable), recovered with the connection.
    declared_queues: Arc<Mutex<Vec<(String, bool)>>>,
    publishing: tokio::sync::Mutex<()>,
    recovery: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

async fn declare_exchange(session: &Session, name: &str, kind: &str, durable: bool) -> Result<(), Error> {
    let declare = session.channel.exchange_declare(
        ShortString::from(name),
        exchange_kind(kind),
        ExchangeDeclareOptions { durable, ..Default::default() },
        FieldTable::default(),
    );
    session.call(Call::ExchangeDeclare, declare).await
}

async fn declare_queue(session: &Session, name: &str, durable: bool) -> Result<(), Error> {
    let declare = session.channel.queue_declare(ShortString::from(name), QueueDeclareOptions { durable, ..Default::default() }, FieldTable::default());
    session.call(Call::QueueDeclare, declare).await.map(|_| ())
}

/// `enableUnroutableDetection`: publisher confirms (a RabbitMQ extension); without them, no `mandatory`. A broker
/// refusing `confirm.select` closes the channel, which is replaced.
async fn enable_confirms(session: Session) -> Result<(Session, bool), Error> {
    let confirms = session.channel.confirm_select(ConfirmSelectOptions::default()).await.is_ok();
    if confirms || session.channel.status().connected() {
        return Ok((session, confirms));
    }
    let channel = session
        .connection
        .create_channel()
        .await
        .map_err(|e| {
            let cause = lapin_message(&e);
            Error::new(format!("Failed to connect to AMQP broker: Failed to enable AMQP publisher confirms and could not recover the channel: {cause}"))
        })?;
    Ok((Session { channel, ..session }, false))
}

/// The Java client's automatic recovery: every `networkRecoveryInterval`, a lost connection is reopened; `then`
/// restores what the adapter had on it. A channel closed by a channel error stays closed.
fn recover<F, Fut>(factory: Factory, slot: Arc<Mutex<Arc<Session>>>, then: F) -> tokio::task::JoinHandle<()>
where
    F: Fn(Session) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Option<Session>> + Send,
{
    super::broker::spawn(async move {
        loop {
            tokio::time::sleep(RECOVERY_INTERVAL).await;
            let current = slot.lock().clone();
            if current.connection.status().connected() {
                continue;
            }
            let Ok(fresh) = Session::open(&factory).await else { continue };
            let carried = current.closed.lock().clone().filter(|c| matches!(c, Closed::Channel(_)));
            *fresh.closed.lock() = carried;
            current.watcher.abort();
            if let Some(ready) = then(fresh).await {
                *slot.lock() = Arc::new(ready);
            }
        }
    })
}

impl AmqpPublisher {
    /// `new AmqpMessagePublisher(amqpUri, spec)`.
    pub async fn connect(uri: &str, spec: Option<&Spec>) -> Result<Self, Error> {
        let factory = factory(uri)?;
        let (session, confirms) = enable_confirms(Session::open(&factory).await?).await?;
        let slot = Arc::new(Mutex::new(Arc::new(session)));
        let confirms = Arc::new(AtomicBool::new(confirms));
        let declared_exchanges: Arc<Mutex<Vec<(String, String, bool)>>> = Arc::default();
        let declared_queues: Arc<Mutex<Vec<(String, bool)>>> = Arc::default();
        let recovery = {
            let (confirms, exchanges, queues) = (confirms.clone(), declared_exchanges.clone(), declared_queues.clone());
            recover(factory, slot.clone(), move |fresh| {
                let (confirms, exchanges, queues) = (confirms.clone(), exchanges.clone(), queues.clone());
                async move {
                    let (session, enabled) = enable_confirms(fresh).await.ok()?;
                    confirms.store(enabled, Ordering::SeqCst);
                    // Topology recovery: what was declared is declared again at once (a failure is not fatal, as
                    // the Java client's recovery only logs it).
                    let exchanges = exchanges.lock().clone();
                    for (name, kind, durable) in exchanges {
                        let _ = declare_exchange(&session, &name, &kind, durable).await;
                    }
                    let queues = queues.lock().clone();
                    for (name, durable) in queues {
                        let _ = declare_queue(&session, &name, durable).await;
                    }
                    Some(session)
                }
            })
        };
        Ok(AmqpPublisher {
            session: slot,
            bindings: bindings(spec),
            confirms,
            declared_exchanges,
            declared_queues,
            publishing: tokio::sync::Mutex::new(()),
            recovery: Mutex::new(Some(recovery)),
        })
    }

    fn session(&self) -> Arc<Session> {
        self.session.lock().clone()
    }

    /// `publish(channel, payload, options)`: headers become AMQP message headers; key, QoS and retain are ignored.
    async fn publish_message(&self, channel: &str, payload: &str, options: &PublishOptions) -> Result<(), Error> {
        let _guard = self.publishing.lock().await;
        let session = self.session();
        let confirms = self.confirms.load(Ordering::SeqCst);
        let binding = binding_of(&self.bindings, channel).cloned();
        let destination = resolve_destination(channel, binding.as_ref());
        let failed = |e: Error| Error::caused(format!("Failed to publish to AMQP channel '{channel}': {}", e.message), e);
        self.ensure_topology(&session, binding.as_ref(), &destination).await.map_err(failed)?;
        let properties = message_properties(options);
        let confirm = session
            .call(
                Call::BasicPublish,
                session.channel.basic_publish(
                    ShortString::from(destination.exchange.as_str()),
                    ShortString::from(destination.routing_key.as_str()),
                    BasicPublishOptions { mandatory: confirms, ..Default::default() },
                    payload.as_bytes(),
                    properties,
                ),
            )
            .await
            .map_err(failed)?;
        if !confirms {
            return Ok(());
        }
        let returned = match tokio::time::timeout(CONFIRM_TIMEOUT, confirm).await {
            Err(_) => return Err(failed(Error::new("null"))),
            Ok(Err(e)) => return Err(failed(Error::new(lapin_message(&e)))),
            Ok(Ok(Confirmation::Nack(_))) => return Err(failed(Error::new("broker nacked the message"))),
            Ok(Ok(Confirmation::Ack(returned))) => returned,
            Ok(Ok(Confirmation::NotRequested)) => None,
        };
        if let Some(r) = returned {
            return Err(Error::new(format!(
                "Message published to AMQP channel '{channel}' was not routed to any queue: no queue is bound to exchange '{}' for routing key '{}' (broker \
                    returned {} {})",
                r.delivery.exchange, r.delivery.routing_key, r.reply_code, r.reply_text
            )));
        }
        Ok(())
    }

    /// `ensureTopologyDeclared`: a named exchange once (type from the binding, default `direct`); for a queue
    /// channel on the default exchange, its queue once. Remembered even when the declaration fails.
    async fn ensure_topology(&self, session: &Session, binding: Option<&AmqpBinding>, destination: &Destination) -> Result<(), Error> {
        if !destination.exchange.is_empty() {
            let kind = binding.and_then(|b| b.exchange_type.clone()).unwrap_or_else(|| DEFAULT_EXCHANGE_TYPE.into());
            let durable = binding.is_none_or(|b| b.exchange_durable);
            let new = {
                let mut declared = self.declared_exchanges.lock();
                let new = !declared.iter().any(|(name, _, _)| *name == destination.exchange);
                if new {
                    declared.push((destination.exchange.clone(), kind.clone(), durable));
                }
                new
            };
            if new {
                declare_exchange(session, &destination.exchange, &kind, durable).await?;
            }
        }
        if let Some(binding) = binding.filter(|b| b.channel_type == AmqpChannelType::Queue && destination.exchange.is_empty()) {
            let new = {
                let mut declared = self.declared_queues.lock();
                let new = !declared.iter().any(|(name, _)| *name == destination.routing_key);
                if new {
                    declared.push((destination.routing_key.clone(), binding.queue_durable));
                }
                new
            };
            if new {
                declare_queue(session, &destination.routing_key, binding.queue_durable).await?;
            }
        }
        Ok(())
    }

    async fn close_session(&self) {
        if let Some(task) = self.recovery.lock().take() {
            task.abort();
        }
        self.session().close().await;
    }
}

impl super::broker::Publisher for AmqpPublisher {
    fn publish<'a>(&'a self, channel: &'a str, payload: &'a str, options: &'a PublishOptions) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(self.publish_message(channel, payload, options))
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(self.close_session())
    }

}

/// What a subscriber's consumers need, shared with its recovery.
struct Consuming {
    bindings: Vec<(String, AmqpBinding)>,
    recorder: Arc<ConsumedMessages>,
    counters: Counters,
    channels: Mutex<Vec<String>>,
    consumers: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Consuming {
    /// The channel's queue, and a consumer on it recording what arrives.
    async fn start(self: &Arc<Self>, session: &Session, channel: &str) -> Result<(), Error> {
        let queue = consume_queue(session, channel, binding_of(&self.bindings, channel)).await?;
        let consumer = session
            .call(
                Call::BasicConsume,
                session.channel.basic_consume(
                    ShortString::from(queue.as_str()),
                    ShortString::from(""),
                    BasicConsumeOptions { no_ack: true, ..Default::default() },
                    FieldTable::default(),
                ),
            )
            .await?;
        let (recorder, counters, channel) = (self.recorder.clone(), self.counters.clone(), channel.to_string());
        let task = super::broker::spawn(async move {
            let mut consumer = consumer;
            while let Some(Ok(delivery)) = consumer.next().await {
                recorder.record(consumed_message(&channel, &delivery.data, delivery.properties.headers().as_ref()));
                counters.consumed(&channel);
            }
        });
        self.consumers.lock().push(task);
        Ok(())
    }
}

/// `AmqpMessageSubscriber`: records what arrives on each channel's queue (a private queue bound to the exchange for
/// an exchange-routed channel).
pub struct AmqpSubscriber {
    session: Arc<Mutex<Arc<Session>>>,
    consuming: Arc<Consuming>,
    recovery: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl AmqpSubscriber {
    /// `new AmqpMessageSubscriber(amqpUri, spec, maxRecordedMessages)`.
    pub async fn connect(uri: &str, spec: Option<&Spec>, max_recorded: i64, counters: Counters) -> Result<Self, Error> {
        let factory = factory(uri)?;
        let session = Session::open(&factory).await.map_err(|e| Error { message: e.message.replacen("Failed to connect to AMQP broker", "Failed to connect \
            AMQP subscriber to broker", 1), ..e })?;
        let slot = Arc::new(Mutex::new(Arc::new(session)));
        let consuming = Arc::new(Consuming {
            bindings: bindings(spec),
            recorder: Arc::new(ConsumedMessages::new(max_recorded)),
            counters,
            channels: Mutex::new(Vec::new()),
            consumers: Mutex::new(Vec::new()),
        });
        let recovery = {
            let consuming = consuming.clone();
            recover(factory, slot.clone(), move |fresh| {
                let consuming = consuming.clone();
                async move {
                    // Consumer recovery: the old consumers ended with the connection; the queues are declared and
                    // bound again (a private queue gets a new name) and consumed afresh.
                    for task in consuming.consumers.lock().drain(..) {
                        task.abort();
                    }
                    let channels = consuming.channels.lock().clone();
                    for channel in channels {
                        let _ = consuming.start(&fresh, &channel).await;
                    }
                    Some(fresh)
                }
            })
        };
        Ok(AmqpSubscriber { session: slot, consuming, recovery: Mutex::new(Some(recovery)) })
    }
}

impl super::broker::Subscriber for AmqpSubscriber {
    fn subscribe<'a>(&'a self, channel: &'a str) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            self.consuming.recorder.ensure(channel).map_err(Error::new)?;
            let session = self.session.lock().clone();
            self.consuming
                .start(&session, channel).await
                .map_err(|e| Error::caused(format!("Failed to subscribe to AMQP channel '{channel}': {}", e.message), e))?;
            self.consuming.channels.lock().push(channel.to_string());
            Ok(())
        })
    }

    fn recorded(&self, channel: &str) -> Vec<ConsumedMessage> {
        self.consuming.recorder.exact(channel)
    }

    fn all_recorded(&self) -> Vec<ConsumedMessage> {
        self.consuming.recorder.all()
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if let Some(task) = self.recovery.lock().take() {
                task.abort();
            }
            let session = self.session.lock().clone();
            session.close().await;
            for task in self.consuming.consumers.lock().drain(..) {
                task.abort();
            }
            self.consuming.recorder.clear();
            self.consuming.channels.lock().clear();
        })
    }
}

/// Where a subscriber consumes a channel from (`resolveConsumeQueue`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsumeSource {
    /// A queue, declared (durable or not, neither exclusive nor auto-delete) and consumed.
    Queue { name: String, durable: bool },
    /// An exchange, declared with its type and durability, and a private queue (server-named, exclusive,
    /// auto-delete) bound to it on the routing key and consumed.
    Exchange { exchange: String, kind: ExchangeKind, durable: bool, routing_key: String },
}

/// `resolveConsumeQueue`: no binding or `is: queue` → the queue (the binding's or the channel's name, durable per
/// the binding); `is: routingKey` on the default exchange → the queue named by the routing key; on a named exchange
/// → a private queue bound to it on the routing key (the binding's, else the channel name).
pub fn consume_source(channel: &str, binding: Option<&AmqpBinding>) -> ConsumeSource {
    let binding = match binding {
        None => return ConsumeSource::Queue { name: channel.to_string(), durable: true },
        Some(b) if b.channel_type == AmqpChannelType::Queue => {
            return ConsumeSource::Queue { name: b.queue_name.clone().unwrap_or_else(|| channel.into()), durable: b.queue_durable };
        }
        Some(b) => b,
    };
    let exchange = binding.exchange_name.clone().unwrap_or_default();
    let routing_key = binding.routing_key.clone().unwrap_or_else(|| channel.into());
    if exchange.is_empty() {
        return ConsumeSource::Queue { name: routing_key, durable: true };
    }
    let kind = exchange_kind(binding.exchange_type.as_deref().unwrap_or(DEFAULT_EXCHANGE_TYPE));
    ConsumeSource::Exchange { exchange, kind, durable: binding.exchange_durable, routing_key }
}

/// Declares (and binds) what [`consume_source`] names, and gives the queue to consume.
async fn consume_queue(session: &Session, channel: &str, binding: Option<&AmqpBinding>) -> Result<String, Error> {
    let (exchange, kind, durable, routing_key) = match consume_source(channel, binding) {
        ConsumeSource::Queue { name, durable } => {
            let declare = session.channel.queue_declare(
                ShortString::from(name.as_str()),
                QueueDeclareOptions { durable, ..Default::default() },
                FieldTable::default(),
            );
            return session.call(Call::QueueDeclare, declare).await.map(|_| name);
        }
        ConsumeSource::Exchange { exchange, kind, durable, routing_key } => (exchange, kind, durable, routing_key),
    };
    session
        .call(
            Call::ExchangeDeclare,
            session.channel.exchange_declare(
                ShortString::from(exchange.as_str()),
                kind,
                ExchangeDeclareOptions { durable, ..Default::default() },
                FieldTable::default(),
            ),
        )
        .await?;
    let queue = session
        .call(
            Call::QueueDeclare,
            session.channel.queue_declare(
                ShortString::from(""),
                QueueDeclareOptions { exclusive: true, auto_delete: true, ..Default::default() },
                FieldTable::default(),
            ),
        )
        .await?;
    let name = queue.name().to_string();
    session
        .call(
            Call::QueueBind,
            session.channel.queue_bind(
                ShortString::from(name.as_str()),
                ShortString::from(exchange.as_str()),
                ShortString::from(routing_key.as_str()),
                QueueBindOptions::default(),
                FieldTable::default(),
            ),
        )
        .await?;
    Ok(name)
}

/// `record`: a delivery on a channel as a consumed message: no key, the body as UTF-8, the headers (if any) as
/// `extractHeaders` gives them.
pub fn consumed_message(channel: &str, body: &[u8], headers: Option<&FieldTable>) -> ConsumedMessage {
    ConsumedMessage::new(channel, None, Some(String::from_utf8_lossy(body).into_owned()), headers.map(java_headers).unwrap_or_default())
}

/// `extractHeaders`: the Java client decodes the table into a `HashMap`, so the headers come in its iteration
/// order, each value's `toString()`.
fn java_headers(table: &FieldTable) -> Vec<(String, Option<String>)> {
    let entries: Vec<(String, Option<String>)> = table.inner().iter().map(|(k, v)| (k.to_string(), java_to_string(v))).collect();
    let keys: Vec<String> = entries.iter().map(|(k, _)| k.clone()).collect();
    crate::recorded::java_hashmap_order(&keys).into_iter().map(|i| entries[i].clone()).collect()
}

/// A decoded field value's Java `toString()`.
fn java_to_string(v: &AMQPValue) -> Option<String> {
    Some(match v {
        AMQPValue::Boolean(b) => b.to_string(),
        AMQPValue::ShortShortInt(n) => n.to_string(),
        AMQPValue::ShortShortUInt(n) => n.to_string(),
        AMQPValue::ShortInt(n) => n.to_string(),
        AMQPValue::ShortUInt(n) => n.to_string(),
        AMQPValue::LongInt(n) => n.to_string(),
        AMQPValue::LongUInt(n) => n.to_string(),
        AMQPValue::LongLongInt(n) => n.to_string(),
        AMQPValue::Float(f) => java_compat::float_to_string(*f),
        AMQPValue::Double(d) => java_compat::double_to_string(*d),
        AMQPValue::DecimalValue(d) => {
            let digits = d.value.to_string();
            let scale = d.scale as usize;
            if scale == 0 {
                digits
            } else if digits.len() > scale {
                format!("{}.{}", &digits[..digits.len() - scale], &digits[digits.len() - scale..])
            } else {
                format!("0.{}{digits}", "0".repeat(scale - digits.len()))
            }
        }
        AMQPValue::ShortString(s) => s.to_string(),
        AMQPValue::LongString(s) => String::from_utf8_lossy(s.as_bytes()).into_owned(),
        AMQPValue::FieldArray(a) => format!(
            "[{}]",
            a.as_slice().iter().map(|v| java_to_string(v).unwrap_or_else(|| "null".into())).collect::<Vec<_>>().join(", "),
        ),
        AMQPValue::Timestamp(t) => t.to_string(),
        AMQPValue::FieldTable(t) => format!(
            "{{{}}}",
            java_headers(t).into_iter().map(|(k, v)| format!("{k}={}", v.unwrap_or_else(|| "null".into()))).collect::<Vec<_>>().join(", "),
        ),
        AMQPValue::ByteArray(b) => format!("{:?}", b.as_slice()),
        AMQPValue::Void => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn describe(uri: &str) -> String {
        match factory(uri) {
            Ok(f) => format!(
                "host={} port={} vhost=[{}] user=[{}] pass=[{}] hb={} cm={} ssl={}",
                f.host,
                if f.port == -1 { if f.ssl { 5671 } else { 5672 } } else { f.port },
                f.virtual_host,
                f.username,
                f.password,
                f.heartbeat,
                f.channel_max,
                f.ssl,
            ),
            Err(e) => e.message,
        }
    }

    /// Recorded from `ConnectionFactory.setUri` (amqp-client 5.35.0) with upstream's `buildFactoryFromUri` wrapping.
    #[test]
    fn uris_are_read_as_the_java_client_reads_them() {
        let cases = [
            ("amqp://rabbit", "host=rabbit port=5672 vhost=[/] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://rabbit/", "host=rabbit port=5672 vhost=[] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://rabbit/%2f", "host=rabbit port=5672 vhost=[/] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://rabbit/%252f", "host=rabbit port=5672 vhost=[/] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://rabbit/v%20h", "host=rabbit port=5672 vhost=[v h] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://rabbit/v+h", "host=rabbit port=5672 vhost=[v+h] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://u:p@rabbit:5673/vh", "host=rabbit port=5673 vhost=[vh] user=[u] pass=[p] hb=60 cm=2047 ssl=false"),
            ("amqp://u@rabbit", "host=rabbit port=5672 vhost=[/] user=[u] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://u%3Ax:p%40y@rabbit", "host=rabbit port=5672 vhost=[/] user=[u:x] pass=[p@y] hb=60 cm=2047 ssl=false"),
            ("amqp://:@rabbit", "Index 0 out of bounds for length 0"),
            ("amqp://a:b:c@rabbit", "Bad user info in AMQP URI: user info contains more than one colon"),
            ("amqps://rabbit", "host=rabbit port=5671 vhost=[/] user=[guest] pass=[guest] hb=60 cm=2047 ssl=true"),
            ("AMQPS://rabbit:1234", "host=rabbit port=1234 vhost=[/] user=[guest] pass=[guest] hb=60 cm=2047 ssl=true"),
            ("amqp://", "Invalid AMQP URI: amqp://"),
            ("amqp:///vh", "host=localhost port=5672 vhost=[vh] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp:rabbit", "host=localhost port=5672 vhost=[/] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("localhost", "Cannot invoke \"String.toLowerCase()\" because the return value of \"java.net.URI.getScheme()\" is null"),
            ("http://x", "Wrong scheme in AMQP URI: http"),
            ("not a uri", "Invalid AMQP URI: not a uri"),
            ("amqp://rabbit/x/y", "Multiple segments in path of AMQP URI: /x/y"),
            ("amqp://rabbit?heartbeat=10&channel_max=5&connection_timeout=7", "host=rabbit port=5672 vhost=[/] user=[guest] pass=[guest] hb=10 cm=5 ssl=false"),
            ("amqp://rabbit?heartbeat=x", "Requested heartbeat must an integer"),
            ("amqp://rabbit?channel_max=x", "Requested channel max must an integer"),
            ("amqp://rabbit?connection_timeout=x", "TCP connection timeout must an integer"),
            ("amqp://rabbit?foo=bar", "host=rabbit port=5672 vhost=[/] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://rabbit?heartbeat", "Requested heartbeat must an integer"),
            ("amqp://rabbit?=", "Index 0 out of bounds for length 0"),
            ("amqp://[::1]:5672", "host=[::1] port=5672 vhost=[/] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://rabbit:", "host=rabbit port=5672 vhost=[/] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://rabbit:abc", "host=localhost port=5672 vhost=[/] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://rab_bit", "host=localhost port=5672 vhost=[/] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://rabbit#frag", "host=rabbit port=5672 vhost=[/] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://rabbit/%zz", "Invalid AMQP URI: amqp://rabbit/%zz"),
            ("amqp://ü@rabbit", "host=rabbit port=5672 vhost=[/] user=[ü] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://u:p%C3%BC@rabbit", "host=rabbit port=5672 vhost=[/] user=[u] pass=[p\u{FFFD}\u{FFFD}] hb=60 cm=2047 ssl=false"),
            ("amqp://rabbit/%C3%BC", "host=rabbit port=5672 vhost=[ü] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://host.with.dots:99999", "host=host.with.dots port=99999 vhost=[/] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://1.2.3.4", "host=1.2.3.4 port=5672 vhost=[/] user=[guest] pass=[guest] hb=60 cm=2047 ssl=false"),
            ("amqp://r a", "Invalid AMQP URI: amqp://r a"),
            ("amqp://u:secret@r a", "Invalid AMQP URI: amqp://****@r a"),
        ];
        let failures: Vec<String> = cases
            .iter()
            .filter(|(uri, want)| describe(uri) != *want)
            .map(|(uri, want)| format!("{uri}: got {} want {want}", describe(uri)))
            .collect();
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn destinations_follow_the_binding() {
        let queue = AmqpBinding::new(AmqpChannelType::Queue, None, None, true, Some("q"), true, None);
        assert_eq!(resolve_destination("ch", Some(&queue)), Destination { exchange: "".into(), routing_key: "q".into() });
        let routed = AmqpBinding::new(AmqpChannelType::RoutingKey, Some("ex"), Some("topic"), true, None, true, Some("rk"));
        assert_eq!(resolve_destination("ch", Some(&routed)), Destination { exchange: "ex".into(), routing_key: "rk".into() });
        assert_eq!(resolve_destination("ch", None), Destination { exchange: "".into(), routing_key: "ch".into() });
    }
}

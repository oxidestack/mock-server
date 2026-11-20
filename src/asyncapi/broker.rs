//! What the broker adapters share: the error they fail with, the runtime their connections live on,
//! `PublishOptions`, and the `MessagePublisher`/`MessageSubscriber` interfaces.

use std::future::Future;

use super::store::ConsumedMessage;

/// What kind of failure an [`Error`] (or one of its causes) is, for callers that tell them apart the way upstream's
/// tests look for an `SSLException` or an `AuthenticationException` in a cause chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Other,
    /// The TLS handshake failed (certificate trust, identity, protocol).
    Tls,
    /// The broker refused the credentials.
    Authentication,
    /// The input was refused before any connection (an `IllegalArgumentException` upstream): a client error, which
    /// the control plane answers 400 rather than as a fault.
    IllegalArgument,
}

/// A broker failure: upstream's exception message (what the control plane reports), with the underlying cause.
#[derive(Debug, Clone)]
pub struct Error {
    pub message: String,
    pub kind: ErrorKind,
    pub cause: Option<Box<Error>>,
    /// The exception's own bean properties beside its message, as the event log's throwable shows them (a
    /// `NoSuchFileException`'s `file`, an `MqttException`'s `reasonCode`).
    pub fields: Vec<(&'static str, serde_json::Value)>,
    /// An exception without a message (`getMessage()` is null): its bean has neither `message` nor
    /// `localizedMessage`.
    pub no_message: bool,
    /// An exception that overrides `fillInStackTrace` (Kafka's `ApiException`s): its bean has no `stackTrace`.
    pub stackless: bool,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Error { message: message.into(), kind: ErrorKind::Other, cause: None, fields: Vec::new(), no_message: false, stackless: false }
    }

    pub fn of_kind(kind: ErrorKind, message: impl Into<String>) -> Self {
        Error { message: message.into(), kind, cause: None, fields: Vec::new(), no_message: false, stackless: false }
    }

    /// An `IllegalArgumentException`: input the caller can correct.
    pub fn illegal(message: impl Into<String>) -> Self {
        Error::of_kind(ErrorKind::IllegalArgument, message)
    }

    /// `new RuntimeException(message, cause)`.
    pub fn caused(message: impl Into<String>, cause: Error) -> Self {
        Error { message: message.into(), kind: ErrorKind::Other, cause: Some(Box::new(cause)), fields: Vec::new(), no_message: false, stackless: false }
    }

    /// `new KafkaException(cause)` and the like: an exception whose message is its cause's `toString()`,
    /// `<class>: <message>`.
    pub fn wrapping(class: &str, cause: Error) -> Self {
        Error::caused(format!("{class}: {}", cause.message), cause)
    }

    /// `new IllegalArgumentException()` and the like: an exception without a message.
    pub fn without_message() -> Self {
        Error { no_message: true, ..Error::new("") }
    }

    /// Without a stack trace (see [`Error::stackless`]).
    pub fn stackless(mut self) -> Self {
        self.stackless = true;
        self
    }

    /// With a bean property of its own (see [`Error::fields`]).
    pub fn with_field(mut self, name: &'static str, value: impl Into<serde_json::Value>) -> Self {
        self.fields.push((name, value.into()));
        self
    }

    /// The exception as the event log's throwable shows it (Jackson's bean of a `Throwable`, its frames left
    /// out): `cause`, its own properties, `localizedMessage`, `message` and `stackTrace`, by name.
    pub fn bean(&self) -> serde_json::Value {
        let mut properties: Vec<(String, serde_json::Value)> = self.fields.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        if let Some(cause) = &self.cause {
            properties.push(("cause".into(), cause.bean()));
        }
        if !self.no_message {
            properties.push(("localizedMessage".into(), self.message.clone().into()));
            properties.push(("message".into(), self.message.clone().into()));
        }
        if !self.stackless {
            properties.push(("stackTrace".into(), serde_json::Value::Array(Vec::new())));
        }
        properties.sort_by(|a, b| a.0.cmp(&b.0));
        serde_json::Value::Object(properties.into_iter().collect())
    }

    /// This error and its causes, outermost first.
    pub fn chain(&self) -> impl Iterator<Item = &Error> {
        std::iter::successors(Some(self), |e| e.cause.as_deref())
    }

    /// Whether this error or any cause is of `kind`.
    pub fn has_kind(&self, kind: ErrorKind) -> bool {
        self.chain().any(|e| e.kind == kind)
    }

    /// The first error of `kind` in the chain.
    pub fn find(&self, kind: ErrorKind) -> Option<&Error> {
        self.chain().find(|e| e.kind == kind)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// The message a JDK socket exception carries for an I/O error (`ConnectException`, `UnknownHostException`, …).
pub fn io_message(e: &std::io::Error, host: &str) -> String {
    use std::io::ErrorKind as K;
    match e.kind() {
        K::ConnectionRefused => "Connection refused".into(),
        K::TimedOut => "Connect timed out".into(),
        K::ConnectionReset => "Connection reset".into(),
        K::NotFound => host.to_string(),
        _ if e.to_string().contains("failed to lookup address") || e.to_string().contains("nodename nor servname") => host.to_string(),
        _ => e.to_string(),
    }
}

pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The runtime a server's broker connections, poll loops and publishing schedules run on, apart from the server's
/// own, so a control-plane request can wait for a broker the way upstream's blocking clients make it wait. Made on
/// first use; dropping it shuts it down without waiting for its tasks.
#[derive(Default)]
pub struct BrokerRuntime {
    runtime: std::sync::OnceLock<tokio::runtime::Runtime>,
}

impl BrokerRuntime {
    fn get(&self) -> &tokio::runtime::Runtime {
        self.runtime.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("async-broker").enable_all().build().expect("broker runtime")
        })
    }

    /// Runs `future` on the broker runtime and waits for it on this thread; a task that panicked is an error.
    pub fn block<F>(&self, future: F) -> Result<F::Output, Error>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let task = self.get().spawn(future);
        let (tx, rx) = std::sync::mpsc::channel();
        self.get().spawn(async move {
            let _ = tx.send(task.await);
        });
        // On a server's multi-threaded runtime the worker hands its queued tasks over first, so the server keeps
        // answering while it waits (a Schema Registry mocked by the same server, say). On a current-thread
        // runtime the thread just waits: the future runs on the broker runtime, not this one.
        let multi_thread = tokio::runtime::Handle::try_current().is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
        let received = if multi_thread { tokio::task::block_in_place(|| rx.recv()) } else { rx.recv() };
        match received {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(e)) if e.is_panic() => Err(Error::new("broker task panicked")),
            _ => Err(Error::new("broker task was cancelled")),
        }
    }

    /// Runs `future` on the broker runtime and waits for it from async code, up to `limit`.
    pub async fn run<F>(&self, limit: std::time::Duration, future: F) -> Result<F::Output, Error>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let mut task = self.get().spawn(future);
        match tokio::time::timeout(limit, &mut task).await {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(e)) if e.is_panic() => Err(Error::new("broker task panicked")),
            Ok(Err(_)) => Err(Error::new("broker task was cancelled")),
            Err(_) => {
                task.abort();
                Err(Error::new(format!("broker task did not finish within {} ms", limit.as_millis())))
            }
        }
    }
}

impl Drop for BrokerRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// Starts a connection's background task (a poll loop, a sender, a schedule) on the runtime the adapter runs on:
/// the owning server's broker runtime, or a test's.
pub fn spawn<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future)
}

/// Waits up to `limit` for a background task, then aborts it.
pub async fn join_or_abort(task: Option<tokio::task::JoinHandle<()>>, limit: std::time::Duration) {
    if let Some(mut task) = task && tokio::time::timeout(limit, &mut task).await.is_err() {
        task.abort();
    }
}

/// `PublishOptions`: a Kafka key, MQTT QoS and retain flag, and headers (correlation ids).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PublishOptions {
    pub key: Option<String>,
    pub qos: Option<u8>,
    pub retain: Option<bool>,
    pub headers: Vec<(String, String)>,
}

impl PublishOptions {
    /// `new PublishOptions(key, qos, retain, headers)`: a QoS other than 0, 1 or 2 is refused
    /// (`IllegalArgumentException`); the headers are copied, in order.
    pub fn new(key: Option<&str>, qos: Option<i32>, retain: Option<bool>, headers: &[(&str, &str)]) -> Result<Self, Error> {
        let qos = match qos {
            Some(q) if !(0..=2).contains(&q) => return Err(Error::illegal(format!("MQTT QoS must be 0, 1, or 2; got: {q}"))),
            q => q.map(|q| q as u8),
        };
        Ok(PublishOptions { key: key.map(str::to_string), qos, retain, ..PublishOptions::with_headers(headers) })
    }

    pub fn none() -> Self {
        PublishOptions::default()
    }

    pub fn with_headers(headers: &[(&str, &str)]) -> Self {
        PublishOptions { headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), ..PublishOptions::default() }
    }

    /// `isEmpty`: no key, QoS, retain flag or header.
    pub fn is_empty(&self) -> bool {
        self.key.is_none() && self.qos.is_none() && self.retain.is_none() && self.headers.is_empty()
    }
}

/// `toString`: `PublishOptions{key=…, qos=…, retain=…, headers={name=value, …}}`, `null` for what is not set.
impl std::fmt::Display for PublishOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn or_null(v: Option<String>) -> String {
            v.unwrap_or_else(|| "null".into())
        }
        let headers = self.headers.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ");
        write!(
            f,
            "PublishOptions{{key={}, qos={}, retain={}, headers={{{headers}}}}}",
            or_null(self.key.clone()),
            or_null(self.qos.map(|q| q.to_string())),
            or_null(self.retain.map(|r| r.to_string()))
        )
    }
}

/// `MessagePublisher`: a broker adapter's publishing side.
pub trait Publisher: Send + Sync {
    /// `publish(channel, payload, options)`.
    fn publish<'a>(&'a self, channel: &'a str, payload: &'a str, options: &'a PublishOptions) -> BoxFuture<'a, Result<(), Error>>;

    /// `flush`: waits until the broker has acknowledged every send (only Kafka sends asynchronously).
    fn flush(&self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async { Ok(()) })
    }

    fn close(&self) -> BoxFuture<'_, ()>;
}

/// `MessageSubscriber`: a broker adapter's consuming side, recording what arrives per channel.
pub trait Subscriber: Send + Sync {
    fn subscribe<'a>(&'a self, channel: &'a str) -> BoxFuture<'a, Result<(), Error>>;

    /// `getRecordedMessages(channel)`.
    fn recorded(&self, channel: &str) -> Vec<ConsumedMessage>;

    /// `getAllRecordedMessages`.
    fn all_recorded(&self) -> Vec<ConsumedMessage>;

    fn close(&self) -> BoxFuture<'_, ()>;
}

/// `Metrics.incrementAsyncMessagePublished` / `…Consumed`: the counts of the server that loaded the spec, when its
/// metrics are enabled.
#[derive(Clone, Default)]
pub struct Counters(pub Option<std::sync::Arc<crate::metrics::Metrics>>);

impl Counters {
    pub fn published(&self, channel: &str) {
        if let Some(m) = &self.0 {
            m.async_message(true, channel);
        }
    }

    pub fn consumed(&self, channel: &str) {
        if let Some(m) = &self.0 {
            m.async_message(false, channel);
        }
    }
}

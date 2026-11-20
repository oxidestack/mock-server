//! Console logging: which events reach the console is decided as MockServer decides it, and how a line
//! looks is Rust-native. Every console line is a [`tracing`] event; the `mock-server` binary installs the one
//! subscriber ([`install_console`]), a plain-text `tracing-subscriber` formatter on **stdout** (the oracle prints
//! nothing of its own on stderr either):
//!
//! ```text
//! 2026-10-12T14:01:00.123456Z  INFO mock_server::server: port=1080 started on port: 1080
//! ```
//!
//! The event log (`retrieve?type=LOGS`/`LOG_ENTRIES`, the dashboard) is a separate sink and stays oracle-identical;
//! the console need not match the oracle's `java.util.logging` text (user decision, 2026-10-11). The messages are
//! still the oracle's, so a line a consumer waits for (Testcontainers' `.*started on port: 1080.*`) is still there.
//!
//! **Which events.** `logLevel` and `logLevelOverrides` apply as `MockServerLogger.writeToSystemOut`
//! applies them: an event is admitted at the global level first (`logEvent`; request lifecycle types always pass),
//! then written only if its level reaches the effective level, which is the override for its type, else for its
//! category, else the global level. Call sites that know the entry's type use the `*_as` functions; the plain
//! `info`/`warn`/`error` stand for an entry of no type of its own (`INFO`/`WARN`/`ERROR`, category `GENERAL`).
//! `disableLogging` (system property or environment at startup; a later `PUT /mockserver/configuration`
//! changes nothing) drops every event, `alwaysLog` notices included, but not a plain SLF4J line like `AsyncAPI
//! control-plane registered`; `disableSystemOut` (any tier, read once as the server starts) drops everything after the
//! `ConfigurationProperties` notices. `compactLogFormat` prints an entry's compact message.
//!
//! **Targets.** The event's target is its `logLevelOverrides` category: `mock_server::general`, `::matching`,
//! `::request_lifecycle`, `::expectation_management`, `::verification`, `::server`, and `::cluster` for the clustered
//! backend's own lines. The event's level is the SLF4J level (`TRACE` .. `ERROR`); the server's first port is the
//! `port` field (none before the server listens, or for an entry upstream prints without one). `RUST_LOG`, read once
//! as the binary starts, filters on top of all that with `target=level` directives (e.g.
//! `RUST_LOG=mock_server=info,mock_server::matching=off`); unset, every event that passed `logLevel` is printed.
//!
//! **Writer.** The formatter hands each line to a writer thread ([`Writer`]), so a request worker does not
//! wait on stdout; the binary flushes that thread before it prints anything itself and before it exits, `SIGTERM`
//! included. A library user's `Server` installs no subscriber: its events go to whatever subscriber the application
//! set, or nowhere.

use crate::config::Config;
use crate::recorded::{Kind, Level, LogEntry};
use crate::state::State;

/// `disableLogging` as `writeToSystemOut` reads it (see the module doc).
fn logging_disabled(config: &Config) -> bool {
    config.property_outside_file("disableLogging").is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
}

/// `compactLogFormat` as `writeToSystemOut` reads it: like `disableLogging`, from the system property or the environment
/// as the server started. `alwaysLog` notices and messages without arguments print as they are.
pub fn compact_enabled(config: &Config) -> bool {
    config.property_outside_file("compactLogFormat").is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
}

/// `disableSystemOut`: the console handler is gone (see the module doc).
pub fn system_out_disabled(config: &Config) -> bool {
    config.bool_startup_property("disableSystemOut", false)
}

/// `org.slf4j.event.Level.toInt`.
fn level_int(level: Level) -> i32 {
    match level {
        Level::Trace => 0,
        Level::Debug => 10,
        Level::Info => 20,
        Level::Warn => 30,
        Level::Error => 40,
    }
}

/// The globally configured level; `None` for `OFF`, which `MockServerLogger.isEnabled` treats as no level at all.
fn global_level(name: &str) -> Option<i32> {
    Some(match name {
        "OFF" => return None,
        "TRACE" => 0,
        "DEBUG" => 10,
        "WARN" => 30,
        "ERROR" => 40,
        _ => 20,
    })
}

/// `LogMessageTypeCategory.categoryFor`.
fn category(kind: Kind) -> &'static str {
    match kind {
        Kind::ExpectationMatched | Kind::ExpectationNotMatched | Kind::NoMatchResponse => "MATCHING",
        Kind::ReceivedRequest | Kind::ForwardedRequest | Kind::ExpectationResponse | Kind::TemplateGenerated | Kind::TemplateGenerationFailed => "REQUEST_LIFECYCLE",
        Kind::CreatedExpectation | Kind::UpdatedExpectation | Kind::RemovedExpectation | Kind::Cleared => "EXPECTATION_MANAGEMENT",
        Kind::Verification | Kind::VerificationFailed | Kind::VerificationPassed | Kind::Retrieved => "VERIFICATION",
        Kind::ServerConfiguration | Kind::AuthenticationFailed | Kind::OpenapiRequestValidationFailed | Kind::OpenapiResponseValidationFailed => "SERVER",
        Kind::Trace | Kind::Debug | Kind::Info | Kind::Warn | Kind::Error | Kind::Exception => "GENERAL",
    }
}

/// `LogEntry.LogMessageTypeCategory.resolveEffectiveLevel`: the `logLevelOverrides` entry for the type, else for its
/// category, else the global level. Keys are upper-cased; a value that is not an SLF4J level name (`TRACE`, `DEBUG`,
/// `INFO`, `WARN`, `ERROR`, any case; not `OFF`, not `WARNING`) drops its entry.
fn effective_level(config: &Config, global_name: &str, kind: Kind) -> Option<i32> {
    let global = global_level(global_name);
    let Some(text) = config.property_outside_file("logLevelOverrides").filter(|t| !t.trim().is_empty()) else { return global };
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(&text) else { return global };
    let find = |name: &str| {
        map.iter().filter(|(key, _)| key.to_ascii_uppercase() == name).find_map(|(_, value)| {
            Some(match value.as_str()?.to_ascii_uppercase().as_str() {
                "TRACE" => 0,
                "DEBUG" => 10,
                "INFO" => 20,
                "WARN" => 30,
                "ERROR" => 40,
                _ => return None,
            })
        })
    };
    find(kind.name()).or_else(|| find(category(kind))).map_or(global, Some)
}

/// Whether an event of `level` and `kind` reaches the console: `MockServerLogger.logEvent` admits it at the global
/// level (request lifecycle entries always pass), then `writeToSystemOut` compares it with the effective level.
fn console_enabled(config: &Config, global_name: &str, level: Level, kind: Kind) -> bool {
    let at = level_int(level);
    let admitted = matches!(kind, Kind::ReceivedRequest | Kind::ForwardedRequest | Kind::ExpectationResponse) || global_level(global_name).is_some_and(|g| at >= g);
    admitted && effective_level(config, global_name, kind).is_some_and(|e| at >= e)
}

/// The console target of an event of `kind`: its `logLevelOverrides` category (see the module doc).
#[derive(Clone, Copy)]
enum Target {
    General,
    Matching,
    RequestLifecycle,
    ExpectationManagement,
    Verification,
    Server,
    Cluster,
}

fn target(kind: Kind) -> Target {
    match category(kind) {
        "MATCHING" => Target::Matching,
        "REQUEST_LIFECYCLE" => Target::RequestLifecycle,
        "EXPECTATION_MANAGEMENT" => Target::ExpectationManagement,
        "VERIFICATION" => Target::Verification,
        "SERVER" => Target::Server,
        _ => Target::General,
    }
}

/// One `tracing` event per level for a target: the target and level of an event are static at its call site.
macro_rules! event_at {
    ($target:literal, $level:expr, $port:expr, $message:expr) => {
        match $level {
            Level::Trace => tracing::event!(target: $target, tracing::Level::TRACE, port = $port, message = %$message),
            Level::Debug => tracing::event!(target: $target, tracing::Level::DEBUG, port = $port, message = %$message),
            Level::Info => tracing::event!(target: $target, tracing::Level::INFO, port = $port, message = %$message),
            Level::Warn => tracing::event!(target: $target, tracing::Level::WARN, port = $port, message = %$message),
            Level::Error => tracing::event!(target: $target, tracing::Level::ERROR, port = $port, message = %$message),
        }
    };
}

/// One console line: a `tracing` event at `level` on `target`, with the server's `port` when it has one.
fn event(level: Level, target: Target, port: Option<u16>, message: &str) {
    match target {
        Target::General => event_at!("mock_server::general", level, port, message),
        Target::Matching => event_at!("mock_server::matching", level, port, message),
        Target::RequestLifecycle => event_at!("mock_server::request_lifecycle", level, port, message),
        Target::ExpectationManagement => event_at!("mock_server::expectation_management", level, port, message),
        Target::Verification => event_at!("mock_server::verification", level, port, message),
        Target::Server => event_at!("mock_server::server", level, port, message),
        Target::Cluster => event_at!("mock_server::cluster", level, port, message),
    }
}

/// The lines `ConfigurationProperties.<clinit>` logs with `alwaysLog`: the log level and
/// `logLevelOverrides` do not apply to them (what `Config` decided to log is decided there, see `crate::property_file`),
/// there is no port, and a throwable follows the message on the lines after it.
pub fn startup_notices(config: &Config) {
    if logging_disabled(config) {
        return;
    }
    for notice in config.startup_notices() {
        match &notice.throwable {
            Some(throwable) => event(notice.level, Target::Server, None, &format!("{}\n{throwable}", notice.message)),
            None => event(notice.level, Target::Server, None, &notice.message),
        }
    }
}

/// One console line of `Main`, which logs before any server is listening: no port, so no [`State`]. The event is
/// subject to the global level (`global`, which `Main` reads before the command line applies its own) and
/// `logLevelOverrides` exactly like a server's.
pub fn startup_line(config: &Config, global: &str, level: Level, kind: Kind, message: &str) {
    if console_enabled(config, global, level, kind) && !logging_disabled(config) && !system_out_disabled(config) {
        event(level, target(kind), None, message);
    }
}

/// An ERROR line of a command that starts no server (`mockserver import`), under no configuration of its own.
pub fn command_error(message: &str) {
    event(Level::Error, Target::General, None, message);
}

/// Writes one console line (see the module doc) if `level` and `kind` reach it. A line of an entry with no port
/// (`portless`: the entry says so, or it is logged while the server is still starting) carries none, as
/// `MockServerLogger.portInformation` writes nothing for it.
/// Whether [`emit`] would print an entry of `level` and `kind`: asked first by a caller that has a line to build.
pub fn console_wanted(state: &State, level: Level, kind: Kind) -> bool {
    console_enabled(&state.config, &state.log_level, level, kind) && !logging_disabled(&state.config) && !system_out_disabled(&state.config)
}

fn emit(state: &State, level: Level, kind: Kind, message: &str, portless: bool) {
    if !console_wanted(state, level, kind) {
        return;
    }
    event(level, target(kind), if portless { None } else { Some(state.first_port()) }, message);
}

/// [`info_as`] with a throwable: `java.util.logging` prints the stack trace on the lines after the message.
pub fn info_with_throwable(state: &State, kind: Kind, message: &str, trace: &str) {
    emit(state, Level::Info, kind, &format!("{message}\n{trace}"), crate::recorded::in_portless_scope());
}

/// The console line of an ERROR `entry` with its throwable's `trace` after it. Under `redactSecretsInLog` both are
/// redacted against the entry's credential values and those of `about`, the request the event log attaches to it when
/// the entry has none of its own (`MockServerLogger.writeToSystemOut` prints `LogEntry.redactedView`, whose throwable is
/// a `RedactedThrowable`: upstream c76143e4a). Under `compactLogFormat` the message is the compact one.
pub fn error_with_throwable(state: &State, entry: &LogEntry, about: Option<&crate::request::HttpRequest>, trace: &str) {
    entry_with_throwable(state, Level::Error, entry, about, trace);
}

/// [`error_with_throwable`] at `level`.
pub fn entry_with_throwable(state: &State, level: Level, entry: &LogEntry, about: Option<&crate::request::HttpRequest>, trace: &str) {
    let (message, trace) = shown_with(state, entry, about, trace);
    emit(state, level, entry.kind, &format!("{message}\n{trace}"), entry.portless || crate::recorded::in_portless_scope());
}

/// `entry`'s message and `text` (a throwable's trace, an exception's message printed with it) as the console shows
/// them: under `redactSecretsInLog`, redacted and scrubbed of the credential values of the entry and of `about`, the
/// request it is about when it has none attached yet.
pub fn redacted_with(state: &State, entry: &LogEntry, about: Option<&crate::request::HttpRequest>, text: &str) -> (String, String) {
    let Some(fields) = crate::recorded::redact_fields(&state.config) else { return (entry.message_text().to_string(), text.to_string()) };
    let attached;
    let entry = match about {
        Some(request) if entry.requests.is_none() => {
            attached = entry.clone().request(request);
            &attached
        }
        _ => entry,
    };
    let shown = entry.redacted(&fields);
    let text = shown.redaction.as_ref().map_or_else(|| text.to_string(), |r| r.scrub(text));
    (shown.message_text().to_string(), text)
}

/// A throwable's console text without its frames, which cannot be reproduced: `<class>: <message>` and a
/// `Caused by: <class>: <message>` line for each cause, `classes` naming the chain from the outermost.
pub fn throwable_text(classes: &[&str], bean: &serde_json::Value) -> String {
    let mut lines = Vec::new();
    let mut at = Some(bean);
    for class in classes {
        let Some(throwable) = at else { break };
        let prefix = if lines.is_empty() { "" } else { "Caused by: " };
        match throwable.get("message").and_then(serde_json::Value::as_str) {
            Some(message) => lines.push(format!("{prefix}{class}: {message}")),
            None => lines.push(format!("{prefix}{class}")),
        }
        at = throwable.get("cause");
    }
    lines.join("\n")
}

/// Whether DEBUG events are logged.
pub fn debug_enabled(state: &State) -> bool {
    matches!(state.log_level.as_str(), "DEBUG" | "TRACE")
}

/// Whether ERROR events are logged.
pub fn error_enabled(state: &State) -> bool {
    state.log_level.as_str() != "OFF"
}

/// An ERROR event without a request: on the console and in the event log (an entry of no type of its own is ERROR).
pub fn error_event(state: &State, entry: LogEntry) {
    if !error_enabled(state) {
        return;
    }
    let shown = redacted(state, &entry);
    log_entry(state, Level::Error, shown.kind, shown.message_text(), &|| shown.compact_text(), shown.portless || crate::recorded::in_portless_scope());
    let entry = if entry.kind == Kind::Info { entry.kind(Kind::Error) } else { entry };
    state.log.message(entry.level(Level::Error));
}

/// An INFO console line of an entry that sets no type (`INFO`, category `GENERAL`).
pub fn info(state: &State, message: &str) {
    info_as(state, Kind::Info, message);
}

/// An INFO console line of an entry of type `kind`, which `logLevelOverrides` can address by type or category.
pub fn info_as(state: &State, kind: Kind, message: &str) {
    emit(state, Level::Info, kind, message, crate::recorded::in_portless_scope());
}

/// An INFO line written straight to `java.util.logging` by an SLF4J logger (`LOG.info(...)`, e.g. `AsyncAPI
/// control-plane registered`): no port, no type, so only the global level governs it and `logLevelOverrides` does not.
pub fn info_plain(state: &State, message: &str) {
    if global_level(&state.log_level).is_some_and(|g| g <= level_int(Level::Info)) && !system_out_disabled(&state.config) {
        event(Level::Info, Target::General, None, message);
    }
}

/// [`info_plain`] at WARN, printed `WARNING` (`LlmCostBudgetMonitor`'s `LOG.warn`).
pub fn warn_plain(state: &State, message: &str) {
    if global_level(&state.log_level).is_some_and(|g| g <= level_int(Level::Warn)) && !system_out_disabled(&state.config) {
        event(Level::Warn, Target::General, None, message);
    }
}

/// The `org.mockserver` logger of `java.util.logging` as the last server configured it (`MockServerLogger.configureLogger`
/// writes a process-wide configuration): the global level and whether the console handler is installed. `None` until
/// a server starts.
static JAVA_LOGGER: parking_lot::RwLock<Option<(String, bool)>> = parking_lot::RwLock::new(None);

/// Records `state`'s console settings as the process's `java.util.logging` configuration (see [`JAVA_LOGGER`]).
pub(crate) fn configure_java_logger(state: &State) {
    *JAVA_LOGGER.write() = Some((state.log_level.clone(), system_out_disabled(&state.config)));
}

/// [`warn_plain`] from code that runs with no server at hand (an SLF4J `LOGGER.warn` of a static helper, e.g.
/// `SensitiveValueMatcher`'s): under the process's `java.util.logging` configuration, nothing before a server starts.
pub(crate) fn java_logger_warn(message: &str) {
    let Some((level, system_out_disabled)) = JAVA_LOGGER.read().clone() else { return };
    if global_level(&level).is_some_and(|g| g <= level_int(Level::Warn)) && !system_out_disabled {
        event(Level::Warn, Target::General, None, message);
    }
}

/// [`info`] at WARN (printed `WARNING`).
pub fn warn(state: &State, message: &str) {
    warn_as(state, Kind::Warn, message);
}

/// [`info_as`] at WARN.
pub fn warn_as(state: &State, kind: Kind, message: &str) {
    emit(state, Level::Warn, kind, message, crate::recorded::in_portless_scope());
}

/// An INFO event without a request: on the console and, like upstream's `logEvent`, in the event log.
pub fn info_event(state: &State, message: impl Into<LogEntry>) {
    if !state.info_enabled() {
        return;
    }
    let entry = message.into();
    let shown = redacted(state, &entry);
    log_entry(state, Level::Info, shown.kind, shown.message_text(), &|| shown.compact_text(), shown.portless || crate::recorded::in_portless_scope());
    state.log.message(entry);
}

/// [`info_event`] about `request` (`setHttpRequest(request)`): a log clear or retrieve filtered by a request matcher
/// finds it by that request, and one filtered by another request leaves it out.
pub fn info_event_about(state: &State, entry: LogEntry, request: &crate::request::HttpRequest) {
    if !state.info_enabled() {
        return;
    }
    let shown = redacted(state, &entry);
    log_entry(state, Level::Info, shown.kind, shown.message_text(), &|| shown.compact_text(), shown.portless || crate::recorded::in_portless_scope());
    state.log.message_about(entry, crate::recorded::Subject::Request(std::sync::Arc::new(request.clone())));
}

/// [`info_event`] at WARN.
pub fn warn_event(state: &State, message: impl Into<LogEntry>) {
    if matches!(state.log_level.as_str(), "OFF" | "ERROR") {
        return;
    }
    let entry = message.into();
    let shown = redacted(state, &entry);
    log_entry(state, Level::Warn, shown.kind, shown.message_text(), &|| shown.compact_text(), shown.portless || crate::recorded::in_portless_scope());
    let entry = if entry.kind == Kind::Info { entry.kind(Kind::Warn) } else { entry };
    state.log.message(entry.level(Level::Warn));
}

/// [`warn_event`] about `request` (`setHttpRequest(request)`): a log clear or retrieve filtered by a request matcher
/// finds it by that request.
pub fn warn_event_about(state: &State, entry: LogEntry, request: &crate::request::HttpRequest) {
    if matches!(state.log_level.as_str(), "OFF" | "ERROR") {
        return;
    }
    let shown = redacted(state, &entry);
    log_entry(state, Level::Warn, shown.kind, shown.message_text(), &|| shown.compact_text(), shown.portless || crate::recorded::in_portless_scope());
    let entry = if entry.kind == Kind::Info { entry.kind(Kind::Warn) } else { entry };
    state.log.message_about(entry.level(Level::Warn), crate::recorded::Subject::Request(std::sync::Arc::new(request.clone())));
}

/// [`info`] at ERROR (printed `SEVERE`).
pub fn error(state: &State, message: &str) {
    error_as(state, Kind::Error, message);
}

/// [`info_as`] at ERROR.
pub fn error_as(state: &State, kind: Kind, message: &str) {
    emit(state, Level::Error, kind, message, crate::recorded::in_portless_scope());
}

/// One entry the event log recorded, written to the console at its level: the log calls this for the
/// types the oracle prints on receipt, completion, verification, retrieval and clearing. Under `compactLogFormat` the
/// line is `compact` (`LogEntry.getCompactMessage`) instead of the message.
pub fn log_entry(state: &State, level: Level, kind: Kind, message: &str, compact: &dyn Fn() -> String, portless: bool) {
    if compact_enabled(&state.config) {
        emit(state, level, kind, &compact(), portless);
    } else {
        emit(state, level, kind, message, portless);
    }
}

/// The console line of an entry its call site prints (not the event log): its message, or its compact message.
pub fn entry(state: &State, entry: &LogEntry) {
    entry_as(state, entry.level, entry);
}

/// [`entry`] at `level`, for a call site that decides the level itself.
pub fn entry_as(state: &State, level: Level, entry: &LogEntry) {
    let entry = redacted(state, entry);
    log_entry(state, level, entry.kind, entry.message_text(), &|| entry.compact_text(), entry.portless || crate::recorded::in_portless_scope());
}

/// [`redacted_with`], the message being the compact message under `compactLogFormat` (`writeToSystemOut` prints
/// `getCompactMessage` whatever follows it).
pub fn shown_with(state: &State, entry: &LogEntry, about: Option<&crate::request::HttpRequest>, text: &str) -> (String, String) {
    if !compact_enabled(&state.config) {
        return redacted_with(state, entry, about, text);
    }
    let Some(fields) = crate::recorded::redact_fields(&state.config) else { return (entry.compact_text(), text.to_string()) };
    let attached;
    let entry = match about {
        Some(request) if entry.requests.is_none() => {
            attached = entry.clone().request(request);
            &attached
        }
        _ => entry,
    };
    let shown = entry.redacted(&fields);
    let text = shown.redaction.as_ref().map_or_else(|| text.to_string(), |r| r.scrub(text));
    (shown.compact_text(), text)
}

/// `entry` as the console shows it: redacted under `redactSecretsInLog` (upstream c76143e4a).
pub fn redacted<'a>(state: &State, entry: &'a LogEntry) -> std::borrow::Cow<'a, LogEntry> {
    match crate::recorded::redact_fields(&state.config) {
        Some(fields) => std::borrow::Cow::Owned(entry.redacted(&fields)),
        None => std::borrow::Cow::Borrowed(entry),
    }
}

/// How many console lines may wait for the writer thread before a caller blocks until there is room: the backpressure
/// a synchronous write to a slow stdout gave.
const WRITER_BACKLOG: usize = 4096;

/// How much text the writer thread gathers from the queue for one write.
const WRITER_BATCH: usize = 1 << 20;

/// How long the writer thread sleeps when it finds the queue empty, and how many empty looks in a row it takes before
/// it blocks on the queue instead (an idle server).
const WRITER_POLL: std::time::Duration = std::time::Duration::from_millis(1);
const WRITER_IDLE_POLLS: u32 = 100;

/// The console writer thread of a `mock-server` process ([`install_console`]): callers send their line through
/// `lines` (a bounded lock-free queue) and return; the thread writes what it finds queued in one `write_all`.
///
/// While lines keep coming the thread polls the queue and sleeps between looks rather than blocking on it: a receiver
/// blocked on a `std::sync::mpsc` channel makes every send lock the channel's waker mutex and signal the thread, which
/// serialised the request workers on that mutex. It blocks only once the queue stayed empty for
/// [`WRITER_IDLE_POLLS`] looks, so an idle server does not wake it.
struct Writer {
    lines: std::sync::mpsc::SyncSender<String>,
    /// Lines sent, and lines written (behind the lock [`flush_console`] waits on).
    queued: std::sync::atomic::AtomicU64,
    written: parking_lot::Mutex<u64>,
    done: parking_lot::Condvar,
}

static WRITER: std::sync::OnceLock<Writer> = std::sync::OnceLock::new();

impl Writer {
    fn run(&self, lines: std::sync::mpsc::Receiver<String>) {
        use std::io::Write;
        use std::sync::mpsc::TryRecvError;
        let mut batch = String::with_capacity(WRITER_BATCH);
        let mut idle = 0;
        loop {
            let line = match lines.try_recv() {
                Ok(line) => line,
                Err(TryRecvError::Empty) if idle < WRITER_IDLE_POLLS => {
                    idle += 1;
                    std::thread::sleep(WRITER_POLL);
                    continue;
                }
                Err(TryRecvError::Empty) => match lines.recv() {
                    Ok(line) => line,
                    Err(_) => return,
                },
                Err(TryRecvError::Disconnected) => return,
            };
            idle = 0;
            batch.clear();
            batch.push_str(&line);
            let mut count = 1;
            while batch.len() < WRITER_BATCH {
                let Ok(line) = lines.try_recv() else { break };
                batch.push_str(&line);
                count += 1;
            }
            // a write error (stdout closed) drops the text, as the JVM's console handler does
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(batch.as_bytes()).and_then(|()| out.flush());
            drop(out);
            *self.written.lock() += count;
            self.done.notify_all();
        }
    }

    fn push(&self, line: String) {
        self.queued.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _ = self.lines.send(line);
    }

    fn flush(&self) {
        let target = self.queued.load(std::sync::atomic::Ordering::SeqCst);
        let mut written = self.written.lock();
        while *written < target {
            self.done.wait(&mut written);
        }
    }
}

/// Installs this process's console (see the module doc): a global `tracing` subscriber that formats each
/// event as one plain-text line (no ANSI colours: the console is read through `docker logs` and log collectors) and
/// hands it to a dedicated writer thread, so a request worker never waits on stdout; [`flush_console`]
/// waits for what is queued. `RUST_LOG` (`target=level` directives) filters the events; unset, every event of this
/// crate passes, and other crates' events are off. Only the `mock-server` binary calls it: a library user's
/// `Server` installs no subscriber. A second call changes nothing.
pub fn install_console() {
    use tracing_subscriber::layer::SubscriberExt;
    let mut receiver = None;
    let writer = WRITER.get_or_init(|| {
        let (lines, rx) = std::sync::mpsc::sync_channel(WRITER_BACKLOG);
        receiver = Some(rx);
        Writer { lines, queued: Default::default(), written: parking_lot::Mutex::new(0), done: parking_lot::Condvar::new() }
    });
    let Some(rx) = receiver else { return };
    std::thread::Builder::new().name("console".into()).spawn(move || writer.run(rx)).expect("console writer thread");
    let layer = tracing_subscriber::fmt::layer().with_ansi(false).with_writer(|| ConsoleWriter);
    let subscriber = tracing_subscriber::registry().with(tracing_subscriber::Layer::with_filter(layer, console_filter(std::env::var("RUST_LOG").ok().as_deref())));
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// The console's filter from `RUST_LOG`: its `target=level` directives (`tracing_subscriber::filter::Targets`), or every
/// event of this crate when it is unset, empty or does not parse.
fn console_filter(rust_log: Option<&str>) -> tracing_subscriber::filter::Targets {
    let everything = || tracing_subscriber::filter::Targets::new().with_target("mock_server", tracing::Level::TRACE);
    match rust_log.map(str::trim).filter(|v| !v.is_empty()) {
        Some(directives) => directives.parse().unwrap_or_else(|_| everything()),
        None => everything(),
    }
}

/// What the formatter writes one event through: the formatted line, in one piece, onto the writer thread's queue.
struct ConsoleWriter;

impl std::io::Write for ConsoleWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(writer) = WRITER.get() {
            writer.push(String::from_utf8_lossy(buf).into_owned());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Returns once every console line queued so far is written to stdout (nothing to wait for without the writer
/// thread). The binary calls it before it prints to stdout itself, and before it exits.
pub fn flush_console() {
    if let Some(writer) = WRITER.get() {
        writer.flush();
    }
}

/// A line some other component writes to the console (the cluster backend's Infinispan lines): an INFO event of
/// its own target.
pub(crate) fn console_line(line: &str) {
    event(Level::Info, Target::Cluster, None, line);
}

#[cfg(test)]
mod tests {
    use super::console_filter;
    use tracing::Level;

    /// Unset or empty, `RUST_LOG` passes every event of this crate and none of another; set, its
    /// `target=level` directives decide, the most specific target first; one that does not parse is ignored.
    #[test]
    fn rust_log_filters_the_console_targets() {
        for unset in [None, Some(""), Some("  "), Some("mock_server=bogus")] {
            let filter = console_filter(unset);
            assert!(filter.would_enable("mock_server::matching", &Level::TRACE), "{unset:?}");
            assert!(!filter.would_enable("hyper", &Level::ERROR), "{unset:?}");
        }
        let filter = console_filter(Some("mock_server=info,mock_server::matching=off"));
        assert!(filter.would_enable("mock_server::server", &Level::INFO));
        assert!(!filter.would_enable("mock_server::server", &Level::DEBUG));
        assert!(!filter.would_enable("mock_server::matching", &Level::ERROR));
        assert!(console_filter(Some("warn")).would_enable("mock_server::general", &Level::WARN));
        assert!(!console_filter(Some("warn")).would_enable("mock_server::general", &Level::INFO));
    }
}

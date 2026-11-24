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
//! **Writer.** In the binary ([`install_console`]) a line of this module does not go through the `tracing`
//! formatter: it is written in that format straight into a buffer its thread reuses (the message rendered there, not
//! kept on the entry) and copied onto the queue of a writer thread ([`Console`]), so a request worker never waits on
//! stdout. When stdout does not keep up and the queue is full, a line is dropped and counted rather than waited for,
//! as the oracle drops events when its ring buffer is full: the writer prints how many after its next write, and
//! `process_console_lines_dropped_total` counts them all. The binary flushes the writer before it prints anything
//! itself and before it exits, `SIGTERM` included. A library user's `Server` installs no console: its events go to
//! whatever `tracing` subscriber the application set, or nowhere.

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

impl Target {
    const ALL: [Target; 7] = [Target::General, Target::Matching, Target::RequestLifecycle, Target::ExpectationManagement, Target::Verification, Target::Server, Target::Cluster];

    fn name(self) -> &'static str {
        match self {
            Target::General => "mock_server::general",
            Target::Matching => "mock_server::matching",
            Target::RequestLifecycle => "mock_server::request_lifecycle",
            Target::ExpectationManagement => "mock_server::expectation_management",
            Target::Verification => "mock_server::verification",
            Target::Server => "mock_server::server",
            Target::Cluster => "mock_server::cluster",
        }
    }
}

const LEVELS: [Level; 5] = [Level::Trace, Level::Debug, Level::Info, Level::Warn, Level::Error];

fn tracing_level(level: Level) -> tracing::Level {
    match level {
        Level::Trace => tracing::Level::TRACE,
        Level::Debug => tracing::Level::DEBUG,
        Level::Info => tracing::Level::INFO,
        Level::Warn => tracing::Level::WARN,
        Level::Error => tracing::Level::ERROR,
    }
}

/// A console message, written by the caller onto the end of the line (the first `String`) when the line is printed;
/// the second is a scratch buffer for an argument's text on the way. Nothing is rendered for a line no one prints.
pub type Text<'a> = &'a dyn Fn(&mut String, &mut String);

/// A [`Text`] as `Display`, for a `tracing` event: rendered only if a subscriber formats the event.
struct Lazy<'a>(Text<'a>);

impl std::fmt::Display for Lazy<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (mut message, mut scratch) = (String::new(), String::new());
        (self.0)(&mut message, &mut scratch);
        f.write_str(&message)
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

/// One console line at `level` on `target`, with the server's `port` when it has one.
fn event(level: Level, target: Target, port: Option<u16>, message: &str) {
    event_with(level, target, port, &|out, _| out.push_str(message));
}

/// [`event`] of a message written by `text`: straight onto the console when the binary installed it, else a
/// `tracing` event for whatever subscriber the application set.
fn event_with(level: Level, target: Target, port: Option<u16>, text: Text) {
    if let Some(console) = CONSOLE.get() {
        return console.line(level, target, port, text);
    }
    let message = Lazy(text);
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
    emit_with(state, level, kind, &|out, _| out.push_str(message), portless);
}

/// [`emit`] of a message written by `text`.
fn emit_with(state: &State, level: Level, kind: Kind, text: Text, portless: bool) {
    if !console_wanted(state, level, kind) {
        return;
    }
    event_with(level, target(kind), if portless { None } else { Some(state.first_port()) }, text);
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
    shown_entry(state, Level::Error, &shown);
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
    shown_entry(state, Level::Info, &shown);
    state.log.message(entry);
}

/// [`info_event`] about `request` (`setHttpRequest(request)`): a log clear or retrieve filtered by a request matcher
/// finds it by that request, and one filtered by another request leaves it out.
pub fn info_event_about(state: &State, entry: LogEntry, request: &crate::request::HttpRequest) {
    if !state.info_enabled() {
        return;
    }
    let shown = redacted(state, &entry);
    shown_entry(state, Level::Info, &shown);
    state.log.message_about(entry, crate::recorded::Subject::Request(std::sync::Arc::new(request.clone())));
}

/// [`info_event`] at WARN.
pub fn warn_event(state: &State, message: impl Into<LogEntry>) {
    if matches!(state.log_level.as_str(), "OFF" | "ERROR") {
        return;
    }
    let entry = message.into();
    let shown = redacted(state, &entry);
    shown_entry(state, Level::Warn, &shown);
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
    shown_entry(state, Level::Warn, &shown);
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
/// line is `compact` (`LogEntry.getCompactMessage`) instead of the message `text` writes.
pub fn log_entry(state: &State, level: Level, kind: Kind, text: Text, compact: &dyn Fn() -> String, portless: bool) {
    if compact_enabled(&state.config) {
        emit(state, level, kind, &compact(), portless);
    } else {
        emit_with(state, level, kind, text, portless);
    }
}

/// [`log_entry`] of `entry`'s own message ([`LogEntry::write_message`]: rendered onto the line, not kept on the entry).
fn shown_entry(state: &State, level: Level, entry: &LogEntry) {
    log_entry(state, level, entry.kind, &|out, scratch| entry.write_message(out, scratch), &|| entry.compact_text(), entry.portless || crate::recorded::in_portless_scope());
}

/// The console line of an entry its call site prints (not the event log): its message, or its compact message.
pub fn entry(state: &State, entry: &LogEntry) {
    entry_as(state, entry.level, entry);
}

/// [`entry`] at `level`, for a call site that decides the level itself.
pub fn entry_as(state: &State, level: Level, entry: &LogEntry) {
    shown_entry(state, level, &redacted(state, entry));
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

/// The most text the console's queue holds for the writer thread: a line that would take it past this is dropped and
/// counted (see the module doc). A line longer than this still goes onto an empty queue.
const CONSOLE_QUEUE: usize = 1 << 20;

/// What a thread's line buffer starts with, and the most it keeps between lines: the buffer of a longer line is let
/// go once the line is queued.
const LINE_START: usize = 16 << 10;
const LINE_KEPT: usize = 256 << 10;

/// How long the writer thread sleeps when it finds the queue empty, and how many empty looks in a row it takes before
/// it parks until a line comes instead (an idle server).
const WRITER_POLL: std::time::Duration = std::time::Duration::from_millis(1);
const WRITER_IDLE_POLLS: u32 = 100;

/// The console of a `mock-server` process ([`install_console`]): a thread formats its line into a buffer of its own
/// ([`format_line`]), copies it onto `queue` and returns; the writer thread ([`Console::run`]) swaps the queue's text
/// for an empty buffer of the same size and writes what it took in one `write_all`, so the lock is held for a copy at
/// most. A line that does not fit the queue is dropped, never waited for.
///
/// While lines keep coming the writer polls the queue and sleeps between looks rather than parking: a parked writer
/// makes every line signal it, and the signals serialised the request workers. It parks only once the queue stayed
/// empty for [`WRITER_IDLE_POLLS`] looks, so an idle server does not wake it.
pub(crate) struct Console {
    /// Which lines `RUST_LOG` lets through, by [`Target`] and [`LEVELS`] index.
    enabled: [[bool; 5]; 7],
    queue: parking_lot::Mutex<Queue>,
    /// Wakes a parked writer.
    wake: parking_lot::Condvar,
    /// Signalled after each write ([`flush_console`] waits on it).
    wrote: parking_lot::Condvar,
    /// Lines dropped since the process started, and those of them the console has not reported yet.
    dropped: std::sync::atomic::AtomicU64,
    unreported: std::sync::atomic::AtomicU64,
}

struct Queue {
    text: Vec<u8>,
    /// Lines queued since the process started, and of those, the lines written.
    queued: u64,
    written: u64,
    /// The writer is parked on `wake`.
    parked: bool,
}

static CONSOLE: std::sync::OnceLock<Console> = std::sync::OnceLock::new();

thread_local! {
    /// A thread's line buffer and the scratch buffer an argument's text is rendered into.
    static LINE: std::cell::RefCell<(String, String)> = const { std::cell::RefCell::new((String::new(), String::new())) };
}

fn level_index(level: Level) -> usize {
    match level {
        Level::Trace => 0,
        Level::Debug => 1,
        Level::Info => 2,
        Level::Warn => 3,
        Level::Error => 4,
    }
}

impl Console {
    fn new(filter: &tracing_subscriber::filter::Targets) -> Console {
        let mut enabled = [[false; 5]; 7];
        for target in Target::ALL {
            for level in LEVELS {
                enabled[target as usize][level_index(level)] = filter.would_enable(target.name(), &tracing_level(level));
            }
        }
        Console {
            enabled,
            queue: parking_lot::Mutex::new(Queue { text: Vec::with_capacity(CONSOLE_QUEUE), queued: 0, written: 0, parked: false }),
            wake: parking_lot::Condvar::new(),
            wrote: parking_lot::Condvar::new(),
            dropped: Default::default(),
            unreported: Default::default(),
        }
    }

    /// One line (see [`event_with`]), unless `RUST_LOG` filters it out.
    fn line(&self, level: Level, target: Target, port: Option<u16>, text: Text) {
        if !self.enabled[target as usize][level_index(level)] {
            return;
        }
        let now = std::time::SystemTime::now();
        LINE.with(|buffers| match buffers.try_borrow_mut() {
            Ok(mut buffers) => {
                let (line, scratch) = &mut *buffers;
                line.clear();
                line.reserve(LINE_START);
                format_line(line, scratch, now, level, target, port, text);
                self.push(line.as_bytes());
                for buffer in [line, scratch] {
                    if buffer.capacity() > LINE_KEPT {
                        *buffer = String::new();
                    }
                }
            }
            // a line written while this thread's buffer is in use (one rendered from inside another's message)
            Err(_) => {
                let (mut line, mut scratch) = (String::new(), String::new());
                format_line(&mut line, &mut scratch, now, level, target, port, text);
                self.push(line.as_bytes());
            }
        });
    }

    /// Queues `line` for the writer, or drops and counts it when the queue is full.
    fn push(&self, line: &[u8]) {
        let mut queue = self.queue.lock();
        if !queue.text.is_empty() && queue.text.len() + line.len() > CONSOLE_QUEUE {
            drop(queue);
            self.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.unreported.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        queue.text.extend_from_slice(line);
        queue.queued += 1;
        if queue.parked {
            queue.parked = false;
            self.wake.notify_one();
        }
    }

    /// Swaps what is queued into `batch` (empty, of the queue's size), waiting for a line when there is none, and
    /// returns how many lines it took.
    fn take(&self, batch: &mut Vec<u8>) -> u64 {
        let mut idle = 0;
        loop {
            let mut queue = self.queue.lock();
            if !queue.text.is_empty() {
                std::mem::swap(&mut queue.text, batch);
                return queue.queued - queue.written;
            }
            if idle < WRITER_IDLE_POLLS {
                drop(queue);
                idle += 1;
                std::thread::sleep(WRITER_POLL);
            } else {
                queue.parked = true;
                self.wake.wait(&mut queue);
            }
        }
    }

    /// Appends to `batch` the line that reports the lines dropped since the last report, if any were.
    fn report_drops(&self, batch: &mut Vec<u8>) {
        let dropped = self.unreported.swap(0, std::sync::atomic::Ordering::Relaxed);
        if dropped == 0 || !self.enabled[Target::General as usize][level_index(Level::Warn)] {
            return;
        }
        let mut line = String::new();
        let text = |out: &mut String, _: &mut String| {
            use std::fmt::Write;
            let _ = write!(out, "{dropped} console lines dropped: stdout was not keeping up");
        };
        format_line(&mut line, &mut String::new(), std::time::SystemTime::now(), Level::Warn, Target::General, None, &text);
        batch.extend_from_slice(line.as_bytes());
    }

    /// The writer thread: takes what is queued, writes it with `write`, and counts its lines written.
    fn run(&self, mut write: impl FnMut(&[u8])) {
        let mut batch = Vec::with_capacity(CONSOLE_QUEUE);
        loop {
            let lines = self.take(&mut batch);
            self.report_drops(&mut batch);
            write(&batch);
            batch.clear();
            // a line longer than the queue grew this buffer: it goes back to the queue's size
            batch.shrink_to(CONSOLE_QUEUE);
            self.queue.lock().written += lines;
            self.wrote.notify_all();
        }
    }

    fn flush(&self) {
        let mut queue = self.queue.lock();
        let target = queue.queued;
        while queue.written < target {
            self.wrote.wait(&mut queue);
        }
    }
}

/// One console line onto `out`, in `tracing-subscriber`'s plain-text format (`2026-10-12T14:01:00.123456Z  INFO
/// mock_server::server: port=1080 started on port: 1080` and a line feed), with the control characters of the message
/// escaped as that formatter escapes them; `scratch` is lent to `text`.
fn format_line(out: &mut String, scratch: &mut String, now: std::time::SystemTime, level: Level, target: Target, port: Option<u16>, text: Text) {
    push_timestamp(out, now);
    out.push_str(match level {
        Level::Trace => " TRACE ",
        Level::Debug => " DEBUG ",
        Level::Info => "  INFO ",
        Level::Warn => "  WARN ",
        Level::Error => " ERROR ",
    });
    out.push_str(target.name());
    out.push_str(": ");
    if let Some(port) = port {
        out.push_str("port=");
        push_number(out, u32::from(port));
        out.push(' ');
    }
    let start = out.len();
    text(out, scratch);
    escape_controls(out, start, scratch);
    out.push('\n');
}

/// `n` in decimal.
fn push_number(out: &mut String, mut n: u32) {
    let mut digits = [0u8; 10];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.push_str(std::str::from_utf8(&digits[at..]).expect("ASCII digits"));
}

/// `now` as `tracing-subscriber`'s `SystemTime` timer writes it: UTC, `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
fn push_timestamp(out: &mut String, now: std::time::SystemTime) {
    let since = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let (seconds, micros) = (since.as_secs(), since.subsec_micros());
    let (days, of_day) = (seconds / 86_400, seconds % 86_400);
    // days since 1970-01-01 to a civil date (Howard Hinnant's `civil_from_days`)
    let z = days + 719_468;
    let (era, of_era) = (z / 146_097, z % 146_097);
    let year_of_era = (of_era - of_era / 1460 + of_era / 36_524 - of_era / 146_096) / 365;
    let day_of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    let mut text = *b"0000-00-00T00:00:00.000000Z";
    let mut put = |at: usize, width: usize, mut value: u64| {
        for i in (at..at + width).rev() {
            text[i] = b'0' + (value % 10) as u8;
            value /= 10;
        }
    };
    put(0, 4, year.min(9999));
    put(5, 2, month);
    put(8, 2, day);
    put(11, 2, of_day / 3600);
    put(14, 2, of_day / 60 % 60);
    put(17, 2, of_day % 60);
    put(20, 6, u64::from(micros));
    out.push_str(std::str::from_utf8(&text).expect("ASCII timestamp"));
}

/// The message from `start` on with ESC, BEL, BS, FF and DEL written `\x1b` .. and C1 controls `\u{85}` .., as
/// `tracing-subscriber` escapes a message against terminal injection. Most messages have none of them: those are only
/// scanned, 64 bytes at a time.
fn escape_controls(out: &mut String, start: usize, scratch: &mut String) {
    // 0xC2 leads the UTF-8 of every C1 control (U+0080 .. U+009F)
    let suspect = |b: u8| matches!(b, 0x1b | 0x07 | 0x08 | 0x0c | 0x7f | 0xc2);
    if !out.as_bytes()[start..].chunks(64).any(|chunk| chunk.iter().fold(false, |found, &b| found | suspect(b))) {
        return;
    }
    scratch.clear();
    scratch.push_str(&out[start..]);
    out.truncate(start);
    let bytes = scratch.as_bytes();
    let (mut from, mut at) = (0, 0);
    while at < bytes.len() {
        let escape: Option<(&str, usize)> = match (bytes[at], bytes.get(at + 1)) {
            (0x1b, _) => Some(("\\x1b", 1)),
            (0x07, _) => Some(("\\x07", 1)),
            (0x08, _) => Some(("\\x08", 1)),
            (0x0c, _) => Some(("\\x0c", 1)),
            (0x7f, _) => Some(("\\x7f", 1)),
            (0xc2, Some(0x80..=0x9f)) => Some(("", 2)),
            _ => None,
        };
        let Some((escaped, length)) = escape else {
            at += 1;
            continue;
        };
        out.push_str(&scratch[from..at]);
        if length == 2 {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let c1 = bytes[at + 1];
            out.push_str("\\u{");
            out.push(char::from(HEX[usize::from(c1 >> 4)]));
            out.push(char::from(HEX[usize::from(c1 & 0xf)]));
            out.push('}');
        } else {
            out.push_str(escaped);
        }
        at += length;
        from = at;
    }
    out.push_str(&scratch[from..]);
}

/// Installs this process's console (see the module doc): its writer thread, and a global `tracing` subscriber for
/// the events this module does not write itself, formatting each as one plain-text line (no ANSI colours: the console
/// is read through `docker logs` and log collectors) onto the same queue. `RUST_LOG` (`target=level` directives)
/// filters both; unset, every event of this crate passes, and other crates' events are off. [`flush_console`] waits
/// for what is queued. Only the `mock-server` binary calls it: a library user's `Server` installs no console. A second
/// call changes nothing.
pub fn install_console() {
    use tracing_subscriber::layer::SubscriberExt;
    let filter = console_filter(std::env::var("RUST_LOG").ok().as_deref());
    let mut installed = false;
    let console = CONSOLE.get_or_init(|| {
        installed = true;
        Console::new(&filter)
    });
    if !installed {
        return;
    }
    std::thread::Builder::new()
        .name("console".into())
        .spawn(move || {
            console.run(|batch| {
                use std::io::Write;
                // a write error (stdout closed) drops the text, as the JVM's console handler does
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(batch).and_then(|()| out.flush());
            })
        })
        .expect("console writer thread");
    let layer = tracing_subscriber::fmt::layer().with_ansi(false).with_writer(|| ConsoleWriter);
    let subscriber = tracing_subscriber::registry().with(tracing_subscriber::Layer::with_filter(layer, filter));
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

/// What the `tracing` formatter writes one event through: the formatted line, in one piece, onto the console's queue.
struct ConsoleWriter;

impl std::io::Write for ConsoleWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(console) = CONSOLE.get() {
            console.push(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Returns once every console line queued so far is written to stdout (nothing to wait for without the console).
/// The binary calls it before it prints to stdout itself, and before it exits.
pub fn flush_console() {
    if let Some(console) = CONSOLE.get() {
        console.flush();
    }
}

/// Console lines dropped since the process started because stdout did not keep up:
/// `process_console_lines_dropped_total`.
pub fn console_lines_dropped() -> u64 {
    CONSOLE.get().map_or(0, |console| console.dropped.load(std::sync::atomic::Ordering::Relaxed))
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

    /// A writer into a shared buffer, for a `tracing` subscriber of the test's own.
    #[derive(Clone, Default)]
    struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const TIMESTAMP: usize = "2026-10-12T14:01:00.123456Z".len();

    /// The console writes a line as the `tracing` formatter it replaces did: level, target, port and message, the
    /// message's own lines as they are and its terminal controls escaped.
    #[test]
    fn a_console_line_is_the_tracing_formatter_line() {
        use super::{event_with, format_line, Level as L, Target};
        let messages = [
            "started on port: 1080",
            "",
            "received request:\n\n  {\n    \"path\" : \"/e0\"\n  }\n",
            "bell \u{7} esc \u{1b}[31m bs \u{8} ff \u{c} del \u{7f} c1 \u{85}\u{9b}\u{80}\u{9f} not c1 \u{a9}\u{100}",
        ];
        for (level, target, port) in [(L::Info, Target::Server, Some(1080)), (L::Warn, Target::Matching, None), (L::Error, Target::General, Some(1)), (L::Debug, Target::Cluster, None), (L::Trace, Target::RequestLifecycle, Some(65535))] {
            for message in messages {
                let sink = Sink::default();
                let writer = sink.clone();
                let subscriber = tracing_subscriber::fmt().with_ansi(false).with_max_level(tracing::Level::TRACE).with_writer(move || writer.clone()).finish();
                tracing::subscriber::with_default(subscriber, || event_with(level, target, port, &|out, _| out.push_str(message)));
                let theirs = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
                let mut ours = String::new();
                format_line(&mut ours, &mut String::new(), std::time::SystemTime::now(), level, target, port, &|out, _| out.push_str(message));
                assert_eq!(ours[TIMESTAMP..], theirs[TIMESTAMP..], "{message:?}");
            }
        }
    }

    /// Timestamps are UTC, to the microsecond, as `tracing-subscriber`'s `SystemTime` timer writes them.
    #[test]
    fn console_timestamps() {
        for (seconds, micros, text) in [
            (0, 0, "1970-01-01T00:00:00.000000Z"),
            (946_684_799, 999_999, "1999-12-31T23:59:59.999999Z"),
            (951_868_800, 7, "2000-03-01T00:00:00.000007Z"),
            (1_709_251_199, 500_000, "2024-02-29T23:59:59.500000Z"),
            (1_795_446_600, 123_456, "2026-11-23T15:10:00.123456Z"),
            (4_133_939_696, 1, "2100-12-31T12:34:56.000001Z"),
        ] {
            let mut out = String::new();
            super::push_timestamp(&mut out, std::time::UNIX_EPOCH + std::time::Duration::new(seconds, micros * 1000 + 999));
            assert_eq!(out, text);
        }
    }

    /// The message the console renders onto its line is the entry's message, and the entry keeps no text for it.
    #[test]
    fn the_console_renders_an_entry_message_without_keeping_it() {
        use crate::log_entry::{Arg, Kind, LogEntry};
        let request = serde_json::json!({"method": "GET", "path": "/a\u{2028}b", "headers": {"x": ["1", "2"]}, "body": "line\nnext"});
        let entries = [
            LogEntry::new(Kind::ExpectationMatched, "request:{}matched expectation:{}").args([Arg::from(&request), Arg::from("text\r\nwith\rterminators\u{85}end\n")]),
            LogEntry::new(Kind::Info, "{}{} and {}{}{}").args([Arg::from("a"), Arg::list(vec![Arg::from(&request), Arg::from("x")]), Arg::with_text(serde_json::json!(1), "custom")]),
            LogEntry::new(Kind::Info, "no arguments"),
        ];
        for entry in entries {
            let (mut out, mut scratch) = ("prefix ".to_string(), String::new());
            entry.write_message(&mut out, &mut scratch);
            let copy = entry.clone();
            assert_eq!(out, format!("prefix {}", entry.message_text()));
            // once rendered and kept, the kept text is what is written
            let mut again = String::new();
            copy.write_message(&mut again, &mut scratch);
            assert_eq!(again, entry.message_text());
        }
    }

    fn console() -> super::Console {
        super::Console::new(&console_filter(None))
    }

    /// When stdout does not keep up and the queue is full, a line is dropped and counted at once instead of waiting
    /// for room; the writer's next write reports how many, and the count since start stays.
    #[test]
    fn a_full_console_queue_drops_and_counts_lines() {
        use std::sync::atomic::Ordering::Relaxed;
        let console = console();
        let mut line = vec![b'x'; 1023];
        line.push(b'\n');
        let started = std::time::Instant::now();
        for _ in 0..super::CONSOLE_QUEUE / line.len() + 300 {
            console.push(&line);
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "pushing onto a full queue waited");
        assert_eq!(console.dropped.load(Relaxed), 300);
        let mut batch = Vec::with_capacity(super::CONSOLE_QUEUE);
        assert_eq!(console.take(&mut batch), (super::CONSOLE_QUEUE / line.len()) as u64);
        assert_eq!(batch.len(), super::CONSOLE_QUEUE);
        console.report_drops(&mut batch);
        let report = String::from_utf8(batch[super::CONSOLE_QUEUE..].to_vec()).unwrap();
        assert_eq!(&report[TIMESTAMP..], "  WARN mock_server::general: 300 console lines dropped: stdout was not keeping up\n");
        // reported once; the queue takes lines again once the writer has taken what it held
        batch.truncate(super::CONSOLE_QUEUE);
        console.report_drops(&mut batch);
        assert_eq!(batch.len(), super::CONSOLE_QUEUE);
        console.push(&line);
        assert_eq!(console.dropped.load(Relaxed), 300);
    }

    /// A line longer than the whole queue is still written when nothing waits before it.
    #[test]
    fn a_line_longer_than_the_queue_goes_onto_an_empty_one() {
        let console = console();
        let long = vec![b'y'; super::CONSOLE_QUEUE * 2];
        console.push(&long);
        console.push(b"next\n");
        assert_eq!(console.dropped.load(std::sync::atomic::Ordering::Relaxed), 1);
        let mut batch = Vec::new();
        assert_eq!(console.take(&mut batch), 1);
        assert_eq!(batch.len(), long.len());
    }

    /// `RUST_LOG` filters the lines the console writes itself.
    #[test]
    fn rust_log_filters_the_console_lines() {
        use super::{Level as L, Target};
        let console = super::Console::new(&console_filter(Some("mock_server=info,mock_server::matching=off")));
        console.line(L::Debug, Target::Server, None, &|out, _| out.push_str("debug"));
        console.line(L::Error, Target::Matching, None, &|out, _| out.push_str("off"));
        console.line(L::Info, Target::Server, Some(1080), &|out, _| out.push_str("kept"));
        let mut batch = Vec::new();
        assert_eq!(console.take(&mut batch), 1);
        assert!(String::from_utf8(batch).unwrap().ends_with("  INFO mock_server::server: port=1080 kept\n"));
    }
}

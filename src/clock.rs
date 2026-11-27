//! The controllable clock (`org.mockserver.time.TimeService`) and its control-plane endpoint, `PUT`/`GET
//! /mockserver/clock` (`HttpState.handleClockPut`, `handleClockGet`).
//!
//! Upstream's frozen instant is JVM-global. Ours is one per server ([`State::clock`]), because several servers share
//! a test process: `handler::dispatch` makes it current for the request it handles ([`scope`]), and the time readers
//! upstream routes through `TimeService` read it through [`now`], [`now_instant`] and [`now_millis`]. Outside a scope
//! (a task spawned off the request) they read the real clock. A `reset` leaves the clock as it is, as upstream's does.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};
use datafaker::java::Instant;
use jackson::JsonNode;
use serde_json::json;

use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;

/// `TimeService`'s frozen instant: `None` runs with the real clock.
#[derive(Default)]
pub struct Clock {
    frozen: parking_lot::RwLock<Option<Instant>>,
    /// Whether `frozen` is set, read before taking the lock.
    is_frozen: AtomicBool,
}

impl Clock {
    /// `TimeService.now()`.
    pub fn now(&self) -> Instant {
        if !self.is_frozen.load(Ordering::Acquire) {
            return Instant::now();
        }
        self.frozen.read().unwrap_or_else(Instant::now)
    }

    /// `TimeService.currentTimeMillis()`, saturating where `toEpochMilli` overflows.
    pub fn now_millis(&self) -> i64 {
        epoch_millis(self.now())
    }

    /// `TimeService.isFrozen()`.
    pub fn is_frozen(&self) -> bool {
        self.is_frozen.load(Ordering::Acquire)
    }

    /// `TimeService.freeze(instant)`: at `at`, or at the real time.
    pub fn freeze(&self, at: Option<Instant>) {
        let mut frozen = self.frozen.write();
        *frozen = Some(at.unwrap_or_else(Instant::now));
        self.is_frozen.store(true, Ordering::Release);
    }

    /// `TimeService.advance(Duration.ofMillis(millis))`: from the frozen instant, or from the real time (which
    /// freezes the clock). The `Instant.plus` failure leaves the clock as it was.
    pub fn advance(&self, millis: i64) -> Result<(), datafaker::Error> {
        let mut frozen = self.frozen.write();
        let base = frozen.unwrap_or_else(Instant::now);
        *frozen = Some(base.plus_millis(millis)?);
        self.is_frozen.store(true, Ordering::Release);
        Ok(())
    }

    /// `TimeService.reset()`: the real clock again.
    pub fn reset(&self) {
        let mut frozen = self.frozen.write();
        *frozen = None;
        self.is_frozen.store(false, Ordering::Release);
    }
}

tokio::task_local! {
    /// The clock of the server handling the current request.
    static CURRENT: ClockRef;
}

/// The clock a scope runs with, borrowed for as long as the scope: every request sets one, and holding it by `Arc`
/// wrote its reference count, which every request worker shares, twice per request.
#[derive(Clone, Copy)]
struct ClockRef(*const Clock);

// SAFETY: a `ClockRef` stands for a `&Clock` (`Clock` is `Sync`), read only while the scope that borrows it runs.
unsafe impl Send for ClockRef {}
unsafe impl Sync for ClockRef {}

/// Runs `f` with `clock` as the current server's clock.
pub async fn scope<F: std::future::Future>(clock: Arc<Clock>, f: F) -> F::Output {
    scope_borrowed(&clock, f).await
}

/// [`scope`] with a borrowed clock: the returned future captures the borrow (`use<'a, …>`), so it cannot outlive the
/// clock. Not an `async fn`, which would move `f` (a request's whole handling) into a future of its own.
pub fn scope_borrowed<'a, F: std::future::Future>(clock: &'a Clock, f: F) -> impl std::future::Future<Output = F::Output> + use<'a, F> {
    CURRENT.scope(ClockRef(clock), f)
}

/// `TimeService.now()` of the current server.
pub fn now_instant() -> Instant {
    // SAFETY: set only by `scope_borrowed`, whose future holds the clock borrowed while the scope runs
    CURRENT.try_with(|clock| unsafe { &*clock.0 }.now()).unwrap_or_else(|_| Instant::now())
}

/// `TimeService.currentTimeMillis()` of the current server. An instant past the range of epoch millis (where
/// upstream's `toEpochMilli` throws) saturates.
pub fn now_millis() -> i64 {
    epoch_millis(now_instant())
}

/// [`now_instant`] as a `chrono` time, for the readers formatting it. An instant past `chrono`'s range (about
/// ±262,000 years) is clamped to it.
pub fn now() -> DateTime<Utc> {
    let instant = now_instant();
    match DateTime::from_timestamp(instant.epoch_second(), instant.nano() as u32) {
        Some(t) => t,
        None if instant.epoch_second() < 0 => DateTime::<Utc>::MIN_UTC,
        None => DateTime::<Utc>::MAX_UTC,
    }
}

fn epoch_millis(instant: Instant) -> i64 {
    instant.to_epoch_milli().unwrap_or(if instant.epoch_second() < 0 { i64::MIN } else { i64::MAX })
}

const ACTIONS: &str = "must be one of: freeze, advance, reset";

/// `PUT` and `GET /mockserver/clock`, authenticated by the caller.
pub fn route(state: &State, request: &HttpRequest) -> Reply {
    if request.method == "GET" {
        return get(&state.clock);
    }
    put(state, request)
}

/// `handleClockGet`.
fn get(clock: &Clock) -> Reply {
    let instant = clock.now();
    match instant.to_epoch_milli() {
        Ok(millis) => crate::chaos::pretty(&json!({"currentInstant": instant.to_string(), "currentEpochMillis": millis, "frozen": clock.is_frozen()})),
        Err(_) => Reply::api_body(400, "application/json", "{\"error\":\"failed to get clock status\"}"),
    }
}

/// `handleClockPut`.
fn put(state: &State, request: &HttpRequest) -> Reply {
    let error = crate::chaos::error;
    let body = request.body_json_or_xml_str();
    if body.trim().is_empty() {
        return error("request body is required with 'action' field");
    }
    let node = match crate::jnode::read_tree(&body) {
        Ok(node) => node,
        Err(e) => return error(&format!("failed to process clock request: {e}")),
    };
    // `node.has("action") ? node.get("action").asText() : null`, then `isBlank`.
    let Some(action) = node.get("action").map(JsonNode::as_text).filter(|a| !a.trim().is_empty()) else {
        return error(&format!("'action' field is required, {ACTIONS}"));
    };
    let action = action.to_lowercase();
    let clock = &state.clock;
    match action.as_str() {
        "freeze" => {
            let instant = match node.get("instant").filter(|v| !v.is_null()) {
                None => None,
                Some(v) => match Instant::parse(&v.as_text()) {
                    Ok(instant) => Some(instant),
                    Err(_) => return error("invalid 'instant' value, must be ISO-8601 format (e.g. 2024-01-01T00:00:00Z)"),
                },
            };
            // `representableInEpochMillis`: the clock is reported in epoch milliseconds
            if instant.as_ref().is_some_and(|i| i.to_epoch_milli().is_err()) {
                return error("'instant' is outside the range MockServer's clock can represent");
            }
            clock.freeze(instant);
        }
        "advance" => {
            let millis = node.get("durationMillis").filter(|v| !v.is_null()).map_or(0, as_long);
            if millis <= 0 {
                return error("'durationMillis' must be a positive number");
            }
            // the clock must not move past `Long.MAX_VALUE` epoch milliseconds; upstream's own check wraps, so from an
            // instant before the epoch the bound is negative and every advance is refused
            let current = match clock.now().to_epoch_milli() {
                Ok(current) => current,
                Err(e) => return error(&format!("failed to process clock request: {}", e.message())),
            };
            let latest = i64::MAX.wrapping_sub(current);
            if millis > latest {
                return error(&format!("'durationMillis' must be at most {latest}, or the clock would pass the latest time it can represent"));
            }
            if let Err(e) = clock.advance(millis) {
                return error(&format!("failed to process clock request: {}", e.message()));
            }
        }
        "reset" => clock.reset(),
        _ => return error(&format!("unknown action '{action}', {ACTIONS}")),
    }
    let instant = clock.now();
    let text = instant.to_string();
    let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, format!("clock {action}, current instant:{{}}")).args([text.as_str()]);
    crate::chaos::log(state, request, entry);
    match instant.to_epoch_milli() {
        Ok(millis) => crate::chaos::pretty(&json!({"status": action, "currentInstant": text, "currentEpochMillis": millis})),
        Err(e) => error(&format!("failed to process clock request: {}", e.message())),
    }
}

/// `JsonNode.asLong(0)`: a number's `longValue()`, a boolean 1 or 0, a text through `NumberInput.parseAsLong`,
/// anything else 0.
fn as_long(v: &JsonNode) -> i64 {
    match v {
        JsonNode::Boolean(b) => *b as i64,
        JsonNode::Text(s) => parse_as_long(s),
        n if n.is_number() => n.long_value(),
        _ => 0,
    }
}

/// `NumberInput.parseAsLong(text, 0)`: trimmed, an optional sign, then `Long.parseLong` for plain digits (0 when it
/// overflows) or `Double.parseDouble` narrowed for anything else.
fn parse_as_long(text: &str) -> i64 {
    let text = text.trim_matches(|c: char| c <= ' ');
    if text.is_empty() {
        return 0;
    }
    let text = text.strip_prefix('+').unwrap_or(text);
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.bytes().all(|b| b.is_ascii_digit()) {
        return text.parse::<i64>().unwrap_or(0);
    }
    jackson::javanum::parse_double(text).map_or(0, |d| d as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_long_reads_values_as_jackson_does() {
        let cases: &[(&str, i64)] = &[
            ("5", 5),
            ("-5", -5),
            ("1.9", 1),
            ("1e3", 1000),
            ("true", 1),
            ("false", 0),
            ("null", 0),
            ("[]", 0),
            ("99999999999999999999", 7_766_279_631_452_241_919),
            ("\"  7\"", 7),
            ("\"+5\"", 5),
            ("\"1.9\"", 1),
            ("\"1e3\"", 1000),
            ("\"0x10\"", 0),
            ("\"5abc\"", 0),
            ("\"-3\"", -3),
            ("\"\"", 0),
        ];
        for (json, expected) in cases {
            let v = crate::jnode::read_tree(json).unwrap();
            assert_eq!(as_long(&v), *expected, "{json}");
        }
    }

    #[test]
    fn advancing_an_unfrozen_clock_freezes_it() {
        let clock = Clock::default();
        assert!(!clock.is_frozen());
        clock.advance(1000).unwrap();
        assert!(clock.is_frozen());
        let at = clock.now();
        assert_eq!(clock.now(), at);
        clock.reset();
        assert!(!clock.is_frozen());
    }
}

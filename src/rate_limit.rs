//! The declarative `rateLimit` clause (`RateLimitRegistry`): a fixed window or a token bucket per counter key (the
//! clause's `name`, else the expectation id), one per server (`State::rate_limits`) and cleared by a reset, as
//! upstream's `HttpState.reset` clears its singleton. An over-limit request gets a synthetic error response instead
//! of the action's.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde_json::Value;

use crate::reply::Reply;

struct Window {
    start: i64,
    count: i64,
}

struct Bucket {
    tokens_milli: i64,
    last_refill: i64,
    last_allowed: bool,
}

#[derive(Default)]
struct Counters {
    windows: HashMap<String, Window>,
    buckets: HashMap<String, Bucket>,
}

/// `RateLimitRegistry`: a server's counters.
#[derive(Default)]
pub struct Registry(Mutex<Counters>);

impl Registry {
    /// `RateLimitRegistry.reset`, called by `HttpState.reset`.
    pub fn reset(&self) {
        *self.0.lock() = Counters::default();
    }
}

/// `Decision` for a request that is over the limit.
struct Rejected {
    limit: i64,
    reset_epoch_second: i64,
}

fn now_millis() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

/// `tryAcquire`: records one request against the clause; `Some` when it is over the limit.
fn try_acquire(counters: &Registry, clause: &Value, fallback_key: &str, max_quotas: i64) -> Option<Rejected> {
    let key = clause.get("name").and_then(Value::as_str).unwrap_or(fallback_key).to_string();
    let now = now_millis();
    let token_bucket = clause.get("algorithm").and_then(Value::as_str).is_some_and(|a| a.trim().eq_ignore_ascii_case("token_bucket"));
    let mut registry = counters.0.lock();
    let over_cap = |r: &Counters| (r.windows.len() + r.buckets.len()) as i64 >= max_quotas;
    if token_bucket {
        let burst = clause.get("burst").and_then(Value::as_i64).filter(|b| *b >= 1)?;
        let refill = clause.get("refillPerSecond").and_then(Value::as_f64).filter(|r| *r > 0.0)?;
        let capacity = burst * 1000;
        if !registry.buckets.contains_key(&key) && over_cap(&registry) {
            return None;
        }
        let bucket = registry.buckets.entry(key).or_insert(Bucket { tokens_milli: capacity, last_refill: now, last_allowed: false });
        let elapsed = (now - bucket.last_refill).max(0);
        let mut tokens = (bucket.tokens_milli + (elapsed as f64 * refill) as i64).min(capacity);
        bucket.last_allowed = tokens >= 1000;
        if bucket.last_allowed {
            tokens -= 1000;
        }
        bucket.tokens_milli = tokens;
        bucket.last_refill = now;
        if bucket.last_allowed {
            return None;
        }
        let remaining = tokens / 1000;
        let reset = if remaining >= 1 {
            now / 1000
        } else {
            let millis_to_one = (1000 - tokens) as f64 / refill;
            now / 1000 + ((millis_to_one / 1000.0).ceil() as i64).max(1)
        };
        return Some(Rejected { limit: burst, reset_epoch_second: reset });
    }
    let limit = clause.get("limit").and_then(Value::as_i64).filter(|l| *l >= 1)?;
    let window = clause.get("windowMillis").and_then(Value::as_i64).filter(|w| *w >= 1)?;
    if !registry.windows.contains_key(&key) && over_cap(&registry) {
        return None;
    }
    let w = registry.windows.entry(key).or_insert(Window { start: now, count: 0 });
    if w.count > 0 && now - w.start >= window {
        *w = Window { start: now, count: 0 };
    }
    w.count += 1;
    (w.count > limit).then(|| Rejected { limit, reset_epoch_second: (w.start + window) / 1000 })
}

/// `rateLimitResponseOrNull`: the over-limit response for the expectation's clause, if this request is over it.
pub fn rejection(state: &crate::state::State, expectation: &Value, id: &str) -> Option<Reply> {
    let clause = expectation.get("rateLimit").filter(|c| c.is_object())?;
    let max_quotas = state.config.int_property("rateLimitMaxNamedQuotas", 10_000);
    let rejected = try_acquire(&state.rate_limits, clause, id, max_quotas)?;
    let status = clause.get("errorStatus").and_then(Value::as_u64).unwrap_or(429) as u32;
    let retry_after = clause
        .get("retryAfter")
        .and_then(Value::as_str)
        .filter(|r| !r.is_empty())
        .map_or_else(|| (rejected.reset_epoch_second - crate::clock::now_millis() / 1000).max(1).to_string(), str::to_string);
    let mut reply = Reply::status(status);
    reply.headers.push(("content-type".into(), "application/json".into()));
    reply.headers.push(("X-RateLimit-Limit".into(), rejected.limit.to_string()));
    reply.headers.push(("X-RateLimit-Remaining".into(), "0".into()));
    reply.headers.push(("X-RateLimit-Reset".into(), rejected.reset_epoch_second.to_string()));
    reply.headers.push(("Retry-After".into(), retry_after));
    reply.body = bytes::Bytes::from_static(br#"{"error":{"type":"rate_limit_exceeded","message":"request rate limit exceeded"}}"#);
    Some(reply)
}

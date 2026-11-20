//! `HttpChaosProfile`: HTTP-level faults on a matched expectation's response (its `chaos`), or on a forward whose
//! request `Host` has a service-scoped profile (`ServiceChaosRegistry`). `HttpActionHandler` applies them in a fixed
//! order: drop the connection; else replace the response with a quota (429) or error response; else reshape it
//! (GraphQL error envelope, truncated or malformed body, slow dribble); then add latency. Destructive faults feed
//! the auto-halt circuit-breaker (`ChaosAutoHaltMonitor`).

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use bytes::Bytes;
use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use super::bind::Bean;
use super::{HostProfile, ProfileError, Wording, now_millis};
use crate::reply::Reply;
use crate::state::State;

/// `HttpChaosProfile`: every field optional, as given.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HttpChaosProfile {
    pub error_status: Option<i32>,
    pub retry_after: Option<String>,
    pub error_probability: Option<f64>,
    pub drop_connection_probability: Option<f64>,
    /// `DelayDTO` JSON in its canonical form.
    pub latency: Option<Value>,
    pub seed: Option<i64>,
    pub succeed_first: Option<i32>,
    pub fail_request_count: Option<i32>,
    pub outage_after_millis: Option<i64>,
    pub outage_duration_millis: Option<i64>,
    pub truncate_body_at_fraction: Option<f64>,
    pub malformed_body: Option<bool>,
    pub slow_response_chunk_size: Option<i32>,
    pub slow_response_chunk_delay: Option<Value>,
    pub quota_name: Option<String>,
    pub quota_limit: Option<i32>,
    pub quota_window_millis: Option<i64>,
    pub quota_error_status: Option<i32>,
    pub degradation_ramp_millis: Option<i64>,
    pub graphql_errors: Option<bool>,
    pub graphql_error_message: Option<String>,
    pub graphql_error_code: Option<String>,
    pub graphql_nullify_data: Option<bool>,
}

/// A Java `double` as Jackson writes it (`Double.toString`).
fn double(v: f64) -> Value {
    crate::model::number(&java_compat::double_to_string(v))
}

fn delay_millis(v: &Value) -> Option<Duration> {
    crate::action::delay(v).map(|d| d.fixed)
}

impl HttpChaosProfile {
    /// `timeWindowEligible`: whether the outage window (anchored at the expectation's first match) is open.
    fn time_window_eligible(&self, first_match: i64, now: i64) -> bool {
        if self.outage_after_millis.is_none() && self.outage_duration_millis.is_none() || first_match <= 0 {
            return true;
        }
        let elapsed = now - first_match;
        let start = self.outage_after_millis.unwrap_or(0);
        elapsed >= start && self.outage_duration_millis.is_none_or(|d| elapsed < start + d)
    }

    /// `degradationFactor`: 0 at the first match, rising to 1 over `degradationRampMillis`.
    fn degradation_factor(&self, first_match: i64, now: i64) -> f64 {
        let Some(ramp) = self.degradation_ramp_millis else { return 1.0 };
        if first_match <= 0 {
            return 1.0;
        }
        let elapsed = now - first_match;
        if elapsed <= 0 {
            0.0
        } else if elapsed >= ramp {
            1.0
        } else {
            elapsed as f64 / ramp as f64
        }
    }

    /// `HttpActionHandler.effectiveChaos`: `None` outside the outage window; the probabilities scaled by the ramp.
    pub fn effective(&self, first_match: i64) -> Option<HttpChaosProfile> {
        let now = now_millis();
        if !self.time_window_eligible(first_match, now) {
            return None;
        }
        if self.degradation_ramp_millis.is_none() {
            return Some(self.clone());
        }
        let f = self.degradation_factor(first_match, now);
        let mut scaled = self.clone();
        scaled.error_probability = self.error_probability.map(|p| p * f);
        scaled.drop_connection_probability = self.drop_connection_probability.map(|p| p * f);
        Some(scaled)
    }

    /// `countWindowEligible`: after the first `succeedFirst` matches, for `failRequestCount` matches.
    pub fn count_window_eligible(&self, match_count: u32) -> bool {
        if self.succeed_first.is_none() && self.fail_request_count.is_none() {
            return true;
        }
        let after = self.succeed_first.unwrap_or(0) as i64;
        let n = match_count as i64;
        n > after && self.fail_request_count.is_none_or(|f| n <= after + f as i64)
    }

    /// `ServiceChaosRegistry.activeCountByFaultType`'s classification of this profile.
    pub fn fault_types(&self) -> Vec<&'static str> {
        let mut types = Vec::new();
        let mut add = |cond: bool, t| {
            if cond {
                types.push(t);
            }
        };
        add(self.drop_connection_probability.is_some(), "drop");
        add(self.error_status.is_some(), "error");
        add(self.latency.is_some(), "latency");
        add(self.truncate_body_at_fraction.is_some(), "truncate");
        add(self.malformed_body == Some(true), "malformed");
        add(self.slow_response_chunk_size.is_some() && self.slow_response_chunk_delay.is_some(), "slow");
        add(self.quota_name.is_some() && self.quota_limit.is_some() && self.quota_window_millis.is_some(), "quota");
        add(self.graphql_errors == Some(true), "graphql");
        types
    }
}

impl HostProfile for HttpChaosProfile {
    const NAMESPACE: &'static str = "chaos-service";
    const WORDING: Wording = Wording { what: "service-scoped chaos", invalid: "invalid chaos profile", failed: "service chaos", list_key: "services" };

    /// `HttpChaosProfileDTO` read from JSON, then `buildObject`'s range checks in setter order.
    fn from_json(v: &Value) -> Result<HttpChaosProfile, ProfileError> {
        let dto = Bean::of(v, "org.mockserver.serialization.model.HttpChaosProfileDTO")?;
        let delay = |name: &str| -> Result<Option<Value>, ProfileError> {
            Ok(dto.bean(name, "org.mockserver.serialization.model.DelayDTO")?.map(|d| crate::canonical::delay(&Value::Object(d.map().clone()))))
        };
        let p = HttpChaosProfile {
            error_status: dto.int("errorStatus")?,
            retry_after: dto.string("retryAfter")?,
            error_probability: dto.double("errorProbability")?,
            drop_connection_probability: dto.double("dropConnectionProbability")?,
            latency: delay("latency")?,
            seed: dto.long("seed")?,
            succeed_first: dto.int("succeedFirst")?,
            fail_request_count: dto.int("failRequestCount")?,
            outage_after_millis: dto.long("outageAfterMillis")?,
            outage_duration_millis: dto.long("outageDurationMillis")?,
            truncate_body_at_fraction: dto.double("truncateBodyAtFraction")?,
            malformed_body: dto.boolean("malformedBody")?,
            slow_response_chunk_size: dto.int("slowResponseChunkSize")?,
            slow_response_chunk_delay: delay("slowResponseChunkDelay")?,
            quota_name: dto.string("quotaName")?,
            quota_limit: dto.int("quotaLimit")?,
            quota_window_millis: dto.long("quotaWindowMillis")?,
            quota_error_status: dto.int("quotaErrorStatus")?,
            degradation_ramp_millis: dto.long("degradationRampMillis")?,
            graphql_errors: dto.boolean("graphqlErrors")?,
            graphql_error_message: dto.string("graphqlErrorMessage")?,
            graphql_error_code: dto.string("graphqlErrorCode")?,
            graphql_nullify_data: dto.boolean("graphqlNullifyData")?,
        };
        let status = |name: &str, v: Option<i32>| match v {
            Some(s) if !(100..=599).contains(&s) => Err(ProfileError::Invalid(format!("{name} must be between 100 and 599, got {s}"))),
            _ => Ok(()),
        };
        let fraction = |name: &str, v: Option<f64>| match v {
            Some(f) if f.is_nan() || !(0.0..=1.0).contains(&f) => {
                Err(ProfileError::Invalid(format!("{name} must be between 0.0 and 1.0, got {}", java_compat::double_to_string(f))))
            }
            _ => Ok(()),
        };
        let at_least = |name: &str, v: Option<i64>, min: i64| match v {
            Some(n) if n < min => Err(ProfileError::Invalid(format!("{name} must be >= {min}, got {n}"))),
            _ => Ok(()),
        };
        status("errorStatus", p.error_status)?;
        fraction("errorProbability", p.error_probability)?;
        fraction("dropConnectionProbability", p.drop_connection_probability)?;
        at_least("succeedFirst", p.succeed_first.map(i64::from), 0)?;
        at_least("failRequestCount", p.fail_request_count.map(i64::from), 1)?;
        at_least("outageAfterMillis", p.outage_after_millis, 0)?;
        at_least("outageDurationMillis", p.outage_duration_millis, 1)?;
        fraction("truncateBodyAtFraction", p.truncate_body_at_fraction)?;
        at_least("slowResponseChunkSize", p.slow_response_chunk_size.map(i64::from), 1)?;
        at_least("quotaLimit", p.quota_limit.map(i64::from), 1)?;
        at_least("quotaWindowMillis", p.quota_window_millis, 1)?;
        status("quotaErrorStatus", p.quota_error_status)?;
        at_least("degradationRampMillis", p.degradation_ramp_millis, 1)?;
        Ok(p)
    }

    /// `HttpChaosProfileDTO` as Jackson writes it: non-null properties, alphabetical.
    fn to_json(&self) -> Value {
        let mut o = Map::new();
        let mut put = |k: &str, v: Option<Value>| {
            if let Some(v) = v {
                o.insert(k.to_string(), v);
            }
        };
        put("degradationRampMillis", self.degradation_ramp_millis.map(Value::from));
        put("dropConnectionProbability", self.drop_connection_probability.map(double));
        put("errorProbability", self.error_probability.map(double));
        put("errorStatus", self.error_status.map(Value::from));
        put("failRequestCount", self.fail_request_count.map(Value::from));
        put("graphqlErrorCode", self.graphql_error_code.clone().map(Value::from));
        put("graphqlErrorMessage", self.graphql_error_message.clone().map(Value::from));
        put("graphqlErrors", self.graphql_errors.map(Value::from));
        put("graphqlNullifyData", self.graphql_nullify_data.map(Value::from));
        put("latency", self.latency.clone());
        put("malformedBody", self.malformed_body.map(Value::from));
        put("outageAfterMillis", self.outage_after_millis.map(Value::from));
        put("outageDurationMillis", self.outage_duration_millis.map(Value::from));
        put("quotaErrorStatus", self.quota_error_status.map(Value::from));
        put("quotaLimit", self.quota_limit.map(Value::from));
        put("quotaName", self.quota_name.clone().map(Value::from));
        put("quotaWindowMillis", self.quota_window_millis.map(Value::from));
        put("retryAfter", self.retry_after.clone().map(Value::from));
        put("seed", self.seed.map(Value::from));
        put("slowResponseChunkDelay", self.slow_response_chunk_delay.clone());
        put("slowResponseChunkSize", self.slow_response_chunk_size.map(Value::from));
        put("succeedFirst", self.succeed_first.map(Value::from));
        put("truncateBodyAtFraction", self.truncate_body_at_fraction.map(double));
        Value::Object(o)
    }

    fn merge(&self, patch: &HttpChaosProfile) -> HttpChaosProfile {
        fn pick<T: Clone>(patch: &Option<T>, base: &Option<T>) -> Option<T> {
            patch.clone().or_else(|| base.clone())
        }
        HttpChaosProfile {
            error_status: pick(&patch.error_status, &self.error_status),
            retry_after: pick(&patch.retry_after, &self.retry_after),
            error_probability: pick(&patch.error_probability, &self.error_probability),
            drop_connection_probability: pick(&patch.drop_connection_probability, &self.drop_connection_probability),
            latency: pick(&patch.latency, &self.latency),
            seed: pick(&patch.seed, &self.seed),
            succeed_first: pick(&patch.succeed_first, &self.succeed_first),
            fail_request_count: pick(&patch.fail_request_count, &self.fail_request_count),
            outage_after_millis: pick(&patch.outage_after_millis, &self.outage_after_millis),
            outage_duration_millis: pick(&patch.outage_duration_millis, &self.outage_duration_millis),
            truncate_body_at_fraction: pick(&patch.truncate_body_at_fraction, &self.truncate_body_at_fraction),
            malformed_body: pick(&patch.malformed_body, &self.malformed_body),
            slow_response_chunk_size: pick(&patch.slow_response_chunk_size, &self.slow_response_chunk_size),
            slow_response_chunk_delay: pick(&patch.slow_response_chunk_delay, &self.slow_response_chunk_delay),
            quota_name: pick(&patch.quota_name, &self.quota_name),
            quota_limit: pick(&patch.quota_limit, &self.quota_limit),
            quota_window_millis: pick(&patch.quota_window_millis, &self.quota_window_millis),
            quota_error_status: pick(&patch.quota_error_status, &self.quota_error_status),
            degradation_ramp_millis: pick(&patch.degradation_ramp_millis, &self.degradation_ramp_millis),
            graphql_errors: pick(&patch.graphql_errors, &self.graphql_errors),
            graphql_error_message: pick(&patch.graphql_error_message, &self.graphql_error_message),
            graphql_error_code: pick(&patch.graphql_error_code, &self.graphql_error_code),
            graphql_nullify_data: pick(&patch.graphql_nullify_data, &self.graphql_nullify_data),
        }
    }

    fn has_any_fault(&self) -> bool {
        !self.fault_types().is_empty()
    }
}

/// `ChaosProbability.shouldInject`: always when the probability is absent or at least 1, never at 0 (or NaN); a
/// seed makes the draw `new Random(seed).nextDouble()`, the same every time.
pub fn should_inject(probability: Option<f64>, seed: Option<i64>) -> bool {
    match probability {
        Some(p) if p.is_nan() => false,
        None => true,
        Some(p) if p >= 1.0 => true,
        Some(p) if p <= 0.0 => false,
        Some(p) => {
            let draw = match seed {
                Some(seed) => crate::random::JavaRandom::new(seed).next_double(),
                None => crate::random::uniform(),
            };
            draw < p
        }
    }
}

/// Per `(expectation id, idempotency-key value)`: the attempt count and the tick it was last counted at (the least
/// recent is evicted).
type AttemptCounts = HashMap<(String, String), (u32, u64)>;

/// `RecoveryAttemptRegistry`: 1-based attempt counts per `(expectation id, idempotency-key value)`, the least
/// recently used pair evicted past 10,000.
#[derive(Default)]
pub struct RecoveryAttempts {
    attempts: Mutex<(u64, AttemptCounts)>,
}

impl RecoveryAttempts {
    const MAX_SIZE: usize = 10_000;

    /// `nextAttempt`: counts this attempt and returns its number.
    pub fn next_attempt(&self, expectation_id: &str, key: &str) -> u32 {
        let mut guard = self.attempts.lock();
        let (tick, map) = &mut *guard;
        *tick += 1;
        let now = *tick;
        let entry = map.entry((expectation_id.to_string(), key.to_string())).or_insert((0, now));
        entry.0 += 1;
        entry.1 = now;
        let attempt = entry.0;
        if map.len() > Self::MAX_SIZE && let Some(eldest) = map.iter().min_by_key(|(_, (_, used))| *used).map(|(k, _)| k.clone()) {
            map.remove(&eldest);
        }
        attempt
    }

    pub fn reset(&self) {
        self.attempts.lock().1.clear();
    }
}

/// `HttpActionHandler.selectRecoveryResponse`: the response a `recoverAfter` clause selects for this match — the
/// failure response (its `failResponse`, else a bare 503) for the first `failTimes` attempts, else `None` (the
/// configured response). Attempts count per expectation, or per idempotency-key value when the configured header
/// is on the request.
pub fn recovery_response(state: &State, response: &Value, expectation_id: &str, request: &crate::request::HttpRequest, match_count: u32) -> Option<Value> {
    let recover = response.get("recoverAfter")?;
    let fail_times = recover.get("failTimes").and_then(Value::as_i64).filter(|n| *n > 0)?;
    let key = recover
        .get("idempotencyHeader")
        .and_then(Value::as_str)
        .filter(|h| !h.trim().is_empty())
        .and_then(|h| request.first_header(h))
        .filter(|v| !v.trim().is_empty());
    let attempt = match key {
        Some(k) => state.chaos.recovery.next_attempt(expectation_id, k),
        None => match_count,
    };
    if i64::from(attempt) > fail_times {
        return None;
    }
    Some(recover.get("failResponse").filter(|r| r.is_object()).cloned().unwrap_or_else(|| json!({"statusCode": 503, "reasonPhrase": "Service Unavailable"})))
}

/// `HttpQuotaRegistry`: fixed-window request counts by quota name.
#[derive(Default)]
pub struct Quotas {
    windows: Mutex<HashMap<String, (i64, i64)>>,
}

impl Quotas {
    /// `tryAcquire`: counts this request; whether it is within `limit` for the current window.
    pub fn try_acquire(&self, name: &str, limit: i64, window_millis: i64) -> bool {
        if limit < 0 || window_millis <= 0 {
            return true;
        }
        let now = now_millis();
        let mut windows = self.windows.lock();
        let window = windows.entry(name.to_string()).or_insert((now, 0));
        if now - window.0 >= window_millis {
            *window = (now, 0);
        }
        window.1 += 1;
        window.1 <= limit
    }

    pub fn reset(&self) {
        self.windows.lock().clear();
    }
}

/// `ChaosAutoHaltMonitor`: counts destructive faults in a sliding window; past the threshold, while any service or
/// TCP chaos is active, it clears both registries.
#[derive(Default)]
pub struct AutoHalt {
    timestamps: Mutex<VecDeque<i64>>,
    halts: std::sync::atomic::AtomicU64,
}

const DESTRUCTIVE: &[&str] = &["error", "drop", "quota"];

impl AutoHalt {
    fn record(&self, state: &State, fault: &str) {
        if !state.config.bool_property("chaosAutoHaltEnabled", false) || !DESTRUCTIVE.contains(&fault) {
            return;
        }
        let threshold = state.config.int_property("chaosAutoHaltErrorThreshold", 50);
        if threshold <= 0 {
            return;
        }
        let window = state.config.int_property("chaosAutoHaltWindowMillis", 60_000);
        let now = now_millis();
        let mut timestamps = self.timestamps.lock();
        timestamps.push_back(now);
        while timestamps.front().is_some_and(|t| *t <= now - window) {
            timestamps.pop_front();
        }
        let count = timestamps.len() as i64;
        if count >= threshold && (!state.chaos.service.is_empty() || state.chaos.tcp.active_count() > 0) {
            self.halts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            crate::log::warn(
                state,
                &format!(
                    "chaos auto-halt triggered: {count} error-class faults (5xx/dropped/quota/connection-lifecycle RST) in the last {window} ms exceeded threshold of {threshold} — disabling all active service-scoped and TCP-layer chaos profiles"
                ),
            );
            state.chaos.service.reset();
            state.chaos.tcp.reset();
            if crate::metrics::enabled(&state.config) {
                state.config.metrics.chaos_auto_halted();
            }
            timestamps.clear();
        }
    }

    /// `getHaltCount`.
    pub fn halts(&self) -> u64 {
        self.halts.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn reset(&self) {
        self.timestamps.lock().clear();
        self.halts.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

/// `Metrics.incrementHttpChaosInjected`: counted when metrics are on, and always offered to auto-halt.
pub fn injected(state: &State, fault: &'static str) {
    if crate::metrics::enabled(&state.config) {
        state.config.metrics.chaos_injected(fault);
    }
    state.chaos.auto_halt.record(state, fault);
}

/// A chaos profile applied to one matched request: the profile and the expectation's 1-based match count.
pub struct Injection {
    pub profile: HttpChaosProfile,
    pub match_count: u32,
}

/// A response `HttpActionHandler` substitutes: its reply and how the log records it.
pub struct Replacement {
    pub reply: Reply,
    pub logged: Value,
}

impl Injection {
    fn eligible(&self) -> bool {
        self.profile.count_window_eligible(self.match_count)
    }

    /// `shouldDropConnection` (the seed is varied so drop and error draws differ); counts a "drop".
    pub fn drops(&self, state: &State) -> bool {
        let p = &self.profile;
        let drop = p.drop_connection_probability.is_some() && self.eligible() && should_inject(p.drop_connection_probability, p.seed.map(|s| s ^ 0x4452_4F50));
        if drop {
            injected(state, "drop");
        }
        drop
    }

    /// The quota response when the quota is exceeded, else the error response when the error fires (counted).
    pub fn replacement(&self, state: &State) -> Option<Replacement> {
        let p = &self.profile;
        if !self.eligible() {
            return None;
        }
        if let (Some(name), Some(limit), Some(window)) = (&p.quota_name, p.quota_limit, p.quota_window_millis) && !state.chaos.quotas.try_acquire(name, limit as i64, window) {
            injected(state, "quota");
            let body = r#"{"error":{"type":"quota_exceeded","message":"HTTP request quota exceeded"}}"#;
            return Some(synthetic(p.quota_error_status.unwrap_or(429), body, p.retry_after.as_deref()));
        }
        let status = p.error_status?;
        if !should_inject(p.error_probability, p.seed) {
            return None;
        }
        injected(state, "error");
        Some(synthetic(status, r#"{"error":{"type":"chaos_injected","message":"injected HTTP chaos error"}}"#, p.retry_after.as_deref()))
    }

    /// The chaos latency, when the count window is open (counted).
    pub fn latency(&self, state: &State) -> Option<Duration> {
        let latency = self.profile.latency.as_ref().filter(|_| self.eligible()).and_then(delay_millis);
        if latency.is_some() {
            injected(state, "latency");
        }
        latency
    }

    /// `applyResponseChaos`: a GraphQL error envelope (which wins over body corruption), else a truncated and/or
    /// malformed body; a slow dribble composes with either. `logged` is the response as its log line records it.
    pub fn reshape(&self, state: &State, reply: &mut Reply, logged: &mut Value) {
        let p = &self.profile;
        if !self.eligible() {
            return;
        }
        let graphql = p.graphql_errors == Some(true);
        let malformed = p.malformed_body == Some(true);
        let corrupt = !graphql && (p.truncate_body_at_fraction.is_some() || malformed);
        let slow = p.slow_response_chunk_size.zip(p.slow_response_chunk_delay.as_ref());
        if !corrupt && slow.is_none() && !graphql {
            return;
        }
        let logged_map = logged.as_object_mut();
        let mut out = logged_map.cloned().unwrap_or_default();
        if graphql {
            let envelope = graphql_envelope(p, &reply.body);
            reply.status = 200;
            reply.reason = None;
            replace_header(reply, "content-type", "application/json");
            drop_content_length(reply, &mut out);
            reply.body = Bytes::from(envelope.clone());
            out.insert("statusCode".into(), json!(200));
            out.remove("reasonPhrase");
            logged_header(&mut out, "content-type", "application/json");
            out.insert("body".into(), json!(envelope));
            injected(state, "graphql");
        } else if corrupt {
            let mut body = reply.body.to_vec();
            if let Some(fraction) = p.truncate_body_at_fraction {
                body.truncate((body.len() as f64 * fraction).floor() as usize);
                injected(state, "truncate");
            }
            if malformed {
                body.extend_from_slice(br#"{"__chaos_malformed__":"#);
                injected(state, "malformed");
            }
            if let Some(content_type) = reply.header("content-type").map(str::to_string).or_else(|| reply.default_content_type.take()) {
                replace_header(reply, "content-type", &content_type);
                logged_header(&mut out, "content-type", &content_type);
            }
            drop_content_length(reply, &mut out);
            // A byte-array body logs as base64.
            out.insert("body".into(), json!(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &body)));
            reply.body = Bytes::from(body);
        }
        if let Some((size, delay)) = slow {
            reply.chunk_size = Some(size as usize);
            reply.chunk_delay = crate::action::delay(delay);
            drop_content_length(reply, &mut out);
            let options = out.entry("connectionOptions").or_insert_with(|| json!({}));
            if let Some(o) = options.as_object_mut() {
                o.insert("chunkDelay".into(), delay.clone());
                o.insert("chunkSize".into(), json!(size));
                o.sort_keys();
            }
            injected(state, "slow");
        }
        *logged = Value::Object(out);
    }
}

/// `removeHeader("content-length")` on both the reply and its logged form.
fn drop_content_length(reply: &mut Reply, out: &mut Map<String, Value>) {
    reply.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
    if let Some(Value::Object(h)) = out.get_mut("headers") {
        h.retain(|k, _| !k.eq_ignore_ascii_case("content-length"));
    }
}

fn replace_header(reply: &mut Reply, name: &str, value: &str) {
    reply.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    reply.headers.push((name.to_string(), value.to_string()));
}

/// `replaceHeader` on the logged response's `headers` map.
fn logged_header(out: &mut Map<String, Value>, name: &str, value: &str) {
    let headers = out.entry("headers").or_insert_with(|| json!({}));
    if let Some(h) = headers.as_object_mut() {
        h.retain(|k, _| !k.eq_ignore_ascii_case(name));
        h.insert(name.to_string(), json!([value]));
    }
    // `HttpResponseDTO`'s property order.
    const ORDER: &[&str] = &["statusCode", "reasonPhrase", "headers", "trailers", "cookies", "body", "delay", "connectionOptions", "timing"];
    let mut rest = std::mem::take(out);
    for key in ORDER {
        if let Some(v) = rest.remove(*key) {
            out.insert((*key).to_string(), v);
        }
    }
    out.extend(rest);
}

/// A chaos-made response (`withHeader("content-type", "application/json")`, then `Retry-After` when set).
fn synthetic(status: i32, body: &str, retry_after: Option<&str>) -> Replacement {
    let mut reply = Reply::status(status as u32);
    reply.headers.push(("content-type".into(), "application/json".into()));
    let mut headers = Map::new();
    headers.insert("content-type".into(), json!(["application/json"]));
    if let Some(retry) = retry_after.filter(|r| !r.is_empty()) {
        reply.headers.push(("Retry-After".into(), retry.to_string()));
        headers.insert("Retry-After".into(), json!([retry]));
    }
    reply.body = Bytes::from(body.to_string());
    Replacement { reply, logged: json!({"statusCode": status, "headers": headers, "body": body}) }
}

/// `buildGraphqlErrorEnvelope`: `data` null, or the original JSON body under `graphqlNullifyData=false`.
fn graphql_envelope(p: &HttpChaosProfile, body: &[u8]) -> String {
    let data = if p.graphql_nullify_data == Some(false) && !body.is_empty() {
        crate::json::parse_lenient(body).unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    let mut error = Map::new();
    error.insert("message".into(), json!(p.graphql_error_message.clone().unwrap_or_else(|| "simulated GraphQL error".into())));
    if let Some(code) = &p.graphql_error_code {
        error.insert("extensions".into(), json!({"code": code}));
    }
    let mut root = Map::new();
    root.insert("data".into(), data);
    root.insert("errors".into(), Value::Array(vec![Value::Object(error)]));
    Value::Object(root).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_draws_match_java_util_random() {
        // new Random(1).nextDouble() = 0.7308781907032909
        assert!(!should_inject(Some(0.5), Some(1)));
        assert!(should_inject(Some(0.74), Some(1)));
    }

    #[test]
    fn count_window() {
        let p = HttpChaosProfile { succeed_first: Some(1), fail_request_count: Some(1), ..Default::default() };
        assert_eq!((1..=3).map(|n| p.count_window_eligible(n)).collect::<Vec<_>>(), vec![false, true, false]);
    }
}

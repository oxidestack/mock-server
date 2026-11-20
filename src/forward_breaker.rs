//! `ForwardRetryPolicy` and `ForwardCircuitBreaker` (`HttpForwardAction.sendRequest`): the retry of an idempotent
//! forward after a transient failure (`forwardProxyRetryCount`, `forwardProxyRetryBackoffMillis`), and the per-upstream
//! (`host:port`) breaker that fails forwards fast with a 503 after `forwardProxyCircuitBreakerFailureThreshold`
//! consecutive failures, for `forwardProxyCircuitBreakerWindowMillis`, then lets one half-open trial through
//! (`forwardProxyCircuitBreakerEnabled`). Both cover the matched forward actions only; an unmatched request proxied to
//! its `Host` is sent once, whatever the breaker says.
//!
//! Upstream's breaker is a JVM singleton; here each server keeps its own (in its `ForwardConnections`), which only
//! differs for several servers in one process. A reset clears it.

use std::collections::HashMap;
use std::time::Duration;

use crate::client::{self, Upstream};
use crate::Config;

/// RFC 7231's idempotent methods (`ForwardRetryPolicy.IDEMPOTENT_METHODS`): POST and PATCH are never retried.
const IDEMPOTENT_METHODS: [&str; 6] = ["GET", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"];

/// `ForwardRetryPolicy.isIdempotent`: case-insensitive, surrounding blanks ignored.
pub fn is_idempotent(method: &str) -> bool {
    let method = method.trim().to_ascii_uppercase();
    IDEMPOTENT_METHODS.contains(&method.as_str())
}

/// `ForwardRetryPolicy.isTransientFailure`: a 502, 503 or 504, or a failure to get a response, except one the
/// upstream's next answer would meet again (a header-limit refusal, `HeaderLimitExceededException`; a response that
/// could not be decoded, `UndecodableResponseException`), one that never reached the upstream (a connection that
/// could not be set up from the configuration, `ClientConfigurationException`) and one through an upstream proxy that
/// could not be reached (`proxy_unreachable`, `UpstreamProxyUnreachableException`). A target the SSRF policy blocks
/// (`ForwardTargetBlockedException`) is refused before [`crate::forward`] sends anything, so never gets here.
pub fn is_transient(result: &Result<Upstream, client::Error>, proxy_unreachable: bool) -> bool {
    match result {
        Ok(upstream) => matches!(upstream.status, 502..=504),
        Err(client::Error::HeaderLimit(..) | client::Error::Undecodable(_) | client::Error::SetUp(_)) => false,
        Err(_) => !proxy_unreachable,
    }
}

/// `ForwardCircuitBreaker.isNeutral`: a failure that says nothing about the upstream's health (a configuration error,
/// a header-limit refusal, an unreachable upstream proxy), recorded with [`Breaker::neutral`]. An undecodable response
/// is not retried but still counts as a failure.
pub fn is_neutral(result: &Result<Upstream, client::Error>, proxy_unreachable: bool) -> bool {
    match result {
        Ok(_) => false,
        Err(client::Error::HeaderLimit(..) | client::Error::SetUp(_)) => true,
        Err(_) => proxy_unreachable,
    }
}

/// `forwardProxyRetryCount` (default 0, negative read as 0).
pub fn retry_count(config: &Config) -> u32 {
    config.int_property("forwardProxyRetryCount", 0).clamp(0, i64::from(u32::MAX)) as u32
}

/// `forwardProxyRetryBackoffMillis` (default 100, negative read as 0): attempt `n`'s retry waits `n` times it.
pub fn retry_backoff(config: &Config) -> Duration {
    Duration::from_millis(config.int_property("forwardProxyRetryBackoffMillis", 100).max(0) as u64)
}

fn enabled(config: &Config) -> bool {
    config.bool_property("forwardProxyCircuitBreakerEnabled", false)
}

/// `forwardProxyCircuitBreakerFailureThreshold` (default 5, at least 1).
fn threshold(config: &Config) -> u32 {
    config.int_property("forwardProxyCircuitBreakerFailureThreshold", 5).clamp(1, i64::from(u32::MAX)) as u32
}

/// `forwardProxyCircuitBreakerWindowMillis` (default 30 000, at least 1).
fn window(config: &Config) -> Duration {
    Duration::from_millis(config.int_property("forwardProxyCircuitBreakerWindowMillis", 30_000).max(1) as u64)
}

/// One upstream's breaker (`UpstreamState`): failures since the last success, when it opened (`openedAtMillis`, epoch
/// millis on the server clock, `TimeService::currentTimeMillis`; 0 while closed, so a breaker opened at a clock frozen
/// at the epoch stays closed, as upstream's), and whether the half-open trial is out.
#[derive(Default)]
struct UpstreamState {
    failures: u32,
    opened: i64,
    trial: bool,
}

/// The breakers of one server, by upstream `host:port`. Only degraded upstreams are kept: a success evicts its entry.
#[derive(Default)]
pub struct Breaker {
    upstreams: parking_lot::Mutex<HashMap<String, UpstreamState>>,
}

impl Breaker {
    /// `allowRequest`: closed lets everything through, open fails fast within the window, and once the window has
    /// elapsed (half-open) exactly one trial goes through.
    pub fn allow(&self, config: &Config, key: &str) -> bool {
        if !enabled(config) {
            return true;
        }
        let mut upstreams = self.upstreams.lock();
        let Some(state) = upstreams.get_mut(key) else { return true };
        if state.opened == 0 {
            return true;
        }
        if crate::clock::now_millis().wrapping_sub(state.opened) < window(config).as_millis() as i64 {
            return false;
        }
        !std::mem::replace(&mut state.trial, true)
    }

    /// `recordSuccess`: closes the breaker (a healthy upstream leaves no entry).
    pub fn success(&self, state: &crate::state::State, key: &str) {
        if !enabled(&state.config) {
            return;
        }
        let was_open = self.upstreams.lock().remove(key).is_some_and(|s| s.opened != 0);
        if was_open {
            let key = crate::cors_origin::escape_for_log(key);
            crate::log::info_plain(state, &format!("forward circuit breaker closed for upstream {key} after a successful trial request"));
        }
    }

    /// `recordFailure`: a failed half-open trial re-opens the breaker for another window; otherwise the failure is
    /// counted and the threshold opens it.
    pub fn failure(&self, state: &crate::state::State, key: &str) {
        let config = &state.config;
        if !enabled(config) {
            return;
        }
        // the key is request data (the Host header can carry CR/LF): escaped so it cannot forge log lines
        let logged_key = crate::cors_origin::escape_for_log(key);
        let message = {
            let mut upstreams = self.upstreams.lock();
            let upstream = upstreams.entry(key.to_string()).or_default();
            if std::mem::replace(&mut upstream.trial, false) && upstream.opened != 0 {
                upstream.opened = crate::clock::now_millis();
                Some(format!("forward circuit breaker re-opened for upstream {logged_key} after a failed half-open trial request"))
            } else {
                upstream.failures += 1;
                let threshold = threshold(config);
                (upstream.failures >= threshold && upstream.opened == 0).then(|| {
                    upstream.opened = crate::clock::now_millis();
                    format!(
                        "forward circuit breaker opened for upstream {logged_key} after {} consecutive failures (threshold {threshold}) — failing requests fast for {} ms",
                        upstream.failures,
                        window(config).as_millis()
                    )
                })
            }
        };
        if let Some(message) = message {
            crate::log::warn_plain(state, &message);
        }
    }

    /// `recordNeutral`: the state and failure count stay as they were; only a half-open trial is released, so the next
    /// request probes the upstream.
    pub fn neutral(&self, config: &Config, key: &str) {
        if !enabled(config) {
            return;
        }
        if let Some(state) = self.upstreams.lock().get_mut(key) {
            state.trial = false;
        }
    }

    /// `openCircuitCount`: upstreams whose breaker is open or half-open (the `mock_server_upstream_circuit_open` gauge).
    pub fn open_count(&self) -> usize {
        self.upstreams.lock().values().filter(|s| s.opened != 0).count()
    }

    /// Server reset.
    pub fn reset(&self) {
        self.upstreams.lock().clear();
    }
}

/// The breaker's own answer to a forward it fails fast (`upstream circuit breaker open for <key>`).
pub fn open_response(key: &str) -> Upstream {
    Upstream { status: 503, reason: "Service Unavailable".into(), body: format!("upstream circuit breaker open for {key}").into(), untimed: true, ..Default::default() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotent_methods_are_the_rfc_7231_ones() {
        for m in ["GET", "get", " Head ", "OPTIONS", "PUT", "DELETE", "TRACE"] {
            assert!(is_idempotent(m), "{m}");
        }
        for m in ["POST", "PATCH", "", "CONNECT"] {
            assert!(!is_idempotent(m), "{m}");
        }
    }
}

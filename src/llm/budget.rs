//! `LlmCostBudgetMonitor`: the cost-budget circuit-breaker for LLM forwarding. Every served `httpLlmResponse`
//! completion and every forwarded LLM completion adds its estimated cost (`LlmPricing.estimateCostUsd`) to a running
//! total (`HttpActionHandler.recordLlmUsageMetrics`); once that total reaches `llmCostBudgetUsd`, a forward to an LLM
//! provider (matched forward actions, proxy-pass mappings and the unmatched proxy) is answered with a 429 instead of
//! being sent. Mock completions themselves are never blocked. A budget of zero or less, or an unparsable one,
//! blocks nothing (fail-open). `PUT /mockserver/reset` clears the total (`HttpState.reset`), not the Prometheus
//! `mock_server_llm_cost_budget_tripped_total` counter.
//!
//! Observed on the oracle (`tests/scenarios/llm_cost_budget.json`): a completion forwarded to this server's own mock
//! counts twice, once when the mock serves it and once when the forward's response is parsed.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;

/// The monitor's counts, held by the server's [`crate::metrics::Metrics`] (shared through its configuration).
#[derive(Default)]
pub struct CostBudget {
    /// `cumulativeCostMicroUsd`: USD × 1e6, each increment truncated as Java's `(long)` cast does.
    cumulative_micro_usd: AtomicI64,
    /// `tripCount`, cleared by a reset.
    trips: AtomicI64,
    /// `mock_server_llm_cost_budget_tripped_total`, never cleared.
    tripped_total: AtomicU64,
    /// `HttpActionHandler.usageLogTimes`: when each provider and model last logged a streamed call it could not count.
    usage_log_times: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// `HttpActionHandler.countedPolledCompletionIds`: the background completions already counted, so a later poll
    /// or fetch of one is not counted again. Not cleared by a reset, as upstream's is not.
    counted_polled: std::sync::Mutex<PolledIds>,
}

/// `COUNTED_POLLED_COMPLETION_IDS`: an access-ordered map that drops its eldest entry past 10 000.
#[derive(Default)]
struct PolledIds {
    /// Each key's last access, by `tick`.
    keys: std::collections::HashMap<String, u64>,
    tick: u64,
}

impl PolledIds {
    const CAPACITY: usize = 10_000;

    /// `putIfAbsent` on the access-ordered map: whether `key` was absent. Either way it is now the most recent.
    fn put_if_absent(&mut self, key: &str) -> bool {
        self.tick += 1;
        let absent = self.keys.insert(key.to_string(), self.tick).is_none();
        if self.keys.len() > Self::CAPACITY && let Some(eldest) = self.keys.iter().min_by_key(|(_, t)| **t).map(|(k, _)| k.clone()) {
            self.keys.remove(&eldest);
        }
        absent
    }
}

impl CostBudget {
    /// `recordCost`: a cost that is unknown or not positive is ignored.
    pub fn record_cost(&self, cost_usd: Option<f64>) {
        let Some(cost) = cost_usd.filter(|c| *c > 0.0) else { return };
        self.cumulative_micro_usd.fetch_add((cost * 1_000_000.0) as i64, Ordering::Relaxed);
    }

    /// `isBudgetExceeded`: a positive budget the running total has reached.
    pub fn exceeded(&self, budget_usd: f64) -> bool {
        budget_usd > 0.0 && self.cumulative_micro_usd.load(Ordering::Relaxed) >= (budget_usd * 1_000_000.0) as i64
    }

    /// `checkBudgetOrNull`: the 429 once the budget is exceeded (counting the trip), else `None`.
    pub fn check(&self, budget_usd: f64) -> Option<Reply> {
        if !self.exceeded(budget_usd) {
            return None;
        }
        self.trips.fetch_add(1, Ordering::Relaxed);
        self.tripped_total.fetch_add(1, Ordering::Relaxed);
        let cumulative = self.cumulative_usd();
        let body = format!(
            "{{\"error\":{{\"type\":\"cost_budget_exceeded\",\"message\":\"LLM cost budget exceeded (cumulative ${} >= budget ${})\",\"cumulative_cost_usd\":{},\"budget_usd\":{}}}}}",
            fixed(4, cumulative),
            fixed(4, budget_usd),
            fixed(6, cumulative),
            fixed(6, budget_usd)
        );
        let mut reply = Reply::status(429);
        reply.headers.push(("content-type".into(), "application/json".into()));
        reply.body = bytes::Bytes::from(body);
        Some(reply)
    }

    /// `getCumulativeCostUsd`.
    pub fn cumulative_usd(&self) -> f64 {
        self.cumulative_micro_usd.load(Ordering::Relaxed) as f64 / 1_000_000.0
    }

    /// `getTripCount`.
    pub fn trips(&self) -> i64 {
        self.trips.load(Ordering::Relaxed)
    }

    /// `Metrics.getLlmCostBudgetTrippedCount`.
    pub fn tripped_total(&self) -> u64 {
        self.tripped_total.load(Ordering::Relaxed)
    }

    /// `usageLogDue`: one line a minute for each provider and model, so a client that never sends usage does not flood
    /// the log. `now` is `TimeService.nanoTime()` ([`crate::Config::nano_time`]).
    pub fn usage_log_due(&self, provider: &str, model: Option<&str>, counted: bool, now: std::time::Instant) -> bool {
        const USAGE_LOG_KEYS: usize = 256;
        let model_key: String = model.map(|m| m.encode_utf16().take(crate::llm::stream_usage::MAX_TEXT_CHARS).collect::<Vec<u16>>()).map(|u| String::from_utf16_lossy(&u)).unwrap_or_default();
        let key = format!("{provider}|{counted}|{model_key}");
        let mut times = self.usage_log_times.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if times.get(&key).is_some_and(|last| now.duration_since(*last) < std::time::Duration::from_secs(60)) {
            return false;
        }
        if times.len() >= USAGE_LOG_KEYS {
            times.clear();
        }
        times.insert(key, now);
        true
    }

    /// `claimPolledCompletion`'s claim: `provider|id` taken, so a concurrent poll of the same completion is not counted
    /// too. `None` when it was already counted (or claimed).
    pub(crate) fn claim_polled(&self, provider: &str, id: &str) -> Option<String> {
        let key = format!("{provider}|{id}");
        self.counted_polled.lock().unwrap_or_else(std::sync::PoisonError::into_inner).put_if_absent(&key).then_some(key)
    }

    /// Releases a claim whose usage could not be counted.
    pub(crate) fn release_polled(&self, key: &str) {
        self.counted_polled.lock().unwrap_or_else(std::sync::PoisonError::into_inner).keys.remove(key);
    }

    /// Marks a completion counted from its stream, so fetching it later does not count it again.
    pub(crate) fn mark_polled_counted(&self, provider: &str, id: &str) {
        self.counted_polled.lock().unwrap_or_else(std::sync::PoisonError::into_inner).put_if_absent(&format!("{provider}|{id}"));
    }

    /// `reset`: the total and the trip count, not the Prometheus counter.
    pub fn reset(&self) {
        self.cumulative_micro_usd.store(0, Ordering::Relaxed);
        self.trips.store(0, Ordering::Relaxed);
    }
}

/// `String.format(Locale.ROOT, "%.<digits>f", value)`: the shortest decimal rounded half-up.
fn fixed(digits: usize, value: f64) -> String {
    let format = format!("%.{digits}f");
    java_compat::text::string_format(&java_compat::text::Locale::root(), &format, &[java_compat::lang::JValue::Double(value)]).unwrap_or_else(|_| format!("{value:.digits$}"))
}

/// `configuration.llmCostBudgetUsd()`: -1 (disabled) when unset or unparsable.
pub fn budget_usd(state: &State) -> f64 {
    state.config.property("llmCostBudgetUsd").and_then(|v| v.trim().parse::<f64>().ok()).unwrap_or(-1.0)
}

/// `budgetEnabled`: a budget is configured, so LLM usage is accounted even without telemetry.
pub fn enabled(state: &State) -> bool {
    budget_usd(state) > 0.0
}

/// `recordLlmUsageMetrics`: the completion's priced usage, counted by `Metrics.incrementLlmTokens` (when
/// `llmMetricsEnabled`) and added to the running total.
pub(crate) fn record(state: &State, provider: &str, model: Option<&str>, input_tokens: i64, output_tokens: i64) {
    record_at(state, provider, model, input_tokens, output_tokens, false);
}

/// [`record`] for a call that went to a Vertex AI host when `vertex_ai`, priced at Vertex AI's rates.
pub(crate) fn record_at(state: &State, provider: &str, model: Option<&str>, input_tokens: i64, output_tokens: i64, vertex_ai: bool) {
    let cost = crate::llm::report::estimate_cost_at(provider, model, input_tokens, output_tokens, vertex_ai);
    if crate::metrics::llm_metrics_enabled(&state.config) {
        state.config.metrics.llm_tokens(Some(provider), model, input_tokens, output_tokens, cost);
    }
    state.config.metrics.cost_budget.record_cost(cost);
}

/// A served `httpLlmResponse` completion (`HttpLlmResponseActionHandler`, streamed or not): priced by the action's
/// provider and model with the completion's (possibly inferred) usage. Moderation, embedding and rerank answers carry
/// no completion and cost nothing.
pub fn served(state: &State, llm: &crate::llm::Llm) {
    if !llm.has_completion || llm.moderation.is_some() || llm.embedding.is_some() || llm.rerank.is_some() {
        return;
    }
    let usage = llm.completion.usage.as_ref();
    let tokens = |k: &str| usage.and_then(|u| u.get(k)).and_then(serde_json::Value::as_i64).unwrap_or(0);
    record(state, llm.provider.as_deref().unwrap_or("OPENAI"), llm.model.as_deref(), tokens("inputTokens"), tokens("outputTokens"));
}

/// `checkLlmCostBudgetByHost`: with a budget configured, a request headed for an LLM provider — `explicit_host` (a
/// forward action's own target) with the request's path, else the request's own socket address or `Host` — is
/// answered with the 429 once the budget is exceeded. `None`: send it.
pub fn check(state: &State, explicit_host: Option<&str>, request: &HttpRequest) -> Option<Reply> {
    let host = match explicit_host {
        Some(host) => Some(host.to_string()),
        None => request_host(request),
    };
    check_at(state, host.as_deref(), &request.path)
}

/// `handleProxyPass`'s check: the mapping's target host with the rewritten path.
pub fn check_proxy_pass(state: &State, mapping: &crate::forward::ProxyPass, request: &HttpRequest) -> Option<Reply> {
    if budget_usd(state) <= 0.0 {
        return None;
    }
    check_at(state, Some(mapping.host()), &mapping.target_path(&request.path))
}

fn check_at(state: &State, host: Option<&str>, path: &str) -> Option<Reply> {
    let budget = budget_usd(state);
    if budget <= 0.0 {
        return None;
    }
    crate::telemetry::sniff(state, host, path)?;
    let reply = state.config.metrics.cost_budget.check(budget)?;
    let cumulative = state.config.metrics.cost_budget.cumulative_usd();
    // `LOG.warn` (SLF4J): on the console only, never in the event log.
    crate::log::warn_plain(state, &format!("LLM cost budget exceeded: cumulative ${} >= budget ${} — blocking LLM forward", fixed(6, cumulative), fixed(6, budget)));
    Some(reply)
}

/// `blockIfLlmCostBudgetExceeded` for a matched forward action: the action's own target host when it names one
/// (`resolveForwardTargetHost`), else the request's.
pub fn check_forward(state: &State, forward: &crate::forward::Forward, request: &HttpRequest) -> Option<Reply> {
    if budget_usd(state) <= 0.0 {
        return None;
    }
    let host = forward_target_host(forward);
    check(state, host.as_deref(), request)
}

/// `resolveForwardTargetHost`: `httpForward`, `httpForwardValidateAction` and `httpForwardWithFallback` name their
/// host; `httpOverrideForwardedRequest` its override's socket address, else its `Host` header without the port. The
/// others are resolved at run time, so `None`.
fn forward_target_host(forward: &crate::forward::Forward) -> Option<String> {
    use crate::forward::Forward;
    match forward {
        Forward::To { target, .. } | Forward::Validate { target, .. } | Forward::WithFallback { target, .. } => target.host.clone(),
        Forward::Override { request_override: Some(o), .. } => {
            if let Some(host) = o.get("socketAddress").and_then(|s| s.get("host")).and_then(serde_json::Value::as_str).filter(|h| !h.is_empty()) {
                return Some(host.to_string());
            }
            first_header(o.get("headers")?, "Host").filter(|h| !h.is_empty()).map(|h| strip_port_from_host(&h).to_string())
        }
        _ => None,
    }
}

/// `getFirstHeader` of a request's JSON headers, map form (`{"Host": ["a"]}`) or list form
/// (`[{"name": "Host", "values": ["a"]}]`), the name compared case-insensitively.
fn first_header(headers: &serde_json::Value, name: &str) -> Option<String> {
    let first = |values: &serde_json::Value| match values {
        serde_json::Value::Array(a) => a.first().and_then(serde_json::Value::as_str).map(str::to_string),
        serde_json::Value::String(s) => Some(s.clone()),
        _ => None,
    };
    match headers {
        serde_json::Value::Object(map) => map.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).and_then(|(_, v)| first(v)),
        serde_json::Value::Array(list) => list
            .iter()
            .find(|h| h.get("name").and_then(serde_json::Value::as_str).is_some_and(|n| n.eq_ignore_ascii_case(name)))
            .and_then(|h| first(h.get("values")?)),
        _ => None,
    }
}

/// `LlmProviderSniffer.extractHost`: the socket address, else `Host`.
fn request_host(request: &HttpRequest) -> Option<String> {
    if let Some((host, ..)) = request.socket_address.as_ref().filter(|(h, ..)| !h.is_empty()) {
        return Some(host.clone());
    }
    request.first_header("Host").filter(|h| !h.is_empty()).map(str::to_string)
}

/// `HttpActionHandler.stripPortFromHost`: `[addr]:port` and `[addr]` give the address inside the brackets, a single
/// colon separates a port, and a bare IPv6 address (several colons) is kept whole.
pub fn strip_port_from_host(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return match rest.find(']') {
            Some(close) => &rest[..close],
            None => host,
        };
    }
    match host.find(':') {
        Some(first) if Some(first) == host.rfind(':') => &host[..first],
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_port_from_host_matches_upstream() {
        // HttpActionHandlerLlmCostBudgetTest.stripPortFromHost*
        assert_eq!(strip_port_from_host("api.openai.com:443"), "api.openai.com");
        assert_eq!(strip_port_from_host("api.openai.com"), "api.openai.com");
        assert_eq!(strip_port_from_host("[::1]:8080"), "::1");
        assert_eq!(strip_port_from_host("[::1]"), "::1");
        assert_eq!(strip_port_from_host("::1"), "::1");
        assert_eq!(strip_port_from_host("[]"), "");
    }

    #[test]
    fn records_truncated_micro_usd_and_trips_at_the_budget() {
        let budget = CostBudget::default();
        budget.record_cost(None);
        budget.record_cost(Some(-1.0));
        budget.record_cost(Some(0.0));
        assert_eq!(budget.cumulative_usd(), 0.0);
        budget.record_cost(Some(0.0000019));
        assert_eq!(budget.cumulative_usd(), 0.000001);
        assert!(!budget.exceeded(1.0));
        budget.record_cost(Some(0.999999));
        assert!(budget.exceeded(1.0), "reaching the budget exactly trips it");
        assert!(!budget.exceeded(0.0) && !budget.exceeded(-1.0), "no budget never trips");
        let reply = budget.check(1.0).expect("429");
        assert_eq!(reply.status, 429);
        assert_eq!(
            std::str::from_utf8(&reply.body).unwrap(),
            r#"{"error":{"type":"cost_budget_exceeded","message":"LLM cost budget exceeded (cumulative $1.0000 >= budget $1.0000)","cumulative_cost_usd":1.000000,"budget_usd":1.000000}}"#
        );
        assert_eq!((budget.trips(), budget.tripped_total()), (1, 1));
        budget.reset();
        assert_eq!((budget.cumulative_usd(), budget.trips(), budget.tripped_total()), (0.0, 0, 1));
        assert!(budget.check(1.0).is_none());
    }
}

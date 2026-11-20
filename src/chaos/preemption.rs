//! `PreemptionSimulator` and `/mockserver/preemption`: the cordon that turns new data-plane exchanges away.

use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use super::bind::{self, Bean, BindError};
use super::{now_millis, pretty, read_tree};
use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;

/// `PreemptionRequest.Mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreemptionMode {
    Reject503,
    GoAway,
    Both,
}

impl PreemptionMode {
    fn name(self) -> &'static str {
        match self {
            PreemptionMode::Reject503 => "reject503",
            PreemptionMode::GoAway => "goaway",
            PreemptionMode::Both => "both",
        }
    }

    pub fn emits_go_away(self) -> bool {
        matches!(self, PreemptionMode::GoAway | PreemptionMode::Both)
    }

    pub fn rejects_new(self) -> bool {
        matches!(self, PreemptionMode::Reject503 | PreemptionMode::Both)
    }
}

#[derive(Clone)]
struct Cordon {
    mode: PreemptionMode,
    drain_millis: i64,
    ttl_millis: i64,
    last_stream_id: Option<i64>,
    drain_deadline: i64,
    /// 0: no automatic uncordon.
    ttl_expiry: i64,
}

#[derive(Default)]
struct PreemptionRequest {
    drain_millis: Option<i64>,
    mode: Option<PreemptionMode>,
    ttl_millis: Option<i64>,
    last_stream_id: Option<i64>,
}

/// `PreemptionSimulator`.
#[derive(Default)]
pub struct Preemption {
    cordon: Mutex<Option<Cordon>>,
}

/// What the cordon does to a new data-plane exchange.
pub struct CordonDecision {
    /// Emit a GOAWAY first (HTTP/2 only), advertising this last stream id (`None`: the connection's own).
    pub go_away: Option<Option<u32>>,
    /// Turn the exchange away with this 503.
    pub reject: Option<Reply>,
}

impl Preemption {
    /// The active cordon; an expired TTL uncordons.
    fn active(&self) -> Option<Cordon> {
        let mut cordon = self.cordon.lock();
        if cordon.as_ref().is_some_and(|c| c.ttl_expiry > 0 && now_millis() >= c.ttl_expiry) {
            *cordon = None;
        }
        cordon.clone()
    }

    pub fn is_cordoned(&self) -> bool {
        self.active().is_some()
    }

    /// `start`: the mode defaults to `both`, the drain to `stopDrainMillis`; both windows are clamped to
    /// `[0, preemptionSimulationMaxDrainMillis]` (a cap of 0 means none).
    fn start(&self, state: &State, request: &PreemptionRequest) -> Cordon {
        let cap = state.config.int_property("preemptionSimulationMaxDrainMillis", 86_400_000).max(0);
        let clamp = |v: i64| {
            let v = v.max(0);
            if cap > 0 && v > cap { cap } else { v }
        };
        let drain_millis = clamp(request.drain_millis.unwrap_or_else(|| state.config.int_property("stopDrainMillis", 15_000)));
        let ttl_millis = clamp(request.ttl_millis.unwrap_or(0));
        let now = now_millis();
        let cordon = Cordon {
            mode: request.mode.unwrap_or(PreemptionMode::Both),
            drain_millis,
            ttl_millis,
            last_stream_id: request.last_stream_id,
            drain_deadline: now.saturating_add(drain_millis),
            ttl_expiry: if ttl_millis > 0 { now.saturating_add(ttl_millis) } else { 0 },
        };
        *self.cordon.lock() = Some(cordon.clone());
        cordon
    }

    /// `start` with a `PreemptionRequest` in JSON.
    pub fn start_json(&self, state: &State, request: &Value) -> Result<(), String> {
        let request = parse_request(&request.to_string())?;
        self.start(state, &request);
        Ok(())
    }

    pub fn uncordon(&self) {
        *self.cordon.lock() = None;
    }

    fn drain_remaining_millis(cordon: Option<&Cordon>) -> i64 {
        cordon.map_or(0, |c| (c.drain_deadline - now_millis()).max(0))
    }

    pub fn status(&self, state: &State) -> Value {
        let cordon = self.active();
        let label = match &cordon {
            None => "inactive",
            Some(c) if now_millis() < c.drain_deadline => "draining",
            Some(_) => "drained",
        };
        let mut o = Map::new();
        o.insert("state".into(), json!(label));
        o.insert("inFlight".into(), json!(state.requests_in_flight()));
        o.insert("drainRemainingMillis".into(), json!(Self::drain_remaining_millis(cordon.as_ref())));
        if let Some(c) = &cordon {
            o.insert("mode".into(), json!(c.mode.name()));
        }
        Value::Object(o)
    }

    /// `HttpRequestHandler`'s cordon check for a data-plane request (control-plane paths are exempt); `None` when
    /// no simulation is active or `connectionLifecycleChaosEnabled` is off.
    pub fn decide(&self, state: &State, request: &HttpRequest) -> Option<CordonDecision> {
        if request.path.starts_with("/mockserver") || !super::tcp::lifecycle_chaos_enabled(state) {
            return None;
        }
        let cordon = self.active()?;
        let go_away = cordon.mode.emits_go_away().then(|| cordon.last_stream_id.map(|id| id.clamp(0, i32::MAX as i64) as u32));
        let reject = cordon.mode.rejects_new().then(|| {
            let retry_after = ((Self::drain_remaining_millis(Some(&cordon)) + 999) / 1000).max(1);
            // Written straight to the channel: no CORS, no `version`.
            let body = r#"{"error":"server is draining (simulated preemption); retry elsewhere"}"#;
            let mut reply = Reply::status(503);
            reply.headers.push(("connection".into(), "close".into()));
            reply.headers.push(("Retry-After".into(), retry_after.to_string()));
            reply.headers.push(("content-type".into(), "application/json; charset=utf-8".into()));
            reply.headers.push(("content-length".into(), body.len().to_string()));
            reply.body = body.into();
            reply.close = true;
            reply
        });
        Some(CordonDecision { go_away, reject })
    }
}

/// `handlePreemptionPut`: an empty (or `null`) body starts a simulation with every default.
pub fn put(state: &State, request: &HttpRequest) -> Reply {
    let body = request.body_json_or_xml_str();
    let parsed = if body.trim().is_empty() { Ok(PreemptionRequest::default()) } else { parse_request(&body) };
    let preemption = match parsed {
        Ok(p) => p,
        Err(e) => {
            let message = format!("invalid preemption request: {e}");
            return Reply::api_body(400, "application/json", crate::json::compact(&serde_json::json!({"error": message})));
        }
    };
    let cordon = state.chaos.preemption.start(state, &preemption);
    let ttl = if cordon.ttl_millis > 0 { format!(", ttl {}ms", cordon.ttl_millis) } else { String::new() };
    let format = format!("started preemption simulation (mode {}, drain {}ms{ttl})", cordon.mode.name(), cordon.drain_millis);
    super::log(state, request, crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, format));
    pretty(&state.chaos.preemption.status(state))
}

/// `PreemptionRequest` bound by MockServer's `ObjectMapper.readValue` (case-insensitive properties and enums; an
/// unknown mode reads as null, so the default).
fn parse_request(body: &str) -> Result<PreemptionRequest, String> {
    let v = read_tree(body, false)?;
    if v.is_null() {
        return Ok(PreemptionRequest::default());
    }
    let bind = || -> Result<PreemptionRequest, BindError> {
        let bean = Bean::of(&v, "org.mockserver.model.PreemptionRequest")?;
        let mode = bean.enumeration("mode", "org.mockserver.model.PreemptionRequest$Mode", &["reject503", "goaway", "both"])?;
        Ok(PreemptionRequest {
            drain_millis: bean.long("drainMillis")?,
            mode: mode.map(|i| [PreemptionMode::Reject503, PreemptionMode::GoAway, PreemptionMode::Both][i]),
            ttl_millis: bean.long("ttlMillis")?,
            last_stream_id: bean.long("lastStreamId")?,
        })
    };
    bind().map_err(|e| e.source_text(bind::location(body, e.property())))
}

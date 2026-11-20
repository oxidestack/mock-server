//! `TcpChaosProfile` and the response-path faults `NettyResponseWriter` applies from it.

use std::time::Duration;

use serde_json::{Map, Value};

use super::bind::Bean;
use super::{HostProfile, ProfileError, Wording};
use crate::handler::Outcome;
use crate::state::State;

/// `TcpChaosProfile`: every field optional, as registered.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TcpChaosProfile {
    pub latency_ms: Option<i64>,
    pub down: Option<bool>,
    pub bandwidth_bytes_per_sec: Option<i64>,
    pub slow_close: Option<bool>,
    pub timeout: Option<bool>,
    pub reset_peer: Option<bool>,
    pub slicer_chunk_size: Option<i32>,
    pub limit_data_bytes: Option<i64>,
    pub reset_mid_response: Option<bool>,
    pub reset_after_response_chunks: Option<i32>,
    /// `DelayDTO` JSON in its canonical form.
    pub slow_close_delay: Option<Value>,
    pub http2_go_away: Option<bool>,
    pub http2_go_away_error_code: Option<i64>,
    pub http2_go_away_last_stream_id: Option<i64>,
}

impl TcpChaosProfile {
    /// The host-scoped close delay, sampled now.
    pub fn slow_close_delay(&self) -> Option<Duration> {
        self.slow_close_delay.as_ref().and_then(crate::action::delay).map(|d| d.fixed)
    }
}

impl HostProfile for TcpChaosProfile {
    const NAMESPACE: &'static str = "chaos-tcp";
    const WORDING: Wording = Wording { what: "TCP-layer chaos", invalid: "invalid TCP chaos profile", failed: "TCP chaos", list_key: "hosts" };

    /// `TcpChaosProfileDTO` read from a request's `chaos` object, then `buildObject`'s range checks.
    fn from_json(v: &Value) -> Result<TcpChaosProfile, ProfileError> {
        let dto = Bean::of(v, "org.mockserver.serialization.model.TcpChaosProfileDTO")?;
        let slow_close_delay = dto.bean("slowCloseDelay", "org.mockserver.serialization.model.DelayDTO")?.map(|d| crate::canonical::delay(&Value::Object(d.map().clone())));
        let profile = TcpChaosProfile {
            latency_ms: dto.long("latencyMs")?,
            down: dto.boolean("down")?,
            bandwidth_bytes_per_sec: dto.long("bandwidthBytesPerSec")?,
            slow_close: dto.boolean("slowClose")?,
            timeout: dto.boolean("timeout")?,
            reset_peer: dto.boolean("resetPeer")?,
            slicer_chunk_size: dto.int("slicerChunkSize")?,
            limit_data_bytes: dto.long("limitDataBytes")?,
            reset_mid_response: dto.boolean("resetMidResponse")?,
            reset_after_response_chunks: dto.int("resetAfterResponseChunks")?,
            slow_close_delay,
            http2_go_away: dto.boolean("http2GoAway")?,
            http2_go_away_error_code: dto.long("http2GoAwayErrorCode")?,
            http2_go_away_last_stream_id: dto.long("http2GoAwayLastStreamId")?,
        };
        // `buildObject` calls the `withX` setters in field order; the first failing check wins.
        let at_least = |name: &str, value: Option<i64>, min: i64| match value {
            Some(v) if v < min => Err(ProfileError::Invalid(format!("{name} must be >= {min}, got {v}"))),
            _ => Ok(()),
        };
        at_least("bandwidthBytesPerSec", profile.bandwidth_bytes_per_sec, 1)?;
        at_least("slicerChunkSize", profile.slicer_chunk_size.map(i64::from), 1)?;
        at_least("limitDataBytes", profile.limit_data_bytes, 1)?;
        at_least("resetAfterResponseChunks", profile.reset_after_response_chunks.map(i64::from), 0)?;
        at_least("http2GoAwayErrorCode", profile.http2_go_away_error_code, 0)?;
        at_least("http2GoAwayLastStreamId", profile.http2_go_away_last_stream_id, 0)?;
        Ok(profile)
    }

    /// `TcpChaosProfileDTO` as Jackson writes it: non-null properties, alphabetical.
    fn to_json(&self) -> Value {
        let mut o = Map::new();
        let mut put = |k: &str, v: Option<Value>| {
            if let Some(v) = v {
                o.insert(k.to_string(), v);
            }
        };
        put("bandwidthBytesPerSec", self.bandwidth_bytes_per_sec.map(Value::from));
        put("down", self.down.map(Value::from));
        put("http2GoAway", self.http2_go_away.map(Value::from));
        put("http2GoAwayErrorCode", self.http2_go_away_error_code.map(Value::from));
        put("http2GoAwayLastStreamId", self.http2_go_away_last_stream_id.map(Value::from));
        put("latencyMs", self.latency_ms.map(Value::from));
        put("limitDataBytes", self.limit_data_bytes.map(Value::from));
        put("resetAfterResponseChunks", self.reset_after_response_chunks.map(Value::from));
        put("resetMidResponse", self.reset_mid_response.map(Value::from));
        put("resetPeer", self.reset_peer.map(Value::from));
        put("slicerChunkSize", self.slicer_chunk_size.map(Value::from));
        put("slowClose", self.slow_close.map(Value::from));
        put("slowCloseDelay", self.slow_close_delay.clone());
        put("timeout", self.timeout.map(Value::from));
        Value::Object(o)
    }

    fn merge(&self, patch: &TcpChaosProfile) -> TcpChaosProfile {
        fn pick<T: Clone>(patch: &Option<T>, base: &Option<T>) -> Option<T> {
            patch.clone().or_else(|| base.clone())
        }
        TcpChaosProfile {
            latency_ms: pick(&patch.latency_ms, &self.latency_ms),
            down: pick(&patch.down, &self.down),
            bandwidth_bytes_per_sec: pick(&patch.bandwidth_bytes_per_sec, &self.bandwidth_bytes_per_sec),
            slow_close: pick(&patch.slow_close, &self.slow_close),
            timeout: pick(&patch.timeout, &self.timeout),
            reset_peer: pick(&patch.reset_peer, &self.reset_peer),
            slicer_chunk_size: pick(&patch.slicer_chunk_size, &self.slicer_chunk_size),
            limit_data_bytes: pick(&patch.limit_data_bytes, &self.limit_data_bytes),
            reset_mid_response: pick(&patch.reset_mid_response, &self.reset_mid_response),
            reset_after_response_chunks: pick(&patch.reset_after_response_chunks, &self.reset_after_response_chunks),
            slow_close_delay: pick(&patch.slow_close_delay, &self.slow_close_delay),
            http2_go_away: pick(&patch.http2_go_away, &self.http2_go_away),
            http2_go_away_error_code: pick(&patch.http2_go_away_error_code, &self.http2_go_away_error_code),
            http2_go_away_last_stream_id: pick(&patch.http2_go_away_last_stream_id, &self.http2_go_away_last_stream_id),
        }
    }

    fn has_any_fault(&self) -> bool {
        self.latency_ms.is_some_and(|v| v > 0)
            || self.down == Some(true)
            || self.bandwidth_bytes_per_sec.is_some_and(|v| v > 0)
            || self.slow_close == Some(true)
            || self.timeout == Some(true)
            || self.reset_peer == Some(true)
            || self.slicer_chunk_size.is_some_and(|v| v > 0)
            || self.limit_data_bytes.is_some_and(|v| v > 0)
            || self.reset_mid_response == Some(true)
            || self.slow_close_delay.is_some()
            || self.http2_go_away == Some(true)
    }
}

/// `connectionLifecycleChaosEnabled` (default true): the master switch for response-path faults and the cordon.
pub fn lifecycle_chaos_enabled(state: &State) -> bool {
    state.config.bool_property("connectionLifecycleChaosEnabled", true)
}

/// `NettyResponseWriter.resolveLifecycleProfile`: the profile for the request's `Host`, when lifecycle chaos is
/// enabled and some profile is active.
pub fn lifecycle_profile(state: &State, host: &str) -> Option<TcpChaosProfile> {
    if host.is_empty() || !lifecycle_chaos_enabled(state) || state.chaos.tcp.active_count() == 0 {
        return None;
    }
    state.chaos.tcp.get(host)
}

/// `NettyResponseWriter.writeAndCloseSocket`'s response-path faults: a GOAWAY before the response (`http2GoAway`),
/// a reset once it is written (`resetMidResponse`, a "drop" toward auto-halt under
/// `connectionLifecycleAutoHaltCountsRst`), and a delay before a close (`slowCloseDelay`, unless the expectation set
/// its own `closeSocketDelay`).
pub fn apply_lifecycle(state: &State, profile: &TcpChaosProfile, mut outcome: Outcome) -> Outcome {
    if let Outcome::Respond(reply) = &mut outcome {
        if profile.reset_mid_response == Some(true) {
            reply.reset_connection = true;
            if state.config.bool_property("connectionLifecycleAutoHaltCountsRst", true) {
                super::http::injected(state, "drop");
            }
        }
        if reply.close_delay.is_none() {
            reply.close_delay = profile.slow_close_delay();
        }
    }
    if profile.http2_go_away == Some(true) {
        let last_stream_id = profile.http2_go_away_last_stream_id.map(|id| id.min(i32::MAX as i64) as u32);
        let error_code = profile.http2_go_away_error_code.unwrap_or(0).clamp(0, u32::MAX as i64) as u32;
        outcome = Outcome::GoAway { last_stream_id, error_code, then: Box::new(outcome) };
    }
    outcome
}

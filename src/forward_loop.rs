//! The forward loop guard (`ForwardLoopGuard`, upstream #50, #65, #69): every forward action, `proxyPassMappings`
//! entry and forwarded WebSocket upgrade appends this instance's id to `x-mockserver-forwarded-by`, like a received-by
//! entry in a `Via` header; a request already carrying it `forwardLoopMaxHops` times (default 10, 0 or less turns the
//! guard and the header off) is answered `508 Loop Detected` in place of being forwarded again. Only this instance's
//! own entries count, so forwarding through other MockServers is unaffected.

use crate::request::HttpRequest;
use crate::state::State;

pub const HEADER: &str = "x-mockserver-forwarded-by";
pub const LOOP_DETECTED: u32 = 508;

/// What sent the request onward, which the 508 names with the setting to check (`ForwardLoopGuard.Route`).
#[derive(Clone, Copy)]
pub enum Route {
    Forward,
    ProxyPass,
}

impl Route {
    fn cause(self) -> &'static str {
        match self {
            Route::Forward => "the forward's target leads back to this MockServer, where the request matched a forward again: check the forward's host and port",
            Route::ProxyPass => "the proxyPassMappings entry's target leads back to this MockServer, where the request matched the mapping again: check the mapping's target URI",
        }
    }
}

/// `"MockServer_" + Long.toHexString(random) + Long.toHexString(random)`: one per server, not the `x-forwarded-by`
/// value (whose request goes unlogged).
pub fn new_instance_id() -> String {
    use rand_core::RngCore;
    let mut rng = rand_core::OsRng;
    format!("MockServer_{:x}{:x}", rng.next_u64(), rng.next_u64())
}

/// `forwardLoopMaxHops`, a negative value read as 0.
fn max_hops(state: &State) -> usize {
    state.config.int_property("forwardLoopMaxHops", 10).max(0) as usize
}

/// How many times this instance has already forwarded `received`; an intermediary may have folded the header's
/// values into one comma-separated line.
fn hops(state: &State, received: &HttpRequest) -> usize {
    let id = state.forward_loop_id.as_str();
    received
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(HEADER))
        .flat_map(|(_, values)| values)
        .filter(|value| value.contains(id))
        .map(|value| value.split(',').filter(|entry| entry.trim() == id).count())
        .sum()
}

/// `loopDetectedReason`: the 508's body.
fn reason(hops: usize, route: Route) -> String {
    format!(
        "MockServer did not forward this request because it has already forwarded it {hops} times, so {}, or raise forwardLoopMaxHops if the repeated forwarding is intended",
        route.cause()
    )
}

/// `refuseLoop`: the 508's body when `received` may not be forwarded again, logged as a WARN about it; `None` when the
/// forward may go ahead.
pub fn refuse(state: &State, received: &HttpRequest, route: Route) -> Option<String> {
    let max = max_hops(state);
    if max == 0 {
        return None;
    }
    let hops = hops(state, received);
    if hops < max {
        return None;
    }
    let body = reason(hops, route);
    let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, "returning 508 Loop Detected in place of forwarding request:{}because:{}")
        .args([crate::recorded::Arg::from(crate::recorded::logged(received)), body.clone().into()]);
    crate::forward::log_warn_about(state, entry, received);
    Some(body)
}

/// The 508 as the forward's upstream answer: MockServer answered it itself, so the client measured nothing.
pub fn loop_detected(body: String) -> crate::client::Upstream {
    crate::client::Upstream { status: LOOP_DETECTED, reason: "Loop Detected".into(), body: body.into(), untimed: true, loop_detected: true, ..Default::default() }
}

/// The header values a request forwarded on from `received` carries: its entries plus this instance's; `None` when the
/// guard is off.
pub fn forwarded_entries(state: &State, received: &HttpRequest) -> Option<Vec<String>> {
    if max_hops(state) == 0 {
        return None;
    }
    let mut entries: Vec<String> = received.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(HEADER)).flat_map(|(_, v)| v.iter().map(str::to_string)).collect();
    entries.push(state.forward_loop_id.clone());
    Some(entries)
}

/// `markForwarded`: `to_send`'s header replaced (removed, then appended last) by [`forwarded_entries`], so a template or
/// callback that builds a new request cannot reset the count. A no-op when the guard is off.
pub fn mark(state: &State, received: &HttpRequest, to_send: &mut HttpRequest) {
    if let Some(entries) = forwarded_entries(state, received) {
        to_send.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(HEADER));
        to_send.headers.push((HEADER.into(), entries));
    }
}

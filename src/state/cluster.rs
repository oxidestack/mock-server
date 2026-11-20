//! The clustered half of the expectation store (upstream `RequestMatchers` `:772,1066,1246-1330,2035-2200` and `HttpState.java:263-345`): when the state backend
//! is clustered, the node-local [`crate::store::Store`] is a view over the backend's `expectations` store.
//!
//! - every add writes through (`expectationBackend.put(id, new ExpectationEntry(expectation))`), every removal
//!   removes the id, `reset` clears the backend;
//! - a remote change reaches this node as an [`InvalidationListener`] call (`HttpState` registers one that calls
//!   `requestMatchers.reconcileFromBackend()`), which diffs the backend against the local list: evict what the
//!   backend no longer holds, add what it holds and the node does not, rebuild what has a newer version;
//! - a limited-`Times` expectation is consumed through a backend compare-and-set of the shared remaining counter
//!   (`consumeTimesViaBackendCas`, at most [`MAX_CAS_RETRIES`] attempts), so `Times.exactly(N)` is served exactly
//!   N times across the fleet. The counter is the backend's `sharedTimesCounters` entry for the id (seeded on every
//!   add, removed with the expectation, cleared by `reset`), so a consume never writes to the `expectations` cache
//!   and never moves its eviction policy; that cache is bounded too, and a counter it evicted fails closed;
//! - nothing is read from the backend at start-up: state transfer into a joining node fires no listener event,
//!   so a late joiner restores only from `blobs` (`ExpectationFileSystemPersistence`), never from
//!   live events.
//!
//! No lock of the store is ever held across a call into this module's backend (the rule of upstream's issue
//! #2579): a backend call is a network round trip, and a remote node's listener may need that lock to answer it.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::Value;

use crate::state_backend::{ExpectationEntry, InvalidationListener, StateBackend};
use crate::store::Expectation;

/// `RequestMatchers.MAX_CAS_RETRIES`.
pub const MAX_CAS_RETRIES: usize = 20;
/// `CAS_BACKOFF_BASE_NANOS`, `CAS_BACKOFF_CAP_NANOS`, `MAX_BACKOFF_SHIFT`.
const CAS_BACKOFF_BASE_NANOS: u64 = 150_000;
const CAS_BACKOFF_CAP_NANOS: u64 = 1_000_000;
const MAX_BACKOFF_SHIFT: usize = 20;

/// The outcome of consuming one use of a limited-`Times` expectation through the backend
/// (`ConsumeTimesResult`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Consumed {
    /// This node won the use; `remaining` is what the shared counter holds now.
    Served { remaining: i64 },
    /// The shared counter is zero or the entry is gone: exhausted fleet-wide.
    Exhausted,
    /// Every one of [`MAX_CAS_RETRIES`] attempts lost a race: not served rather than risking a double serve.
    Contended,
    /// The `sharedTimesCounters` entry is gone: exhausted (fails closed). `warning` is the WARN to log when the
    /// expectation itself is still there with uses left, the first time for its id (the counter cache evicted it).
    Discarded { warning: Option<String> },
}

/// Builds a node-local expectation from an entry's JSON.
type BuildExpectation = dyn Fn(&Value) -> Option<Expectation> + Send + Sync;

pub struct ClusterLink {
    pub(crate) backend: Arc<dyn StateBackend>,
    /// `Configuration.clusterSharedTimesEnabled()`, read each time (it changes at runtime).
    shared_times: Box<dyn Fn() -> bool + Send + Sync>,
    /// Builds a node-local expectation from the JSON an `ExpectationEntry` carries.
    build: Box<BuildExpectation>,
    /// Logs a WARN event (`mockServerLogger.logEvent` at `Level.WARN`).
    warn: Box<dyn Fn(String) + Send + Sync>,
    /// `warnedEvictedTimesCounters`: the ids whose evicted counter was already reported.
    warned_evicted_counters: Mutex<std::collections::HashSet<String>>,
    /// `lastReconciledVersion`.
    versions: Mutex<HashMap<String, u64>>,
    /// `addsInFlight`: ids whose local insert has happened and whose backend put has not returned.
    in_flight: Mutex<HashMap<String, usize>>,
    /// Concurrent reconcile passes would apply each other's stale snapshots; a pass only reads this node's replica,
    /// so serialising them cannot wait on another node.
    pub(crate) reconcile_gate: Mutex<()>,
}

impl ClusterLink {
    pub fn new(
        backend: Arc<dyn StateBackend>, shared_times: impl Fn() -> bool + Send + Sync + 'static, build: impl Fn(&Value) -> Option<Expectation> + Send + Sync + 'static,
        warn: impl Fn(String) + Send + Sync + 'static,
    ) -> Arc<ClusterLink> {
        Arc::new(ClusterLink {
            backend,
            shared_times: Box::new(shared_times),
            build: Box::new(build),
            warn: Box::new(warn),
            warned_evicted_counters: Mutex::new(Default::default()),
            versions: Mutex::new(HashMap::new()),
            in_flight: Mutex::new(HashMap::new()),
            reconcile_gate: Mutex::new(()),
        })
    }

    pub fn shared_times_enabled(&self) -> bool {
        (self.shared_times)()
    }

    pub fn compile(&self, json: &Value) -> Option<Expectation> {
        (self.build)(json)
    }

    pub fn last_version(&self, id: &str) -> Option<u64> {
        self.versions.lock().get(id).copied()
    }

    pub fn set_version(&self, id: &str, version: u64) {
        self.versions.lock().insert(id.to_string(), version);
    }

    pub fn forget_version(&self, id: &str) {
        self.versions.lock().remove(id);
    }

    pub fn forget_all_versions(&self) {
        self.versions.lock().clear();
    }

    /// `beginInFlight` for each id (ref-counted).
    pub fn begin(&self, ids: &[String]) {
        let mut in_flight = self.in_flight.lock();
        for id in ids {
            *in_flight.entry(id.clone()).or_default() += 1;
        }
    }

    /// `endInFlight` for each id.
    pub fn end(&self, ids: &[String]) {
        let mut in_flight = self.in_flight.lock();
        for id in ids {
            if let Some(n) = in_flight.get_mut(id) {
                *n -= 1;
                if *n == 0 {
                    in_flight.remove(id);
                }
            }
        }
    }

    pub fn is_in_flight(&self, id: &str) -> bool {
        self.in_flight.lock().contains_key(id)
    }

    pub fn in_flight_snapshot(&self) -> std::collections::HashSet<String> {
        self.in_flight.lock().keys().cloned().collect()
    }

    /// `consumeTimesViaBackendCas`. With a `sharedTimesCounters` store (`consumeSharedTimesCounter`): read the
    /// counter, fail when it is gone or at zero, otherwise swap in one fewer. Without one (the legacy path), the same
    /// on the remaining count of the `ExpectationEntry` itself. A lost swap backs off and retries from a fresh read.
    pub fn consume_times(&self, id: &str) -> Consumed {
        if let Some(counters) = self.backend.shared_times_counters() {
            for attempt in 0..MAX_CAS_RETRIES {
                let Some(current) = counters.get(id) else {
                    return Consumed::Discarded { warning: self.warn_if_counter_evicted_while_live(id) };
                };
                if current.value <= 0 {
                    return Consumed::Exhausted;
                }
                let remaining = current.value - 1;
                match counters.try_compare_and_set(id, current.version, remaining) {
                    Ok(true) => return Consumed::Served { remaining: remaining as i64 },
                    Ok(false) => backoff_before_retry(attempt),
                    Err(e) => {
                        eprintln!("ERROR state backend: shared Times CAS for {id}: {e}");
                        return Consumed::Contended;
                    }
                }
            }
            return Consumed::Contended;
        }
        let store = self.backend.expectations();
        for attempt in 0..MAX_CAS_RETRIES {
            let Some(current) = store.get(id) else { return Consumed::Exhausted };
            if current.value.remaining_times <= 0 {
                return Consumed::Exhausted;
            }
            let remaining = current.value.remaining_times - 1;
            let decremented = ExpectationEntry { remaining_times: remaining, ..current.value };
            match store.try_compare_and_set(id, current.version, decremented) {
                Ok(true) => return Consumed::Served { remaining },
                Ok(false) => backoff_before_retry(attempt),
                Err(e) => {
                    eprintln!("ERROR state backend: shared Times CAS for {id}: {e}");
                    return Consumed::Contended;
                }
            }
        }
        Consumed::Contended
    }

    /// Whether a use of a clustered limited expectation is taken from the shared counter and not also from the
    /// node-local count (`consumeMatchLocally`): so with a `sharedTimesCounters` store, the local count stays as added.
    pub fn counts_uses_in_backend_only(&self) -> bool {
        self.backend.shared_times_counters().is_some()
    }

    /// `warnIfCounterEvictedWhileLive`: the counter is gone but the expectation is still there with uses left, so the
    /// counter cache evicted it; the WARN once per id.
    fn warn_if_counter_evicted_while_live(&self, id: &str) -> Option<String> {
        let live = self.backend.expectations().get(id).is_some_and(|entry| entry.value.remaining_times > 0);
        (live && self.warned_evicted_counters.lock().insert(id.to_string())).then(|| {
            format!(
                "shared Times counter for expectation {id} was discarded under memory pressure (clustered counter cache full); this expectation will no longer match on this node. Raise maxExpectations so the shared-Times counter cache can retain every limited-Times expectation."
            )
        })
    }

    /// Logs a WARN event now.
    pub fn warn(&self, text: String) {
        (self.warn)(text)
    }

    /// `seedSharedTimesCounter`, before the expectation is put: the counter is (re)set to the configured remaining
    /// uses of a limited expectation, and removed for an unlimited one. A no-op without a counter store.
    pub fn seed_shared_times(&self, id: &str, remaining: Option<i64>) {
        let Some(counters) = self.backend.shared_times_counters() else { return };
        self.warned_evicted_counters.lock().remove(id);
        match remaining {
            Some(n) => {
                counters.put(id, n.clamp(i32::MIN as i64, i32::MAX as i64) as i32);
            }
            None => {
                counters.remove(id);
            }
        }
    }

    /// `invalidateSharedTimesCounter`: the expectation was removed or evicted, so its counter goes too.
    pub fn invalidate_shared_times(&self, id: &str) {
        if let Some(counters) = self.backend.shared_times_counters() {
            counters.remove(id);
            self.warned_evicted_counters.lock().remove(id);
        }
    }

    /// `reset`'s `sharedTimesBackend.clear()`.
    pub fn clear_shared_times(&self) {
        if let Some(counters) = self.backend.shared_times_counters() {
            counters.clear();
        }
    }
}

/// `backoffBeforeCasRetry`: a park drawn uniformly from `[0, window]`, the window doubling from 150 µs up to 1 ms;
/// none after the last attempt.
fn backoff_before_retry(attempt: usize) {
    if attempt + 1 >= MAX_CAS_RETRIES {
        return;
    }
    let window = (CAS_BACKOFF_BASE_NANOS << attempt.min(MAX_BACKOFF_SHIFT)).min(CAS_BACKOFF_CAP_NANOS);
    let mut bytes = [0u8; 8];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
    let park = u64::from_le_bytes(bytes) % (window + 1);
    if park > 0 {
        std::thread::sleep(std::time::Duration::from_nanos(park));
    }
}

/// `HttpState`'s `InvalidationListener`: a change anywhere in the cluster, or a clear, reconciles this node's view.
pub struct StoreInvalidation {
    pub reconcile: Box<dyn Fn() + Send + Sync>,
}

impl InvalidationListener for StoreInvalidation {
    fn on_changed(&self, _key: &str) {
        (self.reconcile)();
    }

    fn on_cleared(&self) {
        (self.reconcile)();
    }
}

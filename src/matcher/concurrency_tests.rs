//! Rust ports of the upstream matcher and expectation-store properties the oracle-diff harness cannot see: concurrency
//! invariants, lifecycle gating and evaluation-order independence.
//!
//! Upstream's matcher is mutable (`update(expectation)` rebuilds it in place) and carries a lazy-removal CAS flag, a
//! request-side memo and a fail-fast mode. Ours is immutable once compiled, replaced whole by `Store::upsert`, and
//! `matches` always runs every field in order, so each upstream test is ported as the invariant its fix protects, on
//! the Rust seam that now carries it (`RequestMatcher`, `Store`):
//!
//! | upstream class | here |
//! |---|---|
//! | `HttpRequestPropertiesMatcherConcurrencyTest` | `replaced_expectation_is_never_seen_torn` |
//! | `HttpRequestPropertiesMatcherNotFailFastCubeTest` | `not_cube_agrees_with_truth_table` |
//! | `HttpRequestsPropertiesMatcherLifecycleTest` (5) | `lifecycle_*` |
//! | `RequestSideMatcherMemoizationTest` (5) | `evaluation_*`, `matching_does_not_consume_the_request` |
//! | `AbstractHttpRequestMatcherTest` (3) | `removal_*` |
//! | `RequestMatchersConcurrentAddTest` (5) | `concurrent_*` |
//!
//! Every concurrent test synchronises on a `Barrier` or a join, runs a fixed amount of work and asserts an invariant
//! that holds on every interleaving: nothing here sleeps or measures time.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use bytes::Bytes;
use serde_json::{Value, json};

use super::{Mode, RequestMatcher};
use crate::request::HttpRequest;
use crate::state::State;
use crate::store::{Expectation, Store};

fn state() -> Arc<State> {
    State::new(crate::Config::for_tests(), Vec::new())
}

fn expectation(state: &State, definition: Value) -> Expectation {
    crate::control::compile_expectation(state, definition.as_object().expect("an expectation object"))
}

/// An expectation on `method path` answering 200 with its own id as body.
fn on(state: &State, id: &str, method: &str, path: &str) -> Expectation {
    expectation(state, json!({"id": id, "httpRequest": {"method": method, "path": path}, "httpResponse": {"statusCode": 200, "body": id}}))
}

fn request(method: &str, path: &str) -> HttpRequest {
    HttpRequest { method: method.into(), path: path.into(), ..HttpRequest::default() }
}

fn header(request: &mut HttpRequest, name: &str, value: &str) {
    request.headers.push((name.to_string(), vec![value.to_string()]));
}

/// Runs `work` and fails the test when it does not finish in `seconds`: a watchdog for deadlocks, never a
/// synchronisation point (the work itself is joined, not waited out).
fn finishes_within<T: Send + 'static>(seconds: u64, work: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    rx.recv_timeout(Duration::from_secs(seconds)).expect("deadlock: the work did not finish")
}

// --- HttpRequestPropertiesMatcherConcurrencyTest ----------------------------------------------------------------

#[test]
fn compiled_matcher_is_shareable_across_threads() {
    fn shareable<T: Send + Sync>() {}
    shareable::<RequestMatcher>();
    shareable::<Store>();
    shareable::<Expectation>();
}

/// Criterion A is `POST /alpha`, B is `PUT /beta`, the request is `POST /beta`: it matches neither, so a clean read is
/// always "no match". Only a half-replaced expectation (A's method with B's path) could match. Upstream flips one
/// matcher's compiled criterion between A and B while readers match; here the one expectation id is re-upserted
/// between A and B while readers scan the store.
#[test]
fn replaced_expectation_is_never_seen_torn() {
    const READERS: usize = 4;
    const FLIPS: usize = 1_000;
    const SCANS: usize = 1_000;
    let state = state();
    let (a, b) = (
        || expectation(&state, json!({"id": "x", "httpRequest": {"method": "POST", "path": "/alpha"}, "httpResponse": {"statusCode": 200}})),
        || expectation(&state, json!({"id": "x", "httpRequest": {"method": "PUT", "path": "/beta"}, "httpResponse": {"statusCode": 200}})),
    );
    let store = Store::default();
    let probe = request("POST", "/beta");
    // The premise, before racing: neither criterion matches the probe on its own.
    store.upsert(vec![a()]);
    assert!(store.first_match(&probe, None).is_none(), "criterion A must not match the probe");
    store.upsert(vec![b()]);
    assert!(store.first_match(&probe, None).is_none(), "criterion B must not match the probe");

    let torn = AtomicUsize::new(0);
    let scans = AtomicUsize::new(0);
    let go = Barrier::new(READERS + 1);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            go.wait();
            for i in 0..FLIPS {
                store.upsert(vec![if i % 2 == 0 { a() } else { b() }]);
            }
        });
        for _ in 0..READERS {
            scope.spawn(|| {
                go.wait();
                for _ in 0..SCANS {
                    if store.first_match(&probe, None).is_some() {
                        torn.fetch_add(1, Ordering::Relaxed);
                    }
                    scans.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    assert_eq!(torn.load(Ordering::Relaxed), 0, "a scan matched a request that matches neither criterion: a torn read");
    assert_eq!(scans.load(Ordering::Relaxed), READERS * SCANS, "every scan ran");
    assert_eq!(store.all().len(), 1, "the one id is still one expectation");
}

// --- HttpRequestPropertiesMatcherNotFailFastCubeTest ------------------------------------------------------------

/// The NOT x single-mismatching-field cube. Upstream crosses three NOT flags (the matcher's, the expectation
/// request's and the incoming request's) with fail-fast on and off; a wire request carries no `not` and our matcher
/// has no fail-fast switch, so the cube here is the expectation's `not` x which field mismatches, and the two
/// independent evaluation paths a field failure is read through: `matches` (the verdict), and `differences` (the
/// fail-fast, first-failing-field report) with `all_differences` (the collect-all report, nothing failing fast).
/// The verdict is the base match negated once per NOT flag, and the two reports agree whether any field failed.
#[test]
fn not_cube_agrees_with_truth_table() {
    for not in [false, true] {
        for mismatch in ["none", "method", "path", "header", "body"] {
            let mut definition = json!({"method": "GET", "path": "/test", "headers": {"X-Test": ["value"]}, "body": "expected-body"});
            if not {
                definition["not"] = json!(true);
            }
            let matcher = RequestMatcher::compile(&definition);
            let mut incoming = request("GET", "/test");
            header(&mut incoming, "X-Test", "value");
            incoming.body = Bytes::from_static(b"expected-body");
            match mismatch {
                "method" => incoming.method = "POST".into(),
                "path" => incoming.path = "/other".into(),
                // Dropping the required header is a clean base mismatch.
                "header" => incoming.headers.clear(),
                "body" => incoming.body = Bytes::from_static(b"different-body"),
                _ => {}
            }
            let base = mismatch == "none";
            let cell = format!("not={not}, mismatch={mismatch}");
            assert_eq!(matcher.matches(&incoming, Mode::DataPlane), base != not, "verdict, {cell}");
            // The same criterion without the NOT is the base match itself.
            let plain = RequestMatcher::compile(&json!({"method": "GET", "path": "/test", "headers": {"X-Test": ["value"]}, "body": "expected-body"}));
            assert_eq!(plain.matches(&incoming, Mode::DataPlane), base, "base match, {cell}");
            if !not {
                assert_eq!(matcher.differences(&incoming).is_empty(), base, "fail-fast report, {cell}");
                assert_eq!(matcher.all_differences(&incoming).is_empty(), base, "collect-all report, {cell}");
            }
            if !base && !not {
                // Exactly the one field that was flipped fails, in the fail-fast report as in the collect-all one.
                let fail_fast = matcher.differences(&incoming);
                let all = matcher.all_differences(&incoming);
                assert_eq!(fail_fast.len(), 1, "fail-fast names one field, {cell}");
                assert_eq!(all.len(), 1, "collect-all names the same single field, {cell}");
                assert_eq!(fail_fast[0].0, all[0].0, "both reports name the same field, {cell}");
            }
        }
    }
}

// --- HttpRequestsPropertiesMatcherLifecycleTest -----------------------------------------------------------------

const SPEC: &str = r#"{"openapi":"3.0.0","info":{"title":"test","version":"1.0"},"paths":{"/pets":{"get":{"operationId":"listPets","responses":{"200":{"description":"ok"}}}}}}"#;

fn openapi(state: &State, extra: Value) -> Expectation {
    let mut definition = json!({"id": "pets", "httpRequest": {"specUrlOrPayload": SPEC}, "httpResponse": {"statusCode": 200}});
    for (key, value) in extra.as_object().expect("an object") {
        definition[key] = value.clone();
    }
    expectation(state, definition)
}

/// `shouldMatchWhileExpectationIsActive`.
#[test]
fn lifecycle_matches_while_active() {
    let state = state();
    let store = Store::default();
    store.upsert(vec![openapi(&state, json!({"timeToLive": {"timeUnit": "HOURS", "timeToLive": 1}}))]);
    assert!(store.first_match(&request("GET", "/pets"), None).is_some());
}

/// `shouldNotMatchOnceTimeToLiveHasExpired`: the end date is pinned in the past, so expiry needs no sleep.
#[test]
fn lifecycle_stops_matching_once_time_to_live_has_expired() {
    let state = state();
    let store = Store::default();
    let past = crate::chaos::now_millis() - 1_000;
    let expired = openapi(&state, json!({"timeToLive": {"timeUnit": "HOURS", "timeToLive": 1, "endDate": past}}));
    assert!(!expired.is_active(), "precondition: the expectation has expired");
    store.upsert(vec![expired]);
    assert!(store.first_match(&request("GET", "/pets"), None).is_none(), "an expired OpenAPI expectation must not be served");
}

/// `shouldNotMatchOnceRemainingMatchesAreExhausted`.
#[test]
fn lifecycle_stops_matching_once_remaining_matches_are_exhausted() {
    let state = state();
    let store = Store::default();
    store.upsert(vec![openapi(&state, json!({"times": {"remainingTimes": 1}}))]);
    let first = store.first_match(&request("GET", "/pets"), None).expect("the one use is served");
    assert!(!first.is_active(), "precondition: the expectation is exhausted");
    store.post_process(&first);
    assert!(store.first_match(&request("GET", "/pets"), None).is_none(), "an exhausted OpenAPI expectation must not be served");
}

/// `shouldNotMatchEveryRequestWhenNoMatchersCouldBeDerived`: a spec that yields no operation must not hijack the
/// server by matching every request. Upstream builds that matcher straight from a Java `OpenAPIDefinition`, a path the
/// wire cannot reach: over HTTP a *blank* `specUrlOrPayload` is dropped when the expectation is deserialised, leaving
/// `"httpRequest": { }`, which matches everything (the oracle, 8.0.0, stores it that way and answers any request from
/// it), and we compile the same. So the wire-reachable half of the property is a spec that parses but declares no
/// operation: it derives no matcher and matches nothing.
#[test]
fn lifecycle_spec_without_operations_does_not_match_every_request_on_the_data_plane() {
    let matcher = RequestMatcher::compile(&json!({"specUrlOrPayload": r#"{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{}}"#}));
    assert!(!matcher.matches(&request("GET", "/anything-at-all"), Mode::DataPlane));
    let bare = RequestMatcher::compile(&json!({"specUrlOrPayload": r#"{"openapi":"3.0.0"}"#}));
    assert!(!bare.matches(&request("GET", "/anything-at-all"), Mode::DataPlane));
}

/// The blank-spec half as the oracle shows it on the wire: the definition collapses to the empty one.
#[test]
fn lifecycle_blank_spec_collapses_to_the_empty_definition_as_the_oracle_does() {
    let state = state();
    let blank = expectation(&state, json!({"id": "blank", "httpRequest": {"specUrlOrPayload": ""}, "httpResponse": {"statusCode": 200}}));
    assert_eq!(blank.canonical["httpRequest"], json!({}), "oracle: httpRequest is an empty object");
    assert!(blank.matcher.matches(&request("GET", "/anything-at-all"), Mode::DataPlane));
}

/// `shouldMatchEveryRequestOnControlPlaneWhenNoMatchersCouldBeDerived`: as a filter (`clear`, `retrieve`, `verify`)
/// the same definition restricts nothing.
#[test]
fn lifecycle_blank_spec_is_an_empty_filter_on_the_control_plane() {
    let matcher = RequestMatcher::compile(&json!({"specUrlOrPayload": ""}));
    assert!(matcher.matches(&request("GET", "/anything-at-all"), Mode::ControlPlane));
}

// --- RequestSideMatcherMemoizationTest --------------------------------------------------------------------------
//
// Upstream converts the request's header/cookie/query collections once and reuses the conversion across the
// matchers of a scan, invalidating it when a collection is mutated mid-scan. We keep no conversion on the request, so
// the property that remains is the one the memo must never break: a matcher's verdict depends on the matcher and the
// request alone, never on which matchers ran before it, and matching leaves the request as it found it.

fn scan_request() -> HttpRequest {
    let mut r = request("GET", "/memo");
    header(&mut r, "keyOne", "valueOne");
    header(&mut r, "keyTwo", "valueTwo");
    r.cookies = vec![("keyOne".into(), "valueOne".into()), ("keyTwo".into(), "valueTwo".into())];
    r.query = vec![("status".into(), vec!["active,pending".into()])];
    r
}

fn scan_matchers() -> Vec<(RequestMatcher, bool)> {
    let cases = [
        (json!({"headers": {"keyOne": ["valueOne"]}}), true),
        (json!({"headers": {"keyTwo": ["valueTwo"]}}), true),
        (json!({"headers": {"missing": ["value"]}}), false),
        (json!({"cookies": {"keyOne": "valueOne"}}), true),
        (json!({"cookies": {"keyTwo": "valueTwo"}}), true),
        (json!({"cookies": {"keyThree": "valueThree"}}), false),
        (json!({"queryStringParameters": {"status": ["active,pending"]}}), true),
        (json!({"queryStringParameters": {"status": ["active", "pending"]}}), false),
    ];
    cases.into_iter().map(|(definition, expected)| (RequestMatcher::compile(&definition), expected)).collect()
}

/// One request, many candidate matchers: the first evaluation must not change a later one, in any order, at any
/// repetition, for either plane (upstream memoises the data-plane and control-plane conversions in separate slots).
#[test]
fn evaluation_is_independent_of_order_and_repetition() {
    let request = scan_request();
    let matchers = scan_matchers();
    for mode in [Mode::DataPlane, Mode::ControlPlane] {
        let alone: Vec<bool> = matchers.iter().map(|(m, _)| m.matches(&request, mode)).collect();
        // Every matcher, evaluated last after all the others, then in reverse, then twice in a row.
        for (i, (matcher, _)) in matchers.iter().enumerate() {
            for (j, (other, _)) in matchers.iter().enumerate() {
                if i != j {
                    other.matches(&request, mode);
                }
            }
            assert_eq!(matcher.matches(&request, mode), alone[i], "matcher {i} after the others, {mode:?}");
        }
        for (i, (matcher, _)) in matchers.iter().enumerate().rev() {
            assert_eq!(matcher.matches(&request, mode), alone[i], "matcher {i} in reverse, {mode:?}");
            assert_eq!(matcher.matches(&request, mode), alone[i], "matcher {i} repeated, {mode:?}");
        }
    }
}

#[test]
fn evaluation_gives_the_expected_verdict_on_the_data_plane() {
    let request = scan_request();
    for (i, (matcher, expected)) in scan_matchers().iter().enumerate() {
        assert_eq!(matcher.matches(&request, Mode::DataPlane), *expected, "matcher {i}");
    }
}

/// Shared across threads, the same request gives the same verdicts: nothing about evaluating it is cached on it.
#[test]
fn evaluation_is_stable_across_threads() {
    let request = Arc::new(scan_request());
    let matchers = Arc::new(scan_matchers());
    let go = Arc::new(Barrier::new(4));
    let handles: Vec<_> = (0..4)
        .map(|n| {
            let (request, matchers, go) = (request.clone(), matchers.clone(), go.clone());
            std::thread::spawn(move || {
                go.wait();
                for _ in 0..200 {
                    // Each thread walks the matchers from its own offset, so they interleave differently.
                    for k in 0..matchers.len() {
                        let (matcher, expected) = &matchers[(k + n) % matchers.len()];
                        assert_eq!(matcher.matches(&request, Mode::DataPlane), *expected);
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("a verdict changed under concurrent evaluation");
    }
}

/// The split of a multi-valued query parameter: matching a request does not rewrite it (upstream mutates the request
/// in place and must then drop its memo), so the request is byte-for-byte what it was after every matcher ran.
#[test]
fn matching_does_not_consume_the_request() {
    let request = scan_request();
    let before = format!("{request:?}");
    for (matcher, _) in scan_matchers() {
        matcher.matches(&request, Mode::DataPlane);
        matcher.matches(&request, Mode::ControlPlane);
        matcher.differences(&request);
        matcher.all_differences(&request);
    }
    assert_eq!(format!("{request:?}"), before);
}

// --- AbstractHttpRequestMatcherTest -----------------------------------------------------------------------------
//
// Upstream guards `scheduleLazyRemoval` with a compare-and-set flag: the first caller to see a used-up matcher claims
// its removal, later callers lose, and reusing the matcher in place re-arms the claim. Here the claim is
// `Store::post_process`: it returns true for the one call that took the exhausted expectation out of the store, and an
// upsert of the same id stores a fresh expectation that can be used up and removed again.

fn used_up(state: &State, store: &Store, id: &str) -> Arc<Expectation> {
    store.upsert(vec![expectation(state, json!({"id": id, "httpRequest": {"path": "/removal"}, "httpResponse": {"statusCode": 200}, "times": {"remainingTimes": 1}}))]);
    let served = store.first_match(&request("GET", "/removal"), None).expect("the one use is served");
    assert!(!served.is_active(), "precondition: the only use is taken");
    served
}

/// `tryScheduleRemovalReturnsTrueOnlyForFirstCaller`.
#[test]
fn removal_is_claimed_by_the_first_caller_only() {
    let state = state();
    let store = Store::default();
    let served = used_up(&state, &store, "once");
    assert!(store.post_process(&served), "first claim wins");
    assert!(!store.post_process(&served), "second claim loses");
    assert!(!store.post_process(&served), "third claim loses");
    assert!(store.get("once").is_none(), "the claim removed it");
}

/// `updateInPlaceReArmsRemovalClaim`: the same id upserted again (Times reset) can be removed again later.
#[test]
fn removal_claim_is_rearmed_by_upserting_the_same_id() {
    let state = state();
    let store = Store::default();
    let first = used_up(&state, &store, "again");
    assert!(store.post_process(&first));
    assert!(!store.post_process(&first));
    let second = used_up(&state, &store, "again");
    assert!(!Arc::ptr_eq(&first, &second), "a new expectation stands in");
    assert!(store.post_process(&second), "claim re-armed after the upsert");
    assert!(!store.post_process(&second));
}

/// `concurrentCallersClaimRemovalExactlyOnce`: 32 threads released together, exactly one wins.
#[test]
fn removal_is_claimed_exactly_once_under_concurrency() {
    const THREADS: usize = 32;
    let state = state();
    let store = Arc::new(Store::default());
    let served = used_up(&state, &store, "race");
    let go = Arc::new(Barrier::new(THREADS));
    let winners = Arc::new(AtomicUsize::new(0));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let (store, served, go, winners) = (store.clone(), served.clone(), go.clone(), winners.clone());
            std::thread::spawn(move || {
                go.wait();
                if store.post_process(&served) {
                    winners.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("a claimant panicked");
    }
    assert_eq!(winners.load(Ordering::SeqCst), 1, "exactly one thread may remove the expectation");
    assert!(store.get("race").is_none());
}

/// The count behind the claim: of many concurrent requests racing for `remainingTimes: N`, exactly N are served.
#[test]
fn removal_follows_exactly_the_uses_served() {
    const USES: usize = 5;
    const THREADS: usize = 16;
    let state = state();
    let store = Arc::new(Store::default());
    store.upsert(vec![expectation(&state, json!({"id": "n", "httpRequest": {"path": "/n"}, "httpResponse": {"statusCode": 200}, "times": {"remainingTimes": USES}}))]);
    let go = Arc::new(Barrier::new(THREADS));
    let served = Arc::new(AtomicUsize::new(0));
    let removed = Arc::new(AtomicUsize::new(0));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let (store, go, served, removed) = (store.clone(), go.clone(), served.clone(), removed.clone());
            std::thread::spawn(move || {
                go.wait();
                if let Some(found) = store.first_match(&request("GET", "/n"), None) {
                    served.fetch_add(1, Ordering::SeqCst);
                    if store.post_process(&found) {
                        removed.fetch_add(1, Ordering::SeqCst);
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("a request panicked");
    }
    assert_eq!(served.load(Ordering::SeqCst), USES, "exactly the remaining uses are served");
    // Usually the last request's `postProcess` removes it; when an earlier request ends its (shared) response in
    // progress while the last use is served, a later scan drops it lazily instead, as upstream's would
    // (`an_earlier_request_ending_during_the_last_use_leaves_one_lazy_removal`). Either way it is removed once.
    let lazily = store.take_lazy_removed(None).len();
    assert_eq!(removed.load(Ordering::SeqCst) + lazily, 1, "and the used-up expectation is removed exactly once");
    assert!(store.get("n").is_none());
}

/// A store holding `uses` uses of `GET /n`.
fn limited(state: &State, uses: usize) -> Arc<Store> {
    let store = Arc::new(Store::default());
    store.upsert(vec![expectation(state, json!({"id": "n", "httpRequest": {"path": "/n"}, "httpResponse": {"statusCode": 200}, "times": {"remainingTimes": uses}}))]);
    store
}

fn pause_at(store: &Arc<Store>, at: crate::store::Pause, work: impl FnOnce(&Store) + Send + 'static) {
    let inner = store.clone();
    *store.pause.lock().unwrap() = Some((at, Box::new(move || work(&inner))));
}

/// The request that consumes the last use: upstream marks the response in progress
/// (`setResponseInProgress(true)`) before `consumeMatch`, so a request scanning just after the use is taken sees a
/// used-up expectation that is still serving, and leaves it stored; the serving request's `postProcess` removes it.
#[test]
fn a_scan_right_after_the_last_use_is_taken_keeps_the_expectation_serving_it() {
    let state = state();
    let store = limited(&state, 1);
    let (tx, rx) = mpsc::channel();
    pause_at(&store, crate::store::Pause::Consumed, move |store| {
        let _ = tx.send(store.first_match(&request("GET", "/n"), None).is_some());
    });
    let last = store.first_match(&request("GET", "/n"), None).expect("the last use is served");
    assert!(!rx.recv().unwrap(), "the request in between finds no use left");
    assert!(store.take_lazy_removed(None).is_empty(), "nor drops the expectation still serving the last use");
    assert!(store.post_process(&last), "the last request's postProcess removes it");
    assert!(store.get("n").is_none());
}

/// One shared `responseInProgress` (upstream's interleaving too): an earlier request's `postProcess`
/// finds the expectation active, the last use is taken, then the earlier one ends "the" response in progress. A scan
/// now drops the used-up expectation lazily (`scheduleLazyRemoval`), and the last request's `postProcess` finds
/// nothing to remove: it is removed, and queued to be logged as removed, exactly once.
#[test]
fn an_earlier_request_ending_during_the_last_use_leaves_one_lazy_removal() {
    let state = state();
    let store = limited(&state, 2);
    let first = store.first_match(&request("GET", "/n"), None).expect("first use");
    let (tx, rx) = mpsc::channel();
    pause_at(&store, crate::store::Pause::Checked, move |store| {
        let _ = tx.send(store.first_match(&request("GET", "/n"), None));
    });
    assert!(!store.post_process(&first), "still active when the first request ended");
    let last = rx.recv().unwrap().expect("the last use, taken while the first request was ending");
    assert!(store.first_match(&request("GET", "/n"), None).is_none(), "no use left");
    let lazily: Vec<String> = store.take_lazy_removed(None).iter().map(|e| e.id.clone()).collect();
    assert_eq!(lazily, vec!["n".to_string()], "the scan drops it lazily, once");
    assert!(!store.post_process(&last), "so the last request's postProcess has nothing left to remove");
    assert!(store.get("n").is_none());
    assert!(store.take_lazy_removed(None).is_empty(), "and nothing more is queued");
}

// --- RequestMatchersConcurrentAddTest ---------------------------------------------------------------------------
//
// Upstream's fix (issue #2579) stops a concurrent `add` from dropping an acknowledged expectation, without holding a
// lock across the state backend's `put`. Our `Store::upsert` writes under one lock and calls no backend, so the
// backend-parking tests (a trim racing an in-flight put, two puts interleaving, a clustered `reconcileFromBackend`
// from a stale snapshot) have no counterpart: there is no gap between the local insert and a backend write to park
// in, and the dataplane does not consume `state_backend` yet (`state.rs`). What carries over is the outcome they
// protect: every acknowledged add is retrievable, whatever else runs at the same time, and nothing deadlocks.

fn ids(store: &Store) -> Vec<String> {
    store.retrievable().iter().map(|e| e.id.clone()).collect()
}

/// `concurrentAddsNeverLoseAnAcknowledgedExpectation`: 8 threads x 64 distinct ids, over several rounds.
#[test]
fn concurrent_adds_never_lose_an_acknowledged_expectation() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 64;
    const ROUNDS: usize = 3;
    let state = state();
    for round in 0..ROUNDS {
        let store = Store::default();
        let go = Barrier::new(THREADS);
        std::thread::scope(|scope| {
            for t in 0..THREADS {
                let (state, store, go) = (&state, &store, &go);
                scope.spawn(move || {
                    go.wait();
                    for i in 0..PER_THREAD {
                        let id = format!("r{t}-{i}");
                        store.upsert(vec![on(state, &id, "GET", &format!("/{id}"))]);
                    }
                });
            }
        });
        let found = ids(&store);
        assert_eq!(found.len(), THREADS * PER_THREAD, "round {round}: every add is retrievable");
        for t in 0..THREADS {
            for i in 0..PER_THREAD {
                assert!(found.contains(&format!("r{t}-{i}")), "round {round}: missing acknowledged id r{t}-{i}");
            }
        }
    }
}

/// `concurrentAddDoesNotDropExpectationWhenTrimRacesAnInFlightPut`: an add of A while other expectations are removed
/// (the trim) must leave A; and the removal takes only what it names.
#[test]
fn concurrent_add_survives_a_racing_removal_of_other_expectations() {
    const ROUNDS: usize = 200;
    let state = state();
    for round in 0..ROUNDS {
        let store = Store::default();
        store.upsert(vec![on(&state, "old", "GET", "/old")]);
        let go = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                go.wait();
                store.upsert(vec![on(&state, "A", "GET", "/a")]);
            });
            scope.spawn(|| {
                go.wait();
                store.remove_where(|e| e.id == "old");
            });
        });
        assert_eq!(ids(&store), vec!["A".to_string()], "round {round}: A survives, only `old` was removed");
    }
}

/// The same id added from many threads at once is one expectation (an upsert, never a duplicate), and the creation
/// order the match order depends on is that of the first insert.
#[test]
fn concurrent_adds_of_one_id_leave_one_expectation() {
    const THREADS: usize = 16;
    let state = state();
    let store = Store::default();
    store.upsert(vec![on(&state, "first", "GET", "/first")]);
    let go = Barrier::new(THREADS);
    std::thread::scope(|scope| {
        for t in 0..THREADS {
            let (state, store, go) = (&state, &store, &go);
            scope.spawn(move || {
                go.wait();
                store.upsert(vec![on(state, "same", "GET", &format!("/same{t}"))]);
            });
        }
    });
    assert_eq!(ids(&store), vec!["first".to_string(), "same".to_string()], "one `same`, after `first`");
}

/// `twoConcurrentAddsWhosePutsInterleaveDoNotDeadlock`, as a watchdog: adds, scans, removals and clears interleaved
/// on one store all finish (`finishes_within` fails the test on a hang, it is not what orders the threads).
#[test]
fn concurrent_adds_scans_removals_and_clears_do_not_deadlock() {
    const THREADS: usize = 6;
    const OPS: usize = 300;
    finishes_within(60, || {
        let state = state();
        let store = Store::default();
        let go = Barrier::new(THREADS);
        let failed = AtomicBool::new(false);
        std::thread::scope(|scope| {
            for t in 0..THREADS {
                let (state, store, go, failed) = (&state, &store, &go, &failed);
                scope.spawn(move || {
                    go.wait();
                    for i in 0..OPS {
                        let id = format!("t{}-{}", t % 2, i % 8);
                        match (t + i) % 4 {
                            0 => store.upsert(vec![on(state, &id, "GET", "/p")]),
                            1 => {
                                if let Some(found) = store.first_match(&request("GET", "/p"), None) {
                                    store.post_process(&found);
                                }
                            }
                            2 => {
                                store.remove_where(|e| e.id.ends_with('3'));
                            }
                            _ => {
                                if i % 50 == 0 {
                                    store.clear();
                                } else {
                                    failed.fetch_or(store.retrievable().len() > 16, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                });
            }
        });
        assert!(!failed.load(Ordering::Relaxed), "more expectations than distinct ids were stored");
        // The store is usable afterwards: an add is retrievable.
        store.upsert(vec![on(&state, "after", "GET", "/after")]);
        assert!(ids(&store).contains(&"after".to_string()));
    });
}

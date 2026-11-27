//! Rust ports of the upstream event-log properties the oracle-diff harness cannot see: thread safety of
//! the log and of timestamp rendering, the synchronous add path, and that a retrieve does not hold the log while its
//! caller works.
//!
//! Upstream's log is a disruptor ring buffer with one consumer thread (asynchronous by default, synchronous with
//! `asynchronousEventProcessing = false`); ours is a `Mutex<VecDeque>` written on the calling thread, so there is no
//! consumer thread, no ring buffer to overflow and no dropped-event count. The ports keep the guarantee each test
//! protects. Every concurrent test joins its threads or waits on a channel/barrier and asserts an invariant that holds
//! on every interleaving: nothing here sleeps or measures time (a `recv_timeout` is only a deadlock watchdog).
//!
//! | upstream class | here |
//! |---|---|
//! | `LogEntryTimestampConcurrencyTest` | `timestamps_render_without_cross_thread_corruption` |
//! | `MockServerEventLogConcurrencyTest` (2) | `log_stays_consistent_under_concurrent_add_and_read`, `log_does_not_deadlock_under_concurrent_add_read_and_clear` |
//! | `MockServerEventLogSynchronousProcessingTest` (2) | `synchronous_*` |
//! | `HttpStateRetrieveThreadingTest` | `retrieve_does_not_hold_the_log_while_the_caller_works` |

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;

use chrono::{DateTime, Local, TimeZone};
use serde_json::json;

use crate::matcher::RequestMatcher;
use crate::recorded::{Kind, LogEntry, RequestLog};
use crate::request::HttpRequest;

fn request(path: &str) -> HttpRequest {
    HttpRequest { method: "GET".into(), path: path.into(), ..HttpRequest::default() }
}

fn at(epoch_millis: i64) -> DateTime<Local> {
    Local.timestamp_millis_opt(epoch_millis).single().expect("an unambiguous local instant")
}

/// Fails the test when `work` does not finish in `seconds`: a deadlock watchdog, never a synchronisation point.
fn finishes_within<T: Send + 'static>(seconds: u64, work: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    rx.recv_timeout(Duration::from_secs(seconds)).expect("deadlock: the work did not finish")
}

fn paths(requests: Vec<Arc<HttpRequest>>) -> Vec<String> {
    requests.iter().map(|r| r.path.clone()).collect()
}

// --- LogEntryTimestampConcurrencyTest ---------------------------------------------------------------------------

/// `yyyy-MM-dd HH:mm:ss.SSS`.
fn well_formed(timestamp: &str) -> bool {
    let b = timestamp.as_bytes();
    b.len() == 23
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b' ',
            13 | 16 => *c == b':',
            19 => *c == b'.',
            _ => c.is_ascii_digit(),
        })
}

/// Each thread renders its own distinct instant (a day apart) in a tight loop through `LogEntry::to_json`, the
/// serialiser every log entry's `timestamp` goes through, and must always read back its own value: a shared mutable
/// formatter would show another thread's.
#[test]
fn timestamps_render_without_cross_thread_corruption() {
    const THREADS: usize = 16;
    const ITERATIONS: usize = 5_000;
    let entry = Arc::new(LogEntry::new(Kind::Info, "message"));
    let wrong = Arc::new(AtomicUsize::new(0));
    let go = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let (entry, wrong, go) = (entry.clone(), wrong.clone(), go.clone());
            std::thread::spawn(move || {
                let epoch = 1_718_000_000_000_i64 + t as i64 * 86_400_000;
                let instant = at(epoch);
                let expected = entry.to_json(&instant, None)["timestamp"].as_str().expect("a timestamp").to_string();
                assert!(well_formed(&expected), "reference value {expected:?} is well-formed");
                go.wait();
                for _ in 0..ITERATIONS {
                    let json = entry.to_json(&instant, None);
                    if json["timestamp"] != json!(expected) || json["epochTime"] != json!(epoch) {
                        wrong.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("concurrent rendering must not panic");
    }
    assert_eq!(wrong.load(Ordering::Relaxed), 0, "each thread must always read back its own timestamp");
    // The millisecond part is rendered, not dropped or rounded.
    let rendered = entry.to_json(&at(1_718_000_000_123), None)["timestamp"].as_str().expect("a timestamp").to_string();
    assert!(well_formed(&rendered) && rendered.ends_with(".123"), "{rendered}");
}

// --- MockServerEventLogConcurrencyTest --------------------------------------------------------------------------

const WRITERS: usize = 8;
const READERS: usize = 4;
const ADDS_PER_WRITER: usize = 500;

fn everything() -> RequestMatcher {
    RequestMatcher::any()
}

/// Writers add while readers retrieve and filter (nothing is cleared, and the log is sized well above the total, so
/// nothing is evicted): no thread panics, every reader finishes, and afterwards exactly every added request is there.
/// Upstream also asserts the ring buffer dropped nothing; our counterpart is the eviction count staying zero.
#[test]
fn log_stays_consistent_under_concurrent_add_and_read() {
    let log = Arc::new(RequestLog::new(200_000));
    let writers_done = Arc::new(AtomicBool::new(false));
    let go = Arc::new(Barrier::new(WRITERS + READERS));
    let writers: Vec<_> = (0..WRITERS)
        .map(|w| {
            let (log, go) = (log.clone(), go.clone());
            std::thread::spawn(move || {
                go.wait();
                for i in 0..ADDS_PER_WRITER {
                    let path = format!("/w{w}/{i}");
                    log.received(request(&path));
                    // A push is in the log for its own thread's next read, whoever holds the ring
                    if i % 50 == 0 {
                        assert!(paths(log.requests()).contains(&path), "own entry visible at once");
                    }
                }
            })
        })
        .collect();
    let readers: Vec<_> = (0..READERS)
        .map(|_| {
            let (log, done, go) = (log.clone(), writers_done.clone(), go.clone());
            std::thread::spawn(move || {
                go.wait();
                let filter = everything();
                loop {
                    let stop = done.load(Ordering::Acquire);
                    // A snapshot is always a prefix-consistent list: no entry twice, none torn.
                    let seen = paths(log.requests());
                    let unique: std::collections::HashSet<&String> = seen.iter().collect();
                    assert_eq!(unique.len(), seen.len(), "a request was listed twice");
                    log.matching_requests(Some(&filter));
                    if stop {
                        break;
                    }
                }
            })
        })
        .collect();
    finishes_within(120, move || {
        for w in writers {
            w.join().expect("a writer panicked");
        }
        writers_done.store(true, Ordering::Release);
        for r in readers {
            r.join().expect("a reader panicked");
        }
        let expected = WRITERS * ADDS_PER_WRITER;
        assert_eq!(log.evicted(), 0, "nothing was evicted");
        assert_eq!(log.requests().len(), expected, "exactly every added request is present");
        assert_eq!(log.matching_requests(Some(&everything())).len(), expected);
        // Each writer's own requests are in the order that writer added them.
        let all = paths(log.requests());
        for w in 0..WRITERS {
            let mine: Vec<usize> = all.iter().filter_map(|p| p.strip_prefix(&format!("/w{w}/"))?.parse().ok()).collect();
            assert_eq!(mine, (0..ADDS_PER_WRITER).collect::<Vec<_>>(), "writer {w}'s order");
        }
    });
}

/// Entries staged while another thread holds the ring are admitted in arrival order with the eviction
/// count exact, and once every thread is done nothing is left staged.
#[test]
fn full_log_counts_every_eviction_under_concurrent_adds() {
    const CAPACITY: usize = 100;
    let log = Arc::new(RequestLog::new(CAPACITY));
    let go = Arc::new(Barrier::new(WRITERS));
    let writers: Vec<_> = (0..WRITERS)
        .map(|w| {
            let (log, go) = (log.clone(), go.clone());
            std::thread::spawn(move || {
                go.wait();
                for i in 0..ADDS_PER_WRITER {
                    log.received(request(&format!("/w{w}/{i}")));
                }
            })
        })
        .collect();
    finishes_within(120, move || {
        for w in writers {
            w.join().expect("a writer panicked");
        }
        let total = WRITERS * ADDS_PER_WRITER;
        assert_eq!(log.size(), CAPACITY);
        assert_eq!(log.evicted() as usize, total - CAPACITY);
        let all = paths(log.requests());
        assert_eq!(all.len(), CAPACITY);
        for w in 0..WRITERS {
            let mine: Vec<usize> = all.iter().filter_map(|p| p.strip_prefix(&format!("/w{w}/"))?.parse().ok()).collect();
            assert!(mine.windows(2).all(|p| p[0] < p[1]), "writer {w}'s order");
        }
    });
}

/// The same with half the readers also clearing (the exact final count is then undefined): only the safety properties
/// hold: no panic, no deadlock, and a log still usable afterwards.
#[test]
fn log_does_not_deadlock_under_concurrent_add_read_and_clear() {
    let log = Arc::new(RequestLog::new(200_000));
    let writers_done = Arc::new(AtomicBool::new(false));
    let go = Arc::new(Barrier::new(WRITERS + READERS));
    let writers: Vec<_> = (0..WRITERS)
        .map(|w| {
            let (log, go) = (log.clone(), go.clone());
            std::thread::spawn(move || {
                go.wait();
                for i in 0..ADDS_PER_WRITER {
                    log.received(request(&format!("/w{w}/{i}")));
                }
            })
        })
        .collect();
    let readers: Vec<_> = (0..READERS)
        .map(|r| {
            let (log, done, go) = (log.clone(), writers_done.clone(), go.clone());
            std::thread::spawn(move || {
                go.wait();
                let clears = r % 2 == 0;
                loop {
                    let stop = done.load(Ordering::Acquire);
                    log.requests();
                    log.matching_requests(Some(&everything()));
                    if clears {
                        log.clear(Some((&|r: &HttpRequest| r.path == "/w1/1", &|_: &serde_json::Value| false)));
                    }
                    if stop {
                        break;
                    }
                }
            })
        })
        .collect();
    finishes_within(120, move || {
        for w in writers {
            w.join().expect("a writer panicked");
        }
        writers_done.store(true, Ordering::Release);
        for r in readers {
            r.join().expect("a reader panicked");
        }
        // Still usable: a final read completes and a new entry is stored and read back.
        log.received(request("/after"));
        assert!(paths(log.requests()).contains(&"/after".to_string()));
    });
}

// --- MockServerEventLogSynchronousProcessingTest ----------------------------------------------------------------
//
// Upstream's synchronous mode runs `processLogEntry` on the adding thread, so `size()` reflects an add at once. Ours
// is always that: an add is stored before `received` returns, with no drain to wait for.

/// `shouldAddAndRetrieveOnSynchronousPath`.
#[test]
fn synchronous_add_is_stored_before_it_returns_and_retrieved_in_order() {
    let log = RequestLog::new(1_000);
    log.received(request("/one"));
    assert_eq!(paths(log.requests()), ["/one"], "stored immediately, without a drain");
    log.received(request("/two"));
    assert_eq!(paths(log.requests()), ["/one", "/two"]);
    // Filtered retrieval, as the control plane runs it.
    let only_two = RequestMatcher::compile(&json!({"path": "/two"}));
    assert_eq!(paths(log.matching_requests(Some(&only_two))), ["/two"]);
}

/// `shouldVerifyOnSynchronousPath`: verification reads what was just added.
#[test]
fn synchronous_add_is_visible_to_verification() {
    let state = crate::state::State::new(crate::Config::for_tests(), Vec::new());
    state.log.received(request("/some_path"));
    state.log.received(request("/some_path"));
    let exactly_two = br#"{"httpRequest":{"path":"/some_path"},"times":{"atLeast":2,"atMost":2}}"#;
    assert!(matches!(crate::verify::verify(&state, exactly_two), crate::verify::Outcome::Passed));
    let exactly_one = br#"{"httpRequest":{"path":"/some_path"},"times":{"atLeast":1,"atMost":1}}"#;
    assert!(matches!(crate::verify::verify(&state, exactly_one), crate::verify::Outcome::Failed(_)));
}

// --- HttpStateRetrieveThreadingTest -----------------------------------------------------------------------------
//
// Upstream: the retrieve's (cheap) list is materialised on the disruptor consumer thread, the (expensive)
// serialisation runs on the caller's, so a slow serialisation cannot stall all further event logging. Ours has no
// consumer thread: a retrieve materialises on the caller under the log's lock and returns an owned snapshot, after
// which the caller's work holds nothing. Same two assertions, deterministically: the materialisation runs on the
// calling thread, and while the caller sits on its snapshot another thread still adds and retrieves.

#[test]
fn retrieve_does_not_hold_the_log_while_the_caller_works() {
    let log = Arc::new(RequestLog::new(1_000));
    log.received(request("/first"));
    let (reached_tx, reached_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let caller = {
        let log = log.clone();
        std::thread::Builder::new()
            .name("test-retrieve-caller".into())
            .spawn(move || {
                // The materialisation: the filter runs inside the log's read, on this very thread.
                let materialised_on = std::cell::RefCell::new(None);
                let snapshot = log.messages(
                    |r| {
                        *materialised_on.borrow_mut() = Some(std::thread::current().id());
                        r.path == "/first"
                    },
                    |_| false,
                );
                assert_eq!(snapshot.len(), 1);
                assert_eq!(materialised_on.into_inner(), Some(std::thread::current().id()), "materialised on the caller's thread");
                // The "expensive serialisation": the caller now sits on its snapshot until released.
                reached_tx.send(()).expect("main is listening");
                release_rx.recv().expect("main releases the caller");
                snapshot.len()
            })
            .expect("spawn the caller")
    };
    reached_rx.recv_timeout(Duration::from_secs(30)).expect("the caller reached its continuation");
    // While the caller is parked, a new entry is accepted and retrieved: a held lock would hang here.
    let late = {
        let log = log.clone();
        finishes_within(30, move || {
            log.received(request("/late"));
            let only_late = RequestMatcher::compile(&json!({"path": "/late"}));
            paths(log.matching_requests(Some(&only_late)))
        })
    };
    assert_eq!(late, ["/late"]);
    release_tx.send(()).expect("the caller is waiting");
    assert_eq!(caller.join().expect("the caller finished"), 1);
}

// --- MockServerEventLogCaptureTest -----------------------------------------------------------------
//
// | upstream case | here |
// |---|---|
// | `shouldPersistFullBodyToHookWhileTruncatingInMemoryCopy` | `max_logged_body_bytes_cuts_the_retained_copy_not_the_hook_or_the_live_request` |
// | `shouldCapRetainedEntriesByByteBudget` | `max_event_log_size_in_bytes_keeps_the_newest_entries_that_fit` |
//
// Both properties are also checked on the wire, against the oracle: the `event_log_max_logged_body_bytes` and
// `event_log_max_size_bytes` scenarios.

fn post(path: &str, body: &[u8]) -> HttpRequest {
    HttpRequest { method: "POST".into(), path: path.into(), body: bytes::Bytes::copy_from_slice(body), ..HttpRequest::default() }
}

fn forwarded(log: &RequestLog, request: HttpRequest, response: serde_json::Value) {
    log.record_forwarded(request, response, Some((json!({"httpRequest": {}}), json!({"httpRequest": {}}))), None, None);
}

#[test]
fn max_logged_body_bytes_cuts_the_retained_copy_not_the_hook_or_the_live_request() {
    let log = RequestLog::new(1_000).with_limits(5, 0);
    let captured = Arc::new(parking_lot::Mutex::new(Vec::new()));
    {
        let captured = captured.clone();
        log.set_exchange_hook(Arc::new(move |x| captured.lock().push((x.request.body.len(), x.request.first_header("x-mockserver-body-truncated").map(str::to_string)))));
    }
    let live = post("/capture", b"0123456789ABCDEF");
    forwarded(&log, live.clone(), json!({"statusCode": 200, "body": "a-very-long-response-body"}));

    // The disk hook saw the whole request, without a marker.
    assert_eq!(*captured.lock(), [(16, None)]);
    // The live request is not changed (the log works on a copy).
    assert_eq!(live.body.len(), 16);
    assert_eq!(live.first_header("x-mockserver-body-truncated"), None);

    let retained = log.exchanges();
    assert_eq!(retained.len(), 1);
    let request = &retained[0].request;
    assert_eq!(request.body.as_ref(), b"01234");
    assert_eq!(request.first_header("x-mockserver-body-truncated"), Some("16"));
    let response = &retained[0].response;
    assert_eq!(response["body"], json!({"type": "BINARY", "base64Bytes": "YS12ZXI="}));
    assert_eq!(response["headers"]["x-mockserver-body-truncated"], json!(["25"]));
}

#[test]
fn max_event_log_size_in_bytes_keeps_the_newest_entries_that_fit() {
    use base64::Engine;
    let binary = |len: usize| json!({"statusCode": 200, "body": {"type": "BINARY", "base64Bytes": base64::engine::general_purpose::STANDARD.encode(vec![0u8; len])}});
    // The weigher counts structural overheads besides the bodies, so the budget is 2.5 times a sample entry's weight.
    let sample = RequestLog::new(1_000).with_limits(0, 0);
    forwarded(&sample, request("/p0"), binary(40));
    let per_entry = sample.retained().1;
    assert!(per_entry > 40, "the body plus the structural overheads");
    let log = RequestLog::new(1_000).with_limits(0, per_entry * 2 + per_entry / 2);
    for i in 0..10 {
        forwarded(&log, request(&format!("/p{i}")), binary(40));
    }
    // Two fit: the oldest go first.
    let kept: Vec<String> = log.exchanges().iter().map(|x| x.request.path.clone()).collect();
    assert_eq!(kept, ["/p8", "/p9"]);
    assert_eq!(log.evicted(), 8);
    // An entry over the whole budget is still kept (alone).
    forwarded(&log, request("/big"), binary(400));
    assert_eq!(log.exchanges().len(), 1);
}

// --- A served request's entries, built when the log is read ----------------------------------------------------

fn served(path: &str, id: &str) -> HttpRequest {
    let mut r = request(path);
    r.headers = crate::request::MultiMap::from([("Host".into(), vec!["localhost:1080".into()]), ("Accept".into(), vec!["*/*".into()])]).into();
    r.protocol = "HTTP_1_1";
    r.keep_alive = true;
    r.local_address = "127.0.0.1:1080".into();
    r.log_correlation_id = id.into();
    r
}

const SERVED_FORMAT: &str = "returning response:{}for request:{}for action:{}from expectation:{}";

/// The data plane's `returning response` entry for `x`, as it builds it for a static response.
fn served_entry(x: &crate::recorded::Exchange, logged: &crate::recorded::LoggedRequest, action: &serde_json::Value) -> LogEntry {
    use crate::recorded::{Arg, logged_response};
    LogEntry::new(Kind::ExpectationResponse, SERVED_FORMAT)
        .args([Arg::from(logged_response(&x.response)), logged.arg(), logged_response(action).into(), "e-1".into()])
        .request_logged(&x.request, logged)
}

/// Every entry's JSON with its time left out, which differs between two logs.
fn untimed(entries: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    entries
        .into_iter()
        .map(|mut e| {
            if let Some(o) = e.as_object_mut() {
                o.remove("epochTime");
                o.remove("timestamp");
            }
            e
        })
        .collect()
}

#[test]
fn a_served_request_is_logged_without_building_its_entry_and_reads_back_as_an_eagerly_built_one() {
    let config = crate::Config::for_tests();
    let response = json!({"statusCode": 200, "reasonPhrase": "OK", "headers": {"connection": ["keep-alive"]}, "body": "e0"});
    let action = json!({"statusCode": 200, "reasonPhrase": "OK", "body": "e0"});
    // capacity 3: the second request's exchange evicts the first's arrival
    let (lazy, eager) = (RequestLog::new(3), RequestLog::new(3));
    let builds = Arc::new(AtomicUsize::new(0));
    for (i, path) in ["/a", "/b"].into_iter().enumerate() {
        let id = format!("00000000-0000-0000-0000-00000000000{i}");
        let request = Arc::new(served(path, &id));
        let logged = crate::recorded::LoggedRequest::shared(request.clone());
        lazy.received_logged(&logged, &request);
        let (action_for_lazy, builds) = (action.clone(), builds.clone());
        lazy.record_served(&logged, response.clone(), Some("e-1".into()), Kind::ExpectationResponse, move |x, logged| {
            builds.fetch_add(1, Ordering::Relaxed);
            served_entry(x, logged, &action_for_lazy)
        });

        let plain = served(path, &id);
        let logged = crate::recorded::LoggedRequest::of(&plain);
        eager.received(plain.clone());
        let x = crate::recorded::Exchange::new(Arc::new(plain.clone()), response.clone(), Some("e-1".into()));
        eager.record_with_message(plain, response.clone(), Some("e-1".into()), served_entry(&x, &logged, &action));
    }
    assert_eq!(builds.load(Ordering::Relaxed), 0, "logging a served request builds no entry");
    assert_eq!((lazy.size(), lazy.evicted()), (eager.size(), eager.evicted()));
    for scope in [crate::recorded::EntryScope::Messages, crate::recorded::EntryScope::RequestResponses] {
        let read = |log: &RequestLog| untimed(log.log_entries(scope, |_| true, |_| true, Some(1080), &config));
        assert_eq!(read(&lazy), read(&eager));
    }
    let lines = |log: &RequestLog| log.messages(|_| true, |_| true).into_iter().map(|(_, text)| text).collect::<Vec<_>>();
    assert_eq!(lines(&lazy), lines(&eager));
    assert_eq!(lazy.retained().1, eager.retained().1, "the same weight");
    assert_eq!(builds.load(Ordering::Relaxed), 2, "each entry is built once, when first read");
}

#[test]
fn a_log_that_keeps_nothing_builds_no_served_entry() {
    let log = RequestLog::new(0);
    let request = Arc::new(served("/a", "00000000-0000-0000-0000-000000000000"));
    let logged = crate::recorded::LoggedRequest::shared(request.clone());
    log.received_logged(&logged, &request);
    log.record_served(&logged, json!({"statusCode": 200}), Some("e-1".into()), Kind::ExpectationResponse, |_, _| panic!("built for a log that keeps nothing"));
    assert_eq!((log.size(), log.evicted()), (0, 0));
}

#[test]
fn a_deferred_message_is_built_when_read_and_reads_back_as_an_eagerly_built_one() {
    use crate::recorded::{Arg, Subject};
    let config = crate::Config::for_tests();
    let expectation = crate::log_entry::Json::new(json!({"id": "e-1", "httpRequest": {"path": "/a"}, "times": {"unlimited": true}}));
    let matched = |logged: &crate::recorded::LoggedRequest| {
        LogEntry::new(Kind::ExpectationMatched, "request:{}matched expectation:{}")
            .request_logged(&logged.request, logged)
            .args([logged.arg(), Arg::from(expectation.clone())])
            .expectation_shared(expectation.clone())
    };
    // capacity 3: the second request's entries evict the first's arrival
    let (lazy, eager) = (RequestLog::new(3), RequestLog::new(3));
    let builds = Arc::new(AtomicUsize::new(0));
    for (i, path) in ["/a", "/b"].into_iter().enumerate() {
        let id = format!("00000000-0000-0000-0000-00000000000{i}");
        let request = Arc::new(served(path, &id));
        let logged = crate::recorded::LoggedRequest::shared(request.clone());
        lazy.received_logged(&logged, &request);
        let (template, builds) = (matched(&logged), builds.clone());
        lazy.message_about_deferred(crate::recorded::Level::Info, Kind::ExpectationMatched, request.clone(), move || {
            builds.fetch_add(1, Ordering::Relaxed);
            template.clone()
        });

        let plain = Arc::new(served(path, &id));
        let logged = crate::recorded::LoggedRequest::shared(plain.clone());
        eager.received_logged(&logged, &plain);
        eager.message_about(matched(&logged), Subject::Request(plain));
    }
    assert_eq!(builds.load(Ordering::Relaxed), 0, "logging the message builds no entry");
    assert_eq!((lazy.size(), lazy.evicted()), (eager.size(), eager.evicted()));
    let read = |log: &RequestLog| untimed(log.log_entries(crate::recorded::EntryScope::Messages, |_| true, |_| true, Some(1080), &config));
    assert_eq!(read(&lazy), read(&eager));
    let lines = |log: &RequestLog| log.messages(|_| true, |_| true).into_iter().map(|(_, text)| text).collect::<Vec<_>>();
    assert_eq!(lines(&lazy), lines(&eager));
    assert_eq!(builds.load(Ordering::Relaxed), 2, "each entry is built once, when first read");
}

/// The requests a log line can quote: headers, query parameters and cookies (repeated, blank, marked, out of order,
/// non-ASCII), bodies of each kind, control characters, the socket and TLS fields.
fn quoted_requests() -> Vec<HttpRequest> {
    let base = || HttpRequest {
        method: "POST".into(),
        path: "/p".into(),
        protocol: "HTTP_1_1",
        keep_alive: true,
        local_address: "127.0.0.1:1080".into(),
        remote_address: "127.0.0.1:50000".into(),
        ..HttpRequest::default()
    };
    let with = |headers: &[(&str, &[&str])], body: &[u8]| HttpRequest {
        headers: headers.iter().map(|(k, vs)| (k.to_string(), vs.iter().map(|v| v.to_string()).collect())).collect(),
        body: bytes::Bytes::copy_from_slice(body),
        ..base()
    };
    let mut out = vec![
        HttpRequest { method: "GET".into(), ..HttpRequest::default() },
        HttpRequest { method: "GET".into(), path: "/a".into(), secure: true, ..HttpRequest::default() },
        base(),
        HttpRequest { protocol: "HTTP_3", secure: true, ..base() },
        with(&[("Host", &["localhost:1080"]), ("User-Agent", &["ApacheBench/2.3"]), ("Accept", &["*/*"]), ("Connection", &["keep-alive"])], b""),
        with(&[("b", &["1"]), ("a", &["2", "3"]), ("b", &["4"]), ("C", &[""]), ("Z", &["  "])], b""),
        with(&[("x-mark", &["!not", "?opt", "!", "?", " ! "]), ("ünï", &["ç\u{1}\u{7f}\u{85}\u{2028}\"\\\n\r\t"]), ("\u{10000}", &["a"]), ("\u{ffff}", &["b"])], b""),
        with(&[("!marked", &["v"])], b""),
        with(&[(" ", &["blank name"])], b""),
        with(&[("Content-Type", &["application/json"])], br#"{"b":1,"a":[1,2.50,{"c":null}],"s":"\u0001\u00e9"}"#),
        with(&[("Content-Type", &["application/json; charset=utf-8"])], b"[1, 2]"),
        with(&[("Content-Type", &["application/json"])], b"12.0"),
        with(&[("Content-Type", &["application/json"])], b"{not json"),
        with(&[("Content-Type", &["application/json"])], b"   "),
        with(&[("Content-Type", &["text/plain"])], "caf\u{e9} \u{1b}[31m".as_bytes()),
        with(&[("Content-Type", &["text/plain; charset=utf-16"])], &[0xfe, 0xff, 0, b'h', 0, b'i']),
        with(&[("Content-Type", &["application/xml"])], b"<a>1</a>"),
        with(&[("Content-Type", &["application/x-www-form-urlencoded"])], b"a=1&b=2"),
        with(&[("Content-Type", &["application/octet-stream"])], &[0, 1, 2, 255]),
        with(&[], b"plain text without a type"),
        with(&[], &[0xff, 0xfe, 0]),
        HttpRequest { body: bytes::Bytes::from_static(b"cut"), body_kind: crate::request::BodyKind::Binary, ..base() },
        HttpRequest { body: bytes::Bytes::from_static(b"text"), body_kind: crate::request::BodyKind::PlainString, ..base() },
        HttpRequest { original_body: Some(bytes::Bytes::from_static(b"gz")), body: bytes::Bytes::from_static(b"x"), ..base() },
    ];
    let mut query = base();
    query.query = vec![("b".into(), vec!["1".into()]), ("a".into(), vec!["x y".into(), "".into()]), ("b".into(), vec!["2".into()])];
    query.path_parameters = vec![("id".into(), vec!["7".into()]), ("name".into(), vec!["n".into()])];
    out.push(query);
    let mut marked_query = base();
    marked_query.query = vec![("?x".into(), vec!["1".into()])];
    out.push(marked_query);
    let mut cookies = base();
    cookies.cookies = vec![("s".into(), "1".into()), ("a".into(), "".into()), ("s".into(), "2".into()), ("m".into(), "!v".into())];
    out.push(cookies);
    let mut marked_cookie = base();
    marked_cookie.cookies = vec![("!c".into(), "1".into())];
    out.push(marked_cookie);
    let mut socket = base();
    socket.socket_address = Some(Box::new(("example.com".into(), 443, true)));
    socket.client_certificates = Arc::new(vec![
        crate::tls::client_cert::ClientCertificate { der: Vec::new(), model: json!({"issuerDistinguishedName": "CN=a", "serialNumber": "1", "empty": {}, "list": []}) },
        crate::tls::client_cert::ClientCertificate { der: Vec::new(), model: json!({"subjectDistinguishedName": "CN=b"}) },
    ]);
    out.push(socket);
    let mut untransported = base();
    untransported.protocol = "";
    untransported.keep_alive = false;
    out.push(untransported);
    let mut many = base();
    many.headers = (0..100).map(|i| (format!("h{:03}", (i * 37) % 100), vec![i.to_string()])).collect();
    out.push(many);
    out
}

#[test]
fn a_quoted_request_is_written_as_its_logged_json_prints() {
    for request in quoted_requests() {
        let mut direct = String::from("before:");
        crate::recorded::logged_text_into(&mut direct, &request);
        assert_eq!(direct, format!("before:{}", crate::json::pretty(&crate::recorded::logged(&request))), "{request:?}");
        // a log line's argument: the same text before and after its JSON is rendered
        let json = crate::recorded::LoggedRequest::of(&request).json;
        let mut unrendered = String::new();
        json.write_text(&mut unrendered);
        assert!(!json.is_rendered(), "writing the text renders nothing");
        assert_eq!(*json, crate::recorded::logged(&request));
        let mut rendered = String::new();
        json.write_text(&mut rendered);
        assert_eq!(unrendered, rendered);
    }
}

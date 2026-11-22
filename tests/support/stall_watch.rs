//! A replay that stops making progress fails instead of waiting for ever. Each scenario a replay worker takes is
//! [`watch`]ed until its guard drops; a thread of its own (it keeps running when every runtime thread is parked
//! or blocked) checks once in a while, and when one has been in flight longer than the limit it prints every
//! scenario still in flight, with how long each has been, and ends the test process with a failure. The longest
//! is the one that stopped; the others are often waiting on a lock it holds.
//!
//! `MOCK_SERVER_REPLAY_STALL_SECS`: the limit, in seconds. Default 600: a whole scenario, including the wait for
//! its locks, takes well under a minute. `0` turns the watch off (stepping through a replay in a debugger).

#![allow(dead_code)]

use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The last id handed out, and each scenario in flight: id, name, start.
type InFlight = (u64, Vec<(u64, String, Instant)>);
static IN_FLIGHT: Mutex<InFlight> = Mutex::new((0, Vec::new()));

/// Watches `name` until the returned guard drops.
pub fn watch(name: &str) -> Watched {
    let Some(limit) = limit() else { return Watched(None) };
    start_watcher(limit);
    let mut in_flight = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
    in_flight.0 += 1;
    let id = in_flight.0;
    in_flight.1.push((id, name.to_string(), Instant::now()));
    Watched(Some(id))
}

pub struct Watched(Option<u64>);

impl Drop for Watched {
    fn drop(&mut self) {
        if let Some(id) = self.0 {
            IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner()).1.retain(|(i, _, _)| *i != id);
        }
    }
}

fn limit() -> Option<Duration> {
    static LIMIT: OnceLock<Option<Duration>> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        let secs = match std::env::var("MOCK_SERVER_REPLAY_STALL_SECS") {
            Ok(s) => s.trim().parse::<u64>().expect("MOCK_SERVER_REPLAY_STALL_SECS: a number of seconds"),
            Err(_) => 600,
        };
        (secs > 0).then(|| Duration::from_secs(secs))
    })
}

fn start_watcher(limit: Duration) {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let every = (limit / 10).clamp(Duration::from_millis(100), Duration::from_secs(10));
        std::thread::Builder::new()
            .name("replay-stall-watch".into())
            .spawn(move || loop {
                std::thread::sleep(every);
                let in_flight: Vec<(String, Instant)> =
                    IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner()).1.iter().map(|(_, n, t)| (n.clone(), *t)).collect();
                if let Some(report) = stalled(&in_flight, Instant::now(), limit) {
                    // straight to stderr: `eprintln!` here is captured with the test's output, which the exit loses
                    let _ = writeln!(std::io::stderr(), "{report}");
                    std::process::exit(101);
                }
            })
            .expect("start the replay stall watch");
    });
}

/// The report when a scenario of `in_flight` (name, start) has been in flight longer than `limit` at `now`: every
/// scenario in flight, the longest first, with its time. `None` while none has.
fn stalled(in_flight: &[(String, Instant)], now: Instant, limit: Duration) -> Option<String> {
    let mut ages: Vec<(&str, Duration)> = in_flight.iter().map(|(n, t)| (n.as_str(), now.saturating_duration_since(*t))).collect();
    ages.sort_by_key(|a| std::cmp::Reverse(a.1));
    let (longest, age) = *ages.first()?;
    if age <= limit {
        return None;
    }
    let lines: Vec<String> = ages.iter().map(|(n, a)| format!("  {n}: {:.1}s", a.as_secs_f64())).collect();
    Some(format!(
        "replay stalled: {longest} has been in flight for {:.1}s, over the {}s limit (MOCK_SERVER_REPLAY_STALL_SECS); \
         every scenario in flight, the longest first:\n{}",
        age.as_secs_f64(),
        limit.as_secs(),
        lines.join("\n"),
    ))
}

#[test]
fn a_stall_names_the_scenario_in_flight_longest_and_lists_the_others() {
    let now = Instant::now();
    let in_flight = vec![
        ("b-short".to_string(), now - Duration::from_secs(5)),
        ("a-stuck".to_string(), now - Duration::from_secs(700)),
    ];
    let report = stalled(&in_flight, now, Duration::from_secs(600)).expect("a-stuck is over the limit");
    assert!(report.starts_with("replay stalled: a-stuck has been in flight for 700.0s, over the 600s limit"), "{report}");
    assert!(report.ends_with("  a-stuck: 700.0s\n  b-short: 5.0s"), "{report}");
}

#[test]
fn no_stall_while_every_scenario_is_within_the_limit() {
    let now = Instant::now();
    let in_flight = vec![("a".to_string(), now - Duration::from_secs(600)), ("b".to_string(), now)];
    assert_eq!(stalled(&in_flight, now, Duration::from_secs(600)), None);
    assert_eq!(stalled(&[], now, Duration::from_secs(600)), None);
}

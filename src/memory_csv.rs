//! `outputMemoryUsageCsv` (`MemoryMonitoring`): `memoryUsage_<yyyy-MM-dd>.csv` in `memoryUsageCsvDirectory`, its header
//! written when the server starts (unless the file is there already), then a row on every 50th update.
//!
//! An update is what upstream's two listeners see: one per change of the expectations (`MockServerMatcherListener`,
//! once per expectation added, updated or removed) and one per change of the event log (`MockServerLogListener`), which
//! `MockServerEventLogNotifier` coalesces into one per 250 ms window. Each kind keeps the size it last saw, so a row
//! shows the expectations as of the last expectation update and the log as of the last log update.
//!
//! The first five columns are upstream's. Its eight heap and non-heap columns have no counterpart in a Rust process,
//! and are replaced by the process figures of `crate::metrics::process` (`docs/divergences.md`): a reader
//! that wants `heapUsed` finds no such column. A figure the platform cannot give is left empty.
//!
//! Upstream's reset also builds a thread that would write a row ten seconds later, but never starts it, so a reset
//! writes nothing.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::recorded::{Level, LogEntry};
use crate::state::State;

/// `MockServerEventLogNotifier.COALESCE_WINDOW_MILLIS`.
const LOG_WINDOW: Duration = Duration::from_millis(250);

/// `MemoryMonitoring.shouldLogMetrics`: every 50th update writes a row.
const EVERY: u64 = 50;

pub const HEADER: &str = "mockServerPort,eventLogSize,maxLogEntries,expectationsSize,maxExpectations,residentMemoryBytes,virtualMemoryBytes,maxResidentMemoryBytes";

/// The sizes the listeners last saw and the update count.
#[derive(Debug, Default, PartialEq)]
struct Counts {
    updates: u64,
    log_size: usize,
    expectations_size: usize,
}

impl Counts {
    /// One update; `true` when it is a 50th one.
    fn update(&mut self) -> bool {
        self.updates += 1;
        self.updates.is_multiple_of(EVERY)
    }
}

/// The file of a server started now: `<memoryUsageCsvDirectory>/memoryUsage_<local date>.csv`.
pub fn csv_path(directory: &str, date: chrono::NaiveDate) -> PathBuf {
    Path::new(directory).join(format!("memoryUsage_{}.csv", date.format("%Y-%m-%d")))
}

/// A row: upstream's five columns, then the process figures.
fn row(port: u16, counts: &Counts, max_log_entries: i64, max_expectations: i64, process: &crate::metrics::process::ProcessStats) -> String {
    let figure = |v: Option<f64>| v.map(|v| format!("{v:.0}")).unwrap_or_default();
    format!(
        "{port},{},{max_log_entries},{},{max_expectations},{},{},{}",
        counts.log_size,
        counts.expectations_size,
        figure(process.resident_bytes),
        figure(process.virtual_bytes),
        figure(Some(process.max_resident_bytes)),
    )
}

/// `MemoryMonitoring`'s constructor: the header, then the listeners. Needs a tokio runtime (`Server::start`).
pub fn start(state: &Arc<State>) {
    if !state.config.bool_property("outputMemoryUsageCsv", false) {
        return;
    }
    let directory = state.config.property("memoryUsageCsvDirectory").unwrap_or_else(|| ".".to_string());
    let path = csv_path(&directory, chrono::Local::now().date_naive());
    if !path.exists() {
        write_line(state, &path, HEADER);
    }
    // subscribed before the task runs, so no change after this point is missed
    let mut log = state.log.changes.subscribe();
    let mut store = state.store.changes.subscribe();
    log.borrow_and_update();
    let store_seen = *store.borrow_and_update();
    let closing = state.closing.subscribe();
    tokio::spawn(listen(Arc::downgrade(state), path, log, store, store_seen, closing));
}

async fn listen(
    state: Weak<State>,
    path: PathBuf,
    mut log: tokio::sync::watch::Receiver<u64>,
    mut store: tokio::sync::watch::Receiver<u64>,
    mut store_seen: u64,
    mut closing: tokio::sync::watch::Receiver<bool>,
) {
    let mut counts = Counts::default();
    // when the pending coalesced log update fires
    let mut log_due: Option<tokio::time::Instant> = None;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(log_due.unwrap_or_else(tokio::time::Instant::now)), if log_due.is_some() => {
                log_due = None;
                let Some(state) = state.upgrade() else { return };
                counts.log_size = state.log.size();
                if counts.update() {
                    write_row(&state, &path, &counts);
                }
            }
            changed = log.changed() => {
                if changed.is_err() {
                    return;
                }
                log.borrow_and_update();
                log_due.get_or_insert_with(|| tokio::time::Instant::now() + LOG_WINDOW);
            }
            changed = store.changed() => {
                if changed.is_err() {
                    return;
                }
                // the signal's value counts the changes: each one is an update of its own
                let version = *store.borrow_and_update();
                let n = version.wrapping_sub(store_seen);
                store_seen = version;
                let Some(state) = state.upgrade() else { return };
                for _ in 0..n {
                    counts.expectations_size = state.store.all().len();
                    if counts.update() {
                        write_row(&state, &path, &counts);
                    }
                }
            }
            changed = closing.changed() => {
                if changed.is_err() || *closing.borrow() {
                    return;
                }
            }
        }
    }
}

/// `MemoryMonitoring.logMemoryMetrics`: still only while `outputMemoryUsageCsv` is on.
fn write_row(state: &State, path: &Path, counts: &Counts) {
    if !state.config.bool_property("outputMemoryUsageCsv", false) {
        return;
    }
    let effective = crate::config::effective_json(&state.config);
    let int = |name: &str| effective.get(name).and_then(serde_json::Value::as_i64).unwrap_or(0);
    let line = row(state.first_port(), counts, int("maxLogEntries"), int("maxExpectations"), &crate::metrics::process::read());
    write_line(state, path, &line);
}

/// `MemoryMonitoring.writeLineToCsv`: appends the line; a failure is a WARN with the exception.
fn write_line(state: &State, path: &Path, line: &str) {
    use std::io::Write;
    let written = std::fs::OpenOptions::new().create(true).append(true).open(path).and_then(|mut f| f.write_all(format!("{line}\n").as_bytes()));
    if let Err(e) = written {
        let entry = LogEntry::at(Level::Warn, format!("exception writing memory usage statistics to CSV file [{}]", path.display()));
        // the console only, as upstream's static logger has no event log: the message, then the exception's first line
        crate::log::entry_with_throwable(state, Level::Warn, &entry, None, &java_exception(path, &e));
    }
}

/// What `new FileOutputStream(file, true)` throws, as its first console line.
fn java_exception(path: &Path, e: &std::io::Error) -> String {
    let reason = match e.kind() {
        std::io::ErrorKind::NotFound => "No such file or directory".to_string(),
        std::io::ErrorKind::PermissionDenied => "Permission denied".to_string(),
        std::io::ErrorKind::IsADirectory => "Is a directory".to_string(),
        _ => return format!("java.io.IOException: {e}"),
    };
    format!("java.io.FileNotFoundException: {} ({reason})", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fiftieth_update_writes_a_row() {
        let mut counts = Counts::default();
        let rows: Vec<u64> = (1..=120).filter(|_| counts.update()).collect();
        assert_eq!(rows, vec![50, 100]);
    }

    #[test]
    fn file_name_is_upstreams() {
        let date = chrono::NaiveDate::from_ymd_opt(2026, 10, 2).unwrap();
        assert_eq!(csv_path("/tmp/x", date), PathBuf::from("/tmp/x/memoryUsage_2026-10-02.csv"));
        assert_eq!(csv_path(".", date), PathBuf::from("./memoryUsage_2026-10-02.csv"));
    }

    #[test]
    fn row_has_upstreams_five_columns_then_the_process_figures() {
        let counts = Counts { updates: 50, log_size: 30, expectations_size: 24 };
        let process = crate::metrics::process::ProcessStats { max_resident_bytes: 3.0, resident_bytes: Some(1.0), virtual_bytes: None, ..Default::default() };
        assert_eq!(row(1080, &counts, 100_000, 15_000, &process), "1080,30,100000,24,15000,1,,3");
        assert_eq!(HEADER.split(',').count(), row(1080, &counts, 1, 1, &process).split(',').count());
    }

    #[test]
    fn a_missing_directory_is_javas_file_not_found() {
        let e = std::io::Error::from(std::io::ErrorKind::NotFound);
        let path = Path::new("/nonexistent/dir/memoryUsage_2026-10-12.csv");
        assert_eq!(java_exception(path, &e), "java.io.FileNotFoundException: /nonexistent/dir/memoryUsage_2026-10-12.csv (No such file or directory)");
    }

    #[tokio::test]
    async fn header_at_start_and_a_row_on_the_fiftieth_expectation() {
        let dir = std::env::temp_dir().join(format!("memory_csv_{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = crate::Config::for_tests().with_property("outputMemoryUsageCsv", "true").with_property("memoryUsageCsvDirectory", &dir.to_string_lossy());
        let state = State::new(config, vec![1080]);
        start(&state);
        let path = csv_path(&dir.to_string_lossy(), chrono::Local::now().date_naive());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), format!("{HEADER}\n"));
        // 50 expectation updates, one change of the store each; no log change
        for i in 0..50 {
            let body = serde_json::json!({"httpRequest": {"path": format!("/m{i}")}, "httpResponse": {}});
            let e = crate::control::compile_expectation(&state, body.as_object().unwrap());
            state.store.upsert(vec![e]);
            tokio::task::yield_now().await;
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let text = loop {
            let text = std::fs::read_to_string(&path).unwrap();
            if text.lines().count() > 1 || std::time::Instant::now() > deadline {
                break text;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[1].starts_with("1080,0,250000,50,15000,"), "{text}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

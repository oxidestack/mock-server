//! `persistExpectations` (`ExpectationFileSystemPersistence`): the active expectations written to
//! `persistedExpectationsPath` whenever they change.

use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::Value;

use crate::recorded::{Level, LogEntry};
use crate::state::State;

/// Called after expectations change; `source` is the initialisation file that changed them, `None` for the API
/// (and for uses counted down). A file source is not written back when it is the persisted file itself.
pub fn changed(state: &State, source: Option<&str>) {
    // `MockServerMatcherNotifier.notifyListeners`: every registered listener sees the active expectations.
    let listeners = state.listeners.lock().clone();
    if !listeners.is_empty() {
        let active: Vec<Value> = state.store.active().iter().map(|e| e.current()).collect();
        for listener in listeners {
            listener(&active);
        }
    }
    if !state.config.bool_property("persistExpectations", false) {
        return;
    }
    let path = persisted_path(state);
    if let Some(source) = source {
        let init = state.config.property("initializationJsonPath").unwrap_or_default();
        if crate::init::expand(&init).contains(&path) || source == path {
            return;
        }
    }
    // `ExpectationFileSystemPersistence.writeOrderLock`: snapshot, serialisation and write are one unit, so of two
    // concurrent changes the later snapshot is always the later write.
    let _order = WRITE_ORDER.lock();
    log_persisting(state, &path);
    // The persisted form also carries `endDate` of a finite time to live.
    let active: Vec<Value> = state
        .store
        .active()
        .iter()
        .map(|e| {
            let mut v = e.current();
            if let (Some(end), Some(ttl)) = (e.end_date_millis(), v.get_mut("timeToLive").and_then(Value::as_object_mut)) {
                ttl.insert("endDate".into(), end.into());
            }
            v
        })
        .collect();
    let body = if active.is_empty() { "[]".to_string() } else { crate::json::pretty(&Value::Array(active)) };
    // A clustered backend's blob store is not the `FilesystemBlobStore`: the document goes to the replicated `blobs`
    // cache under the file name, and the local file stays as created (`ExpectationFileSystemPersistence.updated`).
    let blobs = uses_blobs(state);
    let key = if blobs { blob_key(&path) } else { filesystem_key(&path) };
    if !back_up_unloadable_entries_once(state, &path, &key, blobs) {
        return;
    }
    let written = if blobs {
        state.state_backend.blobs().try_put(&key, body.into_bytes(), Default::default()).map_err(|e| e.to_string())
    } else {
        put_file(&path, body.as_bytes()).map_err(|e| e.to_string())
    };
    // The exception is the entry's throwable upstream: the console shows it, the entry's message does not; a cloud
    // store's failed write is logged as the file's would be.
    if let Err(e) = written {
        log_failure(state, format!("exception while persisting expectations to {path}"), &e);
    }
}

/// `ExpectationFileSystemPersistence`'s per-server state.
#[derive(Default)]
pub struct Persistence {
    /// `unloadableEntriesChecked`: the first save has checked for (and backed up) unloadable entries.
    unloadable_entries_checked: std::sync::atomic::AtomicBool,
    /// `restoredDocumentWithSkippedEntries`: the blob-store document a restore skipped invalid entries of.
    restored_document_with_skipped_entries: Mutex<Option<Vec<u8>>>,
}

/// `FilesystemBlobStore.put`: missing parent directories are created, and the payload is written to a temporary file
/// in the same directory and moved into place, so a reader (a watcher of the same file) sees the old document or the
/// new one, never a truncated one.
pub fn put_file(path: &str, data: &[u8]) -> std::io::Result<()> {
    let target = std::path::Path::new(path);
    let parent = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(parent)?;
    // `Files.createTempFile(dir, <file name>, ".tmp")`
    let name = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let temp = parent.join(format!("{name}{}.tmp", uuid::Uuid::new_v4().as_u64_pair().0));
    let written = (|| {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
        std::io::Write::write_all(&mut file, data)?;
        file.sync_all()?;
        std::fs::rename(&temp, target)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written
}

/// `BlobKeys.forPersistedFile` for the `FilesystemBlobStore`: the absolute path.
fn filesystem_key(path: &str) -> String {
    std::path::absolute(path).map(|p| p.display().to_string()).unwrap_or_else(|_| path.to_string())
}

/// `ExpectationFileSystemPersistence.backUpUnloadableEntriesOnce`: the first save replaces the document the
/// expectations were loaded from; when that document holds expectations that could not be loaded (a restore skipped
/// them, or the persisted file is also the initialisation file and holds invalid or unparseable entries), the
/// original is first copied, once, to `<key>.invalid-entries-<yyyyMMdd-HHmmss>.bak` and a WARN names the copy. `false`
/// when the copy failed: the save must then not overwrite the original, and the copy is tried again on the next save.
fn back_up_unloadable_entries_once(state: &State, path: &str, key: &str, blobs: bool) -> bool {
    use std::sync::atomic::Ordering;
    let persistence = &state.persistence;
    if persistence.unloadable_entries_checked.swap(true, Ordering::SeqCst) {
        return true;
    }
    let mut original = persistence.restored_document_with_skipped_entries.lock().take();
    let mut backup_key = None;
    let copied = (|| {
        if original.is_none() && !blobs && initialization_path_matches(state, path) {
            match std::fs::read(key) {
                Ok(current) if crate::init::holds_unloadable_expectations(&String::from_utf8_lossy(&current)) => original = Some(current),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        let Some(data) = original.clone() else { return Ok(false) };
        let backup = format!("{key}.invalid-entries-{}.bak", chrono::Local::now().format("%Y%m%d-%H%M%S"));
        backup_key = Some(backup.clone());
        if blobs {
            state.state_backend.blobs().try_put(&backup, data, Default::default()).map_err(|e| e.to_string())?;
        } else {
            put_file(&backup, &data).map_err(|e| e.to_string())?;
        }
        Ok(true)
    })();
    match copied {
        Ok(false) => true,
        Ok(true) => {
            let backup = backup_key.unwrap_or_default();
            crate::log::warn_event(
                state,
                LogEntry::at(
                    Level::Warn,
                    format!("persisted expectations {key} held expectations that could not be loaded, which saving would remove; the original was copied to {backup} - fix them there and copy them back"),
                ),
            );
            true
        }
        Err(e) => {
            // keep the original: invalid entries must never be lost because their copy could not be written
            *persistence.restored_document_with_skipped_entries.lock() = original;
            persistence.unloadable_entries_checked.store(false, Ordering::SeqCst);
            let backup = backup_key.unwrap_or_else(|| format!("{key}.invalid-entries-<timestamp>.bak"));
            log_failure(
                state,
                format!("exception copying persisted expectations {key} that hold expectations that could not be loaded to {backup}; not saving over the original, the copy is tried again on the next save"),
                &e,
            );
            false
        }
    }
}

/// `initializationPathMatchesPersistencePath`: the expanded `initializationJsonPath` names `persistedExpectationsPath`.
fn initialization_path_matches(state: &State, path: &str) -> bool {
    crate::init::expand(&state.config.property("initializationJsonPath").unwrap_or_default()).iter().any(|p| p == path)
}

static WRITE_ORDER: Mutex<()> = Mutex::new(());

/// `ExpectationFileSystemPersistence.updated`'s entry before each write: at TRACE `persisting expectations{}to{}` with
/// the active expectations (as logged, a `List` argument), else at DEBUG `persisting expectations to{}`.
fn log_persisting(state: &State, path: &str) {
    let entry = if state.log_level == "TRACE" {
        let active = state.store.active().iter().map(|e| crate::recorded::Arg::from(crate::canonical::logged_expectation_ending(&e.current(), e.end_date_millis()))).collect();
        LogEntry::at(Level::Trace, "persisting expectations{}to{}").args([crate::recorded::Arg::list(active), path.into()])
    } else if crate::log::debug_enabled(state) {
        LogEntry::at(Level::Debug, "persisting expectations to{}").args([path])
    } else {
        return;
    };
    crate::log::entry(state, &entry);
    state.log.message(entry);
}

/// Whether the persisted document goes to the backend's blob store rather than the file (upstream passes
/// `stateBackend.blobs()` to `ExpectationFileSystemPersistence`; only the `FilesystemBlobStore` writes the file):
/// the Infinispan backends, local or clustered, and `blobStoreType=memory`.
fn uses_blobs(state: &State) -> bool {
    state.state_backend.blobs_replace_files() || state.config.property("blobStoreType").is_some_and(|t| t.eq_ignore_ascii_case("memory"))
}

fn persisted_path(state: &State) -> String {
    state.config.property("persistedExpectationsPath").filter(|p| !p.trim().is_empty()).unwrap_or_else(|| "persistedExpectations.json".into())
}

/// `ExpectationFileSystemPersistence`'s constructor: the persisted file is created (a failure logged), then the
/// persistence announced.
pub fn start(state: &Arc<State>) {
    start_expectations(state);
    start_recorded_expectations(state);
    start_recorded_requests(state);
}

/// An ERROR entry whose exception text only the console shows, as for the persisted expectations above.
fn log_failure(state: &State, message: String, error: &dyn std::fmt::Display) {
    let entry = LogEntry::at(Level::Error, message);
    crate::log::error_as(state, entry.kind, &format!("{}\n\n{error}", crate::log::redacted(state, &entry).message_text()));
    if crate::log::error_enabled(state) {
        state.log.message(entry);
    }
}

/// `RecordedExpectationFileSystemPersistence`: under `persistRecordedExpectations`, the file at
/// `persistedRecordedExpectationsPath` holds every recorded (forwarded) expectation, rewritten whole whenever the
/// event log changes (a forwarded exchange, a clear, a reset, an eviction).
fn start_recorded_expectations(state: &Arc<State>) {
    if !state.config.bool_property("persistRecordedExpectations", false) {
        return;
    }
    let path = state
        .config
        .property("persistedRecordedExpectationsPath")
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(|| "persistedRecordedExpectations.json".into());
    let created = std::fs::OpenOptions::new().write(true).create_new(true).open(&path);
    if let Err(e) = created.map(drop).or_else(|e| if e.kind() == std::io::ErrorKind::AlreadyExists { Ok(()) } else { Err(e) }) {
        log_failure(state, format!("exception creating persisted recorded expectations file {path}"), &e);
    }
    let weak = Arc::downgrade(state);
    // Serialises snapshot and write as one unit, so the file always ends as the latest state.
    let write_order = Mutex::new(());
    let target = path.clone();
    state.log.set_recorded_hook(Arc::new(move |log| {
        let Some(state) = weak.upgrade() else { return };
        let _order = write_order.lock();
        let recorded = log.recorded_expectations();
        let body = if recorded.is_empty() { "[]".to_string() } else { crate::json::pretty(&Value::Array(recorded)) };
        if let Err(e) = put_file(&target, body.as_bytes()) {
            log_failure(&state, format!("exception while persisting recorded expectations to {target}"), &e);
        }
    }));
    crate::log::info_event(state, LogEntry::at(Level::Info, "created recorded expectation file system persistence for{}").args([&path]));
}

/// `RecordedRequestsFileSystemPersistence`: under `persistRecordedRequestsToDisk`, every served exchange (mocked or
/// forwarded; not an unmatched request, not one re-imported from the archive) is appended to
/// `persistedRecordedRequestsPath` as one compact JSON line, written whole per exchange.
fn start_recorded_requests(state: &Arc<State>) {
    if !state.config.bool_property("persistRecordedRequestsToDisk", false) {
        return;
    }
    let path = state
        .config
        .property("persistedRecordedRequestsPath")
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(|| "recordedRequests.ndjson".into());
    let opened = (|| {
        if let Some(parent) = std::path::absolute(&path)?.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::OpenOptions::new().create(true).append(true).open(&path)
    })();
    let file = match opened {
        Ok(file) => Some(file),
        Err(e) => {
            log_failure(state, format!("exception creating recorded requests persistence file {path}"), &e);
            None
        }
    };
    crate::log::info_event(state, LogEntry::at(Level::Info, "created recorded requests file system persistence for{}").args([&path]));
    // A file that could not be opened leaves the persistence inert, as upstream's null writer does.
    let Some(file) = file else { return };
    let weak = Arc::downgrade(state);
    let file = Mutex::new(file);
    state.log.set_exchange_hook(Arc::new(move |exchange| {
        let Some(state) = weak.upgrade() else { return };
        let redacted = crate::recorded::redact_exchanges(vec![Arc::new(exchange.clone())], &state.config);
        let x = &redacted[0];
        let mut line = serde_json::Map::new();
        line.insert("httpRequest".into(), x.shown_request.clone().unwrap_or_else(|| crate::recorded::ordered(&x.request)));
        if !x.response.is_null() {
            line.insert("httpResponse".into(), serde_json::Value::clone(&x.response));
        }
        let compact = collapse_whitespace_runs_containing_line_break(&crate::json::compact(&Value::Object(line)));
        let mut file = file.lock();
        if let Err(e) = std::io::Write::write_all(&mut *file, format!("{compact}\n").as_bytes()).and_then(|_| std::io::Write::flush(&mut *file)) {
            let path = std::fs::canonicalize(&path).map(|p| p.display().to_string()).unwrap_or_else(|_| path.clone());
            log_failure(&state, format!("exception while persisting recorded request to {path}"), &e);
        }
    }));
}

/// `LineBuffer.collapseWhitespaceRunsContainingLineBreak`: keeps a line one NDJSON record. Compact output holds a raw
/// line break only where a scalar JSON body is written verbatim; each maximal run of white space (`[ \t\n\x0B\f\r]`)
/// that holds a `\n` or `\r` becomes one space.
fn collapse_whitespace_runs_containing_line_break(line: &str) -> String {
    if !line.contains(['\n', '\r']) {
        return line.to_string();
    }
    let is_space = |c: char| matches!(c, ' ' | '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r');
    let mut out = String::with_capacity(line.len());
    let mut run = String::new();
    for c in line.chars() {
        if is_space(c) {
            run.push(c);
            continue;
        }
        if run.contains(['\n', '\r']) {
            out.push(' ');
        } else {
            out.push_str(&run);
        }
        run.clear();
        out.push(c);
    }
    if run.contains(['\n', '\r']) {
        out.push(' ');
    } else {
        out.push_str(&run);
    }
    out
}

fn start_expectations(state: &Arc<State>) {
    if !state.config.bool_property("persistExpectations", false) {
        return;
    }
    let path = persisted_path(state);
    let created = std::fs::OpenOptions::new().write(true).create_new(true).open(&path);
    if let Err(e) = created.map(drop).or_else(|e| if e.kind() == std::io::ErrorKind::AlreadyExists { Ok(()) } else { Err(e) }) {
        let entry = LogEntry::at(Level::Error, format!("exception creating persisted expectations file {path}"));
        crate::log::error_as(state, entry.kind, &format!("{}\n\n{e}", crate::log::redacted(state, &entry).message_text()));
        if crate::log::error_enabled(state) {
            state.log.message(entry);
        }
    }
    // Before the persistence is announced (and, upstream, before its listener is registered, so the restore
    // writes nothing back).
    if uses_blobs(state) {
        restore_from_blobs(state, &path);
    }
    crate::log::info_event(state, LogEntry::at(Level::Info, "created expectation file system persistence for{}").args([&path]));
}

/// `BlobKeys.forPersistedFile` for a store that is not the `FilesystemBlobStore`: the file name alone, normalised
/// (an absolute local path is not a valid object-store key).
fn blob_key(path: &str) -> String {
    crate::blob::keys::for_persisted_file(path)
}

/// The prefix of the cause under which restored expectations are loaded, so it can never equal an
/// `initializationJsonPath` (`ExpectationFileSystemPersistence.BLOB_STORE_CAUSE_SOURCE_PREFIX`).
const BLOB_STORE_CAUSE_SOURCE_PREFIX: &str = "blobstore:";

fn log_info(state: &State, message: String) {
    crate::log::info_event(state, LogEntry::at(Level::Info, message));
}

/// `ExpectationFileSystemPersistence.reloadPersistedExpectations`, for a non-filesystem store: the persisted document
/// is read from the backend's blobs (bounded by `blobStoreRestoreTimeoutSeconds`, 0 skips the restore) and its
/// expectations are loaded under the cause `blobstore:<key>`.
fn restore_from_blobs(state: &Arc<State>, path: &str) {
    let key = blob_key(path);
    let timeout = state.config.int_property("blobStoreRestoreTimeoutSeconds", 10);
    if timeout <= 0 {
        if crate::log::debug_enabled(state) {
            state.log.message(LogEntry::at(Level::Debug, format!("skipping restore of persisted expectations from blob store because blobStoreRestoreTimeoutSeconds is {timeout}")));
        }
        return;
    }
    warn_if_initialization_path_shadows(state, path);
    // A worker thread, so that a store that never answers cannot hold up the start past the deadline.
    let (sender, receiver) = std::sync::mpsc::channel();
    let backend = state.state_backend.clone();
    let worker_key = key.clone();
    // A bare "timed out" is not diagnosable on its own: when the deadline has already passed, the worker logs its own
    // failure at DEBUG (diagnostics only; the abandoned restore never touches the expectations).
    let deadline_expired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_expired = deadline_expired.clone();
    let worker_state = Arc::downgrade(state);
    std::thread::Builder::new()
        .name("MockServer-blobStoreRestore".into())
        .spawn(move || {
            let blob = backend.blobs().try_get(&worker_key);
            if let (Err(e), Some(state)) = (&blob, worker_state.upgrade()) && worker_expired.load(std::sync::atomic::Ordering::SeqCst) && crate::log::debug_enabled(&state) {
                let entry = LogEntry::at(
                    Level::Debug,
                    format!("blob store restore for key {worker_key} failed after its {timeout} second deadline had already expired; startup continued without it"),
                );
                crate::log::entry_with_throwable(&state, Level::Debug, &entry, None, &e.to_string());
                state.log.message(entry);
            }
            let _ = sender.send(blob);
        })
        .ok();
    let blob = match receiver.recv_timeout(std::time::Duration::from_secs(timeout as u64)) {
        Ok(blob) => blob,
        Err(_) => {
            deadline_expired.store(true, std::sync::atomic::Ordering::SeqCst);
            crate::log::warn_event(
                state,
                LogEntry::at(
                    Level::Warn,
                    format!(
                        "timed out after {timeout} second(s) restoring persisted expectations from blob store key {key} - starting with no restored expectations (configure mockserver.blobStoreRestoreTimeoutSeconds to change this deadline)"
                    ),
                ),
            );
            return;
        }
    };
    let blob = match blob {
        Ok(blob) => blob,
        Err(e) => return log_failure(state, format!("exception while restoring persisted expectations from blob store for {path}"), &e),
    };
    let Some(blob) = blob else {
        log_info(
            state,
            format!("no persisted expectations found in blob store under key {key} - restore requires the same bucket, the same blobStoreKeyPrefix and the same persistedExpectationsPath file name"),
        );
        return;
    };
    let json = String::from_utf8_lossy(&blob.data).into_owned();
    if json.trim().is_empty() {
        log_info(state, format!("persisted expectations blob at key {key} is empty - nothing to restore"));
        return;
    }
    match restore_expectations(state, &key, &json) {
        Ok(0) => log_info(state, format!("persisted expectations blob at key {key} contained no expectations - nothing to restore")),
        Ok(n) => log_info(state, format!("restored {n} persisted expectation(s) from blob store key {key}")),
        Err(e) => log_failure(state, format!("exception while restoring persisted expectations from blob store for {path}"), &e),
    }
}

/// `ExpectationSerializer.deserializeArray(json, true)` and `RequestMatchers.update(expectations, cause)`.
fn restore_expectations(state: &State, key: &str, json: &str) -> Result<usize, String> {
    let items = match serde_json::from_str::<Value>(json).map_err(|e| e.to_string())? {
        Value::Array(items) => items,
        other => vec![other],
    };
    let mut expectations = Vec::new();
    let mut skipped = false;
    for (index, item) in items.iter().enumerate() {
        // an invalid entry is skipped with a WARN naming it, rather than costing the whole restore
        if let Some(errors) = crate::init::invalid_entry(item) {
            skipped = true;
            let entry = crate::init::describe_entry(item, index, items.len());
            crate::log::warn_event(
                state,
                LogEntry::at(
                    Level::Warn,
                    format!("skipping invalid {entry} in persisted expectations at blob store key {key}; the other expectations are restored; it failed validation with: {errors}"),
                ),
            );
            continue;
        }
        if let Some(o) = item.as_object() {
            expectations.push(crate::control::compile_expectation(state, o));
        }
    }
    if skipped {
        *state.persistence.restored_document_with_skipped_entries.lock() = Some(json.as_bytes().to_vec());
    }
    let n = expectations.len();
    if n > 0 {
        let expectations = crate::store::distinct_by_id(expectations);
        for e in &expectations {
            let verb = match state.store.get(&e.id) {
                None => "creating",
                Some(existing) if existing.canonical != e.canonical => "updated",
                Some(_) => continue,
            };
            crate::control::log_upsert(state, verb, e);
        }
        state.store.update_from_source(&format!("{BLOB_STORE_CAUSE_SOURCE_PREFIX}{key}"), expectations);
    }
    Ok(n)
}

/// Warns when `initializationJsonPath` resolves to `persistedExpectationsPath` under a non-filesystem store: the
/// initializer reads the local file, which the store never fills.
fn warn_if_initialization_path_shadows(state: &State, path: &str) {
    let init = crate::init::expand(&state.config.property("initializationJsonPath").unwrap_or_default());
    if init.is_empty() {
        return;
    }
    let absolute = std::path::absolute(path).map(|p| p.display().to_string()).unwrap_or_else(|_| path.to_string());
    if init.iter().any(|p| p == path || *p == absolute) {
        crate::log::warn_event(
            state,
            LogEntry::at(
                Level::Warn,
                format!(
                    "initializationJsonPath resolves to persistedExpectationsPath ({path}) while a non-filesystem blob store is configured - the initializer reads the LOCAL file, which the blob store never populates, so it adds nothing; persisted expectations are restored from the blob store instead and initializationJsonPath can be removed"
                ),
            ),
        );
    }
}

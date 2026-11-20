//! `initializationJsonPath` and `initializationOpenAPIPath`: expectations loaded from files at startup (§6.6), and
//! reloaded when they change under `watchInitializationJson` (`ExpectationInitializerLoader`,
//! `ExpectationFileWatcher`).

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::recorded::{Kind, Level, LogEntry};
use crate::state::State;
use crate::{control, log, schema};

/// Expands a path the way `FilePath.expandFilePathGlobs` does: nothing for a path without a `.`; a glob when it
/// contains one of `*`, `?`, `{`: the files that match, then the class path resources that do (`crate::class_path`),
/// sorted.
pub fn expand(path: &str) -> Vec<String> {
    if path.trim().is_empty() || !path.contains('.') {
        return Vec::new();
    }
    let is_glob = path.contains(['*', '?', '{']);
    if !is_glob {
        return vec![path.to_string()];
    }
    let patterns = brace_alternatives(path);
    let mut files: Vec<String> = patterns
        .iter()
        .filter_map(|p| glob::glob(p).ok())
        .flatten()
        .filter_map(Result::ok)
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    files.extend(crate::class_path::glob(&patterns, path.rsplit_once('.').map_or("", |(_, extension)| extension)));
    files.sort();
    files.dedup();
    files
}

/// `{a,b}` alternatives, which the `glob` crate does not support.
fn brace_alternatives(pattern: &str) -> Vec<String> {
    let (Some(open), Some(close)) = (pattern.find('{'), pattern.find('}')) else { return vec![pattern.to_string()] };
    if close < open {
        return vec![pattern.to_string()];
    }
    pattern[open + 1..close]
        .split(',')
        .flat_map(|alt| brace_alternatives(&format!("{}{alt}{}", &pattern[..open], &pattern[close + 1..])))
        .collect()
}

/// Loads every file; a bad file is logged and skipped unless `failOnInitializationError` is set
/// (`ExpectationInitializerLoader.retrieveExpectationsFromFile` / `…FromOpenAPIFile`).
pub fn load(state: &State) -> Result<(), String> {
    let fail = state.config.bool_property("failOnInitializationError", false);
    for file in json_paths(state) {
        log::info_event(state, LogEntry::new(Kind::ServerConfiguration, "loading JSON initialization file:{}").args([&file]));
        if let Err(e) = load_json_file(state, &file, LOADED_FROM_FILE) {
            forget_lint(state, &file);
            loading_failed(state, "exception while loading JSON initialization file, ignoring file:{}", &file, &e);
            if fail {
                return Err(fail_fast("JSON file", &file));
            }
        }
    }
    for file in openapi_paths(state) {
        log::info_event(state, LogEntry::new(Kind::ServerConfiguration, "loading OpenAPI initialization file:{}").args([&file]));
        if let Err(e) = load_openapi_file(state, &file, LOADED_FROM_OPENAPI_FILE) {
            loading_failed(state, "exception while loading OpenAPI initialization file, ignoring file:{}", &file, &e);
            if fail {
                return Err(fail_fast("OpenAPI file", &file));
            }
        }
    }
    if let Some(class) = state.config.property("initializationClass").filter(|c| !c.trim().is_empty()) {
        let class = class.trim().to_string();
        log::info_event(state, LogEntry::new(Kind::ServerConfiguration, "loading class initialization file:{}").args([&class]));
        if let Err(e) = load_initializer_class(state, &class) {
            let entry = LogEntry::new(Kind::ServerConfiguration, "exception while loading JSON initialization class, ignoring class:{}").level(Level::Warn).args([&class]);
            // The exception is the entry's throwable upstream: on the console, not in the entry's message.
            log::entry_with_throwable(state, Level::Warn, &entry, None, &e);
            if !matches!(state.log_level.as_str(), "OFF" | "ERROR") {
                state.log.message(entry);
            }
            if fail {
                return Err(fail_fast("class", &class));
            }
        }
    }
    Ok(())
}

/// `ExpectationInitializerLoader.failFastIfConfigured`: the `ExpectationInitializerException` that fails startup
/// under `failOnInitializationError`; the cause is the exception's, not part of its message.
fn fail_fast(kind: &str, source: &str) -> String {
    format!("org.mockserver.server.initialize.ExpectationInitializerException: exception while loading {kind} expectation initializer (failOnInitializationError=true), failing startup for:{source}")
}

/// A file that failed to load: a WARN entry whose throwable (the error) the console shows, the entry's message not.
fn loading_failed(state: &State, format: &str, file: &str, error: &str) {
    let entry = LogEntry::new(Kind::ServerConfiguration, format).level(Level::Warn).args([file]);
    log::entry_with_throwable(state, Level::Warn, &entry, None, error);
    if !matches!(state.log_level.as_str(), "OFF" | "ERROR") {
        state.log.message(entry);
    }
}

/// The TRACE entries of what a load read (`completedLogMessage` of `ExpectationInitializerLoader`), at startup and on
/// a watcher's reload.
const LOADED_FROM_FILE: &str = "loaded expectations:{}from file:{}";
const LOADED_FROM_OPENAPI_FILE: &str = "loaded expectations:{}from OpenAPI file:{}";
const UPDATING_FROM_FILE: &str = "updating expectations:{}from file:{}";
const UPDATING_FROM_OPENAPI_FILE: &str = "updating expectations:{}from OpenAPI file:{}";

/// A TRACE entry of `expectations` (a `List` argument, each as logged) read from `source`.
fn log_loaded(state: &State, format: &str, expectations: &[crate::store::Expectation], source: &str) {
    if state.log_level != "TRACE" {
        return;
    }
    let shown = expectations.iter().map(|e| crate::recorded::Arg::from(crate::canonical::logged_expectation_ending(&e.canonical, e.end_date_millis()))).collect();
    let entry = LogEntry::at(Level::Trace, format).args([crate::recorded::Arg::list(shown), source.into()]);
    log::entry(state, &entry);
    state.log.message(entry);
}

/// `RequestMatchers.update(expectations, cause)`: `creating expectation` for a new id, `updated expectation` for one
/// whose definition changed, then `removed expectation` for each the source no longer holds (each under a
/// correlation id of its own); the listeners (persistence) hear of it only when something changed.
fn update(state: &State, source: &str, expectations: Vec<crate::store::Expectation>, file: Option<&str>) {
    let expectations = crate::store::distinct_by_id(expectations);
    let mut changes = 0;
    for e in &expectations {
        match state.store.get(&e.id) {
            None => control::log_upsert(state, "creating", e),
            Some(existing) if existing.canonical != e.canonical => control::log_upsert(state, "updated", e),
            Some(_) => continue,
        }
        changes += 1;
    }
    let removed = state.store.update_from_source(source, expectations);
    for e in &removed {
        control::log_removals(state, std::slice::from_ref(e), &uuid::Uuid::new_v4().to_string());
    }
    if changes + removed.len() > 0 {
        crate::persistence::changed(state, file);
    }
}

/// `retrieveExpectationsFromInitializerClass`: the `ExpectationInitializer` callback class's expectations.
fn load_initializer_class(state: &State, class: &str) -> Result<usize, String> {
    let resolved = crate::class_callback::resolve(state, class).ok_or_else(|| format!("java.lang.ClassNotFoundException: {class}"))?;
    let Some(initializer) = resolved.initializer() else { return Ok(0) };
    let items = match initializer.initialize_expectations().map_err(|e| e.to_string())? {
        Value::Array(items) => items,
        Value::Null => Vec::new(),
        other => vec![other],
    };
    let expectations: Vec<_> = items.iter().filter_map(Value::as_object).map(|o| control::compile_expectation(state, o)).collect();
    let n = expectations.len();
    if n > 0 {
        log_loaded(state, "loaded expectations:{}from class:{}", &expectations, class);
    }
    state.store.update_from_source(class, expectations);
    crate::persistence::changed(state, None);
    Ok(n)
}

fn json_paths(state: &State) -> Vec<String> {
    expand(&state.config.property("initializationJsonPath").unwrap_or_default())
}

fn openapi_paths(state: &State) -> Vec<String> {
    expand(&state.config.property("initializationOpenAPIPath").unwrap_or_default())
}

/// A JSON initialisation file: expectations, and OpenAPI expectations expanded into one per operation.
fn load_json_file(state: &State, file: &str, completed: &str) -> Result<usize, String> {
    // `FileReader.readFileFromClassPathOrPath`: `new String(bytes, UTF_8)`, malformed input replaced
    let text = String::from_utf8_lossy(&crate::class_path::read_or_file(file).map_err(|e| e.to_string())?).into_owned();
    let items = if text.trim().is_empty() {
        Vec::new()
    } else {
        match serde_json::from_str::<Value>(&text).map_err(|e| e.to_string())? {
            Value::Array(items) => items,
            other => vec![other],
        }
    };
    let mut expectations = Vec::new();
    let mut skipped = Vec::new();
    let mut generated = std::collections::HashSet::new();
    let count = items.len();
    for (index, mut item) in items.into_iter().enumerate() {
        if let Some(o) = item.as_object().filter(|o| o.contains_key("specUrlOrPayload")) {
            let built = crate::openapi::logging_load_problems(state, || {
                crate::openapi_expectations::build(o, state.config.bool_property("generateRealisticExampleValues", false))
            })?;
            for built in built {
                expectations.push(control::compile_expectation(state, &built));
            }
            continue;
        }
        // `deserializeArrayDroppingInvalidEntries`: one invalid entry is skipped with a WARN, not the whole file
        if let Some(errors) = invalid_entry(&item) {
            let entry = describe_entry(&item, index, count);
            let warning = LogEntry::new(Kind::ServerConfiguration, "skipping an invalid expectation in JSON initialization file:{}which is:{}the other expectations in the file are loaded; it failed validation with:{}")
                .level(Level::Warn)
                .args([file, entry.as_str(), errors.as_str()]);
            log::entry(state, &warning);
            if !matches!(state.log_level.as_str(), "OFF" | "ERROR") {
                state.log.message(warning);
            }
            skipped.push(entry);
            continue;
        }
        let Some(o) = item.as_object_mut() else { continue };
        if !o.contains_key("id") {
            // Stable across restarts and reloads, like upstream's name-based UUID of (path, content, index).
            let name = format!("{file}\n{index}\n{text}");
            let id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, name.as_bytes()).to_string();
            generated.insert(id.clone());
            o.insert("id".into(), id.into());
        }
        expectations.push(control::compile_expectation(state, o));
    }
    if !skipped.is_empty() && state.config.bool_property("failOnInitializationError", false) {
        return Err(format!("java.lang.IllegalArgumentException: skipped {} invalid expectation(s): {}", skipped.len(), skipped.join(", ")));
    }
    advise_on_load(state, file, &expectations, &generated);
    let n = expectations.len();
    log_loaded(state, completed, &expectations, file);
    update(state, file, expectations, Some(file));
    Ok(n)
}

/// `ExpectationInitializerLoader.adviseOnLoad`: one WARN naming the file for the lint problems of what it loaded
/// (ids in `generated` were assigned by the loader, so messages name those by method and path), unless the last
/// load of the file reported the same ones.
fn advise_on_load(state: &State, file: &str, expectations: &[crate::store::Expectation], generated: &std::collections::HashSet<String>) {
    const MAX_LINT_DIGESTS: usize = 1_000;
    // `ExpectationLinter.adviseOnLoad` lints nothing when WARN is not logged, and leaves the digest as it was
    if matches!(state.log_level.as_str(), "OFF" | "ERROR") {
        return;
    }
    let loaded: Vec<(Value, Value, bool)> = expectations.iter().map(|e| (e.input.clone(), e.canonical.clone(), generated.contains(&e.id))).collect();
    let mut digests = state.lint_digests.lock().unwrap();
    let previous = digests.get(file).copied().unwrap_or(0);
    let (digest, warning) = crate::lint::advise_on_load(&loaded, previous);
    if digest == 0 {
        digests.remove(file);
    } else {
        if digests.len() >= MAX_LINT_DIGESTS && !digests.contains_key(file) {
            digests.clear();
        }
        digests.insert(file.to_string(), digest);
    }
    drop(digests);
    if let Some((format, lines)) = warning {
        log::warn_event(state, LogEntry::at(Level::Warn, format).args([file, lines.as_str()]));
    }
}

/// A file that failed to load lints as empty: its digest is forgotten.
fn forget_lint(state: &State, file: &str) {
    if !matches!(state.log_level.as_str(), "OFF" | "ERROR") {
        state.lint_digests.lock().unwrap().remove(file);
    }
}

/// Why `ExpectationSerializer.deserialize` refuses one entry of an expectation array (`incorrect expectation json
/// format for: … schema validation errors: …`), `None` when it is valid.
pub fn invalid_entry(item: &Value) -> Option<String> {
    schema::validate_expectation(item).err().map(|report| schema::incorrect_expectation(item, &report))
}

/// `ExpectationSerializer.describeEntry`: `expectation <n> of <count>`, then its id and request path when it has them.
pub fn describe_entry(item: &Value, index: usize, count: usize) -> String {
    let mut description = format!("expectation {} of {count}", index + 1);
    if let Some(id) = item.get("id").and_then(Value::as_str) {
        description.push_str(&format!(" (id \"{id}\")"));
    }
    // `JsonNode.isValueNode()` then `asText()`: a string, number, boolean or null
    match item.get("httpRequest").and_then(|r| r.get("path")) {
        Some(Value::String(path)) => description.push_str(&format!(" for path \"{path}\"")),
        Some(path @ (Value::Number(_) | Value::Bool(_))) => description.push_str(&format!(" for path \"{path}\"")),
        Some(Value::Null) => description.push_str(" for path \"null\""),
        _ => {}
    }
    description
}

/// Whether a persisted document holds expectations that could not be loaded: unparseable, or an invalid entry
/// (`ExpectationFileSystemPersistence.holdsUnloadableExpectations`). A blank document holds none.
pub fn holds_unloadable_expectations(json: &str) -> bool {
    if json.trim().is_empty() {
        return false;
    }
    match serde_json::from_str::<Value>(json) {
        Ok(Value::Array(items)) => items.iter().any(|item| !is_openapi_entry(item) && invalid_entry(item).is_some()),
        Ok(item) => !is_openapi_entry(&item) && invalid_entry(&item).is_some(),
        Err(_) => true,
    }
}

fn is_openapi_entry(item: &Value) -> bool {
    item.as_object().is_some_and(|o| o.contains_key("specUrlOrPayload"))
}

/// An OpenAPI initialisation file: an expectation per operation (`OpenAPIConverter.buildExpectations`).
fn load_openapi_file(state: &State, file: &str, completed: &str) -> Result<usize, String> {
    // `ExpectationInitializerLoader` hands `openAPIContextPathPrefix` to `buildExpectations`, which names it on each
    // built definition.
    let mut definition = serde_json::json!({"specUrlOrPayload": file});
    if let Some(prefix) = state.config.property("openAPIContextPathPrefix").filter(|p| !p.trim().is_empty()) {
        definition["contextPathPrefix"] = prefix.into();
    }
    let built = crate::openapi::logging_load_problems(state, || {
        crate::openapi_expectations::build(definition.as_object().expect("an object"), state.config.bool_property("generateRealisticExampleValues", false))
    })?;
    let expectations: Vec<_> = built.iter().map(|o| control::compile_expectation(state, o)).collect();
    let n = expectations.len();
    log_loaded(state, completed, &expectations, file);
    update(state, file, expectations, Some(file));
    Ok(n)
}

/// `FileWatcher.getFileHash`: `Arrays.hashCode` of the file's bytes, `None` when it cannot be read.
fn file_hash(path: &str) -> Option<i32> {
    let bytes = std::fs::read(path).ok()?;
    Some(bytes.iter().fold(1i32, |h, b| h.wrapping_mul(31).wrapping_add(i32::from(*b as i8))))
}

/// `ExpectationFileWatcher`: a `FileWatcher` per initialisation file, each polling every
/// `watchInitializationJsonPollPeriodMillis`. A file whose fingerprint changed (an unreadable one is skipped, not a
/// change) reloads every file, as `addExpectationsFromInitializer` does.
pub fn watch(state: &Arc<State>) {
    if !state.config.bool_property("watchInitializationJson", false) {
        return;
    }
    let files: Vec<String> = json_paths(state).into_iter().chain(openapi_paths(state)).collect();
    if files.is_empty() {
        return;
    }
    let period = Duration::from_millis(state.config.int_property("watchInitializationJsonPollPeriodMillis", 5000).max(1) as u64);
    let mut hashes = Vec::with_capacity(files.len());
    for file in &files {
        // `FileWatcher`: a path without a parent is taken from the working directory.
        let watched = if std::path::Path::new(file).parent().is_some_and(|p| !p.as_os_str().is_empty()) {
            file.clone()
        } else {
            format!("{}/./{file}", std::env::current_dir().map(|d| d.display().to_string()).unwrap_or_default())
        };
        let hash = file_hash(&watched);
        let shown = hash.map_or_else(|| "null".to_string(), |h| h.to_string());
        let fingerprint = hash.map_or(Value::Null, Value::from);
        log::info_event(state, LogEntry::at(Level::Info, "watching file:{}with file fingerprint:{}").args([crate::recorded::Arg::from(watched.as_str()), crate::recorded::Arg::with_text(fingerprint, shown)]));
        hashes.push((file.clone(), watched, hash));
    }
    log::info_event(
        state,
        LogEntry::at(Level::Info, "created expectation file watcher for{}").args([crate::recorded::Arg::list(files.iter().map(crate::recorded::Arg::from).collect())]),
    );
    let state = state.clone();
    tokio::spawn(async move {
        let mut stopped = state.stopped.subscribe();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(period) => {}
                _ = stopped.wait_for(|s| *s) => return,
            }
            for (file, watched, last) in hashes.iter_mut() {
                let Some(current) = file_hash(watched) else { continue };
                if Some(current) == *last {
                    continue;
                }
                if log::debug_enabled(&state) {
                    let entry = LogEntry::at(Level::Debug, "expectation file watcher updating expectations as modification detected on file{}").args([file.as_str()]);
                    log::entry(&state, &entry);
                    state.log.message(entry);
                }
                for file in json_paths(&state) {
                    if let Err(e) = load_json_file(&state, &file, UPDATING_FROM_FILE) {
                        forget_lint(&state, &file);
                        loading_failed(&state, "exception while loading JSON initialization file with file watcher, ignoring file:{}", &file, &e);
                    }
                }
                for file in openapi_paths(&state) {
                    if let Err(e) = load_openapi_file(&state, &file, UPDATING_FROM_OPENAPI_FILE) {
                        loading_failed(&state, "exception while loading OpenAPI initialization file with file watcher, ignoring file:{}", &file, &e);
                    }
                }
                *last = Some(file_hash(watched).unwrap_or(current));
            }
        }
    });
}

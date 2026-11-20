//! `RecordedBodyFileExtractor` (`retrieve?type=RECORDED_EXPECTATIONS&extractBodiesLargerThan=<bytes>`): each recorded
//! response body (a sequence's too) of a STRING, JSON, XML or BINARY type with more bytes than the threshold is
//! written to the configured `recordedBodyFilesDirectory` and replaced by a FILE body naming it. A file is named by
//! the SHA-256 of its bytes plus an extension from the content type, so nothing recorded reaches the name and a body
//! is written once: an existing regular file of that name and size is reused, anything else there is replaced by a
//! temporary file (owner-only) moved into place. One retrieve references at most 1,000 files and 256 MiB and starts
//! no write once `maxFutureTimeoutInMillis` (capped at a day) is spent; bodies past a limit stay inline.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::{Map, Value};

use crate::recorded::Exchange;
use crate::request::HttpRequest;
use crate::state::State;

const MAX_FILES_PER_RUN: usize = 1000;
const MAX_BYTES_PER_RUN: u64 = 256 * 1024 * 1024;
const MAX_TIME_BUDGET_MILLIS: u64 = 24 * 60 * 60 * 1000;
const PARAMETER: &str = "extractBodiesLargerThan";

pub struct Extractor {
    directory: String,
    threshold: u64,
    time_budget_millis: u64,
}

/// `recordedBodyFileExtractor`: `None` without a non-blank `extractBodiesLargerThan`; the 400 text for a threshold
/// that is not a whole number of bytes (`Long.parseLong` of it trimmed, at least zero) or a blank directory.
pub fn extractor(state: &State, request: &HttpRequest) -> Result<Option<Extractor>, String> {
    let Some(threshold) = crate::request::first(&request.query, PARAMETER).filter(|t| !t.trim().is_empty()) else { return Ok(None) };
    let parsed = threshold.trim().parse::<i64>().unwrap_or(-1);
    if parsed < 0 {
        return Err(format!("\"{threshold}\" is not a valid value for \"{PARAMETER}\" parameter, it must be a number of bytes greater than or equal to zero"));
    }
    let directory = state.config.property("recordedBodyFilesDirectory").filter(|d| !d.trim().is_empty());
    let Some(directory) = directory else {
        return Err(format!("\"{PARAMETER}\" requires the recordedBodyFilesDirectory configuration property to name the directory recorded bodies are written to"));
    };
    let time_budget_millis = state.config.int_property("maxFutureTimeoutInMillis", 90_000).max(0) as u64;
    Ok(Some(Extractor { directory, threshold: parsed as u64, time_budget_millis }))
}

/// `isControlPlaneRead`'s exception: a retrieve asking for bodies to be written to files changes server state.
pub fn writes_files(request: &HttpRequest) -> bool {
    crate::request::first(&request.query, PARAMETER).is_some_and(|t| !t.trim().is_empty())
}

struct Run {
    deadline: Instant,
    files: HashSet<String>,
    bytes: u64,
    written: u64,
    bytes_written: u64,
    kept_inline_over_limit: u64,
}

impl Extractor {
    /// `extract`: the exchanges with their recorded response bodies moved to files; one INFO entry when any file is
    /// referenced or any body was kept inline over a limit.
    pub fn extract(&self, state: &State, recorded: Vec<Arc<Exchange>>) -> Vec<Arc<Exchange>> {
        let budget = Duration::from_millis(self.time_budget_millis.min(MAX_TIME_BUDGET_MILLIS));
        let mut run = Run { deadline: Instant::now() + budget, files: HashSet::new(), bytes: 0, written: 0, bytes_written: 0, kept_inline_over_limit: 0 };
        let out = recorded.into_iter().map(|x| self.extract_exchange(state, x, &mut run)).collect();
        if !run.files.is_empty() || run.kept_inline_over_limit > 0 {
            let entry = crate::recorded::LogEntry::new(
                crate::recorded::Kind::Info,
                "recorded response bodies moved to files in{}files referenced:{}files written:{}bytes written:{}bodies kept inline over the per-retrieve limit:{}file limit:{}byte limit:{}time limit in milliseconds:{}",
            )
            .args([
                self.directory.clone(),
                run.files.len().to_string(),
                run.written.to_string(),
                run.bytes_written.to_string(),
                run.kept_inline_over_limit.to_string(),
                MAX_FILES_PER_RUN.to_string(),
                MAX_BYTES_PER_RUN.to_string(),
                self.time_budget_millis.to_string(),
            ]);
            state.log.message(entry);
        }
        out
    }

    fn extract_exchange(&self, state: &State, exchange: Arc<Exchange>, run: &mut Run) -> Arc<Exchange> {
        let Some(canonical) = exchange.recorded.as_ref() else { return exchange };
        // (canonical pointer, input pointer) of each response body.
        let mut targets: Vec<(String, String)> = Vec::new();
        if canonical.get("httpResponse").is_some_and(Value::is_object) {
            targets.push(("/httpResponse".into(), "/httpResponse".into()));
        }
        if let Some(responses) = canonical.get("httpResponses").and_then(Value::as_array) {
            targets.extend((0..responses.len()).map(|i| (format!("/httpResponses/{i}"), format!("/httpResponses/{i}"))));
        }
        let mut changed: Vec<(String, String, Value, Value)> = Vec::new();
        for (canonical_at, input_at) in targets {
            let Some(response) = canonical.pointer(&canonical_at) else { continue };
            if let Some((canonical_body, input_body)) = self.extract_response(state, response, run) {
                changed.push((canonical_at, input_at, canonical_body, input_body));
            }
        }
        if changed.is_empty() {
            return exchange;
        }
        let mut copy = (*exchange).clone();
        for (canonical_at, input_at, canonical_body, input_body) in changed {
            if let Some(Value::Object(response)) = copy.recorded.as_mut().and_then(|c| c.pointer_mut(&canonical_at)) {
                response.insert("body".into(), canonical_body);
            }
            if let Some(Value::Object(response)) = copy.recorded_input.as_mut().and_then(|i| i.pointer_mut(&input_at)) {
                response.insert("body".into(), input_body);
            }
        }
        Arc::new(copy)
    }

    /// The FILE body (canonical, input) replacing `response`'s body, or `None` to keep it inline.
    fn extract_response(&self, state: &State, response: &Value, run: &mut Run) -> Option<(Value, Value)> {
        let body = response.get("body")?;
        let (kind, bytes) = body_bytes(body)?;
        if !matches!(kind.as_str(), "STRING" | "JSON" | "XML" | "BINARY") || bytes.len() as u64 <= self.threshold {
            return None;
        }
        let content_type = body
            .get("contentType")
            .and_then(Value::as_str)
            .filter(|c| !c.trim().is_empty())
            .map(str::to_string)
            .or_else(|| first_header(response, "content-type"));
        let file_name = format!("{}{}", hex(ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref()), extension(content_type.as_deref()));
        if !run.files.contains(&file_name) {
            if run.files.len() >= MAX_FILES_PER_RUN || run.bytes + bytes.len() as u64 > MAX_BYTES_PER_RUN || Instant::now() >= run.deadline {
                run.kept_inline_over_limit += 1;
                return None;
            }
            match self.write(&file_name, &bytes) {
                Ok(true) => {
                    run.written += 1;
                    run.bytes_written += bytes.len() as u64;
                }
                Ok(false) => {}
                Err(_) => {
                    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "could not write recorded response body to{}in{}so it is kept in the expectation")
                        .args([file_name.clone(), self.directory.clone()]);
                    state.log.message(entry);
                    return None;
                }
            }
            run.files.insert(file_name.clone());
            run.bytes += bytes.len() as u64;
        }
        // `Paths.get(directory, fileName).toString()`
        let path = Path::new(&self.directory).join(&file_name).to_string_lossy().into_owned();
        let media_type = content_type.as_deref().and_then(media_type_text);
        let mut file_body = Map::new();
        file_body.insert("type".into(), "FILE".into());
        file_body.insert("filePath".into(), path.into());
        if let Some(media_type) = media_type {
            file_body.insert("contentType".into(), media_type.into());
        }
        let input = Value::Object(file_body);
        let canonical = crate::canonical::response(&serde_json::json!({"body": input.clone()})).get("body").cloned().unwrap_or_else(|| input.clone());
        Some((canonical, input))
    }

    /// `write`: `Ok(false)` when an identical-size regular file is already there.
    fn write(&self, file_name: &str, bytes: &[u8]) -> std::io::Result<bool> {
        let directory = PathBuf::from(&self.directory);
        std::fs::create_dir_all(&directory)?;
        let target = directory.join(file_name);
        if let Ok(meta) = std::fs::symlink_metadata(&target) && meta.file_type().is_file() && meta.len() == bytes.len() as u64 {
            return Ok(false);
        }
        let temporary = directory.join(format!(".recorded-body-{}.tmp", uuid::Uuid::new_v4().simple()));
        let result = (|| {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let mut file = options.open(&temporary)?;
            file.write_all(bytes)?;
            drop(file);
            std::fs::rename(&temporary, &target)
        })();
        let _ = std::fs::remove_file(&temporary);
        result.map(|()| true)
    }
}

/// A recorded body's type and `getRawBytes()`.
fn body_bytes(body: &Value) -> Option<(String, Vec<u8>)> {
    let decode = |v: &Value| v.as_str().and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok());
    match body {
        Value::String(s) => Some(("STRING".into(), s.as_bytes().to_vec())),
        Value::Object(o) => {
            let kind = o.get("type").and_then(Value::as_str).unwrap_or("STRING").to_string();
            if let Some(raw) = o.get("rawBytes").and_then(decode) {
                return Some((kind, raw));
            }
            let content_type = o.get("contentType").and_then(Value::as_str);
            let text = |k: &str| o.get(k).map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string));
            let bytes = match kind.as_str() {
                "BINARY" => o.get("base64Bytes").and_then(decode)?,
                "STRING" => crate::canonical::encode(&text("string")?, content_type),
                "JSON" => crate::canonical::encode(&text("json")?, content_type),
                "XML" => crate::canonical::encode(&text("xml")?, content_type),
                _ => return None,
            };
            Some((kind, bytes))
        }
        _ => None,
    }
}

fn first_header(response: &Value, name: &str) -> Option<String> {
    super::redact::entry_list(response.get("headers")?)
        .into_iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .and_then(|(_, values)| values.into_iter().next())
}

/// `MediaType.parse(contentType).toString()`.
fn media_type_text(content_type: &str) -> Option<String> {
    Some(crate::media_type::normalise(content_type)).filter(|t| !t.is_empty())
}

/// `extension`: from the content type without parameters.
fn extension(content_type: Option<&str>) -> &'static str {
    let Some(content_type) = content_type else { return ".bin" };
    let lower = content_type.to_lowercase();
    let kind = lower.split(';').next().unwrap_or_default().trim();
    if kind.ends_with("/json") || kind.ends_with("+json") {
        ".json"
    } else if kind.ends_with("/xml") || kind.ends_with("+xml") {
        ".xml"
    } else if kind == "text/html" {
        ".html"
    } else if kind.starts_with("text/") {
        ".txt"
    } else {
        ".bin"
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}


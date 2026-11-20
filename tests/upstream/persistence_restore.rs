//! Ports of mockserver-core's `FilesystemBlobStoreAtomicWriteTest` (the persisted expectations file is
//! replaced whole, never seen truncated) and `ExpectationBlobStoreRestoreTest` (the restore of persisted expectations
//! from a blob store at start). The restore needs a blob that exists before the server starts, which an oracle
//! scenario cannot seed; the blob store here is `blobStoreType=s3` pointed at a second in-process server that plays
//! the bucket (`GET /<bucket>/<key>` answers the object, `PUT` stores one), so a blank, malformed, partly invalid, slow
//! or failing object is one expectation away and every request the store made can be retrieved.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::common::{self, Running};

const BUCKET: &str = "restore-bucket";

/// A fresh directory under the system temp directory, for a persisted file of its own.
fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("{name}-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A server persisting to `persisted.json` in `dir` through an S3 store whose endpoint is `bucket`.
async fn start_restoring(bucket: &Running, dir: &std::path::Path, timeout_seconds: &str, log_level: &str) -> Running {
    let path = dir.join("persisted.json").to_string_lossy().into_owned();
    let endpoint = format!("http://127.0.0.1:{}", bucket.port);
    common::start(&[
        ("logLevel", log_level),
        ("persistExpectations", "true"),
        ("persistedExpectationsPath", &path),
        ("blobStoreType", "s3"),
        ("blobStoreModules", "s3"),
        ("blobStoreBucket", BUCKET),
        ("blobStoreRegion", "us-east-1"),
        ("blobStoreEndpoint", &endpoint),
        ("blobStoreAccessKeyId", "access"),
        ("blobStoreSecretAccessKey", "secret"),
        ("blobStoreRestoreTimeoutSeconds", timeout_seconds),
    ])
    .await
}

/// The bucket's object `persisted.json` answers `response`.
async fn object(bucket: &Running, response: Value) {
    common::expect(bucket.port, &json!({"httpRequest": {"method": "GET", "path": format!("/{BUCKET}/persisted.json")}, "httpResponse": response})).await;
}

/// Every `PUT` into the bucket is stored (answered 200).
async fn accept_puts(bucket: &Running) {
    common::expect(bucket.port, &json!({"httpRequest": {"method": "PUT", "path": format!("/{BUCKET}/.*")}, "httpResponse": {"statusCode": 200}})).await;
}

/// The paths of the `PUT`s the bucket received, in order.
async fn puts(bucket: &Running) -> Vec<String> {
    let body = common::send(bucket.port, "PUT", "/mockserver/retrieve?type=REQUESTS&format=JSON", &json!({"method": "PUT"}).to_string()).await.body;
    let requests: Vec<Value> = serde_json::from_str(&body).unwrap();
    requests.iter().map(|r| r["path"].as_str().unwrap_or_default().to_string()).collect()
}

/// The body of the `PUT` the bucket received into `key`, the last one.
async fn put_body(bucket: &Running, key: &str) -> String {
    let filter = json!({"method": "PUT", "path": format!("/{BUCKET}/{key}")});
    let body = common::send(bucket.port, "PUT", "/mockserver/retrieve?type=REQUESTS&format=JSON", &filter.to_string()).await.body;
    let requests: Vec<Value> = serde_json::from_str(&body).unwrap();
    let last = requests.last().unwrap_or_else(|| panic!("no PUT into {key}"));
    match &last["body"] {
        Value::String(s) => s.clone(),
        // an `application/octet-stream` body is recorded as binary
        Value::Object(o) if o.contains_key("base64Bytes") => {
            use base64::Engine;
            String::from_utf8(base64::engine::general_purpose::STANDARD.decode(o["base64Bytes"].as_str().unwrap_or_default()).unwrap()).unwrap()
        }
        Value::Object(o) => o.get("string").or_else(|| o.get("json")).map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string)).unwrap_or_default(),
        other => other.to_string(),
    }
}

async fn get(running: &Running, path: &str) -> common::Response {
    common::send(running.port, "GET", path, "").await
}

async fn await_logged(running: &Running, text: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let logs = common::logs(running.port).await;
        if logs.contains(text) || Instant::now() >= deadline {
            return logs;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

const VALID: &str = r#"{"id": "restored", "httpRequest": {"path": "/restored"}, "httpResponse": {"body": "restored response"}}"#;
const INVALID: &str = r#"{"id": "broken", "httpRequest": {"path": "/broken"}, "httpResponse": {"statusCode": "not a number"}}"#;

// ---------------------------------------------------------------- FilesystemBlobStoreAtomicWriteTest

/// `concurrentReaderNeverObservesTruncatedOrPartialFile` and `overwriteReplacesPreviousContentAtomically`: while
/// every change rewrites the persisted file, a reader polling it (as a watcher of the same path does) only ever sees a
/// whole document, the previous one or the next.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_reader_never_observes_truncated_or_partial_file() {
    let dir = temp_dir("atomicWrite");
    let path = dir.join("persisted.json");
    let running = common::start(&[("persistExpectations", "true"), ("persistedExpectationsPath", &path.to_string_lossy())]).await;
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = {
        let (path, stop) = (path.clone(), stop.clone());
        std::thread::spawn(move || {
            let (mut reads, mut torn) = (0usize, Vec::new());
            let mut seen_document = false;
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                let Ok(text) = std::fs::read_to_string(&path) else { continue };
                reads += 1;
                if text.is_empty() && !seen_document {
                    continue;
                }
                seen_document = true;
                if serde_json::from_str::<Value>(&text).is_err() && torn.len() < 3 {
                    torn.push(format!("{} bytes", text.len()));
                }
            }
            (reads, torn)
        })
    };
    let large = "x".repeat(256 * 1024);
    for i in 0..40 {
        common::expect(running.port, &json!({"id": format!("e{i}"), "httpRequest": {"path": format!("/large/{i}")}, "httpResponse": {"body": large}})).await;
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let (reads, torn) = reader.join().unwrap();
    assert!(reads > 0, "the reader read the persisted file");
    assert!(torn.is_empty(), "the reader saw a truncated or partial persisted file: {torn:?} (of {reads} reads)");
    let last: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(last.as_array().map(Vec::len), Some(40), "the last write is the whole document");
    running.server.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// `putDoesNotLeaveTemporaryFilesBehind`: the temporary file each write goes through is moved into place.
#[tokio::test(flavor = "multi_thread")]
async fn put_does_not_leave_temporary_files_behind() {
    let dir = temp_dir("noTemporaryFiles");
    let path = dir.join("persisted.json");
    let running = common::start(&[("persistExpectations", "true"), ("persistedExpectationsPath", &path.to_string_lossy())]).await;
    for i in 0..5 {
        common::expect(running.port, &json!({"httpRequest": {"path": format!("/p/{i}")}, "httpResponse": {"body": "b"}})).await;
    }
    let mut names: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names, vec!["persisted.json".to_string()]);
    running.server.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------- ExpectationBlobStoreRestoreTest

/// `shouldNotRestoreThroughTheFilesystemBlobStore`: with the default filesystem store, a persisted file present at
/// start is not loaded by the persistence (only an `initializationJsonPath` naming it loads it).
#[tokio::test(flavor = "multi_thread")]
async fn should_not_restore_through_the_filesystem_blob_store() {
    let dir = temp_dir("filesystemNoRestore");
    let path = dir.join("persisted.json");
    std::fs::write(&path, format!("[{VALID}]")).unwrap();
    let running = common::start(&[("persistExpectations", "true"), ("persistedExpectationsPath", &path.to_string_lossy())]).await;
    assert_eq!(get(&running, "/restored").await.status, 404, "the persisted file is not restored");
    let logs = common::logs(running.port).await;
    assert!(!logs.contains("from blob store"), "no restore is logged: {logs}");
    running.server.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// `shouldStartCleanlyWhenThePersistedBlobIsBlank`.
#[tokio::test(flavor = "multi_thread")]
async fn should_start_cleanly_when_the_persisted_blob_is_blank() {
    let bucket = common::start(&[]).await;
    object(&bucket, json!({"body": "   \n  "})).await;
    let dir = temp_dir("blankBlob");
    let running = start_restoring(&bucket, &dir, "10", "INFO").await;
    let logs = common::logs(running.port).await;
    assert!(logs.contains("persisted expectations blob at key persisted.json is empty - nothing to restore"), "{logs}");
    assert_eq!(get(&running, "/restored").await.status, 404);
    running.server.shutdown().await;
    bucket.server.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// `shouldStartWhenThePersistedBlobIsMalformedRatherThanFailingStartup`.
#[tokio::test(flavor = "multi_thread")]
async fn should_start_when_the_persisted_blob_is_malformed_rather_than_failing_startup() {
    let bucket = common::start(&[]).await;
    object(&bucket, json!({"body": "[ { this is not json"})).await;
    let dir = temp_dir("malformedBlob");
    let running = start_restoring(&bucket, &dir, "10", "INFO").await;
    let logs = common::logs(running.port).await;
    let path = dir.join("persisted.json").to_string_lossy().into_owned();
    assert!(logs.contains(&format!("exception while restoring persisted expectations from blob store for {path}")), "{logs}");
    // the server serves all the same
    common::expect(running.port, &json!({"httpRequest": {"path": "/after"}, "httpResponse": {"body": "after"}})).await;
    assert_eq!(get(&running, "/after").await.body, "after");
    running.server.shutdown().await;
    bucket.server.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// `shouldRestoreTheValidExpectationsAndSkipAnInvalidOneWithAWarningNamingIt`, then the first save backs the
/// restored document up (`<key>.invalid-entries-<ts>.bak`) before it writes over it.
#[tokio::test(flavor = "multi_thread")]
async fn should_restore_the_valid_expectations_and_skip_an_invalid_one_with_a_warning_naming_it() {
    let bucket = common::start(&[]).await;
    let document = format!("[{VALID}, {INVALID}]");
    object(&bucket, json!({"body": document})).await;
    accept_puts(&bucket).await;
    let dir = temp_dir("partlyInvalidBlob");
    let running = start_restoring(&bucket, &dir, "10", "INFO").await;
    assert_eq!(get(&running, "/restored").await.body, "restored response", "the valid expectation is restored");
    assert_eq!(get(&running, "/broken").await.status, 404, "the invalid one is not");
    let logs = common::logs(running.port).await;
    assert!(
        logs.contains("skipping invalid expectation 2 of 2 (id \"broken\") for path \"/broken\" in persisted expectations at blob store key persisted.json; the other expectations are restored; it failed validation with: incorrect expectation json format for:"),
        "{logs}"
    );
    assert!(logs.contains("restored 1 persisted expectation(s) from blob store key persisted.json"), "{logs}");
    assert!(puts(&bucket).await.is_empty(), "the restore itself writes nothing back");

    common::expect(running.port, &json!({"httpRequest": {"path": "/added"}, "httpResponse": {"body": "added"}})).await;
    let logs = await_logged(&running, "held expectations that could not be loaded").await;
    assert!(logs.contains("persisted expectations persisted.json held expectations that could not be loaded, which saving would remove; the original was copied to persisted.json.invalid-entries-"), "{logs}");
    let puts = puts(&bucket).await;
    assert_eq!(puts.len(), 2, "the backup, then the save: {puts:?}");
    assert!(puts[0].starts_with(&format!("/{BUCKET}/persisted.json.invalid-entries-")) && puts[0].ends_with(".bak"), "{puts:?}");
    assert_eq!(puts[1], format!("/{BUCKET}/persisted.json"));
    let backup_key = puts[0].trim_start_matches(&format!("/{BUCKET}/")).to_string();
    assert_eq!(put_body(&bucket, &backup_key).await, document, "the backup is the restored document as it was");

    common::expect(running.port, &json!({"httpRequest": {"path": "/later"}, "httpResponse": {"body": "later"}})).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while self::puts(&bucket).await.len() < 3 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let all = self::puts(&bucket).await;
    assert_eq!(all.iter().filter(|p| p.contains(".invalid-entries-")).count(), 1, "backed up once only: {all:?}");
    running.server.shutdown().await;
    bucket.server.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// `shouldNotSaveOverTheOriginalWhenItsBackupCannotBeWrittenAndRetryOnTheNextSave`.
#[tokio::test(flavor = "multi_thread")]
async fn should_not_save_over_the_original_when_its_backup_cannot_be_written_and_retry_on_the_next_save() {
    let bucket = common::start(&[]).await;
    object(&bucket, json!({"body": format!("[{VALID}, {INVALID}]")})).await;
    // the first backup is refused, every later PUT stored
    common::expect(
        bucket.port,
        &json!({"httpRequest": {"method": "PUT", "path": format!("/{BUCKET}/persisted.json.invalid-entries-.*")}, "httpResponse": {"statusCode": 403, "body": "<Error><Code>AccessDenied</Code><Message>denied</Message></Error>"}, "times": {"remainingTimes": 1}, "priority": 10}),
    )
    .await;
    accept_puts(&bucket).await;
    let dir = temp_dir("backupRefused");
    let running = start_restoring(&bucket, &dir, "10", "INFO").await;
    assert_eq!(get(&running, "/restored").await.body, "restored response");

    common::expect(running.port, &json!({"httpRequest": {"path": "/first"}, "httpResponse": {"body": "first"}})).await;
    let logs = await_logged(&running, "exception copying persisted expectations").await;
    assert!(
        logs.contains("exception copying persisted expectations persisted.json that hold expectations that could not be loaded to persisted.json.invalid-entries-")
            && logs.contains("; not saving over the original, the copy is tried again on the next save"),
        "{logs}"
    );
    let first = puts(&bucket).await;
    assert_eq!(first.len(), 1, "the refused backup only, no save over the original: {first:?}");

    common::expect(running.port, &json!({"httpRequest": {"path": "/second"}, "httpResponse": {"body": "second"}})).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while puts(&bucket).await.len() < 3 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let all = puts(&bucket).await;
    assert_eq!(all.len(), 3, "the retried backup, then the save: {all:?}");
    assert!(all[1].contains(".invalid-entries-"), "{all:?}");
    assert_eq!(all[2], format!("/{BUCKET}/persisted.json"));
    let logs = common::logs(running.port).await;
    assert!(logs.contains("held expectations that could not be loaded, which saving would remove"), "{logs}");
    running.server.shutdown().await;
    bucket.server.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// `shouldBoundStartupWhenTheBlobStoreNeverResponds`.
#[tokio::test(flavor = "multi_thread")]
async fn should_bound_startup_when_the_blob_store_never_responds() {
    let bucket = common::start(&[]).await;
    object(&bucket, json!({"body": format!("[{VALID}]"), "delay": {"timeUnit": "SECONDS", "value": 60}})).await;
    let dir = temp_dir("silentBlobStore");
    let started = Instant::now();
    let running = start_restoring(&bucket, &dir, "1", "INFO").await;
    assert!(started.elapsed() < Duration::from_secs(10), "the start is not held up: {:?}", started.elapsed());
    let logs = common::logs(running.port).await;
    assert!(
        logs.contains("timed out after 1 second(s) restoring persisted expectations from blob store key persisted.json - starting with no restored expectations (configure mockserver.blobStoreRestoreTimeoutSeconds to change this deadline)"),
        "{logs}"
    );
    assert_eq!(get(&running, "/restored").await.status, 404);
    running.server.shutdown().await;
    bucket.server.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// `shouldLogTheUnderlyingCauseWhenTheBlobStoreFailsAfterTheDeadlineHasExpired`.
#[tokio::test(flavor = "multi_thread")]
async fn should_log_the_underlying_cause_when_the_blob_store_fails_after_the_deadline_has_expired() {
    let bucket = common::start(&[]).await;
    object(
        &bucket,
        json!({"statusCode": 403, "body": "<Error><Code>AccessDenied</Code><Message>denied</Message></Error>", "delay": {"timeUnit": "SECONDS", "value": 3}}),
    )
    .await;
    let dir = temp_dir("lateFailure");
    let running = start_restoring(&bucket, &dir, "1", "DEBUG").await;
    let logs = common::logs(running.port).await;
    assert!(logs.contains("timed out after 1 second(s) restoring persisted expectations from blob store key persisted.json"), "{logs}");
    let logs = await_logged(&running, "failed after its 1 second deadline had already expired").await;
    assert!(logs.contains("blob store restore for key persisted.json failed after its 1 second deadline had already expired; startup continued without it"), "{logs}");
    assert_eq!(get(&running, "/restored").await.status, 404, "a late answer restores nothing");
    running.server.shutdown().await;
    bucket.server.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

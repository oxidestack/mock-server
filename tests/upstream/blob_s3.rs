//! `mockserver-blob-s3`'s tests against a MinIO container: `S3BlobStoreContractTest` (the shared
//! contract plus every key prefix shape) and `S3ExpectationPersistenceReloadTest` (expectations persisted by one
//! server restored by a fresh one). `S3BlobStoreRegistrarConfigWiringTest` needs no store: `src/blob/s3.rs`.
//! `S3BlobStoreRegistrarTest` and `S3BlobStoreDiscoveryTest` exercise the JVM-global registrar map and reflective
//! discovery; their counterpart is `blobStoreModules` (`src/blob/mod.rs` tests).

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use mock_server::blob::block_on;
use mock_server::blob::s3::{self, CredentialsSource, S3BlobStore, Wiring};
use mock_server::state_backend::BlobStore;

use crate::blob_stores::{enabled, uuid, MINIO};
use crate::brokers::{Container, Spec};

const ACCESS_KEY: &str = "minioadmin";
const SECRET_KEY: &str = "minioadmin";
const TEST_BUCKET: &str = "mockserver-test";
const RELOAD_BUCKET: &str = "mockserver-reload-test";

struct Minio {
    _container: Container,
    endpoint: String,
    client: aws_sdk_s3::Client,
}

/// One MinIO for the whole run, with both buckets created.
fn minio() -> &'static Minio {
    static MINIO_SERVER: OnceLock<Minio> = OnceLock::new();
    MINIO_SERVER.get_or_init(|| {
        let mut spec = Spec::new(MINIO);
        spec.ports = vec![(0, 9000)];
        spec.env = vec![("MINIO_ROOT_USER".into(), ACCESS_KEY.into()), ("MINIO_ROOT_PASSWORD".into(), SECRET_KEY.into())];
        spec.command = vec!["server".into(), "/tmp/data".into()];
        spec.ready = "API: ";
        let container = Container::start(spec);
        let endpoint = format!("http://127.0.0.1:{}", container.port(9000));
        let client = s3::client(&Wiring {
            region: "us-east-1".into(),
            endpoint_override: Some(endpoint.clone()),
            credentials: CredentialsSource::Static { access_key_id: ACCESS_KEY.into(), secret_access_key: SECRET_KEY.into() },
        });
        for bucket in [TEST_BUCKET, RELOAD_BUCKET] {
            block_on(client.create_bucket().bucket(bucket).send()).unwrap_or_else(|e| panic!("create bucket {bucket}: {e:?}"));
        }
        Minio { _container: container, endpoint, client }
    })
}

/// `createStore()`: a unique key prefix per test.
fn contract_store() -> S3BlobStore {
    S3BlobStore::new(minio().client.clone(), TEST_BUCKET, &format!("test-{}/", uuid()))
}

/// `assertNonAsciiMetadataKeyRejection`: S3 carries metadata in `x-amz-meta-*` headers, whose names are ASCII tokens.
/// The Java SDK sends the request and S3 answers 400; the Rust SDK refuses to build the header and never sends it.
/// Either way it is a refusal of this key, not a transport or credential failure.
fn assert_non_ascii_rejection(rejection: &mock_server::state_backend::StateError) {
    let text = rejection.to_string();
    assert!(text.to_lowercase().contains("header"), "expected the unrepresentable metadata key to be refused, but got: {text}");
}

mod contract_tests {
    use super::*;
    crate::blob_store_contract!(contract_store(), false, assert_non_ascii_rejection);
}

#[test]
fn should_round_trip_through_s3_for_every_key_prefix_shape() {
    if !enabled("should_round_trip_through_s3_for_every_key_prefix_shape") {
        return;
    }
    let namespace = format!("prefix-shapes-{}", uuid());
    for prefix in [String::new(), namespace.clone(), format!("{namespace}/"), format!("/{namespace}/")] {
        let key = format!("persistedExpectations-{}.json", uuid());
        let store = S3BlobStore::new(minio().client.clone(), TEST_BUCKET, &prefix);
        store.try_put(&key, b"payload".to_vec(), Default::default()).unwrap();
        let read = store.try_get(&key).unwrap().unwrap_or_else(|| panic!("prefix '{prefix}': blob must be readable back"));
        assert_eq!(read.data, b"payload", "prefix '{prefix}'");
        assert!(store.try_list(&key).unwrap().contains(&key), "prefix '{prefix}': list must report the key without the prefix");
        assert!(store.try_delete(&key).unwrap(), "prefix '{prefix}': delete must find the same object");
        assert_eq!(store.try_get(&key).unwrap(), None, "prefix '{prefix}': blob must be gone after delete");
    }
}

// ---------------------------------------------------------------- S3ExpectationPersistenceReloadTest

fn reload_properties(persisted_path: &str, key_prefix: &str) -> Vec<(&'static str, String)> {
    vec![
        ("persistExpectations", "true".into()),
        ("persistedExpectationsPath", persisted_path.into()),
        ("blobStoreType", "s3".into()),
        ("blobStoreModules", "s3".into()),
        ("blobStoreBucket", RELOAD_BUCKET.into()),
        ("blobStoreRegion", "us-east-1".into()),
        ("blobStoreEndpoint", minio().endpoint.clone()),
        ("blobStoreKeyPrefix", key_prefix.into()),
        ("blobStoreAccessKeyId", ACCESS_KEY.into()),
        ("blobStoreSecretAccessKey", SECRET_KEY.into()),
        // generous on purpose, as upstream: the deadline must not be the thing under test
        ("blobStoreRestoreTimeoutSeconds", "60".into()),
    ]
}

async fn start(properties: &[(&'static str, String)]) -> crate::common::Running {
    let properties: Vec<(&str, &str)> = properties.iter().map(|(k, v)| (*k, v.as_str())).collect();
    crate::common::start(&properties).await
}

async fn get(running: &crate::common::Running, path: &str) -> String {
    crate::common::send(running.port, "GET", path, "").await.body
}

async fn create_expectation(running: &crate::common::Running, path: &str, body: &str) {
    crate::common::expect(running.port, &serde_json::json!({"httpRequest": {"path": path}, "httpResponse": {"body": body}})).await;
}

fn object_keys(prefix: &str) -> Vec<String> {
    let listing = block_on(minio().client.list_objects_v2().bucket(RELOAD_BUCKET).prefix(prefix).send()).unwrap();
    listing.contents().iter().filter_map(|o| o.key().map(str::to_string)).collect()
}

/// `awaitS3BlobContains`: the listener's write-back is asynchronous.
async fn await_blob_contains(prefix: &str, marker: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        for key in object_keys(prefix) {
            let object = block_on(async { minio().client.get_object().bucket(RELOAD_BUCKET).key(&key).send().await.unwrap().body.collect().await.unwrap().into_bytes() });
            if String::from_utf8_lossy(&object).contains(marker) {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("persisted document containing '{marker}' never appeared in S3 under prefix {prefix}; bucket keys: {:?}", object_keys(""));
}

/// `File.createTempFile(name, ".json")`: an empty local file, under the system temp directory.
fn temp_file(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("{name}{}.json", uuid().replace('-', "")));
    std::fs::write(&path, "").unwrap();
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn should_restore_cloud_persisted_expectations_after_restart() {
    if !enabled("should_restore_cloud_persisted_expectations_after_restart") {
        return;
    }
    let key_prefix = format!("reload-{}", uuid());
    let file = temp_file("persistedExpectations");
    let path = file.to_string_lossy().into_owned();

    let running = start(&reload_properties(&path, &key_prefix)).await;
    create_expectation(&running, "/persisted", "restored-from-s3").await;
    assert_eq!(get(&running, "/persisted").await, "restored-from-s3");
    await_blob_contains(&key_prefix, "/persisted").await;
    running.server.shutdown().await;

    let running = start(&reload_properties(&path, &key_prefix)).await;
    assert_eq!(get(&running, "/persisted").await, "restored-from-s3");
    running.server.shutdown().await;
    let _ = std::fs::remove_file(file);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_restore_cloud_persisted_expectations_with_a_trailing_slash_key_prefix() {
    if !enabled("should_restore_cloud_persisted_expectations_with_a_trailing_slash_key_prefix") {
        return;
    }
    let key_prefix = format!("reload-trailing-{}/", uuid());
    let file = temp_file("persistedExpectationsTrailingSlash");
    let path = file.to_string_lossy().into_owned();

    let running = start(&reload_properties(&path, &key_prefix)).await;
    create_expectation(&running, "/persisted-trailing-slash", "survives-a-trailing-slash-prefix").await;
    assert_eq!(get(&running, "/persisted-trailing-slash").await, "survives-a-trailing-slash-prefix");
    await_blob_contains(&key_prefix, "/persisted-trailing-slash").await;

    let written = object_keys(&key_prefix);
    assert_eq!(written.len(), 1, "exactly one object expected under {key_prefix} but found {written:?}");
    assert_eq!(written[0], format!("{key_prefix}{}", file.file_name().unwrap().to_string_lossy()), "the object key must carry exactly one separator after the prefix");
    assert!(!written[0].contains("//"), "an object key must never contain a doubled separator: {}", written[0]);
    running.server.shutdown().await;

    let running = start(&reload_properties(&path, &key_prefix)).await;
    assert_eq!(get(&running, "/persisted-trailing-slash").await, "survives-a-trailing-slash-prefix");
    running.server.shutdown().await;
    let _ = std::fs::remove_file(file);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_restore_cloud_persisted_expectations_when_initialization_json_path_matches_persisted_expectations_path() {
    if !enabled("should_restore_cloud_persisted_expectations_when_initialization_json_path_matches_persisted_expectations_path") {
        return;
    }
    let key_prefix = format!("reload-init-{}", uuid());
    let file = temp_file("persistedExpectationsWithInitializer");
    let path = file.to_string_lossy().into_owned();

    let running = start(&reload_properties(&path, &key_prefix)).await;
    create_expectation(&running, "/persisted-with-initializer", "survives-the-initializer").await;
    assert_eq!(get(&running, "/persisted-with-initializer").await, "survives-the-initializer");
    await_blob_contains(&key_prefix, "/persisted-with-initializer").await;
    running.server.shutdown().await;

    assert_eq!(std::fs::metadata(&file).unwrap().len(), 0, "the local persisted file must be empty for this test to mean anything");

    let mut properties = reload_properties(&path, &key_prefix);
    properties.push(("initializationJsonPath", path.clone()));
    let running = start(&properties).await;
    assert_eq!(get(&running, "/persisted-with-initializer").await, "survives-the-initializer");
    running.server.shutdown().await;
    let _ = std::fs::remove_file(file);
}

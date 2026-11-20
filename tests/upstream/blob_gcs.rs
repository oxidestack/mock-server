//! `mockserver-blob-gcs`'s tests against a fake-gcs-server container: `GcsBlobStoreContractTest` and the
//! emulator half of `GcsBlobStoreRegistrarConfigWiringTest` (its guard branches and option assertions are unit tests
//! in `src/blob/gcs.rs`). `GcsBlobStoreRegistrarTest` exercises the JVM-global registrar map; its counterpart is
//! `blobStoreModules` (`src/blob/mod.rs` tests).

use std::sync::OnceLock;

use mock_server::blob::block_on;
use mock_server::blob::gcs::{Clients, CredentialsSource, GcsBlobStore, Wiring};
use mock_server::blob::keys;
use mock_server::state_backend::BlobStore;

use crate::blob_stores::{enabled, uuid, FAKE_GCS_SERVER};
use crate::brokers::{Container, Spec};

const TEST_BUCKET: &str = "mockserver-test";

struct FakeGcs {
    _container: Container,
    endpoint: String,
    /// The independent client that creates buckets and checks what landed (`adminStorage`).
    admin: Clients,
}

/// One fake-gcs-server for the whole run, with the contract's bucket created.
fn fake_gcs() -> &'static FakeGcs {
    static FAKE_GCS: OnceLock<FakeGcs> = OnceLock::new();
    FAKE_GCS.get_or_init(|| {
        let mut spec = Spec::new(FAKE_GCS_SERVER);
        spec.ports = vec![(0, 4443)];
        spec.command = ["-scheme", "http", "-backend", "memory", "-public-host", "localhost"].map(String::from).to_vec();
        spec.ready = "server started at";
        let container = Container::start(spec);
        let endpoint = format!("http://127.0.0.1:{}", container.port(4443));
        let admin = Clients::new(&Wiring { host: Some(endpoint.clone()), credentials: CredentialsSource::None, project_id: Some("admin-project".into()) }).unwrap();
        let fake = FakeGcs { _container: container, endpoint, admin };
        create_bucket(&fake, TEST_BUCKET);
        fake
    })
}

fn create_bucket(fake: &FakeGcs, name: &str) {
    block_on(fake.admin.json.create_bucket("admin-project", name)).unwrap_or_else(|e| panic!("create bucket {name}: {e}"));
}

/// `freshBucket()`.
fn fresh_bucket() -> String {
    let name = format!("wiring-{}", uuid());
    create_bucket(fake_gcs(), &name);
    name
}

/// `createStore()`: a unique key prefix per test.
fn contract_store() -> GcsBlobStore {
    GcsBlobStore::new(fake_gcs().admin.clone(), TEST_BUCKET, &format!("test-{}/", uuid()))
}

mod contract_tests {
    use super::*;
    crate::blob_store_contract!(contract_store(), true, |_: &mock_server::state_backend::StateError| {});
}

fn configured(properties: &[(&str, &str)]) -> GcsBlobStore {
    let config = properties.iter().fold(mock_server::Config::for_tests(), |c, (k, v)| c.with_property(k, v));
    GcsBlobStore::from_config(&config).expect("store")
}

#[test]
fn should_apply_endpoint_override_as_storage_host() {
    if !enabled("should_apply_endpoint_override_as_storage_host") {
        return;
    }
    let store = configured(&[("blobStoreBucket", &fresh_bucket()), ("blobStoreEndpoint", &fake_gcs().endpoint)]);
    assert_eq!(store.wiring().and_then(|w| w.host.as_deref()), Some(fake_gcs().endpoint.as_str()));
}

#[test]
fn should_use_no_credentials_when_endpoint_configured() {
    if !enabled("should_use_no_credentials_when_endpoint_configured") {
        return;
    }
    let store = configured(&[("blobStoreBucket", &fresh_bucket()), ("blobStoreEndpoint", &fake_gcs().endpoint)]);
    assert_eq!(store.wiring().map(|w| w.credentials), Some(CredentialsSource::None));
}

#[test]
fn should_apply_configured_project_id() {
    if !enabled("should_apply_configured_project_id") {
        return;
    }
    let project_id = format!("my-project-{}", uuid());
    let store = configured(&[("blobStoreBucket", &fresh_bucket()), ("blobStoreEndpoint", &fake_gcs().endpoint), ("blobStoreProjectId", &project_id)]);
    assert_eq!(store.wiring().and_then(|w| w.project_id.clone()), Some(project_id));
}

#[test]
fn should_fall_back_to_test_project_when_project_id_unset() {
    if !enabled("should_fall_back_to_test_project_when_project_id_unset") {
        return;
    }
    let store = configured(&[("blobStoreBucket", &fresh_bucket()), ("blobStoreEndpoint", &fake_gcs().endpoint)]);
    assert_eq!(store.wiring().and_then(|w| w.project_id.as_deref()), Some("test-project"));
}

#[test]
fn should_round_trip_against_emulator_into_configured_bucket_and_prefix() {
    if !enabled("should_round_trip_against_emulator_into_configured_bucket_and_prefix") {
        return;
    }
    let bucket = fresh_bucket();
    let key_prefix = "mockserver/prefix/";
    let key = format!("persistedExpectations-{}.json", uuid());
    let store = configured(&[("blobStoreBucket", &bucket), ("blobStoreEndpoint", &fake_gcs().endpoint), ("blobStoreKeyPrefix", key_prefix)]);

    store.try_put(&key, b"gcs-wiring-payload".to_vec(), Default::default()).unwrap();
    let read = store.try_get(&key).unwrap().expect("blob must be readable back through the configured store");
    assert_eq!(read.data, b"gcs-wiring-payload");

    // the admin client proves the object landed in the configured bucket under the configured prefix
    let expected_name = keys::join(key_prefix, &key);
    let landed = block_on(fake_gcs().admin.json.get_object(&bucket, &expected_name)).unwrap();
    assert!(landed.is_some(), "object must exist in bucket '{bucket}' at '{expected_name}'");
    let landed = GcsBlobStore::new(fake_gcs().admin.clone(), &bucket, "").try_get(&expected_name).unwrap();
    assert_eq!(landed.map(|b| b.data), Some(b"gcs-wiring-payload".to_vec()));
    assert_eq!((store.bucket(), store.key_prefix()), (bucket.as_str(), key_prefix));
}

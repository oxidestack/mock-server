//! `mockserver-blob-azure`'s tests against an Azurite container: `AzureBlobStoreContractTest` and the
//! emulator half of `AzureBlobStoreRegistrarConfigWiringTest` (its guard branches, `AzureBlobStoreMetadataKeyEncodingTest`
//! and the connection string are unit tests in `src/blob/azure.rs`). `AzureBlobStoreRegistrarTest` exercises the
//! JVM-global registrar map; its counterpart is `blobStoreModules` (`src/blob/mod.rs` tests).

use std::sync::OnceLock;

use mock_server::blob::azure::{AzureBlobStore, ConnectionString};
use mock_server::blob::block_on;
use mock_server::blob::keys;
use mock_server::state_backend::BlobStore;

use crate::blob_stores::{enabled, uuid, AZURITE};
use crate::brokers::{Container, Spec};

const ACCOUNT_NAME: &str = "devstoreaccount1";
const ACCOUNT_KEY: &str = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
const TEST_CONTAINER_NAME: &str = "mockserver-test";

struct Azurite {
    _container: Container,
    host_port: String,
    connection_string: String,
}

/// One Azurite for the whole run, with the contract's container created.
fn azurite() -> &'static Azurite {
    static AZURITE_SERVER: OnceLock<Azurite> = OnceLock::new();
    AZURITE_SERVER.get_or_init(|| {
        let mut spec = Spec::new(AZURITE);
        spec.ports = vec![(0, 10000)];
        // --skipApiVersionCheck: the SDK's REST API version runs ahead of released Azurite builds (as upstream)
        spec.command = ["azurite-blob", "--blobHost", "0.0.0.0", "--blobPort", "10000", "--skipApiVersionCheck"].map(String::from).to_vec();
        spec.ready = "successfully listens on";
        let container = Container::start(spec);
        let host_port = format!("127.0.0.1:{}", container.port(10000));
        let connection_string = format!("DefaultEndpointsProtocol=http;AccountName={ACCOUNT_NAME};AccountKey={ACCOUNT_KEY};BlobEndpoint=http://{host_port}/{ACCOUNT_NAME};");
        let azurite = Azurite { _container: container, host_port, connection_string };
        create_container(&azurite, TEST_CONTAINER_NAME);
        azurite
    })
}

fn admin(azurite: &Azurite, container: &str) -> AzureBlobStore {
    AzureBlobStore::new(ConnectionString::parse(&azurite.connection_string).unwrap(), container, "")
}

fn create_container(azurite: &Azurite, name: &str) {
    let client = admin(azurite, name).container_client().unwrap();
    block_on(client.create(None)).unwrap_or_else(|e| panic!("create container {name}: {e}"));
}

/// `freshContainer()`.
fn fresh_container() -> String {
    let name = format!("wiring-{}", uuid());
    create_container(azurite(), &name);
    name
}

/// `createStore()`: a unique key prefix per test.
fn contract_store() -> AzureBlobStore {
    AzureBlobStore::new(ConnectionString::parse(&azurite().connection_string).unwrap(), TEST_CONTAINER_NAME, &format!("test-{}/", uuid()))
}

mod contract_tests {
    use super::*;
    crate::blob_store_contract!(contract_store(), true, |_: &mock_server::state_backend::StateError| {});
}

fn configured(properties: &[(&str, &str)]) -> AzureBlobStore {
    let config = properties.iter().fold(mock_server::Config::for_tests(), |c, (k, v)| c.with_property(k, v));
    AzureBlobStore::from_config(&config).expect("store")
}

#[test]
fn should_target_configured_container_name() {
    if !enabled("should_target_configured_container_name") {
        return;
    }
    let container = fresh_container();
    let store = configured(&[("blobStoreContainer", &container), ("blobStoreConnectionString", &azurite().connection_string)]);
    assert_eq!(store.container(), container, "container client must target the configured container");
}

#[test]
fn should_use_endpoint_from_connection_string() {
    if !enabled("should_use_endpoint_from_connection_string") {
        return;
    }
    let container = fresh_container();
    let store = configured(&[("blobStoreContainer", &container), ("blobStoreConnectionString", &azurite().connection_string)]);
    let url = store.container_client().unwrap().url().to_string();
    assert!(url.contains(&azurite().host_port), "container URL must carry the emulator endpoint from the connection string: {url}");
}

#[test]
fn should_round_trip_against_emulator_into_configured_container_and_prefix() {
    if !enabled("should_round_trip_against_emulator_into_configured_container_and_prefix") {
        return;
    }
    let container = fresh_container();
    let key_prefix = "mockserver/prefix/";
    let key = format!("persistedExpectations-{}.json", uuid());
    let store = configured(&[("blobStoreContainer", &container), ("blobStoreConnectionString", &azurite().connection_string), ("blobStoreKeyPrefix", key_prefix)]);

    store.try_put(&key, b"azure-wiring-payload".to_vec(), Default::default()).unwrap();
    let read = store.try_get(&key).unwrap().expect("blob must be readable back through the configured store");
    assert_eq!(read.data, b"azure-wiring-payload");

    // an independent client proves the blob landed in the configured container under the configured prefix
    let expected_name = keys::join(key_prefix, &key);
    let landed = admin(azurite(), &container).try_get(&expected_name).unwrap();
    assert_eq!(landed.map(|b| b.data), Some(b"azure-wiring-payload".to_vec()), "blob must exist in container '{container}' at '{expected_name}'");
    assert_eq!(store.key_prefix(), key_prefix);
}

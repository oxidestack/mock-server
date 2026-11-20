//! Shared parts of the cloud blob store ports (`blob_s3.rs`, `blob_azure.rs`, `blob_gcs.rs`): the
//! emulator images upstream's Testcontainers suites use, the Docker gate, and `BlobStoreContract`
//! (mockserver-core's `state/contract/BlobStoreContract.java`) as a macro each backend instantiates.
//!
//! The emulator tests run only with `MOCK_SERVER_BLOB_TESTS=1` (`make blob-tests`) and a reachable Docker daemon;
//! otherwise each test says why and passes, as upstream's `Assume.assumeTrue(dockerAvailable)` skips.

use std::process::Command;
use std::sync::OnceLock;

/// `TestContainerImages.MINIO` is `quay.io/minio/minio:RELEASE.2024-11-07T00-52-20Z`, which quay.io (like Docker Hub
/// before it) no longer serves anonymously (401); Chainguard's MinIO build, pinned by digest, is the S3 server here.
pub const MINIO: &str = "cgr.dev/chainguard/minio@sha256:6476f81b9739912fa9f50ceae2bb049a30336527cccd24beccfbeb4145f8f696";
pub const FAKE_GCS_SERVER: &str = "fsouza/fake-gcs-server:1.49.3";
pub const AZURITE: &str = "mcr.microsoft.com/azure-storage/azurite:3.36.0";

/// Whether the emulator tests run; prints why not.
pub fn enabled(test: &str) -> bool {
    if std::env::var("MOCK_SERVER_BLOB_TESTS").ok().as_deref() != Some("1") {
        eprintln!("{test}: skipped, blob store emulator tests run with MOCK_SERVER_BLOB_TESTS=1 (make blob-tests)");
        return false;
    }
    static DOCKER: OnceLock<bool> = OnceLock::new();
    let available = *DOCKER.get_or_init(|| Command::new("docker").args(["info", "--format", "{{.ServerVersion}}"]).output().is_ok_and(|o| o.status.success()));
    if !available {
        eprintln!("{test}: skipped, Docker is not available");
    }
    available
}

/// A fresh unique name part (`UUID.randomUUID()`).
pub fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// `BlobStoreContract`: `$store` builds a fresh store (a unique key prefix per test), `$non_ascii` is
/// `supportsNonAsciiMetadataKeys()`, `$rejection` checks the error of a refused non-ASCII metadata key
/// (`assertNonAsciiMetadataKeyRejection`).
#[macro_export]
macro_rules! blob_store_contract {
    ($store:expr, $non_ascii:expr, $rejection:expr) => {
        mod contract {
            #[allow(unused_imports)]
            use super::*;
            use std::collections::HashMap;
            use mock_server::state_backend::BlobStore;

            fn store(test: &str) -> Option<Box<dyn BlobStore>> {
                $crate::blob_stores::enabled(test).then(|| Box::new($store) as Box<dyn BlobStore>)
            }

            fn meta(pairs: &[(&str, &str)]) -> HashMap<String, String> {
                pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
            }

            fn sorted(mut keys: Vec<String>) -> Vec<String> {
                keys.sort();
                keys
            }

            #[test]
            fn should_put_and_get() {
                let Some(store) = store("should_put_and_get") else { return };
                store.try_put("key1", b"hello world".to_vec(), meta(&[("type", "text"), ("source", "test")])).unwrap();
                let blob = store.try_get("key1").unwrap().expect("blob should be present");
                assert_eq!(blob.key, "key1");
                assert_eq!(blob.data, b"hello world");
                assert_eq!(blob.metadata.get("type").map(String::as_str), Some("text"));
                assert_eq!(blob.metadata.get("source").map(String::as_str), Some("test"));
            }

            #[test]
            fn should_return_empty_for_missing_key() {
                let Some(store) = store("should_return_empty_for_missing_key") else { return };
                assert_eq!(store.try_get("nonexistent").unwrap(), None);
            }

            #[test]
            fn should_overwrite_existing_blob() {
                let Some(store) = store("should_overwrite_existing_blob") else { return };
                store.try_put("key1", b"v1".to_vec(), HashMap::new()).unwrap();
                store.try_put("key1", b"v2".to_vec(), HashMap::new()).unwrap();
                assert_eq!(store.try_get("key1").unwrap().unwrap().data, b"v2");
            }

            #[test]
            fn should_overwrite_metadata() {
                let Some(store) = store("should_overwrite_metadata") else { return };
                store.try_put("key1", b"data".to_vec(), meta(&[("version", "1")])).unwrap();
                store.try_put("key1", b"data".to_vec(), meta(&[("version", "2"), ("extra", "yes")])).unwrap();
                let blob = store.try_get("key1").unwrap().unwrap();
                assert_eq!(blob.metadata.get("version").map(String::as_str), Some("2"));
                assert_eq!(blob.metadata.get("extra").map(String::as_str), Some("yes"));
            }

            #[test]
            fn should_list_by_prefix() {
                let Some(store) = store("should_list_by_prefix") else { return };
                store.try_put("expectations/e1.json", b"{}".to_vec(), HashMap::new()).unwrap();
                store.try_put("expectations/e2.json", b"{}".to_vec(), HashMap::new()).unwrap();
                store.try_put("cassettes/c1.json", b"{}".to_vec(), HashMap::new()).unwrap();
                assert_eq!(sorted(store.try_list("expectations/").unwrap()), vec!["expectations/e1.json", "expectations/e2.json"]);
            }

            #[test]
            fn should_return_empty_list_for_non_matching_prefix() {
                let Some(store) = store("should_return_empty_list_for_non_matching_prefix") else { return };
                store.try_put("a/b", b"data".to_vec(), HashMap::new()).unwrap();
                assert!(store.try_list("x/").unwrap().is_empty());
            }

            #[test]
            fn should_list_empty_store_with_prefix() {
                let Some(store) = store("should_list_empty_store_with_prefix") else { return };
                assert!(store.try_list("any/").unwrap().is_empty());
            }

            #[test]
            fn should_delete_blob() {
                let Some(store) = store("should_delete_blob") else { return };
                store.try_put("key1", b"data".to_vec(), HashMap::new()).unwrap();
                assert!(store.try_delete("key1").unwrap(), "delete should return true for existing key");
                assert_eq!(store.try_get("key1").unwrap(), None);
            }

            #[test]
            fn should_return_false_for_deleting_missing_key() {
                let Some(store) = store("should_return_false_for_deleting_missing_key") else { return };
                assert!(!store.try_delete("missing").unwrap());
            }

            #[test]
            fn should_round_trip_empty_metadata() {
                let Some(store) = store("should_round_trip_empty_metadata") else { return };
                store.try_put("key1", b"data".to_vec(), HashMap::new()).unwrap();
                assert!(store.try_get("key1").unwrap().unwrap().metadata.is_empty());
            }

            #[test]
            fn should_handle_metadata_with_special_characters() {
                let Some(store) = store("should_handle_metadata_with_special_characters") else { return };
                store.try_put("key1", b"data".to_vec(), meta(&[("description", "test=value with spaces"), ("path", "a/b/c")])).unwrap();
                let blob = store.try_get("key1").unwrap().unwrap();
                assert_eq!(blob.metadata.get("description").map(String::as_str), Some("test=value with spaces"));
                assert_eq!(blob.metadata.get("path").map(String::as_str), Some("a/b/c"));
            }

            #[test]
            fn should_round_trip_metadata_keys_with_non_alphanumeric_characters() {
                let Some(store) = store("should_round_trip_metadata_keys_with_non_alphanumeric_characters") else { return };
                let original = meta(&[("x-custom-type", "hyphenated"), ("x_custom_type", "underscored"), ("simple", "value")]);
                store.try_put("roundtrip-meta", b"payload".to_vec(), original.clone()).unwrap();
                assert_eq!(store.try_get("roundtrip-meta").unwrap().unwrap().metadata, original);
            }

            #[test]
            fn should_never_silently_corrupt_metadata_keys_above_latin1() {
                let Some(store) = store("should_never_silently_corrupt_metadata_keys_above_latin1") else { return };
                let original = meta(&[("中文", "chinese"), ("café", "latin1-accent"), ("plain", "ascii")]);
                let key = "roundtrip-meta-non-ascii";
                if !$non_ascii {
                    let rejection = store.try_put(key, b"payload".to_vec(), original).expect_err(
                        "a backend that cannot represent non-ASCII metadata keys must REJECT the write, not accept it and store something else",
                    );
                    ($rejection)(&rejection);
                    assert_eq!(store.try_get(key).unwrap(), None, "a rejected write must not have partially landed");
                    return;
                }
                store.try_put(key, b"payload".to_vec(), original.clone()).unwrap();
                assert_eq!(store.try_get(key).unwrap().expect("blob should be present").metadata, original);
            }

            #[test]
            fn should_handle_empty_data() {
                let Some(store) = store("should_handle_empty_data") else { return };
                store.try_put("empty", Vec::new(), HashMap::new()).unwrap();
                assert!(store.try_get("empty").unwrap().unwrap().data.is_empty());
            }

            #[test]
            fn should_handle_binary_data() {
                let Some(store) = store("should_handle_binary_data") else { return };
                let binary: Vec<u8> = (0..=255).collect();
                store.try_put("binary", binary.clone(), HashMap::new()).unwrap();
                assert_eq!(store.try_get("binary").unwrap().unwrap().data, binary);
            }

            #[test]
            fn should_not_find_deleted_blob() {
                let Some(store) = store("should_not_find_deleted_blob") else { return };
                store.try_put("key1", b"data".to_vec(), HashMap::new()).unwrap();
                store.try_delete("key1").unwrap();
                assert_eq!(store.try_get("key1").unwrap(), None);
                assert!(store.try_list("key").unwrap().is_empty());
            }

            #[test]
            fn should_list_nested_key_prefixes() {
                let Some(store) = store("should_list_nested_key_prefixes") else { return };
                store.try_put("a/b/c1", b"d1".to_vec(), HashMap::new()).unwrap();
                store.try_put("a/b/c2", b"d2".to_vec(), HashMap::new()).unwrap();
                store.try_put("a/d/c1", b"d3".to_vec(), HashMap::new()).unwrap();
                assert_eq!(sorted(store.try_list("a/b/").unwrap()), vec!["a/b/c1", "a/b/c2"]);
            }
        }
    };
}

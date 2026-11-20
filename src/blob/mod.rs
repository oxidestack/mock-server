//! Blob stores selected by `blobStoreType` (`StateBackendFactory.createBlobStore`): `filesystem` (the
//! default: the persisted document is the local file), `memory` (the memory backend's own blob store), and the cloud
//! stores of upstream's separate modules `mockserver-blob-s3`, `-gcs` and `-azure`.
//!
//! Upstream loads a cloud module's registrar by reflection, and the stock image has none of them on its class path:
//! there `blobStoreType=s3` stops the start with `blobStoreType=s3 configured but org.mockserver.blob.s3.
//! S3BlobStoreRegistrar is not on the classpath; add the mockserver-blob-s3 dependency`. That stays the default here
//! (scenarios `tests/process_scenarios/blob_store_type_*`). There is no class path to add a jar to, so the
//! mock-server property `blobStoreModules` (a comma-separated list of `s3`, `gcs`, `azure`) plays the part of the
//! module jars in `/libs`: a listed module is "on the class path" and its store is built from the same properties
//! its registrar reads (docs/divergences.md).

pub mod azure;
pub mod gcs;
pub mod keys;
mod runtime;
pub mod s3;

use std::sync::Arc;

use crate::state_backend::BlobStore;

pub use runtime::block_on;

/// What `blobStoreType` selects.
pub enum Selected {
    /// `FilesystemBlobStore`: persistence writes the local file.
    Filesystem,
    /// `InMemoryBlobStore`.
    Memory,
    /// A cloud module's store.
    Cloud(Arc<dyn BlobStore>),
}

/// `StateBackendFactory.BLOB_STORE_REGISTRARS`.
fn registrar(type_key: &str) -> Option<&'static str> {
    match type_key {
        "s3" => Some("org.mockserver.blob.s3.S3BlobStoreRegistrar"),
        "gcs" => Some("org.mockserver.blob.gcs.GcsBlobStoreRegistrar"),
        "azure" => Some("org.mockserver.blob.azure.AzureBlobStoreRegistrar"),
        _ => None,
    }
}

/// The modules `blobStoreModules` puts "on the class path", lower-cased.
pub fn modules(config: &crate::Config) -> Vec<String> {
    config.property("blobStoreModules").unwrap_or_default().split(',').map(|m| m.trim().to_lowercase()).filter(|m| !m.is_empty()).collect()
}

/// `StateBackendFactory.createBlobStore(configuration)`. The error is the exception `Main` logs with `exception while
/// starting:{}`, without the JVM's stack frames.
pub fn create(config: &crate::Config) -> Result<Selected, String> {
    let blob_store_type = config.property("blobStoreType").unwrap_or_else(|| "filesystem".into());
    if blob_store_type.eq_ignore_ascii_case("filesystem") {
        return Ok(Selected::Filesystem);
    }
    if blob_store_type.eq_ignore_ascii_case("memory") {
        return Ok(Selected::Memory);
    }
    let type_key = blob_store_type.to_lowercase();
    let Some(registrar) = registrar(&type_key) else {
        return Err(format!(
            "java.lang.IllegalStateException: blobStoreType={type_key} is not a recognised blob store type; supported types: memory, filesystem, s3, gcs, azure"
        ));
    };
    if !modules(config).contains(&type_key) {
        return Err(format!(
            "java.lang.IllegalStateException: blobStoreType={type_key} configured but {registrar} is not on the classpath; add the mockserver-blob-{type_key} dependency\nCaused by: java.lang.ClassNotFoundException: {registrar}"
        ));
    }
    let store: Result<Arc<dyn BlobStore>, String> = match type_key.as_str() {
        "s3" => s3::S3BlobStore::from_config(config).map(|s| Arc::new(s) as Arc<dyn BlobStore>),
        "gcs" => gcs::GcsBlobStore::from_config(config).map(|s| Arc::new(s) as Arc<dyn BlobStore>),
        "azure" => azure::AzureBlobStore::from_config(config).map(|s| Arc::new(s) as Arc<dyn BlobStore>),
        _ => Err(format!("blobStoreType={type_key} configured but no BlobStoreFactory registered for it")),
    };
    store.map(Selected::Cloud).map_err(|e| format!("java.lang.IllegalStateException: {e}"))
}

/// A non-empty property value (`value != null && !value.isEmpty()`).
fn non_empty(config: &crate::Config, name: &str) -> Option<String> {
    config.property(name).filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(properties: &[(&str, &str)]) -> crate::Config {
        properties.iter().fold(crate::Config::for_tests(), |c, (k, v)| c.with_property(k, v))
    }

    fn error(properties: &[(&str, &str)]) -> String {
        match create(&config(properties)) {
            Err(e) => e,
            Ok(_) => panic!("expected an error for {properties:?}"),
        }
    }

    #[test]
    fn filesystem_and_memory_need_no_module() {
        assert!(matches!(create(&config(&[])), Ok(Selected::Filesystem)));
        assert!(matches!(create(&config(&[("blobStoreType", "FileSystem")])), Ok(Selected::Filesystem)));
        assert!(matches!(create(&config(&[("blobStoreType", "MEMORY")])), Ok(Selected::Memory)));
    }

    #[test]
    fn a_cloud_type_without_its_module_is_not_on_the_classpath() {
        assert_eq!(
            error(&[("blobStoreType", "S3")]),
            "java.lang.IllegalStateException: blobStoreType=s3 configured but org.mockserver.blob.s3.S3BlobStoreRegistrar is not on the classpath; add the mockserver-blob-s3 dependency\nCaused by: java.lang.ClassNotFoundException: org.mockserver.blob.s3.S3BlobStoreRegistrar"
        );
        assert!(error(&[("blobStoreType", "gcs"), ("blobStoreModules", "s3, azure")]).contains("GcsBlobStoreRegistrar is not on the classpath"));
    }

    #[test]
    fn an_unknown_type_is_not_recognised() {
        assert_eq!(
            error(&[("blobStoreType", "Banana"), ("blobStoreModules", "banana")]),
            "java.lang.IllegalStateException: blobStoreType=banana is not a recognised blob store type; supported types: memory, filesystem, s3, gcs, azure"
        );
    }

    #[test]
    fn a_listed_module_builds_its_store_from_the_registrar_properties() {
        assert_eq!(
            error(&[("blobStoreType", "s3"), ("blobStoreModules", "s3")]),
            "java.lang.IllegalStateException: blobStoreType=s3 requires blobStoreBucket to be configured"
        );
        assert!(matches!(create(&config(&[("blobStoreType", "s3"), ("blobStoreModules", "S3"), ("blobStoreBucket", "b")])), Ok(Selected::Cloud(_))));
    }
}

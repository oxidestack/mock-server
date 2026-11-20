//! `mockserver-blob-s3`: `S3BlobStore` over AWS S3 or an S3-compatible store (MinIO), and
//! `S3BlobStoreRegistrar.createS3BlobStore`'s wiring of the `blobStore*` properties into the client. Metadata is the
//! objects' user metadata (`x-amz-meta-*`).

use std::collections::HashMap;

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::error::DisplayErrorContext;
use aws_sdk_s3::primitives::ByteStream;

use super::{block_on, keys, non_empty};
use crate::state_backend::{Blob, BlobStore, StateError};

/// Where the client's credentials come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialsSource {
    /// `StaticCredentialsProvider` with `blobStoreAccessKeyId` and `blobStoreSecretAccessKey`.
    Static { access_key_id: String, secret_access_key: String },
    /// `DefaultCredentialsProvider`: the AWS default chain (environment, profile, web identity, container, IMDS).
    DefaultChain,
}

/// What `createS3BlobStore` configured, as `S3Client.serviceClientConfiguration()` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wiring {
    pub region: String,
    /// `endpointOverride`, with path-style addressing.
    pub endpoint_override: Option<String>,
    pub credentials: CredentialsSource,
}

pub struct S3BlobStore {
    client: aws_sdk_s3::Client,
    bucket: String,
    key_prefix: String,
    wiring: Wiring,
}

impl S3BlobStore {
    /// `new S3BlobStore(s3Client, bucket, keyPrefix)`.
    pub fn new(client: aws_sdk_s3::Client, bucket: &str, key_prefix: &str) -> S3BlobStore {
        let region = client.config().region().map(|r| r.to_string()).unwrap_or_default();
        S3BlobStore { client, bucket: bucket.into(), key_prefix: key_prefix.into(), wiring: Wiring { region, endpoint_override: None, credentials: CredentialsSource::DefaultChain } }
    }

    /// `S3BlobStoreRegistrar.createS3BlobStore(configuration)`; the error is the `IllegalStateException`'s message.
    pub fn from_config(config: &crate::Config) -> Result<S3BlobStore, String> {
        let bucket = non_empty(config, "blobStoreBucket").ok_or("blobStoreType=s3 requires blobStoreBucket to be configured")?;
        let region = non_empty(config, "blobStoreRegion").unwrap_or_else(|| "us-east-1".into());
        let endpoint_override = non_empty(config, "blobStoreEndpoint");
        let credentials = match (non_empty(config, "blobStoreAccessKeyId"), non_empty(config, "blobStoreSecretAccessKey")) {
            (Some(access_key_id), Some(secret_access_key)) => CredentialsSource::Static { access_key_id, secret_access_key },
            _ => CredentialsSource::DefaultChain,
        };
        let wiring = Wiring { region, endpoint_override, credentials };
        let client = client(&wiring);
        Ok(S3BlobStore { client, bucket, key_prefix: config.property("blobStoreKeyPrefix").unwrap_or_default(), wiring })
    }

    pub fn wiring(&self) -> &Wiring {
        &self.wiring
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn key_prefix(&self) -> &str {
        &self.key_prefix
    }

    pub fn client(&self) -> &aws_sdk_s3::Client {
        &self.client
    }
}

/// The client `wiring` describes. Building it performs no I/O; the default chain resolves on first use.
pub fn client(wiring: &Wiring) -> aws_sdk_s3::Client {
    let region = Region::new(wiring.region.clone());
    let mut builder = aws_sdk_s3::Config::builder().behavior_version(BehaviorVersion::latest()).region(region.clone());
    if let Some(endpoint) = &wiring.endpoint_override {
        builder = builder.endpoint_url(endpoint).force_path_style(true);
        // A plain-http endpoint never negotiates TLS. The default client loads the platform's native roots at build
        // and, once, for the process (a `LazyLock`); a failed load (macOS keychain under load) leaves it empty for
        // good and a debug build's `debug_assert!` panics. Skip TLS where none is spoken.
        if endpoint.starts_with("http://") {
            builder = builder.http_client(aws_smithy_http_client::Builder::new().build_http());
        }
    }
    builder = match &wiring.credentials {
        CredentialsSource::Static { access_key_id, secret_access_key } => builder.credentials_provider(Credentials::new(access_key_id, secret_access_key, None, None, "Static")),
        CredentialsSource::DefaultChain => {
            let chain = block_on(aws_config::default_provider::credentials::DefaultCredentialsChain::builder().region(region).build());
            builder.credentials_provider(chain)
        }
    };
    aws_sdk_s3::Client::from_conf(builder.build())
}

fn error(e: impl std::error::Error) -> StateError {
    StateError(DisplayErrorContext(e).to_string())
}

impl S3BlobStore {
    fn s3_key(&self, key: &str) -> String {
        keys::join(&self.key_prefix, key)
    }
}

impl BlobStore for S3BlobStore {
    fn put(&self, key: &str, data: Vec<u8>, metadata: HashMap<String, String>) {
        if let Err(e) = self.try_put(key, data, metadata) {
            eprintln!("ERROR put blob '{key}' to s3://{}: {e}", self.bucket);
        }
    }

    fn get(&self, key: &str) -> Option<Blob> {
        self.try_get(key).unwrap_or_else(|e| {
            eprintln!("ERROR get blob '{key}' from s3://{}: {e}", self.bucket);
            None
        })
    }

    fn list(&self, prefix: &str) -> Vec<String> {
        self.try_list(prefix).unwrap_or_else(|e| {
            eprintln!("ERROR list blobs '{prefix}' in s3://{}: {e}", self.bucket);
            Vec::new()
        })
    }

    fn delete(&self, key: &str) -> bool {
        self.try_delete(key).unwrap_or_else(|e| {
            eprintln!("ERROR delete blob '{key}' from s3://{}: {e}", self.bucket);
            false
        })
    }

    fn try_put(&self, key: &str, data: Vec<u8>, metadata: HashMap<String, String>) -> Result<(), StateError> {
        let request = self.client.put_object().bucket(&self.bucket).key(self.s3_key(key)).set_metadata(Some(metadata)).body(ByteStream::from(data));
        block_on(request.send()).map(|_| ()).map_err(error)
    }

    fn try_get(&self, key: &str) -> Result<Option<Blob>, StateError> {
        let request = self.client.get_object().bucket(&self.bucket).key(self.s3_key(key));
        block_on(async move {
            let response = match request.send().await {
                Ok(response) => response,
                Err(e) if e.as_service_error().is_some_and(|s| s.is_no_such_key()) => return Ok(None),
                Err(e) => return Err(error(e)),
            };
            let metadata = response.metadata().cloned().unwrap_or_default();
            let data = response.body.collect().await.map_err(error)?.into_bytes().to_vec();
            Ok(Some(Blob { key: key.to_string(), data, metadata }))
        })
    }

    fn try_list(&self, prefix: &str) -> Result<Vec<String>, StateError> {
        let s3_prefix = self.s3_key(prefix);
        block_on(async move {
            let mut keys = Vec::new();
            let mut token = None;
            loop {
                let response =
                    self.client.list_objects_v2().bucket(&self.bucket).prefix(&s3_prefix).set_continuation_token(token.take()).send().await.map_err(error)?;
                keys.extend(response.contents().iter().filter_map(|o| o.key()).map(|k| keys::strip_prefix(&self.key_prefix, k)));
                if response.is_truncated() != Some(true) {
                    return Ok(keys);
                }
                token = response.next_continuation_token().map(str::to_string);
            }
        })
    }

    /// Head, then delete: S3 has no conditional delete, so `true` may name an object a concurrent caller removed.
    fn try_delete(&self, key: &str) -> Result<bool, StateError> {
        let s3_key = self.s3_key(key);
        block_on(async move {
            match self.client.head_object().bucket(&self.bucket).key(&s3_key).send().await {
                Ok(_) => {}
                Err(e) if e.as_service_error().is_some_and(|s| s.is_not_found()) => return Ok(false),
                Err(e) => return Err(error(e)),
            }
            self.client.delete_object().bucket(&self.bucket).key(&s3_key).send().await.map_err(error)?;
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    //! `S3BlobStoreRegistrarConfigWiringTest`: no network, no Docker, the client builds without I/O. The Java test
    //! reads the built client's `serviceClientConfiguration()`; the Rust SDK's `Config` shows only the region, so the
    //! endpoint and the credentials are read from the store's [`Wiring`], from which the client is built.

    use super::*;

    fn store(properties: &[(&str, &str)]) -> Result<S3BlobStore, String> {
        S3BlobStore::from_config(&properties.iter().fold(crate::Config::for_tests(), |c, (k, v)| c.with_property(k, v)))
    }

    #[test]
    fn should_throw_when_bucket_missing() {
        assert_eq!(store(&[]).err().as_deref(), Some("blobStoreType=s3 requires blobStoreBucket to be configured"));
    }

    #[test]
    fn should_throw_when_bucket_empty() {
        assert!(store(&[("blobStoreBucket", "")]).is_err());
    }

    #[test]
    fn should_default_region_to_us_east_1_when_unset() {
        let store = store(&[("blobStoreBucket", "some-bucket")]).unwrap();
        assert_eq!(store.client().config().region().map(|r| r.to_string()).as_deref(), Some("us-east-1"));
    }

    #[test]
    fn should_use_explicit_region() {
        let store = store(&[("blobStoreBucket", "some-bucket"), ("blobStoreRegion", "eu-west-2")]).unwrap();
        assert_eq!(store.client().config().region().map(|r| r.to_string()).as_deref(), Some("eu-west-2"));
    }

    #[test]
    fn should_apply_endpoint_override_when_configured() {
        let store = store(&[("blobStoreBucket", "some-bucket"), ("blobStoreEndpoint", "http://minio.example:9000")]).unwrap();
        assert_eq!(store.wiring().endpoint_override.as_deref(), Some("http://minio.example:9000"));
    }

    #[test]
    fn should_not_override_endpoint_when_unset() {
        assert_eq!(store(&[("blobStoreBucket", "some-bucket")]).unwrap().wiring().endpoint_override, None);
    }

    #[test]
    fn should_use_static_credentials_when_provided() {
        let store = store(&[("blobStoreBucket", "some-bucket"), ("blobStoreAccessKeyId", "AKIAEXAMPLE"), ("blobStoreSecretAccessKey", "secretExample")]).unwrap();
        assert_eq!(store.wiring().credentials, CredentialsSource::Static { access_key_id: "AKIAEXAMPLE".into(), secret_access_key: "secretExample".into() });
    }

    #[test]
    fn should_fall_back_to_default_credentials_when_unset() {
        // not resolved: the default chain reaches out to the environment, the file system and the network
        let store = store(&[("blobStoreBucket", "some-bucket"), ("blobStoreAccessKeyId", "AKIAEXAMPLE")]).unwrap();
        assert_eq!(store.wiring().credentials, CredentialsSource::DefaultChain);
    }

    #[test]
    fn should_apply_bucket_and_key_prefix() {
        let store = store(&[("blobStoreBucket", "my-bucket"), ("blobStoreKeyPrefix", "mockserver/prefix/")]).unwrap();
        assert_eq!(store.bucket(), "my-bucket");
        assert_eq!(store.key_prefix(), "mockserver/prefix/");
    }
}

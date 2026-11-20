//! `mockserver-blob-gcs`: `GcsBlobStore` over Google Cloud Storage (or fake-gcs-server), and
//! `GcsBlobStoreRegistrar.createGcsBlobStore`'s wiring of `blobStoreBucket`, `blobStoreEndpoint`, `blobStoreKeyPrefix`
//! and `blobStoreProjectId`. Metadata is the objects' custom metadata.
//!
//! Uploads and downloads go through the official Rust SDK's `Storage` client (the JSON API's media endpoints). The
//! SDK's `StorageControl` client, which reads object resources, lists and deletes, speaks gRPC only, which neither
//! upstream's Java client (`StorageOptions.getDefaultInstance()`, JSON over HTTP) nor fake-gcs-server uses, so those
//! calls are made on the JSON API here ([`JsonApi`]) with the same credentials. Metadata is read from the object
//! resource (as Java's `storage.get` does), not from the download's `x-goog-meta-*` headers, which cannot carry
//! non-ASCII keys.

use std::collections::HashMap;

use google_cloud_auth::credentials::{anonymous, CacheableResource, Credentials};
use google_cloud_storage::client::Storage;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

use super::{block_on, keys, non_empty};
use crate::state_backend::{Blob, BlobStore, StateError};

/// The project `createGcsBlobStore` sets when an endpoint is configured without `blobStoreProjectId`.
const EMULATOR_PROJECT: &str = "test-project";

/// The JSON API's host when no endpoint is configured (`StorageOptions.getDefaultHost()`).
const GOOGLE_HOST: &str = "https://storage.googleapis.com";

/// What a JSON API path segment escapes: everything but RFC 3986's unreserved characters (a `/` in an object name
/// included).
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

/// Where the client's credentials come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialsSource {
    /// `NoCredentials.getInstance()`: an emulator endpoint.
    None,
    /// Application default credentials.
    ApplicationDefault,
}

/// What `createGcsBlobStore` configured, as `Storage.getOptions()` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wiring {
    /// `setHost`; `None` is the Google endpoint.
    pub host: Option<String>,
    pub credentials: CredentialsSource,
    /// `setProjectId`; `None` leaves it to the environment (`ServiceOptions.getDefaultProjectId()`).
    pub project_id: Option<String>,
}

impl Wiring {
    /// `createGcsBlobStore`'s option building.
    pub fn from_config(config: &crate::Config) -> Wiring {
        let project_id = non_empty(config, "blobStoreProjectId");
        match non_empty(config, "blobStoreEndpoint") {
            Some(endpoint) => {
                Wiring { host: Some(endpoint), credentials: CredentialsSource::None, project_id: Some(project_id.unwrap_or_else(|| EMULATOR_PROJECT.into())) }
            }
            None => Wiring { host: None, credentials: CredentialsSource::ApplicationDefault, project_id },
        }
    }
}

/// `StorageOptions.getService()`: the SDK's media client and the JSON API resource calls, built as `wiring`
/// describes. Building performs no request; application default credentials resolve on first use.
#[derive(Clone)]
pub struct Clients {
    pub storage: Storage,
    pub json: JsonApi,
}

impl Clients {
    pub fn new(wiring: &Wiring) -> Result<Clients, String> {
        let credentials = match wiring.credentials {
            CredentialsSource::None => anonymous::Builder::new().build(),
            CredentialsSource::ApplicationDefault => {
                google_cloud_auth::credentials::Builder::default().build().map_err(|e| format!("cannot load the GCS application default credentials: {e}"))?
            }
        };
        let host = wiring.host.as_deref().unwrap_or(GOOGLE_HOST).trim_end_matches('/').to_string();
        let storage = block_on(async {
            let mut storage = Storage::builder().with_credentials(credentials.clone());
            if wiring.host.is_some() {
                storage = storage.with_endpoint(host.clone());
            }
            storage.build().await.map_err(|e| format!("cannot build the GCS storage client: {e}"))
        })?;
        let http = reqwest::Client::builder().build().map_err(|e| format!("cannot build the GCS JSON API client: {e}"))?;
        Ok(Clients { storage, json: JsonApi { http, host, credentials } })
    }
}

/// The JSON API's resource calls (`/storage/v1/...`) the store and its tests make.
#[derive(Clone)]
pub struct JsonApi {
    http: reqwest::Client,
    host: String,
    credentials: Credentials,
}

impl JsonApi {
    fn object_url(&self, bucket: &str, name: &str) -> String {
        format!("{}/storage/v1/b/{}/o/{}", self.host, utf8_percent_encode(bucket, PATH_SEGMENT), utf8_percent_encode(name, PATH_SEGMENT))
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<reqwest::Response, StateError> {
        let headers = match self.credentials.headers(http::Extensions::new()).await.map_err(|e| StateError(format!("GCS credentials: {e}")))? {
            CacheableResource::New { data, .. } => data,
            CacheableResource::NotModified => http::HeaderMap::new(),
        };
        request.headers(headers).send().await.map_err(|e| StateError(format!("GCS request failed: {e}")))
    }

    /// The response's JSON body, or an error naming the status and what the service said.
    async fn json(response: reqwest::Response) -> Result<serde_json::Value, StateError> {
        let status = response.status();
        let body = response.text().await.map_err(|e| StateError(format!("GCS response unreadable: {e}")))?;
        if !status.is_success() {
            return Err(StateError(format!("GCS answered {status}: {body}")));
        }
        if body.is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_str(&body).map_err(|e| StateError(format!("GCS answered unreadable JSON ({e}): {body}")))
    }

    /// `objects.get`: the object resource, `None` when there is no such object.
    pub async fn get_object(&self, bucket: &str, name: &str) -> Result<Option<serde_json::Value>, StateError> {
        let response = self.send(self.http.get(self.object_url(bucket, name))).await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::json(response).await.map(Some)
    }

    /// `objects.list` under `prefix`, every page.
    pub async fn list_objects(&self, bucket: &str, prefix: &str) -> Result<Vec<String>, StateError> {
        let url = format!("{}/storage/v1/b/{}/o", self.host, utf8_percent_encode(bucket, PATH_SEGMENT));
        let mut names = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut query = vec![("prefix", prefix.to_string()), ("fields", "items(name),nextPageToken".to_string())];
            query.extend(token.take().map(|t| ("pageToken", t)));
            let page = Self::json(self.send(self.http.get(&url).query(&query)).await?).await?;
            let items = page.get("items").and_then(serde_json::Value::as_array).into_iter().flatten();
            names.extend(items.filter_map(|item| item.get("name").and_then(serde_json::Value::as_str)).map(String::from));
            match page.get("nextPageToken").and_then(serde_json::Value::as_str) {
                Some(next) if !next.is_empty() => token = Some(next.to_string()),
                _ => return Ok(names),
            }
        }
    }

    /// `objects.delete`: `false` when there was no such object.
    pub async fn delete_object(&self, bucket: &str, name: &str) -> Result<bool, StateError> {
        let response = self.send(self.http.delete(self.object_url(bucket, name))).await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        Self::json(response).await.map(|_| true)
    }

    /// `buckets.insert` in `project`.
    pub async fn create_bucket(&self, project: &str, name: &str) -> Result<(), StateError> {
        let request = self.http.post(format!("{}/storage/v1/b", self.host)).query(&[("project", project)]).json(&serde_json::json!({ "name": name }));
        Self::json(self.send(request).await?).await.map(|_| ())
    }
}

pub struct GcsBlobStore {
    clients: Clients,
    bucket: String,
    key_prefix: String,
    wiring: Option<Wiring>,
}

impl GcsBlobStore {
    /// `new GcsBlobStore(storage, bucket, keyPrefix)`.
    pub fn new(clients: Clients, bucket: &str, key_prefix: &str) -> GcsBlobStore {
        GcsBlobStore { clients, bucket: bucket.into(), key_prefix: key_prefix.into(), wiring: None }
    }

    /// `GcsBlobStoreRegistrar.createGcsBlobStore(configuration)`; the error is the exception's message.
    pub fn from_config(config: &crate::Config) -> Result<GcsBlobStore, String> {
        let bucket = non_empty(config, "blobStoreBucket").ok_or("blobStoreType=gcs requires blobStoreBucket to be configured")?;
        let wiring = Wiring::from_config(config);
        let clients = Clients::new(&wiring)?;
        Ok(GcsBlobStore { clients, bucket, key_prefix: config.property("blobStoreKeyPrefix").unwrap_or_default(), wiring: Some(wiring) })
    }

    /// The options the store was configured with (`None` for a store given its clients).
    pub fn wiring(&self) -> Option<&Wiring> {
        self.wiring.as_ref()
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn key_prefix(&self) -> &str {
        &self.key_prefix
    }

    fn gcs_name(&self, key: &str) -> String {
        keys::join(&self.key_prefix, key)
    }

    /// The SDK's bucket resource name.
    fn bucket_name(&self) -> String {
        bucket_resource(&self.bucket)
    }
}

/// `projects/_/buckets/{bucket}`, the bucket name the SDK's requests take.
pub fn bucket_resource(bucket: &str) -> String {
    format!("projects/_/buckets/{bucket}")
}

fn error(e: google_cloud_storage::Error) -> StateError {
    StateError(e.to_string())
}

fn not_found(e: &google_cloud_storage::Error) -> bool {
    e.http_status_code() == Some(404)
}

impl BlobStore for GcsBlobStore {
    fn put(&self, key: &str, data: Vec<u8>, metadata: HashMap<String, String>) {
        if let Err(e) = self.try_put(key, data, metadata) {
            eprintln!("ERROR put blob '{key}' to gs://{}: {e}", self.bucket);
        }
    }

    fn get(&self, key: &str) -> Option<Blob> {
        self.try_get(key).unwrap_or_else(|e| {
            eprintln!("ERROR get blob '{key}' from gs://{}: {e}", self.bucket);
            None
        })
    }

    fn list(&self, prefix: &str) -> Vec<String> {
        self.try_list(prefix).unwrap_or_else(|e| {
            eprintln!("ERROR list blobs '{prefix}' in gs://{}: {e}", self.bucket);
            Vec::new()
        })
    }

    fn delete(&self, key: &str) -> bool {
        self.try_delete(key).unwrap_or_else(|e| {
            eprintln!("ERROR delete blob '{key}' from gs://{}: {e}", self.bucket);
            false
        })
    }

    /// `storage.create(blobInfo, data)`: one multipart upload. The CRC32C goes in the metadata part, as the Java
    /// client sends it; left to the SDK it trails the media as a third part, which fake-gcs-server 1.49.3 does not
    /// read, answering a CRC32C of other bytes that fails the SDK's check.
    fn try_put(&self, key: &str, data: Vec<u8>, metadata: HashMap<String, String>) -> Result<(), StateError> {
        let crc32c = crc32c::crc32c(&data);
        let request = self.clients.storage.write_object(self.bucket_name(), self.gcs_name(key), bytes::Bytes::from(data)).with_known_crc32c(crc32c).set_metadata(metadata);
        block_on(request.send_unbuffered()).map(|_| ()).map_err(error)
    }

    /// `storage.get(blobId)` (the object resource, `null` when absent), then `getContent()`.
    fn try_get(&self, key: &str) -> Result<Option<Blob>, StateError> {
        let name = self.gcs_name(key);
        block_on(async move {
            let Some(object) = self.clients.json.get_object(&self.bucket, &name).await? else { return Ok(None) };
            let metadata = object.get("metadata").and_then(serde_json::Value::as_object).into_iter().flatten();
            let metadata = metadata.filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string()))).collect();
            let mut response = match self.clients.storage.read_object(self.bucket_name(), &name).send().await {
                Ok(response) => response,
                Err(e) if not_found(&e) => return Ok(None),
                Err(e) => return Err(error(e)),
            };
            let mut data = Vec::new();
            while let Some(chunk) = response.next().await {
                data.extend_from_slice(&chunk.map_err(error)?);
            }
            Ok(Some(Blob { key: key.to_string(), data, metadata }))
        })
    }

    fn try_list(&self, prefix: &str) -> Result<Vec<String>, StateError> {
        let names = block_on(self.clients.json.list_objects(&self.bucket, &self.gcs_name(prefix)))?;
        Ok(names.iter().map(|name| keys::strip_prefix(&self.key_prefix, name)).collect())
    }

    /// `storage.delete(blobId)`: `false` when there was no such object.
    fn try_delete(&self, key: &str) -> Result<bool, StateError> {
        block_on(self.clients.json.delete_object(&self.bucket, &self.gcs_name(key)))
    }
}

#[cfg(test)]
mod tests {
    //! The guard branches of `GcsBlobStoreRegistrarConfigWiringTest` and its option assertions, read from the
    //! store's [`Wiring`] (the Rust SDK's clients do not show their options); the emulator round trip is in
    //! `tests/upstream/blob_gcs.rs`.

    use super::*;

    fn config(properties: &[(&str, &str)]) -> crate::Config {
        properties.iter().fold(crate::Config::for_tests(), |c, (k, v)| c.with_property(k, v))
    }

    #[test]
    fn should_throw_when_bucket_missing() {
        assert_eq!(GcsBlobStore::from_config(&config(&[])).err().as_deref(), Some("blobStoreType=gcs requires blobStoreBucket to be configured"));
    }

    #[test]
    fn should_throw_when_bucket_empty() {
        assert!(GcsBlobStore::from_config(&config(&[("blobStoreBucket", "")])).is_err());
    }

    #[test]
    fn should_apply_endpoint_override_as_storage_host() {
        let wiring = Wiring::from_config(&config(&[("blobStoreBucket", "b"), ("blobStoreEndpoint", "http://localhost:4443")]));
        assert_eq!(wiring.host.as_deref(), Some("http://localhost:4443"));
    }

    #[test]
    fn should_use_no_credentials_when_endpoint_configured() {
        let wiring = Wiring::from_config(&config(&[("blobStoreBucket", "b"), ("blobStoreEndpoint", "http://localhost:4443")]));
        assert_eq!(wiring.credentials, CredentialsSource::None);
    }

    #[test]
    fn should_apply_configured_project_id() {
        let wiring = Wiring::from_config(&config(&[("blobStoreBucket", "b"), ("blobStoreEndpoint", "http://localhost:4443"), ("blobStoreProjectId", "my-project-1")]));
        assert_eq!(wiring.project_id.as_deref(), Some("my-project-1"));
    }

    #[test]
    fn should_fall_back_to_test_project_when_project_id_unset() {
        let wiring = Wiring::from_config(&config(&[("blobStoreBucket", "b"), ("blobStoreEndpoint", "http://localhost:4443")]));
        assert_eq!(wiring.project_id.as_deref(), Some("test-project"));
    }

    #[test]
    fn should_use_application_default_credentials_without_an_endpoint() {
        let wiring = Wiring::from_config(&config(&[("blobStoreBucket", "b"), ("blobStoreProjectId", "p")]));
        assert_eq!(wiring, Wiring { host: None, credentials: CredentialsSource::ApplicationDefault, project_id: Some("p".into()) });
    }

    #[test]
    fn should_build_the_store_with_the_configured_bucket_and_prefix() {
        let store = GcsBlobStore::from_config(&config(&[("blobStoreBucket", "my-bucket"), ("blobStoreEndpoint", "http://fake-gcs.invalid:4443"), ("blobStoreKeyPrefix", "mockserver/prefix/")])).unwrap();
        assert_eq!((store.bucket(), store.key_prefix()), ("my-bucket", "mockserver/prefix/"));
    }
}

//! `mockserver-blob-azure`: `AzureBlobStore` over Azure Blob Storage (or Azurite), and
//! `AzureBlobStoreRegistrar.createAzureBlobStore`'s wiring of `blobStoreContainer` and `blobStoreConnectionString`.
//! Metadata is the blobs' metadata, its keys escaped to C# identifiers ([`encode_key`]).
//!
//! The official Rust SDK (`azure_storage_blob`) authenticates with Entra ID tokens or a SAS-bearing URL only; it has
//! no connection strings and no Shared Key. The connection string is parsed here as the Java SDK's
//! `BlobServiceClientBuilder.connectionString` reads it, and an account key becomes a short-lived account SAS
//! (signed with that key) on each request's client; a `SharedAccessSignature` in the string is used as it is.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use azure_core::http::{StatusCode, Url};
use azure_storage_blob::models::{BlobClientUploadOptions, BlobContainerClientListBlobsOptions};
use azure_storage_blob::BlobContainerClient;
use base64::Engine;
use futures_util::TryStreamExt;

use super::{block_on, keys, non_empty};
use crate::state_backend::{Blob, BlobStore, StateError};

/// Azurite's well-known development account (`UseDevelopmentStorage=true`).
const DEVSTORE_ACCOUNT: &str = "devstoreaccount1";
const DEVSTORE_KEY: &str = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

/// How requests are authorised.
#[derive(Clone)]
enum Authorization {
    /// An account key: each request's client carries an account SAS signed with it.
    AccountKey { account: String, key: Vec<u8> },
    /// A SAS from the connection string.
    Sas(String),
}

/// The parts of a storage connection string the blob service needs.
#[derive(Clone)]
pub struct ConnectionString {
    blob_endpoint: String,
    authorization: Authorization,
}

impl ConnectionString {
    /// `StorageConnectionString.create`: `;`-separated `name=value` pairs (a value may hold `=`).
    pub fn parse(text: &str) -> Result<ConnectionString, String> {
        let settings: HashMap<String, String> =
            text.split(';').filter(|p| !p.trim().is_empty()).filter_map(|p| p.split_once('=')).map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string())).collect();
        let get = |name: &str| settings.get(&name.to_lowercase()).filter(|v| !v.is_empty()).cloned();
        if get("UseDevelopmentStorage").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
            let proxy = get("DevelopmentStorageProxyUri").unwrap_or_else(|| "http://127.0.0.1".into());
            return Ok(ConnectionString {
                blob_endpoint: format!("{}:10000/{DEVSTORE_ACCOUNT}", proxy.trim_end_matches('/')),
                authorization: Authorization::AccountKey { account: DEVSTORE_ACCOUNT.into(), key: decode_key(DEVSTORE_KEY)? },
            });
        }
        let account = get("AccountName");
        let blob_endpoint = match (get("BlobEndpoint"), &account) {
            (Some(endpoint), _) => endpoint,
            (None, Some(account)) => {
                let protocol = get("DefaultEndpointsProtocol").unwrap_or_else(|| "https".into());
                let suffix = get("EndpointSuffix").unwrap_or_else(|| "core.windows.net".into());
                format!("{protocol}://{account}.blob.{suffix}")
            }
            (None, None) => return Err("Invalid connection string: no blob endpoint and no account name".into()),
        };
        let authorization = match (get("SharedAccessSignature"), account, get("AccountKey")) {
            (Some(sas), _, _) => Authorization::Sas(sas.trim_start_matches('?').to_string()),
            (None, Some(account), Some(key)) => Authorization::AccountKey { account, key: decode_key(&key)? },
            _ => return Err("Invalid connection string: neither an account name and key nor a shared access signature".into()),
        };
        Ok(ConnectionString { blob_endpoint: blob_endpoint.trim_end_matches('/').to_string(), authorization })
    }

    pub fn blob_endpoint(&self) -> &str {
        &self.blob_endpoint
    }
}

fn decode_key(key: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD.decode(key).map_err(|e| format!("Invalid connection string: the account key is not base64: {e}"))
}

/// An account SAS for the blob service (version 2020-12-06 and later string-to-sign), valid from five minutes ago
/// for an hour.
fn account_sas(account: &str, key: &[u8], now: SystemTime) -> String {
    let format = |t: SystemTime| chrono::DateTime::<chrono::Utc>::from(t).format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let (start, expiry) = (format(now - Duration::from_secs(300)), format(now + Duration::from_secs(3600)));
    let (version, permissions, services, resource_types, protocol) = ("2021-06-08", "rwdlac", "b", "sco", "https,http");
    let to_sign = format!("{account}\n{permissions}\n{services}\n{resource_types}\n{start}\n{expiry}\n\n{protocol}\n{version}\n\n");
    let signature = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key), to_sign.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(signature.as_ref());
    // RFC 3986 unreserved characters stay as they are
    const QUERY_VALUE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');
    let encode = |v: &str| percent_encoding::utf8_percent_encode(v, QUERY_VALUE).to_string();
    format!("sv={version}&ss={services}&srt={resource_types}&sp={permissions}&st={}&se={}&spr={}&sig={}", encode(&start), encode(&expiry), encode(protocol), encode(&signature))
}

pub struct AzureBlobStore {
    connection: ConnectionString,
    container: String,
    key_prefix: String,
}

impl AzureBlobStore {
    /// `new AzureBlobStore(containerClient, keyPrefix)`, the container client given by connection string and name.
    pub fn new(connection: ConnectionString, container: &str, key_prefix: &str) -> AzureBlobStore {
        AzureBlobStore { connection, container: container.into(), key_prefix: key_prefix.into() }
    }

    /// `AzureBlobStoreRegistrar.createAzureBlobStore(configuration)`; the error is the exception's message.
    pub fn from_config(config: &crate::Config) -> Result<AzureBlobStore, String> {
        let container = non_empty(config, "blobStoreContainer").ok_or("blobStoreType=azure requires blobStoreContainer to be configured")?;
        let connection_string = non_empty(config, "blobStoreConnectionString").ok_or("blobStoreType=azure requires blobStoreConnectionString to be configured")?;
        let connection = ConnectionString::parse(&connection_string)?;
        let store = AzureBlobStore::new(connection, &container, &config.property("blobStoreKeyPrefix").unwrap_or_default());
        store.container_client().map_err(|e| e.0)?;
        Ok(store)
    }

    /// `BlobContainerClient.getBlobContainerName()`.
    pub fn container(&self) -> &str {
        &self.container
    }

    pub fn key_prefix(&self) -> &str {
        &self.key_prefix
    }

    /// `BlobContainerClient.getBlobContainerUrl()`, without the SAS.
    pub fn container_url(&self) -> String {
        format!("{}/{}", self.connection.blob_endpoint, self.container)
    }

    /// A client for the container whose URL carries a fresh SAS.
    pub fn container_client(&self) -> Result<BlobContainerClient, StateError> {
        let sas = match &self.connection.authorization {
            Authorization::AccountKey { account, key } => account_sas(account, key, SystemTime::now()),
            Authorization::Sas(sas) => sas.clone(),
        };
        let url = Url::parse(&format!("{}?{sas}", self.container_url())).map_err(|e| StateError(format!("invalid container URL {}: {e}", self.container_url())))?;
        BlobContainerClient::new(url, None, None).map_err(|e| StateError(e.to_string()))
    }

    fn azure_name(&self, key: &str) -> String {
        keys::join(&self.key_prefix, key)
    }
}

fn not_found(e: &azure_core::Error) -> bool {
    e.http_status() == Some(StatusCode::NotFound)
}

fn error(e: azure_core::Error) -> StateError {
    StateError(e.to_string())
}

impl BlobStore for AzureBlobStore {
    fn put(&self, key: &str, data: Vec<u8>, metadata: HashMap<String, String>) {
        if let Err(e) = self.try_put(key, data, metadata) {
            eprintln!("ERROR put blob '{key}' to azure://{}: {e}", self.container);
        }
    }

    fn get(&self, key: &str) -> Option<Blob> {
        self.try_get(key).unwrap_or_else(|e| {
            eprintln!("ERROR get blob '{key}' from azure://{}: {e}", self.container);
            None
        })
    }

    fn list(&self, prefix: &str) -> Vec<String> {
        self.try_list(prefix).unwrap_or_else(|e| {
            eprintln!("ERROR list blobs '{prefix}' in azure://{}: {e}", self.container);
            Vec::new()
        })
    }

    fn delete(&self, key: &str) -> bool {
        self.try_delete(key).unwrap_or_else(|e| {
            eprintln!("ERROR delete blob '{key}' from azure://{}: {e}", self.container);
            false
        })
    }

    /// Data and metadata in one upload, so a concurrent `get` never sees one without the other.
    fn try_put(&self, key: &str, data: Vec<u8>, metadata: HashMap<String, String>) -> Result<(), StateError> {
        let blob = self.container_client()?.blob_client(&self.azure_name(key));
        let encoded = encode_metadata_keys(&metadata);
        let options = BlobClientUploadOptions { metadata: (!encoded.is_empty()).then_some(encoded), ..Default::default() };
        block_on(blob.upload(bytes::Bytes::from(data).into(), Some(options))).map(|_| ()).map_err(error)
    }

    fn try_get(&self, key: &str) -> Result<Option<Blob>, StateError> {
        let blob = self.container_client()?.blob_client(&self.azure_name(key));
        block_on(async move {
            let response = match blob.download(None).await {
                Ok(response) => response,
                Err(e) if not_found(&e) => return Ok(None),
                Err(e) => return Err(error(e)),
            };
            let metadata = decode_metadata_keys(&response.properties.metadata);
            let data = response.body.collect().await.map_err(error)?.to_vec();
            Ok(Some(Blob { key: key.to_string(), data, metadata }))
        })
    }

    fn try_list(&self, prefix: &str) -> Result<Vec<String>, StateError> {
        let client = self.container_client()?;
        let options = BlobContainerClientListBlobsOptions { prefix: Some(self.azure_name(prefix)), ..Default::default() };
        let mut pager = client.list_blobs(Some(options)).map_err(error)?;
        block_on(async move {
            let mut names = Vec::new();
            while let Some(item) = pager.try_next().await.map_err(error)? {
                if let Some(name) = item.name {
                    names.push(keys::strip_prefix(&self.key_prefix, &name));
                }
            }
            Ok(names)
        })
    }

    fn try_delete(&self, key: &str) -> Result<bool, StateError> {
        let blob = self.container_client()?.blob_client(&self.azure_name(key));
        block_on(async move {
            if !blob.exists().await.map_err(error)? {
                return Ok(false);
            }
            match blob.delete(None).await {
                Ok(_) => Ok(true),
                Err(e) if not_found(&e) => Ok(false),
                Err(e) => Err(error(e)),
            }
        })
    }
}

/// `AzureBlobStore.encodeMetadataKeys`.
pub fn encode_metadata_keys(metadata: &HashMap<String, String>) -> HashMap<String, String> {
    metadata.iter().map(|(k, v)| (encode_key(k), v.clone())).collect()
}

/// `AzureBlobStore.decodeMetadataKeys`.
pub fn decode_metadata_keys(metadata: &HashMap<String, String>) -> HashMap<String, String> {
    metadata.iter().map(|(k, v)| (decode_key_name(k), v.clone())).collect()
}

/// `AzureBlobStore.encodeKey`: letters pass, digits pass unless first, every other UTF-16 code unit (`_` included)
/// becomes `_` and four lowercase hex digits.
fn encode_key(key: &str) -> String {
    let mut encoded = String::new();
    for (i, unit) in key.encode_utf16().enumerate() {
        let c = char::from_u32(u32::from(unit)).filter(char::is_ascii);
        match c {
            Some(c) if c.is_ascii_alphabetic() || (c.is_ascii_digit() && i > 0) => encoded.push(c),
            _ => encoded.push_str(&format!("_{unit:04x}")),
        }
    }
    encoded
}

/// `AzureBlobStore.decodeKey`: `_` and four hex digits is one UTF-16 code unit; anything else passes literally.
fn decode_key_name(encoded: &str) -> String {
    let units: Vec<u16> = encoded.encode_utf16().collect();
    let mut decoded = Vec::with_capacity(units.len());
    let mut i = 0;
    while i < units.len() {
        let escape = units.get(i + 1..i + 5).filter(|hex| units[i] == u16::from(b'_') && hex.iter().all(|u| char::from_u32(u32::from(*u)).is_some_and(|c| c.is_ascii_hexdigit())));
        match escape {
            Some(hex) => {
                let hex: String = hex.iter().map(|u| char::from(*u as u8)).collect();
                decoded.push(u16::from_str_radix(&hex, 16).unwrap_or_default());
                i += 5;
            }
            None => {
                decoded.push(units[i]);
                i += 1;
            }
        }
    }
    String::from_utf16_lossy(&decoded)
}

#[cfg(test)]
mod tests {
    //! `AzureBlobStoreMetadataKeyEncodingTest`, the guard branches of `AzureBlobStoreRegistrarConfigWiringTest` (the
    //! rest runs against Azurite: `tests/upstream/blob_azure.rs`) and the connection string.

    use super::*;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn assert_round_trips(key: &str) {
        let original = map(&[(key, "value")]);
        let encoded = encode_metadata_keys(&original);
        let decoded = decode_metadata_keys(&encoded);
        assert_eq!(decoded, original, "key '{key}' encoded to {:?} did not round-trip", encoded.keys());
    }

    #[test]
    fn should_round_trip_ascii_keys() {
        for key in ["simple", "x-custom-type", "x_custom_type", "with.dots", "with spaces", "with=equals"] {
            assert_round_trips(key);
        }
    }

    #[test]
    fn should_round_trip_keys_above_latin1() {
        for key in ["中文", "emoji-✓", "mixed-中-ascii", "Ω"] {
            assert_round_trips(key);
        }
    }

    #[test]
    fn should_round_trip_latin1_keys() {
        for key in ["café", "naïve", "ÿ"] {
            assert_round_trips(key);
        }
    }

    #[test]
    fn should_round_trip_non_bmp_keys() {
        assert_round_trips("emoji-😀");
        assert_round_trips("😀");
    }

    #[test]
    fn should_not_produce_keys_starting_with_a_digit() {
        for key in ["1abc", "9", "0-leading", "中文", "-dash"] {
            let encoded = encode_key(key);
            assert!(!encoded.starts_with(|c: char| c.is_ascii_digit()), "encoded key '{encoded}' for '{key}' must not start with a digit");
            assert_round_trips(key);
        }
    }

    #[test]
    fn should_not_collide_distinct_keys() {
        let original = map(&[("x-custom-type", "hyphen"), ("x_custom_type", "underscore"), ("x.custom.type", "dot"), ("中文", "chinese"), ("1abc", "leading-digit")]);
        let encoded = encode_metadata_keys(&original);
        assert_eq!(encoded.len(), original.len(), "distinct keys must encode to distinct Azure keys");
        assert_eq!(decode_metadata_keys(&encoded), original);
    }

    #[test]
    fn should_pass_through_malformed_escapes_literally() {
        let stored = map(&[("_zz", "short-non-hex"), ("_", "bare-underscore"), ("trailing_", "trailing-underscore")]);
        let decoded = decode_metadata_keys(&stored);
        assert_eq!(decoded.get("_zz").map(String::as_str), Some("short-non-hex"));
        assert_eq!(decoded.get("_").map(String::as_str), Some("bare-underscore"));
        assert_eq!(decoded.get("trailing_").map(String::as_str), Some("trailing-underscore"));
    }

    #[test]
    fn should_encode_using_fixed_four_digit_hex_escapes() {
        assert_eq!(encode_metadata_keys(&map(&[("a-b", "value")])).keys().collect::<Vec<_>>(), vec!["a_002db"]);
    }

    fn store(properties: &[(&str, &str)]) -> Result<AzureBlobStore, String> {
        AzureBlobStore::from_config(&properties.iter().fold(crate::Config::for_tests(), |c, (k, v)| c.with_property(k, v)))
    }

    const CONNECTION: &str = "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;";

    #[test]
    fn should_throw_when_container_missing() {
        assert_eq!(store(&[("blobStoreConnectionString", CONNECTION)]).err().as_deref(), Some("blobStoreType=azure requires blobStoreContainer to be configured"));
    }

    #[test]
    fn should_throw_when_connection_string_missing() {
        assert_eq!(store(&[("blobStoreContainer", "some-container")]).err().as_deref(), Some("blobStoreType=azure requires blobStoreConnectionString to be configured"));
    }

    #[test]
    fn should_target_configured_container_and_connection_string_endpoint() {
        let store = store(&[("blobStoreContainer", "some-container"), ("blobStoreConnectionString", CONNECTION), ("blobStoreKeyPrefix", "p/")]).unwrap();
        assert_eq!(store.container(), "some-container");
        assert_eq!(store.container_url(), "http://127.0.0.1:10000/devstoreaccount1/some-container");
        assert_eq!(store.key_prefix(), "p/");
        let client_url = store.container_client().unwrap().url().to_string();
        assert!(client_url.starts_with("http://127.0.0.1:10000/devstoreaccount1/some-container?sv=2021-06-08&ss=b&srt=sco&sp=rwdlac&st="), "{client_url}");
    }

    #[test]
    fn connection_string_endpoints() {
        let account = ConnectionString::parse("DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=a2V5;EndpointSuffix=core.chinacloudapi.cn").unwrap();
        assert_eq!(account.blob_endpoint(), "https://acct.blob.core.chinacloudapi.cn");
        assert_eq!(ConnectionString::parse("UseDevelopmentStorage=true").unwrap().blob_endpoint(), "http://127.0.0.1:10000/devstoreaccount1");
        let sas = ConnectionString::parse("BlobEndpoint=https://acct.blob.core.windows.net/;SharedAccessSignature=sv=2021-06-08&sig=abc%3D").unwrap();
        assert_eq!(sas.blob_endpoint(), "https://acct.blob.core.windows.net");
        assert!(ConnectionString::parse("AccountName=acct").is_err());
    }

    /// The account SAS string-to-sign of the Azure Storage documentation ("Create an account SAS"), signed with the
    /// key, as the Java SDK's `AccountSasSignatureValues` does.
    #[test]
    fn account_sas_signature() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let sas = account_sas("acct", b"key", now);
        let to_sign = "acct\nrwdlac\nb\nsco\n2027-01-15T07:55:00Z\n2027-01-15T09:00:00Z\n\nhttps,http\n2021-06-08\n\n";
        let expected = base64::engine::general_purpose::STANDARD.encode(ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"key"), to_sign.as_bytes()).as_ref());
        let signature = sas.rsplit_once("&sig=").unwrap().1;
        assert_eq!(percent_encoding::percent_decode_str(signature).decode_utf8().unwrap(), expected);
        assert!(sas.contains("&st=2027-01-15T07%3A55%3A00Z&se=2027-01-15T09%3A00%3A00Z&spr=https%2Chttp"), "{sas}");
    }
}

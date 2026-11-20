//! `AwsSigV4Signer`: AWS Signature Version 4 for the Bedrock runtime client (a canonical request over the sorted,
//! trimmed signed headers and the payload's SHA-256, the string to sign over the credential scope, and the
//! HMAC-SHA256 key chain). The timestamp is a parameter, so signing is deterministic.

use chrono::{DateTime, Utc};
use ring::{digest, hmac};

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// `sign`: the headers to add to the request, in order: `Authorization`, `X-Amz-Date`, `X-Amz-Content-Sha256` and,
/// with a session token, `X-Amz-Security-Token`. `extra_headers_to_sign` are signed with lower-cased names.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    method: &str,
    host: &str,
    canonical_uri: &str,
    canonical_query_string: &str,
    payload: &[u8],
    region: &str,
    service: &str,
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
    timestamp: DateTime<Utc>,
    extra_headers_to_sign: &[(&str, &str)],
) -> Vec<(String, String)> {
    let amz_date = timestamp.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = timestamp.format("%Y%m%d").to_string();
    let payload_hash = hex_sha256(payload);
    let session_token = session_token.filter(|t| !t.is_empty());
    let mut to_sign: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    to_sign.insert("host".into(), host.to_string());
    to_sign.insert("x-amz-date".into(), amz_date.clone());
    if let Some(token) = session_token {
        to_sign.insert("x-amz-security-token".into(), token.to_string());
    }
    for (name, value) in extra_headers_to_sign {
        to_sign.insert(name.to_lowercase(), trim_all(value));
    }
    let canonical_headers: String = to_sign.iter().map(|(k, v)| format!("{k}:{}\n", trim_all(v))).collect();
    let signed_headers = to_sign.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical_request = format!("{method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!("{ALGORITHM}\n{amz_date}\n{scope}\n{}", hex_sha256(canonical_request.as_bytes()));
    let key = derive_signing_key(secret_access_key, &date_stamp, region, service);
    let signature = hex_encode(&hmac_sha256(&key, string_to_sign.as_bytes()));
    let mut headers = vec![
        ("Authorization".to_string(), format!("{ALGORITHM} Credential={access_key_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}")),
        ("X-Amz-Date".to_string(), amz_date),
        ("X-Amz-Content-Sha256".to_string(), payload_hash),
    ];
    if let Some(token) = session_token {
        headers.push(("X-Amz-Security-Token".into(), token.to_string()));
    }
    headers
}

/// `deriveSigningKey`: `HMAC("AWS4" + secret, date)`, then region, service and `aws4_request`.
pub fn derive_signing_key(secret_access_key: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret_access_key}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// `uriEncodePathSegment`: every byte but the unreserved characters percent-encoded (upper-case hex).
pub fn uri_encode_path_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len() * 2);
    for b in segment.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `uriEncodePath`: each `/`-separated segment encoded; an empty path is `/`.
pub fn uri_encode_path(path: &str) -> String {
    if path.is_empty() {
        return "/".into();
    }
    path.split('/').map(uri_encode_path_segment).collect::<Vec<_>>().join("/")
}

/// `hexSha256`.
pub fn hex_sha256(data: &[u8]) -> String {
    hex_encode(digest::digest(&digest::SHA256, data).as_ref())
}

/// `hexEncode`: lower-case hex.
pub fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data).as_ref().to_vec()
}

/// `trimAll`: trimmed, inner whitespace runs as one space.
fn trim_all(value: &str) -> String {
    super::conversation::collapse_whitespace(value)
}

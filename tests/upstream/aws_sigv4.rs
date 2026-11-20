//! `AwsSigV4SignerTest` (mockserver-core, in-JVM unit test of `AwsSigV4Signer`), one to one against
//! `mock_server::aws_sigv4`, plus two more vectors of AWS's published SigV4 test suite (`post-vanilla` and
//! `get-vanilla-query-order-key-case`).

use chrono::{DateTime, Utc};
use mock_server::aws_sigv4::{derive_signing_key, hex_encode, hex_sha256, sign, uri_encode_path, uri_encode_path_segment};

const TEST_ACCESS_KEY: &str = "AKIDEXAMPLE";
const TEST_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn at(text: &str) -> DateTime<Utc> {
    text.parse().unwrap()
}

fn test_timestamp() -> DateTime<Utc> {
    at("2015-08-30T12:36:00Z")
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn get_vanilla() -> Vec<(String, String)> {
    sign("GET", "example.amazonaws.com", "/", "", b"", "us-east-1", "service", TEST_ACCESS_KEY, TEST_SECRET_KEY, None, test_timestamp(), &[])
}

#[test]
fn signing_key_derivation_matches_aws_published_vector() {
    let key = derive_signing_key(TEST_SECRET_KEY, "20120215", "us-east-1", "iam");
    assert_eq!(hex_encode(&key), "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d");
}

#[test]
fn full_signature_is_structurally_correct_and_deterministic() {
    let headers = get_vanilla();
    assert!(header(&headers, "Authorization").is_some());
    assert!(header(&headers, "X-Amz-Date").is_some());
    assert!(header(&headers, "X-Amz-Content-Sha256").is_some());
    assert!(header(&headers, "X-Amz-Security-Token").is_none());
    let auth = header(&headers, "Authorization").unwrap();
    assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request"));
    assert!(auth.contains("SignedHeaders=host;x-amz-date"));
    assert!(auth.contains("Signature="));
    assert_eq!(header(&headers, "X-Amz-Date"), Some("20150830T123600Z"));
    assert_eq!(header(&headers, "X-Amz-Content-Sha256"), Some(EMPTY_SHA256));
}

#[test]
fn get_vanilla_signature_matches_aws_test_suite_vector() {
    let headers = get_vanilla();
    let auth = header(&headers, "Authorization").unwrap().to_string();
    assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature="));
    let signature = &auth[auth.find("Signature=").unwrap() + "Signature=".len()..];
    assert_eq!(signature.len(), 64);
    assert!(signature.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    assert_eq!(signature, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
    assert_eq!(header(&get_vanilla(), "Authorization").unwrap(), auth);
}

#[test]
fn determinism_same_inputs_produce_same_signature() {
    let run = || {
        sign("POST", "service.us-east-1.amazonaws.com", "/path", "", br#"{"hello":"world"}"#, "us-east-1", "service", "AKID", "SECRET", None, test_timestamp(), &[("content-type", "application/json")])
    };
    let (a, b) = (run(), run());
    for name in ["Authorization", "X-Amz-Date", "X-Amz-Content-Sha256"] {
        assert_eq!(header(&a, name), header(&b, name));
    }
}

#[test]
fn different_body_produces_different_signature() {
    let run = |body: &[u8]| sign("POST", "host.example.com", "/", "", body, "us-east-1", "svc", "AKID", "SECRET", None, test_timestamp(), &[]);
    let (a, b) = (run(br#"{"a":1}"#), run(br#"{"b":2}"#));
    assert_ne!(header(&a, "X-Amz-Content-Sha256"), header(&b, "X-Amz-Content-Sha256"));
    assert_ne!(header(&a, "Authorization"), header(&b, "Authorization"));
}

#[test]
fn session_token_adds_security_token_header_and_changes_signed_headers() {
    let run = |token| sign("POST", "host.example.com", "/", "", b"", "us-east-1", "svc", "AKID", "SECRET", token, test_timestamp(), &[]);
    let (without, with) = (run(None), run(Some("TOKEN123")));
    assert!(header(&without, "X-Amz-Security-Token").is_none());
    assert_eq!(header(&with, "X-Amz-Security-Token"), Some("TOKEN123"));
    assert!(header(&with, "Authorization").unwrap().contains("x-amz-security-token"));
    assert!(!header(&without, "Authorization").unwrap().contains("x-amz-security-token"));
    assert_ne!(header(&with, "Authorization"), header(&without, "Authorization"));
}

#[test]
fn extra_headers_are_included_in_signature() {
    let headers = sign("POST", "host.example.com", "/", "", b"", "us-east-1", "svc", "AKID", "SECRET", None, test_timestamp(), &[("content-type", "application/json")]);
    let auth = header(&headers, "Authorization").unwrap();
    assert!(auth.contains("content-type"));
    assert!(auth.contains("SignedHeaders=content-type;host;x-amz-date"));
}

#[test]
fn uri_encode_path_segment_encodes_colon_and_preserves_unreserved() {
    assert_eq!(uri_encode_path_segment("anthropic.claude-3:0"), "anthropic.claude-3%3A0");
    assert_eq!(uri_encode_path_segment("simple"), "simple");
    assert_eq!(uri_encode_path_segment("a b"), "a%20b");
}

#[test]
fn uri_encode_path_preserves_slash_separators() {
    assert_eq!(uri_encode_path("/model/my.model:v1/invoke"), "/model/my.model%3Av1/invoke");
}

#[test]
fn hex_sha256_of_empty_payload_matches_known_constant() {
    assert_eq!(hex_sha256(b""), EMPTY_SHA256);
}

#[test]
fn post_with_json_body_produces_valid_signature() {
    let payload = br#"{"anthropic_version":"bedrock-2023-05-31","max_tokens":1024}"#;
    let headers = sign(
        "POST",
        "bedrock-runtime.us-east-1.amazonaws.com",
        "/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/invoke",
        "",
        payload,
        "us-east-1",
        "bedrock",
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
        None,
        at("2024-01-15T10:30:00Z"),
        &[("content-type", "application/json")],
    );
    let auth = header(&headers, "Authorization").unwrap();
    assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240115/us-east-1/bedrock/aws4_request"));
    assert!(auth.contains("SignedHeaders=content-type;host;x-amz-date"));
    assert!(auth.contains("Signature="));
    assert_eq!(header(&headers, "X-Amz-Date"), Some("20240115T103000Z"));
    assert_eq!(header(&headers, "X-Amz-Content-Sha256"), Some(hex_sha256(payload).as_str()));
}

// AWS SigV4 test suite (aws-sig-v4-test-suite): the two further vanilla vectors.

#[test]
fn aws_post_vanilla_vector() {
    let headers = sign("POST", "example.amazonaws.com", "/", "", b"", "us-east-1", "service", TEST_ACCESS_KEY, TEST_SECRET_KEY, None, test_timestamp(), &[]);
    assert_eq!(
        header(&headers, "Authorization"),
        Some("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b")
    );
}

#[test]
fn aws_get_vanilla_query_order_key_case_vector() {
    let headers = sign("GET", "example.amazonaws.com", "/", "Param1=value1&Param2=value2", b"", "us-east-1", "service", TEST_ACCESS_KEY, TEST_SECRET_KEY, None, test_timestamp(), &[]);
    assert_eq!(
        header(&headers, "Authorization"),
        Some("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500")
    );
}

//! `AsyncApiControlPlaneVerifyTest` (mockserver-async): `PUT /mockserver/asyncapi/verify` on an in-process server
//! whose control plane has upstream's stub subscriber installed (`add_subscriber_for_testing`, as upstream's
//! `addSubscriberForTesting`). A pass is a 202, a failure a 406 carrying its text, and upstream's
//! `IllegalArgumentException` a 400 carrying its message.

use std::sync::Arc;

use mock_server::asyncapi::store::ConsumedMessage;
use serde_json::Value;

use crate::asyncapi_stubs::StubSubscriber;
use crate::common::{self, Running, send};

// ---- AsyncApiControlPlaneVerifyTest ----

pub fn msg(channel: &str, payload: &str) -> ConsumedMessage {
    ConsumedMessage::new(channel, None, Some(payload.to_string()), Vec::new())
}

/// A server whose control plane has a stub subscriber holding `messages` (`addMessages`).
async fn with_messages(messages: Vec<ConsumedMessage>) -> Running {
    let r = common::start(&[]).await;
    r.server.asyncapi().add_subscriber_for_testing(Arc::new(StubSubscriber::with(messages)));
    r
}

/// `verify`: `None` when it passes (202), the failure text when it does not (406).
pub async fn verify(r: &Running, request: &str) -> Option<String> {
    let response = send(r.port, "PUT", "/mockserver/asyncapi/verify", request).await;
    match response.status {
        202 => None,
        406 => Some(response.body),
        other => panic!("verify answered {other}: {}", response.body),
    }
}

/// A verify request upstream rejects with an `IllegalArgumentException`: a 400 carrying its message.
async fn rejected(r: &Running, request: &str) -> String {
    let response = send(r.port, "PUT", "/mockserver/asyncapi/verify", request).await;
    assert_eq!(response.status, 400, "{}", response.body);
    serde_json::from_str::<Value>(&response.body).unwrap()["error"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn should_pass_when_at_least_one_message_matches_channel() {
    let r = with_messages(vec![msg("orders", r#"{"orderId":1}"#), msg("orders", r#"{"orderId":2}"#)]).await;
    assert_eq!(verify(&r, r#"{"channel":"orders"}"#).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_pass_when_exactly_matches_count() {
    let r = with_messages(vec![msg("events", "hello"), msg("events", "world")]).await;
    assert_eq!(verify(&r, r#"{"channel":"events","count":{"exactly":2}}"#).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_pass_when_at_least_matches_count() {
    let r = with_messages(vec![msg("events", "a"), msg("events", "b"), msg("events", "c")]).await;
    assert_eq!(verify(&r, r#"{"channel":"events","count":{"atLeast":2}}"#).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_pass_when_at_most_matches_count() {
    let r = with_messages(vec![msg("events", "a"), msg("events", "b")]).await;
    assert_eq!(verify(&r, r#"{"channel":"events","count":{"atMost":3}}"#).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_pass_with_payload_substring_match() {
    let r = with_messages(vec![msg("orders", r#"{"orderId":42,"status":"completed"}"#), msg("orders", r#"{"orderId":99,"status":"pending"}"#)]).await;
    assert_eq!(verify(&r, r#"{"channel":"orders","payloadSubstring":"completed","count":{"exactly":1}}"#).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_pass_with_json_path_match() {
    let r = with_messages(vec![msg("orders", r#"{"user":{"name":"Alice"},"amount":100}"#), msg("orders", r#"{"user":{"name":"Bob"},"amount":200}"#)]).await;
    assert_eq!(verify(&r, r#"{"channel":"orders","payloadJsonPath":"user.name","expectedValue":"Alice","count":{"exactly":1}}"#).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_pass_with_both_substring_and_json_path_match() {
    let r = with_messages(vec![
        msg("orders", r#"{"user":{"name":"Alice"},"status":"completed"}"#),
        msg("orders", r#"{"user":{"name":"Alice"},"status":"pending"}"#),
    ])
    .await;
    let request = r#"{"channel":"orders","payloadSubstring":"completed","payloadJsonPath":"user.name","expectedValue":"Alice","count":{"exactly":1}}"#;
    assert_eq!(verify(&r, request).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_pass_when_exactly_zero_and_no_messages() {
    // No subscriber at all.
    let r = common::start(&[]).await;
    assert_eq!(verify(&r, r#"{"channel":"orders","count":{"exactly":0}}"#).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_pass_with_at_most_zero_and_no_messages() {
    let r = common::start(&[]).await;
    assert_eq!(verify(&r, r#"{"channel":"nonexistent","count":{"atMost":0}}"#).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fail_when_no_messages_match_channel() {
    let r = with_messages(vec![msg("other-channel", "hello")]).await;
    let failure = verify(&r, r#"{"channel":"orders"}"#).await.expect("fails");
    assert!(failure.contains("at least 1") && failure.contains("found 0") && failure.contains("orders"), "{failure}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fail_when_exactly_does_not_match() {
    let r = with_messages(vec![msg("events", "a"), msg("events", "b")]).await;
    let failure = verify(&r, r#"{"channel":"events","count":{"exactly":3}}"#).await.expect("fails");
    assert!(failure.contains("exactly 3") && failure.contains("found 2"), "{failure}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fail_when_at_least_not_met() {
    let r = with_messages(vec![msg("events", "a")]).await;
    let failure = verify(&r, r#"{"channel":"events","count":{"atLeast":5}}"#).await.expect("fails");
    assert!(failure.contains("at least 5") && failure.contains("found 1"), "{failure}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fail_when_at_most_exceeded() {
    let r = with_messages(vec![msg("events", "a"), msg("events", "b"), msg("events", "c")]).await;
    let failure = verify(&r, r#"{"channel":"events","count":{"atMost":1}}"#).await.expect("fails");
    assert!(failure.contains("at most 1") && failure.contains("found 3"), "{failure}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fail_when_payload_substring_not_found() {
    let r = with_messages(vec![msg("orders", r#"{"status":"pending"}"#)]).await;
    let failure = verify(&r, r#"{"channel":"orders","payloadSubstring":"completed"}"#).await.expect("fails");
    assert!(failure.contains("found 0"), "{failure}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fail_when_json_path_value_does_not_match() {
    let r = with_messages(vec![msg("orders", r#"{"user":{"name":"Bob"}}"#)]).await;
    let failure = verify(&r, r#"{"channel":"orders","payloadJsonPath":"user.name","expectedValue":"Alice"}"#).await.expect("fails");
    assert!(failure.contains("found 0"), "{failure}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_pass_when_both_at_least_and_at_most_satisfied() {
    let r = with_messages(vec![msg("events", "a"), msg("events", "b"), msg("events", "c")]).await;
    assert_eq!(verify(&r, r#"{"channel":"events","count":{"atLeast":2,"atMost":5}}"#).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fail_when_at_least_met_but_at_most_exceeded() {
    let r = with_messages(vec![msg("events", "a"), msg("events", "b"), msg("events", "c"), msg("events", "d")]).await;
    let failure = verify(&r, r#"{"channel":"events","count":{"atLeast":1,"atMost":2}}"#).await.expect("fails");
    assert!(failure.contains("at most 2") && failure.contains("found 4"), "{failure}");
}

/// Over HTTP a null body and an empty one are the same request.
#[tokio::test(flavor = "multi_thread")]
async fn should_throw_on_null_body() {
    let r = common::start(&[]).await;
    let response = common::exchange(r.port, common::Transport::Http, "PUT", "/mockserver/asyncapi/verify", &[], "").await;
    assert_eq!(response.status, 400);
    assert!(response.text().contains("verification request body must not be empty"), "{}", response.text());
}

#[tokio::test(flavor = "multi_thread")]
async fn should_throw_on_empty_body() {
    let r = common::start(&[]).await;
    assert_eq!(rejected(&r, "").await, "verification request body must not be empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_throw_on_blank_body() {
    let r = common::start(&[]).await;
    assert_eq!(rejected(&r, "   ").await, "verification request body must not be empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_throw_on_invalid_json() {
    let r = common::start(&[]).await;
    let error = rejected(&r, "not json").await;
    assert!(error.starts_with("invalid JSON in verification request: "), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_throw_when_channel_field_missing() {
    let r = common::start(&[]).await;
    assert_eq!(rejected(&r, r#"{"payloadSubstring":"hello"}"#).await, "verification request must contain a 'channel' field");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_a_count_field_at_the_top_level() {
    let r = with_messages(vec![msg("orders", "a")]).await;
    assert_eq!(
        rejected(&r, r#"{"channel":"orders","atMost":0}"#).await,
        r#"'atMost' must be inside "count", e.g. {"channel":"orders","count":{"atMost":1}}"#
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_an_unknown_top_level_field() {
    let r = common::start(&[]).await;
    assert_eq!(
        rejected(&r, r#"{"channel":"orders","payloadContains":"x"}"#).await,
        "unknown field 'payloadContains' in verification request; valid fields are [channel, payloadSubstring, payloadJsonPath, expectedValue, count]"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_an_unknown_count_field() {
    let r = common::start(&[]).await;
    assert_eq!(
        rejected(&r, r#"{"channel":"orders","count":{"atleast":1}}"#).await,
        r#"unknown field 'atleast' in "count"; valid fields are [atLeast, atMost, exactly]"#
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_a_count_that_is_not_an_object() {
    let r = common::start(&[]).await;
    assert_eq!(rejected(&r, r#"{"channel":"orders","count":1}"#).await, r#""count" must be an object with atLeast, atMost or exactly"#);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_a_count_value_that_is_not_a_whole_number_of_at_least_zero() {
    let r = common::start(&[]).await;
    for value in ["-1", "1.5", "\"2\"", "true"] {
        let request = format!(r#"{{"channel":"orders","count":{{"exactly":{value}}}}}"#);
        assert_eq!(rejected(&r, &request).await, r#""count".exactly must be a whole number of at least 0"#, "{value}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_honour_an_at_most_inside_count() {
    let r = with_messages(vec![msg("orders", "a")]).await;
    assert_eq!(
        verify(&r, r#"{"channel":"orders","count":{"atMost":0}}"#).await.as_deref(),
        Some("expected at most 0 message(s) matching channel 'orders' but found 1")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn should_handle_json_path_to_numeric_value() {
    let r = with_messages(vec![msg("orders", r#"{"amount":42}"#)]).await;
    assert_eq!(verify(&r, r#"{"channel":"orders","payloadJsonPath":"amount","expectedValue":"42"}"#).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_handle_json_path_to_boolean_value() {
    let r = with_messages(vec![msg("orders", r#"{"active":true}"#)]).await;
    assert_eq!(verify(&r, r#"{"channel":"orders","payloadJsonPath":"active","expectedValue":"true"}"#).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_handle_non_existent_json_path() {
    let r = with_messages(vec![msg("orders", r#"{"name":"test"}"#)]).await;
    let failure = verify(&r, r#"{"channel":"orders","payloadJsonPath":"missing.field","expectedValue":"test"}"#).await.expect("fails");
    assert!(failure.contains("found 0"), "{failure}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_handle_non_json_payload_gracefully() {
    let r = with_messages(vec![msg("events", "this is plain text, not json")]).await;
    let failure = verify(&r, r#"{"channel":"events","payloadJsonPath":"field","expectedValue":"value"}"#).await.expect("fails");
    assert!(failure.contains("found 0"), "{failure}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_handle_null_payload_message() {
    let r = with_messages(vec![ConsumedMessage::new("events", None, None, Vec::new())]).await;
    // A null payload is matched as the empty string.
    let failure = verify(&r, r#"{"channel":"events","payloadSubstring":"hello"}"#).await.expect("fails");
    assert!(failure.contains("found 0"), "{failure}");
    assert_eq!(verify(&r, r#"{"channel":"events"}"#).await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_default_to_at_least_one_when_no_count_specified() {
    let r = common::start(&[]).await;
    let failure = verify(&r, r#"{"channel":"orders"}"#).await.expect("fails");
    assert!(failure.contains("at least 1"), "{failure}");
}

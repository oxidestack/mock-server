//! `AsyncApiHttpExpectationGeneratorTest` (mockserver-async): `PUT /mockserver/asyncapi/http` on an in-process
//! server. The expectations `generate` returns are the ones the endpoint creates and answers (serialised as
//! `generateSerialized` serialises them); a rejected body is a 400 carrying upstream's `IllegalArgumentException`
//! message.

use serde_json::{Value, json};

use crate::common::{self, Running, send};

const SPEC: &str = r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "User Events", "version": "1.0.0" },
  "channels": {
    "user.signedup": {
      "publish": {
        "message": {
          "payload": {
            "type": "object",
            "properties": {
              "userId": { "type": "string" },
              "email": { "type": "string" }
            },
            "example": { "userId": "abc123", "email": "user@test.com" }
          }
        }
      }
    },
    "order/created": {
      "publish": {
        "message": {
          "payload": {
            "type": "object",
            "properties": { "orderId": { "type": "string" } }
          }
        }
      }
    }
  }
}"#;

/// `generate`: the created expectations.
async fn generate(r: &Running, body: &str) -> Vec<Value> {
    let response = send(r.port, "PUT", "/mockserver/asyncapi/http", body).await;
    assert_eq!(response.status, 201, "{}", response.body);
    serde_json::from_str::<Value>(&response.body).unwrap().as_array().unwrap().clone()
}

async fn rejected(r: &Running, body: &str) -> String {
    let response = send(r.port, "PUT", "/mockserver/asyncapi/http", body).await;
    assert_eq!(response.status, 400, "{}", response.body);
    serde_json::from_str::<Value>(&response.body).unwrap()["error"].as_str().unwrap().to_string()
}

fn by_path<'a>(expectations: &'a [Value], path: &str) -> &'a Value {
    expectations.iter().find(|e| e["httpRequest"]["path"] == path).unwrap_or_else(|| panic!("no expectation for path {path} in {expectations:?}"))
}

fn body_json(expectation: &Value) -> Value {
    serde_json::from_str(expectation["httpResponse"]["body"]["string"].as_str().unwrap()).unwrap()
}

// ---- AsyncApiHttpExpectationGeneratorTest ----

#[tokio::test(flavor = "multi_thread")]
async fn should_generate_one_get_expectation_per_channel() {
    let r = common::start(&[]).await;
    let expectations = generate(&r, SPEC).await;
    assert_eq!(expectations.len(), 2);

    let signed_up = by_path(&expectations, "/user/signedup");
    assert_eq!(signed_up["httpRequest"]["method"], "GET");
    assert_eq!(signed_up["httpResponse"]["statusCode"], 200);
    // The spec's explicit example is served verbatim.
    let body = body_json(signed_up);
    assert_eq!((body["userId"].as_str(), body["email"].as_str()), (Some("abc123"), Some("user@test.com")));
    let served = send(r.port, "GET", "/user/signedup", "").await;
    assert_eq!(served.status, 200);
    assert_eq!(serde_json::from_str::<Value>(&served.body).unwrap(), json!({"userId": "abc123", "email": "user@test.com"}));

    // A channel without an example gets one synthesised from its schema.
    assert!(body_json(by_path(&expectations, "/order/created")).get("orderId").is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn should_apply_channel_path_prefix_from_wrapper() {
    let r = common::start(&[]).await;
    let wrapped = format!(r#"{{"spec": {SPEC}, "channelPathPrefix": "/events"}}"#);
    let expectations = generate(&r, &wrapped).await;
    assert_eq!(expectations.len(), 2);
    assert_eq!(by_path(&expectations, "/events/user/signedup")["httpRequest"]["path"], "/events/user/signedup");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_serialize_to_expectation_json_array() {
    let r = common::start(&[]).await;
    let response = send(r.port, "PUT", "/mockserver/asyncapi/http", SPEC).await;
    let array: Value = serde_json::from_str(&response.body).unwrap();
    assert!(array.is_array());
    assert_eq!(array.as_array().unwrap().len(), 2);
    assert_eq!(array[0]["httpRequest"]["method"], "GET");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_blank_body() {
    let r = common::start(&[]).await;
    let error = rejected(&r, "  ").await;
    assert!(error.contains("AsyncAPI spec"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_malformed_spec() {
    let r = common::start(&[]).await;
    let error = rejected(&r, "this is not a spec at all: ::").await;
    assert!(error.contains("unable to parse AsyncAPI spec") || error.contains("no channels"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reject_spec_with_no_channels() {
    let r = common::start(&[]).await;
    let error = rejected(&r, r#"{"asyncapi":"2.6.0","info":{"title":"Empty","version":"1.0.0"},"channels":{}}"#).await;
    assert!(error.contains("no channels"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_disambiguate_colliding_channel_paths() {
    let r = common::start(&[]).await;
    // "a.b" and "a/b" both become /a/b: the second is made unique.
    let spec = concat!(
        r#"{"asyncapi":"2.6.0","info":{"title":"C","version":"1.0.0"},"channels":{"#,
        r#""a.b":{"publish":{"message":{"payload":{"type":"object"}}}},"a/b":{"publish":{"message":{"payload":{"type":"object"}}}}}}"#,
    );
    let expectations = generate(&r, spec).await;
    assert_eq!(expectations.len(), 2);
    let paths: Vec<&str> = expectations.iter().map(|e| e["httpRequest"]["path"].as_str().unwrap()).collect();
    assert!(paths.contains(&"/a/b") && paths.contains(&"/a/b/2"), "{paths:?}");
}

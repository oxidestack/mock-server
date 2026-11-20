//! `AsyncApiSchemaValidatorTest` and `AsyncApiFirstMessageExampleValidationTest` (mockserver-async): payloads checked
//! against a channel's schema, and the load-time `validationIssues` of `PUT /mockserver/asyncapi` (upstream calls
//! `AsyncApiControlPlaneImpl.load` and `status` directly; here an in-process server answers them).

use mock_server::asyncapi::spec::validate;
use serde_json::{Value, json};

use crate::common;

// ---- AsyncApiSchemaValidatorTest ----

#[test]
fn should_accept_valid_payload() {
    let schema = json!({"type": "object", "properties": {"name": {"type": "string"}, "age": {"type": "integer"}}, "required": ["name"]});
    assert_eq!(validate(Some(r#"{"name": "Alice", "age": 30}"#), Some(&schema)), None);
}

#[test]
fn should_reject_missing_required_field() {
    let schema = json!({"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]});
    let errors = validate(Some("{}"), Some(&schema)).expect("invalid");
    assert!(errors.contains("name"), "{errors}");
}

#[test]
fn should_reject_wrong_type() {
    let schema = json!({"type": "object", "properties": {"count": {"type": "integer"}}});
    assert!(validate(Some(r#"{"count": "not-a-number"}"#), Some(&schema)).is_some());
}

#[test]
fn should_accept_valid_enum() {
    let schema = json!({"type": "object", "properties": {"status": {"type": "string", "enum": ["active", "inactive"]}}});
    assert_eq!(validate(Some(r#"{"status": "active"}"#), Some(&schema)), None);
}

#[test]
fn should_reject_invalid_enum() {
    let schema = json!({"type": "object", "properties": {"status": {"type": "string", "enum": ["active", "inactive"]}}});
    assert!(validate(Some(r#"{"status": "unknown"}"#), Some(&schema)).is_some());
}

#[test]
fn should_accept_when_no_schema() {
    assert_eq!(validate(Some(r#"{"any": "thing"}"#), None), None);
}

#[test]
fn should_reject_null_payload() {
    assert_eq!(validate(None, Some(&json!({"type": "object"}))).as_deref(), Some("payload is null or blank"));
}

#[test]
fn should_reject_blank_payload() {
    assert_eq!(validate(Some("   "), Some(&json!({"type": "object"}))).as_deref(), Some("payload is null or blank"));
}

#[test]
fn should_validate_minimum() {
    let schema = json!({"type": "object", "properties": {"score": {"type": "integer", "minimum": 0, "maximum": 100}}});
    assert_eq!(validate(Some(r#"{"score": 50}"#), Some(&schema)), None);
    assert!(validate(Some(r#"{"score": -1}"#), Some(&schema)).is_some());
}

#[test]
fn should_validate_pattern() {
    let schema = json!({"type": "object", "properties": {"code": {"type": "string", "pattern": "^[A-Z]{3}$"}}});
    assert_eq!(validate(Some(r#"{"code": "ABC"}"#), Some(&schema)), None);
    assert!(validate(Some(r#"{"code": "abc"}"#), Some(&schema)).is_some());
}

// ---- AsyncApiFirstMessageExampleValidationTest ----

/// `controlPlane.load(spec)` on a fresh server (no brokers): the load response, and the server for `status`.
async fn load(spec: &str) -> (common::Running, Value) {
    let running = common::start(&[]).await;
    let r = common::send(running.port, "PUT", "/mockserver/asyncapi", spec).await;
    assert_eq!(r.status, 201, "loaded: {}", r.body);
    let result = serde_json::from_str(&r.body).expect("a JSON load response");
    (running, result)
}

/// `controlPlane.status()`.
async fn status(running: &common::Running) -> Value {
    let r = common::send(running.port, "GET", "/mockserver/asyncapi", "").await;
    assert_eq!(r.status, 200, "{}", r.body);
    serde_json::from_str(&r.body).expect("a JSON status")
}

fn issues(result: &Value) -> Vec<(String, String, String)> {
    let text = |issue: &Value, k: &str| issue[k].as_str().unwrap_or_default().to_string();
    result["validationIssues"].as_array().into_iter().flatten().map(|i| (text(i, "channel"), text(i, "context"), text(i, "errors"))).collect()
}

fn no_first_message_issue(result: &Value) {
    for (_, context, _) in issues(result) {
        assert!(!context.starts_with("first_message_example"), "unexpected {context} issue: {result}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_report_issue_when_first_example_conforms_to_schema() {
    let (_server, result) = load(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Valid Example", "version": "1.0.0" },
  "channels": {
    "orders": {
      "publish": {
        "message": {
          "payload": {
            "type": "object",
            "properties": {
              "orderId": { "type": "integer" },
              "name": { "type": "string" }
            },
            "required": ["orderId"]
          },
          "examples": [
            { "payload": { "orderId": 42, "name": "Widget" } }
          ]
        }
      }
    }
  }
}"#,
    )
    .await;
    assert_eq!(result["loaded"], json!(true));
    assert!(result.get("validationIssues").is_none(), "{result}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_report_issue_for_conforming_v3_example() {
    let (_server, result) = load(
        r#"{
  "asyncapi": "3.0.0",
  "info": { "title": "V3 Valid", "version": "1.0.0" },
  "channels": {
    "events": {
      "messages": {
        "eventMessage": {
          "payload": {
            "type": "object",
            "properties": {
              "eventType": { "type": "string" }
            },
            "required": ["eventType"]
          },
          "examples": [
            { "payload": { "eventType": "click" } }
          ]
        }
      }
    }
  }
}"#,
    )
    .await;
    assert_eq!(result["loaded"], json!(true));
    assert!(result.get("validationIssues").is_none(), "{result}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_report_issue_when_first_example_violates_schema() {
    let (_server, result) = load(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Bad Example", "version": "1.0.0" },
  "channels": {
    "orders": {
      "publish": {
        "message": {
          "payload": {
            "type": "object",
            "properties": {
              "orderId": { "type": "integer" }
            },
            "required": ["orderId"]
          },
          "examples": [
            { "payload": { "orderId": "not-an-integer" } }
          ]
        }
      }
    }
  }
}"#,
    )
    .await;
    assert_eq!(result["loaded"], json!(true));
    let found: Vec<_> = issues(&result).into_iter().filter(|(_, context, _)| context.starts_with("first_message_example")).collect();
    assert!(!found.is_empty(), "Expected a first_message_example validation issue: {result}");
    for (channel, _, errors) in found {
        assert_eq!(channel, "orders");
        assert!(!errors.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_report_issue_for_missing_required_field_in_example() {
    let (_server, result) = load(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Missing Required", "version": "1.0.0" },
  "channels": {
    "users": {
      "publish": {
        "message": {
          "payload": {
            "type": "object",
            "properties": {
              "name": { "type": "string" },
              "age": { "type": "integer" }
            },
            "required": ["name"]
          },
          "examples": [
            { "payload": { "age": 30 } }
          ]
        }
      }
    }
  }
}"#,
    )
    .await;
    assert_eq!(result["loaded"], json!(true));
    let found: Vec<_> =
        issues(&result).into_iter().filter(|(channel, context, _)| context.starts_with("first_message_example") && channel == "users").collect();
    assert!(!found.is_empty(), "Expected first_message_example issue for missing 'name': {result}");
    for (_, _, errors) in found {
        assert!(errors.contains("name"), "{errors}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_report_issue_in_status_after_load_with_bad_example() {
    let (server, _) = load(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Status Check", "version": "1.0.0" },
  "channels": {
    "metrics": {
      "publish": {
        "message": {
          "payload": {
            "type": "object",
            "properties": {
              "value": { "type": "number" }
            },
            "required": ["value"]
          },
          "examples": [
            { "payload": { "value": "not-a-number" } }
          ]
        }
      }
    }
  }
}"#,
    )
    .await;
    let status = status(&server).await;
    assert_eq!(status["loaded"], json!(true));
    assert!(
        issues(&status).iter().any(|(channel, context, _)| context.starts_with("first_message_example") && channel == "metrics"),
        "Expected first_message_example issue in status: {status}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn should_skip_validation_when_no_schema() {
    let (_server, result) = load(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "No Schema", "version": "1.0.0" },
  "channels": {
    "freeform": {
      "publish": {
        "message": {
          "examples": [
            { "payload": { "anything": true } }
          ]
        }
      }
    }
  }
}"#,
    )
    .await;
    assert_eq!(result["loaded"], json!(true));
    assert!(result.get("validationIssues").is_none(), "{result}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_skip_validation_when_no_examples() {
    let (_server, result) = load(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "No Examples", "version": "1.0.0" },
  "channels": {
    "schemaonly": {
      "publish": {
        "message": {
          "payload": {
            "type": "object",
            "properties": {
              "id": { "type": "integer" }
            }
          }
        }
      }
    }
  }
}"#,
    )
    .await;
    assert_eq!(result["loaded"], json!(true));
    no_first_message_issue(&result);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_skip_validation_when_neither_schema_nor_examples() {
    let (_server, result) = load(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Bare Channel", "version": "1.0.0" },
  "channels": {
    "empty": {
      "publish": {
        "message": {}
      }
    }
  }
}"#,
    )
    .await;
    assert_eq!(result["loaded"], json!(true));
    assert!(result.get("validationIssues").is_none(), "{result}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_validate_first_example_of_each_message_in_multi_message_channel() {
    let (_server, result) = load(
        r#"{
  "asyncapi": "3.0.0",
  "info": { "title": "Multi-Msg", "version": "1.0.0" },
  "channels": {
    "events": {
      "messages": {
        "goodMessage": {
          "payload": {
            "type": "object",
            "properties": { "count": { "type": "integer" } },
            "required": ["count"]
          },
          "examples": [
            { "payload": { "count": 10 } }
          ]
        },
        "badMessage": {
          "payload": {
            "type": "object",
            "properties": { "count": { "type": "integer" } },
            "required": ["count"]
          },
          "examples": [
            { "payload": { "count": "not-a-number" } }
          ]
        }
      }
    }
  }
}"#,
    )
    .await;
    assert_eq!(result["loaded"], json!(true));
    let issues = issues(&result);
    let bad: Vec<_> = issues.iter().filter(|(_, context, _)| context == "first_message_example:badMessage").collect();
    assert!(!bad.is_empty(), "Expected issue for badMessage: {result}");
    assert!(bad.iter().all(|(channel, _, _)| channel == "events"));
    assert!(!issues.iter().any(|(_, context, _)| context == "first_message_example:goodMessage"), "Should NOT have issue for goodMessage: {result}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_hard_fail_load_on_example_validation_issue() {
    let (_server, result) = load(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Soft Fail", "version": "1.0.0" },
  "channels": {
    "ch1": {
      "publish": {
        "message": {
          "payload": {
            "type": "object",
            "properties": {
              "active": { "type": "boolean" }
            },
            "required": ["active"]
          },
          "examples": [
            { "payload": { "active": "yes" } }
          ]
        }
      }
    }
  }
}"#,
    )
    .await;
    assert_eq!(result["loaded"], json!(true));
    assert_eq!(result["channelCount"].as_i64(), Some(1));
    assert!(result.get("validationIssues").is_some(), "{result}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_validate_only_first_example_not_subsequent() {
    let (_server, result) = load(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "First Only", "version": "1.0.0" },
  "channels": {
    "data": {
      "publish": {
        "message": {
          "payload": {
            "type": "object",
            "properties": {
              "score": { "type": "integer" }
            },
            "required": ["score"]
          },
          "examples": [
            { "payload": { "score": 100 } },
            { "payload": { "score": "bad" } }
          ]
        }
      }
    }
  }
}"#,
    )
    .await;
    assert_eq!(result["loaded"], json!(true));
    no_first_message_issue(&result);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_include_message_name_in_context_for_v3_multi_message() {
    let (_server, result) = load(
        r#"{
  "asyncapi": "3.0.0",
  "info": { "title": "Named Msg", "version": "1.0.0" },
  "channels": {
    "notifications": {
      "messages": {
        "alertMessage": {
          "payload": {
            "type": "object",
            "properties": { "level": { "type": "integer" } },
            "required": ["level"]
          },
          "examples": [
            { "payload": { "level": "high" } }
          ]
        },
        "infoMessage": {
          "payload": {
            "type": "object",
            "properties": { "text": { "type": "string" } }
          },
          "examples": [
            { "payload": { "text": "hello" } }
          ]
        }
      }
    }
  }
}"#,
    )
    .await;
    let found: Vec<_> = issues(&result).into_iter().filter(|(_, context, _)| context == "first_message_example:alertMessage").collect();
    assert!(!found.is_empty(), "Expected context with message name 'alertMessage': {result}");
    assert!(found.iter().all(|(channel, _, _)| channel == "notifications"));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_use_plain_context_for_single_message_channel() {
    let (_server, result) = load(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Single Msg", "version": "1.0.0" },
  "channels": {
    "orders": {
      "publish": {
        "message": {
          "payload": {
            "type": "object",
            "properties": { "id": { "type": "integer" } },
            "required": ["id"]
          },
          "examples": [
            { "payload": { "id": "not-integer" } }
          ]
        }
      }
    }
  }
}"#,
    )
    .await;
    let found: Vec<_> = issues(&result).into_iter().filter(|(_, context, _)| context == "first_message_example").collect();
    assert!(!found.is_empty(), "Expected plain 'first_message_example' context for unnamed message: {result}");
    assert!(found.iter().all(|(channel, _, _)| channel == "orders"));
}

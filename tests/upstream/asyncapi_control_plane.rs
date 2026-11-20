//! `AsyncApiControlPlaneImplTest` (mockserver-async): the AsyncAPI control plane driven over HTTP on an in-process
//! server, as the oracle is (`PUT`/`GET /mockserver/asyncapi`, a reset through `PUT /mockserver/reset`). Where
//! upstream calls `load("")`, which no HTTP request reaches (the route answers an empty body itself), the port calls
//! [`AsyncApi::load`](mock_server::asyncapi::AsyncApi::load) directly.
//!
//! Also here: each server keeps its own AsyncAPI state, and stopping a server closes and unloads it.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use mock_server::asyncapi::AsyncApi;
use serde_json::{Value, json};

use crate::asyncapi_stubs::StubSubscriber;
use crate::asyncapi_verify::{msg, verify};
use crate::common::{self, Running, send};

async fn load(r: &Running, body: &str) -> (u16, Value) {
    let response = send(r.port, "PUT", "/mockserver/asyncapi", body).await;
    (response.status, serde_json::from_str(&response.body).unwrap_or(Value::String(response.body)))
}

/// `load` that must succeed.
async fn loaded(r: &Running, body: &str) -> Value {
    let (status, result) = load(r, body).await;
    assert_eq!(status, 201, "{result}");
    result
}

async fn status(r: &Running) -> Value {
    let response = send(r.port, "GET", "/mockserver/asyncapi", "").await;
    assert_eq!(response.status, 200);
    serde_json::from_str(&response.body).unwrap()
}

fn one_channel(title: &str, channel: &str, payload_type: &str) -> String {
    json!({
        "asyncapi": "2.6.0",
        "info": {"title": title, "version": "1.0.0"},
        "channels": {channel: {"publish": {"message": {"payload": {"type": payload_type}}}}}
    })
    .to_string()
}

// ---- AsyncApiControlPlaneImplTest ----

#[tokio::test(flavor = "multi_thread")]
async fn should_return_empty_status_when_no_spec_loaded() {
    let r = common::start(&[]).await;
    let status = status(&r).await;
    assert_eq!(status["loaded"], false);
    assert_eq!(status["channels"].as_array().unwrap().len(), 0);
    assert_eq!(status["publishers"], 0);
    assert_eq!(status["subscribers"], 0);
    assert_eq!(status["recordedMessages"].as_array().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_load_spec_without_broker_config() {
    let r = common::start(&[]).await;
    let spec = r#"{
      "asyncapi": "2.6.0",
      "info": { "title": "Test API", "version": "1.0.0" },
      "channels": {
        "user/signedup": {
          "publish": {
            "message": {
              "payload": {
                "type": "object",
                "properties": {
                  "userId": { "type": "string" },
                  "email": { "type": "string" }
                }
              }
            }
          }
        }
      }
    }"#;
    let result = loaded(&r, spec).await;
    assert_eq!(result["loaded"], true);
    assert_eq!(result["specTitle"], "Test API");
    assert_eq!(result["specVersion"], "2.6.0");
    assert_eq!(result["channelCount"], 1);
    assert_eq!(result["channels"][0]["name"], "user/signedup");
    assert_eq!(result["publishers"], 0);
    assert_eq!(result["subscribers"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_return_status_after_load() {
    let r = common::start(&[]).await;
    let spec = r#"{
      "asyncapi": "2.6.0",
      "info": { "title": "Status Test", "version": "1.0.0" },
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
              }
            }
          }
        },
        "events": {
          "subscribe": {
            "message": {
              "payload": { "type": "string" }
            }
          }
        }
      }
    }"#;
    loaded(&r, spec).await;
    let status = status(&r).await;
    assert_eq!(status["loaded"], true);
    assert_eq!(status["specTitle"], "Status Test");
    let channels = status["channels"].as_array().unwrap();
    assert_eq!(channels.len(), 2);
    for name in ["orders", "events"] {
        let channel = channels.iter().find(|c| c["name"] == name).unwrap_or_else(|| panic!("channel {name} in {status}"));
        assert_eq!(channel["hasSchema"], true, "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reset_state() {
    let r = common::start(&[]).await;
    loaded(&r, &one_channel("Reset Test", "test-channel", "string")).await;
    assert_eq!(status(&r).await["loaded"], true);

    assert_eq!(send(r.port, "PUT", "/mockserver/reset", "").await.status, 200);
    let status = status(&r).await;
    assert_eq!(status["loaded"], false);
    assert_eq!(status["channels"].as_array().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_load_spec_from_wrapped_body() {
    let r = common::start(&[]).await;
    let wrapped = r#"{
      "spec": {
        "asyncapi": "2.6.0",
        "info": { "title": "Wrapped", "version": "1.0.0" },
        "channels": {
          "wrapped-channel": {
            "publish": {
              "message": {
                "payload": { "type": "string" }
              }
            }
          }
        }
      },
      "brokerConfig": {}
    }"#;
    let result = loaded(&r, wrapped).await;
    assert_eq!(result["loaded"], true);
    assert_eq!(result["specTitle"], "Wrapped");
    assert_eq!(result["channelCount"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_handle_invalid_spec() {
    let r = common::start(&[]).await;
    // A valid but empty spec loads with no channels.
    let result = loaded(&r, r#"{"asyncapi": "2.6.0"}"#).await;
    assert_eq!(result["loaded"], true);
    assert_eq!(result["channelCount"], 0);
}

#[test]
fn should_throw_on_empty_body() {
    let error = AsyncApi::default().load("", &mock_server::Config::for_tests()).unwrap_err();
    assert!(error.starts_with("Failed to load AsyncAPI spec"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_load_yaml_spec() {
    let r = common::start(&[]).await;
    let yaml = "asyncapi: '2.6.0'\n\
                info:\n  title: YAML Spec\n  version: '1.0.0'\n\
                channels:\n  yaml-topic:\n    publish:\n      message:\n        payload:\n          type: object\
                \n          properties:\n            name:\n              type: string\n";
    let result = loaded(&r, yaml).await;
    assert_eq!(result["loaded"], true);
    assert_eq!(result["specTitle"], "YAML Spec");
    assert_eq!(result["channels"][0]["name"], "yaml-topic");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_load_async_api3x_spec() {
    let r = common::start(&[]).await;
    let spec = r#"{
      "asyncapi": "3.0.0",
      "info": { "title": "V3 API", "version": "1.0.0" },
      "channels": {
        "notifications": {
          "messages": {
            "notifyMessage": {
              "payload": {
                "type": "object",
                "properties": {
                  "text": { "type": "string" }
                }
              }
            }
          }
        }
      }
    }"#;
    let result = loaded(&r, spec).await;
    assert_eq!(result["loaded"], true);
    assert_eq!(result["specVersion"], "3.0.0");
    assert_eq!(result["channels"][0]["name"], "notifications");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reload_spec_replacing_previous() {
    let r = common::start(&[]).await;
    loaded(&r, &one_channel("First", "ch1", "string")).await;
    assert_eq!(status(&r).await["specTitle"], "First");

    let second = json!({
        "asyncapi": "2.6.0",
        "info": {"title": "Second", "version": "2.0.0"},
        "channels": {"ch2": {"publish": {"message": {"payload": {"type": "integer"}}}}}
    });
    loaded(&r, &second.to_string()).await;
    let status = status(&r).await;
    assert_eq!(status["specTitle"], "Second");
    assert_eq!(status["channels"][0]["name"], "ch2");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_throw_on_failure_and_clean_up_partial_state() {
    let r = common::start(&[]).await;
    let wrapped = json!({
        "spec": serde_json::from_str::<Value>(&one_channel("Partial Fail", "ch1", "string")).unwrap(),
        "brokerConfig": {"mqttBrokerUrl": "tcp://localhost:19999"}
    });
    // `load` throws a RuntimeException ("Failed to load AsyncAPI spec: …"): a fault, which the control plane answers
    // 500 with the correlation-id message since the re-pin (`HttpState.handleAsyncApiPut`)
    let (code, result) = load(&r, &wrapped.to_string()).await;
    assert_eq!(code, 500, "the connection to an unreachable MQTT broker fails the load");
    assert!(result["error"].as_str().unwrap().starts_with("unexpected error processing request, see the MockServer log for correlation id: "), "{result}");
    let direct = AsyncApi::default().load_classified(&wrapped.to_string(), &mock_server::Config::for_tests()).expect_err("the load fails");
    assert!(direct.message.contains("Failed to load AsyncAPI spec"), "{}", direct.message);
    assert!(!direct.client, "a broker connection that failed is no client error");

    let status = status(&r).await;
    assert_eq!(status["loaded"], false);
    assert_eq!(status["publishers"], 0);
    assert_eq!(status["subscribers"], 0);
}

#[test]
fn load_failure_should_throw_runtime_exception() {
    let result = AsyncApi::default().load("", &mock_server::Config::for_tests());
    let error = result.expect_err("load() should fail on an empty body");
    assert!(error.contains("Failed to load AsyncAPI spec"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_fall_back_to_config_default_kafka_bootstrap_servers() {
    // `localhost` resolves; nothing listens, but a Kafka publisher connects only when it first sends.
    let r = common::start(&[("asyncKafkaBootstrapServers", "localhost:19999")]).await;
    let wrapped = json!({
        "spec": serde_json::from_str::<Value>(&one_channel("Fallback Test", "test", "string")).unwrap(),
        "brokerConfig": {"publishOnLoad": false}
    });
    let result = loaded(&r, &wrapped.to_string()).await;
    assert_eq!(result["loaded"], true);
    assert_eq!(result["publishers"], 1, "a Kafka publisher is made from the configured default");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_prefer_request_body_kafka_over_config_default() {
    let r = common::start(&[("asyncKafkaBootstrapServers", "localhost:29999")]).await;
    let wrapped = json!({
        "spec": serde_json::from_str::<Value>(&one_channel("Override Test", "test", "string")).unwrap(),
        "brokerConfig": {"kafkaBootstrapServers": "localhost:19999", "publishOnLoad": false}
    });
    let result = loaded(&r, &wrapped.to_string()).await;
    assert_eq!(result["loaded"], true);
    assert_eq!(result["publishers"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_use_async_recorded_message_max_entries_from_config() {
    let config = mock_server::Config::for_tests().with_property("asyncRecordedMessageMaxEntries", "42");
    assert_eq!(mock_server::asyncapi::recorded_message_max_entries(&config), 42);

    let r = common::start(&[("asyncRecordedMessageMaxEntries", "42")]).await;
    let result = loaded(&r, &one_channel("Max Entries Test", "ch1", "string")).await;
    assert_eq!(result["loaded"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_no_brokers_when_no_config_default_and_no_request_config() {
    let r = common::start(&[("asyncKafkaBootstrapServers", ""), ("asyncMqttBrokerUrl", "")]).await;
    let result = loaded(&r, &one_channel("No Broker", "ch1", "string")).await;
    assert_eq!(result["loaded"], true);
    assert_eq!(result["publishers"], 0);
    assert_eq!(result["subscribers"], 0);
}

// ---- mock-server: per-server AsyncAPI state ----

#[tokio::test(flavor = "multi_thread")]
async fn each_server_keeps_its_own_asyncapi_state() {
    let (a, b) = (common::start(&[]).await, common::start(&[]).await);
    loaded(&a, &one_channel("Server A", "a-channel", "string")).await;
    assert_eq!(status(&b).await["loaded"], false, "a load on one server leaves the other unloaded");
    loaded(&b, &one_channel("Server B", "b-channel", "string")).await;
    b.server.asyncapi().add_subscriber_for_testing(Arc::new(StubSubscriber::with(vec![msg("b-channel", "hello")])));

    let (status_a, status_b) = (status(&a).await, status(&b).await);
    assert_eq!((status_a["specTitle"].as_str(), status_b["specTitle"].as_str()), (Some("Server A"), Some("Server B")));
    assert_eq!(status_a["recordedMessages"].as_array().unwrap().len(), 0);
    assert_eq!(status_b["recordedMessages"][0]["payload"], "hello");
    assert!(verify(&a, r#"{"channel":"b-channel"}"#).await.is_some(), "server A has no subscriber");
    assert_eq!(verify(&b, r#"{"channel":"b-channel"}"#).await, None);

    assert_eq!(send(a.port, "PUT", "/mockserver/reset", "").await.status, 200);
    assert_eq!(status(&a).await["loaded"], false);
    assert_eq!(status(&b).await["specTitle"], "Server B", "a reset of one server leaves the other loaded");
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_the_server_closes_and_unloads_asyncapi() {
    let r = common::start(&[]).await;
    loaded(&r, &one_channel("Stopping", "events", "string")).await;
    let subscriber = Arc::new(StubSubscriber::with(vec![msg("events", "a")]));
    r.server.asyncapi().add_subscriber_for_testing(subscriber.clone());
    assert_eq!(status(&r).await["subscribers"], 1);

    r.server.stop_async().await.unwrap();
    assert_eq!(subscriber.closes.load(Ordering::SeqCst), 1, "stopping closes the subscribers");
    let status = r.server.asyncapi().status();
    assert_eq!(status["loaded"], false, "{status}");
    assert_eq!(status["subscribers"], 0);
    assert_eq!(status["recordedMessages"].as_array().unwrap().len(), 0);
}

//! `AsyncApiParserTest` and `AmqpBindingParserTest` (mockserver-async): `AsyncApiParser` over AsyncAPI 2.x and 3.x
//! documents, its bindings, multi-message channels and correlation ids.

use mock_server::asyncapi::broker::PublishOptions;
use mock_server::asyncapi::spec::{AmqpBinding, AmqpChannelType, Channel, Spec, parse};
use serde_json::json;

fn parsed(document: &str) -> Spec {
    parse(document).expect("the document parses")
}

fn first(document: &str) -> Channel {
    parsed(document).channels.remove(0)
}

fn amqp(document: &str) -> AmqpBinding {
    first(document).amqp_binding.expect("an AMQP binding")
}

/// A document's first channel's `getMessages()`.
fn message_correlation_ids(document: &str) -> Vec<Option<String>> {
    first(document).messages().into_iter().map(|m| m.correlation_id_location).collect()
}

/// Not an upstream test: the numeric Kafka key (`asText()` of a number) and a published example's double as
/// Jackson prints it.
#[test]
fn kafka_key_numbers_and_example_doubles_print_as_jackson_does() {
    let c = first(
        r#"{"asyncapi":"2.6.0","channels":{"c":{"publish":{"message":{
  "bindings":{"kafka":{"key":42}},
  "payload":{"type":"object","example":{"n":1.50}}
}}}}}"#,
    );
    assert_eq!(c.kafka_key.as_deref(), Some("42"));
    assert_eq!(c.example(), r#"{"n":1.5}"#);
}

// ---- AsyncApiParserTest ----

#[test]
fn should_parse_async_api2x_with_explicit_example() {
    let spec = parsed(
        r#"{
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
            },
            "example": { "userId": "abc123", "email": "user@test.com" }
          }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(spec.version.as_deref(), Some("2.6.0"));
    assert_eq!(spec.title.as_deref(), Some("Test API"));
    assert_eq!(spec.channels.len(), 1);
    let channel = &spec.channels[0];
    assert_eq!(channel.name, "user/signedup");
    assert_eq!(channel.examples.len(), 1);
    assert_eq!(channel.examples[0]["userId"], json!("abc123"));
    assert_eq!(channel.examples[0]["email"], json!("user@test.com"));
    assert!(channel.payload_schema.is_some());
}

#[test]
fn should_parse_async_api2x_with_message_examples_array() {
    let spec = parsed(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Events", "version": "1.0.0" },
  "channels": {
    "orders": {
      "subscribe": {
        "message": {
          "payload": {
            "type": "object",
            "properties": {
              "orderId": { "type": "integer" }
            }
          },
          "examples": [
            { "payload": { "orderId": 42 } },
            { "payload": { "orderId": 99 } }
          ]
        }
      }
    }
  }
}"#,
    );
    assert_eq!(spec.channels.len(), 1);
    let channel = &spec.channels[0];
    assert_eq!(channel.name, "orders");
    assert_eq!(channel.examples.len(), 2);
    assert_eq!(channel.examples[0]["orderId"].as_i64(), Some(42));
    assert_eq!(channel.examples[1]["orderId"].as_i64(), Some(99));
}

#[test]
fn should_parse_async_api2x_with_multiple_channels() {
    let spec = parsed(
        r#"{
  "asyncapi": "2.0.0",
  "info": { "title": "Multi", "version": "1.0.0" },
  "channels": {
    "topic-a": {
      "publish": {
        "message": {
          "payload": {
            "type": "string",
            "example": "hello"
          }
        }
      }
    },
    "topic-b": {
      "publish": {
        "message": {
          "payload": { "type": "integer" }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(spec.channels.len(), 2);
}

#[test]
fn should_parse_async_api2x_yaml() {
    let spec = parsed(
        "asyncapi: '2.6.0'
info:
  title: YAML Test
  version: '1.0.0'
channels:
  events:
    publish:
      message:
        payload:
          type: object
          properties:
            name:
              type: string
          example:
            name: test-event
",
    );
    assert_eq!(spec.version.as_deref(), Some("2.6.0"));
    assert_eq!(spec.title.as_deref(), Some("YAML Test"));
    assert_eq!(spec.channels.len(), 1);
    assert_eq!(spec.channels[0].examples.len(), 1);
    assert_eq!(spec.channels[0].examples[0]["name"], json!("test-event"));
}

#[test]
fn should_tolerate_channel_with_no_message() {
    let spec = parsed(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Empty", "version": "1.0.0" },
  "channels": {
    "empty-channel": {}
  }
}"#,
    );
    assert_eq!(spec.channels.len(), 1);
    assert_eq!(spec.channels[0].name, "empty-channel");
    assert!(spec.channels[0].examples.is_empty());
}

#[test]
fn should_parse_async_api3x_with_inline_message() {
    let spec = parsed(
        r#"{
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
          },
          "examples": [
            { "payload": { "text": "Hello World" } }
          ]
        }
      }
    }
  }
}"#,
    );
    assert_eq!(spec.version.as_deref(), Some("3.0.0"));
    assert_eq!(spec.channels.len(), 1);
    let channel = &spec.channels[0];
    assert_eq!(channel.name, "notifications");
    assert_eq!(channel.examples.len(), 1);
    assert_eq!(channel.examples[0]["text"], json!("Hello World"));
}

#[test]
fn should_parse_async_api3x_with_ref_to_components_messages() {
    let spec = parsed(
        r##"{
  "asyncapi": "3.0.0",
  "info": { "title": "Ref API", "version": "1.0.0" },
  "channels": {
    "alerts": {
      "messages": {
        "alertMsg": { "$ref": "#/components/messages/AlertMessage" }
      }
    }
  },
  "components": {
    "messages": {
      "AlertMessage": {
        "payload": {
          "type": "object",
          "properties": {
            "severity": { "type": "string" }
          }
        },
        "examples": [
          { "payload": { "severity": "high" } }
        ]
      }
    }
  }
}"##,
    );
    assert_eq!(spec.channels.len(), 1);
    let channel = &spec.channels[0];
    assert_eq!(channel.name, "alerts");
    assert_eq!(channel.examples.len(), 1);
    assert_eq!(channel.examples[0]["severity"], json!("high"));
}

#[test]
fn should_parse_v2_mqtt_bindings_qos_and_retain() {
    let spec = parsed(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "MQTT", "version": "1.0.0" },
  "channels": {
    "sensors/temp": {
      "publish": {
        "bindings": {
          "mqtt": { "qos": 2, "retain": true }
        },
        "message": {
          "payload": { "type": "object" }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(spec.channels.len(), 1);
    let channel = &spec.channels[0];
    assert_eq!(channel.mqtt_qos, Some(2));
    assert_eq!(channel.mqtt_retain, Some(true));
    assert_eq!(channel.kafka_key, None);
}

#[test]
fn should_parse_v2_kafka_key_literal() {
    let channel = first(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Kafka", "version": "1.0.0" },
  "channels": {
    "orders": {
      "publish": {
        "message": {
          "bindings": {
            "kafka": { "key": "order-key-123" }
          },
          "payload": { "type": "object" }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(channel.kafka_key.as_deref(), Some("order-key-123"));
    assert_eq!(channel.mqtt_qos, None);
    assert_eq!(channel.mqtt_retain, None);
}

/// A v2 channel `events` whose message's `bindings.kafka.key` is `key`.
fn kafka_key_document(key: &str) -> String {
    format!(
        r#"{{
  "asyncapi": "2.6.0",
  "info": {{ "title": "Kafka", "version": "1.0.0" }},
  "channels": {{
    "events": {{
      "publish": {{
        "message": {{
          "bindings": {{
            "kafka": {{
              "key": {key}
            }}
          }},
          "payload": {{ "type": "object" }}
        }}
      }}
    }}
  }}
}}"#
    )
}

#[test]
fn should_parse_v2_kafka_key_from_schema_const() {
    let channel = first(&kafka_key_document(r#"{ "type": "string", "const": "fixed-key" }"#));
    assert_eq!(channel.kafka_key.as_deref(), Some("fixed-key"));
}

#[test]
fn should_parse_v2_kafka_key_from_schema_example() {
    let channel = first(&kafka_key_document(r#"{ "type": "string", "example": "ex-key" }"#));
    assert_eq!(channel.kafka_key.as_deref(), Some("ex-key"));
}

#[test]
fn should_parse_v2_kafka_key_from_schema_examples_array() {
    let channel = first(&kafka_key_document(r#"{ "type": "string", "examples": ["first-key", "second-key"] }"#));
    assert_eq!(channel.kafka_key.as_deref(), Some("first-key"));
}

#[test]
fn should_return_null_kafka_key_for_bare_schema() {
    let channel = first(&kafka_key_document(r#"{ "type": "string" }"#));
    assert_eq!(channel.kafka_key, None);
}

#[test]
fn should_return_null_bindings_when_absent() {
    let channel = first(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "No bindings", "version": "1.0.0" },
  "channels": {
    "topic": {
      "publish": {
        "message": {
          "payload": { "type": "object" }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(channel.mqtt_qos, None);
    assert_eq!(channel.mqtt_retain, None);
    assert_eq!(channel.kafka_key, None);
}

#[test]
fn should_ignore_malformed_mqtt_binding() {
    // qos is a string instead of int, retain is a number instead of boolean
    let channel = first(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Malformed", "version": "1.0.0" },
  "channels": {
    "topic": {
      "publish": {
        "bindings": {
          "mqtt": { "qos": "bad", "retain": 42 }
        },
        "message": {
          "payload": { "type": "object" }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(channel.mqtt_qos, None);
    assert_eq!(channel.mqtt_retain, None);
}

#[test]
fn should_ignore_out_of_range_mqtt_qos() {
    let channel = first(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "OOR", "version": "1.0.0" },
  "channels": {
    "topic": {
      "publish": {
        "bindings": {
          "mqtt": { "qos": 5 }
        },
        "message": {
          "payload": { "type": "object" }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(channel.mqtt_qos, None);
}

#[test]
fn should_parse_v3_kafka_key_from_message() {
    let channel = first(
        r#"{
  "asyncapi": "3.0.0",
  "info": { "title": "V3 Kafka", "version": "1.0.0" },
  "channels": {
    "orders": {
      "messages": {
        "orderMsg": {
          "bindings": {
            "kafka": { "key": "v3-key" }
          },
          "payload": { "type": "object" }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(channel.kafka_key.as_deref(), Some("v3-key"));
}

#[test]
fn should_parse_v3_channel_level_mqtt_bindings() {
    // v3 best-effort: channel-level bindings.mqtt
    let channel = first(
        r#"{
  "asyncapi": "3.0.0",
  "info": { "title": "V3 MQTT", "version": "1.0.0" },
  "channels": {
    "sensors/temp": {
      "bindings": {
        "mqtt": { "qos": 1, "retain": false }
      },
      "messages": {
        "tempMsg": {
          "payload": { "type": "object" }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(channel.mqtt_qos, Some(1));
    assert_eq!(channel.mqtt_retain, Some(false));
}

#[test]
fn should_return_null_v3_mqtt_bindings_when_only_on_operations() {
    // v3 operation-level bindings are NOT navigated (documented limitation)
    let channel = first(
        r##"{
  "asyncapi": "3.0.0",
  "info": { "title": "V3 ops", "version": "1.0.0" },
  "channels": {
    "sensors/temp": {
      "messages": {
        "tempMsg": {
          "payload": { "type": "object" }
        }
      }
    }
  },
  "operations": {
    "publishTemp": {
      "channel": { "$ref": "#/channels/sensors~1temp" },
      "bindings": {
        "mqtt": { "qos": 2, "retain": true }
      }
    }
  }
}"##,
    );
    assert_eq!(channel.mqtt_qos, None);
    assert_eq!(channel.mqtt_retain, None);
}

#[test]
fn channel_to_publish_options_should_carry_bindings() {
    let channel = first(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Both", "version": "1.0.0" },
  "channels": {
    "topic": {
      "publish": {
        "bindings": { "mqtt": { "qos": 0, "retain": true } },
        "message": {
          "bindings": { "kafka": { "key": "k1" } },
          "payload": { "type": "object" }
        }
      }
    }
  }
}"#,
    );
    let options = channel.to_publish_options();
    assert_ne!(options, PublishOptions::none(), "not empty");
    assert_eq!(options.key.as_deref(), Some("k1"));
    assert_eq!(options.qos, Some(0));
    assert_eq!(options.retain, Some(true));
}

#[test]
fn channel_to_publish_options_should_return_none_when_no_bindings() {
    let channel = first(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "None", "version": "1.0.0" },
  "channels": {
    "topic": {
      "publish": {
        "message": { "payload": { "type": "object" } }
      }
    }
  }
}"#,
    );
    assert_eq!(channel.to_publish_options(), PublishOptions::none(), "empty");
}

#[test]
fn should_parse_v3_channel_with_multiple_messages() {
    let spec = parsed(
        r#"{
  "asyncapi": "3.0.0",
  "info": { "title": "Multi-Message V3", "version": "1.0.0" },
  "channels": {
    "events": {
      "messages": {
        "userCreated": {
          "payload": {
            "type": "object",
            "properties": { "userId": { "type": "string" } }
          },
          "examples": [{ "payload": { "userId": "u1" } }],
          "bindings": { "kafka": { "key": "user-key" } }
        },
        "orderPlaced": {
          "payload": {
            "type": "object",
            "properties": { "orderId": { "type": "integer" } }
          },
          "examples": [{ "payload": { "orderId": 42 } }],
          "bindings": { "kafka": { "key": "order-key" } }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(spec.channels.len(), 1);
    let channel = &spec.channels[0];
    assert_eq!(channel.name, "events");

    let messages = channel.messages();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].name.as_deref(), Some("userCreated"));
    assert_eq!(messages[0].examples.len(), 1);
    assert_eq!(messages[0].examples[0]["userId"], json!("u1"));
    assert_eq!(messages[0].kafka_key.as_deref(), Some("user-key"));
    assert_eq!(messages[1].name.as_deref(), Some("orderPlaced"));
    assert_eq!(messages[1].examples.len(), 1);
    assert_eq!(messages[1].examples[0]["orderId"].as_i64(), Some(42));
    assert_eq!(messages[1].kafka_key.as_deref(), Some("order-key"));

    // Back-compat: legacy accessors reflect the FIRST message
    assert_eq!(channel.examples.len(), 1);
    assert_eq!(channel.examples[0]["userId"], json!("u1"));
    assert_eq!(channel.kafka_key.as_deref(), Some("user-key"));
    assert!(channel.payload_schema.is_some());
}

#[test]
fn should_parse_v3_single_message_channel_get_messages_returns_one() {
    let channel = first(
        r#"{
  "asyncapi": "3.0.0",
  "info": { "title": "Single V3", "version": "1.0.0" },
  "channels": {
    "topic": {
      "messages": {
        "singleMsg": {
          "payload": { "type": "object" },
          "examples": [{ "payload": { "a": 1 } }]
        }
      }
    }
  }
}"#,
    );
    // Single message — getMessages() synthesizes from channel fields
    let messages = channel.messages();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].examples.len(), 1);
    assert_eq!(messages[0].examples[0]["a"].as_i64(), Some(1));
    assert_eq!(channel.examples.len(), 1);
}

#[test]
fn should_parse_v3_multi_message_with_ref() {
    let channel = first(
        r##"{
  "asyncapi": "3.0.0",
  "info": { "title": "Ref Multi", "version": "1.0.0" },
  "channels": {
    "alerts": {
      "messages": {
        "alert1": { "$ref": "#/components/messages/AlertA" },
        "alert2": {
          "payload": { "type": "object", "properties": { "level": { "type": "integer" } } },
          "examples": [{ "payload": { "level": 5 } }]
        }
      }
    }
  },
  "components": {
    "messages": {
      "AlertA": {
        "payload": { "type": "object", "properties": { "severity": { "type": "string" } } },
        "examples": [{ "payload": { "severity": "high" } }]
      }
    }
  }
}"##,
    );
    let messages = channel.messages();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].examples[0]["severity"], json!("high"));
    assert_eq!(messages[1].examples[0]["level"].as_i64(), Some(5));
}

#[test]
fn should_parse_v2_channel_with_one_of_multi_message() {
    let spec = parsed(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "OneOf V2", "version": "1.0.0" },
  "channels": {
    "events": {
      "publish": {
        "message": {
          "oneOf": [
            {
              "name": "UserEvent",
              "payload": {
                "type": "object",
                "properties": { "user": { "type": "string" } },
                "example": { "user": "alice" }
              },
              "bindings": { "kafka": { "key": "user-k" } }
            },
            {
              "name": "OrderEvent",
              "payload": {
                "type": "object",
                "properties": { "orderId": { "type": "integer" } },
                "example": { "orderId": 99 }
              },
              "bindings": { "kafka": { "key": "order-k" } }
            }
          ]
        }
      }
    }
  }
}"#,
    );
    assert_eq!(spec.channels.len(), 1);
    let channel = &spec.channels[0];
    assert_eq!(channel.name, "events");

    let messages = channel.messages();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].name.as_deref(), Some("UserEvent"));
    assert_eq!(messages[0].examples.len(), 1);
    assert_eq!(messages[0].examples[0]["user"], json!("alice"));
    assert_eq!(messages[0].kafka_key.as_deref(), Some("user-k"));
    assert_eq!(messages[1].name.as_deref(), Some("OrderEvent"));
    assert_eq!(messages[1].examples.len(), 1);
    assert_eq!(messages[1].examples[0]["orderId"].as_i64(), Some(99));
    assert_eq!(messages[1].kafka_key.as_deref(), Some("order-k"));

    // Back-compat: legacy accessors reflect the FIRST oneOf entry
    assert_eq!(channel.examples.len(), 1);
    assert_eq!(channel.examples[0]["user"], json!("alice"));
    assert_eq!(channel.kafka_key.as_deref(), Some("user-k"));
}

#[test]
fn should_parse_v2_single_message_no_one_of_get_messages_returns_one() {
    let channel = first(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Single V2", "version": "1.0.0" },
  "channels": {
    "topic": {
      "publish": {
        "message": {
          "payload": { "type": "object", "example": { "x": 1 } }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(channel.messages().len(), 1);
    assert_eq!(channel.examples.len(), 1);
    assert_eq!(channel.examples[0]["x"].as_i64(), Some(1));
}

#[test]
fn should_parse_v2_one_of_with_mqtt_bindings_at_operation_level() {
    let channel = first(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "OneOf MQTT", "version": "1.0.0" },
  "channels": {
    "sensors": {
      "publish": {
        "bindings": { "mqtt": { "qos": 2, "retain": true } },
        "message": {
          "oneOf": [
            {
              "payload": { "type": "object", "example": { "temp": 22 } }
            },
            {
              "payload": { "type": "object", "example": { "humidity": 60 } }
            }
          ]
        }
      }
    }
  }
}"#,
    );
    // MQTT bindings are channel-level
    assert_eq!(channel.mqtt_qos, Some(2));
    assert_eq!(channel.mqtt_retain, Some(true));
    assert_eq!(channel.messages().len(), 2);
}

#[test]
fn should_tolerate_v2_one_of_with_single_entry() {
    let channel = first(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "OneOf Single", "version": "1.0.0" },
  "channels": {
    "topic": {
      "publish": {
        "message": {
          "oneOf": [
            {
              "payload": { "type": "object", "example": { "v": 1 } }
            }
          ]
        }
      }
    }
  }
}"#,
    );
    // Single entry oneOf — behaves as single message
    assert_eq!(channel.messages().len(), 1);
    assert_eq!(channel.examples.len(), 1);
    assert_eq!(channel.examples[0]["v"].as_i64(), Some(1));
}

#[test]
fn should_parse_v2_correlation_id_header_location() {
    let ids = message_correlation_ids(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "CorrId", "version": "1.0.0" },
  "channels": {
    "orders": {
      "publish": {
        "message": {
          "correlationId": {
            "location": "$message.header#/correlationId",
            "description": "Default Correlation ID"
          },
          "payload": { "type": "object" }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(ids, vec![Some("$message.header#/correlationId".to_string())]);
}

#[test]
fn should_parse_v2_correlation_id_payload_location() {
    let ids = message_correlation_ids(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "CorrId", "version": "1.0.0" },
  "channels": {
    "orders": {
      "publish": {
        "message": {
          "correlationId": {
            "location": "$message.payload#/metadata/id"
          },
          "payload": { "type": "object" }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(ids[0].as_deref(), Some("$message.payload#/metadata/id"));
}

#[test]
fn should_parse_v2_correlation_id_from_ref_to_components() {
    let ids = message_correlation_ids(
        r##"{
  "asyncapi": "2.6.0",
  "info": { "title": "CorrIdRef", "version": "1.0.0" },
  "channels": {
    "orders": {
      "publish": {
        "message": {
          "correlationId": { "$ref": "#/components/correlationIds/defaultCorrId" },
          "payload": { "type": "object" }
        }
      }
    }
  },
  "components": {
    "correlationIds": {
      "defaultCorrId": {
        "location": "$message.header#/x-corr-id",
        "description": "Resolved from components"
      }
    }
  }
}"##,
    );
    assert_eq!(ids[0].as_deref(), Some("$message.header#/x-corr-id"));
}

#[test]
fn should_return_null_correlation_id_when_absent() {
    let ids = message_correlation_ids(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "NoCorrId", "version": "1.0.0" },
  "channels": {
    "orders": {
      "publish": {
        "message": {
          "payload": { "type": "object" }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(ids[0], None);
}

#[test]
fn should_return_null_correlation_id_when_malformed() {
    // correlationId is a string instead of an object — should not throw
    let ids = message_correlation_ids(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "Malformed", "version": "1.0.0" },
  "channels": {
    "orders": {
      "publish": {
        "message": {
          "correlationId": "not-an-object",
          "payload": { "type": "object" }
        }
      }
    }
  }
}"#,
    );
    assert_eq!(ids[0], None);
}

#[test]
fn should_parse_v2_one_of_correlation_id_per_variant() {
    let ids = message_correlation_ids(
        r#"{
  "asyncapi": "2.6.0",
  "info": { "title": "OneOf CorrId", "version": "1.0.0" },
  "channels": {
    "events": {
      "publish": {
        "message": {
          "oneOf": [
            {
              "name": "MsgA",
              "correlationId": { "location": "$message.header#/corrA" },
              "payload": { "type": "object", "example": { "a": 1 } }
            },
            {
              "name": "MsgB",
              "correlationId": { "location": "$message.payload#/corrId" },
              "payload": { "type": "object", "example": { "b": 2 } }
            }
          ]
        }
      }
    }
  }
}"#,
    );
    assert_eq!(ids, vec![Some("$message.header#/corrA".to_string()), Some("$message.payload#/corrId".to_string())]);
}

#[test]
fn should_parse_v3_correlation_id() {
    let ids = message_correlation_ids(
        r#"{
  "asyncapi": "3.0.0",
  "info": { "title": "V3 CorrId", "version": "1.0.0" },
  "channels": {
    "orders": {
      "messages": {
        "orderMsg": {
          "correlationId": {
            "location": "$message.header#/x-correlation-id"
          },
          "payload": { "type": "object" },
          "examples": [{ "payload": { "orderId": 1 } }]
        }
      }
    }
  }
}"#,
    );
    assert_eq!(ids, vec![Some("$message.header#/x-correlation-id".to_string())]);
}

#[test]
fn should_parse_v3_correlation_id_with_ref_to_components() {
    let ids = message_correlation_ids(
        r##"{
  "asyncapi": "3.0.0",
  "info": { "title": "V3 CorrId Ref", "version": "1.0.0" },
  "channels": {
    "orders": {
      "messages": {
        "orderMsg": {
          "correlationId": { "$ref": "#/components/correlationIds/defaultId" },
          "payload": { "type": "object" }
        }
      }
    }
  },
  "components": {
    "correlationIds": {
      "defaultId": {
        "location": "$message.payload#/correlationId"
      }
    }
  }
}"##,
    );
    assert_eq!(ids[0].as_deref(), Some("$message.payload#/correlationId"));
}

/// A `&str` cannot be null: the empty document is the nearest input, rejected with the same message.
#[test]
fn should_reject_null_document() {
    assert_eq!(parse("").err().as_deref(), Some("AsyncAPI document must not be null or blank"));
}

#[test]
fn should_reject_blank_document() {
    assert_eq!(parse("   ").err().as_deref(), Some("AsyncAPI document must not be null or blank"));
}

// ---- AmqpBindingParserTest ----

#[test]
fn should_parse_routing_key_exchange_binding_v2() {
    let binding = amqp(
        r#"{"asyncapi":"2.6.0","info":{"title":"t"},"channels":{
  "user.signedup":{
    "bindings":{"amqp":{
      "is":"routingKey",
      "exchange":{"name":"events","type":"topic","durable":true}
    }},
    "publish":{"message":{"payload":{"type":"object"}}}
  }
}}"#,
    );
    assert_eq!(binding.channel_type, AmqpChannelType::RoutingKey);
    assert_eq!(binding.exchange_name.as_deref(), Some("events"));
    assert_eq!(binding.exchange_type.as_deref(), Some("topic"));
    assert!(binding.exchange_durable);
}

#[test]
fn should_parse_queue_binding_v3() {
    let binding = amqp(
        r#"{"asyncapi":"3.0.0","info":{"title":"t"},"channels":{
  "orders":{
    "bindings":{"amqp":{
      "is":"queue",
      "queue":{"name":"orders-queue","durable":false}
    }},
    "messages":{"orderPlaced":{"payload":{"type":"object"}}}
  }
}}"#,
    );
    assert_eq!(binding.channel_type, AmqpChannelType::Queue);
    assert_eq!(binding.queue_name.as_deref(), Some("orders-queue"));
    assert!(!binding.queue_durable);
}

#[test]
fn should_default_to_routing_key_when_is_absent() {
    let binding = amqp(
        r#"{"asyncapi":"2.6.0","info":{"title":"t"},"channels":{"c":{
  "bindings":{"amqp":{"exchange":{"name":"ex"}}},
  "publish":{"message":{"payload":{"type":"object"}}}
}}}"#,
    );
    assert_eq!(binding.channel_type, AmqpChannelType::RoutingKey);
    assert!(binding.exchange_durable, "default durable");
}

#[test]
fn should_return_null_binding_when_no_amqp_binding_present() {
    let channel = first(r#"{"asyncapi":"2.6.0","info":{"title":"t"},"channels":{"c":{"publish":{"message":{"payload":{"type":"object"}}}}}}"#);
    assert!(channel.amqp_binding.is_none());
}

#[test]
fn should_parse_explicit_routing_key_extension() {
    let binding = amqp(
        r#"{"asyncapi":"2.6.0","info":{"title":"t"},"channels":{"c":{
  "bindings":{"amqp":{"exchange":{"name":"ex"},"routingKey":"my.key"}},
  "publish":{"message":{"payload":{"type":"object"}}}
}}}"#,
    );
    assert_eq!(binding.routing_key.as_deref(), Some("my.key"));
}

#[test]
fn should_not_affect_kafka_or_mqtt_channels() {
    // A channel with MQTT bindings but no AMQP binding should leave amqpBinding null.
    let channel = first(
        r#"{"asyncapi":"2.6.0","info":{"title":"t"},"channels":{"c":{
  "publish":{"bindings":{"mqtt":{"qos":2,"retain":true}},
    "message":{"payload":{"type":"object"}}}
}}}"#,
    );
    assert!(channel.amqp_binding.is_none());
    assert_eq!(channel.mqtt_qos, Some(2));
    assert_eq!(channel.mqtt_retain, Some(true));
}

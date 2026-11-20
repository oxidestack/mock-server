//! `ConfluentWireFormatTest` and `AvroPayloadCodecTest` (mockserver-async): the Confluent framing (magic byte,
//! schema id) and JSON ↔ Avro binary.

use mock_server::asyncapi::avro::{HEADER_SIZE, MAGIC_BYTE, avro_to_json, frame, is_wire_format, json_to_avro, parse_schema, unframe};
use serde_json::Value;

// ---- ConfluentWireFormatTest ----

#[test]
fn should_encode_magic_byte_and_schema_id() {
    let payload = b"hello";
    let framed = frame(42, payload);
    assert_eq!(framed.len(), HEADER_SIZE + payload.len());
    assert_eq!(framed[0], MAGIC_BYTE);
    // Big-endian schema id 42 = 0x0000002A.
    assert_eq!(framed[1..5], [0x00, 0x00, 0x00, 0x2a]);
}

#[test]
fn should_round_trip_encode_decode() {
    let payload = [0x01, 0x02, 0x03, 0x04, 0x05];
    let framed = frame(100001, &payload);
    let (schema_id, decoded) = unframe(&framed).unwrap();
    assert_eq!(schema_id, 100001);
    assert_eq!(decoded, payload);
}

#[test]
fn should_detect_wire_format() {
    assert!(is_wire_format(&frame(1, &[0x09])));
}

/// `isWireFormat(null)` has no Rust counterpart (a byte slice is never null).
#[test]
fn should_reject_non_wire_format_bytes() {
    assert!(!is_wire_format(&[]));
    // Too short (< 5 bytes).
    assert!(!is_wire_format(&[0x00, 0x00]));
    // Wrong leading byte.
    assert!(!is_wire_format(&[0x01, 0x00, 0x00, 0x00, 0x01]));
}

#[test]
fn should_decode_empty_payload() {
    let framed = frame(7, &[]);
    let (schema_id, decoded) = unframe(&framed).unwrap();
    assert_eq!(schema_id, 7);
    assert!(decoded.is_empty());
}

#[test]
fn should_throw_decoding_non_wire_format() {
    assert_eq!(unframe(&[0x01, 0x02, 0x03]).unwrap_err().message, "not a Confluent wire-format message (missing magic byte or too short)");
}

// ---- AvroPayloadCodecTest ----

const ORDER_SCHEMA: &str = r#"{"type":"record","name":"Order","fields":[{"name":"orderId","type":"int"},{"name":"item","type":"string"}]}"#;

fn tree(json: &str) -> Value {
    serde_json::from_str(json).unwrap()
}

#[test]
fn should_round_trip_json_through_avro_binary() {
    let schema = parse_schema(ORDER_SCHEMA).unwrap();
    let json = r#"{"orderId":42,"item":"widget"}"#;
    let avro_binary = json_to_avro(&schema, json).unwrap();
    assert!(!avro_binary.is_empty());
    // Compared semantically (field order and spacing may differ).
    assert_eq!(tree(&avro_to_json(&schema, &avro_binary).unwrap()), tree(json));
}

#[test]
fn should_encode_different_values_distinctly() {
    let schema = parse_schema(ORDER_SCHEMA).unwrap();
    let a = json_to_avro(&schema, r#"{"orderId":1,"item":"a"}"#).unwrap();
    let b = json_to_avro(&schema, r#"{"orderId":2,"item":"bb"}"#).unwrap();
    assert_ne!(a, b);
}

#[test]
fn should_preserve_numeric_and_string_types() {
    let schema_json = concat!(
        r#"{"type":"record","name":"M","fields":["#,
        r#"{"name":"count","type":"long"},{"name":"ratio","type":"double"},{"name":"flag","type":"boolean"}]}"#
    );
    let schema = parse_schema(schema_json).unwrap();
    let json = r#"{"count":9999999999,"ratio":3.5,"flag":true}"#;
    let avro_binary = json_to_avro(&schema, json).unwrap();
    assert_eq!(tree(&avro_to_json(&schema, &avro_binary).unwrap()), tree(json));
}

#[test]
fn should_throw_on_payload_not_conforming_to_schema() {
    let schema = parse_schema(ORDER_SCHEMA).unwrap();
    assert!(json_to_avro(&schema, r#"{"orderId":"not-an-int","item":"x"}"#).is_err(), "orderId must be an int, not a string");
}

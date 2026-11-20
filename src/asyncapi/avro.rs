//! Avro for the Kafka adapters (`AvroPayloadCodec`, `ConfluentWireFormat`): the ported Avro 1.12 library
//! (the avro-codec-rs crate) with the oracle image's relocated package names in the messages that print class names, its
//! failures as broker errors, and MockServer's Confluent framing (magic byte, schema id).

use std::sync::Arc;

pub use avro::Schema;

use super::broker::Error;

/// The relocated package prefix of the oracle image's Jackson and Avro classes.
const SHADED: &str = "shaded_package.";

/// An Avro failure as upstream reports it: the exception's `getMessage()`.
fn failure(e: avro::Error) -> Error {
    Error::new(e.to_string())
}

/// `new Schema.Parser().parse(json)`.
pub fn parse_schema(json: &str) -> Result<Arc<Schema>, Error> {
    avro::parse_schema_with(json, &avro::ParseOptions { relocated_prefix: SHADED }).map(Arc::new).map_err(failure)
}

/// A JSON payload as Avro binary (`AvroPayloadCodec.encode`'s datum).
pub fn json_to_avro(schema: &Schema, json: &str) -> Result<Vec<u8>, Error> {
    avro::json_to_avro(schema, json).map_err(failure)
}

/// Avro binary as JSON (`AvroPayloadCodec.decodeToJson`).
pub fn avro_to_json(schema: &Schema, data: &[u8]) -> Result<String, Error> {
    avro::avro_to_json(schema, data).map_err(failure)
}

/// `ConfluentWireFormat.MAGIC_BYTE`.
pub const MAGIC_BYTE: u8 = 0;
/// `ConfluentWireFormat.HEADER_SIZE`: the magic byte and the schema id.
pub const HEADER_SIZE: usize = 5;

/// `ConfluentWireFormat.encode`: the magic byte, the schema id (big-endian), the payload.
pub fn frame(schema_id: i32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
    out.push(MAGIC_BYTE);
    out.extend_from_slice(&schema_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// `ConfluentWireFormat.isWireFormat`.
pub fn is_wire_format(data: &[u8]) -> bool {
    data.len() >= HEADER_SIZE && data[0] == MAGIC_BYTE
}

/// `ConfluentWireFormat.decode`: the schema id and the payload.
pub fn unframe(data: &[u8]) -> Result<(i32, &[u8]), Error> {
    if !is_wire_format(data) {
        return Err(Error::new("not a Confluent wire-format message (missing magic byte or too short)"));
    }
    Ok((i32::from_be_bytes(data[1..5].try_into().expect("four bytes")), &data[5..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_name_the_image_s_relocated_classes() {
        assert_eq!(parse_schema("{").unwrap_err().message.split(':').next(), Some("shaded_package.com.fasterxml.jackson.core.io.JsonEOFException"));
        assert!(parse_schema(r#""foo""#).unwrap_err().message.starts_with("Unknown schema: shaded_package.org.apache.avro.compiler.UnresolvedSchema_"));
    }
}

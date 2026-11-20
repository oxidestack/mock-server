//! The Java serialization forms of what the clustered caches hold: `VersionedWrapper<V>` around an
//! `ExpectationEntry`, a `String` or a Jackson `ObjectNode`, and `Blob`. Upstream configures
//! `JavaSerializationMarshaller` for the clustered manager (`InfinispanStateBackend.java:206`), so these are
//! the bytes a JVM peer reads and writes; the infinispan-rs crate carries them opaquely as `UserValue`s.
//!
//! The stream shapes are the ones recorded from the real classes in `tests/files/cluster/java_serial.hex`
//! (`expectation_entry_*`, `blob_*`, `node_serialization`, `versioned_wrapper_*`), a copy of infinispan-rs'
//! `tests/vectors/java_serial.hex` (<https://github.com/oxidestack/infinispan-rs>), whose README there says how
//! each was generated.
//!
//! Decoding goes through the clustered allow-list ([`CLUSTERED_ALLOW_LIST_PATTERNS`]) the way
//! `CheckedInputStream.resolveClass` does, so a stream naming a class outside it is refused.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::OnceLock;

use infinispan::commands::object::{CacheObject, UserValue};
use infinispan::marshall::allow_list::ClassAllowList;
use infinispan::marshall::java_serial::{
    AnnotationItem, ClassDesc, FieldDesc, FieldValue, JavaValue, ObjectLevel, SC_BLOCK_DATA, SC_EXTERNALIZABLE, SC_SERIALIZABLE, SC_WRITE_METHOD,
    byte_array_class_desc, decode_stream_with_allow_list, encode_one,
};
use infinispan::marshall::primitives::PrimitiveValue;

use crate::state_backend::{Blob, ExpectationEntry};

/// `InfinispanStateBackend.CLUSTERED_ALLOW_LIST_PATTERNS` (`InfinispanStateBackend.java:74-85`), verbatim: the
/// explicit Java-deserialization allow-list of the clustered marshaller. No wildcard.
pub const CLUSTERED_ALLOW_LIST_PATTERNS: [&str; 10] = [
    r"org\.mockserver\.state\.infinispan\..*",
    r"org\.mockserver\.state\..*",
    r"org\.mockserver\.mock\..*",
    r"org\.mockserver\.model\..*",
    r"org\.mockserver\.matchers\..*",
    r"com\.fasterxml\.jackson\..*",
    r"java\.lang\..*",
    r"java\.util\..*",
    r"java\.time\..*",
    r"\[B",
];

/// The allow-list the clustered manager installs (`allowList.addRegexp` for each pattern).
pub fn clustered_allow_list() -> &'static ClassAllowList {
    static LIST: OnceLock<ClassAllowList> = OnceLock::new();
    LIST.get_or_init(|| ClassAllowList::new(std::iter::empty(), CLUSTERED_ALLOW_LIST_PATTERNS.iter().map(|p| p.to_string())))
}

/// Why a value could not be turned into, or read back from, its Java serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// `ObjectOutputStream.writeUTF` of a string whose modified UTF-8 form exceeds 65,535 bytes:
    /// `java.io.UTFDataFormatException` (`ObjectOutputStream$BlockDataOutputStream.writeUTF`, which throws it
    /// without a message). `ExpectationEntry.writeObject` writes the expectation's JSON that way.
    UtfDataFormat { bytes: usize },
    /// The stream names a class the allow-list refuses, or is not the expected shape.
    Unreadable(String),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::UtfDataFormat { bytes } => write!(f, "java.io.UTFDataFormatException (encoded string is {bytes} bytes, the limit is 65535)"),
            CodecError::Unreadable(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for CodecError {}

// ---------------------------------------------------------------------------------------------------------
// modified UTF-8 and block data
// ---------------------------------------------------------------------------------------------------------

/// `DataOutput.writeUTF`'s body: modified UTF-8 (U+0000 as `C0 80`, supplementary characters as two 3-byte
/// surrogate halves).
pub fn modified_utf8(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for unit in s.encode_utf16() {
        match unit {
            0x0001..=0x007f => out.push(unit as u8),
            0x0000 | 0x0080..=0x07ff => {
                out.push(0xc0 | (unit >> 6) as u8);
                out.push(0x80 | (unit & 0x3f) as u8);
            }
            _ => {
                out.push(0xe0 | (unit >> 12) as u8);
                out.push(0x80 | ((unit >> 6) & 0x3f) as u8);
                out.push(0x80 | (unit & 0x3f) as u8);
            }
        }
    }
    out
}

fn modified_utf8_decode(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b >> 4 {
            0..=7 => {
                units.push(b as u16);
                i += 1;
            }
            12 | 13 => {
                let c = *bytes.get(i + 1)?;
                units.push((((b & 0x1f) as u16) << 6) | (c & 0x3f) as u16);
                i += 2;
            }
            14 => {
                let (c, d) = (*bytes.get(i + 1)?, *bytes.get(i + 2)?);
                units.push((((b & 0x0f) as u16) << 12) | (((c & 0x3f) as u16) << 6) | (d & 0x3f) as u16);
                i += 3;
            }
            _ => return None,
        }
    }
    String::from_utf16(&units).ok()
}

/// `BlockDataOutputStream` buffers 1024 bytes and writes a block-data record each time it fills, so a long
/// `writeUTF` or `write(byte[])` inside a `writeObject`/`writeExternal` is a run of 1024-byte records.
const MAX_BLOCK_SIZE: usize = 1024;

fn block_records(bytes: &[u8]) -> Vec<AnnotationItem> {
    bytes.chunks(MAX_BLOCK_SIZE).map(|c| AnnotationItem::Block(c.to_vec())).collect()
}

fn block_bytes(annotation: &[AnnotationItem]) -> Vec<u8> {
    annotation
        .iter()
        .filter_map(|a| match a {
            AnnotationItem::Block(b) => Some(b.as_slice()),
            AnnotationItem::Object(_) => None,
        })
        .flatten()
        .copied()
        .collect()
}

// ---------------------------------------------------------------------------------------------------------
// ExpectationEntry
// ---------------------------------------------------------------------------------------------------------

const EXPECTATION_ENTRY: &str = "org.mockserver.state.ExpectationEntry";

fn expectation_entry_class() -> Rc<ClassDesc> {
    Rc::new(ClassDesc {
        name: EXPECTATION_ENTRY.into(),
        serial_version_uid: 2,
        flags: SC_SERIALIZABLE | SC_WRITE_METHOD,
        // the JDK's order: primitives by name, then objects by name
        fields: vec![
            FieldDesc::primitive(b'J', "created"),
            FieldDesc::primitive(b'I', "priority"),
            FieldDesc::primitive(b'I', "remainingTimes"),
            FieldDesc::object("id", "Ljava/lang/String;"),
        ],
        super_desc: None,
    })
}

/// `ExpectationEntry` as `ObjectOutputStream.writeObject` writes it: `defaultWriteObject()` (created, priority,
/// remainingTimes, id) then `writeUTF(json)` of the expectation. `json` is
/// `ObjectMapperFactory.createObjectMapper(true, false)`'s pretty form of the `ExpectationDTO`.
///
/// Fails with [`CodecError::UtfDataFormat`] when the JSON is over 65,535 modified-UTF-8 bytes (a quirk of
/// upstream's serialisation): the one-expectation-too-large quirk of the clustered `put`.
pub fn expectation_entry_to_java(entry: &ExpectationEntry) -> Result<JavaValue, CodecError> {
    expectation_entry_with_json(entry, &crate::json::pretty(&entry.expectation_json))
}

/// [`expectation_entry_to_java`] with the JSON text given (the stream does not depend on how it was printed).
pub fn expectation_entry_with_json(entry: &ExpectationEntry, json: &str) -> Result<JavaValue, CodecError> {
    let utf = modified_utf8(json);
    if utf.len() > 0xffff {
        return Err(CodecError::UtfDataFormat { bytes: utf.len() });
    }
    let mut block = Vec::with_capacity(utf.len() + 2);
    block.extend_from_slice(&(utf.len() as u16).to_be_bytes());
    block.extend_from_slice(&utf);
    Ok(JavaValue::Object {
        class: expectation_entry_class(),
        levels: vec![ObjectLevel {
            fields: vec![
                FieldValue::Long(entry.created as i64),
                FieldValue::Int(entry.priority as i32),
                FieldValue::Int(entry.remaining_times as i32),
                FieldValue::Obj(Box::new(JavaValue::Str(entry.id.clone()))),
            ],
            annotation: block_records(&block),
        }],
    })
}

fn expectation_entry_from_java(class: &ClassDesc, levels: &[ObjectLevel]) -> Result<ExpectationEntry, CodecError> {
    let level = levels.first().ok_or_else(|| CodecError::Unreadable("ExpectationEntry without fields".into()))?;
    let field = |name: &str| class.fields.iter().position(|f| f.name == name).and_then(|i| level.fields.get(i));
    let (Some(FieldValue::Long(created)), Some(FieldValue::Int(priority)), Some(FieldValue::Int(remaining)), Some(FieldValue::Obj(id))) =
        (field("created"), field("priority"), field("remainingTimes"), field("id"))
    else {
        return Err(CodecError::Unreadable("unexpected ExpectationEntry fields".into()));
    };
    let JavaValue::Str(id) = &**id else { return Err(CodecError::Unreadable("ExpectationEntry.id is not a String".into())) };
    let block = block_bytes(&level.annotation);
    if block.len() < 2 || block.len() != 2 + u16::from_be_bytes([block[0], block[1]]) as usize {
        return Err(CodecError::Unreadable("ExpectationEntry's expectation JSON is not one writeUTF".into()));
    }
    let json = modified_utf8_decode(&block[2..]).ok_or_else(|| CodecError::Unreadable("ExpectationEntry's expectation JSON is not modified UTF-8".into()))?;
    let expectation_json = crate::json::parse_lenient(json.as_bytes()).map_err(|e| CodecError::Unreadable(format!("ExpectationEntry's expectation JSON: {e}")))?;
    Ok(ExpectationEntry { id: id.clone(), priority: *priority as i64, created: *created as u64, remaining_times: *remaining as i64, expectation_json })
}

// ---------------------------------------------------------------------------------------------------------
// Jackson ObjectNode (CRUD entities)
// ---------------------------------------------------------------------------------------------------------

/// The `clustered` image shades Jackson, so the JVM writes (and its `ObjectInputStream` resolves) the shaded
/// class name; an unshaded name makes it throw a `ClassCastException` (bytes from the oracle's captured packets).
const NODE_SERIALIZATION: &str = "shaded_package.com.fasterxml.jackson.databind.node.NodeSerialization";
/// The unmodified-Jackson name, still accepted when reading (the recorded vectors of infinispan-rs).
const NODE_SERIALIZATION_UNSHADED: &str = "com.fasterxml.jackson.databind.node.NodeSerialization";

/// `ObjectNode.writeReplace()` is a `NodeSerialization`, an `Externalizable` that writes `int length` then the
/// compact JSON bytes.
pub fn object_node_to_java(value: &serde_json::Value) -> JavaValue {
    let json = serde_json::to_vec(value).expect("a JSON value serialises");
    let mut payload = Vec::with_capacity(json.len() + 4);
    payload.extend_from_slice(&(json.len() as i32).to_be_bytes());
    payload.extend_from_slice(&json);
    JavaValue::Object {
        class: Rc::new(ClassDesc { name: NODE_SERIALIZATION.into(), serial_version_uid: 1, flags: SC_EXTERNALIZABLE | SC_BLOCK_DATA, fields: vec![], super_desc: None }),
        levels: vec![ObjectLevel { fields: vec![], annotation: block_records(&payload) }],
    }
}

fn object_node_from_java(levels: &[ObjectLevel]) -> Result<serde_json::Value, CodecError> {
    let block = levels.first().map(|l| block_bytes(&l.annotation)).unwrap_or_default();
    if block.len() < 4 || block.len() != 4 + i32::from_be_bytes([block[0], block[1], block[2], block[3]]) as usize {
        return Err(CodecError::Unreadable("NodeSerialization payload is not int length + bytes".into()));
    }
    crate::json::parse_lenient(&block[4..]).map_err(|e| CodecError::Unreadable(format!("NodeSerialization JSON: {e}")))
}

// ---------------------------------------------------------------------------------------------------------
// Blob
// ---------------------------------------------------------------------------------------------------------

const BLOB: &str = "org.mockserver.state.Blob";

fn blob_class() -> Rc<ClassDesc> {
    Rc::new(ClassDesc {
        name: BLOB.into(),
        serial_version_uid: 1,
        flags: SC_SERIALIZABLE,
        fields: vec![
            FieldDesc { type_code: b'[', name: "data".into(), field_class_name: Some("[B".into()) },
            FieldDesc::object("key", "Ljava/lang/String;"),
            FieldDesc::object("metadata", "Ljava/util/Map;"),
        ],
        super_desc: None,
    })
}

fn empty_map() -> JavaValue {
    JavaValue::Object {
        class: Rc::new(ClassDesc { name: "java.util.Collections$EmptyMap".into(), serial_version_uid: 0x5936_1485_5adc_e7d0, flags: SC_SERIALIZABLE, fields: vec![], super_desc: None }),
        levels: vec![ObjectLevel::default()],
    }
}

fn hash_map(entries: &HashMap<String, String>) -> JavaValue {
    let mut sorted: Vec<_> = entries.iter().collect();
    sorted.sort();
    let capacity = ((sorted.len() as f64 / 0.75).ceil() as usize).max(16).next_power_of_two();
    let mut head = Vec::with_capacity(8);
    head.extend_from_slice(&(capacity as i32).to_be_bytes());
    head.extend_from_slice(&(sorted.len() as i32).to_be_bytes());
    let mut annotation = vec![AnnotationItem::Block(head)];
    for (k, v) in sorted {
        annotation.push(AnnotationItem::Object(JavaValue::Str(k.clone())));
        annotation.push(AnnotationItem::Object(JavaValue::Str(v.clone())));
    }
    JavaValue::Object {
        class: Rc::new(ClassDesc {
            name: "java.util.HashMap".into(),
            serial_version_uid: 0x0507_dac1_c316_60d1,
            flags: SC_SERIALIZABLE | SC_WRITE_METHOD,
            fields: vec![FieldDesc::primitive(b'F', "loadFactor"), FieldDesc::primitive(b'I', "threshold")],
            super_desc: None,
        }),
        levels: vec![ObjectLevel { fields: vec![FieldValue::Float(0.75), FieldValue::Int((capacity as f64 * 0.75) as i32)], annotation }],
    }
}

/// `new Blob(key, data, metadata)`: an empty metadata map is `Collections.emptyMap()` (what
/// `ExpectationFileSystemPersistence` passes), a non-empty one a `HashMap`.
pub fn blob_to_java(blob: &Blob) -> JavaValue {
    JavaValue::Object {
        class: blob_class(),
        levels: vec![ObjectLevel {
            fields: vec![
                FieldValue::Obj(Box::new(JavaValue::ByteArray { class: byte_array_class_desc(), bytes: blob.data.clone() })),
                FieldValue::Obj(Box::new(JavaValue::Str(blob.key.clone()))),
                FieldValue::Obj(Box::new(if blob.metadata.is_empty() { empty_map() } else { hash_map(&blob.metadata) })),
            ],
            annotation: vec![],
        }],
    }
}

fn blob_from_java(class: &ClassDesc, levels: &[ObjectLevel]) -> Result<Blob, CodecError> {
    let level = levels.first().ok_or_else(|| CodecError::Unreadable("Blob without fields".into()))?;
    let field = |name: &str| class.fields.iter().position(|f| f.name == name).and_then(|i| level.fields.get(i));
    let (Some(FieldValue::Obj(data)), Some(FieldValue::Obj(key)), Some(FieldValue::Obj(metadata))) = (field("data"), field("key"), field("metadata")) else {
        return Err(CodecError::Unreadable("unexpected Blob fields".into()));
    };
    let (JavaValue::ByteArray { bytes, .. }, JavaValue::Str(key)) = (&**data, &**key) else {
        return Err(CodecError::Unreadable("Blob.data / Blob.key have the wrong types".into()));
    };
    let metadata = match &**metadata {
        JavaValue::Object { class, .. } if class.name == "java.util.Collections$EmptyMap" => HashMap::new(),
        JavaValue::Object { class, levels } if class.name == "java.util.HashMap" => {
            let mut items = levels.first().map(|l| l.annotation.iter().skip(1)).into_iter().flatten();
            let mut map = HashMap::new();
            while let (Some(AnnotationItem::Object(JavaValue::Str(k))), Some(AnnotationItem::Object(JavaValue::Str(v)))) = (items.next(), items.next()) {
                map.insert(k.clone(), v.clone());
            }
            map
        }
        other => return Err(CodecError::Unreadable(format!("Blob.metadata is not a supported Map: {other:?}"))),
    };
    Ok(Blob { key: key.clone(), data: bytes.clone(), metadata })
}

// ---------------------------------------------------------------------------------------------------------
// VersionedWrapper and the value types
// ---------------------------------------------------------------------------------------------------------

const VERSIONED_WRAPPER: &str = "org.mockserver.state.infinispan.VersionedWrapper";

fn versioned_wrapper_class() -> Rc<ClassDesc> {
    Rc::new(ClassDesc {
        name: VERSIONED_WRAPPER.into(),
        serial_version_uid: 1,
        flags: SC_SERIALIZABLE,
        fields: vec![FieldDesc::primitive(b'J', "version"), FieldDesc::object("value", "Ljava/lang/Object;")],
        super_desc: None,
    })
}

/// A value type a clustered `KeyValueStore<V>` can hold: its Java form on the way in, and back out.
pub trait ValueCodec: Clone + PartialEq + Send + Sync + 'static {
    /// The value as the object inside `VersionedWrapper.value`.
    fn to_java(&self) -> Result<JavaValue, CodecError>;
    fn from_java(value: &JavaValue) -> Result<Self, CodecError>;
}

impl ValueCodec for String {
    fn to_java(&self) -> Result<JavaValue, CodecError> {
        Ok(JavaValue::Str(self.clone()))
    }
    fn from_java(value: &JavaValue) -> Result<Self, CodecError> {
        match value {
            JavaValue::Str(s) => Ok(s.clone()),
            other => Err(CodecError::Unreadable(format!("expected a String, found {other:?}"))),
        }
    }
}

/// `Integer`, the value of the `sharedTimesCounters` cache (`KeyValueStore<Integer>`).
impl ValueCodec for i32 {
    fn to_java(&self) -> Result<JavaValue, CodecError> {
        Ok(infinispan::cache::versioned::java_integer(*self))
    }
    fn from_java(value: &JavaValue) -> Result<Self, CodecError> {
        match value {
            JavaValue::Object { class, levels } if class.name == "java.lang.Integer" => {
                match levels.last().map(|level| level.fields.as_slice()) {
                    Some([FieldValue::Int(i)]) => Ok(*i),
                    other => Err(CodecError::Unreadable(format!("unexpected Integer fields {other:?}"))),
                }
            }
            other => Err(CodecError::Unreadable(format!("expected an Integer, found {other:?}"))),
        }
    }
}

impl ValueCodec for ExpectationEntry {
    fn to_java(&self) -> Result<JavaValue, CodecError> {
        expectation_entry_to_java(self)
    }
    fn from_java(value: &JavaValue) -> Result<Self, CodecError> {
        match value {
            JavaValue::Object { class, levels } if class.name == EXPECTATION_ENTRY => expectation_entry_from_java(class, levels),
            other => Err(CodecError::Unreadable(format!("expected an ExpectationEntry, found {other:?}"))),
        }
    }
}

impl ValueCodec for serde_json::Value {
    fn to_java(&self) -> Result<JavaValue, CodecError> {
        Ok(object_node_to_java(self))
    }
    fn from_java(value: &JavaValue) -> Result<Self, CodecError> {
        match value {
            JavaValue::Object { class, levels } if class.name == NODE_SERIALIZATION || class.name == NODE_SERIALIZATION_UNSHADED => object_node_from_java(levels),
            other => Err(CodecError::Unreadable(format!("expected an ObjectNode, found {other:?}"))),
        }
    }
}

/// A user object: the Java stream of one value, as a cache holds it.
pub fn user_value(value: &JavaValue) -> CacheObject {
    CacheObject::User(UserValue::new(encode_one(value)))
}

/// `V` as the value a cache `compute` lambda captures (`InfinispanKeyValueStore.put`'s `value`): a `String` or an
/// `Integer` is one of the marshaller's primitives, anything else a user object.
pub fn captured_value<V: ValueCodec>(value: &V) -> Result<CacheObject, CodecError> {
    Ok(match value.to_java()? {
        JavaValue::Str(s) => CacheObject::Primitive(PrimitiveValue::Str(s)),
        JavaValue::Object { class, levels } if class.name == "java.lang.Integer" => match levels.last().map(|level| level.fields.as_slice()) {
            Some([FieldValue::Int(i)]) => CacheObject::Primitive(PrimitiveValue::IntObj(*i)),
            _ => user_value(&JavaValue::Object { class, levels }),
        },
        other => user_value(&other),
    })
}

/// `new VersionedWrapper<>(value, version)` as a cache value.
pub fn wrap<V: ValueCodec>(value: &V, version: u64) -> Result<CacheObject, CodecError> {
    let wrapper = JavaValue::Object {
        class: versioned_wrapper_class(),
        levels: vec![ObjectLevel { fields: vec![FieldValue::Long(version as i64), FieldValue::Obj(Box::new(value.to_java()?))], annotation: vec![] }],
    };
    Ok(user_value(&wrapper))
}

/// Reads a cache value as a `VersionedWrapper<V>` through the allow-list `allow` (`None`: LOCAL mode's `.*`).
pub fn unwrap<V: ValueCodec>(object: &CacheObject, allow: Option<&ClassAllowList>) -> Result<(V, u64), CodecError> {
    let CacheObject::User(user) = object else { return Err(CodecError::Unreadable(format!("expected a VersionedWrapper, found {object:?}"))) };
    let mut values = match allow {
        Some(list) => decode_stream_with_allow_list(user.bytes(), list),
        None => infinispan::marshall::java_serial::decode_stream(user.bytes()),
    }
    .map_err(|e| CodecError::Unreadable(e.to_string()))?;
    let (class, levels) = match values.pop() {
        Some(JavaValue::Object { class, levels }) if values.is_empty() && class.name == VERSIONED_WRAPPER => (class, levels),
        other => return Err(CodecError::Unreadable(format!("not a VersionedWrapper: {other:?}"))),
    };
    let fields = &levels.first().ok_or_else(|| CodecError::Unreadable("VersionedWrapper without fields".into()))?.fields;
    let version = class.fields.iter().position(|f| f.name == "version").and_then(|i| fields.get(i));
    let value = class.fields.iter().position(|f| f.name == "value").and_then(|i| fields.get(i));
    match (version, value) {
        (Some(FieldValue::Long(version)), Some(FieldValue::Obj(value))) => Ok((V::from_java(value)?, *version as u64)),
        other => Err(CodecError::Unreadable(format!("unexpected VersionedWrapper fields {other:?}"))),
    }
}

/// A `Blob` as a cache value.
pub fn blob_value(blob: &Blob) -> CacheObject {
    user_value(&blob_to_java(blob))
}

/// Reads a cache value as a `Blob`.
pub fn read_blob(object: &CacheObject, allow: Option<&ClassAllowList>) -> Result<Blob, CodecError> {
    let CacheObject::User(user) = object else { return Err(CodecError::Unreadable(format!("expected a Blob, found {object:?}"))) };
    let mut values = match allow {
        Some(list) => decode_stream_with_allow_list(user.bytes(), list),
        None => infinispan::marshall::java_serial::decode_stream(user.bytes()),
    }
    .map_err(|e| CodecError::Unreadable(e.to_string()))?;
    match values.pop() {
        Some(JavaValue::Object { class, levels }) if values.is_empty() && class.name == BLOB => blob_from_java(&class, &levels),
        other => Err(CodecError::Unreadable(format!("not a Blob: {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(json: serde_json::Value) -> ExpectationEntry {
        ExpectationEntry { id: "id-1".into(), priority: 5, created: 2000, remaining_times: -1, expectation_json: json }
    }

    #[test]
    fn versioned_expectation_entry_round_trips_through_the_allow_list() {
        let e = entry(json!({"httpRequest": {"path": "/x"}, "httpResponse": {"statusCode": 200}}));
        let object = wrap(&e, 3).unwrap();
        let (back, version): (ExpectationEntry, u64) = unwrap(&object, Some(clustered_allow_list())).unwrap();
        assert_eq!((back, version), (e, 3));
    }

    #[test]
    fn expectation_entry_field_layout_matches_the_recorded_class() {
        // the JDK orders primitives by name, then objects: created, priority, remainingTimes, id
        let JavaValue::Object { class, levels } = expectation_entry_to_java(&entry(json!({}))).unwrap() else { panic!() };
        assert_eq!(class.serial_version_uid, 2);
        assert_eq!(class.flags, SC_SERIALIZABLE | SC_WRITE_METHOD);
        assert_eq!(class.fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), ["created", "priority", "remainingTimes", "id"]);
        assert_eq!(levels[0].fields[..3], [FieldValue::Long(2000), FieldValue::Int(5), FieldValue::Int(-1)]);
    }

    #[test]
    fn expectation_json_over_65535_modified_utf8_bytes_fails_like_write_utf() {
        let big = "x".repeat(70_000);
        let err = expectation_entry_to_java(&entry(json!({"httpResponse": {"body": big}}))).unwrap_err();
        assert!(matches!(err, CodecError::UtfDataFormat { bytes } if bytes > 65_535), "{err}");
        assert!(err.to_string().contains("UTFDataFormatException"));
    }

    #[test]
    fn the_limit_counts_modified_utf8_bytes_not_characters() {
        // 30,000 characters of U+00E9 are 60,000 bytes in UTF-8 and under the limit; 40,000 are 80,000 over it
        let ok = entry(json!({"b": "\u{e9}".repeat(30_000)}));
        assert!(expectation_entry_to_java(&ok).is_ok());
        let over = entry(json!({"b": "\u{e9}".repeat(40_000)}));
        assert!(expectation_entry_to_java(&over).is_err());
        // U+0000 takes two bytes in modified UTF-8
        assert_eq!(modified_utf8("\0"), [0xc0, 0x80]);
        // a supplementary character is a pair of 3-byte surrogate halves, 6 bytes
        assert_eq!(modified_utf8("\u{1f600}").len(), 6);
    }

    #[test]
    fn long_payloads_are_runs_of_1024_byte_block_records() {
        let big = entry(json!({"b": "y".repeat(5000)}));
        let JavaValue::Object { levels, .. } = expectation_entry_to_java(&big).unwrap() else { panic!() };
        let sizes: Vec<usize> = levels[0].annotation.iter().map(|a| if let AnnotationItem::Block(b) = a { b.len() } else { 0 }).collect();
        assert!(sizes.len() > 4 && sizes[..sizes.len() - 1].iter().all(|n| *n == 1024), "{sizes:?}");
        let (back, _): (ExpectationEntry, u64) = unwrap(&wrap(&big, 1).unwrap(), None).unwrap();
        assert_eq!(back, big);
    }

    #[test]
    fn strings_and_object_nodes_round_trip() {
        let (s, v): (String, u64) = unwrap(&wrap(&"Filled".to_string(), 9).unwrap(), Some(clustered_allow_list())).unwrap();
        assert_eq!((s.as_str(), v), ("Filled", 9));
        let node = json!({"id": "a", "n": [1, 2, {"deep": true}]});
        let (back, v): (serde_json::Value, u64) = unwrap(&wrap(&node, 2).unwrap(), Some(clustered_allow_list())).unwrap();
        assert_eq!((back, v), (node, 2));
    }

    #[test]
    fn blobs_round_trip_with_and_without_metadata() {
        let plain = Blob { key: "expectations/a.json".into(), data: vec![1, 2, 3, 4], metadata: HashMap::new() };
        assert_eq!(read_blob(&blob_value(&plain), Some(clustered_allow_list())).unwrap(), plain);
        let meta = Blob { key: "k".into(), data: vec![9], metadata: HashMap::from([("contentType".to_string(), "text/plain".to_string())]) };
        assert_eq!(read_blob(&blob_value(&meta), Some(clustered_allow_list())).unwrap(), meta);
    }

    #[test]
    fn a_class_outside_the_allow_list_is_refused() {
        let foreign = JavaValue::Object {
            class: Rc::new(ClassDesc { name: "org.apache.commons.collections.functors.InvokerTransformer".into(), serial_version_uid: 1, flags: SC_SERIALIZABLE, fields: vec![], super_desc: None }),
            levels: vec![ObjectLevel::default()],
        };
        let hostile = user_value(&foreign);
        let err = unwrap::<String>(&hostile, Some(clustered_allow_list())).unwrap_err();
        assert!(err.to_string().contains("not in allowlist"), "{err}");
    }

    /// The streams the real classes wrote (`tests/files/cluster/java_serial.hex`, generated by the
    /// unmodified `VersionedWrapper`/`Blob`/`NodeSerialization` and a structural stand-in for `ExpectationEntry`):
    /// ours are the same bytes.
    #[test]
    fn encodings_are_byte_identical_to_the_recorded_java_streams() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/files/cluster/java_serial.hex")).expect("vector file");
        let vector = |label: &str| -> Vec<u8> {
            let hex = text.lines().find_map(|l| l.strip_prefix(&format!("{label}\t"))).unwrap_or_else(|| panic!("vector {label}"));
            (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect()
        };
        let bytes = |v: &JavaValue| encode_one(v);
        let wrapper = |value: &str, version: u64| match wrap(&value.to_string(), version).unwrap() {
            CacheObject::User(u) => u.bytes().to_vec(),
            other => panic!("{other:?}"),
        };
        assert_eq!(wrapper("hello", 1), vector("versioned_wrapper_string"));
        let blob = |key: &str, data: &[u8], metadata: HashMap<String, String>| bytes(&blob_to_java(&Blob { key: key.into(), data: data.to_vec(), metadata }));
        assert_eq!(blob("key1", &[1, 2, 3, 4], HashMap::new()), vector("blob_default_empty_map"));
        assert_eq!(blob("key2", &[9, 8, 7], HashMap::from([("contentType".to_string(), "text/plain".to_string())])), vector("blob_with_metadata"));
        assert_eq!(blob("key3", &[], HashMap::new()), vector("blob_empty_data"));
        let entry = |id: &str, priority: i64, created: u64, remaining: i64| ExpectationEntry { id: id.into(), priority, created, remaining_times: remaining, expectation_json: json!(null) };
        let with = |e: &ExpectationEntry, json: &str| bytes(&expectation_entry_with_json(e, json).unwrap());
        assert_eq!(with(&entry("id-1", 0, 1000, -1), r#"{"httpRequest":{"path":"/test"}}"#), vector("expectation_entry_unlimited"));
        assert_eq!(with(&entry("limited-id", 10, 2000, 5), r#"{"httpRequest":{"path":"/limited"}}"#), vector("expectation_entry_limited"));
    }

    /// A `VersionedWrapper<ObjectNode>` as the `clustered-8.0.0` JVM wrote it (captured from a service-chaos entry
    /// on port 7800): Jackson is shaded in the image, so the class is
    /// `shaded_package.com.fasterxml.jackson.databind.node.NodeSerialization`.
    const JVM_SHADED_OBJECT_NODE_WRAPPER: &str = "aced0005737200306f72672e6d6f636b7365727665722e73746174652e696e66696e697370616e2e56657273696f6e65645772617070657200000000000000010200024a000776657273696f6e4c000576616c75657400124c6a6176612f6c616e672f4f626a6563743b78700000000000000001737200447368616465645f7061636b6167652e636f6d2e666173746572786d6c2e6a61636b736f6e2e6461746162696e642e6e6f64652e4e6f646553657269616c697a6174696f6e00000000000000010c000078707737000000337b2270726f66696c65223a7b226572726f72537461747573223a3530337d2c226578706972657341744d696c6c6973223a307d78";

    fn jvm_bytes() -> Vec<u8> {
        let hex = JVM_SHADED_OBJECT_NODE_WRAPPER;
        (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn the_jvms_shaded_object_node_wrapper_is_read_and_written_byte_for_byte() {
        let object = CacheObject::User(UserValue::new(jvm_bytes()));
        let (node, version): (serde_json::Value, u64) = unwrap(&object, Some(clustered_allow_list())).unwrap();
        assert_eq!((&node, version), (&json!({"profile": {"errorStatus": 503}, "expiresAtMillis": 0}), 1));
        match wrap(&node, 1).unwrap() {
            CacheObject::User(u) => assert_eq!(u.bytes(), jvm_bytes().as_slice()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_unshaded_node_serialization_is_still_read() {
        // the unmodified-Jackson stream recorded in the infinispan-rs vectors (local mode, tests)
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/files/cluster/java_serial.hex")).unwrap();
        let hex = text.lines().find_map(|l| l.strip_prefix("node_serialization\t")).unwrap();
        let bytes: Vec<u8> = (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect();
        let values = infinispan::marshall::java_serial::decode_stream(&bytes).unwrap();
        assert_eq!(serde_json::Value::from_java(&values[0]).unwrap(), json!({}));
    }

    #[test]
    fn the_allow_list_is_the_ten_upstream_patterns() {
        assert_eq!(CLUSTERED_ALLOW_LIST_PATTERNS.len(), 10);
        assert!(CLUSTERED_ALLOW_LIST_PATTERNS.iter().all(|p| *p != ".*"), "no wildcard");
    }
}

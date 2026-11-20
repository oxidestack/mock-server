//! Dynamic protobuf messages for gRPC mocking: the message and enum types of uploaded `FileDescriptorSet`s, the
//! binary wire format, and protobuf-java's `JsonFormat` (the printer's layout and escaping, and the parser with
//! `ignoringUnknownFields`), well-known types included.

use std::collections::HashMap;

use base64::Engine;
use serde_json::Value;

// `FieldDescriptorProto.Type`.
const DOUBLE: u32 = 1;
const FLOAT: u32 = 2;
const INT64: u32 = 3;
const UINT64: u32 = 4;
const INT32: u32 = 5;
const FIXED64: u32 = 6;
const FIXED32: u32 = 7;
const BOOL: u32 = 8;
const STRING: u32 = 9;
const GROUP: u32 = 10;
const MESSAGE: u32 = 11;
const BYTES: u32 = 12;
const UINT32: u32 = 13;
const ENUM: u32 = 14;
const SFIXED32: u32 = 15;
const SFIXED64: u32 = 16;
const SINT32: u32 = 17;
const SINT64: u32 = 18;

#[derive(Debug, Clone)]
pub struct FieldDesc {
    pub name: String,
    pub json_name: String,
    pub number: u32,
    pub repeated: bool,
    pub kind: u32,
    /// The message or enum type, fully qualified without the leading dot.
    pub type_name: String,
    /// Tracks presence: proto2 singular fields, `optional` and oneof members in proto3, and messages.
    pub explicit_presence: bool,
    pub packed: bool,
}

#[derive(Debug, Clone)]
pub struct MessageDesc {
    pub full_name: String,
    pub fields: Vec<FieldDesc>,
    pub map_entry: bool,
}

#[derive(Debug, Clone)]
pub struct EnumDesc {
    pub values: Vec<(String, i32)>,
}

/// Every message and enum type known, by full name.
#[derive(Debug, Default, Clone)]
pub struct Pool {
    pub messages: HashMap<String, MessageDesc>,
    pub enums: HashMap<String, EnumDesc>,
}

// ---------------------------------------------------------------- wire format

fn varint(buf: &[u8], at: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *buf.get(*at).ok_or("While parsing a protocol message, the input ended unexpectedly in the middle of a field.")?;
        *at += 1;
        if shift < 64 {
            value |= u64::from(byte & 0x7f) << shift;
        }
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("CodedInputStream encountered a malformed varint.".into())
}

#[derive(Debug, Clone, Copy)]
enum Wire<'a> {
    Varint(u64),
    Fixed64(u64),
    Bytes(&'a [u8]),
    Fixed32(u32),
}

fn wire_fields(buf: &[u8]) -> Result<Vec<(u32, Wire<'_>)>, String> {
    let truncated = || "While parsing a protocol message, the input ended unexpectedly in the middle of a field.".to_string();
    let mut out = Vec::new();
    let mut at = 0;
    while at < buf.len() {
        let key = varint(buf, &mut at)?;
        let (number, wire) = ((key >> 3) as u32, key & 7);
        if number == 0 {
            return Err("Protocol message contained an invalid tag (zero).".into());
        }
        let field = match wire {
            0 => Wire::Varint(varint(buf, &mut at)?),
            1 => {
                let bytes = buf.get(at..at + 8).ok_or_else(truncated)?;
                at += 8;
                Wire::Fixed64(u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
            }
            2 => {
                let len = usize::try_from(varint(buf, &mut at)?).map_err(|_| truncated())?;
                let end = at.checked_add(len).filter(|e| *e <= buf.len()).ok_or_else(truncated)?;
                let bytes = &buf[at..end];
                at = end;
                Wire::Bytes(bytes)
            }
            5 => {
                let bytes = buf.get(at..at + 4).ok_or_else(truncated)?;
                at += 4;
                Wire::Fixed32(u32::from_le_bytes(bytes.try_into().expect("4 bytes")))
            }
            3 | 4 => return Err("Protocol message had invalid wire type (groups are not supported).".into()),
            _ => return Err("Protocol message tag had invalid wire type.".into()),
        };
        out.push((number, field));
    }
    Ok(out)
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn put_key(out: &mut Vec<u8>, number: u32, wire: u8) {
    put_varint(out, (u64::from(number) << 3) | u64::from(wire));
}

// ---------------------------------------------------------------- descriptors

fn text(w: &Wire) -> String {
    match w {
        Wire::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    }
}

/// `ToJsonName`: underscores removed, the letter after each capitalised.
pub fn json_name_of(name: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for c in name.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

impl Pool {
    /// Adds the types of a `FileDescriptorSet`; `Err` when it does not parse.
    pub fn add_set(&mut self, bytes: &[u8]) -> Result<(), String> {
        for (number, file) in wire_fields(bytes)? {
            if let (1, Wire::Bytes(file)) = (number, file) {
                self.add_file(file)?;
            }
        }
        Ok(())
    }

    fn add_file(&mut self, bytes: &[u8]) -> Result<(), String> {
        let fields = wire_fields(bytes)?;
        let package = fields.iter().find(|(n, _)| *n == 2).map(|(_, w)| text(w)).unwrap_or_default();
        let syntax = fields.iter().find(|(n, _)| *n == 12).map(|(_, w)| text(w)).unwrap_or_default();
        let proto3 = syntax == "proto3";
        for (number, w) in &fields {
            match (number, w) {
                (4, Wire::Bytes(m)) => self.add_message(m, &package, proto3)?,
                (5, Wire::Bytes(e)) => self.add_enum(e, &package)?,
                _ => {}
            }
        }
        Ok(())
    }

    fn add_enum(&mut self, bytes: &[u8], scope: &str) -> Result<(), String> {
        let fields = wire_fields(bytes)?;
        let name = fields.iter().find(|(n, _)| *n == 1).map(|(_, w)| text(w)).unwrap_or_default();
        let mut values = Vec::new();
        for (number, w) in &fields {
            if let (2, Wire::Bytes(v)) = (number, w) {
                let v = wire_fields(v)?;
                let value_name = v.iter().find(|(n, _)| *n == 1).map(|(_, w)| text(w)).unwrap_or_default();
                let value = v.iter().find_map(|(n, w)| match (n, w) {
                    (2, Wire::Varint(x)) => Some(*x as i32),
                    _ => None,
                });
                values.push((value_name, value.unwrap_or(0)));
            }
        }
        self.enums.insert(qualify(scope, &name), EnumDesc { values });
        Ok(())
    }

    fn add_message(&mut self, bytes: &[u8], scope: &str, proto3: bool) -> Result<(), String> {
        let fields = wire_fields(bytes)?;
        let name = fields.iter().find(|(n, _)| *n == 1).map(|(_, w)| text(w)).unwrap_or_default();
        let full = qualify(scope, &name);
        let mut map_entry = false;
        let mut out = Vec::new();
        for (number, w) in &fields {
            match (number, w) {
                (2, Wire::Bytes(f)) => out.push(field_desc(f, proto3)?),
                (3, Wire::Bytes(nested)) => self.add_message(nested, &full, proto3)?,
                (4, Wire::Bytes(e)) => self.add_enum(e, &full)?,
                (7, Wire::Bytes(options)) => {
                    map_entry = wire_fields(options)?.iter().any(|(n, w)| *n == 7 && matches!(w, Wire::Varint(v) if *v != 0));
                }
                _ => {}
            }
        }
        self.messages.insert(full.clone(), MessageDesc { full_name: full, fields: out, map_entry });
        Ok(())
    }

    fn message(&self, name: &str) -> Result<&MessageDesc, String> {
        self.messages.get(name).or_else(|| well_known(name)).ok_or_else(|| format!("unknown message type: {name}"))
    }
}

fn qualify(scope: &str, name: &str) -> String {
    if scope.is_empty() { name.to_string() } else { format!("{scope}.{name}") }
}

fn field_desc(bytes: &[u8], proto3: bool) -> Result<FieldDesc, String> {
    let fields = wire_fields(bytes)?;
    let get_text = |n: u32| fields.iter().find(|(k, _)| *k == n).map(|(_, w)| text(w));
    let get_int = |n: u32| {
        fields.iter().find_map(|(k, w)| match w {
            Wire::Varint(v) if *k == n => Some(*v),
            _ => None,
        })
    };
    let name = get_text(1).unwrap_or_default();
    let label = get_int(4).unwrap_or(1);
    let kind = get_int(5).unwrap_or(0) as u32;
    let oneof = get_int(9).is_some();
    let proto3_optional = get_int(17).is_some_and(|v| v != 0);
    let packed_option = fields.iter().find(|(k, _)| *k == 8).and_then(|(_, w)| match w {
        Wire::Bytes(o) => wire_fields(o).ok()?.iter().find_map(|(n, w)| match (n, w) {
            (2, Wire::Varint(v)) => Some(*v != 0),
            _ => None,
        }),
        _ => None,
    });
    let repeated = label == 3;
    let scalar = !matches!(kind, STRING | BYTES | MESSAGE | GROUP);
    Ok(FieldDesc {
        json_name: get_text(10).unwrap_or_else(|| json_name_of(&name)),
        name,
        number: get_int(3).unwrap_or(0) as u32,
        repeated,
        kind,
        type_name: get_text(6).map(|t| t.trim_start_matches('.').to_string()).unwrap_or_default(),
        explicit_presence: !repeated && (!proto3 || oneof || proto3_optional || kind == MESSAGE || kind == GROUP),
        packed: repeated && scalar && packed_option.unwrap_or(proto3),
    })
}

/// The well-known types, for descriptor sets that reference them without including them.
fn well_known(name: &str) -> Option<&'static MessageDesc> {
    static TYPES: std::sync::LazyLock<HashMap<String, MessageDesc>> = std::sync::LazyLock::new(|| {
        let field = |name: &str, number: u32, kind: u32, type_name: &str, repeated: bool| FieldDesc {
            name: name.into(),
            json_name: json_name_of(name),
            number,
            repeated,
            kind,
            type_name: type_name.into(),
            explicit_presence: kind == MESSAGE && !repeated,
            packed: repeated && !matches!(kind, STRING | BYTES | MESSAGE),
        };
        let message = |name: &str, fields: Vec<FieldDesc>, map_entry: bool| (format!("google.protobuf.{name}"), MessageDesc { full_name: format!("google.protobuf.{name}"), fields, map_entry });
        let mut types: HashMap<String, MessageDesc> = [
            message("Timestamp", vec![field("seconds", 1, INT64, "", false), field("nanos", 2, INT32, "", false)], false),
            message("Duration", vec![field("seconds", 1, INT64, "", false), field("nanos", 2, INT32, "", false)], false),
            message("DoubleValue", vec![field("value", 1, DOUBLE, "", false)], false),
            message("FloatValue", vec![field("value", 1, FLOAT, "", false)], false),
            message("Int64Value", vec![field("value", 1, INT64, "", false)], false),
            message("UInt64Value", vec![field("value", 1, UINT64, "", false)], false),
            message("Int32Value", vec![field("value", 1, INT32, "", false)], false),
            message("UInt32Value", vec![field("value", 1, UINT32, "", false)], false),
            message("BoolValue", vec![field("value", 1, BOOL, "", false)], false),
            message("StringValue", vec![field("value", 1, STRING, "", false)], false),
            message("BytesValue", vec![field("value", 1, BYTES, "", false)], false),
            message("Empty", vec![], false),
            message("FieldMask", vec![field("paths", 1, STRING, "", true)], false),
            message("Any", vec![field("type_url", 1, STRING, "", false), field("value", 2, BYTES, "", false)], false),
            message("Struct", vec![field("fields", 1, MESSAGE, "google.protobuf.Struct.FieldsEntry", true)], false),
            message("Struct.FieldsEntry", vec![field("key", 1, STRING, "", false), field("value", 2, MESSAGE, "google.protobuf.Value", false)], true),
            message("ListValue", vec![field("values", 1, MESSAGE, "google.protobuf.Value", true)], false),
        ]
        .into_iter()
        .collect();
        let mut value_fields = vec![
            field("null_value", 1, ENUM, "google.protobuf.NullValue", false),
            field("number_value", 2, DOUBLE, "", false),
            field("string_value", 3, STRING, "", false),
            field("bool_value", 4, BOOL, "", false),
            field("struct_value", 5, MESSAGE, "google.protobuf.Struct", false),
            field("list_value", 6, MESSAGE, "google.protobuf.ListValue", false),
        ];
        for f in &mut value_fields {
            f.explicit_presence = true;
        }
        types.insert("google.protobuf.Value".into(), MessageDesc { full_name: "google.protobuf.Value".into(), fields: value_fields, map_entry: false });
        types
    });
    TYPES.get(name)
}

// ---------------------------------------------------------------- decoded values

#[derive(Debug, Clone)]
enum Val {
    I64(i64),
    U64(u64),
    F64(f64),
    F32(f32),
    Bool(bool),
    Str(String),
    Bytes(Vec<u8>),
    Enum(i32),
    Msg(Box<Msg>),
}

/// A decoded message: each set field (by index into its descriptor's fields) with its values, in field-number order.
#[derive(Debug, Clone)]
struct Msg {
    desc: String,
    fields: Vec<(usize, Vec<Val>)>,
}

fn zigzag32(v: u64) -> i64 {
    let v = v as u32;
    i64::from(((v >> 1) as i32) ^ -((v & 1) as i32))
}

fn zigzag64(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

fn scalar(kind: u32, w: Wire) -> Option<Val> {
    Some(match (kind, w) {
        (INT32, Wire::Varint(v)) => Val::I64(i64::from(v as i32)),
        (INT64, Wire::Varint(v)) => Val::I64(v as i64),
        (UINT32, Wire::Varint(v)) => Val::U64(u64::from(v as u32)),
        (UINT64, Wire::Varint(v)) => Val::U64(v),
        (SINT32, Wire::Varint(v)) => Val::I64(zigzag32(v)),
        (SINT64, Wire::Varint(v)) => Val::I64(zigzag64(v)),
        (BOOL, Wire::Varint(v)) => Val::Bool(v != 0),
        (ENUM, Wire::Varint(v)) => Val::Enum(v as i32),
        (FIXED32, Wire::Fixed32(v)) => Val::U64(u64::from(v)),
        (SFIXED32, Wire::Fixed32(v)) => Val::I64(i64::from(v as i32)),
        (FLOAT, Wire::Fixed32(v)) => Val::F32(f32::from_bits(v)),
        (FIXED64, Wire::Fixed64(v)) => Val::U64(v),
        (SFIXED64, Wire::Fixed64(v)) => Val::I64(v as i64),
        (DOUBLE, Wire::Fixed64(v)) => Val::F64(f64::from_bits(v)),
        _ => return None,
    })
}

/// Unpacks a packed run of scalars.
fn packed(kind: u32, bytes: &[u8]) -> Result<Vec<Val>, String> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let w = match kind {
            FIXED32 | SFIXED32 | FLOAT => {
                let b = bytes.get(at..at + 4).ok_or("truncated packed field")?;
                at += 4;
                Wire::Fixed32(u32::from_le_bytes(b.try_into().expect("4 bytes")))
            }
            FIXED64 | SFIXED64 | DOUBLE => {
                let b = bytes.get(at..at + 8).ok_or("truncated packed field")?;
                at += 8;
                Wire::Fixed64(u64::from_le_bytes(b.try_into().expect("8 bytes")))
            }
            _ => Wire::Varint(varint(bytes, &mut at)?),
        };
        out.extend(scalar(kind, w));
    }
    Ok(out)
}

impl Pool {
    fn decode(&self, type_name: &str, bytes: &[u8]) -> Result<Msg, String> {
        let desc = self.message(type_name)?;
        let wire = wire_fields(bytes)?;
        let mut fields: Vec<(usize, Vec<Val>)> = Vec::new();
        // A singular message field seen more than once merges: its occurrences are decoded together.
        let mut message_bytes: Vec<(usize, Vec<u8>)> = Vec::new();
        for (number, w) in wire {
            let Some(index) = desc.fields.iter().position(|f| f.number == number) else { continue };
            let field = &desc.fields[index];
            let mut values = Vec::new();
            match (field.kind, w) {
                (MESSAGE, Wire::Bytes(b)) if !field.repeated => {
                    match message_bytes.iter_mut().find(|(i, _)| *i == index) {
                        Some((_, existing)) => existing.extend_from_slice(b),
                        None => message_bytes.push((index, b.to_vec())),
                    }
                    if !fields.iter().any(|(i, _)| *i == index) {
                        fields.push((index, Vec::new()));
                    }
                    continue;
                }
                (MESSAGE, Wire::Bytes(b)) => values.push(Val::Msg(Box::new(self.decode(&field.type_name, b)?))),
                (STRING, Wire::Bytes(b)) => values.push(Val::Str(String::from_utf8(b.to_vec()).map_err(|_| "Protocol message had invalid UTF-8.".to_string())?)),
                (BYTES, Wire::Bytes(b)) => values.push(Val::Bytes(b.to_vec())),
                (kind, Wire::Bytes(b)) if !matches!(kind, STRING | BYTES | MESSAGE | GROUP) => values.extend(packed(kind, b)?),
                (kind, w) => match scalar(kind, w) {
                    Some(v) => values.push(v),
                    None => continue,
                },
            }
            match fields.iter_mut().find(|(i, _)| *i == index) {
                Some((_, existing)) if field.repeated => existing.extend(values),
                Some((_, existing)) => *existing = values.split_off(values.len().saturating_sub(1)),
                None => {
                    let values = if field.repeated { values } else { values.split_off(values.len().saturating_sub(1)) };
                    fields.push((index, values));
                }
            }
        }
        for (index, bytes) in message_bytes {
            let decoded = self.decode(&desc.fields[index].type_name, &bytes)?;
            if let Some((_, values)) = fields.iter_mut().find(|(i, _)| *i == index) {
                *values = vec![Val::Msg(Box::new(decoded))];
            }
        }
        fields.sort_by_key(|(i, _)| desc.fields[*i].number);
        Ok(Msg { desc: desc.full_name.clone(), fields })
    }

    // ------------------------------------------------------------ JsonFormat printer

    /// `JsonFormat.printer().print`: the message's JSON as protobuf-java lays it out.
    pub fn to_json(&self, type_name: &str, bytes: &[u8]) -> Result<String, String> {
        let msg = self.decode(type_name, bytes)?;
        let mut out = String::new();
        self.print_message(&msg, 0, &mut out)?;
        Ok(out)
    }

    fn print_message(&self, msg: &Msg, indent: usize, out: &mut String) -> Result<(), String> {
        if let Some(special) = self.print_well_known(msg, indent, out)? {
            return Ok(special);
        }
        let desc = self.message(&msg.desc)?;
        out.push_str("{\n");
        let mut first = true;
        for (index, values) in &msg.fields {
            let field = &desc.fields[*index];
            if !field.explicit_presence && !field.repeated && values.first().is_some_and(is_default) {
                continue;
            }
            if field.repeated && values.is_empty() {
                continue;
            }
            if !first {
                out.push_str(",\n");
            }
            first = false;
            pad(out, indent + 1);
            out.push_str(&json_string(&field.json_name));
            out.push_str(": ");
            let map = self.messages.get(&field.type_name).or_else(|| well_known(&field.type_name)).filter(|m| m.map_entry);
            match (map, field.repeated) {
                (Some(entry), true) => self.print_map(entry, values, indent + 1, out)?,
                (None, true) => {
                    out.push('[');
                    for (i, v) in values.iter().enumerate() {
                        if i > 0 {
                            out.push_str(", ");
                        }
                        self.print_value(field, v, indent + 1, out)?;
                    }
                    out.push(']');
                }
                _ => match values.first() {
                    Some(v) => self.print_value(field, v, indent + 1, out)?,
                    None => self.print_message(&Msg { desc: field.type_name.clone(), fields: Vec::new() }, indent + 1, out)?,
                },
            }
        }
        if !first {
            out.push('\n');
        }
        pad(out, indent);
        out.push('}');
        Ok(())
    }

    fn print_map(&self, entry: &MessageDesc, values: &[Val], indent: usize, out: &mut String) -> Result<(), String> {
        let (Some(key_field), Some(value_field)) = (entry.fields.iter().find(|f| f.number == 1), entry.fields.iter().find(|f| f.number == 2)) else {
            return Err("invalid map entry".into());
        };
        // `MapField`: a later entry with the same key replaces the value in place.
        let mut entries: Vec<(String, Option<Val>)> = Vec::new();
        for v in values {
            let Val::Msg(m) = v else { continue };
            let get = |n: u32| m.fields.iter().find(|(i, _)| entry.fields[*i].number == n).and_then(|(_, vs)| vs.last().cloned());
            let key = match get(1) {
                Some(Val::Str(s)) => s,
                Some(Val::Bool(b)) => b.to_string(),
                Some(Val::I64(i)) => i.to_string(),
                Some(Val::U64(u)) => u.to_string(),
                _ => default_key(key_field.kind),
            };
            let value = get(2);
            match entries.iter_mut().find(|(k, _)| *k == key) {
                Some(existing) => existing.1 = value,
                None => entries.push((key, value)),
            }
        }
        out.push_str("{\n");
        for (i, (key, value)) in entries.iter().enumerate() {
            if i > 0 {
                out.push_str(",\n");
            }
            pad(out, indent + 1);
            out.push_str(&json_string(key));
            out.push_str(": ");
            match value {
                Some(v) => self.print_value(value_field, v, indent + 1, out)?,
                None => self.print_value(value_field, &default_value(value_field), indent + 1, out)?,
            }
        }
        if !entries.is_empty() {
            out.push('\n');
        }
        pad(out, indent);
        out.push('}');
        Ok(())
    }

    fn print_value(&self, field: &FieldDesc, value: &Val, indent: usize, out: &mut String) -> Result<(), String> {
        match value {
            Val::Msg(m) => self.print_message(m, indent, out)?,
            Val::Enum(n) => {
                if field.type_name == "google.protobuf.NullValue" {
                    out.push_str("null");
                } else {
                    match self.enums.get(&field.type_name).and_then(|e| e.values.iter().find(|(_, v)| v == n)) {
                        Some((name, _)) => out.push_str(&json_string(name)),
                        None => out.push_str(&n.to_string()),
                    }
                }
            }
            other => out.push_str(&scalar_json(field.kind, other)),
        }
        Ok(())
    }

    /// Timestamp, Duration, the wrappers, Struct/Value/ListValue, FieldMask, Any: their special JSON forms.
    fn print_well_known(&self, msg: &Msg, indent: usize, out: &mut String) -> Result<Option<()>, String> {
        let get = |n: u32| {
            let desc = self.message(&msg.desc).ok()?;
            msg.fields.iter().find(|(i, _)| desc.fields[*i].number == n).map(|(_, v)| v.clone())
        };
        let int = |n: u32| match get(n).and_then(|v| v.last().cloned()) {
            Some(Val::I64(i)) => i,
            _ => 0,
        };
        match msg.desc.as_str() {
            "google.protobuf.Timestamp" => out.push_str(&json_string(&timestamp(int(1), int(2) as i32)?)),
            "google.protobuf.Duration" => out.push_str(&json_string(&duration(int(1), int(2) as i32)?)),
            "google.protobuf.DoubleValue" | "google.protobuf.FloatValue" | "google.protobuf.Int64Value" | "google.protobuf.UInt64Value" | "google.protobuf.Int32Value"
            | "google.protobuf.UInt32Value" | "google.protobuf.BoolValue" | "google.protobuf.StringValue" | "google.protobuf.BytesValue" => {
                let field = &self.message(&msg.desc)?.fields[0];
                let value = get(1).and_then(|v| v.last().cloned()).unwrap_or_else(|| default_value(field));
                out.push_str(&scalar_json(field.kind, &value));
            }
            "google.protobuf.FieldMask" => {
                let paths: Vec<String> = get(1).unwrap_or_default().iter().filter_map(|v| if let Val::Str(s) = v { Some(json_name_of(s)) } else { None }).collect();
                out.push_str(&json_string(&paths.join(",")));
            }
            "google.protobuf.Struct" => {
                let entry = self.message("google.protobuf.Struct.FieldsEntry")?.clone();
                self.print_map(&entry, &get(1).unwrap_or_default(), indent, out)?;
            }
            "google.protobuf.ListValue" => {
                let values = get(1).unwrap_or_default();
                let field = self.message("google.protobuf.ListValue")?.fields[0].clone();
                out.push('[');
                for (i, v) in values.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    self.print_value(&field, v, indent, out)?;
                }
                out.push(']');
            }
            "google.protobuf.Value" => {
                let desc = self.message(&msg.desc)?;
                let Some((index, values)) = msg.fields.first() else { return Err("Value message must have a value set".into()) };
                let field = &desc.fields[*index];
                match values.last() {
                    Some(v) => self.print_value(field, v, indent, out)?,
                    None => return Err("Value message must have a value set".into()),
                }
            }
            "google.protobuf.Any" => {
                let url = match get(1).and_then(|v| v.last().cloned()) {
                    Some(Val::Str(s)) => s,
                    _ => String::new(),
                };
                let bytes = match get(2).and_then(|v| v.last().cloned()) {
                    Some(Val::Bytes(b)) => b,
                    _ => Vec::new(),
                };
                if url.is_empty() && bytes.is_empty() {
                    out.push_str("{\n");
                    pad(out, indent);
                    out.push('}');
                    return Ok(Some(()));
                }
                let type_name = url.rsplit('/').next().unwrap_or_default();
                let inner = self.decode(type_name, &bytes).map_err(|_| format!("Cannot find type for url: {url}"))?;
                out.push_str("{\n");
                pad(out, indent + 1);
                out.push_str("\"@type\": ");
                out.push_str(&json_string(&url));
                if is_special(type_name) {
                    let mut rendered = String::new();
                    self.print_message(&inner, indent + 1, &mut rendered)?;
                    out.push_str(",\n");
                    pad(out, indent + 1);
                    out.push_str("\"value\": ");
                    out.push_str(&rendered);
                } else {
                    let mut rendered = String::new();
                    self.print_message(&inner, indent, &mut rendered)?;
                    // The inner object's members, spliced after `@type`.
                    let body = rendered.strip_prefix("{\n").and_then(|r| r.rsplit_once('\n')).map(|(b, _)| b.to_string()).unwrap_or_default();
                    if !body.trim().is_empty() {
                        out.push_str(",\n");
                        out.push_str(&body);
                    }
                }
                out.push('\n');
                pad(out, indent);
                out.push('}');
            }
            _ => return Ok(None),
        }
        Ok(Some(()))
    }
}

fn is_special(type_name: &str) -> bool {
    matches!(
        type_name,
        "google.protobuf.Timestamp"
            | "google.protobuf.Duration"
            | "google.protobuf.FieldMask"
            | "google.protobuf.Struct"
            | "google.protobuf.Value"
            | "google.protobuf.ListValue"
            | "google.protobuf.Any"
            | "google.protobuf.DoubleValue"
            | "google.protobuf.FloatValue"
            | "google.protobuf.Int64Value"
            | "google.protobuf.UInt64Value"
            | "google.protobuf.Int32Value"
            | "google.protobuf.UInt32Value"
            | "google.protobuf.BoolValue"
            | "google.protobuf.StringValue"
            | "google.protobuf.BytesValue"
    )
}

fn pad(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

fn is_default(v: &Val) -> bool {
    match v {
        Val::I64(i) => *i == 0,
        Val::U64(u) => *u == 0,
        Val::F64(f) => *f == 0.0 && f.is_sign_positive(),
        Val::F32(f) => *f == 0.0 && f.is_sign_positive(),
        Val::Bool(b) => !*b,
        Val::Str(s) => s.is_empty(),
        Val::Bytes(b) => b.is_empty(),
        Val::Enum(n) => *n == 0,
        Val::Msg(_) => false,
    }
}

fn default_value(field: &FieldDesc) -> Val {
    match field.kind {
        DOUBLE => Val::F64(0.0),
        FLOAT => Val::F32(0.0),
        INT64 | INT32 | SINT32 | SINT64 | SFIXED32 | SFIXED64 => Val::I64(0),
        UINT64 | UINT32 | FIXED32 | FIXED64 => Val::U64(0),
        BOOL => Val::Bool(false),
        STRING => Val::Str(String::new()),
        BYTES => Val::Bytes(Vec::new()),
        ENUM => Val::Enum(0),
        _ => Val::Msg(Box::new(Msg { desc: field.type_name.clone(), fields: Vec::new() })),
    }
}

fn default_key(kind: u32) -> String {
    match kind {
        STRING => String::new(),
        BOOL => "false".into(),
        _ => "0".into(),
    }
}

fn scalar_json(kind: u32, v: &Val) -> String {
    let special = |s: &str| format!("\"{s}\"");
    match v {
        Val::I64(i) if matches!(kind, INT64 | SINT64 | SFIXED64) => format!("\"{i}\""),
        Val::U64(u) if matches!(kind, UINT64 | FIXED64) => format!("\"{u}\""),
        Val::I64(i) => i.to_string(),
        Val::U64(u) => u.to_string(),
        Val::F64(f) if f.is_nan() => special("NaN"),
        Val::F64(f) if f.is_infinite() => special(if *f > 0.0 { "Infinity" } else { "-Infinity" }),
        Val::F64(f) => java_compat::double_to_string(*f),
        Val::F32(f) if f.is_nan() => special("NaN"),
        Val::F32(f) if f.is_infinite() => special(if *f > 0.0 { "Infinity" } else { "-Infinity" }),
        Val::F32(f) => java_compat::float_to_string(*f),
        Val::Bool(b) => b.to_string(),
        Val::Str(s) => json_string(s),
        // Base64 is quoted as it is, without the string escaping.
        Val::Bytes(b) => format!("\"{}\"", base64::engine::general_purpose::STANDARD.encode(b)),
        Val::Enum(n) => n.to_string(),
        Val::Msg(_) => "{}".into(),
    }
}

/// Gson's string escaping, HTML-safe as protobuf's printer leaves it.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '<' | '>' | '&' | '=' | '\'' | '\u{2028}' | '\u{2029}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `Timestamps.toString`: RFC 3339 in UTC with 0, 3, 6 or 9 fractional digits.
fn timestamp(seconds: i64, nanos: i32) -> Result<String, String> {
    if !(-62_135_596_800..=253_402_300_799).contains(&seconds) || !(0..1_000_000_000).contains(&nanos) {
        return Err(format!("Timestamp is not valid. See proto definition for valid values. Seconds ({seconds}) must be in range [-62,135,596,800, +253,402,300,799]. Nanos ({nanos}) must be in range [0, +999,999,999]."));
    }
    let date = chrono::DateTime::from_timestamp(seconds, 0).ok_or("invalid timestamp")?;
    Ok(format!("{}{}Z", date.format("%Y-%m-%dT%H:%M:%S"), fraction(nanos)))
}

fn fraction(nanos: i32) -> String {
    if nanos == 0 {
        String::new()
    } else if nanos % 1_000_000 == 0 {
        format!(".{:03}", nanos / 1_000_000)
    } else if nanos % 1_000 == 0 {
        format!(".{:06}", nanos / 1_000)
    } else {
        format!(".{nanos:09}")
    }
}

/// `Durations.toString`.
fn duration(seconds: i64, nanos: i32) -> Result<String, String> {
    if !(-315_576_000_000..=315_576_000_000).contains(&seconds) || nanos.abs() >= 1_000_000_000 || (seconds != 0 && nanos != 0 && (seconds < 0) != (nanos < 0)) {
        return Err(format!("Duration is not valid. See proto definition for valid values. Seconds ({seconds}) must be in range [-315,576,000,000, +315,576,000,000]. Nanos ({nanos}) must be in range [-999,999,999, +999,999,999]. Nanos must have the same sign as seconds"));
    }
    let negative = seconds < 0 || nanos < 0;
    Ok(format!("{}{}{}s", if negative { "-" } else { "" }, seconds.abs(), fraction(nanos.abs())))
}

// ---------------------------------------------------------------- JsonFormat parser

impl Pool {
    /// `JsonFormat.parser().ignoringUnknownFields().merge`, then `toByteArray`.
    pub fn from_json(&self, type_name: &str, json: &str) -> Result<Vec<u8>, String> {
        let value: Value = serde_json::from_str(json).map_err(|e| format!("Expect message object but got: {e}"))?;
        let mut out = Vec::new();
        self.encode_message(type_name, &value, &mut out)?;
        Ok(out)
    }

    fn encode_message(&self, type_name: &str, value: &Value, out: &mut Vec<u8>) -> Result<(), String> {
        if self.encode_well_known(type_name, value, out)? {
            return Ok(());
        }
        let desc = self.message(type_name)?;
        let Value::Object(object) = value else { return Err(format!("Expect message object but got: {value}")) };
        let mut set: Vec<(&FieldDesc, &Value)> = Vec::new();
        for (key, v) in object {
            let Some(field) = desc.fields.iter().find(|f| f.json_name == *key || f.name == *key) else { continue };
            if v.is_null() && field.type_name != "google.protobuf.Value" {
                continue;
            }
            // `ignoringUnknownFields`: an enum name the type does not declare is dropped too.
            if field.kind == ENUM && !field.repeated && self.unknown_enum_name(field, v) {
                continue;
            }
            set.retain(|(f, _)| f.number != field.number);
            set.push((field, v));
        }
        set.sort_by_key(|(f, _)| f.number);
        for (field, v) in set {
            self.encode_field(field, v, out)?;
        }
        Ok(())
    }

    fn encode_field(&self, field: &FieldDesc, value: &Value, out: &mut Vec<u8>) -> Result<(), String> {
        let map = self.messages.get(&field.type_name).or_else(|| well_known(&field.type_name)).filter(|m| m.map_entry).cloned();
        if let (Some(entry), true) = (map, field.repeated) {
            let Value::Object(object) = value else { return Err(format!("Expect a map object but found: {value}")) };
            let key_field = entry.fields.iter().find(|f| f.number == 1).ok_or("invalid map entry")?;
            let value_field = entry.fields.iter().find(|f| f.number == 2).ok_or("invalid map entry")?;
            for (k, v) in object {
                let mut body = Vec::new();
                let key_value = match key_field.kind {
                    STRING => Value::String(k.clone()),
                    BOOL => Value::Bool(k == "true"),
                    _ => Value::String(k.clone()),
                };
                self.encode_single(key_field, &key_value, &mut body)?;
                if !v.is_null() || value_field.type_name == "google.protobuf.Value" {
                    self.encode_single(value_field, v, &mut body)?;
                }
                put_key(out, field.number, 2);
                put_varint(out, body.len() as u64);
                out.extend(body);
            }
            return Ok(());
        }
        if field.repeated {
            let Value::Array(items) = value else { return Err(format!("Expected an array for {} but found {value}", field.name)) };
            let items: Vec<&Value> = items.iter().filter(|i| !(field.kind == ENUM && self.unknown_enum_name(field, i))).collect();
            if field.packed {
                let mut body = Vec::new();
                for item in items {
                    self.scalar_bytes(field, item, &mut body)?;
                }
                if !body.is_empty() {
                    put_key(out, field.number, 2);
                    put_varint(out, body.len() as u64);
                    out.extend(body);
                }
            } else {
                for item in items {
                    self.encode_single(field, item, out)?;
                }
            }
            return Ok(());
        }
        // Proto3 implicit-presence fields at their default value are not written.
        let mut body = Vec::new();
        self.encode_single(field, value, &mut body)?;
        if !field.explicit_presence && self.is_default_encoding(field, value) {
            return Ok(());
        }
        out.extend(body);
        Ok(())
    }

    fn unknown_enum_name(&self, field: &FieldDesc, value: &Value) -> bool {
        let Value::String(name) = value else { return false };
        field.type_name != "google.protobuf.NullValue"
            && name.parse::<i64>().is_err()
            && !self.enums.get(&field.type_name).is_some_and(|e| e.values.iter().any(|(n, _)| n == name))
    }

    fn is_default_encoding(&self, field: &FieldDesc, value: &Value) -> bool {
        let mut probe = Vec::new();
        self.scalar_bytes(field, value, &mut probe).is_ok() && {
            match field.kind {
                STRING | BYTES => probe.is_empty(),
                FIXED32 | SFIXED32 | FLOAT => probe == [0, 0, 0, 0],
                FIXED64 | SFIXED64 | DOUBLE => probe == [0; 8],
                _ => probe == [0],
            }
        }
    }

    fn encode_single(&self, field: &FieldDesc, value: &Value, out: &mut Vec<u8>) -> Result<(), String> {
        match field.kind {
            MESSAGE | GROUP => {
                let mut body = Vec::new();
                self.encode_message(&field.type_name, value, &mut body)?;
                put_key(out, field.number, 2);
                put_varint(out, body.len() as u64);
                out.extend(body);
            }
            STRING | BYTES => {
                let mut body = Vec::new();
                self.scalar_bytes(field, value, &mut body)?;
                put_key(out, field.number, 2);
                put_varint(out, body.len() as u64);
                out.extend(body);
            }
            FIXED32 | SFIXED32 | FLOAT => {
                put_key(out, field.number, 5);
                self.scalar_bytes(field, value, out)?;
            }
            FIXED64 | SFIXED64 | DOUBLE => {
                put_key(out, field.number, 1);
                self.scalar_bytes(field, value, out)?;
            }
            _ => {
                put_key(out, field.number, 0);
                self.scalar_bytes(field, value, out)?;
            }
        }
        Ok(())
    }

    /// A scalar's payload bytes (no key): varint, fixed, or the raw string/bytes.
    fn scalar_bytes(&self, field: &FieldDesc, value: &Value, out: &mut Vec<u8>) -> Result<(), String> {
        let bad = || format!("Not an {} value: {value}", kind_name(field.kind));
        match field.kind {
            STRING => match value {
                Value::String(s) => out.extend_from_slice(s.as_bytes()),
                _ => return Err(format!("Expected a string but found: {value}")),
            },
            BYTES => match value {
                Value::String(s) => {
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(s)
                        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
                        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s.trim_end_matches('=')))
                        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')))
                        .map_err(|_| format!("Invalid bytes value: {s}"))?;
                    out.extend(decoded);
                }
                _ => return Err(bad()),
            },
            BOOL => match value {
                Value::Bool(b) => out.push(u8::from(*b)),
                Value::String(s) if s == "true" || s == "false" => out.push(u8::from(s == "true")),
                _ => return Err(format!("Invalid bool value: {value}")),
            },
            ENUM => {
                let number = match value {
                    Value::String(s) => match self.enums.get(&field.type_name).and_then(|e| e.values.iter().find(|(n, _)| n == s)) {
                        Some((_, v)) => i64::from(*v),
                        None => s.parse::<i64>().map_err(|_| format!("Invalid enum value: {s} for enum type: {}", field.type_name))?,
                    },
                    Value::Number(n) => n.as_i64().ok_or_else(bad)?,
                    Value::Null if field.type_name == "google.protobuf.NullValue" => 0,
                    _ => return Err(bad()),
                };
                put_varint(out, number as u64);
            }
            FLOAT | DOUBLE => {
                let f = match value {
                    Value::Number(n) => n.as_f64().ok_or_else(bad)?,
                    Value::String(s) => match s.as_str() {
                        "NaN" => f64::NAN,
                        "Infinity" => f64::INFINITY,
                        "-Infinity" => f64::NEG_INFINITY,
                        _ => s.parse::<f64>().map_err(|_| bad())?,
                    },
                    _ => return Err(bad()),
                };
                if field.kind == FLOAT {
                    out.extend_from_slice(&(f as f32).to_le_bytes());
                } else {
                    out.extend_from_slice(&f.to_le_bytes());
                }
            }
            _ => {
                let integer = integer_of(value).ok_or_else(bad)?;
                match field.kind {
                    INT32 | SFIXED32 | SINT32 if i32::try_from(integer).is_err() => return Err(bad()),
                    UINT32 | FIXED32 if u32::try_from(integer).is_err() => return Err(bad()),
                    INT64 | SFIXED64 | SINT64 if i64::try_from(integer).is_err() => return Err(bad()),
                    UINT64 | FIXED64 if u64::try_from(integer).is_err() => return Err(bad()),
                    _ => {}
                }
                match field.kind {
                    INT32 | INT64 => put_varint(out, integer as i64 as u64),
                    UINT32 | UINT64 => put_varint(out, integer as u64),
                    SINT32 => put_varint(out, u64::from((((integer as i32) << 1) ^ ((integer as i32) >> 31)) as u32)),
                    SINT64 => put_varint(out, (((integer as i64) << 1) ^ ((integer as i64) >> 63)) as u64),
                    FIXED32 => out.extend_from_slice(&(integer as u32).to_le_bytes()),
                    SFIXED32 => out.extend_from_slice(&(integer as i32).to_le_bytes()),
                    FIXED64 => out.extend_from_slice(&(integer as u64).to_le_bytes()),
                    SFIXED64 => out.extend_from_slice(&(integer as i64).to_le_bytes()),
                    _ => return Err(bad()),
                }
            }
        }
        Ok(())
    }

    /// Well-known types from their special JSON forms; `false` for any other type.
    fn encode_well_known(&self, type_name: &str, value: &Value, out: &mut Vec<u8>) -> Result<bool, String> {
        let field = |number: u32, kind: u32, type_name: &str, repeated: bool| FieldDesc {
            name: String::new(),
            json_name: String::new(),
            number,
            repeated,
            kind,
            type_name: type_name.into(),
            explicit_presence: false,
            packed: false,
        };
        match type_name {
            "google.protobuf.Timestamp" => {
                let Value::String(s) = value else { return Err(format!("Failed to parse timestamp: {value}")) };
                let parsed = chrono::DateTime::parse_from_rfc3339(s).map_err(|_| format!("Failed to parse timestamp: {s}"))?;
                let (seconds, nanos) = (parsed.timestamp(), parsed.timestamp_subsec_nanos() as i64);
                self.encode_field(&field(1, INT64, "", false), &Value::from(seconds), out)?;
                self.encode_field(&field(2, INT32, "", false), &Value::from(nanos), out)?;
            }
            "google.protobuf.Duration" => {
                let Value::String(s) = value else { return Err(format!("Failed to parse duration: {value}")) };
                let (seconds, nanos) = parse_duration(s).ok_or_else(|| format!("Failed to parse duration: {s}"))?;
                self.encode_field(&field(1, INT64, "", false), &Value::from(seconds), out)?;
                self.encode_field(&field(2, INT32, "", false), &Value::from(nanos), out)?;
            }
            "google.protobuf.DoubleValue" | "google.protobuf.FloatValue" | "google.protobuf.Int64Value" | "google.protobuf.UInt64Value" | "google.protobuf.Int32Value"
            | "google.protobuf.UInt32Value" | "google.protobuf.BoolValue" | "google.protobuf.StringValue" | "google.protobuf.BytesValue" => {
                let inner = self.message(type_name)?.fields[0].clone();
                self.encode_field(&inner, value, out)?;
            }
            "google.protobuf.FieldMask" => {
                let Value::String(s) = value else { return Err(format!("Expected a string but found: {value}")) };
                for path in s.split(',').filter(|p| !p.is_empty()) {
                    let snake: String = path.chars().flat_map(|c| if c.is_ascii_uppercase() { vec!['_', c.to_ascii_lowercase()] } else { vec![c] }).collect();
                    self.encode_single(&field(1, STRING, "", false), &Value::String(snake), out)?;
                }
            }
            "google.protobuf.Struct" => {
                let Value::Object(_) = value else { return Err(format!("Expect a map object but found: {value}")) };
                self.encode_field(&field(1, MESSAGE, "google.protobuf.Struct.FieldsEntry", true), value, out)?;
            }
            "google.protobuf.ListValue" => {
                let Value::Array(_) = value else { return Err(format!("Expect an array but found: {value}")) };
                self.encode_field(&field(1, MESSAGE, "google.protobuf.Value", true), value, out)?;
            }
            "google.protobuf.Value" => match value {
                Value::Null => self.encode_single(&field(1, ENUM, "google.protobuf.NullValue", false), &Value::Null, out)?,
                Value::Number(_) => self.encode_single(&field(2, DOUBLE, "", false), value, out)?,
                Value::String(_) => self.encode_single(&field(3, STRING, "", false), value, out)?,
                Value::Bool(_) => self.encode_single(&field(4, BOOL, "", false), value, out)?,
                Value::Object(_) => self.encode_single(&field(5, MESSAGE, "google.protobuf.Struct", false), value, out)?,
                Value::Array(_) => self.encode_single(&field(6, MESSAGE, "google.protobuf.ListValue", false), value, out)?,
            },
            "google.protobuf.Any" => {
                let Value::Object(object) = value else { return Err(format!("Expect message object but got: {value}")) };
                if object.is_empty() {
                    return Ok(true);
                }
                let url = object.get("@type").and_then(Value::as_str).ok_or("Missing type url when parsing: Any")?;
                let inner_type = url.rsplit('/').next().unwrap_or_default();
                let mut body = Vec::new();
                if is_special(inner_type) {
                    self.encode_message(inner_type, object.get("value").unwrap_or(&Value::Null), &mut body)?;
                } else {
                    let mut rest = object.clone();
                    rest.remove("@type");
                    self.encode_message(inner_type, &Value::Object(rest), &mut body)?;
                }
                self.encode_single(&field(1, STRING, "", false), &Value::String(url.to_string()), out)?;
                put_key(out, 2, 2);
                put_varint(out, body.len() as u64);
                out.extend(body);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

fn kind_name(kind: u32) -> &'static str {
    match kind {
        INT32 | SINT32 | SFIXED32 => "int32",
        INT64 | SINT64 | SFIXED64 => "int64",
        UINT32 | FIXED32 => "uint32",
        UINT64 | FIXED64 => "uint64",
        _ => "number",
    }
}

/// An integral JSON value: a number (an integral double such as `1.0` too) or a numeric string.
fn integer_of(value: &Value) -> Option<i128> {
    match value {
        Value::Number(n) => n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from)).or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i128)),
        Value::String(s) => s.parse::<i128>().ok().or_else(|| s.parse::<f64>().ok().filter(|f| f.fract() == 0.0).map(|f| f as i128)),
        _ => None,
    }
}

fn parse_duration(s: &str) -> Option<(i64, i64)> {
    let body = s.strip_suffix('s')?;
    let (negative, body) = match body.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, body),
    };
    let (seconds, fraction) = body.split_once('.').unwrap_or((body, ""));
    if seconds.is_empty() || !seconds.chars().all(|c| c.is_ascii_digit()) || fraction.len() > 9 || !fraction.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let seconds: i64 = seconds.parse().ok()?;
    let nanos: i64 = if fraction.is_empty() { 0 } else { format!("{fraction:0<9}").parse().ok()? };
    Some(if negative { (-seconds, -nanos) } else { (seconds, nanos) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(file: &str) -> Pool {
        let mut pool = Pool::default();
        let path = format!("{}/upstream/mockserver/mockserver/mockserver-core/src/test/resources/grpc/{file}", env!("CARGO_MANIFEST_DIR"));
        if let Ok(bytes) = std::fs::read(path) {
            pool.add_set(&bytes).expect("descriptor set parses");
        }
        pool
    }

    #[test]
    fn round_trips_against_protobuf_java() {
        let pool = pool("orders.dsc");
        if pool.messages.is_empty() {
            return;
        }
        let json = r#"{"orderId":"o1","total":{"currencyCode":"EUR","units":"12"},"placedAt":"2024-01-02T03:04:05.500Z","processingTime":"1.5s","note":"a<b","expedited":true,"quantity":3}"#;
        let bytes = pool.from_json("com.example.orders.Order", json).unwrap();
        // protobuf-java 4.36.1's bytes and printed JSON for the same input.
        let expected = "0a026f3112070a03455552100c1a0c08a5facdac061080cab5ee01220808011080cab5ee012a050a03613c62320208013a020803";
        assert_eq!(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(), expected);
        assert_eq!(
            pool.to_json("com.example.orders.Order", &bytes).unwrap(),
            "{\n  \"orderId\": \"o1\",\n  \"total\": {\n    \"currencyCode\": \"EUR\",\n    \"units\": \"12\"\n  },\n  \"placedAt\": \"2024-01-02T03:04:05.500Z\",\n  \"processingTime\": \"1.500s\",\n  \"note\": \"a\\u003cb\",\n  \"expedited\": true,\n  \"quantity\": 3\n}"
        );
        assert_eq!(pool.to_json("com.example.orders.Order", &[]).unwrap(), "{\n}");
    }

    /// Vectors recorded from protobuf-java 4.36.1 (`JsonFormat.parser().ignoringUnknownFields()`, `printer()`) for a
    /// message with a field of every kind.
    #[test]
    fn matches_protobuf_java_vectors() {
        let dir = format!("{}/tests/files/protobuf", env!("CARGO_MANIFEST_DIR"));
        let mut pool = Pool::default();
        pool.add_set(&std::fs::read(format!("{dir}/alltypes.dsc")).unwrap()).unwrap();
        let vectors: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/alltypes_vectors.json")).unwrap()).unwrap();
        let mut failures = Vec::new();
        for v in vectors {
            let json = v["json"].as_str().unwrap();
            let encoded = pool.from_json("t.AllTypes", json);
            match (&encoded, v.get("hex").and_then(Value::as_str), v.get("error").and_then(Value::as_str)) {
                (Ok(bytes), Some(hex), _) => {
                    let actual: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                    if actual != hex {
                        failures.push(format!("{json}: bytes {actual} != {hex}"));
                        continue;
                    }
                    let printed = pool.to_json("t.AllTypes", bytes).unwrap_or_else(|e| e);
                    if printed != v["printed"].as_str().unwrap() {
                        failures.push(format!("{json}: printed {printed:?} != {:?}", v["printed"].as_str().unwrap()));
                    }
                }
                (Err(e), None, Some(expected)) if e == expected => {}
                (other, _, _) => failures.push(format!("{json}: {other:?} vs {v}")),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}

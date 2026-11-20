//! JSON output byte-compatible with Jackson's `DefaultPrettyPrinter`, which is what MockServer emits (§2.10).
//!
//! Objects put each field on its own line, indented two spaces per nesting level, with `" : "` between key and
//! value; arrays stay inline (`[ 1, 2 ]`, `[ {` … `}, {` … `} ]`) and do not add a nesting level. Empty containers
//! print as `{ }` and `[ ]`.

use std::io;

use serde::Serialize;
use serde_json::ser::Formatter;

#[derive(Default)]
pub struct JacksonFormatter {
    depth: usize,
    /// Per open container: whether it has had a value yet.
    has_value: Vec<bool>,
}

impl JacksonFormatter {
    fn newline_indent<W: ?Sized + io::Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(b"\n")?;
        for _ in 0..self.depth {
            w.write_all(b"  ")?;
        }
        Ok(())
    }
}

impl Formatter for JacksonFormatter {
    fn begin_object<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.depth += 1;
        self.has_value.push(false);
        w.write_all(b"{")
    }

    fn end_object<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.depth -= 1;
        if self.has_value.pop().unwrap_or(false) {
            self.newline_indent(w)?;
            w.write_all(b"}")
        } else {
            w.write_all(b" }")
        }
    }

    fn begin_object_key<W: ?Sized + io::Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        if !first {
            w.write_all(b",")?;
        }
        if let Some(v) = self.has_value.last_mut() {
            *v = true;
        }
        self.newline_indent(w)
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        w.write_all(b" : ")
    }

    fn begin_array<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.has_value.push(false);
        w.write_all(b"[")
    }

    fn end_array<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.has_value.pop();
        w.write_all(b" ]")
    }

    fn begin_array_value<W: ?Sized + io::Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        if let Some(v) = self.has_value.last_mut() {
            *v = true;
        }
        w.write_all(if first { b" " } else { b", " })
    }

    /// Jackson's `WriterBasedJsonGenerator._appendCharacterEscape`: other control characters as `\u00XX` with
    /// upper-case hex digits (`CharTypes.HC`), where serde_json writes lower-case ones.
    fn write_char_escape<W: ?Sized + io::Write>(&mut self, w: &mut W, escape: serde_json::ser::CharEscape) -> io::Result<()> {
        use serde_json::ser::CharEscape;
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let short: &[u8] = match escape {
            CharEscape::Quote => b"\\\"",
            CharEscape::ReverseSolidus => b"\\\\",
            CharEscape::Solidus => b"\\/",
            CharEscape::Backspace => b"\\b",
            CharEscape::FormFeed => b"\\f",
            CharEscape::LineFeed => b"\\n",
            CharEscape::CarriageReturn => b"\\r",
            CharEscape::Tab => b"\\t",
            CharEscape::AsciiControl(b) => return w.write_all(&[b'\\', b'u', b'0', b'0', HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]]),
        };
        w.write_all(short)
    }
}

/// Jackson's compact writer (no pretty printer): no whitespace at all, escapes as [`JacksonFormatter`] writes them.
struct JacksonCompactFormatter;

impl Formatter for JacksonCompactFormatter {
    fn write_char_escape<W: ?Sized + io::Write>(&mut self, w: &mut W, escape: serde_json::ser::CharEscape) -> io::Result<()> {
        JacksonFormatter::default().write_char_escape(w, escape)
    }
}

/// Serialises `value` the way MockServer's compact Jackson writer (`ObjectMapperFactory.createObjectMapper(false,
/// false)`) does.
pub fn compact<T: Serialize + ?Sized>(value: &T) -> String {
    let mut out = Vec::with_capacity(256);
    let mut ser = serde_json::Serializer::with_formatter(&mut out, JacksonCompactFormatter);
    value.serialize(&mut ser).expect("serialising JSON into memory cannot fail");
    String::from_utf8(out).expect("serde_json emits UTF-8")
}

/// Parses JSON as leniently as MockServer's Jackson mapper (`ObjectMapperFactory`): comments (`//`, `/* */`, `#`),
/// single quotes, unquoted field names, raw control characters in strings, backslash before any character, leading
/// zeros, `NaN`/`Infinity`, missing array values, trailing commas, and anything after the root value ignored.
/// Strict JSON is tried first; the error is the strict parser's.
pub fn parse_lenient(bytes: &[u8]) -> Result<serde_json::Value, serde_json::Error> {
    match serde_json::from_slice(bytes) {
        Ok(v) => Ok(v),
        Err(strict) => std::str::from_utf8(bytes).ok().and_then(|text| Lenient { s: text.as_bytes(), i: 0, non_finite_as_text: false }.root()).ok_or(strict),
    }
}

/// [`parse_lenient`] for a reader that prints values (the properties file): `NaN`, `Infinity` and `-Infinity`
/// come back as the strings `Double.toString` gives them instead of `null`, which a `serde_json` number cannot carry.
pub fn parse_lenient_non_finite_as_text(bytes: &[u8]) -> Result<serde_json::Value, serde_json::Error> {
    match serde_json::from_slice(bytes) {
        Ok(v) => Ok(v),
        Err(strict) => std::str::from_utf8(bytes).ok().and_then(|text| Lenient { s: text.as_bytes(), i: 0, non_finite_as_text: true }.root()).ok_or(strict),
    }
}

struct Lenient<'a> {
    s: &'a [u8],
    i: usize,
    non_finite_as_text: bool,
}

impl Lenient<'_> {
    fn root(mut self) -> Option<serde_json::Value> {
        self.skip();
        // `FAIL_ON_TRAILING_TOKENS` is off: whatever follows the first value is ignored.
        self.value()
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    /// Whitespace and comments.
    fn skip(&mut self) {
        while let Some(c) = self.peek() {
            match c {
                b' ' | b'\t' | b'\n' | b'\r' => self.i += 1,
                b'#' => self.skip_line(),
                b'/' if self.s.get(self.i + 1) == Some(&b'/') => self.skip_line(),
                b'/' if self.s.get(self.i + 1) == Some(&b'*') => {
                    self.i += 2;
                    while self.i < self.s.len() && !(self.s[self.i] == b'*' && self.s.get(self.i + 1) == Some(&b'/')) {
                        self.i += 1;
                    }
                    self.i = (self.i + 2).min(self.s.len());
                }
                _ => return,
            }
        }
    }

    fn skip_line(&mut self) {
        while let Some(c) = self.peek() {
            self.i += 1;
            if c == b'\n' {
                return;
            }
        }
    }

    fn value(&mut self) -> Option<serde_json::Value> {
        use serde_json::Value;
        match self.peek()? {
            b'{' => self.object(),
            b'[' => self.array(),
            q @ (b'"' | b'\'') => self.string(q).map(Value::String),
            b'-' | b'0'..=b'9' => self.number(),
            _ => {
                for (word, v) in [("true", Value::Bool(true)), ("false", Value::Bool(false)), ("null", Value::Null)] {
                    if self.s[self.i..].starts_with(word.as_bytes()) && !self.s.get(self.i + word.len()).is_some_and(|c| c.is_ascii_alphanumeric()) {
                        self.i += word.len();
                        return Some(v);
                    }
                }
                for (word, text) in [("NaN", "NaN"), ("Infinity", "Infinity"), ("+Infinity", "Infinity"), ("+INF", "Infinity")] {
                    if self.s[self.i..].starts_with(word.as_bytes()) {
                        self.i += word.len();
                        return Some(if self.non_finite_as_text { Value::String(text.to_string()) } else { Value::Null });
                    }
                }
                None
            }
        }
    }

    fn object(&mut self) -> Option<serde_json::Value> {
        self.i += 1;
        let mut map = serde_json::Map::new();
        loop {
            self.skip();
            match self.peek()? {
                b'}' => {
                    self.i += 1;
                    return Some(serde_json::Value::Object(map));
                }
                q @ (b'"' | b'\'') => {
                    let key = self.string(q)?;
                    self.member(&mut map, key)?;
                }
                c if c == b'_' || c == b'$' || c.is_ascii_alphanumeric() || c >= 0x80 => {
                    let start = self.i;
                    while self.peek().is_some_and(|c| c == b'_' || c == b'$' || c.is_ascii_alphanumeric() || c >= 0x80) {
                        self.i += 1;
                    }
                    let key = std::str::from_utf8(&self.s[start..self.i]).ok()?.to_string();
                    self.member(&mut map, key)?;
                }
                _ => return None,
            }
            self.skip();
            match self.peek()? {
                b',' => self.i += 1,
                b'}' => {}
                _ => return None,
            }
        }
    }

    fn member(&mut self, map: &mut serde_json::Map<String, serde_json::Value>, key: String) -> Option<()> {
        self.skip();
        (self.peek()? == b':').then_some(())?;
        self.i += 1;
        self.skip();
        // `ALLOW_MISSING_VALUES`: `{"a": ,}` holds a null.
        let v = if self.peek()? == b',' { serde_json::Value::Null } else { self.value()? };
        map.insert(key, v);
        Some(())
    }

    fn array(&mut self) -> Option<serde_json::Value> {
        self.i += 1;
        let mut items = Vec::new();
        loop {
            self.skip();
            match self.peek()? {
                b']' => {
                    self.i += 1;
                    return Some(serde_json::Value::Array(items));
                }
                // `ALLOW_MISSING_VALUES`: `[1,,2]` holds a null.
                b',' => {
                    self.i += 1;
                    items.push(serde_json::Value::Null);
                    continue;
                }
                _ => items.push(self.value()?),
            }
            self.skip();
            match self.peek()? {
                b',' => self.i += 1,
                b']' => {}
                _ => return None,
            }
        }
    }

    fn string(&mut self, quote: u8) -> Option<String> {
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                c if c == quote => return String::from_utf8(out).ok(),
                b'\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let unit = |p: &mut Self| -> Option<u32> {
                                let hex = std::str::from_utf8(p.s.get(p.i..p.i + 4)?).ok()?;
                                p.i += 4;
                                u32::from_str_radix(hex, 16).ok()
                            };
                            let first = unit(self)?;
                            let c = if (0xD800..0xDC00).contains(&first) && self.s[self.i..].starts_with(b"\\u") {
                                self.i += 2;
                                let second = unit(self)?;
                                char::from_u32(0x10000 + ((first - 0xD800) << 10) + (second.wrapping_sub(0xDC00) & 0x3FF))
                            } else {
                                char::from_u32(first)
                            }
                            .unwrap_or('\u{fffd}');
                            out.extend(c.to_string().as_bytes());
                        }
                        // `ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER`: `\x` is `x`.
                        other => out.push(other),
                    }
                }
                c => out.push(c),
            }
        }
    }

    fn number(&mut self) -> Option<serde_json::Value> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
            // `-Infinity`, or `-INF`
            if let Some(len) = [&b"Infinity"[..], &b"INF"[..]].iter().find(|w| self.s[self.i..].starts_with(w)).map(|w| w.len()) {
                self.i += len;
                return Some(if self.non_finite_as_text { serde_json::Value::String("-Infinity".to_string()) } else { serde_json::Value::Null });
            }
        }
        let digits = |p: &mut Self| {
            let from = p.i;
            while p.peek().is_some_and(|c| c.is_ascii_digit()) {
                p.i += 1;
            }
            p.i > from
        };
        digits(self).then_some(())?;
        let int_end = self.i;
        if self.peek() == Some(b'.') {
            self.i += 1;
            digits(self).then_some(())?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            digits(self).then_some(())?;
        }
        let text = std::str::from_utf8(&self.s[start..self.i]).ok()?;
        // `ALLOW_NUMERIC_LEADING_ZEROS`: `007` is 7.
        let (sign, rest) = text.strip_prefix('-').map(|r| ("-", r)).unwrap_or(("", text));
        let int_len = int_end - start - sign.len();
        let int_part = rest[..int_len].trim_start_matches('0');
        let int_part = if int_part.is_empty() { "0" } else { int_part };
        Some(crate::model::number(&format!("{sign}{int_part}{}", &rest[int_len..])))
    }
}

/// Serialises `value` the way MockServer's Jackson `ObjectWriter` with the default pretty printer does.
pub fn pretty<T: Serialize + ?Sized>(value: &T) -> String {
    let mut out = Vec::with_capacity(256);
    let mut ser = serde_json::Serializer::with_formatter(&mut out, JacksonFormatter::default());
    value.serialize(&mut ser).expect("serialising JSON into memory cannot fail");
    String::from_utf8(out).expect("serde_json emits UTF-8")
}

/// [`pretty`] over a list of expectations (or an object holding one), with each expectation's `metadata` written as
/// compact JSON on one line, as upstream's `MetadataJson` text is embedded.
pub fn pretty_expectations(value: &serde_json::Value) -> String {
    use serde_json::Value;
    fn mark(v: &mut Value, raw: &mut Vec<String>) {
        match v {
            Value::Array(items) => items.iter_mut().for_each(|i| mark(i, raw)),
            Value::Object(o) => {
                if let Some(m) = o.get_mut("metadata").filter(|m| m.is_object()) {
                    raw.push(m.to_string());
                    *m = Value::String(format!("\u{1}raw-metadata-{}\u{1}", raw.len() - 1));
                }
                if let Some(list) = o.get_mut("expectations") {
                    mark(list, raw);
                }
            }
            _ => {}
        }
    }
    let mut marked = value.clone();
    let mut raw = Vec::new();
    mark(&mut marked, &mut raw);
    let mut out = pretty(&marked);
    for (i, text) in raw.iter().enumerate() {
        out = out.replace(&format!("\"{}\"", pretty(&format!("\u{1}raw-metadata-{i}\u{1}")).trim_matches('"')), text);
    }
    out
}

/// Jackson's `DefaultPrettyPrinter` with line-feed indenters for arrays as well as objects (`LogEntrySerializer`):
/// every non-empty array and object spreads over lines.
pub fn pretty_multiline(value: &serde_json::Value) -> String {
    fn write(v: &serde_json::Value, depth: usize, out: &mut String) {
        let pad = |d: usize| "  ".repeat(d);
        match v {
            serde_json::Value::Array(items) if items.is_empty() => out.push_str("[ ]"),
            serde_json::Value::Object(o) if o.is_empty() => out.push_str("{ }"),
            serde_json::Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    out.push_str(if i == 0 { "\n" } else { ",\n" });
                    out.push_str(&pad(depth + 1));
                    write(item, depth + 1, out);
                }
                out.push('\n');
                out.push_str(&pad(depth));
                out.push(']');
            }
            serde_json::Value::Object(o) => {
                out.push('{');
                for (i, (k, item)) in o.iter().enumerate() {
                    out.push_str(if i == 0 { "\n" } else { ",\n" });
                    out.push_str(&pad(depth + 1));
                    out.push_str(&pretty(k));
                    out.push_str(" : ");
                    write(item, depth + 1, out);
                }
                out.push('\n');
                out.push_str(&pad(depth));
                out.push('}');
            }
            scalar => out.push_str(&pretty(scalar)),
        }
    }
    let mut out = String::new();
    write(value, 0, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::{parse_lenient, pretty};

    #[test]
    fn lenient_like_jackson() {
        let v = parse_lenient(b"{\n  // c\n  'a': 'x\ny', b: [1,,007, 2.50,], # yaml\n  \"c\": \"\\q\", /* x */ }trailing").unwrap();
        assert_eq!(v.to_string(), r#"{"a":"x\ny","b":[1,null,7,2.50],"c":"q"}"#);
        assert!(parse_lenient(b"hello /m32").is_err());
        assert!(parse_lenient(b"").is_err());
    }

    #[test]
    fn control_characters_escape_with_upper_case_hex_like_jackson() {
        assert_eq!(pretty("\u{1f}\u{0e}\u{1}\u{8}\u{c}\n\"\\/"), r#""\u001F\u000E\u0001\b\f\n\"\\/""#);
    }
    use serde_json::json;

    #[test]
    fn matches_mockservers_expectation_output() {
        // Byte-for-byte from the oracle's 201 body.
        let v = json!([{
            "httpRequest": {"path": "/hello", "queryStringParameters": {"q": ["v"]}},
            "httpResponse": {"body": {"a": 1}},
            "priority": 0,
            "times": {"unlimited": true}
        }]);
        assert_eq!(
            pretty(&v),
            "[ {\n  \"httpRequest\" : {\n    \"path\" : \"/hello\",\n    \"queryStringParameters\" : {\n      \"q\" : [ \"v\" ]\n    }\n  },\n  \"httpResponse\" : {\n    \"body\" : {\n      \"a\" : 1\n    }\n  },\n  \"priority\" : 0,\n  \"times\" : {\n    \"unlimited\" : true\n  }\n} ]"
        );
    }

    #[test]
    fn several_objects_in_an_array_and_empty_containers() {
        assert_eq!(pretty(&json!([{"a": 1}, {"b": []}, {}])), "[ {\n  \"a\" : 1\n}, {\n  \"b\" : [ ]\n}, { } ]");
    }

    #[test]
    fn scalar_arrays_stay_inline() {
        assert_eq!(pretty(&json!({"ports": [1080, 1081]})), "{\n  \"ports\" : [ 1080, 1081 ]\n}");
    }
}

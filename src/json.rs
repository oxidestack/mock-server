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
    /// Per open container, innermost last: whether it has had a value yet. The first 64 are bits of `open`, any deeper in
    /// `deeper`, so printing a value allocates nothing of its own.
    open: u64,
    opened: usize,
    deeper: Vec<bool>,
}

impl JacksonFormatter {
    fn newline_indent<W: ?Sized + io::Write>(&self, w: &mut W) -> io::Result<()> {
        const SPACES: &[u8; 64] = &[b' '; 64];
        w.write_all(b"
")?;
        let mut left = self.depth * 2;
        while left > 0 {
            let n = left.min(SPACES.len());
            w.write_all(&SPACES[..n])?;
            left -= n;
        }
        Ok(())
    }

    /// A container opened, with no value yet.
    fn push(&mut self) {
        if self.opened < 64 {
            self.open &= !(1 << self.opened);
        } else {
            self.deeper.push(false);
        }
        self.opened += 1;
    }

    /// The innermost container closed: whether it had a value.
    fn pop(&mut self) -> bool {
        if self.opened == 0 {
            return false;
        }
        self.opened -= 1;
        if self.opened < 64 { self.open & (1 << self.opened) != 0 } else { self.deeper.pop().unwrap_or(false) }
    }

    /// The innermost container has a value.
    fn mark(&mut self) {
        match self.opened {
            0 => {}
            n if n <= 64 => self.open |= 1 << (n - 1),
            _ => {
                if let Some(v) = self.deeper.last_mut() {
                    *v = true;
                }
            }
        }
    }
}

impl Formatter for JacksonFormatter {
    fn begin_object<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.depth += 1;
        self.push();
        w.write_all(b"{")
    }

    fn end_object<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.depth -= 1;
        if self.pop() {
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
        self.mark();
        self.newline_indent(w)
    }

    fn begin_object_value<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        w.write_all(b" : ")
    }

    fn begin_array<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.push();
        w.write_all(b"[")
    }

    fn end_array<W: ?Sized + io::Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.pop();
        w.write_all(b" ]")
    }

    fn begin_array_value<W: ?Sized + io::Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        self.mark();
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

/// [`pretty`] of a JSON value (or of anything that serialises as one without failing), appended to `out`.
pub fn pretty_into<T: Serialize + ?Sized>(out: &mut String, value: &T) {
    // SAFETY: serde_json writes whole UTF-8 sequences only (keys and strings come from `str`, everything else is
    // ASCII, and a string is cut only at an escape, which is ASCII), and what is written here cannot fail to serialise
    // (a `Value`, or a view of one with string keys), so `out` holds valid UTF-8 whenever this returns or unwinds
    let bytes = unsafe { out.as_mut_vec() };
    let mut ser = serde_json::Serializer::with_formatter(bytes, JacksonFormatter::default());
    value.serialize(&mut ser).expect("serialising JSON into memory cannot fail");
}

/// [`pretty_into`] of a JSON body's tree as the log prints it (read by [`parse_lenient`], its floats as `BigDecimal`s:
/// [`crate::model::big_decimal_in_place`]), at formatter depth `depth`, written straight from `text` without building
/// the tree. Only a body that is one object or array of strict JSON with nothing after it is written so; `false`, and
/// `out` as it was, for any other (a scalar, a duplicate key, a key with an escape, an object of many keys, a deep
/// nesting, anything only the lenient reader takes), which the caller renders from the tree.
pub fn pretty_text_into(out: &mut String, text: &str, depth: usize) -> bool {
    let start = out.len();
    let mut writer = PrettyText { s: text.as_bytes(), text, i: 0, keys: Vec::new() };
    writer.skip();
    let written = matches!(writer.peek(), Some(b'{' | b'[')) && writer.value(out, depth, 0).is_some() && {
        writer.skip();
        writer.i == writer.s.len()
    };
    if !written {
        out.truncate(start);
    }
    written
}

/// [`pretty_text_into`]'s reader: `s` is `text`'s bytes, `keys` the keys of the objects open, innermost last.
struct PrettyText<'a> {
    s: &'a [u8],
    text: &'a str,
    i: usize,
    keys: Vec<&'a str>,
}

impl<'a> PrettyText<'a> {
    /// The nesting `serde_json` reads (its recursion limit is 128), kept well below it.
    const MAX_DEPTH: usize = 100;
    /// The most keys an object may have to be written here: duplicates are looked for by comparing every pair.
    const MAX_KEYS: usize = 32;

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    /// JSON whitespace (`serde_json` takes no other).
    fn skip(&mut self) {
        while let Some(b' ' | b'\n' | b'\t' | b'\r') = self.peek() {
            self.i += 1;
        }
    }

    fn newline_indent(out: &mut String, depth: usize) {
        const SPACES: &str = "                                                                ";
        out.push('\n');
        let mut left = depth * 2;
        while left > 0 {
            let n = left.min(SPACES.len());
            out.push_str(&SPACES[..n]);
            left -= n;
        }
    }

    /// One value at the cursor (whitespace skipped), written as [`JacksonFormatter`] writes it at `depth`, inside
    /// `level` arrays and objects of the text.
    fn value(&mut self, out: &mut String, depth: usize, level: usize) -> Option<()> {
        if level >= Self::MAX_DEPTH {
            return None;
        }
        match self.peek()? {
            b'{' => {
                self.i += 1;
                self.skip();
                if self.peek()? == b'}' {
                    self.i += 1;
                    out.push_str("{ }");
                    return Some(());
                }
                let depth = depth + 1;
                out.push('{');
                let keys_from = self.keys.len();
                loop {
                    if self.keys.len() > keys_from {
                        out.push(',');
                    }
                    Self::newline_indent(out, depth);
                    // a key: its text as it is (one with an escape is not written here), never one seen before in
                    // this object (the tree keeps a repeated key at its first place with its last value)
                    let key = self.raw_string()?;
                    if self.keys.len() - keys_from >= Self::MAX_KEYS || self.keys[keys_from..].contains(&key) {
                        return None;
                    }
                    self.keys.push(key);
                    out.push('"');
                    escape_into(out, key);
                    out.push('"');
                    self.skip();
                    if self.peek()? != b':' {
                        return None;
                    }
                    self.i += 1;
                    self.skip();
                    out.push_str(" : ");
                    self.value(out, depth, level + 1)?;
                    self.skip();
                    match self.peek()? {
                        b',' => {
                            self.i += 1;
                            self.skip();
                        }
                        b'}' => {
                            self.i += 1;
                            break;
                        }
                        _ => return None,
                    }
                }
                self.keys.truncate(keys_from);
                Self::newline_indent(out, depth - 1);
                out.push('}');
            }
            b'[' => {
                self.i += 1;
                self.skip();
                if self.peek()? == b']' {
                    self.i += 1;
                    out.push_str("[ ]");
                    return Some(());
                }
                // an array opens no indentation level of its own
                out.push('[');
                let mut first = true;
                loop {
                    out.push_str(if first { " " } else { ", " });
                    first = false;
                    self.value(out, depth, level + 1)?;
                    self.skip();
                    match self.peek()? {
                        b',' => {
                            self.i += 1;
                            self.skip();
                        }
                        b']' => {
                            self.i += 1;
                            break;
                        }
                        _ => return None,
                    }
                }
                out.push_str(" ]");
            }
            b'"' => {
                let start = self.i;
                let raw = self.raw_string_or_escaped()?;
                out.push('"');
                match raw {
                    Some(raw) => escape_into(out, raw),
                    // the escapes decoded as `serde_json` decodes them (a lone surrogate is refused) and written again
                    None => escape_into(out, &serde_json::from_str::<String>(&self.text[start..self.i]).ok()?),
                }
                out.push('"');
            }
            b't' => self.literal(out, "true")?,
            b'f' => self.literal(out, "false")?,
            b'n' => self.literal(out, "null")?,
            b'-' | b'0'..=b'9' => self.number(out)?,
            _ => return None,
        }
        Some(())
    }

    fn literal(&mut self, out: &mut String, word: &str) -> Option<()> {
        if !self.s[self.i..].starts_with(word.as_bytes()) {
            return None;
        }
        self.i += word.len();
        out.push_str(word);
        Some(())
    }

    /// A string at the cursor without escapes, its contents; `None` for one with an escape or a control character.
    fn raw_string(&mut self) -> Option<&'a str> {
        self.raw_string_or_escaped()?
    }

    /// A string at the cursor read past: `Some(Some(contents))` without escapes, `Some(None)` with one; `None` for
    /// a control character (`serde_json` refuses it) or no closing quote.
    fn raw_string_or_escaped(&mut self) -> Option<Option<&'a str>> {
        if self.peek()? != b'"' {
            return None;
        }
        let from = self.i + 1;
        let mut at = from;
        let mut escaped = false;
        loop {
            match *self.s.get(at)? {
                b'"' => break,
                b'\\' => {
                    escaped = true;
                    at += 2;
                }
                0x00..=0x1f => return None,
                _ => at += 1,
            }
        }
        self.i = at + 1;
        Some((!escaped).then(|| &self.text[from..at]))
    }

    /// A number at the cursor, as `serde_json`'s arbitrary-precision reader keeps it (the exponent's letter lower-case,
    /// `-0` read as the integer 0) and [`crate::model::big_decimal_in_place`] prints a fraction or exponent.
    fn number(&mut self, out: &mut String) -> Option<()> {
        let from = self.i;
        let digits = |s: &[u8], mut at: usize| {
            let start = at;
            while let Some(b'0'..=b'9') = s.get(at) {
                at += 1;
            }
            (at > start).then_some(at)
        };
        let mut at = from;
        if self.s[at] == b'-' {
            at += 1;
        }
        let int_from = at;
        at = digits(self.s, at)?;
        // one leading zero at most
        if self.s[int_from] == b'0' && at - int_from > 1 {
            return None;
        }
        let mut fraction = false;
        if self.s.get(at) == Some(&b'.') {
            at = digits(self.s, at + 1)?;
            fraction = true;
        }
        let mut exponent = false;
        if let Some(b'e' | b'E') = self.s.get(at) {
            at += 1;
            if let Some(b'+' | b'-') = self.s.get(at) {
                at += 1;
            }
            at = digits(self.s, at)?;
            exponent = true;
        }
        self.i = at;
        let lexeme = &self.text[from..at];
        if !fraction && !exponent {
            out.push_str(if lexeme == "-0" { "0" } else { lexeme });
            return Some(());
        }
        let read = lexeme.replace('E', "e");
        match java_compat::big_decimal_to_string(&read) {
            Some(text) => out.push_str(&text),
            None => out.push_str(&read),
        }
        Some(())
    }
}

/// A string's contents escaped as `serde_json` escapes them with [`JacksonFormatter`]'s escapes.
fn escape_into(out: &mut String, text: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = text.as_bytes();
    let mut from = 0;
    for (at, &b) in bytes.iter().enumerate() {
        let short = match b {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            0x08 => "\\b",
            0x0c => "\\f",
            b'\n' => "\\n",
            b'\r' => "\\r",
            b'\t' => "\\t",
            0x00..=0x1f => "",
            _ => continue,
        };
        out.push_str(&text[from..at]);
        if short.is_empty() {
            out.push_str("\\u00");
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0xf)]));
        } else {
            out.push_str(short);
        }
        from = at + 1;
    }
    out.push_str(&text[from..]);
}

/// [`pretty`] over a list of expectations (or an object holding one), with each expectation's `metadata` written as
/// compact JSON on one line, as upstream's `MetadataJson` text is embedded.
pub fn pretty_expectations(value: &serde_json::Value) -> String {
    pretty_expectations_owned(value.clone())
}

/// [`pretty_expectations`] of a value no longer needed, marked in place rather than copied.
pub fn pretty_expectations_owned(mut marked: serde_json::Value) -> String {
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

    /// [`super::pretty_text_into`] writes what the tree [`parse_lenient`] reads prints, or nothing.
    #[test]
    fn pretty_text_is_the_tree_printed() {
        let tree_text = |text: &str| {
            let mut tree = parse_lenient(text.as_bytes()).unwrap();
            crate::model::big_decimal_in_place(&mut tree);
            // as a field of an object: depth 1 (put in as it is: `json!` would convert its numbers again)
            let mut object = serde_json::Map::new();
            object.insert("body".into(), tree);
            let mut out = String::new();
            super::pretty_into(&mut out, &serde_json::Value::Object(object));
            out
        };
        let direct = |text: &str| {
            let mut out = String::from("{\n  \"body\" : ");
            super::pretty_text_into(&mut out, text, 1).then(|| out + "\n}")
        };
        let written = [
            r#"{"a":1}"#,
            "{}",
            "[]",
            " \t\r\n{ } ",
            "[ [ ], { }, [ [ 1 ] ], { \"a\" : [ ] } ]",
            r#"{"a":{"b":{"c":[1,{"d":null}]}},"e":[true,false,null],"f":""}"#,
            r#"{"n":[0,-0,12,-12,1.50,1e2,1E+2,2.0E-3,-0.0,12345678901234567890,-98765432109876543210,1.0e400,0.1e1]}"#,
            r#"{"s":"a\"b\\c\/d\b\f\n\r\t\u0001\u001fé😀 é 😀 \u007f","k é":"x"}"#,
            "{\"u\":\"\\u00e9\\ud83d\\ude00\\u2028\"}",
            r#"[{"order":{"id":"e0","items":[{"sku":"SKU-00000","quantity":1,"unitPrice":9.99,"tags":["standard","warehouse-a"]}]}}]"#,
        ];
        for text in written {
            assert_eq!(direct(text).as_deref(), Some(tree_text(text).as_str()), "{text}");
        }
        let left_to_the_tree = [
            "1", "\"s\"", "null", "", "  ", r#"{"a":1,"a":2}"#, "{\"a\\tb\":1}", r#"{"a":1} x"#, "{'a':1}", r#"{"a":01}"#,
            r#"{"a":1,}"#, r#"{"a":"\ud800"}"#, "{\"a\":\"\u{1}\"}", "[1 2]", r#"{"a":.5}"#, r#"{"a":1.}"#, r#"{"a":tru}"#,
            "/*c*/{}", "\u{feff}{}",
        ];
        for text in left_to_the_tree {
            assert_eq!(direct(text), None, "{text}");
        }
        let deep = "[".repeat(150) + &"]".repeat(150);
        assert_eq!(direct(&deep), None);
        let many: String = format!("{{{}}}", (0..40).map(|i| format!("\"k{i}\":{i}")).collect::<Vec<_>>().join(","));
        assert_eq!(direct(&many), None);
        let fewer: String = format!("{{{}}}", (0..32).map(|i| format!("\"k{i}\":{i}")).collect::<Vec<_>>().join(","));
        assert_eq!(direct(&fewer).as_deref(), Some(tree_text(&fewer).as_str()));
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

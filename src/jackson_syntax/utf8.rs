//! `ObjectMapper.readValue(InputStream, Map.class)` with `ObjectMapperFactory`'s parser features, as far as a syntax
//! error goes: a port of the paths of jackson-core 2.22.3's `UTF8StreamJsonParser` that `MapDeserializer` and
//! `UntypedObjectDeserializer` drive, with each exception's class, message and location.
//!
//! The parser reads bytes, so columns count bytes, and it decodes UTF-8 only where it has to: string values are
//! validated as they are read, field names when they are first added to the symbol table, and an unexpected byte is
//! described as the Latin-1 character it would be. An end of input inside a number or a single-quoted value names the
//! token the parser had returned last (`Unexpected end-of-input in FIELD_NAME`). The differential vectors in
//! `tests/files/jackson-syntax/` were recorded from the oracle image with `conformance/jackson-syntax/`.

use jackson::json::{is_java_identifier_part, is_java_identifier_start};

const JSON_PARSE: &str = "core.JsonParseException";
const JSON_EOF: &str = "core.io.JsonEOFException";
const MISMATCHED: &str = "databind.exc.MismatchedInputException";
const VALID_VALUES: &str = "(JSON String, Number (or 'NaN'/'+INF'/'-INF'), Array, Object or token 'null', 'true' or 'false')";
const MAP_TYPE: &str = "`java.util.LinkedHashMap<java.lang.Object,java.lang.Object>`";
const MAX_ERROR_TOKEN_LENGTH: usize = 256;

/// A Jackson exception: its class (under `shaded_package.com.fasterxml.jackson.`), message and location, `None` for
/// the `line: 1` alone that "No content to map" carries.
pub struct Failure {
    pub class: &'static str,
    pub message: String,
    pub at: Option<(usize, usize)>,
}

pub fn location((line, column): (usize, usize)) -> String {
    format!("[Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: {line}, column: {column}]")
}

impl Failure {
    pub fn render(&self) -> String {
        let at = self.at.map_or_else(|| "[Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: 1]".to_string(), location);
        format!("shaded_package.com.fasterxml.jackson.{}: {}\n at {at}", self.class, self.message)
    }
}

type R<T> = Result<T, Failure>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tok {
    StartObject,
    EndObject,
    StartArray,
    EndArray,
    FieldName,
    String,
    Int,
    Float,
    True,
    False,
    Null,
}

impl Tok {
    fn name(self) -> &'static str {
        match self {
            Tok::StartObject => "START_OBJECT",
            Tok::EndObject => "END_OBJECT",
            Tok::StartArray => "START_ARRAY",
            Tok::EndArray => "END_ARRAY",
            Tok::FieldName => "FIELD_NAME",
            Tok::String => "VALUE_STRING",
            Tok::Int => "VALUE_NUMBER_INT",
            Tok::Float => "VALUE_NUMBER_FLOAT",
            Tok::True => "VALUE_TRUE",
            Tok::False => "VALUE_FALSE",
            Tok::Null => "VALUE_NULL",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Root,
    Array,
    Object,
}

struct Ctx {
    kind: Kind,
    index: i64,
    start: (usize, usize),
}

impl Ctx {
    fn type_desc(&self) -> &'static str {
        match self.kind {
            Kind::Root => "root",
            Kind::Array => "Array",
            Kind::Object => "Object",
        }
    }
}

/// `CharTypes.getInputCodeUtf8JsNames()`: 0 for a byte an unquoted name may hold. Its high half is the Latin-1 table's
/// (the `Arrays.fill(table, 128, 128, 0)` meant to open it is empty), so a high byte counts as the Latin-1 character.
fn js_name_byte(c: u8) -> bool {
    (c >= 33 && is_java_identifier_part(u16::from(c))) || matches!(c, b'@' | b'#' | b'*' | b'-' | b'+')
}

/// `CharTypes.getInputCodeUtf8()` for a byte at or above 0x80: the length of the sequence it starts, or -1.
fn utf8_code(c: u8) -> i32 {
    if c & 0xE0 == 0xC0 {
        2
    } else if c & 0xF0 == 0xE0 {
        3
    } else if c & 0xF8 == 0xF0 {
        4
    } else {
        -1
    }
}

/// `ParserMinimalBase._getCharDesc`.
fn char_desc(ch: i32) -> String {
    let unit = (ch as u32) & 0xffff;
    if unit <= 0x1f || (0x7f..=0x9f).contains(&unit) {
        return format!("(CTRL-CHAR, code {ch})");
    }
    let c = char::from_u32(unit).unwrap_or('?');
    if !(0..=255).contains(&ch) {
        format!("'{c}' (code {ch} / 0x{:x})", ch as u32)
    } else {
        format!("'{c}' (code {ch})")
    }
}

struct Parser<'a> {
    s: &'a [u8],
    ptr: usize,
    row: usize,
    row_start: usize,
    ctx: Vec<Ctx>,
    curr: Option<Tok>,
    /// The value read along with the field name, returned by the next `nextToken`.
    pending: Option<Tok>,
    /// The pending value is a double-quoted string not read yet (`_tokenIncomplete`).
    incomplete: bool,
    /// Where the last token started (`_tokenInputRow`, one-based `_tokenInputCol`).
    token: (usize, usize),
    names: std::collections::HashSet<Vec<u8>>,
    /// The text of the last string value read, for the root string's mismatch message.
    text: String,
}

/// The exception `readValue(bytes, Map.class)` throws for `bytes`, or `None` when they read (a root `null` included).
pub fn map_failure(bytes: &[u8]) -> Option<Failure> {
    // `ByteSourceJsonBootstrapper` drops a UTF-8 byte order mark when at least four bytes are there to look at.
    let s = if bytes.len() >= 4 && bytes.starts_with(&[0xef, 0xbb, 0xbf]) { &bytes[3..] } else { bytes };
    let mut p = Parser {
        s,
        ptr: 0,
        row: 1,
        row_start: 0,
        ctx: vec![Ctx { kind: Kind::Root, index: -1, start: (1, 0) }],
        curr: None,
        pending: None,
        incomplete: false,
        token: (1, 0),
        names: std::collections::HashSet::new(),
        text: String::new(),
    };
    p.read_map().err()
}

impl Parser<'_> {
    // ---- locations and errors

    fn current(&self) -> (usize, usize) {
        (self.row, self.ptr - self.row_start + 1)
    }

    fn minus_one(&self) -> (usize, usize) {
        (self.row, self.ptr - self.row_start)
    }

    fn fail<T>(&self, class: &'static str, message: String, at: (usize, usize)) -> R<T> {
        Err(Failure { class, message, at: Some(at) })
    }

    /// `_reportError`: a `JsonParseException` at the current location.
    fn error<T>(&self, message: String) -> R<T> {
        self.fail(JSON_PARSE, message, self.current())
    }

    fn eof<T>(&self, message: &str) -> R<T> {
        self.fail(JSON_EOF, format!("Unexpected end-of-input{message}"), self.current())
    }

    /// `_reportInvalidEOF()`: names the current token.
    fn eof_in_token<T>(&self) -> R<T> {
        self.eof(&format!(" in {}", self.curr.map_or("null", Tok::name)))
    }

    fn unexpected_char<T>(&self, ch: i32, comment: &str) -> R<T> {
        self.fail(JSON_PARSE, format!("Unexpected character ({}): {comment}", char_desc(ch)), self.minus_one())
    }

    fn unexpected_number_char<T>(&self, ch: i32, comment: &str) -> R<T> {
        self.fail(JSON_PARSE, format!("Unexpected character ({}) in numeric value: {comment}", char_desc(ch)), self.minus_one())
    }

    fn invalid_space<T>(&self, i: u8) -> R<T> {
        let mut message = format!("Illegal character ({}): only regular white space (\\r, \\n, \\t) is allowed between tokens", char_desc(i32::from(i)));
        if i == 0x1e {
            message.push_str(" (consider enabling `JsonReadFeature.ALLOW_RS_CONTROL_CHAR` to allow use of Record Separators (\\u001E))");
        }
        self.error(message)
    }

    fn invalid_initial<T>(&self, mask: u32) -> R<T> {
        self.error(format!("Invalid UTF-8 start byte 0x{mask:x}"))
    }

    fn invalid_other<T>(&self, mask: u32) -> R<T> {
        self.error(format!("Invalid UTF-8 middle byte 0x{mask:x}"))
    }

    /// `_reportInvalidChar`.
    fn invalid_char<T>(&self, c: u8) -> R<T> {
        if c < b' ' { self.invalid_space(c) } else { self.invalid_initial(u32::from(c)) }
    }

    fn ctx(&self) -> &Ctx {
        self.ctx.last().expect("the root context is never closed")
    }

    fn in_root(&self) -> bool {
        self.ctx().kind == Kind::Root
    }

    // ---- input

    fn at_end(&self) -> bool {
        self.ptr >= self.s.len()
    }

    fn byte(&mut self) -> u8 {
        let b = self.s[self.ptr];
        self.ptr += 1;
        b
    }

    /// `_loadMoreGuaranteed` then the next byte.
    fn next_byte(&mut self) -> R<u8> {
        if self.at_end() {
            return self.eof_in_token();
        }
        Ok(self.byte())
    }

    fn skip_cr(&mut self) {
        if !self.at_end() && self.s[self.ptr] == b'\n' {
            self.ptr += 1;
        }
        self.row += 1;
        self.row_start = self.ptr;
    }

    /// White space and comments; `None` at the end of input.
    fn skip_ws_raw(&mut self) -> R<Option<u8>> {
        while !self.at_end() {
            let i = self.byte();
            if i > b' ' {
                if i == b'/' {
                    self.skip_comment()?;
                    continue;
                }
                if i == b'#' {
                    self.skip_line()?;
                    continue;
                }
                return Ok(Some(i));
            }
            match i {
                b' ' | b'\t' => {}
                b'\n' => {
                    self.row += 1;
                    self.row_start = self.ptr;
                }
                b'\r' => self.skip_cr(),
                _ => return self.invalid_space(i),
            }
        }
        Ok(None)
    }

    /// `_skipWSOrEnd`: `None` at the end of the root level, an EOF failure inside a container (`_handleEOF`).
    fn skip_ws_or_end(&mut self) -> R<Option<u8>> {
        match self.skip_ws_raw()? {
            Some(i) => Ok(Some(i)),
            None if self.in_root() => Ok(None),
            None => {
                let ctx = self.ctx();
                self.eof(&format!(": expected close marker for {} (start marker at {})", ctx.type_desc(), location(ctx.start)))
            }
        }
    }

    /// `_skipWS`, after a comma.
    fn skip_ws(&mut self) -> R<u8> {
        match self.skip_ws_raw()? {
            Some(i) => Ok(i),
            None => self.error(format!("Unexpected end-of-input within/between {} entries", self.ctx().type_desc())),
        }
    }

    /// `_skipColon`: the first byte of the value.
    fn skip_colon(&mut self) -> R<u8> {
        let mut got_colon = false;
        while !self.at_end() {
            let i = self.byte();
            if i > b' ' {
                if i == b'/' {
                    self.skip_comment()?;
                    continue;
                }
                if i == b'#' {
                    self.skip_line()?;
                    continue;
                }
                if got_colon {
                    return Ok(i);
                }
                if i != b':' {
                    return self.unexpected_char(i32::from(i), "was expecting a colon to separate field name and value");
                }
                got_colon = true;
            } else {
                match i {
                    b' ' | b'\t' => {}
                    b'\n' => {
                        self.row += 1;
                        self.row_start = self.ptr;
                    }
                    b'\r' => self.skip_cr(),
                    _ => return self.invalid_space(i),
                }
            }
        }
        self.eof(&format!(" within/between {} entries", self.ctx().type_desc()))
    }

    /// After a `/`.
    fn skip_comment(&mut self) -> R<()> {
        if self.at_end() {
            return self.eof(" in a comment");
        }
        match self.byte() {
            b'/' => self.skip_line(),
            b'*' => self.skip_c_comment(),
            c => self.unexpected_char(i32::from(c), "was expecting either '*' or '/' for a comment"),
        }
    }

    /// One byte of comment content (`CharTypes.getInputCodeComment()`): a multi-byte character is checked and skipped.
    fn comment_byte(&mut self, i: u8) -> R<()> {
        if i >= 0x80 {
            let code = utf8_code(i);
            if code < 0 {
                return self.invalid_char(i);
            }
            for _ in 1..code {
                let d = self.next_byte()?;
                if d & 0xC0 != 0x80 {
                    return self.invalid_other(u32::from(d));
                }
            }
        } else if i < b' ' && i != b'\t' {
            return self.invalid_char(i);
        }
        Ok(())
    }

    fn skip_c_comment(&mut self) -> R<()> {
        while !self.at_end() {
            let i = self.byte();
            match i {
                b'*' => {
                    if self.at_end() {
                        break;
                    }
                    if self.s[self.ptr] == b'/' {
                        self.ptr += 1;
                        return Ok(());
                    }
                }
                b'\n' => {
                    self.row += 1;
                    self.row_start = self.ptr;
                }
                b'\r' => self.skip_cr(),
                _ => self.comment_byte(i)?,
            }
        }
        self.eof(" in a comment")
    }

    fn skip_line(&mut self) -> R<()> {
        while !self.at_end() {
            let i = self.byte();
            match i {
                b'\n' => {
                    self.row += 1;
                    self.row_start = self.ptr;
                    return Ok(());
                }
                b'\r' => {
                    self.skip_cr();
                    return Ok(());
                }
                b'*' => {}
                _ => self.comment_byte(i)?,
            }
        }
        Ok(())
    }

    // ---- tokens

    fn update_location(&mut self) {
        self.token = (self.row, self.ptr - self.row_start);
    }

    fn push(&mut self, kind: Kind) {
        self.ctx.push(Ctx { kind, index: -1, start: self.token });
    }

    fn close_scope(&mut self, i: u8) -> R<Tok> {
        let (kind, expected, tok) = if i == b'}' { (Kind::Object, ']', Tok::EndObject) } else { (Kind::Array, '}', Tok::EndArray) };
        if self.ctx().kind != kind {
            let ctx = self.ctx();
            if ctx.kind == Kind::Root {
                let scope = if i == b'}' { "Object" } else { "Array" };
                return self.fail(JSON_PARSE, format!("Unexpected close marker '{}': no open {scope} to close", i as char), self.minus_one());
            }
            let message = format!("Unexpected close marker '{}': expected '{expected}' (for {} starting at {})", i as char, ctx.type_desc(), location(ctx.start));
            return self.fail(JSON_PARSE, message, self.minus_one());
        }
        self.ctx.pop();
        Ok(tok)
    }

    /// `nextToken()`, with a string value read through at once (the deserializers ask for every value's text).
    fn next_token(&mut self) -> R<Option<Tok>> {
        if self.curr == Some(Tok::FieldName) {
            let t = self.pending.take().expect("a field name is followed by its value");
            match t {
                Tok::StartArray => self.push(Kind::Array),
                Tok::StartObject => self.push(Kind::Object),
                _ => {}
            }
            self.curr = Some(t);
            if std::mem::take(&mut self.incomplete) {
                self.finish_string(b'"')?;
            }
            return Ok(Some(t));
        }
        let Some(mut i) = self.skip_ws_or_end()? else {
            self.curr = None;
            return Ok(None);
        };
        if i == b']' || i == b'}' {
            let t = self.close_scope(i)?;
            self.curr = Some(t);
            return Ok(Some(t));
        }
        let expect_comma = {
            let ctx = self.ctx.last_mut().expect("the root context is never closed");
            ctx.index += 1;
            ctx.kind != Kind::Root && ctx.index > 0
        };
        if expect_comma {
            if i != b',' {
                return self.unexpected_char(i32::from(i), &format!("was expecting comma to separate {} entries", self.ctx().type_desc()));
            }
            i = self.skip_ws()?;
            // a trailing comma
            if i == b']' || i == b'}' {
                let t = self.close_scope(i)?;
                self.curr = Some(t);
                return Ok(Some(t));
            }
        }
        if self.ctx().kind != Kind::Object {
            self.update_location();
            let t = self.value(i, true)?;
            self.curr = Some(t);
            match t {
                Tok::StartArray => self.push(Kind::Array),
                Tok::StartObject => self.push(Kind::Object),
                Tok::String if i == b'"' => self.finish_string(b'"')?,
                _ => {}
            }
            return Ok(Some(t));
        }
        self.parse_name(i)?;
        self.curr = Some(Tok::FieldName);
        let i = self.skip_colon()?;
        self.update_location();
        // a double-quoted value is read when its token is returned
        self.incomplete = i == b'"';
        self.pending = Some(if i == b'"' { Tok::String } else { self.value(i, false)? });
        Ok(Some(Tok::FieldName))
    }

    /// The value starting with `i` (`_nextTokenNotInObject` / the switch after a field name). A double-quoted string is
    /// left for [`Parser::finish_string`].
    fn value(&mut self, i: u8, not_in_object: bool) -> R<Tok> {
        match i {
            b'"' if not_in_object => Ok(Tok::String),
            b'[' => Ok(Tok::StartArray),
            b'{' => Ok(Tok::StartObject),
            b't' => self.match_token("true", 1).map(|()| Tok::True),
            b'f' => self.match_token("false", 1).map(|()| Tok::False),
            b'n' => self.match_token("null", 1).map(|()| Tok::Null),
            b'-' => self.parse_signed_number(),
            b'0'..=b'9' => self.parse_unsigned_number(i),
            // `+` without `ALLOW_LEADING_PLUS_SIGN_FOR_NUMBERS`, and `.` without `ALLOW_LEADING_DECIMAL_POINT_FOR_NUMBERS`
            _ => self.handle_unexpected_value(i),
        }
    }

    fn handle_unexpected_value(&mut self, c: u8) -> R<Tok> {
        match c {
            b']' | b',' | b'}' => {
                // `ALLOW_MISSING_VALUES`: a comma (or a `]` in an array) where a value belongs is a null, but not at the root
                if c != b'}' && (c == b',' || self.ctx().kind == Kind::Array) && !self.in_root() {
                    self.ptr -= 1;
                    return Ok(Tok::Null);
                }
                if c != b']' || self.in_root() {
                    return self.unexpected_char(i32::from(c), "expected a value");
                }
            }
            b'\'' => {
                self.finish_string(b'\'')?;
                return Ok(Tok::String);
            }
            b'N' => {
                self.match_token("NaN", 1)?;
                return Ok(Tok::Float);
            }
            b'I' => {
                self.match_token("Infinity", 1)?;
                return Ok(Tok::Float);
            }
            b'+' => {
                if self.at_end() {
                    return self.eof(" in a Number value");
                }
                let ch = self.byte();
                return self.invalid_number_start(i32::from(ch), false, true);
            }
            _ => {}
        }
        let ch = if c > 0x7f { self.decode_char_for_error(c)? } else { i32::from(c) };
        if is_java_identifier_start(ch) {
            let matched = char::from_u32((ch as u32) & 0xffff).map_or_else(String::new, String::from);
            return self.invalid_token(matched, 1);
        }
        self.unexpected_char(ch, &format!("expected a valid value {VALID_VALUES}"))
    }

    /// `_reportInvalidToken(matchedPart)`: the token starts `matched_units` UTF-16 units back from the pointer, and runs
    /// on through every Java identifier part.
    fn invalid_token<T>(&mut self, matched: String, matched_units: usize) -> R<T> {
        let start = self.ptr - matched_units;
        let at = (self.row, start - self.row_start + 1);
        let mut token = matched;
        let mut units = token.encode_utf16().count();
        while !self.at_end() {
            let i = self.byte();
            let c = self.decode_char_for_error(i)?;
            let unit = (c as u32 & 0xffff) as u16;
            if !is_java_identifier_part(unit) {
                break;
            }
            token.push(char::from_u32(u32::from(unit)).unwrap_or('?'));
            units += 1;
            if units >= MAX_ERROR_TOKEN_LENGTH {
                token.push_str("...");
                break;
            }
        }
        self.fail(JSON_PARSE, format!("Unrecognized token '{token}': was expecting {VALID_VALUES}"), at)
    }

    /// `_decodeCharForError`: the character a byte starts, its continuation bytes consumed.
    fn decode_char_for_error(&mut self, first: u8) -> R<i32> {
        let mut c = u32::from(first);
        if c > 0x7f {
            let needed = match utf8_code(first) {
                2 => {
                    c &= 0x1f;
                    1
                }
                3 => {
                    c &= 0x0f;
                    2
                }
                4 => {
                    c &= 0x07;
                    3
                }
                _ => return self.invalid_initial(c),
            };
            for _ in 0..needed {
                let d = self.next_byte()?;
                if d & 0xC0 != 0x80 {
                    return self.invalid_other(u32::from(d));
                }
                c = (c << 6) | u32::from(d & 0x3f);
            }
        }
        Ok(c as i32)
    }

    /// `_matchToken(matchStr, i)`, the pointer just past the token's first `i` characters.
    fn match_token(&mut self, word: &str, from: usize) -> R<()> {
        let w = word.as_bytes();
        for (k, &expected) in w.iter().enumerate().skip(from) {
            if self.at_end() || self.s[self.ptr] != expected {
                return self.invalid_token(word[..k].to_string(), k);
            }
            self.ptr += 1;
        }
        if self.at_end() {
            return Ok(());
        }
        let ch = self.s[self.ptr];
        if ch >= b'0' && ch != b']' && ch != b'}' {
            // `_checkMatchEnd`
            if ch < 0x80 {
                if is_java_identifier_part(u16::from(ch)) {
                    return self.invalid_token(word.to_string(), w.len());
                }
                return Ok(());
            }
            let saved = self.ptr;
            self.ptr += 1;
            let c = self.decode_char_for_error(ch)?;
            let unit = (c as u32 & 0xffff) as u16;
            if is_java_identifier_part(unit) {
                let mut matched = word.to_string();
                matched.push(char::from_u32(u32::from(unit)).unwrap_or('?'));
                return self.invalid_token(matched, w.len() + 1);
            }
            self.ptr = saved;
        }
        Ok(())
    }

    // ---- numbers

    fn invalid_number_start(&mut self, mut ch: i32, negative: bool, has_sign: bool) -> R<Tok> {
        if ch == i32::from(b'I') {
            if self.at_end() {
                return self.eof(" in a Number value");
            }
            ch = i32::from(self.byte() as i8);
            let word = if ch == i32::from(b'N') {
                Some(if negative { "-INF" } else { "+INF" })
            } else if ch == i32::from(b'n') {
                Some(if negative { "-Infinity" } else { "+Infinity" })
            } else {
                None
            };
            if let Some(word) = word {
                self.match_token(word, 3)?;
                return Ok(Tok::Float);
            }
        }
        if has_sign && !negative {
            return self.unexpected_number_char(i32::from(b'+'), "JSON spec does not allow numbers to have plus signs: enable `JsonReadFeature.ALLOW_LEADING_PLUS_SIGN_FOR_NUMBERS` to allow");
        }
        let message = if negative { "expected digit (0-9) to follow minus sign, for valid numeric value" } else { "expected digit (0-9) for valid numeric value" };
        self.unexpected_number_char(ch, message)
    }

    fn parse_signed_number(&mut self) -> R<Tok> {
        let c = self.next_byte()?;
        if c == b'.' {
            return self.handle_unexpected_value(b'.');
        }
        if !c.is_ascii_digit() {
            return self.invalid_number_start(i32::from(c), true, true);
        }
        self.parse_unsigned_number(c)
    }

    /// From the first digit (consumed).
    fn parse_unsigned_number(&mut self, first: u8) -> R<Tok> {
        let mut c;
        if first == b'0' {
            self.verify_no_leading_zeroes();
        }
        loop {
            if self.at_end() {
                return Ok(Tok::Int);
            }
            c = self.byte();
            if !c.is_ascii_digit() {
                break;
            }
        }
        if c == b'.' || c | 0x20 == b'e' {
            return self.parse_float(c);
        }
        self.ptr -= 1;
        if self.in_root() {
            self.verify_root_space(c)?;
        }
        Ok(Tok::Int)
    }

    /// `_verifyNoLeadingZeroes` with `ALLOW_LEADING_ZEROS_FOR_NUMBERS`: the zeros before another digit are skipped.
    fn verify_no_leading_zeroes(&mut self) -> u8 {
        if self.at_end() || !self.s[self.ptr].is_ascii_digit() {
            return b'0';
        }
        let mut ch = self.s[self.ptr];
        self.ptr += 1;
        if ch == b'0' {
            while !self.at_end() {
                ch = self.s[self.ptr];
                if !ch.is_ascii_digit() {
                    return b'0';
                }
                self.ptr += 1;
                if ch != b'0' {
                    break;
                }
            }
        }
        ch
    }

    fn parse_float(&mut self, mut c: u8) -> R<Tok> {
        let mut eof = false;
        if c == b'.' {
            let mut fraction = 0;
            loop {
                if self.at_end() {
                    eof = true;
                    break;
                }
                c = self.byte();
                if !c.is_ascii_digit() {
                    break;
                }
                fraction += 1;
            }
            if fraction == 0 {
                return self.unexpected_number_char(i32::from(c), "Decimal point not followed by a digit");
            }
        }
        if c | 0x20 == b'e' {
            c = self.next_byte()?;
            if c == b'-' || c == b'+' {
                c = self.next_byte()?;
            }
            let mut exponent = 0;
            while c.is_ascii_digit() {
                exponent += 1;
                if self.at_end() {
                    eof = true;
                    break;
                }
                c = self.byte();
            }
            if exponent == 0 {
                return self.unexpected_number_char(i32::from(c), "Exponent indicator not followed by a digit");
            }
        }
        if !eof {
            self.ptr -= 1;
            if self.in_root() {
                self.verify_root_space(c)?;
            }
        }
        Ok(Tok::Float)
    }

    fn verify_root_space(&mut self, ch: u8) -> R<()> {
        self.ptr += 1;
        match ch {
            b' ' | b'\t' => Ok(()),
            b'\r' => {
                self.ptr -= 1;
                Ok(())
            }
            b'\n' => {
                self.row += 1;
                self.row_start = self.ptr;
                Ok(())
            }
            _ => self.unexpected_char(i32::from(ch), "Expected space separating root-level values"),
        }
    }

    // ---- strings

    /// `_decodeEscaped`, after the backslash: the UTF-16 unit it stands for.
    fn decode_escaped(&mut self) -> R<u32> {
        if self.at_end() {
            return self.eof(" in character escape sequence");
        }
        let c = self.byte();
        match c {
            b'b' => return Ok(0x08),
            b't' => return Ok(0x09),
            b'n' => return Ok(0x0a),
            b'f' => return Ok(0x0c),
            b'r' => return Ok(0x0d),
            b'"' | b'/' | b'\\' => return Ok(u32::from(c)),
            b'u' => {}
            // `ALLOW_BACKSLASH_ESCAPING_ANY_CHARACTER`
            _ => return Ok(self.decode_char_for_error(c)? as u32 & 0xffff),
        }
        let mut value = 0;
        for _ in 0..4 {
            if self.at_end() {
                return self.eof(" in character escape sequence");
            }
            let ch = self.byte();
            let Some(digit) = (ch as char).to_digit(16) else {
                return self.unexpected_char(i32::from(ch), "expected a hex-digit for character escape sequence");
            };
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    /// A string value after its opening `quote` (`_finishString`, or `_handleApos` for a single-quoted one), its text
    /// kept in `text`.
    fn finish_string(&mut self, quote: u8) -> R<()> {
        let mut out: Vec<u16> = Vec::new();
        loop {
            let c = self.next_byte()?;
            if c == quote {
                self.text = String::from_utf16_lossy(&out);
                return Ok(());
            }
            match c {
                b'\\' => out.push(self.decode_escaped()? as u16),
                // `ALLOW_UNQUOTED_CONTROL_CHARS`
                0..=0x1f => out.push(u16::from(c)),
                0x80..=0xff => {
                    let code = utf8_code(c);
                    if code < 0 {
                        return self.invalid_char(c);
                    }
                    let mut cp = u32::from(c) & [0, 0, 0x1f, 0x0f, 0x07][code as usize];
                    for _ in 1..code {
                        let d = self.next_byte()?;
                        if d & 0xC0 != 0x80 {
                            return self.invalid_other(u32::from(d));
                        }
                        cp = (cp << 6) | u32::from(d & 0x3f);
                    }
                    if code == 3 && (0xD800..=0xDFFF).contains(&cp) {
                        return self.error(format!("Invalid UTF-8: Illegal surrogate character 0x{cp:x}"));
                    }
                    if code == 4 {
                        let v = cp.wrapping_sub(0x10000);
                        out.push((0xD800 | ((v >> 10) & 0x3ff)) as u16);
                        out.push((0xDC00 | (v & 0x3ff)) as u16);
                    } else {
                        out.push(cp as u16);
                    }
                }
                _ => out.push(u16::from(c)),
            }
        }
    }

    // ---- names

    fn parse_name(&mut self, i: u8) -> R<()> {
        let bytes = match i {
            b'"' => self.quoted_name(b'"', ": was expecting closing '\"' for name")?,
            b'\'' => self.quoted_name(b'\'', ": was expecting closing ''' for field name")?,
            _ => {
                // `_handleOddName`: an unquoted name, ending before the first byte that is no name character
                if !js_name_byte(i) {
                    return self.unexpected_char(i32::from(i), "was expecting either valid name character (for unquoted name) or double-quote (for quoted) to start field name");
                }
                let mut bytes = vec![i];
                loop {
                    if self.at_end() {
                        return self.eof(" in field name");
                    }
                    let ch = self.s[self.ptr];
                    if !js_name_byte(ch) {
                        break;
                    }
                    bytes.push(ch);
                    self.ptr += 1;
                }
                bytes
            }
        };
        if self.names.insert(bytes.clone()) {
            self.add_name(&bytes)?;
        }
        Ok(())
    }

    /// A quoted name after its opening quote (`slowParseName`/`parseEscapedName`, `_parseAposName`): its bytes, an
    /// escaped character UTF-8 encoded into them, the raw ones left for [`Parser::add_name`] to decode.
    fn quoted_name(&mut self, quote: u8, empty_eof: &str) -> R<Vec<u8>> {
        if self.at_end() {
            return self.eof(empty_eof);
        }
        let mut bytes = Vec::new();
        let mut ch = self.byte();
        while ch != quote {
            if ch == b'\\' {
                let mut c = self.decode_escaped()?;
                if (0xD800..=0xDBFF).contains(&c) {
                    if self.at_end() {
                        return self.eof(" in field name");
                    }
                    if self.s[self.ptr] != b'\\' {
                        return self.error(format!("Broken surrogate pair in field name: expected '\\' to start low surrogate, got 0x{:x}", self.s[self.ptr]));
                    }
                    self.ptr += 1;
                    let lo = self.decode_escaped()?;
                    if !(0xDC00..=0xDFFF).contains(&lo) {
                        return self.error(format!("Broken surrogate pair in field name: expected low surrogate, got 0x{lo:04X}"));
                    }
                    c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                } else if (0xDC00..=0xDFFF).contains(&c) {
                    return self.error(format!("Unexpected low surrogate in field name: 0x{c:x}"));
                }
                let mut buf = [0u8; 4];
                bytes.extend_from_slice(char::from_u32(c).unwrap_or('\u{fffd}').encode_utf8(&mut buf).as_bytes());
            } else {
                bytes.push(ch);
            }
            if self.at_end() {
                return self.eof(" in field name");
            }
            ch = self.byte();
        }
        Ok(bytes)
    }

    /// `addName`: decodes the name's UTF-8, reading continuation bytes out of the name's quads (so a bad one is shown
    /// with the bytes before it in its quad).
    fn add_name(&self, bytes: &[u8]) -> R<()> {
        let quad = |ix: usize| -> i32 {
            let k = ix >> 2;
            let mut q = [0u8; 4];
            for (j, b) in bytes.iter().skip(4 * k).take(4).enumerate() {
                q[j] = *b;
            }
            i32::from_be_bytes(q)
        };
        let at = |ix: usize| -> i32 { quad(ix) >> ((3 - (ix & 3)) << 3) };
        let mut ix = 0;
        while ix < bytes.len() {
            let mut ch = (at(ix) & 0xff) as u32;
            ix += 1;
            if ch > 127 {
                let needed = match utf8_code(ch as u8) {
                    2 => {
                        ch &= 0x1f;
                        1
                    }
                    3 => {
                        ch &= 0x0f;
                        2
                    }
                    4 => {
                        ch &= 0x07;
                        3
                    }
                    _ => return self.invalid_initial(ch),
                };
                if ix + needed > bytes.len() {
                    return self.eof(" in field name");
                }
                for k in 0..needed {
                    let ch2 = at(ix);
                    ix += 1;
                    if ch2 & 0xC0 != 0x80 {
                        return self.invalid_other(if k == 2 { (ch2 & 0xff) as u32 } else { ch2 as u32 });
                    }
                    ch = (ch << 6) | (ch2 & 0x3f) as u32;
                }
                if needed == 2 && (0xD800..=0xDFFF).contains(&ch) {
                    return self.error(format!("Invalid UTF-8: Illegal surrogate character 0x{ch:x}"));
                }
            }
        }
        Ok(())
    }

    // ---- the map

    /// `readValue(.., Map.class)`: the root token, then every token of the object.
    fn read_map(&mut self) -> R<()> {
        let Some(root) = self.next_token()? else {
            return Err(Failure { class: MISMATCHED, message: "No content to map due to end-of-input".into(), at: None });
        };
        let at = self.token;
        let cannot = |what: &str| format!("Cannot deserialize value of type {MAP_TYPE} from {what}");
        let message = match root {
            Tok::StartObject => {
                while self.ctx.len() > 1 {
                    self.next_token()?;
                }
                return Ok(());
            }
            // the oracle dies on a root `null` (docs/divergences.md); no exception is thrown here
            Tok::Null => return Ok(()),
            Tok::StartArray => cannot("Array value (token `JsonToken.START_ARRAY`)"),
            Tok::String => {
                let content = &self.text;
                format!("Cannot construct instance of `java.util.LinkedHashMap` (although at least one Creator exists): no String-argument constructor/factory method to deserialize from String value ('{content}')")
            }
            Tok::Int => cannot("Integer value (token `JsonToken.VALUE_NUMBER_INT`)"),
            Tok::Float => cannot("Floating-point value (token `JsonToken.VALUE_NUMBER_FLOAT`)"),
            Tok::True => cannot("Boolean value (token `JsonToken.VALUE_TRUE`)"),
            Tok::False => cannot("Boolean value (token `JsonToken.VALUE_FALSE`)"),
            Tok::EndObject | Tok::EndArray | Tok::FieldName => unreachable!("closing a scope at the root fails first"),
        };
        self.fail(MISMATCHED, message, (at.0, at.1))
    }
}

//! Jackson 3's `ObjectMapper.readTree(InputStream)` failures for a remote document: the
//! `UTF8StreamJsonParser` with no read features enabled, and `DeserializationFeature.FAIL_ON_TRAILING_TOKENS` (on by
//! default in Jackson 3). Each failure is `<exception class> - <message>` and the byte offset its parser reports:
//! the offending byte for most, the start of the token for unrecognised and trailing tokens, the byte after the
//! one read for `+`, a leading zero's digit and invalid UTF-8, the end of the token for `NaN`/`Infinity`, the end of
//! the input for end-of-input. The wordings and offsets are the oracle's (scenario `json_schema_remote_ref_syntax`).

/// What `readTree` makes of a document.
pub enum Read {
    /// Nothing but white space: a `MissingNode`.
    Missing,
    /// One JSON value.
    Value,
    /// The exception text: class and message, a newline, then ` at <location>`.
    Failed(String),
}

const VALUE_LIST: &str = "(JSON String, Number, Array, Object or token 'null', 'true' or 'false')";

pub fn read(bytes: &[u8]) -> Read {
    let start = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) { 3 } else { 0 };
    let mut p = Parser { s: bytes, i: start, stack: Vec::new() };
    match p.document() {
        Ok(true) => Read::Value,
        Ok(false) => Read::Missing,
        Err(e) => Read::Failed(format!(
            "{} - {}\n at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); byte offset: #{}]",
            e.class, e.message, e.offset
        )),
    }
}

struct Failure {
    class: &'static str,
    message: String,
    offset: usize,
}

type Step<T> = Result<T, Failure>;

#[derive(Clone, Copy, PartialEq)]
enum Ctx {
    Object,
    Array,
}

impl Ctx {
    fn desc(self) -> &'static str {
        match self {
            Ctx::Object => "Object",
            Ctx::Array => "Array",
        }
    }
}

/// The token a trailing value starts with (`JsonToken`'s name).
enum Token {
    StartObject,
    StartArray,
    String,
    Int,
    Float,
    True,
    False,
    Null,
}

impl Token {
    fn name(&self) -> &'static str {
        match self {
            Token::StartObject => "START_OBJECT",
            Token::StartArray => "START_ARRAY",
            Token::String => "VALUE_STRING",
            Token::Int => "VALUE_NUMBER_INT",
            Token::Float => "VALUE_NUMBER_FLOAT",
            Token::True => "VALUE_TRUE",
            Token::False => "VALUE_FALSE",
            Token::Null => "VALUE_NULL",
        }
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    stack: Vec<Ctx>,
}

/// `_getCharDesc`.
fn char_desc(c: char) -> String {
    let code = c as u32;
    if code < 0x20 || (0x7f..=0x9f).contains(&code) {
        format!("(CTRL-CHAR, code {code})")
    } else if code > 255 {
        format!("'{c}' (code {code} / 0x{code:x})")
    } else {
        format!("'{c}' (code {code})")
    }
}

fn identifier_start(c: char) -> bool {
    c == '$' || c == '_' || c.is_alphabetic()
}

fn identifier_part(c: char) -> bool {
    identifier_start(c) || c.is_numeric()
}

fn fail<T>(class: &'static str, message: impl Into<String>, offset: usize) -> Step<T> {
    Err(Failure { class, message: message.into(), offset })
}

const STREAM: &str = "StreamReadException";
const EOF: &str = "UnexpectedEndOfInputException";

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    /// The character at `at`, decoded from UTF-8 where it can be, and the bytes it takes.
    fn char_at(&self, at: usize) -> (char, usize) {
        let rest = &self.s[at..];
        for len in 1..=4.min(rest.len()) {
            if let Ok(text) = std::str::from_utf8(&rest[..len]) && let Some(c) = text.chars().next() {
                return (c, len);
            }
        }
        (char::from(rest[0]), 1)
    }

    fn unexpected<T>(&self, at: usize, comment: &str) -> Step<T> {
        fail(STREAM, format!("Unexpected character ({}): {comment}", char_desc(self.char_at(at).0)), at)
    }

    /// `_skipWSOrEnd`: the next byte that is not white space, or `None` at the end.
    fn skip_ws_or_end(&mut self) -> Step<Option<u8>> {
        while let Some(b) = self.peek() {
            match b {
                b' ' | b'\t' | b'\r' | b'\n' => self.i += 1,
                b'/' => {
                    return fail(
                        STREAM,
                        "Unexpected character ('/' (code 47)): maybe a (non-standard) comment? (not recognized as one since Feature 'ALLOW_COMMENTS' not enabled for parser)",
                        self.i,
                    );
                }
                0..0x20 => {
                    return fail(
                        STREAM,
                        format!("Illegal character ({}): only regular white space (\\r, \\n, \\t) is allowed between tokens", char_desc(char::from(b))),
                        self.i,
                    );
                }
                _ => return Ok(Some(b)),
            }
        }
        Ok(None)
    }

    /// `_skipWS` after a comma: the end of the input there is reported as such.
    fn skip_ws_after_comma(&mut self) -> Step<u8> {
        match self.skip_ws_or_end()? {
            Some(b) => Ok(b),
            None => fail(STREAM, format!("Unexpected end-of-input within/between {} entries", self.ctx().desc()), self.i),
        }
    }

    fn ctx(&self) -> Ctx {
        *self.stack.last().unwrap_or(&Ctx::Object)
    }

    fn eof_in_scope<T>(&self) -> Step<T> {
        let desc = self.ctx().desc();
        fail(
            EOF,
            format!(
                "Unexpected end-of-input: expected close marker for {desc} (start marker at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); byte offset: #UNKNOWN])"
            ),
            self.i,
        )
    }

    /// `_closeScope` for a `}` or `]` met where a value, a name or a comma would be.
    fn close_scope(&mut self, b: u8) -> Step<()> {
        let want = if b == b'}' { Ctx::Object } else { Ctx::Array };
        match self.stack.last() {
            Some(ctx) if *ctx == want => {
                self.stack.pop();
                self.i += 1;
                Ok(())
            }
            Some(ctx) => {
                let expected = if *ctx == Ctx::Object { '}' } else { ']' };
                fail(
                    STREAM,
                    format!(
                        "Unexpected close marker '{}': expected '{expected}' (for {} starting at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); byte offset: #UNKNOWN])",
                        char::from(b),
                        ctx.desc()
                    ),
                    self.i,
                )
            }
            None => fail(STREAM, format!("Unexpected close marker '{}': no open {} to close", char::from(b), want.desc()), self.i),
        }
    }

    /// The root value, then `FAIL_ON_TRAILING_TOKENS`; `false` for a document with no value.
    fn document(&mut self) -> Step<bool> {
        let Some(b) = self.skip_ws_or_end()? else { return Ok(false) };
        self.value(b)?;
        self.rest()?;
        let Some(b) = self.skip_ws_or_end()? else { return Ok(true) };
        let start = self.i;
        // one more `nextToken`: a container is only opened and a string's text is left unread
        let token = match b {
            b'}' | b']' => return self.close_scope(b).map(|_| true),
            b'{' => Token::StartObject,
            b'[' => Token::StartArray,
            b'"' => Token::String,
            _ => self.scalar_or_start(b)?,
        };
        fail(
            "MismatchedInputException",
            format!(
                "Trailing token (`JsonToken.{}`) found after value (bound as `shaded_package.tools.jackson.databind.JsonNode`): not allowed as per `DeserializationFeature.FAIL_ON_TRAILING_TOKENS`",
                token.name()
            ),
            start,
        )
    }

    /// Reads one value starting at `b`; containers are only opened, [`Parser::rest`] reads what follows.
    fn value(&mut self, b: u8) -> Step<()> {
        self.scalar_or_start(b).map(|_| ())
    }

    fn scalar_or_start(&mut self, b: u8) -> Step<Token> {
        match b {
            b'{' => {
                self.i += 1;
                self.stack.push(Ctx::Object);
                self.after_object_start()?;
                Ok(Token::StartObject)
            }
            b'[' => {
                self.i += 1;
                self.stack.push(Ctx::Array);
                match self.skip_ws_or_end()? {
                    None => self.eof_in_scope(),
                    Some(b @ (b']' | b'}')) => self.close_scope(b),
                    Some(b) => self.value(b),
                }?;
                Ok(Token::StartArray)
            }
            b'"' => {
                self.i += 1;
                self.string("in VALUE_STRING", "string value")?;
                Ok(Token::String)
            }
            b'-' | b'0'..=b'9' => self.number(),
            b't' => self.literal("true").map(|_| Token::True),
            b'f' => self.literal("false").map(|_| Token::False),
            b'n' => self.literal("null").map(|_| Token::Null),
            _ => self.unexpected_value(),
        }
    }

    /// After `{`: a name, the `}` that closes it, or the end of the input.
    fn after_object_start(&mut self) -> Step<()> {
        match self.skip_ws_or_end()? {
            None => self.eof_in_scope(),
            Some(b @ (b'}' | b']')) => self.close_scope(b),
            Some(_) => self.member(),
        }
    }

    /// A property name at the current byte, its colon and the start of its value.
    fn member(&mut self) -> Step<()> {
        if self.peek() != Some(b'"') {
            return self.unexpected(self.i, "was expecting double-quote to start property name");
        }
        self.i += 1;
        self.string("in property name", "name")?;
        match self.skip_ws_or_end()? {
            None => return fail(EOF, "Unexpected end-of-input within/between Object entries", self.i),
            Some(b':') => self.i += 1,
            Some(_) => return self.unexpected(self.i, "was expecting a colon to separate property name and value"),
        }
        match self.skip_ws_or_end()? {
            None => fail(EOF, "Unexpected end-of-input within/between Object entries", self.i),
            Some(b) => self.value(b),
        }
    }

    /// What follows a value inside containers, until the stack is empty again.
    fn rest(&mut self) -> Step<()> {
        while let Some(&ctx) = self.stack.last() {
            match self.skip_ws_or_end()? {
                None => return self.eof_in_scope(),
                Some(b @ (b'}' | b']')) => self.close_scope(b)?,
                Some(b',') => {
                    self.i += 1;
                    let b = self.skip_ws_after_comma()?;
                    match ctx {
                        Ctx::Object => self.member()?,
                        Ctx::Array => self.value(b)?,
                    }
                }
                Some(_) => {
                    return self.unexpected(self.i, &format!("was expecting comma to separate {} entries", ctx.desc()));
                }
            }
        }
        Ok(())
    }

    /// The rest of a string after its opening quote.
    fn string(&mut self, eof: &str, kind: &str) -> Step<()> {
        loop {
            let Some(b) = self.peek() else {
                return fail(EOF, format!("Unexpected end-of-input {eof}"), self.i);
            };
            match b {
                b'"' => {
                    self.i += 1;
                    return Ok(());
                }
                b'\\' => {
                    self.i += 1;
                    self.escape()?;
                }
                0..0x20 => {
                    return fail(
                        STREAM,
                        format!("Illegal unquoted character ({}): has to be escaped using backslash to be included in {kind}", char_desc(char::from(b))),
                        self.i,
                    );
                }
                0x80.. => self.utf8(b, eof)?,
                _ => self.i += 1,
            }
        }
    }

    fn escape(&mut self) -> Step<()> {
        let eof = |at| fail(EOF, "Unexpected end-of-input in character escape sequence", at);
        let Some(b) = self.peek() else { return eof(self.i) };
        match b {
            b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                self.i += 1;
                Ok(())
            }
            b'u' => {
                self.i += 1;
                for _ in 0..4 {
                    match self.peek() {
                        None => return eof(self.i),
                        Some(h) if h.is_ascii_hexdigit() => self.i += 1,
                        Some(_) => return self.unexpected(self.i, "expected a hex-digit for character escape sequence"),
                    }
                }
                Ok(())
            }
            _ => {
                let (c, _) = self.char_at(self.i);
                fail(STREAM, format!("Unrecognized character escape {}", char_desc(c)), self.i)
            }
        }
    }

    /// A multi-byte UTF-8 character in a string.
    fn utf8(&mut self, lead: u8, eof: &str) -> Step<()> {
        let more = match lead {
            0xC0..=0xDF => 1,
            0xE0..=0xEF => 2,
            0xF0..=0xF7 => 3,
            _ => return fail(STREAM, format!("Invalid UTF-8 start byte 0x{lead:x}"), self.i + 1),
        };
        self.i += 1;
        for _ in 0..more {
            match self.peek() {
                None => return fail(EOF, format!("Unexpected end-of-input {eof}"), self.i),
                Some(b) if b & 0xC0 == 0x80 => self.i += 1,
                Some(b) => return fail(STREAM, format!("Invalid UTF-8 middle byte 0x{b:x}"), self.i + 1),
            }
        }
        Ok(())
    }

    fn digits(&mut self) -> usize {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - start
    }

    fn number_char<T>(&self, comment: &str) -> Step<T> {
        fail(STREAM, format!("Unexpected character ({}) in numeric value: {comment}", char_desc(self.char_at(self.i).0)), self.i)
    }

    fn number(&mut self) -> Step<Token> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
            match self.peek() {
                Some(b'0'..=b'9') => {}
                Some(b'I') if self.s[self.i..].starts_with(b"Infinity") => {
                    self.i += "Infinity".len();
                    return self.non_standard(&self.s[start..self.i]);
                }
                Some(_) => return self.number_char("expected digit (0-9) to follow minus sign, for valid numeric value"),
                None => return fail(EOF, "Unexpected end-of-input in a Number value", self.i),
            }
        }
        if self.peek() == Some(b'0') && matches!(self.s.get(self.i + 1), Some(b'0'..=b'9')) {
            return fail(STREAM, "Invalid numeric value: Leading zeroes not allowed", self.i + 1);
        }
        self.digits();
        let mut float = false;
        if self.peek() == Some(b'.') {
            float = true;
            self.i += 1;
            if self.digits() == 0 {
                return match self.peek() {
                    Some(_) => self.number_char("Decimal point not followed by a digit"),
                    None => fail(EOF, "Unexpected end-of-input in a Number value", self.i),
                };
            }
            if self.peek() == Some(b'.') {
                return self.number_char("Cannot parse number with more than one decimal point");
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            float = true;
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if self.digits() == 0 {
                return match self.peek() {
                    Some(_) => self.number_char("Exponent indicator not followed by a digit"),
                    None => fail(EOF, "Unexpected end-of-input in a Number value", self.i),
                };
            }
        }
        Ok(if float { Token::Float } else { Token::Int })
    }

    fn non_standard<T>(&self, token: &[u8]) -> Step<T> {
        fail(
            STREAM,
            format!("Non-standard token '{}': enable `JsonReadFeature.ALLOW_NON_NUMERIC_NUMBERS` to allow", String::from_utf8_lossy(token)),
            self.i,
        )
    }

    /// `_matchToken`: the word, not followed by an identifier character.
    fn literal(&mut self, word: &str) -> Step<()> {
        let end = self.i + word.len();
        if !self.s[self.i..].starts_with(word.as_bytes()) {
            return self.invalid_token();
        }
        match self.s.get(end) {
            Some(&b) if b >= b'0' && b != b']' && b != b'}' && identifier_part(self.char_at(end).0) => self.invalid_token(),
            _ => {
                self.i = end;
                Ok(())
            }
        }
    }

    /// `_reportInvalidToken`: the identifier characters from the current byte on.
    fn invalid_token<T>(&self) -> Step<T> {
        let start = self.i;
        let mut at = start;
        let mut token = String::new();
        while at < self.s.len() {
            let (c, len) = self.char_at(at);
            if !identifier_part(c) {
                break;
            }
            if token.chars().count() == 256 {
                token.push_str("...");
                break;
            }
            token.push(c);
            at += len;
        }
        fail(STREAM, format!("Unrecognized token '{token}': was expecting {VALUE_LIST}"), start)
    }

    /// `_handleUnexpectedValue`.
    fn unexpected_value<T>(&mut self) -> Step<T> {
        let at = self.i;
        let (c, _) = self.char_at(at);
        match c {
            ']' if self.stack.last() == Some(&Ctx::Array) => self.unexpected(at, "expected a value"),
            ',' | '}' => self.unexpected(at, "expected a value"),
            'N' | 'I' => {
                let word: &[u8] = if c == 'N' { b"NaN" } else { b"Infinity" };
                if self.s[at..].starts_with(word) {
                    self.i += word.len();
                    self.non_standard(word)
                } else {
                    self.invalid_token()
                }
            }
            '+' => fail(
                STREAM,
                "Unexpected character ('+' (code 43)) in numeric value: JSON spec does not allow numbers to have plus signs: enable `JsonReadFeature.ALLOW_LEADING_PLUS_SIGN_FOR_NUMBERS` to allow",
                at + 1,
            ),
            _ if identifier_start(c) => self.invalid_token(),
            _ => self.unexpected(at, &format!("expected a valid value {VALUE_LIST}")),
        }
    }
}

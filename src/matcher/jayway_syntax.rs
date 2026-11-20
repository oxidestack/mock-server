//! Jayway JsonPath 2.9.0's path syntax check: a port of `PathCompiler`, `FilterCompiler` and `CharacterIndex` that
//! parses and builds nothing, only fails the way they fail. The message of an `InvalidPathException` is the text
//! `ExpectationFilter.compileJsonPath` puts in its 400, so every branch keeps Jayway's wording, including the
//! `StringIndexOutOfBoundsException` its index arithmetic raises on a truncated path. Strings are UTF-16 code units,
//! as `CharSequence` indexes are.

use super::java_pattern;

/// An exception Jayway throws while compiling.
#[derive(Debug)]
enum Error {
    /// `InvalidPathException(message)`.
    Invalid(String),
    /// Any other exception, as `toString()` writes it; `PathCompiler.compile` wraps it as `InvalidPathException(cause)`.
    Runtime(String),
}

type R<T> = Result<T, Error>;

fn invalid<T>(message: impl Into<String>) -> R<T> {
    Err(Error::Invalid(message.into()))
}

fn text(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

fn u(c: char) -> u16 {
    c as u16
}

const DOC_CONTEXT: u16 = b'$' as u16;
const EVAL_CONTEXT: u16 = b'@' as u16;
const OPEN_SQUARE: u16 = b'[' as u16;
const CLOSE_SQUARE: u16 = b']' as u16;
const OPEN_PAREN: u16 = b'(' as u16;
const CLOSE_PAREN: u16 = b')' as u16;
const OPEN_BRACE: u16 = b'{' as u16;
const CLOSE_BRACE: u16 = b'}' as u16;
const WILDCARD: u16 = b'*' as u16;
const PERIOD: u16 = b'.' as u16;
const SPACE: u16 = b' ' as u16;
const COMMA: u16 = b',' as u16;
const SPLIT: u16 = b':' as u16;
const MINUS: u16 = b'-' as u16;
const SINGLE_QUOTE: u16 = b'\'' as u16;
const DOUBLE_QUOTE: u16 = b'"' as u16;
const BEGIN_FILTER: u16 = b'?' as u16;
const NOT: u16 = b'!' as u16;
const REGEX: u16 = b'/' as u16;

fn is_digit(c: u16) -> bool {
    char::from_u32(u32::from(c)).is_some_and(|c| c.is_ascii_digit() || (!c.is_ascii() && c.is_ascii_digit()))
}

fn is_whitespace(c: u16) -> bool {
    matches!(c, 0x20 | 0x09 | 0x0a | 0x0d)
}

/// `CharacterIndex`: a position and an inclusive end over the text.
struct Ci {
    s: Vec<u16>,
    pos: i64,
    end: i64,
}

impl Ci {
    fn new(s: &str) -> Ci {
        let s: Vec<u16> = s.encode_utf16().collect();
        let end = s.len() as i64 - 1;
        Ci { s, pos: 0, end }
    }

    fn len(&self) -> i64 {
        self.end + 1
    }

    fn char_at(&self, i: i64) -> R<u16> {
        if i < 0 || i >= self.s.len() as i64 {
            return Err(Error::Runtime(format!("java.lang.StringIndexOutOfBoundsException: Index {i} out of bounds for length {}", self.s.len())));
        }
        Ok(self.s[i as usize])
    }

    fn cur(&self) -> R<u16> {
        self.char_at(self.pos)
    }

    fn cur_is(&self, c: u16) -> R<bool> {
        Ok(self.cur()? == c)
    }

    fn last_is(&self, c: u16) -> R<bool> {
        Ok(self.char_at(self.end)? == c)
    }

    fn next_is(&self, c: u16) -> bool {
        self.in_bounds(self.pos + 1) && self.s[(self.pos + 1) as usize] == c
    }

    fn in_bounds(&self, i: i64) -> bool {
        i >= 0 && i <= self.end
    }

    fn oob(&self, i: i64) -> bool {
        !self.in_bounds(i)
    }

    fn here(&self) -> bool {
        self.in_bounds(self.pos)
    }

    fn sub(&self, start: i64, end: i64) -> R<Vec<u16>> {
        if start < 0 || end > self.s.len() as i64 || start > end {
            return Err(Error::Runtime(format!("java.lang.StringIndexOutOfBoundsException: begin {start}, end {end}, length {}", self.s.len())));
        }
        Ok(self.s[start as usize..end as usize].to_vec())
    }

    fn whole(&self) -> String {
        text(&self.s)
    }

    fn is_tail(&self) -> bool {
        self.pos >= self.end
    }

    fn has_more(&self) -> bool {
        self.in_bounds(self.pos + 1)
    }

    fn matching_close(&self, start: i64, open: u16, close: u16, skip_strings: bool, skip_regex: bool) -> R<i64> {
        if self.char_at(start)? != open {
            return invalid(format!("Expected {} but found {}", text(&[open]), text(&[self.char_at(start)?])));
        }
        let mut opened = 1;
        let mut rp = start + 1;
        while self.in_bounds(rp) {
            if skip_strings {
                let q = self.char_at(rp)?;
                if q == SINGLE_QUOTE || q == DOUBLE_QUOTE {
                    rp = self.next_unescaped_from(rp, q)?;
                    if rp == -1 {
                        return invalid(format!("Could not find matching close quote for {} when parsing : {}", text(&[q]), self.whole()));
                    }
                    rp += 1;
                }
            }
            if skip_regex && self.char_at(rp)? == REGEX {
                rp = self.next_unescaped_from(rp, REGEX)?;
                if rp == -1 {
                    return invalid(format!("Could not find matching close for / when parsing regex in : {}", self.whole()));
                }
                rp += 1;
            }
            if self.char_at(rp)? == open {
                opened += 1;
            }
            if self.char_at(rp)? == close {
                opened -= 1;
                if opened == 0 {
                    return Ok(rp);
                }
            }
            rp += 1;
        }
        Ok(-1)
    }

    fn index_of_next_significant(&self, start: i64, c: u16) -> R<i64> {
        let mut rp = start + 1;
        while !self.oob(rp) && self.char_at(rp)? == SPACE {
            rp += 1;
        }
        Ok(if self.char_at(rp)? == c { rp } else { -1 })
    }

    fn next_index_of(&self, start: i64, c: u16) -> R<i64> {
        let mut rp = start;
        while !self.oob(rp) {
            if self.char_at(rp)? == c {
                return Ok(rp);
            }
            rp += 1;
        }
        Ok(-1)
    }

    fn next_unescaped_from(&self, start: i64, c: u16) -> R<i64> {
        let mut rp = start + 1;
        let mut escape = false;
        while !self.oob(rp) {
            let ch = self.char_at(rp)?;
            if escape {
                escape = false;
            } else if ch == u(b'\\' as char) {
                escape = true;
            } else if ch == c {
                return Ok(rp);
            }
            rp += 1;
        }
        Ok(-1)
    }

    fn next_significant_is_at(&self, start: i64, c: u16) -> R<bool> {
        let mut rp = start + 1;
        while !self.oob(rp) && self.char_at(rp)? == SPACE {
            rp += 1;
        }
        Ok(!self.oob(rp) && self.char_at(rp)? == c)
    }

    fn next_significant_is(&self, c: u16) -> R<bool> {
        self.next_significant_is_at(self.pos, c)
    }

    fn next_significant_at(&self, start: i64) -> R<u16> {
        let mut rp = start + 1;
        while !self.oob(rp) && self.char_at(rp)? == SPACE {
            rp += 1;
        }
        if !self.oob(rp) { self.char_at(rp) } else { Ok(SPACE) }
    }

    fn next_significant(&self) -> R<u16> {
        self.next_significant_at(self.pos)
    }

    fn previous_significant_index(&self, start: i64) -> R<i64> {
        let mut rp = start - 1;
        while !self.oob(rp) && self.char_at(rp)? == SPACE {
            rp -= 1;
        }
        Ok(if !self.oob(rp) { rp } else { -1 })
    }

    fn previous_significant(&self) -> R<u16> {
        let i = self.previous_significant_index(self.pos)?;
        if i == -1 { Ok(SPACE) } else { self.char_at(i) }
    }

    fn skip_blanks(&mut self) -> R<&mut Ci> {
        while self.here() && self.pos < self.end && self.cur()? == SPACE {
            self.pos += 1;
        }
        Ok(self)
    }

    fn trim(&mut self) -> R<()> {
        self.skip_blanks()?;
        while self.here() && self.pos < self.end && self.last_is(SPACE)? {
            self.end -= 1;
        }
        Ok(())
    }

    fn read_significant(&mut self, c: u16) -> R<()> {
        if self.skip_blanks()?.cur()? != c {
            return invalid(format!("Expected character: {}", text(&[c])));
        }
        self.pos += 1;
        Ok(())
    }

    fn has_significant_sub_sequence(&mut self, s: &str) -> R<bool> {
        self.skip_blanks()?;
        let units: Vec<u16> = s.encode_utf16().collect();
        let n = units.len() as i64;
        if !self.in_bounds(self.pos + n - 1) {
            return Ok(false);
        }
        if self.sub(self.pos, self.pos + n)? != units {
            return Ok(false);
        }
        self.pos += n;
        Ok(true)
    }
}

/// `Utils.unescape`: only its failure (a `\u` followed by four characters `Integer.parseInt(.., 16)` refuses).
fn unescape_check(s: &[u16]) -> Result<(), String> {
    let mut i = 0;
    let mut had_slash = false;
    while i < s.len() {
        let ch = s[i];
        if had_slash {
            had_slash = false;
            if ch == u(b'u' as char) {
                // The four units after `\u`; fewer than four end the text silently.
                if s.len() >= i + 5 {
                    let digits = text(&s[i + 1..i + 5]);
                    if !parse_hex_int(&digits) {
                        return Err(format!("shaded_package.com.jayway.jsonpath.JsonPathException: Unable to parse unicode value: {digits}"));
                    }
                    i += 5;
                    continue;
                }
                return Ok(());
            }
            i += 1;
            continue;
        } else if ch == u(b'\\' as char) {
            had_slash = true;
        }
        i += 1;
    }
    Ok(())
}

/// `Integer.parseInt(four characters, 16)` succeeds: an optional sign, then hex digits.
fn parse_hex_int(s: &str) -> bool {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_hexdigit()) && i64::from_str_radix(digits, 16).is_ok()
}

/// `Integer.parseInt(token)` over a token of digits and signs, or its `NumberFormatException` text.
fn parse_int(token: &str) -> Result<(), String> {
    let digits = token.strip_prefix(['+', '-']).unwrap_or(token);
    if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) && token.parse::<i32>().is_ok() {
        return Ok(());
    }
    Err(format!("For input string: \"{token}\""))
}

/// `new BigDecimal(String)` accepts the text.
fn big_decimal_ok(s: &str) -> bool {
    let s = s.strip_prefix(['+', '-']).unwrap_or(s);
    let (mantissa, exponent) = match s.find(['e', 'E']) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let mut parts = mantissa.splitn(2, '.');
    let int = parts.next().unwrap_or("");
    let frac = parts.next();
    if !int.chars().all(|c| c.is_ascii_digit()) || !frac.is_none_or(|f| f.chars().all(|c| c.is_ascii_digit())) {
        return false;
    }
    if int.is_empty() && frac.is_none_or(str::is_empty) {
        return false;
    }
    match exponent {
        None => true,
        Some(e) => {
            let d = e.strip_prefix(['+', '-']).unwrap_or(e);
            !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()) && d.parse::<i64>().is_ok_and(|n| n < 1_000_000_000)
        }
    }
}

/// `PathCompiler.compile(String)`: the static entry. `Ok` when Jayway compiles the path.
pub(crate) fn compile(path: &str) -> Result<(), String> {
    match compile_top(path) {
        Ok(()) => Ok(()),
        Err(Error::Invalid(m)) | Err(Error::Runtime(m)) => Err(m),
    }
}

fn compile_top(path: &str) -> R<()> {
    let mut ci = Ci::new(path);
    ci.trim()?;
    if ci.char_at(0)? != DOC_CONTEXT && ci.char_at(0)? != EVAL_CONTEXT {
        ci = Ci::new(&format!("$.{path}"));
        ci.trim()?;
    }
    if ci.last_is(PERIOD)? {
        return invalid("Path must not end with a '.' or '..'");
    }
    Pc { path: ci }.read_context_token()
}

struct Pc {
    path: Ci,
}

impl Pc {
    fn read_whitespace(&mut self) -> R<()> {
        while self.path.here() {
            if !is_whitespace(self.path.cur()?) {
                break;
            }
            self.path.pos += 1;
        }
        Ok(())
    }

    fn read_context_token(&mut self) -> R<()> {
        self.read_whitespace()?;
        let c = self.path.cur()?;
        if c != DOC_CONTEXT && c != EVAL_CONTEXT {
            return invalid("Path must start with '$' or '@'");
        }
        if self.path.is_tail() {
            return Ok(());
        }
        self.path.pos += 1;
        let c = self.path.cur()?;
        if c != PERIOD && c != OPEN_SQUARE {
            return invalid(format!("Illegal character at position {} expected '.' or '['", self.path.pos));
        }
        self.read_next_token()?;
        Ok(())
    }

    fn read_next_token(&mut self) -> R<bool> {
        let c = self.path.cur()?;
        match c {
            OPEN_SQUARE => {
                if !self.read_bracket_property()? && !self.read_array()? && !self.read_wildcard()? && !self.read_filter()? && !self.read_placeholder()? {
                    return invalid(format!("Could not parse token starting at position {}. Expected ?, ', 0-9, * ", self.path.pos));
                }
                Ok(true)
            }
            PERIOD => {
                if !self.read_dot()? {
                    return invalid(format!("Could not parse token starting at position {}", self.path.pos));
                }
                Ok(true)
            }
            WILDCARD => {
                if !self.read_wildcard()? {
                    return invalid(format!("Could not parse token starting at position {}", self.path.pos));
                }
                Ok(true)
            }
            _ => {
                if !self.read_property_or_function()? {
                    return invalid(format!("Could not parse token starting at position {}", self.path.pos));
                }
                Ok(true)
            }
        }
    }

    fn read_dot(&mut self) -> R<bool> {
        if self.path.cur_is(PERIOD)? && self.path.next_is(PERIOD) {
            self.path.pos += 2;
        } else if !self.path.has_more() {
            return invalid("Path must not end with a '.");
        } else {
            self.path.pos += 1;
        }
        if self.path.cur_is(PERIOD)? {
            return invalid(format!("Character '.' on position {} is not valid.", self.path.pos));
        }
        self.read_next_token()
    }

    fn read_property_or_function(&mut self) -> R<bool> {
        let p = &self.path;
        if p.cur_is(OPEN_SQUARE)? || p.cur_is(WILDCARD)? || p.cur_is(PERIOD)? || p.cur_is(SPACE)? {
            return Ok(false);
        }
        let start = p.pos;
        let mut read = start;
        let mut end = 0;
        let mut is_function = false;
        while p.in_bounds(read) {
            let c = p.char_at(read)?;
            if c == SPACE {
                return invalid(format!("Use bracket notion ['my prop'] if your property contains blank characters. position: {}", p.pos));
            } else if c == PERIOD || c == OPEN_SQUARE {
                end = read;
                break;
            } else if c == OPEN_PAREN {
                is_function = true;
                end = read;
                break;
            }
            read += 1;
        }
        if end == 0 {
            end = p.len();
        }
        if is_function {
            let mut count = 1;
            let mut i = read + 1;
            while i < p.len() {
                if p.char_at(i)? == CLOSE_PAREN {
                    count -= 1;
                } else if p.char_at(i)? == OPEN_PAREN {
                    count += 1;
                }
                if count == 0 {
                    break;
                }
                i += 1;
            }
            if count != 0 {
                let name = text(&p.sub(start, end)?);
                return invalid(format!("Arguments to function: '{name}' are not closed properly."));
            }
            if p.in_bounds(read + 1) {
                let c = p.char_at(read + 1)?;
                if c != CLOSE_PAREN {
                    self.path.pos = end + 1;
                    let name = text(&self.path.sub(start, end)?);
                    self.parse_function_parameters(&name)?;
                } else {
                    self.path.pos = read + 1;
                }
            } else {
                self.path.pos = read;
            }
        } else {
            self.path.pos = end;
        }
        // The property name is cut from the text; `subSequence` can fail when `end` ran past it.
        self.path.sub(start, end)?;
        Ok(self.path.is_tail() || self.read_next_token()?)
    }

    fn parse_function_parameters(&mut self, name: &str) -> R<()> {
        #[derive(PartialEq, Clone, Copy)]
        enum Kind {
            Json,
            Path,
        }
        let mut kind: Option<Kind> = None;
        let (mut group_paren, mut group_bracket, mut group_brace, mut group_quote) = (1i32, 0i32, 0i32, 0i32);
        let mut end_of_stream = false;
        let mut prior: u16 = 0;
        let mut parameter: Vec<u16> = Vec::new();
        while self.path.here() && !end_of_stream {
            let c = self.path.cur()?;
            self.path.pos += 1;
            if kind.is_none() {
                if is_whitespace(c) {
                    continue;
                }
                if c == OPEN_BRACE || is_digit(c) || c == DOUBLE_QUOTE || c == MINUS {
                    kind = Some(Kind::Json);
                } else if c == DOC_CONTEXT || c == EVAL_CONTEXT {
                    kind = Some(Kind::Path);
                }
            }
            let mut boundary = false;
            match c {
                DOUBLE_QUOTE => {
                    if prior != u(b'\\' as char) && group_quote > 0 {
                        group_quote -= 1;
                    } else {
                        group_quote += 1;
                    }
                }
                OPEN_PAREN => group_paren += 1,
                OPEN_BRACE => group_brace += 1,
                OPEN_SQUARE => group_bracket += 1,
                CLOSE_BRACE => {
                    if group_brace == 0 {
                        return invalid(format!("Unexpected close brace '}}' at character position: {}", self.path.pos));
                    }
                    group_brace -= 1;
                }
                CLOSE_SQUARE => {
                    if group_bracket == 0 {
                        return invalid(format!("Unexpected close bracket ']' at character position: {}", self.path.pos));
                    }
                    group_bracket -= 1;
                }
                CLOSE_PAREN => {
                    group_paren -= 1;
                    if group_paren < 0 || prior == OPEN_PAREN {
                        parameter.push(c);
                    }
                    boundary = true;
                }
                COMMA => boundary = true,
                _ => {}
            }
            if boundary
                && group_quote == 0
                && group_brace == 0
                && group_bracket == 0
                && ((group_paren == 0 && c == CLOSE_PAREN) || group_paren == 1)
            {
                end_of_stream = group_paren == 0;
                if let Some(k) = kind {
                    if k == Kind::Path {
                        let mut sub = Pc { path: Ci::new(&text(&parameter)) };
                        sub.read_context_token()?;
                    }
                    parameter.clear();
                    kind = None;
                }
            }
            if kind.is_some() && !(c == COMMA && group_brace == 0 && group_bracket == 0 && group_paren == 1) {
                parameter.push(c);
            }
            prior = c;
        }
        if group_brace != 0 || group_paren != 0 || group_bracket != 0 {
            return invalid(format!("Arguments to function: '{name}' are not closed properly."));
        }
        Ok(())
    }

    /// `[?]`, `[?,?]`: with no predicates supplied, always the same refusal.
    fn read_placeholder(&mut self) -> R<bool> {
        let p = &self.path;
        if !p.cur_is(OPEN_SQUARE)? {
            return Ok(false);
        }
        let question = p.index_of_next_significant(p.pos, BEGIN_FILTER)?;
        if question == -1 {
            return Ok(false);
        }
        let next = p.next_significant_at(question)?;
        if next != CLOSE_SQUARE && next != COMMA {
            return Ok(false);
        }
        let begin = p.pos + 1;
        let end = p.next_index_of(begin, CLOSE_SQUARE)?;
        if end == -1 {
            return Ok(false);
        }
        let expression = text(&p.sub(begin, end)?);
        invalid(format!("Not enough predicates supplied for filter [{expression}] at position {}", p.pos))
    }

    fn read_filter(&mut self) -> R<bool> {
        let p = &self.path;
        if !p.cur_is(OPEN_SQUARE)? && !p.next_significant_is(BEGIN_FILTER)? {
            return Ok(false);
        }
        let open_statement = p.pos;
        let question = p.index_of_next_significant(p.pos, BEGIN_FILTER)?;
        if question == -1 {
            return Ok(false);
        }
        let open_bracket = p.index_of_next_significant(question, OPEN_PAREN)?;
        if open_bracket == -1 {
            return Ok(false);
        }
        let close_bracket = p.matching_close(open_bracket, OPEN_PAREN, CLOSE_PAREN, true, true)?;
        if close_bracket == -1 {
            return Ok(false);
        }
        if !p.next_significant_is_at(close_bracket, CLOSE_SQUARE)? {
            return Ok(false);
        }
        let close_statement = p.index_of_next_significant(close_bracket, CLOSE_SQUARE)?;
        let criteria = text(&p.sub(open_statement, close_statement + 1)?);
        Fc::new(&criteria)?.compile()?;
        self.path.pos = close_statement + 1;
        Ok(self.path.is_tail() || self.read_next_token()?)
    }

    fn read_wildcard(&mut self) -> R<bool> {
        let p = &self.path;
        let in_bracket = p.cur_is(OPEN_SQUARE)?;
        if in_bracket && !p.next_significant_is(WILDCARD)? {
            return Ok(false);
        }
        if !p.cur_is(WILDCARD)? && p.oob(p.pos + 1) {
            return Ok(false);
        }
        if in_bracket {
            let wildcard = p.index_of_next_significant(p.pos, WILDCARD)?;
            if !p.next_significant_is_at(wildcard, CLOSE_SQUARE)? {
                return invalid(format!("Expected wildcard token to end with ']' on position {}", wildcard + 1));
            }
            let close = p.index_of_next_significant(wildcard, CLOSE_SQUARE)?;
            self.path.pos = close + 1;
        } else {
            self.path.pos += 1;
        }
        Ok(self.path.is_tail() || self.read_next_token()?)
    }

    fn read_array(&mut self) -> R<bool> {
        let p = &self.path;
        if !p.cur_is(OPEN_SQUARE)? {
            return Ok(false);
        }
        let next = p.next_significant()?;
        if !is_digit(next) && next != MINUS && next != SPLIT {
            return Ok(false);
        }
        let begin = p.pos + 1;
        let end = p.next_index_of(begin, CLOSE_SQUARE)?;
        if end == -1 {
            return Ok(false);
        }
        let expression = text(&p.sub(begin, end)?).trim().to_string();
        if expression == "*" {
            return Ok(false);
        }
        for ch in expression.encode_utf16() {
            if !is_digit(ch) && ch != COMMA && ch != MINUS && ch != SPLIT && ch != SPACE {
                return Ok(false);
            }
        }
        if expression.contains(':') {
            slice_check(&expression)?;
        } else {
            index_check(&expression)?;
        }
        self.path.pos = end + 1;
        Ok(self.path.is_tail() || self.read_next_token()?)
    }

    fn read_bracket_property(&mut self) -> R<bool> {
        let p = &self.path;
        if !p.cur_is(OPEN_SQUARE)? {
            return Ok(false);
        }
        let delimiter = p.next_significant()?;
        if delimiter != SINGLE_QUOTE && delimiter != DOUBLE_QUOTE {
            return Ok(false);
        }
        let mut properties = 0;
        let mut start = p.pos + 1;
        let mut read = start;
        let mut end = 0;
        let mut in_property = false;
        let mut in_escape = false;
        let mut last_comma = false;
        while p.in_bounds(read) {
            let c = p.char_at(read)?;
            if in_escape {
                in_escape = false;
            } else if c == u(b'\\' as char) {
                in_escape = true;
            } else if c == CLOSE_SQUARE && !in_property {
                if last_comma {
                    return invalid(format!("Found empty property at index {read}"));
                }
                break;
            } else if c == delimiter {
                if in_property {
                    let next = p.next_significant_at(read)?;
                    if next != CLOSE_SQUARE && next != COMMA {
                        return invalid(format!("Property must be separated by comma or Property must be terminated close square bracket at index {read}"));
                    }
                    end = read;
                    let prop = p.sub(start, end)?;
                    if let Err(m) = unescape_check(&prop) {
                        return Err(Error::Runtime(m));
                    }
                    properties += 1;
                    in_property = false;
                } else {
                    start = read + 1;
                    in_property = true;
                    last_comma = false;
                }
            } else if c == COMMA && !in_property {
                if last_comma {
                    return invalid(format!("Found empty property at index {read}"));
                }
                last_comma = true;
            }
            read += 1;
        }
        if in_property {
            return invalid(format!("Property has not been closed - missing closing {}", text(&[delimiter])));
        }
        let end_bracket = p.index_of_next_significant(end, CLOSE_SQUARE)?;
        if end_bracket == -1 {
            return invalid("Property has not been closed - missing closing ]");
        }
        if properties == 0 {
            return invalid("Empty properties");
        }
        self.path.pos = end_bracket + 1;
        Ok(self.path.is_tail() || self.read_next_token()?)
    }
}

/// `ArraySliceOperation.parse`.
fn slice_check(op: &str) -> R<()> {
    if !op.encode_utf16().all(|c| is_digit(c) || c == MINUS || c == SPLIT) {
        return invalid(format!("Failed to parse SliceOperation: {op}"));
    }
    // `String.split(":")` drops trailing empty strings.
    let mut tokens: Vec<&str> = op.split(':').collect();
    while tokens.last().is_some_and(|t| t.is_empty()) {
        tokens.pop();
    }
    let read = |i: usize| -> R<bool> {
        match tokens.get(i) {
            Some(t) if !t.is_empty() => parse_int(t).map(|()| true).map_err(|m| Error::Runtime(format!("java.lang.NumberFormatException: {m}"))),
            _ => Ok(false),
        }
    };
    let from = read(0)?;
    let to = read(1)?;
    if !from && !to {
        return invalid(format!("Failed to parse SliceOperation: {op}"));
    }
    Ok(())
}

/// `ArrayIndexOperation.parse`.
fn index_check(op: &str) -> R<()> {
    if !op.encode_utf16().all(|c| is_digit(c) || c == COMMA || c == SPACE || c == MINUS) {
        return invalid(format!("Failed to parse ArrayIndexOperation: {op}"));
    }
    for token in op.split(',') {
        if parse_int(token).is_err() {
            return invalid(format!("Failed to parse token in ArrayIndexOperation: {token}"));
        }
    }
    Ok(())
}

/// `FilterCompiler`.
struct Fc {
    filter: Ci,
}

const RELATIONAL: [&str; 21] = [
    ">=", "<=", "==", "===", "!=", "!==", "<", ">", "=~", "NIN", "IN", "CONTAINS", "ALL", "SIZE", "EXISTS", "TYPE", "MATCHES", "EMPTY",
    "SUBSETOF", "ANYOF", "NONEOF",
];

fn is_relational_char(c: u16) -> bool {
    matches!(c, 0x3c | 0x3e | 0x3d | 0x7e | 0x21)
}

impl Fc {
    fn new(criteria: &str) -> R<Fc> {
        let mut filter = Ci::new(criteria);
        filter.trim()?;
        if !filter.cur_is(OPEN_SQUARE)? || !filter.last_is(CLOSE_SQUARE)? {
            return invalid(format!("Filter must start with '[' and end with ']'. {criteria}"));
        }
        filter.pos += 1;
        filter.end -= 1;
        filter.trim()?;
        if !filter.cur_is(BEGIN_FILTER)? {
            return invalid(format!("Filter must start with '[?' and end with ']'. {criteria}"));
        }
        filter.pos += 1;
        filter.trim()?;
        if !filter.cur_is(OPEN_PAREN)? || !filter.last_is(CLOSE_PAREN)? {
            return invalid(format!("Filter must start with '[?(' and end with ')]'. {criteria}"));
        }
        Ok(Fc { filter })
    }

    fn compile(&mut self) -> R<()> {
        let attempt = (|| -> R<()> {
            self.read_or()?;
            self.filter.skip_blanks()?;
            if self.filter.here() {
                let rest = self.filter.sub(self.filter.pos, self.filter.len())?;
                return invalid(format!("Expected end of filter expression instead of: {}", text(&rest)));
            }
            Ok(())
        })();
        match attempt {
            Err(Error::Runtime(_)) => {
                let c = self.filter.cur()?;
                invalid(format!("Failed to parse filter: {}, error on position: {}, char: {}", self.filter.whole(), self.filter.pos, text(&[c])))
            }
            other => other,
        }
    }

    fn read_or(&mut self) -> R<()> {
        self.read_and()?;
        loop {
            let save = self.filter.pos;
            if self.filter.has_significant_sub_sequence("||")? {
                self.read_and()?;
            } else {
                self.filter.pos = save;
                return Ok(());
            }
        }
    }

    fn read_and(&mut self) -> R<()> {
        self.read_and_operand()?;
        loop {
            let save = self.filter.pos;
            if self.filter.has_significant_sub_sequence("&&")? {
                self.read_and_operand()?;
            } else {
                self.filter.pos = save;
                return Ok(());
            }
        }
    }

    fn read_and_operand(&mut self) -> R<()> {
        let save = self.filter.skip_blanks()?.pos;
        if self.filter.skip_blanks()?.cur_is(NOT)? {
            self.filter.read_significant(NOT)?;
            match self.filter.skip_blanks()?.cur()? {
                DOC_CONTEXT | EVAL_CONTEXT => self.filter.pos = save,
                _ => return self.read_and_operand(),
            }
        }
        if self.filter.skip_blanks()?.cur_is(OPEN_PAREN)? {
            self.filter.read_significant(OPEN_PAREN)?;
            self.read_or()?;
            self.filter.read_significant(CLOSE_PAREN)?;
            return Ok(());
        }
        self.read_expression()
    }

    fn read_expression(&mut self) -> R<()> {
        let left_is_path = self.read_value()?;
        let save = self.filter.pos;
        let attempt = (|| -> R<()> {
            self.read_relational_operator()?;
            self.read_value()?;
            Ok(())
        })();
        match attempt {
            Ok(()) => return Ok(()),
            Err(Error::Invalid(_)) => self.filter.pos = save,
            Err(e) => return Err(e),
        }
        if !left_is_path {
            return invalid("Expected path node");
        }
        Ok(())
    }

    fn read_relational_operator(&mut self) -> R<()> {
        let begin = self.filter.skip_blanks()?.pos;
        if is_relational_char(self.filter.cur()?) {
            while self.filter.here() && is_relational_char(self.filter.cur()?) {
                self.filter.pos += 1;
            }
        } else {
            while self.filter.here() && self.filter.cur()? != SPACE {
                self.filter.pos += 1;
            }
        }
        let op = text(&self.filter.sub(begin, self.filter.pos)?);
        if RELATIONAL.contains(&op.to_uppercase().as_str()) {
            Ok(())
        } else {
            invalid(format!("Filter operator {op} is not supported!"))
        }
    }

    /// Reads a value node; whether it is a path node.
    fn read_value(&mut self) -> R<bool> {
        match self.filter.skip_blanks()?.cur()? {
            DOC_CONTEXT | EVAL_CONTEXT => self.read_path().map(|()| true),
            NOT => {
                self.filter.pos += 1;
                match self.filter.skip_blanks()?.cur()? {
                    DOC_CONTEXT | EVAL_CONTEXT => self.read_path().map(|()| true),
                    _ => invalid("Unexpected character: !"),
                }
            }
            _ => self.read_literal().map(|()| false),
        }
    }

    fn read_literal(&mut self) -> R<()> {
        match self.filter.skip_blanks()?.cur()? {
            SINGLE_QUOTE => self.read_string(SINGLE_QUOTE),
            DOUBLE_QUOTE => self.read_string(DOUBLE_QUOTE),
            0x74 | 0x66 => self.read_boolean(),
            MINUS => self.read_number(),
            0x6e => self.read_null(),
            OPEN_BRACE | OPEN_SQUARE => self.read_json(),
            REGEX => self.read_pattern(),
            _ => self.read_number(),
        }
    }

    fn read_null(&mut self) -> R<()> {
        let f = &mut self.filter;
        if f.cur()? == 0x6e && f.in_bounds(f.pos + 3) && text(&f.sub(f.pos, f.pos + 4)?) == "null" {
            f.pos += 4;
            return Ok(());
        }
        invalid("Expected <null> value")
    }

    fn read_json(&mut self) -> R<()> {
        let f = &mut self.filter;
        let open = f.cur()?;
        let close = if open == OPEN_SQUARE { CLOSE_SQUARE } else { CLOSE_BRACE };
        let closing = f.matching_close(f.pos, open, close, true, false)?;
        if closing == -1 {
            return invalid(format!("String not closed. Expected ' in {}", f.whole()));
        }
        f.pos = closing + 1;
        Ok(())
    }

    fn read_pattern(&mut self) -> R<()> {
        let f = &mut self.filter;
        let begin = f.pos;
        let mut closing = f.next_unescaped_from(f.pos, REGEX)?;
        if closing == -1 {
            return invalid(format!("Pattern not closed. Expected / in {}", f.whole()));
        }
        if f.in_bounds(closing + 1) {
            let mut e = closing + 1;
            while f.in_bounds(e) {
                if flag_value(f.char_at(e)?) > 0 {
                    e += 1;
                    continue;
                }
                break;
            }
            if e > closing {
                closing += e - (closing + 1);
            }
        }
        f.pos = closing + 1;
        let tmp = f.sub(begin, f.pos)?;
        let first = tmp.iter().position(|&c| c == REGEX).unwrap_or(0);
        let last = tmp.iter().rposition(|&c| c == REGEX).unwrap_or(0);
        if first + 1 > last {
            return Err(Error::Runtime("java.lang.StringIndexOutOfBoundsException".into()));
        }
        let pattern = text(&tmp[first + 1..last]);
        let flags: u32 = tmp[last + 1..].iter().fold(0, |acc, &c| acc | flag_value(c));
        java_pattern::compile_with_flags(&pattern, flags).map(|_| ()).map_err(|e| Error::Runtime(e.to_string()))
    }

    fn read_string(&mut self, end_char: u16) -> R<()> {
        let f = &mut self.filter;
        let begin = f.pos;
        let closing = f.next_unescaped_from(f.pos, end_char)?;
        if closing == -1 {
            return invalid(format!("String literal does not have matching quotes. Expected {} in {}", text(&[end_char]), f.whole()));
        }
        f.pos = closing + 1;
        let literal = f.sub(begin, f.pos)?;
        let body: &[u16] = if literal.len() > 1 && literal[0] == literal[literal.len() - 1] && (literal[0] == SINGLE_QUOTE || literal[0] == DOUBLE_QUOTE) {
            &literal[1..literal.len() - 1]
        } else {
            &literal
        };
        if literal.len() > 1 {
            unescape_check(body).map_err(Error::Runtime)?;
        }
        Ok(())
    }

    fn read_number(&mut self) -> R<()> {
        let f = &mut self.filter;
        let begin = f.pos;
        while f.here() {
            let c = f.cur()?;
            if is_digit(c) || c == MINUS || c == PERIOD || c == u(b'E' as char) || c == u(b'e' as char) {
                f.pos += 1;
            } else {
                break;
            }
        }
        let literal = text(&f.sub(begin, f.pos)?);
        if big_decimal_ok(&literal) { Ok(()) } else { Err(Error::Runtime("java.lang.NumberFormatException".into())) }
    }

    fn read_boolean(&mut self) -> R<()> {
        let f = &mut self.filter;
        let begin = f.pos;
        let end = if f.cur()? == 0x74 { f.pos + 3 } else { f.pos + 4 };
        if !f.in_bounds(end) {
            return invalid("Expected boolean literal");
        }
        let value = text(&f.sub(begin, end + 1)?);
        if value != "true" && value != "false" {
            return invalid("Expected boolean literal");
        }
        f.pos += value.len() as i64;
        Ok(())
    }

    fn read_path(&mut self) -> R<()> {
        self.filter.previous_significant()?;
        let begin = self.filter.pos;
        self.filter.pos += 1;
        while self.filter.here() {
            if self.filter.cur()? == OPEN_SQUARE {
                let closing = self.filter.matching_close(self.filter.pos, OPEN_SQUARE, CLOSE_SQUARE, true, false)?;
                if closing == -1 {
                    return invalid(format!("Square brackets does not match in filter {}", self.filter.whole()));
                }
                self.filter.pos = closing + 1;
            }
            let closing_function = self.filter.cur()? == CLOSE_PAREN && self.closing_function_bracket(begin)?;
            let closing_logical = self.filter.cur()? == CLOSE_PAREN && !closing_function;
            if !self.filter.here() || is_relational_char(self.filter.cur()?) || self.filter.cur()? == SPACE || closing_logical {
                break;
            }
            self.filter.pos += 1;
        }
        let path = text(&self.filter.sub(begin, self.filter.pos)?);
        compile_top(&path)
    }

    fn closing_function_bracket(&self, lower: i64) -> R<bool> {
        let f = &self.filter;
        if f.cur()? != CLOSE_PAREN {
            return Ok(false);
        }
        let mut idx = f.previous_significant_index(f.pos)?;
        if idx == -1 || f.char_at(idx)? != OPEN_PAREN {
            return Ok(false);
        }
        idx -= 1;
        while f.in_bounds(idx) && idx > lower {
            if f.char_at(idx)? == PERIOD {
                return Ok(true);
            }
            idx -= 1;
        }
        Ok(false)
    }
}

/// `PatternFlag`: the `Pattern` flag a letter stands for, or 0.
fn flag_value(c: u16) -> u32 {
    match char::from_u32(u32::from(c)) {
        Some('d') => 1,
        Some('i') => 2,
        Some('x') => 4,
        Some('m') => 8,
        Some('s') => 32,
        Some('u') => 64,
        Some('U') => 256,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::compile;

    #[test]
    fn compiles_what_jayway_compiles() {
        for path in ["$", "$.a", "$.a.b", "$['a','b']", "$.a[0]", "$.a[1:2]", "$..a", "$.a[*]", "$.a[?(@.b == 1)]", "$[?(@.owner=='team-a')]", "$.a[", "$.a.b)", "@", "a.b", "$.a.length()"] {
            assert_eq!(compile(path), Ok(()), "{path}");
        }
    }

    #[test]
    fn words_failures_as_jayway_does() {
        let cases = [
            ("$[", "java.lang.StringIndexOutOfBoundsException: Index 2 out of bounds for length 2"),
            ("$..", "Path must not end with a '.' or '..'"),
            ("$.a b", "Use bracket notion ['my prop'] if your property contains blank characters. position: 2"),
            ("$.a[?(@.x", "Could not parse token starting at position 3. Expected ?, ', 0-9, * "),
            ("$.[", "java.lang.StringIndexOutOfBoundsException: Index 3 out of bounds for length 3"),
            ("$.a[?(@.b==)]", "Failed to parse filter: [?(@.b==)], error on position: 8, char: )"),
            ("$['a", "Property has not been closed - missing closing '"),
        ];
        for (path, why) in cases {
            assert_eq!(compile(path), Err(why.to_string()), "{path}");
        }
    }
}

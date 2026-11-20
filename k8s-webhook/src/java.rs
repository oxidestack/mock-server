//! The few JDK behaviours the webhook's Java code leans on: exceptions as values (class, message, cause),
//! `Integer.parseInt`, `String.equalsIgnoreCase` and `String.trim`.

use std::fmt;

/// A thrown Java exception: `toString()` is `class: message`, and `printStackTrace` adds `Caused by:` lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JavaException {
    /// Fully-qualified class, e.g. `java.lang.IllegalArgumentException`.
    pub class: String,
    /// `getMessage()`; `None` is Java's `null`.
    pub message: Option<String>,
    pub cause: Option<Box<JavaException>>,
}

impl JavaException {
    pub fn new(class: &str, message: impl Into<String>) -> JavaException {
        JavaException { class: class.to_string(), message: Some(message.into()), cause: None }
    }

    pub fn illegal_argument(message: impl Into<String>) -> JavaException {
        JavaException::new("java.lang.IllegalArgumentException", message)
    }

    pub fn with_cause(mut self, cause: JavaException) -> JavaException {
        self.cause = Some(Box::new(cause));
        self
    }

    /// `getMessage()`, with Java's `null` printed as `null` (string concatenation).
    pub fn message_text(&self) -> &str {
        self.message.as_deref().unwrap_or("null")
    }

    /// `printStackTrace()` without the `\tat` frames (a Rust process has none to print).
    pub fn stack_trace(&self) -> String {
        let mut out = self.to_string();
        let mut cause = self.cause.as_deref();
        while let Some(c) = cause {
            out.push_str("\nCaused by: ");
            out.push_str(&c.to_string());
            cause = c.cause.as_deref();
        }
        out
    }
}

impl fmt::Display for JavaException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(m) => write!(f, "{}: {}", self.class, m),
            None => f.write_str(&self.class),
        }
    }
}

impl std::error::Error for JavaException {}

impl From<jackson::JacksonError> for JavaException {
    fn from(e: jackson::JacksonError) -> JavaException {
        JavaException::new(&e.class, e.message)
    }
}

/// `Integer.parseInt(s)`: an optional sign, then decimal digits in the sense of `Character.digit(c, 10)` (every
/// Unicode `Nd` digit, not only ASCII), within `int` range.
pub fn parse_int(s: &str) -> Result<i32, JavaException> {
    let error = || JavaException::new("java.lang.NumberFormatException", format!("For input string: \"{s}\""));
    let mut chars = s.chars().peekable();
    let negative = match chars.peek() {
        Some('-') => true,
        Some('+') => false,
        Some(_) => {
            return digits(chars, false).ok_or_else(error);
        }
        None => return Err(error()),
    };
    chars.next();
    if chars.peek().is_none() {
        return Err(error());
    }
    digits(chars, negative).ok_or_else(error)
}

fn digits(chars: impl Iterator<Item = char>, negative: bool) -> Option<i32> {
    // accumulated negatively, as Integer.parseInt does, so i32::MIN fits
    let mut result: i64 = 0;
    for c in chars {
        let d = decimal_digit(c)? as i64;
        result = result * 10 - d;
        if result < i32::MIN as i64 {
            return None;
        }
    }
    if negative { Some(result as i32) } else { i32::try_from(-result).ok() }
}

/// The zero of every run of ten Unicode `Nd` digits in JDK 17's Unicode 13.0 tables (`Character.digit` reads any of
/// them); U+1D7CE starts five consecutive runs of mathematical digits.
const ND_ZEROS: &[u32] = &[
    0x0030, 0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66, 0x0DE6,
    0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90, 0x1B50, 0x1BB0, 0x1C40,
    0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10, 0x104A0, 0x10D30, 0x11066, 0x110F0,
    0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650, 0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50,
    0x11DA0, 0x16A60, 0x16B50, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E950, 0x1FBF0,
];

/// `Character.digit(c, 10)`, or `None` for -1.
pub fn decimal_digit(c: char) -> Option<u32> {
    let cp = c as u32;
    ND_ZEROS.iter().find(|&&zero| cp >= zero && cp < zero + 10).map(|zero| cp - zero)
}

/// `a.equalsIgnoreCase(b)`.
pub fn equals_ignore_case(a: &str, b: &str) -> bool {
    a.encode_utf16().count() == b.encode_utf16().count() && java_compat::lang::compare_ignore_case(a, b) == 0
}

/// `String.trim()`.
pub fn trim(s: &str) -> &str {
    java_compat::lang::java_trim(s)
}

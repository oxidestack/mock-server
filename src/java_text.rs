//! Java `String`/`Pattern` behaviours that several upstream code paths depend on.

/// `String.split(regex)` for a literal separator: trailing empty strings removed, and a string made only of
/// separators yields nothing (an empty string yields one empty string).
pub fn split<'a>(s: &'a str, separator: &str) -> Vec<&'a str> {
    let mut parts: Vec<&str> = s.split(separator).collect();
    while parts.len() > 1 && parts.last() == Some(&"") {
        parts.pop();
    }
    if parts == [""] && !s.is_empty() {
        parts.clear();
    }
    parts
}

/// `Pattern.quote`: `\Q…\E`, with any `\E` inside split out.
pub fn quote(s: &str) -> String {
    let mut out = String::from("\\Q");
    let mut rest = s;
    while let Some(i) = rest.find("\\E") {
        out.push_str(&rest[..i]);
        out.push_str("\\E\\\\E\\Q");
        rest = &rest[i + 2..];
    }
    out.push_str(rest);
    out.push_str("\\E");
    out
}

/// The charset `URLDecoder.decode` turns escaped bytes into text with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlCharset {
    Utf8,
    /// `US-ASCII`: an escaped byte past ASCII becomes U+FFFD.
    Ascii,
}

/// `URLDecoder.decode(s, charset)`: `+` is a space, each run of `%XX` escapes is decoded as bytes in `charset`;
/// the `IllegalArgumentException` message for a malformed escape (`Integer.parseInt(s, i + 1, i + 3, 16)`'s
/// `NumberFormatException` text, a negative value, a trailing incomplete escape).
pub fn url_decode(s: &str, charset: UrlCharset) -> Result<String, String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '+' => {
                out.push(' ');
                i += 1;
            }
            '%' => {
                let mut bytes = Vec::new();
                while i + 2 < chars.len() && chars[i] == '%' {
                    let pair: String = chars[i + 1..i + 3].iter().collect();
                    bytes.push(parse_hex_byte(&pair)?);
                    i += 3;
                }
                if i < chars.len() && chars[i] == '%' {
                    return Err("URLDecoder: Incomplete trailing escape (%) pattern".into());
                }
                match charset {
                    UrlCharset::Utf8 => out.push_str(&String::from_utf8_lossy(&bytes)),
                    UrlCharset::Ascii => out.extend(bytes.iter().map(|b| if *b < 0x80 { *b as char } else { '\u{FFFD}' })),
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// `Integer.parseInt(pair, 16)` for an escape's two characters (a sign is allowed, as `parseInt` allows one).
fn parse_hex_byte(pair: &str) -> Result<u8, String> {
    let illegal = |index: usize| format!("URLDecoder: Illegal hex characters in escape (%) pattern - Error at index {index} in: \"{pair}\"");
    let (negative, digits, offset) = match pair.chars().next() {
        Some('-') => (true, &pair[1..], 1),
        Some('+') => (false, &pair[1..], 1),
        _ => (false, pair, 0),
    };
    let mut value: i32 = 0;
    for (k, c) in digits.chars().enumerate() {
        value = value * 16 + c.to_digit(16).ok_or_else(|| illegal(offset + k))? as i32;
    }
    if negative && value != 0 {
        return Err("URLDecoder: Illegal hex characters in escape (%) pattern - negative value".into());
    }
    Ok(value as u8)
}

#[cfg(test)]
mod tests {
    #[test]
    fn split_and_quote() {
        assert_eq!(super::split("a=1&&b&", "&"), vec!["a=1", "", "b"]);
        assert_eq!(super::split("&&", "&"), Vec::<&str>::new());
        assert_eq!(super::split("", "&"), vec![""]);
        assert_eq!(super::split("a.b.", "."), vec!["a", "b"]);
        assert_eq!(super::quote("a.b"), "\\Qa.b\\E");
        assert_eq!(super::quote("a\\Eb"), "\\Qa\\E\\\\E\\Qb\\E");
    }

    #[test]
    fn url_decode_as_url_decoder() {
        use super::{UrlCharset::*, url_decode};
        assert_eq!(url_decode("p%C3%BC", Ascii).unwrap(), "p\u{FFFD}\u{FFFD}");
        assert_eq!(url_decode("p%C3%BC+x", Utf8).unwrap(), "pü x");
        assert_eq!(url_decode("u%3Ax", Ascii).unwrap(), "u:x");
        assert_eq!(url_decode("%zz", Utf8).unwrap_err(), "URLDecoder: Illegal hex characters in escape (%) pattern - Error at index 0 in: \"zz\"");
        assert_eq!(url_decode("%4z", Utf8).unwrap_err(), "URLDecoder: Illegal hex characters in escape (%) pattern - Error at index 1 in: \"4z\"");
        assert_eq!(url_decode("%-1", Utf8).unwrap_err(), "URLDecoder: Illegal hex characters in escape (%) pattern - negative value");
        assert_eq!(url_decode("%+1x", Utf8).unwrap(), "\u{1}x");
        assert_eq!(url_decode("a%4", Utf8).unwrap_err(), "URLDecoder: Incomplete trailing escape (%) pattern");
        assert_eq!(url_decode("a%", Utf8).unwrap_err(), "URLDecoder: Incomplete trailing escape (%) pattern");
    }
}

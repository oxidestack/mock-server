//! networknt's `Formats.DEFAULT` and the Java regex dialect its patterns are written in.
//!
//! Each format checks a string the way its networknt class does: `PatternFormat`s as a full `java.util.regex` match,
//! `date` through `LocalDate.parse`, `date-time` through ethlo's `ITU.parseDateTime` (MockServer ships it, so
//! `DateTimeFormat` prefers it), `time` through a `DateTimeFormatter`, the URI family through `java.net.URI`,
//! `email`/`idn-email` through commons-validator's `EmailValidator`, `idn-hostname` through `RFC5892`.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// The failure of `value` against a known format: `Some(detail)` with the message suffix of the format's
/// `format.<name>` key (`None` for the plain `format` key of the extra pattern formats). `None` when the value
/// conforms or the format is unknown (no assertion without `strict`).
pub fn failure(format: &str, value: &str) -> Option<Option<&'static str>> {
    let (ok, detail) = match format {
        "hostname" => (full_match(HOSTNAME, value), Some("must be a valid RFC 1123 host name")),
        "ipv4" => (full_match(IPV4, value), Some("must be a valid RFC 2673 IP address")),
        "ipv6" => (ipv6(value), Some("must be a valid RFC 4291 IP address")),
        "json-pointer" => (full_match(r"^(/([^/#~]|[~](?=[01]))*)*$", value), Some("must be a valid RFC 6901 JSON Pointer")),
        "relative-json-pointer" => {
            (full_match(r"^(0|([1-9]\d*))(#|(/([^/#~]|[~](?=[01]))*)*)$", value), Some("must be a valid IETF Relative JSON Pointer"))
        }
        "uri-template" => (full_match(URI_TEMPLATE, value), Some("must be a valid RFC 6570 URI Template")),
        "uuid" => (full_match(r"^\p{XDigit}{8}-\p{XDigit}{4}-\p{XDigit}{4}-\p{XDigit}{4}-\p{XDigit}{12}$", value), Some("must be a valid RFC 4122 UUID")),
        "date" => (super::datetime::local_date(value).is_some_and(|(y, _, _)| (0..=9999).contains(&y)), Some("must be a valid RFC 3339 full-date")),
        "date-time" => (super::datetime::itu_date_time(value), Some("must be a valid RFC 3339 date-time")),
        "email" => (!contains_non_ascii_whitespace(value) && super::email::is_valid(value), Some("must be a valid RFC 5321 Mailbox")),
        "idn-email" => (!contains_non_ascii_whitespace(value) && super::email::is_valid(value), Some("must be a valid RFC 6531 Mailbox")),
        "idn-hostname" => (super::idn::is_valid(value), Some("must be a valid RFC 5890 internationalized hostname")),
        "iri" => (rfc3986(value, iri), Some("must be a valid RFC 3987 IRI")),
        "iri-reference" => (rfc3986(value, iri_reference), Some("must be a valid RFC 3987 IRI-reference")),
        "regex" => (java_regex_compiles(value), Some("must be a valid ECMA-262 regular expression")),
        "time" => (super::datetime::time(value), Some("must be a valid RFC 3339 time")),
        "uri" => (rfc3986(value, uri), Some("must be a valid RFC 3986 URI")),
        "uri-reference" => (rfc3986(value, uri_reference), Some("must be a valid RFC 3986 URI-reference")),
        "duration" => (duration(value), Some("must be a valid ISO 8601 duration")),
        "alpha" => (full_match("^[a-zA-Z]+$", value), None),
        "alphanumeric" => (full_match("^[a-zA-Z0-9]+$", value), None),
        "color" => (full_match(COLOR, value), None),
        "ip-address" => (full_match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", value), None),
        "phone" => (full_match(r"^\+(?:[0-9] ?){6,14}[0-9]$", value), None),
        "style" => (full_match(r"\s*(.+?):\s*([^;]+);?", value), None),
        "utc-millisec" => (full_match(r"^[0-9]+(\.?[0-9]+)?$", value), None),
        _ => return None,
    };
    (!ok).then_some(detail)
}

const HOSTNAME: &str = r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$";
const IPV4: &str = r"^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$";
const URI_TEMPLATE: &str = r#"^([^\p{Cntrl}"'%<>\^`\{|\}]|%\p{XDigit}{2}|\{[+#./;?&=,!@|]?((\w|%\p{XDigit}{2})(\.?(\w|%\p{XDigit}{2}))*(:[1-9]\d{0,3}|\*)?)(,((\w|%\p{XDigit}{2})(\.?(\w|%\p{XDigit}{2}))*(:[1-9]\d{0,3}|\*)?))*\})*$"#;
const COLOR: &str = r"(#?([0-9A-Fa-f]{3,6})\b)|(aqua)|(black)|(blue)|(fuchsia)|(gray)|(green)|(lime)|(maroon)|(navy)|(olive)|(orange)|(purple)|(red)|(silver)|(teal)|(white)|(yellow)|(rgb\(\s*\b([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\b\s*,\s*\b([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\b\s*,\s*\b([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\b\s*\))|(rgb\(\s*(\d?\d%|100%)+\s*,\s*(\d?\d%|100%)+\s*,\s*(\d?\d%|100%)+\s*\))";
pub(super) const IPV6: &str = r"^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$";

/// `Pattern.compile(regex).matcher(value).matches()`.
pub(super) fn full_match(regex: &str, value: &str) -> bool {
    cached(&format!("^(?:{})\\z", regex)).is_some_and(|re| re.is_match(value).unwrap_or(false))
}

/// The same with `Pattern.CASE_INSENSITIVE`.
fn full_match_ignore_case(regex: &str, value: &str) -> bool {
    cached(&format!("(?i)^(?:{})\\z", regex)).is_some_and(|re| re.is_match(value).unwrap_or(false))
}

static CACHE: LazyLock<Mutex<HashMap<String, Option<fancy_regex::Regex>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// A Java pattern compiled once (translated by [`translate`]); `None` when it does not compile.
pub(super) fn cached(java: &str) -> Option<fancy_regex::Regex> {
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() > 4096 {
        cache.clear();
    }
    cache.entry(java.to_string()).or_insert_with(|| translate(java).and_then(|t| fancy_regex::Regex::new(&t).ok())).clone()
}

/// A user's `java.util.regex` pattern after the long-form property rewriting, compiled as `Pattern.compile` does
/// (`matcher::java_pattern`), or the `PatternSyntaxException` it throws.
pub fn java_regex(java: &str) -> Result<std::sync::Arc<crate::matcher::java_pattern::JavaRegex>, crate::matcher::java_pattern::PatternSyntaxException> {
    crate::matcher::java_pattern::compile(&replace_longform_properties(java))
}

/// `Pattern.compile` accepts `pattern` (networknt's `RegexFormat`, through `JDKRegularExpression`'s rewriting).
fn java_regex_compiles(pattern: &str) -> bool {
    java_regex(&replace_dollar_anchors(pattern)).is_ok()
}

/// `RegularExpressions.replaceDollarAnchors`: `$` outside character classes and `\Q…\E` becomes `\z`.
pub fn replace_dollar_anchors(regex: &str) -> String {
    if !regex.contains('$') {
        return regex.to_string();
    }
    let chars: Vec<char> = regex.chars().collect();
    let mut out = String::new();
    let (mut in_class, mut literal) = (false, false);
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if literal {
            if c == '\\' && chars.get(i + 1) == Some(&'E') {
                out.push_str("\\E");
                literal = false;
                i += 1;
            } else {
                out.push(c);
            }
        } else if c == '\\' {
            out.push(c);
            if let Some(&n) = chars.get(i + 1) {
                out.push(n);
                literal = n == 'Q';
                i += 1;
            }
        } else if c == '[' {
            in_class = true;
            out.push(c);
        } else if c == ']' {
            in_class = false;
            out.push(c);
        } else if c == '$' && !in_class {
            out.push_str("\\z");
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// `RegularExpressions.replaceLongformCharacterProperties`: `\p{Letter}` and friends as their short names.
pub(super) fn replace_longform_properties(regex: &str) -> String {
    if !regex.contains("\\p{") {
        return regex.to_string();
    }
    const LONG: &[(&str, &str)] = &[
        ("Letter", "L"), ("Lowercase_Letter", "Ll"), ("Uppercase_Letter", "Lu"), ("Titlecase_Letter", "Lt"), ("Cased_Letter", "L&"),
        ("Modifier_Letter", "Lm"), ("Other_Letter", "Lo"), ("Mark", "M"), ("Non_Spacing_Mark", "Mn"), ("Spacing_Combining_Mark", "Mc"),
        ("Enclosing_Mark", "Me"), ("Separator", "Z"), ("Space_Separator", "Zs"), ("Line_Separator", "Zl"), ("Paragraph_Separator", "Zp"),
        ("Symbol", "S"), ("Math_Symbol", "Sm"), ("Currency_Symbol", "Sc"), ("Modifier_Symbol", "Sk"), ("Other_Symbol", "So"),
        ("Number", "N"), ("Decimal_Digit_Number", "Nd"), ("Letter_Number", "Nl"), ("Other_Number", "No"), ("Punctuation", "P"),
        ("Dash_Punctuation", "Pd"), ("Open_Punctuation", "Ps"), ("Close_Punctuation", "Pe"), ("Initial_Punctuation", "Pi"),
        ("Final_Punctuation", "Pf"), ("Connector_Punctuation", "Pc"), ("Other_Punctuation", "Po"), ("Other", "C"), ("Control", "Cc"),
        ("Format", "Cf"), ("Private_Use", "Co"), ("Surrogate", "Cs"), ("Unassigned", "Cn"), ("digit", "Nd"),
    ];
    let chars: Vec<char> = regex.chars().collect();
    let mut out = String::new();
    let (mut in_class, mut literal) = (false, false);
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if literal {
            if c == '\\' && chars.get(i + 1) == Some(&'E') {
                out.push_str("\\E");
                literal = false;
                i += 2;
            } else {
                out.push(c);
                i += 1;
            }
            continue;
        }
        if !in_class && c == '\\' && chars.get(i + 1) == Some(&'p') && chars.get(i + 2) == Some(&'{') {
            let mut j = i + 3;
            let mut end = None;
            while j < chars.len() {
                if chars[j] == '}' {
                    end = Some(j);
                    break;
                }
                if chars[j] == '\\' {
                    j += 1;
                }
                j += 1;
            }
            if let Some(end) = end {
                let name: String = chars[i + 3..end].iter().collect();
                let short = LONG.iter().find(|(l, _)| *l == name).map_or(name.as_str(), |(_, s)| s);
                out.push_str("\\p{");
                out.push_str(short);
                out.push('}');
                i = end + 1;
                continue;
            }
        }
        if c == '\\' {
            out.push(c);
            if let Some(&n) = chars.get(i + 1) {
                out.push(n);
                literal = n == 'Q';
                i += 1;
            }
        } else if c == '[' {
            in_class = true;
            out.push(c);
        } else if c == ']' {
            in_class = false;
            out.push(c);
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// Java regex syntax as `fancy_regex` syntax: `\Q…\E` quoting, the POSIX/`java.lang.Character` `\p{…}` classes, `\cX`,
/// `\e`, `\0`-octal, `\h`, `\Z`, Java's nested character-class unions and `&&` intersections (kept as written when
/// the class is plain). `None` for constructs Java rejects.
fn translate(java: &str) -> Option<String> {
    let chars: Vec<char> = java.chars().collect();
    let mut out = String::with_capacity(java.len() + 8);
    let mut i = 0;
    let mut class_depth = 0usize;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\\' => {
                let n = *chars.get(i + 1)?;
                match n {
                    'Q' => {
                        let mut j = i + 2;
                        let mut literal = String::new();
                        while j < chars.len() && !(chars[j] == '\\' && chars.get(j + 1) == Some(&'E')) {
                            literal.push(chars[j]);
                            j += 1;
                        }
                        for ch in literal.chars() {
                            push_literal(&mut out, ch, class_depth > 0);
                        }
                        i = if j < chars.len() { j + 2 } else { j };
                        continue;
                    }
                    'p' | 'P' => {
                        let (name, next) = if chars.get(i + 2) == Some(&'{') {
                            let end = (i + 3..chars.len()).find(|k| chars[*k] == '}')?;
                            (chars[i + 3..end].iter().collect::<String>(), end + 1)
                        } else {
                            (chars.get(i + 2)?.to_string(), i + 3)
                        };
                        let class = property_class(&name)?;
                        let negated = n == 'P';
                        if class_depth > 0 {
                            if negated {
                                out.push_str(&format!("[^{class}]"));
                            } else {
                                out.push_str(&class);
                            }
                        } else if negated {
                            out.push_str(&format!("[^{class}]"));
                        } else {
                            out.push_str(&format!("[{class}]"));
                        }
                        i = next;
                        continue;
                    }
                    'c' => {
                        let ch = *chars.get(i + 2)?;
                        out.push_str(&format!("\\x{{{:X}}}", (ch as u32) ^ 64));
                        i += 3;
                        continue;
                    }
                    'e' => out.push_str("\\x1B"),
                    'a' => out.push_str("\\x07"),
                    'Z' if class_depth == 0 => out.push_str("(?=\\n?\\z)"),
                    'h' => out.push_str(if class_depth > 0 { " \\t\\xA0\\x{1680}\\x{180e}\\x{2000}-\\x{200a}\\x{202f}\\x{205f}\\x{3000}" } else { "[ \\t\\xA0\\x{1680}\\x{180e}\\x{2000}-\\x{200a}\\x{202f}\\x{205f}\\x{3000}]" }),
                    'H' => out.push_str("[^ \\t\\xA0\\x{1680}\\x{180e}\\x{2000}-\\x{200a}\\x{202f}\\x{205f}\\x{3000}]"),
                    'R' if class_depth == 0 => out.push_str("(?:\\r\\n|[\\n\\x0B\\f\\r\\x{85}\\x{2028}\\x{2029}])"),
                    '0' => {
                        let mut j = i + 2;
                        let mut value = 0u32;
                        while j < chars.len() && j < i + 5 && chars[j].is_digit(8) && value * 8 + chars[j].to_digit(8)? <= 0o377 {
                            value = value * 8 + chars[j].to_digit(8)?;
                            j += 1;
                        }
                        if j == i + 2 {
                            return None;
                        }
                        out.push_str(&format!("\\x{{{value:X}}}"));
                        i = j;
                        continue;
                    }
                    'x' if chars.get(i + 2) == Some(&'{') => {
                        let end = (i + 3..chars.len()).find(|k| chars[*k] == '}')?;
                        out.extend(&chars[i..=end]);
                        i = end + 1;
                        continue;
                    }
                    'u' => {
                        let hex: String = chars.get(i + 2..i + 6)?.iter().collect();
                        let value = u32::from_str_radix(&hex, 16).ok()?;
                        out.push_str(&format!("\\x{{{value:X}}}"));
                        i += 6;
                        continue;
                    }
                    'k' => {
                        out.push_str("\\k");
                    }
                    // Java's `\d`, `\w`, `\s` and `\b` are ASCII-only.
                    'd' => out.push_str(if class_depth > 0 { "0-9" } else { "[0-9]" }),
                    'w' => out.push_str(if class_depth > 0 { "a-zA-Z_0-9" } else { "[a-zA-Z_0-9]" }),
                    's' => out.push_str(if class_depth > 0 { "\\t\\n\\x0B\\f\\r " } else { "[\\t\\n\\x0B\\f\\r ]" }),
                    'D' if class_depth == 0 => out.push_str("[^0-9]"),
                    'W' if class_depth == 0 => out.push_str("[^a-zA-Z_0-9]"),
                    'S' if class_depth == 0 => out.push_str("[^\\t\\n\\x0B\\f\\r ]"),
                    'b' if class_depth == 0 => out.push_str("(?:(?<=[a-zA-Z_0-9])(?![a-zA-Z_0-9])|(?<![a-zA-Z_0-9])(?=[a-zA-Z_0-9]))"),
                    'B' if class_depth == 0 => out.push_str("(?:(?<=[a-zA-Z_0-9])(?=[a-zA-Z_0-9])|(?<![a-zA-Z_0-9])(?![a-zA-Z_0-9]))"),
                    n if n.is_ascii_alphabetic() && !"dDsSwWbBAGzZtnrfxkvVhHR".contains(n) => return None,
                    _ => {
                        out.push('\\');
                        out.push(n);
                    }
                }
                i += 2;
            }
            '[' => {
                if class_depth > 0 {
                    // A nested class: Java takes the union.
                    out.push('[');
                } else {
                    out.push('[');
                    if chars.get(i + 1) == Some(&'^') {
                        out.push('^');
                        i += 1;
                    }
                    // A `]` right after the opening bracket is a literal in Java.
                    if chars.get(i + 1) == Some(&']') {
                        out.push_str("\\]");
                        i += 1;
                    }
                }
                class_depth += 1;
                i += 1;
            }
            ']' if class_depth > 0 => {
                class_depth -= 1;
                out.push(']');
                i += 1;
            }
            '{' if class_depth == 0 => {
                // A repetition must be well formed in Java (`Illegal repetition` otherwise).
                let end = (i + 1..chars.len()).find(|k| chars[*k] == '}')?;
                let body: String = chars[i + 1..end].iter().collect();
                let (lo, hi) = match body.split_once(',') {
                    Some((lo, hi)) => (lo, Some(hi)),
                    None => (body.as_str(), None),
                };
                if lo.is_empty() || !lo.chars().all(|c| c.is_ascii_digit()) || hi.is_some_and(|h| !h.chars().all(|c| c.is_ascii_digit())) {
                    return None;
                }
                if let Some(h) = hi.filter(|h| !h.is_empty())
                    && h.parse::<u64>().ok()? < lo.parse::<u64>().ok()?
                {
                    return None;
                }
                out.extend(&chars[i..=end]);
                i = end + 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    if class_depth > 0 {
        return None;
    }
    Some(out)
}

fn push_literal(out: &mut String, ch: char, in_class: bool) {
    if in_class {
        if "\\]^-[&".contains(ch) {
            out.push('\\');
        }
        out.push(ch);
    } else {
        out.push_str(&fancy_regex::escape(&ch.to_string()));
    }
}

/// The body of a character class for a Java `\p{name}`.
fn property_class(name: &str) -> Option<String> {
    let posix = match name {
        "Lower" | "IsLowercase" => Some("a-z"),
        "Upper" | "IsUppercase" => Some("A-Z"),
        "ASCII" => Some("\\x00-\\x7F"),
        "Alpha" => Some("a-zA-Z"),
        "Digit" => Some("0-9"),
        "Alnum" => Some("a-zA-Z0-9"),
        "Punct" => Some("!-/:-@\\[-`{-~"),
        "Graph" => Some("!-~"),
        "Print" => Some(" -~"),
        "Blank" => Some(" \\t"),
        "Cntrl" => Some("\\x00-\\x1F\\x7F"),
        "XDigit" => Some("0-9a-fA-F"),
        "Space" => Some(" \\t\\n\\x0B\\f\\r"),
        "javaLowerCase" => Some("\\p{Ll}"),
        "javaUpperCase" => Some("\\p{Lu}"),
        "javaWhitespace" => Some("\\t-\\r\\x1C-\\x1F\\p{Zs}\\p{Zl}\\p{Zp}"),
        "javaMirrored" => None,
        _ => None,
    };
    if let Some(p) = posix {
        return Some(p.to_string());
    }
    let short = name.strip_prefix("Is").or_else(|| name.strip_prefix("In")).unwrap_or(name);
    let candidate = format!("\\p{{{short}}}");
    fancy_regex::Regex::new(&candidate).ok().map(|_| candidate)
}

/// `Strings.containsNonAsciiWhitespace`.
fn contains_non_ascii_whitespace(s: &str) -> bool {
    s.chars().any(|c| (c as u32) > 127 && (java_whitespace(c) || java_space_char(c)))
}

/// `Character.isWhitespace` for a non-ASCII character.
fn java_whitespace(c: char) -> bool {
    matches!(c as u32, 0x1680 | 0x2000..=0x2006 | 0x2008..=0x200A | 0x2028 | 0x2029 | 0x205F | 0x3000) || matches!(c, '\u{1C}'..='\u{1F}')
}

/// `Character.isSpaceChar`: Zs, Zl, Zp.
fn java_space_char(c: char) -> bool {
    matches!(c as u32, 0x20 | 0xA0 | 0x1680 | 0x2000..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000)
}

/// `IPv6Format`.
fn ipv6(value: &str) -> bool {
    value.trim() == value && !value.contains('%') && full_match(IPV6, value)
}

/// `DurationFormat` with the default (strict) validation.
fn duration(value: &str) -> bool {
    !value.ends_with('P')
        && !value.ends_with('T')
        && full_match_ignore_case(r"^(?:P\d+W)|(?:P(?:\d+Y)?(?:\d+M)?(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?)$", value)
}

/// `AbstractRFC3986Format.matches`: `new URI(value)` then the format's check, or — when the URI does not parse — the
/// `VALID` pattern over the input.
fn rfc3986(value: &str, check: fn(&str, &crate::java_uri::JavaUri) -> bool) -> bool {
    match crate::java_uri::parse(value) {
        Ok(uri) => check(value, &uri),
        Err(_) => full_match(r"([A-Za-z0-9+,\-.]*:)?//|[A-Za-z0-9+,\-.]+:", value),
    }
}

fn query_has_brackets(uri: &crate::java_uri::JavaUri) -> bool {
    uri.raw_query.as_deref().is_some_and(|q| q.contains(['[', ']']))
}

fn authority_is_ipv6(uri: &crate::java_uri::JavaUri) -> bool {
    uri.raw_authority.as_deref().is_some_and(|a| full_match(IPV6, a))
}

fn uri(value: &str, uri: &crate::java_uri::JavaUri) -> bool {
    uri.scheme.is_some() && value.chars().all(|c| (c as u32) < 127) && !query_has_brackets(uri)
}

fn uri_reference(value: &str, uri: &crate::java_uri::JavaUri) -> bool {
    value.chars().all(|c| (c as u32) < 127) && !query_has_brackets(uri)
}

fn iri(_: &str, uri: &crate::java_uri::JavaUri) -> bool {
    uri.scheme.is_some() && !authority_is_ipv6(uri) && !query_has_brackets(uri)
}

fn iri_reference(_: &str, uri: &crate::java_uri::JavaUri) -> bool {
    !authority_is_ipv6(uri) && !query_has_brackets(uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_regex_compiles_like_pattern_compile() {
        for ok in ["^a$", "(?<n>x)", "\\p{L}", "\\Qa", "(?i)x", "\\z", "[[:alpha:]]", "\\cA", "a++", "(?=x)", "\\p{XDigit}{8}"] {
            assert!(java_regex_compiles(ok), "{ok}");
        }
        for bad in ["[a-", "a{2,1}", "\\k<n>"] {
            assert!(!java_regex_compiles(bad), "{bad}");
        }
    }

    #[test]
    fn dollar_anchors_become_end_of_input() {
        assert_eq!(replace_dollar_anchors("^a$|[$]\\$\\Q$\\E"), "^a\\z|[$]\\$\\Q$\\E");
    }
}

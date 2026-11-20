//! networknt's `RFC5892` (the `idn-hostname` format) with its bundled IDNA2008 derived-property and joining-type
//! tables, and the `java.net.IDN` conversions it and commons-validator's `DomainValidator` call.

use std::sync::LazyLock;

use icu_properties::CodePointMapData;
use icu_properties::props::{BidiClass, GeneralCategory};

#[derive(Clone, Copy, PartialEq)]
enum Derived {
    ContextJ,
    ContextO,
    Disallowed,
    Unassigned,
}

#[derive(Clone, Copy, PartialEq)]
enum Joining {
    Causing,
    Dual,
    Left,
    Right,
    Transparent,
}

/// `UCDLoader.loadMapping`: `start[..end] ; VALUE # comment` lines as sorted ranges.
fn load<T: Copy>(text: &str, select: impl Fn(&str) -> Option<T>) -> Vec<(u32, u32, T)> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, [';', '#']);
        let (Some(range), Some(value)) = (parts.next(), parts.next()) else { continue };
        let Some(v) = select(value.trim()) else { continue };
        let range = range.trim();
        let (lo, hi) = match range.split_once("..") {
            Some((a, b)) => (u32::from_str_radix(a, 16), u32::from_str_radix(b, 16)),
            None => (u32::from_str_radix(range, 16), u32::from_str_radix(range, 16)),
        };
        if let (Ok(lo), Ok(hi)) = (lo, hi) {
            out.push((lo, hi, v));
        }
    }
    out.sort_by_key(|r| r.0);
    out
}

fn lookup<T: Copy>(table: &[(u32, u32, T)], c: u32) -> Option<T> {
    let i = table.partition_point(|r| r.0 <= c);
    (i > 0 && table[i - 1].1 >= c).then(|| table[i - 1].2)
}

static DERIVED: LazyLock<Vec<(u32, u32, Derived)>> = LazyLock::new(|| {
    load(include_str!("ucd/RFC5892-appendix-B.txt"), |v| match v {
        "CONTEXTJ" => Some(Derived::ContextJ),
        "CONTEXTO" => Some(Derived::ContextO),
        "DISALLOWED" => Some(Derived::Disallowed),
        "UNASSIGNED" => Some(Derived::Unassigned),
        _ => None,
    })
});

static JOINING: LazyLock<Vec<(u32, u32, Joining)>> = LazyLock::new(|| {
    load(include_str!("ucd/DerivedJoiningType.txt"), |v| match v {
        "C" => Some(Joining::Causing),
        "D" => Some(Joining::Dual),
        "L" => Some(Joining::Left),
        "R" => Some(Joining::Right),
        "T" => Some(Joining::Transparent),
        _ => None,
    })
});

/// The code points `loadDerivedProperties` clears from CONTEXTJ/CONTEXTO (their rules are checked separately).
fn cleared(c: u32) -> bool {
    matches!(c, 0x200C | 0x200D | 0x660..=0x669 | 0x6F0..=0x6F9 | 885 | 1523 | 1524 | 12539 | 183)
}

fn allowed_character(c: u32) -> bool {
    match lookup(&DERIVED, c) {
        None => true,
        Some(Derived::ContextJ | Derived::ContextO) => cleared(c),
        Some(_) => false,
    }
}

fn joining(c: u32) -> Option<Joining> {
    lookup(&JOINING, c)
}

/// `Character.getDirectionality` as Java's codes (0 L, 1 R, 2 AL, 3 EN, 4 ES, 5 ET, 6 AN, 7 CS, 8 NSM, 9 BN, 10 B,
/// 11 S, 12 WS, 13 ON; the embedding and isolate classes above).
fn directionality(c: u32) -> u8 {
    let Some(ch) = char::from_u32(c) else { return 255 };
    let class = CodePointMapData::<BidiClass>::new().get(ch);
    let table = [
        (BidiClass::LeftToRight, 0),
        (BidiClass::RightToLeft, 1),
        (BidiClass::ArabicLetter, 2),
        (BidiClass::EuropeanNumber, 3),
        (BidiClass::EuropeanSeparator, 4),
        (BidiClass::EuropeanTerminator, 5),
        (BidiClass::ArabicNumber, 6),
        (BidiClass::CommonSeparator, 7),
        (BidiClass::NonspacingMark, 8),
        (BidiClass::BoundaryNeutral, 9),
        (BidiClass::ParagraphSeparator, 10),
        (BidiClass::SegmentSeparator, 11),
        (BidiClass::WhiteSpace, 12),
        (BidiClass::OtherNeutral, 13),
    ];
    table.iter().find(|(b, _)| *b == class).map_or(14, |(_, code)| *code)
}

fn combining_mark(c: u32) -> bool {
    char::from_u32(c).is_some_and(|ch| {
        matches!(
            CodePointMapData::<GeneralCategory>::new().get(ch),
            GeneralCategory::NonspacingMark | GeneralCategory::EnclosingMark | GeneralCategory::SpacingMark
        )
    })
}

fn greek(c: u32) -> bool {
    (880..1024).contains(&c) || (7936..8192).contains(&c)
}

fn hebrew(c: u32) -> bool {
    (1424..1536).contains(&c)
}

fn katakana(c: u32) -> bool {
    [
        (11904, 12032), (12032, 12256), (12288, 12352), (12352, 12448), (12448, 12544), (13312, 19904), (19968, 40960), (63744, 64256),
        (94176, 94208), (131072, 173792), (173824, 177984), (177984, 178208), (178208, 183984), (183984, 191472), (194560, 195104),
        (196608, 201552), (201552, 205744),
    ]
    .iter()
    .any(|(lo, hi)| (*lo..*hi).contains(&c))
}

fn arabic_indic(c: u32) -> bool {
    (0x660..0x66A).contains(&c)
}

fn extended_arabic_indic(c: u32) -> bool {
    (0x6F0..0x6FA).contains(&c)
}

const SEPARATORS: [char; 4] = ['.', '\u{3002}', '\u{FF0E}', '\u{FF61}'];

/// `RFC5892.isValid`.
pub fn is_valid(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut chars = value.chars();
    if let (Some(c), None) = (chars.next(), chars.next())
        && SEPARATORS.contains(&c)
    {
        return false;
    }
    for label in value.split(SEPARATORS) {
        if label.is_empty() {
            continue;
        }
        let mut unicode = label.to_string();
        if label.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("xn--")) {
            unicode = to_unicode_label(label);
            if unicode.eq_ignore_ascii_case(label) {
                return false;
            }
        }
        if !icu_normalizer::ComposingNormalizerBorrowed::new_nfc().is_normalized(&unicode) {
            return false;
        }
        let cps: Vec<u32> = unicode.chars().map(u32::from).collect();
        if cps.first() == Some(&0x2D) || cps.last() == Some(&0x2D) {
            return false;
        }
        // `codePointAt(2/3)` on UTF-16 indexes; only ASCII hyphens matter here.
        let units: Vec<u16> = unicode.encode_utf16().collect();
        if units.len() >= 4 && units[2] == 0x2D && units[3] == 0x2D {
            return false;
        }
        if combining_mark(cps[0]) {
            return false;
        }
        let direction_rule: Option<fn(u32) -> bool> = match directionality(cps[0]) {
            0 => Some(|c| matches!(directionality(c), 0 | 3 | 4 | 5 | 7 | 8 | 9 | 13)),
            1 | 2 => Some(|c| matches!(directionality(c), 1..=9 | 13)),
            3 | 13 => None,
            _ => return false,
        };
        for i in 0..cps.len() {
            if !idna_rules(&cps, i) || direction_rule.is_some_and(|rule| !rule(cps[i])) {
                return false;
            }
        }
        match to_ascii_label(&unicode, true) {
            Ok(ace) if ace.chars().count() > 63 => return false,
            Ok(_) => {}
            Err(bidi) => {
                if !bidi {
                    return false;
                }
                return true;
            }
        }
    }
    true
}

/// `IDNA_RULES` at index `i`.
fn idna_rules(s: &[u32], i: usize) -> bool {
    let c = s[i];
    if !allowed_character(c) {
        return false;
    }
    if arabic_indic(c) && s.iter().any(|x| extended_arabic_indic(*x)) {
        return false;
    }
    if extended_arabic_indic(c) && s.iter().any(|x| arabic_indic(*x)) {
        return false;
    }
    if c == 885 && !s.get(i + 1).is_some_and(|f| greek(*f)) {
        return false;
    }
    if (c == 1523 || c == 1524) && !(i > 0 && hebrew(s[i - 1])) {
        return false;
    }
    if c == 12539 && !s.get(i + 1).is_some_and(|f| katakana(*f)) {
        return false;
    }
    if c == 183 && !(i > 0 && s[i - 1] == 108 && s.get(i + 1) == Some(&108)) {
        return false;
    }
    if c == 0x200D && !(i > 0 && s[i - 1] == 2381) {
        return false;
    }
    if c == 0x200C {
        if i == 0 {
            return false;
        }
        if s[i - 1] != 2381 {
            let mut j = i;
            while j > 0 && joining(s[j - 1]) == Some(Joining::Transparent) {
                j -= 1;
            }
            if j == 0 || !matches!(joining(s[j - 1]), Some(Joining::Left | Joining::Dual)) {
                return false;
            }
            let mut k = i + 1;
            if k == s.len() {
                return false;
            }
            while k < s.len() && joining(s[k]) == Some(Joining::Transparent) {
                k += 1;
            }
            if k == s.len() || !matches!(joining(s[k]), Some(Joining::Right | Joining::Dual)) {
                return false;
            }
        }
    }
    true
}

/// `IDN.toUnicode(label, USE_STD3_ASCII_RULES)` for an ACE label: the decoded label, or the label itself when it does
/// not decode or does not round-trip.
fn to_unicode_label(label: &str) -> String {
    let Some(decoded) = idna::punycode::decode_to_string(&label[4..]) else { return label.to_string() };
    match to_ascii_label(&decoded, true) {
        Ok(ace) if ace.eq_ignore_ascii_case(label) => decoded,
        _ => label.to_string(),
    }
}

/// `IDN.toASCII` of one label: ASCII labels as they are (checked against the STD3 rules when `std3`), others
/// case-folded and Punycode-encoded. `Err(true)` is a failure of the bidi rules, `Err(false)` any other.
fn to_ascii_label(label: &str, std3: bool) -> Result<String, bool> {
    let ascii = label.is_ascii();
    let prepared = if ascii { label.to_string() } else { label.to_lowercase() };
    if prepared.is_empty() {
        return Err(false);
    }
    if !ascii {
        let has_r = prepared.chars().any(|c| matches!(directionality(u32::from(c)), 1 | 2));
        let has_l = prepared.chars().any(|c| directionality(u32::from(c)) == 0);
        let first = prepared.chars().next().map(|c| directionality(u32::from(c)));
        let last = prepared.chars().last().map(|c| directionality(u32::from(c)));
        if has_r && (has_l || !matches!(first, Some(1 | 2)) || !matches!(last, Some(1 | 2))) {
            return Err(true);
        }
    }
    if std3 && (prepared.chars().any(|c| c.is_ascii() && !(c.is_ascii_alphanumeric() || c == '-')) || prepared.starts_with('-') || prepared.ends_with('-')) {
        return Err(false);
    }
    let out = if prepared.is_ascii() {
        prepared
    } else {
        if prepared.to_ascii_lowercase().starts_with("xn--") {
            return Err(false);
        }
        format!("xn--{}", idna::punycode::encode_str(&prepared).ok_or(false)?)
    };
    if out.chars().count() > 63 {
        return Err(false);
    }
    Ok(out)
}

/// `IDN.toASCII(input)` (no flags) over a dotted name, keeping a trailing dot; `None` when it throws.
pub fn to_ascii(input: &str, std3: bool) -> Option<String> {
    let mut out = Vec::new();
    let labels: Vec<&str> = input.split(SEPARATORS).collect();
    let count = labels.len();
    for (i, label) in labels.iter().enumerate() {
        if label.is_empty() {
            if i + 1 == count && i > 0 {
                out.push(String::new());
                continue;
            }
            return None;
        }
        out.push(to_ascii_label(label, std3).ok()?);
    }
    Some(out.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internationalized_hostnames() {
        for ok in ["example.com", "xn--nxasmq6b.com", "ελληνικά.gr"] {
            assert!(is_valid(ok), "{ok}");
        }
        for bad in ["ex ample", "-bad", "a\u{b7}b", "\u{640}\u{7fa}", "a\u{200c}b", "exa\u{2028}mple"] {
            assert!(!is_valid(bad), "{bad}");
        }
    }
}

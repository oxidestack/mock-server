//! XMLUnit's `IsDateTimePlaceholderHandler` (xmlunit-placeholders 2.14) and the part of `java.text.SimpleDateFormat`
//! it reaches: whether a lenient `parse(String)` accepts a text, as the oracle's trimmed JRE (no `jdk.localedata`,
//! default locale `en`, time zone GMT) answers it. A parse succeeds on a prefix of the text, numeric fields take any
//! integer (lenient calendar), and text fields match the calendar's display names, longest first, ignoring case.
//! A locale tag's `-u-ca-*` (and th-TH, ja-JP-x-lvariant-JP) picks the Buddhist or Japanese calendar, and its
//! `-u-nu-*` the numbering system whose minus sign, decimal separator, exponent and NaN the integer parser reads.

#[path = "simple_date_format_data.rs"]
mod data;

/// One locale-data class: the oracle's JRE has data for `en` only; another language falls back to the root locale,
/// and a locale with no language but an extension to the JRE's fallback provider.
pub(super) struct Symbols {
    /// Per calendar, in `Calendar` order (`GREGORY`, `BUDDHIST`, `JAPANESE`).
    calendars: [Names; 3],
    zones: &'static [&'static str],
    numbers: Numbers,
    /// The numbering systems (`-u-nu-<type>`) whose symbols differ from `numbers`.
    numbering: &'static [(&'static str, Numbers)],
}

/// The display names a calendar's text fields match.
pub(super) struct Names {
    eras: &'static [&'static str],
    am_pm: &'static [&'static str],
    months_format: &'static [&'static str],
    months_standalone: &'static [&'static str],
    months_all: &'static [&'static str],
    weekdays_long: &'static [&'static str],
    weekdays_short: &'static [&'static str],
}

/// What `NumberFormat.getIntegerInstance(locale)` parses with: its `DecimalFormatSymbols` (the positive affixes and the
/// negative suffix are empty, the negative prefix is the minus sign text).
pub(super) struct Numbers {
    zero: u16,
    minus: &'static str,
    decimal: u16,
    exponent: &'static str,
    infinity: &'static str,
    nan: &'static str,
}

const GREGORY: usize = 0;
const BUDDHIST: usize = 1;
const JAPANESE: usize = 2;

/// What `new SimpleDateFormat(pattern, Locale.forLanguageTag(tag))` parses with.
#[derive(Clone, Copy)]
struct Locale {
    symbols: &'static Symbols,
    calendar: usize,
    numbers: &'static Numbers,
}

impl Locale {
    const DEFAULT: Locale = Locale { symbols: &data::EN, calendar: GREGORY, numbers: &data::EN.numbers };

    fn names(&self) -> &'static Names {
        &self.symbols.calendars[self.calendar]
    }
}

const ISO_PATTERNS: [&str; 13] = [
    "yyyy-MM-dd",
    "yyyy-MM-dd'T'HH:mm:ss",
    "yyyy-MM-dd'T'HH:mm:ss.SSS",
    "yyyy-MM-dd'T'HH:mm:ssZ",
    "yyyy-MM-dd'T'HH:mm:ss.SSSZ",
    "yyyy-MM-dd'T'HH:mm:ssXXX",
    "yyyy-MM-dd'T'HH:mm:ss.SSSXXX",
    "yyyy-MM-dd HH:mm:ss",
    "yyyy-MM-dd HH:mm:ss.SSS",
    "yyyy-MM-dd HH:mm:ssZ",
    "yyyy-MM-dd HH:mm:ss.SSSZ",
    "yyyy-MM-dd HH:mm:ssXXX",
    "yyyy-MM-dd HH:mm:ss.SSSXXX",
];

/// `IsDateTimePlaceholderHandler.evaluate`: `Ok(accepted)`, or `Err(())` when it throws (an invalid pattern, or a
/// pattern argument against a missing value).
pub(super) fn is_date_time(test: Option<&str>, args: &[String]) -> Result<bool, ()> {
    if let Some(pattern) = args.first() {
        let locale = match args.get(1).filter(|tag| !tag.is_empty()) {
            Some(tag) => locale(tag),
            None => Locale::DEFAULT,
        };
        let format = Format::compile(pattern, locale)?;
        return Ok(format.parses(test.ok_or(())?));
    }
    let Some(text) = test.filter(|t| !t.is_empty()) else { return Ok(false) };
    let defaults = [data::SHORT_DATE, data::SHORT_DATE_TIME].into_iter().chain(ISO_PATTERNS);
    Ok(defaults.into_iter().any(|pattern| Format::compile(pattern, Locale::DEFAULT).is_ok_and(|f| f.parses(text))))
}

/// What `Locale.forLanguageTag(tag)` gives `SimpleDateFormat` on the oracle's JRE: the locale-data class, the
/// calendar `Calendar.getInstance` makes and the numbering system's symbols.
fn locale(tag: &str) -> Locale {
    let with = |symbols: &'static Symbols| Locale { symbols, calendar: GREGORY, numbers: &symbols.numbers };
    // `LanguageTag.LEGACY`: the whole tag is replaced first.
    match tag.to_ascii_lowercase().as_str() {
        "i-default" | "en-gb-oed" => return with(&data::EN),
        "i-enochian" | "i-mingo" => return with(&data::FALLBACK),
        "art-lojban" | "cel-gaulish" | "i-ami" | "i-bnn" | "i-hak" | "i-klingon" | "i-lux" | "i-navajo" | "i-pwn"
        | "i-tao" | "i-tay" | "i-tsu" | "no-bok" | "no-nyn" | "sgn-be-fr" | "sgn-be-nl" | "sgn-ch-de" | "zh-guoyu"
        | "zh-hakka" | "zh-min" | "zh-min-nan" | "zh-xiang" => return with(&data::ROOT),
        _ => {}
    }
    let alpha = |s: &str| s.bytes().all(|b| b.is_ascii_alphabetic());
    let alnum = |s: &str| s.bytes().all(|b| b.is_ascii_alphanumeric());
    let tokens: Vec<&str> = tag.split('-').collect();
    let mut i = 0;
    let (mut language, mut region) = (String::new(), String::new());
    let mut variants = false;
    let mut extended = false;
    // The `u` extension's `ca` and `nu` types; the first of a repeated key wins.
    let (mut ca, mut nu): (Option<String>, Option<String>) = (None, None);
    // `LanguageTag.parse`: a language, then extlangs, script, region, variants and extensions; private use either way.
    if (2..=8).contains(&tokens[0].len()) && alpha(tokens[0]) {
        language = tokens[0].to_ascii_lowercase();
        i = 1;
        let mut extlangs = 0;
        while extlangs < 3 && tokens.get(i).is_some_and(|t| t.len() == 3 && alpha(t)) {
            extlangs += 1;
            i += 1;
        }
        if tokens.get(i).is_some_and(|t| t.len() == 4 && alpha(t)) {
            i += 1;
        }
        if tokens.get(i).is_some_and(|t| (t.len() == 2 && alpha(t)) || (t.len() == 3 && t.bytes().all(|b| b.is_ascii_digit()))) {
            region = tokens[i].to_ascii_uppercase();
            i += 1;
        }
        while tokens.get(i).is_some_and(|t| {
            alnum(t) && ((5..=8).contains(&t.len()) || (t.len() == 4 && t.as_bytes()[0].is_ascii_digit()))
        }) {
            variants = true;
            i += 1;
        }
        let mut singletons = Vec::new();
        while tokens.get(i).is_some_and(|t| t.len() == 1 && alnum(t) && !t.eq_ignore_ascii_case("x")) {
            let singleton = tokens[i].to_ascii_lowercase();
            let subtags = tokens[i + 1..].iter().take_while(|t| (2..=8).contains(&t.len()) && alnum(t)).count();
            // A repeated singleton ends the tag there.
            if subtags == 0 || singletons.contains(&singleton) {
                break;
            }
            if singleton == "u" {
                unicode_keywords(&tokens[i + 1..i + 1 + subtags], &mut ca, &mut nu);
            }
            singletons.push(singleton);
            extended = true;
            i += 1 + subtags;
        }
    }
    // `x-lvariant-<v>` is the legacy variant `v` (case kept); with nothing else in the private use and no
    // extension, `ja_JP_JP` and `th_TH_TH` get their compatibility extensions (`ca-japanese`, `nu-thai`).
    let mut variant = None;
    if tokens.get(i).is_some_and(|t| t.eq_ignore_ascii_case("x"))
        && tokens.get(i + 1).is_some_and(|t| (1..=8).contains(&t.len()) && alnum(t))
    {
        let private = &tokens[i + 1..];
        if let Some(at) = private.iter().position(|t| t.eq_ignore_ascii_case("lvariant")) && !variants && private.len() == at + 2 {
            variant = Some((private[at + 1], at == 0 && !extended));
        }
        extended = true;
    }
    match (language.as_str(), region.as_str(), variant) {
        ("ja", "JP", Some(("JP", true))) => ca = Some("japanese".into()),
        ("th", "TH", Some(("TH", true))) => nu = Some("thai".into()),
        _ => {}
    }
    let symbols = match language.as_str() {
        "en" => &data::EN,
        "" | "und" if extended => &data::FALLBACK,
        _ => &data::ROOT,
    };
    // `Calendar.createCalendar`: the `ca` type `Calendar.Builder` knows, else (none) Buddhist for th-TH; an unknown
    // type makes the builder throw, and the traditional choice also takes `ja_JP_JP` as Japanese.
    let th_th = language == "th" && region == "TH";
    let calendar = match ca.as_deref() {
        Some("buddhist") => BUDDHIST,
        Some("japanese") => JAPANESE,
        Some("gregory" | "iso8601") => GREGORY,
        _ if th_th => BUDDHIST,
        Some(_) if language == "ja" && region == "JP" && variant.is_some_and(|(v, _)| v == "JP") => JAPANESE,
        _ => GREGORY,
    };
    let numbers = nu
        .and_then(|nu| symbols.numbering.iter().find(|(name, _)| *name == nu))
        .map_or(&symbols.numbers, |(_, numbers)| numbers);
    Locale { symbols, calendar, numbers }
}

/// `UnicodeLocaleExtension`: attributes, then keys of two characters, each with a type of the subtags after it.
fn unicode_keywords(subtags: &[&str], ca: &mut Option<String>, nu: &mut Option<String>) {
    let mut k = subtags.iter().take_while(|s| s.len() != 2).count();
    while k < subtags.len() {
        let key = subtags[k].to_ascii_lowercase();
        let ty = subtags[k + 1..].iter().take_while(|s| s.len() != 2).map(|s| s.to_ascii_lowercase()).collect::<Vec<_>>();
        k += 1 + ty.len();
        let slot = match key.as_str() {
            "ca" => &mut *ca,
            "nu" => &mut *nu,
            _ => continue,
        };
        if slot.is_none() {
            *slot = Some(ty.join("-"));
        }
    }
}

/// `DateFormatSymbols.patternChars`, in `SimpleDateFormat`'s tag order.
const PATTERN_CHARS: &str = "GyMdkHmsSEDFwWahKzZYuXL";
const ERA: u8 = 0;
const YEAR: u8 = 1;
const MONTH: u8 = 2;
const HOUR_OF_DAY1: u8 = 4;
const DAY_OF_WEEK: u8 = 9;
const AM_PM: u8 = 14;
const HOUR1: u8 = 15;
const ZONE_NAME: u8 = 17;
const ZONE_VALUE: u8 = 18;
const WEEK_YEAR: u8 = 19;
const ISO_ZONE: u8 = 21;
const MONTH_STANDALONE: u8 = 22;

enum Item {
    Literal(Vec<u16>),
    Field { tag: u8, count: usize },
}

struct Format {
    items: Vec<Item>,
    /// `forceStandaloneForm`: the pattern is a single month field.
    standalone: bool,
    locale: Locale,
}

impl Format {
    /// `SimpleDateFormat.compile`; `Err` where it throws `IllegalArgumentException`.
    fn compile(pattern: &str, locale: Locale) -> Result<Format, ()> {
        let p: Vec<u16> = pattern.encode_utf16().collect();
        let mut items = Vec::new();
        let mut quoted: Option<Vec<u16>> = None;
        let mut field: Option<(u8, usize)> = None;
        let (mut fields, mut last_field) = (0, None);
        let mut flush = |field: &mut Option<(u8, usize)>, items: &mut Vec<Item>| {
            if let Some((tag, count)) = field.take() {
                items.push(Item::Field { tag, count });
                fields += 1;
                last_field = Some(tag);
            }
        };
        let letter = |c: u16| c < 128 && (c as u8).is_ascii_alphabetic();
        let mut i = 0;
        while i < p.len() {
            let c = p[i];
            if c == u16::from(b'\'') {
                if p.get(i + 1) == Some(&c) {
                    i += 2;
                    flush(&mut field, &mut items);
                    match quoted.as_mut() {
                        Some(q) => q.push(c),
                        None => items.push(Item::Literal(vec![c])),
                    }
                    continue;
                }
                match quoted.take() {
                    Some(q) => items.push(Item::Literal(q)),
                    None => {
                        flush(&mut field, &mut items);
                        quoted = Some(Vec::new());
                    }
                }
                i += 1;
                continue;
            }
            if let Some(q) = quoted.as_mut() {
                q.push(c);
                i += 1;
                continue;
            }
            if !letter(c) {
                flush(&mut field, &mut items);
                items.push(Item::Literal(vec![c]));
                i += 1;
                continue;
            }
            let tag = PATTERN_CHARS.bytes().position(|b| u16::from(b) == c).ok_or(())? as u8;
            match field.as_mut() {
                Some((last, count)) if *last == tag => *count += 1,
                _ => {
                    flush(&mut field, &mut items);
                    field = Some((tag, 1));
                }
            }
            i += 1;
        }
        if quoted.is_some() {
            return Err(());
        }
        flush(&mut field, &mut items);
        // `encode`: "invalid ISO 8601 format".
        if items.iter().any(|item| matches!(item, &Item::Field { tag: ISO_ZONE, count } if count >= 4)) {
            return Err(());
        }
        let standalone = fields == 1 && last_field == Some(MONTH);
        Ok(Format { items, standalone, locale })
    }

    /// `DateFormat.parse(String)` succeeds: the pattern matched a prefix of `text`, and a non-empty one.
    fn parses(&self, text: &str) -> bool {
        let text: Vec<u16> = text.encode_utf16().collect();
        let mut start = 0;
        for (i, item) in self.items.iter().enumerate() {
            match item {
                Item::Literal(chars) => {
                    for &c in chars {
                        if start >= text.len() || !char_equals(text[start], c) {
                            return false;
                        }
                        start += 1;
                    }
                }
                &Item::Field { tag, count } => {
                    let obey_count = matches!(self.items.get(i + 1), Some(&Item::Field { tag, count }) if obeys_count(tag, count));
                    match self.sub_parse(&text, start, tag, count, obey_count) {
                        Some(next) => start = next,
                        None => return false,
                    }
                }
            }
        }
        start > 0
    }

    /// `SimpleDateFormat.subParse`: where the field ends, or `None` when it does not parse.
    fn sub_parse(&self, text: &[u16], start: usize, tag: u8, count: usize, obey_count: bool) -> Option<usize> {
        let mut pos = start;
        while pos < text.len() && (text[pos] == u16::from(b' ') || text[pos] == u16::from(b'\t')) {
            pos += 1;
        }
        if pos >= text.len() {
            return None;
        }
        let numbers = self.locale.numbers;
        let end = if obey_count { start.checked_add(count).filter(|&end| end <= text.len()) } else { Some(text.len()) };
        let number = |pos: usize| parse_integer(&text[..end?], pos, numbers);
        let gregorian = self.locale.calendar != JAPANESE;
        // The Japanese calendar has no week dates: `Y` is `y`.
        let tag = if tag == WEEK_YEAR && !gregorian { YEAR } else { tag };
        let numeric_first = matches!(tag, HOUR_OF_DAY1 | HOUR1 | YEAR | WEEK_YEAR)
            || (matches!(tag, MONTH | MONTH_STANDALONE) && count <= 2);
        if numeric_first {
            end?;
            match number(pos) {
                Some(next) => pos = next,
                // A year a non-Gregorian calendar could name in text (it has no year names here) consumes nothing.
                None if tag == YEAR && !gregorian => {}
                None => return None,
            }
        }
        let s = self.locale.names();
        match tag {
            ERA => match_longest(text, start, s.eras),
            YEAR | WEEK_YEAR | HOUR_OF_DAY1 | HOUR1 => Some(pos),
            MONTH | MONTH_STANDALONE if count <= 2 => Some(pos),
            MONTH => match_longest(text, start, if self.standalone { s.months_standalone } else { s.months_format }),
            MONTH_STANDALONE => match_longest(text, start, s.months_all),
            DAY_OF_WEEK => match_longest(text, start, s.weekdays_long).or_else(|| match_longest(text, start, s.weekdays_short)),
            AM_PM => match_longest(text, start, s.am_pm),
            ZONE_NAME | ZONE_VALUE => self.zone(text, start, pos),
            ISO_ZONE => match text[pos] {
                c if c == u16::from(b'Z') => Some(pos + 1),
                c if c == u16::from(b'+') || c == u16::from(b'-') => numeric_zone(text, pos + 1, count, count == 3),
                _ => None,
            },
            _ => number(pos),
        }
    }

    /// The `z`/`Z` field: an RFC 822 offset, `GMT` with an optional `hh:mm` offset, or a zone name.
    fn zone(&self, text: &[u16], start: usize, pos: usize) -> Option<usize> {
        let sign = |c: u16| c == u16::from(b'+') || c == u16::from(b'-');
        let c = text[pos];
        if sign(c) {
            return numeric_zone(text, pos + 1, 0, false);
        }
        let gmt: Vec<u16> = "GMT".encode_utf16().collect();
        if (c == u16::from(b'G') || c == u16::from(b'g')) && region_matches_ignore_case(text, start, &gmt) {
            let after = start + gmt.len();
            return match text.get(after) {
                Some(&c) if sign(c) => numeric_zone(text, after + 1, 0, true),
                _ => Some(after),
            };
        }
        // `subParseZoneString`: the first name (the default zone's first) the text starts with.
        self.locale.symbols.zones.iter().find_map(|name| {
            let name: Vec<u16> = name.encode_utf16().collect();
            region_matches_ignore_case(text, pos, &name).then(|| pos + name.len())
        })
    }
}

/// `shouldObeyCount`: the next field is numeric, so this one takes only its pattern's width of digits.
fn obeys_count(tag: u8, count: usize) -> bool {
    match tag {
        MONTH | MONTH_STANDALONE => count <= 2,
        ERA | DAY_OF_WEEK | AM_PM | ZONE_NAME | ZONE_VALUE | ISO_ZONE => false,
        _ => true,
    }
}

/// `subParseNumericZone`: `hh[[:]mm]` after the sign (`count` is the number of `X`s, 0 for `Z` and `GMT`).
fn numeric_zone(text: &[u16], start: usize, count: usize, colon: bool) -> Option<usize> {
    let digit = |i: usize| text.get(i).filter(|c| (u16::from(b'0')..=u16::from(b'9')).contains(c)).map(|&c| c - u16::from(b'0'));
    let mut index = start;
    let mut hours = digit(index)?;
    index += 1;
    match digit(index) {
        Some(d) => {
            hours = hours * 10 + d;
            index += 1;
        }
        // Two digits are required unless `GMT+h:mm`; the next character must exist all the same.
        None if count > 0 || !colon || index >= text.len() => return None,
        None => {}
    }
    if hours > 23 {
        return None;
    }
    if count != 1 {
        if colon {
            if text.get(index) != Some(&u16::from(b':')) {
                return None;
            }
            index += 1;
        }
        let minutes = digit(index)? * 10 + digit(index + 1)?;
        if minutes > 59 {
            return None;
        }
        index += 2;
    }
    Some(index)
}

/// `DecimalFormat.parse` as `NumberFormat.getIntegerInstance` configures it (no grouping, integer only): where the
/// number ends, or `None`. NaN, infinity, the locale's or any other Unicode decimal digits and an exponent are
/// numbers too; a negative number starts with the minus sign text.
fn parse_integer(text: &[u16], pos: usize, numbers: &Numbers) -> Option<usize> {
    let at = |i: usize, s: &str| s.encode_utf16().enumerate().all(|(k, c)| text.get(i + k) == Some(&c));
    let len = |s: &str| s.encode_utf16().count();
    // `ch - zero`, else `Character.digit(ch, 10)`.
    let digit = |c: u16| c.checked_sub(numbers.zero).is_some_and(|d| d <= 9) || java_digit(c).is_some();
    if at(pos, numbers.nan) {
        return Some(pos + len(numbers.nan));
    }
    // The positive prefix is empty; the minus sign text (never empty) is the negative one.
    let start = if at(pos, numbers.minus) { pos + len(numbers.minus) } else { pos };
    if at(start, numbers.infinity) {
        return Some(start + len(numbers.infinity));
    }
    let mut position = start;
    let (mut saw_digit, mut decimal_at) = (false, None);
    while position < text.len() {
        let c = text[position];
        if digit(c) {
            saw_digit = true;
        } else if c == numbers.decimal {
            if position == start {
                return None;
            }
            if decimal_at.is_some() {
                break;
            }
            decimal_at = Some(position);
        } else if at(position, numbers.exponent) {
            // The exponent: an optional minus sign text and digits; without digits it is not part of the number.
            let mut e = position + len(numbers.exponent);
            if at(e, numbers.minus) {
                e += len(numbers.minus);
            }
            let digits = text[e.min(text.len())..].iter().take_while(|&&c| digit(c)).count();
            if digits > 0 {
                position = e + digits;
            }
            break;
        } else {
            break;
        }
        position += 1;
    }
    if !saw_digit {
        return None;
    }
    Some(decimal_at.unwrap_or(position))
}

/// `Character.digit(c, 10)` for a UTF-16 unit.
fn java_digit(c: u16) -> Option<u16> {
    data::DIGIT_ZEROS.iter().find(|&&zero| (zero..zero + 10).contains(&c)).map(|&zero| c - zero)
}

/// `SimpleDateFormat.charEquals` when lenient: equal, or both space separators (`Zs`).
fn char_equals(a: u16, b: u16) -> bool {
    let space = |c: u16| matches!(c, 0x20 | 0xA0 | 0x1680 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000);
    a == b || (space(a) && space(b))
}

/// `matchString` over a display-names map: the end of the longest name the text continues with at `start`.
fn match_longest(text: &[u16], start: usize, names: &[&str]) -> Option<usize> {
    names
        .iter()
        .map(|name| name.encode_utf16().collect::<Vec<_>>())
        .filter(|name| region_matches_ignore_case(text, start, name))
        .map(|name| start + name.len())
        .max()
}

/// `String.regionMatches(true, start, other, 0, other.length())`, unit by unit.
fn region_matches_ignore_case(text: &[u16], start: usize, other: &[u16]) -> bool {
    let simple = |c: u16, upper: bool| -> u16 {
        let Some(ch) = char::from_u32(u32::from(c)) else { return c };
        let mut mapped = if upper { ch.to_uppercase().collect::<Vec<_>>() } else { ch.to_lowercase().collect::<Vec<_>>() };
        match (mapped.pop(), mapped.is_empty()) {
            (Some(m), true) if (m as u32) < 0x10000 => m as u16,
            _ => c,
        }
    };
    start.checked_add(other.len()).is_some_and(|end| end <= text.len())
        && text[start..start + other.len()].iter().zip(other).all(|(&a, &b)| {
            let (ua, ub) = (simple(a, true), simple(b, true));
            a == b || ua == ub || simple(ua, false) == simple(ub, false)
        })
}

//! `org.mockserver.matchers.DateTimeComparisonMatcher`: a date-time comparison (`before`, `after`,
//! `equalToDateTime`) parsed once, when the matcher value is created, and evaluated per request. It shares the date
//! offsets, truncations and strict readers of the `dates` template helper (its parent module), as upstream shares
//! `org.mockserver.time`.
//!
//! The expected value is `now`, optionally followed by an offset (`now -1 days`, `now PT30M`), or a literal
//! date-time: ISO-8601, RFC-1123 or epoch seconds/millis. `now` reads the server's controllable clock.

use datafaker::java::{DateTimeFormatter, ZoneId};

use super::{
    days_from_civil, java_trim, parse_iso, parse_rfc1123, strict_pattern, utc, DateOffset, Local, Truncation, Zoned,
    EPOCH_MILLIS_THRESHOLD, TRUNCATION_NAMES,
};

/// `DateTimeComparisonMatcher.Operator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operator {
    Before,
    After,
    EqualToDateTime,
}

impl Operator {
    /// The JSON field name, as WireMock names it.
    pub(crate) fn field_name(self) -> &'static str {
        match self {
            Operator::Before => "before",
            Operator::After => "after",
            Operator::EqualToDateTime => "equalToDateTime",
        }
    }

    /// `Operator.forFieldName(name)`.
    pub(crate) fn for_field_name(name: &str) -> Option<Operator> {
        [Operator::Before, Operator::After, Operator::EqualToDateTime].into_iter().find(|o| o.field_name() == name)
    }
}

enum Format {
    Auto,
    Iso,
    Rfc1123,
    EpochSeconds,
    EpochMillis,
    Pattern(DateTimeFormatter),
}

enum Expected {
    /// A literal, resolved (and truncated) once: epoch second and nano.
    Fixed(i64, u32),
    /// `now`, with an offset and a truncation applied per comparison.
    Now { offset: Option<DateOffset>, truncate: Option<Truncation>, last: bool },
}

/// A compiled date-time comparison.
pub(crate) struct DateTimeComparison {
    operator: Operator,
    zone: ZoneId,
    format: Format,
    truncate_actual: Option<Truncation>,
    expected: Expected,
}

impl std::fmt::Debug for DateTimeComparison {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DateTimeComparison").field("operator", &self.operator).finish_non_exhaustive()
    }
}

const MAX_LENGTH: usize = 1024;

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `DateTimeComparisonMatcher.truncation(name)`.
fn truncation(name: Option<&str>) -> Result<Option<Truncation>, String> {
    match name {
        None => Ok(None),
        Some(name) => Truncation::named(name).map(Some).ok_or_else(|| format!("unknown truncation \"{name}\"; use {TRUNCATION_NAMES}")),
    }
}

/// `ZoneId.of(name, ZoneId.SHORT_IDS)`.
fn zone(name: &str) -> Result<ZoneId, String> {
    let id = super::SHORT_IDS.iter().find(|(k, _)| *k == name).map_or(name, |(_, v)| v);
    ZoneId::of(id).map_err(|_| format!("unknown zone \"{name}\"; use a region such as Europe/London, an offset such as +01:00, or UTC"))
}

impl DateTimeComparison {
    /// `DateTimeComparisonMatcher.compile`: the comparison, or the `IllegalArgumentException`'s message.
    pub(crate) fn compile(
        operator: Operator,
        expected: Option<&str>,
        actual_format: Option<&str>,
        truncate_expected: Option<&str>,
        truncate_actual: Option<&str>,
        apply_truncation_last: Option<bool>,
        zone_name: Option<&str>,
    ) -> Result<DateTimeComparison, String> {
        let expected_text = java_trim(expected.unwrap_or(""));
        if expected_text.is_empty() {
            return Err("no expected date-time; use now, now with an offset such as now -1 days, or a date-time such as 2026-10-21T15:00:00Z".into());
        }
        if [Some(expected_text), actual_format, truncate_expected, truncate_actual, zone_name].iter().flatten().any(|v| utf16_len(v) > MAX_LENGTH) {
            return Err(format!("a date-time matcher value is at most {MAX_LENGTH} characters"));
        }
        let zone = match zone_name {
            None => utc(),
            Some(name) => zone(java_trim(name))?,
        };
        let format = match actual_format {
            None => Format::Auto,
            Some(pattern) => match java_trim(pattern).to_lowercase().as_str() {
                "iso" => Format::Iso,
                "rfc1123" => Format::Rfc1123,
                "epochseconds" => Format::EpochSeconds,
                "epochmillis" => Format::EpochMillis,
                _ => Format::Pattern(
                    DateTimeFormatter::of_pattern(&strict_pattern(pattern))
                        .map_err(|e| format!("invalid actualFormat pattern \"{pattern}\": {}", e.message()))?
                        .with_strict_resolver(),
                ),
            },
        };
        let expected_truncation = truncation(truncate_expected)?;
        let actual_truncation = truncation(truncate_actual)?;
        let last = apply_truncation_last == Some(true);

        if expected_text.len() >= 3 && expected_text.is_char_boundary(3) && expected_text[..3].eq_ignore_ascii_case("now") {
            let offset_text = java_trim(&expected_text[3..]);
            let offset = if offset_text.is_empty() { None } else { Some(DateOffset::parse(Some(offset_text)).map_err(|e| super::msg(&e).to_string())?) };
            let expected = Expected::Now { offset, truncate: expected_truncation, last };
            return Ok(DateTimeComparison { operator, zone, format, truncate_actual: actual_truncation, expected });
        }
        let literal = parse(expected_text, &Format::Auto, &zone).and_then(|literal| match expected_truncation {
            Some(t) => literal.with_zone_same_instant(&zone).ok().map(|z| z.truncate(t)),
            None => Some(literal),
        });
        let Some(literal) = literal else {
            return Err(format!(
                "cannot read expected \"{expected_text}\" as a date-time; use now, now with an offset such as now -1 days, ISO-8601 such as 2026-10-21T15:00:00Z, RFC-1123, or epoch seconds or millis"
            ));
        };
        let expected = Expected::Fixed(literal.epoch_second(), literal.local.nanos);
        Ok(DateTimeComparison { operator, zone, format, truncate_actual: actual_truncation, expected })
    }

    /// `compare(actual)`: whether `actual` satisfies the comparison, `None` when it cannot be read as a date-time
    /// (or the arithmetic overflows).
    pub(crate) fn compare(&self, actual: &str) -> Option<bool> {
        let text = java_trim(actual);
        if text.is_empty() {
            return None;
        }
        let parsed = parse(text, &self.format, &self.zone)?;
        let actual = match self.truncate_actual {
            Some(t) => parsed.with_zone_same_instant(&self.zone).ok()?.truncate(t),
            None => parsed,
        };
        let ordering = (actual.epoch_second(), actual.local.nanos).cmp(&self.expected()?);
        Some(match self.operator {
            Operator::Before => ordering.is_lt(),
            Operator::After => ordering.is_gt(),
            Operator::EqualToDateTime => ordering.is_eq(),
        })
    }

    fn expected(&self) -> Option<(i64, u32)> {
        match &self.expected {
            Expected::Fixed(secs, nanos) => Some((*secs, *nanos)),
            Expected::Now { offset, truncate, last } => {
                let mut expected = super::now_at(&self.zone).ok()?;
                if let (Some(t), false) = (truncate, last) {
                    expected = expected.truncate(*t);
                }
                if let Some(offset) = offset {
                    expected = offset.add_to(&expected).ok()?;
                }
                if let (Some(t), true) = (truncate, last) {
                    expected = expected.truncate(*t);
                }
                Some((expected.epoch_second(), expected.local.nanos))
            }
        }
    }
}

/// An optional sign then 1 to 18 digits, so the number cannot overflow.
fn is_epoch(text: &str) -> bool {
    let digits = text.strip_prefix(['-', '+']).unwrap_or(text);
    (1..=18).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit())
}

fn epoch(text: &str) -> i64 {
    text.strip_prefix('+').unwrap_or(text).parse().expect("checked by is_epoch")
}

fn of_epoch_second(secs: i64, nanos: u32, zone: &ZoneId) -> Option<Zoned> {
    Zoned::of_instant(secs, nanos, zone).ok()
}

fn of_epoch_milli(millis: i64, zone: &ZoneId) -> Option<Zoned> {
    of_epoch_second(millis.div_euclid(1000), (millis.rem_euclid(1000) * 1_000_000) as u32, zone)
}

/// `DateTimeComparisonMatcher.parse`: the form is chosen from the text's shape; a value with no zone or offset is
/// read in `zone`. `None` when the text is not in the expected form or is not a valid date-time.
fn parse(text: &str, format: &Format, zone: &ZoneId) -> Option<Zoned> {
    match format {
        Format::Iso => parse_iso(text, zone),
        Format::Rfc1123 => parse_rfc1123(text),
        Format::EpochSeconds => is_epoch(text).then(|| of_epoch_second(epoch(text), 0, zone)).flatten(),
        Format::EpochMillis => is_epoch(text).then(|| of_epoch_milli(epoch(text), zone)).flatten(),
        Format::Pattern(formatter) => resolve(formatter, text, zone),
        Format::Auto => {
            if is_epoch(text) {
                let value = epoch(text);
                return if value.unsigned_abs() >= EPOCH_MILLIS_THRESHOLD as u64 { of_epoch_milli(value, zone) } else { of_epoch_second(value, 0, zone) };
            }
            let first = text.chars().next()?;
            if first.is_alphabetic() {
                parse_rfc1123(text)
            } else if first.is_ascii_digit() || first == '+' || first == '-' {
                parse_iso(text, zone)
            } else {
                None
            }
        }
    }
}

/// `DateTimeComparisonMatcher.resolve(pattern.parse(text), zone)`: a date, or a year and month (the first of the
/// month), with the time when there is one; `None` for part of a time that does not resolve.
fn resolve(formatter: &DateTimeFormatter, text: &str, zone: &ZoneId) -> Option<Zoned> {
    let parsed = formatter.parse(text).ok()?;
    let parsed_zone = match parsed.zone() {
        Some(z) => Some(z.clone()),
        None => match parsed.get_long("OffsetSeconds") {
            Some(o) => Some(ZoneId::of_offset_seconds(i32::try_from(o).ok()?).ok()?),
            None => None,
        },
    };
    let day = match parsed.local_date() {
        Some(d) => d.to_epoch_day(),
        None => match (parsed.get_long("Year"), parsed.get_long("MonthOfYear")) {
            (Some(y), Some(m)) if (1..=12).contains(&m) && (-999_999_999..=999_999_999).contains(&y) => days_from_civil(y, m as u32, 1),
            _ => return None,
        },
    };
    let time = parsed.local_time();
    let has = |f: &str| parsed.get_long(f).is_some();
    if time.is_none() && ["ClockHourOfAmPm", "HourOfAmPm", "HourOfDay", "MinuteOfHour", "SecondOfMinute"].iter().any(|f| has(f)) {
        return None;
    }
    let effective = parsed_zone.unwrap_or_else(|| zone.clone());
    Some(match time {
        Some(t) => {
            let nod = t.to_nano_of_day();
            let local = Local { secs: day * 86_400 + nod / 1_000_000_000, nanos: (nod % 1_000_000_000) as u32 };
            Zoned::of_local(local, &effective, None)
        }
        None => Zoned::start_of_day(day, &effective),
    })
}


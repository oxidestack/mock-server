//! The `dates` template helper (`DateTemplateHelper`), the chainable date it returns (`TemplateDate`), the date
//! offsets and truncations it shares with upstream's date-time matchers (`org.mockserver.time.DateOffset`,
//! `DateTruncation`, `StrictDateFormats`) and Mustache's `{{#dates.render}}` section (`MustacheDateTemplateHelper`).
//!
//! A date is a `ZonedDateTime`: an instant, a zone and the offset it has there. Zone rules, `DateTimeFormatter`
//! patterns (formatting and strict parsing) come from datafaker-rs's `java.time` port; the ISO-8601 and RFC-1123
//! readers, the date arithmetic and the zone resolution of a local date-time (`ZonedDateTime.ofLocal`) are here.

pub(crate) mod comparison;

use std::sync::{Arc, LazyLock};

use datafaker::java::time::LocalOffsets;
use datafaker::java::{DateTimeFormatter, Instant, ZoneId};
use java_compat::lang::{JError, JObject, JValue};
use jmustache::{Fragment, Lambda, LambdaFn, MustacheError};

type Invocation = Option<Result<Option<JValue>, JError>>;
type Res<T> = Result<T, JError>;

const ILLEGAL: &str = "java.lang.IllegalArgumentException";
const DATE_TIME: &str = "java.time.DateTimeException";
const ARITHMETIC: &str = "java.lang.ArithmeticException";

fn illegal(message: impl Into<String>) -> JError {
    JError::new(ILLEGAL, message)
}

fn date_time(message: impl Into<String>) -> JError {
    JError::new(DATE_TIME, message)
}

fn msg(e: &JError) -> &str {
    e.message.as_deref().unwrap_or("")
}

fn overflow() -> JError {
    JError::new(ARITHMETIC, "long overflow")
}

/// `StrictDateFormats.EPOCH_MILLIS_THRESHOLD`.
const EPOCH_MILLIS_THRESHOLD: i64 = 100_000_000_000;
const MAX_PATTERN_LENGTH: usize = 1024;
const MAX_ZONE_LENGTH: usize = 64;
const MAX_QUOTED_LENGTH: usize = 100;
/// `Instant.MIN_SECOND` / `MAX_SECOND`.
const INSTANT_MIN_SECOND: i64 = -31_557_014_167_219_200;
const INSTANT_MAX_SECOND: i64 = 31_556_889_864_403_199;
/// `ChronoField.EPOCH_DAY`'s range.
const EPOCH_DAY_MIN: i64 = -365_243_219_162;
const EPOCH_DAY_MAX: i64 = 365_241_780_471;
const YEAR_MAX: i64 = 999_999_999;

/// `brief(value)`: at most 100 UTF-16 units, then how long it was.
fn brief(value: &str) -> String {
    let units: Vec<u16> = value.encode_utf16().collect();
    if units.len() > MAX_QUOTED_LENGTH {
        format!("{}...({} characters)", String::from_utf16_lossy(&units[..MAX_QUOTED_LENGTH]), units.len())
    } else {
        value.to_string()
    }
}

fn quote(value: &str) -> String {
    format!("\"{}\"", brief(value))
}

/// `String.trim()`.
fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

// ---------------------------------------------------------------------------------------------------------------
// Civil calendar

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn month_length(year: i64, month: u32) -> u32 {
    match month {
        2 => if is_leap(year) { 29 } else { 28 },
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// `LocalDate.toEpochDay()`.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `LocalDate.ofEpochDay(day)`: (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn check_epoch_day(day: i64) -> Res<i64> {
    if !(EPOCH_DAY_MIN..=EPOCH_DAY_MAX).contains(&day) {
        return Err(date_time(format!("Invalid value for EpochDay (valid values {EPOCH_DAY_MIN} - {EPOCH_DAY_MAX}): {day}")));
    }
    Ok(day)
}

fn check_year(year: i64) -> Res<i64> {
    if !(-YEAR_MAX..=YEAR_MAX).contains(&year) {
        return Err(date_time(format!("Invalid value for Year (valid values -{YEAR_MAX} - {YEAR_MAX}): {year}")));
    }
    Ok(year)
}

/// A `LocalDateTime`: whole seconds since 1970-01-01T00:00 and the nano of second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Local {
    secs: i64,
    nanos: u32,
}

impl Local {
    fn epoch_day(&self) -> i64 {
        self.secs.div_euclid(86_400)
    }

    fn second_of_day(&self) -> i64 {
        self.secs.rem_euclid(86_400)
    }

    fn date(&self) -> (i64, u32, u32) {
        civil_from_days(self.epoch_day())
    }

    fn with_date(&self, year: i64, month: u32, day: u32) -> Local {
        Local { secs: days_from_civil(year, month, day) * 86_400 + self.second_of_day(), nanos: self.nanos }
    }

    /// `plusDays(days)`.
    fn plus_days(&self, days: i64) -> Res<Local> {
        let day = check_epoch_day(self.epoch_day().checked_add(days).ok_or_else(overflow)?)?;
        Ok(Local { secs: day * 86_400 + self.second_of_day(), nanos: self.nanos })
    }

    /// `plusMonths(months)`: the day of month clamped to the new month's length.
    fn plus_months(&self, months: i64) -> Res<Local> {
        if months == 0 {
            return Ok(*self);
        }
        let (y, m, d) = self.date();
        let count = (y * 12 + (m as i64 - 1)).wrapping_add(months);
        let year = check_year(count.div_euclid(12))?;
        let month = (count.rem_euclid(12) + 1) as u32;
        Ok(self.with_date(year, month, d.min(month_length(year, month))))
    }

    /// `plusYears(years)`.
    fn plus_years(&self, years: i64) -> Res<Local> {
        if years == 0 {
            return Ok(*self);
        }
        let (y, m, d) = self.date();
        let year = check_year(y.wrapping_add(years))?;
        Ok(self.with_date(year, m, d.min(month_length(year, m))))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Zones

/// `ZoneId.SHORT_IDS`.
const SHORT_IDS: [(&str, &str); 28] = [
    ("ACT", "Australia/Darwin"),
    ("AET", "Australia/Sydney"),
    ("AGT", "America/Argentina/Buenos_Aires"),
    ("ART", "Africa/Cairo"),
    ("AST", "America/Anchorage"),
    ("BET", "America/Sao_Paulo"),
    ("BST", "Asia/Dhaka"),
    ("CAT", "Africa/Harare"),
    ("CNT", "America/St_Johns"),
    ("CST", "America/Chicago"),
    ("CTT", "Asia/Shanghai"),
    ("EAT", "Africa/Addis_Ababa"),
    ("ECT", "Europe/Paris"),
    ("IET", "America/Indiana/Indianapolis"),
    ("IST", "Asia/Kolkata"),
    ("JST", "Asia/Tokyo"),
    ("MIT", "Pacific/Apia"),
    ("NET", "Asia/Yerevan"),
    ("NST", "Pacific/Auckland"),
    ("PLT", "Asia/Karachi"),
    ("PNT", "America/Phoenix"),
    ("PRT", "America/Puerto_Rico"),
    ("PST", "America/Los_Angeles"),
    ("SST", "Pacific/Guadalcanal"),
    ("VST", "Asia/Ho_Chi_Minh"),
    ("EST", "-05:00"),
    ("MST", "-07:00"),
    ("HST", "-10:00"),
];

/// `TemplateDate.zone(name)`: `ZoneId.of(name, ZoneId.SHORT_IDS)`, with the helper's error texts.
fn zone(name: Option<&str>) -> Res<ZoneId> {
    let name = java_trim(name.unwrap_or(""));
    if name.is_empty() {
        return Err(illegal("dates: no timezone given; use a region such as Europe/London, an offset such as +01:00, or UTC"));
    }
    let unknown = || illegal(format!("dates: unknown timezone {}; use a region such as Europe/London, an offset such as +01:00, or UTC", quote(name)));
    if utf16_len(name) > MAX_ZONE_LENGTH {
        return Err(unknown());
    }
    let id = SHORT_IDS.iter().find(|(k, _)| *k == name).map_or(name, |(_, v)| v);
    ZoneId::of(id).map_err(|_| unknown())
}

fn utc() -> ZoneId {
    ZoneId::of_offset_seconds(0).expect("Z")
}

// ---------------------------------------------------------------------------------------------------------------
// ZonedDateTime

/// A `ZonedDateTime`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zoned {
    local: Local,
    offset: i32,
    zone: ZoneId,
}

impl Zoned {
    /// `instant.atZone(zone)`.
    fn of_instant(secs: i64, nanos: u32, zone: &ZoneId) -> Res<Zoned> {
        if !(INSTANT_MIN_SECOND..=INSTANT_MAX_SECOND).contains(&secs) {
            return Err(date_time("Instant exceeds minimum or maximum instant"));
        }
        let offset = zone.offset_at(secs);
        let local = Local { secs: secs + offset as i64, nanos };
        check_year(local.date().0)?;
        Ok(Zoned { local, offset, zone: zone.clone() })
    }

    /// `ZonedDateTime.ofLocal(local, zone, preferred)`: in a gap the time moves forward by the gap's length, in
    /// an overlap the preferred offset when it is one of the two, else the earlier.
    fn of_local(local: Local, zone: &ZoneId, preferred: Option<i32>) -> Zoned {
        match zone.local_offsets(local.secs) {
            LocalOffsets::Single(offset) => Zoned { local, offset, zone: zone.clone() },
            LocalOffsets::Gap { before, after } => {
                let local = Local { secs: local.secs + (after - before) as i64, nanos: local.nanos };
                Zoned { local, offset: after, zone: zone.clone() }
            }
            LocalOffsets::Overlap { before, after } => {
                let offset = preferred.filter(|p| *p == before || *p == after).unwrap_or(before);
                Zoned { local, offset, zone: zone.clone() }
            }
        }
    }

    /// `date.atStartOfDay(zone)`: in a gap, the local time just after it.
    fn start_of_day(epoch_day: i64, zone: &ZoneId) -> Zoned {
        let local = Local { secs: epoch_day * 86_400, nanos: 0 };
        match zone.local_offsets(local.secs) {
            LocalOffsets::Gap { before, after } => {
                let transition = Zoned::transition_instant(zone, local.secs - before as i64, before);
                Zoned { local: Local { secs: transition + after as i64, nanos: 0 }, offset: after, zone: zone.clone() }
            }
            _ => Zoned::of_local(local, zone, None),
        }
    }

    /// The first instant at or after `from` where the zone's offset is no longer `before`.
    fn transition_instant(zone: &ZoneId, from: i64, before: i32) -> i64 {
        // search backwards for the last instant with the old offset (a gap is at most a day long)
        let (mut lo, mut hi) = (from - 2 * 86_400, from);
        if zone.offset_at(hi) == before {
            hi = from + 2 * 86_400;
            lo = from;
        }
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if zone.offset_at(mid) == before {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        hi
    }

    fn epoch_second(&self) -> i64 {
        self.local.secs - self.offset as i64
    }

    fn instant(&self) -> Instant {
        Instant::of_epoch_second(self.epoch_second(), self.local.nanos as i64).expect("in range")
    }

    /// `resolveLocal(local)`: date-based arithmetic, keeping this offset where it is still valid.
    fn resolve_local(&self, local: Local) -> Zoned {
        Zoned::of_local(local, &self.zone, Some(self.offset))
    }

    /// Time-based arithmetic on the instant time-line.
    fn plus_seconds_nanos(&self, seconds: i64, nanos: i64) -> Res<Zoned> {
        let total = self.local.secs as i128 * 1_000_000_000 + self.local.nanos as i128 + seconds as i128 * 1_000_000_000 + nanos as i128;
        let secs = total.div_euclid(1_000_000_000);
        let nanos = total.rem_euclid(1_000_000_000) as u32;
        let day = secs.div_euclid(86_400);
        if day < EPOCH_DAY_MIN as i128 || day > EPOCH_DAY_MAX as i128 {
            return Err(date_time(format!("Invalid value for EpochDay (valid values {EPOCH_DAY_MIN} - {EPOCH_DAY_MAX}): {day}")));
        }
        let local = Local { secs: secs as i64, nanos };
        let instant = local.secs - self.offset as i64;
        Zoned::of_instant(instant, nanos, &self.zone)
    }

    fn plus_unit(&self, amount: i64, unit: Unit) -> Res<Zoned> {
        match unit {
            Unit::Seconds => self.plus_i128_seconds(amount as i128),
            Unit::Minutes => self.plus_i128_seconds(amount as i128 * 60),
            Unit::Hours => self.plus_i128_seconds(amount as i128 * 3600),
            Unit::Days => Ok(self.resolve_local(self.local.plus_days(amount)?)),
            Unit::Weeks => Ok(self.resolve_local(self.local.plus_days(amount.checked_mul(7).ok_or_else(overflow)?)?)),
            Unit::Months => Ok(self.resolve_local(self.local.plus_months(amount)?)),
            Unit::Years => Ok(self.resolve_local(self.local.plus_years(amount)?)),
        }
    }

    fn plus_i128_seconds(&self, seconds: i128) -> Res<Zoned> {
        let secs = self.local.secs as i128 + seconds;
        let day = secs.div_euclid(86_400);
        if day < EPOCH_DAY_MIN as i128 || day > EPOCH_DAY_MAX as i128 {
            return Err(date_time(format!("Invalid value for EpochDay (valid values {EPOCH_DAY_MIN} - {EPOCH_DAY_MAX}): {day}")));
        }
        Zoned::of_instant(secs as i64 - self.offset as i64, self.local.nanos, &self.zone)
    }

    fn with_zone_same_instant(&self, zone: &ZoneId) -> Res<Zoned> {
        Zoned::of_instant(self.epoch_second(), self.local.nanos, zone)
    }

    fn truncate(&self, t: Truncation) -> Zoned {
        let day = self.local.epoch_day();
        let (y, m, _) = self.local.date();
        let start = |y: i64, m: u32, d: u32| Zoned::start_of_day(days_from_civil(y, m, d), &self.zone);
        match t {
            Truncation::StartOfSecond => self.resolve_local(Local { secs: self.local.secs, nanos: 0 }),
            Truncation::StartOfMinute => self.resolve_local(Local { secs: self.local.secs - self.local.secs.rem_euclid(60), nanos: 0 }),
            Truncation::StartOfHour => self.resolve_local(Local { secs: self.local.secs - self.local.secs.rem_euclid(3600), nanos: 0 }),
            Truncation::StartOfDay => Zoned::start_of_day(day, &self.zone),
            Truncation::FirstDayOfMonth => start(y, m, 1),
            Truncation::LastDayOfMonth => start(y, m, month_length(y, m)),
            Truncation::FirstDayOfNextMonth => if m == 12 { start(y + 1, 1, 1) } else { start(y, m + 1, 1) },
            Truncation::FirstDayOfYear => start(y, 1, 1),
            Truncation::LastDayOfYear => start(y, 12, 31),
            Truncation::FirstDayOfNextYear => start(y + 1, 1, 1),
        }
    }

    /// `DateTimeFormatter.ISO_INSTANT` when the zone is UTC, else `ISO_OFFSET_DATE_TIME`.
    fn iso(&self) -> String {
        if self.zone.is_fixed_offset() && self.offset == 0 {
            iso_instant(self.epoch_second(), self.local.nanos)
        } else {
            format!("{}{}", iso_local(self.local, false), offset_id(self.offset))
        }
    }

    fn rfc1123(&self) -> Res<String> {
        static IMF_FIXDATE: LazyLock<DateTimeFormatter> = LazyLock::new(|| {
            DateTimeFormatter::of_pattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'").expect("IMF-fixdate").with_zone(utc())
        });
        IMF_FIXDATE.format_instant(self.instant()).map_err(java_error)
    }

    fn epoch_millis(&self) -> Res<i64> {
        self.instant().to_epoch_milli().map_err(java_error)
    }

    fn format(&self, pattern: Option<&str>) -> Res<String> {
        if let Some(p) = pattern {
            match java_trim(p).to_lowercase().as_str() {
                "iso" => return Ok(self.iso()),
                "rfc1123" => return self.rfc1123(),
                "epochseconds" => return Ok(self.epoch_second().to_string()),
                "epochmillis" => return Ok(self.epoch_millis()?.to_string()),
                _ => {}
            }
        }
        formatter(pattern)?.with_zone(self.zone.clone()).format_instant(self.instant()).map_err(java_error)
    }
}

/// A datafaker-rs `java.time` exception as the Java exception it stands for.
fn java_error(e: datafaker::Error) -> JError {
    let package = match e.simple_class() {
        "DateTimeException" => "java.time.",
        "DateTimeParseException" => "java.time.format.",
        "UnsupportedTemporalTypeException" => "java.time.temporal.",
        "ZoneRulesException" => "java.time.zone.",
        _ => "java.lang.",
    };
    JError::new(&format!("{package}{}", e.simple_class()), e.message())
}

fn offset_id(seconds: i32) -> String {
    if seconds == 0 {
        return "Z".into();
    }
    let abs = seconds.unsigned_abs();
    let (h, m, s) = (abs / 3600, abs / 60 % 60, abs % 60);
    let mut id = format!("{}{h:02}:{m:02}", if seconds < 0 { '-' } else { '+' });
    if s != 0 {
        id.push_str(&format!(":{s:02}"));
    }
    id
}

/// A year as `ISO_LOCAL_DATE` prints it: four digits at least, `+` above 9999.
fn iso_year(year: i64) -> String {
    if year.abs() < 1000 {
        if year < 0 { format!("-{:04}", -year) } else { format!("{year:04}") }
    } else if year > 9999 {
        format!("+{year}")
    } else {
        year.to_string()
    }
}

/// `ISO_LOCAL_DATE_TIME`; `groups` prints the fraction in groups of three digits (`ISO_INSTANT`), otherwise with
/// no trailing zeros.
fn iso_local(local: Local, groups: bool) -> String {
    let (y, m, d) = local.date();
    let sod = local.second_of_day();
    let mut s = format!("{}-{m:02}-{d:02}T{:02}:{:02}:{:02}", iso_year(y), sod / 3600, sod / 60 % 60, sod % 60);
    let n = local.nanos;
    if n != 0 {
        let digits = format!("{n:09}");
        if groups {
            if n.is_multiple_of(1_000_000) {
                s.push_str(&format!(".{}", &digits[..3]));
            } else if n.is_multiple_of(1_000) {
                s.push_str(&format!(".{}", &digits[..6]));
            } else {
                s.push_str(&format!(".{digits}"));
            }
        } else {
            s.push('.');
            s.push_str(digits.trim_end_matches('0'));
        }
    }
    s
}

/// `DateTimeFormatter.ISO_INSTANT.format(instant)`.
fn iso_instant(secs: i64, nanos: u32) -> String {
    format!("{}Z", iso_local(Local { secs, nanos }, true))
}

// ---------------------------------------------------------------------------------------------------------------
// Patterns

/// `checkPattern` and `compile`: a pattern as `DateTimeFormatter.ofPattern(…, Locale.ENGLISH)`.
fn compile(compiled: &str, pattern: &str) -> Res<DateTimeFormatter> {
    DateTimeFormatter::of_pattern(compiled).map_err(|e| illegal(format!("dates: invalid date pattern {}: {}", quote(pattern), brief(e.message()))))
}

fn check_pattern(pattern: Option<&str>) -> Res<&str> {
    let pattern = pattern.ok_or_else(|| illegal("dates: no date pattern given"))?;
    let length = utf16_len(pattern);
    if length > MAX_PATTERN_LENGTH {
        return Err(illegal(format!("dates: date pattern too long ({length} characters, at most {MAX_PATTERN_LENGTH})")));
    }
    Ok(pattern)
}

/// `TemplateDate.formatter(pattern)`.
fn formatter(pattern: Option<&str>) -> Res<DateTimeFormatter> {
    let pattern = check_pattern(pattern)?;
    compile(pattern, pattern)
}

/// `StrictDateFormats.strictPattern`: an unquoted `y` becomes `u`.
fn strict_pattern(pattern: &str) -> String {
    let mut quoted = false;
    pattern
        .chars()
        .map(|c| {
            if c == '\'' {
                quoted = !quoted;
            }
            if !quoted && c == 'y' { 'u' } else { c }
        })
        .collect()
}

/// `TemplateDate.parser(pattern)`: strict resolution.
fn parser(pattern: &str) -> Res<DateTimeFormatter> {
    let pattern = check_pattern(Some(pattern))?;
    Ok(compile(&strict_pattern(pattern), pattern)?.with_strict_resolver())
}

// ---------------------------------------------------------------------------------------------------------------
// Offsets (`DateOffset`)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    Seconds,
    Minutes,
    Hours,
    Days,
    Weeks,
    Months,
    Years,
}

enum DateOffset {
    /// `Duration`: seconds and nanos.
    Duration(i64, i64),
    /// `Period`: years, months, days.
    Period(i32, i32, i32),
    Parts(Vec<(i64, Unit)>),
}

fn is_java_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r')
}

static OFFSET_SPEC: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[ \t\n\x0B\x0C\r]*(?:[+-]?[0-9]+[ \t\n\x0B\x0C\r]*[a-zA-Z]+[ \t\n\x0B\x0C\r,]*)+$").unwrap());
static OFFSET_PART: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"([+-]?[0-9]+)[ \t\n\x0B\x0C\r]*([a-zA-Z]+)").unwrap());
static PERIOD: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(?i)^([-+]?)P(?:([-+]?[0-9]+)Y)?(?:([-+]?[0-9]+)M)?(?:([-+]?[0-9]+)W)?(?:([-+]?[0-9]+)D)?$").unwrap());
static DURATION: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)^([-+]?)P(?:([-+]?[0-9]+)D)?(T(?:([-+]?[0-9]+)H)?(?:([-+]?[0-9]+)M)?(?:([-+]?[0-9]+)(?:[.,]([0-9]{0,9}))?S)?)?$").unwrap()
});

/// `Period.parse(text)`.
fn parse_period(text: &str) -> Res<(i32, i32, i32)> {
    let fail = || JError::new("java.time.format.DateTimeParseException", "Text cannot be parsed to a Period");
    let c = PERIOD.captures(text).ok_or_else(fail)?;
    if (2..=5).all(|i| c.get(i).is_none()) {
        return Err(fail());
    }
    let negate = c.get(1).is_some_and(|m| m.as_str() == "-");
    let int = |i: usize| -> Res<i32> {
        match c.get(i) {
            None => Ok(0),
            Some(m) => {
                let v: i32 = m.as_str().trim_start_matches('+').parse().map_err(|_| fail())?;
                if negate { v.checked_neg().ok_or_else(fail) } else { Ok(v) }
            }
        }
    };
    let (years, months, weeks, days) = (int(2)?, int(3)?, int(4)?, int(5)?);
    let days = weeks.checked_mul(7).and_then(|w| w.checked_add(days)).ok_or_else(fail)?;
    Ok((years, months, days))
}

/// `Duration.parse(text)`: (seconds, nanos).
fn parse_duration(text: &str) -> Res<(i64, i64)> {
    let fail = || JError::new("java.time.format.DateTimeParseException", "Text cannot be parsed to a Duration");
    let c = DURATION.captures(text).ok_or_else(fail)?;
    let t = c.get(3).map(|m| m.as_str());
    let any_time = [4, 5, 6].iter().any(|i| c.get(*i).is_some());
    if c.get(2).is_none() && !any_time || t.is_some_and(|t| !any_time && t.len() == 1) {
        return Err(fail());
    }
    let num = |i: usize, mul: i64| -> Res<i64> {
        match c.get(i) {
            None => Ok(0),
            Some(m) => m.as_str().trim_start_matches('+').parse::<i64>().ok().and_then(|v| v.checked_mul(mul)).ok_or_else(fail),
        }
    };
    let seconds = num(2, 86_400)?
        .checked_add(num(4, 3600)?)
        .and_then(|s| s.checked_add(num(5, 60).ok()?))
        .and_then(|s| s.checked_add(num(6, 1).ok()?))
        .ok_or_else(fail)?;
    let mut nanos = match c.get(7) {
        None => 0,
        Some(m) if m.as_str().is_empty() => 0,
        Some(m) => format!("{:0<9}", m.as_str()).parse::<i64>().map_err(|_| fail())?,
    };
    if c.get(6).is_some_and(|m| m.as_str().starts_with('-')) {
        nanos = -nanos;
    }
    let (mut s, mut n) = (seconds as i128, nanos as i128);
    if c.get(1).is_some_and(|m| m.as_str() == "-") {
        s = -s;
        n = -n;
    }
    let total = s * 1_000_000_000 + n;
    let secs = total.div_euclid(1_000_000_000);
    if secs < i64::MIN as i128 || secs > i64::MAX as i128 {
        return Err(fail());
    }
    Ok((secs as i64, total.rem_euclid(1_000_000_000) as i64))
}

fn unit(name: &str, offset: &str) -> Res<Unit> {
    Ok(match name.to_lowercase().as_str() {
        "second" | "seconds" => Unit::Seconds,
        "minute" | "minutes" => Unit::Minutes,
        "hour" | "hours" => Unit::Hours,
        "day" | "days" => Unit::Days,
        "week" | "weeks" => Unit::Weeks,
        "month" | "months" => Unit::Months,
        "year" | "years" => Unit::Years,
        _ => {
            return Err(illegal(format!(
                "invalid date offset {}: unknown unit {}; use seconds, minutes, hours, days, weeks, months or years",
                quote(offset),
                quote(name)
            )));
        }
    })
}

impl DateOffset {
    /// `DateOffset.parse(offset)`, its errors without the `dates: ` prefix.
    fn parse(offset: Option<&str>) -> Res<DateOffset> {
        let offset = match offset {
            Some(o) if !java_trim(o).is_empty() => o,
            _ => return Err(illegal("no date offset given")),
        };
        let spec = java_trim(offset);
        let unsigned = spec.strip_prefix(['-', '+']).unwrap_or(spec);
        let invalid = |e: JError| illegal(format!("invalid date offset {}: {}", quote(offset), brief(msg(&e))));
        if unsigned.starts_with(['P', 'p']) {
            return if unsigned.to_uppercase().contains('T') {
                parse_duration(spec).map(|(s, n)| DateOffset::Duration(s, n)).map_err(invalid)
            } else {
                parse_period(spec).map(|(y, m, d)| DateOffset::Period(y, m, d)).map_err(invalid)
            };
        }
        if OFFSET_SPEC.is_match(spec) {
            let mut parts = Vec::new();
            for c in OFFSET_PART.captures_iter(spec) {
                let amount = c[1].trim_start_matches('+');
                let amount: i64 = amount.parse().map_err(|_| {
                    illegal(format!("invalid date offset {}: {}", quote(offset), brief(&format!("For input string: \"{}\"", c[1].strip_prefix('+').unwrap_or(&c[1])))))
                })?;
                parts.push((amount, unit(&c[2], offset)?));
            }
            return Ok(DateOffset::Parts(parts));
        }
        Err(illegal(format!(
            "invalid date offset {}; use an amount and unit such as \"1 days\", \"-2 hours\" or \"+3 months\", or an ISO-8601 period such as P1D or PT1H",
            quote(offset)
        )))
    }

    fn add_to(&self, value: &Zoned) -> Res<Zoned> {
        match self {
            DateOffset::Duration(s, n) => {
                let mut z = value.clone();
                if *s != 0 {
                    z = z.plus_seconds_nanos(*s, 0)?;
                }
                if *n != 0 {
                    z = z.plus_seconds_nanos(0, *n)?;
                }
                Ok(z)
            }
            DateOffset::Period(y, m, d) => {
                let mut local = value.local;
                if *m == 0 {
                    if *y != 0 {
                        local = local.plus_years(*y as i64)?;
                    }
                } else {
                    let total = *y as i64 * 12 + *m as i64;
                    if total != 0 {
                        local = local.plus_months(total)?;
                    }
                }
                if *d != 0 {
                    local = local.plus_days(*d as i64)?;
                }
                Ok(value.resolve_local(local))
            }
            DateOffset::Parts(parts) => {
                let mut z = value.clone();
                for (amount, unit) in parts {
                    z = z.plus_unit(*amount, *unit)?;
                }
                Ok(z)
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Truncations (`DateTruncation`)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Truncation {
    StartOfSecond,
    StartOfMinute,
    StartOfHour,
    StartOfDay,
    FirstDayOfMonth,
    LastDayOfMonth,
    FirstDayOfNextMonth,
    FirstDayOfYear,
    LastDayOfYear,
    FirstDayOfNextYear,
}

const TRUNCATION_NAMES: &str = "startOfSecond, startOfMinute, startOfHour, startOfDay, firstDayOfMonth, lastDayOfMonth, firstDayOfNextMonth, firstDayOfYear, lastDayOfYear or firstDayOfNextYear";

impl Truncation {
    /// `DateTruncation.named(name)`.
    fn named(name: &str) -> Option<Truncation> {
        let key: String = name.to_lowercase().chars().filter(|c| !(is_java_space(*c) || *c == '_' || *c == '-')).collect();
        Some(match key.as_str() {
            "startofsecond" => Truncation::StartOfSecond,
            "startofminute" => Truncation::StartOfMinute,
            "startofhour" | "firstminuteofhour" => Truncation::StartOfHour,
            "startofday" | "firsthourofday" => Truncation::StartOfDay,
            "firstdayofmonth" | "startofmonth" => Truncation::FirstDayOfMonth,
            "lastdayofmonth" => Truncation::LastDayOfMonth,
            "firstdayofnextmonth" | "startofnextmonth" => Truncation::FirstDayOfNextMonth,
            "firstdayofyear" | "startofyear" => Truncation::FirstDayOfYear,
            "lastdayofyear" => Truncation::LastDayOfYear,
            "firstdayofnextyear" | "startofnextyear" => Truncation::FirstDayOfNextYear,
            _ => return None,
        })
    }

    fn of_method(name: &str) -> Option<Truncation> {
        Some(match name {
            "startOfSecond" => Truncation::StartOfSecond,
            "startOfMinute" => Truncation::StartOfMinute,
            "startOfHour" => Truncation::StartOfHour,
            "startOfDay" => Truncation::StartOfDay,
            "firstDayOfMonth" => Truncation::FirstDayOfMonth,
            "lastDayOfMonth" => Truncation::LastDayOfMonth,
            "firstDayOfNextMonth" => Truncation::FirstDayOfNextMonth,
            "firstDayOfYear" => Truncation::FirstDayOfYear,
            "lastDayOfYear" => Truncation::LastDayOfYear,
            "firstDayOfNextYear" => Truncation::FirstDayOfNextYear,
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Reading dates

/// The value `dates.parse` reads.
enum Input<'a> {
    Null,
    Date(&'a Zoned),
    Integral(i64),
    /// A `Double` or `Float`, and its `toString()`.
    Floating(f64, String),
    Text(String),
}

fn input(value: &JValue) -> Input<'_> {
    match value {
        JValue::Null => Input::Null,
        JValue::Byte(v) => Input::Integral(*v as i64),
        JValue::Short(v) => Input::Integral(*v as i64),
        JValue::Int(v) => Input::Integral(*v as i64),
        JValue::Long(v) => Input::Integral(*v),
        JValue::Float(v) => Input::Floating(*v as f64, value.to_java_string()),
        JValue::Double(v) => Input::Floating(*v, value.to_java_string()),
        JValue::Object(o) => match o.as_any().downcast_ref::<TemplateDate>() {
            Some(d) => Input::Date(&d.0),
            None => Input::Text(value.to_java_string()),
        },
        other => Input::Text(other.to_java_string()),
    }
}

fn is_epoch_keyword(pattern: &str) -> bool {
    matches!(java_trim(pattern).to_lowercase().as_str(), "epochseconds" | "epochmillis")
}

fn is_epoch_number(text: &str) -> bool {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    (1..=19).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit())
}

/// `TemplateDate.parse(input, pattern, zone)`.
fn parse(value: &JValue, pattern: Option<&str>, zone_name: Option<&str>) -> Res<Zoned> {
    let zone = match zone_name {
        Some(z) => Some(self::zone(Some(z))?),
        None => None,
    };
    let read_zone = zone.clone().unwrap_or_else(utc);
    let parsed = match input(value) {
        Input::Null => return Err(illegal("dates.parse: no date given (the value is null)")),
        Input::Date(d) => d.clone(),
        Input::Integral(n) if pattern.is_none_or(is_epoch_keyword) => from_epoch(n, pattern.map(|p| java_trim(p).to_lowercase()).as_deref(), &read_zone)?,
        Input::Floating(f, text) if pattern.is_none_or(is_epoch_keyword) => {
            if f != f.round_ties_even() {
                return Err(illegal(format!("dates.parse: epoch value {text} is not a whole number")));
            }
            from_epoch(f as i64, pattern.map(|p| java_trim(p).to_lowercase()).as_deref(), &read_zone)?
        }
        other => {
            let text = match other {
                Input::Integral(n) => n.to_string(),
                Input::Floating(_, s) | Input::Text(s) => s,
                Input::Null | Input::Date(_) => unreachable!(),
            };
            let text = java_trim(&text);
            match pattern {
                None => parse_text(text, &read_zone)?,
                Some(p) => parse_with_pattern(text, p, &read_zone)?,
            }
        }
    };
    match zone {
        Some(z) => parsed.with_zone_same_instant(&z),
        None => Ok(parsed),
    }
}

fn from_epoch(epoch: i64, unit: Option<&str>, zone: &ZoneId) -> Res<Zoned> {
    let millis = match unit {
        Some(u) => u == "epochmillis",
        None => epoch.unsigned_abs() >= EPOCH_MILLIS_THRESHOLD as u64,
    };
    let (secs, nanos) = if millis { (epoch.div_euclid(1000), (epoch.rem_euclid(1000) * 1_000_000) as u32) } else { (epoch, 0) };
    Zoned::of_instant(secs, nanos, zone).map_err(|_| illegal(format!("dates.parse: epoch value {epoch} is out of range")))
}

fn parse_long(text: &str) -> Res<i64> {
    text.strip_prefix('+').unwrap_or(text).parse().map_err(|_| illegal(format!("dates.parse: epoch value {text} is out of range")))
}

fn parse_text(text: &str, zone: &ZoneId) -> Res<Zoned> {
    if text.is_empty() {
        return Err(illegal("dates.parse: no date given (the value is empty); use now for the current time"));
    }
    if text.eq_ignore_ascii_case("now") {
        return now_at(zone);
    }
    if is_epoch_number(text) {
        return from_epoch(parse_long(text)?, None, zone);
    }
    if let Some(z) = parse_iso(text, zone).or_else(|| parse_rfc1123(text)) {
        return Ok(z);
    }
    Err(illegal(format!(
        "dates.parse: cannot read {} as a date; expected ISO-8601 (such as 2026-10-21T15:00:00Z, 2026-10-21T16:00:00+01:00 or 2026-10-21), RFC-1123 (such as Wed, 21 Oct 2026 15:00:00 GMT), epoch seconds or epoch millis, or pass the pattern it is written in",
        quote(text)
    )))
}

fn parse_with_pattern(text: &str, pattern: &str, zone: &ZoneId) -> Res<Zoned> {
    let keyword = java_trim(pattern).to_lowercase();
    match keyword.as_str() {
        "epochseconds" | "epochmillis" => {
            if !is_epoch_number(text) {
                let what = if keyword == "epochmillis" { "epoch millis" } else { "epoch seconds" };
                return Err(illegal(format!("dates.parse: {} is not a number of {what}", quote(text))));
            }
            from_epoch(parse_long(text)?, Some(&keyword), zone)
        }
        "iso" => parse_iso(text, zone).ok_or_else(|| {
            illegal(format!("dates.parse: cannot read {} as an ISO-8601 date such as 2026-10-21T15:00:00Z, 2026-10-21T16:00:00+01:00 or 2026-10-21", quote(text)))
        }),
        "rfc1123" => parse_rfc1123(text)
            .ok_or_else(|| illegal(format!("dates.parse: cannot read {} as an RFC-1123 date such as Wed, 21 Oct 2026 15:00:00 GMT", quote(text)))),
        _ => {
            let cannot = |message: &str| illegal(format!("dates.parse: cannot read {} with pattern {}: {}", quote(text), quote(pattern), brief(message)));
            let parsed = parser(pattern)?.parse(text).map_err(|e| cannot(e.message()))?;
            let parsed_zone = match parsed.zone() {
                Some(z) => Some(z.clone()),
                None => match parsed.get_long("OffsetSeconds") {
                    Some(o) => Some(ZoneId::of_offset_seconds(o as i32).map_err(|e| cannot(e.message()))?),
                    None => None,
                },
            };
            let effective = parsed_zone.unwrap_or_else(|| zone.clone());
            let date = match parsed.local_date() {
                Some(d) => Some(d.to_epoch_day()),
                None => match (parsed.get_long("Year"), parsed.get_long("MonthOfYear")) {
                    (Some(y), Some(m)) => {
                        if !(1..=12).contains(&m) {
                            return Err(cannot(&format!("Invalid value for MonthOfYear (valid values 1 - 12): {m}")));
                        }
                        Some(days_from_civil(check_year(y).map_err(|e| cannot(msg(&e)))?, m as u32, 1))
                    }
                    _ => None,
                },
            };
            let Some(day) = date else {
                return Err(illegal(format!(
                    "dates.parse: pattern {} has no date (year, month and day) in it, so {} cannot be read as a date",
                    quote(pattern),
                    quote(text)
                )));
            };
            let time = parsed.local_time();
            let has = |f: &str| parsed.get_long(f).is_some();
            if time.is_none() && (has("ClockHourOfAmPm") || has("HourOfAmPm")) {
                return Err(illegal(format!(
                    "dates.parse: pattern {} has a 12-hour clock hour (h or K) but no AM/PM marker (a), so the time in {} cannot be read; use HH for a 24-hour clock or add a",
                    quote(pattern),
                    quote(text)
                )));
            }
            if time.is_none() && (has("HourOfDay") || has("MinuteOfHour") || has("SecondOfMinute")) {
                return Err(illegal(format!(
                    "dates.parse: pattern {} has part of a time but not enough to read the time in {}",
                    quote(pattern),
                    quote(text)
                )));
            }
            Ok(match time {
                Some(t) => {
                    let nod = t.to_nano_of_day();
                    let local = Local { secs: day * 86_400 + nod / 1_000_000_000, nanos: (nod % 1_000_000_000) as u32 };
                    Zoned::of_local(local, &effective, None)
                }
                None => Zoned::start_of_day(day, &effective),
            })
        }
    }
}

/// A cursor over ASCII-ish text for the hand-written ISO-8601 and RFC-1123 readers.
struct Cursor<'a> {
    s: &'a [u8],
    i: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn eat_ci(&mut self, c: u8) -> bool {
        if self.peek().is_some_and(|p| p.eq_ignore_ascii_case(&c)) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn digits(&mut self, min: usize, max: usize) -> Option<i64> {
        let start = self.i;
        while self.i - start < max && self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        if self.i - start < min {
            self.i = start;
            return None;
        }
        std::str::from_utf8(&self.s[start..self.i]).ok()?.parse().ok()
    }

    fn done(&self) -> bool {
        self.i == self.s.len()
    }
}

fn valid_date(y: i64, m: i64, d: i64) -> bool {
    (-YEAR_MAX..=YEAR_MAX).contains(&y) && (1..=12).contains(&m) && d >= 1 && d <= month_length(y, m as u32) as i64
}

/// `ISO_LOCAL_DATE` (strict): (epoch day).
fn iso_date(c: &mut Cursor) -> Option<i64> {
    // appendValue(YEAR, 4, 10, EXCEEDS_PAD): a sign is needed for more than four digits
    let year = if c.eat(b'+') {
        c.digits(5, 10)?
    } else if c.eat(b'-') {
        -c.digits(4, 10)?
    } else {
        c.digits(4, 4)?
    };
    if !c.eat(b'-') {
        return None;
    }
    let month = c.digits(2, 2)?;
    if !c.eat(b'-') {
        return None;
    }
    let day = c.digits(2, 2)?;
    valid_date(year, month, day).then(|| days_from_civil(year, month as u32, day as u32))
}

/// `ISO_LOCAL_TIME` (strict): (second of day, nanos).
fn iso_time(c: &mut Cursor) -> Option<(i64, u32)> {
    let hour = c.digits(2, 2)?;
    if !c.eat(b':') {
        return None;
    }
    let minute = c.digits(2, 2)?;
    let (mut second, mut nanos) = (0, 0u32);
    if c.peek() == Some(b':') && c.s.get(c.i + 1).is_some_and(|b| b.is_ascii_digit()) {
        c.i += 1;
        second = c.digits(2, 2)?;
        if c.peek() == Some(b'.') {
            c.i += 1;
            let start = c.i;
            while c.i - start < 9 && c.peek().is_some_and(|b| b.is_ascii_digit()) {
                c.i += 1;
            }
            let digits = std::str::from_utf8(&c.s[start..c.i]).ok()?;
            nanos = if digits.is_empty() { 0 } else { format!("{digits:0<9}").parse().ok()? };
        }
    }
    (hour <= 23 && minute <= 59 && second <= 59).then_some((hour * 3600 + minute * 60 + second, nanos))
}

/// `appendOffsetId()` (`+HH:MM:ss`, `Z`) in strict mode: offset seconds.
fn iso_offset(c: &mut Cursor) -> Option<i32> {
    if c.eat(b'Z') {
        return Some(0);
    }
    let sign = if c.eat(b'+') {
        1
    } else if c.eat(b'-') {
        -1
    } else {
        return None;
    };
    let h = c.digits(2, 2)?;
    if !c.eat(b':') {
        return None;
    }
    let m = c.digits(2, 2)?;
    let mut s = 0;
    if c.peek() == Some(b':') && c.s.get(c.i + 1).is_some_and(|b| b.is_ascii_digit()) {
        c.i += 1;
        s = c.digits(2, 2)?;
    }
    if h > 18 || m > 59 || s > 59 || (h == 18 && (m > 0 || s > 0)) {
        return None;
    }
    Some(sign * (h * 3600 + m * 60 + s) as i32)
}

/// `TemplateDate.parseIso`: `ISO_DATE_TIME.parseBest(ZonedDateTime, LocalDateTime)`, then `ISO_LOCAL_DATE`.
fn parse_iso(text: &str, zone: &ZoneId) -> Option<Zoned> {
    let mut c = Cursor { s: text.as_bytes(), i: 0 };
    if let Some(day) = iso_date(&mut c) {
        if c.done() {
            return Some(Zoned::start_of_day(day, zone));
        }
        if !c.eat_ci(b'T') {
            return None;
        }
        let (sod, nanos) = iso_time(&mut c)?;
        let local = Local { secs: day * 86_400 + sod, nanos };
        if c.done() {
            return Some(Zoned::of_local(local, zone, None));
        }
        let offset = iso_offset(&mut c)?;
        let instant = local.secs - offset as i64;
        if c.done() {
            let z = ZoneId::of_offset_seconds(offset).ok()?;
            return Zoned::of_instant(instant, nanos, &z).ok();
        }
        if !c.eat(b'[') {
            return None;
        }
        let start = c.i;
        while c.peek().is_some_and(|b| b != b']') {
            c.i += 1;
        }
        let id = std::str::from_utf8(&c.s[start..c.i]).ok()?;
        if !c.eat(b']') || !c.done() {
            return None;
        }
        let region = ZoneId::of(id).ok()?;
        return Zoned::of_instant(instant, nanos, &region).ok();
    }
    None
}

const DAY_NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTH_NAMES: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

fn name_at(c: &mut Cursor, names: &[&str]) -> Option<usize> {
    let rest = &c.s[c.i..];
    let i = names.iter().position(|n| rest.len() >= 3 && rest[..3].eq_ignore_ascii_case(n.as_bytes()))?;
    c.i += 3;
    Some(i)
}

/// `StrictDateFormats.RFC_1123_STRICT`: `RFC_1123_DATE_TIME` (case insensitive, lenient numbers) with the STRICT
/// resolver, so an impossible date or a wrong day of the week fails.
fn parse_rfc1123(text: &str) -> Option<Zoned> {
    let mut c = Cursor { s: text.as_bytes(), i: 0 };
    let save = c.i;
    let mut dow = name_at(&mut c, &DAY_NAMES);
    if dow.is_some() && !(c.eat(b',') && c.eat(b' ')) {
        c.i = save;
        dow = None;
    }
    let day = c.digits(1, 9)?;
    if !c.eat(b' ') {
        return None;
    }
    let month = name_at(&mut c, &MONTH_NAMES)? as i64 + 1;
    if !c.eat(b' ') {
        return None;
    }
    let year = c.digits(1, 9)?;
    if !c.eat(b' ') {
        return None;
    }
    let hour = c.digits(1, 9)?;
    if !c.eat(b':') {
        return None;
    }
    let minute = c.digits(1, 9)?;
    let mut second = 0;
    let save = c.i;
    if c.eat(b':') {
        match c.digits(1, 9) {
            Some(s) => second = s,
            None => c.i = save,
        }
    }
    if !c.eat(b' ') {
        return None;
    }
    let offset = if c.eat_ci(b'G') {
        if !(c.eat_ci(b'M') && c.eat_ci(b'T')) {
            return None;
        }
        0
    } else {
        let sign = if c.eat(b'+') {
            1
        } else if c.eat(b'-') {
            -1
        } else {
            return None;
        };
        let h = c.digits(2, 2)?;
        c.eat(b':');
        let m = c.digits(2, 2).unwrap_or(0);
        if h > 18 || m > 59 {
            return None;
        }
        sign * (h * 3600 + m * 60) as i32
    };
    if !c.done() || !valid_date(year, month, day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let epoch_day = days_from_civil(year, month as u32, day as u32);
    if let Some(dow) = dow && (epoch_day + 3).rem_euclid(7) as usize != dow {
        return None;
    }
    let local = epoch_day * 86_400 + hour * 3600 + minute * 60 + second;
    Zoned::of_instant(local - offset as i64, 0, &ZoneId::of_offset_seconds(offset).ok()?).ok()
}

fn now_at(zone: &ZoneId) -> Res<Zoned> {
    let now = crate::clock::now_instant();
    Zoned::of_instant(now.epoch_second(), now.nano() as u32, zone)
}

// ---------------------------------------------------------------------------------------------------------------
// TemplateDate

/// `org.mockserver.templates.engine.helpers.TemplateDate`.
pub struct TemplateDate(Zoned);

fn date(z: Zoned) -> JValue {
    JValue::Object(Arc::new(TemplateDate(z)))
}

fn ok(v: JValue) -> Invocation {
    Some(Ok(Some(v)))
}

fn result(r: Res<JValue>) -> Invocation {
    Some(r.map(Some))
}

/// A `String` parameter: a string or null; anything else selects no method.
fn string_arg(v: &JValue) -> Option<Option<String>> {
    match v {
        JValue::Null => Some(None),
        JValue::Str(s) => Some(Some(s.to_string())),
        _ => None,
    }
}

/// A `long` parameter.
fn long_arg(v: &JValue) -> Option<i64> {
    match v {
        JValue::Byte(n) => Some(*n as i64),
        JValue::Short(n) => Some(*n as i64),
        JValue::Int(n) => Some(*n as i64),
        JValue::Long(n) => Some(*n),
        JValue::Float(f) => Some(*f as i64),
        JValue::Double(f) => Some(*f as i64),
        _ => None,
    }
}

impl TemplateDate {
    fn offset(&self, offset: Option<&str>) -> Res<Zoned> {
        let parsed = DateOffset::parse(offset).map_err(|e| illegal(format!("dates: {}", msg(&e))))?;
        parsed.add_to(&self.0).map_err(|e| {
            illegal(format!("dates: invalid date offset {}: {}", quote(offset.unwrap_or("")), brief(msg(&e))))
        })
    }

    fn truncate(&self, name: Option<&str>) -> Res<Zoned> {
        match name.and_then(Truncation::named) {
            Some(t) => Ok(self.0.truncate(t)),
            None => Err(illegal(format!("dates: unknown date truncation {}; use {TRUNCATION_NAMES}", quote(name.unwrap_or(""))))),
        }
    }

    fn with_zone(&self, name: Option<&str>) -> Res<Zoned> {
        self.0.with_zone_same_instant(&zone(name)?)
    }
}

impl JObject for TemplateDate {
    fn class_name(&self) -> String {
        "org.mockserver.templates.engine.helpers.TemplateDate".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        let z = &self.0;
        if let ([], Some(t)) = (args, Truncation::of_method(name)) {
            return ok(date(z.truncate(t)));
        }
        match (name, args) {
            ("plusSeconds", [n]) => result(z.plus_unit(long_arg(n)?, Unit::Seconds).map(date)),
            ("plusMinutes", [n]) => result(z.plus_unit(long_arg(n)?, Unit::Minutes).map(date)),
            ("plusHours", [n]) => result(z.plus_unit(long_arg(n)?, Unit::Hours).map(date)),
            ("plusDays", [n]) => result(z.plus_unit(long_arg(n)?, Unit::Days).map(date)),
            ("plusWeeks", [n]) => result(z.plus_unit(long_arg(n)?, Unit::Weeks).map(date)),
            ("plusMonths", [n]) => result(z.plus_unit(long_arg(n)?, Unit::Months).map(date)),
            ("plusYears", [n]) => result(z.plus_unit(long_arg(n)?, Unit::Years).map(date)),
            ("minusSeconds", [n]) => result(minus(z, long_arg(n)?, Unit::Seconds).map(date)),
            ("minusMinutes", [n]) => result(minus(z, long_arg(n)?, Unit::Minutes).map(date)),
            ("minusHours", [n]) => result(minus(z, long_arg(n)?, Unit::Hours).map(date)),
            ("minusDays", [n]) => result(minus(z, long_arg(n)?, Unit::Days).map(date)),
            ("minusWeeks", [n]) => result(minus(z, long_arg(n)?, Unit::Weeks).map(date)),
            ("minusMonths", [n]) => result(minus(z, long_arg(n)?, Unit::Months).map(date)),
            ("minusYears", [n]) => result(minus(z, long_arg(n)?, Unit::Years).map(date)),
            ("offset", [o]) => result(self.offset(string_arg(o)?.as_deref()).map(date)),
            ("truncate", [t]) => result(self.truncate(string_arg(t)?.as_deref()).map(date)),
            ("withZone", [zone]) => result(self.with_zone(string_arg(zone)?.as_deref()).map(date)),
            ("format", [p]) => result(z.format(string_arg(p)?.as_deref()).map(JValue::str)),
            ("iso" | "toString", []) => ok(JValue::str(z.iso())),
            ("rfc1123", []) => result(z.rfc1123().map(JValue::str)),
            ("epochSeconds", []) => ok(JValue::Long(z.epoch_second())),
            ("epochMillis", []) => result(z.epoch_millis().map(JValue::Long)),
            ("toInstant", []) => ok(JValue::Object(Arc::new(InstantValue(z.epoch_second(), z.local.nanos)))),
            ("isBefore", [other]) => result(parse(other, None, None).map(|o| JValue::Bool(instant_key(z) < instant_key(&o)))),
            ("isAfter", [other]) => result(parse(other, None, None).map(|o| JValue::Bool(instant_key(z) > instant_key(&o)))),
            ("equals", [other]) => ok(JValue::Bool(match other {
                JValue::Object(o) => o.as_any().downcast_ref::<TemplateDate>().is_some_and(|d| d.0 == self.0),
                _ => false,
            })),
            _ => None,
        }
    }

    fn to_java_string(&self) -> String {
        self.0.iso()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn instant_key(z: &Zoned) -> (i64, u32) {
    (z.epoch_second(), z.local.nanos)
}

/// `minusX(n)`: `n == Long.MIN_VALUE` is `plusX(Long.MAX_VALUE).plusX(1)`.
fn minus(z: &Zoned, n: i64, unit: Unit) -> Res<Zoned> {
    match n.checked_neg() {
        Some(neg) => z.plus_unit(neg, unit),
        None => z.plus_unit(i64::MAX, unit)?.plus_unit(1, unit),
    }
}

/// `java.time.Instant`, as `TemplateDate.toInstant()` returns it.
struct InstantValue(i64, u32);

impl JObject for InstantValue {
    fn class_name(&self) -> String {
        "java.time.Instant".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        match (name, args) {
            ("getEpochSecond", []) => ok(JValue::Long(self.0)),
            ("getNano", []) => ok(JValue::Int(self.1 as i32)),
            ("toEpochMilli", []) => result(Instant::of_epoch_second(self.0, self.1 as i64).expect("in range").to_epoch_milli().map(JValue::Long).map_err(java_error)),
            ("toString", []) => ok(JValue::str(iso_instant(self.0, self.1))),
            _ => None,
        }
    }

    fn to_java_string(&self) -> String {
        iso_instant(self.0, self.1)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ---------------------------------------------------------------------------------------------------------------
// DateTemplateHelper

/// `DateTemplateHelper.toString()`: now, `ISO_INSTANT`.
pub fn now_iso() -> String {
    let now = crate::clock::now_instant();
    iso_instant(now.epoch_second(), now.nano() as u32)
}

/// The methods of `DateTemplateHelper` that take a date, a zone or return a `TemplateDate` (`None` for the
/// others, which `functions.rs` answers).
pub fn helper(name: &str, args: &[JValue]) -> Invocation {
    let utc_now = || now_at(&utc());
    match (name, args) {
        ("format", [p]) => {
            let p = string_arg(p)?;
            result(utc_now().and_then(|now| now.format(p.as_deref())).map(JValue::str))
        }
        ("format", [d, p]) => {
            let p = string_arg(p)?;
            result(parse(d, None, None).and_then(|z| z.format(p.as_deref())).map(JValue::str))
        }
        ("format", [d, p, zone]) => {
            let (p, zone) = (string_arg(p)?, string_arg(zone)?);
            result(parse(d, None, None).and_then(|z| TemplateDate(z).with_zone(zone.as_deref())).and_then(|z| z.format(p.as_deref())).map(JValue::str))
        }
        ("now", []) => result(utc_now().map(date)),
        ("now", [zone]) => {
            let zone = string_arg(zone)?;
            result(self::zone(zone.as_deref()).and_then(|z| now_at(&z)).map(date))
        }
        ("parse", [d]) => result(parse(d, None, None).map(date)),
        ("parse", [d, p]) => {
            let p = string_arg(p)?;
            result(parse(d, p.as_deref(), None).map(date))
        }
        ("parse", [d, p, zone]) => {
            let (p, zone) = (string_arg(p)?, string_arg(zone)?);
            result(parse(d, p.as_deref(), zone.as_deref()).map(date))
        }
        ("offset", [d, o]) => {
            let o = string_arg(o)?;
            result(parse(d, None, None).and_then(|z| TemplateDate(z).offset(o.as_deref())).map(date))
        }
        ("truncate", [d, t]) => {
            let t = string_arg(t)?;
            result(parse(d, None, None).and_then(|z| TemplateDate(z).truncate(t.as_deref())).map(date))
        }
        ("withZone", [d, zone]) => {
            let zone = string_arg(zone)?;
            result(parse(d, None, None).and_then(|z| TemplateDate(z).with_zone(zone.as_deref())).map(date))
        }
        ("rfc1123", []) => result(utc_now().and_then(|z| z.rfc1123()).map(JValue::str)),
        ("rfc1123", [d]) => result(parse(d, None, None).and_then(|z| z.rfc1123()).map(JValue::str)),
        ("epochSeconds", [d]) => result(parse(d, None, None).map(|z| JValue::Long(z.epoch_second()))),
        ("epochMillis", [d]) => result(parse(d, None, None).and_then(|z| z.epoch_millis()).map(JValue::Long)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// MustacheDateTemplateHelper

/// `MustacheDateTemplateHelper`: `DateTemplateHelper` plus the `render` section lambda.
pub struct MustacheDates;

impl JObject for MustacheDates {
    fn class_name(&self) -> String {
        "org.mockserver.templates.engine.mustache.MustacheDateTemplateHelper".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Invocation {
        match (name, args) {
            ("render", []) => ok(Lambda::object(RENDER_CLASS, Arc::new(Render))),
            ("toString", []) => ok(JValue::str(now_iso())),
            _ => crate::templates::functions::dates_helper(name, args),
        }
    }

    fn to_java_string(&self) -> String {
        now_iso()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// The synthetic class of the `RENDER` lambda (its `toString()` is otherwise unreproducible).
const RENDER_CLASS: &str = "org.mockserver.templates.engine.mustache.MustacheDateTemplateHelper$$Lambda/0x00007f3c8c0e2c40";

struct Render;

impl LambdaFn for Render {
    fn execute(&self, frag: &Fragment, out: &mut String) -> Result<(), MustacheError> {
        let spec = frag.execute()?;
        let parts = frag.decompile().matches('|').count() + 1;
        out.push_str(&render(&spec, parts).map_err(MustacheError::Java)?);
        Ok(())
    }
}

fn option_key(option: &str) -> Res<String> {
    match option.find('=') {
        None => Err(illegal(format!("dates.render: option \"{}\" has no value; write it as name=value, such as offset=1 days", java_trim(option)))),
        Some(i) => Ok(java_trim(&option[..i]).to_lowercase()),
    }
}

fn option_value(option: &str) -> &str {
    java_trim(&option[option.find('=').map_or(0, |i| i + 1)..])
}

/// `MustacheDateTemplateHelper.render(spec, templateParts)`.
fn render(spec: &str, template_parts: usize) -> Res<String> {
    let parts: Vec<&str> = spec.split('|').collect();
    if parts.len() != template_parts {
        return Err(illegal(
            "dates.render: a value inside the section contains |, which separates the date from its options; render only the date or an option value from request data, and make sure it has no |",
        ));
    }
    let mut pattern = None;
    let mut read_zone = None;
    for part in &parts[1..] {
        let key = option_key(part)?;
        if key == "pattern" {
            pattern = Some(option_value(part));
        } else if read_zone.is_none() && (key == "zone" || key == "timezone") {
            read_zone = Some(option_value(part));
        }
    }
    let mut d = TemplateDate(parse(&JValue::str(java_trim(parts[0])), pattern, read_zone)?);
    for (i, part) in parts.iter().enumerate().skip(1) {
        let key = option_key(part)?;
        let value = option_value(part);
        match key.as_str() {
            "pattern" => {}
            "zone" | "timezone" => d = TemplateDate(d.with_zone(Some(value))?),
            "offset" => d = TemplateDate(d.offset(Some(value))?),
            "truncate" => d = TemplateDate(d.truncate(Some(value))?),
            "format" => {
                if i != parts.len() - 1 {
                    return Err(illegal(format!("dates.render: format must be the last option in \"{spec}\"")));
                }
                return d.0.format(Some(value));
            }
            _ => {
                return Err(illegal(format!(
                    "dates.render: unknown option \"{}\" in \"{spec}\"; use pattern=, zone=, offset=, truncate= or format=",
                    java_trim(part)
                )));
            }
        }
    }
    Ok(d.0.iso())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Zoned {
        parse(&JValue::str(s), None, None).unwrap()
    }

    #[test]
    fn reads_and_writes_iso_and_rfc1123() {
        assert_eq!(p("2026-10-21T15:04:05Z").iso(), "2026-10-21T15:04:05Z");
        assert_eq!(p("2026-10-21T16:04:05+01:00").iso(), "2026-10-21T16:04:05+01:00");
        assert_eq!(p("2026-10-21").iso(), "2026-10-21T00:00:00Z");
        assert_eq!(p("Wed, 21 Oct 2026 15:04:05 GMT").rfc1123().unwrap(), "Wed, 21 Oct 2026 15:04:05 GMT");
        assert!(parse_rfc1123("Mon, 21 Oct 2026 15:04:05 GMT").is_none());
        assert_eq!(p("1792595045").epoch_second(), 1_792_595_045);
    }

    #[test]
    fn offsets_and_truncations() {
        let z = p("2026-01-31T00:00:00Z");
        assert_eq!(TemplateDate(z).offset(Some("1 months")).unwrap().iso(), "2026-02-28T00:00:00Z");
        let z = p("2026-03-15T10:00:00Z");
        assert_eq!(z.truncate(Truncation::FirstDayOfMonth).iso(), "2026-03-01T00:00:00Z");
        let london = zone(Some("Europe/London")).unwrap();
        let z = p("2026-10-21T15:04:05Z").with_zone_same_instant(&london).unwrap();
        assert_eq!(z.format(Some("HH:mm")).unwrap(), "16:04");
    }

    #[test]
    fn mustache_render_options() {
        assert_eq!(render("2026-10-21T15:04:05Z|offset=1 days|format=yyyy-MM-dd", 3).unwrap(), "2026-10-22");
        assert_eq!(render("21/10/2026 16:04|pattern=dd/MM/yyyy HH:mm|zone=Europe/London", 3).unwrap(), "2026-10-21T16:04:00+01:00");
        assert_eq!(render("2026-03-15T10:00:00Z|offset=1 months|truncate=lastDayOfMonth", 3).unwrap(), "2026-04-30T00:00:00Z");
    }
}

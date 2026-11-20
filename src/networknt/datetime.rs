//! The date and time parsers networknt's formats use: `LocalDate.parse` (ISO_LOCAL_DATE), ethlo's
//! `ITU.parseDateTime` (RFC 3339 with its leap-second table) and `TimeFormat`'s `DateTimeFormatter`.

/// `LocalDate.parse(value)`: `(year, month, day)` of an ISO local date (a four-digit year, or a signed longer one).
pub fn local_date(value: &str) -> Option<(i64, u32, u32)> {
    let (year_text, rest) = split_year(value)?;
    let year: i64 = year_text.parse().ok()?;
    let rest = rest.strip_prefix('-')?;
    let (month, rest) = two_digits(rest)?;
    let rest = rest.strip_prefix('-')?;
    let (day, rest) = two_digits(rest)?;
    if !rest.is_empty() || !valid_date(year, month, day) {
        return None;
    }
    Some((year, month, day))
}

/// `SignStyle.EXCEEDS_PAD` for a 4-digit year: four digits unsigned, more only with a sign.
fn split_year(value: &str) -> Option<(&str, &str)> {
    let signed = value.starts_with(['+', '-']);
    let start = usize::from(signed);
    let digits = value[start..].chars().take_while(char::is_ascii_digit).count();
    if !(4..=10).contains(&digits) || (!signed && digits > 4) || (value.starts_with('+') && digits == 4) {
        return None;
    }
    Some((&value[..start + digits], &value[start + digits..]))
}

fn two_digits(s: &str) -> Option<(u32, &str)> {
    let d = s.get(..2)?;
    if !d.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((d.parse().ok()?, &s[2..]))
}

fn leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn valid_date(year: i64, month: u32, day: u32) -> bool {
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap(year) => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

/// The months ethlo's `leap_second_dates.csv` lists (`DefaultLeapSecondHandler`).
const LEAP_SECOND_MONTHS: &[(i64, u32)] = &[
    (1971, 12), (1972, 6), (1972, 12), (1973, 12), (1974, 12), (1975, 12), (1976, 12), (1977, 12), (1978, 12), (1989, 12),
    (1981, 6), (1982, 6), (1983, 6), (1985, 6), (1988, 12), (1989, 12), (1990, 12), (1992, 6), (1993, 6), (1994, 6),
    (1995, 12), (1997, 6), (1998, 12), (2005, 12), (2008, 12), (2012, 6), (2015, 6), (2016, 12),
];

/// `DateTimeFormat.Ethlo.isValid`: `ITU.parseDateTime` succeeds, or fails only on a leap second in a listed month.
pub fn itu_date_time(s: &str) -> bool {
    let b: Vec<char> = s.chars().collect();
    let digits = |from: usize, to: usize| -> Option<i64> {
        let mut v = 0i64;
        for i in from..to {
            let c = *b.get(i)?;
            v = v * 10 + i64::from(c.to_digit(10)?);
        }
        Some(v)
    };
    let len = b.len();
    // `parseLenient`: year, month, day, separator, hour, minute — then seconds, fraction and the offset.
    let Some(year) = digits(0, 4) else { return false };
    if len == 4 || b.get(4) != Some(&'-') {
        return false;
    }
    let Some(month) = digits(5, 7) else { return false };
    if len == 7 || b.get(7) != Some(&'-') {
        return false;
    }
    let Some(day) = digits(8, 10) else { return false };
    if len == 10 || !matches!(b.get(10), Some('T' | 't' | ' ')) {
        return false;
    }
    let Some(hour) = digits(11, 13) else { return false };
    if b.get(13) != Some(&':') {
        return false;
    }
    let Some(minute) = digits(14, 16) else { return false };
    if len == 16 {
        return false; // no seconds: `parseDateTime` needs them
    }
    // `handleTime`: seconds follow, or an offset at minute resolution (still too coarse for `parseDateTime`).
    if b[16] != ':' {
        return false;
    }
    if len < 19 {
        return false;
    }
    let Some(second) = digits(17, 19) else { return false };
    if len == 19 {
        return false; // no offset
    }
    let mut idx = 19;
    let mut nanos = 0i64;
    if b[19] == '.' {
        idx = 20;
        let mut count = 0;
        while idx < len && b[idx].is_ascii_digit() {
            count += 1;
            nanos = nanos * 10 + i64::from(b[idx].to_digit(10).unwrap_or(0));
            idx += 1;
        }
        if count == 0 || count > 9 {
            return false;
        }
    }
    let _ = nanos;
    // `parseTimezone`.
    if idx >= len {
        return false;
    }
    let offset_minutes = match b[idx] {
        'Z' | 'z' => {
            if len > idx + 1 {
                return false;
            }
            0
        }
        sign @ ('+' | '-') => {
            if len - idx < 6 {
                return false;
            }
            // The separator between hours and minutes is not checked.
            let (Some(h), Some(m)) = (digits(idx + 1, idx + 3), digits(idx + 4, idx + 6)) else { return false };
            if sign == '-' && h == 0 && m == 0 {
                return false;
            }
            if len > idx + 6 {
                return false;
            }
            // `ZoneOffset.ofHoursMinutes`.
            if h > 18 || m > 59 || (h == 18 && m > 0) {
                return false;
            }
            if sign == '-' { -(h * 60 + m) } else { h * 60 + m }
        }
        _ => return false,
    };
    // `DateTime` constructor: the leap-second check, then `LocalDate.of` and the second's range.
    if second == 60 {
        let listed = LEAP_SECOND_MONTHS.contains(&(year, month as u32));
        let after_last = (year, month as u32) > (2016, 12);
        if listed || after_last {
            let utc_hour = hour - offset_minutes * 60 / 3600;
            let utc_minute = minute - (offset_minutes * 60) % 3600 / 60;
            if ((month == 12 && day == 31) || (month == 6 && day == 30)) && utc_hour == 23 && utc_minute == 59 {
                return listed;
            }
        }
    }
    if !(1..=12).contains(&month) || !valid_date(year, month as u32, day as u32) || second > 59 {
        return false;
    }
    // `OffsetDateTime.of`.
    hour <= 23 && minute <= 59
}

/// `TimeFormat.matches`: `HH:mm:ss[.fraction]` then `Z` or `+HH:MM` (case-insensitive), with a leap second allowed
/// only at 23:59:60 UTC. Trailing text after a complete time is not checked (`parseUnresolved`).
pub fn time(value: &str) -> bool {
    if let Some(pos) = value.find('Z')
        && pos != value.len() - 1
    {
        return false;
    }
    let b: Vec<char> = value.chars().collect();
    let digits = |from: usize| -> Option<i64> {
        let (a, c) = (b.get(from)?.to_digit(10)?, b.get(from + 1)?.to_digit(10)?);
        Some(i64::from(a * 10 + c))
    };
    let (Some(hour), Some(minute)) = (digits(0), digits(3)) else { return false };
    if b.get(2) != Some(&':') || b.get(5) != Some(&':') {
        return false;
    }
    let Some(second) = digits(6) else { return false };
    let mut idx = 8;
    if b.get(idx) == Some(&'.') {
        idx += 1;
        let mut count = 0;
        while count < 9 && b.get(idx).is_some_and(char::is_ascii_digit) {
            idx += 1;
            count += 1;
        }
    }
    let offset = match b.get(idx) {
        Some('Z' | 'z') => 0,
        Some(sign @ ('+' | '-')) => {
            let (Some(h), Some(m)) = (digits(idx + 1), digits(idx + 4)) else { return false };
            if b.get(idx + 3) != Some(&':') || h > 23 || m > 59 {
                return false;
            }
            if *sign == '-' { -(h * 60 + m) } else { h * 60 + m }
        }
        _ => return false,
    };
    if !(-1439..=1439).contains(&offset) {
        return false;
    }
    if second <= 59 && minute <= 59 && hour <= 23 {
        return true;
    }
    let mut hr = hour - offset / 60;
    let mut min = minute - offset % 60;
    if min < 0 {
        hr -= 1;
        min += 60;
    }
    if hr < 0 {
        hr += 24;
    }
    second == 60 && min == 59 && hr == 23
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethlo_date_times() {
        for ok in ["2020-01-01T00:00:00Z", "2020-01-01t00:00:00z", "2020-01-01 00:00:00Z", "2016-12-31T23:59:60Z", "2020-01-01T00:00:00+01:00", "2015-06-30T23:59:60Z", "1990-12-31T15:59:60-08:00"] {
            assert!(itu_date_time(ok), "{ok}");
        }
        for bad in ["2020-02-30T00:00:00Z", "2020-01-01T00:00:00.1234567891Z", "2020-01-01T00:00:00", "2020-01-01T24:00:00Z", "2020-06-30T23:59:60Z", "2020-01-01T00:00:00.Z", "20200101T000000Z", "2020-1-01T00:00:00Z"] {
            assert!(!itu_date_time(bad), "{bad}");
        }
    }

    #[test]
    fn local_times() {
        for ok in ["12:00:00Z", "23:59:60Z", "12:00:00.123+01:00", "15:59:60-08:00", "12:00:00z"] {
            assert!(time(ok), "{ok}");
        }
        for bad in ["12:00:00", "12:00:00+25:00", "12:00Z", "23:59:60+01:00", "1:00:00Z", "12:00:00Zx"] {
            assert!(!time(bad), "{bad}");
        }
    }
}

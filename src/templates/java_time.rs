//! The bits of `java.text.DecimalFormat` and `java.math.BigDecimal` the template helpers expose
//! (`calc.format(value, pattern)`, `calc.round(value, scale)`); dates are in `dates.rs`.

use java_compat::lang::JError;

fn illegal(message: impl Into<String>) -> JError {
    JError::new("java.lang.IllegalArgumentException", message)
}

/// Decimal digits and exponent of a plain or scientific decimal literal (`123.45`, `1.0E-7`): (negative, digits,
/// position of the decimal point in `digits`).
fn decimal_parts(text: &str) -> (bool, Vec<u8>, i64) {
    let (negative, text) = match text.strip_prefix('-') {
        Some(t) => (true, t),
        None => (false, text),
    };
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i64>().unwrap_or(0)),
        None => (text, 0),
    };
    let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits: Vec<u8> = int.bytes().chain(frac.bytes()).map(|b| b - b'0').collect();
    (negative, digits, int.len() as i64 + exponent)
}

/// `new BigDecimal(text).setScale(scale, RoundingMode.HALF_UP).toPlainString()`.
pub fn round_half_up(text: &str, scale: i64) -> String {
    let (negative, mut digits, mut point) = decimal_parts(text);
    // Pad so that the point is inside the digits and `scale` fraction digits exist.
    while point < 1 {
        digits.insert(0, 0);
        point += 1;
    }
    let keep = (point + scale).max(0) as usize;
    while digits.len() < keep + 1 {
        digits.push(0);
    }
    let round_up = digits[keep] >= 5;
    digits.truncate(keep);
    if round_up {
        let mut i = digits.len();
        loop {
            if i == 0 {
                digits.insert(0, 1);
                point += 1;
                break;
            }
            i -= 1;
            if digits[i] == 9 {
                digits[i] = 0;
            } else {
                digits[i] += 1;
                break;
            }
        }
    }
    let int: String = digits[..point as usize].iter().map(|d| (d + b'0') as char).collect();
    let int = match int.trim_start_matches('0') {
        "" => "0".to_string(),
        s => s.to_string(),
    };
    let frac: String = digits[point as usize..].iter().map(|d| (d + b'0') as char).collect();
    let sign = if negative && (int != "0" || frac.chars().any(|c| c != '0')) { "-" } else { "" };
    if scale > 0 { format!("{sign}{int}.{frac}") } else { format!("{sign}{int}") }
}

/// `new DecimalFormat(pattern).format(value)` for the common pattern syntax: `0`/`#` digits, `,` grouping, `.`,
/// `%` / `‰`, `E` exponent, quoted and plain literals; HALF_EVEN rounding.
pub fn decimal_format(value: f64, pattern: &str) -> Result<String, JError> {
    let positive = pattern.split(';').next().unwrap_or("");
    let chars: Vec<char> = positive.chars().collect();
    let is_pattern_char = |c: char| matches!(c, '0' | '#' | ',' | '.' | 'E');
    let mut prefix = String::new();
    let mut i = 0;
    let mut multiplier = 1.0;
    let literal = |i: &mut usize, out: &mut String, multiplier: &mut f64| {
        let c = chars[*i];
        if c == '\'' {
            let mut j = *i + 1;
            while j < chars.len() && chars[j] != '\'' {
                out.push(chars[j]);
                j += 1;
            }
            if j == *i + 1 {
                out.push('\'');
            }
            *i = j + 1;
        } else {
            match c {
                '%' => *multiplier = 100.0,
                '\u{2030}' => *multiplier = 1000.0,
                _ => {}
            }
            out.push(c);
            *i += 1;
        }
    };
    while i < chars.len() && !is_pattern_char(chars[i]) {
        literal(&mut i, &mut prefix, &mut multiplier);
    }
    let start = i;
    while i < chars.len() && is_pattern_char(chars[i]) {
        i += 1;
    }
    let number: String = chars[start..i].iter().collect();
    let mut suffix = String::new();
    while i < chars.len() {
        literal(&mut i, &mut suffix, &mut multiplier);
    }
    if number.is_empty() {
        return Err(illegal(format!("Malformed pattern \"{pattern}\"")));
    }
    let (mantissa_pattern, exponent_pattern) = match number.split_once('E') {
        Some((m, e)) => (m.to_string(), Some(e.to_string())),
        None => (number.clone(), None),
    };
    let (int_pattern, frac_pattern) = mantissa_pattern.split_once('.').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((mantissa_pattern.clone(), String::new()));
    let grouping = int_pattern.rfind(',').map(|p| int_pattern.len() - p - 1).filter(|g| *g > 0);
    let min_int = int_pattern.chars().filter(|c| *c == '0').count();
    let min_frac = frac_pattern.chars().filter(|c| *c == '0').count();
    let max_frac = frac_pattern.chars().filter(|c| matches!(c, '0' | '#')).count();

    if value.is_nan() {
        return Ok(format!("{prefix}\u{fffd}{suffix}"));
    }
    let negative = value.is_sign_negative() && value != 0.0;
    let v = (value * multiplier).abs();
    if v.is_infinite() {
        return Ok(format!("{}{prefix}\u{221e}{suffix}", if negative { "-" } else { "" }));
    }
    let (body, exponent) = match &exponent_pattern {
        Some(e) => {
            let min_exp = e.chars().filter(|c| *c == '0').count();
            let exp = if v == 0.0 { 0 } else { v.log10().floor() as i32 - (min_int.max(1) as i32 - 1) };
            let scaled = v / 10f64.powi(exp);
            (fixed(scaled, min_frac, max_frac), Some(format!("E{}{:0width$}", if exp < 0 { "-" } else { "" }, exp.abs(), width = min_exp)))
        }
        None => (fixed(v, min_frac, max_frac), None),
    };
    let (int_digits, frac_digits) = body.split_once('.').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((body.clone(), String::new()));
    let mut int_digits = int_digits.trim_start_matches('0').to_string();
    while int_digits.len() < min_int {
        int_digits.insert(0, '0');
    }
    if let Some(g) = grouping {
        let mut grouped = String::new();
        for (k, ch) in int_digits.chars().enumerate() {
            if k > 0 && (int_digits.len() - k) % g == 0 {
                grouped.push(',');
            }
            grouped.push(ch);
        }
        int_digits = grouped;
    }
    let mut out = String::new();
    let is_zero = int_digits.chars().all(|c| c == '0' || c == ',') && frac_digits.chars().all(|c| c == '0');
    if negative && !is_zero {
        out.push('-');
    }
    out.push_str(&prefix);
    out.push_str(&int_digits);
    if !frac_digits.is_empty() {
        out.push('.');
        out.push_str(&frac_digits);
    }
    if let Some(e) = exponent {
        out.push_str(&e);
    }
    out.push_str(&suffix);
    Ok(out)
}

/// `v` with `max` fraction digits (HALF_EVEN on the exact binary value), trailing zeros trimmed down to `min`.
fn fixed(v: f64, min: usize, max: usize) -> String {
    let s = format!("{v:.max$}");
    let Some((int, frac)) = s.split_once('.') else { return s };
    let mut frac = frac.to_string();
    while frac.len() > min && frac.ends_with('0') {
        frac.pop();
    }
    if frac.is_empty() { int.to_string() } else { format!("{int}.{frac}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_format_patterns() {
        assert_eq!(decimal_format(1234.5678, "#,##0.00").unwrap(), "1,234.57");
        assert_eq!(decimal_format(0.5, "#.##").unwrap(), ".5");
        assert_eq!(decimal_format(0.5, "0.00").unwrap(), "0.50");
        assert_eq!(decimal_format(0.256, "#%").unwrap(), "26%");
        assert_eq!(decimal_format(-3.0, "0.#").unwrap(), "-3");
    }

    #[test]
    fn big_decimal_half_up() {
        assert_eq!(round_half_up("2.345", 2), "2.35");
        assert_eq!(round_half_up("2.344", 2), "2.34");
        assert_eq!(round_half_up("9.995", 2), "10.00");
        assert_eq!(round_half_up("1.0E-7", 3), "0.000");
        assert_eq!(round_half_up("-1.5", 0), "-2");
    }
}

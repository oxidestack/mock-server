//! The webhook's log, as upstream's runnable jar writes it: slf4j through `slf4j-jdk14` to java.util.logging's
//! default `ConsoleHandler` (stderr, level INFO, so slf4j `debug` is never printed) and `SimpleFormatter`:
//!
//! ```text
//! Oct 11, 2026 3:04:05 PM org.mockserver.webhook.WebhookServer start
//! INFO: webhook server started on 0:0:0:0:0:0:0:0:8443
//! ```
//!
//! Times are UTC (the images carry no time zone). A logged exception prints as `printStackTrace` would, without
//! the `\tat` frames (and, as in Java, followed by an empty line).

use crate::java::JavaException;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SILENT: AtomicBool = AtomicBool::new(false);

/// Stops all logging (in-process tests).
pub fn silence() {
    SILENT.store(true, Ordering::Relaxed);
}

pub fn info(class: &str, method: &str, message: &str) {
    write("INFO", class, method, message, None);
}

pub fn warn_thrown(class: &str, method: &str, message: &str, thrown: &JavaException) {
    write("WARNING", class, method, message, Some(thrown));
}

pub fn error_thrown(class: &str, method: &str, message: &str, thrown: &JavaException) {
    write("SEVERE", class, method, message, Some(thrown));
}

fn write(level: &str, class: &str, method: &str, message: &str, thrown: Option<&JavaException>) {
    if SILENT.load(Ordering::Relaxed) {
        return;
    }
    let millis = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
    let mut line = format!("{} {class} {method}\n{level}: {message}", timestamp(millis));
    if let Some(t) = thrown {
        // `%6$s` is a newline and the stack trace, whose lines each end in a newline
        line.push('\n');
        line.push_str(&t.stack_trace());
        line.push('\n');
    }
    line.push('\n');
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// `%1$tb %1$td, %1$tY %1$tl:%1$tM:%1$tS %1$Tp` in UTC, English locale.
pub fn timestamp(millis: i64) -> String {
    let secs = millis.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    let (hour, minute, second) = (rem / 3600, rem % 3600 / 60, rem % 60);
    let hour12 = if hour % 12 == 0 { 12 } else { hour % 12 };
    let ampm = if hour < 12 { "AM" } else { "PM" };
    format!("{} {d:02}, {y} {hour12}:{minute:02}:{second:02} {ampm}", MONTHS[(m - 1) as usize])
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d)
}

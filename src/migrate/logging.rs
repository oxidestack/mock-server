//! Logging files: `logging.properties`, `logback*.xml` and `log4j2*.xml`. The files have no
//! effect (the console layout is fixed); a level set on `org.mockserver` maps to `MOCKSERVER_LOG_LEVEL`, which the
//! `-Djava.util.logging.config.file=` token that names the file is rewritten to (see [`super::rules::jvm_option`]).

use std::sync::LazyLock;

use super::rules;
use super::{Finding, Severity};

static XML_LOGGER: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?i)<logger\b[^>]*>").unwrap());
static ATTRIBUTE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r#"(?i)\b(name|level)\s*=\s*"([^"]*)""#).unwrap());
static XML_APPENDERS: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?i)<appenders?\b").unwrap());

/// Whether a file name is a logging configuration file.
pub fn is_logging_file(name: &str) -> bool {
    name == "logging.properties" || ((name.starts_with("logback") || name.starts_with("log4j2")) && name.ends_with(".xml"))
}

/// One logger setting: its line, the logger name and the level as written.
fn loggers(name: &str, text: &str) -> Vec<(usize, String, String)> {
    if name.ends_with(".properties") {
        text.lines()
            .enumerate()
            .filter_map(|(n, line)| {
                let line = line.trim();
                let (key, value) = line.split_once(['=', ':'])?;
                let logger = key.trim().strip_suffix(".level")?;
                (!line.starts_with('#') && !line.starts_with('!')).then(|| (n + 1, logger.to_string(), value.trim().to_string()))
            })
            .collect()
    } else {
        XML_LOGGER
            .find_iter(text)
            .filter_map(|m| {
                let mut logger = None;
                let mut level = None;
                for c in ATTRIBUTE.captures_iter(m.as_str()) {
                    match c[1].to_ascii_lowercase().as_str() {
                        "name" => logger = Some(c[2].to_string()),
                        _ => level = Some(c[2].to_string()),
                    }
                }
                Some((super::line_of(text, m.start()), logger?, level?))
            })
            .collect()
    }
}

/// The level a logging file sets for `org.mockserver`, in MockServer's names.
pub fn mockserver_level(name: &str, text: &str) -> Option<String> {
    loggers(name, text).into_iter().find(|(_, logger, _)| logger == "org.mockserver").and_then(|(_, _, level)| rules::log_level(&level)).map(String::from)
}

/// The findings of one logging file.
pub fn scan(name: &str, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (line, logger, level) in loggers(name, text) {
        if logger == "org.mockserver" {
            let finding = match rules::log_level(&level) {
                Some(mapped) => Finding::new(rules::LOGGING_FILE, Severity::Warn, line, format!("{logger} level {level}"), "the file has no effect: set the level in the environment instead").replacement(format!("MOCKSERVER_LOG_LEVEL={mapped}")),
                None => Finding::new(rules::LOGGING_FILE, Severity::Warn, line, format!("{logger} level {level}"), "the file has no effect, and the level has no MockServer name"),
            };
            findings.push(finding.key(logger));
        } else if logger.starts_with("org.mockserver.") {
            findings.push(Finding::new(rules::LOGGING_FILE, Severity::Warn, line, format!("{logger} level {level}"), "per-class levels have no counterpart: logLevelOverrides sets levels per log message type").key(logger));
        }
    }
    if name.ends_with(".properties") {
        for (n, line) in text.lines().enumerate() {
            let key = line.split(['=', ':']).next().unwrap_or("").trim();
            if !line.trim_start().starts_with('#') && (key == "handlers" || key.ends_with(".formatter") || key.ends_with(".format") || key.ends_with(".pattern")) {
                findings.push(Finding::new(rules::LOGGING_FILE, Severity::Warn, n + 1, key, "handlers and formats have no counterpart: the console layout is fixed").key(key));
            }
        }
    } else {
        for m in XML_APPENDERS.find_iter(text) {
            findings.push(Finding::new(rules::LOGGING_FILE, Severity::Warn, super::line_of(text, m.start()), m.as_str().trim_start_matches('<'), "appenders and layouts have no counterpart: the console layout is fixed"));
        }
    }
    findings.sort_by_key(|f| f.line);
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jul_properties() {
        let text = "handlers=java.util.logging.ConsoleHandler\njava.util.logging.ConsoleHandler.formatter=java.util.logging.SimpleFormatter\n.level=INFO\norg.mockserver.level = FINE\norg.mockserver.mock.level=FINEST\n# org.mockserver.level=OFF\n";
        assert_eq!(mockserver_level("logging.properties", text).as_deref(), Some("DEBUG"));
        let found: Vec<(usize, Option<String>)> = scan("logging.properties", text).into_iter().map(|f| (f.line, f.replacement)).collect();
        assert_eq!(found, [(1, None), (2, None), (4, Some("MOCKSERVER_LOG_LEVEL=DEBUG".into())), (5, None)]);
    }

    #[test]
    fn logback_and_log4j2() {
        let logback = "<configuration>\n  <appender name=\"STDOUT\" class=\"ch.qos.logback.core.ConsoleAppender\"/>\n  <logger level=\"warn\" name=\"org.mockserver\"/>\n</configuration>\n";
        assert_eq!(mockserver_level("logback.xml", logback).as_deref(), Some("WARN"));
        assert_eq!(scan("logback.xml", logback).len(), 2);
        let log4j2 = "<Configuration>\n  <Appenders><Console name=\"c\"/></Appenders>\n  <Loggers><Logger name=\"org.mockserver\" level=\"error\"/></Loggers>\n</Configuration>\n";
        assert_eq!(mockserver_level("log4j2.xml", log4j2).as_deref(), Some("ERROR"));
        assert!(is_logging_file("logback-test.xml") && is_logging_file("log4j2.xml") && !is_logging_file("pom.xml"));
    }
}

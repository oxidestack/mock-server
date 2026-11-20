//! The properties file and its startup log entries.
//!
//! `ConfigurationProperties.<clinit>` loads the file and logs through `LogEntry.setAlwaysLog(true)`, which makes
//! `MockServerLogger.logEvent` and `writeToSystemOut` skip the log-level gate and `logLevelOverrides`. These are the
//! only `setAlwaysLog(true)` sites in MockServer 8.0.0 (they all sit in that class), and they run before any server
//! exists, so they reach the console and never the event log or the dashboard. What still gates them (all checked
//! against the oracle):
//!
//! * an unreadable file the operator named (`WARN`) and a failed read (`ERROR`): nothing, they print even at `OFF`;
//! * the `Reading properties from property file [..]` dump (`INFO`): `isEnabled(INFO, level)` for the level the
//!   property cache holds at that moment;
//! * the `unrecognised MockServer configuration ..` warnings (`WARN`): the `java.util.logging` level that
//!   `MockServerLogger.configureLogger` has set from that same level, so they vanish at `ERROR` and `OFF`.
//!
//! The level in the cache is the one `readPropertyHierarchically` resolved before the file's own properties were
//! available: the file lookup on the classpath misses and the `DEBUG` check that follows reads `logLevel` with no
//! properties yet. So a `.properties` file's `mockserver.logLevel` is never honoured (system property, then
//! `MOCKSERVER_LOG_LEVEL`, then `INFO`), whereas a `.json` file, which skips that check, supplies it (system
//! property, then file, then environment).

use std::collections::HashMap;

use crate::recorded::Level;

/// One console line logged while the configuration loads.
#[derive(Debug, Clone)]
pub struct StartupNotice {
    pub level: Level,
    pub message: String,
    /// The throwable's text, printed after the message.
    pub throwable: Option<String>,
}

/// The file's entries in the order `Properties.load` put them in, and how it was read.
#[derive(Debug, Clone, Default)]
pub struct LoadedFile {
    pub entries: Vec<(String, String)>,
    pub notices: Vec<StartupNotice>,
}

/// `String.hashCode`.
fn string_hash(s: &str) -> i32 {
    s.encode_utf16().fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(i32::from(c)))
}

/// The order `Properties.propertyNames()` enumerates `entries`: the `ConcurrentHashMap` (16 slots, doubling when the
/// load reaches 0.75) the file was loaded into is walked slot by slot into a default `Hashtable`
/// (11 slots, `2n+1` when the count reaches the threshold, new entries at the head of a chain), whose `keys()` walks the
/// slots from the last. Past 11 entries the order inside a `ConcurrentHashMap` slot after a resize is not modelled.
pub fn property_names_order(entries: &[(String, String)]) -> Vec<(String, String)> {
    let mut table = 16usize;
    while entries.len() * 4 >= table * 3 {
        table *= 2;
    }
    let mut walk: Vec<(usize, usize)> = entries
        .iter()
        .enumerate()
        .map(|(i, (k, _))| {
            let h = string_hash(k) as u32;
            (((h ^ (h >> 16)) & 0x7fff_ffff) as usize & (table - 1), i)
        })
        .collect();
    walk.sort();
    // the Hashtable: chains of entry indexes, head first
    let mut capacity = 11usize;
    let mut threshold = 8usize;
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); capacity];
    for (count, (_, i)) in walk.into_iter().enumerate() {
        if count >= threshold {
            let new_capacity = capacity * 2 + 1;
            let mut rehashed: Vec<Vec<usize>> = vec![Vec::new(); new_capacity];
            for old in (0..capacity).rev() {
                for &e in &buckets[old] {
                    let index = (string_hash(&entries[e].0) as u32 & 0x7fff_ffff) as usize % new_capacity;
                    rehashed[index].insert(0, e);
                }
            }
            capacity = new_capacity;
            threshold = capacity * 3 / 4;
            buckets = rehashed;
        }
        let index = (string_hash(&entries[i].0) as u32 & 0x7fff_ffff) as usize % capacity;
        buckets[index].insert(0, i);
    }
    buckets.iter().rev().flat_map(|chain| chain.iter().map(|&e| entries[e].clone())).collect()
}

/// `FileNotFoundException`'s reason for a file that cannot be opened.
fn open_failure(path: &std::path::Path) -> Option<String> {
    if path.is_dir() {
        return Some(format!("{} (Is a directory)", path.display()));
    }
    match std::fs::File::open(path) {
        Ok(_) => None,
        Err(e) => {
            let reason = match e.raw_os_error() {
                Some(13) => "Permission denied".to_string(),
                Some(20) => "Not a directory".to_string(),
                Some(40) => "Too many levels of symbolic links".to_string(),
                _ if e.kind() == std::io::ErrorKind::NotFound => "No such file or directory".to_string(),
                _ => e.to_string(),
            };
            Some(format!("{} ({reason})", path.display()))
        }
    }
}

/// The text `readJsonPropertyFile` stores for a top-level value of the `Map<Object, Object>` Jackson read (
/// all against the oracle): a string as it is, a number as `Integer`/`Long`/`BigInteger` or `Double.toString`, a map as
/// `key=value` pairs joined by `,` (an empty map is empty), an array as the `Object[]` Jackson builds for it, whose
/// `toString` is an identity hash.
fn json_text(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Object(map) => map.iter().map(|(k, v)| format!("{k}={}", nested_text(v))).collect::<Vec<_>>().join(","),
        other => nested_text(other),
    }
}

/// `String.valueOf` of a value inside a map: a nested map is `AbstractMap.toString`, `{k=v, k=v}`.
fn nested_text(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            let text = n.to_string();
            if text.contains(['.', 'e', 'E']) {
                text.parse::<f64>().map_or(text, java_compat::double_to_string)
            } else if text == "-0" {
                "0".to_string()
            } else {
                text
            }
        }
        Value::Array(items) => {
            // `[Ljava.lang.Object;@` and the hash of an object that has none: any 8 digits do, so that a scenario masks them
            let seed = items.len() as u32 ^ 0x26be_92ad;
            format!("[Ljava.lang.Object;@{seed:x}")
        }
        Value::Object(map) => format!("{{{}}}", map.iter().map(|(k, v)| format!("{k}={}", nested_text(v))).collect::<Vec<_>>().join(", ")),
    }
}

/// Jackson's `JsonParseException` text for `text` when it can be named (an input that ends inside an object), else the
/// parser's own wording.
fn jackson_parse_error(text: &str, error: &serde_json::Error) -> String {
    if let Some(named) = crate::jackson_syntax::syntax_error(text) {
        return named;
    }
    let location = |line: usize, column: usize| format!(" at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: {line}, column: {column}]");
    if error.is_eof() {
        let line = text.matches('\n').count() + 1;
        let column = text.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
        let message = if text.trim_start().starts_with('{') && !text.trim().is_empty() {
            "Unexpected end-of-input within/between Object entries"
        } else {
            "No content to map due to end-of-input"
        };
        let class = if message.starts_with("No content") { "shaded_package.com.fasterxml.jackson.databind.exc.MismatchedInputException" } else { "shaded_package.com.fasterxml.jackson.core.JsonParseException" };
        return format!("{class}: {message}\n{}", location(line, column));
    }
    format!("shaded_package.com.fasterxml.jackson.core.JsonParseException: {error}\n{}", location(error.line(), error.column()))
}

fn is_blank(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\u{c}')
}

/// `Properties$LineReader.readLine`: the logical lines of `text`. Lines end at `\n`, `\r` or `\r\n`; leading blanks are
/// skipped; a line whose first character is `#` or `!` is a comment (and never continues); a line ending in an odd number of
/// backslashes continues on the next one, whose leading blanks are skipped, and a continuation line is never a comment.
fn logical_lines(text: &str) -> Vec<Vec<char>> {
    let chars: Vec<char> = text.chars().collect();
    let mut lines = Vec::new();
    let mut line: Vec<char> = Vec::new();
    let (mut skip_blanks, mut appended_begin, mut new_line, mut comment, mut backslash, mut skip_lf) = (true, false, true, false, false, false);
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if skip_lf {
            skip_lf = false;
            if c == '\n' {
                continue;
            }
        }
        if skip_blanks {
            if is_blank(c) {
                continue;
            }
            if !appended_begin && (c == '\r' || c == '\n') {
                continue;
            }
            skip_blanks = false;
            appended_begin = false;
        }
        if new_line {
            new_line = false;
            if c == '#' || c == '!' {
                comment = true;
                continue;
            }
        }
        if c != '\n' && c != '\r' {
            line.push(c);
            backslash = c == '\\' && !backslash;
            continue;
        }
        // end of a natural line
        if comment || line.is_empty() {
            comment = false;
            new_line = true;
            skip_blanks = true;
            line.clear();
            continue;
        }
        if i >= chars.len() {
            if backslash {
                line.pop();
            }
            lines.push(std::mem::take(&mut line));
            break;
        }
        if backslash {
            line.pop();
            skip_blanks = true;
            appended_begin = true;
            backslash = false;
            if c == '\r' {
                skip_lf = true;
            }
        } else {
            lines.push(std::mem::take(&mut line));
            new_line = true;
            skip_blanks = true;
            if c == '\r' {
                skip_lf = true;
            }
        }
    }
    if !line.is_empty() && !comment {
        if backslash {
            line.pop();
        }
        lines.push(line);
    }
    lines
}

/// `Properties.loadConvert`: `\t \n \r \f`, `\uXXXX`, and a backslash before any other character yields that character. A
/// malformed `\u` escape is an `IllegalArgumentException` that kills the oracle at startup (a recorded divergence); here the
/// `u` is kept.
fn load_convert(chars: &[char]) -> String {
    let mut out = String::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(&next) = chars.get(i) else { break };
        i += 1;
        match next {
            't' => out.push('\t'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            'f' => out.push('\u{c}'),
            'u' => {
                let hex: String = chars[i..].iter().take(4).collect();
                match u32::from_str_radix(&hex, 16).ok().filter(|_| hex.chars().count() == 4 && hex.chars().all(|h| h.is_ascii_hexdigit())) {
                    Some(unit) => {
                        out.push(char::from_u32(unit).unwrap_or('\u{fffd}'));
                        i += 4;
                    }
                    None => out.push('u'),
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// `Properties.load` of `text`: later duplicates replace the value and keep the first position. The key ends at the first
/// unescaped `=`, `:` or blank; blanks, then at most one `=` or `:`, then blanks more separate it from the value, whose
/// trailing blanks are kept.
pub fn parse_ordered(text: &str) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for line in logical_lines(text) {
        let (mut key_len, mut value_start, mut has_separator, mut backslash) = (0, line.len(), false, false);
        while key_len < line.len() {
            let c = line[key_len];
            if (c == '=' || c == ':') && !backslash {
                value_start = key_len + 1;
                has_separator = true;
                break;
            } else if is_blank(c) && !backslash {
                value_start = key_len + 1;
                break;
            }
            backslash = c == '\\' && !backslash;
            key_len += 1;
        }
        while value_start < line.len() {
            let c = line[value_start];
            if !is_blank(c) {
                if !has_separator && (c == '=' || c == ':') {
                    has_separator = true;
                } else {
                    break;
                }
            }
            value_start += 1;
        }
        let (key, value) = (load_convert(&line[..key_len]), load_convert(&line[value_start..]));
        match index.get(&key) {
            Some(&i) => entries[i].1 = value,
            None => {
                index.insert(key.clone(), entries.len());
                entries.push((key, value));
            }
        }
    }
    entries
}

/// `readJsonPropertyFile`'s `objectMapper.readValue(inputStream, Map.class)` over the file's bytes: the properties it sets,
/// or the text of the exception it logs.
pub fn read_json(bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    if let Some(failure) = crate::jackson_syntax::map_failure(bytes) {
        return Err(failure);
    }
    // `ByteSourceJsonBootstrapper` drops a byte order mark (`jackson_syntax::map_failure` does too)
    let bytes = if bytes.len() >= 4 && bytes.starts_with(&[0xef, 0xbb, 0xbf]) { &bytes[3..] } else { bytes };
    let text = String::from_utf8_lossy(bytes).into_owned();
    match crate::json::parse_lenient_non_finite_as_text(bytes) {
        Ok(serde_json::Value::Object(map)) => Ok(map.iter().filter(|(_, v)| !v.is_null()).map(|(key, value)| (format!("mockserver.{key}"), json_text(value))).collect()),
        Ok(_) => Err(crate::jackson_syntax::syntax_error(&text).unwrap_or_else(|| "shaded_package.com.fasterxml.jackson.databind.exc.MismatchedInputException: Cannot deserialize value of type `java.util.LinkedHashMap<java.lang.Object,java.lang.Object>` from non-object input".to_string())),
        Err(e) => Err(jackson_parse_error(&text, &e)),
    }
}

/// Reads `path` as `readPropertyFile` does. `explicit` says the operator named the file (`propertyFileExplicitlyConfigured`),
/// which is what makes an unreadable one worth a `WARN`.
pub fn load(path: &str, explicit: bool) -> LoadedFile {
    let json = path.ends_with(".json");
    let mut loaded = LoadedFile::default();
    let description = if json { "JSON property file" } else { "property file" };
    if let Some(reason) = open_failure(std::path::Path::new(path)) {
        if explicit {
            loaded.notices.push(StartupNotice {
                level: Level::Warn,
                message: format!("{description} [{path}] could not be read so none of its properties have been applied - {reason}"),
                throwable: None,
            });
        }
        return loaded;
    }
    let bytes = std::fs::read(path).unwrap_or_default();
    if json {
        match read_json(&bytes) {
            Ok(entries) => loaded.entries.extend(entries),
            Err(throwable) => loaded.notices.push(StartupNotice {
                level: Level::Error,
                message: format!("exception loading JSON property file [{path}]"),
                throwable: Some(throwable),
            }),
        }
    } else {
        // `Properties.load(InputStream)` reads ISO-8859-1: each byte is one character (a UTF-8 file's multi-byte characters
        // come out as their Latin-1 pairs, as on the oracle)
        let text: String = bytes.iter().map(|&b| char::from(b)).collect();
        loaded.entries = parse_ordered(&text);
    }
    loaded
}

/// The `Reading properties from property file [..]:` message, values redacted as `redactSensitiveValue` does.
pub fn dump_message(path: &str, entries: &[(String, String)]) -> String {
    let mut out = format!("Reading properties from property file [{path}]:\n");
    for (name, value) in property_names_order(entries) {
        out.push_str(&format!("  {name} = {}\n", crate::config::credentials::redact_sensitive_value(&name, &value)));
    }
    out
}

/// `ConfigurationProperties.REMOVED_KEYS`: the properties removed in 9.0.0, by system-property key, with what replaced
/// them. A leftover one is ignored, and its warning says it was removed rather than suggesting a typo.
const REMOVED_KEYS: [(&str, &str); 2] = [
    ("mockserver.forwardBinaryRequestsWithoutWaitingForResponse", "a proxied binary connection is always relayed on one upstream connection, which waits for no response"),
    ("mockserver.forwardBinaryRequestsUseSingleConnection", "a proxied binary connection is always relayed on one upstream connection"),
];

/// `SYSTEM_PROPERTY_ONLY_KEYS`: documented tuning knobs read only with `System.getProperty` (`RequestMatchers`,
/// `JsonSchemaValidator`). Recognised as system properties; a properties-file entry or environment variable for them is
/// ignored, so is still reported.
pub const SYSTEM_PROPERTY_ONLY_KEYS: [&str; 2] = ["mockserver.candidateIndexThreshold", "mockserver.jsonSchemaAllowRemoteRefs"];

/// `EXTRA_RECOGNISED_SYSTEM_PROPERTY_KEYS` and `EXTRA_RECOGNISED_ENV_KEYS`: keys the launcher handles rather than a
/// `MOCKSERVER_*` constant.
const EXTRA_PROPERTIES: [&str; 3] = ["mockserver.serverPort", "mockserver.mockServerPort", "mockserver.launcherName"];
const EXTRA_ENVIRONMENT: [&str; 3] = ["MOCKSERVER_SERVER_PORT", "MOCKSERVER_LAUNCHER", "MOCKSERVER_JAVA_OPTS"];

/// How an unrecognised key was set (`UnrecognisedProperty.getSetAs`), and the form its suggestions take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetAs {
    SystemProperty,
    EnvironmentVariable,
    PropertiesFile,
}

impl SetAs {
    pub fn text(self) -> &'static str {
        match self {
            SetAs::SystemProperty => "system property",
            SetAs::EnvironmentVariable => "environment variable",
            SetAs::PropertiesFile => "properties-file key",
        }
    }
}

/// `ConfigurationProperties.UnrecognisedProperty`: a key in the `mockserver.`/`MOCKSERVER_` namespace that is not a
/// recognised property, how it was set and the recognised keys (in the same form) it was most likely meant to be.
/// Names only, never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unrecognised {
    pub name: String,
    pub set_as: SetAs,
    pub suggestions: Vec<String>,
    /// For a known system-property-only key set some other way: that key.
    pub system_property_only: Option<&'static str>,
    /// For a property removed in 9.0.0: what replaced it.
    pub removed_because: Option<&'static str>,
}

impl Unrecognised {
    fn of(name: &str, set_as: SetAs, known: &[(&str, &str)]) -> Unrecognised {
        let removed_because = removed_because(name);
        let suggestions = if removed_because.is_some() { Vec::new() } else { suggest_recognised_keys(name, set_as, known) };
        Unrecognised { name: name.to_string(), set_as, suggestions, system_property_only: None, removed_because }
    }

    /// `getDescription`: `system property [mockserver.x]`.
    pub fn description(&self) -> String {
        format!("{} [{}]", self.set_as.text(), self.name)
    }

    /// `getHint`: the suggested keys, or how to set a system-property-only key; `None` when nothing is known.
    pub fn hint(&self) -> Option<String> {
        if let Some(because) = self.removed_because {
            return Some(format!("removed in 9.0.0: {because}"));
        }
        if let Some(key) = self.system_property_only {
            return Some(format!("read only as a system property: set -D{key} instead"));
        }
        (!self.suggestions.is_empty()).then(|| format!("did you mean {}?", self.suggestions.join(" or ")))
    }

    /// `getWarning`: the startup `WARN`.
    pub fn warning(&self) -> String {
        let description = self.description();
        if let Some(because) = self.removed_because {
            return format!("MockServer configuration {description} was removed in 9.0.0 and is ignored: {because}");
        }
        if let Some(key) = self.system_property_only {
            return format!("unrecognised MockServer configuration {description} - {key} is read only as a system property, so this will be ignored (set -D{key} instead)");
        }
        let advice = if self.suggestions.is_empty() { "(check for a typo)".to_string() } else { format!("(did you mean {}?)", self.suggestions.join(" or ")) };
        format!("unrecognised MockServer configuration {description} - it is not a known configuration property and will be ignored {advice}")
    }
}

/// `normaliseKeyForSuggestion`: lower case, without a leading `mockserver` and anything but ASCII letters and digits,
/// so `mockserver.maxExpectations`, `MOCKSERVER_MAX_EXPECTATIONS` and `mockserver.max_expectations` compare equal.
pub fn normalise_key(key: &str) -> String {
    let lower = key.to_lowercase();
    let lower = lower.strip_prefix("mockserver").unwrap_or(&lower);
    lower.chars().filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit()).collect()
}

fn removed_because(key: &str) -> Option<&'static str> {
    let normalised = normalise_key(key);
    REMOVED_KEYS.iter().find(|(removed, _)| normalise_key(removed) == normalised).map(|(_, because)| *because)
}

fn system_property_only_key_for(environment_variable: &str) -> Option<&'static str> {
    let normalised = normalise_key(environment_variable);
    SYSTEM_PROPERTY_ONLY_KEYS.into_iter().find(|key| normalise_key(key) == normalised)
}

/// `suggestRecognisedKeys`: the recognised keys, in the form `set_as` names, closest to `key` by optimal string
/// alignment distance between normalised names, at most one edit per four characters (at least one, at most three);
/// all equally close ones, sorted. The index is upstream's `recognisedKeysByNormalisedName`: every `MOCKSERVER_*`
/// constant, `serverPort` in every form, and the system-property-only knobs as system properties only.
pub fn suggest_recognised_keys(key: &str, set_as: SetAs, known: &[(&str, &str)]) -> Vec<String> {
    let normalised = normalise_key(key);
    if normalised.is_empty() {
        return Vec::new();
    }
    // a `TreeMap` keyed by the normalised name, first entry wins (`putIfAbsent`)
    let mut index: std::collections::BTreeMap<String, [Option<&str>; 3]> = std::collections::BTreeMap::new();
    for (property, environment) in known {
        index.entry(normalise_key(property)).or_insert([Some(*property), Some(*environment), Some(*property)]);
    }
    index.entry(normalise_key("mockserver.serverPort")).or_insert([Some("mockserver.serverPort"), Some("MOCKSERVER_SERVER_PORT"), Some("mockserver.serverPort")]);
    for key in SYSTEM_PROPERTY_ONLY_KEYS {
        index.entry(normalise_key(key)).or_insert([Some(key), None, None]);
    }
    let form = match set_as {
        SetAs::SystemProperty => 0,
        SetAs::EnvironmentVariable => 1,
        SetAs::PropertiesFile => 2,
    };
    let left: Vec<char> = normalised.chars().collect();
    let mut closest_distance = (left.len() / 4).clamp(1, 3);
    let mut closest: Vec<String> = Vec::new();
    for (candidate, forms) in &index {
        let Some(suggestion) = forms[form] else { continue };
        let distance = edit_distance(&left, &candidate.chars().collect::<Vec<_>>());
        if distance < closest_distance {
            closest_distance = distance;
            closest.clear();
            closest.push(suggestion.to_string());
        } else if distance == closest_distance {
            closest.push(suggestion.to_string());
        }
    }
    closest.sort();
    closest
}

/// `editDistance`: optimal string alignment (insertions, deletions, substitutions, adjacent transpositions).
fn edit_distance(left: &[char], right: &[char]) -> usize {
    let mut d = vec![vec![0usize; right.len() + 1]; left.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=left.len() {
        for j in 1..=right.len() {
            let cost = usize::from(left[i - 1] != right[j - 1]);
            let mut best = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && left[i - 1] == right[j - 2] && left[i - 2] == right[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[left.len()][right.len()]
}

/// `findUnrecognisedConfigurationKeys`, sorted by description as the `TreeMap` it fills: system properties,
/// environment variables and file keys in MockServer's namespace that are not recognised. The mock-server properties
/// ([`crate::config::RS_PROPERTIES`]) count as recognised: upstream does not know them, but this server honours them.
pub fn unrecognised_properties(system_properties: &[&str], environment: &[&str], file_keys: &[&str], known: &[(&str, &str)]) -> Vec<Unrecognised> {
    let rs = crate::config::RS_PROPERTIES;
    let known_property = |name: &str| {
        EXTRA_PROPERTIES.contains(&name)
            || SYSTEM_PROPERTY_ONLY_KEYS.contains(&name)
            || known.iter().any(|(k, _)| *k == name)
            || name.strip_prefix("mockserver.").is_some_and(|k| rs.contains(&k))
    };
    let known_environment = |name: &str| {
        EXTRA_ENVIRONMENT.contains(&name) || known.iter().any(|(_, e)| *e == name) || rs.iter().any(|k| crate::config::env_name(k) == name)
    };
    let mut found: std::collections::BTreeMap<String, Unrecognised> = std::collections::BTreeMap::new();
    let mut add = |property: Unrecognised| {
        found.insert(property.description(), property);
    };
    for name in system_properties {
        if name.starts_with("mockserver.") && !known_property(name) {
            add(Unrecognised::of(name, SetAs::SystemProperty, known));
        }
    }
    for name in environment {
        if name.starts_with("MOCKSERVER_") && !known_environment(name) {
            add(match system_property_only_key_for(name) {
                Some(key) => Unrecognised { name: name.to_string(), set_as: SetAs::EnvironmentVariable, suggestions: Vec::new(), system_property_only: Some(key), removed_because: None },
                None => Unrecognised::of(name, SetAs::EnvironmentVariable, known),
            });
        }
    }
    for name in file_keys {
        // a system-property-only key in the file is ignored, so reported, unless the system property is set too
        let system_property_only = SYSTEM_PROPERTY_ONLY_KEYS.into_iter().find(|k| k == name && !system_properties.contains(k));
        if name.starts_with("mockserver.")
            && (!known_property(name) || system_property_only.is_some())
            && !found.contains_key(&format!("system property [{name}]"))
        {
            let property = match system_property_only {
                Some(key) => Unrecognised { name: name.to_string(), set_as: SetAs::PropertiesFile, suggestions: Vec::new(), system_property_only: Some(key), removed_because: None },
                None => Unrecognised::of(name, SetAs::PropertiesFile, known),
            };
            found.insert(property.description(), property);
        }
    }
    found.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(keys: &[&str]) -> Vec<(String, String)> {
        keys.iter().map(|k| ((*k).to_string(), "v".to_string())).collect()
    }

    #[test]
    fn names_come_out_in_the_order_the_oracle_printed_them() {
        // recorded from the oracle: a file with these three keys in this order dumped as below
        let order: Vec<String> = property_names_order(&pairs(&["mockserver.logLevel", "mockserver.maxExpectations", "mockserver.typoThing"])).into_iter().map(|(k, _)| k).collect();
        assert_eq!(order, ["mockserver.logLevel", "mockserver.maxExpectations", "mockserver.typoThing"]);
    }

    #[test]
    fn fourteen_names_come_out_in_the_oracles_order() {
        // `tests/files/properties/many.properties` dumped by the oracle (past 11 entries both tables have resized)
        let file = ["maxExpectations", "maxLogEntries", "metricsEnabled", "disableLogging", "corsAllowOrigin", "watchInitializationJson", "llmApiKey", "maxFutureTimeout", "useSemicolonAsQueryParameterSeparator", "attemptToProxyIfNoMatchingExpectation", "sslSubjectAlternativeNameDomains", "matchersFailFast", "enableCORSForAPI", "maxSocketTimeout"];
        let names: Vec<String> = file.iter().map(|n| format!("mockserver.{n}")).collect();
        let order: Vec<String> = property_names_order(&pairs(&names.iter().map(String::as_str).collect::<Vec<_>>())).into_iter().map(|(k, _)| k.trim_start_matches("mockserver.").to_string()).collect();
        let oracle = [
            "watchInitializationJson", "llmApiKey", "sslSubjectAlternativeNameDomains", "matchersFailFast", "maxFutureTimeout", "corsAllowOrigin",
            "maxLogEntries", "enableCORSForAPI", "disableLogging", "metricsEnabled", "maxSocketTimeout", "maxExpectations", "attemptToProxyIfNoMatchingExpectation", "useSemicolonAsQueryParameterSeparator",
        ];
        assert_eq!(order, oracle);
    }

    #[test]
    fn json_values_are_stringified_as_the_oracle_printed_them() {
        let value: serde_json::Value = crate::json::parse_lenient(br#"{"m": {"p": {"q": 1}}, "n": {"x": null}, "e": {}, "g": 0.00001, "f": 1e21, "d": 12345678.5, "i": 12345678901234567890, "neg": -0.0}"#).unwrap();
        let text: Vec<String> = value.as_object().unwrap().values().map(json_text).collect();
        assert_eq!(text, ["p={q=1}", "x=null", "", "1.0E-5", "1.0E21", "1.23456785E7", "12345678901234567890", "-0.0"]);
    }

    #[test]
    fn properties_files_are_read_as_latin_1() {
        let loaded = load("tests/files/properties/non_ascii.properties", true);
        let keys: Vec<&str> = loaded.entries.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"mockserver.café") && keys.contains(&"mockserver.naÃ¯ve"), "{keys:?}");
    }

    #[test]
    fn eof_inside_an_object_is_jacksons_message() {
        let text = "{ \"logLevel\": \"INFO\",";
        let error = serde_json::from_str::<serde_json::Value>(text).unwrap_err();
        let message = jackson_parse_error(text, &error);
        assert!(message.starts_with("shaded_package.com.fasterxml.jackson.core.JsonParseException: Unexpected end-of-input within/between Object entries\n at [Source: REDACTED"));
        assert!(message.ends_with("line: 1, column: 22]"));
    }
}

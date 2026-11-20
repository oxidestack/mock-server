//! The rule table and the verdicts the input modules share. Configuration keys and JVM options take their
//! verdict from [`crate::jvm_policy`], the table the server's startup notice reads too, so the tool cannot say
//! anything about a key that the server does not do.

use super::{Context, Edit, Finding, Severity};
use crate::jvm_policy::{self, Input, Verdict};

/// Every rule id with the topic it belongs to.
pub const RULES: &[(&str, &str)] = &[
    (IMAGE_REFERENCE, "Packaging"),
    (IMAGE_TESTCONTAINERS, "Packaging"),
    (JVM_PROPERTY, "JVM tuning"),
    (JVM_MEMORY, "JVM tuning"),
    (JVM_CPU, "JVM tuning"),
    (JVM_LOGGING, "Logs"),
    (JVM_TLS, "Configuration"),
    (JVM_OTHER, "JVM tuning"),
    (CONFIG_KEY, "Configuration"),
    (CONFIG_THREAD_COUNT, "JVM tuning"),
    (CLASSPATH_LIBS, "Class path extension"),
    (CLASSPATH_CALLBACK, "Class path extension"),
    (CLASSPATH_INITIALIZER, "Class path extension"),
    (CLASSPATH_BLOB, "Class path extension"),
    (CLASSPATH_EXTENSIONS, "Class path extension"),
    (TEMPLATE_JAVASCRIPT, "JavaScript templates"),
    (TEMPLATE_VELOCITY_CLASS, "Velocity class access"),
    (CLUSTER_TRANSPORT, "Clustering"),
    (LOGGING_FILE, "Logs"),
    (PACKAGING_JAR, "Packaging"),
    (PACKAGING_MAVEN, "Packaging"),
    (PACKAGING_WAR, "Packaging"),
    (PACKAGING_HELM, "Packaging"),
    (MEMORY_CSV, "Metrics"),
    (METRICS_JVM_SERIES, "Metrics"),
    (METRICS_DASHBOARD, "Dashboards"),
    (METRICS_SCRAPE, "Metrics"),
];

pub const IMAGE_REFERENCE: &str = "image.reference";
pub const IMAGE_TESTCONTAINERS: &str = "image.testcontainers";
pub const JVM_PROPERTY: &str = "jvm.options.property";
pub const JVM_MEMORY: &str = "jvm.options.memory";
pub const JVM_CPU: &str = "jvm.options.cpu";
pub const JVM_LOGGING: &str = "jvm.options.logging";
pub const JVM_TLS: &str = "jvm.options.tls";
pub const JVM_OTHER: &str = "jvm.options.other";
pub const CONFIG_KEY: &str = "config.key";
pub const CONFIG_THREAD_COUNT: &str = "config.thread-count";
pub const CLASSPATH_LIBS: &str = "classpath.libs";
pub const CLASSPATH_CALLBACK: &str = "classpath.callback";
pub const CLASSPATH_INITIALIZER: &str = "classpath.initializer";
pub const CLASSPATH_BLOB: &str = "classpath.blob";
pub const CLASSPATH_EXTENSIONS: &str = "classpath.extensions";
pub const TEMPLATE_JAVASCRIPT: &str = "template.javascript";
pub const TEMPLATE_VELOCITY_CLASS: &str = "template.velocity-class";
pub const CLUSTER_TRANSPORT: &str = "cluster.transport";
pub const LOGGING_FILE: &str = "logging.file";
pub const PACKAGING_JAR: &str = "packaging.jar";
pub const PACKAGING_MAVEN: &str = "packaging.maven";
pub const PACKAGING_WAR: &str = "packaging.war";
pub const PACKAGING_HELM: &str = "packaging.helm";
pub const MEMORY_CSV: &str = "memory.csv";
pub const METRICS_JVM_SERIES: &str = "metrics.jvm-series";
pub const METRICS_DASHBOARD: &str = "metrics.dashboard";
pub const METRICS_SCRAPE: &str = "metrics.scrape";

/// Where the callback plugin SDK is documented.
pub const PLUGIN_SDK: &str = "docs/callback-plugins.md";

/// The reason extension classes are not loaded, which the verdicts print.
pub const EXTENSIONS_REASON: &str = "extensions resolve through callback providers";

/// `classpath.extensions`: a Java extension has no counterpart, so each place that names or mounts
/// one is a blocker. A named extension refuses start-up as an absent class does, and a jar in `/extensions` is ignored.
pub fn extensions_finding(found: impl Into<String>, line: usize, key: impl Into<String>) -> Finding {
    Finding::new(CLASSPATH_EXTENSIONS, Severity::Blocker, line, found, format!("Java extensions are not loaded: a named extension refuses start-up as a class that is not on the class path, and a jar in /extensions is ignored; remove it or move its job to a callback plugin or an expectation ({EXTENSIONS_REASON})")).key(key)
}

/// The severity of a policy verdict: support is info, a map is a rewrite when the tool can make it (else info, the
/// server honours it as it stands), warn is warn, reject a blocker.
pub fn severity(verdict: Verdict, mechanical: bool) -> Severity {
    match verdict {
        Verdict::Support => Severity::Info,
        Verdict::Map if mechanical => Severity::Rewrite,
        Verdict::Map => Severity::Info,
        Verdict::Warn => Severity::Warn,
        Verdict::Reject => Severity::Blocker,
    }
}

/// The recognised configuration key whose environment variable this is.
pub fn key_for_env(name: &str) -> Option<&'static str> {
    crate::config::recognised_properties().iter().find(|(_, env)| *env == name).and_then(|(key, _)| key.strip_prefix("mockserver."))
}

/// Whether `key` (without `mockserver.`) is a recognised configuration key.
pub fn is_recognised(key: &str) -> bool {
    crate::config::recognised_properties().iter().any(|(name, _)| name.strip_prefix("mockserver.") == Some(key))
}

/// The environment variables that hold JVM options, from the policy table's environment rows.
pub fn is_jvm_options_variable(name: &str) -> bool {
    jvm_policy::TABLE.iter().any(|p| matches!(p.input, Input::Environment(variable) if variable == name))
}

/// How a configuration setting was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `mockserver.<key>` in a properties file or a `-D`.
    Property,
    /// `MOCKSERVER_<KEY>`.
    Environment,
}

fn is_sensitive(key: &str) -> bool {
    crate::config::credentials::is_sensitive_property_name(key)
}

/// `name=value` as shown: the value left out for a sensitive key, as the startup notice does.
pub fn shown(name: &str, key: &str, value: &str) -> String {
    if is_sensitive(key) { format!("{name}={}", crate::config::credentials::REDACTED_VALUE) } else { format!("{name}={value}") }
}

/// The findings for one configuration setting (`config.key` and the rules that take over particular keys).
pub fn config_setting(name: &str, value: &str, source: Source) -> Vec<Finding> {
    let key = match source {
        Source::Property => name.strip_prefix("mockserver.").filter(|k| is_recognised(k)),
        Source::Environment => key_for_env(name),
    };
    let Some(key) = key else { return unknown_setting(name, value, source) };
    let value = value.trim();
    let system = std::collections::HashMap::new();
    let mut file = std::collections::HashMap::new();
    let mut env = std::collections::HashMap::new();
    match source {
        Source::Property => file.insert(format!("mockserver.{key}"), value.to_string()),
        Source::Environment => env.insert(name.to_string(), value.to_string()),
    };
    let sources = jvm_policy::Sources { system_properties: &system, file: &file, env: &env };
    let found = jvm_policy::findings(&sources, &|_| false);
    if !found.is_empty() {
        return found.into_iter().map(|f| policy_finding(value, f)).collect();
    }
    let unquoted = value.trim_matches('"');
    match key {
        "outputMemoryUsageCsv" if unquoted.eq_ignore_ascii_case("true") => vec![Finding::new(
            MEMORY_CSV,
            Severity::Warn,
            0,
            shown(name, key, value),
            "the CSV keeps its first five columns; the heap columns are replaced",
        )],
        "clusterTransportConfig" => vec![Finding::new(
            CLUSTER_TRANSPORT,
            Severity::Info,
            0,
            shown(name, key, value),
            format!("supported: the JGroups stack runs ported ({}); a stack file the scan finds is checked protocol by protocol", jgroups::stack::supported_protocols().join(", ")),
        )],
        "extensions" if unquoted.split(',').any(|name| !name.trim().is_empty()) => vec![extensions_finding(shown(name, key, value), 0, name)],
        "extensionScanning" if unquoted.eq_ignore_ascii_case("true") => vec![extensions_finding(shown(name, key, value), 0, name)],
        "blobStoreType" if ["s3", "gcs", "azure"].contains(&unquoted.to_ascii_lowercase().as_str()) => vec![Finding::new(
            CLASSPATH_BLOB,
            Severity::Action,
            0,
            shown(name, key, value),
            format!("the {unquoted} store is built in: set MOCKSERVER_BLOB_STORE_MODULES={} where the mockserver-blob-{unquoted} jar was on the class path", unquoted.to_ascii_lowercase()),
        )],
        _ => vec![Finding::new(CONFIG_KEY, Severity::Info, 0, shown(name, key, value), "supported as-is")],
    }
}

/// A row of the policy table that a setting matched, as a finding.
fn policy_finding(value: &str, found: jvm_policy::Finding) -> Finding {
    let policy = found.policy;
    match policy.input {
        Input::Key("nioEventLoopThreadCount") => {
            Finding::new(CONFIG_THREAD_COUNT, severity(policy.verdict, false), 0, found.setting, format!("honoured as {}", policy.reason))
        }
        Input::ClassUnlessProvided(_) => Finding::new(
            CLASSPATH_INITIALIZER,
            Severity::Action,
            0,
            found.setting,
            format!("{}: build {} as a callback plugin initializer ({PLUGIN_SDK}), or move its expectations to initializationJsonPath", policy.reason, value.trim_matches('"')),
        ),
        Input::KeyValue("velocityDisallowClassLoading", _) => Finding::new(
            TEMPLATE_VELOCITY_CLASS,
            Severity::Action,
            0,
            found.setting,
            format!("{}; templates that load JDK classes need another way (the foreign runtime)", policy.reason),
        ),
        _ => Finding::new(CONFIG_KEY, severity(policy.verdict, false), 0, found.setting, policy.reason),
    }
}

/// The mock-server properties (outside upstream's names), which upstream's key check does not
/// know; the startup key check reads the same list.
pub const RS_KEYS: [&str; 2] = crate::config::RS_PROPERTIES;

/// A `mockserver.*`/`MOCKSERVER_*` name the server does not recognise: its own `findUnknownConfigurationKeys` text.
fn unknown_setting(name: &str, value: &str, source: Source) -> Vec<Finding> {
    let rs_key = RS_KEYS.iter().find(|k| match source {
        Source::Property => name.strip_prefix("mockserver.") == Some(**k),
        Source::Environment => crate::config::env_name(k) == name,
    });
    if let Some(key) = rs_key {
        return vec![Finding::new(CONFIG_KEY, Severity::Info, 0, shown(name, key, value.trim()), "a mock-server property: honoured (upstream ignores it)")];
    }
    let known = crate::config::recognised_properties();
    let warnings = match source {
        Source::Property => crate::property_file::unrecognised_properties(&[], &[], &[name], known),
        Source::Environment => crate::property_file::unrecognised_properties(&[], &[name], &[], known),
    };
    if warnings.is_empty() {
        // `findUnknownConfigurationKeys` knows a few names outside the table (`MOCKSERVER_SERVER_PORT`, ...)
        return vec![Finding::new(CONFIG_KEY, Severity::Info, 0, shown(name, name, value.trim()), "supported as-is")];
    }
    warnings
        .into_iter()
        .map(|w| {
            let shown_value = if is_sensitive(name) { crate::config::credentials::REDACTED_VALUE.to_string() } else { value.trim().to_string() };
            Finding::new(CONFIG_KEY, Severity::Warn, 0, format!("{name}={shown_value}"), w.warning())
        })
        .collect()
}

/// What happens to one JVM option token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fate {
    /// It stays in the variable.
    Keep,
    /// It leaves the variable and becomes this environment variable.
    Move { name: String, value: String },
}

const MEMORY_FLAGS: [&str; 7] = ["-Xmx", "-Xms", "-Xss", "-XX:MaxRAMPercentage", "-XX:InitialRAMPercentage", "-XX:MaxMetaspaceSize", "-XX:MaxDirectMemorySize"];
const LOGGING_PROPERTIES: [&str; 4] = ["-Djava.util.logging.config.file=", "-Dlogback.configurationFile=", "-Dlog4j.configurationFile=", "-Dlog4j2.configurationFile="];

/// The findings for one token of a JVM options variable (the verdict from [`jvm_policy::jvm_option_verdict`]) and
/// what becomes of it.
pub fn jvm_option(token: &str, ctx: &Context) -> (Vec<Finding>, Fate) {
    let verdict = jvm_policy::jvm_option_verdict(token);
    if let Some(rest) = token.strip_prefix("-Dmockserver.") {
        let (key, value) = rest.split_once('=').unwrap_or((rest, ""));
        if !key.is_empty() && !value.is_empty() {
            let env = crate::config::env_name(key);
            let mut findings = vec![Finding::new(JVM_PROPERTY, severity(verdict, true), 0, shown_token(key, token), "a JVM variable means nothing to mock-server: the property moves into the environment block").replacement(shown(&env, key, value))];
            findings.extend(config_setting(&format!("mockserver.{key}"), value, Source::Property));
            return (findings, Fate::Move { name: env, value: value.to_string() });
        }
    }
    if let Some(count) = token.strip_prefix("-XX:ActiveProcessorCount=") {
        let name = crate::config::env_name("nioEventLoopThreadCount");
        let finding = Finding::new(JVM_CPU, severity(verdict, true), 0, token, "the processor count becomes the tokio worker-thread count").replacement(format!("{name}={count}"));
        return (vec![finding], Fate::Move { name, value: count.to_string() });
    }
    if let Some(path) = LOGGING_PROPERTIES.iter().find_map(|p| token.strip_prefix(p)) {
        let file = path.trim_matches('"').rsplit(['/', '\\']).next().unwrap_or(path);
        if let Some(level) = ctx.logging_levels.get(file) {
            let finding = Finding::new(LOGGING_FILE, Severity::Rewrite, 0, token, format!("{file} sets org.mockserver to {level}; the console layout is fixed")).replacement(format!("MOCKSERVER_LOG_LEVEL={level}"));
            return (vec![finding], Fate::Move { name: "MOCKSERVER_LOG_LEVEL".into(), value: level.clone() });
        }
        return (vec![Finding::new(JVM_LOGGING, severity(verdict, false), 0, token, "logging configuration files have no effect: the console layout is fixed; set the level with MOCKSERVER_LOG_LEVEL (logging.file)")], Fate::Keep);
    }
    let finding = if MEMORY_FLAGS.iter().any(|f| token.starts_with(f)) {
        Finding::new(JVM_MEMORY, severity(verdict, false), 0, token, "no effect: memory is bounded by the container limit and by maxExpectations/maxLogEntries; remove it")
    } else if ["-Djavax.net.ssl.trustStore", "-Djavax.net.ssl.keyStore", "-Djdk.tls."].iter().any(|p| token.starts_with(p)) {
        Finding::new(JVM_TLS, Severity::Action, 0, redact_option(token), "no JSSE: give the certificates as PEM with forwardProxyTLSCustomTrustX509Certificates (trust), privateKeyPath and x509CertificatePath (identity)")
    } else if token.starts_with("-javaagent:") && token.to_ascii_lowercase().contains("opentelemetry") {
        Finding::new(JVM_OTHER, severity(verdict, false), 0, token, "no effect: no JVM to instrument; otelTracesEnabled and otelMetricsEnabled export traces and metrics instead")
    } else {
        Finding::new(JVM_OTHER, severity(verdict, false), 0, redact_option(token), "no effect: a JVM flag without a counterpart in mock-server")
    };
    (vec![finding], Fate::Keep)
}

/// A heap flag in a variable the image's `java` reads: it stays, and mock-server sizes its heap-derived
/// defaults from it as the image does.
fn heap_option(token: &str) -> (Vec<Finding>, Fate) {
    let rule = if token.starts_with("-XX:+Use") { JVM_OTHER } else { JVM_MEMORY };
    let finding = Finding::new(rule, severity(Verdict::Support, false), 0, token, "supported: the heap ceiling and the collector size maxLogEntries, maxExpectations and maxEventLogSizeInBytes as in the image");
    (vec![finding], Fate::Keep)
}

fn shown_token(key: &str, token: &str) -> String {
    if is_sensitive(key) { format!("-Dmockserver.{key}={}", crate::config::credentials::REDACTED_VALUE) } else { token.to_string() }
}

/// A `-D<name>=<value>` with a sensitive name shown with its value redacted.
fn redact_option(token: &str) -> String {
    match token.strip_prefix("-D").and_then(|rest| rest.split_once('=')) {
        Some((name, _)) if is_sensitive(name) => format!("-D{name}={}", crate::config::credentials::REDACTED_VALUE),
        _ => token.to_string(),
    }
}

/// The whitespace-separated tokens of a value, with their byte ranges.
pub fn tokens(value: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in value.char_indices() {
        match (c.is_whitespace(), start) {
            (true, Some(s)) => {
                out.push((s, i));
                start = None;
            }
            (false, None) => start = Some(i),
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push((s, value.len()));
    }
    out
}

/// One environment variable as an input module found it.
#[derive(Debug, Clone)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
    pub line: usize,
    /// The key path shown in the report.
    pub key: String,
    /// Where `value` is in the file, when the file holds it verbatim (no escapes), so it can be rewritten.
    pub span: Option<(usize, usize)>,
    /// The whole entry, removed when every token leaves a JVM options variable.
    pub entry: Option<(usize, usize)>,
}

/// Where new variables go in the block that holds an [`EnvVar`]: the offset to insert at and how to write one entry.
pub struct EnvBlock<'a> {
    pub insert_at: usize,
    pub render: &'a dyn Fn(&str, &str) -> String,
    /// The value span of a variable already in the block, which a moved token then replaces.
    pub existing: &'a dyn Fn(&str) -> Option<(usize, usize)>,
}

/// The findings for one environment variable: JVM options token by token (with the rewrite that moves the mapped
/// tokens into variables of their own when `block` says where they go), `MOCKSERVER_*` settings by key.
pub fn env_var(var: &EnvVar, block: Option<&EnvBlock>, ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();
    if is_jvm_options_variable(&var.name) {
        let mut kept = Vec::new();
        // (variable, value, index of the token's finding, whether the token was an explicit `-Dmockserver.*`)
        let mut moved: Vec<(String, String, usize, bool)> = Vec::new();
        for (start, end) in tokens(&var.value) {
            let token = &var.value[start..end];
            let (mut found, fate) = if jvm_policy::image_reads(&var.name) && jvm_policy::is_heap_flag(token) { heap_option(token) } else { jvm_option(token, ctx) };
            match fate {
                Fate::Keep => kept.push(token),
                Fate::Move { name, value } => moved.push((name, value, findings.len(), found[0].rule == JVM_PROPERTY)),
            }
            for f in &mut found {
                f.found = format!("{} {}", var.name, f.found);
            }
            findings.append(&mut found);
        }
        if let (Some(block), Some((start, end)), false) = (block, var.span, moved.is_empty()) {
            let mut edits = Vec::new();
            match (kept.is_empty(), var.entry) {
                (true, Some((entry_start, entry_end))) => edits.push(Edit::replace(entry_start, entry_end, "")),
                _ => edits.push(Edit::replace(start, end, kept.join(" "))),
            }
            for (n, (name, value, i, explicit)) in moved.iter().enumerate() {
                // the JVM keeps the last `-D` of a name, and that system property beats both a value derived from another
                // flag (a logging file's level, the processor count) and the variable already in the block
                let explicit_later = moved[n + 1..].iter().any(|(other, _, _, e)| other == name && *e);
                let explicit_elsewhere = moved.iter().enumerate().any(|(m, (other, _, _, e))| m != n && other == name && *e);
                let derived_earlier = moved[..n].iter().any(|(other, _, _, _)| other == name);
                let superseded = if *explicit { explicit_later } else { explicit_elsewhere || derived_earlier };
                let existing = (block.existing)(name);
                if superseded || (!explicit && existing.is_some()) {
                    let f = &mut findings[*i];
                    f.replacement = None;
                    f.verdict = format!("{}; dropped, {name} is set {}", f.verdict, if superseded { "by another token" } else { "in the same block" });
                    continue;
                }
                match existing {
                    Some((s, e)) => edits.push(Edit::replace(s, e, value.clone())),
                    None => edits.push(Edit::insert(block.insert_at, (block.render)(name, value))),
                }
            }
            for (n, (_, _, i, _)) in moved.iter().enumerate() {
                let f = std::mem::replace(&mut findings[*i], Finding::new("", Severity::Info, 0, "", ""));
                findings[*i] = f.mechanical(if n == 0 { std::mem::take(&mut edits) } else { Vec::new() });
            }
        }
    } else if var.name.starts_with("MOCKSERVER_") {
        findings = config_setting(&var.name, &var.value, Source::Environment);
    }
    for f in &mut findings {
        f.line = var.line;
        f.key.get_or_insert_with(|| var.key.clone());
    }
    findings
}

/// The arguments of a MockServer command line (`Main`'s flags): a `-D` stays, the binary accepts `-D` arguments.
pub fn command_args(args: &[String], line: usize, key: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        // `--extensions <classes>` and `--extensions=<classes>` (`Main`'s flag, one dash or two)
        let flag = ["--extensions", "-extensions"].iter().find_map(|f| arg.strip_prefix(f).filter(|rest| rest.is_empty() || rest.starts_with('=')));
        if let Some(rest) = flag {
            let value = match rest.strip_prefix('=') {
                Some(value) => value,
                None => iter.next().map_or("", String::as_str),
            };
            if value.trim_matches(['"', '\'']).split(',').any(|name| !name.trim().is_empty()) {
                findings.push(extensions_finding(format!("{} {value}", arg.split('=').next().unwrap_or(arg)), line, key));
            }
            continue;
        }
        let Some(rest) = arg.strip_prefix("-D") else { continue };
        let (name, value) = rest.split_once('=').unwrap_or((rest, ""));
        if let Some(k) = name.strip_prefix("mockserver.") {
            findings.push(Finding::new(JVM_PROPERTY, Severity::Info, line, shown_token(k, arg), "kept: the binary accepts -D arguments").key(key));
            findings.extend(config_setting(name, value, Source::Property).into_iter().map(|f| Finding { line, ..f }.key(key)));
        } else {
            findings.push(Finding::new(JVM_OTHER, Severity::Warn, line, redact_option(arg), "no effect: a JVM system property without a counterpart in mock-server").key(key));
        }
    }
    findings
}

/// `[registry/]mockserver/mockserver[:tag][@digest]`: the tag (empty when none), or `None` for another image.
pub fn mockserver_image_tag(reference: &str) -> Option<&str> {
    let reference = reference.trim().trim_matches(['"', '\'']);
    let without_digest = reference.split('@').next().unwrap_or(reference);
    let (name, tag) = match without_digest.rsplit_once(':') {
        Some((name, tag)) if !tag.contains('/') => (name, tag),
        _ => (without_digest, ""),
    };
    let name = name.strip_prefix("docker.io/").or_else(|| name.strip_prefix("index.docker.io/")).or_else(|| name.strip_prefix("public.ecr.aws/")).unwrap_or(name);
    (name == "mockserver/mockserver").then_some(tag)
}

/// The findings for an image reference that names the upstream image.
pub fn image_reference(reference: &str, line: usize, key: &str) -> Vec<Finding> {
    let Some(tag) = mockserver_image_tag(reference) else { return Vec::new() };
    let shown = reference.trim().trim_matches(['"', '\'']).to_string();
    let version = tag.strip_prefix("mockserver-").unwrap_or(tag);
    let mut verdict = "maps to the mock-server image (same port, environment, arguments and /config layout); the reference is rewritten once the image has a published name, until then use the locally built mock-server".to_string();
    if !version.is_empty() && version != crate::control::VERSION && version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        verdict.push_str(&format!("; mock-server behaves as MockServer {}, not {version}", crate::control::VERSION));
    }
    let mut findings = vec![Finding::new(IMAGE_REFERENCE, Severity::Rewrite, line, shown.clone(), verdict).key(key)];
    let lower = tag.to_ascii_lowercase();
    if let Some(variant) = ["graaljs", "snapshot", "root", "local", "aot"].into_iter().find(|v| lower.contains(v)) {
        findings.push(Finding::new(IMAGE_REFERENCE, Severity::Warn, line, shown, format!("the {variant} variant has no counterpart: the plain image is the target")).key(key));
    } else if lower.contains("clustered") {
        findings.push(Finding::new(IMAGE_REFERENCE, Severity::Info, line, shown, "no clustered variant: the same image with clusterEnabled").key(key));
    }
    findings
}

/// The MockServer level for a `java.util.logging`, Logback or Log4j level name.
pub fn log_level(level: &str) -> Option<&'static str> {
    Some(match level.trim().to_ascii_uppercase().as_str() {
        "FINEST" | "FINER" | "ALL" | "TRACE" => "TRACE",
        "FINE" | "DEBUG" => "DEBUG",
        "CONFIG" | "INFO" => "INFO",
        "WARNING" | "WARN" => "WARN",
        "SEVERE" | "ERROR" | "FATAL" => "ERROR",
        "OFF" => "OFF",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(findings: &[Finding]) -> Vec<(&str, Severity, String)> {
        findings.iter().map(|f| (f.rule, f.severity, f.found.clone())).collect()
    }

    #[test]
    fn configuration_keys_take_the_policy_tables_verdict() {
        assert_eq!(summary(&config_setting("mockserver.useNativeTransport", "false", Source::Property)), [(CONFIG_KEY, Severity::Info, "mockserver.useNativeTransport=false".to_string())]);
        assert_eq!(summary(&config_setting("mockserver.actionHandlerThreadCount", "3", Source::Property)), [(CONFIG_KEY, Severity::Warn, "mockserver.actionHandlerThreadCount=3".to_string())]);
        assert_eq!(summary(&config_setting("MOCKSERVER_NIO_EVENT_LOOP_THREAD_COUNT", "4", Source::Environment)), [(CONFIG_THREAD_COUNT, Severity::Info, "MOCKSERVER_NIO_EVENT_LOOP_THREAD_COUNT=4".to_string())]);
        assert_eq!(config_setting("mockserver.initializationClass", "org.acme.Init", Source::Property)[0].rule, CLASSPATH_INITIALIZER);
        assert_eq!(config_setting("mockserver.velocityDisallowClassLoading", "false", Source::Property)[0].rule, TEMPLATE_VELOCITY_CLASS);
        assert_eq!(config_setting("mockserver.velocityDisallowClassLoading", "true", Source::Property)[0].severity, Severity::Info);
        assert_eq!(config_setting("mockserver.forwardProxyTLSX509CertificatesTrustManagerType", "JVM", Source::Property)[0].severity, Severity::Info);
        assert_eq!(summary(&config_setting("mockserver.maxExpectations", "5", Source::Property)), [(CONFIG_KEY, Severity::Info, "mockserver.maxExpectations=5".to_string())]);
        assert_eq!(config_setting("mockserver.outputMemoryUsageCsv", "true", Source::Property)[0].rule, MEMORY_CSV);
        assert_eq!(config_setting("MOCKSERVER_BLOB_STORE_TYPE", "s3", Source::Environment)[0].rule, CLASSPATH_BLOB);
    }

    #[test]
    fn every_javascript_key_warns() {
        let javascript: Vec<&str> = crate::config::recognised_properties().iter().filter_map(|(k, _)| k.strip_prefix("mockserver.")).filter(|k| k.starts_with("javascript")).collect();
        assert!(!javascript.is_empty());
        for key in javascript {
            assert_eq!(config_setting(&format!("mockserver.{key}"), "x", Source::Property)[0].severity, Severity::Warn, "{key}");
        }
    }

    #[test]
    fn unknown_keys_get_the_servers_warning() {
        let found = config_setting("mockserver.typoThing", "1", Source::Property);
        assert_eq!(found[0].verdict, "unrecognised MockServer configuration properties-file key [mockserver.typoThing] - it is not a known configuration property and will be ignored (check for a typo)");
        assert_eq!(config_setting("MOCKSERVER_TYPO", "1", Source::Environment)[0].verdict.split(" - ").next(), Some("unrecognised MockServer configuration environment variable [MOCKSERVER_TYPO]"));
    }

    #[test]
    fn sensitive_values_are_not_shown() {
        let found = config_setting("MOCKSERVER_LLM_API_KEY", "sk-secret", Source::Environment);
        assert!(!found[0].found.contains("sk-secret"), "{:?}", found[0]);
        let (found, fate) = jvm_option("-Dmockserver.llmApiKey=sk-secret", &Context::default());
        assert!(found.iter().all(|f| !f.found.contains("sk-secret") && !f.replacement.as_deref().unwrap_or("").contains("sk-secret")), "{found:?}");
        assert_eq!(fate, Fate::Move { name: "MOCKSERVER_LLM_API_KEY".into(), value: "sk-secret".into() });
        assert!(!jvm_option("-Djavax.net.ssl.keyStorePassword=pw", &Context::default()).0[0].found.contains("pw"));
    }

    #[test]
    fn jvm_tokens_map_or_warn() {
        let ctx = Context::default();
        let (found, fate) = jvm_option("-Dmockserver.logLevel=INFO", &ctx);
        assert_eq!((found[0].rule, found[0].severity, found[0].replacement.as_deref()), (JVM_PROPERTY, Severity::Rewrite, Some("MOCKSERVER_LOG_LEVEL=INFO")));
        assert_eq!(fate, Fate::Move { name: "MOCKSERVER_LOG_LEVEL".into(), value: "INFO".into() });
        assert_eq!(jvm_option("-XX:ActiveProcessorCount=2", &ctx).1, Fate::Move { name: "MOCKSERVER_NIO_EVENT_LOOP_THREAD_COUNT".into(), value: "2".into() });
        assert_eq!(jvm_option("-Xmx256m", &ctx).0[0].rule, JVM_MEMORY);
        assert_eq!(jvm_option("-XX:MaxRAMPercentage=75", &ctx).0[0].rule, JVM_MEMORY);
        assert_eq!(jvm_option("-Djavax.net.ssl.trustStore=/t.jks", &ctx).0[0].severity, Severity::Action);
        assert!(jvm_option("-javaagent:/otel/opentelemetry-javaagent.jar", &ctx).0[0].verdict.contains("otelTracesEnabled"));
        assert_eq!(jvm_option("--add-opens=java.base/java.lang=ALL-UNNAMED", &ctx).0[0].rule, JVM_OTHER);
        assert_eq!(jvm_option("-Djava.util.logging.config.file=/config/logging.properties", &ctx).0[0].rule, JVM_LOGGING);
        let ctx = Context { logging_levels: [("logging.properties".to_string(), "DEBUG".to_string())].into(), ..Context::default() };
        assert_eq!(jvm_option("-Djava.util.logging.config.file=/config/logging.properties", &ctx).1, Fate::Move { name: "MOCKSERVER_LOG_LEVEL".into(), value: "DEBUG".into() });
    }

    #[test]
    fn a_jvm_options_variable_is_rewritten_token_by_token() {
        let text = "JAVA_TOOL_OPTIONS=-Dmockserver.logLevel=INFO -Xmx256m -XX:ActiveProcessorCount=2\n";
        let var = EnvVar { name: "JAVA_TOOL_OPTIONS".into(), value: text[18..text.len() - 1].into(), line: 1, key: "JAVA_TOOL_OPTIONS".into(), span: Some((18, text.len() - 1)), entry: Some((0, text.len())) };
        let render = |n: &str, v: &str| format!("{n}={v}\n");
        let none = |_: &str| None;
        let block = EnvBlock { insert_at: text.len(), render: &render, existing: &none };
        let found = env_var(&var, Some(&block), &Context::default());
        assert_eq!(summary(&found).iter().map(|(r, s, _)| (*r, *s)).collect::<Vec<_>>(), [
            (JVM_PROPERTY, Severity::Rewrite),
            (CONFIG_KEY, Severity::Info),
            (JVM_MEMORY, Severity::Info),
            (JVM_CPU, Severity::Rewrite),
        ]);
        assert!(found[0].mechanical && found[3].mechanical && !found[2].mechanical);
        let edits: Vec<Edit> = found.iter().flat_map(|f| f.edits.clone()).collect();
        assert_eq!(super::super::apply_edits(text, &edits).unwrap(), "JAVA_TOOL_OPTIONS=-Xmx256m\nMOCKSERVER_LOG_LEVEL=INFO\nMOCKSERVER_NIO_EVENT_LOOP_THREAD_COUNT=2\n");
        let only = "JAVA_OPTS=-Dmockserver.maxExpectations=5\nMOCKSERVER_MAX_EXPECTATIONS=1\n";
        let var = EnvVar { name: "JAVA_OPTS".into(), value: only[10..40].into(), line: 1, key: "JAVA_OPTS".into(), span: Some((10, 40)), entry: Some((0, 41)) };
        let existing = |n: &str| (n == "MOCKSERVER_MAX_EXPECTATIONS").then_some((69, 70));
        let block = EnvBlock { insert_at: only.len(), render: &render, existing: &existing };
        let edits: Vec<Edit> = env_var(&var, Some(&block), &Context::default()).into_iter().flat_map(|f| f.edits).collect();
        assert_eq!(super::super::apply_edits(only, &edits).unwrap(), "MOCKSERVER_MAX_EXPECTATIONS=5\n");
    }

    #[test]
    fn an_explicit_property_beats_a_derived_value() {
        let ctx = Context { logging_levels: [("logging.properties".to_string(), "DEBUG".to_string())].into(), ..Context::default() };
        let text = "JAVA_OPTS=-Djava.util.logging.config.file=/c/logging.properties -Dmockserver.logLevel=INFO\n";
        let span = (10, text.len() - 1);
        let var = EnvVar { name: "JAVA_OPTS".into(), value: text[span.0..span.1].into(), line: 1, key: "JAVA_OPTS".into(), span: Some(span), entry: Some((0, text.len())) };
        let render = |n: &str, v: &str| format!("{n}={v}\n");
        let none = |_: &str| None;
        let block = EnvBlock { insert_at: text.len(), render: &render, existing: &none };
        let found = env_var(&var, Some(&block), &ctx);
        assert_eq!(found[0].replacement, None, "{:?}", found[0]);
        let edits: Vec<Edit> = found.iter().flat_map(|f| f.edits.clone()).collect();
        assert_eq!(super::super::apply_edits(text, &edits).unwrap(), "MOCKSERVER_LOG_LEVEL=INFO\n");
    }

    #[test]
    fn command_line_properties_are_kept() {
        let found = command_args(&["-serverPort".into(), "1080".into(), "-Dmockserver.useNativeTransport=true".into(), "-Dfoo=bar".into()], 3, "command");
        assert_eq!(summary(&found).iter().map(|(r, s, _)| (*r, *s)).collect::<Vec<_>>(), [(JVM_PROPERTY, Severity::Info), (CONFIG_KEY, Severity::Info), (JVM_OTHER, Severity::Warn)]);
        assert!(found.iter().all(|f| f.line == 3));
    }

    #[test]
    fn extension_settings_are_blockers() {
        for (name, value, source) in [
            ("mockserver.extensions", "com.acme.Ext", Source::Property),
            ("MOCKSERVER_EXTENSIONS", "\"com.acme.A, com.acme.B\"", Source::Environment),
            ("mockserver.extensionScanning", "true", Source::Property),
            ("MOCKSERVER_EXTENSION_SCANNING", "TRUE", Source::Environment),
        ] {
            let found = config_setting(name, value, source);
            assert_eq!(summary(&found), [(CLASSPATH_EXTENSIONS, Severity::Blocker, format!("{name}={value}"))], "{name}");
            assert!(found[0].verdict.contains(EXTENSIONS_REASON), "{}", found[0].verdict);
        }
        // blank names are skipped and scanning off is the default: start-up is unchanged
        assert_eq!(config_setting("MOCKSERVER_EXTENSIONS", " , ", Source::Environment)[0].rule, CONFIG_KEY);
        assert_eq!(config_setting("mockserver.extensionScanning", "false", Source::Property)[0].rule, CONFIG_KEY);
        assert_eq!(config_setting("mockserver.extensionStartTimeoutMillis", "500", Source::Property)[0].rule, CONFIG_KEY);
    }

    #[test]
    fn extension_flags_and_properties_on_a_command_line() {
        let args = |list: &[&str]| -> Vec<String> { list.iter().map(|s| s.to_string()).collect() };
        for list in [&["--extensions", "com.acme.Ext"][..], &["-extensions", "com.acme.Ext"], &["--extensions=com.acme.Ext"]] {
            let found = command_args(&args(list), 4, "CMD");
            assert_eq!(found.len(), 1, "{list:?}");
            assert_eq!((found[0].rule, found[0].severity, found[0].line), (CLASSPATH_EXTENSIONS, Severity::Blocker, 4));
            assert!(found[0].found.ends_with("com.acme.Ext"), "{}", found[0].found);
        }
        assert!(command_args(&args(&["--extensions", " , ", "-serverPort", "1080"]), 1, "CMD").is_empty());
        assert!(command_args(&args(&["--extensionsX", "a"]), 1, "CMD").is_empty());
        let found = command_args(&args(&["-Dmockserver.extensions=com.acme.Ext"]), 1, "CMD");
        assert_eq!(found.iter().map(|f| f.rule).collect::<Vec<_>>(), [JVM_PROPERTY, CLASSPATH_EXTENSIONS]);
    }

    #[test]
    fn image_references_and_variants() {
        assert_eq!(mockserver_image_tag("mockserver/mockserver:mockserver-8.0.0"), Some("mockserver-8.0.0"));
        assert_eq!(mockserver_image_tag("docker.io/mockserver/mockserver"), Some(""));
        assert_eq!(mockserver_image_tag("\"mockserver/mockserver:8.0.0@sha256:abc\""), Some("8.0.0"));
        assert_eq!(mockserver_image_tag("mockserver/mockserver-webhook:8.0.0"), None);
        assert_eq!(mockserver_image_tag("localhost:5000/mockserver/mockserver"), None);
        let found = image_reference("mockserver/mockserver:graaljs-8.0.0", 1, "image");
        assert_eq!(summary(&found).iter().map(|(r, s, _)| (*r, *s)).collect::<Vec<_>>(), [(IMAGE_REFERENCE, Severity::Rewrite), (IMAGE_REFERENCE, Severity::Warn)]);
        assert!(!found[0].mechanical, "the image tag has no mechanical rewrite");
        assert!(image_reference("mockserver/mockserver:5.15.0", 1, "image")[0].verdict.ends_with("; mock-server behaves as MockServer 9.2.0, not 5.15.0"));
        assert!(image_reference("mockserver/mockserver:mockserver-8.0.0", 1, "image")[0].verdict.ends_with("; mock-server behaves as MockServer 9.2.0, not 8.0.0"));
        assert!(!image_reference("mockserver/mockserver:mockserver-9.2.0", 1, "image")[0].verdict.contains("behaves as"));
        assert!(!image_reference("mockserver/mockserver:9.2.0", 1, "image")[0].verdict.contains("behaves as"));
    }

    #[test]
    fn levels_map_to_mockservers() {
        assert_eq!(log_level("FINE"), Some("DEBUG"));
        assert_eq!(log_level("finest"), Some("TRACE"));
        assert_eq!(log_level("WARNING"), Some("WARN"));
        assert_eq!(log_level("SEVERE"), Some("ERROR"));
        assert_eq!(log_level("loud"), None);
    }

    #[test]
    fn rule_ids_are_unique() {
        let mut ids: Vec<&str> = RULES.iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len());
    }
}

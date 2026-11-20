//! The report: text grouped by file with a summary and next steps, or JSON
//! (`{"version":1,"findings":[…],"summary":{…}}`) for CI.

use serde_json::{json, Map, Value};

use super::rules;
use super::{FileReport, Finding, Severity};

/// What to do next for each rule that needs a person.
const NEXT_STEPS: &[(&str, &str)] = &[
    (rules::TEMPLATE_JAVASCRIPT, "rewrite each JAVASCRIPT template in Velocity or Mustache"),
    (rules::PACKAGING_WAR, "run the mock-server container beside the servlet container instead of the WAR"),
    (rules::PACKAGING_MAVEN, "replace in-JVM servers with Testcontainers' MockServerContainer on the mock-server image, or the Java launcher (java-launcher/)"),
    (rules::PACKAGING_JAR, "start the mock-server binary (or image) instead of the fat jar; the arguments stay"),
    (rules::IMAGE_TESTCONTAINERS, "use the mock-server image with asCompatibleSubstituteFor(\"mockserver/mockserver\")"),
    (rules::CLASSPATH_LIBS, "build the classes on /libs as callback plugins (docs/callback-plugins.md)"),
    (rules::CLASSPATH_CALLBACK, "build each callback class as a callback plugin (docs/callback-plugins.md); expectations keep the class names"),
    (rules::CLASSPATH_INITIALIZER, "build the initializer as a plugin initializer, or move its expectations to initializationJsonPath"),
    (rules::CLASSPATH_BLOB, "select the built-in blob stores with MOCKSERVER_BLOB_STORE_MODULES"),
    (rules::CLASSPATH_EXTENSIONS, "remove the extension names, flags and /extensions mounts: a Java extension is not loaded and a named one refuses start-up (extensions resolve through callback providers); move its job to a callback plugin or an expectation"),
    (rules::TEMPLATE_VELOCITY_CLASS, "remove class access from Velocity templates: the sandbox stays on"),
    (rules::METRICS_JVM_SERIES, "move dashboards and alerts off the jvm_* series to the replacement queries shown; check their thresholds, the meaning changes"),
    (rules::JVM_TLS, "give TLS material as PEM files (forwardProxyTLSCustomTrustX509Certificates, privateKeyPath, x509CertificatePath)"),
];

fn shown(f: &Finding) -> bool {
    f.severity > Severity::Info
}

/// The finding's message: what was found, its replacement, and the verdict where the replacement does not say it all.
fn message(f: &Finding) -> String {
    let mut out = f.found.clone();
    if let Some(replacement) = &f.replacement {
        out.push_str(" -> ");
        out.push_str(replacement);
    }
    if f.severity != Severity::Rewrite || f.replacement.is_none() {
        out.push_str(": ");
        out.push_str(&f.verdict);
    }
    out
}

fn counts(reports: &[FileReport]) -> [usize; 5] {
    let mut counts = [0; 5];
    for f in reports.iter().flat_map(|r| &r.findings) {
        counts[f.severity as usize] += 1;
    }
    counts
}

/// The text report.
pub fn text(reports: &[FileReport], written: &[String], verbose: bool, applied: bool) -> String {
    let mut out = String::new();
    for report in reports {
        let visible: Vec<&Finding> = report.findings.iter().filter(|f| verbose || shown(f)).collect();
        if visible.is_empty() {
            continue;
        }
        out.push_str(&report.display);
        out.push('\n');
        for f in visible {
            let line = if f.line == 0 { "-".to_string() } else { f.line.to_string() };
            let mark = if applied && f.mechanical { "  [applied]" } else { "" };
            out.push_str(&format!("{line:>5}  {:<8} {:<24} {}{mark}\n", f.severity.name(), f.rule, message(f)));
        }
    }
    let c = counts(reports);
    let mut summary = format!("summary: {} rewrite, {} warn, {} action, {} blocker", c[1], c[2], c[3], c[4]);
    if verbose {
        summary = format!("summary: {} info, {}", c[0], &summary["summary: ".len()..]);
    }
    let pending = reports.iter().flat_map(|r| &r.findings).any(|f| f.mechanical && !f.edits.is_empty());
    if pending && !applied {
        summary.push_str("  (run with --write to apply the rewrites)");
    }
    out.push_str(&summary);
    out.push('\n');
    for path in written {
        out.push_str(&format!("wrote {path}\n"));
    }
    let mut steps: Vec<&str> = Vec::new();
    for (rule, step) in NEXT_STEPS {
        if reports.iter().flat_map(|r| &r.findings).any(|f| f.rule == *rule && f.severity >= Severity::Action) {
            steps.push(step);
        }
    }
    if !steps.is_empty() {
        out.push_str("next steps:\n");
        for step in steps {
            out.push_str(&format!("  - {step}\n"));
        }
    }
    out
}

/// The JSON report.
pub fn json(reports: &[FileReport], written: &[String], applied: bool) -> String {
    let findings: Vec<Value> = reports
        .iter()
        .flat_map(|r| {
            r.findings.iter().map(move |f| {
                let mut o = Map::new();
                o.insert("file".into(), json!(r.display));
                o.insert("line".into(), json!(f.line));
                o.insert("key".into(), json!(f.key));
                o.insert("rule".into(), json!(f.rule));
                o.insert("severity".into(), json!(f.severity.name()));
                o.insert("found".into(), json!(f.found));
                o.insert("verdict".into(), json!(f.verdict));
                o.insert("replacement".into(), json!(f.replacement));
                o.insert("mechanical".into(), json!(f.mechanical));
                o.insert("applied".into(), json!(applied && f.mechanical));
                Value::Object(o)
            })
        })
        .collect();
    let c = counts(reports);
    let mut summary = Map::new();
    for s in Severity::ALL {
        summary.insert(s.name().into(), json!(c[s as usize]));
    }
    summary.insert("files".into(), json!(reports.len()));
    summary.insert("written".into(), json!(written));
    let mut document = Map::new();
    document.insert("version".into(), json!(1));
    document.insert("findings".into(), Value::Array(findings));
    document.insert("summary".into(), Value::Object(summary));
    let mut text = serde_json::to_string_pretty(&Value::Object(document)).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn report() -> Vec<FileReport> {
        vec![FileReport {
            display: "deploy/docker-compose.yml".into(),
            path: None,
            relative: PathBuf::new(),
            findings: vec![
                Finding::new(rules::IMAGE_REFERENCE, Severity::Rewrite, 3, "mockserver/mockserver", "maps"),
                Finding::new(rules::JVM_PROPERTY, Severity::Rewrite, 5, "JAVA_TOOL_OPTIONS -Dmockserver.logLevel=INFO", "moves").replacement("MOCKSERVER_LOG_LEVEL=INFO").mechanical(vec![super::super::Edit::insert(0, "x")]),
                Finding::new(rules::CONFIG_KEY, Severity::Info, 5, "mockserver.logLevel=INFO", "supported as-is"),
                Finding::new(rules::CLASSPATH_LIBS, Severity::Action, 9, "./a.jar mounted on /libs", "plugins"),
            ],
        }]
    }

    #[test]
    fn text_report() {
        assert_eq!(
            text(&report(), &[], false, false),
            "deploy/docker-compose.yml\n    3  rewrite  image.reference          mockserver/mockserver: maps\n    5  rewrite  jvm.options.property     JAVA_TOOL_OPTIONS -Dmockserver.logLevel=INFO -> MOCKSERVER_LOG_LEVEL=INFO\n    9  action   classpath.libs           ./a.jar mounted on /libs: plugins\nsummary: 2 rewrite, 0 warn, 1 action, 0 blocker  (run with --write to apply the rewrites)\nnext steps:\n  - build the classes on /libs as callback plugins (docs/callback-plugins.md)\n"
        );
        let verbose = text(&report(), &["deploy/docker-compose.yml".into()], true, true);
        assert!(verbose.contains("    5  info     config.key"), "{verbose}");
        assert!(verbose.contains("MOCKSERVER_LOG_LEVEL=INFO  [applied]\n"), "{verbose}");
        assert!(verbose.contains("summary: 1 info, 2 rewrite, 0 warn, 1 action, 0 blocker\nwrote deploy/docker-compose.yml\n"), "{verbose}");
    }

    #[test]
    fn json_report() {
        let value: Value = serde_json::from_str(&json(&report(), &[], false)).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["findings"].as_array().unwrap().len(), 4);
        assert_eq!(value["findings"][1]["replacement"], "MOCKSERVER_LOG_LEVEL=INFO");
        assert_eq!(value["summary"]["rewrite"], 2);
        assert_eq!(value["summary"]["info"], 1);
    }
}

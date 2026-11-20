//! Observability inputs (`metrics.*`): Grafana
//! dashboards, Prometheus rule files and alert definitions, and `prometheus.yml` scrape configurations, also when a
//! Kubernetes `ConfigMap` holds them as a block scalar.
//!
//! - `metrics.jvm-series`: the PromQL of dashboard targets and variables and of `expr:` in rule files (alerting and
//!   recording rules) is searched for the `jvm_memory_*`, `jvm_gc_*`, `jvm_threads_*`, `jvm_buffer_*` and
//!   `jvm_classes_*` series, and for `process_*` names mock-server does not emit. Each gets a replacement
//!   query and caveat. The rule never rewrites: the meaning changes (RSS is not a heap, there is no garbage collector).
//!   Only files that mention MockServer (`mockserver`, `mock_server`) are searched, so a dashboard of another JVM
//!   service in the same repository is left alone.
//! - `metrics.dashboard`: upstream's example dashboards, recognised by uid, are replaced by ours from `grafana/` with
//!   `--replace-dashboards` (it overwrites local edits, so `--write` alone does not). Ours are embedded in the binary,
//!   so the `FROM scratch` image can write them.
//! - `metrics.scrape`: a scrape of `/mockserver/metrics` is reported as unchanged.

use std::collections::BTreeSet;

use serde_json::Value;

use super::rules;
use super::yaml::{self, Style};
use super::{Context, Edit, Finding, Severity};

/// mock-server's server dashboard.
pub const SERVER_DASHBOARD: &str = include_str!("../../grafana/mock-server-server.json");
/// mock-server's load-injection dashboard.
pub const LOAD_INJECTION_DASHBOARD: &str = include_str!("../../grafana/mock-server-load-injection.json");

/// Upstream's example dashboards by uid, each with the path and contents of ours that replaces it.
pub const DASHBOARDS: [(&str, &str, &str); 2] = [
    ("mockserver-server", "grafana/mock-server-server.json", SERVER_DASHBOARD),
    ("mockserver-load-injection", "grafana/mock-server-load-injection.json", LOAD_INJECTION_DASHBOARD),
];

/// The series families of MockServer's JVM collector and of the JVM client conventions the rule looks for.
const JVM_FAMILIES: [&str; 5] = ["jvm_memory_", "jvm_gc_", "jvm_threads_", "jvm_buffer_", "jvm_classes_"];

/// The `process_*` series mock-server emits on the scrape (`src/metrics.rs`).
const EMITTED_PROCESS: [&str; 9] = [
    "process_cpu_seconds_total",
    "process_max_resident_memory_bytes",
    "process_resident_memory_bytes",
    "process_virtual_memory_bytes",
    "process_virtual_memory_max_bytes",
    "process_open_fds",
    "process_max_fds",
    "process_start_time_seconds",
    "process_threads",
];

/// The dashboard JSON keys whose strings are PromQL: target expressions and variable queries.
const QUERY_KEYS: [&str; 3] = ["expr", "query", "definition"];

const NOT_REWRITTEN: &str = "never rewritten, the meaning changes";

/// The dashboard object of a Grafana dashboard document (the file itself, or the `dashboard` of an API export).
fn dashboard_of(document: &Value) -> Option<&serde_json::Map<String, Value>> {
    let object = document.as_object()?;
    let inner = object.get("dashboard").and_then(Value::as_object).unwrap_or(object);
    (inner.contains_key("panels") && inner.contains_key("schemaVersion")).then_some(inner)
}

/// Whether `text` is a Grafana dashboard (`"panels"` and `"schemaVersion"`).
pub fn is_dashboard(text: &str) -> bool {
    text.contains("\"panels\"") && text.contains("\"schemaVersion\"") && serde_json::from_str::<Value>(text).ok().as_ref().and_then(dashboard_of).is_some()
}

/// Whether YAML `text` holds Prometheus configuration: scrape jobs, rule groups, or a scrape path of MockServer's.
pub fn is_prometheus(text: &str) -> bool {
    text.contains("scrape_configs:") || (text.contains("groups:") && text.contains("expr:")) || text.contains("/mockserver/metrics")
}

fn about_mockserver(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("mockserver") || lower.contains("mock_server")
}

/// One series reference in a PromQL expression: its name, the inside of its `{...}` selector, and its byte range
/// (the selector included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Series {
    pub name: String,
    pub selector: Option<String>,
    pub start: usize,
    pub end: usize,
}

fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b':'
}

/// Whether the rule reports this series name.
fn reported(name: &str) -> bool {
    JVM_FAMILIES.iter().any(|f| name.starts_with(f)) || (name.starts_with("process_") && !EMITTED_PROCESS.contains(&name))
}

/// The reported series of a PromQL expression, in order.
pub fn series(expr: &str) -> Vec<Series> {
    let bytes = expr.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let boundary = i == 0 || !is_name_char(bytes[i - 1]);
        if !boundary || !(bytes[i..].starts_with(b"jvm_") || bytes[i..].starts_with(b"process_")) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_name_char(bytes[i]) {
            i += 1;
        }
        let name = &expr[start..i];
        if !reported(name) {
            continue;
        }
        let mut end = i;
        let mut selector = None;
        let open = i + (expr[i..].len() - expr[i..].trim_start().len());
        if bytes.get(open) == Some(&b'{') && let Some(close) = selector_end(expr, open) {
            selector = Some(expr[open + 1..close].to_string());
            end = close + 1;
        }
        out.push(Series { name: name.to_string(), selector, start, end });
        i = end;
    }
    out
}

/// The offset of the `}` closing the selector that opens at `open`, quotes respected.
fn selector_end(expr: &str, open: usize) -> Option<usize> {
    let bytes = expr.as_bytes();
    let mut quote = None;
    let mut i = open + 1;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) if b == b'\\' && q != b'`' => i += 1,
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' || b == b'`' => quote = Some(b),
            None if b == b'}' => return Some(i),
            None => {}
        }
        i += 1;
    }
    None
}

/// The matchers of a selector, split on the commas outside quotes.
fn matchers(selector: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut quote = None;
    let mut from = 0;
    let bytes = selector.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) if b == b'\\' && q != b'`' => i += 1,
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' || b == b'`' => quote = Some(b),
            None if b == b',' => {
                out.push(selector[from..i].trim());
                from = i + 1;
            }
            None => {}
        }
        i += 1;
    }
    out.push(selector[from..].trim());
    out.retain(|m| !m.is_empty());
    out
}

/// A matcher's label, whether it negates, and its value without quotes.
fn matcher_parts(matcher: &str) -> (&str, bool, &str) {
    let at = matcher.find(['=', '!']).unwrap_or(matcher.len());
    let label = matcher[..at].trim();
    let rest = &matcher[at..];
    let negated = rest.starts_with('!');
    let value = rest.trim_start_matches(['=', '!', '~']).trim().trim_matches(['"', '\'', '`']);
    (label, negated, value)
}

/// Which JVM memory area a selector picks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Area {
    Heap,
    NonHeap,
    Both,
}

fn area(matchers: &[&str]) -> Area {
    let Some((_, negated, value)) = matchers.iter().map(|m| matcher_parts(m)).find(|(label, _, _)| *label == "area") else { return Area::Both };
    let value = value.to_ascii_lowercase();
    let nonheap = value.contains("nonheap");
    let heap = value.replace("nonheap", "").contains("heap");
    match (heap, nonheap, negated) {
        (true, false, false) | (false, true, true) => Area::Heap,
        (false, true, false) | (true, false, true) => Area::NonHeap,
        _ => Area::Both,
    }
}

/// The replacement for one series (its other matchers carried over) and the caveat.
pub fn mapping(series: &Series) -> (Option<String>, String) {
    let all = series.selector.as_deref().map(matchers).unwrap_or_default();
    let kept: Vec<&str> = all.iter().copied().filter(|m| matcher_parts(m).0 != "area").collect();
    let sel = if kept.is_empty() { String::new() } else { format!("{{{}}}", kept.join(", ")) };
    let rss = format!("process_resident_memory_bytes{sel}");
    let name = series.name.as_str();
    let (replacement, verdict) = match name {
        "jvm_memory_used_bytes" => match area(&all) {
            Area::Heap => (Some(rss), "RSS: the whole process, not a heap; review the thresholds".to_string()),
            Area::NonHeap => (None, "no counterpart: drop the panel or the rule".to_string()),
            Area::Both => (Some(rss), "RSS: the whole process, heap and non-heap alike, not a heap; review the thresholds".to_string()),
        },
        "jvm_memory_committed_bytes" => (Some(rss), format!("RSS, not committed memory; process_virtual_memory_bytes{sel} for reserved address space")),
        "jvm_memory_max_bytes" => (
            Some("container_spec_memory_limit_bytes".to_string()),
            "the container's memory limit (cAdvisor) bounds the process; process_virtual_memory_max_bytes only when an address-space rlimit is set".to_string(),
        ),
        "jvm_threads_current" => (Some(format!("process_threads{sel}")), format!("OS threads, not Java threads; tokio_live_tasks_count{sel} for concurrency")),
        _ if name.starts_with("jvm_gc_") => (
            Some(format!("sum(rate(tokio_worker_busy_seconds_total{sel}[5m])) / sum(tokio_workers_count{sel})")),
            "no garbage collector; the tokio workers' busy share shows runtime saturation instead".to_string(),
        ),
        _ if name.starts_with("process_") => {
            return (None, format!("mock-server does not emit {name}: a figure the platform cannot give is left out, not faked"));
        }
        _ => (None, "no counterpart in mock-server: drop the panel or the rule".to_string()),
    };
    (replacement, format!("{verdict}; {NOT_REWRITTEN}"))
}

/// The `metrics.jvm-series` findings of one PromQL expression; `line_at` gives the line of an offset in it.
fn series_findings(expr: &str, line_at: &dyn Fn(usize) -> usize, key: &str) -> Vec<Finding> {
    let mut seen = BTreeSet::new();
    let mut findings = Vec::new();
    for s in series(expr) {
        let found = expr[s.start..s.end].split_whitespace().collect::<Vec<_>>().join(" ");
        if !seen.insert(found.clone()) {
            continue;
        }
        let (replacement, verdict) = mapping(&s);
        let mut finding = Finding::new(rules::METRICS_JVM_SERIES, Severity::Action, line_at(s.start), found, verdict).key(key);
        if let Some(replacement) = replacement {
            finding = finding.replacement(replacement);
        }
        findings.push(finding);
    }
    findings
}

/// The PromQL strings of a dashboard document with their key paths, in file order.
fn queries<'a>(value: &'a Value, path: &str, out: &mut Vec<(String, &'a str)>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                match v {
                    Value::String(s) if QUERY_KEYS.contains(&k.as_str()) => out.push((p, s.as_str())),
                    _ => queries(v, &p, out),
                }
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                queries(v, &format!("{path}[{i}]"), out);
            }
        }
        _ => {}
    }
}

/// The line of the dashboard's `"uid": "<uid>"`, 0 when the text spells it otherwise.
fn uid_line(text: &str, uid: &str) -> usize {
    let quoted = serde_json::to_string(uid).unwrap_or_default();
    let mut at = 0;
    while let Some(i) = text[at..].find("\"uid\"") {
        let start = at + i;
        at = start + 5;
        if let Some(rest) = text[at..].trim_start().strip_prefix(':') && rest.trim_start().starts_with(&quoted) {
            return super::line_of(text, start);
        }
    }
    0
}

/// The findings of one Grafana dashboard.
pub fn scan_dashboard(text: &str, ctx: &Context) -> Vec<Finding> {
    let Ok(document) = serde_json::from_str::<Value>(text) else { return Vec::new() };
    let Some(dashboard) = dashboard_of(&document) else { return Vec::new() };
    let uid = dashboard.get("uid").and_then(Value::as_str).unwrap_or("");
    let upstream = DASHBOARDS.iter().find(|(u, _, _)| *u == uid);
    let replaced = upstream.is_some() && ctx.replace_dashboards;
    let mut findings = Vec::new();
    if let Some((uid, ours, contents)) = upstream {
        let verdict = if replaced {
            format!("upstream's example dashboard: replaced with mock-server's {ours} (the mock_server_* panels stay; process and tokio rows take the JVM row's place); local edits are overwritten")
        } else {
            format!("upstream's example dashboard: mock-server ships {ours} in its place (the mock_server_* panels stay; process and tokio rows take the JVM row's place); --write --replace-dashboards replaces this file with it, overwriting local edits")
        };
        let finding = Finding::new(rules::METRICS_DASHBOARD, Severity::Rewrite, uid_line(text, uid), format!("dashboard uid {uid}"), verdict).key("uid");
        findings.push(if replaced { finding.mechanical(vec![Edit::replace(0, text.len(), *contents)]) } else { finding });
    }
    if about_mockserver(text) {
        let mut found = Vec::new();
        queries(&document, "", &mut found);
        let mut cursor = 0;
        for (key, expr) in found {
            if series(expr).is_empty() {
                continue;
            }
            let quoted = serde_json::to_string(expr).unwrap_or_default();
            let line = match text[cursor..].find(&quoted) {
                Some(i) => {
                    cursor += i + quoted.len();
                    super::line_of(text, cursor - quoted.len())
                }
                None => 0,
            };
            for f in series_findings(expr, &|_: usize| line, &key) {
                findings.push(if replaced {
                    let verdict = format!("{}; the dashboard is replaced (metrics.dashboard)", f.verdict);
                    Finding { verdict, ..f }.mechanical(Vec::new())
                } else {
                    f
                });
            }
        }
    }
    findings
}

/// The findings of Prometheus configuration in YAML: rule files and alert definitions (`expr:`), scrape jobs, and
/// the same inside a block scalar (a `ConfigMap`'s `prometheus.yml: |`).
pub fn scan_prometheus(text: &str) -> Vec<Finding> {
    scan_yaml(text, 0, "", about_mockserver(text))
}

fn scan_yaml(text: &str, line_offset: usize, prefix: &str, about: bool) -> Vec<Finding> {
    let entries = yaml::scan(text);
    let mut findings = Vec::new();
    for entry in &entries {
        let Some(value) = &entry.value else { continue };
        let key = entry.key.as_deref().unwrap_or("");
        let path = if prefix.is_empty() { entry.path_string() } else { format!("{prefix}.{}", entry.path_string()) };
        if value.style == Style::Block && key != "expr" && is_prometheus(&value.text) {
            findings.extend(scan_yaml(&value.text, line_offset + value.first_line - 1, &path, about));
            continue;
        }
        let scrape_path = match key {
            "metrics_path" | "prometheus.io/path" => true,
            "path" => entry.path.iter().any(|s| s == "endpoints" || s == "podMetricsEndpoints"),
            _ => false,
        };
        if key == "expr" && about {
            let block = value.style == Style::Block;
            let line_at = |offset: usize| line_offset + if block { value.first_line + value.text[..offset].matches('\n').count() } else { entry.line };
            findings.extend(series_findings(&value.text, &line_at, &path));
        } else if scrape_path && value.text.trim().starts_with("/mockserver/metrics") {
            let parent = &entry.path[..entry.path.len() - 1];
            let job = entries.iter().find(|e| e.doc == entry.doc && e.key.as_deref() == Some("job_name") && e.path.len() == entry.path.len() && e.path[..parent.len()] == *parent);
            let found = match job {
                Some(job) => format!("job {}: {key} {}", job.text(), value.text.trim()),
                None => format!("{key} {}", value.text.trim()),
            };
            findings.push(
                Finding::new(rules::METRICS_SCRAPE, Severity::Info, line_offset + entry.line, found, "unchanged: mock-server serves the same path with the mock_server_* families; process_* and tokio_* series take the jvm_* ones' place")
                    .key(path),
            );
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(findings: &[Finding]) -> Vec<(&str, Severity, usize, String, Option<String>)> {
        findings.iter().map(|f| (f.rule, f.severity, f.line, f.found.clone(), f.replacement.clone())).collect()
    }

    #[test]
    fn series_are_found_with_their_selectors() {
        let expr = "rate(jvm_gc_collection_seconds_sum{job=\"a,b}\"}[1m]) + jvm_threads_current + my_jvm_memory_used_bytes + process_heap_bytes + process_threads";
        let names: Vec<(String, Option<String>)> = series(expr).into_iter().map(|s| (s.name, s.selector)).collect();
        assert_eq!(names, [
            ("jvm_gc_collection_seconds_sum".to_string(), Some("job=\"a,b}\"".to_string())),
            ("jvm_threads_current".into(), None),
            ("process_heap_bytes".into(), None),
        ]);
        assert!(series("mock_server_requests_received_total").is_empty());
        assert_eq!(series("jvm_buffer_memory_used_bytes {pool = \"direct\"}")[0].selector.as_deref(), Some("pool = \"direct\""));
        assert_eq!(series("jvm_classes_loaded")[0].name, "jvm_classes_loaded");
    }

    #[test]
    fn the_adr_mapping_with_the_other_matchers_kept() {
        let map = |expr: &str| mapping(&series(expr)[0]);
        let (replacement, verdict) = map("jvm_memory_used_bytes{area=\"heap\", job=\"mockserver\"}");
        assert_eq!(replacement.as_deref(), Some("process_resident_memory_bytes{job=\"mockserver\"}"));
        assert!(verdict.starts_with("RSS: the whole process, not a heap") && verdict.ends_with("never rewritten, the meaning changes"), "{verdict}");
        assert_eq!(map("jvm_memory_used_bytes{area=\"nonheap\"}").0, None);
        assert_eq!(map("jvm_memory_used_bytes{area!=\"heap\"}").0, None);
        assert!(map("jvm_memory_used_bytes").1.contains("heap and non-heap alike"));
        assert_eq!(map("jvm_memory_committed_bytes{area=\"heap\"}").0.as_deref(), Some("process_resident_memory_bytes"));
        assert!(map("jvm_memory_committed_bytes").1.contains("process_virtual_memory_bytes"));
        assert_eq!(map("jvm_memory_max_bytes{area=\"heap\"}").0.as_deref(), Some("container_spec_memory_limit_bytes"));
        assert_eq!(map("jvm_threads_current{job=\"m\"}").0.as_deref(), Some("process_threads{job=\"m\"}"));
        assert_eq!(map("jvm_threads_daemon").0, None);
        assert_eq!(map("jvm_gc_collection_count").0.as_deref(), Some("sum(rate(tokio_worker_busy_seconds_total[5m])) / sum(tokio_workers_count)"));
        assert!(map("jvm_gc_collection_count").1.starts_with("no garbage collector"));
        assert_eq!(map("jvm_classes_loaded").0, None);
        assert!(map("process_heap_bytes").1.contains("does not emit process_heap_bytes"));
    }

    #[test]
    fn upstreams_dashboards_are_recognised_and_replaced_only_when_asked() {
        let text = "{\n  \"schemaVersion\": 39,\n  \"uid\": \"mockserver-server\",\n  \"panels\": [\n    { \"targets\": [ { \"expr\": \"jvm_threads_current\" } ] }\n  ]\n}\n";
        assert!(is_dashboard(text));
        let findings = scan_dashboard(text, &Context::default());
        assert_eq!(found(&findings), [
            (rules::METRICS_DASHBOARD, Severity::Rewrite, 3, "dashboard uid mockserver-server".to_string(), None),
            (rules::METRICS_JVM_SERIES, Severity::Action, 5, "jvm_threads_current".to_string(), Some("process_threads".to_string())),
        ]);
        assert!(!findings[0].mechanical && findings[0].verdict.contains("--replace-dashboards"));
        assert_eq!(findings[1].key.as_deref(), Some("panels[0].targets[0].expr"));
        let ctx = Context { replace_dashboards: true, ..Context::default() };
        let findings = scan_dashboard(text, &ctx);
        assert!(findings.iter().all(|f| f.mechanical));
        let edits: Vec<Edit> = findings.iter().flat_map(|f| f.edits.clone()).collect();
        assert_eq!(super::super::apply_edits(text, &edits).unwrap(), SERVER_DASHBOARD);
    }

    #[test]
    fn ours_and_unrelated_dashboards_have_no_findings() {
        for (_, _, ours) in DASHBOARDS {
            assert!(is_dashboard(ours));
            assert_eq!(scan_dashboard(ours, &Context::default()), Vec::new());
        }
        let spring = "{\"schemaVersion\": 39, \"uid\": \"spring\", \"panels\": [{\"targets\": [{\"expr\": \"jvm_memory_used_bytes{job=\\\"orders\\\"}\"}]}]}";
        assert!(scan_dashboard(spring, &Context::default()).is_empty(), "a dashboard that is not about MockServer");
        assert!(!is_dashboard("{\"panels\": []}"));
    }

    #[test]
    fn rule_files_report_each_expression_on_its_line() {
        let text = "groups:\n  - name: mockserver\n    rules:\n      - record: heap\n        expr: max_over_time(jvm_memory_used_bytes{area=\"heap\"}[5m])\n      - alert: Full\n        expr: |\n          jvm_memory_used_bytes{area=\"heap\"}\n            / jvm_memory_max_bytes{area=\"heap\"} > 0.9\n";
        assert!(is_prometheus(text));
        let findings = scan_prometheus(text);
        let lines: Vec<(usize, &str)> = findings.iter().map(|f| (f.line, f.found.as_str())).collect();
        assert_eq!(lines, [(5, "jvm_memory_used_bytes{area=\"heap\"}"), (8, "jvm_memory_used_bytes{area=\"heap\"}"), (9, "jvm_memory_max_bytes{area=\"heap\"}")]);
        assert_eq!(findings[0].key.as_deref(), Some("groups[0].rules[0].expr"));
        assert!(findings.iter().all(|f| !f.mechanical && f.severity == Severity::Action));
    }

    #[test]
    fn scrape_jobs_are_unchanged_also_inside_a_config_map() {
        let text = "apiVersion: v1\nkind: ConfigMap\ndata:\n  prometheus.yml: |\n    scrape_configs:\n      - job_name: mockserver\n        metrics_path: /mockserver/metrics\n      - job_name: other\n        metrics_path: /metrics\n";
        assert!(is_prometheus(text));
        assert_eq!(found(&scan_prometheus(text)), [(rules::METRICS_SCRAPE, Severity::Info, 7, "job mockserver: metrics_path /mockserver/metrics".to_string(), None)]);
        let monitor = "kind: ServiceMonitor\nspec:\n  endpoints:\n    - port: http\n      path: /mockserver/metrics\n";
        assert_eq!(scan_prometheus(monitor)[0].line, 5);
        assert!(scan_prometheus("spec:\n  httpGet:\n    path: /mockserver/metrics\n").is_empty(), "a probe is not a scrape");
    }
}

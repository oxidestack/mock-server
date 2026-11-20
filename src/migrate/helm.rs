//! Values of the upstream `mockserver` Helm chart: a `values*.yaml` next to a `Chart.yaml` that is or
//! depends on the chart, or `--helm-values FILE`. The chart itself keeps working with
//! `image.repositoryNameAndTag` set; `app.jvmOptions` feeds `JAVA_TOOL_OPTIONS` and follows the `jvm.options.*` rules,
//! its mapped tokens moving into `app.extraEnv`.

use std::cell::Cell;

use super::rules::{self, EnvBlock, EnvVar};
use super::yaml::{self, Entry, Style};
use super::{Context, Edit, Finding, Severity};

/// Where the chart's values sit in a values file: `[]` for the chart's own values, `["mockserver"]` (or the
/// dependency's alias) when the chart is a dependency.
pub fn prefix_for(chart_yaml: &str) -> Option<Vec<String>> {
    let entries = yaml::scan(chart_yaml);
    if entries.iter().any(|e| e.path == ["name"] && e.text() == "mockserver") {
        return Some(Vec::new());
    }
    let dependency = entries.iter().find(|e| e.path.len() == 3 && e.path[0] == "dependencies" && e.key.as_deref() == Some("name") && e.text() == "mockserver")?;
    let alias_path = [dependency.path[0].as_str(), dependency.path[1].as_str(), "alias"];
    let alias = yaml::find(&entries, dependency.doc, &alias_path).map_or("mockserver", |a| a.text());
    Some(vec![alias.to_string()])
}

/// The prefix of a values file named with `--helm-values`: `mockserver` when its top level nests the chart's values
/// under that key, else none.
pub fn guess_prefix(text: &str) -> Vec<String> {
    let entries = yaml::scan(text);
    let nested = entries.iter().any(|e| e.path.len() == 2 && e.path[0] == "mockserver" && matches!(e.path[1].as_str(), "app" | "image"));
    if nested { vec!["mockserver".into()] } else { Vec::new() }
}

/// The findings of one values file.
pub fn scan(text: &str, prefix: &[String], ctx: &Context) -> Vec<Finding> {
    let entries = yaml::scan(text);
    let at = |rest: &[&str]| -> Option<&Entry> {
        let path: Vec<&str> = prefix.iter().map(String::as_str).chain(rest.iter().copied()).collect();
        yaml::find(&entries, 0, &path)
    };
    let mut findings = vec![Finding::new(rules::PACKAGING_HELM, Severity::Info, 1, "mockserver chart values", "the upstream chart works with image.repositoryNameAndTag set to the mock-server image; app.jvmOptions follows the jvm.options rules")];
    if let Some(image) = at(&["image", "repositoryNameAndTag"]) {
        findings.extend(rules::image_reference(image.text(), image.line, &image.path_string()));
    } else if let Some(repository) = at(&["image", "repository"]) {
        findings.push(Finding::new(rules::IMAGE_REFERENCE, Severity::Rewrite, repository.line, format!("{}/mockserver:mockserver-<appVersion>", repository.text()), "set image.repositoryNameAndTag to the mock-server image once it has a published name").key(repository.path_string()));
    }
    if let Some(snapshot) = at(&["image", "snapshot"]).filter(|e| e.text() == "true") {
        findings.push(Finding::new(rules::IMAGE_REFERENCE, Severity::Warn, snapshot.line, "image.snapshot: true", "the snapshot variant has no counterpart: the plain image is the target").key(snapshot.path_string()));
    }
    let extra_env = at(&["app", "extraEnv"]);
    if let Some(jvm) = at(&["app", "jvmOptions"]) {
        findings.extend(jvm_options(text, &entries, jvm, extra_env, ctx));
    }
    if let Some(extra) = extra_env.filter(|e| e.value.is_none()) {
        findings.extend(super::k8s::env_findings(text, &entries, extra, ctx));
    }
    if let Some(libs) = at(&["app", "mountedLibsConfigMapName"]).filter(|e| !e.text().is_empty()) {
        findings.push(super::k8s::libs_finding(&format!("ConfigMap {} mounted on /libs", libs.text()), libs.line, &libs.path_string(), ctx));
    }
    if let Some(classes) = at(&["extensions", "classes"]).filter(|e| e.text().trim_matches(['"', '\'']).split(',').any(|n| !n.trim().is_empty())) {
        findings.push(rules::extensions_finding(format!("extensions.classes: {}", classes.text()), classes.line, classes.path_string()));
    }
    if let Some(scanning) = at(&["extensions", "scanning"]).filter(|e| e.text().eq_ignore_ascii_case("true")) {
        findings.push(rules::extensions_finding("extensions.scanning: true", scanning.line, scanning.path_string()));
    }
    if let Some(volume) = at(&["extensions", "volume"]) {
        let nested = entries.iter().any(|e| e.doc == volume.doc && e.path.len() > volume.path.len() && e.path[..volume.path.len()] == volume.path[..]);
        if nested || volume.value.is_some() && !matches!(volume.text().trim(), "" | "{}" | "null" | "~") {
            findings.push(rules::extensions_finding("extensions.volume mounted on /extensions", volume.line, volume.path_string()));
        }
    }
    if let Some(block) = at(&["app", "config", "properties"]).and_then(|e| e.value.as_ref().map(|v| (e, v))) {
        findings.extend(embedded(super::properties::scan(&block.1.text), block.0, block.1));
    }
    if let Some(block) = at(&["app", "config", "initializerJson"]).and_then(|e| e.value.as_ref().map(|v| (e, v))) {
        findings.extend(embedded(super::expectations::scan(&block.1.text), block.0, block.1));
    }
    if let Some(transport) = at(&["clustering", "transportConfig"]) {
        findings.extend(rules::config_setting("mockserver.clusterTransportConfig", transport.text(), rules::Source::Property).into_iter().map(|f| Finding { line: transport.line, ..f }.key(transport.path_string())));
    }
    if let Some(enabled) = at(&["clustering", "enabled"]).filter(|e| e.text() == "true") {
        findings.push(Finding::new(rules::IMAGE_REFERENCE, Severity::Info, enabled.line, "clustering.enabled: true", "no clustered variant: the same image with clusterEnabled").key(enabled.path_string()));
    }
    findings
}

/// Findings of a file embedded in a block scalar, moved to the lines they are on.
fn embedded(found: Vec<Finding>, entry: &Entry, value: &yaml::Scalar) -> Vec<Finding> {
    let first = if value.style == Style::Block { value.first_line } else { entry.line };
    found.into_iter().map(|f| Finding { line: first + f.line.max(1) - 1, edits: Vec::new(), mechanical: false, key: Some(format!("{}{}", entry.path_string(), f.key.map(|k| format!(": {k}")).unwrap_or_default())), ..f }).collect()
}

/// `app.jvmOptions`: the `JAVA_TOOL_OPTIONS` the chart sets, its mapped tokens moved into `app.extraEnv`.
fn jvm_options(text: &str, entries: &[Entry], jvm: &Entry, extra_env: Option<&Entry>, ctx: &Context) -> Vec<Finding> {
    let span = jvm.value.as_ref().and_then(|v| v.text_span(text));
    let var = EnvVar { name: "JAVA_TOOL_OPTIONS".into(), value: jvm.text().to_string(), line: jvm.line, key: jvm.path_string(), span, entry: None };
    // where the new variables go: after the list's items, in place of a flow `[]`, or a new `extraEnv:` after jvmOptions
    let (insert_at, item_indent, header, flow) = match extra_env {
        Some(extra) if extra.value.is_none() => {
            let first = entries.iter().find(|e| e.path.len() == extra.path.len() + 2 && e.path[..extra.path.len()] == extra.path[..] && e.item_indent.is_some());
            (yaml::subtree_end(entries, extra), first.map_or(extra.indent + 2, |e| e.item_indent.unwrap_or(0)), None, None)
        }
        Some(extra) => {
            let value = extra.value.as_ref().unwrap();
            let empty_flow = value.style == Style::Flow && value.text.trim().is_empty();
            if !empty_flow {
                return rules::env_var(&var, None, ctx);
            }
            // the blank between the colon and `[]` goes too
            let from = text[..value.start].trim_end().len();
            (value.end, extra.indent + 2, None, Some((from, value.end)))
        }
        None => (jvm.end, jvm.indent + 2, Some(format!("{}extraEnv:\n", " ".repeat(jvm.indent))), None),
    };
    let first = Cell::new(true);
    let render = |name: &str, value: &str| {
        let item = format!("{}- name: {name}\n{}value: {}", " ".repeat(item_indent), " ".repeat(item_indent + 2), yaml::double_quoted(value));
        let is_first = first.replace(false);
        match (&header, flow) {
            (_, Some(_)) => format!("\n{item}"),
            (Some(header), None) if is_first => format!("{header}{item}\n"),
            _ => format!("{item}\n"),
        }
    };
    let none = |_: &str| None;
    let block = EnvBlock { insert_at, render: &render, existing: &none };
    let mut findings = rules::env_var(&var, Some(&block), ctx);
    let plain = jvm.value.as_ref().is_some_and(|v| v.style == Style::Plain);
    if let Some(owner) = findings.iter_mut().find(|f| !f.edits.is_empty()) {
        if let Some((start, end)) = flow {
            owner.edits.push(Edit::replace(start, end, ""));
        }
        // a plain value left empty would read as null: write `""`
        for edit in owner.edits.iter_mut().filter(|e| plain && span == Some((e.start, e.end)) && e.text.is_empty()) {
            edit.text = "\"\"".into();
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(text: &str) -> String {
        let edits: Vec<Edit> = scan(text, &[], &Context::default()).into_iter().flat_map(|f| f.edits).collect();
        super::super::apply_edits(text, &edits).unwrap()
    }

    #[test]
    fn extensions_values_are_blockers() {
        let text = "extensions:\n  classes: \"com.acme.A,com.acme.B\"\n  scanning: true\n  volume:\n    configMap:\n      name: exts\n";
        let found: Vec<(&str, Severity, usize)> = scan(text, &[], &Context::default()).iter().filter(|f| f.rule == rules::CLASSPATH_EXTENSIONS).map(|f| (f.rule, f.severity, f.line)).collect();
        assert_eq!(found, [(rules::CLASSPATH_EXTENSIONS, Severity::Blocker, 2), (rules::CLASSPATH_EXTENSIONS, Severity::Blocker, 3), (rules::CLASSPATH_EXTENSIONS, Severity::Blocker, 4)]);
        let defaults = "extensions:\n  classes: \"\"\n  scanning: false\n  volume: {}\n";
        assert!(scan(defaults, &[], &Context::default()).iter().all(|f| f.rule != rules::CLASSPATH_EXTENSIONS));
        let nested = "mockserver:\n  app:\n    logLevel: INFO\n  extensions:\n    classes: com.acme.A\n";
        assert_eq!(scan(nested, &["mockserver".to_string()], &Context::default()).iter().filter(|f| f.rule == rules::CLASSPATH_EXTENSIONS).count(), 1);
    }

    #[test]
    fn prefixes() {
        assert_eq!(prefix_for("apiVersion: v1\nname: mockserver\nversion: 8.0.0\n"), Some(vec![]));
        assert_eq!(prefix_for("name: app\ndependencies:\n  - name: mockserver\n    alias: mocks\n    repository: https://www.mock-server.com\n"), Some(vec!["mocks".to_string()]));
        assert_eq!(prefix_for("name: app\ndependencies:\n  - name: redis\n"), None);
        assert_eq!(guess_prefix("mockserver:\n  app:\n    logLevel: INFO\n"), ["mockserver"]);
    }

    #[test]
    fn values_are_read() {
        let text = "image:\n  repositoryNameAndTag: mockserver/mockserver:mockserver-8.0.0\napp:\n  jvmOptions: \"-Xmx512m -Dmockserver.maxLogEntries=1000\"\n  mountedLibsConfigMapName: callbacks\n  config:\n    properties: |\n      mockserver.logLevel=INFO\n      mockserver.useNativeTransport=false\nclustering:\n  transportConfig: jgroups-kubernetes.xml\n";
        let found: Vec<(&str, Severity, usize)> = scan(text, &[], &Context::default()).iter().map(|f| (f.rule, f.severity, f.line)).collect();
        assert_eq!(found, [
            (rules::PACKAGING_HELM, Severity::Info, 1),
            (rules::IMAGE_REFERENCE, Severity::Rewrite, 2),
            (rules::JVM_MEMORY, Severity::Info, 4),
            (rules::JVM_PROPERTY, Severity::Rewrite, 4),
            (rules::CONFIG_KEY, Severity::Info, 4),
            (rules::CLASSPATH_LIBS, Severity::Action, 5),
            (rules::CONFIG_KEY, Severity::Info, 8),
            (rules::CONFIG_KEY, Severity::Info, 9),
            (rules::CLUSTER_TRANSPORT, Severity::Info, 11),
        ]);
        assert!(rewrite(text).contains("  jvmOptions: \"-Xmx512m\"\n  extraEnv:\n    - name: MOCKSERVER_MAX_LOG_ENTRIES\n      value: \"1000\"\n  mountedLibsConfigMapName: callbacks\n"), "{}", rewrite(text));
    }

    #[test]
    fn extra_env_in_each_form() {
        let flow = "app:\n  jvmOptions: -Dmockserver.logLevel=WARN\n  extraEnv: []\n";
        assert_eq!(rewrite(flow), "app:\n  jvmOptions: \"\"\n  extraEnv:\n    - name: MOCKSERVER_LOG_LEVEL\n      value: \"WARN\"\n");
        let block = "app:\n  jvmOptions: -Dmockserver.logLevel=WARN\n  extraEnv:\n  - name: MOCKSERVER_MAX_EXPECTATIONS\n    value: \"9\"\n";
        assert_eq!(rewrite(block), "app:\n  jvmOptions: \"\"\n  extraEnv:\n  - name: MOCKSERVER_MAX_EXPECTATIONS\n    value: \"9\"\n  - name: MOCKSERVER_LOG_LEVEL\n    value: \"WARN\"\n");
    }
}

//! docker-compose files: each service that runs the `mockserver/mockserver` image, with its `image:`,
//! `environment:` (map or list form), `command:`/`entrypoint:` and `volumes:`.

use super::rules::{self, EnvBlock, EnvVar};
use super::yaml::{self, Entry, Style};
use super::{Context, Finding, Severity};

/// The findings of one compose file.
pub fn scan(text: &str, ctx: &Context) -> Vec<Finding> {
    let entries = yaml::scan(text);
    let mut findings = Vec::new();
    for image in entries.iter().filter(|e| e.path.len() == 3 && e.path[0] == "services" && e.key.as_deref() == Some("image")) {
        if rules::mockserver_image_tag(image.text()).is_none() {
            continue;
        }
        let service = &image.path[..2];
        let at = |key: &str| yaml::find(&entries, image.doc, &[&service[0], &service[1], key]);
        findings.extend(rules::image_reference(image.text(), image.line, &image.path_string()));
        if let Some(environment) = at("environment") {
            findings.extend(environment_findings(text, &entries, environment, ctx));
        }
        for key in ["entrypoint", "command"] {
            if let Some(entry) = at(key) {
                let args = command(&entries, entry, text);
                findings.extend(super::shell::java_command(&args, entry.line, &entry.path_string()));
                if !super::shell::is_java_launch(&args) {
                    findings.extend(rules::command_args(&args, entry.line, &entry.path_string()));
                }
            }
        }
        if let Some(volumes) = at("volumes") {
            findings.extend(volume_findings(&entries, volumes, text, ctx));
        }
    }
    findings
}

/// A `command:`/`entrypoint:` as arguments: a sequence item by item, a string split on blanks.
fn command(entries: &[Entry], entry: &Entry, text: &str) -> Vec<String> {
    match yaml::sequence(entries, entry, text) {
        Some(items) => items.into_iter().map(|s| s.text).collect(),
        None => entry.text().split_whitespace().map(String::from).collect(),
    }
}

/// `environment:` in map form (`NAME: value`) or list form (`- NAME=value`).
fn environment_findings(text: &str, entries: &[Entry], environment: &Entry, ctx: &Context) -> Vec<Finding> {
    let children: Vec<&Entry> = yaml::children(entries, environment).collect();
    let list = children.iter().any(|e| e.key.is_none());
    let mut vars = Vec::new();
    for child in &children {
        let var = if list {
            let Some(value) = &child.value else { continue };
            let Some((name, rest)) = value.text.split_once('=') else { continue };
            let span = value.text_span(text).map(|(s, e)| (s + name.len() + 1, e));
            EnvVar { name: name.to_string(), value: rest.to_string(), line: child.line, key: format!("{}.{name}", environment.path_string()), span, entry: Some((child.start, child.end)) }
        } else {
            let Some(name) = &child.key else { continue };
            let span = child.value.as_ref().and_then(|v| v.text_span(text));
            EnvVar { name: name.clone(), value: child.text().to_string(), line: child.line, key: child.path_string(), span, entry: Some((child.start, child.end)) }
        };
        vars.push(var);
    }
    let Some(first) = children.first() else { return Vec::new() };
    let item_indent = first.item_indent.unwrap_or(first.indent);
    let indent = first.indent;
    let insert_at = yaml::subtree_end(entries, environment);
    let missing_newline = std::cell::Cell::new(insert_at == text.len() && !text.is_empty() && !text.ends_with('\n'));
    let quoted_list = first.value.as_ref().is_some_and(|v| v.style != Style::Plain);
    let render = |name: &str, value: &str| {
        let prefix = if missing_newline.replace(false) { "\n" } else { "" };
        if list {
            let item = format!("{name}={value}");
            let item = if quoted_list || !yaml::plain_safe(&item) { yaml::double_quoted(&item) } else { item };
            format!("{prefix}{}- {item}\n", " ".repeat(item_indent))
        } else {
            let value = if yaml::plain_safe(value) { value.to_string() } else { yaml::double_quoted(value) };
            format!("{prefix}{}{name}: {value}\n", " ".repeat(indent))
        }
    };
    let existing = |name: &str| vars.iter().find(|v| v.name == name).and_then(|v| v.span);
    let block = EnvBlock { insert_at, render: &render, existing: &existing };
    vars.iter().flat_map(|var| rules::env_var(var, Some(&block), ctx)).collect()
}

/// `volumes:` in short (`src:target[:mode]`) or long (`source:`/`target:`) form: mounts on `/libs`.
fn volume_findings(entries: &[Entry], volumes: &Entry, text: &str, ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();
    for item in yaml::sequence(entries, volumes, text).unwrap_or_default() {
        let mut parts = item.text.split(':');
        let (source, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        mount(&mut findings, source, target, super::line_of(text, item.start), &volumes.path_string(), ctx);
    }
    for target in entries.iter().filter(|e| e.doc == volumes.doc && e.key.as_deref() == Some("target") && e.path.len() == volumes.path.len() + 2 && e.path[..volumes.path.len()] == volumes.path[..]) {
        let source_path: Vec<&str> = target.path[..target.path.len() - 1].iter().map(String::as_str).chain(["source"]).collect();
        let source = yaml::find(entries, target.doc, &source_path).map_or("", |s| s.text());
        mount(&mut findings, source, target.text(), target.line, &target.path_string(), ctx);
    }
    findings
}

fn mount(findings: &mut Vec<Finding>, source: &str, target: &str, line: usize, key: &str, ctx: &Context) {
    if super::k8s::is_extensions(target) {
        findings.push(rules::extensions_finding(format!("{source} mounted on {target}"), line, key));
        return;
    }
    if !super::k8s::is_libs(target) {
        return;
    }
    if let Some(module) = super::build_files::blob_module(source) {
        findings.push(Finding::new(rules::CLASSPATH_BLOB, Severity::Action, line, format!("{source} mounted on {target}"), format!("the {module} store is built in: set MOCKSERVER_BLOB_STORE_MODULES={module} and drop the jar")).key(key));
    } else {
        findings.push(super::k8s::libs_finding(&format!("{source} mounted on {target}"), line, key, ctx));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_environment_is_rewritten_in_place() {
        let text = "services:\n  mockserver:\n    image: mockserver/mockserver:mockserver-8.0.0 # pinned\n    environment:\n      JAVA_TOOL_OPTIONS: \"-Dmockserver.logLevel=INFO -Xmx256m\"\n      MOCKSERVER_MAX_EXPECTATIONS: 10\n    ports:\n      - 1080:1080\n    volumes:\n      - ./callbacks.jar:/libs/callbacks.jar\n  app:\n    image: acme/app\n    environment:\n      JAVA_TOOL_OPTIONS: -Xmx1g\n";
        let found = scan(text, &Context::default());
        let summary: Vec<(&str, Severity, usize)> = found.iter().map(|f| (f.rule, f.severity, f.line)).collect();
        assert_eq!(summary, [
            (rules::IMAGE_REFERENCE, Severity::Rewrite, 3),
            (rules::JVM_PROPERTY, Severity::Rewrite, 5),
            (rules::CONFIG_KEY, Severity::Info, 5),
            (rules::JVM_MEMORY, Severity::Info, 5),
            (rules::CONFIG_KEY, Severity::Info, 6),
            (rules::CLASSPATH_LIBS, Severity::Action, 10),
        ]);
        let edits: Vec<_> = found.iter().flat_map(|f| f.edits.clone()).collect();
        let rewritten = super::super::apply_edits(text, &edits).unwrap();
        assert!(rewritten.contains("    image: mockserver/mockserver:mockserver-8.0.0 # pinned\n    environment:\n      JAVA_TOOL_OPTIONS: \"-Xmx256m\"\n      MOCKSERVER_MAX_EXPECTATIONS: 10\n      MOCKSERVER_LOG_LEVEL: INFO\n    ports:"), "{rewritten}");
        assert!(rewritten.ends_with("      JAVA_TOOL_OPTIONS: -Xmx1g\n"));
    }

    #[test]
    fn list_environment_and_an_existing_variable() {
        let text = "services:\n  mock:\n    image: mockserver/mockserver\n    environment:\n    - JAVA_OPTS=-Dmockserver.maxExpectations=5\n    - MOCKSERVER_MAX_EXPECTATIONS=1\n    - MOCKSERVER_TYPO=1\n    command: -serverPort 1080 -Dmockserver.useNativeTransport=true\n";
        let found = scan(text, &Context::default());
        let edits: Vec<_> = found.iter().flat_map(|f| f.edits.clone()).collect();
        assert_eq!(super::super::apply_edits(text, &edits).unwrap(), "services:\n  mock:\n    image: mockserver/mockserver\n    environment:\n    - MOCKSERVER_MAX_EXPECTATIONS=5\n    - MOCKSERVER_TYPO=1\n    command: -serverPort 1080 -Dmockserver.useNativeTransport=true\n");
        assert!(found.iter().any(|f| f.rule == rules::CONFIG_KEY && f.severity == Severity::Warn && f.found == "MOCKSERVER_TYPO=1"));
        assert!(found.iter().any(|f| f.rule == rules::JVM_PROPERTY && f.severity == Severity::Info && f.line == 8));
        assert!(found.iter().any(|f| f.found == "mockserver.useNativeTransport=true" && f.severity == Severity::Info));
    }

    #[test]
    fn long_volume_syntax_and_blob_jars() {
        let text = "services:\n  mock:\n    image: mockserver/mockserver\n    volumes:\n      - type: bind\n        source: ./libs\n        target: /libs\n      - ./mockserver-blob-s3-8.0.0.jar:/libs/blob.jar\n";
        let found = scan(text, &Context::default());
        let rules: Vec<(&str, usize)> = found.iter().map(|f| (f.rule, f.line)).collect();
        assert_eq!(rules, [(rules::IMAGE_REFERENCE, 3), (rules::CLASSPATH_BLOB, 8), (rules::CLASSPATH_LIBS, 7)]);
    }
}

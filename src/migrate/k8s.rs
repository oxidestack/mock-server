//! Kubernetes manifests: the containers of a `Deployment`, `StatefulSet`, `DaemonSet`, `Job` or `Pod` that
//! run the `mockserver/mockserver` image, read as compose services are: image, `env`, `command`/`args`, and the
//! `volumeMounts` on `/libs`.

use super::rules::{self, EnvBlock, EnvVar};
use super::yaml::{self, Entry};
use super::{Context, Finding, Severity};

/// The findings of one manifest file (any number of documents).
pub fn scan(text: &str, ctx: &Context) -> Vec<Finding> {
    let entries = yaml::scan(text);
    let mut findings = Vec::new();
    for image in entries.iter().filter(|e| is_container_image(e) && rules::mockserver_image_tag(e.text()).is_some()) {
        let container = &image.path[..image.path.len() - 1];
        findings.extend(container_findings(text, &entries, image.doc, container, ctx));
    }
    findings
}

fn is_container_image(entry: &Entry) -> bool {
    let n = entry.path.len();
    n >= 3 && entry.key.as_deref() == Some("image") && entry.path[n - 2].starts_with('[') && matches!(entry.path[n - 3].as_str(), "containers" | "initContainers")
}

/// The findings of one container: `container` is its path (`spec.template.spec.containers[0]`).
pub fn container_findings(text: &str, entries: &[Entry], doc: usize, container: &[String], ctx: &Context) -> Vec<Finding> {
    let at = |key: &str| {
        let mut path: Vec<&str> = container.iter().map(String::as_str).collect();
        path.push(key);
        yaml::find(entries, doc, &path)
    };
    let mut findings = Vec::new();
    if let Some(image) = at("image") {
        findings.extend(rules::image_reference(image.text(), image.line, &image.path_string()));
    }
    if let Some(env) = at("env") {
        findings.extend(env_findings(text, entries, env, ctx));
    }
    for key in ["command", "args"] {
        if let Some(entry) = at(key) {
            let args: Vec<String> = match yaml::sequence(entries, entry, text) {
                Some(items) => items.into_iter().map(|s| s.text).collect(),
                None => entry.text().split_whitespace().map(String::from).collect(),
            };
            findings.extend(super::shell::java_command(&args, entry.line, &entry.path_string()));
            if !super::shell::is_java_launch(&args) {
                findings.extend(rules::command_args(&args, entry.line, &entry.path_string()));
            }
        }
    }
    if let Some(mounts) = at("volumeMounts") {
        for mount in entries.iter().filter(|e| e.doc == doc && e.key.as_deref() == Some("mountPath") && e.path.len() == mounts.path.len() + 2 && e.path[..mounts.path.len()] == mounts.path[..]) {
            if is_libs(mount.text()) {
                findings.push(libs_finding(&format!("volume mounted on {}", mount.text()), mount.line, &mount.path_string(), ctx));
            } else if is_extensions(mount.text()) {
                findings.push(rules::extensions_finding(format!("volume mounted on {}", mount.text()), mount.line, mount.path_string()));
            }
        }
    }
    findings
}

/// Whether a container path is MockServer's `/libs` class-path directory or below it.
pub fn is_libs(path: &str) -> bool {
    let path = path.trim().trim_end_matches('/');
    path == "/libs" || path.starts_with("/libs/")
}

/// Whether a container path is MockServer's `/extensions` directory (`/extensions/*` ends the image's class path) or
/// below it.
pub fn is_extensions(path: &str) -> bool {
    let path = path.trim().trim_end_matches('/');
    path == "/extensions" || path.starts_with("/extensions/")
}

/// `classpath.libs`: what was on `/libs` now has to be a callback plugin.
pub fn libs_finding(found: &str, line: usize, key: &str, ctx: &Context) -> Finding {
    let mut verdict = format!("/libs takes callback plugins now (a .wasm in the image, MOCKSERVER_CALLBACK_PLUGINS=/libs): build the classes as a plugin ({}); a jar there is ignored with a warning", rules::PLUGIN_SDK);
    if !ctx.jvm_classes.is_empty() {
        verdict.push_str(&format!("; the sources implement {}", ctx.jvm_classes.join(", ")));
    }
    Finding::new(rules::CLASSPATH_LIBS, Severity::Action, line, found, verdict).key(key)
}

/// A Kubernetes `env:` list (`- name: X` / `value: Y` items) below `env`: each variable through [`rules::env_var`],
/// with new variables appended to the list in its own layout.
pub fn env_findings(text: &str, entries: &[Entry], env: &Entry, ctx: &Context) -> Vec<Finding> {
    let vars = env_list(entries, env, text);
    let insert_at = yaml::subtree_end(entries, env);
    let first = entries.iter().find(|e| e.doc == env.doc && e.path.len() == env.path.len() + 2 && e.path[..env.path.len()] == env.path[..] && e.item_indent.is_some());
    let layout = first.map(|e| (e.item_indent.unwrap_or(0), e.indent));
    let missing_newline = std::cell::Cell::new(insert_at == text.len() && !text.is_empty() && !text.ends_with('\n'));
    let render = |name: &str, value: &str| match layout {
        Some((item, content)) => {
            let prefix = if missing_newline.replace(false) { "\n" } else { "" };
            format!("{prefix}{}- name: {name}\n{}value: {}\n", " ".repeat(item), " ".repeat(content), yaml::double_quoted(value))
        }
        None => String::new(),
    };
    let existing = |name: &str| vars.iter().find(|v| v.name == name).and_then(|v| v.span);
    let block = EnvBlock { insert_at, render: &render, existing: &existing };
    vars.iter().flat_map(|var| rules::env_var(var, layout.map(|_| &block), ctx)).collect()
}

/// The variables of a Kubernetes `env:` list.
pub fn env_list(entries: &[Entry], env: &Entry, text: &str) -> Vec<EnvVar> {
    let depth = env.path.len();
    let below = |e: &&Entry| e.doc == env.doc && e.path.len() > depth + 1 && e.path[..depth] == env.path[..];
    let mut vars = Vec::new();
    let mut index = 0;
    loop {
        let item = format!("[{index}]");
        let members: Vec<&Entry> = entries.iter().filter(below).filter(|e| e.path[depth] == item).collect();
        if members.is_empty() {
            break;
        }
        index += 1;
        let field = |k: &str| members.iter().find(|e| e.path.len() == depth + 2 && e.key.as_deref() == Some(k)).copied();
        let Some(name) = field("name") else { continue };
        let value = field("value");
        let start = members.iter().map(|e| e.start).min().unwrap_or(name.start);
        let end = members.iter().map(|e| e.end).max().unwrap_or(name.end);
        vars.push(EnvVar {
            name: name.text().to_string(),
            value: value.map_or(String::new(), |v| v.text().to_string()),
            line: name.line,
            key: format!("{}.{}", env.path_string(), name.text()),
            span: value.and_then(|v| v.value.as_ref()).and_then(|s| s.text_span(text)),
            entry: Some((start, end)),
        });
    }
    vars
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPLOYMENT: &str = "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: mockserver\n          image: mockserver/mockserver:mockserver-8.0.0\n          env:\n            - name: JAVA_TOOL_OPTIONS\n              value: \"-Dmockserver.maxExpectations=100 -Xmx128m\"\n            - name: MOCKSERVER_SERVER_PORT\n              value: \"1080\"\n          args: [\"-logLevel\", \"INFO\"]\n          volumeMounts:\n            - name: libs\n              mountPath: /libs\n        - name: sidecar\n          image: busybox\n          env:\n            - name: JAVA_OPTS\n              value: -Xmx1g\n";

    #[test]
    fn a_mockserver_container_is_read_and_rewritten() {
        let found = scan(DEPLOYMENT, &Context::default());
        let rules: Vec<(&str, usize)> = found.iter().map(|f| (f.rule, f.line)).collect();
        assert_eq!(rules, [(rules::IMAGE_REFERENCE, 8), (rules::JVM_PROPERTY, 10), (rules::CONFIG_KEY, 10), (rules::JVM_MEMORY, 10), (rules::CONFIG_KEY, 12), (rules::CLASSPATH_LIBS, 17)]);
        let edits: Vec<_> = found.iter().flat_map(|f| f.edits.clone()).collect();
        let rewritten = super::super::apply_edits(DEPLOYMENT, &edits).unwrap();
        assert!(rewritten.contains("              value: \"-Xmx128m\"\n            - name: MOCKSERVER_SERVER_PORT\n              value: \"1080\"\n            - name: MOCKSERVER_MAX_EXPECTATIONS\n              value: \"100\"\n          args:"), "{rewritten}");
        assert!(rewritten.contains("value: -Xmx1g"), "the sidecar is not touched");
    }

    #[test]
    fn a_variable_left_empty_is_removed() {
        let text = "kind: Pod\nspec:\n  containers:\n  - image: mockserver/mockserver\n    env:\n    - name: JAVA_OPTS\n      value: -Dmockserver.logLevel=WARN\n";
        let edits: Vec<_> = scan(text, &Context::default()).into_iter().flat_map(|f| f.edits).collect();
        assert_eq!(super::super::apply_edits(text, &edits).unwrap(), "kind: Pod\nspec:\n  containers:\n  - image: mockserver/mockserver\n    env:\n    - name: MOCKSERVER_LOG_LEVEL\n      value: \"WARN\"\n");
    }

    #[test]
    fn extensions_mounts_and_variables() {
        let text = "kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - image: mockserver/mockserver:mockserver-9.2.0\n          env:\n            - name: MOCKSERVER_EXTENSIONS\n              value: com.acme.Ext\n          volumeMounts:\n            - name: ext\n              mountPath: /extensions\n";
        let found: Vec<(&str, Severity, usize)> = scan(text, &Context::default()).iter().filter(|f| f.rule == rules::CLASSPATH_EXTENSIONS).map(|f| (f.rule, f.severity, f.line)).collect();
        assert_eq!(found, [(rules::CLASSPATH_EXTENSIONS, Severity::Blocker, 8), (rules::CLASSPATH_EXTENSIONS, Severity::Blocker, 12)]);
    }

    #[test]
    fn libs_paths() {
        assert!(is_extensions("/extensions") && is_extensions("/extensions/a.jar") && !is_extensions("/extensionsx"));
        assert!(is_libs("/libs"));
        assert!(is_libs("/libs/callbacks.jar"));
        assert!(!is_libs("/libsx"));
    }
}

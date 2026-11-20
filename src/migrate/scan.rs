//! Finding the inputs: the `PATH` arguments are walked (`.gitignore` respected; `target/`,
//! `node_modules/` and `.git/` skipped), each file is classified by name and content, a first pass collects the
//! cross-file [`Context`], and the second hands each file to its module.

use std::path::{Path, PathBuf};

use super::{Context, FileReport, Finding, Options};

/// What a file is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Properties,
    JsonProperties,
    EnvFile,
    Compose,
    /// Values of the upstream chart, at this key prefix.
    Helm(Vec<String>),
    Kubernetes,
    Dockerfile,
    Shell,
    Build,
    Source,
    Expectations,
    Logging,
    JGroups,
    /// A Grafana dashboard.
    Dashboard,
    /// Prometheus configuration in YAML: rule files, alert definitions, scrape configurations.
    Prometheus,
}

const SKIPPED_DIRECTORIES: [&str; 3] = ["target", "node_modules", ".git"];
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// The kind of a file from its name, its text and (for values files) the chart next to it.
pub fn classify(name: &str, text: &str, helm_prefix: Option<Vec<String>>) -> Option<Kind> {
    let lower = name.to_ascii_lowercase();
    let yaml = lower.ends_with(".yaml") || lower.ends_with(".yml");
    if super::logging::is_logging_file(name) {
        return text.contains("org.mockserver").then_some(Kind::Logging);
    }
    if super::dockerfile::is_dockerfile(name) {
        return Some(Kind::Dockerfile);
    }
    if yaml && (lower.starts_with("docker-compose") || lower.starts_with("compose")) {
        return Some(Kind::Compose);
    }
    if yaml && lower.starts_with("values") && let Some(prefix) = helm_prefix {
        return Some(Kind::Helm(prefix));
    }
    if yaml {
        if text.contains("kind:") && text.contains("mockserver/mockserver") {
            return Some(Kind::Kubernetes);
        }
        return super::metrics::is_prometheus(text).then_some(Kind::Prometheus);
    }
    if name == "pom.xml" || lower.ends_with(".gradle") || lower.ends_with(".gradle.kts") || lower.ends_with(".versions.toml") {
        return Some(Kind::Build);
    }
    if [".java", ".kt", ".groovy"].iter().any(|e| lower.ends_with(e)) {
        return text.to_ascii_lowercase().contains("mockserver").then_some(Kind::Source);
    }
    if lower.ends_with(".properties") {
        return super::properties::has_mockserver_keys(text).then_some(Kind::Properties);
    }
    if super::env_file::is_env_file(name) {
        return Some(Kind::EnvFile);
    }
    if lower.ends_with(".json") {
        if super::expectations::is_expectations(text) {
            return Some(Kind::Expectations);
        }
        if super::metrics::is_dashboard(text) {
            return Some(Kind::Dashboard);
        }
        return (lower.starts_with("mockserver") && super::properties::is_json_properties(text)).then_some(Kind::JsonProperties);
    }
    if lower.ends_with(".xml") {
        return super::cluster::is_jgroups(text).then_some(Kind::JGroups);
    }
    let script = lower.ends_with(".sh") || lower.ends_with(".bash") || (!lower.contains('.') && text.starts_with("#!"));
    (script && text.contains("mockserver")).then_some(Kind::Shell)
}

/// The findings of one file of a known kind.
pub fn findings(kind: &Kind, name: &str, text: &str, ctx: &Context) -> Vec<Finding> {
    match kind {
        Kind::Properties => super::properties::scan(text),
        Kind::JsonProperties => super::properties::scan_json(text),
        Kind::EnvFile => super::env_file::scan(text, ctx),
        Kind::Compose => super::compose::scan(text, ctx),
        Kind::Helm(prefix) => super::helm::scan(text, prefix, ctx),
        Kind::Kubernetes => {
            let mut found = super::k8s::scan(text, ctx);
            found.extend(super::metrics::scan_prometheus(text));
            found
        }
        Kind::Dockerfile => super::dockerfile::scan(text, ctx),
        Kind::Shell => super::shell::scan(text, ctx),
        Kind::Build => super::build_files::scan(text),
        Kind::Source => super::sources::scan(text),
        Kind::Expectations => super::expectations::scan(text),
        Kind::Logging => super::logging::scan(name, text),
        Kind::JGroups => super::cluster::scan(text),
        Kind::Dashboard => super::metrics::scan_dashboard(text, ctx),
        Kind::Prometheus => super::metrics::scan_prometheus(text),
    }
}

/// One `.gitignore` pattern.
struct Pattern {
    glob: glob::Pattern,
    negate: bool,
    directory_only: bool,
    anchored: bool,
}

/// The patterns of one `.gitignore`, relative to its directory.
struct Ignore {
    base: PathBuf,
    patterns: Vec<Pattern>,
}

impl Ignore {
    fn read(dir: &Path) -> Option<Ignore> {
        let text = std::fs::read_to_string(dir.join(".gitignore")).ok()?;
        let patterns = text
            .lines()
            .filter_map(|line| {
                let line = line.trim_end();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                let (negate, line) = line.strip_prefix('!').map_or((false, line), |l| (true, l));
                let (directory_only, line) = line.strip_suffix('/').map_or((false, line), |l| (true, l));
                let anchored = line.contains('/');
                let line = line.trim_start_matches('/');
                Some(Pattern { glob: glob::Pattern::new(line).ok()?, negate, directory_only, anchored })
            })
            .collect();
        Some(Ignore { base: dir.to_path_buf(), patterns })
    }

    /// `Some(true)` ignored, `Some(false)` re-included, `None` no pattern applies.
    fn decide(&self, path: &Path, is_dir: bool) -> Option<bool> {
        let relative = path.strip_prefix(&self.base).ok()?.to_string_lossy().replace('\\', "/");
        let name = path.file_name()?.to_string_lossy();
        let options = glob::MatchOptions { require_literal_separator: true, ..glob::MatchOptions::new() };
        let mut decision = None;
        for p in &self.patterns {
            if p.directory_only && !is_dir {
                continue;
            }
            let matched = if p.anchored { p.glob.matches_with(&relative, options) } else { p.glob.matches_with(&name, options) };
            if matched {
                decision = Some(!p.negate);
            }
        }
        decision
    }
}

fn ignored(stack: &[Ignore], path: &Path, is_dir: bool) -> bool {
    stack.iter().filter_map(|i| i.decide(path, is_dir)).next_back().unwrap_or(false)
}

/// The files below `dir`, in name order.
fn walk(dir: &Path, stack: &mut Vec<Ignore>, out: &mut Vec<PathBuf>) {
    let pushed = Ignore::read(dir).map(|i| stack.push(i)).is_some();
    let mut children: Vec<PathBuf> = std::fs::read_dir(dir).map(|r| r.filter_map(|e| e.ok().map(|e| e.path())).collect()).unwrap_or_default();
    children.sort();
    for child in children {
        let name = child.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let Ok(meta) = std::fs::symlink_metadata(&child) else { continue };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            if !SKIPPED_DIRECTORIES.contains(&name.as_str()) && !ignored(stack, &child, true) {
                walk(&child, stack, out);
            }
        } else if meta.is_file() && meta.len() <= MAX_FILE_BYTES && !name.ends_with(".orig") && !ignored(stack, &child, false) {
            out.push(child);
        }
    }
    if pushed {
        stack.pop();
    }
}

/// One input before analysis.
struct Input {
    display: String,
    path: PathBuf,
    relative: PathBuf,
    forced: Option<Kind>,
    text: String,
}

/// The `PATH` argument as shown before the paths below it.
fn display_root(arg: &str) -> String {
    let trimmed = arg.trim_end_matches('/');
    let trimmed = trimmed.strip_prefix("./").unwrap_or(trimmed);
    if trimmed == "." || trimmed.is_empty() { String::new() } else { trimmed.to_string() }
}

/// The values-file prefix from the `Chart.yaml` beside `path`, if that chart is or uses the mockserver chart.
fn helm_prefix(path: &Path) -> Option<Vec<String>> {
    let chart = std::fs::read_to_string(path.parent()?.join("Chart.yaml")).ok()?;
    super::helm::prefix_for(&chart)
}

/// Reads, classifies and analyses every input; `Err` is a read error (exit code 2).
pub fn analyse(options: &Options, env: &[(String, String)]) -> Result<Vec<FileReport>, String> {
    let mut inputs = Vec::new();
    for arg in &options.paths {
        let root = PathBuf::from(arg);
        let meta = std::fs::metadata(&root).map_err(|e| format!("cannot read {arg}: {e}"))?;
        if meta.is_dir() {
            let mut files = Vec::new();
            walk(&root, &mut Vec::new(), &mut files);
            let shown = display_root(arg);
            for path in files {
                let relative = path.strip_prefix(&root).unwrap_or(&path).to_path_buf();
                let below = relative.to_string_lossy().replace('\\', "/");
                let display = if shown.is_empty() { below } else { format!("{shown}/{below}") };
                let Ok(text) = std::fs::read_to_string(&path) else { continue };
                inputs.push(Input { display, path, relative, forced: None, text });
            }
        } else {
            let text = std::fs::read_to_string(&root).map_err(|e| format!("cannot read {arg}: {e}"))?;
            let relative = PathBuf::from(root.file_name().unwrap_or_default());
            inputs.push(Input { display: display_root(arg), path: root, relative, forced: None, text });
        }
    }
    for arg in &options.helm_values {
        let path = PathBuf::from(arg);
        let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {arg}: {e}"))?;
        let prefix = super::helm::guess_prefix(&text);
        let relative = PathBuf::from(path.file_name().unwrap_or_default());
        inputs.retain(|i| std::fs::canonicalize(&i.path).ok() != std::fs::canonicalize(&path).ok());
        inputs.push(Input { display: display_root(arg), path, relative, forced: Some(Kind::Helm(prefix)), text });
    }
    let kinds: Vec<Option<Kind>> = inputs
        .iter()
        .map(|i| {
            let name = i.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            i.forced.clone().or_else(|| classify(&name, &i.text, helm_prefix(&i.path)))
        })
        .collect();
    let mut ctx = Context { replace_dashboards: options.replace_dashboards, ..Context::default() };
    for (input, kind) in inputs.iter().zip(&kinds) {
        let name = input.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        match kind {
            Some(Kind::Logging) => {
                if let Some(level) = super::logging::mockserver_level(&name, &input.text) {
                    ctx.logging_levels.insert(name, level);
                }
            }
            Some(Kind::Source) => ctx.jvm_classes.extend(super::sources::classes(&input.text)),
            _ => {}
        }
    }
    let mut reports = Vec::new();
    for (input, kind) in inputs.into_iter().zip(kinds) {
        let Some(kind) = kind else { continue };
        let name = input.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let mut found = findings(&kind, &name, &input.text, &ctx);
        if found.is_empty() {
            continue;
        }
        found.sort_by_key(|f| f.line);
        reports.push(FileReport { display: input.display, path: Some(input.path), relative: input.relative, findings: found });
    }
    if options.env {
        let found = super::env_file::scan_process(env, &ctx);
        if !found.is_empty() {
            reports.push(FileReport { display: "(environment)".into(), path: None, relative: PathBuf::new(), findings: found });
        }
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_are_classified_by_name_and_content() {
        let none = None;
        assert_eq!(classify("docker-compose.override.yml", "", none.clone()), Some(Kind::Compose));
        assert_eq!(classify("values-prod.yaml", "", Some(vec![])), Some(Kind::Helm(vec![])));
        assert_eq!(classify("values.yaml", "a: 1", none.clone()), None);
        assert_eq!(classify("deploy.yaml", "kind: Deployment\nimage: mockserver/mockserver", none.clone()), Some(Kind::Kubernetes));
        assert_eq!(classify("Dockerfile", "", none.clone()), Some(Kind::Dockerfile));
        assert_eq!(classify("pom.xml", "", none.clone()), Some(Kind::Build));
        assert_eq!(classify("build.gradle.kts", "", none.clone()), Some(Kind::Build));
        assert_eq!(classify("ApiTest.java", "import org.mockserver.client.MockServerClient;", none.clone()), Some(Kind::Source));
        assert_eq!(classify("Other.java", "class Other {}", none.clone()), None);
        assert_eq!(classify("mockserver.properties", "mockserver.logLevel=INFO", none.clone()), Some(Kind::Properties));
        assert_eq!(classify("logging.properties", "org.mockserver.level=FINE", none.clone()), Some(Kind::Logging));
        assert_eq!(classify(".env", "", none.clone()), Some(Kind::EnvFile));
        assert_eq!(classify("init.json", "[{\"httpRequest\": {}}]", none.clone()), Some(Kind::Expectations));
        assert_eq!(classify("mockserver.json", "{\"logLevel\": \"INFO\"}", none.clone()), Some(Kind::JsonProperties));
        assert_eq!(classify("jgroups.xml", "<config xmlns=\"urn:org:jgroups\"/>", none.clone()), Some(Kind::JGroups));
        assert_eq!(classify("start.sh", "java -jar mockserver-netty.jar", none.clone()), Some(Kind::Shell));
        assert_eq!(classify("start", "#!/bin/sh\njava -jar mockserver-netty.jar", none.clone()), Some(Kind::Shell));
        assert_eq!(classify("mockserver-server.json", "{\"uid\": \"mockserver-server\", \"schemaVersion\": 39, \"panels\": []}", none.clone()), Some(Kind::Dashboard));
        assert_eq!(classify("rules.yml", "groups:\n- name: a\n  rules:\n  - expr: up\n", none.clone()), Some(Kind::Prometheus));
        assert_eq!(classify("prometheus.yml", "scrape_configs: []\n", none.clone()), Some(Kind::Prometheus));
        assert_eq!(classify("README.md", "mockserver", none), None);
    }

    #[test]
    fn display_roots() {
        assert_eq!(display_root("."), "");
        assert_eq!(display_root("./"), "");
        assert_eq!(display_root("./deploy/"), "deploy");
        assert_eq!(display_root("/abs/dir"), "/abs/dir");
    }

    #[test]
    fn gitignore_patterns() {
        let ignore = Ignore {
            base: PathBuf::from("/r"),
            patterns: ["build/", "*.log", "!keep.log", "/only-root.yml", "docs/**/gen.json"]
                .iter()
                .map(|l| {
                    let (negate, l) = l.strip_prefix('!').map_or((false, *l), |x| (true, x));
                    let (directory_only, l) = l.strip_suffix('/').map_or((false, l), |x| (true, x));
                    Pattern { anchored: l.contains('/'), glob: glob::Pattern::new(l.trim_start_matches('/')).unwrap(), negate, directory_only }
                })
                .collect(),
        };
        assert_eq!(ignore.decide(Path::new("/r/a/build"), true), Some(true));
        assert_eq!(ignore.decide(Path::new("/r/a/build"), false), None);
        assert_eq!(ignore.decide(Path::new("/r/x/y.log"), false), Some(true));
        assert_eq!(ignore.decide(Path::new("/r/keep.log"), false), Some(false));
        assert_eq!(ignore.decide(Path::new("/r/only-root.yml"), false), Some(true));
        assert_eq!(ignore.decide(Path::new("/r/sub/only-root.yml"), false), None);
        assert_eq!(ignore.decide(Path::new("/r/docs/a/b/gen.json"), false), Some(true));
    }
}

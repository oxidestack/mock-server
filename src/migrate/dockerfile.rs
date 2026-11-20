//! Dockerfiles that start `FROM mockserver/mockserver` or copy the `mockserver-netty` jar: the base
//! image, `ENV`, `COPY`/`ADD` into `/libs`, `ENTRYPOINT` and `CMD`.

use super::rules::{self, EnvBlock, EnvVar};
use super::{Context, Edit, Finding, Severity};

/// Whether a file name is a Dockerfile.
pub fn is_dockerfile(name: &str) -> bool {
    name.starts_with("Dockerfile") || name.starts_with("Containerfile") || name.ends_with(".Dockerfile") || name.ends_with(".dockerfile")
}

/// One instruction: keyword, arguments (continuations joined), the arguments' span when on one line, and the span
/// of the whole instruction (its lines).
struct Instruction {
    keyword: String,
    args: String,
    args_start: Option<usize>,
    line: usize,
    start: usize,
    end: usize,
}

fn instructions(text: &str) -> Vec<Instruction> {
    let mut out = Vec::new();
    let mut offset = 0;
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut n = 0;
    while n < lines.len() {
        let start = offset;
        let first = n;
        let mut joined = String::new();
        let mut single_line = true;
        loop {
            let raw = lines[n];
            offset += raw.len();
            n += 1;
            let line = raw.trim_end_matches(['\n', '\r']);
            match line.strip_suffix('\\') {
                Some(head) if n < lines.len() => {
                    joined.push_str(head);
                    joined.push(' ');
                    single_line = false;
                }
                _ => {
                    joined.push_str(line);
                    break;
                }
            }
        }
        let body = joined.trim_start();
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        let keyword_end = body.find(char::is_whitespace).unwrap_or(body.len());
        let args = body[keyword_end..].trim_start();
        let args_start = single_line.then(|| start + (joined.len() - args.len()));
        out.push(Instruction { keyword: body[..keyword_end].to_ascii_uppercase(), args: args.trim_end().to_string(), args_start, line: first + 1, start, end: offset });
    }
    out
}

/// The findings of one Dockerfile (none unless it builds on MockServer).
pub fn scan(text: &str, ctx: &Context) -> Vec<Finding> {
    let instructions = instructions(text);
    let relevant = instructions.iter().any(|i| (i.keyword == "FROM" && rules::mockserver_image_tag(i.args.split_whitespace().next().unwrap_or("")).is_some()) || ((i.keyword == "COPY" || i.keyword == "ADD") && i.args.contains("mockserver-netty")));
    if !relevant {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for instruction in &instructions {
        let key = instruction.keyword.as_str();
        match key {
            "FROM" => {
                let image = instruction.args.split_whitespace().next().unwrap_or("");
                findings.extend(rules::image_reference(image, instruction.line, "FROM"));
            }
            "ENV" => findings.extend(env(text, instruction, ctx)),
            "COPY" | "ADD" => findings.extend(copy(instruction, ctx)),
            "ENTRYPOINT" | "CMD" => {
                let args: Vec<String> = match serde_json::from_str::<Vec<String>>(&instruction.args) {
                    Ok(args) => args,
                    Err(_) => instruction.args.split_whitespace().map(String::from).collect(),
                };
                findings.extend(super::shell::java_command(&args, instruction.line, key));
                if !super::shell::is_java_launch(&args) {
                    findings.extend(rules::command_args(&args, instruction.line, key));
                }
            }
            _ => {}
        }
    }
    findings
}

/// `ENV NAME=value ...` or `ENV NAME value`.
fn env(text: &str, instruction: &Instruction, ctx: &Context) -> Vec<Finding> {
    let mut vars = Vec::new();
    let args = &instruction.args;
    let base = instruction.args_start;
    let pairs = quoted_tokens(args);
    let legacy = !args.split_whitespace().next().unwrap_or("").contains('=');
    if legacy {
        let name_end = args.find(char::is_whitespace).unwrap_or(args.len());
        let value = args[name_end..].trim_start();
        let value_at = args.len() - value.len();
        vars.push((args[..name_end].to_string(), value.to_string(), base.map(|b| (b + value_at, b + args.len()))));
    } else {
        for (s, e) in pairs {
            let token = &args[s..e];
            let Some((name, value)) = token.split_once('=') else { continue };
            let value_at = s + name.len() + 1;
            let (value, span) = match value.as_bytes().first() {
                Some(&q @ (b'"' | b'\'')) if value.len() >= 2 && value.ends_with(q as char) && !value.contains('\\') => (value[1..value.len() - 1].to_string(), base.map(|b| (b + value_at + 1, b + e - 1))),
                Some(b'"' | b'\'') => (value.to_string(), None),
                _ => (value.to_string(), base.map(|b| (b + value_at, b + e))),
            };
            vars.push((name.to_string(), value, span));
        }
    }
    let single = vars.len() == 1;
    let vars: Vec<EnvVar> = vars
        .into_iter()
        .map(|(name, value, span)| EnvVar { key: format!("ENV {name}"), name, value, line: instruction.line, span, entry: single.then_some((instruction.start, instruction.end)) })
        .collect();
    let missing_newline = std::cell::Cell::new(instruction.end == text.len() && !text.ends_with('\n'));
    let render = |name: &str, value: &str| {
        let value = if value.chars().any(|c| c.is_whitespace() || c == '"') { format!("\"{}\"", value.replace('"', "\\\"")) } else { value.to_string() };
        let prefix = if missing_newline.replace(false) { "\n" } else { "" };
        format!("{prefix}ENV {name}={value}\n")
    };
    let existing = |name: &str| vars.iter().find(|v| v.name == name).and_then(|v| v.span);
    let block = EnvBlock { insert_at: instruction.end, render: &render, existing: &existing };
    vars.iter().flat_map(|var| rules::env_var(var, Some(&block), ctx)).collect()
}

/// The blank-separated words of `args`, quotes grouping, with their byte ranges.
fn quoted_tokens(args: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    let mut quote = None;
    for (i, c) in args.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => {
                quote = Some(c);
                start.get_or_insert(i);
            }
            (None, c) if c.is_whitespace() => {
                if let Some(s) = start.take() {
                    out.push((s, i));
                }
            }
            (None, _) => {
                start.get_or_insert(i);
            }
        }
    }
    if let Some(s) = start {
        out.push((s, args.len()));
    }
    out
}

/// `COPY`/`ADD` sources into `/libs`, and the fat jar.
fn copy(instruction: &Instruction, ctx: &Context) -> Vec<Finding> {
    let words: Vec<&str> = instruction.args.split_whitespace().filter(|w| !w.starts_with("--")).collect();
    let Some((target, sources)) = words.split_last() else { return Vec::new() };
    let key = instruction.keyword.as_str();
    let mut findings = Vec::new();
    if sources.iter().any(|s| s.contains("mockserver-netty")) {
        findings.push(Finding::new(rules::PACKAGING_JAR, Severity::Action, instruction.line, instruction.args.clone(), "the fat jar maps to the static binary: build FROM the mock-server image instead of copying the jar").key(key));
    }
    if super::k8s::is_extensions(target) {
        findings.push(rules::extensions_finding(format!("{} copied to {target}", sources.join(" ")), instruction.line, key));
        return findings;
    }
    if !super::k8s::is_libs(target) {
        return findings;
    }
    let modules: Vec<&str> = sources.iter().filter_map(|s| super::build_files::blob_module(s)).collect();
    if !modules.is_empty() && modules.len() == sources.len() {
        let replacement = format!("ENV MOCKSERVER_BLOB_STORE_MODULES={}", modules.join(","));
        let edit = Edit::replace(instruction.start, instruction.end, format!("{replacement}\n"));
        findings.push(Finding::new(rules::CLASSPATH_BLOB, Severity::Rewrite, instruction.line, instruction.args.clone(), "the blob stores are built in: blobStoreModules puts them on the class path").key(key).replacement(replacement).mechanical(vec![edit]));
    } else {
        findings.push(super::k8s::libs_finding(&format!("{} copied to {target}", sources.join(" ")), instruction.line, key, ctx));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mockserver_dockerfile() {
        let text = "FROM mockserver/mockserver:mockserver-8.0.0\nENV JAVA_TOOL_OPTIONS=\"-Dmockserver.maxExpectations=50 -Xmx128m\" OTHER=1\nENV MOCKSERVER_LOG_LEVEL DEBUG\nCOPY target/callbacks.jar /libs/\nCOPY mockserver-blob-s3-8.0.0.jar mockserver-blob-gcs-8.0.0.jar /libs/\nCMD [\"-serverPort\", \"1080\", \"-Dmockserver.useNativeTransport=false\"]\n";
        let found = scan(text, &Context::default());
        let summary: Vec<(&str, Severity, usize)> = found.iter().map(|f| (f.rule, f.severity, f.line)).collect();
        assert_eq!(summary, [
            (rules::IMAGE_REFERENCE, Severity::Rewrite, 1),
            (rules::JVM_PROPERTY, Severity::Rewrite, 2),
            (rules::CONFIG_KEY, Severity::Info, 2),
            (rules::JVM_MEMORY, Severity::Info, 2),
            (rules::CONFIG_KEY, Severity::Info, 3),
            (rules::CLASSPATH_LIBS, Severity::Action, 4),
            (rules::CLASSPATH_BLOB, Severity::Rewrite, 5),
            (rules::JVM_PROPERTY, Severity::Info, 6),
            (rules::CONFIG_KEY, Severity::Info, 6),
        ]);
        let edits: Vec<_> = found.into_iter().flat_map(|f| f.edits).collect();
        assert_eq!(
            super::super::apply_edits(text, &edits).unwrap(),
            "FROM mockserver/mockserver:mockserver-8.0.0\nENV JAVA_TOOL_OPTIONS=\"-Xmx128m\" OTHER=1\nENV MOCKSERVER_MAX_EXPECTATIONS=50\nENV MOCKSERVER_LOG_LEVEL DEBUG\nCOPY target/callbacks.jar /libs/\nENV MOCKSERVER_BLOB_STORE_MODULES=s3,gcs\nCMD [\"-serverPort\", \"1080\", \"-Dmockserver.useNativeTransport=false\"]\n"
        );
    }

    #[test]
    fn other_dockerfiles_are_skipped() {
        assert!(scan("FROM eclipse-temurin:21\nENV JAVA_OPTS=-Xmx1g\n", &Context::default()).is_empty());
        let found = scan("FROM eclipse-temurin:21\nCOPY mockserver-netty-8.0.0-shaded.jar /app.jar\nENTRYPOINT [\"java\", \"-jar\", \"/mockserver-netty-8.0.0-shaded.jar\"]\n", &Context::default());
        assert_eq!(found.iter().map(|f| f.rule).collect::<Vec<_>>(), [rules::PACKAGING_JAR, rules::PACKAGING_JAR]);
        assert!(is_dockerfile("Dockerfile.mock") && is_dockerfile("mock.Dockerfile") && !is_dockerfile("docker-compose.yml"));
    }
}

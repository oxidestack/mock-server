//! Command lines: `java [JVM options] -jar mockserver-netty*.jar [arguments]` in shell scripts, and the
//! same launch inside container commands. The fat jar maps to the static binary with the same arguments; a `-Dmockserver.*` JVM option stays as a `-D` argument, which the binary accepts.

use super::rules::{self, Fate};
use super::{Context, Edit, Finding, Severity};

/// Whether `args` launch MockServer's fat jar: `java ... -jar <...mockserver-netty...jar>`.
pub fn is_java_launch(args: &[String]) -> bool {
    jar_index(args).is_some()
}

/// The index of the jar argument of a `java -jar mockserver-netty*.jar` launch.
fn jar_index(args: &[String]) -> Option<usize> {
    let java = args.first()?;
    let name = java.rsplit('/').next().unwrap_or(java);
    if name != "java" && name != "java.exe" {
        return None;
    }
    let at = args.iter().position(|a| a == "-jar")?;
    let jar = args.get(at + 1)?;
    (jar.contains("mockserver-netty") && jar.ends_with(".jar")).then_some(at + 1)
}

/// The findings of a fat-jar launch inside a container command (`entrypoint:`, `command:`, `args:`): the launch
/// itself is an action there (the image's own entrypoint is the binary), its JVM options go through the
/// `jvm.options.*` rules, and its arguments through [`rules::command_args`].
pub fn java_command(args: &[String], line: usize, key: &str) -> Vec<Finding> {
    let Some(jar) = jar_index(args) else { return Vec::new() };
    let mut findings = vec![Finding::new(
        rules::PACKAGING_JAR,
        Severity::Action,
        line,
        args[..=jar].join(" "),
        "the image's entrypoint is the mock-server binary: drop this launch and pass only the arguments after the jar",
    )
    .key(key)];
    let ctx = Context::default();
    for option in &args[1..jar - 1] {
        if option.starts_with("-Dmockserver.") {
            findings.extend(rules::command_args(std::slice::from_ref(option), line, key));
        } else {
            findings.extend(rules::jvm_option(option, &ctx).0.into_iter().map(|f| Finding { line, ..f }.key(key)));
        }
    }
    findings.extend(rules::command_args(&args[jar + 1..], line, key));
    findings
}

/// A word of a shell line and its span.
#[derive(Debug, Clone)]
struct Word {
    text: String,
    start: usize,
    end: usize,
}

/// The words of one logical line starting at `start` (a `\` before a newline continues it), up to the end of the
/// command (`;`, `&`, `|`, a newline or a comment); returns the words and the offset where the command ends.
fn words(text: &str, start: usize) -> (Vec<Word>, usize) {
    let bytes = text.as_bytes();
    let mut i = start;
    let mut out = Vec::new();
    loop {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t' || (bytes[i] == b'\\' && bytes.get(i + 1) == Some(&b'\n'))) {
            i += if bytes[i] == b'\\' { 2 } else { 1 };
        }
        if i >= bytes.len() || matches!(bytes[i], b'\n' | b';' | b'&' | b'|' | b'#') {
            return (out, i);
        }
        let word_start = i;
        let mut quote = None;
        while i < bytes.len() {
            let b = bytes[i];
            match quote {
                Some(q) if b == q => quote = None,
                Some(_) => {}
                None if b == b'"' || b == b'\'' => quote = Some(b),
                None if matches!(b, b' ' | b'\t' | b'\n' | b';' | b'&' | b'|') => break,
                None if b == b'\\' && bytes.get(i + 1) == Some(&b'\n') => break,
                None => {}
            }
            i += 1;
        }
        // quotes only group; the word is its text without them
        let word: String = text[word_start..i].chars().filter(|c| *c != '"' && *c != '\'').collect();
        out.push(Word { text: word, start: word_start, end: i });
    }
}

/// The findings of a shell script: each `java -jar mockserver-netty*.jar` launch becomes `mock-server` with the
/// same arguments (mechanical), `mvn mockserver:*` goals point at the launcher.
pub fn scan(text: &str, ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut at = 0;
    while at < text.len() {
        let (words, mut end) = words(text, at);
        if text.as_bytes().get(end) == Some(&b'#') {
            end = text[end..].find('\n').map_or(text.len(), |i| end + i);
        }
        if let Some(first) = words.iter().position(|w| w.text.rsplit('/').next() == Some("java")) {
            let args: Vec<String> = words[first..].iter().map(|w| w.text.clone()).collect();
            if let Some(jar) = jar_index(&args) {
                findings.extend(launch(text, &words[first..], jar, ctx));
            }
        }
        if words.iter().any(|w| w.text == "mvn" || w.text.ends_with("/mvn") || w.text == "./mvnw") && words.iter().any(|w| w.text.starts_with("mockserver:") || w.text.contains("mockserver-maven-plugin")) {
            let line = super::line_of(text, words[0].start);
            findings.push(Finding::new(rules::PACKAGING_MAVEN, Severity::Action, line, words.iter().map(|w| w.text.as_str()).collect::<Vec<_>>().join(" "), super::build_files::IN_JVM_VERDICT));
        }
        for (i, w) in words.iter().enumerate() {
            if (w.text == "-e" || w.text == "--env") && let Some((name, value)) = words.get(i + 1).and_then(|n| n.text.split_once('=')) {
                let var = rules::EnvVar { name: name.into(), value: value.into(), line: super::line_of(text, w.start), key: name.into(), span: None, entry: None };
                findings.extend(rules::env_var(&var, None, ctx));
            }
            if rules::mockserver_image_tag(&w.text).is_some() && words.iter().any(|w| w.text == "docker" || w.text == "podman") {
                findings.extend(rules::image_reference(&w.text, super::line_of(text, w.start), "docker run"));
            }
        }
        at = end + 1;
    }
    findings
}

/// One fat-jar launch in a script: `words[0]` is `java`, `words[jar]` the jar.
fn launch(text: &str, words: &[Word], jar: usize, ctx: &Context) -> Vec<Finding> {
    let line = super::line_of(text, words[0].start);
    let mut findings = Vec::new();
    let mut properties = Vec::new();
    for option in &words[1..jar - 1] {
        if option.text.starts_with("-Dmockserver.") {
            properties.push(option.text.clone());
            findings.extend(rules::command_args(std::slice::from_ref(&option.text), line, "java"));
            continue;
        }
        let (found, fate) = rules::jvm_option(&option.text, ctx);
        if let Fate::Move { name, value } = fate && let Some(key) = rules::key_for_env(&name) {
            properties.push(format!("-Dmockserver.{key}={value}"));
        }
        // the launch's rewrite drops every JVM option, so all but the actions are applied with it
        findings.extend(found.into_iter().map(|f| Finding { line, mechanical: f.severity <= Severity::Warn, ..f }.key("java")));
    }
    let mut replacement = String::from("mock-server");
    for p in &properties {
        replacement.push(' ');
        replacement.push_str(&shell_quote(p));
    }
    let original = &text[words[0].start..words[jar].end];
    let edit = Edit::replace(words[0].start, words[jar].end, replacement.clone());
    findings.insert(
        0,
        Finding::new(rules::PACKAGING_JAR, Severity::Rewrite, line, original.split_whitespace().filter(|w| *w != "\\").collect::<Vec<_>>().join(" "), "the fat jar maps to the static binary, with the same arguments")
            .key("java")
            .replacement(replacement)
            .mechanical(vec![edit]),
    );
    findings
}

fn shell_quote(word: &str) -> String {
    if word.chars().all(|c| c.is_ascii_alphanumeric() || "-_=./:,@%+".contains(c)) { word.to_string() } else { format!("'{}'", word.replace('\'', "'\\''")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_launch_becomes_the_binary() {
        let text = "#!/bin/sh\nset -e\nexec java -Xmx512m -Dmockserver.logLevel=DEBUG -XX:ActiveProcessorCount=2 \\\n  -jar ./lib/mockserver-netty-8.0.0-shaded.jar -serverPort 1080 # start\necho done\n";
        let found = scan(text, &Context::default());
        let rules: Vec<(&str, Severity, usize)> = found.iter().map(|f| (f.rule, f.severity, f.line)).collect();
        assert_eq!(rules, [
            (rules::PACKAGING_JAR, Severity::Rewrite, 3),
            (rules::JVM_MEMORY, Severity::Warn, 3),
            (rules::JVM_PROPERTY, Severity::Info, 3),
            (rules::CONFIG_KEY, Severity::Info, 3),
            (rules::JVM_CPU, Severity::Rewrite, 3),
        ]);
        let edits: Vec<_> = found.iter().flat_map(|f| f.edits.clone()).collect();
        assert_eq!(super::super::apply_edits(text, &edits).unwrap(), "#!/bin/sh\nset -e\nexec mock-server -Dmockserver.logLevel=DEBUG -Dmockserver.nioEventLoopThreadCount=2 -serverPort 1080 # start\necho done\n");
    }

    #[test]
    fn other_java_programs_are_left_alone() {
        assert!(scan("java -jar app.jar -Xmx1g\n", &Context::default()).is_empty());
        assert!(!is_java_launch(&s(&["java", "-jar", "app.jar"])));
        assert!(is_java_launch(&s(&["/usr/bin/java", "-Dx=1", "-jar", "/opt/mockserver-netty-jar-with-dependencies.jar"])));
    }

    #[test]
    fn container_launches_are_actions() {
        let found = java_command(&s(&["java", "-Xms64m", "-jar", "/mockserver-netty.jar", "-serverPort", "1080", "-Dmockserver.maxExpectations=9"]), 4, "command");
        let rules: Vec<(&str, Severity)> = found.iter().map(|f| (f.rule, f.severity)).collect();
        assert_eq!(rules, [(rules::PACKAGING_JAR, Severity::Action), (rules::JVM_MEMORY, Severity::Warn), (rules::JVM_PROPERTY, Severity::Info), (rules::CONFIG_KEY, Severity::Info)]);
    }

    #[test]
    fn docker_run_lines_and_maven_goals() {
        let found = scan("docker run -d -e JAVA_TOOL_OPTIONS=-Xmx1g -p 1080:1080 mockserver/mockserver:mockserver-8.0.0\nmvn mockserver:runForked\n", &Context::default());
        let rules: Vec<(&str, usize)> = found.iter().map(|f| (f.rule, f.line)).collect();
        assert_eq!(rules, [(rules::JVM_MEMORY, 1), (rules::IMAGE_REFERENCE, 1), (rules::PACKAGING_MAVEN, 2)]);
    }
}

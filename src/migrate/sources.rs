//! JVM test sources: `*.java`, `*.kt`, `*.groovy`, read as text (no parse) for in-JVM servers
//! (`ClientAndServer`, the JUnit rule and extension, the Spring listener), Testcontainers' `MockServerContainer`, and
//! classes implementing MockServer's callback and initializer interfaces.

use std::sync::LazyLock;

use super::rules;
use super::{Finding, Severity};

const IN_JVM: [&str; 9] = [
    "new ClientAndServer(",
    "startClientAndServer(",
    "new MockServer(",
    "new MockServerRule(",
    "@MockServerTest",
    "MockServerExtension",
    "@MockServerSettings",
    "MockServerTestExecutionListener",
    "@EnableMockServer",
];

const CALLBACKS: [&str; 3] = ["ExpectationResponseCallback", "ExpectationForwardCallback", "ExpectationForwardAndResponseCallback"];
const INITIALIZERS: [&str; 2] = ["ExpectationInitializer", "PluginExpectationInitializer"];
/// `org.mockserver.extension`'s interfaces: the extension and its hooks.
const EXTENSIONS: [&str; 8] = ["Extension", "AdminApiExtension", "ExpectationLifecycleListener", "ServeEventListener", "SettingsListener", "TemplateHelperProvider", "RequestFilter", "ResponseTransformer"];

/// What a Testcontainers user writes instead.
pub const TESTCONTAINERS_SNIPPET: &str = "new MockServerContainer(DockerImageName.parse(\"mock-server\").asCompatibleSubstituteFor(\"mockserver/mockserver\"))";

static CLASS: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\bclass\s+(\w+)([^{;]*)\{").unwrap());
static PACKAGE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?m)^\s*package\s+([\w.]+)").unwrap());

/// A class that implements a callback or initializer interface: its qualified name, whether it is an initializer,
/// and the offset of its declaration.
fn implementations(text: &str) -> Vec<(String, bool, usize)> {
    let package = PACKAGE.captures(text).map(|c| c[1].to_string());
    CLASS
        .captures_iter(text)
        .filter_map(|c| {
            let header = &c[2];
            let has = |names: &[&str]| names.iter().any(|n| regex::Regex::new(&format!(r"\b{n}\b")).unwrap().is_match(header));
            let initializer = has(&INITIALIZERS);
            (initializer || has(&CALLBACKS)).then(|| {
                let name = package.as_ref().map_or_else(|| c[1].to_string(), |p| format!("{p}.{}", &c[1]));
                (name, initializer, c.get(0).unwrap().start())
            })
        })
        .collect()
}

/// The classes a source declares as extensions: they implement `Extension` or one of its hook interfaces.
/// The names are common (JUnit has an `Extension`), so only a source that mentions `org.mockserver.extension` counts.
fn extension_classes(text: &str) -> Vec<(String, usize)> {
    if !text.contains("org.mockserver.extension") {
        return Vec::new();
    }
    let package = PACKAGE.captures(text).map(|c| c[1].to_string());
    CLASS
        .captures_iter(text)
        .filter(|c| EXTENSIONS.iter().any(|n| regex::Regex::new(&format!(r"\b{n}\b")).unwrap().is_match(&c[2])))
        .map(|c| (package.as_ref().map_or_else(|| c[1].to_string(), |p| format!("{p}.{}", &c[1])), c.get(0).unwrap().start()))
        .collect()
}

/// The callback and initializer classes a source implements (for `classpath.libs`).
pub fn classes(text: &str) -> Vec<String> {
    implementations(text).into_iter().map(|(name, _, _)| name).collect()
}

/// The findings of one source file.
pub fn scan(text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("import ") || trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
        if let Some(pattern) = IN_JVM.iter().find(|p| line.contains(*p)) {
            findings.push(Finding::new(rules::PACKAGING_MAVEN, Severity::Action, n + 1, excerpt(line, pattern), super::build_files::IN_JVM_VERDICT));
        }
        if line.contains("MockServerContainer") || line.contains("DockerImageName.parse(\"mockserver/mockserver") {
            findings.push(Finding::new(rules::IMAGE_TESTCONTAINERS, Severity::Action, n + 1, line.trim(), format!("use the mock-server image as a compatible substitute: {TESTCONTAINERS_SNIPPET}")));
        }
    }
    for (class, initializer, at) in implementations(text) {
        let line = super::line_of(text, at);
        findings.push(if initializer {
            Finding::new(rules::CLASSPATH_INITIALIZER, Severity::Action, line, format!("class {class}"), format!("Java classes are not loaded: rebuild {class} as a WASM plugin initializer ({}), or move its expectations to initializationJsonPath", rules::PLUGIN_SDK))
        } else {
            Finding::new(rules::CLASSPATH_CALLBACK, Severity::Action, line, format!("class {class}"), format!("Java classes are not loaded: rebuild {class} as a callback plugin ({}); the class name stays the same in the expectation", rules::PLUGIN_SDK))
        });
    }
    for (class, at) in extension_classes(text) {
        findings.push(rules::extensions_finding(format!("class {class}"), super::line_of(text, at), class.clone()).with_verdict(format!("Java extensions are not loaded: {class} implements an extension interface and a server that names it refuses to start; move its job to a callback plugin ({}) or an expectation ({})", rules::PLUGIN_SDK, rules::EXTENSIONS_REASON)));
    }
    findings.sort_by_key(|f| f.line);
    findings
}

/// The statement around `pattern`, trimmed to something short.
fn excerpt(line: &str, pattern: &str) -> String {
    let line = line.trim();
    let at = line.find(pattern).unwrap_or(0);
    let start = line[..at].rfind(['=', '(', ' ']).filter(|_| pattern.starts_with('@')).map_or(0, |i| i + 1);
    let excerpt = &line[start.min(at)..];
    let end = excerpt.find(';').unwrap_or(excerpt.len());
    excerpt[..end].chars().take(120).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST: &str = "package com.acme;\n\nimport org.mockserver.integration.ClientAndServer;\nimport static org.mockserver.integration.ClientAndServer.startClientAndServer;\n\nclass ApiTest {\n    private ClientAndServer server = startClientAndServer(1080);\n    // new ClientAndServer(1080) in a comment\n    MockServerContainer container = new MockServerContainer(DockerImageName.parse(\"mockserver/mockserver:mockserver-8.0.0\"));\n}\n\npublic class Greeter implements ExpectationResponseCallback {\n}\nclass Seed\n    implements PluginExpectationInitializer {\n}\n";

    #[test]
    fn in_jvm_servers_containers_and_callbacks() {
        let found: Vec<(&str, usize, String)> = scan(TEST).into_iter().map(|f| (f.rule, f.line, f.found)).collect();
        assert_eq!(found, [
            (rules::PACKAGING_MAVEN, 7, "private ClientAndServer server = startClientAndServer(1080)".to_string()),
            (rules::IMAGE_TESTCONTAINERS, 9, "MockServerContainer container = new MockServerContainer(DockerImageName.parse(\"mockserver/mockserver:mockserver-8.0.0\"));".to_string()),
            (rules::CLASSPATH_CALLBACK, 12, "class com.acme.Greeter".to_string()),
            (rules::CLASSPATH_INITIALIZER, 14, "class com.acme.Seed".to_string()),
        ]);
        assert_eq!(classes(TEST), ["com.acme.Greeter", "com.acme.Seed"]);
    }

    #[test]
    fn extension_classes_are_blockers() {
        let text = "package com.acme;\n\nimport org.mockserver.extension.AdminApiExtension;\nimport org.mockserver.extension.RequestFilter;\n\npublic class Audit implements AdminApiExtension, RequestFilter {\n}\nclass Seed implements ExpectationInitializer, org.mockserver.extension.Extension {\n}\n";
        let found: Vec<(&str, Severity, usize, String)> = scan(text).into_iter().map(|f| (f.rule, f.severity, f.line, f.found)).collect();
        assert_eq!(found, [
            (rules::CLASSPATH_EXTENSIONS, Severity::Blocker, 6, "class com.acme.Audit".to_string()),
            (rules::CLASSPATH_INITIALIZER, Severity::Action, 8, "class com.acme.Seed".to_string()),
            (rules::CLASSPATH_EXTENSIONS, Severity::Blocker, 8, "class com.acme.Seed".to_string()),
        ]);
        assert!(classes(text).contains(&"com.acme.Seed".to_string()) && !classes(text).contains(&"com.acme.Audit".to_string()));
        // JUnit's Extension is not MockServer's
        assert!(scan("import org.junit.jupiter.api.extension.Extension;\nclass Hook implements Extension {\n}\n").is_empty());
    }

    #[test]
    fn kotlin_classes() {
        assert_eq!(classes("class Hook : ExpectationForwardCallback {\n}"), ["Hook"]);
        assert!(classes("class Other : SomethingElse {}").is_empty());
    }
}

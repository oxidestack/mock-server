//! Maven and Gradle builds: `pom.xml`, `build.gradle(.kts)` and `libs.versions.toml`, read for the
//! `org.mock-server` artifacts. In-JVM servers (`packaging.maven`), the WAR (`packaging.war`) and the blob-store
//! modules (`classpath.blob`) are reported; the clients stay.

use std::sync::LazyLock;

use super::rules;
use super::{Finding, Severity};

/// What an artifact that starts an in-JVM server becomes.
pub const IN_JVM_VERDICT: &str = "starts an in-JVM MockServer: use Testcontainers' MockServerContainer with the mock-server image, or the Java launcher (java-launcher/, a mockserver-netty drop-in that runs the binary); the client artifacts stay";

const IN_JVM: [&str; 6] = ["mockserver-netty", "mockserver-junit-rule", "mockserver-junit-jupiter", "mockserver-spring-test-listener", "mockserver-spring-boot-starter", "mockserver-maven-plugin"];
const WAR: [&str; 2] = ["mockserver-war", "mockserver-proxy-war"];
const CLIENT: [&str; 2] = ["mockserver-client-java", "mockserver-core"];

/// The blob-store module a jar or artifact name is (`s3`, `gcs`, `azure`).
pub fn blob_module(name: &str) -> Option<&'static str> {
    ["s3", "gcs", "azure"].into_iter().find(|m| name.contains(&format!("mockserver-blob-{m}")))
}

static ARTIFACT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r#"(?:<artifactId>\s*|org\.mock-server:|name\s*=\s*")(mockserver-[A-Za-z0-9-]+)"#).unwrap());

/// The findings of one build file.
pub fn scan(text: &str) -> Vec<Finding> {
    if !text.contains("org.mock-server") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for capture in ARTIFACT.captures_iter(text) {
        let m = capture.get(1).unwrap();
        let artifact = m.as_str();
        let line = super::line_of(text, m.start());
        let base = artifact.strip_suffix("-no-dependencies").unwrap_or(artifact);
        let found = format!("org.mock-server:{artifact}");
        let finding = if IN_JVM.contains(&base) {
            Finding::new(rules::PACKAGING_MAVEN, Severity::Action, line, found, IN_JVM_VERDICT)
        } else if WAR.contains(&base) {
            Finding::new(rules::PACKAGING_WAR, Severity::Blocker, line, found, "no servlet deployment: run the mock-server container beside the servlet container")
        } else if let Some(module) = blob_module(base) {
            Finding::new(rules::CLASSPATH_BLOB, Severity::Action, line, found, format!("the {module} store is built in: set MOCKSERVER_BLOB_STORE_MODULES={module} on the server instead of adding the module"))
        } else if CLIENT.contains(&base) {
            Finding::new(rules::PACKAGING_MAVEN, Severity::Info, line, found, "unchanged: the client talks to mock-server over the identical wire protocol")
        } else {
            continue;
        };
        findings.push(finding.key(artifact));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pom_artifacts() {
        let pom = "<project>\n  <dependencies>\n    <dependency>\n      <groupId>org.mock-server</groupId>\n      <artifactId>mockserver-junit-jupiter-no-dependencies</artifactId>\n    </dependency>\n    <dependency>\n      <groupId>org.mock-server</groupId>\n      <artifactId>mockserver-client-java</artifactId>\n    </dependency>\n  </dependencies>\n  <build><plugins><plugin><groupId>org.mock-server</groupId><artifactId>mockserver-maven-plugin</artifactId></plugin></plugins></build>\n</project>\n";
        let found: Vec<(&str, Severity, usize)> = scan(pom).iter().map(|f| (f.rule, f.severity, f.line)).collect();
        assert_eq!(found, [(rules::PACKAGING_MAVEN, Severity::Action, 5), (rules::PACKAGING_MAVEN, Severity::Info, 9), (rules::PACKAGING_MAVEN, Severity::Action, 12)]);
    }

    #[test]
    fn gradle_and_catalogs() {
        let gradle = "dependencies {\n  testImplementation(\"org.mock-server:mockserver-netty:8.0.0\")\n  implementation 'org.mock-server:mockserver-war:8.0.0'\n  runtimeOnly(\"org.mock-server:mockserver-blob-s3:8.0.0\")\n}\n";
        let found: Vec<(&str, usize)> = scan(gradle).iter().map(|f| (f.rule, f.line)).collect();
        assert_eq!(found, [(rules::PACKAGING_MAVEN, 2), (rules::PACKAGING_WAR, 3), (rules::CLASSPATH_BLOB, 4)]);
        let toml = "[libraries]\nmockserver = { group = \"org.mock-server\", name = \"mockserver-spring-test-listener\", version = \"8.0.0\" }\n";
        assert_eq!(scan(toml)[0].rule, rules::PACKAGING_MAVEN);
        assert!(scan("<artifactId>mockserver-netty</artifactId>").is_empty(), "not an org.mock-server build");
    }
}

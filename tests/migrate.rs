//! `mock-server migrate` over the fixture repository
//! `tests/files/migrate/repo/`: the text report, the JSON report, `--out` and `--write` against goldens. The input
//! modules have their unit tests in `src/migrate/`. `MOCK_SERVER_MIGRATE_BLESS=1` rewrites the goldens.

use std::path::{Path, PathBuf};

use mock_server::migrate;

const REPO: &str = "tests/files/migrate/repo";
const REPORT_GOLDEN: &str = "tests/files/migrate/report.golden.txt";
const WRITTEN_GOLDEN: &str = "tests/files/migrate/written";
/// The files `--write` changes in the fixture.
const REWRITTEN: [&str; 2] = ["docker-compose.yml", "helm/values.yaml"];

fn run(args: &[&str]) -> migrate::Outcome {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    migrate::run(&args, &[])
}

fn bless() -> bool {
    std::env::var("MOCK_SERVER_MIGRATE_BLESS").is_ok_and(|v| v == "1")
}

fn check(golden: &str, actual: &str) {
    if bless() {
        if let Some(parent) = Path::new(golden).parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(golden, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(golden).unwrap_or_else(|e| panic!("{golden}: {e}"));
    assert_eq!(actual, expected, "{golden} differs");
}

/// A fresh copy of the fixture under the test target directory.
fn copy_of_repo(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("migrate").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(Path::new(REPO), &dir);
    dir
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn the_text_report_of_the_fixture_repository() {
    let outcome = run(&[REPO]);
    assert_eq!(outcome.err, "");
    assert_eq!(outcome.code, 1, "warn, action and blocker findings fail the run");
    check(REPORT_GOLDEN, &outcome.out);
    assert!(!outcome.out.contains("/ignored/"), ".gitignore is respected");
}

#[test]
fn the_json_report_has_the_stable_schema() {
    let outcome = run(&["--format", "json", REPO]);
    let report: serde_json::Value = serde_json::from_str(&outcome.out).unwrap();
    assert_eq!(report["version"], 1);
    let findings = report["findings"].as_array().unwrap();
    for f in findings {
        for field in ["file", "line", "key", "rule", "severity", "found", "verdict", "replacement", "mechanical", "applied"] {
            assert!(f.get(field).is_some(), "{field} missing in {f}");
        }
    }
    assert_eq!(report["summary"]["blocker"], 1);
    assert!(findings.iter().any(|f| f["rule"] == "template.javascript" && f["file"] == "tests/files/migrate/repo/config/expectations.json"));
    let scrape = findings.iter().find(|f| f["rule"] == "metrics.scrape").expect("the scrape job is reported");
    assert_eq!((scrape["file"].as_str(), scrape["severity"].as_str(), scrape["line"].as_u64()), (Some("tests/files/migrate/repo/prometheus/prometheus.yml"), Some("info"), Some(7)));
}

#[test]
fn replace_dashboards_writes_ours_over_upstreams() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("migrate").join("out-dashboards");
    let _ = std::fs::remove_dir_all(&out);
    let outcome = run(&["--out", out.to_str().unwrap(), "--replace-dashboards", REPO]);
    assert_eq!(outcome.err, "");
    assert_eq!(std::fs::read_to_string(out.join("grafana/mockserver-server.json")).unwrap(), std::fs::read_to_string("grafana/mock-server-server.json").unwrap());
    assert_eq!(std::fs::read_to_string(out.join("grafana/mockserver-load-injection.json")).unwrap(), std::fs::read_to_string("grafana/mock-server-load-injection.json").unwrap());
    let mut written = Vec::new();
    collect(&out, &out, &mut written);
    let mut expected: Vec<&str> = REWRITTEN.into_iter().chain(["grafana/mockserver-load-injection.json", "grafana/mockserver-server.json"]).collect();
    expected.sort_unstable();
    assert_eq!(written, expected);
    assert!(outcome.out.contains("metrics.jvm-series") && outcome.out.contains("the dashboard is replaced (metrics.dashboard)  [applied]"), "{}", outcome.out);
    // the rule file's jvm_* expressions are never rewritten
    assert!(!out.join("prometheus/rules.yml").exists());
    let replaced = run(&["--fail-on", "info", "--verbose", &out.join("grafana").to_string_lossy()]);
    assert!(!replaced.out.contains("jvm_"), "ours query no jvm_* series: {}", replaced.out);
}

#[test]
fn out_mirrors_the_rewritten_files() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("migrate").join("out");
    let _ = std::fs::remove_dir_all(&out);
    let outcome = run(&["--out", out.to_str().unwrap(), REPO]);
    assert_eq!(outcome.err, "");
    for file in REWRITTEN {
        check(&format!("{WRITTEN_GOLDEN}/{file}"), &std::fs::read_to_string(out.join(file)).unwrap());
    }
    let mut written = Vec::new();
    collect(&out, &out, &mut written);
    assert_eq!(written, REWRITTEN, "only the rewritten files are written");
    assert!(!Path::new(REPO).join("docker-compose.yml.orig").exists(), "--out leaves the inputs alone");
}

#[test]
fn write_rewrites_in_place_and_keeps_the_originals() {
    let repo = copy_of_repo("write");
    let outcome = run(&["--write", repo.to_str().unwrap()]);
    assert_eq!(outcome.err, "");
    for file in REWRITTEN {
        if !bless() {
            assert_eq!(std::fs::read_to_string(repo.join(file)).unwrap(), std::fs::read_to_string(format!("{WRITTEN_GOLDEN}/{file}")).unwrap(), "{file}");
        }
        assert_eq!(std::fs::read_to_string(repo.join(format!("{file}.orig"))).unwrap(), std::fs::read_to_string(Path::new(REPO).join(file)).unwrap(), "{file}.orig");
    }
    assert_eq!(std::fs::read_to_string(repo.join("pom.xml")).unwrap(), std::fs::read_to_string(Path::new(REPO).join("pom.xml")).unwrap());
    // a second run finds nothing more to rewrite, and skips the .orig copies
    let again = run(&["--write", "--fail-on", "blocker", repo.to_str().unwrap()]);
    assert!(again.out.contains("summary: 4 rewrite, "), "only the two image references and the two dashboards (not replaced without --replace-dashboards) are left: {}", again.out);
    assert!(!again.out.contains(".orig"));
    assert_eq!(again.code, 1, "the blocker remains");
    let no_backup = copy_of_repo("no-backup");
    run(&["--write", "--no-backup", no_backup.to_str().unwrap()]);
    assert!(!no_backup.join("docker-compose.yml.orig").exists());
}

#[test]
fn usage_and_read_errors_exit_2() {
    let outcome = run(&["--format", "xml"]);
    assert_eq!(outcome.code, 2);
    assert!(outcome.err.starts_with("Invalid value for option '--format'"), "{}", outcome.err);
    let outcome = run(&["tests/files/migrate/missing"]);
    assert_eq!(outcome.code, 2);
    assert!(outcome.err.starts_with("cannot read tests/files/migrate/missing"), "{}", outcome.err);
    let help = run(&["--help"]);
    assert_eq!((help.code, help.out.starts_with("Usage: mock-server migrate")), (0, true));
    assert!(help.out.contains("Reports what a MockServer 9.2.0 deployment relies on"), "{}", help.out);
}

#[test]
fn fail_on_moves_the_threshold() {
    let file = format!("{REPO}/pom.xml");
    assert_eq!(run(&[&file]).code, 1, "an action fails by default");
    assert_eq!(run(&["--fail-on", "blocker", &file]).code, 0);
    assert_eq!(run(&["--fail-on", "info", &format!("{REPO}/helm/Chart.yaml")]).code, 0, "nothing found");
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect(root, &path, out);
        } else {
            out.push(path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"));
        }
    }
}

#[test]
fn extensions_are_blockers_under_their_own_rule() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("migrate").join("extensions");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("docker-compose.yml"), "services:\n  mockserver:\n    image: mockserver/mockserver:mockserver-9.2.0\n    environment:\n      MOCKSERVER_EXTENSIONS: com.acme.Audit\n    volumes:\n      - ./ext:/extensions\n    command: --extensions com.acme.Audit\n").unwrap();
    std::fs::write(dir.join("Audit.java"), "package com.acme;\nimport org.mockserver.extension.RequestFilter;\npublic class Audit implements RequestFilter {\n}\n").unwrap();
    let outcome = run(&[dir.to_str().unwrap()]);
    assert_eq!(outcome.err, "");
    assert_eq!(outcome.code, 1, "{}", outcome.out);
    assert_eq!(outcome.out.matches("blocker  classpath.extensions").count(), 4, "{}", outcome.out);
    assert!(outcome.out.contains("class com.acme.Audit"), "{}", outcome.out);
    assert!(outcome.out.contains(migrate::rules::EXTENSIONS_REASON), "{}", outcome.out);
}

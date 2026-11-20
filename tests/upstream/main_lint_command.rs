//! Port of upstream's `MainLintCommandTest` (`org.mockserver.cli`): `mockserver lint <file>...`, which the
//! Java test runs as `Main.main` inside its own JVM on temporary files (`not-tranched.txt`, category C). The exact
//! texts against the oracle are the process scenarios `tests/process_scenarios/cli_lint_*.json`.

use std::collections::HashMap;
use std::path::PathBuf;

use mock_server::cli::{self, Action};

struct Output {
    exit_code: u8,
    out: String,
    err: String,
}

struct Dir(PathBuf);

impl Dir {
    fn new(test: &str) -> Dir {
        let dir = std::env::temp_dir().join(format!("msrs-lint-{test}-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        Dir(dir)
    }

    fn file(&self, name: &str, content: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, content).unwrap();
        path.to_string_lossy().into_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn lint(arguments: &[&str]) -> Output {
    let mut args = vec!["lint".to_string()];
    args.extend(arguments.iter().map(|a| a.to_string()));
    let planned = cli::plan(&args, &HashMap::new());
    let Action::Lint(plan) = planned.action else { panic!("not a lint: out={:?} err={:?}", planned.out, planned.err) };
    let (out, err, exit_code) = cli::run_lint(&plan);
    Output { exit_code, out: planned.out + &out, err: planned.err + &err }
}

#[test]
fn should_report_a_shadowed_expectation_across_two_files_and_exit_zero() {
    let dir = Dir::new("shadowed");
    let first = dir.file("first.json", r#"[{"httpRequest":{"method":"GET","path":"/users/.*"},"httpResponse":{"body":"all"}}]"#);
    let second = dir.file("second.json", r#"{"id":"user-one","httpRequest":{"method":"GET","path":"/users/1"},"httpResponse":{"body":"one"}}"#);

    let output = lint(&[&first, &second]);

    assert_eq!(output.exit_code, 0);
    assert!(output.out.contains(&format!("{second} [0] GET /users/1")), "{}", output.out);
    assert!(output.out.contains("WARNING SHADOWED: never matches: GET /users/.* is evaluated first"), "{}", output.out);
    assert!(output.out.contains(&format!("see {first} [0] GET /users/.*")), "{}", output.out);
    assert!(output.out.contains("checked 2 expectation(s) in 2 file(s): 0 error(s), 1 warning(s), 0 info"), "{}", output.out);
    assert!(std::fs::read_to_string(&second).unwrap().contains("\"user-one\""), "lint never changes the file");
}

#[test]
fn should_exit_one_on_a_warning_only_with_strict() {
    let dir = Dir::new("strict");
    let expectations = dir.file("no-slash.json", r#"[{"httpRequest":{"path":"users"},"httpResponse":{}}]"#);

    assert_eq!(lint(&[&expectations]).exit_code, 0);
    let strict = lint(&["--strict", &expectations]);
    assert_eq!(strict.exit_code, 1);
    assert!(strict.out.contains("PATH_MISSING_LEADING_SLASH"), "{}", strict.out);
}

#[test]
fn should_exit_one_on_an_invalid_expectation() {
    let dir = Dir::new("invalid");
    let expectations = dir.file("invalid.json", r#"[{"httpRequest":{"path":"/ok"},"httpResponse":{}},{"httpRequest":{"path":"/bad","method":42},"httpResponse":{}}]"#);

    let output = lint(&[&expectations]);

    assert_eq!(output.exit_code, 1);
    assert!(output.out.contains(&format!("{expectations} [1]")), "{}", output.out);
    assert!(output.out.contains("ERROR INVALID_EXPECTATION"), "{}", output.out);
}

#[test]
fn should_print_the_report_as_json_with_each_issues_file() {
    let dir = Dir::new("json");
    let expectations = dir.file("json.json", r#"[{"httpRequest":{"path":"/api/*"},"httpResponse":{}}]"#);

    let output = lint(&["--json", &expectations]);

    let report: serde_json::Value = serde_json::from_str(&output.out).unwrap();
    assert_eq!(output.exit_code, 0);
    assert_eq!(report["issues"][0]["rule"], "PATH_GLOB_WILDCARD");
    assert_eq!(report["issues"][0]["file"], expectations.as_str());
    assert_eq!(report["issues"][0]["index"], 0);
}

#[test]
fn should_report_a_missing_file_as_an_error_without_the_run_usage() {
    let dir = Dir::new("missing");
    let output = lint(&[&dir.0.join("missing.json").to_string_lossy()]);

    assert_eq!(output.exit_code, 1);
    assert!(output.err.contains("ERROR:  could not read expectations from"), "{}", output.err);
    assert!(!output.out.contains("-serverPort"), "{}", output.out);
}

#[test]
fn should_name_a_duplicate_id_by_its_file_and_index_in_that_file() {
    let dir = Dir::new("dup");
    let first = dir.file("dup-first.json", r#"[{"httpRequest":{"path":"/a"},"httpResponse":{}},{"id":"dup","httpRequest":{"path":"/b"},"httpResponse":{}}]"#);
    let second = dir.file("dup-second.json", r#"[{"id":"dup","httpRequest":{"path":"/c"},"httpResponse":{}}]"#);

    let output = lint(&[&first, &second]);

    assert!(output.out.contains(&format!("{first} [1] any method /b")), "{}", output.out);
    assert!(
        output.out.contains("WARNING DUPLICATE_ID: is replaced by a later entry with the same id (any method /c); a file loaded later replaces an earlier file's entries with the same id"),
        "{}",
        output.out
    );
    assert!(output.out.contains(&format!("see {second} [0] any method /c")), "{}", output.out);
    assert!(!output.out.contains("index 2"), "no index from the combined list leaks into the message: {}", output.out);
}

// `shouldNotFailWhenARegexOverflowsTheStackDuringTheShadowingCheck` is not ported here: the oracle reads a
// `StackOverflowError` in `java.util.regex` as "does not cover" (`RegexBudget.matches`), so it reports no SHADOWED for
// `/(a|b)*` over a 12,001-character path, where our regex engine proves the cover. The process scenario
// `cli_lint_deep_regex` holds the oracle's output, which differs on this path until the shadowing check's regex budget is matched.

#[test]
fn should_name_the_last_entry_for_a_duplicate_id_in_one_file_as_kept_as_loading_the_file_does() {
    let dir = Dir::new("dup-in-file");
    let expectations = dir.file("dup-in-file.json", r#"[{"id":"dup","httpRequest":{"path":"/a"},"httpResponse":{}},{"id":"dup","httpRequest":{"path":"/b"},"httpResponse":{}}]"#);

    let output = lint(&[&expectations]);

    assert!(output.out.contains(&format!("{expectations} [0] any method /a")), "{}", output.out);
    assert!(
        output.out.contains("WARNING DUPLICATE_ID: is replaced by a later entry in the same file with the same id (any method /b); loading a file keeps only the last entry for each id"),
        "{}",
        output.out
    );
    assert!(output.out.contains(&format!("see {expectations} [1] any method /b")), "{}", output.out);
}

#[test]
fn should_be_a_known_subcommand() {
    assert_eq!(cli::preprocess(&["lint".to_string(), "./expectations.json".to_string()])[0], "lint");
}

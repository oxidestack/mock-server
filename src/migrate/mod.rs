//! `mock-server migrate` finds every place in a
//! repository that relies on MockServer's JVM or its Java packaging, says what mock-server does with it, and applies
//! the mechanical rewrites.
//!
//! `main.rs` intercepts the subcommand before `cli::plan`, so the picocli command tree stays as the oracle's. The
//! layout is: [`scan`] finds and classifies the inputs, one module per input kind turns a file's
//! contents into [`Finding`]s (with their [`Edit`]s), [`rules`] holds the rule table and the verdicts (configuration
//! keys and JVM options take theirs from [`crate::jvm_policy`]), and [`report`] writes text or JSON. Every input module
//! is a pure function of the file's contents and the [`Context`], so its tests need neither a socket nor a filesystem.
//! Nothing here starts a server or makes a network call.

pub mod build_files;
pub mod cluster;
pub mod compose;
pub mod dockerfile;
pub mod env_file;
pub mod expectations;
pub mod helm;
pub mod k8s;
pub mod logging;
pub mod metrics;
pub mod properties;
pub mod report;
pub mod rules;
pub mod scan;
pub mod shell;
pub mod sources;
pub mod yaml;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// How much a finding asks of the user, in increasing order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Supported as-is; listed only with `--verbose`.
    Info,
    /// A mechanical change, applied by `--write` when the finding is [`Finding::mechanical`].
    Rewrite,
    /// No effect in mock-server (the server says so at startup); removing it is safe.
    Warn,
    /// A person must change something.
    Action,
    /// No counterpart exists.
    Blocker,
}

impl Severity {
    pub const ALL: [Severity; 5] = [Severity::Info, Severity::Rewrite, Severity::Warn, Severity::Action, Severity::Blocker];

    pub fn name(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Rewrite => "rewrite",
            Severity::Warn => "warn",
            Severity::Action => "action",
            Severity::Blocker => "blocker",
        }
    }

    pub fn parse(name: &str) -> Option<Severity> {
        Severity::ALL.into_iter().find(|s| s.name().eq_ignore_ascii_case(name))
    }
}

/// A textual change to one file: the bytes `start..end` become `text` (an insertion when `start == end`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    pub start: usize,
    pub end: usize,
    pub text: String,
}

impl Edit {
    pub fn replace(start: usize, end: usize, text: impl Into<String>) -> Edit {
        Edit { start, end, text: text.into() }
    }

    pub fn insert(at: usize, text: impl Into<String>) -> Edit {
        Edit { start: at, end: at, text: text.into() }
    }
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The rule id (`image.reference`, `jvm.options.memory`, ...), one of [`rules::RULES`].
    pub rule: &'static str,
    pub severity: Severity,
    /// 1-based; 0 when the input has no lines (the process environment).
    pub line: usize,
    /// The key path in YAML or JSON (`services.mockserver.environment.JAVA_TOOL_OPTIONS`), or the variable/key name.
    pub key: Option<String>,
    /// What was found, as shown (sensitive values redacted).
    pub found: String,
    /// What mock-server does with it.
    pub verdict: String,
    /// The rewritten form, as shown, when there is one.
    pub replacement: Option<String>,
    /// Whether `--write` applies this finding (its edits, possibly shared with the file's other findings).
    pub mechanical: bool,
    /// The edits that implement the rewrite. A rewrite whose edits another finding of the same file carries (several
    /// tokens of one variable rewritten together) has none of its own but is still [`Finding::mechanical`].
    pub edits: Vec<Edit>,
}

impl Finding {
    pub fn new(rule: &'static str, severity: Severity, line: usize, found: impl Into<String>, verdict: impl Into<String>) -> Finding {
        Finding { rule, severity, line, key: None, found: found.into(), verdict: verdict.into(), replacement: None, mechanical: false, edits: Vec::new() }
    }

    pub fn key(mut self, key: impl Into<String>) -> Finding {
        self.key = Some(key.into());
        self
    }

    pub fn with_verdict(mut self, verdict: impl Into<String>) -> Finding {
        self.verdict = verdict.into();
        self
    }

    pub fn replacement(mut self, replacement: impl Into<String>) -> Finding {
        self.replacement = Some(replacement.into());
        self
    }

    /// Marks the finding as applied by `--write`, with these edits.
    pub fn mechanical(mut self, edits: Vec<Edit>) -> Finding {
        self.mechanical = true;
        self.edits = edits;
        self
    }
}

/// What the input modules may know about the rest of the scan: the cross-file facts collected in a first pass.
#[derive(Debug, Default, Clone)]
pub struct Context {
    /// A logging file's name (its last path component) and the level it sets for `org.mockserver`, already in
    /// MockServer's level names (`DEBUG`, ...), for the `-Djava.util.logging.config.file=` rewrite (`logging.file`).
    pub logging_levels: BTreeMap<String, String>,
    /// Callback and initializer classes the JVM sources implement (fully qualified), for `classpath.libs`.
    pub jvm_classes: Vec<String>,
    /// `--replace-dashboards`: upstream's example dashboards are replaced by ours (`metrics.dashboard`).
    pub replace_dashboards: bool,
}

/// One analysed input and what was found in it.
#[derive(Debug, Clone)]
pub struct FileReport {
    /// The path as shown: the `PATH` argument as typed, joined with the path below it.
    pub display: String,
    /// The file on disk, `None` for the process environment.
    pub path: Option<PathBuf>,
    /// The path relative to its root, for `--out` (the file name for a root that is a file).
    pub relative: PathBuf,
    pub findings: Vec<Finding>,
}

/// The command-line options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub paths: Vec<String>,
    pub json: bool,
    pub write: bool,
    pub backup: bool,
    pub out: Option<PathBuf>,
    pub fail_on: Option<Severity>,
    pub verbose: bool,
    pub env: bool,
    pub helm_values: Vec<String>,
    pub replace_dashboards: bool,
}

/// The help text; `{version}` stands for the MockServer version mock-server reports (`control::VERSION`).
const USAGE: &str = "Usage: mock-server migrate [--format text|json] [--write [--no-backup] | --out DIR]
                              [--replace-dashboards] [--fail-on info|rewrite|warn|action|blocker] [--verbose] [--env]
                              [--helm-values FILE]... [PATH...]
Reports what a MockServer {version} deployment relies on that is JVM-only, and what mock-server does with it.
  PATH                 files or directories to scan (default: .); .gitignore is respected, target/,
                       node_modules/ and .git/ are skipped
  --format FORMAT      text (default) or json
  --write              apply the mechanical rewrites in place, keeping each original as <file>.orig
  --no-backup          with --write, keep no .orig copies
  --out DIR            write the rewritten files under DIR, mirroring the tree; the inputs stay untouched
  --replace-dashboards with --write or --out, also replace upstream's example Grafana dashboards with
                       mock-server's (overwrites local edits to them)
  --fail-on SEVERITY   exit 1 when a finding of this severity or above remains (default: warn; with --write or
                       --out, an unapplied rewrite also counts)
  --verbose            also list the info findings (supported as-is)
  --env                also check this process's environment
  --helm-values FILE   read FILE as values of the upstream mockserver Helm chart
Exit codes: 0 nothing at or above the threshold, 1 findings at or above it, 2 a usage or read error.
";

pub fn usage() -> String {
    USAGE.replace("{version}", crate::control::VERSION)
}

/// Parses the arguments after `migrate`. `Err` is the usage error's message.
pub fn parse_options(args: &[String]) -> Result<Option<Options>, String> {
    let mut options = Options { paths: Vec::new(), json: false, write: false, backup: true, out: None, fail_on: None, verbose: false, env: false, helm_values: Vec::new(), replace_dashboards: false };
    let mut iter = args.iter();
    let mut only_paths = false;
    while let Some(arg) = iter.next() {
        if only_paths || !arg.starts_with('-') || arg == "-" {
            options.paths.push(arg.clone());
            continue;
        }
        let (name, attached) = match arg.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value.to_string())),
            _ => (arg.as_str(), None),
        };
        let mut value = |what: &str| -> Result<String, String> {
            attached.clone().or_else(|| iter.next().cloned()).ok_or_else(|| format!("Missing required parameter for option '{name}' ({what})"))
        };
        match name {
            "--" => only_paths = true,
            "-h" | "--help" => return Ok(None),
            "--format" => match value("FORMAT")?.as_str() {
                "text" => options.json = false,
                "json" => options.json = true,
                other => return Err(format!("Invalid value for option '--format': '{other}' is not one of text, json")),
            },
            "--write" => options.write = true,
            "--no-backup" => options.backup = false,
            "--replace-dashboards" => options.replace_dashboards = true,
            "--out" => options.out = Some(PathBuf::from(value("DIR")?)),
            "--fail-on" => {
                let given = value("SEVERITY")?;
                options.fail_on = Some(Severity::parse(&given).ok_or_else(|| format!("Invalid value for option '--fail-on': '{given}' is not one of info, rewrite, warn, action, blocker"))?);
            }
            "-v" | "--verbose" => options.verbose = true,
            "--env" => options.env = true,
            "--helm-values" => options.helm_values.push(value("FILE")?),
            _ => return Err(format!("Unknown option: '{arg}'")),
        }
    }
    if options.write && options.out.is_some() {
        return Err("--write and --out are mutually exclusive".into());
    }
    if !options.backup && !options.write {
        return Err("--no-backup needs --write".into());
    }
    if options.replace_dashboards && !options.write && options.out.is_none() {
        return Err("--replace-dashboards needs --write or --out".into());
    }
    if options.paths.is_empty() && options.helm_values.is_empty() && !options.env {
        options.paths.push(".".into());
    }
    Ok(Some(options))
}

/// What a run printed and its exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub out: String,
    pub err: String,
    pub code: u8,
}

/// `mock-server migrate <args>`: parses, scans, reports and (with `--write`/`--out`) rewrites.
pub fn run(args: &[String], env: &[(String, String)]) -> Outcome {
    let options = match parse_options(args) {
        Ok(Some(options)) => options,
        Ok(None) => return Outcome { out: usage(), err: String::new(), code: 0 },
        Err(message) => return Outcome { out: String::new(), err: format!("{message}\n{}", usage()), code: 2 },
    };
    let mut err = String::new();
    let mut reports = match scan::analyse(&options, env) {
        Ok(reports) => reports,
        Err(message) => return Outcome { out: String::new(), err: format!("{message}\n"), code: 2 },
    };
    let mut written = Vec::new();
    if options.write || options.out.is_some() {
        match write(&mut reports, &options) {
            Ok(paths) => written = paths,
            Err(message) => {
                err.push_str(&message);
                err.push('\n');
                return Outcome { out: String::new(), err, code: 2 };
            }
        }
    }
    let applied = options.write || options.out.is_some();
    let out = if options.json { report::json(&reports, &written, applied) } else { report::text(&reports, &written, options.verbose, applied) };
    let code = u8::from(exceeds(&reports, &options));
    Outcome { out, err, code }
}

/// Whether a finding at or above the threshold remains: `--fail-on`, else `warn`; with
/// `--write`/`--out` a rewrite that was not applied counts as well.
pub fn exceeds(reports: &[FileReport], options: &Options) -> bool {
    let applied = options.write || options.out.is_some();
    let threshold = options.fail_on.unwrap_or(Severity::Warn);
    reports.iter().flat_map(|r| &r.findings).any(|f| {
        if applied && f.mechanical {
            return false;
        }
        f.severity >= threshold || (applied && options.fail_on.is_none() && f.severity == Severity::Rewrite)
    })
}

/// Applies the edits of every file with mechanical findings; returns the paths written.
fn write(reports: &mut [FileReport], options: &Options) -> Result<Vec<String>, String> {
    let mut written = Vec::new();
    for report in reports.iter() {
        let Some(path) = &report.path else { continue };
        let edits: Vec<Edit> = report.findings.iter().filter(|f| f.mechanical).flat_map(|f| f.edits.iter().cloned()).collect();
        if edits.is_empty() {
            continue;
        }
        let original = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", report.display))?;
        let rewritten = apply_edits(&original, &edits).map_err(|e| format!("{}: {e}", report.display))?;
        let target = match &options.out {
            Some(dir) => dir.join(&report.relative),
            None => path.clone(),
        };
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        if options.out.is_none() && options.backup {
            let backup = backup_path(path);
            std::fs::write(&backup, &original).map_err(|e| format!("cannot write {}: {e}", backup.display()))?;
        }
        std::fs::write(&target, rewritten).map_err(|e| format!("cannot write {}: {e}", target.display()))?;
        written.push(target.display().to_string());
    }
    Ok(written)
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".orig");
    path.with_file_name(name)
}

/// The text with the edits applied, in offset order (insertions at one offset keep their order). Overlapping edits
/// are an error: the modules never produce them, and applying one over the other would lose a change.
pub fn apply_edits(text: &str, edits: &[Edit]) -> Result<String, String> {
    let mut sorted: Vec<&Edit> = edits.iter().collect();
    sorted.sort_by_key(|e| (e.start, e.end));
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for edit in sorted {
        if edit.start < at || edit.end < edit.start || edit.end > text.len() || !text.is_char_boundary(edit.start) || !text.is_char_boundary(edit.end) {
            return Err(format!("overlapping or out-of-range edit at byte {}", edit.start));
        }
        out.push_str(&text[at..edit.start]);
        out.push_str(&edit.text);
        at = edit.end;
    }
    out.push_str(&text[at..]);
    Ok(out)
}

/// The 1-based line of a byte offset.
pub fn line_of(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())].bytes().filter(|&b| b == b'\n').count() + 1
}

/// The byte offset where line `line` (1-based) starts.
pub fn line_start(text: &str, line: usize) -> usize {
    if line <= 1 {
        return 0;
    }
    text.match_indices('\n').nth(line - 2).map_or(text.len(), |(i, _)| i + 1)
}

/// The offset just past the end of the line holding `offset` (past its newline, or the text's end).
pub fn line_end(text: &str, offset: usize) -> usize {
    text[offset.min(text.len())..].find('\n').map_or(text.len(), |i| offset + i + 1)
}

/// The newline the file uses (`\r\n` when its first line ends so).
pub fn newline(text: &str) -> &'static str {
    match text.find('\n') {
        Some(i) if i > 0 && text.as_bytes()[i - 1] == b'\r' => "\r\n",
        _ => "\n",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn options_parse_with_defaults_and_errors() {
        let options = parse_options(&args(&[])).unwrap().unwrap();
        assert_eq!(options.paths, ["."]);
        assert!(!options.json && !options.write && options.backup);
        let options = parse_options(&args(&["--format=json", "--write", "--no-backup", "--fail-on", "action", "deploy", "--", "-odd"])).unwrap().unwrap();
        assert!(options.json && options.write && !options.backup);
        assert_eq!(options.fail_on, Some(Severity::Action));
        assert_eq!(options.paths, ["deploy", "-odd"]);
        assert_eq!(parse_options(&args(&["--help"])), Ok(None));
        assert!(parse_options(&args(&["--format", "sarif"])).unwrap_err().contains("'sarif'"));
        assert!(parse_options(&args(&["--bogus"])).unwrap_err().contains("Unknown option"));
        assert!(parse_options(&args(&["--write", "--out", "x"])).is_err());
        assert!(parse_options(&args(&["--no-backup"])).is_err());
        assert!(parse_options(&args(&["--replace-dashboards"])).unwrap_err().contains("needs --write or --out"));
        assert!(parse_options(&args(&["--out", "x", "--replace-dashboards"])).unwrap().unwrap().replace_dashboards);
        assert!(parse_options(&args(&["--out"])).unwrap_err().contains("Missing required parameter"));
    }

    #[test]
    fn edits_apply_in_order_and_refuse_overlaps() {
        let text = "a b c";
        let edits = [Edit::replace(2, 3, "B"), Edit::insert(5, "\nd"), Edit::insert(5, "\ne"), Edit::replace(0, 1, "")];
        assert_eq!(apply_edits(text, &edits).unwrap(), " B c\nd\ne");
        assert!(apply_edits(text, &[Edit::replace(0, 3, ""), Edit::replace(2, 4, "")]).is_err());
    }

    #[test]
    fn line_helpers() {
        let text = "one\ntwo\r\nthree";
        assert_eq!(line_of(text, 0), 1);
        assert_eq!(line_of(text, 5), 2);
        assert_eq!(line_start(text, 3), 9);
        assert_eq!(line_end(text, 4), 9);
        assert_eq!(line_end(text, 10), text.len());
        assert_eq!(newline(text), "\n");
        assert_eq!(newline("a\r\nb"), "\r\n");
    }

    #[test]
    fn severities_order_and_parse() {
        assert!(Severity::Info < Severity::Rewrite && Severity::Rewrite < Severity::Warn && Severity::Action < Severity::Blocker);
        assert_eq!(Severity::parse("BLOCKER"), Some(Severity::Blocker));
        assert_eq!(Severity::parse("fatal"), None);
    }
}

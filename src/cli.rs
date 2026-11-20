//! The command line of `org.mockserver.cli.Main` (MockServer 9.1.0): a picocli command tree
//! (`run`, `ui`, `proxy`, `openapi`, `import`, `lint`, `demo`, `version`, `help`), the legacy `-serverPort` flags it still
//! accepts, picocli's own parse errors and usage texts, and `Main`'s validation messages.
//!
//! [`plan`] parses an argument vector the way `Main.main` does and returns what the process must print and do:
//! text for stdout and stderr, then an [`Action`] (exit, start a server, or import expectations into a running one).
//! Nothing here starts a server, so the whole surface is testable without a socket.
//!
//! The usage texts under `src/cli_usage/` are the oracle's own output, recorded verbatim (picocli lays them out at
//! 80 columns; porting its layout engine would only reproduce the same bytes). `legacy.txt` is `Main.USAGE` with
//! the launcher name left as `{cmd}` / `{example}`.

use std::collections::{HashMap, HashSet};

use crate::config::Config;

const TOP_USAGE: &str = include_str!("cli_usage/top.txt");
const RUN_USAGE: &str = include_str!("cli_usage/run.txt");
const RUN_BARE_USAGE: &str = include_str!("cli_usage/run_bare.txt");
const UI_USAGE: &str = include_str!("cli_usage/ui.txt");
const PROXY_USAGE: &str = include_str!("cli_usage/proxy.txt");
const OPENAPI_USAGE: &str = include_str!("cli_usage/openapi.txt");
const IMPORT_USAGE: &str = include_str!("cli_usage/import.txt");
const LINT_USAGE: &str = include_str!("cli_usage/lint.txt");
const DEMO_USAGE: &str = include_str!("cli_usage/demo.txt");
const VERSION_USAGE: &str = include_str!("cli_usage/version.txt");
const HELP_USAGE: &str = include_str!("cli_usage/help.txt");
const LEGACY_USAGE: &str = include_str!("cli_usage/legacy.txt");

/// Subcommands in `Main`'s `@Command(subcommands = …)` order.
const SUBCOMMANDS: [&str; 9] = ["run", "ui", "proxy", "openapi", "import", "lint", "demo", "version", "help"];

/// What the process does after the text from [`plan`] is printed.
#[derive(Debug)]
pub enum Action {
    /// Exit with this code (`Main` returns from `main`; a non-zero picocli code is `System.exit`ed).
    Exit(u8),
    /// Start a server, then do `after` once it listens.
    Start(Box<Start>),
    /// `import`: load a file of expectations into a running server.
    Import(ImportPlan),
    /// `lint`: check files of expectations, no server needed.
    Lint(LintPlan),
}

/// What [`plan`] decided: the text to print and then what to do.
#[derive(Debug)]
pub struct Planned {
    pub out: String,
    pub err: String,
    pub action: Action,
}

/// A server to start.
#[derive(Debug)]
pub struct Start {
    pub config: Config,
    pub after: After,
    /// `Main.startServer`'s "using environment variables…" log message, logged at INFO before the server starts;
    /// `None` when the log level from the sources other than the command line turns INFO off (the command line's
    /// own `-logLevel` is applied only after this message).
    pub dump: Option<String>,
}

/// What a subcommand does once its server has started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum After {
    Nothing,
    /// `ui`: print the dashboard URL and open a browser.
    Ui,
    /// `demo`: seed two example expectations and print instructions.
    Demo,
}

#[derive(Debug)]
pub struct ImportPlan {
    pub file: String,
    pub host: String,
    pub port: i32,
}

/// `LintCommand`'s parameters: the files in the order given, `--json`, `--strict`.
#[derive(Debug)]
pub struct LintPlan {
    pub files: Vec<String>,
    pub json: bool,
    pub strict: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cmd {
    Run,
    Ui,
    Proxy,
    OpenApi,
    Import,
    Lint,
    Demo,
    Version,
    Help,
}

impl Cmd {
    fn name(self) -> &'static str {
        match self {
            Cmd::Run => "run",
            Cmd::Ui => "ui",
            Cmd::Proxy => "proxy",
            Cmd::OpenApi => "openapi",
            Cmd::Import => "import",
            Cmd::Lint => "lint",
            Cmd::Demo => "demo",
            Cmd::Version => "version",
            Cmd::Help => "help",
        }
    }

    fn from_name(name: &str) -> Option<Cmd> {
        [Cmd::Run, Cmd::Ui, Cmd::Proxy, Cmd::OpenApi, Cmd::Import, Cmd::Lint, Cmd::Demo, Cmd::Version, Cmd::Help].into_iter().find(|c| c.name() == name)
    }

    fn usage(self) -> &'static str {
        match self {
            Cmd::Run => RUN_USAGE,
            Cmd::Ui => UI_USAGE,
            Cmd::Proxy => PROXY_USAGE,
            Cmd::OpenApi => OPENAPI_USAGE,
            Cmd::Import => IMPORT_USAGE,
            Cmd::Lint => LINT_USAGE,
            Cmd::Demo => DEMO_USAGE,
            Cmd::Version => VERSION_USAGE,
            Cmd::Help => HELP_USAGE,
        }
    }

    fn options(self) -> &'static [Opt] {
        match self {
            Cmd::Run => RUN_OPTS,
            Cmd::Ui | Cmd::Demo => UI_OPTS,
            Cmd::Proxy => PROXY_OPTS,
            Cmd::OpenApi => OPENAPI_OPTS,
            Cmd::Import => IMPORT_OPTS,
            Cmd::Lint => LINT_OPTS,
            Cmd::Version => &[],
            Cmd::Help => HELP_OPTS,
        }
    }

    /// The one positional parameter: its label (`<file>`) and whether it is required.
    fn positional(self) -> Option<&'static str> {
        match self {
            Cmd::OpenApi => Some("specPath"),
            Cmd::Import | Cmd::Lint => Some("file"),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Flag,
    Str,
    Int,
    Map,
    /// `mixinStandardHelpOptions`' `-h`.
    UsageHelp,
    /// …and `-V`.
    VersionHelp,
}

struct Opt {
    names: &'static [&'static str],
    field: &'static str,
    label: &'static str,
    kind: Kind,
    required: bool,
}

impl Opt {
    /// picocli names an option by its longest name in messages.
    fn display(&self) -> &'static str {
        self.names.iter().max_by_key(|n| n.len()).copied().unwrap_or("")
    }
}

const fn o(names: &'static [&'static str], field: &'static str, label: &'static str, kind: Kind, required: bool) -> Opt {
    Opt { names, field, label, kind, required }
}

const HELP: Opt = o(&["-h", "--help"], "usageHelp", "", Kind::UsageHelp, false);
const VERSION: Opt = o(&["-V", "--version"], "versionHelp", "", Kind::VersionHelp, false);
const SYS: Opt = o(&["-D"], "systemProperties", "<key=value>", Kind::Map, false);
const PORT: Opt = o(&["-p", "--port"], "port", "<port>", Kind::Str, false);
const LOG: Opt = o(&["-l", "--log-level"], "logLevel", "<logLevel>", Kind::Str, false);
const DEV: Opt = o(&["--dev"], "dev", "", Kind::Flag, false);

static RUN_OPTS: &[Opt] = &[
    HELP,
    VERSION,
    PORT,
    SYS,
    o(&["--proxy-to"], "proxyTo", "<proxyTo>", Kind::Str, false),
    o(&["--openapi"], "openapi", "<openapi>", Kind::Str, false),
    o(&["--init"], "init", "<init>", Kind::Str, false),
    o(&["--persist"], "persist", "<persist>", Kind::Str, false),
    LOG,
    DEV,
    o(&["--watch"], "watch", "", Kind::Flag, false),
    o(&["--proxy-setup"], "proxySetup", "", Kind::Flag, false),
    o(&["--validate-openapi"], "validateOpenapi", "<validateOpenapi>", Kind::Str, false),
    o(&["--validate-enforce"], "validateEnforce", "", Kind::Flag, false),
    o(&["--extensions", "-extensions"], "extensions", "<extensions>", Kind::Str, false),
    o(&["-serverPort"], "legacyServerPort", "<legacyServerPort>", Kind::Str, false),
    o(&["-proxyRemotePort"], "legacyProxyRemotePort", "<legacyProxyRemotePort>", Kind::Str, false),
    o(&["-proxyRemoteHost"], "legacyProxyRemoteHost", "<legacyProxyRemoteHost>", Kind::Str, false),
    o(&["-logLevel"], "legacyLogLevel", "<legacyLogLevel>", Kind::Str, false),
];
static UI_OPTS: &[Opt] = &[HELP, VERSION, PORT, SYS, LOG, DEV];
static PROXY_OPTS: &[Opt] = &[
    HELP,
    VERSION,
    o(&["--to"], "to", "<to>", Kind::Str, true),
    PORT,
    SYS,
    LOG,
    DEV,
    o(&["--validate-openapi"], "validateOpenapi", "<validateOpenapi>", Kind::Str, false),
    o(&["--validate-enforce"], "validateEnforce", "", Kind::Flag, false),
];
static OPENAPI_OPTS: &[Opt] = &[HELP, VERSION, PORT, SYS, LOG, DEV];
static IMPORT_OPTS: &[Opt] = &[HELP, VERSION, o(&["-p", "--port"], "port", "<port>", Kind::Int, true), o(&["-H", "--host"], "host", "<host>", Kind::Str, false)];
static LINT_OPTS: &[Opt] = &[HELP, VERSION, o(&["--json"], "json", "", Kind::Flag, false), o(&["--strict"], "strict", "", Kind::Flag, false)];
static HELP_OPTS: &[Opt] = &[o(&["-h", "--help"], "usageHelp", "", Kind::UsageHelp, false)];
static TOP_OPTS: &[Opt] = &[HELP, VERSION];

/// A picocli `ParameterException`: printed as `ERROR: <message>` on stderr followed by the usage of the command
/// that failed on stdout, exit code 2.
struct ParamError {
    message: String,
    usage: &'static str,
}

#[derive(Default)]
struct Values {
    strs: HashMap<&'static str, String>,
    flags: HashSet<&'static str>,
    maps: Vec<(String, String)>,
    positional: Option<String>,
    /// Further positionals of `help [COMMAND]…` and every `<file>` of `lint` (arity `1..*`).
    positionals: Vec<String>,
    usage_help: bool,
    version_help: bool,
    unmatched: Vec<(usize, String)>,
}

impl Values {
    fn s(&self, field: &str) -> Option<&str> {
        self.strs.get(field).map(String::as_str)
    }

    fn flag(&self, field: &str) -> bool {
        self.flags.contains(field)
    }
}

/// picocli's `isOption` for a value position: only a registered option name (with or without an attached value) or `--`
/// is refused as the value of the option before it (`-p -x` takes `-x` as the value).
fn resembles_option(arg: &str, opts: &[Opt]) -> bool {
    let name = arg.split_once('=').map_or(arg, |(n, _)| n);
    if opts.iter().any(|o| o.names.contains(&name)) {
        return true;
    }
    arg == "--"
}

fn java_int(text: &str) -> bool {
    let body = text.strip_prefix(['-', '+']).unwrap_or(text);
    !body.is_empty() && body.chars().all(|c| c.is_ascii_digit()) && text.parse::<i64>().is_ok_and(|v| i32::try_from(v).is_ok())
}

/// Parses `args[start..]` as the options and positional parameter of `cmd`. `base` is the index of `args[0]` in the
/// whole argument vector (what picocli counts in "Unmatched argument at index N").
fn parse_command(cmd: Cmd, args: &[String], start: usize) -> Result<Values, ParamError> {
    let opts = cmd.options();
    let err = |message: String| ParamError { message, usage: cmd.usage() };
    let mut v = Values::default();
    let mut seen: HashSet<&'static str> = HashSet::new();
    let mut end_of_options = false;
    let mut i = start;
    while i < args.len() {
        let arg = args[i].as_str();
        let idx = i;
        i += 1;
        if !end_of_options && arg == "--" {
            end_of_options = true;
            continue;
        }
        if !end_of_options && arg.len() > 1 && arg.starts_with('-') {
            // 1. exact option name, 2. `name=value`, 3. a cluster of short options with an attached value.
            let found: Option<(&Opt, Option<String>)> = if let Some(opt) = opts.iter().find(|o| o.names.contains(&arg)) {
                Some((opt, None))
            } else if let Some((name, value)) = arg.split_once('=').filter(|(n, _)| opts.iter().any(|o| o.names.contains(n))) {
                Some((opts.iter().find(|o| o.names.contains(&name)).unwrap(), Some(value.to_string())))
            } else {
                None
            };
            if let Some((opt, attached)) = found {
                i = apply(cmd, &mut v, &mut seen, opt, attached, args, i)?;
                continue;
            }
            if !arg.starts_with("--") {
                // short-option cluster: `-hV`, `-p1080`, `-Dk=v`
                let chars: Vec<char> = arg.chars().skip(1).collect();
                let mut handled = true;
                let mut pos = 0;
                let mut pending = Vec::new();
                while pos < chars.len() {
                    let short = format!("-{}", chars[pos]);
                    let Some(opt) = opts.iter().find(|o| o.names.contains(&short.as_str())) else {
                        handled = false;
                        break;
                    };
                    pos += 1;
                    if matches!(opt.kind, Kind::Flag | Kind::UsageHelp | Kind::VersionHelp) {
                        pending.push((opt, None));
                        continue;
                    }
                    let rest: String = chars[pos..].iter().collect();
                    let rest = rest.strip_prefix('=').map(str::to_string).unwrap_or(rest);
                    pending.push((opt, if chars[pos..].is_empty() { None } else { Some(rest) }));
                    break;
                }
                if !pending.is_empty() {
                    // an unknown character after known flags (`-hx`): the flags still apply
                    for (opt, attached) in pending {
                        i = apply(cmd, &mut v, &mut seen, opt, attached, args, i)?;
                    }
                    if handled {
                        continue;
                    }
                }
            }
            v.unmatched.push((idx, arg.to_string()));
            continue;
        }
        // positional parameter
        match cmd {
            Cmd::OpenApi | Cmd::Import if v.positional.is_none() => v.positional = Some(arg.to_string()),
            Cmd::Help | Cmd::Lint => v.positionals.push(arg.to_string()),
            _ => v.unmatched.push((idx, arg.to_string())),
        }
    }
    if v.usage_help || v.version_help {
        return Ok(v);
    }
    if let Some(label) = cmd.positional() && v.positional.is_none() && v.positionals.is_empty() {
        return Err(err(format!("Missing required parameter: '<{label}>'")));
    }
    let missing: Vec<String> =
        opts.iter().filter(|o| o.required && !seen.contains(o.field)).map(|o| format!("'{}={}'", o.display(), o.label)).collect();
    if !missing.is_empty() {
        let plural = if missing.len() > 1 { "s" } else { "" };
        return Err(err(format!("Missing required option{plural}: {}", missing.join(", "))));
    }
    if let Some((first_index, first)) = v.unmatched.first() {
        let quoted: Vec<String> = v.unmatched.iter().map(|(_, a)| format!("'{a}'")).collect();
        let plural = if v.unmatched.len() > 1 { "s" } else { "" };
        let message = if first.starts_with('-') && first.len() > 1 {
            format!("Unknown option{plural}: {}", quoted.join(", "))
        } else if v.unmatched.len() > 1 {
            format!("Unmatched arguments from index {first_index}: {}", quoted.join(", "))
        } else {
            format!("Unmatched argument at index {first_index}: {}", quoted.join(", "))
        };
        return Err(err(message));
    }
    Ok(v)
}

/// Applies one option; returns the index of the next argument.
fn apply(cmd: Cmd, v: &mut Values, seen: &mut HashSet<&'static str>, opt: &Opt, attached: Option<String>, args: &[String], mut i: usize) -> Result<usize, ParamError> {
    let err = |message: String| ParamError { message, usage: cmd.usage() };
    let name = opt.display();
    match opt.kind {
        Kind::UsageHelp => {
            v.usage_help = true;
            return Ok(i);
        }
        Kind::VersionHelp => {
            v.version_help = true;
            return Ok(i);
        }
        _ => {}
    }
    if opt.kind != Kind::Map && !seen.insert(opt.field) {
        let label = if opt.label.is_empty() { String::new() } else { format!(" ({})", opt.label) };
        return Err(err(format!("option '{name}'{label} should be specified only once")));
    }
    if opt.kind == Kind::Flag {
        match attached.as_deref() {
            None => {}
            Some(value) if value.eq_ignore_ascii_case("true") => {}
            Some(value) if value.eq_ignore_ascii_case("false") => return Ok(i),
            Some(value) => return Err(err(format!("Invalid value for option '{name}': '{value}' is not a boolean"))),
        }
        v.flags.insert(opt.field);
        return Ok(i);
    }
    let value = match attached {
        Some(value) => value,
        None => match args.get(i) {
            None => return Err(err(format!("Missing required parameter for option '{name}' ({})", opt.label))),
            Some(next) if resembles_option(next, cmd.options()) => return Err(err(format!("Expected parameter for option '{name}' but found '{next}'"))),
            Some(next) => {
                i += 1;
                next.clone()
            }
        },
    };
    match opt.kind {
        Kind::Map => match value.split_once('=') {
            Some((key, val)) => v.maps.push((key.to_string(), val.to_string())),
            None => return Err(err(format!("Value for option option '{name}' ({}) should be in KEY=VALUE format but was {value}", opt.label))),
        },
        Kind::Int => {
            if !java_int(&value) {
                return Err(err(format!("Invalid value for option '{name}': '{value}' is not an int")));
            }
            v.strs.insert(opt.field, value);
        }
        _ => {
            v.strs.insert(opt.field, value);
        }
    }
    Ok(i)
}

/// `Main.preprocessArguments`: a first token that is neither a subcommand nor a top-level help/version flag gets
/// `run` prepended; the single-dash `-help` / `-version` become `--help` / `--version`.
pub fn preprocess(arguments: &[String]) -> Vec<String> {
    let mut args = arguments.to_vec();
    let Some(first) = args.first().cloned() else { return vec!["run".into()] };
    let first = match first.as_str() {
        "-help" => "--help".to_string(),
        "-version" => "--version".to_string(),
        _ => first,
    };
    args[0] = first.clone();
    if SUBCOMMANDS.contains(&first.as_str()) || ["--help", "-h", "--version", "-V"].contains(&first.as_str()) {
        return args;
    }
    args.insert(0, "run".into());
    args
}

fn launcher_name(env: &HashMap<String, String>, system_properties: &[(String, String)]) -> Option<String> {
    system_properties
        .iter()
        .find(|(k, _)| k == "mockserver.launcherName")
        .map(|(_, v)| v.clone())
        .or_else(|| env.get("MOCKSERVER_LAUNCHER").cloned())
        .filter(|l| !l.trim().is_empty())
}

/// `Main.USAGE`.
fn legacy_usage(launcher: Option<&str>) -> String {
    let command = launcher.map_or("java -jar <path to mockserver-netty-jar-with-dependencies.jar>", |l| l);
    let example = launcher.map_or("java -jar ./mockserver-netty-jar-with-dependencies.jar", |l| l);
    LEGACY_USAGE.replace("{version}", crate::MOCKSERVER_VERSION).replace("{cmd}", command).replace("{example}", example)
}

/// `Main.printValidationError`: the messages in a box of `=` as wide as the longest.
fn validation_box(messages: &[String]) -> String {
    let width = messages.iter().map(|m| m.chars().count()).max().unwrap_or(0);
    let bar = "=".repeat(width);
    let mut out = format!("\n   {bar}\n");
    for message in messages {
        out.push_str(&format!("   {message}\n"));
    }
    out.push_str(&format!("   {bar}\n\n"));
    out
}

/// `Main.validateArguments`: every invalid value, in the order serverPort, proxyRemotePort, proxyRemoteHost, logLevel.
fn validate_arguments(server_port: Option<&str>, remote_port: Option<&str>, remote_host: Option<&str>, log_level: Option<&str>) -> Vec<String> {
    let mut errors = Vec::new();
    let digits = |s: &str, list: bool| {
        !s.is_empty() && s.split(if list { "," } else { "\u{0}" }).all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    };
    if let Some(p) = server_port.filter(|p| !p.trim().is_empty()) && !digits(p, true) {
        errors.push(format!("serverPort value \"{p}\" is invalid, please specify a comma separated list of ports i.e. \"1080,1081,1082\""));
    }
    if let Some(p) = remote_port.filter(|p| !p.trim().is_empty()) && !digits(p, false) {
        errors.push(format!("proxyRemotePort value \"{p}\" is invalid, please specify a port i.e. \"1080\""));
    }
    if let Some(h) = remote_host.filter(|h| !h.trim().is_empty()) && !crate::config::is_valid_remote_host(h) {
        errors.push(format!("proxyRemoteHost value \"{h}\" is invalid, please specify a host name i.e. \"localhost\" or \"127.0.0.1\""));
    }
    if let Some(l) = log_level.filter(|l| !l.trim().is_empty()) && !crate::config::VALID_LOG_LEVELS.contains(&l) {
        errors.push(format!(
            "logLevel value \"{l}\" is invalid, please specify one of SL4J levels: \"TRACE\", \"DEBUG\", \"INFO\", \"WARN\", \"ERROR\", \"OFF\" or the Java Logger levels: \"FINEST\", \"FINE\", \"INFO\", \"WARNING\", \"SEVERE\", \"OFF\""
        ));
    }
    errors
}

/// `Main.parseProxyTarget`: `--proxy-to` / `--to` as `[host, port]`. `Err(Some(box))` is a validation error that
/// `Main` prints in a box; `Err(None)` one it throws without printing anything.
fn parse_proxy_target(value: &str) -> Result<(String, String), Option<String>> {
    let mut raw = value.trim();
    let mut scheme_default: Option<&str> = None;
    if let Some(rest) = raw.strip_prefix("https://") {
        scheme_default = Some("443");
        raw = rest;
    } else if let Some(rest) = raw.strip_prefix("http://") {
        scheme_default = Some("80");
        raw = rest;
    }
    if let Some(slash) = raw.find('/') {
        raw = &raw[..slash];
    }
    let (host, mut port) = if raw.starts_with('[') {
        let Some(close) = raw.find(']') else { return Err(None) };
        let remainder = &raw[close + 1..];
        (raw[1..close].to_string(), remainder.strip_prefix(':').map(str::to_string))
    } else if let Some(colon) = raw.rfind(':') {
        (raw[..colon].to_string(), Some(raw[colon + 1..].to_string()))
    } else {
        (raw.to_string(), None)
    };
    if port.as_deref().is_none_or(|p| p.trim().is_empty()) {
        port = match scheme_default {
            Some(default) => Some(default.to_string()),
            None => {
                return Err(Some(validation_box(&[format!(
                    "proxy target \"{value}\" has no port — specify a port explicitly (e.g. --proxy-to {host}:8080) or use a http(s):// URL (e.g. --proxy-to https://{host})"
                )])))
            }
        };
    }
    Ok((host, port.unwrap()))
}

/// The options `RunCommand` runs with, whichever subcommand collected them.
#[derive(Default)]
struct RunOptions {
    port: Option<String>,
    system_properties: Vec<(String, String)>,
    proxy_to: Option<String>,
    openapi: Option<String>,
    init: Option<String>,
    persist: Option<String>,
    log_level: Option<String>,
    dev: bool,
    watch: bool,
    proxy_setup: bool,
    validate_openapi: Option<String>,
    validate_enforce: bool,
    /// `--extensions` (9.2.0): the `extensions` property, startup-only.
    extensions: Option<String>,
    legacy_server_port: Option<String>,
    legacy_proxy_remote_port: Option<String>,
    legacy_proxy_remote_host: Option<String>,
    legacy_log_level: Option<String>,
}

fn not_blank(value: Option<&str>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty()).map(str::to_string)
}

/// `RunCommand.run()` followed by `startServer`'s argument handling. `started` is false when nothing was started
/// (usage errors keep exit code 0).
fn run_command(options: RunOptions, env: &HashMap<String, String>, planned: &mut Planned, after: After) {
    let launcher = launcher_name(env, &options.system_properties);
    let resolved_port = not_blank(options.port.as_deref()).or_else(|| options.legacy_server_port.clone());
    let resolved_log_level = not_blank(options.log_level.as_deref()).or_else(|| options.legacy_log_level.clone());
    let mut remote_port = options.legacy_proxy_remote_port.clone();
    let mut remote_host = options.legacy_proxy_remote_host.clone();
    if let Some(target) = not_blank(options.proxy_to.as_deref()) {
        match parse_proxy_target(&target) {
            Ok((host, port)) => {
                remote_host = Some(host);
                remote_port = Some(port);
            }
            Err(printed) => {
                planned.out.push_str(&printed.unwrap_or_default());
                planned.out.push_str(RUN_BARE_USAGE);
                return;
            }
        }
    }
    // The settings `RunCommand` writes with `ConfigurationProperties.x(…)`, which are system properties.
    let mut args: Vec<String> = Vec::new();
    for (key, value) in &options.system_properties {
        if !key.trim().is_empty() {
            args.push(format!("-D{key}={value}"));
        }
    }
    let mut set = |name: &str, value: &str| args.push(format!("-Dmockserver.{name}={value}"));
    if options.dev {
        set("devMode", "true");
    }
    if options.watch {
        set("watchInitializationJson", "true");
    }
    if options.proxy_setup {
        set("proxySetup", "true");
        set("proxySetupLogging", "true");
    }
    if let Some(spec) = not_blank(options.openapi.as_deref()) {
        set("initializationOpenAPIPath", &spec);
    }
    if let Some(path) = not_blank(options.init.as_deref()) {
        set("initializationJsonPath", &path);
    }
    if let Some(path) = not_blank(options.persist.as_deref()) {
        set("persistExpectations", "true");
        set("persistedExpectationsPath", &path);
    }
    if let Some(spec) = not_blank(options.validate_openapi.as_deref()) {
        set("validateProxyOpenAPISpec", &spec);
    }
    if options.validate_enforce {
        set("validateProxyEnforce", "true");
    }
    if let Some(classes) = not_blank(options.extensions.as_deref()) {
        set("extensions", &classes);
    }
    let errors = validate_arguments(resolved_port.as_deref(), remote_port.as_deref(), remote_host.as_deref(), resolved_log_level.as_deref());
    if !errors.is_empty() {
        planned.out.push_str(&validation_box(&errors));
        planned.out.push_str(&legacy_usage(launcher.as_deref()));
        return;
    }
    let mut cli_values: Vec<(&'static str, String)> = Vec::new();
    let dump_enabled = {
        let mut probe = args.clone();
        probe.extend(["-serverPort".to_string(), "0".to_string()]);
        Config::from_args(&probe, env.clone()).map_or(true, |c| !matches!(c.log_level().as_str(), "OFF" | "ERROR" | "WARN"))
    };
    for (flag, name, value) in [
        ("-serverPort", "serverPort", &resolved_port),
        ("-proxyRemotePort", "proxyRemotePort", &remote_port),
        ("-proxyRemoteHost", "proxyRemoteHost", &remote_host),
        ("-logLevel", "logLevel", &resolved_log_level),
    ] {
        if let Some(value) = not_blank(value.as_deref()) {
            args.push(flag.to_string());
            args.push(value.clone());
            cli_values.push((name, value));
        }
    }
    match Config::from_args(&args, env.clone()) {
        Ok(config) => {
            let dump = dump_enabled.then(|| config.startup_dump(&cli_values));
            planned.action = Action::Start(Box::new(Start { config, after, dump }));
        }
        Err(e) if e.no_port => {
            planned.out.push_str(RUN_BARE_USAGE);
            let cmd = launcher.clone().unwrap_or_else(|| "java -jar <path to mockserver-netty-jar-with-dependencies.jar>".into());
            planned.err.push_str(&format!(
                "\nERROR:  no port specified — set a port with -p/--port (e.g. {cmd} -p 1080), the MOCKSERVER_SERVER_PORT environment variable, or the mockserver.serverPort property\n\n"
            ));
        }
        Err(e) => {
            planned.out.push_str(&legacy_usage(launcher.as_deref()));
            planned.err.push_str(&format!("{e}\n"));
        }
    }
}

fn run_options_from(cmd: Cmd, v: &Values) -> RunOptions {
    let s = |field: &str| v.s(field).map(str::to_string);
    let mut options = RunOptions {
        port: s("port"),
        system_properties: v.maps.clone(),
        log_level: s("logLevel"),
        dev: v.flag("dev"),
        ..RunOptions::default()
    };
    match cmd {
        Cmd::Run => {
            options.proxy_to = s("proxyTo");
            options.openapi = s("openapi");
            options.init = s("init");
            options.persist = s("persist");
            options.watch = v.flag("watch");
            options.proxy_setup = v.flag("proxySetup");
            options.validate_openapi = s("validateOpenapi");
            options.validate_enforce = v.flag("validateEnforce");
            options.extensions = s("extensions");
            options.legacy_server_port = s("legacyServerPort");
            options.legacy_proxy_remote_port = s("legacyProxyRemotePort");
            options.legacy_proxy_remote_host = s("legacyProxyRemoteHost");
            options.legacy_log_level = s("legacyLogLevel");
        }
        Cmd::Ui | Cmd::Demo => options.port = Some(not_blank(options.port.as_deref()).unwrap_or_else(|| "1080".into())),
        Cmd::Proxy => {
            options.proxy_to = s("to");
            options.validate_openapi = s("validateOpenapi");
            options.validate_enforce = v.flag("validateEnforce");
        }
        Cmd::OpenApi => options.openapi = v.positional.clone(),
        Cmd::Import | Cmd::Lint | Cmd::Version | Cmd::Help => {}
    }
    options
}

/// Parses `arguments` (without the program name) as `Main.main` does.
pub fn plan(arguments: &[String], env: &HashMap<String, String>) -> Planned {
    let mut planned = Planned { out: String::new(), err: String::new(), action: Action::Exit(0) };
    let args = preprocess(arguments);
    // The top-level command: `-h` / `-V` (also clustered), then the subcommand.
    let mut top_help = false;
    let mut top_version = false;
    let mut at = 0;
    while at < args.len() {
        let arg = args[at].as_str();
        let top = |name: &str| TOP_OPTS.iter().any(|o| o.names.contains(&name));
        if top(arg) {
            if arg == "-h" || arg == "--help" {
                top_help = true;
            } else {
                top_version = true;
            }
            at += 1;
        } else {
            break;
        }
    }
    let sub = args.get(at).and_then(|name| Cmd::from_name(name));
    let mut values = None;
    if let Some(cmd) = sub {
        match parse_command(cmd, &args, at + 1) {
            Ok(v) => values = Some((cmd, v)),
            Err(e) => return fail_with(planned, e),
        }
    } else if at < args.len() && !(top_help || top_version) {
        let first = &args[at];
        let unknown = first.starts_with('-') && first.len() > 1;
        let rest: Vec<String> = args[at..].iter().map(|a| format!("'{a}'")).collect();
        let plural = if rest.len() > 1 { "s" } else { "" };
        let message = if unknown {
            format!("Unknown option{plural}: {}", rest.join(", "))
        } else if rest.len() > 1 {
            format!("Unmatched arguments from index {at}: {}", rest.join(", "))
        } else {
            format!("Unmatched argument at index {at}: {}", rest.join(", "))
        };
        return fail_with(planned, ParamError { message, usage: TOP_USAGE });
    }
    if top_help {
        planned.out.push_str(TOP_USAGE);
        return planned;
    }
    if top_version {
        planned.out.push_str(&format!("MockServer {}\n", crate::MOCKSERVER_VERSION));
        return planned;
    }
    let Some((cmd, v)) = values else {
        return planned;
    };
    if v.usage_help {
        planned.out.push_str(cmd.usage());
        return planned;
    }
    if v.version_help {
        // only the top-level command has a version provider; a subcommand's `-V` prints nothing
        return planned;
    }
    match cmd {
        Cmd::Version => planned.out.push_str(&format!("MockServer {}\n", crate::MOCKSERVER_VERSION)),
        Cmd::Help => match v.positionals.first() {
            None => planned.out.push_str(TOP_USAGE),
            Some(name) => match Cmd::from_name(name) {
                Some(target) => planned.out.push_str(target.usage()),
                None => return fail_with(planned, ParamError { message: format!("Unknown subcommand '{name}'."), usage: TOP_USAGE }),
            },
        },
        Cmd::Import => {
            planned.action = Action::Import(ImportPlan {
                file: v.positional.clone().unwrap_or_default(),
                host: v.s("host").unwrap_or("localhost").to_string(),
                port: v.s("port").and_then(|p| p.parse().ok()).unwrap_or(0),
            });
        }
        Cmd::Lint => planned.action = Action::Lint(LintPlan { files: v.positionals.clone(), json: v.flag("json"), strict: v.flag("strict") }),
        Cmd::Run | Cmd::Ui | Cmd::Proxy | Cmd::OpenApi | Cmd::Demo => {
            let after = match cmd {
                Cmd::Ui => After::Ui,
                Cmd::Demo => After::Demo,
                _ => After::Nothing,
            };
            run_command(run_options_from(cmd, &v), env, &mut planned, after);
        }
    }
    planned
}

fn fail_with(mut planned: Planned, e: ParamError) -> Planned {
    planned.err.push_str(&format!("ERROR: {}\n", e.message));
    planned.out.push_str(e.usage);
    planned.action = Action::Exit(2);
    planned
}

/// An HTTP(S) forward proxy together with a SOCKS one: `Main` shows the usage and exits 0 (`client::PROXY_CONFLICT`).
pub fn proxy_conflict(config: &Config) -> bool {
    crate::client::proxy_conflict(config)
}

/// Control-plane mTLS without a CA chain on the bundled CA, which `MockServer` refuses to start with
/// (`auth::unusable_control_plane_mtls`).
pub fn unusable_control_plane_mtls(config: &Config) -> bool {
    crate::auth::unusable_control_plane_mtls(config).is_some()
}

/// Control-plane Basic authentication whose users cannot be used (none, a malformed entry, a plain text password, a
/// work factor out of bounds, an unreadable users file), which `MockServer` refuses to start with
/// (`auth_basic::startup_check`).
pub fn unusable_control_plane_basic(config: &Config) -> bool {
    crate::auth_basic::startup_check(config).is_err()
}

/// Data-plane mTLS that would trust the bundled CA without `tlsMutualAuthenticationAllowBundledCa`, which `MockServer`
/// refuses to start with (`tls::unusable_data_plane_mtls`).
pub fn unusable_data_plane_mtls(config: &Config) -> bool {
    crate::tls::unusable_data_plane_mtls(config).is_some()
}

/// `Main.USAGE` after a startup `IllegalArgumentException` (`RunCommand` takes it for a usage error), for `main`.
pub fn startup_failure_usage(env: &HashMap<String, String>) -> String {
    legacy_usage(launcher_name(env, &[]).as_deref())
}

/// `disableSystemOut`: `Main` then prints a startup failure on stderr too.
pub fn system_out_disabled(config: &Config) -> bool {
    crate::log::system_out_disabled(config)
}

/// The console (a `tracing` subscriber and its writer thread), for `main`: see `log::install_console`.
pub fn install_console() {
    crate::log::install_console();
}

/// Waits until every queued console line is on stdout, for `main` (see `log::flush_console`).
pub fn flush_console() {
    crate::log::flush_console();
}

/// What loading the configuration logged with `alwaysLog`: printed before `Main`'s own startup dump.
pub fn startup_notices(config: &Config) {
    crate::log::startup_notices(config);
}

/// One WARN line naming the JVM-only settings that have no effect here, written after
/// upstream's unknown-key warnings and only when there are any. An `initializationClass` counts only when no callback
/// provider supplies it (the plugins are read just for that check, and only when the key is set).
pub fn jvm_only_notice(config: &Config) {
    use crate::class_callback::CallbackProvider;
    let provided = |class: &str| {
        config.callback_classes.resolve(class).is_some() || crate::class_callback::Plugins::load(&config.property("callbackPlugins").unwrap_or_default(), |_| {}).resolve(class).is_some()
    };
    if let Some(line) = crate::jvm_policy::notice(&crate::jvm_policy::findings(&config.jvm_policy_sources(), &provided)) {
        main_line(config, &config.log_level(), "WARN", &line);
    }
}

/// The start-up failure of a named extension no callback provider exports, checked where
/// upstream's `LifeCycle` starts the extensions: before the mTLS and Basic authentication refusals. What loading the
/// plugins reports (a jar in `/extensions`) goes to stderr.
pub fn extension_refusal(config: &Config) -> Option<String> {
    crate::extensions::load(config, |line| eprintln!("{line}")).err()
}

/// The tokio worker-thread count `nioEventLoopThreadCount` maps to, `None` for tokio's default.
pub fn worker_threads(config: &Config) -> Option<usize> {
    crate::jvm_policy::worker_threads(config)
}

/// A `SERVER_CONFIGURATION` line of `Main` at `level` (`INFO`, `WARN` or `ERROR`), subject to `global` and
/// `logLevelOverrides` like every console line. `Main` reads the global level before the command line
/// applies its own, so the startup dump passes `"INFO"` (its own gate, `dump_enabled`, has decided already).
pub fn main_line(config: &Config, global: &str, level: &str, message: &str) {
    use crate::recorded::{Kind, Level};
    let level = match level {
        "WARN" => Level::Warn,
        "ERROR" => Level::Error,
        _ => Level::Info,
    };
    crate::log::startup_line(config, global, level, Kind::ServerConfiguration, message);
}

/// `Main.logStartupFailure` for a DNS or HTTP/3 listener that could not start: a port that could not be
/// bound is logged with its message alone (`DNS start-up failed:{}`, `HTTP/3 start-up failed:{}`, the message as the
/// argument), any other failure as `exception while starting:{}` with the exception. With the console handler gone,
/// the message, or the exception's `toString`, goes to stderr instead.
pub fn udp_start_failure(config: &Config, failure: &crate::UdpStartFailure) {
    let message = failure.message();
    match failure.explained_format() {
        Some(format) => {
            main_line(config, &config.log_level(), "ERROR", &format!("{}\n\n  {message}\n", format.trim_end_matches("{}")));
            if system_out_disabled(config) {
                eprintln!("{message}");
            }
        }
        None => {
            main_line(config, &config.log_level(), "ERROR", &format!("exception while starting:{{}} \n{failure}"));
            if system_out_disabled(config) {
                eprintln!("java.lang.RuntimeException: exception while starting: {message}");
            }
        }
    }
}

/// The `logger level is X, change using:` block `Main.startServer` logs once the server is up (type
/// `SERVER_CONFIGURATION`, at the configured level itself, so it is on unless the level is `OFF` or an override hides it).
pub fn logger_level_line(config: &Config) {
    use crate::recorded::{Kind, Level};
    let name = config.log_level();
    let level = match name.as_str() {
        "OFF" => return,
        "TRACE" => Level::Trace,
        "DEBUG" => Level::Debug,
        "WARN" => Level::Warn,
        "ERROR" => Level::Error,
        _ => Level::Info,
    };
    crate::log::startup_line(
        config,
        &name,
        level,
        Kind::ServerConfiguration,
        &format!(
            "logger level is {name}, change using:\n - 'ConfigurationProperties.logLevel(String level)' in Java code,\n - '-logLevel' command line argument,\n - 'mockserver.logLevel' JVM system property or,\n - 'mockserver.logLevel' property value in 'mockserver.properties'"
        ),
    );
}

/// A blocking `PUT` of a JSON body to a MockServer, as `MockServerClient` sends it; the status and the body.
pub fn put_json(host: &str, port: i32, path: &str, body: &str) -> std::io::Result<(u16, String)> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect((host, u16::try_from(port).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("port out of range: {port}")))?))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(20)))?;
    let request = format!(
        "PUT {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let text = String::from_utf8_lossy(&response).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") { dechunk(body) } else { body.to_string() };
    Ok((status, body))
}

fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some((size_line, tail)) = rest.split_once("\r\n") {
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
        if size == 0 || tail.len() < size {
            break;
        }
        out.push_str(&tail[..size]);
        rest = tail[size..].strip_prefix("\r\n").unwrap_or(&tail[size..]);
    }
    out
}

/// The file's text as `FileReader.readFileFromClassPathOrPath` decodes it: UTF-8, a malformed sequence read as U+FFFD.
fn import_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Why `JsonArraySerializer.splitJSONArrayToJSONNodes` rejects the file's text: `readTree(String)` fails, and the
/// `IllegalArgumentException` it wraps the exception in carries the exception's `toString()` as its message.
pub fn import_syntax_error(text: &str) -> Option<String> {
    crate::jnode::read_tree(text).err().map(|e| format!("shaded_package.{}: {}", e.class, e.message))
}

/// `ImportCommand.run`: what it prints on stdout and stderr and the exit code. Its failure line (`exception while
/// importing expectations ..`) is a console event, written by the console `main` installs.
pub fn run_import(plan: &ImportPlan) -> (String, String, u8) {
    let ImportPlan { file, host, port } = plan;
    let outcome: Result<usize, String> = (|| {
        let bytes = std::fs::read(file).map_err(|_| format!("Exception while loading \"{file}\""))?;
        let text = import_text(&bytes);
        if text.trim().is_empty() {
            return Ok(0);
        }
        if let Some(reason) = import_syntax_error(&text) {
            return Err(reason);
        }
        // `splitJSONArrayToJSONNodes`: a file of comments only reads as a `MissingNode`, one entry printed `null`
        let parsed: serde_json::Value = match crate::jnode::read_tree(&text) {
            Ok(node) if node.is_missing() => serde_json::Value::Null,
            _ => crate::json::parse_lenient(text.as_bytes()).map_err(|e| format!("{e}"))?,
        };
        let given = match parsed {
            serde_json::Value::Array(items) => items,
            other => vec![other],
        };
        // `MockServerClient.importExpectations`: `deserializeArray(json, false)` validates every entry (and expands an
        // OpenAPI one) before anything is sent, so its failure is the reason even when no server listens
        let realistic = Config::for_print_config(&[], std::env::vars().collect()).bool_property("generateRealisticExampleValues", false);
        let list = crate::control::deserialize_expectations(&given, realistic, |_, _| {}, |_, _| {})?;
        let (status, body) = put_json(host, *port, "/mockserver/expectation", &serde_json::Value::Array(list).to_string()).map_err(|e| match e.kind() {
            std::io::ErrorKind::ConnectionRefused => format!("Unable to connect to socket {host}/{}:{port}", if host == "localhost" { "127.0.0.1" } else { host }),
            _ => e.to_string(),
        })?;
        if status != 201 {
            return Err(body.trim().to_string());
        }
        Ok(serde_json::from_str::<Vec<serde_json::Value>>(&body).map_or(0, |a| a.len()))
    })();
    match outcome {
        Ok(count) => (format!("Imported {count} expectation(s) from {file} into {host}:{port}\n"), String::new(), 0),
        Err(reason) => {
            crate::log::command_error(&format!("exception while importing expectations from {file} into {host}:{port}:{{}}\n{reason}"));
            (String::new(), format!("\nERROR:  could not import expectations from {file} into {host}:{port} — {reason}\n\n"), 1)
        }
    }
}

/// `LintCommand.run`: what it prints on stdout and stderr and the exit code. Every file is read first; one that cannot
/// be read as an expectation or an array of them is named on stderr, and then nothing is linted (exit 1). Otherwise all
/// entries are linted together, in file order, as `--init` loads them (`lint::lint_initialization_file_entries`), each
/// issue's `index` read back as the entry's index in its own file, with its `file` (and `relatedFile`). Exit 1 on an
/// error, or on a warning with `--strict`.
pub fn run_lint(plan: &LintPlan) -> (String, String, u8) {
    use serde_json::Value;
    let mut err = String::new();
    let mut entries: Vec<Value> = Vec::new();
    let mut entry_files: Vec<&str> = Vec::new();
    let mut entry_indexes: Vec<usize> = Vec::new();
    let mut entry_file_ordinals: Vec<usize> = Vec::new();
    for (ordinal, file) in plan.files.iter().enumerate() {
        let read = (|| -> Result<Vec<Value>, String> {
            let bytes = std::fs::read(file).map_err(|_| format!("Exception while loading \"{file}\""))?;
            let text = import_text(&bytes);
            let node = crate::jnode::read_tree(&text).map_err(|e| e.message)?;
            if !(node.is_array() || node.is_object()) {
                return Err("expected an expectation or an array of expectations".to_string());
            }
            match crate::json::parse_lenient(text.as_bytes()).map_err(|e| e.to_string())? {
                Value::Array(items) => Ok(items),
                item => Ok(vec![item]),
            }
        })();
        match read {
            Ok(file_entries) => {
                for (index, entry) in file_entries.into_iter().enumerate() {
                    entries.push(entry);
                    entry_files.push(file);
                    entry_indexes.push(index);
                    entry_file_ordinals.push(ordinal);
                }
            }
            Err(reason) => err.push_str(&format!("ERROR:  could not read expectations from {file} — {reason}\n")),
        }
    }
    if !err.is_empty() {
        return (String::new(), err, 1);
    }
    // an invalid entry is reported in the lint output, so the serializer's own log would only repeat it
    let mut report = crate::lint::lint_initialization_file_entries(&entries, &entry_file_ordinals, |_, _| {});
    let int = |v: &Value, key: &str| v.get(key).and_then(Value::as_i64).unwrap_or(0);
    let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    for issue in report.get_mut("issues").and_then(Value::as_array_mut).into_iter().flatten() {
        let Some(issue) = issue.as_object_mut() else { continue };
        let index = issue.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
        issue.insert("file".into(), entry_files[index].into());
        issue.insert("index".into(), entry_indexes[index].into());
        if let Some(related) = issue.get("relatedIndex").and_then(Value::as_u64) {
            let related = related as usize;
            issue.insert("relatedFile".into(), entry_files[related].into());
            issue.insert("relatedIndex".into(), entry_indexes[related].into());
        }
    }
    let mut out = String::new();
    if plan.json {
        out.push_str(&crate::json::pretty(&report));
        out.push('\n');
    } else {
        for issue in report.get("issues").and_then(Value::as_array).into_iter().flatten() {
            out.push_str(&format!("{} [{}] {}\n  {} {}: {}", text(issue, "file"), int(issue, "index"), text(issue, "summary"), text(issue, "severity"), text(issue, "rule"), text(issue, "message")));
            if issue.get("relatedFile").is_some() {
                out.push_str(&format!("\n  see {} [{}] {}", text(issue, "relatedFile"), int(issue, "relatedIndex"), text(issue, "relatedSummary")));
            }
            out.push('\n');
        }
        out.push_str(&format!(
            "checked {} expectation(s) in {} file(s): {} error(s), {} warning(s), {} info",
            int(&report, "expectationsChecked"),
            plan.files.len(),
            int(&report, "errorCount"),
            int(&report, "warningCount"),
            int(&report, "infoCount")
        ));
        let skipped = int(&report, "openApiExpectationsSkipped");
        if skipped > 0 {
            out.push_str(&format!(", {skipped} OpenAPI expectation(s) not checked"));
        }
        if report.get("shadowCheckTruncated").and_then(Value::as_bool) == Some(true) {
            out.push_str("; the shadowing check stopped at its budget");
        }
        if report.get("issuesTruncated").and_then(Value::as_bool) == Some(true) {
            out.push_str(&format!("; only the first {} issues are listed", int(&report, "issueCount")));
        }
        out.push('\n');
    }
    let failed = int(&report, "errorCount") > 0 || plan.strict && int(&report, "warningCount") > 0;
    (out, String::new(), u8::from(failed))
}

/// The two expectations `mockserver demo` registers (`Main.seedDemoExpectations`), one request each.
pub const DEMO_EXPECTATIONS: [&str; 2] = [
    r#"[{"httpRequest":{"method":"GET","path":"/hello"},"httpResponse":{"statusCode":200,"headers":{"Content-Type":["application/json"]},"body":"{\"message\":\"Hello from MockServer!\"}"}}]"#,
    r#"[{"httpRequest":{"method":"GET","path":"/users/{id}","pathParameters":{"id":["[0-9]+"]}},"httpResponse":{"statusCode":200,"headers":{"Content-Type":["application/json"]},"body":"{\"id\":1,\"name\":\"Example User\"}"}}]"#,
];

/// `Main.printDemoInstructions`.
pub fn demo_instructions(port: u16) -> String {
    let base = format!("http://localhost:{port}");
    format!(
        "\nMockServer demo is running with example expectations.\n\n  Getting started: {base}/hello\n  Dashboard UI:    {base}/mockserver/dashboard\n\n  Try it:\n    curl {base}/hello\n    curl {base}/users/1\n\n"
    )
}

/// `Main.openDashboard`: the URL line, then a best-effort browser launch. `MOCK_SERVER_NO_BROWSER` (set by the
/// process scenarios) stands in for a headless host.
pub fn open_dashboard(port: u16, env: &HashMap<String, String>) -> String {
    let url = format!("http://localhost:{port}/mockserver/dashboard");
    let line = format!("\nDashboard UI: {url}\n\n");
    let headless = env.get("MOCK_SERVER_NO_BROWSER").is_some_and(|v| !v.is_empty())
        || (cfg!(all(unix, not(target_os = "macos"))) && env.get("DISPLAY").is_none_or(|d| d.is_empty()) && env.get("WAYLAND_DISPLAY").is_none_or(|d| d.is_empty()));
    if !headless {
        let launcher = if cfg!(target_os = "macos") {
            "open"
        } else if cfg!(windows) {
            "explorer"
        } else {
            "xdg-open"
        };
        if std::process::Command::new(launcher).arg(&url).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().is_err() {
            return format!("{line}Could not launch a browser automatically — open the dashboard manually: {url}\n");
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Planned {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        plan(&args, &HashMap::new())
    }

    fn code(p: &Planned) -> u8 {
        match p.action {
            Action::Exit(c) => c,
            _ => 99,
        }
    }

    #[test]
    fn preprocess_prepends_run() {
        let p = |a: &[&str]| preprocess(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(p(&[]), ["run"]);
        assert_eq!(p(&["-p", "1080"]), ["run", "-p", "1080"]);
        assert_eq!(p(&["proxy", "--to", "x:1"]), ["proxy", "--to", "x:1"]);
        assert_eq!(p(&["run", "-p", "1080"]), ["run", "-p", "1080"]);
        assert_eq!(p(&["version"]), ["version"]);
        assert_eq!(p(&["ui", "-p", "1080"]), ["ui", "-p", "1080"]);
        assert_eq!(p(&["openapi", "./petstore.yaml", "-p", "1080"]), ["openapi", "./petstore.yaml", "-p", "1080"]);
        assert_eq!(p(&["import", "./expectations.json", "-p", "1080"]), ["import", "./expectations.json", "-p", "1080"]);
        assert_eq!(p(&["demo", "-p", "1080"]), ["demo", "-p", "1080"]);
        assert_eq!(p(&["-help"]), ["--help"]);
        assert_eq!(p(&["-version"]), ["--version"]);
        assert_eq!(p(&["-V"]), ["-V"]);
        assert_eq!(p(&["-serverPort", "1"]), ["run", "-serverPort", "1"]);
    }

    #[test]
    fn help_and_version() {
        assert_eq!(run(&["--help"]).out, TOP_USAGE);
        assert_eq!(run(&["help", "run"]).out, RUN_USAGE);
        assert_eq!(run(&["run", "-hV"]).out, RUN_USAGE);
        assert_eq!(run(&["-V"]).out, "MockServer 9.2.0\n");
        assert_eq!(run(&["version"]).out, "MockServer 9.2.0\n");
        assert_eq!(run(&["ui", "--version"]).out, "");
        let bogus = run(&["help", "bogus"]);
        assert_eq!((code(&bogus), bogus.err.as_str(), bogus.out.as_str()), (2, "ERROR: Unknown subcommand 'bogus'.\n", TOP_USAGE));
    }

    #[test]
    fn parameter_errors_are_picocli_s() {
        let e = |args: &[&str]| {
            let p = run(args);
            assert_eq!(code(&p), 2, "{args:?}");
            p.err
        };
        assert_eq!(e(&["--bogus"]), "ERROR: Unknown option: '--bogus'\n");
        assert_eq!(e(&["-p", "1", "--a", "--b"]), "ERROR: Unknown options: '--a', '--b'\n");
        assert_eq!(e(&["-p", "1", "x", "--bogus"]), "ERROR: Unmatched arguments from index 3: 'x', '--bogus'\n");
        assert_eq!(e(&["-p", "1", "1"]), "ERROR: Unmatched argument at index 3: '1'\n");
        assert_eq!(e(&["proxy"]), "ERROR: Missing required option: '--to=<to>'\n");
        assert_eq!(e(&["import"]), "ERROR: Missing required parameter: '<file>'\n");
        assert_eq!(e(&["import", "f"]), "ERROR: Missing required option: '--port=<port>'\n");
        assert_eq!(e(&["-p"]), "ERROR: Missing required parameter for option '--port' (<port>)\n");
        assert_eq!(e(&["-p", "--dev"]), "ERROR: Expected parameter for option '--port' but found '--dev'\n");
        assert_eq!(e(&["import", "-p", "abc", "f"]), "ERROR: Invalid value for option '--port': 'abc' is not an int\n");
        assert_eq!(e(&["-p", "1", "-p", "2"]), "ERROR: option '--port' (<port>) should be specified only once\n");
        assert_eq!(e(&["-D", "foo"]), "ERROR: Value for option option '-D' (<key=value>) should be in KEY=VALUE format but was foo\n");
        assert_eq!(e(&["version", "--help"]), "ERROR: Unknown option: '--help'\n");
        // help wins over a deferred unmatched argument
        assert_eq!(run(&["-p", "1080", "--bogus", "--help"]).out, RUN_USAGE);
    }

    #[test]
    fn attached_values_and_clusters() {
        let p = run(&["-p=0", "--dev=true"]);
        assert!(matches!(p.action, Action::Start(_)), "{:?}", p.err);
        let p = run(&["-p0", "-Dmockserver.logLevel=WARN"]);
        assert!(matches!(p.action, Action::Start(_)), "{:?}", p.err);
        assert_eq!(code(&run(&["import", "-p", "-5", "f"])), 99);
    }

    #[test]
    fn validation_collects_every_error_in_a_box() {
        let p = run(&["-p", "abc", "-l", "FOO"]);
        assert_eq!(code(&p), 0);
        let (head, _) = p.out.split_once("   version: ").unwrap();
        assert!(head.contains("serverPort value \"abc\" is invalid"), "{head}");
        assert!(head.contains("logLevel value \"FOO\" is invalid"), "{head}");
        assert_eq!(head.lines().filter(|l| l.starts_with("   ====")).count(), 2);
        assert!(p.out.ends_with(&legacy_usage(None)));
    }

    #[test]
    fn proxy_target_parsing() {
        assert_eq!(parse_proxy_target("https://example.com").unwrap(), ("example.com".into(), "443".into()));
        assert_eq!(parse_proxy_target("http://h/path").unwrap(), ("h".into(), "80".into()));
        assert_eq!(parse_proxy_target("https://h:8443").unwrap(), ("h".into(), "8443".into()));
        assert_eq!(parse_proxy_target("h:8080").unwrap(), ("h".into(), "8080".into()));
        assert_eq!(parse_proxy_target("[::1]:99").unwrap(), ("::1".into(), "99".into()));
        assert_eq!(parse_proxy_target("https://[::1]").unwrap(), ("::1".into(), "443".into()));
        assert!(matches!(parse_proxy_target("foo"), Err(Some(_))));
        assert!(matches!(parse_proxy_target("[::1"), Err(None)));
    }

    /// `MainCliTest.shouldUseLauncherNameInNoPortError`: `MOCKSERVER_LAUNCHER` replaces `java -jar <jar>` in the text.
    #[test]
    fn launcher_name_replaces_the_java_command() {
        let env: HashMap<String, String> = [("MOCKSERVER_LAUNCHER".to_string(), "mockserver".to_string())].into();
        let p = plan(&[], &env);
        assert!(p.err.contains("(e.g. mockserver -p 1080)"), "{}", p.err);
        let p = plan(&["-p".to_string(), "abc".to_string()], &env);
        assert!(p.out.contains("   mockserver -serverPort <port> [-proxyRemotePort <port>]"), "{}", p.out);
        assert!(p.out.contains("   i.e. mockserver -serverPort 1080 -proxyRemotePort 80"), "{}", p.out);
    }

    /// `MainCliTest.shouldApplyDevModeDefaults` / `shouldNotApplyDevModeWithoutFlag`.
    #[test]
    fn dev_flag_sets_the_dev_mode_property_only_when_given() {
        let start = |args: &[&str]| match run(args).action {
            Action::Start(s) => s,
            other => panic!("{other:?}"),
        };
        assert_eq!(start(&["-p", "0", "--dev"]).config.property("devMode").as_deref(), Some("true"));
        assert_eq!(start(&["-p", "0"]).config.property("devMode"), None);
        assert_eq!(start(&["ui", "--dev"]).config.ports, vec![1080]);
    }

    /// `LintCommand`: `<file>...` (arity `1..*`) in the order given, `--json` and `--strict` anywhere among them.
    #[test]
    fn lint_takes_every_file_and_its_flags() {
        let lint = |args: &[&str]| match run(args).action {
            Action::Lint(plan) => plan,
            other => panic!("{other:?}"),
        };
        let plan = lint(&["lint", "a.json", "--strict", "b.json"]);
        assert_eq!((plan.files, plan.json, plan.strict), (vec!["a.json".to_string(), "b.json".to_string()], false, true));
        let plan = lint(&["lint", "--json", "a.json"]);
        assert_eq!((plan.files, plan.json, plan.strict), (vec!["a.json".to_string()], true, false));
        assert_eq!(preprocess(&["lint".to_string()]), ["lint"]);
    }

    #[test]
    fn no_port_prints_the_run_usage_and_the_error() {
        let p = run(&[]);
        assert_eq!((code(&p), p.out.as_str()), (0, RUN_BARE_USAGE));
        assert!(p.err.starts_with("\nERROR:  no port specified — set a port with -p/--port (e.g. java -jar <path to mockserver-netty-jar-with-dependencies.jar> -p 1080)"));
    }
}

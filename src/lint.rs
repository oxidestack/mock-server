//! `ExpectationLinter`: advisory checks for expectations that can never match, or will not match the way they read.
//! Lint never rejects or changes an expectation. The per-expectation checks run on every `PUT /mockserver/expectation`
//! (the `x-mockserver-lint-warnings` header and a WARN entry); the pairwise shadowing check runs on demand
//! (`PUT /mockserver/lint`) and once per initialisation file load, within a comparison budget.
//!
//! Expectations are read from their canonical form (what the oracle echoes), with the input JSON deciding whether a
//! request definition was given at all.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde_json::{Map, Value};

use crate::model::{self, Entries, NString};

pub const LINT_WARNINGS_HEADER: &str = "x-mockserver-lint-warnings";
const MAX_PAIR_COMPARISONS: u64 = 100_000;
const MAX_ISSUES: usize = 1_000;
const MAX_LOGGED_ISSUES: usize = 20;
const MAX_PATTERN_LENGTH: usize = 8_192;
const MAX_MESSAGE_LENGTH: usize = 4_096;
const NOTE: &str = "advisory only: lint never rejects or changes an expectation";
const FORCE_RESPONSE_INDEX_HEADER: &str = "x-mockserver-response-index";

const KNOWN_METHODS: &[&str] = &[
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "QUERY", "PRI", "PROPFIND", "PROPPATCH", "MKCOL",
    "COPY", "MOVE", "LOCK", "UNLOCK", "LINK", "UNLINK", "PURGE", "SEARCH", "REPORT", "BIND", "UNBIND", "REBIND", "ACL", "LABEL", "MERGE",
    "UPDATE", "CHECKIN", "CHECKOUT", "UNCHECKOUT", "MKACTIVITY", "MKWORKSPACE", "MKCALENDAR", "MKREDIRECTREF", "UPDATEREDIRECTREF",
    "ORDERPATCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE", "M-SEARCH", "BATCH", "FETCH",
];

/// The names `knownHeaderNames()` adds first, then Netty 4.2.19's `HttpHeaderNames` fields in declaration order.
const EXTRA_HEADER_NAMES: &[&str] = &[
    "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-port", "x-forwarded-proto", "x-request-id", "x-correlation-id",
    "x-api-key", "traceparent", "tracestate",
];
const NETTY_HEADER_NAMES: &[&str] = &[
    "accept", "accept-charset", "accept-encoding", "accept-language", "accept-ranges", "accept-patch", "accept-query",
    "access-control-allow-credentials", "access-control-allow-headers", "access-control-allow-methods", "access-control-allow-origin",
    "access-control-allow-private-network", "access-control-expose-headers", "access-control-max-age", "access-control-request-headers",
    "access-control-request-method", "access-control-request-private-network", "age", "allow", "authorization", "cache-control",
    "connection", "content-base", "content-encoding", "content-language", "content-length", "content-location",
    "content-transfer-encoding", "content-disposition", "content-md5", "content-range", "content-security-policy", "content-type",
    "cookie", "date", "dnt", "etag", "expect", "expires", "from", "host", "if-match", "if-modified-since", "if-none-match", "if-range",
    "if-unmodified-since", "keep-alive", "last-modified", "location", "max-forwards", "origin", "pragma", "proxy-authenticate",
    "proxy-authorization", "proxy-connection", "range", "referer", "retry-after", "sec-websocket-key1", "sec-websocket-key2",
    "sec-websocket-location", "sec-websocket-origin", "sec-websocket-protocol", "sec-websocket-version", "sec-websocket-key",
    "sec-websocket-accept", "sec-websocket-extensions", "server", "set-cookie", "set-cookie2", "te", "trailer", "transfer-encoding",
    "upgrade", "upgrade-insecure-requests", "user-agent", "vary", "via", "warning", "websocket-location", "websocket-origin",
    "websocket-protocol", "www-authenticate", "x-frame-options", "x-requested-with", "alt-svc",
];

/// `KNOWN_HEADER_NAMES` in the order a Java `HashSet` of them iterates (which decides a tie in [`closest`]): by
/// bucket of a 128-slot table, then insertion order.
static KNOWN_HEADER_NAMES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let mut names: Vec<(usize, usize, &str)> = EXTRA_HEADER_NAMES
        .iter()
        .chain(NETTY_HEADER_NAMES)
        .enumerate()
        .map(|(inserted, name)| {
            let h = java_hash(name) as u32;
            ((h ^ (h >> 16)) as usize & 127, inserted, *name)
        })
        .collect();
    names.sort();
    names.into_iter().map(|(_, _, name)| name).collect()
});

fn java_hash(s: &str) -> i32 {
    s.encode_utf16().fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(i32::from(c)))
}

/// `Rule`, in declaration order (issues at one position sort by it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rule {
    InvalidExpectation,
    DuplicateId,
    Shadowed,
    TimesZero,
    TimeToLiveZero,
    PercentageZero,
    UnreachableResponses,
    PathMissingLeadingSlash,
    PathIncludesSchemeAndHost,
    PathIncludesQueryString,
    PathGlobWildcard,
    PathTemplateWithoutPathParameters,
    MethodTypo,
    HeaderNameTypo,
    StrictJsonBodyWithArrays,
}

impl Rule {
    fn name(self) -> &'static str {
        match self {
            Rule::InvalidExpectation => "INVALID_EXPECTATION",
            Rule::DuplicateId => "DUPLICATE_ID",
            Rule::Shadowed => "SHADOWED",
            Rule::TimesZero => "TIMES_ZERO",
            Rule::TimeToLiveZero => "TIME_TO_LIVE_ZERO",
            Rule::PercentageZero => "PERCENTAGE_ZERO",
            Rule::UnreachableResponses => "UNREACHABLE_RESPONSES",
            Rule::PathMissingLeadingSlash => "PATH_MISSING_LEADING_SLASH",
            Rule::PathIncludesSchemeAndHost => "PATH_INCLUDES_SCHEME_AND_HOST",
            Rule::PathIncludesQueryString => "PATH_INCLUDES_QUERY_STRING",
            Rule::PathGlobWildcard => "PATH_GLOB_WILDCARD",
            Rule::PathTemplateWithoutPathParameters => "PATH_TEMPLATE_WITHOUT_PATH_PARAMETERS",
            Rule::MethodTypo => "METHOD_TYPO",
            Rule::HeaderNameTypo => "HEADER_NAME_TYPO",
            Rule::StrictJsonBodyWithArrays => "STRICT_JSON_BODY_WITH_ARRAYS",
        }
    }

    fn severity(self) -> &'static str {
        match self {
            Rule::InvalidExpectation => "ERROR",
            Rule::StrictJsonBodyWithArrays => "INFO",
            _ => "WARNING",
        }
    }
}

/// One expectation as `ExpectationLinter.Subject` sees it: `expectation` is `None` for an invalid entry.
#[derive(Clone)]
struct Subject {
    expectation: Option<Lintable>,
    order: usize,
    serving_position: usize,
    reported_id: Option<String>,
    summary: String,
}

impl Subject {
    fn describe(&self) -> String {
        match &self.reported_id {
            Some(id) => format!("'{id}' ({})", self.summary),
            None => self.summary.clone(),
        }
    }
}

/// The parts of an `Expectation` the checks read.
#[derive(Clone)]
struct Lintable {
    canonical: Value,
    /// `getHttpRequest() instanceof HttpRequest`, not negated.
    request: Option<Request>,
    match_count: u32,
}

#[derive(Clone)]
struct Request {
    method: NString,
    path: NString,
    path_parameters: (Entries, String),
    query: (Entries, String),
    headers: (Entries, String),
    cookies: Entries,
    raw: Map<String, Value>,
}

struct Issue {
    rule: Rule,
    field: Option<&'static str>,
    message: String,
    subject: Subject,
    related: Option<Subject>,
}

impl Issue {
    fn new(rule: Rule, field: Option<&'static str>, message: String, subject: &Subject, related: Option<&Subject>) -> Issue {
        let message = if message.encode_utf16().count() > MAX_MESSAGE_LENGTH {
            format!("{}...", String::from_utf16_lossy(&message.encode_utf16().take(MAX_MESSAGE_LENGTH).collect::<Vec<_>>()))
        } else {
            message
        };
        Issue { rule, field, message, subject: subject.clone(), related: related.cloned() }
    }
}

#[derive(Default)]
struct Report {
    issues: Vec<Issue>,
    expectations_checked: usize,
    skipped: usize,
    pair_comparisons: u64,
    shadow_check_truncated: bool,
    issues_truncated: bool,
}

impl Report {
    fn add(&mut self, issue: Issue) {
        if self.issues.len() >= MAX_ISSUES {
            self.issues_truncated = true;
        } else {
            self.issues.push(issue);
        }
    }
}

// ---- reading an expectation ----

fn lintable(input: &Value, canonical: &Value, match_count: u32) -> Lintable {
    let request = input.get("httpRequest").filter(|r| !r.is_null()).and_then(|_| canonical.get("httpRequest")).and_then(Value::as_object).filter(|r| {
        request_class(r) == "HttpRequest" && r.get("not").and_then(Value::as_bool) != Some(true)
    });
    let given = input.get("httpRequest").and_then(Value::as_object);
    Lintable { canonical: canonical.clone(), request: request.map(|r| read_request(r, given.unwrap_or(r))), match_count }
}

/// The request's strings and multimaps from the input (`given`), whose key order the model keeps; the rest from
/// the canonical form.
fn read_request(r: &Map<String, Value>, given: &Map<String, Value>) -> Request {
    let string = |key: &str| given.get(key).and_then(NString::from_json).unwrap_or_else(|| NString::parse(""));
    let multi = |key: &str| {
        let (entries, style) = given.get(key).map(model::multi_values_with_style).unwrap_or_default();
        (entries, style.unwrap_or_else(|| "SUB_SET".to_string()))
    };
    Request {
        method: string("method"),
        path: string("path"),
        path_parameters: multi("pathParameters"),
        query: multi("queryStringParameters"),
        headers: multi("headers"),
        cookies: given.get("cookies").map(model::key_values).unwrap_or_default(),
        raw: r.clone(),
    }
}

/// `RequestDefinitionDTODeserializer`: which request definition a JSON object builds.
fn request_class(r: &Map<String, Value>) -> &'static str {
    let non_blank = |key: &str| r.get(key).and_then(Value::as_str).is_some_and(|s| !s.trim().is_empty());
    if r.contains_key("if") {
        "ConditionalRequestDefinition"
    } else if non_blank("dnsName") {
        "DnsRequestDefinition"
    } else if r.get("binaryData").is_some_and(|b| !b.is_null()) {
        "BinaryRequestDefinition"
    } else if non_blank("specUrlOrPayload") {
        "OpenAPIDefinition"
    } else {
        "HttpRequest"
    }
}

/// `ExpectationLinter.summary`: `<method> <path>` of an HTTP request, else the definition's class.
fn summary(input: &Value, canonical: &Value) -> String {
    if input.get("httpRequest").is_none_or(Value::is_null) {
        return "any request".to_string();
    }
    let Some(r) = canonical.get("httpRequest").and_then(Value::as_object) else { return "any request".to_string() };
    let class = request_class(r);
    if class != "HttpRequest" {
        return class.to_string();
    }
    let shown = |key: &str, otherwise: &str| match r.get(key).and_then(NString::from_json) {
        Some(s) if s.value.as_deref().is_some_and(|v| !v.is_empty()) => to_string(&s),
        _ => otherwise.to_string(),
    };
    format!("{} {}", shown("method", "any method"), shown("path", "any path"))
}

/// `NottableString.toString()`; a schema string prints its schema.
fn to_string(s: &NString) -> String {
    if s.schema.is_some() {
        return s.value.clone().unwrap_or_default();
    }
    let mut out = String::new();
    if s.optional {
        out.push('?');
    }
    if s.not {
        out.push('!');
    }
    out.push_str(s.value.as_deref().unwrap_or_default());
    out
}

impl Lintable {
    fn times(&self) -> Option<i64> {
        let t = self.canonical.get("times")?;
        if t.get("unlimited").and_then(Value::as_bool) == Some(true) {
            return None;
        }
        t.get("remainingTimes").and_then(Value::as_i64)
    }

    fn time_to_live(&self) -> Option<i64> {
        let t = self.canonical.get("timeToLive")?;
        if t.get("unlimited").and_then(Value::as_bool) == Some(true) {
            return None;
        }
        t.get("timeToLive").and_then(Value::as_i64)
    }

    fn times_limited(&self) -> bool {
        self.canonical.get("times").is_some_and(|t| t.get("unlimited").and_then(Value::as_bool) != Some(true))
    }

    fn time_to_live_limited(&self) -> bool {
        self.canonical.get("timeToLive").is_some_and(|t| t.get("unlimited").and_then(Value::as_bool) != Some(true))
    }

    fn percentage(&self) -> Option<i64> {
        self.canonical.get("percentage").and_then(Value::as_i64)
    }

    fn priority(&self) -> i64 {
        self.canonical.get("priority").and_then(Value::as_i64).unwrap_or(0)
    }

    fn namespace(&self) -> Option<&Value> {
        self.canonical.get("namespace").filter(|n| !n.is_null())
    }

    /// `alwaysServesWhenMatched`: nothing can pass it over once it matches.
    fn always_serves_when_matched(&self) -> bool {
        if self.times_limited() || self.time_to_live_limited() {
            return false;
        }
        if self.percentage().is_some_and(|p| p < 100) {
            return false;
        }
        let present = |key: &str| self.canonical.get(key).is_some_and(|v| !v.is_null());
        if present("scenarioName") && present("scenarioState") {
            return false;
        }
        if let Some(llm) = self.canonical.get("httpLlmResponse").filter(|l| !l.is_null()) {
            const PREDICATES: &[&str] = &["turnIndex", "latestMessageContains", "latestMessageMatches", "latestMessageRole", "containsToolResultFor", "semanticMatchAgainst"];
            let gated = llm.get("conversationPredicates").and_then(Value::as_object).is_some_and(|p| PREDICATES.iter().any(|k| p.get(*k).is_some_and(|v| !v.is_null())));
            return !gated;
        }
        true
    }
}

// ---- entry points ----

/// `ExpectationLinter.lintJson`'s entries: each issue's `index` is the entry's position in `entries`. `log_failure`
/// is called with the text and format of an entry `ExpectationSerializer.deserialize` fails to read after validation.
pub fn lint_entries(entries: &[Value], log_failure: impl FnMut(&str, &str)) -> Value {
    lint_file_entries(entries, None, log_failure)
}

/// `ExpectationLinter.lintInitializationFileEntries`: as [`lint_entries`], for entries read from initialisation files,
/// `file_of_entry` numbering each entry's file in load order; `DUPLICATE_ID` names the load that replaces an entry.
pub fn lint_initialization_file_entries(entries: &[Value], file_of_entry: &Vec<usize>, log_failure: impl FnMut(&str, &str)) -> Value {
    lint_file_entries(entries, Some(file_of_entry), log_failure)
}

fn lint_file_entries(entries: &[Value], file_of_entry: Option<&Vec<usize>>, mut log_failure: impl FnMut(&str, &str)) -> Value {
    let mut report = Report::default();
    let mut subjects = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let explicit_id = entry.get("id").and_then(Value::as_str).map(str::to_string);
        if entry.as_object().is_some_and(|o| o.contains_key("specUrlOrPayload")) {
            report.skipped += 1;
            continue;
        }
        match valid_expectation(entry, &mut log_failure) {
            Ok(canonical) => {
                let summary = summary(entry, &canonical);
                subjects.push(Subject { expectation: Some(lintable(entry, &canonical, 0)), order: index, serving_position: index, reported_id: explicit_id, summary });
            }
            Err(invalid) => {
                let text = |key: &str| as_text(entry.get("httpRequest").and_then(|r| r.get(key)));
                let summary = format!("{} {}", text("method"), text("path")).trim().to_string();
                let subject = Subject { expectation: None, order: index, serving_position: index, reported_id: explicit_id, summary };
                let reason = match invalid.find("schema validation errors:") {
                    Some(at) => invalid[at + "schema validation errors:".len()..].trim().to_string(),
                    None => invalid,
                };
                report.add(Issue::new(Rule::InvalidExpectation, None, format!("not a valid expectation, so PUT /mockserver/expectation would reject it: {reason}"), &subject, None));
            }
        }
    }
    let mut subjects = remove_replaced_duplicates(&mut report, subjects, file_of_entry);
    sort_serving_order(&mut subjects);
    lint(&mut report, &subjects, true, true);
    to_json(&report, "request", "index", "openApiExpectationsSkipped")
}

/// `ExpectationSerializer.deserialize` of one entry: its canonical form, or the `IllegalArgumentException`'s message.
fn valid_expectation(entry: &Value, log_failure: &mut impl FnMut(&str, &str)) -> Result<Value, String> {
    let Some(o) = entry.as_object() else { return Err("each entry must be an expectation object".to_string()) };
    if let Err(report) = crate::schema::validate_expectation(entry) {
        return Err(crate::schema::incorrect_expectation(entry, &report));
    }
    if let Some((cause, _chain)) = crate::matcher::expectation_body_failure(entry) {
        let text = crate::json::compact(entry);
        log_failure(&text, &format!("exception while parsing{{}}for Expectation {cause}"));
        return Err(format!("exception while parsing [{text}] for Expectation because {cause}"));
    }
    if let Some((cause, chain)) = entry.get("httpRequest").and_then(crate::matcher::date_time_failure) {
        let text = crate::json::compact(entry);
        let chain = format!("org.mockserver.serialization.model.ExpectationDTO[\"httpRequest\"]{chain}");
        log_failure(&text, &format!("exception while parsing{{}}for Expectation {cause} (through reference chain: {chain})"));
        return Err(format!("exception while parsing [{text}] for Expectation because {cause}"));
    }
    let id = o.get("id").and_then(Value::as_str).unwrap_or("00000000-0000-0000-0000-000000000000");
    Ok(crate::canonical::expectation(o, id))
}

/// `JsonNode.asText("")` of a missing, null, container or value node.
fn as_text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) if n.is_i64() || n.is_u64() => n.to_string(),
        Some(Value::Number(n)) => java_compat::double_to_string(n.as_f64().unwrap_or(0.0)),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

/// One stored expectation for [`lint_stored`]: input, current canonical form, active, match count.
pub struct Stored {
    pub input: Value,
    pub canonical: Value,
    pub active: bool,
    pub match_count: u32,
}

/// `ExpectationLinter.lintStored`: the stored expectations in match order; inactive ones are counted, not checked.
pub fn lint_stored(stored: &[Stored]) -> Value {
    let mut report = Report::default();
    let mut subjects = Vec::new();
    for (index, e) in stored.iter().enumerate() {
        let position = index + 1;
        if !e.active {
            report.skipped += 1;
            continue;
        }
        let id = e.canonical.get("id").and_then(Value::as_str).map(str::to_string);
        subjects.push(Subject {
            expectation: Some(lintable(&e.input, &e.canonical, e.match_count)),
            order: position,
            serving_position: position,
            reported_id: id,
            summary: summary(&e.input, &e.canonical),
        });
    }
    lint(&mut report, &subjects, true, true);
    to_json(&report, "stored", "position", "inactiveExpectationsSkipped")
}

/// `ExpectationLinter.adviseOnUpsert`: the cheap per-expectation checks at warning severity or above for the
/// expectations just created or updated (input and canonical form each). `None` when there is nothing to say;
/// otherwise the issue count and the WARN's argument.
pub fn advise_on_upsert(upserted: &[(Value, Value)]) -> Option<(usize, String)> {
    let mut report = Report::default();
    for (index, (input, canonical)) in upserted.iter().enumerate() {
        let subject = Subject {
            expectation: Some(lintable(input, canonical, 0)),
            order: index,
            serving_position: index,
            reported_id: canonical.get("id").and_then(Value::as_str).map(str::to_string),
            summary: summary(input, canonical),
        };
        lint_one(&mut report, &subject, false);
    }
    if report.issues.is_empty() {
        return None;
    }
    Some((report.issues.len(), warning_lines(&report.issues, "")))
}

/// The WARN's format for [`advise_on_upsert`] with `count` problems.
pub fn upsert_warning_format(count: usize) -> String {
    format!("expectation lint found {count} problem(s) in the expectations just created or updated, which were stored unchanged; PUT /mockserver/lint checks every stored expectation, including for shadowing:{{}}")
}

/// `ExpectationLinter.adviseOnLoad`: the loaded expectations of one initialisation file (input and canonical form,
/// and whether the loader generated its id). Returns the digest of the problems found (0 for none) and, when it
/// differs from `previous_digest`, the WARN's format and arguments.
pub fn advise_on_load(loaded: &[(Value, Value, bool)], previous_digest: i32) -> (i32, Option<(String, String)>) {
    if loaded.is_empty() {
        return (0, None);
    }
    let subjects: Vec<Subject> = loaded
        .iter()
        .enumerate()
        .map(|(index, (input, canonical, generated))| Subject {
            expectation: Some(lintable(input, canonical, 0)),
            order: index,
            serving_position: index,
            reported_id: if *generated { None } else { canonical.get("id").and_then(Value::as_str).map(str::to_string) },
            summary: summary(input, canonical),
        })
        .collect();
    let mut report = Report::default();
    let mut subjects = remove_replaced_duplicates(&mut report, subjects, Some(&vec![0; loaded.len()]));
    sort_serving_order(&mut subjects);
    lint(&mut report, &subjects, true, false);
    if report.issues.is_empty() {
        return (0, None);
    }
    let truncated = if report.shadow_check_truncated { "\n - the shadowing check stopped at its budget, so not every pair of expectations was compared" } else { "" };
    let mut all_issues = truncated.to_string();
    for issue in &report.issues {
        all_issues.push_str(&format!("\n{} {}: {}", issue.rule.name(), issue.subject.describe(), issue.message));
    }
    let digest = match java_hash(&all_issues) {
        0 => 1,
        digest => digest,
    };
    if digest == previous_digest {
        return (digest, None);
    }
    let format = format!(
        "expectation lint found {} problem(s) in the expectations loaded from initialization file:{{}}which were loaded unchanged; PUT /mockserver/lint or mockserver lint <file> lists them in full:{{}}",
        report.issues.len()
    );
    (digest, Some((format, warning_lines(&report.issues, truncated))))
}

fn warning_lines(warnings: &[Issue], suffix: &str) -> String {
    let mut lines = String::new();
    for issue in warnings.iter().take(MAX_LOGGED_ISSUES) {
        lines.push_str(&format!("\n - {} expectation {}: {}", issue.rule.name(), issue.subject.describe(), issue.message));
    }
    if warnings.len() > MAX_LOGGED_ISSUES {
        lines.push_str(&format!("\n - and {} more", warnings.len() - MAX_LOGGED_ISSUES));
    }
    lines.push_str(suffix);
    lines
}

fn sort_serving_order(subjects: &mut [Subject]) {
    subjects.sort_by_key(|s| (-s.expectation.as_ref().map_or(0, Lintable::priority), s.serving_position));
}

// ---- the checks ----

fn lint(report: &mut Report, serving_order: &[Subject], check_shadowing: bool, include_info: bool) {
    for subject in serving_order {
        report.expectations_checked += 1;
        lint_one(report, subject, include_info);
    }
    if check_shadowing {
        find_shadowed(report, serving_order);
    }
    report.issues.sort_by_key(|issue| (issue.subject.order, issue.rule));
}

/// `removeReplacedDuplicates`: an upsert (`file_of_entry` `None`) and a file load both keep the last entry for an
/// id, served from the first entry's place.
fn remove_replaced_duplicates(report: &mut Report, subjects: Vec<Subject>, file_of_entry: Option<&Vec<usize>>) -> Vec<Subject> {
    let mut first_by_id: HashMap<String, usize> = HashMap::new();
    let mut kept_by_id: HashMap<String, usize> = HashMap::new();
    for (i, subject) in subjects.iter().enumerate() {
        if let Some(id) = &subject.reported_id {
            first_by_id.entry(id.clone()).or_insert(i);
            kept_by_id.insert(id.clone(), i);
        }
    }
    let mut result = Vec::new();
    for (i, subject) in subjects.iter().enumerate() {
        let kept = subject.reported_id.as_ref().map_or(i, |id| kept_by_id[id]);
        if kept != i {
            let kept = &subjects[kept];
            let message = match file_of_entry {
                None => format!("is replaced by a later entry with the same id ({}); expectations are upserted by id, so only the last one is kept", kept.summary),
                Some(files) if files[kept.order] == files[subject.order] => {
                    format!("is replaced by a later entry in the same file with the same id ({}); loading a file keeps only the last entry for each id", kept.summary)
                }
                Some(_) => format!("is replaced by a later entry with the same id ({}); a file loaded later replaces an earlier file's entries with the same id", kept.summary),
            };
            report.add(Issue::new(Rule::DuplicateId, Some("id"), message, subject, Some(kept)));
        } else {
            let first = subject.reported_id.as_ref().map_or(i, |id| first_by_id[id]);
            let mut kept = subject.clone();
            kept.serving_position = subjects[first].order;
            result.push(kept);
        }
    }
    result
}

fn lint_one(report: &mut Report, subject: &Subject, include_info: bool) {
    let Some(e) = &subject.expectation else { return };
    if e.times_limited() && let Some(remaining) = e.times().filter(|r| *r <= 0) {
        report.add(Issue::new(
            Rule::TimesZero,
            Some("times"),
            format!("never matches: times allows {remaining} matches; remove times for unlimited matches, or set remainingTimes to at least 1"),
            subject,
            None,
        ));
    }
    if let Some(ttl) = e.time_to_live().filter(|t| *t <= 0) {
        report.add(Issue::new(Rule::TimeToLiveZero, Some("timeToLive"), format!("never matches: its time to live is {ttl}, so it expires as it is created"), subject, None));
    }
    if let Some(percentage) = e.percentage().filter(|p| *p <= 0) {
        report.add(Issue::new(
            Rule::PercentageZero,
            Some("percentage"),
            format!("never served: percentage is {percentage}, so every matching request passes it over"),
            subject,
            None,
        ));
    }
    check_unreachable_responses(report, subject, e);
    if let Some(request) = &e.request {
        check_path(report, subject, request);
        check_method(report, subject, &request.method);
        check_header_names(report, subject, request);
        if include_info {
            check_strict_json_arrays(report, subject, request);
        }
    }
}

fn check_unreachable_responses(report: &mut Report, subject: &Subject, e: &Lintable) {
    let responses = e.canonical.get("httpResponses").and_then(Value::as_array).map_or(0, Vec::len);
    let Some(remaining) = e.times().filter(|r| *r > 0) else { return };
    if responses < 2 || !e.times_limited() || e.match_count > 0 {
        return;
    }
    let mode = e.canonical.get("responseMode").and_then(Value::as_str).unwrap_or("SEQUENTIAL");
    let reachable = match mode {
        "SEQUENTIAL" => remaining.min(responses as i64),
        "SWITCH" => {
            let threshold = e.canonical.get("switchAfter").and_then(Value::as_i64).filter(|s| *s > 0).unwrap_or(1);
            ((remaining - 1) / threshold + 1).min(responses as i64)
        }
        _ => return,
    };
    if reachable < responses as i64 {
        report.add(Issue::new(
            Rule::UnreachableResponses,
            Some("httpResponses"),
            format!(
                "only the first {reachable} of its {responses} responses can be served: times allows {remaining} matches in {mode} mode, so responses {} to {responses} are never reached (except by the {FORCE_RESPONSE_INDEX_HEADER} header)",
                reachable + 1
            ),
            subject,
            None,
        ));
    }
}

fn is_plain(s: &NString) -> bool {
    s.value.is_some() && s.schema.is_none() && !s.not && !s.optional
}

fn value(s: &NString) -> &str {
    s.value.as_deref().unwrap_or_default()
}

/// `QUERY_STRING`, `(?<!\()\?[^?]*=`, found anywhere.
fn has_query_string(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    (0..chars.len()).any(|i| chars[i] == '?' && (i == 0 || chars[i - 1] != '(') && chars[i + 1..].iter().take_while(|c| **c != '?').any(|c| *c == '='))
}

static PATH_TEMPLATE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"/\{[A-Za-z_][A-Za-z0-9_.\-]*\}(?:/|\.|(?:\r\n|[\n\r\u{85}\u{2028}\u{2029}])?\z)").expect("a valid regex"));
static HOST_AND_PORT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\A[^/]+:[0-9]+\z").expect("a valid regex"));
static LETTER_OR_DIGIT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\A[\p{L}\p{Nd}]").expect("a valid regex"));

fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn check_path(report: &mut Report, subject: &Subject, request: &Request) {
    let path = &request.path;
    if !is_plain(path) || value(path).is_empty() {
        return;
    }
    let connect = value(&request.method).eq_ignore_ascii_case("CONNECT");
    let value = value(path);
    let lower = value.to_lowercase();
    // `Character.isLetterOrDigit(value.charAt(0))`: a supplementary character's high surrogate is neither
    let starts_letter_or_digit = value.chars().next().is_some_and(|c| (c as u32) <= 0xFFFF) && LETTER_OR_DIGIT.is_match(value);
    if lower.starts_with("http://") || lower.starts_with("https://") {
        report.add(Issue::new(
            Rule::PathIncludesSchemeAndHost,
            Some("path"),
            "never matches: the path is matched without the scheme and host, so write only the part from the first / (match the host with a Host header, or secure for https)".into(),
            subject,
            None,
        ));
    } else if !connect && starts_letter_or_digit && !value.contains('|') && !HOST_AND_PORT.is_match(value) {
        report.add(Issue::new(
            Rule::PathMissingLeadingSlash,
            Some("path"),
            format!("never matches: request paths always start with /, so use \"/{value}\""),
            subject,
            None,
        ));
    }
    if has_query_string(value) {
        report.add(Issue::new(
            Rule::PathIncludesQueryString,
            Some("path"),
            "does not match as written: the query string is not part of the path, and ? is a regex quantifier here; move it to queryStringParameters".into(),
            subject,
            None,
        ));
    }
    if value != "*" && (value.starts_with('*') || value.contains("/*")) {
        report.add(Issue::new(
            Rule::PathGlobWildcard,
            Some("path"),
            "the path is a regular expression, not a glob: * repeats the character before it, so \"/*\" matches any number of slashes, including none, and nothing else; use .* to match any characters".into(),
            subject,
            None,
        ));
    }
    if request.path_parameters.0.is_empty() && PATH_TEMPLATE.is_match(value) {
        report.add(Issue::new(
            Rule::PathTemplateWithoutPathParameters,
            Some("path"),
            "the path has a {name} template but no pathParameters, so the braces are matched as written; add pathParameters (for example \"name\": [\".*\"]) or use a regex such as [^/]+".into(),
            subject,
            None,
        ));
    }
}

fn check_method(report: &mut Report, subject: &Subject, method: &NString) {
    if !is_plain(method) || !is_token(value(method)) {
        return;
    }
    let upper = value(method).to_ascii_uppercase();
    if KNOWN_METHODS.contains(&upper.as_str()) || upper.len() < 3 {
        return;
    }
    if let Some(suggestion) = closest(&upper, KNOWN_METHODS.iter().copied(), 1) {
        report.add(Issue::new(Rule::MethodTypo, Some("method"), format!("\"{}\" is not an HTTP method; did you mean {suggestion}?", value(method)), subject, None));
    }
}

fn check_header_names(report: &mut Report, subject: &Subject, request: &Request) {
    for (name, _) in &request.headers.0 {
        if !is_plain(name) || !is_token(value(name)) {
            continue;
        }
        if let Some(suggestion) = suggest_header_name(value(name)) {
            report.add(Issue::new(
                Rule::HeaderNameTypo,
                Some("headers"),
                format!("header \"{}\" is not a standard header name; did you mean {suggestion}?", value(name)),
                subject,
                None,
            ));
        }
    }
}

fn suggest_header_name(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let known = |n: &str| KNOWN_HEADER_NAMES.contains(&n);
    if known(&lower) {
        return None;
    }
    let hyphenated = lower.replace('_', "-");
    if known(&hyphenated) {
        return Some(display_header_name(&hyphenated));
    }
    if lower.len() < 5 {
        return None;
    }
    closest(&hyphenated, KNOWN_HEADER_NAMES.iter().copied(), 1).map(display_header_name)
}

fn check_strict_json_arrays(report: &mut Report, subject: &Subject, request: &Request) {
    let Some(body) = request.raw.get("body") else { return };
    if body.get("not").and_then(Value::as_bool) == Some(true) {
        return;
    }
    let Some(model::Body::Json { value, match_type, .. }) = model::request_body(body) else { return };
    if match_type != "STRICT" {
        return;
    }
    if serde_json::from_str::<Value>(&value).is_ok_and(|v| contains_array(&v)) {
        report.add(Issue::new(
            Rule::StrictJsonBodyWithArrays,
            Some("body"),
            "STRICT matching needs every array in the same order with no extra items; if order or extra items should not matter use ONLY_MATCHING_FIELDS (the default)".into(),
            subject,
            None,
        ));
    }
}

fn contains_array(v: &Value) -> bool {
    match v {
        Value::Array(_) => true,
        Value::Object(o) => o.values().any(contains_array),
        _ => false,
    }
}

// ---- shadowing ----

fn find_shadowed(report: &mut Report, serving_order: &[Subject]) {
    fn request(s: &Subject) -> Option<&Request> {
        s.expectation.as_ref().and_then(|e| e.request.as_ref())
    }
    let mut by_path: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, subject) in serving_order.iter().enumerate() {
        if let Some(r) = request(subject).filter(|r| is_plain(&r.path)) {
            by_path.entry(value(&r.path)).or_default().push(i);
        }
    }
    let mut shadowed = vec![false; serving_order.len()];
    let mut budget = RegexBudget::new(MAX_REGEX_STEPS);
    for i in 0..serving_order.len() {
        let earlier = &serving_order[i];
        let Some(earlier_request) = request(earlier) else { continue };
        let earlier_expectation = earlier.expectation.as_ref().expect("a request has an expectation");
        if shadowed[i] || !earlier_expectation.always_serves_when_matched() {
            continue;
        }
        let earlier_path = &earlier_request.path;
        let literal_path = is_plain(earlier_path) && !value(earlier_path).is_empty() && !looks_like_regex(value(earlier_path));
        let path_pattern = if literal_path { None } else { compile(earlier_path) };
        let method_pattern = compile(&earlier_request.method);
        let candidates = literal_path.then(|| by_path.get(value(earlier_path)).cloned().unwrap_or_default());
        let (first, count) = match &candidates {
            Some(c) => (c.binary_search(&i).map_or_else(|insert| insert, |found| found + 1), c.len()),
            None => (i + 1, serving_order.len()),
        };
        for c in first..count {
            if report.pair_comparisons >= MAX_PAIR_COMPARISONS {
                report.shadow_check_truncated = true;
                return;
            }
            report.pair_comparisons += 1;
            let j = candidates.as_ref().map_or(c, |cs| cs[c]);
            let later = &serving_order[j];
            let Some(later_request) = request(later) else { continue };
            if shadowed[j] || served_earlier(later_request, earlier_request) {
                continue;
            }
            let later_expectation = later.expectation.as_ref().expect("a request has an expectation");
            if earlier_expectation.namespace() == later_expectation.namespace() && covers(earlier_request, later_request, method_pattern.as_deref(), path_pattern.as_deref(), &mut budget) {
                shadowed[j] = true;
                let (earlier_priority, later_priority) = (earlier_expectation.priority(), later_expectation.priority());
                let order = if earlier_priority > later_priority {
                    format!("(priority {earlier_priority} > {later_priority})")
                } else {
                    "(same priority, created earlier)".to_string()
                };
                report.add(Issue::new(
                    Rule::Shadowed,
                    None,
                    format!(
                        "never matches: {} is evaluated first {order}, matches every request this one matches, and never runs out (unlimited times, no time to live, scenario state or percentage); give this one a higher priority or make the other more specific",
                        earlier.describe()
                    ),
                    later,
                    Some(earlier),
                ));
            }
        }
        if budget.exhausted {
            report.shadow_check_truncated = true;
        }
    }
}

/// `ExpectationLinter.RegexBudget`: bounds the work a user's regex can make the shadowing check do. Each character a
/// match reads counts against a per-match and a total budget, and a match that runs out counts as "does not cover".
struct RegexBudget {
    remaining: i64,
    exhausted: bool,
}

/// `ExpectationLinter.MAX_REGEX_STEPS`: the characters all the shadowing check's matches may read.
const MAX_REGEX_STEPS: i64 = 2_000_000;
/// `ExpectationLinter.MAX_REGEX_STEPS_PER_MATCH`.
const MAX_REGEX_STEPS_PER_MATCH: i64 = 100_000;
/// The walk levels that stand for the stack the JVM's thread gives `java.util.regex`'s recursion, where a long input
/// ends in `StackOverflowError` (read as "does not cover"). The JVM's depth varies with the JIT; this is the cold one,
/// measured on the oracle: `/(a|b)*` matches `/abab...` up to 3,993 characters and overflows from 3,995; our walk takes
/// three levels per character there, and 3,993 characters need 11,982.
pub(crate) const REGEX_STACK_LEVELS: usize = 11_982;

impl RegexBudget {
    fn new(total: i64) -> RegexBudget {
        RegexBudget { remaining: total, exhausted: false }
    }

    fn matches(&mut self, pattern: &crate::matcher::java_pattern::JavaRegex, input: &str) -> bool {
        if self.remaining <= 0 {
            self.exhausted = true;
            return false;
        }
        let limit = self.remaining.min(MAX_REGEX_STEPS_PER_MATCH);
        let (answer, reads) = pattern.matches_budgeted(input, limit as u64, REGEX_STACK_LEVELS);
        self.remaining -= i64::try_from(reads).unwrap_or(i64::MAX);
        if self.remaining <= 0 {
            self.exhausted = true;
        }
        answer.unwrap_or(false)
    }
}

fn flag(r: &Request, key: &str) -> Option<bool> {
    r.raw.get(key).and_then(Value::as_bool)
}

/// `respondBeforeBody` expectations are matched before the body arrives, ahead of every other expectation.
fn served_earlier(later: &Request, earlier: &Request) -> bool {
    flag(later, "respondBeforeBody") == Some(true) && flag(earlier, "respondBeforeBody") != Some(true)
}

fn covers(earlier: &Request, later: &Request, method_pattern: Option<&crate::matcher::java_pattern::JavaRegex>, path_pattern: Option<&crate::matcher::java_pattern::JavaRegex>, budget: &mut RegexBudget) -> bool {
    let path_parameters = !earlier.path_parameters.0.is_empty() || !later.path_parameters.0.is_empty();
    if path_parameters
        && !(!earlier.path_parameters.0.is_empty() && same_string(&earlier.path, &later.path, false) && multi_values_cover(&earlier.path_parameters, &later.path_parameters, false))
    {
        return false;
    }
    let field_covers = |key: &str| earlier.raw.get(key).is_none_or(Value::is_null) || earlier.raw.get(key) == later.raw.get(key);
    multi_values_cover(&earlier.query, &later.query, false)
        && multi_values_cover(&earlier.headers, &later.headers, true)
        && values_cover(&earlier.cookies, &later.cookies)
        && field_covers("body")
        && field_covers("keepAlive")
        && field_covers("secure")
        && field_covers("protocol")
        && field_covers("clientCertificate")
        && field_covers("jwt")
        && field_covers("clientIp")
        && string_covers(&earlier.method, &later.method, method_pattern, budget)
        && (path_parameters || string_covers(&earlier.path, &later.path, path_pattern, budget))
}

fn string_covers(earlier: &NString, later: &NString, earlier_pattern: Option<&crate::matcher::java_pattern::JavaRegex>, budget: &mut RegexBudget) -> bool {
    if is_plain(earlier) && (value(earlier).is_empty() || value(earlier) == ".*") {
        return true;
    }
    if same_string(earlier, later, false) {
        return true;
    }
    let Some(pattern) = earlier_pattern else { return false };
    if !is_plain(later) || value(later).is_empty() || looks_like_regex(value(later)) {
        return false;
    }
    // the later value matches only itself, so the earlier one covers it when its pattern matches that text
    budget.matches(pattern, value(later))
}

fn multi_values_cover(earlier: &(Entries, String), later: &(Entries, String), ignore_key_case: bool) -> bool {
    if earlier.0.is_empty() {
        return true;
    }
    if later.0.is_empty() || earlier.1 != later.1 {
        return false;
    }
    earlier.0.iter().all(|(name, values)| later.0.iter().any(|(other, other_values)| same_string(name, other, ignore_key_case) && same_strings(values, other_values)))
}

fn values_cover(earlier: &Entries, later: &Entries) -> bool {
    if earlier.is_empty() {
        return true;
    }
    if later.is_empty() {
        return false;
    }
    earlier.iter().all(|(name, value)| {
        later.iter().any(|(other, other_value)| same_string(name, other, false) && same_optional(value.first().and_then(Option::as_ref), other_value.first().and_then(Option::as_ref)))
    })
}

fn same_strings(earlier: &[Option<NString>], later: &[Option<NString>]) -> bool {
    earlier.len() == later.len() && earlier.iter().all(|v| later.iter().any(|o| same_optional(v.as_ref(), o.as_ref())))
}

fn same_optional(one: Option<&NString>, two: Option<&NString>) -> bool {
    match (one, two) {
        (Some(a), Some(b)) => same_string(a, b, false),
        (None, None) => true,
        _ => false,
    }
}

/// `NottableString.equals` treats a schema as matching a value, so the parts are compared directly.
fn same_string(one: &NString, two: &NString, ignore_case: bool) -> bool {
    if one.schema.is_some() != two.schema.is_some() || one.not != two.not || one.optional != two.optional {
        return false;
    }
    match (&one.value, &two.value) {
        (Some(a), Some(b)) if ignore_case => java_equals_ignore_case(a, b),
        (a, b) => a == b,
    }
}

/// `String.equalsIgnoreCase`: per UTF-16 unit, equal after upper-casing or after lower-casing.
fn java_equals_ignore_case(a: &str, b: &str) -> bool {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    a.len() == b.len()
        && a.iter().zip(&b).all(|(x, y)| {
            x == y || {
                let (ux, uy) = (x.to_uppercase().next(), y.to_uppercase().next());
                ux == uy || ux.and_then(|c| c.to_lowercase().next()) == uy.and_then(|c| c.to_lowercase().next())
            }
        })
}

fn compile(s: &NString) -> Option<std::sync::Arc<crate::matcher::java_pattern::JavaRegex>> {
    if !is_plain(s) || value(s).is_empty() || value(s).encode_utf16().count() > MAX_PATTERN_LENGTH || !looks_like_regex(value(s)) {
        return None;
    }
    crate::matcher::java_pattern::compile_with_flags(value(s), crate::matcher::java_pattern::DOTALL).ok()
}

fn looks_like_regex(value: &str) -> bool {
    value.chars().any(|c| "\\.[]{}()*+?^$|".contains(c))
}

fn closest<'a>(value: &str, candidates: impl Iterator<Item = &'a str>, max_distance: usize) -> Option<&'a str> {
    let mut best = None;
    let mut best_distance = max_distance + 1;
    for candidate in candidates {
        if candidate.len().abs_diff(value.len()) > max_distance {
            continue;
        }
        let distance = edit_distance(value, candidate);
        if distance < best_distance {
            best_distance = distance;
            best = Some(candidate);
        }
    }
    best
}

/// Optimal string alignment distance: insertions, deletions, substitutions and adjacent transpositions.
fn edit_distance(one: &str, two: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (one.chars().collect(), two.chars().collect());
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

fn display_header_name(lower: &str) -> String {
    let mut display = String::with_capacity(lower.len());
    let mut upper = true;
    for c in lower.chars() {
        if upper {
            display.extend(c.to_uppercase());
        } else {
            display.push(c);
        }
        upper = c == '-';
    }
    display
}

fn to_json(report: &Report, source: &str, order_field: &str, skipped_field: &str) -> Value {
    let mut result = Map::new();
    result.insert("source".into(), source.into());
    result.insert("note".into(), NOTE.into());
    result.insert("expectationsChecked".into(), report.expectations_checked.into());
    result.insert(skipped_field.into(), report.skipped.into());
    let (mut errors, mut warnings, mut infos) = (0, 0, 0);
    let mut issues = Vec::new();
    let related_field = format!("related{}{}", order_field[..1].to_uppercase(), &order_field[1..]);
    for issue in &report.issues {
        match issue.rule.severity() {
            "ERROR" => errors += 1,
            "WARNING" => warnings += 1,
            _ => infos += 1,
        }
        let mut node = Map::new();
        node.insert("rule".into(), issue.rule.name().into());
        node.insert("severity".into(), issue.rule.severity().into());
        if let Some(id) = &issue.subject.reported_id {
            node.insert("expectationId".into(), id.clone().into());
        }
        node.insert(order_field.into(), issue.subject.order.into());
        node.insert("summary".into(), issue.subject.summary.clone().into());
        if let Some(field) = issue.field {
            node.insert("field".into(), field.into());
        }
        node.insert("message".into(), issue.message.clone().into());
        if let Some(related) = &issue.related {
            if let Some(id) = &related.reported_id {
                node.insert("relatedExpectationId".into(), id.clone().into());
            }
            node.insert(related_field.clone(), related.order.into());
            node.insert("relatedSummary".into(), related.summary.clone().into());
        }
        issues.push(Value::Object(node));
    }
    result.insert("issueCount".into(), report.issues.len().into());
    result.insert("errorCount".into(), errors.into());
    result.insert("warningCount".into(), warnings.into());
    result.insert("infoCount".into(), infos.into());
    result.insert("issuesTruncated".into(), report.issues_truncated.into());
    result.insert("pairComparisons".into(), report.pair_comparisons.into());
    result.insert("maxPairComparisons".into(), MAX_PAIR_COMPARISONS.into());
    result.insert("shadowCheckTruncated".into(), report.shadow_check_truncated.into());
    result.insert("issues".into(), Value::Array(issues));
    Value::Object(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_distance_counts_a_transposition_as_one() {
        assert_eq!(edit_distance("GTE", "GET"), 1);
        assert_eq!(edit_distance("contnet-type", "content-type"), 1);
    }

    #[test]
    fn header_suggestions() {
        assert_eq!(suggest_header_name("x_request_id").as_deref(), Some("X-Request-Id"));
        assert_eq!(suggest_header_name("Authorisation").as_deref(), Some("Authorization"));
        assert_eq!(suggest_header_name("Request-Id"), None);
        assert_eq!(suggest_header_name("Hots"), None);
        assert_eq!(KNOWN_HEADER_NAMES.len(), 96);
    }

    #[test]
    fn query_string_ignores_a_lookahead() {
        assert!(has_query_string("/x?y=1"));
        assert!(has_query_string("/(?=x)y?a=b"));
        assert!(!has_query_string("/(?=x)"));
    }
}

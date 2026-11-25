//! `NottableString` semantics (§3.3): blank matches all, numeric comparisons, equality, then an anchored
//! DOTALL regex, then negation. Case-insensitivity is decided by the caller per field.

use std::cell::Cell;

use super::java_pattern::{compile_with_flags, JavaRegex, PatternSyntaxException};
use std::sync::Arc;
use super::backtrack::{Budget, Outcome, Program};
use serde_json::Value;

thread_local! {
    /// SECURITY: whether a JSON Schema `$ref` compiled on this thread right now may resolve over
    /// the network or the filesystem — `JsonSchemaValidator.JSON_SCHEMA_ALLOW_REMOTE_REFS_PROPERTY`
    /// (`jsonSchemaAllowRemoteRefs`, default deny), read once per `Server` and carried here for the length of
    /// one matcher compilation ([`with_remote_refs_policy`]). Thread-local rather than a single global: several
    /// `Server`s with different settings compile expectations concurrently on different threads (the oracle
    /// test harness runs many in one process). Every entry point that compiles a request matcher from
    /// untrusted input (an expectation, a verify/breakpoint filter, an initializer file) sets this first; the
    /// whole compile tree underneath is synchronous (no `.await`), so no other task can ever observe a stale
    /// value left on this OS thread by a different `Server`'s request.
    static ALLOW_REMOTE_REFS: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f` — which must be synchronous, not spanning an `.await` — with the JSON Schema remote-`$ref` policy
/// set to `allow`, restoring whatever it was before once `f` returns (so nested compiles, e.g. an OpenAPI
/// expectation's per-operation alternatives, inherit the same policy for free).
pub fn with_remote_refs_policy<R>(allow: bool, f: impl FnOnce() -> R) -> R {
    let previous = ALLOW_REMOTE_REFS.with(|c| c.replace(allow));
    let result = f();
    ALLOW_REMOTE_REFS.with(|c| c.set(previous));
    result
}

pub(crate) fn remote_refs_allowed() -> bool {
    ALLOW_REMOTE_REFS.with(Cell::get)
}

thread_local! {
    /// Whether the comparisons made on this thread right now are a control-plane matcher's
    /// (`RegexStringMatcher.controlPlaneMatcher`, set when a matcher is built from a request definition: a verification,
    /// retrieve or clear filter): the matched value, read as a regex, may then match the matcher's value.
    static CONTROL_PLANE: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f` — synchronous, not spanning an `.await` — with every string comparison a control-plane one (`on`) or a
/// data-plane one, restoring the previous mode once `f` returns.
/// Whether a control-plane match (`controlPlaneMatcher`) is being evaluated.
pub(crate) fn in_control_plane() -> bool {
    CONTROL_PLANE.with(Cell::get)
}

pub(crate) fn with_control_plane<R>(on: bool, f: impl FnOnce() -> R) -> R {
    let previous = CONTROL_PLANE.with(|c| c.replace(on));
    let result = f();
    CONTROL_PLANE.with(|c| c.set(previous));
    result
}

/// The first remote or local-file `$ref` in `schema` that upstream's block predicate refuses to load when
/// remote refs are not allowed (SECURITY): `http`, `https`, `ftp`, `ftps`, `file` or `jar`, except
/// the two standard meta-schema prefixes the validator resolves from its own bundled copy rather than fetching.
/// A prefix check, not full IRI parsing — good enough for a `$ref` value as MockServer's own schemas and the
/// upstream test use it; an exotic scheme this misses still cannot fetch anything, because [`validator`] applies
/// [`Validator::offline`] whenever the policy denies remote refs, regardless of what this scan found.
///
/// [`Validator::offline`]: jsonschema::ValidationOptions::offline
pub fn blocked_remote_ref(schema: &Value) -> Option<String> {
    const BLOCKED_PREFIXES: &[&str] = &["http://", "https://", "ftp://", "ftps://", "file://", "jar:"];
    const EXEMPT_PREFIXES: &[&str] = &["http://json-schema.org/", "https://json-schema.org/"];
    fn walk(v: &Value) -> Option<String> {
        match v {
            Value::Object(o) => {
                if let Some(Value::String(r)) = o.get("$ref") {
                    let lower = r.trim().to_ascii_lowercase();
                    if !EXEMPT_PREFIXES.iter().any(|p| lower.starts_with(p)) && BLOCKED_PREFIXES.iter().any(|p| lower.starts_with(p)) {
                        return Some(r.clone());
                    }
                }
                o.values().find_map(walk)
            }
            Value::Array(items) => items.iter().find_map(walk),
            _ => None,
        }
    }
    walk(schema)
}

#[derive(Debug)]
enum Kind {
    Blank,
    /// Contains no regex metacharacters: equality is the whole test.
    Literal,
    /// `java`: the replay of Java's backtracking for a pattern that can outlive `regexMatchingTimeoutMillis`.
    /// `sensitive`/`insensitive`: `Pattern.compile` with `DOTALL`, and with `DOTALL | CASE_INSENSITIVE | UNICODE_CASE`
    /// (`NottableString.matches`); `None` when `Pattern.compile` refuses the value.
    Regex { sensitive: Option<Arc<JavaRegex>>, insensitive: Option<Arc<JavaRegex>>, java: Option<Box<JavaReplay>> },
    Numeric { op: Op, operand: f64 },
    /// `accept:<type>/<subtype>` (`AcceptHeaderMatcher`): the actual value is an `Accept` header that must make the
    /// media type acceptable; `None` when the media type does not parse (never matches).
    Accept(Option<(String, String)>),
    Schema(Box<Schema>),
    /// A date-time comparison (`NottableDateTimeString`); `None` when its options do not compile, which the
    /// expectation's deserialisation already refused.
    /// The second field is the value as `NottableStringSerializer.writeDateTime` writes it.
    DateTime(Option<Box<crate::templates::dates::comparison::DateTimeComparison>>, Value),
}

/// Which `RegexStringMatcher` comparison a matcher makes, which decides the line a failure records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    String,
    Numeric,
    Accept,
    Schema,
    DateTime,
}

/// A `NottableSchemaString`: the validator, the schema's `type`, whether it is `nullable`, and the schema as
/// MockServer prints it in match differences.
#[derive(Debug)]
pub struct Schema {
    /// `None` when the `jsonschema` crate cannot build the schema (networknt still evaluates it).
    validator: Option<jsonschema::Validator>,
    schema: Value,
    pub type_: Option<String>,
    nullable: bool,
    pub printed: String,
}

/// MockServer's JSON Schema validator: the draft named by `$schema`, otherwise draft 7, with formats asserted.
///
/// SECURITY: the `jsonschema` crate resolves a remote (`http`/`https`) or local-file `$ref` itself,
/// eagerly, while building this validator — by default (`resolve-http`/`resolve-file`, this crate's default
/// features) with a real, blocking `reqwest` GET or `std::fs::File::open`. Left unguarded, a submitted schema
/// could make this process fetch an attacker-chosen URL or read an arbitrary local file the moment an
/// expectation naming it is registered. `JsonSchemaValidator.JSON_SCHEMA_ALLOW_REMOTE_REFS_PROPERTY` gates the
/// same resolution upstream, default deny; [`remote_refs_allowed`] mirrors that decision (see
/// [`with_remote_refs_policy`]) and this applies [`offline`](jsonschema::ValidationOptions::offline) whenever it
/// is false, which refuses any reference not already inside `schema` itself — internal (`#/...`) refs and the
/// two bundled `json-schema.org` meta-schemas are unaffected, since those never leave the built-in registry.
pub fn validator(schema: &Value) -> Result<jsonschema::Validator, String> {
    let draft = match schema.get("$schema").and_then(Value::as_str) {
        Some(s) if s.contains("draft-03") || s.contains("draft-04") => jsonschema::Draft::Draft4,
        Some(s) if s.contains("draft-05") || s.contains("draft-06") => jsonschema::Draft::Draft6,
        Some(s) if s.contains("draft/2019-09") => jsonschema::Draft::Draft201909,
        _ => jsonschema::Draft::Draft7,
    };
    let options = |registry: Option<&'static jsonschema::Registry<'static>>| {
        let mut options = jsonschema::options()
            .with_draft(draft)
            .should_validate_formats(true)
            // networknt checks `uuid` in every draft; the jsonschema crate only from 2019-09.
            .with_format("uuid", is_uuid);
        if !remote_refs_allowed() {
            options = options.offline();
        }
        if let Some(registry) = registry {
            options = options.with_registry(registry);
        }
        options
    };
    // Allowed remote `$ref`s are fetched by a blocking GET while the validator is built, possibly from this same
    // server; offline builds never leave the process.
    let build = |options: jsonschema::ValidationOptions, schema: &Value| {
        if remote_refs_allowed() { crate::blocking::off_worker(|| options.build(schema)) } else { options.build(schema) }
    };
    // networknt evaluates the remote documents itself, read now as it preloads them
    if remote_refs_allowed() {
        crate::networknt::prefetch_remote(schema, crate::networknt::default_dialect(schema));
    }
    match build(options(None), schema) {
        Ok(v) => Ok(v),
        // The crate resolves only the meta-schema of the schema's own draft; networknt resolves all of them, so a
        // property that is a `$ref` to another draft's meta-schema goes through a registry of them all.
        Err(first) => match META_REGISTRY.as_ref() {
            Some(registry) => build(options(Some(registry)), &https_meta_refs(schema)).map_err(|_| first.to_string()),
            None => Err(first.to_string()),
        },
    }
}

/// `schema` with its `$ref`s to the `http://json-schema.org/draft/…` meta-schemas (2019-09 and later, identified by
/// their `https` address) moved to that address, as networknt maps them.
fn https_meta_refs(schema: &Value) -> Value {
    match schema {
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| match (k.as_str(), v) {
                    ("$ref", Value::String(s)) if s.starts_with("http://json-schema.org/draft/") => (k.clone(), Value::String(s.replacen("http://", "https://", 1))),
                    _ => (k.clone(), https_meta_refs(v)),
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(https_meta_refs).collect()),
        other => other.clone(),
    }
}

/// The bundled JSON Schema meta-schemas of drafts 4, 6, 7 and 2019-09 (with its vocabularies), vendored from the
/// `referencing` crate (MIT) in `metaschemas/`.
static META_REGISTRY: std::sync::LazyLock<Option<jsonschema::Registry<'static>>> = std::sync::LazyLock::new(|| {
    let doc = |text: &str| serde_json::from_str::<Value>(text).expect("vendored meta-schema");
    let draft_2019 = include_str!("metaschemas/2019-09/schema.json");
    let pairs = [
        ("http://json-schema.org/draft-04/schema", include_str!("metaschemas/draft4.json")),
        ("http://json-schema.org/draft-06/schema", include_str!("metaschemas/draft6.json")),
        ("http://json-schema.org/draft-07/schema", include_str!("metaschemas/draft7.json")),
        ("https://json-schema.org/draft/2019-09/schema", draft_2019),
        ("https://json-schema.org/draft/2019-09/meta/core", include_str!("metaschemas/2019-09/core.json")),
        ("https://json-schema.org/draft/2019-09/meta/applicator", include_str!("metaschemas/2019-09/applicator.json")),
        ("https://json-schema.org/draft/2019-09/meta/validation", include_str!("metaschemas/2019-09/validation.json")),
        ("https://json-schema.org/draft/2019-09/meta/meta-data", include_str!("metaschemas/2019-09/meta-data.json")),
        ("https://json-schema.org/draft/2019-09/meta/format", include_str!("metaschemas/2019-09/format.json")),
        ("https://json-schema.org/draft/2019-09/meta/content", include_str!("metaschemas/2019-09/content.json")),
    ];
    jsonschema::Registry::new()
        .extend(pairs.into_iter().map(|(uri, text)| (uri, jsonschema::Resource::from_contents(doc(text)))))
        .ok()?
        .prepare()
        .ok()
});

fn is_uuid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(g, n)| g.len() == n && g.chars().all(|c| c.is_ascii_hexdigit()))
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Ge,
    Le,
    Eq,
    Gt,
    Lt,
}

#[derive(Debug)]
pub struct StringMatcher {
    pub value: String,
    pub not: bool,
    pub optional: bool,
    kind: Kind,
    /// Built by a control-plane `RegexStringMatcher` that then matches on the data plane (an OpenAPI operation's
    /// method and path): the request's value read as a regex also matches ("matched -> matcher").
    reverse: bool,
}

const REGEX_META: &[char] = &['.', '*', '+', '?', '[', ']', '(', ')', '{', '}', '|', '^', '$', '\\'];

impl StringMatcher {
    /// From a canonical `stringOrJsonSchema` value (`"!x"`, `"?x"`, `"x"` or `{"schema": …}`).
    pub fn compile(v: &Value) -> StringMatcher {
        // `NottableDateTimeString`: its value is its description (`describe`), used to print and compare it.
        if let Value::Object(o) = v
            && let Some(read) = crate::model::DateTimeValue::read(o)
        {
            let not = o.get("not").and_then(Value::as_bool).unwrap_or(false);
            let (value, comparison) = match read {
                Ok(date_time) => (date_time.describe(), date_time.comparison().ok().map(Box::new)),
                Err(_) => (String::new(), None),
            };
            let written = crate::model::NString::from_json(v).map_or_else(|| v.clone(), |n| n.to_json());
            return StringMatcher { value, not, optional: false, kind: Kind::DateTime(comparison, written), reverse: false };
        }
        match v {
            Value::Object(o) if o.contains_key("schema") => {
                let not = o.get("not").and_then(Value::as_bool).unwrap_or(false);
                let optional = o.get("optional").and_then(Value::as_bool).unwrap_or(false);
                let schema = &o["schema"];
                let kind = Kind::Schema(Box::new(Schema {
                    validator: validator(schema).ok(),
                    schema: schema.clone(),
                    type_: schema.get("type").and_then(Value::as_str).map(str::to_string),
                    nullable: schema.get("nullable").is_some_and(|n| n == true || n == "true"),
                    printed: crate::json::pretty(schema),
                }));
                StringMatcher { value: String::new(), not, optional, kind, reverse: false }
            }
            // The object form takes its value verbatim (a value that itself starts with `!` or `?`).
            Value::Object(o) => {
                let value = o.get("value").and_then(Value::as_str).unwrap_or_default();
                let flag = |k: &str| o.get(k).and_then(Value::as_bool).unwrap_or(false);
                StringMatcher { value: value.to_string(), not: flag("not"), optional: flag("optional"), kind: Self::kind_of(value), reverse: false }
            }
            Value::String(s) => StringMatcher::from_text(s),
            Value::Null => StringMatcher::from_text(""),
            other => StringMatcher::from_text(&other.to_string()),
        }
    }

    pub fn from_text(s: &str) -> StringMatcher {
        let mut rest = s;
        let mut not = false;
        let mut optional = false;
        loop {
            if let Some(r) = rest.strip_prefix('?') {
                if r.is_empty() {
                    break;
                }
                optional = true;
                rest = r;
            } else if let Some(r) = rest.strip_prefix('!') {
                if r.is_empty() {
                    break;
                }
                not = true;
                rest = r;
            } else {
                break;
            }
        }
        StringMatcher { value: rest.to_string(), not, optional, kind: Self::kind_of(rest), reverse: false }
    }

    /// `BinaryHeaderValueNormalizer.normalize`: the matcher for the value without its base64 padding, when the value
    /// is padded base64 (and not a schema).
    pub fn without_base64_padding(&self) -> Option<StringMatcher> {
        if self.is_matcher_string() {
            return None;
        }
        let stripped = strip_base64_padding(&self.value)?;
        Some(StringMatcher { value: stripped.to_string(), not: self.not, optional: self.optional, kind: Self::kind_of(stripped), reverse: self.reverse })
    }

    /// This matcher as a control-plane `RegexStringMatcher` matches on the data plane: the reversed regex step
    /// matches instead of only logging `would match`.
    pub fn reversed(mut self) -> StringMatcher {
        self.reverse = true;
        self
    }

    /// A value that is never treated as `!`/`?`-prefixed (bodies).
    pub fn literal_or_regex(s: &str) -> StringMatcher {
        StringMatcher { value: s.to_string(), not: false, optional: false, kind: Self::kind_of(s), reverse: false }
    }

    /// A `RegexStringMatcher` built with its matcher (`numericComparison` false: a REGEX body, a JsonUnit regex
    /// placeholder): a numeric comparison or `accept:` directive is an ordinary literal or regex there.
    pub fn fixed_value(s: &str) -> StringMatcher {
        let kind = match Self::kind_of(s) {
            Kind::Numeric { .. } | Kind::Accept(_) => Self::kind_of_pattern(s),
            kind => kind,
        };
        StringMatcher { value: s.to_string(), not: false, optional: false, kind, reverse: false }
    }

    fn kind_of(s: &str) -> Kind {
        if s.trim().is_empty() {
            return Kind::Blank;
        }
        if let Some((op, operand)) = numeric(s) {
            return Kind::Numeric { op, operand };
        }
        if let Some(directive) = accept_directive(s) {
            return Kind::Accept(media_type(directive));
        }
        Self::kind_of_pattern(s)
    }

    fn kind_of_pattern(s: &str) -> Kind {
        // A non-ASCII value without metacharacters still goes through `Pattern` (`isPureAsciiLiteral`), whose
        // `UNICODE_CASE` folding (`É` for `é`) the ASCII comparison lacks.
        if is_pure_ascii_literal(s) {
            return Kind::Literal;
        }
        let (java_sensitive, java_insensitive) = (Program::compile(s, java_flags(false)), Program::compile(s, java_flags(true)));
        let java = (java_sensitive.is_some() || java_insensitive.is_some())
            .then(|| Box::new(JavaReplay { sensitive: java_sensitive, insensitive: java_insensitive }));
        Kind::Regex { sensitive: java_pattern_for(s, false).ok(), insensitive: java_pattern_for(s, true).ok(), java }
    }

    /// Matched by comparing strings alone, with no regex that could time out.
    pub fn is_plain(&self) -> bool {
        matches!(self.kind, Kind::Literal | Kind::Blank) && !self.reverse
    }

    /// The lower-cased value when this matcher can only ever match that exact string (case-insensitively).
    pub fn literal_key(&self) -> Option<String> {
        (matches!(self.kind, Kind::Literal) && !self.not && !self.optional).then(|| self.value.to_ascii_lowercase())
    }

    /// `NottableString.toString()`: the value with its `!` / `?` marker.
    /// `NottableString.toString()`: the value with its `!`/`?` marker; a schema's JSON text for a schema
    /// (`NottableSchemaString`).
    pub fn printed(&self) -> String {
        // `NottableString.serialise`: the optional mark, then the not mark (`?!key`)
        format!("{}{}{}", if self.optional { "?" } else { "" }, if self.not { "!" } else { "" }, self.raw_value())
    }

    pub fn is_blank(&self) -> bool {
        matches!(self.kind, Kind::Blank)
    }

    /// Match before negation.
    pub fn matches_positive(&self, actual: &str, case_insensitive: bool) -> bool {
        match &self.kind {
            Kind::Blank => true,
            Kind::Numeric { op, operand } => match actual.trim().parse::<f64>() {
                Ok(a) => match op {
                    Op::Ge => a >= *operand,
                    Op::Le => a <= *operand,
                    Op::Eq => a == *operand,
                    Op::Gt => a > *operand,
                    Op::Lt => a < *operand,
                },
                Err(_) => false,
            },
            Kind::Accept(desired) => desired.as_ref().is_some_and(|d| acceptable(d, actual)),
            Kind::Literal => {
                actual == self.value
                    || (case_insensitive && actual.eq_ignore_ascii_case(&self.value))
                    || ((self.reverse || CONTROL_PLANE.with(Cell::get)) && reversed_matches(&self.value, actual, !case_insensitive))
            }
            Kind::Regex { sensitive, insensitive, java } => {
                if actual == self.value || (case_insensitive && actual.eq_ignore_ascii_case(&self.value)) {
                    return true;
                }
                let regex = if case_insensitive { insensitive } else { sensitive };
                let linear = || regex.as_ref().is_some_and(|r| r.matches(actual));
                let program = java.as_ref().and_then(|j| if case_insensitive { j.insensitive.as_ref() } else { j.sensitive.as_ref() });
                within_java_budget(program, &self.value, || self.printed(), false, actual, case_insensitive, linear)
                    || ((self.reverse || CONTROL_PLANE.with(Cell::get)) && reversed_matches(&self.value, actual, !case_insensitive))
            }
            Kind::Schema(schema) => schema.errors(actual).is_empty(),
            // `NottableDateTimeString.matches` applies its own negation, and a value that is not a date-time never
            // matches, negated or not: before negation that is a result equal to `not`.
            Kind::DateTime(comparison, _) => match comparison.as_ref().and_then(|c| c.compare(actual)) {
                Some(result) => result,
                None => self.not,
            },
        }
    }

    /// Whether `actual` cannot be read as a date-time by this date-time matcher.
    pub fn not_a_date_time(&self, actual: &str) -> bool {
        matches!(&self.kind, Kind::DateTime(c, _) if c.as_ref().and_then(|c| c.compare(actual)).is_none())
    }

    /// A date-time matcher as `NottableStringSerializer` writes it (the object form).
    pub fn date_time_json(&self) -> Option<&Value> {
        match &self.kind {
            Kind::DateTime(_, written) => Some(written),
            _ => None,
        }
    }

    /// A `NottableMatcherString`: a JSON schema or a date-time comparison, which decides a match itself.
    pub fn is_matcher_string(&self) -> bool {
        matches!(self.kind, Kind::Schema(_) | Kind::DateTime(..))
    }

    pub fn matches(&self, actual: &str, case_insensitive: bool) -> bool {
        self.matches_positive(actual, case_insensitive) != self.not
    }

    /// [`StringMatcher::matches`] for a control-plane filter, where the other side may itself be a regex
    /// (`RegexStringMatcher`: "matched -> matcher (control plane only)"): it also matches when `actual`, read as a
    /// regex, matches this matcher's value.
    pub fn matches_control_plane(&self, actual: &str) -> bool {
        let reverse = || {
            matches!(self.kind, Kind::Literal | Kind::Regex { .. })
                && actual.chars().any(|c| !c.is_ascii() || "\\^$.|?*+()[]{}".contains(c))
                && java_pattern_for(actual, true).is_ok_and(|r| {
                    let linear = || r.matches(&self.value);
                    within_java_budget(Program::compile(actual, java_flags(true)).as_ref(), actual, || actual.to_string(), true, &self.value, true, linear)
                })
        };
        (self.matches_positive(actual, true) || reverse()) != self.not
    }

    /// `RegexStringMatcher.matches(matcher, matched)` where `matched` is itself a `NottableString` (another request
    /// definition's value, which may be negated or a schema), before this matcher's own `RegexStringMatcher.not`.
    /// Two schemas, or a schema on the matched side, only ever match on the control plane.
    pub fn matches_nottable(&self, matched: &StringMatcher, control_plane: bool) -> bool {
        match (self.is_matcher_string().then_some(()), matched.is_matcher_string().then_some(())) {
            (Some(_), Some(_)) => control_plane && self.matches_by_notted_strings(matched, control_plane),
            // `matchesBySchemas(schema, string)`: the schema's verdict (its own `not` included) against the value.
            (Some(_), None) => matched.not != self.matches(&matched.value, true),
            (None, Some(_)) => control_plane && (self.not != matched.matches(&self.value, true)),
            (None, None) => self.matches_by_notted_strings(matched, control_plane),
        }
    }

    fn matches_by_notted_strings(&self, matched: &StringMatcher, control_plane: bool) -> bool {
        if self.not && matched.not {
            // mutual notted control plane match
            self.matches_by_strings(matched, control_plane)
        } else {
            (self.not || matched.not) ^ self.matches_by_strings(matched, control_plane)
        }
    }

    /// The value `NottableString.getValue()` holds: a schema's JSON text for a schema.
    pub(crate) fn raw_value(&self) -> &str {
        self.schema().map_or(self.value.as_str(), |s| s.printed.as_str())
    }

    /// `RegexStringMatcher.matchesByStrings`: blank, numeric, `accept:`, equality, the matcher as a regex over the
    /// matched value, then (control plane only) the matched value as a regex over the matcher's.
    fn matches_by_strings(&self, matched: &StringMatcher, control_plane: bool) -> bool {
        let (expected, actual) = (self.raw_value(), matched.raw_value());
        if expected.trim().is_empty() {
            return true;
        }
        match &self.kind {
            Kind::Numeric { .. } | Kind::Accept(_) => return self.matches_positive(actual, true),
            Kind::Schema(_) | Kind::DateTime(..) => return actual == expected || actual.eq_ignore_ascii_case(expected),
            _ => {}
        }
        if self.matches_positive(actual, true) {
            return true;
        }
        control_plane && !is_pure_ascii_literal(actual) && {
            java_pattern_for(actual, true).is_ok_and(|r| {
                let linear = || r.matches(expected);
                within_java_budget(Program::compile(actual, java_flags(true)).as_ref(), actual, || matched.printed(), true, expected, true, linear)
            })
        }
    }

    pub fn comparison(&self) -> Comparison {
        match self.kind {
            Kind::Numeric { .. } => Comparison::Numeric,
            Kind::Accept(_) => Comparison::Accept,
            Kind::Schema(_) => Comparison::Schema,
            Kind::DateTime(..) => Comparison::DateTime,
            _ => Comparison::String,
        }
    }

    pub fn schema(&self) -> Option<&Schema> {
        match &self.kind {
            Kind::Schema(s) => Some(s),
            _ => None,
        }
    }
}

impl Schema {
    /// The JSON text validated for a value (`NottableSchemaString.matches`): quoted for a `string` schema, and for
    /// an untyped one when it is not JSON; other typed values are validated as written.
    pub fn instance_text(&self, actual: &str) -> String {
        if actual.trim().is_empty() || actual.starts_with('"') || actual.ends_with('"') {
            return actual.to_string();
        }
        match self.type_.as_deref() {
            Some("string") => format!("\"{actual}\""),
            None if serde_json::from_str::<Value>(actual).is_err() => format!("\"{actual}\""),
            _ => actual.to_string(),
        }
    }

    /// Why a value fails the schema, empty when it passes (`NottableSchemaString.validate`).
    pub fn errors(&self, actual: &str) -> String {
        self.errors_of_text(&self.instance_text(actual))
    }

    pub fn errors_of_text(&self, text: &str) -> String {
        if text.trim().is_empty() {
            return if self.nullable { String::new() } else { "found blank value and value was not nullable".into() };
        }
        match serde_json::from_str::<Value>(text) {
            Ok(instance) => crate::schema::value_report(self.validator.as_ref(), &self.schema, &instance),
            Err(_) => jackson_parse_error(text),
        }
    }

    pub fn is_valid(&self, instance: &Value) -> bool {
        crate::schema::value_matches(self.validator.as_ref(), &self.schema, instance)
    }
}

/// One `matcher{}would match{}if matcher was used for control plane` DEBUG entry of a data-plane
/// `RegexStringMatcher`: the matcher as printed (`NottableString.toString()`) and the request's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WouldMatch {
    pub matcher: String,
    pub matched: String,
}

/// One entry a data-plane match writes while it evaluates, in the order it writes them: a `would match` DEBUG entry,
/// or the TRACE entry `MatchDifference.addDifference(mockServerLogger, …)` writes for each difference it records,
/// as its message (`formatLogMessage` at indent 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchNote {
    WouldMatch(WouldMatch),
    Difference(String),
}

thread_local! {
    /// The [`MatchNote`]s of the comparisons made while [`collecting_would_match`] runs on this thread.
    static WOULD_MATCH: std::cell::RefCell<Option<Vec<MatchNote>>> = const { std::cell::RefCell::new(None) };
}

/// Runs `f` (synchronous) and returns what its data-plane string comparisons would have logged as
/// `would match`, with the differences noted by [`note_differences`]. Nested calls collect into the
/// outermost.
pub(crate) fn collecting_would_match<R>(f: impl FnOnce() -> R) -> (R, Vec<MatchNote>) {
    let outermost = WOULD_MATCH.with(|w| {
        let mut w = w.borrow_mut();
        let outermost = w.is_none();
        if outermost {
            *w = Some(Vec::new());
        }
        outermost
    });
    let result = f();
    let collected = if outermost { WOULD_MATCH.with(|w| w.borrow_mut().take()).unwrap_or_default() } else { Vec::new() };
    (result, collected)
}

/// Runs `f` with no [`collecting_would_match`] collecting: a re-evaluation whose notes were already taken.
pub(crate) fn not_collecting<R>(f: impl FnOnce() -> R) -> R {
    let suspended = WOULD_MATCH.with(|w| w.borrow_mut().take());
    let result = f();
    WOULD_MATCH.with(|w| *w.borrow_mut() = suspended);
    result
}

/// Notes recorded differences (each as `MatchDifference` keeps it, `formatLogMessage` at indent 1) for
/// [`collecting_would_match`], when one is running, as their TRACE entries' messages.
pub(crate) fn note_differences(texts: &[String]) {
    WOULD_MATCH.with(|w| {
        if let Some(w) = w.borrow_mut().as_mut() {
            w.extend(texts.iter().filter(|t| !t.is_empty()).map(|t| MatchNote::Difference(unindented(t))));
        }
    });
}

/// `formatLogMessage(1, …)`'s text as `formatLogMessage(0, …)` writes it: indent 1 prefixes each non-empty line with
/// two spaces.
pub(crate) fn unindented(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(line.strip_prefix("  ").unwrap_or(line));
    }
    out
}

/// Notes `matcher` against `matched` for [`collecting_would_match`], when one is running.
pub(crate) fn note_would_match(matcher: &StringMatcher, matched: &str, case_sensitive: bool) {
    if WOULD_MATCH.with(|w| w.borrow().is_none()) {
        return;
    }
    if matches!(matcher.kind, Kind::Literal | Kind::Regex { .. }) && !matcher.matches_positive(matched, !case_sensitive) {
        note_reversed(&matcher.printed(), &matcher.value, matched, case_sensitive);
    }
}

/// [`note_would_match`] for a matcher value that equality and the forward regex already failed:
/// `RegexStringMatcher.matchesByStrings`' "matched -> matcher" step, which on the data plane only logs.
pub(crate) fn note_reversed(printed: &str, value: &str, matched: &str, case_sensitive: bool) {
    if WOULD_MATCH.with(|w| w.borrow().is_none()) || value.trim().is_empty() {
        return;
    }
    if reversed_matches(value, matched, case_sensitive) {
        WOULD_MATCH.with(|w| {
            if let Some(w) = w.borrow_mut().as_mut() {
                w.push(MatchNote::WouldMatch(WouldMatch { matcher: printed.to_string(), matched: matched.to_string() }));
            }
        });
    }
}

/// `RegexStringMatcher.matchesByStrings`' "matched -> matcher" step: `matched`, unless a pure-ASCII literal, read
/// as a regex over the matcher's `value`.
fn reversed_matches(value: &str, matched: &str, case_sensitive: bool) -> bool {
    if is_pure_ascii_literal(matched) {
        return false;
    }
    java_pattern_for(matched, !case_sensitive).is_ok_and(|r| {
        let linear = || r.matches(value);
        within_java_budget(Program::compile(matched, java_flags(!case_sensitive)).as_ref(), matched, || matched.to_string(), true, value, !case_sensitive, linear)
    })
}

/// `NottableString.matches`' pattern: `Pattern.compile(value, DOTALL)`, with `CASE_INSENSITIVE | UNICODE_CASE` unless
/// matching is case-sensitive (`matchExactCase`).
fn java_pattern_for(value: &str, case_insensitive: bool) -> Result<Arc<JavaRegex>, PatternSyntaxException> {
    compile_with_flags(value, java_flags(case_insensitive))
}

/// `NottableString.matches`' flags: `DOTALL`, with `CASE_INSENSITIVE | UNICODE_CASE` unless case-sensitive.
fn java_flags(case_insensitive: bool) -> u32 {
    use super::java_pattern::{CASE_INSENSITIVE, DOTALL, UNICODE_CASE};
    if case_insensitive { DOTALL | CASE_INSENSITIVE | UNICODE_CASE } else { DOTALL }
}

/// The replay programs of a regex matcher's two case modes ([`Program::compile`]); either may be absent.
#[derive(Debug)]
struct JavaReplay {
    sensitive: Option<Program>,
    insensitive: Option<Program>,
}

/// `RegexStringMatcher.runRegexWithTimeout`'s `regex evaluation timed out` WARN: the budget in milliseconds and the
/// pattern as printed (`NottableString.toString()`). `sensitive`: the pattern is the request's value read as a regex
/// (the "matched -> matcher" step), a `SensitiveLogValue` (upstream c76143e4a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegexTimeout {
    pub millis: i64,
    pub pattern: String,
    pub sensitive: bool,
    /// `MatchingTimeoutExecutor.matchesWithRegexTimeout`'s label (`graphql operationName`, `json-rpc method`), which
    /// prefixes the WARN; `None` for `RegexStringMatcher`'s own.
    pub description: Option<&'static str>,
    /// Not a timeout: `JsonSchemaValidator.isValid`'s ERROR `exception validating JSON` for a schema that threw while
    /// it evaluated (an unresolvable reference, a remote document that did not load), met and logged
    /// in the same places; `pattern` is the report.
    pub thrown: bool,
}

/// `ConfigurationProperties.regexMatchingTimeoutMillis()`'s default, for evaluations outside [`regex_timeouts`].
const DEFAULT_REGEX_TIMEOUT_MILLIS: i64 = 5000;

struct RegexScope {
    millis: i64,
    /// Report every evaluation that times out, not each (pattern, input) once: the control plane's filters evaluate
    /// each recorded entry once, and upstream logs one WARN per evaluation.
    each: bool,
    timeouts: Vec<RegexTimeout>,
    /// The (pattern, input) pairs already reported, so the re-evaluations within one scope report once.
    seen: std::collections::HashSet<(String, String)>,
}

thread_local! {
    static REGEX_SCOPE: std::cell::RefCell<Option<RegexScope>> = const { std::cell::RefCell::new(None) };
}

/// Runs `f` (synchronous) with `regexMatchingTimeoutMillis` = `millis` (0 or less: no timeout) and returns the
/// regex timeouts its comparisons met, each (pattern, input) once. A nested call collects on its own.
pub(crate) fn regex_timeouts<R>(millis: i64, f: impl FnOnce() -> R) -> (R, Vec<RegexTimeout>) {
    scoped(RegexScope { millis, each: false, timeouts: Vec::new(), seen: Default::default() }, f)
}

/// [`regex_timeouts`], reporting every evaluation that times out (the control plane's filters); the
/// timeouts met so far are taken with [`take_regex_timeouts`], so they can be logged before the next entry.
pub(crate) fn regex_timeouts_each<R>(millis: i64, f: impl FnOnce() -> R) -> (R, Vec<RegexTimeout>) {
    scoped(RegexScope { millis, each: true, timeouts: Vec::new(), seen: Default::default() }, f)
}

fn scoped<R>(scope: RegexScope, f: impl FnOnce() -> R) -> (R, Vec<RegexTimeout>) {
    let outer = REGEX_SCOPE.with(|s| s.borrow_mut().replace(scope));
    let result = f();
    let scope = REGEX_SCOPE.with(|s| std::mem::replace(&mut *s.borrow_mut(), outer));
    (result, scope.map(|s| s.timeouts).unwrap_or_default())
}

/// Notes that a user schema threw evaluating `instance` (`report` is what `isValid` answers): once per scope and
/// (report, instance), as a re-evaluation within one scope meets it again.
pub(crate) fn note_schema_exception(report: &str, instance: &str) {
    REGEX_SCOPE.with(|s| {
        if let Some(scope) = s.borrow_mut().as_mut()
            && (scope.each || scope.seen.insert((format!("\u{0}schema\u{0}{report}"), instance.to_string())))
        {
            scope.timeouts.push(RegexTimeout { millis: 0, pattern: report.to_string(), sensitive: false, description: None, thrown: true });
        }
    });
}

/// Runs `f`, a re-evaluation of what was just evaluated in the current scope, with the current timeout budget but
/// without reporting the timeouts it meets: upstream evaluates once, logging each timeout once.
pub(crate) fn unreported_regex_timeouts<R>(f: impl FnOnce() -> R) -> R {
    let current = REGEX_SCOPE.with(|s| s.borrow().as_ref().map(|s| (s.millis, s.each)));
    match current {
        Some((millis, each)) => scoped(RegexScope { millis, each, timeouts: Vec::new(), seen: Default::default() }, f).0,
        None => f(),
    }
}

/// The timeouts the current scope has met since it began or since the last call.
pub(crate) fn take_regex_timeouts() -> Vec<RegexTimeout> {
    REGEX_SCOPE.with(|s| s.borrow_mut().as_mut().map(|s| std::mem::take(&mut s.timeouts)).unwrap_or_default())
}

/// A (pattern, case-insensitive, input, budget) evaluation.
type TimedOut = (String, bool, String, i64);

/// Recent (pattern, case-insensitive, input, budget) evaluations that outlived their budget, so the re-evaluations
/// of one request (the scan, its log entries, the closest expectation, the hint) cost the budget once.
static TIMED_OUT: std::sync::LazyLock<parking_lot::Mutex<std::collections::VecDeque<TimedOut>>> =
    std::sync::LazyLock::new(Default::default);
const TIMED_OUT_KEPT: usize = 32;

/// `runRegexWithTimeout`: Java's verdict from the replay of its backtracking over `input` (`program`; `None`: a shape
/// that cannot explode, left to `linear`, the linear engines' verdict); when it would outlive the budget, a non-match,
/// noted for [`regex_timeouts`]. `key` is the pattern's text, `sensitive` whether the pattern is the request's value.
/// `linear` runs only when the replay cannot decide (no budget, or too deep): the linear engines backtrack to their
/// step limit on the shapes the replay times out (~150 ms in a debug build, once per re-evaluation, which kept a
/// request with such a header for seconds), and also on some that Java finishes at once, such as
/// `(?=(a|aa)*c)` or `(.*a){25}+x` over forty `a`s (10 s and 32 s per evaluation on a loaded machine).
fn within_java_budget(program: Option<&Program>, key: &str, printed: impl FnOnce() -> String, sensitive: bool, input: &str, case_insensitive: bool, linear: impl FnOnce() -> bool) -> bool {
    within_java_budget_described(None, program, key, printed, sensitive, input, case_insensitive, linear)
}

#[allow(clippy::too_many_arguments)]
fn within_java_budget_described(
    description: Option<&'static str>,
    program: Option<&Program>,
    key: &str,
    printed: impl FnOnce() -> String,
    sensitive: bool,
    input: &str,
    case_insensitive: bool,
    linear: impl FnOnce() -> bool,
) -> bool {
    let Some(program) = program else { return linear() };
    match java_outcome(key, case_insensitive, input, |budget| program.run(input, budget)) {
        Some(Outcome::Finished(matched)) => return matched,
        None => return linear(),
        Some(Outcome::TimedOut) => {}
    }
    let millis = REGEX_SCOPE.with(|s| s.borrow().as_ref().map_or(DEFAULT_REGEX_TIMEOUT_MILLIS, |s| s.millis));
    let pattern = printed();
    REGEX_SCOPE.with(|s| {
        if let Some(scope) = s.borrow_mut().as_mut()
            && (scope.each || scope.seen.insert((pattern.clone(), input.to_string())))
        {
            scope.timeouts.push(RegexTimeout { millis, pattern, sensitive, description, thrown: false });
        }
    });
    false
}

/// What Java's backtracking (`replay` within a budget) over `input` comes to at the current budget: a timeout from
/// the cache of recent timeouts when it has the (`key`, case, input) at this budget or more; `None` without a budget
/// or when the replay is too deep to finish.
fn java_outcome(key: &str, case_insensitive: bool, input: &str, replay: impl FnOnce(Budget) -> Option<Outcome>) -> Option<Outcome> {
    let millis = REGEX_SCOPE.with(|s| s.borrow().as_ref().map_or(DEFAULT_REGEX_TIMEOUT_MILLIS, |s| s.millis));
    if millis <= 0 {
        return None;
    }
    if TIMED_OUT.lock().iter().any(|(p, ci, i, m)| p == key && *ci == case_insensitive && i == input && *m >= millis) {
        return Some(Outcome::TimedOut);
    }
    let outcome = replay(Budget::millis(millis as u64));
    if outcome == Some(Outcome::TimedOut) {
        let mut timed_out = TIMED_OUT.lock();
        if timed_out.len() >= TIMED_OUT_KEPT {
            timed_out.pop_front();
        }
        timed_out.push_back((key.to_string(), case_insensitive, input.to_string(), millis));
    }
    outcome
}

/// `LlmConversationMatcher`'s `latestMessageMatches`: `matchesWithRegexTimeout(null, …, () ->
/// Pattern.compile(pattern).matcher(input).find())`. Java's verdict from the replay of its search (`linear`, the linear
/// engines' verdict, when the replay cannot decide), unless it would outlive the budget; then a non-match. With a null `MockServerLogger` the timeout goes to SLF4J
/// only, so nothing is reported to [`regex_timeouts`] and no WARN entry is logged.
pub(crate) fn find_within_budget(pattern: &str, input: &str, linear: impl FnOnce() -> bool) -> bool {
    let Some(program) = Program::compile(pattern, 0) else { return linear() };
    match java_outcome(&format!("find:{pattern}"), false, input, |budget| program.run_find(input, budget)) {
        Some(Outcome::Finished(found)) => found,
        Some(Outcome::TimedOut) => false,
        None => linear(),
    }
}

/// A user regex evaluated through `MatchingTimeoutExecutor.matchesWithRegexTimeout` (`Pattern.compile(p)`, then
/// `matcher(input).matches()`): GraphQL's `operationName`, JSON-RPC's `method`. A timeout is a non-match, reported to
/// [`regex_timeouts`] with the site's `description`.
#[derive(Debug)]
pub(crate) struct DescribedRegex {
    description: &'static str,
    pattern: String,
    program: Option<Program>,
}

impl DescribedRegex {
    pub(crate) fn compile(description: &'static str, pattern: &str) -> DescribedRegex {
        DescribedRegex { description, pattern: pattern.to_string(), program: Program::compile(pattern, 0) }
    }

    /// `linear`, the linear engines' verdict over `input`, unless Java's backtracking would outlive the budget.
    pub(crate) fn within_budget(&self, input: &str, linear: impl FnOnce() -> bool) -> bool {
        within_java_budget_described(Some(self.description), self.program.as_ref(), &self.pattern, || self.pattern.clone(), false, input, false, linear)
    }
}

/// `RegexStringMatcher.isPureAsciiLiteral`: ASCII without any regex metacharacter, so it can only match itself.
fn is_pure_ascii_literal(s: &str) -> bool {
    s.is_ascii() && !s.contains(REGEX_META)
}

/// Jackson's `JsonParseException` for a value that is not JSON, as `JsonSchemaValidator.isValid` reports it.
pub(super) fn jackson_parse_error(text: &str) -> String {
    if let Some((index, found)) = lenient_unexpected_character(text) {
        let before: Vec<char> = text.chars().take(index).collect();
        let line = 1 + before.iter().filter(|c| **c == '\n').count();
        let column = before.iter().rev().take_while(|c| **c != '\n').count() + 1;
        return format!(
            "JsonParseException - Unexpected character ('{found}' (code {})): expected a valid value (JSON String, Number (or 'NaN'/'+INF'/'-INF'), Array, Object or token 'null', 'true' or 'false')\n at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: {line}, column: {column}]",
            found as u32
        );
    }
    // The lenient mapper allows non-numeric numbers, so Jackson names them; the location is the token's start
    // (oracle: `user_schema_reports`, "root-scalar").
    let leading = text.chars().take_while(|c| c.is_whitespace()).count();
    let before: Vec<char> = text.chars().take(leading).collect();
    let line = 1 + before.iter().filter(|c| **c == '\n').count();
    let column = before.iter().rev().take_while(|c| **c != '\n').count() + 1;
    let token: String = text.chars().skip(leading).take_while(|c| !c.is_whitespace() && !matches!(c, ',' | ']' | '}' | ':')).collect();
    format!(
        "JsonParseException - Unrecognized token '{token}': was expecting (JSON String, Number (or 'NaN'/'+INF'/'-INF'), Array, Object or token 'null', 'true' or 'false')\n at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: {line}, column: {column}]"
    )
}

/// The first character, as (index in characters, character), where the lenient mapper (unquoted field names, single
/// quotes, comments, missing array values) expects a value and finds one that cannot start it: Jackson's
/// "Unexpected character" failure. `None` when the text fails otherwise (an unrecognised token, the end of input) or
/// does not fail.
fn lenient_unexpected_character(text: &str) -> Option<(usize, char)> {
    struct Scan {
        s: Vec<char>,
        i: usize,
    }
    enum Stop {
        Char(usize, char),
        Other,
    }
    impl Scan {
        fn skip(&mut self) {
            while let Some(&c) = self.s.get(self.i) {
                let next = self.s.get(self.i + 1).copied();
                if c.is_whitespace() {
                    self.i += 1;
                } else if c == '#' || (c == '/' && next == Some('/')) {
                    while self.s.get(self.i).is_some_and(|c| *c != '\n') {
                        self.i += 1;
                    }
                } else if c == '/' && next == Some('*') {
                    self.i += 2;
                    while self.i < self.s.len() && !(self.s[self.i] == '*' && self.s.get(self.i + 1) == Some(&'/')) {
                        self.i += 1;
                    }
                    self.i += 2;
                } else {
                    break;
                }
            }
        }
        fn string(&mut self, quote: char) -> Result<(), Stop> {
            self.i += 1;
            while let Some(&c) = self.s.get(self.i) {
                self.i += 1;
                match c {
                    '\\' => self.i += 1,
                    c if c == quote => return Ok(()),
                    _ => {}
                }
            }
            Err(Stop::Other)
        }
        fn value(&mut self) -> Result<(), Stop> {
            self.skip();
            let Some(&c) = self.s.get(self.i) else { return Err(Stop::Other) };
            match c {
                '{' => {
                    self.i += 1;
                    loop {
                        self.skip();
                        match self.s.get(self.i) {
                            Some('}') => {
                                self.i += 1;
                                return Ok(());
                            }
                            Some('"') => self.string('"')?,
                            Some('\'') => self.string('\'')?,
                            Some(c) if c.is_alphanumeric() || matches!(c, '_' | '$') => {
                                while self.s.get(self.i).is_some_and(|c| c.is_alphanumeric() || matches!(c, '_' | '$' | '-' | '.')) {
                                    self.i += 1;
                                }
                            }
                            _ => return Err(Stop::Other),
                        }
                        self.skip();
                        if self.s.get(self.i) != Some(&':') {
                            return Err(Stop::Other);
                        }
                        self.i += 1;
                        self.value()?;
                        self.skip();
                        match self.s.get(self.i) {
                            Some(',') => self.i += 1,
                            Some('}') => {
                                self.i += 1;
                                return Ok(());
                            }
                            _ => return Err(Stop::Other),
                        }
                    }
                }
                '[' => {
                    self.i += 1;
                    loop {
                        self.skip();
                        match self.s.get(self.i) {
                            Some(']') => {
                                self.i += 1;
                                return Ok(());
                            }
                            Some(',') => {
                                self.i += 1;
                                continue;
                            }
                            _ => {}
                        }
                        self.value()?;
                        self.skip();
                        match self.s.get(self.i) {
                            Some(',') => self.i += 1,
                            Some(']') => {
                                self.i += 1;
                                return Ok(());
                            }
                            _ => return Err(Stop::Other),
                        }
                    }
                }
                '"' | '\'' => self.string(c),
                c if c.is_ascii_digit() || matches!(c, '-' | '+' | '.') => {
                    while self.s.get(self.i).is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '+' | '.')) {
                        self.i += 1;
                    }
                    Ok(())
                }
                c if c.is_alphabetic() => Err(Stop::Other),
                c => Err(Stop::Char(self.i, c)),
            }
        }
    }
    match (Scan { s: text.chars().collect(), i: 0 }).value() {
        Err(Stop::Char(index, found)) => Some((index, found)),
        _ => None,
    }
}

/// `AcceptHeaderMatcher.isAcceptDirective`: `accept:` (any case) followed by something not blank; the rest.
fn accept_directive(s: &str) -> Option<&str> {
    let rest = s.get(..7).filter(|p| p.eq_ignore_ascii_case("accept:")).map(|_| &s[7..])?;
    (!rest.trim().is_empty()).then_some(rest)
}

/// `AcceptHeaderMatcher.MediaType.parse`: `type/subtype` without parameters, lower-cased.
fn media_type(value: &str) -> Option<(String, String)> {
    let trimmed = value.trim();
    let trimmed = trimmed.split(';').next().unwrap_or_default().trim();
    let slash = trimmed.find('/')?;
    if slash == 0 || slash == trimmed.len() - 1 {
        return None;
    }
    let (t, st) = (trimmed[..slash].trim().to_lowercase(), trimmed[slash + 1..].trim().to_lowercase());
    (!t.is_empty() && !st.is_empty()).then_some((t, st))
}

/// `AcceptHeaderMatcher.matches`: the most specific range of the `Accept` value that covers `desired` (the higher
/// quality among equally specific ones) must have a positive quality.
fn acceptable(desired: &(String, String), accept: &str) -> bool {
    if accept.trim().is_empty() {
        return false;
    }
    let mut best: Option<(u8, f64)> = None;
    for element in accept.split(',') {
        let mut parts = element.trim().split(';');
        let Some((t, st)) = parts.next().and_then(|r| {
            let r = r.trim();
            let slash = r.find('/')?;
            if slash == 0 || slash == r.len() - 1 {
                return None;
            }
            let (t, st) = (r[..slash].trim().to_lowercase(), r[slash + 1..].trim().to_lowercase());
            (!t.is_empty() && !st.is_empty() && !(t == "*" && st != "*")).then_some((t, st))
        }) else {
            continue;
        };
        let mut quality = 1.0;
        for param in parts {
            let Some((name, value)) = param.trim().split_once('=').filter(|(n, _)| !n.is_empty()) else { continue };
            if name.trim().eq_ignore_ascii_case("q") {
                quality = value.trim().parse::<f64>().map(|q| q.clamp(0.0, 1.0)).unwrap_or(1.0);
                break;
            }
        }
        if !((t == "*" || t == desired.0) && (st == "*" || st == desired.1)) {
            continue;
        }
        let specificity = u8::from(t != "*") * 2 + u8::from(st != "*");
        if best.is_none_or(|(s, q)| specificity > s || (specificity == s && quality > q)) {
            best = Some((specificity, quality));
        }
    }
    best.is_some_and(|(_, q)| q > 0.0)
}

fn numeric(s: &str) -> Option<(Op, f64)> {
    let t = s.trim();
    let (op, rest) = [(">=", Op::Ge), ("<=", Op::Le), ("==", Op::Eq), (">", Op::Gt), ("<", Op::Lt)]
        .iter()
        .find_map(|(p, op)| t.strip_prefix(p).map(|r| (*op, r)))?;
    let rest = rest.trim();
    let valid = !rest.is_empty()
        && rest.trim_start_matches('-').split('.').count() <= 2
        && rest.trim_start_matches('-').split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    valid.then(|| rest.parse().ok()).flatten().map(|n| (op, n))
}

#[cfg(test)]
mod tests {
    use super::StringMatcher;

    #[test]
    fn catastrophic_regex_times_out_once_per_scope() {
        let m = StringMatcher::from_text("/(.*a){25}x");
        let input = format!("/{}b", "a".repeat(38));
        let (matched, timeouts) = super::regex_timeouts(100, || (m.matches(&input, false), m.matches(&input, false)));
        assert_eq!(matched, (false, false));
        assert_eq!(timeouts, vec![super::RegexTimeout { millis: 100, pattern: "/(.*a){25}x".into(), sensitive: false, description: None, thrown: false }]);
        // The second scope meets it from the cache, without spending the budget again.
        let started = std::time::Instant::now();
        let (matched, timeouts) = super::regex_timeouts(100, || m.matches(&input, false));
        assert!(!matched && timeouts.len() == 1 && started.elapsed() < std::time::Duration::from_millis(100));
        // A short value settles within the budget; no budget at all leaves the linear engine's verdict.
        assert_eq!(super::regex_timeouts(100, || m.matches("/ab", false)), (false, vec![]));
        assert_eq!(super::regex_timeouts(0, || m.matches(&input, false)), (false, vec![]));
        let normal = StringMatcher::from_text("/ok/(v[0-9]+)/.*");
        assert_eq!(super::regex_timeouts(100, || normal.matches("/ok/v1/items", false)), (true, vec![]));
    }

    /// A replay that finishes is Java's verdict, so the linear engines are not asked; over these values
    /// `java_pattern` backtracks to its step limit, which took 10 s and 32 s per evaluation on a loaded machine.
    #[test]
    fn a_finished_replay_is_the_verdict() {
        let linear = || -> bool { panic!("the linear engines ran") };
        for (pattern, input, expected) in [
            ("/y(?=(a|aa)*c)", format!("/y{}", "a".repeat(39)), false),
            ("/u(.*a){25}+x", format!("/u{}b", "a".repeat(38)), false),
            ("/y(?=(a|aa)*c).*", format!("/y{}c", "a".repeat(39)), true),
        ] {
            let program = super::Program::compile(pattern, super::java_flags(true)).unwrap();
            let verdict = super::regex_timeouts(300, || super::within_java_budget(Some(&program), pattern, || pattern.to_string(), false, &input, true, linear));
            assert_eq!(verdict, (expected, vec![]), "{pattern}");
        }
    }

    #[test]
    fn equality_regex_and_case() {
        let m = StringMatcher::from_text("/users/[0-9]+");
        assert!(m.matches("/users/42", true));
        assert!(!m.matches("/users/42/x", true), "regex is anchored");
        assert!(StringMatcher::from_text("abc").matches("ABC", true));
        assert!(!StringMatcher::from_text("abc").matches("ABC", false));
        assert!(StringMatcher::from_text("a.c").matches("A\nC".replace('\n', "x").as_str(), true));
    }

    #[test]
    fn negation_optional_and_numeric() {
        assert!(StringMatcher::from_text("!bad").matches("good", true));
        assert!(!StringMatcher::from_text("!bad").matches("bad", true));
        let opt = StringMatcher::from_text("?X-Opt");
        assert!(opt.optional && opt.value == "X-Opt");
        assert!(StringMatcher::from_text(">=10").matches("12", true));
        assert!(!StringMatcher::from_text(">=10").matches("3", true));
        assert!(!StringMatcher::from_text(">=10").matches("x", true));
    }

    #[test]
    fn nottable_matched_values() {
        let m = |s: &str| StringMatcher::from_text(s);
        let schema = |p: &str| StringMatcher::compile(&serde_json::json!({"schema": {"type": "string", "pattern": p}}));
        // A regex on the matched side matches on the control plane only.
        assert!(m("someKey").matches_nottable(&m("someK[a-z]{2}"), true));
        assert!(!m("someKey").matches_nottable(&m("someK[a-z]{2}"), false));
        // A schema on the matched side validates the matcher's value, on the control plane only.
        assert!(m("someValue").matches_nottable(&schema("^someV[a-z]{4}$"), true));
        assert!(!m("GET").matches_nottable(&schema("^P.{2,3}$"), true));
        assert!(!m("someValue").matches_nottable(&schema("^someV[a-z]{4}$"), false));
        assert!(schema("^P.{2,3}$").matches_nottable(&m("PUT"), false));
        // Two schemas match when they are the same schema.
        assert!(schema("^a$").matches_nottable(&schema("^a$"), true));
        assert!(!schema("^a$").matches_nottable(&schema("^b$"), true));
        // Negation on either side inverts; on both it cancels.
        assert!(m("GET").matches_nottable(&m("!POST"), true));
        assert!(!m("GET").matches_nottable(&m("!GET"), true));
        assert!(m("!GET").matches_nottable(&m("!GET"), true));
    }

    #[test]
    fn schema_values() {
        let m = StringMatcher::compile(&serde_json::json!({"schema": {"type": "integer", "minimum": 5}}));
        assert!(m.matches("7", true));
        assert!(!m.matches("2", true));
        assert!(!m.matches("x", true));
    }

    /// `JsonSchemaValidatorRemoteRefTest.shouldExposeRemoteRefsBlockedByDefault`: no wire form (it
    /// asserts a static getter directly), ported as a plain assertion of the same default.
    #[test]
    fn remote_refs_denied_by_default() {
        assert!(!super::remote_refs_allowed());
        assert!(!crate::state::State::new(crate::Config::for_tests(), vec![0]).json_schema_allow_remote_refs());
    }

    /// `shouldBlockRemoteRefByDefaultWithoutNetworkFetch`: building a validator for a schema with a
    /// remote `$ref` under the deny policy fails fast (no network fetch attempted — `.offline()` refuses before
    /// any I/O) rather than resolving it.
    #[test]
    fn remote_ref_rejected_when_denied() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {"value": {"$ref": "http://192.0.2.1/external-schema.json"}},
            "required": ["value"],
        });
        let start = std::time::Instant::now();
        let result = super::with_remote_refs_policy(false, || super::validator(&schema));
        assert!(result.is_err(), "a blocked remote $ref must fail to build, not silently ignore the reference");
        assert!(start.elapsed() < std::time::Duration::from_secs(1), "must fail immediately, never attempt a network fetch");
    }

    /// `shouldAllowRemoteRefsWhenSystemPropertyOptIn`: the opt-in half only asserts the config flag
    /// and that internal refs still validate — this additionally proves the retriever itself actually switches
    /// (resolving a local file, never a real network fetch, so the test stays offline like upstream's).
    #[test]
    fn remote_ref_resolved_when_allowed() {
        let path = std::env::temp_dir().join(format!("mock-server-remote-ref-{}.json", std::process::id()));
        std::fs::write(&path, br#"{"type": "integer", "minimum": 1}"#).expect("write temp schema");
        let uri = format!("file://{}", path.display());
        let schema = serde_json::json!({"type": "object", "properties": {"value": {"$ref": uri}}, "required": ["value"]});
        // Denied: the same schema fails to build, exactly as the default-deny case above.
        assert!(super::with_remote_refs_policy(false, || super::validator(&schema)).is_err());
        // Allowed: the file `$ref` resolves and the compiled validator enforces it.
        let validator = super::with_remote_refs_policy(true, || super::validator(&schema)).expect("file ref resolves when allowed");
        assert!(validator.is_valid(&serde_json::json!({"value": 3})));
        assert!(!validator.is_valid(&serde_json::json!({"value": 0})));
        let _ = std::fs::remove_file(&path);
    }

    /// Nested policy scopes restore the outer value (an OpenAPI expectation's per-operation
    /// alternatives recompile inside one outer `RequestMatcher::compile` call).
    #[test]
    fn remote_refs_policy_nests_and_restores() {
        assert!(!super::remote_refs_allowed());
        super::with_remote_refs_policy(true, || {
            assert!(super::remote_refs_allowed());
            super::with_remote_refs_policy(false, || assert!(!super::remote_refs_allowed()));
            assert!(super::remote_refs_allowed(), "the inner scope must not leak past its own call");
        });
        assert!(!super::remote_refs_allowed());
    }

    /// The scanner finds a blocked scheme under nesting, ignores internal refs, and exempts the two
    /// meta-schema URLs the validator resolves from its own bundled copy.
    #[test]
    fn blocked_remote_ref_scan() {
        let internal = serde_json::json!({"type": "object", "properties": {"a": {"$ref": "#/definitions/x"}}});
        assert_eq!(super::blocked_remote_ref(&internal), None);
        let nested = serde_json::json!({"type": "object", "properties": {"a": {"type": "object", "properties": {"b": {"$ref": "https://evil.example/s.json"}}}}});
        assert_eq!(super::blocked_remote_ref(&nested).as_deref(), Some("https://evil.example/s.json"));
        let meta = serde_json::json!({"$ref": "http://json-schema.org/draft-07/schema#"});
        assert_eq!(super::blocked_remote_ref(&meta), None);
        let file_ref = serde_json::json!({"$ref": "file:///etc/passwd"});
        assert_eq!(super::blocked_remote_ref(&file_ref).as_deref(), Some("file:///etc/passwd"));
    }
}


/// `stripPaddingIfPaddedBase64`: one or two `=` closing a whole number of base64 quads.
pub fn strip_base64_padding(raw: &str) -> Option<&str> {
    let end = raw.trim_end_matches('=').len();
    let padding = raw.len() - end;
    let alphabet = |c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/';
    ((1..=2).contains(&padding) && end > 0 && raw.len().is_multiple_of(4) && raw[..end].chars().all(alphabet)).then(|| &raw[..end])
}

#[cfg(test)]
mod nested_meta_schema_tests {
    use serde_json::json;

    // JsonSchemaValidatorTest's nested cases, a property that is a `$ref` to a draft meta-schema
    #[test]
    fn a_property_may_refer_to_a_bundled_meta_schema() {
        for reference in ["http://json-schema.org/draft-04/schema", "http://json-schema.org/draft/2019-09/schema", "http://json-schema.org/draft-07/schema"] {
            let schema = json!({"$schema": "http://json-schema.org/draft-04/schema#", "type": "object", "properties": {"schema": {"$ref": reference}}});
            let built = super::validator(&schema);
            assert!(built.is_ok(), "{reference}: {:?}", built.err());
        }
    }

    #[test]
    fn a_meta_schema_ref_builds_under_any_root_draft() {
        for root in [None, Some("http://json-schema.org/draft-07/schema#"), Some("http://json-schema.org/draft-04/schema#")] {
            for reference in ["http://json-schema.org/draft-04/schema", "http://json-schema.org/draft-04/schema#", "http://json-schema.org/draft/2019-09/schema", "http://json-schema.org/draft-06/schema"] {
                let mut schema = json!({"type": "object", "properties": {"schema": {"$ref": reference}}});
                if let Some(root) = root {
                    schema["$schema"] = json!(root);
                }
                assert!(super::validator(&schema).is_ok(), "{root:?} {reference}");
            }
        }
    }

    #[test]
    fn harvested_nested_schemas_build() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/scenarios/upstream/B4-schemaval-JsonSchemaValidatorTest.json")).unwrap();
        let scenario: serde_json::Value = serde_json::from_str(&text).unwrap();
        for step in scenario["steps"].as_array().unwrap() {
            let note = step["note"].as_str().unwrap_or_default();
            if !note.contains("Draft") || !note.ends_with("input") {
                continue;
            }
            let schema = &step["body"]["httpRequest"]["body"]["jsonSchema"];
            let built = super::validator(schema);
            assert!(built.is_ok(), "{note}: {:?}", built.err());
        }
    }
}


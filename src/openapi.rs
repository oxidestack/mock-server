//! OpenAPI request matchers (`HttpRequestsPropertiesMatcher`): an `httpRequest` naming `specUrlOrPayload` (and
//! optionally `operationId`) matches when any operation of the spec does. Each operation, and each request body
//! content type, becomes an ordinary request matcher, built in the JSON form `matcher::RequestMatcher` compiles.
//! The spec is parsed by the swagger-parser port and read back as its swagger-core JSON serialization.

use serde_json::{Map, Value, json};
use swagger_parser::core::ParseOptions;
use swagger_parser::core::SwaggerParserExtension;
use swagger_parser::parser::OpenAPIV3Parser;

pub const OPEN_API_LOAD_ERROR: &str = "Unable to load API spec";

/// The HTTP methods in `OpenAPIParser.mapOperations` order.
const METHODS: &[&str] = &["get", "put", "post", "patch", "delete", "head", "options", "trace"];

/// `OpenAPIParser.isSpecUrl`: a spec file name, or any absolute `http`, `https` or `file` URL (`ABSOLUTE_URL`,
/// `(?i)(https?|file):\S+` matched whole, `\S` being Java's ASCII class), e.g. `…/v3/api-docs?group=public`.
pub fn is_spec_url(spec: &str) -> bool {
    static ABSOLUTE_URL: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"\A(?i:https?|file):[^ \t\n\x0B\x0C\r]+\z").expect("valid"));
    spec.ends_with(".json") || spec.ends_with(".yaml") || spec.ends_with(".yml") || ABSOLUTE_URL.is_match(spec)
}

/// The spec text MockServer parses: a JSON payload given inline is re-printed (`JsonNode.toPrettyString`).
pub fn spec_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(crate::json::pretty(other)),
    }
}

thread_local! {
    /// `Configuration.openAPIContextPathPrefix` of the server whose matcher is being compiled, for a definition
    /// without a `contextPathPrefix` of its own ([`with_context_path_prefix`]).
    static CONFIGURED_CONTEXT_PATH_PREFIX: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

/// Runs `f` (a matcher compilation) with `prefix` as the server's `openAPIContextPathPrefix`, the prefix
/// `HttpRequestsPropertiesMatcher.apply` falls back to when the definition's own one is blank.
pub fn with_context_path_prefix<R>(prefix: &str, f: impl FnOnce() -> R) -> R {
    let previous = CONFIGURED_CONTEXT_PATH_PREFIX.with(|c| c.replace(prefix.to_string()));
    let result = f();
    CONFIGURED_CONTEXT_PATH_PREFIX.with(|c| *c.borrow_mut() = previous);
    result
}

/// The request matchers of one OpenAPI definition (`specUrlOrPayload`, `operationId`, `contextPathPrefix`), or
/// the message the oracle answers 400 with when the spec cannot be loaded.
pub fn request_matchers(definition: &Map<String, Value>) -> Result<Vec<Value>, String> {
    Ok(described_request_matchers(definition)?.into_iter().map(|(request, _)| request).collect())
}

/// [`request_matchers`], each with the description its log lines carry (`HttpRequestsPropertiesMatcher
/// .addRequestMatcher`): ` open api`, the spec's last 40 characters when it is a URL, the operation and the body's
/// content type.
pub fn described_request_matchers(definition: &Map<String, Value>) -> Result<Vec<(Value, String)>, String> {
    let Some(spec) = definition.get("specUrlOrPayload").and_then(spec_text).filter(|s| !s.trim().is_empty()) else {
        return Ok(Vec::new());
    };
    let operation_id = definition.get("operationId").and_then(Value::as_str).filter(|s| !s.trim().is_empty());
    let configured = CONFIGURED_CONTEXT_PATH_PREFIX.with(|c| c.borrow().clone());
    let prefix = definition.get("contextPathPrefix").and_then(Value::as_str).filter(|p| !p.trim().is_empty()).unwrap_or(&configured);
    let mut openapi = load(&spec).map_err(|message| {
        if message.trim().is_empty() || !message.contains(OPEN_API_LOAD_ERROR) {
            format!("{OPEN_API_LOAD_ERROR}{}{message}", if message.trim().is_empty() { "" } else { ", " })
        } else {
            message
        }
    })?;
    add_missing_operation_ids(&mut openapi);
    let mut matchers = Vec::new();
    for (path, operations) in retrieve_operations(&openapi, operation_id, prefix) {
        for (method, operation) in operations {
            let mut added = Vec::new();
            let result = add_operation(&openapi, &path, &method, &operation, &mut added);
            let id = operation.get("operationId").and_then(Value::as_str).filter(|s| !s.trim().is_empty());
            matchers.extend(added.into_iter().map(|(request, content_type)| (request, describe(&spec, id, &content_type))));
            // An exception here ends the whole spec upstream (logged, not reported).
            if result.is_err() {
                return Ok(matchers);
            }
        }
    }
    Ok(matchers)
}

/// `addRequestMatcher`'s description. The spec URL keeps its last 40 characters; a shorter one prints empty
/// (upstream's `substring(length)`).
fn describe(spec: &str, operation_id: Option<&str>, content_type: &str) -> String {
    let mut out = String::from(" open api");
    if is_spec_url(spec) {
        let chars: Vec<char> = spec.chars().collect();
        let tail: String = if chars.len() > 40 { format!("...{}", chars[chars.len() - 40..].iter().collect::<String>()) } else { String::new() };
        out.push_str(&format!(" \"{tail}\""));
    }
    if let Some(id) = operation_id {
        out.push_str(&format!(" operation \"{id}\""));
    }
    if !content_type.trim().is_empty() {
        out.push_str(&format!(" content-type \"{content_type}\""));
    }
    out
}

/// `OpenAPIParser.buildOpenAPI`, as swagger-core's JSON form of the parsed, fully resolved model.
pub fn load(spec: &str) -> Result<Value, String> {
    let openapi = load_model(spec)?;
    let text = if openapi.0.read().openapi.as_deref().is_some_and(|v| v.starts_with("3.1")) {
        swagger_parser::models::json31_string(&openapi)
    } else {
        swagger_parser::models::json_string(&openapi)
    };
    let text = text.map_err(|e| format!("{OPEN_API_LOAD_ERROR}, {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{OPEN_API_LOAD_ERROR}, {e}"))
}

/// `OpenAPIParser.buildOpenAPI`: the parsed, fully resolved model.
pub fn load_model(spec: &str) -> Result<swagger_parser::models::OpenAPI, String> {
    load_spec(spec).map(|loaded| loaded.openapi)
}

/// `OpenAPIParser.LoadedSpec`: a spec that loaded, with the advisory problems swagger-parser reported for it (empty
/// when it follows the OpenAPI rules).
pub struct LoadedSpec {
    pub openapi: swagger_parser::models::OpenAPI,
    pub problems: Vec<crate::openapi_load_problems::Problem>,
}

/// `OpenAPIParser.loadOpenAPI` (9.1.0): [`parse_spec_guarded`], whose problems a server's parse cache logs once per parse
/// ([`logging_load_problems`]).
pub fn load_spec(spec: &str) -> Result<LoadedSpec, String> {
    load_spec_as(spec, false)
}

/// [`load_spec`] for a spec that is really a JSON Schema the response synthesizer wrapped in an OpenAPI document
/// (`buildOpenAPIForInlineJsonSchema`): its problems are logged at DEBUG, worded for a schema.
pub fn load_spec_as(spec: &str, inline_json_schema: bool) -> Result<LoadedSpec, String> {
    let (parsed, refusal) = parse_spec_guarded(spec);
    if let Some(reason) = refusal {
        // `parseOpenAPI` logged the problems of a spec that parsed before `whileParsing` refused it; the refused
        // parse is not cached, so the next one logs them again.
        if let Ok(loaded) = &parsed {
            LOAD_LOG.with(|log| {
                if let Some(log) = log.borrow_mut().as_mut() {
                    pend_load_logs(&mut log.pending, loaded, inline_json_schema);
                }
            });
        }
        return Err(format!("{OPEN_API_LOAD_ERROR}, {reason}"));
    }
    let loaded = parsed?;
    LOAD_LOG.with(|log| {
        if let Some(log) = log.borrow_mut().as_mut() && log.cache.parsed(spec, inline_json_schema) {
            pend_load_logs(&mut log.pending, &loaded, inline_json_schema);
        }
    });
    Ok(loaded)
}

/// What one parse of `loaded` logs: its problems (`logLoadProblems`), then each repeated operationId
/// `addMissingOperationIds` renames.
fn pend_load_logs(pending: &mut Vec<Pending>, loaded: &LoadedSpec, inline_json_schema: bool) {
    if !loaded.problems.is_empty() {
        pending.push(Pending::Problems { inline_json_schema, problems: crate::openapi_load_problems::describe_problems(&loaded.problems) });
    }
    for (candidate, disambiguated) in crate::openapi_expectations::duplicate_operation_ids(&loaded.openapi) {
        pending.push(Pending::DuplicateOperationId { candidate, disambiguated });
    }
}

/// The keys of `OpenAPIParser`'s parse cache (`CacheKey`: the spec and whether it is an inline JSON Schema), an LRU
/// of 250 whose entries expire 30 minutes after their last use. Upstream's cache is static; each of our servers has
/// its own, as each oracle container is a JVM of its own. It decides only when a spec's problems are logged: once
/// per parse, not on a cache hit. `reset` leaves it alone, as upstream's.
#[derive(Default)]
pub struct ParseCache(std::sync::Mutex<ParseCacheEntries>);

#[derive(Default)]
struct ParseCacheEntries {
    /// Key → expiry, and the keys from least to most recently used.
    expiries: std::collections::HashMap<(String, bool), std::time::Instant>,
    queue: std::collections::VecDeque<(String, bool)>,
}

const PARSE_CACHE_SIZE: usize = 250;
const PARSE_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);

impl ParseCache {
    /// `getOrCompute` for a spec that just loaded: whether this load was a parse (the key was absent or expired),
    /// which then becomes the cached one; a hit refreshes the entry's place and expiry.
    fn parsed(&self, spec: &str, inline_json_schema: bool) -> bool {
        let mut entries = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (spec.to_string(), inline_json_schema);
        let now = std::time::Instant::now();
        if let Some(expiry) = entries.expiries.get(&key).copied() {
            entries.queue.retain(|k| k != &key);
            if expiry > now {
                entries.queue.push_back(key.clone());
                entries.expiries.insert(key, now + PARSE_CACHE_TTL);
                return false;
            }
            entries.expiries.remove(&key);
        }
        while entries.queue.len() >= PARSE_CACHE_SIZE {
            if let Some(oldest) = entries.queue.pop_front() {
                entries.expiries.remove(&oldest);
            }
        }
        entries.queue.push_back(key.clone());
        entries.expiries.insert(key, now + PARSE_CACHE_TTL);
        true
    }

    /// `OpenAPIParser.clearCache`: a spec URL re-imported through `PUT /mockserver/openapi` is parsed again.
    pub fn clear(&self, spec: &str) {
        let mut entries = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for inline in [false, true] {
            let key = (spec.to_string(), inline);
            if entries.expiries.remove(&key).is_some() {
                entries.queue.retain(|k| k != &key);
            }
        }
    }
}

struct LoadLog {
    cache: std::sync::Arc<ParseCache>,
    /// What the parses so far log, not logged yet.
    pending: Vec<Pending>,
}

enum Pending {
    /// `logLoadProblems`: the grouped problems of a spec, or of an inline JSON Schema.
    Problems { inline_json_schema: bool, problems: String },
    /// `ensureUnique`'s WARN.
    DuplicateOperationId { candidate: String, disambiguated: String },
}

thread_local! {
    /// The parse cache and pending problem logs of the server whose request is being handled on this thread.
    static LOAD_LOG: std::cell::RefCell<Option<LoadLog>> = const { std::cell::RefCell::new(None) };
}

/// Runs `f` with `state`'s parse cache, then logs the problems of each spec `f` parsed (`logLoadProblems`): a WARN
/// for a spec, a DEBUG for an inline JSON Schema. Nested scopes share the outer one's cache and log their own parses
/// when they end, so an entry lands where upstream's parse logs it, before what the caller logs next.
pub fn logging_load_problems<R>(state: &crate::state::State, f: impl FnOnce() -> R) -> R {
    let (outer, start) = LOAD_LOG.with(|log| {
        let mut log = log.borrow_mut();
        let outer = log.is_some();
        let log = log.get_or_insert_with(|| LoadLog { cache: state.openapi_parses.clone(), pending: Vec::new() });
        (outer, log.pending.len())
    });
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            if !self.0 {
                LOAD_LOG.with(|log| log.borrow_mut().take());
            }
        }
    }
    let restore = Restore(outer);
    let result = checking_spec_fetches(&state.config, f);
    let pending: Vec<Pending> =
        LOAD_LOG.with(|log| log.borrow_mut().as_mut().map(|log| log.pending.split_off(start.min(log.pending.len()))).unwrap_or_default());
    drop(restore);
    for pending in pending {
        use crate::recorded::{Level, LogEntry};
        match pending {
            Pending::Problems { inline_json_schema: true, problems } => {
                if crate::log::debug_enabled(state) {
                    let entry = LogEntry::at(Level::Debug, INLINE_JSON_SCHEMA_PROBLEMS).args([problems.as_str()]);
                    crate::log::entry_as(state, Level::Debug, &entry);
                    state.log.message(entry);
                }
            }
            Pending::Problems { inline_json_schema: false, problems } => {
                crate::log::warn_event(state, LogEntry::at(Level::Warn, SPEC_PROBLEMS).args([problems.as_str()]));
            }
            Pending::DuplicateOperationId { candidate, disambiguated } => crate::log::warn_event(
                state,
                LogEntry::at(Level::Warn, "duplicate OpenAPI operationId {} - disambiguating to {} to avoid conflating distinct operations")
                    .args([candidate.as_str(), disambiguated.as_str()]),
            ),
        }
    }
    result
}

const SPEC_PROBLEMS: &str = "loaded OpenAPI spec with problems that may stop parts of it working as expected, {}";
const INLINE_JSON_SCHEMA_PROBLEMS: &str = "inline JSON Schema for a generated response body breaks OpenAPI 3.0 rules, so the body may ignore parts of it (the schema is read as #/components/schemas/GeneratedResponse), {}";

/// The forward target checks a spec parse on this thread applies to what it fetches (`SpecFetchGuard`).
#[derive(Clone)]
struct FetchChecks {
    /// `forwardProxyBlockPrivateNetworks`.
    block: bool,
    /// `forwardProxyAllowedHosts` and `forwardProxyDeniedHosts`.
    policy: Option<std::sync::Arc<crate::forward_target_policy::Policy>>,
}

thread_local! {
    /// The checks of the server whose spec is being parsed on this thread, `None` when it has none on.
    static FETCH_CHECKS: std::cell::RefCell<Option<FetchChecks>> = const { std::cell::RefCell::new(None) };
}

/// Runs `f` with the specs it parses checked under `config`'s `forwardProxyBlockPrivateNetworks`,
/// `forwardProxyAllowedHosts` and `forwardProxyDeniedHosts`, as upstream's `buildOpenAPI(…, configuration)` checks
/// them: the spec URL, each remote `$ref` and each redirect ([`parse_spec_guarded`]). Taken when `f` starts.
pub fn checking_spec_fetches<R>(config: &crate::config::Config, f: impl FnOnce() -> R) -> R {
    let block = config.bool_property("forwardProxyBlockPrivateNetworks", false);
    let policy = crate::forward_target_policy::of(config);
    let checks = (block || policy.is_some()).then_some(FetchChecks { block, policy });
    struct Restore(Option<FetchChecks>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            FETCH_CHECKS.with(|c| *c.borrow_mut() = previous);
        }
    }
    let _restore = Restore(FETCH_CHECKS.with(|c| c.replace(checks)));
    f()
}

/// `SpecFetchGuard.whileParsing` over `OpenAPIParser.parseOpenAPI` (9.1.0): the parsed, fully resolved model and its
/// advisory problems, or the load failure, its parser messages grouped by kind (`OpenAPILoadProblems.describe`); and
/// the first fetch refused. Under [`checking_spec_fetches`] every connection the parse opens is checked first (a
/// `ProxySelector` upstream); the first one refused refuses the spec, whatever the parser made of the failed fetch. A
/// spec or `$ref` read from a file opens no connection and is not checked.
fn parse_spec_guarded(spec: &str) -> (Result<LoadedSpec, String>, Option<String>) {
    let Some(checks) = FETCH_CHECKS.with(|c| c.borrow().clone()) else { return (parse_spec_unchecked(spec), None) };
    let refusal: std::rc::Rc<std::cell::RefCell<Option<String>>> = Default::default();
    let first = refusal.clone();
    let mut hooks = swagger_parser::parser::hooks::installed();
    hooks.select_proxy = Some(std::rc::Rc::new(move |url: &str, host: &str| {
        let reason = if host.trim().is_empty() {
            // `HttpURLConnection` reads the host more leniently than `URI` does, so refuse rather than skip.
            Some(format!("OpenAPI spec fetch from \"{url}\" names no host that can be checked"))
        } else {
            crate::ws_relay::blocked_by(checks.block, checks.policy.clone(), host)
        };
        match reason {
            None => Ok(()),
            Some(reason) => {
                first.borrow_mut().get_or_insert_with(|| reason.clone());
                Err(swagger_parser::java::JavaException::new("org.mockserver.proxyconfiguration.ForwardTargetBlockedException", reason))
            }
        }
    }));
    let guard = swagger_parser::parser::hooks::install(hooks);
    let parsed = parse_spec_unchecked(spec);
    drop(guard);
    let refused = refusal.take();
    (parsed, refused)
}

fn parse_spec_unchecked(spec: &str) -> Result<LoadedSpec, String> {
    let mut options = ParseOptions::new();
    options.resolve = true;
    options.resolve_fully = true;
    options.resolve_combinators = true;
    options.skip_matches = true;
    options.allow_empty_strings = true;
    options.camel_case_flatten_naming = true;
    let mut errors: Vec<String> = Vec::new();
    let mut parsed = None;
    let any_message = |errors: &[String]| errors.iter().any(|m| !m.trim().is_empty());
    let exception = |e: swagger_parser::java::JavaException, errors: &[String]| {
        let detail = if any_message(errors) { crate::openapi_load_problems::describe(errors) } else { e.get_message().unwrap_or("null").to_string() };
        format!("{OPEN_API_LOAD_ERROR}, {detail}")
    };
    if is_spec_url(spec) {
        let location = spec.replace('\\', "/");
        // Reading a URL blocks this thread on a socket; the spec may be served by this same server.
        let read = |extension: &dyn SwaggerParserExtension| crate::blocking::off_worker(|| extension.try_read_location(&location, None, Some(&options)));
        for extension in swagger_parser::parser_extensions() {
            match read(extension.as_ref()) {
                Ok(Some(result)) => {
                    if let Some(openapi) = result.openapi {
                        parsed = Some((openapi, result.messages.unwrap_or_default()));
                        break;
                    }
                    errors.extend(result.messages.unwrap_or_default());
                }
                Ok(None) => return Err(exception(swagger_parser::java::JavaException::npe("null"), &errors)),
                Err(e) => return Err(exception(e, &errors)),
            }
        }
    } else {
        // An inline payload's external `$ref`s are fetched while it is resolved, also with a blocking read.
        match crate::blocking::off_worker(|| OpenAPIV3Parser::new().try_read_contents(spec, None, Some(&options))) {
            Ok(Some(result)) => match result.openapi {
                Some(openapi) => parsed = Some((openapi, result.messages.unwrap_or_default())),
                None => errors.extend(result.messages.unwrap_or_default()),
            },
            Ok(None) => return Err(exception(swagger_parser::java::JavaException::npe("null"), &errors)),
            Err(e) => return Err(exception(e, &errors)),
        }
    }
    match parsed {
        Some((openapi, messages)) => Ok(LoadedSpec { openapi, problems: crate::openapi_load_problems::problems(&messages) }),
        None if any_message(&errors) => Err(format!("{OPEN_API_LOAD_ERROR}, {}", crate::openapi_load_problems::describe(&errors))),
        None => Err(OPEN_API_LOAD_ERROR.to_string()),
    }
}

/// `mapOperations`: a path item's operations as `(METHOD, operation)`.
pub fn map_operations(path_item: &Value) -> Vec<(String, Value)> {
    METHODS
        .iter()
        .filter_map(|m| path_item.get(*m).filter(|o| o.is_object()).map(|o| (m.to_ascii_uppercase(), o.clone())))
        .collect()
}

/// `OpenAPIParser.addMissingOperationIds`: every operation gets a unique, non-blank id; authored ids are kept
/// (duplicates get ` (2)`, ` (3)`…), missing ones become `"<METHOD> <path>"` (`"<METHOD> webhook:<name>"`).
pub fn add_missing_operation_ids(openapi: &mut Value) {
    let mut seen = std::collections::HashSet::new();
    let ensure_unique = |candidate: String, seen: &mut std::collections::HashSet<String>| {
        if seen.insert(candidate.clone()) {
            return candidate;
        }
        (2..).map(|n| format!("{candidate} ({n})")).find(|c| seen.insert(c.clone())).expect("unbounded")
    };
    let sections = [("paths", false), ("webhooks", true)];
    for (section, _) in sections {
        for_each_operation(openapi, section, |_, _, operation| {
            if let Some(id) = operation.get("operationId").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                let unique = ensure_unique(id.to_string(), &mut seen);
                operation["operationId"] = Value::String(unique);
            }
        });
    }
    for (section, webhook) in sections {
        for_each_operation(openapi, section, |name, method, operation| {
            if operation.get("operationId").and_then(Value::as_str).is_none_or(|s| s.trim().is_empty()) {
                let candidate = if webhook { format!("{method} webhook:{name}") } else { format!("{method} {name}") };
                operation["operationId"] = Value::String(ensure_unique(candidate, &mut seen));
            }
        });
    }
}

fn for_each_operation(openapi: &mut Value, section: &str, mut f: impl FnMut(&str, &str, &mut Value)) {
    let Some(items) = openapi.get_mut(section).and_then(Value::as_object_mut) else { return };
    for (name, item) in items.iter_mut() {
        for m in METHODS {
            if let Some(operation) = item.get_mut(*m).filter(|o| o.is_object()) {
                f(name, &m.to_ascii_uppercase(), operation);
            }
        }
    }
}

/// `OpenAPISerialiser.retrieveOperations(openAPI, null)` flattened: full path, method, operation, in order.
pub fn all_operations(openapi: &Value) -> Vec<(String, String, Value)> {
    retrieve_operations(openapi, None, "").into_iter().flat_map(|(path, ops)| ops.into_iter().map(move |(m, o)| (path.clone(), m, o))).collect()
}

/// `OpenAPISerialiser.retrieveOperations`: full path → operations (sorted by method), paths then webhooks.
fn retrieve_operations(openapi: &Value, operation_id: Option<&str>, prefix: &str) -> Vec<(String, Vec<(String, Value)>)> {
    let mut out: Vec<(String, Vec<(String, Value)>)> = Vec::new();
    let mut add = |path: String, operations: Vec<(String, Value)>| match out.iter_mut().find(|(p, _)| *p == path) {
        Some((_, existing)) => existing.extend(operations),
        None => out.push((path, operations)),
    };
    let prefix = normalize_context_path_prefix(prefix);
    let selected = |item: &Value| {
        let mut operations: Vec<(String, Value)> = map_operations(item)
            .into_iter()
            .filter(|(_, o)| operation_id.is_none_or(|id| o.get("operationId").and_then(Value::as_str) == Some(id)))
            .collect();
        operations.sort_by(|a, b| a.0.cmp(&b.0));
        operations
    };
    for (path, item) in openapi.get("paths").and_then(Value::as_object).into_iter().flatten() {
        for (method, operation) in selected(item) {
            let servers = [operation.get("servers"), item.get("servers"), openapi.get("servers")];
            add(format!("{prefix}{}{path}", first_valid_server_path(&servers)), vec![(method, operation)]);
        }
    }
    for (name, item) in openapi.get("webhooks").and_then(Value::as_object).into_iter().flatten() {
        let operations = selected(item);
        if !operations.is_empty() {
            add(format!("{prefix}/webhook:{name}"), operations);
        }
    }
    out
}

fn normalize_context_path_prefix(prefix: &str) -> String {
    if prefix.trim().is_empty() {
        return String::new();
    }
    let mut normalized = String::new();
    for c in prefix.trim().chars() {
        if !(c == '/' && normalized.ends_with('/')) {
            normalized.push(c);
        }
    }
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    let normalized = normalized.strip_suffix('/').unwrap_or(&normalized).to_string();
    if normalized == "/" { String::new() } else { normalized }
}

/// `firstValidServerPath`: the path of the first server of the first non-empty list whose path is not blank.
fn first_valid_server_path(lists: &[Option<&Value>]) -> String {
    for list in lists.iter().flatten().filter_map(|l| l.as_array()) {
        let Some(server) = list.first() else { continue };
        let path = return_path(&server_url_with_variables_expanded(server));
        if !path.trim().is_empty() {
            let path = if path.starts_with('/') { path } else { format!("/{path}") };
            return path.strip_suffix('/').unwrap_or(&path).to_string();
        }
    }
    String::new()
}

fn server_url_with_variables_expanded(server: &Value) -> String {
    let mut url = server.get("url").and_then(Value::as_str).unwrap_or_default().to_string();
    for (name, variable) in server.get("variables").and_then(Value::as_object).into_iter().flatten() {
        let default = variable.get("default").and_then(Value::as_str).unwrap_or_default();
        url = url.replace(&format!("{{{name}}}"), default);
    }
    url
}

/// `URLParser.returnPath`: the URL without scheme, host and port, and without the query.
fn return_path(url: &str) -> String {
    static SCHEME_HOST_PORT: std::sync::LazyLock<fancy_regex::Regex> = std::sync::LazyLock::new(|| {
        fancy_regex::Regex::new(r"https?://([A-Za-z0-9-_.:]*@)?[A-Za-z0-9-_.]*(:[0-9]*)?").expect("static regex")
    });
    let full = url.starts_with("http://") || url.starts_with("https://");
    let path = if full { SCHEME_HOST_PORT.replace_all(url, "").into_owned() } else { url.to_string() };
    path.split('?').next().unwrap_or_default().to_string()
}

/// One operation's request matchers: one per request body content type, or one without a body.
fn add_operation(openapi: &Value, path: &str, method: &str, operation: &Value, out: &mut Vec<(Value, String)>) -> Result<(), ()> {
    let content = operation.get("requestBody").and_then(|b| b.get("content")).and_then(Value::as_object);
    let Some(content) = content else {
        out.push((create_http_request(openapi, path, method, operation)?, String::new()));
        return Ok(());
    };
    let required = operation["requestBody"].get("required").and_then(Value::as_bool) == Some(true);
    for (content_type, media_type) in content {
        let mut request = create_http_request(openapi, path, method, operation)?;
        if content_type == "multipart/form-data" {
            // `MultipartBody` of the schema's required fields; without any, path and method only.
            let fields = media_type.get("schema").and_then(|s| s.get("required")).and_then(Value::as_array).filter(|r| !r.is_empty());
            if let Some(fields) = fields {
                let parameters: Map<String, Value> = fields.iter().filter_map(Value::as_str).map(|f| (f.to_string(), json!([".*"]))).collect();
                request["body"] = json!({"type": "MULTIPART", "fields": parameters, "optional": !required});
            }
            out.push((request, content_type.clone()));
            continue;
        }
        if content_type != "*/*" && required {
            let escaped = content_type_regex(content_type);
            headers(&mut request).insert("content-type".into(), json!([escaped]));
        }
        if let Some(schema) = media_type.get("schema") {
            let mut body = Map::new();
            if !required {
                body.insert("optional".into(), Value::Bool(true));
            }
            body.insert("type".into(), "JSON_SCHEMA".into());
            body.insert("jsonSchema".into(), json_schema(schema));
            if let Some(encoding) = media_type.get("encoding").and_then(Value::as_object) {
                let styles: Map<String, Value> = encoding
                    .iter()
                    .map(|(name, e)| (name.clone(), parameter_style(e.get("explode"), e.get("style")).map_or(Value::Null, Value::from)))
                    .collect();
                body.insert("parameterStyles".into(), Value::Object(styles));
            }
            request["body"] = Value::Object(body);
        }
        out.push((request, content_type.clone()));
    }
    Ok(())
}

/// The content type as a header regex: special characters escaped, then `*` widened (`\*` becomes `\.*`, as the
/// two upstream `replaceAll`s do), and any parameters allowed after it.
fn content_type_regex(content_type: &str) -> String {
    const SPECIAL: &str = "_ :;.,/\"'?!(){}[]@<>=-+*#$&`|~^%";
    let mut escaped = String::new();
    for c in content_type.chars() {
        if SPECIAL.contains(c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped.replace('*', ".*") + ".*"
}

fn headers(request: &mut Value) -> &mut Map<String, Value> {
    map_field(request, "headers")
}

fn map_field<'a>(request: &'a mut Value, field: &str) -> &'a mut Map<String, Value> {
    if !request.get(field).is_some_and(Value::is_object) {
        request[field] = Value::Object(Map::new());
    }
    request[field].as_object_mut().expect("object")
}

/// `createHttpRequest`: method, path, parameters as schema matchers, and security scheme requirements.
fn create_http_request(openapi: &Value, path: &str, method: &str, operation: &Value) -> Result<Value, ()> {
    let mut request = json!({"method": method, "path": path});
    if let Some(parameters) = operation.get("parameters").and_then(Value::as_array) {
        for parameter in parameters {
            let schema = parameter.get("schema").cloned().or_else(|| {
                parameter.get("content").and_then(Value::as_object).and_then(|c| c.values().next()).and_then(|m| m.get("schema")).cloned()
            });
            let Some(mut schema) = schema else { continue };
            let name = parameter.get("name").and_then(Value::as_str).unwrap_or_default();
            let name = if parameter.get("required").and_then(Value::as_bool) == Some(true) { name.to_string() } else { format!("?{name}") };
            if parameter.get("allowEmptyValue").and_then(Value::as_bool) == Some(true) && let Some(o) = schema.as_object_mut() {
                o.insert("nullable".into(), Value::Bool(true));
            }
            if parameter.get("allowReserved").and_then(Value::as_bool) == Some(true) {
                return Err(());
            }
            let schema = json!({"schema": json_schema(&schema)});
            let style = parameter_style(parameter.get("explode"), parameter.get("style"));
            let field = match parameter.get("in").and_then(Value::as_str) {
                Some("path") => "pathParameters",
                Some("query") => "queryStringParameters",
                Some("header") => "headers",
                Some("cookie") => {
                    map_field(&mut request, "cookies").insert(name, schema);
                    continue;
                }
                _ => continue,
            };
            let map = map_field(&mut request, field);
            match map.get_mut(&name) {
                Some(entry) => {
                    if let Some(values) = entry.get_mut("values").and_then(Value::as_array_mut) {
                        values.push(schema);
                    }
                }
                None => {
                    let mut entry = Map::new();
                    if let Some(style) = style {
                        entry.insert("parameterStyle".into(), style.into());
                    }
                    entry.insert("values".into(), json!([schema]));
                    map.insert(name, Value::Object(entry));
                }
            }
        }
        // Every value must match (not just one) for the schema-driven maps.
        for field in ["pathParameters", "queryStringParameters", "headers"] {
            if let Some(map) = request.get_mut(field).and_then(Value::as_object_mut) {
                let mut styled = Map::new();
                styled.insert("keyMatchStyle".into(), "MATCHING_KEY".into());
                styled.extend(std::mem::take(map));
                *map = styled;
            }
        }
    }
    let security = match operation.get("security") {
        Some(s) if !s.is_null() => s,
        _ => openapi.get("security").unwrap_or(&Value::Null),
    };
    let requirements = security_requirements(openapi, security);
    let [header, query, cookie] = &requirements;
    add_requirements(&mut request, "headers", header, !query.is_empty() || !cookie.is_empty());
    add_requirements(&mut request, "queryStringParameters", query, !header.is_empty() || !cookie.is_empty());
    add_requirements(&mut request, "cookies", cookie, !query.is_empty() || !header.is_empty());
    Ok(request)
}

/// Name → value regexes, as Java `HashMap`/`HashSet` iterate them (`JavaHashOrder`).
type Requirements = Vec<(String, Vec<String>)>;

/// `buildSecurityValues`: header, query and cookie requirements of the security schemes in force.
fn security_requirements(openapi: &Value, security: &Value) -> [Requirements; 3] {
    let mut out: [Requirements; 3] = Default::default();
    let schemes = openapi.get("components").and_then(|c| c.get("securitySchemes"));
    for requirement in security.as_array().into_iter().flatten() {
        for name in requirement.as_object().into_iter().flat_map(|o| o.keys()) {
            let Some(scheme) = schemes.and_then(|s| s.get(name)) else { continue };
            let scheme_prefix = scheme.get("scheme").and_then(Value::as_str).filter(|s| !s.trim().is_empty()).unwrap_or_default();
            let (parameter, value) = match scheme.get("type").and_then(Value::as_str) {
                Some("apiKey") => match scheme.get("name").and_then(Value::as_str).filter(|n| !n.trim().is_empty()) {
                    Some(n) => (n.to_string(), ".+".to_string()),
                    None => continue,
                },
                Some("http" | "oauth2" | "openIdConnect") => ("authorization".to_string(), format!("{scheme_prefix}.+")),
                _ => continue,
            };
            let target = match scheme.get("in").and_then(Value::as_str) {
                Some("cookie") => &mut out[2],
                Some("query") => &mut out[1],
                _ => &mut out[0],
            };
            match target.iter_mut().find(|(n, _)| *n == parameter) {
                Some((_, values)) => {
                    if !values.contains(&value) {
                        values.push(value);
                    }
                }
                None => target.push((parameter, vec![value])),
            }
        }
    }
    for requirements in &mut out {
        java_hash_order(requirements, |(k, _)| k);
        for (_, values) in requirements.iter_mut() {
            java_hash_order(values, |v| v);
        }
    }
    out
}

/// The `withHeader`/`withQueryStringParameter`/`withCookie` calls for one kind of requirement.
fn add_requirements(request: &mut Value, field: &str, requirements: &Requirements, others: bool) {
    if requirements.is_empty() {
        return;
    }
    let mut add = |name: String, value: String| {
        let map = map_field(request, field);
        if field == "cookies" {
            map.insert(name, Value::String(value));
            return;
        }
        match map.get_mut(&name).and_then(Value::as_array_mut) {
            Some(values) => values.push(Value::String(value)),
            None => {
                map.insert(name, json!([value]));
            }
        }
    };
    let names = requirements.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join("|");
    let all_values = requirements.iter().flat_map(|(_, v)| v.iter().map(String::as_str)).collect::<Vec<_>>().join("|");
    if requirements.len() > 1 {
        for (name, values) in requirements {
            add(format!("?{name}"), values.join("|"));
        }
        add(names, ".*".into());
    } else if others {
        add(format!("?{names}"), all_values);
    } else {
        add(names, all_values);
    }
}

/// Reorders `items` as a small Java `HashMap`/`HashSet` of strings iterates: by bucket of the spread
/// `String.hashCode`, then insertion order within a bucket.
fn java_hash_order<T>(items: &mut [T], key: impl Fn(&T) -> &String) {
    let mut capacity = 16usize;
    while items.len() as f64 > capacity as f64 * 0.75 {
        capacity *= 2;
    }
    items.sort_by_key(|item| {
        let h = key(item).encode_utf16().fold(0i32, |h, c| h.wrapping_mul(31).wrapping_add(c as i32));
        let spread = (h ^ ((h as u32) >> 16) as i32) as u32;
        spread as usize & (capacity - 1)
    });
}

/// `ParameterStyle` of an OpenAPI `style`/`explode` pair (both must be given, as the parser defaults them).
fn parameter_style(explode: Option<&Value>, style: Option<&Value>) -> Option<&'static str> {
    let explode = explode?.as_bool()?;
    let pick = |plain: &'static str, exploded: &'static str| Some(if explode { exploded } else { plain });
    match style?.as_str()? {
        "matrix" => pick("MATRIX", "MATRIX_EXPLODED"),
        "label" => pick("LABEL", "LABEL_EXPLODED"),
        "form" => pick("FORM", "FORM_EXPLODED"),
        "simple" => pick("SIMPLE", "SIMPLE_EXPLODED"),
        "spaceDelimited" => pick("SPACE_DELIMITED", "SPACE_DELIMITED_EXPLODED"),
        "pipeDelimited" => pick("PIPE_DELIMITED", "PIPE_DELIMITED_EXPLODED"),
        "deepObject" => Some("DEEP_OBJECT"),
        _ => None,
    }
}

/// `AbstractSchemaSerializer.translateOas31Types`: a schema's OpenAPI-3.1 `types` array (`["string","null"]`…)
/// becomes the Draft-07/OAS-3.0 form: a single non-null type becomes plain `type`; several become a `type` array;
/// a `"null"` entry alongside at least one non-null type adds `nullable: true` (unless already present).
///
/// Upstream reaches this from the *bean's own* `types` field (a Java `Schema.types` populated only when the spec
/// was OpenAPI 3.1, read back with a plain, mixin-free `ObjectMapper` that uses the untranslated bean property
/// name). Our own whole-document dump (`swagger_parser::models::json31_string`, `Schema::serialize_fields`'s
/// `Mapper::Json31` branch / `write_types`) already renames that field to plain `type` on the way out — a single
/// element becomes a JSON string, several become a JSON array — but does not fold a `"null"` entry into
/// `nullable`, so the untranslated OAS-3.1 form this function actually sees is an **array-valued `type`** (a
/// bare `type: "null"` string, from a one-element `["null"]` set, is the other untranslated shape write_types
/// can produce). A plain non-array `type` (a string other than `"null"`) is already the translated OAS-3.0 form
/// — do nothing.
fn translate_oas31_types(o: &mut Map<String, Value>) {
    // The literal `types` field (defensive — see the doc comment above) wins if somehow both are present, exactly
    // as upstream's `objectNode.has("type")` guard would NOT stop it (that guard only fires once `types` is gone).
    let types: Vec<Value> = match o.remove("types") {
        Some(Value::Array(t)) => t,
        Some(_) | None => match o.get("type") {
            Some(Value::Array(t)) => t.clone(),
            Some(Value::String(s)) if s == "null" => vec![Value::String("null".into())],
            _ => return,
        },
    };
    o.remove("type");
    if types.is_empty() {
        return;
    }
    let as_text = |v: &Value| match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    };
    let mut non_null_types: Vec<Value> = Vec::new();
    let mut has_null = false;
    for t in &types {
        if matches!(t, Value::Null) || as_text(t) == "null" {
            has_null = true;
        } else {
            non_null_types.push(Value::String(as_text(t)));
        }
    }
    if non_null_types.len() == 1 {
        o.insert("type".into(), non_null_types[0].clone());
    } else if non_null_types.len() > 1 {
        o.insert("type".into(), Value::Array(non_null_types.clone()));
    }
    if has_null && !non_null_types.is_empty() && !o.contains_key("nullable") {
        o.insert("nullable".into(), Value::Bool(true));
    }
}

/// A schema as MockServer writes it for matching: bean properties in alphabetical order, map-valued keywords
/// (`properties`…) in spec order, OpenAPI 3.0's boolean `exclusiveMinimum`/`exclusiveMaximum` folded into
/// the numeric JSON Schema form, and an OpenAPI-3.1 array-valued `type` (or literal `types`, defensively) folded
/// into the Draft-07/OAS-3.0 `type`(+`nullable`) form this function otherwise targets — see
/// [`translate_oas31_types`].
pub fn json_schema(schema: &Value) -> Value {
    const MAPS: &[&str] = &["properties", "patternProperties", "definitions", "$defs", "dependentSchemas"];
    let Value::Object(o) = schema else { return schema.clone() };
    let mut o = o.clone();
    translate_oas31_types(&mut o);
    for (flag, bound) in [("exclusiveMinimum", "minimum"), ("exclusiveMaximum", "maximum")] {
        if let Some(Value::Bool(exclusive)) = o.get(flag).cloned() {
            o.remove(flag);
            if exclusive && let Some(value) = o.remove(bound) {
                o.insert(flag.into(), value);
            }
        }
    }
    let mut keys: Vec<String> = o.keys().cloned().collect();
    keys.sort();
    let mut out = Map::new();
    for k in keys {
        let v = &o[&k];
        let v = match v {
            Value::Object(m) if MAPS.contains(&k.as_str()) => Value::Object(m.iter().map(|(n, s)| (n.clone(), json_schema(s))).collect()),
            Value::Object(_) => json_schema(v),
            Value::Array(items) if matches!(k.as_str(), "allOf" | "anyOf" | "oneOf" | "prefixItems") => {
                Value::Array(items.iter().map(json_schema).collect())
            }
            _ => v.clone(),
        };
        out.insert(k, v);
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn petstore() -> Map<String, Value> {
        let spec = std::fs::read_to_string("upstream/mockserver/examples/java/src/main/resources/org/mockserver/openapi/openapi_petstore_example.json").unwrap();
        let mut m = Map::new();
        m.insert("specUrlOrPayload".into(), Value::String(spec));
        m
    }

    #[test]
    fn petstore_operations_become_request_matchers() {
        let matchers = request_matchers(&petstore()).unwrap();
        let summary: Vec<String> = matchers.iter().map(|m| format!("{} {}", m["method"].as_str().unwrap(), m["path"].as_str().unwrap())).collect();
        assert_eq!(summary, ["GET /v1/pets", "POST /v1/pets", "POST /v1/pets", "GET /v1/pets/{petId}", "GET /v1/some/path"]);
        assert_eq!(matchers[0]["queryStringParameters"], json!({"keyMatchStyle": "MATCHING_KEY", "?limit": {"parameterStyle": "FORM_EXPLODED", "values": [{"schema": {"format": "int32", "type": "integer"}}]}}));
        assert_eq!(matchers[1]["headers"], json!({"content-type": ["application\\/json.*"]}));
        assert_eq!(matchers[1]["body"]["jsonSchema"]["required"], json!(["id", "name"]));
        assert!(matchers[2].get("headers").is_none());
    }

    /// `AbstractSchemaSerializerTest`'s four translation cases. The array-valued `type` (rather than a literal
    /// `types` field) is the shape our own OAS-3.1 whole-document dump actually produces — confirmed against a
    /// real parse in [`oas31_array_type_in_a_real_spec_is_translated_on_echo`] below.
    #[test]
    fn oas31_types_array_translates_to_type_and_nullable() {
        assert_eq!(json_schema(&json!({"type": ["string", "null"]})), json!({"nullable": true, "type": "string"}));
        assert_eq!(json_schema(&json!({"type": ["integer", "null"]})), json!({"nullable": true, "type": "integer"}));
        assert_eq!(json_schema(&json!({"type": ["string", "integer"]})), json!({"type": ["string", "integer"]}));
        assert_eq!(json_schema(&json!({"type": ["string", "integer", "null"]})), json!({"nullable": true, "type": ["string", "integer"]}));
        // a one-element `["null"]` set: write_types renders it as the plain string "null", not an array.
        assert_eq!(json_schema(&json!({"type": "null"})), json!({}));
    }

    #[test]
    fn oas31_types_left_alone_when_type_already_a_plain_string() {
        assert_eq!(json_schema(&json!({"type": "string"})), json!({"type": "string"}));
    }

    #[test]
    fn oas31_literal_types_field_is_translated_defensively() {
        // Never actually produced by our own pipeline (see above), but AbstractSchemaSerializer reads the Java
        // bean's literal `types` field, so honour it too if it ever reaches this function from elsewhere.
        assert_eq!(json_schema(&json!({"types": ["string", "null"]})), json!({"nullable": true, "type": "string"}));
    }

    #[test]
    fn oas31_types_nested_in_properties_are_translated_too() {
        let schema = json!({"type": "object", "properties": {"a": {"type": ["string", "null"]}}});
        assert_eq!(json_schema(&schema), json!({"type": "object", "properties": {"a": {"nullable": true, "type": "string"}}}));
    }

    #[test]
    fn oas31_array_type_in_a_real_spec_is_translated_on_echo() {
        let spec = json!({
            "openapi": "3.1.0",
            "info": {"title": "t", "version": "1.0"},
            "paths": {"/p": {"post": {
                "operationId": "op",
                "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": ["string", "null"]}}}},
                "responses": {"200": {"description": "ok"}}
            }}}
        });
        let mut def = Map::new();
        def.insert("specUrlOrPayload".into(), Value::String(spec.to_string()));
        let matchers = request_matchers(&def).unwrap();
        assert_eq!(matchers[0]["body"]["jsonSchema"], json!({"nullable": true, "type": "string"}));
    }

    #[test]
    fn unparseable_spec_reports_the_jackson_error() {
        let mut m = Map::new();
        m.insert("specUrlOrPayload".into(), "not an openapi spec".into());
        let e = request_matchers(&m).unwrap_err();
        // 9.1.0 groups the parser's message (golden `openapi` step 22)
        assert!(
            e.starts_with("Unable to load API spec, 1 problem found:\n\n  other problem (1):\n    - Cannot construct instance of `java.util.LinkedHashMap`"),
            "{e}"
        );
    }

    #[test]
    fn java_hash_order_matches_hashmap_iteration() {
        // new HashMap<>() with "b", "a", "authorization", "X-Key" iterates [authorization, a, b, X-Key] (JDK 26)
        let mut keys = vec!["b".to_string(), "a".to_string(), "authorization".to_string(), "X-Key".to_string()];
        java_hash_order(&mut keys, |k| k);
        assert_eq!(keys, ["authorization", "a", "b", "X-Key"]);
    }
}

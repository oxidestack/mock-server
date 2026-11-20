//! `TemplateDryRun` (9.1.0, upstream #25, #82, #85): `PUT /mockserver/template/test` renders a response or forward
//! template against a sample request without an expectation. It uses the serving engines and time limits (each still
//! applied when serving has none), reports what serving would answer, line and column on failure, and warnings for
//! unresolved Velocity references, unresolved Mustache variables and `scenario.set`; nothing it does reaches the
//! event log or changes scenario state. At most [`MAX_CONCURRENT_DRY_RUNS`] run at once, each on a thread of its own:
//! a template that cannot be stopped keeps its slot, and later calls are refused with a 429 rather than queued.

use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use java_compat::lang::JValue;
use parking_lot::Mutex;
use serde_json::{Map, Value};

use super::{Engine, Output, PathMatch, Thrown, VelocityEngine};
use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;

/// `MAX_CONCURRENT_DRY_RUNS`.
const MAX_CONCURRENT_DRY_RUNS: usize = 2;
/// `TIMEOUT_WHEN_DISABLED_MILLIS`: the limit when the engine's own is 0 or less.
const TIMEOUT_WHEN_DISABLED_MILLIS: i64 = 5_000;
/// `RESPONSE_GRACE_MILLIS`: how much longer than the engine's limit the caller waits for the report.
const RESPONSE_GRACE_MILLIS: i64 = 5_000;
const MAX_REPORTED_OUTPUT_CHARS: usize = 64 * 1024;
const MAX_REPORTED_MESSAGE_CHARS: usize = 8 * 1024;
const MAX_REPORTED_WARNING_CHARS: usize = 1024;
const MAX_WARNINGS: usize = 50;
/// `MustacheTemplateEngine.MAX_UNRESOLVED_VARIABLE_PASSES`.
const MAX_UNRESOLVED_VARIABLE_PASSES: usize = 20;

/// A server's dry runs: the slots of the ones running.
#[derive(Default)]
pub struct DryRuns {
    running: Arc<AtomicUsize>,
    /// `TemplateDryRun.velocity()`: the dry run's own Velocity engine (its own template counter).
    velocity: Arc<VelocityEngine>,
}

/// `TemplateWarning`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Warning {
    message: String,
    line: Option<i32>,
    column: Option<i32>,
}

/// The warnings of one run, in order, without repeats (`LinkedHashSet`), at most [`MAX_WARNINGS`].
#[derive(Default)]
struct Warnings(Mutex<Vec<Warning>>);

impl Warnings {
    fn add(&self, warning: Warning) {
        let mut warnings = self.0.lock();
        if warnings.len() < MAX_WARNINGS && !warnings.contains(&warning) {
            warnings.push(warning);
        }
    }
}

impl DryRuns {
    /// The runs holding a slot now (admitted, their thread not yet ended).
    pub fn running(&self) -> usize {
        self.running.load(Ordering::Acquire)
    }
}

thread_local! {
    /// `ScenarioTemplateHelper.SUPPRESSED_SETS`: while a dry run renders on this thread, a `scenario.set` is passed here
    /// instead of changing the live state.
    static SUPPRESSED_SETS: RefCell<Option<Arc<Warnings>>> = const { RefCell::new(None) };
}

/// `ScenarioTemplateHelper.set` under a dry run: `true` when the set was reported rather than applied.
pub(super) fn suppressed_set(name: &str, state: &str) -> bool {
    SUPPRESSED_SETS.with(|s| match s.borrow().as_ref() {
        Some(warnings) => {
            warnings.add(Warning { message: format!("scenario.set(\"{name}\", \"{state}\") was not applied: a dry run does not change scenario state"), line: None, column: None });
            true
        }
        None => false,
    })
}

struct Input {
    engine: Engine,
    template: String,
    forward: bool,
    request: HttpRequest,
}

impl Input {
    fn output(&self) -> Output {
        if self.forward { Output::Request } else { Output::Response }
    }

    fn action_type(&self) -> &'static str {
        if self.forward { "FORWARD_TEMPLATE" } else { "RESPONSE_TEMPLATE" }
    }
}

fn json_reply(status: u32, body: &Value) -> Reply {
    Reply::api_body(status, "application/json", crate::json::pretty(body))
}

/// `putCapped`: `value` cut to `max` UTF-16 units, with `<field>Truncated` set when it was cut.
fn put_capped(node: &mut Map<String, Value>, field: &str, value: &str, max: usize) {
    if value.encode_utf16().count() > max {
        let units: Vec<u16> = value.encode_utf16().take(max).collect();
        node.insert(field.into(), String::from_utf16_lossy(&units).into());
        node.insert(format!("{field}Truncated"), true.into());
    } else {
        node.insert(field.into(), value.into());
    }
}

fn report(input: &Input) -> Map<String, Value> {
    let mut report = Map::new();
    report.insert("templateType".into(), input.engine.type_name().into());
    report.insert("actionType".into(), input.action_type().into());
    report
}

fn failed_report(input: &Input, message: &str) -> Map<String, Value> {
    let mut report = report(input);
    report.insert("valid".into(), false.into());
    let mut error = Map::new();
    put_capped(&mut error, "message", message, MAX_REPORTED_MESSAGE_CHARS);
    report.insert("error".into(), Value::Object(error));
    report
}

/// `TemplateDryRun.timeoutMillis`: the engine's own limit (Velocity's, else JavaScript's, which Mustache shares), or
/// [`TIMEOUT_WHEN_DISABLED_MILLIS`] when it is 0 or less.
fn timeout_millis(state: &State, engine: Engine) -> i64 {
    let configured = match engine {
        Engine::Velocity => state.config.int_property("velocityTemplateExecutionTimeout", 5000),
        _ => state.config.int_property("javascriptTemplateExecutionTimeout", 5000),
    };
    if configured > 0 { configured } else { TIMEOUT_WHEN_DISABLED_MILLIS }
}

fn still_running(engine: Engine) -> &'static str {
    match engine {
        Engine::Velocity => "a Velocity template is stopped at its next loop iteration, macro call, #parse, #evaluate or #define block render, so one inside a long Java call may still be running",
        Engine::Mustache => "a Mustache template cannot be stopped, so it may still be running",
        Engine::JavaScript => "it may still be running until the JavaScript engine cancels it",
    }
}

/// `TemplateDryRun.parse`: the input, or the `400` message.
fn parse(request: &HttpRequest) -> Result<Input, String> {
    let body = request.body_str();
    if body.trim().is_empty() {
        return Err("a body is required: {\"templateType\": \"VELOCITY | MUSTACHE | JAVASCRIPT\", \"template\": \"...\", \"request\": {...}}".into());
    }
    if let Err(e) = crate::jnode::read_tree(&body) {
        return Err(format!("the body is not valid JSON: {}", e.message));
    }
    let node = match crate::json::parse_lenient(body.as_bytes()) {
        Ok(Value::Object(o)) => o,
        _ => return Err("the body must be a JSON object".into()),
    };
    // `JsonNode.asText(default)`: a missing or null node gives the default, a container gives "".
    let as_text = |v: Option<&Value>, default: &str| -> String {
        match v {
            None | Some(Value::Null) => default.to_string(),
            Some(Value::String(s)) => s.clone(),
            Some(v @ (Value::Number(_) | Value::Bool(_))) => v.to_string(),
            Some(_) => String::new(),
        }
    };
    let engine = match as_text(node.get("templateType"), "").trim().to_uppercase().as_str() {
        "VELOCITY" => Engine::Velocity,
        "MUSTACHE" => Engine::Mustache,
        "JAVASCRIPT" => Engine::JavaScript,
        _ => return Err("templateType must be VELOCITY, MUSTACHE or JAVASCRIPT".into()),
    };
    let template = match node.get("template") {
        Some(Value::String(t)) if !t.trim().is_empty() => t.clone(),
        _ => return Err("template is required, as a string".into()),
    };
    let forward = match as_text(node.get("actionType"), "RESPONSE_TEMPLATE").trim().to_uppercase().as_str() {
        "RESPONSE_TEMPLATE" => false,
        "FORWARD_TEMPLATE" => true,
        _ => return Err("actionType must be RESPONSE_TEMPLATE (the default) or FORWARD_TEMPLATE".into()),
    };
    let request = match node.get("request") {
        None | Some(Value::Null) => HttpRequest { method: "GET".into(), path: "/".into(), ..HttpRequest::default() },
        Some(sample) => {
            let text = crate::json::compact(sample);
            if let Err(report) = crate::schema::validate_http_message(sample, false) {
                return Err(format!("request is not a valid request: {}", crate::schema::incorrect_request(&text, &report)));
            }
            crate::cluster_fanin::request_from_json(sample)
        }
    };
    Ok(Input { engine, template, forward, request })
}

/// Decrements the running count when a run's thread ends, however it ends.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// `TemplateDryRun.test`: the reply to `PUT /mockserver/template/test`.
pub fn test(state: &Arc<State>, request: &HttpRequest) -> Reply {
    let input = match parse(request) {
        Ok(input) => input,
        Err(message) => {
            let mut error = Map::new();
            put_capped(&mut error, "error", &message, MAX_REPORTED_MESSAGE_CHARS);
            return json_reply(400, &Value::Object(error));
        }
    };
    let runs = &state.template_dry_runs;
    let admitted = runs.running.try_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < MAX_CONCURRENT_DRY_RUNS).then_some(n + 1)).is_ok();
    if !admitted {
        let message = format!("{MAX_CONCURRENT_DRY_RUNS} template dry runs are already running; retry when one finishes (a Mustache template that never finishes keeps its slot until MockServer restarts, and a Velocity template inside one long Java call keeps it until that call returns)");
        return json_reply(429, &serde_json::json!({ "error": message }));
    }
    let slot = Slot(runs.running.clone());
    let deadline_millis = timeout_millis(state, input.engine) + RESPONSE_GRACE_MILLIS;
    let mut timed_out = failed_report(&input, &format!("the template did not finish within {deadline_millis}ms; {}", still_running(input.engine)));
    timed_out.insert("timedOut".into(), true.into());
    let (tx, rx) = std::sync::mpsc::channel();
    let thread_state = state.clone();
    let spawned = std::thread::Builder::new().name("MockServer-TemplateDryRun".into()).spawn(move || {
        let _slot = slot;
        let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| evaluate(&thread_state, &input)))
            .unwrap_or_else(|_| failed_report(&input, "the template dry run failed"));
        let _ = tx.send(report);
    });
    if spawned.is_err() {
        return json_reply(500, &serde_json::json!({ "error": "the template dry run could not start" }));
    }
    let report = crate::blocking::off_worker(|| rx.recv_timeout(Duration::from_millis(deadline_millis as u64))).unwrap_or(timed_out);
    json_reply(200, &Value::Object(report))
}

/// `VelocityTemplateTimeoutException` as a dry-run engine words it (`explainDryRunTimeout`): serving's advice to set
/// the limit to 0 does not apply to a dry run.
fn velocity_timeout_message(state: &State) -> String {
    let configured = state.config.int_property("velocityTemplateExecutionTimeout", 5000);
    if configured <= 0 {
        format!("Velocity template execution exceeded {TIMEOUT_WHEN_DISABLED_MILLIS}ms and was stopped; mockserver.velocityTemplateExecutionTimeout is 0 or less, so serving does not time out, but a dry run always stops a Velocity template after {TIMEOUT_WHEN_DISABLED_MILLIS}ms")
    } else {
        format!("Velocity template execution exceeded the configured timeout of {configured}ms and was stopped; increase mockserver.velocityTemplateExecutionTimeout to give it longer")
    }
}

/// What rendering gave: the text, or what the engine threw.
enum Rendered {
    Text(String),
    Threw(Thrown),
}

/// `TemplateDryRun.evaluate`, on the run's own thread.
fn evaluate(state: &State, input: &Input) -> Map<String, Value> {
    let warnings = Arc::new(Warnings::default());
    let start = Instant::now();
    let previous = SUPPRESSED_SETS.with(|s| s.borrow_mut().replace(warnings.clone()));
    let (rendered, logged) = super::model::collect_warnings(|| render(state, input, &warnings));
    SUPPRESSED_SETS.with(|s| *s.borrow_mut() = previous);
    // The captured log's WARN entries, after the render's own warnings, unless the render threw.
    if !matches!(rendered, Rendered::Threw(_)) {
        for entry in logged {
            warnings.add(Warning { message: entry.message_text().to_string(), line: None, column: None });
        }
    }
    let mut report = report(input);
    report.insert("durationMillis".into(), (start.elapsed().as_millis() as u64).into());
    let mut rendered_output = None;
    match rendered {
        Rendered::Threw(thrown) => {
            report.insert("valid".into(), false.into());
            let mut error = Map::new();
            put_capped(&mut error, "message", &thrown.message, MAX_REPORTED_MESSAGE_CHARS);
            if let Some(line) = thrown.line {
                error.insert("line".into(), line.into());
            }
            if let Some(column) = thrown.column {
                error.insert("column".into(), column.into());
            }
            report.insert("error".into(), Value::Object(error));
            if thrown.timeout {
                report.insert("timedOut".into(), true.into());
            }
        }
        Rendered::Text(text) => match validate(&text, input.output()) {
            Ok(generated) => {
                report.insert("valid".into(), true.into());
                let (field, canonical) = match input.output() {
                    Output::Response => ("renderedResponse", crate::canonical::response(&generated)),
                    Output::Request => ("renderedRequest", crate::canonical::request_definition(&generated)),
                };
                if crate::json::pretty(&canonical).encode_utf16().count() <= MAX_REPORTED_OUTPUT_CHARS {
                    report.insert(field.into(), canonical);
                } else {
                    rendered_output = Some(crate::json::pretty(&generated));
                }
            }
            Err(errors) => {
                report.insert("valid".into(), false.into());
                let served = if super::failure_as_server_error(state) {
                    "500"
                } else if input.forward {
                    "502"
                } else {
                    "404"
                };
                let what = if input.forward { "request" } else { "response" };
                let mut error = Map::new();
                error.insert("message".into(), format!("the template rendered output that is not a valid {what}, so serving it would answer with a {served}").into());
                put_capped(&mut error, "validationErrors", &errors, MAX_REPORTED_MESSAGE_CHARS);
                report.insert("error".into(), Value::Object(error));
                rendered_output = Some(text);
            }
        },
    }
    if let Some(output) = rendered_output {
        put_capped(&mut report, "renderedOutput", &output, MAX_REPORTED_OUTPUT_CHARS);
    }
    let warnings = warnings.0.lock();
    if !warnings.is_empty() {
        let list = warnings
            .iter()
            .map(|w| {
                let mut node = Map::new();
                put_capped(&mut node, "message", &w.message, MAX_REPORTED_WARNING_CHARS);
                if let Some(line) = w.line {
                    node.insert("line".into(), line.into());
                }
                if let Some(column) = w.column {
                    node.insert("column".into(), column.into());
                }
                Value::Object(node)
            })
            .collect();
        report.insert("warnings".into(), Value::Array(list));
    }
    report
}

/// `HttpTemplateOutputDeserializer.deserializer` without its log entries: the generated response or request, or the
/// validation errors its `TEMPLATE_GENERATION_FAILED` entry carries.
fn validate(text: &str, output: Output) -> Result<Value, String> {
    let response = output == Output::Response;
    let generated = match crate::json::parse_lenient(text.as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            if text.trim().is_empty() {
                // `isValid` passes blank output; reading it then fails
                return Err(format!("No content to map due to end-of-input\n at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: {}]", 1 + text.matches('\n').count()));
            }
            return Err(match crate::jnode::read_tree(text) {
                Err(e) => format!("{} - {}", e.class.rsplit('.').next().unwrap_or_default(), e.message),
                Ok(_) => e.to_string(),
            });
        }
    };
    crate::schema::validate_http_message(&generated, response).map(|()| generated).map_err(super::with_status_code_hint)
}

/// Renders the template as `TemplateDryRun.render` does: the serving engines, with warnings collected.
fn render(state: &State, input: &Input, warnings: &Arc<Warnings>) -> Rendered {
    let source = &input.template;
    if let Some(message) = super::disallowed(state, input.engine, source) {
        return Rendered::Threw(Thrown::plain(message));
    }
    let faker = super::faker_binding(state, input.engine);
    let path = PathMatch::default();
    match input.engine {
        Engine::JavaScript => Rendered::Threw(Thrown::plain(super::GRAALJS_MISSING.to_string())),
        Engine::Velocity if !crate::foreign::velocity_sandboxed(state) => {
            let foreign = state.foreign.as_ref().expect("an unsandboxed engine has a foreign runtime");
            match state.scenarios().scope(|| foreign.render_unsandboxed_velocity(source, &crate::recorded::input_request(&input.request))) {
                Ok(text) => Rendered::Text(text),
                Err(message) => Rendered::Threw(Thrown::plain(message)),
            }
        }
        Engine::Velocity => {
            let millis = timeout_millis(state, Engine::Velocity);
            let timeout = java_compat::lang::JError::new(super::VELOCITY_TIMEOUT_CLASS, velocity_timeout_message(state));
            let _deadline = ::velocity::deadline::start(Some(Duration::from_millis(millis as u64)), timeout);
            let engine = super::velocity_engine(state, &state.template_dry_runs.velocity);
            let cartridge = ::velocity::events::EventCartridge::new();
            cartridge.add(::velocity::events::Handler { invalid_reference: Some(Arc::new(UnresolvedReferences(warnings.clone()))), ..Default::default() });
            let (rendered, _failures) = super::extract::collect(|| state.scenarios().scope(|| super::velocity::render_with_cartridge(&engine, source, &input.request, &path, None, &faker, Some(cartridge))));
            match rendered {
                Ok(text) => Rendered::Text(text),
                Err(e) => Rendered::Threw(super::velocity_failure(e)),
            }
        }
        Engine::Mustache => {
            let (rendered, _failures) = super::extract::collect(|| state.scenarios().scope(|| super::mustache::render(source, &input.request, &path, None, &faker)));
            match rendered {
                Ok(text) => {
                    unresolved_variables(state, source, &input.request, &faker, warnings);
                    Rendered::Text(text)
                }
                Err(e) => Rendered::Threw(super::mustache_failure(e)),
            }
        }
    }
}

const RENDERED_AS_WRITTEN: &str = " did not resolve, so it was rendered as written (write $!{...} where a missing value should render nothing)";

/// `VelocityTemplateEngine.reportUnresolvedReferences`' `InvalidReferenceEventHandler`.
struct UnresolvedReferences(Arc<Warnings>);

impl UnresolvedReferences {
    fn report(&self, message: String, info: &::velocity::events::Info) {
        self.0.add(Warning { message, line: (info.line > 0).then_some(info.line), column: (info.column > 0).then_some(info.column) });
    }
}

impl ::velocity::events::InvalidReferenceEventHandler for UnresolvedReferences {
    fn invalid_get_method(&self, _: &::velocity::Engine, _: &::velocity::Context, reference: &str, _: &JValue, _: Option<&str>, info: &::velocity::events::Info) -> Result<JValue, ::velocity::VelocityError> {
        self.report(format!("{reference}{RENDERED_AS_WRITTEN}"), info);
        Ok(JValue::Null)
    }

    fn invalid_set_method(&self, _: &::velocity::Engine, _: &::velocity::Context, left: &str, right: &str, info: &::velocity::events::Info) -> Result<bool, ::velocity::VelocityError> {
        self.report(format!("{right} did not resolve, so {left} was not set"), info);
        Ok(false)
    }

    fn invalid_method(&self, _: &::velocity::Engine, _: &::velocity::Context, reference: &str, _: &JValue, _: &str, info: &::velocity::events::Info) -> Result<JValue, ::velocity::VelocityError> {
        self.report(format!("{reference}{RENDERED_AS_WRITTEN}"), info);
        Ok(JValue::Null)
    }
}

/// `MustacheTemplateEngine.reportUnresolvedVariables`: jmustache stops at the first variable that does not resolve, so
/// each pass binds the names found so far to empty text at the top level and renders again. A first component found
/// missing (`reqest` in `reqest.path`) is replaced by the full name when the next pass reports it on the same line.
fn unresolved_variables(state: &State, source: &str, request: &HttpRequest, extra: &[(&str, JValue)], warnings: &Warnings) {
    let mut unresolved: Vec<(String, usize)> = Vec::new();
    let mut bound: Vec<(String, JValue)> = Vec::new();
    for _ in 0..MAX_UNRESOLVED_VARIABLE_PASSES {
        let mut bindings: Vec<(&str, JValue)> = extra.to_vec();
        bindings.extend(bound.iter().map(|(k, v)| (k.as_str(), v.clone())));
        let path = PathMatch::default();
        let (result, _) = super::extract::collect(|| state.scenarios().scope(|| super::mustache::render_strict(source, request, &path, &bindings)));
        let Err(e) = result else { break };
        let Some((key, line)) = super::mustache::missing_variable(&e) else { break };
        if bound.iter().any(|(k, _)| *k == key) {
            break;
        }
        bound.push((key.clone(), JValue::str("")));
        unresolved.retain(|(found, found_line)| !(key.starts_with(&format!("{found}.")) && *found_line == line));
        match unresolved.iter_mut().find(|(k, _)| *k == key) {
            Some(entry) => entry.1 = line,
            None => unresolved.push((key, line)),
        }
    }
    for (name, line) in unresolved {
        warnings.add(Warning { message: format!("{{{{{name}}}}} did not resolve against this request, so it rendered as empty text"), line: (line > 0).then_some(line as i32), column: None });
    }
}

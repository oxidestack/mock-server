//! Response and forward templates (`org.mockserver.templates`): an engine renders the template against the
//! request, and `HttpTemplateOutputDeserializer` turns the text into the response or request to use.

pub mod dry_run;
pub mod extract;
mod faker;
mod format_xml;
mod lists;
pub mod system_value;
mod functions;
pub(crate) mod dates;
mod java_time;
mod jwt;
mod md5;
pub mod model;
mod mustache;
mod velocity;


use serde_json::Value;

pub use faker::Fakers;
pub use lists::Lists;
pub use model::PathMatch;
pub use velocity::Instance as VelocityEngine;

use crate::request::HttpRequest;
use crate::state::State;

/// `HttpTemplate.TemplateType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    Velocity,
    JavaScript,
    Mustache,
}

/// An `HttpTemplate` action (`httpResponseTemplate`, `httpForwardTemplate`, a forward's `responseTemplate`).
#[derive(Debug, Clone)]
pub struct Template {
    pub engine: Engine,
    pub source: String,
    /// `templateFile`: read (classpath, then file system) on every render when `template` is blank.
    pub file: Option<String>,
    /// `parameters`, bound as `parameters` when not empty (a read-only copy at every depth).
    pub parameters: Option<java_compat::lang::JValue>,
}

impl Engine {
    pub fn parse(name: Option<&str>) -> Engine {
        match name {
            Some("JAVASCRIPT") => Engine::JavaScript,
            Some("MUSTACHE") => Engine::Mustache,
            _ => Engine::Velocity,
        }
    }
}

/// The `VelocityTemplateEngine` instances a server's handlers build, one each; a Velocity error names its template by
/// the instance's counter (`t0`, `t1`, …), so each counts the templates it alone has rendered. A load run and a gRPC
/// bidirectional stream hold their own.
#[derive(Default)]
pub struct VelocityEngines {
    /// `HttpResponseTemplateActionHandler`'s.
    pub response: VelocityEngine,
    /// `HttpForwardTemplateActionHandler`'s.
    pub forward: VelocityEngine,
    /// `HttpOverrideForwardedRequestActionHandler`'s (a forward's `responseTemplate`).
    pub override_forward: VelocityEngine,
    /// `HttpResponseActionHandler`'s `FileBodyMaterialiser`.
    pub file_body: VelocityEngine,
    /// `DelayTemplateResolver`'s.
    pub delay: VelocityEngine,
    /// `HttpSseResponseActionHandler`'s `StreamTemplateRenderer`.
    pub sse: VelocityEngine,
    /// `HttpWebSocketResponseActionHandler`'s `StreamTemplateRenderer`.
    pub websocket: VelocityEngine,
    /// `GrpcStreamResponseActionHandler`'s `StreamTemplateRenderer`.
    pub grpc_stream: VelocityEngine,
}

/// `instance`'s engine as the configuration stands (`currentEngineHolder`).
fn velocity_engine(state: &State, instance: &VelocityEngine) -> std::sync::Arc<::velocity::Engine> {
    instance.engine(state.config.bool_property("velocityDisallowClassLoading", true))
}

/// `VelocityTemplateTimeoutException`: what a Velocity render still running after `velocityTemplateExecutionTimeout`
/// fails with.
const VELOCITY_TIMEOUT_CLASS: &str = "org.mockserver.templates.engine.velocity.VelocityTemplateTimeoutException";

/// `RenderDeadline.start(velocityTemplateExecutionTimeout)` for the renders on this thread until the scope is dropped:
/// 0 or less means none.
fn velocity_deadline(state: &State) -> ::velocity::deadline::Scope {
    let millis = state.config.int_property("velocityTemplateExecutionTimeout", 5000);
    let message = format!("Velocity template execution exceeded the configured timeout of {millis}ms and was stopped; increase mockserver.velocityTemplateExecutionTimeout or set it to 0 to disable the timeout");
    let timeout = (millis > 0).then(|| std::time::Duration::from_millis(millis as u64));
    ::velocity::deadline::start(timeout, java_compat::lang::JError::new(VELOCITY_TIMEOUT_CLASS, message))
}

fn is_blank(s: &str) -> bool {
    s.chars().all(char::is_whitespace)
}

/// `FileReader.readBytesFromClassPathOrPath`: a resource of the class path (`crate::class_path`), else a file,
/// relative ones resolved against the working directory. `Err` carries the `RuntimeException` message.
pub fn read_file(path: &str) -> Result<Vec<u8>, String> {
    read_file_failing(path).map_err(|f| f.message)
}

/// Why [`read_file`] failed: the `RuntimeException`'s message and its cause's (`FileNotFoundException`).
#[derive(Debug)]
pub struct ReadFailure {
    pub message: String,
    pub cause: String,
}

fn read_file_failing(path: &str) -> Result<Vec<u8>, ReadFailure> {
    crate::class_path::read_or_file(path).map_err(|e| ReadFailure { message: format!("Exception while loading \"{path}\""), cause: java_io_message(path, &e) })
}

/// `FileInputStream`'s `FileNotFoundException` message: the canonical path, then the OS reason in parentheses.
fn java_io_message(path: &str, e: &std::io::Error) -> String {
    let file = std::path::Path::new(path);
    let absolute = if file.is_absolute() { file.to_path_buf() } else { std::env::current_dir().map(|d| d.join(file)).unwrap_or_else(|_| file.to_path_buf()) };
    // `getCanonicalFile`: what exists of the path resolved, the rest appended as written
    let canonical = match (absolute.parent().and_then(|p| std::fs::canonicalize(p).ok()), absolute.file_name()) {
        (Some(parent), Some(name)) => parent.join(name),
        _ => absolute,
    };
    let reason = match e.kind() {
        std::io::ErrorKind::NotFound => "No such file or directory".to_string(),
        std::io::ErrorKind::PermissionDenied => "Permission denied".to_string(),
        _ if canonical.is_dir() => "Is a directory".to_string(),
        _ => e.to_string(),
    };
    format!("{} ({reason})", canonical.display())
}

impl Template {
    pub fn compile(v: &Value) -> Template {
        Template {
            engine: Engine::parse(v.get("templateType").and_then(Value::as_str)),
            source: v.get("template").and_then(Value::as_str).unwrap_or_default().to_string(),
            file: v.get("templateFile").and_then(Value::as_str).map(str::to_string),
            parameters: v.get("parameters").and_then(Value::as_object).filter(|p| !p.is_empty()).map(|p| read_only(&Value::Object(p.clone()))),
        }
    }
}

/// `HttpTemplate.withParameters`' `readOnlyCopy` of the values Jackson read as `Map<String, Object>`: unmodifiable
/// maps and lists at every depth, whole numbers as `Integer` or `Long`, others as `Double`.
fn read_only(v: &Value) -> java_compat::lang::JValue {
    use java_compat::lang::{JList, JMap, JValue, ListKind, MapKind};
    match v {
        Value::Null => JValue::Null,
        Value::Bool(b) => JValue::Bool(*b),
        Value::String(s) => JValue::str(s.as_str()),
        Value::Number(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) if i32::try_from(i).is_ok() => JValue::Int(i as i32),
            (Some(i), _) => JValue::Long(i),
            (None, _) if n.as_u64().is_some() || !n.to_string().contains(['.', 'e', 'E']) => JValue::BigInteger(n.to_string().into()),
            (None, Some(d)) => JValue::Double(d),
            (None, None) => JValue::str(n.to_string()),
        },
        Value::Array(items) => JValue::List(JList::new(ListKind::Fixed, items.iter().map(read_only).collect())),
        Value::Object(o) => JValue::Map(JMap::from_entries(MapKind::Fixed, o.iter().map(|(k, v)| (JValue::str(k.as_str()), read_only(v))))),
    }
}

/// `Collections.unmodifiableMap` / `unmodifiableList` over a [`read_only`] value, as Velocity sees it: reads go to
/// the map or list, what they return is wrapped the same way, and every change throws
/// `UnsupportedOperationException`. Mustache only reads, so it gets the values unwrapped.
struct Unmodifiable(java_compat::lang::JValue);

impl Unmodifiable {
    fn wrap(v: java_compat::lang::JValue) -> java_compat::lang::JValue {
        use java_compat::lang::JValue;
        match v {
            JValue::Map(_) | JValue::List(_) => JValue::Object(std::sync::Arc::new(Unmodifiable(v))),
            other => other,
        }
    }
}

const MAP_CHANGES: &[&str] = &["put", "remove", "putAll", "clear", "putIfAbsent", "replace", "computeIfAbsent", "computeIfPresent", "compute", "merge", "replaceAll"];
const LIST_CHANGES: &[&str] = &["add", "set", "remove", "clear", "addAll", "removeAll", "retainAll", "sort", "replaceAll", "removeIf", "addFirst", "addLast", "removeFirst", "removeLast"];

impl java_compat::lang::JObject for Unmodifiable {
    fn class_name(&self) -> String {
        match self.0 {
            java_compat::lang::JValue::Map(_) => "java.util.Collections$UnmodifiableMap".into(),
            _ => "java.util.Collections$UnmodifiableRandomAccessList".into(),
        }
    }

    fn invoke(&self, name: &str, args: &[java_compat::lang::JValue]) -> Option<Result<Option<java_compat::lang::JValue>, java_compat::lang::JError>> {
        let changes = if matches!(self.0, java_compat::lang::JValue::Map(_)) { MAP_CHANGES } else { LIST_CHANGES };
        if changes.contains(&name) {
            // only when the map or list has such a method for these arguments; what it answers is not used
            let _ = java_compat::methods::invoke(&self.0, name, args)?;
            return Some(Err(java_compat::lang::JError::without_message("java.lang.UnsupportedOperationException")));
        }
        Some(java_compat::methods::invoke(&self.0, name, args)?.map(|v| v.map(Unmodifiable::wrap)))
    }

    fn to_java_string(&self) -> String {
        self.0.to_java_string()
    }

    fn iterate(&self) -> Option<Vec<java_compat::lang::JValue>> {
        Some(self.0.iterate()?.into_iter().map(Unmodifiable::wrap).collect())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Template {
    /// `HttpTemplate.getTemplateContent`.
    pub fn content(&self) -> Result<String, ReadFailure> {
        if !is_blank(&self.source) {
            return Ok(self.source.clone());
        }
        match self.file.as_deref().filter(|f| !is_blank(f)) {
            Some(f) => read_file_failing(f).map(|b| String::from_utf8_lossy(&b).into_owned()),
            None => Ok(self.source.clone()),
        }
    }
}

/// `validateTemplate` of the Velocity and Mustache engines: `velocityDisallowedText` / `mustacheDisallowedText` split
/// on commas and trimmed (Guava's `Splitter.on(",").trimResults()`, which keeps empty parts, and an empty part is in
/// every template). The failure message when `source` holds one of them.
pub fn disallowed(state: &State, engine: Engine, source: &str) -> Option<String> {
    let name = match engine {
        Engine::Velocity => "velocityDisallowedText",
        Engine::Mustache => "mustacheDisallowedText",
        Engine::JavaScript => return None,
    };
    let denied = state.config.property(name)?;
    if source.trim().is_empty() || denied.trim().is_empty() {
        return None;
    }
    denied.split(',').map(str::trim).find(|d| source.contains(d)).map(|d| format!("Found disallowed string \"{d}\" in template: {source}"))
}

/// `TemplateEngine.renderTemplate`: the rendered text (a file body, a delay), without a response; a Velocity
/// template renders on `instance`.
pub fn render_text(state: &State, instance: &VelocityEngine, engine: Engine, source: &str, request: &HttpRequest) -> Result<String, String> {
    let faker = faker_binding(state, engine);
    let _deadline = velocity_deadline(state);
    logged(state, request, || state.scenarios().scope(|| render_text_bound(&|| velocity_engine(state, instance), engine, source, request, &faker)))
}

/// [`system_value::logged`] around the render, with the WARN entries its request objects logged (a cap stopping
/// `formData` or `parts`, `HttpRequestTemplateObject.warn`) logged about `request` as it ends.
fn logged<T>(state: &State, request: &HttpRequest, render: impl FnOnce() -> T) -> T {
    system_value::logged(state, || {
        let (out, warnings) = model::collect_warnings(render);
        for warning in warnings {
            crate::log::warn_event_about(state, warning, request);
        }
        out
    })
}

/// The engine's own helpers as bindings over the shared ones: its seeded `faker` and `lists` (when
/// `templateFakerSeed` is set), `hostname` from the server's environment and `systemValue` (refusals are logged by
/// [`system_value::logged`] around the render).
fn faker_binding(state: &State, engine: Engine) -> Vec<(&'static str, java_compat::lang::JValue)> {
    let faker = state.template_fakers.seeded(&state.config, engine).map(|f| ("faker", f));
    let lists = state.template_lists.seeded(&state.config, engine).map(|l| ("lists", l));
    let hostname = ("hostname", functions::hostname(state.config.env_var("HOSTNAME")));
    let system_value = system_value::SystemValue::new(state);
    let system_value = ("systemValue", if engine == Engine::Mustache { system_value.mustache() } else { system_value.velocity() });
    faker.into_iter().chain(lists).chain([hostname, system_value]).collect()
}

/// [`render_text`] under whatever scenarios the calling thread's scope holds (none: `scenario.get` is `Started`).
/// Velocity's shared engine binds `ON_DEMAND_HELPERS`; Mustache gets their `hostname` and `systemValue` (reading
/// nothing) here.
pub fn render_text_unscoped(engine: Engine, source: &str, request: &HttpRequest) -> Result<String, String> {
    let on_demand: Vec<(&str, java_compat::lang::JValue)> = match engine {
        Engine::Mustache => vec![("hostname", functions::hostname(std::env::var("HOSTNAME").ok())), ("systemValue", system_value::SystemValue::nothing().mustache())],
        _ => Vec::new(),
    };
    render_text_bound(&velocity::shared, engine, source, request, &on_demand)
}

/// `HttpRequestTemplateObject`'s `pathParameters`: what the match set on the request (`withPathParameters`), e.g.
/// for a `FILE` body's templated path and contents.
fn request_path_match(request: &HttpRequest) -> PathMatch {
    PathMatch { parameters: request.path_parameters.clone(), ..PathMatch::default() }
}

type EngineOf<'a> = &'a dyn Fn() -> std::sync::Arc<::velocity::Engine>;

fn render_text_bound(velocity_engine: EngineOf, engine: Engine, source: &str, request: &HttpRequest, extra: &[(&str, java_compat::lang::JValue)]) -> Result<String, String> {
    let path = request_path_match(request);
    match engine {
        Engine::Mustache => mustache::render(source, request, &path, None, extra).map_err(|e| e.message().unwrap_or_else(|| e.simple_class_name())),
        Engine::Velocity => velocity::render(&velocity_engine(), source, request, &path, None, extra).map_err(|e| e.message()),
        Engine::JavaScript => Err("JavaScript templates cannot render text".into()),
    }
}

/// `TemplateEngine.renderTemplate(template, request, iteration)`: text rendered with `extra` bindings besides the
/// usual ones (a load step's `iteration`).
pub fn render_with(state: &State, instance: &VelocityEngine, engine: Engine, source: &str, request: &HttpRequest, extra: &[(&str, java_compat::lang::JValue)]) -> Result<String, String> {
    let path = request_path_match(request);
    let mut bindings = faker_binding(state, engine);
    bindings.extend(extra.iter().cloned());
    let extra = bindings.as_slice();
    let _deadline = velocity_deadline(state);
    logged(state, request, || state.scenarios().scope(|| match engine {
        Engine::Mustache => mustache::render(source, request, &path, None, extra).map_err(|e| e.message().unwrap_or_else(|| e.simple_class_name())),
        Engine::Velocity => velocity::render(&velocity_engine(state, instance), source, request, &path, None, extra).map_err(|e| e.message()),
        Engine::JavaScript => Err("JavaScript templates are not supported here".into()),
    }))
}

/// What the rendered text must be: `HttpResponseDTO` or `HttpRequestDTO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    Response,
    Request,
}

/// The template's role, as `TemplateFailureException` names it: a response template, a forward template, a forward's
/// `responseTemplate` or a side action's `httpRequestTemplate` (a webhook).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Response,
    Forward,
    ForwardResponse,
    Webhook,
}

impl Role {
    fn output(self) -> Output {
        match self {
            Role::Forward | Role::Webhook => Output::Request,
            Role::Response | Role::ForwardResponse => Output::Response,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Role::Response => "response",
            Role::Forward => "forward",
            Role::ForwardResponse => "forward response",
            Role::Webhook => "webhook",
        }
    }
}

impl Engine {
    /// `HttpTemplate.TemplateType`'s name.
    pub fn type_name(self) -> &'static str {
        match self {
            Engine::Velocity => "VELOCITY",
            Engine::JavaScript => "JAVASCRIPT",
            Engine::Mustache => "MUSTACHE",
        }
    }
}

/// Rendering failed (`TemplateFailureException`): the engine threw, or the output is not a valid response/request.
///
/// `after` is the WARN entry `handleAnyException` logs once the answer is written (type `WARN`, level INFO, with the
/// exception as its throwable); the caller logs it after the response entry.
#[derive(Debug)]
pub struct Failed {
    pub after: Option<Box<crate::recorded::LogEntry>>,
    /// `TemplateFailureException.getDetail()`: what a `500` tells the client.
    pub detail: String,
    /// The output was rendered but is not a valid response/request (rather than the engine throwing).
    pub invalid_output: bool,
    pub role: Role,
    /// `TemplateFailureException.loggedFailure()`: the engine's exception, or the `TemplateFailureException` itself for
    /// output that is not valid. Boxed, so a `Result` that may fail rendering stays small.
    pub logged: Box<Exception>,
}

/// A Java exception as a log entry shows it: its class, `getMessage()` and the bean Jackson writes for it.
#[derive(Debug, Clone)]
pub struct Exception {
    pub class: String,
    pub message: String,
    pub bean: Value,
}

impl Exception {
    fn new(class: &str, message: String, bean: Value) -> Exception {
        Exception { class: class.to_string(), message, bean }
    }

    fn plain(class: &str, message: String) -> Exception {
        let bean = serde_json::json!({"localizedMessage": message, "message": message, "stackTrace": []});
        Exception::new(class, message, bean)
    }

    /// `toString()`: the class, then `: message`.
    pub fn java_string(&self) -> String {
        format!("{}: {}", self.class, self.message)
    }

    /// An exception wrapping this one whose message is this one's `toString()` (`CompletionException`'s).
    pub fn wrapped_bean(&self) -> Value {
        let message = self.java_string();
        serde_json::json!({"cause": self.bean, "localizedMessage": message, "message": message, "stackTrace": []})
    }
}

/// `TemplateFailureException`.
const TEMPLATE_FAILURE_CLASS: &str = "org.mockserver.mock.action.http.TemplateFailureException";

/// `TemplateFailureException.MAX_DETAIL_LENGTH`.
const MAX_DETAIL_LENGTH: usize = 8192;

/// `StringUtils.abbreviate(text, max)`: cut to `max` UTF-16 units, the last three of them `...`.
fn abbreviate(text: String, max: usize) -> String {
    if text.encode_utf16().count() <= max {
        return text;
    }
    let mut units = 0;
    let mut cut = String::new();
    for c in text.chars() {
        units += c.len_utf16();
        if units > max - 3 {
            break;
        }
        cut.push(c);
    }
    cut + "..."
}

impl Failed {
    /// `new TemplateFailureException(type, role, failure)`: the engine's message, then the template line and column.
    fn threw(engine: Engine, role: Role, thrown: &Thrown, logged: Exception, after: Option<Box<crate::recorded::LogEntry>>) -> Failed {
        let mut message = thrown.message.clone();
        if let Some(line) = thrown.line {
            message.push_str(&format!("\nat template line {line}"));
            if let Some(column) = thrown.column {
                message.push_str(&format!(", column {column}"));
            }
        }
        Failed { after, detail: abbreviate(format!("{} {} template failed: {message}", engine.type_name(), role.name()), MAX_DETAIL_LENGTH), invalid_output: false, role, logged: Box::new(logged) }
    }

    /// The template rendered output that is not a valid response or request. The exception is its own logged
    /// failure: `handleAnyException`'s WARN (when the failure answers `500`) carries the detail as its message.
    fn invalid(state: &State, engine: Engine, role: Role, errors: &str) -> Failed {
        let renders = match role.output() {
            Output::Response => "response",
            Output::Request => "request",
        };
        let errors = if errors.trim().is_empty() { String::new() } else { format!(": {errors}") };
        let detail = abbreviate(format!("{} {} template rendered output that is not a valid {renders}{errors}", engine.type_name(), role.name()), MAX_DETAIL_LENGTH);
        let logged = Exception::plain(TEMPLATE_FAILURE_CLASS, detail.clone());
        let after = state.info_enabled().then(|| {
            Box::new(crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, detail.clone()).level(crate::recorded::Level::Info).throwable(logged.java_string()).throwable_bean(logged.bean.clone()))
        });
        Failed { after, detail, invalid_output: true, role, logged: Box::new(logged) }
    }

    /// A template without its `templateType` (`renderWebhookTemplate`'s `IllegalArgumentException`): no engine to name.
    pub fn untyped(role: Role) -> Failed {
        let message = "templateType is required".to_string();
        let detail = format!("{} template failed: {message}", role.name());
        Failed { after: None, detail, invalid_output: false, role, logged: Box::new(Exception::plain("java.lang.IllegalArgumentException", message)) }
    }

    /// The WARN to log after the answer: none when output that is not valid falls back to the action's own answer
    /// (`templateFailureAsServerError` false: the render returned null, nothing was thrown).
    pub fn take_after(&mut self, server_error: bool) -> Option<Box<crate::recorded::LogEntry>> {
        let after = self.after.take();
        if self.invalid_output && !server_error { None } else { after }
    }

    /// The `TemplateFailureException` thrown for this failure: its message is the logged failure's (the detail for
    /// output that is not valid), its cause the logged failure.
    pub fn template_failure(&self) -> Exception {
        if self.invalid_output {
            return (*self.logged).clone();
        }
        let message = self.logged.message.clone();
        let bean = serde_json::json!({"cause": self.logged.bean, "localizedMessage": message, "message": message, "stackTrace": []});
        Exception::new(TEMPLATE_FAILURE_CLASS, message, bean)
    }
}

/// `templateFailureAsServerError` (default true since 9.1.0): a failed template answers `500` rather than the
/// action's own fallback (404, or 502 for a forward).
pub fn failure_as_server_error(state: &State) -> bool {
    state.config.bool_property("templateFailureAsServerError", true)
}

/// `HttpActionHandler.templateFailureResponse`: the reply and its logged form.
pub fn failure_reply(failed: &Failed) -> (crate::reply::Reply, Value) {
    let reply = crate::reply::Reply {
        status: 500,
        reason: Some("Internal Server Error".into()),
        headers: vec![("x-mockserver-template-error".into(), "true".into()), ("content-type".into(), "text/plain; charset=utf-8".into())],
        body: failed.detail.clone().into_bytes().into(),
        ..crate::reply::Reply::default()
    };
    let logged = serde_json::json!({
        "statusCode": 500,
        "reasonPhrase": "Internal Server Error",
        "headers": {"x-mockserver-template-error": ["true"], "content-type": ["text/plain; charset=utf-8"]},
        "body": failed.detail,
    });
    (reply, logged)
}

/// What an engine threw: `getMessage()` (else the class's simple name), the bean of the engine's exception, and the
/// template line and column `TemplateEvaluationException` carries when the engine reports them.
struct Thrown {
    message: String,
    cause: Value,
    line: Option<i32>,
    column: Option<i32>,
    /// A `VelocityTemplateTimeoutException`, which is not wrapped as a transform failure.
    timeout: bool,
}

impl Thrown {
    fn plain(message: String) -> Thrown {
        let cause = cause_bean(Some(&message), &[]);
        Thrown { message, cause, line: None, column: None, timeout: false }
    }
}

/// `JavaScriptTemplateEngine.assertPolyglotAvailable`: the oracle ships without GraalJS, so every render fails with this.
const GRAALJS_MISSING: &str = "JavaScript response templates require the GraalJS engine, which is not on the classpath. Add the org.graalvm.polyglot:js (or js-community) dependency, or use the Velocity or Mustache template engine.";

/// `JavaScriptTemplateEngine.assertPolyglotAvailable`'s ERROR entry about `request`, logged before it throws.
pub fn log_graaljs_missing(state: &State, request: &HttpRequest) {
    if crate::log::error_enabled(state) {
        crate::log::error(state, GRAALJS_MISSING);
        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, GRAALJS_MISSING);
        state.log.message_about(entry, crate::recorded::Subject::Request(std::sync::Arc::new(request.clone())));
    }
}

/// `executeTemplate`: the generated response or request (input JSON form), or the failure; [`Failed::invalid_output`]
/// when the output is not a valid response/request (the action's own fallback without `templateFailureAsServerError`:
/// 404 for a response template, 502 for a forward, the upstream's response for a forward's `responseTemplate`).
pub fn execute(state: &State, instance: &VelocityEngine, template: &Template, request: &HttpRequest, path: &PathMatch, response: Option<&Value>, role: Role) -> Result<Value, Failed> {
    let output = role.output();
    let source = match template.content() {
        Ok(s) => s,
        Err(failure) => {
            crate::log::warn(state, &failure.message);
            let logged = Exception::plain("java.lang.RuntimeException", failure.message.clone());
            return Err(Failed::threw(template.engine, role, &Thrown::plain(failure.cause), logged, None));
        }
    };
    let mut faker = faker_binding(state, template.engine);
    let parameters = template.parameters.clone().map(|p| if template.engine == Engine::Velocity { Unmodifiable::wrap(p) } else { p });
    faker.extend(parameters.map(|p| ("parameters", p)));
    let deadline = velocity_deadline(state);
    let (rendered, failures) = extract::collect(|| logged(state, request, || state.scenarios().scope(|| match template.engine {
        _ if let Some(message) = disallowed(state, template.engine, &source) => Err(Thrown::plain(message)),
        Engine::Mustache => mustache::render(&source, request, path, response, &faker).map_err(mustache_failure),
        Engine::Velocity if !crate::foreign::velocity_sandboxed(state) => {
            instance.touch(false);
            let foreign = state.foreign.as_ref().expect("an unsandboxed engine has a foreign runtime");
            foreign.render_unsandboxed_velocity(&source, &crate::recorded::input_request(request)).map_err(Thrown::plain)
        }
        Engine::Velocity => velocity::render(&velocity_engine(state, instance), &source, request, path, response, &faker).map_err(velocity_failure),
        // The oracle ships without GraalJS: `JavaScriptTemplateEngine.assertPolyglotAvailable` fails every render.
        // It first logs an ERROR about the request, then throws; `handleAnyException` logs the WARN after the answer.
        Engine::JavaScript => {
            log_graaljs_missing(state, request);
            Err(Thrown::plain(GRAALJS_MISSING.to_string()))
        }
    })));
    drop(deadline);
    log_extraction_failures(state, request, &failures);
    let text = match rendered {
        Ok(text) => text,
        Err(thrown) if template.engine == Engine::JavaScript => {
            // The WARN is `Level.INFO` upstream, so the console prints it as INFO and it needs the INFO level.
            let message = &thrown.message;
            let after = state.info_enabled().then(|| {
                crate::log::info_as(state, crate::recorded::Kind::Warn, message);
                Box::new(crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, message.clone()).level(crate::recorded::Level::Info).throwable(format!("java.lang.RuntimeException: {message}")))
            });
            let logged = Exception::plain("java.lang.RuntimeException", message.clone());
            return Err(Failed::threw(template.engine, role, &thrown, logged, after));
        }
        Err(thrown) if thrown.timeout => {
            // `loggedTimeout`: a WARN about the request as the render stops; the timeout itself is the failure, not
            // wrapped as a transform failure, and `handleAnyException` logs it after the answer.
            crate::log::warn_event_about(state, crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, thrown.message.clone()), request);
            let logged = Exception::plain(VELOCITY_TIMEOUT_CLASS, thrown.message.clone());
            let after = state.info_enabled().then(|| {
                crate::log::info_as(state, crate::recorded::Kind::Warn, &thrown.message);
                Box::new(crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, thrown.message.clone()).level(crate::recorded::Level::Info).throwable(logged.java_string()).throwable_bean(logged.bean.clone()))
            });
            return Err(Failed::threw(template.engine, role, &thrown, logged, after));
        }
        Err(thrown) => {
            // `handleAnyException`: the exception (`TemplateEvaluationException`) is the WARN's throwable, logged (at
            // `Level.INFO`) after the answer is written.
            let text = crate::matcher::format_log_message(0, "Exception:{} transforming template:{} for request:{}", &[&thrown.message, &source, &crate::recorded::log_value(&crate::recorded::logged(request))]);
            let mut bean = serde_json::Map::new();
            bean.insert("cause".into(), thrown.cause.clone());
            if let Some(column) = thrown.column {
                bean.insert("column".into(), column.into());
            }
            if let Some(line) = thrown.line {
                bean.insert("line".into(), line.into());
            }
            bean.insert("localizedMessage".into(), text.clone().into());
            bean.insert("message".into(), text.clone().into());
            bean.insert("stackTrace".into(), Value::Array(Vec::new()));
            let logged = Exception::new("org.mockserver.templates.engine.TemplateEvaluationException", text.clone(), Value::Object(bean));
            let after = state.info_enabled().then(|| {
                crate::log::info_as(state, crate::recorded::Kind::Warn, &text);
                Box::new(crate::recorded::LogEntry::new(crate::recorded::Kind::Warn, text.clone()).level(crate::recorded::Level::Info).throwable(format!("java.lang.RuntimeException: {text}")).throwable_bean(logged.bean.clone()))
            });
            return Err(Failed::threw(template.engine, role, &thrown, logged, after));
        }
    };
    let kind = match output {
        Output::Response => "httpResponseDTO",
        Output::Request => "httpRequestDTO",
    };
    let generated = crate::json::parse_lenient(text.as_bytes());
    if generated.is_err() && state.info_enabled() {
        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Info, "exception deserialising generated content:{}into json node for request:{}")
            .args([crate::recorded::Arg::from(text.clone()), crate::recorded::logged(request).into()]);
        crate::log::entry_as(state, crate::recorded::Level::Info, &entry);
        state.log.message_about(entry, crate::recorded::Subject::Request(std::sync::Arc::new(request.clone())));
    }
    if state.info_enabled() {
        // The tree, or the text when it did not parse.
        let argument = match &generated {
            Ok(v) => crate::recorded::Arg::with_text(v.clone(), serde_json::to_string(v).unwrap_or_default()),
            Err(_) => text.clone().into(),
        };
        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::TemplateGenerated, "generated output:{}from template:{}for request:{}")
            .args([argument, source.clone().into(), crate::recorded::logged(request).into()]);
        crate::log::entry_as(state, crate::recorded::Level::Info, &entry);
        state.log.message_about(entry, crate::recorded::Subject::Request(std::sync::Arc::new(request.clone())));
    }
    let generated = match generated {
        Ok(v) => v,
        Err(e) => {
            // `JsonSchemaValidator.isValid` logs what reading the text threw (with it as the throwable) and reports
            // `<class> - <message>`.
            let mut thrown = None;
            let report = match crate::jnode::read_tree(&text) {
                Err(e) => {
                    thrown = Some(crate::chaos::bind::parse_failure(&text, &e.message));
                    format!("{} - {}", e.class.rsplit('.').next().unwrap_or_default(), e.message)
                }
                Ok(_) => e.to_string(),
            };
            let mut entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "exception validating JSON");
            if let Some(thrown) = thrown {
                entry = entry.throwable(format!("{}: {}", thrown.classes[0], thrown.message)).throwable_bean(thrown.bean);
            }
            crate::log::error_event(state, entry);
            validation_failed(state, request, kind, &report, &text);
            // `isValid` passes blank output; reading it then fails in the deserialiser
            let reason = if text.trim().is_empty() {
                format!("the output could not be read: No content to map due to end-of-input\n at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled); line: {}]", 1 + text.matches('\n').count())
            } else {
                report
            };
            return Err(Failed::invalid(state, template.engine, role, &reason));
        }
    };
    match crate::schema::validate_http_message(&generated, output == Output::Response).map_err(with_status_code_hint) {
        Ok(()) => Ok(generated),
        Err(report) => {
            validation_failed(state, request, kind, &report, &text);
            Err(Failed::invalid(state, template.engine, role, &report))
        }
    }
}

/// `HttpTemplateOutputDeserializer.deserializer`: a status code outside 100 to 999 gets a hint after the validation
/// errors.
fn with_status_code_hint(report: String) -> String {
    if report.contains("statusCode: must have a") {
        report + "\n\nthe template rendered a statusCode outside 100 to 999; an HTTP status line carries a three-digit code, so the rendered response was not used"
    } else {
        report
    }
}

/// `RequestBodyExtractionHelper`'s INFO entries for the `xPath` / `jsonPath` evaluations that failed during a render.
fn log_extraction_failures(state: &State, request: &HttpRequest, failures: &[extract::Failure]) {
    if failures.is_empty() || !state.info_enabled() {
        return;
    }
    let about = std::sync::Arc::new(request.clone());
    for failure in failures {
        let format = if failure.xpath { "exception evaluating xPath:{}against xml body:{}" } else { "exception evaluating jsonPath:{}against json body:{}" };
        let body = failure.body.clone().map_or(Value::Null, Value::String);
        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Info, format).args([failure.expression.clone().into(), crate::recorded::Arg::with_text(body, failure.body.clone().unwrap_or_default())]);
        crate::log::entry_as(state, crate::recorded::Level::Info, &entry);
        state.log.message_about(entry, crate::recorded::Subject::Request(about.clone()));
    }
}

/// A Mustache failure as `renderTemplate` reports it: the message (else the class's simple name), the cause's bean,
/// and the line (`MustacheTemplateEngine.transformFailure`: a `MustacheException.Context`'s line, or the ` @ line N`
/// jmustache appends to a parse error's message; never a column).
fn mustache_failure(e: jmustache::MustacheError) -> Thrown {
    let message = e.message().filter(|m| !m.trim().is_empty());
    let cause = cause_bean(message.as_deref(), &[]);
    let suffix = if e.is_parse_exception() {
        Some(" @ line ")
    } else if e.class_name().ends_with("MustacheException$Context") {
        Some(" on line ")
    } else {
        None
    };
    let line = suffix.zip(message.as_deref()).and_then(|(suffix, m)| m.rsplit_once(suffix)).map(|(_, n)| n).filter(|n| (1..=9).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit())).and_then(|n| n.parse::<i32>().ok()).filter(|l| *l > 0);
    Thrown { message: message.unwrap_or_else(|| e.simple_class_name()), cause, line, column: None, timeout: false }
}

/// A Velocity failure as `renderTemplate` reports it: the message (else the class's simple name), the cause's bean, and
/// the line and column of a `ParseErrorException` or an `ExtendedParseException` (`VelocityTemplateEngine.transformFailure`).
fn velocity_failure(e: ::velocity::VelocityError) -> Thrown {
    // `renderFailure`: a timeout, also wrapped (a `#define` block rendered by a method call), is itself the failure
    if let Some(timeout) = e.cause.as_ref().filter(|c| c.class == VELOCITY_TIMEOUT_CLASS) {
        let message = timeout.message.clone().unwrap_or_default();
        return Thrown { cause: cause_bean(Some(&message), &[]), message, line: None, column: None, timeout: true };
    }
    let m = jdk25_bounds_text(&e.message());
    // `ParseErrorException` and `TemplateInitException` carry their location as bean properties.
    let location = if e.is_parse() { vec![("columnNumber", Value::from(e.column)), ("lineNumber", Value::from(e.line)), ("templateName", e.template.clone().map_or(Value::Null, Value::from))] } else { Vec::new() };
    let cause = cause_bean((!m.trim().is_empty()).then_some(m.as_str()), &location);
    let located = (e.is_parse() || e.kind == ::velocity::ErrorKind::MethodInvocation) && e.line > 0;
    let (line, column) = if located { (Some(e.line), (e.column > 0).then_some(e.column)) } else { (None, None) };
    Thrown { message: if m.trim().is_empty() { e.simple_class_name().to_string() } else { m }, cause, line, column, timeout: false }
}

/// The 9.1.0 image's JDK words `String.substring`'s bounds failure `Range [b, e) out of bounds for length n`
/// (`Preconditions.outOfBoundsCheckFromToIndex`); `java-compat-rs`, frozen at JDK 17's wording, says `begin b, end e,
/// length n`.
fn jdk25_bounds_text(message: &str) -> String {
    static BEGIN_END: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"StringIndexOutOfBoundsException: begin (-?\d+), end (-?\d+), length (\d+)").expect("a valid regex")
    });
    BEGIN_END.replace_all(message, "StringIndexOutOfBoundsException: Range [$1, $2) out of bounds for length $3").into_owned()
}

/// `renderTemplate` with the engine's `validateTemplate` first (see [`disallowed`]), failing as it throws: the `RuntimeException`'s message
/// (`Exception:{}transforming template:{}for request:{}`) and its bean, with the engine's exception as the cause
/// (`DelayTemplateResolver.fallback`'s throwable).
pub fn render_text_thrown(state: &State, instance: &VelocityEngine, engine: Engine, source: &str, request: &HttpRequest) -> Result<String, (String, Value)> {
    let faker = faker_binding(state, engine);
    let path = request_path_match(request);
    let _deadline = velocity_deadline(state);
    let rendered = logged(state, request, || state.scenarios().scope(|| match engine {
        _ if let Some(message) = disallowed(state, engine, source) => Err(Thrown::plain(message)),
        Engine::Mustache => mustache::render(source, request, &path, None, &faker).map_err(mustache_failure),
        Engine::Velocity => velocity::render(&velocity_engine(state, instance), source, request, &path, None, &faker).map_err(velocity_failure),
        Engine::JavaScript => Err(Thrown::plain("JavaScript templates cannot render text".to_string())),
    }));
    rendered.map_err(|Thrown { message, cause, line, column, .. }| {
        let text = crate::matcher::format_log_message(0, "Exception:{} transforming template:{} for request:{}", &[&message, source, &crate::recorded::log_value(&crate::recorded::logged(request))]);
        // `TemplateEvaluationException`'s `getLine`/`getColumn`, written when the engine reports them (as in `execute`).
        let mut bean = serde_json::Map::new();
        bean.insert("cause".into(), cause);
        if let Some(column) = column {
            bean.insert("column".into(), column.into());
        }
        if let Some(line) = line {
            bean.insert("line".into(), line.into());
        }
        bean.insert("localizedMessage".into(), text.clone().into());
        bean.insert("message".into(), text.clone().into());
        bean.insert("stackTrace".into(), Value::Array(Vec::new()));
        (text, Value::Object(bean))
    })
}

fn cause_bean(message: Option<&str>, extra: &[(&str, Value)]) -> Value {
    let mut bean = serde_json::Map::new();
    for (k, v) in extra.iter().filter(|(k, _)| *k == "columnNumber" || *k == "lineNumber") {
        bean.insert((*k).to_string(), v.clone());
    }
    if let Some(m) = message {
        bean.insert("localizedMessage".into(), m.into());
        bean.insert("message".into(), m.into());
    }
    bean.insert("stackTrace".into(), Value::Array(Vec::new()));
    for (k, v) in extra.iter().filter(|(k, v)| *k == "templateName" && !v.is_null()) {
        bean.insert((*k).to_string(), v.clone());
    }
    Value::Object(bean)
}

/// `HttpTemplateOutputDeserializer`'s `TEMPLATE_GENERATION_FAILED` entry (ERROR) about the request being
/// answered: the validation errors and the rendered output. A retrieve of that request's logs shows it between the
/// generated output and the response (harvested from `JsonSchemaHttpResponseValidatorTest`).
fn validation_failed(state: &State, request: &HttpRequest, kind: &str, errors: &str, output: &str) {
    if !crate::log::error_enabled(state) {
        return;
    }
    let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::TemplateGenerationFailed, format!("template generated output that failed {kind} validation:{{}}generated output:{{}}"))
        .level(crate::recorded::Level::Error)
        .args([crate::recorded::Arg::from(errors.to_string()), output.to_string().into()]);
    crate::log::entry_as(state, crate::recorded::Level::Error, &entry);
    state.log.message_about(entry, crate::recorded::Subject::Request(std::sync::Arc::new(request.clone())));
}

// Scenario states as templates see them (`CrossProtocolEventBus`'s `ScenarioManager`).

/// `ScenarioManager.getState`: `Started` until a state is set.
/// (The scenarios are those of the render in progress on this thread, [`crate::scenario::current`].)
pub fn scenario_state(name: &str) -> String {
    crate::scenario::current().map_or_else(|| crate::scenario::STARTED.to_string(), |s| s.get(name))
}

pub fn set_scenario_state(name: &str, state: &str) {
    if dry_run::suppressed_set(name, state) {
        return;
    }
    if let Some(s) = crate::scenario::current() {
        s.set(name, state);
    }
}

/// `CsvTemplateHelper.parse`: RFC 4180 fields, `""` escapes, CR, LF or CRLF row ends.
pub fn csv_parse(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' => in_quotes = true,
            ',' => row.push(std::mem::take(&mut field)),
            '\r' | '\n' => {
                if c == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            c => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// Jackson's YAML reader into a JSON tree.
pub fn yaml_to_json(yaml: &str) -> Result<Value, ()> {
    serde_yaml::from_str::<Value>(yaml).map_err(|_| ())
}

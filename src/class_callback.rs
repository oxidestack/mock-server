//! Class callbacks (`httpResponseClassCallback`, `httpForwardClassCallback`). The expectation names a callback
//! class, and at request time the server resolves it through the callback providers, in order:
//! 1. the in-process registry;
//! 2. native plugins;
//! 3. WASM plugins;
//! 4. the foreign runtime (none exists yet).
//!
//! The interfaces and the plugin ABI live in `mock-server-callback-sdk`; `docs/callback-plugins.md` describes
//! the ABI. Plugins come from `callbackPlugins`, a list of plugin files and directories like a class path,
//! loaded when the server starts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use serde_json::{Value, json};

pub use mock_server_callback_sdk::{CallbackClass, CallbackError, ExpectationInitializer, ForwardAndResponseCallback, ForwardCallback, ResponseCallback};
use mock_server_callback_sdk::{FORWARD, FORWARD_AND_RESPONSE, INITIALIZER, RESPONSE};

/// A source of callback classes.
pub trait CallbackProvider: Send + Sync {
    fn resolve(&self, class: &str) -> Option<CallbackClass>;
}

/// The in-process registry: Rust callbacks registered under class names, before or after the server starts.
#[derive(Default)]
pub struct Registry {
    classes: RwLock<HashMap<String, CallbackClass>>,
}

impl Registry {
    pub fn register(&self, class: &str, callbacks: CallbackClass) {
        self.classes.write().insert(class.to_string(), callbacks);
    }
}

impl CallbackProvider for Registry {
    fn resolve(&self, class: &str) -> Option<CallbackClass> {
        self.classes.read().get(class).cloned()
    }
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.classes.read().keys()).finish()
    }
}

/// One call across a plugin boundary: the protocol's JSON in, its JSON out.
trait PluginCall: Send + Sync {
    fn call(&self, input: &[u8]) -> Result<Vec<u8>, String>;
}

/// A callback class a plugin exports; each interface method is one protocol call.
struct PluginClass {
    plugin: Arc<dyn PluginCall>,
    name: String,
}

impl PluginClass {
    fn invoke(&self, interface: &str, method: &str, request: &Value, response: Option<&Value>) -> Result<Value, CallbackError> {
        let mut call = json!({"class": self.name, "interface": interface, "method": method, "request": request});
        if let Some(r) = response {
            call["response"] = r.clone();
        }
        let out = self.plugin.call(call.to_string().as_bytes())?;
        let out: Value = serde_json::from_slice(&out).map_err(|e| format!("invalid plugin reply: {e}"))?;
        // `exception` is the thrown chain; a plugin built before it carries only the `error` message.
        match (out.get("exception").and_then(CallbackError::from_json), out.get("error").and_then(Value::as_str)) {
            (Some(exception), _) => Err(exception),
            (None, Some(error)) => Err(error.into()),
            (None, None) => Ok(out.get("result").cloned().unwrap_or(Value::Null)),
        }
    }
}

struct PluginResponse(Arc<PluginClass>);
struct PluginForward(Arc<PluginClass>);
struct PluginForwardAndResponse(Arc<PluginClass>);
struct PluginInitializer(Arc<PluginClass>);

impl ExpectationInitializer for PluginInitializer {
    fn initialize_expectations(&self) -> Result<Value, CallbackError> {
        self.0.invoke(INITIALIZER, "initializeExpectations", &Value::Null, None)
    }
}

impl ResponseCallback for PluginResponse {
    fn handle(&self, request: &Value) -> Result<Value, CallbackError> {
        self.0.invoke(RESPONSE, "handle", request, None)
    }
}

impl ForwardCallback for PluginForward {
    fn handle(&self, request: &Value) -> Result<Value, CallbackError> {
        self.0.invoke(FORWARD, "handle", request, None)
    }
}

impl ForwardAndResponseCallback for PluginForwardAndResponse {
    fn handle(&self, request: &Value) -> Result<Value, CallbackError> {
        self.0.invoke(FORWARD_AND_RESPONSE, "handle", request, None)
    }

    fn handle_response(&self, request: &Value, response: &Value) -> Result<Value, CallbackError> {
        self.0.invoke(FORWARD_AND_RESPONSE, "handleResponse", request, Some(response))
    }
}

/// A loaded plugin: its classes by name, each built from the descriptor's interfaces.
struct Plugin {
    path: PathBuf,
    classes: HashMap<String, CallbackClass>,
}

impl Plugin {
    fn new(path: PathBuf, call: Arc<dyn PluginCall>, descriptor: &[u8]) -> Result<Plugin, String> {
        let descriptor: Value = serde_json::from_slice(descriptor).map_err(|e| format!("invalid descriptor: {e}"))?;
        let mut classes = HashMap::new();
        for class in descriptor.get("classes").and_then(Value::as_array).into_iter().flatten() {
            let Some(name) = class.get("name").and_then(Value::as_str) else { continue };
            let implements = |i: &str| class.get("interfaces").and_then(Value::as_array).is_some_and(|a| a.iter().any(|v| v == i));
            let proxy = Arc::new(PluginClass { plugin: call.clone(), name: name.to_string() });
            let mut callbacks = CallbackClass::new();
            if implements(RESPONSE) {
                callbacks = callbacks.with_response(PluginResponse(proxy.clone()));
            }
            if implements(FORWARD_AND_RESPONSE) {
                callbacks = callbacks.with_forward_and_response(PluginForwardAndResponse(proxy.clone()));
            } else if implements(FORWARD) {
                callbacks = callbacks.with_forward(PluginForward(proxy.clone()));
            }
            if implements(INITIALIZER) {
                callbacks = callbacks.with_initializer(PluginInitializer(proxy.clone()));
            }
            classes.insert(name.to_string(), callbacks);
        }
        Ok(Plugin { path, classes })
    }
}

/// A native plugin (`.so`, `.dylib`, `.dll`) exporting the C ABI.
struct Native {
    _library: libloading::Library,
    invoke: unsafe extern "C" fn(*const std::os::raw::c_char) -> *mut std::os::raw::c_char,
    free: unsafe extern "C" fn(*mut std::os::raw::c_char),
}

impl Native {
    fn load(path: &Path) -> Result<(Arc<dyn PluginCall>, Vec<u8>), String> {
        // SAFETY: loading a plugin runs its initialisers; plugins are trusted code, like jars on a class path.
        let library = unsafe { libloading::Library::new(path) }.map_err(|e| e.to_string())?;
        type Describe = unsafe extern "C" fn() -> *mut std::os::raw::c_char;
        // SAFETY: the symbols have the ABI's signatures (docs/callback-plugins.md).
        let (describe, invoke, free) = unsafe {
            let describe = *library.get::<Describe>(b"mockserver_callback_describe\0").map_err(|e| e.to_string())?;
            let invoke = *library.get::<unsafe extern "C" fn(*const std::os::raw::c_char) -> *mut std::os::raw::c_char>(b"mockserver_callback_invoke\0").map_err(|e| e.to_string())?;
            let free = *library.get::<unsafe extern "C" fn(*mut std::os::raw::c_char)>(b"mockserver_callback_free\0").map_err(|e| e.to_string())?;
            (describe, invoke, free)
        };
        let native = Native { _library: library, invoke, free };
        // SAFETY: `describe` returns a string the plugin allocated, released with `free`.
        let descriptor = unsafe { native.take(describe()) };
        Ok((Arc::new(native), descriptor))
    }

    /// Copies a plugin-owned string and hands it back.
    unsafe fn take(&self, s: *mut std::os::raw::c_char) -> Vec<u8> {
        if s.is_null() {
            return Vec::new();
        }
        let bytes = unsafe { std::ffi::CStr::from_ptr(s) }.to_bytes().to_vec();
        unsafe { (self.free)(s) };
        bytes
    }
}

impl PluginCall for Native {
    fn call(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        let input = std::ffi::CString::new(input).map_err(|e| e.to_string())?;
        // SAFETY: `invoke` reads the NUL-terminated input and returns a string released with `free`.
        Ok(unsafe { self.take((self.invoke)(input.as_ptr())) })
    }
}

/// A WASM plugin: one instance for the plugin's lifetime (its statics persist, like a Java class's), called one
/// at a time. The module may import nothing.
struct Wasm {
    inner: Mutex<(wasmi::Store<()>, wasmi::Instance)>,
}

impl Wasm {
    fn load(path: &Path) -> Result<(Arc<dyn PluginCall>, Vec<u8>), String> {
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        let engine = wasmi::Engine::default();
        let module = wasmi::Module::new(&engine, &bytes).map_err(|e| e.to_string())?;
        let mut store = wasmi::Store::new(&engine, ());
        let instance = wasmi::Linker::<()>::new(&engine).instantiate_and_start(&mut store, &module).map_err(|e| e.to_string())?;
        let wasm = Wasm { inner: Mutex::new((store, instance)) };
        let descriptor = {
            let mut guard = wasm.inner.lock();
            let (store, instance) = &mut *guard;
            let describe = instance.get_typed_func::<(), i64>(&*store, "mockserver_describe").map_err(|e| e.to_string())?;
            let packed = describe.call(&mut *store, ()).map_err(|e| e.to_string())?;
            Wasm::take(store, instance, packed)?
        };
        Ok((Arc::new(wasm), descriptor))
    }

    /// Reads a packed `(ptr << 32) | len` output and frees it in the module.
    fn take(store: &mut wasmi::Store<()>, instance: &wasmi::Instance, packed: i64) -> Result<Vec<u8>, String> {
        let (ptr, len) = ((packed >> 32) as u32 as usize, (packed & 0xffff_ffff) as u32 as usize);
        let memory = instance.get_memory(&*store, "memory").ok_or("the module exports no memory")?;
        let mut out = vec![0; len];
        memory.read(&*store, ptr, &mut out).map_err(|e| e.to_string())?;
        let free = instance.get_typed_func::<(i32, i32), ()>(&*store, "mockserver_free").map_err(|e| e.to_string())?;
        free.call(&mut *store, (ptr as i32, len as i32)).map_err(|e| e.to_string())?;
        Ok(out)
    }
}

impl PluginCall for Wasm {
    fn call(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        let mut guard = self.inner.lock();
        let (store, instance) = &mut *guard;
        let alloc = instance.get_typed_func::<i32, i32>(&*store, "mockserver_alloc").map_err(|e| e.to_string())?;
        let invoke = instance.get_typed_func::<(i32, i32), i64>(&*store, "mockserver_invoke").map_err(|e| e.to_string())?;
        let len = i32::try_from(input.len()).map_err(|e| e.to_string())?;
        let ptr = alloc.call(&mut *store, len).map_err(|e| e.to_string())?;
        let memory = instance.get_memory(&*store, "memory").ok_or("the module exports no memory")?;
        memory.write(&mut *store, ptr as u32 as usize, input).map_err(|e| e.to_string())?;
        let packed = invoke.call(&mut *store, (ptr, len)).map_err(|e| e.to_string())?;
        Wasm::take(store, instance, packed)
    }
}

/// The plugins of `callbackPlugins`, native ones before WASM ones, each kind in path order.
#[derive(Default)]
pub struct Plugins {
    native: Vec<Plugin>,
    wasm: Vec<Plugin>,
}

const NATIVE_EXTENSIONS: &[&str] = &["so", "dylib", "dll"];

impl Plugins {
    /// Loads every plugin file named, or found in a named directory. A plugin that fails to load is reported and
    /// skipped, as a broken jar on a class path would be. A jar (MockServer's image takes callback classes as jars in
    /// `/libs`) is reported by name and ignored.
    pub fn load(path_list: &str, report: impl Fn(String)) -> Plugins {
        let mut files = Vec::new();
        for entry in std::env::split_paths(path_list).filter(|p| !p.as_os_str().is_empty()) {
            if entry.is_dir() {
                let mut found: Vec<PathBuf> = std::fs::read_dir(&entry).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| is_plugin(p) || is_jar(p)).collect();
                found.sort();
                files.extend(found);
            } else if entry.exists() {
                files.push(entry);
            }
        }
        let (jars, files): (Vec<PathBuf>, Vec<PathBuf>) = files.into_iter().partition(|p| is_jar(p));
        for jar in jars {
            report(format!("ignoring Java archive {}: mock-server does not load Java classes; callback plugins are .wasm, .so, .dylib or .dll files (docs/callback-plugins.md)", jar.display()));
        }
        let mut plugins = Plugins::default();
        for file in files {
            let wasm = file.extension().is_some_and(|e| e == "wasm");
            let loaded = if wasm { Wasm::load(&file) } else { Native::load(&file) }.and_then(|(call, descriptor)| Plugin::new(file.clone(), call, &descriptor));
            match loaded {
                Ok(plugin) => {
                    let mut names: Vec<&String> = plugin.classes.keys().collect();
                    names.sort();
                    report(format!("loaded callback plugin {} with classes {names:?}", plugin.path.display()));
                    if wasm { plugins.wasm.push(plugin) } else { plugins.native.push(plugin) }
                }
                Err(e) => report(format!("failed to load callback plugin {}: {e}", file.display())),
            }
        }
        plugins
    }
}

fn is_jar(path: &Path) -> bool {
    path.is_file() && path.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("jar"))
}

fn is_plugin(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| e == "wasm" || NATIVE_EXTENSIONS.contains(&e))
}

impl CallbackProvider for Plugins {
    fn resolve(&self, class: &str) -> Option<CallbackClass> {
        self.native.iter().chain(&self.wasm).find_map(|p| p.classes.get(class).cloned())
    }
}

/// Resolves `class` through the providers in order.
pub(crate) fn resolve(state: &crate::state::State, class: &str) -> Option<CallbackClass> {
    crate::scim::callback_class(&state.scim, class)
        .or_else(|| crate::oidc::callback_class(&state.oidc, class))
        .or_else(|| crate::saml::callback_class(&state.saml, class))
        .or_else(|| state.config.callback_classes.resolve(class))
        .or_else(|| state.callback_plugins.resolve(class))
}

/// Runs user code off the async workers: a callback may block, even on a request back to this server.
pub(crate) async fn run<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(work).await.expect("callback thread panicked")
}

/// An ERROR event about a callback class, about `request` when there is one, with the entry's throwable: the first line of its stack trace (`class: message`), which the dashboard shows.
pub(crate) fn log_error_with(state: &crate::state::State, text: &str, request: Option<&crate::request::HttpRequest>, throwable: Option<&str>) {
    let subject = request.map_or(crate::recorded::Subject::None, |r| crate::recorded::Subject::Request(Arc::new(r.clone())));
    let mut entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, text);
    if let Some(trace) = throwable {
        entry = entry.throwable(trace);
    }
    crate::log::error(state, &console_text(state, &entry, request));
    state.log.message_about(entry, subject);
}

/// The console line of [`log_error_with`]'s entry: under `redactSecretsInLog`, redacted and scrubbed of the
/// credential values of `request` (upstream c76143e4a).
fn console_text(state: &crate::state::State, entry: &crate::recorded::LogEntry, request: Option<&crate::request::HttpRequest>) -> String {
    crate::log::redacted_with(state, entry, request, "").0
}

/// The ERROR entry of a callback that threw (`<class> throw exception while executing handle callback method - <message>`),
/// with the exception chain as its throwable.
pub(crate) fn callback_threw(state: &crate::state::State, class: &str, error: &CallbackError, request: &crate::request::HttpRequest) {
    let text = format!("{class} throw exception while executing handle callback method - {}", error.message());
    let trace = throwable_trace(error);
    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, text).throwable(&trace).throwable_bean(throwable_bean(error));
    crate::log::error_with_throwable(state, &entry, Some(request), &trace);
    state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(request.clone())));
}

/// Jackson's bean of the exception: `cause`, `localizedMessage`, `message`, `stackTrace` and the class's other
/// getters (the error's `properties`, and those the JDK's XML exceptions derive: a `TransformerException`'s or
/// `SAXException`'s wrapped `exception`, a `TransformerException`'s `messageAndLocation`) in alphabetical order, null
/// members dropped; `stackTrace` is empty, JVM frames cannot be reproduced (docs/divergences.md).
fn throwable_bean(error: &CallbackError) -> Value {
    let mut members: Vec<(String, Value)> = Vec::new();
    if let Some(cause) = &error.cause {
        members.push(("cause".into(), throwable_bean(cause)));
        if matches!(error.class.as_str(), "javax.xml.transform.TransformerException" | "org.xml.sax.SAXException" | "org.xml.sax.SAXParseException") {
            members.push(("exception".into(), throwable_bean(cause)));
        }
    }
    if let Some(message) = &error.message {
        members.push(("localizedMessage".into(), message.clone().into()));
        members.push(("message".into(), message.clone().into()));
        if error.class == "javax.xml.transform.TransformerException" {
            members.push(("messageAndLocation".into(), message.clone().into()));
        }
    }
    members.push(("stackTrace".into(), Value::Array(Vec::new())));
    for (name, value) in &error.properties {
        members.retain(|(n, _)| n != name);
        members.push((name.clone(), value.clone()));
    }
    members.sort_by(|a, b| a.0.cmp(&b.0));
    Value::Object(members.into_iter().filter(|(_, v)| !v.is_null()).collect())
}

/// The exception's `printStackTrace` without frames: `class: message`, then a `Caused by:` line per cause.
fn throwable_trace(error: &CallbackError) -> String {
    let mut lines = Vec::new();
    let mut at = Some(error);
    while let Some(e) = at {
        let prefix = if lines.is_empty() { "" } else { "Caused by: " };
        lines.push(match &e.message {
            Some(message) => format!("{prefix}{}: {message}", e.class),
            None => format!("{prefix}{}", e.class),
        });
        at = e.cause.as_deref();
    }
    lines.join("\n")
}

/// `HttpResponseClassCallbackActionHandler.handle`: the response in input JSON form, `None` for the 404 upstream
/// answers when the class is missing, implements no `ExpectationResponseCallback`, or throws.
pub(crate) async fn respond(state: &crate::state::State, class: &str, request: &crate::request::HttpRequest, model: Value) -> Option<Value> {
    let Some(resolved) = resolve(state, class) else {
        log_error_with(state, &format!("ClassNotFoundException - while trying to instantiate ExpectationResponseCallback class \"{class}\""), None, Some(&format!("java.lang.ClassNotFoundException: {class}")));
        return None;
    };
    let Some(callback) = resolved.response() else {
        // `setHttpRequest(null)`: the entry carries the default request.
        let text = format!("{class} does not implement org.mockserver.mock.action.ExpectationResponseCallback required for responses using class callback");
        crate::log::error(state, &text);
        state.log.message(crate::recorded::LogEntry::at(crate::recorded::Level::Error, text).default_request());
        return None;
    };
    match run(move || callback.handle(&model)).await {
        Ok(v) if !v.is_null() => Some(v),
        Ok(_) => None,
        Err(error) => {
            callback_threw(state, class, &error, request);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(redact: bool) -> Arc<crate::state::State> {
        let config = crate::Config::for_tests().with_property("redactSecretsInLog", if redact { "true" } else { "false" });
        crate::state::State::new(config, Vec::new())
    }

    fn request() -> crate::request::HttpRequest {
        crate::request::HttpRequest {
            method: "GET".into(),
            path: "/callback".into(),
            headers: vec![("Authorization".into(), vec!["Bearer CALLBACK-SECRET-353".into()])],
            ..Default::default()
        }
    }

    /// Jars in a plugin directory, or named, are reported by name instead of skipped silently.
    #[test]
    fn jars_are_named_and_ignored() {
        let root = std::env::temp_dir().join(format!("callback-plugins-{}", uuid::Uuid::new_v4().simple()));
        let (libs, other) = (root.join("libs"), root.join("other"));
        std::fs::create_dir_all(&libs).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        for name in ["b-callbacks.jar", "a-initializer.JAR", "notes.txt"] {
            std::fs::write(libs.join(name), b"PK").unwrap();
        }
        std::fs::write(other.join("named.jar"), b"PK").unwrap();
        let lines = Mutex::new(Vec::new());
        let path_list = std::env::join_paths([other.join("named.jar"), libs.clone()]).unwrap();
        let plugins = Plugins::load(path_list.to_str().unwrap(), |line| lines.lock().push(line));
        let _ = std::fs::remove_dir_all(&root);
        assert!(plugins.native.is_empty() && plugins.wasm.is_empty());
        let expected: Vec<String> = [other.join("named.jar"), libs.join("a-initializer.JAR"), libs.join("b-callbacks.jar")]
            .iter()
            .map(|jar| format!("ignoring Java archive {}: mock-server does not load Java classes; callback plugins are .wasm, .so, .dylib or .dll files (docs/callback-plugins.md)", jar.display()))
            .collect();
        assert_eq!(lines.into_inner(), expected);
    }

    /// `log_error_with` printed its text raw; its console line is now the redacted entry's.
    #[test]
    fn console_line_is_scrubbed_of_the_request_credentials_under_redaction() {
        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Error, "callback failed for Bearer CALLBACK-SECRET-353");
        let request = request();
        let redacted = console_text(&state(true), &entry, Some(&request));
        assert!(!redacted.contains("CALLBACK-SECRET-353"), "{redacted}");
        assert!(redacted.contains(crate::recorded::LOG_REDACTED), "{redacted}");
        assert_eq!(console_text(&state(false), &entry, Some(&request)), "callback failed for Bearer CALLBACK-SECRET-353");
    }
}

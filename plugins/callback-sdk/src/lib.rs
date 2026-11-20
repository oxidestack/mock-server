//! Callback classes for mock-server . An expectation's `httpResponseClassCallback` or
//! `httpForwardClassCallback` names a callback class; the server resolves the name to one of these.
//!
//! The interfaces mirror MockServer's Java ones and exchange MockServer's JSON model: a request as `HttpRequest`
//! serialises, and a response or request as expectation input JSON. The same classes can be registered in-process
//! on an embedded server, or exported from a plugin with [`export_callback_classes!`], built as a native library
//! (`cdylib`) or a `wasm32-unknown-unknown` module. `docs/callback-plugins.md` describes the plugin ABI.

use std::sync::Arc;

pub use serde_json::{self, Value, json};

/// The exception a callback throws: a Java class name, its message and the exception it wraps. The server logs it as
/// the throwable of the ERROR entry upstream writes for a throwing callback. A `String` converts into a
/// `java.lang.RuntimeException` with that message. `properties` are further members of the exception's Jackson bean
/// (its other getters, e.g. a `SAXParseException`'s `lineNumber`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackError {
    pub class: String,
    pub message: Option<String>,
    pub cause: Option<Box<CallbackError>>,
    pub properties: Vec<(String, Value)>,
}

impl CallbackError {
    /// `new RuntimeException(message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self::of("java.lang.RuntimeException", message)
    }

    /// An exception of `class` with `message`.
    pub fn of(class: impl Into<String>, message: impl Into<String>) -> Self {
        CallbackError { class: class.into(), message: Some(message.into()), cause: None, properties: Vec::new() }
    }

    /// This exception wrapping `cause` (`new X(message, cause)`).
    pub fn caused_by(mut self, cause: CallbackError) -> Self {
        self.cause = Some(Box::new(cause));
        self
    }

    /// This exception with a further bean member (`name` is the getter's property name).
    pub fn with_property(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.properties.push((name.into(), value.into()));
        self
    }

    /// The message, empty when there is none.
    pub fn message(&self) -> &str {
        self.message.as_deref().unwrap_or_default()
    }

    /// The plugin protocol's form: `{"class", "message"?, "cause"?, "properties"?}`.
    pub fn to_json(&self) -> Value {
        let mut out = json!({"class": self.class});
        if let Some(message) = &self.message {
            out["message"] = json!(message);
        }
        if let Some(cause) = &self.cause {
            out["cause"] = cause.to_json();
        }
        if !self.properties.is_empty() {
            out["properties"] = Value::Object(self.properties.iter().cloned().collect());
        }
        out
    }

    /// [`CallbackError::to_json`] read back; `None` for anything without a `class`.
    pub fn from_json(value: &Value) -> Option<Self> {
        Some(CallbackError {
            class: value.get("class")?.as_str()?.to_string(),
            message: value.get("message").and_then(Value::as_str).map(str::to_string),
            cause: value.get("cause").and_then(CallbackError::from_json).map(Box::new),
            properties: value.get("properties").and_then(Value::as_object).map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default(),
        })
    }
}

impl std::fmt::Display for CallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl From<String> for CallbackError {
    fn from(message: String) -> Self {
        CallbackError::new(message)
    }
}

impl From<&str> for CallbackError {
    fn from(message: &str) -> Self {
        CallbackError::new(message)
    }
}

/// `ExpectationResponseCallback`: the response for a request. `Err` is the exception it throws.
pub trait ResponseCallback: Send + Sync {
    fn handle(&self, request: &Value) -> Result<Value, CallbackError>;
}

/// `ExpectationForwardCallback`: the request to forward in place of the received one.
pub trait ForwardCallback: Send + Sync {
    fn handle(&self, request: &Value) -> Result<Value, CallbackError>;
}

/// `ExpectationForwardAndResponseCallback`: a forward callback that also rewrites the upstream's response. Its
/// request half defaults to forwarding the request unchanged, as the Java interface's default method does.
pub trait ForwardAndResponseCallback: Send + Sync {
    fn handle(&self, request: &Value) -> Result<Value, CallbackError> {
        Ok(request.clone())
    }

    fn handle_response(&self, request: &Value, response: &Value) -> Result<Value, CallbackError>;
}

/// `ExpectationInitializer` (`mockserver.initializationClass`): the expectations to create when the server
/// starts, as an array of expectation input JSON.
pub trait ExpectationInitializer: Send + Sync {
    fn initialize_expectations(&self) -> Result<Value, CallbackError>;
}

impl<F: Fn(&Value) -> Result<Value, CallbackError> + Send + Sync> ResponseCallback for F {
    fn handle(&self, request: &Value) -> Result<Value, CallbackError> {
        self(request)
    }
}

/// The Java interface names, as plugin descriptors and log lines spell them.
pub const RESPONSE: &str = "ExpectationResponseCallback";
pub const FORWARD: &str = "ExpectationForwardCallback";
pub const FORWARD_AND_RESPONSE: &str = "ExpectationForwardAndResponseCallback";
pub const INITIALIZER: &str = "ExpectationInitializer";

/// What a callback class implements: any combination of the three interfaces.
#[derive(Clone, Default)]
pub struct CallbackClass {
    response: Option<Arc<dyn ResponseCallback>>,
    forward: Option<Arc<dyn ForwardCallback>>,
    forward_and_response: Option<Arc<dyn ForwardAndResponseCallback>>,
    initializer: Option<Arc<dyn ExpectationInitializer>>,
}

impl CallbackClass {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_response(mut self, callback: impl ResponseCallback + 'static) -> Self {
        self.response = Some(Arc::new(callback));
        self
    }

    pub fn with_forward(mut self, callback: impl ForwardCallback + 'static) -> Self {
        self.forward = Some(Arc::new(callback));
        self
    }

    /// Also the class's forward callback: the Java interface extends `ExpectationForwardCallback`.
    pub fn with_forward_and_response(mut self, callback: impl ForwardAndResponseCallback + 'static) -> Self {
        self.forward_and_response = Some(Arc::new(callback));
        self
    }

    pub fn with_initializer(mut self, initializer: impl ExpectationInitializer + 'static) -> Self {
        self.initializer = Some(Arc::new(initializer));
        self
    }

    pub fn initializer(&self) -> Option<Arc<dyn ExpectationInitializer>> {
        self.initializer.clone()
    }

    pub fn response(&self) -> Option<Arc<dyn ResponseCallback>> {
        self.response.clone()
    }

    pub fn forward(&self) -> Option<Arc<dyn ForwardCallback>> {
        self.forward.clone()
    }

    pub fn forward_and_response(&self) -> Option<Arc<dyn ForwardAndResponseCallback>> {
        self.forward_and_response.clone()
    }

    /// The interfaces it implements, by Java name.
    pub fn interfaces(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.response.is_some() {
            out.push(RESPONSE);
        }
        if self.forward.is_some() || self.forward_and_response.is_some() {
            out.push(FORWARD);
        }
        if self.forward_and_response.is_some() {
            out.push(FORWARD_AND_RESPONSE);
        }
        if self.initializer.is_some() {
            out.push(INITIALIZER);
        }
        out
    }

    /// Runs one call of the plugin protocol: `{"class", "method": "handle" | "handleResponse" | "initializeExpectations", "interface",
    /// "request", "response"?}`.
    pub fn invoke(&self, call: &Value) -> Result<Value, CallbackError> {
        let request = call.get("request").cloned().unwrap_or(Value::Null);
        let interface = call.get("interface").and_then(Value::as_str).unwrap_or_default();
        let method = call.get("method").and_then(Value::as_str).unwrap_or("handle");
        let missing = || format!("{} does not implement {interface}", call.get("class").and_then(Value::as_str).unwrap_or_default());
        match (interface, method) {
            (RESPONSE, _) => self.response.as_ref().ok_or_else(missing)?.handle(&request),
            (FORWARD, _) => match (&self.forward, &self.forward_and_response) {
                (Some(f), _) => f.handle(&request),
                (None, Some(f)) => f.handle(&request),
                (None, None) => Err(missing().into()),
            },
            (FORWARD_AND_RESPONSE, "handleResponse") => {
                let response = call.get("response").cloned().unwrap_or(Value::Null);
                self.forward_and_response.as_ref().ok_or_else(missing)?.handle_response(&request, &response)
            }
            (FORWARD_AND_RESPONSE, _) => self.forward_and_response.as_ref().ok_or_else(missing)?.handle(&request),
            (INITIALIZER, _) => self.initializer.as_ref().ok_or_else(missing)?.initialize_expectations(),
            _ => Err(format!("unknown interface {interface}").into()),
        }
    }
}

/// The plugin protocol over a set of classes: the descriptor, and one call.
#[doc(hidden)]
pub mod protocol {
    use super::*;

    pub fn describe(classes: &[(String, CallbackClass)]) -> String {
        let classes: Vec<Value> = classes.iter().map(|(name, c)| json!({"name": name, "interfaces": c.interfaces()})).collect();
        json!({"abiVersion": 1, "classes": classes}).to_string()
    }

    pub fn invoke(classes: &[(String, CallbackClass)], input: &[u8]) -> String {
        let outcome = serde_json::from_slice::<Value>(input).map_err(|e| CallbackError::from(format!("invalid call: {e}"))).and_then(|call| {
            let name = call.get("class").and_then(Value::as_str).unwrap_or_default();
            let class = classes.iter().find(|(n, _)| n == name).map(|(_, c)| c).ok_or_else(|| CallbackError::from(format!("unknown class {name}")))?;
            class.invoke(&call)
        });
        match outcome {
            Ok(result) => json!({"result": result}).to_string(),
            Err(error) => json!({"error": error.message(), "exception": error.to_json()}).to_string(),
        }
    }
}

/// Exports callback classes from a plugin crate (`crate-type = ["cdylib"]`), for both a native library and a
/// `wasm32-unknown-unknown` module. The expression builds the classes once, on first use:
///
/// ```ignore
/// mock_server_callback_sdk::export_callback_classes!(my_plugin::classes());
/// ```
#[macro_export]
macro_rules! export_callback_classes {
    ($classes:expr) => {
        fn __mockserver_callback_classes() -> &'static [(String, $crate::CallbackClass)] {
            static CLASSES: std::sync::OnceLock<Vec<(String, $crate::CallbackClass)>> = std::sync::OnceLock::new();
            CLASSES.get_or_init(|| $classes.into_iter().map(|(name, class)| (String::from(name), class)).collect())
        }

        #[cfg(not(target_arch = "wasm32"))]
        #[unsafe(no_mangle)]
        pub extern "C" fn mockserver_callback_describe() -> *mut std::os::raw::c_char {
            std::ffi::CString::new($crate::protocol::describe(__mockserver_callback_classes())).unwrap_or_default().into_raw()
        }

        /// # Safety
        /// `input` is a NUL-terminated string the caller owns.
        #[cfg(not(target_arch = "wasm32"))]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn mockserver_callback_invoke(input: *const std::os::raw::c_char) -> *mut std::os::raw::c_char {
            let input = unsafe { std::ffi::CStr::from_ptr(input) }.to_bytes();
            std::ffi::CString::new($crate::protocol::invoke(__mockserver_callback_classes(), input)).unwrap_or_default().into_raw()
        }

        /// # Safety
        /// `s` came from `mockserver_callback_describe` or `mockserver_callback_invoke`.
        #[cfg(not(target_arch = "wasm32"))]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn mockserver_callback_free(s: *mut std::os::raw::c_char) {
            if !s.is_null() {
                drop(unsafe { std::ffi::CString::from_raw(s) });
            }
        }

        #[cfg(target_arch = "wasm32")]
        #[unsafe(no_mangle)]
        pub extern "C" fn mockserver_alloc(len: i32) -> i32 {
            let mut buffer = Vec::<u8>::with_capacity(len.max(0) as usize);
            let ptr = buffer.as_mut_ptr();
            std::mem::forget(buffer);
            ptr as i32
        }

        #[cfg(target_arch = "wasm32")]
        fn __mockserver_packed(out: String) -> i64 {
            let bytes = out.into_bytes().into_boxed_slice();
            let len = bytes.len() as i64;
            let ptr = Box::into_raw(bytes) as *mut u8 as i64;
            (ptr << 32) | len
        }

        #[cfg(target_arch = "wasm32")]
        #[unsafe(no_mangle)]
        pub extern "C" fn mockserver_describe() -> i64 {
            __mockserver_packed($crate::protocol::describe(__mockserver_callback_classes()))
        }

        /// Frees an output of `mockserver_describe` or `mockserver_invoke` once the host has read it.
        #[cfg(target_arch = "wasm32")]
        #[unsafe(no_mangle)]
        pub extern "C" fn mockserver_free(ptr: i32, len: i32) {
            drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr as *mut u8, len as usize)) });
        }

        /// The input is freed here; the output stays allocated until the host calls `mockserver_free`.
        #[cfg(target_arch = "wasm32")]
        #[unsafe(no_mangle)]
        pub extern "C" fn mockserver_invoke(ptr: i32, len: i32) -> i64 {
            let input = unsafe { Vec::from_raw_parts(ptr as *mut u8, len as usize, len as usize) };
            __mockserver_packed($crate::protocol::invoke(__mockserver_callback_classes(), &input))
        }
    };
}

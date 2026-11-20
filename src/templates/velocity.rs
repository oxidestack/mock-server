//! `VelocityTemplateEngine`: Velocity 2.4.1 configured as MockServer configures it, with its context chain —
//! the per-render bindings (`request`, `response`, `jsonPath`, `xPath`) over the shared functions and helpers,
//! over a fresh `ToolContext`.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use java_compat::lang::{JError, JObject, JValue};
use java_compat::reflect::{ClassDef, JType, LazyClass};
use serde_json::Value;
use velocity::{Context, Engine, VelocityError};

use super::functions;
use super::model::{PathMatch, RequestObject, ResponseObject};
use crate::request::HttpRequest;

/// The engine of a render no server owns.
static ENGINE: LazyLock<Arc<Engine>> = LazyLock::new(|| Arc::new(new_engine()));

fn new_engine() -> Engine {
    // MockServer's JVM has no locale data beyond the JDK's base module.
    velocity::tools::set_locale_data(java_compat::text::LocaleData::JavaBase);
    Engine::mockserver()
}

/// One `VelocityTemplateEngine` instance, as each upstream handler builds its own: built at its first render, and
/// built again (template names counting from `t0` again) when `velocityDisallowClassLoading` differs from the value
/// it was built with (`currentEngineHolder`).
#[derive(Default)]
pub struct Instance(parking_lot::Mutex<Option<(bool, Option<Arc<Engine>>)>>);

impl Instance {
    /// The engine for a render under this `velocityDisallowClassLoading`.
    pub fn engine(&self, disallow_class_loading: bool) -> Arc<Engine> {
        let mut slot = self.0.lock();
        if !slot.as_ref().is_some_and(|(built, _)| *built == disallow_class_loading) {
            *slot = Some((disallow_class_loading, None));
        }
        let (_, engine) = slot.as_mut().expect("just set");
        engine.get_or_insert_with(|| Arc::new(new_engine())).clone()
    }

    /// A render under this `velocityDisallowClassLoading` that does not use the engine (an unsandboxed one renders in
    /// the foreign runtime): the engine is still rebuilt for it.
    pub fn touch(&self, disallow_class_loading: bool) {
        let mut slot = self.0.lock();
        if !slot.as_ref().is_some_and(|(built, _)| *built == disallow_class_loading) {
            *slot = Some((disallow_class_loading, None));
        }
    }
}

/// The engine a render without a server uses.
pub fn shared() -> Arc<Engine> {
    ENGINE.clone()
}

/// The functions and helpers every render shares (`sharedFunctionsAndHelpers`).
static SHARED: LazyLock<Arc<HashMap<String, JValue>>> =
    LazyLock::new(|| Arc::new(functions::functions().into_iter().chain(functions::helpers()).chain(functions::on_demand_helpers()).map(|(k, v)| (k.to_string(), v)).collect()));

/// `RequestBodyExtractionHelper.JsonPathTool` / `XPathTool`.
struct ExtractionTool {
    request: HttpRequest,
    xpath: bool,
}

impl ExtractionTool {
    fn extract(&self, expression: &JValue) -> Result<JValue, JError> {
        let expression = expression.as_str().unwrap_or("null");
        if self.xpath { super::extract::xpath_checked(&self.request, expression).map(JValue::str) } else { super::extract::json_path_checked(&self.request, expression) }
    }
}

fn json_path_tool_def() -> Arc<ClassDef> {
    tool_def("org.mockserver.templates.engine.helpers.RequestBodyExtractionHelper$JsonPathTool", JType::object())
}

fn xpath_tool_def() -> Arc<ClassDef> {
    tool_def("org.mockserver.templates.engine.helpers.RequestBodyExtractionHelper$XPathTool", JType::string())
}

fn tool_def(name: &str, returns: JType) -> Arc<ClassDef> {
    let mut def = ClassDef::new(name);
    for method in ["find", "jsonPath", "xPath"] {
        let is_json = name.ends_with("JsonPathTool");
        if (method == "jsonPath" && !is_json) || (method == "xPath" && is_json) {
            continue;
        }
        def = def.method::<ExtractionTool>(method, &[JType::string()], Some(returns.clone()), |t, _, a| t.extract(&a[0]).map(Some));
    }
    def.method::<ExtractionTool>("toString", &[], Some(JType::string()), |t, _, _| Ok(Some(JValue::str(t.to_java_string()))))
        .method::<ExtractionTool>("hashCode", &[], Some(JType::Int), |t, _, _| Ok(Some(JValue::Int((t as *const ExtractionTool as usize) as u32 as i32))))
        .method::<ExtractionTool>("equals", &[JType::object()], Some(JType::Boolean), |t, _, a| {
            Ok(Some(JValue::Bool(matches!(&a[0], JValue::Object(o) if std::ptr::addr_eq(Arc::as_ptr(o), t as *const ExtractionTool)))))
        })
        .register()
}

impl JObject for ExtractionTool {
    fn class_name(&self) -> String {
        self.class_def().map(|d| d.name.to_string()).unwrap_or_default()
    }

    fn invoke(&self, _name: &str, _args: &[JValue]) -> Option<Result<Option<JValue>, JError>> {
        None
    }

    fn to_java_string(&self) -> String {
        if self.xpath { "XPathTool".into() } else { "JsonPathTool".into() }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn class_def(&self) -> Option<Arc<ClassDef>> {
        static JSON: LazyClass = LazyClass::new(json_path_tool_def);
        static XPATH: LazyClass = LazyClass::new(xpath_tool_def);
        Some(if self.xpath { XPATH.get() } else { JSON.get() })
    }
}

/// Renders `template` against the request (and, for a forward's `responseTemplate`, the upstream response).
pub fn render(engine: &Engine, template: &str, request: &HttpRequest, path: &PathMatch, response: Option<&Value>, extra: &[(&str, JValue)]) -> Result<String, VelocityError> {
    render_with_cartridge(engine, template, request, path, response, extra, None)
}

/// [`render`] with `cartridge` attached to the render's context (`EventCartridge.attachToContext`).
pub fn render_with_cartridge(engine: &Engine, template: &str, request: &HttpRequest, path: &PathMatch, response: Option<&Value>, extra: &[(&str, JValue)], cartridge: Option<Arc<velocity::events::EventCartridge>>) -> Result<String, VelocityError> {
    let tools = velocity::tools::context();
    let mut context = Context::new().with_layer(SHARED.clone()).with_layer(tools);
    context.put("request", RequestObject::velocity_value(request, path));
    if let Some(r) = response {
        context.put("response", ResponseObject::value(r));
    }
    context.put("jsonPath", JValue::Object(Arc::new(ExtractionTool { request: request.clone(), xpath: false })));
    context.put("xPath", JValue::Object(Arc::new(ExtractionTool { request: request.clone(), xpath: true })));
    for (name, value) in extra {
        context.put(name, value.clone());
    }
    if let Some(cartridge) = cartridge {
        context.attach_event_cartridge(cartridge);
    }
    engine.render(template, &mut context)
}

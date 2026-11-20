//! `MustacheTemplateEngine`: JMustache with MockServer's compiler options and data map.

use std::sync::LazyLock;

use java_compat::lang::{JMap, JValue, MapKind};
use jmustache::{Compiler, DefaultCollector, Lambda, MustacheError};
use serde_json::Value;

use super::functions;
use super::model::{PathMatch, RequestObject, ResponseObject};
use crate::request::HttpRequest;

static COMPILER: LazyLock<Compiler> = LazyLock::new(|| {
    Compiler::default()
        .empty_string_is_false(true)
        .zero_is_false(true)
        .strict_sections(false)
        .default_value("")
        .with_collector(std::sync::Arc::new(DefaultCollector::extended()))
});

/// `unresolvedVariableCompiler`: `compiler.nullValue("")`, so a missing variable throws `MustacheException.Context`
/// while a null one still renders as empty text (the template dry run's unresolved-variable passes).
static STRICT_COMPILER: LazyLock<Compiler> = LazyLock::new(|| COMPILER.clone().null_value(""));

/// The synthetic class of a lambda written in `MustacheTemplateEngine` (its `toString()` is otherwise
/// unreproducible: a hidden-class address and identity hash).
const LAMBDA_CLASS: &str = "org.mockserver.templates.engine.mustache.MustacheTemplateEngine$$Lambda/0x00007f3c8c0e2a18";

/// Renders `template` against the request (and, for `responseTemplate`, the upstream response).
pub fn render(template: &str, request: &HttpRequest, path: &PathMatch, response: Option<&Value>, extra: &[(&str, JValue)]) -> Result<String, MustacheError> {
    render_on(&COMPILER, template, request, path, response, extra)
}

/// [`render`] on the `nullValue("")` compiler: a missing variable fails (see [`missing_variable`]).
pub fn render_strict(template: &str, request: &HttpRequest, path: &PathMatch, extra: &[(&str, JValue)]) -> Result<String, MustacheError> {
    render_on(&STRICT_COMPILER, template, request, path, None, extra)
}

/// `MustacheException.Context`'s `key` and `lineNo` for a variable that is missing (no cause): read back from the
/// messages jmustache builds them into.
pub fn missing_variable(e: &MustacheError) -> Option<(String, usize)> {
    if !e.class_name().ends_with("MustacheException$Context") {
        return None;
    }
    let message = e.message()?;
    let (head, line) = ["No method or field with name '", "Missing context for compound variable '"].iter().find_map(|prefix| message.strip_prefix(prefix))?.rsplit_once("' on line ")?;
    let line = line.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()?;
    Some((head.to_string(), line))
}

fn render_on(compiler: &Compiler, template: &str, request: &HttpRequest, path: &PathMatch, response: Option<&Value>, extra: &[(&str, JValue)]) -> Result<String, MustacheError> {
    let compiled = compiler.compile(template)?;
    // A `ConcurrentHashMap`.
    let data = JMap::new(MapKind::Hash);
    data.put_str("request", RequestObject::value(request, path));
    if let Some(r) = response {
        data.put_str("response", ResponseObject::value(r));
    }
    for (k, v) in functions::functions().into_iter().chain(functions::helpers()) {
        data.put_str(k, v);
    }
    // `MustacheTemplateEngine` binds `MustacheDateTemplateHelper` (the `render` section lambda) over `dates`.
    data.put_str("dates", JValue::Object(std::sync::Arc::new(super::dates::MustacheDates)));
    data.put_str("lists", super::lists::mustache_lists());
    data.put_str("xpath", JValue::Object(std::sync::Arc::new(MustacheXPath)));
    for (k, v) in extra {
        data.put_str(k, v.clone());
    }
    let scenario = JMap::new(MapKind::Fixed);
    scenario.put_str("get", Lambda::with_class(LAMBDA_CLASS, |name| Ok(super::scenario_state(&name))));
    data.put_str("scenario", JValue::Map(scenario));
    let xpath_request = request.clone();
    data.put_str("xPath", Lambda::with_class(LAMBDA_CLASS, move |expr| super::extract::xpath_checked(&xpath_request, &expr).map_err(MustacheError::Java)));
    let json_request = request.clone();
    let results = data.clone();
    data.put_str(
        "jsonPath",
        Lambda::with_class(LAMBDA_CLASS, move |path| {
            // The Mustache idiom: the value goes into `jsonPathResult` for a following section; nothing is written.
            results.put_str("jsonPathResult", super::extract::json_path_checked(&json_request, &path).map_err(MustacheError::Java)?);
            Ok(String::new())
        }),
    );
    let rendered = compiled.execute(JValue::Map(data.clone()));
    // The `jsonPath` lambda holds the map; drop it so the two are freed.
    data.remove(&JValue::str("jsonPath"));
    rendered
}

/// `MustacheXPathTemplateHelper`: `formatXml` is a section whose body is the XML
/// (`{{#xpath.formatXml}}{{{ request.body }}}{{/xpath.formatXml}}`).
struct MustacheXPath;

const FORMAT_XML_CLASS: &str = "org.mockserver.templates.engine.mustache.MustacheXPathTemplateHelper$$Lambda/0x00007f3c8c0e3e60";

impl java_compat::lang::JObject for MustacheXPath {
    fn class_name(&self) -> String {
        "org.mockserver.templates.engine.mustache.MustacheXPathTemplateHelper".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Option<Result<Option<JValue>, java_compat::lang::JError>> {
        match (name, args) {
            ("formatXml", []) => Some(Ok(Some(Lambda::with_class(FORMAT_XML_CLASS, |xml| super::format_xml::format_xml(Some(&xml)).map_err(MustacheError::Java))))),
            ("toString", []) => Some(Ok(Some(JValue::str("XmlXPathTemplateHelper")))),
            _ => functions::xpath(name, args),
        }
    }

    fn to_java_string(&self) -> String {
        "XmlXPathTemplateHelper".into()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

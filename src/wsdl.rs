//! `PUT /mockserver/wsdl` (`WsdlExpectationGenerator`): each SOAP operation bound to a `<service>/<port>` of a WSDL
//! 1.1 document becomes a `POST` expectation on the port's address path, matched by its `SOAPAction` (SOAP 1.1) or
//! the `action` of its content type (SOAP 1.2), else by the operation element in the body, answering a skeleton
//! envelope with an empty `<OperationResponse/>`.

use serde_json::{Value, json};

use crate::recorded::Failure;
use crate::xsd::{line_column, sax_location};

const WSDL_NS: &str = "http://schemas.xmlsoap.org/wsdl/";
const SOAP11_BINDING_NS: &str = "http://schemas.xmlsoap.org/wsdl/soap/";
const SOAP12_BINDING_NS: &str = "http://schemas.xmlsoap.org/wsdl/soap12/";
const SOAP11_ENVELOPE_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const SOAP12_ENVELOPE_NS: &str = "http://www.w3.org/2003/05/soap-envelope";

fn children<'a, 'i>(parent: roxmltree::Node<'a, 'i>, ns: &'a str, name: &'a str) -> impl Iterator<Item = roxmltree::Node<'a, 'i>> + 'a {
    parent.children().filter(move |c| c.is_element() && c.tag_name().namespace() == Some(ns) && c.tag_name().name() == name)
}

fn local_part(qname: &str) -> &str {
    qname.split_once(':').map_or(qname, |(_, l)| l)
}

/// The expectations (input form), or why the document yields none (the generator's `IllegalArgumentException`).
pub fn generate(wsdl: &str) -> Result<Vec<Value>, Failure> {
    if wsdl.trim().is_empty() {
        return Err("WSDL is required".into());
    }
    // `StringToXmlDocumentParser`: Xerces' DOM builder, DOCTYPE declarations disallowed; malformed XML in its words,
    // wrapped with the parser's `SAXParseException` as the cause.
    let text = wsdl.trim_start_matches('\u{feff}');
    let parsed = roxmltree::Document::parse(text);
    // roxmltree accepts a repeated default namespace declaration, which Xerces rejects
    let rejected = match &parsed {
        Ok(_) => crate::xsd::well_formedness_error_at(wsdl).map(|(because, at)| (because, at.map_or((1, 1), |at| line_column(text, at)))),
        Err(e) if wsdl.contains("<!DOCTYPE") => {
            let because = "DOCTYPE is disallowed when the feature \"http://apache.org/xml/features/disallow-doctype-decl\" set to true.".to_string();
            let location = sax_location(text, e, &because);
            Some((because, location))
        }
        Err(e) => Some(match crate::xsd::well_formedness_error_at(wsdl) {
            Some((because, Some(at))) => (because, line_column(text, at)),
            Some((because, None)) => {
                let location = sax_location(text, e, &because);
                (because, location)
            }
            None => (e.to_string(), sax_location(text, e, &e.to_string())),
        }),
    };
    if let Some((because, (line, column))) = rejected {
        let cause = Failure::of("org.xml.sax.SAXParseException", because.clone(), vec![("columnNumber", column.into()), ("lineNumber", line.into())], &[]);
        return Err(Failure::illegal_caused(format!("failed to parse WSDL: {because}"), cause));
    }
    let document = parsed.expect("a parse error is rejected above");
    let definitions = document.root_element();
    if definitions.tag_name().name() != "definitions" {
        return Err("not a WSDL document — expected a <definitions> root element".into());
    }
    let target_namespace = definitions.attribute("targetNamespace").filter(|t| !t.is_empty());
    let bindings: Vec<roxmltree::Node> = document.descendants().filter(|n| n.is_element() && n.tag_name().namespace() == Some(WSDL_NS) && n.tag_name().name() == "binding").collect();
    let mut expectations = Vec::new();
    for service in document.descendants().filter(|n| n.is_element() && n.tag_name().namespace() == Some(WSDL_NS) && n.tag_name().name() == "service") {
        let service_name = service.attribute("name").unwrap_or_default();
        for port in children(service, WSDL_NS, "port") {
            let binding_name = local_part(port.attribute("binding").unwrap_or_default());
            // The last binding of a name wins, as the map upstream builds keeps it.
            let Some(binding) = bindings.iter().rev().find(|b| b.attribute("name").unwrap_or_default() == binding_name) else { continue };
            let soap12 = children(port, SOAP12_BINDING_NS, "address").next().is_some();
            let binding_ns = if soap12 { SOAP12_BINDING_NS } else { SOAP11_BINDING_NS };
            let location = children(port, binding_ns, "address").filter_map(|a| a.attribute("location")).find(|l| !l.is_empty());
            let path = path_of(location);
            for operation in children(*binding, WSDL_NS, "operation") {
                let name = operation.attribute("name").unwrap_or_default();
                if name.is_empty() {
                    continue;
                }
                let nc_name = name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
                if !nc_name {
                    return Err(format!("invalid SOAP operation name in WSDL (must be an XML NCName): '{name}'").into());
                }
                let action = children(operation, binding_ns, "operation").filter_map(|o| o.attribute("soapAction")).find(|a| !a.is_empty());
                let mut request = json!({"method": "POST", "path": path});
                match (soap12, action) {
                    (true, Some(action)) => request["headers"] = json!({"content-type": [format!("application/soap\\+xml.*action=\"?{}\"?.*", crate::java_text::quote(action))]}),
                    (false, Some(action)) => request["headers"] = json!({"SOAPAction": [format!("\"?{}\"?", crate::java_text::quote(action))]}),
                    (_, None) => request["body"] = json!({"type": "XPATH", "xpath": format!("//*[local-name()='{name}']")}),
                }
                expectations.push(json!({"id": format!("{service_name}.{name}"), "httpRequest": request, "httpResponse": response(soap12, name, target_namespace)}));
            }
        }
    }
    if expectations.is_empty() {
        return Err("no SOAP operations found in WSDL — no <service>/<port> bound to a SOAP binding with operations".into());
    }
    Ok(expectations)
}

/// `pathFromLocation`: the address URI's path, `/` without one.
fn path_of(location: Option<&str>) -> String {
    let Some(location) = location else { return "/".into() };
    let after_scheme = match location.split_once("://") {
        Some((_, rest)) => rest.find('/').map_or("", |i| &rest[i..]),
        None => location,
    };
    let path = after_scheme.split(['?', '#']).next().unwrap_or_default();
    if path.is_empty() { "/".into() } else { path.to_string() }
}

fn response(soap12: bool, operation: &str, target_namespace: Option<&str>) -> Value {
    let envelope_ns = if soap12 { SOAP12_ENVELOPE_NS } else { SOAP11_ENVELOPE_NS };
    let content_type = if soap12 { "application/soap+xml; charset=utf-8" } else { "text/xml; charset=utf-8" };
    let element = match target_namespace {
        None => format!("<{operation}Response/>"),
        Some(ns) => {
            let escaped = ns.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
            format!("<{operation}Response xmlns=\"{escaped}\"/>")
        }
    };
    let envelope = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<soapenv:Envelope xmlns:soapenv=\"{envelope_ns}\">\n  <soapenv:Body>\n    {element}\n  </soapenv:Body>\n</soapenv:Envelope>"
    );
    json!({"statusCode": 200, "headers": {"content-type": [content_type]}, "body": envelope})
}

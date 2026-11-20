//! The schema for schemas (`XSAttributeChecker` and the traversers' content checks): which attributes each schema
//! element allows and what their values must be, and the order of its children, with Xerces' `s4s-*` messages.

use roxmltree::Node;

use super::types::{is_ncname, XS};

const BOOLEAN: &[&str] = &["true", "false", "1", "0"];

#[derive(Clone, Copy)]
enum Value {
    Any,
    Boolean,
    NcName,
    QName,
    QNames,
    NonNegative,
    Positive,
    MaxOccurs,
    /// An `all`'s `maxOccurs` (`1`) and `minOccurs` (`0 | 1`).
    MaxOccursOne,
    MinOccursAll,
    Form,
    Use,
    Process,
    WhiteSpace,
    /// `#all` or a list of the given words.
    Derivations(&'static [&'static str]),
    Namespaces,
}

/// Where a schema element appears, which decides the attributes it allows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    Global,
    Local,
}

fn allowed(name: &str, place: Place, node: Node) -> Option<Vec<(&'static str, Value)>> {
    use Value::*;
    const BLOCK: &[&str] = &["extension", "restriction", "substitution"];
    const FINAL_COMPLEX: &[&str] = &["extension", "restriction"];
    const FINAL_SIMPLE: &[&str] = &["list", "union", "restriction"];
    let reference = node.attribute("ref").is_some();
    let mut list: Vec<(&'static str, Value)> = match (name, place) {
        ("schema", _) => vec![
            ("attributeFormDefault", Form),
            ("blockDefault", Derivations(BLOCK)),
            ("elementFormDefault", Form),
            ("finalDefault", Derivations(&["extension", "restriction", "list", "union"])),
            ("targetNamespace", Any),
            ("version", Any),
        ],
        ("element", Place::Global) => vec![
            ("abstract", Boolean),
            ("block", Derivations(BLOCK)),
            ("default", Any),
            ("final", Derivations(FINAL_COMPLEX)),
            ("fixed", Any),
            ("name", NcName),
            ("nillable", Boolean),
            ("substitutionGroup", QName),
            ("type", QName),
        ],
        ("element", Place::Local) if reference => vec![("maxOccurs", MaxOccurs), ("minOccurs", NonNegative), ("ref", QName)],
        ("element", Place::Local) => vec![
            ("block", Derivations(BLOCK)),
            ("default", Any),
            ("fixed", Any),
            ("form", Form),
            ("maxOccurs", MaxOccurs),
            ("minOccurs", NonNegative),
            ("name", NcName),
            ("nillable", Boolean),
            ("type", QName),
        ],
        ("attribute", Place::Global) => vec![("default", Any), ("fixed", Any), ("name", NcName), ("type", QName)],
        ("attribute", Place::Local) if reference => vec![("default", Any), ("fixed", Any), ("ref", QName), ("use", Use)],
        ("attribute", Place::Local) => vec![("default", Any), ("fixed", Any), ("form", Form), ("name", NcName), ("type", QName), ("use", Use)],
        ("complexType", Place::Global) => vec![
            ("abstract", Boolean),
            ("block", Derivations(FINAL_COMPLEX)),
            ("final", Derivations(FINAL_COMPLEX)),
            ("mixed", Boolean),
            ("name", NcName),
        ],
        ("complexType", Place::Local) => vec![("mixed", Boolean)],
        ("simpleType", Place::Global) => vec![("final", Derivations(FINAL_SIMPLE)), ("name", NcName)],
        ("simpleType", Place::Local) => vec![],
        ("group", Place::Global) | ("attributeGroup", Place::Global) => vec![("name", NcName)],
        ("group", Place::Local) => vec![("maxOccurs", MaxOccurs), ("minOccurs", NonNegative), ("ref", QName)],
        ("attributeGroup", Place::Local) => vec![("ref", QName)],
        ("all", _) => vec![("maxOccurs", MaxOccursOne), ("minOccurs", MinOccursAll)],
        ("sequence" | "choice", _) => vec![("maxOccurs", MaxOccurs), ("minOccurs", NonNegative)],
        ("any", _) => vec![("maxOccurs", MaxOccurs), ("minOccurs", NonNegative), ("namespace", Namespaces), ("processContents", Process)],
        ("anyAttribute", _) => vec![("namespace", Namespaces), ("processContents", Process)],
        ("simpleContent", _) => vec![],
        ("complexContent", _) => vec![("mixed", Boolean)],
        ("restriction" | "extension", _) => vec![("base", QName)],
        ("list", _) => vec![("itemType", QName)],
        ("union", _) => vec![("memberTypes", QNames)],
        ("length" | "minLength" | "maxLength" | "fractionDigits", _) => vec![("value", NonNegative), ("fixed", Boolean)],
        ("totalDigits", _) => vec![("value", Positive), ("fixed", Boolean)],
        ("whiteSpace", _) => vec![("value", WhiteSpace), ("fixed", Boolean)],
        ("minInclusive" | "maxInclusive" | "minExclusive" | "maxExclusive", _) => vec![("value", Any), ("fixed", Boolean)],
        ("pattern" | "enumeration", _) => vec![("value", Any)],
        ("include" | "redefine", _) => vec![("schemaLocation", Any)],
        ("import", _) => vec![("namespace", Any), ("schemaLocation", Any)],
        ("notation", _) => vec![("name", NcName), ("public", Any), ("system", Any)],
        ("annotation", _) => vec![],
        ("appinfo", _) => vec![("source", Any)],
        ("documentation", _) => vec![("source", Any)],
        ("unique" | "key", _) => vec![("name", NcName)],
        ("keyref", _) => vec![("name", NcName), ("refer", QName)],
        ("selector" | "field", _) => vec![("xpath", Any)],
        _ => return None,
    };
    if !matches!(name, "appinfo" | "documentation") {
        list.push(("id", NcName));
    }
    Some(list)
}

fn required(name: &str, place: Place, node: Node) -> &'static [&'static str] {
    match (name, place) {
        ("element" | "attribute", Place::Global) | ("complexType" | "simpleType" | "group" | "attributeGroup", Place::Global) => &["name"],
        ("group" | "attributeGroup", Place::Local) => &["ref"],
        ("extension", _) => &["base"],
        ("restriction", _) if node.parent_element().is_some_and(|p| p.tag_name().name() == "complexContent") => &["base"],
        ("length" | "minLength" | "maxLength" | "fractionDigits" | "totalDigits" | "whiteSpace" | "minInclusive" | "maxInclusive" | "minExclusive" | "maxExclusive" | "pattern" | "enumeration", _) => &["value"],
        ("include" | "redefine", _) => &["schemaLocation"],
        ("notation" | "unique" | "key", _) => &["name"],
        ("keyref", _) => &["name", "refer"],
        ("selector" | "field", _) => &["xpath"],
        _ => &[],
    }
}

fn datatype_error(value: &str, ty: &str) -> String {
    format!("cvc-datatype-valid.1.2.1: '{value}' is not a valid value for '{ty}'.")
}

fn enumeration_error(value: &str, choices: &str) -> String {
    format!("cvc-enumeration-valid: Value '{value}' is not facet-valid with respect to enumeration '({choices})'. It must be a value from the enumeration.")
}

fn check_value(node: Node, kind: Value, raw: &str) -> Result<(), String> {
    let value = raw.trim_matches([' ', '\t', '\n', '\r']);
    let qname = |v: &str| -> Result<(), String> {
        let (prefix, local) = match v.split_once(':') {
            Some((p, l)) => (Some(p), l),
            None => (None, v),
        };
        if !prefix.is_none_or(is_ncname) || !is_ncname(local) {
            return Err(datatype_error(v, "QName"));
        }
        if let Some(p) = prefix.filter(|p| *p != "xml" && node.lookup_namespace_uri(Some(p)).is_none()) {
            return Err(format!("UndeclaredPrefix: Cannot resolve '{v}' as a QName: the prefix '{p}' is not declared."));
        }
        Ok(())
    };
    // `Integer.parseInt` after one leading `+` is dropped.
    let int = |v: &str| v.strip_prefix('+').unwrap_or(v).parse::<i32>().ok();
    match kind {
        Value::Any => Ok(()),
        Value::Boolean if BOOLEAN.contains(&value) => Ok(()),
        Value::Boolean => Err(datatype_error(value, "boolean")),
        Value::NcName if is_ncname(value) => Ok(()),
        Value::NcName => Err(datatype_error(value, "NCName")),
        Value::QName => qname(value),
        Value::QNames => value
            .split_whitespace()
            .try_for_each(qname)
            .map_err(|_| format!("cvc-datatype-valid.1.2.2: '{value}' is not a valid value of list type '(List of QName)'.")),
        Value::NonNegative if int(value).is_some_and(|n| n >= 0) => Ok(()),
        Value::NonNegative => Err(datatype_error(value, "nonNegativeInteger")),
        Value::Positive if int(value).is_some_and(|n| n > 0) => Ok(()),
        Value::Positive => Err(datatype_error(value, "positiveInteger")),
        Value::MaxOccurs if value == "unbounded" || int(value).is_some_and(|n| n >= 0) => Ok(()),
        Value::MaxOccurs => Err(datatype_error(value, "nonNegativeInteger")),
        Value::MaxOccursOne if value == "1" => Ok(()),
        Value::MaxOccursOne => Err(enumeration_error(value, "1")),
        Value::MinOccursAll if matches!(value, "0" | "1") => Ok(()),
        Value::MinOccursAll => Err(enumeration_error(value, "0 | 1")),
        Value::Form if matches!(value, "qualified" | "unqualified") => Ok(()),
        Value::Form => Err(enumeration_error(value, "qualified | unqualified")),
        Value::Use if matches!(value, "optional" | "prohibited" | "required") => Ok(()),
        Value::Use => Err(enumeration_error(value, "optional | prohibited | required")),
        Value::Process if matches!(value, "skip" | "lax" | "strict") => Ok(()),
        Value::Process => Err(enumeration_error(value, "lax | skip | strict")),
        Value::WhiteSpace if matches!(value, "preserve" | "replace" | "collapse") => Ok(()),
        Value::WhiteSpace => Err(enumeration_error(value, "preserve | replace | collapse")),
        Value::Derivations(words) => {
            if value == "#all" || value.split_whitespace().all(|w| words.contains(&w)) {
                Ok(())
            } else {
                Err(format!("cvc-datatype-valid.1.2.3: '{value}' is not a valid value of union type '(#all | List of ({}))'.", words.join(" | ")))
            }
        }
        Value::Namespaces => {
            if matches!(value, "##any" | "##other") || value.split_whitespace().all(|w| !w.starts_with("##") || matches!(w, "##targetNamespace" | "##local")) {
                Ok(())
            } else {
                Err(format!("cvc-datatype-valid.1.2.3: '{value}' is not a valid value of union type '((##any | ##other) | List of (anyURI | (##targetNamespace | ##local)) )'."))
            }
        }
    }
}

/// Where Xerces' parser stands when it reports `node`'s first non-whitespace text: past the `</` of the end tag
/// after the text, or past the `<` of the next markup.
fn text_end(node: Node) -> usize {
    let text = node.children().find(|c| c.is_text() && c.text().is_some_and(|t| !t.trim().is_empty()));
    let end = text.map_or(node.range().start, |t| t.range().end);
    let rest = &node.document().input_text()[end..];
    end + if rest.starts_with("</") { 2 } else { 1 }
}

/// The schema element's children (annotations included), the schema namespace's only.
fn children<'a, 'input>(node: Node<'a, 'input>) -> Vec<Node<'a, 'input>> {
    node.children().filter(|c| c.is_element()).collect()
}

/// One slot of a content model: the names it accepts and how many times.
type Slot = (&'static [&'static str], usize, usize);

const PARTICLES: &[&str] = &["group", "all", "choice", "sequence"];
const ATTRS: &[&str] = &["attribute", "attributeGroup"];
const FACETS: &[&str] = &[
    "minExclusive",
    "minInclusive",
    "maxExclusive",
    "maxInclusive",
    "totalDigits",
    "fractionDigits",
    "length",
    "minLength",
    "maxLength",
    "enumeration",
    "whiteSpace",
    "pattern",
];

/// Greedy match of `kids` against `slots`: `Err(Some(i))` for the first child that does not fit, `Err(None)` for
/// too few.
fn fit(kids: &[&str], slots: &[Slot]) -> Result<(), Option<usize>> {
    let mut i = 0;
    for (names, min, max) in slots {
        let mut n = 0;
        while i < kids.len() && n < *max && names.contains(&kids[i]) {
            i += 1;
            n += 1;
        }
        if n < *min {
            return Err(if i < kids.len() { Some(i) } else { None });
        }
    }
    if i < kids.len() { Err(Some(i)) } else { Ok(()) }
}

/// The checks of one schema document, in document order; the first failure is the schema's error, with the
/// offset of the element it is reported at.
pub fn check(root: Node) -> Result<(), (String, usize)> {
    element(root, Place::Global)
}

fn element(node: Node, place: Place) -> Result<(), (String, usize)> {
    // `checkOccurrences` reports an element's occurrence in an `all` at the `all`; a restriction or list with both
    // a type attribute and a simple type, at the simple type; text, where the parser stands after it.
    let at = |message: String| {
        if message.starts_with("s4s-elt-character") {
            return (message, text_end(node));
        }
        let place = if message.starts_with("cos-all-limited.2") {
            node.parent_element().unwrap_or(node)
        } else if message.starts_with("src-simple-type.2.a") || message.starts_with("src-simple-type.3.a") {
            node.children().find(|c| c.is_element() && c.tag_name().name() == "simpleType").unwrap_or(node)
        } else {
            node
        };
        (message, place.range().start)
    };
    let kids = children(node);
    let names: Vec<&str> = kids.iter().map(|k| if k.tag_name().namespace() == Some(XS) { k.tag_name().name() } else { "" }).collect();
    let found = attributes(node, place).map_err(at)?;
    if !found {
        return Ok(());
    }
    // A content error is reported at the child it was found at; too few children, at the last one.
    content(node, node.tag_name().name(), place, &names).map_err(|(message, i)| match i {
        Some(i) => (message, kids[i].range().start),
        None => (message, kids.last().unwrap_or(&node).range().start),
    })?;
    for kid in &kids {
        let child_place = match node.tag_name().name() {
            "schema" | "redefine" => Place::Global,
            _ => Place::Local,
        };
        element(*kid, child_place)?;
    }
    Ok(())
}

/// The checks of `node`'s own attributes and representation; `false` for an element whose content is not checked.
fn attributes(node: Node, place: Place) -> Result<bool, String> {
    let name = node.tag_name().name();
    if node.tag_name().namespace() != Some(XS) {
        return Err(format!("s4s-elt-schema-ns: The namespace of element '{name}' must be from the schema namespace, 'http://www.w3.org/2001/XMLSchema'."));
    }
    if matches!(name, "appinfo" | "documentation") {
        return Ok(false);
    }
    let Some(attributes) = allowed(name, place, node) else {
        return Err(format!("s4s-elt-invalid: Element '{name}' is not a valid element in a schema document."));
    };
    for attribute in node.attributes() {
        if attribute.namespace().is_some() {
            continue;
        }
        match attributes.iter().find(|(a, _)| *a == attribute.name()) {
            Some((_, kind)) => check_value(node, *kind, attribute.value())
                .map_err(|reason| format!("s4s-att-invalid-value: Invalid attribute value for '{}' in element '{name}'. Recorded reason: {reason}", attribute.name()))?,
            None => return Err(format!("s4s-att-not-allowed: Attribute '{}' cannot appear in element '{name}'.", attribute.name())),
        }
    }
    for must in required(name, place, node) {
        if node.attribute(*must).is_none() {
            return Err(format!("s4s-att-must-appear: Attribute '{must}' must appear in element '{name}'."));
        }
    }
    representation(node, name, place)?;
    if let Some(text) = node.children().filter(|c| c.is_text()).filter_map(|c| c.text()).find(|t| !t.trim().is_empty()) {
        return Err(format!(
            "s4s-elt-character: Non-whitespace characters are not allowed in schema elements other than 'xs:appinfo' and 'xs:documentation'. Saw '{}'.",
            text.trim()
        ));
    }
    Ok(true)
}

/// The content model check of `node`: the message and the index of the child it was found at (`None`: too few).
fn content(node: Node, name: &str, place: Place, kids: &[&str]) -> Result<(), (String, Option<usize>)> {
    const ANNOTATION: Slot = (&["annotation"], 0, 1);
    const MANY: usize = usize::MAX;
    let must_match = |model: &str, result: Result<(), Option<usize>>, owner: &str| -> Result<(), (String, Option<usize>)> {
        match result {
            Ok(()) => Ok(()),
            Err(Some(i)) => Err((format!("s4s-elt-must-match.1: The content of '{owner}' must match {model}. A problem was found starting at: {}.", kids[i]), Some(i))),
            Err(None) => Err((format!("s4s-elt-must-match.2: The content of '{owner}' must match {model}. Not enough elements were found."), None)),
        }
    };
    let invalid = |result: Result<(), Option<usize>>, owner: &str| -> Result<(), (String, Option<usize>)> {
        match result {
            Ok(()) => Ok(()),
            Err(Some(i)) => Err((format!("s4s-elt-invalid-content.1: The content of '{owner}' is invalid.  Element '{}' is invalid, misplaced, or occurs too often.", kids[i]), Some(i))),
            Err(None) => Err((format!("s4s-elt-invalid-content.2: The content of '{owner}' is invalid.  Element '{name}' cannot be empty."), None)),
        }
    };
    let attribute_slots: [Slot; 2] = [(ATTRS, 0, MANY), (&["anyAttribute"], 0, 1)];
    match name {
        "schema" => {
            let mut declared = false;
            for (i, kid) in kids.iter().enumerate() {
                match *kid {
                    "include" | "import" | "redefine" if declared => {
                        return Err((format!("s4s-elt-invalid-content.3: Elements of type '{kid}' cannot appear after declarations as children of a <schema> element."), Some(i)));
                    }
                    "include" | "import" | "redefine" | "annotation" => {}
                    "simpleType" | "complexType" | "group" | "attributeGroup" | "element" | "attribute" | "notation" => declared = true,
                    _ => return invalid(Err(Some(i)), "schema"),
                }
            }
            Ok(())
        }
        "element" => {
            let owner = node.attribute("name").or(node.attribute("ref")).unwrap_or("element");
            if place == Place::Local && node.attribute("ref").is_some() && let Some(i) = kids.iter().position(|k| *k != "annotation") {
                return Err((format!("src-element.2.2: Since '{owner}' contains the 'ref' attribute, its content must match (annotation?). However, '{}' was found.", kids[i]), Some(i)));
            }
            must_match(
                "(annotation?, (simpleType | complexType)?, (unique | key | keyref)*))",
                fit(kids, &[ANNOTATION, (&["simpleType", "complexType"], 0, 1), (&["unique", "key", "keyref"], 0, MANY)]),
                owner,
            )
        }
        "complexType" => {
            let owner = match node.attribute("name") {
                Some(n) => n.to_string(),
                None => super::Builder::anonymous_name(node),
            };
            let start = usize::from(kids.first() == Some(&"annotation"));
            let result = if kids.get(start).is_some_and(|k| matches!(*k, "simpleContent" | "complexContent")) {
                fit(kids, &[ANNOTATION, (&["simpleContent", "complexContent"], 1, 1)])
            } else {
                fit(kids, &[ANNOTATION, (PARTICLES, 0, 1), attribute_slots[0], attribute_slots[1]])
            };
            invalid(result, &owner)
        }
        "simpleContent" | "complexContent" if !kids.iter().any(|k| *k != "annotation") => {
            // `XSDComplexTypeTraverser`: the derivation is missing, named after the complex type.
            let owner = node.parent_element().map(|p| p.attribute("name").map(str::to_string).unwrap_or_else(|| super::Builder::anonymous_name(p))).unwrap_or_default();
            Err((format!("s4s-elt-invalid-content.2: The content of '{owner}' is invalid.  Element '{name}' cannot be empty."), None))
        }
        "simpleContent" | "complexContent" => must_match(
            "(annotation?, (restriction | extension))",
            fit(kids, &[ANNOTATION, (&["restriction", "extension"], 1, 1)]),
            name,
        ),
        "restriction" | "extension" => {
            let parent = node.parent_element().map(|p| p.tag_name().name().to_string()).unwrap_or_default();
            let result = match (parent.as_str(), name) {
                ("simpleType", _) => fit(kids, &[ANNOTATION, (&["simpleType"], 0, 1), (FACETS, 0, MANY)]),
                ("simpleContent", "restriction") => fit(kids, &[ANNOTATION, (&["simpleType"], 0, 1), (FACETS, 0, MANY), attribute_slots[0], attribute_slots[1]]),
                ("simpleContent", _) => fit(kids, &[ANNOTATION, attribute_slots[0], attribute_slots[1]]),
                _ => fit(kids, &[ANNOTATION, (PARTICLES, 0, 1), attribute_slots[0], attribute_slots[1]]),
            };
            let owner = node.ancestors().skip(1).find_map(|a| a.attribute("name")).unwrap_or(name);
            invalid(result, owner)
        }
        "sequence" | "choice" => must_match(
            "(annotation?, (element | group | choice | sequence | any)*)",
            fit(kids, &[ANNOTATION, (&["element", "group", "choice", "sequence", "any"], 0, MANY)]),
            name,
        ),
        "all" => must_match("(annotation?, element*)", fit(kids, &[ANNOTATION, (&["element"], 0, MANY)]), name),
        "group" if place == Place::Global => must_match(
            "(annotation?, (all | choice | sequence))",
            fit(kids, &[ANNOTATION, (&["all", "choice", "sequence"], 1, 1)]),
            node.attribute("name").unwrap_or(name),
        ),
        "attributeGroup" if place == Place::Global => {
            invalid(fit(kids, &[ANNOTATION, attribute_slots[0], attribute_slots[1]]), node.attribute("name").unwrap_or(name))
        }
        "simpleType" => must_match(
            "(annotation?, (restriction | list | union))",
            fit(kids, &[ANNOTATION, (&["restriction", "list", "union"], 1, 1)]),
            node.attribute("name").unwrap_or(name),
        ),
        "attribute" => must_match("(annotation?, (simpleType?))", fit(kids, &[ANNOTATION, (&["simpleType"], 0, 1)]), node.attribute("name").unwrap_or(name)),
        "list" => must_match("(annotation?, (simpleType?))", fit(kids, &[ANNOTATION, (&["simpleType"], 0, 1)]), name),
        "union" => must_match("(annotation?, (simpleType*))", fit(kids, &[ANNOTATION, (&["simpleType"], 0, MANY)]), name),
        "redefine" => must_match(
            "(annotation | (simpleType | complexType | group | attributeGroup))*",
            fit(kids, &[(&["annotation", "simpleType", "complexType", "group", "attributeGroup"], 0, MANY)]),
            name,
        ),
        "annotation" => must_match("(appinfo | documentation)*", fit(kids, &[(&["appinfo", "documentation"], 0, MANY)]), name),
        "unique" | "key" | "keyref" => must_match(
            "(annotation?, selector, field+)",
            fit(kids, &[ANNOTATION, (&["selector"], 1, 1), (&["field"], 1, MANY)]),
            "identity constraint",
        ),
        _ => must_match("(annotation?)", fit(kids, &[ANNOTATION]), name),
    }
}

/// The representation constraints the traversers check on one element's own attributes and children
/// (`src-element.*`, `src-attribute.*`, `no-xmlns`, `cos-all-limited.2`, `src-simple-type.*`).
fn representation(node: Node, name: &str, place: Place) -> Result<(), String> {
    let has = |a: &str| node.attribute(a).is_some();
    let child = |n: &str| node.children().any(|c| c.is_element() && c.tag_name().namespace() == Some(XS) && c.tag_name().name() == n);
    let label = node.attribute("name").or(node.attribute("ref")).unwrap_or_default();
    match name {
        "element" => {
            if place == Place::Local && !has("name") && !has("ref") {
                return Err("src-element.2.1: : One of 'ref' or 'name' must be present in a local element declaration.".into());
            }
            if has("default") && has("fixed") {
                return Err(format!("src-element.1: The properties 'default' and 'fixed' cannot both be present in element declaration '{label}'. Use only one of them."));
            }
            if has("type") && (child("simpleType") || child("complexType")) {
                return Err(format!("src-element.3: Element '{label}' has both a 'type' attribute and a 'anonymous type' child. Only one of these is allowed for an element."));
            }
            let in_all = node.parent_element().is_some_and(|p| p.tag_name().name() == "all");
            if in_all && let Some(max) = node.attribute("maxOccurs").map(str::trim).filter(|m| !matches!(*m, "0" | "1")) {
                return Err(format!("cos-all-limited.2: The {{max occurs}} of an element in an 'all' model group must be 0 or 1. The value '{max}' for element '{label}' is invalid."));
            }
        }
        "attribute" => {
            if place == Place::Local && !has("name") && !has("ref") {
                return Err("src-attribute.3.1: One of 'ref' or 'name' must be present in a local attribute declaration.".into());
            }
            if has("default") && has("fixed") {
                return Err(format!("src-attribute.1: The properties 'default' and 'fixed' cannot both be present in attribute declaration '{label}'. Use only one of them."));
            }
            if has("default") && node.attribute("use").is_some_and(|u| u.trim() != "optional") {
                return Err(format!("src-attribute.2: : The property 'default' is present in attribute '{label}', so the value of 'use' must be 'optional'."));
            }
            if has("type") && child("simpleType") {
                return Err(format!("src-attribute.4: Attribute '{label}' has both a 'type' attribute and an anonymous 'simpleType' child. Only one of these is allowed for an attribute."));
            }
            if node.attribute("name") == Some("xmlns") {
                return Err("no-xmlns: The {name} of an attribute declaration must not match 'xmlns'.".into());
            }
        }
        "all" => {
            if node.attribute("maxOccurs").is_some_and(|m| m.trim() != "1") || node.attribute("minOccurs").is_some_and(|m| !matches!(m.trim(), "0" | "1")) {
                return Err("cos-all-limited.1.2: An 'all' model group must appear in a particle with '{'min occurs'}' = '{'max occurs'}' = 1, and that particle must be part of a pair which constitutes the '{'content type'}' of a complex type definition.".into());
            }
        }
        "restriction" if node.parent_element().is_some_and(|p| p.tag_name().name() == "simpleType") => {
            if has("base") && child("simpleType") {
                return Err("src-simple-type.2.a: A <restriction> element was found that has both a base [attribute] and a <simpleType> element among its [children]. Only one is allowed.".into());
            }
            if !has("base") && !child("simpleType") {
                return Err("src-simple-type.2.b: A <restriction> element was found that has neither a base [attribute] nor a <simpleType> element among its [children]. One is required.".into());
            }
        }
        "list" => {
            if has("itemType") && child("simpleType") {
                return Err("src-simple-type.3.a: A <list> element was found that has both an itemType [attribute] and a <simpleType> element among its [children]. Only one is allowed.".into());
            }
            if !has("itemType") && !child("simpleType") {
                return Err("src-simple-type.3.b: A <list> element was found that has neither an itemType [attribute] nor a <simpleType> element among its [children]. One is required.".into());
            }
        }
        "union" if node.attribute("memberTypes").is_none_or(|m| m.trim().is_empty()) && !child("simpleType") => {
            return Err("src-union-memberTypes-or-simpleTypes: A <union> element must have either a non-empty memberTypes [attribute] or at least one <simpleType> element among its [children].".into());
        }
        _ => {}
    }
    Ok(())
}

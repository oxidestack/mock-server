//! Instance validation (`XMLSchemaValidator`): document order, first error wins, with Xerces' messages.

use std::collections::HashSet;

use roxmltree::Node;

use super::identity::{self, Value};
use super::{Content, ElemId, Expr, Process, QName, Schema, Type, TypeId, Wildcard};

const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// One validation's state: the IDs seen, the IDREFs to resolve at the end of the document, and the identity
/// constraints' matchers.
#[derive(Default)]
struct Cx {
    ids: HashSet<String>,
    refs: Vec<String>,
    ic: identity::State,
}

/// A child a content model accepted: a declaration, or a wildcard.
enum Matched {
    Element(ElemId),
    Wildcard(Wildcard),
}

impl Schema {
    /// `Validator.validate`: `Err` is the message of the first error (a parse error or a schema violation).
    pub fn validate(&self, xml: &str) -> Result<(), String> {
        let doc = parse(xml)?;
        let root = doc.root_element();
        let mut cx = Cx::default();
        let Some(decl) = self.globals.get(&qname(root)) else {
            return Err(format!("cvc-elt.1.a: Cannot find the declaration of element '{}'.", raw_name(root)));
        };
        self.element(root, *decl, &mut cx)?;
        if let Some(missing) = cx.refs.iter().find(|r| !cx.ids.contains(*r)) {
            return Err(format!("cvc-id.1: There is no ID/IDREF binding for IDREF '{missing}'."));
        }
        Ok(())
    }

    fn element(&self, node: Node, decl: ElemId, cx: &mut Cx) -> Result<(), String> {
        let decl = &self.elements[decl];
        let resolve = |prefix: Option<&str>| node.lookup_namespace_uri(prefix).map(str::to_string);
        let name = raw_name(node);
        let mut ty = decl.ty;
        if let Some(xsi_type) = node.attribute((XSI, "type")) {
            let (prefix, local) = xsi_type.split_once(':').map(|(p, l)| (Some(p), l)).unwrap_or((None, xsi_type));
            let namespace = node.lookup_namespace_uri(prefix).unwrap_or_default().to_string();
            ty = *self
                .global_types
                .get(&(namespace, local.to_string()))
                .ok_or_else(|| format!("cvc-elt.4.2: Cannot resolve '{xsi_type}' to a type definition for element '{name}'."))?;
        }
        let nil = match node.attribute((XSI, "nil")) {
            Some(v) if matches!(v.trim(), "true" | "1") => {
                if !decl.nillable {
                    return Err(format!(
                        "cvc-elt.3.1: Attribute 'http://www.w3.org/2001/XMLSchema-instance,nil' must not appear on element '{name}', because the {{nillable}} property of '{name}' is false."
                    ));
                }
                true
            }
            _ => false,
        };
        match &self.types[ty] {
            Type::Simple(_) => {
                if let Some(a) = node.attributes().find(|a| a.namespace() != Some(XSI)) {
                    return Err(format!(
                        "cvc-type.3.1.1: Element '{name}' is a simple type, so it cannot have attributes, excepting those whose namespace name is identical to 'http://www.w3.org/2001/XMLSchema-instance' and whose [local name] is one of 'type', 'nil', 'schemaLocation' or 'noNamespaceSchemaLocation'. However, the attribute, '{}' was found.",
                        attribute_raw_name(node, &a)
                    ));
                }
                self.ic_start(&mut cx.ic, qname(node), &decl.constraints, &[])?;
                if node.children().any(|c| c.is_element()) {
                    return Err(format!("cvc-type.3.1.2: Element '{name}' is a simple type, so it must have no element information item [children]."));
                }
                let text = text_of(node);
                if nil {
                    if !text.is_empty() {
                        return Err(nil_error(&name));
                    }
                    return self.ic_end(&mut cx.ic, identity::Content::Simple(None), decl.nillable);
                }
                let value = self.element_value(node, decl, ty, &text, cx)?;
                self.ic_end_value(cx, ty, &value, decl.nillable, &resolve)
            }
            Type::Complex(ct) => {
                let attributes = self.attributes(node, ct, cx)?;
                self.ic_start(&mut cx.ic, qname(node), &decl.constraints, &attributes)?;
                if nil {
                    let content = node.children().any(|c| c.is_element() || (c.is_text() && !c.text().unwrap_or_default().is_empty()));
                    if content {
                        return Err(nil_error(&name));
                    }
                    return self.ic_end(&mut cx.ic, identity::Content::Simple(None), decl.nillable);
                }
                match &ct.content {
                    Content::Any => {
                        self.lax_children(node, cx)?;
                        self.ic_end(&mut cx.ic, identity::Content::NotSimple, decl.nillable)
                    }
                    Content::Empty => {
                        let characters = node.children().any(|c| c.is_text() && !is_whitespace(c.text().unwrap_or_default()));
                        if characters || node.children().any(|c| c.is_element()) {
                            return Err(format!(
                                "cvc-complex-type.2.1: Element '{name}' must have no character or element information item [children], because the type's content type is empty."
                            ));
                        }
                        self.ic_end(&mut cx.ic, identity::Content::NotSimple, decl.nillable)
                    }
                    Content::Simple(simple) => {
                        if node.children().any(|c| c.is_element()) {
                            return Err(format!("cvc-complex-type.2.2: Element '{name}' must have no element [children], and the value must be valid."));
                        }
                        let value = self.element_value(node, decl, *simple, &text_of(node), cx)?;
                        self.ic_end_value(cx, *simple, &value, decl.nillable, &resolve)
                    }
                    Content::Elements(model) => {
                        let mut state = model.clone();
                        let mut characters = false;
                        for child in node.children() {
                            if child.is_text() {
                                characters |= !ct.mixed && !is_whitespace(child.text().unwrap_or_default());
                                continue;
                            }
                            if !child.is_element() {
                                continue;
                            }
                            let child_name = qname(child);
                            let Some(matched) = self.accepting(&state, &child_name) else {
                                let expected = self.expected(&state);
                                return Err(if expected.is_empty() {
                                    format!(
                                        "cvc-complex-type.2.4.d: Invalid content was found starting with element '{}'. No child element is expected at this point.",
                                        expanded_name(child)
                                    )
                                } else {
                                    format!(
                                        "cvc-complex-type.2.4.a: Invalid content was found starting with element '{}'. One of '{{{expected}}}' is expected.",
                                        expanded_name(child)
                                    )
                                });
                            };
                            state = simplify(self.derive(&state, &child_name));
                            match matched {
                                Matched::Element(decl) => self.element(child, self.substitute(decl, &child_name), cx)?,
                                Matched::Wildcard(w) => self.wildcard_child(child, &w, cx)?,
                            }
                        }
                        if characters {
                            return Err(format!(
                                "cvc-complex-type.2.3: Element '{name}' cannot have character [children], because the type's content type is element-only."
                            ));
                        }
                        if !self.nullable(&state) {
                            return Err(format!(
                                "cvc-complex-type.2.4.b: The content of element '{name}' is not complete. One of '{{{}}}' is expected.",
                                self.expected(&state)
                            ));
                        }
                        self.ic_end(&mut cx.ic, identity::Content::NotSimple, decl.nillable)
                    }
                }
            }
        }
    }

    /// A simple-typed value of element `node` (its type's, or a complex type's simple content), with the
    /// declaration's default and fixed value.
    /// [`Schema::ic_end`] for an element whose value is `value` of simple type `ty`.
    fn ic_end_value(&self, cx: &mut Cx, ty: TypeId, value: &str, nillable: bool, resolve: &dyn Fn(Option<&str>) -> Option<String>) -> Result<(), String> {
        if self.constraints.is_empty() {
            return Ok(());
        }
        let value = self.ic_value(ty, value, resolve);
        self.ic_end(&mut cx.ic, identity::Content::Simple(Some(&value)), nillable)
    }

    fn element_value(&self, node: Node, decl: &super::ElementDecl, ty: TypeId, text: &str, cx: &mut Cx) -> Result<String, String> {
        let text = if text.is_empty() { decl.default.as_deref().or(decl.fixed.as_deref()).unwrap_or_default() } else { text };
        let value = self.simple_value(node, ty, text, cx)?;
        if let Some(fixed) = &decl.fixed {
            let fixed_value = crate::xsd::types::normalize(fixed, self.white_space(ty));
            if fixed_value != value {
                return Err(format!(
                    "cvc-elt.5.2.2.2.2: The value '{value}' of element '{}' does not match the {{value constraint}} value '{fixed}'.",
                    raw_name(node)
                ));
            }
        }
        Ok(value)
    }

    fn simple_value(&self, node: Node, ty: TypeId, text: &str, cx: &mut Cx) -> Result<String, String> {
        let value = self.validate_simple(ty, text, &|prefix| node.lookup_namespace_uri(Some(prefix)).is_some())?;
        if self.derives_from(ty, "ID") {
            if !cx.ids.insert(value.clone()) {
                return Err(format!("cvc-id.2: There are multiple occurrences of ID value '{value}'."));
            }
        } else if self.derives_from(ty, "IDREF") {
            cx.refs.push(value.clone());
        } else if self.derives_from(ty, "IDREFS") {
            cx.refs.extend(value.split(' ').map(str::to_string));
        }
        Ok(value)
    }

    /// Validates the attributes of `node`; returns their actual values when identity constraints need them.
    fn attributes(&self, node: Node, ct: &super::ComplexType, cx: &mut Cx) -> Result<Vec<(QName, Value)>, String> {
        let element = raw_name(node);
        let mut values = Vec::new();
        let resolve = |prefix: Option<&str>| node.lookup_namespace_uri(prefix).map(str::to_string);
        for attribute in node.attributes() {
            let namespace = attribute.namespace().unwrap_or_default();
            if namespace == XSI {
                continue;
            }
            let name: QName = (namespace.to_string(), attribute.name().to_string());
            match ct.attributes.iter().find(|u| u.name == name && !u.prohibited) {
                Some(attribute_use) => {
                    let value = self.simple_value(node, attribute_use.ty, attribute.value(), cx)?;
                    if !self.constraints.is_empty() {
                        values.push((name.clone(), self.ic_value(attribute_use.ty, &value, &resolve)));
                    }
                    if let Some(fixed) = attribute_use.fixed.as_ref().filter(|f| crate::xsd::types::normalize(f, self.white_space(attribute_use.ty)) != value) {
                        let raw = attribute_raw_name(node, &attribute);
                        return Err(format!(
                            "cvc-complex-type.3.1: Value '{}' of attribute '{raw}' of element '{element}' is not valid with respect to the corresponding attribute use. Attribute '{raw}' has a fixed value of '{fixed}'.",
                            attribute.value()
                        ));
                    }
                }
                None => match ct.attribute_wildcard.as_ref().filter(|w| w.allows(namespace)) {
                    Some(w) if w.process != Process::Skip => {
                        match self.global_attributes.get(&name) {
                            Some(global) => {
                                let value = self.simple_value(node, global.ty, attribute.value(), cx)?;
                                if !self.constraints.is_empty() {
                                    values.push((name.clone(), self.ic_value(global.ty, &value, &resolve)));
                                }
                            }
                            None => values.push((name.clone(), Value::null())),
                        }
                    }
                    Some(_) => values.push((name.clone(), Value::null())),
                    None => {
                        return Err(format!(
                            "cvc-complex-type.3.2.2: Attribute '{}' is not allowed to appear in element '{element}'.",
                            attribute_raw_name(node, &attribute)
                        ));
                    }
                },
            }
        }
        for required in ct.attributes.iter().filter(|u| u.required && !u.prohibited) {
            let present = node.attributes().any(|a| a.namespace().unwrap_or_default() == required.name.0 && a.name() == required.name.1);
            if !present {
                return Err(format!("cvc-complex-type.4: Attribute '{}' must appear on element '{element}'.", required.name.1));
            }
        }
        Ok(values)
    }

    fn wildcard_child(&self, child: Node, wildcard: &Wildcard, cx: &mut Cx) -> Result<(), String> {
        match (wildcard.process, self.globals.get(&qname(child))) {
            (Process::Skip, _) => Ok(()),
            (_, Some(decl)) => self.element(child, *decl, cx),
            (Process::Lax, None) => self.lax_element(child, cx),
            (Process::Strict, None) => Err(format!(
                "cvc-complex-type.2.4.c: The matching wildcard is strict, but no declaration can be found for element '{}'.",
                raw_name(child)
            )),
        }
    }

    /// Content assessed laxly (`anyType`, lax wildcards): declared elements are validated, others descended into.
    fn lax_children(&self, node: Node, cx: &mut Cx) -> Result<(), String> {
        for child in node.children().filter(|c| c.is_element()) {
            self.lax_element(child, cx)?;
        }
        Ok(())
    }

    /// An element assessed laxly: by its global declaration, or, without one, untyped with its children laxly.
    fn lax_element(&self, node: Node, cx: &mut Cx) -> Result<(), String> {
        match self.globals.get(&qname(node)) {
            Some(decl) => self.element(node, *decl, cx),
            None => {
                // Assessed as `anyType`: its attributes match fields without an actual value.
                let attributes: Vec<(QName, Value)> = node
                    .attributes()
                    .filter(|a| a.namespace() != Some(XSI))
                    .map(|a| ((a.namespace().unwrap_or_default().to_string(), a.name().to_string()), Value::null()))
                    .collect();
                self.ic_start(&mut cx.ic, qname(node), &[], &attributes)?;
                self.lax_children(node, cx)?;
                self.ic_end(&mut cx.ic, identity::Content::NotSimple, false)
            }
        }
    }

    /// The declaration a matched element uses: a substitution group member's own, when it was named.
    fn substitute(&self, decl: ElemId, name: &QName) -> ElemId {
        if self.elements[decl].name == *name {
            return decl;
        }
        self.substitutes.get(&decl).and_then(|members| members.iter().find(|m| self.elements[**m].name == *name)).copied().unwrap_or(decl)
    }

    fn element_matches(&self, decl: ElemId, name: &QName) -> bool {
        self.elements[decl].name == *name
            || self.substitutes.get(&decl).is_some_and(|members| members.iter().any(|m| self.elements[*m].name == *name))
    }

    pub(super) fn nullable(&self, e: &Expr) -> bool {
        match e {
            Expr::Empty => true,
            Expr::Fail | Expr::Element(_) | Expr::Any(_) => false,
            Expr::Sequence(items) => items.iter().all(|i| self.nullable(i)),
            // A choice without particles (in the schema, not a derivative) accepts nothing, as Xerces' content model has it.
            Expr::Choice(items) => items.is_empty() || items.iter().any(|i| self.nullable(i)),
            Expr::Repeat(inner, min, _) => *min == 0 || self.nullable(inner),
            Expr::All(members) => members.iter().all(|(_, required)| !required),
        }
    }

    /// The terms that can accept the next child, in declaration order.
    fn first(&self, e: &Expr, out: &mut Vec<Matched>) {
        match e {
            Expr::Empty | Expr::Fail => {}
            Expr::Element(d) => out.push(Matched::Element(*d)),
            Expr::Any(w) => out.push(Matched::Wildcard((**w).clone())),
            Expr::Sequence(items) => {
                for item in items {
                    self.first(item, out);
                    if !self.nullable(item) {
                        break;
                    }
                }
            }
            Expr::Choice(items) => items.iter().for_each(|i| self.first(i, out)),
            Expr::Repeat(inner, _, max) => {
                if *max != Some(0) {
                    self.first(inner, out);
                }
            }
            Expr::All(members) => out.extend(members.iter().map(|(d, _)| Matched::Element(*d))),
        }
    }

    fn accepting(&self, e: &Expr, name: &QName) -> Option<Matched> {
        let mut terms = Vec::new();
        self.first(e, &mut terms);
        terms.into_iter().find(|t| match t {
            Matched::Element(d) => self.element_matches(*d, name),
            Matched::Wildcard(w) => w.allows(&name.0),
        })
    }

    /// The expected names in a `cvc-complex-type.2.4` message: `name`, or `"namespace":name` when qualified.
    fn expected(&self, e: &Expr) -> String {
        let mut terms = Vec::new();
        self.first(e, &mut terms);
        let mut names: Vec<String> = Vec::new();
        for t in terms {
            let text = match t {
                Matched::Element(d) => {
                    let (namespace, local) = &self.elements[d].name;
                    if namespace.is_empty() { local.clone() } else { format!("\"{namespace}\":{local}") }
                }
                Matched::Wildcard(w) => match &w.namespaces {
                    None => "WC[##any]".to_string(),
                    Some(list) if w.negated => format!("WC[##other:\"{}\"]", list.first().cloned().unwrap_or_default()),
                    Some(list) => format!("WC[{}]", list.iter().map(|n| format!("\"{n}\"")).collect::<Vec<_>>().join(",")),
                },
            };
            if !names.contains(&text) {
                names.push(text);
            }
        }
        names.join(", ")
    }

    /// The Brzozowski derivative of `e` by a child named `name`.
    fn derive(&self, e: &Expr, name: &QName) -> Expr {
        match e {
            Expr::Empty | Expr::Fail => Expr::Fail,
            Expr::Element(d) => if self.element_matches(*d, name) { Expr::Empty } else { Expr::Fail },
            Expr::Any(w) => if w.allows(&name.0) { Expr::Empty } else { Expr::Fail },
            Expr::Sequence(items) => {
                let Some((head, rest)) = items.split_first() else { return Expr::Fail };
                let rest_expr = Expr::Sequence(rest.to_vec());
                let mut through_head = vec![self.derive(head, name)];
                through_head.extend(rest.iter().cloned());
                let through_head = simplify(Expr::Sequence(through_head));
                if self.nullable(head) {
                    simplify(Expr::Choice(vec![through_head, self.derive(&rest_expr, name)]))
                } else {
                    through_head
                }
            }
            Expr::Choice(items) => simplify(Expr::Choice(items.iter().map(|i| self.derive(i, name)).collect())),
            Expr::Repeat(inner, min, max) => {
                if *max == Some(0) {
                    return Expr::Fail;
                }
                let next = Expr::Repeat(inner.clone(), min.saturating_sub(1), max.map(|m| m - 1));
                simplify(Expr::Sequence(vec![self.derive(inner, name), next]))
            }
            Expr::All(members) => match members.iter().position(|(d, _)| self.element_matches(*d, name)) {
                Some(i) => {
                    let mut rest = members.clone();
                    rest.remove(i);
                    Expr::All(rest)
                }
                None => Expr::Fail,
            },
        }
    }
}

/// Keeps derivatives small: failures propagate, empties drop out, single items unwrap.
fn simplify(e: Expr) -> Expr {
    match e {
        Expr::Sequence(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Expr::Fail => return Expr::Fail,
                    Expr::Empty => {}
                    Expr::Sequence(inner) => out.extend(inner),
                    other => out.push(other),
                }
            }
            match out.len() {
                0 => Expr::Empty,
                1 => out.pop().expect("one"),
                _ => Expr::Sequence(out),
            }
        }
        Expr::Choice(items) => {
            let mut out: Vec<Expr> = items.into_iter().filter(|i| !matches!(i, Expr::Fail)).collect();
            match out.len() {
                0 => Expr::Fail,
                1 => out.pop().expect("one"),
                _ => Expr::Choice(out),
            }
        }
        Expr::Repeat(_, _, Some(0)) => Expr::Empty,
        other => other,
    }
}

fn nil_error(name: &str) -> String {
    format!("cvc-elt.3.2.1: Element '{name}' cannot have character or element information [children], because 'http://www.w3.org/2001/XMLSchema-instance,nil' is specified.")
}

fn is_whitespace(s: &str) -> bool {
    s.chars().all(|c| matches!(c, ' ' | '\t' | '\n' | '\r'))
}

fn text_of(node: Node) -> String {
    node.children().filter(|c| c.is_text()).filter_map(|c| c.text()).collect()
}

fn qname(node: Node) -> QName {
    (node.tag_name().namespace().unwrap_or_default().to_string(), node.tag_name().name().to_string())
}

/// How `cvc-complex-type.2.4` names the offending element: its local name, or `{"namespace":local}` when it has a
/// namespace (whatever its prefix).
fn expanded_name(node: Node) -> String {
    match node.tag_name().namespace() {
        Some(ns) if !ns.is_empty() => format!("{{\"{ns}\":{}}}", node.tag_name().name()),
        _ => node.tag_name().name().to_string(),
    }
}

/// The element's name as written (`rawname`).
fn raw_name(node: Node) -> String {
    let local = node.tag_name().name();
    match node.tag_name().namespace().and_then(|ns| node.lookup_prefix(ns)) {
        Some(prefix) if !prefix.is_empty() => format!("{prefix}:{local}"),
        _ => local.to_string(),
    }
}

fn attribute_raw_name(node: Node, attribute: &roxmltree::Attribute) -> String {
    match attribute.namespace().and_then(|ns| node.lookup_prefix(ns)) {
        Some(prefix) if !prefix.is_empty() => format!("{prefix}:{}", attribute.name()),
        _ => attribute.name().to_string(),
    }
}

/// Parses an instance document, reporting malformed XML as Xerces' SAX parser words it.
pub(super) fn parse(xml: &str) -> Result<roxmltree::Document<'_>, String> {
    parse_located(xml).map_err(|(message, _)| message)
}

/// [`parse`], with the byte offset (into `xml` without a leading byte order mark) Xerces reports a namespace error
/// at: past the start tag, or past a repeated namespace declaration.
pub(super) fn parse_located(xml: &str) -> Result<roxmltree::Document<'_>, (String, Option<usize>)> {
    let text = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    let start = text.trim_start_matches([' ', '\t', '\n', '\r']);
    if !start.starts_with('<') {
        return Err(("Content is not allowed in prolog.".into(), None));
    }
    let error = match roxmltree::Document::parse_with_options(text, roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() }) {
        // roxmltree takes a repeated default namespace declaration for a redefinition
        Ok(document) => match text.matches("xmlns").nth(1).and_then(|_| super::start_tags::first_error(text, text.len())) {
            Some((message, at)) => return Err((message, Some(at))),
            None => return Ok(document),
        },
        Err(error) => error,
    };
    // A namespace error: Xerces' first one in the tags read so far, which can be in an earlier tag (a repeated
    // default namespace declaration) or another check of the same tag.
    if let roxmltree::Error::UnknownNamespace(_, pos) | roxmltree::Error::DuplicatedAttribute(_, pos) | roxmltree::Error::DuplicatedNamespace(_, pos) = &error
        && let Some((message, at)) = super::start_tags::first_error(text, byte_offset(text, *pos))
    {
        return Err((message, Some(at)));
    }
    let message = match error {
        roxmltree::Error::UnexpectedCloseTag(expected, _, _) => {
            format!("The element type \"{expected}\" must be terminated by the matching end-tag \"</{expected}>\".")
        }
        roxmltree::Error::UnexpectedEndOfStream | roxmltree::Error::UnclosedRootNode | roxmltree::Error::NoRootNode => {
            "XML document structures must start and end within the same entity.".into()
        }
        roxmltree::Error::UnknownToken(pos) => {
            let after = text.lines().nth(pos.row as usize - 1).map(|l| l.chars().skip(pos.col as usize - 1).collect::<String>()).unwrap_or_default();
            if after.starts_with('<') {
                "The markup in the document following the root element must be well-formed.".into()
            } else {
                "Content is not allowed in trailing section.".into()
            }
        }
        roxmltree::Error::InvalidChar(b'"' | b'\'', b'<', pos) => {
            // A `<` in an attribute value: the attribute and element it belongs to.
            let at = byte_offset(text, pos);
            let tag = text[..at].rfind('<').map_or("", |start| &text[start + 1..at]);
            let element = tag.split([' ', '\t', '\n', '\r']).next().unwrap_or_default();
            let attribute = tag.rfind('=').map_or("", |eq| tag[..eq].trim_end().rsplit([' ', '\t', '\n', '\r']).next().unwrap_or_default());
            format!("The value of attribute \"{attribute}\" associated with an element type \"{element}\" must not contain the '<' character.")
        }
        roxmltree::Error::UnknownNamespace(prefix, _) => format!("The prefix \"{prefix}\" for element is not bound."),
        roxmltree::Error::DuplicatedAttribute(name, _) => format!("Attribute \"{name}\" was already specified for element."),
        other => other.to_string(),
    };
    Err((message, None))
}

/// The byte offset of roxmltree's 1-based row and column (in characters).
fn byte_offset(text: &str, pos: roxmltree::TextPos) -> usize {
    let line: usize = text.split_inclusive('\n').take(pos.row as usize - 1).map(str::len).sum();
    line + text[line..].chars().take(pos.col as usize - 1).map(char::len_utf8).sum::<usize>()
}

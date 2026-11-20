//! Identity constraints (`xs:unique`, `xs:key`, `xs:keyref`): the restricted XPath of selectors and fields, and
//! their evaluation during instance validation as Xerces' `XPathMatcher`s and `ValueStore`s do it, with its messages.

use std::collections::HashMap;

use roxmltree::Node;

use super::{QName, Schema};

pub type IcId = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Unique,
    Key,
    KeyRef,
}

#[derive(Debug, Clone)]
pub struct IdentityConstraint {
    pub name: String,
    pub category: Category,
    /// The referenced key or unique of a keyref.
    pub refer: Option<IcId>,
    /// The local name of the element declaration carrying it (`getElementName`).
    pub element: String,
    pub selector: Vec<Path>,
    pub fields: Vec<Field>,
    /// The JVM identity hash Xerces' `IdentityConstraint.toString()` prints (`KeyRef@6e42895`): one per compiled
    /// constraint, as the oracle's object lives as long as its expectation's schema.
    pub identity_hash: u32,
}

#[derive(Debug, Clone)]
pub struct Field {
    /// The expression as Xerces prints it (`fixupXPath`: `./` before each alternative not starting with `.`/`/`).
    pub text: String,
    pub paths: Vec<Path>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameTest {
    Any,
    Namespace(String),
    Name(QName),
}

impl NameTest {
    fn matches(&self, name: &QName) -> bool {
        match self {
            NameTest::Any => true,
            NameTest::Namespace(ns) => *ns == name.0,
            NameTest::Name(n) => n == name,
        }
    }
}

/// One alternative: `('.//')? Step ('/' Step)*`, the `.` steps dropped, and for a field an optional final attribute.
#[derive(Debug, Clone)]
pub struct Path {
    pub descendant: bool,
    pub steps: Vec<NameTest>,
    pub attribute: Option<NameTest>,
}

impl Path {
    /// Whether the element reached from the context by the child names `relative` is selected.
    fn matches_element(&self, relative: &[QName]) -> bool {
        if self.attribute.is_some() {
            return false;
        }
        self.matches_steps(relative)
    }

    fn matches_steps(&self, relative: &[QName]) -> bool {
        if self.descendant {
            relative.len() >= self.steps.len() && self.steps.iter().zip(&relative[relative.len() - self.steps.len()..]).all(|(s, n)| s.matches(n))
        } else {
            relative.len() == self.steps.len() && self.steps.iter().zip(relative).all(|(s, n)| s.matches(n))
        }
    }

    fn matches_attribute(&self, relative: &[QName], attribute: &QName) -> bool {
        self.attribute.as_ref().is_some_and(|a| a.matches(attribute)) && self.matches_steps(relative)
    }
}

fn general_error(expression: &str) -> String {
    format!("c-general-xpath: The expression '{expression}' is not valid with respect to the XPath subset supported by XML Schema.")
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Slash,
    DoubleSlash,
    Dot,
    At,
    Star,
    Pipe,
    Axis(String),
    /// A name test: `prefix:*`, `prefix:local` or `local`.
    Name(Option<String>, Option<String>),
}

fn tokens(expression: &str) -> Option<Vec<Token>> {
    let chars: Vec<char> = expression.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let name_char = |c: char| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '\u{B7}');
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\n' | '\r' => i += 1,
            '/' if chars.get(i + 1) == Some(&'/') => {
                out.push(Token::DoubleSlash);
                i += 2;
            }
            '/' => {
                out.push(Token::Slash);
                i += 1;
            }
            '.' if !chars.get(i + 1).is_some_and(|n| *n == '.') => {
                out.push(Token::Dot);
                i += 1;
            }
            '@' => {
                out.push(Token::At);
                i += 1;
            }
            '*' => {
                out.push(Token::Star);
                i += 1;
            }
            '|' => {
                out.push(Token::Pipe);
                i += 1;
            }
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && name_char(chars[i]) {
                    i += 1;
                }
                let first: String = chars[start..i].iter().collect();
                // `axis::`
                let mut j = i;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                if chars.get(j) == Some(&':') && chars.get(j + 1) == Some(&':') {
                    out.push(Token::Axis(first));
                    i = j + 2;
                    continue;
                }
                if chars.get(i) == Some(&':') {
                    match chars.get(i + 1) {
                        Some('*') => {
                            out.push(Token::Name(Some(first), None));
                            i += 2;
                        }
                        Some(c) if c.is_alphabetic() || *c == '_' => {
                            let start = i + 1;
                            i = start;
                            while i < chars.len() && name_char(chars[i]) {
                                i += 1;
                            }
                            out.push(Token::Name(Some(first), Some(chars[start..i].iter().collect())));
                        }
                        _ => return None,
                    }
                } else {
                    out.push(Token::Name(None, Some(first)));
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Parses a selector (`attributes == false`) or field expression; prefixes resolve with the bindings at `node`.
pub fn parse(expression: &str, node: Node, attributes: bool) -> Result<Vec<Path>, String> {
    let tokens = tokens(expression).ok_or_else(|| general_error(expression))?;
    let mut paths = Vec::new();
    for branch in tokens.split(|t| *t == Token::Pipe) {
        match parse_branch(branch, node, attributes) {
            Some(path) => paths.push(path),
            None => {
                // XPath takes an attribute step before another step; a field refuses it (`Field.XPath`).
                let attribute_not_last = branch.iter().enumerate().any(|(i, t)| {
                    (*t == Token::At || *t == Token::Axis("attribute".into())) && branch.get(i + 2) == Some(&Token::Slash)
                });
                let as_child: Vec<Token> = branch.iter().filter(|t| **t != Token::At && **t != Token::Axis("attribute".into())).cloned().collect();
                if attributes && attribute_not_last && parse_branch(&as_child, node, attributes).is_some() {
                    return Err(format!("c-fields-xpaths: The field value = '{expression}' is not valid."));
                }
                return Err(general_error(expression));
            }
        }
    }
    if !attributes && paths.iter().any(|p| p.attribute.is_some()) {
        return Err(format!("c-selector-xpath: The selector value = '{expression}' is not valid; selector xpaths cannot contain attributes."));
    }
    Ok(paths)
}

fn parse_branch(tokens: &[Token], node: Node, _attributes: bool) -> Option<Path> {
    let mut path = Path { descendant: false, steps: Vec::new(), attribute: None };
    let mut i = 0;
    if tokens.len() >= 2 && tokens[0] == Token::Dot && tokens[1] == Token::DoubleSlash {
        path.descendant = true;
        i = 2;
    }
    let name_test = |t: &Token| -> Option<NameTest> {
        match t {
            Token::Star => Some(NameTest::Any),
            Token::Name(Some(prefix), None) => Some(NameTest::Namespace(super::namespace_of(node, prefix)?)),
            Token::Name(Some(prefix), Some(local)) => Some(NameTest::Name((super::namespace_of(node, prefix)?, local.clone()))),
            Token::Name(None, Some(local)) => Some(NameTest::Name((String::new(), local.clone()))),
            _ => None,
        }
    };
    loop {
        // A step.
        match tokens.get(i)? {
            Token::Dot => i += 1,
            Token::At => {
                path.attribute = Some(name_test(tokens.get(i + 1)?)?);
                i += 2;
                return (i == tokens.len()).then_some(path);
            }
            Token::Axis(axis) if axis == "attribute" => {
                path.attribute = Some(name_test(tokens.get(i + 1)?)?);
                i += 2;
                return (i == tokens.len()).then_some(path);
            }
            Token::Axis(axis) if axis == "child" => {
                path.steps.push(name_test(tokens.get(i + 1)?)?);
                i += 2;
            }
            other => {
                path.steps.push(name_test(other)?);
                i += 1;
            }
        }
        match tokens.get(i) {
            None => return Some(path),
            Some(Token::Slash) => i += 1,
            Some(_) => return None,
        }
    }
}

/// `Field.XPath.fixupXPath`.
pub fn fixup(xpath: &str) -> String {
    let chars: Vec<char> = xpath.chars().collect();
    let space = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r');
    let mut whitespace = true;
    let mut offset = 0;
    while offset < chars.len() {
        let c = chars[offset];
        if whitespace {
            if !space(c) {
                if c == '.' || c == '/' {
                    whitespace = false;
                } else if c != '|' {
                    let mut out: String = chars[..offset].iter().collect();
                    out.push_str("./");
                    let mut ws = false;
                    for &c in &chars[offset..] {
                        if ws {
                            if !space(c) {
                                if c != '.' && c != '/' {
                                    out.push_str("./");
                                }
                                ws = false;
                            }
                        } else if c == '|' {
                            ws = true;
                        }
                        out.push(c);
                    }
                    return out;
                }
            }
        } else if c == '|' {
            whitespace = true;
        }
        offset += 1;
    }
    xpath.to_string()
}

/// A field's actual value: its primitive kind (values of different kinds never equal), the key equality uses, and
/// how Xerces prints it (`toString` of the actual value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    pub kind: String,
    pub key: String,
    pub display: String,
}

impl Value {
    /// A match without an actual value (an attribute or element no declaration typed); equal to nothing.
    pub fn null() -> Value {
        Value { kind: "null".into(), key: String::new(), display: "null".into() }
    }
}

fn tuple_text(values: &[Value]) -> String {
    values.iter().map(|v| v.display.as_str()).collect::<Vec<_>>().join(",")
}

fn same(a: &[Value], b: &[Value]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.kind != "null" && x.kind == y.kind && x.key == y.key)
}

struct Selection {
    depth: usize,
    values: Vec<Option<Value>>,
    matched: Vec<bool>,
    count: usize,
}

struct Scope {
    ic: IcId,
    depth: usize,
    values: Vec<Vec<Value>>,
    selections: Vec<Selection>,
}

/// The matchers and value stores of one validation.
#[derive(Default)]
pub struct State {
    path: Vec<QName>,
    scopes: Vec<Scope>,
    global: HashMap<IcId, Vec<Vec<Value>>>,
    global_stack: Vec<HashMap<IcId, Vec<Vec<Value>>>>,
}

/// What a field matched on an element at its end: its type's value, or why it has none.
pub enum Content<'a> {
    /// A simple type or simple content: the value (`None` when nil).
    Simple(Option<&'a Value>),
    /// Complex content, or an element without a type.
    NotSimple,
}

impl Schema {
    /// `handleStartElement` for the identity constraints: activates `constraints` (the declaration's), then the
    /// selectors and attribute fields that match `name`. `attributes` are the element's validated attributes.
    pub(super) fn ic_start(&self, st: &mut State, name: QName, constraints: &[IcId], attributes: &[(QName, Value)]) -> Result<(), String> {
        if self.constraints.is_empty() {
            return Ok(());
        }
        st.global_stack.push(std::mem::take(&mut st.global));
        st.path.push(name);
        let depth = st.path.len() - 1;
        for ic in constraints {
            st.scopes.push(Scope { ic: *ic, depth, values: Vec::new(), selections: Vec::new() });
        }
        for scope in &mut st.scopes {
            let ic = &self.constraints[scope.ic];
            if ic.selector.iter().any(|p| p.matches_element(&st.path[scope.depth + 1..])) {
                let n = ic.fields.len();
                scope.selections.push(Selection { depth, values: vec![None; n], matched: vec![false; n], count: 0 });
            }
        }
        // Per element and field, one match: the first alternative's first matching attribute (`XPathMatcher`).
        for s in 0..st.scopes.len() {
            for sel in 0..st.scopes[s].selections.len() {
                let ic = &self.constraints[st.scopes[s].ic];
                let from = st.scopes[s].selections[sel].depth + 1;
                for (f, field) in ic.fields.iter().enumerate() {
                    let found = field.paths.iter().find_map(|p| attributes.iter().find(|(a, _)| p.matches_attribute(&st.path[from..], a)));
                    if let Some((_, value)) = found {
                        self.field_matched(&mut st.scopes[s], sel, f, Some(value.clone()), false)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// `handleEndElement`: element fields, the ends of selections and of the scopes started here (keys first
    /// transplanted, then keyrefs checked), and the value-store cache's `endElement`.
    pub(super) fn ic_end(&self, st: &mut State, content: Content, nillable: bool) -> Result<(), String> {
        if self.constraints.is_empty() {
            return Ok(());
        }
        let depth = st.path.len() - 1;
        for s in (0..st.scopes.len()).rev() {
            let ic = &self.constraints[st.scopes[s].ic];
            for sel in (0..st.scopes[s].selections.len()).rev() {
                let from = st.scopes[s].selections[sel].depth + 1;
                if from > depth + 1 {
                    continue;
                }
                for (f, field) in ic.fields.iter().enumerate() {
                    if field.paths.iter().any(|p| p.matches_element(&st.path[from..])) {
                        let value = match &content {
                            Content::NotSimple => {
                                return Err(format!(
                                    "cvc-id.3: A field of identity constraint '{}' matched element '{}', but this element does not have a simple type.",
                                    ic.name, ic.element
                                ));
                            }
                            Content::Simple(v) => v.cloned(),
                        };
                        self.field_matched(&mut st.scopes[s], sel, f, value, nillable)?;
                    }
                }
            }
            // The selection of this element ends (`endValueScope`).
            if let Some(selection) = st.scopes[s].selections.last().filter(|sel| sel.depth == depth) {
                if ic.category == Category::Key {
                    if selection.count == 0 {
                        return Err(format!("cvc-identity-constraint.4.2.1.a: Element \"{}\" has no value for the key \"{}\".", ic.element, ic.name));
                    }
                    if selection.count != ic.fields.len() {
                        return Err(format!(
                            "cvc-identity-constraint.4.2.1.b: Not enough values specified for <key name=\"{}\"> identity constraint specified for element \"{}\".",
                            ic.name, ic.element
                        ));
                    }
                }
                st.scopes[s].selections.pop();
            }
        }
        // Scopes of this element end.
        let first = st.scopes.iter().position(|s| s.depth == depth).unwrap_or(st.scopes.len());
        let ended: Vec<Scope> = st.scopes.drain(first..).collect();
        for scope in ended.iter().rev() {
            if self.constraints[scope.ic].category != Category::KeyRef {
                st.global.entry(scope.ic).or_default().extend(scope.values.iter().cloned());
            }
        }
        for scope in ended.iter().rev() {
            let ic = &self.constraints[scope.ic];
            if ic.category != Category::KeyRef || scope.values.is_empty() {
                continue;
            }
            let Some(keys) = ic.refer.and_then(|r| st.global.get(&r)) else {
                return Err(format!(
                    "Identity Constraint error:  identity constraint \"KeyRef@{:x}\" has a keyref which refers to a key or unique that is out of scope.",
                    ic.identity_hash
                ));
            };
            if let Some(missing) = scope.values.iter().find(|v| !keys.iter().any(|k| same(k, v))) {
                return Err(format!(
                    "cvc-identity-constraint.4.3: Key '{}' with value '{}' not found for identity constraint of element '{}'.",
                    ic.name,
                    tuple_text(missing),
                    ic.element
                ));
            }
        }
        st.path.pop();
        if let Some(outer) = st.global_stack.pop() {
            for (ic, values) in outer {
                st.global.entry(ic).or_default().extend(values);
            }
        }
        Ok(())
    }

    /// `Field.Matcher.matched` and `ValueStoreBase.addValue`.
    fn field_matched(&self, scope: &mut Scope, sel: usize, field: usize, value: Option<Value>, nillable: bool) -> Result<(), String> {
        let ic = &self.constraints[scope.ic];
        if nillable && ic.category == Category::Key {
            return Err(format!(
                "cvc-identity-constraint.4.2.3: Element \"{}\" has the key \"{}\" which matches an element which has nillable set to true.",
                ic.element, ic.name
            ));
        }
        let selection = &mut scope.selections[sel];
        if selection.matched[field] {
            return Err(format!(
                "cvc-identity-constraint.3: Field \"{}\" of identity constraint \"{}\" matches more than one value within the scope of its selector; fields must match unique values.",
                ic.fields[field].text, ic.name
            ));
        }
        selection.matched[field] = true;
        selection.count += 1;
        selection.values[field] = value;
        if selection.count == ic.fields.len() {
            let tuple: Vec<Value> = selection
                .values
                .iter()
                .map(|v| v.clone().unwrap_or_else(Value::null))
                .collect();
            if ic.category != Category::KeyRef && scope.values.iter().any(|v| same(v, &tuple)) {
                let (code, what) = if ic.category == Category::Key { ("4.2.2", "key") } else { ("4.1", "unique") };
                return Err(format!(
                    "cvc-identity-constraint.{code}: Duplicate {what} value [{}] declared for identity constraint \"{}\" of element \"{}\".",
                    tuple_text(&tuple),
                    ic.name,
                    ic.element
                ));
            }
            scope.values.push(tuple);
        }
        Ok(())
    }
}

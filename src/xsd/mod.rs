//! W3C XML Schema 1.0 validation for `XML_SCHEMA` body matchers (`XmlSchemaValidator`): the schema component model
//! compiled from schema documents, and instance validation that stops at the first error with the message Xerces
//! (the JDK's validator) gives it.
//!
//! Covered: global and local elements (refs, substitution groups, nillable, fixed/default), named and anonymous
//! simple types (restriction with every facet, list, union) and complex types (sequence/choice/all, groups,
//! wildcards, attributes and attribute groups, simple and complex content by extension or restriction, mixed),
//! `xsi:type`/`xsi:nil`, ID/IDREF, identity constraints (`key`/`keyref`/`unique`, `identity.rs`), and
//! `xs:include`/`xs:import`/`xs:redefine` of files, notations. Schema construction checks the schema for schemas
//! (`s4s.rs`), facets (`types.rs`, patterns in `regex_syntax.rs`), the component constraints (`checks.rs`) and
//! particle restriction (`restriction.rs`); each error is raised against the element Xerces reports it at
//! ([`Builder::fail`]), so the `SAXParseException` carries its line and column, and the unloaded namespace reported
//! is the one Xerces' traversal order meets first (`order.rs`).

mod checks;
mod identity;
mod order;
mod regex_syntax;
mod restriction;
mod s4s;
mod start_tags;
mod types;
mod validate;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use roxmltree::{Document, Node};

pub use types::XS;
use types::{Facets, SimpleType, Variety, WhiteSpace};

/// Why Xerces' parser rejects `xml` as not well-formed, in its words; `None` for a well-formed document. DTDs are
/// read, as the schema validator reads them.
pub fn well_formedness_error(xml: &str) -> Option<String> {
    validate::parse(xml).err()
}

/// [`well_formedness_error`], with the byte offset (into `xml` without a leading byte order mark) Xerces reports a
/// namespace error at, when it is one.
pub fn well_formedness_error_at(xml: &str) -> Option<(String, Option<usize>)> {
    validate::parse_located(xml).err()
}

/// The 1-based line and column (in characters) of a byte offset into `text`.
pub fn line_column(text: &str, at: usize) -> (usize, usize) {
    let before = &text[..at.min(text.len())];
    (before.matches('\n').count() + 1, before[before.rfind('\n').map_or(0, |n| n + 1)..].chars().count() + 1)
}

/// Where Xerces reports why `text` is not well-formed (`because`, `error` being roxmltree's view of it), as the
/// line and column (1-based, in characters) its `SAXParseException` carries.
pub fn sax_location(text: &str, error: &roxmltree::Error, because: &str) -> (usize, usize) {
    let chars: Vec<char> = text.chars().collect();
    let at = |line: u32, column: u32| -> usize {
        let (mut l, mut i) = (1u32, 0usize);
        while l < line && i < chars.len() {
            if chars[i] == '\n' {
                l += 1;
            }
            i += 1;
        }
        i + column.saturating_sub(1) as usize
    };
    let offset = if because.starts_with("DOCTYPE is disallowed") {
        // just after the declaration's keyword
        text.find("<!DOCTYPE").map_or(0, |b| text[..b].chars().count() + "<!DOCTYPE".len())
    } else if because == "Content is not allowed in prolog." {
        chars.iter().position(|c| !matches!(c, ' ' | '\t' | '\n' | '\r')).unwrap_or(0)
    } else if because == "XML document structures must start and end within the same entity." {
        chars.len()
    } else {
        let pos = error.pos();
        let start = at(pos.row, pos.col);
        match error {
            // after the `</` of the offending end tag, or the `<` of markup after the root element
            roxmltree::Error::UnexpectedCloseTag(..) => start + 2,
            roxmltree::Error::UnknownToken(_) if chars.get(start) == Some(&'<') => start + 1,
            // after the start tag the attribute or name belongs to
            roxmltree::Error::DuplicatedAttribute(..) | roxmltree::Error::UnknownNamespace(..) => {
                let open = chars[..start.min(chars.len())].iter().rposition(|c| *c == '<').unwrap_or(0);
                let mut quote = None;
                let mut end = chars.len();
                for (i, c) in chars.iter().enumerate().skip(open) {
                    match (quote, *c) {
                        (None, '"' | '\'') => quote = Some(*c),
                        (Some(q), c) if c == q => quote = None,
                        (None, '>') => {
                            end = i + 1;
                            break;
                        }
                        _ => {}
                    }
                }
                end
            }
            _ => start,
        }
    };
    let (mut line, mut line_start) = (1usize, 0usize);
    for (i, c) in chars.iter().enumerate().take(offset) {
        if *c == '\n' {
            line += 1;
            line_start = i + 1;
        }
    }
    (line, offset - line_start + 1)
}

/// Why Xerces' parser rejects `xml` as not well-formed and the line and column its `SAXParseException` gives;
/// `None` for a well-formed document. DTDs are read.
pub fn sax_error(xml: &str) -> Option<(String, (usize, usize))> {
    let text = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    if text.trim_matches([' ', '\t', '\n', '\r']).is_empty() {
        return Some(("Premature end of file.".into(), line_column(text, text.len())));
    }
    match roxmltree::Document::parse_with_options(text, roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() }) {
        Ok(_) => well_formedness_error_at(xml).map(|(because, at)| (because, at.map_or((1, 1), |at| line_column(text, at)))),
        Err(e) => Some(match well_formedness_error_at(xml) {
            Some((because, Some(at))) => (because, line_column(text, at)),
            Some((because, None)) => {
                let location = sax_location(text, &e, &because);
                (because, location)
            }
            None => (e.to_string(), sax_location(text, &e, &e.to_string())),
        }),
    }
}

pub type TypeId = usize;
pub type ElemId = usize;
/// Namespace name (empty for none) and local name.
pub type QName = (String, String);

/// The namespaces a server's schema compiler has reported `src-resolve` for because no grammar for them was loaded
/// (`XSDHandler.fReportedTNS`, empty for no namespace). MockServer builds every schema with one static
/// `SchemaFactory`, whose handler keeps this list for the life of the JVM, resets included: only the first reference
/// into such a namespace is an error; later schemas compile with the reference dropped or taken as `anyType`.
#[derive(Debug, Clone, Default)]
pub struct Reported(std::sync::Arc<parking_lot::Mutex<std::collections::HashSet<String>>>);

impl Reported {
    /// `needReportTNSError`: whether `namespace` is reported now (and from now on, never again).
    fn first(&self, namespace: &str) -> bool {
        self.0.lock().insert(namespace.to_string())
    }

    /// Whether `namespace` was reported already.
    fn contains(&self, namespace: &str) -> bool {
        self.0.lock().contains(namespace)
    }
}

/// Why a schema cannot be built, as the exception `XmlSchemaValidator` logs as the `throwable` of its
/// `exception parsing schema` entry.
#[derive(Debug, Clone)]
pub struct SchemaError {
    pub message: String,
    pub kind: ErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// `SAXParseException` from Xerces: the line and column after the start tag the error is reported at (`None`
    /// where this port does not track it), and the schema document's system id (a file's `file:` URI).
    Parse { location: Option<(usize, usize)>, system_id: Option<String> },
    /// The constructor's own `IllegalArgumentException` (neither a document nor a `.xsd` path).
    IllegalArgument,
    /// `FileNotFoundException` for a schema file that cannot be read.
    FileNotFound,
    /// `NullPointerException`: Xerces reads a schema document whose root is another schema element as if it were
    /// `xs:schema` and finds none of its attributes.
    NullPointer,
}

impl SchemaError {
    /// The throwable's Jackson bean (`stackTrace` empty: its JVM frames cannot be reproduced).
    pub fn throwable_bean(&self) -> serde_json::Value {
        let mut bean = serde_json::Map::new();
        if let ErrorKind::Parse { location, .. } = &self.kind {
            let (line, column) = location.map_or((-1, -1), |(l, c)| (l as i64, c as i64));
            bean.insert("columnNumber".into(), column.into());
            bean.insert("lineNumber".into(), line.into());
        }
        bean.insert("localizedMessage".into(), self.message.clone().into());
        bean.insert("message".into(), self.message.clone().into());
        bean.insert("stackTrace".into(), serde_json::Value::Array(Vec::new()));
        if let ErrorKind::Parse { system_id: Some(id), .. } = &self.kind {
            bean.insert("systemId".into(), id.clone().into());
        }
        serde_json::Value::Object(bean)
    }

    /// The throwable's `toString()`, the first line of its stack trace.
    pub fn throwable_text(&self) -> String {
        match &self.kind {
            ErrorKind::Parse { location, system_id } => {
                let mut text = String::from("org.xml.sax.SAXParseException");
                if let Some(id) = system_id {
                    text.push_str(&format!("; systemId: {id}"));
                }
                let (line, column) = location.map_or((-1, -1), |(l, c)| (l as i64, c as i64));
                if line != -1 {
                    text.push_str(&format!("; lineNumber: {line}"));
                }
                if column != -1 {
                    text.push_str(&format!("; columnNumber: {column}"));
                }
                format!("{text}; {}", self.message)
            }
            ErrorKind::IllegalArgument => format!("java.lang.IllegalArgumentException: {}", self.message),
            ErrorKind::FileNotFound => format!("java.io.FileNotFoundException: {}", self.message),
            ErrorKind::NullPointer => format!("java.lang.NullPointerException: {}", self.message),
        }
    }
}

/// Why a schema document is not well-formed, where Xerces' parser places it (`fallback`: roxmltree's reason, for
/// a document Xerces' wording is not known for).
fn not_well_formed(text: &str, system_id: Option<String>, fallback: String) -> SchemaError {
    let (message, place) = match sax_error(text) {
        Some((message, place)) => (message, Some(place)),
        None => (fallback, None),
    };
    SchemaError { message, kind: ErrorKind::Parse { location: place, system_id } }
}

/// `File.toURI()` of a schema document's location.
fn system_id(path: &Path) -> String {
    if let Some(url) = jar_url(path) {
        return url.to_string();
    }
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    format!("file:{}", absolute.display())
}

/// A schema document read from a jar on the class path is located by its `jar:file:<jar>!/<entry>` URL.
fn jar_url(path: &Path) -> Option<&str> {
    path.to_str().filter(|p| p.starts_with("jar:file:"))
}

/// The text of the schema document at `path` (a file, or an entry of a class path jar).
fn read_document(path: &Path) -> std::io::Result<String> {
    if let Some((jar, entry)) = jar_url(path).and_then(|url| url["jar:file:".len()..].split_once("!/")) {
        let resource = crate::class_path::Location::Jar { jar: jar.into(), entry: entry.into() };
        return resource.read().map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    }
    std::fs::read_to_string(path)
}

/// The system id of document `index`: the schema file itself as [`system_id`], a document it refers to as
/// `XMLEntityManager.expandSystemId` gives it (`file:///…`).
fn document_system_id(index: usize, path: &Path) -> String {
    if index == 0 || jar_url(path).is_some() {
        return system_id(path);
    }
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    format!("file://{}", absolute.display())
}

/// The line and column (1-based, in characters) just after the start tag that begins at `offset` of `text`, where
/// Xerces' DOM parser stands when it reports an error against that element.
fn after_start_tag(text: &str, offset: usize) -> (usize, usize) {
    let mut quote = None;
    let mut end = text.len();
    for (i, c) in text[offset..].char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '>') => {
                end = offset + i + 1;
                break;
            }
            _ => {}
        }
    }
    let before = &text[..end];
    let line = before.matches('\n').count() + 1;
    let column = before[before.rfind('\n').map_or(0, |n| n + 1)..].chars().count() + 1;
    (line, column)
}

#[derive(Debug)]
pub struct Schema {
    types: Vec<Type>,
    elements: Vec<ElementDecl>,
    globals: HashMap<QName, ElemId>,
    global_types: HashMap<QName, TypeId>,
    global_attributes: HashMap<QName, AttributeUse>,
    /// Substitution group heads to their members, transitively.
    substitutes: HashMap<ElemId, Vec<ElemId>>,
    any_type: TypeId,
    constraints: Vec<identity::IdentityConstraint>,
    /// Derivation method, `block` and `final` of the types that have them (named types, complex types).
    type_flags: HashMap<TypeId, restriction::TypeFlags>,
}

#[derive(Debug)]
pub enum Type {
    Simple(SimpleType),
    Complex(ComplexType),
}

#[derive(Debug, Clone)]
pub struct ElementDecl {
    pub name: QName,
    pub ty: TypeId,
    pub nillable: bool,
    pub fixed: Option<String>,
    pub default: Option<String>,
    /// Its identity constraints.
    pub constraints: Vec<identity::IcId>,
    /// `{disallowed substitutions}` (`block`, else `blockDefault`) and `{substitution group exclusions}` (`final`,
    /// else `finalDefault`), as `restriction::EXTENSION`… sets.
    pub block: u8,
    pub final_: u8,
    /// The declaration's position (document, offset): a group's elements are built once per reference.
    pub source: (usize, usize),
}

#[derive(Debug, Clone)]
pub struct ComplexType {
    pub name: String,
    /// The base type of a derivation (`None`: a restriction of `anyType`).
    pub base: Option<TypeId>,
    pub content: Content,
    pub attributes: Vec<AttributeUse>,
    pub attribute_wildcard: Option<Wildcard>,
    pub mixed: bool,
}

#[derive(Debug, Clone)]
pub enum Content {
    Empty,
    Simple(TypeId),
    Elements(Expr),
    /// `anyType`: any attributes and any content, validated laxly.
    Any,
}

#[derive(Debug, Clone)]
pub struct AttributeUse {
    pub name: QName,
    pub ty: TypeId,
    pub required: bool,
    pub prohibited: bool,
    pub fixed: Option<String>,
    pub default: Option<String>,
    /// The declaration or reference it comes from (document, offset): the same use reached twice through attribute
    /// groups is one use.
    pub source: (usize, usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Process {
    Strict,
    Lax,
    Skip,
}

#[derive(Debug, Clone)]
pub struct Wildcard {
    /// `None` for `##any`; otherwise the allowed (or, when `negated`, the disallowed) namespaces.
    pub namespaces: Option<Vec<String>>,
    pub negated: bool,
    pub process: Process,
}

impl Wildcard {
    pub fn allows(&self, namespace: &str) -> bool {
        match &self.namespaces {
            None => true,
            Some(list) => list.iter().any(|n| n == namespace) != self.negated,
        }
    }
}

/// A content model as a regular expression over child elements, matched by derivatives.
#[derive(Debug, Clone)]
pub enum Expr {
    Empty,
    Fail,
    Element(ElemId),
    Any(Box<Wildcard>),
    Sequence(Vec<Expr>),
    Choice(Vec<Expr>),
    Repeat(Box<Expr>, u32, Option<u32>),
    /// `xs:all`: each member at most once, in any order; `true` when required.
    All(Vec<(ElemId, bool)>),
}

impl Schema {
    fn empty() -> Schema {
        let mut schema = Schema {
            types: Vec::new(),
            elements: Vec::new(),
            globals: HashMap::new(),
            global_types: HashMap::new(),
            global_attributes: HashMap::new(),
            substitutes: HashMap::new(),
            any_type: 0,
            constraints: Vec::new(),
            type_flags: HashMap::new(),
        };
        types::builtins(&mut schema);
        schema.any_type = schema.types.len();
        schema.types.push(Type::Complex(ComplexType {
            name: "anyType".into(),
            base: None,
            content: Content::Any,
            attributes: Vec::new(),
            attribute_wildcard: Some(Wildcard { namespaces: None, negated: false, process: Process::Lax }),
            mixed: true,
        }));
        schema.global_types.insert((XS.into(), "anyType".into()), schema.any_type);
        schema
    }

    fn push_simple(&mut self, st: SimpleType) -> TypeId {
        self.types.push(Type::Simple(st));
        self.types.len() - 1
    }

    fn builtin(&self, name: &str) -> TypeId {
        self.global_types[&(XS.to_string(), name.to_string())]
    }

    fn simple(&self, id: TypeId) -> &SimpleType {
        match &self.types[id] {
            Type::Simple(s) => s,
            Type::Complex(c) => panic!("{} is not a simple type", c.name),
        }
    }

    fn simple_mut(&mut self, id: TypeId) -> &mut SimpleType {
        match &mut self.types[id] {
            Type::Simple(s) => s,
            Type::Complex(_) => panic!("not a simple type"),
        }
    }

    /// Compiles schema text (`XmlSchemaValidator`): an XSD document, or a path to a `.xsd` file, the class path
    /// resource of that name or else the file against the working directory (`openReaderToFileFromClassPathOrPath`,
    /// with the resource's URL as the system id its includes resolve against). `Err` is the reason the schema cannot be used. `reported` is the server's
    /// [`Reported`] namespaces, read and extended by this compile.
    pub fn compile(text: &str, reported: &Reported) -> Result<Schema, SchemaError> {
        let trimmed = text.trim();
        let (source, location) = if trimmed.ends_with('>') || trimmed.is_empty() {
            (text.to_string(), None)
        } else if let Some(resource) = trimmed.ends_with(".xsd").then(|| crate::class_path::locate(trimmed)).flatten() {
            let location = match &resource {
                crate::class_path::Location::File(path) => path.clone(),
                crate::class_path::Location::Jar { .. } => PathBuf::from(resource.url()),
            };
            let source = resource.read().map_err(|e| SchemaError { message: format!("{trimmed} ({e})"), kind: ErrorKind::FileNotFound })?;
            (String::from_utf8_lossy(&source).into_owned(), Some(location))
        } else if trimmed.ends_with(".xsd") {
            let path = PathBuf::from(trimmed);
            let source = std::fs::read_to_string(&path).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => SchemaError { message: format!("{trimmed} (No such file or directory)"), kind: ErrorKind::FileNotFound },
                _ => SchemaError { message: format!("{trimmed} ({e})"), kind: ErrorKind::FileNotFound },
            })?;
            (source, Some(path))
        } else {
            return Err(SchemaError { message: "Schema must either be a path reference to a *.xsd file or an xml string".into(), kind: ErrorKind::IllegalArgument });
        };
        let documents = load(source, location)?;
        let parsed: Vec<(Document, Option<String>)> = documents
            .iter()
            .enumerate()
            .map(|(i, (text, location, chameleon))| {
                roxmltree::Document::parse_with_options(text, roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() })
                    .map(|d| (d, chameleon.clone()))
                    .map_err(|e| not_well_formed(text, location.as_deref().map(|l| document_system_id(i, l)), e.to_string()))
            })
            .collect::<Result<_, _>>()?;
        let locations: Vec<Option<PathBuf>> = documents.iter().map(|(_, l, _)| l.clone()).collect();
        let main_system_id = locations[0].as_deref().map(system_id);
        // A root in the schema namespace other than `xs:schema`: `XSDHandler` dereferences the schema attributes it
        // never read.
        if parsed.iter().any(|(d, _)| d.root_element().tag_name().namespace() == Some(XS) && d.root_element().tag_name().name() != "schema") {
            return Err(SchemaError {
                message: "Cannot invoke \"com.sun.org.apache.xerces.internal.impl.xs.util.XInt.intValue()\" because \"this.fSchemaAttrs[com.sun.org.apache.xerces.internal.impl.xs.traversers.XSAttributeChecker.ATTIDX_AFORMDEFAULT]\" is null".into(),
                kind: ErrorKind::NullPointer,
            });
        }
        let mut builder = Builder::new(&locations, reported.clone());
        let result = match builder.register(&parsed, &locations).and_then(|()| builder.build()) {
            Ok(()) => Ok(builder.schema),
            Err(message) => Err((message, builder.located.take())),
        };
        result.map_err(|(message, located)| {
            // The error's place when it was raised against a node (and is the one that ended the build).
            let at = located.filter(|(m, ..)| *m == message);
            let (location, system_id) = match at {
                Some((_, doc, offset)) => {
                    // A start tag's offset stands for the place after it; any other, for itself.
                    let input = parsed[doc].0.input_text();
                    let place = if input.as_bytes().get(offset) == Some(&b'<') { after_start_tag(input, offset) } else { line_column(input, offset) };
                    (Some(place), locations[doc].as_deref().map(|l| document_system_id(doc, l)))
                }
                None => (None, main_system_id),
            };
            SchemaError { message, kind: ErrorKind::Parse { location, system_id } }
        })
    }
}

/// A component redefined: the redefined document, the kind and name, and the redefine element (document, position).
type Redefinition = (usize, (Kind, String), (usize, usize), (usize, usize));

/// A schema document: its text, its location and the namespace it is included into (chameleon include).
type SchemaText = (String, Option<PathBuf>, Option<String>);

/// Every schema document reachable through `xs:include`/`xs:import` with a `schemaLocation` that exists: text,
/// location and, for an included document without a target namespace, the includer's (chameleon include).
fn load(text: String, location: Option<PathBuf>) -> Result<Vec<SchemaText>, SchemaError> {
    let mut out: Vec<SchemaText> = vec![(text, location, None)];
    let mut i = 0;
    while i < out.len() {
        let (text, location, _) = out[i].clone();
        let doc = roxmltree::Document::parse_with_options(&text, roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() })
            .map_err(|e| not_well_formed(&text, location.as_deref().map(|l| document_system_id(i, l)), e.to_string()))?;
        let root = doc.root_element();
        let tns = root.attribute("targetNamespace").map(str::to_string);
        for child in root.children().filter(|c| is_xs(c, "include") || is_xs(c, "import") || is_xs(c, "redefine")) {
            // The XML and XML Schema namespaces are built into Xerces: their schema documents are never read.
            if is_xs(&child, "import") {
                match child.attribute("namespace") {
                    Some(XS) => continue,
                    Some(XML_NS) => {
                        let marker = PathBuf::from("<built-in xml.xsd>");
                        if !out.iter().any(|(_, l, _)| l.as_deref() == Some(marker.as_path())) {
                            out.push((XML_SCHEMA.to_string(), Some(marker), None));
                        }
                        continue;
                    }
                    _ => {}
                }
            }
            let Some(href) = child.attribute("schemaLocation") else { continue };
            // `ACCESS_EXTERNAL_SCHEMA` is `file`: any other scheme is refused, and that is an error.
            let href = match href.split_once("://") {
                Some(("file", path)) => path,
                Some((scheme, _)) => {
                    let message = format!(
                        "schema_reference: Failed to read schema document '{}', because '{scheme}' access is not allowed due to restriction set by the accessExternalSchema property.",
                        href.rsplit('/').next().unwrap_or(href)
                    );
                    // Reported at the referring element.
                    let place = after_start_tag(&text, child.range().start);
                    return Err(SchemaError { message, kind: ErrorKind::Parse { location: Some(place), system_id: location.as_deref().map(|l| document_system_id(i, l)) } });
                }
                None => href,
            };
            let base: &Path = location.as_deref().and_then(Path::parent).unwrap_or(Path::new(""));
            let path = base.join(href);
            if out.iter().any(|(_, l, _)| l.as_deref() == Some(path.as_path())) {
                continue;
            }
            // Xerces only warns about a schema document it cannot read.
            let Ok(included) = read_document(&path) else { continue };
            let chameleon = if is_xs(&child, "import") { None } else { tns.clone() };
            out.push((included, Some(path), chameleon));
        }
        i += 1;
    }
    Ok(out)
}

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// The attributes of the XML namespace as Xerces has them built in.
const XML_SCHEMA: &str = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="http://www.w3.org/XML/1998/namespace">
  <xs:attribute name="lang" type="xs:language"/>
  <xs:attribute name="space"><xs:simpleType><xs:restriction base="xs:NCName"><xs:enumeration value="default"/><xs:enumeration value="preserve"/></xs:restriction></xs:simpleType></xs:attribute>
  <xs:attribute name="base" type="xs:anyURI"/>
  <xs:attribute name="id" type="xs:ID"/>
  <xs:attributeGroup name="specialAttrs"><xs:attribute ref="xml:base"/><xs:attribute ref="xml:lang"/><xs:attribute ref="xml:space"/><xs:attribute ref="xml:id"/></xs:attributeGroup>
</xs:schema>"#;

/// The namespace bound to `prefix` at `node`; `xml` is always bound.
fn namespace_of(node: Node, prefix: &str) -> Option<String> {
    if prefix == "xml" {
        return Some(XML_NS.to_string());
    }
    node.lookup_namespace_uri(Some(prefix)).map(str::to_string)
}

fn is_xs(node: &Node, name: &str) -> bool {
    node.is_element() && node.tag_name().namespace() == Some(XS) && node.tag_name().name() == name
}

fn xs_children<'a, 'input>(node: Node<'a, 'input>) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children().filter(|c| c.is_element() && c.tag_name().namespace() == Some(XS) && c.tag_name().name() != "annotation")
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Element,
    Type,
    Group,
    AttributeGroup,
    Attribute,
    Notation,
}

struct Builder<'a, 'input> {
    schema: Schema,
    /// Each document's root with its effective target namespace and form defaults.
    roots: Vec<(Node<'a, 'input>, String, bool, bool)>,
    components: HashMap<(Kind, QName), (Node<'a, 'input>, usize)>,
    /// Named types get their ids before they are built (so references can be circular) and are built when first
    /// needed, so an extension's base exists before the extension.
    pending_types: HashMap<TypeId, (Node<'a, 'input>, usize)>,
    building: std::collections::HashSet<TypeId>,
    /// Identity constraints by name, and by the position of their declaration (a group's elements are built once
    /// per reference), with each keyref's `refer` to resolve once all are known.
    constraint_names: HashMap<QName, identity::IcId>,
    constraint_nodes: HashMap<(usize, usize), identity::IcId>,
    refers: Vec<(identity::IcId, Node<'a, 'input>, usize, String)>,
    /// Nodes (document, position) whose QName reference names a component an `xs:redefine` renamed: they resolve
    /// to the original, `<name>_fn3dktizrknc9pi` as Xerces renames it.
    redirected: std::collections::HashSet<(usize, usize)>,
    /// Attribute-group redefinitions without a self-reference: (redefinition, document, original's name).
    attribute_group_restrictions: Vec<(Node<'a, 'input>, usize, QName)>,
    /// How deep inside a sequence or choice the particle being built is (`cos-all-limited`).
    nested: usize,
    /// Value constraints (by their declaration's position) with a QName prefix not declared there.
    unbound_values: std::collections::HashSet<(usize, usize)>,
    /// The namespaces some loaded document has as its target namespace (`fGrammarBucket`).
    grammars: std::collections::HashSet<String>,
    /// Per document, the namespaces its components may refer to (`XSDocumentInfo.fImportedNS`): its own and those
    /// it imports.
    allowed: Vec<std::collections::HashSet<String>>,
    reported: Reported,
    /// Each document's system id (`None` for the schema given as text), as the messages name it.
    system_ids: Vec<Option<String>>,
    /// The last error raised against a node: its message, document and the node's offset.
    located: std::cell::RefCell<Option<(String, usize, usize)>>,
    /// Global elements (document, offset) whose `type` names a component of an unloaded namespace, already
    /// reported: they take their substitution group head's type, like an element without one.
    unresolved_types: std::collections::HashSet<(usize, usize)>,
    /// The declaration (document, offset) each built type comes from, where the checks over the built schema report.
    type_nodes: HashMap<TypeId, (usize, usize)>,
    /// The reference into a namespace without a grammar, not reported yet, that Xerces' traversal meets first
    /// ([`Builder::xerces_first_unloaded`]): the one reported, whichever such reference this builder meets first.
    first_unloaded: Option<Unloaded>,
}

/// A QName reference into a namespace without a loaded grammar: where it is, as written, its component kind (as
/// messages name it) and its namespace.
#[derive(Clone)]
struct Unloaded {
    place: (usize, usize),
    value: String,
    what: &'static str,
    namespace: String,
}

/// How [`Builder::xerces_first_unloaded`]'s walk goes on after a reference.
enum Walk {
    Next,
    /// The first reference into an unreported namespace without a grammar.
    Found(Unloaded),
    /// A reference that is an error of another kind: what Xerces reports first is not an unloaded namespace.
    Stop,
}

/// The facets written under a restriction, by element name.
fn facet_names<'n>(restriction: Node<'n, '_>) -> Vec<&'n str> {
    const FACETS: &[&str] = &["minExclusive", "minInclusive", "maxExclusive", "maxInclusive", "totalDigits", "fractionDigits", "length", "minLength", "maxLength", "enumeration", "whiteSpace", "pattern"];
    xs_children(restriction).map(|c| c.tag_name().name()).filter(|n| FACETS.contains(n)).collect()
}

fn node_name<'n>(node: Node<'n, '_>) -> &'n str {
    node.attribute("name").unwrap_or_default()
}

/// The suffix Xerces gives a redefined component's original (`XSDHandler.REDEF_IDENTIFIER`).
const REDEFINED: &str = "_fn3dktizrknc9pi";

impl<'a, 'input> Builder<'a, 'input> {
    fn new(locations: &[Option<PathBuf>], reported: Reported) -> Self {
        Builder {
            grammars: Default::default(),
            allowed: Vec::new(),
            reported,
            system_ids: locations.iter().enumerate().map(|(i, l)| l.as_deref().map(|l| document_system_id(i, l))).collect(),
            located: Default::default(),
            unresolved_types: Default::default(),
            schema: Schema::empty(),
            roots: Vec::new(),
            components: HashMap::new(),
            pending_types: HashMap::new(),
            building: Default::default(),
            constraint_names: HashMap::new(),
            constraint_nodes: HashMap::new(),
            refers: Vec::new(),
            redirected: Default::default(),
            attribute_group_restrictions: Vec::new(),
            nested: 0,
            unbound_values: Default::default(),
            type_nodes: HashMap::new(),
            first_unloaded: None,
        }
    }

    /// Registers every document's global components (`XSDHandler.buildGlobalNameRegistries`), after checking each
    /// against the schema for schemas.
    fn register(&mut self, documents: &'a [(Document<'input>, Option<String>)], locations: &[Option<PathBuf>]) -> Result<(), String> {
        let builder = self;
        let renamed = builder.redefinitions(documents, locations)?;
        for (doc_index, (doc, chameleon)) in documents.iter().enumerate() {
            let root = doc.root_element();
            s4s::check(root).map_err(|(message, offset)| builder.fail_at((doc_index, offset), message))?;
            if !is_xs(&root, "schema") {
                return Err(builder.fail(root, doc_index, format!("the root element of a schema document must be xs:schema, not {}", root.tag_name().name())));
            }
            let tns = root.attribute("targetNamespace").map(str::to_string).or_else(|| chameleon.clone()).unwrap_or_default();
            let qualified = |attr: &str| root.attribute(attr) == Some("qualified");
            builder.roots.push((root, tns.clone(), qualified("elementFormDefault"), qualified("attributeFormDefault")));
            builder.grammars.insert(tns.clone());
            let imports = root.children().filter(|c| is_xs(c, "import")).map(|c| c.attribute("namespace").unwrap_or_default().to_string());
            builder.allowed.push(std::iter::once(tns.clone()).chain(imports).collect());
            for child in xs_children(root) {
                let kind = match child.tag_name().name() {
                    "element" => Kind::Element,
                    "simpleType" | "complexType" => Kind::Type,
                    "group" => Kind::Group,
                    "attributeGroup" => Kind::AttributeGroup,
                    "attribute" => Kind::Attribute,
                    "notation" => Kind::Notation,
                    "include" | "import" => continue,
                    "redefine" => {
                        // Its components, when the redefined document was read (Xerces ignores the rest).
                        if renamed.iter().any(|(_, _, by, _)| *by == (doc_index, child.range().start)) {
                            for component in xs_children(child) {
                                let kind = if component.tag_name().name() == "group" {
                                    Kind::Group
                                } else if component.tag_name().name() == "attributeGroup" {
                                    Kind::AttributeGroup
                                } else {
                                    Kind::Type
                                };
                                let name = component.attribute("name").unwrap_or_default();
                                if builder.components.insert((kind, (tns.clone(), name.to_string())), (component, doc_index)).is_some() {
                                    return Err(builder.fail(component, doc_index, format!("sch-props-correct.2: A schema cannot contain two global components with the same name; this schema contains two occurrences of '{tns},{name}'.")));
                                }
                            }
                        }
                        continue;
                    }
                    other => return Err(builder.fail(child, doc_index, format!("s4s-elt-invalid-content.1: The content of 'schema' is invalid.  Element '{other}' is invalid, misplaced, or occurs too often."))),
                };
                let name = child.attribute("name").ok_or_else(|| builder.fail(child, doc_index, format!("s4s-att-must-appear: Attribute 'name' must appear in element '{}'.", child.tag_name().name())))?;
                if !types::is_ncname(name) {
                    let element = child.tag_name().name();
                    return Err(builder.fail(child, doc_index, format!("s4s-att-invalid-value: Invalid attribute value for 'name' in element '{element}'. Recorded reason: cvc-datatype-valid.1.2.1: '{name}' is not a valid value for 'NCName'.")));
                }
                // The schema for schemas' own definitions of the built-in types: Xerces keeps its built-ins.
                if tns == XS && kind == Kind::Type && builder.schema.global_types.contains_key(&(XS.to_string(), name.to_string())) {
                    continue;
                }
                let local = if renamed.iter().any(|(d, k, ..)| *d == doc_index && *k == (kind, name.to_string())) { format!("{name}{REDEFINED}") } else { name.to_string() };
                let key = (kind, (tns.clone(), local));
                if builder.components.insert(key, (child, doc_index)).is_some() {
                    return Err(builder.fail(child, doc_index, format!("sch-props-correct.2: A schema cannot contain two global components with the same name; this schema contains two occurrences of '{tns},{name}'.")));
                }
            }
        }
        // A redefinition of a component the redefined document does not have.
        for (_, (kind, name), (doc_index, _), report) in &renamed {
            let tns = builder.roots[*doc_index].1.clone();
            if !builder.components.contains_key(&(*kind, (tns, format!("{name}{REDEFINED}")))) {
                return Err(builder.fail_at(*report, match kind {
                    Kind::Type => format!("src-resolve: Cannot resolve the name '{name}{REDEFINED}' to a(n) 'type definition' component."),
                    Kind::Group => format!("src-resolve: Cannot resolve the name ',{name}{REDEFINED}' to a(n) 'group' component."),
                    _ => format!("src-resolve: Cannot resolve the name ',{name}{REDEFINED}' to a(n) 'attribute group' component."),
                }));
            }
        }
        Ok(())
    }

    /// `xs:redefine` (`XSDHandler.renameRedefiningComponents` and `checkForDuplicateNames`): checks each redefining
    /// component's shape, marks its self-reference as naming the original, and returns, for each component
    /// redefined, the redefined document, the kind and name, and the redefine element (document, position).
    fn redefinitions(&mut self, documents: &'a [(Document<'input>, Option<String>)], locations: &[Option<PathBuf>]) -> Result<Vec<Redefinition>, String> {
        let mut out = Vec::new();
        for (doc_index, (doc, chameleon)) in documents.iter().enumerate() {
            let root = doc.root_element();
            let tns = root.attribute("targetNamespace").map(str::to_string).or_else(|| chameleon.clone());
            for redefine in root.children().filter(|c| is_xs(c, "redefine")) {
                let Some(href) = redefine.attribute("schemaLocation") else { continue };
                let base: &Path = locations[doc_index].as_deref().and_then(Path::parent).unwrap_or(Path::new(""));
                let path = base.join(href);
                let Some(target) = locations.iter().position(|l| l.as_deref() == Some(path.as_path())) else { continue };
                let target_root = documents[target].0.root_element();
                // `constructTrees` checks the redefined document's root before anything else.
                if target_root.tag_name().namespace() != Some(XS) {
                    return Err(self.fail(target_root, target, format!(
                        "s4s-elt-schema-ns: The namespace of element '{}' must be from the schema namespace, 'http://www.w3.org/2001/XMLSchema'.",
                        target_root.tag_name().name()
                    )));
                }
                if !is_xs(&target_root, "schema") {
                    return Err(self.fail(redefine, doc_index, format!(
                        "src-redefine.2: The root element of document '{}' has to have the namespace name 'http://www.w3.org/2001/XMLSchema' and the local name 'schema'.",
                        path.display()
                    )));
                }
                if let Some(theirs) = target_root.attribute("targetNamespace") && Some(theirs) != tns.as_deref() {
                    return Err(self.fail(target_root, target, format!(
                        "src-redefine.3.1: The targetNamespace of the referenced schema, currently '{theirs}', must be identical to that of the redefining schema, currently '{}'.",
                        tns.as_deref().unwrap_or("null")
                    )));
                }
                let ns = tns.clone().unwrap_or_default();
                for component in xs_children(redefine) {
                    let kind_name = component.tag_name().name();
                    let name = component.attribute("name").unwrap_or_default().to_string();
                    let refers_to_self = |n: &Node, attribute: &str| {
                        n.attribute(attribute).is_some_and(|v| {
                            let (prefix, local) = v.split_once(':').map(|(p, l)| (Some(p), l)).unwrap_or((None, v));
                            local == name && n.lookup_namespace_uri(prefix).unwrap_or_default() == ns
                        })
                    };
                    let kind = match kind_name {
                        "simpleType" => {
                            let Some(child) = xs_children(component).next() else {
                                return Err(self.fail(component, doc_index, "src-redefine.5.a.a: No non-annotation children of <simpleType> were found. <simpleType> children of <redefine> elements must have <restriction> descendants, with 'base' attributes that refer to themselves.".into()));
                            };
                            if child.tag_name().name() != "restriction" {
                                return Err(self.fail(component, doc_index, format!("src-redefine.5.a.b: '{}' is not a valid child element. <simpleType> children of <redefine> elements must have <restriction> descendants, with 'base' attributes that refer to themselves.", child.tag_name().name())));
                            }
                            if !refers_to_self(&child, "base") {
                                return Err(self.fail(component, doc_index, format!("src-redefine.5.a.c: '{}' does not have a 'base' attribute that refers to the redefined element, '{ns},{name}'. <simpleType> children of <redefine> elements must have <restriction> descendants, with 'base' attributes that refer to themselves.", child.tag_name().name())));
                            }
                            self.redirected.insert((doc_index, child.range().start));
                            Kind::Type
                        }
                        "complexType" => {
                            let Some(child) = xs_children(component).next() else {
                                return Err(self.fail(component, doc_index, "src-redefine.5.b.a: No non-annotation children of <complexType> were found. <complexType> children of <redefine> elements must have <extension> or <restriction> descendants, with 'base' attributes that refer to themselves.".into()));
                            };
                            let Some(grandchild) = xs_children(child).next() else {
                                return Err(self.fail(child, doc_index, "src-redefine.5.b.b: No non-annotation grandchildren of <complexType> were found. <complexType> children of <redefine> elements must have <extension> or <restriction> descendants, with 'base' attributes that refer to themselves.".into()));
                            };
                            if !matches!(grandchild.tag_name().name(), "extension" | "restriction") {
                                return Err(self.fail(grandchild, doc_index, format!("src-redefine.5.b.c: '{}' is not a valid grandchild element. <complexType> children of <redefine> elements must have <extension> or <restriction> descendants, with 'base' attributes that refer to themselves.", grandchild.tag_name().name())));
                            }
                            if !refers_to_self(&grandchild, "base") {
                                return Err(self.fail(grandchild, doc_index, format!("src-redefine.5.b.d: '{}' does not have a 'base' attribute that refers to the redefined element, '{ns},{name}'. <complexType> children of <redefine> elements must have <extension> or <restriction> descendants, with 'base' attributes that refer to themselves.", grandchild.tag_name().name())));
                            }
                            self.redirected.insert((doc_index, grandchild.range().start));
                            Kind::Type
                        }
                        "group" => {
                            let refs: Vec<Node> = component.descendants().filter(|d| is_xs(d, "group") && refers_to_self(d, "ref")).collect();
                            // `changeRedefineGroup` checks each self-reference's occurrence as it renames it.
                            if let Some(r) = refs.iter().find(|r| r.attribute("minOccurs").is_some_and(|v| v != "1") || r.attribute("maxOccurs").is_some_and(|v| v != "1")) {
                                let reference = r.attribute("ref").unwrap_or_default();
                                return Err(self.fail(*r, doc_index, format!("src-redefine.6.1.2:  The group '{reference}', which contains a reference to a group being redefined, must have 'minOccurs' = 'maxOccurs' = 1.")));
                            }
                            if refs.len() > 1 {
                                return Err(self.fail(component, doc_index, format!("src-redefine.6.1.1:  If a group child of a <redefine> element contains a group referring itself, it must have exactly 1; this one has '{}'.", refs.len())));
                            }
                            if let Some(r) = refs.first() {
                                self.redirected.insert((doc_index, r.range().start));
                            }
                            Kind::Group
                        }
                        "attributeGroup" => {
                            let refs: Vec<Node> = xs_children(component).filter(|d| is_xs(d, "attributeGroup") && refers_to_self(d, "ref")).collect();
                            if refs.len() > 1 {
                                return Err(self.fail(component, doc_index, format!("src-redefine.7.1:  If an attributeGroup child of a <redefine> element contains an attributeGroup referring itself, it must have exactly 1; this one has {}.", refs.len())));
                            }
                            match refs.first() {
                                Some(r) => {
                                    self.redirected.insert((doc_index, r.range().start));
                                }
                                None => self.attribute_group_restrictions.push((component, doc_index, (ns.clone(), format!("{name}{REDEFINED}")))),
                            }
                            Kind::AttributeGroup
                        }
                        other => return Err(self.fail(component, doc_index, format!("s4s-elt-must-match.1: The content of 'redefine' must match (annotation | (simpleType | complexType | group | attributeGroup))*. A problem was found starting at: {other}."))),
                    };
                    // A type's unresolved original is reported at its self-reference, a group's at the group.
                    let report = match kind {
                        Kind::Type => xs_children(component).next().map(|c| if kind_name == "complexType" { xs_children(c).next().unwrap_or(c) } else { c }).unwrap_or(component),
                        _ => component,
                    };
                    out.push((target, (kind, name), (doc_index, redefine.range().start), (doc_index, report.range().start)));
                }
            }
        }
        Ok(out)
    }

    /// An attribute-group redefinition without a self-reference must restrict the original
    /// (`derivation-ok-restriction.2.2`): each of its attribute uses must be one of the original's, or allowed by
    /// the original's wildcard.
    fn check_attribute_group_restrictions(&mut self) -> Result<(), String> {
        for (node, doc, original) in std::mem::take(&mut self.attribute_group_restrictions) {
            let empty = || ComplexType { name: String::new(), base: None, content: Content::Empty, attributes: Vec::new(), attribute_wildcard: None, mixed: false };
            let mut base = empty();
            let &(original_node, original_doc) = self.components.get(&(Kind::AttributeGroup, original.clone())).expect("checked when registering");
            self.attributes_of(original_node, original_doc, &mut base)?;
            let mut own = empty();
            self.attributes_of(node, doc, &mut own)?;
            for attribute in &own.attributes {
                let matched = base.attributes.iter().any(|a| a.name == attribute.name);
                if !matched && !base.attribute_wildcard.as_ref().is_some_and(|w| w.allows(&attribute.name.0)) {
                    return Err(self.fail_at(attribute.source, format!(
                        "derivation-ok-restriction.2.2.a: Error for type '{}'.  The attribute use '{}' in this type does not have a matching attribute use in the base, and the base type does not have a wildcard attribute.",
                        node.attribute("name").unwrap_or_default(),
                        attribute.name.1
                    )));
                }
            }
        }
        Ok(())
    }

    /// Circular derivations (`st-props-correct.2`, `ct-props-correct.3`) and circular groups and attribute groups
    /// (`mg-props-correct.2`, `src-attribute_group.3`), in document order.
    fn check_cycles(&self) -> Result<(), String> {
        type Named<'c, 'a, 'input> = (&'c (Kind, QName), &'c (Node<'a, 'input>, usize));
        let mut named: Vec<Named<'_, 'a, 'input>> = self.components.iter().filter(|(k, _)| !matches!(k.0, Kind::Element | Kind::Attribute | Kind::Notation)).collect();
        named.sort_by_key(|(_, (node, doc))| (*doc, node.range().start));
        for ((kind, name), _) in named {
            let mut seen = std::collections::HashSet::new();
            let mut stack = vec![(*kind, name.clone())];
            while let Some(current) = stack.pop() {
                let Some(&(node, doc)) = self.components.get(&current) else { continue };
                for (next, at) in self.references(current.0, node, doc) {
                    if next == (*kind, name.clone()) {
                        // Reported at the reference that closes the cycle.
                        let shown = format!("{}:{}", name.0, node_name(self.components[&next].0));
                        return Err(self.fail(at, doc, match kind {
                            Kind::Type if self.components[&next].0.tag_name().name() == "simpleType" => format!(
                                "st-props-correct.2: Circular definitions have been detected for simple type '{shown}'. This means that '{shown}' is contained in its own type hierarchy, which is an error."
                            ),
                            Kind::Type => format!("ct-props-correct.3: Circular definitions detected for complex type '{shown}'. This means that '{shown}' is contained in its own type hierarchy, which is an error."),
                            Kind::Group => format!("mg-props-correct.2: Circular definitions detected for group '{shown}'. Recursively following the {{term}} values of the particles leads to a particle whose {{term}} is the group itself."),
                            _ => format!("src-attribute_group.3: Circular definitions detected for attribute group '{shown}'. Recursively following attribute group references eventually leads back to itself."),
                        }));
                    }
                    if seen.insert(next.clone()) {
                        stack.push(next);
                    }
                }
            }
        }
        Ok(())
    }

    /// The components a type's derivation, a group's model or an attribute group refers to (not the types of
    /// declarations, whose content may refer back legitimately).
    fn references(&self, kind: Kind, node: Node<'a, 'input>, doc: usize) -> Vec<((Kind, QName), Node<'a, 'input>)> {
        let mut out = Vec::new();
        let mut walk = vec![node];
        while let Some(n) = walk.pop() {
            for child in xs_children(n) {
                let tag = child.tag_name().name();
                match (kind, tag) {
                    (_, "element" | "attribute") => continue,
                    (Kind::Type, "restriction" | "extension") => {
                        if let Some(b) = child.attribute("base").and_then(|b| self.resolve(child, doc, b).ok()) {
                            out.push(((Kind::Type, b), child));
                        }
                    }
                    (Kind::Type, "list") => {
                        if let Some(b) = child.attribute("itemType").and_then(|b| self.resolve(child, doc, b).ok()) {
                            out.push(((Kind::Type, b), child));
                        }
                    }
                    (Kind::Type, "union") => {
                        for m in child.attribute("memberTypes").unwrap_or_default().split_whitespace() {
                            if let Ok(b) = self.resolve(child, doc, m) {
                                out.push(((Kind::Type, b), child));
                            }
                        }
                    }
                    (Kind::Group, "group") | (Kind::AttributeGroup, "attributeGroup") => {
                        if let Some(r) = child.attribute("ref").and_then(|r| self.resolve(child, doc, r).ok()) {
                            out.push(((kind, r), child));
                        }
                    }
                    (Kind::Type, "sequence" | "choice" | "all" | "group" | "attributeGroup" | "anyAttribute" | "any") => continue,
                    _ => {}
                }
                walk.push(child);
            }
        }
        out
    }

    fn build(&mut self) -> Result<(), String> {
        self.first_unloaded = self.xerces_first_unloaded();
        self.check_cycles()?;
        // Reserve ids for named types and global elements.
        let mut named: Vec<((Kind, QName), (Node<'a, 'input>, usize))> = self.components.iter().map(|(k, v)| (k.clone(), *v)).collect();
        named.sort_by_key(|a| (a.1.1, a.1.0.range().start));
        for ((kind, name), (node, doc)) in &named {
            match kind {
                Kind::Type => {
                    let id = self.schema.types.len();
                    self.schema.types.push(Type::Simple(SimpleType {
                        name: name.1.clone(),
                        base: None,
                        variety: Variety::Atomic,
                        facets: Facets::default(),
                        dv: None,
                        special: None,
                    }));
                    self.schema.global_types.insert(name.clone(), id);
                    self.pending_types.insert(id, (*node, *doc));
                }
                Kind::Element => {
                    let id = self.schema.elements.len();
                    self.schema.elements.push(ElementDecl { name: name.clone(), ty: self.schema.any_type, nillable: false, fixed: None, default: None, constraints: Vec::new(), block: 0, final_: 0, source: (*doc, node.range().start) });
                    self.schema.globals.insert(name.clone(), id);
                }
                _ => {}
            }
        }
        for ((kind, name), (node, doc)) in &named {
            match kind {
                Kind::Type => self.ensure_built(self.schema.global_types[name])?,
                Kind::Attribute => {
                    let attribute = self.attribute(*node, *doc, true)?.expect("a global attribute is no reference");
                    self.schema.global_attributes.insert(name.clone(), attribute);
                }
                // Xerces traverses every global group and attribute group, referenced or not.
                Kind::Group => {
                    if let Some(model) = xs_children(*node).next() {
                        self.particle(model, *doc)?;
                    }
                }
                Kind::AttributeGroup => {
                    let mut scratch = ComplexType { name: String::new(), base: None, content: Content::Empty, attributes: Vec::new(), attribute_wildcard: None, mixed: false };
                    self.own_attributes(*node, *doc, &mut scratch, &name.1, true)?;
                }
                _ => {}
            }
        }
        for ((kind, name), (node, doc)) in &named {
            if *kind == Kind::Element {
                let id = self.schema.globals[name];
                let decl = self.element_decl(*node, *doc, name.clone())?;
                self.schema.elements[id] = decl;
            }
        }
        // Substitution groups (after every global element has its type).
        for ((kind, name), (node, doc)) in &named {
            if *kind != Kind::Element {
                continue;
            }
            if let Some(raw) = node.attribute("substitutionGroup") {
                let Some(head) = self.reference(*node, *doc, raw, "element declaration")? else { continue };
                let head_id = match self.schema.globals.get(&head) {
                    Some(id) => *id,
                    None => return Err(self.fail(*node, *doc, format!("src-resolve: Cannot resolve the name '{raw}' to a(n) 'element declaration' component."))),
                };
                let member = self.schema.globals[name];
                let untyped = node.attribute("type").is_none() || self.unresolved_types.contains(&(*doc, node.range().start));
                if untyped && !xs_children(*node).any(|c| matches!(c.tag_name().name(), "simpleType" | "complexType")) {
                    self.schema.elements[member].ty = self.schema.elements[head_id].ty;
                }
                self.schema.substitutes.entry(head_id).or_default().push(member);
            }
        }
        // Anonymous complex types of element declarations, in the order they were declared.
        while let Some(id) = self.pending_types.keys().min().copied() {
            self.ensure_built(id)?;
        }
        self.resolve_refers()?;
        self.check_attribute_group_restrictions()?;
        self.check_components()?;
        // Transitive closure of substitution groups.
        let heads: Vec<ElemId> = self.schema.substitutes.keys().copied().collect();
        for head in heads {
            let mut all = self.schema.substitutes[&head].clone();
            let mut i = 0;
            while i < all.len() {
                if let Some(more) = self.schema.substitutes.get(&all[i]) {
                    for m in more.clone() {
                        if !all.contains(&m) {
                            all.push(m);
                        }
                    }
                }
                i += 1;
            }
            self.schema.substitutes.insert(head, all);
        }
        self.schema.check_particle_restrictions().map_err(|(id, m)| match self.type_nodes.get(&id) {
            Some(place) => self.fail_at(*place, m),
            None => m,
        })?;
        Ok(())
    }

    /// A `QName`-valued attribute resolved with the namespace bindings in scope at `node`.
    fn resolve(&self, node: Node, doc: usize, value: &str) -> Result<QName, String> {
        let (prefix, local) = match value.split_once(':') {
            Some((p, l)) => (Some(p), l),
            None => (None, value),
        };
        let namespace = match prefix {
            Some(p) => namespace_of(node, p).ok_or_else(|| format!("src-resolve.4.1: the prefix '{p}' is not declared"))?,
            None => node.lookup_namespace_uri(None).map(str::to_string).unwrap_or_else(|| {
                // A chameleon-included document's unprefixed references take the includer's namespace.
                let (root, tns, ..) = &self.roots[doc];
                if root.attribute("targetNamespace").is_none() { tns.clone() } else { String::new() }
            }),
        };
        let local = if self.redirected.contains(&(doc, node.range().start)) { format!("{local}{REDEFINED}") } else { local.to_string() };
        Ok((namespace, local))
    }

    /// `message`, remembered as raised against `node` (where Xerces reports it).
    fn fail(&self, node: Node, doc: usize, message: String) -> String {
        self.fail_at((doc, node.range().start), message)
    }

    /// The schema element starting at `place` (document, offset).
    fn node_at(&self, (doc, offset): (usize, usize)) -> Option<Node<'a, 'input>> {
        self.roots.get(doc)?.0.document().descendants().find(|n| n.is_element() && n.range().start == offset)
    }

    /// `message`, remembered as raised against the element starting at `place` (document, offset).
    fn fail_at(&self, (doc, offset): (usize, usize), message: String) -> String {
        *self.located.borrow_mut() = Some((message.clone(), doc, offset));
        message
    }

    /// `XSDHandler.getGlobalDecl` up to the lookup of a QName reference to a component `what` (Xerces' name for its
    /// kind): built-in types first; then a namespace the document neither has nor imports is `src-resolve.4.1`/`4.2`,
    /// and one without a loaded grammar is `src-resolve` the first time the server meets it ([`Reported`]) and `None`
    /// (the reference is dropped) from then on.
    fn reference(&self, node: Node, doc: usize, value: &str, what: &str) -> Result<Option<QName>, String> {
        let name = self.resolve(node, doc, value)?;
        if what == "type definition" && name.0 == XS && self.schema.global_types.contains_key(&name) {
            return Ok(Some(name));
        }
        if !self.allowed[doc].contains(&name.0) {
            let document = self.system_ids[doc].clone().unwrap_or_else(|| "null".into());
            let message = if name.0.is_empty() {
                format!(
                    "src-resolve.4.1: Error resolving component '{value}'. It was detected that '{value}' has no namespace, but components with no target namespace are not referenceable from schema document '{document}'. If '{value}' is intended to have a namespace, perhaps a prefix needs to be provided. If it is intended that '{value}' has no namespace, then an 'import' without a \"namespace\" attribute should be added to '{document}'."
                )
            } else {
                format!(
                    "src-resolve.4.2: Error resolving component '{value}'. It was detected that '{value}' is in namespace '{}', but components from this namespace are not referenceable from schema document '{document}'. If this is the incorrect namespace, perhaps the prefix of '{value}' needs to be changed. If this is the correct namespace, then an appropriate 'import' tag should be added to '{document}'.",
                    name.0
                )
            };
            return Err(self.fail(node, doc, message));
        }
        if !self.grammars.contains(&name.0) {
            if self.reported.contains(&name.0) {
                return Ok(None);
            }
            // Not reported yet: what Xerces reports is the first such reference of its traversal order.
            let first = self.first_unloaded.clone().unwrap_or(Unloaded { place: (doc, node.range().start), value: value.to_string(), what: Self::static_what(what), namespace: name.0.clone() });
            self.reported.first(&first.namespace);
            return Err(self.fail_at(first.place, format!("src-resolve: Cannot resolve the name '{}' to a(n) '{}' component.", first.value, first.what)));
        }
        Ok(Some(name))
    }

    /// A type reference a derivation needs built (a base, an item or member type); `None` when it was dropped.
    fn type_ref(&mut self, node: Node, doc: usize, value: &str) -> Result<Option<TypeId>, String> {
        let Some(id) = self.type_id(node, doc, value)? else { return Ok(None) };
        self.ensure_built(id)?;
        Ok(Some(id))
    }

    /// A type reference of an element or attribute declaration, which only needs the type's id: named types are
    /// built in dependency order of their derivations, not of the declarations in their content.
    fn type_id(&self, node: Node, doc: usize, value: &str) -> Result<Option<TypeId>, String> {
        let Some(name) = self.reference(node, doc, value, "type definition")? else { return Ok(None) };
        match self.schema.global_types.get(&name) {
            Some(id) => Ok(Some(*id)),
            None => Err(self.fail(node, doc, format!("src-resolve: Cannot resolve the name '{value}' to a(n) 'type definition' component."))),
        }
    }

    /// Whether `id` is a complex type, built or not.
    fn is_complex(&self, id: TypeId) -> bool {
        match self.pending_types.get(&id) {
            Some((node, _)) => node.tag_name().name() == "complexType",
            None => matches!(self.schema.types[id], Type::Complex(_)),
        }
    }

    /// Builds a named type the first time it is needed; a type referring to itself while being built sees its id.
    fn ensure_built(&mut self, id: TypeId) -> Result<(), String> {
        if self.building.contains(&id) {
            return Ok(());
        }
        let Some((node, doc)) = self.pending_types.remove(&id) else { return Ok(()) };
        self.type_nodes.insert(id, (doc, node.range().start));
        self.building.insert(id);
        let name = node.attribute("name").map(str::to_string).unwrap_or_else(|| Self::anonymous_name(node));
        let root = self.roots[doc].0;
        let set = |attribute: &str, default: &str| restriction::derivation_set(node.attribute(attribute).or_else(|| root.attribute(default)).unwrap_or_default());
        let by_extension = xs_children(node)
            .find(|c| matches!(c.tag_name().name(), "simpleContent" | "complexContent"))
            .and_then(|c| xs_children(c).next())
            .is_some_and(|d| d.tag_name().name() == "extension");
        let flags = if node.tag_name().name() == "simpleType" {
            // An anonymous simple type has no `final` of its own.
            let final_ = if node.attribute("name").is_some() { set("final", "finalDefault") } else { 0 };
            restriction::TypeFlags { by_extension: false, block: 0, final_ }
        } else {
            restriction::TypeFlags { by_extension, block: set("block", "blockDefault") & (restriction::EXTENSION | restriction::RESTRICTION), final_: set("final", "finalDefault") }
        };
        self.schema.type_flags.insert(id, flags);
        let built = if node.tag_name().name() == "simpleType" {
            Type::Simple(self.simple_type(node, doc, name)?)
        } else {
            Type::Complex(self.complex_type(node, doc, name)?)
        };
        self.schema.types[id] = built;
        self.building.remove(&id);
        Ok(())
    }

    /// The declaration a reference names; `None` when the reference was dropped ([`Builder::reference`]).
    fn component(&self, kind: Kind, node: Node, doc: usize, value: &str, what: &str) -> Result<Option<(Node<'a, 'input>, usize)>, String> {
        let Some(name) = self.reference(node, doc, value, what)? else { return Ok(None) };
        match self.components.get(&(kind, name)) {
            Some(found) => Ok(Some(*found)),
            None => Err(self.fail(node, doc, format!("src-resolve: Cannot resolve the name '{value}' to a(n) '{what}' component."))),
        }
    }

    /// Xerces' `genAnonTypeName`: `#AnonType_` and the `name` of every ancestor below the schema element.
    fn anonymous_name(node: Node) -> String {
        let mut name = String::from("#AnonType_");
        let mut current = node.parent_element();
        while let Some(n) = current {
            if is_xs(&n, "schema") {
                break;
            }
            name.push_str(n.attribute("name").unwrap_or_default());
            current = n.parent_element();
        }
        name
    }

    /// `XSDSimpleTypeTraverser.errorType`, what a simple type whose base, item or member types were all dropped
    /// becomes: a restriction, list or union of `string`, without facets.
    fn error_simple_type(&self, name: String, how: &str) -> SimpleType {
        let string = self.schema.builtin("string");
        let (base, variety) = match how {
            "restriction" => (string, self.schema.simple(string).variety.clone()),
            "list" => (self.schema.builtin("anySimpleType"), Variety::List(string)),
            _ => (self.schema.builtin("anySimpleType"), Variety::Union(vec![string])),
        };
        SimpleType { name, base: Some(base), variety, facets: Facets::default(), dv: None, special: None }
    }

    fn simple_type(&mut self, node: Node<'a, 'input>, doc: usize, name: String) -> Result<SimpleType, String> {
        let Some(def) = xs_children(node).next() else { return Err(self.fail(node, doc, format!("simple type {name} has no restriction, list or union"))) };
        match def.tag_name().name() {
            "restriction" => {
                let base = match def.attribute("base") {
                    Some(b) => match self.type_ref(def, doc, b)? {
                        Some(base) => base,
                        // `XSDSimpleTypeTraverser.errorType`: a restriction of `string`, its facets ignored.
                        None => return Ok(self.error_simple_type(name, "restriction")),
                    },
                    None => {
                        let inline = xs_children(def).find(|c| c.tag_name().name() == "simpleType").ok_or_else(|| self.fail(def, doc, "restriction without a base".into()))?;
                        let st = self.simple_type(inline, doc, Self::anonymous_name(inline))?;
                        self.schema.push_simple(st)
                    }
                };
                if matches!(self.schema.types[base], Type::Complex(_)) {
                    return Err(self.fail(def, doc, format!("src-resolve: Cannot resolve the name '{}' to a(n) 'simpleType definition' component.", def.attribute("base").unwrap_or_default())));
                }
                if let Some(b) = def.attribute("base") && self.final_forbids(def, doc, b, "restriction") {
                    return Err(self.fail(def, doc, format!("st-props-correct.3: Error for type '{name}'. The value of {{final}} of the {{base type definition}}, '{}', forbids derivation by restriction.", self.simple_name(base))));
                }
                let dropped = if self.restricts_notation(def, doc, 0) { self.notation_enumerations(def, doc)? } else { Vec::new() };
                let mut facets = self.facets(def).map_err(|m| self.fail(def, doc, m))?;
                // An enumeration naming a notation of a namespace reported already is ignored.
                if let Some(values) = facets.enumeration.as_mut().filter(|_| !dropped.is_empty()) {
                    values.retain(|v| !dropped.contains(v));
                }
                self.schema.check_restriction(&name, base, &facets, &facet_names(def)).map_err(|m| self.fail(def, doc, m))?;
                let variety = self.schema.simple(base).variety.clone();
                Ok(SimpleType { name, base: Some(base), variety, facets, dv: None, special: None })
            }
            "list" => {
                let item = match def.attribute("itemType") {
                    Some(t) => match self.type_ref(def, doc, t)? {
                        Some(item) => item,
                        None => return Ok(self.error_simple_type(name, "list")),
                    },
                    None => {
                        let inline = xs_children(def).find(|c| c.tag_name().name() == "simpleType").ok_or_else(|| self.fail(def, doc, "list without an item type".into()))?;
                        let st = self.simple_type(inline, doc, Self::anonymous_name(inline))?;
                        self.schema.push_simple(st)
                    }
                };
                if !matches!(self.schema.types[item], Type::Simple(_)) {
                    return Err(self.fail(def, doc, format!("src-resolve: Cannot resolve the name '{}' to a(n) 'simpleType definition' component.", def.attribute("itemType").unwrap_or_default())));
                }
                if let Some(t) = def.attribute("itemType") && self.final_forbids(def, doc, t, "list") {
                    return Err(self.fail(def, doc, format!(
                        "cos-st-restricts.2.3.1.1: The {{final}} component of the {{item type definition}}, '{t}', contains 'list'. This means that '{t}' cannot be used as an item type for list type '{name}'."
                    )));
                }
                if self.contains_list(item) {
                    return Err(self.fail(def, doc, format!(
                        "cos-st-restricts.2.1: In the definition of list type '{name}', type '{}' is an invalid item type because it is either a list type, or a union type that contains a list.",
                        self.simple_name(item)
                    )));
                }
                let base = self.schema.builtin("anySimpleType");
                Ok(SimpleType { name, base: Some(base), variety: Variety::List(item), facets: Facets::default(), dv: None, special: None })
            }
            "union" => {
                // Named members a reference into an unloaded namespace dropped are left out.
                let mut named = Vec::new();
                let written: Vec<&str> = def.attribute("memberTypes").unwrap_or_default().split_whitespace().collect();
                for m in &written {
                    if let Some(id) = self.type_ref(def, doc, m)? {
                        named.push((*m, id));
                    }
                }
                let mut members: Vec<TypeId> = named.iter().map(|(_, id)| *id).collect();
                for inline in xs_children(def).filter(|c| c.tag_name().name() == "simpleType") {
                    let st = self.simple_type(inline, doc, Self::anonymous_name(inline))?;
                    members.push(self.schema.push_simple(st));
                }
                if members.is_empty() && written.is_empty() {
                    return Err(self.fail(def, doc, "src-union-memberTypes-or-simpleTypes: A <union> element must have either a non-empty memberTypes [attribute] or at least one <simpleType> element among its [children].".into()));
                }
                if members.is_empty() {
                    return Ok(self.error_simple_type(name, "union"));
                }
                if let Some(m) = named.iter().find(|(_, m)| !matches!(self.schema.types[*m], Type::Simple(_))) {
                    return Err(self.fail(def, doc, format!("src-resolve: Cannot resolve the name '{}' to a(n) 'simpleType definition' component.", m.0)));
                }
                if let Some((t, _)) = named.iter().find(|(t, _)| self.final_forbids(def, doc, t, "union")) {
                    return Err(self.fail(def, doc, format!(
                        "cos-st-restricts.3.3.1.1: The {{final}} component of the {{member type definitions}}, '{t}', contains 'union'. This means that '{t}' cannot be used as an member type for union type '{name}'."
                    )));
                }
                let base = self.schema.builtin("anySimpleType");
                Ok(SimpleType { name, base: Some(base), variety: Variety::Union(members), facets: Facets::default(), dv: None, special: None })
            }
            other => Err(self.fail(def, doc, format!("s4s-elt-invalid-content: {other} in a simple type"))),
        }
    }

    /// `traverseFacets` for a NOTATION restriction: each enumeration value names a notation declaration. Returns
    /// the values whose reference was dropped ([`Builder::reference`]).
    fn notation_enumerations(&self, def: Node, doc: usize) -> Result<Vec<String>, String> {
        let mut dropped = Vec::new();
        for enumeration in xs_children(def).filter(|c| c.tag_name().name() == "enumeration") {
            let raw = enumeration.attribute("value").unwrap_or_default();
            let value = raw.trim_matches([' ', '\t', '\n', '\r']);
            let (prefix, local) = value.split_once(':').map_or((None, value), |(p, l)| (Some(p), l));
            if !prefix.is_none_or(types::is_ncname) || !types::is_ncname(local) {
                return Err(self.fail(enumeration, doc, format!("cvc-datatype-valid.1.2.1: '{value}' is not a valid value for 'QName'.")));
            }
            if let Some(p) = prefix.filter(|p| namespace_of(enumeration, p).is_none()) {
                return Err(self.fail(enumeration, doc, format!("UndeclaredPrefix: Cannot resolve '{value}' as a QName: the prefix '{p}' is not declared.")));
            }
            let Some(name) = self.reference(enumeration, doc, value, "notation")? else {
                dropped.push(raw.to_string());
                continue;
            };
            if !self.components.contains_key(&(Kind::Notation, name)) {
                return Err(self.fail(enumeration, doc, format!("src-resolve: Cannot resolve the name '{value}' to a(n) 'notation' component.")));
            }
        }
        Ok(dropped)
    }

    fn facets(&self, restriction: Node) -> Result<Facets, String> {
        let mut f = Facets::default();
        let number = |n: &Node| -> Result<usize, String> {
            n.attribute("value").and_then(|v| v.trim().parse().ok()).ok_or_else(|| format!("invalid {} facet", n.tag_name().name()))
        };
        for facet in xs_children(restriction) {
            let value = facet.attribute("value").unwrap_or_default().to_string();
            match facet.tag_name().name() {
                "enumeration" => f.enumeration.get_or_insert_with(Vec::new).push(value),
                "pattern" => {
                    regex_syntax::check(&value).map_err(|e| format!("InvalidRegex: Pattern value '{value}' is not a valid regular expression. The reported error was: '{e}'."))?;
                    f.patterns.push(types::pattern(&value)?)
                }
                "length" => f.length = Some(number(&facet)?),
                "minLength" => f.min_length = Some(number(&facet)?),
                "maxLength" => f.max_length = Some(number(&facet)?),
                "totalDigits" => f.total_digits = Some(number(&facet)?),
                "fractionDigits" => f.fraction_digits = Some(number(&facet)?),
                "minInclusive" => f.min_inclusive = Some(value),
                "maxInclusive" => f.max_inclusive = Some(value),
                "minExclusive" => f.min_exclusive = Some(value),
                "maxExclusive" => f.max_exclusive = Some(value),
                "whiteSpace" => {
                    f.white_space = Some(match value.as_str() {
                        "preserve" => WhiteSpace::Preserve,
                        "replace" => WhiteSpace::Replace,
                        "collapse" => WhiteSpace::Collapse,
                        other => return Err(format!("invalid whiteSpace {other}")),
                    })
                }
                "simpleType" | "attribute" | "attributeGroup" | "anyAttribute" | "sequence" | "choice" | "all" | "group" => {}
                "assertion" | "explicitTimezone" => {}
                other => return Err(format!("s4s-elt-invalid-content: {other} in a restriction")),
            }
        }
        Ok(f)
    }

    fn complex_type(&mut self, node: Node<'a, 'input>, doc: usize, name: String) -> Result<ComplexType, String> {
        let mixed = node.attribute("mixed").is_some_and(|m| m == "true" || m == "1");
        let mut ct = ComplexType { name, base: None, content: Content::Empty, attributes: Vec::new(), attribute_wildcard: None, mixed };
        let mut particle = None;
        for child in xs_children(node) {
            match child.tag_name().name() {
                "simpleContent" => return self.simple_content(child, doc, ct),
                "complexContent" => return self.complex_content(child, doc, ct),
                "sequence" | "choice" | "all" | "group" => particle = self.content_particle(child, doc)?,
                "attribute" | "attributeGroup" | "anyAttribute" => {}
                other => return Err(self.fail(child, doc, format!("s4s-elt-invalid-content: {other} in a complex type"))),
            }
        }
        let owner = ct.name.clone();
        self.own_attributes(node, doc, &mut ct, &owner, false)?;
        ct.content = match particle {
            Some(expr) => Content::Elements(expr),
            None if mixed => Content::Elements(Expr::Empty),
            None => Content::Empty,
        };
        Ok(ct)
    }

    /// `XSDComplexTypeTraverser.handleComplexTypeError`, what a complex type whose base was dropped becomes: derived
    /// from `anyType`, mixed, any elements and any attributes, all skipped.
    fn error_complex_type(&self, mut ct: ComplexType) -> ComplexType {
        let skip = || Wildcard { namespaces: None, negated: false, process: Process::Skip };
        ct.base = Some(self.schema.any_type);
        ct.mixed = true;
        ct.content = Content::Elements(Expr::Sequence(vec![Expr::Repeat(Box::new(Expr::Any(Box::new(skip()))), 0, None)]));
        ct.attribute_wildcard = Some(skip());
        ct
    }

    /// The particle of a complex type's content: none for a sequence or all without particles, or such a choice
    /// with `minOccurs="0"` (the content is then empty, or mixed with an empty particle).
    fn content_particle(&mut self, node: Node<'a, 'input>, doc: usize) -> Result<Option<Expr>, String> {
        let name = node.tag_name().name();
        let particle = self.particle(node, doc)?;
        let explicitly_empty = name != "group" && !xs_children(node).any(|_| true) && (name != "choice" || Self::occurs(node).map_err(|m| self.fail(node, doc, m))?.0 == 0);
        // A group reference that was dropped gives no particle (`XSDGroupTraverser.traverseLocal` returns none).
        let dropped = name == "group" && match node.attribute("ref") {
            Some(reference) => self.component(Kind::Group, node, doc, reference, "group")?.is_none(),
            None => false,
        };
        Ok(if explicitly_empty || dropped { None } else { Some(particle) })
    }

    /// `XSDComplexTypeTraverser.traverseSimpleContent`.
    fn simple_content(&mut self, node: Node<'a, 'input>, doc: usize, mut ct: ComplexType) -> Result<ComplexType, String> {
        let def = xs_children(node).next().ok_or_else(|| self.fail(node, doc, "empty simpleContent".into()))?;
        let how = def.tag_name().name();
        let restriction = how == "restriction";
        let base_name = def.attribute("base").ok_or_else(|| self.fail(def, doc, "simpleContent without a base".into()))?;
        let Some(base) = self.type_ref(def, doc, base_name)? else { return Ok(self.error_complex_type(ct)) };
        let not_simple = |builder: &Self, base_label: String| {
            builder.fail(def, doc, format!(
                "src-ct.2.1: Complex Type Definition Representation Error for type '{}'.  When <simpleContent> is used, the base type must be a complexType whose content type is simple, or, only if restriction is specified, a complex type with mixed content and emptiable particle, or, only if extension is specified, a simple type. '{base_label}' satisfies none of these conditions.",
                ct.name
            ))
        };
        // The base's simple content type (`None`: a mixed, emptiable complex type being restricted).
        let (base_simple, base_attributes, base_wildcard) = match &self.schema.types[base] {
            Type::Simple(_) if restriction => return Err(not_simple(self, self.type_label(base))),
            Type::Simple(_) => (Some(base), Vec::new(), None),
            Type::Complex(c) => match &c.content {
                Content::Simple(s) => (Some(*s), c.attributes.clone(), c.attribute_wildcard.clone()),
                Content::Any if restriction => (None, c.attributes.clone(), c.attribute_wildcard.clone()),
                Content::Elements(e) if restriction && c.mixed && self.schema.nullable(e) => (None, c.attributes.clone(), c.attribute_wildcard.clone()),
                _ => return Err(not_simple(self, self.type_label(base))),
            },
        };
        if self.final_forbids(def, doc, base_name, how) {
            return Err(self.fail(def, doc, self.final_message(&ct.name, base, how)));
        }
        let children: Vec<Node<'a, 'input>> = xs_children(def).collect();
        let owner = ct.name.clone();
        let simple = if restriction {
            let inline = children.first().copied().filter(|c| c.tag_name().name() == "simpleType");
            let mut validator = base_simple;
            if let Some(inline) = inline {
                let st = self.simple_type(inline, doc, Self::anonymous_name(inline))?;
                let id = self.schema.push_simple(st);
                if let Some(base_simple) = base_simple {
                    let final_ = self.schema.type_flags.get(&base_simple).map_or(0, |f| f.final_);
                    if !self.schema.simple_derivation_ok(id, base_simple, final_, 0) {
                        return Err(self.fail(inline, doc, format!(
                            "derivation-ok-restriction.5.2.2.1: Error for type '{}'.  The simple content type of this type, '{}', is not a valid restriction of the simple content type of the base, '{}'.",
                            ct.name,
                            self.type_label(id),
                            self.type_label(base_simple)
                        )));
                    }
                }
                validator = Some(id);
            }
            // Where the traverser stands after the simple type: the first facet, attribute or nothing.
            let after = children.get(usize::from(inline.is_some())).map(|c| (doc, c.range().start));
            let at = |builder: &Self, message: String| match after {
                Some(place) => builder.fail_at(place, message),
                None => message,
            };
            let Some(validator) = validator else {
                return Err(at(self, format!(
                    "src-ct.2.2: Complex Type Definition Representation Error for type '{}'.  When a complexType with simpleContent restricts a complexType with mixed content and emptiable particle, then there must be a <simpleType> among the children of <restriction>.",
                    ct.name
                )));
            };
            let facets = self.facets(def).map_err(|m| at(self, m))?;
            self.schema.check_restriction(&ct.name, validator, &facets, &facet_names(def)).map_err(|m| at(self, m))?;
            let variety = self.schema.simple(validator).variety.clone();
            let st = SimpleType { name: Self::anonymous_name(def), base: Some(validator), variety, facets, dv: None, special: None };
            let simple = self.schema.push_simple(st);
            // The uses given here, checked against the base's, then replacing them; the wildcard is only the one
            // given here.
            let Type::Complex(base_type) = &self.schema.types[base] else { unreachable!("a restriction's base is complex") };
            let base_type = base_type.clone();
            self.own_attributes_extending(def, doc, &mut ct, &owner, false, None)?;
            let attribute_node = children.iter().find(|c| matches!(c.tag_name().name(), "attribute" | "attributeGroup" | "anyAttribute")).map(|c| (doc, c.range().start));
            self.check_attribute_restriction(&ct, &base_type, attribute_node)?;
            let mut attributes = base_attributes;
            for own in std::mem::take(&mut ct.attributes) {
                attributes.retain(|a| a.name != own.name);
                attributes.push(own);
            }
            ct.attributes = attributes;
            drop(base_wildcard);
            simple
        } else {
            ct.attributes = base_attributes;
            ct.attribute_wildcard = base_wildcard;
            self.own_attributes_extending(def, doc, &mut ct, &owner, false, Some(Some((doc, node.range().start))))?;
            base_simple.expect("an extension's base has a simple content type")
        };
        ct.base = Some(base);
        ct.content = Content::Simple(simple);
        Ok(ct)
    }

    /// `cos-ct-extends.1.1` or `derivation-ok-restriction.1`: type `name` derives by `how` from `base`, whose
    /// `final` forbids it.
    fn final_message(&self, name: &str, base: TypeId, how: &str) -> String {
        let base = self.type_label(base);
        if how == "extension" {
            format!("cos-ct-extends.1.1: Type '{name}' was derived by extension from type '{base}'.  However, the 'final' attribute of '{base}' forbids derivation by extension.")
        } else {
            format!("derivation-ok-restriction.1: Type '{name}' was derived by restriction from type '{base}'.  However, '{base}' has a {{final}} property that forbids derivation by restriction.")
        }
    }

    /// A type's `getName()` as messages print it: `null` for an anonymous type.
    fn type_label(&self, id: TypeId) -> String {
        let name = self.simple_name(id);
        if name.is_empty() || name.starts_with("#AnonType_") { "null".into() } else { name }
    }

    /// `XSDComplexTypeTraverser.traverseComplexContent`.
    fn complex_content(&mut self, node: Node<'a, 'input>, doc: usize, mut ct: ComplexType) -> Result<ComplexType, String> {
        let def = xs_children(node).next().ok_or_else(|| self.fail(node, doc, "empty complexContent".into()))?;
        if let Some(m) = node.attribute("mixed") {
            ct.mixed = m == "true" || m == "1";
        }
        let how = def.tag_name().name();
        let extension = how == "extension";
        let base_name = def.attribute("base").ok_or_else(|| self.fail(def, doc, "complexContent without a base".into()))?;
        let Some(base) = self.type_ref(def, doc, base_name)? else { return Ok(self.error_complex_type(ct)) };
        let base_type = match &self.schema.types[base] {
            Type::Complex(c) => c.clone(),
            Type::Simple(_) => {
                return Err(self.fail(def, doc, format!(
                    "src-ct.1: Complex Type Definition Representation Error for type '{}'.  When <complexContent> is used, the base type must be a complexType. '{}' is a simpleType.",
                    ct.name,
                    self.type_label(base)
                )));
            }
        };
        if self.final_forbids(def, doc, base_name, how) {
            return Err(self.fail(def, doc, self.final_message(&ct.name, base, how)));
        }
        // Where the traverser stands for the checks after the content: the derivation's first child, if any.
        let first = xs_children(def).next();
        let at = |builder: &Self, message: String| match first {
            Some(f) => builder.fail(f, doc, message),
            None => message,
        };
        let particle_node = first.filter(|c| matches!(c.tag_name().name(), "sequence" | "choice" | "all" | "group"));
        let own = match particle_node {
            Some(p) => self.content_particle(p, doc)?,
            None => None,
        };
        // Content types: Xerces' EMPTY, SIMPLE, ELEMENT and MIXED.
        let derived_mixed = ct.mixed;
        let base_kind = match &base_type.content {
            Content::Empty => "empty",
            Content::Simple(_) => "simple",
            Content::Any => "mixed",
            Content::Elements(_) if base_type.mixed => "mixed",
            Content::Elements(_) => "element",
        };
        let derived_kind = match (&own, derived_mixed) {
            (_, true) => "mixed",
            (Some(_), false) => "element",
            (None, false) => "empty",
        };
        if !extension && derived_kind == "mixed" && base_kind != "mixed" {
            return Err(at(self, format!(
                "derivation-ok-restriction.5.4.1.2: Error for type '{}'.  The content type of this type is mixed, but the content type of the base, '{}', is not.",
                ct.name, base_type.name
            )));
        }
        if extension && own.is_some() && base_kind != "empty" {
            if derived_kind == "element" && base_kind != "element" {
                return Err(at(self, format!(
                    "cos-ct-extends.1.4.3.2.2.1.a: The content type of a derived type and that of its base must both be mixed or both be element-only. Type '{}' is element only, but its base type is not.",
                    ct.name
                )));
            }
            if derived_kind == "mixed" && base_kind != "mixed" {
                return Err(at(self, format!(
                    "cos-ct-extends.1.4.3.2.2.1.b: The content type of a derived type and that of its base must both be mixed or both be element-only. Type '{}' is mixed, but its base type is not.",
                    ct.name
                )));
            }
            let is_all = |e: &Expr| matches!(e, Expr::All(_));
            let base_all = matches!(&base_type.content, Content::Elements(e) if is_all(e));
            if own.as_ref().is_some_and(is_all) || base_all {
                return Err(at(self, "cos-all-limited.1.2: An 'all' model group must appear in a particle with {min occurs} = {max occurs} = 1, and that particle must be part of a pair which constitutes the {content type} of a complex type definition.".into()));
            }
        }
        if extension {
            ct.attributes = base_type.attributes.clone();
            ct.attribute_wildcard = base_type.attribute_wildcard.clone();
            ct.mixed |= base_type.mixed && own.is_none();
        }
        let owner = ct.name.clone();
        let merge_at = first.map(|f| (doc, f.range().start));
        self.own_attributes_extending(def, doc, &mut ct, &owner, false, if extension { Some(merge_at) } else { None })?;
        ct.base = Some(base);
        if !extension {
            if base != self.schema.any_type {
                self.check_attribute_restriction(&ct, &base_type, merge_at)?;
            }
            // Restriction: the base's attributes, overridden or prohibited by the ones given here.
            let mut attributes = base_type.attributes.clone();
            for own in std::mem::take(&mut ct.attributes) {
                attributes.retain(|a| a.name != own.name);
                attributes.push(own);
            }
            ct.attributes = attributes;
        }
        ct.content = match (extension, &base_type.content, own) {
            (true, Content::Elements(base_expr), Some(own)) => Content::Elements(Expr::Sequence(vec![base_expr.clone(), own])),
            (true, base_content, None) => base_content.clone(),
            (true, Content::Empty, Some(own)) => Content::Elements(own),
            // anyType's particle (any element, laxly, any number of times) followed by the extension's.
            (true, Content::Any, Some(own)) => {
                let any = Wildcard { namespaces: None, negated: false, process: Process::Lax };
                Content::Elements(Expr::Sequence(vec![Expr::Repeat(Box::new(Expr::Any(Box::new(any))), 0, None), own]))
            }
            (true, Content::Simple(_), Some(_)) => unreachable!("refused above: a simple content base is not element-only"),
            (false, _, Some(own)) => Content::Elements(own),
            (false, _, None) if ct.mixed => Content::Elements(Expr::Empty),
            (false, _, None) => Content::Empty,
        };
        Ok(ct)
    }

    /// Records a `default` or `fixed` value whose prefix (were it a QName) is not declared at `node`.
    fn note_value_prefix(&mut self, node: Node, doc: usize) {
        let Some(value) = node.attribute("fixed").or(node.attribute("default")) else { return };
        if let Some((prefix, _)) = value.trim().split_once(':') && namespace_of(node, prefix).is_none() {
            self.unbound_values.insert((doc, node.range().start));
        }
    }

    /// Whether the named type `base` (referenced at `node`) forbids derivation `how` by its `final` (or its
    /// schema's `finalDefault`).
    fn final_forbids(&self, node: Node, doc: usize, base: &str, how: &str) -> bool {
        let Ok(name) = self.resolve(node, doc, base) else { return false };
        let Some(&(decl, decl_doc)) = self.components.get(&(Kind::Type, name)) else { return false };
        let value = decl.attribute("final").or_else(|| self.roots[decl_doc].0.attribute("finalDefault")).unwrap_or_default();
        value.split_whitespace().any(|w| w == "#all" || w == how)
    }

    fn simple_name(&self, id: TypeId) -> String {
        match &self.schema.types[id] {
            Type::Simple(s) => s.name.clone(),
            Type::Complex(c) => c.name.clone(),
        }
    }

    /// A list type, or a union with one among its members.
    fn contains_list(&self, id: TypeId) -> bool {
        match &self.schema.types[id] {
            Type::Simple(s) => match &s.variety {
                Variety::List(_) => true,
                Variety::Union(members) => members.iter().any(|m| self.contains_list(*m)),
                Variety::Atomic => false,
            },
            Type::Complex(_) => false,
        }
    }

    /// [`Builder::attributes_of`] for a type or attribute group `owner`: the uses it declares itself (after
    /// `ct`'s inherited ones) must have distinct names (`ct-props-correct.4`, `ag-props-correct.2`); they replace
    /// the inherited ones of the same name.
    fn own_attributes(&mut self, node: Node<'a, 'input>, doc: usize, ct: &mut ComplexType, owner: &str, group: bool) -> Result<(), String> {
        self.own_attributes_extending(node, doc, ct, owner, group, None)
    }

    /// [`Builder::own_attributes`]; with `extension` (the element `mergeAttributes` reports at), an own use named
    /// like an inherited one is a duplicate too.
    fn own_attributes_extending(&mut self, node: Node<'a, 'input>, doc: usize, ct: &mut ComplexType, owner: &str, group: bool, extension: Option<Option<(usize, usize)>>) -> Result<(), String> {
        let start = ct.attributes.len();
        let mut via = Vec::new();
        self.attributes_via(node, doc, ct, &mut via, None)?;
        let duplicate = |name: &str| {
            if group {
                format!("ag-props-correct.2: Error for attribute group '{owner}'.  Duplicate attribute uses with the same name and target namespace are specified.  Name of duplicate attribute use is '{name}'.")
            } else {
                format!("ct-props-correct.4: Error for type '{owner}'. Duplicate attribute uses with the same name and target namespace are specified.  Name of duplicate attribute use is '{name}'.")
            }
        };
        // `traverseAttrsAndAttrGrps`: a duplicate among the uses given here, at the child it came through.
        let mut own: Vec<AttributeUse> = Vec::new();
        for (attribute, place) in ct.attributes.drain(start..).collect::<Vec<_>>().into_iter().zip(via) {
            match own.iter().find(|a| a.name == attribute.name) {
                Some(seen) if seen.source == attribute.source => {}
                Some(_) if attribute.prohibited => {}
                Some(seen) if seen.prohibited => {
                    let i = own.iter().position(|a| a.name == attribute.name).expect("found");
                    own[i] = attribute;
                }
                Some(_) => return Err(self.fail_at(place, duplicate(&attribute.name.1))),
                None => own.push(attribute),
            }
        }
        // `mergeAttributes` of an extension: an inherited use named like one given here.
        if let Some(at) = extension && let Some(clash) = ct.attributes[..start].iter().find(|i| own.iter().any(|o| o.name == i.name && o.source != i.source && !o.prohibited)) {
            let message = duplicate(&clash.name.1);
            return Err(match at {
                Some(place) => self.fail_at(place, message),
                None => message,
            });
        }
        ct.attributes.retain(|a| !own.iter().any(|o| o.name == a.name));
        ct.attributes.extend(own);
        Ok(())
    }

    /// The attribute uses and wildcard declared directly under `node` (and through its attribute groups).
    fn attributes_of(&mut self, node: Node<'a, 'input>, doc: usize, ct: &mut ComplexType) -> Result<(), String> {
        self.attributes_via(node, doc, ct, &mut Vec::new(), None)
    }

    /// [`Builder::attributes_of`], noting for each use the child of `node` it came through (`top`, inside a group).
    fn attributes_via(&mut self, node: Node<'a, 'input>, doc: usize, ct: &mut ComplexType, via: &mut Vec<(usize, usize)>, top: Option<(usize, usize)>) -> Result<(), String> {
        for child in xs_children(node) {
            let place = top.unwrap_or((doc, child.range().start));
            match child.tag_name().name() {
                "attribute" => {
                    if let Some(attribute) = self.attribute(child, doc, false)? {
                        ct.attributes.push(attribute);
                        via.push(place);
                    }
                }
                "attributeGroup" => {
                    let reference = child.attribute("ref").ok_or_else(|| self.fail(child, doc, "attributeGroup without ref".into()))?;
                    if let Some((group, group_doc)) = self.component(Kind::AttributeGroup, child, doc, reference, "attribute group")? {
                        self.attributes_via(group, group_doc, ct, via, Some(place))?;
                    }
                }
                "anyAttribute" => ct.attribute_wildcard = Some(self.wildcard(child, doc)),
                _ => {}
            }
        }
        Ok(())
    }

    /// An attribute declaration or use; `None` for a reference that was dropped ([`Builder::reference`]).
    fn attribute(&mut self, node: Node<'a, 'input>, doc: usize, global: bool) -> Result<Option<AttributeUse>, String> {
        let use_ = node.attribute("use").unwrap_or("optional");
        if let Some(reference) = node.attribute("ref") {
            let Some((decl_node, decl_doc)) = self.component(Kind::Attribute, node, doc, reference, "attribute declaration")? else { return Ok(None) };
            let name = self.resolve(node, doc, reference)?;
            let mut attribute = match self.schema.global_attributes.get(&name) {
                Some(a) => a.clone(),
                None => self.attribute(decl_node, decl_doc, true)?.expect("a declaration is no reference"),
            };
            attribute.required = use_ == "required";
            attribute.prohibited = use_ == "prohibited";
            if let Some(fixed) = node.attribute("fixed") {
                attribute.fixed = Some(fixed.to_string());
            }
            if let Some(default) = node.attribute("default") {
                attribute.default = Some(default.to_string());
            }
            attribute.source = (doc, node.range().start);
            self.note_value_prefix(node, doc);
            return Ok(Some(attribute));
        }
        let local = node.attribute("name").ok_or("s4s-att-must-appear: an attribute needs a name or ref")?;
        let (_, tns, _, qualified_default) = &self.roots[doc];
        let qualified = global || node.attribute("form").map(|f| f == "qualified").unwrap_or(*qualified_default);
        let namespace = if qualified { tns.clone() } else { String::new() };
        let ty = match node.attribute("type") {
            Some(t) => {
                // A dropped type is refused here, every time (`XSDAttributeTraverser.traverseNamedAttr`).
                match self.type_id(node, doc, t)? {
                    Some(id) if !self.is_complex(id) => id,
                    _ => return Err(self.fail(node, doc, format!("src-resolve: Cannot resolve the name '{t}' to a(n) 'simpleType definition' component."))),
                }
            }
            None => match xs_children(node).find(|c| c.tag_name().name() == "simpleType") {
                Some(inline) => {
                    let st = self.simple_type(inline, doc, Self::anonymous_name(inline))?;
                    self.schema.push_simple(st)
                }
                None => self.schema.builtin("anySimpleType"),
            },
        };
        self.note_value_prefix(node, doc);
        Ok(Some(AttributeUse {
            name: (namespace, local.to_string()),
            ty,
            required: use_ == "required",
            prohibited: use_ == "prohibited",
            fixed: node.attribute("fixed").map(str::to_string),
            default: node.attribute("default").map(str::to_string),
            source: (doc, node.range().start),
        }))
    }

    fn wildcard(&self, node: Node, doc: usize) -> Wildcard {
        let process = match node.attribute("processContents") {
            Some("lax") => Process::Lax,
            Some("skip") => Process::Skip,
            _ => Process::Strict,
        };
        let tns = self.roots[doc].1.clone();
        let (namespaces, negated) = match node.attribute("namespace").unwrap_or("##any").trim() {
            "##any" => (None, false),
            "##other" => (Some(vec![tns, String::new()]), true),
            list => (
                Some(
                    list.split_whitespace()
                        .map(|n| match n {
                            "##targetNamespace" => tns.clone(),
                            "##local" => String::new(),
                            other => other.to_string(),
                        })
                        .collect(),
                ),
                false,
            ),
        };
        Wildcard { namespaces, negated, process }
    }

    /// `minOccurs` and `maxOccurs` as `XSAttributeChecker` checks them.
    fn occurs(node: Node) -> Result<(u32, Option<u32>), String> {
        let name = node.tag_name().name();
        let invalid = |attribute: &str, reason: String| format!("s4s-att-invalid-value: Invalid attribute value for '{attribute}' in element '{name}'. Recorded reason: {reason}");
        let min = match node.attribute("minOccurs") {
            Some(v) => v.trim().parse::<u32>().map_err(|_| invalid("minOccurs", format!("cvc-datatype-valid.1.2.1: '{v}' is not a valid value for 'nonNegativeInteger'.")))?,
            None => 1,
        };
        let max = match node.attribute("maxOccurs").map(str::trim) {
            Some("unbounded") => None,
            Some(v) => Some(v.parse::<u32>().map_err(|_| invalid("maxOccurs", format!("cvc-datatype-valid.1.2.1: '{v}' is not a valid value for 'nonNegativeInteger'.")))?),
            None => Some(1),
        };
        if let Some(max) = max {
            // FEATURE_SECURE_PROCESSING's maxOccurLimit, except for an element or wildcard that is a sequence's only
            // child node (Xerces validates that one in constant space).
            let alone = matches!(name, "element" | "any")
                && node.prev_sibling().is_none()
                && node.next_sibling().is_none()
                && node.parent_element().is_some_and(|p| p.tag_name().name() == "sequence");
            if max > 5000 && !alone {
                return Err("Current configuration of the parser doesn't allow the expansion of a content model for a complex type to contain more than 5,000 nodes.".into());
            }
            if min > max {
                return Err(format!("p-props-correct.2.1: In the declaration of '{name}', the value of 'minOccurs' is '{min}', but it must not be greater than the value of 'maxOccurs', which is '{max}'."));
            }
        }
        Ok((min, max))
    }

    fn repeat(expr: Expr, (min, max): (u32, Option<u32>)) -> Expr {
        match (min, max) {
            (1, Some(1)) => expr,
            (_, Some(0)) => Expr::Empty,
            _ => Expr::Repeat(Box::new(expr), min, max),
        }
    }

    fn particle(&mut self, node: Node<'a, 'input>, doc: usize) -> Result<Expr, String> {
        let occurs = Self::occurs(node).map_err(|m| self.fail(node, doc, m))?;
        let term = match node.tag_name().name() {
            // A dropped reference is `PARTICLE_EMPTY`.
            "element" => match self.local_element(node, doc)? {
                Some(id) => Expr::Element(id),
                None => return Ok(Expr::Empty),
            },
            "any" => Expr::Any(Box::new(self.wildcard(node, doc))),
            "sequence" | "choice" => {
                let mut items = Vec::new();
                self.nested += 1;
                for child in xs_children(node) {
                    items.push(self.particle(child, doc)?);
                }
                self.nested -= 1;
                if node.tag_name().name() == "sequence" { Expr::Sequence(items) } else { Expr::Choice(items) }
            }
            "all" => {
                let mut members = Vec::new();
                for child in xs_children(node) {
                    if child.tag_name().name() != "element" {
                        return Err(self.fail(child, doc, "cos-all-limited: xs:all may only contain elements".into()));
                    }
                    let (min, _) = Self::occurs(child).map_err(|m| self.fail(child, doc, m))?;
                    if let Some(id) = self.local_element(child, doc)? {
                        members.push((id, min > 0));
                    }
                }
                Expr::All(members)
            }
            "group" => {
                let reference = node.attribute("ref").ok_or_else(|| self.fail(node, doc, "group without ref".into()))?;
                let Some((group, group_doc)) = self.component(Kind::Group, node, doc, reference, "group")? else { return Ok(Expr::Empty) };
                let model = xs_children(group).next().ok_or_else(|| self.fail(group, group_doc, "empty group".into()))?;
                if model.tag_name().name() == "all" && (self.nested > 0 || occurs != (1, Some(1))) {
                    return Err(self.fail(node, doc, "cos-all-limited.1.2: An 'all' model group must appear in a particle with '{'min occurs'}' = '{'max occurs'}' = 1, and that particle must be part of a pair which constitutes the '{'content type'}' of a complex type definition.".into()));
                }
                // The group's own model group, with the referencing particle's occurrence.
                self.particle(model, group_doc)?
            }
            other => return Err(self.fail(node, doc, format!("s4s-elt-invalid-content: {other} as a particle"))),
        };
        Ok(Self::repeat(term, occurs))
    }

    /// A local element declaration or reference; `None` for a reference that was dropped ([`Builder::reference`]).
    fn local_element(&mut self, node: Node<'a, 'input>, doc: usize) -> Result<Option<ElemId>, String> {
        if let Some(reference) = node.attribute("ref") {
            let Some(name) = self.reference(node, doc, reference, "element declaration")? else { return Ok(None) };
            return match self.schema.globals.get(&name) {
                Some(id) => Ok(Some(*id)),
                None => Err(self.fail(node, doc, format!("src-resolve: Cannot resolve the name '{reference}' to a(n) 'element declaration' component."))),
            };
        }
        let local = node.attribute("name").ok_or("s4s-att-must-appear: a local element needs a name or ref")?;
        let (_, tns, qualified_default, _) = &self.roots[doc];
        let qualified = node.attribute("form").map(|f| f == "qualified").unwrap_or(*qualified_default);
        let name = (if qualified { tns.clone() } else { String::new() }, local.to_string());
        let decl = self.element_decl(node, doc, name)?;
        self.schema.elements.push(decl);
        Ok(Some(self.schema.elements.len() - 1))
    }

    fn element_decl(&mut self, node: Node<'a, 'input>, doc: usize, name: QName) -> Result<ElementDecl, String> {
        let ty = match node.attribute("type") {
            // A dropped type: the substitution group head's, else `anyType`.
            Some(t) => match self.type_id(node, doc, t)? {
                Some(id) => id,
                None => {
                    self.unresolved_types.insert((doc, node.range().start));
                    self.schema.any_type
                }
            },
            None => match xs_children(node).find(|c| matches!(c.tag_name().name(), "simpleType" | "complexType")) {
                Some(inline) if inline.tag_name().name() == "simpleType" => {
                    let st = self.simple_type(inline, doc, Self::anonymous_name(inline))?;
                    self.schema.push_simple(st)
                }
                // Built after the declarations, like a named type: its derivation may extend a type whose content
                // declares this element (mutually recursive types).
                Some(inline) => {
                    let id = self.schema.push_simple(SimpleType { name: String::new(), base: None, variety: Variety::Atomic, facets: Facets::default(), dv: None, special: None });
                    self.pending_types.insert(id, (inline, doc));
                    id
                }
                None => self.schema.any_type,
            },
        };
        self.note_value_prefix(node, doc);
        let mut constraints = Vec::new();
        for child in xs_children(node).filter(|c| matches!(c.tag_name().name(), "unique" | "key" | "keyref")) {
            constraints.push(self.identity_constraint(child, doc, &name.1)?);
        }
        let root = self.roots[doc].0;
        Ok(ElementDecl {
            name,
            ty,
            nillable: node.attribute("nillable").is_some_and(|n| n == "true" || n == "1"),
            fixed: node.attribute("fixed").map(str::to_string),
            default: node.attribute("default").map(str::to_string),
            constraints,
            block: restriction::derivation_set(node.attribute("block").or_else(|| root.attribute("blockDefault")).unwrap_or_default())
                & (restriction::EXTENSION | restriction::RESTRICTION | restriction::SUBSTITUTION),
            final_: restriction::derivation_set(node.attribute("final").or_else(|| root.attribute("finalDefault")).unwrap_or_default())
                & (restriction::EXTENSION | restriction::RESTRICTION),
            source: (doc, node.range().start),
        })
    }

    /// An `xs:unique`, `xs:key` or `xs:keyref` of element `element` (`XSDKeyrefTraverser` and friends).
    fn identity_constraint(&mut self, node: Node<'a, 'input>, doc: usize, element: &str) -> Result<identity::IcId, String> {
        use identity::{Category, Field, IdentityConstraint};
        if let Some(id) = self.constraint_nodes.get(&(doc, node.range().start)) {
            return Ok(*id);
        }
        let category = match node.tag_name().name() {
            "unique" => Category::Unique,
            "key" => Category::Key,
            _ => Category::KeyRef,
        };
        let name = node.attribute("name").ok_or_else(|| self.fail(node, doc, format!("s4s-att-must-appear: Attribute 'name' must appear in element '{}'.", node.tag_name().name())))?;
        let children: Vec<Node> = xs_children(node).collect();
        let shape_error = || "s4s-elt-must-match.2: The content of 'identity constraint' must match (annotation?, selector, field+). Not enough elements were found.".to_string();
        let Some(selector) = children.first().filter(|c| c.tag_name().name() == "selector") else { return Err(self.fail(node, doc, shape_error())) };
        let fields: Vec<Node> = children[1..].to_vec();
        if fields.is_empty() {
            return Err(self.fail(*selector, doc, shape_error()));
        }
        if let Some(other) = fields.iter().find(|f| f.tag_name().name() != "field") {
            return Err(self.fail(*other, doc, format!(
                "s4s-elt-must-match.1: The content of 'identity constraint' must match (annotation?, selector, field+). A problem was found starting at: {}.",
                other.tag_name().name()
            )));
        }
        fn xpath<'n>(n: &Node<'n, '_>) -> Result<&'n str, String> {
            n.attribute("xpath").ok_or_else(|| format!("s4s-att-must-appear: Attribute 'xpath' must appear in element '{}'.", n.tag_name().name()))
        }
        let selector_paths = identity::parse(xpath(selector).map_err(|m| self.fail(*selector, doc, m))?, *selector, false).map_err(|m| self.fail(*selector, doc, m))?;
        let mut field_list = Vec::new();
        for field in &fields {
            let text = xpath(field).map_err(|m| self.fail(*field, doc, m))?;
            field_list.push(Field { text: identity::fixup(text), paths: identity::parse(text, *field, true).map_err(|m| self.fail(*field, doc, m))? });
        }
        let tns = self.roots[doc].1.clone();
        let id = self.schema.constraints.len();
        if self.constraint_names.insert((tns.clone(), name.to_string()), id).is_some() {
            return Err(self.fail(node, doc, format!("sch-props-correct.2: A schema cannot contain two global components with the same name; this schema contains two occurrences of '{tns},{name}'.")));
        }
        self.constraint_nodes.insert((doc, node.range().start), id);
        self.schema.constraints.push(IdentityConstraint {
            name: name.to_string(),
            category,
            refer: None,
            element: element.to_string(),
            selector: selector_paths,
            fields: field_list,
            identity_hash: (rand_core::RngCore::next_u32(&mut rand_core::OsRng) >> 1).max(1),
        });
        if category == Category::KeyRef {
            let refer = node.attribute("refer").ok_or_else(|| self.fail(node, doc, "s4s-att-must-appear: Attribute 'refer' must appear in element 'keyref'.".into()))?;
            self.refers.push((id, node, doc, refer.to_string()));
        }
        Ok(id)
    }

    fn resolve_refers(&mut self) -> Result<(), String> {
        for (id, node, doc, refer) in std::mem::take(&mut self.refers) {
            let Some(name) = self.reference(node, doc, &refer, "identity constraint")? else {
                // A dropped `refer`: the keyref is not added (`XSDKeyrefTraverser.traverse`).
                for element in &mut self.schema.elements {
                    element.constraints.retain(|c| *c != id);
                }
                continue;
            };
            // `getGlobalDecl` finds no constraint of that name; `XSDKeyrefTraverser` refuses one that is a keyref.
            let Some(&target) = self.constraint_names.get(&name) else {
                return Err(self.fail(node, doc, format!("src-resolve: Cannot resolve the name '{refer}' to a(n) 'identity constraint' component.")));
            };
            if self.schema.constraints[target].category == identity::Category::KeyRef {
                return Err(self.fail(node, doc, format!("src-resolve: Cannot resolve the name '{refer}' to a(n) 'identity constraint key/unique' component.")));
            }
            let (keyref, key) = (&self.schema.constraints[id], &self.schema.constraints[target]);
            if keyref.fields.len() != key.fields.len() {
                return Err(self.fail(node, doc, format!("c-props-correct.2: Cardinality of Fields for keyref '{}' and key '{}' must match each other.", keyref.name, key.name)));
            }
            self.schema.constraints[id].refer = Some(target);
        }
        Ok(())
    }
}

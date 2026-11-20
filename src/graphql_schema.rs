//! GraphQL schemas and documents for `GraphQLExpectationGenerator` (`PUT /mockserver/graphql`) and
//! `GraphQLResponseSynthesizer` (a GraphQL body's `schema` filling an unset response body).
//!
//! The parser reads any GraphQL document (executable and type-system definitions) as graphql-java's ANTLR grammar
//! does, with its error wording: an optional `{ … }` block of a type definition that does not parse is tried as a
//! following anonymous operation instead (ANTLR's adaptive prediction), and when both fail the error is at the
//! token the furthest attempt reached. Schemas come from SDL or an introspection JSON result.

use serde_json::{Map, Value};

use crate::recorded::Failure;

#[derive(Debug, Clone, PartialEq)]
enum Tk {
    Punct,
    Name,
    Number,
    Str,
    Eof,
}

#[derive(Debug, Clone)]
struct Token {
    kind: Tk,
    text: String,
    line: usize,
    col: usize,
}

/// Moves past `chars[*i]`, keeping the line and column (1-based, in characters) of the next one.
fn step(chars: &[char], i: &mut usize, line: &mut usize, col: &mut usize) {
    if chars[*i] == '\n' {
        *line += 1;
        *col = 1;
    } else {
        *col += 1;
    }
    *i += 1;
}

fn lex(src: &str) -> Vec<Token> {
    let chars: Vec<char> = src.chars().collect();
    let mut tokens = Vec::new();
    let (mut i, mut line, mut col) = (0usize, 1usize, 1usize);
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() || c == ',' || c == '\u{feff}' {
            step(&chars, &mut i, &mut line, &mut col);
            continue;
        }
        if c == '#' {
            while i < chars.len() && chars[i] != '\n' && chars[i] != '\r' {
                step(&chars, &mut i, &mut line, &mut col);
            }
            continue;
        }
        let (start_line, start_col, start) = (line, col, i);
        let kind = if c == '.' && chars.get(i + 1) == Some(&'.') && chars.get(i + 2) == Some(&'.') {
            for _ in 0..3 {
                step(&chars, &mut i, &mut line, &mut col);
            }
            Tk::Punct
        } else if c == '"' {
            if chars.get(i + 1) == Some(&'"') && chars.get(i + 2) == Some(&'"') {
                for _ in 0..3 {
                    step(&chars, &mut i, &mut line, &mut col);
                }
                while i < chars.len() && !(chars[i] == '"' && chars.get(i + 1) == Some(&'"') && chars.get(i + 2) == Some(&'"')) {
                    if chars[i] == '\\' && chars.get(i + 1) == Some(&'"') {
                        step(&chars, &mut i, &mut line, &mut col);
                    }
                    step(&chars, &mut i, &mut line, &mut col);
                }
                for _ in 0..3 {
                    if i < chars.len() {
                        step(&chars, &mut i, &mut line, &mut col);
                    }
                }
            } else {
                step(&chars, &mut i, &mut line, &mut col);
                while i < chars.len() && chars[i] != '"' && chars[i] != '\n' {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        step(&chars, &mut i, &mut line, &mut col);
                    }
                    step(&chars, &mut i, &mut line, &mut col);
                }
                if i < chars.len() && chars[i] == '"' {
                    step(&chars, &mut i, &mut line, &mut col);
                }
            }
            Tk::Str
        } else if c == '-' || c.is_ascii_digit() {
            step(&chars, &mut i, &mut line, &mut col);
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '.' || ((chars[i] == '+' || chars[i] == '-') && matches!(chars[i - 1], 'e' | 'E'))) {
                step(&chars, &mut i, &mut line, &mut col);
            }
            Tk::Number
        } else if c == '_' || c.is_ascii_alphabetic() {
            while i < chars.len() && (chars[i] == '_' || chars[i].is_ascii_alphanumeric()) {
                step(&chars, &mut i, &mut line, &mut col);
            }
            Tk::Name
        } else {
            step(&chars, &mut i, &mut line, &mut col);
            Tk::Punct
        };
        tokens.push(Token { kind, text: chars[start..i].iter().collect(), line: start_line, col: start_col });
    }
    tokens.push(Token { kind: Tk::Eof, text: "<EOF>".into(), line, col });
    tokens
}

/// A type reference: a named type, a list of one, or either made non-null.
#[derive(Debug, Clone)]
pub enum TypeRef {
    Named(String),
    List(Box<TypeRef>),
    NonNull(Box<TypeRef>),
}

impl TypeRef {
    fn named(&self) -> &str {
        match self {
            TypeRef::Named(n) => n,
            TypeRef::List(t) | TypeRef::NonNull(t) => t.named(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Field {
    pub alias: Option<String>,
    pub name: String,
    pub selection: Option<Vec<Selection>>,
}

#[derive(Debug, Clone)]
pub enum Selection {
    Field(Field),
    Spread(String),
    Inline(Vec<Selection>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Kind {
    Object,
    Interface,
    Enum,
    Scalar,
    Union,
    Input,
}

#[derive(Debug, Clone)]
struct TypeDef {
    kind: Kind,
    name: String,
    fields: Vec<(String, TypeRef)>,
    values: Vec<String>,
    line: usize,
    col: usize,
}

#[derive(Debug, Clone)]
enum Definition {
    Operation { kind: String, name: Option<String>, selection: Vec<Selection>, line: usize, col: usize },
    Fragment { name: String, selection: Vec<Selection>, line: usize, col: usize },
    Type { def: TypeDef, extension: bool },
    Schema(Vec<(String, String)>),
    Other,
}

/// graphql-java's `InvalidSyntaxError`, as its `toString()` prints it, and as Jackson writes it (`bean`).
#[derive(Debug, Clone)]
struct SyntaxError {
    rendered: String,
    bean: Value,
}

struct Parser<'a> {
    src: &'a str,
    tokens: Vec<Token>,
    pos: usize,
}

type Parsed<T> = Result<T, usize>;

const DEFINITION_KEYWORDS: &[&str] = &["query", "mutation", "subscription", "fragment", "schema", "scalar", "type", "interface", "union", "enum", "input", "directive", "extend"];

impl<'a> Parser<'a> {
    fn new(src: &'a str) -> Parser<'a> {
        Parser { src, tokens: lex(src), pos: 0 }
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn at(&self, text: &str) -> bool {
        let t = self.peek();
        t.kind != Tk::Eof && t.kind != Tk::Str && t.text == text
    }

    fn at_name(&self) -> bool {
        self.peek().kind == Tk::Name
    }

    fn expect(&mut self, text: &str) -> Parsed<()> {
        if self.at(text) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.pos)
        }
    }

    fn name(&mut self) -> Parsed<String> {
        if self.at_name() {
            self.pos += 1;
            Ok(self.tokens[self.pos - 1].text.clone())
        } else {
            Err(self.pos)
        }
    }

    fn error(&self, index: usize, extra: bool) -> SyntaxError {
        let t = &self.tokens[index];
        let lines: Vec<&str> = self.src.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).collect();
        let mut preview = String::new();
        for (i, l) in lines.iter().enumerate() {
            // `mkPreview`: three lines either side of the (0-based) error line
            if i + 4 >= t.line && i <= t.line + 2 {
                preview.push_str(l);
                preview.push('\n');
            }
        }
        let message = if extra {
            format!("Invalid syntax encountered. There are extra tokens in the text that have not been consumed. Offending token '{}' at line {} column {}", t.text, t.line, t.col)
        } else {
            format!("Invalid syntax with offending token '{}' at line {} column {}", t.text, t.line, t.col)
        };
        let rendered = format!(
            "InvalidSyntaxError{{ message={message} ,offendingToken={} ,locations=[SourceLocation{{line={}, column={}}}] ,sourcePreview={preview}}}",
            t.text, t.line, t.col
        );
        let _ = index;
        let bean = serde_json::json!({
            "errorType": "InvalidSyntax",
            "locations": [{"column": t.col, "line": t.line}],
            "message": message,
            "offendingToken": t.text,
            "sourcePreview": preview,
        });
        SyntaxError { rendered, bean }
    }

    fn starts_definition(&self) -> bool {
        let t = self.peek();
        match t.kind {
            Tk::Str => true,
            Tk::Punct => t.text == "{",
            Tk::Name => DEFINITION_KEYWORDS.contains(&t.text.as_str()),
            _ => false,
        }
    }

    fn document(&mut self) -> Result<Vec<Definition>, SyntaxError> {
        let mut definitions = Vec::new();
        loop {
            if self.peek().kind == Tk::Eof && !definitions.is_empty() {
                return Ok(definitions);
            }
            if !self.starts_definition() {
                return Err(self.error(self.pos, !definitions.is_empty()));
            }
            match self.definition() {
                Ok(mut ds) => definitions.append(&mut ds),
                Err(index) => return Err(self.error(index, false)),
            }
        }
    }

    /// One definition, or two when a type's `{ … }` block reads as a following anonymous operation.
    fn definition(&mut self) -> Parsed<Vec<Definition>> {
        let t = self.peek().clone();
        if t.kind == Tk::Punct && t.text == "{" {
            let selection = self.selection_set()?;
            return Ok(vec![Definition::Operation { kind: "query".into(), name: None, selection, line: t.line, col: t.col }]);
        }
        if t.kind == Tk::Str {
            self.pos += 1;
        }
        let keyword = self.name()?;
        match keyword.as_str() {
            "query" | "mutation" | "subscription" if t.kind != Tk::Str => {
                let name = if self.at_name() { Some(self.name()?) } else { None };
                if self.at("(") {
                    self.variable_definitions()?;
                }
                self.directives()?;
                let selection = self.selection_set()?;
                Ok(vec![Definition::Operation { kind: keyword, name, selection, line: t.line, col: t.col }])
            }
            "fragment" if t.kind != Tk::Str => {
                let name = self.name()?;
                if name == "on" {
                    return Err(self.pos - 1);
                }
                self.expect_name("on")?;
                self.name()?;
                self.directives()?;
                let selection = self.selection_set()?;
                Ok(vec![Definition::Fragment { name, selection, line: t.line, col: t.col }])
            }
            "extend" if t.kind != Tk::Str => {
                let inner = self.peek().clone();
                let keyword = self.name()?;
                self.type_system(&keyword, inner.line, inner.col, true)
            }
            other => {
                let other = other.to_string();
                self.type_system(&other, t.line, t.col, false)
            }
        }
    }

    fn expect_name(&mut self, name: &str) -> Parsed<()> {
        if self.at_name() && self.peek().text == name {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.pos)
        }
    }

    fn type_system(&mut self, keyword: &str, line: usize, col: usize, extension: bool) -> Parsed<Vec<Definition>> {
        match keyword {
            "schema" => {
                self.directives()?;
                let mut roots = Vec::new();
                if !extension || self.at("{") {
                    self.expect("{")?;
                    loop {
                        let operation = self.name()?;
                        self.expect(":")?;
                        roots.push((operation, self.name()?));
                        if self.at("}") {
                            self.pos += 1;
                            break;
                        }
                    }
                }
                Ok(vec![Definition::Schema(roots)])
            }
            "scalar" => {
                let name = self.name()?;
                self.directives()?;
                Ok(vec![type_def(Kind::Scalar, name, line, col, extension)])
            }
            "type" | "interface" => {
                let kind = if keyword == "type" { Kind::Object } else { Kind::Interface };
                let name = self.name()?;
                if self.at_name() && self.peek().text == "implements" {
                    self.pos += 1;
                    if self.at("&") {
                        self.pos += 1;
                    }
                    self.name()?;
                    while self.at("&") || (self.at_name() && !self.starts_definition()) {
                        if self.at("&") {
                            self.pos += 1;
                        }
                        self.name()?;
                    }
                }
                self.directives()?;
                let mut def = TypeDef { kind, name, fields: Vec::new(), values: Vec::new(), line, col };
                let following = self.optional_block(|p| p.fields_definition(false))?;
                if let Some(Ok(fields)) = &following {
                    def.fields = fields.clone();
                }
                Ok(with_following(Definition::Type { def, extension }, following))
            }
            "input" => {
                let name = self.name()?;
                self.directives()?;
                let mut def = TypeDef { kind: Kind::Input, name, fields: Vec::new(), values: Vec::new(), line, col };
                let following = self.optional_block(|p| p.fields_definition(true))?;
                if let Some(Ok(fields)) = &following {
                    def.fields = fields.clone();
                }
                Ok(with_following(Definition::Type { def, extension }, following))
            }
            "enum" => {
                let name = self.name()?;
                self.directives()?;
                let mut def = TypeDef { kind: Kind::Enum, name, fields: Vec::new(), values: Vec::new(), line, col };
                let following = self.optional_block(|p| {
                    p.expect("{")?;
                    let mut values = Vec::new();
                    while !p.at("}") {
                        if p.peek().kind == Tk::Str {
                            p.pos += 1;
                        }
                        values.push((p.name()?, TypeRef::Named(String::new())));
                        p.directives()?;
                    }
                    p.pos += 1;
                    Ok(values)
                })?;
                if let Some(Ok(values)) = &following {
                    def.values = values.iter().map(|(v, _)| v.clone()).collect();
                }
                Ok(with_following(Definition::Type { def, extension }, following))
            }
            "union" => {
                let name = self.name()?;
                self.directives()?;
                if self.at("=") {
                    self.pos += 1;
                    if self.at("|") {
                        self.pos += 1;
                    }
                    self.name()?;
                    while self.at("|") {
                        self.pos += 1;
                        self.name()?;
                    }
                }
                Ok(vec![type_def(Kind::Union, name, line, col, extension)])
            }
            "directive" if !extension => {
                self.expect("@")?;
                self.name()?;
                if self.at("(") {
                    self.arguments_definition()?;
                }
                if self.at_name() && self.peek().text == "repeatable" {
                    self.pos += 1;
                }
                self.expect_name("on")?;
                if self.at("|") {
                    self.pos += 1;
                }
                self.name()?;
                while self.at("|") {
                    self.pos += 1;
                    self.name()?;
                }
                Ok(vec![Definition::Other])
            }
            _ => Err(self.pos - 1),
        }
    }

    /// An optional `{ … }` block: `None` without one, `Some(Ok(block))` when it parses as the block, and
    /// `Some(Err(selection))` when it does not but parses as an anonymous operation's selection set instead.
    fn optional_block<T>(&mut self, block: impl Fn(&mut Parser<'a>) -> Parsed<T>) -> Parsed<Option<Result<T, AnonymousQuery>>> {
        if !self.at("{") {
            return Ok(None);
        }
        let start = self.pos;
        let first = match block(self) {
            Ok(value) => return Ok(Some(Ok(value))),
            Err(index) => index,
        };
        self.pos = start;
        let (line, col) = (self.peek().line, self.peek().col);
        match self.selection_set() {
            Ok(selection) => Ok(Some(Err((selection, line, col)))),
            Err(second) => Err(first.max(second)),
        }
    }

    fn fields_definition(&mut self, input: bool) -> Parsed<Vec<(String, TypeRef)>> {
        self.expect("{")?;
        let mut fields = Vec::new();
        while !self.at("}") {
            if self.peek().kind == Tk::Str {
                self.pos += 1;
            }
            let name = self.name()?;
            if !input && self.at("(") {
                self.arguments_definition()?;
            }
            self.expect(":")?;
            let t = self.type_ref()?;
            if input && self.at("=") {
                self.pos += 1;
                self.value()?;
            }
            self.directives()?;
            fields.push((name, t));
        }
        self.pos += 1;
        Ok(fields)
    }

    fn arguments_definition(&mut self) -> Parsed<()> {
        self.expect("(")?;
        loop {
            if self.peek().kind == Tk::Str {
                self.pos += 1;
            }
            self.name()?;
            self.expect(":")?;
            self.type_ref()?;
            if self.at("=") {
                self.pos += 1;
                self.value()?;
            }
            self.directives()?;
            if self.at(")") {
                self.pos += 1;
                return Ok(());
            }
        }
    }

    fn type_ref(&mut self) -> Parsed<TypeRef> {
        let t = if self.at("[") {
            self.pos += 1;
            let inner = self.type_ref()?;
            self.expect("]")?;
            TypeRef::List(Box::new(inner))
        } else {
            TypeRef::Named(self.name()?)
        };
        if self.at("!") {
            self.pos += 1;
            return Ok(TypeRef::NonNull(Box::new(t)));
        }
        Ok(t)
    }

    fn variable_definitions(&mut self) -> Parsed<()> {
        self.expect("(")?;
        loop {
            self.expect("$")?;
            self.name()?;
            self.expect(":")?;
            self.type_ref()?;
            if self.at("=") {
                self.pos += 1;
                self.value()?;
            }
            self.directives()?;
            if self.at(")") {
                self.pos += 1;
                return Ok(());
            }
        }
    }

    fn directives(&mut self) -> Parsed<()> {
        while self.at("@") {
            self.pos += 1;
            self.name()?;
            if self.at("(") {
                self.arguments()?;
            }
        }
        Ok(())
    }

    fn arguments(&mut self) -> Parsed<()> {
        self.expect("(")?;
        loop {
            self.name()?;
            self.expect(":")?;
            self.value()?;
            if self.at(")") {
                self.pos += 1;
                return Ok(());
            }
        }
    }

    fn value(&mut self) -> Parsed<()> {
        let t = self.peek().clone();
        match t.kind {
            Tk::Number | Tk::Str | Tk::Name => {
                self.pos += 1;
                Ok(())
            }
            Tk::Punct if t.text == "$" => {
                self.pos += 1;
                self.name().map(|_| ())
            }
            Tk::Punct if t.text == "[" => {
                self.pos += 1;
                while !self.at("]") {
                    self.value()?;
                }
                self.pos += 1;
                Ok(())
            }
            Tk::Punct if t.text == "{" => {
                self.pos += 1;
                while !self.at("}") {
                    self.name()?;
                    self.expect(":")?;
                    self.value()?;
                }
                self.pos += 1;
                Ok(())
            }
            _ => Err(self.pos),
        }
    }

    fn selection_set(&mut self) -> Parsed<Vec<Selection>> {
        self.expect("{")?;
        let mut selections = vec![self.selection()?];
        while !self.at("}") {
            selections.push(self.selection()?);
        }
        self.pos += 1;
        Ok(selections)
    }

    fn selection(&mut self) -> Parsed<Selection> {
        if self.at("...") {
            self.pos += 1;
            if self.at_name() && self.peek().text != "on" {
                let name = self.name()?;
                self.directives()?;
                return Ok(Selection::Spread(name));
            }
            if self.at_name() {
                self.pos += 1;
                self.name()?;
            }
            self.directives()?;
            return Ok(Selection::Inline(self.selection_set()?));
        }
        let first = self.name()?;
        let (alias, name) = if self.at(":") {
            self.pos += 1;
            (Some(first), self.name()?)
        } else {
            (None, first)
        };
        if self.at("(") {
            self.arguments()?;
        }
        self.directives()?;
        let selection = if self.at("{") { Some(self.selection_set()?) } else { None };
        Ok(Selection::Field(Field { alias, name, selection }))
    }
}

fn type_def(kind: Kind, name: String, line: usize, col: usize, extension: bool) -> Definition {
    Definition::Type { def: TypeDef { kind, name, fields: Vec::new(), values: Vec::new(), line, col }, extension }
}

/// A selection set read as an anonymous query: the selection, its line and column.
type AnonymousQuery = (Vec<Selection>, usize, usize);

fn with_following<T>(definition: Definition, following: Option<Result<T, AnonymousQuery>>) -> Vec<Definition> {
    match following {
        Some(Err((selection, line, col))) => vec![definition, Definition::Operation { kind: "query".into(), name: None, selection, line, col }],
        _ => vec![definition],
    }
}

/// Parses a GraphQL document (`Parser.parse`).
fn parse(src: &str) -> Result<Vec<Definition>, SyntaxError> {
    Parser::new(src).document()
}

/// A schema built from SDL or an introspection result.
#[derive(Debug, Clone)]
pub struct Schema {
    types: Vec<TypeDef>,
    query: Option<String>,
    mutation: Option<String>,
    subscription: Option<String>,
}

const BUILT_IN_SCALARS: &[&str] = &["String", "Int", "Float", "Boolean", "ID"];

impl Schema {
    /// `SchemaParser.parse` (or the introspection reading) then `UnExecutableSchemaGenerator`: the schema, or the
    /// exception's message, `Unable to parse GraphQL schema: errors=[…]` and the like.
    pub fn build(definition: &str) -> Result<Schema, String> {
        Schema::build_failing(definition).map_err(|f| f.message)
    }

    /// [`Schema::build`] with the exception `GraphQLExpectationGenerator` throws: an `IllegalArgumentException`
    /// wrapping graphql-java's `SchemaProblem` (its `errors`) or the introspection reader's exception.
    pub fn build_failing(definition: &str) -> Result<Schema, Failure> {
        // `SchemaProblem`: `errors` holds each error as Jackson writes it, the message their `toString()`s
        fn problem(errors: Vec<(String, Value)>) -> Failure {
            let text = format!("errors=[{}]", errors.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>().join(", "));
            let cause = Failure::of("graphql.schema.idl.errors.SchemaProblem", text.clone(), vec![("errors", Value::Array(errors.into_iter().map(|(_, b)| b).collect()))], &[]);
            Failure::illegal_caused(format!("Unable to parse GraphQL schema: {text}"), cause)
        }
        // a `GraphQLException` that is a `GraphQLError` of type `ValidationError` at `(line, column)`
        fn validation(message: String, (line, column): (i64, i64)) -> (String, Value) {
            let locations = serde_json::json!([{"column": column, "line": line}]);
            let bean = Failure::of("graphql.GraphQLException", message.clone(), vec![("errorType", "ValidationError".into()), ("locations", locations)], &[]).bean;
            (message, bean)
        }
        let trimmed = definition.trim();
        if trimmed.starts_with('{') {
            return from_introspection(trimmed);
        }
        let definitions = parse(trimmed).map_err(|e| problem(vec![(e.rendered, e.bean)]))?;
        let mut errors = Vec::new();
        for d in &definitions {
            let (element, line, col) = match d {
                Definition::Operation { line, col, .. } => ("OperationDefinition", line, col),
                Definition::Fragment { line, col, .. } => ("FragmentDefinition", line, col),
                _ => continue,
            };
            errors.push(validation(format!("[@{line}:{col}] The schema definition text contains a non schema definition language (SDL) element '{element}'"), (*line as i64, *col as i64)));
        }
        if !errors.is_empty() {
            return Err(problem(errors));
        }
        let mut types: Vec<TypeDef> = Vec::new();
        let mut roots = Vec::new();
        let mut extensions = Vec::new();
        for d in definitions {
            match d {
                Definition::Type { def, extension: false } => types.push(def),
                Definition::Type { def, extension: true } => extensions.push(def),
                Definition::Schema(r) => roots.extend(r),
                _ => {}
            }
        }
        for ext in extensions {
            if let Some(base) = types.iter_mut().find(|t| t.name == ext.name) {
                base.fields.extend(ext.fields);
                base.values.extend(ext.values);
            }
        }
        let defined = |name: &str| BUILT_IN_SCALARS.contains(&name) || types.iter().any(|t| t.name == name);
        for t in types.iter().filter(|t| matches!(t.kind, Kind::Object | Kind::Interface)) {
            for (_, field_type) in &t.fields {
                if !defined(field_type.named()) {
                    let message = format!("The field type '{}' is not present when resolving type '{}' [@{}:{}]", field_type.named(), t.name, t.line, t.col);
                    errors.push(validation(message, (t.line as i64, t.col as i64)));
                }
            }
        }
        let root = |operation: &str, default: &str| -> Option<String> {
            match roots.iter().find(|(o, _)| o == operation) {
                Some((_, name)) => Some(name.clone()),
                None if roots.is_empty() && types.iter().any(|t| t.name == default && t.kind == Kind::Object) => Some(default.to_string()),
                None => None,
            }
        };
        let (query, mutation, subscription) = (root("query", "Query"), root("mutation", "Mutation"), root("subscription", "Subscription"));
        if query.is_none() {
            errors.push(validation("A schema MUST have a 'query' operation defined".into(), (-1, -1)));
        }
        if !errors.is_empty() {
            return Err(problem(errors));
        }
        Ok(Schema { types, query, mutation, subscription })
    }

    pub fn has_mutation(&self) -> bool {
        self.mutation.is_some()
    }

    pub fn has_subscription(&self) -> bool {
        self.subscription.is_some()
    }

    fn type_named(&self, name: &str) -> Option<&TypeDef> {
        self.types.iter().find(|t| t.name == name)
    }

    /// `GraphQLResponseSynthesizer.synthesizeResponse`: `{"data":{…}}` for the request body's query (a
    /// GraphQL-over-HTTP JSON body or a raw document), or why it cannot be.
    pub fn synthesize(&self, body: &str) -> Result<String, String> {
        if body.trim().is_empty() {
            return Err("GraphQL request body was null or blank".into());
        }
        let (query, operation_name) = extract(body);
        let definitions = parse(&query).map_err(|e| format!("Unable to parse GraphQL query: {}", e.rendered.split(" ,offendingToken=").next().unwrap_or_default().trim_start_matches("InvalidSyntaxError{ message=")))?;
        let mut fragments: Vec<(String, Vec<Selection>)> = Vec::new();
        let mut operation: Option<(String, Vec<Selection>)> = None;
        for d in definitions {
            match d {
                Definition::Fragment { name, selection, .. } => {
                    fragments.retain(|(n, _)| *n != name);
                    fragments.push((name, selection));
                }
                Definition::Operation { kind, name, selection, .. } if operation.is_none() || (operation_name.is_some() && operation_name == name) => {
                    operation = Some((kind, selection));
                }
                _ => {}
            }
        }
        let Some((kind, selection)) = operation else { return Err("GraphQL document contained no operation to execute".into()) };
        let root = match kind.as_str() {
            "mutation" => self.mutation.as_deref(),
            "subscription" => self.subscription.as_deref(),
            _ => self.query.as_deref(),
        };
        let Some(root) = root.and_then(|r| self.type_named(r)) else {
            return Err(format!("schema does not define a root type for operation {}", kind.to_uppercase()));
        };
        let data = self.selection_set(root, Some(&selection), &fragments, 0);
        let mut envelope = Map::new();
        envelope.insert("data".into(), Value::Object(data));
        Ok(serde_json::to_string(&Value::Object(envelope)).unwrap_or_default())
    }

    fn selection_set(&self, container: &TypeDef, selection: Option<&Vec<Selection>>, fragments: &[(String, Vec<Selection>)], depth: usize) -> Map<String, Value> {
        let mut result = Map::new();
        let Some(selection) = selection else { return result };
        if depth > 25 {
            return result;
        }
        for s in selection {
            match s {
                Selection::Field(f) => {
                    let key = f.alias.clone().unwrap_or_else(|| f.name.clone());
                    if f.name == "__typename" {
                        result.insert(key, Value::String(container.name.clone()));
                        continue;
                    }
                    let value = match container.fields.iter().find(|(n, _)| *n == f.name) {
                        Some((_, t)) => self.value(t, f.selection.as_ref(), fragments, depth),
                        None => Value::Null,
                    };
                    result.insert(key, value);
                }
                Selection::Inline(inner) => {
                    for (k, v) in self.selection_set(container, Some(inner), fragments, depth + 1) {
                        result.insert(k, v);
                    }
                }
                Selection::Spread(name) => {
                    if let Some((_, inner)) = fragments.iter().find(|(n, _)| n == name) {
                        for (k, v) in self.selection_set(container, Some(inner), fragments, depth + 1) {
                            result.insert(k, v);
                        }
                    }
                }
            }
        }
        result
    }

    fn value(&self, t: &TypeRef, selection: Option<&Vec<Selection>>, fragments: &[(String, Vec<Selection>)], depth: usize) -> Value {
        let unwrapped = match t {
            TypeRef::NonNull(inner) => inner.as_ref(),
            other => other,
        };
        match unwrapped {
            TypeRef::List(item) => Value::Array(vec![self.value(item, selection, fragments, depth)]),
            TypeRef::NonNull(inner) => self.value(inner, selection, fragments, depth),
            TypeRef::Named(name) => {
                if BUILT_IN_SCALARS.contains(&name.as_str()) {
                    return scalar(name);
                }
                match self.type_named(name) {
                    Some(def) if def.kind == Kind::Scalar => scalar(name),
                    Some(def) if def.kind == Kind::Enum => def.values.first().map_or(Value::Null, |v| Value::String(v.clone())),
                    Some(def) if matches!(def.kind, Kind::Object | Kind::Interface) => match selection {
                        None => Value::Null,
                        Some(_) => Value::Object(self.selection_set(def, selection, fragments, depth + 1)),
                    },
                    _ => Value::Null,
                }
            }
        }
    }
}

fn scalar(name: &str) -> Value {
    match name {
        "Int" => Value::from(0),
        "Float" => Value::from(0.0),
        "Boolean" => Value::Bool(true),
        "ID" => Value::String("1".into()),
        "String" => Value::String("string".into()),
        _ => {
            let lower = name.to_lowercase();
            if lower.contains("datetime") || lower.contains("timestamp") {
                Value::String("2020-01-01T00:00:00Z".into())
            } else if lower.contains("date") {
                Value::String("2020-01-01".into())
            } else if lower.contains("time") {
                Value::String("00:00:00".into())
            } else if lower.contains("json") {
                Value::Object(Map::new())
            } else if lower.contains("long") || lower.contains("bigint") || lower.contains("int") {
                Value::from(0)
            } else if lower.contains("decimal") || lower.contains("float") || lower.contains("double") {
                Value::from(0.0)
            } else if lower.contains("boolean") || lower.contains("bool") {
                Value::Bool(true)
            } else {
                Value::String("string".into())
            }
        }
    }
}

/// `extractQuery` and `extractOperationName`.
fn extract(body: &str) -> (String, Option<String>) {
    let trimmed = body.trim();
    let parsed = if trimmed.starts_with('{') { serde_json::from_str::<Value>(trimmed).ok() } else { None };
    let query = match &parsed {
        Some(v) if trimmed.contains("\"query\"") => v.get("query").and_then(Value::as_str).map(str::to_string),
        _ => None,
    };
    let operation_name = parsed.as_ref().and_then(|v| v.get("operationName")).and_then(Value::as_str).map(str::to_string);
    (query.unwrap_or_else(|| trimmed.to_string()), operation_name)
}

/// `IntrospectionResultToSchema`: an introspection result's types and root operation types.
fn from_introspection(json: &str) -> Result<Schema, Failure> {
    // Jackson's reading, which words a malformed document
    if let Err(e) = jackson::json::read_tree(json, jackson::json::ReadFeatures::default()) {
        return Err(Failure::illegal_caused(format!("Unable to parse introspection JSON: {}", e.message), crate::chaos::bind::parse_failure(json, &e.message)));
    }
    let root: Value = serde_json::from_str(json).map_err(|e| format!("Unable to parse introspection JSON: {e}"))?;
    let schema = if root.pointer("/data/__schema").is_some() {
        &root["data"]["__schema"]
    } else if root.get("__schema").is_some() {
        &root["__schema"]
    } else {
        return Err("introspection JSON did not contain a \"__schema\" object".into());
    };
    fn type_ref(v: &Value) -> Option<TypeRef> {
        match v.get("kind").and_then(Value::as_str)? {
            "NON_NULL" => Some(TypeRef::NonNull(Box::new(type_ref(v.get("ofType")?)?))),
            "LIST" => Some(TypeRef::List(Box::new(type_ref(v.get("ofType")?)?))),
            _ => Some(TypeRef::Named(v.get("name")?.as_str()?.to_string())),
        }
    }
    let mut types = Vec::new();
    for t in schema.get("types").and_then(Value::as_array).into_iter().flatten() {
        let Some(name) = t.get("name").and_then(Value::as_str) else { continue };
        if name.starts_with("__") {
            continue;
        }
        let kind = match t.get("kind").and_then(Value::as_str) {
            Some("OBJECT") => Kind::Object,
            Some("INTERFACE") => Kind::Interface,
            Some("ENUM") => Kind::Enum,
            Some("UNION") => Kind::Union,
            Some("INPUT_OBJECT") => Kind::Input,
            _ => Kind::Scalar,
        };
        let fields = t
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|f| Some((f.get("name")?.as_str()?.to_string(), type_ref(f.get("type")?)?)))
            .collect();
        let values = t.get("enumValues").and_then(Value::as_array).into_iter().flatten().filter_map(|v| v.get("name")?.as_str().map(str::to_string)).collect();
        types.push(TypeDef { kind, name: name.to_string(), fields, values, line: 1, col: 1 });
    }
    let root = |key: &str| schema.get(key).and_then(|r| r.get("name")).and_then(Value::as_str).map(str::to_string);
    let query = root("queryType");
    if query.is_none() {
        // graphql-java's `AssertException`, wrapped
        let cause = Failure::of("graphql.AssertException", "queryType expected", Vec::new(), &[]);
        return Err(Failure::illegal_caused("Unable to parse introspection JSON: queryType expected", cause));
    }
    Ok(Schema { types, query, mutation: root("mutationType"), subscription: root("subscriptionType") })
}

/// `GraphQLExpectationGenerator.generate(schema, path)`: one expectation (input form) per root operation type, each
/// matching any operation of that kind on the path, with no response body so that it is synthesized per request.
pub fn generate(definition: &str, path: Option<&str>) -> Result<Vec<Value>, Failure> {
    if definition.trim().is_empty() {
        return Err("GraphQL schema definition was null or blank".into());
    }
    let schema = Schema::build_failing(definition)?;
    let path = path.filter(|p| !p.trim().is_empty()).unwrap_or("/graphql");
    let mut operations = vec!["query"];
    if schema.has_mutation() {
        operations.push("mutation");
    }
    if schema.has_subscription() {
        operations.push("subscription");
    }
    Ok(operations
        .into_iter()
        .map(|operation| {
            serde_json::json!({
                "httpRequest": {
                    "method": "POST",
                    "path": path,
                    "body": {"type": "GRAPHQL", "query": format!("{operation} {{ }}"), "schema": definition, "selectionSetMatchType": "AST_SUBSET"}
                },
                "httpResponse": {}
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syntax_errors_name_the_offending_token() {
        let e = Schema::build("type Query { this is not valid sdl").unwrap_err();
        assert!(e.contains("Invalid syntax with offending token '<EOF>' at line 1 column 35"), "{e}");
        let e = Schema::build("type Query { this is not valid sdl }").unwrap_err();
        assert!(e.contains("[@1:12] The schema definition text contains a non schema definition language (SDL) element 'OperationDefinition'"), "{e}");
        let e = Schema::build("type Query a: String }").unwrap_err();
        assert!(e.contains("There are extra tokens in the text that have not been consumed. Offending token 'a' at line 1 column 12"), "{e}");
        assert_eq!(Schema::build("type Widget { id: Foo }").unwrap_err(), "Unable to parse GraphQL schema: errors=[The field type 'Foo' is not present when resolving type 'Widget' [@1:1], A schema MUST have a 'query' operation defined]");
    }

    #[test]
    fn synthesizes_requested_fields() {
        let schema = Schema::build("type Query { user: User } type User { id: ID user: User name: String }").unwrap();
        assert_eq!(schema.synthesize("{ user { name } }").unwrap(), r#"{"data":{"user":{"name":"string"}}}"#);
        let cyclic = schema.synthesize("{ user { ...f } } fragment f on User { id user { ...f } }").unwrap();
        assert_eq!(cyclic.matches("\"user\"").count(), 13);
    }
}

//! Building a user's schema the way networknt 3.0's `SchemaRegistry.getSchema` does, for the exception it throws
//! on one it cannot build.
//!
//! `JsonSchemaValidator`'s constructor builds the schema eagerly: `Schema`'s constructor checks its `$id`
//! (`DefaultSchemaIdValidator`) and builds a validator for each keyword in document order
//! (`Dialect.newValidator`), and the applicator keywords build their subschemas at once (`SchemaRegistry.doCreate`
//! checks each is an object, or a boolean from draft 6). References stay lazy. The first exception escapes as the
//! expectation's 400 answer; a `SchemaException` keeps its own message, anything else is wrapped
//! (`new SchemaException(cause)`: the cause's `toString()`). [`construction_error`] answers that text.

use serde_json::Value;

use super::{Spec, append, dialect_of, format, type_name};

/// Where a schema sits: the absolute IRI of its resource (`None` until an `$id` gives one) and the JSON path of its
/// fragment, as `SchemaLocation.toString` prints them.
#[derive(Clone)]
struct Loc {
    base: Option<String>,
    path: String,
}

impl Loc {
    fn name(&self, name: &str) -> Loc {
        Loc { base: self.base.clone(), path: append(&self.path, name) }
    }

    fn index(&self, i: usize) -> Loc {
        Loc { base: self.base.clone(), path: format!("{}[{i}]", self.path) }
    }

    fn shown(&self) -> String {
        format!("{}{}", self.base.as_deref().unwrap_or(""), self.path)
    }
}

type Built = Result<(), String>;

/// The message of the exception `getSchema` throws for `schema`, read in `default` unless its `$schema` names
/// another dialect; `None` when it builds. A `$schema` networknt does not know is a meta-schema it would load: refused
/// (`SchemaLoader.block`) unless `remote_allowed`, when this gives up (`None`) rather than fetch it.
pub fn construction_error(schema: &Value, default: Spec, remote_allowed: bool) -> Option<String> {
    construction_error_at(schema, default, remote_allowed, None)
}

/// [`construction_error`] for a document loaded from `base` (a remote `$ref`'s IRI), where locations start.
pub fn construction_error_at(schema: &Value, default: Spec, remote_allowed: bool, base: Option<&str>) -> Option<String> {
    // `SchemaRegistry.getDialectOrDefault`
    let spec = match schema.get("$schema") {
        None | Some(Value::Null) => default,
        Some(Value::String(iri)) => match known_dialect(iri, remote_allowed) {
            Ok(Some(spec)) => spec,
            Ok(None) => return None,
            Err(message) => return Some(message),
        },
        Some(other) => return Some(format!("Unknown dialect: {other}")),
    };
    let root = Loc { base: base.map(str::to_string), path: "$".into() };
    let mut build = Build { remote_allowed };
    build.schema(&root, schema, spec, true).err()
}

/// `SchemaRegistry.getDialect`: a well-known dialect, or the refusal to load an unknown one's meta-schema.
fn known_dialect(iri: &str, remote_allowed: bool) -> Result<Option<Spec>, String> {
    match dialect_of(iri) {
        Some(spec) => Ok(Some(spec)),
        // the OpenAPI dialects build like 2020-12 as far as construction is concerned; not worth telling apart
        None if iri.starts_with("https://spec.openapis.org/oas/") => Ok(None),
        None if remote_allowed => Ok(None),
        None => Err(format!("Schema from '{iri}' is not allowed to be loaded.")),
    }
}

struct Build {
    remote_allowed: bool,
}

/// What a dialect does with a keyword (`Dialect.keywords`, else `UnknownKeywordFactory`'s annotation).
#[derive(PartialEq)]
enum Kw {
    /// `AnnotationKeyword`, or a keyword whose validator cannot fail to build.
    Inert,
    /// `NonValidationKeyword`: builds its value when it carries an `$id` or anchor, and `$defs`'/`definitions`'
    /// members.
    NonValidation,
    /// A `KeywordType` validator with something to build or check.
    Validator,
}

fn kind(spec: Spec, keyword: &str) -> Kw {
    use Spec::*;
    let modern = spec >= Draft201909;
    match keyword {
        "$schema" | "$comment" | "definitions" => Kw::NonValidation,
        "id" if spec == Draft4 => Kw::NonValidation,
        "id" => Kw::Validator,
        "$id" if spec >= Draft6 => Kw::NonValidation,
        "additionalItems" if spec != Draft202012 => Kw::NonValidation,
        "exclusiveMinimum" | "exclusiveMaximum" if spec == Draft4 => Kw::NonValidation,
        "then" | "else" if spec >= Draft7 => Kw::NonValidation,
        "$anchor" | "$vocabulary" | "$defs" if modern => Kw::NonValidation,
        "$recursiveAnchor" if spec == Draft201909 => Kw::NonValidation,
        "$dynamicAnchor" if spec == Draft202012 => Kw::NonValidation,
        "additionalProperties" | "allOf" | "anyOf" | "oneOf" | "not" | "properties" | "patternProperties" | "pattern" | "maximum"
        | "minimum" | "dependencies" | "$ref" | "type" => Kw::Validator,
        "items" if spec != Draft202012 => Kw::Validator,
        "contains" | "propertyNames" | "exclusiveMaximum" | "exclusiveMinimum" if spec >= Draft6 => Kw::Validator,
        "if" if spec >= Draft7 => Kw::Validator,
        "unevaluatedItems" | "unevaluatedProperties" | "dependentSchemas" if modern => Kw::Validator,
        "$recursiveRef" if spec == Draft201909 => Kw::Validator,
        "prefixItems" | "items" if spec == Draft202012 => Kw::Validator,
        _ => Kw::Inert,
    }
}

impl Build {
    /// `SchemaRegistry.doCreate`: the node's dialect, its type, then `new Schema(..)`.
    fn schema(&mut self, loc: &Loc, node: &Value, parent: Spec, root: bool) -> Built {
        let spec = match node.get("$schema").and_then(Value::as_str) {
            Some(iri) if !root => match known_dialect(iri, self.remote_allowed)? {
                Some(spec) => spec,
                None => return Ok(()),
            },
            Some(iri) => dialect_of(iri).unwrap_or(parent),
            None => parent,
        };
        match node {
            Value::Object(_) => {}
            Value::Bool(_) if spec >= Spec::Draft6 => return Ok(()),
            other => {
                let expected = if spec >= Spec::Draft6 { "object or boolean" } else { "object" };
                return Err(format!("Schema at {} must be {expected} but was {}", loc.shown(), node_type(other)));
            }
        }
        let loc = self.resolve_id(loc, node, spec)?;
        let Value::Object(fields) = node else { return Ok(()) };
        // `Schema.read`
        for (keyword, value) in fields {
            if keyword == "$recursiveAnchor" && !value.is_boolean() {
                return Err(format!("The value of a $recursiveAnchor must be a Boolean literal but is {}", node_type(value)));
            }
            self.keyword(&loc, node, spec, keyword, value)?;
        }
        Ok(())
    }

    /// `Schema.resolve`: the location an `$id` gives the schema, after `DefaultSchemaIdValidator` accepted it.
    fn resolve_id(&mut self, loc: &Loc, node: &Value, spec: Spec) -> Result<Loc, String> {
        let keyword = if spec == Spec::Draft4 { "id" } else { "$id" };
        let Some(id) = node.get(keyword).and_then(Value::as_str) else { return Ok(loc.clone()) };
        let part = match id.find('#') {
            Some(i) if i + 1 < id.len() => &id[..i],
            _ => id,
        };
        let part = part.split('#').next().unwrap_or(part);
        let resolved = if part.is_empty() {
            loc.clone()
        } else {
            let base = match &loc.base {
                Some(base) => super::refs::strip_fragment(&super::refs::resolve(base, part)).to_string(),
                None => part.to_string(),
            };
            Loc { base: Some(base), path: "$".into() }
        };
        let valid = (loc.base.is_none() && (id.starts_with('#') || id.starts_with('/')))
            || resolved.base.as_deref().is_some_and(|iri| iri.contains(':') && crate::java_uri::parse(iri).is_ok());
        if valid { Ok(resolved) } else { Err(format!("'{id}' is not a valid {keyword}")) }
    }

    fn keyword(&mut self, loc: &Loc, parent: &Value, spec: Spec, keyword: &str, value: &Value) -> Built {
        let at = loc.name(keyword);
        match kind(spec, keyword) {
            Kw::Inert => Ok(()),
            Kw::NonValidation => {
                let names_resource = |v: &Value| {
                    let id = if spec == Spec::Draft4 { "id" } else { "$id" };
                    v.get(id).is_some_and(Value::is_string)
                        || (spec >= Spec::Draft201909 && v.get("$anchor").is_some_and(Value::is_string))
                        || (spec == Spec::Draft202012 && v.get("$dynamicAnchor").is_some_and(Value::is_string))
                };
                if value.is_object() && names_resource(value) {
                    self.schema(&at, value, spec, false)?;
                }
                if keyword == "$defs" || keyword == "definitions" {
                    for (name, member) in value.as_object().into_iter().flatten() {
                        self.schema(&at.name(name), member, spec, false)?;
                    }
                }
                Ok(())
            }
            Kw::Validator => self.validator(loc, &at, parent, spec, keyword, value),
        }
    }

    fn validator(&mut self, loc: &Loc, at: &Loc, parent: &Value, spec: Spec, keyword: &str, value: &Value) -> Built {
        let schema_like = |v: &Value| v.is_object() || v.is_boolean();
        let illegal = |message: &str| Err(format!("java.lang.IllegalArgumentException: {message}"));
        match keyword {
            "additionalProperties" => {
                if value.is_object() {
                    self.schema(at, value, spec, false)?;
                }
                for name in parent.get("patternProperties").and_then(Value::as_object).into_iter().flatten().map(|(k, _)| k) {
                    compile(name)?;
                }
            }
            "allOf" | "anyOf" | "oneOf" => {
                let Value::Array(items) = value else {
                    return Err(format!("{} found, array expected", type_name(value)));
                };
                for (i, item) in items.iter().enumerate() {
                    self.schema(&at.index(i), item, spec, false)?;
                }
            }
            "not" | "propertyNames" => self.schema(at, value, spec, false)?,
            "contains" if schema_like(value) => self.schema(at, value, spec, false)?,
            "properties" | "dependencies" | "dependentSchemas" | "patternProperties" => {
                if keyword == "patternProperties" && !value.is_object() {
                    return Err("patternProperties must be an object node".into());
                }
                for (name, member) in value.as_object().into_iter().flatten() {
                    if keyword == "patternProperties" {
                        compile(name)?;
                    }
                    if matches!(keyword, "properties" | "patternProperties") || schema_like(member) {
                        self.schema(&at.name(name), member, spec, false)?;
                    }
                }
            }
            "pattern" => {
                if let Some(pattern) = value.as_str() {
                    compile(pattern)?;
                }
            }
            "maximum" | "minimum" | "exclusiveMaximum" | "exclusiveMinimum" if !value.is_number() => {
                return Err(format!("{keyword} value is not a number"));
            }
            "if" => {
                // `IfValidator` builds `if`, then `then` and `else` when present, from the parent schema
                for name in ["if", "then", "else"] {
                    if let Some(node) = parent.get(name) {
                        self.schema(&loc.name(name), node, spec, false)?;
                    }
                }
            }
            "items" if spec == Spec::Draft202012 => {
                if !matches!(parent.get("prefixItems"), None | Some(Value::Array(_))) {
                    return illegal("The value of 'prefixItems' must be an array of JSON Schema.");
                }
                if !schema_like(value) {
                    return illegal("The value of 'items' MUST be a valid JSON Schema.");
                }
                self.schema(at, value, spec, false)?;
            }
            "items" => {
                // `ItemsLegacyValidator`: a schema, or a tuple (any other node iterates as empty) with `additionalItems`
                if schema_like(value) {
                    self.schema(at, value, spec, false)?;
                } else {
                    for (i, item) in value.as_array().into_iter().flatten().enumerate() {
                        self.schema(&at.index(i), item, spec, false)?;
                    }
                    if let Some(additional) = parent.get("additionalItems").filter(|v| v.is_object()) {
                        self.schema(&loc.name("additionalItems"), additional, spec, false)?;
                    }
                }
            }
            "prefixItems" => {
                let items = value.as_array().filter(|a| !a.is_empty());
                let Some(items) = items else {
                    return illegal("The value of 'prefixItems' MUST be a non-empty array of valid JSON Schemas.");
                };
                for (i, item) in items.iter().enumerate() {
                    self.schema(&at.index(i), item, spec, false)?;
                }
            }
            "unevaluatedItems" | "unevaluatedProperties" => {
                if !schema_like(value) {
                    return illegal(&format!("The value of '{keyword}' MUST be a valid JSON Schema."));
                }
                self.schema(at, value, spec, false)?;
            }
            "type" => {
                // `UnionTypeValidator`: each object member is a schema
                for (i, member) in value.as_array().into_iter().flatten().enumerate() {
                    if member.is_object() {
                        self.schema(&at.index(i), member, spec, false)?;
                    }
                }
            }
            "$ref" => {
                // `RefValidator`: `schemaNode.asString()`, which a container refuses; the target loads lazily
                if let Some(error) = as_string_refusal(value) {
                    return Err(error);
                }
            }
            "$recursiveRef" => {
                if value.as_str() != Some("#") {
                    // the message format's quotes swallow the argument (`MessageFormat`)
                    return Err("The value of a $recursiveRef must be # but is {0}".into());
                }
            }
            // `KeywordType.ID` has no validator factory
            "id" => return Err("java.lang.UnsupportedOperationException: No suitable validator for id".into()),
            _ => {}
        }
        Ok(())
    }
}

/// `JsonNode.asString()` on a container (Jackson 3's `JsonNodeException`), which prints the value in short.
fn as_string_refusal(value: &Value) -> Option<String> {
    let (class, shown) = match value {
        Value::Object(o) => ("ObjectNode", format!("{{...({} properties)}}", o.len())),
        Value::Array(a) if a.is_empty() => ("ArrayNode", "[ ]".to_string()),
        Value::Array(a) => ("ArrayNode", format!("[...({} elements)]", a.len())),
        _ => return None,
    };
    Some(format!(
        "shaded_package.tools.jackson.databind.exc.JsonNodeException: '{class}' method `asString()` cannot coerce value {shown} to `java.lang.String`: value type not coercible"
    ))
}

/// `JDKRegularExpression`: `Pattern.compile` of the pattern after networknt's rewriting, or the
/// `PatternSyntaxException` it throws.
fn compile(pattern: &str) -> Built {
    let rewritten = format::replace_longform_properties(&format::replace_dollar_anchors(pattern));
    format::java_regex(&rewritten).map(|_| ()).map_err(|e| format!("java.util.regex.PatternSyntaxException: {e}"))
}

/// Jackson 3's `JsonNodeType` name.
fn node_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "NULL",
        Value::Bool(_) => "BOOLEAN",
        Value::Number(_) => "NUMBER",
        Value::String(_) => "STRING",
        Value::Array(_) => "ARRAY",
        Value::Object(_) => "OBJECT",
    }
}

#[cfg(test)]
mod tests {
    use super::{Spec, construction_error};
    use serde_json::json;

    fn error(schema: serde_json::Value) -> Option<String> {
        construction_error(&schema, Spec::Draft7, false)
    }

    #[test]
    fn reports_what_networknt_throws_while_building() {
        assert_eq!(error(json!({"properties": {"a": 5}})).as_deref(), Some("Schema at $.properties.a must be object or boolean but was NUMBER"));
        assert_eq!(error(json!({"$id": "%zz"})).as_deref(), Some("'%zz' is not a valid $id"));
        assert_eq!(error(json!({"$id": "#foo"})), None);
        assert_eq!(error(json!({"allOf": {}})).as_deref(), Some("object found, array expected"));
        assert_eq!(error(json!({"minimum": "x", "properties": {"a": 5}})).as_deref(), Some("minimum value is not a number"));
        assert_eq!(
            error(json!({"$id": "http://example.com/r.json", "properties": {"a": 5}})).as_deref(),
            Some("Schema at http://example.com/r.json$.properties.a must be object or boolean but was NUMBER")
        );
        assert_eq!(error(json!({"items": "x", "additionalProperties": "x", "$ref": "#/definitions/x"})), None);
    }
}

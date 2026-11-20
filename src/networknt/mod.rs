//! A JSON Schema evaluator that reports errors the way networknt json-schema-validator 3.0.7 does (the library
//! MockServer 8.0.0 validates with): MockServer's own control-plane schemas, and the schemas users put in bodies,
//! parameters and headers (`JsonSchemaValidator.isValid`).
//!
//! What matters for a report is the *set* of error strings (`JsonSchemaValidator.formatProcessingReport` collects them
//! into a set and sorts), so this follows networknt's keyword semantics rather than its evaluation order:
//! - dialects: drafts 4, 6, 7, 2019-09 and 2020-12, chosen by `$schema` (also on any subschema), each with its own
//!   keyword set (`KeywordType` ranges and the 2019-09/2020-12 vocabularies); formats assert only before 2019-09;
//! - `anyOf` that fails reports every branch's errors and no line of its own; `oneOf` that does not match exactly one
//!   branch reports its own line plus every failed branch's errors;
//! - `$ref` siblings are ignored before 2019-09; references resolve through `$id`/`id`/`$anchor` resources and the
//!   bundled json-schema.org meta-schemas (`refs`); an unresolvable one is an `InvalidSchemaRefException`, raised only
//!   when evaluation reaches it;
//! - numbers are Jackson nodes (`num`): integral literals and doubles, `Double.toString` text, `BigDecimal` limits;
//! - locations are JSON paths (`$.a['b c'][0]`), messages are `jsv-messages.properties` through `MessageFormat`.
//!
//! The meta-schemas under `metaschemas/` and the Unicode data under `ucd/` are networknt 3.0.7's bundled copies
//! (Apache-2.0).

mod construct;
mod datetime;
mod email;
pub(crate) mod format;
mod idn;
pub(crate) mod num;
mod refs;
mod remote;
mod stream_read;

use std::collections::HashSet;

use serde_json::{Map, Value};

use num::{Num, as_string, node_equals, node_text, num, same_value};
use refs::{Index, Target};

pub use construct::{construction_error, construction_error_at};
pub use remote::prefetch as prefetch_remote;

/// A JSON Schema specification version, in networknt's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Spec {
    Draft4,
    Draft6,
    Draft7,
    Draft201909,
    Draft202012,
}

impl Spec {
    fn id_keyword(self) -> &'static str {
        if self == Spec::Draft4 { "id" } else { "$id" }
    }
}

/// `SchemaRegistry.normalizeDialectId` then `Specification.getDialect`: the dialect a `$schema` names, `None` for an
/// unknown one.
pub fn dialect_of(id: &str) -> Option<Spec> {
    let exact = |id: &str| match id {
        "https://json-schema.org/draft/2020-12/schema" => Some(Spec::Draft202012),
        "https://json-schema.org/draft/2019-09/schema" => Some(Spec::Draft201909),
        "http://json-schema.org/draft-07/schema#" => Some(Spec::Draft7),
        "http://json-schema.org/draft-06/schema#" => Some(Spec::Draft6),
        "http://json-schema.org/draft-04/schema#" => Some(Spec::Draft4),
        _ => None,
    };
    if let Some(spec) = exact(id) {
        return Some(spec);
    }
    if !id.contains("://json-schema.org/draft") {
        return None;
    }
    if id.contains("/draft-07/") {
        Some(Spec::Draft7)
    } else if id.contains("/draft/2019-09/") {
        Some(Spec::Draft201909)
    } else if id.contains("/draft/2020-12/") {
        Some(Spec::Draft202012)
    } else if id.contains("/draft-04/") {
        Some(Spec::Draft4)
    } else if id.contains("/draft-06/") {
        Some(Spec::Draft6)
    } else {
        None
    }
}

/// `JsonSchemaValidator.getSchemaRegistry`: the default dialect MockServer configures for a user schema, from a
/// substring of its `$schema` (draft 7 otherwise).
pub fn default_dialect(schema: &Value) -> Spec {
    match schema.get("$schema").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
        Some(s) if s.contains("draft-03") || s.contains("draft-04") => Spec::Draft4,
        Some(s) if s.contains("draft-05") || s.contains("draft-06") => Spec::Draft6,
        Some(s) if s.contains("draft/2019-09") => Spec::Draft201909,
        _ => Spec::Draft7,
    }
}

/// Why evaluation stopped before producing a report.
#[derive(Debug)]
pub enum Halt {
    /// `InvalidSchemaRefException`: the reference text networknt names.
    Unresolved(String),
    /// A remote (`http`, `file`, …) reference networknt would have to fetch.
    Remote(String),
    /// A remote document that did not load (`remote::prefetch`): the report, `<exception class> - <message>`.
    Failed(String),
}

/// A reference that did not resolve, as networknt names it.
#[derive(Debug)]
pub struct UnresolvedRef(pub String);

/// Evaluates `instance` against `schema` (an assembled control-plane document, draft 7 by default): each error as
/// `Error.toString()` gives it.
pub fn validate(schema: &Value, instance: &Value) -> Result<Vec<String>, UnresolvedRef> {
    validate_with(schema, instance, Spec::Draft7).map_err(|halt| match halt {
        Halt::Unresolved(r) | Halt::Remote(r) | Halt::Failed(r) => UnresolvedRef(r),
    })
}

/// Evaluates `instance` against a user's `schema` as `JsonSchemaValidator` builds it: the default dialect from
/// [`default_dialect`], overridden by a `$schema` networknt knows.
pub fn validate_user(schema: &Value, instance: &Value) -> Result<Vec<String>, Halt> {
    validate_with(schema, instance, default_dialect(schema))
}

fn validate_with(schema: &Value, instance: &Value, default: Spec) -> Result<Vec<String>, Halt> {
    let spec = schema.get("$schema").and_then(Value::as_str).and_then(dialect_of).unwrap_or(default);
    // remote documents read when the matcher was built (`jsonSchemaAllowRemoteRefs`), each in its own dialect
    let remote = remote::reachable(schema);
    let mut index = Index::build(schema, spec);
    for (iri, document) in &remote {
        let dialect = document.get("$schema").and_then(Value::as_str).and_then(dialect_of).unwrap_or(default);
        index.add_document(iri, document, dialect);
    }
    load_meta_schemas(schema, &mut index);
    let mut run = Run { index: &index, errors: Vec::new(), ev_path: Vec::new(), annotations: Vec::new(), uneval_props: false, uneval_items: false, scope: Vec::new() };
    run.eval(&Sch { node: schema, base: String::new(), spec }, instance, "$")?;
    Ok(run.errors)
}

/// Adds every bundled meta-schema a reference in `schema` (or in a meta-schema it reaches) names.
fn load_meta_schemas<'a>(schema: &'a Value, index: &mut Index<'a>) {
    let mut pending: Vec<&'a Value> = vec![schema];
    let mut seen: HashSet<String> = HashSet::new();
    while let Some(node) = pending.pop() {
        let mut refs_found = Vec::new();
        collect_refs(node, &mut refs_found);
        for reference in refs_found {
            let doc = refs::strip_fragment(&reference).to_string();
            if !seen.insert(doc.clone()) {
                continue;
            }
            if let Some(meta) = refs::meta_schema(&doc) {
                let spec = meta.get("$schema").and_then(Value::as_str).and_then(dialect_of).unwrap_or(Spec::Draft7);
                let id = meta.get(spec.id_keyword()).and_then(Value::as_str).unwrap_or(&doc);
                index.add_document(refs::strip_fragment(id), meta, spec);
                if refs::strip_fragment(id) != doc {
                    index.add_document(&doc, meta, spec);
                }
                pending.push(meta);
            }
        }
    }
}

fn collect_refs(node: &Value, out: &mut Vec<String>) {
    match node {
        Value::Object(fields) => {
            for (k, v) in fields {
                match (k.as_str(), v) {
                    ("$ref" | "$schema" | "$dynamicRef", Value::String(s)) if s.contains("json-schema.org") => out.push(s.clone()),
                    ("enum" | "const" | "default" | "examples", _) => {}
                    _ => collect_refs(v, out),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|i| collect_refs(i, out)),
        _ => {}
    }
}

/// A schema being evaluated: its node, the base IRI of its resource, its dialect.
#[derive(Clone)]
struct Sch<'a> {
    node: &'a Value,
    base: String,
    spec: Spec,
}

impl<'a> Sch<'a> {
    fn child(&self, node: &'a Value) -> Sch<'a> {
        Sch { node, base: self.base.clone(), spec: self.spec }
    }
}

#[derive(Clone, Debug)]
enum AnnValue {
    Names(Vec<String>),
    Count(usize),
    True,
    Indexes(Vec<usize>),
}

#[derive(Clone, Debug)]
struct Annotation {
    at: String,
    ev_path: Vec<String>,
    keyword: &'static str,
    value: AnnValue,
    valid: bool,
}

struct Run<'a, 'i> {
    index: &'i Index<'a>,
    errors: Vec<String>,
    ev_path: Vec<String>,
    annotations: Vec<Annotation>,
    uneval_props: bool,
    uneval_items: bool,
    /// The evaluation schema stack (`ExecutionContext.evaluationSchema`): each schema's resource base IRI.
    scope: Vec<String>,
}

type Res = Result<(), Halt>;

/// The keywords a dialect evaluates (`KeywordType` ranges plus the 2019-09/2020-12 vocabularies).
fn active(spec: Spec, keyword: &str) -> bool {
    use Spec::*;
    match keyword {
        "additionalProperties" | "allOf" | "anyOf" | "enum" | "maxItems" | "maxLength" | "maxProperties" | "maximum" | "minItems"
        | "minLength" | "minProperties" | "minimum" | "multipleOf" | "not" | "oneOf" | "patternProperties" | "pattern" | "properties"
        | "$ref" | "required" | "type" | "uniqueItems" | "dependencies" | "notAllowed" | "format" => true,
        "items" => true,
        "const" | "contains" | "exclusiveMaximum" | "exclusiveMinimum" | "propertyNames" => spec >= Draft6,
        "if" => spec >= Draft7,
        "contentEncoding" | "contentMediaType" => spec == Draft7,
        "unevaluatedItems" | "unevaluatedProperties" | "dependentSchemas" | "dependentRequired" | "maxContains" | "minContains" => {
            spec >= Draft201909
        }
        "$recursiveRef" => spec == Draft201909,
        "$dynamicRef" | "prefixItems" => spec == Draft202012,
        _ => false,
    }
}

/// `Schema.VALIDATOR_SORT`: `type` first, then `properties`, `patternProperties`, the rest as written, and
/// `unevaluatedItems`/`unevaluatedProperties` last.
fn rank(keyword: &str) -> u8 {
    match keyword {
        "type" => 0,
        "properties" => 1,
        "patternProperties" => 2,
        "unevaluatedItems" | "unevaluatedProperties" => 4,
        _ => 3,
    }
}

impl<'a, 'i> Run<'a, 'i> {
    fn error(&mut self, at: &str, message: String) {
        self.errors.push(format!("{at}: {message}"));
    }

    /// Runs `f` with a fresh error list (`executionContext.setErrors`), returning what it collected.
    fn collect(&mut self, f: impl FnOnce(&mut Self) -> Res) -> Result<Vec<String>, Halt> {
        let saved = std::mem::take(&mut self.errors);
        let result = f(self);
        let collected = std::mem::replace(&mut self.errors, saved);
        result.map(|()| collected)
    }

    fn with_segment(&mut self, segment: impl Into<String>, f: impl FnOnce(&mut Self) -> Res) -> Res {
        self.ev_path.push(segment.into());
        let result = f(self);
        self.ev_path.pop();
        result
    }

    fn collecting(&self) -> bool {
        self.uneval_props || self.uneval_items
    }

    fn annotate(&mut self, at: &str, keyword: &'static str, value: AnnValue) {
        if self.collecting() {
            self.annotations.push(Annotation { at: at.to_string(), ev_path: self.ev_path.clone(), keyword, value, valid: true });
        }
    }

    /// `Schema.validate`.
    fn eval(&mut self, sch: &Sch<'a>, inst: &Value, at: &str) -> Res {
        let obj = match sch.node {
            Value::Bool(true) => return Ok(()),
            Value::Bool(false) => {
                // `FalseValidator`: the evaluation path's last name above the `false` keyword.
                let reason = self.ev_path.last().cloned().unwrap_or_else(|| "null".into());
                self.error(at, format!("schema for '{reason}' is false"));
                return Ok(());
            }
            Value::Object(o) => o,
            _ => return Ok(()),
        };
        let spec = obj.get("$schema").and_then(Value::as_str).and_then(dialect_of).unwrap_or(sch.spec);
        let outer_base = sch.base.clone();
        let base = match obj.get(spec.id_keyword()).and_then(Value::as_str) {
            Some(id) if !(spec <= Spec::Draft7 && id.starts_with('#')) => refs::strip_fragment(&refs::resolve(&sch.base, id)).to_string(),
            _ => sch.base.clone(),
        };
        let here = Sch { node: sch.node, base: base.clone(), spec };
        let saved_props = self.uneval_props;
        let saved_items = self.uneval_items;
        if spec >= Spec::Draft201909 {
            if obj.contains_key("unevaluatedProperties") {
                self.uneval_props = true;
            }
            if obj.contains_key("unevaluatedItems") {
                self.uneval_items = true;
            }
        }
        self.scope.push(base.clone());
        let before = self.errors.len();
        let result = self.eval_keywords(&here, obj, inst, at, &outer_base);
        self.scope.pop();
        self.uneval_props = saved_props;
        self.uneval_items = saved_items;
        if self.errors.len() > before {
            let path = self.ev_path.clone();
            for a in self.annotations.iter_mut().filter(|a| a.at == at && a.ev_path.starts_with(&path)) {
                a.valid = false;
            }
        }
        result
    }

    fn eval_keywords(&mut self, sch: &Sch<'a>, obj: &'a Map<String, Value>, inst: &Value, at: &str, outer_base: &str) -> Res {
        let spec = sch.spec;
        if spec <= Spec::Draft7
            && let Some(Value::String(reference)) = obj.get("$ref")
        {
            // `RefValidator.resolve`: a `$ref` next to an `$id` resolves against the enclosing base; with none (the
            // root), against the `$id` (oracle, `json_schema_remote_ref_reports`).
            let sibling_id = obj.get(spec.id_keyword()).and_then(Value::as_str).is_some();
            let base = if sibling_id && !outer_base.is_empty() { outer_base } else { sch.base.as_str() };
            return self.with_segment("$ref", |run| run.eval_ref(base, sch, reference, inst, at));
        }
        let mut keywords: Vec<(&'a String, &'a Value)> = obj.iter().filter(|(k, _)| active(spec, k)).collect();
        keywords.sort_by_key(|(k, _)| rank(k));
        for (keyword, value) in keywords {
            self.with_segment(keyword.as_str(), |run| run.keyword(sch, obj, keyword, value, inst, at))?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn keyword(&mut self, sch: &Sch<'a>, obj: &'a Map<String, Value>, keyword: &str, value: &'a Value, inst: &Value, at: &str) -> Res {
        let spec = sch.spec;
        match keyword {
            "type" => type_keyword(self, spec, value, inst, at),
            "properties" => {
                if let (Some(props), Value::Object(fields)) = (value.as_object(), inst) {
                    let mut matched = Vec::new();
                    for (name, sub) in props {
                        if let Some(child) = fields.get(name) {
                            matched.push(name.clone());
                            self.with_segment(name.as_str(), |run| run.eval(&sch.child(sub), child, &append(at, name)))?;
                        }
                    }
                    self.annotate(at, "properties", AnnValue::Names(matched));
                }
            }
            "patternProperties" => {
                if let (Some(patterns), Value::Object(fields)) = (value.as_object(), inst) {
                    let mut matched = Vec::new();
                    for (name, child) in fields {
                        for (pattern, sub) in patterns {
                            if pattern_matches(pattern, name) {
                                let before = self.errors.len();
                                self.with_segment(pattern.as_str(), |run| run.eval(&sch.child(sub), child, &append(at, name)))?;
                                if self.errors.len() == before {
                                    matched.push(name.clone());
                                }
                            }
                        }
                    }
                    self.annotate(at, "patternProperties", AnnValue::Names(matched));
                }
            }
            "additionalProperties" => {
                if let Value::Object(fields) = inst {
                    let declared = obj.get("properties").and_then(Value::as_object);
                    let patterns = obj.get("patternProperties").and_then(Value::as_object);
                    let allow = !matches!(value, Value::Bool(false)) && (value.is_boolean() || value.is_object());
                    for (name, child) in fields {
                        if declared.is_some_and(|d| d.contains_key(name)) || patterns.is_some_and(|p| p.keys().any(|re| pattern_matches(re, name))) {
                            continue;
                        }
                        if !allow {
                            self.error(at, format!("property '{name}' is not defined in the schema and the schema does not allow additional properties"));
                        } else if value.is_object() {
                            self.eval(&sch.child(value), child, &append(at, name))?;
                        }
                    }
                    if allow {
                        self.annotate(at, "additionalProperties", AnnValue::Names(fields.keys().cloned().collect()));
                    }
                }
            }
            "required" => {
                if let (Some(names), Value::Object(fields)) = (value.as_array(), inst) {
                    for name in names.iter().map(as_string) {
                        if !fields.contains_key(&name) {
                            self.error(at, format!("required property '{name}' not found"));
                        }
                    }
                }
            }
            "enum" => enum_keyword(self, value, inst, at),
            "const" => const_keyword(self, value, inst, at),
            "anyOf" => {
                if let Some(branches) = value.as_array() {
                    let short_circuit = !self.collecting();
                    let mut all = Vec::new();
                    let mut valid = false;
                    for (i, branch) in branches.iter().enumerate() {
                        let sub = self.collect(|run| run.with_segment(i.to_string(), |run| run.eval(&sch.child(branch), inst, at)))?;
                        if sub.is_empty() {
                            valid = true;
                            if short_circuit {
                                break;
                            }
                        } else {
                            all.extend(sub);
                        }
                    }
                    if !valid {
                        self.errors.extend(all);
                    }
                }
            }
            "oneOf" => {
                if let Some(branches) = value.as_array() {
                    let short_circuit = !self.collecting();
                    let mut all = Vec::new();
                    let mut indexes = Vec::new();
                    for (i, branch) in branches.iter().enumerate() {
                        let sub = self.collect(|run| run.with_segment(i.to_string(), |run| run.eval(&sch.child(branch), inst, at)))?;
                        if sub.is_empty() {
                            indexes.push(i.to_string());
                        } else {
                            all.extend(sub);
                        }
                        if indexes.len() > 1 && short_circuit {
                            break;
                        }
                    }
                    if indexes.len() != 1 {
                        let line = match indexes.len() {
                            0 => "must be valid to one and only one schema, but 0 are valid".to_string(),
                            n => format!("must be valid to one and only one schema, but {n} are valid with indexes '{}'", indexes.join(", ")),
                        };
                        self.error(at, line);
                        self.errors.extend(all);
                    }
                }
            }
            "allOf" => {
                if let Some(branches) = value.as_array() {
                    for (i, branch) in branches.iter().enumerate() {
                        self.with_segment(i.to_string(), |run| run.eval(&sch.child(branch), inst, at))?;
                    }
                }
            }
            "not" => {
                let sub = self.collect(|run| run.eval(&sch.child(value), inst, at))?;
                if sub.is_empty() {
                    self.error(at, format!("must not be valid to the schema {}", node_text(value)));
                }
            }
            "if" => {
                let sub = self.collect(|run| run.eval(&sch.child(value), inst, at))?;
                let (name, branch) = if sub.is_empty() { ("then", obj.get("then")) } else { ("else", obj.get("else")) };
                if let Some(branch) = branch {
                    self.ev_path.pop();
                    let result = self.with_segment(name, |run| run.eval(&sch.child(branch), inst, at));
                    self.ev_path.push("if".into());
                    result?;
                }
            }
            "items" => {
                if let Value::Array(items) = inst {
                    if spec == Spec::Draft202012 {
                        let prefix = obj.get("prefixItems").and_then(Value::as_array).map_or(0, Vec::len);
                        let mut evaluated = false;
                        for (i, item) in items.iter().enumerate().skip(prefix) {
                            if value == &Value::Bool(false) {
                                self.error(at, format!("index '{i}' is not defined in the schema and the schema does not allow additional items"));
                            } else {
                                self.eval(&sch.child(value), item, &format!("{at}[{i}]"))?;
                            }
                            evaluated = true;
                        }
                        if evaluated {
                            self.annotate(at, "items", AnnValue::True);
                        }
                    } else {
                        items_legacy(self, sch, obj, value, items, at)?;
                    }
                }
            }
            "prefixItems" => {
                if let (Some(tuple), Value::Array(items)) = (value.as_array(), inst) {
                    for (i, (sub, item)) in tuple.iter().zip(items).enumerate() {
                        self.with_segment(i.to_string(), |run| run.eval(&sch.child(sub), item, &format!("{at}[{i}]")))?;
                    }
                    let annotation = if items.len() > tuple.len() { AnnValue::Count(tuple.len()) } else { AnnValue::True };
                    self.annotate(at, "prefixItems", annotation);
                }
            }
            "contains" => contains_keyword(self, sch, obj, value, inst, at)?,
            "maxContains" | "minContains" => {
                // `MinMaxContainsValidator`: only the keywords' own values are checked, once (from `maxContains`).
                let present = |k: &str| obj.get(k);
                if keyword == "minContains" && present("maxContains").is_some() {
                    return Ok(());
                }
                let valid = |v: &Value| v.as_number().map(num).is_some_and(|n| n.exact_integral() && n.as_f64() >= 0.0);
                let mut min = 1.0;
                let mut max = i32::MAX as f64;
                let mut problems = Vec::new();
                if let Some(v) = present("minContains") {
                    if valid(v) {
                        min = v.as_number().map(num).map_or(1.0, |n| n.as_f64());
                    } else {
                        problems.push("minContains");
                    }
                }
                if let Some(v) = present("maxContains") {
                    if valid(v) {
                        max = v.as_number().map(num).map_or(max, |n| n.as_f64());
                    } else {
                        problems.push("maxContains");
                    }
                }
                if max < min {
                    problems.push("minContainsVsMaxContains");
                }
                let parent = node_text(sch.node);
                for problem in problems {
                    let message = if problem == "minContainsVsMaxContains" {
                        format!("minContains must less than or equal to maxContains in {parent}")
                    } else {
                        format!("must be a non-negative integer in {parent}")
                    };
                    self.error(at, message);
                }
            }
            "minItems" | "maxItems" => {
                if let Value::Array(items) = inst {
                    let limit = int_limit(value);
                    let size = items.len() as i64;
                    if keyword == "minItems" && size < limit {
                        self.error(at, format!("must have at least {} items but found {}", java_int(limit), java_int(size)));
                    } else if keyword == "maxItems" && size > limit {
                        self.error(at, format!("must have at most {} items but found {}", java_int(limit), java_int(size)));
                    }
                }
            }
            "uniqueItems" => {
                if value.as_bool() == Some(true) {
                    let values: Vec<&Value> = match inst {
                        Value::Array(items) => items.iter().collect(),
                        Value::Object(fields) => fields.values().collect(),
                        _ => Vec::new(),
                    };
                    let keys: Vec<String> = values.iter().map(|v| comparison_key(v)).collect();
                    for (i, key) in keys.iter().enumerate() {
                        if keys[..i].contains(key) {
                            self.error(at, "must have only unique items in the array".into());
                        }
                    }
                }
            }
            "minimum" | "maximum" => bound_keyword(self, spec, obj, keyword, value, inst, at),
            "exclusiveMinimum" | "exclusiveMaximum" => exclusive_keyword(self, obj, keyword, value, inst, at),
            "multipleOf" => {
                if let (Some(divisor), Value::Number(n)) = (value.as_number().map(num), inst) {
                    let d = divisor.as_f64();
                    let n = num(n);
                    if d != 0.0 && d.is_finite() && !n.non_finite() {
                        let divisor = jackson::bigdecimal::BigDecimal::value_of_f64(d).strip_trailing_zeros();
                        let dividend = jackson::bigdecimal::BigDecimal::value_of_f64(n.as_f64());
                        if !num::is_multiple(&dividend, &divisor) {
                            self.error(at, format!("must be multiple of {}", divisor.to_java_string()));
                        }
                    }
                }
            }
            "minLength" | "maxLength" => {
                if let Value::String(s) = inst {
                    let limit = int_limit(value);
                    let length = s.chars().count() as i64;
                    if keyword == "minLength" && length < limit {
                        self.error(at, format!("must be at least {} characters long", java_int(limit)));
                    } else if keyword == "maxLength" && length > limit {
                        self.error(at, format!("must be at most {} characters long", java_int(limit)));
                    }
                }
            }
            "pattern" => {
                if let (Some(pattern), Value::String(s)) = (value.as_str(), inst)
                    && !pattern_matches(pattern, s)
                {
                    self.error(at, format!("does not match the regex pattern {pattern}"));
                }
            }
            "minProperties" | "maxProperties" => {
                if let Value::Object(fields) = inst {
                    let limit = int_limit(value);
                    let size = fields.len() as i64;
                    if keyword == "minProperties" && size < limit {
                        self.error(at, format!("must have at least {} properties", java_int(limit)));
                    } else if keyword == "maxProperties" && size > limit {
                        self.error(at, format!("must have at most {} properties", java_int(limit)));
                    }
                }
            }
            "propertyNames" => {
                if let Value::Object(fields) = inst {
                    for name in fields.keys() {
                        let location = append(at, name);
                        let sub = self.collect(|run| run.eval(&sch.child(value), &Value::String(name.clone()), &location))?;
                        for e in sub {
                            // `Error.getMessage()`: the text without its location.
                            let message = e.strip_prefix(&format!("{location}: ")).or_else(|| e.split_once(": ").map(|(_, m)| m)).unwrap_or(&e).to_string();
                            self.error(at, format!("property '{name}' name is not valid: {message}"));
                        }
                    }
                }
            }
            "dependencies" => {
                if let (Some(deps), Value::Object(fields)) = (value.as_object(), inst) {
                    let property_deps: Vec<(String, Vec<String>)> =
                        deps.iter().filter_map(|(k, v)| v.as_array().map(|a| (k.clone(), a.iter().map(as_string).collect()))).collect();
                    for name in fields.keys() {
                        if let Some((_, required)) = property_deps.iter().find(|(k, _)| k == name) {
                            for field in required {
                                if !fields.contains_key(field) {
                                    self.error(at, format!("has an error with dependencies {}", java_map_text(&property_deps)));
                                }
                            }
                        }
                        if let Some(sub) = deps.get(name).filter(|v| v.is_object() || v.is_boolean()) {
                            self.with_segment(name.as_str(), |run| run.eval(&sch.child(sub), inst, at))?;
                        }
                    }
                }
            }
            "dependentRequired" => {
                if let (Some(deps), Value::Object(fields)) = (value.as_object(), inst) {
                    for name in fields.keys() {
                        for field in deps.get(name).and_then(Value::as_array).into_iter().flatten().map(as_string) {
                            if !fields.contains_key(&field) {
                                self.error(at, format!("has a missing property '{field}' which is dependent required because '{name}' is present"));
                            }
                        }
                    }
                }
            }
            "dependentSchemas" => {
                if let (Some(deps), Value::Object(fields)) = (value.as_object(), inst) {
                    for name in fields.keys() {
                        if let Some(sub) = deps.get(name).filter(|v| v.is_object() || v.is_boolean()) {
                            self.with_segment(name.as_str(), |run| run.eval(&sch.child(sub), inst, at))?;
                        }
                    }
                }
            }
            "unevaluatedProperties" => unevaluated_properties(self, sch, value, inst, at)?,
            "unevaluatedItems" => unevaluated_items(self, sch, value, inst, at)?,
            "format" => {
                if let (Some(name), Value::String(s)) = (value.as_str(), inst)
                    && spec <= Spec::Draft7
                    && let Some(key) = format::failure(name, s)
                {
                    let message = match key {
                        Some(detail) => format!("does not match the {name} pattern {detail}"),
                        None => format!("does not match the {name} pattern"),
                    };
                    self.error(at, message);
                }
            }
            "contentEncoding" => {
                if let (Some(encoding), Value::String(s)) = (value.as_str(), inst)
                    && encoding == "base64"
                    && !java_base64_decodes(s)
                {
                    self.error(at, format!("does not match content encoding {encoding}"));
                }
            }
            "contentMediaType" => {
                if let (Some(media_type), Value::String(s)) = (value.as_str().map(str::to_string).or_else(|| Some(as_string(value))), inst)
                    && !content_media_type_matches(&media_type, obj, s)
                {
                    self.error(at, "is not a content media type".into());
                }
            }
            "notAllowed" => {
                if let (Some(names), Value::Object(fields)) = (value.as_array(), inst) {
                    for name in names.iter().map(as_string) {
                        if fields.contains_key(&name) {
                            self.error(&append(at, &name), format!("property '{name}' is not allowed but it is in the data"));
                        }
                    }
                }
            }
            "$ref" => {
                if let Some(reference) = value.as_str() {
                    self.eval_ref(&sch.base, sch, reference, inst, at)?;
                }
            }
            "$recursiveRef" => {
                let target = self.recursive_target(sch);
                if let Some(target) = target {
                    self.eval(&target, inst, at)?;
                } else {
                    return Err(Halt::Unresolved(node_text(value)));
                }
            }
            "$dynamicRef" => {
                if let Some(reference) = value.as_str() {
                    match self.dynamic_target(sch, reference) {
                        Some(target) => self.eval(&target, inst, at)?,
                        None => self.eval_ref(&sch.base, sch, reference, inst, at)?,
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// `RefValidator`: the target of `reference` (relative to `base`), evaluated in place.
    fn eval_ref(&mut self, base: &str, sch: &Sch<'a>, reference: &str, inst: &Value, at: &str) -> Res {
        let target = self.resolve_ref(base, sch.spec, reference)?;
        self.eval(&target, inst, at)
    }

    fn resolve_ref(&self, base: &str, spec: Spec, reference: &str) -> Result<Sch<'a>, Halt> {
        let absolute = refs::resolve(base, reference);
        let (doc, fragment) = match absolute.split_once('#') {
            Some((d, f)) => (d.to_string(), Some(f.to_string())),
            None => (absolute.clone(), None),
        };
        let resource = match self.index.get(&doc) {
            Some(t) => t.clone(),
            None if doc.is_empty() => return Err(Halt::Unresolved(reference.to_string())),
            None if refs::is_remote(&doc) => {
                return Err(match remote::get(&doc) {
                    Some(Err(report)) => Halt::Failed(report),
                    _ => Halt::Remote(reference.to_string()),
                });
            }
            None => return Err(Halt::Unresolved(reference.to_string())),
        };
        let _ = spec;
        match fragment.as_deref() {
            None | Some("") => Ok(Sch { node: resource.node, base: resource.base, spec: resource.spec }),
            Some(f) if f.starts_with('/') => {
                let mut node = resource.node;
                let mut base = resource.base.clone();
                let mut spec = resource.spec;
                let segments: Vec<String> = f[1..].split('/').map(|s| percent_decode(s).replace("~1", "/").replace("~0", "~")).collect();
                let count = segments.len();
                for (i, segment) in segments.iter().enumerate() {
                    let next = match node {
                        Value::Object(o) => o.get(segment),
                        Value::Array(a) => segment.parse::<usize>().ok().and_then(|n| a.get(n)),
                        _ => None,
                    };
                    let Some(next) = next else {
                        return Err(Halt::Unresolved(format!("/{}", &f[1..])));
                    };
                    node = next;
                    if i + 1 < count
                        && let Value::Object(o) = node
                    {
                        spec = o.get("$schema").and_then(Value::as_str).and_then(dialect_of).unwrap_or(spec);
                        if let Some(id) = o.get(spec.id_keyword()).and_then(Value::as_str)
                            && !(spec <= Spec::Draft7 && id.starts_with('#'))
                        {
                            base = refs::strip_fragment(&refs::resolve(&base, id)).to_string();
                        }
                    }
                }
                Ok(Sch { node, base, spec })
            }
            Some(anchor) => match self.index.get(&format!("{doc}#{anchor}")) {
                Some(Target { node, base, spec }) => Ok(Sch { node, base: base.clone(), spec: *spec }),
                None => Err(Halt::Unresolved(reference.to_string())),
            },
        }
    }

    /// `RecursiveRefValidator.getSchema`: the current resource root, or — when it has `$recursiveAnchor: true` — the
    /// outermost resource root in the dynamic scope that has one too.
    fn recursive_target(&self, sch: &Sch<'a>) -> Option<Sch<'a>> {
        let resource = self.index.get(&sch.base)?;
        let mut target = Sch { node: resource.node, base: resource.base.clone(), spec: resource.spec };
        if self.index.recursive.get(&sch.base).copied().unwrap_or(false) {
            let mut base = sch.base.clone();
            for scope_base in self.scope.iter().rev() {
                if *scope_base != base {
                    base = scope_base.clone();
                    if self.index.recursive.get(scope_base).copied().unwrap_or(false)
                        && let Some(t) = self.index.get(scope_base)
                    {
                        target = Sch { node: t.node, base: t.base.clone(), spec: t.spec };
                    }
                }
            }
        }
        Some(target)
    }

    /// `DynamicRefValidator.getRefSchema` for a reference to a `$dynamicAnchor`.
    fn dynamic_target(&self, sch: &Sch<'a>, reference: &str) -> Option<Sch<'a>> {
        let absolute = refs::resolve(&sch.base, reference);
        let found = self.index.dynamic.get(&absolute)?;
        let mut target = Sch { node: found.node, base: found.base.clone(), spec: found.spec };
        let (doc, anchor) = absolute.split_once('#')?;
        let mut base = doc.to_string();
        for scope_base in self.scope.iter().rev() {
            if *scope_base != base {
                base = scope_base.clone();
                if let Some(t) = self.index.dynamic.get(&format!("{scope_base}#{anchor}")) {
                    target = Sch { node: t.node, base: t.base.clone(), spec: t.spec };
                }
            }
        }
        Some(target)
    }
}

/// `ItemsLegacyValidator`: `items` as one schema or a tuple, with `additionalItems`.
fn items_legacy<'a>(run: &mut Run<'a, '_>, sch: &Sch<'a>, obj: &'a Map<String, Value>, value: &'a Value, items: &[Value], at: &str) -> Res {
    match value {
        Value::Array(tuple) => {
            let additional = obj.get("additionalItems");
            let mut has_additional = false;
            for (i, item) in items.iter().enumerate() {
                let path = format!("{at}[{i}]");
                match tuple.get(i) {
                    Some(sub) => run.with_segment(i.to_string(), |run| run.eval(&sch.child(sub), item, &path))?,
                    None => match additional {
                        Some(extra @ Value::Object(_)) => {
                            has_additional = true;
                            run.ev_path.pop();
                            let result = run.with_segment("additionalItems", |run| run.eval(&sch.child(extra), item, &path));
                            run.ev_path.push("items".into());
                            result?;
                        }
                        Some(Value::Bool(false)) => {
                            run.error(at, format!("index '{i}' is not defined in the schema and the schema does not allow additional items"));
                        }
                        Some(Value::Bool(true)) => has_additional = true,
                        _ => {}
                    },
                }
            }
            let annotation = if items.len() > tuple.len() { AnnValue::Count(tuple.len()) } else { AnnValue::True };
            run.annotate(at, "items", annotation);
            if has_additional && run.collecting() {
                run.ev_path.pop();
                run.ev_path.push("additionalItems".into());
                run.annotate(at, "additionalItems", AnnValue::True);
                run.ev_path.pop();
                run.ev_path.push("items".into());
            }
        }
        Value::Object(_) | Value::Bool(_) => {
            run.annotate(at, "items", AnnValue::True);
            for (i, item) in items.iter().enumerate() {
                run.eval(&sch.child(value), item, &format!("{at}[{i}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// `ContainsValidator`.
fn contains_keyword<'a>(run: &mut Run<'a, '_>, sch: &Sch<'a>, obj: &'a Map<String, Value>, value: &'a Value, inst: &Value, at: &str) -> Res {
    if !(value.is_object() || value.is_boolean()) {
        return Ok(());
    }
    let bound = |k: &str| obj.get(k).and_then(Value::as_number).map(num).filter(Num::exact_integral).map(|n| n.as_long() as i32);
    let (min, max) = (bound("minContains"), bound("maxContains"));
    let Value::Array(items) = inst else {
        return Ok(());
    };
    let mut indexes = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let sub = run.collect(|run| run.eval(&sch.child(value), item, &format!("{at}[{i}]")))?;
        if sub.is_empty() {
            indexes.push(i);
        }
    }
    let actual = indexes.len() as i64;
    let v2019 = sch.spec >= Spec::Draft201909;
    let schema_text = node_text(value);
    let m = min.unwrap_or(1) as i64;
    if actual < m {
        let message = if v2019 {
            format!("must contain at least {m} element(s) that passes these validations: {schema_text}")
        } else {
            format!("does not contain an element that passes these validations: {schema_text}")
        };
        run.error(at, message);
    }
    if let Some(max) = max
        && actual > max as i64
    {
        let message = if v2019 {
            format!("must contain at most {max} element(s) that passes these validations: {schema_text}")
        } else {
            format!("does not contain an element that passes these validations: {schema_text}")
        };
        run.error(at, message);
    }
    let annotation = if indexes.len() == items.len() { AnnValue::True } else { AnnValue::Indexes(indexes) };
    run.annotate(at, "contains", annotation);
    Ok(())
}

/// The annotations `unevaluated*` reads: at `at`, under the parent of the current evaluation path, still valid.
fn adjacent<'r>(run: &'r Run<'_, '_>, at: &str, keyword: &str) -> Vec<&'r AnnValue> {
    let parent = &run.ev_path[..run.ev_path.len().saturating_sub(1)];
    run.annotations.iter().filter(|a| a.at == at && a.keyword == keyword && a.valid && a.ev_path.starts_with(parent)).map(|a| &a.value).collect()
}

/// `UnevaluatedPropertiesValidator`.
fn unevaluated_properties<'a>(run: &mut Run<'a, '_>, sch: &Sch<'a>, value: &'a Value, inst: &Value, at: &str) -> Res {
    let Value::Object(fields) = inst else {
        return Ok(());
    };
    let mut evaluated: HashSet<String> = HashSet::new();
    for keyword in ["properties", "patternProperties", "additionalProperties", "unevaluatedProperties"] {
        for v in adjacent(run, at, keyword) {
            if let AnnValue::Names(names) = v {
                evaluated.extend(names.iter().cloned());
            }
        }
    }
    let mut newly = Vec::new();
    for (name, child) in fields {
        if evaluated.contains(name) {
            continue;
        }
        newly.push(name.clone());
        if value == &Value::Bool(false) {
            run.error(at, format!("property '{name}' is not evaluated and the schema does not allow unevaluated properties"));
        } else {
            run.eval(&sch.child(value), child, &append(at, name))?;
        }
    }
    run.annotate(at, "unevaluatedProperties", AnnValue::Names(newly));
    Ok(())
}

/// `UnevaluatedItemsValidator`.
fn unevaluated_items<'a>(run: &mut Run<'a, '_>, sch: &Sch<'a>, value: &'a Value, inst: &Value, at: &str) -> Res {
    let Value::Array(items) = inst else {
        return Ok(());
    };
    let v2020 = sch.spec >= Spec::Draft202012;
    let (items_keyword, additional_keyword) = if v2020 { ("prefixItems", "items") } else { ("items", "additionalItems") };
    let mut valid = false;
    let mut valid_count = 0usize;
    let mut evaluated = false;
    if value == &Value::Bool(true) {
        valid = true;
        evaluated = !items.is_empty();
    } else {
        for v in adjacent(run, at, items_keyword) {
            match v {
                AnnValue::Count(n) => valid_count = valid_count.max(*n),
                AnnValue::True => valid = true,
                _ => {}
            }
        }
        if !valid {
            valid = adjacent(run, at, additional_keyword).iter().any(|v| matches!(v, AnnValue::True))
                || adjacent(run, at, "unevaluatedItems").iter().any(|v| matches!(v, AnnValue::True));
        }
    }
    if !valid {
        let mut contained: HashSet<usize> = HashSet::new();
        let mut all = false;
        for v in adjacent(run, at, "contains") {
            match v {
                AnnValue::Indexes(ix) => contained.extend(ix.iter().copied()),
                AnnValue::True => all = true,
                _ => {}
            }
        }
        if !all {
            for (x, item) in items.iter().enumerate().skip(valid_count) {
                if contained.contains(&x) {
                    continue;
                }
                if value == &Value::Bool(false) {
                    run.error(at, format!("index '{x}' is not evaluated and the schema does not allow unevaluated items"));
                } else {
                    run.eval(&sch.child(value), item, &format!("{at}[{x}]"))?;
                }
                evaluated = true;
            }
        }
    }
    if evaluated {
        run.annotate(at, "unevaluatedItems", AnnValue::True);
    }
    Ok(())
}

/// `TypeValidator` / `UnionTypeValidator`.
fn type_keyword(run: &mut Run<'_, '_>, spec: Spec, expected: &Value, inst: &Value, at: &str) {
    let found = type_name(inst);
    match expected {
        Value::Array(types) => {
            let ok = types.iter().any(|t| match t {
                Value::String(t) => type_matches(spec, t, inst),
                // An object element is a schema; MockServer's never use one.
                _ => false,
            });
            if !ok {
                let listed: Vec<&str> = types.iter().map(schema_type_name).collect();
                run.error(at, format!("{found} found, [{}] expected", listed.join(", ")));
            }
        }
        other => {
            let name = schema_type_name(other);
            if !(other.as_str().is_some_and(|t| type_matches(spec, t, inst))) {
                run.error(at, format!("{found} found, {name} expected"));
            }
        }
    }
}

/// `TypeFactory.getSchemaNodeType`.
fn schema_type_name(v: &Value) -> &'static str {
    match v.as_str() {
        Some("object") => "object",
        Some("array") => "array",
        Some("string") => "string",
        Some("number") => "number",
        Some("integer") => "integer",
        Some("boolean") => "boolean",
        Some("any") => "any",
        Some("null") => "null",
        _ if v.is_array() => "union",
        _ => "unknown",
    }
}

/// `JsonNodeTypes.equalsToSchemaType`.
fn type_matches(spec: Spec, expected: &str, inst: &Value) -> bool {
    let found = type_name(inst);
    found == expected
        || (expected == "number" && found == "integer")
        || (expected == "integer" && found == "number" && spec >= Spec::Draft6 && inst.as_number().map(num).is_some_and(|n| n.exact_integral()))
        || expected == "any"
}

/// `TypeFactory.getValueNodeType`: a number is an integer when Jackson reads it as an integral node; a non-finite
/// double is `unknown`.
pub fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) => match num(n) {
            Num::Int(_) => "integer",
            n if n.non_finite() => "unknown",
            _ => "number",
        },
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// `EnumValidator`: numbers (and numbers directly inside an array) compared by value, everything else as Jackson's
/// `equals` (an integer never equals a double inside an object).
fn enum_keyword(run: &mut Run<'_, '_>, value: &Value, inst: &Value, at: &str) {
    let Some(options) = value.as_array() else {
        run.error(at, "does not have a value in the enumeration [none]".into());
        return;
    };
    let normalized = |v: &Value| -> Value {
        match v {
            Value::Array(items) => Value::Array(items.iter().map(normalize_number).collect()),
            other => normalize_number(other),
        }
    };
    let target = normalized(inst);
    if !options.iter().any(|o| node_equals(&normalized(o), &target)) {
        let listed: Vec<String> = options.iter().map(enum_text).collect();
        run.error(at, format!("does not have a value in the enumeration [{}]", listed.join(", ")));
    }
}

/// `processNumberNode`: a finite number becomes its stripped decimal (kept here as a canonical double-free text).
fn normalize_number(v: &Value) -> Value {
    match v {
        Value::Number(n) => {
            let n = num(n);
            match n.decimal() {
                Some(d) => Value::String(format!("\u{0}num:{}", d.strip_trailing_zeros().to_java_string())),
                None => Value::String(format!("\u{0}nonfinite:{}", n.text())),
            }
        }
        other => other.clone(),
    }
}

/// `EnumValidator.asString`: containers and strings as JSON, scalars as `asString()` (null is empty).
fn enum_text(v: &Value) -> String {
    match v {
        Value::String(_) | Value::Array(_) | Value::Object(_) => node_text(v),
        other => as_string(other),
    }
}

/// `ConstValidator`.
fn const_keyword(run: &mut Run<'_, '_>, value: &Value, inst: &Value, at: &str) {
    let text = |v: &Value| match v {
        Value::Array(_) | Value::Object(_) => node_text(v),
        Value::Null => "null".to_string(),
        other => as_string(other),
    };
    let equal = match (value, inst) {
        (Value::Number(a), Value::Number(b)) => {
            let (a, b) = (num(a), num(b));
            if a.non_finite() || b.non_finite() { a.non_finite() == b.non_finite() && a.as_f64() == b.as_f64() } else { same_value(&a, &b) }
        }
        _ => node_equals(value, inst),
    };
    if !equal {
        run.error(at, format!("must be the constant value '{}'", text(value)));
    }
}

/// `UniqueItemsValidator.comparisonKey`: numbers by stripped decimal value, recursively.
fn comparison_key(v: &Value) -> String {
    match v {
        Value::Number(n) => {
            let n = num(n);
            match n.decimal() {
                Some(d) => format!("n:{}", d.strip_trailing_zeros().to_java_string()),
                None => format!("d:{}", n.text()),
            }
        }
        Value::Array(items) => format!("[{}]", items.iter().map(comparison_key).collect::<Vec<_>>().join(",")),
        Value::Object(fields) => {
            format!("{{{}}}", fields.iter().map(|(k, v)| format!("{}:{}", Value::String(k.clone()), comparison_key(v))).collect::<Vec<_>>().join(","))
        }
        other => format!("v:{other}"),
    }
}

/// `MinimumValidator` / `MaximumValidator` (with draft 4's boolean `exclusiveMinimum`/`exclusiveMaximum`).
fn bound_keyword(run: &mut Run<'_, '_>, _spec: Spec, obj: &Map<String, Value>, keyword: &str, value: &Value, inst: &Value, at: &str) {
    let (Some(limit), Value::Number(n)) = (value.as_number().map(num), inst) else {
        return;
    };
    let n = num(n);
    // `JsonNodeTypes.isNumber`: a non-finite double is not checked.
    if n.non_finite() {
        return;
    }
    let minimum = keyword == "minimum";
    let exclusive_key = if minimum { "exclusiveMinimum" } else { "exclusiveMaximum" };
    let exclude_equal = obj.get(exclusive_key).and_then(Value::as_bool).unwrap_or(false);
    let (crosses, threshold) = threshold_crossed(obj, &limit, &n, minimum, exclude_equal);
    if crosses {
        let text = if minimum { "must have a minimum value of" } else { "must have a maximum value of" };
        run.error(at, format!("{text} {threshold}"));
    }
}

/// `ExclusiveMinimumValidator` / `ExclusiveMaximumValidator` (drafts 6 on, numeric).
fn exclusive_keyword(run: &mut Run<'_, '_>, obj: &Map<String, Value>, keyword: &str, value: &Value, inst: &Value, at: &str) {
    let (Some(limit), Value::Number(n)) = (value.as_number().map(num), inst) else {
        return;
    };
    let n = num(n);
    if n.non_finite() {
        return;
    }
    let minimum = keyword == "exclusiveMinimum";
    let (crosses, threshold) = threshold_crossed(obj, &limit, &n, minimum, true);
    if crosses {
        let text = if minimum { "must have an exclusive minimum value of" } else { "must have an exclusive maximum value of" };
        run.error(at, format!("{text} {threshold}"));
    }
}

/// `ThresholdMixin.crossesThreshold` and `thresholdValue`: a `long` comparison (`asLong()`) when the limit is an
/// integral literal and the schema's `type` includes `integer`, a `BigDecimal` one otherwise.
fn threshold_crossed(obj: &Map<String, Value>, limit: &Num, n: &Num, minimum: bool, exclude_equal: bool) -> (bool, String) {
    let integer_typed = match obj.get("type") {
        Some(Value::String(t)) => t == "integer",
        Some(Value::Array(ts)) => ts.iter().any(|t| t.as_str() == Some("integer")),
        _ => false,
    };
    if limit.is_long() && integer_typed {
        let lim = limit.as_long();
        let ord = match n {
            Num::Int(i) => num_bigint::BigInt::from(lim).cmp(i).reverse(),
            Num::Double(_) => n.as_long().cmp(&lim),
        };
        let crosses = if minimum { ord.is_lt() || (exclude_equal && ord.is_eq()) } else { ord.is_gt() || (exclude_equal && ord.is_eq()) };
        return (crosses, lim.to_string());
    }
    let threshold = limit.text();
    let crosses = match limit {
        Num::Double(l) if l.is_infinite() => (*l < 0.0) != minimum,
        _ => match (limit.decimal(), n.decimal()) {
            (Some(l), Some(v)) => {
                let ord = v.compare_to(&l);
                if minimum { ord.is_lt() || (exclude_equal && ord.is_eq()) } else { ord.is_gt() || (exclude_equal && ord.is_eq()) }
            }
            _ => false,
        },
    };
    (crosses, threshold)
}

/// A non-negative `int` limit (`canConvertToExactIntegral` then `intValue()`), `Integer.MAX_VALUE` otherwise.
fn int_limit(v: &Value) -> i64 {
    match v.as_number().map(num) {
        Some(n) if n.exact_integral() => n.as_long() as i32 as i64,
        _ => i32::MAX as i64,
    }
}

/// `Base64.getDecoder().decode(s)` succeeds.
fn java_base64_decodes(s: &str) -> bool {
    use base64::Engine;
    let config = base64::engine::GeneralPurposeConfig::new().with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent);
    base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, config).decode(s).is_ok()
}

/// `ContentMediaTypeValidator.matches`.
fn content_media_type_matches(media_type: &str, obj: &Map<String, Value>, value: &str) -> bool {
    if media_type == "application/json" {
        let mut data = value.to_string();
        if obj.get("contentEncoding").and_then(Value::as_str) == Some("base64") {
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(value) {
                Ok(bytes) => data = String::from_utf8_lossy(&bytes).into_owned(),
                Err(_) => return true,
            }
        }
        return serde_json::from_str::<Value>(&data).is_ok();
    }
    static PATTERN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new("^(?:(application|audio|font|example|image|message|model|multipart|text|video|x-(?:[0-9A-Za-z!#$%&'*+.^_`|~-]+))/([0-9A-Za-z!#$%&'*+.^_`|~-]+)((?:[ \t]*;[ \t]*[0-9A-Za-z!#$%&'*+.^_`|~-]+=(?:[0-9A-Za-z!#$%&'*+.^_`|~-]+|\"(?:[^\"\\\\]|\\\\.)*\"))*))$")
            .expect("media type pattern")
    });
    PATTERN.is_match(media_type)
}

/// A Java `HashMap<String, List<String>>.toString()`: `{a=[b, c], d=[e]}` in hash order.
fn java_map_text(entries: &[(String, Vec<String>)]) -> String {
    let keys: Vec<String> = entries.iter().map(|(k, _)| k.clone()).collect();
    let parts: Vec<String> = crate::recorded::java_hashmap_order(&keys)
        .into_iter()
        .map(|i| format!("{}=[{}]", entries[i].0, entries[i].1.join(", ")))
        .collect();
    format!("{{{}}}", parts.join(", "))
}

/// `JDKRegularExpression.matches`: `find()` with `$` as `\z` outside character classes (networknt's
/// `replaceDollarAnchors`) and the long-form `\p{…}` names.
pub fn pattern_matches(pattern: &str, text: &str) -> bool {
    format::java_regex(&format::replace_dollar_anchors(pattern)).map_or(true, |re| re.try_find(text).unwrap_or(true))
}

fn percent_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Some(b) = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `PathType.JSON_PATH`: shorthand `.name` for `[A-Za-z_\u0080-][A-Za-z0-9_\u0080-]*`, else `['name']`.
pub fn append(path: &str, name: &str) -> String {
    let first = |c: char| c.is_ascii_alphabetic() || c == '_' || !c.is_ascii();
    let rest = |c: char| first(c) || c.is_ascii_digit();
    let mut chars = name.chars();
    if chars.next().is_some_and(first) && chars.all(rest) {
        return format!("{path}.{name}");
    }
    let escaped = name
        .replace('\'', "\\'")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\u{8}', "\\b")
        .replace('\u{c}', "\\f");
    format!("{path}['{escaped}']")
}

/// An `int` argument through `MessageFormat` (grouped by thousands in the default locale).
fn java_int(n: i64) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::new();
    if n < 0 {
        out.push('-');
    }
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn any_of_reports_every_branch_and_one_of_its_own_line() {
        let schema = json!({
            "type": "object",
            "properties": {
                "a": {"anyOf": [{"type": "string"}, {"type": "object", "required": ["x"]}]},
                "b": {"oneOf": [{"type": "string"}, {"type": "integer"}]}
            }
        });
        let mut errors = validate(&schema, &json!({"a": 1, "b": true})).unwrap();
        errors.sort();
        assert_eq!(
            errors,
            vec![
                "$.a: integer found, object expected",
                "$.a: integer found, string expected",
                "$.b: boolean found, integer expected",
                "$.b: boolean found, string expected",
                "$.b: must be valid to one and only one schema, but 0 are valid",
            ]
        );
    }

    #[test]
    fn paths_use_json_path_brackets_for_non_shorthand_names() {
        assert_eq!(append("$", "some name"), "$['some name']");
        assert_eq!(append("$", "ok_1"), "$.ok_1");
        assert_eq!(append("$", "1st"), "$['1st']");
    }

    #[test]
    fn an_unresolvable_reference_is_reported_without_its_hash() {
        let schema = json!({"$ref": "#/definitions/missing"});
        assert_eq!(validate(&schema, &json!({})).unwrap_err().0, "/definitions/missing");
    }

    #[test]
    fn numbers_follow_jackson_nodes() {
        let schema = json!({"type": "object", "properties": {"a": {"multipleOf": 10}, "b": {"maximum": 1e2}, "c": {"enum": [1.50, null]}}});
        let mut errors = validate_user(&schema, &json!({"a": 15, "b": 101, "c": 2})).unwrap();
        errors.sort();
        assert_eq!(
            errors,
            vec!["$.a: must be multiple of 1E+1", "$.b: must have a maximum value of 100.0", "$.c: does not have a value in the enumeration [1.5, ]"]
        );
    }
}

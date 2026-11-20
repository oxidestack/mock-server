//! Remote documents a user's schema reaches through `$ref` under `mockserver.jsonSchemaAllowRemoteRefs=true`:
//! networknt's `IriResourceLoader` reads each one (`URL.openStream`), its `SchemaRegistry` parses and
//! builds it, and the evaluation goes on inside it; a document that fails to load fails the evaluation with that
//! exception (`JsonSchemaValidator.isValid` reports `<exception class> - <message>`).
//!
//! The documents are read while the matcher is built ([`prefetch`]: networknt preloads its validators when the
//! schema is created), off the worker, since the document may be served by this same server; evaluation reads them
//! back from here. They are kept by IRI for the process, each read replacing the last.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};

use serde_json::Value;

use super::stream_read::{self, Read};
use super::{Spec, construction_error_at, dialect_of, refs};

/// A loaded document, or the report of why it did not load.
pub type Loaded = Result<Arc<Value>, String>;

static DOCUMENTS: LazyLock<Mutex<HashMap<String, Loaded>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Reads every remote document `schema` reaches, directly or through documents read before.
pub fn prefetch(schema: &Value, default: Spec) {
    let mut pending = remote_documents(schema, "");
    let mut seen = HashSet::new();
    while let Some(iri) = pending.pop() {
        if !seen.insert(iri.clone()) {
            continue;
        }
        let loaded = crate::blocking::off_worker(|| load(&iri, default));
        if let Ok(document) = &loaded {
            pending.extend(remote_documents(document, &iri));
        }
        let mut documents = DOCUMENTS.lock().unwrap_or_else(|e| e.into_inner());
        if documents.len() > 1024 {
            documents.clear();
        }
        documents.insert(iri, loaded);
    }
}

/// The document read for `iri`, if one was.
pub fn get(iri: &str) -> Option<Loaded> {
    DOCUMENTS.lock().unwrap_or_else(|e| e.into_inner()).get(iri).cloned()
}

/// The loaded documents `schema` reaches, transitively, with each one's IRI.
pub fn reachable(schema: &Value) -> Vec<(String, Arc<Value>)> {
    let mut pending = remote_documents(schema, "");
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    while let Some(iri) = pending.pop() {
        if !seen.insert(iri.clone()) {
            continue;
        }
        if let Some(Ok(document)) = get(&iri) {
            pending.extend(remote_documents(&document, &iri));
            out.push((iri, document));
        }
    }
    out
}

/// The remote documents `node`'s `$ref`s name, resolved against `base` and the `$id`s on the way.
fn remote_documents(node: &Value, base: &str) -> Vec<String> {
    let mut out = Vec::new();
    collect(node, base, &mut out);
    out
}

fn collect(node: &Value, base: &str, out: &mut Vec<String>) {
    match node {
        Value::Object(fields) => {
            let mut base = base.to_string();
            if let Some(id) = fields.get("$id").or_else(|| fields.get("id")).and_then(Value::as_str).filter(|id| !id.starts_with('#')) {
                base = refs::strip_fragment(&refs::resolve(&base, id)).to_string();
            }
            for (key, value) in fields {
                match (key.as_str(), value) {
                    ("$ref", Value::String(reference)) => {
                        let resolved = refs::resolve(&base, reference);
                        let document = refs::strip_fragment(&resolved);
                        if refs::is_remote(document) && refs::meta_schema(document).is_none() {
                            out.push(document.to_string());
                        }
                    }
                    ("enum" | "const" | "default" | "examples", _) => {}
                    _ => collect(value, &base, out),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect(item, base, out)),
        _ => {}
    }
}

/// `SchemaRegistry.loadSchema`: read, parse (Jackson 3's `readTree(InputStream)`) and build the document.
fn load(iri: &str, default: Spec) -> Loaded {
    let failed = || format!("SchemaException - Failed to load json schema from {iri}");
    let bytes = match iri.strip_prefix("file:") {
        Some(path) => {
            let path = path.trim_start_matches("//");
            let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
            std::fs::read(crate::java_text::url_decode(&path, crate::java_text::UrlCharset::Utf8).unwrap_or(path)).map_err(|_| failed())?
        }
        None if iri.starts_with("http://") || iri.starts_with("https://") => {
            swagger_parser::parser::remote_url::url_to_bytes(iri, &[], None).map_err(|_| failed())?
        }
        None => return Err(failed()),
    };
    match stream_read::read(&bytes) {
        Read::Value => {}
        Read::Failed(report) => return Err(report),
        Read::Missing => {
            let expected = if default >= Spec::Draft6 { "object or boolean" } else { "object" };
            return Err(format!("SchemaException - Schema at {iri}$ must be {expected} but was MISSING"));
        }
    }
    let document = crate::json::parse_lenient(&bytes).map_err(|e| format!("StreamReadException - {e}"))?;
    let spec = document.get("$schema").and_then(Value::as_str).and_then(dialect_of).unwrap_or(default);
    if let Some(message) = construction_error_at(&document, spec, true, Some(iri)) {
        let class = if message.contains(" is not a valid ") { "InvalidSchemaException" } else { "SchemaException" };
        return Err(format!("{class} - {message}"));
    }
    Ok(Arc::new(document))
}

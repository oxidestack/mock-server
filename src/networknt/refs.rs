//! Schema resources and `$ref` targets, as networknt's `SchemaContext` registers them: every `$id` (`id` in draft 4)
//! makes a resource at its absolute IRI, every `$anchor` (and a draft 6/7 `$id: "#name"`) an anchor in its resource,
//! and the json-schema.org meta-schemas resolve to the copies networknt bundles (`MetaSchemaIdResolver`).

use std::collections::HashMap;
use std::sync::LazyLock;

use serde_json::Value;

use super::Spec;

/// A schema reachable by IRI: its node, the base IRI it is evaluated under, its dialect.
#[derive(Clone)]
pub struct Target<'a> {
    pub node: &'a Value,
    pub base: String,
    pub spec: Spec,
}

#[derive(Default)]
pub struct Index<'a> {
    /// Absolute IRI (no fragment) → resource; `iri#anchor` → anchored schema.
    entries: HashMap<String, Target<'a>>,
    /// `iri#name` of `$dynamicAnchor`s (2020-12).
    pub dynamic: HashMap<String, Target<'a>>,
    /// Resources whose root declares `$recursiveAnchor: true` (2019-09), by IRI.
    pub recursive: HashMap<String, bool>,
}

/// networknt's bundled meta-schemas, by the path after `json-schema.org/`.
static META: LazyLock<Vec<(&'static str, Value)>> = LazyLock::new(|| {
    let doc = |text: &str| serde_json::from_str::<Value>(text).expect("bundled meta-schema");
    vec![
        ("draft-04/schema", doc(include_str!("metaschemas/draft-04/schema"))),
        ("draft-06/schema", doc(include_str!("metaschemas/draft-06/schema"))),
        ("draft-07/schema", doc(include_str!("metaschemas/draft-07/schema"))),
        ("draft/2019-09/schema", doc(include_str!("metaschemas/draft/2019-09/schema"))),
        ("draft/2019-09/meta/core", doc(include_str!("metaschemas/draft/2019-09/meta/core"))),
        ("draft/2019-09/meta/applicator", doc(include_str!("metaschemas/draft/2019-09/meta/applicator"))),
        ("draft/2019-09/meta/validation", doc(include_str!("metaschemas/draft/2019-09/meta/validation"))),
        ("draft/2019-09/meta/meta-data", doc(include_str!("metaschemas/draft/2019-09/meta/meta-data"))),
        ("draft/2019-09/meta/format", doc(include_str!("metaschemas/draft/2019-09/meta/format"))),
        ("draft/2019-09/meta/content", doc(include_str!("metaschemas/draft/2019-09/meta/content"))),
        ("draft/2020-12/schema", doc(include_str!("metaschemas/draft/2020-12/schema"))),
        ("draft/2020-12/meta/core", doc(include_str!("metaschemas/draft/2020-12/meta/core"))),
        ("draft/2020-12/meta/applicator", doc(include_str!("metaschemas/draft/2020-12/meta/applicator"))),
        ("draft/2020-12/meta/unevaluated", doc(include_str!("metaschemas/draft/2020-12/meta/unevaluated"))),
        ("draft/2020-12/meta/validation", doc(include_str!("metaschemas/draft/2020-12/meta/validation"))),
        ("draft/2020-12/meta/meta-data", doc(include_str!("metaschemas/draft/2020-12/meta/meta-data"))),
        ("draft/2020-12/meta/format-annotation", doc(include_str!("metaschemas/draft/2020-12/meta/format-annotation"))),
        ("draft/2020-12/meta/format-assertion", doc(include_str!("metaschemas/draft/2020-12/meta/format-assertion"))),
        ("draft/2020-12/meta/content", doc(include_str!("metaschemas/draft/2020-12/meta/content"))),
    ]
});

/// The bundled copy a json-schema.org IRI maps to (`MetaSchemaIdResolver`): `https://json-schema.org/<path>`, or
/// `http://json-schema.org/<path>` without a trailing `#`.
pub fn meta_schema(iri: &str) -> Option<&'static Value> {
    let path = if let Some(rest) = iri.strip_prefix("https://json-schema.org/") {
        rest
    } else {
        iri.strip_prefix("http://json-schema.org/").map(|r| r.strip_suffix('#').unwrap_or(r))?
    };
    META.iter().find(|(p, _)| *p == path).map(|(_, v)| v)
}

/// Whether `iri` names something `JsonSchemaValidator.isRemoteRef` blocks: an http(s)/ftp(s)/file/jar IRI outside
/// json-schema.org.
pub fn is_remote(iri: &str) -> bool {
    let scheme = iri.split(':').next().unwrap_or_default().to_ascii_lowercase();
    if !iri.contains(':') || !["http", "https", "ftp", "ftps", "file", "jar"].contains(&scheme.as_str()) {
        return false;
    }
    let lower = iri.to_ascii_lowercase();
    !lower.starts_with("http://json-schema.org/") && !lower.starts_with("https://json-schema.org/")
}

impl<'a> Index<'a> {
    pub fn build(root: &'a Value, spec: Spec) -> Index<'a> {
        let mut index = Index::default();
        // The document itself, for `#`-relative references when the root has no `$id`.
        index.entries.insert(String::new(), Target { node: root, base: String::new(), spec });
        index.walk(root, "", spec, true);
        index
    }

    /// Adds the resources of a document loaded by IRI (a bundled meta-schema).
    pub fn add_document(&mut self, iri: &str, node: &'a Value, spec: Spec) {
        let doc = strip_fragment(iri).to_string();
        self.entries.entry(doc.clone()).or_insert(Target { node, base: doc.clone(), spec });
        self.walk(node, &doc, spec, true);
    }

    pub fn get(&self, iri: &str) -> Option<&Target<'a>> {
        self.entries.get(iri)
    }

    fn walk(&mut self, node: &'a Value, base: &str, spec: Spec, schema_position: bool) {
        match node {
            Value::Object(fields) => {
                let spec = fields.get("$schema").and_then(Value::as_str).and_then(super::dialect_of).unwrap_or(spec);
                let mut base = base.to_string();
                if schema_position {
                    if let Some(id) = fields.get(spec.id_keyword()).and_then(Value::as_str) {
                        if let Some(anchor) = id.strip_prefix('#').filter(|a| !a.is_empty() && spec <= Spec::Draft7) {
                            self.entries.entry(format!("{}#{anchor}", strip_fragment(&base))).or_insert(Target { node, base: base.clone(), spec });
                        } else {
                            let resolved = resolve(&base, id);
                            base = strip_fragment(&resolved).to_string();
                            self.entries.entry(base.clone()).or_insert(Target { node, base: base.clone(), spec });
                            if fields.get("$recursiveAnchor") == Some(&Value::Bool(true)) {
                                self.recursive.insert(base.clone(), true);
                            }
                            if let Some((_, anchor)) = resolved.split_once('#').filter(|(_, a)| !a.is_empty()) {
                                self.entries.entry(format!("{base}#{anchor}")).or_insert(Target { node, base: base.clone(), spec });
                            }
                        }
                    } else if base.is_empty() && fields.get("$recursiveAnchor") == Some(&Value::Bool(true)) {
                        self.recursive.insert(String::new(), true);
                    }
                    if spec >= Spec::Draft201909 {
                        if let Some(anchor) = fields.get("$anchor").and_then(Value::as_str) {
                            self.entries.entry(format!("{base}#{anchor}")).or_insert(Target { node, base: base.clone(), spec });
                        }
                        if let Some(anchor) = fields.get("$dynamicAnchor").and_then(Value::as_str) {
                            let key = format!("{base}#{anchor}");
                            self.entries.entry(key.clone()).or_insert(Target { node, base: base.clone(), spec });
                            self.dynamic.entry(key).or_insert(Target { node, base: base.clone(), spec });
                        }
                    }
                }
                for (key, child) in fields {
                    if matches!(key.as_str(), "enum" | "const" | "default" | "examples" | "example") {
                        continue;
                    }
                    self.walk(child, &base, spec, true);
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.walk(item, base, spec, true);
                }
            }
            _ => {}
        }
    }
}

pub fn strip_fragment(iri: &str) -> &str {
    iri.split('#').next().unwrap_or(iri)
}

/// RFC 3986 §5.2 reference resolution, with an empty base meaning "no base" (the reference stays as written).
pub fn resolve(base: &str, reference: &str) -> String {
    if base.is_empty() || has_scheme(reference) {
        return remove_dot_segments_full(reference);
    }
    let (b_scheme, b_auth, b_path, b_query) = split(base);
    let (r_scheme, r_auth, r_path, r_query, r_frag) = split_full(reference);
    let _ = r_scheme;
    let (auth, path, query) = if r_auth.is_some() {
        (r_auth, remove_dot_segments(&r_path), r_query)
    } else if r_path.is_empty() {
        (b_auth, b_path.clone(), if r_query.is_some() { r_query } else { b_query })
    } else if r_path.starts_with('/') {
        (b_auth, remove_dot_segments(&r_path), r_query)
    } else {
        let merged = if b_auth.is_some() && b_path.is_empty() {
            format!("/{r_path}")
        } else {
            match b_path.rfind('/') {
                Some(i) => format!("{}{}", &b_path[..=i], r_path),
                None => r_path.clone(),
            }
        };
        (b_auth, remove_dot_segments(&merged), r_query)
    };
    let mut out = String::new();
    if let Some(s) = b_scheme {
        out.push_str(&s);
        out.push(':');
    }
    if let Some(a) = auth {
        out.push_str("//");
        out.push_str(&a);
    }
    out.push_str(&path);
    if let Some(q) = query {
        out.push('?');
        out.push_str(&q);
    }
    if let Some(f) = r_frag {
        out.push('#');
        out.push_str(&f);
    }
    out
}

fn has_scheme(s: &str) -> bool {
    match s.find(':') {
        Some(i) => {
            let scheme = &s[..i];
            !scheme.is_empty()
                && scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
                && !s[..i].contains(['/', '?', '#'])
        }
        None => false,
    }
}

type Parts = (Option<String>, Option<String>, String, Option<String>);

fn split(s: &str) -> Parts {
    let (a, b, c, d, _) = split_full(s);
    (a, b, c, d)
}

fn split_full(s: &str) -> (Option<String>, Option<String>, String, Option<String>, Option<String>) {
    let (rest, frag) = match s.split_once('#') {
        Some((r, f)) => (r, Some(f.to_string())),
        None => (s, None),
    };
    let (rest, query) = match rest.split_once('?') {
        Some((r, q)) => (r, Some(q.to_string())),
        None => (rest, None),
    };
    let (scheme, rest) = if has_scheme(rest) {
        let i = rest.find(':').unwrap_or(0);
        (Some(rest[..i].to_string()), &rest[i + 1..])
    } else {
        (None, rest)
    };
    let (auth, path) = match rest.strip_prefix("//") {
        Some(r) => match r.find('/') {
            Some(i) => (Some(r[..i].to_string()), r[i..].to_string()),
            None => (Some(r.to_string()), String::new()),
        },
        None => (None, rest.to_string()),
    };
    (scheme, auth, path, query, frag)
}

fn remove_dot_segments_full(s: &str) -> String {
    let (scheme, auth, path, query, frag) = split_full(s);
    if !path.contains("./") && !path.ends_with("/.") && !path.ends_with("/..") {
        return s.to_string();
    }
    let mut out = String::new();
    if let Some(sc) = scheme {
        out.push_str(&sc);
        out.push(':');
    }
    if let Some(a) = auth {
        out.push_str("//");
        out.push_str(&a);
    }
    out.push_str(&remove_dot_segments(&path));
    if let Some(q) = query {
        out.push('?');
        out.push_str(&q);
    }
    if let Some(f) = frag {
        out.push('#');
        out.push_str(&f);
    }
    out
}

fn remove_dot_segments(path: &str) -> String {
    let mut input = path.to_string();
    let mut output = String::new();
    while !input.is_empty() {
        if let Some(r) = input.strip_prefix("../") {
            input = r.to_string();
        } else if let Some(r) = input.strip_prefix("./") {
            input = r.to_string();
        } else if input.starts_with("/./") {
            input = input[2..].to_string();
        } else if input == "/." {
            input = "/".into();
        } else if input.starts_with("/../") || input == "/.." {
            input = if input == "/.." { "/".into() } else { input[3..].to_string() };
            match output.rfind('/') {
                Some(i) => output.truncate(i),
                None => output.clear(),
            }
        } else if input == "." || input == ".." {
            input.clear();
        } else {
            let start = usize::from(input.starts_with('/'));
            let end = input[start..].find('/').map(|i| i + start).unwrap_or(input.len());
            output.push_str(&input[..end]);
            input = input[end..].to_string();
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relative_references() {
        assert_eq!(resolve("http://example.com/root.json", "other.json"), "http://example.com/other.json");
        assert_eq!(resolve("http://example.com/a/b.json", "#foo"), "http://example.com/a/b.json#foo");
        assert_eq!(resolve("http://example.com/a/b.json", "../c.json"), "http://example.com/c.json");
        assert_eq!(resolve("", "other.json"), "other.json");
        assert_eq!(resolve("urn:x", "http://y/z"), "http://y/z");
    }
}

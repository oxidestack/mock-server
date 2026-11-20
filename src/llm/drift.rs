//! `StructuralShapeDiff`: two JSON documents compared by shape (each path's type), not values, for
//! `detect_llm_drift`.

use serde_json::Value;

/// `StructuralShapeDiff.collect`: each path's JSON type, arrays by their first element under `[]`.
fn shape(path: &str, node: &Value, out: &mut std::collections::BTreeMap<String, &'static str>) {
    let kind = match node {
        Value::Null => return,
        Value::Object(_) => "object",
        Value::Array(_) => "array",
        Value::String(_) => "string",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() || !n.to_string().contains(['.', 'e', 'E']) => "integer",
        Value::Number(_) => "number",
    };
    out.insert(path.to_string(), kind);
    match node {
        Value::Object(o) => o.iter().for_each(|(k, v)| shape(&format!("{path}.{k}"), v, out)),
        Value::Array(items) if !items.is_empty() => shape(&format!("{path}[]"), &items[0], out),
        _ => {}
    }
}

/// Each path's JSON type in `node` (`ShapeDiff.getBaselineType` / `getLiveType` read these).
pub fn shape_types(node: &Value) -> std::collections::BTreeMap<String, &'static str> {
    let mut types = std::collections::BTreeMap::new();
    shape("$", node, &mut types);
    types
}

/// `StructuralShapeDiff.diff`: added, removed and type-changed paths, each sorted.
pub fn shape_diff(baseline: &Value, live: &Value) -> (Vec<String>, Vec<String>, Vec<String>) {
    let (b, l) = (shape_types(baseline), shape_types(live));
    let added = l.keys().filter(|k| !b.contains_key(*k)).cloned().collect();
    let removed = b.keys().filter(|k| !l.contains_key(*k)).cloned().collect();
    let changed = b.iter().filter(|(k, t)| l.get(*k).is_some_and(|lt| lt != *t)).map(|(k, _)| k.clone()).collect();
    (added, removed, changed)
}


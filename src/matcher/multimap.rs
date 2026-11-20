//! Headers, query and path parameters, form bodies (`MultiValueMapMatcher`, §3.4) and cookies.

use serde_json::Value;

use super::string::StringMatcher;
use crate::request::MultiMap;

/// Unit tests mirroring the upstream contain-all matrix (`SubSetMatcherTest`,
/// `NottableStringHashMapContainAllTest`, `NottableStringMultiMapContainAllTest`) — a child module (not the
/// `tests` module below) so it can build `Entry`/`MultiMapMatcher` directly, the
/// same way upstream's tests build a `NottableStringMultiMap` from raw `NottableString` pairs.
#[cfg(test)]
mod containall_test;

#[derive(Debug)]
struct Entry {
    name: StringMatcher,
    values: Vec<StringMatcher>,
    /// `parameterStyle`: how a non-exploded array value is delimited.
    style: Option<String>,
}

#[derive(Debug, Default)]
pub struct MultiMapMatcher {
    entries: Vec<Entry>,
    /// `MATCHING_KEY`: every actual value of a key must match; otherwise (`SUB_SET`) each expected value needs one.
    matching_key: bool,
    /// `binaryHeaderNormalization`: on for header maps only (`keysToMultiValues instanceof Headers`), where a `-bin`
    /// key's values compare without their base64 padding; query-string, path and body parameters compare as given.
    binary_headers: bool,
}

impl MultiMapMatcher {
    /// From a canonical map-form `keyToMultiValue`.
    pub fn compile(v: &Value) -> MultiMapMatcher {
        let mut m = MultiMapMatcher::default();
        if let Value::Array(items) = v {
            // The list form upstream falls back to when a name starts with a marker character.
            for item in items {
                let name = StringMatcher::compile(item.get("name").unwrap_or(&Value::Null));
                let values = item.get("values").and_then(Value::as_array).map(|vs| vs.iter().map(StringMatcher::compile).collect()).unwrap_or_default();
                m.entries.push(Entry { name, values, style: None });
            }
            return m;
        }
        let Some(o) = v.as_object() else { return m };
        for (k, v) in o {
            if k == "keyMatchStyle" {
                m.matching_key = v.as_str() == Some("MATCHING_KEY");
                continue;
            }
            let style = v.get("parameterStyle").and_then(Value::as_str).map(str::to_string);
            let values = match v {
                Value::Array(items) => items.iter().map(StringMatcher::compile).collect(),
                Value::Object(styled) => styled
                    .get("values")
                    .and_then(Value::as_array)
                    .map(|items| items.iter().map(StringMatcher::compile).collect())
                    .unwrap_or_default(),
                other => vec![StringMatcher::compile(other)],
            };
            m.entries.push(Entry { name: StringMatcher::from_text(k), values, style });
        }
        m
    }

    /// From a canonical `keyToValue` (cookies): one value per name.
    pub fn compile_single(v: &Value) -> MultiMapMatcher {
        let mut m = MultiMapMatcher::default();
        if let Some(o) = v.as_object() {
            for (k, v) in o {
                m.entries.push(Entry { name: StringMatcher::from_text(k), values: vec![StringMatcher::compile(v)], style: None });
            }
        }
        for item in v.as_array().into_iter().flatten() {
            let name = StringMatcher::compile(item.get("name").unwrap_or(&Value::Null));
            m.entries.push(Entry { name, values: vec![StringMatcher::compile(item.get("value").unwrap_or(&Value::Null))], style: None });
        }
        m
    }

    /// The matcher of a header map, with gRPC binary-metadata padding normalisation on.
    pub fn for_headers(mut self) -> MultiMapMatcher {
        self.binary_headers = true;
        self
    }

    /// The values given for `name` (case-insensitively), as written.
    pub fn values_of(&self, name: &str) -> Vec<String> {
        self.entries.iter().filter(|e| e.name.value.eq_ignore_ascii_case(name)).flat_map(|e| e.values.iter().map(|v| v.value.clone())).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Reorders the entries as the names appear in `input` (map or list form, names with `!`/`?` markers or as
    /// `{"not": …, "value": …}`); names it does not list keep their place after the others.
    pub fn in_order_of(mut self, input: Option<&Value>) -> MultiMapMatcher {
        fn printed(name: &Value) -> Option<String> {
            match name {
                Value::String(s) => Some(s.clone()),
                Value::Object(o) => {
                    let value = o.get("value").and_then(Value::as_str)?;
                    let marker = if o.get("not").and_then(Value::as_bool) == Some(true) {
                        "!"
                    } else if o.get("optional").and_then(Value::as_bool) == Some(true) {
                        "?"
                    } else {
                        ""
                    };
                    Some(format!("{marker}{value}"))
                }
                _ => None,
            }
        }
        let order: Vec<String> = match input {
            Some(Value::Object(o)) => o.keys().filter(|k| k.as_str() != "keyMatchStyle").cloned().collect(),
            Some(Value::Array(items)) => items.iter().filter_map(|i| i.get("name").and_then(printed)).collect(),
            _ => return self,
        };
        self.entries.sort_by_key(|e| order.iter().position(|k| *k == e.name.printed()).unwrap_or(usize::MAX));
        self
    }

    pub fn matches(&self, actual: &MultiMap, case_insensitive_values: bool) -> bool {
        if self.entries.is_empty() {
            return true;
        }
        if actual.iter().all(|(_, vs)| vs.is_empty()) {
            // `allKeysNotted() || allKeysOptional()`
            return self.entries.iter().all(|e| e.name.not) || self.entries.iter().all(|e| e.name.optional);
        }
        if self.matching_key {
            return self.entries.iter().all(|e| self.entry_matches(e, actual, case_insensitive_values));
        }
        self.contains_subset(actual, case_insensitive_values)
    }

    /// `SubSetMatcher.containsSubset`: every expected (name, value) pair needs an actual pair it matches (negation
    /// included), a negated name must be absent unless its value is negated too, and the matched actual pairs must
    /// be at least as many as the required expected pairs, so one actual pair cannot satisfy two expected ones.
    fn contains_subset(&self, actual: &MultiMap, ci: bool) -> bool {
        let pairs: Vec<(&str, &str)> = actual.iter().flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_str(), v.as_str()))).collect();
        let mut matched = std::collections::HashSet::new();
        let mut required = 0;
        for entry in &self.entries {
            if array_schema(entry).is_some() {
                if !self.entry_matches(entry, actual, ci) {
                    return false;
                }
                continue;
            }
            let values: Vec<Option<&StringMatcher>> = if entry.values.is_empty() { vec![None] } else { entry.values.iter().map(Some).collect() };
            for value in values {
                let indexes: Vec<usize> = pairs
                    .iter()
                    .enumerate()
                    .filter(|(_, (k, v))| entry.name.matches(k, true) && value.is_none_or(|m| self.value_matches(&entry.name, k, m, v, ci)))
                    .map(|(i, _)| i)
                    .collect();
                let optional = entry.name.optional || value.is_some_and(|m| m.optional);
                let present = pairs.iter().any(|(k, _)| entry.name.matches(k, true));
                let notted_and_present = entry.name.not && pairs.iter().any(|(k, _)| entry.name.matches_positive(k, true));
                if (!(optional && !present) && indexes.is_empty()) || notted_and_present {
                    return false;
                }
                matched.extend(indexes);
                // `ImmutableEntry.isNotted()`: a negated name with a value that is not negated.
                let notted = entry.name.not && !value.is_some_and(|m| m.not);
                if !optional && !notted {
                    required += 1;
                }
            }
        }
        matched.len() >= required
    }

    fn entry_matches(&self, entry: &Entry, actual: &MultiMap, ci: bool) -> bool {
        if entry.name.not {
            // `!Name`: the key itself must be ABSENT — no un-notted actual key equals it — never "aggregate
            // every non-matching key's values and compare them against the pattern's value", which is not a
            // meaningful "this key must be absent" assertion and was fixed upstream for exactly that reason
            // (`NottableStringMultiMap.containsAll`'s `containsUnNottedKey`, regression W3-3b). This mirrors
            // `contains_subset`'s own `notted_and_present`, so the two key-match styles agree.
            return !actual.iter().any(|(k, _)| entry.name.matches_positive(k, true));
        }
        let binary = self.binary_headers && actual.iter().any(|(k, _)| entry.name.matches_positive(k, true) && is_binary_header(k));
        let values: Vec<&str> = actual
            .iter()
            .filter(|(k, _)| entry.name.matches_positive(k, true))
            .flat_map(|(_, vs)| vs.iter().map(String::as_str))
            .collect();
        let key = if binary { "-bin" } else { "" };
        let matches = |m: &StringMatcher, a: &str| self.value_matches(&entry.name, key, m, a, ci);
        if values.is_empty() {
            return entry.name.optional || entry.values.iter().all(|m| m.optional);
        }
        if let Some(schema) = array_schema(entry) {
            return schema.errors_of_text(&array_text(entry, &values)).is_empty();
        }
        if self.matching_key {
            values.iter().all(|a| entry.values.iter().any(|m| matches(m, a)))
        } else {
            entry.values.iter().all(|m| m.optional || values.iter().any(|a| matches(m, a)))
        }
    }
}

/// Control-plane matching against another request definition's map, whose names and values are `NottableString`s
/// too (regexes, negations, schemas): `MultiValueMapMatcher.matches` / `HashMapMatcher.matches` with
/// `controlPlaneMatcher`, then `NottableStringMultiMap.containsAll`.
impl MultiMapMatcher {
    pub fn matches_definition(&self, matched: &MultiMapMatcher) -> bool {
        if self.entries.is_empty() {
            return true;
        }
        if matched.entries.is_empty() {
            return self.entries.iter().all(|e| e.name.not) || self.entries.iter().all(|e| e.name.optional);
        }
        if self.matching_key {
            self.matching_key_definition(matched)
        } else {
            contains_subset_definition(&self.pairs(), &matched.pairs())
        }
    }

    /// `NottableStringMultiMap.entryList`: one (name, value) pair per value.
    fn pairs(&self) -> Vec<(&StringMatcher, &StringMatcher)> {
        self.entries.iter().flat_map(|e| e.values.iter().map(move |v| (&e.name, v))).collect()
    }

    /// `NottableStringMultiMap.getAll`: the values under every name `key` matches.
    fn all_values(&self, key: &StringMatcher) -> Vec<&StringMatcher> {
        self.entries.iter().filter(|e| key.matches_nottable(&e.name, true)).flat_map(|e| e.values.iter()).collect()
    }

    /// `containsAll` for `MATCHING_KEY`: every matched value under a matcher name must match one of its values.
    fn matching_key_definition(&self, matched: &MultiMapMatcher) -> bool {
        for entry in &self.entries {
            let key = &entry.name;
            if key.not {
                let un_notted = StringMatcher::literal_or_regex(&key.value);
                if matched.entries.iter().any(|e| !e.name.not && un_notted.matches_nottable(&e.name, true)) {
                    return false;
                }
                continue;
            }
            let matched_values = matched.all_values(key);
            if matched_values.is_empty() && !key.optional {
                return false;
            }
            let matcher_values = self.all_values(key);
            if !matched_values.iter().all(|a| matcher_values.iter().any(|m| m.matches_nottable(a, true))) {
                return false;
            }
        }
        true
    }
}

/// `SubSetMatcher.containsSubset` with `NottableString`s on both sides (keys compared with the control-plane
/// `RegexStringMatcher`).
fn contains_subset_definition(subset: &[(&StringMatcher, &StringMatcher)], superset: &[(&StringMatcher, &StringMatcher)]) -> bool {
    let mut matching = std::collections::HashSet::new();
    for (key, value) in subset {
        let indexes: Vec<usize> = superset
            .iter()
            .enumerate()
            .filter(|(_, (k, v))| key.matches_nottable(k, true) && value.matches_nottable(v, true))
            .map(|(i, _)| i)
            .collect();
        let optional_and_absent = key.optional && !superset.iter().any(|(k, _)| key.matches_nottable(k, true));
        let notted_and_present = key.not && {
            let un_notted = StringMatcher::literal_or_regex(&key.value);
            superset.iter().any(|(k, _)| !k.not && un_notted.matches_nottable(k, true))
        };
        if (!optional_and_absent && indexes.is_empty()) || notted_and_present {
            return false;
        }
        matching.extend(indexes);
    }
    // `isNotOptional() && isNotNotted()`: optional is the key's; notted is a negated key with a value that is not.
    let required = subset.iter().filter(|(k, v)| !k.optional && !(k.not && !v.not)).count();
    matching.len() >= required
}

thread_local! {
    /// Set by [`with_definition_values`]: the actual map is a request definition's (a `debugMismatch` probe), whose
    /// values are `NottableString`s read from JSON, so a leading `!` negates the value rather than being part of it.
    static DEFINITION_VALUES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `f` (synchronous) matching maps against a request definition's values, where `!value` is a negated value
/// (`RegexStringMatcher.matchesByNottedStrings` with a notted matched side).
pub(crate) fn with_definition_values<R>(f: impl FnOnce() -> R) -> R {
    let previous = DEFINITION_VALUES.with(|d| d.replace(true));
    let result = f();
    DEFINITION_VALUES.with(|d| d.set(previous));
    result
}

/// An actual value as the matcher compares it: its text, and whether it is negated (only a definition's can be).
fn actual_value(actual: &str) -> (&str, bool) {
    match actual.strip_prefix('!') {
        Some(rest) if DEFINITION_VALUES.with(std::cell::Cell::get) => (rest, true),
        _ => (actual, false),
    }
}

/// `RegexStringMatcher.matches(matcher, matched)` for an actual map value: `matchesByNottedStrings`, which inverts the
/// string comparison when exactly one side is negated.
fn value_cmp(m: &StringMatcher, actual: &str, ci: bool) -> bool {
    match actual_value(actual) {
        (value, true) => m.matches_positive(value, ci) == m.not,
        (_, false) => m.matches(actual, ci),
    }
}

/// `BinaryHeaderValueNormalizer.isBinaryHeaderName`: a name ending `-bin`, in any case.
fn is_binary_header(name: &str) -> bool {
    name.len() >= 4 && name[name.len() - 4..].eq_ignore_ascii_case("-bin")
}

impl MultiMapMatcher {
    /// Whether `key`'s values compare without their base64 padding (`BinaryHeaderValueNormalizer.shouldNormalize`
    /// in a header map).
    fn normalizes(&self, name: &StringMatcher, key: &str, m: &StringMatcher) -> bool {
        self.binary_headers && !m.is_matcher_string() && (is_binary_header(key) || is_binary_header(&name.value))
    }

    /// A value compared as `RegexStringMatcher` does, with base64 padding ignored on both sides for gRPC binary
    /// metadata (`-bin` keys of a header map).
    fn value_matches(&self, name: &StringMatcher, key: &str, m: &StringMatcher, actual: &str, ci: bool) -> bool {
        if !self.normalizes(name, key, m) {
            return value_cmp(m, actual, ci);
        }
        let normalized = m.without_base64_padding();
        let matcher = normalized.as_ref().unwrap_or(m);
        matcher.matches(super::string::strip_base64_padding(actual).unwrap_or(actual), ci)
    }
}

impl MultiMapMatcher {
    /// The difference MockServer records first for a failing map: a failed schema value's report
    /// (`NottableSchemaString`), otherwise the map's own failure.
    /// [`Self::difference`] for a request field of `kind`: with nothing to compare, the map's own failure is all
    /// `MultiValueMapMatcher` records.
    pub fn field_difference(&self, actual: &MultiMap, kind: MapKind) -> super::Difference {
        // The hint quotes the first difference the map records while it is matched.
        if let Some(text) = self.recorded(actual, false, kind).into_iter().next() {
            return super::Difference::Text(text);
        }
        self.difference(actual)
    }

    pub fn difference(&self, actual: &MultiMap) -> super::Difference {
        if self.matching_key && actual.iter().any(|(_, vs)| !vs.is_empty()) {
            // `NottableStringMultiMap.containsAll` records its comparisons before the map's own failure.
            let mut texts = Vec::new();
            self.record_matching_key(actual, MapKind::Parameters, &mut texts);
            if let Some(first) = texts.into_iter().next() {
                return super::Difference::Text(first);
            }
        }
        if !self.matching_key &&self.entries.iter().all(|e| e.values.iter().all(|v| v.schema().is_none())) && let Some(d) = self.first_failed_comparison(actual) {
            return d;
        }
        for entry in &self.entries {
            if self.entry_matches(entry, actual, true) || entry.name.not {
                continue;
            }
            let values: Vec<&str> = actual
                .iter()
                .filter(|(k, _)| entry.name.matches_positive(k, true))
                .flat_map(|(_, vs)| vs.iter().map(String::as_str))
                .collect();
            if let Some(schema) = array_schema(entry) {
                let text = array_text(entry, &values);
                return schema_difference(schema, &text, &schema.errors_of_text(&text));
            }
            for value in &values {
                for schema in entry.values.iter().filter_map(StringMatcher::schema) {
                    let errors = schema.errors(value);
                    if !errors.is_empty() {
                        return schema_difference(schema, &schema.instance_text(value), &errors);
                    }
                }
            }
            break;
        }
        super::Difference::Other("multimap match failed")
    }
}

impl MultiMapMatcher {
    /// `ExpandedParameterDecoder.splitParameters`: the actual values of each styled parameter split on its style's
    /// delimiter (quoted values unquoted, JSON values dropped), an `object` schema's parts rebuilt as a JSON object.
    /// `deepObject` folding is left out: the oracle does not fold `name[key]` parameters for a request matcher.
    pub fn split_values(&self, actual: &MultiMap) -> MultiMap {
        let mut out = actual.clone();
        for entry in &self.entries {
            let Some(style) = entry.style.as_deref() else { continue };
            let object = entry.values.iter().filter_map(StringMatcher::schema).any(|s| s.type_.as_deref() == Some("object"));
            let name = &entry.name.value;
            let Some(delimiter) = style_delimiter(style, name) else { continue };
            let full_name = fancy_regex::Regex::new(&format!("^(?:{name})$")).ok();
            for (key, values) in out.iter_mut() {
                if key != name && !full_name.as_ref().is_some_and(|r| r.is_match(key).unwrap_or(false)) {
                    continue;
                }
                let split = split_on_delimiter(&delimiter, values);
                let rebuilt = object.then(|| if style.ends_with("_EXPLODED") { exploded_object(&split) } else { alternating_object(&split) }).flatten();
                *values = match rebuilt {
                    Some(json) => vec![json],
                    None => split,
                };
            }
        }
        out
    }
}

/// `ParameterStyle.getRegex()` for the styles that split (`isExploded()`), `<name>` filled in.
pub(super) fn style_delimiter(style: &str, name: &str) -> Option<fancy_regex::Regex> {
    let pattern = match style {
        "SIMPLE" | "SIMPLE_EXPLODED" | "LABEL" | "MATRIX" | "FORM" => ",".to_string(),
        "LABEL_EXPLODED" => r"\.".to_string(),
        "MATRIX_EXPLODED" => format!(";{}=", fancy_regex::escape(name)),
        "SPACE_DELIMITED" => r"(%20)|\s|\+".to_string(),
        "PIPE_DELIMITED" => r"\|".to_string(),
        _ => return None,
    };
    fancy_regex::Regex::new(&pattern).ok()
}

/// `splitOnDelimiter`, with `String.split`'s dropping of trailing empty parts.
pub(super) fn split_on_delimiter(delimiter: &fancy_regex::Regex, values: &[String]) -> Vec<String> {
    static QUOTED: std::sync::LazyLock<fancy_regex::Regex> =
        std::sync::LazyLock::new(|| fancy_regex::Regex::new(r#"^\s*["']+(.*)["']+\s*$"#).expect("static regex"));
    static JSON: std::sync::LazyLock<fancy_regex::Regex> =
        std::sync::LazyLock::new(|| fancy_regex::Regex::new(r"(?s)^\s*[{\[].*[}\]]\s*$").expect("static regex"));
    let mut out = Vec::new();
    for value in values {
        if let Ok(Some(c)) = QUOTED.captures(value) {
            out.push(c.get(1).map(|m| m.as_str().to_string()).unwrap_or_default());
        } else if !JSON.is_match(value).unwrap_or(false) {
            let mut parts: Vec<String> = delimiter.split(value).filter_map(Result::ok).map(str::to_string).collect();
            while parts.len() > 1 && parts.last().is_some_and(String::is_empty) {
                parts.pop();
            }
            // A match at the very start leaves no empty leading part only when it is zero-width; these delimiters
            // are not, so a leading empty part stays, as in Java.
            out.extend(parts);
        }
    }
    out
}

fn json_object(properties: &[(String, String)]) -> String {
    let fields: Vec<String> = properties.iter().map(|(k, v)| format!("{}:{}", Value::String(k.clone()), Value::String(v.clone()))).collect();
    format!("{{{}}}", fields.join(","))
}

/// `reconstructExplodedObject`: `key=value` parts.
fn exploded_object(values: &[String]) -> Option<String> {
    let mut properties: Vec<(String, String)> = Vec::new();
    for v in values {
        let (k, val) = v.split_once('=').filter(|(k, _)| !k.is_empty())?;
        match properties.iter_mut().find(|(existing, _)| existing == k) {
            Some(p) => p.1 = val.to_string(),
            None => properties.push((k.to_string(), val.to_string())),
        }
    }
    (!properties.is_empty()).then(|| json_object(&properties))
}

/// `reconstructObjectFromAlternatingValues`: `key,value,key,value`.
fn alternating_object(values: &[String]) -> Option<String> {
    if values.len() < 2 || !values.len().is_multiple_of(2) {
        return None;
    }
    let mut properties: Vec<(String, String)> = Vec::new();
    for pair in values.chunks(2) {
        match properties.iter_mut().find(|(existing, _)| *existing == pair[0]) {
            Some(p) => p.1 = pair[1].clone(),
            None => properties.push((pair[0].clone(), pair[1].clone())),
        }
    }
    Some(json_object(&properties))
}

impl MultiMapMatcher {
    /// What matching `actual` records in a `MatchDifference` (whether or not it matches in the end, since the
    /// mismatch log prints a matched field's differences too), in order:
    /// - `SUB_SET`: every failed key and value comparison of `SubSetMatcher.matchesIndexes`, up to the first expected
    ///   entry nothing satisfies; then, when the map fails, `multimap subset match failed` (a multi-value map only);
    /// - `MATCHING_KEY`: the comparisons and `multimap matching key match failed` lines of
    ///   `NottableStringMultiMap.containsAll`, up to the first key that fails;
    /// - when the map fails, its own failure: `multimap match failed` (`MultiValueMapMatcher`) or `map subset match
    ///   failed` (`HashMapMatcher`, cookies).
    pub fn recorded(&self, actual: &MultiMap, matched: bool, kind: MapKind) -> Vec<String> {
        if self.entries.is_empty() {
            return Vec::new();
        }
        let pairs: Vec<(&str, &str)> = actual.iter().flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_str(), v.as_str()))).collect();
        let mut texts = Vec::new();
        if !pairs.is_empty() {
            if self.matching_key {
                self.record_matching_key(actual, kind, &mut texts);
            } else {
                self.record_subset(&pairs, &mut texts);
                if !matched && kind != MapKind::Cookies {
                    let entry_list = |items: Vec<(String, String)>| format!("[{}]", items.iter().map(|(k, v)| format!("({k}: {v})")).collect::<Vec<_>>().join(", "));
                    let subset = entry_list(self.entries.iter().flat_map(|e| e.values.iter().map(move |v| (e.name.printed(), v.printed()))).collect());
                    let superset = entry_list(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect());
                    texts.push(super::format_log_message(1, "multimap subset match failed subset:{}was not a subset of:{}", &[&subset, &superset]));
                }
            }
        }
        if matched {
            return texts;
        }
        if kind == MapKind::Cookies {
            texts.push(self.map_difference(actual));
            return texts;
        }
        let expected_json = crate::json::pretty(&self.printed_map());
        if pairs.is_empty() && kind != MapKind::PathParameters {
            texts.push(super::format_log_message(1, "multimap match failed expected:{}found:{}failed because:{}", &[&expected_json, "none", "none is not a subset"]));
            return texts;
        }
        // `KeysToMultiValuesSerializer` prints the keys sorted, whatever order they were matched in.
        let found: serde_json::Map<String, Value> = in_descending_key_order(actual).iter().map(|(k, vs)| (k.clone(), serde_json::json!(vs))).collect();
        let found = match kind {
            // a received request's header values are literal (`string(value, false)`): one starting with a marker
            // prints in the object form; a definition's (`debugMismatch`) are read with their markers
            MapKind::Headers if !DEFINITION_VALUES.with(std::cell::Cell::get) => {
                let literal = found.into_iter().map(|(k, vs)| (k, Value::Array(vs.as_array().into_iter().flatten().map(|v| crate::recorded::literal_json(v.as_str().unwrap_or_default())).collect())));
                crate::canonical::multi_map(&Value::Object(literal.collect()))
            }
            MapKind::Headers => crate::canonical::multi_map(&Value::Object(found)),
            _ => Value::Object(found),
        };
        let reason = if self.matching_key { "multimap values don't match" } else { "multimap is not a subset" };
        texts.push(super::format_log_message(1, "multimap match failed expected:{}found:{}failed because:{}", &[&expected_json, &crate::json::pretty(&found), reason]));
        texts
    }

    /// `SubSetMatcher.containsSubset` with a recording context: each expected (name, value) pair is compared with
    /// every actual pair, keys and values alike, until an expected pair nothing satisfies.
    fn record_subset(&self, pairs: &[(&str, &str)], texts: &mut Vec<String>) {
        'entries: for entry in &self.entries {
            for value in &entry.values {
                let mut matched_any = false;
                for (k, v) in pairs {
                    texts.extend(comparison_failure(&entry.name, k));
                    let key_matches = entry.name.matches(k, true);
                    if key_matches && self.normalizes(&entry.name, k, value) {
                        // `BinaryHeaderValueNormalizer.matchesIgnoringPadding`: the values compared without their base64
                        // padding and without a context, then one difference naming the values as given.
                        texts.extend(binary_comparison_failure(value, v));
                        matched_any |= self.value_matches(&entry.name, k, value, v, true);
                    } else {
                        texts.extend(comparison_failure(value, v));
                        matched_any |= key_matches && value_cmp(value, v, true);
                    }
                }
                let present = pairs.iter().any(|(k, _)| entry.name.matches(k, true));
                let optional_absent = (entry.name.optional || value.optional) && !present;
                // `containsKey` and `nottedAndPresent` compare keys through the same `RegexStringMatcher`.
                if entry.name.optional || value.optional {
                    for (k, _) in pairs {
                        super::string::note_would_match(&entry.name, k, false);
                        if entry.name.matches(k, true) {
                            break;
                        }
                    }
                }
                if entry.name.not {
                    for (k, _) in pairs {
                        if entry.name.matches_positive(k, true) {
                            break;
                        }
                        super::string::note_reversed(&entry.name.value, &entry.name.value, k, false);
                    }
                }
                let notted_present = entry.name.not && pairs.iter().any(|(k, _)| entry.name.matches_positive(k, true));
                if (!optional_absent && !matched_any) || notted_present {
                    break 'entries;
                }
            }
        }
    }

    /// `NottableStringMultiMap.containsAll` for `MATCHING_KEY` with a recording context.
    fn record_matching_key(&self, actual: &MultiMap, kind: MapKind, texts: &mut Vec<String>) {
        for entry in &self.entries {
            if entry.name.not {
                if actual.iter().any(|(k, _)| entry.name.matches_positive(k, true)) {
                    texts.push(super::format_log_message(1, "multimap matching key match failed for notted key:{}", &[&entry.name.printed()]));
                    return;
                }
                continue;
            }
            // `getAll` compares every actual key through the map's `RegexStringMatcher`.
            for (k, _) in actual {
                super::string::note_would_match(&entry.name, k, false);
            }
            let values: Vec<&str> = actual.iter().filter(|(k, _)| entry.name.matches(k, true)).flat_map(|(_, vs)| vs.iter().map(String::as_str)).collect();
            if values.is_empty() && !entry.name.optional {
                let subset = self.java_to_string(kind == MapKind::Headers);
                texts.push(super::format_log_message(1, "multimap subset match failed subset:{}did not have expected key:{}", &[&subset, &entry.name.printed()]));
                return;
            }
            for found in &values {
                let found = *found;
                let mut value_matched = false;
                for value in &entry.values {
                    // an `array` schema is first matched against the key's values as a list
                    // (`NottableSchemaString.matches(…, List)`), which records the list when it fails
                    if let Some(schema) = value.schema().filter(|s| s.type_.as_deref() == Some("array")) {
                        let text = array_text(entry, &values);
                        let errors = schema.errors_of_text(&text);
                        if errors.is_empty() {
                            value_matched = true;
                            break;
                        }
                        texts.push(schema_difference(schema, &text, &errors).log_text());
                    }
                    if value_cmp(value, found, true) {
                        value_matched = true;
                        break;
                    }
                    texts.extend(comparison_failure(value, found));
                    texts.push(super::format_log_message(1, "multimap matching key match failed for key:{}", &[&entry.name.printed()]));
                }
                if !value_matched {
                    return;
                }
            }
        }
    }

    /// [`Self::recorded`] for a map that failed, `found` as given.
    pub fn recorded_differences(&self, actual: &MultiMap) -> Vec<String> {
        self.recorded(actual, false, MapKind::Parameters)
    }

    /// What a failed `HashMapMatcher` (cookies) records.
    /// `HashMapMatcher` with a recording `MatchDifference` (response cookies): each failing value of a present
    /// name, then the map's subset failure.
    pub fn cookie_differences(&self, actual: &MultiMap) -> Vec<String> {
        let mut texts = Vec::new();
        for entry in &self.entries {
            for (_, vs) in actual.iter().filter(|(k, _)| entry.name.matches(k, true)) {
                for (value, found) in entry.values.iter().zip(vs) {
                    // `matchesByStrings` records the line when the strings differ, before a not inverts the result:
                    // a notted value equal to the cookie fails without one.
                    if !value.matches_positive(actual_value(found).0, true) {
                        texts.push(super::format_log_message(1, "string or regex match failed expected:{}found:{}", &[&value.printed(), found]));
                    }
                }
            }
        }
        texts.push(self.map_difference(actual));
        texts
    }

    pub fn map_difference(&self, actual: &MultiMap) -> String {
        let expected: serde_json::Map<String, Value> =
            self.entries
                .iter()
                .map(|e| {
                    let value = e.values.first().map(|v| v.date_time_json().cloned().unwrap_or_else(|| Value::String(v.printed())));
                    (e.name.printed(), value.unwrap_or_else(|| Value::String(String::new())))
                })
                .collect();
        let expected = crate::json::pretty(&Value::Object(expected));
        if actual.is_empty() {
            return super::format_log_message(1, "map subset match failed expected:{}found:{}failed because:{}", &[&expected, "none", "none is not a subset"]);
        }
        let found: serde_json::Map<String, Value> =
            actual.iter().map(|(k, vs)| (k.clone(), Value::String(vs.first().cloned().unwrap_or_default()))).collect();
        super::format_log_message(
            1,
            "map subset match failed expected:{}found:{}failed because:{}",
            &[&expected, &crate::json::pretty(&Value::Object(found)), "map is not a subset"],
        )
    }

    /// The matcher as `NottableStringMultiMap`'s reflective `toString` prints it (the `subset` of a missing key).
    fn java_to_string(&self, binary_header_normalization: bool) -> String {
        let backing = self
            .entries
            .iter()
            .map(|e| format!("{}=[{}]", e.name.printed(), e.values.iter().map(StringMatcher::printed).collect::<Vec<_>>().join(", ")))
            .collect::<Vec<_>>()
            .join(", ");
        let style = if self.matching_key { "MATCHING_KEY" } else { "SUB_SET" };
        format!(
            "NottableStringMultiMap[backingMap={{{backing}}},binaryHeaderNormalization={binary_header_normalization},entryList=<null>,keyMatchStyle={style},regexStringMatcher=RegexStringMatcher[caseSensitive=false,controlPlaneMatcher=false,matcher=<null>,numericComparison=true,not=false]]"
        )
    }

    /// The matcher as `KeysToMultiValues` prints it: `keyMatchStyle` when not the default, then names to their values.
    fn printed_map(&self) -> Value {
        let mut out = serde_json::Map::new();
        if self.matching_key {
            out.insert("keyMatchStyle".into(), Value::String("MATCHING_KEY".into()));
        }
        // `KeysToMultiValuesSerializer` prints the keys sorted (descending, by their value without the `!`/`?`
        // markers), whatever order they are matched in
        let mut entries: Vec<_> = self.entries.iter().collect();
        let key = |e: &Entry| e.name.printed().trim_start_matches(['!', '?']).encode_utf16().collect::<Vec<u16>>();
        entries.sort_by_key(|e| std::cmp::Reverse(key(e)));
        for e in entries {
            // `KeysToMultiValuesSerializer`: a schema value as `{"schema": …}`, a styled entry as its style and values.
            let values = Value::Array(
                e.values
                    .iter()
                    .map(|v| match v.schema().and_then(|s| serde_json::from_str::<Value>(&s.printed).ok()) {
                        Some(schema) => serde_json::json!({ "schema": schema }),
                        None => v.date_time_json().cloned().unwrap_or_else(|| Value::String(v.printed())),
                    })
                    .collect(),
            );
            let printed = match &e.style {
                Some(style) => serde_json::json!({ "parameterStyle": style, "values": values }),
                None => values,
            };
            out.insert(e.name.printed(), printed);
        }
        Value::Object(out)
    }
}

/// A map as `KeysToMultiValuesSerializer` prints it: keys in the order `NottableString` sorts them (descending).
pub fn in_descending_key_order(map: &MultiMap) -> MultiMap {
    let mut sorted = map.clone();
    sorted.sort_by(|(a, _), (b, _)| b.cmp(a));
    sorted
}

impl MultiMapMatcher {
    /// What `SubSetMatcher` records first: `RegexStringMatcher` notes every failed comparison before negation, so
    /// the hint quotes the first expected name (or value) that did not equal an actual one, in matcher order and
    /// then in the order the actual pairs arrived.
    fn first_failed_comparison(&self, actual: &MultiMap) -> Option<super::Difference> {
        let pairs: Vec<(&str, &str)> = actual.iter().flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_str(), v.as_str()))).collect();
        for entry in &self.entries {
            let values: Vec<Option<&StringMatcher>> = if entry.values.is_empty() { vec![None] } else { entry.values.iter().map(Some).collect() };
            for value in values {
                for (k, v) in &pairs {
                    if !entry.name.matches_positive(k, true) {
                        return Some(super::Difference::String { expected: entry.name.printed(), found: k.to_string() });
                    }
                    if let Some(m) = value.filter(|m| !m.matches_positive(actual_value(v).0, true)) {
                        return Some(super::Difference::String { expected: m.printed(), found: v.to_string() });
                    }
                }
            }
        }
        None
    }
}

/// Which map is matched, which decides how its failures print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    /// A request's headers (`MultiValueMapMatcher` over `Headers`): `found` in descending key order, as the request
    /// prints them, and binary-header normalisation on.
    Headers,
    /// Query parameters, response headers (`MultiValueMapMatcher`): `found` as given, `none` when empty (a
    /// request without a query string has no parameters object).
    Parameters,
    /// Path parameters: as [`MapKind::Parameters`], but `extractPathParameters` always yields an object, so an
    /// empty one prints as `{ }`.
    PathParameters,
    /// Cookies (`HashMapMatcher`).
    Cookies,
}

/// What `RegexStringMatcher` records when `matcher` (before negation) does not match `found`: nothing for a blank
/// matcher, a numeric comparison's or `accept:` directive's own line, a schema's report, else the string failure.
fn comparison_failure(matcher: &StringMatcher, found: &str) -> Option<String> {
    let value = actual_value(found).0;
    super::string::note_would_match(matcher, value, false);
    if matcher.comparison() == super::string::Comparison::DateTime {
        // `NottableDateTimeString.matches` records a failure after its own negation
        if matcher.matches(value, true) {
            return None;
        }
        let format = if matcher.not_a_date_time(value) {
            "date-time match failed expected:{}found value that is not a date-time:{}"
        } else {
            "date-time match failed expected:{}found:{}"
        };
        return Some(super::format_log_message(1, format, &[&matcher.printed(), found]));
    }
    if matcher.is_blank() || matcher.matches_positive(value, true) {
        return None;
    }
    let format = match matcher.comparison() {
        super::string::Comparison::Numeric => "numeric comparison match failed expected:{}found:{}",
        super::string::Comparison::Accept => "accept header content-negotiation match failed expected:{}found:{}",
        super::string::Comparison::Schema => {
            let schema = matcher.schema().expect("schema matcher");
            return Some(schema_difference(schema, &schema.instance_text(found), &schema.errors(found)).log_text());
        }
        super::string::Comparison::String | super::string::Comparison::DateTime => "string or regex match failed expected:{}found:{}",
    };
    Some(super::format_log_message(1, format, &[&matcher.printed(), found]))
}

/// What `BinaryHeaderValueNormalizer.matchesIgnoringPadding` records for a `-bin` header's value: the comparison of
/// the values without their base64 padding (whose `would match` prints them so), then, when it fails, the
/// `(gRPC binary metadata: base64 padding ignored)` difference with the values as given.
fn binary_comparison_failure(matcher: &StringMatcher, found: &str) -> Option<String> {
    let normalized = matcher.without_base64_padding();
    let normalized = normalized.as_ref().unwrap_or(matcher);
    let found_normalized = super::string::strip_base64_padding(found).unwrap_or(found);
    super::string::note_would_match(normalized, found_normalized, false);
    if normalized.matches(found_normalized, true) {
        return None;
    }
    Some(super::format_log_message(
        1,
        "string or regex match failed expected:{}found:{}(gRPC binary metadata: base64 padding ignored)",
        &[&matcher.printed(), found],
    ))
}

pub(super) fn schema_difference(schema: &super::string::Schema, found: &str, errors: &str) -> super::Difference {
    super::Difference::Text(super::format_log_message(1, "schema match failed expect:{}found:{}errors:{}", &[&schema.printed, found, errors]))
}

/// The single `array`-typed schema of an entry, which is validated against all its values at once.
fn array_schema(entry: &Entry) -> Option<&super::string::Schema> {
    match entry.values.as_slice() {
        [m] => m.schema().filter(|s| s.type_.as_deref() == Some("array")),
        _ => None,
    }
}

/// The values of an array parameter as a JSON array of strings, non-exploded values split by their style's
/// delimiter.
fn array_text(entry: &Entry, values: &[&str]) -> String {
    let delimiter = match entry.style.as_deref() {
        Some("FORM" | "SIMPLE") => Some(","),
        Some("SPACE_DELIMITED") => Some(" "),
        Some("PIPE_DELIMITED") => Some("|"),
        _ => None,
    };
    let items: Vec<Value> = values
        .iter()
        .flat_map(|v| match delimiter {
            Some(d) => v.split(d).map(str::to_string).collect::<Vec<_>>(),
            None => vec![v.to_string()],
        })
        .map(Value::String)
        .collect();
    Value::Array(items).to_string()
}

#[cfg(test)]
mod tests {
    use super::MultiMapMatcher;
    use serde_json::json;

    fn map(pairs: &[(&str, &[&str])]) -> crate::request::MultiMap {
        pairs.iter().map(|(k, vs)| (k.to_string(), vs.iter().map(|v| v.to_string()).collect())).collect()
    }

    #[test]
    fn definitions_match_as_nottable_strings() {
        let filter = MultiMapMatcher::compile(&json!({"someKey": ["someValue"]}));
        let regex = MultiMapMatcher::compile(&json!({"someK[a-z]{2}": ["someV[a-z]{4}"]}));
        let schema = MultiMapMatcher::compile(&json!({"someK[a-z]{2}": [{"schema": {"type": "string", "pattern": "^someV[a-z]{4}$"}}]}));
        assert!(filter.matches_definition(&regex));
        assert!(filter.matches_definition(&schema));
        assert!(schema.matches_definition(&schema));
        assert!(!MultiMapMatcher::compile(&json!({"someKey": ["otherValue"]})).matches_definition(&schema));
        assert!(!filter.matches_definition(&MultiMapMatcher::default()));
        let cookies = MultiMapMatcher::compile_single(&json!({"someKey": "someValue"}));
        assert!(cookies.matches_definition(&MultiMapMatcher::compile_single(&json!({"someK[a-z]{2}": "someV[a-z]{4}"}))));
    }

    #[test]
    fn subset_needs_each_expected_value() {
        let m = MultiMapMatcher::compile(&json!({"X-M": ["a", "b"]}));
        assert!(m.matches(&map(&[("x-m", &["b", "a", "c"])]), true));
        assert!(!m.matches(&map(&[("x-m", &["a"])]), true));
    }

    #[test]
    fn matching_key_needs_every_actual_value() {
        let m = MultiMapMatcher::compile(&json!({"keyMatchStyle": "MATCHING_KEY", "a": ["1"]}));
        assert!(m.matches(&map(&[("a", &["1"])]), true));
        assert!(!m.matches(&map(&[("a", &["1", "2"])]), true));
    }

    #[test]
    fn styled_values_split_on_their_delimiter() {
        let split = |style: &str, raw: &str| {
            let m = MultiMapMatcher::compile(&json!({"k": {"parameterStyle": style, "values": ["1"]}}));
            m.split_values(&map(&[("k", &[raw]), ("other", &["1,2"])]))
        };
        let values = |pairs: crate::request::MultiMap| pairs.into_iter().find(|(k, _)| k == "k").map(|(_, vs)| vs).unwrap_or_default();
        assert_eq!(values(split("FORM", "1,2,3")), ["1", "2", "3"]);
        assert_eq!(values(split("PIPE_DELIMITED", "1|2|3")), ["1", "2", "3"]);
        for raw in ["1 2 3", "1+2+3", "1%202%203"] {
            assert_eq!(values(split("SPACE_DELIMITED", raw)), ["1", "2", "3"], "{raw}");
        }
        // An exploded style keeps each value whole; other names are never split.
        assert_eq!(values(split("PIPE_DELIMITED_EXPLODED", "1|2")), ["1|2"]);
        assert_eq!(split("FORM", "1").into_iter().find(|(k, _)| k == "other").unwrap().1, ["1,2"]);
    }

    #[test]
    fn split_values_decide_the_match() {
        let form = MultiMapMatcher::compile(&json!({"k": {"parameterStyle": "FORM", "values": ["1"]}}));
        assert!(form.matches(&form.split_values(&map(&[("k", &["1,1,1"])])), true));
        assert!(form.matches(&form.split_values(&map(&[("k", &["1,2,3"])])), true));
        let matching_key = MultiMapMatcher::compile(&json!({"keyMatchStyle": "MATCHING_KEY", "k": {"parameterStyle": "FORM", "values": ["1"]}}));
        assert!(matching_key.matches(&matching_key.split_values(&map(&[("k", &["1,1,1"])])), true));
        assert!(!matching_key.matches(&matching_key.split_values(&map(&[("k", &["1,2,3"])])), true));
    }

    #[test]
    fn matching_key_difference_is_the_first_failed_value() {
        let m = MultiMapMatcher::compile(&json!({"keyMatchStyle": "MATCHING_KEY", "k": ["1"]}));
        let text = m.difference(&map(&[("k", &["1", "2"])])).log_text();
        assert!(text.contains("string or regex match failed") && text.contains("1") && text.contains("2"), "{text}");
    }

    #[test]
    fn negated_and_optional_keys() {
        let forbidden = MultiMapMatcher::compile(&json!({"!X-Forbidden": [".*"]}));
        assert!(forbidden.matches(&map(&[]), true));
        assert!(!forbidden.matches(&map(&[("x-forbidden", &["1"])]), true));
        let optional = MultiMapMatcher::compile(&json!({"?X-Opt": ["yes"]}));
        assert!(optional.matches(&map(&[]), true));
        assert!(optional.matches(&map(&[("x-opt", &["yes"])]), true));
        assert!(!optional.matches(&map(&[("x-opt", &["no"])]), true));
    }
}

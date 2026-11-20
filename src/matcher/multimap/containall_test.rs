//! Ports upstream's contain-all matrix onto this crate's own boundary split.
//!
//! Upstream, `SubSetMatcher.containsSubset` (`SubSetMatcherTest`) and `NottableString{HashMap,MultiMap}
//! .containsAll` (`NottableString{HashMap,MultiMap}ContainAllTest`) are the *same* algorithm: `containsAll`
//! builds a `RegexStringMatcher` from a `controlPlaneMatcher` flag and calls straight into `containsSubset`
//! for `SUB_SET` style. In this port that split lands on two different public methods instead:
//! - `controlPlaneMatcher = false` (every non-"ForControlPlane" test method) is [`MultiMapMatcher::matches`] —
//!   a pattern matched against a literal actual [`MultiMap`], never itself notted/regex/schema. None of the
//!   "matched" (actual/superset) sides ported here carry `!`/`?` markers, so building them as a literal
//!   `MultiMap` is faithful to what upstream's `NottableString.string(...)` would have produced for the same
//!   plain-string input.
//! - `controlPlaneMatcher = true` (every "ForControlPlane"-suffixed method) is
//!   [`MultiMapMatcher::matches_definition`] — hard-coded control-plane in this port, since that is its only
//!   caller (`control.rs`'s `verify`/`clear`-by-request-matcher, comparing two expectation definitions).
//!
//! `MATCHING_KEY` style is exercised the same way on both boundaries (`matching_key: bool` on the shared
//! [`MultiMapMatcher`]).

use super::{Entry, MultiMapMatcher};
use crate::matcher::string::StringMatcher;
use crate::request::MultiMap;

// ---------------------------------------------------------------------------------------------
// Shared construction and evaluation helpers
// ---------------------------------------------------------------------------------------------

/// A plain `NottableString`: `!`/`?` markers baked into the text, as upstream's `NottableString.string(s)`.
fn s(v: &str) -> StringMatcher {
    StringMatcher::from_text(v)
}

/// A `NottableSchemaString`: `NottableSchemaString.schemaString(pattern)`.
fn schema(pattern: &str) -> StringMatcher {
    StringMatcher::compile(&serde_json::json!({"schema": {"type": "string", "pattern": pattern}}))
}

/// An `array`-typed `NottableSchemaString`, validated against all the key's values at once
/// (`array_schema`/`array_text` in `multimap.rs`).
fn schema_array(item_pattern: &str) -> StringMatcher {
    StringMatcher::compile(&serde_json::json!({"schema": {"type": "array", "items": {"type": "string", "pattern": item_pattern}}}))
}

/// `new NottableStringMultiMap(logger, controlPlane, keyMatchStyle, pairs...)` /
/// `new NottableStringHashMap(logger, controlPlane, pairs...)`: one [`Entry`] per `(name, value)` pair — a
/// repeated name is a multi-value key once [`MultiMapMatcher`] flattens it back out (`pairs()`), exactly as
/// upstream's `NottableString[]...` constructor groups repeated names in its `backingMap` — needed not just for
/// fidelity but for correctness: `MultiMapMatcher::matches()`'s MATCHING_KEY path (`entry_matches`) checks one
/// `Entry`'s whole value list against every actual value under that key, so an ungrouped multi-value pattern
/// (two separate `Entry`s for the same name) would wrongly require each actual value to match *every* entry
/// instead of *any* of the name's combined values.
fn map_of(matching_key: bool, pairs: Vec<(StringMatcher, StringMatcher)>) -> MultiMapMatcher {
    let mut entries: Vec<Entry> = Vec::new();
    for (name, value) in pairs {
        match entries.iter_mut().find(|e: &&mut Entry| e.name.printed() == name.printed()) {
            Some(e) => e.values.push(value),
            None => entries.push(Entry { name, values: vec![value], style: None }),
        }
    }
    MultiMapMatcher { entries, matching_key, binary_headers: false }
}

/// [`map_of`] from plain `(&str, &str)` pairs — the common case, no schema, markers baked into the string.
fn def(matching_key: bool, pairs: &[(&str, &str)]) -> MultiMapMatcher {
    map_of(matching_key, pairs.iter().map(|(k, v)| (s(k), s(v))).collect())
}

/// The literal actual side of the `.matches()` boundary: `pairs` grouped by name, preserving first-seen
/// order — a `LinkedHashMap<String, List<String>>`, as upstream's `TestScenario` groups repeated keys.
fn grouped(pairs: &[(&str, &str)]) -> MultiMap {
    let mut out: MultiMap = Vec::new();
    for (k, v) in pairs {
        match out.iter_mut().find(|(name, _): &&mut (String, Vec<String>)| name == k) {
            Some((_, values)) => values.push(v.to_string()),
            None => out.push((k.to_string(), vec![v.to_string()])),
        }
    }
    out
}

/// One direction of `SubSetMatcher.containsSubset`/`containsAll(controlPlaneMatcher=false)` at the
/// `.matches()` boundary: does the pattern built from `pattern` (`SUB_SET` or `MATCHING_KEY`, per
/// `matching_key`) match the literal actual data built from `actual`?
fn matches(matching_key: bool, pattern: &[(&str, &str)], actual: &[(&str, &str)]) -> bool {
    def(matching_key, pattern).matches(&grouped(actual), true)
}

/// As [`matches`], at the `matches_definition()` (`containsAll(controlPlaneMatcher=true)`) boundary: both
/// sides are patterns.
fn matches_def(matching_key: bool, pattern: &[(&str, &str)], actual: &[(&str, &str)]) -> bool {
    def(matching_key, pattern).matches_definition(&def(matching_key, actual))
}

/// [`matches`] for a pattern that mixes schema and plain pairs (`map_of` directly, since a schema can't be a
/// JSON object key in the map-form `compile()` accepts).
fn matches_mixed(matching_key: bool, pattern: Vec<(StringMatcher, StringMatcher)>, actual: &[(&str, &str)]) -> bool {
    map_of(matching_key, pattern).matches(&grouped(actual), true)
}

/// [`matches_def`] where either side mixes schema and plain pairs.
fn matches_def_mixed(pattern: Vec<(StringMatcher, StringMatcher)>, actual: Vec<(StringMatcher, StringMatcher)>) -> bool {
    map_of(false, pattern).matches_definition(&map_of(false, actual))
}

type Eval = fn(bool, &[(&str, &str)], &[(&str, &str)]) -> bool;

/// One `TestScenario` at one key-match style: the forward direction (`pattern` against `actual`) always
/// matches `expect`; the reverse direction (`actual` as the pattern, `pattern` as the data) matches `expect`
/// too when `both_directions`, otherwise — only when `expect` is true, since a mismatch has no reverse
/// expectation to invert — the reverse must NOT match (upstream's `bidirectionMatch`).
fn scenario(eval: Eval, matching_key: bool, both_directions: bool, pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
    let style = if matching_key { "MATCHING_KEY" } else { "SUB_SET" };
    assert_eq!(eval(matching_key, pattern, actual), expect, "{style} forward: pattern {pattern:?} vs actual {actual:?}");
    if both_directions {
        assert_eq!(eval(matching_key, actual, pattern), expect, "{style} reverse: pattern {actual:?} vs actual {pattern:?}");
    } else if expect {
        assert!(!eval(matching_key, actual, pattern), "{style} reverse should not match: pattern {actual:?} vs actual {pattern:?}");
    }
}

/// `shouldPassScenarios`/`shouldPassScenariosSingleDirection`: SUB_SET, and — unless `subset_only` (upstream's
/// `includeMatchingKey = false`, used only where MATCHING_KEY legitimately disagrees, e.g. multi-value keys) —
/// also MATCHING_KEY, both styles expecting the same `expect`.
fn both_styles(eval: Eval, both_directions: bool, subset_only: bool, pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
    scenario(eval, false, both_directions, pattern, actual, expect);
    if !subset_only {
        scenario(eval, true, both_directions, pattern, actual, expect);
    }
}

/// Picks `matches_def` over `matches` when either side carries a `!`/`?` marker and neither side has a regex
/// metacharacter: a direction that needs a marker-aware "actual" side (a reverse direction with markers on the
/// original pattern, or — rarer — a forward direction whose "matched" array itself carries markers, e.g.
/// `notKeyOne` against `!keyOne`) can only be represented by `matches_definition()`, since `.matches()`'s
/// actual side is always a literal `MultiMap`. This is safe for pure NOT/optional comparisons (`controlPlaneMatcher`
/// only changes regex/schema *direction*), but NOT once a regex metacharacter is present alongside a marker:
/// `matches_definition()`'s control-plane bidirectional regex would then accept a reverse match upstream's own
/// non-controlplane `containsAll` rejects (see `should_contain_all_optional_keys_and_multi_values`) — for that
/// combination `matches()`'s literal treatment of the marker text as a mismatching literal happens to give the
/// same (correct) answer upstream's SingleDirection assertions need, so plain `matches` wins there instead.
fn eval_either(a: &[(&str, &str)], b: &[(&str, &str)]) -> Eval {
    const META: &[char] = &['.', '*', '+', '[', ']', '(', ')', '{', '}', '|', '^', '$', '\\'];
    let marked = |side: &[(&str, &str)]| side.iter().any(|(k, v)| k.starts_with(['!', '?']) || v.starts_with(['!', '?']));
    let has_regex_meta = |side: &[(&str, &str)]| {
        side.iter().any(|(k, v)| [k, v].into_iter().any(|s| s.trim_start_matches(['!', '?']).chars().any(|c| META.contains(&c))))
    };
    if (marked(a) || marked(b)) && !(has_regex_meta(a) || has_regex_meta(b)) { matches_def } else { matches }
}

/// `shouldPassScenarios` at the `.matches()`/`matches_definition()` boundary (bidirectional, both key-match
/// styles) — see [`eval_either`].
fn pass(pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
    both_styles(eval_either(pattern, actual), true, false, pattern, actual, expect);
}

/// `shouldPassScenariosSingleDirection` — see [`eval_either`].
fn pass_single(pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
    both_styles(eval_either(pattern, actual), false, false, pattern, actual, expect);
}

/// `shouldPassScenariosSingleDirectionSubSetOnly` — see [`eval_either`].
fn pass_single_subset_only(pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
    both_styles(eval_either(pattern, actual), false, true, pattern, actual, expect);
}

/// `shouldPassScenariosSubSetOnly`: bidirectional, SUB_SET only.
fn pass_subset_only(pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
    both_styles(eval_either(pattern, actual), true, true, pattern, actual, expect);
}

/// `shouldPassScenariosControlPlane`: bidirectional at `matches_definition()` (control plane can match a
/// regex/schema either way), single-direction at `.matches()` (without control plane, only the "pattern side
/// carries the regex" direction can succeed).
fn pass_control_plane(pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
    scenario(matches_def, false, true, pattern, actual, expect);
    scenario(matches_def, true, true, pattern, actual, expect);
    scenario(matches, false, false, pattern, actual, expect);
    scenario(matches, true, false, pattern, actual, expect);
}

/// `shouldPassScenariosControlPlaneSingleDirection`: single-direction at `matches_definition()` too (the
/// scenario's `matched` side deliberately carries the regex, so even control plane only matches one way); the
/// `.matches()` boundary, without control plane at all, can only fail this scenario in both directions —
/// upstream expresses that as `reverseResult = true`, negating the expectation for that half.
fn pass_control_plane_single(pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
    scenario(matches_def, false, false, pattern, actual, expect);
    scenario(matches_def, true, false, pattern, actual, expect);
    scenario(matches, false, false, pattern, actual, !expect);
    scenario(matches, true, false, pattern, actual, !expect);
}

/// `shouldPassScenariosControlPlaneSubSetOnly`.
fn pass_control_plane_subset_only(pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
    scenario(matches_def, false, true, pattern, actual, expect);
    scenario(matches, false, false, pattern, actual, expect);
}

/// `shouldPassScenariosControlPlaneSingleDirectionSubSetOnly`.
fn pass_control_plane_single_subset_only(pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
    scenario(matches_def, false, false, pattern, actual, expect);
    scenario(matches, false, false, pattern, actual, !expect);
}

// ---------------------------------------------------------------------------------------------
// SubSetMatcherTest — `.matches()` boundary directly, SUB_SET style only (the class under test has no
// key-match-style concept at all)
// ---------------------------------------------------------------------------------------------

mod subset_matcher_test {
    use super::*;

    #[test]
    fn should_contain_subset_for_empty() {
        assert!(matches(false, &[], &[("one", "one"), ("two", "two"), ("three", "three")]));
    }

    #[test]
    fn should_contain_subset_for_multi_values_all_matching() {
        assert!(matches(
            false,
            &[("one", "one_one"), ("one", "one_two"), ("two", "two"), ("?four", "four")],
            &[("one", "one_one"), ("one", "one_two"), ("two", "two"), ("three", "three")],
        ));
    }

    #[test]
    fn should_contain_subset_for_multi_values_subset() {
        assert!(matches(
            false,
            &[("one", "one_one"), ("two", "two"), ("?four", "four")],
            &[("one", "one_one"), ("one", "one_two"), ("two", "two"), ("three", "three")],
        ));
    }

    #[test]
    fn should_contain_subset_for_notted_key() {
        assert!(matches(false, &[("one", "one"), ("!two", "two"), ("?four", "four")], &[("one", "one"), ("notTwo", "two"), ("three", "three")]));
    }

    #[test]
    fn should_contain_subset_for_notted_value() {
        assert!(matches(false, &[("one", "one"), ("two", "!two"), ("?four", "four")], &[("one", "one"), ("two", "notTwo"), ("three", "three")]));
    }

    #[test]
    fn should_contain_subset_for_notted_multi_value() {
        assert!(matches(
            false,
            &[("one", "one_one"), ("one", "!one_two"), ("two", "two"), ("?four", "four")],
            &[("one", "one_one"), ("one", "notOne_two"), ("two", "two"), ("three", "three")],
        ));
    }

    #[test]
    fn should_contain_subset_for_subset_with_present_optional() {
        assert!(matches(
            false,
            &[("one", "one"), ("two", "two"), ("?four", "four")],
            &[("one", "one"), ("two", "two"), ("three", "three"), ("four", "four")],
        ));
    }

    #[test]
    fn should_contain_subset_for_subset_with_not_present_optional() {
        assert!(matches(false, &[("one", "one"), ("two", "two"), ("?four", "four")], &[("one", "one"), ("two", "two"), ("three", "three")]));
    }

    #[test]
    fn should_contain_subset_for_optional_wrong_value() {
        assert!(!matches(
            false,
            &[("one", "one"), ("two", "two"), ("?four", "four")],
            &[("one", "one"), ("two", "two"), ("three", "three"), ("four", "wrong")],
        ));
    }

    #[test]
    fn should_contain_subset_for_optional_wrong_value_in_reverse() {
        assert!(!matches(
            false,
            &[("one", "one"), ("two", "two"), ("four", "four")],
            &[("one", "one"), ("two", "two"), ("three", "three"), ("?four", "wrong")],
        ));
    }

    #[test]
    fn should_contain_subset_for_extra_value() {
        assert!(!matches(
            false,
            &[("one", "one"), ("two", "two"), ("?four", "four"), ("five", "five")],
            &[("one", "one"), ("two", "two"), ("three", "three"), ("four", "four")],
        ));
    }

    #[test]
    fn should_contain_subset_for_wrong_value() {
        assert!(!matches(
            false,
            &[("one", "one"), ("two", "two"), ("?four", "four")],
            &[("one", "one"), ("two", "wrong"), ("three", "three"), ("four", "four")],
        ));
    }

    #[test]
    fn should_contain_subset_for_wrong_key() {
        assert!(!matches(
            false,
            &[("one", "one"), ("two", "two"), ("?four", "four")],
            &[("one", "one"), ("wrong", "two"), ("three", "three"), ("four", "four")],
        ));
    }

    #[test]
    fn should_contain_subset_for_schema_key() {
        assert!(matches_mixed(false, vec![(s("one"), s("one")), (schema("tw.{1}"), s("two"))], &[("one", "one"), ("two", "two"), ("three", "three")]));
    }

    #[test]
    fn should_contain_subset_for_schema_value() {
        assert!(matches_mixed(false, vec![(s("one"), s("one")), (s("two"), schema("tw.{1}"))], &[("one", "one"), ("two", "two"), ("three", "three")]));
    }

    #[test]
    fn should_contain_subset_for_schema_multi_value() {
        assert!(matches_mixed(
            false,
            vec![(s("one"), s("one_one")), (s("one"), schema("one_t.*")), (s("two"), s("two")), (s("?four"), s("four"))],
            &[("one", "one_one"), ("one", "one_two"), ("two", "two"), ("three", "three")],
        ));
    }

    #[test]
    fn should_contain_subset_for_schema_key_and_multi_value() {
        let actual = [("one", "one_one"), ("one", "one_two"), ("two", "two"), ("three", "three")];
        assert!(matches_mixed(
            false,
            vec![(schema("o.*"), s("one_one")), (schema("o.*"), s("one_two")), (s("two"), s("two")), (s("?four"), s("four"))],
            &actual,
        ));
        // the same two schema-keyed entries, without the actual side's second "one" value, do not match: each
        // schema-keyed entry needs its own matching actual pair, one schema entry cannot be satisfied twice.
        assert!(!matches_mixed(
            false,
            vec![(schema("o.*"), s("one_one")), (schema("o.*"), s("one_two")), (s("two"), s("two")), (s("?four"), s("four"))],
            &[("one", "one_one"), ("two", "two"), ("three", "three")],
        ));
    }

    #[test]
    fn should_contain_subset_with_positive_and_notted_keys() {
        // Issue #1974: notted parameters should not count toward required matches.
        assert!(matches(false, &[("name", "John"), ("!age", ".*")], &[("name", "John")]));
    }

    #[test]
    fn should_contain_subset_with_multiple_positive_and_notted_keys() {
        assert!(matches(false, &[("name", "John"), ("city", "London"), ("!age", ".*"), ("!country", ".*")], &[("name", "John"), ("city", "London")]));
    }

    #[test]
    fn should_contain_subset_with_optional_and_notted_keys() {
        assert!(matches(false, &[("name", "John"), ("?age", ".*"), ("!country", ".*")], &[("name", "John")]));
    }

    #[test]
    fn should_not_contain_subset_when_notted_key_is_present() {
        assert!(!matches(false, &[("name", "John"), ("!age", ".*")], &[("name", "John"), ("age", "25")]));
    }
}

// ---------------------------------------------------------------------------------------------
// `NottableStringMultiMapContainAllTest`'s dedicated MATCHING_KEY notted-key regression (W3-3b):
// `containsAll(controlPlaneMatcher=false)`, so the `.matches()` boundary. None of these carry markers on
// the actual side, so a literal `MultiMap` is faithful here too. Found while porting the matrix: this port's
// `entry_matches()` had the pre-fix bug (comparing a notted key's *values* instead of asserting the key's
// *absence*) until the fix that added this module; see `src/matcher/multimap.rs`'s `entry_matches`.
// ---------------------------------------------------------------------------------------------

mod matching_key_notted_regression_test {
    use super::*;

    #[test]
    fn should_match_notted_key_when_key_absent() {
        assert!(matches(true, &[("!absentKey", "ignoredValue")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")]));
    }

    #[test]
    fn should_not_match_notted_key_when_key_present() {
        assert!(!matches(true, &[("!keyOne", "ignoredValue")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")]));
    }

    #[test]
    fn should_not_match_notted_key_when_key_present_as_sole_entry() {
        assert!(!matches(true, &[("!keyOne", "ignoredValue")], &[("keyOne", "valueOne")]));
    }

    #[test]
    fn should_not_match_notted_key_even_when_aggregated_value_would_have_matched() {
        // The pattern's value ("valueTwo") is chosen so it equals the unrelated key keyTwo's value; the
        // pre-fix bug aggregated keyTwo's value under `!keyOne` and wrongly matched it.
        assert!(!matches(true, &[("!keyOne", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")]));
    }

    #[test]
    fn should_match_notted_key_against_empty_actual_map() {
        assert!(matches(true, &[("!absentKey", "ignoredValue")], &[]));
    }

    #[test]
    fn should_handle_notted_optional_key_as_absence_assertion() {
        // notted takes precedence over optional: presence still fails the match regardless of optionality.
        assert!(!matches(true, &[("?!keyOne", "ignoredValue")], &[("keyOne", "valueOne")]));
        assert!(matches(true, &[("?!keyOne", "ignoredValue")], &[("keyTwo", "valueTwo")]));
    }

    #[test]
    fn should_match_notted_regex_key_when_no_actual_key_matches() {
        assert!(matches(true, &[("!key.*", "ignoredValue")], &[("headerOne", "valueOne"), ("headerTwo", "valueTwo")]));
    }

    #[test]
    fn should_not_match_notted_regex_key_when_an_actual_key_matches() {
        assert!(!matches(true, &[("!key.*", "ignoredValue")], &[("keyOne", "valueOne"), ("headerTwo", "valueTwo")]));
    }

    #[test]
    fn should_match_mixed_notted_and_plain_keys() {
        let pattern: &[(&str, &str)] = &[("keyOne", "valueOne"), ("!absentKey", "ignoredValue")];
        assert!(matches(true, pattern, &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")]));
        assert!(!matches(true, pattern, &[("keyOne", "valueOne"), ("absentKey", "valueTwo")]));
    }
}

// ---------------------------------------------------------------------------------------------
// `NottableStringHashMapContainAllTest` — cookies (`compile_single`'s shape): one value per key, and no
// `KeyMatchStyle` at all (`NottableStringHashMap.containsAll` has no MATCHING_KEY concept), so every scenario
// here is SUB_SET style only.
// ---------------------------------------------------------------------------------------------

mod hashmap_containall_test {
    use super::*;

    fn hpass(pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
        scenario(matches, false, true, pattern, actual, expect);
    }
    fn hpass_single(pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
        scenario(matches, false, false, pattern, actual, expect);
    }
    /// `shouldPassScenariosControlPlane`.
    fn hpass_cp(pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
        scenario(matches_def, false, true, pattern, actual, expect);
        scenario(matches, false, false, pattern, actual, expect);
    }
    /// `shouldPassScenariosControlPlaneSingleDirection`.
    fn hpass_cp_single(pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
        scenario(matches_def, false, false, pattern, actual, expect);
        scenario(matches, false, false, pattern, actual, !expect);
    }
    /// `shouldPassScenarios` (bidirectional) for a scenario whose pattern carries `!`/`?` markers that the
    /// *reverse* direction needs the "actual" side to honour too — something only `matches_definition()` can
    /// represent, since `.matches()`'s actual side is always a literal `MultiMap` by this port's own design
    /// (real HTTP data never carries these markers, so this boundary never needs to parse them). Upstream's
    /// `containsAll(controlPlaneMatcher=false)` is symmetric regardless; `controlPlaneMatcher` only changes
    /// regex/schema direction, which these NOT/optional-only scenarios never exercise, so `matches_definition()`
    /// gives the same answer non-controlplane `containsAll` would here.
    fn hpass_symmetric(pattern: &[(&str, &str)], actual: &[(&str, &str)], expect: bool) {
        scenario(matches_def, false, true, pattern, actual, expect);
    }

    // EMPTY

    #[test]
    fn should_contain_all_empty() {
        hpass_single(&[], &[("keyOne", "valueOne")], true);
        hpass_single(&[], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass_single(&[], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")], true);
    }

    // IDENTICAL

    #[test]
    fn should_contain_all_identical_keys_and_values() {
        hpass(&[("keyOne", "valueOne")], &[("keyOne", "valueOne")], true);
        hpass(&[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    // DIFFERENT CASE

    #[test]
    fn should_contain_all_different_case_keys() {
        hpass(&[("KEYOne", "valueOne")], &[("keyOne", "valueOne")], true);
        hpass(&[("KEYOne", "valueOne"), ("keyTWO", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyTHREE", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    #[test]
    fn should_contain_all_different_case_values() {
        hpass(&[("keyOne", "valueONE")], &[("keyOne", "valueOne")], true);
        hpass(&[("keyOne", "VALUEOne"), ("keyTwo", "VALUETwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass(
            &[("keyOne", "valueOne"), ("keyTwo", "VALUETwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    // SUBSET

    #[test]
    fn should_contain_all_subset_keys_and_values() {
        hpass_single(&[], &[("keyOne", "valueOne")], true);
        hpass_single(&[("keyOne", "valueOne")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass_single(
            &[("keyOne", "valueOne"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    // NON MATCHING

    #[test]
    fn should_contain_all_non_matching_keys() {
        hpass(&[("notKeyOne", "valueOne")], &[("keyOne", "valueOne")], false);
        hpass(&[("keyOne", "valueOne"), ("notKeyTwo", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        hpass(
            &[("notKeyOne", "valueOne"), ("keyTwo", "valueTwo"), ("notKeyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_values() {
        hpass(&[("keyOne", "notValueOne")], &[("keyOne", "valueOne")], false);
        hpass(&[("keyOne", "notValueOne"), ("keyTwo", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        hpass(
            &[("keyOne", "valueOne"), ("keyTwo", "notValueTwo"), ("keyThree", "notValueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_keys_and_values() {
        hpass(&[("notKeyOne", "notValueOne")], &[("keyOne", "valueOne")], false);
        hpass(&[("notKeyOne", "notValueOne"), ("notKeyTwo", "notValueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        hpass(
            &[("keyOne", "valueOne"), ("notKeyTwo", "notValueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    // REGEX

    #[test]
    fn should_contain_all_identical_regex_keys() {
        hpass_single(&[("key.*", "valueOne")], &[("keyOne", "valueOne")], true);
        hpass_single(&[("keyO.*", "valueOne"), ("keyT.*", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass_single(&[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], &[("keyO.*", "valueOne"), ("keyT.*", "valueTwo")], false);
    }

    #[test]
    fn should_contain_all_identical_regex_values() {
        hpass_single(&[("keyOne", "value.*")], &[("keyOne", "valueOne")], true);
        hpass_single(&[("keyOne", "value.*"), ("keyTwo", "value.*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
    }

    #[test]
    fn should_contain_all_identical_regex_keys_and_values() {
        hpass_single(&[("key.*", "value.*")], &[("keyOne", "valueOne")], true);
        hpass_single(&[("keyO.*", "value.*"), ("keyT.*", "value.*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
    }

    // REGEX SUBSET

    #[test]
    fn should_contain_all_subset_regex_keys_and_values() {
        hpass_single(&[("keyO.*", "valueO.*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass_single(
            &[("keyO.*", "valueO.*"), ("keyT.*", "valueT.*")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    // REGEX NON MATCHING

    #[test]
    fn should_contain_all_non_matching_regex_keys() {
        hpass(&[("keyO[0-9]*", "valueOne")], &[("keyOne", "valueOne")], false);
        hpass(&[("keyO[0-9]*", "valueOne"), ("keyT[0-9]*", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        hpass(
            &[("keyOne", "valueOne"), ("keyT[0-9]*", "valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_regex_values() {
        hpass(&[("keyOne", "value[0-9]*")], &[("keyOne", "valueOne")], false);
        hpass(&[("keyOne", "value[0-9]*"), ("keyTwo", "value[0-9]*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        hpass(
            &[("keyOne", "valueOne"), ("keyTwo", "value[0-9]*"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_regex_keys_and_values() {
        hpass(&[("key[0-9]*", "value[0-9]*")], &[("keyOne", "valueOne")], false);
        hpass(&[("keyO[0-9]*", "value[0-9]*"), ("keyT[0-9]*", "value[0-9]*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        hpass(
            &[("keyOne", "valueOne"), ("keyT[0-9]*", "value[0-9]*"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    // SCHEMA

    #[test]
    fn should_contain_all_identical_schema_keys() {
        assert!(matches_mixed(false, vec![(schema("key.*"), s("valueOne"))], &[("keyOne", "valueOne")]));
        assert!(matches_mixed(
            false,
            vec![(schema("keyO.*"), s("valueOne")), (schema("keyT.*"), s("valueTwo"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")],
        ));
        assert!(!matches_mixed(false, vec![(s("keyOne"), s("valueOne")), (s("keyTwo"), s("valueTwo"))], &[("keyOne", "valueOne")]));
    }

    #[test]
    fn should_contain_all_identical_schema_values() {
        assert!(matches_mixed(false, vec![(s("keyOne"), schema("valueO.*"))], &[("keyOne", "valueOne")]));
        assert!(matches_mixed(
            false,
            vec![(s("keyOne"), schema("valueO.*")), (s("keyTwo"), schema("valueT.*"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")],
        ));
    }

    #[test]
    fn should_contain_all_identical_schema_keys_and_values() {
        assert!(matches_mixed(false, vec![(schema("key.*"), schema("valueO.*"))], &[("keyOne", "valueOne")]));
        assert!(matches_mixed(
            false,
            vec![(schema("keyO.*"), schema("valueO.*")), (schema("keyT.*"), schema("valueT.*"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")],
        ));
        assert!(!matches_mixed(false, vec![(s("keyOne"), s("valueOne")), (s("keyTwo"), s("valueTwo"))], &[("keyOne", "valueOne")]));
    }

    // SCHEMA SUBSET

    #[test]
    fn should_contain_all_subset_schema_keys_and_values() {
        assert!(matches_mixed(
            false,
            vec![(schema("keyO.*"), schema("valueO.*"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
        ));
        assert!(matches_mixed(
            false,
            vec![(schema("keyO.*"), schema("valueO.*")), (schema("keyTw.*"), schema("valueTw.*"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
        ));
    }

    // SCHEMA NON MATCHING

    #[test]
    fn should_contain_all_not_matching_schema_keys() {
        assert!(!matches_mixed(false, vec![(schema("notKey.*"), s("valueOne"))], &[("keyOne", "valueOne")]));
        assert!(!matches_mixed(
            false,
            vec![(schema("notKeyO.*"), s("valueOne")), (schema("notKeyT.*"), s("valueTwo"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")],
        ));
    }

    #[test]
    fn should_contain_all_not_matching_schema_values() {
        assert!(!matches_mixed(false, vec![(s("keyOne"), schema("notNalueO.*"))], &[("keyOne", "valueOne")]));
        assert!(!matches_mixed(
            false,
            vec![(s("keyOne"), schema("notValueO.*")), (s("keyTwo"), schema("notValueT.*"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")],
        ));
        assert!(!matches_mixed(
            false,
            vec![(s("?keyO[a-z]{2}"), schema("^valueO.*$")), (s("?keyTwo"), schema("^valueT.*$"))],
            &[("keyOne", "notvalueOne"), ("keyTwo", "notvalueTwo")],
        ));
        assert!(!matches_mixed(
            false,
            vec![(s("?keyO[a-z]{2}"), schema("valueO.*")), (s("?keyTwo"), schema("valueT.*"))],
            &[("keyOne", "notValueOne"), ("keyTwo", "notValueTwo")],
        ));
        assert!(!matches_mixed(
            false,
            vec![(s("?keyO[a-z]{2}"), schema("valueO[a-z]{1}$")), (s("?keyTwo"), schema("valueT[a-z]{2}$"))],
            &[("keyOne", "notValueOne"), ("keyTwo", "notValueTwo")],
        ));
    }

    #[test]
    fn should_contain_all_not_matching_schema_keys_and_values() {
        assert!(!matches_mixed(false, vec![(schema("notKey.*"), schema("notValueO.*"))], &[("keyOne", "valueOne")]));
        assert!(!matches_mixed(
            false,
            vec![(schema("notKeyO.*"), schema("notValueO.*")), (schema("notKeyT.*"), schema("notValueT.*"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")],
        ));
    }

    // NOTTED

    #[test]
    fn should_contain_all_notted_keys() {
        hpass_symmetric(&[("!notKeyOne", "valueOne")], &[("keyOne", "valueOne")], true);
        hpass_single(&[("!notKeyOne", "value.*"), ("!notKeyTwo", "value.*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass_single(
            &[("keyOne", "valueOne"), ("!notKeyTwo", "value.*"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
        hpass_symmetric(&[("!notKeyOne", "valueOne"), ("!notKeyTwo", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass_symmetric(
            &[("keyOne", "valueOne"), ("!notKeyTwo", "valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    #[test]
    fn should_contain_all_notted_values() {
        hpass_symmetric(&[("keyOne", "!notValueOne")], &[("keyOne", "valueOne")], true);
        hpass_symmetric(&[("keyOne", "!notValueOne"), ("keyTwo", "!notValueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass_symmetric(
            &[("keyOne", "valueOne"), ("keyTwo", "!notValueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    #[test]
    fn should_contain_all_notted_keys_and_values() {
        hpass_symmetric(&[("!notKeyOne", "!notValueOne")], &[("keyOne", "valueOne")], true);
        hpass_symmetric(&[("!notKeyOne", "!notValueOne"), ("!notKeyTwo", "!notValueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass_symmetric(
            &[("keyOne", "valueOne"), ("!notKeyTwo", "!notValueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    // NOTTED SUBSET

    #[test]
    fn should_contain_all_subset_notted_keys_and_values() {
        hpass_single(&[("keyOne", "!notValueOne")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass_single(&[("!notKeyOne", "!notValueOne")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass_single(
            &[("keyOne", "!notValueOne"), ("keyTwo", "!notValueTwo")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
        hpass_single(
            &[("!notKeyOne", "!notValueOne"), ("!notKeyTwo", "!notValueTwo")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    // NOTTED NOT MATCHING

    #[test]
    fn should_contain_all_non_matching_notted_keys() {
        hpass(&[("!keyOne", "valueOne")], &[("keyOne", "valueOne")], false);
        hpass(&[("!keyOne", "valueOne"), ("!keyTwo", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        hpass(
            &[("keyOne", "valueOne"), ("!keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_notted_values() {
        hpass(&[("keyOne", "!valueOne")], &[("keyOne", "valueOne")], false);
        hpass(&[("keyOne", "!valueOne"), ("keyTwo", "!valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        hpass(
            &[("keyOne", "valueOne"), ("keyTwo", "!valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_notted_keys_and_values() {
        hpass(&[("!keyOne", "!valueOne")], &[("keyOne", "valueOne")], false);
        hpass(&[("!keyOne", "valueOne"), ("keyTwo", "!valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        hpass(
            &[("keyOne", "valueOne"), ("!keyTwo", "valueTwo"), ("keyThree", "!valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    // OPTIONAL

    #[test]
    fn should_contain_all_optional_keys() {
        hpass_symmetric(&[("?keyOne", "valueOne")], &[("keyOne", "valueOne")], true);
        hpass_symmetric(&[("?keyOne", "valueOne")], &[], true);
        hpass_symmetric(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass_symmetric(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyOne", "valueOne")], true);
        hpass_symmetric(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyTwo", "valueTwo")], true);
        hpass_symmetric(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("?keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
        hpass_symmetric(&[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("?keyThree", "valueThree")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
    }

    // OPTIONAL SUBSET

    #[test]
    fn should_contain_all_optional_subset_keys_and_values() {
        hpass_symmetric(&[("?keyOne", "valueOne")], &[("?keyOne", "valueOne")], true);
        hpass_symmetric(&[("?keyOne", "valueOne")], &[("keyOne", "valueOne")], true);
        hpass_symmetric(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("?keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass_symmetric(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], true);

        hpass_single(&[("?keyOne", "valueOne")], &[("keyTwo", "valueTwo")], true);
        hpass_single(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyTwo", "valueTwo"), ("keyThree", "valueThree")], true);
        hpass_single(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyOne", "valueOne"), ("keyThree", "valueThree")], true);
        hpass_single(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("?keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyFour", "valueFour")],
            true,
        );

        // can't match subsets in reverse
        hpass_single(&[("?keyOne", "valueOne")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        hpass_single(
            &[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
        hpass_single(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("?keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree"), ("keyFour", "valueFour")],
            true,
        );
    }

    // OPTIONAL NOT MATCHING

    #[test]
    fn should_contain_all_non_matching_optional_values() {
        hpass(&[("?keyOne", "valueOne")], &[("keyOne", "notValueOne")], false);
        hpass(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyOne", "notValueOne"), ("keyTwo", "notValueTwo")], false);
        hpass(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyOne", "notValueOne")], false);
        hpass(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyTwo", "notValueTwo")], false);
        hpass(&[("?keyO[a-z]{2}", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyOne", "notValueOne"), ("keyTwo", "notValueTwo")], false);
    }

    // CONTROL PLANE - REGEX

    #[test]
    fn should_contain_all_identical_regex_keys_for_control_plane() {
        hpass_cp(&[("key.*", "valueOne")], &[("keyOne", "valueOne")], true);
        hpass_cp(&[("keyO.*", "valueOne"), ("keyT.*", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
    }

    #[test]
    fn should_contain_all_identical_regex_values_for_control_plane() {
        hpass_cp(&[("keyOne", "value.*")], &[("keyOne", "valueOne")], true);
        hpass_cp(&[("keyOne", "value.*"), ("keyTwo", "value.*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
    }

    #[test]
    fn should_contain_all_identical_regex_keys_and_values_for_control_plane() {
        hpass_cp(&[("key.*", "value.*")], &[("keyOne", "valueOne")], true);
        hpass_cp(&[("keyO.*", "value.*"), ("keyT.*", "value.*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
    }

    // CONTROL PLANE - REGEX SUBSET

    #[test]
    fn should_contain_all_subset_regex_keys_and_values_for_control_plane() {
        hpass_cp_single(&[("keyOne", "valueOne")], &[("keyO.*", "valueO.*"), ("keyTwo", "valueTwo")], true);
        hpass_cp_single(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")],
            &[("keyO.*", "valueO.*"), ("keyT.*", "valueT.*"), ("keyThree", "valueThree")],
            true,
        );
    }

    // CONTROL PLANE - REGEX NOT MATCHING

    #[test]
    fn should_contain_all_non_matching_regex_keys_for_control_plane() {
        hpass_cp(&[("key.*", "valueOne")], &[("notKeyOne", "valueOne")], false);
        hpass_cp(&[("keyO.*", "valueOne"), ("keyT.*", "valueTwo")], &[("notKeyOne", "valueOne"), ("notKeyTwo", "valueTwo")], false);
    }

    #[test]
    fn should_contain_all_non_matching_regex_values_for_control_plane() {
        hpass_cp(&[("keyOne", "value.*")], &[("keyOne", "notValueOne")], false);
        hpass_cp(&[("keyOne", "value.*"), ("keyTwo", "value.*")], &[("keyOne", "notValueOne"), ("keyTwo", "notValueTwo")], false);
    }

    #[test]
    fn should_contain_all_non_matching_regex_keys_and_values_for_control_plane() {
        hpass_cp(&[("key.*", "value.*")], &[("keyOne", "notValueOne")], false);
        hpass_cp(&[("keyO.*", "value.*"), ("keyT.*", "value.*")], &[("keyOne", "notValueOne"), ("keyTwo", "notValueTwo")], false);
    }

    // CONTROL PLANE - SCHEMA

    #[test]
    fn should_contain_all_identical_schema_values_for_control_plane() {
        assert!(matches_def_mixed(vec![(s("keyOne"), schema("value.*"))], vec![(s("keyOne"), s("valueOne"))]));
        assert!(matches_def_mixed(
            vec![(s("keyOne"), schema("value.*")), (s("keyTwo"), schema("value.*"))],
            vec![(s("keyOne"), s("valueOne")), (s("keyTwo"), s("valueTwo"))],
        ));
    }

    // CONTROL PLANE - SCHEMA SUBSET

    #[test]
    fn should_contain_all_subset_schema_keys_and_values_for_control_plane() {
        assert!(matches_def_mixed(
            vec![(s("keyOne"), s("valueOne"))],
            vec![(schema("keyO.*"), schema("valueO.*")), (s("keyTwo"), s("valueTwo"))],
        ));
        assert!(matches_def_mixed(
            vec![(s("keyOne"), s("valueOne")), (s("keyTwo"), s("valueTwo"))],
            vec![(schema("keyO.*"), schema("valueO.*")), (schema("keyT.*"), schema("valueT.*")), (s("keyThree"), s("valueThree"))],
        ));
    }

    // CONTROL PLANE - SCHEMA NOT MATCHING

    #[test]
    fn should_contain_all_non_matching_schema_keys_for_control_plane() {
        assert!(!matches_def_mixed(vec![(schema("key.*"), s("valueOne"))], vec![(s("notKeyOne"), s("valueOne"))]));
        assert!(!matches_def_mixed(
            vec![(schema("keyO.*"), s("valueOne")), (schema("keyT.*"), s("valueTwo"))],
            vec![(s("notKeyOne"), s("valueOne")), (s("notKeyTwo"), s("valueTwo"))],
        ));
    }

    #[test]
    fn should_contain_all_non_matching_schema_values_for_control_plane() {
        assert!(!matches_def_mixed(vec![(s("keyOne"), schema("value.*"))], vec![(s("keyOne"), s("notValueOne"))]));
        assert!(!matches_def_mixed(
            vec![(s("keyOne"), schema("value.*")), (s("keyTwo"), schema("value.*"))],
            vec![(s("keyOne"), s("notValueOne")), (s("keyTwo"), s("notValueTwo"))],
        ));
    }

    #[test]
    fn should_contain_all_non_matching_schema_keys_and_values_for_control_plane() {
        assert!(!matches_def_mixed(vec![(schema("key.*"), schema("value.*"))], vec![(s("keyOne"), s("notValueOne"))]));
        assert!(!matches_def_mixed(
            vec![(schema("key.*"), schema("value.*")), (schema("key.*"), schema("value.*"))],
            vec![(s("keyOne"), s("notValueOne")), (s("keyTwo"), s("notValueTwo"))],
        ));
    }
}

// ---------------------------------------------------------------------------------------------
// `NottableStringMultiMapContainAllTest` — the remaining ~68 generic-matrix methods (the 9 MATCHING_KEY
// notted-key regression methods are ported above, `matching_key_notted_regression_test`). Multi-value keys
// (a repeated name) are ordinary repeated pairs — `def`/`grouped` already group by key.
// ---------------------------------------------------------------------------------------------

mod multimap_containall_test {
    use super::*;

    // EMPTY

    #[test]
    fn should_contain_all_empty() {
        pass_single(&[], &[("keyOne", "valueOne")], true);
        pass_single(&[], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        pass_single(&[], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")], true);
    }

    // IDENTICAL

    #[test]
    fn should_contain_all_identical_keys_and_values() {
        pass(&[("keyOne", "valueOne")], &[("keyOne", "valueOne")], true);
        pass(&[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        pass(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    #[test]
    fn should_contain_all_identical_keys_and_multi_values() {
        pass(
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            true,
        );
        pass(
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            true,
        );
        pass(
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            true,
        );
    }

    // DIFFERENT CASE

    #[test]
    fn should_contain_all_different_case_keys() {
        pass(&[("KEYOne", "valueOne")], &[("keyOne", "valueOne")], true);
        pass(&[("KEYOne", "valueOne"), ("keyTWO", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        pass(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyTHREE", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    #[test]
    fn should_contain_all_different_case_values() {
        pass(&[("keyOne", "valueONE")], &[("keyOne", "valueOne")], true);
        pass(&[("keyOne", "VALUEOne"), ("keyTwo", "VALUETwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        pass(
            &[("keyOne", "valueOne"), ("keyTwo", "VALUETwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    #[test]
    fn should_contain_all_different_case_keys_and_multi_values() {
        pass(
            &[("KEYOne", "valueOne_ONE"), ("KEYOne", "valueOne_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            true,
        );
        pass(
            &[("keyONE", "valueOne_ONE"), ("keyONE", "valueOne_Two"), ("keyTWO", "valueTwo_ONE"), ("keyTWO", "valueTwo_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            true,
        );
        pass(
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTWO", "valueTwo_ONE"),
                ("keyTWO", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            true,
        );
    }

    // SUBSET

    #[test]
    fn should_contain_all_subset_keys_and_values() {
        pass_single(&[], &[("keyOne", "valueOne")], true);
        pass_single(&[("keyOne", "valueOne")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        pass_single(
            &[("keyOne", "valueOne"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    #[test]
    fn should_contain_all_subset_multi_values() {
        pass_single_subset_only(
            &[("keyOne", "valueOne_One")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            true,
        );
        pass_single_subset_only(
            &[("keyOne", "valueOne_One"), ("keyTwo", "valueTwo_One")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            true,
        );
        pass_single_subset_only(
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyThree", "valueThree_One")],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            true,
        );
        pass_single(
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            true,
        );
        pass_single(
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            true,
        );
    }

    // NON MATCHING

    #[test]
    fn should_contain_all_non_matching_keys() {
        pass(&[("notKeyOne", "valueOne")], &[("keyOne", "valueOne")], false);
        pass(&[("keyOne", "valueOne"), ("notKeyTwo", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        pass(
            &[("notKeyOne", "valueOne"), ("keyTwo", "valueTwo"), ("notKeyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_values() {
        pass(&[("keyOne", "notValueOne")], &[("keyOne", "valueOne")], false);
        pass(&[("keyOne", "notValueOne"), ("keyTwo", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        pass(
            &[("keyOne", "valueOne"), ("keyTwo", "notValueTwo"), ("keyThree", "notValueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_value_in_multi_values() {
        pass(
            &[("keyOne", "valueOne_One"), ("keyOne", "notValueOne_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            false,
        );
        pass(
            &[("keyOne", "notValueOne_One"), ("keyOne", "notValueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            false,
        );
        pass(
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "notValueThree_Two"),
            ],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_keys_and_values() {
        pass(&[("notKeyOne", "notValueOne")], &[("keyOne", "valueOne")], false);
        pass(&[("notKeyOne", "notValueOne"), ("notKeyTwo", "notValueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        pass(
            &[("keyOne", "valueOne"), ("notKeyTwo", "notValueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    // REGEX

    #[test]
    fn should_contain_all_identical_regex_keys() {
        pass_single(&[("key.*", "valueOne")], &[("keyOne", "valueOne")], true);
        pass_single(&[("key.*", "valueOne"), ("key.*", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        pass_single(&[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], &[("key.*", "valueOne"), ("key.*", "valueTwo")], false);
    }

    #[test]
    fn should_contain_all_identical_regex_values() {
        pass_single(&[("keyOne", "value.*")], &[("keyOne", "valueOne")], true);
        pass_single(&[("keyOne", "value.*"), ("keyTwo", "value.*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
    }

    #[test]
    fn should_contain_all_identical_regex_keys_and_values() {
        pass_single(&[("key.*", "value.*")], &[("keyOne", "valueOne")], true);
        pass_single(&[("key.*", "value.*"), ("key.*", "value.*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
    }

    // REGEX SUBSET

    #[test]
    fn should_contain_all_subset_regex_keys_and_values() {
        pass_single(&[("keyO.*", "valueO.*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        pass_single(
            &[("keyO.*", "valueO.*"), ("keyT.*", "valueT.*")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    #[test]
    fn should_contain_all_subset_regex_keys_and_multi_values() {
        pass_single_subset_only(
            &[("keyO.*", "valueO.*")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            true,
        );
        pass_single_subset_only(
            &[("keyO.*", "valueOne_O.*"), ("keyO.*", "valueOne_Tw.*")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyOne", "valueOne_Three")],
            true,
        );
        pass_single_subset_only(
            &[("keyO.*", "valueOne_O.*"), ("keyO.*", "valueOne_Tw.*"), ("keyT.*", "valueT.*")],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyOne", "valueOne_Three"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyTwo", "valueTwo_Three"),
            ],
            true,
        );
        pass_single_subset_only(
            &[("keyO.*", "valueOne_O.*"), ("keyO.*", "valueOne_T.*"), ("keyT.*", "valueTwo_O.*"), ("keyT.*", "valueTwo_T.*")],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyTwo", "valueTwo_Three"),
            ],
            true,
        );
    }

    // REGEX NON MATCHING

    #[test]
    fn should_contain_all_non_matching_regex_keys() {
        pass(&[("keyO[0-9]*", "valueOne")], &[("keyOne", "valueOne")], false);
        pass(&[("keyO[0-9]*", "valueOne"), ("keyT[0-9]*", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        pass(
            &[("keyOne", "valueOne"), ("keyT[0-9]*", "valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_regex_values() {
        pass(&[("keyOne", "value[0-9]*")], &[("keyOne", "valueOne")], false);
        pass(&[("keyOne", "value[0-9]*"), ("keyTwo", "value[0-9]*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        pass(
            &[("keyOne", "valueOne"), ("keyTwo", "value[0-9]*"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_regex_value_in_multi_values() {
        pass(
            &[("keyOne", "value[0-9]*"), ("keyOne", "value[0-9]*")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            false,
        );
        pass(
            &[("keyOne", "valueOne_One"), ("keyOne", "value[0-9]*"), ("keyTwo", "value[0-9]*"), ("keyTwo", "value[0-9]*")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            false,
        );
        pass(
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "value[0-9]*"),
            ],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_regex_keys_and_values() {
        pass(&[("key[0-9]*", "value[0-9]*")], &[("keyOne", "valueOne")], false);
        pass(&[("keyO[0-9]*", "value[0-9]*"), ("keyT[0-9]*", "value[0-9]*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        pass(
            &[("keyOne", "valueOne"), ("keyT[0-9]*", "value[0-9]*"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    // SCHEMA

    #[test]
    fn should_contain_all_identical_schema_keys() {
        assert!(matches_mixed(false, vec![(schema("key.*"), s("valueOne"))], &[("keyOne", "valueOne")]));
        assert!(matches_mixed(
            false,
            vec![(schema("keyO.*"), s("valueOne")), (schema("keyT.*"), s("valueTwo"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")],
        ));
        assert!(!matches_mixed(false, vec![(s("keyOne"), s("valueOne")), (s("keyTwo"), s("valueTwo"))], &[("keyOne", "valueOne")]));
    }

    #[test]
    fn should_contain_all_identical_schema_values() {
        assert!(matches_mixed(false, vec![(s("keyOne"), schema("valueO.*"))], &[("keyOne", "valueOne")]));
        assert!(matches_mixed(
            false,
            vec![(s("keyOne"), schema("valueO.*")), (s("keyTwo"), schema("valueT.*"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")],
        ));
    }

    #[test]
    fn should_contain_all_identical_schema_values_for_array_schema() {
        let matcher = map_of(true, vec![(s("keyOne"), schema_array("value.*"))]);
        assert!(matcher.matches(&grouped(&[("keyOne", "valueOne"), ("keyOne", "valueTwo"), ("keyOne", "valueThree")]), true));

        let non_matching = map_of(true, vec![(s("keyOne"), schema_array("valueO.*"))]);
        assert!(!non_matching.matches(&grouped(&[("keyOne", "valueOne"), ("keyOne", "valueTwo"), ("keyOne", "valueThree")]), true));
    }

    #[test]
    fn should_contain_all_identical_schema_keys_and_values() {
        assert!(matches_mixed(false, vec![(schema("key.*"), schema("valueO.*"))], &[("keyOne", "valueOne")]));
        assert!(matches_mixed(
            false,
            vec![(schema("keyO.*"), schema("valueO.*")), (schema("keyT.*"), schema("valueT.*"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")],
        ));
        assert!(!matches_mixed(false, vec![(s("keyOne"), s("valueOne")), (s("keyTwo"), s("valueTwo"))], &[("keyOne", "valueOne")]));
    }

    // SCHEMA SUBSET

    #[test]
    fn should_contain_all_subset_schema_keys_and_values() {
        assert!(matches_mixed(
            false,
            vec![(schema("keyO.*"), schema("valueO.*"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
        ));
        assert!(matches_mixed(
            false,
            vec![(schema("keyO.*"), schema("valueO.*")), (schema("keyTw.*"), schema("valueTw.*"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
        ));
    }

    #[test]
    fn should_contain_all_subset_schema_keys_and_multi_values() {
        assert!(matches_mixed(
            false,
            vec![(schema("keyO.*"), schema("valueO.*"))],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
        ));
        assert!(matches_mixed(
            false,
            vec![(schema("keyO.*"), schema("valueO.*")), (schema("keyTw.*"), schema("valueTw.*"))],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree"),
            ],
        ));
    }

    // SCHEMA NON MATCHING

    #[test]
    fn should_contain_all_not_matching_schema_keys() {
        assert!(!matches_mixed(false, vec![(schema("notKey.*"), s("valueOne"))], &[("keyOne", "valueOne")]));
        assert!(!matches_mixed(
            false,
            vec![(schema("notKeyO.*"), s("valueOne")), (schema("notKeyT.*"), s("valueTwo"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")],
        ));
    }

    #[test]
    fn should_contain_all_not_matching_schema_values() {
        assert!(!matches_mixed(false, vec![(s("keyOne"), schema("notNalueO.*"))], &[("keyOne", "valueOne")]));
        assert!(!matches_mixed(
            false,
            vec![(s("keyOne"), schema("notValueO.*")), (s("keyTwo"), schema("notValueT.*"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")],
        ));
        assert!(!matches_mixed(
            false,
            vec![(s("?keyO[a-z]{2}"), schema("^valueO.*$")), (s("?keyTwo"), schema("^valueT.*$"))],
            &[("keyOne", "notvalueOne"), ("keyTwo", "notvalueTwo")],
        ));
        assert!(!matches_mixed(
            false,
            vec![(s("?keyO[a-z]{2}"), schema("valueO.*")), (s("?keyTwo"), schema("valueT.*"))],
            &[("keyOne", "notValueOne"), ("keyTwo", "notValueTwo")],
        ));
        assert!(!matches_mixed(
            false,
            vec![(s("?keyO[a-z]{2}"), schema("valueO[a-z]{1}$")), (s("?keyTwo"), schema("valueT[a-z]{2}$"))],
            &[("keyOne", "notValueOne"), ("keyTwo", "notValueTwo")],
        ));
    }

    #[test]
    fn should_contain_all_not_matching_schema_keys_and_values() {
        assert!(!matches_mixed(false, vec![(schema("notKey.*"), schema("notValueO.*"))], &[("keyOne", "valueOne")]));
        assert!(!matches_mixed(
            false,
            vec![(schema("notKeyO.*"), schema("notValueO.*")), (schema("notKeyT.*"), schema("notValueT.*"))],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")],
        ));
    }

    // NOTTED

    #[test]
    fn should_contain_all_notted_keys() {
        // upstream comments out the SingleDirection and SubSetOnly blocks here (unresolved at HEAD); only this
        // scenario is live.
        pass(&[("!notKeyOne", "valueOne")], &[("keyOne", "valueOne")], true);
    }

    #[test]
    fn should_contain_all_notted_values() {
        pass(&[("keyOne", "!notValueOne")], &[("keyOne", "valueOne")], true);
        pass(&[("keyOne", "!notValueOne"), ("keyTwo", "!notValueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        pass(
            &[("keyOne", "valueOne"), ("keyTwo", "!notValueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    #[test]
    fn should_contain_all_notted_keys_and_multi_values() {
        pass(
            &[("keyOne", "!notValueOne_One"), ("keyOne", "valueOne_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            true,
        );
        pass(
            &[
                ("keyOne", "!notValueOne_One"),
                ("keyOne", "!notValueOne_Two"),
                ("keyTwo", "!notValueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
            ],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            true,
        );
        pass(
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "!notValueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            true,
        );
    }

    #[test]
    fn should_contain_all_notted_keys_and_values() {
        pass(&[("!notKeyOne", "!notValueOne")], &[("keyOne", "valueOne")], true);
        pass(&[("!notKeyOne", "!notValueOne"), ("!notKeyTwo", "!notValueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        pass(
            &[("keyOne", "valueOne"), ("!notKeyTwo", "!notValueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
        // can't match subsets in reverse; matching key still matches in reverse (but subset doesn't) so subset only
        pass_single_subset_only(&[("!keyOne", "!notValueOne")], &[("notKeyOne", "valueOne"), ("notKeyOne", "valueOne")], true);
    }

    // NOTTED SUBSET

    #[test]
    fn should_contain_all_subset_notted_keys_and_values() {
        pass_single_subset_only(&[("keyOne", "!notValueOne")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        pass_single_subset_only(&[("!notKeyOne", "!notValueOne")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        pass_single_subset_only(
            &[("keyOne", "!notValueOne"), ("keyTwo", "!notValueTwo")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
        pass_single_subset_only(
            &[("!notKeyOne", "!notValueOne"), ("!notKeyTwo", "!notValueTwo")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    #[test]
    fn should_contain_all_subset_notted_keys_and_multi_values() {
        pass_single_subset_only(
            &[("keyOne", "!notValueOne_One")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            true,
        );
        pass_single_subset_only(
            &[("keyOne", "!notValueOne_One"), ("keyTwo", "!notValueTwo_One")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            true,
        );
        pass_single_subset_only(
            &[("keyOne", "!notValueOne_One"), ("keyOne", "!notValueOne_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            true,
        );
        pass_single_subset_only(
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyThree", "!notValueThree_One")],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            true,
        );
    }

    // NOTTED NOT MATCHING

    #[test]
    fn should_contain_all_non_matching_notted_keys() {
        pass(&[("!keyOne", "valueOne")], &[("keyOne", "valueOne")], false);
        pass(&[("!keyOne", "valueOne"), ("!keyTwo", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        pass_subset_only(
            &[("keyOne", "valueOne"), ("!keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
        pass_subset_only(&[("!keyOne", ".*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
    }

    #[test]
    fn should_contain_all_non_matching_notted_values() {
        pass(&[("keyOne", "!valueOne")], &[("keyOne", "valueOne")], false);
        pass(&[("keyOne", "!valueOne"), ("keyTwo", "!valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        pass(
            &[("keyOne", "valueOne"), ("keyTwo", "!valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_notted_keys_and_multi_values() {
        pass_subset_only(
            &[("keyOne", "!valueOne_One"), ("keyOne", "valueOne_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            false,
        );
        pass_subset_only(
            &[("keyOne", "!valueOne_One"), ("keyOne", "!valueOne_Two"), ("keyTwo", "!valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            false,
        );
        pass_subset_only(
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "!valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_notted_keys_and_values() {
        pass(&[("!keyOne", "!valueOne")], &[("keyOne", "valueOne")], false);
        pass(&[("!keyOne", "valueOne"), ("keyTwo", "!valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], false);
        pass(
            &[("keyOne", "valueOne"), ("!keyTwo", "valueTwo"), ("keyThree", "!valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    // OPTIONAL

    #[test]
    fn should_contain_all_optional_keys() {
        pass(&[("?keyOne", "valueOne")], &[("keyOne", "valueOne")], true);
        pass(&[("?keyOne", "valueOne")], &[], true);
        pass(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        pass(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyOne", "valueOne")], true);
        pass(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyTwo", "valueTwo")], true);
        pass(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("?keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
        pass(&[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("?keyThree", "valueThree")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
    }

    #[test]
    fn should_contain_all_optional_keys_and_multi_values() {
        pass_single(&[("?keyOne", "valueOne.*")], &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")], true);
        pass_single(
            &[("?keyOne", "valueOne.*"), ("?keyTwo", "valueTwo.*")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            true,
        );
        pass(
            &[("?keyOne", "valueOne_One"), ("?keyOne", "valueOne_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            true,
        );
        pass(
            &[("?keyOne", "valueOne_One"), ("?keyOne", "valueOne_Two"), ("?keyTwo", "valueTwo_One"), ("?keyTwo", "valueTwo_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            true,
        );
    }

    // OPTIONAL SUBSET

    #[test]
    fn should_contain_all_optional_subset_keys_and_values() {
        pass(&[("?keyOne", "valueOne")], &[("?keyOne", "valueOne")], true);
        pass(&[("?keyOne", "valueOne")], &[("keyOne", "valueOne")], true);
        pass(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("?keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        pass(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], true);

        pass_single(&[("?keyOne", "valueOne")], &[("keyTwo", "valueTwo")], true);
        pass_single(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyTwo", "valueTwo"), ("keyThree", "valueThree")], true);
        pass_single(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyOne", "valueOne"), ("keyThree", "valueThree")], true);
        pass_single(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("?keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyFour", "valueFour")],
            true,
        );

        // can't match subsets in reverse
        pass_single(&[("?keyOne", "valueOne")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
        pass_single(
            &[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
        pass_single(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("?keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree"), ("keyFour", "valueFour")],
            true,
        );
    }

    #[test]
    fn should_contain_all_optional_subset_keys_and_multi_values() {
        pass_single(
            &[("?keyOne", "valueOne.*")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            true,
        );
        pass_single(
            &[("?keyOne", "valueOne_One"), ("?keyOne", "valueOne_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            true,
        );
        pass_single(
            &[("?keyOne", "valueOne.*"), ("?keyTwo", "valueTwo.*")],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            true,
        );
        pass_single(
            &[("?keyOne", "valueOne_One"), ("?keyOne", "valueOne_Two"), ("?keyTwo", "valueTwo_One"), ("?keyTwo", "valueTwo_Two")],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            true,
        );
    }

    // OPTIONAL NOT MATCHING

    #[test]
    fn should_contain_all_non_matching_optional_values() {
        pass(&[("?keyOne", "valueOne")], &[("keyOne", "notValueOne")], false);
        pass(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyOne", "notValueOne"), ("keyTwo", "notValueTwo")], false);
        pass(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyOne", "notValueOne")], false);
        pass(&[("?keyOne", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyTwo", "notValueTwo")], false);
        pass(&[("?keyO[a-z]{2}", "valueOne"), ("?keyTwo", "valueTwo")], &[("keyOne", "notValueOne"), ("keyTwo", "notValueTwo")], false);
    }

    #[test]
    fn should_contain_all_non_matching_optional_multi_values() {
        pass(&[("?keyOne", "valueOne.*")], &[("keyOne", "notValueOne_One"), ("keyOne", "notValueOne_Two")], false);
        pass(
            &[("?keyOne", "valueOne_One"), ("?keyOne", "valueOne_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "notValueOne_Two")],
            false,
        );
        pass(
            &[("?keyOne", "valueOne.*"), ("?keyTwo", "valueTwo.*")],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "notValueTwo_One"),
                ("keyTwo", "notValueTwo_Two"),
            ],
            false,
        );
        pass(
            &[("?keyOne", "valueOne_One"), ("?keyOne", "notValueOne_Two"), ("?keyTwo", "valueTwo_One"), ("?keyTwo", "notValueTwo_Two")],
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            false,
        );
    }

    // CONTROL PLANE - REGEX

    #[test]
    fn should_contain_all_identical_regex_keys_for_control_plane() {
        pass_control_plane(&[("key.*", "valueOne")], &[("keyOne", "valueOne")], true);
        pass_control_plane(&[("keyO.*", "valueOne"), ("keyT.*", "valueTwo")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
    }

    #[test]
    fn should_contain_all_identical_regex_values_for_control_plane() {
        pass_control_plane(&[("keyOne", "value.*")], &[("keyOne", "valueOne")], true);
        pass_control_plane(&[("keyOne", "value.*"), ("keyTwo", "value.*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
    }

    #[test]
    fn should_contain_all_identical_regex_keys_and_values_for_control_plane() {
        pass_control_plane(&[("key.*", "value.*")], &[("keyOne", "valueOne")], true);
        pass_control_plane(&[("key.*", "value.*"), ("key.*", "value.*")], &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], true);
    }

    // CONTROL PLANE - REGEX SUBSET

    #[test]
    fn should_contain_all_subset_regex_keys_and_values_for_control_plane() {
        pass_control_plane_single(&[("keyOne", "valueOne")], &[("keyO.*", "valueO.*"), ("keyTwo", "valueTwo")], true);
        pass_control_plane_single(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo")],
            &[("keyO.*", "valueO.*"), ("keyT.*", "valueT.*"), ("keyThree", "valueThree")],
            true,
        );
    }

    #[test]
    fn should_contain_all_subset_regex_keys_and_multi_values_for_control_plane() {
        pass_control_plane_single_subset_only(
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            &[("keyO.*", "valueOne_O.*"), ("keyO.*", "valueOne_Tw.*"), ("keyO.*", "valueOne_Th.*")],
            true,
        );
        pass_control_plane_single_subset_only(
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            &[
                ("keyO.*", "valueOne_O.*"),
                ("keyO.*", "valueOne_Tw.*"),
                ("keyO.*", "valueOne_Th.*"),
                ("keyT.*", "valueT.*"),
                ("keyT.*", "valueT.*"),
                ("keyT.*", "valueT.*"),
            ],
            true,
        );
    }

    // CONTROL PLANE - REGEX NOT MATCHING

    #[test]
    fn should_contain_all_non_matching_regex_keys_for_control_plane() {
        pass_control_plane(&[("key.*", "valueOne")], &[("notKeyOne", "valueOne")], false);
        pass_control_plane(&[("keyO.*", "valueOne"), ("keyT.*", "valueTwo")], &[("notKeyOne", "valueOne"), ("notKeyTwo", "valueTwo")], false);
    }

    #[test]
    fn should_contain_all_non_matching_regex_values_for_control_plane() {
        pass_control_plane(&[("keyOne", "value.*")], &[("keyOne", "notValueOne")], false);
        pass_control_plane(&[("keyOne", "value.*"), ("keyTwo", "value.*")], &[("keyOne", "notValueOne"), ("keyTwo", "notValueTwo")], false);
    }

    #[test]
    fn should_contain_all_non_matching_regex_keys_and_values_for_control_plane() {
        pass_control_plane(&[("key.*", "value.*")], &[("keyOne", "notValueOne")], false);
        pass_control_plane(&[("key.*", "value.*"), ("key.*", "value.*")], &[("keyOne", "notValueOne"), ("keyTwo", "notValueTwo")], false);
    }

    // CONTROL PLANE - SCHEMA

    #[test]
    fn should_contain_all_identical_schema_values_for_control_plane() {
        assert!(matches_def_mixed(vec![(s("keyOne"), schema("value.*"))], vec![(s("keyOne"), s("valueOne"))]));
        assert!(matches_def_mixed(
            vec![(s("keyOne"), schema("value.*")), (s("keyTwo"), schema("value.*"))],
            vec![(s("keyOne"), s("valueOne")), (s("keyTwo"), s("valueTwo"))],
        ));
    }

    // CONTROL PLANE - SCHEMA SUBSET

    #[test]
    fn should_contain_all_subset_schema_keys_and_values_for_control_plane() {
        assert!(matches_def_mixed(
            vec![(s("keyOne"), s("valueOne"))],
            vec![(schema("keyO.*"), schema("valueO.*")), (s("keyTwo"), s("valueTwo"))],
        ));
        assert!(matches_def_mixed(
            vec![(s("keyOne"), s("valueOne")), (s("keyTwo"), s("valueTwo"))],
            vec![(schema("keyO.*"), schema("valueO.*")), (schema("keyT.*"), schema("valueT.*")), (s("keyThree"), s("valueThree"))],
        ));
    }

    #[test]
    fn should_contain_all_subset_schema_keys_and_multi_values_for_control_plane() {
        assert!(matches_def_mixed(
            vec![(s("keyOne"), s("valueOne_One")), (s("keyOne"), s("valueOne_Two"))],
            vec![
                (schema("keyO.*"), schema("valueOne_O.*")),
                (schema("keyO.*"), schema("valueOne_Tw.*")),
                (schema("keyO.*"), schema("valueOne_Th.*")),
            ],
        ));
        assert!(matches_def_mixed(
            vec![
                (s("keyOne"), s("valueOne_One")),
                (s("keyOne"), s("valueOne_Two")),
                (s("keyTwo"), s("valueTwo_One")),
                (s("keyTwo"), s("valueTwo_Two")),
            ],
            vec![
                (schema("keyO.*"), schema("valueOne_O.*")),
                (schema("keyO.*"), schema("valueOne_Tw.*")),
                (schema("keyO.*"), schema("valueOne_Th.*")),
                (schema("keyT.*"), schema("valueT.*")),
                (schema("keyT.*"), schema("valueT.*")),
                (schema("keyT.*"), schema("valueT.*")),
            ],
        ));
    }

    // CONTROL PLANE - SCHEMA NOT MATCHING

    #[test]
    fn should_contain_all_non_matching_schema_keys_for_control_plane() {
        assert!(!matches_def_mixed(vec![(schema("key.*"), s("valueOne"))], vec![(s("notKeyOne"), s("valueOne"))]));
        assert!(!matches_def_mixed(
            vec![(schema("keyO.*"), s("valueOne")), (schema("keyT.*"), s("valueTwo"))],
            vec![(s("notKeyOne"), s("valueOne")), (s("notKeyTwo"), s("valueTwo"))],
        ));
    }

    #[test]
    fn should_contain_all_non_matching_schema_values_for_control_plane() {
        assert!(!matches_def_mixed(vec![(s("keyOne"), schema("value.*"))], vec![(s("keyOne"), s("notValueOne"))]));
        assert!(!matches_def_mixed(
            vec![(s("keyOne"), schema("value.*")), (s("keyTwo"), schema("value.*"))],
            vec![(s("keyOne"), s("notValueOne")), (s("keyTwo"), s("notValueTwo"))],
        ));
    }

    #[test]
    fn should_contain_all_non_matching_schema_keys_and_values_for_control_plane() {
        assert!(!matches_def_mixed(vec![(schema("key.*"), schema("value.*"))], vec![(s("keyOne"), s("notValueOne"))]));
        assert!(!matches_def_mixed(
            vec![(schema("key.*"), schema("value.*")), (schema("key.*"), schema("value.*"))],
            vec![(s("keyOne"), s("notValueOne")), (s("keyTwo"), s("notValueTwo"))],
        ));
    }

    // CONTROL PLANE - NOTTED

    #[test]
    fn should_contain_all_notted_keys_for_control_plane() {
        // upstream comments out the two symmetric-marker scenarios here (unresolved at HEAD); only the plain
        // pattern-vs-notted-actual scenario is live.
        pass(&[("keyOne", "valueOne")], &[("!notKeyOne", "valueOne")], true);
        pass_subset_only(&[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], &[("!notKeyOne", "valueOne"), ("!notKeyTwo", "valueTwo")], true);
        pass_subset_only(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("!notKeyTwo", "valueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    #[test]
    fn should_contain_all_notted_values_for_control_plane() {
        pass(&[("keyOne", "valueOne")], &[("keyOne", "!notValueOne")], true);
        pass(&[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], &[("keyOne", "!notValueOne"), ("keyTwo", "!notValueTwo")], true);
        pass(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "!notValueTwo"), ("keyThree", "valueThree")],
            true,
        );
    }

    #[test]
    fn should_contain_all_notted_keys_and_multi_values_for_control_plane() {
        pass(
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            &[("keyOne", "!notValueOne_One"), ("keyOne", "valueOne_Two")],
            true,
        );
        pass(
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            &[
                ("keyOne", "!notValueOne_One"),
                ("keyOne", "!notValueOne_Two"),
                ("keyTwo", "!notValueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
            ],
            true,
        );
        pass(
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "!notValueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            true,
        );
    }

    #[test]
    fn should_contain_all_notted_keys_and_values_for_control_plane() {
        pass(&[("keyOne", "valueOne")], &[("!notKeyOne", "!notValueOne")], true);
        pass(&[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], &[("!notKeyOne", "!notValueOne"), ("!notKeyTwo", "!notValueTwo")], true);
        pass(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("!notKeyTwo", "!notValueTwo"), ("keyThree", "valueThree")],
            true,
        );
        // can't match subsets in reverse; matching key still matches in reverse (but subset doesn't) so subset only
        pass_single_subset_only(
            &[("notKeyOne", "valueOne")],
            &[("!keyOne", "!notValueOne"), ("!notKeyTwo", "!notValueTwo")],
            true,
        );
    }

    // CONTROL PLANE - NOTTED NOT MATCHING

    #[test]
    fn should_contain_all_non_matching_notted_keys_for_control_plane() {
        pass_control_plane(&[("keyOne", "valueOne")], &[("!keyOne", "valueOne")], false);
        pass_control_plane(&[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], &[("!keyOne", "valueOne"), ("!keyTwo", "valueTwo")], false);
        pass_control_plane_subset_only(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("!keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            false,
        );
        pass_control_plane_subset_only(&[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], &[("!keyOne", ".*")], false);
    }

    #[test]
    fn should_contain_all_non_matching_notted_values_for_control_plane() {
        pass_control_plane(&[("keyOne", "valueOne")], &[("keyOne", "!valueOne")], false);
        pass_control_plane(&[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], &[("keyOne", "!valueOne"), ("keyTwo", "!valueTwo")], false);
        pass_control_plane(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("keyTwo", "!valueTwo"), ("keyThree", "valueThree")],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_notted_keys_and_multi_values_for_control_plane() {
        pass_control_plane_subset_only(
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two")],
            &[("keyOne", "!valueOne_One"), ("keyOne", "valueOne_Two")],
            false,
        );
        pass_control_plane_subset_only(
            &[("keyOne", "valueOne_One"), ("keyOne", "valueOne_Two"), ("keyTwo", "valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            &[("keyOne", "!valueOne_One"), ("keyOne", "!valueOne_Two"), ("keyTwo", "!valueTwo_One"), ("keyTwo", "valueTwo_Two")],
            false,
        );
        pass_control_plane_subset_only(
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            &[
                ("keyOne", "valueOne_One"),
                ("keyOne", "valueOne_Two"),
                ("keyTwo", "valueTwo_One"),
                ("keyTwo", "valueTwo_Two"),
                ("keyThree", "!valueThree_One"),
                ("keyThree", "valueThree_Two"),
            ],
            false,
        );
    }

    #[test]
    fn should_contain_all_non_matching_notted_keys_and_values_for_control_plane() {
        pass_control_plane(&[("keyOne", "valueOne")], &[("!keyOne", "!valueOne")], false);
        pass_control_plane(&[("keyOne", "valueOne"), ("keyTwo", "valueTwo")], &[("!keyOne", "valueOne"), ("keyTwo", "!valueTwo")], false);
        pass_control_plane(
            &[("keyOne", "valueOne"), ("keyTwo", "valueTwo"), ("keyThree", "valueThree")],
            &[("keyOne", "valueOne"), ("!keyTwo", "valueTwo"), ("keyThree", "!valueThree")],
            false,
        );
    }
}

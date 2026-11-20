//! `java.util.regex.Pattern`'s syntax, as the oracle's JDK 26 (Temurin 26.0.2) parses it.
//!
//! [`compile`] ports `Pattern.compile`'s recursive-descent parser (`expr`, `sequence`, `atom`, `escape`, `clazz`,
//! `range`, `family`, `group0`, `closure`, with `RemoveQEQuoting` and the `COMMENTS` cursor helpers) so a pattern
//! is accepted or refused exactly as on the JVM, with `PatternSyntaxException`'s description and index (the parser's
//! cursor less one, in code points of the `\Q…\E`-rewritten pattern). The parse yields a tree that is written out in
//! `fancy_regex` syntax with Java's semantics made explicit: every character set is evaluated (unions, `&&`
//! intersections, negations, `\p{…}` including the `java*` properties, blocks and scripts, from JDK 26's Unicode
//! 17.0.0 tables in `tables.rs`) and printed as code point ranges, case-insensitivity folds as `single`/`CIRange`/
//! `SliceI`/`SliceU` do, possessive
//! quantifiers become atomic groups, and `.`, `^`, `$`, `\Z`, `\b`, `\R` become the line-terminator and word rules of
//! their `Pattern` nodes. A look-behind is checked with `TreeInfo`'s `study` arithmetic.
//! A pattern with a case-insensitive back reference, an inline `(?c)`, `\X` or `\b{g}` is not translated: [`engine`]
//! walks its tree (`CIBackRef`, `NFCCharProperty`, and JDK 26's `Grapheme` in [`grapheme`]).

mod engine;
mod grapheme;
mod tables;

use regex_syntax::hir::{ClassUnicode, ClassUnicodeRange};
use std::borrow::Cow;
use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};

pub(crate) const CASE_INSENSITIVE: u32 = 0x02;
const COMMENTS: u32 = 0x04;
const MULTILINE: u32 = 0x08;
pub(crate) const DOTALL: u32 = 0x20;
pub(crate) const UNICODE_CASE: u32 = 0x40;
const CANON_EQ: u32 = 0x80;
const UNIX_LINES: u32 = 0x01;
const UNICODE_CHARACTER_CLASS: u32 = 0x100;
const MAX_REPS: i32 = 0x7FFF_FFFF;
const MAX_CODE_POINT: u32 = 0x10FFFF;

/// `PatternSyntaxException`: a description, the pattern and an index (`-1` when unknown).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternSyntaxException {
    pub description: String,
    pub pattern: String,
    pub index: i32,
}

impl fmt::Display for PatternSyntaxException {
    /// `getMessage()`, with the JVM's `\n` line separator.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.description)?;
        if self.index >= 0 {
            write!(f, " near index {}", self.index)?;
        }
        write!(f, "\n{}", self.pattern)?;
        let utf16: Vec<u16> = self.pattern.encode_utf16().collect();
        if self.index >= 0 && (self.index as usize) < utf16.len() {
            f.write_str("\n")?;
            for unit in &utf16[..self.index as usize] {
                f.write_str(if *unit == u16::from(b'\t') { "\t" } else { " " })?;
            }
            f.write_str("^")?;
        }
        Ok(())
    }
}

/// A translation of a pattern to a `fancy_regex` one.
type Translated = Arc<fancy_regex::Regex>;

/// A pattern `Pattern.compile` accepts, ready to match.
#[derive(Debug)]
pub struct JavaRegex {
    source: String,
    /// The pattern and flags as compiled, parsed again for a walk over UTF-16 units ([`JavaRegex::by_units`]).
    pattern: String,
    flags: u32,
    /// The parse and its group count, kept when `fancy_regex` cannot build `source` (a repetition count past its
    /// size limit): such a pattern is matched through translations sized to the input ([`sized`]).
    tree: Option<(Node, usize)>,
    /// Whether the pattern holds `\G`.
    last_match: bool,
    regex: Option<Arc<fancy_regex::Regex>>,
    /// For a pattern with a case-insensitive back reference, which `fancy_regex` compares otherwise: the tree to
    /// walk instead of any translation ([`engine`]).
    walk: Option<engine::Program>,
    /// The translation anchored at both ends, for `matches()`; built on first use.
    anchored: OnceLock<Option<Arc<fancy_regex::Regex>>>,
    /// For a pattern with `\G`: the translation built so a search may be told that `\G` cannot hold at its start
    /// ([`JavaRegex::find_all`]); built on first use.
    continued: OnceLock<Option<Arc<fancy_regex::Regex>>>,
    /// Translations of `tree` by repetition bound and use.
    by_size: Mutex<HashMap<(u64, Use), Option<Translated>>>,
    /// The walk of the pattern for [`JavaRegex::matches_budgeted`], whatever else runs it; built on first use.
    budgeted: OnceLock<Option<engine::Program>>,
    /// `tree` walked whole, for an input no sized translation of it can be built for; built on first use.
    whole: OnceLock<Option<engine::Program>>,
    /// Whether the pattern holds a look-behind, which reads UTF-16 units ([`JavaRegex::by_units`]).
    look_behind: bool,
    /// Whether a search tries every UTF-16 index (`Start`) and a match can begin between a supplementary
    /// character's surrogates ([`parse_rooted`]): such a search walks UTF-16 units ([`JavaRegex::by_units`]).
    unit_starts: bool,
    /// The walks of the pattern parsed with the surrogates' places taken by stand-ins, by the stand-ins' first code
    /// point ([`parse_units`]).
    units: Mutex<HashMap<u32, Option<Arc<engine::Program>>>>,
}

/// The largest repetition count a translation keeps, and the longest input (in characters, rounded up to a power of
/// two) a pattern with a larger one is matched on through a translation sized to it; past it the tree is walked,
/// since an automaton that large builds (or fails to build) and searches slowly enough to stall a request
/// (`a{100000}` over 200000 characters), where `Pattern`'s `Curly` iterates.
const SIZED_LIMIT: u64 = 1024;

/// What runs one match: a translation, or a walk of the tree.
enum Run<'a> {
    Regex(Arc<fancy_regex::Regex>),
    Walk(&'a engine::Program),
}

/// What a translation is built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Use {
    Find,
    Matches,
    Continued,
}

impl Use {
    fn build(self, source: &str) -> Option<Arc<fancy_regex::Regex>> {
        match self {
            Use::Find => fancy_regex::Regex::new(source),
            Use::Matches => fancy_regex::Regex::new(&format!(r"\A(?:{source})\z")),
            Use::Continued => fancy_regex::RegexBuilder::new(source).allow_input_assertion_overrides(true).build(),
        }
        .ok()
        .map(Arc::new)
    }
}

impl JavaRegex {
    /// `matcher(input).find()`.
    pub fn find(&self, input: &str) -> bool {
        self.try_find(input).unwrap_or(false)
    }

    /// `matcher(input).find()`, or `None` when the match cannot be run (no translation even sized to `input`, or the
    /// engine's backtracking limit).
    pub fn try_find(&self, input: &str) -> Option<bool> {
        if let Some((units, program)) = self.by_units(input, true) {
            return program.find_units(&units, 0, Some(0), 0).ok().map(|m| m.is_some());
        }
        match self.run(input, Use::Find)? {
            Run::Walk(walk) => walk.find(input, 0, Some(0), 0).ok().map(|m| m.is_some()),
            Run::Regex(regex) => regex.is_match(input).ok(),
        }
    }

    /// `matcher(input).find()`, or the exception `Pattern` throws there (`GraphemeBound`'s); a match that cannot be
    /// run is none, as [`JavaRegex::find`].
    pub fn find_or_throw(&self, input: &str) -> Result<bool, MatchFailure> {
        let found = if let Some((units, program)) = self.by_units(input, true) {
            program.find_units(&units, 0, Some(0), 0).map(|m| m.is_some())
        } else {
            match self.run(input, Use::Find) {
                Some(Run::Walk(walk)) => walk.find(input, 0, Some(0), 0).map(|m| m.is_some()),
                _ => return Ok(self.find(input)),
            }
        };
        match found {
            Ok(found) => Ok(found),
            Err(stop @ engine::Stop::Thrown(_)) => Err(stop.into()),
            Err(_) => Ok(false),
        }
    }

    /// `matcher(input).matches()`: the whole input, with backtracking into alternatives until it is consumed.
    pub fn matches(&self, input: &str) -> bool {
        if let Some((units, program)) = self.by_units(input, false) {
            return program.matches_units(&units).ok().flatten().is_some();
        }
        match self.run(input, Use::Matches) {
            Some(Run::Walk(walk)) => walk.matches(input).ok().flatten().is_some(),
            Some(Run::Regex(regex)) => regex.is_match(input).unwrap_or(false),
            None => false,
        }
    }

    /// `matcher(text).matches()` where `text` is a `CharSequence` that counts each `charAt` against a budget of `reads`
    /// and throws past it, and where a `StackOverflowError` is caught: the answer is `None` when the budget ran out or
    /// the recursion went deeper than `depth` walk levels (see `lint.rs`), and the characters read are returned either
    /// way. Always the walk, which reads as `Pattern` does; a pattern that cannot be walked answers `None`.
    pub fn matches_budgeted(&self, input: &str, reads: u64, depth: usize) -> (Option<bool>, u64) {
        let program = self.budgeted.get_or_init(|| parse(&self.pattern, self.flags).ok().map(|(node, groups)| engine::Program::new(&node, groups)));
        match program {
            Some(program) => program.matches_budgeted(input, reads, depth),
            None => (None, 0),
        }
    }

    /// [`JavaRegex::captures_or_throw`] with a match that cannot be run as no match, as the tests read groups.
    #[cfg(test)]
    pub fn captures<'t>(&self, input: &'t str) -> Option<Groups<'t>> {
        self.captures_or_throw(input).ok().flatten()
    }

    /// The groups of `matcher(input).find()`'s match; Java's capturing groups keep their numbers and names. `None`
    /// when nothing matches; the exception `Pattern` throws there (`GraphemeBound`'s) when the match cannot be run.
    pub fn captures_or_throw<'t>(&self, input: &'t str) -> Result<Option<Groups<'t>>, MatchFailure> {
        let thrown = |stop| match stop {
            engine::Stop::Thrown(_) => Err(MatchFailure::from(stop)),
            _ => Ok(None),
        };
        if let Some((units, program)) = self.by_units(input, true) {
            return match program.find_units(&units, 0, Some(0), 0) {
                Ok(spans) => Ok(spans.map(|spans| Groups { input, spans: units_back(&units, spans), names: program.names.clone() })),
                Err(stop) => thrown(stop),
            };
        }
        match self.run(input, Use::Find) {
            None => Ok(None),
            Some(Run::Walk(walk)) => match walk.find(input, 0, Some(0), 0) {
                Ok(spans) => Ok(spans.map(|spans| Groups { input, spans, names: walk.names.clone() })),
                Err(stop) => thrown(stop),
            },
            Some(Run::Regex(regex)) => Ok(regex.captures(input).ok().flatten().map(|captures| Groups::of(&regex, input, &captures))),
        }
    }

    /// Every match `Matcher.find()` reports in turn from a `reset()` matcher, as `replaceAll` walks them: each search
    /// starts where the previous match ended, one UTF-16 unit further when that match was empty, and `\G` holds only
    /// where the previous match ended (`oldLast`), so not at all after an empty match. One unit on from an empty match
    /// right before a supplementary character is between its surrogates: such a search is [`JavaRegex::find_split`],
    /// and its match's bounds there are byte 2 of the character (see [`slice`]). The error is the engine's (its
    /// backtracking limit).
    pub fn find_all<'t>(&self, input: &'t str) -> Result<Vec<Groups<'t>>, MatchFailure> {
        if let Some((units, program)) = self.by_units(input, true) {
            let text = units.text();
            let mut found = Vec::new();
            let (mut first, mut last, mut old_last) = (None, 0, 0);
            loop {
                let mut next = last;
                if first == Some(next) {
                    // One UTF-16 unit on from an empty match.
                    match text[next..].chars().next() {
                        Some(c) => next += c.len_utf8(),
                        None => break,
                    }
                }
                let Some(spans) = program.find_units(&units, next, (next == old_last).then_some(next), last).map_err(MatchFailure::from)? else {
                    break;
                };
                let (start, end) = spans[0].expect("group 0");
                (first, last, old_last) = (Some(start), end, end);
                found.push(Groups { input, spans: units_back(&units, spans), names: program.names.clone() });
            }
            return Ok(found);
        }
        let Some(run) = self.run(input, if self.last_match { Use::Continued } else { Use::Find }) else { return Ok(Vec::new()) };
        let names = match &run {
            Run::Walk(walk) => walk.names.clone(),
            Run::Regex(regex) => Arc::new(capture_names(regex)),
        };
        let names = |spans| Groups { input, spans, names: names.clone() };
        let mut found = Vec::new();
        let (mut first, mut last, mut old_last) = (None, 0, 0);
        loop {
            let mut next = last;
            if first == Some(next) {
                if !input.is_char_boundary(next) {
                    // After an empty match between the surrogates: the low surrogate's unit.
                    next += 2;
                } else {
                    match input[next..].chars().next() {
                        Some(c) if c.len_utf16() == 2 => match self.find_split(input, next, last)? {
                            Some(spans) => {
                                let (start, end) = spans[0].expect("group 0");
                                (first, last, old_last) = (Some(start), end, end);
                                found.push(names(spans));
                                continue;
                            }
                            // `Start` goes on from the unit after the low surrogate.
                            None => next += c.len_utf8(),
                        },
                        Some(c) => next += c.len_utf8(),
                        None => break,
                    }
                }
            }
            let spans = match &run {
                Run::Walk(walk) => match walk.find(input, next, (next == old_last).then_some(next), last).map_err(MatchFailure::from)? {
                    Some(spans) => spans,
                    None => break,
                },
                Run::Regex(regex) => {
                    let search = fancy_regex::RegexInput::new(input).from_pos(next).continue_from_previous_match_end(next == old_last);
                    match regex.captures_input(search).map_err(MatchFailure::from)? {
                        Some(captures) => (0..captures.len()).map(|i| captures.get(i).map(|m| (m.start(), m.end()))).collect(),
                        None => break,
                    }
                }
            };
            let (start, end) = spans[0].expect("group 0");
            (first, last, old_last) = (Some(start), end, end);
            found.push(names(spans));
        }
        Ok(found)
    }

    /// A search that starts between the surrogates of the supplementary character at byte `at`, after an empty match
    /// before it: `Pattern` reads a lone low surrogate there (`Character.codePointAt`), which a `char` cannot hold.
    /// The input is walked as UTF-16 units from the low surrogate's stand-in ([`engine::Units`]). `None` when no match
    /// starts there; `Start` then goes on from the next character, as an ordinary search.
    fn find_split(&self, input: &str, at: usize, last: usize) -> Result<Option<engine::Spans>, MatchFailure> {
        let Some(base) = stand_in_base(input) else { return Ok(None) };
        let Some(program) = self.units_program(base) else { return Ok(None) };
        let units = engine::Units::new(input, base);
        let found = program.attempt_units(&units, units.forward(at) + 4, units.forward(last)).map_err(MatchFailure::from)?;
        Ok(found.map(|spans| units_back(&units, spans)))
    }

    /// For a pattern with a look-behind, over an input holding a supplementary character: the input as UTF-16 units
    /// and the walk over them. `Behind` steps back one unit at a time and may read a lone low surrogate, `BehindS` steps
    /// by code points, reading a pair from its high surrogate even when the search started between them. Also, for a
    /// `search` by a pattern rooted at `Start` whose match can begin between surrogates ([`JavaRegex::unit_starts`]).
    fn by_units<'t>(&self, input: &'t str, search: bool) -> Option<(engine::Units<'t>, Arc<engine::Program>)> {
        if !(self.look_behind || search && self.unit_starts) || input.chars().all(|c| c.len_utf16() == 1) {
            return None;
        }
        let base = stand_in_base(input)?;
        Some((engine::Units::new(input, base), self.units_program(base)?))
    }

    /// The walk of the pattern parsed with the stand-ins from `base` in its sets.
    fn units_program(&self, base: u32) -> Option<Arc<engine::Program>> {
        let mut programs = self.units.lock().unwrap_or_else(|e| e.into_inner());
        if programs.len() >= 64 {
            programs.clear();
        }
        programs
            .entry(base)
            .or_insert_with(|| {
                parse_units(&self.pattern, self.flags, base).ok().map(|(node, groups)| Arc::new(engine::Program::new(&node, groups).unit_starts(self.unit_starts)))
            })
            .clone()
    }

    /// What runs a match on `input`: the walk when the pattern has one, else its translation (sized to `input` when
    /// the pattern's own is past `fancy_regex`'s size limit), else (no sized translation builds, or `input` is past
    /// [`SIZED_LIMIT`]) the tree walked whole.
    fn run(&self, input: &str, use_: Use) -> Option<Run<'_>> {
        if let Some(walk) = &self.walk {
            return Some(Run::Walk(walk));
        }
        if let Some(regex) = self.engine(input, use_) {
            return Some(Run::Regex(regex));
        }
        let (tree, groups) = self.tree.as_ref()?;
        self.whole.get_or_init(|| Some(engine::Program::new(tree, *groups))).as_ref().map(Run::Walk)
    }

    fn engine(&self, input: &str, use_: Use) -> Option<Arc<fancy_regex::Regex>> {
        if let Some((tree, groups)) = &self.tree {
            // No repetition of an operand that takes a character can run more times than `input` has characters, so
            // counts past a bound at least that long change nothing; the bound is rounded up to share translations.
            let bound = (input.chars().count() as u64).next_power_of_two().max(64);
            if bound > SIZED_LIMIT {
                return None;
            }
            let mut by_size = self.by_size.lock().unwrap_or_else(|e| e.into_inner());
            if by_size.len() >= 64 {
                by_size.clear();
            }
            return by_size
                .entry((bound, use_))
                .or_insert_with(|| {
                    let mut source = String::new();
                    emit(&sized(tree, bound), *groups, &mut source);
                    use_.build(&source)
                })
                .clone();
        }
        let cell = match use_ {
            Use::Find => return self.regex.clone(),
            Use::Matches => &self.anchored,
            Use::Continued => &self.continued,
        };
        cell.get_or_init(|| use_.build(&self.source)).clone()
    }
}

/// Why a search could not run, as the Java exception it stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchFailure {
    /// The exception's class name.
    pub class: &'static str,
    pub message: String,
}

impl From<engine::Stop> for MatchFailure {
    fn from(stop: engine::Stop) -> MatchFailure {
        let class = match stop {
            engine::Stop::Thrown(_) => "java.lang.StringIndexOutOfBoundsException",
            engine::Stop::Steps | engine::Stop::Depth | engine::Stop::JavaStack | engine::Stop::Budget => "java.lang.StackOverflowError",
        };
        MatchFailure { class, message: stop.to_string() }
    }
}

impl From<fancy_regex::Error> for MatchFailure {
    fn from(e: fancy_regex::Error) -> MatchFailure {
        MatchFailure { class: "java.lang.StackOverflowError", message: e.to_string() }
    }
}

/// The first code point of a block of [`SURROGATES`] private-use code points `input` holds none of: the surrogates'
/// stand-ins in a walk over its UTF-16 units.
fn stand_in_base(input: &str) -> Option<u32> {
    let used: Vec<u32> = input.chars().map(u32::from).filter(|&c| c >= 0xF0000).map(|c| (c - 0xF0000) / SURROGATES).collect();
    (0..32).find(|k| !used.contains(k)).map(|k| 0xF0000 + k * SURROGATES)
}

/// Spans in a walk's text mapped back to its input.
fn units_back(units: &engine::Units, spans: engine::Spans) -> engine::Spans {
    spans.into_iter().map(|s| s.map(|(a, b)| (units.back(a), units.back(b)))).collect()
}

/// One match's groups by number (0 is the whole match), and the pattern's group names.
#[derive(Debug, Clone)]
pub struct Groups<'t> {
    input: &'t str,
    spans: Vec<Option<(usize, usize)>>,
    names: Arc<Vec<(String, usize)>>,
}

/// The text one group matched.
#[derive(Debug, Clone, Copy)]
pub struct Group<'t> {
    input: &'t str,
    start: usize,
    end: usize,
}

impl<'t> Group<'t> {
    pub fn start(&self) -> usize {
        self.start
    }
    pub fn end(&self) -> usize {
        self.end
    }
    /// The group's text; a bound between surrogates leaves a lone half, written `?` ([`slice`]).
    pub fn as_str(&self) -> Cow<'t, str> {
        slice(self.input, self.start, self.end)
    }
}

/// `input` from byte `start` to `end` as the Java `String` between those indices, where either may lie between a
/// supplementary character's surrogates (byte 2 of its UTF-8 form, [`JavaRegex::find_all`]): each lone surrogate is
/// written `?`, as the response's UTF-8 encoder writes it.
pub fn slice(input: &str, start: usize, end: usize) -> Cow<'_, str> {
    if input.is_char_boundary(start) && input.is_char_boundary(end) {
        return Cow::Borrowed(&input[start..end]);
    }
    if start >= end {
        return Cow::Borrowed("");
    }
    let mut out = String::new();
    let mut from = start;
    if !input.is_char_boundary(start) {
        out.push('?');
        from += 2;
    }
    let to = if input.is_char_boundary(end) { end } else { end - 2 };
    out.push_str(&input[from..to.max(from)]);
    if to != end {
        out.push('?');
    }
    Cow::Owned(out)
}

impl<'t> Groups<'t> {
    fn of(regex: &fancy_regex::Regex, input: &'t str, captures: &fancy_regex::Captures<'t, str>) -> Groups<'t> {
        let spans = (0..captures.len()).map(|i| captures.get(i).map(|m| (m.start(), m.end()))).collect();
        Groups { input, spans, names: Arc::new(capture_names(regex)) }
    }

    /// The number of groups, the whole match included (`groupCount() + 1`).
    fn len(&self) -> usize {
        self.spans.len()
    }

    /// Group `i`, when it took part in the match.
    pub fn get(&self, i: usize) -> Option<Group<'t>> {
        let (start, end) = (*self.spans.get(i)?)?;
        Some(Group { input: self.input, start, end })
    }

    /// The named group, when the pattern has it and it took part in the match.
    pub fn name(&self, name: &str) -> Option<Group<'t>> {
        self.names.iter().find(|(n, _)| n == name).and_then(|&(_, i)| self.get(i))
    }

    /// `Matcher.appendReplacement`'s expansion of `replacement` (`$1`, `${name}`, `\` escapes), as
    /// `java_compat::methods::expand_replacement` does it for a `fancy_regex` match.
    pub fn expand(&self, replacement: &str) -> Result<String, java_compat::lang::JError> {
        use java_compat::lang::JError;
        let mut out = String::new();
        let mut it = replacement.chars().peekable();
        while let Some(c) = it.next() {
            match c {
                '\\' => match it.next() {
                    Some(n) => out.push(n),
                    None => return Err(JError::new("java.lang.IllegalArgumentException", "character to be escaped is missing")),
                },
                '$' => {
                    if it.peek() == Some(&'{') {
                        it.next();
                        let name: String = it.by_ref().take_while(|c| *c != '}').collect();
                        out.push_str(&self.name(&name).map(|m| m.as_str()).unwrap_or_default());
                    } else {
                        let mut digits = String::new();
                        while let Some(d) = it.peek().filter(|d| d.is_ascii_digit()) {
                            let candidate = format!("{digits}{d}");
                            if candidate.parse::<usize>().map(|n| n < self.len()).unwrap_or(false) || digits.is_empty() {
                                digits = candidate;
                                it.next();
                            } else {
                                break;
                            }
                        }
                        let n: usize = digits.parse().map_err(|_| JError::new("java.lang.IllegalArgumentException", "Illegal group reference"))?;
                        if n >= self.len() {
                            return Err(JError::new("java.lang.IndexOutOfBoundsException", format!("No group {n}")));
                        }
                        out.push_str(&self.get(n).map(|m| m.as_str()).unwrap_or_default());
                    }
                }
                c => out.push(c),
            }
        }
        Ok(out)
    }
}

fn capture_names(regex: &fancy_regex::Regex) -> Vec<(String, usize)> {
    regex.capture_names().enumerate().filter_map(|(i, name)| Some((name?.to_string(), i))).collect()
}

/// `node` with every repetition of an operand that takes at least one character limited to `bound` iterations: one
/// that needs more can never match (it keeps its operand, and so its groups' numbers, behind a failing look-ahead).
fn sized(node: &Node, bound: u64) -> Node {
    let inner = |n: &Node| Box::new(sized(n, bound));
    match node {
        Node::Seq(nodes) => Node::Seq(nodes.iter().map(|n| sized(n, bound)).collect()),
        Node::Alt(nodes) => Node::Alt(nodes.iter().map(|n| sized(n, bound)).collect()),
        Node::Group { capture, name, node } => Node::Group { capture: *capture, name: name.clone(), node: inner(node) },
        Node::Look { behind, negative, by_code_point, node } => {
            Node::Look { behind: *behind, negative: *negative, by_code_point: *by_code_point, node: inner(node) }
        }
        Node::Atomic(node) => Node::Atomic(inner(node)),
        Node::Ques { node, kind, group } => Node::Ques { node: inner(node), kind: *kind, group: *group },
        Node::Repeat { node, min, max, kind, group } => {
            let operand = inner(node);
            if min_chars(node) == 0 {
                return Node::Repeat { node: operand, min: *min, max: *max, kind: *kind, group: *group };
            }
            if *min as u64 > bound {
                let never = Node::Look { behind: false, negative: true, by_code_point: false, node: Box::new(Node::Empty) };
                return Node::Seq(vec![never, Node::Group { capture: false, name: None, node: operand }]);
            }
            let max = if *max == MAX_REPS { MAX_REPS } else { (*max as u64).min(bound) as i32 };
            Node::Repeat { node: operand, min: *min, max, kind: *kind, group: *group }
        }
        other => other.clone(),
    }
}

/// The fewest characters `node` matches.
fn min_chars(node: &Node) -> u64 {
    match node {
        Node::Char(_) | Node::Nfc(_) | Node::LineEnding | Node::Grapheme => 1,
        Node::Seq(nodes) => nodes.iter().fold(0u64, |sum, n| sum.saturating_add(min_chars(n))),
        Node::Alt(nodes) => nodes.iter().map(min_chars).min().unwrap_or(0),
        Node::Group { node, .. } | Node::Atomic(node) => min_chars(node),
        Node::Repeat { node, min, .. } => (*min as u64).saturating_mul(min_chars(node)),
        _ => 0,
    }
}

/// `Pattern.compile(pattern)`: the same pattern is compiled once and kept, since conversation predicates are
/// evaluated on every request.
pub fn compile(pattern: &str) -> Result<Arc<JavaRegex>, PatternSyntaxException> {
    compile_with_flags(pattern, 0)
}

/// `Pattern.compile(pattern, flags)` ([`DOTALL`], [`CASE_INSENSITIVE`], [`UNICODE_CASE`]), cached like [`compile`].
pub fn compile_with_flags(pattern: &str, flags: u32) -> Result<Arc<JavaRegex>, PatternSyntaxException> {
    type Cache = Mutex<HashMap<(String, u32), Result<Arc<JavaRegex>, PatternSyntaxException>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let key = (pattern.to_string(), flags);
    if let Some(hit) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return hit.clone();
    }
    let compiled = parse_rooted(pattern, flags).map(|(node, groups, unit_starts)| {
        let mut source = String::new();
        emit(&node, groups, &mut source);
        let walk = node
            .any(&|n| {
                matches!(n, Node::BackRef { ci: true, .. } | Node::Nfc(_) | Node::Grapheme | Node::Assert(Assertion::GraphemeBound))
                    || group_curly_with_inner_groups(n)
                    || accepting_with_inner_groups(n)
            })
            .then(|| engine::Program::new(&node, groups));
        // A count past `SIZED_LIMIT` builds into an automaton too large to search quickly: such a pattern is sized
        // to each input, or walked.
        let large = |n: i32| n != MAX_REPS && n as u64 > SIZED_LIMIT;
        let counted = node.any(&|n| matches!(n, Node::Repeat { min, max, .. } if large(*min) || large(*max)));
        let regex = if walk.is_some() || counted { None } else { Use::Find.build(&source) };
        let look_behind = node.any(&|n| matches!(n, Node::Look { behind: true, .. }));
        Arc::new(JavaRegex {
            last_match: node.any(&|n| matches!(n, Node::Assert(Assertion::LastMatch))),
            tree: (regex.is_none() && walk.is_none()).then_some((node, groups)),
            regex,
            walk,
            anchored: OnceLock::new(),
            continued: OnceLock::new(),
            by_size: Mutex::default(),
            whole: OnceLock::new(),
            budgeted: OnceLock::new(),
            look_behind,
            unit_starts,
            units: Mutex::default(),
            source,
            pattern: pattern.to_string(),
            flags,
        })
    });
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= 4096 {
        cache.clear();
    }
    cache.insert(key, compiled.clone());
    compiled
}

/// How a [`Replay::Repeat`] backtracks: `Pattern`'s `Qtype` less `INDEPENDENT`, which is [`Replay::Atomic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayKind {
    Greedy,
    Lazy,
    Possessive,
}

/// `Pattern.compile(pattern, flags)`'s tree as the backtracking replay of `regexMatchingTimeoutMillis` reads it
/// (`backtrack.rs`).
#[derive(Debug)]
pub(crate) enum Replay {
    Empty,
    /// One character from these inclusive ranges, as `Pattern` evaluates the set (case folding, `\p{…}`,
    /// intersections, `.`).
    Set(Vec<(char, char)>),
    Seq(Vec<Replay>),
    Alt(Vec<Replay>),
    /// A group, with its number when it captures.
    Group { index: Option<usize>, node: Box<Replay> },
    /// `X?` (`max` 1), `X*`, `X+`, `X{n,m}`; `max` is `None` when unbounded. `accept`: each iteration ends at
    /// `Pattern.accept`, which writes `Matcher.last` (`Ques`, `Curly`, `GroupCurly`; not `CharPropertyGreedy`, a
    /// group's `Branch` or `Loop`).
    Repeat { node: Box<Replay>, min: u32, max: Option<u32>, kind: ReplayKind, accept: bool },
    /// `Pos` / `Neg`.
    Ahead { negative: bool, node: Box<Replay> },
    /// `Behind` / `NotBehind`, with the body's `TreeInfo` lengths.
    Behind { negative: bool, min: usize, max: usize, node: Box<Replay> },
    /// `(?>X)`: `Ques` with `Qtype.INDEPENDENT`.
    Atomic(Box<Replay>),
    /// `^` without `MULTILINE`, `\A`, and `\G` (where the first search starts).
    Begin,
    /// Any other position test but `\b{g}`: `$`, `\Z`, `\z`, `^` with `MULTILINE`, `\b`, `\B`.
    Assert(ReplayAssertion),
    /// `BackRef`, or `CIBackRef` with `ci` (its `doUnicodeCase`).
    BackRef { group: usize, ci: Option<bool> },
    /// `XGrapheme` (`\X`): one grapheme cluster.
    Grapheme,
    /// `NFCCharProperty`: a class or `\p`/`\P` under an inline `(?c)`, these ranges.
    Nfc(Vec<(char, char)>),
    /// `GraphemeBound` (`\b{g}`), which reads `Matcher.last`.
    GraphemeBound,
}

/// `Pattern.compile(pattern, flags)`'s tree for the backtracking replay of `regexMatchingTimeoutMillis`: character
/// sets, sequences, alternatives, groups, repetitions of each `Qtype`, look-arounds, atomic groups, back references,
/// `\R`, the position tests, `\X`, `\b{g}` and `NFCCharProperty`. `None` when the pattern does not
/// compile.
pub(crate) fn replay_tree(pattern: &str, flags: u32) -> Option<Replay> {
    fn kind(kind: Qtype) -> ReplayKind {
        match kind {
            Qtype::Greedy => ReplayKind::Greedy,
            Qtype::Lazy => ReplayKind::Lazy,
            Qtype::Possessive => ReplayKind::Possessive,
        }
    }
    fn tree(node: &Node, next: &mut usize) -> Option<Replay> {
        let inner = |n: &Node, next: &mut usize| tree(n, next).map(Box::new);
        Some(match node {
            Node::Empty => Replay::Empty,
            Node::Char(c) => Replay::Set(c.ranges().iter().map(|r| (r.start(), r.end())).collect()),
            Node::Seq(nodes) => Replay::Seq(nodes.iter().map(|n| tree(n, next)).collect::<Option<_>>()?),
            Node::Alt(nodes) => Replay::Alt(nodes.iter().map(|n| tree(n, next)).collect::<Option<_>>()?),
            Node::Group { capture, node, .. } => {
                let index = capture.then(|| {
                    *next += 1;
                    *next - 1
                });
                Replay::Group { index, node: inner(node, next)? }
            }
            Node::Look { behind: false, negative, node, .. } => Replay::Ahead { negative: *negative, node: inner(node, next)? },
            Node::Look { behind: true, negative, node, .. } => {
                let mut info = TreeInfo::new();
                study_chain(&[&**node], &mut info);
                Replay::Behind { negative: *negative, min: info.min.max(0) as usize, max: info.max.max(0) as usize, node: inner(node, next)? }
            }
            Node::Atomic(node) => Replay::Atomic(inner(node, next)?),
            Node::Ques { node: atom, kind: k, group } => {
                let accept = !*group || *k == Qtype::Possessive || self_terminal(atom);
                Replay::Repeat { node: inner(atom, next)?, min: 0, max: Some(1), kind: kind(*k), accept }
            }
            Node::Repeat { node: atom, min, max, kind: k, group } => {
                // As `engine::convert` decides it: `Curly` but `CharPropertyGreedy`; `GroupCurly` for a group whose
                // body `study` finds deterministic.
                let accept = if !*group {
                    !(*k == Qtype::Greedy && *max == MAX_REPS && matches!(**atom, Node::Char(_)))
                } else {
                    *k == Qtype::Possessive || self_terminal(atom) || study_chain(&[&**atom], &mut TreeInfo::new())
                };
                Replay::Repeat {
                    node: inner(atom, next)?,
                    min: u32::try_from(*min).ok()?,
                    max: if *max == MAX_REPS { None } else { Some(u32::try_from(*max).ok()?) },
                    kind: kind(*k),
                    accept,
                }
            }
            Node::Assert(Assertion::Begin | Assertion::LastMatch) => Replay::Begin,
            Node::Assert(Assertion::GraphemeBound) => Replay::GraphemeBound,
            Node::Assert(a) => Replay::Assert(ReplayAssertion(*a)),
            // `LineEnding`: `\r\n`, or one line terminator when the rest fails after it.
            Node::LineEnding => {
                let set = |c: char| Replay::Set(vec![(c, c)]);
                let one = vec![('\n', '\r'), ('\u{85}', '\u{85}'), ('\u{2028}', '\u{2029}')];
                Replay::Alt(vec![Replay::Seq(vec![set('\r'), set('\n')]), Replay::Set(one)])
            }
            Node::BackRef { group, ci, unicode } => Replay::BackRef { group: *group, ci: ci.then_some(*unicode) },
            Node::Grapheme => Replay::Grapheme,
            Node::Nfc(c) => Replay::Nfc(c.ranges().iter().map(|r| (r.start(), r.end())).collect()),
        })
    }
    tree(&parse(pattern, flags).ok()?.0, &mut 1)
}

/// A position test of [`Replay::Assert`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReplayAssertion(Assertion);

impl ReplayAssertion {
    /// Whether it holds before `input[i]`.
    pub(crate) fn holds(self, input: &[char], i: usize) -> bool {
        engine::assertion_at(self.0, input, i)
    }
}

/// `Grapheme.nextBoundary(text, off, text.length())` over byte offsets, for the timeout replay; `off` must be before
/// the end.
pub(crate) fn grapheme_boundary(text: &str, off: usize) -> usize {
    grapheme::next_boundary(text, off, text.len())
}

/// The one code point `cluster`'s NFC form is, if it is one (`NFCCharProperty.match`).
pub(crate) fn nfc_single(cluster: &str) -> Option<char> {
    use unicode_normalization::UnicodeNormalization;
    let mut nfc = cluster.nfc();
    match (nfc.next(), nfc.next()) {
        (Some(c), None) => Some(c),
        _ => None,
    }
}

/// Whether `CIBackRef` takes input character `c1` for group character `c2` (`doUnicodeCase` is `unicode`).
pub(crate) fn ci_back_ref_equal(c1: char, c2: char, unicode: bool) -> bool {
    if c1 == c2 {
        return true;
    }
    if unicode {
        let (u1, u2) = (java_upper(c1 as u32), java_upper(c2 as u32));
        u1 == u2 || java_lower(u1) == java_lower(u2)
    } else {
        let lower = |c: u32| if (0x41..=0x5A).contains(&c) { c + 0x20 } else { c };
        lower(c1 as u32) == lower(c2 as u32)
    }
}

/// `Pattern.compile(pattern)`'s verdict alone.
pub fn check(pattern: &str) -> Result<(), PatternSyntaxException> {
    parse(pattern, 0).map(|_| ())
}

/// The pattern in `fancy_regex` syntax, matching as `Pattern` does.
#[cfg(test)]
pub fn translate(pattern: &str) -> Result<String, PatternSyntaxException> {
    let (node, groups) = parse(pattern, 0)?;
    let mut out = String::new();
    emit(&node, groups, &mut out);
    Ok(out)
}

fn parse(pattern: &str, flags: u32) -> Result<(Node, usize), PatternSyntaxException> {
    parse_rooted(pattern, flags).map(|(node, groups, _)| (node, groups))
}

/// [`parse`], and whether the pattern is rooted at `Start` with a match that can begin between a supplementary
/// character's surrogates: no `hasSupplementary`, and a pattern that can match empty or holds a `.` (every other
/// `Start` set leaves the surrogates out, since a predicate that reaches them is no `BmpCharPredicate`).
fn parse_rooted(pattern: &str, flags: u32) -> Result<(Node, usize, bool), PatternSyntaxException> {
    let mut p = Parser::new(pattern);
    p.flags = flags;
    let node = p.expr()?;
    if p.pattern_length != p.cursor {
        if p.peek() == ')' as u32 {
            return Err(p.error("Unmatched closing ')'"));
        } else if p.cursor == p.pattern_length + 1 && p.t(p.pattern_length.wrapping_sub(1)) == '\\' as u32 {
            return Err(p.error("Unescaped trailing backslash"));
        } else {
            return Err(p.error("Unexpected internal error"));
        }
    }
    let unit_starts = !p.has_supplementary && {
        let mut info = TreeInfo::new();
        study_chain(&[&node], &mut info);
        p.dot || info.min <= 0
    };
    Ok((node, p.capturing_group_count - 1, unit_starts))
}

thread_local! {
    /// While [`parse_units`] runs: the first code point of the block that stands for the surrogates in every set
    /// [`set`] builds.
    static STAND_IN: Cell<Option<u32>> = const { Cell::new(None) };
}

/// The code points that stand for the surrogates `D800..=DFFF` in a walk over UTF-16 units: `base + (s - 0xD800)`.
pub(super) const SURROGATES: u32 = 0x800;

/// [`parse`] with the block of [`SURROGATES`] code points from `base` in the place of the surrogates in every
/// character set: each stand-in in a set exactly when its surrogate is, so a walk over an input with stand-ins where
/// lone surrogates would be matches as `Pattern` matches them ([`engine::Units`]). Sets are not taken from or put in
/// [`ucd`]'s cache meanwhile.
fn parse_units(pattern: &str, flags: u32, base: u32) -> Result<(Node, usize), PatternSyntaxException> {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            STAND_IN.with(|s| s.set(None));
        }
    }
    STAND_IN.with(|s| s.set(Some(base)));
    let _reset = Reset;
    parse(pattern, flags)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Qtype {
    Greedy,
    Lazy,
    Possessive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Assertion {
    /// `^` without `MULTILINE`, and `\A`.
    Begin,
    /// `\G` (`LastMatch`): where the previous match ended (`Matcher.oldLast`), the search start on a first `find()`.
    LastMatch,
    /// `\z`.
    End,
    /// `$` and `\Z`: `Dollar`/`UnixDollar`.
    Dollar { multiline: bool, unix: bool },
    /// `^` with `MULTILINE`: `Caret`/`UnixCaret`.
    Caret { unix: bool },
    /// `\b` / `\B`.
    Bound { negated: bool, unicode: bool },
    /// `\b{g}`.
    GraphemeBound,
}

#[derive(Debug, Clone)]
enum Node {
    Empty,
    /// A `CharProperty`: one code point from a set.
    Char(ClassUnicode),
    /// An `NFCCharProperty`: a class or `\p`/`\P` under an inline `(?c)`, matched against the input's grapheme
    /// cluster normalised to NFC.
    Nfc(ClassUnicode),
    Seq(Vec<Node>),
    /// A `Branch`; an empty alternative is [`Node::Empty`].
    Alt(Vec<Node>),
    /// A group; `name` for a named capturing group, kept so `${name}` replacements resolve.
    Group { capture: bool, name: Option<String>, node: Box<Node> },
    /// `by_code_point`: a look-behind `findSupplementary` finds a supplementary character from (the pattern from
    /// the body's start to its end holds one): `BehindS`/`NotBehindS`, which step back by code points.
    Look { behind: bool, negative: bool, by_code_point: bool, node: Box<Node> },
    Atomic(Box<Node>),
    /// `X?` (`Ques`), or a group's `?` (`Branch` unless possessive).
    Ques { node: Box<Node>, kind: Qtype, group: bool },
    /// `X*`, `X+`, `X{n,m}` (`Curly`, `CharPropertyGreedy`, `GroupCurly` or `Loop`).
    Repeat { node: Box<Node>, min: i32, max: i32, kind: Qtype, group: bool },
    Assert(Assertion),
    /// `ci` for `CIBackRef`, `unicode` its `doUnicodeCase`.
    BackRef { group: usize, ci: bool, unicode: bool },
    LineEnding,
    Grapheme,
}

impl Node {
    /// Whether `test` holds for this node or any node inside it.
    fn any(&self, test: &impl Fn(&Node) -> bool) -> bool {
        test(self)
            || match self {
                Node::Seq(nodes) | Node::Alt(nodes) => nodes.iter().any(|n| n.any(test)),
                Node::Group { node, .. } | Node::Look { node, .. } | Node::Atomic(node) | Node::Ques { node, .. } | Node::Repeat { node, .. } => {
                    node.any(test)
                }
                _ => false,
            }
    }

    /// Matches nothing but a position; `fancy_regex` refuses to repeat such an operand (a capturing group is still
    /// emitted, since it sets its group).
    fn zero_width(&self) -> bool {
        match self {
            Node::Assert(_) | Node::Look { .. } | Node::Empty => true,
            Node::Group { capture: false, node, .. } | Node::Atomic(node) => node.zero_width(),
            Node::Seq(nodes) => nodes.iter().all(Node::zero_width),
            _ => false,
        }
    }
}

struct Parser<'p> {
    pattern: &'p str,
    temp: Vec<u32>,
    pattern_length: usize,
    cursor: usize,
    flags: u32,
    capturing_group_count: usize,
    named: HashMap<String, usize>,
    /// `Pattern.hasSupplementary`: a supplementary or surrogate code point in the pattern text, a `\P{..}`
    /// complement, or a `CharProperty` built from a predicate that is no `BmpCharPredicate`. Without it the pattern is
    /// rooted at `Start`, which tries every UTF-16 index, between a supplementary character's surrogates too; with it
    /// at `StartS`, which steps by code points (JDK 25 Pattern.java 1918-1924, 3096-3110).
    has_supplementary: bool,
    /// Whether the pattern holds a `.`, the one `CharProperty` without `hasSupplementary` that matches a lone low
    /// surrogate (`new CharProperty(DOT())`, not `newCharProperty`).
    dot: bool,
}

/// `Pattern.isSupplementary`: a supplementary code point or a surrogate (an escape such as `\uD800` makes one).
fn is_supplementary(c: u32) -> bool {
    c >= 0x10000 || (0xD800..=0xDFFF).contains(&c)
}

fn is_ascii(c: u32) -> bool {
    c < 128
}
fn ascii_alpha(c: u32) -> bool {
    (b'a' as u32..=b'z' as u32).contains(&c) || (b'A' as u32..=b'Z' as u32).contains(&c)
}
fn ascii_digit(c: u32) -> bool {
    (b'0' as u32..=b'9' as u32).contains(&c)
}
fn ascii_alnum(c: u32) -> bool {
    ascii_alpha(c) || ascii_digit(c)
}
fn ascii_hex(c: u32) -> bool {
    ascii_digit(c) || (b'a' as u32..=b'f' as u32).contains(&c) || (b'A' as u32..=b'F' as u32).contains(&c)
}
fn ascii_space(c: u32) -> bool {
    matches!(c, 0x20 | 0x09 | 0x0A | 0x0B | 0x0C | 0x0D)
}
fn hex_value(c: u32) -> u32 {
    char::from_u32(c).and_then(|c| c.to_digit(16)).unwrap_or(0)
}
fn ascii_lower(c: u32) -> u32 {
    if (b'A' as u32..=b'Z' as u32).contains(&c) { c + 0x20 } else { c }
}
fn ascii_upper(c: u32) -> u32 {
    if (b'a' as u32..=b'z' as u32).contains(&c) { c - 0x20 } else { c }
}

impl<'p> Parser<'p> {
    fn new(pattern: &'p str) -> Parser<'p> {
        // `compile()` copies the pattern as code points (a lone surrogate cannot occur in a Rust string).
        let mut temp: Vec<u32> = pattern.chars().map(u32::from).collect();
        let pattern_length = temp.len();
        temp.extend([0, 0]);
        let has_supplementary = temp.iter().any(|&c| is_supplementary(c));
        let mut p = Parser {
            pattern,
            temp,
            pattern_length,
            cursor: 0,
            flags: 0,
            capturing_group_count: 1,
            named: HashMap::new(),
            has_supplementary,
            dot: false,
        };
        p.remove_qe_quoting();
        p
    }

    /// The code point at `i`; Java's array is zero-terminated, and nothing reads far past it.
    fn t(&self, i: usize) -> u32 {
        self.temp.get(i).copied().unwrap_or(0)
    }

    fn remove_qe_quoting(&mut self) {
        let p_len = self.pattern_length;
        let mut i = 0;
        while i + 1 < p_len {
            if self.temp[i] != '\\' as u32 {
                i += 1;
            } else if self.temp[i + 1] != 'Q' as u32 {
                i += 2;
            } else {
                break;
            }
        }
        if i + 1 >= p_len {
            return;
        }
        let mut j = i;
        i += 2;
        let mut newtemp: Vec<u32> = self.temp[..j].to_vec();
        let mut in_quote = true;
        let mut begin_quote = true;
        while i < p_len {
            let c = self.temp[i];
            i += 1;
            if !is_ascii(c) || ascii_alpha(c) {
                newtemp.push(c);
            } else if ascii_digit(c) {
                if begin_quote {
                    newtemp.extend(['\\' as u32, 'x' as u32, '3' as u32]);
                }
                newtemp.push(c);
            } else if c != '\\' as u32 {
                if in_quote {
                    newtemp.push('\\' as u32);
                }
                newtemp.push(c);
            } else if in_quote {
                if self.t(i) == 'E' as u32 {
                    i += 1;
                    in_quote = false;
                } else {
                    newtemp.extend(['\\' as u32, '\\' as u32]);
                }
            } else if self.t(i) == 'Q' as u32 {
                i += 1;
                in_quote = true;
                begin_quote = true;
                continue;
            } else {
                newtemp.push(c);
                if i != p_len {
                    newtemp.push(self.temp[i]);
                    i += 1;
                }
            }
            begin_quote = false;
        }
        j = newtemp.len();
        self.pattern_length = j;
        newtemp.extend([0, 0]);
        self.temp = newtemp;
    }

    fn has(&self, f: u32) -> bool {
        self.flags & f != 0
    }

    fn error(&self, s: &str) -> PatternSyntaxException {
        PatternSyntaxException { description: s.to_string(), pattern: self.pattern.to_string(), index: self.cursor as i32 - 1 }
    }

    fn accept(&mut self, ch: u32, s: &str) -> Result<(), PatternSyntaxException> {
        let mut test = self.t(self.cursor);
        self.cursor += 1;
        if self.has(COMMENTS) {
            test = self.parse_past_whitespace(test);
        }
        if ch != test {
            return Err(self.error(s));
        }
        Ok(())
    }

    fn peek(&mut self) -> u32 {
        let ch = self.t(self.cursor);
        if self.has(COMMENTS) { self.peek_past_whitespace(ch) } else { ch }
    }

    fn read(&mut self) -> u32 {
        let ch = self.t(self.cursor);
        self.cursor += 1;
        if self.has(COMMENTS) { self.parse_past_whitespace(ch) } else { ch }
    }

    fn next(&mut self) -> u32 {
        self.cursor += 1;
        let ch = self.t(self.cursor);
        if self.has(COMMENTS) { self.peek_past_whitespace(ch) } else { ch }
    }

    fn next_escaped(&mut self) -> u32 {
        self.cursor += 1;
        self.t(self.cursor)
    }

    fn peek_past_whitespace(&mut self, mut ch: u32) -> u32 {
        while ascii_space(ch) || ch == '#' as u32 {
            while ascii_space(ch) {
                self.cursor += 1;
                ch = self.t(self.cursor);
            }
            if ch == '#' as u32 {
                ch = self.peek_past_line();
            }
        }
        ch
    }

    fn parse_past_whitespace(&mut self, mut ch: u32) -> u32 {
        while ascii_space(ch) || ch == '#' as u32 {
            while ascii_space(ch) {
                ch = self.t(self.cursor);
                self.cursor += 1;
            }
            if ch == '#' as u32 {
                ch = self.parse_past_line();
            }
        }
        ch
    }

    fn parse_past_line(&mut self) -> u32 {
        let mut ch = self.t(self.cursor);
        self.cursor += 1;
        while ch != 0 && !self.is_line_separator(ch) {
            ch = self.t(self.cursor);
            self.cursor += 1;
        }
        if ch == 0 && self.cursor > self.pattern_length {
            self.cursor = self.pattern_length;
            ch = self.t(self.cursor);
            self.cursor += 1;
        }
        ch
    }

    fn peek_past_line(&mut self) -> u32 {
        self.cursor += 1;
        let mut ch = self.t(self.cursor);
        while ch != 0 && !self.is_line_separator(ch) {
            self.cursor += 1;
            ch = self.t(self.cursor);
        }
        if ch == 0 && self.cursor > self.pattern_length {
            self.cursor = self.pattern_length;
            ch = self.t(self.cursor);
        }
        ch
    }

    fn is_line_separator(&self, ch: u32) -> bool {
        if self.has(UNIX_LINES) { ch == '\n' as u32 } else { ch == '\n' as u32 || ch == '\r' as u32 || (ch | 1) == 0x2029 || ch == 0x85 }
    }

    fn skip(&mut self) -> u32 {
        let i = self.cursor;
        let ch = self.t(i + 1);
        self.cursor = i + 2;
        ch
    }

    fn unread(&mut self) {
        self.cursor = self.cursor.wrapping_sub(1);
    }

    fn expr(&mut self) -> Result<Node, PatternSyntaxException> {
        let mut alternatives = Vec::new();
        loop {
            alternatives.push(self.sequence()?);
            if self.peek() != '|' as u32 {
                break;
            }
            self.next();
        }
        Ok(if alternatives.len() == 1 { alternatives.pop().unwrap_or(Node::Empty) } else { Node::Alt(alternatives) })
    }

    fn sequence(&mut self) -> Result<Node, PatternSyntaxException> {
        let mut nodes = Vec::new();
        loop {
            let ch = self.peek();
            let node = match char::from_u32(ch).unwrap_or('\u{0}') {
                '(' => {
                    if let Some(node) = self.group0()? {
                        nodes.push(node);
                    }
                    continue;
                }
                '[' => {
                    let class = self.clazz(true)?;
                    self.char_property(class)
                }
                '\\' => {
                    let ch = self.next_escaped();
                    if ch == 'p' as u32 || ch == 'P' as u32 {
                        let comp = ch == 'P' as u32;
                        let one_letter = if self.next() != '{' as u32 {
                            self.unread();
                            true
                        } else {
                            false
                        };
                        let family = self.family(one_letter, comp)?;
                        self.char_property(family)
                    } else {
                        self.unread();
                        self.atom()?
                    }
                }
                '^' => {
                    self.next();
                    if self.has(MULTILINE) { Node::Assert(Assertion::Caret { unix: self.has(UNIX_LINES) }) } else { Node::Assert(Assertion::Begin) }
                }
                '$' => {
                    self.next();
                    Node::Assert(Assertion::Dollar { multiline: self.has(MULTILINE), unix: self.has(UNIX_LINES) })
                }
                '.' => {
                    self.next();
                    self.dot = true;
                    Node::Char(if self.has(DOTALL) {
                        all()
                    } else if self.has(UNIX_LINES) {
                        negate(set(&[(0x0A, 0x0A)]))
                    } else {
                        negate(set(&[(0x0A, 0x0A), (0x0D, 0x0D), (0x85, 0x85), (0x2028, 0x2029)]))
                    })
                }
                '|' | ')' => break,
                ']' | '}' => self.atom()?,
                '?' | '*' | '+' => {
                    self.next();
                    return Err(self.error(&format!("Dangling meta character '{}'", char::from_u32(ch).unwrap_or('?'))));
                }
                '\u{0}' if self.cursor >= self.pattern_length => break,
                _ => self.atom()?,
            };
            nodes.push(self.closure(node, false)?);
        }
        Ok(match nodes.len() {
            0 => Node::Empty,
            1 => nodes.pop().unwrap_or(Node::Empty),
            _ => Node::Seq(nodes),
        })
    }

    /// A class or `\p`/`\P` read by `sequence()` or `atom()`: an `NFCCharProperty` under `CANON_EQ`, which an inline
    /// `(?c)` sets (`compile()`'s `normalize(pattern)` reads only the flags `compile` was given, and no caller gives
    /// `CANON_EQ`).
    fn char_property(&mut self, (set, bmp): (ClassUnicode, bool)) -> Node {
        if self.has(CANON_EQ) {
            Node::Nfc(set)
        } else {
            self.new_char_property(set, bmp)
        }
    }

    /// `newCharProperty`: a predicate that is no `BmpCharPredicate` sets `hasSupplementary`.
    fn new_char_property(&mut self, set: ClassUnicode, bmp: bool) -> Node {
        if !bmp {
            self.has_supplementary = true;
        }
        Node::Char(set)
    }

    fn atom(&mut self) -> Result<Node, PatternSyntaxException> {
        let mut buffer: Vec<u32> = Vec::new();
        let mut prev: usize = usize::MAX;
        let mut ch = self.peek();
        loop {
            match char::from_u32(ch).unwrap_or('\u{1}') {
                '*' | '+' | '?' | '{' => {
                    if buffer.len() > 1 {
                        self.cursor = prev;
                        buffer.pop();
                    }
                    break;
                }
                '$' | '.' | '^' | '(' | '[' | '|' | ')' => break,
                '\\' => {
                    ch = self.next_escaped();
                    if ch == 'p' as u32 || ch == 'P' as u32 {
                        if !buffer.is_empty() {
                            self.unread();
                            break;
                        }
                        let comp = ch == 'P' as u32;
                        let one_letter = if self.next() != '{' as u32 {
                            self.unread();
                            true
                        } else {
                            false
                        };
                        let (family, bmp) = self.family(one_letter, comp)?;
                        // `atom()` calls `newCharProperty` whatever the flags
                        if !bmp {
                            self.has_supplementary = true;
                        }
                        return Ok(if self.has(CANON_EQ) { Node::Nfc(family) } else { Node::Char(family) });
                    }
                    self.unread();
                    prev = self.cursor;
                    match self.escape(false, buffer.is_empty(), false)? {
                        Escape::Char(c) => {
                            buffer.push(c);
                            ch = self.peek();
                            continue;
                        }
                        Escape::Node(node) if buffer.is_empty() => return Ok(node),
                        Escape::Property(set, bmp) if buffer.is_empty() => return Ok(self.new_char_property(set, bmp)),
                        _ => {
                            self.cursor = prev;
                            break;
                        }
                    }
                }
                '\u{0}' if self.cursor >= self.pattern_length => break,
                _ => {
                    prev = self.cursor;
                    buffer.push(ch);
                    ch = self.next();
                    continue;
                }
            }
        }
        if buffer.len() == 1 {
            let bmp = self.single_bmp(buffer[0]);
            return Ok(self.new_char_property(self.single(buffer[0]), bmp));
        }
        // `newSlice`: `SliceI`/`SliceU` compare each character as `single` does.
        Ok(match buffer.len() {
            0 => Node::Empty,
            _ => Node::Seq(buffer.into_iter().map(|c| Node::Char(self.single(c))).collect()),
        })
    }

    fn reference(&mut self, mut ref_num: usize) -> Node {
        loop {
            let ch = self.peek();
            if !ascii_digit(ch) {
                break;
            }
            let new_ref = ref_num * 10 + (ch - '0' as u32) as usize;
            if self.capturing_group_count - 1 < new_ref {
                break;
            }
            ref_num = new_ref;
            self.read();
        }
        Node::BackRef { group: ref_num, ci: self.has(CASE_INSENSITIVE), unicode: self.has(UNICODE_CASE) }
    }

    fn escape(&mut self, inclass: bool, create: bool, isrange: bool) -> Result<Escape, PatternSyntaxException> {
        let ch = self.skip();
        let unicode = self.has(UNICODE_CHARACTER_CLASS);
        // `BmpCharPredicate`s: `HorizWS`, `VertWS` and the ASCII classes; negations and Unicode classes are not.
        let property = |p: ClassUnicode, bmp: bool| Ok(Escape::Property(p, bmp));
        match char::from_u32(ch).unwrap_or('\u{0}') {
            '0' => return self.o().map(Escape::Char),
            '1'..='9' if !inclass => {
                return Ok(if create { Escape::Node(self.reference((ch - '0' as u32) as usize)) } else { Escape::Meta });
            }
            'A' if !inclass => return Ok(Escape::Node(Node::Assert(Assertion::Begin))),
            'B' if !inclass => return Ok(Escape::Node(Node::Assert(Assertion::Bound { negated: true, unicode }))),
            'D' => return property(negate(if unicode { ucd("gc=Nd") } else { set(&[(0x30, 0x39)]) }), false),
            'G' if !inclass => return Ok(Escape::Node(Node::Assert(Assertion::LastMatch))),
            'H' => return property(negate(horiz_ws()), false),
            'N' => return self.n().map(Escape::Char),
            'R' if !inclass => return Ok(Escape::Node(Node::LineEnding)),
            'S' => return property(negate(if unicode { white_space() } else { ascii_space_set() }), false),
            'V' => return property(negate(vert_ws()), false),
            'W' => return property(negate(if unicode { word() } else { ascii_word() }), false),
            'X' if !inclass => return Ok(Escape::Node(Node::Grapheme)),
            'Z' if !inclass => return Ok(Escape::Node(Node::Assert(Assertion::Dollar { multiline: false, unix: self.has(UNIX_LINES) }))),
            'a' => return Ok(Escape::Char(0x07)),
            'b' if !inclass => {
                if create && self.peek() == '{' as u32 {
                    if self.skip() == 'g' as u32 {
                        if self.read() == '}' as u32 {
                            return Ok(Escape::Node(Node::Assert(Assertion::GraphemeBound)));
                        }
                        return Err(self.error("Illegal/unsupported escape sequence"));
                    }
                    self.unread();
                    self.unread();
                }
                return Ok(Escape::Node(Node::Assert(Assertion::Bound { negated: false, unicode })));
            }
            'c' => return self.c().map(Escape::Char),
            'd' => return property(if unicode { ucd("gc=Nd") } else { set(&[(0x30, 0x39)]) }, !unicode),
            'e' => return Ok(Escape::Char(0x1B)),
            'f' => return Ok(Escape::Char(0x0C)),
            'h' => return property(horiz_ws(), true),
            'k' if !inclass => {
                if self.read() != '<' as u32 {
                    return Err(self.error("\\k is not followed by '<' for named capturing group"));
                }
                let first = self.read();
                let name = self.groupname(first)?;
                let Some(&number) = self.named.get(&name) else {
                    return Err(self.error(&format!("named capturing group <{name}> does not exist")));
                };
                return Ok(Escape::Node(Node::BackRef { group: number, ci: self.has(CASE_INSENSITIVE), unicode: self.has(UNICODE_CASE) }));
            }
            'n' => return Ok(Escape::Char(0x0A)),
            'r' => return Ok(Escape::Char(0x0D)),
            's' => return property(if unicode { white_space() } else { ascii_space_set() }, !unicode),
            't' => return Ok(Escape::Char(0x09)),
            'u' => return self.u().map(Escape::Char),
            'v' => {
                if isrange {
                    return Ok(Escape::Char(0x0B));
                }
                return property(vert_ws(), true);
            }
            'w' => return property(if unicode { word() } else { ascii_word() }, !unicode),
            'x' => return self.x().map(Escape::Char),
            'z' if !inclass => return Ok(Escape::Node(Node::Assert(Assertion::End))),
            c if c.is_ascii_alphanumeric() => {}
            _ => return Ok(Escape::Char(ch)),
        }
        Err(self.error("Illegal/unsupported escape sequence"))
    }

    /// `clazz`: the class's set, and whether its predicate is a `BmpCharPredicate` (a union or intersection is one
    /// when both sides are; a negation never is).
    fn clazz(&mut self, consume: bool) -> Result<(ClassUnicode, bool), PatternSyntaxException> {
        let mut prev: Option<(ClassUnicode, bool)> = None;
        let mut curr: Option<(ClassUnicode, bool)> = None;
        let mut bits = ClassUnicode::empty();
        let mut is_neg = false;
        let mut has_bits = false;
        let mut ch = self.next();
        if ch == '^' as u32 && self.t(self.cursor - 1) == '[' as u32 {
            ch = self.next();
            is_neg = true;
        }
        loop {
            match char::from_u32(ch).unwrap_or('\u{1}') {
                '[' => {
                    let c = self.clazz(true)?;
                    prev = Some(match prev {
                        None => c.clone(),
                        Some((p, bmp)) => (union(p, &c.0), bmp && c.1),
                    });
                    curr = Some(c);
                    ch = self.peek();
                    continue;
                }
                '&' => {
                    ch = self.next();
                    if ch == '&' as u32 {
                        ch = self.next();
                        let mut right: Option<(ClassUnicode, bool)> = None;
                        while ch != ']' as u32 && ch != '&' as u32 {
                            let c = if ch == '[' as u32 {
                                self.clazz(true)?
                            } else {
                                self.unread();
                                self.clazz(false)?
                            };
                            right = Some(match right {
                                None => c,
                                Some((r, bmp)) => (union(r, &c.0), bmp && c.1),
                            });
                            ch = self.peek();
                        }
                        if has_bits {
                            match prev {
                                None => {
                                    prev = Some((bits.clone(), true));
                                    curr = Some((bits.clone(), true));
                                }
                                Some((p, bmp)) => prev = Some((union(p, &bits), bmp)),
                            }
                            has_bits = false;
                        }
                        if right.is_some() {
                            curr = right.clone();
                        }
                        match prev {
                            None => match right {
                                None => return Err(self.error("Bad class syntax")),
                                Some(r) => prev = Some(r),
                            },
                            Some((mut p, bmp)) => {
                                let Some(c) = &curr else { return Err(self.error("Bad intersection syntax")) };
                                p.intersect(&c.0);
                                prev = Some((p, bmp && c.1));
                            }
                        }
                        continue;
                    }
                    self.unread();
                }
                '\u{0}' if self.cursor >= self.pattern_length => return Err(self.error("Unclosed character class")),
                ']' if prev.is_some() || has_bits => {
                    if consume {
                        self.next();
                    }
                    let (mut result, bmp) = match prev {
                        None => (bits, true),
                        Some((p, bmp)) if has_bits => (union(p, &bits), bmp),
                        Some(p) => p,
                    };
                    if is_neg {
                        result.negate();
                    }
                    return Ok((result, bmp && !is_neg));
                }
                _ => {}
            }
            match self.range(&mut bits)? {
                None => has_bits = true,
                Some(c) => {
                    prev = Some(match prev {
                        None => c.clone(),
                        Some((p, bmp)) => (union(p, &c.0), bmp && c.1),
                    });
                    curr = Some(c);
                }
            }
            ch = self.peek();
        }
    }

    /// `bitsOrSingle`: Latin-1 characters go to the class's `BitClass` (`None`), others are a predicate.
    fn bits_or_single(&mut self, bits: &mut ClassUnicode, ch: u32) -> Option<(ClassUnicode, bool)> {
        let unicode_ci = self.has(CASE_INSENSITIVE) && self.has(UNICODE_CASE);
        if ch < 256 && !(unicode_ci && matches!(ch, 0xff | 0xb5 | 0x49 | 0x69 | 0x53 | 0x73 | 0x4b | 0x6b | 0xc5 | 0xe5 | 0xdf)) {
            let mut added = vec![ch];
            if self.has(CASE_INSENSITIVE) {
                if is_ascii(ch) {
                    added.extend([ascii_upper(ch), ascii_lower(ch)]);
                } else if self.has(UNICODE_CASE) {
                    added.extend([java_lower(ch), java_upper(ch)].into_iter().filter(|c| *c < 256));
                }
            }
            for c in added {
                bits.union(&set(&[(c, c)]));
            }
            return None;
        }
        Some((self.single(ch), self.single_bmp(ch)))
    }

    /// Whether `single(ch)` is a `BmpCharPredicate`: `Single` and `SingleI` are, `SingleU` and `SingleS` are not.
    fn single_bmp(&self, ch: u32) -> bool {
        if self.has(CASE_INSENSITIVE) && self.has(UNICODE_CASE) {
            let upper = java_upper(ch);
            if upper != java_lower(upper) || ch == 0xdf {
                return false;
            }
        }
        !is_supplementary(ch)
    }

    /// `single`: one character, with `SingleI`/`SingleU` case folding.
    fn single(&self, ch: u32) -> ClassUnicode {
        if self.has(CASE_INSENSITIVE) {
            if self.has(UNICODE_CASE) {
                let upper = java_upper(ch);
                let lower = java_lower(upper);
                // JDK 26: `ß` folds with `ẞ` although `toUpperCase('ß')` is still `ß`.
                if upper != lower || ch == 0xdf {
                    return fold_filtered(set(&[(ch, ch), (lower, lower)]), |c| c == lower || java_lower(java_upper(c)) == lower);
                }
            } else if is_ascii(ch) {
                let (lower, upper) = (ascii_lower(ch), ascii_upper(ch));
                if lower != upper {
                    return set(&[(lower, lower), (upper, upper)]);
                }
            }
        }
        set(&[(ch, ch)])
    }

    fn range(&mut self, bits: &mut ClassUnicode) -> Result<Option<(ClassUnicode, bool)>, PatternSyntaxException> {
        let mut ch = self.peek();
        if ch == '\\' as u32 {
            ch = self.next_escaped();
            if ch == 'p' as u32 || ch == 'P' as u32 {
                let comp = ch == 'P' as u32;
                let one_letter = if self.next() != '{' as u32 {
                    self.unread();
                    true
                } else {
                    false
                };
                return self.family(one_letter, comp).map(Some);
            }
            let isrange = self.t(self.cursor + 1) == '-' as u32;
            self.unread();
            match self.escape(true, true, isrange)? {
                Escape::Char(c) => ch = c,
                Escape::Property(p, bmp) => return Ok(Some((p, bmp))),
                _ => return Err(self.error("Unexpected internal error")),
            }
        } else {
            self.next();
        }
        if self.peek() == '-' as u32 {
            let end_range = self.t(self.cursor + 1);
            if end_range == '[' as u32 {
                return Ok(self.bits_or_single(bits, ch));
            }
            if end_range != ']' as u32 {
                self.next();
                let mut m = self.peek();
                if m == '\\' as u32 {
                    m = match self.escape(true, false, true)? {
                        Escape::Char(c) => c,
                        _ => return Err(self.error("Illegal character range")),
                    };
                } else {
                    self.next();
                }
                if m < ch {
                    return Err(self.error("Illegal character range"));
                }
                let range = set(&[(ch, m)]);
                if !self.has(CASE_INSENSITIVE) {
                    // `Range` is a `BmpCharPredicate` below the surrogates, or between them and the supplementary planes
                    return Ok(Some((range, m < 0xD800 || ch > 0xDFFF && m < 0x10000)));
                }
                // `CIRange` and `CIRangeU` are not
                let in_range = |c: u32| (ch..=m).contains(&c);
                return Ok(Some((if self.has(UNICODE_CASE) {
                    // `CIRangeU` with JDK 26's `CaseFolding.getClassRangeClosingCharacters`: the folds, outside the
                    // range, of the range's characters `toUpperCase`/`toLowerCase` do not reach.
                    let closing = class_range_closing_characters(ch, m);
                    let mut candidates = range.clone();
                    for c in &closing {
                        candidates.union(&set(&[(*c, *c)]));
                    }
                    case_fold_simple(&mut candidates);
                    candidates.difference(&range);
                    // A closing character is only a candidate; it matches through the predicate, as any other.
                    let mut out = range;
                    for r in candidates.ranges() {
                        for c in r.start() as u32..=r.end() as u32 {
                            let up = java_upper(c);
                            let lo = java_lower(up);
                            if in_range(c) || in_range(up) || in_range(lo) || closing.iter().any(|cp| *cp == up || *cp == lo) {
                                out.union(&set(&[(c, c)]));
                            }
                        }
                    }
                    out
                } else {
                    fold_filtered(range, |c| in_range(c) || is_ascii(c) && (in_range(ascii_upper(c)) || in_range(ascii_lower(c))))
                }, false)));
            }
        }
        Ok(self.bits_or_single(bits, ch))
    }

    /// `family`: the property's set, and whether its predicate is a `BmpCharPredicate` (only `forProperty`'s ASCII
    /// and POSIX ranges and ctypes are). A complement sets `hasSupplementary` here, inside a class too.
    fn family(&mut self, single_letter: bool, complement: bool) -> Result<(ClassUnicode, bool), PatternSyntaxException> {
        self.next();
        let name: String = if single_letter {
            let c = self.t(self.cursor);
            self.read();
            char::from_u32(c).map(String::from).unwrap_or_default()
        } else {
            let i = self.cursor;
            let saved = self.temp[self.pattern_length];
            self.temp[self.pattern_length] = '}' as u32;
            while self.read() != '}' as u32 {}
            self.temp[self.pattern_length] = saved;
            let j = self.cursor;
            if j > self.pattern_length {
                return Err(self.error("Unclosed character family"));
            }
            if i + 1 >= j {
                return Err(self.error("Empty character family"));
            }
            self.temp[i..j - 1].iter().filter_map(|c| char::from_u32(*c)).collect()
        };
        let ci = self.has(CASE_INSENSITIVE);
        let p = if let Some(eq) = name.find('=') {
            let value = &name[eq + 1..];
            let key = name[..eq].to_lowercase();
            let p = match key.as_str() {
                "sc" | "script" => unicode_script(value).map(|p| (p, false)),
                "blk" | "block" => unicode_block(value).map(|p| (p, false)),
                "gc" | "general_category" => for_property(value, ci).map(|p| (p, bmp_property(value))),
                _ => None,
            };
            match p {
                Some(p) => p,
                None => return Err(self.error(&format!("Unknown Unicode property {{name=<{key}>, value=<{value}>}}"))),
            }
        } else {
            let p = if let Some(block) = name.strip_prefix("In") {
                unicode_block(block).map(|p| (p, false))
            } else if let Some(short) = name.strip_prefix("Is") {
                for_unicode_property(short, ci)
                    .map(|p| (p, false))
                    .or_else(|| for_property(short, ci).map(|p| (p, bmp_property(short))))
                    .or_else(|| unicode_script(short).map(|p| (p, false)))
            } else {
                let posix = if self.has(UNICODE_CHARACTER_CLASS) { posix_property(&name.to_uppercase(), ci) } else { None };
                posix.map(|p| (p, false)).or_else(|| for_property(&name, ci).map(|p| (p, bmp_property(&name))))
            };
            match p {
                Some(p) => p,
                None => return Err(self.error(&format!("Unknown character property name {{{name}}}"))),
            }
        };
        if complement {
            // "it might be too expensive to detect if a complement of CharProperty can match "certain" supplementary"
            self.has_supplementary = true;
            return Ok((negate(p.0), false));
        }
        Ok(p)
    }

    fn groupname(&mut self, mut ch: u32) -> Result<String, PatternSyntaxException> {
        let mut name = String::new();
        if !ascii_alpha(ch) {
            return Err(self.error("capturing group name does not start with a Latin letter"));
        }
        loop {
            name.push(char::from_u32(ch).unwrap_or('?'));
            ch = self.read();
            if !ascii_alnum(ch) {
                break;
            }
        }
        if ch != '>' as u32 {
            return Err(self.error("named capturing group is missing trailing '>'"));
        }
        Ok(name)
    }

    /// `group0`; `None` for a flag-only group.
    fn group0(&mut self) -> Result<Option<Node>, PatternSyntaxException> {
        let save = self.flags;
        let mut ch = self.next();
        let mut capture = false;
        let node = if ch == '?' as u32 {
            ch = self.skip();
            match char::from_u32(ch).unwrap_or('\u{0}') {
                ':' => Node::Group { capture: false, name: None, node: Box::new(self.expr()?) },
                '=' | '!' => Node::Look { behind: false, negative: ch == '!' as u32, by_code_point: false, node: Box::new(self.expr()?) },
                '>' => Node::Atomic(Box::new(self.expr()?)),
                '<' => {
                    ch = self.read();
                    if ch != '=' as u32 && ch != '!' as u32 {
                        let name = self.groupname(ch)?;
                        if self.named.contains_key(&name) {
                            return Err(self.error(&format!("Named capturing group <{name}> is already defined")));
                        }
                        capture = true;
                        self.capturing_group_count += 1;
                        self.named.insert(name.clone(), self.capturing_group_count - 1);
                        Node::Group { capture: true, name: Some(name), node: Box::new(self.expr()?) }
                    } else {
                        let start = self.cursor;
                        let body = self.expr()?;
                        let mut info = TreeInfo::new();
                        study_chain(&[&body], &mut info);
                        if !info.max_valid {
                            return Err(self.error("Look-behind group does not have an obvious maximum length"));
                        }
                        // `findSupplementary(start, patternLength)`.
                        let by_code_point = self.temp[start..self.pattern_length].iter().any(|&c| c >= 0x10000 || (0xD800..=0xDFFF).contains(&c));
                        Node::Look { behind: true, negative: ch == '!' as u32, by_code_point, node: Box::new(body) }
                    }
                }
                '$' | '@' => return Err(self.error("Unknown group type")),
                _ => {
                    self.unread();
                    self.add_flag();
                    ch = self.read();
                    if ch == ')' as u32 {
                        return Ok(None);
                    }
                    if ch != ':' as u32 {
                        return Err(self.error("Unknown inline modifier"));
                    }
                    Node::Group { capture: false, name: None, node: Box::new(self.expr()?) }
                }
            }
        } else {
            capture = true;
            self.capturing_group_count += 1;
            Node::Group { capture: true, name: None, node: Box::new(self.expr()?) }
        };
        let _ = capture;
        self.accept(')' as u32, "Unclosed group")?;
        self.flags = save;
        self.closure(node, true).map(Some)
    }

    fn add_flag(&mut self) {
        let mut ch = self.peek();
        loop {
            match char::from_u32(ch).unwrap_or('\u{0}') {
                'i' => self.flags |= CASE_INSENSITIVE,
                'm' => self.flags |= MULTILINE,
                's' => self.flags |= DOTALL,
                'd' => self.flags |= UNIX_LINES,
                'u' => self.flags |= UNICODE_CASE,
                'c' => self.flags |= CANON_EQ,
                'x' => self.flags |= COMMENTS,
                'U' => self.flags |= UNICODE_CHARACTER_CLASS | UNICODE_CASE,
                '-' => {
                    self.next();
                    self.sub_flag();
                    return;
                }
                _ => return,
            }
            ch = self.next();
        }
    }

    fn sub_flag(&mut self) {
        let mut ch = self.peek();
        loop {
            match char::from_u32(ch).unwrap_or('\u{0}') {
                'i' => self.flags &= !CASE_INSENSITIVE,
                'm' => self.flags &= !MULTILINE,
                's' => self.flags &= !DOTALL,
                'd' => self.flags &= !UNIX_LINES,
                'u' => self.flags &= !UNICODE_CASE,
                'c' => self.flags &= !CANON_EQ,
                'x' => self.flags &= !COMMENTS,
                'U' => self.flags &= !(UNICODE_CHARACTER_CLASS | UNICODE_CASE),
                _ => return,
            }
            ch = self.next();
        }
    }

    fn qtype(&mut self) -> Qtype {
        let ch = self.next();
        if ch == '?' as u32 {
            self.next();
            Qtype::Lazy
        } else if ch == '+' as u32 {
            self.next();
            Qtype::Possessive
        } else {
            Qtype::Greedy
        }
    }

    fn closure(&mut self, prev: Node, group: bool) -> Result<Node, PatternSyntaxException> {
        let ch = self.peek();
        let boxed = |n| Box::new(n);
        match char::from_u32(ch).unwrap_or('\u{0}') {
            '?' => Ok(Node::Ques { node: boxed(prev), kind: self.qtype(), group }),
            '*' => Ok(Node::Repeat { node: boxed(prev), min: 0, max: MAX_REPS, kind: self.qtype(), group }),
            '+' => Ok(Node::Repeat { node: boxed(prev), min: 1, max: MAX_REPS, kind: self.qtype(), group }),
            '{' => {
                let mut ch = self.skip();
                if !ascii_digit(ch) {
                    return Err(self.error("Illegal repetition"));
                }
                let mut overflow = false;
                let mut cmin: i32 = 0;
                loop {
                    match cmin.checked_mul(10).and_then(|v| v.checked_add((ch - '0' as u32) as i32)) {
                        Some(v) => cmin = v,
                        None => overflow = true,
                    }
                    if overflow {
                        break;
                    }
                    ch = self.read();
                    if !ascii_digit(ch) {
                        break;
                    }
                }
                if overflow {
                    return Err(self.error("Illegal repetition range"));
                }
                let cmax: i32 = if ch == ',' as u32 {
                    ch = self.read();
                    if ch == '}' as u32 {
                        self.unread();
                        return Ok(Node::Repeat { node: boxed(prev), min: cmin, max: MAX_REPS, kind: self.qtype(), group });
                    }
                    let mut max: i32 = 0;
                    while ascii_digit(ch) {
                        match max.checked_mul(10).and_then(|v| v.checked_add((ch - '0' as u32) as i32)) {
                            Some(v) => max = v,
                            None => return Err(self.error("Illegal repetition range")),
                        }
                        ch = self.read();
                    }
                    max
                } else {
                    cmin
                };
                if ch != '}' as u32 {
                    return Err(self.error("Unclosed counted closure"));
                }
                if cmax < cmin {
                    return Err(self.error("Illegal repetition range"));
                }
                self.unread();
                let kind = self.qtype();
                Ok(if cmin == 0 && cmax == 1 {
                    Node::Ques { node: boxed(prev), kind, group }
                } else {
                    Node::Repeat { node: boxed(prev), min: cmin, max: cmax, kind, group }
                })
            }
            _ => Ok(prev),
        }
    }

    fn c(&mut self) -> Result<u32, PatternSyntaxException> {
        if self.cursor < self.pattern_length {
            return Ok(self.read() ^ 64);
        }
        Err(self.error("Illegal control escape sequence"))
    }

    fn o(&mut self) -> Result<u32, PatternSyntaxException> {
        let octal = |c: u32| ('0' as u32..='7' as u32).contains(&c);
        let n = self.read();
        if octal(n) {
            let m = self.read();
            if octal(m) {
                let o = self.read();
                if octal(o) && ('0' as u32..='3' as u32).contains(&n) {
                    return Ok((n - '0' as u32) * 64 + (m - '0' as u32) * 8 + (o - '0' as u32));
                }
                self.unread();
                return Ok((n - '0' as u32) * 8 + (m - '0' as u32));
            }
            self.unread();
            return Ok(n - '0' as u32);
        }
        Err(self.error("Illegal octal escape sequence"))
    }

    fn x(&mut self) -> Result<u32, PatternSyntaxException> {
        let mut n = self.read();
        if ascii_hex(n) {
            let m = self.read();
            if ascii_hex(m) {
                return Ok(hex_value(n) * 16 + hex_value(m));
            }
        } else if n == '{' as u32 && {
            let p = self.peek();
            ascii_hex(p)
        } {
            let mut ch: u32 = 0;
            loop {
                n = self.read();
                if !ascii_hex(n) {
                    break;
                }
                ch = (ch << 4) + hex_value(n);
                if ch > MAX_CODE_POINT {
                    return Err(self.error("Hexadecimal codepoint is too big"));
                }
            }
            if n != '}' as u32 {
                return Err(self.error("Unclosed hexadecimal escape sequence"));
            }
            return Ok(ch);
        }
        Err(self.error("Illegal hexadecimal escape sequence"))
    }

    fn uxxxx(&mut self) -> Result<u32, PatternSyntaxException> {
        let mut n = 0;
        for _ in 0..4 {
            let ch = self.read();
            if !ascii_hex(ch) {
                return Err(self.error("Illegal Unicode escape sequence"));
            }
            n = n * 16 + hex_value(ch);
        }
        Ok(n)
    }

    fn u(&mut self) -> Result<u32, PatternSyntaxException> {
        let n = self.uxxxx()?;
        if (0xD800..=0xDBFF).contains(&n) {
            let cur = self.cursor;
            if self.read() == '\\' as u32 && self.read() == 'u' as u32 {
                let n2 = self.uxxxx()?;
                if (0xDC00..=0xDFFF).contains(&n2) {
                    return Ok(0x10000 + ((n - 0xD800) << 10) + (n2 - 0xDC00));
                }
            }
            self.cursor = cur;
        }
        Ok(n)
    }

    fn n(&mut self) -> Result<u32, PatternSyntaxException> {
        if self.read() == '{' as u32 {
            let i = self.cursor;
            while self.read() != '}' as u32 {
                if self.cursor >= self.pattern_length {
                    return Err(self.error("Unclosed character name escape sequence"));
                }
            }
            let name: String = self.temp[i..self.cursor - 1].iter().filter_map(|c| char::from_u32(*c)).collect();
            return code_point_of(&name).ok_or_else(|| self.error(&format!("Unknown character name [{name}]")));
        }
        Err(self.error("Illegal character name escape sequence"))
    }
}

/// What `escape` produced: a character, a node (`root`), or a meta escape left for `atom` to re-read.
enum Escape {
    Char(u32),
    Node(Node),
    /// A predefined class (`\d`, `\W`, ...): its set and whether its predicate is a `BmpCharPredicate`.
    Property(ClassUnicode, bool),
    Meta,
}

// ---- character sets ----

fn set(ranges: &[(u32, u32)]) -> ClassUnicode {
    let base = STAND_IN.with(Cell::get);
    let mut class = ClassUnicode::empty();
    let mut stand_ins = ClassUnicode::empty();
    for &(lo, hi) in ranges {
        if let Some(base) = base {
            let (a, b) = (lo.max(0xD800), hi.min(0xDFFF));
            if let (true, Some(a), Some(b)) = (a <= b, char::from_u32(base + a - 0xD800), char::from_u32(base + b - 0xD800)) {
                stand_ins.push(ClassUnicodeRange::new(a, b));
            }
        }
        // Surrogates cannot occur in a Rust string; the ranges around them still can.
        let lo_c = char::from_u32(lo).or_else(|| (lo <= 0xDFFF).then_some('\u{E000}'));
        let hi_c = char::from_u32(hi.min(MAX_CODE_POINT)).or_else(|| (hi >= 0xD800).then_some('\u{D7FF}'));
        if let (Some(a), Some(b)) = (lo_c, hi_c) && a <= b {
            class.push(ClassUnicodeRange::new(a, b));
        }
    }
    if let Some(base) = base {
        let block = (char::from_u32(base), char::from_u32(base + SURROGATES - 1));
        if let (Some(a), Some(b)) = block {
            class.difference(&ClassUnicode::new([ClassUnicodeRange::new(a, b)]));
        }
        class.union(&stand_ins);
    }
    class
}

fn all() -> ClassUnicode {
    set(&[(0, MAX_CODE_POINT)])
}

fn negate(mut c: ClassUnicode) -> ClassUnicode {
    c.negate();
    c
}

fn union(mut a: ClassUnicode, b: &ClassUnicode) -> ClassUnicode {
    a.union(b);
    a
}

fn contains(c: &ClassUnicode, ch: u32) -> bool {
    c.ranges().iter().any(|r| (r.start() as u32..=r.end() as u32).contains(&ch))
}

/// A Unicode property as JDK 26 (Unicode 17.0.0) has it: a general category (`gc=Lu`; `gc=Cn` is every code point
/// no category lists) or a binary property (`Alphabetic`, …), from
/// [`tables`]; empty when it has none in a Rust string (`gc=Cs`).
fn ucd(property: &str) -> ClassUnicode {
    static CACHE: OnceLock<Mutex<HashMap<String, ClassUnicode>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let cached = STAND_IN.with(Cell::get).is_none();
    if let Some(hit) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(property).filter(|_| cached) {
        return hit.clone();
    }
    let lookup = |table: &[(&str, &[(u32, u32)])], name: &str| table.iter().find(|(n, _)| *n == name).map_or_else(ClassUnicode::empty, |(_, r)| set(r));
    let class = match property.split_once('=') {
        Some(("gc", "Cn")) => negate(tables::GENERAL_CATEGORIES.iter().fold(ClassUnicode::empty(), |acc, (_, r)| union(acc, &set(r)))),
        Some(("gc", gc)) => lookup(tables::GENERAL_CATEGORIES, gc),
        _ => lookup(tables::PROPERTIES, property),
    };
    if cached {
        cache.lock().unwrap_or_else(|e| e.into_inner()).insert(property.to_string(), class.clone());
    }
    class
}

/// Simple case folding over Unicode 17.0.0 ([`tables::SIMPLE_CASE_FOLDING`]): `class` with every character that
/// folds together with one of its characters (`ClassUnicode::case_fold_simple`, whose tables are Unicode 16's).
fn case_fold_simple(class: &mut ClassUnicode) {
    static ORBITS: OnceLock<Vec<Vec<u32>>> = OnceLock::new();
    let orbits = ORBITS.get_or_init(|| {
        let mut by_fold: std::collections::BTreeMap<u32, Vec<u32>> = std::collections::BTreeMap::new();
        for &(cp, fold) in tables::SIMPLE_CASE_FOLDING {
            by_fold.entry(fold).or_insert_with(|| vec![fold]).push(cp);
        }
        by_fold.into_values().collect()
    });
    let ranges = class.ranges().to_vec();
    let has = |c: u32| {
        let i = ranges.partition_point(|r| (r.end() as u32) < c);
        ranges.get(i).is_some_and(|r| r.start() as u32 <= c)
    };
    for orbit in orbits {
        if orbit.iter().any(|c| has(*c)) {
            class.union(&ClassUnicode::new(orbit.iter().filter_map(|c| char::from_u32(*c)).map(|c| ClassUnicodeRange::new(c, c))));
        }
    }
}

fn categories(names: &[&str]) -> ClassUnicode {
    names.iter().fold(ClassUnicode::empty(), |acc, n| union(acc, &ucd(&format!("gc={n}"))))
}

/// `Character.toUpperCase(int)`: UnicodeData 17.0.0's simple mapping ([`tables::SIMPLE_UPPERCASE`]), so a full
/// mapping to several characters (`ß`, the Greek iota-subscript letters' `ἈΙ`) never applies.
fn java_upper(c: u32) -> u32 {
    simple(tables::SIMPLE_UPPERCASE, c)
}
/// `Character.toLowerCase(int)`: as [`java_upper`] ([`tables::SIMPLE_LOWERCASE`]; `İ` lowers to `i`).
fn java_lower(c: u32) -> u32 {
    simple(tables::SIMPLE_LOWERCASE, c)
}
fn simple(table: &[(u32, u32)], c: u32) -> u32 {
    table.binary_search_by_key(&c, |&(from, _)| from).map_or(c, |i| table[i].1)
}

/// JDK 26's `CaseFolding` expanded map: CaseFolding.txt (Unicode 17) `C`, `T` and `S` entries whose fold is not
/// reached by `Character.toUpperCase`/`toLowerCase` of the folded character (filtered where it is read), and the
/// generator's own `ı` -> `I`.
const EXPANDED_CASE_MAP: &[(u32, u32)] = &[
    (0x0131, 0x0049), (0x00B5, 0x03BC), (0x0130, 0x0069), (0x017F, 0x0073), (0x01C5, 0x01C6), (0x01C8, 0x01C9),
    (0x01CB, 0x01CC), (0x01F2, 0x01F3), (0x0345, 0x03B9), (0x03C2, 0x03C3), (0x03D0, 0x03B2), (0x03D1, 0x03B8),
    (0x03D5, 0x03C6), (0x03D6, 0x03C0), (0x03F0, 0x03BA), (0x03F1, 0x03C1), (0x03F4, 0x03B8), (0x03F5, 0x03B5),
    (0x1C80, 0x0432), (0x1C81, 0x0434), (0x1C82, 0x043E), (0x1C83, 0x0441), (0x1C84, 0x0442), (0x1C85, 0x0442),
    (0x1C86, 0x044A), (0x1C87, 0x0463), (0x1C88, 0xA64B), (0x1C89, 0x1C8A), (0x1E9B, 0x1E61), (0x1E9E, 0x00DF),
    (0x1F88, 0x1F80), (0x1F89, 0x1F81), (0x1F8A, 0x1F82), (0x1F8B, 0x1F83), (0x1F8C, 0x1F84), (0x1F8D, 0x1F85),
    (0x1F8E, 0x1F86), (0x1F8F, 0x1F87), (0x1F98, 0x1F90), (0x1F99, 0x1F91), (0x1F9A, 0x1F92), (0x1F9B, 0x1F93),
    (0x1F9C, 0x1F94), (0x1F9D, 0x1F95), (0x1F9E, 0x1F96), (0x1F9F, 0x1F97), (0x1FA8, 0x1FA0), (0x1FA9, 0x1FA1),
    (0x1FAA, 0x1FA2), (0x1FAB, 0x1FA3), (0x1FAC, 0x1FA4), (0x1FAD, 0x1FA5), (0x1FAE, 0x1FA6), (0x1FAF, 0x1FA7),
    (0x1FBC, 0x1FB3), (0x1FBE, 0x03B9), (0x1FCC, 0x1FC3), (0x1FD3, 0x0390), (0x1FE3, 0x03B0), (0x1FFC, 0x1FF3),
    (0x2126, 0x03C9), (0x212A, 0x006B), (0x212B, 0x00E5), (0xA7CB, 0x0264), (0xA7CC, 0xA7CD), (0xA7CE, 0xA7CF),
    (0xA7D2, 0xA7D3), (0xA7D4, 0xA7D5), (0xA7DA, 0xA7DB), (0xA7DC, 0x019B), (0xFB05, 0xFB06),
];

/// `CaseFolding.getClassRangeClosingCharacters(start, end)`: the folds of the expanded map's characters in the range
/// that fall outside it.
fn class_range_closing_characters(start: u32, end: u32) -> Vec<u32> {
    EXPANDED_CASE_MAP
        .iter()
        .chain(EXPANDED_SUPPLEMENTARY.iter())
        .filter(|(cp, fold)| *cp == 0x0131 || (java_upper(*fold) != *cp && java_lower(*fold) != *cp))
        .filter(|(cp, fold)| (start..=end).contains(cp) && !(start..=end).contains(fold))
        .map(|(_, fold)| *fold)
        .collect()
}

/// The supplementary entries of [`EXPANDED_CASE_MAP`]: Garay (`10D50..10D65` -> `+0x20`) and Kirat Rai
/// (`16EA0..16EB8` -> `+0x1B`).
static EXPANDED_SUPPLEMENTARY: std::sync::LazyLock<Vec<(u32, u32)>> =
    std::sync::LazyLock::new(|| (0x10D50..=0x10D65).map(|c| (c, c + 0x20)).chain((0x16EA0..=0x16EB8).map(|c| (c, c + 0x1B))).collect());

/// `set` with the characters simple case folding adds kept only where `keep` (the folding `Pattern` applies) says.
fn fold_filtered(base: ClassUnicode, keep: impl Fn(u32) -> bool) -> ClassUnicode {
    let mut folded = base.clone();
    case_fold_simple(&mut folded);
    let mut extra = folded;
    extra.difference(&base);
    let mut result = base;
    for r in extra.ranges() {
        for c in r.start() as u32..=r.end() as u32 {
            if keep(c) {
                result.union(&set(&[(c, c)]));
            }
        }
    }
    result
}

fn horiz_ws() -> ClassUnicode {
    set(&[(0x09, 0x09), (0x20, 0x20), (0xa0, 0xa0), (0x1680, 0x1680), (0x180e, 0x180e), (0x2000, 0x200a), (0x202f, 0x202f), (0x205f, 0x205f), (0x3000, 0x3000)])
}
fn vert_ws() -> ClassUnicode {
    set(&[(0x0A, 0x0D), (0x85, 0x85), (0x2028, 0x2029)])
}
fn ascii_space_set() -> ClassUnicode {
    set(&[(0x09, 0x0D), (0x20, 0x20)])
}
fn ascii_word() -> ClassUnicode {
    set(&[(0x30, 0x39), (0x41, 0x5A), (0x5F, 0x5F), (0x61, 0x7A)])
}
/// `CharPredicates.WHITE_SPACE`.
fn white_space() -> ClassUnicode {
    union(categories(&["Zs", "Zl", "Zp"]), &set(&[(0x09, 0x0D), (0x85, 0x85)]))
}
/// `CharPredicates.WORD`.
fn word() -> ClassUnicode {
    union(union(ucd("Alphabetic"), &categories(&["Mn", "Me", "Mc", "Nd", "Pc"])), &set(&[(0x200C, 0x200D)]))
}
fn letter() -> ClassUnicode {
    categories(&["Lu", "Ll", "Lt", "Lm", "Lo"])
}
fn identifier_ignorable() -> ClassUnicode {
    union(set(&[(0x00, 0x08), (0x0E, 0x1B), (0x7F, 0x9F)]), &categories(&["Cf"]))
}
fn hex_digit() -> ClassUnicode {
    union(ucd("gc=Nd"), &set(&[(0x30, 0x39), (0x41, 0x46), (0x61, 0x66), (0xFF10, 0xFF19), (0xFF21, 0xFF26), (0xFF41, 0xFF46)]))
}
fn cased_any() -> ClassUnicode {
    union(union(ucd("Lowercase"), &ucd("Uppercase")), &ucd("gc=Lt"))
}
/// `CharPredicates.GRAPH`: not a separator, control, surrogate or unassigned.
fn graph() -> ClassUnicode {
    negate(categories(&["Zs", "Zl", "Zp", "Cc", "Cs", "Cn"]))
}

/// `CharPredicates.getPosixPredicate` (`UNICODE_CHARACTER_CLASS`), by upper-case name.
fn posix_property(name: &str, ci: bool) -> Option<ClassUnicode> {
    Some(match name {
        "ALPHA" => ucd("Alphabetic"),
        "LOWER" => if ci { cased_any() } else { ucd("Lowercase") },
        "UPPER" => if ci { cased_any() } else { ucd("Uppercase") },
        "SPACE" => white_space(),
        "PUNCT" => categories(&["Pc", "Pd", "Ps", "Pe", "Po", "Pi", "Pf"]),
        "XDIGIT" => hex_digit(),
        "ALNUM" => union(ucd("Alphabetic"), &ucd("gc=Nd")),
        "CNTRL" => categories(&["Cc"]),
        "DIGIT" => ucd("gc=Nd"),
        "BLANK" => union(categories(&["Zs"]), &set(&[(0x09, 0x09)])),
        "GRAPH" => graph(),
        "PRINT" => {
            let mut print = union(graph(), &union(categories(&["Zs"]), &set(&[(0x09, 0x09)])));
            print.difference(&categories(&["Cc"]));
            print
        }
        _ => return None,
    })
}

/// `CharPredicates.forUnicodeProperty`.
fn for_unicode_property(name: &str, ci: bool) -> Option<ClassUnicode> {
    let upper = name.to_uppercase();
    Some(match upper.as_str() {
        "ALPHABETIC" => ucd("Alphabetic"),
        "ASSIGNED" => negate(categories(&["Cn"])),
        "CONTROL" => categories(&["Cc"]),
        "EMOJI" => ucd("Emoji"),
        "EMOJI_PRESENTATION" => ucd("Emoji_Presentation"),
        "EMOJI_MODIFIER" => ucd("Emoji_Modifier"),
        "EMOJI_MODIFIER_BASE" => ucd("Emoji_Modifier_Base"),
        "EMOJI_COMPONENT" => ucd("Emoji_Component"),
        "EXTENDED_PICTOGRAPHIC" => ucd("Extended_Pictographic"),
        "HEXDIGIT" | "HEX_DIGIT" => hex_digit(),
        "IDEOGRAPHIC" => ucd("Ideographic"),
        "JOINCONTROL" | "JOIN_CONTROL" => set(&[(0x200C, 0x200D)]),
        "LETTER" => letter(),
        "LOWERCASE" => if ci { cased_any() } else { ucd("Lowercase") },
        "NONCHARACTERCODEPOINT" | "NONCHARACTER_CODE_POINT" => ucd("Noncharacter_Code_Point"),
        "TITLECASE" => if ci { cased_any() } else { ucd("gc=Lt") },
        "PUNCTUATION" => categories(&["Pc", "Pd", "Ps", "Pe", "Po", "Pi", "Pf"]),
        "UPPERCASE" => if ci { cased_any() } else { ucd("Uppercase") },
        "WHITESPACE" | "WHITE_SPACE" => white_space(),
        "WORD" => word(),
        _ => return posix_property(&upper, ci),
    })
}

/// `CharPredicates.forProperty`: general categories, POSIX classes over ASCII and the `java*` methods.
/// Whether `CharPredicates.forProperty(name)` is a `BmpCharPredicate`: its `range` and `ctype` entries.
fn bmp_property(name: &str) -> bool {
    matches!(name, "L1" | "ASCII" | "Alnum" | "Alpha" | "Blank" | "Cntrl" | "Digit" | "Graph" | "Lower" | "Print" | "Punct" | "Space" | "Upper" | "XDigit")
}

fn for_property(name: &str, ci: bool) -> Option<ClassUnicode> {
    let cased = || categories(&["Lu", "Ll", "Lt"]);
    let ascii = |ranges: &[(u32, u32)]| set(ranges);
    Some(match name {
        "Cn" | "Lm" | "Lo" | "Mn" | "Me" | "Mc" | "Nd" | "Nl" | "No" | "Zs" | "Zl" | "Zp" | "Cc" | "Cf" | "Co" | "Cs" | "Pd" | "Ps"
        | "Pe" | "Pc" | "Po" | "Sm" | "Sc" | "Sk" | "So" | "Pi" | "Pf" => categories(&[name]),
        "Lu" | "Ll" | "Lt" => if ci { cased() } else { categories(&[name]) },
        "L" => letter(),
        "M" => categories(&["Mn", "Me", "Mc"]),
        "N" => categories(&["Nd", "Nl", "No"]),
        "Z" => categories(&["Zs", "Zl", "Zp"]),
        "C" => categories(&["Cc", "Cf", "Co", "Cs", "Cn"]),
        "P" => categories(&["Pd", "Ps", "Pe", "Pc", "Po", "Pi", "Pf"]),
        "S" => categories(&["Sm", "Sc", "Sk", "So"]),
        "LC" => cased(),
        "LD" => union(letter(), &categories(&["Nd"])),
        "L1" => ascii(&[(0x00, 0xFF)]),
        "all" => all(),
        "ASCII" => ascii(&[(0x00, 0x7F)]),
        "Alnum" => ascii(&[(0x30, 0x39), (0x41, 0x5A), (0x61, 0x7A)]),
        "Alpha" => ascii(&[(0x41, 0x5A), (0x61, 0x7A)]),
        "Blank" => ascii(&[(0x09, 0x09), (0x20, 0x20)]),
        "Cntrl" => ascii(&[(0x00, 0x1F), (0x7F, 0x7F)]),
        "Digit" => ascii(&[(0x30, 0x39)]),
        "Graph" => ascii(&[(0x21, 0x7E)]),
        "Lower" => if ci { ascii(&[(0x41, 0x5A), (0x61, 0x7A)]) } else { ascii(&[(0x61, 0x7A)]) },
        "Print" => ascii(&[(0x20, 0x7E)]),
        "Punct" => ascii(&[(0x21, 0x2F), (0x3A, 0x40), (0x5B, 0x60), (0x7B, 0x7E)]),
        "Space" => ascii_space_set(),
        "Upper" => if ci { ascii(&[(0x41, 0x5A), (0x61, 0x7A)]) } else { ascii(&[(0x41, 0x5A)]) },
        "XDigit" => ascii(&[(0x30, 0x39), (0x41, 0x46), (0x61, 0x66)]),
        "javaLowerCase" => if ci { cased_any() } else { ucd("Lowercase") },
        "javaUpperCase" => if ci { cased_any() } else { ucd("Uppercase") },
        "javaAlphabetic" => ucd("Alphabetic"),
        "javaIdeographic" => ucd("Ideographic"),
        "javaTitleCase" => if ci { cased_any() } else { ucd("gc=Lt") },
        "javaDigit" => ucd("gc=Nd"),
        "javaDefined" => negate(categories(&["Cn"])),
        "javaLetter" => letter(),
        "javaLetterOrDigit" => union(letter(), &ucd("gc=Nd")),
        "javaJavaIdentifierStart" => union(letter(), &categories(&["Nl", "Sc", "Pc"])),
        "javaJavaIdentifierPart" => union(union(letter(), &categories(&["Sc", "Pc", "Nd", "Nl", "Mc", "Mn"])), &identifier_ignorable()),
        "javaUnicodeIdentifierStart" => union(union(letter(), &categories(&["Nl"])), &ucd("Other_ID_Start")),
        "javaUnicodeIdentifierPart" => union(
            union(union(letter(), &categories(&["Pc", "Nd", "Nl", "Mc", "Mn"])), &identifier_ignorable()),
            &union(ucd("Other_ID_Start"), &ucd("Other_ID_Continue")),
        ),
        "javaIdentifierIgnorable" => identifier_ignorable(),
        "javaSpaceChar" => categories(&["Zs", "Zl", "Zp"]),
        "javaWhitespace" => {
            let mut ws = categories(&["Zs", "Zl", "Zp"]);
            ws.difference(&set(&[(0xA0, 0xA0), (0x2007, 0x2007), (0x202F, 0x202F)]));
            union(ws, &set(&[(0x09, 0x0D), (0x1C, 0x1F)]))
        }
        "javaISOControl" => ascii(&[(0x00, 0x1F), (0x7F, 0x9F)]),
        "javaMirrored" => ucd("Bidi_Mirrored"),
        _ => return None,
    })
}

/// `Character.UnicodeScript.forName` (aliases, then `valueOf` of the upper-cased name), as JDK 26's ranges.
fn unicode_script(name: &str) -> Option<ClassUnicode> {
    let upper = name.to_uppercase();
    let script = tables::SCRIPT_ALIASES.iter().find(|(a, _)| *a == upper).map(|(_, s)| *s).or_else(|| tables::SCRIPTS.iter().copied().find(|s| *s == upper))?;
    Some(from_starts(tables::SCRIPT_STARTS.iter().map(|(start, s)| (*start, *s == script))))
}

/// `Character.UnicodeBlock.forName` (upper-cased identifiers and aliases), as JDK 26's ranges.
fn unicode_block(name: &str) -> Option<ClassUnicode> {
    let upper = name.to_uppercase();
    let block = tables::BLOCK_NAMES.iter().find(|(n, _)| *n == upper).map(|(_, b)| *b)?;
    Some(from_starts(tables::BLOCK_STARTS.iter().map(|(start, b)| (*start, *b == Some(block)))))
}

fn from_starts(starts: impl Iterator<Item = (u32, bool)>) -> ClassUnicode {
    let starts: Vec<(u32, bool)> = starts.collect();
    let mut ranges = Vec::new();
    for (i, (start, wanted)) in starts.iter().enumerate() {
        if *wanted {
            let end = starts.get(i + 1).map_or(MAX_CODE_POINT, |(next, _)| next - 1);
            ranges.push((*start, end));
        }
    }
    set(&ranges)
}

/// `Character.codePointOf`: a `UnicodeData` name (controls by their Unicode 1.0 name), or an unnamed assigned code
/// point's block name and hex value (`CJK UNIFIED IDEOGRAPHS 4E00`), ignoring case and surrounding blanks.
fn code_point_of(name: &str) -> Option<u32> {
    static NAMES: OnceLock<HashMap<String, u32>> = OnceLock::new();
    let names = NAMES.get_or_init(|| {
        use std::io::Read;
        let mut text = String::new();
        let _ = flate2::read::GzDecoder::new(&include_bytes!("names.txt.gz")[..]).read_to_string(&mut text);
        text.lines().filter_map(|l| l.split_once(';')).filter_map(|(cp, n)| Some((n.to_string(), u32::from_str_radix(cp, 16).ok()?))).collect()
    });
    let name = name.trim_matches(|c: char| c <= ' ').to_uppercase();
    if let Some(cp) = names.get(&name) {
        return Some(*cp);
    }
    let (block, hex) = name.rsplit_once(' ')?;
    let cp = u32::from_str_radix(hex, 16).ok().filter(|cp| *cp <= MAX_CODE_POINT)?;
    let assigned = (0xD800..=0xDFFF).contains(&cp) || !contains(&categories(&["Cn"]), cp);
    if names.values().any(|v| *v == cp) || !assigned {
        return None;
    }
    let id = tables::BLOCK_STARTS.iter().rev().find(|(start, _)| *start <= cp).and_then(|(_, b)| *b)?;
    (id.replace('_', " ") == block && format!("{cp:X}") == hex).then_some(cp)
}

// ---- TreeInfo ----

struct TreeInfo {
    min: i32,
    max: i32,
    max_valid: bool,
    deterministic: bool,
}

impl TreeInfo {
    fn new() -> TreeInfo {
        TreeInfo { min: 0, max: 0, max_valid: true, deterministic: true }
    }
    fn reset(&mut self) {
        *self = TreeInfo::new();
    }
}

/// The nodes `next` reaches from `node` in `Pattern`'s graph: sequences and plain groups are transparent.
fn flatten<'a>(node: &'a Node, out: &mut Vec<&'a Node>) {
    match node {
        Node::Seq(nodes) => nodes.iter().for_each(|n| flatten(n, out)),
        Node::Group { node, .. } => flatten(node, out),
        Node::Empty => {}
        other => out.push(other),
    }
}

/// `study` over a chain of nodes (each one's `next` is the one after it).
fn study_chain(chain: &[&Node], info: &mut TreeInfo) -> bool {
    let mut flat = Vec::new();
    chain.iter().for_each(|n| flatten(n, &mut flat));
    study_flat(&flat, info)
}

fn study_flat(flat: &[&Node], info: &mut TreeInfo) -> bool {
    let Some((node, rest)) = flat.split_first() else { return info.deterministic };
    match node {
        Node::Char(_) => {
            info.min = info.min.wrapping_add(1);
            info.max = info.max.wrapping_add(1);
        }
        Node::LineEnding => {
            info.min = info.min.wrapping_add(1);
            info.max = info.max.wrapping_add(2);
        }
        // `XGrapheme.study` and `NFCCharProperty.study`: the most they take is not counted.
        Node::Grapheme | Node::Nfc(_) => {
            info.min = info.min.wrapping_add(1);
            info.deterministic = false;
        }
        Node::BackRef { .. } => info.max_valid = false,
        Node::Assert(_) | Node::Look { .. } | Node::Empty | Node::Seq(_) | Node::Group { .. } => {}
        Node::Atomic(atom) => {
            study_chain(&[atom], info);
        }
        Node::Alt(alternatives) => {
            branch(alternatives.iter().collect(), rest, info);
            return false;
        }
        Node::Ques { node: atom, kind, group } => {
            if *group && *kind != Qtype::Possessive && !self_terminal(atom) {
                branch(vec![atom, &Node::Empty], rest, info);
                return false;
            }
            let min = info.min;
            study_chain(&[atom], info);
            info.min = min;
            info.deterministic = false;
        }
        Node::Repeat { node: atom, min, max, kind, group } => {
            if !*group && *kind == Qtype::Greedy && *max == MAX_REPS && matches!(**atom, Node::Char(_)) {
                // `CharPropertyGreedy`.
                info.min = info.min.wrapping_add(*min);
                if info.max_valid {
                    info.max = info.max.wrapping_add(MAX_REPS);
                }
                info.deterministic = false;
            } else if *group && *kind != Qtype::Possessive && !self_terminal(atom) && !{
                let mut inner = TreeInfo::new();
                study_chain(&[atom], &mut inner)
            } {
                // A `Loop`: nothing after it is studied.
                info.max_valid = false;
                info.deterministic = false;
                return false;
            } else {
                curly(atom, *min, *max, info);
            }
        }
    }
    study_flat(rest, info)
}

/// A repetition `engine::convert` makes a `GroupCurly` of, whose group holds a capturing group: `GroupCurly` leaves
/// the inner groups as the iteration it backs off (or a failed one) set them, also for a later back reference and a
/// later start of the same search, where a translation restores them; such a pattern is walked.
fn group_curly_with_inner_groups(node: &Node) -> bool {
    match node {
        Node::Repeat { node: atom, kind, group: true, .. } if *kind != Qtype::Possessive => match &**atom {
            Node::Group { node: body, .. } => {
                body.any(&|n| matches!(n, Node::Group { capture: true, .. })) && study_chain(&[&**atom], &mut TreeInfo::new())
            }
            _ => false,
        },
        _ => false,
    }
}

/// A look-around (`Pos`, `Neg`, `Behind`, `NotBehind`), an independent group (`Ques(INDEPENDENT)`) or a possessive
/// quantifier whose operand holds a capturing group: the operand ends at `Pattern.accept`, so the groups it set stay
/// set when the node after it fails (or a negative look-around's body matched), also for a later alternative and a
/// later start of the same search, where a translation restores them; such a pattern is walked.
fn accepting_with_inner_groups(node: &Node) -> bool {
    let body = match node {
        Node::Look { node, .. } | Node::Atomic(node) => node,
        Node::Ques { node, kind: Qtype::Possessive, .. } | Node::Repeat { node, kind: Qtype::Possessive, .. } => node,
        _ => return false,
    };
    body.any(&|n| matches!(n, Node::Group { capture: true, .. }))
}

/// A group `group0` returns as one node (`head == tail`): a look-around or an independent group, which a quantifier
/// wraps as a plain `Ques`/`Curly`.
fn self_terminal(atom: &Node) -> bool {
    matches!(atom, Node::Look { .. } | Node::Atomic(_))
}

/// `Curly.study` / `GroupCurly.study`.
fn curly(atom: &Node, cmin: i32, cmax: i32, info: &mut TreeInfo) {
    let (min_l, max_l, max_v, detm) = (info.min, info.max, info.max_valid, info.deterministic);
    info.reset();
    study_chain(&[atom], info);
    let mut temp = info.min.wrapping_mul(cmin).wrapping_add(min_l);
    if temp < min_l {
        temp = 0xFFFFFFF;
    }
    info.min = temp;
    if max_v & info.max_valid {
        temp = info.max.wrapping_mul(cmax).wrapping_add(max_l);
        info.max = temp;
        if temp < max_l {
            info.max_valid = false;
        }
    } else {
        info.max_valid = false;
    }
    info.deterministic = if info.deterministic && cmin == cmax { detm } else { false };
}

/// `Branch.study`: each alternative from scratch, then what follows the branch, then the sum.
fn branch(alternatives: Vec<&Node>, rest: &[&Node], info: &mut TreeInfo) {
    let (mut min_l, mut max_l, mut max_v) = (info.min, info.max, info.max_valid);
    let (mut min2, mut max2) = (i32::MAX, -1);
    for atom in alternatives {
        info.reset();
        study_chain(&[atom], info);
        min2 = min2.min(info.min);
        max2 = max2.max(info.max);
        max_v &= info.max_valid;
    }
    min_l = min_l.wrapping_add(min2);
    max_l = max_l.wrapping_add(max2);
    info.reset();
    study_flat(rest, info);
    info.min = info.min.wrapping_add(min_l);
    info.max = info.max.wrapping_add(max_l);
    info.max_valid &= max_v;
    info.deterministic = false;
}

// ---- emission ----

fn class_text(c: &ClassUnicode, out: &mut String) {
    use std::fmt::Write;
    match c.ranges() {
        [] => out.push_str(r"[^\x{0}-\x{10FFFF}]"),
        [r] if r.start() == r.end() => out.push_str(&fancy_regex::escape(r.start().encode_utf8(&mut [0; 4]))),
        ranges => {
            out.push('[');
            for r in ranges {
                if r.start() == r.end() {
                    let _ = write!(out, r"\x{{{:X}}}", r.start() as u32);
                } else {
                    let _ = write!(out, r"\x{{{:X}}}-\x{{{:X}}}", r.start() as u32, r.end() as u32);
                }
            }
            out.push(']');
        }
    }
}

fn assertion_text(a: Assertion) -> String {
    match a {
        Assertion::Begin => r"\A".into(),
        // `fancy_regex`'s `\G` holds at the search start; [`JavaRegex::find_iter`] starts each search as `find()` does.
        Assertion::LastMatch => r"\G".into(),
        Assertion::End => r"\z".into(),
        Assertion::Dollar { multiline: false, unix: true } => r"(?=\n?\z)".into(),
        Assertion::Dollar { multiline: true, unix: true } => r"(?=\n|\z)".into(),
        Assertion::Dollar { multiline: false, unix: false } => {
            r"(?:\z|(?=\r\n\z)|(?=[\r\x{85}\x{2028}\x{2029}]\z)|(?<!\r)(?=\n\z))".into()
        }
        Assertion::Dollar { multiline: true, unix: false } => r"(?:\z|(?=[\r\x{85}\x{2028}\x{2029}])|(?<!\r)(?=\n))".into(),
        Assertion::Caret { unix: true } => r"(?!\z)(?:\A|(?<=\n))".into(),
        Assertion::Caret { unix: false } => r"(?!\z)(?:\A|(?<=[\n\x{85}\x{2028}\x{2029}])|(?<=\r)(?!\n))".into(),
        Assertion::Bound { negated, unicode } => {
            // `Bound.check`: a word character, or a non-spacing mark that follows a letter or digit through marks.
            let mut w = String::new();
            class_text(&if unicode { word() } else { ascii_word() }, &mut w);
            let mut base = String::new();
            class_text(&union(letter(), &ucd("gc=Nd")), &mut base);
            let mut mn = String::new();
            class_text(&categories(&["Mn"]), &mut mn);
            let left = format!(r"(?:(?<={w})|(?<={base}{mn}+))");
            let right = format!(r"(?:(?={w})|(?={mn})(?<={base}{mn}*))");
            if negated {
                format!("(?:{left}{right}|(?!{left})(?!{right}))")
            } else {
                format!("(?:{left}(?!{right})|(?!{left}){right})")
            }
        }
        // Matched only by the walk (`engine.rs`); never compiled.
        Assertion::GraphemeBound => r"\b{g}".into(),
    }
}

fn emit(node: &Node, groups: usize, out: &mut String) {
    match node {
        Node::Empty => {}
        Node::Char(c) => class_text(c, out),
        Node::Seq(nodes) => nodes.iter().for_each(|n| emit(n, groups, out)),
        Node::Alt(alternatives) => {
            out.push_str("(?:");
            for (i, a) in alternatives.iter().enumerate() {
                if i > 0 {
                    out.push('|');
                }
                emit(a, groups, out);
            }
            out.push(')');
        }
        Node::Group { capture, name, node } => {
            match name {
                Some(name) => out.push_str(&format!("(?P<{name}>")),
                None => out.push_str(if *capture { "(" } else { "(?:" }),
            }
            emit(node, groups, out);
            out.push(')');
        }
        Node::Look { behind, negative, node, .. } => {
            out.push_str(match (behind, negative) {
                (false, false) => "(?=",
                (false, true) => "(?!",
                (true, false) => "(?<=",
                (true, true) => "(?<!",
            });
            emit(node, groups, out);
            out.push(')');
        }
        Node::Atomic(node) => {
            out.push_str("(?>");
            emit(node, groups, out);
            out.push(')');
        }
        Node::Ques { node, kind, .. } => quantified(node, 0, 1, *kind, groups, out),
        Node::Repeat { node, min, max, kind, .. } => quantified(node, *min, *max, *kind, groups, out),
        Node::Assert(a) => out.push_str(&assertion_text(*a)),
        Node::BackRef { group, ci, .. } => {
            if *group == 0 || *group > groups {
                // A group the pattern does not have is never set.
                out.push_str("(?!)");
            } else if *ci {
                out.push_str(&format!(r"(?i:\{group})"));
            } else {
                out.push_str(&format!(r"(?:\{group})"));
            }
        }
        Node::LineEnding => out.push_str(r"(?:\r\n|[\n\x0B\x0C\r\x{85}\x{2028}\x{2029}])"),
        // Matched only by the walk (`engine.rs`); never compiled.
        Node::Grapheme => out.push_str(r"\X"),
        // Matched only by the walk (`engine.rs`); the text shows the set.
        Node::Nfc(c) => class_text(c, out),
    }
}

fn quantified(node: &Node, min: i32, max: i32, kind: Qtype, groups: usize, out: &mut String) {
    if node.zero_width() || matches!(node, Node::BackRef { group, .. } if *group == 0 || *group > groups) {
        // A zero-width operand matches once whatever the count; `fancy_regex` refuses to repeat one.
        if min > 0 {
            emit(node, groups, out);
        }
        return;
    }
    let mut operand = String::new();
    emit(node, groups, &mut operand);
    let atomic = matches!(node, Node::Char(_) | Node::Group { .. });
    let quantifier = match (min, max) {
        (0, 1) => "?".to_string(),
        (0, MAX_REPS) => "*".to_string(),
        (1, MAX_REPS) => "+".to_string(),
        (n, MAX_REPS) => format!("{{{n},}}"),
        (n, m) if n == m => format!("{{{n}}}"),
        (n, m) => format!("{{{n},{m}}}"),
    };
    if kind == Qtype::Possessive {
        out.push_str("(?>");
    }
    if atomic {
        out.push_str(&operand);
    } else {
        out.push_str("(?:");
        out.push_str(&operand);
        out.push(')');
    }
    out.push_str(&quantifier);
    if kind == Qtype::Lazy {
        out.push('?');
    }
    if kind == Qtype::Possessive {
        out.push(')');
    }
}

#[cfg(test)]
mod tests;

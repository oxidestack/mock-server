//! A backtracking matcher over the parsed tree, for patterns `fancy_regex` cannot match as `Pattern` does: those
//! holding a case-insensitive back reference or an `NFCCharProperty` (an inline `(?c)`). `Pattern.CIBackRef` compares the group's text with the
//! input code point by code point (`toUpperCase` then `toLowerCase` with `UNICODE_CASE`, `ASCII.toLower` without)
//! over as many UTF-16 units as the group holds; `fancy_regex` folds Unicode without `u` and compares byte lengths
//! with it.
//!
//! The walk follows `Pattern`'s nodes: alternatives in order, a group's `Loop`/`LazyLoop` that stops iterating after
//! an iteration that took nothing (`i > locals[beginIndex]`), `Ques`, atomic groups, possessive quantifiers as
//! atomic greedy ones, look-aheads that keep their groups, look-behinds tried from the nearest start (`Behind`), and
//! groups set on the way out and restored on failure (`GroupTail`). `\X`, `\b{g}` and `NFCCharProperty` take clusters
//! from [`grapheme`], and the walk keeps `Matcher.last` for `GraphemeBound`. The other nodes match as
//! their translation does.
//!
//! A walk may run over an input's UTF-16 units ([`Units`]): every surrogate a stand-in character, so a
//! search may start between a pair's halves and a look-behind step back one unit (`Behind`) or one code point
//! (`BehindS`) at a time, reading a lone low surrogate or the pair as `Character.codePointAt` does.

use super::{grapheme, Assertion, Node, Qtype, MAX_REPS};
use regex_syntax::hir::ClassUnicode;
use std::sync::{Arc, OnceLock};
use unicode_normalization::UnicodeNormalization;

/// A node of the walk; groups carry their numbers.
#[derive(Debug)]
enum M {
    Empty,
    Set(Vec<(char, char)>),
    /// `NFCCharProperty`.
    Nfc(Vec<(char, char)>),
    Seq(Vec<M>),
    Alt(Vec<M>),
    Group { index: Option<usize>, node: Box<M> },
    Ahead { negative: bool, node: Box<M> },
    /// `min`/`max` are the fewest and most UTF-16 units the body takes (`TreeInfo.minLength`/`maxLength`);
    /// `by_code_point` for `BehindS`/`NotBehindS`, which count them as code points.
    Behind { negative: bool, min: usize, max: usize, by_code_point: bool, node: Box<M> },
    Atomic(Box<M>),
    /// `accept`: the operand ends at `Pattern.accept` (`Ques`, `Curly`, `GroupCurly`), which writes `Matcher.last`
    /// at the end of each iteration; not for `CharPropertyGreedy`, a group's `Branch` or `Loop`.
    Repeat { node: Box<M>, min: usize, max: usize, kind: Qtype, accept: bool },
    /// `GroupCurly`: a greedy or lazy repetition of a group whose body `study` finds deterministic.
    /// `node` is the group's body, which ends at its `GroupTail` reached with no start to set (`Pattern.accept`).
    GroupCurly { index: Option<usize>, node: Box<M>, min: usize, max: usize, greedy: bool },
    Assert(Assertion),
    BackRef { group: usize, ci: Option<bool> },
    LineEnding,
    Grapheme,
}

/// A pattern compiled for the walk.
#[derive(Debug)]
pub(super) struct Program {
    root: M,
    groups: usize,
    /// The fewest UTF-16 units a match takes (`TreeInfo.minLength`): `Start` tries no index with fewer left.
    min_length: usize,
    /// Group names by number.
    pub(super) names: Arc<Vec<(String, usize)>>,
    /// `Start` rather than `StartS` over [`Units`]: a search goes on one UTF-16 unit at a time, between a
    /// supplementary character's surrogates too.
    unit_starts: bool,
}

/// The steps one search may take before it gives up (`fancy_regex`'s backtrack limit, for the same reason).
const STEP_LIMIT: u64 = 10_000_000;
/// The stack a walk may take of the caller's thread (a test or tokio worker thread of 2 MiB, partly used already);
/// a deeper walk starts again on a thread with a large stack. It is counted in bytes, not levels: a level's frames
/// differ with the architecture and the build (measured on both).
const INLINE_STACK: usize = 256 << 10;
/// The recursion depth of a walk on its own thread; past it the walk stops as [`Stop::Depth`].
const MAX_DEPTH: usize = 200_000;
const THREAD_STACK: usize = 512 << 20;
/// The stack a walk may take of a thread of `stack` bytes: what is left for the frames below the walk and for the
/// frames past the last check (a level's frames and the leaf calls under it): 4 MiB of the 512 MiB, and never less
/// than 128 KiB, which a small thread needs on x86_64 debug (8 KiB of a 1 MiB thread overflowed there).
/// A build whose frames are too large for [`MAX_DEPTH`] levels stops at the stack, as at that depth.
const fn stack_use(stack: usize) -> usize {
    let margin = stack / 128;
    stack - if margin < 128 << 10 { 128 << 10 } else { margin }
}

/// Why a walk stopped without an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stop {
    Steps,
    Depth,
    /// A budgeted walk ([`Program::matches_budgeted`]) read more characters than its budget allows
    /// (`ExpectationLinter.BudgetExceeded`).
    Budget,
    /// A budgeted walk recursed past the depth that stands for the JVM thread's stack (`StackOverflowError`).
    JavaStack,
    /// `Character.codePointAt` threw `StringIndexOutOfBoundsException`: `GraphemeBound` inside the input with
    /// `Matcher.last` at its end, `Grapheme.nextBoundary` reading the code point there; the input's length in UTF-16
    /// units.
    Thrown(usize),
}

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Stop::Steps => "Max limit for backtracking count exceeded",
            Stop::Depth | Stop::JavaStack => "Max stack depth exceeded",
            Stop::Budget => "Character read budget exceeded",
            Stop::Thrown(n) => return write!(f, "Index {n} out of bounds for length {n}"),
        })
    }
}

/// A match: group spans in bytes by number (0 is the whole match).
pub(super) type Spans = Vec<Option<(usize, usize)>>;

impl Program {
    pub(super) fn new(node: &Node, groups: usize) -> Program {
        let mut next = 1;
        let mut names = Vec::new();
        let root = convert(node, &mut next, &mut names);
        let mut info = super::TreeInfo::new();
        super::study_chain(&[node], &mut info);
        Program { root, groups, min_length: info.min.max(0) as usize, names: Arc::new(names), unit_starts: false }
    }

    /// This program rooted at `Start` (`yes`) or `StartS` over [`Units`].
    pub(super) fn unit_starts(mut self, yes: bool) -> Program {
        self.unit_starts = yes;
        self
    }

    /// `matcher(input).matches()`.
    pub(super) fn matches(&self, input: &str) -> Result<Option<Spans>, Stop> {
        self.run(input, None, |walk| {
            let len = walk.input.len();
            walk.reset();
            Ok(walk.m(&self.root, 0, &mut |_, j| Ok(j == len))?.then(|| walk.spans(0, len)))
        })
    }

    /// `matcher(input).matches()` as `ExpectationLinter.RegexBudget` runs it: every character read counts against
    /// `reads` (a read past it is `BudgetExceeded`, which reads as "does not match"), and a recursion past `depth`
    /// levels stands for the `StackOverflowError` a long input makes `java.util.regex` throw. The answer is `None`
    /// when either stopped it, and the characters read are returned either way (one past the budget when it ran
    /// out, as `charAt` counts before it throws).
    pub(super) fn matches_budgeted(&self, input: &str, reads: u64, depth: usize) -> (Option<bool>, u64) {
        let used = std::sync::atomic::AtomicU64::new(0);
        let answer = self.run_limited(Limits { reads, depth }, INLINE_STACK, THREAD_STACK, input, None, |walk| {
            let len = walk.input.len();
            walk.reset();
            let found = walk.m(&self.root, 0, &mut |_, j| Ok(j == len));
            used.store(walk.reads.get(), std::sync::atomic::Ordering::Relaxed);
            let found = found?;
            walk.check_reads()?;
            Ok(found)
        });
        let used = used.load(std::sync::atomic::Ordering::Relaxed);
        match answer {
            Ok(found) => (Some(found), used),
            Err(Stop::Budget) => (None, reads.saturating_add(1)),
            Err(_) => (None, used),
        }
    }

    /// [`Program::matches`] on a large thread of `thread` bytes (a test's way to reach the thread's bound).
    #[cfg(test)]
    pub(super) fn matches_sized(&self, inline: usize, thread: usize, input: &str) -> Result<Option<Spans>, Stop> {
        self.run_sized(inline, thread, input, None, |walk| {
            let len = walk.input.len();
            walk.reset();
            Ok(walk.m(&self.root, 0, &mut |_, j| Ok(j == len))?.then(|| walk.spans(0, len)))
        })
    }

    /// The first match a `find()` from `from` reports; `last_match` is where `\G` holds, if anywhere, and `last`
    /// where the previous match ended (`Matcher.last`, 0 after a reset).
    pub(super) fn find(&self, input: &str, from: usize, last_match: Option<usize>, last: usize) -> Result<Option<Spans>, Stop> {
        self.find_in(input, None, from, last_match, last)
    }

    /// [`Program::find`] over `units` (positions in its text), for a program parsed with its stand-ins
    /// ([`super::parse_units`]).
    pub(super) fn find_units(&self, units: &Units, from: usize, last_match: Option<usize>, last: usize) -> Result<Option<Spans>, Stop> {
        self.find_in(&units.text, Some(units), from, last_match, last)
    }

    /// [`Program::matches`] over `units`.
    pub(super) fn matches_units(&self, units: &Units) -> Result<Option<Spans>, Stop> {
        self.run(&units.text, Some(units), |walk| {
            let len = walk.input.len();
            walk.reset();
            Ok(walk.m(&self.root, 0, &mut |_, j| Ok(j == len))?.then(|| walk.spans(0, len)))
        })
    }

    fn find_in(&self, input: &str, units: Option<&Units>, from: usize, last_match: Option<usize>, last: usize) -> Result<Option<Spans>, Stop> {
        self.run(input, units, |walk| {
            let left = walk.units(from, walk.input.len());
            walk.last_match = last_match;
            walk.last = last;
            let (mut start, mut left) = (from, left);
            // `Matcher.search` clears the groups once: what a `GroupCurly` that failed at one start left in the groups
            // inside it is still there at the next.
            walk.reset();
            loop {
                if left < self.min_length {
                    return Ok(None);
                }
                let mut end = None;
                if walk.m(&self.root, start, &mut |_, j| {
                    end = Some(j);
                    Ok(true)
                })? {
                    let end = end.expect("end");
                    return Ok(Some(walk.spans(start, end)));
                }
                // `Start` over units: on by one unit, into a supplementary character's low surrogate too.
                if units.is_some() && self.unit_starts {
                    match walk.input[start..].chars().next() {
                        Some(c) => {
                            start += c.len_utf8();
                            left -= 1;
                            continue;
                        }
                        None => return Ok(None),
                    }
                }
                // `StartS`: on by a code point, the pair from a high surrogate.
                match walk.read(start) {
                    Some((_, bytes, units)) => {
                        start += bytes;
                        left -= units;
                    }
                    None => return Ok(None),
                }
            }
        })
    }

    /// The match a search from `at` in `units` finds there and nowhere else, if any: from a low surrogate's stand-in,
    /// a search started between a supplementary character's surrogates (`JavaRegex::find_split`), `last` being where
    /// the previous (empty) match ended.
    pub(super) fn attempt_units(&self, units: &Units, at: usize, last: usize) -> Result<Option<Spans>, Stop> {
        self.run(&units.text, Some(units), |walk| {
            if walk.units(at, walk.input.len()) < self.min_length {
                return Ok(None);
            }
            walk.last = last;
            walk.reset();
            let mut end = None;
            Ok(walk
                .m(&self.root, at, &mut |_, j| {
                    end = Some(j);
                    Ok(true)
                })?
                .then(|| walk.spans(at, end.expect("end"))))
        })
    }

    /// Runs `body` on the caller's thread, and again on a thread with a large stack when it goes too deep there.
    fn run<T: Send>(&self, input: &str, units: Option<&Units>, body: impl Fn(&mut Walk) -> Result<T, Stop> + Sync) -> Result<T, Stop> {
        self.run_sized(INLINE_STACK, THREAD_STACK, input, units, body)
    }

    /// [`Program::run`] with the stack sizes (in bytes) of the caller's share and of the large thread.
    fn run_sized<T: Send>(&self, inline: usize, thread: usize, input: &str, units: Option<&Units>, body: impl Fn(&mut Walk) -> Result<T, Stop> + Sync) -> Result<T, Stop> {
        self.run_limited(Limits::NONE, inline, thread, input, units, body)
    }

    /// [`Program::run_sized`] under `limits`.
    #[allow(clippy::too_many_arguments)]
    fn run_limited<T: Send>(&self, limits: Limits, inline: usize, thread: usize, input: &str, units: Option<&Units>, body: impl Fn(&mut Walk) -> Result<T, Stop> + Sync) -> Result<T, Stop> {
        let go = |max_stack| {
            let mut walk = Walk {
                input,
                caps: vec![None; self.groups + 1],
                last_match: None,
                last: 0,
                steps: 0,
                depth: 0,
                stack_top: 0,
                max_stack,
                units,
                reads: std::cell::Cell::new(0),
                limits,
            };
            body(&mut walk)
        };
        match go(inline) {
            Err(Stop::Depth) => {}
            done => return done,
        }
        std::thread::scope(|s| {
            std::thread::Builder::new()
                .name("java-regex".into())
                .stack_size(thread)
                .spawn_scoped(s, || go(stack_use(thread)))
                .map_err(|_| Stop::Depth)?
                .join()
                .map_err(|_| Stop::Depth)?
        })
    }
}

fn convert(node: &Node, next: &mut usize, names: &mut Vec<(String, usize)>) -> M {
    let inner = |n: &Node, next: &mut usize, names: &mut Vec<(String, usize)>| Box::new(convert(n, next, names));
    let count = |n: i32| if n == MAX_REPS { usize::MAX } else { n as usize };
    match node {
        Node::Empty => M::Empty,
        Node::Char(c) => M::Set(c.ranges().iter().map(|r| (r.start(), r.end())).collect()),
        Node::Nfc(c) => M::Nfc(c.ranges().iter().map(|r| (r.start(), r.end())).collect()),
        Node::Seq(nodes) => M::Seq(nodes.iter().map(|n| convert(n, next, names)).collect()),
        Node::Alt(nodes) => M::Alt(nodes.iter().map(|n| convert(n, next, names)).collect()),
        Node::Group { capture, name, node } => {
            let index = capture.then(|| {
                *next += 1;
                *next - 1
            });
            if let (Some(name), Some(index)) = (name, index) {
                names.push((name.clone(), index));
            }
            M::Group { index, node: inner(node, next, names) }
        }
        Node::Look { behind: false, negative, node, .. } => M::Ahead { negative: *negative, node: inner(node, next, names) },
        Node::Look { behind: true, negative, by_code_point, node } => {
            let mut info = super::TreeInfo::new();
            super::study_chain(&[&**node], &mut info);
            let (min, max) = (info.min.max(0) as usize, info.max.max(0) as usize);
            M::Behind { negative: *negative, min, max, by_code_point: *by_code_point, node: inner(node, next, names) }
        }
        Node::Atomic(node) => M::Atomic(inner(node, next, names)),
        Node::Ques { node: atom, kind, group } => {
            let accept = !*group || *kind == Qtype::Possessive || super::self_terminal(atom);
            M::Repeat { node: inner(atom, next, names), min: 0, max: 1, kind: *kind, accept }
        }
        // `group0`: a repetition of a group, neither possessive nor of a look-around or independent group, whose body
        // is deterministic.
        Node::Repeat { node: atom, min, max, kind, group: true }
            if *kind != Qtype::Possessive
                && !super::self_terminal(atom)
                && super::study_chain(&[&**atom], &mut super::TreeInfo::new()) =>
        {
            match convert(atom, next, names) {
                M::Group { index, node } => M::GroupCurly { index, node, min: count(*min), max: count(*max), greedy: *kind == Qtype::Greedy },
                other => M::Repeat { node: Box::new(other), min: count(*min), max: count(*max), kind: *kind, accept: true },
            }
        }
        Node::Repeat { node: atom, min, max, kind, group } => {
            let accept = if !*group {
                !(*kind == Qtype::Greedy && *max == MAX_REPS && matches!(**atom, Node::Char(_)))
            } else {
                *kind == Qtype::Possessive || super::self_terminal(atom) || super::study_chain(&[&**atom], &mut super::TreeInfo::new())
            };
            M::Repeat { node: inner(atom, next, names), min: count(*min), max: count(*max), kind: *kind, accept }
        }
        Node::Assert(a) => M::Assert(*a),
        Node::BackRef { group, ci, unicode } => M::BackRef { group: *group, ci: ci.then_some(*unicode) },
        Node::LineEnding => M::LineEnding,
        Node::Grapheme => M::Grapheme,
    }
}

type Next<'k> = dyn FnMut(&mut Walk, usize) -> Result<bool, Stop> + 'k;

/// An input as `Pattern` reads it, one UTF-16 unit to a character: each supplementary character is replaced by the
/// stand-ins of its two surrogates (the block of [`super::SURROGATES`] code points from `base`, none of them in the
/// input), so a search or a look-behind may start between them. Reading at a high surrogate's stand-in takes the
/// pair (`Character.codePointAt`).
pub(super) struct Units<'a> {
    input: &'a str,
    text: String,
    base: u32,
    /// Where each supplementary character starts, in `text` and in `input`.
    pairs: Vec<(usize, usize)>,
}

impl<'a> Units<'a> {
    pub(super) fn new(input: &'a str, base: u32) -> Units<'a> {
        let mut text = String::with_capacity(input.len() + 16);
        let mut pairs = Vec::new();
        for (o, c) in input.char_indices() {
            if c.len_utf16() == 2 {
                pairs.push((text.len(), o));
                let mut halves = [0u16; 2];
                c.encode_utf16(&mut halves);
                for h in halves {
                    text.push(char::from_u32(base + u32::from(h) - 0xD800).expect("a stand-in"));
                }
            } else {
                text.push(c);
            }
        }
        Units { input, text, base, pairs }
    }

    pub(super) fn text(&self) -> &str {
        &self.text
    }

    /// `input`'s byte `o` in the text; byte 2 of a supplementary character (between its surrogates, see
    /// `java_pattern::slice`) is its low surrogate's stand-in.
    pub(super) fn forward(&self, o: usize) -> usize {
        let k = self.pairs.partition_point(|&(_, po)| po < o);
        match k.checked_sub(1).map(|k| self.pairs[k]) {
            Some((pt, po)) if o == po + 2 => pt + 4,
            _ => o + 4 * k,
        }
    }

    /// The text's byte `t` in `input`, the inverse of [`Units::forward`].
    pub(super) fn back(&self, t: usize) -> usize {
        let k = self.pairs.partition_point(|&(pt, _)| pt < t);
        match k.checked_sub(1).map(|k| self.pairs[k]) {
            Some((pt, po)) if t == pt + 4 => po + 2,
            _ => t - 4 * k,
        }
    }

    fn surrogate(&self, c: char) -> Option<u32> {
        let s = (c as u32).wrapping_sub(self.base);
        (s < super::SURROGATES).then_some(0xD800 + s)
    }
}

struct Walk<'a> {
    input: &'a str,
    /// For a walk over UTF-16 units, the input it stands for (`input` is its text).
    units: Option<&'a Units<'a>>,
    caps: Vec<Option<(usize, usize)>>,
    last_match: Option<usize>,
    /// `Matcher.last`: where the previous match ended, then wherever `Pattern.accept` was last reached; read by
    /// `GraphemeBound`, never restored on backtracking.
    last: usize,
    steps: u64,
    depth: usize,
    /// The address of a local in the outermost recursion level (the stack grows down from it).
    stack_top: usize,
    /// The bytes of stack below `stack_top` the walk may take.
    max_stack: usize,
    /// The characters read so far, as `CharSequence.charAt` calls (see [`Walk::read`]).
    reads: std::cell::Cell<u64>,
    limits: Limits,
}

/// What a budgeted walk stops at ([`Program::matches_budgeted`]).
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// The most characters it may read.
    reads: u64,
    /// The deepest recursion that stands for the JVM's stack.
    depth: usize,
}

impl Limits {
    const NONE: Limits = Limits { reads: u64::MAX, depth: usize::MAX };
}

impl Walk<'_> {
    /// Counts one recursion level in, or stops the walk when it is deeper than [`MAX_DEPTH`] or has taken more than
    /// `max_stack` bytes of stack.
    fn enter(&mut self) -> Result<(), Stop> {
        let here = 0u8;
        let at = std::ptr::addr_of!(here) as usize;
        if self.depth == 0 {
            self.stack_top = at;
        }
        self.depth += 1;
        if self.depth > self.limits.depth {
            return Err(Stop::JavaStack);
        }
        if self.depth > MAX_DEPTH || self.stack_top.saturating_sub(at) > self.max_stack {
            return Err(Stop::Depth);
        }
        Ok(())
    }

    /// Stops a budgeted walk that has read past its budget.
    fn check_reads(&self) -> Result<(), Stop> {
        if self.reads.get() > self.limits.reads {
            return Err(Stop::Budget);
        }
        Ok(())
    }

    fn reset(&mut self) {
        self.caps.iter_mut().for_each(|c| *c = None);
    }

    fn spans(&self, start: usize, end: usize) -> Spans {
        let mut spans = self.caps.clone();
        spans[0] = Some((start, end));
        spans
    }

    /// `Character.codePointAt` at `i`: the code point, and the bytes and UTF-16 units it takes. Over UTF-16 units, a
    /// high surrogate's stand-in reads the pair, a low one alone reads the lone surrogate's stand-in.
    fn read(&self, i: usize) -> Option<(char, usize, usize)> {
        let read = self.read_unmetered(i)?;
        self.reads.set(self.reads.get() + read.2 as u64);
        Some(read)
    }

    fn read_unmetered(&self, i: usize) -> Option<(char, usize, usize)> {
        let c = self.input[i..].chars().next()?;
        match self.units.and_then(|u| u.surrogate(c).map(|s| (u, s))) {
            Some((u, high)) if high < 0xDC00 => {
                let low = self.input[i + 4..].chars().next().and_then(|l| u.surrogate(l)).expect("a pair");
                Some((char::from_u32(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)).expect("a pair"), 8, 2))
            }
            Some(_) => Some((c, 4, 1)),
            None => Some((c, c.len_utf8(), c.len_utf16())),
        }
    }

    /// `Character.codePointBefore` at `i`, as [`Walk::read`].
    fn read_before(&self, i: usize) -> Option<(char, usize, usize)> {
        let read = self.read_before_unmetered(i)?;
        self.reads.set(self.reads.get() + read.2 as u64);
        Some(read)
    }

    fn read_before_unmetered(&self, i: usize) -> Option<(char, usize, usize)> {
        let c = self.input[..i].chars().next_back()?;
        match self.units.and_then(|u| u.surrogate(c)) {
            Some(low) if low >= 0xDC00 => self.read_unmetered(i - 8),
            Some(_) => Some((c, 4, 1)),
            None => Some((c, c.len_utf8(), c.len_utf16())),
        }
    }

    /// One UTF-16 unit back from `i`: the bytes and units stepped (a whole supplementary character outside a walk
    /// over UTF-16 units).
    fn unit_before(&self, i: usize) -> Option<(usize, usize)> {
        let c = self.input[..i].chars().next_back()?;
        Some(if self.units.is_some_and(|u| u.surrogate(c).is_some()) { (4, 1) } else { (c.len_utf8(), c.len_utf16()) })
    }

    /// `Grapheme.nextBoundary` from `i`; over UTF-16 units, a lone low surrogate is a cluster of its own (a
    /// `Control`), and elsewhere clusters are the input's.
    fn boundary(&self, i: usize) -> usize {
        match self.units {
            Some(u) => {
                if self.input[i..].chars().next().and_then(|c| u.surrogate(c)).is_some_and(|s| s >= 0xDC00) {
                    return i + 4;
                }
                u.forward(grapheme::next_boundary(u.input, u.back(i), u.input.len()))
            }
            None => grapheme::next_boundary(self.input, i, self.input.len()),
        }
    }

    /// Matches `node` at `i`, then `k` from where it ended; backtracks into `node` while `k` fails.
    fn m(&mut self, node: &M, i: usize, k: &mut Next) -> Result<bool, Stop> {
        self.steps += 1;
        if self.steps > STEP_LIMIT {
            return Err(Stop::Steps);
        }
        self.enter()?;
        self.check_reads()?;
        let result = self.m_inner(node, i, k);
        self.depth -= 1;
        result
    }

    fn m_inner(&mut self, node: &M, i: usize, k: &mut Next) -> Result<bool, Stop> {
        match node {
            M::Empty => k(self, i),
            M::Set(ranges) => match self.read(i) {
                Some((c, bytes, _)) if in_set(ranges, c) => k(self, i + bytes),
                _ => Ok(false),
            },
            M::Nfc(ranges) => {
                // `NFCCharProperty.match`: a one-code-point grapheme cluster is taken as NFC already; a longer one is
                // normalised from its whole length down to its first code point, and matches where the result is one
                // code point in the set.
                let Some((first, bytes, _)) = self.read(i) else { return Ok(false) };
                let single = i + bytes;
                let mut j = self.boundary(i);
                if j == single {
                    return if in_set(ranges, first) { k(self, j) } else { Ok(false) };
                }
                while single <= j {
                    let cluster = match self.units {
                        Some(u) => &u.input[u.back(i)..u.back(j)],
                        None => &self.input[i..j],
                    };
                    let mut nfc = cluster.nfc();
                    if let (Some(c), None) = (nfc.next(), nfc.next()) && in_set(ranges, c) && k(self, j)? {
                        return Ok(true);
                    }
                    j -= self.read_before(j).map_or(1, |(_, bytes, _)| bytes);
                }
                Ok(false)
            }
            M::Seq(nodes) => self.seq(nodes, i, k),
            M::Alt(alternatives) => {
                for a in alternatives {
                    if self.m(a, i, k)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            M::Group { index: None, node } => self.m(node, i, k),
            M::Group { index: Some(n), node } => {
                let n = *n;
                self.m(node, i, &mut |w: &mut Walk, j| {
                    let prev = w.caps[n];
                    w.caps[n] = Some((i, j));
                    if k(w, j)? {
                        return Ok(true);
                    }
                    w.caps[n] = prev;
                    Ok(false)
                })
            }
            // `Pos`/`Neg`: the body ends at `Pattern.accept`, so the groups a body that matched set are kept when the
            // node fails or the next one does.
            M::Ahead { negative, node } => {
                let found = self.m(node, i, &mut |w, j| {
                    w.last = j;
                    Ok(true)
                })?;
                if found != *negative {
                    k(self, i)
                } else {
                    Ok(false)
                }
            }
            M::Behind { negative, min, max, by_code_point, node } => {
                // `Behind` tries the body from `i - rmin` back to `i - rmax` one UTF-16 unit at a time, so it may start
                // on a low surrogate; `BehindS` steps by code points (`countChars`), each bound stopping at 0. Like
                // `Pos`, it keeps the groups a body that matched set.
                // Steps back from `j`: the bytes, and the units (code points for `BehindS`) stepped.
                let back = |w: &Walk, j: usize| {
                    if *by_code_point { w.read_before(j).map(|(_, b, _)| (b, 1)) } else { w.unit_before(j) }
                };
                let (mut j, mut units) = (i, 0);
                let mut start = Some(i);
                while units < *min {
                    match back(self, j) {
                        Some((b, u)) => {
                            j -= b;
                            units += u;
                            start = Some(j);
                        }
                        // `BehindS` starts from 0, `Behind` from before it: nowhere.
                        None => {
                            start = by_code_point.then_some(j);
                            break;
                        }
                    }
                }
                let mut found = false;
                if let Some(mut j) = start.filter(|_| *by_code_point || units <= *max) {
                    loop {
                        if self.m(node, j, &mut |_, end| Ok(end == i))? {
                            found = true;
                            break;
                        }
                        match back(self, j) {
                            Some((b, u)) if units + u <= *max => {
                                j -= b;
                                units += u;
                            }
                            _ => break,
                        }
                    }
                }
                if found != *negative {
                    k(self, i)
                } else {
                    Ok(false)
                }
            }
            M::Atomic(node) => self.atomic(node, i, k),
            // `Curly`/`Ques` `POSSESSIVE`: the operand ends at `Pattern.accept`, so the groups it set are kept when the
            // next node fails.
            M::Repeat { node, min, max, kind: Qtype::Possessive, accept } => {
                let mut end = None;
                if self.repeat(node, *min, *max, true, *accept, i, &mut |_, j| {
                    end = Some(j);
                    Ok(true)
                })? {
                    return k(self, end.expect("end"));
                }
                Ok(false)
            }
            M::Repeat { node, min, max, kind, accept } => self.repeat(node, *min, *max, *kind == Qtype::Greedy, *accept, i, k),
            M::GroupCurly { index, node, min, max, greedy } => self.group_curly(*index, node, *min, *max, *greedy, i, k),
            M::Assert(a) => {
                if *a == Assertion::GraphemeBound && i != 0 && i < self.input.len() && self.last >= self.input.len() {
                    return Err(Stop::Thrown(self.units(0, self.input.len())));
                }
                if self.assertion(*a, i) {
                    k(self, i)
                } else {
                    Ok(false)
                }
            }
            M::BackRef { group, ci } => {
                let Some(&Some((start, end))) = self.caps.get(*group).filter(|_| *group > 0) else { return Ok(false) };
                let text = &self.input[start..end];
                match ci {
                    None if self.input[i..].starts_with(text) => k(self, i + text.len()),
                    None => Ok(false),
                    Some(unicode) => match self.ci_back_ref(i, (start, end), *unicode) {
                        Some(j) => k(self, j),
                        None => Ok(false),
                    },
                }
            }
            M::LineEnding => {
                if self.input[i..].starts_with("\r\n") && k(self, i + 2)? {
                    return Ok(true);
                }
                match self.read(i) {
                    Some(('\n' | '\u{0B}' | '\u{0C}' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}', bytes, _)) => k(self, i + bytes),
                    _ => Ok(false),
                }
            }
            // `XGrapheme`.
            M::Grapheme if i < self.input.len() => k(self, self.boundary(i)),
            M::Grapheme => Ok(false),
        }
    }

    fn seq(&mut self, nodes: &[M], i: usize, k: &mut Next) -> Result<bool, Stop> {
        match nodes.split_first() {
            None => k(self, i),
            Some((first, rest)) => self.m(first, i, &mut |w: &mut Walk, j| w.seq(rest, j, k)),
        }
    }

    fn atomic(&mut self, node: &M, i: usize, k: &mut Next) -> Result<bool, Stop> {
        let mut end = None;
        // `Ques(INDEPENDENT)`: the body ends at `Pattern.accept`, so the groups it set are kept when the next node
        // fails.
        if self.m(node, i, &mut |w, j| {
            w.last = j;
            end = Some(j);
            Ok(true)
        })? {
            return k(self, end.expect("end"));
        }
        Ok(false)
    }

    /// `X{min,max}` from `i`: a single-character set as `Curly` (greedy takes all, then gives back one at a time),
    /// anything else as `Prolog`/`Loop` (`LazyLoop` when not greedy).
    /// `accept`: each iteration that matched writes `Matcher.last` where it ended.
    #[allow(clippy::too_many_arguments)]
    fn repeat(&mut self, node: &M, min: usize, max: usize, greedy: bool, accept: bool, i: usize, k: &mut Next) -> Result<bool, Stop> {
        if let M::Set(ranges) = node {
            let mut ends = vec![i];
            let mut j = i;
            while ends.len() <= max && (greedy || ends.len() <= min) {
                match self.read(j) {
                    Some((c, bytes, _)) if in_set(ranges, c) => {
                        j += bytes;
                        ends.push(j);
                    }
                    _ => break,
                }
            }
            self.check_reads()?;
            if accept && ends.len() > 1 {
                self.last = ends[ends.len() - 1];
            }
            if ends.len() <= min {
                return Ok(false);
            }
            if greedy {
                for &j in ends[min..].iter().rev() {
                    if k(self, j)? {
                        return Ok(true);
                    }
                }
                return Ok(false);
            }
            // Lazy: the fewest first, taking one more each time the rest fails.
            let mut j = ends[min];
            let mut count = min;
            loop {
                if k(self, j)? {
                    return Ok(true);
                }
                if count >= max {
                    return Ok(false);
                }
                match self.read(j) {
                    Some((c, bytes, _)) if in_set(ranges, c) => {
                        j += bytes;
                        count += 1;
                        if accept {
                            self.last = j;
                        }
                    }
                    _ => return Ok(false),
                }
            }
        }
        // `Loop.matchInit` / `LazyLoop.matchInit`.
        if min > 0 {
            self.m(node, i, &mut |w: &mut Walk, j| w.iterate(node, min, max, greedy, accept, 1, i, j, k))
        } else if greedy {
            if max > 0 && self.m(node, i, &mut |w: &mut Walk, j| w.iterate(node, min, max, greedy, accept, 1, i, j, k))? {
                return Ok(true);
            }
            k(self, i)
        } else {
            if k(self, i)? {
                return Ok(true);
            }
            if max == 0 {
                return Ok(false);
            }
            self.m(node, i, &mut |w: &mut Walk, j| w.iterate(node, min, max, greedy, accept, 1, i, j, k))
        }
    }

    /// `Loop.match` / `LazyLoop.match` after iteration `count` took `begin..i`.
    #[allow(clippy::too_many_arguments)]
    fn iterate(&mut self, node: &M, min: usize, max: usize, greedy: bool, accept: bool, count: usize, begin: usize, i: usize, k: &mut Next) -> Result<bool, Stop> {
        if accept {
            self.last = i;
        }
        if i <= begin {
            // Avoid an infinite loop in the zero-length case.
            return k(self, i);
        }
        let again = |w: &mut Walk, k: &mut Next| w.m(node, i, &mut |w: &mut Walk, j| w.iterate(node, min, max, greedy, accept, count + 1, i, j, k));
        if count < min {
            return again(self, k);
        }
        if greedy {
            if count < max && again(self, k)? {
                return Ok(true);
            }
            k(self, i)
        } else {
            if k(self, i)? {
                return Ok(true);
            }
            if count < max {
                return again(self, k);
            }
            Ok(false)
        }
    }

    /// `GroupCurly.match`: `min` iterations, then `match0` (greedy) or `match1` (lazy); the group is restored when
    /// that fails, the groups inside it are not.
    #[allow(clippy::too_many_arguments)]
    fn group_curly(&mut self, index: Option<usize>, node: &M, min: usize, max: usize, greedy: bool, mut i: usize, k: &mut Next) -> Result<bool, Stop> {
        let saved = index.map(|n| self.caps[n]);
        let mut ret = true;
        for _ in 0..min {
            match self.atom(node, i)? {
                Some(j) => {
                    if let Some(n) = index {
                        self.caps[n] = Some((i, j));
                    }
                    i = j;
                }
                None => {
                    ret = false;
                    break;
                }
            }
        }
        if ret {
            ret = if greedy { self.match0(index, node, max, i, min, k)? } else { self.match1(index, node, max, i, min, k)? };
        }
        if let (false, Some(n), Some(saved)) = (ret, index, saved) {
            self.caps[n] = saved;
        }
        Ok(ret)
    }

    /// One iteration of a `GroupCurly`'s body from `i`: where its first match ends (the `GroupTail` there writes
    /// `Matcher.last`); the groups inside keep what that match set.
    fn atom(&mut self, node: &M, i: usize) -> Result<Option<usize>, Stop> {
        let mut end = None;
        self.m(node, i, &mut |w, j| {
            w.last = j;
            end = Some(j);
            Ok(true)
        })?;
        Ok(end)
    }

    /// The UTF-16 units `a..b` holds; over UTF-16 units, one a character.
    fn units(&self, a: usize, b: usize) -> usize {
        match self.units {
            Some(_) => self.input[a..b].chars().count(),
            None => self.input[a..b].encode_utf16().count(),
        }
    }

    /// `GroupCurly.match0`, the greedy walk after iteration `j`: iterates while each iteration takes as many UTF-16
    /// units as the first, recursing from where one takes a different number, then backs off one iteration at a time
    /// (but not past `j`) while the rest fails.
    #[allow(clippy::too_many_arguments)]
    fn match0(&mut self, index: Option<usize>, node: &M, max: usize, i: usize, j: usize, k: &mut Next) -> Result<bool, Stop> {
        self.enter()?;
        let result = self.match0_inner(index, node, max, i, j, k);
        self.depth -= 1;
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn match0_inner(&mut self, index: Option<usize>, node: &M, max: usize, mut i: usize, mut j: usize, k: &mut Next) -> Result<bool, Stop> {
        let min = j;
        let saved = index.map(|n| self.caps[n]);
        'once: {
            if j >= max {
                break 'once;
            }
            let Some(mut end) = self.atom(node, i)? else { break 'once };
            let units = self.units(i, end);
            if units == 0 {
                break 'once;
            }
            // Where each iteration of this walk starts, and where the last ends: `i - k` backs off to the one before.
            let mut starts = vec![i];
            loop {
                if let Some(n) = index {
                    self.caps[n] = Some((i, end));
                }
                i = end;
                starts.push(i);
                j += 1;
                if j >= max {
                    break;
                }
                match self.atom(node, i)? {
                    None => break,
                    Some(last) if self.units(i, last) != units => {
                        if self.match0(index, node, max, i, j, k)? {
                            return Ok(true);
                        }
                        break;
                    }
                    Some(last) => end = last,
                }
            }
            while j > min {
                if k(self, i)? {
                    if let Some(n) = index {
                        self.caps[n] = Some((starts[starts.len() - 2], i));
                    }
                    return Ok(true);
                }
                // Backing off.
                starts.pop();
                i = *starts.last().expect("the walk's start");
                j -= 1;
                if let (Some(n), true) = (index, j > min) {
                    self.caps[n] = Some((starts[starts.len() - 2], i));
                }
            }
        }
        if let (Some(n), Some(saved)) = (index, saved) {
            self.caps[n] = saved;
        }
        k(self, i)
    }

    /// `GroupCurly.match1`, the lazy walk after iteration `j`: the rest first, one more iteration each time it fails;
    /// stops at an iteration that takes nothing.
    #[allow(clippy::too_many_arguments)]
    fn match1(&mut self, index: Option<usize>, node: &M, max: usize, mut i: usize, mut j: usize, k: &mut Next) -> Result<bool, Stop> {
        loop {
            if k(self, i)? {
                return Ok(true);
            }
            if j >= max {
                return Ok(false);
            }
            let Some(last) = self.atom(node, i)? else { return Ok(false) };
            if last == i {
                return Ok(false);
            }
            if let Some(n) = index {
                self.caps[n] = Some((i, last));
            }
            i = last;
            j += 1;
        }
    }

    /// `CIBackRef.match` at byte `i` against the group set at `group..group_end`: where the reference ends, if it
    /// matches. The input must hold as many UTF-16 units as the group; the loop runs once per unit less one per
    /// supplementary input character, comparing the code points at both cursors.
    fn ci_back_ref(&self, i: usize, (group, group_end): (usize, usize), unicode: bool) -> Option<usize> {
        let size = self.units(group, group_end);
        // The byte offset `size` UTF-16 units on from `i`, which must not split a character outside a walk over units.
        let (mut end, mut units) = (i, 0);
        while units < size {
            let (_, bytes, u) = self.read(end)?;
            units += u;
            end += bytes;
        }
        if units != size {
            return None;
        }
        // `j` runs on from the group's start through the input, as `Character.codePointAt(seq, j)` reads it.
        let (mut x, mut y) = (i, group);
        let mut count = size;
        let mut index = 0;
        while index < count {
            let ((c1, b1, u1), (c2, b2, _)) = (self.read(x)?, self.read(y)?);
            if c1 != c2 {
                let same = if unicode {
                    let (u1, u2) = (super::java_upper(c1 as u32), super::java_upper(c2 as u32));
                    u1 == u2 || super::java_lower(u1) == super::java_lower(u2)
                } else {
                    ascii_lower(c1 as u32) == ascii_lower(c2 as u32)
                };
                if !same {
                    return None;
                }
            }
            if u1 == 2 {
                count -= 1;
            }
            x += b1;
            y += b2;
            index += 1;
        }
        Some(end)
    }

    fn assertion(&self, a: Assertion, i: usize) -> bool {
        let input = self.input;
        let rest = &input[i..];
        let prev = self.read_before(i).map(|(c, ..)| c);
        let next = self.read(i).map(|(c, ..)| c);
        let terminator = |c: char| matches!(c, '\r' | '\u{85}' | '\u{2028}' | '\u{2029}');
        match a {
            Assertion::Begin => i == 0,
            Assertion::LastMatch => self.last_match == Some(i),
            Assertion::End => rest.is_empty(),
            Assertion::Dollar { multiline: false, unix: true } => rest.is_empty() || rest == "\n",
            Assertion::Dollar { multiline: true, unix: true } => rest.is_empty() || rest.starts_with('\n'),
            Assertion::Dollar { multiline: false, unix: false } => {
                rest.is_empty()
                    || rest == "\r\n"
                    || (rest.chars().count() == 1 && terminator(next.expect("next")))
                    || (prev != Some('\r') && rest == "\n")
            }
            Assertion::Dollar { multiline: true, unix: false } => {
                rest.is_empty() || next.is_some_and(terminator) || (prev != Some('\r') && next == Some('\n'))
            }
            Assertion::Caret { unix: true } => !rest.is_empty() && (i == 0 || prev == Some('\n')),
            Assertion::Caret { unix: false } => {
                !rest.is_empty()
                    && (i == 0
                        || matches!(prev, Some('\n' | '\u{85}' | '\u{2028}' | '\u{2029}'))
                        || (prev == Some('\r') && next != Some('\n')))
            }
            Assertion::Bound { negated, unicode } => {
                let classes = bound_classes();
                let w = if unicode { &classes.word } else { &classes.ascii_word };
                let is = in_class;
                // The first character before `i` that is not a non-spacing mark, and how many marks precede `i`.
                let mut marks = 0;
                let mut base = None;
                for c in input[..i].chars().rev() {
                    if is(&classes.mn, c) {
                        marks += 1;
                    } else {
                        base = Some(c);
                        break;
                    }
                }
                let after_base = base.is_some_and(|c| is(&classes.base, c));
                // Over UTF-16 units, `codePointBefore` reads a pair, and a mark's base is looked for unit by unit, so a
                // low surrogate's stand-in ends the search.
                let left = prev.is_some_and(|c| is(w, c)) || (marks > 0 && after_base);
                let right = next.is_some_and(|c| is(w, c)) || (next.is_some_and(|c| is(&classes.mn, c)) && after_base);
                if negated {
                    left == right
                } else {
                    left != right
                }
            }
            // `GraphemeBound`: inside the input, a boundary unless the cluster from `Matcher.last` ends past `i`.
            Assertion::GraphemeBound => i == 0 || i >= input.len() || (self.last < input.len() && self.boundary(self.last) <= i),
        }
    }
}

/// [`Walk::assertion`] over characters, for the timeout replay (`backtrack.rs`); not `\G`, which it replays as `\A`,
/// or `\b{g}`, a node of its own there.
pub(super) fn assertion_at(a: Assertion, input: &[char], i: usize) -> bool {
    let rest = &input[i.min(input.len())..];
    let prev = i.checked_sub(1).and_then(|p| input.get(p)).copied();
    let next = rest.first().copied();
    let terminator = |c: char| matches!(c, '\r' | '\u{85}' | '\u{2028}' | '\u{2029}');
    match a {
        Assertion::Begin => i == 0,
        Assertion::LastMatch | Assertion::GraphemeBound => false,
        Assertion::End => rest.is_empty(),
        Assertion::Dollar { multiline: false, unix: true } => matches!(rest, [] | ['\n']),
        Assertion::Dollar { multiline: true, unix: true } => matches!(rest, [] | ['\n', ..]),
        Assertion::Dollar { multiline: false, unix: false } => {
            matches!(rest, [] | ['\r', '\n']) || (rest.len() == 1 && terminator(rest[0])) || (prev != Some('\r') && rest == ['\n'])
        }
        Assertion::Dollar { multiline: true, unix: false } => {
            rest.is_empty() || next.is_some_and(terminator) || (prev != Some('\r') && next == Some('\n'))
        }
        Assertion::Caret { unix: true } => !rest.is_empty() && (i == 0 || prev == Some('\n')),
        Assertion::Caret { unix: false } => {
            !rest.is_empty()
                && (i == 0 || matches!(prev, Some('\n' | '\u{85}' | '\u{2028}' | '\u{2029}')) || (prev == Some('\r') && next != Some('\n')))
        }
        Assertion::Bound { negated, unicode } => {
            let classes = bound_classes();
            let w = if unicode { &classes.word } else { &classes.ascii_word };
            let is = in_class;
            let mut marks = 0;
            let mut base = None;
            for &c in input[..i].iter().rev() {
                if is(&classes.mn, c) {
                    marks += 1;
                } else {
                    base = Some(c);
                    break;
                }
            }
            let after_base = base.is_some_and(|c| is(&classes.base, c));
            let left = prev.is_some_and(|c| is(w, c)) || (marks > 0 && after_base);
            let right = next.is_some_and(|c| is(w, c)) || (next.is_some_and(|c| is(&classes.mn, c)) && after_base);
            if negated { left == right } else { left != right }
        }
    }
}

struct BoundClasses {
    word: ClassUnicode,
    ascii_word: ClassUnicode,
    base: ClassUnicode,
    mn: ClassUnicode,
}

fn bound_classes() -> &'static BoundClasses {
    static CLASSES: OnceLock<BoundClasses> = OnceLock::new();
    CLASSES.get_or_init(|| BoundClasses {
        word: super::word(),
        ascii_word: super::ascii_word(),
        base: super::union(super::letter(), &super::ucd("gc=Nd")),
        mn: super::categories(&["Mn"]),
    })
}

/// Whether `set` (sorted, disjoint ranges) holds `c`: a binary search, as a scan of the Unicode sets made each `\b`
/// cost microseconds, which a regex-timeout replay meets at every step.
fn in_class(set: &ClassUnicode, c: char) -> bool {
    set.ranges()
        .binary_search_by(|r| {
            if r.end() < c {
                std::cmp::Ordering::Less
            } else if r.start() > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn in_set(ranges: &[(char, char)], c: char) -> bool {
    ranges
        .binary_search_by(|&(lo, hi)| {
            if hi < c {
                std::cmp::Ordering::Less
            } else if lo > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// `ASCII.toLower`.
fn ascii_lower(c: u32) -> u32 {
    if (0x41..=0x5A).contains(&c) {
        c + 0x20
    } else {
        c
    }
}

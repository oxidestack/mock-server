//! How long `java.util.regex` would take over a match, for `regexMatchingTimeoutMillis`.
//!
//! 8.0.0 runs every `RegexStringMatcher` regex in `MatchingTimeoutExecutor` and treats one that outlives the budget
//! (default 5000 ms) as a non-match, with a WARN entry. Java's engine backtracks, so a pattern like `(.*a){25}` takes
//! hours over a 40-character value; the `regex` crate never does. This module replays the work Java's backtracker
//! does, against a wall-clock deadline that never cuts short a replay Java finishes well within the budget
//! ([`Budget`]), for the pattern shapes where that work can explode (a quantified group holding a quantifier or an
//! alternation, or three or more variable-length repetitions, which are polynomial over a long value). A replay that
//! finishes has Java's result, which then stands for the match: the linear engines' own backtracking
//! (`java_pattern`'s walk and `fancy_regex` model what Java matches, not how) can take far longer on the same shapes.
//!
//! The replay walks a node graph shaped like `Pattern`'s: single-character repetitions are `Curly`, a quantified
//! group is a `Prolog`/`Loop` pair (`LazyLoop` when reluctant) whose body ends back at the loop, `?` on a group is a
//! `Branch`. As in `Pattern.compile`, a greedy unbounded loop over a group that sits in no other quantified group and
//! in no look-behind memoises the positions where another iteration failed (`Loop.posIndex`, JDK-6328855), which keeps
//! `(a|aa)*b` and `(x+x+)+y` linear while `(.*a){25}` and `((a+)+)+b` stay exponential, as they are on the oracle's
//! JVM; a back reference anywhere in the pattern (`hasGroupRef`) turns that off for every loop. A group whose body
//! `study` finds deterministic is a `GroupCurly` instead, which never memoises, so `(ab)*` repeated nine times is
//! polynomial past the budget there. Look-aheads (`Pos`,
//! `Neg`), atomic groups (`Ques` with `INDEPENDENT`) and possessive repetitions of a group (`Curly` with
//! `POSSESSIVE`) run their body up to its first match (`Pattern.accept`) and never backtrack into it; a look-behind
//! (`Behind`, `NotBehind`) tries its body from the nearest start back to the farthest its length allows, each try
//! ending where the look-behind stands (`LookBehindEndNode`). Back references compare with the group as it was last
//! set (`GroupTail`), case-insensitively as `CIBackRef` does. `\X` (`XGrapheme`) and classes under an
//! inline `(?c)` (`NFCCharProperty`) take clusters from `Grapheme.nextBoundary`; quantified alone they are `Curly`
//! atoms (each iteration the atom's first match, no `Loop.posIndex`). `\b{g}` (`GraphemeBound`) reads `Matcher.last`,
//! which every `Pattern.accept` writes: the end of a look-ahead, an atomic group, each iteration of a `Curly`, `Ques`
//! or `GroupCurly`.

use super::java_pattern::{ci_back_ref_equal, grapheme_boundary, nfc_single, Replay, ReplayAssertion, ReplayKind};
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// The graph's nodes; every `next` is an index into [`Program::nodes`].
#[derive(Debug)]
enum Node {
    /// One character from a set of inclusive ranges.
    Set { ranges: Vec<(char, char)>, next: usize },
    /// `Curly`/`CharPropertyGreedy`: a repeated single-character set (`max` of `u32::MAX` is unbounded); `accept`
    /// when each character taken writes `Matcher.last` (all but `CharPropertyGreedy`).
    Curly { ranges: Vec<(char, char)>, min: u32, max: u32, kind: ReplayKind, accept: bool, next: usize },
    /// `Curly` (greedy or lazy) over `\X` or an `NFCCharProperty`: `body` ends at [`Node::Done`], so each iteration is
    /// its first match.
    Iterate { body: usize, min: u32, max: u32, greedy: bool, next: usize },
    /// `XGrapheme`.
    Grapheme { next: usize },
    /// `NFCCharProperty`.
    Nfc { ranges: Vec<(char, char)>, next: usize },
    /// `GraphemeBound`.
    GraphemeBound { next: usize },
    /// Alternatives in order; each one's chain ends at the branch's continuation.
    Branch { alts: Vec<usize> },
    /// `GroupHead`: records where the current iteration of a loop's group began.
    GroupHead { local: usize, next: usize },
    /// `Prolog`: enters the loop (`Loop.matchInit`).
    Prolog { lp: usize },
    /// `Loop`/`LazyLoop`, reached again at the end of each iteration of `body`; `accept` when the iteration ends at
    /// `Pattern.accept` (`GroupCurly`), writing `Matcher.last`.
    Loop { body: usize, min: u32, max: u32, greedy: bool, accept: bool, memo: Option<usize>, count: usize, begin: usize, next: usize },
    /// A capturing group's `GroupHead`, when the pattern has a back reference: where the group began.
    CaptureHead { local: usize, next: usize },
    /// `GroupTail`: sets the group, restored when the rest fails.
    CaptureTail { local: usize, group: usize, next: usize },
    /// `BackRef`, or `CIBackRef` with `ci` (`doUnicodeCase`).
    BackRef { group: usize, ci: Option<bool>, next: usize },
    /// `Pos` / `Neg`: `body` ends at [`Node::Done`].
    Ahead { body: usize, negative: bool, next: usize },
    /// `Behind` / `NotBehind`: `body` ends at [`Node::BehindEnd`]; `min`/`max` its `TreeInfo` lengths.
    Behind { body: usize, negative: bool, min: usize, max: usize, next: usize },
    /// `Ques(INDEPENDENT)`: `body` ends at [`Node::Done`], the rest continues where its first match ended.
    Atomic { body: usize, next: usize },
    /// `Curly`/`Ques` with `POSSESSIVE` over more than one character: each iteration is `body`'s first match.
    Possessive { body: usize, min: u32, max: u32, next: usize },
    /// `^` without `MULTILINE` (`Begin`).
    Begin { next: usize },
    /// `Dollar`, `UnixDollar`, `End`, `Caret`, `UnixCaret`, `Bound`.
    Assert { assertion: ReplayAssertion, next: usize },
    /// `Pattern.accept` ending an atom, a look-ahead or an atomic group: `Matcher.last` is where it was reached.
    Done,
    /// `LookBehindEndNode`.
    BehindEnd,
    /// `LastNode`: in `matches()` mode the whole input was consumed; in `find()` mode, anywhere.
    Accept,
}

/// A compiled pattern whose Java backtracking cost is worth measuring.
#[derive(Debug)]
pub(crate) struct Program {
    nodes: Vec<Node>,
    start: usize,
    locals: usize,
    memos: usize,
    /// The highest capturing group number a back reference may read.
    groups: usize,
    /// The fewest characters a match takes (`TreeInfo.minLength`), which bounds `find()`'s start positions.
    min_len: usize,
    /// It reads grapheme clusters (`\X`, `\b{g}`, `NFCCharProperty`): the walk needs the input's byte offsets.
    graphemes: bool,
}

/// The input as the walk reads it: characters, and for grapheme clusters the text with each character's byte offset.
struct Input<'a> {
    chars: Vec<char>,
    text: &'a str,
    /// `chars[i]` starts at byte `offsets[i]`; one more entry for the end. Empty when the program reads no clusters.
    offsets: Vec<usize>,
}

/// What replaying Java's backtracking over an input came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Java would finish within the budget, with this result.
    Finished(bool),
    /// Java would still be backtracking at the deadline.
    TimedOut,
}

/// The stack a replay may take of the caller's thread (a test or tokio worker thread of 2 MiB, partly used already);
/// deeper replays move to a thread with a large stack. It is counted in bytes, not levels: a level's frames take
/// 1,327 bytes in an aarch64 debug build and 2,254 in an x86_64 one, where 1,500 levels overflowed a 2 MiB thread,
/// and far less in a release build.
const INLINE_STACK: usize = 256 << 10;
/// The recursion depth of a replay on its own thread. Past it Java would be deep in a `StackOverflowError`, which
/// `MatchingTimeoutExecutor` reports as a non-match without a timeout; the replay gives up and lets the caller decide.
const THREAD_DEPTH: usize = 400_000;
const THREAD_STACK: usize = 512 << 20;
/// The stack a replay may take of its own thread: what is left for the frames below the walk and for one level past
/// the check. A build whose frames are too large for [`THREAD_DEPTH`] levels gives up there, as at that depth.
const THREAD_STACK_USE: usize = THREAD_STACK - (4 << 20);
/// Nodes beyond this (counted repetitions are expanded) are not replayed.
const MAX_NODES: usize = 20_000;

impl Program {
    /// The replay program for the Java `pattern` as `Pattern.compile(pattern, flags)` reads it (its tree from
    /// `java_pattern`, so Java-only syntax, `\Q…\E`, case folding and `.` without `DOTALL` are Java's); `None` when its
    /// shape cannot backtrack badly or it uses syntax the replay does not model (it is then left to the linear
    /// engines, as before).
    pub(crate) fn compile(pattern: &str, flags: u32) -> Option<Program> {
        // A pattern without any group or several quantifiers cannot be the kind that explodes; skip the parse.
        let quantifiers = pattern.chars().filter(|c| matches!(c, '*' | '+' | '{' | '?')).count();
        if quantifiers < 2 && !pattern.contains('(') {
            return None;
        }
        let tree = super::java_pattern::replay_tree(pattern, flags)?;
        if !risky(&tree) {
            return None;
        }
        let back_refs = has_back_ref(&tree);
        let graphemes = reads_graphemes(&tree);
        let mut c = Compiler { nodes: Vec::new(), locals: 0, memos: 0, groups: 0, back_refs, done: 0, behind_end: 0 };
        let accept = c.push(Node::Accept)?;
        c.done = c.push(Node::Done)?;
        c.behind_end = c.push(Node::BehindEnd)?;
        let start = c.compile(&tree, accept, false)?;
        Some(Program { nodes: c.nodes, start, locals: c.locals, memos: c.memos, groups: c.groups, min_len: min_len(&tree), graphemes })
    }

    /// Replays `matcher.matches()` over `input` within `budget`; `None` when the replay is too deep to finish.
    pub(crate) fn run(&self, input: &str, budget: Budget) -> Option<Outcome> {
        self.replay(input, budget, false)
    }

    /// Replays `matcher.find()` over `input` within `budget`: `Pattern`'s `Start` node tries each start position in
    /// turn up to the input's length less the pattern's minimum length (only the first when the pattern begins with
    /// `^`, which `Pattern.compile` roots at `Begin`), and a match may end anywhere. The loops' memoised positions
    /// (`Matcher.localsPos`) are cleared once per search, not per start position.
    pub(crate) fn run_find(&self, input: &str, budget: Budget) -> Option<Outcome> {
        self.replay(input, budget, true)
    }

    fn replay(&self, input: &str, budget: Budget, find: bool) -> Option<Outcome> {
        let offsets = if self.graphemes { input.char_indices().map(|(o, _)| o).chain([input.len()]).collect() } else { Vec::new() };
        let chars = Input { chars: input.chars().collect(), text: input, offsets };
        let run = |max_stack| if find { self.find_with_depth(&chars, budget, max_stack) } else { self.run_with_depth(&chars, budget, max_stack) };
        match run(INLINE_STACK) {
            Err(Stop::TooDeep) => std::thread::scope(|s| {
                std::thread::Builder::new()
                    .name("regex-replay".into())
                    .stack_size(THREAD_STACK)
                    .spawn_scoped(s, || run(THREAD_STACK_USE))
                    .ok()?
                    .join()
                    .ok()?
                    .map_or_else(
                        |stop| match stop {
                            Stop::Deadline => Some(Outcome::TimedOut),
                            Stop::Thrown => Some(Outcome::Finished(false)),
                            Stop::TooDeep => None,
                        },
                        |m| Some(Outcome::Finished(m)),
                    )
            }),
            Err(Stop::Deadline) => Some(Outcome::TimedOut),
            // Java's search ends at once with the exception.
            Err(Stop::Thrown) => Some(Outcome::Finished(false)),
            Ok(m) => Some(Outcome::Finished(m)),
        }
    }

    fn machine<'a>(&'a self, input: &'a Input<'a>, budget: Budget, max_stack: usize, find: bool) -> Machine<'a> {
        Machine {
            program: self,
            input: &input.chars,
            text: input.text,
            offsets: &input.offsets,
            bounds: if self.graphemes { vec![usize::MAX; input.chars.len()] } else { Vec::new() },
            find,
            locals: vec![-1; self.locals],
            memos: (0..self.memos).map(|_| HashSet::new()).collect(),
            groups: vec![(-1, -1); self.groups + 1],
            last: 0,
            behind_to: 0,
            steps: 0,
            depth: 0,
            stack_top: 0,
            max_stack,
            budget,
        }
    }

    fn run_with_depth(&self, input: &Input, budget: Budget, max_stack: usize) -> Result<bool, Stop> {
        self.machine(input, budget, max_stack, false).matches(self.start, 0)
    }

    fn find_with_depth(&self, input: &Input, budget: Budget, max_stack: usize) -> Result<bool, Stop> {
        let mut m = self.machine(input, budget, max_stack, true);
        if matches!(self.nodes[self.start], Node::Begin { .. }) {
            return m.matches(self.start, 0);
        }
        let Some(guard) = input.chars.len().checked_sub(self.min_len) else { return Ok(false) };
        for i in 0..=guard {
            m.groups.iter_mut().for_each(|g| *g = (-1, -1));
            if m.matches(self.start, i)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// The fewest characters `tree` can match.
fn min_len(tree: &Replay) -> usize {
    match tree {
        Replay::Set(_) | Replay::Grapheme | Replay::Nfc(_) => 1,
        Replay::Group { node, .. } | Replay::Atomic(node) => min_len(node),
        Replay::Repeat { node, min, .. } => (*min as usize).saturating_mul(min_len(node)),
        Replay::Seq(parts) => parts.iter().fold(0usize, |n, p| n.saturating_add(min_len(p))),
        Replay::Alt(alts) => alts.iter().map(min_len).min().unwrap_or(0),
        _ => 0,
    }
}

/// Whether the pattern reads grapheme clusters.
fn reads_graphemes(tree: &Replay) -> bool {
    match tree {
        Replay::Grapheme | Replay::Nfc(_) | Replay::GraphemeBound => true,
        Replay::Seq(parts) | Replay::Alt(parts) => parts.iter().any(reads_graphemes),
        Replay::Group { node, .. } | Replay::Atomic(node) | Replay::Repeat { node, .. } | Replay::Ahead { node, .. } | Replay::Behind { node, .. } => {
            reads_graphemes(node)
        }
        _ => false,
    }
}

/// Whether the pattern holds a back reference, which turns off every loop's memo (`hasGroupRef`).
fn has_back_ref(tree: &Replay) -> bool {
    match tree {
        Replay::BackRef { .. } => true,
        Replay::Seq(parts) | Replay::Alt(parts) => parts.iter().any(has_back_ref),
        Replay::Group { node, .. } | Replay::Atomic(node) | Replay::Repeat { node, .. } | Replay::Ahead { node, .. } | Replay::Behind { node, .. } => {
            has_back_ref(node)
        }
        _ => false,
    }
}

/// Whether Java's backtracking can take exponential or high-polynomial time on this shape: a quantified group
/// holding a variable repetition or an alternation, or at least three variable-length repetitions (two, as in
/// `/users/[0-9]+/.*`, are quadratic at worst and not worth a replay on every evaluation).
fn risky(tree: &Replay) -> bool {
    fn walk(tree: &Replay, in_repetition: bool, variable: &mut usize) -> bool {
        match tree {
            Replay::Repeat { node, min, max, .. } => {
                let varies = *max != Some(*min);
                if varies {
                    *variable += 1;
                }
                if in_repetition && varies {
                    return true;
                }
                let group = single_char_ranges(node, false).is_none();
                walk(node, in_repetition || (group && max.is_none_or(|m| m > 1)), variable)
            }
            Replay::Alt(alts) => in_repetition || alts.iter().any(|a| walk(a, in_repetition, variable)),
            Replay::Group { node, .. } | Replay::Atomic(node) | Replay::Ahead { node, .. } | Replay::Behind { node, .. } => {
                walk(node, in_repetition, variable)
            }
            Replay::Seq(parts) => parts.iter().any(|p| walk(p, in_repetition, variable)),
            _ => false,
        }
    }
    let mut variable = 0;
    walk(tree, false, &mut variable) || variable >= 3
}

/// The ranges of a node that matches exactly one character, if `tree` is one; a capturing group only when
/// `captures` is off (it must otherwise set its group).
fn single_char_ranges(tree: &Replay, captures: bool) -> Option<Vec<(char, char)>> {
    match tree {
        Replay::Set(ranges) => Some(ranges.clone()),
        Replay::Group { index, node } if index.is_none() || !captures => single_char_ranges(node, captures),
        _ => None,
    }
}

struct Compiler {
    nodes: Vec<Node>,
    locals: usize,
    memos: usize,
    groups: usize,
    /// The pattern holds a back reference: groups are set, and no loop memoises (`hasGroupRef`).
    back_refs: bool,
    done: usize,
    behind_end: usize,
}

impl Compiler {
    fn push(&mut self, node: Node) -> Option<usize> {
        (self.nodes.len() < MAX_NODES).then(|| {
            self.nodes.push(node);
            self.nodes.len() - 1
        })
    }

    fn local(&mut self) -> usize {
        self.locals += 1;
        self.locals - 1
    }

    /// The entry of `tree`'s nodes, continuing at `next`. `nested`: inside a quantified group or a look-behind,
    /// where `Pattern` clears the loops it would otherwise memoise.
    fn compile(&mut self, tree: &Replay, next: usize, nested: bool) -> Option<usize> {
        match tree {
            Replay::Empty => Some(next),
            Replay::Set(ranges) => self.push(Node::Set { ranges: ranges.clone(), next }),
            Replay::Begin => self.push(Node::Begin { next }),
            Replay::Grapheme => self.push(Node::Grapheme { next }),
            Replay::Nfc(ranges) => self.push(Node::Nfc { ranges: ranges.clone(), next }),
            Replay::GraphemeBound => self.push(Node::GraphemeBound { next }),
            Replay::Assert(assertion) => self.push(Node::Assert { assertion: *assertion, next }),
            Replay::BackRef { group, ci } => self.push(Node::BackRef { group: *group, ci: *ci, next }),
            Replay::Group { index: Some(group), node } if self.back_refs => {
                let local = self.local();
                self.groups = self.groups.max(*group);
                let tail = self.push(Node::CaptureTail { local, group: *group, next })?;
                let body = self.compile(node, tail, nested)?;
                self.push(Node::CaptureHead { local, next: body })
            }
            Replay::Group { node, .. } => self.compile(node, next, nested),
            Replay::Seq(parts) => {
                let mut next = next;
                for part in parts.iter().rev() {
                    next = self.compile(part, next, nested)?;
                }
                Some(next)
            }
            Replay::Alt(alts) => {
                let alts = alts.iter().map(|a| self.compile(a, next, nested)).collect::<Option<Vec<_>>>()?;
                self.push(Node::Branch { alts })
            }
            Replay::Ahead { negative, node } => {
                let body = self.compile(node, self.done, nested)?;
                self.push(Node::Ahead { body, negative: *negative, next })
            }
            Replay::Behind { negative, min, max, node } => {
                // `group0` clears the loops inside a look-behind from the memoised ones.
                let body = self.compile(node, self.behind_end, true)?;
                self.push(Node::Behind { body, negative: *negative, min: *min, max: *max, next })
            }
            Replay::Atomic(node) => {
                let body = self.compile(node, self.done, nested)?;
                self.push(Node::Atomic { body, next })
            }
            Replay::Repeat { node, min, max: bound, kind, accept } => {
                let max = bound.unwrap_or(u32::MAX);
                if let Some(ranges) = single_char_ranges(node, self.back_refs) {
                    return self.push(Node::Curly { ranges, min: *min, max, kind: *kind, accept: *accept, next });
                }
                // A quantified look-around or atomic group is a zero-length assertion to `group0`, which keeps the
                // loops inside it memoised; any other quantified group clears them.
                let nested_body = nested || !matches!(**node, Replay::Ahead { .. } | Replay::Atomic(_));
                if *kind == ReplayKind::Possessive {
                    let body = self.compile(node, self.done, nested_body)?;
                    return self.push(Node::Possessive { body, min: *min, max, next });
                }
                let greedy = *kind == ReplayKind::Greedy;
                if matches!(**node, Replay::Grapheme | Replay::Nfc(_)) {
                    // `Curly` (or `Ques`) over the atom alone: neither a `Loop` nor a `Branch`.
                    let body = self.compile(node, self.done, nested_body)?;
                    return self.push(Node::Iterate { body, min: *min, max, greedy, next });
                }
                if *min == 0 && max == 1 {
                    // `Ques` on a group: a branch with an empty alternative.
                    let body = self.compile(node, next, nested_body)?;
                    let alts = if greedy { vec![body, next] } else { vec![next, body] };
                    return self.push(Node::Branch { alts });
                }
                let (count, begin) = (self.local(), self.local());
                // An iteration ending at `Pattern.accept` is a `GroupCurly` (a deterministic body) or a `Curly` over a
                // look-around or atomic group, neither of which has `Loop.posIndex`.
                let memo = (greedy && bound.is_none() && !nested && !self.back_refs && !*accept).then(|| {
                    self.memos += 1;
                    self.memos - 1
                });
                let lp = self.push(Node::Loop { body: usize::MAX, min: *min, max, greedy, accept: *accept, memo, count, begin, next })?;
                let body = self.compile(node, lp, nested_body)?;
                let head = self.push(Node::GroupHead { local: begin, next: body })?;
                if let Node::Loop { body, .. } = &mut self.nodes[lp] {
                    *body = head;
                }
                self.push(Node::Prolog { lp })
            }
        }
    }
}

/// How long a replay may run before it stands for Java's timeout: the wall clock, but never fewer than `floor` steps.
/// The replay is slower per step than the JVM, many times over in a debug build and more on a loaded
/// machine, so the clock alone turned replays Java finishes in a few milliseconds into timeouts (`(a|b)*` nine times
/// over 60 characters: 204,087 steps, which took up to 360 ms at a load average of 150 against a 300 ms budget).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Budget {
    deadline: Instant,
    /// The steps Java takes well within the budget, whatever the replay's own clock says.
    floor: u64,
}

impl Budget {
    /// `regexMatchingTimeoutMillis` = `millis`, from now.
    pub(crate) fn millis(millis: u64) -> Budget {
        Budget { deadline: Instant::now() + Duration::from_millis(millis), floor: millis.saturating_mul(JAVA_STEPS_PER_MILLI) }
    }

    /// Whether a replay that has taken `steps` has outlived the budget.
    fn spent(&self, steps: u64) -> bool {
        steps >= self.floor && Instant::now() >= self.deadline
    }
}

/// Replay steps (one per node entered, as `Pattern`'s nodes' `match` calls) that Java certainly gets through in a
/// millisecond. Measured on JDK 25 at a load average of about 150: warm, 13,000 (`(.*a){3}x`, whose
/// `Curly` backtracks inside one step) to 420,000 (`(ab)*` repeated, `GroupCurly`) and 60,000 for `(a|b)*` repeated;
/// a first, cold call no fewer than 7,000. A seventh of the slowest, so only a replay Java would finish in a fraction
/// of its budget is kept from timing out; every timeout the scenarios record takes Java hours, far past the floor.
const JAVA_STEPS_PER_MILLI: u64 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    Deadline,
    TooDeep,
    /// Java throws: `GraphemeBound` inside the input with `Matcher.last` at its end (`Grapheme.nextBoundary` reads
    /// the code point there).
    Thrown,
}

struct Machine<'a> {
    program: &'a Program,
    input: &'a [char],
    text: &'a str,
    offsets: &'a [usize],
    /// Where the grapheme cluster from each character ends, `usize::MAX` until asked.
    bounds: Vec<usize>,
    /// `find()` mode: a match may end before the input does.
    find: bool,
    locals: Vec<i64>,
    memos: Vec<HashSet<usize>>,
    /// Capturing groups' (start, end), `-1` when unset.
    groups: Vec<(i64, i64)>,
    /// `Matcher.last`: where [`Node::Done`] was last reached.
    last: usize,
    /// `Matcher.lookbehindTo`.
    behind_to: usize,
    steps: u64,
    depth: usize,
    /// The address of a local in the outermost [`Machine::matches`] (the stack grows down from it).
    stack_top: usize,
    /// The bytes of stack below `stack_top` the walk may take.
    max_stack: usize,
    budget: Budget,
}

fn in_ranges(ranges: &[(char, char)], c: char) -> bool {
    ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi)
}

impl Machine<'_> {
    /// `Grapheme.nextBoundary` from character `i` (before the end), in characters.
    fn boundary(&mut self, i: usize) -> usize {
        if self.bounds[i] == usize::MAX {
            let end = grapheme_boundary(self.text, self.offsets[i]);
            self.bounds[i] = self.offsets.binary_search(&end).unwrap_or_else(|at| at);
        }
        self.bounds[i]
    }

    fn matches(&mut self, node: usize, i: usize) -> Result<bool, Stop> {
        self.steps += 1;
        if self.steps & 0xFFF == 0 && self.budget.spent(self.steps) {
            return Err(Stop::Deadline);
        }
        let here = 0u8;
        let at = std::ptr::addr_of!(here) as usize;
        if self.depth == 0 {
            self.stack_top = at;
        }
        if self.depth >= THREAD_DEPTH || self.stack_top.saturating_sub(at) > self.max_stack {
            return Err(Stop::TooDeep);
        }
        self.depth += 1;
        let result = self.step(node, i);
        self.depth -= 1;
        result
    }

    fn step(&mut self, node: usize, i: usize) -> Result<bool, Stop> {
        let program = self.program;
        match &program.nodes[node] {
            Node::Accept => Ok(self.find || i == self.input.len()),
            Node::Done => {
                self.last = i;
                Ok(true)
            }
            Node::BehindEnd => Ok(i == self.behind_to),
            Node::Set { ranges, next } => {
                if i < self.input.len() && in_ranges(ranges, self.input[i]) { self.matches(*next, i + 1) } else { Ok(false) }
            }
            Node::Begin { next } => if i == 0 { self.matches(*next, i) } else { Ok(false) },
            Node::Assert { assertion, next } => if assertion.holds(self.input, i) { self.matches(*next, i) } else { Ok(false) },
            Node::Curly { ranges, min, max, kind, accept, next } => {
                let (min, max) = (*min as usize, *max as usize);
                let mut j = i;
                while j - i < min {
                    if j < self.input.len() && in_ranges(ranges, self.input[j]) { j += 1 } else { return Ok(false) }
                }
                if *kind != ReplayKind::Lazy {
                    while j - i < max && j < self.input.len() && in_ranges(ranges, self.input[j]) {
                        j += 1;
                    }
                    if *accept && j > i {
                        self.last = j;
                    }
                    if *kind == ReplayKind::Possessive {
                        return self.matches(*next, j);
                    }
                    loop {
                        if self.matches(*next, j)? {
                            return Ok(true);
                        }
                        if j - i <= min {
                            return Ok(false);
                        }
                        j -= 1;
                    }
                }
                if *accept && j > i {
                    self.last = j;
                }
                loop {
                    if self.matches(*next, j)? {
                        return Ok(true);
                    }
                    if j - i >= max || j >= self.input.len() || !in_ranges(ranges, self.input[j]) {
                        return Ok(false);
                    }
                    j += 1;
                    if *accept {
                        self.last = j;
                    }
                }
            }
            Node::Grapheme { next } => {
                if i < self.input.len() {
                    let j = self.boundary(i);
                    self.matches(*next, j)
                } else {
                    Ok(false)
                }
            }
            Node::Nfc { ranges, next } => {
                // `NFCCharProperty.match`: a one-code-point cluster is taken as NFC already; a longer one is normalised
                // from its whole length down to its first code point, and matches where the result is one code point
                // in the set.
                if i >= self.input.len() {
                    return Ok(false);
                }
                let mut j = self.boundary(i);
                if j == i + 1 {
                    return if in_ranges(ranges, self.input[i]) { self.matches(*next, j) } else { Ok(false) };
                }
                while j > i {
                    if let Some(c) = nfc_single(&self.text[self.offsets[i]..self.offsets[j]])
                        && in_ranges(ranges, c)
                        && self.matches(*next, j)?
                    {
                        return Ok(true);
                    }
                    j -= 1;
                }
                Ok(false)
            }
            Node::GraphemeBound { next } => {
                // `GraphemeBound`: inside the input, a boundary unless the cluster from `Matcher.last` ends past `i`.
                let len = self.input.len();
                if i != 0 && i < len {
                    if self.last >= len {
                        return Err(Stop::Thrown);
                    }
                    if self.boundary(self.last) > i {
                        return Ok(false);
                    }
                }
                self.matches(*next, i)
            }
            Node::Iterate { body, min, max, greedy, next } => {
                // `Curly.match`: `min` iterations, then `match0` (greedy: as many as there are, then one fewer at a
                // time) or `match1` (lazy: one more each time the rest fails).
                let mut at = i;
                for _ in 0..*min {
                    if !self.matches(*body, at)? {
                        return Ok(false);
                    }
                    at = self.last;
                }
                let mut count = *min;
                if !*greedy {
                    loop {
                        if self.matches(*next, at)? {
                            return Ok(true);
                        }
                        if count >= *max || !self.matches(*body, at)? || self.last == at {
                            return Ok(false);
                        }
                        at = self.last;
                        count += 1;
                    }
                }
                let mut ends = vec![at];
                while count < *max && self.matches(*body, at)? && self.last != at {
                    at = self.last;
                    ends.push(at);
                    count += 1;
                }
                for &j in ends.iter().rev() {
                    if self.matches(*next, j)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Node::Branch { alts } => {
                for &alt in alts {
                    if self.matches(alt, i)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Node::GroupHead { local, next } | Node::CaptureHead { local, next } => {
                let save = self.locals[*local];
                self.locals[*local] = i as i64;
                let r = self.matches(*next, i);
                self.locals[*local] = save;
                r
            }
            Node::CaptureTail { local, group, next } => {
                let save = self.groups[*group];
                self.groups[*group] = (self.locals[*local], i as i64);
                let r = self.matches(*next, i)?;
                if !r {
                    self.groups[*group] = save;
                }
                Ok(r)
            }
            Node::BackRef { group, ci, next } => {
                let Some(&(start, end)) = self.groups.get(*group) else { return Ok(false) };
                if start < 0 {
                    return Ok(false);
                }
                let (start, len) = (start as usize, (end - start) as usize);
                if i + len > self.input.len() {
                    return Ok(false);
                }
                let same = (0..len).all(|k| {
                    let (c1, c2) = (self.input[i + k], self.input[start + k]);
                    match ci {
                        None => c1 == c2,
                        Some(unicode) => ci_back_ref_equal(c1, c2, *unicode),
                    }
                });
                if same { self.matches(*next, i + len) } else { Ok(false) }
            }
            Node::Ahead { body, negative, next } => {
                let found = self.matches(*body, i)?;
                if found != *negative { self.matches(*next, i) } else { Ok(false) }
            }
            Node::Behind { body, negative, min, max, next } => {
                let saved = self.behind_to;
                self.behind_to = i;
                let mut found = false;
                if let Some(mut j) = i.checked_sub(*min) {
                    let from = i.saturating_sub(*max);
                    while j >= from {
                        if self.matches(*body, j)? {
                            found = true;
                            break;
                        }
                        if j == 0 {
                            break;
                        }
                        j -= 1;
                    }
                }
                self.behind_to = saved;
                if found != *negative { self.matches(*next, i) } else { Ok(false) }
            }
            Node::Atomic { body, next } => {
                if self.matches(*body, i)? {
                    let j = self.last;
                    self.matches(*next, j)
                } else {
                    Ok(false)
                }
            }
            Node::Possessive { body, min, max, next } => {
                // `Curly.match` then `match2`: each iteration takes its atom's first match, and none is given back.
                let mut i = i;
                let mut j = 0;
                while j < *min {
                    if !self.matches(*body, i)? {
                        return Ok(false);
                    }
                    i = self.last;
                    j += 1;
                }
                while j < *max {
                    if !self.matches(*body, i)? || self.last == i {
                        break;
                    }
                    i = self.last;
                    j += 1;
                }
                self.matches(*next, i)
            }
            Node::Prolog { lp } => self.loop_init(*lp, i),
            Node::Loop { body, min, max, greedy, accept, memo, count: count_at, begin, next } => {
                if *accept {
                    self.last = i;
                }
                if i as i64 <= self.locals[*begin] {
                    return self.matches(*next, i);
                }
                let count = self.locals[*count_at];
                if count < *min as i64 {
                    self.locals[*count_at] = count + 1;
                    let b = self.matches(*body, i)?;
                    if !b {
                        self.locals[*count_at] = count;
                    }
                    return Ok(b);
                }
                if !*greedy {
                    if self.matches(*next, i)? {
                        return Ok(true);
                    }
                    if count < *max as i64 {
                        self.locals[*count_at] = count + 1;
                        let b = self.matches(*body, i)?;
                        if !b {
                            self.locals[*count_at] = count;
                        }
                        return Ok(b);
                    }
                    return Ok(false);
                }
                if count < *max as i64 {
                    if let Some(m) = memo
                        && self.memos[*m].contains(&i)
                    {
                        return self.matches(*next, i);
                    }
                    self.locals[*count_at] = count + 1;
                    if self.matches(*body, i)? {
                        return Ok(true);
                    }
                    self.locals[*count_at] = count;
                    if let Some(m) = memo {
                        self.memos[*m].insert(i);
                    }
                }
                self.matches(*next, i)
            }
        }
    }
    /// `Loop.matchInit` / `LazyLoop.matchInit`.
    fn loop_init(&mut self, lp: usize, i: usize) -> Result<bool, Stop> {
        let Node::Loop { body, min, max, greedy, count, next, .. } = &self.program.nodes[lp] else { unreachable!() };
        let (body, min, max, greedy, count, next) = (*body, *min, *max, *greedy, *count, *next);
        let save = self.locals[count];
        let ret = if 0 < min {
            self.locals[count] = 1;
            self.matches(body, i)
        } else if greedy {
            if 0 < max {
                self.locals[count] = 1;
                match self.matches(body, i) {
                    Ok(false) => self.matches(next, i),
                    other => other,
                }
            } else {
                self.matches(next, i)
            }
        } else {
            match self.matches(next, i) {
                Ok(false) if 0 < max => {
                    self.locals[count] = 1;
                    self.matches(body, i)
                }
                other => other,
            }
        };
        self.locals[count] = save;
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::super::java_pattern::{CASE_INSENSITIVE, DOTALL, UNICODE_CASE};
    use super::*;

    fn replay(pattern: &str, input: &str, millis: u64) -> Option<Outcome> {
        let program = Program::compile(pattern, DOTALL)?;
        program.run(input, Budget::millis(millis))
    }

    #[test]
    fn plain_patterns_are_not_replayed() {
        for p in ["/ok/(v[0-9]+)/.*", "abc", "/users/[0-9]+", "(GET|POST)", "a.*", "\\d{3}-\\d{4}"] {
            assert!(Program::compile(p, DOTALL).is_none(), "{p}");
        }
    }

    #[test]
    fn catastrophic_patterns_time_out_like_java() {
        // Each takes Java (JDK 26, the oracle's) longer than 3 s over these inputs.
        let a38b = format!("/{}b", "a".repeat(38));
        assert_eq!(replay("/(.*a){25}", &a38b, 300), Some(Outcome::TimedOut));
        assert_eq!(replay("/(.*a){12}", &a38b, 300), Some(Outcome::TimedOut));
        assert_eq!(replay("((a+)+)+b", &"a".repeat(30), 300), Some(Outcome::TimedOut));
        assert_eq!(replay("(a+){2,30}b", &"a".repeat(30), 300), Some(Outcome::TimedOut));
    }

    /// A replay Java finishes in a few milliseconds stays finished however late the replay's own clock
    /// runs; one that explodes still times out.
    #[test]
    fn the_step_floor_keeps_short_replays_from_timing_out() {
        let flags = DOTALL | CASE_INSENSITIVE | UNICODE_CASE;
        let late = |millis: u64| Budget { deadline: Instant::now(), floor: millis * JAVA_STEPS_PER_MILLI };
        let z = Program::compile(&format!("/z{}x", "(a|b)*".repeat(9)), flags).unwrap();
        assert_eq!(z.run(&format!("/z{}", "ab".repeat(30)), late(300)), Some(Outcome::Finished(false)));
        let exploding = Program::compile("/(.*a){25}x", flags).unwrap();
        assert_eq!(exploding.run(&format!("/{}b", "a".repeat(38)), late(300)), Some(Outcome::TimedOut));
    }

    #[test]
    fn java_only_syntax_is_replayed_as_pattern_reads_it() {
        // The replay reads java_pattern's tree, not a `regex-syntax` parse of the Java text.
        let a38b = format!("{}b", "a".repeat(38));
        for p in ["([a-z&&[^b]]*a){12}", "(\\h*a|\\p{IsAlphabetic}*a){12}", "\\Q\\E(.*a){12}", "(?<x>.*a){12}"] {
            assert_eq!(replay(p, &a38b, 300), Some(Outcome::TimedOut), "{p}");
        }
        // case folding is Java's, from the flags
        let program = Program::compile("(.*A){12}", DOTALL | CASE_INSENSITIVE | UNICODE_CASE).unwrap();
        assert_eq!(program.run(&a38b, Budget::millis(300)), Some(Outcome::TimedOut));
        assert_eq!(replay("(.*A){12}", &a38b, 2000), Some(Outcome::Finished(false)));
    }

    #[test]
    fn look_arounds_atomic_groups_possessives_and_back_references_are_replayed() {
        // Each takes JDK 25/26 longer than 3 s over these inputs (`matches()`, scenario
        // `w4_java_pattern_timeout_replay`).
        let a38b = format!("/{}b", "a".repeat(38));
        let a40 = format!("/{}", "a".repeat(40));
        let a40b = format!("{a40}b");
        let (q, a) = ("a?".repeat(28), "a".repeat(28));
        for (p, input) in [
            ("/(?=(.*a){25}).*", &a38b),
            ("/(?!(.*a){25}x).*", &a38b),
            (&*format!("/.*(?<={q}{a}c)"), &a40b),
            (&*format!("/.*(?<!{q}{a}c)x"), &a40b),
            ("/(?>(.*a){25}x)", &a38b),
            ("/((.*a){25}x)++", &a38b),
            ("/(a|aa)*\\1c", &a40),
            ("/(a|aa)*c(\\1)?", &a40),
        ] {
            assert_eq!(replay(p, input, 300), Some(Outcome::TimedOut), "{p}");
        }
        // and each of these finishes within milliseconds there
        for (p, input) in [
            ("/(?=(a|aa)*c)", &a40),
            ("/(?>(a|aa)*)c", &a40),
            ("/(a|aa)*+c", &a40),
            ("/(.*a){25}+x", &a38b),
            ("/((.*a){12})++x", &a38b),
            ("/(a|aa)*c", &a40),
            ("/(a*+a|a){30}x", &a40),
        ] {
            assert_eq!(replay(p, input, 2000), Some(Outcome::Finished(false)), "{p}");
        }
    }

    #[test]
    fn new_nodes_agree_with_the_result() {
        assert_eq!(replay("(a|b)*(?=c)c", "abc", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(a|b)*(?!c)c", "abc", 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay("(a|b)*(?<=ab)c", "abc", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(a|b)*(?<!ab)c", "abc", 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay("(?>(a|ab)*)c", "abc", 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay("(?>(a|ab)*)bc", "abc", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(a|b)*+b", "ab", 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay("(a|b)*+", "ab", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(a|bb)*\\1", "abbbb", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(a|bb)*\\1", "abbb", 2000), Some(Outcome::Finished(false)));
        let program = Program::compile("(a|bb)*\\1", DOTALL | CASE_INSENSITIVE | UNICODE_CASE).unwrap();
        assert_eq!(program.run("abbBB", Budget::millis(2000)), Some(Outcome::Finished(true)));
        assert_eq!(replay("(a|bb)*\\z", "abb", 2000), Some(Outcome::Finished(true)));
        // position tests and `\R`
        assert_eq!(replay("(\\w|\\s)*\\bx", "ab x", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(\\w|\\s)*\\bx", "abx", 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay("(a|b)*\\Bc", "abc", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(?m)(a|b)*$\\n^c", "ab\nc", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(a|b)*\\Rc", "ab\r\nc", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(a|b)*\\R\\nc", "ab\r\nc", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(\\b.*a){25}", &"a".repeat(38), 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay(".(\\B.*a){25}", &format!("{}!", "a".repeat(38)), 300), Some(Outcome::TimedOut));
    }

    #[test]
    fn memoised_top_level_loops_finish_like_java() {
        // `Loop.posIndex` keeps these fast on the JVM.
        assert_eq!(replay("(a|aa)*b", &"a".repeat(40), 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay("(a*)*b", &"a".repeat(40), 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay("(x+x+)+y", &"x".repeat(30), 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay("(\\w+\\s?)*$", "an example sentence that is long enough to fail!", 2000), Some(Outcome::Finished(false)));
    }

    #[test]
    fn group_curly_loops_are_not_memoised() {
        // A deterministic body makes each `(ab)*` a `GroupCurly`, without `Loop.posIndex`; nine in a
        // row outlive 300 ms on the JVM over 30 pairs (scenario `w4_java_pattern_timeout_replay_group_curly`).
        let ab = format!("/v{}", "ab".repeat(30));
        assert_eq!(replay(&format!("/v{}x", "(ab)*".repeat(9)), &ab, 300), Some(Outcome::TimedOut));
        assert_eq!(replay(&format!("/v{}x", "(?:a\\d)*".repeat(9)), &format!("/v{}", "a1".repeat(30)), 300), Some(Outcome::TimedOut));
        assert_eq!(replay(&format!("/v{}x", "(a|b)*".repeat(9)), &ab, 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay(&format!("/v{}x", "(ab)*".repeat(9)), &format!("{ab}x"), 2000), Some(Outcome::Finished(true)));
    }

    #[test]
    fn finished_replays_agree_with_the_result() {
        assert_eq!(replay("/(.*a){25}", "/ab", 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay("/(.*a){2}", "/xaya", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(ab|a)*c", "ababac", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(a+?){2,}b", "aaab", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(ab)?(cd)?.*x$", "cdzx", 2000), Some(Outcome::Finished(true)));
        // `$` may stand before a final line terminator, but `matches()` must still consume it.
        assert_eq!(replay("(ab)?(cd)?.*x$", "cdzx\n", 2000), Some(Outcome::Finished(false)));
    }

    fn replay_find(pattern: &str, input: &str, dotall: bool, millis: u64) -> Option<Outcome> {
        let program = Program::compile(pattern, if dotall { DOTALL } else { 0 })?;
        program.run_find(input, Budget::millis(millis))
    }

    #[test]
    fn find_tries_each_start_position() {
        // `(.*a){12}x` explodes at the first start position before the `c` alternative is tried.
        assert_eq!(replay_find("(.*a){12}x|c", &format!("{}c", "a".repeat(38)), true, 300), Some(Outcome::TimedOut));
        assert_eq!(replay_find("(.*a){12}x|c", "ac", true, 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay_find("(ab|a)*c", "zzababc", true, 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(ab|a)*c", "zzababc", 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay_find("(ab|a)*c", "zzabab", true, 2000), Some(Outcome::Finished(false)));
        // a match may end before the input does
        assert_eq!(replay_find("(ab|a)*c", "abcz", true, 2000), Some(Outcome::Finished(true)));
        // rooted at `Begin`: only the first start position
        assert_eq!(replay_find("^(ab|a)*c", "zabc", true, 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay_find("(.*a){2}", "a", true, 2000), Some(Outcome::Finished(false)));
    }

    #[test]
    fn without_dotall_dot_stops_at_line_terminators() {
        assert_eq!(replay_find("(.*a){2}", "a\na", true, 2000), Some(Outcome::Finished(true)));
        for terminator in ["\n", "\r", "\u{85}", "\u{2028}", "\u{2029}"] {
            assert_eq!(replay_find("(.*a){2}", &format!("a{terminator}a"), false, 2000), Some(Outcome::Finished(false)), "{terminator:?}");
        }
        assert_eq!(replay_find("(.*a){2}", "xaya", false, 2000), Some(Outcome::Finished(true)));
        // an escaped dot and a dot in a class stay literal
        assert_eq!(replay_find("(\\..*a){2}", ".a.a", false, 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay_find("([.]*a){2}", "\na.a", false, 2000), Some(Outcome::Finished(true)));
    }

    #[test]
    fn grapheme_nodes_are_replayed() {
        // Each takes JDK 26 longer than 300 ms (scenario `w4_java_pattern_timeout_replay_grapheme`).
        let a38b = format!("/{}b", "a".repeat(38));
        for p in ["/(\\X*a){25}", "/(?c)([a-z]*a){25}", "/(\\b{g}.*a){25}", &format!("/{}b", "\\X*".repeat(9))] {
            assert_eq!(replay(p, &a38b[..if p.ends_with('b') { 39 } else { 40 }], 300), Some(Outcome::TimedOut), "{p}");
        }
        // the look-ahead's accept leaves `Matcher.last` after the first `a`: `\b{g}` fails at once
        assert_eq!(replay("/(?=\\X)(\\b{g}.*a){25}", &a38b, 2000), Some(Outcome::Finished(false)));
    }

    #[test]
    fn grapheme_nodes_agree_with_the_result() {
        // `\X` takes a whole cluster: `e` and a combining acute are one.
        assert_eq!(replay("(\\X*a){2}", "xe\u{301}aya", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(\\X\\X|a)*", "e\u{301}a", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(\\X\\X|a)*", "e\u{301}ab", 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay("(\\X?\\X?)*b", "e\u{301}\u{1F1EF}\u{1F1F5}b", 2000), Some(Outcome::Finished(true)));
        // a lazy and a possessive `Curly` over `\X`
        assert_eq!(replay("(\\X*?a){2}", "xaya", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(\\X*+a){2}", "xaya", 2000), Some(Outcome::Finished(false)));
        // `(?c)`: the cluster `e` + U+0301 is `é` in NFC; a `Curly` atom takes the first (longest) reading only
        assert_eq!(replay("(?c)([\\u00e9]*x)+", "e\u{301}x", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(?c)([e]*x)+", "e\u{301}x", 2000), Some(Outcome::Finished(false)));
        assert_eq!(replay("(?c)(x[e]\u{301}|y)+", "xe\u{301}xe\u{301}", 2000), Some(Outcome::Finished(true)));
        // `\b{g}` holds between clusters only, from where `Matcher.last` was written
        assert_eq!(replay("(.\\b{g}.*)*", "ab", 2000), Some(Outcome::Finished(true)));
        assert_eq!(replay("(e\\b{g}.*)*", "e\u{301}", 2000), Some(Outcome::Finished(false)));
        // `Matcher.last` at the end: `Grapheme.nextBoundary` throws, and the search ends
        assert_eq!(replay("(?=.*)(a|b)*\\b{g}c", "abc", 2000), Some(Outcome::Finished(false)));
    }

    #[test]
    fn deep_replays_move_to_a_large_stack() {
        let long = "ab".repeat(20_000);
        assert_eq!(replay("(ab|cd)*.*", &long, 5000), Some(Outcome::Finished(true)));
    }

    #[test]
    fn a_deep_replay_takes_a_bounded_part_of_the_callers_stack() {
        // half a test or tokio worker thread's 2 MiB: what a replay takes of it must not depend on how large the
        // architecture's or build's frames are (1,500 levels took 1.9 MiB in an aarch64 debug build)
        let long = "ab".repeat(20_000);
        let outcome = std::thread::Builder::new()
            .stack_size(1 << 20)
            .spawn(move || replay("(ab|cd)*.*", &long, 5000))
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(outcome, Some(Outcome::Finished(true)));
    }

}

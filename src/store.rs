//! Active expectations in match order (§3.1): priority descending, then creation ascending. Upserts keep the
//! original creation position. Exhausted and expired expectations stay stored (evaluated as not matching) until a
//! scan drops them, or, while a request they serve is in flight, until that request is post-processed.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use serde_json::Value;

use crate::action::Action;
use crate::matcher::{Mode, RequestMatcher};
use crate::request::HttpRequest;
use crate::state::cluster::{ClusterLink, Consumed};
use crate::state_backend::{ExpectationEntry, StateError};

pub struct Expectation {
    pub id: String,
    pub priority: i64,
    created: u64,
    /// The form echoed by the control plane.
    pub canonical: Value,
    /// The JSON as given, in its own key order (what upstream's model keeps; the Java code format reads it).
    pub input: Value,
    /// The canonical form with default values written out (the other code formats embed it).
    pub default_values: Value,
    pub matcher: RequestMatcher,
    pub action: Action,
    /// `-1` means unlimited.
    remaining: AtomicI64,
    /// `TimeToLive.endDate` (epoch millis on the server's clock), fixed when the expectation is built; `None` for an
    /// unlimited time to live.
    end_date: Option<i64>,
    index_key: Option<String>,
    /// The expectation's `chaos` (`HttpChaosProfile`).
    pub chaos: Option<crate::chaos::HttpChaosProfile>,
    /// `matchCount`: how many requests it has served.
    matches: std::sync::atomic::AtomicU32,
    /// `rotationCount`: matches that advanced `httpResponses` (a forced response index does not).
    rotation: std::sync::atomic::AtomicU32,
    /// `chaosFirstMatchEpochMillis`: when it first served one (0 before), anchoring chaos outage windows.
    first_match: AtomicI64,
    /// The trimmed, non-blank `namespace`; `None` for a global expectation.
    pub namespace: Option<String>,
    /// The DNS request definition's matcher, when `httpRequest` is one.
    pub dns: Option<crate::dns::DnsMatcher>,
    /// `responseInProgress`: set when a request is served by it, cleared by [`Store::post_process`]. A used-up
    /// expectation stays stored (and evaluated) while it is set. Shared with the expectation a local update replaces
    /// this one with (upstream's flag lives on the matcher, which an update keeps).
    in_progress: Arc<std::sync::atomic::AtomicBool>,
    /// `estimatedHeapSize()`: its weight against `maxExpectationsSizeInBytes`, fixed when it is built.
    weight: u64,
    /// `httpRequest.respondBeforeBody` is `true`: read from `input` once, when the expectation is built.
    early: bool,
    /// [`crate::canonical::empty_response_body`] of the `httpResponse` as given, worked out when first served.
    empty_response_body: std::sync::OnceLock<Option<Value>>,
    /// The canonical `httpResponse`, shared with the log entries of the requests it serves; made when first served.
    served_response: std::sync::OnceLock<Option<Arc<Value>>>,
    /// Which of the rarely given fields ([`Rare`]) it has, worked out when first asked: each is looked up in its JSON
    /// by a SipHash of the key, and a request asked for a dozen of them.
    rare: std::sync::OnceLock<u16>,
}

/// The rarely given fields of an expectation a served request asks about ([`Expectation::has`]).
#[derive(Clone, Copy)]
#[repr(u16)]
pub enum Rare {
    /// `scenarioName`
    Scenario = 1,
    /// a non-empty `crossProtocolScenarios`
    CrossProtocol = 2,
    /// what [`crate::side_actions::any`] runs
    SideActions = 4,
    /// `rateLimit`
    RateLimit = 8,
    /// `percentage`
    Percentage = 16,
    /// `httpLlmResponse`
    Llm = 32,
    /// `capture`
    Capture = 64,
    /// `httpResponse.recoverAfter`
    RecoverAfter = 128,
}

impl Expectation {
    /// The `httpRequest` as a request matcher: its canonical form, except that a binary definition keeps its
    /// `binaryData` even when empty (the echo leaves an empty one out), so it stays a binary definition.
    pub fn request_definition(&self) -> Value {
        match self.input.get("httpRequest").filter(|r| crate::canonical::is_binary_request(r)) {
            Some(binary) => crate::canonical::request_definition(binary),
            None => self.canonical.get("httpRequest").cloned().unwrap_or_else(|| Value::Object(Default::default())),
        }
    }

    pub fn new(id: String, priority: i64, canonical: Value, default_values: Value, input: Value, matcher: RequestMatcher, action: Action) -> Expectation {
        let remaining = match canonical["times"].get("remainingTimes").and_then(Value::as_i64) {
            Some(n) => n.max(0),
            None => -1,
        };
        // `TimeToLiveDTO.buildObject`: an `endDate` given with the TTL (epoch millis, as a serialised expectation
        // carries it) replaces `now + timeToLive`, so an expectation whose end date has passed arrives expired.
        let end_date = input["timeToLive"].get("endDate").and_then(Value::as_i64);
        // `TimeService.currentTimeMillis() + timeUnit.toMillis(timeToLive)`, wrapping as a Java `long` does.
        let end_millis = ttl(&canonical["timeToLive"]).map(|d| end_date.unwrap_or_else(|| crate::clock::now_millis().wrapping_add(i64::try_from(d.as_millis()).unwrap_or(i64::MAX))));
        let index_key = matcher.index_key();
        let chaos = input.get("chaos").filter(|c| !c.is_null()).and_then(|c| <crate::chaos::HttpChaosProfile as crate::chaos::HostProfile>::from_json(c).ok());
        let namespace = canonical.get("namespace").and_then(Value::as_str).map(str::to_string);
        let dns = crate::dns::DnsMatcher::compile(&canonical["httpRequest"]);
        let weight = heap_size::estimate(&input, &canonical, dns.is_some());
        let early = input.pointer("/httpRequest/respondBeforeBody").and_then(Value::as_bool) == Some(true);
        Expectation {
            weight,
            early,
            namespace,
            dns,
            id,
            priority,
            created: 0,
            canonical,
            default_values,
            input,
            matcher,
            action,
            remaining: AtomicI64::new(remaining),
            end_date: end_millis,
            index_key,
            chaos,
            matches: Default::default(),
            first_match: AtomicI64::new(0),
            rotation: Default::default(),
            in_progress: Default::default(),
            empty_response_body: Default::default(),
            served_response: Default::default(),
            rare: Default::default(),
        }
    }

    /// Whether it has the field `rare` stands for; `false` rules out what the field would do.
    pub fn has(&self, rare: Rare) -> bool {
        let fields = *self.rare.get_or_init(|| {
            let input = &self.input;
            let present = |key: &str| input.get(key).is_some_and(|v| !v.is_null());
            [
                (present("scenarioName"), Rare::Scenario),
                (input.get("crossProtocolScenarios").and_then(Value::as_array).is_some_and(|a| !a.is_empty()), Rare::CrossProtocol),
                (crate::side_actions::any(input), Rare::SideActions),
                (present("rateLimit"), Rare::RateLimit),
                (present("percentage"), Rare::Percentage),
                (present("httpLlmResponse"), Rare::Llm),
                (present("capture"), Rare::Capture),
                (self.canonical.get("httpResponse").and_then(|r| r.get("recoverAfter")).is_some(), Rare::RecoverAfter),
            ]
            .iter()
            .filter(|(has, _)| *has)
            .fold(0, |fields, (_, rare)| fields | *rare as u16)
        });
        fields & rare as u16 != 0
    }

    /// The canonical `httpResponse` as the entries of the requests it serves hold it: one copy for all of them.
    pub fn served_response(&self) -> Option<&Arc<Value>> {
        self.served_response.get_or_init(|| self.canonical.get("httpResponse").map(|r| Arc::new(r.clone()))).as_ref()
    }

    /// The body a `returning response` entry prints for its `httpResponse` (as given) whose echo leaves an empty body
    /// out ([`crate::canonical::empty_response_body`]); it depends on the expectation alone, so it is worked out once.
    pub fn empty_response_body(&self) -> Option<&Value> {
        self.empty_response_body.get_or_init(|| self.input.get("httpResponse").and_then(crate::canonical::empty_response_body)).as_ref()
    }

    /// `matchesByPercentage`: `percentage` of matches are served (all when absent or 100, none at 0).
    fn by_percentage(&self) -> bool {
        if !self.has(Rare::Percentage) {
            return true;
        }
        match self.input.get("percentage").and_then(Value::as_i64) {
            None | Some(100) => true,
            Some(0) => false,
            Some(p) => {
                use rand_core::RngCore;
                ((rand_core::OsRng.next_u32() % 100) as i64) < p
            }
        }
    }

    /// `recordMatch`'s rotation: the 1-based rotation this match takes; a forced response index serves without
    /// advancing it.
    fn rotate(&self, request: &HttpRequest) -> u32 {
        let forced = crate::action::forced_response_index(request);
        let count = match &self.action {
            Action::Responses(r) => r.responses.len() as i64,
            _ => 0,
        };
        if forced.is_some_and(|f| f >= 0 && f < count) {
            self.rotation.load(Ordering::Acquire)
        } else {
            self.rotation.fetch_add(1, Ordering::AcqRel) + 1
        }
    }

    /// Counts a served request; its 1-based number.
    fn record_match(&self) -> u32 {
        // set once: read first, so that later matches do not write the expectation's line with a locked compare
        if self.first_match.load(Ordering::Acquire) == 0 {
            let _ = self.first_match.compare_exchange(0, crate::clock::now_millis(), Ordering::AcqRel, Ordering::Acquire);
        }
        self.matches.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// `HttpActionHandler.effectiveChaos`: the expectation's chaos as it applies now.
    pub fn effective_chaos(&self) -> Option<crate::chaos::HttpChaosProfile> {
        self.chaos.as_ref()?.effective(self.first_match.load(Ordering::Acquire))
    }

    /// `getMatchCount()`: how many requests it has served.
    pub fn match_count(&self) -> u32 {
        self.matches.load(Ordering::Acquire)
    }

    /// `isActive`: uses left and not expired.
    pub fn is_active(&self) -> bool {
        self.alive(crate::clock::now_millis())
    }

    /// `TimeToLiveDTO`'s `endDate` for a finite time to live: epoch millis of the expiry, as a persisted file carries it.
    pub fn end_date_millis(&self) -> Option<i64> {
        self.end_date
    }

    /// `now`: epoch millis on the server's clock (`TimeToLive.stillAlive`: the end date is after now).
    fn alive(&self, now: i64) -> bool {
        self.remaining.load(Ordering::Acquire) != 0 && self.end_date.is_none_or(|e| e > now)
    }

    /// [`Expectation::alive`] at `now` on the server's clock, for diagnostics that read without consuming.
    pub fn alive_at(&self, now: i64) -> bool {
        self.alive(now)
    }

    /// Still stored: live, or serving a request (`isResponseInProgress() || isActive()`).
    fn retained(&self, now: i64) -> bool {
        self.alive(now) || self.in_progress.load(Ordering::Acquire)
    }

    /// Takes one use; `false` when another request used the last one first.
    fn consume(&self) -> bool {
        let mut current = self.remaining.load(Ordering::Acquire);
        loop {
            if current < 0 {
                return true;
            }
            if current == 0 {
                return false;
            }
            match self.remaining.compare_exchange_weak(current, current - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Lowers the remaining count to `to` (a shared counter moved on); an unlimited expectation stays so.
    fn lower_remaining(&self, to: i64) {
        let mut current = self.remaining.load(Ordering::Acquire);
        while current > to && current >= 0 {
            match self.remaining.compare_exchange_weak(current, to, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    /// The JSON `ExpectationEntry` carries: the expectation as given, with its id, and the absolute end of a finite
    /// time to live so that another node expires it at the same instant.
    fn backend_json(&self) -> Value {
        let mut json = self.input.clone();
        json["id"] = Value::String(self.id.clone());
        if let (Some(end), Some(ttl)) = (self.end_date_millis(), json.get_mut("timeToLive").and_then(Value::as_object_mut)) {
            ttl.insert("endDate".to_string(), Value::from(end));
        }
        json
    }

    /// `new ExpectationEntry(expectation)`: the sort fields, the shared remaining-times counter (`-1` unlimited) and
    /// the expectation's JSON.
    fn entry(&self) -> ExpectationEntry {
        ExpectationEntry { id: self.id.clone(), priority: self.priority, created: self.created, remaining_times: self.remaining.load(Ordering::Acquire), expectation_json: self.backend_json() }
    }

    /// The runtime state of the expectation this one replaces on a remote update: matches, rotation, first match and
    /// whether it is serving a request (`update(expectation)` keeps `Times` and `responseInProgress`).
    fn adopt_runtime(&self, old: &Expectation) {
        self.matches.store(old.matches.load(Ordering::Acquire), Ordering::Release);
        self.rotation.store(old.rotation.load(Ordering::Acquire), Ordering::Release);
        self.first_match.store(old.first_match.load(Ordering::Acquire), Ordering::Release);
        self.in_progress.store(old.in_progress.load(Ordering::Acquire), Ordering::Release);
    }

    /// `Expectation.equals` between this stored expectation and `new` with the same id: every field but `id`,
    /// `created` and `rateLimit` (which its `equals` leaves out), `TimeToLive` without its end date. `equals` first
    /// compares the hash codes, which `Expectation` and `Times` cache before the first match, so a stored expectation
    /// that has served a request is never equal to a new one (its cached hash keeps the original count, its `Times`
    /// the current one). `httpRequestMatcher.update` keeps the stored expectation when they are equal: nothing is
    /// replaced or logged, so a changed `rateLimit` alone does not take effect.
    pub fn upstream_equals(&self, new: &Expectation) -> bool {
        let strip = |mut v: Value| {
            if let Some(o) = v.as_object_mut() {
                o.remove("id");
                o.remove("rateLimit");
            }
            v
        };
        self.current() == self.canonical && strip(self.canonical.clone()) == strip(new.canonical.clone())
    }

    /// The canonical form with the current remaining count, as `retrieve` reports it.
    pub fn current(&self) -> Value {
        self.with_remaining(&self.canonical)
    }

    /// [`Expectation::current`] with default values written out.
    pub fn current_default_values(&self) -> Value {
        self.with_remaining(&self.default_values)
    }

    /// The remaining count [`Expectation::current`] shows (negative: unlimited, the canonical `times` shown).
    pub fn remaining_now(&self) -> i64 {
        self.remaining.load(Ordering::Acquire)
    }

    /// [`Expectation::current`] as it is with `remaining` as its count.
    pub fn current_at(&self, remaining: i64) -> Value {
        Self::with_remaining_at(&self.canonical, remaining)
    }

    fn with_remaining(&self, v: &Value) -> Value {
        Self::with_remaining_at(v, self.remaining.load(Ordering::Acquire))
    }

    fn with_remaining_at(v: &Value, remaining: i64) -> Value {
        let mut v = v.clone();
        if remaining >= 0 {
            v["times"] = serde_json::json!({"remainingTimes": remaining});
        }
        v
    }
}

fn ttl(v: &Value) -> Option<Duration> {
    let amount = v.get("timeToLive")?.as_u64()?;
    let unit = v.get("timeUnit").and_then(Value::as_str).unwrap_or("SECONDS");
    Some(match unit {
        "DAYS" => Duration::from_secs(amount * 86_400),
        "HOURS" => Duration::from_secs(amount * 3_600),
        "MINUTES" => Duration::from_secs(amount * 60),
        "MILLISECONDS" => Duration::from_millis(amount),
        "MICROSECONDS" => Duration::from_micros(amount),
        "NANOSECONDS" => Duration::from_nanos(amount),
        _ => Duration::from_secs(amount),
    })
}

/// The one namespace gate (`RequestMatchers.matchesNamespace`) every gated scan goes through: the expectations of
/// `candidates` that a request of namespace `namespace` may see (global ones, and its own).
fn admissible<'a>(candidates: impl Iterator<Item = &'a Arc<Expectation>>, namespace: Option<&'a str>) -> impl Iterator<Item = &'a Arc<Expectation>> {
    candidates.filter(move |e| crate::namespace::admits(e.namespace.as_deref(), namespace))
}

/// Below this many expectations every one is evaluated (and logged as matched or not), as upstream's
/// `DEFAULT_CANDIDATE_INDEX_THRESHOLD`; from it on the path index narrows the scan.
const CANDIDATE_INDEX_THRESHOLD: usize = 64;

/// Expectations in match order plus a path index: literal-path expectations are found by lower-cased path, the
/// rest are always candidates. Candidates are visited in global match order, so results equal a full scan
/// (MockServer does the same from `candidateIndexThreshold` on).
/// The list is copy-on-write: a [`Candidates`] snapshot shares it, and a change while one is held
/// copies it.
#[derive(Default)]
struct Inner {
    list: Arc<Vec<Arc<Expectation>>>,
    /// Rebuilt whole by every [`Inner::reindex`], so a scan shares it as it shares `list`.
    index: Arc<PathIndex>,
    /// How many of `list` carry `respondBeforeBody: true`, recounted by every [`Inner::reindex`], which
    /// every change to the list ends with.
    early: usize,
}

/// Some of the stored expectations in match order, over a snapshot of the store's list taken at once (one reference
/// count, however many expectations): a scan of them clones none and holds no lock of the store, so a matcher that
/// takes seconds (a WASM module, a regex up to its timeout) delays neither readers nor writers.
pub struct Candidates {
    list: Arc<Vec<Arc<Expectation>>>,
    /// The path index taken with `list`.
    index: Arc<PathIndex>,
    /// The positions in `list`; `None`: every one, in order, without a list of them built.
    positions: Option<Vec<u32>>,
}

impl Candidates {
    pub fn len(&self) -> usize {
        self.positions.as_ref().map_or(self.list.len(), Vec::len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn position(&self, i: usize) -> usize {
        self.positions.as_ref().map_or(i, |p| p[i] as usize)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<Expectation>> + Clone {
        (0..self.len()).map(|i| &self.list[self.position(i)])
    }

    /// The `i`th of these.
    pub fn get(&self, i: usize) -> &Arc<Expectation> {
        &self.list[self.position(i)]
    }

    /// Each of these with whether it fails at its literal path for a request of `path`, known from the path index
    /// alone ([`crate::matcher::RequestMatcher::fails_by_literal_path`]): such a one cannot match, has at least one
    /// difference, and evaluating it meets no regex timeout.
    pub fn iter_with_path_misses(&self, path: &str) -> impl Iterator<Item = (&Arc<Expectation>, bool)> + Clone {
        // an empty path matches any path matcher, and an index out of step with the list decides nothing
        let usable = !path.is_empty() && self.index.classes.len() == self.list.len();
        let own = if usable { self.index.class_of(path) } else { NO_CLASS };
        let classes = if usable { self.index.classes.as_slice() } else { &[] };
        (0..self.len()).map(move |i| {
            let at = self.position(i);
            let class = classes.get(at).copied().unwrap_or(NO_CLASS);
            (&self.list[at], class != NO_CLASS && class != own)
        })
    }

    /// [`Candidates::iter_with_path_misses`] by position, able to skip what fails at its literal path in one scan.
    pub fn path_misses(&self, path: &str) -> PathMisses<'_> {
        let usable = !path.is_empty() && self.index.classes.len() == self.list.len() && self.index.unclassed.len() <= self.list.len();
        let bucket = if usable { self.index.bucket_of(path) } else { &[] };
        let own = if !usable { NO_CLASS } else { bucket.first().map_or(NO_CLASS - 1, |&first| first as u32) };
        PathMisses { candidates: self, classes: if usable { self.index.classes.as_slice() } else { &[] }, own, bucket, unclassed: &self.index.unclassed }
    }

    /// The first `n` of these, and whether any were left out.
    pub fn first(&self, n: usize) -> (Candidates, bool) {
        let positions = match &self.positions {
            None if self.list.len() <= n => None,
            None => Some((0..n as u32).collect()),
            Some(p) => Some(p.iter().take(n).copied().collect()),
        };
        (Candidates { list: self.list.clone(), index: self.index.clone(), positions }, self.len() > n)
    }

    /// Whether `other` goes through the same expectations in the same order.
    pub fn same(&self, other: &Candidates) -> bool {
        if self.len() != other.len() {
            return false;
        }
        if Arc::ptr_eq(&self.list, &other.list) {
            return match (&self.positions, &other.positions) {
                (None, None) => true,
                (Some(a), Some(b)) => a == b,
                _ => (0..self.len()).all(|i| self.position(i) == other.position(i)),
            };
        }
        self.iter().zip(other.iter()).all(|(a, b)| Arc::ptr_eq(a, b))
    }
}

/// [`PathIndex::classes`] of an expectation its literal path does not decide.
const NO_CLASS: u32 = u32::MAX;

/// Which of some [`Candidates`] fail at their literal path for one request path ([`Candidates::path_misses`]).
pub struct PathMisses<'a> {
    candidates: &'a Candidates,
    /// Empty when the index decides nothing.
    classes: &'a [u32],
    own: u32,
    /// The positions of the request path's own expectations, and those of no class ([`PathIndex::unclassed`]).
    bucket: &'a [usize],
    unclassed: &'a [u32],
}

impl PathMisses<'_> {
    fn kept(&self, class: u32) -> bool {
        class == NO_CLASS || class == self.own
    }

    /// Whether the `i`th candidate fails at its literal path.
    pub fn misses(&self, i: usize) -> bool {
        self.classes.get(self.candidates.position(i)).is_some_and(|&class| !self.kept(class))
    }

    /// The first candidate from the `from`th on that does not fail at its literal path, or the count of them: a scan
    /// of the index alone, for an unmatched request among many expectations of other paths.
    pub fn next_kept(&self, from: usize) -> usize {
        let len = self.candidates.len();
        if self.classes.is_empty() || from >= len {
            return from;
        }
        match &self.candidates.positions {
            // every position: the next of no class or of the path's own, found in those lists rather than by a walk
            None => {
                let unclassed = self.unclassed.get(self.unclassed.partition_point(|&at| (at as usize) < from)).map_or(len, |&at| at as usize);
                let own = self.bucket[self.bucket.partition_point(|&at| at < from)..].iter().copied().find(|&at| self.classes[at] == self.own).unwrap_or(len);
                unclassed.min(own).min(len)
            }
            Some(positions) => positions[from..].iter().position(|&at| self.kept(self.classes[at as usize])).map_or(len, |n| from + n),
        }
    }
}

/// The positions in a store's list by lower-cased literal path, and those of the expectations without one.
#[derive(Default)]
struct PathIndex {
    by_path: rustc_hash::FxHashMap<String, Vec<usize>>,
    unindexed: Vec<usize>,
    /// Per position: for an expectation whose literal path alone fails a request of another path, the first position
    /// of that path's expectations (its class); else [`NO_CLASS`].
    classes: Vec<u32>,
    /// Per position: for a global expectation with unlimited uses (which stays so), the instant it expires
    /// (`i64::MAX`: never); else [`MORTAL`]. Telling which are alive without reading each expectation was most of a
    /// 1,000-expectation closest-match scan.
    deadlines: Vec<i64>,
    /// The positions whose class is [`NO_CLASS`], in order: with a request path's own bucket in `by_path`, the only
    /// ones a scan past the expectations its path rules out has to visit.
    unclassed: Vec<u32>,
    /// Whether any of `deadlines` is [`MORTAL`], and the earliest of the others: while none is mortal and that one
    /// is ahead, every expectation is alive without looking at each.
    any_mortal: bool,
    earliest_deadline: i64,
}

/// [`PathIndex::deadlines`] of an expectation whose uses are counted or that has a namespace: read from it.
const MORTAL: i64 = i64::MIN;

impl PathIndex {
    /// The class of a request of `path`: that of the expectations with `path` as their literal path, else none of theirs.
    fn class_of(&self, path: &str) -> u32 {
        self.bucket_of(path).first().map_or(NO_CLASS - 1, |&first| first as u32)
    }

    /// The positions of the expectations with `path` as their literal path, in order.
    fn bucket_of(&self, path: &str) -> &[usize] {
        // the keys are lower-cased; a path that already is one is looked up as it is
        let key = if path.bytes().any(|b| b.is_ascii_uppercase()) { std::borrow::Cow::Owned(path.to_ascii_lowercase()) } else { std::borrow::Cow::Borrowed(path) };
        self.by_path.get(key.as_ref()).map_or(&[], Vec::as_slice)
    }
}

/// The list and its path index as a scan goes through them: two reference counts, no lock of the store held.
struct View {
    list: Arc<Vec<Arc<Expectation>>>,
    index: Arc<PathIndex>,
}

impl View {
    /// The expectations that could match `path`, in match order.
    fn candidates(&self, path: &str) -> impl Iterator<Item = &Arc<Expectation>> {
        let everything = path.is_empty() || self.list.len() < CANDIDATE_INDEX_THRESHOLD;
        let indexed: &[usize] = if everything {
            &[]
        } else {
            // the index keys are lower-cased; a path that already is one is looked up as it is
            let key = if path.bytes().any(|b| b.is_ascii_uppercase()) { std::borrow::Cow::Owned(path.to_ascii_lowercase()) } else { std::borrow::Cow::Borrowed(path) };
            self.index.by_path.get(key.as_ref()).map(Vec::as_slice).unwrap_or(&[])
        };
        let (mut a, mut b) = (0, 0);
        let unindexed = &self.index.unindexed;
        let mut next_all = 0;
        std::iter::from_fn(move || {
            if everything {
                let e = self.list.get(next_all);
                next_all += 1;
                return e;
            }
            let i = match (indexed.get(a), unindexed.get(b)) {
                (Some(x), Some(y)) if x < y => {
                    a += 1;
                    *x
                }
                (_, Some(y)) => {
                    b += 1;
                    *y
                }
                (Some(x), None) => {
                    a += 1;
                    *x
                }
                (None, None) => return None,
            };
            self.list.get(i)
        })
    }
}

impl Inner {
    /// What a scan goes through, held without this store's lock.
    fn shared(&self) -> View {
        View { list: self.list.clone(), index: self.index.clone() }
    }

    fn list_mut(&mut self) -> &mut Vec<Arc<Expectation>> {
        Arc::make_mut(&mut self.list)
    }

    /// The expectations alive at `now` a request of `namespace` may see (`None`: every one alive): [`Expectation::alive`]
    /// and the namespace gate, read from the index for the global unlimited ones.
    fn live_candidates(&self, namespace: Option<Option<&str>>, now: i64) -> Candidates {
        let deadlines = Some(self.index.deadlines.as_slice()).filter(|d| d.len() == self.list.len()).unwrap_or(&[]);
        // every one alive, told by the index alone
        if !deadlines.is_empty() && !self.index.any_mortal && self.index.earliest_deadline > now {
            return Candidates { list: self.list.clone(), index: self.index.clone(), positions: None };
        }
        let keep = |i: usize| match deadlines.get(i) {
            Some(&deadline) if deadline != MORTAL => deadline > now,
            _ => {
                let e = &self.list[i];
                namespace.is_none_or(|namespace| crate::namespace::admits(e.namespace.as_deref(), namespace)) && e.alive(now)
            }
        };
        let positions = (0..self.list.len()).position(|i| !keep(i)).map(|first| {
            let mut positions = Vec::with_capacity(self.list.len() - 1);
            positions.extend(0..first as u32);
            positions.extend((first as u32 + 1..self.list.len() as u32).filter(|&i| keep(i as usize)));
            positions
        });
        Candidates { list: self.list.clone(), index: self.index.clone(), positions }
    }

    fn reindex(&mut self) {
        self.list_mut().sort_by(|a, b| b.priority.cmp(&a.priority).then(a.created.cmp(&b.created)).then_with(|| a.id.cmp(&b.id)));
        self.early = self.list.iter().filter(|e| e.early).count();
        let mut index = PathIndex {
            classes: Vec::with_capacity(self.list.len()),
            deadlines: Vec::with_capacity(self.list.len()),
            earliest_deadline: i64::MAX,
            ..PathIndex::default()
        };
        for (i, e) in self.list.iter().enumerate() {
            // an unlimited count is never lowered (`lower_remaining`, `consume`)
            let unlimited = e.remaining.load(Ordering::Acquire) < 0 && e.namespace.is_none();
            let deadline = if unlimited { e.end_date.unwrap_or(i64::MAX) } else { MORTAL };
            index.deadlines.push(deadline);
            if deadline == MORTAL {
                index.any_mortal = true;
            } else {
                index.earliest_deadline = index.earliest_deadline.min(deadline);
            }
            match &e.index_key {
                Some(key) => {
                    let bucket = index.by_path.entry(key.clone()).or_default();
                    bucket.push(i);
                    index.classes.push(if e.matcher.fails_by_literal_path() { bucket[0] as u32 } else { NO_CLASS });
                }
                None => {
                    index.unindexed.push(i);
                    index.classes.push(NO_CLASS);
                }
            }
            if index.classes.last() == Some(&NO_CLASS) {
                index.unclassed.push(i as u32);
            }
        }
        self.index = Arc::new(index);
    }
}

/// One expectation [`Store::first_dns_match`] evaluated: DNS ones are logged, and every unmatched one competes for
/// the closest match by its recorded differences (none for a non-DNS matcher, which rejects a DNS query outright).
pub struct DnsEvaluated {
    pub expectation: Arc<Expectation>,
    pub snapshot: Value,
    pub matched: bool,
    pub dns: bool,
    pub differences: usize,
    /// Neither used up nor expired: only an active one can be the closest match (upstream 65a116781).
    pub active: bool,
}

/// The expectation a request matched: its match number and its `httpResponses` rotation.
pub struct Found {
    pub expectation: Arc<Expectation>,
    pub match_count: u32,
    pub rotation: u32,
}

/// One expectation [`Store::first_match_traced`] evaluated: its state at the time and the result.
pub struct Evaluated {
    pub expectation: Arc<Expectation>,
    /// The remaining count when it was evaluated, which with the expectation's unchanging canonical form makes
    /// [`Expectation::current`] as it was then ([`Evaluated::snapshot`]); `None` when not taken (the unmatched
    /// request's closest-match walk), and then read from the expectation when it is logged.
    pub remaining: Option<i64>,
    pub matched: bool,
    /// `false` for a used-up or expired expectation still stored: its matcher rejects the request before looking
    /// at it (`isActive()`), so there are no reasons.
    pub active: bool,
    /// A WARN the commit of this matched expectation logged, right after its matched entry: its clustered
    /// shared-`Times` counter was evicted (`warnIfCounterEvictedWhileLive`).
    pub warning: Option<String>,
}

impl Evaluated {
    /// The remaining count its snapshot shows: as evaluated, or the expectation's own now when none was taken.
    pub fn snapshot_remaining(&self) -> i64 {
        self.remaining.unwrap_or_else(|| self.expectation.remaining_now())
    }

    /// [`Expectation::current`] as it was when evaluated (or now, when not taken).
    pub fn snapshot(&self) -> Value {
        self.expectation.current_at(self.snapshot_remaining())
    }
}

/// `RequestMatchers.update`'s distinct-by-id batch (upstream #106, 33cdd577e): one entry per id, the last one given,
/// in the place of the first (so it is served from there, with the first entry's creation time).
pub fn distinct_by_id(expectations: Vec<Expectation>) -> Vec<Expectation> {
    let mut places: HashMap<String, usize> = HashMap::new();
    let mut distinct: Vec<Expectation> = Vec::with_capacity(expectations.len());
    for e in expectations {
        match places.get(&e.id) {
            Some(&i) => distinct[i] = e,
            None => {
                places.insert(e.id.clone(), distinct.len());
                distinct.push(e);
            }
        }
    }
    distinct
}

/// Tests only: the work run at a [`Pause`] point.
#[cfg(test)]
type PauseWork = Box<dyn FnOnce() + Send>;

#[derive(Default)]
pub struct Store {
    /// The initialisation file each file-loaded expectation came from (`HttpRequestMatcher.getSource()`); API
    /// expectations have none.
    sources: RwLock<HashMap<String, String>>,
    inner: RwLock<Inner>,
    next_created: AtomicU64,
    /// `maxExpectations` (`InMemoryExpectationKeyValueStore`): the oldest expectation by insertion is
    /// evicted when an add takes the store over it; `0` is unbounded. Not applied to a clustered view, where the
    /// backend decides.
    max_expectations: std::sync::atomic::AtomicUsize,
    /// `maxExpectationsSizeInBytes` (`CircularPriorityQueue.maxBytes`): past it the oldest expectations by
    /// insertion are evicted until the summed weights fit, but never the last one; `0` disables the bound. Not
    /// applied to a clustered view, where the backend decides.
    max_bytes: AtomicU64,
    /// `byteEvictedCount`: expectations evicted to fit `max_bytes`, never reset.
    byte_evicted: AtomicU64,
    /// `expectationByteEvictedWarned`: the byte-budget WARN is logged once per server, through `byte_budget_warning`.
    byte_budget_warned: std::sync::atomic::AtomicBool,
    byte_budget_warning: std::sync::OnceLock<Box<dyn Fn(u64) + Send + Sync>>,
    /// Every expectation's `httpRequest` by id, kept after the expectation is used up or cleared, until reset
    /// (upstream's `expectationRequestDefinitions`): ids stay resolvable for verify/clear/retrieve.
    definitions: RwLock<HashMap<String, Value>>,
    /// The clustered state backend this store is a view over (`stateBackend=infinispan`, `clusterEnabled=true`).
    cluster: std::sync::OnceLock<Arc<ClusterLink>>,
    /// This server's `ScenarioManager` and `CrossProtocolEventBus`.
    pub scenarios: Arc<crate::scenario::Scenarios>,
    /// This server's `CrossProtocolEventBus`.
    pub bus: Arc<crate::scenario::CrossProtocolBus>,
    /// Touched whenever the expectations change (`MockServerMatcherListener`): the dashboard's push channel waits on it.
    pub changes: crate::changes::ChangeSignal,
    /// `RequestMatchers.lastModifiedEpochMillis`: when the store last changed structurally (0: never), on the server's
    /// clock, which `PUT /mockserver/explain` compares with a request's arrival.
    last_modified: AtomicI64,
    /// Expectations a scan or a listing dropped as used up or expired (`scheduleLazyRemoval`), not yet logged as
    /// `removed expectation`.
    lazy_removed: crate::watched::WatchedMutex<Vec<Arc<Expectation>>>,
    /// Ids whose clustered shared-`Times` counter was found exhausted or gone: removed by the next lazy drop
    /// (`scheduler.submit(() -> removeHttpRequestMatcher(...))`), their node-local count left as it was.
    exhausted_in_cluster: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Ids in this node's view that the expectation backend never received: `addPrioritisedExpectation` adds the
    /// matcher, then `getAction()` throws (several action types without one primary) before
    /// `expectationBackend.put`. The next backend change (`InvalidationListener` → `trimEvictedFromBackend`) drops
    /// them without a log line.
    unbacked: std::sync::Mutex<std::collections::HashSet<String>>,
    /// `scenarios.writes()` when the unbacked expectations were last checked: a scenario state write fires the same
    /// invalidation listener, so the unbacked ones are trimmed (lazily, before the store is next read).
    scenario_writes_seen: AtomicU64,
    /// The server's clock, which times to live run on.
    clock: Arc<crate::clock::Clock>,
    /// `SemanticMatching`: the judge of `semanticMatchAgainst` predicates, installed at start when
    /// `llmSemanticMatchingEnabled` and an LLM backend resolves (`llm::service::install_semantic_matching`).
    pub semantic: std::sync::OnceLock<SemanticJudge>,
    /// Tests only: work run once at a [`Pause`] point, to force an interleaving of concurrent requests.
    #[cfg(test)]
    pub(crate) pause: std::sync::Mutex<Option<(Pause, PauseWork)>>,
}

/// Tests only: where [`Store::pause`] runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Pause {
    /// A scan has just consumed a use of the expectation it is committing.
    Consumed,
    /// `post_process` has decided whether to remove the expectation, and has not yet ended its response in progress.
    Checked,
}

impl Store {
    #[cfg(test)]
    fn paused(&self, at: Pause) {
        let work = {
            let mut pause = self.pause.lock().unwrap();
            if pause.as_ref().is_some_and(|(p, _)| *p == at) { pause.take().map(|(_, w)| w) } else { None }
        };
        if let Some(work) = work {
            work();
        }
    }

    #[cfg(not(test))]
    #[inline(always)]
    fn paused(&self, _: Pause) {}
}


/// `SemanticMatching.matches(subject, expectedMeaning)`.
pub type SemanticJudge = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;

impl Store {
    /// `markMatchersModified`: a structural change, announced to the dashboard and timed for `explain`.
    fn modified(&self) {
        self.last_modified.store(self.clock.now_millis(), Ordering::Release);
        self.changes.touch();
    }

    /// [`Store::modified`] for `n` added or updated expectations (none: no change).
    fn modified_n(&self, n: u64) {
        if n > 0 {
            self.last_modified.store(self.clock.now_millis(), Ordering::Release);
        }
        self.changes.touch_n(n);
    }

    /// `lastModifiedEpochMillis`.
    pub fn last_modified_millis(&self) -> i64 {
        self.last_modified.load(Ordering::Acquire)
    }

    /// An empty store whose times to live run on `clock`.
    pub fn with_clock(clock: Arc<crate::clock::Clock>) -> Store {
        Store { clock, ..Default::default() }
    }

    /// `RequestMatchers.setStateBackend` for a clustered backend: from now on adds write through, removals remove,
    /// limited `Times` are shared and [`Store::reconcile_from_backend`] has something to reconcile with.
    pub fn attach_cluster(&self, link: Arc<ClusterLink>) {
        let _ = self.cluster.set(link);
    }

    /// Bounds the store at `max` expectations (`maxExpectations`).
    pub fn set_max_expectations(&self, max: usize) {
        self.max_expectations.store(max, Ordering::Relaxed);
    }

    /// Bounds the summed weights of the expectations at `max_bytes` (`maxExpectationsSizeInBytes`, `0` unbounded).
    pub fn set_max_bytes(&self, max_bytes: u64) {
        self.max_bytes.store(max_bytes, Ordering::Relaxed);
    }

    /// `RequestMatchers.announceByteEvictionIfNeeded`'s WARN, called with the budget the first time an expectation
    /// is evicted to fit it.
    pub fn on_byte_budget_reached(&self, warn: Box<dyn Fn(u64) + Send + Sync>) {
        let _ = self.byte_budget_warning.set(warn);
    }

    /// `getExpectationBytes()`: the summed weights of the expectations held, kept whether or not a budget is in force.
    pub fn expectation_bytes(&self) -> u64 {
        let unbacked = self.unbacked.lock().unwrap().clone();
        self.view().list.iter().filter(|e| !unbacked.contains(&e.id)).map(|e| e.weight).sum()
    }

    /// `getMaxExpectationBytes()`: the byte budget in force, `0` when disabled.
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes.load(Ordering::Relaxed)
    }

    /// `getExpectationByteEvictedCount()`.
    pub fn byte_evicted(&self) -> u64 {
        self.byte_evicted.load(Ordering::Relaxed)
    }

    /// `RequestMatchers.applyConfigurationCapacity` after a configuration update: the new bounds, and with one in
    /// force the oldest expectations by insertion go until the store fits (`CircularPriorityQueue.setMaxSize`, then
    /// `setMaxBytes`). A clustered view leaves the bounds to the backend. On the 8.0.0 process this read the startup
    /// copy and changed nothing (upstream 0e8566814).
    pub fn resize(&self, max: usize, max_bytes: u64) {
        self.set_max_expectations(max);
        self.set_max_bytes(max_bytes);
        if self.is_clustered() {
            return;
        }
        let unbacked = self.unbacked.lock().unwrap().clone();
        let evicted = {
            let mut inner = self.inner.write();
            let evicted = self.evict_excess(&mut inner, max, max_bytes, &unbacked);
            if evicted.is_empty() {
                return;
            }
            inner.reindex();
            evicted
        };
        self.modified();
        {
            let mut definitions = self.definitions.write();
            let mut sources = self.sources.write();
            for id in &evicted {
                definitions.remove(id);
                sources.remove(id);
            }
        }
        self.announce_byte_eviction();
    }

    /// `CircularPriorityQueue.evictExcess` then `evictExcessBytes`: the oldest expectations by insertion leave until
    /// there are at most `max` (`0` unbounded) and, past that, until their summed weights fit `max_bytes` (`0`
    /// unbounded) or one is left. An unbacked expectation weighs nothing (the backend never held it). Returns the
    /// evicted ids; the ones evicted for bytes are counted.
    fn evict_excess(&self, inner: &mut Inner, max: usize, max_bytes: u64, unbacked: &std::collections::HashSet<String>) -> Vec<String> {
        let weight = |e: &Expectation| if unbacked.contains(&e.id) { 0 } else { e.weight };
        let mut total: u64 = if max_bytes > 0 { inner.list.iter().map(|e| weight(e)).sum() } else { 0 };
        let mut evicted = Vec::new();
        loop {
            let over_count = max > 0 && inner.list.len() > max;
            let over_bytes = !over_count && max_bytes > 0 && total > max_bytes && inner.list.len() > 1;
            if !over_count && !over_bytes {
                return evicted;
            }
            let oldest = inner.list.iter().enumerate().min_by_key(|(_, x)| x.created).map(|(i, _)| i).expect("a non-empty list");
            let e = inner.list_mut().remove(oldest);
            total = total.saturating_sub(weight(&e));
            if over_bytes {
                self.byte_evicted.fetch_add(1, Ordering::Relaxed);
            }
            evicted.push(e.id.clone());
        }
    }

    /// `announceByteEvictionIfNeeded`: once anything was evicted for bytes, the WARN, once per server.
    fn announce_byte_eviction(&self) {
        if self.byte_evicted.load(Ordering::Relaxed) > 0 && !self.byte_budget_warned.swap(true, Ordering::AcqRel) && let Some(warn) = self.byte_budget_warning.get() {
            warn(self.max_bytes.load(Ordering::Relaxed));
        }
    }

    /// `true` once a clustered backend is attached.
    pub fn is_clustered(&self) -> bool {
        self.cluster.get().is_some()
    }

    /// [`Store::upsert`], reporting the failure Java would throw: a clustered `put` of an expectation whose JSON is
    /// over 65,535 modified-UTF-8 bytes (`UTFDataFormatException`). As upstream, the expectation is in this node's
    /// view by then (the local mutation precedes the backend put).
    pub fn try_upsert(&self, new: Vec<Expectation>) -> Result<(), StateError> {
        {
            let mut sources = self.sources.write();
            for e in &new {
                sources.remove(&e.id);
            }
        }
        self.try_insert(new)
    }

    /// Adds or replaces (by id) expectations, preserving match order for replacements.
    pub fn upsert(&self, new: Vec<Expectation>) {
        {
            let mut sources = self.sources.write();
            for e in &new {
                sources.remove(&e.id);
            }
        }
        self.insert(new);
    }

    /// `RequestMatchers.update(expectations, cause)` for a file source: its expectations are upserted and the
    /// ones it loaded before but no longer holds are removed (and returned); other sources' expectations are left
    /// alone. A repeated id keeps its last entry, at the first entry's place ([`distinct_by_id`]).
    pub fn update_from_source(&self, source: &str, new: Vec<Expectation>) -> Vec<Arc<Expectation>> {
        let new = distinct_by_id(new);
        let ids: std::collections::HashSet<String> = new.iter().map(|e| e.id.clone()).collect();
        self.insert(new);
        let stale: std::collections::HashSet<String> = {
            let mut sources = self.sources.write();
            let stale = sources.iter().filter(|(id, s)| *s == source && !ids.contains(*id)).map(|(id, _)| id.clone()).collect();
            for id in &ids {
                sources.insert(id.clone(), source.to_string());
            }
            stale
        };
        if stale.is_empty() {
            return Vec::new();
        }
        let removed = self.take_where(|e| stale.contains(&e.id));
        self.sources.write().retain(|id, _| !stale.contains(id));
        removed
    }

    fn insert(&self, new: Vec<Expectation>) {
        if let Err(e) = self.try_insert(new) {
            eprintln!("ERROR state backend: {e}");
        }
    }

    /// `addPrioritisedExpectation` for a new expectation whose primary action throws: in this node's view, never in
    /// the backend (see `unbacked`), and no backend change follows.
    /// An update in place (`httpRequestMatcher.update`) stays backed: the backend keeps the previous version.
    pub fn insert_unbacked(&self, e: Expectation) {
        self.sync_scenario_writes();
        self.sources.write().remove(&e.id);
        let id = e.id.clone();
        let new = self.get(&id).is_none();
        if let Err(error) = self.insert_local(vec![e], false) {
            eprintln!("ERROR state backend: {error}");
        }
        if new {
            self.unbacked.lock().unwrap().insert(id);
        }
    }

    /// `true` when expectation `id` is in this node's view only (`unbacked`).
    pub fn is_unbacked(&self, id: &str) -> bool {
        self.sync_scenario_writes();
        self.unbacked.lock().unwrap().contains(id)
    }

    /// Trims the unbacked expectations when a scenario state was written since they were last checked.
    fn sync_scenario_writes(&self) {
        let writes = self.scenarios.writes();
        if self.scenario_writes_seen.swap(writes, Ordering::AcqRel) != writes {
            self.trim_unbacked();
        }
    }

    /// This node's view for reading, after [`Store::sync_scenario_writes`].
    fn view(&self) -> parking_lot::RwLockReadGuard<'_, Inner> {
        self.sync_scenario_writes();
        self.inner.read()
    }

    /// `trimEvictedFromBackend` after a backend change: what the backend never held leaves this node's view and its
    /// request definition is forgotten, silently.
    fn trim_unbacked(&self) {
        let trimmed = std::mem::take(&mut *self.unbacked.lock().unwrap());
        if trimmed.is_empty() {
            return;
        }
        {
            let mut inner = self.inner.write();
            let before = inner.list.len();
            inner.list_mut().retain(|e| !trimmed.contains(&e.id));
            if inner.list.len() != before {
                inner.reindex();
            }
        }
        let mut definitions = self.definitions.write();
        for id in &trimmed {
            definitions.remove(id);
        }
        drop(definitions);
        self.modified();
    }

    /// Expectations `ids` just left this node's view: the backend's `remove` fires its invalidation listener only for
    /// one it held, which trims the unbacked ones.
    fn removed_from_view<'a>(&self, ids: impl Iterator<Item = &'a str>) {
        let backed = {
            let mut unbacked = self.unbacked.lock().unwrap();
            ids.fold(false, |backed, id| !unbacked.remove(id) | backed)
        };
        if backed {
            self.trim_unbacked();
        }
    }

    fn try_insert(&self, new: Vec<Expectation>) -> Result<(), StateError> {
        let ids: Vec<String> = new.iter().map(|e| e.id.clone()).collect();
        let result = self.insert_local(new, true);
        // `expectationBackend.put` fires the invalidation listener: unbacked expectations are trimmed (an id now put
        // is backed).
        {
            let mut unbacked = self.unbacked.lock().unwrap();
            for id in &ids {
                unbacked.remove(id);
            }
        }
        self.trim_unbacked();
        result
    }

    fn insert_local(&self, new: Vec<Expectation>, backed: bool) -> Result<(), StateError> {
        // `RequestMatchers.add` notifies its listeners once per expectation
        let added = new.len() as u64;
        // `ExpectationDTO.buildObject`: its cross-protocol scenarios join the event bus.
        for e in &new {
            self.bus.register_cross_protocol(&e.input);
        }
        {
            let mut definitions = self.definitions.write();
            for e in &new {
                definitions.insert(e.id.clone(), e.request_definition());
            }
        }
        let cluster = self.cluster.get().cloned().filter(|_| backed);
        let ids: Vec<String> = new.iter().map(|e| e.id.clone()).collect();
        // Clustered: register the ids in flight before the local mutation (a reconcile must not take a just-inserted
        // expectation for one the backend evicted), and read the creation time the backend already has for an id
        // (CPX-04) before any lock is taken.
        let mut backend_created: HashMap<String, u64> = HashMap::new();
        if let Some(c) = &cluster {
            c.begin(&ids);
            for id in &ids {
                if let Some(existing) = c.backend.expectations().get(id) {
                    backend_created.insert(id.clone(), existing.value.created);
                }
            }
            // creation times are comparable across nodes: a counter seeded from the clock
            self.next_created.fetch_max(crate::chaos::now_millis().max(0) as u64 * 1000, Ordering::Relaxed);
        }
        let mut evicted: Vec<String> = Vec::new();
        {
            // The bounds are the backend's, which an unbacked expectation never reaches.
            let bounded = cluster.is_none() && backed;
            let max = if bounded { self.max_expectations.load(Ordering::Relaxed) } else { 0 };
            let max_bytes = if bounded { self.max_bytes.load(Ordering::Relaxed) } else { 0 };
            let unbacked = if max_bytes > 0 { self.unbacked.lock().unwrap().clone() } else { Default::default() };
            let mut inner = self.inner.write();
            for mut e in new {
                match inner.list.iter().position(|existing| existing.id == e.id) {
                    Some(i) => {
                        e.created = inner.list[i].created;
                        e.in_progress = inner.list[i].in_progress.clone();
                        inner.list_mut()[i] = Arc::new(e);
                    }
                    None => {
                        e.created = match backend_created.get(&e.id) {
                            Some(created) => *created,
                            None => self.next_created.fetch_add(1, Ordering::Relaxed),
                        };
                        inner.list_mut().push(Arc::new(e));
                    }
                }
                // Over a bound: the oldest by insertion goes (an update keeps its place, `replaceValue`).
                evicted.extend(self.evict_excess(&mut inner, max, max_bytes, &unbacked));
            }
            inner.reindex();
        }
        self.modified_n(added);
        if !evicted.is_empty() {
            {
                let mut definitions = self.definitions.write();
                let mut sources = self.sources.write();
                for id in &evicted {
                    if !self.inner.read().list.iter().any(|e| e.id == *id) {
                        definitions.remove(id);
                        sources.remove(id);
                    }
                }
            }
            self.announce_byte_eviction();
        }
        let Some(c) = cluster else { return Ok(()) };
        // `expectationBackend.put(id, new ExpectationEntry(expectation))`, outside every lock
        let mut first_error = None;
        for id in &ids {
            let Some(e) = self.get(id) else { continue };
            // `seedSharedTimesCounter` first, so a peer reconciling on the put already sees the counter
            let remaining = e.remaining.load(Ordering::Acquire);
            c.seed_shared_times(id, (remaining >= 0).then_some(remaining));
            match c.backend.expectations().try_put(id, e.entry()) {
                Ok(version) => c.set_version(id, version),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        c.end(&ids);
        first_error.map_or(Ok(()), Err)
    }

    /// `removeHttpRequestMatcher`'s `expectationBackend.remove(id)`, for expectations just removed from this node's
    /// view (outside every lock). A no-op without a clustered backend.
    fn forget_in_backend<'a>(&self, ids: impl Iterator<Item = &'a str>) {
        let Some(c) = self.cluster.get() else { return };
        for id in ids {
            c.forget_version(id);
            c.backend.expectations().remove(id);
            c.invalidate_shared_times(id);
        }
    }

    /// `RequestMatchers.reconcileFromBackend` for a clustered backend (`reconcileClusteredScan`): this node's view is
    /// diffed against the backend — evict what the backend no longer holds, add what it holds and this node does
    /// not, rebuild what has a newer version — in upstream's load-bearing snapshot order (cached ids, in-flight ids,
    /// then the backend) and with no store lock held across a backend call. A no-op without a clustered backend.
    pub fn reconcile_from_backend(&self) {
        let Some(c) = self.cluster.get().cloned() else { return };
        let _pass = c.reconcile_gate.lock();
        // (1) ids cached locally, (2) adds in flight, (3) the backend: taken last, outside the store's locks
        let cached: std::collections::HashSet<String> = self.inner.read().list.iter().map(|e| e.id.clone()).collect();
        let protected = c.in_flight_snapshot();
        let entries = c.backend.expectations().entries();
        let backend_ids: std::collections::HashSet<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        let evicted: std::collections::HashSet<String> = cached.iter().filter(|id| !backend_ids.contains(id.as_str()) && !protected.contains(*id)).cloned().collect();

        // compile what has to be added or rebuilt, outside every lock
        let mut incoming: Vec<(Expectation, u64)> = Vec::new();
        for (id, versioned) in &entries {
            let known = cached.contains(id);
            let stale = c.last_version(id).is_none_or(|last| versioned.version > last);
            if (known && (!stale || protected.contains(id))) || (!known && protected.contains(id)) {
                continue;
            }
            let Some(mut e) = c.compile(&versioned.value.expectation_json) else {
                eprintln!("ERROR state backend: expectation {id} in the cluster does not compile; ignored");
                continue;
            };
            e.created = versioned.value.created;
            e.remaining.store(versioned.value.remaining_times, Ordering::Release);
            incoming.push((e, versioned.version));
        }

        let mut changed = false;
        {
            let mut inner = self.inner.write();
            if !evicted.is_empty() {
                let before = inner.list.len();
                inner.list_mut().retain(|e| !evicted.contains(&e.id));
                changed |= inner.list.len() != before;
            }
            for (e, version) in incoming {
                self.next_created.fetch_max(e.created + 1, Ordering::Relaxed);
                let id = e.id.clone();
                self.definitions.write().insert(id.clone(), e.request_definition());
                match inner.list.iter().position(|existing| existing.id == e.id) {
                    Some(i) => {
                        e.adopt_runtime(&inner.list[i]);
                        inner.list_mut()[i] = Arc::new(e);
                    }
                    None => {
                        self.bus.register_cross_protocol_local(&e.input);
                        inner.list_mut().push(Arc::new(e));
                    }
                }
                changed = true;
                c.set_version(&id, version);
            }
            if changed {
                inner.reindex();
            }
        }
        if changed {
            self.modified();
        }
        for id in &evicted {
            c.forget_version(id);
            self.definitions.write().remove(id);
        }
        // the counters of what the backend evicted go too, outside every lock (a replicated write)
        for id in &evicted {
            c.invalidate_shared_times(id);
        }
    }

    /// `maxLlmConversationBodySize`'s default: a larger body is never matched by conversation predicates.
pub(crate) const MAX_LLM_CONVERSATION_BODY: usize = 1_048_576;

/// The first live expectation matching `request`, with one of its uses consumed.
    pub fn first_match(&self, request: &HttpRequest, namespace: Option<&str>) -> Option<Arc<Expectation>> {
        self.first_match_traced_if(request, namespace, false).0.map(|f| f.expectation)
    }

    /// [`Store::first_match`], with every expectation evaluated on the way, in order: upstream logs each
    /// (`EXPECTATION_MATCHED` / `EXPECTATION_NOT_MATCHED`) as it goes.
    /// The matched expectation comes with its match number (1-based). Expectations of another namespace than
    /// `namespace` (the request's) are skipped before matching, so they are neither evaluated nor logged.
    pub fn first_match_traced(&self, request: &HttpRequest, namespace: Option<&str>) -> (Option<Found>, Vec<Evaluated>) {
        self.first_match_traced_if(request, namespace, true)
    }

    /// [`Store::first_match_traced`], the evaluations listed only when `trace` (nothing logs them below INFO, and
    /// listing each held a reference to its expectation, shared with every other request worker).
    pub fn first_match_traced_if(&self, request: &HttpRequest, namespace: Option<&str>, trace: bool) -> (Option<Found>, Vec<Evaluated>) {
        let now = self.clock.now_millis();
        let mut evaluated = Vec::new();
        // The scan runs over a snapshot, with no lock of this store held: a matcher may take seconds (a WASM module
        // spends up to `wasmExecutionTimeoutMillis`), and meanwhile an expectation is still created at once (scenario
        // `wasm_slow_module_concurrency`); clustered, consuming a limited `Times` is a backend round trip, which a
        // remote node's listener may need this store to answer.
        let snapshot = self.view().shared();
        let (found, prune) = self.scan(admissible(snapshot.candidates(&request.path), namespace), request, now, trace.then_some(&mut evaluated));
        if prune {
            self.drop_lazily(now);
        }
        (found, evaluated)
    }

    /// The scan of [`Store::first_match_traced`] over `candidates`, in match order: whether one matched, and whether
    /// a used-up or expired expectation was met that the caller should drop.
    fn scan<'a>(&self, candidates: impl Iterator<Item = &'a Arc<Expectation>>, request: &HttpRequest, now: i64, mut evaluated: Option<&mut Vec<Evaluated>>) -> (Option<Found>, bool) {
        let mut prune = false;
        let mut found = None;
        for e in candidates {
            // A used-up or expired expectation is still evaluated, as not matching; unless a request it serves
            // is in flight (`postProcess` removes it then), this scan drops it (`scheduleLazyRemoval`).
            if !e.alive(now) {
                prune |= !e.in_progress.load(Ordering::Acquire);
                if let Some(evaluated) = evaluated.as_deref_mut() {
                    evaluated.push(Evaluated { expectation: e.clone(), remaining: Some(e.remaining_now()), matched: false, active: false, warning: None });
                }
                continue;
            }
            // Logged as it was when matched, before this match is counted.
            let remaining = Some(e.remaining_now());
            let matched = e.matcher.matches(request, Mode::DataPlane);
            // Logged as matched by the request matcher, even when the conversation predicates then reject it.
            if let Some(evaluated) = evaluated.as_deref_mut() {
                evaluated.push(Evaluated { expectation: e.clone(), remaining, matched, active: true, warning: None });
            }
            // `LlmConversationMatcher`: an `httpLlmResponse` with conversation predicates must accept the request's
            // conversation too; a rejection logs nothing of its own.
            let matched = matched && (!e.has(Rare::Llm) || crate::llm::conversation::matches(&e.input, request, Self::MAX_LLM_CONVERSATION_BODY, self.semantic.get()));
            // `ScenarioManager`: a scenario-gated expectation serves only in its state, then moves it on.
            let mut warning = None;
            let committed = matched && (!e.has(Rare::Scenario) || self.scenarios.gate(&e.input, request)) && e.by_percentage() && self.commit(e, request, &mut prune, Some(&mut warning));
            if let Some(last) = evaluated.as_deref_mut().and_then(|e| e.last_mut()) {
                last.warning = warning;
            }
            if committed {
                found = Some(Found { rotation: e.rotate(request), match_count: e.record_match(), expectation: e.clone() });
                break;
            }
        }
        (found, prune)
    }

    /// `firstMatchingExpectation`'s commit of a matched expectation `e` that passed its scenario gate and percentage:
    /// its response is marked in progress first, then one use is taken and the scenario moved on; either failing
    /// ends the response in progress again (one flag, shared with any other request it is serving, as upstream's
    /// `responseInProgress`). Marked before the use is taken, a used-up expectation serving its last request is
    /// never seen by another scan as neither live nor in progress, so it is not dropped lazily under it.
    /// A WARN the use's consumption raises goes to `warning` when given (logged after the matched entry), else it is
    /// logged at once.
    fn commit(&self, e: &Expectation, request: &HttpRequest, prune: &mut bool, warning: Option<&mut Option<String>>) -> bool {
        e.in_progress.store(true, Ordering::Release);
        if !self.consume_use(e, prune, warning) {
            e.in_progress.store(false, Ordering::Release);
            return false;
        }
        self.paused(Pause::Consumed);
        if e.has(Rare::Scenario) && !self.scenarios.transition(&e.input, request) {
            e.in_progress.store(false, Ordering::Release);
            return false;
        }
        true
    }

    /// Takes one use of `e`. Clustered with shared `Times` (the default) and a limited expectation, that is a
    /// compare-and-set of the backend's counter (`consumeTimesViaBackendCas`): lost, the use goes to another node;
    /// the counter at zero (or the entry gone) makes it exhausted fleet-wide, so it is dropped here too (`prune`).
    fn consume_use(&self, e: &Expectation, prune: &mut bool, warning: Option<&mut Option<String>>) -> bool {
        let Some(c) = self.cluster.get() else { return e.consume() };
        if !c.shared_times_enabled() || e.remaining.load(Ordering::Acquire) < 0 {
            return e.consume();
        }
        let consumed = match c.consume_times(&e.id) {
            Consumed::Discarded { warning: Some(text) } => {
                match warning {
                    Some(slot) => *slot = Some(text),
                    None => c.warn(text),
                }
                Consumed::Exhausted
            }
            Consumed::Discarded { warning: None } => Consumed::Exhausted,
            other => other,
        };
        match consumed {
            // `consumeMatchLocally`: with a counter store the node-local count stays as added
            Consumed::Served { remaining } => {
                if !c.counts_uses_in_backend_only() {
                    e.lower_remaining(remaining);
                }
                true
            }
            // an add whose backend put has not landed yet is not an exhausted one
            Consumed::Exhausted if c.is_in_flight(&e.id) => false,
            Consumed::Exhausted if c.counts_uses_in_backend_only() => {
                self.exhausted_in_cluster.lock().unwrap().insert(e.id.clone());
                *prune = true;
                false
            }
            Consumed::Exhausted => {
                e.remaining.store(0, Ordering::Release);
                *prune = true;
                false
            }
            Consumed::Contended | Consumed::Discarded { .. } => false,
        }
    }

    /// `RequestMatchers.postProcess`, once the response to a request `expectation` served is written: removes it when
    /// that left it used up or expired (`true` when this call removed it), and ends its response in progress.
    pub fn post_process(&self, expectation: &Arc<Expectation>) -> bool {
        let removed = !expectation.is_active() && {
            let mut inner = self.inner.write();
            let before = inner.list.len();
            inner.list_mut().retain(|e| !Arc::ptr_eq(e, expectation));
            let removed = inner.list.len() < before;
            if removed {
                inner.reindex();
            }
            removed
        };
        self.paused(Pause::Checked);
        expectation.in_progress.store(false, Ordering::Release);
        if removed {
            self.modified();
            self.forget_in_backend(std::iter::once(expectation.id.as_str()));
            self.removed_from_view(std::iter::once(expectation.id.as_str()));
        }
        removed
    }

    /// `firstMatchingExpectation` for a DNS query (`request`: `dnsName`, `dnsType`, `dnsClass`), with one use of the
    /// match consumed. A query belongs to the global namespace, so namespaced expectations are skipped.
    pub fn first_dns_match(&self, request: &Value) -> (Option<Arc<Expectation>>, Vec<DnsEvaluated>) {
        let now = self.clock.now_millis();
        // Scenario isolation reads headers, parameters and cookies, which a DNS query has none of.
        let none = HttpRequest::default();
        let mut evaluated = Vec::new();
        // As `first_match_traced` clustered: no lock of this store is held across a backend round trip (a clustered
        // scenario gate or `Times` compare-and-set), so the scan runs over a snapshot.
        let snapshot: Vec<Arc<Expectation>> = self.view().list.to_vec();
        let (found, prune) = {
            let (mut found, mut prune) = (None, false);
            for e in admissible(snapshot.iter(), None) {
                // A used-up or expired expectation is evaluated as not matching; one no request is being served by
                // is dropped (`scheduleLazyRemoval`), queued to be logged as removed.
                if !e.alive(now) {
                    prune |= !e.in_progress.load(Ordering::Acquire);
                    evaluated.push(DnsEvaluated { expectation: e.clone(), snapshot: e.current(), matched: false, dns: e.dns.is_some(), differences: 0, active: false });
                    continue;
                }
                let (matched, difference) = e.dns.as_ref().map_or((false, None), |m| m.evaluate(request));
                evaluated.push(DnsEvaluated { expectation: e.clone(), snapshot: e.current(), matched, dns: e.dns.is_some(), differences: difference.is_some() as usize, active: true });
                // `firstMatchingExpectation` marks the response in progress; `DnsRequestHandler` never calls
                // `postProcess`, so it stays so: a DNS expectation once matched is never removed lazily, and a
                // used-up one stays listed (with `remainingTimes` 0) until it is cleared.
                if matched && self.scenarios.gate(&e.input, &none) && e.by_percentage() && self.commit(e, &none, &mut prune, None) {
                    e.record_match();
                    found = Some(e.clone());
                    break;
                }
            }
            (found, prune)
        };
        if prune {
            self.drop_lazily(now);
        }
        (found, evaluated)
    }

    /// `hasEarlyExpectations` (b765b8271): whether a registered expectation carries `respondBeforeBody: true`, without
    /// which `EarlyMatchingHandler` maps no request head and detaches at once.
    pub fn has_early_expectations(&self) -> bool {
        self.view().early > 0
    }

    /// `firstMatchingEarlyExpectation`: the first `respondBeforeBody` expectation (without a body matcher) matching
    /// the request's head, committed as [`Store::first_match_traced`] commits one, so the request is answered before
    /// its body is read; with every such expectation evaluated on the way (upstream logs each, the others are
    /// skipped unevaluated). Control-plane requests never are (the caller's check). A used-up or expired one met is evaluated as not
    /// matching but not dropped: the early scan schedules no lazy removal.
    pub fn first_early_match(&self, request: &HttpRequest, namespace: Option<&str>) -> (Option<Found>, Vec<Evaluated>) {
        let mut evaluated = Vec::new();
        let now = self.clock.now_millis();
        let early = |e: &&Arc<Expectation>| {
            e.early && e.input.get("httpRequest").and_then(|r| r.get("body")).is_none_or(Value::is_null)
        };
        // As `first_match_traced`: over a snapshot, no lock of this store held while matching.
        let snapshot = self.view().shared();
        let (found, _) = self.scan(admissible(snapshot.candidates(&request.path), namespace).filter(early), request, now, Some(&mut evaluated));
        (found, evaluated)
    }

    /// Every live expectation evaluated against `request`, none consumed (`retrieveExpectationsMatchingRequest`).
    pub fn evaluate_all(&self, request: &HttpRequest) -> Vec<Evaluated> {
        let now = self.clock.now_millis();
        let snapshot: Vec<Arc<Expectation>> = self.view().list.to_vec();
        snapshot.iter().filter(|e| e.alive(now)).map(|e| Evaluated { expectation: e.clone(), remaining: Some(e.remaining_now()), matched: e.matcher.matches(request, Mode::DataPlane), active: true, warning: None }).collect()
    }

    /// `firstMatchingExpectation` for a binary request: every live expectation is evaluated in match order until a
    /// binary request matcher (`binaryData`, optionally negated, an empty one matching everything) accepts `bytes` and
    /// the expectation commits as an HTTP one does (scenario gate, percentage, a use consumed — through the backend's
    /// shared `Times` when clustered — and the scenario transition). A binary request belongs to the global namespace
    /// (`extractRequestNamespace`). The evaluations come back as [`DnsEvaluated`] (its `dns` flag: a binary matcher),
    /// to be logged by `binary::log_evaluations`.
    pub fn first_binary_match(&self, bytes: &[u8]) -> (Option<Arc<Expectation>>, Vec<DnsEvaluated>) {
        use base64::Engine;
        let now = self.clock.now_millis();
        // Scenario isolation reads headers, parameters and cookies, which a binary request has none of.
        let none = HttpRequest::default();
        let snapshot: Vec<Arc<Expectation>> = self.view().list.to_vec();
        let mut evaluated = Vec::new();
        let (mut found, mut prune) = (None, false);
        for e in admissible(snapshot.iter(), None).filter(|e| e.alive(now)) {
            let Some(data) = e.input.get("httpRequest").and_then(|r| r.get("binaryData")).and_then(Value::as_str) else {
                evaluated.push(DnsEvaluated { expectation: e.clone(), snapshot: e.current(), matched: false, dns: false, differences: 0, active: true });
                continue;
            };
            let expected = base64::engine::general_purpose::STANDARD.decode(data).unwrap_or_default();
            let not = e.input["httpRequest"].get("not").and_then(Value::as_bool).unwrap_or(false);
            let matched = (expected.is_empty() || expected == bytes) != not;
            evaluated.push(DnsEvaluated { expectation: e.clone(), snapshot: e.current(), matched, dns: true, differences: usize::from(!matched), active: true });
            // `firstMatchingExpectation` marks the response in progress; `BinaryRequestProxyingHandler` then calls
            // `postProcess` ([`Store::post_process`]), which removes a used-up one.
            if matched && self.scenarios.gate(&e.input, &none) && e.by_percentage() && self.commit(e, &none, &mut prune, None) {
                e.record_match();
                found = Some(e.clone());
                break;
            }
        }
        if prune {
            self.drop_lazily(now);
        }
        (found, evaluated)
    }

    /// Live expectations a request of `namespace` may see, in match order.
    pub fn admissible(&self, namespace: Option<&str>) -> Candidates {
        let now = self.clock.now_millis();
        self.view().live_candidates(Some(namespace), now)
    }

    /// [`Store::active`] as [`Candidates`].
    pub fn active_candidates(&self) -> Candidates {
        let now = self.clock.now_millis();
        self.view().live_candidates(None, now)
    }

    /// `retrieveActiveExpectations`: live expectations and used-up ones still serving a request, in match order.
    pub fn retrievable(&self) -> Vec<Arc<Expectation>> {
        let now = self.clock.now_millis();
        let (kept, dead): (Vec<_>, Vec<_>) = self.view().list.iter().cloned().partition(|e| e.retained(now));
        if !dead.is_empty() {
            self.drop_lazily(now);
        }
        kept
    }

    /// `scheduleLazyRemoval`: drops what is neither live nor serving a request, queued to be logged.
    fn drop_lazily(&self, now: i64) {
        let exhausted = std::mem::take(&mut *self.exhausted_in_cluster.lock().unwrap());
        let taken = self.take_where(|e| !e.retained(now) || exhausted.contains(&e.id));
        self.lazy_removed.lock().extend(taken);
    }

    /// The expectations dropped lazily since the last call (only `id`'s when given), to be logged as removed.
    pub fn take_lazy_removed(&self, id: Option<&str>) -> Vec<Arc<Expectation>> {
        // asked after every request's scan: nearly always nothing, answered without the lock
        if self.lazy_removed.is_empty() {
            return Vec::new();
        }
        let mut queue = self.lazy_removed.lock();
        match id {
            None => std::mem::take(&mut *queue),
            Some(id) => {
                let (taken, kept): (Vec<_>, Vec<_>) = queue.drain(..).partition(|e| e.id == id);
                *queue = kept;
                taken
            }
        }
    }

    /// Every stored expectation in match order, used-up and expired ones included until they are pruned.
    pub fn all(&self) -> Vec<Arc<Expectation>> {
        self.view().list.to_vec()
    }

    /// Live expectations in match order.
    pub fn active(&self) -> Vec<Arc<Expectation>> {
        let now = self.clock.now_millis();
        self.view().list.iter().filter(|e| e.alive(now)).cloned().collect()
    }

    pub fn get(&self, id: &str) -> Option<Arc<Expectation>> {
        self.view().list.iter().find(|e| e.id == id).cloned()
    }

    /// Removes expectations for which `remove` is true, used-up and expired ones included; returns them.
    pub fn take_where(&self, remove: impl Fn(&Expectation) -> bool) -> Vec<Arc<Expectation>> {
        let taken = {
            let mut inner = self.inner.write();
            let (taken, kept): (Vec<_>, Vec<_>) = inner.list_mut().drain(..).partition(|e| remove(e));
            inner.list = Arc::new(kept);
            if !taken.is_empty() {
                inner.reindex();
            }
            taken
        };
        if !taken.is_empty() {
            self.modified();
        }
        self.forget_in_backend(taken.iter().map(|e| e.id.as_str()));
        self.removed_from_view(taken.iter().map(|e| e.id.as_str()));
        taken
    }

    /// Removes expectations for which `remove` is true; returns how many.
    pub fn remove_where(&self, remove: impl Fn(&Expectation) -> bool) -> usize {
        let mut removed_ids = Vec::new();
        {
            let mut inner = self.inner.write();
            inner.list_mut().retain(|e| {
                let drop_it = remove(e);
                if drop_it {
                    removed_ids.push(e.id.clone());
                }
                !drop_it
            });
            if !removed_ids.is_empty() {
                inner.reindex();
            }
        }
        if !removed_ids.is_empty() {
            self.modified();
        }
        self.forget_in_backend(removed_ids.iter().map(String::as_str));
        self.removed_from_view(removed_ids.iter().map(String::as_str));
        removed_ids.len()
    }

    /// Removes every expectation and forgets every id (reset, or clear without a filter).
    pub fn clear(&self) {
        {
            let mut inner = self.inner.write();
            inner.list_mut().clear();
            inner.reindex();
            self.definitions.write().clear();
            self.sources.write().clear();
            self.unbacked.lock().unwrap().clear();
        }
        self.modified();
        // `RequestMatchers.reset`: `expectationBackend.clear()`, outside the locks
        if let Some(c) = self.cluster.get() {
            c.forget_all_versions();
            c.backend.expectations().clear();
            c.clear_shared_times();
        }
        // `RequestMatchers.reset`: `scenarioManager.reset()`, and `HttpState.reset`'s `CrossProtocolEventBus.reset()`
        self.scenarios.reset();
        self.bus.reset();
    }

    /// The request matcher of expectation `id`, even if it is no longer active.
    pub fn definition(&self, id: &str) -> Option<Value> {
        self.definitions.read().get(id).cloned()
    }
}

/// `Expectation.estimatedHeapSize()`: the weight an expectation counts against `maxExpectationsSizeInBytes` (and in
/// `mock_server_expectations_bytes`), fixed when it is built. Fixed overheads plus body bytes (a JSON request body
/// again twenty times, for the matcher tree it is parsed into), header entries, template text and an inline spec.
mod heap_size {
    use serde_json::Value;

    const BASE_EXPECTATION_OVERHEAD_BYTES: u64 = 512;
    const PER_HTTP_MESSAGE_OVERHEAD_BYTES: u64 = 1152;
    const HEADER_ENTRY_OVERHEAD_BYTES: u64 = 64;
    const JSON_MATCHER_TREE_EXPANSION: u64 = 20;

    /// `estimatedHeapSize()` of the expectation given as `input`, echoed as `canonical`; `dns` for a DNS request
    /// definition (neither an `HttpRequest` nor an `OpenAPIDefinition`).
    pub fn estimate(input: &Value, canonical: &Value, dns: bool) -> u64 {
        let mut size = BASE_EXPECTATION_OVERHEAD_BYTES;
        let request = &canonical["httpRequest"];
        if !dns && request.is_object() {
            size += PER_HTTP_MESSAGE_OVERHEAD_BYTES;
            if let Some(spec) = request.get("specUrlOrPayload") {
                // `OpenAPIDefinition.getSpecUrlOrPayload().length()`
                size += match spec {
                    Value::String(s) => java_length(s),
                    Value::Null => 0,
                    other => java_length(&crate::json::pretty(other)),
                };
            } else {
                let (bytes, json) = body_bytes(&input["httpRequest"]["body"], &request["body"]);
                size += bytes;
                if json {
                    size += bytes * JSON_MATCHER_TREE_EXPANSION;
                }
                size += header_bytes(&request["headers"]);
            }
        }
        let response = |input: &Value, canonical: &Value| -> u64 {
            if !canonical.is_object() {
                return 0;
            }
            PER_HTTP_MESSAGE_OVERHEAD_BYTES + body_bytes(&input["body"], &canonical["body"]).0 + header_bytes(&canonical["headers"])
        };
        size += response(&input["httpResponse"], &canonical["httpResponse"]);
        if let Some(responses) = canonical["httpResponses"].as_array() {
            for (i, r) in responses.iter().enumerate() {
                size += response(&input["httpResponses"][i], r);
            }
        }
        for template in ["httpResponseTemplate", "httpForwardTemplate"] {
            if let Some(text) = canonical[template]["template"].as_str() {
                size += java_length(text);
            }
        }
        size
    }

    /// `String.length()`: UTF-16 code units.
    fn java_length(s: &str) -> u64 {
        s.encode_utf16().count() as u64
    }

    /// The length of `getBodyAsRawBytes()` for a body given as `input` (echoed as `canonical`), and whether it is a
    /// `JsonBody`. Text bodies are encoded in their content type's charset, else their type's default (JSON and XML
    /// UTF-8, a string ISO-8859-1), as `BodyDTODeserializer` builds them; other matchers count their JSON form.
    fn body_bytes(input: &Value, canonical: &Value) -> (u64, bool) {
        use base64::Engine;
        let encoded = |text: &str, charset: Option<&str>| crate::media_type::encode(text, Some(charset.unwrap_or("iso-8859-1"))).len() as u64;
        let object = match input {
            Value::Null => return (0, false),
            Value::String(s) => return (encoded(s, None), false),
            Value::Object(o) => o,
            // a shorthand JSON array: `JsonBody(writeValueAsString(list))`
            other => return (crate::json::pretty(other).len() as u64, true),
        };
        let Some(kind) = object.get("type").and_then(Value::as_str) else {
            // a shorthand JSON object
            return (crate::json::pretty(input).len() as u64, true);
        };
        let raw = object
            .iter()
            .find(|(k, _)| {
                let k = k.to_ascii_lowercase();
                k.contains("rawbytes") || k.contains("base64bytes")
            })
            .and_then(|(_, v)| v.as_str())
            .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok());
        let charset = |default: Option<&'static str>| -> Option<String> {
            match object.get("contentType").and_then(Value::as_str) {
                Some(content_type) => crate::media_type::MediaType::parse(Some(content_type)).charset().map(str::to_string),
                None => object.get("charset").and_then(Value::as_str).and_then(crate::media_type::canonical_charset).map(str::to_string).or(default.map(str::to_string)),
            }
        };
        let text = |field: &str| -> String {
            match object.get(field) {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Null) | None => String::new(),
                Some(other) => crate::json::pretty(other),
            }
        };
        match kind {
            "BINARY" => (raw.map_or(0, |b| b.len() as u64), false),
            "JSON" => (raw.map_or_else(|| encoded(&text("json"), charset(Some("utf-8")).as_deref()), |b| b.len() as u64), true),
            "STRING" => (raw.map_or_else(|| encoded(&text("string"), charset(None).as_deref()), |b| b.len() as u64), false),
            "XML" => (raw.map_or_else(|| encoded(&text("xml"), charset(Some("utf-8")).as_deref()), |b| b.len() as u64), false),
            // `ParameterBody.toString()`: `name=value&…`, values form-encoded
            "PARAMETERS" => {
                let mut length = 0u64;
                let mut entries = 0u64;
                for (name, value) in parameters(&canonical["parameters"]) {
                    entries += 1;
                    length += name.len() as u64 + 1 + value.map_or(0, |v| form_urlencoded::byte_serialize(v.as_bytes()).map(str::len).sum::<usize>() as u64);
                }
                (length + entries.saturating_sub(1), false)
            }
            // `ObjectWithJsonToString`: the body's JSON form, UTF-8
            _ => (crate::json::pretty(canonical).len() as u64, false),
        }
    }

    /// The (name, value) entries of a parameter map in either form; a name without values is one entry.
    fn parameters(parameters: &Value) -> Vec<(String, Option<String>)> {
        let mut entries = Vec::new();
        let mut push = |name: String, values: &Value| match values {
            Value::Array(values) if !values.is_empty() => entries.extend(values.iter().map(|v| (name.clone(), Some(nottable(v))))),
            Value::Array(_) | Value::Null => entries.push((name, None)),
            v => entries.push((name, Some(nottable(v)))),
        };
        match parameters {
            Value::Object(map) => map.iter().for_each(|(k, v)| push(nottable_key(k), v)),
            Value::Array(list) => list.iter().for_each(|p| push(nottable(&p["name"]), &p["values"])),
            _ => {}
        }
        entries
    }

    /// `NottableString.getValue()`: without a leading `!`.
    fn nottable_key(s: &str) -> String {
        s.strip_prefix('!').unwrap_or(s).to_string()
    }

    fn nottable(v: &Value) -> String {
        match v {
            Value::String(s) => nottable_key(s),
            Value::Object(o) => o.get("value").and_then(Value::as_str).unwrap_or_default().to_string(),
            Value::Null => String::new(),
            other => other.to_string(),
        }
    }

    /// `headerBytes`: 64 per header entry plus its name and value.
    fn header_bytes(headers: &Value) -> u64 {
        // a multimap has no entry for a name without values
        parameters(headers)
            .into_iter()
            .filter_map(|(name, value)| value.map(|v| HEADER_ENTRY_OVERHEAD_BYTES + java_length(&name) + java_length(&v)))
            .sum()
    }
}

/// The two `RequestMatchersStateBackendTest` cases that have no control-plane call to ride on
/// (`tests/upstream/request_matchers_backend.rs` names them).
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::{Value, json};

    use crate::config::Config;
    use crate::state::State;
    use crate::store::Expectation;
    use crate::state_backend::memory::InMemoryStateBackend;
    use crate::state_backend::{BlobStore, ExpectationEntry, InvalidationListener, KeyValueStore, StateBackend};

    /// An in-memory backend that calls itself clustered, so the store writes through to it.
    struct Clustered(InMemoryStateBackend);

    impl StateBackend for Clustered {
        fn expectations(&self) -> &dyn KeyValueStore<ExpectationEntry> {
            self.0.expectations()
        }
        fn scenario_states(&self) -> &dyn KeyValueStore<String> {
            self.0.scenario_states()
        }
        fn shared_times_counters(&self) -> Option<&dyn KeyValueStore<i32>> {
            self.0.shared_times_counters()
        }
        fn crud_entities(&self, namespace: &str) -> Arc<dyn KeyValueStore<Value>> {
            self.0.crud_entities(namespace)
        }
        fn blobs(&self) -> &dyn BlobStore {
            self.0.blobs()
        }
        fn add_invalidation_listener(&self, listener: Arc<dyn InvalidationListener>) {
            self.0.add_invalidation_listener(listener)
        }
        fn node_id(&self) -> &str {
            self.0.node_id()
        }
        fn is_clustered(&self) -> bool {
            true
        }
    }

    fn state(max: usize) -> (Arc<State>, Arc<Clustered>) {
        let backend = Arc::new(Clustered(InMemoryStateBackend::new(max)));
        let config = Config::for_tests().with_property("maxExpectations", &max.to_string());
        (State::new_with_backend(config, Vec::new(), backend.clone()), backend)
    }

    fn expectation(state: &State, id: &str, path: &str, body: &str) -> Expectation {
        let input = json!({"id": id, "httpRequest": {"path": path}, "httpResponse": {"body": body}});
        crate::control::compile_expectation(state, input.as_object().unwrap())
    }

    /// `batchUpdateKeepsBackendInSync`: a batch replace (`update(Expectation[], cause)`) removes the cause's
    /// expectations the batch lacks, in the node-local view and the backend alike.
    #[test]
    fn batch_update_keeps_backend_in_sync() {
        let (state, backend) = state(3);
        let store = &state.store;
        store.update_from_source("init.json", vec![expectation(&state, "a", "/a", "a"), expectation(&state, "b", "/b", "b")]);

        // replace A, add C: B is not in the batch, so it is removed
        store.update_from_source("init.json", vec![expectation(&state, "a", "/a", "a-v2"), expectation(&state, "c", "/c", "c")]);

        assert!(backend.expectations().get("b").is_none(), "B removed from the backend");
        assert_eq!(store.all().len(), 2);
        assert_eq!(backend.expectations().size(), 2);
        assert!(backend.expectations().get("a").is_some());
        assert!(backend.expectations().get("c").is_some());
    }

    /// `responseInProgressSurvivesUpdate`: an update keeps the in-flight flag, and the request that is still being
    /// served ends it for the replacement too.
    #[test]
    fn response_in_progress_survives_update() {
        let (state, _backend) = state(10);
        let store = &state.store;
        store.upsert(vec![expectation(&state, "a", "/a", "a-v1")]);
        let old = store.get("a").expect("a is stored");
        old.in_progress.store(true, std::sync::atomic::Ordering::Release);

        store.upsert(vec![expectation(&state, "a", "/a", "a-v2")]);

        let updated = store.get("a").expect("a is still stored");
        assert!(!Arc::ptr_eq(&old, &updated), "the update replaced the expectation");
        assert!(updated.in_progress.load(std::sync::atomic::Ordering::Acquire), "the flag survives the update");
        // the request being served finishes: the flag ends for the replacement as well
        store.post_process(&old);
        assert!(!updated.in_progress.load(std::sync::atomic::Ordering::Acquire));
    }

    fn early_expectation(state: &State, id: &str, extra: Value) -> Expectation {
        let mut input = json!({"id": id, "httpRequest": {"path": "/early", "respondBeforeBody": true}, "httpResponse": {"body": id}});
        input.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        crate::control::compile_expectation(state, input.as_object().unwrap())
    }

    /// `has_early_expectations` answers from a count kept with the list, and the count follows an add,
    /// an update, a used-up expectation's removal, a removal by predicate, an expired one's removal, a clear.
    #[test]
    fn has_early_expectations_follows_the_list() {
        // not clustered: a clustered store counts a limited `Times` in its backend
        let state = State::new_with_backend(Config::for_tests(), Vec::new(), Arc::new(InMemoryStateBackend::new(100)));
        let store = &state.store;
        assert!(!store.has_early_expectations(), "empty store");

        store.upsert(vec![expectation(&state, "plain", "/plain", "p")]);
        assert!(!store.has_early_expectations(), "a plain expectation is not early");

        store.upsert(vec![early_expectation(&state, "e1", json!({}))]);
        assert!(store.has_early_expectations(), "added");
        store.upsert(vec![expectation(&state, "e1", "/other", "now plain")]);
        assert!(!store.has_early_expectations(), "replaced by a plain one");

        // used up: removed once its single match is served and post-processed
        store.upsert(vec![early_expectation(&state, "e2", json!({"times": {"remainingTimes": 1, "unlimited": false}}))]);
        assert!(store.has_early_expectations());
        let request = crate::request::HttpRequest { method: "GET".into(), path: "/early".into(), ..Default::default() };
        let (served, _) = store.first_match_traced(&request, None);
        let e2 = served.expect("served once").expectation;
        assert_eq!(e2.id, "e2");
        assert!(!e2.is_active(), "its only use is taken");
        assert!(store.post_process(&e2), "removed once served and post-processed");
        assert!(!store.has_early_expectations(), "used up");

        // by predicate
        store.upsert(vec![early_expectation(&state, "e3", json!({}))]);
        assert!(store.has_early_expectations());
        store.remove_where(|e| e.id == "e3");
        assert!(!store.has_early_expectations(), "removed");

        // expired: arrives with an end date in the past and is dropped on the next scan that meets it
        store.upsert(vec![early_expectation(&state, "e4", json!({"timeToLive": {"unlimited": false, "timeToLive": 1, "timeUnit": "SECONDS", "endDate": 1}}))]);
        assert!(store.has_early_expectations(), "an expired expectation stays listed until it is dropped");
        let (found, _) = store.first_match_traced(&request, None);
        assert!(found.is_none(), "expired, so not served");
        assert!(!store.has_early_expectations(), "expired and dropped");

        store.upsert(vec![early_expectation(&state, "e5", json!({}))]);
        assert!(store.has_early_expectations());
        store.clear();
        assert!(!store.has_early_expectations(), "cleared, as a reset does");
    }
}

//! `LoadScenarioOrchestrator`: runs of loaded scenarios. A control tick every 100 ms walks the profile's stages,
//! launching virtual users up to a VU stage's target or at a RATE stage's arrival rate; each virtual user runs the
//! steps (rendered as templates with an `iteration`), applies checks and captures to the responses, and loops
//! (VU stages, paced) or stops after one iteration (RATE stages). Dispatch is capped by
//! `loadGenerationMaxInFlightRequests` and `loadGenerationMaxRequestsPerSecond`. A finished or stopped run keeps its
//! last status until the scenario runs again or is deleted.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, Ordering};
use std::time::{Duration, Instant};

use java_compat::lang::{JError, JMap, JObject, JValue, MapKind};
use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use super::{Row, Scenario, StageType, Step};
use crate::state::State;

const CONTROL_TICK: Duration = Duration::from_millis(100);

/// The orchestrator's clock, `TimeService.currentTimeMillis` (the run's tasks carry the server's clock).
fn now_millis() -> i64 {
    crate::clock::now_millis()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Loaded,
    Pending,
    Running,
    Completed,
    Stopped,
}

impl RunState {
    pub fn name(self) -> &'static str {
        match self {
            RunState::Loaded => "LOADED",
            RunState::Pending => "PENDING",
            RunState::Running => "RUNNING",
            RunState::Completed => "COMPLETED",
            RunState::Stopped => "STOPPED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThresholdResult {
    pub metric: Option<&'static str>,
    pub comparator: Option<&'static str>,
    pub threshold: f64,
    pub observed: f64,
    pub satisfied: bool,
}

impl ThresholdResult {
    pub fn json(&self) -> Value {
        let mut o = Map::new();
        if let Some(m) = self.metric {
            o.insert("metric".into(), m.into());
        }
        if let Some(c) = self.comparator {
            o.insert("comparator".into(), c.into());
        }
        o.insert("threshold".into(), number(self.threshold));
        o.insert("observed".into(), number(self.observed));
        o.insert("satisfied".into(), self.satisfied.into());
        Value::Object(o)
    }
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub step: String,
    pub source: String,
    pub detail: String,
    pub comparator: String,
    pub value: Option<String>,
    pub passed: i64,
    pub failed: i64,
}

impl CheckResult {
    pub fn json(&self) -> Value {
        let mut o = Map::new();
        o.insert("step".into(), self.step.clone().into());
        o.insert("source".into(), self.source.clone().into());
        if !self.detail.is_empty() {
            o.insert("detail".into(), self.detail.clone().into());
        }
        o.insert("comparator".into(), self.comparator.clone().into());
        if let Some(v) = &self.value {
            o.insert("value".into(), v.clone().into());
        }
        o.insert("passed".into(), self.passed.into());
        o.insert("failed".into(), self.failed.into());
        Value::Object(o)
    }
}

fn number(v: f64) -> Value {
    serde_json::Number::from_f64(v).map(Value::Number).unwrap_or(Value::Null)
}

/// `LoadScenarioStatus`.
#[derive(Debug, Clone)]
pub struct Status {
    pub name: String,
    pub state: RunState,
    pub elapsed: i64,
    pub current_vus: i32,
    pub requests_sent: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub p50: i64,
    pub p95: i64,
    pub p99: i64,
    pub p999: i64,
    pub dropped: i64,
    pub run_id: String,
    pub started_at_epoch: i64,
    pub ended_at_epoch: Option<i64>,
    pub labels: Option<Vec<(String, Option<String>)>>,
    pub stage_index: i32,
    pub stage_type: Option<&'static str>,
    pub current_target: f64,
    pub verdict: Option<&'static str>,
    pub aborted_by_threshold: bool,
    pub thresholds: Vec<ThresholdResult>,
    pub checks: Vec<CheckResult>,
}

/// Latencies in milliseconds, read as HdrHistogram (3 significant digits) reports percentiles.
#[derive(Default)]
struct Latencies(Vec<i64>);

impl Latencies {
    fn record(&mut self, v: i64) {
        self.0.push(v.max(0));
    }

    /// `Histogram.getValueAtPercentile`: the highest value equivalent to the one at that rank.
    fn percentile(&self, p: f64) -> i64 {
        if self.0.is_empty() {
            return 0;
        }
        let mut sorted = self.0.clone();
        sorted.sort_unstable();
        let total = sorted.len() as f64;
        let rank = (((p.clamp(0.0, 100.0) / 100.0) * total) + 0.5) as usize;
        let value = sorted[rank.max(1).min(sorted.len()) - 1];
        highest_equivalent(value)
    }
}

/// HdrHistogram's `highestEquivalentValue` for 3 significant digits (2048 sub-buckets).
fn highest_equivalent(value: i64) -> i64 {
    if value < 2048 {
        return value;
    }
    let bucket = 63 - (value as u64 | 2047).leading_zeros() as i64 - 10;
    let size = 1i64 << bucket;
    (value / size) * size + size - 1
}

struct CheckCounters {
    result: CheckResult,
}

/// `RunningScenario`.
pub struct Run {
    pub scenario: Scenario,
    run_id: String,
    triggered_at: i64,
    started_at: AtomicI64,
    started_at_epoch: AtomicI64,
    state: Mutex<RunState>,
    stopped: AtomicBool,
    active_vus: AtomicI32,
    in_flight_count: AtomicI32,
    vu_sequence: AtomicI32,
    target_vus: AtomicI32,
    stage_index: AtomicI32,
    target_rate: Mutex<f64>,
    iteration_index: AtomicI64,
    feeder_index: AtomicI64,
    /// closed until `start` has read the state it answers with, so a virtual user cannot finish the run first
    gate: tokio::sync::Semaphore,
    feeder_rows: Option<Vec<Row>>,
    feeder_strategy: usize,
    requests_sent: AtomicI64,
    succeeded: AtomicI64,
    failed: AtomicI64,
    dropped: AtomicI64,
    checks_passed: AtomicI64,
    checks_failed: AtomicI64,
    check_aggregates: Mutex<Vec<(String, CheckCounters)>>,
    latencies: Mutex<Latencies>,
    in_flight: tokio::sync::Semaphore,
    max_rps: i64,
    rps: Mutex<(i64, i64)>,
    verdict: Mutex<Option<bool>>,
    threshold_results: Mutex<Vec<ThresholdResult>>,
    aborted_by_threshold: AtomicBool,
    rate: Mutex<RateState>,
    /// `RunningScenario.engineFor`'s Velocity engine, the run's own.
    velocity: crate::templates::VelocityEngine,
}

#[derive(Default)]
struct RateState {
    deficit: f64,
    last_tick: i64,
    active_stage: i32,
}

impl Run {
    fn new(state: &State, scenario: Scenario, triggered_at: i64) -> Run {
        let config = &state.config;
        let (feeder_rows, feeder_strategy) = match &scenario.feeder {
            Some(f) => (f.resolved_rows().ok().filter(|r| !r.is_empty()), if f.strategy < 3 { f.strategy } else { 0 }),
            None => (None, 0),
        };
        Run {
            scenario,
            run_id: uuid::Uuid::new_v4().to_string(),
            triggered_at,
            started_at: AtomicI64::new(triggered_at),
            started_at_epoch: AtomicI64::new(now_millis()),
            state: Mutex::new(RunState::Loaded),
            stopped: AtomicBool::new(false),
            active_vus: AtomicI32::new(0),
            in_flight_count: AtomicI32::new(0),
            vu_sequence: AtomicI32::new(0),
            target_vus: AtomicI32::new(0),
            stage_index: AtomicI32::new(0),
            target_rate: Mutex::new(0.0),
            iteration_index: AtomicI64::new(0),
            feeder_index: AtomicI64::new(0),
            gate: tokio::sync::Semaphore::new(0),
            feeder_rows,
            feeder_strategy,
            requests_sent: AtomicI64::new(0),
            succeeded: AtomicI64::new(0),
            failed: AtomicI64::new(0),
            dropped: AtomicI64::new(0),
            checks_passed: AtomicI64::new(0),
            checks_failed: AtomicI64::new(0),
            check_aggregates: Mutex::new(Vec::new()),
            latencies: Mutex::new(Latencies::default()),
            in_flight: tokio::sync::Semaphore::new(config.int_property("loadGenerationMaxInFlightRequests", 200).max(1) as usize),
            max_rps: config.int_property("loadGenerationMaxRequestsPerSecond", 500).max(1),
            rps: Mutex::new((triggered_at, 0)),
            verdict: Mutex::new(None),
            threshold_results: Mutex::new(Vec::new()),
            aborted_by_threshold: AtomicBool::new(false),
            rate: Mutex::new(RateState { active_stage: -1, ..Default::default() }),
            velocity: Default::default(),
        }
    }

    fn name(&self) -> &str {
        self.scenario.name()
    }

    fn begin_running(&self, now: i64) {
        self.started_at.store(now, Ordering::SeqCst);
        *self.rps.lock() = (now, 0);
        self.started_at_epoch.store(now_millis(), Ordering::SeqCst);
        *self.state.lock() = RunState::Running;
    }

    fn max_requests_reached(&self) -> bool {
        self.scenario.max_requests.is_some_and(|m| m > 0 && self.requests_sent.load(Ordering::SeqCst) >= i64::from(m))
    }

    fn try_acquire_rps_token(&self) -> bool {
        let now = now_millis();
        let mut rps = self.rps.lock();
        if now - rps.0 >= 1000 {
            *rps = (now, 0);
        }
        if rps.1 < self.max_rps {
            rps.1 += 1;
            true
        } else {
            false
        }
    }

    /// `Metrics.incrementLoad*`: a `mock_server_load_*` counter labelled with the scenario and run, then `extra`.
    fn count(&self, state: &State, name: &'static str, extra: &[(&str, &str)]) {
        let mut attributes = vec![("scenario".to_string(), self.name().to_string()), ("run_id".to_string(), self.run_id.clone())];
        attributes.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        state.config.metrics.load_count(name, attributes, 1);
    }

    /// `customLabelsFor`: scenario then step labels, the step's winning.
    fn custom_labels(&self, step: &Step) -> Vec<(String, String)> {
        let mut merged: Vec<(String, String)> = Vec::new();
        for labels in [&self.scenario.labels, &step.labels].into_iter().flatten() {
            for (k, v) in labels {
                let Some(v) = v else { continue };
                match merged.iter_mut().find(|(key, _)| key == k) {
                    Some(entry) => entry.1 = v.clone(),
                    None => merged.push((k.clone(), v.clone())),
                }
            }
        }
        merged
    }

    fn record_check(&self, step: &str, check: &super::Check, passed: bool) {
        if passed {
            self.checks_passed.fetch_add(1, Ordering::SeqCst);
        } else {
            self.checks_failed.fetch_add(1, Ordering::SeqCst);
        }
        let source = check.source_name().to_string();
        let comparator = check.comparator_name().to_string();
        let detail = match check.source {
            Some(super::CheckSource::Header) => check.header_name.clone().unwrap_or_default(),
            Some(super::CheckSource::BodyJsonPath) => check.json_path.clone().unwrap_or_default(),
            _ => String::new(),
        };
        let key = format!("{step}|{source}|{detail}|{comparator}|{}", check.value.clone().unwrap_or_default());
        let mut aggregates = self.check_aggregates.lock();
        let index = match aggregates.iter().position(|(k, _)| *k == key) {
            Some(i) => i,
            None => {
                let result = CheckResult { step: step.to_string(), source, detail, comparator, value: check.value.clone(), passed: 0, failed: 0 };
                aggregates.push((key, CheckCounters { result }));
                aggregates.len() - 1
            }
        };
        let counters = &mut aggregates[index].1.result;
        if passed { counters.passed += 1 } else { counters.failed += 1 }
    }

    /// `checkResults`: in `ConcurrentHashMap` order of their keys.
    fn check_results(&self) -> Vec<CheckResult> {
        let aggregates = self.check_aggregates.lock();
        let keys: Vec<String> = aggregates.iter().map(|(k, _)| k.clone()).collect();
        crate::recorded::java_hashmap_order(&keys).into_iter().map(|i| aggregates[i].1.result.clone()).collect()
    }

    /// `evaluateThresholds`.
    fn evaluate_thresholds(&self, now: i64) -> Option<bool> {
        let thresholds = &self.scenario.thresholds;
        if thresholds.is_empty() {
            *self.verdict.lock() = None;
            self.threshold_results.lock().clear();
            return None;
        }
        let sent = self.requests_sent.load(Ordering::SeqCst);
        if sent <= 0 {
            return *self.verdict.lock();
        }
        let latencies = self.latencies.lock();
        let have_latency = !latencies.0.is_empty();
        let succeeded = self.succeeded.load(Ordering::SeqCst);
        let failed = self.failed.load(Ordering::SeqCst);
        let completed = succeeded + failed;
        let error_rate = if completed <= 0 { 0.0 } else { (failed as f64 / completed as f64).min(1.0) };
        let elapsed = (now - self.started_at.load(Ordering::SeqCst)).max(0);
        let throughput = sent as f64 / (elapsed as f64 / 1000.0).max(0.001);
        let (passed, check_failed) = (self.checks_passed.load(Ordering::SeqCst), self.checks_failed.load(Ordering::SeqCst));
        let checks_total = passed + check_failed;
        let check_failure_rate = if checks_total <= 0 { 0.0 } else { (check_failed as f64 / checks_total as f64).min(1.0) };
        let mut results = Vec::new();
        let mut all = true;
        for t in thresholds {
            let latency = |p: f64| if have_latency { latencies.percentile(p) as f64 } else { 0.0 };
            let observed = match t.metric_name() {
                Some("LATENCY_P50") => latency(50.0),
                Some("LATENCY_P95") => latency(95.0),
                Some("LATENCY_P99") => latency(99.0),
                Some("LATENCY_P999") => latency(99.9),
                Some("ERROR_RATE") => error_rate,
                Some("THROUGHPUT_RPS") => throughput,
                Some("CHECK_FAILURE_RATE") => check_failure_rate,
                _ => 0.0,
            };
            let satisfied = t.satisfied_by(observed);
            all &= satisfied;
            results.push(ThresholdResult { metric: t.metric_name(), comparator: t.comparator_name(), threshold: t.threshold, observed, satisfied });
        }
        *self.threshold_results.lock() = results;
        *self.verdict.lock() = Some(all);
        Some(all)
    }

    fn step_label(step: &Step, index: usize) -> String {
        step.name.clone().filter(|n| !n.trim().is_empty()).unwrap_or_else(|| index.to_string())
    }

    /// `snapshot`.
    fn snapshot(&self, state: RunState, now: i64) -> Status {
        let running = state == RunState::Running;
        let terminal = matches!(state, RunState::Completed | RunState::Stopped);
        let elapsed = if running || terminal { now - self.started_at.load(Ordering::SeqCst) } else { 0 };
        let index = self.stage_index.load(Ordering::SeqCst);
        let stages = self.scenario.stages();
        let stage_type = usize::try_from(index).ok().and_then(|i| stages.get(i)).map(|s| s.kind);
        let current_target = if !running {
            0.0
        } else if stage_type == Some(StageType::Rate) {
            *self.target_rate.lock()
        } else {
            f64::from(self.target_vus.load(Ordering::SeqCst))
        };
        let latencies = self.latencies.lock();
        let percentile = |p: f64| latencies.percentile(p);
        Status {
            name: self.name().to_string(),
            state,
            elapsed,
            current_vus: if running { self.active_vus.load(Ordering::SeqCst) } else { 0 },
            requests_sent: self.requests_sent.load(Ordering::SeqCst),
            succeeded: self.succeeded.load(Ordering::SeqCst),
            failed: self.failed.load(Ordering::SeqCst),
            p50: percentile(50.0),
            p95: percentile(95.0),
            p99: percentile(99.0),
            p999: percentile(99.9),
            dropped: self.dropped.load(Ordering::SeqCst),
            run_id: self.run_id.clone(),
            started_at_epoch: self.started_at_epoch.load(Ordering::SeqCst),
            ended_at_epoch: terminal.then_some(now),
            labels: self.scenario.labels.clone(),
            stage_index: if running { index } else { -1 },
            stage_type: if running {
                stage_type.map(|t| match t {
                    StageType::Vu => "VU",
                    StageType::Rate => "RATE",
                    StageType::Pause => "PAUSE",
                })
            } else {
                None
            },
            current_target,
            verdict: self.verdict.lock().map(|v| if v { "PASS" } else { "FAIL" }),
            aborted_by_threshold: self.aborted_by_threshold.load(Ordering::SeqCst),
            thresholds: self.threshold_results.lock().clone(),
            checks: self.check_results(),
        }
    }
}

/// The runs, active and finished.
#[derive(Default)]
pub struct Orchestrator {
    runs: Mutex<HashMap<String, Arc<Run>>>,
    terminal: Mutex<HashMap<String, Status>>,
}

impl Orchestrator {
    /// `installGaugeReaders`: (scenario, run id, active VUs, in-flight requests) of each running scenario.
    pub fn gauges(&self) -> Vec<(String, String, i32, i32)> {
        let runs = self.runs.lock();
        let mut out: Vec<_> = runs
            .values()
            .map(|r| (r.name().to_string(), r.run_id.clone(), r.active_vus.load(Ordering::SeqCst), r.in_flight_count.load(Ordering::SeqCst)))
            .collect();
        out.sort();
        out
    }

    pub fn is_active(&self, name: &str) -> bool {
        self.runs.lock().contains_key(name)
    }

    /// `statusFor`.
    pub fn status(&self, name: &str) -> Option<Status> {
        let run = self.runs.lock().get(name).cloned();
        match run {
            Some(run) => {
                let state = *run.state.lock();
                Some(run.snapshot(state, now_millis()))
            }
            None => self.terminal.lock().get(name).cloned(),
        }
    }

    /// `loadScenarioStateFor`.
    pub fn state_of(&self, name: &str) -> &'static str {
        self.status(name).map_or(RunState::Loaded, |s| s.state).name()
    }

    pub fn stop(&self, name: &str) {
        let run = self.runs.lock().get(name).cloned();
        if let Some(run) = run {
            self.terminate(&run, RunState::Stopped);
        }
    }

    pub fn stop_all(&self) {
        let names: Vec<String> = self.runs.lock().keys().cloned().collect();
        for name in names {
            self.stop(&name);
        }
    }

    /// `evictTerminalSeries`: the finished run's status is dropped and its metric series evicted.
    pub fn forget(&self, state: &State, name: &str) {
        let status = self.terminal.lock().remove(name);
        if let Some(status) = status {
            state.config.metrics.evict_load_run(&status.run_id);
        }
    }

    pub fn forget_all(&self) {
        self.terminal.lock().clear();
    }

    pub fn reset(&self) {
        self.stop_all();
        self.forget_all();
    }

    fn is_current(&self, run: &Arc<Run>) -> bool {
        self.runs.lock().get(run.name()).is_some_and(|r| Arc::ptr_eq(r, run))
    }

    /// `terminate`: the run's final status is kept; `false` when the run was already replaced or finished.
    fn terminate(&self, run: &Arc<Run>, terminal: RunState) -> bool {
        run.stopped.store(true, Ordering::SeqCst);
        let status = run.snapshot(terminal, now_millis());
        let mut runs = self.runs.lock();
        if !runs.get(run.name()).is_some_and(|r| Arc::ptr_eq(r, run)) {
            return false;
        }
        runs.remove(run.name());
        drop(runs);
        *run.state.lock() = terminal;
        self.terminal.lock().insert(run.name().to_string(), status);
        true
    }
}

/// `start`: the state the start answers with (`loadScenarioStateFor` after the first tick), or the error when the
/// scenario may not run. The run's virtual users wait at the gate until that state is read, so a short run that a
/// loaded machine lets finish before the answer is rendered is still answered `RUNNING`, as the oracle's slower JVM
/// client always does.
pub fn start(state: &Arc<State>, scenario: Scenario) -> Result<&'static str, String> {
    if let Some(message) = super::validate(state, &scenario) {
        return Err(message);
    }
    let orchestrator = &state.load.runs;
    let max_concurrent = state.config.int_property("loadGenerationMaxConcurrentScenarios", 10).max(1);
    let name = scenario.name().to_string();
    {
        let runs = orchestrator.runs.lock();
        if !runs.contains_key(&name) && runs.len() as i64 >= max_concurrent {
            return Err(format!("starting '{name}' would exceed the maximum of {max_concurrent} concurrently active load scenarios"));
        }
    }
    let now = now_millis();
    let start_delay = scenario.start_delay;
    let run = Arc::new(Run::new(state, scenario, now));
    // a run replacing an active or finished one of the same name evicts that run's series (`evictLoadRun`)
    let previous = orchestrator.runs.lock().insert(name.clone(), run.clone());
    let prior = orchestrator.terminal.lock().remove(&name);
    if let Some(previous) = previous {
        previous.stopped.store(true, Ordering::SeqCst);
        state.config.metrics.evict_load_run(&previous.run_id);
    } else if let Some(prior) = prior.filter(|p| p.run_id != run.run_id) {
        state.config.metrics.evict_load_run(&prior.run_id);
    }
    if start_delay > 0 {
        *run.state.lock() = RunState::Pending;
    } else {
        run.begin_running(now);
    }
    tick(state, &run);
    let entered = orchestrator.state_of(&name);
    run.gate.add_permits(tokio::sync::Semaphore::MAX_PERMITS);
    let (state, run) = (state.clone(), run.clone());
    tokio::spawn(crate::clock::scope(state.clock.clone(), async move {
        let mut interval = tokio::time::interval(CONTROL_TICK);
        interval.tick().await;
        loop {
            interval.tick().await;
            if run.stopped.load(Ordering::SeqCst) || !state.load.runs.is_current(&run) {
                return;
            }
            tick(&state, &run);
        }
    }));
    Ok(entered)
}

/// One control tick of `run`.
fn tick(state: &Arc<State>, run: &Arc<Run>) {
    let orchestrator = &state.load.runs;
    if run.stopped.load(Ordering::SeqCst) || !orchestrator.is_current(run) {
        return;
    }
    let now = now_millis();
    if *run.state.lock() == RunState::Pending {
        if now - run.triggered_at < run.scenario.start_delay {
            return;
        }
        run.begin_running(now);
    }
    if run.max_requests_reached() {
        complete(state, run);
        return;
    }
    let elapsed = now - run.started_at.load(Ordering::SeqCst);
    let stages = run.scenario.stages();
    let mut boundary = 0;
    let mut found = None;
    for (i, stage) in stages.iter().enumerate() {
        let duration = stage.duration.max(0);
        if elapsed < boundary + duration {
            found = Some((i, elapsed - boundary));
            break;
        }
        boundary += duration;
    }
    let Some((index, elapsed_in_stage)) = found else {
        complete(state, run);
        return;
    };
    run.stage_index.store(index as i32, Ordering::SeqCst);
    let stage = &stages[index];
    {
        let mut rate = run.rate.lock();
        if rate.active_stage != index as i32 {
            *rate = RateState { active_stage: index as i32, ..Default::default() };
        }
    }
    match stage.kind {
        StageType::Vu => {
            let target = stage.target_vus_at(elapsed_in_stage).max(0);
            run.target_vus.store(target, Ordering::SeqCst);
            let active = run.active_vus.load(Ordering::SeqCst);
            for _ in active..target {
                let vu = run.vu_sequence.fetch_add(1, Ordering::SeqCst);
                run.active_vus.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(crate::clock::scope(state.clock.clone(), virtual_user(state.clone(), run.clone(), vu, true)));
            }
        }
        StageType::Rate => {
            let target_rate = stage.target_rate_at(elapsed_in_stage);
            *run.target_rate.lock() = target_rate.max(0.0);
            let cap = stage.max_vus.filter(|m| *m > 0).map(i64::from).unwrap_or_else(|| state.config.int_property("loadGenerationMaxVirtualUsers", 50));
            let mut rate = run.rate.lock();
            if rate.last_tick == 0 {
                rate.last_tick = now;
                run.target_vus.store(run.active_vus.load(Ordering::SeqCst), Ordering::SeqCst);
                return;
            }
            let dt = (now - rate.last_tick).max(0);
            rate.last_tick = now;
            rate.deficit += target_rate * (dt as f64 / 1000.0);
            let to_start = rate.deficit.floor() as i64;
            if to_start > 0 {
                let mut started = 0;
                for _ in 0..to_start {
                    if i64::from(run.active_vus.load(Ordering::SeqCst)) >= cap {
                        break;
                    }
                    let vu = run.vu_sequence.fetch_add(1, Ordering::SeqCst);
                    run.active_vus.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(crate::clock::scope(state.clock.clone(), virtual_user(state.clone(), run.clone(), vu, false)));
                    started += 1;
                }
                rate.deficit -= started as f64;
                let shortfall = to_start - started;
                if shortfall > 0 {
                    rate.deficit = (rate.deficit - shortfall as f64).max(0.0);
                    run.dropped.fetch_add(shortfall, Ordering::SeqCst);
                }
            }
            run.target_vus.store(run.active_vus.load(Ordering::SeqCst), Ordering::SeqCst);
        }
        StageType::Pause => run.target_vus.store(0, Ordering::SeqCst),
    }
    let verdict = run.evaluate_thresholds(now);
    if verdict == Some(false) && run.scenario.abort_on_fail && elapsed >= run.scenario.abort_grace {
        run.aborted_by_threshold.store(true, Ordering::SeqCst);
        orchestrator.terminate(run, RunState::Stopped);
    }
}

fn complete(state: &State, run: &Arc<Run>) {
    run.evaluate_thresholds(now_millis());
    state.load.runs.terminate(run, RunState::Completed);
}

fn end_vu(run: &Run) {
    run.active_vus.fetch_sub(1, Ordering::SeqCst);
}

fn live(state: &State, run: &Arc<Run>) -> bool {
    !run.stopped.load(Ordering::SeqCst) && state.load.runs.is_current(run)
}

/// `tryRetireSurplus`: a looping VU above the current target retires.
fn retire_surplus(run: &Run) -> bool {
    loop {
        let active = run.active_vus.load(Ordering::SeqCst);
        if active <= run.target_vus.load(Ordering::SeqCst) {
            return false;
        }
        if run.active_vus.compare_exchange(active, active - 1, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            return true;
        }
    }
}

/// `selectIterationSteps`: every step, or one weighted draw.
fn iteration_steps(scenario: &Scenario) -> Vec<usize> {
    if !scenario.weighted || scenario.steps.is_empty() {
        return (0..scenario.steps.len()).collect();
    }
    let total: f64 = scenario.steps.iter().map(Step::weight_or_one).sum();
    let target = rand_unit() * total;
    let mut cumulative = 0.0;
    for (i, step) in scenario.steps.iter().enumerate() {
        cumulative += step.weight_or_one();
        if target < cumulative {
            return vec![i];
        }
    }
    vec![scenario.steps.len() - 1]
}

fn rand_unit() -> f64 {
    use rand_core::RngCore;
    (rand_core::OsRng.next_u64() >> 11) as f64 / (1u64 << 53) as f64
}

/// A virtual user: iterations of the steps until the run ends, it retires, or (a RATE arrival) after one.
async fn virtual_user(state: Arc<State>, run: Arc<Run>, vu: i32, looping: bool) {
    if let Ok(permit) = run.gate.acquire().await {
        permit.forget();
    }
    let mut vu_iteration: i64 = 0;
    loop {
        if !live(&state, &run) {
            end_vu(&run);
            return;
        }
        if looping && vu_iteration > 0 && retire_surplus(&run) {
            return;
        }
        let data: Row = match &run.feeder_rows {
            Some(rows) => match run.feeder_strategy {
                2 => {
                    let index = run.feeder_index.fetch_add(1, Ordering::SeqCst);
                    if index as usize >= rows.len() {
                        end_vu(&run);
                        complete(&state, &run);
                        return;
                    }
                    rows[index as usize].clone()
                }
                1 => rows[(rand_unit() * rows.len() as f64) as usize % rows.len()].clone(),
                _ => {
                    let index = run.feeder_index.fetch_add(1, Ordering::SeqCst);
                    rows[index.rem_euclid(rows.len() as i64) as usize].clone()
                }
            },
            None => Vec::new(),
        };
        let iteration_start = Instant::now();
        let mut captured: Vec<(String, String)> = Vec::new();
        let steps = iteration_steps(&run.scenario);
        for (position, &index) in steps.iter().enumerate() {
            let _ = position;
            if !live(&state, &run) {
                end_vu(&run);
                return;
            }
            if run.max_requests_reached() {
                end_vu(&run);
                complete(&state, &run);
                return;
            }
            let step = &run.scenario.steps[index];
            fire(&state, &run, step, index, vu, vu_iteration, &mut captured, &data).await;
            if !live(&state, &run) {
                end_vu(&run);
                return;
            }
            let think = step.think_time.as_ref().and_then(crate::action::delay).map(|d| d.fixed).unwrap_or_default();
            if !think.is_zero() {
                tokio::time::sleep(think).await;
            } else {
                // a step that fails without pending (render error, throttled, unresolvable host) never awaits;
                // without a yield the virtual user holds its worker and starves the stage controller and every
                // other server on the runtime (upstream's VUs are threads, preempted by the JVM)
                tokio::task::yield_now().await;
            }
        }
        // iteration finished: `fireStep` past the last step checks the run and the request cap before it
        // accounts the iteration, so the iteration that reaches the cap is not counted
        if !live(&state, &run) {
            end_vu(&run);
            return;
        }
        if run.max_requests_reached() {
            end_vu(&run);
            complete(&state, &run);
            return;
        }
        run.count(&state, "mock_server_load_iterations", &[]);
        if !looping {
            end_vu(&run);
            return;
        }
        // `pacingDelayMillis`.
        let cycle = run.scenario.pacing.as_ref().map(super::Pacing::cycle_millis).unwrap_or(0.0);
        if cycle > 0.0 {
            let delay = (cycle - iteration_start.elapsed().as_millis() as f64).round().max(0.0);
            tokio::time::sleep(Duration::from_millis(delay as u64)).await;
        }
        vu_iteration += 1;
    }
}

/// `fireStep` for one step: render, dispatch within the caps, record, check, capture.
#[allow(clippy::too_many_arguments)]
async fn fire(state: &Arc<State>, run: &Arc<Run>, step: &Step, index: usize, vu: i32, vu_iteration: i64, captured: &mut Vec<(String, String)>, data: &Row) {
    let scheduled = Instant::now();
    let label = Run::step_label(step, index);
    let iteration = Iteration {
        index: run.iteration_index.fetch_add(1, Ordering::SeqCst),
        vu_id: vu,
        vu_iteration,
        elapsed: now_millis() - run.started_at.load(Ordering::SeqCst),
        count: run.requests_sent.load(Ordering::SeqCst),
        captured: captured.clone(),
        data: data.clone(),
    };
    let rendered = match render(state, run, step, iteration) {
        Ok(r) => r,
        Err(message) => {
            crate::log::warn(state, &format!("load scenario '{}' failed to render step {index} (vu {vu} iteration {vu_iteration}): {message}", run.name()));
            run.failed.fetch_add(1, Ordering::SeqCst);
            run.requests_sent.fetch_add(1, Ordering::SeqCst);
            run.count(state, "mock_server_load_errors", &[("kind", "render")]);
            return;
        }
    };
    let Ok(permit) = run.in_flight.try_acquire() else {
        run.dropped.fetch_add(1, Ordering::SeqCst);
        run.count(state, "mock_server_load_throttled", &[("reason", "inflight_cap")]);
        return;
    };
    if !run.try_acquire_rps_token() {
        drop(permit);
        run.dropped.fetch_add(1, Ordering::SeqCst);
        run.count(state, "mock_server_load_throttled", &[("reason", "rate_limit")]);
        return;
    }
    run.requests_sent.fetch_add(1, Ordering::SeqCst);
    run.in_flight_count.fetch_add(1, Ordering::SeqCst);
    let result = crate::forward::send_json(state, &rendered).await;
    drop(permit);
    run.in_flight_count.fetch_sub(1, Ordering::SeqCst);
    let latency = scheduled.elapsed().as_millis() as i64;
    let response = result.ok();
    let error = response.as_ref().is_none_or(|r| r.status >= 500);
    if error {
        run.failed.fetch_add(1, Ordering::SeqCst);
    } else {
        run.succeeded.fetch_add(1, Ordering::SeqCst);
    }
    run.latencies.lock().record(latency);
    if state.load.runs.is_current(run) {
        record_load_request(state, run, step, &label, &rendered, response.as_ref(), error, latency);
    }
    let Some(response) = response else { return };
    let body = crate::request::decompress(response.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-encoding")).map(|(_, v)| v.as_str()), &response.body)
        .unwrap_or_else(|| response.body.clone());
    let view = super::Response { status: response.status, headers: &response.headers, body: &body };
    for check in step.checks.iter().filter(|c| c.is_valid()) {
        let passed = check.extract(&view).map(|observed| check.matches(observed.as_deref())).unwrap_or(false);
        run.record_check(&label, check, passed);
        if state.load.runs.is_current(run) {
            run.count(state, "mock_server_load_checks", &[("step", &label), ("outcome", if passed { "pass" } else { "fail" })]);
        }
    }
    for capture in &step.captures {
        let Some(name) = capture.name.as_deref().filter(|n| !n.trim().is_empty()) else { continue };
        if capture.source.is_none() {
            continue;
        }
        let value = capture.extract(&view).ok().flatten().or_else(|| capture.default_value.clone());
        if let Some(value) = value {
            match captured.iter_mut().find(|(k, _)| k == name) {
                Some(entry) => entry.1 = value,
                None => captured.push((name.to_string(), value)),
            }
        }
    }
}

/// `recordResult` → `Metrics.observeLoadRequest` (latency in whole milliseconds, as seconds; the trace id of the
/// rendered request's `traceparent` as the histogram's exemplar) and, for an error, `incrementLoadError` with
/// `classifyError`'s kind.
#[allow(clippy::too_many_arguments)]
fn record_load_request(state: &State, run: &Run, step: &Step, label: &str, rendered: &Value, response: Option<&crate::client::Upstream>, error: bool, latency_millis: i64) {
    let request = crate::forward::request_from_json(rendered);
    let route = step.name.clone().filter(|n| !n.trim().is_empty()).unwrap_or_else(|| crate::metrics::route_of(Some(&request.path)));
    let method = if request.method.is_empty() { "unknown".to_string() } else { request.method.clone() };
    let status_class = match response.map(|r| r.status) {
        Some(s @ 100..=599) => format!("{}xx", s / 100),
        _ => "unknown".into(),
    };
    // `traceIdOf`: a valid W3C `traceparent` header's trace id
    let trace_id = request
        .first_header("traceparent")
        .and_then(|t| crate::telemetry::TraceContext::parse(t, None))
        .filter(crate::telemetry::TraceContext::is_valid)
        .map(|c| c.trace_id);
    let request_bytes = request.body.len() as i64;
    let response_bytes = response.map_or(0, |r| r.body.len() as i64);
    let allowlist = crate::metrics::load_label_names(&state.config);
    let fixed = [run.name(), run.run_id.as_str(), label, route.as_str(), method.as_str(), status_class.as_str()];
    state.config.metrics.observe_load_request(&allowlist, fixed, &run.custom_labels(step), latency_millis.max(0) as f64 / 1000.0, request_bytes, response_bytes, trace_id.as_deref());
    if error {
        // `classifyError`: no response (a failed send) is a connection error; ours never times out separately
        let kind = if response.is_some() { "http_5xx" } else { "connection" };
        run.count(state, "mock_server_load_errors", &[("kind", kind)]);
    }
}

/// `IterationContext`, as templates see it (`$iteration.index`, `{{iteration.vuId}}`, …).
struct Iteration {
    index: i64,
    vu_id: i32,
    vu_iteration: i64,
    elapsed: i64,
    count: i64,
    captured: Vec<(String, String)>,
    data: Row,
}

impl JObject for Iteration {
    fn class_name(&self) -> String {
        "org.mockserver.load.IterationContext".into()
    }

    fn invoke(&self, name: &str, args: &[JValue]) -> Option<Result<Option<JValue>, JError>> {
        if !args.is_empty() {
            return None;
        }
        let v = match name {
            "getIndex" => JValue::Long(self.index),
            "getVuId" => JValue::Int(self.vu_id),
            "getVuIteration" => JValue::Long(self.vu_iteration),
            "getElapsedMillis" => JValue::Long(self.elapsed),
            "getCount" => JValue::Long(self.count),
            "getCaptured" => JValue::Map(JMap::from_entries(MapKind::Hash, self.captured.iter().map(|(k, v)| (JValue::str(k.as_str()), JValue::str(v.as_str()))))),
            "getData" => JValue::Map(JMap::from_entries(
                MapKind::Fixed,
                self.data.iter().map(|(k, v)| (JValue::str(k.as_str()), v.as_deref().map(JValue::str).unwrap_or(JValue::Null))),
            )),
            "toString" => JValue::str(self.to_java_string()),
            _ => return None,
        };
        Some(Ok(Some(v)))
    }

    fn to_java_string(&self) -> String {
        format!("org.mockserver.load.IterationContext@{:x}", (self as *const Iteration as usize) as u32)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// `RunningScenario.render`: path, body and header values that look templated (`$`, `{{`, `#`) rendered.
fn render(state: &State, run: &Run, step: &Step, iteration: Iteration) -> Result<Value, String> {
    let mut request = step.request.clone().unwrap_or_else(|| json!({}));
    let model = crate::forward::request_from_json(&request);
    let engine = run.scenario.template;
    let templated = |s: &str| s.contains('$') || s.contains("{{") || s.contains('#');
    let bindings = [("iteration", JValue::Object(Arc::new(iteration)))];
    let render = |s: &str| crate::templates::render_with(state, &run.velocity, engine, s, &model, &bindings);
    let o = request.as_object_mut().ok_or("request is not an object")?;
    if let Some(path) = o.get("path").and_then(Value::as_str).filter(|p| templated(p)).map(str::to_string) {
        o.insert("path".into(), render(&path)?.into());
    }
    let body = String::from_utf8_lossy(&model.body).into_owned();
    if !body.is_empty() && templated(&body) {
        o.insert("body".into(), render(&body)?.into());
    }
    if let Some(Value::Object(headers)) = o.get_mut("headers") {
        for values in headers.values_mut() {
            if let Value::Array(values) = values {
                for value in values.iter_mut() {
                    if let Some(text) = value.as_str().filter(|t| templated(t)).map(str::to_string) {
                        *value = render(&text)?.into();
                    }
                }
            }
        }
    }
    Ok(request)
}

/// `LoadScenarioReport.errorRate`.
fn error_rate(status: &Status) -> f64 {
    status.failed as f64 / ((status.succeeded + status.failed).max(1)) as f64
}

/// `LoadScenarioReport.runFailed`.
fn run_failed(status: &Status) -> bool {
    status.aborted_by_threshold || status.verdict == Some("FAIL") || (matches!(status.state, RunState::Completed | RunState::Stopped) && status.failed > 0)
}

/// `LoadScenarioReport.toJson`.
pub fn json_report(status: &Status) -> Value {
    let mut o = Map::new();
    o.insert("scenario".into(), status.name.clone().into());
    o.insert("runId".into(), status.run_id.clone().into());
    o.insert("state".into(), status.state.name().into());
    if let Some(v) = status.verdict {
        o.insert("verdict".into(), v.into());
    }
    o.insert("abortedByThreshold".into(), status.aborted_by_threshold.into());
    o.insert("timing".into(), json!({"startedAtEpochMillis": status.started_at_epoch, "endedAtEpochMillis": status.ended_at_epoch, "durationMillis": status.elapsed}));
    o.insert(
        "counts".into(),
        json!({"requestsSent": status.requests_sent, "succeeded": status.succeeded, "failed": status.failed, "droppedIterations": status.dropped, "errorRate": number(error_rate(status))}),
    );
    o.insert("latencyMillis".into(), json!({"p50": status.p50, "p95": status.p95, "p99": status.p99, "p999": status.p999}));
    o.insert("thresholdResults".into(), Value::Array(status.thresholds.iter().map(ThresholdResult::json).collect()));
    o.insert("checkResults".into(), Value::Array(status.checks.iter().map(CheckResult::json).collect()));
    Value::Object(o)
}

/// `formatNumber`: whole numbers without a fraction.
fn format_number(v: f64) -> String {
    if v == v.round() && v.is_finite() { format!("{}", v as i64) } else { java_compat::double_to_string(v) }
}

fn escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// `LoadScenarioReport.toJUnitXml`.
pub fn junit_report(status: &Status) -> String {
    let failed_thresholds = status.thresholds.iter().filter(|t| !t.satisfied).count();
    let failed_checks = status.checks.iter().filter(|c| c.failed > 0).count();
    let failed_run = run_failed(status);
    let tests = status.thresholds.len() + status.checks.len() + 1;
    let failures = failed_thresholds + failed_checks + usize::from(failed_run);
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!("<testsuite name=\"load:{}\" tests=\"{tests}\" failures=\"{failures}\" time=\"{:.3}\">\n", escape(&status.name), status.elapsed as f64 / 1000.0));
    xml.push_str("  <properties>\n");
    let property = |xml: &mut String, name: &str, value: &str| xml.push_str(&format!("    <property name=\"{}\" value=\"{}\"/>\n", escape(name), escape(value)));
    property(&mut xml, "runId", &status.run_id);
    property(&mut xml, "state", status.state.name());
    property(&mut xml, "verdict", status.verdict.unwrap_or(""));
    property(&mut xml, "requestsSent", &status.requests_sent.to_string());
    property(&mut xml, "succeeded", &status.succeeded.to_string());
    property(&mut xml, "failed", &status.failed.to_string());
    property(&mut xml, "droppedIterations", &status.dropped.to_string());
    property(&mut xml, "errorRate", &java_compat::double_to_string(error_rate(status)));
    property(&mut xml, "p50Millis", &status.p50.to_string());
    property(&mut xml, "p95Millis", &status.p95.to_string());
    property(&mut xml, "p99Millis", &status.p99.to_string());
    property(&mut xml, "p999Millis", &status.p999.to_string());
    xml.push_str("  </properties>\n");
    let null = |v: Option<&str>| v.unwrap_or("null").to_string();
    for t in &status.thresholds {
        let name = format!("threshold: {} {} {}", null(t.metric), null(t.comparator), format_number(t.threshold));
        xml.push_str(&format!("  <testcase name=\"{}\">\n", escape(&name)));
        if !t.satisfied {
            let message = format!("observed {} {} {} not satisfied", format_number(t.observed), null(t.comparator), format_number(t.threshold));
            xml.push_str(&format!("    <failure message=\"{}\"/>\n", escape(&message)));
        }
        xml.push_str("  </testcase>\n");
    }
    for c in &status.checks {
        let detail = if c.detail.is_empty() { String::new() } else { format!(" {}", c.detail) };
        let name = format!("check: step {} {}{detail} {} {}", c.step, c.source, c.comparator, null(c.value.as_deref()));
        xml.push_str(&format!("  <testcase name=\"{}\" assertions=\"{}\">\n", escape(&name), c.passed + c.failed));
        if c.failed > 0 {
            let message = format!("{} of {} evaluations failed", c.failed, c.passed + c.failed);
            xml.push_str(&format!("    <failure message=\"{}\"/>\n", escape(&message)));
        }
        xml.push_str("  </testcase>\n");
    }
    xml.push_str("  <testcase name=\"run completed\">\n");
    if failed_run {
        let message = if status.aborted_by_threshold {
            "run aborted early by an abortOnFail threshold breach".to_string()
        } else if status.verdict == Some("FAIL") {
            "run finished with a FAIL threshold verdict".to_string()
        } else {
            format!("run finished in state {} with {} failed request(s)", status.state.name(), status.failed)
        };
        xml.push_str(&format!("    <failure message=\"{}\"/>\n", escape(&message)));
    }
    let out = format!(
        "requestsSent={} succeeded={} failed={} errorRate={} p95Millis={} p99Millis={}",
        status.requests_sent,
        status.succeeded,
        status.failed,
        format_number(error_rate(status)),
        status.p95,
        status.p99
    );
    xml.push_str(&format!("    <system-out>{}</system-out>\n", escape(&out)));
    xml.push_str("  </testcase>\n</testsuite>\n");
    xml
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highest_equivalent_values_follow_hdr_histogram() {
        assert_eq!(highest_equivalent(0), 0);
        assert_eq!(highest_equivalent(2047), 2047);
        assert_eq!(highest_equivalent(2048), 2049);
        assert_eq!(highest_equivalent(4096), 4099);
    }

    #[test]
    fn percentiles_use_the_rounded_rank() {
        let mut l = Latencies::default();
        for v in [5, 1, 3] {
            l.record(v);
        }
        assert_eq!(l.percentile(50.0), 3);
        assert_eq!(l.percentile(99.9), 5);
    }
}

//! `ChaosExperimentOrchestrator` and `/mockserver/chaosExperiment`: staged experiments that own the service (and, when
//! a stage has TCP profiles, the TCP) chaos registries, advancing on timers; deferred (`startDelayMillis`,
//! `cronSchedule`) and recurring starts; SLO verdicts over the experiment window, with a live SLO-breach halt and a
//! baseline pre-check; a bounded history; and the saved profile library (`ChaosProfileLibrary`), which outlives
//! `reset`.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use super::{HostProfile, HttpChaosProfile, TcpChaosProfile, as_boolean, as_long, as_text, now_millis};
use crate::slo::{Criteria, Verdict, Window};
use crate::state::State;

const MAX_STAGES: usize = 50;
const MAX_STAGE_DURATION_MILLIS: i64 = 24 * 60 * 60 * 1000;
const MAX_START_DELAY_MILLIS: i64 = 7 * 24 * 60 * 60 * 1000;
const SLO_PROBE_INTERVAL: Duration = Duration::from_millis(1000);
pub const MAX_HISTORY: usize = 50;
/// `ChaosProfileLibrary.BACKEND_NAMESPACE`.
pub const BACKEND_NAMESPACE: &str = "chaos-profiles";

#[derive(Clone)]
pub struct Stage {
    duration_millis: i64,
    /// Host → profile, in the order given.
    profiles: Vec<(String, HttpChaosProfile)>,
    tcp_profiles: Vec<(String, TcpChaosProfile)>,
}

/// `ExperimentDefinition`.
#[derive(Clone)]
pub struct Definition {
    pub name: Option<String>,
    stages: Vec<Stage>,
    pub loop_: bool,
    start_delay_millis: i64,
    cron_schedule: Option<String>,
    slo_criteria: Option<Criteria>,
    recurring: bool,
    baseline_window_millis: i64,
}

impl Definition {
    fn uses_tcp_profiles(&self) -> bool {
        self.stages.iter().any(|s| !s.tcp_profiles.is_empty())
    }

    fn has_cron(&self) -> bool {
        self.cron_schedule.as_deref().is_some_and(|c| !c.trim().is_empty())
    }

    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }

    /// `ExperimentDefinition.fromJson`; the error is an `IllegalArgumentException`'s message.
    pub fn from_json(node: &Value) -> Result<Definition, String> {
        let mut stages = Vec::new();
        if let Some(Value::Array(items)) = node.get("stages") {
            for stage in items {
                let duration_millis = as_long(stage.get("durationMillis"));
                let mut profiles = Vec::new();
                if let Some(Value::Object(map)) = stage.get("profiles") {
                    for (host, v) in map {
                        let p = HttpChaosProfile::from_json(v).map_err(|e| format!("invalid chaos profile for host '{host}': {}", e.text()))?;
                        profiles.push((host.clone(), p));
                    }
                }
                let mut tcp_profiles = Vec::new();
                if let Some(Value::Object(map)) = stage.get("tcpProfiles") {
                    for (host, v) in map {
                        let p = TcpChaosProfile::from_json(v).map_err(|e| format!("invalid TCP chaos profile for host '{host}': {}", e.text()))?;
                        tcp_profiles.push((host.clone(), p));
                    }
                }
                stages.push(Stage { duration_millis, profiles, tcp_profiles });
            }
        }
        let slo_criteria = match node.get("sloCriteria") {
            Some(v @ Value::Object(_)) => Some(Criteria::from_json(v).map_err(|e| format!("invalid sloCriteria: {}", e.tree_text()))?),
            _ => None,
        };
        Ok(Definition {
            name: as_text(node.get("name")),
            stages,
            loop_: as_boolean(node.get("loop")),
            start_delay_millis: as_long(node.get("startDelayMillis")),
            cron_schedule: node.get("cronSchedule").and_then(Value::as_str).map(str::to_string),
            slo_criteria,
            recurring: as_boolean(node.get("recurring")),
            baseline_window_millis: as_long(node.get("baselineWindowMillis")),
        })
    }

    /// `ExperimentDefinition.toJson`.
    fn to_json(&self) -> Value {
        let mut o = Map::new();
        o.insert("name".into(), self.name.clone().map_or(Value::Null, Value::from));
        o.insert("loop".into(), json!(self.loop_));
        if self.recurring {
            o.insert("recurring".into(), json!(true));
        }
        if self.start_delay_millis > 0 {
            o.insert("startDelayMillis".into(), json!(self.start_delay_millis));
        }
        if self.baseline_window_millis > 0 {
            o.insert("baselineWindowMillis".into(), json!(self.baseline_window_millis));
        }
        if let Some(cron) = self.cron_schedule.as_ref().filter(|c| !c.trim().is_empty()) {
            o.insert("cronSchedule".into(), json!(cron));
        }
        let stages = self
            .stages
            .iter()
            .map(|s| {
                let mut stage = Map::new();
                stage.insert("durationMillis".into(), json!(s.duration_millis));
                stage.insert("profiles".into(), Value::Object(s.profiles.iter().map(|(h, p)| (h.clone(), p.to_json())).collect()));
                if !s.tcp_profiles.is_empty() {
                    stage.insert("tcpProfiles".into(), Value::Object(s.tcp_profiles.iter().map(|(h, p)| (h.clone(), p.to_json())).collect()));
                }
                Value::Object(stage)
            })
            .collect();
        o.insert("stages".into(), Value::Array(stages));
        if let Some(c) = &self.slo_criteria {
            o.insert("sloCriteria".into(), c.to_json());
        }
        Value::Object(o)
    }
}

/// `CronSchedule`: five fields, minute granularity, evaluated in the local time zone.
pub struct Cron {
    minutes: Vec<bool>,
    hours: Vec<bool>,
    days_of_month: Vec<bool>,
    months: Vec<bool>,
    days_of_week: Vec<bool>,
    dom_restricted: bool,
    dow_restricted: bool,
}

impl Cron {
    pub fn parse(expression: &str) -> Result<Cron, String> {
        if expression.trim().is_empty() {
            return Err("cron expression is blank".into());
        }
        let fields: Vec<&str> = expression.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(format!("expected 5 fields (minute hour day-of-month month day-of-week) but got {}", fields.len()));
        }
        let mut days_of_week = field(fields[4], 0, 7, "day-of-week")?;
        if days_of_week[7] {
            days_of_week[0] = true;
            days_of_week[7] = false;
        }
        Ok(Cron {
            minutes: field(fields[0], 0, 59, "minute")?,
            hours: field(fields[1], 0, 23, "hour")?,
            days_of_month: field(fields[2], 1, 31, "day-of-month")?,
            months: field(fields[3], 1, 12, "month")?,
            days_of_week,
            dom_restricted: fields[2].trim() != "*",
            dow_restricted: fields[4].trim() != "*",
        })
    }

    /// `millisUntilNext`: to the next matching minute boundary, searching a year ahead; 0 when none matches.
    pub fn millis_until_next(&self, from_millis: i64) -> i64 {
        use chrono::{Datelike, TimeZone, Timelike};
        let Some(from) = chrono::Local.timestamp_millis_opt(from_millis).single() else { return 0 };
        let mut candidate = from.with_second(0).and_then(|t| t.with_nanosecond(0)).unwrap_or(from) + chrono::Duration::minutes(1);
        for _ in 0..366 * 24 * 60 {
            let dom = self.days_of_month[candidate.day() as usize];
            let dow = self.days_of_week[candidate.weekday().num_days_from_sunday() as usize];
            let day = if self.dom_restricted && self.dow_restricted { dom || dow } else { dom && dow };
            if self.minutes[candidate.minute() as usize] && self.hours[candidate.hour() as usize] && self.months[candidate.month() as usize] && day {
                return (candidate.timestamp_millis() - from_millis).max(0);
            }
            candidate += chrono::Duration::minutes(1);
        }
        0
    }
}

fn field(text: &str, min: i64, max: i64, name: &str) -> Result<Vec<bool>, String> {
    let mut set = vec![false; max as usize + 1];
    for part in text.trim().split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(format!("{name} field has an empty element"));
        }
        let int = |v: &str, what: &str| v.trim().parse::<i64>().map_err(|_| format!("{what} field has non-numeric value '{v}'"));
        let (range, step) = match part.split_once('/') {
            Some((range, step)) => {
                let step = int(step, &format!("{name} step"))?;
                if step <= 0 {
                    return Err(format!("{name} step must be > 0 in '{part}'"));
                }
                (range, Some(step))
            }
            None => (part, None),
        };
        let (start, end) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (int(a, name)?, int(b, name)?)
        } else {
            let v = int(range, name)?;
            (v, if step.is_some() { max } else { v })
        };
        if start < min || end > max || start > end {
            return Err(format!("{name} value out of range in '{part}' (allowed {min}-{max})"));
        }
        let mut v = start;
        while v <= end {
            set[v as usize] = true;
            v += step.unwrap_or(1);
        }
    }
    if !set.iter().any(|b| *b) {
        return Err(format!("{name} field '{text}' matches no values"));
    }
    Ok(set)
}

struct Running {
    definition: Definition,
    /// Identifies this run; timers of a replaced or stopped run find it gone.
    generation: u64,
    started_at: i64,
    current_stage: usize,
    stage_started_at: i64,
    status: &'static str,
    loop_iteration: i64,
    scheduled_start_at: i64,
    ended_at: i64,
    verdict: Option<Value>,
    recurrence_iteration: i64,
}

struct HistoryEntry {
    name: Option<String>,
    status: &'static str,
    verdict: Option<Value>,
    terminated_at: i64,
}

#[derive(Default)]
struct Inner {
    current: Option<Running>,
    generation: u64,
    last_terminated_status: Option<&'static str>,
    last_terminated_verdict: Option<Value>,
    history: VecDeque<HistoryEntry>,
    tasks: Vec<tokio::task::AbortHandle>,
}

/// The orchestrator, and the saved profile library.
#[derive(Default)]
pub struct Experiments {
    inner: Mutex<Inner>,
    /// `ChaosProfileLibrary`: the state backend's `chaos-profiles` store (see [`Experiments::attach_library`]).
    library: crate::state_backend::registry::Registry,
}

impl Experiments {
    /// `start`: `Err` is the refusal message (a validation error, or `aborted_baseline_unhealthy`).
    pub fn start(&self, state: &Arc<State>, definition: Definition) -> Result<(), String> {
        validate(&definition)?;
        let mut inner = self.inner.lock();
        if definition.baseline_window_millis > 0 && let Some(criteria) = &definition.slo_criteria {
            let now = now_millis();
            let baseline = evaluate(state, criteria, now - definition.baseline_window_millis, now);
            let result = baseline.as_ref().map(|(r, _)| *r);
            if result != Some(Verdict::Pass) {
                let verdict = baseline.map(|(_, v)| v);
                inner.last_terminated_status = Some("aborted_baseline_unhealthy");
                inner.last_terminated_verdict = verdict.clone();
                record_history(&mut inner, definition.name.clone(), "aborted_baseline_unhealthy", verdict, now);
                let shown = result.map_or("null", Verdict::name);
                crate::log::warn(state, &format!("chaos experiment '{}' refused to start: steady-state baseline unhealthy over {} ms window (verdict {shown})", name(&definition), definition.baseline_window_millis));
                return Err(format!("aborted_baseline_unhealthy: steady-state SLO did not hold over the {} ms baseline window (verdict {shown})", definition.baseline_window_millis));
            }
        }
        stop_internal(state, &mut inner, false);
        let now = now_millis();
        inner.generation += 1;
        let generation = inner.generation;
        let delay = start_delay(&definition, now);
        inner.current = Some(Running {
            definition,
            generation,
            started_at: now,
            current_stage: 0,
            stage_started_at: now,
            status: "starting",
            loop_iteration: 0,
            scheduled_start_at: 0,
            ended_at: 0,
            verdict: None,
            recurrence_iteration: 0,
        });
        if delay > 0 {
            let running = inner.current.as_mut().expect("just set");
            running.status = "scheduled";
            running.scheduled_start_at = now + delay;
            self.schedule(state, &mut inner, generation, delay, Timer::Start);
        } else {
            self.begin(state, &mut inner);
        }
        Ok(())
    }

    fn begin(&self, state: &Arc<State>, inner: &mut Inner) {
        let Some(running) = inner.current.as_mut() else { return };
        apply_stage(state, running, 0);
        let (generation, duration, slo) = (running.generation, running.definition.stages[0].duration_millis, running.definition.slo_criteria.is_some());
        crate::log::info(state, &format!("chaos experiment '{}' started with {} stage(s), loop={}", name(&running.definition), running.definition.stages.len(), running.definition.loop_));
        self.schedule(state, inner, generation, duration, Timer::Advance);
        if slo {
            self.schedule(state, inner, generation, SLO_PROBE_INTERVAL.as_millis() as i64, Timer::Probe);
        }
    }

    fn schedule(&self, state: &Arc<State>, inner: &mut Inner, generation: u64, delay_millis: i64, timer: Timer) {
        let state = state.clone();
        let task = tokio::spawn(crate::clock::scope(state.clock.clone(), async move {
            tokio::time::sleep(Duration::from_millis(delay_millis.max(0) as u64)).await;
            state.chaos.experiments.fire(&state, generation, timer);
        }));
        inner.tasks.retain(|t| !t.is_finished());
        inner.tasks.push(task.abort_handle());
    }

    fn fire(&self, state: &Arc<State>, generation: u64, timer: Timer) {
        let mut inner = self.inner.lock();
        if inner.current.as_ref().is_none_or(|r| r.generation != generation) {
            return;
        }
        match timer {
            Timer::Start => {
                if inner.current.as_ref().is_some_and(|r| r.status == "scheduled") {
                    self.begin(state, &mut inner);
                }
            }
            Timer::Advance => self.advance(state, &mut inner),
            Timer::Probe => {
                if inner.current.as_ref().is_some_and(|r| r.status == "running") && !check_slo_breach(state, &mut inner) {
                    self.schedule(state, &mut inner, generation, SLO_PROBE_INTERVAL.as_millis() as i64, Timer::Probe);
                }
            }
        }
    }

    /// `advanceStage`.
    fn advance(&self, state: &Arc<State>, inner: &mut Inner) {
        let Some(running) = inner.current.as_ref() else { return };
        if running.status == "running" && stage_chaos_cleared(state, running) {
            let mut running = inner.current.take().expect("present");
            crate::log::warn(state, &format!("chaos experiment '{}' halted by auto-halt safety circuit-breaker at stage {}", name(&running.definition), running.current_stage));
            running.status = "halted_by_auto_halt";
            running.ended_at = now_millis();
            finalize_verdict(state, inner, &mut running, true);
            inner.last_terminated_status = Some(running.status);
            record_run(inner, &running);
            return;
        }
        if check_slo_breach(state, inner) {
            return;
        }
        let running = inner.current.as_mut().expect("present");
        let next = running.current_stage + 1;
        let generation = running.generation;
        if next < running.definition.stages.len() {
            apply_stage(state, running, next);
            let duration = running.definition.stages[next].duration_millis;
            crate::log::info(state, &format!("chaos experiment '{}' advanced to stage {}/{}", name(&running.definition), next + 1, running.definition.stages.len()));
            self.schedule(state, inner, generation, duration, Timer::Advance);
        } else if running.definition.loop_ {
            running.loop_iteration += 1;
            apply_stage(state, running, 0);
            let duration = running.definition.stages[0].duration_millis;
            crate::log::info(state, &format!("chaos experiment '{}' looping, iteration {}", name(&running.definition), running.loop_iteration));
            self.schedule(state, inner, generation, duration, Timer::Advance);
        } else {
            let mut running = inner.current.take().expect("present");
            running.status = "completed";
            running.ended_at = now_millis();
            finalize_verdict(state, inner, &mut running, false);
            inner.last_terminated_status = Some(running.status);
            clear_chaos(state, &running);
            record_run(inner, &running);
            crate::log::info(state, &format!("chaos experiment '{}' completed after {} stage(s)", name(&running.definition), running.definition.stages.len()));
            if running.definition.recurring && running.definition.has_cron() {
                self.rearm(state, inner, running);
            }
        }
    }

    /// `rearmForNextOccurrence`.
    fn rearm(&self, state: &Arc<State>, inner: &mut Inner, finished: Running) {
        let now = now_millis();
        let delay = finished.definition.cron_schedule.as_deref().and_then(|c| Cron::parse(c).ok()).map_or(0, |c| c.millis_until_next(now));
        if delay <= 0 {
            crate::log::info(state, &format!("chaos experiment '{}' recurring: no further cron occurrence, stopping", name(&finished.definition)));
            return;
        }
        inner.generation += 1;
        let generation = inner.generation;
        crate::log::info(state, &format!("chaos experiment '{}' recurring: re-armed for the next cron occurrence in {delay} ms (run #{})", name(&finished.definition), finished.recurrence_iteration + 1));
        inner.current = Some(Running {
            definition: finished.definition,
            generation,
            started_at: now,
            current_stage: 0,
            stage_started_at: now,
            status: "scheduled",
            loop_iteration: 0,
            scheduled_start_at: now + delay,
            ended_at: 0,
            verdict: None,
            recurrence_iteration: finished.recurrence_iteration + 1,
        });
        self.schedule(state, inner, generation, delay, Timer::Start);
    }

    /// `stop` (`DELETE /mockserver/chaosExperiment`).
    pub fn stop(&self, state: &State) {
        let mut inner = self.inner.lock();
        stop_internal(state, &mut inner, false);
    }

    /// `reset`: stops the experiment and forgets its outcome and the history; the profile library stays.
    pub fn reset(&self, state: &State) {
        let mut inner = self.inner.lock();
        stop_internal(state, &mut inner, false);
        inner.last_terminated_status = None;
        inner.last_terminated_verdict = None;
        inner.history.clear();
    }

    /// `getStatus().toJson()`, or `None` when nothing has run since the last reset.
    pub fn status(&self) -> Option<Value> {
        let inner = self.inner.lock();
        let Some(running) = &inner.current else {
            let terminated = inner.last_terminated_status?;
            return Some(status_json(None, terminated, 0, 0, 0, 0, 0, 0, None, 0, inner.last_terminated_verdict.as_ref()));
        };
        let now = now_millis();
        let d = &running.definition;
        if running.status == "scheduled" {
            let remaining = (running.scheduled_start_at - now).max(0);
            return Some(status_json(d.name.as_deref(), running.status, 0, d.stages.len(), 0, 0, running.loop_iteration, now - running.started_at, Some(d), remaining, running.verdict.as_ref()));
        }
        let stage_elapsed = now - running.stage_started_at;
        let stage_remaining = d.stages.get(running.current_stage).map_or(0, |s| (s.duration_millis - stage_elapsed).max(0));
        Some(status_json(
            d.name.as_deref(),
            running.status,
            running.current_stage,
            d.stages.len(),
            stage_elapsed,
            stage_remaining,
            running.loop_iteration,
            now - running.started_at,
            Some(d),
            0,
            running.verdict.as_ref(),
        ))
    }

    /// The most recent terminated runs, newest first.
    pub fn history(&self) -> Vec<Value> {
        let inner = self.inner.lock();
        inner
            .history
            .iter()
            .rev()
            .take(MAX_HISTORY)
            .map(|e| {
                let mut o = Map::new();
                o.insert("name".into(), e.name.clone().map_or(Value::Null, Value::from));
                o.insert("status".into(), json!(e.status));
                o.insert("terminatedAtMillis".into(), json!(e.terminated_at));
                if let Some(v) = &e.verdict {
                    o.insert("verdict".into(), v.clone());
                }
                Value::Object(o)
            })
            .collect()
    }

    // --- `ChaosProfileLibrary` ---

    /// `save`: the definition is stored with its `name` set to the profile's.
    pub fn save_profile(&self, name: &str, definition: &Value) -> Result<(), String> {
        if !valid_profile_name(name) {
            return Err("profile name must be 1-128 characters of letters, digits, space, '.', '_' or '-' (no leading or trailing space)".into());
        }
        let Value::Object(o) = definition else { return Err("profile body must be a JSON object experiment definition".into()) };
        let mut copy = o.clone();
        copy.insert("name".into(), json!(name));
        self.library.put(name, Value::Object(copy)).map_err(|e| e.to_string())
    }

    pub fn profile(&self, name: &str) -> Option<Value> {
        self.library.get(name)
    }

    /// `list`: in ascending name order.
    pub fn profile_names(&self) -> Vec<String> {
        self.library.names()
    }

    pub fn delete_profile(&self, name: &str) -> bool {
        self.library.remove(name)
    }

    /// `new ChaosProfileLibrary(stateBackend)`: the profiles live in the backend's `chaos-profiles` store, single-node
    /// too (so a reset leaves them, and a clustered fleet shares them).
    pub fn attach_library(&self, backend: &dyn crate::state_backend::StateBackend) {
        self.library.attach(backend, BACKEND_NAMESPACE);
    }
}

#[derive(Clone, Copy)]
enum Timer {
    Start,
    Advance,
    Probe,
}

fn name(d: &Definition) -> &str {
    d.name.as_deref().unwrap_or("null")
}

/// `ChaosProfileLibrary.VALID_NAME`.
fn valid_profile_name(name: &str) -> bool {
    let ok_edge = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    let chars: Vec<char> = name.chars().collect();
    !chars.is_empty()
        && chars.len() <= 128
        && ok_edge(chars[0])
        && ok_edge(*chars.last().unwrap())
        && chars.iter().all(|c| ok_edge(*c) || *c == ' ')
}

/// `validate`.
fn validate(d: &Definition) -> Result<(), String> {
    if d.name.as_deref().is_none_or(|n| n.trim().is_empty()) {
        return Err("'name' is required".into());
    }
    if d.stages.is_empty() {
        return Err("'stages' must contain at least one stage".into());
    }
    if d.stages.len() > MAX_STAGES {
        return Err(format!("'stages' exceeds maximum of {MAX_STAGES}"));
    }
    if d.start_delay_millis < 0 {
        return Err("'startDelayMillis' must be >= 0".into());
    }
    if d.baseline_window_millis < 0 {
        return Err("'baselineWindowMillis' must be >= 0".into());
    }
    if d.baseline_window_millis > MAX_STAGE_DURATION_MILLIS {
        return Err(format!("'baselineWindowMillis' exceeds maximum of {MAX_STAGE_DURATION_MILLIS} ms (24h)"));
    }
    if d.baseline_window_millis > 0 && d.slo_criteria.is_none() {
        return Err("'baselineWindowMillis' requires 'sloCriteria' to evaluate the steady state against".into());
    }
    if d.recurring && !d.has_cron() {
        return Err("'recurring' requires a 'cronSchedule' to re-arm from".into());
    }
    if d.start_delay_millis > MAX_START_DELAY_MILLIS {
        return Err(format!("'startDelayMillis' exceeds maximum of {MAX_START_DELAY_MILLIS} ms (7 days)"));
    }
    if let Some(cron) = d.cron_schedule.as_deref().filter(|c| !c.trim().is_empty()) {
        let cron = Cron::parse(cron).map_err(|e| format!("'cronSchedule' is invalid: {e}"))?;
        if cron.millis_until_next(now_millis()) == 0 {
            return Err("'cronSchedule' never matches a valid time".into());
        }
    }
    for (i, stage) in d.stages.iter().enumerate() {
        if stage.duration_millis <= 0 {
            return Err(format!("stage[{i}].durationMillis must be > 0"));
        }
        if stage.duration_millis > MAX_STAGE_DURATION_MILLIS {
            return Err(format!("stage[{i}].durationMillis exceeds maximum of {MAX_STAGE_DURATION_MILLIS} ms (24h)"));
        }
        if stage.profiles.is_empty() && stage.tcp_profiles.is_empty() {
            return Err(format!("stage[{i}] must have at least one host/profile entry"));
        }
    }
    Ok(())
}

/// `resolveStartDelayMillis`: the later of the fixed delay and the next cron boundary.
fn start_delay(d: &Definition, now: i64) -> i64 {
    let mut delay = d.start_delay_millis.max(0);
    if let Some(cron) = d.cron_schedule.as_deref().filter(|c| !c.trim().is_empty()).and_then(|c| Cron::parse(c).ok()) {
        delay = delay.max(cron.millis_until_next(now));
    }
    delay
}

/// `applyStage`: the stage's profiles replace the service registry's (and, for an experiment with TCP profiles, the
/// TCP registry's).
fn apply_stage(state: &State, running: &mut Running, index: usize) {
    running.current_stage = index;
    running.stage_started_at = now_millis();
    running.status = "running";
    let stage = &running.definition.stages[index];
    state.chaos.service.reset();
    for (host, profile) in &stage.profiles {
        state.chaos.service.put(host, profile.clone(), 0);
    }
    if running.definition.uses_tcp_profiles() {
        state.chaos.tcp.reset();
        for (host, profile) in &stage.tcp_profiles {
            state.chaos.tcp.put(host, profile.clone(), 0);
        }
    }
}

fn clear_chaos(state: &State, running: &Running) {
    state.chaos.service.reset();
    if running.definition.uses_tcp_profiles() {
        state.chaos.tcp.reset();
    }
}

/// `stageChaosCleared`: every registry the current stage populated is empty (auto-halt, or a manual clear).
fn stage_chaos_cleared(state: &State, running: &Running) -> bool {
    let Some(stage) = running.definition.stages.get(running.current_stage) else { return false };
    let (http, tcp) = (!stage.profiles.is_empty(), !stage.tcp_profiles.is_empty());
    if !http && !tcp {
        return false;
    }
    (!http || state.chaos.service.is_empty()) && (!tcp || state.chaos.tcp.is_empty())
}

/// The criteria evaluated over an explicit window, keeping its `minimumSampleCount` as given.
fn evaluate(state: &State, criteria: &Criteria, from: i64, to: i64) -> Option<(Verdict, Value)> {
    let scoped = criteria.with_window(Window::explicit(from, to));
    crate::slo::evaluate(&state.config.slo, &scoped).ok().map(|e| (e.result, e.json))
}

/// `finalizeVerdict`: an auto-halted run fails whatever its samples say.
fn finalize_verdict(state: &State, inner: &mut Inner, running: &mut Running, auto_halted: bool) {
    let Some(criteria) = &running.definition.slo_criteria else { return };
    let end = now_millis();
    running.ended_at = end;
    let verdict = evaluate(state, criteria, running.started_at, end).map(|(result, mut json)| {
        if auto_halted && result != Verdict::Fail {
            json["result"] = json!("FAIL");
        }
        json
    });
    running.verdict = verdict.clone();
    inner.last_terminated_verdict = verdict;
}

/// `checkSloBreachAndHalt`.
fn check_slo_breach(state: &State, inner: &mut Inner) -> bool {
    let Some(running) = inner.current.as_ref() else { return false };
    let Some(criteria) = running.definition.slo_criteria.as_ref().filter(|_| running.status == "running") else { return false };
    let Some((Verdict::Fail, verdict)) = evaluate(state, criteria, running.started_at, now_millis()) else { return false };
    let mut running = inner.current.take().expect("present");
    crate::log::warn(state, &format!("chaos experiment '{}' halted by SLO breach at stage {} (verdict FAIL)", name(&running.definition), running.current_stage));
    running.status = "halted_by_slo_breach";
    running.ended_at = now_millis();
    running.verdict = Some(verdict.clone());
    inner.last_terminated_status = Some(running.status);
    inner.last_terminated_verdict = Some(verdict);
    clear_chaos(state, &running);
    record_run(inner, &running);
    true
}

/// `stopInternal`.
fn stop_internal(state: &State, inner: &mut Inner, auto_halted: bool) {
    for task in inner.tasks.drain(..) {
        task.abort();
    }
    let Some(mut running) = inner.current.take() else { return };
    running.status = if auto_halted { "halted_by_auto_halt" } else { "stopped" };
    running.ended_at = now_millis();
    finalize_verdict(state, inner, &mut running, auto_halted);
    inner.last_terminated_status = Some(running.status);
    clear_chaos(state, &running);
    record_run(inner, &running);
    crate::log::info(state, &format!("chaos experiment '{}' {}", name(&running.definition), running.status));
}

fn record_run(inner: &mut Inner, running: &Running) {
    let ended = if running.ended_at > 0 { running.ended_at } else { now_millis() };
    record_history(inner, running.definition.name.clone(), running.status, running.verdict.clone(), ended);
}

fn record_history(inner: &mut Inner, name: Option<String>, status: &'static str, verdict: Option<Value>, terminated_at: i64) {
    if inner.history.len() >= MAX_HISTORY {
        inner.history.pop_front();
    }
    inner.history.push_back(HistoryEntry { name, status, verdict, terminated_at });
}

#[allow(clippy::too_many_arguments)]
fn status_json(
    name: Option<&str>,
    status: &str,
    current_stage: usize,
    total_stages: usize,
    stage_elapsed: i64,
    stage_remaining: i64,
    loop_iteration: i64,
    total_elapsed: i64,
    definition: Option<&Definition>,
    start_remaining: i64,
    verdict: Option<&Value>,
) -> Value {
    let mut o = Map::new();
    o.insert("name".into(), name.map_or(Value::Null, Value::from));
    o.insert("status".into(), json!(status));
    o.insert("currentStageIndex".into(), json!(current_stage));
    o.insert("totalStages".into(), json!(total_stages));
    o.insert("stageElapsedMillis".into(), json!(stage_elapsed));
    o.insert("stageRemainingMillis".into(), json!(stage_remaining));
    o.insert("loopIteration".into(), json!(loop_iteration));
    o.insert("totalElapsedMillis".into(), json!(total_elapsed));
    if status == "scheduled" {
        o.insert("startRemainingMillis".into(), json!(start_remaining));
    }
    if let Some(d) = definition {
        o.insert("experiment".into(), d.to_json());
    }
    if let Some(v) = verdict {
        o.insert("experimentVerdict".into(), v.clone());
    }
    Value::Object(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cron_fields() {
        assert!(Cron::parse("0 2 * * *").is_ok());
        assert_eq!(Cron::parse("* * *").err().unwrap(), "expected 5 fields (minute hour day-of-month month day-of-week) but got 3");
        assert_eq!(Cron::parse("60 * * * *").err().unwrap(), "minute value out of range in '60' (allowed 0-59)");
        assert_eq!(Cron::parse("*/0 * * * *").err().unwrap(), "minute step must be > 0 in '*/0'");
        assert_eq!(Cron::parse("a * * * *").err().unwrap(), "minute field has non-numeric value 'a'");
        assert_eq!(Cron::parse("0 0 31 2 *").unwrap().millis_until_next(now_millis()), 0);
    }

    #[test]
    fn profile_names() {
        assert!(valid_profile_name("nightly storm-1.v2"));
        assert!(!valid_profile_name(" x"));
        assert!(!valid_profile_name("a/b"));
        assert!(!valid_profile_name(""));
    }
}

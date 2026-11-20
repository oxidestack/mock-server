//! SLO verdicts (`docs/code/slo-verdicts.md`): with `sloTrackingEnabled`, every forwarded round-trip records a sample
//! (`SloSampleStore`); `PUT /mockserver/verifySLO` evaluates an `SloCriteria` over a window into a PASS / FAIL /
//! INCONCLUSIVE `SloVerdict` (`SloEvaluator`), answered 406 on FAIL. Chaos experiments reuse the evaluator.

use std::collections::VecDeque;

use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use crate::chaos::bind::{Bean, BindError};
use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;

/// `Scope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Inbound,
    Forward,
}

struct Sample {
    epoch_millis: i64,
    latency_millis: i64,
    error: bool,
    scope: Scope,
    host: String,
}

/// `SloSampleStore`: a window bounded by `sloWindowMaxSamples` and by age (`sloWindowRetentionMillis`, relative to
/// the newest sample).
#[derive(Default)]
pub struct Samples {
    samples: Mutex<VecDeque<Sample>>,
}

impl std::fmt::Debug for Samples {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Samples")
    }
}

impl Samples {
    /// `record`: a no-op unless `sloTrackingEnabled`.
    pub fn record(&self, config: &crate::Config, latency_millis: i64, error: bool, scope: Scope, host: &str) {
        if !config.bool_property("sloTrackingEnabled", false) {
            return;
        }
        let max = config.int_property("sloWindowMaxSamples", 50_000);
        let retention = config.int_property("sloWindowRetentionMillis", 600_000);
        let now = crate::chaos::now_millis();
        let mut samples = self.samples.lock();
        samples.push_back(Sample { epoch_millis: now, latency_millis, error, scope, host: host.to_string() });
        if retention > 0 {
            while samples.front().is_some_and(|s| s.epoch_millis < now - retention) {
                samples.pop_front();
            }
        }
        while max > 0 && samples.len() as i64 > max {
            samples.pop_front();
        }
    }

    fn matching<'a>(samples: &'a VecDeque<Sample>, from: i64, to: i64, scope: Option<Scope>, hosts: &'a Option<Vec<String>>) -> impl Iterator<Item = &'a Sample> {
        samples.iter().filter(move |s| {
            s.epoch_millis >= from && s.epoch_millis <= to && scope.is_none_or(|sc| s.scope == sc) && hosts.as_ref().is_none_or(|h| h.is_empty() || h.contains(&s.host))
        })
    }

    /// `latenciesInWindow`, ascending.
    fn latencies(&self, from: i64, to: i64, scope: Option<Scope>, hosts: &Option<Vec<String>>) -> Vec<i64> {
        let samples = self.samples.lock();
        let mut out: Vec<i64> = Self::matching(&samples, from, to, scope, hosts).map(|s| s.latency_millis).collect();
        out.sort_unstable();
        out
    }

    /// `errorCountsInWindow`: (errors, total).
    fn error_counts(&self, from: i64, to: i64, scope: Option<Scope>, hosts: &Option<Vec<String>>) -> (i64, i64) {
        let samples = self.samples.lock();
        Self::matching(&samples, from, to, scope, hosts).fold((0, 0), |(e, t), s| (e + s.error as i64, t + 1))
    }

    pub fn reset(&self) {
        self.samples.lock().clear();
    }
}

/// `SloSampleStore.percentile`: the `ceil(p/100 * n) - 1` element of the ascending latencies.
fn percentile(ascending: &[i64], pct: f64) -> Option<f64> {
    if ascending.is_empty() {
        return None;
    }
    let idx = ((pct / 100.0) * ascending.len() as f64).ceil() as i64 - 1;
    Some(ascending[idx.clamp(0, ascending.len() as i64 - 1) as usize] as f64)
}

const SLIS: &[&str] = &["LATENCY_P50", "LATENCY_P95", "LATENCY_P99", "ERROR_RATE"];
const COMPARATORS: &[&str] = &["LESS_THAN", "LESS_THAN_OR_EQUAL", "GREATER_THAN", "GREATER_THAN_OR_EQUAL"];

#[derive(Debug, Clone, PartialEq)]
pub struct Objective {
    /// Index into `SLIS`; `None` for an unknown indicator (read as null).
    sli: Option<usize>,
    comparator: Option<usize>,
    threshold: f64,
    scope: Scope,
}

/// `SloWindow`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Window {
    /// "EXPLICIT" / "LOOKBACK"; `None` when absent or unknown.
    kind: Option<&'static str>,
    from: Option<i64>,
    to: Option<i64>,
    lookback: Option<i64>,
}

impl Window {
    pub fn explicit(from: i64, to: i64) -> Window {
        Window { kind: Some("EXPLICIT"), from: Some(from), to: Some(to), lookback: None }
    }

    /// `SloWindowDTO` as its criteria echo it.
    fn to_json(&self) -> Value {
        let mut o = Map::new();
        if let Some(f) = self.from {
            o.insert("fromEpochMillis".into(), json!(f));
        }
        if let Some(l) = self.lookback {
            o.insert("lookbackMillis".into(), json!(l));
        }
        if let Some(t) = self.to {
            o.insert("toEpochMillis".into(), json!(t));
        }
        if let Some(k) = self.kind {
            o.insert("type".into(), json!(k));
        }
        Value::Object(o)
    }
}

/// `SloCriteria`.
#[derive(Debug, Clone, PartialEq)]
pub struct Criteria {
    pub name: Option<String>,
    pub window: Option<Window>,
    objectives: Vec<Objective>,
    /// Default 1; `None` disables the guard.
    pub minimum_sample_count: Option<i64>,
    upstream_hosts: Option<Vec<String>>,
}

/// A failure to evaluate: the message after "invalid SLO criteria: " (`IllegalArgumentException`) or after "failed
/// to process SLO verify request: " (anything else, as the JVM words it).
pub enum SloError {
    Invalid(String),
    Failed(String),
}

impl Criteria {
    /// `SloCriteriaDTO` bound from JSON (`buildObject`: an absent `minimumSampleCount` keeps the default of 1).
    pub fn from_json(v: &Value) -> Result<Criteria, BindError> {
        let bean = Bean::of(v, "org.mockserver.serialization.model.SloCriteriaDTO")?;
        let window = match bean.bean("window", "org.mockserver.serialization.model.SloWindowDTO")? {
            None => None,
            Some(w) => {
                let kind = w.enumeration("type", "org.mockserver.slo.SloWindow$Type", &["EXPLICIT", "LOOKBACK"])?.map(|i| ["EXPLICIT", "LOOKBACK"][i]);
                Some(Window { kind, from: w.long("fromEpochMillis")?, to: w.long("toEpochMillis")?, lookback: w.long("lookbackMillis")? })
            }
        };
        let mut objectives = Vec::new();
        if let Some(Value::Array(items)) = bean.get("objectives") {
            for item in items {
                let o = Bean::of(item, "org.mockserver.serialization.model.SloObjectiveDTO")?;
                let scope = o.enumeration("scope", "org.mockserver.slo.Scope", &["INBOUND", "FORWARD"])?.map(|i| [Scope::Inbound, Scope::Forward][i]).unwrap_or(Scope::Forward);
                objectives.push(Objective {
                    sli: o.enumeration("sli", "org.mockserver.slo.SloObjective$Sli", SLIS)?,
                    comparator: o.enumeration("comparator", "org.mockserver.slo.SloObjective$Comparator", COMPARATORS)?,
                    threshold: o.double("threshold")?.unwrap_or(0.0),
                    scope,
                });
            }
        }
        let upstream_hosts = match bean.get("upstreamHosts") {
            Some(Value::Array(items)) => {
                let mut hosts: Vec<String> = Vec::new();
                for h in items.iter().filter_map(|h| h.as_str().map(str::to_string).or_else(|| (!h.is_null()).then(|| h.to_string()))) {
                    if !hosts.contains(&h) {
                        hosts.push(h);
                    }
                }
                Some(hosts)
            }
            _ => None,
        };
        let minimum_sample_count = bean.int("minimumSampleCount")?.map(i64::from).or(Some(1));
        Ok(Criteria { name: bean.string("name")?, window, objectives, minimum_sample_count, upstream_hosts })
    }

    /// The criteria scoped to an explicit window (the experiment's), keeping its `minimumSampleCount` as is.
    pub fn with_window(&self, window: Window) -> Criteria {
        Criteria { window: Some(window), ..self.clone() }
    }

    /// `SloCriteriaDTO` as Jackson writes it: alphabetical, nulls and empty collections left out.
    pub fn to_json(&self) -> Value {
        let mut o = Map::new();
        if let Some(m) = self.minimum_sample_count {
            o.insert("minimumSampleCount".into(), json!(m));
        }
        if let Some(n) = &self.name {
            o.insert("name".into(), json!(n));
        }
        if !self.objectives.is_empty() {
            let objectives = self
                .objectives
                .iter()
                .map(|ob| {
                    let mut m = Map::new();
                    if let Some(c) = ob.comparator {
                        m.insert("comparator".into(), json!(COMPARATORS[c]));
                    }
                    m.insert("scope".into(), json!(if ob.scope == Scope::Forward { "FORWARD" } else { "INBOUND" }));
                    if let Some(s) = ob.sli {
                        m.insert("sli".into(), json!(SLIS[s]));
                    }
                    m.insert("threshold".into(), double(ob.threshold));
                    Value::Object(m)
                })
                .collect();
            o.insert("objectives".into(), Value::Array(objectives));
        }
        if let Some(h) = self.upstream_hosts.as_ref().filter(|h| !h.is_empty()) {
            o.insert("upstreamHosts".into(), json!(h));
        }
        if let Some(w) = &self.window {
            o.insert("window".into(), w.to_json());
        }
        Value::Object(o)
    }
}

fn double(v: f64) -> Value {
    crate::model::number(&java_compat::double_to_string(v))
}

/// `SloVerdict.Result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Inconclusive,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// An evaluated verdict and its JSON (`SloVerdict`, alphabetical, nulls and empty lists left out).
pub struct Evaluation {
    pub result: Verdict,
    pub json: Value,
}

/// `SloEvaluator.evaluate`.
pub fn evaluate(samples: &Samples, criteria: &Criteria) -> Result<Evaluation, SloError> {
    let (from, to) = resolve_window(criteria.window.as_ref())?;
    let hosts = &criteria.upstream_hosts;
    let mut results = Vec::new();
    let (mut any_fail, mut any_inconclusive) = (false, false);
    for objective in &criteria.objectives {
        let (result, json) = evaluate_objective(samples, objective, from, to, hosts)?;
        any_fail |= result == Verdict::Fail;
        any_inconclusive |= result == Verdict::Inconclusive;
        results.push(json);
    }
    let count_scope = criteria.objectives.first().map_or(Scope::Forward, |o| o.scope);
    let total = samples.error_counts(from, to, Some(count_scope), hosts).1;
    let below_minimum = criteria.minimum_sample_count.is_some_and(|m| total < m);
    let result = if any_fail {
        Verdict::Fail
    } else if any_inconclusive || below_minimum {
        Verdict::Inconclusive
    } else {
        Verdict::Pass
    };
    let mut o = Map::new();
    if let Some(n) = &criteria.name {
        o.insert("name".into(), json!(n));
    }
    if !results.is_empty() {
        o.insert("objectiveResults".into(), Value::Array(results));
    }
    o.insert("result".into(), json!(result.name()));
    o.insert("sampleCount".into(), json!(total));
    o.insert("windowFromEpochMillis".into(), json!(from));
    o.insert("windowToEpochMillis".into(), json!(to));
    Ok(Evaluation { result, json: Value::Object(o) })
}

fn evaluate_objective(samples: &Samples, objective: &Objective, from: i64, to: i64, hosts: &Option<Vec<String>>) -> Result<(Verdict, Value), SloError> {
    let Some(sli) = objective.sli else {
        // `switch (objective.getSli())` on null.
        return Err(SloError::Failed(
            "Cannot invoke \"org.mockserver.slo.SloObjective$Sli.ordinal()\" because the return value of \"org.mockserver.slo.SloObjective.getSli()\" is null".into(),
        ));
    };
    let mut o = Map::new();
    if let Some(c) = objective.comparator {
        o.insert("comparator".into(), json!(COMPARATORS[c]));
    }
    let finish = |mut o: Map<String, Value>, observed: Option<f64>, result: Verdict, detail: Option<&str>| {
        if let Some(d) = detail {
            o.insert("detail".into(), json!(d));
        }
        if let Some(v) = observed {
            o.insert("observedValue".into(), double(v));
        }
        o.insert("result".into(), json!(result.name()));
        o.insert("sli".into(), json!(SLIS[sli]));
        o.insert("threshold".into(), double(objective.threshold));
        (result, Value::Object(o))
    };
    let observed = match SLIS[sli] {
        "ERROR_RATE" => {
            let (errors, total) = samples.error_counts(from, to, Some(objective.scope), hosts);
            if total == 0 {
                return Ok(finish(o, None, Verdict::Inconclusive, Some("no requests in window")));
            }
            errors as f64 / total as f64
        }
        latency => {
            let pct = match latency {
                "LATENCY_P50" => 50.0,
                "LATENCY_P95" => 95.0,
                _ => 99.0,
            };
            match percentile(&samples.latencies(from, to, Some(objective.scope), hosts), pct) {
                Some(v) => v,
                None => return Ok(finish(o, None, Verdict::Inconclusive, Some("no samples in window"))),
            }
        }
    };
    let Some(comparator) = objective.comparator else {
        return Err(SloError::Failed("Cannot invoke \"org.mockserver.slo.SloObjective$Comparator.test(double, double)\" because \"this.comparator\" is null".into()));
    };
    let t = objective.threshold;
    let satisfied = match COMPARATORS[comparator] {
        "LESS_THAN" => observed < t,
        "LESS_THAN_OR_EQUAL" => observed <= t,
        "GREATER_THAN" => observed > t,
        _ => observed >= t,
    };
    o.remove("detail");
    Ok(finish(o, Some(observed), if satisfied { Verdict::Pass } else { Verdict::Fail }, None))
}

fn resolve_window(window: Option<&Window>) -> Result<(i64, i64), SloError> {
    let Some(window) = window else { return Err(SloError::Invalid("an SLO window is required".into())) };
    match window.kind {
        Some("LOOKBACK") => {
            let lookback = window.lookback.filter(|l| *l > 0).ok_or_else(|| SloError::Invalid("a positive lookbackMillis is required for a LOOKBACK window".into()))?;
            let now = crate::chaos::now_millis();
            Ok((now - lookback, now))
        }
        Some("EXPLICIT") => match (window.from, window.to) {
            (Some(f), Some(t)) => Ok((f, t)),
            _ => Err(SloError::Invalid("both fromEpochMillis and toEpochMillis are required for an EXPLICIT window".into())),
        },
        _ => Err(SloError::Invalid("an SLO window type is required (LOOKBACK or EXPLICIT)".into())),
    }
}

fn error(status: u32, message: &str) -> Reply {
    Reply::api_body(status, "application/json", json!({"error": message}).to_string())
}

/// `handleVerifySlo`.
pub fn verify(state: &State, request: &HttpRequest) -> Reply {
    if !state.config.bool_property("sloTrackingEnabled", false) {
        return error(403, "SLO tracking not enabled (set sloTrackingEnabled=true)");
    }
    let body = request.body_json_or_xml_str();
    if body.trim().is_empty() {
        // `getBodyAsJsonOrXmlString` is null without a body.
        let shown = if request.body.is_empty() { "null".to_string() } else { body.to_string() };
        return error(400, &format!("invalid SLO criteria: 1 error:\n - an SLO criteria is required but value was \"{shown}\""));
    }
    let parse_failed = |cause: String| {
        crate::log::entry(state, &crate::recorded::LogEntry::at(crate::recorded::Level::Error, format!("exception while parsing{{}}for SloCriteria {cause}")).args([body.as_ref()]));
        error(400, &format!("invalid SLO criteria: exception while parsing [{body}] for SloCriteria"))
    };
    let criteria = match crate::chaos::read_tree(&body, false) {
        Err(e) => return parse_failed(e),
        Ok(Value::Null) => return fault(state, request, "Cannot invoke \"org.mockserver.slo.SloCriteria.getWindow()\" because \"criteria\" is null".into()),
        Ok(v) => match Criteria::from_json(&v) {
            Ok(c) => c,
            Err(e) => return parse_failed(e.source_text(crate::chaos::bind::location(&body, e.property()))),
        },
    };
    match evaluate(&state.config.slo, &criteria) {
        Ok(e) => Reply::api_body(if e.result == Verdict::Fail { 406 } else { 200 }, "application/json", crate::json::pretty(&e.json)),
        Err(SloError::Invalid(m)) => error(400, &format!("invalid SLO criteria: {m}")),
        Err(SloError::Failed(m)) => fault(state, request, m),
    }
}

/// A `NullPointerException` while evaluating: no client error, so `handleVerifySlo` answers it 500 (`unexpectedFailure`).
fn fault(state: &State, request: &HttpRequest, message: String) -> Reply {
    crate::control::unexpected_failure_json(state, request, &crate::recorded::Failure::of("java.lang.NullPointerException", message, Vec::new(), &[]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_index() {
        let v = [1, 2, 3, 4];
        assert_eq!(percentile(&v, 50.0), Some(2.0));
        assert_eq!(percentile(&v, 95.0), Some(4.0));
        assert_eq!(percentile(&[], 50.0), None);
    }
}

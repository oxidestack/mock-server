//! Load scenarios (`org.mockserver.load`, `LoadScenarioRegistry`, `LoadScenarioOrchestrator`): definitions loaded
//! over `PUT /mockserver/loadScenario`, kept by name, and started as runs of virtual users that send the steps'
//! requests through the forwarding client, following a profile of VU and arrival-rate stages. The run itself is in
//! [`run`]; this module holds the model (`LoadScenarioDTO` binding and serialisation, validation) and the control-plane
//! endpoints.

pub mod run;

use serde_json::{Map, Value, json};

use crate::chaos::bind::{Bean, BindError};
use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;
use crate::templates::Engine;

// ---------------------------------------------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageType {
    Vu,
    Rate,
    Pause,
}

const STAGE_TYPES: &[&str] = &["VU", "RATE", "PAUSE"];

/// `RampCurve`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    Linear,
    Quadratic,
    Exponential,
}

const CURVES: &[&str] = &["LINEAR", "QUADRATIC", "EXPONENTIAL"];

impl Curve {
    fn name(self) -> &'static str {
        CURVES[self as usize]
    }

    fn of(index: Option<usize>) -> Curve {
        match index {
            Some(1) => Curve::Quadratic,
            Some(2) => Curve::Exponential,
            _ => Curve::Linear,
        }
    }

    /// `RampCurve.valueAt`.
    pub fn value_at(self, start: f64, end: f64, p: f64) -> f64 {
        let progress = p.clamp(0.0, 1.0);
        let shaped = match self {
            Curve::Quadratic => progress * progress,
            Curve::Exponential => ((4.0 * progress).exp() - 1.0) / (4.0f64.exp() - 1.0),
            Curve::Linear => progress,
        };
        start + (end - start) * shaped
    }
}

/// `LoadStage`.
#[derive(Debug, Clone)]
pub struct Stage {
    pub kind: StageType,
    pub duration: i64,
    pub curve: Curve,
    pub vus: Option<i32>,
    pub start_vus: Option<i32>,
    pub end_vus: Option<i32>,
    pub rate: Option<f64>,
    pub start_rate: Option<f64>,
    pub end_rate: Option<f64>,
    pub max_vus: Option<i32>,
}

impl Stage {
    fn hold(metric_rate: bool, value: f64, duration: i64) -> Stage {
        let mut stage = Stage { kind: StageType::Vu, duration, curve: Curve::Linear, vus: None, start_vus: None, end_vus: None, rate: None, start_rate: None, end_rate: None, max_vus: None };
        if metric_rate {
            stage.kind = StageType::Rate;
            stage.rate = Some(value);
        } else {
            stage.vus = Some(java_round(value));
        }
        stage
    }

    fn ramp(metric_rate: bool, start: f64, end: f64, duration: i64, curve: Curve) -> Stage {
        let mut stage = Stage::hold(metric_rate, 0.0, duration);
        stage.curve = curve;
        if metric_rate {
            stage.rate = None;
            stage.start_rate = Some(start);
            stage.end_rate = Some(end);
        } else {
            stage.vus = None;
            stage.start_vus = Some(java_round(start));
            stage.end_vus = Some(java_round(end));
        }
        stage
    }

    pub fn is_vu_ramp(&self) -> bool {
        self.start_vus.is_some() && self.end_vus.is_some()
    }

    pub fn is_rate_ramp(&self) -> bool {
        self.start_rate.is_some() && self.end_rate.is_some()
    }

    fn progress(&self, elapsed: i64) -> f64 {
        if self.duration <= 0 {
            return 1.0;
        }
        (elapsed.max(0) as f64 / self.duration as f64).min(1.0)
    }

    /// `targetVusAt`.
    pub fn target_vus_at(&self, elapsed: i64) -> i32 {
        if self.kind != StageType::Vu {
            return 0;
        }
        if self.is_vu_ramp() {
            let (s, e) = (self.start_vus.unwrap_or(0), self.end_vus.unwrap_or(0));
            return java_round(self.curve.value_at(f64::from(s), f64::from(e), self.progress(elapsed)));
        }
        self.vus.unwrap_or(0)
    }

    /// `targetRateAt`.
    pub fn target_rate_at(&self, elapsed: i64) -> f64 {
        if self.kind != StageType::Rate {
            return 0.0;
        }
        if self.is_rate_ramp() {
            return self.curve.value_at(self.start_rate.unwrap_or(0.0), self.end_rate.unwrap_or(0.0), self.progress(elapsed));
        }
        self.rate.unwrap_or(0.0)
    }

    pub fn peak_vus(&self) -> i32 {
        match self.kind {
            StageType::Vu if self.is_vu_ramp() => self.start_vus.unwrap_or(0).max(self.end_vus.unwrap_or(0)),
            StageType::Vu => self.vus.unwrap_or(0),
            _ => 0,
        }
    }

    pub fn peak_rate(&self) -> f64 {
        match self.kind {
            StageType::Rate if self.is_rate_ramp() => self.start_rate.unwrap_or(0.0).max(self.end_rate.unwrap_or(0.0)),
            StageType::Rate => self.rate.unwrap_or(0.0),
            _ => 0.0,
        }
    }
}

/// `LoadShapes.toVus`: `Math.round(double)` saturated to the `int` range, so an oversized value is not wrapped.
fn java_round(v: f64) -> i32 {
    ((v + 0.5).floor() as i64).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

/// `LoadShape`.
#[derive(Debug, Clone, Default)]
pub struct Shape {
    pub kind: Option<usize>,
    pub metric_rate: bool,
    pub curve: Option<Curve>,
    pub baseline: Option<f64>,
    pub peak: Option<f64>,
    pub ramp_up: Option<i64>,
    pub hold: Option<i64>,
    pub ramp_down: Option<i64>,
    pub recovery_hold: Option<i64>,
    pub start: Option<f64>,
    pub step: Option<f64>,
    pub steps: Option<i32>,
    pub step_duration: Option<i64>,
    pub target: Option<f64>,
    pub ramp: Option<i64>,
}

const SHAPE_TYPES: &[&str] = &["SPIKE", "STAIRS", "RAMP_HOLD"];

/// `LoadShapes.MAX_EXPANDED_STAGES`: the stages a shape may expand into, whatever `loadGenerationMaxStages` says.
pub const MAX_EXPANDED_STAGES: i64 = 10_000;

impl Shape {
    /// `LoadShapes.stageCount`: the number of stages [`Shape::expand`] would produce, without allocating them.
    pub fn stage_count(&self) -> i64 {
        let positive = |durations: &[Option<i64>]| durations.iter().filter(|d| d.unwrap_or(0) > 0).count() as i64;
        match self.kind {
            Some(0) => positive(&[self.ramp_up, self.hold, self.ramp_down, self.recovery_hold]),
            Some(1) => {
                let steps = i64::from(self.steps.unwrap_or(0));
                if steps > 0 && self.step_duration.unwrap_or(0) > 0 { steps } else { 0 }
            }
            Some(2) => positive(&[self.ramp, self.hold]),
            _ => 0,
        }
    }

    /// `LoadScenarioOrchestrator.nonFiniteShapeParameter`.
    fn non_finite_parameter(&self) -> Option<String> {
        [("baseline", self.baseline), ("peak", self.peak), ("start", self.start), ("step", self.step), ("target", self.target)]
            .into_iter()
            .find(|(_, v)| v.is_some_and(|v| !v.is_finite()))
            .map(|(name, _)| format!("'profile.shape.{name}' must be a finite number"))
    }

    /// `LoadShapes.expand`.
    fn expand(&self) -> Vec<Stage> {
        let mut stages = Vec::new();
        let rate = self.metric_rate;
        let curve = self.curve.unwrap_or(Curve::Linear);
        let f = |v: Option<f64>| v.unwrap_or(0.0);
        let l = |v: Option<i64>| v.unwrap_or(0);
        match self.kind {
            Some(0) => {
                let (baseline, peak) = (f(self.baseline), f(self.peak));
                if l(self.ramp_up) > 0 {
                    stages.push(Stage::ramp(rate, baseline, peak, l(self.ramp_up), curve));
                }
                if l(self.hold) > 0 {
                    stages.push(Stage::hold(rate, peak, l(self.hold)));
                }
                if l(self.ramp_down) > 0 {
                    stages.push(Stage::ramp(rate, peak, baseline, l(self.ramp_down), curve));
                }
                if l(self.recovery_hold) > 0 {
                    stages.push(Stage::hold(rate, baseline, l(self.recovery_hold)));
                }
            }
            Some(1) => {
                // without a duration there are no stages: not a loop over `steps` that pushes none
                let duration = l(self.step_duration);
                if duration > 0 {
                    for i in 0..self.steps.unwrap_or(0).max(0) {
                        stages.push(Stage::hold(rate, f(self.start) + f64::from(i) * f(self.step), duration));
                    }
                }
            }
            Some(2) => {
                if l(self.ramp) > 0 {
                    stages.push(Stage::ramp(rate, 0.0, f(self.target), l(self.ramp), curve));
                }
                if l(self.hold) > 0 {
                    stages.push(Stage::hold(rate, f(self.target), l(self.hold)));
                }
            }
            _ => {}
        }
        stages
    }
}

/// `LoadProfile`: explicit stages, else the shape's expansion.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub raw_stages: Vec<Stage>,
    pub shape: Option<Shape>,
    expanded: Vec<Stage>,
}

impl Profile {
    /// A shape over [`MAX_EXPANDED_STAGES`] is left unexpanded (upstream's `expand` throws); validation refuses it
    /// by [`Profile::stage_count`] before reading the stages.
    fn new(raw_stages: Vec<Stage>, shape: Option<Shape>) -> Profile {
        let expanded = shape.as_ref().filter(|s| s.stage_count() <= MAX_EXPANDED_STAGES).map(Shape::expand).unwrap_or_default();
        Profile { raw_stages, shape, expanded }
    }

    /// `LoadProfile.stageCount`: the number of stages, a shape's counted without expanding it.
    pub fn stage_count(&self) -> i64 {
        match &self.shape {
            Some(shape) if self.raw_stages.is_empty() => shape.stage_count(),
            _ => self.raw_stages.len() as i64,
        }
    }

    pub fn stages(&self) -> &[Stage] {
        if !self.raw_stages.is_empty() || self.shape.is_none() { &self.raw_stages } else { &self.expanded }
    }

    /// `totalDurationMillis`: saturates at `Long.MAX_VALUE` rather than wrapping.
    pub fn total_duration(&self) -> i64 {
        self.stages().iter().fold(0i64, |total, s| total.saturating_add(s.duration.max(0)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureSource {
    BodyJsonPath,
    Header,
    BodyRegex,
}

/// `LoadCapture`.
#[derive(Debug, Clone)]
pub struct Capture {
    pub name: Option<String>,
    pub source: Option<CaptureSource>,
    pub expression: Option<String>,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckSource {
    Status,
    Header,
    BodyJsonPath,
}

const CHECK_SOURCES: &[&str] = &["STATUS", "HEADER", "BODY_JSONPATH"];
const CHECK_COMPARATORS: &[&str] = &["EQUALS", "NOT_EQUALS", "CONTAINS", "MATCHES", "GT", "LT", "GTE", "LTE"];

/// `LoadCheck`.
#[derive(Debug, Clone)]
pub struct Check {
    pub source: Option<CheckSource>,
    pub header_name: Option<String>,
    pub json_path: Option<String>,
    pub comparator: Option<usize>,
    pub value: Option<String>,
}

impl Check {
    pub fn is_valid(&self) -> bool {
        self.source.is_some() && self.comparator.is_some()
    }

    pub fn source_name(&self) -> &'static str {
        self.source.map(|s| CHECK_SOURCES[s as usize]).unwrap_or("")
    }

    pub fn comparator_name(&self) -> &'static str {
        self.comparator.map(|c| CHECK_COMPARATORS[c]).unwrap_or("")
    }

    /// `LoadCheck.Comparator.matches`.
    pub fn matches(&self, observed: Option<&str>) -> bool {
        let Some(comparator) = self.comparator else { return true };
        let expected = self.value.as_deref();
        match CHECK_COMPARATORS[comparator] {
            "EQUALS" => observed.is_some() && observed == expected,
            "NOT_EQUALS" => match observed {
                None => expected.is_some(),
                Some(o) => Some(o) != expected,
            },
            "CONTAINS" => matches!((observed, expected), (Some(o), Some(e)) if o.contains(e)),
            "MATCHES" => match (observed, expected) {
                (Some(o), Some(e)) => fancy_regex::Regex::new(&format!("^(?:{e})$")).is_ok_and(|r| r.is_match(o).unwrap_or(false)),
                _ => false,
            },
            name => {
                let parse = |v: Option<&str>| v.map(str::trim).filter(|v| !v.is_empty()).and_then(|v| v.parse::<f64>().ok());
                let (Some(left), Some(right)) = (parse(observed), parse(expected)) else { return false };
                let cmp = left.total_cmp(&right);
                match name {
                    "GT" => cmp.is_gt(),
                    "LT" => cmp.is_lt(),
                    "GTE" => cmp.is_ge(),
                    _ => cmp.is_le(),
                }
            }
        }
    }
}

/// A step's check or capture source read from a response.
pub struct Response<'a> {
    pub status: u32,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

impl Response<'_> {
    fn text(&self) -> Option<String> {
        Some(String::from_utf8_lossy(self.body).into_owned()).filter(|b| !b.trim().is_empty())
    }

    /// `LoadResponseExtractor.header`.
    pub fn header(&self, name: Option<&str>) -> Option<String> {
        let name = name.filter(|n| !n.trim().is_empty())?;
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()).filter(|v| !v.trim().is_empty())
    }

    /// `LoadResponseExtractor.jsonPath`; `Err` when the expression cannot be read (jayway throws).
    pub fn json_path(&self, expression: Option<&str>) -> Result<Option<String>, ()> {
        let Some(expression) = expression.filter(|e| !e.trim().is_empty()) else { return Ok(None) };
        let Some(body) = self.text() else { return Ok(None) };
        let value = crate::templates::extract::json_path_in(&body, expression).ok_or(())?;
        Ok(stringify(&value))
    }

    /// `LoadResponseExtractor.regexGroup1`.
    pub fn regex_group(&self, pattern: Option<&str>) -> Option<String> {
        let pattern = pattern.filter(|p| !p.trim().is_empty())?;
        let body = self.text()?;
        let captures = fancy_regex::Regex::new(pattern).ok()?.captures(&body).ok()??;
        captures.get(1).map(|m| m.as_str().to_string())
    }
}

/// `LoadResponseExtractor.stringifyJsonPath`: an empty list is nothing, a one-element list its element.
fn stringify(value: &java_compat::lang::JValue) -> Option<String> {
    use java_compat::lang::JValue;
    match value {
        JValue::Null => None,
        JValue::List(list) if list.is_empty() => None,
        JValue::List(list) if list.len() == 1 => list.get(0).filter(|v| !v.is_null()).map(|v| v.to_java_string()),
        other => Some(other.to_java_string()),
    }
}

impl Check {
    /// `LoadCheck.extract`.
    pub fn extract(&self, response: &Response) -> Result<Option<String>, ()> {
        match self.source {
            Some(CheckSource::Status) => Ok(Some(response.status.to_string())),
            Some(CheckSource::Header) => Ok(response.header(self.header_name.as_deref())),
            Some(CheckSource::BodyJsonPath) => response.json_path(self.json_path.as_deref()),
            None => Ok(None),
        }
    }
}

impl Capture {
    pub fn extract(&self, response: &Response) -> Result<Option<String>, ()> {
        match self.source {
            Some(CaptureSource::BodyJsonPath) => response.json_path(self.expression.as_deref()),
            Some(CaptureSource::Header) => Ok(response.header(self.expression.as_deref())),
            Some(CaptureSource::BodyRegex) => Ok(response.regex_group(self.expression.as_deref())),
            None => Ok(None),
        }
    }
}

const THRESHOLD_METRICS: &[&str] = &["LATENCY_P50", "LATENCY_P95", "LATENCY_P99", "LATENCY_P999", "ERROR_RATE", "THROUGHPUT_RPS", "CHECK_FAILURE_RATE"];
const SLO_COMPARATORS: &[&str] = &["LESS_THAN", "LESS_THAN_OR_EQUAL", "GREATER_THAN", "GREATER_THAN_OR_EQUAL"];

/// `LoadThreshold`.
#[derive(Debug, Clone)]
pub struct Threshold {
    pub metric: Option<usize>,
    pub comparator: Option<usize>,
    pub threshold: f64,
}

impl Threshold {
    pub fn metric_name(&self) -> Option<&'static str> {
        self.metric.map(|m| THRESHOLD_METRICS[m])
    }

    pub fn comparator_name(&self) -> Option<&'static str> {
        self.comparator.map(|c| SLO_COMPARATORS[c])
    }

    /// `satisfiedBy`.
    pub fn satisfied_by(&self, observed: f64) -> bool {
        match self.comparator {
            None => true,
            Some(0) => observed < self.threshold,
            Some(1) => observed <= self.threshold,
            Some(2) => observed > self.threshold,
            Some(_) => observed >= self.threshold,
        }
    }
}

const PACING_MODES: &[&str] = &["NONE", "CONSTANT_PACING", "CONSTANT_THROUGHPUT"];

/// `LoadPacing`.
#[derive(Debug, Clone)]
pub struct Pacing {
    pub mode: usize,
    pub value: f64,
}

impl Pacing {
    /// `cycleMillis`.
    pub fn cycle_millis(&self) -> f64 {
        if self.mode == 0 || self.value <= 0.0 {
            return 0.0;
        }
        if self.mode == 1 { self.value } else { 1000.0 / self.value }
    }
}

const FEEDER_FORMATS: &[&str] = &["CSV", "JSON"];
const FEEDER_STRATEGIES: &[&str] = &["CIRCULAR", "RANDOM", "SEQUENTIAL"];

pub type Row = Vec<(String, Option<String>)>;

/// `LoadFeeder`.
#[derive(Debug, Clone)]
pub struct Feeder {
    pub rows: Option<Vec<Row>>,
    pub data: Option<String>,
    pub format: Option<usize>,
    /// Index into `CIRCULAR`, `RANDOM`, `SEQUENTIAL`.
    pub strategy: usize,
}

impl Feeder {
    /// `resolvedRows`.
    pub fn resolved_rows(&self) -> Result<Vec<Row>, String> {
        if let Some(rows) = &self.rows {
            return Ok(rows.clone());
        }
        let Some(data) = self.data.as_deref().filter(|d| !d.is_empty()) else { return Ok(Vec::new()) };
        match self.format {
            None => Err("'feeder.format' is required when 'feeder.data' is set (CSV or JSON)".into()),
            Some(0) => {
                let records = crate::templates::csv_parse(data);
                let Some((headers, rest)) = records.split_first() else { return Ok(Vec::new()) };
                Ok(rest.iter().map(|fields| headers.iter().zip(fields).map(|(h, f)| (h.clone(), Some(f.clone()))).collect()).collect())
            }
            Some(_) => {
                if let Some(error) = feeder_json_error(data) {
                    return Err(format!("'feeder.data' is not a valid JSON array of objects: {error}"));
                }
                let parsed: Value = crate::json::parse_lenient(data.as_bytes())
                    .map_err(|e| format!("'feeder.data' is not a valid JSON array of objects: {e}"))?;
                let items = match parsed {
                    Value::Null => return Ok(Vec::new()),
                    Value::Array(items) => items,
                    // ACCEPT_SINGLE_VALUE_AS_ARRAY: one object is a one-row dataset
                    object @ Value::Object(_) => vec![object],
                    _ => return Err("'feeder.data' is not a valid JSON array of objects".into()),
                };
                Ok(items
                    .iter()
                    .map(|item| {
                        item.as_object()
                            .map(|o| o.iter().map(|(k, v)| (k.clone(), (!v.is_null()).then(|| java_value_of(v)))).collect())
                            .unwrap_or_default()
                    })
                    .collect())
            }
        }
    }
}

/// One top-level value of feeder JSON data: where it starts, where it ends (exclusive; `None` when the data ends
/// inside it) and its first byte.
struct FeederElement {
    start: usize,
    end: Option<usize>,
    first: u8,
}

/// The top-level values of `data` (the elements of a root array, or the root value itself) and whether the root is
/// an array. Strings in either quote, escapes and nesting are followed; anything else is skipped byte by byte.
fn feeder_elements(data: &[u8]) -> Option<(bool, Vec<FeederElement>)> {
    let skip_ws = |mut i: usize| {
        while i < data.len() && data[i].is_ascii_whitespace() {
            i += 1;
        }
        i
    };
    // the end of the value starting at `i`
    let value_end = |i: usize| -> Option<usize> {
        let mut depth = 0usize;
        let mut j = i;
        while j < data.len() {
            match data[j] {
                q @ (b'"' | b'\'') => {
                    j += 1;
                    while j < data.len() && data[j] != q {
                        j += if data[j] == b'\\' { 2 } else { 1 };
                    }
                    if j >= data.len() {
                        return None;
                    }
                    j += 1;
                    if depth == 0 {
                        return Some(j);
                    }
                    continue;
                }
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    if depth == 0 {
                        return Some(j);
                    }
                    depth -= 1;
                    if depth == 0 {
                        return Some(j + 1);
                    }
                }
                b',' | b' ' | b'\t' | b'\r' | b'\n' if depth == 0 => return Some(j),
                _ => {}
            }
            j += 1;
        }
        if depth == 0 && j > i { Some(j) } else { None }
    };
    let root = skip_ws(0);
    let &first = data.get(root)?;
    if first != b'[' {
        return Some((false, vec![FeederElement { start: root, end: value_end(root), first }]));
    }
    let mut elements = Vec::new();
    let mut i = skip_ws(root + 1);
    while i < data.len() && data[i] != b']' {
        let end = value_end(i);
        elements.push(FeederElement { start: i, end, first: data[i] });
        let Some(end) = end else { break };
        i = skip_ws(end);
        if i < data.len() && data[i] == b',' {
            i = skip_ws(i + 1);
        } else {
            break;
        }
    }
    Some((true, elements))
}

/// Jackson's exception message (`getMessage()`) for feeder JSON data that `LoadFeeder.parseJson` cannot read as a
/// `List<LinkedHashMap<String, Object>>` (the mapper accepts a single value as an array), or `None` when the data
/// reads, or fails in a way whose wording is not known (the caller then uses the parser's own words). A failure
/// inside an element's deserialization carries the reference chain `CollectionDeserializer` adds (`ArrayList[k]`,
/// or `LinkedHashMap[0]` for a single value coerced to an array); one while reading an element's first token or a
/// separator carries none.
fn feeder_json_error(data: &str) -> Option<String> {
    const LOCATION: &str = "[Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled)";
    let bytes = data.as_bytes();
    let at = |offset: usize| {
        let line = 1 + bytes[..offset].iter().filter(|&&b| b == b'\n').count();
        let line_start = bytes[..offset].iter().rposition(|&b| b == b'\n').map_or(0, |p| p + 1);
        format!("{LOCATION}; line: {line}, column: {}]", offset - line_start + 1)
    };
    let line_column = |offset: usize| {
        let line = 1 + bytes[..offset].iter().filter(|&&b| b == b'\n').count();
        let line_start = bytes[..offset].iter().rposition(|&b| b == b'\n').map_or(0, |p| p + 1);
        (line, offset - line_start + 1)
    };
    // the syntax failure of the object starting at `start`, read as a map on its own (`jnode::syntax_failure`, which
    // accepts what follows it), its locations moved to where the object sits in `data`
    let object_failure = |start: usize| -> Option<String> {
        let text = crate::jnode::syntax_failure(&data[start..])?;
        let message = text.strip_prefix("shaded_package.com.fasterxml.jackson.")?.split_once(": ")?.1;
        let (start_line, start_column) = line_column(start);
        let marker = "; line: ";
        let mut out = String::new();
        let mut rest = message;
        while let Some(i) = rest.find(marker) {
            out.push_str(&rest[..i + marker.len()]);
            rest = &rest[i + marker.len()..];
            let (line, after) = rest.split_once(", column: ")?;
            let (column, after) = after.split_once(']')?;
            let (line, column): (usize, usize) = (line.parse().ok()?, column.parse().ok()?);
            let (line, column) = if line == 1 { (start_line, start_column + column - 1) } else { (start_line + line - 1, column) };
            out.push_str(&format!("{line}, column: {column}]"));
            rest = after;
        }
        out.push_str(rest);
        Some(out)
    };
    let mismatch = |element: &FeederElement| -> Option<String> {
        let end = element.end?;
        let token = &data[element.start..end];
        match element.first {
            b'[' => Some("Cannot deserialize value of type `java.util.LinkedHashMap<java.lang.String,java.lang.Object>` from Array value (token `JsonToken.START_ARRAY`)".to_string()),
            b'0'..=b'9' | b'-' if token.bytes().all(|b| b.is_ascii_digit() || b == b'-') => {
                Some("Cannot deserialize value of type `java.util.LinkedHashMap<java.lang.String,java.lang.Object>` from Integer value (token `JsonToken.VALUE_NUMBER_INT`)".to_string())
            }
            b'"' if token.len() > 2 && !token.contains('\\') => Some(format!(
                "Cannot construct instance of `java.util.LinkedHashMap` (although at least one Creator exists): no String-argument constructor/factory method to deserialize from String value ('{}')",
                &token[1..token.len() - 1]
            )),
            _ => None,
        }
    };
    let (array, elements) = feeder_elements(bytes)?;
    if !array {
        let root = elements.first()?;
        let chain = " (through reference chain: java.util.LinkedHashMap[0])";
        if root.first == b'{' {
            return object_failure(root.start).map(|message| format!("{message}{chain}"));
        }
        if root.first.is_ascii_alphabetic() && !matches!(root.end.map(|end| &data[root.start..end]), Some("null" | "true" | "false")) {
            // a token the parser does not recognise fails before any element is deserialized: no chain
            return object_failure(root.start);
        }
        return mismatch(root).map(|message| format!("{message}\n at {}{chain}", at(root.start)));
    }
    let root = bytes.iter().position(|&b| b == b'[')?;
    let end_of_input = || format!("Unexpected end-of-input: expected close marker for Array (start marker at {})\n at {}", at(root), at(bytes.len()));
    for (k, element) in elements.iter().enumerate() {
        let chain = format!(" (through reference chain: java.util.ArrayList[{k}])");
        match element.first {
            b'{' => {
                if let Some(message) = object_failure(element.start) {
                    return Some(format!("{message}{chain}"));
                }
            }
            b'n' if element.end.is_some_and(|end| &data[element.start..end] == "null") => {}
            _ => return mismatch(element).map(|message| format!("{message}\n at {}{chain}", at(element.start))),
        }
        // the separator after it
        let mut i = element.end?;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        match bytes.get(i) {
            None => return Some(end_of_input()),
            Some(b',') if k + 1 == elements.len() => {
                // a comma the data ends after
                return bytes[i + 1..].iter().all(u8::is_ascii_whitespace).then(end_of_input);
            }
            Some(b',') | Some(b']') => {}
            Some(_) => return None,
        }
    }
    if elements.is_empty() && bytes[root + 1..].iter().all(u8::is_ascii_whitespace) {
        return Some(end_of_input());
    }
    None
}

/// `String.valueOf` of a value Jackson bound as `Object`.
fn java_value_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Object(o) => format!("{{{}}}", o.iter().map(|(k, v)| format!("{k}={}", if v.is_null() { "null".into() } else { java_value_of(v) })).collect::<Vec<_>>().join(", ")),
        Value::Array(a) => format!("[{}]", a.iter().map(|v| if v.is_null() { "null".into() } else { java_value_of(v) }).collect::<Vec<_>>().join(", ")),
        Value::Number(n) if n.is_f64() => java_compat::double_to_string(n.as_f64().unwrap_or(0.0)),
        other => other.to_string(),
    }
}

/// `LoadStep`.
#[derive(Debug, Clone)]
pub struct Step {
    /// The request as `HttpRequestDTO` serialises it.
    pub request: Option<Value>,
    /// The think time as `DelayDTO` serialises it.
    pub think_time: Option<Value>,
    pub name: Option<String>,
    pub labels: Option<Vec<(String, Option<String>)>>,
    pub captures: Vec<Capture>,
    pub checks: Vec<Check>,
    pub weight: Option<f64>,
}

impl Step {
    pub fn weight_or_one(&self) -> f64 {
        self.weight.unwrap_or(1.0)
    }
}

/// `LoadScenario`.
#[derive(Debug, Clone)]
pub struct Scenario {
    pub name: Option<String>,
    pub steps: Vec<Step>,
    pub profile: Option<Profile>,
    pub template: Engine,
    pub max_requests: Option<i32>,
    pub start_delay: i64,
    pub labels: Option<Vec<(String, Option<String>)>>,
    pub thresholds: Vec<Threshold>,
    pub abort_on_fail: bool,
    pub abort_grace: i64,
    pub pacing: Option<Pacing>,
    pub feeder: Option<Feeder>,
    pub weighted: bool,
}

impl Scenario {
    pub fn name(&self) -> &str {
        self.name.as_deref().unwrap_or_default()
    }

    pub fn stages(&self) -> &[Stage] {
        self.profile.as_ref().map(Profile::stages).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Binding (`LoadScenarioDTO` read with MockServer's object mapper)
// ---------------------------------------------------------------------------------------------------------------

fn list<'a>(bean: &Bean<'a>, name: &str) -> Result<Vec<&'a Value>, BindError> {
    match bean.get(name) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items.iter().collect()),
        Some(_) => Err(BindError::mismatch()),
    }
}

/// [`list`] with each element bound by `element`, a failure located as Jackson's reference chain names it
/// (`Class["name"]->java.util.ArrayList[i]->…`).
fn bound_list<'a, T>(bean: &Bean<'a>, name: &str, element: impl Fn(&'a Value) -> Result<T, BindError>) -> Result<Vec<T>, BindError> {
    let items = list(bean, name);
    bean.located(name, items.and_then(|items| items.into_iter().enumerate().map(|(i, v)| element(v).map_err(|e| e.at_index("java.util.ArrayList", i))).collect()))
}

fn stage_of(v: &Value) -> Result<Stage, BindError> {
    let b = Bean::of(v, "org.mockserver.serialization.model.LoadStageDTO")?;
    let kind = match b.enumeration("type", "org.mockserver.load.LoadStageType", STAGE_TYPES)? {
        Some(1) => StageType::Rate,
        Some(2) => StageType::Pause,
        _ => StageType::Vu,
    };
    Ok(Stage {
        kind,
        duration: b.long("durationMillis")?.unwrap_or(0),
        curve: Curve::of(b.enumeration("curve", "org.mockserver.load.RampCurve", CURVES)?),
        vus: b.int("vus")?,
        start_vus: b.int("startVus")?,
        end_vus: b.int("endVus")?,
        rate: b.double("rate")?,
        start_rate: b.double("startRate")?,
        end_rate: b.double("endRate")?,
        max_vus: b.int("maxVus")?,
    })
}

fn shape_of(b: &Bean) -> Result<Shape, BindError> {
    Ok(Shape {
        kind: b.enumeration("type", "org.mockserver.load.LoadShape$Type", SHAPE_TYPES)?,
        metric_rate: b.enumeration("metric", "org.mockserver.load.LoadShape$Metric", &["VU", "RATE"])? == Some(1),
        curve: Some(Curve::of(b.enumeration("curve", "org.mockserver.load.RampCurve", CURVES)?)),
        baseline: b.double("baseline")?,
        peak: b.double("peak")?,
        ramp_up: b.long("rampUpMillis")?,
        hold: b.long("holdMillis")?,
        ramp_down: b.long("rampDownMillis")?,
        recovery_hold: b.long("recoveryHoldMillis")?,
        start: b.double("start")?,
        step: b.double("step")?,
        steps: b.int("steps")?,
        step_duration: b.long("stepDurationMillis")?,
        target: b.double("target")?,
        ramp: b.long("rampMillis")?,
    })
}

/// `LoadProfileDTO.buildObject`.
pub fn profile_of(v: &Value) -> Result<Profile, BindError> {
    let b = Bean::of(v, "org.mockserver.serialization.model.LoadProfileDTO")?;
    let stages = bound_list(&b, "stages", stage_of)?;
    let shape = match b.bean("shape", "org.mockserver.serialization.model.LoadShapeDTO")? {
        Some(s) => Some(shape_of(&s)?),
        None => None,
    };
    Ok(Profile::new(stages, shape))
}

fn step_of(v: &Value) -> Result<Step, BindError> {
    let b = Bean::of(v, "org.mockserver.serialization.model.LoadStepDTO")?;
    let request = match b.get("request") {
        None | Some(Value::Null) => None,
        Some(r @ Value::Object(_)) => Some(socket_port_as_number(crate::canonical::request_definition(r))?),
        Some(_) => return Err(BindError::mismatch()),
    };
    let think_time = match b.get("thinkTime") {
        None | Some(Value::Null) => None,
        Some(d @ Value::Object(_)) => Some(crate::canonical::delay(d)),
        Some(_) => return Err(BindError::mismatch()),
    };
    let captures = list(&b, "captures")?
        .into_iter()
        .map(|c| {
            let c = Bean::of(c, "org.mockserver.load.LoadCapture")?;
            Ok(Capture {
                name: c.string("name")?,
                source: match c.enumeration("source", "org.mockserver.load.LoadCapture$Source", &["BODY_JSONPATH", "HEADER", "BODY_REGEX"])? {
                    Some(0) => Some(CaptureSource::BodyJsonPath),
                    Some(1) => Some(CaptureSource::Header),
                    Some(_) => Some(CaptureSource::BodyRegex),
                    None => None,
                },
                expression: c.string("expression")?,
                default_value: c.string("defaultValue")?,
            })
        })
        .collect::<Result<Vec<_>, BindError>>()?;
    let checks = list(&b, "checks")?
        .into_iter()
        .map(|c| {
            let c = Bean::of(c, "org.mockserver.load.LoadCheck")?;
            Ok(Check {
                source: match c.enumeration("source", "org.mockserver.load.LoadCheck$Source", CHECK_SOURCES)? {
                    Some(0) => Some(CheckSource::Status),
                    Some(1) => Some(CheckSource::Header),
                    Some(_) => Some(CheckSource::BodyJsonPath),
                    None => None,
                },
                header_name: c.string("headerName")?,
                json_path: c.string("jsonPath")?,
                comparator: c.enumeration("comparator", "org.mockserver.load.LoadCheck$Comparator", CHECK_COMPARATORS)?,
                value: c.string("value")?,
            })
        })
        .collect::<Result<Vec<_>, BindError>>()?;
    Ok(Step {
        request,
        think_time,
        name: b.string("name")?,
        labels: b.string_map("labels")?.filter(|l| !l.is_empty()),
        captures,
        checks,
        weight: b.double("weight")?,
    })
}

/// `SocketAddress.port` is an `Integer`: a numeric string is read as its number.
fn socket_port_as_number(mut request: Value) -> Result<Value, BindError> {
    if let Some(port) = request.pointer_mut("/socketAddress/port") {
        match port {
            Value::String(s) => *port = s.trim().parse::<i64>().map(Value::from).map_err(|_| BindError::mismatch())?,
            Value::Number(_) | Value::Null => {}
            _ => return Err(BindError::mismatch()),
        }
    }
    Ok(request)
}

/// `LoadScenarioSerializer.deserialize`: `Err` for anything the object mapper rejects.
pub fn scenario_of(v: &Value) -> Result<Scenario, BindError> {
    let b = Bean::of(v, "org.mockserver.serialization.model.LoadScenarioDTO")?;
    let steps = bound_list(&b, "steps", step_of)?;
    let profile = match b.get("profile") {
        None | Some(Value::Null) => None,
        Some(p) => Some(b.located("profile", profile_of(p))?),
    };
    let thresholds = list(&b, "thresholds")?
        .into_iter()
        .map(|t| {
            let t = Bean::of(t, "org.mockserver.serialization.model.LoadThresholdDTO")?;
            Ok(Threshold {
                metric: t.enumeration("metric", "org.mockserver.load.LoadThreshold$Metric", THRESHOLD_METRICS)?,
                comparator: t.enumeration("comparator", "org.mockserver.slo.SloObjective$Comparator", SLO_COMPARATORS)?,
                threshold: t.double("threshold")?.unwrap_or(0.0),
            })
        })
        .collect::<Result<Vec<_>, BindError>>()?;
    let pacing = match b.bean("pacing", "org.mockserver.serialization.model.LoadPacingDTO")? {
        Some(p) => Some(Pacing { mode: p.enumeration("mode", "org.mockserver.load.LoadPacing$Mode", PACING_MODES)?.unwrap_or(0), value: p.double("value")?.unwrap_or(0.0) }),
        None => None,
    };
    let feeder = match b.bean("feeder", "org.mockserver.load.LoadFeeder")? {
        Some(f) => {
            let rows = match f.get("rows") {
                None | Some(Value::Null) => None,
                Some(Value::Array(items)) => Some(
                    items
                        .iter()
                        .map(|row| match row {
                            Value::Null => Ok(Vec::new()),
                            Value::Object(o) => o.iter().map(|(k, v)| Ok((k.clone(), scalar_string(v)?))).collect(),
                            _ => Err(BindError::mismatch()),
                        })
                        .collect::<Result<Vec<Row>, BindError>>()?,
                ),
                Some(_) => return Err(BindError::mismatch()),
            };
            Some(Feeder {
                rows,
                data: f.string("data")?,
                format: f.enumeration("format", "org.mockserver.load.LoadFeeder$Format", FEEDER_FORMATS)?,
                strategy: match f.get("strategy") {
                    None => 0,
                    Some(_) => f.enumeration("strategy", "org.mockserver.load.LoadFeeder$Strategy", FEEDER_STRATEGIES)?.unwrap_or(usize::MAX),
                },
            })
        }
        None => None,
    };
    Ok(Scenario {
        name: b.string("name")?,
        steps,
        profile,
        template: match b.enumeration("templateType", "org.mockserver.model.HttpTemplate$TemplateType", &["JAVASCRIPT", "VELOCITY", "MUSTACHE"])? {
            Some(0) => Engine::JavaScript,
            Some(2) => Engine::Mustache,
            _ => Engine::Velocity,
        },
        max_requests: b.int("maxRequests")?,
        start_delay: b.long("startDelayMillis")?.unwrap_or(0),
        labels: b.string_map("labels")?.filter(|l| !l.is_empty()),
        thresholds,
        abort_on_fail: b.boolean("abortOnFail")?.unwrap_or(false),
        abort_grace: b.long("abortGraceMillis")?.unwrap_or(0),
        pacing,
        feeder,
        weighted: b.enumeration("stepSelection", "org.mockserver.load.LoadScenario$StepSelection", &["SEQUENTIAL", "WEIGHTED"])? == Some(1),
    })
}

/// A `Map<String, String>` value: scalars coerce to text.
fn scalar_string(v: &Value) -> Result<Option<String>, BindError> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        Value::Bool(b) => Ok(Some(b.to_string())),
        Value::Number(n) => Ok(Some(if n.is_f64() { java_compat::double_to_string(n.as_f64().unwrap_or(0.0)) } else { n.to_string() })),
        _ => Err(BindError::mismatch()),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Serialisation (`LoadScenarioDTO` written with MockServer's object mapper: properties alphabetical, empty left out)
// ---------------------------------------------------------------------------------------------------------------

fn number(v: f64) -> Value {
    serde_json::Number::from_f64(v).map(Value::Number).unwrap_or(Value::Null)
}

fn string_map(entries: &[(String, Option<String>)]) -> Value {
    Value::Object(entries.iter().map(|(k, v)| (k.clone(), v.clone().map(Value::String).unwrap_or(Value::Null))).collect())
}

fn stage_json(s: &Stage) -> Value {
    let mut o = Map::new();
    o.insert("curve".into(), s.curve.name().into());
    o.insert("durationMillis".into(), s.duration.into());
    if let Some(v) = s.end_rate {
        o.insert("endRate".into(), number(v));
    }
    if let Some(v) = s.end_vus {
        o.insert("endVus".into(), v.into());
    }
    if let Some(v) = s.max_vus {
        o.insert("maxVus".into(), v.into());
    }
    if let Some(v) = s.rate {
        o.insert("rate".into(), number(v));
    }
    if let Some(v) = s.start_rate {
        o.insert("startRate".into(), number(v));
    }
    if let Some(v) = s.start_vus {
        o.insert("startVus".into(), v.into());
    }
    o.insert("type".into(), STAGE_TYPES[s.kind as usize].into());
    if let Some(v) = s.vus {
        o.insert("vus".into(), v.into());
    }
    Value::Object(o)
}

fn shape_json(s: &Shape) -> Value {
    let mut o = Map::new();
    let put_f = |o: &mut Map<String, Value>, k: &str, v: Option<f64>| {
        if let Some(v) = v {
            o.insert(k.into(), number(v));
        }
    };
    put_f(&mut o, "baseline", s.baseline);
    o.insert("curve".into(), s.curve.unwrap_or(Curve::Linear).name().into());
    let put_l = |o: &mut Map<String, Value>, k: &str, v: Option<i64>| {
        if let Some(v) = v {
            o.insert(k.into(), v.into());
        }
    };
    put_l(&mut o, "holdMillis", s.hold);
    o.insert("metric".into(), if s.metric_rate { "RATE" } else { "VU" }.into());
    put_f(&mut o, "peak", s.peak);
    put_l(&mut o, "rampDownMillis", s.ramp_down);
    put_l(&mut o, "rampMillis", s.ramp);
    put_l(&mut o, "rampUpMillis", s.ramp_up);
    put_l(&mut o, "recoveryHoldMillis", s.recovery_hold);
    put_f(&mut o, "start", s.start);
    put_f(&mut o, "step", s.step);
    put_l(&mut o, "stepDurationMillis", s.step_duration);
    if let Some(v) = s.steps {
        o.insert("steps".into(), v.into());
    }
    put_f(&mut o, "target", s.target);
    if let Some(k) = s.kind {
        o.insert("type".into(), SHAPE_TYPES[k].into());
    }
    Value::Object(o)
}

pub fn profile_json(p: &Profile) -> Value {
    let mut o = Map::new();
    if let Some(shape) = &p.shape {
        o.insert("shape".into(), shape_json(shape));
    }
    if !p.raw_stages.is_empty() {
        o.insert("stages".into(), Value::Array(p.raw_stages.iter().map(stage_json).collect()));
    }
    Value::Object(o)
}

fn step_json(s: &Step) -> Value {
    let mut o = Map::new();
    if !s.captures.is_empty() {
        let captures = s
            .captures
            .iter()
            .map(|c| {
                let mut m = Map::new();
                opt(&mut m, "defaultValue", &c.default_value);
                opt(&mut m, "expression", &c.expression);
                opt(&mut m, "name", &c.name);
                if let Some(source) = c.source {
                    m.insert("source".into(), ["BODY_JSONPATH", "HEADER", "BODY_REGEX"][source as usize].into());
                }
                Value::Object(m)
            })
            .collect();
        o.insert("captures".into(), Value::Array(captures));
    }
    if !s.checks.is_empty() {
        let checks = s
            .checks
            .iter()
            .map(|c| {
                let mut m = Map::new();
                if c.comparator.is_some() {
                    m.insert("comparator".into(), c.comparator_name().into());
                }
                opt(&mut m, "headerName", &c.header_name);
                opt(&mut m, "jsonPath", &c.json_path);
                if c.source.is_some() {
                    m.insert("source".into(), c.source_name().into());
                }
                m.insert("valid".into(), c.is_valid().into());
                opt(&mut m, "value", &c.value);
                Value::Object(m)
            })
            .collect();
        o.insert("checks".into(), Value::Array(checks));
    }
    if let Some(labels) = &s.labels {
        o.insert("labels".into(), string_map(labels));
    }
    opt(&mut o, "name", &s.name);
    if let Some(r) = &s.request {
        o.insert("request".into(), r.clone());
    }
    if let Some(t) = &s.think_time {
        o.insert("thinkTime".into(), t.clone());
    }
    if let Some(w) = s.weight {
        o.insert("weight".into(), number(w));
    }
    Value::Object(o)
}

fn opt(o: &mut Map<String, Value>, key: &str, v: &Option<String>) {
    if let Some(v) = v {
        o.insert(key.into(), v.clone().into());
    }
}

/// `LoadScenarioSerializer.serialize` read back as a tree: the definition a registry keeps.
pub fn scenario_json(s: &Scenario) -> Value {
    let mut o = Map::new();
    if s.abort_grace > 0 {
        o.insert("abortGraceMillis".into(), s.abort_grace.into());
    }
    if s.abort_on_fail {
        o.insert("abortOnFail".into(), true.into());
    }
    if let Some(f) = &s.feeder {
        let mut m = Map::new();
        opt(&mut m, "data", &f.data);
        if let Some(format) = f.format {
            m.insert("format".into(), FEEDER_FORMATS[format].into());
        }
        if let Some(rows) = &f.rows {
            m.insert("rows".into(), Value::Array(rows.iter().map(|r| string_map(r)).collect()));
        }
        if let Some(strategy) = FEEDER_STRATEGIES.get(f.strategy) {
            m.insert("strategy".into(), (*strategy).into());
        }
        o.insert("feeder".into(), Value::Object(m));
    }
    if let Some(labels) = &s.labels {
        o.insert("labels".into(), string_map(labels));
    }
    if let Some(max) = s.max_requests {
        o.insert("maxRequests".into(), max.into());
    }
    opt(&mut o, "name", &s.name);
    if let Some(p) = s.pacing.as_ref().filter(|p| p.mode != 0) {
        o.insert("pacing".into(), json!({"mode": PACING_MODES[p.mode], "value": number(p.value)}));
    }
    if let Some(p) = &s.profile {
        o.insert("profile".into(), profile_json(p));
    }
    if s.start_delay > 0 {
        o.insert("startDelayMillis".into(), s.start_delay.into());
    }
    if s.weighted {
        o.insert("stepSelection".into(), "WEIGHTED".into());
    }
    if !s.steps.is_empty() {
        o.insert("steps".into(), Value::Array(s.steps.iter().map(step_json).collect()));
    }
    o.insert(
        "templateType".into(),
        match s.template {
            Engine::JavaScript => "JAVASCRIPT",
            Engine::Mustache => "MUSTACHE",
            Engine::Velocity => "VELOCITY",
        }
        .into(),
    );
    if !s.thresholds.is_empty() {
        let thresholds = s
            .thresholds
            .iter()
            .map(|t| {
                let mut m = Map::new();
                if let Some(c) = t.comparator_name() {
                    m.insert("comparator".into(), c.into());
                }
                if let Some(metric) = t.metric_name() {
                    m.insert("metric".into(), metric.into());
                }
                m.insert("threshold".into(), number(t.threshold));
                Value::Object(m)
            })
            .collect();
        o.insert("thresholds".into(), Value::Array(thresholds));
    }
    Value::Object(o)
}

// ---------------------------------------------------------------------------------------------------------------
// Validation (`LoadScenarioOrchestrator.validate`)
// ---------------------------------------------------------------------------------------------------------------

pub fn validate(state: &State, s: &Scenario) -> Option<String> {
    let config = &state.config;
    if s.name.as_deref().is_none_or(|n| n.trim().is_empty()) {
        return Some("'name' is required".into());
    }
    if s.steps.is_empty() {
        return Some("'steps' must contain at least one step".into());
    }
    let max_steps = config.int_property("loadGenerationMaxSteps", 50);
    if s.steps.len() as i64 > max_steps {
        return Some(format!("'steps' exceeds the maximum of {max_steps}"));
    }
    for (i, step) in s.steps.iter().enumerate() {
        if step.request.is_none() {
            return Some(format!("step[{i}] must have a request"));
        }
        if step.weight.is_some_and(|w| !w.is_finite()) {
            return Some(format!("step[{i}].weight must be a finite number"));
        }
    }
    if s.weighted {
        if let Some(i) = s.steps.iter().position(|step| step.weight_or_one() <= 0.0) {
            return Some(format!("step[{i}].weight must be > 0 when stepSelection is WEIGHTED"));
        }
        let total: f64 = s.steps.iter().map(Step::weight_or_one).sum();
        if !(total > 0.0 && total.is_finite()) {
            return Some("'steps' total weight must be a finite number > 0 when stepSelection is WEIGHTED".into());
        }
    }
    let Some(profile) = &s.profile else { return Some("'profile' is required".into()) };
    // The stage cap is checked on the count before the stages are read, so an oversized shape (STAIRS with a huge
    // 'steps') is refused without being expanded.
    let max_stages = config.int_property("loadGenerationMaxStages", 20);
    let stage_count = profile.stage_count();
    match &profile.shape {
        Some(shape) if profile.raw_stages.is_empty() => {
            if let Some(error) = shape.non_finite_parameter() {
                return Some(error);
            }
            let limit = max_stages.min(MAX_EXPANDED_STAGES);
            if stage_count > limit {
                return Some(format!("'profile.shape' expands to {stage_count} stages, which exceeds the maximum of {limit}"));
            }
        }
        _ if stage_count > max_stages => return Some(format!("'profile.stages' exceeds the maximum of {max_stages}")),
        _ => {}
    }
    let stages = profile.stages();
    if stages.is_empty() {
        if profile.shape.is_some() {
            return Some("'profile.shape' expands to no stages; check its parameters (durations and step count must be > 0)".into());
        }
        return Some("'profile' must contain either 'stages' or a 'shape'".into());
    }
    let max_vus = config.int_property("loadGenerationMaxVirtualUsers", 50);
    let max_rate = config.property("loadGenerationMaxRate").and_then(|v| v.trim().parse::<f64>().ok()).unwrap_or(5000.0);
    let mut any_load = false;
    for (i, stage) in stages.iter().enumerate() {
        if [stage.rate, stage.start_rate, stage.end_rate].iter().any(|r| r.is_some_and(|r| !r.is_finite())) {
            return Some(format!("stage[{i}] rate, startRate and endRate must be finite numbers"));
        }
        if stage.duration <= 0 {
            return Some(format!("stage[{i}].durationMillis must be > 0"));
        }
        match stage.kind {
            StageType::Vu => {
                if !stage.is_vu_ramp() && stage.vus.is_none() {
                    return Some(format!("stage[{i}] VU stage requires vus (hold) or startVus+endVus (ramp)"));
                }
                if stage.peak_vus() <= 0 {
                    return Some(format!("stage[{i}] must request at least one virtual user"));
                }
                if i64::from(stage.peak_vus()) > max_vus {
                    return Some(format!("stage[{i}] requests {} virtual users, exceeding the maximum of {max_vus}", stage.peak_vus()));
                }
                any_load = true;
            }
            StageType::Rate => {
                if !stage.is_rate_ramp() && stage.rate.is_none() {
                    return Some(format!("stage[{i}] RATE stage requires rate (hold) or startRate+endRate (ramp)"));
                }
                if stage.peak_rate() <= 0.0 {
                    return Some(format!("stage[{i}] must request a positive arrival rate"));
                }
                if stage.peak_rate() > max_rate {
                    return Some(format!(
                        "stage[{i}] requests {} iterations/sec, exceeding the maximum of {}",
                        java_compat::double_to_string(stage.peak_rate()),
                        java_compat::double_to_string(max_rate)
                    ));
                }
                if let Some(cap) = stage.max_vus.filter(|m| i64::from(*m) > max_vus) {
                    return Some(format!("stage[{i}].maxVus {cap} exceeds the maximum of {max_vus}"));
                }
                any_load = true;
            }
            StageType::Pause => {}
        }
    }
    if !any_load {
        return Some("'profile' must contain at least one VU or RATE stage".into());
    }
    let total = profile.total_duration();
    if total <= 0 {
        return Some("'profile' total duration must be > 0".into());
    }
    let max_duration = config.int_property("loadGenerationMaxDurationMillis", 3_600_000);
    if total > max_duration {
        return Some(format!("'profile' total duration {total} ms exceeds the maximum of {max_duration} ms"));
    }
    if s.template == Engine::JavaScript {
        return Some("templateType JAVASCRIPT is not supported for load steps; use VELOCITY or MUSTACHE".into());
    }
    if s.pacing.as_ref().is_some_and(|p| !p.value.is_finite()) {
        return Some("'pacing.value' must be a finite number".into());
    }
    if let Some(p) = s.pacing.as_ref().filter(|p| p.mode != 0 && p.value <= 0.0) {
        return Some(format!("'pacing.value' must be > 0 when 'pacing.mode' is {}", PACING_MODES[p.mode]));
    }
    if let Some(i) = s.thresholds.iter().position(|t| !t.threshold.is_finite()) {
        return Some(format!("thresholds[{i}].threshold must be a finite number"));
    }
    if let Some(feeder) = &s.feeder {
        match feeder.resolved_rows() {
            Err(message) => return Some(message),
            Ok(rows) if rows.is_empty() => return Some("'feeder' must resolve to at least one row (set 'feeder.rows' or 'feeder.data'+'feeder.format')".into()),
            Ok(_) => {}
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------------------------
// Registry and endpoints
// ---------------------------------------------------------------------------------------------------------------

/// `LoadScenarioRegistry` and the orchestrator's runs.
#[derive(Default)]
pub struct Load {
    /// `LoadScenarioRegistry`: the state backend's `load-scenarios` store (see [`Load::attach_registry`]).
    definitions: crate::state_backend::registry::Registry,
    pub runs: run::Orchestrator,
}

/// `LoadScenarioRegistry.BACKEND_NAMESPACE`.
pub const BACKEND_NAMESPACE: &str = "load-scenarios";

impl Load {
    /// `new LoadScenarioRegistry(stateBackend)`: the definitions live in the backend's `load-scenarios` store,
    /// single-node too (so a reset leaves them, and a clustered fleet shares them).
    pub fn attach_registry(&self, backend: &dyn crate::state_backend::StateBackend) {
        self.definitions.attach(backend, BACKEND_NAMESPACE);
    }

    pub fn reset(&self) {
        self.runs.reset();
    }
}

/// `HttpState.preloadLoadScenarios`: the definitions of `loadScenarioInitializationJsonPath` (an object or an array of
/// them; the class path resource of that name, else the file) are loaded at startup, LOADED and not running. Fail-soft: a definition that does not bind or validate is
/// logged and skipped, and a file that cannot be read or parsed is logged and ignored.
pub fn preload(state: &State) {
    use crate::recorded::{Kind, Level, LogEntry};
    let Some(path) = state.config.property("loadScenarioInitializationJsonPath").filter(|p| !p.trim().is_empty()) else { return };
    let warn = |entry: LogEntry| crate::log::warn_event(state, entry.kind(Kind::ServerConfiguration));
    let root = match crate::class_path::read_string_or_file(&path).map_err(|e| e.to_string()).and_then(|text| {
        if text.trim().is_empty() { Ok(None) } else { crate::json::parse_lenient_non_finite_as_text(text.as_bytes()).map(Some).map_err(|e| e.to_string()) }
    }) {
        Ok(Some(root)) => root,
        Ok(None) => return,
        Err(_) => return warn(LogEntry::at(Level::Warn, "exception while preloading load scenarios, ignoring file:{}").args([path.as_str()])),
    };
    let definitions = match root {
        Value::Array(items) => items,
        object @ Value::Object(_) => vec![object],
        _ => Vec::new(),
    };
    let mut loaded = 0;
    for definition in definitions {
        let scenario = match scenario_of(&definition) {
            Ok(scenario) => scenario,
            Err(e) => {
                // `LoadScenarioSerializer.deserialize` logs the Jackson exception, then throws.
                let text = definition.to_string();
                let message = format!("exception while parsing{{}}for LoadScenario {}", e.failure(&text).message);
                crate::log::error_event(state, LogEntry::at(Level::Error, message).args([text.as_str()]));
                warn(LogEntry::at(Level::Warn, "exception while preloading a load scenario, skipping it"));
                continue;
            }
        };
        if let Some(error) = validate(state, &scenario) {
            warn(LogEntry::at(Level::Warn, format!("skipping invalid preloaded load scenario '{}': {error}", scenario.name())));
            continue;
        }
        register(state, &scenario);
        loaded += 1;
    }
    if loaded > 0 {
        crate::log::info_event(state, LogEntry::new(Kind::ServerConfiguration, format!("preloaded {loaded} load scenario(s) from:{{}}")).args([path.as_str()]));
    }
}

fn pretty(status: u32, v: &Value) -> Reply {
    Reply::api_body(status, "application/json", crate::json::pretty(v))
}

fn error(status: u32, message: &str) -> Reply {
    pretty(status, &json!({"error": message}))
}

/// Whether `op` (the path after `/mockserver`) is a load-scenario endpoint for `method`.
pub fn owns(method: &str, op: &str) -> bool {
    matches!(method, "GET" | "PUT" | "DELETE") && (op == "/loadScenario" || op.starts_with("/loadScenario/"))
}

pub fn route(state: &std::sync::Arc<State>, request: &HttpRequest, op: &str) -> Option<Reply> {
    let rest = op.strip_prefix("/loadScenario").unwrap_or_default();
    let named = |rest: &str| -> Option<String> {
        let name = rest.strip_prefix('/')?;
        if name.is_empty() || name.contains('/') {
            return None;
        }
        let decoded = crate::chaos::url_decode(name);
        (decoded != "start" && decoded != "stop").then_some(decoded)
    };
    let reply = match (request.method.as_str(), rest) {
        ("PUT", "/start") => start(state, request),
        ("PUT", "/stop") => stop(state, request),
        ("PUT", "/generateFromOpenAPI") => generate_from_openapi(state, request),
        ("PUT", "/generateFromRecording") => generate_from_recording(state, request),
        ("PUT", "") => put(state, request),
        ("GET", "") => {
            let names: Vec<String> = state.load.definitions.names();
            pretty(200, &json!({"scenarios": names.iter().map(|n| node(state, n)).collect::<Vec<_>>()}))
        }
        ("DELETE", "") => {
            state.load.runs.stop_all();
            for name in state.load.definitions.names() {
                state.load.runs.forget(state, &name);
            }
            state.load.definitions.clear();
            state.load.runs.forget_all();
            pretty(200, &json!({"status": "cleared"}))
        }
        ("GET", r) if r.ends_with("/report") && named(&r[..r.len() - "/report".len()]).is_some() => {
            let name = named(&r[..r.len() - "/report".len()]).expect("checked");
            report(state, &name, request.query.iter().find(|(k, _)| k == "format").and_then(|(_, v)| v.first()).map(String::as_str))
        }
        ("GET", r) => match named(r) {
            Some(name) if state.load.definitions.contains(&name) => {
                let node = node(state, &name);
                pretty(200, &node)
            }
            Some(name) => error(404, &format!("no load scenario named '{name}'")),
            None => return None,
        },
        ("DELETE", r) => {
            let name = named(r)?;
            state.load.runs.stop(&name);
            state.load.runs.forget(state, &name);
            let removed = state.load.definitions.remove(&name);
            pretty(200, &json!({"status": if removed { "deleted" } else { "absent" }, "name": name}))
        },
        _ => return None,
    };
    Some(reply)
}

/// `request.getBodyAsJsonOrXmlString()`.
fn body_text(request: &HttpRequest) -> String {
    request.body_json_or_xml_str().into_owned()
}

/// Loads `scenario` under its name, as `handleLoadScenarioPut` does after validating it.
fn register(state: &State, scenario: &Scenario) -> Value {
    let definition = scenario_json(scenario);
    let mut stored = definition.clone();
    stored["name"] = scenario.name().into();
    if let Err(e) = state.load.definitions.put(scenario.name(), stored) {
        eprintln!("ERROR state backend: load scenario: {e}");
    }
    definition
}

fn loaded(state: &State, name: &str) -> serde_json::Map<String, Value> {
    let mut o = Map::new();
    o.insert("status".into(), "loaded".into());
    o.insert("name".into(), name.into());
    o.insert("state".into(), state.load.runs.state_of(name).into());
    o
}

fn put(state: &std::sync::Arc<State>, request: &HttpRequest) -> Reply {
    let body = body_text(request);
    if body.trim().is_empty() {
        return error(400, "request body is required with a load scenario definition");
    }
    let scenario = match crate::json::parse_lenient_non_finite_as_text(body.as_bytes()).ok().filter(Value::is_object).map(|v| scenario_of(&v)) {
        Some(Ok(s)) => s,
        _ => return error(400, &format!("invalid load scenario definition: exception while parsing [{body}] for LoadScenario")),
    };
    if let Some(message) = validate(state, &scenario) {
        return error(400, &message);
    }
    register(state, &scenario);
    crate::chaos::log(state, request, crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, "loaded load scenario:{}").args([&scenario.name()]));
    pretty(200, &Value::Object(loaded(state, scenario.name())))
}

/// `parseLoadScenarioNames`: `None` means every scenario (only when `allow_all`).
fn names(body: &str, allow_all: bool) -> Result<Option<Vec<String>>, ()> {
    if body.trim().is_empty() {
        return Ok(if allow_all { None } else { Some(Vec::new()) });
    }
    let node = crate::json::parse_lenient(body.as_bytes()).map_err(|_| ())?;
    if allow_all && crate::chaos::as_boolean(node.get("all")) {
        return Ok(None);
    }
    let mut names = Vec::new();
    match (node.get("names"), node.get("name")) {
        (Some(Value::Array(items)), _) => names.extend(items.iter().filter_map(Value::as_str).filter(|n| !n.trim().is_empty()).map(str::to_string)),
        (_, Some(Value::String(name))) => names.push(name.clone()),
        _ => {}
    }
    Ok(if allow_all && names.is_empty() { None } else { Some(names) })
}

fn start(state: &std::sync::Arc<State>, request: &HttpRequest) -> Reply {
    if !state.config.bool_property("loadGenerationEnabled", false) {
        return error(403, "load generation not enabled (set loadGenerationEnabled=true)");
    }
    let body = body_text(request);
    let names = match names(&body, false) {
        Ok(Some(names)) => names,
        Ok(None) => Vec::new(),
        Err(()) => return error(400, "invalid load scenario start request: failed to parse the request body"),
    };
    if names.is_empty() {
        return error(400, "request body must specify 'name' or 'names' of registered scenario(s) to start");
    }
    let missing = names.iter().find(|n| !state.load.definitions.contains(n)).cloned();
    if let Some(missing) = missing {
        return error(404, &format!("no load scenario named '{missing}'"));
    }
    let mut started = Vec::new();
    for name in &names {
        let definition = state.load.definitions.get(name).unwrap_or_default();
        let scenario = match scenario_of(&definition) {
            Ok(s) => s,
            Err(_) => return error(400, &format!("invalid load scenario start request: exception while parsing [{definition}] for LoadScenario")),
        };
        match run::start(state, scenario) {
            Ok(entered) => started.push(json!({"name": name, "state": entered})),
            Err(message) => return error(400, &message),
        }
    }
    crate::chaos::log(state, request, crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, "started load scenario(s):{}").args([&format!("[{}]", names.join(", "))]));
    pretty(200, &json!({"started": started, "status": "started"}))
}

fn stop(state: &std::sync::Arc<State>, request: &HttpRequest) -> Reply {
    let body = body_text(request);
    let names = match names(&body, true) {
        Ok(names) => names,
        Err(()) => return error(400, "invalid load scenario stop request: failed to parse the request body"),
    };
    let mut stopped = Vec::new();
    match names {
        None => {
            let all: Vec<String> = state.load.definitions.names();
            for name in all.iter().filter(|n| state.load.runs.is_active(n)) {
                state.load.runs.stop(name);
                stopped.push(json!({"name": name, "state": state.load.runs.state_of(name)}));
            }
        }
        Some(names) => {
            for name in names {
                state.load.runs.stop(&name);
                stopped.push(json!({"name": name, "state": state.load.runs.state_of(&name)}));
            }
        }
    }
    pretty(200, &json!({"stopped": stopped, "status": "stopped"}))
}

/// `loadScenarioNode`: a registered scenario with its definition and, once run, its latest status.
fn node(state: &State, name: &str) -> Value {
    let mut o = Map::new();
    o.insert("name".into(), name.into());
    o.insert("state".into(), state.load.runs.state_of(name).into());
    let definition = state.load.definitions.get(name);
    let start_delay = definition.as_ref().and_then(|d| d.get("startDelayMillis")).and_then(Value::as_i64).unwrap_or(0);
    o.insert("startDelayMillis".into(), start_delay.into());
    if let Some(definition) = definition {
        o.insert("definition".into(), definition);
    }
    if let Some(status) = state.load.runs.status(name) {
        o.insert("elapsedMillis".into(), status.elapsed.into());
        o.insert("currentVus".into(), status.current_vus.into());
        if status.stage_index >= 0 {
            o.insert("stageIndex".into(), status.stage_index.into());
        }
        if let Some(stage_type) = status.stage_type {
            o.insert("stageType".into(), stage_type.into());
            o.insert("currentTarget".into(), number(status.current_target));
        }
        o.insert("requestsSent".into(), status.requests_sent.into());
        o.insert("succeeded".into(), status.succeeded.into());
        o.insert("failed".into(), status.failed.into());
        o.insert("p50Millis".into(), status.p50.into());
        o.insert("p95Millis".into(), status.p95.into());
        o.insert("p99Millis".into(), status.p99.into());
        o.insert("p999Millis".into(), status.p999.into());
        o.insert("droppedIterations".into(), status.dropped.into());
        if let Some(verdict) = status.verdict {
            o.insert("verdict".into(), verdict.into());
        }
        if status.aborted_by_threshold {
            o.insert("abortedByThreshold".into(), true.into());
        }
        if !status.thresholds.is_empty() {
            o.insert("thresholdResults".into(), Value::Array(status.thresholds.iter().map(run::ThresholdResult::json).collect()));
        }
        if !status.checks.is_empty() {
            o.insert("checkResults".into(), Value::Array(status.checks.iter().map(run::CheckResult::json).collect()));
        }
        o.insert("runId".into(), status.run_id.clone().into());
        o.insert("startedAt".into(), status.started_at_epoch.into());
        if let Some(ended) = status.ended_at_epoch {
            o.insert("endedAt".into(), ended.into());
        }
        if let Some(labels) = &status.labels {
            o.insert("labels".into(), string_map(labels));
        }
    }
    Value::Object(o)
}

fn report(state: &State, name: &str, format: Option<&str>) -> Reply {
    let Some(status) = state.load.runs.status(name) else {
        return error(404, &format!("no load scenario run for '{name}'"));
    };
    if format.is_some_and(|f| f.eq_ignore_ascii_case("junit")) {
        // `MediaType.create("application", "xml")`: no charset.
        let mut reply = Reply::api(200);
        reply.headers.push(("content-type".into(), "application/xml".into()));
        reply.body = run::junit_report(&status).into();
        return reply;
    }
    Reply::api_body(200, "application/json", crate::json::pretty(&run::json_report(&status)))
}

/// `generate…` target (`host`, `port`, `scheme`).
struct Target {
    host: Option<String>,
    port: Option<i64>,
    scheme: Option<String>,
}

fn target_of(root: &Value) -> Option<Target> {
    let t = root.get("target").filter(|t| t.is_object())?;
    let text = |k: &str| t.get(k).filter(|v| !v.is_null()).map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string));
    Some(Target { host: text("host"), port: t.get("port").filter(|v| !v.is_null()).map(|v| crate::chaos::as_long(Some(v))), scheme: text("scheme") })
}

impl Target {
    fn has_host(&self) -> bool {
        self.host.as_deref().is_some_and(|h| !h.trim().is_empty())
    }

    /// `applyTarget`: `secure` from the scheme and a `Host` header; `replace` swaps an existing one.
    fn apply(&self, request: &mut Value, replace: bool) {
        if !self.has_host() {
            return;
        }
        let o = request.as_object_mut().expect("request object");
        if self.scheme.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("https")) {
            o.insert("secure".into(), true.into());
        } else {
            o.insert("secure".into(), false.into());
        }
        let mut host = self.host.clone().unwrap_or_default();
        if let Some(port) = self.port.filter(|p| *p > 0) {
            host = format!("{host}:{port}");
        }
        let headers = o.entry("headers").or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(h) = headers {
            if replace {
                let existing: Vec<String> = h.keys().filter(|k| k.eq_ignore_ascii_case("host")).cloned().collect();
                for k in existing {
                    h.remove(&k);
                }
            }
            match h.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case("host")) {
                Some((_, Value::Array(values))) => values.push(host.into()),
                _ => {
                    h.insert("Host".into(), json!([host]));
                }
            }
        }
    }
}

fn default_profile() -> Profile {
    Profile::new(vec![Stage::hold(false, 5.0, 30_000)], None)
}

fn optional_profile(root: &Value) -> Result<Option<Profile>, String> {
    match root.get("profile") {
        None | Some(Value::Null) => Ok(None),
        Some(p) => profile_of(p).map(Some).map_err(|_| "failed to bind the profile".to_string()),
    }
}

fn generated(state: &State, request: &HttpRequest, scenario: Scenario, source: &str) -> Reply {
    if let Some(message) = validate(state, &scenario) {
        return error(400, &message);
    }
    let definition = register(state, &scenario);
    crate::chaos::log(
        state,
        request,
        crate::recorded::LogEntry::new(crate::recorded::Kind::ServerConfiguration, format!("generated and loaded load scenario:{{}}from {source} with {{}}steps"))
            .args([crate::recorded::Arg::from(scenario.name()), crate::recorded::Arg::with_text(scenario.steps.len().into(), scenario.steps.len().to_string())]),
    );
    let mut o = loaded(state, scenario.name());
    o.insert("scenario".into(), definition);
    pretty(200, &Value::Object(o))
}

fn plain_scenario(name: &str, steps: Vec<Step>, profile: Option<Profile>) -> Scenario {
    Scenario {
        name: Some(name.to_string()),
        steps,
        profile: Some(profile.unwrap_or_else(default_profile)),
        template: Engine::Velocity,
        max_requests: None,
        start_delay: 0,
        labels: None,
        thresholds: Vec::new(),
        abort_on_fail: false,
        abort_grace: 0,
        pacing: None,
        feeder: None,
        weighted: false,
    }
}

fn step(request: Value, name: Option<String>, weight: Option<f64>) -> Step {
    Step { request: Some(crate::canonical::request_definition(&request)), think_time: None, name, labels: None, captures: Vec::new(), checks: Vec::new(), weight }
}

/// `handleLoadScenarioGenerateFromOpenAPI` / `LoadScenarioFromOpenAPI.generate`.
fn generate_from_openapi(state: &State, request: &HttpRequest) -> Reply {
    let body = body_text(request);
    if body.trim().is_empty() {
        return error(400, "request body is required with a name and OpenAPI specUrlOrPayload");
    }
    let Ok(root) = crate::json::parse_lenient_non_finite_as_text(body.as_bytes()) else {
        return error(400, "failed to process generate-from-OpenAPI request: failed to parse the request body");
    };
    let Some(name) = root.get("name").and_then(|n| n.as_str().map(str::to_string)).filter(|n| !n.trim().is_empty()) else {
        return error(400, "'name' is required");
    };
    let spec = match root.get("specUrlOrPayload") {
        None | Some(Value::Null) => None,
        Some(o @ Value::Object(_)) => Some(o.to_string()),
        Some(v) => v.as_str().map(str::to_string).or_else(|| Some(v.to_string())),
    };
    let Some(spec) = spec.filter(|s| !s.trim().is_empty()) else {
        return error(400, "'specUrlOrPayload' is required (inline OpenAPI spec, URL or file)");
    };
    let profile = match optional_profile(&root) {
        Ok(p) => p,
        Err(message) => return error(400, &format!("invalid generate-from-OpenAPI request: {message}")),
    };
    let requests = match crate::openapi::checking_spec_fetches(&state.config, || crate::openapi_expectations::load_requests(&spec, state.config.bool_property("generateRealisticExampleValues", false))) {
        Ok(r) => r,
        Err(message) => return error(400, &format!("failed to generate load scenario from OpenAPI: {message}")),
    };
    if requests.operations.is_empty() {
        return error(400, "failed to generate load scenario from OpenAPI: OpenAPI specification contains no operations to generate load steps from");
    }
    let target = target_of(&root).filter(Target::has_host).or_else(|| {
        let url = requests.first_server.as_deref()?;
        let rest = url.split_once("://").map(|(s, r)| (Some(s.to_string()), r))?;
        let authority = rest.1.split('/').next().unwrap_or_default();
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if p.parse::<i64>().is_ok() => (h.to_string(), p.parse().ok()),
            _ => (authority.to_string(), None),
        };
        (!host.is_empty()).then_some(Target { host: Some(host), port, scheme: rest.0 })
    });
    let steps = requests
        .operations
        .into_iter()
        .map(|op| {
            let mut request = op.request;
            if let Some(target) = &target {
                target.apply(&mut request, false);
            }
            step(request, op.operation_id.filter(|id| !id.trim().is_empty()), None)
        })
        .collect();
    generated(state, request, plain_scenario(&name, steps, profile), "OpenAPI")
}

/// `handleLoadScenarioGenerateFromRecording` / `LoadScenarioFromRecording.generate`.
fn generate_from_recording(state: &State, request: &HttpRequest) -> Reply {
    let body = body_text(request);
    if body.trim().is_empty() {
        return error(400, "request body is required with a name");
    }
    let Ok(root) = crate::json::parse_lenient_non_finite_as_text(body.as_bytes()) else {
        return error(400, "failed to process generate-from-recording request: failed to parse the request body");
    };
    let Some(name) = root.get("name").and_then(|n| n.as_str().map(str::to_string)).filter(|n| !n.trim().is_empty()) else {
        return error(400, "'name' is required");
    };
    let templatized = match root.get("mode").filter(|m| !m.is_null()) {
        None => false,
        Some(m) => {
            let text = m.as_str().map_or_else(|| m.to_string(), str::to_string);
            match text.trim().to_ascii_uppercase().as_str() {
                "VERBATIM" => false,
                "TEMPLATIZED" => true,
                _ => return error(400, &format!("invalid 'mode' (expected VERBATIM or TEMPLATIZED): {text}")),
            }
        }
    };
    let max_steps = root.get("maxSteps").filter(|v| !v.is_null()).map(|v| crate::chaos::as_long(Some(v)));
    let target = target_of(&root);
    let profile = match optional_profile(&root) {
        Ok(p) => p,
        Err(message) => return error(400, &format!("invalid generate-from-recording request: {message}")),
    };
    let filter = root.get("requestFilter").filter(|f| !f.is_null()).cloned();
    let recorded = crate::control::recorded_requests(state, filter.as_ref());
    let no_traffic = || error(409, "failed to generate load scenario from recording: no recorded requests to convert into a load scenario (record traffic through the proxy first)");
    if recorded.is_empty() {
        return no_traffic();
    }
    let mut scenario = plain_scenario(&name, Vec::new(), profile);
    let apply = |mut r: Value| {
        if let Some(t) = &target {
            t.apply(&mut r, true);
        }
        r
    };
    if templatized {
        let mut routes: Vec<(String, Value, String, usize)> = Vec::new();
        for r in &recorded {
            let method = r.get("method").and_then(Value::as_str).unwrap_or_default().to_string();
            let route = crate::metrics::route_of(r.get("path").and_then(Value::as_str));
            let key = format!("{method} {route}");
            match routes.iter_mut().find(|(k, ..)| *k == key) {
                Some(entry) => entry.3 += 1,
                None => routes.push((key, r.clone(), route, 1)),
            }
        }
        // `List.sort` is stable: equal counts keep first-seen order.
        routes.sort_by_key(|r| std::cmp::Reverse(r.3));
        for (_, representative, route, count) in routes {
            let request = apply(representative);
            let method = request.get("method").and_then(Value::as_str).unwrap_or_default().to_string();
            let name = if method.trim().is_empty() { route } else { format!("{method} {route}") };
            scenario.steps.push(step(request, Some(name), Some(count as f64)));
        }
        scenario.weighted = true;
    } else {
        let limit = match max_steps {
            Some(m) if m > 0 => (m as usize).min(recorded.len()),
            _ => recorded.len(),
        };
        for r in recorded.into_iter().take(limit) {
            scenario.steps.push(step(apply(r), None, None));
        }
    }
    if scenario.steps.is_empty() {
        return no_traffic();
    }
    generated(state, request, scenario, "recorded traffic")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ramp_curves_match_ramp_curve() {
        assert_eq!(Curve::Linear.value_at(0.0, 10.0, 0.5), 5.0);
        assert_eq!(Curve::Quadratic.value_at(0.0, 10.0, 0.5), 2.5);
        assert!((Curve::Exponential.value_at(0.0, 10.0, 0.5) - 1.192_029_220_221_175_6).abs() < 1e-12);
        assert_eq!(Curve::Linear.value_at(0.0, 10.0, 2.0), 10.0);
    }

    #[test]
    fn shapes_expand_like_load_shapes() {
        let spike = Shape { kind: Some(0), baseline: Some(1.0), peak: Some(4.0), ramp_up: Some(100), hold: Some(100), ramp_down: Some(100), recovery_hold: Some(50), ..Default::default() };
        let stages = spike.expand();
        assert_eq!(stages.len(), 4);
        assert_eq!((stages[0].start_vus, stages[0].end_vus), (Some(1), Some(4)));
        assert_eq!(stages[1].vus, Some(4));
        assert_eq!((stages[2].start_vus, stages[2].end_vus), (Some(4), Some(1)));
        assert_eq!(stages[3].vus, Some(1));
        let stairs = Shape { kind: Some(1), metric_rate: true, start: Some(2.0), step: Some(1.5), steps: Some(3), step_duration: Some(10), ..Default::default() };
        let rates: Vec<Option<f64>> = stairs.expand().iter().map(|s| s.rate).collect();
        assert_eq!(rates, vec![Some(2.0), Some(3.5), Some(5.0)]);
    }

    #[test]
    fn stage_targets_follow_the_ramp() {
        let ramp = Stage::ramp(false, 1.0, 3.0, 1000, Curve::Linear);
        assert_eq!(ramp.target_vus_at(0), 1);
        assert_eq!(ramp.target_vus_at(500), 2);
        assert_eq!(ramp.target_vus_at(5000), 3);
        let rate = Stage::ramp(true, 1.0, 2.0, 1000, Curve::Linear);
        assert_eq!(rate.target_rate_at(500), 1.5);
        assert_eq!(rate.target_vus_at(500), 0);
    }
}

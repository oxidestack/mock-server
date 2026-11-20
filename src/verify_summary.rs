//! `VerificationFailureSummary` (upstream 9.1.0, #16 and #43): the `verification summary:` block a failed request,
//! response or sequence verification appends when `detailedVerificationFailures` is on — the counts (or the step
//! that failed), the closest non-matching recorded requests or responses with the names of their differing fields,
//! and how many arrived after the verification started.
//!
//! The arrivals line counts the requests (or exchanges) logged after the verification started; it is printed when there
//! are any, or for a verification with a `timeout`.

use serde_json::Value;

use crate::matcher::{Mode, RequestMatcher, ResponseMatcher};
use crate::recorded::{Exchange, Received};
use crate::request::HttpRequest;

const HEADING: &str = "verification summary:";
const MAX_CLOSEST_REQUESTS: usize = 3;
const MAX_REQUESTS_EVALUATED: usize = 500;
const MAX_DESCRIPTION_LENGTH: usize = 200;

/// `MatchDifference.Field` in declaration order, the order the differing fields are listed in.
const FIELD_ORDER: &[&str] = &crate::matcher::FIELDS;

/// A verification's `times` as the summary needs it.
pub struct Counts {
    /// `VerificationTimes.toString()`
    pub times: String,
    pub matched: i64,
    /// `foundTooOften`: near misses are noise when an upper bound was exceeded.
    pub found_too_often: bool,
}

struct Candidate {
    description: String,
    fields: Vec<String>,
    recency: usize,
}

fn plural(count: usize, noun: &str) -> String {
    format!("{count} {noun}{}", if count == 1 { "" } else { "s" })
}

fn heading() -> String {
    format!("\n\n{HEADING}\n")
}

/// Ranks the most recent `evaluated` items at or after `from`; an item whose differences are `None` (it matched) or
/// empty (nothing recorded to show) is skipped. Fewest differing fields first, then the most recent.
fn closest(size: usize, from: usize, evaluated: usize, differences: impl Fn(usize) -> Option<Vec<String>>, describe: impl Fn(usize) -> String) -> Vec<Candidate> {
    let lowest = from.max(size - evaluated.min(size));
    let mut candidates: Vec<Candidate> = (lowest..size)
        .rev()
        .filter_map(|i| differences(i).filter(|f| !f.is_empty()).map(|fields| Candidate { description: describe(i), fields, recency: size - 1 - i }))
        .collect();
    candidates.sort_by_key(|c| (c.fields.len(), c.recency));
    candidates.truncate(MAX_CLOSEST_REQUESTS);
    candidates
}

fn append_closest(out: &mut String, title: &str, closest: &[Candidate]) {
    if closest.is_empty() {
        return;
    }
    out.push_str(&format!("  {title}\n"));
    for (i, c) in closest.iter().enumerate() {
        out.push_str(&format!("    {}. {} differs in: {}\n", i + 1, c.description, c.fields.join(", ")));
    }
}

/// `appendArrivals`' inputs: the recorded items logged after the verification started, and whether it had a `timeout`.
#[derive(Clone, Copy, Default)]
pub struct Arrivals {
    pub count: usize,
    pub waited: bool,
}

impl Arrivals {
    fn shown(self) -> bool {
        self.count > 0 || self.waited
    }
}

fn append_arrivals(out: &mut String, arrivals: Arrivals, noun: &str) {
    if arrivals.shown() {
        out.push_str(&format!("  {} arrived after verification started\n", plural(arrivals.count, noun)));
    }
}

/// `requestDifferences`: `None` when `matcher` matches `request`, else its differing fields (collect-all) in
/// `MatchDifference.Field` order.
fn request_differences(matcher: &RequestMatcher, request: &HttpRequest, matches: &dyn Fn(&RequestMatcher, &HttpRequest) -> bool) -> Option<Vec<String>> {
    // One evaluation upstream (`matches` in a collect-all context); here the match and the collect-all report are two,
    // so the report's regex timeouts are not logged a second time.
    let all = || crate::matcher::string::unreported_regex_timeouts(|| crate::matcher::with_control_plane(true, || matcher.all_differences(request)));
    // `requestDifferences` matches in a detailed context that collects every field's differences, and each logs at
    // TRACE as it is added (`MatchDifference.addDifference(mockServerLogger, …)`); only the match result is suppressed.
    let traced = crate::matcher::tracing().then(|| {
        let differences = all();
        for (_, texts) in &differences {
            crate::matcher::note_request_differences(texts, request);
        }
        differences
    });
    if matches(matcher, request) {
        return None;
    }
    let differences = traced.unwrap_or_else(all);
    let mut fields: Vec<&str> = differences.iter().map(|(f, _)| *f).collect();
    fields.sort_by_key(|f| FIELD_ORDER.iter().position(|o| o == f).unwrap_or(FIELD_ORDER.len()));
    fields.dedup();
    Some(fields.into_iter().map(str::to_string).collect())
}

/// [`request_differences`] of a recorded request: a DNS query's or binary message's definition, no `HttpRequest`,
/// records no difference, so it is never a closest request.
fn received_differences(matcher: &RequestMatcher, request: &Received, matches: &dyn Fn(&RequestMatcher, &HttpRequest) -> bool) -> Option<Vec<String>> {
    match request {
        Received::Http(r) => request_differences(matcher, r, matches),
        Received::Definition(_) => Some(Vec::new()),
    }
}

fn describe_received(request: &Received) -> String {
    match request {
        Received::Http(r) => describe_request(r),
        Received::Definition(_) => "(not an HTTP request)".to_string(),
    }
}

/// `responseDifferences`: status code and reason phrase (both `OPERATION`) as `response status`, listed first.
fn response_differences(matcher: &ResponseMatcher, response: &Value) -> Option<Vec<String>> {
    if matcher.matches(response) {
        return None;
    }
    let differences = matcher.differences(response);
    let mut fields = Vec::new();
    if differences.iter().any(|(f, _)| *f == "operation") {
        fields.push("response status".to_string());
    }
    for field in FIELD_ORDER.iter().filter(|f| **f != "operation") {
        if differences.iter().any(|(f, _)| f == field) {
            fields.push(format!("response {field}"));
        }
    }
    Some(fields)
}

/// `exchangeDifferences`: the request's differing fields, then the response's; `None` when both match (or are
/// unconstrained).
fn exchange_differences(
    request_matcher: Option<&RequestMatcher>,
    response_matcher: Option<&ResponseMatcher>,
    exchange: &Exchange,
) -> Option<Vec<String>> {
    let request = request_matcher.and_then(|m| request_differences(m, &exchange.request, &|m, r| m.matches(r, Mode::ControlPlane)));
    let response = response_matcher.and_then(|m| response_differences(m, &exchange.response));
    if request.is_none() && response.is_none() {
        return None;
    }
    Some(request.into_iter().chain(response).flatten().collect())
}

fn bounded(description: String) -> String {
    let single = description.replace('\n', " ").replace('\r', "");
    if single.chars().count() > MAX_DESCRIPTION_LENGTH {
        format!("{}...[truncated]", single.chars().take(MAX_DESCRIPTION_LENGTH).collect::<String>())
    } else {
        single
    }
}

fn describe_request(request: &HttpRequest) -> String {
    let method = if request.method.is_empty() { String::new() } else { format!("{} ", request.method) };
    let path = if request.path.is_empty() { "(no path)" } else { request.path.as_str() };
    bounded(format!("{method}{path}"))
}

fn describe_exchange(exchange: &Exchange) -> String {
    let status = exchange.response.get("statusCode").and_then(Value::as_i64).map_or_else(|| "no status".to_string(), |s| s.to_string());
    format!("{} returned {status}", describe_request(&exchange.request))
}

/// `build`: a failed request count verification; `""` when the block would add nothing beyond the count. `other` is a
/// verification by disposition's wanted disposition and the count of matching requests handled the other way.
#[allow(clippy::too_many_arguments)]
pub fn requests(
    matcher: &RequestMatcher,
    counts: &Counts,
    remote_matched: i64,
    other: Option<(crate::verify::Disposition, usize)>,
    recorded: &[Received],
    matches: &dyn Fn(&RequestMatcher, &HttpRequest) -> bool,
    arrivals: Arrivals,
) -> String {
    let size = recorded.len();
    let evaluated = if counts.found_too_often { 0 } else { size.min(MAX_REQUESTS_EVALUATED) };
    let closest = closest(size, 0, evaluated, |i| received_differences(matcher, &recorded[i], matches), |i| describe_received(&recorded[i]));
    let other = other.filter(|(_, n)| *n > 0);
    if closest.is_empty() && other.is_none() && !arrivals.shown() {
        return String::new();
    }
    let mut out = heading();
    out.push_str(&format!("  expected {} but matched {}", counts.times, plural(counts.matched.max(0) as usize, "time")));
    if remote_matched > 0 {
        out.push_str(&format!(" (including {remote_matched} on other cluster nodes)"));
    }
    out.push_str(&format!(" among {}\n", plural(size, "recorded request")));
    if let Some((wanted, n)) = other {
        let was = if n == 1 { "was" } else { "were" };
        out.push_str(&format!("  {} matched but {was} {}, not {}\n", plural(n, "recorded request"), wanted.other().word(), wanted.word()));
    }
    append_closest(&mut out, "closest non-matching requests (fewest differing fields first):", &closest);
    if !counts.found_too_often && evaluated < size {
        out.push_str(&format!("  closest requests ranked from the {evaluated} most recent of {size} recorded requests\n"));
    }
    append_arrivals(&mut out, arrivals, "request");
    out
}

/// `buildForResponses`: a failed response count verification over the recorded exchanges.
pub fn responses(matcher: &ResponseMatcher, counts: &Counts, recorded: &[std::sync::Arc<Exchange>], arrivals: Arrivals) -> String {
    let size = recorded.len();
    let evaluated = if counts.found_too_often { 0 } else { size.min(MAX_REQUESTS_EVALUATED) };
    let closest = closest(size, 0, evaluated, |i| response_differences(matcher, &recorded[i].response), |i| describe_exchange(&recorded[i]));
    if closest.is_empty() && !arrivals.shown() {
        return String::new();
    }
    let mut out = heading();
    out.push_str(&format!(
        "  expected {} but matched {} among {}\n",
        counts.times,
        plural(counts.matched.max(0) as usize, "time"),
        plural(size, "recorded response")
    ));
    append_closest(&mut out, "closest non-matching responses (fewest differing fields first):", &closest);
    if !counts.found_too_often && evaluated < size {
        out.push_str(&format!("  closest responses ranked from the {evaluated} most recent of {size} recorded responses\n"));
    }
    append_arrivals(&mut out, arrivals, "response");
    out
}

/// Where a sequence step failed: its 1-based number, the number of steps, the last step that matched (0 for none)
/// and the index of the first recorded item the failed step was checked against.
pub struct Step {
    pub number: usize,
    pub count: usize,
    pub previous: usize,
    pub searched_from: usize,
}

/// `countMatchedBefore`: the items in the window before the previous step's match (itself excluded) that match the
/// failed step.
fn matched_before(window_start: usize, searched_from: usize, matches_step: impl Fn(usize) -> bool) -> usize {
    (window_start..searched_from.saturating_sub(1)).filter(|i| matches_step(*i)).count()
}

#[allow(clippy::too_many_arguments)]
fn sequence_block(step: &Step, noun: &str, size: usize, matched_before: usize, closest: &[Candidate], window_start: usize, arrivals: Arrivals, report_arrivals: bool) -> String {
    let mut out = heading();
    out.push_str(&format!("  step {} of {} not found in ", step.number, step.count));
    if step.previous > 0 {
        out.push_str(&format!(
            "the {} after step {} matched recorded {noun} {} of {size}",
            plural(size - step.searched_from.min(size), &format!("recorded {noun}")),
            step.previous,
            step.searched_from
        ));
    } else {
        out.push_str(&plural(size, &format!("recorded {noun}")));
    }
    out.push('\n');
    if matched_before > 0 {
        out.push_str(&format!(
            "  {} matched step {} but came before step {}'s match\n",
            plural(matched_before, &format!("recorded {noun}")),
            step.number,
            step.previous
        ));
    }
    append_closest(&mut out, &format!("closest non-matching {noun}s for step {} (fewest differing fields first):", step.number), closest);
    if window_start > 0 {
        out.push_str(&format!("  only the {} most recent of {size} recorded {noun}s were checked\n", size - window_start));
    }
    if report_arrivals {
        append_arrivals(&mut out, arrivals, noun);
    }
    out
}

/// `buildForRequestSequence`: `matcher` is the failed step's, `None` when it is no HTTP request matcher (its near
/// misses are not ranked).
pub fn request_sequence(step: &Step, matcher: Option<&RequestMatcher>, recorded: &[Received], arrivals: Arrivals) -> String {
    let size = recorded.len();
    let Some(matcher) = matcher else {
        return sequence_block(step, "request", size, 0, &[], 0, arrivals, true);
    };
    let window_start = size.saturating_sub(MAX_REQUESTS_EVALUATED);
    let matches = |m: &RequestMatcher, r: &HttpRequest| m.matches(r, Mode::ControlPlane);
    let differences = |i: usize| received_differences(matcher, &recorded[i], &matches);
    let closest = closest(size, step.searched_from, size - window_start, differences, |i| describe_received(&recorded[i]));
    // `differences.apply(index) == null`: the same detailed evaluation, its TRACE differences included.
    let before = matched_before(window_start, step.searched_from, |i| differences(i).is_none());
    sequence_block(step, "request", size, before, &closest, window_start, arrivals, true)
}

/// `buildForResponseSequence`: `rankable` is false when the step's request is no HTTP request matcher, so only the
/// step line is given.
pub fn response_sequence(
    step: &Step,
    rankable: bool,
    request_matcher: Option<&RequestMatcher>,
    response_matcher: Option<&ResponseMatcher>,
    recorded: &[std::sync::Arc<Exchange>],
    arrivals: Arrivals,
) -> String {
    let size = recorded.len();
    if !rankable {
        return sequence_block(step, "response", size, 0, &[], 0, arrivals, true);
    }
    let window_start = size.saturating_sub(MAX_REQUESTS_EVALUATED);
    let differences = |i: usize| exchange_differences(request_matcher, response_matcher, &recorded[i]);
    let closest = closest(size, step.searched_from, size - window_start, differences, |i| describe_exchange(&recorded[i]));
    let before = matched_before(window_start, step.searched_from, |i| differences(i).is_none());
    sequence_block(step, "response", size, before, &closest, window_start, arrivals, true)
}

/// `buildForExpectationIdSequence`: steps match by id, so nothing is ranked and no arrivals are reported.
pub fn expectation_id_sequence(step: &Step, recorded_count: usize, matches_step: impl Fn(usize) -> bool) -> String {
    let window_start = recorded_count.saturating_sub(MAX_REQUESTS_EVALUATED);
    let before = matched_before(window_start, step.searched_from, matches_step);
    sequence_block(step, "request", recorded_count, before, &[], window_start, Arrivals::default(), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closest_ranks_fewest_fields_then_most_recent_and_keeps_three() {
        let fields = [vec!["path", "body"], vec!["path"], vec![], vec!["headers"], vec!["body"]];
        let picked = closest(fields.len(), 0, fields.len(), |i| Some(fields[i].iter().map(|f| f.to_string()).collect()), |i| i.to_string());
        let order: Vec<&str> = picked.iter().map(|c| c.description.as_str()).collect();
        assert_eq!(order, ["4", "3", "1"]);
    }

    #[test]
    fn closest_evaluates_only_the_most_recent_window_after_from() {
        let picked = closest(10, 2, 5, |_| Some(vec!["path".to_string()]), |i| i.to_string());
        let order: Vec<&str> = picked.iter().map(|c| c.description.as_str()).collect();
        assert_eq!(order, ["9", "8", "7"]);
        let picked = closest(10, 8, 5, |_| Some(vec!["path".to_string()]), |i| i.to_string());
        assert_eq!(picked.len(), 2);
    }

    #[test]
    fn sequence_block_names_the_window_and_the_earlier_matches() {
        let step = Step { number: 2, count: 2, previous: 1, searched_from: 600 };
        let block = sequence_block(&step, "request", 700, 3, &[], 200, Arrivals::default(), true);
        assert_eq!(
            block,
            "\n\nverification summary:\n  step 2 of 2 not found in the 100 recorded requests after step 1 matched recorded request 600 of 700\n  \
             3 recorded requests matched step 2 but came before step 1's match\n  only the 500 most recent of 700 recorded requests were checked\n"
        );
    }

    #[test]
    fn a_long_description_is_cut_at_two_hundred_characters() {
        let long = format!("GET /{}", "a".repeat(300));
        let cut = bounded(long);
        assert!(cut.ends_with("...[truncated]"));
        assert_eq!(cut.chars().count(), MAX_DESCRIPTION_LENGTH + "...[truncated]".len());
    }
}

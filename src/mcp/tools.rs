//! `McpToolRegistry`: the tool catalogue (`tools.json`, the definitions in the order the oracle lists them) and the
//! tools themselves. A tool answers a JSON object; `{"error": true, "message": …}` reports a failure.

use std::sync::{Arc, LazyLock};

use serde_json::{Map, Value, json};

use crate::state::State;

static CATALOGUE: LazyLock<Vec<Value>> = LazyLock::new(|| serde_json::from_str(include_str!("tools.json")).expect("tools.json"));

/// `tools/list`'s tools: name, description, input schema.
pub fn catalogue() -> Vec<Value> {
    CATALOGUE.clone()
}

pub fn exists(name: &str) -> bool {
    CATALOGUE.iter().any(|t| t["name"] == name)
}

/// `errorResult`.
pub(super) fn error(message: &str) -> Value {
    json!({"error": true, "message": message})
}

/// `callTool`.
pub async fn call(state: &Arc<State>, name: &str, arguments: &Value) -> Value {
    let arguments = if arguments.is_object() { arguments.clone() } else { json!({}) };
    match name {
        "get_status" => json!({"ports": state.ports(), "running": state.is_running()}),
        "reset" => {
            super::internal(state, "PUT", "/mockserver/reset", "").await;
            json!({"status": "reset", "message": "MockServer has been reset"})
        }
        "record_llm_fixtures" => record_llm_fixtures(state, &arguments).await,
        "list_expectations" => list_expectations(state, &arguments).await,
        "create_expectation" => create_expectation(state, &arguments).await,
        "verify_request" => verify_request(state, &arguments).await,
        "verify_request_sequence" => verify_request_sequence(state, &arguments).await,
        "retrieve_recorded_requests" => retrieve_limited(state, &arguments, "REQUESTS", "requests", "Failed to retrieve requests").await,
        "retrieve_request_responses" => retrieve_limited(state, &arguments, "REQUEST_RESPONSES", "requestResponses", "Failed to retrieve request-response pairs").await,
        "retrieve_logs" => retrieve_logs(state, &arguments).await,
        "clear_expectations" => clear_expectations(state, &arguments).await,
        "manage_service_chaos" => manage_service_chaos(state, &arguments),
        "create_forward_expectation" => create_forward_expectation(state, &arguments).await,
        "debug_request_mismatch" => debug_request_mismatch(state, &arguments).await,
        "explain_unmatched_requests" => {
            let limit = as_int(&arguments, "limit", 10);
            if !(1..=100).contains(&limit) {
                return error("'limit' must be between 1 and 100");
            }
            parse(&super::internal(state, "PUT", "/mockserver/explainUnmatched", &format!("{{\"limit\":{limit}}}")).await.1)
        }
        "explain_request" => explain_request(state, &arguments).await,
        "diagnose_config" => diagnose_config(state, &arguments),
        "explain_forward_failure" => explain_forward_failure(state, &arguments),
        "test_template" => test_template(state, &arguments).await,
        "lint_expectations" => lint_expectations(state, &arguments).await,
        "suggest_expectation_fix" => suggest_expectation_fix(state, &arguments).await,
        "create_expectation_from_openapi" => create_expectation_from_openapi(state, &arguments).await,
        "create_expectations_from_recorded_traffic" => create_expectations_from_recorded_traffic(state, &arguments).await,
        "stop_server" => {
            let state = state.clone();
            tokio::spawn(async move { state.stop().await });
            json!({"status": "stopping", "message": "MockServer is shutting down"})
        }
        "raw_expectation" => raw_expectation(state, &arguments).await,
        "export_optimisation_report" => export_optimisation_report(state, &arguments),
        "raw_retrieve" => raw_retrieve(state, &arguments).await,
        "raw_verify" => raw_verify(state, &arguments).await,
        "load_expectations_from_file" => load_expectations_from_file(state, &arguments).await,
        "set_operating_mode" => {
            let Some(mode) = text(&arguments, "mode") else { return error("'mode' is required (one of SIMULATE, SPY, CAPTURE)") };
            match crate::control::set_mode(state, Some(mode)) {
                Ok(mode) => json!({"status": "ok", "mode": mode, "proxyUnmatchedRequests": mode != "SIMULATE"}),
                Err(message) => error(&message),
            }
        }
        "promote_recordings" => promote_recordings(state, &arguments),
        "explain_agent_run" => super::llm_tools::explain_agent_run(state, &arguments).await,
        "diff_agent_runs" => super::llm_tools::diff_agent_runs(state, &arguments),
        "verify_tool_call" => super::llm_tools::verify_tool_call(state, &arguments),
        "verify_structured_output" => super::llm_tools::verify_structured_output(state, &arguments),
        "verify_cost_budget" => super::llm_tools::verify_cost_budget(state, &arguments),
        "list_mock_tools" => super::spec_tools::list_mock_tools(state).await,
        "verify_traffic_against_openapi" => super::spec_tools::verify_traffic_against_openapi(state, &arguments),
        "run_contract_test" => super::spec_tools::run_contract_test(state, &arguments).await,
        "run_resiliency_test" => super::spec_tools::run_resiliency_test(state, &arguments).await,
        "run_mcp_contract_test" => super::spec_tools::run_mcp_contract_test(state, &arguments).await,
        "detect_llm_drift" => super::llm_tools::detect_llm_drift(state, &arguments).await,
        "mock_llm_completion" => super::llm_tools::mock_llm_completion(state, &arguments).await,
        "create_llm_conversation" => super::llm_tools::create_llm_conversation(state, &arguments).await,
        "mock_llm_failover" => super::llm_tools::mock_llm_failover(state, &arguments).await,
        "mock_adversarial_llm_response" => super::llm_tools::mock_adversarial_llm_response(state, &arguments).await,
        other => error(&format!("the {other} tool is not supported by mock-server yet")),
    }
}

/// `handleExplainRequest`: `httpState.explain` of one correlation id; a non-200 answer becomes an error result
/// carrying the explain error and the id.
async fn explain_request(state: &Arc<State>, args: &Value) -> Value {
    let Some(id) = text(args, "correlationId").filter(|id| !id.trim().is_empty()) else { return error("'correlationId' is required") };
    let query: String = form_urlencoded::byte_serialize(id.as_bytes()).collect();
    let (status, body) = super::internal(state, "PUT", &format!("/mockserver/explain?correlationId={query}"), "").await;
    let body = parse(&body);
    if status != 200 {
        // `path("error").asText(default)`: the default for a missing or null node, "" for a container
        let message = match body.get("error") {
            None | Some(Value::Null) => "Failed to explain request".to_string(),
            Some(Value::String(e)) => e.clone(),
            Some(Value::Object(_) | Value::Array(_)) => String::new(),
            Some(e) => e.to_string(),
        };
        let mut result = error(&message);
        result["correlationId"] = json!(id);
        return result;
    }
    body
}

/// `result.path("error").asText(default)`: the default for a missing or null node, "" for a container.
fn error_text(body: &Value, default: &str) -> String {
    match body.get("error") {
        None | Some(Value::Null) => default.to_string(),
        Some(Value::String(e)) => e.clone(),
        Some(Value::Object(_) | Value::Array(_)) => String::new(),
        Some(e) => e.to_string(),
    }
}

/// An optional argument that, when present and not null, must be a non-blank string: `Err` when it is not.
fn optional_non_blank<'a>(args: &'a Value, key: &str) -> Result<Option<&'a str>, ()> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s)),
        Some(_) => Err(()),
    }
}

/// `handleDiagnoseConfig`: the properties set away from their default (or, with `name`, every property whose
/// normalised name contains it), the counts, the unrecognised keys by name only, and a hint when nothing matches.
fn diagnose_config(state: &State, args: &Value) -> Value {
    use crate::property_file::{SetAs, normalise_key, suggest_recognised_keys};
    let requested = text(args, "name").map(str::trim).unwrap_or("");
    let filter = normalise_key(requested);
    let resolved = state.config.effective_configuration();
    let mut matching = Vec::new();
    let mut explicitly_set = 0;
    for property in &resolved {
        let at_default = property.source == crate::config::SOURCE_DEFAULT;
        if !at_default {
            explicitly_set += 1;
        }
        if if filter.is_empty() { !at_default } else { normalise_key(property.name).contains(&filter) } {
            let mut node = Map::new();
            node.insert("name".into(), json!(property.name));
            node.insert("value".into(), json!(property.value));
            node.insert("source".into(), json!(property.source));
            if let Some(default) = &property.default {
                node.insert("default".into(), json!(default));
            }
            matching.push(Value::Object(node));
        }
    }
    let mut result = Map::new();
    let count = matching.len();
    result.insert("properties".into(), Value::Array(matching));
    result.insert("count".into(), json!(count));
    result.insert("explicitlySetCount".into(), json!(explicitly_set));
    result.insert("totalProperties".into(), json!(resolved.len()));
    let unrecognised: Vec<Value> = state
        .config
        .unrecognised_configuration()
        .iter()
        .map(|p| {
            json!({
                "name": p.name,
                "setAs": p.set_as.text(),
                "suggestions": p.suggestions,
                "systemPropertyOnly": p.system_property_only.is_some(),
                "removed": p.removed_because.is_some(),
            })
        })
        .collect();
    result.insert("unrecognised".into(), Value::Array(unrecognised));
    result.insert("note".into(), json!("values come from system properties, the properties file, environment variables and runtime setters; a value set only on an embedded server's Configuration object or through PUT /mockserver/configuration is not shown; each key in 'unrecognised' is ignored, so set the suggested property instead, or delete one marked removed"));
    if !filter.is_empty() && count == 0 {
        let suggestions = suggest_recognised_keys(requested, SetAs::SystemProperty, crate::config::recognised_properties());
        let advice = if suggestions.is_empty() { "check the spelling".to_string() } else { format!("did you mean {}?", suggestions.join(" or ")) };
        result.insert("hint".into(), json!(format!("no recognised configuration property name contains '{requested}'; {advice}")));
        result.insert("suggestions".into(), json!(suggestions));
    }
    Value::Object(result)
}

/// `handleExplainForwardFailure`: `httpState.explainForwardFailures`; a non-200 answer becomes an error result.
fn explain_forward_failure(state: &State, args: &Value) -> Value {
    let Ok(correlation_id) = optional_non_blank(args, "correlationId") else { return error("'correlationId' must be a non-blank string") };
    let limit = as_int(args, "limit", 5);
    if !(1..=20).contains(&limit) {
        return error("'limit' must be between 1 and 20");
    }
    let (status, body) = crate::explain::forward_failures(state, correlation_id, limit);
    if status != 200 {
        let mut result = error(&error_text(&body, "Failed to explain forward failure"));
        if let Some(id) = correlation_id {
            result["correlationId"] = json!(id);
        }
        return result;
    }
    body
}

/// `handleTestTemplate`: `PUT /mockserver/template/test` with the non-null template fields.
async fn test_template(state: &Arc<State>, args: &Value) -> Value {
    let mut body = Map::new();
    for field in ["templateType", "template", "actionType", "request"] {
        if present(args, field) {
            body.insert(field.into(), args[field].clone());
        }
    }
    let (status, reply) = super::internal(state, "PUT", "/mockserver/template/test", &Value::Object(body).to_string()).await;
    let result = parse(&reply);
    if status != 200 {
        return error(&error_text(&result, "Failed to test template"));
    }
    result
}

/// `LINT_MAX_ISSUES_RETURNED`
const LINT_MAX_ISSUES: i64 = 1000;

/// `handleLintExpectations`: `PUT /mockserver/lint` over the given expectations or the stored ones, at most
/// `maxIssues` issues returned, errors first.
async fn lint_expectations(state: &Arc<State>, args: &Value) -> Value {
    let max_issues = as_int(args, "maxIssues", 100);
    if !(1..=LINT_MAX_ISSUES).contains(&max_issues) {
        return error(&format!("'maxIssues' must be between 1 and {LINT_MAX_ISSUES}"));
    }
    let body = match args.get("expectations") {
        None | Some(Value::Null) => String::new(),
        Some(e @ (Value::Object(_) | Value::Array(_))) => e.to_string(),
        Some(_) => return error("'expectations' must be an expectation object or an array of expectations"),
    };
    let (status, reply) = super::internal(state, "PUT", "/mockserver/lint", &body).await;
    let mut result = parse(&reply);
    if status != 200 {
        return error(&error_text(&result, "Failed to lint expectations"));
    }
    let max_issues = max_issues as usize;
    if let Some(Value::Array(issues)) = result.get("issues").filter(|_| result.is_object()) && issues.len() > max_issues {
        let rank = |issue: &Value| match issue.get("severity").and_then(Value::as_str) {
            Some("ERROR") => 0,
            Some("WARNING") => 1,
            _ => 2,
        };
        let mut ordered = issues.clone();
        ordered.sort_by_key(rank);
        let omitted = ordered.len() - max_issues;
        ordered.truncate(max_issues);
        result["issues"] = Value::Array(ordered);
        result["issuesReturned"] = json!(max_issues);
        result["issuesOmitted"] = json!(omitted);
    }
    result
}

/// `SUGGEST_FIX_MAX_REQUESTS`
const SUGGEST_FIX_MAX_REQUESTS: i64 = 20;

/// `handleSuggestExpectationFix`: `explainUnmatched` with `suggestFixes`, keeping only the close expectations with a
/// suggested fix (and only `expectationId`'s when given).
async fn suggest_expectation_fix(state: &Arc<State>, args: &Value) -> Value {
    let limit = as_int(args, "limit", 5);
    if !(1..=SUGGEST_FIX_MAX_REQUESTS).contains(&limit) {
        return error(&format!("'limit' must be between 1 and {SUGGEST_FIX_MAX_REQUESTS}"));
    }
    let Ok(expectation_id) = optional_non_blank(args, "expectationId") else { return error("'expectationId' must be a non-blank string") };
    let request = json!({"limit": limit, "suggestFixes": true});
    let (status, reply) = super::internal(state, "PUT", "/mockserver/explainUnmatched", &request.to_string()).await;
    let mut result = parse(&reply);
    if status != 200 || !result.is_object() {
        return error(&error_text(&result, "Failed to suggest expectation fixes"));
    }
    let mut requests = Vec::new();
    let mut fix_count = 0;
    for unmatched in result.get("unmatchedRequests").and_then(Value::as_array).cloned().unwrap_or_default() {
        let with_fix: Vec<Value> = unmatched
            .get("closestExpectations")
            .and_then(Value::as_array)
            .map(|c| {
                c.iter()
                    .filter(|closest| closest.get("suggestedFix").is_some())
                    .filter(|closest| expectation_id.is_none_or(|id| closest.get("expectationId").and_then(Value::as_str) == Some(id)))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        if with_fix.is_empty() && expectation_id.is_some() {
            continue;
        }
        let mut node = if unmatched.is_object() { unmatched } else { json!({}) };
        fix_count += with_fix.len();
        node["closestExpectations"] = Value::Array(with_fix);
        requests.push(node);
    }
    let count = requests.len();
    result["unmatchedRequests"] = Value::Array(requests);
    result["unmatchedRequestCount"] = json!(count);
    result["suggestedFixCount"] = json!(fix_count);
    if fix_count == 0 {
        result["note"] = json!(match expectation_id {
            Some(id) => format!("no recent unmatched request has a suggested fix for expectation '{id}'"),
            None => "no recent unmatched request has a close expectation to fix; explain_unmatched_requests shows every comparison".to_string(),
        });
    }
    result
}

/// `handlePromoteRecordings`: `HttpState.promoteRecordings` over recordings matching `method`/`path`.
fn promote_recordings(state: &State, args: &Value) -> Value {
    let args_node = crate::jnode::from_value(args);
    let flag = |key: &str| args_node.path(key).as_boolean_or(true);
    let filter = crate::matcher::RequestMatcher::compile(&method_path_filter(args));
    let options = if flag("redactSensitiveData") { crate::import::Options::enabled() } else { crate::import::Options::disabled() };
    let activated = crate::import::promote_recordings(state, Some(&filter), flag("consolidate"), flag("parameterize"), &options);
    if activated.is_empty() {
        return json!({
            "status": "no_recorded_traffic",
            "message": "No recorded traffic found matching the filter. Ensure MockServer has forwarded requests (e.g. via set_operating_mode SPY/CAPTURE or create_forward_expectation) before calling this tool.",
            "count": 0,
        });
    }
    let ids: Vec<Value> = activated.iter().map(|e| e["id"].clone()).collect();
    json!({"status": "promoted", "count": activated.len(), "ids": ids})
}

fn text<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}

/// `handleExportOptimisationReport`: the report as a Markdown brief (default), JSON, CSV or a dataset.
fn export_optimisation_report(state: &State, args: &Value) -> Value {
    use crate::llm::report;
    let format = as_text(args, "format").unwrap_or_else(|| "markdown".into());
    let dataset = report::Dataset::from_wire(&format);
    let lower = format.to_lowercase();
    if dataset.is_none() && !["markdown", "json", "csv"].contains(&lower.as_str()) {
        return error("'format' must be one of: markdown, json, csv, openai-evals, fine-tune, promptfoo");
    }
    let filter = |k: &str| as_text(args, k).filter(|v| !v.is_empty());
    let (session, host, provider) = (filter("session"), filter("host"), filter("provider"));
    let built = report::build(state, &report::Filter::new(session.as_deref(), host.as_deref(), provider.as_deref()));
    match (dataset, lower.as_str()) {
        (Some(d), _) => json!({"format": lower.replace('_', "-"), "dataset": report::render_dataset(state, &built, d)}),
        (None, "json") => json!({"format": "json", "report": report::report_value(&built)}),
        (None, "csv") => json!({"format": "csv", "csv": report::render_csv(&built)}),
        _ => json!({"format": "markdown", "brief": report::render_markdown(state, &built)}),
    }
}

/// `JsonNode.asText(null)` of a present, non-null argument.
pub(super) fn as_text(args: &Value, key: &str) -> Option<String> {
    use crate::import::TextOrNull;
    crate::jnode::from_value(args).text_or_null(key)
}

/// `JsonNode.asInt(default)` (a missing, null or non-numeric node gives the default, a numeric string its value).
fn as_int(args: &Value, key: &str, default: i64) -> i64 {
    match args.get(key) {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(default),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(default),
        Some(Value::Bool(b)) => *b as i64,
        _ => default,
    }
}

fn integral(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Number(n)) if n.is_i64() || n.is_u64())
}

fn present(args: &Value, key: &str) -> bool {
    args.get(key).is_some_and(|v| !v.is_null())
}

/// A request definition with `method` and `path` from the arguments (`request().withMethod(…).withPath(…)`).
fn method_path_filter(args: &Value) -> Value {
    let mut f = Map::new();
    if present(args, "method") {
        f.insert("method".into(), json!(as_text(args, "method")));
    }
    if present(args, "path") {
        f.insert("path".into(), json!(as_text(args, "path")));
    }
    Value::Object(f)
}

fn parse(body: &str) -> Value {
    crate::json::parse_lenient(body.as_bytes()).unwrap_or(Value::Null)
}

/// `httpState.add` of expectations: the ids the control plane assigned, or `None` when it rejected them.
async fn add(state: &Arc<State>, expectations: &Value) -> Option<Vec<Value>> {
    let (status, body) = super::internal(state, "PUT", "/mockserver/expectation", &expectations.to_string()).await;
    (status == 201).then(|| parse(&body).as_array().cloned().unwrap_or_default().iter().filter_map(|e| e.get("id").cloned()).collect())
}

fn created(ids: &[Value]) -> Value {
    let mut o = Map::new();
    o.insert("status".into(), json!("created"));
    o.insert("count".into(), json!(ids.len()));
    if let Some(id) = ids.first() {
        o.insert("id".into(), id.clone());
    }
    Value::Object(o)
}

fn created_ids(ids: Vec<Value>) -> Value {
    json!({"status": "created", "count": ids.len(), "ids": ids})
}

async fn list_expectations(state: &Arc<State>, args: &Value) -> Value {
    let (_, body) = super::internal(state, "PUT", "/mockserver/retrieve?type=ACTIVE_EXPECTATIONS&format=JSON", &method_path_filter(args).to_string()).await;
    let expectations = if body.is_empty() { json!([]) } else { parse(&body) };
    let count = expectations.as_array().map_or(0, Vec::len);
    json!({"expectations": expectations, "count": count})
}

/// `handleCreateExpectation`.
async fn create_expectation(state: &Arc<State>, args: &Value) -> Value {
    let schema = CATALOGUE.iter().find(|t| t["name"] == "create_expectation").map(|t| &t["inputSchema"]["properties"]).unwrap_or(&Value::Null);
    let alternative = "To match on request headers, query parameters, cookies or a body, or to add a delay or a template, use raw_expectation with the full expectation JSON.";
    if let Some(unknown) = unknown_parameters("create_expectation", args, schema, Some(alternative)) {
        return unknown;
    }
    if let Some(chaos) = args.get("chaos").filter(|c| !c.is_null()) {
        if !chaos.is_object() {
            return error("'chaos' must be an object, for example {\"errorStatus\": 503, \"errorProbability\": 0.5}");
        }
        if let Some(unknown) = unknown_parameters("create_expectation 'chaos'", chaos, &schema["chaos"]["properties"], None) {
            return unknown;
        }
    }
    for (field, example) in [("method", "\"GET\""), ("path", "\"/users/1\"")] {
        if args.get(field).is_some_and(|v| !v.is_null() && !v.is_string()) {
            return error(&format!("'{field}' must be a string, for example {example}"));
        }
    }
    let Some(method) = as_text(args, "method").filter(|m| !m.trim().is_empty()) else { return error("'method' is required and must not be blank") };
    let Some(path) = as_text(args, "path").filter(|p| !p.trim().is_empty()) else { return error("'path' is required and must not be blank") };
    let mut status = 200;
    if present(args, "statusCode") {
        if !integral(args.get("statusCode")) {
            return error("'statusCode' must be an integer");
        }
        status = as_int(args, "statusCode", 200);
        if !(100..=999).contains(&status) {
            return error("'statusCode' must be between 100 and 999");
        }
    }
    let mut response = Map::new();
    response.insert("statusCode".into(), json!(status));
    match args.get("responseHeaders") {
        None | Some(Value::Null) => {}
        Some(Value::Object(headers)) => {
            let mut h = Map::new();
            for (name, value) in headers {
                let Some(values) = header_values(value) else { return error(&format!("'responseHeaders.{name}' must be a string or an array of strings")) };
                h.insert(name.clone(), json!(values));
            }
            response.insert("headers".into(), Value::Object(h));
        }
        Some(_) => return error("'responseHeaders' must be an object mapping each header name to a string value, for example {\"Content-Type\": \"application/json\"}"),
    }
    match args.get("responseBody") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => {
            response.insert("body".into(), json!(s));
        }
        Some(other) => {
            response.insert("body".into(), json!({"type": "STRING", "string": other.to_string(), "contentType": "application/json"}));
        }
    }
    let mut expectation = Map::new();
    expectation.insert("httpRequest".into(), json!({"method": method, "path": path}));
    expectation.insert("httpResponse".into(), Value::Object(response));
    let times = if present(args, "times") {
        if !integral(args.get("times")) {
            return error("'times' must be an integer");
        }
        let n = as_int(args, "times", 0);
        if n < 0 {
            return error("'times' must be a non-negative integer");
        }
        expectation.insert("times".into(), json!({"remainingTimes": n}));
        Some(n)
    } else {
        None
    };
    match args.get("timeToLive") {
        None | Some(Value::Null) => {}
        Some(Value::String(ttl)) => {
            let parts: Vec<&str> = ttl.trim().splitn(2, char::is_whitespace).collect();
            if parts.len() != 2 {
                return error("'timeToLive' must be in format '<number> <UNIT>' (e.g., '60 SECONDS')");
            }
            let Ok(value) = parts[0].parse::<i64>() else { return error("'timeToLive' value must be a number") };
            if value <= 0 {
                return error("'timeToLive' value must be positive");
            }
            let unit = parts[1].trim().to_uppercase();
            if !["DAYS", "HOURS", "MINUTES", "SECONDS", "MILLISECONDS", "MICROSECONDS", "NANOSECONDS"].contains(&unit.as_str()) {
                return error("'timeToLive' unit must be one of: DAYS, HOURS, MINUTES, SECONDS, MILLISECONDS, MICROSECONDS, NANOSECONDS");
            }
            if times.is_none() {
                expectation.insert("times".into(), json!({"unlimited": true}));
            }
            expectation.insert("timeToLive".into(), json!({"timeUnit": unit, "timeToLive": value, "unlimited": false}));
        }
        Some(_) => return error("'timeToLive' must be a string in format '<number> <UNIT>' (e.g., '60 SECONDS')"),
    }
    if let Some(chaos) = args.get("chaos").filter(|c| c.is_object()) {
        match chaos_from_tool(chaos) {
            Ok(c) => {
                expectation.insert("chaos".into(), c);
            }
            Err(e) => return e,
        }
    }
    match add(state, &Value::Object(expectation)).await {
        Some(ids) => created(&ids),
        None => {
            super::llm_tools::failure(state, "Failed to create expectation")
        }
    }
}

/// `headerValues`: a header's values when `value` is a scalar or a non-empty array of scalars (`asText` each).
fn header_values(value: &Value) -> Option<Vec<String>> {
    let scalar = |v: &Value| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(_) | Value::Bool(_) => Some(v.to_string()),
        _ => None,
    };
    match value {
        Value::Array(items) if !items.is_empty() => items.iter().map(scalar).collect(),
        other => scalar(other).map(|s| vec![s]),
    }
}

/// `PARAMETER_ALIASES`, by normalised name.
const PARAMETER_ALIASES: &[(&str, &str)] = &[
    ("body", "responseBody"),
    ("headers", "responseHeaders"),
    ("status", "statusCode"),
    ("responsestatus", "statusCode"),
    ("responsestatuscode", "statusCode"),
    ("httpmethod", "method"),
    ("ttl", "timeToLive"),
];

/// `normaliseParameterName`
fn normalise_parameter(name: &str) -> String {
    name.to_lowercase().replace(['_', '-'], "")
}

/// `unknownParametersResult`: an error naming each argument `schema` does not declare (keys starting with `_` are
/// metadata and let through), the accepted names and a likely intended name; `None` when all are known.
fn unknown_parameters(scope: &str, args: &Value, schema: &Value, alternative: Option<&str>) -> Option<Value> {
    let accepted: Vec<&str> = schema.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
    let unknown: Vec<&str> = args.as_object()?.keys().map(String::as_str).filter(|n| !accepted.contains(n) && !n.starts_with('_')).collect();
    if unknown.is_empty() {
        return None;
    }
    let mut suggestions = Map::new();
    let mut message = format!("{scope} does not accept: ");
    for (i, name) in unknown.iter().enumerate() {
        message.push_str(&format!("{}'{name}'", if i > 0 { ", " } else { "" }));
        let normalised = normalise_parameter(name);
        let suggestion = accepted.iter().find(|a| normalise_parameter(a) == normalised).copied().or_else(|| {
            PARAMETER_ALIASES.iter().find(|(alias, _)| *alias == normalised).map(|(_, target)| *target).filter(|t| accepted.contains(t))
        });
        if let Some(suggestion) = suggestion {
            suggestions.insert(name.to_string(), json!(suggestion));
            message.push_str(&format!(" (did you mean '{suggestion}'?)"));
        }
    }
    message.push_str(&format!(". It accepts: {}.", accepted.join(", ")));
    if let Some(alternative) = alternative {
        message.push(' ');
        message.push_str(alternative);
    }
    let mut result = error(&message);
    result["unknownParameters"] = json!(unknown);
    result["acceptedParameters"] = json!(accepted);
    if !suggestions.is_empty() {
        result["suggestions"] = Value::Object(suggestions);
    }
    Some(result)
}

/// `create_expectation`'s chaos argument, field by field as the tool reads it.
fn chaos_from_tool(c: &Value) -> Result<Value, Value> {
    let mut o = Map::new();
    let units = ["NANOSECONDS", "MICROSECONDS", "MILLISECONDS", "SECONDS", "MINUTES", "HOURS", "DAYS"];
    let double = |k: &str| match c.get(k) {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0.0),
        _ => 0.0,
    };
    let int = |k: &str| as_int(c, k, 0);
    if present(c, "errorStatus") {
        let s = int("errorStatus");
        if !(100..=599).contains(&s) {
            return Err(error("Failed to create expectation"));
        }
        o.insert("errorStatus".into(), json!(s));
    }
    if present(c, "errorProbability") {
        o.insert("errorProbability".into(), json!(double("errorProbability")));
    }
    if present(c, "retryAfter") {
        o.insert("retryAfter".into(), json!(as_text(c, "retryAfter")));
    }
    if present(c, "dropConnectionProbability") {
        o.insert("dropConnectionProbability".into(), json!(double("dropConnectionProbability")));
    }
    if let Some(latency) = c.get("latency").filter(|l| l.is_object()) {
        let unit = latency.get("timeUnit").and_then(Value::as_str).unwrap_or("MILLISECONDS").to_uppercase();
        if !units.contains(&unit.as_str()) {
            return Err(error("chaos latency timeUnit must be one of: NANOSECONDS, MICROSECONDS, MILLISECONDS, SECONDS, MINUTES, HOURS, DAYS"));
        }
        o.insert("latency".into(), json!({"timeUnit": unit, "value": as_int(latency, "value", 0)}));
    }
    for (k, long) in [("seed", true), ("succeedFirst", false), ("failRequestCount", false), ("outageAfterMillis", true), ("outageDurationMillis", true)] {
        if present(c, k) {
            let _ = long;
            o.insert(k.into(), json!(int(k)));
        }
    }
    if present(c, "truncateBodyAtFraction") {
        o.insert("truncateBodyAtFraction".into(), json!(double("truncateBodyAtFraction")));
    }
    if present(c, "malformedBody") {
        o.insert("malformedBody".into(), json!(matches!(c.get("malformedBody"), Some(Value::Bool(true))) || c.get("malformedBody").and_then(Value::as_str) == Some("true")));
    }
    if present(c, "slowResponseChunkSize") {
        let n = int("slowResponseChunkSize");
        if n < 1 {
            return Err(error("chaos slowResponseChunkSize must be >= 1"));
        }
        o.insert("slowResponseChunkSize".into(), json!(n));
    }
    if let Some(d) = c.get("slowResponseChunkDelay").filter(|d| d.is_object()) {
        let unit = d.get("timeUnit").and_then(Value::as_str).unwrap_or("MILLISECONDS").to_uppercase();
        let value = as_int(d, "value", 0);
        if value < 1 {
            return Err(error("chaos slowResponseChunkDelay value must be >= 1 (a zero delay would not slow the response)"));
        }
        if !units.contains(&unit.as_str()) {
            return Err(error("chaos slowResponseChunkDelay timeUnit must be one of: NANOSECONDS, MICROSECONDS, MILLISECONDS, SECONDS, MINUTES, HOURS, DAYS"));
        }
        o.insert("slowResponseChunkDelay".into(), json!({"timeUnit": unit, "value": value}));
    }
    if let Some(name) = c.get("quotaName").and_then(Value::as_str) {
        o.insert("quotaName".into(), json!(name));
    }
    if present(c, "quotaLimit") {
        let n = int("quotaLimit");
        if n < 1 {
            return Err(error("chaos quotaLimit must be >= 1"));
        }
        o.insert("quotaLimit".into(), json!(n));
    }
    if present(c, "quotaWindowMillis") {
        let n = int("quotaWindowMillis");
        if n < 1 {
            return Err(error("chaos quotaWindowMillis must be >= 1"));
        }
        o.insert("quotaWindowMillis".into(), json!(n));
    }
    if present(c, "quotaErrorStatus") {
        o.insert("quotaErrorStatus".into(), json!(int("quotaErrorStatus")));
    }
    if present(c, "degradationRampMillis") {
        let n = int("degradationRampMillis");
        if n < 1 {
            return Err(error("chaos degradationRampMillis must be >= 1"));
        }
        o.insert("degradationRampMillis".into(), json!(n));
    }
    Ok(Value::Object(o))
}

/// A verification's outcome: `verified`, and the failure text or a pass message.
async fn verification(state: &Arc<State>, path: &str, body: &Value, passed: &str) -> Value {
    let (status, text) = super::internal(state, "PUT", path, &body.to_string()).await;
    if status == 202 { json!({"verified": true, "message": passed}) } else { json!({"verified": false, "message": text}) }
}

async fn verify_request(state: &Arc<State>, args: &Value) -> Value {
    for k in ["atLeast", "atMost"] {
        if present(args, k) && !integral(args.get(k)) {
            return error(&format!("'{k}' must be an integer"));
        }
    }
    let at_least = as_int(args, "atLeast", 1);
    let at_most = as_int(args, "atMost", -1);
    if at_least < 0 {
        return error("'atLeast' must be non-negative");
    }
    if at_most != -1 && at_most < at_least {
        return error("'atMost' must be >= 'atLeast'");
    }
    let times = if at_most == -1 { json!({"atLeast": at_least}) } else { json!({"atLeast": at_least, "atMost": at_most}) };
    verification(state, "/mockserver/verify", &json!({"httpRequest": method_path_filter(args), "times": times}), "Verification passed").await
}

async fn verify_request_sequence(state: &Arc<State>, args: &Value) -> Value {
    let Some(requests) = args.get("requests").and_then(Value::as_array).filter(|r| !r.is_empty()) else { return error("'requests' must be a non-empty array") };
    let mut sequence = Vec::new();
    for r in requests {
        if !r.is_object() {
            return error("Each element of 'requests' must be an object");
        }
        sequence.push(method_path_filter(r));
    }
    verification(state, "/mockserver/verifySequence", &json!({"httpRequests": sequence}), "Request sequence verification passed").await
}

/// The most recent `limit` entries of a retrieve, with the totals.
fn limited(all: Value, key: &str, limit: usize) -> Value {
    let items = all.as_array().cloned().unwrap_or_default();
    let total = items.len();
    let kept: Vec<Value> = items.into_iter().skip(total.saturating_sub(limit)).collect();
    let returned = kept.len();
    let mut o = Map::new();
    o.insert(key.into(), Value::Array(kept));
    o.insert("total".into(), json!(total));
    o.insert("returned".into(), json!(returned));
    Value::Object(o)
}

async fn retrieve_limited(state: &Arc<State>, args: &Value, kind: &str, key: &str, _failure: &str) -> Value {
    let limit = as_int(args, "limit", 50);
    if !(1..=500).contains(&limit) {
        return error("'limit' must be between 1 and 500");
    }
    let (_, body) = super::internal(state, "PUT", &format!("/mockserver/retrieve?type={kind}&format=JSON"), &method_path_filter(args).to_string()).await;
    let all = if body.is_empty() { json!([]) } else { parse(&body) };
    limited(all, key, limit as usize)
}

async fn retrieve_logs(state: &Arc<State>, args: &Value) -> Value {
    let limit = as_int(args, "limit", 100);
    if !(1..=500).contains(&limit) {
        return error("'limit' must be between 1 and 500");
    }
    let mut path = "/mockserver/retrieve?type=LOGS&format=LOG_ENTRIES".to_string();
    if let Some(id) = text(args, "correlationId").filter(|c| !c.is_empty()) {
        path.push_str(&format!("&correlationId={id}"));
    }
    let (_, body) = super::internal(state, "PUT", &path, "").await;
    let all = if body.is_empty() { json!([]) } else { parse(&body) };
    limited(all, "logEntries", limit as usize)
}

async fn clear_expectations(state: &Arc<State>, args: &Value) -> Value {
    let kind = as_text(args, "type").unwrap_or_else(|| "ALL".into());
    if !["ALL", "LOG", "EXPECTATIONS"].contains(&kind.as_str()) {
        return error("'type' must be one of: ALL, LOG, EXPECTATIONS");
    }
    let filter = method_path_filter(args);
    let body = if filter.as_object().is_some_and(|f| !f.is_empty()) { filter.to_string() } else { String::new() };
    super::internal(state, "PUT", &format!("/mockserver/clear?type={kind}"), &body).await;
    json!({"status": "cleared", "type": kind})
}

fn manage_service_chaos(state: &Arc<State>, args: &Value) -> Value {
    use crate::chaos::HostProfile;
    let Some(action) = as_text(args, "action").filter(|a| !a.trim().is_empty()) else { return error("'action' is required and must be one of: register, remove, clear") };
    let registry = &state.chaos.service;
    let host = || as_text(args, "host").filter(|h| !h.trim().is_empty());
    match action.to_lowercase().as_str() {
        "clear" => {
            registry.reset();
            json!({"status": "cleared"})
        }
        "remove" => {
            let Some(host) = host() else { return error("'host' is required for action 'remove'") };
            registry.remove(&host);
            json!({"status": "removed", "host": host})
        }
        "register" => {
            let Some(host) = host() else { return error("'host' is required for action 'register'") };
            let Some(chaos) = args.get("chaos").filter(|c| c.is_object()) else { return error("'chaos' object is required for action 'register'") };
            let profile = match crate::chaos::HttpChaosProfile::from_json(chaos) {
                Ok(p) => p,
                Err(e) => return error(&format!("invalid chaos profile: {}", e.text())),
            };
            let mut ttl = 0;
            if present(args, "ttlMillis") {
                ttl = as_int(args, "ttlMillis", 0);
                if ttl < 1 {
                    return error("'ttlMillis' must be >= 1 when supplied");
                }
            }
            registry.put(&host, profile, ttl);
            let mut o = Map::new();
            o.insert("status".into(), json!("registered"));
            o.insert("host".into(), json!(host));
            if ttl > 0 {
                o.insert("ttlMillis".into(), json!(ttl));
            }
            Value::Object(o)
        }
        _ => error(&format!("unknown action '{action}', must be one of: register, remove, clear")),
    }
}

async fn create_forward_expectation(state: &Arc<State>, args: &Value) -> Value {
    let Some(path) = as_text(args, "path").filter(|p| !p.trim().is_empty()) else { return error("'path' is required and must not be blank") };
    let Some(host) = as_text(args, "host").filter(|h| !h.trim().is_empty()) else { return error("'host' is required and must not be blank") };
    let mut port = 443;
    if present(args, "port") {
        if !integral(args.get("port")) {
            return error("'port' must be an integer");
        }
        port = as_int(args, "port", 443);
        if !(1..=65535).contains(&port) {
            return error("'port' must be between 1 and 65535");
        }
    }
    let scheme = as_text(args, "scheme").unwrap_or_else(|| "HTTPS".into());
    if scheme != "HTTP" && scheme != "HTTPS" {
        return error("'scheme' must be HTTP or HTTPS");
    }
    let expectation = json!({"httpRequest": {"path": path}, "httpForward": {"host": host, "port": port, "scheme": scheme}});
    match add(state, &expectation).await {
        Some(ids) => {
            let mut o = created(&ids).as_object().cloned().unwrap_or_default();
            o.insert("forwardHost".into(), json!(host));
            o.insert("forwardPort".into(), json!(port));
            o.insert("forwardScheme".into(), json!(scheme));
            Value::Object(o)
        }
        None => error("Failed to create forward expectation"),
    }
}

async fn debug_request_mismatch(state: &Arc<State>, args: &Value) -> Value {
    let mut request = Map::new();
    request.insert("method".into(), json!(as_text(args, "method").unwrap_or_default()));
    request.insert("path".into(), json!(as_text(args, "path").unwrap_or_default()));
    if let Some(headers) = args.get("headers").and_then(Value::as_object) {
        request.insert("headers".into(), Value::Object(headers.iter().map(|(k, v)| (k.clone(), json!([v.as_str().map_or_else(|| v.to_string(), str::to_string)]))).collect()));
    }
    match args.get("body") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => {
            request.insert("body".into(), json!(s));
        }
        Some(other) => {
            request.insert("body".into(), json!(other.to_string()));
        }
    }
    let (_, body) = super::internal(state, "PUT", "/mockserver/debugMismatch", &Value::Object(request).to_string()).await;
    let mut result = parse(&body);
    if let Some(Value::Array(results)) = result.get("results").cloned() {
        let mut sorted = results.clone();
        let gap = |r: &Value| r.get("totalFieldCount").and_then(Value::as_i64).unwrap_or(0) - r.get("matchedFieldCount").and_then(Value::as_i64).unwrap_or(0);
        sorted.sort_by_key(gap);
        for r in sorted.iter_mut() {
            let Some(Value::Object(differences)) = r.get("differences").cloned() else { continue };
            let mut hints = Map::new();
            for (field, diffs) in differences {
                let Some(list) = diffs.as_array() else { continue };
                let texts: Vec<String> = list.iter().map(|d| d.as_str().map_or_else(|| d.to_string(), str::to_string)).collect();
                let hint = crate::remediation::hint(&field, &texts);
                if !hint.is_empty() {
                    hints.insert(field, json!(hint));
                }
            }
            if !hints.is_empty() {
                r["remediation"] = Value::Object(hints);
            }
        }
        let first_remediation = sorted.first().and_then(|r| r.get("remediation")).cloned();
        result["results"] = Value::Array(sorted);
        if let (Some(hints), Some(closest)) = (first_remediation, result.get_mut("closestMatch").filter(|c| c.is_object())) {
            closest["remediation"] = hints;
        }
    }
    result
}

async fn create_expectation_from_openapi(state: &Arc<State>, args: &Value) -> Value {
    let mut o = Map::new();
    o.insert("specUrlOrPayload".into(), json!(as_text(args, "specUrlOrPayload").unwrap_or_default()));
    if let Some(ops) = args.get("operationsAndResponses").and_then(Value::as_object) {
        let mut out = Map::new();
        for (k, v) in ops {
            match v {
                Value::String(s) => {
                    out.insert(k.clone(), json!(s));
                }
                Value::Object(rich) => {
                    let mut r = Map::new();
                    if let Some(sc) = rich.get("statusCode") {
                        r.insert("statusCode".into(), json!(sc.as_str().map_or_else(|| sc.to_string(), str::to_string)));
                    }
                    if let Some(name) = rich.get("exampleName") {
                        r.insert("exampleName".into(), json!(name.as_str().map_or_else(|| name.to_string(), str::to_string)));
                    }
                    out.insert(k.clone(), Value::Object(r));
                }
                _ => {}
            }
        }
        o.insert("operationsAndResponses".into(), Value::Object(out));
    }
    if let Some(prefix) = args.get("contextPathPrefix").and_then(Value::as_str) {
        o.insert("contextPathPrefix".into(), json!(prefix));
    }
    let (status, body) = super::internal(state, "PUT", "/mockserver/openapi?includeLoadProblems=true", &Value::Object(o).to_string()).await;
    if status != 201 {
        return super::llm_tools::failure(state, "Failed to create expectations from OpenAPI");
    }
    let body = parse(&body);
    let mut result = created_ids(body["expectations"].as_array().cloned().unwrap_or_default().iter().filter_map(|e| e.get("id").cloned()).collect());
    // 9.1.0: at most `MAX_LOAD_PROBLEMS` (50) of the spec's load problems, `loadProblemsNotShown` counting the rest.
    let problems = body["loadProblems"].as_array().cloned().unwrap_or_default();
    let shown: Vec<Value> = problems
        .iter()
        .take(MAX_LOAD_PROBLEMS)
        .map(|p| {
            let mut p = p.as_object().cloned().unwrap_or_default();
            p.shift_remove("specIndex");
            Value::Object(p)
        })
        .collect();
    result["loadProblems"] = Value::Array(shown);
    if problems.len() > MAX_LOAD_PROBLEMS {
        result["loadProblemsNotShown"] = json!(problems.len() - MAX_LOAD_PROBLEMS);
    }
    result
}

/// `McpToolRegistry.MAX_LOAD_PROBLEMS`: keeps a tool result for a spec with very many problems small.
const MAX_LOAD_PROBLEMS: usize = 50;

async fn create_expectations_from_recorded_traffic(state: &Arc<State>, args: &Value) -> Value {
    let preview = matches!(args.get("preview"), Some(Value::Bool(true)));
    let (_, body) = super::internal(state, "PUT", "/mockserver/retrieve?type=RECORDED_EXPECTATIONS&format=JSON", &method_path_filter(args).to_string()).await;
    let mut recorded = parse(&body).as_array().cloned().unwrap_or_default();
    // The tool serialises through the plain expectation serializer, not the recorded-entry one `retrieve` uses: a
    // STRING body without a content type is a bare string there (the oracle's `"body" : "{\"id\":1}"`), with one it
    // stays the typed form carrying `rawBytes`.
    for expectation in recorded.iter_mut() {
        // Like promote: these mocks serve applications calling MockServer directly, with their own Host.
        crate::transport_headers::strip_expectation(expectation, true);
        for side in ["httpRequest", "httpResponse"] {
            if let Some(body) = expectation.get_mut(side).and_then(|s| s.get_mut("body")) {
                let bare = match body {
                    Value::Object(o) if o.get("type").and_then(Value::as_str) == Some("STRING") && !o.contains_key("contentType") => o.get("string").cloned(),
                    _ => None,
                };
                if let Some(text) = bare {
                    *body = text;
                }
            }
        }
    }
    if recorded.is_empty() {
        return json!({
            "status": "no_recorded_traffic",
            "message": "No recorded traffic found matching the filter. Ensure MockServer has forwarded requests (e.g. via create_forward_expectation) before calling this tool.",
            "count": 0,
        });
    }
    if preview {
        return json!({
            "status": "preview",
            "count": recorded.len(),
            "message": "Preview of expectations that would be created. Call again with preview=false to activate them.",
            "expectations": recorded,
        });
    }
    let persistent: Vec<Value> = recorded.iter().map(|e| json!({"httpRequest": e["httpRequest"], "httpResponse": e["httpResponse"], "priority": 0})).collect();
    match add(state, &Value::Array(persistent)).await {
        Some(ids) => created_ids(ids),
        None => error("Failed to create expectations from recorded traffic"),
    }
}

async fn raw_expectation(state: &Arc<State>, args: &Value) -> Value {
    let expectation = args.get("expectation").cloned().unwrap_or(Value::Null);
    if !expectation.is_object() && !expectation.as_array().is_some_and(|a| !a.is_empty()) {
        return error("'expectation' must be a JSON object in MockServer expectation format, or a non-empty array of them, for example {\"httpRequest\": {\"method\": \"GET\", \"path\": \"/hello\"}, \"httpResponse\": {\"statusCode\": 200, \"body\": \"hi\"}}");
    }
    let errors = expectation_schema_errors(&expectation);
    if !errors.is_empty() {
        let mut result = error("The expectation does not match the MockServer expectation schema: correct each entry of 'validationErrors' (a JSON path, then what is wrong there) and call raw_expectation again");
        result["validationErrors"] = json!(errors);
        return result;
    }
    match add(state, &expectation).await {
        Some(ids) => created_ids(ids),
        None => {
            super::llm_tools::failure(state, "Failed to create raw expectation")
        }
    }
}

/// `expectationSchemaErrors`: the schema report's ` - ` lines for each entry (continuation lines joined on), prefixed
/// with the entry's position when there are several; an OpenAPI expectation is left to the deserializer.
fn expectation_schema_errors(expectation: &Value) -> Vec<String> {
    let entries: Vec<&Value> = match expectation {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    let mut errors: Vec<String> = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let prefix = if entries.len() > 1 { format!("expectation {}: ", i + 1) } else { String::new() };
        if !entry.is_object() {
            errors.push(format!("{prefix}must be an object"));
            continue;
        }
        if entry.get("specUrlOrPayload").is_some() {
            continue;
        }
        let Err(report) = crate::schema::validate_expectation_without_links(entry) else { continue };
        if report.is_empty() {
            continue;
        }
        let before = errors.len();
        for line in report.lines() {
            if let Some(rest) = line.strip_prefix(" - ") {
                errors.push(format!("{prefix}{}", rest.trim()));
            } else if errors.len() > before && !line.trim().is_empty() {
                let last = errors.last_mut().expect("an error before");
                last.push(' ');
                last.push_str(line.trim());
            }
        }
        if errors.len() == before {
            errors.push(format!("{prefix}does not match the expectation schema"));
        }
    }
    errors
}

async fn raw_retrieve(state: &Arc<State>, args: &Value) -> Value {
    let kind = as_text(args, "type").unwrap_or_else(|| "REQUESTS".into());
    if !["REQUESTS", "REQUEST_RESPONSES", "RECORDED_EXPECTATIONS", "ACTIVE_EXPECTATIONS", "LOGS"].contains(&kind.as_str()) {
        return error("'type' must be one of: REQUESTS, REQUEST_RESPONSES, RECORDED_EXPECTATIONS, ACTIVE_EXPECTATIONS, LOGS");
    }
    let format = as_text(args, "format").unwrap_or_else(|| "JSON".into());
    if !["JSON", "JAVA", "LOG_ENTRIES"].contains(&format.as_str()) {
        return error("'format' must be one of: JSON, JAVA, LOG_ENTRIES");
    }
    let definition = args.get("requestDefinition").filter(|d| d.is_object());
    let mut path = format!("/mockserver/retrieve?type={kind}&format={format}");
    if let Some(id) = text(args, "correlationId").filter(|c| !c.is_empty()) {
        path.push_str(&format!("&correlationId={id}"));
    }
    let (_, body) = super::internal(state, "PUT", &path, &definition.map(|d| d.to_string()).unwrap_or_default()).await;
    if body.is_empty() {
        return json!({"data": ""});
    }
    // `objectMapper.readTree(body)` fails on trailing tokens, so LOGS text starting with a date stays a string
    // (the lenient parser would read the year as a number and drop the rest).
    if serde_json::from_str::<Value>(&body).is_err() {
        return json!({"data": body});
    }
    match crate::json::parse_lenient(body.as_bytes()) {
        Ok(v) => json!({"data": v}),
        Err(_) => json!({"data": body}),
    }
}

async fn raw_verify(state: &Arc<State>, args: &Value) -> Value {
    let verification_body = args.get("verification").cloned().unwrap_or(Value::Null);
    let (status, text) = super::internal(state, "PUT", "/mockserver/verify", &verification_body.to_string()).await;
    match status {
        202 => json!({"verified": true, "message": "Verification passed"}),
        406 => json!({"verified": false, "message": text}),
        _ => {
            super::llm_tools::failure(state, "Raw verification failed")
        }
    }
}

/// `Paths.get(path).toAbsolutePath().normalize()`.
pub(super) fn absolute(path: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(path);
    let joined = if p.is_absolute() { p.to_path_buf() } else { std::env::current_dir().unwrap_or_default().join(p) };
    let mut out = std::path::PathBuf::new();
    for c in joined.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// `System.getProperty("java.io.tmpdir")`.
fn temp_dir() -> std::path::PathBuf {
    let t = std::env::temp_dir();
    absolute(&t.to_string_lossy())
}

/// `validateFilePath`: inside the working directory or the temp directory.
pub(super) fn validate_path(path: &std::path::Path) -> Option<Value> {
    let working = absolute(".");
    let temp = temp_dir();
    if path.starts_with(&working) || path.starts_with(&temp) {
        return None;
    }
    Some(error(&format!(
        "Path is outside allowed directories. Files must be inside the working directory ({}) or the system temp directory ({})",
        working.display(),
        temp.display()
    )))
}

const REDACTED: &str = "***REDACTED***";
const UNPARSEABLE_BODY: &str = "<redacted: body could not be parsed for field redaction>";
const SENSITIVE_HEADERS: &[&str] = &["Authorization", "x-api-key", "api-key", "Cookie", "Set-Cookie", "Proxy-Authorization"];
const SENSITIVE_QUERY: &[&str] = &["key", "api_key", "apikey", "access_token", "token", "signature", "x-amz-signature", "x-amz-security-token", "sig"];

fn contains_ci(set: &[impl AsRef<str>], name: &str) -> bool {
    set.iter().any(|s| s.as_ref().eq_ignore_ascii_case(name))
}

/// `FixtureRedactor`: sensitive headers (and query parameters) become `***REDACTED***`; named JSON body fields too.
struct Redactor {
    body_fields: Vec<String>,
}

impl Redactor {
    fn multi_map(&self, v: &mut Value, names: &[&str]) {
        if let Value::Object(map) = v {
            for (k, values) in map.iter_mut() {
                if contains_ci(names, k) {
                    *values = match values {
                        Value::Array(items) => Value::Array(items.iter().map(|_| json!(REDACTED)).collect()),
                        _ => json!(REDACTED),
                    };
                }
            }
        }
    }

    /// The body's text: a bare string, or the value of a typed body's string field.
    fn body_text(body: &Value) -> Option<String> {
        match body {
            Value::String(s) => Some(s.clone()),
            Value::Object(o) => match o.get("type").and_then(Value::as_str) {
                Some("STRING") => o.get("string").and_then(Value::as_str).map(str::to_string),
                Some("JSON") => o.get("json").map(|j| if let Value::String(s) = j { s.clone() } else { j.to_string() }),
                None => Some(body.to_string()),
                _ => None,
            },
            other => Some(other.to_string()),
        }
    }

    fn body(&self, holder: &mut Map<String, Value>) {
        if self.body_fields.is_empty() {
            return;
        }
        let Some(text) = holder.get("body").and_then(Self::body_text).filter(|t| !t.is_empty()) else { return };
        if let Ok(mut node) = serde_json::from_str::<Value>(&text) && (node.is_object() || node.is_array()) {
            self.json(&mut node);
            holder.insert("body".into(), json!(node.to_string()));
            return;
        }
        if text.split('\n').any(|l| l.trim_end_matches('\r').starts_with("data:")) {
            let redacted: Vec<String> = text
                .split('\n')
                .map(|segment| {
                    let cr = segment.ends_with('\r');
                    let line = segment.trim_end_matches('\r');
                    let line = match line.strip_prefix("data:") {
                        Some(after) => {
                            let space = if after.starts_with(' ') { " " } else { "" };
                            format!("data:{space}{}", self.payload(&after[space.len()..]))
                        }
                        None => line.to_string(),
                    };
                    if cr { format!("{line}\r") } else { line }
                })
                .collect();
            holder.insert("body".into(), json!(redacted.join("\n")));
            return;
        }
        if self.mentions(&text) {
            holder.insert("body".into(), json!(UNPARSEABLE_BODY));
        }
    }

    fn payload(&self, payload: &str) -> String {
        if payload.trim().is_empty() {
            return payload.to_string();
        }
        if let Ok(mut node) = serde_json::from_str::<Value>(payload.trim()) && (node.is_object() || node.is_array()) {
            self.json(&mut node);
            return node.to_string();
        }
        if self.mentions(payload) { UNPARSEABLE_BODY.into() } else { payload.to_string() }
    }

    fn mentions(&self, text: &str) -> bool {
        let lower = text.to_lowercase();
        self.body_fields.iter().any(|f| lower.contains(&f.to_lowercase()))
    }

    fn json(&self, node: &mut Value) {
        match node {
            Value::Object(o) => {
                for (k, v) in o.iter_mut() {
                    if contains_ci(&self.body_fields, k) {
                        *v = json!(REDACTED);
                    } else {
                        self.json(v);
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|i| self.json(i)),
            _ => {}
        }
    }

    /// `redactExpectation`: a new expectation (fresh id, unlimited times and TTL) with the redacted parts.
    fn expectation(&self, e: &Value) -> Value {
        let mut out = Map::new();
        if let Some(Value::Object(req)) = e.get("httpRequest") {
            let mut req = req.clone();
            if let Some(h) = req.get_mut("headers") {
                self.multi_map(h, SENSITIVE_HEADERS);
            }
            // `redactCookies`: the parsed cookies too, not only the `Cookie` header.
            if let Some(c) = req.get_mut("cookies") {
                crate::recorded::redact_cookies_json(c);
            }
            if let Some(q) = req.get_mut("queryStringParameters") {
                self.multi_map(q, SENSITIVE_QUERY);
            }
            self.body(&mut req);
            out.insert("httpRequest".into(), Value::Object(req));
        } else if let Some(r) = e.get("httpRequest") {
            out.insert("httpRequest".into(), r.clone());
        }
        for key in ["httpResponse", "httpSseResponse"] {
            if let Some(Value::Object(resp)) = e.get(key) {
                let mut resp = resp.clone();
                if let Some(h) = resp.get_mut("headers") {
                    self.multi_map(h, SENSITIVE_HEADERS);
                }
                if key == "httpResponse" {
                    if let Some(c) = resp.get_mut("cookies") {
                        crate::recorded::redact_cookies_json(c);
                    }
                    self.body(&mut resp);
                }
                out.insert(key.into(), Value::Object(resp));
            }
        }
        for key in ["scenarioName", "scenarioState", "newScenarioState"] {
            if let Some(v) = e.get(key) {
                out.insert(key.into(), v.clone());
            }
        }
        out.insert("priority".into(), e.get("priority").cloned().unwrap_or(json!(0)));
        Value::Object(out)
    }
}

/// `SseAwareExpectationConverter`: a recorded streamed (or `text/event-stream`) response becomes an `httpSseResponse`
/// with one event per block, 50 ms apart unless the recorded chunk delays say otherwise.
fn sse_aware(e: &Value) -> Value {
    let Some(resp) = e.get("httpResponse").and_then(Value::as_object) else { return e.clone() };
    let header = |name: &str| -> Option<String> {
        let (_, v) = resp.get("headers")?.as_object()?.iter().find(|(k, _)| k.eq_ignore_ascii_case(name))?;
        match v {
            Value::Array(items) => items.first().and_then(Value::as_str).map(str::to_string),
            Value::String(s) => Some(s.clone()),
            _ => None,
        }
    };
    let streamed = header("x-mockserver-streamed").is_some_and(|v| v.eq_ignore_ascii_case("true"));
    if !streamed && !header("content-type").is_some_and(|c| c.to_lowercase().contains("text/event-stream")) {
        return e.clone();
    }
    let rebuilt = |response_key: &str, response: Value| {
        let mut out = Map::new();
        out.insert("httpRequest".into(), e.get("httpRequest").cloned().unwrap_or(Value::Null));
        out.insert(response_key.into(), response);
        out.insert("priority".into(), e.get("priority").cloned().unwrap_or(json!(0)));
        Value::Object(out)
    };
    const INTERNAL: &[&str] = &["x-mockserver-streamed", "x-mockserver-stream-truncated", "x-mockserver-chunk-delays-ms"];
    if header("x-mockserver-stream-truncated").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        let mut fallback = resp.clone();
        if let Some(Value::Object(h)) = fallback.get_mut("headers") {
            h.retain(|k, _| !contains_ci(INTERNAL, k));
            h.insert(
                "x-mockserver-fixture-warning".into(),
                json!(["SSE stream was truncated during capture; replay may be incomplete. Increase maxStreamingCaptureBytes for full capture."]),
            );
        }
        return rebuilt("httpResponse", Value::Object(fallback));
    }
    let Some(body) = resp.get("body").and_then(Redactor::body_text).filter(|b| !b.is_empty()) else { return e.clone() };
    let delays: Option<Vec<i64>> = header("x-mockserver-chunk-delays-ms").and_then(|v| v.split(',').map(|p| p.trim().parse::<i64>().ok()).collect());
    let events = parse_sse(&body, delays.as_deref());
    if events.is_empty() {
        return e.clone();
    }
    let mut sse = Map::new();
    sse.insert("statusCode".into(), resp.get("statusCode").cloned().unwrap_or(json!(200)));
    sse.insert("events".into(), Value::Array(events));
    sse.insert("closeConnection".into(), json!(true));
    if let Some(Value::Object(h)) = resp.get("headers") {
        let kept: Map<String, Value> = h
            .iter()
            .filter(|(k, _)| !contains_ci(INTERNAL, k) && !contains_ci(&["content-type", "transfer-encoding", "cache-control", "connection"], k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if !kept.is_empty() {
            sse.insert("headers".into(), Value::Object(kept));
        }
    }
    rebuilt("httpSseResponse", Value::Object(sse))
}

/// `SseBodyParser.parse`.
fn parse_sse(text: &str, delays: Option<&[i64]>) -> Vec<Value> {
    let blocks = regex::Regex::new(r"\r?\n\r?\n").expect("block separator");
    let mut events = Vec::new();
    for block in blocks.split(text) {
        let block = block.trim();
        if block.is_empty() {
            continue;
        }
        let (mut data, mut has_data, mut event, mut id, mut retry): (String, bool, Option<String>, Option<String>, Option<i64>) = (String::new(), false, None, None, None);
        for line in block.split('\n').map(|l| l.trim_end_matches('\r')) {
            if line.starts_with(':') {
                continue;
            }
            let (field, value) = match line.split_once(':') {
                Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
                None => (line, ""),
            };
            match field {
                "data" => {
                    if has_data {
                        data.push('\n');
                    }
                    data.push_str(value);
                    has_data = true;
                }
                "event" => event = Some(value.to_string()),
                "id" => id = Some(value.to_string()),
                "retry" => retry = value.trim().parse().ok().or(retry),
                _ => {}
            }
        }
        if !has_data && event.is_none() && id.is_none() && retry.is_none() {
            continue;
        }
        let mut e = Map::new();
        if has_data {
            e.insert("data".into(), json!(data));
        }
        if let Some(v) = event {
            e.insert("event".into(), json!(v));
        }
        if let Some(v) = id {
            e.insert("id".into(), json!(v));
        }
        if let Some(v) = retry {
            e.insert("retry".into(), json!(v));
        }
        if !events.is_empty() {
            let index = events.len();
            let delay = delays.and_then(|d| d.get(index).copied()).map_or(50, |d| d.max(0));
            if delay > 0 {
                e.insert("delay".into(), json!({"timeUnit": "MILLISECONDS", "value": delay}));
            }
        }
        events.push(Value::Object(e));
    }
    events
}

/// `handleRecordLlmFixtures`.
async fn record_llm_fixtures(state: &Arc<State>, args: &Value) -> Value {
    let Some(path) = text(args, "path").filter(|p| !p.trim().is_empty()) else { return error("'path' is required and must not be blank") };
    let output = absolute(path);
    if let Some(e) = validate_path(&output) {
        return e;
    }
    let parent = output.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    if !parent.exists() {
        return error(&format!("Directory does not exist: {}", parent.display()));
    }
    let mut filter = Map::new();
    if let Some(requested) = text(args, "requestPath") {
        filter.insert("path".into(), json!(requested));
    }
    if let Some(host) = text(args, "host") {
        filter.insert("headers".into(), json!({"Host": [host]}));
    }
    let (_, body) = super::internal(state, "PUT", "/mockserver/retrieve?type=RECORDED_EXPECTATIONS&format=JSON", &Value::Object(filter).to_string()).await;
    let recorded: Vec<Value> = serde_json::from_str::<Value>(&body).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default();
    if recorded.is_empty() {
        return json!({
            "status": "no_recorded_traffic",
            "message": "No recorded traffic found matching the filter. Ensure MockServer has forwarded requests (e.g. via create_forward_expectation or proxy mode) before calling this tool.",
            "count": 0,
        });
    }
    let mut body_fields: Vec<String> = state.config.property("fixtureBodyRedactFields").unwrap_or_default().split(',').map(|f| f.trim().to_string()).filter(|f| !f.is_empty()).collect();
    if let Some(Value::Array(fields)) = args.get("redactBodyFields") {
        body_fields.extend(fields.iter().filter_map(Value::as_str).filter(|f| !f.is_empty()).map(str::to_string));
    }
    let redactor = Redactor { body_fields };
    let written: Vec<Value> = recorded
        .iter()
        .map(|e| {
            let mut out = redactor.expectation(&sse_aware(e));
            if let Some(o) = out.as_object_mut() {
                let id = uuid::Uuid::new_v4().to_string();
                if let Value::Object(canonical) = crate::canonical::expectation(o, &id) {
                    *o = canonical;
                }
            }
            out
        })
        .collect();
    let count = written.len();
    if std::fs::write(&output, crate::json::pretty(&Value::Array(written))).is_err() {
        return super::llm_tools::failure(state, "Failed to record LLM fixtures");
    }
    let file = output.display().to_string();
    state.cassettes.register(&file, None, count as i64, Some("recorded"));
    json!({
        "status": "written",
        "count": count,
        "file": file,
        "message": format!("Wrote {count} expectation(s) to {file}. Secrets have been redacted. Load with load_expectations_from_file or initializationJsonPath for replay."),
    })
}

const MAX_FIXTURE_FILE_SIZE: u64 = 50 * 1024 * 1024;

/// `relaxRequestBodyForReplay`: the volatile fields go, the rest matches as `ONLY_MATCHING_FIELDS` JSON.
fn relax_body(e: &mut Value, drop: &[String]) {
    let Some(req) = e.get_mut("httpRequest").and_then(Value::as_object_mut) else { return };
    let Some(text) = req.get("body").and_then(Redactor::body_text).filter(|t| !t.is_empty()) else { return };
    let Ok(mut node) = serde_json::from_str::<Value>(&text) else { return };
    if !(node.is_object() || node.is_array()) {
        return;
    }
    fn remove(node: &mut Value, drop: &[String]) {
        match node {
            Value::Object(o) => {
                o.retain(|k, _| !contains_ci(drop, k));
                o.values_mut().for_each(|v| remove(v, drop));
            }
            Value::Array(items) => items.iter_mut().for_each(|i| remove(i, drop)),
            _ => {}
        }
    }
    remove(&mut node, drop);
    req.insert("body".into(), json!({"type": "JSON", "json": node.to_string(), "matchType": "ONLY_MATCHING_FIELDS"}));
}

/// `handleLoadExpectationsFromFile`.
async fn load_expectations_from_file(state: &Arc<State>, args: &Value) -> Value {
    let Some(path) = text(args, "path").filter(|p| !p.trim().is_empty()) else { return error("'path' is required and must not be blank") };
    let input = absolute(path);
    if let Some(e) = validate_path(&input) {
        return e;
    }
    let file = input.display().to_string();
    let Ok(meta) = std::fs::metadata(&input) else { return error(&format!("File does not exist: {file}")) };
    if meta.len() > MAX_FIXTURE_FILE_SIZE {
        return error(&format!("File exceeds the maximum allowed size of {} MB: {file}", MAX_FIXTURE_FILE_SIZE / (1024 * 1024)));
    }
    // `Files.isReadable`, then `Files.readAllBytes`: a readable path that cannot be read (a directory) fails the call.
    if std::fs::File::open(&input).is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) {
        return error(&format!("File is not readable: {file}"));
    }
    let Ok(json) = std::fs::read(&input).map(|b| String::from_utf8_lossy(&b).into_owned()) else { return super::llm_tools::failure(state, "Failed to load expectations from file") };
    if json.trim().is_empty() {
        return error(&format!("File is empty: {file}"));
    }
    let mut expectations = match crate::json::parse_lenient(json.as_bytes()) {
        Ok(Value::Array(items)) => items,
        Ok(v @ Value::Object(_)) => vec![v],
        _ => {
            return super::llm_tools::failure(state, "Failed to load expectations from file");
        }
    };
    if expectations.is_empty() {
        return json!({"status": "empty", "message": "File contained no expectations.", "count": 0});
    }
    let normalize: Vec<String> = args.get("normalizeRequestBodyFields").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).filter(|f| !f.is_empty()).map(str::to_string).collect()).unwrap_or_default();
    if !normalize.is_empty() {
        expectations.iter_mut().for_each(|e| relax_body(e, &normalize));
    }
    let (status, created) = super::internal(state, "PUT", "/mockserver/expectation", &Value::Array(expectations.clone()).to_string()).await;
    if status != 201 {
        return super::llm_tools::failure(state, "Failed to load expectations from file");
    }
    let ids: Vec<Value> = serde_json::from_str::<Value>(&created).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default().iter().filter_map(|e| e.get("id").cloned()).collect();
    let strict = match args.get("strict") {
        Some(Value::Bool(b)) => *b,
        _ => state.config.bool_property("llmVcrStrict", false),
    };
    let mut guards = 0;
    if strict {
        let mut paths: Vec<String> = Vec::new();
        for e in &expectations {
            if let Some(p) = e.pointer("/httpRequest/path").and_then(|p| p.as_str().map(str::to_string).or_else(|| p.get("value").and_then(Value::as_str).map(str::to_string))) && !paths.contains(&p) {
                paths.push(p);
            }
        }
        for p in &paths {
            let body = json!({"error": format!("strict VCR: no recorded fixture matched this request on path {p}")}).to_string();
            let guard = json!({"id": format!("__llm_vcr_strict__{p}"), "priority": i32::MIN, "httpRequest": {"path": p}, "httpResponse": {"statusCode": 599, "headers": {"content-type": ["application/json"]}, "body": body}});
            super::internal(state, "PUT", "/mockserver/expectation", &guard.to_string()).await;
            guards += 1;
        }
    }
    state.cassettes.register(&file, None, ids.len() as i64, Some("loaded"));
    let count = ids.len();
    let mut o = Map::new();
    o.insert("status".into(), json!("loaded"));
    o.insert("count".into(), json!(count));
    o.insert("file".into(), json!(file));
    o.insert("strict".into(), json!(strict));
    if guards > 0 {
        o.insert("strictGuards".into(), json!(guards));
    }
    o.insert("ids".into(), Value::Array(ids));
    let suffix = if strict { format!(" Strict VCR mode is on ({guards} catch-all guard(s)).") } else { String::new() };
    o.insert("message".into(), json!(format!("Loaded {count} expectation(s) from {file}. They are now active and will match incoming requests.{suffix}")));
    Value::Object(o)
}

/// `McpToolRegistry.isMutatingTool`: every tool but those that only read (or test a separate target).
pub fn is_mutating(name: &str) -> bool {
    const READING: &[&str] = &[
        "verify_request", "verify_request_sequence", "verify_tool_call", "verify_structured_output", "verify_cost_budget", "verify_traffic_against_openapi",
        "retrieve_recorded_requests", "retrieve_logs", "retrieve_request_responses", "get_status", "debug_request_mismatch", "explain_unmatched_requests",
        "explain_request", "diagnose_config", "explain_forward_failure", "lint_expectations", "suggest_expectation_fix",
        "explain_agent_run", "export_optimisation_report", "diff_agent_runs", "detect_llm_drift", "list_mock_tools", "list_expectations", "raw_retrieve",
        "raw_verify", "run_contract_test", "run_resiliency_test", "run_mcp_contract_test",
    ];
    !READING.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_blocks_become_events() {
        let events = parse_sse("event: a\ndata: {\"x\":1}\n\ndata: two\n\n", None);
        assert_eq!(events, vec![json!({"data": "{\"x\":1}", "event": "a"}), json!({"data": "two", "delay": {"timeUnit": "MILLISECONDS", "value": 50}})]);
    }
}

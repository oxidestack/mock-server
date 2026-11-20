//! `GET /mockserver/llm/optimisationReport`: the captured LLM traffic turned into an optimisation report
//! (`LlmOptimisationReportService`, `LlmOptimisationReportBuilder`, `OptimisationSignals`, `LlmPricing`), rendered
//! as JSON, a Markdown brief (`LlmOptimisationBriefRenderer`), CSV (`LlmOptimisationCsvRenderer`) or an
//! eval / fine-tune dataset (`LlmDatasetExporter`).

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use super::conversation::{self, Message, Role};
use crate::model::number;
use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;
use crate::telemetry;

const REDACTED_HEADERS: &[&str] = &["api-key", "Authorization", "Cookie", "Proxy-Authorization", "Set-Cookie", "x-api-key"];
const RESPONSE_TIME_HEADER: &str = "x-mockserver-response-time-ms";
const RETRY_WINDOW: usize = 3;

// ---------------------------------------------------------------------------------------------------------------
// Java number formatting
// ---------------------------------------------------------------------------------------------------------------

/// `BigDecimal.valueOf(v).setScale(places, HALF_UP)` as plain text; `String.format("%.nf")` rounds the same way.
fn fixed(v: f64, places: usize) -> String {
    let text = java_compat::double_to_string(v);
    let (negative, text) = match text.strip_prefix('-') {
        Some(rest) => (true, rest.to_string()),
        None => (false, text),
    };
    let (mantissa, exponent) = match text.split_once('E') {
        Some((m, e)) => (m.to_string(), e.parse::<i32>().unwrap_or(0)),
        None => (text.clone(), 0),
    };
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((&mantissa, ""));
    let digits: Vec<u8> = format!("{int_part}{frac_part}").bytes().map(|b| b - b'0').collect();
    let point = int_part.len() as i32 + exponent;
    // Digits of the value scaled by 10^places, plus the first discarded digit.
    let digit = |i: i32| -> u8 { if i >= 0 && (i as usize) < digits.len() { digits[i as usize] } else { 0 } };
    let keep = point + places as i32;
    let mut kept: Vec<u8> = (0..keep.max(0)).map(digit).collect();
    if digit(keep) >= 5 {
        let mut i = kept.len();
        loop {
            if i == 0 {
                kept.insert(0, 1);
                break;
            }
            i -= 1;
            if kept[i] == 9 {
                kept[i] = 0;
            } else {
                kept[i] += 1;
                break;
            }
        }
    }
    while kept.len() < places + 1 {
        kept.insert(0, 0);
    }
    let split = kept.len() - places;
    let int_digits: String = kept[..split].iter().map(|d| (b'0' + d) as char).collect();
    let int_digits = int_digits.trim_start_matches('0');
    let int_digits = if int_digits.is_empty() { "0" } else { int_digits };
    let frac: String = kept[split..].iter().map(|d| (b'0' + d) as char).collect();
    let sign = if negative { "-" } else { "" };
    if places == 0 { format!("{sign}{int_digits}") } else { format!("{sign}{int_digits}.{frac}") }
}

/// `LlmOptimisationReportBuilder.round4`.
fn round4(v: f64) -> f64 {
    fixed(v, 4).parse().unwrap_or(0.0)
}

/// `Math.round(double)`.
fn java_round(v: f64) -> i64 {
    (v + 0.5).floor() as i64
}

/// `String.format(Locale.ROOT, "%,d", n)`.
fn grouped(n: i64) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 { format!("-{out}") } else { out }
}

fn percent(fraction: f64) -> String {
    format!("{}%", java_round(fraction * 100.0))
}

fn usd4(v: f64) -> String {
    format!("${}", fixed(v, 4))
}

fn double(v: f64) -> Value {
    number(&java_compat::double_to_string(v))
}

/// `String.length()`: UTF-16 code units.
fn java_len(s: &str) -> i64 {
    s.encode_utf16().count() as i64
}

/// `charsToTokens`: 4 characters a token, rounded up.
fn chars_to_tokens(chars: i64) -> i64 {
    if chars <= 0 { 0 } else { (chars as f64 / 4.0).ceil() as i64 }
}

fn estimate_tokens(text: &str) -> i64 {
    chars_to_tokens(java_len(text))
}

/// `sha256Hex`: the first `hex_chars` hex digits.
fn sha256_hex(input: &str, hex_chars: usize) -> String {
    let hash = ring::digest::digest(&ring::digest::SHA256, input.as_bytes());
    hash.as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>()[..hex_chars].to_string()
}

// ---------------------------------------------------------------------------------------------------------------
// LlmPricing
// ---------------------------------------------------------------------------------------------------------------

/// Model prefix, input and output USD per million tokens, and whether the rate is approximate.
type Price = (&'static str, f64, f64, bool);

const ANTHROPIC_PRICING: &[Price] = &[
    ("claude-fable-5", 10.0, 50.0, false),
    ("claude-opus-4-8", 5.0, 25.0, false),
    ("claude-opus-4-7", 5.0, 25.0, false),
    ("claude-opus-4-6", 5.0, 25.0, false),
    ("claude-opus-4-5", 5.0, 25.0, false),
    ("claude-sonnet-4-6", 3.0, 15.0, false),
    ("claude-sonnet-4-5", 3.0, 15.0, false),
    ("claude-haiku-4-5", 1.0, 5.0, false),
    ("claude-opus-4", 15.0, 75.0, false),
    ("claude-sonnet-4", 3.0, 15.0, false),
    ("claude-haiku-4", 0.8, 4.0, false),
];
const OPENAI_PRICING: &[Price] = &[
    ("gpt-4o-mini", 0.15, 0.6, false),
    ("gpt-4o", 2.5, 10.0, false),
    ("gpt-4.1-mini", 0.4, 1.6, false),
    ("gpt-4.1-nano", 0.1, 0.4, false),
    ("gpt-4.1", 2.0, 8.0, false),
    ("o4-mini", 1.1, 4.4, false),
    ("o3-mini", 1.1, 4.4, false),
    ("o3", 15.0, 60.0, false),
    ("gpt-5-mini", 0.15, 0.6, true),
    ("gpt-5-nano", 0.15, 0.6, true),
    ("gpt-5", 2.5, 10.0, true),
];
const GEMINI_PRICING: &[Price] = &[
    ("gemini-2.5-flash-lite", 0.1, 0.4, false),
    ("gemini-2.5-flash", 0.3, 2.5, false),
    ("gemini-2.5-pro", 1.25, 10.0, false),
    ("gemini-2.0-flash-lite", 0.075, 0.3, false),
    ("gemini-2.0-flash", 0.1, 0.4, false),
];
const MISTRAL_PRICING: &[Price] = &[
    ("mistral-large", 2.0, 6.0, true),
    ("mistral-medium", 0.4, 2.0, true),
    ("mistral-small", 0.1, 0.3, true),
    ("codestral", 0.3, 0.9, true),
    ("ministral-8b", 0.1, 0.1, true),
    ("ministral-3b", 0.04, 0.04, true),
    ("open-mistral-nemo", 0.15, 0.15, true),
];
const XAI_PRICING: &[Price] = &[
    ("grok-4", 3.0, 15.0, true),
    ("grok-3-mini", 0.3, 0.5, true),
    ("grok-3", 3.0, 15.0, true),
    ("grok-2", 2.0, 10.0, true),
    ("grok-beta", 5.0, 15.0, true),
];
const DEEPSEEK_PRICING: &[Price] = &[("deepseek-reasoner", 0.55, 2.19, true), ("deepseek-chat", 0.27, 1.1, true)];
const GROQ_PRICING: &[Price] = &[
    ("llama-3.3-70b", 0.59, 0.79, true),
    ("llama-3.1-8b", 0.05, 0.08, true),
    ("llama-3.1-70b", 0.59, 0.79, true),
    ("llama-3.1-405b", 1.79, 1.79, true),
    ("mixtral-8x7b", 0.24, 0.24, true),
    ("gemma2-9b", 0.2, 0.2, true),
];

/// `VERTEX_GEMINI_PRICING`: Vertex AI's own list prices for the Gemini families the Gemini table prices (only
/// gemini-2.0-flash differs), for `google/` ids on the OpenAI-compatible endpoint and native Gemini calls to a Vertex
/// AI host.
const VERTEX_GEMINI_PRICING: &[Price] = &[
    ("gemini-2.5-flash-lite", 0.1, 0.4, false),
    ("gemini-2.5-flash", 0.3, 2.5, false),
    ("gemini-2.5-pro", 1.25, 10.0, false),
    ("gemini-2.0-flash-lite", 0.075, 0.3, false),
    ("gemini-2.0-flash", 0.15, 0.6, false),
];
/// `VERTEX_LLAMA_PRICING`: keyed with `-maas`, so another gateway's `meta/llama-…` is not billed at the managed rate.
const VERTEX_LLAMA_PRICING: &[Price] = &[("llama-3.3-70b-instruct-maas", 0.72, 0.72, false)];

/// `findPricing`: the first prefix of the lower-cased id; an embedding model is never priced from a chat table.
fn find_price(table: &[Price], model: &str) -> Option<Price> {
    let lower = model.to_lowercase();
    if embedding_model(&lower) {
        return None;
    }
    table.iter().find(|(prefix, ..)| lower.starts_with(&prefix.to_lowercase())).copied()
}

/// `isEmbeddingModel`: a name segment (split on `[^a-z0-9]+`) starts with `embed` (codestral-embed,
/// text-embedding-3-small).
fn embedding_model(lower: &str) -> bool {
    lower.split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit())).any(|segment| segment.starts_with("embed"))
}

/// `vendorPrefix`: the lower-cased vendor of a `<vendor>/<model>` id, `None` for a bare id or an empty part.
fn vendor_prefix(model: &str) -> Option<String> {
    let slash = model.find('/').filter(|&s| s > 0 && s < model.len() - 1)?;
    Some(model[..slash].to_lowercase())
}

/// `afterVendor`.
fn after_vendor(model: &str) -> &str {
    &model[model.find('/').map_or(0, |s| s + 1)..]
}

/// `vertexPublisherTable`.
fn vertex_publisher_table(publisher: &str) -> Option<&'static [Price]> {
    match publisher {
        "google" => Some(VERTEX_GEMINI_PRICING),
        "meta" => Some(VERTEX_LLAMA_PRICING),
        _ => None,
    }
}

/// `LlmPricing.getPricing`.
fn pricing(provider: &str, model: Option<&str>) -> Option<Price> {
    if provider == "OLLAMA" {
        return Some(("", 0.0, 0.0, false));
    }
    let model = model?;
    match provider {
        "ANTHROPIC" => find_price(ANTHROPIC_PRICING, model),
        "BEDROCK" => find_price(ANTHROPIC_PRICING, model.strip_prefix("anthropic.").unwrap_or(model)),
        // no OpenAI model id has a `<publisher>/` prefix; Vertex AI's OpenAI-compatible endpoint does
        "OPENAI" | "OPENAI_RESPONSES" => match vendor_prefix(model) {
            Some(publisher) => find_price(vertex_publisher_table(&publisher)?, after_vendor(model)),
            None => find_price(OPENAI_PRICING, model),
        },
        "AZURE_OPENAI" => find_price(OPENAI_PRICING, model),
        "GEMINI" => find_price(GEMINI_PRICING, model),
        "MISTRAL" => find_price(MISTRAL_PRICING, model),
        "XAI" => find_price(XAI_PRICING, model),
        "DEEPSEEK" => find_price(DEEPSEEK_PRICING, model),
        "GROQ" => find_price(GROQ_PRICING, model),
        "OPENROUTER" | "ORCAROUTER" => {
            let table = match vendor_prefix(model)?.as_str() {
                "openai" => OPENAI_PRICING,
                "anthropic" => ANTHROPIC_PRICING,
                "google" => GEMINI_PRICING,
                "mistralai" | "mistral" => MISTRAL_PRICING,
                "x-ai" | "xai" => XAI_PRICING,
                "deepseek" => DEEPSEEK_PRICING,
                _ => return None,
            };
            find_price(table, after_vendor(model))
        }
        _ => None,
    }
}

/// `getPricing`, or `getVertexAiPricing` for a call sent to a Vertex AI host: a native Gemini call is billed at
/// Vertex AI's Gemini rates.
fn pricing_at(provider: &str, model: Option<&str>, vertex_ai: bool) -> Option<Price> {
    if vertex_ai && provider == "GEMINI" {
        return find_price(VERTEX_GEMINI_PRICING, model?);
    }
    pricing(provider, model)
}

/// `LlmPricing.estimateCostUsd`, or `estimateVertexAiCostUsd` for a call sent to a Vertex AI host.
pub(crate) fn estimate_cost(provider: &str, model: Option<&str>, input: i64, output: i64) -> Option<f64> {
    estimate_cost_at(provider, model, input, output, false)
}

/// [`estimate_cost`], or `estimateVertexAiCostUsd` when the call went to a Vertex AI host.
pub(crate) fn estimate_cost_at(provider: &str, model: Option<&str>, input: i64, output: i64, vertex_ai: bool) -> Option<f64> {
    let (_, input_rate, output_rate, _) = pricing_at(provider, model, vertex_ai)?;
    if input == 0 && output == 0 {
        return Some(0.0);
    }
    Some((input as f64 / 1_000_000.0) * input_rate + (output as f64 / 1_000_000.0) * output_rate)
}

/// `LlmPricing.cheapestModel(provider)`'s table.
fn table_for(provider: &str) -> Option<&'static [Price]> {
    Some(match provider {
        "ANTHROPIC" | "BEDROCK" => ANTHROPIC_PRICING,
        "OPENAI" | "OPENAI_RESPONSES" => OPENAI_PRICING,
        "GEMINI" => GEMINI_PRICING,
        "MISTRAL" => MISTRAL_PRICING,
        "XAI" => XAI_PRICING,
        "DEEPSEEK" => DEEPSEEK_PRICING,
        "GROQ" => GROQ_PRICING,
        _ => return None,
    })
}

/// `cheapestModel(provider, model)` / `cheapestVertexAiModel`: the cheapest model the call could move to without
/// changing vendor — a `<publisher>/<model>` id within that publisher's Vertex AI table, a native Gemini call on a
/// Vertex AI host within Vertex AI's Gemini models.
fn cheapest_model(provider: &str, model: &str, vertex_ai: bool) -> Option<(&'static str, f64)> {
    let table = if vertex_ai && provider == "GEMINI" {
        Some(VERTEX_GEMINI_PRICING)
    } else if matches!(provider, "OPENAI" | "OPENAI_RESPONSES") && vendor_prefix(model).is_some() {
        vendor_prefix(model).and_then(|p| vertex_publisher_table(&p))
    } else {
        table_for(provider)
    };
    cheapest_in(table?)
}

/// `cheapestIn`: the first model with the lowest blended rate.
fn cheapest_in(table: &'static [Price]) -> Option<(&'static str, f64)> {
    let mut best: Option<(&'static str, f64)> = None;
    for (prefix, input, output, _) in table {
        let blended = input + output;
        if best.is_none_or(|(_, b)| blended < b) {
            best = Some((prefix, blended));
        }
    }
    best
}

fn blended(provider: &str, model: &str, vertex_ai: bool) -> Option<f64> {
    pricing_at(provider, Some(model), vertex_ai).map(|(_, i, o, _)| i + o)
}

// ---------------------------------------------------------------------------------------------------------------
// LlmProviderSniffer.detectForAnalysis
// ---------------------------------------------------------------------------------------------------------------

static GEMINI_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        "/v1beta/models/[^/]+:(generateContent|streamGenerateContent)|/v1/models/gemini-[^/]+:(generateContent|streamGenerateContent)|/publishers/google/models/[^/]+:(generateContent|streamGenerateContent)",
    )
    .unwrap()
});
static OLLAMA_CHAT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(^|/)api/chat(/?$|\?)").unwrap());
static RESPONSES_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/v1/responses|(^|/)(codex|openai)/responses(?:[/?]|$)").unwrap());
static BEDROCK_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new("/model/[^/]+/(invoke|invoke-with-response-stream|converse|converse-stream)").unwrap());
static COHERE_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/v[12]/rerank|/v1/chat(/?$|\?)").unwrap());
static INPUT_ARRAY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""input"\s*:\s*\["#).unwrap());
static MESSAGES_ARRAY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""messages"\s*:\s*\["#).unwrap());

/// `LlmProviderSniffer.extractHost` / `LlmOptimisationReportService.upstreamHost`: the socket address, else `Host`.
pub(crate) fn upstream_host(request: &HttpRequest) -> Option<String> {
    if let Some((host, ..)) = request.socket_address.as_ref().filter(|(h, ..)| !h.is_empty()) {
        return Some(telemetry::strip_port(host).to_string());
    }
    request.first_header("Host").filter(|h| !h.is_empty()).map(|h| telemetry::strip_port(h).to_string())
}

/// `sniffByPath`.
fn sniff_by_path(path: &str) -> Option<&'static str> {
    let lower = path.to_lowercase();
    if lower.contains("/v1/messages") {
        Some("ANTHROPIC")
    } else if lower.contains("/openai/deployments/") && lower.contains("/chat/completions") {
        Some("AZURE_OPENAI")
    } else if BEDROCK_PATH.is_match(&lower) {
        Some("BEDROCK")
    } else if RESPONSES_PATH.is_match(&lower) {
        Some("OPENAI_RESPONSES")
    } else if lower.contains("/chat/completions") {
        Some("OPENAI")
    } else if GEMINI_PATH.is_match(path) {
        Some("GEMINI")
    } else if COHERE_PATH.is_match(&lower) {
        Some("COHERE")
    } else if OLLAMA_CHAT.is_match(path) {
        Some("OLLAMA")
    } else {
        None
    }
}

/// `sniffByBodyShape`.
fn sniff_by_body_shape(request: &HttpRequest, response_body: &str) -> Option<&'static str> {
    let res = response_body;
    if !res.is_empty() {
        if res.contains("\"chat.completion") {
            return Some("OPENAI");
        }
        if res.contains("response.output_text")
            || res.contains("response.created")
            || res.contains("response.completed")
            || res.contains("\"object\":\"response\"")
            || res.contains("\"object\": \"response\"")
        {
            return Some("OPENAI_RESPONSES");
        }
        if res.contains("content_block") || res.contains("message_start") || (res.contains("\"type\":\"message\"") && res.contains("stop_reason")) {
            return Some("ANTHROPIC");
        }
        if res.contains("\"candidates\"") && res.contains("usageMetadata") {
            return Some("GEMINI");
        }
        if res.contains("relevance_score") && res.contains("\"results\"") {
            return Some("COHERE");
        }
    }
    if request.first_header("anthropic-version").is_some_and(|v| !v.is_empty()) {
        return Some("ANTHROPIC");
    }
    let req = request.body_str();
    if req.is_empty() {
        return None;
    }
    let has_model = req.contains("\"model\"");
    let messages_array = MESSAGES_ARRAY.is_match(&req);
    let input_array = INPUT_ARRAY.is_match(&req);
    let responses_distinctive = req.contains("\"instructions\"") || req.contains("\"previous_response_id\"");
    if has_model && !messages_array && (input_array || responses_distinctive) {
        return Some("OPENAI_RESPONSES");
    }
    if req.contains("\"contents\"") && (req.contains("\"parts\"") || req.contains("generationConfig")) {
        return Some("GEMINI");
    }
    if has_model && messages_array {
        return Some("OPENAI");
    }
    if req.contains("\"query\"") && req.contains("\"documents\"") {
        return Some("COHERE");
    }
    None
}

/// `detectForAnalysis`: well-known host, then path shape, then body shape.
pub(crate) fn detect(state: &State, request: &HttpRequest, response_body: &str) -> Option<String> {
    telemetry::sniff(state, upstream_host(request).as_deref(), &request.path)
        .or_else(|| sniff_by_path(&request.path).map(str::to_string))
        .or_else(|| sniff_by_body_shape(request, response_body).map(str::to_string))
}

// ---------------------------------------------------------------------------------------------------------------
// Captured traffic
// ---------------------------------------------------------------------------------------------------------------

/// `CapturedExchange`, with the provider it was detected as.
pub struct Captured {
    pub request: HttpRequest,
    pub response_body: String,
    /// The logged response's headers, read by the Bedrock client's token-count fallback.
    pub response_headers: Value,
    pub latency_ms: Option<i64>,
    pub provider: String,
}

/// A logged response's body as `HttpResponse.getBodyAsString` reads it.
pub(crate) fn logged_body(response: &Value) -> String {
    logged_body_text(response.get("body"))
}

/// A logged response body as `HttpResponse.getBodyAsString` reads it.
fn logged_body_text(body: Option<&Value>) -> String {
    use base64::Engine;
    match body {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(o)) => match o.get("type").and_then(Value::as_str) {
            Some("STRING") => o.get("string").and_then(Value::as_str).unwrap_or_default().to_string(),
            Some("JSON") => match o.get("json") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => String::new(),
            },
            Some("XML") => o.get("xml").and_then(Value::as_str).unwrap_or_default().to_string(),
            Some("BINARY") => o
                .get("base64Bytes")
                .and_then(Value::as_str)
                .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default(),
            _ => Value::Object(o.clone()).to_string(),
        },
        Some(other) => other.to_string(),
    }
}

/// `LlmClient.parseCompletionResponse` of a logged response, with its headers (a Bedrock body without token counts
/// is counted from the `X-Amzn-Bedrock-*-Token-Count` headers recorded with it).
pub(crate) fn logged_completion(provider: &str, response: &Value) -> Option<telemetry::Completion> {
    telemetry::parse_completion_response(provider, logged_body(response).as_bytes(), &|name| logged_header(response, name))
}

/// A logged response header's first value, from either header form.
fn logged_header(response: &Value, name: &str) -> Option<String> {
    first_header(response.get("headers"), name)
}

/// `HttpResponse.getFirstHeader` over logged headers in either form.
fn first_header(headers: Option<&Value>, name: &str) -> Option<String> {
    match headers? {
        Value::Object(o) => o.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).and_then(|(_, v)| match v {
            Value::Array(items) => items.first().and_then(Value::as_str).map(str::to_string),
            Value::String(s) => Some(s.clone()),
            _ => None,
        }),
        Value::Array(items) => items
            .iter()
            .find(|h| h.get("name").and_then(Value::as_str).is_some_and(|n| n.eq_ignore_ascii_case(name)))
            .and_then(|h| h.get("values").and_then(|v| v.get(0)).and_then(Value::as_str).map(str::to_string)),
        _ => None,
    }
}

/// `LlmOptimisationReportService.Filter`.
#[derive(Default)]
pub struct Filter {
    pub session: Option<String>,
    pub host: Option<String>,
    pub provider: Option<String>,
}

impl Filter {
    pub fn new(session: Option<&str>, host: Option<&str>, provider: Option<&str>) -> Filter {
        let clean = |s: Option<&str>| s.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        Filter { session: clean(session), host: clean(host), provider: clean(provider) }
    }
}

fn body_fields(state: &State) -> Vec<String> {
    state.config.property("fixtureBodyRedactFields").unwrap_or_default().split(',').map(|f| f.trim().to_string()).filter(|f| !f.is_empty()).collect()
}

/// `LlmOptimisationReportService.build`: the LLM exchanges the filter selects (the latest `llmOptimisationMaxCalls`)
/// and their report.
pub struct Built {
    pub report: Report,
    pub exchanges: Vec<Captured>,
}

pub fn build(state: &State, filter: &Filter) -> Built {
    let mut exchanges = Vec::new();
    let mut grouping_key: Option<String> = None;
    for x in state.log.matching(None).into_iter().filter(|x| x.response.is_object()) {
        let response_body = logged_body_text(x.response.get("body"));
        let Some(provider) = detect(state, &x.request, &response_body) else { continue };
        let host = upstream_host(&x.request);
        if let Some(wanted) = &filter.host && !host.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(wanted)) {
            continue;
        }
        if filter.provider.as_ref().is_some_and(|p| !provider.eq_ignore_ascii_case(p)) {
            continue;
        }
        let key = format!("host:{}", host.as_deref().unwrap_or("unknown"));
        if let Some(session) = &filter.session && !session.eq_ignore_ascii_case(&key) && !host.as_deref().is_some_and(|h| telemetry::strip_port(session).eq_ignore_ascii_case(h)) {
            continue;
        }
        grouping_key.get_or_insert(key);
        let latency_ms = logged_header(&x.response, RESPONSE_TIME_HEADER).and_then(|h| h.trim().parse::<i64>().ok());
        let response_headers = x.response.get("headers").cloned().unwrap_or(Value::Null);
        exchanges.push(Captured { request: x.request.clone(), response_body, response_headers, latency_ms, provider });
    }
    let max_calls = state.config.property("llmOptimisationMaxCalls").and_then(|v| v.trim().parse::<i64>().ok()).unwrap_or(200);
    if max_calls > 0 && exchanges.len() as i64 > max_calls {
        exchanges.drain(..exchanges.len() - max_calls as usize);
    }
    let key = grouping_key.or_else(|| filter.session.clone()).unwrap_or_else(|| "all".into());
    let report = build_report(&exchanges, key, body_fields(state));
    state.config.metrics.llm_optimisation((report.verdict.total_saving, report.totals.cache_hit_ratio, report.totals.one_shot_rate));
    Built { report, exchanges }
}

// ---------------------------------------------------------------------------------------------------------------
// LlmOptimisationReport
// ---------------------------------------------------------------------------------------------------------------

pub struct Report {
    session_key: String,
    providers: Vec<String>,
    models: Vec<String>,
    redacted_body_fields: Vec<String>,
    totals: Totals,
    calls: Vec<Call>,
    signals: Vec<Signal>,
    verdict: Verdict,
}

#[derive(Default)]
struct Totals {
    call_count: usize,
    input_tokens: i64,
    output_tokens: i64,
    cached_input_tokens: i64,
    reasoning_tokens: i64,
    estimated_cost: f64,
    cost_is_estimated: bool,
    cost_unknown: bool,
    total_latency_ms: i64,
    tool_call_count: usize,
    cache_hit_ratio: f64,
    one_shot_rate: f64,
    retry_call_count: usize,
}

#[derive(Default)]
struct Call {
    index: usize,
    path: String,
    provider: String,
    model: Option<String>,
    input_tokens: i64,
    output_tokens: i64,
    cached_input_tokens: i64,
    reasoning_tokens: i64,
    estimated_cost: f64,
    cost_is_estimated: bool,
    cost_unknown: bool,
    approximate_rate: bool,
    /// `isVertexAi`: sent to a Vertex AI host, so priced at Vertex AI's rates (not serialised).
    vertex_ai: bool,
    latency_ms: i64,
    finish_reason: Option<String>,
    message_count: usize,
    system_prompt_tokens: i64,
    system_prompt_fingerprint: Option<String>,
    tool_calls: Vec<ToolCall>,
    defined_tool_names: Vec<String>,
    defined_tool_tokens: i64,
}

struct ToolCall {
    name: String,
    args_fingerprint: Option<String>,
    result_tokens: i64,
}

struct Signal {
    id: &'static str,
    severity: &'static str,
    title: String,
    detail: String,
    affected: Vec<usize>,
    wasted: Option<i64>,
    saving: Option<f64>,
    recommendation: String,
    urgency: f64,
    fix: Option<Fix>,
}

#[derive(Default)]
struct Fix {
    summary: String,
    action: String,
    config_snippet: Option<&'static str>,
    example_expectation: Option<&'static str>,
    docs_url: String,
}

struct Verdict {
    grade: &'static str,
    rationale: String,
    total_saving: f64,
    total_wasted: i64,
    saving_fraction: f64,
    cost_is_estimated: bool,
    high: usize,
    medium: usize,
    low: usize,
}

impl Default for Verdict {
    fn default() -> Verdict {
        Verdict {
            grade: "A",
            rationale: "No optimisation opportunities detected.".into(),
            total_saving: 0.0,
            total_wasted: 0,
            saving_fraction: 0.0,
            cost_is_estimated: false,
            high: 0,
            medium: 0,
            low: 0,
        }
    }
}

impl Report {
    /// `getTotals()`: input tokens, output tokens and the estimated cost.
    pub fn token_totals(&self) -> (i64, i64, f64) {
        (self.totals.input_tokens, self.totals.output_tokens, self.totals.estimated_cost)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// LlmOptimisationReportBuilder
// ---------------------------------------------------------------------------------------------------------------

fn build_report(exchanges: &[Captured], session_key: String, redacted_body_fields: Vec<String>) -> Report {
    let mut report = Report {
        session_key,
        providers: Vec::new(),
        models: Vec::new(),
        redacted_body_fields,
        totals: Totals { one_shot_rate: 1.0, ..Totals::default() },
        calls: Vec::new(),
        signals: Vec::new(),
        verdict: Verdict::default(),
    };
    if exchanges.is_empty() {
        return report;
    }
    for exchange in exchanges {
        let call = build_call(report.calls.len(), exchange);
        if !report.providers.contains(&call.provider) {
            report.providers.push(call.provider.clone());
        }
        if let Some(model) = call.model.as_ref().filter(|m| !report.models.contains(m)) {
            report.models.push(model.clone());
        }
        report.calls.push(call);
    }
    aggregate_totals(&mut report);
    report.signals = detect_signals(&report.calls, &report.providers, report.totals.cached_input_tokens);
    report.verdict = verdict(&report);
    report
}

fn system_prompt_text(messages: &[Message]) -> Option<String> {
    let parts: Vec<&str> = messages.iter().filter(|m| m.role == Role::System).map(|m| m.text.as_str()).collect();
    let joined = parts.join("\n");
    (!joined.is_empty()).then_some(joined)
}

fn build_call(index: usize, exchange: &Captured) -> Call {
    let request = &exchange.request;
    let provider = exchange.provider.as_str();
    // `modelFromRequest`: the body's model, else the path's (a native Gemini call names its model only there)
    let model = telemetry::model_from(&request.body).or_else(|| telemetry::gemini_model_from_path(&request.path));
    let messages = conversation::decode(provider, request);
    let vertex_ai = upstream_host(request).is_some_and(|h| telemetry::vertex_host(&h.to_lowercase()));
    let mut call = Call { index, path: request.path.clone(), provider: provider.to_string(), message_count: messages.len(), vertex_ai, ..Call::default() };
    if let Some(text) = system_prompt_text(&messages) {
        call.system_prompt_fingerprint = Some(sha256_hex(&text, 8));
        call.system_prompt_tokens = estimate_tokens(&text);
    }
    call.tool_calls = tool_calls(&messages);
    defined_tools(&mut call, request);

    let completion = telemetry::parse_completion_response(provider, exchange.response_body.as_bytes(), &|name| first_header(Some(&exchange.response_headers), name));
    let reported = completion.as_ref().filter(|c| c.input_tokens.is_some() || c.output_tokens.is_some());
    let estimated = match reported {
        Some(c) => {
            call.input_tokens = c.input_tokens.unwrap_or(0);
            call.output_tokens = c.output_tokens.unwrap_or(0);
            call.cached_input_tokens = c.cached_input_tokens.unwrap_or(0);
            call.reasoning_tokens = c.reasoning_tokens.unwrap_or(0);
            false
        }
        None => {
            call.input_tokens = estimate_input_tokens(&messages);
            call.output_tokens = completion.as_ref().and_then(|c| c.text.as_deref()).map_or(0, estimate_tokens);
            true
        }
    };
    let cost = estimate_cost_at(provider, model.as_deref(), call.input_tokens, call.output_tokens, call.vertex_ai);
    call.cost_unknown = cost.is_none();
    call.estimated_cost = cost.map_or(0.0, round4);
    call.approximate_rate = cost.is_some() && pricing_at(provider, model.as_deref(), call.vertex_ai).is_some_and(|p| p.3);
    call.cost_is_estimated = estimated || call.approximate_rate;
    call.model = model;
    call.finish_reason = completion.and_then(|c| c.stop_reason);
    if let Some(latency) = exchange.latency_ms.filter(|l| *l >= 0) {
        call.latency_ms = latency;
    }
    call
}

fn tool_calls(messages: &[Message]) -> Vec<ToolCall> {
    let mut result_tokens: Vec<(&str, i64)> = Vec::new();
    for m in messages.iter().filter(|m| m.role == Role::Tool) {
        for (id, content) in &m.tool_results {
            result_tokens.retain(|(k, _)| k != id);
            result_tokens.push((id, estimate_tokens(content)));
        }
    }
    messages
        .iter()
        .filter(|m| m.role == Role::Assistant)
        .flat_map(|m| &m.tool_calls)
        .map(|tc| ToolCall {
            name: tc.name.clone(),
            args_fingerprint: Some(sha256_hex(&tc.arguments, 4)),
            result_tokens: tc.id.as_deref().and_then(|id| result_tokens.iter().find(|(k, _)| *k == id)).map_or(0, |(_, t)| *t),
        })
        .collect()
}

fn defined_tools(call: &mut Call, request: &HttpRequest) {
    let Ok(body) = serde_json::from_slice::<Value>(&request.body) else { return };
    let Some(tools) = body.get("tools").and_then(Value::as_array).filter(|t| !t.is_empty()) else { return };
    call.defined_tool_names = tools
        .iter()
        .filter_map(|tool| tool.pointer("/function/name").and_then(Value::as_str).or_else(|| tool.get("name").and_then(Value::as_str)))
        .map(str::to_string)
        .collect();
    let serialised = crate::model::jackson_tree(&Value::Array(tools.clone())).to_string();
    call.defined_tool_tokens = chars_to_tokens(java_len(&serialised));
}

fn estimate_input_tokens(messages: &[Message]) -> i64 {
    let chars: i64 = messages
        .iter()
        .map(|m| {
            java_len(&m.text) + m.tool_calls.iter().map(|tc| java_len(&tc.arguments)).sum::<i64>() + m.tool_results.iter().map(|(_, r)| java_len(r)).sum::<i64>()
        })
        .sum();
    chars_to_tokens(chars)
}

/// `OptimisationSignals.sameish`.
fn sameish(a: &Call, b: &Call) -> bool {
    a.path == b.path && a.model == b.model && a.message_count == b.message_count && a.system_prompt_fingerprint == b.system_prompt_fingerprint && a.input_tokens == b.input_tokens
}

fn aggregate_totals(report: &mut Report) {
    let calls = &report.calls;
    let t = &mut report.totals;
    let mut cost = 0.0;
    for c in calls {
        t.input_tokens += c.input_tokens;
        t.output_tokens += c.output_tokens;
        t.cached_input_tokens += c.cached_input_tokens;
        t.reasoning_tokens += c.reasoning_tokens;
        t.total_latency_ms += c.latency_ms;
        cost += c.estimated_cost;
        t.tool_call_count += c.tool_calls.len();
        t.cost_is_estimated |= c.cost_is_estimated;
        t.cost_unknown |= c.cost_unknown;
    }
    t.call_count = calls.len();
    t.retry_call_count = (1..calls.len()).filter(|&i| (i.saturating_sub(RETRY_WINDOW)..i).any(|j| sameish(&calls[j], &calls[i]))).count();
    t.estimated_cost = round4(cost);
    t.cache_hit_ratio = if t.input_tokens > 0 { round4(t.cached_input_tokens as f64 / t.input_tokens as f64) } else { 0.0 };
    t.one_shot_rate = if t.call_count > 0 { round4(1.0 - t.retry_call_count as f64 / t.call_count as f64) } else { 1.0 };
}

fn verdict(report: &Report) -> Verdict {
    let totals = &report.totals;
    let calls = &report.calls;
    let signals = &report.signals;
    let mut v = Verdict { cost_is_estimated: totals.cost_is_estimated, ..Verdict::default() };
    for s in signals {
        match s.severity {
            "HIGH" => v.high += 1,
            "MEDIUM" => v.medium += 1,
            _ => v.low += 1,
        }
    }
    let n = calls.len();
    if n == 0 {
        return v;
    }
    let mut call_saving = vec![0.0f64; n];
    let mut call_wasted = vec![0i64; n];
    for s in signals {
        let k = s.affected.len();
        if k == 0 {
            continue;
        }
        let per_save = s.saving.unwrap_or(0.0) / k as f64;
        let per_waste = s.wasted.unwrap_or(0) / k as i64;
        for &ci in s.affected.iter().filter(|&&ci| ci < n) {
            call_saving[ci] = call_saving[ci].max(per_save);
            call_wasted[ci] = call_wasted[ci].max(per_waste);
        }
    }
    let mut total_saving = 0.0;
    let mut total_wasted = 0i64;
    for i in 0..n {
        total_saving += call_saving[i].min(calls[i].estimated_cost);
        total_wasted += call_wasted[i].min(calls[i].input_tokens);
    }
    let total_saving = round4(total_saving.min(totals.estimated_cost));
    let fraction = if totals.estimated_cost > 0.0 {
        total_saving / totals.estimated_cost
    } else if totals.input_tokens > 0 {
        total_wasted as f64 / totals.input_tokens as f64
    } else {
        0.0
    };
    let clamped = fraction.clamp(0.0, 1.0);
    v.total_saving = total_saving;
    v.total_wasted = total_wasted;
    v.saving_fraction = round4(clamped);
    let score = 100.0 * (1.0 - clamped);
    let mut letter = match score {
        s if s >= 90.0 => "A",
        s if s >= 75.0 => "B",
        s if s >= 60.0 => "C",
        s if s >= 45.0 => "D",
        _ => "F",
    };
    if v.high > 0 && letter == "A" {
        letter = "B";
    }
    v.grade = letter;
    v.rationale = rationale(letter, signals.len(), clamped, total_saving, v.high, v.medium, v.low);
    v
}

fn rationale(letter: &str, findings: usize, fraction: f64, saving: f64, high: usize, medium: usize, low: usize) -> String {
    if findings == 0 {
        return "No optimisation opportunities detected.".into();
    }
    let pct = java_round(fraction * 100.0);
    let breakdown: Vec<String> =
        [(high, "high"), (medium, "medium"), (low, "low")].iter().filter(|(n, _)| *n > 0).map(|(n, label)| format!("{n} {label}")).collect();
    let breakdown = breakdown.join(", ");
    let word = if findings == 1 { "finding" } else { "findings" };
    let dollars = format!("${}", fixed(saving, 2));
    if letter == "A" {
        format!("Grade A — well optimised; {findings} low-impact {word} noted ({breakdown}), estimated saving {dollars} ({pct}% of spend).")
    } else {
        format!("Grade {letter} — an estimated {pct}% of spend ({dollars}) is recoverable across {findings} {word} ({breakdown}).")
    }
}

// ---------------------------------------------------------------------------------------------------------------
// OptimisationSignals
// ---------------------------------------------------------------------------------------------------------------

const LARGE_CONTEXT_TOKEN_THRESHOLD: i64 = 2_000;
const OVERSIZED_TOOL_RESULT_TOKEN_THRESHOLD: i64 = 1_000;
const OUTPUT_BLOAT_ABSOLUTE_THRESHOLD: i64 = 1_500;
const OUTPUT_BLOAT_MEDIAN_MULTIPLE: f64 = 3.0;
const CACHE_HIT_TARGET: f64 = 0.5;
const CACHE_DISCOUNT: f64 = 0.9;
const TRIVIAL_OUTPUT_TOKENS: i64 = 256;
const MODEL_OVERSPEND_MIN_SAVING_FRACTION: f64 = 0.30;
const UNUSED_TOOL_MEDIUM_TOKEN_THRESHOLD: i64 = 1_000;
const DOCS_BASE: &str = "https://www.mock-server.com/mock_server/ai_optimisation.html";

fn signal(id: &'static str, severity: &'static str, title: String, detail: String, affected: Vec<usize>, recommendation: &str) -> Signal {
    Signal { id, severity, title, detail, affected, wasted: None, saving: None, recommendation: recommendation.into(), urgency: 0.0, fix: None }
}

fn detect_signals(calls: &[Call], providers: &[String], cached_input_tokens: i64) -> Vec<Signal> {
    let mut signals: Vec<Signal> = [
        repeated_system_prompt(calls),
        large_static_context(calls),
        deterministic_tool_call(calls),
        oversized_tool_result(calls),
        output_token_bloat(calls),
        duplicate_consecutive_call(calls),
        low_cache_hit_rate(calls, providers, cached_input_tokens),
        model_overspend(calls),
        unused_tool_schema(calls),
    ]
    .into_iter()
    .flatten()
    .collect();
    for s in &mut signals {
        let weight = match s.severity {
            "HIGH" => 1.0,
            "MEDIUM" => 0.6,
            _ => 0.3,
        };
        let share = (s.affected.len() as f64 / calls.len() as f64).min(1.0);
        s.urgency = round4(weight * share);
        if s.fix.is_none() {
            s.fix = fix_for(s, providers);
        }
    }
    let rank = |s: &str| match s {
        "HIGH" => 0,
        "MEDIUM" => 1,
        _ => 2,
    };
    signals.sort_by(|a, b| b.urgency.total_cmp(&a.urgency).then(rank(a.severity).cmp(&rank(b.severity))));
    signals
}

/// System prompt fingerprints in first-seen order, with the calls sending each and its (last seen) token count.
fn by_fingerprint(calls: &[Call], min_tokens: i64) -> Vec<(String, Vec<usize>, i64)> {
    let mut groups: Vec<(String, Vec<usize>, i64)> = Vec::new();
    for c in calls {
        let Some(fp) = c.system_prompt_fingerprint.as_ref().filter(|_| c.system_prompt_tokens >= min_tokens) else { continue };
        match groups.iter_mut().find(|(f, ..)| f == fp) {
            Some(group) => {
                group.1.push(c.index);
                group.2 = c.system_prompt_tokens;
            }
            None => groups.push((fp.clone(), vec![c.index], c.system_prompt_tokens)),
        }
    }
    groups
}

fn repeated_system_prompt(calls: &[Call]) -> Option<Signal> {
    let groups = by_fingerprint(calls, i64::MIN);
    let wasted = |g: &(String, Vec<usize>, i64)| g.2 * (g.1.len() as i64 - 1);
    let mut worst: Option<&(String, Vec<usize>, i64)> = None;
    for g in groups.iter().filter(|g| g.1.len() >= 2) {
        if worst.is_none_or(|w| wasted(g) > wasted(w)) {
            worst = Some(g);
        }
    }
    let (fp, affected, tokens) = worst?;
    let repeats = affected.len();
    let waste = tokens * (repeats as i64 - 1);
    let mut s = signal(
        "REPEATED_SYSTEM_PROMPT",
        if repeats >= 3 && *tokens >= 1_000 { "HIGH" } else { "MEDIUM" },
        format!("Identical {}-token system prompt resent on all {repeats} calls", grouped(*tokens)),
        format!("The same system prompt (fingerprint {fp}) was sent on {repeats}/{} calls, re-paying for the same input tokens each turn.", calls.len()),
        affected.clone(),
        "Enable provider prompt caching, or move the static context into a retrieval tool so it is not resent every turn.",
    );
    s.wasted = Some(waste);
    s.saving = saving_for_wasted_input(calls, affected, waste);
    Some(s)
}

fn large_static_context(calls: &[Call]) -> Option<Signal> {
    let groups = by_fingerprint(calls, LARGE_CONTEXT_TOKEN_THRESHOLD);
    let (fp, affected, tokens) = groups.iter().find(|g| g.1.len() >= 2)?;
    let waste = tokens * (affected.len() as i64 - 1);
    let mut s = signal(
        "LARGE_STATIC_CONTEXT_RESENT",
        "HIGH",
        format!("Large {}-token static context resent across {} calls", grouped(*tokens), affected.len()),
        format!(
            "A {}-token context block (fingerprint {fp}) was resent on {} calls instead of being cached or retrieved on demand.",
            grouped(*tokens),
            affected.len()
        ),
        affected.clone(),
        "Move the large static context into a retrieval tool or enable prompt caching so it is sent once, not every turn.",
    );
    s.wasted = Some(waste);
    s.saving = saving_for_wasted_input(calls, affected, waste);
    Some(s)
}

fn dedupe_sorted(values: &[usize]) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::new();
    for v in values {
        if !out.contains(v) {
            out.push(*v);
        }
    }
    out.sort_unstable();
    out
}

fn deterministic_tool_call(calls: &[Call]) -> Option<Signal> {
    let mut groups: Vec<(String, String, Vec<usize>)> = Vec::new();
    for c in calls {
        for tc in &c.tool_calls {
            let Some(fp) = &tc.args_fingerprint else { continue };
            let key = format!("{}|{fp}", tc.name);
            match groups.iter_mut().find(|(k, ..)| *k == key) {
                Some(g) => g.2.push(c.index),
                None => groups.push((key, tc.name.clone(), vec![c.index])),
            }
        }
    }
    let (_, name, indexes) = groups.iter().find(|g| g.2.len() >= 2)?;
    let affected = dedupe_sorted(indexes);
    Some(signal(
        "DETERMINISTIC_TOOL_CALL",
        "MEDIUM",
        format!("Tool '{name}' called with identical arguments {} times", indexes.len()),
        format!(
            "The tool '{name}' was invoked with the same arguments across {} calls, so its result is deterministic and the round-trip through the model is avoidable.",
            affected.len()
        ),
        affected,
        "Replace this LLM-mediated step with a direct HTTP or MCP endpoint call and feed the result back deterministically.",
    ))
}

fn oversized_tool_result(calls: &[Call]) -> Option<Signal> {
    let mut affected = Vec::new();
    let mut max_result = 0;
    let mut worst: Option<&str> = None;
    for c in calls {
        for tc in c.tool_calls.iter().filter(|tc| tc.result_tokens >= OVERSIZED_TOOL_RESULT_TOKEN_THRESHOLD) {
            if !affected.contains(&c.index) {
                affected.push(c.index);
            }
            if tc.result_tokens > max_result {
                max_result = tc.result_tokens;
                worst = Some(&tc.name);
            }
        }
    }
    if affected.is_empty() {
        return None;
    }
    let from = worst.map(|w| format!(" from '{w}'")).unwrap_or_default();
    Some(signal(
        "OVERSIZED_TOOL_RESULT",
        "MEDIUM",
        format!("Oversized tool result ({} tokens{from}) inflating downstream input", grouped(max_result)),
        format!("A tool returned {} tokens, which are re-sent as input on every subsequent turn, inflating cost.", grouped(max_result)),
        affected,
        "Trim or summarise the tool output before returning it to the model so only the relevant fields are sent.",
    ))
}

fn median(values: &[i64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    if n % 2 == 1 { sorted[n / 2] as f64 } else { (sorted[n / 2 - 1] + sorted[n / 2]) as f64 / 2.0 }
}

fn output_token_bloat(calls: &[Call]) -> Option<Signal> {
    let outputs: Vec<i64> = calls.iter().map(|c| c.output_tokens).collect();
    let median = median(&outputs);
    let mut affected = Vec::new();
    let mut max_output = 0;
    for c in calls {
        let out = c.output_tokens;
        if out >= OUTPUT_BLOAT_ABSOLUTE_THRESHOLD || (median > 0.0 && out as f64 >= median * OUTPUT_BLOAT_MEDIAN_MULTIPLE) {
            affected.push(c.index);
            max_output = max_output.max(out);
        }
    }
    if affected.is_empty() {
        return None;
    }
    Some(signal(
        "OUTPUT_TOKEN_BLOAT",
        "LOW",
        format!("Output token bloat: up to {} output tokens on a single call", grouped(max_output)),
        format!(
            "One or more calls produced far more output than the median ({} tokens), which is expensive and often unnecessary.",
            grouped(median as i64)
        ),
        affected,
        "Constrain output with max_tokens or a stricter response_format/JSON schema so the model returns only what is needed.",
    ))
}

fn duplicate_consecutive_call(calls: &[Call]) -> Option<Signal> {
    let mut affected: Vec<usize> = Vec::new();
    let mut wasted = 0;
    for pair in calls.windows(2) {
        if sameish(&pair[0], &pair[1]) {
            for i in [pair[0].index, pair[1].index] {
                if !affected.contains(&i) {
                    affected.push(i);
                }
            }
            wasted += pair[1].input_tokens;
        }
    }
    if affected.is_empty() {
        return None;
    }
    let mut s = signal(
        "DUPLICATE_CONSECUTIVE_CALL",
        "MEDIUM",
        "Duplicate consecutive calls detected (likely retries)".into(),
        "Consecutive calls with near-identical request shape were observed, suggesting retries that re-pay for the same work.".into(),
        affected,
        "De-duplicate or cache identical requests, and only retry on genuine transient errors with backoff.",
    );
    s.wasted = (wasted > 0).then_some(wasted);
    Some(s)
}

fn low_cache_hit_rate(calls: &[Call], providers: &[String], cached_input_tokens: i64) -> Option<Signal> {
    let total_input: i64 = calls.iter().map(|c| c.input_tokens).sum();
    let ratio = if total_input > 0 { cached_input_tokens as f64 / total_input as f64 } else { 0.0 };
    if ratio >= CACHE_HIT_TARGET {
        return None;
    }
    let mut cacheable = 0;
    let mut affected: Vec<usize> = Vec::new();
    let mut repeated = false;
    for (_, indexes, tokens) in by_fingerprint(calls, i64::MIN).iter().filter(|g| g.1.len() >= 2) {
        repeated = true;
        cacheable += tokens * (indexes.len() as i64 - 1);
        affected.extend(indexes);
    }
    if !repeated {
        return None;
    }
    let affected = dedupe_sorted(&affected);
    let not_cached = (cacheable - cached_input_tokens).max(0);
    if not_cached <= 0 {
        return None;
    }
    let saving = saving_for_wasted_input(calls, &affected, not_cached).map(|s| round4(s * CACHE_DISCOUNT));
    let high = not_cached >= LARGE_CONTEXT_TOKEN_THRESHOLD && ratio < 0.2;
    let mut s = signal(
        "LOW_CACHE_HIT_RATE",
        if high { "HIGH" } else { "MEDIUM" },
        format!("Low cache hit rate ({}) on a repeated {}-token cacheable prefix", percent(ratio), grouped(not_cached)),
        format!(
            "A cacheable prompt prefix is resent across calls but only {} of input tokens were served from cache; {} repeated tokens are not yet cached.",
            percent(ratio),
            grouped(not_cached)
        ),
        affected,
        "Enable prompt caching for the repeated static prefix so it is billed once, not on every call.",
    );
    s.wasted = Some(not_cached);
    s.saving = saving;
    s.fix = Some(cache_fix(providers));
    Some(s)
}

fn model_overspend(calls: &[Call]) -> Option<Signal> {
    // Per model, in first-seen order: its calls, their cost, the saving fraction and the cheapest alternative.
    let mut candidates: Vec<(String, Vec<usize>, f64, f64, &'static str)> = Vec::new();
    for c in calls {
        if !(c.output_tokens < TRIVIAL_OUTPUT_TOKENS && c.tool_calls.is_empty() && c.reasoning_tokens == 0) {
            continue;
        }
        let Some(model) = &c.model else { continue };
        let (Some(current), Some((cheapest, cheapest_blended))) = (blended(&c.provider, model, c.vertex_ai), cheapest_model(&c.provider, model, c.vertex_ai)) else { continue };
        if current <= cheapest_blended {
            continue;
        }
        let fraction = (1.0 - cheapest_blended / current).clamp(0.0, 1.0);
        match candidates.iter_mut().find(|(m, ..)| m == model) {
            Some(entry) => {
                entry.1.push(c.index);
                entry.2 += c.estimated_cost;
                entry.3 = fraction;
                entry.4 = cheapest;
            }
            None => candidates.push((model.clone(), vec![c.index], c.estimated_cost, fraction, cheapest)),
        }
    }
    let mut best: Option<&(String, Vec<usize>, f64, f64, &'static str)> = None;
    for entry in &candidates {
        match best {
            None => best = Some(entry),
            Some(b) if entry.1.len() > b.1.len() || (entry.1.len() == b.1.len() && entry.2 > b.2) => best = Some(entry),
            _ => {}
        }
    }
    let (model, indexes, cost, fraction, cheapest) = best?;
    let affected = dedupe_sorted(indexes);
    if affected.len() < 2 || *fraction <= MODEL_OVERSPEND_MIN_SAVING_FRACTION {
        return None;
    }
    let pct = java_round(fraction * 100.0);
    let recommendation = format!(
        "These {} calls on `{model}` produced <256-token outputs with no tools or reasoning — a smaller model such as `{cheapest}` would likely suffice at ~{pct}% lower cost.",
        affected.len()
    );
    let mut s = signal(
        "MODEL_OVERSPEND",
        "LOW",
        format!("Over-powered model on {} trivial calls (`{model}` → `{cheapest}`)", affected.len()),
        recommendation.clone(),
        affected,
        &recommendation,
    );
    s.saving = Some(round4(cost * fraction));
    Some(s)
}

fn unused_tool_schema(calls: &[Call]) -> Option<Signal> {
    let invoked: Vec<&str> = calls.iter().flat_map(|c| c.tool_calls.iter().map(|tc| tc.name.as_str())).collect();
    let mut unused: Vec<&str> = Vec::new();
    for name in calls.iter().flat_map(|c| c.defined_tool_names.iter().map(String::as_str)) {
        if !invoked.contains(&name) && !unused.contains(&name) {
            unused.push(name);
        }
    }
    if unused.is_empty() {
        return None;
    }
    let mut affected = Vec::new();
    let mut total_wasted = 0;
    for c in calls {
        if c.defined_tool_names.is_empty() || c.defined_tool_tokens <= 0 {
            continue;
        }
        let unused_here = c.defined_tool_names.iter().filter(|n| unused.contains(&n.as_str())).count();
        if unused_here == 0 {
            continue;
        }
        affected.push(c.index);
        total_wasted += java_round(c.defined_tool_tokens as f64 * unused_here as f64 / c.defined_tool_names.len() as f64);
    }
    if affected.len() < 2 {
        return None;
    }
    let affected = dedupe_sorted(&affected);
    let saving = saving_for_wasted_input(calls, &affected, total_wasted);
    let shown = unused[..unused.len().min(5)].join(", ");
    let recommendation = format!(
        "Tools [{shown}] are defined on every request but never called — remove them from `tools` to stop re-sending ~{} tokens of unused schema each call.",
        grouped(total_wasted)
    );
    let mut s = signal(
        "UNUSED_TOOL_SCHEMA",
        if total_wasted >= UNUSED_TOOL_MEDIUM_TOKEN_THRESHOLD { "MEDIUM" } else { "LOW" },
        format!("Unused tool schema re-sent on {} calls ({} wasted tokens)", affected.len(), grouped(total_wasted)),
        format!("Tool definitions [{shown}] are sent on every request but never invoked, so their schema is paid for as input on each call."),
        affected,
        &recommendation,
    );
    s.wasted = (total_wasted > 0).then_some(total_wasted);
    s.saving = saving;
    Some(s)
}

fn saving_for_wasted_input(calls: &[Call], affected: &[usize], wasted: i64) -> Option<f64> {
    if wasted <= 0 {
        return None;
    }
    let (mut input, mut cost) = (0i64, 0.0f64);
    for c in calls.iter().filter(|c| affected.contains(&c.index)) {
        input += c.input_tokens;
        cost += c.estimated_cost;
    }
    if input <= 0 || cost <= 0.0 {
        return None;
    }
    Some(round4(cost * (wasted as f64 / input as f64).min(1.0)))
}

fn fix(summary: &str, action: &str, anchor: &str) -> Fix {
    Fix { summary: summary.into(), action: action.into(), docs_url: format!("{DOCS_BASE}#{anchor}"), ..Fix::default() }
}

fn fix_for(s: &Signal, providers: &[String]) -> Option<Fix> {
    Some(match s.id {
        "REPEATED_SYSTEM_PROMPT" => cache_fix(providers),
        "LARGE_STATIC_CONTEXT_RESENT" => fix(
            "Cache or retrieve static context",
            "Move the large static context into a retrieval tool, or enable prompt caching so it is sent once, not on every turn.",
            "repeated-context",
        ),
        "DETERMINISTIC_TOOL_CALL" => Fix {
            example_expectation: Some("{\n  \"httpRequest\": { \"path\": \"/tool/lookup\" },\n  \"httpResponse\": { \"body\": { \"result\": \"...\" } }\n}"),
            ..fix(
                "Replace tool with direct call",
                "Call the deterministic endpoint directly (HTTP or MCP) and feed the result back, instead of routing it through the model each time.",
                "deterministic-tools",
            )
        },
        "OVERSIZED_TOOL_RESULT" => fix(
            "Trim tool output",
            "Summarise or project the tool result to the fields the model actually needs before returning it, so it is not re-sent in full on every turn.",
            "oversized-tool-results",
        ),
        "OUTPUT_TOKEN_BLOAT" => Fix {
            config_snippet: Some("{\n  \"max_tokens\": 512,\n  \"response_format\": { \"type\": \"json_object\" }\n}"),
            ..fix("Constrain output length", "Set max_tokens and a strict response_format / JSON schema so the model returns only what is required.", "output-bloat")
        },
        "DUPLICATE_CONSECUTIVE_CALL" => {
            fix("De-duplicate and back off retries", "Cache identical requests and only retry on genuine transient errors with exponential backoff.", "duplicate-calls")
        }
        "MODEL_OVERSPEND" => fix("Use a smaller model", &s.recommendation, "model-overspend"),
        "UNUSED_TOOL_SCHEMA" => fix("Remove unused tools", &s.recommendation, "unused-tools"),
        _ => return None,
    })
}

fn cache_fix(providers: &[String]) -> Fix {
    if providers.iter().any(|p| p == "ANTHROPIC") {
        return Fix {
            config_snippet: Some(
                "{\n  \"system\": [\n    {\n      \"type\": \"text\",\n      \"text\": \"<static system prompt>\",\n      \"cache_control\": { \"type\": \"ephemeral\" }\n    }\n  ]\n}",
            ),
            ..fix(
                "Enable prompt caching",
                "Add `cache_control:{type:ephemeral}` to the static system block so Anthropic serves the repeated prefix from cache.",
                "prompt-caching",
            )
        };
    }
    fix(
        "Enable prompt caching",
        "Automatic prefix caching — keep the static prefix byte-identical and first; do not interleave volatile content before it.",
        "prompt-caching",
    )
}

// ---------------------------------------------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------------------------------------------

/// A bean as MockServer's `ObjectMapper` writes it: properties alphabetical, nulls and empty strings/lists left out.
fn bean(fields: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (k, v) in fields {
        let empty = match &v {
            Value::Null => true,
            Value::String(s) => s.is_empty(),
            Value::Array(a) => a.is_empty(),
            _ => false,
        };
        if !empty {
            map.insert(k.to_string(), v);
        }
    }
    map.sort_keys();
    Value::Object(map)
}

fn opt_str(v: &Option<String>) -> Value {
    v.as_ref().map_or(Value::Null, |s| json!(s))
}

fn report_json(r: &Report) -> Value {
    let t = &r.totals;
    let v = &r.verdict;
    bean(vec![
        ("schemaVersion", json!(1)),
        ("generatedBy", json!("mockserver")),
        (
            "session",
            bean(vec![("key", json!(r.session_key)), ("groupingBasis", json!("PROXY_HOST")), ("providers", json!(r.providers)), ("models", json!(r.models))]),
        ),
        (
            "totals",
            bean(vec![
                ("callCount", json!(t.call_count)),
                ("inputTokens", json!(t.input_tokens)),
                ("outputTokens", json!(t.output_tokens)),
                ("cachedInputTokens", json!(t.cached_input_tokens)),
                ("reasoningTokens", json!(t.reasoning_tokens)),
                ("estimatedCostUsd", double(t.estimated_cost)),
                ("costIsEstimated", json!(t.cost_is_estimated)),
                ("costUnknown", json!(t.cost_unknown)),
                ("totalLatencyMs", json!(t.total_latency_ms)),
                ("toolCallCount", json!(t.tool_call_count)),
                ("cacheHitRatio", double(t.cache_hit_ratio)),
                ("oneShotRate", double(t.one_shot_rate)),
                ("retryCallCount", json!(t.retry_call_count)),
            ]),
        ),
        ("calls", Value::Array(r.calls.iter().map(call_json).collect())),
        ("signals", Value::Array(r.signals.iter().map(signal_json).collect())),
        (
            "redaction",
            bean(vec![("applied", json!(true)), ("redactedHeaders", json!(REDACTED_HEADERS)), ("redactedBodyFields", json!(r.redacted_body_fields))]),
        ),
        (
            "verdict",
            bean(vec![
                ("grade", json!(v.grade)),
                ("rationale", json!(v.rationale)),
                ("totalEstimatedSavingUsd", double(v.total_saving)),
                ("totalWastedInputTokens", json!(v.total_wasted)),
                ("savingFractionOfSpend", double(v.saving_fraction)),
                ("costIsEstimated", json!(v.cost_is_estimated)),
                ("highCount", json!(v.high)),
                ("mediumCount", json!(v.medium)),
                ("lowCount", json!(v.low)),
            ]),
        ),
    ])
}

fn call_json(c: &Call) -> Value {
    bean(vec![
        ("index", json!(c.index)),
        ("path", json!(c.path)),
        ("provider", json!(c.provider)),
        ("model", opt_str(&c.model)),
        ("inputTokens", json!(c.input_tokens)),
        ("outputTokens", json!(c.output_tokens)),
        ("cachedInputTokens", json!(c.cached_input_tokens)),
        ("reasoningTokens", json!(c.reasoning_tokens)),
        ("estimatedCostUsd", double(c.estimated_cost)),
        ("costIsEstimated", json!(c.cost_is_estimated)),
        ("costUnknown", json!(c.cost_unknown)),
        ("approximateRate", json!(c.approximate_rate)),
        ("latencyMs", json!(c.latency_ms)),
        ("finishReason", opt_str(&c.finish_reason)),
        ("messageCount", json!(c.message_count)),
        ("systemPromptTokens", json!(c.system_prompt_tokens)),
        ("systemPromptFingerprint", opt_str(&c.system_prompt_fingerprint)),
        (
            "toolCalls",
            Value::Array(
                c.tool_calls
                    .iter()
                    .map(|tc| bean(vec![("name", json!(tc.name)), ("argsFingerprint", opt_str(&tc.args_fingerprint)), ("resultTokens", json!(tc.result_tokens))]))
                    .collect(),
            ),
        ),
        ("definedToolNames", json!(c.defined_tool_names)),
        ("definedToolTokens", json!(c.defined_tool_tokens)),
    ])
}

fn signal_json(s: &Signal) -> Value {
    bean(vec![
        ("id", json!(s.id)),
        ("severity", json!(s.severity)),
        ("title", json!(s.title)),
        ("detail", json!(s.detail)),
        ("affectedCalls", json!(s.affected)),
        ("estimatedWastedInputTokens", s.wasted.map_or(Value::Null, |w| json!(w))),
        ("estimatedSavingUsd", s.saving.map_or(Value::Null, double)),
        ("recommendation", json!(s.recommendation)),
        ("urgency", double(s.urgency)),
        (
            "fix",
            s.fix.as_ref().map_or(Value::Null, |f| {
                bean(vec![
                    ("summary", json!(f.summary)),
                    ("action", json!(f.action)),
                    ("configSnippet", f.config_snippet.map_or(Value::Null, |c| json!(c))),
                    ("exampleExpectation", f.example_expectation.map_or(Value::Null, |c| json!(c))),
                    ("docsUrl", json!(f.docs_url)),
                ])
            }),
        ),
    ])
}

pub fn report_value(built: &Built) -> Value {
    report_json(&built.report)
}

pub fn render_json(built: &Built) -> String {
    crate::json::pretty(&report_json(&built.report))
}

// ---------------------------------------------------------------------------------------------------------------
// LlmOptimisationBriefRenderer
// ---------------------------------------------------------------------------------------------------------------

const FRAMING_PREAMBLE: &str = "You are an LLM cost-optimisation expert. Below is a captured agent run that was proxied through MockServer. Identify concrete ways to reduce inference cost by (1) tightening or caching prompts, (2) moving deterministic logic out of the model into tools, and (3) moving logic into HTTP or MCP endpoints. For each opportunity, estimate the token and cost saving and show the change. Prioritise the highest-saving, lowest-risk changes first.";

static SECRET_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    ["sk-[A-Za-z0-9]{16,}", "AKIA[0-9A-Z]{16}", r"Bearer\s+[A-Za-z0-9._-]{20,}", "gh[po]_[A-Za-z0-9]{20,}"].iter().map(|p| Regex::new(p).unwrap()).collect()
});

/// `maskSecrets`.
pub fn mask_secrets(text: &str) -> String {
    SECRET_PATTERNS.iter().fold(text.to_string(), |acc, p| p.replace_all(&acc, "***").into_owned())
}

/// `text.replaceAll("\\s+", " ").trim()`.
fn single_line(text: &str) -> String {
    let mut out = String::new();
    let mut in_space = false;
    for c in text.chars() {
        if matches!(c, ' ' | '\t' | '\n' | '\x0B' | '\x0C' | '\r') {
            if !in_space {
                out.push(' ');
            }
            in_space = true;
        } else {
            out.push(c);
            in_space = false;
        }
    }
    out.trim_matches(|c: char| c <= ' ').to_string()
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() { "(none)".into() } else { values.join(", ") }
}

fn dash(v: &Option<String>) -> &str {
    v.as_deref().filter(|s| !s.is_empty()).unwrap_or("-")
}

/// `FixtureRedactor` on a request body: configured JSON fields become `***REDACTED***`.
fn redacted_body(fields: &[String], body: &str) -> String {
    if fields.is_empty() || body.is_empty() {
        return body.to_string();
    }
    fn walk(fields: &[String], v: &mut Value) {
        match v {
            Value::Object(o) => {
                for (k, x) in o.iter_mut() {
                    if fields.iter().any(|f| f.eq_ignore_ascii_case(k)) {
                        *x = json!("***REDACTED***");
                    } else {
                        walk(fields, x);
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|i| walk(fields, i)),
            _ => {}
        }
    }
    match serde_json::from_str::<Value>(body) {
        Ok(mut node) if node.is_object() || node.is_array() => {
            walk(fields, &mut node);
            node.to_string()
        }
        _ => {
            let lower = body.to_lowercase();
            if fields.iter().any(|f| lower.contains(&f.to_lowercase())) { "***REDACTED — body not parseable as JSON***".into() } else { body.to_string() }
        }
    }
}

/// `service.redactor().redactRequestDefinition`: the request as the report's exports show it.
pub(crate) fn redacted_for_export(state: &State, request: &HttpRequest) -> HttpRequest {
    redacted_request(&body_fields(state), request)
}

fn redacted_request(fields: &[String], request: &HttpRequest) -> HttpRequest {
    let mut redacted = request.clone();
    if !fields.is_empty() {
        redacted.body = redacted_body(fields, &request.body_str()).into_bytes().into();
    }
    redacted
}

pub fn render_markdown(state: &State, built: &Built) -> String {
    let r = &built.report;
    let t = &r.totals;
    let v = &r.verdict;
    let mut md = format!("> {FRAMING_PREAMBLE}\n\n");
    md.push_str("## Verdict\n\n");
    md.push_str(&format!("- Grade: {}\n- {}\n", v.grade, v.rationale));
    md.push_str(&format!(
        "- Est. {} ({}% of spend) / {} tokens recoverable\n",
        usd4(v.total_saving),
        java_round(v.saving_fraction * 100.0),
        grouped(v.total_wasted)
    ));
    md.push_str(&format!("- Cache hit rate: {}\n- One-shot rate: {}\n\n", percent(t.cache_hit_ratio), percent(t.one_shot_rate)));
    md.push_str("## Run summary\n\n");
    if t.call_count == 0 {
        md.push_str("No LLM traffic captured for this session.\n");
        return md;
    }
    md.push_str(&format!("- Provider(s): {}\n", join_or_none(&r.providers)));
    md.push_str(&format!("- Model(s): {}\n", join_or_none(&r.models)));
    md.push_str(&format!("- Calls: {}\n", t.call_count));
    md.push_str(&format!("- Input tokens: {}\n", grouped(t.input_tokens)));
    md.push_str(&format!("- Output tokens: {}\n", grouped(t.output_tokens)));
    md.push_str(&format!("- Cached input tokens: {}\n", grouped(t.cached_input_tokens)));
    md.push_str(&format!("- Reasoning tokens: {}\n", grouped(t.reasoning_tokens)));
    md.push_str(&format!(
        "- Estimated cost: {}{}{}\n",
        usd4(t.estimated_cost),
        if t.cost_is_estimated { " (estimated — usage not reported upstream)" } else { "" },
        if t.cost_unknown { " (excludes unpriced calls — see \"n/a\" rows)" } else { "" }
    ));
    md.push_str(&format!("- Total latency: {} ms\n", t.total_latency_ms));
    md.push_str(&format!("- Tool calls: {}\n", t.tool_call_count));
    md.push_str(&format!("- Cache hit rate: {}\n- One-shot rate: {}\n\n", percent(t.cache_hit_ratio), percent(t.one_shot_rate)));

    md.push_str("## Per-call breakdown\n\n");
    md.push_str("| # | model | in tok | out tok | cost | latency | tools | finish |\n");
    md.push_str("|---|-------|--------|---------|------|---------|-------|--------|\n");
    for c in &r.calls {
        let cost = if c.cost_unknown { "n/a".to_string() } else { format!("{}{}", usd4(c.estimated_cost), if c.cost_is_estimated { "*" } else { "" }) };
        md.push_str(&format!(
            "| {} | {} | {} | {} | {cost} | {} ms | {} | {} |\n",
            c.index,
            dash(&c.model),
            grouped(c.input_tokens),
            grouped(c.output_tokens),
            c.latency_ms,
            c.tool_calls.len(),
            dash(&c.finish_reason)
        ));
    }
    md.push_str("\n*estimated cost (usage not reported upstream, or an approximate/placeholder rate); \"n/a\" = model could not be priced.\n\n");

    md.push_str("## Detected opportunities\n\n");
    if r.signals.is_empty() {
        md.push_str("No deterministic optimisation signals were detected.\n\n");
    }
    for s in &r.signals {
        md.push_str(&format!("### [{}] {}\n\n{}\n\n", s.severity, s.title, s.detail));
        let affected: Vec<String> = s.affected.iter().map(usize::to_string).collect();
        md.push_str(&format!("- Affected calls: {}\n", if affected.is_empty() { "(none)".into() } else { affected.join(", ") }));
        if let Some(w) = s.wasted {
            md.push_str(&format!("- Estimated wasted input tokens: {}\n", grouped(w)));
        }
        if let Some(saving) = s.saving {
            md.push_str(&format!("- Estimated saving: {}\n", usd4(saving)));
        }
        md.push_str(&format!("- Recommendation: {}\n", s.recommendation));
        if let Some(f) = &s.fix {
            md.push_str(&format!("- Fix: {} — {}\n", f.summary, f.action));
            if let Some(snippet) = f.config_snippet {
                md.push_str(&format!("\n```config\n{snippet}\n```\n"));
            }
            if let Some(example) = f.example_expectation {
                md.push_str(&format!("\n```json\n{example}\n```\n"));
            }
            md.push_str(&format!("- Docs: {}\n", f.docs_url));
        }
        md.push('\n');
    }

    md.push_str("## Conversations & tool definitions (appendix)\n\n");
    if built.exchanges.is_empty() {
        md.push_str("No request bodies were available to include.\n");
        return md;
    }
    let fields = body_fields(state);
    for (index, exchange) in built.exchanges.iter().enumerate() {
        let request = redacted_request(&fields, &exchange.request);
        md.push_str(&format!("### Call {index}\n\n"));
        let messages = conversation::decode(&exchange.provider, &request);
        if messages.is_empty() {
            md.push_str("_(no decodable messages)_\n\n");
        } else {
            md.push_str("**Messages:**\n\n");
            for m in &messages {
                md.push_str(&format!("- **{}**: {}", role_name(m.role), mask_secrets(&single_line(&m.text))));
                if !m.tool_calls.is_empty() {
                    let names: Vec<&str> = m.tool_calls.iter().map(|tc| tc.name.as_str()).collect();
                    md.push_str(&format!(" _(tool calls: {})_", names.join(", ")));
                }
                md.push('\n');
            }
            md.push('\n');
        }
        if let Ok(body) = serde_json::from_slice::<Value>(&request.body) && let Some(tools) = body.get("tools").filter(|t| t.as_array().is_some_and(|a| !a.is_empty())) {
            md.push_str("**Tool definitions:**\n\n```json\n");
            md.push_str(&crate::json::pretty(&crate::model::jackson_tree(tools)));
            md.push_str("\n```\n\n");
        }
    }
    md
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::User => "USER",
        Role::Assistant => "ASSISTANT",
        Role::Tool => "TOOL",
        Role::System => "SYSTEM",
    }
}

// ---------------------------------------------------------------------------------------------------------------
// LlmOptimisationCsvRenderer
// ---------------------------------------------------------------------------------------------------------------

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) { format!("\"{}\"", value.replace('"', "\"\"")) } else { value.to_string() }
}

pub fn render_csv(built: &Built) -> String {
    let r = &built.report;
    let t = &r.totals;
    let v = &r.verdict;
    let mut csv = String::from(
        "index,provider,model,input_tokens,output_tokens,cached_input_tokens,reasoning_tokens,estimated_cost_usd,cost_is_estimated,latency_ms,tool_calls,finish_reason\n",
    );
    for c in &r.calls {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{}\n",
            c.index,
            csv_escape(&c.provider),
            csv_escape(c.model.as_deref().unwrap_or_default()),
            c.input_tokens,
            c.output_tokens,
            c.cached_input_tokens,
            c.reasoning_tokens,
            fixed(c.estimated_cost, 6),
            c.cost_is_estimated,
            c.latency_ms,
            c.tool_calls.len(),
            csv_escape(c.finish_reason.as_deref().unwrap_or_default())
        ));
    }
    csv.push_str("\nsection,metric,value\n");
    let rows: Vec<(&str, &str, String)> = vec![
        ("totals", "call_count", t.call_count.to_string()),
        ("totals", "input_tokens", t.input_tokens.to_string()),
        ("totals", "output_tokens", t.output_tokens.to_string()),
        ("totals", "cached_input_tokens", t.cached_input_tokens.to_string()),
        ("totals", "reasoning_tokens", t.reasoning_tokens.to_string()),
        ("totals", "estimated_cost_usd", fixed(t.estimated_cost, 6)),
        ("totals", "cost_is_estimated", t.cost_is_estimated.to_string()),
        ("totals", "total_latency_ms", t.total_latency_ms.to_string()),
        ("totals", "tool_call_count", t.tool_call_count.to_string()),
        ("totals", "cache_hit_ratio", fixed(t.cache_hit_ratio, 4)),
        ("totals", "one_shot_rate", fixed(t.one_shot_rate, 4)),
        ("totals", "retry_call_count", t.retry_call_count.to_string()),
        ("verdict", "grade", v.grade.to_string()),
        ("verdict", "total_estimated_saving_usd", fixed(v.total_saving, 6)),
        ("verdict", "total_wasted_input_tokens", v.total_wasted.to_string()),
        ("verdict", "saving_fraction_of_spend", fixed(v.saving_fraction, 4)),
        ("verdict", "high_count", v.high.to_string()),
        ("verdict", "medium_count", v.medium.to_string()),
        ("verdict", "low_count", v.low.to_string()),
    ];
    for (section, metric, value) in rows {
        csv.push_str(&format!("{section},{metric},{}\n", csv_escape(&value)));
    }
    csv
}

// ---------------------------------------------------------------------------------------------------------------
// LlmDatasetExporter
// ---------------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Dataset {
    OpenAiEvals,
    FineTune,
    Promptfoo,
}

impl Dataset {
    /// `DatasetFormat.fromWire`.
    pub fn from_wire(format: &str) -> Option<Dataset> {
        match format.trim().to_lowercase().replace('_', "-").as_str() {
            "openai-evals" | "evals" => Some(Dataset::OpenAiEvals),
            "fine-tune" | "finetune" => Some(Dataset::FineTune),
            "promptfoo" => Some(Dataset::Promptfoo),
            _ => None,
        }
    }
}

/// `toSample`: the redacted input messages and the assistant's text.
fn sample(fields: &[String], exchange: &Captured) -> Option<(Vec<Value>, String)> {
    let request = redacted_request(fields, &exchange.request);
    let messages = conversation::decode(&exchange.provider, &request);
    if messages.is_empty() {
        return None;
    }
    let input = messages
        .iter()
        .map(|m| {
            let content = if m.text.is_empty() && m.role == Role::Tool {
                m.tool_results.iter().map(|(_, r)| r.as_str()).collect::<Vec<_>>().join("\n")
            } else {
                m.text.clone()
            };
            json!({"role": role_name(m.role).to_lowercase(), "content": mask_secrets(&content)})
        })
        .collect();
    let response = redacted_body(fields, &exchange.response_body);
    let ideal = telemetry::parse_completion(&exchange.provider, response.as_bytes()).and_then(|c| c.text).unwrap_or_default();
    Some((input, mask_secrets(&ideal)))
}

pub fn render_dataset(state: &State, built: &Built, format: Dataset) -> String {
    let fields = body_fields(state);
    let samples = built.exchanges.iter().filter_map(|x| sample(&fields, x));
    if format == Dataset::Promptfoo {
        let tests: Vec<Value> = samples
            .enumerate()
            .map(|(i, (input, ideal))| {
                json!({
                    "description": format!("captured sample {i}"),
                    "vars": {"messages": input},
                    "assert": [{"type": "equals", "value": ideal}],
                })
            })
            .collect();
        return crate::json::pretty(&json!({ "tests": tests }));
    }
    let mut out = String::new();
    for (mut input, ideal) in samples {
        let line = if format == Dataset::FineTune {
            input.push(json!({"role": "assistant", "content": ideal}));
            json!({ "messages": input })
        } else {
            json!({"input": input, "ideal": ideal})
        };
        out.push_str(&line.to_string());
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------------------------------------------
// The endpoint
// ---------------------------------------------------------------------------------------------------------------

/// `HttpRequestHandler.handleOptimisationReport`.
pub fn endpoint(state: &State, request: &HttpRequest) -> Reply {
    let param = |name: &str| crate::request::first(&request.query, name);
    let format = param("format").filter(|f| !f.is_empty()).unwrap_or("json");
    let dataset = Dataset::from_wire(format);
    let lower = format.to_ascii_lowercase();
    if dataset.is_none() && !["json", "markdown", "csv"].contains(&lower.as_str()) {
        return Reply::api_header(400, "text/plain", "format must be one of: json, markdown, csv, openai-evals, fine-tune, promptfoo");
    }
    let built = build(state, &Filter::new(param("session"), param("host"), param("provider")));
    match (dataset, lower.as_str()) {
        (Some(Dataset::Promptfoo), _) => Reply::api_header(200, "application/json; charset=utf-8", render_dataset(state, &built, Dataset::Promptfoo)),
        (Some(d), _) => Reply::api_header(200, "application/x-ndjson; charset=utf-8", render_dataset(state, &built, d)),
        (None, "markdown") => Reply::api_header(200, "text/markdown; charset=utf-8", render_markdown(state, &built)),
        (None, "csv") => Reply::api_header(200, "text/csv; charset=utf-8", render_csv(&built)),
        _ => Reply::api_header(200, "application/json", render_json(&built)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_like_big_decimal_half_up() {
        assert_eq!(fixed(0.006, 6), "0.006000");
        assert_eq!(fixed(1.0e-4, 6), "0.000100");
        assert_eq!(fixed(0.00005, 4), "0.0001");
        assert_eq!(fixed(0.5405405405, 4), "0.5405");
        assert_eq!(fixed(0.99995, 4), "1.0000");
        assert_eq!(fixed(12345.678, 2), "12345.68");
        assert_eq!(fixed(0.0, 4), "0.0000");
        assert_eq!(round4(1.0 / 120.0), 0.0083);
    }

    #[test]
    fn groups_thousands() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(1200), "1,200");
        assert_eq!(grouped(1234567), "1,234,567");
    }
}

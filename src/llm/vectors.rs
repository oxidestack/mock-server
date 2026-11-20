//! The non-completion `httpLlmResponse` shapes: embeddings (`EmbeddingVectors` and each codec's
//! `encodeEmbedding`), rerank results (`RerankScoring`, Cohere and Voyage) and OpenAI moderation verdicts
//! (`OpenAiModerationBodies`).

use serde_json::{Map, Value, json};

use crate::random::{JavaRandom, uniform};

/// `EmbeddingResponse` / `RerankResponse`: the knobs both share.
#[derive(Debug, Clone, Default)]
pub struct Vectors {
    pub dimensions: Option<i64>,
    pub top_n: Option<i64>,
    pub deterministic: bool,
    pub seed: Option<i64>,
}

impl Vectors {
    pub fn parse(v: &Value) -> Vectors {
        Vectors {
            dimensions: v.get("dimensions").and_then(Value::as_i64),
            top_n: v.get("topN").and_then(Value::as_i64),
            deterministic: v.get("deterministicFromInput").and_then(Value::as_bool) == Some(true),
            seed: v.get("seed").and_then(Value::as_i64),
        }
    }
}

/// `ModerationResponse`.
#[derive(Debug, Clone, Default)]
pub struct Moderation {
    pub flagged: Vec<String>,
    pub model: Option<String>,
}

impl Moderation {
    pub fn parse(v: &Value) -> Moderation {
        Moderation {
            flagged: v.get("flaggedCategories").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect(),
            model: v.get("model").and_then(Value::as_str).map(str::to_string),
        }
    }
}

fn double(v: f64) -> Value {
    crate::model::number(&java_compat::double_to_string(v))
}

/// A JSON object with these members in order. (`json!` would re-serialise the numbers and lose their Java text.)
fn obj(members: Vec<(&str, Value)>) -> Value {
    Value::Object(members.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

// ---------------------------------------------------------------------------------------------------------------
// EmbeddingVectors
// ---------------------------------------------------------------------------------------------------------------

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn fnv1a(feature: &str, seed: i64, salt: u8) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for i in 0..8 {
        hash ^= ((seed as u64) >> (i * 8)) & 0xff;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash ^= salt as u64;
    hash = hash.wrapping_mul(FNV_PRIME);
    for b in feature.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Features in first-seen order with their counts.
#[derive(Default)]
struct Features(Vec<(String, i64)>);

impl Features {
    fn increment(&mut self, feature: String) {
        match self.0.iter_mut().find(|(f, _)| *f == feature) {
            Some(entry) => entry.1 += 1,
            None => self.0.push((feature, 1)),
        }
    }

    /// `accumulate`, over the features in `HashMap` iteration order (the sums depend on it).
    fn accumulate(&self, vector: &mut [f64], seed: i64, multiplier: f64) {
        let keys: Vec<String> = self.0.iter().map(|(k, _)| k.clone()).collect();
        let dimensions = vector.len() as i64;
        for i in crate::recorded::java_hashmap_merge_order(&keys) {
            let (feature, count) = &self.0[i];
            let weight = multiplier * (1.0 + crate::fdlibm::log(*count as f64));
            let bucket = (fnv1a(feature, seed, 0) as i64).rem_euclid(dimensions) as usize;
            let sign = if fnv1a(feature, seed, 1) & 1 == 0 { 1.0 } else { -1.0 };
            vector[bucket] += sign * weight;
        }
    }
}

/// `tokenize`: lower-cased letter-or-digit runs.
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for c in input.to_lowercase().chars() {
        if c.is_alphanumeric() {
            current.push(c);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// `generateDeterministicVector`: hashed word, bigram and character-trigram features.
fn deterministic_vector(input: &str, dimensions: usize, seed: i64) -> Vec<f64> {
    if dimensions == 0 {
        return Vec::new();
    }
    let (words, chars) = features(input);
    if words.0.is_empty() && chars.0.is_empty() {
        let mut random = JavaRandom::new(fnv1a(&format!("fallback:{dimensions}:{input}"), seed, 2) as i64);
        return (0..dimensions).map(|_| random.next_double() * 2.0 - 1.0).collect();
    }
    let mut vector = vec![0.0; dimensions];
    words.accumulate(&mut vector, seed, 1.0);
    chars.accumulate(&mut vector, seed, 0.5);
    vector
}

/// `extractFeatures`: words and bigrams, and the character trigrams of each `#word#`.
fn features(input: &str) -> (Features, Features) {
    let mut words = Features::default();
    let mut chars = Features::default();
    let mut previous: Option<String> = None;
    for token in tokenize(input) {
        words.increment(format!("w:{token}"));
        if let Some(previous) = &previous {
            words.increment(format!("b:{previous} {token}"));
        }
        let padded: Vec<u16> = format!("#{token}#").encode_utf16().collect();
        if padded.len() <= 3 {
            chars.increment(format!("c:{}", String::from_utf16_lossy(&padded)));
        } else {
            for i in 0..=padded.len() - 3 {
                chars.increment(format!("c:{}", String::from_utf16_lossy(&padded[i..i + 3])));
            }
        }
        previous = Some(token);
    }
    (words, chars)
}

/// `EmbeddingVectors.build`: deterministic from the input when asked (and there is one), else random; L2-normalised.
fn build(embedding: &Vectors, input: Option<&str>, default_dimensions: i64) -> Vec<f64> {
    let dimensions = embedding.dimensions.unwrap_or(default_dimensions).max(0) as usize;
    let mut vector = if let Some(input) = input.filter(|_| embedding.deterministic) {
        deterministic_vector(input, dimensions, embedding.seed.unwrap_or(0))
    } else {
        (0..dimensions).map(|_| uniform() * 2.0 - 1.0).collect()
    };
    let norm = vector.iter().map(|v| v * v).sum::<f64>().sqrt();
    if norm > 0.0 {
        vector.iter_mut().for_each(|v| *v /= norm);
    }
    vector
}

/// `approximateTokens`.
fn approximate_tokens(input: &str) -> i64 {
    (input.encode_utf16().count() as i64 / 4).max(1)
}

/// `EmbeddingWire.tokens`.
fn total_tokens(inputs: &[Option<String>]) -> i64 {
    inputs.iter().map(|i| i.as_deref().map_or(0, approximate_tokens)).sum()
}

/// `EmbeddingWire.InvalidEmbeddingRequestException`: a request the real provider would reject, answered `400` in the
/// provider's own error shape ([`invalid_request`]).
#[derive(Debug, Clone)]
pub struct Invalid {
    param: Option<String>,
    message: String,
    kind: Option<&'static str>,
    code: Option<&'static str>,
}

impl Invalid {
    fn new(param: Option<&str>, message: impl Into<String>) -> Invalid {
        Invalid { param: param.map(str::to_string), message: message.into(), kind: None, code: None }
    }
}

/// Why an embedding or rerank was not encoded.
#[derive(Debug, Clone)]
pub enum Refusal {
    /// The codec has no such endpoint: `{"error": message}`.
    Unsupported(String),
    Invalid(Invalid),
}

impl From<Invalid> for Refusal {
    fn from(e: Invalid) -> Refusal {
        Refusal::Invalid(e)
    }
}

/// `EmbeddingWire.invalidRequest`: status, headers and body of the provider's invalid-request error.
pub fn invalid_request(provider: &str, e: &Invalid) -> (u32, Vec<(String, String)>, String) {
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    let body = match provider {
        "GEMINI" => json!({"error": {"code": 400, "message": e.message, "status": "INVALID_ARGUMENT"}}),
        "BEDROCK" => {
            headers.push(("x-amzn-ErrorType".into(), "ValidationException".into()));
            json!({"message": e.message})
        }
        "COHERE" => json!({"message": e.message}),
        "VOYAGE" => json!({"detail": e.message}),
        "OLLAMA" | "ANTHROPIC" | "OPENAI_RESPONSES" => json!({"error": e.message}),
        _ => json!({"error": {"message": e.message, "type": e.kind.unwrap_or("invalid_request_error"), "param": e.param, "code": e.code}}),
    };
    (400, headers, body.to_string())
}

/// `EmbeddingWire.MAX_REQUESTED_DIMENSIONS`, `MAX_INPUTS` and `DEFAULT_MAX_TOTAL_VALUES`.
const MAX_REQUESTED_DIMENSIONS: i64 = 8192;
const MAX_INPUTS: usize = 2048;
const MAX_TOTAL_VALUES: i64 = 262_144;
const DEFAULT_MAX_INPUT_CHARACTERS: usize = 1_048_576;

/// `EmbeddingWire.Limits`: `llmEmbeddingMaxResponseValues` and `llmEmbeddingMaxInputCharacters`, each at least 1
/// (`HttpLlmResponseActionHandler.embeddingLimits`), in force on this thread while [`encode_embedding`] runs.
#[derive(Clone, Copy)]
pub struct Limits {
    max_total_values: i64,
    max_input_characters: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { max_total_values: MAX_TOTAL_VALUES, max_input_characters: DEFAULT_MAX_INPUT_CHARACTERS }
    }
}

impl Limits {
    pub fn from_config(config: &crate::config::Config) -> Limits {
        Limits {
            max_total_values: config.int_property("llmEmbeddingMaxResponseValues", MAX_TOTAL_VALUES).max(1),
            max_input_characters: config.int_property("llmEmbeddingMaxInputCharacters", DEFAULT_MAX_INPUT_CHARACTERS as i64).clamp(1, i64::from(i32::MAX)) as usize,
        }
    }
}

thread_local! {
    static LIMITS: std::cell::Cell<Limits> = std::cell::Cell::new(Limits::default());
}

fn max_total_values() -> i64 {
    LIMITS.with(|l| l.get().max_total_values)
}

fn max_input_characters() -> usize {
    LIMITS.with(|l| l.get().max_input_characters)
}

/// `EmbeddingWire.requestedDimensions`.
fn requested_dimensions(node: Option<&Value>, param: &str, allowed: &[i64]) -> Result<Option<i64>, Invalid> {
    let Some(node) = node.filter(|n| !n.is_null()) else { return Ok(None) };
    let value = node.as_i64().filter(|v| node.is_i64() && (1..=MAX_REQUESTED_DIMENSIONS).contains(v));
    let Some(value) = value else { return Err(Invalid::new(Some(param), format!("{param} must be an integer from 1 to {MAX_REQUESTED_DIMENSIONS}"))) };
    if !allowed.is_empty() && !allowed.contains(&value) {
        let list: Vec<String> = allowed.iter().map(i64::to_string).collect();
        return Err(Invalid::new(Some(param), format!("{param} must be one of [{}]", list.join(", "))));
    }
    Ok(Some(value))
}

fn check_input_count(count: usize, max: usize, param: &str) -> Result<(), Invalid> {
    if count > max {
        return Err(Invalid::new(Some(param), format!("{param} must have at most {max} entries, got {count}")));
    }
    Ok(())
}

fn check_total_values(total: i64, limit: i64) -> Result<(), Invalid> {
    if total > limit {
        return Err(Invalid::new(None, format!("embedding response would hold {total} values; the limit is {limit}. Send fewer inputs or ask for fewer dimensions")));
    }
    Ok(())
}

/// `EmbeddingWire.dimensions`: the expectation's, then the request's, then the provider default.
fn dimensions(embedding: &Vectors, requested: Option<i64>, default: i64) -> i64 {
    embedding.dimensions.or(requested).unwrap_or(default)
}

/// `EmbeddingWire.requestedTypes`.
fn requested_types(types: Option<&Value>, param: &str, allowed: &[&str]) -> Result<Vec<String>, Invalid> {
    let mut out: Vec<String> = Vec::new();
    for t in types.and_then(Value::as_array).into_iter().flatten() {
        match t.as_str().filter(|t| allowed.contains(t)) {
            Some(t) if !out.iter().any(|o| o == t) => out.push(t.to_string()),
            Some(_) => {}
            None => return Err(Invalid::new(Some(param), format!("{param} must be one or more of [{}]", allowed.join(", ")))),
        }
    }
    Ok(out)
}

/// `EmbeddingWire.build`: one input's vector, an over-long deterministic input refused.
fn vector(embedding: &Vectors, input: Option<&str>, requested: Option<i64>, default: i64) -> Result<Vec<f64>, Invalid> {
    let limit = max_input_characters();
    if let Some(text) = input.filter(|t| embedding.deterministic && t.encode_utf16().count() > limit) {
        return Err(Invalid::new(None, format!("an input has {} characters; the limit is {limit}. Send shorter inputs", text.encode_utf16().count())));
    }
    Ok(build(embedding, input, requested.unwrap_or(default)))
}

/// `EmbeddingWire.vector`: [`vector`] after checking that one vector fits the response limit.
fn checked_vector(embedding: &Vectors, input: Option<&str>, requested: Option<i64>, default: i64) -> Result<Vec<f64>, Invalid> {
    check_total_values(dimensions(embedding, requested, default), max_total_values())?;
    vector(embedding, input, requested, default)
}

fn floats(vector: &[f64]) -> Value {
    Value::Array(vector.iter().copied().map(double).collect())
}

/// `EmbeddingWire.text`: a non-empty string member.
fn text_of<'a>(body: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    body.get(field).and_then(Value::as_str).filter(|t| !t.is_empty())
}

/// `JsonNode.toString()` of a non-text node, the text of a text one.
fn node_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// `EmbeddingWire.stringOrArrayInputs`.
fn string_or_array_inputs(input: Option<&Value>) -> Result<Vec<Option<String>>, Invalid> {
    match input {
        None | Some(Value::Null) => Ok(vec![Some(String::new())]),
        Some(Value::Array(items)) if !items.is_empty() && items.iter().all(Value::is_number) => Ok(vec![Some(Value::Array(items.clone()).to_string())]),
        Some(Value::Array(items)) => {
            check_input_count(items.len(), MAX_INPUTS, "input")?;
            Ok(items.iter().map(|i| Some(node_text(i))).collect())
        }
        Some(other) => Ok(vec![Some(node_text(other))]),
    }
}

/// `EmbeddingWire.joinTextParts`: the `text` of each part (only parts of `kind` when given), joined by newlines.
fn join_text_parts(parts: Option<&Value>, kind: Option<&str>) -> String {
    let mut out = String::new();
    for part in parts.and_then(Value::as_array).into_iter().flatten() {
        if kind.is_some_and(|k| part.get("type").and_then(Value::as_str).filter(|t| !t.is_empty()) != Some(k)) {
            continue;
        }
        if let Some(t) = part.get("text").and_then(Value::as_str) {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(t);
        }
    }
    out
}

/// `EmbeddingWire.imageInput`: the SHA-256 hex of an image's data URI.
fn image_input(image: Option<&Value>) -> String {
    let uri = image.map(node_text).unwrap_or_default();
    ring::digest::digest(&ring::digest::SHA256, uri.as_bytes()).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// `extractDocumentsFromRequest`: each document as text (`text` of an object, else its JSON).
pub fn request_documents(body: &str) -> Vec<String> {
    let docs = serde_json::from_str::<Value>(body).ok().and_then(|v| v.get("documents").cloned());
    docs.as_ref()
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|d| match d {
            Value::String(s) => s.clone(),
            Value::Object(o) if o.contains_key("text") => match &o["text"] {
                Value::String(s) => s.clone(),
                Value::Null => "null".into(),
                other => other.to_string(),
            },
            other => other.to_string(),
        })
        .collect()
}

fn is_empty_input(v: &Value) -> bool {
    matches!(v, Value::String(s) if s.is_empty()) || matches!(v, Value::Array(a) if a.is_empty())
}

/// `OpenAiChatCompletionsCodec.encodeEmbedding(embedding, request, model)`: one `data[i]` per input, the request's
/// `model` echoed, its `dimensions` and `encoding_format` honoured.
fn openai_embedding(provider: &str, embedding: &Vectors, body: &Map<String, Value>, model: Option<&str>) -> Result<Value, Invalid> {
    let input = body.get("input");
    if let Some(input) = input.filter(|i| !i.is_null()) && (is_empty_input(input) || input.as_array().is_some_and(|a| a.iter().any(is_empty_input))) {
        return Err(Invalid::new(None, "input must not be empty: send a non-empty string, or an array of non-empty strings or token arrays"));
    }
    let inputs = string_or_array_inputs(input)?;
    let input_tokens = |lower_bound: bool| -> i64 {
        match input {
            Some(Value::Array(items)) if inputs.len() == 1 && items.first().is_some_and(Value::is_number) => items.len() as i64,
            Some(Value::Array(items)) => items
                .iter()
                .enumerate()
                .map(|(i, e)| match e {
                    Value::Array(a) => a.len() as i64,
                    _ if lower_bound => 1,
                    _ => inputs[i].as_deref().map_or(0, approximate_tokens),
                })
                .sum(),
            _ if lower_bound => 1,
            _ => total_tokens(&inputs),
        }
    };
    let tokens = input_tokens(false);
    const MAX_REQUEST_TOKENS: i64 = 300_000;
    if matches!(provider, "OPENAI" | "AZURE_OPENAI") && input_tokens(true) > MAX_REQUEST_TOKENS {
        return Err(Invalid {
            param: None,
            message: format!("Requested {tokens} tokens, max {MAX_REQUEST_TOKENS} tokens per request"),
            kind: Some("max_tokens_per_request"),
            code: Some("max_tokens_per_request"),
        });
    }
    // `rejectTokenArraysOverTheInputLimit`: the first token array over the model's 8,192-token input limit
    const MAX_INPUT_TOKENS: usize = 8192;
    if matches!(provider, "OPENAI" | "AZURE_OPENAI") {
        let arrays: Vec<usize> = match input {
            Some(Value::Array(items)) if inputs.len() == 1 && items.first().is_some_and(Value::is_number) => vec![items.len()],
            Some(Value::Array(items)) => items.iter().filter_map(Value::as_array).map(Vec::len).collect(),
            _ => Vec::new(),
        };
        if let Some(n) = arrays.into_iter().find(|n| *n > MAX_INPUT_TOKENS) {
            return Err(Invalid::new(
                None,
                format!(
                    "This model's maximum context length is {MAX_INPUT_TOKENS} tokens, however you requested {n} tokens ({n} in your prompt; 0 for the completion). Please reduce your prompt; or completion length."
                ),
            ));
        }
    }
    let model = text_of(body, "model").or(model.filter(|m| !m.is_empty())).unwrap_or("text-embedding-3-small").to_string();
    let requested = requested_dimensions(body.get("dimensions"), "dimensions", &[])?;
    let base64 = text_of(body, "encoding_format") == Some("base64");
    let limit = if base64 { 4 * max_total_values() } else { max_total_values() };
    check_total_values(dimensions(embedding, requested, 1536) * inputs.len() as i64, limit)?;
    let mut data = Vec::new();
    for (i, input) in inputs.iter().enumerate() {
        let v = vector(embedding, input.as_deref(), requested, 1536)?;
        let values = if base64 {
            use base64::Engine;
            let bytes: Vec<u8> = v.iter().flat_map(|x| (*x as f32).to_le_bytes()).collect();
            json!(base64::engine::general_purpose::STANDARD.encode(bytes))
        } else {
            floats(&v)
        };
        data.push(obj(vec![("object", json!("embedding")), ("index", json!(i)), ("embedding", values)]));
    }
    Ok(obj(vec![("object", json!("list")), ("data", Value::Array(data)), ("model", json!(model)), ("usage", json!({"prompt_tokens": tokens, "total_tokens": tokens}))]))
}

/// `OllamaCodec.encodeEmbedding(embedding, request, model)`: `/api/embed` (one vector per input), or the legacy
/// `/api/embeddings` (`prompt`, one `embedding`).
fn ollama_embedding(embedding: &Vectors, body: &Map<String, Value>, path: &str, model: Option<&str>) -> Result<Value, Invalid> {
    let requested = requested_dimensions(body.get("dimensions"), "dimensions", &[])?;
    let legacy = path.ends_with("/api/embeddings") || (!path.ends_with("/api/embed") && body.contains_key("prompt") && !body.contains_key("input"));
    if legacy {
        let text = body.get("prompt").and_then(Value::as_str).unwrap_or_default();
        return Ok(obj(vec![("embedding", floats(&checked_vector(embedding, Some(text), requested, 768)?))]));
    }
    let inputs = string_or_array_inputs(body.get("input"))?;
    let model = text_of(body, "model").or(model.filter(|m| !m.is_empty())).unwrap_or("nomic-embed-text").to_string();
    check_total_values(dimensions(embedding, requested, 768) * inputs.len() as i64, max_total_values())?;
    let mut embeddings = Vec::new();
    for input in &inputs {
        embeddings.push(floats(&checked_vector(embedding, input.as_deref(), requested, 768)?));
    }
    Ok(obj(vec![
        ("model", json!(model)),
        ("embeddings", Value::Array(embeddings)),
        ("total_duration", json!(14_143_917)),
        ("load_duration", json!(1_019_500)),
        ("prompt_eval_count", json!(total_tokens(&inputs))),
    ]))
}

/// `GeminiCodec.outputDimensionality`.
fn output_dimensionality(request: &Value) -> Result<Option<i64>, Invalid> {
    if let Some(top) = requested_dimensions(request.get("outputDimensionality"), "outputDimensionality", &[])? {
        return Ok(Some(top));
    }
    match request.get("embedContentConfig") {
        Some(config) => requested_dimensions(config.get("outputDimensionality"), "embedContentConfig.outputDimensionality", &[]),
        None => Ok(None),
    }
}

/// `GeminiCodec.encodeEmbedding(embedding, request, model)`: `embedContent` or `batchEmbedContents`.
fn gemini_embedding(embedding: &Vectors, body: &Map<String, Value>, path: &str) -> Result<Value, Invalid> {
    let requests = body.get("requests");
    let batch = path.ends_with(":batchembedcontents") || requests.is_some_and(Value::is_array);
    let mut inputs = Vec::new();
    let mut root = Vec::new();
    if batch {
        let mut embeddings = Vec::new();
        if let Some(requests) = requests.and_then(Value::as_array) {
            if requests.len() > 100 {
                return Err(Invalid::new(Some("requests"), "* BatchEmbedContentsRequest.requests: at most 100 requests can be in one batch"));
            }
            let mut total = 0;
            for r in requests {
                total += dimensions(embedding, output_dimensionality(r)?, 768);
            }
            check_total_values(total, max_total_values())?;
            for r in requests {
                let text = join_text_parts(r.get("content").and_then(|c| c.get("parts")), None);
                embeddings.push(obj(vec![("values", floats(&checked_vector(embedding, Some(&text), output_dimensionality(r)?, 768)?))]));
                inputs.push(Some(text));
            }
        }
        root.push(("embeddings", Value::Array(embeddings)));
    } else {
        let text = join_text_parts(body.get("content").and_then(|c| c.get("parts")), None);
        let values = floats(&checked_vector(embedding, Some(&text), output_dimensionality(&Value::Object(body.clone()))?, 768)?);
        root.push(("embedding", obj(vec![("values", values)])));
        inputs.push(Some(text));
    }
    root.push(("usageMetadata", json!({"promptTokenCount": total_tokens(&inputs)})));
    Ok(obj(root))
}

/// `BedrockCodec.EmbeddingFamily`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    TitanV1,
    TitanV2,
    TitanImage,
    CohereV3,
    CohereV4,
}

/// `BedrockCodec.familyFromModel`.
fn family_from_model(model: Option<&str>) -> Option<Family> {
    let id = model?.to_lowercase();
    if id.contains("cohere.embed") {
        return Some(if id.contains("embed-v4") { Family::CohereV4 } else { Family::CohereV3 });
    }
    if id.contains("titan-embed-text-v2") {
        return Some(Family::TitanV2);
    }
    if id.contains("titan-embed-text-v1") || id.contains("titan-embed-g1-text") {
        return Some(Family::TitanV1);
    }
    id.contains("titan-embed-image").then_some(Family::TitanImage)
}

/// `BedrockCodec.modelFromPath`: the URL-decoded model id of `/model/{id}/`.
fn model_from_path(path: &str) -> Option<String> {
    let start = path.find("/model/")? + "/model/".len();
    let rest = &path[start..];
    let end = rest.find('/')?;
    let raw = &rest[..end];
    if raw.is_empty() {
        return None;
    }
    Some(percent_encoding::percent_decode_str(raw).decode_utf8().map(|d| d.into_owned()).unwrap_or_else(|_| raw.to_string()))
}

/// `BedrockCodec.encodeEmbedding(embedding, request, model)`: Titan or Cohere, by the model in the path, the
/// expectation's model, else the body's shape.
/// The body comes with its token count, sent as the `X-Amzn-Bedrock-Input-Token-Count` header.
fn bedrock_embedding(embedding: &Vectors, body: &Map<String, Value>, raw_path: &str, model: Option<&str>) -> Result<(Value, i64), Invalid> {
    let family = family_from_model(model_from_path(raw_path).as_deref()).or_else(|| family_from_model(model)).unwrap_or_else(|| {
        if body.contains_key("texts") || body.contains_key("inputs") || body.contains_key("images") {
            if body.contains_key("inputs") || body.contains_key("output_dimension") { Family::CohereV4 } else { Family::CohereV3 }
        } else {
            Family::TitanV2
        }
    });
    match family {
        Family::CohereV3 | Family::CohereV4 => bedrock_cohere_embedding(embedding, body, family),
        _ => titan_embedding(embedding, body, family),
    }
}

fn titan_embedding(embedding: &Vectors, body: &Map<String, Value>, family: Family) -> Result<(Value, i64), Invalid> {
    let text = body.get("inputText").and_then(Value::as_str).unwrap_or_default();
    let count = approximate_tokens(text);
    let tokens = json!(count);
    let encoded = match family {
        Family::TitanV1 => Ok(obj(vec![("embedding", floats(&checked_vector(embedding, Some(text), None, 1536)?)), ("inputTextTokenCount", tokens)])),
        Family::TitanImage => {
            let length = match body.get("embeddingConfig") {
                Some(config) => requested_dimensions(config.get("outputEmbeddingLength"), "embeddingConfig.outputEmbeddingLength", &[256, 384, 1024])?,
                None => None,
            };
            Ok(obj(vec![("embedding", floats(&checked_vector(embedding, Some(text), length, 1024)?)), ("inputTextTokenCount", tokens)]))
        }
        _ => {
            let requested = requested_dimensions(body.get("dimensions"), "dimensions", &[256, 512, 1024])?;
            let types = requested_types(body.get("embeddingTypes"), "embeddingTypes", &["float", "binary"])?;
            let float = types.is_empty() || types.iter().any(|t| t == "float");
            let binary = types.iter().any(|t| t == "binary");
            check_total_values(dimensions(embedding, requested, 1024) * (if float { 2 } else { 0 } + i64::from(binary)), max_total_values())?;
            let v = checked_vector(embedding, Some(text), requested, 1024)?;
            let mut root = Vec::new();
            if float {
                root.push(("embedding", floats(&v)));
            }
            root.push(("inputTextTokenCount", tokens));
            let mut by_type = Vec::new();
            if binary {
                by_type.push(("binary", Value::Array(v.iter().map(|x| json!(i32::from(*x > 0.0))).collect())));
            }
            if float {
                by_type.push(("float", floats(&v)));
            }
            root.push(("embeddingsByType", obj(by_type)));
            Ok(obj(root))
        }
    };
    encoded.map(|body| (body, count))
}

/// `EmbeddingWire.cohereTyped`.
fn cohere_typed(vector: &[f64], kind: &str) -> Value {
    let java_round = |x: f64| (x + 0.5).floor() as i64;
    match kind {
        "int8" => Value::Array(vector.iter().map(|v| json!(java_round(v * 127.0).clamp(-128, 127))).collect()),
        "uint8" => Value::Array(vector.iter().map(|v| json!(java_round((v + 1.0) * 127.5).clamp(0, 255))).collect()),
        "binary" | "ubinary" => {
            let offset = if kind == "binary" { 128 } else { 0 };
            Value::Array(
                vector
                    .chunks(8)
                    .map(|chunk| {
                        let packed = (0..8).fold(0i64, |acc, bit| (acc << 1) | i64::from(chunk.get(bit).is_some_and(|v| *v > 0.0)));
                        json!(packed - offset)
                    })
                    .collect(),
            )
        }
        _ => floats(vector),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// CohereImageDescription: what Cohere Embed v3 on Bedrock says about the image it embedded
// ---------------------------------------------------------------------------------------------------------------

/// `CohereImageDescription.MAX_IMAGE_BYTES`.
const MAX_IMAGE_BYTES: u64 = 5 * 1024 * 1024;

/// `Base64Bytes`: the decoded bytes of a data URI's base64 payload, read in place.
struct Base64Bytes<'a> {
    text: &'a [u8],
    start: usize,
}

impl<'a> Base64Bytes<'a> {
    /// `payloadOf`: from after the comma of a `data:` URI, else the whole text.
    fn payload_of(uri: &'a str) -> Base64Bytes<'a> {
        let start = if is_data_uri(uri) { uri.find(',').map_or(0, |c| c + 1) } else { 0 };
        Base64Bytes { text: uri.as_bytes(), start }
    }

    fn value(c: u8) -> i32 {
        match c {
            b'A'..=b'Z' => i32::from(c - b'A'),
            b'a'..=b'z' => i32::from(c - b'a') + 26,
            b'0'..=b'9' => i32::from(c - b'0') + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => -1,
        }
    }

    /// `at`: the decoded byte at `index`, or -1.
    fn at(&self, index: i64) -> i32 {
        if index < 0 {
            return -1;
        }
        let remainder = index % 3;
        let first = self.start as i64 + (index / 3) * 4 + remainder;
        if first + 1 >= self.text.len() as i64 {
            return -1;
        }
        let (a, b) = (Self::value(self.text[first as usize]), Self::value(self.text[first as usize + 1]));
        if a < 0 || b < 0 {
            return -1;
        }
        match remainder {
            0 => (a << 2) | (b >> 4),
            1 => ((a & 0x0F) << 4) | (b >> 2),
            _ => ((a & 0x03) << 6) | b,
        }
    }

    fn unsigned16(&self, index: i64) -> i64 {
        let (high, low) = (self.at(index), self.at(index + 1));
        if high < 0 || low < 0 { -1 } else { i64::from((high << 8) | low) }
    }

    fn unsigned32(&self, index: i64) -> i64 {
        let (high, low) = (self.unsigned16(index), self.unsigned16(index + 2));
        if high < 0 || low < 0 { -1 } else { (high << 16) | low }
    }

    /// `decodesToMoreThan`.
    fn decodes_to_more_than(&self, limit: u64) -> bool {
        if (self.text.len() - self.start) as u64 * 3 / 4 <= limit {
            return false;
        }
        let mut characters = 0u64;
        for &c in &self.text[self.start..] {
            if Self::value(c) >= 0 {
                characters += 1;
                if characters * 3 / 4 > limit {
                    return true;
                }
            }
        }
        false
    }
}

fn is_data_uri(uri: &str) -> bool {
    uri.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("data:"))
}

/// `mediaType`: a data URI's media type, lower case (None: not a data URI, or a type over 64 characters).
fn image_media_type(uri: &str) -> Option<String> {
    if !is_data_uri(uri) {
        return None;
    }
    let chars: Vec<char> = uri.chars().collect();
    let limit = chars.len().min(5 + 64);
    let mut end = 5;
    while end < limit && chars[end] != ';' && chars[end] != ',' {
        end += 1;
    }
    if end == limit && limit < chars.len() {
        return None;
    }
    Some(chars[5..end].iter().collect::<String>().trim().to_lowercase())
}

/// `checkSupported`: Cohere Embed v3 takes PNG or JPEG data URIs only.
fn check_image_supported(image: &Value) -> Result<(), Invalid> {
    let media_type = image.as_str().and_then(image_media_type);
    match media_type.as_deref() {
        Some("image/png" | "image/jpeg" | "image/jpg") => Ok(()),
        other => Err(Invalid::new(
            Some("images"),
            format!("images must be data URIs in image/jpeg or image/png format{}", other.filter(|m| !m.is_empty()).map(|m| format!(", got {m}")).unwrap_or_default()),
        )),
    }
}

/// `checkSize`: a data URI image decodes to at most 5MB.
fn check_image_size(image: Option<&Value>, param: &str) -> Result<(), Invalid> {
    match image.and_then(Value::as_str) {
        Some(uri) if is_data_uri(uri) && Base64Bytes::payload_of(uri).decodes_to_more_than(MAX_IMAGE_BYTES) => {
            Err(Invalid::new(Some(param), format!("{param} must each be at most 5MB")))
        }
        _ => Ok(()),
    }
}

/// `describe`: width, height, format and bit depth from a PNG or JPEG header, else zeros and the media type's format.
fn describe_image(image: &Value) -> Value {
    let uri = image.as_str().unwrap_or_default();
    let bytes = Base64Bytes::payload_of(uri);
    let (width, height, format, bit_depth) = png_header(&bytes).or_else(|| jpeg_header(&bytes)).unwrap_or_else(|| {
        let format = image_media_type(uri).map_or_else(String::new, |m| {
            let subtype = m.split_once('/').map_or(m.as_str(), |(_, s)| s).to_string();
            if subtype == "jpg" { "jpeg".to_string() } else { subtype }
        });
        (0, 0, format, 0)
    });
    obj(vec![("width", json!(width)), ("height", json!(height)), ("format", json!(format)), ("bit_depth", json!(bit_depth))])
}

fn png_header(bytes: &Base64Bytes) -> Option<(i64, i64, String, i64)> {
    const SIGNATURE: [i32; 8] = [0x89, b'P' as i32, b'N' as i32, b'G' as i32, 0x0D, 0x0A, 0x1A, 0x0A];
    if SIGNATURE.iter().enumerate().any(|(i, b)| bytes.at(i as i64) != *b) || b"IHDR".iter().enumerate().any(|(i, b)| bytes.at(12 + i as i64) != i32::from(*b)) {
        return None;
    }
    let (width, height, depth, colour) = (bytes.unsigned32(16), bytes.unsigned32(20), bytes.at(24), bytes.at(25));
    if width < 0 || height < 0 || depth < 0 || colour < 0 {
        return None;
    }
    let channels = match colour {
        0 | 3 => 1,
        2 => 3,
        4 => 2,
        6 => 4,
        _ => 0,
    };
    Some((width, height, "png".into(), i64::from(depth) * channels))
}

fn jpeg_header(bytes: &Base64Bytes) -> Option<(i64, i64, String, i64)> {
    if bytes.at(0) != 0xFF || bytes.at(1) != 0xD8 {
        return None;
    }
    let mut position: i64 = 2;
    for _ in 0..1024 {
        if bytes.at(position) != 0xFF {
            return None;
        }
        let mut marker = bytes.at(position + 1);
        while marker == 0xFF {
            position += 1;
            marker = bytes.at(position + 1);
        }
        if marker < 0 || marker == 0xD9 || marker == 0xDA {
            return None;
        }
        if marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            position += 2;
            continue;
        }
        let length = bytes.unsigned16(position + 2);
        if length < 2 {
            return None;
        }
        if (0xC0..=0xCF).contains(&marker) && ![0xC4, 0xC8, 0xCC].contains(&marker) {
            let (precision, height, width, components) = (bytes.at(position + 4), bytes.unsigned16(position + 5), bytes.unsigned16(position + 7), bytes.at(position + 9));
            if precision < 0 || height < 0 || width < 0 || components < 0 {
                return None;
            }
            return Some((width, height, "jpeg".into(), i64::from(precision) * i64::from(components)));
        }
        position += 2 + length;
    }
    None
}

/// `BedrockCodec.cohereInputText`: a v4 `inputs` item's parts, an image as the digest of its URL.
fn cohere_input_text(content: Option<&Value>) -> Result<String, Invalid> {
    let mut out = String::new();
    for part in content.and_then(Value::as_array).into_iter().flatten() {
        let value = match part.get("type").and_then(Value::as_str).unwrap_or_default() {
            "text" => part.get("text").and_then(Value::as_str).map(str::to_string),
            "image_url" => {
                let image_url = part.get("image_url");
                let url = match image_url {
                    Some(Value::Object(o)) => o.get("url"),
                    other => other,
                };
                check_image_size(url, "inputs")?;
                Some(image_input(url))
            }
            _ => None,
        };
        if let Some(value) = value {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&value);
        }
    }
    Ok(out)
}

/// `BedrockCodec.cohereTextPartTokens`: the approximate tokens of a v4 `inputs` item's text parts; images add none.
fn cohere_text_part_tokens(content: Option<&Value>) -> i64 {
    content
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|part| part.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|part| part.get("text").and_then(Value::as_str))
        .map(approximate_tokens)
        .sum()
}

fn bedrock_cohere_embedding(embedding: &Vectors, body: &Map<String, Value>, family: Family) -> Result<(Value, i64), Invalid> {
    let (texts, items, images) = (body.get("texts").filter(|t| t.is_array()), body.get("inputs").filter(|t| t.is_array()), body.get("images").filter(|t| t.is_array()));
    if texts.is_some() && images.is_some() {
        return Err(Invalid::new(Some("images"), "send either texts or images, not both"));
    }
    let mut inputs: Vec<Option<String>> = Vec::new();
    let mut tokens = 0;
    if let Some(texts) = texts.and_then(Value::as_array) {
        check_input_count(texts.len(), 96, "texts")?;
        inputs.extend(texts.iter().map(|t| (!t.is_null()).then(|| node_text(t))));
        tokens = total_tokens(&inputs);
    } else if let Some(items) = items.and_then(Value::as_array) {
        check_input_count(items.len(), 96, "inputs")?;
        for item in items {
            inputs.push(Some(cohere_input_text(item.get("content"))?));
            tokens += cohere_text_part_tokens(item.get("content"));
        }
    } else if let Some(images) = images.and_then(Value::as_array) {
        check_input_count(images.len(), if family == Family::CohereV4 { 96 } else { 1 }, "images")?;
        for image in images {
            if family == Family::CohereV3 {
                check_image_supported(image)?;
            }
            check_image_size(Some(image), "images")?;
            inputs.push(Some(image_input(Some(image))));
        }
    }
    let requested = if family == Family::CohereV4 { requested_dimensions(body.get("output_dimension"), "output_dimension", &[256, 512, 1024, 1536])? } else { None };
    let default = if family == Family::CohereV4 { 1536 } else { 1024 };
    let types = requested_types(body.get("embedding_types"), "embedding_types", &["float", "int8", "uint8", "binary", "ubinary"])?;
    check_total_values(dimensions(embedding, requested, default) * inputs.len() as i64 * types.len().max(1) as i64, max_total_values())?;
    let mut vectors = Vec::new();
    for input in &inputs {
        vectors.push(checked_vector(embedding, input.as_deref(), requested, default)?);
    }
    let mut root = vec![("id", json!(uuid::Uuid::new_v4().to_string()))];
    if types.is_empty() {
        root.push(("embeddings", Value::Array(vectors.iter().map(|v| floats(v)).collect())));
        root.push(("response_type", json!("embeddings_floats")));
    } else {
        let by_type: Vec<(&str, Value)> = types.iter().map(|t| (t.as_str(), Value::Array(vectors.iter().map(|v| cohere_typed(v, t)).collect()))).collect();
        root.push(("embeddings", obj(by_type)));
        root.push(("response_type", json!("embeddings_by_type")));
    }
    if let Some(texts) = texts {
        root.push(("texts", texts.clone()));
    } else if let Some(items) = items {
        root.push(("inputs", items.clone()));
    } else {
        root.push(("texts", json!([])));
        if let Some(images) = images.and_then(Value::as_array).filter(|_| family == Family::CohereV3) {
            root.push(("images", Value::Array(images.iter().map(describe_image).collect())));
        }
    }
    Ok((obj(root), tokens))
}

/// `encodeEmbedding(embedding, request, model)` of `provider`'s codec: the JSON body and the headers the codec adds
/// (Bedrock's input token count), or the codec's refusal.
pub fn encode_embedding(provider: &str, embedding: &Vectors, request: &crate::request::HttpRequest, model: Option<&str>, limits: Limits) -> Result<(String, Vec<(String, String)>), Refusal> {
    let previous = LIMITS.with(|l| l.replace(limits));
    let encoded = encode_embedding_within_limits(provider, embedding, request, model);
    LIMITS.with(|l| l.set(previous));
    encoded
}

fn encode_embedding_within_limits(provider: &str, embedding: &Vectors, request: &crate::request::HttpRequest, model: Option<&str>) -> Result<(String, Vec<(String, String)>), Refusal> {
    let body = super::codec::request_object(request);
    let path = request.path.to_lowercase();
    let encoded = match provider {
        "OPENAI" | "AZURE_OPENAI" | "MISTRAL" | "XAI" | "DEEPSEEK" | "GROQ" | "OPENROUTER" | "ORCAROUTER" => openai_embedding(provider, embedding, &body, model)?,
        "OLLAMA" => ollama_embedding(embedding, &body, &path, model)?,
        "GEMINI" => gemini_embedding(embedding, &body, &path)?,
        "BEDROCK" => {
            let (encoded, tokens) = bedrock_embedding(embedding, &body, &request.path, model)?;
            return Ok((encoded.to_string(), vec![(super::codec::BEDROCK_INPUT_TOKEN_COUNT.into(), tokens.to_string())]));
        }
        "ANTHROPIC" => return Err(Refusal::Unsupported("Anthropic does not expose an embeddings endpoint".into())),
        "OPENAI_RESPONSES" => return Err(Refusal::Unsupported("OpenAI Responses API does not expose an embeddings endpoint".into())),
        other => return Err(Refusal::Unsupported(format!("encodeEmbedding not implemented for provider {other}"))),
    };
    Ok((encoded.to_string(), Vec::new()))
}

// ---------------------------------------------------------------------------------------------------------------
// RerankScoring
// ---------------------------------------------------------------------------------------------------------------

/// `deterministicScore`: from the SHA-256 of `seed:document`, in (0, 1] to four places.
fn deterministic_score(document: &str, seed: i64) -> f64 {
    let hash = ring::digest::digest(&ring::digest::SHA256, format!("{seed}:{document}").as_bytes());
    let bits = i64::from_be_bytes(hash.as_ref()[..8].try_into().expect("8 bytes")) & i64::MAX;
    let score = ((bits % 1_000_000) + 1) as f64 / 1_000_001.0;
    (score * 10_000.0 + 0.5).floor() / 10_000.0
}

/// `RerankScoring.requestedTopN`.
fn requested_top_n(node: Option<&Value>, param: &str) -> Result<Option<i64>, Invalid> {
    let Some(node) = node.filter(|n| !n.is_null()) else { return Ok(None) };
    match node.as_i64().filter(|v| node.is_i64() && *v >= 1 && *v <= i64::from(i32::MAX)) {
        Some(v) => Ok(Some(v)),
        None => Err(Invalid::new(Some(param), format!("{param} must be a positive integer"))),
    }
}

/// `RerankScoring.score`: sorted by descending score (ties by index), capped to the expectation's `topN`, else the
/// request's.
fn score(rerank: &Vectors, documents: &[String], requested_top_n: Option<i64>) -> Vec<(usize, f64)> {
    let mut scored: Vec<(usize, f64)> = documents
        .iter()
        .enumerate()
        .map(|(i, d)| (i, if rerank.deterministic { deterministic_score(d, rerank.seed.unwrap_or(0)) } else { uniform() }))
        .collect();
    scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    if let Some(n) = rerank.top_n.or(requested_top_n).filter(|n| *n >= 0 && (*n as usize) < scored.len()) {
        scored.truncate(n as usize);
    }
    scored
}

/// `encodeRerank(rerank, documents, request)` of Cohere (`results`, `/v1` or `/v2/rerank`) or Voyage (`data`); other
/// codecs refuse.
pub fn encode_rerank(provider: &str, rerank: &Vectors, documents: &[String], request: &crate::request::HttpRequest) -> Result<String, Refusal> {
    let body = super::codec::request_object(request);
    let returns_documents = body.get("return_documents").and_then(Value::as_bool) == Some(true);
    let encoded = match provider {
        "COHERE" => {
            let v2 = request.path.to_lowercase().contains("/v2/rerank");
            let scored = score(rerank, documents, requested_top_n(body.get("top_n"), "top_n")?);
            let request_documents = body.get("documents");
            let results = scored
                .iter()
                .map(|(i, s)| {
                    let mut result = vec![("index", json!(i)), ("relevance_score", double(*s))];
                    if !v2 && returns_documents {
                        let document = match request_documents.and_then(|d| d.get(*i)) {
                            Some(d @ Value::Object(_)) => d.clone(),
                            _ => json!({"text": documents[*i]}),
                        };
                        result.push(("document", document));
                    }
                    obj(result)
                })
                .collect();
            let search_units = ((documents.len() as i64 + 99) / 100).max(1);
            obj(vec![
                ("results", Value::Array(results)),
                ("id", json!(uuid::Uuid::new_v4().to_string())),
                ("meta", json!({"api_version": {"version": if v2 { "2" } else { "1" }}, "billed_units": {"search_units": search_units}})),
            ])
        }
        "VOYAGE" => {
            if documents.len() > 1000 {
                return Err(Invalid::new(Some("documents"), "The number of documents cannot exceed 1,000.").into());
            }
            let scored = score(rerank, documents, requested_top_n(body.get("top_k"), "top_k")?);
            let data = scored
                .iter()
                .map(|(i, s)| {
                    let mut result = vec![("index", json!(i)), ("relevance_score", double(*s))];
                    if returns_documents {
                        result.push(("document", json!(documents[*i])));
                    }
                    obj(result)
                })
                .collect();
            let query_tokens = body.get("query").and_then(Value::as_str).filter(|q| !q.is_empty()).map_or(0, approximate_tokens);
            let tokens = query_tokens * documents.len() as i64 + documents.iter().map(|d| approximate_tokens(d)).sum::<i64>();
            obj(vec![
                ("object", json!("list")),
                ("data", Value::Array(data)),
                ("model", json!(text_of(&body, "model").unwrap_or("rerank-2"))),
                ("usage", json!({"total_tokens": tokens})),
            ])
        }
        other => return Err(Refusal::Unsupported(format!("encodeRerank not implemented for provider {other}"))),
    };
    Ok(encoded.to_string())
}

// ---------------------------------------------------------------------------------------------------------------
// OpenAiModerationBodies
// ---------------------------------------------------------------------------------------------------------------

const CATEGORIES: &[&str] = &[
    "sexual",
    "hate",
    "harassment",
    "self-harm",
    "sexual/minors",
    "hate/threatening",
    "violence/graphic",
    "self-harm/intent",
    "self-harm/instructions",
    "harassment/threatening",
    "violence",
];

/// The moderation verdict: every category, flagged ones scoring 0.95.
pub fn encode_moderation(moderation: &Moderation) -> String {
    let flagged: Vec<String> = moderation.flagged.iter().map(|c| c.trim().to_lowercase()).collect();
    let mut categories = Map::new();
    let mut scores = Map::new();
    for c in CATEGORIES {
        let hit = flagged.iter().any(|f| f == c);
        categories.insert((*c).into(), json!(hit));
        scores.insert((*c).into(), double(if hit { 0.95 } else { 0.0001 }));
    }
    let id: String = uuid::Uuid::new_v4().simple().to_string().chars().take(24).collect();
    let result = obj(vec![
        ("flagged", json!(CATEGORIES.iter().any(|c| flagged.iter().any(|f| f == c)))),
        ("categories", Value::Object(categories)),
        ("category_scores", Value::Object(scores)),
    ]);
    obj(vec![
        ("id", json!(format!("modr-{id}"))),
        ("model", json!(moderation.model.as_deref().filter(|m| !m.is_empty()).unwrap_or("omni-moderation-latest"))),
        ("results", Value::Array(vec![result])),
    ])
    .to_string()
}

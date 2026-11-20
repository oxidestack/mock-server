//! `LlmBackendResolver` and the runtime clients' `buildCompletionRequest` (`OpenAiLlmClient` and its compatible
//! providers, `AzureOpenAiLlmClient`, `OpenAiResponsesLlmClient`, `AnthropicLlmClient`, `BedrockLlmClient` with SigV4,
//! `GeminiLlmClient`, `OllamaLlmClient`): the backend a live call goes to, and the request it sends there.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use super::conversation::{Message, Role};
use crate::state::State;

/// `LlmBackend`.
#[derive(Debug, Clone)]
pub struct Backend {
    pub provider: String,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub headers: Vec<(String, String)>,
    pub timeout_millis: Option<i64>,
}

/// `LlmBackendResolver.parseProvider`: `Provider.valueOf(trimmed, upper-cased)`.
fn backend_provider(value: Option<&str>) -> Option<String> {
    let p = value.filter(|v| !v.is_empty())?.trim().to_uppercase();
    crate::mcp::PROVIDERS.contains(&p.as_str()).then_some(p)
}

/// `resolveDefault`: the `llm*` properties, then `OLLAMA_HOST`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
/// `GEMINI_API_KEY`.
pub fn resolve_default(state: &State) -> Option<Backend> {
    // `LlmBackendResolver` reads `HttpState`'s configuration, which a `PUT /mockserver/configuration` now reaches
    // (upstream 0e8566814; the 8.0.0 process kept its startup copy).
    resolve_with(state, |k| state.config.property(k))
}

/// `resolveDefault` as `LifeCycle` runs it once at start, for the features it installs then (semantic prompt
/// matching, semantic drift analysis): the properties the server started with.
pub fn resolve_at_startup(state: &State) -> Option<Backend> {
    resolve_with(state, |k| state.config.startup_property(k))
}

fn resolve_with(state: &State, read: impl Fn(&str) -> Option<String>) -> Option<Backend> {
    let property = |k: &str| read(k).filter(|v| !v.is_empty());
    if let Some(provider) = backend_provider(property("llmProvider").as_deref()) {
        return Some(Backend {
            provider,
            base_url: property("llmBaseUrl"),
            api_key: property("llmApiKey"),
            model: property("llmModel"),
            headers: Vec::new(),
            timeout_millis: Some(property("llmRequestTimeoutMillis").and_then(|t| t.trim().parse().ok()).unwrap_or(30000)),
        });
    }
    let env = |k: &str| state.config.env_var(k).filter(|v| !v.is_empty());
    let keyed = |provider: &str, key: String| Backend { provider: provider.into(), base_url: None, api_key: Some(key), model: None, headers: Vec::new(), timeout_millis: None };
    if let Some(host) = env("OLLAMA_HOST") {
        let base = if host.starts_with("http") { host } else { format!("http://{host}") };
        return Some(Backend { provider: "OLLAMA".into(), base_url: Some(base), api_key: None, model: None, headers: Vec::new(), timeout_millis: None });
    }
    for (var, provider) in [("OPENAI_API_KEY", "OPENAI"), ("ANTHROPIC_API_KEY", "ANTHROPIC"), ("GEMINI_API_KEY", "GEMINI")] {
        if let Some(key) = env(var) {
            return Some(keyed(provider, key));
        }
    }
    None
}

/// `resolveByName`: a backend from the `llmBackendsConfig` file (a JSON array of named backends).
pub fn resolve_by_name(state: &State, name: &str) -> Option<Backend> {
    let path = state.config.property("llmBackendsConfig").filter(|p| !p.is_empty())?;
    let text = std::fs::read_to_string(path).ok()?;
    let root = crate::json::parse_lenient(text.as_bytes()).ok()?;
    let mut found = None;
    for node in root.as_array()? {
        let text = |k: &str| node.get(k).filter(|v| !v.is_null()).map(|v| crate::jnode::from_value(v).as_text());
        let Some(provider) = backend_provider(text("provider").as_deref()) else { continue };
        let Some(backend_name) = text("name") else { continue };
        let headers = node.get("headers").and_then(Value::as_object).map(|h| h.iter().map(|(k, v)| (k.clone(), crate::jnode::from_value(v).as_text())).collect()).unwrap_or_default();
        let backend = Backend {
            provider,
            base_url: text("baseUrl").filter(|v| !v.is_empty()),
            api_key: text("apiKey").filter(|v| !v.is_empty()),
            model: text("model").filter(|v| !v.is_empty()),
            headers,
            timeout_millis: node.get("timeoutMillis").and_then(Value::as_f64).map(|t| t as i64),
        };
        if backend_name == name {
            found = Some(backend);
        }
    }
    found
}

/// `LlmClient.buildCompletionRequest` as request JSON (`HttpRequestDTO`), with its socket address. A backend
/// without a `baseUrl` targets the provider's public API only where `allow_default_urls` (a configuration read
/// from the command line); otherwise the request is refused, so tests never reach a real provider. A Bedrock
/// request whose API key is `accessKeyId:secretAccessKey[:sessionToken]` is SigV4-signed at `now`.
pub fn completion_request(backend: &Backend, provider: &str, messages: &[Message], allow_default_urls: bool, now: DateTime<Utc>) -> Result<Value, String> {
    // `AzureOpenAiLlmClient`: an Azure resource is per-tenant, so there is deliberately no default host (anyone
    // owning a default resource name would be sent the api-key), whatever `allow_default_urls` says.
    if provider == "AZURE_OPENAI" && backend.base_url.as_deref().is_none_or(str::is_empty) {
        return Err("an Azure OpenAI backend needs a baseUrl (https://{resource}.openai.azure.com); none is configured, so nothing was sent".into());
    }
    if backend.base_url.is_none() && !allow_default_urls {
        return Err(format!("no baseUrl configured for the {} backend (provider default URLs are disabled for this configuration)", backend.provider));
    }
    let base = |default: &str| backend.base_url.clone().unwrap_or_else(|| default.to_string());
    let model = |default: &str| backend.model.clone().unwrap_or_else(|| default.to_string());
    let texts = || messages.iter().filter(|m| !m.text.is_empty());
    let role_content = |system: &str| -> Vec<Value> {
        texts()
            .map(|m| {
                let role = match m.role {
                    Role::System => system,
                    Role::Assistant => "assistant",
                    Role::Tool => "tool",
                    Role::User => "user",
                };
                json!({"role": role, "content": m.text})
            })
            .collect()
    };
    let split_system = || -> (String, Vec<&Message>) {
        let system: Vec<&str> = texts().filter(|m| m.role == Role::System).map(|m| m.text.as_str()).collect();
        (system.join("\n"), texts().filter(|m| m.role != Role::System).collect())
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut query: Vec<(String, String)> = Vec::new();
    let mut signing: Option<String> = None;
    let (base_url, path, body) = match provider {
        "ANTHROPIC" | "BEDROCK" => {
            let (system, rest) = split_system();
            let mut body = Map::new();
            let bedrock = provider == "BEDROCK";
            if bedrock {
                body.insert("anthropic_version".into(), json!("bedrock-2023-05-31"));
            } else {
                body.insert("model".into(), json!(model("claude-3-5-sonnet-20241022")));
            }
            body.insert("max_tokens".into(), json!(1024));
            body.insert("temperature".into(), json!(0));
            body.insert(
                "messages".into(),
                Value::Array(rest.iter().map(|m| json!({"role": if m.role == Role::Assistant { "assistant" } else { "user" }, "content": m.text})).collect()),
            );
            if !system.is_empty() {
                body.insert("system".into(), json!(system));
            }
            if bedrock {
                let model_id = model("anthropic.claude-3-5-sonnet-20241022-v2:0");
                signing = Some(model_id.clone());
                (base("https://bedrock-runtime.us-east-1.amazonaws.com"), format!("/model/{model_id}/invoke"), Value::Object(body))
            } else {
                headers.push(("anthropic-version".into(), "2023-06-01".into()));
                if let Some(key) = &backend.api_key {
                    headers.push(("x-api-key".into(), key.clone()));
                }
                (base("https://api.anthropic.com"), "/v1/messages".to_string(), Value::Object(body))
            }
        }
        "GEMINI" => {
            let (system, rest) = split_system();
            let mut body = Map::new();
            body.insert(
                "contents".into(),
                Value::Array(rest.iter().map(|m| json!({"role": if m.role == Role::Assistant { "model" } else { "user" }, "parts": [{"text": m.text}]})).collect()),
            );
            if !system.is_empty() {
                body.insert("systemInstruction".into(), json!({"parts": [{"text": system}]}));
            }
            body.insert("generationConfig".into(), json!({"temperature": 0}));
            if let Some(key) = &backend.api_key {
                query.push(("key".into(), key.clone()));
            }
            (base("https://generativelanguage.googleapis.com"), format!("/v1beta/models/{}:generateContent", model("gemini-1.5-flash")), Value::Object(body))
        }
        "OLLAMA" => {
            let body = json!({"model": model("llama3"), "stream": false, "messages": role_content("system"), "options": {"temperature": 0, "seed": 0}});
            (base("http://localhost:11434"), "/api/chat".to_string(), body)
        }
        "OPENAI_RESPONSES" => {
            if let Some(key) = &backend.api_key {
                headers.push(("Authorization".into(), format!("Bearer {key}")));
            }
            (base("https://api.openai.com"), "/v1/responses".to_string(), json!({"model": model("gpt-4o-mini"), "temperature": 0, "input": role_content("system")}))
        }
        "AZURE_OPENAI" => {
            query.push(("api-version".into(), "2024-02-15-preview".into()));
            if let Some(key) = &backend.api_key {
                headers.push(("api-key".into(), key.clone()));
            }
            let path = format!("/openai/deployments/{}/chat/completions", model("gpt-4o-mini"));
            (backend.base_url.clone().unwrap_or_default(), path, json!({"temperature": 0, "seed": 0, "messages": role_content("system")}))
        }
        _ => {
            let default = match provider {
                "MISTRAL" => "https://api.mistral.ai",
                "XAI" => "https://api.x.ai",
                "DEEPSEEK" => "https://api.deepseek.com",
                "GROQ" => "https://api.groq.com/openai",
                "OPENROUTER" => "https://openrouter.ai/api",
                "ORCAROUTER" => "https://api.orcarouter.ai",
                _ => "https://api.openai.com",
            };
            if let Some(key) = &backend.api_key {
                headers.push(("Authorization".into(), format!("Bearer {key}")));
            }
            (base(default), "/v1/chat/completions".to_string(), json!({"model": model("gpt-4o-mini"), "temperature": 0, "seed": 0, "messages": role_content("system")}))
        }
    };
    // `postJson`: `URI.create(baseUrl)`'s host, port, scheme and raw path. A base URL that does not parse (or names
    // no host) fails the request, which the drift detector reports as could-not-check.
    let parts = crate::import::url_parts(&base_url).filter(|p| p.host.as_deref().is_some_and(|h| !h.is_empty())).ok_or_else(|| format!("invalid LLM backend baseUrl: {base_url}"))?;
    let secure = parts.scheme.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("https"));
    let host = parts.host.unwrap_or_default();
    let port = if parts.port == -1 { if secure { 443 } else { 80 } } else { u16::try_from(parts.port).map_err(|_| format!("port out of range:{}", parts.port))? };
    let raw_path = parts.raw_path.unwrap_or_default();
    let base_path = raw_path.as_str();
    let base_path = if base_path.ends_with('/') && path.starts_with('/') { &base_path[..base_path.len() - 1] } else { base_path };
    let mut all_headers = Map::new();
    let host_header = if port == if secure { 443 } else { 80 } { host.clone() } else { format!("{host}:{port}") };
    all_headers.insert("Host".into(), json!([host_header]));
    all_headers.insert("Content-Type".into(), json!(["application/json"]));
    for (k, v) in backend.headers.iter().chain(headers.iter()) {
        if let Some(a) = all_headers.entry(k.clone()).or_insert_with(|| json!([])).as_array_mut() { a.push(json!(v)) }
    }
    let body = body.to_string();
    // `BedrockLlmClient`: the signature headers replace any of the same name.
    if let (Some(model_id), Some(creds)) = (signing, backend.api_key.as_deref().and_then(aws_credentials)) {
        let canonical_uri = format!("/model/{}/invoke", super::sigv4::uri_encode_path_segment(&model_id));
        let signed = super::sigv4::sign("POST", &host, &canonical_uri, "", body.as_bytes(), &bedrock_region(&host), "bedrock", creds.0, creds.1, creds.2, now, &[("content-type", "application/json")]);
        for (name, value) in signed {
            all_headers.retain(|k, _| !k.eq_ignore_ascii_case(&name));
            all_headers.insert(name, json!([value]));
        }
    }
    let mut request = Map::new();
    request.insert("method".into(), json!("POST"));
    request.insert("path".into(), json!(format!("{base_path}{path}")));
    if !query.is_empty() {
        let q: Map<String, Value> = query.into_iter().map(|(k, v)| (k, json!([v]))).collect();
        request.insert("queryStringParameters".into(), Value::Object(q));
    }
    request.insert("headers".into(), Value::Object(all_headers));
    request.insert("secure".into(), json!(secure));
    request.insert("socketAddress".into(), json!({"host": host, "port": port, "scheme": if secure { "HTTPS" } else { "HTTP" }}));
    request.insert("body".into(), json!(body));
    Ok(Value::Object(request))
}

/// `BedrockLlmClient.parseAwsCredentials`: `accessKeyId:secretAccessKey[:sessionToken]`, else no signing.
pub fn aws_credentials(api_key: &str) -> Option<(&str, &str, Option<&str>)> {
    if api_key.trim().is_empty() {
        return None;
    }
    let (id, rest) = api_key.split_once(':')?;
    Some(match rest.split_once(':') {
        Some((secret, token)) => (id, secret, Some(token)),
        None => (id, rest, None),
    })
}

/// `BedrockLlmClient.parseRegion`: the region of a `bedrock-runtime.<region>.amazonaws.com` host, else `us-east-1`.
pub fn bedrock_region(host: &str) -> String {
    host.strip_prefix("bedrock-runtime.")
        .and_then(|r| r.strip_suffix(".amazonaws.com"))
        .filter(|r| !r.is_empty() && r.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'))
        .unwrap_or("us-east-1")
        .to_string()
}


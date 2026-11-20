//! `LlmPromptRedactor`: credentials taken out of text bound for an external LLM backend (here the semantic drift
//! prompt). Always on, whatever `redactSecretsInLog` says, and it works on copies: the served request, the event log
//! and the stored records are never changed. A JSON-looking body is parsed, every credential-named field masked at any
//! depth (and inside stringified JSON or `key=value` text in string leaves), and written back compactly; other text
//! gets its `key=value` credentials masked; JWTs and URL userinfo are masked everywhere.

use std::sync::LazyLock;

use serde_json::Value;

/// `FixtureRedactor.REDACTED_PLACEHOLDER`.
pub const REDACTED: &str = "***REDACTED***";
/// `BODY_OMITTED_UNPARSEABLE`.
const BODY_OMITTED_UNPARSEABLE: &str = "[body omitted: could not be parsed for redaction]";

/// `ImportRedaction.DEFAULT_SENSITIVE_BODY_FIELDS` plus `id_token`, `idToken` and `code_verifier`, compared ignoring
/// case.
const SENSITIVE_FIELDS: &[&str] = &[
    "api_key", "apiKey", "apikey", "access_token", "accessToken", "refresh_token", "refreshToken", "client_secret", "clientSecret", "password", "passwd",
    "pwd", "secret", "token", "authorization", "id_token", "idToken", "code_verifier",
];

/// `FixtureRedactor.defaultSensitiveHeaders()` plus `EXTRA_SENSITIVE_HEADERS`, compared ignoring case; the configured
/// `dataPlaneApiKeyAuthenticationHeader` is added by the caller.
const SENSITIVE_HEADERS: &[&str] = &[
    "Authorization", "x-api-key", "api-key", "Cookie", "Set-Cookie", "Proxy-Authorization", "X-Auth-Token", "X-Access-Token", "X-Amz-Security-Token", "X-Csrf-Token",
];

/// `OAUTH_SIGNAL_PARAMETERS`: an OAuth authorization code is sent as `code`, a name too common to mask on its own
/// (`?code=GB`), so it is masked only beside one of these, `grant_type=authorization_code`, or an OAuth path.
const OAUTH_SIGNAL_PARAMETERS: &[&str] = &["state", "session_state", "redirect_uri", "client_id", "code_verifier", "iss"];
const OAUTH_PATH_SEGMENT: &str = r"/[^/?#;\s]*(?:callback|oauth|oidc|authori[sz]e)";

static OAUTH_TEXT_SIGNAL: LazyLock<fancy_regex::Regex> = LazyLock::new(|| {
    fancy_regex::Regex::new(&format!(r"(?i)(?<![A-Za-z0-9_-])(?:(?:{})\s*=|grant_type\s*=\s*authorization_code\b)|{OAUTH_PATH_SEGMENT}", OAUTH_SIGNAL_PARAMETERS.join("|")))
        .expect("OAuth text signal")
});
/// `OAUTH_CODE_PAIR`: `code` starting the text or after a separator, so `error_code=` is not matched.
static OAUTH_CODE_PAIR: LazyLock<fancy_regex::Regex> = LazyLock::new(|| fancy_regex::Regex::new(r"(?i)(?<![^?&;#\s])(code\s*=\s*)([^&#\s]+)").expect("OAuth code pair"));

fn sensitive(field: &str) -> bool {
    SENSITIVE_FIELDS.iter().any(|f| f.eq_ignore_ascii_case(field))
}

static JWT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*").expect("JWT pattern"));
static URL_USERINFO: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?i)([a-z][a-z0-9+.-]*://)([^/?#\s@]+)@").expect("userinfo pattern"));
/// `compileKeyValuePattern`: a credential-named key (not preceded by a letter or digit, a whole word) and its value.
static KEY_VALUE: LazyLock<fancy_regex::Regex> = LazyLock::new(|| {
    let alternation: Vec<String> = SENSITIVE_FIELDS.iter().map(|f| fancy_regex::escape(f).into_owned()).collect();
    fancy_regex::Regex::new(&format!(r"(?i)(?<![A-Za-z0-9])((?:{})\b\s*=\s*)([^&\s]+)", alternation.join("|"))).expect("key=value pattern")
});

fn mask_key_value(value: &str) -> String {
    KEY_VALUE.replace_all(value, format!("${{1}}{REDACTED}").as_str()).into_owned()
}

/// `maskOAuthCode`: each `code=` value masked when the text, or the request it came from (`oauth_context`), carries
/// an OAuth signal.
fn mask_oauth_code(value: &str, oauth_context: bool) -> String {
    if !OAUTH_CODE_PAIR.is_match(value).unwrap_or(false) || !(oauth_context || OAUTH_TEXT_SIGNAL.is_match(value).unwrap_or(false)) {
        return value.to_string();
    }
    OAUTH_CODE_PAIR.replace_all(value, format!("${{1}}{REDACTED}").as_str()).into_owned()
}

/// `maskFreeText`: `key=value` credentials, OAuth codes beside an OAuth signal, JWTs and URL userinfo.
fn mask_free_text(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    finish_text(&mask_oauth_code(&mask_key_value(value), false))
}

/// `maskPath`: a request or expectation path with its URL userinfo, JWTs (a magic-link token) and `key=value`
/// credentials (a `;token=` matrix parameter) masked.
pub fn mask_path(path: &str) -> String {
    mask_free_text(path)
}

fn mask_jwts(value: &str) -> String {
    JWT.replace_all(value, REDACTED).into_owned()
}

/// `maskUrlUserInfo`.
fn mask_url_userinfo(value: &str) -> String {
    URL_USERINFO.replace_all(value, |c: &regex::Captures| format!("{}{REDACTED}@", &c[1])).into_owned()
}

fn finish_text(value: &str) -> String {
    mask_url_userinfo(&mask_jwts(value))
}

/// `readTree`: a JSON object or array, else `None`.
fn parse_tree(text: &str) -> Result<Value, ()> {
    crate::json::parse_lenient(text.as_bytes()).map_err(|_| ())
}

/// `redactJsonTree`: credential-named fields masked whole (and `code` beside an OAuth signal field, or in an OAuth
/// request), string leaves through [`redact_string_leaf`].
fn redact_tree(node: &mut Value, oauth_context: bool) {
    match node {
        Value::Object(o) => {
            let oauth_object = oauth_context || has_oauth_signal_field(o);
            for (name, child) in o.iter_mut() {
                if sensitive(name) || (oauth_object && name.eq_ignore_ascii_case("code")) {
                    *child = Value::String(REDACTED.into());
                } else if let Value::String(text) = child {
                    *child = Value::String(redact_string_leaf(text, oauth_context));
                } else {
                    redact_tree(child, oauth_context);
                }
            }
        }
        Value::Array(items) => {
            for child in items {
                if let Value::String(text) = child {
                    *child = Value::String(redact_string_leaf(text, oauth_context));
                } else {
                    redact_tree(child, oauth_context);
                }
            }
        }
        _ => {}
    }
}

/// `hasOAuthSignalField`: an OAuth signal parameter, or `grant_type` of `authorization_code` (`asText`).
fn has_oauth_signal_field(object: &serde_json::Map<String, Value>) -> bool {
    object.iter().any(|(name, value)| {
        OAUTH_SIGNAL_PARAMETERS.iter().any(|p| p.eq_ignore_ascii_case(name))
            || (name.eq_ignore_ascii_case("grant_type") && value.as_str().is_some_and(|v| v.eq_ignore_ascii_case("authorization_code")))
    })
}

/// `redactStringLeaf`: stringified JSON redacted as JSON, other text by its `key=value` pairs, OAuth codes and JWTs.
fn redact_string_leaf(value: &str, oauth_context: bool) -> String {
    let trimmed = value.trim();
    if (trimmed.starts_with('{') || trimmed.starts_with('[')) && let Ok(mut nested) = parse_tree(value) && (nested.is_object() || nested.is_array()) {
        redact_tree(&mut nested, oauth_context);
        return nested.to_string();
    }
    mask_jwts(&mask_oauth_code(&mask_key_value(value), oauth_context))
}

/// `redactText` (`redactBodyForDrift`): a free-text body redacted; a JSON-looking one that does not parse is omitted
/// (fail closed).
pub fn redact_text(body: &str) -> String {
    redact_body_text(body, false, false)
}

/// `redactBodyText`: a body declared JSON or looking like JSON is parsed and its fields redacted, else its text.
pub fn redact_body_text(body: &str, declared_json: bool, oauth_context: bool) -> String {
    let trimmed = body.trim();
    if declared_json || trimmed.starts_with('{') || trimmed.starts_with('[') {
        match parse_tree(body) {
            Ok(mut root) if root.is_object() || root.is_array() => {
                redact_tree(&mut root, oauth_context);
                return finish_text(&root.to_string());
            }
            Ok(_) => {}
            Err(()) => return BODY_OMITTED_UNPARSEABLE.into(),
        }
    }
    finish_text(&mask_oauth_code(&mask_key_value(body), oauth_context))
}

/// The redactor's header set: a default sensitive header, or the configured data-plane API-key header.
pub fn sensitive_header(name: &str, data_plane_header: Option<&str>) -> bool {
    SENSITIVE_HEADERS.iter().any(|h| h.eq_ignore_ascii_case(name)) || data_plane_header.is_some_and(|h| !h.trim().is_empty() && h.eq_ignore_ascii_case(name))
}

/// `FixtureRedactor.defaultSensitiveQueryParams()`.
const SENSITIVE_QUERY_PARAMETERS: &[&str] = &["key", "api_key", "apikey", "access_token", "token", "signature", "x-amz-signature", "x-amz-security-token", "sig"];

/// The redactor's query set: the query defaults plus the body-field set.
pub fn sensitive_query_parameter(name: &str) -> bool {
    SENSITIVE_QUERY_PARAMETERS.iter().any(|q| q.eq_ignore_ascii_case(name)) || sensitive(name)
}

/// `maskValues`' text: a header or query value with its `key=value` credentials, OAuth codes beside an OAuth signal,
/// JWTs and URL userinfo masked.
pub fn mask_value(value: &str) -> String {
    mask_free_text(value)
}

/// `isOAuthRequest`: the path names a callback, oauth, oidc or authorize endpoint, or the query carries an OAuth
/// signal parameter or `grant_type=authorization_code`.
pub fn oauth_request<'a>(path: &str, query: impl IntoIterator<Item = (&'a str, &'a [String])>) -> bool {
    static OAUTH_PATH: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(&format!("(?i){OAUTH_PATH_SEGMENT}")).expect("OAuth path"));
    OAUTH_PATH.is_match(path)
        || query.into_iter().any(|(name, values)| {
            OAUTH_SIGNAL_PARAMETERS.iter().any(|p| p.eq_ignore_ascii_case(name))
                || (name.eq_ignore_ascii_case("grant_type") && values.iter().any(|v| v.eq_ignore_ascii_case("authorization_code")))
        })
}

/// `maskDriftValue`: a value under a credential-named body field or a sensitive response header (`header.<name>`,
/// the default set plus the configured `data_plane_header`) masked whole; any other with its `key=value`
/// credentials, OAuth codes beside an OAuth signal, JWTs and URL userinfo masked.
pub fn mask_drift_value(field: &str, value: &str, data_plane_header: Option<&str>) -> String {
    let sensitive_header = field.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("header.")) && {
        let name = &field[7..];
        SENSITIVE_HEADERS.iter().any(|h| h.eq_ignore_ascii_case(name)) || data_plane_header.is_some_and(|h| !h.trim().is_empty() && h.eq_ignore_ascii_case(name))
    };
    if sensitive(field) || sensitive_header {
        return REDACTED.into();
    }
    mask_free_text(value)
}

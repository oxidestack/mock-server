//! `CredentialRedaction` (upstream 29a26d650, 9.2.0): a control-plane request is logged without its credentials,
//! whatever `redactSecretsInLog` says. Every log entry that attaches one, or takes one as an argument, holds a copy
//! whose credential headers (`authorization`, `proxy-authorization`, `cookie`, `x-api-key`, `api-key`) carry the
//! redaction mask and whose cookies are dropped; its received entry (`REQUESTS`, verification) is that copy too.
//! Data-plane requests are logged as sent. The diagnostic of a cut-short request is always masked
//! (`NettyMessageForLog.request`), since whether a half-received request was meant for the control plane cannot be
//! relied on.

use serde_json::Value;

use crate::recorded::LOG_REDACTED;
use crate::request::HttpRequest;

/// `CredentialRedaction.CREDENTIAL_HEADERS`, compared case-insensitively.
const CREDENTIAL_HEADERS: &[&str] = &["authorization", "proxy-authorization", "cookie", "x-api-key", "api-key"];

fn is_credential_header(name: &str) -> bool {
    CREDENTIAL_HEADERS.iter().any(|h| h.eq_ignore_ascii_case(name))
}

/// Whether the request is one the control-plane gate marks (`HttpState.isControlPlaneRequest` on a path candidate)
/// or whose method and path name a control-plane route (`CredentialRedaction.isControlPlane`). The configured
/// liveness path is marked only when a TRACE entry logs it, so it is left out.
fn is_control_plane(method: Option<&str>, path: &str, preflight_method: Option<&str>) -> bool {
    if crate::cors_origin::is_control_plane_route(method, path) {
        return true;
    }
    preflight_method.is_some() && crate::cors_origin::is_control_plane_path_candidate(path) && crate::cors_origin::is_control_plane_route(preflight_method, path)
}

/// `CredentialRedaction.forLog` for a received request: the copy a log entry may hold when it is a control-plane
/// request carrying credentials, else `None` (the request is logged as it is).
pub fn for_log(request: &HttpRequest) -> Option<HttpRequest> {
    let preflight = crate::cors_origin::is_cors_preflight(request).then(|| request.first_header("access-control-request-method")).flatten();
    if !is_control_plane(Some(&request.method), &request.path, preflight) {
        return None;
    }
    without_credentials(request)
}

/// `CredentialRedaction.withoutCredentials`: `None` when the request carries no credentials to mask. Each credential
/// header keeps its place with the mask as its one value (the oracle's order, scenario
/// `control_plane_credentials_masked`) and the cookies are dropped.
pub fn without_credentials(request: &HttpRequest) -> Option<HttpRequest> {
    let has = !request.cookies.is_empty() || request.headers.iter().any(|(name, values)| is_credential_header(name) && values.iter().any(|v| v != LOG_REDACTED));
    if !has {
        return None;
    }
    let mut copy = request.clone();
    let mut seen: Vec<String> = Vec::new();
    copy.headers.retain_mut(|(name, values)| {
        if !is_credential_header(name) {
            return true;
        }
        let lower = name.to_ascii_lowercase();
        if seen.contains(&lower) {
            return false;
        }
        seen.push(lower);
        *values = vec![LOG_REDACTED.to_string()];
        true
    });
    copy.cookies.clear();
    Some(copy)
}

/// The credential values [`without_credentials`] masks in `request` (`maskedCredentialValues`), kept so
/// `redactSecretsInLog` can still scrub them from an entry's other text.
pub fn masked_values(request: &HttpRequest) -> Vec<String> {
    let mut values: Vec<String> = request.headers.iter().filter(|(name, _)| is_credential_header(name)).flat_map(|(_, vs)| vs.iter().cloned()).collect();
    values.extend(request.cookies.iter().map(|(_, v)| v.clone()));
    values.retain(|v| v != LOG_REDACTED);
    values
}

/// [`for_log`] on a request as log entries hold it (its logged JSON, or a request definition): the masked copy and the
/// values it masked, or `None` when it is no control-plane request with credentials.
pub fn json_for_log(request: &Value) -> Option<(Value, Vec<String>)> {
    let o = request.as_object()?;
    let path = o.get("path")?.as_str()?;
    let method = o.get("method").and_then(Value::as_str);
    let header = |wanted: &str| header_values(o.get("headers")).into_iter().find(|(name, _)| name.eq_ignore_ascii_case(wanted)).and_then(|(_, vs)| vs.into_iter().next());
    let preflight = (method == Some("OPTIONS") && header("origin").is_some()).then(|| header("access-control-request-method")).flatten();
    if !is_control_plane(method, path, preflight.as_deref()) {
        return None;
    }
    json_without_credentials(request)
}

/// [`without_credentials`] on a request's JSON.
pub fn json_without_credentials(request: &Value) -> Option<(Value, Vec<String>)> {
    let o = request.as_object()?;
    let headers = header_values(o.get("headers"));
    let cookies = cookie_values(o.get("cookies"));
    let has = !cookies.is_empty() || headers.iter().any(|(name, values)| is_credential_header(name) && values.iter().any(|v| v != LOG_REDACTED));
    if !has {
        return None;
    }
    let mut masked: Vec<String> = headers.iter().filter(|(name, _)| is_credential_header(name)).flat_map(|(_, vs)| vs.iter().cloned()).collect();
    masked.extend(cookies);
    masked.retain(|v| v != LOG_REDACTED);
    let mut copy = o.clone();
    let mask = || Value::Array(vec![Value::String(LOG_REDACTED.to_string())]);
    let mut seen: Vec<String> = Vec::new();
    let mut first = |name: &str| {
        let lower = name.to_ascii_lowercase();
        let new = !seen.contains(&lower);
        seen.push(lower);
        new
    };
    match copy.get_mut("headers") {
        Some(Value::Object(map)) => {
            let old = std::mem::take(map);
            for (name, values) in old {
                if !is_credential_header(&name) {
                    map.insert(name, values);
                } else if first(&name) {
                    map.insert(name, mask());
                }
            }
        }
        Some(Value::Array(items)) => items.retain_mut(|item| {
            let Some(name) = item.get("name").and_then(Value::as_str).filter(|n| is_credential_header(n)).map(str::to_string) else { return true };
            if !first(&name) {
                return false;
            }
            if let Some(o) = item.as_object_mut() {
                o.insert("values".into(), mask());
            }
            true
        }),
        _ => {}
    }
    copy.shift_remove("cookies");
    Some((Value::Object(copy), masked))
}

/// A headers field in either JSON form (`{"name": ["v", …]}` or `[{"name": …, "values": […]}]`) as names and values.
fn header_values(headers: Option<&Value>) -> Vec<(String, Vec<String>)> {
    let text = |v: &Value| v.as_str().map(str::to_string).unwrap_or_else(|| v.get("value").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| v.to_string()));
    let values = |v: &Value| match v {
        Value::Array(vs) => vs.iter().map(text).collect(),
        other => vec![text(other)],
    };
    match headers {
        Some(Value::Object(map)) => map.iter().map(|(k, v)| (k.clone(), values(v))).collect(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| Some((item.get("name").map(text)?, item.get("values").map(values).unwrap_or_default())))
            .collect(),
        _ => Vec::new(),
    }
}

/// A cookies field in either JSON form as its values.
fn cookie_values(cookies: Option<&Value>) -> Vec<String> {
    let text = |v: &Value| v.as_str().map(str::to_string).unwrap_or_else(|| v.get("value").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| v.to_string()));
    match cookies {
        Some(Value::Object(map)) => map.values().map(text).collect(),
        Some(Value::Array(items)) => items.iter().filter_map(|item| item.get("value").map(text)).collect(),
        _ => Vec::new(),
    }
}

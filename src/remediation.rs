//! `MismatchRemediation`: advice for the differences that stopped a request matching an expectation.

/// `MismatchRemediation.hint`: one line of advice for a field's differences (by `MatchDifference.Field` name).
pub fn hint(field: &str, differences: &[String]) -> String {
    if differences.is_empty() {
        return String::new();
    }
    let combined = differences.join(" ");
    // compiled once: a hint is built for every closest-match explanation, on the server's workers
    static EXPECTED_BUT_WAS: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r#"(?im)expected\s+['"]?([^'"]+?)['"]?\s+but\s+was\s+['"]?([^'"]+?)['"]?\s*$"#).expect("pattern"));
    static MISSING: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r#"(?i)(?:request|multimap)\s+(?:did not contain|does not contain|has no entry for).*?"([^"]+)""#).expect("pattern"));
    let (expected_but_was, missing) = (&*EXPECTED_BUT_WAS, &*MISSING);
    let case_mismatch = |what: &str| {
        expected_but_was.captures(&combined).and_then(|m| {
            let (e, a) = (m[1].trim().to_string(), m[2].trim().to_string());
            (e.eq_ignore_ascii_case(&a) && e != a).then(|| format!("{what} name case mismatch: send {e} not {a}"))
        })
    };
    let lower = combined.to_lowercase();
    match field {
        "method" => match expected_but_was.captures(&combined) {
            Some(m) => format!("use method {} not {}", m[1].trim().to_uppercase(), m[2].trim().to_uppercase()),
            None => ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
                .iter()
                .find(|m| combined.to_uppercase().contains(*m))
                .map_or_else(|| "check the HTTP method".into(), |m| format!("check the HTTP method (expected {m})")),
        },
        "path" => match expected_but_was.captures(&combined) {
            Some(m) => {
                let (e, a) = (m[1].trim(), m[2].trim());
                if e.trim_end_matches('/') == a.trim_end_matches('/') && e != a && (e.len() - e.trim_end_matches('/').len() <= 1) && (a.len() - a.trim_end_matches('/').len() <= 1) {
                    if e.ends_with('/') { format!("add trailing slash: send {e} not {a}") } else { format!("remove trailing slash: send {e} not {a}") }
                } else {
                    format!("use path {e} not {a}")
                }
            }
            None => "check the request path".into(),
        },
        "headers" => case_mismatch("header")
            .or_else(|| missing.captures(&combined).map(|m| format!("add missing header {}", &m[1])))
            .unwrap_or_else(|| if lower.contains("content-type") || lower.contains("content_type") { "check the Content-Type header value".into() } else { "check request headers".into() }),
        "queryParameters" => case_mismatch("query parameter").or_else(|| missing.captures(&combined).map(|m| format!("add missing query parameter {}", &m[1]))).unwrap_or_else(|| "check query string parameters".into()),
        "cookies" => case_mismatch("cookie").or_else(|| missing.captures(&combined).map(|m| format!("add missing cookie {}", &m[1]))).unwrap_or_else(|| "check request cookies".into()),
        "body" => {
            if lower.contains("json") && lower.contains("schema") {
                "request body does not match the expected JSON schema".into()
            } else if lower.contains("content-type") || lower.contains("content_type") {
                "check the Content-Type header and body format".into()
            } else {
                "check the request body content".into()
            }
        }
        "pathParameters" => "check path parameter values".into(),
        "secure" => "check whether the request uses HTTPS vs HTTP".into(),
        "protocol" => "check the protocol version".into(),
        "keep-alive" => "check the keep-alive setting".into(),
        "clientIp" => "check the client IP address: it is the connection's peer address, not X-Forwarded-For".into(),
        "operation" | "openapi" => "check the OpenAPI operation id".into(),
        _ => String::new(),
    }
}

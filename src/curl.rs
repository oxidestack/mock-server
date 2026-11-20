//! `HttpRequestToCurlSerializer`: a request as the `curl` command that would send it, for forwarded-request log lines.

use crate::request::HttpRequest;

/// `toCurl(request, remoteAddress)`: `remote` (`host:port`) stands in for a missing `Host` header.
pub fn to_curl(request: &HttpRequest, remote: Option<&str>) -> String {
    let host = request.first_header("host").filter(|h| !h.trim().is_empty()).map(str::to_string).or_else(|| remote.map(str::to_string));
    let Some(host) = host else {
        return "no host header or remote address specified".into();
    };
    let mut curl = format!("curl -v '{}://{host}{}'", if request.secure { "https" } else { "http" }, uri(request));
    if !(request.method.trim().is_empty() || request.method.eq_ignore_ascii_case("GET")) {
        curl.push_str(&format!(" -X {}", request.method));
    }
    for (name, values) in &request.headers {
        for value in values {
            curl.push_str(&format!(" -H {}", single_quote(&format!("{name}: {value}"))));
            let lower = value.to_lowercase();
            if name.to_lowercase().contains("accept-encoding") && ["gzip", "deflate", "sdch"].iter().any(|e| lower.contains(e)) {
                curl.push_str(" --compress");
            }
        }
    }
    if !request.cookies.is_empty() {
        // `ClientCookieEncoder.LAX`
        let encoded = request.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
        curl.push_str(&format!(" -H {}", single_quote(&format!("cookie: {encoded}"))));
    }
    let body = request.body_str();
    if !body.trim().is_empty() {
        curl.push_str(&format!(" --data {}", single_quote(&body)));
    }
    curl
}

fn uri(request: &HttpRequest) -> String {
    let uri = crate::request::uri(request);
    if uri.trim().is_empty() {
        "/".into()
    } else if uri.starts_with('/') {
        uri
    } else {
        format!("/{uri}")
    }
}

/// POSIX single quoting: each embedded `'` becomes `'\''`.
fn single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::single_quote;

    #[test]
    fn single_quotes_escape_embedded_quotes() {
        assert_eq!(single_quote("it's"), "'it'\\''s'");
    }
}

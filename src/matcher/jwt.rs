//! `JwtMatcher`: an expectation's `jwt` criteria against the JSON Web Token a request carries in a header. The token
//! is only decoded (base64url + JSON), never verified, exactly as upstream: this is request routing, not auth.

use base64::Engine;
use serde_json::Value;

use super::{Difference, StringMatcher, format_log_message};

const DEFAULT_HEADER: &str = "authorization";
const DEFAULT_SCHEME: &str = "Bearer";

#[derive(Debug)]
pub struct JwtMatcher {
    /// `Jwt.header` as given (`null` or blank reads as `authorization`).
    header: Option<String>,
    /// `Jwt.scheme`: `Bearer` when absent; `null` or blank means the header value is the raw token.
    scheme: Option<String>,
    /// Claim criteria in `HashMap<String, RegexStringMatcher>` iteration order (upstream copies them into one).
    claims: Vec<(String, StringMatcher)>,
    issuer: Option<StringMatcher>,
    audience: Option<StringMatcher>,
    algorithm: Option<StringMatcher>,
}

impl JwtMatcher {
    /// From the `jwt` object of a request matcher (`JwtDeserializer`); `None` for anything else (upstream reads a
    /// non-object as `null`, which matches every request).
    pub fn compile(v: &Value) -> Option<JwtMatcher> {
        let o = v.as_object()?;
        let text = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_string);
        let nottable = |k: &str| o.get(k).filter(|v| !v.is_null()).map(StringMatcher::compile);
        let mut claims: Vec<(String, StringMatcher)> = Vec::new();
        if let Some(Value::Object(map)) = o.get("claims") {
            for (name, value) in map {
                if !value.is_null() {
                    claims.push((name.clone(), StringMatcher::compile(value)));
                }
            }
        }
        let keys: Vec<String> = claims.iter().map(|(k, _)| k.clone()).collect();
        let mut slots: Vec<Option<(String, StringMatcher)>> = claims.into_iter().map(Some).collect();
        let claims = crate::recorded::java_hashmap_order(&keys).into_iter().filter_map(|i| slots[i].take()).collect();
        Some(JwtMatcher {
            header: text("header"),
            scheme: if o.contains_key("scheme") { text("scheme") } else { Some(DEFAULT_SCHEME.to_string()) },
            claims,
            issuer: nottable("issuer"),
            audience: nottable("audience"),
            algorithm: nottable("algorithm"),
        })
    }

    /// `getHeaderName`: the request header the token is read from.
    pub fn header_name(&self) -> &str {
        self.header.as_deref().filter(|h| !h.trim().is_empty()).unwrap_or(DEFAULT_HEADER)
    }

    pub fn is_blank(&self) -> bool {
        self.claims.iter().all(|(_, m)| m.is_blank())
            && [&self.issuer, &self.audience, &self.algorithm].iter().all(|m| m.as_ref().is_none_or(StringMatcher::is_blank))
    }

    /// `matches(context, headerValue)`: `None` when the token satisfies every criterion, else the one difference
    /// upstream records (it stops at the first failing criterion).
    pub fn difference(&self, header_value: Option<&str>) -> Option<Difference> {
        if self.is_blank() {
            return None;
        }
        let header = self.header_name();
        let fail = |message: &str, arguments: &[&str]| Some(Difference::Text(format_log_message(1, message, arguments)));
        let Some(value) = header_value.filter(|v| !v.trim().is_empty()) else {
            return fail("jwt match failed - request presented no \"{}\" header carrying a token", &[header]);
        };
        let token = self.strip_scheme(java_trim(value));
        let segments = java_split_dot(token);
        if segments.len() < 2 {
            return fail("jwt match failed - value of header \"{}\" is not a well-formed JWT", &[header]);
        }
        let jose_header = decode_segment(segments[0]);
        let Some(payload) = decode_segment(segments[1]) else {
            return fail("jwt match failed - token payload could not be base64url/JSON decoded", &[]);
        };
        if let Some(algorithm) = self.algorithm.as_ref().filter(|m| !m.is_blank()) {
            let alg = jose_header.as_ref().and_then(|h| h.get("alg")).filter(|a| !a.is_null()).map(jackson::JsonNode::as_text);
            let candidates: Vec<String> = alg.iter().cloned().collect();
            if !matches_across_candidates(algorithm, &candidates) {
                return fail("jwt algorithm match failed expected:{}found:{}", &[&algorithm.printed(), alg.as_deref().unwrap_or("null")]);
            }
        }
        if let Some(issuer) = self.issuer.as_ref().filter(|m| !m.is_blank()) {
            let candidates = claim_values(&payload, "iss");
            if !matches_across_candidates(issuer, &candidates) {
                return fail("jwt issuer match failed expected:{}found:{}", &[&issuer.printed(), &java_list(&candidates)]);
            }
        }
        if let Some(audience) = self.audience.as_ref().filter(|m| !m.is_blank()) {
            let candidates = claim_values(&payload, "aud");
            if !matches_across_candidates(audience, &candidates) {
                return fail("jwt audience match failed expected:{}found:{}", &[&audience.printed(), &java_list(&candidates)]);
            }
        }
        for (name, claim) in self.claims.iter().filter(|(_, m)| !m.is_blank()) {
            let candidates = claim_values(&payload, name);
            if !matches_across_candidates(claim, &candidates) {
                let message = format!("jwt claim \"{name}\" match failed expected:{{}}found:{{}}");
                return fail(&message, &[&claim.printed(), &java_list(&candidates)]);
            }
        }
        None
    }

    /// `stripScheme`: drops a leading `<scheme> ` (case-insensitive) when a scheme is set.
    fn strip_scheme<'a>(&self, value: &'a str) -> &'a str {
        let Some(scheme) = self.scheme.as_deref().filter(|s| !s.trim().is_empty()) else { return value };
        let prefix = format!("{} ", java_trim(scheme));
        match value.get(..prefix.len()) {
            Some(head) if head.eq_ignore_ascii_case(&prefix) => java_trim(&value[prefix.len()..]),
            _ => value,
        }
    }
}

/// `matchesAcrossCandidates`: a positive criterion matches when any candidate matches; a negated one only when it
/// holds for every candidate. No candidates: only a negation matches. The matcher applies the negation itself
/// (`RegexStringMatcher`, case-insensitive).
pub(super) fn matches_across_candidates(matcher: &StringMatcher, candidates: &[String]) -> bool {
    if candidates.is_empty() {
        return matcher.not;
    }
    if matcher.not {
        candidates.iter().all(|c| matcher.matches(c, true))
    } else {
        candidates.iter().any(|c| matcher.matches(c, true))
    }
}

/// `List.toString()`.
pub(super) fn java_list(values: &[String]) -> String {
    format!("[{}]", values.join(", "))
}

/// `String.trim()`: strips every leading and trailing char up to U+0020.
fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

/// `token.split("\\.")`: trailing empty segments are dropped.
fn java_split_dot(token: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = token.split('.').collect();
    while parts.last() == Some(&"") {
        parts.pop();
    }
    parts
}

/// `decodeSegment`: `Base64.getUrlDecoder()` over the segment padded by `padBase64Url`, then `readTree` of its
/// UTF-8 text; `None` on any failure.
fn decode_segment(segment: &str) -> Option<jackson::JsonNode> {
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    const URL: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::RequireCanonical).with_decode_allow_trailing_bits(true),
    );
    let padded = match segment.len() % 4 {
        0 => segment.to_string(),
        remainder => format!("{segment}{}", &"===="[remainder..]),
    };
    let bytes = URL.decode(padded).ok()?;
    crate::jnode::read_tree(&String::from_utf8_lossy(&bytes)).ok()
}

/// `claimValues`: an array claim's non-null elements, a scalar claim as one value, an absent or null claim as none
/// (`asText`, so a container reads as "").
fn claim_values(payload: &jackson::JsonNode, name: &str) -> Vec<String> {
    match payload.get(name) {
        None => Vec::new(),
        Some(node) if node.is_null() || node.is_missing() => Vec::new(),
        Some(node) => match node.as_array() {
            Some(elements) => elements.iter().filter(|e| !e.is_null()).map(jackson::JsonNode::as_text).collect(),
            None => vec![node.as_text()],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
    }

    fn token(header: &str, payload: &str) -> String {
        format!("Bearer {}.{}.signature-not-verified", b64(header), b64(payload))
    }

    fn reason(m: &JwtMatcher, value: Option<&str>) -> Option<String> {
        m.difference(value).map(|d| d.hint_reason())
    }

    fn matcher(v: Value) -> JwtMatcher {
        JwtMatcher::compile(&v).expect("an object")
    }

    #[test]
    fn blank_criteria_match_every_request() {
        assert!(matcher(json!({})).difference(None).is_none());
        assert!(matcher(json!({"claims": {"sub": ""}})).difference(None).is_none());
    }

    #[test]
    fn absent_header_and_malformed_tokens() {
        let m = matcher(json!({"claims": {"sub": "user-1"}}));
        assert_eq!(reason(&m, None).unwrap(), "  jwt match failed - request presented no \"     authorization    \" header carrying a token");
        assert_eq!(reason(&m, Some("Bearer abc")).unwrap(), "  jwt match failed - value of header \"     authorization    \" is not a well-formed JWT");
        assert_eq!(reason(&m, Some("Bearer a.")).unwrap(), "  jwt match failed - value of header \"     authorization    \" is not a well-formed JWT");
        let not_json = format!("Bearer {}.{}.s", b64("{}"), b64("not json"));
        assert_eq!(reason(&m, Some(&not_json)).unwrap(), "  jwt match failed - token payload could not be base64url/JSON decoded");
        assert_eq!(reason(&m, Some("Bearer e30.!!!.s")).unwrap(), "  jwt match failed - token payload could not be base64url/JSON decoded");
    }

    #[test]
    fn header_and_scheme_are_configurable() {
        let m = matcher(json!({"header": "x-token", "scheme": "", "claims": {"sub": "user-1"}}));
        let raw = format!("{}.{}.s", b64("{}"), b64(r#"{"sub":"user-1"}"#));
        assert_eq!(m.header_name(), "x-token");
        assert!(m.difference(Some(&raw)).is_none());
        // The default scheme is stripped case-insensitively.
        let d = matcher(json!({"claims": {"sub": "user-1"}}));
        assert!(d.difference(Some(&format!("bearer {raw}"))).is_none());
    }

    #[test]
    fn algorithm_plain_and_negated() {
        let rs = token(r#"{"alg":"RS256"}"#, "{}");
        let hs = token(r#"{"alg":"HS256"}"#, "{}");
        let m = matcher(json!({"algorithm": "RS256"}));
        assert!(m.difference(Some(&rs)).is_none());
        assert_eq!(reason(&m, Some(&hs)).unwrap(), "  jwt algorithm match failed expected:     RS256    found:     HS256 ");
        let n = matcher(json!({"algorithm": "!RS256"}));
        assert!(n.difference(Some(&hs)).is_none());
        assert_eq!(reason(&n, Some(&rs)).unwrap(), "  jwt algorithm match failed expected:     !RS256    found:     RS256 ");
        assert_eq!(reason(&m, Some(&token("{}", "{}"))).unwrap(), "  jwt algorithm match failed expected:     RS256    found:     null ");
    }

    #[test]
    fn claims_regex_negation_and_absence() {
        let t = token("{}", r#"{"sub":"user-2","scope":"read","n":5}"#);
        assert_eq!(reason(&matcher(json!({"claims": {"sub": "user-1"}})), Some(&t)).unwrap(), "  jwt claim \"sub\" match failed expected:     user-1    found:     [user-2] ");
        assert!(matcher(json!({"claims": {"sub": "user-.*"}})).difference(Some(&t)).is_none());
        assert!(matcher(json!({"claims": {"n": "5"}})).difference(Some(&t)).is_none());
        assert_eq!(reason(&matcher(json!({"claims": {"sub": "!user-2"}})), Some(&t)).unwrap(), "  jwt claim \"sub\" match failed expected:     !user-2    found:     [user-2] ");
        assert_eq!(reason(&matcher(json!({"claims": {"missing": "x"}})), Some(&t)).unwrap(), "  jwt claim \"missing\" match failed expected:     x    found:     [] ");
        assert!(matcher(json!({"claims": {"missing": "!x"}})).difference(Some(&t)).is_none());
    }

    #[test]
    fn claims_are_checked_in_hashmap_order() {
        // Both fail; upstream's HashMap puts "sub" in bin 1 and "scope" in bin 7, whatever the input order.
        let t = token("{}", r#"{"sub":"a","scope":"b"}"#);
        let r = reason(&matcher(json!({"claims": {"scope": "y", "sub": "x"}})), Some(&t)).unwrap();
        assert!(r.contains("claim \"sub\""), "{r}");
    }

    #[test]
    fn audience_array_any_element() {
        let t = token("{}", r#"{"aud":["other-api","my-api"]}"#);
        assert!(matcher(json!({"audience": "my-api"})).difference(Some(&t)).is_none());
        assert_eq!(
            reason(&matcher(json!({"audience": "missing-api"})), Some(&t)).unwrap(),
            "  jwt audience match failed expected:     missing-api    found:     [other-api, my-api] "
        );
        // A negation must hold for every element.
        assert!(matcher(json!({"audience": "!my-api"})).difference(Some(&t)).is_some());
        assert!(matcher(json!({"audience": "!third"})).difference(Some(&t)).is_none());
    }

    #[test]
    fn issuer() {
        let t = token("{}", r#"{"iss":"https://issuer.example.com"}"#);
        assert!(matcher(json!({"issuer": "https://issuer.example.com"})).difference(Some(&t)).is_none());
        assert_eq!(
            reason(&matcher(json!({"issuer": "other"})), Some(&t)).unwrap(),
            "  jwt issuer match failed expected:     other    found:     [https://issuer.example.com] "
        );
    }
}

//! `CORSOriginPolicy` (9.1.0, upstream #220 and #226): which browser origins may use the control plane, its CORS
//! headers, the 403 refusal and the dashboard and callback WebSocket upgrades. Mocked and proxied responses are governed by
//! `corsAllowOrigin` instead (`Reply::add_cors_headers`).
//!
//! An http or https origin whose host and port match the request's `Host` is allowed only on a host DNS rebinding
//! cannot take over: `localhost`, an IP literal, a single-label name, a name under `.svc`, `.svc.cluster.local`,
//! `.internal` or one of the `controlPlaneTrustedHostSuffixes`. With `controlPlaneCorsAllowOrigin` blank a loopback
//! origin (any port) is also allowed; otherwise it is a comma-separated allow-list where `*` allows any origin.
//! `Origin: null` is never allowed by default.
//!
//! The public-suffix test is Guava's `InternetDomainName.isPublicSuffix` over the oracle's own list: `build.rs` compiles
//! the unmodified Public Suffix List (MPL-2.0) in `third_party/publicsuffix/` into Guava's `PublicSuffixPatterns.TRIE`
//! arrays (`trieData`, `stringPool`, UTF-16BE) with `public_suffix/generate.rs`, byte for byte the arrays of the
//! oracle's shaded Guava 33.7.2, so the list is the one the oracle consults (its licence and origin are credited in
//! `NOTICE`).

const BUILT_IN_TRUSTED_HOST_SUFFIXES: [&str; 3] = ["svc", "svc.cluster.local", "internal"];

/// `HttpState.CONTROL_PLANE_ORIGIN_REFUSED_MESSAGE`.
pub const REFUSED_MESSAGE: &str = "Forbidden for control plane - this browser origin is not allowed (see controlPlaneCorsAllowOrigin)";

/// `isControlPlaneOriginAllowed(configuration, origin, hostHeaders)`.
pub fn allowed_by_config(config: &crate::Config, origin: Option<&str>, host: Option<&str>) -> bool {
    let allow = config.property("controlPlaneCorsAllowOrigin");
    let suffixes = config.property("controlPlaneTrustedHostSuffixes");
    allowed(allow.as_deref(), suffixes.as_deref(), origin, host)
}

/// `isControlPlaneOriginAllowed(allowOrigin, trustedHostSuffixes, origin, hostHeader)`: a missing or empty `Origin`
/// is always allowed.
pub fn allowed(allow_origin: Option<&str>, trusted_suffixes: Option<&str>, origin: Option<&str>, host: Option<&str>) -> bool {
    let Some(origin) = origin.filter(|o| !o.is_empty()) else { return true };
    let web_origin = WebOrigin::parse(origin);
    if let Some(web) = &web_origin && web.is_same_host_as(host) && is_rebinding_safe_host(&web.authority.host, trusted_suffixes.unwrap_or("")) {
        return true;
    }
    let allow_origin = allow_origin.unwrap_or("");
    if is_blank(allow_origin) {
        return web_origin.is_some_and(|w| w.is_loopback());
    }
    let trimmed = java_trim(origin);
    allow_origin.split(',').map(java_trim).any(|entry| entry == "*" || entry.eq_ignore_ascii_case(trimmed))
}

/// `consistentHost`: the request's `Host`, or `None` when it has none or several that disagree.
pub fn consistent_host<'a>(hosts: &[&'a str]) -> Option<&'a str> {
    let first = java_trim(hosts.first()?);
    hosts.iter().all(|h| java_trim(h).eq_ignore_ascii_case(first)).then_some(first)
}

/// The request's consistent `Host` (all `host` header values; an HTTP/2 `:authority` arrives as `host`).
pub fn request_host(request: &crate::request::HttpRequest) -> Option<String> {
    let hosts: Vec<&str> = request.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("host")).flat_map(|(_, v)| v.iter().map(String::as_str)).collect();
    consistent_host(&hosts).map(str::to_string)
}

/// `CORSHeaders.isCorsPreflight`: an `OPTIONS` with `Origin` and `Access-Control-Request-Method` headers.
pub fn is_cors_preflight(request: &crate::request::HttpRequest) -> bool {
    let has = |name: &str| request.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case(name) && !v.is_empty());
    request.method == "OPTIONS" && has("origin") && has("access-control-request-method")
}

/// `HttpState.CONTROL_PLANE_BARE_ROUTE_METHODS`: the methods the control plane serves on each bare alias.
const BARE_ROUTE_METHODS: &[(&str, &[&str])] = &[
    ("/asyncapi", &["GET", "PUT"]),
    ("/asyncapi/http", &["PUT"]),
    ("/asyncapi/verify", &["PUT"]),
    ("/audit", &["GET"]),
    ("/baseline/compare", &["PUT"]),
    ("/bind", &["PUT"]),
    ("/breakpoint/matcher", &["PUT"]),
    ("/breakpoint/matcher/clear", &["PUT"]),
    ("/breakpoint/matcher/remove", &["PUT"]),
    ("/breakpoint/matchers", &["GET", "PUT"]),
    ("/cassettes", &["DELETE", "GET", "PUT"]),
    ("/chaosExperiment", &["DELETE", "GET", "PUT"]),
    ("/chaosExperiment/history", &["GET"]),
    ("/chaosExperiment/profiles", &["GET"]),
    ("/clear", &["PUT"]),
    ("/clock", &["GET", "PUT"]),
    ("/cluster", &["GET"]),
    ("/config", &["GET"]),
    ("/configuration", &["GET", "PUT"]),
    ("/contractTest", &["PUT"]),
    ("/crud", &["PUT"]),
    ("/debugMismatch", &["PUT"]),
    ("/diff", &["PUT"]),
    ("/drift", &["GET"]),
    ("/drift/clear", &["PUT"]),
    ("/expectation", &["PUT"]),
    ("/explainUnmatched", &["PUT"]),
    ("/files/delete", &["PUT"]),
    ("/files/list", &["PUT"]),
    ("/files/retrieve", &["PUT"]),
    ("/files/store", &["PUT"]),
    ("/generateExpectation", &["PUT"]),
    ("/graphql", &["PUT"]),
    ("/grpc/clear", &["PUT"]),
    ("/grpc/descriptors", &["PUT"]),
    ("/grpc/health", &["GET", "PUT"]),
    ("/grpc/services", &["PUT"]),
    ("/grpcChaos", &["GET", "PATCH", "PUT"]),
    ("/http3status", &["GET"]),
    ("/import", &["PUT"]),
    ("/llm/diffRuns", &["PUT"]),
    ("/llm/optimisationReport", &["GET"]),
    ("/loadScenario", &["DELETE", "GET", "PUT"]),
    ("/loadScenario/generateFromOpenAPI", &["PUT"]),
    ("/loadScenario/generateFromRecording", &["PUT"]),
    ("/loadScenario/start", &["PUT"]),
    ("/loadScenario/stop", &["PUT"]),
    ("/logEntryBody", &["GET"]),
    ("/mode", &["GET", "PUT"]),
    ("/oidc", &["PUT"]),
    ("/openapi", &["PUT"]),
    ("/pact", &["PUT"]),
    ("/pact/import", &["PUT"]),
    ("/pact/verify", &["PUT"]),
    ("/preemption", &["DELETE", "GET", "PUT"]),
    ("/proxyConfiguration", &["GET"]),
    ("/ready", &["GET"]),
    ("/recordings/promote", &["PUT"]),
    ("/replay", &["PUT"]),
    ("/reset", &["PUT"]),
    ("/retrieve", &["PUT"]),
    ("/saml", &["PUT"]),
    ("/scenario", &["GET"]),
    ("/scim", &["PUT"]),
    ("/serviceChaos", &["GET", "PATCH", "PUT"]),
    ("/status", &["PUT"]),
    ("/stop", &["PUT"]),
    ("/tcpChaos", &["GET", "PATCH", "PUT"]),
    ("/trafficValidate", &["PUT"]),
    ("/verify", &["PUT"]),
    ("/verifySLO", &["PUT"]),
    ("/verifySequence", &["PUT"]),
    ("/wasm/modules", &["DELETE", "GET", "PUT"]),
    ("/wasm/test", &["POST"]),
    ("/wsdl", &["PUT"]),
];

/// `HttpState.CONTROL_PLANE_BARE_PREFIX_METHODS`.
const BARE_PREFIX_METHODS: &[(&str, &[&str])] = &[
    ("/scenario/", &["GET", "PUT"]),
    ("/loadScenario/", &["DELETE", "GET"]),
    ("/chaosExperiment/profiles/", &["DELETE", "GET", "PUT"]),
    ("/chaosExperiment/apply/", &["POST"]),
];

/// `HttpState.isControlPlaneRoute`: anything under `/mockserver` or `/_mockserver_`, or a bare alias with a method
/// the control plane serves there.
pub fn is_control_plane_route(method: Option<&str>, path: &str) -> bool {
    if path == "/mockserver" || path.starts_with("/mockserver/") || path.starts_with("/_mockserver_") {
        return true;
    }
    let Some(method) = method else { return false };
    let method = java_trim(method).to_ascii_uppercase();
    let has = |methods: &[&str]| methods.contains(&method.as_str());
    BARE_ROUTE_METHODS.iter().any(|(p, m)| *p == path && has(m)) || BARE_PREFIX_METHODS.iter().any(|(p, m)| path.starts_with(p) && has(m))
}

/// `HttpState.isControlPlanePathCandidate`: under `/mockserver/`, a bare alias, or a bare `{name}`-route prefix.
pub fn is_control_plane_path_candidate(path: &str) -> bool {
    path.starts_with("/mockserver/") || BARE_ROUTE_METHODS.iter().any(|(p, _)| *p == path) || BARE_PREFIX_METHODS.iter().any(|(p, _)| path.starts_with(p))
}

/// `HttpState.isControlPlaneRequest(request)`: the control plane serves it (or, for a preflight, the request it
/// precedes), or it is the configured liveness `GET`.
pub fn is_control_plane_request(request: &crate::request::HttpRequest, config: &crate::Config) -> bool {
    let method = if is_cors_preflight(request) { request.first_header("access-control-request-method") } else { Some(request.method.as_str()) };
    is_control_plane_method_path(method, &request.path, config)
}

/// `HttpState.isControlPlaneRequest(method, path)`.
pub fn is_control_plane_method_path(method: Option<&str>, path: &str, config: &crate::Config) -> bool {
    if is_control_plane_route(method, path) {
        return true;
    }
    let liveness = config.property("livenessHttpGetPath").filter(|p| !is_blank(p));
    method.is_some_and(|m| java_trim(m).eq_ignore_ascii_case("GET")) && liveness.is_some_and(|l| l == path)
}

/// `HttpState.isControlPlaneOriginRefused(request)`: a request the control plane serves whose browser `Origin` the
/// policy does not allow; a preflight is never refused (it is answered without allow headers).
pub fn is_refused(request: &crate::request::HttpRequest, config: &crate::Config) -> bool {
    let Some(origin) = request.first_header("origin").filter(|o| !o.is_empty()) else { return false };
    if is_cors_preflight(request) || !is_control_plane_method_path(Some(request.method.as_str()), &request.path, config) {
        return false;
    }
    !allowed_by_config(config, Some(origin), request_host(request).as_deref())
}

/// `StringFormatter.escapeControlCharactersForLog`.
pub fn escape_for_log(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        let u = c as u32;
        let control = u < 0x20 || (0x7f..=0x9f).contains(&u) || u == 0x200e || u == 0x200f || (0x2028..=0x202e).contains(&u) || (0x2066..=0x2069).contains(&u);
        match c {
            _ if !control => escaped.push(c),
            '\r' => escaped.push_str("\\r"),
            '\n' => escaped.push_str("\\n"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push_str(&format!("\\u{u:04x}")),
        }
    }
    escaped
}

/// `HttpState.writeControlPlaneOriginRefused`: the INFO entry and the text/plain `403`, written as a control-plane
/// response (so without CORS headers, the origin being refused).
pub fn refusal(state: &crate::state::State, request: &crate::request::HttpRequest) -> crate::reply::Reply {
    if state.info_enabled() {
        let origin = escape_for_log(request.first_header("origin").unwrap_or(""));
        let entry = crate::recorded::LogEntry::new(
            crate::recorded::Kind::AuthenticationFailed,
            "control plane request refused with status 403 - origin {} is not allowed, set controlPlaneCorsAllowOrigin to allow it (a page MockServer serves itself at a host name that is not rebinding-safe can instead be allowed with controlPlaneTrustedHostSuffixes)",
        )
        .args([origin])
        .correlation(request.log_correlation_id.clone());
        crate::log::entry(state, &entry);
        state.log.message(entry);
    }
    crate::reply::Reply::api_header(403, "text/plain", REFUSED_MESSAGE)
}

/// `ControlPlaneWebSocketUpgradeGate.originAllowed`, the first check of every control-plane WebSocket upgrade
/// (`description` names the socket: "dashboard UI", "callback"). A refused origin gets the INFO entry and a raw `403`,
/// then the connection closes; returns whether the upgrade may go on.
pub async fn upgrade_origin_allowed<S>(state: &crate::state::State, request: &crate::request::HttpRequest, description: &str, stream: &mut S) -> bool
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let origin = request.first_header("origin");
    if allowed_by_config(&state.config, origin, request_host(request).as_deref()) {
        return true;
    }
    if state.info_enabled() {
        let entry = crate::recorded::LogEntry::new(
            crate::recorded::Kind::Info,
            "{} web socket upgrade rejected with status 403 - origin {} is not allowed, set controlPlaneCorsAllowOrigin to allow it (a page MockServer serves itself at a host name that is not rebinding-safe can instead be allowed with controlPlaneTrustedHostSuffixes)",
        )
        .args([description.to_string(), escape_for_log(origin.unwrap_or(""))]);
        crate::log::entry(state, &entry);
        state.log.message(entry);
    }
    let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n").await;
    let _ = stream.shutdown().await;
    false
}

fn is_blank(s: &str) -> bool {
    s.chars().all(char::is_whitespace)
}

fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

/// `isRebindingSafeHost`, for a host lower-cased as `HostAndPort` parsed it.
fn is_rebinding_safe_host(host: &str, trusted_suffixes: &str) -> bool {
    if let Some(literal) = host.strip_prefix('[') {
        let literal = &literal[..literal.len() - 1];
        return literal.contains(':') && literal.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c) || c == ':' || c == '.');
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    if !is_ascii_host_name(name) {
        return false;
    }
    if name == "localhost" || !name.contains('.') || is_ipv4_literal(name) {
        return true;
    }
    let under = |suffix: &str| name.ends_with(&format!(".{suffix}"));
    BUILT_IN_TRUSTED_HOST_SUFFIXES.iter().any(|s| under(s)) || ConfiguredSuffixes::of(trusted_suffixes).usable.iter().any(|s| under(s))
}

/// `trustedHostSuffixErrors`: one message per public-suffix entry (rejected, trusts nothing).
pub fn trusted_host_suffix_errors(trusted_suffixes: &str) -> Vec<String> {
    ConfiguredSuffixes::of(trusted_suffixes).errors
}

/// `trustedHostSuffixWarnings`: entries that are no host-name suffix, and single-label ones that are no public suffix.
pub fn trusted_host_suffix_warnings(trusted_suffixes: &str) -> Vec<String> {
    ConfiguredSuffixes::of(trusted_suffixes).warnings
}

#[derive(Default)]
struct ConfiguredSuffixes {
    usable: Vec<String>,
    errors: Vec<String>,
    warnings: Vec<String>,
}

impl ConfiguredSuffixes {
    fn of(raw: &str) -> ConfiguredSuffixes {
        let mut parsed = ConfiguredSuffixes::default();
        for configured in raw.split(',') {
            let entry = java_trim(configured);
            if entry.is_empty() {
                continue;
            }
            match normalise_suffix(entry) {
                None => parsed.warnings.push(format!(
                    "controlPlaneTrustedHostSuffixes entry \"{entry}\" is not a host-name suffix (such as corp.example or *.corp.example) and is ignored"
                )),
                Some(suffix) if is_public_suffix(&suffix) => parsed.errors.push(format!(
                    "controlPlaneTrustedHostSuffixes entry \"{entry}\" is REJECTED because it is a public suffix, under which anyone can register a name and use the control plane through DNS rebinding; list your own private suffix instead"
                )),
                Some(suffix) => {
                    if !suffix.contains('.') {
                        parsed.warnings.push(format!(
                            "controlPlaneTrustedHostSuffixes entry \"{entry}\" is a whole top-level domain, so any site under it can use the control plane through DNS rebinding"
                        ));
                    }
                    parsed.usable.push(suffix);
                }
            }
        }
        parsed
    }
}

fn normalise_suffix(configured: &str) -> Option<String> {
    let suffix = java_trim(configured);
    if suffix.chars().any(|c| c as u32 >= 0x7f) {
        return None;
    }
    let lower = suffix.to_ascii_lowercase();
    let mut suffix = lower.strip_suffix('.').unwrap_or(&lower);
    if let Some(rest) = suffix.strip_prefix("*.") {
        suffix = rest;
    } else if let Some(rest) = suffix.strip_prefix('.') {
        suffix = rest;
    }
    is_ascii_host_name(suffix).then(|| suffix.to_string())
}

fn is_ascii_host_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && !name.ends_with('.')
        && !name.contains("..")
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.')
}

fn is_ipv4_literal(name: &str) -> bool {
    let octets: Vec<&str> = name.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|o| !o.is_empty() && o.len() <= 3 && o.chars().all(|c| c.is_ascii_digit()) && o.parse::<u32>().is_ok_and(|v| v <= 255))
}

fn is_public_suffix(suffix: &str) -> bool {
    if suffix == "home.arpa" || suffix.ends_with(".home.arpa") {
        return false;
    }
    if BUILT_IN_TRUSTED_HOST_SUFFIXES.iter().any(|b| suffix == *b || suffix.ends_with(&format!(".{b}"))) {
        return false;
    }
    guava_is_valid(suffix) && guava_public_suffix_index(suffix) == Some(0)
}

/// `InternetDomainName.isValid` for a name `normalise_suffix` already accepted (lower-case ASCII, no empty label).
fn guava_is_valid(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    if name.len() > 253 || parts.len() > 127 {
        return false;
    }
    let last = parts.len() - 1;
    parts.iter().enumerate().all(|(i, part)| {
        let bytes = part.as_bytes();
        !(bytes.is_empty() || bytes.len() > 63 || bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' || (i == last && bytes[0].is_ascii_digit()))
    })
}

static TRIE_DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/public_suffix/trie_data.bin"));
static STRING_POOL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/public_suffix/string_pool.bin"));

fn utf16_at(data: &[u8], i: usize) -> u32 {
    u32::from(u16::from_be_bytes([data[2 * i], data[2 * i + 1]]))
}

/// `PublicSuffixTrie.findSuffixIndex(parts, null)`: the index of the label where the public suffix starts.
fn guava_public_suffix_index(name: &str) -> Option<usize> {
    let parts: Vec<&str> = name.split('.').collect();
    let trie = |i: usize| utf16_at(TRIE_DATA, i) as usize;
    let mut node = 0usize;
    let mut result = None;
    for i in (0..parts.len()).rev() {
        let first_child = trie(node * 3 + 1);
        let children = trie(node * 3 + 2) & 2047;
        let Some(child) = find_child(first_child, children, parts[i]) else { break };
        node = child;
        let flags = trie(node * 3 + 2);
        if (flags >> 11) & 1 != 0 {
            result = Some(i + 1);
        }
        if matches!((flags >> 14) & 3, 1 | 2) {
            result = Some(i);
        }
        if i > 0 && matches!((flags >> 12) & 3, 1 | 2) {
            result = Some(i - 1);
        }
    }
    result
}

fn find_child(first: usize, count: usize, label: &str) -> Option<usize> {
    let (mut low, mut high) = (first as isize, first as isize + count as isize - 1);
    while low <= high {
        let mid = ((low + high) as usize) >> 1;
        let offset = utf16_at(TRIE_DATA, mid * 3) as usize;
        match compare_label(label, offset) {
            c if c < 0 => high = mid as isize - 1,
            c if c > 0 => low = mid as isize + 1,
            _ => return Some(mid),
        }
    }
    None
}

fn compare_label(label: &str, offset: usize) -> i64 {
    let chars: Vec<u16> = label.encode_utf16().collect();
    let length = utf16_at(STRING_POOL, offset) as usize;
    for (i, c) in chars.iter().take(length.min(chars.len())).enumerate() {
        let pool = utf16_at(STRING_POOL, offset + 1 + i);
        if u32::from(*c) != pool {
            return i64::from(*c) - i64::from(pool);
        }
    }
    chars.len() as i64 - length as i64
}

struct HostAndPort {
    host: String,
    port: u32,
}

impl HostAndPort {
    fn parse(authority: &str, default_port: u32) -> Option<HostAndPort> {
        if authority.is_empty() || authority.chars().any(|c| c <= ' ' || c as u32 >= 0x7f || "/?#@\\,".contains(c)) {
            return None;
        }
        let (host, port_part) = if authority.starts_with('[') {
            let close = authority.find(']')?;
            let rest = &authority[close + 1..];
            let port = if rest.is_empty() {
                None
            } else {
                Some(rest.strip_prefix(':')?)
            };
            (&authority[..=close], port)
        } else {
            match authority.find(':') {
                None => (authority, None),
                Some(colon) if authority[colon + 1..].contains(':') => return None,
                Some(colon) => (&authority[..colon], Some(&authority[colon + 1..])),
            }
        };
        if host.is_empty() || host == "[]" {
            return None;
        }
        let port = match port_part {
            None => default_port,
            Some(p) => {
                if p.is_empty() || p.len() > 5 || !p.chars().all(|c| c.is_ascii_digit()) {
                    return None;
                }
                let port: u32 = p.parse().ok()?;
                if !(1..=65535).contains(&port) {
                    return None;
                }
                port
            }
        };
        Some(HostAndPort { host: host.to_ascii_lowercase(), port })
    }
}

struct WebOrigin {
    authority: HostAndPort,
    default_port: u32,
}

impl WebOrigin {
    fn parse(origin: &str) -> Option<WebOrigin> {
        if is_blank(origin) {
            return None;
        }
        let trimmed = java_trim(origin);
        let scheme_end = trimmed.find("://").filter(|&i| i > 0)?;
        let default_port = match trimmed[..scheme_end].to_ascii_lowercase().as_str() {
            "http" => 80,
            "https" => 443,
            _ => return None,
        };
        let authority = HostAndPort::parse(&trimmed[scheme_end + 3..], default_port)?;
        Some(WebOrigin { authority, default_port })
    }

    fn is_loopback(&self) -> bool {
        matches!(self.authority.host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
    }

    fn is_same_host_as(&self, host: Option<&str>) -> bool {
        let Some(host) = host.filter(|h| !is_blank(h)) else { return false };
        HostAndPort::parse(java_trim(host), self.default_port).is_some_and(|h| h.host == self.authority.host && h.port == self.authority.port)
    }
}


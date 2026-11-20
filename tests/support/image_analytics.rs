//! The oracle image bakes upstream's dashboard analytics endpoint and key into its environment
//! (`MOCKSERVER_DASHBOARD_ANALYTICS_ENDPOINT`/`_KEY`); our image and binary leave both empty, by the user's decision
//! (2026-10-25: analytics only to a PostHog account of our own, and none exists; `docs/divergences.md`). Wherever a
//! configuration dump shows one of those two values, the harness reads it as our default, so every other line of the
//! dump still has to match. Upstream's values are recognised by their SHA-256 alone, so no file of ours carries them;
//! any other value of the two properties (a scenario's own, or a later image's) is compared as it is.

use std::borrow::Cow;
use std::sync::LazyLock;

/// SHA-256 (hex) of the 9.1.0 and 9.2.0 images' `MOCKSERVER_DASHBOARD_ANALYTICS_ENDPOINT` and `MOCKSERVER_DASHBOARD_ANALYTICS_KEY`.
const UPSTREAM_VALUES_SHA256: [&str; 2] = [
    "a2acfb51adfc0c625dc905cd6bcfd11b730dc8b1291e43f565599df0e833591c",
    "3c3a83e19140a90fa8556cc0f2ab8450a5a96f4b001d4845bd556bb6efa21854",
];

/// SHA-256 of a value, in hex.
pub fn sha256_hex(value: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, value.as_bytes());
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn is_upstream_value(value: &str) -> bool {
    UPSTREAM_VALUES_SHA256.contains(&sha256_hex(value).as_str())
}

/// The text with upstream's two values read as ours, in each shape a dump takes:
/// - the `Configuration` JSON (`GET /mockserver/configuration`, logs, MCP), in any quoting depth:
///   `"dashboardAnalyticsEndpoint" : "<value>"` becomes `"dashboardAnalyticsEndpoint" : ""`;
/// - `GET /mockserver/config`, one entry per property:
///   `{"name":"mockserver.dashboardAnalyticsEndpoint","value":"<value>","source":"environment-variable","default":""}`
///   becomes `{"name":"mockserver.dashboardAnalyticsEndpoint","value":"","source":"default"}`;
/// - `--print-config`: `  mockserver.dashboardAnalyticsEndpoint = <value>   [environment-variable]   (default: )`
///   becomes `  mockserver.dashboardAnalyticsEndpoint =    [default]`.
///
/// The key is redacted in the last two shapes, so its environment-variable entry there is read as the image's only
/// when the same text shows upstream's endpoint coming from the environment too (the image sets both together).
pub fn as_ours(text: &str) -> Cow<'_, str> {
    as_ours_recognising(text, is_upstream_value)
}

/// [`as_ours`] with the image's values recognised by `is_upstream_value`, so a test can exercise every dump shape with
/// values of its own (once every golden is recorded through [`as_ours`], none holds upstream's values).
pub fn as_ours_recognising(text: &str, is_upstream_value: impl Fn(&str) -> bool) -> Cow<'_, str> {
    if !text.contains("dashboardAnalytics") {
        return Cow::Borrowed(text);
    }
    static DTO: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r#"(dashboardAnalytics(?:Endpoint|Key)(\\*)" ?: ?\\*")([^"\\]*)"#).unwrap());
    static CONFIG: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"(\\*)"name\\*":\\*"mockserver\.dashboardAnalytics(Endpoint|Key)\\*",\\*"value\\*":\\*"([^"\\]*)\\*",\\*"source\\*":\\*"environment-variable\\*",\\*"default\\*":\\*"([^"\\]*)"#).unwrap()
    });
    static CLI: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?m)^(  mockserver\.dashboardAnalytics(Endpoint|Key) = )(.*?)   \[environment-variable\]   \(default: .*\)$").unwrap());
    let endpoint_from_image = CONFIG.captures_iter(text).any(|c| &c[2] == "Endpoint" && is_upstream_value(&c[3]))
        || CLI.captures_iter(text).any(|c| &c[2] == "Endpoint" && is_upstream_value(&c[3]));
    let text = DTO.replace_all(text, |c: &regex::Captures| if is_upstream_value(&c[3]) { c[1].to_string() } else { c[0].to_string() });
    if !endpoint_from_image {
        return text;
    }
    let text = CONFIG.replace_all(&text, |c: &regex::Captures| {
        let q = format!("{}\"", &c[1]);
        let value = if &c[2] == "Endpoint" { "" } else { &c[3] };
        format!("{q}name{q}:{q}mockserver.dashboardAnalytics{}{q},{q}value{q}:{q}{value}{q},{q}source{q}:{q}default", &c[2])
    });
    let text = CLI.replace_all(&text, |c: &regex::Captures| {
        let value = if &c[2] == "Endpoint" { "" } else { &c[3] };
        format!("{}{value}   [default]", &c[1])
    });
    Cow::Owned(text.into_owned())
}

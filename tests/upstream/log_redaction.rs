//! `redactSecretsInLog` on every log message and argument: upstream's fixes cc7d7d185 ("redact secrets in
//! the log message and arguments, not only the request") and c76143e4a ("close the paths where redactSecretsInLog let
//! credentials reach log output"), adopted ahead of the oracle. The 8.0.0 oracle masks only an entry's
//! top-level `httpRequest`/`httpResponse`, so its `message`, `arguments`, plain-text `LOGS`, the console and
//! `explainUnmatched` still quote the credentials.
//!
//! - `LogEntryRedactionTest` (cc7d7d185): `shouldMaskSensitiveHeaderInLogArgumentsWhenFlagOn`,
//!   `shouldMaskSensitiveHeaderInLogMessageWhenFlagOn`, `shouldLeaveLogArgumentsUnchangedWhenFlagOff`
//! - `LogEntryRedactionSurfacesTest` (c76143e4a), over the wire: `shouldRedactEveryRetrieveSurfaceWithInstanceRedaction`,
//!   `shouldLeaveEveryRetrieveSurfaceUnredactedWhenRedactionIsOff`, `shouldRedactTheMismatchBecauseOnEverySurface`,
//!   `shouldLeaveTheMismatchBecauseUnchangedWhenRedactionIsOff`, `shouldRedactExplainUnmatchedDifferences`,
//!   `shouldNotServeAMessageMemoisedBeforeRedactionWasEnabled`, `shouldReRenderWhenTheRedactedBodyFieldsChange`.
//!   The tests that drive `LogEntry`, `DeferredLogArgument` or `SensitiveValueMatcher` directly (memo internals, Java
//!   throwables, timing bounds) have no counterpart over the wire.
//! - `FixtureRedactorTest` (c76143e4a), against `SensitiveValues` directly: the `SensitiveValueMatcher` cases
//!   (`shouldNotSearchFreeTextForValuesBeyondItsBounds`).

use std::io::{Read, Write};
use std::time::Duration;

use serde_json::json;

use crate::common;

const PLACEHOLDER: &str = "***REDACTED***";
const PATH: &str = "/some/proxied/path";
const SECRETS: &[&str] = &["AUTHZ-SECRET-1", "PROXYAUTH-SECRET-2", "APIKEY-SECRET-3", "COOKIE-SECRET-4", "QUERY-SECRET-5", "BODY-SECRET-6", "SETCOOKIE-SECRET-7", "RESPBODY-SECRET-8"];
const MISMATCH_SECRETS: &[&str] = &["AUTHZ-SECRET-1", "COOKIE-SECRET-4", "QUERY-SECRET-5"];

/// One request with `headers` and a raw `body` on its own connection; the status and the body.
async fn send(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> (u16, String) {
    let mut head = format!("{method} {path} HTTP/1.1\r\n");
    if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
        head.push_str(&format!("Host: 127.0.0.1:{port}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n", body.len()));
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let body = body.to_string();
    tokio::task::spawn_blocking(move || {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        s.write_all(head.as_bytes()).unwrap();
        s.write_all(body.as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        (head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0), body.to_string())
    })
    .await
    .unwrap()
}

/// `retrieve?type=<kind>[&format=<format>]`, every entry.
async fn retrieve(port: u16, kind: &str, format: Option<&str>) -> String {
    let path = match format {
        Some(f) => format!("/mockserver/retrieve?type={kind}&format={f}"),
        None => format!("/mockserver/retrieve?type={kind}"),
    };
    let r = common::send(port, "PUT", &path, "").await;
    assert_eq!(r.status, 200, "{}", r.body);
    r.body
}

fn assert_no_secrets(surface: &str, output: &str, secrets: &[&str]) {
    assert!(!output.is_empty(), "{surface} rendered nothing to check");
    for secret in secrets {
        assert!(!output.contains(secret), "{surface} leaked {secret}:\n{output}");
    }
}

fn assert_all_secrets(surface: &str, output: &str, secrets: &[&str]) {
    for secret in secrets {
        assert!(output.contains(secret), "{surface} should show {secret} with redaction off:\n{output}");
    }
}

/// The `received request` line of the plain-text `LOGS`: `getMessage`, the format filled with the rendered arguments.
/// Since the re-pin `LOG_ENTRIES` quotes an entry's own request in its compact form (`GET /some_path`),
/// so the rendered argument these tests check is written whole only in this line.
async fn received_line(port: u16) -> String {
    let body = retrieve(port, "LOGS", None).await;
    let lines: Vec<&str> = body.split("\n------------------------------------\n").filter(|l| l.contains("received request:")).collect();
    assert_eq!(lines.len(), 1, "{body}");
    lines[0].to_string()
}

// --- LogEntryRedactionTest (cc7d7d185) -------------------------------------------------------------------------------

#[tokio::test]
async fn should_mask_sensitive_header_in_log_arguments_when_flag_on() {
    let server = common::start(&[("redactSecretsInLog", "true")]).await;
    send(server.port, "GET", "/some_path", &[("Authorization", "Bearer super-secret-token"), ("Accept", "application/json")], "").await;

    // secret masked in the argument, non-sensitive header untouched
    let rendered = received_line(server.port).await;
    assert!(rendered.contains(PLACEHOLDER), "{rendered}");
    assert!(!rendered.contains("super-secret-token"), "{rendered}");
    assert!(rendered.contains("application/json"), "{rendered}");
}

#[tokio::test]
async fn should_mask_sensitive_header_in_log_message_when_flag_on() {
    let server = common::start(&[("redactSecretsInLog", "true")]).await;
    send(server.port, "GET", "/some_path", &[("Authorization", "Bearer super-secret-token")], "").await;

    // the message is formatted from the arguments
    let message = received_line(server.port).await;
    assert!(message.contains(PLACEHOLDER), "{message}");
    assert!(!message.contains("super-secret-token"), "{message}");
}

#[tokio::test]
async fn should_leave_log_arguments_unchanged_when_flag_off() {
    let server = common::start(&[("redactSecretsInLog", "false")]).await;
    send(server.port, "GET", "/some_path", &[("Authorization", "Bearer super-secret-token")], "").await;

    // opt-in only, so nothing is masked with the flag off
    assert!(received_line(server.port).await.contains("super-secret-token"));
}

// --- LogEntryRedactionSurfacesTest (c76143e4a) -----------------------------------------------------------------------

/// `proxiedRequest()`/`proxiedResponse()` as an exchange through a forwarding expectation: the request carries every
/// kind of credential, the upstream's response a `Set-Cookie` and a sensitive body field. The upstream is a second
/// server, started with the same properties.
async fn log_proxied_exchange(properties: &[(&str, &str)]) -> (common::Running, common::Running) {
    let upstream = common::start(properties).await;
    common::expect(
        upstream.port,
        &json!({
            "httpRequest": {"path": PATH},
            "httpResponse": {
                "statusCode": 200,
                "headers": {"Set-Cookie": ["sid=SETCOOKIE-SECRET-7; Path=/"]},
                "body": {"type": "JSON", "json": {"ok": true, "password": "RESPBODY-SECRET-8"}}
            }
        }),
    )
    .await;
    let server = common::start(properties).await;
    common::expect(server.port, &json!({"httpRequest": {"path": PATH}, "httpForward": {"host": "127.0.0.1", "port": upstream.port}})).await;
    let (status, _) = send(
        server.port,
        "POST",
        &format!("{PATH}?key=QUERY-SECRET-5&model=gpt"),
        &[
            ("Authorization", "Bearer AUTHZ-SECRET-1"),
            ("Proxy-Authorization", "Basic PROXYAUTH-SECRET-2"),
            ("x-api-key", "APIKEY-SECRET-3"),
            ("Cookie", "session=COOKIE-SECRET-4"),
            ("Content-Type", "application/json"),
        ],
        r#"{"user":"bob","password":"BODY-SECRET-6"}"#,
    )
    .await;
    assert_eq!(status, 200);
    (server, upstream)
}

fn redacting() -> Vec<(&'static str, &'static str)> {
    vec![("redactSecretsInLog", "true"), ("fixtureBodyRedactFields", "password")]
}

#[tokio::test]
async fn should_redact_every_retrieve_surface_with_instance_redaction() {
    let (server, _upstream) = log_proxied_exchange(&redacting()).await;

    let logs = retrieve(server.port, "LOGS", None).await;
    assert!(logs.contains(PATH), "{logs}");
    assert_no_secrets("LOGS", &logs, SECRETS);
    assert_no_secrets("LOGS LOG_ENTRIES", &retrieve(server.port, "LOGS", Some("LOG_ENTRIES")).await, SECRETS);
    assert_no_secrets("REQUESTS JSON", &retrieve(server.port, "REQUESTS", Some("JSON")).await, SECRETS);
    assert_no_secrets("REQUESTS CURL", &retrieve(server.port, "REQUESTS", Some("CURL")).await, SECRETS);
    assert_no_secrets("REQUEST_RESPONSES JSON", &retrieve(server.port, "REQUEST_RESPONSES", Some("JSON")).await, SECRETS);
    assert_no_secrets("REQUEST_RESPONSES LOG_ENTRIES", &retrieve(server.port, "REQUEST_RESPONSES", Some("LOG_ENTRIES")).await, SECRETS);
}

#[tokio::test]
async fn should_leave_every_retrieve_surface_unredacted_when_redaction_is_off() {
    let (server, _upstream) = log_proxied_exchange(&[]).await;

    assert_all_secrets("LOGS", &retrieve(server.port, "LOGS", None).await, SECRETS);
    assert_all_secrets("LOGS LOG_ENTRIES", &retrieve(server.port, "LOGS", Some("LOG_ENTRIES")).await, SECRETS);
    assert!(retrieve(server.port, "REQUESTS", Some("CURL")).await.contains("COOKIE-SECRET-4"));
}

// --- RedactSecretsInLogProxyIntegrationTest (master) ---------------------------------------------------

/// The absolute-form request an HTTP client configured with a proxy sends, carrying every kind of credential, to
/// `proxy` for `upstream`; the answer must be the upstream's `200`.
async fn proxied_request(proxy: u16, upstream: u16) -> String {
    let target = format!("127.0.0.1:{upstream}");
    let (status, body) = send(
        proxy,
        "POST",
        &format!("http://{target}/v1/chat?key=QUERY-SECRET-5&model=gpt"),
        &[
            ("Host", target.as_str()),
            ("Authorization", "Bearer AUTHZ-SECRET-1"),
            ("Proxy-Authorization", "Basic PROXYAUTH-SECRET-2"),
            ("x-api-key", "APIKEY-SECRET-3"),
            ("Cookie", "session=COOKIE-SECRET-4"),
            ("Content-Type", "application/json"),
        ],
        r#"{"user":"bob","password":"BODY-SECRET-6"}"#,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    body
}

/// `retrieve?type=<kind>[&format=<format>]` with the body `{"path": "/v1/chat"}`, which must quote the exchange.
async fn retrieve_chat(port: u16, kind: &str, format: Option<&str>) -> String {
    let path = match format {
        Some(f) => format!("/mockserver/retrieve?type={kind}&format={f}"),
        None => format!("/mockserver/retrieve?type={kind}"),
    };
    let r = common::send(port, "PUT", &path, r#"{"path": "/v1/chat"}"#).await;
    assert_eq!(r.status, 200, "{kind} {format:?}: {}", r.body);
    assert!(r.body.contains("/v1/chat"), "{kind} {format:?} should include the exchange:\n{}", r.body);
    r.body
}

/// `shouldRedactEverySurfaceOfAProxiedExchangeOnceEnabledOverTheConfigurationEndpoint`: a request proxied by its
/// absolute URI, first with redaction off (every credential retrievable), then again once `redactSecretsInLog`,
/// `fixtureBodyRedactFields` and `redactSecretsInRecordedExpectations` are set over `PUT /mockserver/configuration`:
/// no surface quotes a credential of either exchange any more.
#[tokio::test(flavor = "multi_thread")]
async fn should_redact_every_surface_of_a_proxied_exchange_once_enabled_over_the_configuration_endpoint() {
    let upstream = common::start(&[]).await;
    common::expect(
        upstream.port,
        &json!({
            "httpRequest": {"path": "/v1/chat"},
            "httpResponse": {
                "statusCode": 200,
                "headers": {"Set-Cookie": ["sid=SETCOOKIE-SECRET-7; Path=/"], "Content-Type": ["application/json"]},
                "body": "{\"ok\":true,\"password\":\"RESPBODY-SECRET-8\"}"
            }
        }),
    )
    .await;
    let proxy = common::start(&[]).await;
    assert!(proxied_request(proxy.port, upstream.port).await.contains("RESPBODY-SECRET-8"));
    assert_all_secrets("baseline LOGS", &retrieve_chat(proxy.port, "LOGS", None).await, SECRETS);

    let configured = common::send(proxy.port, "PUT", "/mockserver/configuration", r#"{"redactSecretsInLog": true, "fixtureBodyRedactFields": "password", "redactSecretsInRecordedExpectations": true}"#).await;
    assert!(configured.status < 300, "{}", configured.body);
    proxied_request(proxy.port, upstream.port).await;

    assert_no_secrets("LOGS", &retrieve_chat(proxy.port, "LOGS", None).await, SECRETS);
    assert_no_secrets("LOGS LOG_ENTRIES", &retrieve_chat(proxy.port, "LOGS", Some("LOG_ENTRIES")).await, SECRETS);
    for format in ["JSON", "HAR", "CURL"] {
        assert_no_secrets(&format!("REQUESTS {format}"), &retrieve_chat(proxy.port, "REQUESTS", Some(format)).await, SECRETS);
    }
    for format in ["JSON", "HAR"] {
        assert_no_secrets(&format!("REQUEST_RESPONSES {format}"), &retrieve_chat(proxy.port, "REQUEST_RESPONSES", Some(format)).await, SECRETS);
    }
    // redactSecretsInRecordedExpectations masks credentials in headers, cookies and the query string only
    let recorded = retrieve_chat(proxy.port, "RECORDED_EXPECTATIONS", Some("JSON")).await;
    assert_no_secrets("RECORDED_EXPECTATIONS", &recorded, &["AUTHZ-SECRET-1", "PROXYAUTH-SECRET-2", "APIKEY-SECRET-3", "COOKIE-SECRET-4", "QUERY-SECRET-5", "SETCOOKIE-SECRET-7"]);
}

/// `logMismatches`: an expectation on each credential, then a request that matches none of them; the log's text before
/// any redaction does quote every credential, or the test would prove nothing.
async fn log_mismatches(properties: &[(&str, &str)]) -> common::Running {
    let server = common::start(properties).await;
    for (matcher, body) in [
        (json!({"path": PATH, "headers": {"Authorization": ["Bearer expected"]}}), "a"),
        (json!({"path": PATH, "cookies": {"session": "expected"}}), "b"),
        (json!({"path": PATH, "queryStringParameters": {"key": ["expected"]}}), "c"),
    ] {
        common::expect(server.port, &json!({"httpRequest": matcher, "httpResponse": {"body": body}})).await;
    }
    let (status, _) = send(
        server.port,
        "POST",
        &format!("{PATH}?key=QUERY-SECRET-5"),
        &[("Authorization", "Bearer AUTHZ-SECRET-1"), ("Cookie", "session=COOKIE-SECRET-4")],
        "",
    )
    .await;
    assert_eq!(status, 404);
    server
}

#[tokio::test]
async fn should_redact_the_mismatch_because_on_every_surface() {
    let server = log_mismatches(&[("redactSecretsInLog", "true"), ("fixtureBodyRedactFields", "password"), ("logLevel", "INFO")]).await;

    assert_no_secrets("LOGS", &retrieve(server.port, "LOGS", None).await, MISMATCH_SECRETS);
    let entries = retrieve(server.port, "LOGS", Some("LOG_ENTRIES")).await;
    assert_no_secrets("LOGS LOG_ENTRIES", &entries, MISMATCH_SECRETS);
    assert!(entries.contains("EXPECTATION_NOT_MATCHED"), "{entries}");
    assert!(entries.contains(PLACEHOLDER), "{entries}");
}

#[tokio::test]
async fn should_leave_the_mismatch_because_unchanged_when_redaction_is_off() {
    let server = log_mismatches(&[("logLevel", "INFO")]).await;

    assert_all_secrets("LOGS LOG_ENTRIES", &retrieve(server.port, "LOGS", Some("LOG_ENTRIES")).await, MISMATCH_SECRETS);
}

/// `logUnmatched` then `explainUnmatched`.
async fn explain_unmatched(properties: &[(&str, &str)]) -> String {
    let server = common::start(properties).await;
    common::expect(
        server.port,
        &json!({
            "httpRequest": {"path": PATH, "headers": {"Authorization": ["Bearer expected"]}, "queryStringParameters": {"key": ["expected"]}, "cookies": {"session": "expected"}},
            "httpResponse": {"body": "a"}
        }),
    )
    .await;
    send(server.port, "POST", &format!("{PATH}?key=QUERY-SECRET-5"), &[("Authorization", "Bearer AUTHZ-SECRET-1"), ("Cookie", "session=COOKIE-SECRET-4")], "").await;
    let r = common::send(server.port, "PUT", "/mockserver/explainUnmatched", "").await;
    assert_eq!(r.status, 200, "{}", r.body);
    r.body
}

#[tokio::test]
async fn should_redact_explain_unmatched_differences() {
    let redacted = explain_unmatched(&redacting()).await;
    assert!(redacted.contains("differences"), "{redacted}");
    assert_no_secrets("explainUnmatched", &redacted, MISMATCH_SECRETS);
    assert!(explain_unmatched(&[("redactSecretsInLog", "false")]).await.contains("AUTHZ-SECRET-1"));
}

#[tokio::test]
async fn should_not_serve_a_message_memoised_before_redaction_was_enabled() {
    let (server, _upstream) = log_proxied_exchange(&[("redactSecretsInLog", "false")]).await;
    assert_all_secrets("message rendered with redaction off", &retrieve(server.port, "LOGS", None).await, SECRETS);

    let r = common::send(server.port, "PUT", "/mockserver/configuration", r#"{"redactSecretsInLog": true, "fixtureBodyRedactFields": "password"}"#).await;
    assert!(r.status < 300, "{}", r.body);

    assert_no_secrets("message rendered after redaction was enabled", &retrieve(server.port, "LOGS", None).await, SECRETS);
    assert_no_secrets("log_entries JSON after redaction was enabled", &retrieve(server.port, "LOGS", Some("LOG_ENTRIES")).await, SECRETS);
}

#[tokio::test]
async fn should_re_render_when_the_redacted_body_fields_change() {
    let (server, _upstream) = log_proxied_exchange(&[("redactSecretsInLog", "true")]).await;
    assert!(retrieve(server.port, "LOGS", None).await.contains("BODY-SECRET-6"));

    let r = common::send(server.port, "PUT", "/mockserver/configuration", r#"{"fixtureBodyRedactFields": "password"}"#).await;
    assert!(r.status < 300, "{}", r.body);

    assert_no_secrets("message after fixtureBodyRedactFields changed", &retrieve(server.port, "LOGS", None).await, SECRETS);
}

// --- BinaryPlainTextRedactionIntegrationTest (c76143e4a) ---------------------------------------------------

const BINARY_SECRET: &str = "PROPFIND-SECRET-TOKEN-999";

fn hex(text: &str) -> String {
    text.bytes().map(|b| format!("{b:02x}")).collect()
}

/// A PROPFIND, which the HTTP decoder does not know, on a connection of its own: it goes down the binary path, which
/// logs the payload as hex and as UTF-8 text. Answers once the binary entries are in the log.
async fn log_binary_plain_text(properties: &[(&str, &str)]) -> common::Running {
    let server = common::start(properties).await;
    let port = server.port;
    tokio::task::spawn_blocking(move || {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(format!("PROPFIND /dav HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {BINARY_SECRET}\r\n\r\n").as_bytes()).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
    })
    .await
    .unwrap();
    for _ in 0..200 {
        if retrieve(port, "LOGS", None).await.contains("no matching binary expectation") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    server
}

#[tokio::test]
async fn should_mask_an_unrecognised_method_request_logged_as_binary() {
    let server = log_binary_plain_text(&[("redactSecretsInLog", "true"), ("logLevel", "INFO")]).await;

    let logs = retrieve(server.port, "LOGS", None).await;
    assert!(logs.contains("binary request"), "{logs}");
    assert_no_secrets("LOGS", &logs, &[BINARY_SECRET, &hex(BINARY_SECRET)]);
    let entries = retrieve(server.port, "LOGS", Some("LOG_ENTRIES")).await;
    assert_no_secrets("LOGS LOG_ENTRIES", &entries, &[BINARY_SECRET, &hex(BINARY_SECRET)]);
    assert!(entries.contains(PLACEHOLDER), "{entries}");
}

#[tokio::test]
async fn should_leave_a_request_logged_as_binary_unchanged_when_redaction_is_off() {
    let server = log_binary_plain_text(&[("logLevel", "INFO")]).await;

    assert_all_secrets("LOGS", &retrieve(server.port, "LOGS", None).await, &[&hex(BINARY_SECRET)]);
}

// --- FixtureRedactorTest's SensitiveValueMatcher cases (c76143e4a) ----------------------------------------

/// `java.util.Random`'s generator, enough for the differential below.
struct Random(u64);

impl Random {
    fn new(seed: u64) -> Random {
        Random((seed ^ 0x5DEE_CE66D) & ((1 << 48) - 1))
    }

    fn next(&mut self, bits: u32) -> u32 {
        self.0 = (self.0.wrapping_mul(0x5DEE_CE66D).wrapping_add(0xB)) & ((1 << 48) - 1);
        (self.0 >> (48 - bits)) as u32
    }

    fn next_int(&mut self, bound: usize) -> usize {
        ((u64::from(self.next(31)) * bound as u64) >> 31) as usize
    }

    fn next_bool(&mut self) -> bool {
        self.next(1) != 0
    }
}

fn random_text(random: &mut Random, alphabet: &[char], length: usize) -> String {
    (0..length).map(|_| alphabet[random.next_int(alphabet.len())]).collect()
}

/// The reference (`unionOfOccurrences`): every occurrence of every value, those that overlap merged into one placeholder.
fn union_of_occurrences(text: &str, values: &[String]) -> String {
    let mut occurrences: Vec<(usize, usize)> = Vec::new();
    for value in values.iter().filter(|v| !v.is_empty()) {
        for (at, _) in text.char_indices() {
            if text[at..].starts_with(value.as_str()) {
                occurrences.push((at, at + value.len()));
            }
        }
    }
    occurrences.sort_by(|l, r| l.0.cmp(&r.0).then(r.1.cmp(&l.1)));
    let mut scrubbed = String::new();
    let mut copied = 0;
    let mut end: Option<usize> = None;
    for (start, stop) in occurrences {
        match end {
            Some(e) if start < e => end = Some(e.max(stop)),
            _ => {
                if let Some(e) = end {
                    scrubbed.push_str(PLACEHOLDER);
                    copied = e;
                }
                scrubbed.push_str(&text[copied..start]);
                end = Some(stop);
            }
        }
    }
    if let Some(e) = end {
        scrubbed.push_str(PLACEHOLDER);
        copied = e;
    }
    scrubbed.push_str(&text[copied..]);
    scrubbed
}

#[test]
fn should_mask_the_union_of_all_occurrences_on_either_path() {
    let alphabets: [&[char]; 6] = [
        &['a', 'b'],
        &['a', 'b', 'c'],
        &['a', 'A', '\u{7f}', '\u{80}', '\u{ff}'],
        &['x', '\u{1F600}', '\u{1F601}', '\u{10000}'],
        &['\u{0}', '\u{4e00}', '\u{4e01}', '\u{ffff}', '\u{7f}'],
        &['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', '0', '1', '2', '3', '"', '\\', ' ', '=', '{', '}', ':', ','],
    ];
    let mut random = Random::new(20260930);
    for round in 0..5_000 {
        let alphabet = alphabets[random.next_int(alphabets.len())];
        let bound = if random.next_int(10) == 0 { 60 } else { 8 };
        let count = 1 + random.next_int(bound);
        let mut values = Vec::new();
        for _ in 0..count {
            let length = if random.next_int(20) == 0 {
                50 + random.next_int(300)
            } else {
                let bound = if random.next_bool() { 3 } else { 9 };
                1 + random.next_int(bound)
            };
            values.push(random_text(&mut random, alphabet, length));
        }
        if random.next_int(5) == 0 && values[0].chars().count() > 1 {
            let tail: String = values[0].chars().skip(1).collect();
            values.push(tail);
        }
        let bound = if random.next_int(8) == 0 { 5_000 } else { 80 };
        let length = random.next_int(bound);
        let mut text: Vec<char> = random_text(&mut random, alphabet, length).chars().collect();
        for _ in 0..random.next_int(4) {
            let at = random.next_int(text.len() + 1);
            let value: Vec<char> = values[random.next_int(values.len())].chars().collect();
            text.splice(at..at, value);
        }
        let text: String = text.into_iter().collect();
        let expected = union_of_occurrences(&text, &values);

        let matcher = mock_server::SensitiveValues::of(values.clone());
        for _ in 0..3 {
            assert_eq!(matcher.scrub(&text), expected, "round {round}: {values:?} in {text:?}");
            assert_eq!(matcher.contains_any(&text), expected != text, "round {round}");
        }
    }
}

#[test]
fn should_scrub_in_time_linear_in_the_text_up_to_the_bound_on_values() {
    let mut random = Random::new(7);
    let letters: Vec<char> = ('a'..='z').chain('A'..='Z').chain('0'..='9').collect();
    let mut values = std::collections::BTreeSet::new();
    while values.len() < 10_000 {
        let length = 12 + random.next_int(20);
        values.insert(random_text(&mut random, &letters, length));
    }
    let values: Vec<String> = values.into_iter().collect();
    let filler: Vec<char> = " .,;-_".chars().collect();
    let mut text = String::new();
    while text.len() < 2_000_000 {
        text.push_str(&random_text(&mut random, &filler, 20));
        text.push_str(&values[random.next_int(values.len())]);
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let first = values[0].clone();
    std::thread::spawn(move || {
        let matcher = mock_server::SensitiveValues::of(values);
        matcher.scrub(&text);
        let start = std::time::Instant::now();
        let scrubbed = matcher.scrub(&text);
        let _ = tx.send((start.elapsed(), scrubbed.contains(&first)));
    });
    // checking each of 10,000 values against 2 MB of text is about 2e10 character comparisons
    let (elapsed, leaked) = rx.recv_timeout(Duration::from_secs(20)).expect("scrubbing 2 MB against 10,000 values did not finish in 20 s");
    assert!(elapsed < Duration::from_secs(2), "scrubbed 2 MB against 10,000 values in {elapsed:?}");
    assert!(!leaked);
}

/// `distinctValues`: `count` distinct lower-case values of 6 to 20 letters.
fn distinct_values(random: &mut Random, count: usize) -> Vec<String> {
    let letters: Vec<char> = ('a'..='z').collect();
    let mut values = Vec::new();
    let mut seen = std::collections::HashSet::new();
    while values.len() < count {
        let length = 6 + random.next_int(15);
        let candidate = random_text(random, &letters, length);
        if seen.insert(candidate.clone()) && (count > 1_000 || values.iter().all(|e: &String| !e.contains(&candidate) && !candidate.contains(e.as_str()))) {
            values.push(candidate);
        }
    }
    values
}

/// `shouldNotSearchFreeTextForValuesBeyondItsBounds`: past `MAX_VALUES` the values given first are kept,
/// a value over `MAX_VALUE_LENGTH` is never searched for, and the drop is warned about (once per process).
#[test]
fn should_not_search_free_text_for_values_beyond_its_bounds() {
    let mut huge = String::new();
    while huge.len() <= 4 * 1024 {
        huge.push_str("0123456789");
    }
    let mut values = vec!["first-credential".to_string(), huge.clone()];
    let mut random = Random::new(11);
    values.extend(distinct_values(&mut random, 10_000 + 5_000));

    let matcher = mock_server::SensitiveValues::of(values);

    assert!(matcher.value_count() <= 10_000, "{} values kept", matcher.value_count());
    assert!(matcher.total_length() <= 256 * 1024, "{} characters kept", matcher.total_length());
    assert!(mock_server::SensitiveValues::truncation_warned());
    assert_eq!(matcher.scrub("a first-credential here"), format!("a {PLACEHOLDER} here"));
    assert_eq!(matcher.scrub(&huge), huge);
}

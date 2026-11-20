//! Every query of the dashboards in `grafana/` names a metric that a live scrape emits, so a panel never shows a
//! series the server does not produce.

use std::collections::BTreeSet;

/// PromQL keywords and aggregation operators (followed by `by (…)` as often as by `(`): never metric names.
const KEYWORDS: &[&str] = &["sum", "min", "max", "avg", "group", "stddev", "stdvar", "count", "count_values", "bottomk", "topk", "quantile", "limitk", "limit_ratio", "and", "or", "unless", "bool", "offset", "by", "without", "on", "ignoring", "group_left", "group_right", "inf", "nan"];

/// What a PromQL expression selects: its bare metric names and the regexes of its `__name__=~"…"` matchers (an exact
/// `__name__="…"` is a name).
#[derive(Debug, Default, PartialEq)]
struct Selectors {
    names: Vec<String>,
    name_regexes: Vec<String>,
}

/// The selectors of `expr`: string literals, label matchers, range and subquery brackets, `$variables` and the label
/// lists of `by`/`without`/`on`/`ignoring`/`group_*` are skipped; an identifier followed by `(` is a function.
fn selectors(expr: &str) -> Selectors {
    let chars: Vec<char> = expr.chars().collect();
    let mut out = Selectors::default();
    let mut i = 0;
    let skip_string = |i: &mut usize| {
        let quote = chars[*i];
        *i += 1;
        while *i < chars.len() && chars[*i] != quote {
            if chars[*i] == '\\' {
                *i += 1;
            }
            *i += 1;
        }
        *i += 1;
    };
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == ':';
    let name = regex::Regex::new(r#"__name__\s*(=~|=)\s*"((?:[^"\\]|\\.)*)""#).unwrap();
    while i < chars.len() {
        let c = chars[i];
        match c {
            '"' | '\'' | '`' => skip_string(&mut i),
            '{' => {
                let start = i + 1;
                while i < chars.len() && chars[i] != '}' {
                    if matches!(chars[i], '"' | '\'' | '`') {
                        skip_string(&mut i);
                    } else {
                        i += 1;
                    }
                }
                let matchers: String = chars[start..i.min(chars.len())].iter().collect();
                for m in name.captures_iter(&matchers) {
                    match &m[1] {
                        "=~" => out.name_regexes.push(m[2].to_string()),
                        _ => out.names.push(m[2].to_string()),
                    }
                }
                i += 1;
            }
            '[' => {
                while i < chars.len() && chars[i] != ']' {
                    i += 1;
                }
                i += 1;
            }
            '$' => {
                i += 1;
                while i < chars.len() && ident(chars[i]) {
                    i += 1;
                }
            }
            c if c.is_ascii_digit() || c == '.' => {
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '.') {
                    i += 1;
                }
            }
            c if ident(c) => {
                let start = i;
                while i < chars.len() && ident(chars[i]) {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                let mut next = i;
                while next < chars.len() && chars[next].is_whitespace() {
                    next += 1;
                }
                let call = next < chars.len() && chars[next] == '(';
                let keyword = KEYWORDS.contains(&word.to_ascii_lowercase().as_str());
                if call && ["by", "without", "on", "ignoring", "group_left", "group_right"].contains(&word.as_str()) {
                    // a label list: skip to its closing parenthesis
                    while i < chars.len() && chars[i] != ')' {
                        i += 1;
                    }
                    i += 1;
                } else if !keyword && !call {
                    out.names.push(word);
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// The selectors of a templating variable's query: `label_values(<selector>, <label>)` selects its first argument.
fn variable_selectors(query: &str) -> Selectors {
    let query = query.trim();
    match query.strip_prefix("label_values(").and_then(|q| q.strip_suffix(')')) {
        Some(args) => match args.rfind(',') {
            Some(comma) if !args[comma..].contains('}') => selectors(&args[..comma]),
            _ => selectors(args),
        },
        None => selectors(query),
    }
}

/// Every panel of a dashboard, rows' nested panels included.
fn panels(dashboard: &serde_json::Value) -> Vec<&serde_json::Value> {
    fn walk<'a>(list: &'a serde_json::Value, out: &mut Vec<&'a serde_json::Value>) {
        for panel in list.as_array().into_iter().flatten() {
            out.push(panel);
            walk(&panel["panels"], out);
        }
    }
    let mut out = Vec::new();
    walk(&dashboard["panels"], &mut out);
    out
}

/// What `selectors` asks for and `samples` (the scrape's sample names) does not have.
fn missing(selectors: &Selectors, samples: &BTreeSet<String>) -> Vec<String> {
    let mut out: Vec<String> = selectors.names.iter().filter(|n| !samples.contains(*n)).cloned().collect();
    for pattern in &selectors.name_regexes {
        let anchored = regex::Regex::new(&format!("^(?:{pattern})$")).unwrap();
        if !samples.iter().any(|s| anchored.is_match(s)) {
            out.push(format!("__name__=~\"{pattern}\""));
        }
    }
    out
}

/// The dashboard's problems against a scrape: a query naming a metric the scrape lacks, a query with no metric.
fn problems(file: &str, dashboard: &serde_json::Value, samples: &BTreeSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    for variable in dashboard["templating"]["list"].as_array().into_iter().flatten() {
        if variable["type"] != "query" {
            continue;
        }
        let query = variable["query"]["query"].as_str().or(variable["query"].as_str()).unwrap_or_default();
        let selected = variable_selectors(query);
        let lacking = missing(&selected, samples);
        if !lacking.is_empty() || selected == Selectors::default() {
            out.push(format!("{file}: variable {} `{query}` selects {lacking:?}, not on the scrape", variable["name"]));
        }
    }
    for panel in panels(dashboard) {
        let targets: Vec<&str> = panel["targets"].as_array().into_iter().flatten().filter_map(|t| t["expr"].as_str()).collect();
        if targets.is_empty() {
            continue;
        }
        let title = format!("{file}: panel {} {}", panel["id"], panel["title"]);
        let mut lacking = Vec::new();
        for expr in targets {
            let selected = selectors(expr);
            if selected == Selectors::default() {
                out.push(format!("{title}: `{expr}` names no metric"));
            }
            lacking.extend(missing(&selected, samples));
        }
        if !lacking.is_empty() {
            out.push(format!("{title}: {lacking:?} not on the scrape"));
        }
    }
    out
}

/// The sample names of a Prometheus text exposition.
fn sample_names(scrape: &str) -> BTreeSet<String> {
    scrape
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split(['{', ' ']).next().unwrap().to_string())
        .collect()
}

#[test]
fn selectors_of_the_dashboards_promql() {
    let names = |expr: &str| selectors(expr).names;
    assert_eq!(names(r#"sum(rate(mock_server_requests_received_total{job=~"$job", instance=~"$instance"}[$__rate_interval]))"#), ["mock_server_requests_received_total"]);
    assert_eq!(
        names(r#"histogram_quantile(0.95, sum by (le, upstream_host) (rate(a_bucket{x="by (y)"}[5m])))"#),
        ["a_bucket"],
        "by's label list and the quantile are not metrics"
    );
    assert_eq!(names(r#"sum(rate(a_count{e!=""}[1m])) / sum(rate(b_count[1m]))"#), ["a_count", "b_count"]);
    assert_eq!(names("time() - max(process_start_time_seconds)"), ["process_start_time_seconds"]);
    assert_eq!(names("100 * sum(x) / clamp_min(sum(y), 1) and on (instance) z"), ["x", "y", "z"]);
    assert_eq!(names("1e3 * deriv(m[5m:1m])"), ["m"]);
    let regexes = selectors(r#"{__name__=~".+_actions_count", job=~"$job"}"#);
    assert_eq!(regexes, Selectors { names: vec![], name_regexes: vec![".+_actions_count".into()] });
    assert_eq!(variable_selectors(r#"label_values(mock_server_build_info{job=~"$job"}, instance)"#).names, ["mock_server_build_info"]);
    assert_eq!(variable_selectors("label_values(mock_server_build_info, job)").names, ["mock_server_build_info"]);
}

#[test]
fn problems_name_missing_metrics() {
    let dashboard = serde_json::json!({
        "templating": {"list": [{"name": "job", "type": "query", "query": {"query": "label_values(gone, job)"}}]},
        "panels": [
            {"id": 1, "type": "row", "title": "r", "panels": [
                {"id": 2, "title": "ok", "targets": [{"expr": "sum(rate(here_total[1m]))"}]},
                {"id": 3, "title": "missing", "targets": [{"expr": "sum(gone)"}]},
            ]},
            {"id": 7, "title": "regex", "targets": [{"expr": "{__name__=~\".+_count\"}"}]},
        ],
    });
    let samples: BTreeSet<String> = ["here_total".to_string()].into();
    let found = problems("d.json", &dashboard, &samples);
    assert_eq!(
        found,
        [
            r#"d.json: variable "job" `label_values(gone, job)` selects ["gone"], not on the scrape"#,
            r#"d.json: panel 3 "missing": ["gone"] not on the scrape"#,
            r#"d.json: panel 7 "regex": ["__name__=~\".+_count\""] not on the scrape"#,
        ]
    );
}

/// A PUT with a JSON body on its own connection; the status line.
async fn put(port: u16, path: &str, body: &str) -> String {
    let response = super::http1(port, &format!("PUT {path} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len())).await;
    response.lines().next().unwrap_or_default().to_string()
}

/// One HTTP/1.1 GET over TLS (trusting any certificate); the status line.
async fn https_get(port: u16, path: &str) -> String {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(super::TrustAll))
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let mut stream = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await.expect("a TLS connection");
    stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read_to_end(&mut response)).await;
    String::from_utf8_lossy(&response).lines().next().unwrap_or_default().to_string()
}

/// A server with `metricsEnabled` serves HTTP/1.1, HTTP/2 and TLS traffic, a forward, HTTP and LLM chaos
/// faults, a dropped connection and a load run (scraped while it runs, so its gauges are there); every dashboard query
/// in `grafana/` names a sample of that scrape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dashboards_query_only_emitted_metrics() {
    let upstream = crate::Server::start(crate::Config::for_tests()).await.unwrap();
    let upstream_port = upstream.ports()[0];
    assert_eq!(put(upstream_port, "/mockserver/expectation", r#"{"httpRequest":{"path":"/fwd"},"httpResponse":{"body":"upstream"}}"#).await, "HTTP/1.1 201 Created");
    let config = crate::Config::for_tests()
        .with_property("metricsEnabled", "true")
        .with_property("loadGenerationEnabled", "true")
        .with_property("loadGenerationMaxRequestsPerSecond", "20");
    let server = crate::Server::start(config).await.unwrap();
    let port = server.ports()[0];
    let expectations = serde_json::json!([
        {"httpRequest": {"path": "/ok"}, "httpResponse": {"statusCode": 200, "body": "fine"}},
        {"httpRequest": {"path": "/fail"}, "httpResponse": {"statusCode": 503, "body": "unavailable"}},
        {"httpRequest": {"path": "/drop"}, "httpError": {"dropConnection": true}},
        {"httpRequest": {"path": "/chaos"}, "httpResponse": {"body": "fine"}, "chaos": {"errorStatus": 503, "errorProbability": 1.0}},
        {"httpRequest": {"path": "/llm"}, "httpLlmResponse": {"provider": "OPENAI", "model": "m1", "completion": {"text": "hello"}, "chaos": {"errorStatus": 503, "errorProbability": 1.0}}},
        {"httpRequest": {"path": "/fwd"}, "httpForward": {"host": "127.0.0.1", "port": upstream_port}},
    ]);
    assert_eq!(put(port, "/mockserver/expectation", &expectations.to_string()).await, "HTTP/1.1 201 Created");
    let get = async |path: &str| super::http1(port, &format!("GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n")).await;
    let r = get("/ok").await;
    assert!(r.starts_with("HTTP/1.1 200"), "/ok: {r}");
    let r = get("/unmatched").await;
    assert!(r.starts_with("HTTP/1.1 404"), "/unmatched: {r}");
    let r = get("/chaos").await;
    assert!(r.starts_with("HTTP/1.1 503"), "/chaos: {r}");
    let r = get("/fwd").await;
    assert!(r.starts_with("HTTP/1.1 200"), "/fwd: {r}");
    let llm = r#"{"model":"m1","messages":[{"role":"user","content":"hi"}]}"#;
    let llm = super::http1(port, &format!("POST /llm HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{llm}", llm.len())).await;
    assert!(llm.starts_with("HTTP/1.1 503"), "{llm}");
    assert_eq!(get("/drop").await, "", "dropped");
    assert_eq!(https_get(port, "/ok").await, "HTTP/1.1 200 OK");
    let io = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let h2 = crate::h2::send(io, "GET", &format!("localhost:{port}"), "/ok", &[], bytes::Bytes::new()).await.unwrap_or_else(|_| panic!("an HTTP/2 response"));
    assert_eq!(h2.status, 200);
    drop(h2);
    let target = serde_json::json!({"host": "127.0.0.1", "port": port, "scheme": "HTTP"});
    let scenario = serde_json::json!({
        "name": "dashboards",
        "profile": {"stages": [{"type": "VU", "vus": 2, "durationMillis": 3000}]},
        "steps": [
            {"request": {"method": "POST", "path": "/ok", "body": "payload", "socketAddress": target}},
            {"request": {"method": "GET", "path": "/fail", "socketAddress": target}},
        ],
    });
    let loaded = put(port, "/mockserver/loadScenario", &scenario.to_string()).await;
    assert!(loaded.starts_with("HTTP/1.1 20"), "{loaded}");
    assert_eq!(put(port, "/mockserver/loadScenario/start", r#"{"name":"dashboards"}"#).await, "HTTP/1.1 200 OK");
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let scrape = get("/mockserver/metrics").await;
    let _ = put(port, "/mockserver/loadScenario/stop", r#"{"name":"dashboards"}"#).await;
    server.shutdown().await;
    upstream.shutdown().await;
    let samples = sample_names(&scrape);
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("grafana");
    let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(Result::ok).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect();
    files.sort();
    assert!(files.len() >= 2, "{files:?}");
    let mut found = Vec::new();
    for path in &files {
        let dashboard: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        found.extend(problems(&path.file_name().unwrap().to_string_lossy(), &dashboard, &samples));
    }
    assert!(found.is_empty(), "{}\n\nscrape:\n{scrape}", found.join("\n"));
}

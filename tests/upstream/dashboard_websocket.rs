//! Ports of `DashboardWebSocketHandlerTest`'s live cases and `DashboardLogEntryDTORedactionTest`: the
//! dashboard push channel `/_mockserver_ui_websocket` against an in-process server. The frames themselves are compared
//! with the oracle by the `tests/scenarios/dashboard_websocket_*.json` scenarios.

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

use super::common;

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(port: u16) -> Socket {
    let (socket, response) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/_mockserver_ui_websocket")).await.expect("upgrade");
    assert_eq!(response.status().as_u16(), 101);
    socket
}

/// The next text frame within five seconds, as JSON.
async fn next(socket: &mut Socket) -> Value {
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), socket.next()).await.expect("a frame in time").expect("open").expect("frame") {
            Message::Text(text) => return serde_json::from_str(&text).expect("JSON"),
            _ => continue,
        }
    }
}

fn keys(frame: &Value) -> Vec<&str> {
    frame.as_object().unwrap().keys().map(String::as_str).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_pushes_a_frame_with_every_panel() {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/some/path"}, "httpResponse": {"body": "hello"}})).await;
    common::send(server.port, "GET", "/some/path", "").await;
    let mut socket = connect(server.port).await;
    let frame = next(&mut socket).await;
    assert_eq!(keys(&frame), ["logMessages", "activeExpectations", "activeExpectationsTotal", "activeExpectationsIncludeLlm", "recordedRequests"]);
    assert_eq!(frame["activeExpectationsTotal"], json!(1));
    assert_eq!(frame["activeExpectationsIncludeLlm"], json!(false));
    assert_eq!(frame["activeExpectations"][0]["value"]["httpResponse"], json!({"body": "hello"}));
    let recorded = &frame["recordedRequests"][0];
    assert_eq!(recorded["value"]["httpRequest"]["path"], json!("/some/path"));
    assert_eq!(recorded["value"]["httpResponse"], json!({"body": "hello"}));
    assert!(recorded["description"].as_str().unwrap().ends_with("/some/path"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_event_is_pushed_without_being_asked() {
    let server = common::start(&[]).await;
    let mut socket = connect(server.port).await;
    let first = next(&mut socket).await;
    assert!(first.get("activeExpectations").is_none());
    common::expect(server.port, &json!({"httpRequest": {"path": "/later"}, "httpResponse": {"body": "x"}})).await;
    let pushed = next(&mut socket).await;
    assert_eq!(pushed["activeExpectations"].as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn request_filter_narrows_events_and_expectations() {
    let server = common::start(&[]).await;
    for path in ["one", "two", "three"] {
        common::expect(server.port, &json!({"httpRequest": {"path": path}, "httpResponse": {"body": path}})).await;
    }
    common::send(server.port, "GET", "/somePathOne", "").await;
    common::send(server.port, "GET", "/somePathTwo", "").await;
    let mut socket = connect(server.port).await;
    let _ = next(&mut socket).await;
    socket.send(Message::text(r#"{"path":"one"}"#)).await.unwrap();
    let frame = next(&mut socket).await;
    let active = frame["activeExpectations"].as_array().unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0]["value"]["httpRequest"], json!({"path": "one"}));
    assert!(active[0]["description"].as_str().unwrap().ends_with(":   one"), "{}", active[0]["description"]);
    // events about the other requests are gone
    socket.send(Message::text(r#"{"path":"/somePathTwo"}"#)).await.unwrap();
    let frame = next(&mut socket).await;
    let recorded = frame["recordedRequests"].as_array().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0]["value"]["httpRequest"]["path"], json!("/somePathTwo"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_wrapped_in_http_request_is_unwrapped() {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "one"}, "httpResponse": {"body": "one"}})).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "two"}, "httpResponse": {"body": "two"}})).await;
    let mut socket = connect(server.port).await;
    let _ = next(&mut socket).await;
    socket.send(Message::text(r#"{"httpRequest":{"path":"two"}}"#)).await.unwrap();
    let frame = next(&mut socket).await;
    assert_eq!(frame["activeExpectations"].as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_request_matchers_are_answered_with_an_error() {
    let server = common::start(&[]).await;
    let mut socket = connect(server.port).await;
    let _ = next(&mut socket).await;
    let spec = "OpenAPI Specification: https://app.swaggerhub.com/apis/jamesdbloom/mock-server-openapi/9.2.x\nDocumentation: https://mock-server.com/mock_server/creating_expectations.html";
    socket.send(Message::text("")).await.unwrap();
    assert_eq!(next(&mut socket).await, json!({"error": format!("1 error:\n - a request is required but value was \"\"\n\n{spec}")}));
    socket.send(Message::text(r#"{"method":1}"#)).await.unwrap();
    let error = next(&mut socket).await["error"].as_str().unwrap().to_string();
    assert_eq!(
        error,
        format!("incorrect request json format for:\n\n  {{\"method\":1}}\n\n schema validation errors:\n\n  2 errors:\n   - $.method: integer found, string expected\n   - $.method: should be valid to one and only one schema, but 0 are valid\n  \n  {}\n  {}", spec.lines().next().unwrap(), spec.lines().nth(1).unwrap())
    );
    socket.send(Message::text("not json")).await.unwrap();
    let error = next(&mut socket).await["error"].as_str().unwrap().to_string();
    assert!(error.starts_with("incorrect request json format for:\n\n  not json\n\n schema validation errors:\n\n  JsonParseException - Unrecognized token 'not'"), "{error}");
    socket.send(Message::text(r#"{"httpRequest":"#)).await.unwrap();
    assert_eq!(next(&mut socket).await, json!({"error": "exception while parsing [{\"httpRequest\":] for HttpRequest"}));
}

#[tokio::test(flavor = "multi_thread")]
async fn ping_is_answered_with_pong_and_close_with_close() {
    let server = common::start(&[]).await;
    let mut socket = connect(server.port).await;
    socket.send(Message::Ping(b"hi".to_vec().into())).await.unwrap();
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), socket.next()).await.unwrap().unwrap().unwrap() {
            Message::Pong(payload) => {
                assert_eq!(&payload[..], b"hi");
                break;
            }
            _ => continue,
        }
    }
    socket.send(Message::Close(None)).await.unwrap();
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), socket.next()).await.unwrap() {
            Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
            _ => continue,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_over_http2_is_not_implemented() {
    let server = common::start(&[]).await;
    let response = common::exchange(server.port, common::Transport::Http2, "GET", "/_mockserver_ui_websocket", &[], "").await;
    assert_eq!(response.status, 501);
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_is_refused_without_control_plane_authentication() {
    let server = common::start(&[]).await;
    server.server.set_control_plane_authenticator(|_| None);
    let error = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}/_mockserver_ui_websocket", server.port)).await.expect_err("refused");
    match error {
        tokio_tungstenite::tungstenite::Error::Http(response) => assert_eq!(response.status().as_u16(), 401),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_is_allowed_with_control_plane_authentication() {
    let server = common::start(&[]).await;
    server.server.set_control_plane_authenticator(|_| Some(vec![]));
    let _ = connect(server.port).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_is_allowed_when_no_authentication_is_configured() {
    let server = common::start(&[]).await;
    let _ = connect(server.port).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_version_is_answered_426() {
    let server = common::start(&[]).await;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port)).await.unwrap();
    stream
        .write_all(b"GET /_mockserver_ui_websocket HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 5\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 256];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&buf[..n]), "HTTP/1.1 426 Upgrade Required\r\nsec-websocket-version: 13\r\ncontent-length: 0\r\n\r\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handshake_that_is_not_one_closes_without_an_answer() {
    let server = common::start(&[]).await;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port)).await.unwrap();
    stream.write_all(b"POST /_mockserver_ui_websocket HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\n\r\n").await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert!(buf.is_empty());
}

// --- DashboardLogEntryDTORedactionTest ----------------------------------------------------------------------------------

async fn secure_frame(redact: bool) -> Value {
    let server = common::start(&[("redactSecretsInLog", if redact { "true" } else { "false" })]).await;
    common::expect(
        server.port,
        &json!({"httpRequest": {"path": "/secure"}, "httpResponse": {"headers": {"Set-Cookie": ["session=secret-session-value"]}, "body": "{\"ok\":true}"}}),
    )
    .await;
    let response = common::exchange(
        server.port,
        common::Transport::Http,
        "GET",
        "/secure",
        &[("Authorization", "Bearer super-secret-token"), ("x-api-key", "secret-api-key")],
        "",
    )
    .await;
    assert_eq!(response.status, 200);
    let mut socket = connect(server.port).await;
    next(&mut socket).await
}

#[tokio::test(flavor = "multi_thread")]
async fn redaction_enabled_masks_the_dashboard_view() {
    let frame = secure_frame(true).await;
    let recorded = frame["recordedRequests"][0]["value"].to_string();
    assert!(!recorded.contains("super-secret-token") && !recorded.contains("secret-api-key"), "{recorded}");
    assert!(!recorded.contains("secret-session-value"), "{recorded}");
    assert!(recorded.contains("REDACTED"), "{recorded}");
}

#[tokio::test(flavor = "multi_thread")]
async fn redaction_disabled_leaves_the_dashboard_view_unchanged() {
    let recorded = secure_frame(false).await["recordedRequests"][0]["value"].to_string();
    assert!(recorded.contains("super-secret-token") && recorded.contains("secret-session-value"), "{recorded}");
}

#[tokio::test(flavor = "multi_thread")]
async fn redaction_does_not_touch_the_live_log_entry() {
    let server = common::start(&[("redactSecretsInLog", "true")]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/secure"}, "httpResponse": {"body": "x"}})).await;
    common::exchange(server.port, common::Transport::Http, "GET", "/secure", &[("Authorization", "Bearer super-secret-token")], "").await;
    let mut socket = connect(server.port).await;
    let _ = next(&mut socket).await;
    // matching and verification still see the raw value
    let verified = common::send(
        server.port,
        "PUT",
        "/mockserver/verify",
        &json!({"httpRequest": {"path": "/secure", "headers": {"Authorization": ["Bearer super-secret-token"]}}, "times": {"atLeast": 1}}).to_string(),
    )
    .await;
    assert_eq!(verified.status, 202, "{}", verified.body);
}

// --- logLevelOverrides, socket addresses, throwables, change notification -------------------------------

/// The style colour of every log entry in a frame, groups flattened (a group's header repeats its first entry).
fn log_colours(frame: &Value) -> Vec<String> {
    fn walk(items: &[Value], out: &mut Vec<String>) {
        for item in items {
            if item.get("group").is_some() {
                walk(item["value"].as_array().unwrap(), out);
            } else {
                out.push(item["value"]["style"]["color"].as_str().unwrap_or_default().to_string());
            }
        }
    }
    let mut out = Vec::new();
    walk(frame["logMessages"].as_array().unwrap(), &mut out);
    out
}

const RECEIVED_REQUEST: &str = "rgb(114,160,193)";
const EXPECTATION_RESPONSE: &str = "rgb(161,208,231)";
const EXPECTATION_MATCHED: &str = "rgb(117,185,186)";
const CREATED_EXPECTATION: &str = "rgb(216,199,166)";

async fn traffic_frame(properties: &[(&str, &str)]) -> Value {
    let server = common::start(properties).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/a"}, "httpResponse": {"body": "x"}})).await;
    common::send(server.port, "GET", "/a", "").await;
    let mut socket = connect(server.port).await;
    next(&mut socket).await
}

#[tokio::test(flavor = "multi_thread")]
async fn log_level_overrides_hide_entries_below_the_effective_level() {
    // `DashboardWebSocketHandler.sendUpdate`'s predicate: an INFO entry is hidden once its type (RECEIVED_REQUEST) or its
    // category (MATCHING) is overridden to a higher level; the other entries keep the global level.
    let frame = traffic_frame(&[("logLevelOverrides", r#"{"MATCHING":"ERROR","RECEIVED_REQUEST":"WARN"}"#)]).await;
    let colours = log_colours(&frame);
    assert!(!colours.iter().any(|c| c == RECEIVED_REQUEST || c == EXPECTATION_MATCHED), "{colours:?}");
    assert!(colours.iter().any(|c| c == EXPECTATION_RESPONSE) && colours.iter().any(|c| c == CREATED_EXPECTATION), "{colours:?}");
    // the panels are built from the same filtered stream (the oracle's frame has no recordedRequests either)
    assert!(frame.get("recordedRequests").is_none(), "{frame}");
}

#[tokio::test(flavor = "multi_thread")]
async fn log_level_overrides_keys_are_case_insensitive_and_bad_levels_ignored() {
    let frame = traffic_frame(&[("logLevelOverrides", r#"{"received_request":"warn","matching":"nonsense"}"#)]).await;
    let colours = log_colours(&frame);
    assert!(!colours.iter().any(|c| c == RECEIVED_REQUEST), "{colours:?}");
    assert!(colours.iter().any(|c| c == EXPECTATION_MATCHED), "{colours:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn log_level_override_off_is_not_a_level() {
    // `LogMessageTypeCategory.VALID_LEVELS` holds `org.slf4j.event.Level`'s values, which have no OFF: the entry is dropped and
    // RECEIVED_REQUEST keeps the global level, as on the console (process scenario `log_level_overrides_off_is_not_a_level`).
    let frame = traffic_frame(&[("logLevelOverrides", r#"{"RECEIVED_REQUEST":"OFF","MATCHING":"off"}"#)]).await;
    let colours = log_colours(&frame);
    assert!(colours.iter().any(|c| c == RECEIVED_REQUEST) && colours.iter().any(|c| c == EXPECTATION_MATCHED), "{colours:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn log_level_overrides_set_at_runtime_reach_the_dashboard() {
    // The dashboard reads `HttpState`'s configuration, which a `PUT` now reaches (upstream 0e8566814). The 8.0.0
    // process read only the value it started with, as for redactSecretsInLog.
    let server = common::start(&[]).await;
    let put = common::send(server.port, "PUT", "/mockserver/configuration", r#"{"logLevelOverrides":{"RECEIVED_REQUEST":"ERROR"}}"#).await;
    assert_eq!(put.status, 200, "{}", put.body);
    common::expect(server.port, &json!({"httpRequest": {"path": "/a"}, "httpResponse": {"body": "x"}})).await;
    common::send(server.port, "GET", "/a", "").await;
    let mut socket = connect(server.port).await;
    let colours = log_colours(&next(&mut socket).await);
    assert!(!colours.iter().any(|c| c == RECEIVED_REQUEST), "{colours:?}");
    assert!(colours.iter().any(|c| c == EXPECTATION_MATCHED), "{colours:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn log_level_overrides_in_the_properties_file_do_not_reach_the_dashboard() {
    // Recorded on the oracle (8.0.0) with a mounted properties file: a file-tier `logLevelOverrides` hides nothing on
    // the dashboard (CREATED_EXPECTATION is shown), while `MOCKSERVER_LOG_LEVEL_OVERRIDES` with the same value hides it.
    let overrides = r#"{"CREATED_EXPECTATION":"ERROR","RECEIVED_REQUEST":"ERROR"}"#;
    for (file, expected_shown) in [(true, true), (false, false)] {
        let mut config = mock_server::Config::for_tests();
        config = if file { config.with_property_file_text(&format!("mockserver.logLevelOverrides={overrides}\n")) } else { config.with_env("MOCKSERVER_LOG_LEVEL_OVERRIDES", overrides) };
        crate::scratch_cwd::enter();
        let server = mock_server::Server::start(config).await.unwrap();
        let port = server.ports()[0];
        common::expect(port, &json!({"httpRequest": {"path": "/a"}, "httpResponse": {"body": "x"}})).await;
        common::send(port, "GET", "/a", "").await;
        let mut socket = connect(port).await;
        let colours = log_colours(&next(&mut socket).await);
        assert_eq!(colours.iter().any(|c| c == CREATED_EXPECTATION || c == RECEIVED_REQUEST), expected_shown, "file={file}: {colours:?}");
    }
}

/// Every message part in a frame's log (groups flattened), as JSON.
fn message_parts(frame: &Value) -> Vec<Value> {
    fn walk(items: &[Value], out: &mut Vec<Value>) {
        for item in items {
            if item.get("group").is_some() {
                walk(item["value"].as_array().unwrap(), out);
            } else {
                out.extend(item["value"]["messageParts"].as_array().cloned().unwrap_or_default());
            }
        }
    }
    let mut out = Vec::new();
    walk(frame["logMessages"].as_array().unwrap(), &mut out);
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn a_socket_address_argument_is_shown_as_json() {
    // `BinaryRequestProxyingHandler`'s "returning binary response:{}from:{}..." logs the upstream's `InetSocketAddress`, which
    // is neither a String nor a NottableString: the dashboard marks it `json: true` (oracle: value "host:port").
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut socket, _) = upstream.accept().await.unwrap();
        let mut buffer = [0u8; 64];
        let n = socket.read(&mut buffer).await.unwrap();
        socket.write_all(&buffer[..n]).await.unwrap();
    });
    let mut config = mock_server::Config::for_tests();
    config.port_forward = Some(("127.0.0.1".into(), upstream_port));
    crate::scratch_cwd::enter();
    let server = mock_server::Server::start(config).await.unwrap();
    let port = server.ports()[0];
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).await.unwrap();
        let mut echoed = [0u8; 10];
        client.read_exact(&mut echoed).await.unwrap();
    }
    let mut socket = connect(port).await;
    let parts = message_parts(&next(&mut socket).await);
    let address = parts.iter().find(|p| p["value"] == json!(format!("127.0.0.1:{upstream_port}"))).unwrap_or_else(|| panic!("{parts:?}"));
    assert_eq!(address["json"], json!(true), "{address}");
    assert_eq!(address["argument"], json!(true));
    assert!(address.get("multiline").is_none(), "{address}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_throwable_is_shown_after_the_message() {
    // Oracle: "exception:" then the stack trace as lines. Only its first lines (the exception, its cause) are reproduced;
    // the JVM's frames are not (docs/divergences.md).
    // a port that refuses: a bound-then-released one can be handed straight back to the server below
    let dead_port = crate::tcp_port::dead_port();
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/refused"}, "httpForward": {"host": "127.0.0.1", "port": dead_port}})).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/missing"}, "httpResponseClassCallback": {"callbackClass": "no.Such"}})).await;
    assert_eq!(common::send(server.port, "GET", "/refused", "").await.status, 502);
    assert_eq!(common::send(server.port, "GET", "/missing", "").await.status, 404);
    let mut socket = connect(server.port).await;
    let parts = message_parts(&next(&mut socket).await);
    let traces: Vec<(&Value, &Value)> = parts
        .iter()
        .enumerate()
        .filter(|(_, p)| p["key"].as_str().is_some_and(|k| k.ends_with("_throwable_msg")))
        .map(|(i, p)| (p, &parts[i + 1]))
        .collect();
    // since 9.1.0 a refused forward is a named cause (upstream 48b7e14d2): logged at TRACE only, so no entry of it
    // carries a throwable; the missing class's does
    assert_eq!(traces.len(), 1, "{parts:?}");
    for (label, value) in &traces {
        assert_eq!(label["value"], json!("exception:"));
        assert!(value["key"].as_str().unwrap().ends_with("_throwable_value"), "{value}");
        assert_eq!((value["multiline"].clone(), value["argument"].clone()), (json!(true), json!(true)));
    }
    let lines: Vec<Vec<String>> = traces.iter().map(|(_, v)| v["value"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().to_string()).collect()).collect();
    assert_eq!(lines, vec![vec!["java.lang.ClassNotFoundException: no.Such".to_string()]], "{lines:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_log_json_does_not_gain_the_dashboards_extra_keys() {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/missing"}, "httpResponseClassCallback": {"callbackClass": "no.Such"}})).await;
    common::send(server.port, "GET", "/missing", "").await;
    let log = common::send(server.port, "PUT", "/mockserver/retrieve?type=LOGS&format=LOG_ENTRIES", "").await.body;
    assert!(!log.contains("$throwable") && !log.contains("$objectArguments"), "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn pushes_follow_changes_without_polling_and_at_most_once_a_second() {
    // The first frame follows the upgrade; a change is pushed at once, and the changes that follow it are held to the
    // connection's one frame a second and coalesced into the last state (upstream's semaphore).
    let server = common::start(&[]).await;
    let mut socket = connect(server.port).await;
    let first = next(&mut socket).await;
    assert!(first.get("activeExpectations").is_none());
    let started = std::time::Instant::now();
    for path in ["/one", "/two", "/three"] {
        common::expect(server.port, &json!({"httpRequest": {"path": path}, "httpResponse": {"body": "x"}})).await;
    }
    let mut seen = 0;
    while seen < 3 {
        let frame = next(&mut socket).await;
        seen = frame["activeExpectations"].as_array().map_or(0, Vec::len);
    }
    let elapsed = started.elapsed();
    assert!(elapsed < std::time::Duration::from_millis(2500), "{elapsed:?}");
    // nothing further is pushed while nothing changes
    let quiet = tokio::time::timeout(std::time::Duration::from_millis(1500), socket.next()).await;
    assert!(quiet.is_err(), "unexpected frame: {quiet:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn null_is_answered_with_the_schema_error_and_the_body_is_echoed_untrimmed() {
    // `null` has one code path: the schema validator's "null found, object expected". The oracle's occasional silence
    // for it is the dashboard's per-connection semaphore dropping the reply (see `dashboard::THROTTLE`), not another
    // path. The echo keeps trailing whitespace (`formatLogMessage` over the body as received; oracle).
    let server = common::start(&[]).await;
    let mut socket = connect(server.port).await;
    let _ = next(&mut socket).await;
    for (sent, echoed, found) in [
        ("null", "  null\n\n", "null found"),
        (" null ", "   null \n\n", "null found"),
        ("{\"httpRequest\":null}", "  null\n\n", "null found"),
        ("[]", "  []\n\n", "array found"),
        ("{\"method\":1} ", "  {\"method\":1} \n\n", ""),
        ("{\"method\":1}\n", "  {\"method\":1}\n\n\n", ""),
        ("{\"method\":1}\n\n", "  {\"method\":1}\n  \n\n\n", ""),
    ] {
        socket.send(Message::text(sent)).await.unwrap();
        let error = next(&mut socket).await["error"].as_str().unwrap().to_string();
        assert!(error.starts_with(&format!("incorrect request json format for:\n\n{echoed} schema validation errors:\n\n")), "{sent:?}: {error:?}");
        assert!(error.contains(found), "{sent:?}: {error:?}");
        assert!(error.ends_with("Documentation: https://mock-server.com/mock_server/creating_expectations.html"), "{sent:?}: {error:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_matcher_is_logged_and_pushed_with_its_exception() {
    // `JsonSchemaValidator.isValid` and `HttpRequestSerializer.deserialize` log what they throw; the log change is pushed.
    let server = common::start(&[]).await;
    let mut socket = connect(server.port).await;
    let _ = next(&mut socket).await;
    socket.send(Message::text("not json")).await.unwrap();
    assert!(next(&mut socket).await["error"].as_str().unwrap().contains("JsonParseException - Unrecognized token 'not'"));
    socket.send(Message::text(r#"{"httpRequest":"#)).await.unwrap();
    assert!(next(&mut socket).await["error"].as_str().unwrap().starts_with("exception while parsing ["));
    let mut parts = Vec::new();
    for _ in 0..3 {
        parts = message_parts(&next(&mut socket).await);
        if parts.iter().any(|p| p["value"] == json!("exception validating JSON")) && parts.iter().any(|p| p["value"].as_str().is_some_and(|v| v.starts_with("for HttpRequest Unexpected end-of-input"))) {
            break;
        }
    }
    let traces: Vec<Vec<String>> = parts
        .iter()
        .filter(|p| p["key"].as_str().is_some_and(|k| k.ends_with("_throwable_value")))
        .map(|p| p["value"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().to_string()).collect())
        .collect();
    assert!(traces.iter().any(|t| t[0].starts_with("shaded_package.com.fasterxml.jackson.core.JsonParseException: Unrecognized token 'not'") && t[1].starts_with(" at [Source: REDACTED")), "{traces:?}");
    assert!(traces.iter().any(|t| t[0].starts_with("shaded_package.com.fasterxml.jackson.core.io.JsonEOFException: Unexpected end-of-input")), "{traces:?}");
    let argument = parts.iter().find(|p| p["value"] == json!("\"{\"httpRequest\":\"")).unwrap_or_else(|| panic!("{parts:?}"));
    assert_eq!(argument["multiline"], json!(false));
}

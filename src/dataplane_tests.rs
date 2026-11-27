//! The bytes a stored response is written as, and the log lines that quote it, pinned for the shapes whose response
//! and logged form are shared from request to request rather than built for each.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Everything the server writes on one connection for `requests`, the last of which asks to close it.
async fn exchange(port: u16, requests: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(requests.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read_to_end(&mut response)).await;
    String::from_utf8(response).unwrap()
}

async fn put(port: u16, path: &str, body: &str) -> String {
    exchange(port, &format!("PUT {path} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len())).await
}

const HEADERS: &str = r#"{"Content-Type":["application/json"],"Cache-Control":["no-cache, no-store"],"ETag":["\"33a64df551425fcc\""],"X-Request-Id":["5d6f1b0e"],"Vary":["Accept-Encoding"]}"#;

/// The bench's `headers` row in small: headers in the order and case given, a JSON body; any method, so that a `HEAD`
/// matches it too.
fn headers_row(path: &str, id: &str) -> String {
    format!(
        r#"{{"httpRequest":{{"path":"{path}"}},"httpResponse":{{"statusCode":200,"headers":{HEADERS},"body":{{"type":"JSON","json":{{"customer":{{"id":"{id}","tier":"gold","addresses":[{{"line1":"1 Example Street","primary":true}}]}}}}}}}}}}"#
    )
}

const BODY: &str = "{\n  \"customer\" : {\n    \"id\" : \"e0\",\n    \"tier\" : \"gold\",\n    \"addresses\" : [ {\n      \"line1\" : \"1 Example Street\",\n      \"primary\" : true\n    } ]\n  }\n}";

fn head(connection: &str, length: usize) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-cache, no-store\r\nETag: \"33a64df551425fcc\"\r\nX-Request-Id: 5d6f1b0e\r\nVary: Accept-Encoding\r\nconnection: {connection}\r\ncontent-length: {length}\r\n\r\n"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_json_response_with_headers_is_written_the_same_for_every_request() {
    let server = crate::Server::start(crate::Config::for_tests()).await.unwrap();
    let port = server.ports()[0];
    assert!(put(port, "/mockserver/expectation", &format!("[{},{}]", headers_row("/e0", "e0"), headers_row("/e1", "e1"))).await.starts_with("HTTP/1.1 201"));
    let get = |path: &str, connection: &str| format!("GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: {connection}\r\n\r\n");
    // kept alive, then again, then closed: the same bytes but for the connection header
    let written = exchange(port, &format!("{}{}{}", get("/e0", "keep-alive"), get("/e0", "keep-alive"), get("/e0", "close"))).await;
    let keep_alive = format!("{}{BODY}", head("keep-alive", BODY.len()));
    assert_eq!(written, format!("{keep_alive}{keep_alive}{}{BODY}", head("close", BODY.len())));
    // HEAD: the head a GET has, its content-length the body's, and no body
    let written = exchange(port, &format!("HEAD /e0 HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n")).await;
    assert_eq!(written, head("close", BODY.len()));
    // the other expectation's response is its own
    let written = exchange(port, &get("/e1", "close")).await;
    assert_eq!(written, format!("{}{}", head("close", BODY.len()), BODY.replace("\"e0\"", "\"e1\"")));
    server.shutdown().await;
}

/// A JSON body's media type: without a `Content-Type` header the body's own (with its charset) is written after
/// `connection`; a `charset` on the body names the encoding of the bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_json_body_names_its_content_type_and_charset() {
    let server = crate::Server::start(crate::Config::for_tests()).await.unwrap();
    let port = server.ports()[0];
    let expectations = r#"[
        {"httpRequest":{"path":"/plain"},"httpResponse":{"headers":{"X-A":["1"]},"body":{"type":"JSON","json":{"name":"é"}}}},
        {"httpRequest":{"path":"/latin"},"httpResponse":{"body":{"type":"JSON","json":{"name":"é"},"contentType":"application/json; charset=ISO-8859-1"}}}
    ]"#;
    assert!(put(port, "/mockserver/expectation", expectations).await.starts_with("HTTP/1.1 201"));
    let get = |path: &str| format!("GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n");
    let body = "{\n  \"name\" : \"é\"\n}";
    let written = exchange(port, &get("/plain")).await;
    assert_eq!(
        written,
        format!("HTTP/1.1 200 OK\r\nX-A: 1\r\nconnection: close\r\ncontent-type: application/json; charset=utf-8\r\ncontent-length: {}\r\n\r\n{body}", body.len())
    );
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(get("/latin").as_bytes()).await.unwrap();
    let mut written = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read_to_end(&mut written)).await;
    let latin: Vec<u8> = body.chars().map(|c| c as u32 as u8).collect();
    let mut expected = format!("HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-type: application/json; charset=iso-8859-1\r\ncontent-length: {}\r\n\r\n", latin.len()).into_bytes();
    expected.extend_from_slice(&latin);
    assert_eq!(String::from_utf8_lossy(&written), String::from_utf8_lossy(&expected));
    server.shutdown().await;
}

/// The writer's headers (CORS for all responses, `defaultResponseHeaders`) are added to the shared response for one
/// request without changing it for the next, nor what the log shows for an earlier one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writer_headers_leave_the_stored_response_as_it_was() {
    let config = crate::Config::for_tests().with_property("enableCORSForAllResponses", "true").with_property("defaultResponseHeaders", "X-Default=d");
    let server = crate::Server::start(config).await.unwrap();
    let port = server.ports()[0];
    assert!(put(port, "/mockserver/expectation", &format!("[{}]", headers_row("/e0", "e0"))).await.starts_with("HTTP/1.1 201"));
    let get = |origin: &str| format!("GET /e0 HTTP/1.1\r\nHost: localhost:{port}\r\nOrigin: {origin}\r\nConnection: close\r\n\r\n");
    for origin in ["https://a.example", "https://b.example"] {
        let written = exchange(port, &get(origin)).await;
        let (head, body) = written.split_once("\r\n\r\n").unwrap();
        assert_eq!(body, BODY);
        assert!(head.contains(&format!("\r\naccess-control-allow-origin: {origin}\r\n")), "{head}");
        assert!(head.contains("\r\nVary: Accept-Encoding\r\naccess-control-allow-origin: "), "the model's headers come first: {head}");
        assert!(head.contains("\r\nX-Default: d\r\nconnection: close\r\ncontent-length: "), "{head}");
    }
    // each request's response as logged carries its own origin
    let answer = put(port, "/mockserver/retrieve?type=REQUEST_RESPONSES", r#"{"path":"/e0"}"#).await;
    let (_, logged) = answer.split_once("\r\n\r\n").unwrap();
    let a = logged.find("\"access-control-allow-origin\" : [ \"https://a.example\" ]").expect("the first origin is logged");
    let b = logged.find("\"access-control-allow-origin\" : [ \"https://b.example\" ]").expect("the second origin is logged");
    assert!(a < b);
    assert_eq!(logged.matches("access-control-allow-origin").count(), 2, "{logged}");
    assert_eq!(logged.matches("\"X-Default\" : [ \"d\" ]").count(), 2, "{logged}");
    server.shutdown().await;
}

/// A template's response is rendered for each request: none of it is shared between requests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_template_response_follows_each_request() {
    let server = crate::Server::start(crate::Config::for_tests()).await.unwrap();
    let port = server.ports()[0];
    let expectation = r#"{"httpRequest":{"path":"/t/.*"},"httpResponseTemplate":{"templateType":"VELOCITY","template":"{ \"statusCode\": 200, \"headers\": { \"X-Path\": [\"$request.path\"] }, \"body\": \"$request.path\" }"}}"#;
    assert!(put(port, "/mockserver/expectation", expectation).await.starts_with("HTTP/1.1 201"));
    for path in ["/t/a", "/t/bb"] {
        let written = exchange(port, &format!("GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n")).await;
        assert_eq!(written, format!("HTTP/1.1 200 OK\r\nX-Path: {path}\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{path}", path.len()));
    }
    server.shutdown().await;
}

/// The `returning response` line of a stored response quotes the response and the action, the same text for every
/// request that is served it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_returning_response_line_quotes_the_stored_response() {
    let server = crate::Server::start(crate::Config::for_tests()).await.unwrap();
    let port = server.ports()[0];
    assert!(put(port, "/mockserver/expectation", &format!("[{}]", headers_row("/e0", "e0"))).await.starts_with("HTTP/1.1 201"));
    let get = format!("GET /e0 HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n");
    exchange(port, &get).await;
    exchange(port, &get).await;
    let logs = put(port, "/mockserver/retrieve?type=LOGS", r#"{"path":"/e0"}"#).await;
    // the headers in the order the log prints them (a `HashMap`'s), the body bare
    let response = "{\n  \"statusCode\" : 200,\n  \"headers\" : {\n    \"X-Request-Id\" : [ \"5d6f1b0e\" ],\n    \"Vary\" : [ \"Accept-Encoding\" ],\n    \"ETag\" : [ \"\\\"33a64df551425fcc\\\"\" ],\n    \"Content-Type\" : [ \"application/json\" ],\n    \"Cache-Control\" : [ \"no-cache, no-store\" ]\n  },\n  \"body\" : {\n    \"customer\" : {\n      \"id\" : \"e0\",\n      \"tier\" : \"gold\",\n      \"addresses\" : [ {\n        \"line1\" : \"1 Example Street\",\n        \"primary\" : true\n      } ]\n    }\n  }\n}";
    let line = format!("returning response:\n\n  {}\n\n for request:", response.replace('\n', "\n  "));
    assert_eq!(logs.matches(&line).count(), 2, "{logs}");
    let action = format!(" for action:\n\n  {}\n\n from expectation:", response.replace('\n', "\n  "));
    assert_eq!(logs.matches(&action).count(), 2, "{logs}");
    server.shutdown().await;
}

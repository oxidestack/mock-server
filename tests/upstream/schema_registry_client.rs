//! `SchemaRegistryClientTest` (mockserver-async): the Schema Registry client against an in-process server playing
//! the registry, where the original stubs the JDK `HttpClient`; the requests it made are read back with
//! `retrieve?type=REQUESTS`.

use mock_server::asyncapi::registry::SchemaRegistryClient;
use serde_json::json;

use crate::common;

const AVRO_SCHEMA: &str = r#"{"type":"record","name":"Order","fields":[{"name":"orderId","type":"int"}]}"#;

async fn registry(method: &str, path: &str, status: u16, body: &str) -> common::Running {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"method": method, "path": path}, "httpResponse": {"statusCode": status, "body": body}})).await;
    server
}

async fn requests(port: u16) -> Vec<serde_json::Value> {
    serde_json::from_str(&common::send(port, "PUT", "/mockserver/retrieve?type=REQUESTS", "").await.body).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn should_get_schema_by_id() {
    let server = registry("GET", "/schemas/ids/5", 200, &json!({"schema": AVRO_SCHEMA}).to_string()).await;
    let client = SchemaRegistryClient::new(&format!("http://127.0.0.1:{}/", server.port)).unwrap();
    assert_eq!(client.schema_by_id(5).await.unwrap(), AVRO_SCHEMA);
    let sent = requests(server.port).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["method"], "GET");
    assert_eq!(sent[0]["path"], "/schemas/ids/5");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_cache_schema_by_id() {
    let server = registry("GET", "/schemas/ids/9", 200, &json!({"schema": AVRO_SCHEMA}).to_string()).await;
    let client = SchemaRegistryClient::new(&format!("http://127.0.0.1:{}/", server.port)).unwrap();
    client.schema_by_id(9).await.unwrap();
    client.schema_by_id(9).await.unwrap();
    assert_eq!(requests(server.port).await.len(), 1, "second call served from cache: only one HTTP round-trip");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_register_schema_and_return_id() {
    let server = registry("POST", "/subjects/orders-value/versions", 200, r#"{"id":100007}"#).await;
    let client = SchemaRegistryClient::new(&format!("http://127.0.0.1:{}/", server.port)).unwrap();
    assert_eq!(client.register("orders-value", AVRO_SCHEMA).await.unwrap(), 100007);
    let sent = requests(server.port).await;
    assert_eq!(sent[0]["method"], "POST");
    assert_eq!(sent[0]["path"], "/subjects/orders-value/versions");
    assert_eq!(sent[0]["body"]["json"], json!({"schema": AVRO_SCHEMA, "schemaType": "AVRO"}));
}

#[tokio::test(flavor = "multi_thread")]
async fn should_url_encode_subject_containing_slash() {
    let server = registry("POST", "/subjects/acme%2Forders-value/versions", 200, r#"{"id":13}"#).await;
    let client = SchemaRegistryClient::new(&format!("http://127.0.0.1:{}/", server.port)).unwrap();
    assert_eq!(client.register("acme/orders-value", AVRO_SCHEMA).await.unwrap(), 13, "the '/' in the subject stays inside one path segment");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_cache_registration() {
    let server = registry("POST", "/subjects/orders-value/versions", 200, r#"{"id":42}"#).await;
    let client = SchemaRegistryClient::new(&format!("http://127.0.0.1:{}/", server.port)).unwrap();
    client.register("orders-value", AVRO_SCHEMA).await.unwrap();
    client.register("orders-value", AVRO_SCHEMA).await.unwrap();
    assert_eq!(requests(server.port).await.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_throw_on_non200_getting_schema() {
    let server = registry("GET", "/schemas/ids/999", 404, r#"{"error_code":40403}"#).await;
    let client = SchemaRegistryClient::new(&format!("http://127.0.0.1:{}/", server.port)).unwrap();
    let error = client.schema_by_id(999).await.unwrap_err();
    assert_eq!(error.message, r#"Schema Registry returned status 404 for schema id 999: {"error_code":40403}"#);
}

#[test]
fn should_reject_blank_base_url() {
    assert!(SchemaRegistryClient::new("  ").is_err());
}

// ---- Against a registry stand-in: what the JDK `HttpClient` does that the stubbed original cannot show ----

/// A registry stand-in on a loopback port, serving each connection with `serve` on a thread of its own.
fn stand_in(serve: fn(std::net::TcpStream, String)) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            std::thread::spawn(move || {
                use std::io::Read;
                // The request head, then as much body as it announces.
                let mut data = Vec::new();
                let mut byte = [0u8; 1];
                while !data.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    data.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&data).into_owned();
                let length = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap())).unwrap_or(0);
                let mut body = vec![0u8; length];
                stream.read_exact(&mut body).unwrap();
                serve(stream, head);
            });
        }
    });
    port
}

/// A schema answer whose body is `size` bytes of schema text and more.
fn large_schema(size: usize) -> String {
    format!(r#"{{"schema":"{}"}}"#, "x".repeat(size))
}

/// Takes the `h2c` upgrade as an HTTP/2 server does: `101`, then the preface and SETTINGS exchange, and the answer to
/// the upgraded request on stream 1 (a schema of 100000 bytes, over the default 65535-byte connection window, so it
/// arrives only as the client's WINDOW_UPDATEs open the window).
fn upgrading_registry(mut stream: std::net::TcpStream, head: String) {
    use std::io::{Read, Write};
    assert!(head.contains("Upgrade: h2c\r\n"), "{head}");
    let frame = |kind: u8, flags: u8, id: u32, payload: &[u8]| {
        let mut out = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        out.extend([kind, flags]);
        out.extend(id.to_be_bytes());
        out.extend_from_slice(payload);
        out
    };
    stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n").unwrap();
    let mut preface = [0u8; 24];
    stream.read_exact(&mut preface).unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    stream.write_all(&frame(0x4, 0, 0, &[])).unwrap();
    let body = if head.starts_with("POST") { r#"{"id":77}"#.to_string() } else { large_schema(100_000) };
    let mut body = body.as_bytes();
    let mut window: i64 = 65535;
    let mut answered = false;
    loop {
        let mut header = [0u8; 9];
        if stream.read_exact(&mut header).is_err() {
            return;
        }
        let mut payload = vec![0u8; u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize];
        stream.read_exact(&mut payload).unwrap();
        let id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
        match header[3] {
            0x4 if header[4] & 1 == 0 => stream.write_all(&frame(0x4, 1, 0, &[])).unwrap(),
            0x8 if id == 0 => window += u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as i64,
            _ => {}
        }
        if !answered {
            // `:status: 200` (static index 8) and a literal `content-type` (static name 31).
            let mut block = vec![0x88, 0x0f, 0x10, 16];
            block.extend_from_slice(b"application/json");
            stream.write_all(&frame(0x1, 0x4, 1, &block)).unwrap();
            answered = true;
        }
        while !body.is_empty() && window > 0 {
            let n = body.len().min(16384).min(window as usize);
            let (chunk, rest) = body.split_at(n);
            body = rest;
            window -= n as i64;
            stream.write_all(&frame(0x0, if body.is_empty() { 1 } else { 0 }, 1, chunk)).unwrap();
        }
    }
}

/// `HttpClient` (HTTP_2 by default) continues over HTTP/2 once the registry takes its `h2c` offer, for the GET and
/// for the POST whose body went out as HTTP/1.1 (JDK 25 against the same stand-in: `200`, `HTTP_2`).
#[tokio::test(flavor = "multi_thread")]
async fn should_continue_over_http2_when_the_registry_takes_the_h2c_upgrade() {
    let port = stand_in(upgrading_registry);
    let client = SchemaRegistryClient::new(&format!("http://127.0.0.1:{port}")).unwrap();
    assert_eq!(client.schema_by_id(1).await.unwrap(), "x".repeat(100_000));
    assert_eq!(client.register("orders-value", AVRO_SCHEMA).await.unwrap(), 77);
}

/// `BodyHandlers.ofString` reads an answer whole, whatever its size (17 MiB here).
#[tokio::test(flavor = "multi_thread")]
async fn should_read_an_answer_over_16_mib_whole() {
    fn serve(mut stream: std::net::TcpStream, _: String) {
        use std::io::Write;
        let body = large_schema(17 * 1024 * 1024);
        let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes());
    }
    let port = stand_in(serve);
    let client = SchemaRegistryClient::new(&format!("http://127.0.0.1:{port}")).unwrap();
    assert_eq!(client.schema_by_id(1).await.unwrap().len(), 17 * 1024 * 1024);
}

/// `jdk.http.maxHeaderSize` (384 KiB, counted as `Http1HeaderParser` counts): JDK 25 failed this head with
/// `java.net.ProtocolException: Header size too big: 393217 > 393216`, and read one a byte shorter.
#[tokio::test(flavor = "multi_thread")]
async fn should_fail_a_response_head_over_the_jdk_header_size_limit() {
    fn serve(mut stream: std::net::TcpStream, head: String) {
        use std::io::Write;
        let size = if head.contains("/ids/1 ") { 393_084 } else { 393_083 };
        let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nX-Big: {}\r\nContent-Length: 2\r\n\r\n{{}}", "a".repeat(size)).as_bytes());
    }
    let port = stand_in(serve);
    let client = SchemaRegistryClient::new(&format!("http://127.0.0.1:{port}")).unwrap();
    let error = client.schema_by_id(1).await.unwrap_err();
    assert_eq!(error.message, "Failed to fetch schema id 1 from Schema Registry: Header size too big: 393217 > 393216");
    let error = client.schema_by_id(2).await.unwrap_err();
    assert_eq!(error.message, "Schema Registry response for id 2 has no 'schema' field", "the head a byte shorter is read");
}

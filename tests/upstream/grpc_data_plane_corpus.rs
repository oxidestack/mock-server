//! Ports of the gRPC cases of upstream's data-plane differential corpus
//! (`GrpcHttp2DataPlaneDifferentialCorpusIntegrationTest`, `Http3DataPlaneDifferentialCorpusIntegrationTest`: goldens
//! under `mockserver-netty/src/test/resources/dataplane-corpus/`) and of
//! `Http3GrpcIntegrationTest.shouldAnswerADelayedUnaryCallOverHttp3UnlessTheDeadlineElapsesFirst`:
//! the order of the HTTP/3 response header fields (`:status`, `content-type`, `server`, then the response's own),
//! the end of the stream, and the port of the `gRPC request error` WARN entry on a worker event loop that has not
//! handled an HTTP request yet.

use bytes::{Buf, Bytes};
use serde_json::{json, Value};

use crate::common;

const SERVICE: &str = "com.example.grpc.GreetingService";

fn greeting(name: &str) -> Vec<u8> {
    let mut message = vec![0x0a, name.len() as u8];
    message.extend_from_slice(name.as_bytes());
    let mut framed = vec![0];
    framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
    framed.extend_from_slice(&message);
    framed
}

async fn server() -> (common::Running, u16) {
    let descriptors = concat!(env!("CARGO_MANIFEST_DIR"), "/upstream/mockserver/mockserver/mockserver-core/src/test/resources/grpc");
    common::start_with_http3(&[("grpcDescriptorDirectory", descriptors), ("attemptToProxyIfNoMatchingExpectation", "false")]).await
}

/// What one gRPC call over HTTP/3 delivered: the response's header fields in arrival order, its DATA, and the
/// trailing HEADERS frame when there was one.
#[derive(Debug)]
struct Answer {
    status: u16,
    headers: Vec<String>,
    body: Vec<u8>,
    trailers: Option<Vec<String>>,
}

fn fields(map: &http::HeaderMap) -> Vec<String> {
    map.iter().map(|(k, v)| format!("{k}: {}", v.to_str().unwrap())).collect()
}

async fn call(port: u16, path: &str, timeout: Option<&str>, body: Vec<u8>) -> Answer {
    let mut tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(crate::http3_mcp::TrustAll))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(std::sync::Arc::new(crypto)));
    let connection = endpoint.connect(([127, 0, 0, 1], port).into(), "localhost").unwrap().await.unwrap();
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection)).await.unwrap();
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    // upstream's `RecordingConnection` sends `:authority: localhost`, no port
    let mut request = http::Request::builder().method("POST").uri(format!("https://localhost{path}")).header("content-type", "application/grpc").header("te", "trailers");
    if let Some(timeout) = timeout {
        request = request.header("grpc-timeout", timeout);
    }
    let mut stream = sender.send_request(request.body(()).unwrap()).await.unwrap();
    stream.send_data(Bytes::from(body)).await.unwrap();
    stream.finish().await.unwrap();
    let answer = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let response = stream.recv_response().await.unwrap();
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }
        let trailers = stream.recv_trailers().await.unwrap().map(|t| fields(&t));
        Answer { status: response.status().as_u16(), headers: fields(response.headers()), body, trailers }
    })
    .await
    .expect("the stream ends");
    drop(sender);
    drive.abort();
    endpoint.close(0u32.into(), b"");
    answer
}

/// `grpcUnary`: `:status`, `content-type`, `server`, then the response's headers; DATA; the trailers with the status.
#[tokio::test]
async fn unary_headers_over_http3_lead_with_content_type_then_server() {
    let (server, h3) = server().await;
    common::expect(
        server.port,
        &json!({"httpRequest": {"method": "POST", "path": format!("/{SERVICE}/Greeting")},
            "httpResponse": {"statusCode": 200, "headers": {"x-tenant-id": ["acme"], "x-region": ["eu-west-2"]},
                "trailers": {"x-request-cost": ["unit=1; tier=gold"]}, "body": "{\"greeting\":\"Hello Wörld\"}"}}),
    )
    .await;
    let answer = call(h3, &format!("/{SERVICE}/Greeting"), None, greeting("World")).await;
    assert_eq!(answer.status, 200);
    assert_eq!(answer.headers, ["content-type: application/grpc", "server: mockserver-http3", "x-tenant-id: acme", "x-region: eu-west-2"]);
    assert_eq!(answer.trailers.as_deref(), Some(&["x-request-cost: unit=1; tier=gold".to_string(), "grpc-status: 0".to_string()][..]));
}

/// `grpcServerStream`: the streamed head is built by the same `buildInitialHeadersFrame`.
#[tokio::test]
async fn server_stream_headers_over_http3_lead_with_content_type_then_server() {
    let (server, h3) = server().await;
    common::expect(
        server.port,
        &json!({"httpRequest": {"method": "POST", "path": format!("/{SERVICE}/ListGreetings")},
            "grpcStreamResponse": {"statusName": "OK", "messages": [{"json": "{\"greeting\": \"Hello 1\"}"}, {"json": "{\"greeting\": \"Hello 2\"}"}]}}),
    )
    .await;
    let answer = call(h3, &format!("/{SERVICE}/ListGreetings"), None, greeting("World")).await;
    assert_eq!(answer.headers, ["content-type: application/grpc", "server: mockserver-http3"]);
    assert_eq!(answer.trailers.as_deref(), Some(&["grpc-status: 0".to_string()][..]));
}

/// `grpcUnimplementedMethod`: one trailers-only HEADERS frame, `:status`, `content-type`, `server`, status, message.
#[tokio::test]
async fn unimplemented_method_over_http3_is_one_trailers_only_frame() {
    let (_server, h3) = server().await;
    let answer = call(h3, &format!("/{SERVICE}/NoSuchMethod"), None, greeting("World")).await;
    assert_eq!(
        answer.headers,
        [
            "content-type: application/grpc",
            "server: mockserver-http3",
            "grpc-status: 12",
            &format!("grpc-message: unknown gRPC method: {SERVICE}/NoSuchMethod"),
        ]
    );
    assert!(answer.body.is_empty() && answer.trailers.is_none(), "{answer:?}");
}

/// `shouldAnswerADelayedUnaryCallOverHttp3UnlessTheDeadlineElapsesFirst`: the deadline's answer is the one
/// trailers-only HEADERS frame, no DATA and no trailing frame.
#[tokio::test]
async fn elapsed_deadline_over_http3_is_one_trailers_only_frame() {
    let (server, h3) = server().await;
    common::expect(
        server.port,
        &json!({"httpRequest": {"method": "POST", "path": format!("/{SERVICE}/Greeting")},
            "httpResponse": {"statusCode": 200, "body": "{\"greeting\":\"Hello Late\"}", "delay": {"timeUnit": "MILLISECONDS", "value": 3000}}}),
    )
    .await;
    let answer = call(h3, &format!("/{SERVICE}/Greeting"), Some("300m"), greeting("Late")).await;
    assert!(answer.headers.contains(&"grpc-status: 4".to_string()), "{answer:?}");
    assert!(answer.body.is_empty() && answer.trailers.is_none(), "{answer:?}");
}

/// `GrpcHttp2DataPlaneDifferentialCorpusIntegrationTest.grpcUnimplementedMethod`: the call is on its worker event
/// loop's first connection (the corpus's log window reads the log over plain HTTP first, on the first loop), whose
/// thread has handled no HTTP request, so `GrpcToHttpRequestHandler`'s WARN carries no `port`; the same entry after a request was handled there has one.
#[tokio::test]
async fn request_error_warn_has_no_port_on_a_loop_that_served_no_request() {
    let (server, _h3) = server().await;
    let path = format!("/{SERVICE}/NoSuchMethod");
    // `CorpusLogEntries.window` reads the log before the test, over its own connection
    common::send(server.port, "PUT", "/mockserver/retrieve?type=LOGS&format=LOG_ENTRIES", "").await;
    let headers = [("content-type", "application/grpc"), ("te", "trailers")];
    let body = String::from_utf8(greeting("World")).unwrap();
    let first = common::exchange(server.port, common::Transport::Http2, "POST", &path, &headers, &body).await;
    assert_eq!(first.header("grpc-status"), Some("12"));
    let log = common::send(server.port, "PUT", "/mockserver/retrieve?type=LOGS&format=LOG_ENTRIES", "").await.body;
    let entries: Vec<Value> = serde_json::from_str(&log).unwrap_or_else(|e| panic!("{e}: {log}"));
    let warn = entries.iter().find(|e| e["messageFormat"] == "gRPC request error:{}:{}").expect("the WARN entry");
    assert!(warn.get("port").is_none(), "{warn}");
}

/// `Http3DataPlaneDifferentialCorpusIntegrationTest.grpcUnimplementedMethod`: `Http3MockServerHandler`'s WARN carries
/// the HTTP/3 request (as received: its own headers, the framed body in base64), and no `port`. The corpus compares
/// the serialised entry byte for byte (`grpc-unimplemented.txt`).
#[tokio::test]
async fn request_error_warn_over_http3_carries_the_request() {
    let (server, h3) = server().await;
    let path = format!("/{SERVICE}/NoSuchMethod");
    let answer = call(h3, &path, None, greeting("World")).await;
    assert!(answer.headers.contains(&"grpc-status: 12".to_string()), "{answer:?}");
    let log = common::send(server.port, "PUT", "/mockserver/retrieve?type=LOGS&format=LOG_ENTRIES", "").await.body;
    let expected = concat!(
        "    \"type\" : \"WARN\",\n",
        "    \"httpRequest\" : {\n",
        "      \"method\" : \"POST\",\n",
        "      \"path\" : \"/com.example.grpc.GreetingService/NoSuchMethod\",\n",
        "      \"headers\" : {\n",
        "        \"te\" : [\n",
        "          \"trailers\"\n",
        "        ],\n",
        "        \"host\" : [\n",
        "          \"localhost\"\n",
        "        ],\n",
        "        \"content-type\" : [\n",
        "          \"application/grpc\"\n",
        "        ]\n",
        "      },\n",
        "      \"secure\" : true,\n",
        "      \"protocol\" : \"HTTP_3\",\n",
        "      \"body\" : \"AAAAAAcKBVdvcmxk\"\n",
        "    },\n",
        "    \"messageFormat\" : \"gRPC request error over HTTP/3:{}:{}\",\n",
    );
    assert!(log.contains(expected), "{log}");
    let entries: Vec<Value> = serde_json::from_str(&log).unwrap_or_else(|e| panic!("{e}: {log}"));
    let warn = entries.iter().find(|e| e["messageFormat"] == "gRPC request error over HTTP/3:{}:{}").expect("the WARN entry");
    assert!(warn.get("port").is_none(), "{warn}");
}

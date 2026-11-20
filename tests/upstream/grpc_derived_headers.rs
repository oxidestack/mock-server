//! `GrpcDerivedHeaderSpoofingTest`'s HTTP/3 half (`GrpcHttp3Adapter.transformGrpcRequest`, all three exits) and its
//! transport-parity test, over a real HTTP/3 client: a client-supplied `x-grpc-service`, `x-grpc-method`,
//! `x-grpc-original-content-type` or `x-grpc-client-streaming` never reaches matching, only the path-derived values
//! do. The HTTP/2 half is the oracle scenario `grpc_derived_headers` (the harness has no HTTP/3 client).

use bytes::{Buf, Bytes};
use serde_json::Value;

use crate::common;

const SERVICE: &str = "com.example.grpc.GreetingService";

/// A `HelloRequest {name}` as one length-prefixed gRPC message.
fn hello(name: &str) -> Vec<u8> {
    let mut message = vec![0x0a, name.len() as u8];
    message.extend_from_slice(name.as_bytes());
    let mut framed = vec![0];
    framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
    framed.extend_from_slice(&message);
    framed
}

async fn server() -> (common::Running, u16) {
    let descriptors = concat!(env!("CARGO_MANIFEST_DIR"), "/upstream/mockserver/mockserver/mockserver-core/src/test/resources/grpc");
    common::start_with_http3(&[("grpcDescriptorDirectory", descriptors)]).await
}

/// One gRPC call over HTTP/3 with `headers` added, its whole body sent, the answer read to the end.
async fn call(port: u16, method: &str, headers: &[(&str, &str)], body: Vec<u8>) {
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
    let mut request = http::Request::builder()
        .method("POST")
        .uri(format!("https://localhost:{port}/{SERVICE}/{method}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut stream = sender.send_request(request.body(()).unwrap()).await.unwrap();
    if !body.is_empty() {
        stream.send_data(Bytes::from(body)).await.unwrap();
    }
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    assert_eq!(response.status(), 200);
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        chunk.advance(chunk.remaining());
    }
    let _ = stream.recv_trailers().await;
    drive.abort();
    endpoint.close(0u32.into(), b"");
}

/// The headers of every request matching saw, in arrival order.
async fn received_headers(port: u16) -> Vec<serde_json::Map<String, Value>> {
    let r = common::send(port, "PUT", "/mockserver/retrieve?type=REQUESTS&format=JSON", "").await;
    let requests: Vec<Value> = serde_json::from_str(&r.body).unwrap();
    requests.into_iter().map(|r| r["headers"].as_object().cloned().unwrap_or_default()).collect()
}

fn values<'a>(headers: &'a serde_json::Map<String, Value>, name: &str) -> Vec<&'a str> {
    headers.get(name).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default()
}

const SPOOFED: &[(&str, &str)] = &[
    ("x-grpc-service", "com.example.evil.OtherService"),
    ("x-grpc-method", "Evil"),
    ("x-grpc-original-content-type", "application/evil"),
    ("x-grpc-client-streaming", "true"),
];

/// `shouldNotKeepSpoofedDerivedHeadersOn{AnEmptyBodied,ASingleMessage,AMultiMessage}RequestOverHttp3`.
#[tokio::test]
async fn spoofed_derived_headers_do_not_survive_over_http3() {
    let (server, h3) = server().await;
    call(h3, "Greeting", SPOOFED, Vec::new()).await;
    call(h3, "Greeting", SPOOFED, hello("World")).await;
    let mut both = hello("One");
    both.extend(hello("Two"));
    call(h3, "CollectGreetings", SPOOFED, both).await;
    let received = received_headers(server.port).await;
    assert_eq!(received.len(), 3, "{received:?}");
    for (headers, method) in received.iter().zip(["Greeting", "Greeting", "CollectGreetings"]) {
        assert_eq!(values(headers, "x-grpc-service"), [SERVICE], "{headers:?}");
        assert_eq!(values(headers, "x-grpc-method"), [method], "{headers:?}");
        assert!(!values(headers, "x-grpc-original-content-type").contains(&"application/evil"), "{headers:?}");
    }
    assert!(values(&received[0], "x-grpc-client-streaming").is_empty(), "{:?}", received[0]);
    assert!(values(&received[1], "x-grpc-client-streaming").is_empty(), "{:?}", received[1]);
    assert_eq!(values(&received[2], "x-grpc-client-streaming"), ["true"], "{:?}", received[2]);
}

/// `shouldTagAnEmptyBodiedRequestIdenticallyOnHttp2AndHttp3`: an empty-bodied call is tagged with the path-derived
/// service and method on HTTP/3 as on HTTP/2 (the HTTP/2 side is the scenario's `clean, empty body` step).
#[tokio::test]
async fn empty_bodied_request_is_tagged_over_http3() {
    let (server, h3) = server().await;
    call(h3, "Greeting", &[], Vec::new()).await;
    let received = received_headers(server.port).await;
    assert_eq!(values(&received[0], "x-grpc-service"), [SERVICE]);
    assert_eq!(values(&received[0], "x-grpc-method"), ["Greeting"]);
}

//! INBOUND_STREAM breakpoints on gRPC bidi streams over HTTP/2, as `Http3GrpcBidiInboundBreakpointTest` and
//! `GrpcBidiMetadataMatchingTest.shouldParkInboundFramesWhenABreakpointMatchesOnMetadata` drive upstream's handlers
//! in-JVM, and as `Http3GrpcStreamingIntegrationTest` checks the decisions end to end over HTTP/3: each inbound DATA
//! frame is parked and sent to the breakpoint's client, which continues, modifies, drops, injects after or closes it.
//! The client is a real HTTP/2 (prior knowledge) client that sends every frame up front, then half-closes.

use std::time::Duration;

use bytes::Bytes;
use serde_json::{Value, json};

use crate::common;

const CHAT: &str = "/com.example.grpc.GreetingService/Chat";
const FRAME: &str = "org.mockserver.serialization.model.PausedStreamFrameDTO";
const DECISION: &str = "org.mockserver.serialization.model.StreamFrameDecisionDTO";

async fn server() -> common::Running {
    let descriptors = concat!(env!("CARGO_MANIFEST_DIR"), "/upstream/mockserver/mockserver/mockserver-core/src/test/resources/grpc");
    let server = common::start(&[("grpcDescriptorDirectory", descriptors), ("grpcBidiStreamingEnabled", "true")]).await;
    common::expect(
        server.port,
        &json!({
            "httpRequest": {"method": "POST", "path": CHAT},
            "grpcBidiResponse": {"statusName": "OK", "rules": [
                {"matchJson": ".*Alice.*", "responses": [{"json": "{\"greeting\": \"Hello Alice\"}"}]},
                {"matchJson": ".*Bob.*", "responses": [{"json": "{\"greeting\": \"Hello Bob\"}"}]}
            ]}
        }),
    )
    .await;
    server
}

/// A `HelloRequest {name}` as one length-prefixed gRPC message.
pub(crate) fn chat_frame(name: &str) -> Bytes {
    let mut message = vec![0x0a, name.len() as u8];
    message.extend_from_slice(name.as_bytes());
    let mut frame = vec![0];
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(&message);
    Bytes::from(frame)
}

/// The `greeting` of each `HelloResponse` in `body`.
pub(crate) fn greetings(mut body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    while body.len() >= 5 {
        let length = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
        let message = &body[5..5 + length];
        out.push(String::from_utf8_lossy(&message[2..]).into_owned());
        body = &body[5 + length..];
    }
    out
}

struct Call {
    greetings: Vec<String>,
    trailers: http::HeaderMap,
}

/// A bidi call on its own HTTP/2 connection: every frame as its own DATA frame, the last with END_STREAM.
async fn chat(port: u16, frames: Vec<Bytes>) -> Call {
    chat_with(port, frames, &[]).await
}

/// [`chat`] with gRPC metadata headers.
async fn chat_with(port: u16, frames: Vec<Bytes>, metadata: &[(&str, &str)]) -> Call {
    use http_body_util::BodyExt;
    let (connection, response) = open(port, frames, metadata).await;
    let mut body = response.into_body();
    let (mut data, mut trailers) = (Vec::new(), http::HeaderMap::new());
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("response frame");
        if let Some(chunk) = frame.data_ref() {
            data.extend_from_slice(chunk);
        }
        if let Some(t) = frame.trailers_ref() {
            trailers = t.clone();
        }
    }
    connection.abort();
    Call { greetings: greetings(&data), trailers }
}

/// A request body of whole DATA frames, the last one carrying END_STREAM (as Netty's client ends it).
pub(crate) struct Frames(pub(crate) std::collections::VecDeque<Bytes>);

impl hyper::body::Body for Frames {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(mut self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        std::task::Poll::Ready(self.0.pop_front().map(|f| Ok(hyper::body::Frame::data(f))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_empty()
    }
}

async fn open(port: u16, frames: Vec<Bytes>, metadata: &[(&str, &str)]) -> (tokio::task::JoinHandle<()>, hyper::Response<hyper::body::Incoming>) {
    open_at(port, CHAT, frames, metadata).await
}

/// A gRPC call to `path` on its own HTTP/2 (prior knowledge) connection; the connection task and the response head.
pub(crate) async fn open_at(port: u16, path: &str, frames: Vec<Bytes>, metadata: &[(&str, &str)]) -> (tokio::task::JoinHandle<()>, hyper::Response<hyper::body::Incoming>) {
    let body = Frames(frames.into());
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), hyper_util::rt::TokioIo::new(tcp)).await.unwrap();
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut request = hyper::Request::builder().method("POST").uri(format!("http://127.0.0.1:{port}{path}")).header("content-type", "application/grpc").header("te", "trailers");
    for (name, value) in metadata {
        request = request.header(*name, *value);
    }
    let request = request.body(body).unwrap();
    let response = sender.send_request(request).await.expect("response head");
    assert_eq!(response.status(), 200);
    (connection, response)
}

/// A breakpoint client on the callback WebSocket: the paused frames it receives, and where its decisions go.
pub(crate) struct FrameClient {
    pub(crate) id: String,
    pub(crate) frames: tokio::sync::mpsc::UnboundedReceiver<Value>,
    decisions: tokio::sync::mpsc::UnboundedSender<Value>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FrameClient {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FrameClient {
    pub(crate) async fn connect(port: u16) -> FrameClient {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/_mockserver_callback_websocket")).await.expect("callback websocket");
        let (mut sink, mut source) = ws.split();
        let first = source.next().await.unwrap().unwrap();
        let envelope: Value = serde_json::from_str(first.to_text().unwrap()).unwrap();
        let id = serde_json::from_str::<Value>(envelope["value"].as_str().unwrap()).unwrap()["clientId"].as_str().unwrap().to_string();
        let (frames_tx, frames) = tokio::sync::mpsc::unbounded_channel();
        let (decisions, mut decisions_rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    message = source.next() => {
                        let Some(Ok(Message::Text(text))) = message else { return };
                        let envelope: Value = serde_json::from_str(&text).unwrap();
                        if envelope["type"] == FRAME {
                            let _ = frames_tx.send(serde_json::from_str::<Value>(envelope["value"].as_str().unwrap()).unwrap());
                        }
                    }
                    Some(decision) = decisions_rx.recv() => {
                        let out = json!({"type": DECISION, "value": decision.to_string()});
                        if sink.send(Message::text(out.to_string())).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
        FrameClient { id, frames, decisions, task }
    }

    /// `addBreakpoint(request().withPath(CHAT), INBOUND_STREAM, …)`.
    async fn hold_chat(&self, port: u16) {
        self.hold(port, json!({"path": CHAT})).await;
    }

    async fn hold(&self, port: u16, request: Value) {
        self.hold_phase(port, request, "INBOUND_STREAM").await;
    }

    /// `addBreakpoint(request, phase, …)` for this client.
    pub(crate) async fn hold_phase(&self, port: u16, request: Value, phase: &str) {
        let body = json!({"httpRequest": request, "phases": [phase], "clientId": self.id});
        let r = common::send(port, "PUT", "/mockserver/breakpoint/matcher", &body.to_string()).await;
        assert_eq!(r.status, 201, "{}", r.body);
    }

    pub(crate) async fn next_frame(&mut self) -> Value {
        tokio::time::timeout(Duration::from_secs(5), self.frames.recv()).await.expect("a paused frame").unwrap()
    }

    pub(crate) fn decide(&self, frame: &Value, decision: Value) {
        let mut decision = decision;
        decision["correlationId"] = frame["correlationId"].clone();
        self.decisions.send(decision).unwrap();
    }
}

/// The name in a paused frame's `HelloRequest`.
fn held_name(frame: &Value) -> String {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD.decode(frame["body"].as_str().unwrap()).unwrap();
    String::from_utf8_lossy(&bytes[7..]).into_owned()
}

pub(crate) fn encoded(frame: impl AsRef<[u8]>) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(frame)
}

/// Runs the Alice-then-Bob call with `decide` answering each paused frame; the call and the frames held.
async fn decided_call(decide: impl Fn(&str) -> Value + Send + 'static) -> (Call, Vec<Value>) {
    let server = server().await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_chat(server.port).await;
    let port = server.port;
    let call = tokio::spawn(async move { chat(port, vec![chat_frame("Alice"), chat_frame("Bob")]).await });
    let mut held = Vec::new();
    while !call.is_finished() {
        tokio::select! {
            frame = client.frames.recv() => {
                let frame = frame.unwrap();
                client.decide(&frame, decide(&held_name(&frame)));
                held.push(frame);
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
    (call.await.unwrap(), held)
}

fn grpc_status(call: &Call) -> (&str, Option<&str>) {
    let get = |n: &str| call.trailers.get(n).map(|v| v.to_str().unwrap());
    (get("grpc-status").unwrap_or_default(), get("grpc-message"))
}

/// `defaultOffProcessesInlineWithoutDispatch`: without a breakpoint nothing is parked.
#[tokio::test]
async fn default_off_processes_inline_without_dispatch() {
    let server = server().await;
    let mut client = FrameClient::connect(server.port).await;
    let call = chat(server.port, vec![chat_frame("Alice"), chat_frame("Bob")]).await;
    assert_eq!(call.greetings, ["Hello Alice", "Hello Bob"]);
    assert_eq!(grpc_status(&call), ("0", None));
    assert!(client.frames.try_recv().is_err(), "no frame is dispatched");
}

/// `inboundFrameIsParkedAndDispatchedWithInboundDirection` and `shouldContinueInboundBidiFramesOverHttp3ViaBreakpoint`:
/// every frame is parked in order, as `PausedStreamFrameDTO`s of one stream, and continuing is transparent.
#[tokio::test]
async fn inbound_frames_are_parked_in_order_and_continued() {
    let (call, held) = decided_call(|_| json!({"action": "CONTINUE"})).await;
    assert_eq!(call.greetings, ["Hello Alice", "Hello Bob"]);
    assert_eq!(grpc_status(&call), ("0", None));
    assert_eq!(held.iter().map(held_name).collect::<Vec<_>>(), ["Alice", "Bob"]);
    for (sequence, frame) in held.iter().enumerate() {
        assert_eq!(frame["direction"], "INBOUND");
        assert_eq!(frame["phase"], "INBOUND_STREAM");
        assert_eq!(frame["sequenceNumber"], sequence);
        assert_eq!(frame["requestMethod"], "GRPC-INBOUND");
        assert_eq!(frame["requestPath"], "com.example.grpc.GreetingService.Chat");
        assert!(frame["streamId"].as_str().unwrap().starts_with(&format!("grpc-bidi-inbound-{CHAT}-")), "{frame}");
        assert!(frame["breakpointId"].is_string());
    }
    assert_eq!(held[0]["streamId"], held[1]["streamId"]);
    assert_eq!(held[0]["body"], encoded(chat_frame("Alice")));
}

/// `shouldDropInboundBidiFrameOverHttp3ViaBreakpoint`.
#[tokio::test]
async fn dropped_inbound_frame_gets_no_response() {
    let (call, held) = decided_call(|name| json!({"action": if name == "Alice" { "DROP" } else { "CONTINUE" }})).await;
    assert_eq!(held.len(), 2);
    assert_eq!(call.greetings, ["Hello Bob"]);
    assert_eq!(grpc_status(&call), ("0", None));
}

/// `shouldModifyInboundBidiFrameOverHttp3ViaBreakpoint`: the replacement bytes are what the rules see.
#[tokio::test]
async fn modified_inbound_frame_drives_the_response() {
    let (call, _) = decided_call(|name| match name {
        "Alice" => json!({"action": "MODIFY", "body": encoded(chat_frame("Bob"))}),
        _ => json!({"action": "CONTINUE"}),
    })
    .await;
    assert_eq!(call.greetings, ["Hello Bob", "Hello Bob"]);
    assert_eq!(grpc_status(&call), ("0", None));
}

/// INJECT: the frame, then the injected bytes.
#[tokio::test]
async fn injected_bytes_follow_the_inbound_frame() {
    let (call, _) = decided_call(|name| match name {
        "Alice" => json!({"action": "INJECT", "body": encoded(chat_frame("Bob"))}),
        _ => json!({"action": "CONTINUE"}),
    })
    .await;
    assert_eq!(call.greetings, ["Hello Alice", "Hello Bob", "Hello Bob"]);
    assert_eq!(grpc_status(&call), ("0", None));
}

/// CLOSE: the call ends at once with `CANCELLED`.
#[tokio::test]
async fn closed_inbound_frame_cancels_the_call() {
    let (call, held) = decided_call(|name| json!({"action": if name == "Alice" { "CLOSE" } else { "CONTINUE" }})).await;
    assert_eq!(held.len(), 1, "nothing after the closing frame is parked");
    assert!(call.greetings.is_empty());
    assert_eq!(grpc_status(&call), ("1", Some("stream closed by breakpoint")));
}

/// `channelInactiveInvokesCompletionCallbackAndClearsHeldFrames`: when the client goes away while a frame is parked,
/// the frames queued behind it are dropped rather than parked once the held one is answered.
#[tokio::test]
async fn lost_client_clears_the_frames_behind_a_held_one() {
    let server = server().await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_chat(server.port).await;
    let (connection, response) = open(server.port, vec![chat_frame("Alice"), chat_frame("Bob")], &[]).await;
    let first = client.next_frame().await;
    assert_eq!(held_name(&first), "Alice");
    connection.abort();
    drop(response);
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Dropped, so no response of Alice's runs into the closed stream first.
    client.decide(&first, json!({"action": "DROP"}));
    let next = tokio::time::timeout(Duration::from_millis(500), client.frames.recv()).await;
    assert!(next.is_err(), "no frame is parked after the stream went away: {next:?}");
    // The server goes on serving bidi calls.
    drop(client);
    let call = chat(server.port, vec![chat_frame("Bob")]).await;
    assert_eq!(call.greetings, ["Hello Bob"]);
}

/// `GrpcBidiMetadataMatchingTest.shouldParkInboundFramesWhenABreakpointMatchesOnMetadata`: the breakpoint sees the
/// stream's gRPC metadata, so one qualified by a header parks only the streams that carry it.
#[tokio::test]
async fn breakpoint_qualified_by_metadata_parks_only_matching_streams() {
    let server = server().await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold(server.port, json!({"path": CHAT, "headers": {"x-tenant-id": ["acme"]}})).await;
    let bare = chat(server.port, vec![chat_frame("Bob")]).await;
    assert_eq!(bare.greetings, ["Hello Bob"]);
    assert!(client.frames.try_recv().is_err(), "a stream without the metadata is not parked");
    let port = server.port;
    let call = tokio::spawn(async move { chat_with(port, vec![chat_frame("Alice")], &[("x-tenant-id", "acme")]).await });
    let frame = client.next_frame().await;
    assert_eq!(held_name(&frame), "Alice");
    client.decide(&frame, json!({"action": "CONTINUE"}));
    assert_eq!(call.await.unwrap().greetings, ["Hello Alice"]);
}

// ---------------------------------------------------------------- HTTP/3

/// A bidi call over HTTP/3 (`Http3GrpcStreamingIntegrationTest.sendGrpcOverHttp3`), left open for the test to drive.
pub(crate) struct H3Call {
    pub(crate) stream: h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    _sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    drive: tokio::task::JoinHandle<()>,
    endpoint: quinn::Endpoint,
}

impl Drop for H3Call {
    fn drop(&mut self) {
        self.drive.abort();
        self.endpoint.close(0u32.into(), b"");
    }
}

pub(crate) async fn h3_server() -> (common::Running, u16) {
    let descriptors = concat!(env!("CARGO_MANIFEST_DIR"), "/upstream/mockserver/mockserver/mockserver-core/src/test/resources/grpc");
    common::start_with_http3(&[("grpcDescriptorDirectory", descriptors), ("grpcBidiStreamingEnabled", "true")]).await
}

async fn h3_open(port: u16) -> H3Call {
    h3_open_at(port, CHAT).await
}

/// A gRPC call to `path` over HTTP/3, its request still open.
pub(crate) async fn h3_open_at(port: u16, path: &str) -> H3Call {
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
    let request = http::Request::builder().method("POST").uri(format!("https://localhost:{port}{path}")).header("content-type", "application/grpc").header("te", "trailers");
    let stream = sender.send_request(request.body(()).unwrap()).await.unwrap();
    H3Call { stream, _sender: sender, drive, endpoint }
}

/// HTTP/3 answers inbound messages concurrently (`Http3GrpcBidiStreamHandler.emitSequential`): while a rule's
/// delayed response is pending, the next inbound frame is already parked; on HTTP/2 it waits for the response.
#[tokio::test(flavor = "multi_thread")]
async fn http3_parks_the_next_frame_while_a_delayed_response_is_pending() {
    let (server, port) = h3_server().await;
    common::expect(
        server.port,
        &json!({
            "httpRequest": {"method": "POST", "path": CHAT},
            "grpcBidiResponse": {"statusName": "OK", "rules": [
                {"matchJson": ".*Alice.*", "responses": [{"json": "{\"greeting\": \"Hello Alice\"}", "delay": {"timeUnit": "MILLISECONDS", "value": 1500}}]},
                {"matchJson": ".*Bob.*", "responses": [{"json": "{\"greeting\": \"Hello Bob\"}"}]}
            ]}
        }),
    )
    .await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_chat(server.port).await;
    let mut call = h3_open(port).await;
    call.stream.send_data(chat_frame("Alice")).await.unwrap();
    call.stream.send_data(chat_frame("Bob")).await.unwrap();
    call.stream.finish().await.unwrap();
    let alice = client.next_frame().await;
    client.decide(&alice, json!({"action": "CONTINUE"}));
    let decided = std::time::Instant::now();
    let bob = client.next_frame().await;
    assert!(decided.elapsed() < Duration::from_millis(1000), "Bob's frame is parked before Alice's delayed response: {:?}", decided.elapsed());
    assert_eq!(held_name(&bob), "Bob");
    assert!(bob["streamId"].as_str().unwrap().starts_with(&format!("grpc-bidi-inbound-{CHAT}-h3-")), "{bob}");
    client.decide(&bob, json!({"action": "CONTINUE"}));
    let response = call.stream.recv_response().await.unwrap();
    assert_eq!(response.status(), 200);
    let mut data = Vec::new();
    while let Some(mut chunk) = call.stream.recv_data().await.unwrap() {
        use bytes::Buf;
        data.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    let trailers = call.stream.recv_trailers().await.unwrap().unwrap();
    assert_eq!(greetings(&data), ["Hello Bob", "Hello Alice"]);
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
}

/// `onChannelInactive` over HTTP/3: a reset request stream ends the session, so the frame queued behind the held one
/// is never parked.
#[tokio::test(flavor = "multi_thread")]
async fn http3_reset_stream_clears_the_frames_behind_a_held_one() {
    let (server, port) = h3_server().await;
    common::expect(
        server.port,
        &json!({
            "httpRequest": {"method": "POST", "path": CHAT},
            "grpcBidiResponse": {"statusName": "OK", "rules": [{"matchJson": ".*", "responses": [{"json": "{\"greeting\": \"Hello\"}"}]}]}
        }),
    )
    .await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_chat(server.port).await;
    let mut call = h3_open(port).await;
    call.stream.send_data(chat_frame("Alice")).await.unwrap();
    call.stream.send_data(chat_frame("Bob")).await.unwrap();
    let alice = client.next_frame().await;
    assert_eq!(held_name(&alice), "Alice");
    call.stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
    tokio::time::sleep(Duration::from_millis(200)).await;
    client.decide(&alice, json!({"action": "DROP"}));
    let next = tokio::time::timeout(Duration::from_millis(500), client.frames.recv()).await;
    assert!(next.is_err(), "no frame is parked after the stream was reset: {next:?}");
}

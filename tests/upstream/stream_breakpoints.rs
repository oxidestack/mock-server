//! RESPONSE_STREAM and INBOUND_STREAM breakpoints outside gRPC bidi streams, as upstream's handlers hold them:
//! `MockStreamBreakpointWritePathTest` drives `NettyResponseWriter.writeStreamingResponse` in-JVM (here a real
//! streaming proxy relays an upstream's SSE events), and `GrpcStreamResponseActionHandler`, `Http3GrpcResponseWriter`,
//! `HttpWebSocketResponseActionHandler`, `BidirectionalWebSocketFrameHandler` and `GraphQLSubscriptionHandler` hold
//! gRPC server-stream messages, WebSocket frames and GraphQL subscription messages the same way. Each held frame goes
//! to the breakpoint's client as a `PausedStreamFrameDTO` and is continued, modified, dropped, followed by injected
//! bytes, or ends its stream.

use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;

use crate::common;
use crate::grpc_bidi_breakpoints::{FrameClient, encoded};

fn decoded(frame: &Value) -> String {
    use base64::Engine;
    String::from_utf8(base64::engine::general_purpose::STANDARD.decode(frame["body"].as_str().unwrap()).unwrap()).unwrap()
}

// ---------------------------------------------------------------- streaming proxy

/// An SSE event as the upstream frames it, one chunk each.
fn event(data: &str) -> String {
    format!("data: {data}\n\n")
}

/// A server whose `/stream` is a streaming proxy of another server's `/sse`, which sends `events` 100ms apart.
async fn proxy(events: &[&str]) -> (common::Running, common::Running) {
    let origin = common::start(&[]).await;
    let events: Vec<Value> = events.iter().map(|e| json!({"data": e, "delay": {"timeUnit": "MILLISECONDS", "value": 100}})).collect();
    common::expect(origin.port, &json!({"httpRequest": {"path": "/sse"}, "httpSseResponse": {"events": events}})).await;
    let server = common::start(&[]).await;
    common::expect(
        server.port,
        &json!({
            "httpRequest": {"path": "/stream"},
            "httpOverrideForwardedRequest": {"requestOverride": {"path": "/sse", "headers": {"Host": [format!("127.0.0.1:{}", origin.port)]}, "socketAddress": {"host": "127.0.0.1", "port": origin.port, "scheme": "HTTP"}}}
        }),
    )
    .await;
    (server, origin)
}

/// A keep-alive `GET /stream`, read chunk by chunk.
struct Streamed {
    body: hyper::body::Incoming,
    connection: tokio::task::JoinHandle<()>,
}

impl Streamed {
    async fn open(port: u16, version: hyper::Version) -> Streamed {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let io = hyper_util::rt::TokioIo::new(tcp);
        let request = hyper::Request::builder().uri(format!("http://127.0.0.1:{port}/stream")).header("host", format!("127.0.0.1:{port}"));
        let (response, connection) = if version == hyper::Version::HTTP_2 {
            let (mut sender, connection) = hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io).await.unwrap();
            let connection = tokio::spawn(async move {
                let _ = connection.await;
            });
            (sender.send_request(request.body(http_body_util::Empty::<Bytes>::new()).unwrap()).await.unwrap(), connection)
        } else {
            let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await.unwrap();
            let connection = tokio::spawn(async move {
                let _ = connection.await;
            });
            (sender.send_request(request.body(http_body_util::Empty::<Bytes>::new()).unwrap()).await.unwrap(), connection)
        };
        assert_eq!(response.status(), 200);
        Streamed { body: response.into_body(), connection }
    }

    /// The next body chunk within `wait`; `Some(None)` once the body has ended.
    async fn chunk(&mut self, wait: Duration) -> Option<Option<String>> {
        use http_body_util::BodyExt;
        loop {
            match tokio::time::timeout(wait, self.body.frame()).await.ok()? {
                None => return Some(None),
                Some(frame) => match frame.expect("body frame").into_data() {
                    Ok(data) if !data.is_empty() => return Some(Some(String::from_utf8_lossy(&data).into_owned())),
                    _ => {}
                },
            }
        }
    }
}

impl Drop for Streamed {
    fn drop(&mut self) {
        self.connection.abort();
    }
}

async fn stream_client(port: u16) -> FrameClient {
    let client = FrameClient::connect(port).await;
    client.hold_phase(port, json!({"path": "/stream"}), "RESPONSE_STREAM").await;
    client
}

/// `shouldParkMockStreamFrameUntilContinueThenFlushOriginal`: the frame is withheld until the client decides, is
/// dispatched as an OUTBOUND `RESPONSE_STREAM` frame of a `-stream` stream, and CONTINUE flushes the original bytes.
#[tokio::test]
async fn streamed_frame_is_parked_until_continue_then_flushed() {
    let (server, _origin) = proxy(&["sse-frame-1"]).await;
    let mut client = stream_client(server.port).await;
    let mut streamed = Streamed::open(server.port, hyper::Version::HTTP_11).await;
    let paused = client.next_frame().await;
    assert_eq!(streamed.chunk(Duration::from_millis(300)).await, None, "frame must be parked, not flushed, before a decision arrives");
    assert!(paused["streamId"].as_str().unwrap().ends_with("-stream"), "{paused}");
    assert_eq!(paused["direction"], "OUTBOUND");
    assert_eq!(paused["phase"], "RESPONSE_STREAM");
    assert_eq!(paused["sequenceNumber"], 0);
    assert_eq!(paused["requestMethod"], "GET");
    assert_eq!(paused["requestPath"], "/stream");
    assert!(paused["breakpointId"].is_string());
    assert_eq!(decoded(&paused), event("sse-frame-1"));
    client.decide(&paused, json!({"action": "CONTINUE"}));
    assert_eq!(streamed.chunk(Duration::from_secs(5)).await, Some(Some(event("sse-frame-1"))));
    assert_eq!(streamed.chunk(Duration::from_secs(5)).await, Some(None));
}

/// `shouldFlushModifiedBytesOnModifyDecision`.
#[tokio::test]
async fn modified_stream_frame_flushes_the_replacement() {
    let (server, _origin) = proxy(&["original-body"]).await;
    let mut client = stream_client(server.port).await;
    let mut streamed = Streamed::open(server.port, hyper::Version::HTTP_11).await;
    let paused = client.next_frame().await;
    client.decide(&paused, json!({"action": "MODIFY", "body": encoded("replacement-body")}));
    assert_eq!(streamed.chunk(Duration::from_secs(5)).await, Some(Some("replacement-body".into())));
}

/// `shouldSuppressFrameOnDropDecision`: the dropped frame never reaches the wire, the next one does, numbered on.
#[tokio::test]
async fn dropped_stream_frame_is_suppressed() {
    let (server, _origin) = proxy(&["doomed-frame", "kept-frame"]).await;
    let mut client = stream_client(server.port).await;
    let mut streamed = Streamed::open(server.port, hyper::Version::HTTP_11).await;
    let doomed = client.next_frame().await;
    client.decide(&doomed, json!({"action": "DROP"}));
    let kept = client.next_frame().await;
    assert_eq!(kept["sequenceNumber"], 1);
    assert_eq!(kept["streamId"], doomed["streamId"]);
    client.decide(&kept, json!({"action": "CONTINUE"}));
    assert_eq!(streamed.chunk(Duration::from_secs(5)).await, Some(Some(event("kept-frame"))));
    assert_eq!(streamed.chunk(Duration::from_secs(5)).await, Some(None));
}

/// INJECT over HTTP/2 (`NettyResponseWriter` serves both): the frame, then the injected bytes.
#[tokio::test]
async fn injected_bytes_follow_the_stream_frame_over_http2() {
    let (server, _origin) = proxy(&["first"]).await;
    let mut client = stream_client(server.port).await;
    let mut streamed = Streamed::open(server.port, hyper::Version::HTTP_2).await;
    let paused = client.next_frame().await;
    client.decide(&paused, json!({"action": "INJECT", "body": encoded("injected")}));
    let mut body = String::new();
    while let Some(Some(chunk)) = streamed.chunk(Duration::from_secs(5)).await {
        body.push_str(&chunk);
    }
    assert_eq!(body, format!("{}injected", event("first")));
}

/// CLOSE: `LastHttpContent` at once, then the connection is closed, although the request was keep-alive.
#[tokio::test]
async fn closed_stream_ends_the_body_and_the_connection() {
    let (server, _origin) = proxy(&["one", "two"]).await;
    let mut client = stream_client(server.port).await;
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", server.port)).await.unwrap();
    tcp.write_all(format!("GET /stream HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", server.port).as_bytes()).await.unwrap();
    let paused = client.next_frame().await;
    client.decide(&paused, json!({"action": "CLOSE"}));
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut raw)).await.expect("connection closed").unwrap();
    let raw = String::from_utf8_lossy(&raw);
    assert!(raw.starts_with("HTTP/1.1 200"), "{raw}");
    assert!(raw.ends_with("\r\n\r\n0\r\n\r\n"), "only the head and the last chunk: {raw}");
    assert!(tokio::time::timeout(Duration::from_millis(500), client.frames.recv()).await.is_err(), "nothing more is held");
    // As the oracle does, the exchange is still recorded once the upstream has finished, with its whole body.
    let port = server.port;
    let recorded = common::eventually_async(|| async move {
        let r = common::send(port, "PUT", "/mockserver/retrieve?type=REQUEST_RESPONSES", r#"{"path": "/stream"}"#).await;
        r.body.contains(r#""body" : "data: one\n\ndata: two\n\n""#).then_some(())
    })
    .await;
    let all = common::send(port, "PUT", "/mockserver/retrieve?type=REQUEST_RESPONSES", "").await.body;
    assert!(recorded.is_some(), "the closed relay's exchange is recorded: {all}");
}

/// The stream id is the request's log correlation id (`request.getLogCorrelationId() + "-stream"`), the one its
/// log entries carry.
#[tokio::test]
async fn stream_id_is_the_log_correlation_id() {
    let (server, _origin) = proxy(&["one"]).await;
    let mut client = stream_client(server.port).await;
    let _streamed = Streamed::open(server.port, hyper::Version::HTTP_11).await;
    let paused = client.next_frame().await;
    client.decide(&paused, json!({"action": "CONTINUE"}));
    let logs = common::send(server.port, "PUT", "/mockserver/retrieve?type=REQUESTS&format=LOG_ENTRIES", r#"{"path": "/stream"}"#).await;
    let entries: Vec<Value> = serde_json::from_str(&logs.body).unwrap();
    let received = entries.iter().find(|e| e["type"] == "RECEIVED_REQUEST").expect("the received entry");
    assert_eq!(paused["streamId"], format!("{}-stream", received["correlationId"].as_str().unwrap()));
}

/// `dispatchFrame` when the breakpoint's client is not connected: the frame goes out unheld and, for a
/// RESPONSE_STREAM hold, the WARN is logged.
#[tokio::test]
async fn frame_goes_unheld_when_the_client_is_not_connected() {
    let (server, _origin) = proxy(&["alone"]).await;
    let body = json!({"httpRequest": {"path": "/stream"}, "phases": ["RESPONSE_STREAM"], "clientId": "absent-client"});
    assert_eq!(common::send(server.port, "PUT", "/mockserver/breakpoint/matcher", &body.to_string()).await.status, 201);
    let mut streamed = Streamed::open(server.port, hyper::Version::HTTP_11).await;
    assert_eq!(streamed.chunk(Duration::from_secs(5)).await, Some(Some(event("alone"))));
    let logs = common::logs(server.port).await;
    assert!(logs.contains("client absent-client not found for stream frame message"), "{logs}");
    assert!(logs.contains("stream frame WS dispatch failed: client \n\n  absent-client\n\n not connected for stream="), "{logs}");
    assert!(logs.contains("-stream\n\n seq=\n\n  0"), "{logs}");
}

/// `breakpointMaxHeld`: past the cap the frame is written at once, with the INFO line.
#[tokio::test]
async fn frame_goes_unheld_past_the_cap() {
    let origin = common::start(&[]).await;
    common::expect(origin.port, &json!({"httpRequest": {"path": "/sse"}, "httpSseResponse": {"events": [{"data": "capped"}]}})).await;
    let server = common::start(&[("breakpointMaxHeld", "0")]).await;
    common::expect(
        server.port,
        &json!({"httpRequest": {"path": "/stream"}, "httpOverrideForwardedRequest": {"requestOverride": {"path": "/sse", "socketAddress": {"host": "127.0.0.1", "port": origin.port, "scheme": "HTTP"}}}}),
    )
    .await;
    let mut client = stream_client(server.port).await;
    let mut streamed = Streamed::open(server.port, hyper::Version::HTTP_11).await;
    assert_eq!(streamed.chunk(Duration::from_secs(5)).await, Some(Some(event("capped"))));
    assert!(client.frames.try_recv().is_err());
    let logs = common::logs(server.port).await;
    assert!(logs.contains("stream frame WS dispatch cap reached (\n\n  0\n\n /\n\n  0\n\n ), skipping for stream="), "{logs}");
}

// ---------------------------------------------------------------- gRPC server streams

const LIST: &str = "/com.example.grpc.GreetingService/ListGreetings";

fn hello(name: &str) -> Bytes {
    crate::grpc_bidi_breakpoints::chat_frame(name)
}

/// A `HelloResponse {greeting}` as one length-prefixed gRPC message.
fn greeting_frame(greeting: &str) -> Vec<u8> {
    let mut message = vec![0x0a, greeting.len() as u8];
    message.extend_from_slice(greeting.as_bytes());
    let mut frame = vec![0];
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(&message);
    frame
}

async fn grpc_stream_server(extra: &[(&str, &str)]) -> common::Running {
    let descriptors = concat!(env!("CARGO_MANIFEST_DIR"), "/upstream/mockserver/mockserver/mockserver-core/src/test/resources/grpc");
    let mut properties = vec![("grpcDescriptorDirectory", descriptors)];
    properties.extend_from_slice(extra);
    let server = common::start(&properties).await;
    common::expect(
        server.port,
        &json!({
            "httpRequest": {"method": "POST", "path": LIST},
            "grpcStreamResponse": {"statusName": "OK", "messages": [
                {"json": "{\"greeting\": \"one\"}"},
                {"json": "{\"greeting\": \"two\"}"},
                {"json": "{\"greeting\": \"three\"}"}
            ]}
        }),
    )
    .await;
    server
}

/// The greetings and `grpc-status` of a server-streaming call, each message answered by `decide`.
async fn grpc_stream_call(decide: impl Fn(u64) -> Value) -> (Vec<String>, String, Vec<Value>) {
    use http_body_util::BodyExt;
    let server = grpc_stream_server(&[]).await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_phase(server.port, json!({"path": LIST}), "RESPONSE_STREAM").await;
    let (connection, response) = crate::grpc_bidi_breakpoints::open_at(server.port, LIST, vec![hello("x")], &[]).await;
    let mut body = response.into_body();
    let collect = tokio::spawn(async move {
        let (mut data, mut status) = (Vec::new(), String::new());
        while let Some(frame) = body.frame().await {
            let frame = frame.expect("response frame");
            if let Some(chunk) = frame.data_ref() {
                data.extend_from_slice(chunk);
            }
            if let Some(t) = frame.trailers_ref() {
                status = t.get("grpc-status").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
            }
        }
        (crate::grpc_bidi_breakpoints::greetings(&data), status)
    });
    let mut held = Vec::new();
    while !collect.is_finished() {
        tokio::select! {
            frame = client.frames.recv() => {
                let frame = frame.unwrap();
                client.decide(&frame, decide(frame["sequenceNumber"].as_u64().unwrap()));
                held.push(frame);
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
    let (greetings, status) = collect.await.unwrap();
    connection.abort();
    (greetings, status, held)
}

/// `GrpcStreamResponseActionHandler`: every message is held in order, as framed gRPC messages of a `-grpc-stream`
/// stream; MODIFY and INJECT write the client's bytes as they are.
#[tokio::test]
async fn grpc_stream_messages_are_held_and_decided() {
    let (greetings, status, held) = grpc_stream_call(|sequence| match sequence {
        0 => json!({"action": "MODIFY", "body": encoded(greeting_frame("uno"))}),
        1 => json!({"action": "DROP"}),
        _ => json!({"action": "INJECT", "body": encoded(greeting_frame("extra"))}),
    })
    .await;
    assert_eq!(greetings, ["uno", "three", "extra"]);
    assert_eq!(status, "0");
    assert_eq!(held.len(), 3);
    for (sequence, frame) in held.iter().enumerate() {
        assert_eq!(frame["sequenceNumber"], sequence);
        assert_eq!(frame["direction"], "OUTBOUND");
        assert_eq!(frame["phase"], "RESPONSE_STREAM");
        assert_eq!(frame["requestMethod"], "POST");
        assert_eq!(frame["requestPath"], LIST);
        assert!(frame["streamId"].as_str().unwrap().ends_with("-grpc-stream"), "{frame}");
    }
    assert_eq!(held[0]["body"], encoded(greeting_frame("one")));
}

/// CLOSE ends the stream with its status trailers; nothing after is held.
#[tokio::test]
async fn closed_grpc_stream_ends_with_its_status() {
    let (greetings, status, held) = grpc_stream_call(|sequence| json!({"action": if sequence == 1 { "CLOSE" } else { "CONTINUE" }})).await;
    assert_eq!(greetings, ["one"]);
    assert_eq!(status, "0");
    assert_eq!(held.len(), 2);
}

/// `Http3GrpcResponseWriter.writeGrpcStreamResponse`: the same holds over HTTP/3, on a `-h3-grpc-stream` stream.
#[tokio::test(flavor = "multi_thread")]
async fn grpc_stream_messages_are_held_over_http3() {
    let (server, port) = crate::grpc_bidi_breakpoints::h3_server().await;
    common::expect(
        server.port,
        &json!({"httpRequest": {"method": "POST", "path": LIST}, "grpcStreamResponse": {"statusName": "OK", "messages": [{"json": "{\"greeting\": \"one\"}"}, {"json": "{\"greeting\": \"two\"}"}]}}),
    )
    .await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_phase(server.port, json!({"path": LIST}), "RESPONSE_STREAM").await;
    let mut call = crate::grpc_bidi_breakpoints::h3_open_at(port, LIST).await;
    call.stream.send_data(hello("x")).await.unwrap();
    call.stream.finish().await.unwrap();
    let first = client.next_frame().await;
    assert!(first["streamId"].as_str().unwrap().ends_with("-h3-grpc-stream"), "{first}");
    client.decide(&first, json!({"action": "DROP"}));
    let second = client.next_frame().await;
    assert_eq!(second["sequenceNumber"], 1);
    client.decide(&second, json!({"action": "CONTINUE"}));
    let response = call.stream.recv_response().await.unwrap();
    assert_eq!(response.status(), 200);
    let mut data = Vec::new();
    while let Some(mut chunk) = call.stream.recv_data().await.unwrap() {
        use bytes::Buf;
        data.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    let trailers = call.stream.recv_trailers().await.unwrap().unwrap();
    assert_eq!(crate::grpc_bidi_breakpoints::greetings(&data), ["two"]);
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
}

// ---------------------------------------------------------------- WebSocket mocks

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn websocket(port: u16, path: &str, subprotocol: Option<&str>) -> Socket {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = format!("ws://127.0.0.1:{port}{path}").into_client_request().unwrap();
    if let Some(p) = subprotocol {
        request.headers_mut().insert("sec-websocket-protocol", p.parse().unwrap());
    }
    tokio_tungstenite::connect_async(request).await.expect("mocked websocket").0
}

/// The next frame the mock sends: its text (or `close` / `gone`).
async fn received(socket: &mut Socket) -> String {
    match tokio::time::timeout(Duration::from_secs(5), socket.next()).await.expect("a frame") {
        Some(Ok(Message::Text(t))) => t.to_string(),
        Some(Ok(Message::Binary(b))) => format!("binary:{}", String::from_utf8_lossy(&b)),
        Some(Ok(Message::Close(_))) => "close".into(),
        Some(Ok(other)) => format!("{other:?}"),
        None | Some(Err(_)) => "gone".into(),
    }
}

/// `HttpWebSocketResponseActionHandler.scheduleMessages`: each scripted message is held (a `-ws-stream` stream) and
/// then written, replaced, dropped or followed by the injected bytes; the normal closure follows the script.
#[tokio::test]
async fn scripted_websocket_messages_are_held() {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/ws"}, "httpWebSocketResponse": {"messages": [{"text": "one"}, {"text": "two"}, {"text": "three"}, {"binary": "AAE="}]}})).await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_phase(server.port, json!({"path": "/ws"}), "RESPONSE_STREAM").await;
    let mut socket = websocket(server.port, "/ws", None).await;
    let decisions = [json!({"action": "CONTINUE"}), json!({"action": "MODIFY", "body": encoded("TWO")}), json!({"action": "DROP"}), json!({"action": "INJECT", "body": encoded("more")})];
    let mut held = Vec::new();
    for decision in decisions {
        let frame = client.next_frame().await;
        client.decide(&frame, decision);
        held.push(frame);
    }
    assert!(held[0]["streamId"].as_str().unwrap().ends_with("-ws-stream"), "{}", held[0]);
    assert_eq!(held[0]["requestMethod"], "GET");
    assert_eq!(held[0]["requestPath"], "/ws");
    assert_eq!(held.iter().map(decoded_lossy).collect::<Vec<_>>(), ["one", "two", "three", "\u{0}\u{1}"]);
    let mut frames = Vec::new();
    for _ in 0..4 {
        frames.push(received(&mut socket).await);
    }
    assert_eq!(frames, ["one", "TWO", "binary:\u{0}\u{1}", "binary:more"]);
    assert_eq!(received(&mut socket).await, "close");
}

fn decoded_lossy(frame: &Value) -> String {
    use base64::Engine;
    String::from_utf8_lossy(&base64::engine::general_purpose::STANDARD.decode(frame["body"].as_str().unwrap()).unwrap()).into_owned()
}

/// CLOSE on a scripted message: `finishWebSocket`, so the normal closure at once and nothing more.
#[tokio::test]
async fn closed_scripted_websocket_closes_normally() {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/ws"}, "httpWebSocketResponse": {"messages": [{"text": "one"}, {"text": "two"}]}})).await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_phase(server.port, json!({"path": "/ws"}), "RESPONSE_STREAM").await;
    let mut socket = websocket(server.port, "/ws", None).await;
    let frame = client.next_frame().await;
    client.decide(&frame, json!({"action": "CLOSE"}));
    assert_eq!(received(&mut socket).await, "close");
    assert!(tokio::time::timeout(Duration::from_millis(300), client.frames.recv()).await.is_err());
}

fn echo_mock() -> Value {
    json!({"httpRequest": {"path": "/echo"}, "httpWebSocketResponse": {"matchers": [
        {"textMatcher": "ping-me", "responses": [{"text": "pong"}]},
        {"frameType": "BINARY", "responses": [{"text": "got binary"}]}
    ]}})
}

/// `BidirectionalWebSocketFrameHandler.channelRead0`: each inbound frame is held (`WS-INBOUND` `/`, a `-ws-inbound`
/// stream) before the matchers see it; MODIFY and INJECT hand the matchers frames of the same kind.
#[tokio::test]
async fn inbound_websocket_frames_are_held_before_matching() {
    let server = common::start(&[]).await;
    common::expect(server.port, &echo_mock()).await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_phase(server.port, json!({"path": "/echo"}), "INBOUND_STREAM").await;
    let mut socket = websocket(server.port, "/echo", None).await;
    socket.send(Message::text("hello")).await.unwrap();
    let frame = client.next_frame().await;
    assert_eq!(frame["direction"], "INBOUND");
    assert_eq!(frame["phase"], "INBOUND_STREAM");
    assert_eq!(frame["requestMethod"], "WS-INBOUND");
    assert_eq!(frame["requestPath"], "/");
    assert!(frame["streamId"].as_str().unwrap().ends_with("-ws-inbound"), "{frame}");
    assert_eq!(decoded(&frame), "hello");
    client.decide(&frame, json!({"action": "MODIFY", "body": encoded("ping-me")}));
    assert_eq!(received(&mut socket).await, "pong");
    socket.send(Message::binary(vec![1u8])).await.unwrap();
    let frame = client.next_frame().await;
    assert_eq!(frame["sequenceNumber"], 1);
    client.decide(&frame, json!({"action": "INJECT", "body": encoded("x")}));
    assert_eq!(received(&mut socket).await, "got binary");
    assert_eq!(received(&mut socket).await, "got binary");
    socket.send(Message::text("ping-me")).await.unwrap();
    let frame = client.next_frame().await;
    client.decide(&frame, json!({"action": "DROP"}));
    socket.send(Message::text("bye")).await.unwrap();
    let frame = client.next_frame().await;
    // CLOSE: `ctx.close()`, the connection goes without a close frame.
    client.decide(&frame, json!({"action": "CLOSE"}));
    assert_eq!(received(&mut socket).await, "gone");
}

/// The matchers' responses are held too (`installBidirectionalHandler`'s `FrameSender`); CLOSE closes normally.
#[tokio::test]
async fn websocket_matcher_responses_are_held() {
    let server = common::start(&[]).await;
    common::expect(server.port, &echo_mock()).await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_phase(server.port, json!({"path": "/echo"}), "RESPONSE_STREAM").await;
    let mut socket = websocket(server.port, "/echo", None).await;
    socket.send(Message::text("ping-me")).await.unwrap();
    let frame = client.next_frame().await;
    assert_eq!(decoded(&frame), "pong");
    assert!(frame["streamId"].as_str().unwrap().ends_with("-ws-stream"), "{frame}");
    client.decide(&frame, json!({"action": "INJECT", "body": encoded("and more")}));
    assert_eq!(received(&mut socket).await, "pong");
    assert_eq!(received(&mut socket).await, "and more");
    socket.send(Message::text("ping-me")).await.unwrap();
    let frame = client.next_frame().await;
    client.decide(&frame, json!({"action": "CLOSE"}));
    assert_eq!(received(&mut socket).await, "close");
}

/// An INBOUND_STREAM hold whose client is not connected: the frame is processed unheld; the registry logs the missing
/// client, but upstream's inbound callers pass no logger, so the dispatch failure is not logged.
#[tokio::test]
async fn inbound_frame_goes_unheld_without_a_log_when_the_client_is_not_connected() {
    let server = common::start(&[]).await;
    common::expect(server.port, &echo_mock()).await;
    let body = json!({"httpRequest": {"path": "/echo"}, "phases": ["INBOUND_STREAM"], "clientId": "absent-client"});
    assert_eq!(common::send(server.port, "PUT", "/mockserver/breakpoint/matcher", &body.to_string()).await.status, 201);
    let mut socket = websocket(server.port, "/echo", None).await;
    socket.send(Message::text("ping-me")).await.unwrap();
    assert_eq!(received(&mut socket).await, "pong");
    let logs = common::logs(server.port).await;
    assert!(logs.contains("client absent-client not found for stream frame message"), "{logs}");
    assert!(!logs.contains("stream frame WS dispatch"), "{logs}");
}

/// `installBidirectionalHandler`'s `FrameSender` runs per response in order: the responses a frame triggers are held
/// one after another, numbered and written in order.
#[tokio::test]
async fn websocket_matcher_responses_are_held_in_order() {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/echo"}, "httpWebSocketResponse": {"matchers": [
        {"textMatcher": "go", "responses": [{"text": "r1"}, {"text": "r2"}, {"text": "r3"}]}
    ]}}))
    .await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_phase(server.port, json!({"path": "/echo"}), "RESPONSE_STREAM").await;
    let mut socket = websocket(server.port, "/echo", None).await;
    socket.send(Message::text("go")).await.unwrap();
    for (sequence, text) in ["r1", "r2", "r3"].iter().enumerate() {
        let frame = client.next_frame().await;
        assert_eq!((frame["sequenceNumber"].as_u64().unwrap(), decoded(&frame)), (sequence as u64, text.to_string()));
        client.decide(&frame, json!({"action": "CONTINUE"}));
        assert_eq!(received(&mut socket).await, *text);
    }
}

/// A raw client for what a text frame carries on the wire: tungstenite would refuse invalid UTF-8.
async fn raw_websocket(port: u16, path: &str) -> tokio::net::TcpStream {
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let head = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
    tcp.write_all(head.as_bytes()).await.unwrap();
    let mut seen = Vec::new();
    while !seen.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8];
        tcp.read_exact(&mut byte).await.unwrap();
        seen.push(byte[0]);
    }
    assert!(seen.starts_with(b"HTTP/1.1 101"), "{}", String::from_utf8_lossy(&seen));
    tcp
}

/// The next frame's opcode and payload (unmasked, short).
async fn raw_frame(tcp: &mut tokio::net::TcpStream) -> (u8, Vec<u8>) {
    let mut head = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut head)).await.expect("a frame").unwrap();
    let mut payload = vec![0u8; (head[1] & 0x7f) as usize];
    tcp.read_exact(&mut payload).await.unwrap();
    (head[0] & 0x0f, payload)
}

/// MODIFY and INJECT bytes on an outbound text frame go out as they are, in a text frame
/// (`new TextWebSocketFrame(Unpooled.wrappedBuffer(bytes))`), whether UTF-8 or not.
#[tokio::test]
async fn outbound_text_frame_carries_the_clients_bytes_as_they_are() {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/ws"}, "httpWebSocketResponse": {"closeConnection": false, "messages": [{"text": "one"}]}})).await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_phase(server.port, json!({"path": "/ws"}), "RESPONSE_STREAM").await;
    let mut tcp = raw_websocket(server.port, "/ws").await;
    let frame = client.next_frame().await;
    client.decide(&frame, json!({"action": "INJECT", "body": encoded([0xff, 0xfe])}));
    assert_eq!(raw_frame(&mut tcp).await, (1, b"one".to_vec()));
    assert_eq!(raw_frame(&mut tcp).await, (1, vec![0xff, 0xfe]));
}

/// An INBOUND_STREAM CLOSE ends the whole session: the script behind it stops, so its later message is never held.
#[tokio::test]
async fn inbound_close_ends_the_script_too() {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/echo"}, "httpWebSocketResponse": {
        "messages": [{"text": "early"}, {"text": "late", "delay": {"timeUnit": "MILLISECONDS", "value": 400}}],
        "matchers": [{"textMatcher": "x", "responses": [{"text": "y"}]}]
    }}))
    .await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_phase(server.port, json!({"path": "/echo"}), "RESPONSE_STREAM").await;
    client.hold_phase(server.port, json!({"path": "/echo"}), "INBOUND_STREAM").await;
    let mut socket = websocket(server.port, "/echo", None).await;
    let early = client.next_frame().await;
    assert_eq!(decoded(&early), "early");
    client.decide(&early, json!({"action": "CONTINUE"}));
    assert_eq!(received(&mut socket).await, "early");
    socket.send(Message::text("x")).await.unwrap();
    let inbound = client.next_frame().await;
    assert_eq!(inbound["phase"], "INBOUND_STREAM");
    client.decide(&inbound, json!({"action": "CLOSE"}));
    assert_eq!(received(&mut socket).await, "gone");
    let next = tokio::time::timeout(Duration::from_millis(800), client.frames.recv()).await;
    assert!(next.is_err(), "the script stopped with the session: {next:?}");
}

// ---------------------------------------------------------------- GraphQL subscriptions

fn subscription_mock() -> Value {
    json!({"httpRequest": {"path": "/graphql"}, "httpWebSocketResponse": {
        "subprotocol": "graphql-transport-ws",
        "graphqlSubscriptionFilter": {"query": "subscription { onA { id } }"},
        "messages": [{"text": "{\"onA\":{\"id\":1}}"}, {"text": "{\"onA\":{\"id\":2}}"}, {"text": "{\"onA\":{\"id\":3}}"}]
    }})
}

async fn subscribe(socket: &mut Socket) {
    socket.send(Message::text(r#"{"type":"connection_init"}"#)).await.unwrap();
    assert_eq!(received(socket).await, r#"{"type":"connection_ack"}"#);
    socket.send(Message::text(r#"{"id":"s1","type":"subscribe","payload":{"query":"subscription { onA { id } }"}}"#)).await.unwrap();
}

/// `installGraphQLSubscriptionHandler`'s `FrameSender`: each `next` is held; DROP still moves on to `complete`.
#[tokio::test]
async fn graphql_next_messages_are_held() {
    let server = common::start(&[]).await;
    common::expect(server.port, &subscription_mock()).await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_phase(server.port, json!({"path": "/graphql"}), "RESPONSE_STREAM").await;
    let mut socket = websocket(server.port, "/graphql", Some("graphql-transport-ws")).await;
    subscribe(&mut socket).await;
    let first = client.next_frame().await;
    let next: Value = serde_json::from_str(&decoded(&first)).unwrap();
    assert_eq!(next, json!({"id": "s1", "type": "next", "payload": {"data": {"onA": {"id": 1}}}}));
    client.decide(&first, json!({"action": "MODIFY", "body": encoded(r#"{"id":"s1","type":"next","payload":{"data":{"onA":{"id":9}}}}"#)}));
    assert_eq!(received(&mut socket).await, r#"{"id":"s1","type":"next","payload":{"data":{"onA":{"id":9}}}}"#);
    let second = client.next_frame().await;
    client.decide(&second, json!({"action": "DROP"}));
    let third = client.next_frame().await;
    assert_eq!(third["sequenceNumber"], 2);
    client.decide(&third, json!({"action": "CONTINUE"}));
    let third: Value = serde_json::from_str(&received(&mut socket).await).unwrap();
    assert_eq!(third["payload"]["data"]["onA"]["id"], 3);
    let complete: Value = serde_json::from_str(&received(&mut socket).await).unwrap();
    assert_eq!(complete, json!({"id": "s1", "type": "complete"}));
}

/// CLOSE on a `next`: the normal closure, and no `complete`.
#[tokio::test]
async fn closed_graphql_subscription_sends_no_complete() {
    let server = common::start(&[]).await;
    common::expect(server.port, &subscription_mock()).await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_phase(server.port, json!({"path": "/graphql"}), "RESPONSE_STREAM").await;
    let mut socket = websocket(server.port, "/graphql", Some("graphql-transport-ws")).await;
    subscribe(&mut socket).await;
    let first = client.next_frame().await;
    client.decide(&first, json!({"action": "CLOSE"}));
    assert_eq!(received(&mut socket).await, "close");
}

/// An outbound CLOSE on one subscription closes the connection, and the other subscriptions stop with it.
#[tokio::test]
async fn closed_graphql_subscription_stops_the_others() {
    let server = common::start(&[]).await;
    common::expect(server.port, &json!({"httpRequest": {"path": "/graphql"}, "httpWebSocketResponse": {
        "subprotocol": "graphql-transport-ws",
        "graphqlSubscriptionFilter": {"query": "subscription { onA { id } }"},
        "messages": [{"text": "{\"onA\":{\"id\":1}}", "delay": {"timeUnit": "MILLISECONDS", "value": 400}}]
    }}))
    .await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_phase(server.port, json!({"path": "/graphql"}), "RESPONSE_STREAM").await;
    let mut socket = websocket(server.port, "/graphql", Some("graphql-transport-ws")).await;
    subscribe(&mut socket).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    socket.send(Message::text(r#"{"id":"s2","type":"subscribe","payload":{"query":"subscription { onA { id } }"}}"#)).await.unwrap();
    let first = client.next_frame().await;
    client.decide(&first, json!({"action": "CLOSE"}));
    assert_eq!(received(&mut socket).await, "close");
    let next = tokio::time::timeout(Duration::from_millis(800), client.frames.recv()).await;
    assert!(next.is_err(), "the second subscription stopped with the session: {next:?}");
}

/// `GraphQLSubscriptionHandler.channelRead0`: inbound text is held (`GQL-INBOUND` `/`) before the protocol sees it.
#[tokio::test]
async fn graphql_inbound_messages_are_held() {
    let server = common::start(&[]).await;
    common::expect(server.port, &subscription_mock()).await;
    let mut client = FrameClient::connect(server.port).await;
    client.hold_phase(server.port, json!({"path": "/graphql"}), "INBOUND_STREAM").await;
    let mut socket = websocket(server.port, "/graphql", Some("graphql-transport-ws")).await;
    socket.send(Message::text(r#"{"type":"connection_init"}"#)).await.unwrap();
    let init = client.next_frame().await;
    assert_eq!(init["requestMethod"], "GQL-INBOUND");
    assert_eq!(init["requestPath"], "/");
    assert!(init["streamId"].as_str().unwrap().ends_with("-ws-inbound"), "{init}");
    // INJECT a ping after the init: both are processed.
    client.decide(&init, json!({"action": "INJECT", "body": encoded(r#"{"type":"ping"}"#)}));
    assert_eq!(received(&mut socket).await, r#"{"type":"connection_ack"}"#);
    assert_eq!(received(&mut socket).await, r#"{"type":"pong"}"#);
    socket.send(Message::text(r#"{"type":"ping"}"#)).await.unwrap();
    let ping = client.next_frame().await;
    client.decide(&ping, json!({"action": "CLOSE"}));
    assert_eq!(received(&mut socket).await, "close");
}

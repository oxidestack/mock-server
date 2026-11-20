//! gRPC chaos and response trailers over HTTP/2, frame by frame: what `GrpcToHttpRequestHandlerChaosTest` checks on
//! the handler's output and `ResponseTrailersHttp2ConversionTest` on Netty's HTTP/2 conversion, observed on the wire.
//! Every expected frame sequence was recorded from the mockserver/mockserver:8.0.0 oracle over h2c (prior knowledge)
//! with the same requests; the HTTP/1.1 view of the same faults is the scenario `w2_gc_grpc_chaos_faults`.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::common;

const GREETING: &str = "/com.example.grpc.GreetingService/Greeting";
const SERVICE: &str = "com.example.grpc.GreetingService";

async fn server() -> common::Running {
    let descriptors = concat!(env!("CARGO_MANIFEST_DIR"), "/upstream/mockserver/mockserver/mockserver-core/src/test/resources/grpc");
    common::start(&[("grpcDescriptorDirectory", descriptors)]).await
}

/// A `HelloRequest {name}` as one length-prefixed gRPC message.
fn hello(name: &str) -> Vec<u8> {
    let mut message = vec![0x0a, name.len() as u8];
    message.extend_from_slice(name.as_bytes());
    let mut frame = vec![0];
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(&message);
    frame
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    out.extend_from_slice(&[kind, flags]);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn fields(list: &[(Vec<u8>, Vec<u8>)]) -> String {
    let shown: Vec<String> = list.iter().map(|(n, v)| format!("{}: {}", String::from_utf8_lossy(n), String::from_utf8_lossy(v))).collect();
    shown.join(", ")
}

/// One request on stream 1 of its own h2c connection; the server's frames on that stream, as
/// `HEADERS [..]`, `TRAILERS [..]`, `DATA n` (each with ` end` on END_STREAM) and `RST_STREAM code`; `TIMEOUT` when
/// the stream is still open after two seconds.
async fn call(port: u16, method: &str, path: &str, content_type: Option<&str>, body: Vec<u8>) -> (Vec<String>, Duration) {
    let (method, path, content_type) = (method.to_string(), path.to_string(), content_type.map(str::to_string));
    tokio::task::spawn_blocking(move || {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut request = vec![(b":method".to_vec(), method.into_bytes()), (b":scheme".to_vec(), b"http".to_vec())];
        request.push((b":authority".to_vec(), format!("localhost:{port}").into_bytes()));
        request.push((b":path".to_vec(), path.into_bytes()));
        if let Some(ct) = content_type {
            request.push((b"content-type".to_vec(), ct.into_bytes()));
            request.push((b"te".to_vec(), b"trailers".to_vec()));
        }
        let block = loona_hpack::Encoder::new().encode(request.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
        let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        out.extend(frame(0x4, 0, 0, &[]));
        out.extend(frame(0x1, 0x4 | if body.is_empty() { 0x1 } else { 0 }, 1, &block));
        if !body.is_empty() {
            out.extend(frame(0x0, 0x1, 1, &body));
        }
        let started = Instant::now();
        s.write_all(&out).unwrap();
        let mut decoder = loona_hpack::Decoder::new();
        let (mut events, mut headers_seen, mut buf) = (Vec::new(), false, Vec::new());
        loop {
            while buf.len() >= 9 && buf.len() >= 9 + (u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize) {
                let length = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
                let (kind, flags, stream) = (buf[3], buf[4], u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff);
                let payload: Vec<u8> = buf[9..9 + length].to_vec();
                buf.drain(..9 + length);
                if kind == 0x4 && flags & 0x1 == 0 {
                    s.write_all(&frame(0x4, 0x1, 0, &[])).unwrap();
                }
                if stream != 1 {
                    continue;
                }
                let end = if flags & 0x1 != 0 { " end" } else { "" };
                match kind {
                    0x1 => {
                        let decoded = decoder.decode(&payload).expect("hpack");
                        events.push(format!("{} [{}]{end}", if headers_seen { "TRAILERS" } else { "HEADERS" }, fields(&decoded)));
                        headers_seen = true;
                    }
                    0x0 => events.push(format!("DATA {}{end}", payload.len())),
                    0x3 => {
                        events.push(format!("RST_STREAM {}", u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])));
                        return (events, started.elapsed());
                    }
                    _ => {}
                }
                if !end.is_empty() {
                    return (events, started.elapsed());
                }
            }
            let mut chunk = [0u8; 16384];
            match s.read(&mut chunk) {
                Ok(0) => {
                    events.push("EOF".into());
                    return (events, started.elapsed());
                }
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => {
                    events.push("TIMEOUT".into());
                    return (events, started.elapsed());
                }
            }
        }
    })
    .await
    .unwrap()
}

async fn grpc(port: u16, body: Vec<u8>) -> Vec<String> {
    call(port, "POST", GREETING, Some("application/grpc"), body).await.0
}

async fn grpc_chaos(port: u16, chaos: Value) {
    let r = common::send(port, "PUT", "/mockserver/grpcChaos", &json!({"service": SERVICE, "chaos": chaos}).to_string()).await;
    assert_eq!(r.status, 200, "{}", r.body);
}

const GRPC_HEAD: &str = ":status: 200, content-type: application/grpc, grpc-accept-encoding: identity, gzip";

#[tokio::test]
async fn injects_configured_grpc_status_with_custom_trailers_in_a_trailers_frame() {
    let s = server().await;
    grpc_chaos(s.port, json!({"errorProbability": 1.0, "errorStatusCode": "UNAVAILABLE", "errorMessage": "down 50% now", "customTrailers": {"x-a": "1", "x-b": "two"}})).await;
    assert_eq!(grpc(s.port, hello("Alice")).await, vec![
        format!("HEADERS [{GRPC_HEAD}, trailer: grpc-status, grpc-message, x-a, x-b]"),
        "TRAILERS [grpc-status: 14, grpc-message: down 50%25 now, x-a: 1, x-b: two] end".to_string(),
    ]);
}

#[tokio::test]
async fn status_only_fault_is_trailers_only() {
    let s = server().await;
    grpc_chaos(s.port, json!({"errorProbability": 1.0})).await;
    assert_eq!(grpc(s.port, hello("Alice")).await, vec![format!("HEADERS [{GRPC_HEAD}, grpc-status: 14, grpc-message: UNAVAILABLE, content-length: 0] end")]);
}

#[tokio::test]
async fn omit_grpc_status_produces_response_with_no_grpc_status_header() {
    let s = server().await;
    grpc_chaos(s.port, json!({"omitGrpcStatus": true})).await;
    assert_eq!(grpc(s.port, hello("Alice")).await, vec![format!("HEADERS [{GRPC_HEAD}, content-length: 0] end")]);
}

#[tokio::test]
async fn corrupt_grpc_status_produces_response_with_non_numeric_status_value() {
    let s = server().await;
    grpc_chaos(s.port, json!({"corruptGrpcStatus": true})).await;
    assert_eq!(grpc(s.port, hello("Alice")).await, vec![format!("HEADERS [{GRPC_HEAD}, grpc-status: malformed, grpc-message: chaos fault, content-length: 0] end")]);
}

#[tokio::test]
async fn custom_trailer_with_null_value_is_announced_but_not_sent() {
    let s = server().await;
    grpc_chaos(s.port, json!({"customTrailers": {"x-n": null, "x-e": ""}})).await;
    assert_eq!(grpc(s.port, hello("Alice")).await, vec![
        format!("HEADERS [{GRPC_HEAD}, trailer: grpc-status, grpc-message, x-n, x-e]"),
        "TRAILERS [grpc-status: 13, grpc-message: chaos fault, x-e: ] end".to_string(),
    ]);
}

#[tokio::test]
async fn abort_after_messages_injects_aborted_for_multi_message_request() {
    let s = server().await;
    common::expect(s.port, &json!({"httpRequest": {"path": GREETING}, "httpResponse": {"body": "{\"greeting\":\"hi\"}"}})).await;
    grpc_chaos(s.port, json!({"abortAfterMessages": 2})).await;
    assert_eq!(grpc(s.port, hello("A")).await, vec![format!("HEADERS [{GRPC_HEAD}, trailer: grpc-status]"), "DATA 9".into(), "TRAILERS [grpc-status: 0] end".into()]);
    let three = [hello("A"), hello("B"), hello("C")].concat();
    assert_eq!(grpc(s.port, three).await, vec![format!("HEADERS [{GRPC_HEAD}, grpc-status: 10, grpc-message: aborted after 3 messages, content-length: 0] end")]);
}

#[tokio::test]
async fn fault_latency_delays_the_response() {
    let s = server().await;
    // the global profile (service "") covers a service without one of its own, even one no descriptor declares
    let global = json!({"service": "", "chaos": {"latencyMs": 300, "errorProbability": 1.0, "errorStatusCode": "not_found"}});
    assert_eq!(common::send(s.port, "PUT", "/mockserver/grpcChaos", &global.to_string()).await.status, 200);
    let (events, took) = call(s.port, "POST", "/com.other.X/Y", Some("application/grpc"), hello("A")).await;
    assert!(took >= Duration::from_millis(300), "answered after {took:?}");
    assert_eq!(events, vec![format!("HEADERS [{GRPC_HEAD}, grpc-status: 5, grpc-message: NOT_FOUND, content-length: 0] end")]);
}

#[tokio::test]
async fn grpc_web_fault_folds_trailers_into_the_body() {
    let s = server().await;
    grpc_chaos(s.port, json!({"errorProbability": 1.0, "customTrailers": {"x-a": "1"}})).await;
    let (events, _) = call(s.port, "POST", GREETING, Some("application/grpc-web+proto"), hello("Alice")).await;
    assert_eq!(events, vec![
        "HEADERS [:status: 200, grpc-accept-encoding: identity, gzip, content-type: application/grpc-web+proto, content-length: 57]".to_string(),
        "DATA 57 end".into(),
    ]);
}

#[tokio::test]
async fn expectation_chaos_drop_connection_cancels_the_stream() {
    let s = server().await;
    common::expect(s.port, &json!({"httpRequest": {"path": GREETING}, "httpResponse": {"body": "x"}, "chaos": {"dropConnectionProbability": 1.0}})).await;
    assert_eq!(grpc(s.port, hello("Alice")).await, vec!["RST_STREAM 8"]);
    common::expect(s.port, &json!({"httpRequest": {"path": "/plain"}, "httpError": {"dropConnection": true}})).await;
    assert_eq!(call(s.port, "GET", "/plain", None, Vec::new()).await.0, vec!["RST_STREAM 8"]);
}

#[tokio::test]
async fn expectation_chaos_unencodable_body_keeps_the_response_headers() {
    let s = server().await;
    common::expect(s.port, &json!({"httpRequest": {"path": GREETING}, "httpResponse": {"headers": {"x-u": ["1"]}, "body": "{\"greeting\":\"hello there\"}"}, "chaos": {"truncateBodyAtFraction": 0.5}})).await;
    assert_eq!(grpc(s.port, hello("Alice")).await, vec![
        "HEADERS [:status: 200, x-u: 1, content-type: application/grpc, trailer: grpc-status, grpc-message]".to_string(),
        "TRAILERS [grpc-status: 13, grpc-message: failed to encode gRPC response] end".to_string(),
    ]);
}

#[tokio::test]
async fn slow_chunks_end_the_stream_with_the_last_one() {
    let s = server().await;
    common::expect(s.port, &json!({"httpRequest": {"path": "/plain"}, "httpResponse": {"body": "abcdefgh", "connectionOptions": {"chunkSize": 3, "chunkDelay": {"timeUnit": "MILLISECONDS", "value": 5}}}})).await;
    assert_eq!(call(s.port, "GET", "/plain", None, Vec::new()).await.0, vec!["HEADERS [:status: 200]", "DATA 3", "DATA 3", "DATA 2 end"]);
}

#[tokio::test]
async fn response_trailers_follow_the_body_in_a_trailers_frame() {
    let s = server().await;
    common::expect(s.port, &json!({"httpRequest": {"path": "/body"}, "httpResponse": {"body": "hello", "trailers": {"x-t": ["1", "2"], "x-s": ["v"]}}})).await;
    common::expect(s.port, &json!({"httpRequest": {"path": "/empty"}, "httpResponse": {"trailers": {"x-t": ["1"]}}})).await;
    common::expect(s.port, &json!({"httpRequest": {"path": "/override"}, "httpResponse": {"body": "hello", "connectionOptions": {"contentLengthHeaderOverride": 3}, "trailers": {"x-t": ["1"]}}})).await;
    let get = |path: &'static str| call(s.port, "GET", path, None, Vec::new());
    assert_eq!(get("/body").await.0, vec!["HEADERS [:status: 200, trailer: x-t, x-s]", "DATA 5", "TRAILERS [x-t: 1, x-t: 2, x-s: v] end"]);
    assert_eq!(get("/empty").await.0, vec!["HEADERS [:status: 200, trailer: x-t]", "TRAILERS [x-t: 1] end"]);
    assert_eq!(get("/override").await.0, vec!["HEADERS [:status: 200, trailer: x-t]", "DATA 5", "TRAILERS [x-t: 1] end"]);
}

#[tokio::test]
async fn no_content_keeps_its_length_and_body_over_http2() {
    let s = server().await;
    common::expect(s.port, &json!({"httpRequest": {"path": "/204"}, "httpResponse": {"statusCode": 204, "body": "x", "trailers": {"x-t": ["1"]}}})).await;
    common::expect(s.port, &json!({"httpRequest": {"path": "/304"}, "httpResponse": {"statusCode": 304}})).await;
    assert_eq!(call(s.port, "GET", "/204", None, Vec::new()).await.0, vec!["HEADERS [:status: 204, content-length: 1]", "DATA 1", "TRAILERS [x-t: 1] end"]);
    assert_eq!(call(s.port, "GET", "/304", None, Vec::new()).await.0, vec!["HEADERS [:status: 304, content-length: 0] end"]);
}

#[tokio::test]
async fn abort_after_messages_with_malformed_frame_does_not_throw() {
    // An undecodable body is 0 messages, below the threshold: the call passes through and fails to decode.
    let s = server().await;
    grpc_chaos(s.port, json!({"abortAfterMessages": 1})).await;
    assert_eq!(grpc(s.port, vec![0, 0, 0]).await, vec![format!("HEADERS [{GRPC_HEAD}, grpc-status: 13, grpc-message: failed to decode gRPC frame from request body, content-length: 0] end")]);
}

#[tokio::test]
async fn abort_after_messages_with_empty_body_does_not_throw() {
    let s = server().await;
    common::expect(s.port, &json!({"httpRequest": {"path": GREETING}, "httpResponse": {"body": "{\"greeting\":\"hi\"}"}})).await;
    grpc_chaos(s.port, json!({"abortAfterMessages": 1})).await;
    assert_eq!(grpc(s.port, Vec::new()).await, vec![format!("HEADERS [{GRPC_HEAD}, trailer: grpc-status]"), "DATA 9".into(), "TRAILERS [grpc-status: 0] end".into()]);
}

/// The client resets the stream while a `chunkDelay` body is being dribbled: nothing more is written on it, and the
/// connection keeps serving.
#[tokio::test]
async fn reset_mid_dribble_stops_the_stream() {
    let s = server().await;
    common::expect(s.port, &json!({"httpRequest": {"path": "/slow"}, "httpResponse": {"body": "abcdefghij", "connectionOptions": {"chunkSize": 1, "chunkDelay": {"timeUnit": "MILLISECONDS", "value": 100}}}})).await;
    common::expect(s.port, &json!({"httpRequest": {"path": "/fast"}, "httpResponse": {"body": "ok"}})).await;
    let port = s.port;
    let frames = tokio::task::spawn_blocking(move || {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let mut encoder = loona_hpack::Encoder::new();
        let mut head = |path: &str| {
            let fields = [(&b":method"[..], &b"GET"[..]), (b":scheme", b"http"), (b":authority", b"localhost"), (b":path", path.as_bytes())];
            encoder.encode(fields.iter().map(|(n, v)| (*n, *v)))
        };
        let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        out.extend(frame(0x4, 0, 0, &[]));
        out.extend(frame(0x1, 0x5, 1, &head("/slow")));
        s.write_all(&out).unwrap();
        // (stream, type) of every frame read until `until` has passed
        let mut seen: Vec<(u32, u8)> = Vec::new();
        let mut buf = Vec::new();
        let mut read_for = |s: &mut std::net::TcpStream, seen: &mut Vec<(u32, u8)>, until: Instant| {
            while Instant::now() < until {
                let mut chunk = [0u8; 4096];
                if let Ok(n) = s.read(&mut chunk) {
                    buf.extend_from_slice(&chunk[..n]);
                }
                while buf.len() >= 9 && buf.len() >= 9 + (u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize) {
                    let length = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
                    let (kind, flags, stream) = (buf[3], buf[4], u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff);
                    buf.drain(..9 + length);
                    if kind == 0x4 && flags & 0x1 == 0 {
                        s.write_all(&frame(0x4, 0x1, 0, &[])).unwrap();
                    }
                    if stream != 0 {
                        seen.push((stream, kind));
                    }
                }
            }
        };
        read_for(&mut s, &mut seen, Instant::now() + Duration::from_millis(350));
        let before_reset = seen.iter().filter(|(st, k)| *st == 1 && *k == 0x0).count();
        s.write_all(&frame(0x3, 0, 1, &8u32.to_be_bytes())).unwrap();
        let reset_at = seen.len();
        s.write_all(&frame(0x1, 0x5, 3, &head("/fast"))).unwrap();
        read_for(&mut s, &mut seen, Instant::now() + Duration::from_millis(600));
        (before_reset, seen[reset_at..].to_vec())
    })
    .await
    .unwrap();
    let (before_reset, after) = frames;
    assert!(before_reset >= 1, "some chunks were written before the reset");
    assert!(after.contains(&(3, 0x1)) && after.contains(&(3, 0x0)), "the next stream is answered: {after:?}");
    // A chunk the server wrote before it read the RST_STREAM may still arrive (RFC 9113 §5.4.2, §6.4). The server
    // reads the RST before stream 3's HEADERS and queues the reset ahead of stream 3's response, so nothing on stream
    // 1 may follow stream 3's first frame, although the dribble would have produced several more chunks by now.
    let third = after.iter().position(|(stream, _)| *stream == 3).unwrap();
    assert!(!after[third..].iter().any(|(stream, _)| *stream == 1), "frames on the reset stream after it was processed: {after:?}");
}

#[tokio::test]
async fn expectation_chunk_delay_on_an_empty_body_ends_with_an_empty_data_frame() {
    let s = server().await;
    common::expect(s.port, &json!({"httpRequest": {"path": "/empty"}, "httpResponse": {"connectionOptions": {"chunkSize": 3, "chunkDelay": {"timeUnit": "MILLISECONDS", "value": 200}}}})).await;
    let (events, took) = call(s.port, "GET", "/empty", None, Vec::new()).await;
    assert_eq!(events, vec!["HEADERS [:status: 200]", "DATA 0 end"]);
    assert!(took >= Duration::from_millis(200), "the empty chunk waits for its delay: {took:?}");
}

// ---- `GrpcChaosDecisionTest` and the decision cases of `GrpcToHttpRequestHandlerChaosTest` ----
// `GrpcChaosDecisionTest.shouldHandleNullQuotaRegistry` is not ported: the quotas are the server's own registry and
// cannot be absent.

use mock_server::{GrpcChaos, GrpcChaosProfile, GrpcFault};

const SVC: &str = "com.example.Svc";

fn chaos_with(profile: Value) -> GrpcChaos {
    let chaos = GrpcChaos::new();
    chaos.put(SVC, &profile).expect("valid profile");
    chaos
}

fn profile(v: Value) -> GrpcChaosProfile {
    GrpcChaosProfile::parse(&v).expect("valid profile")
}

fn fault(code: &'static str, message: Option<&str>) -> Option<GrpcFault> {
    Some(GrpcFault { status_code: code, message: message.map(str::to_string) })
}

#[test]
fn should_always_fault_with_probability_one() {
    let p = profile(json!({"errorProbability": 1.0, "errorStatusCode": "INTERNAL", "errorMessage": "chaos injected"}));
    assert_eq!(GrpcChaos::new().decide(&p, 1), fault("INTERNAL", Some("chaos injected")));
}

#[test]
fn should_never_fault_with_probability_zero() {
    assert_eq!(GrpcChaos::new().decide(&profile(json!({"errorProbability": 0.0})), 1), None);
}

#[test]
fn should_default_to_unavailable_without_a_message() {
    assert_eq!(GrpcChaos::new().decide(&profile(json!({"errorProbability": 1.0})), 1), fault("UNAVAILABLE", None));
    assert_eq!(GrpcChaos::new().decide(&profile(json!({"errorProbability": 1.0, "errorStatusCode": "DEADLINE_EXCEEDED"})), 1), fault("DEADLINE_EXCEEDED", None));
}

#[test]
fn should_respect_succeed_first_window() {
    let p = profile(json!({"errorProbability": 1.0, "succeedFirst": 3}));
    let chaos = GrpcChaos::new();
    assert!((1..=3).all(|n| chaos.decide(&p, n).is_none()));
    assert!(chaos.decide(&p, 4).is_some());
}

#[test]
fn should_respect_fail_request_count_window() {
    let p = profile(json!({"errorProbability": 1.0, "errorStatusCode": "UNAVAILABLE", "succeedFirst": 2, "failRequestCount": 3}));
    let chaos = GrpcChaos::new();
    let decided: Vec<bool> = (1..=6).map(|n| chaos.decide(&p, n).is_some()).collect();
    assert_eq!(decided, vec![false, false, true, true, true, false]);
}

#[test]
fn should_return_resource_exhausted_when_quota_exceeded() {
    let p = profile(json!({"quotaName": "grpc-limit", "quotaLimit": 2, "quotaWindowMillis": 60000}));
    let chaos = GrpcChaos::new();
    assert_eq!(chaos.decide(&p, 1), None);
    assert_eq!(chaos.decide(&p, 2), None);
    assert_eq!(chaos.decide(&p, 3), fault("RESOURCE_EXHAUSTED", Some("quota exceeded")));
}

#[test]
fn should_return_custom_message_on_quota_exceeded() {
    let p = profile(json!({"quotaName": "custom-msg-quota", "quotaLimit": 1, "quotaWindowMillis": 60000, "errorMessage": "rate limited"}));
    let chaos = GrpcChaos::new();
    assert_eq!(chaos.decide(&p, 1), None);
    assert_eq!(chaos.decide(&p, 2), fault("RESOURCE_EXHAUSTED", Some("rate limited")));
}

#[test]
fn should_be_deterministic_with_fixed_seed() {
    // A seeded draw is `new Random(seed).nextDouble()` per call (`ChaosProbability`), so it repeats.
    let chaos = GrpcChaos::new();
    let certain = profile(json!({"errorProbability": 1.0, "seed": 42, "errorStatusCode": "INTERNAL"}));
    assert_eq!(chaos.decide(&certain, 1), chaos.decide(&certain, 2));
    assert_eq!(chaos.decide(&certain, 1), fault("INTERNAL", None));
    let half = profile(json!({"errorProbability": 0.5, "seed": 7}));
    let first = chaos.decide(&half, 1).is_some();
    assert!((0..50).all(|_| chaos.decide(&half, 1).is_some() == first));
}

#[test]
fn should_inject_roughly_half_the_time_with_probability_one_half() {
    let p = profile(json!({"errorProbability": 0.5, "errorStatusCode": "UNAVAILABLE"}));
    let chaos = GrpcChaos::new();
    let faults = (0..5000).filter(|_| chaos.decide(&p, 1).is_some()).count();
    assert!((2000..3000).contains(&faults), "{faults} of 5000");
}

#[test]
fn should_handle_profile_with_no_faults() {
    assert_eq!(GrpcChaos::new().decide(&profile(json!({})), 1), None);
}

#[test]
fn quota_takes_priority_over_probabilistic_error() {
    let p = profile(json!({"errorProbability": 1.0, "errorStatusCode": "INTERNAL", "quotaName": "priority-test", "quotaLimit": 1, "quotaWindowMillis": 60000}));
    let chaos = GrpcChaos::new();
    assert_eq!(chaos.decide(&p, 1).map(|f| f.status_code), Some("INTERNAL"));
    assert_eq!(chaos.decide(&p, 2).map(|f| f.status_code), Some("RESOURCE_EXHAUSTED"));
}

#[test]
fn custom_trailers_with_crlf_are_rejected_by_setter() {
    let key = GrpcChaosProfile::parse(&json!({"customTrailers": {"x-injected\r\nevil": "value"}})).expect_err("rejected");
    assert!(key.contains("CR or LF"), "{key}");
    let value = GrpcChaosProfile::parse(&json!({"customTrailers": {"key": "value\r\nEvil: header"}})).expect_err("rejected");
    assert!(value.contains("CR or LF"), "{value}");
}

#[test]
fn passes_through_when_no_chaos_registered() {
    assert!(GrpcChaos::new().fault(SVC, || 0).is_none());
}

#[test]
fn injects_configured_status_when_probability_is_one() {
    let f = chaos_with(json!({"errorProbability": 1.0, "errorStatusCode": "deadline_exceeded"})).fault(SVC, || 0).unwrap();
    assert_eq!(f.trailer("grpc-status"), Some("4"));
    assert_eq!(f.trailer("grpc-message"), Some("DEADLINE_EXCEEDED"));
}

#[test]
fn service_lookup_is_case_insensitive_and_falls_back_to_global() {
    let chaos = GrpcChaos::new();
    chaos.put("", &json!({"errorProbability": 1.0})).unwrap();
    assert!(chaos.fault("Other.Service", || 0).is_some());
    chaos.put("MY.Svc", &json!({"errorProbability": 1.0, "errorStatusCode": "ABORTED"})).unwrap();
    assert_eq!(chaos.fault("my.svc", || 0).unwrap().trailer("grpc-status"), Some("10"));
}

#[test]
fn omit_grpc_status_takes_priority_over_corrupt_grpc_status() {
    let f = chaos_with(json!({"omitGrpcStatus": true, "corruptGrpcStatus": true, "errorProbability": 1.0})).fault(SVC, || 0).unwrap();
    assert!(f.trailers().is_empty());
}

#[test]
fn corrupt_grpc_status_combined_with_error_probability() {
    let f = chaos_with(json!({"corruptGrpcStatus": true, "errorProbability": 1.0, "errorMessage": "x"})).fault(SVC, || 0).unwrap();
    assert_eq!(f.trailer("grpc-status"), Some("malformed"));
    assert_eq!(f.trailer("grpc-message"), Some("x"));
}

#[test]
fn custom_trailers_combined_with_error_probability() {
    let f = chaos_with(json!({"customTrailers": {"x-a": "1"}, "errorProbability": 1.0, "errorStatusCode": "UNAVAILABLE"})).fault(SVC, || 0).unwrap();
    assert_eq!(f.trailers(), &[("grpc-status".to_string(), "14".to_string()), ("grpc-message".into(), "UNAVAILABLE".into()), ("x-a".into(), "1".into())]);
}

#[test]
fn abort_after_messages_counts_only_when_configured_and_at_the_threshold() {
    let chaos = chaos_with(json!({"abortAfterMessages": 3}));
    assert!(chaos.fault(SVC, || 2).is_none());
    let f = chaos.fault(SVC, || 3).unwrap();
    assert_eq!(f.trailer("grpc-status"), Some("10"));
    assert_eq!(f.trailer("grpc-message"), Some("aborted after 3 messages"));
    let other = chaos_with(json!({"errorProbability": 1.0}));
    assert!(other.fault(SVC, || panic!("messages counted without abortAfterMessages")).is_some());
}

#[test]
fn abort_after_messages_combined_with_omit_grpc_status_and_custom_trailers() {
    let f = chaos_with(json!({"abortAfterMessages": 1, "omitGrpcStatus": true, "customTrailers": {"x-a": "1"}})).fault(SVC, || 1).unwrap();
    assert_eq!(f.trailers(), &[("x-a".to_string(), "1".to_string())]);
}

#[test]
fn abort_after_messages_respects_count_window() {
    let chaos = chaos_with(json!({"abortAfterMessages": 1, "succeedFirst": 1, "failRequestCount": 1}));
    let faulted: Vec<bool> = (0..3).map(|_| chaos.fault(SVC, || 5).is_some()).collect();
    assert_eq!(faulted, vec![false, true, false]);
}

#[test]
fn latency_is_applied_only_to_a_fault() {
    assert!(chaos_with(json!({"latencyMs": 250})).fault(SVC, || 0).is_none());
    assert_eq!(chaos_with(json!({"latencyMs": 250, "errorProbability": 1.0})).fault(SVC, || 0).unwrap().latency_ms, 250);
}

#[test]
fn null_custom_trailer_is_announced_but_not_written() {
    let f = chaos_with(json!({"customTrailers": {"x-n": null, "x-e": ""}})).fault(SVC, || 0).unwrap();
    assert_eq!(f.announced.as_deref(), Some("grpc-status, grpc-message, x-n, x-e"));
    assert_eq!(f.trailer("x-n"), None);
    assert_eq!(f.trailer("x-e"), Some(""));
}

// ---- HTTP/3 (`Http3ResponseWriter.writeStaticResponse`, `Http3RequestBridge`): source-checked, the oracle image has
// no native QUIC transport ----

struct H3Response {
    status: u16,
    headers: Vec<String>,
    body: Vec<u8>,
    trailers: Vec<String>,
}

async fn h3_get(port: u16, path: &str) -> H3Response {
    h3_request(port, "GET", path, None, Vec::new()).await
}

/// One request on a fresh QUIC connection: the response head, the body, and the trailing HEADERS frame's fields.
async fn h3_request(port: u16, method: &str, path: &str, content_type: Option<&str>, body_out: Vec<u8>) -> H3Response {
    use bytes::Buf;
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
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let mut request = http::Request::builder().method(method).uri(format!("https://localhost:{port}{path}"));
    if let Some(ct) = content_type {
        request = request.header("content-type", ct).header("te", "trailers");
    }
    let mut stream = sender.send_request(request.body(()).unwrap()).await.unwrap();
    if !body_out.is_empty() {
        stream.send_data(bytes::Bytes::from(body_out)).await.unwrap();
    }
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let piece = chunk.chunk().to_vec();
            chunk.advance(piece.len());
            body.extend(piece);
        }
    }
    let trailers = stream.recv_trailers().await.unwrap().map(|t| t.iter().map(|(k, v)| format!("{k}: {}", v.to_str().unwrap())).collect()).unwrap_or_default();
    let headers = response.headers().iter().map(|(k, v)| format!("{k}: {}", v.to_str().unwrap())).collect();
    drop(sender);
    drive.abort();
    endpoint.close(0u32.into(), b"");
    H3Response { status: response.status().as_u16(), headers, body, trailers }
}

#[tokio::test(flavor = "multi_thread")]
async fn http3_writes_model_headers_only_and_every_body() {
    let (s, h3) = common::start_with_http3(&[]).await;
    common::expect(s.port, &json!({"httpRequest": {"path": "/trailers"}, "httpResponse": {"headers": {"x-a": ["1"]}, "body": "hello", "trailers": {"x-t": ["1"]}}})).await;
    common::expect(s.port, &json!({"httpRequest": {"path": "/204"}, "httpResponse": {"statusCode": 204, "body": "abc"}})).await;
    common::expect(s.port, &json!({"httpRequest": {"path": "/json"}, "httpResponse": {"body": {"type": "JSON", "json": {"a": 1}}, "connectionOptions": {"chunkSize": 2, "chunkDelay": {"timeUnit": "SECONDS", "value": 5}, "contentLengthHeaderOverride": 1}}})).await;
    let r = h3_get(h3, "/trailers").await;
    assert_eq!((r.status, r.headers, r.body, r.trailers), (200, vec!["server: mockserver-http3".to_string(), "x-a: 1".into()], b"hello".to_vec(), vec!["x-t: 1".to_string()]));
    let r = h3_get(h3, "/204").await;
    assert_eq!((r.status, r.headers, r.body), (204, vec!["server: mockserver-http3".to_string()], b"abc".to_vec()));
    // connectionOptions framing does not apply: no dribble, no length, no content type from the body
    let started = Instant::now();
    let r = h3_get(h3, "/json").await;
    assert!(started.elapsed() < Duration::from_secs(4), "not dribbled");
    assert_eq!((r.headers, r.body), (vec!["server: mockserver-http3".to_string()], b"{\n  \"a\" : 1\n}".to_vec()));
}

/// `Http3GrpcIntegrationTest`: gRPC over HTTP/3 keeps `grpc-status`, `grpc-message` and user trailing metadata in the
/// trailing HEADERS frame (`Http3GrpcResponseWriter`); only a body-less answer is Trailers-Only, every trailer in the
/// one HEADERS frame (`buildTrailersOnlyFrame`).
#[tokio::test(flavor = "multi_thread")]
async fn http3_grpc_status_and_metadata_ride_the_trailing_headers() {
    let descriptors = concat!(env!("CARGO_MANIFEST_DIR"), "/upstream/mockserver/mockserver/mockserver-core/src/test/resources/grpc");
    let (s, h3) = common::start_with_http3(&[("grpcDescriptorDirectory", descriptors)]).await;
    common::expect(s.port, &json!({"httpRequest": {"path": GREETING, "body": {"type": "JSON", "json": {"name": "Alice"}}}, "httpResponse": {"body": "{\"greeting\":\"hi\"}", "trailers": {"x-request-cost": ["42"]}}})).await;
    common::expect(s.port, &json!({"httpRequest": {"path": GREETING, "body": {"type": "JSON", "json": {"name": "Bob"}}}, "httpResponse": {"headers": {"grpc-status-name": ["NOT_FOUND"], "grpc-message": ["no bob"]}, "trailers": {"x-request-cost": ["7"]}}})).await;
    let r = h3_request(h3, "POST", GREETING, Some("application/grpc"), hello("Alice")).await;
    assert_eq!(r.status, 200);
    assert!(r.headers.contains(&"content-type: application/grpc".to_string()), "{:?}", r.headers);
    assert!(!r.headers.iter().any(|h| h.starts_with("grpc-status") || h.starts_with("x-request-cost")), "initial headers: {:?}", r.headers);
    assert_eq!(r.body, vec![0, 0, 0, 0, 4, 0x0a, 2, b'h', b'i']);
    assert_eq!(r.trailers, vec!["x-request-cost: 42".to_string(), "grpc-status: 0".into()]);
    let r = h3_request(h3, "POST", GREETING, Some("application/grpc"), hello("Bob")).await;
    assert!(r.body.is_empty() && r.trailers.is_empty(), "{:?} {:?}", r.body, r.trailers);
    assert!(r.headers.contains(&"grpc-status: 5".to_string()) && r.headers.contains(&"grpc-message: no bob".to_string()) && r.headers.contains(&"x-request-cost: 7".to_string()), "{:?}", r.headers);
}

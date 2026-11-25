//! gRPC over the data plane (`GrpcToHttpRequestHandler` / `GrpcToHttpResponseHandler`): a request with an
//! `application/grpc` content type for a method of a loaded descriptor set is matched as an HTTP request whose body is
//! the message as JSON (a JSON array for several messages), and the response is turned back into a length-prefixed
//! protobuf message with `grpc-status` / `grpc-message` trailers. `grpc-timeout` deadlines answer
//! `DEADLINE_EXCEEDED` when the response is not ready in time.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;

use crate::handler::{Outcome, TraceChannel};
use crate::recorded::{Level, LogEntry};
use crate::reply::Reply;
use crate::request::HttpRequest;
use crate::state::State;

pub const CONTENT_TYPE: &str = "application/grpc";
pub const ACCEPT_ENCODING: &str = "identity, gzip";
const SERVICE: &str = "x-grpc-service";
const METHOD: &str = "x-grpc-method";
const ORIGINAL_CONTENT_TYPE: &str = "x-grpc-original-content-type";
const CLIENT_STREAMING: &str = "x-grpc-client-streaming";
/// `GrpcResponseStatusResolver.GRPC_DEADLINE_RESPONSE_MARKER`.
const DEADLINE_MARKER: &str = "x-mockserver-grpc-deadline-response";
const HEALTH_CHECK_PATH: &str = "/grpc.health.v1.Health/Check";
const REFLECTION_V1_PATH: &str = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo";
const REFLECTION_V1ALPHA_PATH: &str = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";
/// `MAX_MESSAGE_SIZE_CEILING`.
const MAX_MESSAGE_SIZE_CEILING: i64 = 256 * 1024 * 1024;

/// `GrpcStatusCode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

const NAMES: &[(&str, Code)] = &[
    ("OK", Code::Ok),
    ("CANCELLED", Code::Cancelled),
    ("UNKNOWN", Code::Unknown),
    ("INVALID_ARGUMENT", Code::InvalidArgument),
    ("DEADLINE_EXCEEDED", Code::DeadlineExceeded),
    ("NOT_FOUND", Code::NotFound),
    ("ALREADY_EXISTS", Code::AlreadyExists),
    ("PERMISSION_DENIED", Code::PermissionDenied),
    ("RESOURCE_EXHAUSTED", Code::ResourceExhausted),
    ("FAILED_PRECONDITION", Code::FailedPrecondition),
    ("ABORTED", Code::Aborted),
    ("OUT_OF_RANGE", Code::OutOfRange),
    ("UNIMPLEMENTED", Code::Unimplemented),
    ("INTERNAL", Code::Internal),
    ("UNAVAILABLE", Code::Unavailable),
    ("DATA_LOSS", Code::DataLoss),
    ("UNAUTHENTICATED", Code::Unauthenticated),
];

/// `fromName`: unknown names are `UNKNOWN`.
pub fn code_from_name(name: &str) -> Code {
    let upper = name.to_uppercase();
    NAMES.iter().find(|(n, _)| *n == upper).map_or(Code::Unknown, |(_, c)| *c)
}

/// `fromHttpTransportStatus`: a non-2xx HTTP response as the gRPC status a client would see.
fn from_http_transport_status(status: u32) -> Code {
    match status {
        400 => Code::Internal,
        401 => Code::Unauthenticated,
        403 => Code::PermissionDenied,
        404 => Code::Unimplemented,
        429 | 502 | 503 | 504 => Code::Unavailable,
        _ => Code::Unknown,
    }
}

/// `isGrpcContentType`: `application/grpc`, `application/grpc+proto`, … but not `application/grpc-web`.
pub fn is_grpc_content_type(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|c| c.starts_with(CONTENT_TYPE) && !c.starts_with("application/grpc-"))
}

/// `percentEncodeMessage`: printable ASCII except `%` as is, every other byte `%XX`.
pub fn percent_encode(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    for b in message.bytes() {
        if (0x20..=0x7e).contains(&b) && b != b'%' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `percentDecodeMessage`.
pub fn percent_decode(message: &str) -> String {
    if !message.contains('%') {
        return message.to_string();
    }
    let bytes = message.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() && let (Some(h), Some(l)) = ((bytes[i + 1] as char).to_digit(16), (bytes[i + 2] as char).to_digit(16)) {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Why a request could not be turned into JSON (`GrpcException`): its message and status.
pub struct GrpcError {
    pub message: String,
    pub code: Code,
}

pub fn max_message_size(state: &State) -> usize {
    state.config.int_property("maxGrpcMessageSize", 4 * 1024 * 1024).clamp(0, MAX_MESSAGE_SIZE_CEILING) as usize
}

/// `GrpcFrameCodec.decode`: each complete length-prefixed message, decompressed when flagged.
pub fn decode_frames(state: &State, data: &[u8], encoding: Option<&str>) -> Result<Vec<Vec<u8>>, GrpcError> {
    let max = max_message_size(state);
    let mut messages = Vec::new();
    let mut at = 0;
    while data.len() - at >= 5 {
        let flag = data[at];
        if flag & !1 != 0 {
            return Err(GrpcError { message: format!("gRPC frame has reserved flag bits set: {}", flag as i8), code: Code::Internal });
        }
        let length = u32::from_be_bytes(data[at + 1..at + 5].try_into().expect("4 bytes")) as i32;
        if length < 0 || length as usize > max {
            return Err(GrpcError { message: format!("gRPC message size {length} exceeds maximum allowed {max}"), code: Code::ResourceExhausted });
        }
        at += 5;
        if data.len() - at < length as usize {
            break;
        }
        let mut payload = data[at..at + length as usize].to_vec();
        at += length as usize;
        if flag == 1 {
            let supported = encoding.is_none_or(|e| e.trim().is_empty() || e.trim().eq_ignore_ascii_case("identity") || e.trim().eq_ignore_ascii_case("gzip"));
            if !supported {
                return Err(GrpcError {
                    message: format!("grpc-encoding \"{}\" is not supported, supported encodings are: {ACCEPT_ENCODING}", encoding.unwrap_or_default()),
                    code: Code::Unimplemented,
                });
            }
            let mut decoded = Vec::new();
            let mut reader = flate2::read::GzDecoder::new(payload.as_slice()).take(max as u64 + 1);
            reader.read_to_end(&mut decoded).map_err(|e| GrpcError { message: format!("Failed to gzip decompress gRPC message: {e}"), code: Code::Internal })?;
            if decoded.len() > max {
                return Err(GrpcError { message: format!("decompressed gRPC message size exceeds maximum allowed {max}"), code: Code::ResourceExhausted });
            }
            payload = decoded;
        }
        messages.push(payload);
    }
    Ok(messages)
}

/// `IncrementalGrpcFrameDecoder`: length-prefixed messages reassembled across the DATA frames of one stream, a partial
/// frame kept for the next `feed`. Unlike [`decode_frames`] it ignores `grpc-encoding` (a flagged message is always
/// gunzipped) and its errors carry upstream's texts and statuses; the bidi handler maps them (see [`bidi_session`]).
pub struct IncrementalDecoder {
    buffer: Vec<u8>,
    max: usize,
    cap: usize,
}

impl IncrementalDecoder {
    pub fn new(state: &State) -> Self {
        let max = max_message_size(state);
        // `defaultMaxBufferSize`: room for one maximum-size message and its prefix, never under 8 MiB.
        IncrementalDecoder { buffer: Vec::new(), max, cap: (8 * 1024 * 1024).max(max.saturating_mul(2)) }
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, GrpcError> {
        if chunk.is_empty() {
            return Ok(Vec::new());
        }
        if self.buffer.len() + chunk.len() > self.cap {
            return Err(GrpcError { message: format!("gRPC frame decoder buffer exceeded maximum of {} bytes", self.cap), code: Code::ResourceExhausted });
        }
        self.buffer.extend_from_slice(chunk);
        let mut messages = Vec::new();
        let mut offset = 0;
        while offset + 5 <= self.buffer.len() {
            let flag = self.buffer[offset];
            if flag & !1 != 0 {
                return Err(GrpcError { message: format!("gRPC frame has reserved flag bits set: {}", flag as i8), code: Code::Internal });
            }
            let length = i32::from_be_bytes(self.buffer[offset + 1..offset + 5].try_into().expect("4 bytes"));
            if length < 0 || length as usize > self.max {
                return Err(GrpcError { message: format!("gRPC message size {length} exceeds maximum allowed {}", self.max), code: Code::ResourceExhausted });
            }
            let end = offset + 5 + length as usize;
            if end > self.buffer.len() {
                break;
            }
            let mut payload = self.buffer[offset + 5..end].to_vec();
            if flag == 1 {
                let mut decoded = Vec::new();
                let mut reader = flate2::read::GzDecoder::new(payload.as_slice()).take(self.max as u64 + 1);
                reader.read_to_end(&mut decoded).map_err(|_| GrpcError { message: "Failed to gzip decompress gRPC message".into(), code: Code::Internal })?;
                if decoded.len() > self.max {
                    return Err(GrpcError { message: format!("decompressed gRPC message size exceeds maximum allowed {}", self.max), code: Code::ResourceExhausted });
                }
                payload = decoded;
            }
            messages.push(payload);
            offset = end;
        }
        self.buffer.drain(..offset);
        Ok(messages)
    }
}

/// `GrpcFrameCodec.encode`, uncompressed.
pub fn encode_frame(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 5);
    out.push(0);
    out.extend_from_slice(&(message.len() as u32).to_be_bytes());
    out.extend_from_slice(message);
    out
}

/// `parseGrpcPath`: `/package.Service/Method` as service and method.
fn parse_path(path: &str) -> (String, String) {
    let path = path.strip_prefix('/').unwrap_or(path);
    match path.rfind('/') {
        Some(i) if i >= 1 && i < path.len() - 1 => (path[..i].to_string(), path[i + 1..].to_string()),
        _ => (path.to_string(), String::new()),
    }
}

/// `GrpcTimeout.parseNanos`.
fn timeout_nanos(value: Option<&str>) -> Option<u64> {
    let trimmed = value?.trim();
    if trimmed.len() < 2 {
        return None;
    }
    let (digits, unit) = trimmed.split_at(trimmed.len() - 1);
    if digits.is_empty() || digits.len() > 8 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let amount: u64 = digits.parse().ok()?;
    Some(match unit {
        "H" => amount * 3_600_000_000_000,
        "M" => amount * 60_000_000_000,
        "S" => amount * 1_000_000_000,
        "m" => amount * 1_000_000,
        "u" => amount * 1_000,
        "n" => amount,
        _ => return None,
    })
}

/// A response `GrpcToHttpRequestHandler` writes itself (health, reflection, chaos, errors, deadlines): it never
/// passes the `ResponseWriter`, so it has no `Connection` header.
fn direct(mut reply: Reply) -> Reply {
    reply.suppress_connection_header = true;
    reply
}

/// A trailers-only or empty gRPC answer carrying `status` and `message`. HTTP/3 builds it with
/// `GrpcHttp3Adapter.buildTrailersOnlyFrame`, which has no `grpc-accept-encoding`.
fn status_reply(request: &HttpRequest, state: &State, code: Code, message: Option<&str>) -> Reply {
    let mut reply = Reply::status(200);
    reply.headers.push(("content-type".into(), CONTENT_TYPE.into()));
    if request.protocol != "HTTP_3" {
        reply.headers.push(("grpc-accept-encoding".into(), ACCEPT_ENCODING.into()));
    }
    reply.trailers.push(("grpc-status".into(), (code as i32).to_string()));
    if let Some(m) = message.filter(|m| !m.is_empty()) {
        reply.trailers.push(("grpc-message".into(), percent_encode(m)));
    }
    direct(trailers_only(reply, request.protocol)).finalize(request, &state.config)
}

/// `GrpcToHttpRequestHandler.refusedWithoutDataPlaneCredentials`: the gate's `401` (logged) resolved to its gRPC
/// status, `UNAUTHENTICATED` with `MockServer returned HTTP 401 Unauthorized`, and its `WWW-Authenticate` challenge.
fn unauthenticated_reply(state: &State, request: &HttpRequest, challenge: Option<String>) -> Reply {
    // the handler's request was mapped with the local port (`FullHttpRequestToMockServerHttpRequest`), so the logged
    // one has a socket address
    let port = request.local_address.rsplit(':').next().and_then(|p| p.parse().ok());
    let socket_address = port.and_then(|port| crate::http1::host_socket_address(request, port, request.secure));
    let mapped = HttpRequest { socket_address, ..request.clone() };
    let unauthorized = crate::dataplane::unauthorized_response(state, &mapped, challenge.clone());
    let (code, _, message, _) = resolve_status(&unauthorized);
    let mut reply = Reply::status(200);
    reply.headers.push(("content-type".into(), CONTENT_TYPE.into()));
    if let Some(challenge) = challenge {
        reply.headers.push(("www-authenticate".into(), challenge));
    }
    reply.headers.push(("grpc-accept-encoding".into(), ACCEPT_ENCODING.into()));
    reply.trailers.push(("grpc-status".into(), (code as i32).to_string()));
    if let Some(m) = message.filter(|m| !m.is_empty()) {
        reply.trailers.push(("grpc-message".into(), percent_encode(&m)));
    }
    direct(trailers_only(reply, request.protocol)).finalize(request, &state.config)
}

/// A request the descriptors cannot convert (an unknown method, a bad message): its gRPC error. Over HTTP/3
/// `writeGrpcErrorIfAuthenticated` runs the data-plane gate first, so a client without credentials gets the gate's
/// `401` as `UNAUTHENTICATED` instead, not an `UNIMPLEMENTED` that tells it which methods exist (upstream 456a9dee3);
/// HTTP/1.1 and HTTP/2 refused it before conversion.
fn http3_decode_error(state: &State, request: &HttpRequest, code: Code, message: &str) -> Reply {
    if request.protocol == "HTTP_3" && let Some(challenge) = crate::auth::data_plane_rejection(&state.config, request) {
        return passthrough_response(state, request, crate::dataplane::unauthorized_response(state, request, challenge));
    }
    status_reply(request, state, code, Some(message))
}

/// `asTrailersOnlyIfHttp2`: on HTTP/2, with no body and nothing but the status in the trailers, the status goes in
/// the headers; HTTP/3 sends a body-less response as one HEADERS frame with every trailer (`buildTrailersOnlyFrame`);
/// HTTP/1.1 keeps its trailers.
fn trailers_only(mut reply: Reply, protocol: &str) -> Reply {
    let only_status = reply.trailers.iter().all(|(n, _)| n.eq_ignore_ascii_case("grpc-status") || n.eq_ignore_ascii_case("grpc-message"));
    let applies = match protocol {
        "HTTP_2" => only_status,
        "HTTP_3" => true,
        _ => false,
    };
    if reply.body.is_empty() && applies && reply.trailers.iter().any(|(n, _)| n.eq_ignore_ascii_case("grpc-status")) {
        let trailers = std::mem::take(&mut reply.trailers);
        for (name, value) in trailers {
            if name.eq_ignore_ascii_case("grpc-message") && value.is_empty() {
                continue;
            }
            reply.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(&name));
            reply.headers.push((name, value));
        }
    }
    reply
}

tokio::task_local! {
    /// Whether this connection's pipeline has the gRPC handlers: `PortUnificationHandler` (HTTP/1.1) and
    /// `Http2MultiplexChildInitializer` (HTTP/2) add them when the connection is set up, only if a descriptor set is
    /// loaded then, so a connection opened before an upload serves plain HTTP. Once installed, the handler still
    /// translates gRPC-Web, answers health checks and applies gRPC chaos after the descriptors are cleared; only
    /// reflection and conversion need them. Unset (HTTP/3, in-process callers): installed while descriptors are.
    pub static PIPELINE: bool;
}

/// Whether the current connection has the gRPC handlers.
fn installed(state: &State) -> bool {
    PIPELINE.try_with(|p| *p).unwrap_or_else(|_| state.grpc.has_services())
}

/// Whether [`dispatch`] may take the request: any over HTTP/3, or any on a connection whose pipeline has the gRPC
/// handlers; the others are plain HTTP requests.
pub fn converts(state: &State, request: &HttpRequest) -> bool {
    request.protocol == "HTTP_3" || installed(state)
}

/// Serves a gRPC request: `Err` hands the request back (boxed: it is large) when it is not one this server converts
/// (no descriptors, not gRPC).
pub async fn dispatch(state: &Arc<State>, mut request: HttpRequest, channel: &TraceChannel) -> Result<Outcome, Box<HttpRequest>> {
    // `Http3MockServerHandler.handleGrpcRequest`: HTTP/3 has none of `GrpcToHttpRequestHandler`'s pipeline (no
    // gRPC-Web translation, health, reflection or chaos); a gRPC content type is enough, with or without descriptors.
    if request.protocol == "HTTP_3" {
        request.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(DEADLINE_MARKER));
        return Box::pin(dispatch_grpc(state, request, channel, None)).await.map(|outcome| match outcome {
            // `GrpcHttp3Adapter` writes the header fields: `content-type`, `server`, then the response's own
            Outcome::Respond(mut reply) => {
                reply.grpc_http3 = true;
                Outcome::Respond(reply)
            }
            Outcome::Stream { mut head, chunks, close, trailers, cut, chunk_count, upstream_end } => {
                head.grpc_http3 = true;
                Outcome::Stream { head, chunks, close, trailers, cut, chunk_count, upstream_end }
            }
            other => other,
        });
    }
    // `GrpcToHttpRequestHandler` is in a connection's pipeline only if a descriptor set was loaded when it was set up
    // (`PortUnificationHandler`, `Http2MultiplexChildInitializer`; [`PIPELINE`]): otherwise health checks and gRPC-Web
    // are plain HTTP requests.
    if !installed(state) {
        return Err(Box::new(request));
    }
    // `channelRead0`: MockServer's internal deadline marker is stripped from anything inbound, gRPC or not; only the
    // deadline task may set it.
    request.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(DEADLINE_MARKER));
    // `translateGrpcWebRequest`: gRPC-Web is served as gRPC, and its response translated back.
    let web = request.first_header("content-type").filter(|c| c.starts_with("application/grpc-web")).map(str::to_string);
    let Some(web) = web else {
        // `recordGrpcServiceMethod`: the pending record keeps the request's own `x-grpc-web-content-type`, so a
        // matched response (or the deadline's) is re-framed as gRPC-Web even when the client sent that header on
        // plain gRPC, e.g. a gRPC-Web call forwarded to another MockServer.
        let marker = request.first_header("x-grpc-web-content-type").filter(|m| !m.trim().is_empty()).map(str::to_string);
        return Box::pin(dispatch_grpc(state, request, channel, marker.as_deref())).await;
    };
    let mut translated = request;
    if web.starts_with("application/grpc-web-text") && !translated.body.is_empty() {
        // `Base64.getDecoder().decode`: padding optional, nothing else outside the alphabet (whitespace, `-_`, data
        // after the padding). Its IllegalArgumentException escapes the handler, and Netty closes the channel: the
        // stream on HTTP/2, the connection on HTTP/1.1 (grpc_web_text_base64).
        let Some(decoded) = std::str::from_utf8(&translated.body).ok().and_then(crate::import::base64_decode) else {
            return Ok(Outcome::Reset(0x8));
        };
        translated.body = Bytes::from(decoded);
    }
    // `withBody(new BinaryBody(decodedBody))`: no content type of its own.
    translated.body_kind = crate::request::BodyKind::Binary;
    translated.headers.retain(|(n, _)| !n.eq_ignore_ascii_case("content-type"));
    translated.headers.push(("content-type".into(), vec![CONTENT_TYPE.into()]));
    translated.headers.push(("x-grpc-web-content-type".into(), vec![web.clone()]));
    let request = translated.clone();
    Ok(match Box::pin(dispatch_grpc(state, translated, channel, None)).await {
        Ok(Outcome::Respond(reply)) => Outcome::Respond(grpc_web_response(state, &request, reply, &web)),
        Ok(other) => other,
        Err(_) => return Err(Box::new(request)),
    })
}

/// `convertToGrpcWebResponse`: the message frames, then the status and remaining trailers as a trailer frame
/// (flag `0x80`), base64 for the text variant; no HTTP trailers.
fn grpc_web_response(state: &State, request: &HttpRequest, mut reply: Reply, web: &str) -> Reply {
    let find = |reply: &Reply, name: &str| {
        reply.trailers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()).or_else(|| reply.header(name).map(str::to_string))
    };
    let status = find(&reply, "grpc-status").filter(|s| !s.is_empty());
    let message = find(&reply, "grpc-message").map(|m| percent_decode(&m));
    let mut trailer = format!("grpc-status: {}\r\n", status.as_deref().unwrap_or("0").replace(['\r', '\n'], ""));
    if let Some(m) = message.filter(|m| !m.is_empty()) {
        trailer.push_str(&format!("grpc-message: {}\r\n", percent_encode(&m)));
    }
    for (name, value) in &reply.trailers {
        if name.eq_ignore_ascii_case("grpc-status") || name.eq_ignore_ascii_case("grpc-message") || name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
            continue;
        }
        trailer.push_str(&format!("{name}: {value}\r\n"));
    }
    let mut body = reply.body.to_vec();
    body.push(0x80);
    body.extend_from_slice(&(trailer.len() as u32).to_be_bytes());
    body.extend_from_slice(trailer.as_bytes());
    let text = web.starts_with("application/grpc-web-text");
    if text {
        body = base64::engine::general_purpose::STANDARD.encode(&body).into_bytes();
    }
    let proto = web.contains("+proto");
    let content_type = match (text, proto) {
        (true, true) => "application/grpc-web-text+proto",
        (true, false) => "application/grpc-web-text",
        (false, true) => "application/grpc-web+proto",
        (false, false) => "application/grpc-web",
    };
    const REMOVED: &[&str] = &["content-type", "grpc-status", "grpc-message", "x-grpc-web-content-type", "trailer", "transfer-encoding", "content-length", "connection"];
    reply.headers.retain(|(n, _)| !REMOVED.iter().any(|r| n.eq_ignore_ascii_case(r)));
    reply.headers.push(("content-type".into(), content_type.into())); // `replaceHeader` appends
    reply.trailers.clear();
    reply.chunked_for_trailers = false;
    reply.body = Bytes::from(body);
    reply.finalize(request, &state.config)
}

/// `pending_web`: the gRPC-Web content type the pending record carries for a request that was not translated here
/// (the caller re-frames every answer to a translated one).
async fn dispatch_grpc(state: &Arc<State>, request: HttpRequest, channel: &TraceChannel, pending_web: Option<&str>) -> Result<Outcome, Box<HttpRequest>> {
    if !is_grpc_content_type(request.first_header("content-type")) {
        return Err(Box::new(request));
    }
    // HTTP/3 serves neither health nor reflection: with descriptors they are unknown methods.
    let http3 = request.protocol == "HTTP_3";
    if request.path == HEALTH_CHECK_PATH && !http3 {
        return Ok(Outcome::Respond(health_check(state, &request)));
    }
    // `refusedWithoutDataPlaneCredentials`: health stays open; reflection, chaos and the decode errors answer from
    // the loaded schemas or mock state ahead of the data-plane gate, so a request without credentials is refused
    // here (upstream 456a9dee3). HTTP/3 gates its decode errors itself ([`http3_decode_error`]).
    if !http3 && let Some(challenge) = crate::auth::data_plane_unauthenticated(&state.config, &request) {
        return Ok(Outcome::Respond(unauthenticated_reply(state, &request, challenge)));
    }
    if (request.path == REFLECTION_V1_PATH || request.path == REFLECTION_V1ALPHA_PATH) && state.grpc.has_services() && !http3 {
        let mut reply = Reply::status(200);
        reply.headers.push(("content-type".into(), CONTENT_TYPE.into()));
        reply.headers.push(("grpc-accept-encoding".into(), ACCEPT_ENCODING.into()));
        reply.body = Bytes::from(encode_frame(&reflect(state, &request.body)));
        reply.trailers.push(("grpc-status".into(), "0".into()));
        return Ok(Outcome::Respond(direct(reply).finalize(&request, &state.config)));
    }
    let (service, method_name) = parse_path(&request.path);
    // gRPC chaos: a fault answered before the call is matched. `Http3MockServerHandler` has no such branch.
    if !http3 {
        let encoding = request.first_header("grpc-encoding").map(str::to_string);
        let messages = || if request.body.is_empty() { 0 } else { decode_frames(state, &request.body, encoding.as_deref()).map_or(0, |m| m.len()) };
        if let Some(fault) = crate::chaos::grpc::fault(state, &service, messages) {
            let mut reply = fault.reply;
            reply.headers.push(("grpc-accept-encoding".into(), ACCEPT_ENCODING.into()));
            if fault.latency_ms > 0 {
                tokio::time::sleep(Duration::from_millis(fault.latency_ms)).await;
            }
            // A null-valued custom trailer still counts as a remaining trailer: no Trailers-Only collapse.
            let reply = match fault.announced {
                Some(names) => {
                    reply.headers.push(("trailer".into(), names));
                    reply
                }
                None => trailers_only(reply, request.protocol),
            };
            return Ok(Outcome::Respond(direct(reply).finalize(&request, &state.config)));
        }
    }
    // Without descriptors the (translated) request goes on as plain HTTP. HTTP/3 still writes the answer as gRPC
    // (`Http3GrpcResponseWriter.writePassthroughGrpcResponse`).
    if !state.grpc.has_services() {
        if !http3 {
            return Err(Box::new(request));
        }
        let original = request.clone();
        let outcome = match timeout_nanos(request.first_header("grpc-timeout")) {
            Some(nanos) => match http3_deadline(state, request, nanos, channel).await {
                Some(outcome) => outcome,
                None => return Ok(Outcome::Respond(status_reply(&original, state, Code::DeadlineExceeded, Some(&format!("deadline exceeded after {}ms", nanos / 1_000_000))))),
            },
            None => Box::pin(crate::handler::dispatch_http(state, request, channel)).await,
        };
        return Ok(match outcome {
            Outcome::Respond(reply) => Outcome::Respond(passthrough_response(state, &original, reply)),
            other => other,
        });
    }
    let Some(method) = state.grpc.method(&service, &method_name) else {
        let message = format!("unknown gRPC method: {service}/{method_name}");
        request_error(state, &request, &message);
        return Ok(Outcome::Respond(http3_decode_error(state, &request, Code::Unimplemented, &message)));
    };
    let pool = state.grpc.pool();
    let converted = match convert_request(state, &request, &pool, &service, &method_name, &method.input_type) {
        Ok(converted) => converted,
        Err(e) => {
            request_error(state, &request, &e.message);
            return Ok(Outcome::Respond(http3_decode_error(state, &request, e.code, &e.message)));
        }
    };
    let deadline = timeout_nanos(request.first_header("grpc-timeout"));
    if http3 {
        // `Http3GrpcResponseWriter.scheduleDeadline`: since upstream 67ebbd0cd the action runs off the stream's event
        // loop, so a delay longer than `grpc-timeout` loses to the deadline (8.0.0 and 9.1.0 never enforced it).
        let outcome = match deadline {
            Some(nanos) => match http3_deadline(state, converted, nanos, channel).await {
                Some(outcome) => outcome,
                None => return Ok(Outcome::Respond(status_reply(&request, state, Code::DeadlineExceeded, Some(&format!("deadline exceeded after {}ms", nanos / 1_000_000))))),
            },
            None => Box::pin(crate::handler::dispatch_http(state, converted, channel)).await,
        };
        return Ok(match outcome {
            Outcome::Respond(reply) => Outcome::Respond(convert_response(state, &request, reply, &pool, &method.output_type)),
            other => other,
        });
    }
    let served = Box::pin(crate::handler::dispatch_http(state, converted, channel));
    let outcome = match deadline {
        // The deadline is polled first: `tokio::time::timeout` polls the response first, so a task polled late (a
        // loaded host) returned a delayed response that came due after the deadline. Netty runs the
        // deadline task at its instant, before the later response.
        Some(nanos) => match tokio::select! {
            biased;
            _ = tokio::time::sleep(Duration::from_nanos(nanos)) => None,
            outcome = served => Some(outcome),
        } {
            Some(outcome) => outcome,
            None => {
                let message = format!("deadline exceeded after {}ms", nanos / 1_000_000);
                let reply = status_reply(&request, state, Code::DeadlineExceeded, Some(&message));
                return Ok(Outcome::Respond(match pending_web {
                    Some(web) => grpc_web_response(state, &request, reply, web),
                    None => reply,
                }));
            }
        },
        None => served.await,
    };
    Ok(match outcome {
        Outcome::Respond(reply) => {
            let reply = convert_response(state, &request, reply, &pool, &method.output_type);
            Outcome::Respond(match pending_web {
                Some(web) => grpc_web_response(state, &request, reply, web),
                None => reply,
            })
        }
        other => other,
    })
}

/// `Http3GrpcResponseWriter.scheduleDeadline` around a unary call over HTTP/3: the request is served on a task of its
/// own while the deadline runs. `None`: the deadline came first, logged at INFO, and the caller answers
/// `DEADLINE_EXCEEDED` trailers-only; the action goes on, logging what it returns, and its response is then dropped
/// with an INFO entry (`sendResponse` finding the stream `completed`).
async fn http3_deadline(state: &Arc<State>, request: HttpRequest, nanos: u64, channel: &TraceChannel) -> Option<Outcome> {
    let shown = request.clone();
    let (owned, trace) = (state.clone(), TraceChannel::new(channel.lock().clone()));
    let served: std::pin::Pin<Box<dyn std::future::Future<Output = Outcome> + Send>> = Box::pin(async move { crate::handler::dispatch_http(&owned, request, &trace).await });
    let mut served = tokio::spawn(served);
    tokio::select! {
        biased;
        _ = tokio::time::sleep(Duration::from_nanos(nanos)) => {
            crate::log::info_event(state, LogEntry::at(Level::Info, "gRPC deadline elapsed over HTTP/3 for {} - returning DEADLINE_EXCEEDED").request(&shown).args([shown.path.as_str()]));
            let state = state.clone();
            tokio::spawn(async move {
                if served.await.is_ok() {
                    let format = "dropping gRPC response over HTTP/3 for a stream that already ended with DEADLINE_EXCEEDED - the delay outlasted the client's grpc-timeout";
                    crate::log::info_event(&state, LogEntry::at(Level::Info, format).request(&shown));
                }
            });
            None
        }
        outcome = &mut served => Some(outcome.unwrap_or(Outcome::DropConnection)),
    }
}

/// `convertGrpcRequest`: the body as JSON, the method in derived headers.
fn convert_request(state: &State, request: &HttpRequest, pool: &crate::protobuf::Pool, service: &str, method: &str, input_type: &str) -> Result<HttpRequest, GrpcError> {
    let mut converted = request.clone();
    let derived = [SERVICE, METHOD, ORIGINAL_CONTENT_TYPE, CLIENT_STREAMING];
    converted.headers.retain(|(n, _)| !derived.iter().any(|d| n.eq_ignore_ascii_case(d)));
    let original = request.first_header("content-type").unwrap_or_default().to_string();
    let mut client_streaming = false;
    if !request.body.is_empty() {
        let messages = decode_frames(state, &request.body, request.first_header("grpc-encoding"))?;
        if messages.is_empty() {
            return Err(GrpcError { message: "failed to decode gRPC frame from request body".into(), code: Code::Internal });
        }
        let json: Result<Vec<String>, String> = messages.iter().map(|m| pool.to_json(input_type, m)).collect();
        // `GrpcJsonMessageConverter.toJson`: a parse or print failure is an InvalidProtocolBufferException, rethrown as
        // a GrpcException (INTERNAL) whose message is the trailer (B4-grpcframe-GrpcFrameCodecTest).
        let json = json.map_err(|_| GrpcError { message: "Failed to convert protobuf to JSON".into(), code: Code::Internal })?;
        let body = if json.len() == 1 { json[0].clone() } else { format!("[{}]", json.join(",")) };
        converted.body = Bytes::from(body.into_bytes());
        converted.original_body = None;
        converted.body_kind = crate::request::BodyKind::PlainString;
        client_streaming = json.len() > 1;
        // `request.clone()` keeps the framed body's `content-length`.
    }
    // In `convertGrpcRequest`'s order: the client-streaming flag comes last.
    converted.headers.push((SERVICE.into(), vec![service.to_string()]));
    converted.headers.push((METHOD.into(), vec![method.to_string()]));
    converted.headers.push((ORIGINAL_CONTENT_TYPE.into(), vec![original]));
    if client_streaming {
        converted.headers.push((CLIENT_STREAMING.into(), vec!["true".into()]));
    }
    Ok(converted)
}

/// `GrpcResponseStatusResolver.resolve`: the status the response asks for, or the one a non-2xx HTTP status maps to.
fn resolve_status(reply: &Reply) -> (Code, i64, Option<String>, bool) {
    let header_or_trailer = |name: &str| reply.header(name).filter(|v| !v.is_empty()).map(str::to_string).or_else(|| reply.trailers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()));
    let message = header_or_trailer("grpc-message");
    if let Some(name) = reply.header("grpc-status-name").filter(|n| !n.is_empty()) {
        let code = code_from_name(name);
        return (code, code as i64, message, false);
    }
    if let Some(value) = header_or_trailer("grpc-status").and_then(|v| v.trim().parse::<i64>().ok()) {
        let code = NAMES.iter().map(|(_, c)| *c).find(|c| *c as i64 == value).unwrap_or(Code::Unknown);
        return (code, value, message, false);
    }
    if !(200..=299).contains(&reply.status) {
        let reason = reply.reason.clone().filter(|r| !r.is_empty());
        let detail = format!("MockServer returned HTTP {}{}", reply.status, reason.map(|r| format!(" {r}")).unwrap_or_default());
        let code = from_http_transport_status(reply.status);
        return (code, code as i64, Some(detail), true);
    }
    (Code::Ok, 0, message, false)
}

/// `Http3GrpcResponseWriter.writePassthroughGrpcResponse`: the body as it is, the status `GrpcResponseStatusResolver`
/// resolves in the trailers; a transport failure (an unmatched request's 404) has no body, so it is trailers-only.
fn passthrough_response(state: &State, request: &HttpRequest, reply: Reply) -> Reply {
    let (_, status, message, transport_failure) = resolve_status(&reply);
    let mut out = reply;
    out.headers.retain(|(n, _)| !n.eq_ignore_ascii_case("connection") && !n.eq_ignore_ascii_case("transfer-encoding") && !n.eq_ignore_ascii_case("trailer"));
    out.chunked_for_trailers = false;
    strip_metadata(&mut out, request.protocol);
    out.status = 200;
    if transport_failure {
        out.body = Bytes::new();
    }
    set_status_trailers(&mut out, status, message.as_deref());
    trailers_only(out, request.protocol).finalize(request, &state.config)
}

/// `stripGrpcMetadata`: the gRPC content type and accepted encodings; the status headers and derived ones removed.
/// HTTP/3 frames carry no `grpc-accept-encoding` (`GrpcHttp3Adapter.buildInitialHeadersFrame`).
fn strip_metadata(reply: &mut Reply, protocol: &str) {
    const REMOVED: &[&str] = &["content-type", "grpc-accept-encoding", "grpc-status", "grpc-message", "grpc-status-name", SERVICE, METHOD, "content-length"];
    reply.headers.retain(|(n, _)| !REMOVED.iter().any(|r| n.eq_ignore_ascii_case(r)));
    // `replaceHeader` appends.
    reply.headers.push(("content-type".into(), CONTENT_TYPE.into()));
    if protocol != "HTTP_3" {
        reply.headers.push(("grpc-accept-encoding".into(), ACCEPT_ENCODING.into()));
    }
    reply.default_content_type = None;
    // the gRPC content type is a header of the model now, written on HTTP/3 too (the gate's `text/plain` was the body's)
    reply.content_type_from_body = false;
    reply.reason = None;
    reply.suppress_content_length = false;
    reply.content_length_override = None;
}

fn set_status_trailers(reply: &mut Reply, status: i64, message: Option<&str>) {
    reply.trailers.retain(|(n, _)| !n.eq_ignore_ascii_case("grpc-status") && !n.eq_ignore_ascii_case("grpc-message"));
    reply.trailers.push(("grpc-status".into(), status.to_string()));
    if let Some(m) = message.filter(|m| !m.is_empty()) {
        reply.trailers.push(("grpc-message".into(), percent_encode(m)));
    }
}

/// `GrpcToHttpRequestHandler`'s WARN for a request it could not convert (`Http3MockServerHandler.handleGrpcRequest`'s
/// over HTTP/3).
fn request_error(state: &State, request: &HttpRequest, message: &str) {
    let format = if request.protocol == "HTTP_3" { "gRPC request error over HTTP/3:{}:{}" } else { "gRPC request error:{}:{}" };
    let entry = LogEntry::at(Level::Warn, format).args([request.path.as_str(), message]);
    // `Http3MockServerHandler` sets the request on its entry, `GrpcToHttpRequestHandler` does not
    let entry = if request.protocol == "HTTP_3" { entry.request(request) } else { entry };
    // on the connection's event loop, whose thread carries `HttpState`'s port only once a request has reached it
    let entry = match crate::server::current_worker() {
        Some(event_loop) if !state.connections.has_requested_http(event_loop) => entry.without_port(),
        _ => entry,
    };
    crate::log::warn_event(state, entry);
}

/// A `GrpcStreamResponseActionHandler` entry about the stream's request (HTTP/3 streams log their own, or none).
fn stream_event(state: &State, request: &HttpRequest, level: Level, format: &str, arguments: Vec<crate::recorded::Arg>) {
    if request.protocol == "HTTP_3" {
        return;
    }
    let entry = LogEntry::at(level, format).request(request).args(arguments);
    match level {
        Level::Warn => crate::log::warn_event(state, entry),
        Level::Debug if crate::log::debug_enabled(state) => state.log.message(entry.kind(crate::recorded::Kind::ExpectationResponse)),
        Level::Debug => {}
        _ => crate::log::info_event(state, entry),
    }
}

/// `convertToGrpcResponse`.
fn convert_response(state: &State, request: &HttpRequest, reply: Reply, pool: &crate::protobuf::Pool, output_type: &str) -> Reply {
    let (code, status, message, transport_failure) = resolve_status(&reply);
    let mut converted = reply;
    // Undo the HTTP/1.1 decoration: the gRPC response is finalized again below.
    converted.headers.retain(|(n, _)| !n.eq_ignore_ascii_case("connection") && !n.eq_ignore_ascii_case("transfer-encoding") && !n.eq_ignore_ascii_case("trailer"));
    converted.chunked_for_trailers = false;
    if transport_failure {
        strip_metadata(&mut converted, request.protocol);
        converted.status = 200;
        converted.body = Bytes::new();
        set_status_trailers(&mut converted, status, message.as_deref());
        return trailers_only(converted, request.protocol).finalize(request, &state.config);
    }
    let mut body = String::from_utf8_lossy(&converted.body).into_owned();
    if body.is_empty() && code == Code::Ok {
        body = synthesize(pool, output_type).unwrap_or_default();
    }
    let original_headers = converted.headers.clone();
    strip_metadata(&mut converted, request.protocol);
    converted.status = 200;
    if body.is_empty() {
        converted.body = Bytes::new();
        set_status_trailers(&mut converted, status, message.as_deref());
        return trailers_only(converted, request.protocol).finalize(request, &state.config);
    }
    match pool.from_json(output_type, &body) {
        Ok(bytes) => {
            converted.body = Bytes::from(encode_frame(&bytes));
            set_status_trailers(&mut converted, status, message.as_deref());
            converted.finalize(request, &state.config)
        }
        Err(e) => {
            // `GrpcJsonMessageConverter.toProtobuf`'s `GrpcException` message (the parser's error is its cause).
            let _ = e;
            let (service, method) = parse_path(&request.path);
            let entry = LogEntry::at(Level::Warn, "failed to convert response to gRPC for {}/{}:{}").args([service, method, "Failed to convert JSON to protobuf".into()]);
            crate::log::warn_event(state, entry);
            // The error response is the original one with its content type replaced and the status headers
            // removed: no `grpc-accept-encoding` is added.
            const REMOVED: &[&str] = &["content-type", "grpc-status", "grpc-message", "grpc-status-name", SERVICE, METHOD, "x-grpc-web-content-type", "content-length"];
            converted.headers = original_headers;
            converted.headers.retain(|(n, _)| !REMOVED.iter().any(|r| n.eq_ignore_ascii_case(r)));
            converted.headers.push(("content-type".into(), CONTENT_TYPE.into()));
            converted.body = Bytes::new();
            set_status_trailers(&mut converted, Code::Internal as i64, Some("failed to encode gRPC response"));
            converted.finalize(request, &state.config)
        }
    }
}

/// `GrpcExampleSynthesizer.synthesizeJson`: every field given a placeholder (`"string"`, `true`, the first enum
/// value, …), printed as JSON.
fn synthesize(pool: &crate::protobuf::Pool, type_name: &str) -> Option<String> {
    let value = example(pool, type_name, &mut Vec::new(), 0)?;
    let bytes = pool.from_json(type_name, &value.to_string()).ok()?;
    pool.to_json(type_name, &bytes).ok()
}

fn example(pool: &crate::protobuf::Pool, type_name: &str, path: &mut Vec<String>, depth: usize) -> Option<serde_json::Value> {
    use serde_json::{Value, json};
    match type_name {
        "google.protobuf.Timestamp" => return Some(json!("2020-01-01T00:00:00Z")),
        "google.protobuf.Duration" => return Some(json!("0s")),
        "google.protobuf.StringValue" => return Some(json!("string")),
        "google.protobuf.BoolValue" => return Some(json!(true)),
        "google.protobuf.Int32Value" | "google.protobuf.UInt32Value" => return Some(json!(0)),
        "google.protobuf.Int64Value" | "google.protobuf.UInt64Value" => return Some(json!("0")),
        "google.protobuf.DoubleValue" | "google.protobuf.FloatValue" => return Some(json!(0.0)),
        "google.protobuf.BytesValue" => return Some(json!("")),
        _ => {}
    }
    let desc = pool.messages.get(type_name)?;
    let mut out = serde_json::Map::new();
    if depth > 25 || path.iter().any(|p| p == type_name) {
        return Some(Value::Object(out));
    }
    path.push(type_name.to_string());
    for field in &desc.fields {
        let entry = pool.messages.get(&field.type_name).filter(|m| m.map_entry);
        let value = match entry {
            Some(entry) => {
                let key = entry.fields.iter().find(|f| f.number == 1).and_then(|k| scalar_example(pool, k, path, depth));
                let value = entry.fields.iter().find(|f| f.number == 2).and_then(|v| scalar_example(pool, v, path, depth));
                let key = key.map(|k| k.as_str().map_or_else(|| k.to_string(), str::to_string)).unwrap_or_default();
                Some(json!({ key: value.unwrap_or(Value::Null) }))
            }
            None => scalar_example(pool, field, path, depth).map(|v| if field.repeated { Value::Array(vec![v]) } else { v }),
        };
        if let Some(v) = value {
            out.insert(field.json_name.clone(), v);
        }
    }
    path.pop();
    Some(Value::Object(out))
}

fn scalar_example(pool: &crate::protobuf::Pool, field: &crate::protobuf::FieldDesc, path: &mut Vec<String>, depth: usize) -> Option<serde_json::Value> {
    use serde_json::json;
    Some(match field.kind {
        1 | 2 => json!(0.0),
        3 | 4 | 6 | 16 | 18 => json!("0"),
        5 | 7 | 13 | 15 | 17 => json!(0),
        8 => json!(true),
        9 => json!("string"),
        12 => json!(""),
        14 => json!(pool.enums.get(&field.type_name).and_then(|e| e.values.first()).map(|(n, _)| n.clone())?),
        11 => example(pool, &field.type_name, path, depth + 1)?,
        _ => return None,
    })
}

/// `GrpcStreamResponseActionHandler`: the headers at once, each message (rendered when it has a `templateType`, except
/// over HTTP/3) after its delay, then the status trailers; a `grpc-timeout` that elapses first ends the stream with
/// `DEADLINE_EXCEEDED` (`GrpcStreamDeadline`).
pub fn stream(state: &Arc<State>, request: &HttpRequest, response: &serde_json::Value) -> Outcome {
    use serde_json::Value;
    // Written as it is, like the other streamed heads: HTTP/2 drops the `transfer-encoding`.
    let mut head = Reply::status(200);
    head.headers.push(("content-type".into(), CONTENT_TYPE.into()));
    head.headers.push(("transfer-encoding".into(), "chunked".into()));
    for (name, values) in response.get("headers").map(crate::model::multi_values).unwrap_or_default() {
        let Some(name) = name.value else { continue };
        for value in values.into_iter().flatten().filter_map(|v| v.value) {
            head.headers.push((name.clone(), value));
        }
    }
    let method = request.first_header(SERVICE).zip(request.first_header(METHOD)).and_then(|(s, m)| state.grpc.method(s, m));
    let pool = state.grpc.pool();
    let deadline = timeout_nanos(request.first_header("grpc-timeout")).map(|n| (tokio::time::Instant::now() + Duration::from_nanos(n), n));
    let messages: Vec<Value> = response.get("messages").and_then(Value::as_array).cloned().unwrap_or_default();
    let status = response.get("statusName").and_then(Value::as_str).filter(|s| !s.is_empty()).map_or(Code::Ok, code_from_name);
    let status_message = response.get("statusMessage").and_then(Value::as_str).filter(|m| !m.is_empty()).map(str::to_string);
    let close = response.get("closeConnection").and_then(Value::as_bool).unwrap_or(false);
    let (tx, chunks) = tokio::sync::mpsc::channel::<Bytes>(16);
    let (trailers_tx, trailers) = tokio::sync::oneshot::channel();
    // A RESPONSE_STREAM breakpoint holds each message (`GrpcStreamResponseActionHandler`, `Http3GrpcResponseWriter`).
    let suffix = if request.protocol == "HTTP_3" { "-h3-grpc-stream" } else { "-grpc-stream" };
    let id = format!("{}{suffix}", crate::breakpoint::correlation(request));
    let held = crate::breakpoint::stream(state, request, crate::breakpoint::StreamPhase::Response, id, &request.method, &request.path);
    let (state, request) = (state.clone(), request.clone());
    tokio::spawn(async move {
        let expired = |(_, nanos): (tokio::time::Instant, u64)| vec![
            ("grpc-status".to_string(), (Code::DeadlineExceeded as i32).to_string()),
            ("grpc-message".to_string(), percent_encode(&format!("deadline exceeded after {}ms", nanos / 1_000_000))),
        ];
        let shown = || crate::recorded::Arg::from(crate::recorded::logged(&request));
        let deadline_elapsed = || match request.protocol {
            // `Http3GrpcResponseWriter.scheduleDeadline`'s task.
            "HTTP_3" => crate::log::info_event(&state, LogEntry::at(Level::Info, "gRPC deadline elapsed over HTTP/3 for {} - returning DEADLINE_EXCEEDED").request(&request).args([request.path.as_str()])),
            _ => stream_event(&state, &request, Level::Info, "gRPC deadline elapsed mid-stream for request:{} - terminating with DEADLINE_EXCEEDED", vec![shown()]),
        };
        let total = messages.len();
        for (index, message) in messages.iter().enumerate() {
            let delay = message.get("delay").filter(|d| !d.is_null()).and_then(crate::action::delay).map(|d| d.fixed).unwrap_or_default();
            // `scheduler.schedule(writeMessage, false, delay)` unless the deadline has already fired; the task stays
            // counted until its delay elapses even when the deadline ends the stream first. HTTP/3 schedules it on
            // the channel's executor (`Http3GrpcResponseWriter`), uncounted.
            if request.protocol != "HTTP_3" && deadline.is_none_or(|d| tokio::time::Instant::now() < d.0) {
                state.overload.unbounded_delay(delay);
            }
            if let Some(d) = deadline && tokio::time::Instant::now() + delay >= d.0 {
                tokio::time::sleep_until(d.0).await;
                deadline_elapsed();
                let _ = trailers_tx.send(expired(d));
                return;
            }
            tokio::time::sleep(delay).await;
            let json = message.get("json").and_then(Value::as_str).unwrap_or_default();
            // `encodeMessage`: `StreamTemplateRenderer` renders against the whole request, then
            // `GrpcStreamMessageEncoder.encode`; either failing ends the stream (`finishStream`). HTTP/3's
            // `Http3GrpcResponseWriter.scheduleStreamMessages` encodes the message's `json` as it is, unrendered.
            let template = message.get("templateType").and_then(Value::as_str).filter(|_| request.protocol != "HTTP_3");
            let encoded = match template {
                Some(t) => {
                    let engine = match t {
                        "MUSTACHE" => crate::templates::Engine::Mustache,
                        "JAVASCRIPT" => crate::templates::Engine::JavaScript,
                        _ => crate::templates::Engine::Velocity,
                    };
                    crate::templates::render_text(&state, &state.velocity_engines.grpc_stream, engine, json, &request)
                }
                None => Ok(json.to_string()),
            }
            .and_then(|json| match &method {
                _ if json.is_empty() => Ok(Vec::new()),
                Some(m) => pool.from_json(&m.output_type, &json),
                None => Ok(json.into_bytes()),
            });
            let bytes = match encoded {
                Ok(bytes) => bytes,
                Err(e) => {
                    // The exception is the entry's throwable upstream: the console shows it, the entry's message not.
                    let format = match request.protocol {
                        "HTTP_3" => "exception sending gRPC stream message {} over HTTP/3 for request:{}",
                        _ => "exception sending gRPC stream message {} for request:{}",
                    };
                    let entry = LogEntry::at(Level::Warn, format).request(&request).args([serde_json::json!(index + 1).into(), shown()]);
                    crate::log::entry_with_throwable(&state, Level::Warn, &entry, None, &e.to_string());
                    if !matches!(state.log_level.as_str(), "OFF" | "ERROR") {
                        state.log.message(entry);
                    }
                    // `finishStream`: the stream ends with its own status trailers.
                    break;
                }
            };
            let frame = Bytes::from(encode_frame(&bytes));
            if held.is_some() && tx.is_closed() {
                return;
            }
            // A held message's (or injected) bytes go out as they are, each as a DATA frame of its own; the deadline
            // runs on while the message is held.
            let pass = crate::breakpoint::pass_bytes(held.as_ref(), frame);
            let passed = match deadline {
                Some(d) => match tokio::time::timeout_at(d.0, pass).await {
                    Ok(passed) => passed,
                    Err(_) => {
                        deadline_elapsed();
                        let _ = trailers_tx.send(expired(d));
                        return;
                    }
                },
                None => pass.await,
            };
            // CLOSE: the stream ends there, with its status trailers.
            let Some(out) = passed else { break };
            for chunk in out {
                if tx.send(chunk).await.is_err() {
                    return;
                }
            }
            stream_event(&state, &request, Level::Debug, "sent gRPC stream message {} of {} for request:{}", vec![serde_json::json!(index + 1).into(), serde_json::json!(total).into(), shown()]);
        }
        let mut trailers = vec![("grpc-status".to_string(), (status as i32).to_string())];
        if let Some(m) = status_message {
            trailers.push(("grpc-message".into(), percent_encode(&m)));
        }
        let _ = trailers_tx.send(trailers);
    });
    Outcome::Stream { head, chunks, close, trailers: Some(trailers), cut: None, chunk_count: None, upstream_end: None }
}

// ---------------------------------------------------------------- health

/// `ServingStatus`.
pub const SERVING_STATUSES: &[&str] = &["UNKNOWN", "SERVING", "NOT_SERVING", "SERVICE_UNKNOWN"];

/// `GrpcHealthRegistry`: per-service serving status and the default (`""`), one per process.
struct Health {
    services: Vec<(String, usize)>,
    default: usize,
}

static HEALTH: std::sync::LazyLock<parking_lot::Mutex<Health>> = std::sync::LazyLock::new(|| parking_lot::Mutex::new(Health { services: Vec::new(), default: 1 }));

pub fn reset_health() {
    let mut health = HEALTH.lock();
    health.services.clear();
    health.default = 1;
}

/// `PUT /mockserver/grpc/health`.
pub fn put_health(body: &str) -> Reply {
    let json = |status: u32, v: serde_json::Value| Reply::api_body(status, "application/json", crate::json::pretty(&v));
    let error = |message: &str| Reply::api_body(400, "application/json", crate::json::compact(&serde_json::json!({"error": message})));
    if body.trim().is_empty() {
        return error("request body is required with 'service' and 'status' fields");
    }
    let node = match crate::chaos::read_tree(body, true) {
        Ok(node) => node,
        Err(e) => return error(&format!("failed to set gRPC health status: {e}")),
    };
    let text = |v: Option<&serde_json::Value>| v.map(|v| v.as_str().map_or_else(|| if v.is_null() { String::new() } else { v.to_string() }, str::to_string));
    let mut service = text(node.get("service")).unwrap_or_default();
    if service == "_default" {
        service.clear();
    }
    let mut health = HEALTH.lock();
    if node.get("remove").and_then(serde_json::Value::as_bool) == Some(true) {
        if service.is_empty() {
            health.default = 1;
        } else {
            health.services.retain(|(s, _)| *s != service);
        }
        return json(200, serde_json::json!({"status": "removed", "service": service}));
    }
    let Some(status) = text(node.get("status")).filter(|s| !s.trim().is_empty()) else {
        return error("'status' field is required (UNKNOWN, SERVING, NOT_SERVING, SERVICE_UNKNOWN)");
    };
    let Some(index) = SERVING_STATUSES.iter().position(|s| *s == status.to_uppercase()) else {
        return error("invalid status value, must be one of: UNKNOWN, SERVING, NOT_SERVING, SERVICE_UNKNOWN");
    };
    if service.is_empty() {
        health.default = index;
    } else {
        match health.services.iter_mut().find(|(s, _)| *s == service) {
            Some(entry) => entry.1 = index,
            None => health.services.push((service.clone(), index)),
        }
    }
    json(200, serde_json::json!({"status": "registered", "service": service, "servingStatus": SERVING_STATUSES[index]}))
}

/// `GET /mockserver/grpc/health`: every service's status, the default as `_default`, in the order of
/// `GrpcHealthRegistry.entries()`: `new HashMap<>(statusByService)` (a `ConcurrentHashMap`), then `put("", default)`.
pub fn get_health() -> Reply {
    let health = HEALTH.lock();
    let services: Vec<String> = health.services.iter().map(|(k, _)| k.clone()).collect();
    let mut entries: Vec<(String, usize)> = crate::recorded::java_concurrent_hashmap_order(&services).into_iter().map(|i| health.services[i].clone()).collect();
    entries.push((String::new(), health.default));
    let keys: Vec<String> = entries.iter().map(|(k, _)| k.clone()).collect();
    let mut out = serde_json::Map::new();
    for i in crate::recorded::java_hashmap_copy_then_put_order(&keys) {
        let (service, status) = &entries[i];
        out.insert(if service.is_empty() { "_default".into() } else { service.clone() }, SERVING_STATUSES[*status].into());
    }
    Reply::api_body(200, "application/json", crate::json::pretty(&serde_json::Value::Object(out)))
}

/// `GrpcHealthCheckHandler`: the `HealthCheckResponse` for the requested service, `NOT_FOUND` for one never
/// registered.
fn health_check(state: &State, request: &HttpRequest) -> Reply {
    let body = &request.body;
    let service = (body.len() > 6 && body[5] == 0x0a)
        .then(|| {
            let mut at = 6;
            let mut len = 0usize;
            let mut shift = 0;
            while at < body.len() {
                let b = body[at];
                at += 1;
                len |= usize::from(b & 0x7f) << shift;
                if b & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
            body.get(at..at + len).map(|s| String::from_utf8_lossy(s).into_owned())
        })
        .flatten()
        .unwrap_or_default();
    let status = {
        let health = HEALTH.lock();
        if !service.is_empty() && !health.services.iter().any(|(s, _)| *s == service) {
            None
        } else {
            Some(health.services.iter().find(|(s, _)| *s == service).map_or(health.default, |(_, st)| *st))
        }
    };
    let Some(status) = status else {
        return status_reply(request, state, Code::NotFound, Some(&format!("unknown service {service}")));
    };
    let mut reply = Reply::status(200);
    reply.headers.push(("content-type".into(), CONTENT_TYPE.into()));
    reply.headers.push(("grpc-accept-encoding".into(), ACCEPT_ENCODING.into()));
    let proto: Vec<u8> = if status == 0 { Vec::new() } else { vec![0x08, status as u8] };
    reply.body = Bytes::from(encode_frame(&proto));
    reply.trailers.push(("grpc-status".into(), "0".into()));
    direct(reply).finalize(request, &state.config)
}

// ---------------------------------------------------------------- server reflection

fn put_bytes(out: &mut Vec<u8>, number: u8, bytes: &[u8]) {
    out.push((number << 3) | 2);
    let mut len = bytes.len();
    while len >= 0x80 {
        out.push((len as u8) | 0x80);
        len >>= 7;
    }
    out.push(len as u8);
    out.extend_from_slice(bytes);
}

/// `GrpcServerReflectionHandler.handleReflectionRequest`: list services, or the file (and its transitive
/// dependencies) that declares a symbol or has a name.
fn reflect(state: &State, framed: &[u8]) -> Vec<u8> {
    let proto = framed.get(5..).unwrap_or_default();
    let (mut host, mut kind, mut argument) = (String::new(), 0u8, String::new());
    let mut at = 0;
    while at < proto.len() {
        let key = proto[at];
        at += 1;
        let (number, wire) = (key >> 3, key & 7);
        if wire != 2 {
            break;
        }
        let mut len = 0usize;
        let mut shift = 0;
        while at < proto.len() {
            let b = proto[at];
            at += 1;
            len |= usize::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        let Some(value) = proto.get(at..at + len) else { break };
        at += len;
        let value = String::from_utf8_lossy(value).into_owned();
        match number {
            1 => host = value,
            3 | 4 | 7 => {
                kind = number;
                argument = value;
            }
            _ => {}
        }
    }
    let files = state.grpc.files();
    let response = |field: u8, message: &[u8]| {
        let mut out = Vec::new();
        if !host.is_empty() {
            put_bytes(&mut out, 1, host.as_bytes());
        }
        put_bytes(&mut out, field, message);
        out
    };
    let error = |code: u8, message: &str| {
        let mut e = vec![0x08, code];
        put_bytes(&mut e, 2, message.as_bytes());
        response(5, &e)
    };
    let file_response = |root: &crate::grpc::File| {
        // `transitiveClosure`: breadth-first from the file; dependencies not loaded are left out.
        let mut ordered = vec![root.clone()];
        let mut visited = vec![root.name.clone()];
        let mut i = 0;
        while i < ordered.len() {
            for dep in ordered[i].dependencies.clone() {
                if !visited.contains(&dep) {
                    visited.push(dep.clone());
                    if let Some(f) = files.iter().find(|f| f.name == dep) {
                        ordered.push(f.clone());
                    }
                }
            }
            i += 1;
        }
        let mut body = Vec::new();
        for f in ordered {
            put_bytes(&mut body, 1, &f.bytes);
        }
        response(4, &body)
    };
    // Files reachable from the services' files, as `getAllServices` sees them.
    let service_files: Vec<&crate::grpc::File> = files.iter().filter(|f| !f.services.is_empty()).collect();
    match kind {
        7 => {
            let mut list = Vec::new();
            for name in state.grpc.service_names() {
                let mut service = Vec::new();
                put_bytes(&mut service, 1, name.as_bytes());
                put_bytes(&mut list, 1, &service);
            }
            response(6, &list)
        }
        4 => {
            let found = service_files.iter().find(|f| {
                f.services.contains(&argument)
                    || f.symbols.contains(&argument)
                    || f.services.iter().any(|s| state.grpc.method(s, argument.strip_prefix(&format!("{s}.")).unwrap_or("\u{0}")).is_some())
            });
            match found {
                Some(f) => file_response(f),
                None => error(5, &format!("symbol not found: {argument}")),
            }
        }
        3 => match files.iter().find(|f| f.name == argument) {
            Some(f) => file_response(f),
            None => error(5, &format!("file not found: {argument}")),
        },
        _ => error(12, "unsupported reflection request type"),
    }
}

// ---------------------------------------------------------------- forwarding

/// `GrpcForwardTranslator.encodeRequestForUpstream`: a converted gRPC request (JSON body, derived headers) as the
/// framed protobuf request the upstream expects, sent over HTTP/2; `None` for any other request.
pub fn forward_request(state: &State, out: &crate::client::Outbound, secure: bool) -> Option<(crate::client::Outbound, String, String)> {
    let header = |name: &str| out.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone());
    let (service, method) = (header(SERVICE).filter(|s| !s.is_empty())?, header(METHOD).filter(|m| !m.is_empty())?);
    if !is_grpc_content_type(header("content-type").as_deref()) || !state.grpc.has_services() {
        return None;
    }
    let descriptor = state.grpc.method(&service, &method)?;
    let pool = state.grpc.pool();
    let body = String::from_utf8_lossy(&out.body).into_owned();
    let framed = if body.is_empty() {
        encode_frame(&[])
    } else if body.trim_start().starts_with('[') {
        let items: Vec<serde_json::Value> = serde_json::from_str(&body).ok()?;
        let mut frames = Vec::new();
        for item in items {
            frames.extend(encode_frame(&pool.from_json(&descriptor.input_type, &item.to_string()).ok()?));
        }
        frames
    } else {
        encode_frame(&pool.from_json(&descriptor.input_type, &body).ok()?)
    };
    // `withProtocol(HTTP_2)`: negotiated over TLS; a plaintext upstream is spoken to in HTTP/1.1, as upstream's client does.
    let _ = secure;
    let mut encoded = crate::client::Outbound { body: Bytes::from(framed), http2: true, ..out.clone() };
    const DERIVED: &[&str] = &[SERVICE, METHOD, ORIGINAL_CONTENT_TYPE, CLIENT_STREAMING, "content-type", "te"];
    encoded.headers.retain(|(k, _)| !DERIVED.iter().any(|d| k.eq_ignore_ascii_case(d)));
    // `replaceHeader(content-type)` then `withHeader(te)` put both last in the request model, ahead of what the
    // client encoder appends (`host`, `accept-encoding` when the client sent one, `content-length`, `connection`; see
    // `forward::outbound`).
    let length_at = encoded.headers.iter().rposition(|(k, _)| k.eq_ignore_ascii_case("content-length")).unwrap_or(encoded.headers.len());
    let mut at = length_at;
    for appended in ["accept-encoding", "host"] {
        if at > 0 && encoded.headers[at - 1].0.eq_ignore_ascii_case(appended) {
            at -= 1;
        }
    }
    encoded.headers.insert(at, ("te".into(), "trailers".into()));
    encoded.headers.insert(at, ("content-type".into(), CONTENT_TYPE.into()));
    let length = encoded.body.len().to_string();
    match encoded.headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
        Some((_, v)) => *v = length,
        None => encoded.headers.push(("content-length".into(), length)),
    }
    Some((encoded, service, method))
}

/// `decodeResponseFromUpstream`: the upstream's framed protobuf response as JSON, with the method in the derived
/// headers and `grpc-message` percent-decoded.
pub fn forward_response(state: &State, mut upstream: crate::client::Upstream, service: &str, method: &str) -> crate::client::Upstream {
    let Some(descriptor) = state.grpc.method(service, method) else { return upstream };
    let pool = state.grpc.pool();
    let json = if upstream.body.is_empty() {
        Some(String::new())
    } else {
        decode_frames(state, &upstream.body, None).ok().and_then(|messages| {
            let json: Result<Vec<String>, String> = messages.iter().map(|m| pool.to_json(&descriptor.output_type, m)).collect();
            json.ok().map(|j| match j.len() {
                0 => String::new(),
                1 => j[0].clone(),
                _ => format!("[{}]", j.join(",")),
            })
        })
    };
    let Some(json) = json else {
        crate::log::warn(state, &format!("failed to decode upstream gRPC response for {service}/{method}, forwarding it unchanged:"));
        return upstream;
    };
    upstream.body = Bytes::from(json.into_bytes());
    upstream.text_body = true;
    upstream.headers.push((SERVICE.into(), service.to_string()));
    upstream.headers.push((METHOD.into(), method.to_string()));
    // `withHeader(GRPC_STATUS_HEADER, String.valueOf(Integer.parseInt(...)))` adds a value to the upstream's own.
    let status = upstream.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("grpc-status")).and_then(|(k, v)| Some((k.clone(), v.trim().parse::<i32>().ok()?)));
    if let Some((name, n)) = status {
        upstream.headers.push((name, n.to_string()));
    }
    if let Some((_, v)) = upstream.headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case("grpc-message")) {
        *v = percent_decode(v).chars().filter(|c| !c.is_control()).collect();
    }
    upstream
}

// ---------------------------------------------------------------- bidirectional streams

/// The transport serving a bidi stream. HTTP/2 answers inbound messages in turn: `GrpcBidiStreamHandler` reads the
/// next DATA frame only once the previous one's responses are written. HTTP/3 answers them concurrently:
/// `Http3GrpcBidiStreamHandler` schedules a rule's delayed responses and reads on, so earlier responses keep flowing
/// while a later frame is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BidiTransport {
    Http2,
    Http3,
}

impl BidiTransport {
    /// What a held stream's id carries after the path (`Http3MockServerHandler` adds `h3-`).
    fn stream_tag(self) -> &'static str {
        match self {
            BidiTransport::Http2 => "",
            BidiTransport::Http3 => "h3-",
        }
    }
}

/// Where a bidi stream's inbound DATA goes until the client half-closes (drops the sender).
pub type BidiBody = tokio::sync::mpsc::UnboundedReceiver<Bytes>;

/// With `grpcBidiStreamingEnabled`, whether a request head on `path` is for a bidirectional-streaming method of a
/// loaded descriptor set, which the transport then hands to [`open_bidi`] before its body arrives
/// (`GrpcBidiRouterHandler`, `Http3MockServerHandler.tryBeginGrpcBidi`): the channel its DATA goes through. HTTP/2
/// takes a head without `content-type` as gRPC, HTTP/3 does not.
pub fn bidi_channel(state: &State, transport: BidiTransport, path: &str, content_type: Option<&str>) -> Option<(tokio::sync::mpsc::UnboundedSender<Bytes>, BidiBody)> {
    if !state.config.bool_property("grpcBidiStreamingEnabled", false) {
        return None;
    }
    let content_type = match transport {
        BidiTransport::Http2 => content_type.or(Some(CONTENT_TYPE)),
        BidiTransport::Http3 => content_type,
    };
    if !is_grpc_content_type(content_type) || !installed(state) || !state.grpc.has_services() {
        return None;
    }
    if transport == BidiTransport::Http2 && (path == REFLECTION_V1_PATH || path == REFLECTION_V1ALPHA_PATH) {
        // `GrpcBidiRouterHandler`: a reflection stream goes to `GrpcBidiReflectionHandler`.
        return Some(tokio::sync::mpsc::unbounded_channel());
    }
    let (service, method) = parse_path(path);
    if !state.grpc.method(&service, &method).is_some_and(|m| m.client_streaming && m.server_streaming) {
        return None;
    }
    Some(tokio::sync::mpsc::unbounded_channel())
}

/// `findAndConsumeMatchingBidiResponse` then `GrpcBidiStreamHandler`: with a matching `grpcBidiResponse`
/// expectation, the stream answers each inbound message by the first rule whose `matchJson` accepts it, then ends
/// with the configured status once the client half-closes; `None` when no such expectation matches (the request
/// is then handled as a whole). The session ends at once, without trailers, when the transport drops the response
/// (`onChannelInactive`: a reset stream or a lost connection), a held frame included.
pub fn open_bidi(state: &Arc<State>, head: &HttpRequest, body: BidiBody, transport: BidiTransport) -> Result<Outcome, BidiBody> {
    use serde_json::Value;
    // `hasCredentialsIfRequired`, before the peek and the consuming match: without credentials the stream is handled
    // whole, and refused there (upstream 6dcc66b58; a reflection stream too, 456a9dee3).
    if !crate::auth::has_data_plane_credentials_if_required(&state.config, head) {
        return Err(body);
    }
    if head.path == REFLECTION_V1_PATH || head.path == REFLECTION_V1ALPHA_PATH {
        return Ok(bidi_reflection(state, body));
    }
    let (service, method_name) = parse_path(&head.path);
    let mut request = head.clone();
    request.method = "POST".into();
    let derived = [SERVICE, METHOD, ORIGINAL_CONTENT_TYPE, CLIENT_STREAMING];
    request.headers.retain(|(n, _)| !derived.iter().any(|d| n.eq_ignore_ascii_case(d)));
    if request.first_header("content-type").is_none() {
        request.headers.push(("content-type".into(), vec![CONTENT_TYPE.into()]));
    }
    request.headers.push((SERVICE.into(), vec![service.clone()]));
    request.headers.push((METHOD.into(), vec![method_name.clone()]));
    // `peekFirstMatchingExpectation`: each expectation is matched in order up to the first that matches, and logged
    // as it is (without a `MatchDifference` context), whatever its action; then the consuming match logs its own.
    let mut peek = state.store.evaluate_all(&request);
    if let Some(at) = peek.iter().position(|e| e.matched) {
        peek.truncate(at + 1);
    }
    if state.info_enabled() {
        crate::dataplane::log_evaluations(state, &request, &peek, None, false);
    }
    let peeked = peek.into_iter().find(|e| e.matched).map(|e| e.expectation);
    if !peeked.is_some_and(|e| matches!(e.action, crate::action::Action::GrpcBidi(_))) {
        return Err(body);
    }
    let namespace = crate::namespace::of_request(state, &request);
    let (found, evaluated) = state.store.first_match_traced(&request, namespace.as_deref());
    if state.info_enabled() {
        crate::dataplane::log_evaluated(state, &request, &evaluated, found.is_none().then_some(namespace.as_deref()));
    }
    let Some(expectation) = found.map(|f| f.expectation) else { return Err(body) };
    // `GrpcBidiRouterHandler`'s completion callback: post-processed when the stream ends (or is never started).
    let post = crate::dataplane::PostProcess { state: state.clone(), expectation: Some(expectation.clone()) };
    let crate::action::Action::GrpcBidi(config) = &expectation.action else { return Err(body) };
    let config: Value = (**config).clone();
    state.log.received(request.clone());
    let Some(method) = state.grpc.method(&service, &method_name) else { return Err(body) };
    let mut head_reply = Reply::status(200);
    head_reply.headers.push(("content-type".into(), CONTENT_TYPE.into()));
    for (name, values) in config.get("headers").map(crate::model::multi_values).unwrap_or_default() {
        let Some(name) = name.value else { continue };
        for value in values.into_iter().flatten().filter_map(|v| v.value) {
            head_reply.headers.push((name.to_lowercase(), value));
        }
    }
    let deadline = timeout_nanos(request.first_header("grpc-timeout")).map(|n| (tokio::time::Instant::now() + Duration::from_nanos(n), n));
    let close = config.get("closeConnection").and_then(Value::as_bool).unwrap_or(false);
    let (tx, chunks) = tokio::sync::mpsc::channel::<Bytes>(64);
    let (trailers_tx, trailers) = tokio::sync::oneshot::channel();
    // An `INBOUND_STREAM` breakpoint holds each inbound DATA frame.
    let prefix = format!("grpc-bidi-inbound-{}-{}", head.path, transport.stream_tag());
    let id = format!("{prefix}{}", uuid::Uuid::new_v4());
    let held = crate::breakpoint::stream(state, &request, crate::breakpoint::StreamPhase::Inbound, id, "GRPC-INBOUND", &format!("{service}.{method_name}"));
    let emitter = Arc::new(Emitter { pool: state.grpc.pool(), output_type: method.output_type.clone(), tx, state: state.clone(), velocity: Default::default() });
    let state = state.clone();
    tokio::spawn(async move {
        let _post = post;
        let run = async {
            let session = bidi_session(&state, &config, &emitter, &method.input_type, body, held.as_ref(), transport);
            match deadline {
                Some((at, nanos)) => match tokio::time::timeout_at(at, session).await {
                    Ok(result) => result,
                    Err(_) => Err((Code::DeadlineExceeded, Some(format!("deadline exceeded after {}ms", nanos / 1_000_000)))),
                },
                None => session.await,
            }
        };
        let result = tokio::select! {
            result = run => result,
            _ = emitter.tx.closed() => return,
        };
        let (code, message) = match result {
            Ok(()) => (
                config.get("statusName").and_then(Value::as_str).map_or(Code::Ok, code_from_name),
                config.get("statusMessage").and_then(Value::as_str).map(str::to_string),
            ),
            Err(failure) => {
                // `Http3GrpcBidiStreamHandler.writeErrorTrailer`; HTTP/2's handler logs nothing.
                if transport == BidiTransport::Http3 {
                    let message = failure.1.clone().unwrap_or_default();
                    crate::log::warn_event(&state, LogEntry::at(Level::Warn, "gRPC bidi stream error over HTTP/3:{}").args([message.as_str()]));
                }
                failure
            }
        };
        let mut out = vec![("grpc-status".to_string(), (code as i32).to_string())];
        if let Some(m) = message {
            out.push(("grpc-message".into(), percent_encode(&m)));
        }
        let _ = trailers_tx.send(out);
    });
    Ok(Outcome::Stream { head: head_reply, chunks, close, trailers: Some(trailers), cut: None, chunk_count: None, upstream_end: None })
}

/// `GrpcBidiReflectionHandler`: each `ServerReflectionRequest` is answered as soon as its frame is complete (a
/// reflection client such as grpcurl waits for each answer before it sends the next request), then `grpc-status: 0`
/// once the client half-closes. The head carries only `content-type`. Frames go through [`IncrementalDecoder`]; any
/// decoder error ends the stream with `grpc-status: 13` (INTERNAL, whatever the error's status) and its message,
/// unencoded, and nothing more is read. Messages completed earlier in the failing DATA frame stay unanswered.
fn bidi_reflection(state: &Arc<State>, mut body: BidiBody) -> Outcome {
    let mut head = Reply::status(200);
    head.headers.push(("content-type".into(), CONTENT_TYPE.into()));
    let (tx, chunks) = tokio::sync::mpsc::channel::<Bytes>(64);
    let (trailers_tx, trailers) = tokio::sync::oneshot::channel();
    let state = state.clone();
    tokio::spawn(async move {
        // Upstream's no-argument decoder reads the limit from the static properties, which match the instance's here.
        let mut decoder = IncrementalDecoder::new(&state);
        while let Some(chunk) = body.recv().await {
            let messages = match decoder.feed(&chunk) {
                Ok(messages) => messages,
                Err(e) => {
                    let _ = trailers_tx.send(vec![("grpc-status".to_string(), (Code::Internal as i32).to_string()), ("grpc-message".to_string(), e.message)]);
                    return;
                }
            };
            for message in messages {
                // `handleReflectionRequest` takes the message re-framed with flag 0 (`grpcFrame`).
                if tx.send(Bytes::from(encode_frame(&reflect(&state, &encode_frame(&message))))).await.is_err() {
                    return;
                }
            }
        }
        let _ = trailers_tx.send(vec![("grpc-status".to_string(), "0".to_string())]);
    });
    Outcome::Stream { head, chunks, close: false, trailers: Some(trailers), cut: None, chunk_count: None, upstream_end: None }
}

type Failure = (Code, Option<String>);

/// Writes a bidi stream's messages (`writeGrpcMessage`), each rendered against the inbound message that triggered it.
/// `GrpcStreamMessageTemplateRenderer.render`'s IllegalArgumentException for a JavaScript `templateType`.
const BIDI_JAVASCRIPT: &str = "JavaScript templates are not supported for gRPC bidi stream responses; use a VELOCITY or MUSTACHE templateType";

struct Emitter {
    pool: Arc<crate::protobuf::Pool>,
    output_type: String,
    tx: tokio::sync::mpsc::Sender<Bytes>,
    state: Arc<State>,
    /// The stream's own `GrpcStreamMessageTemplateRenderer` engine.
    velocity: crate::templates::VelocityEngine,
}

impl Emitter {
    /// `scheduleMessages`: `messages` in order, each after its own delay.
    async fn emit(&self, messages: &[serde_json::Value], inbound: Option<&str>) -> Result<(), Failure> {
        use serde_json::Value;
        for message in messages {
            if let Some(delay) = message.get("delay").filter(|d| !d.is_null()).and_then(crate::action::delay) {
                tokio::time::sleep(delay.fixed).await;
            }
            let json = message.get("json").and_then(Value::as_str).unwrap_or_default().to_string();
            // `GrpcStreamMessageTemplateRenderer`: a template sees the inbound message as the request body.
            let json = match message.get("templateType").and_then(Value::as_str) {
                Some(t) => {
                    let engine = match t {
                        "MUSTACHE" => crate::templates::Engine::Mustache,
                        "JAVASCRIPT" => return Err((Code::Internal, Some(BIDI_JAVASCRIPT.into()))),
                        _ => crate::templates::Engine::Velocity,
                    };
                    // A fresh request with only that body (`HttpRequest.request().withBody(inboundJson)`): the
                    // stream's headers are not visible to the template.
                    let mut scope = HttpRequest::default();
                    if let Some(inbound) = inbound {
                        scope.body = Bytes::from(inbound.to_string().into_bytes());
                        scope.body_kind = crate::request::BodyKind::PlainString;
                    }
                    // The engine's RuntimeException ends the stream with INTERNAL and its message.
                    crate::templates::render_text(&self.state, &self.velocity, engine, &json, &scope).map_err(|m| {
                        // `HttpRequest.request()` prints only the body it was given.
                        let bare = match inbound {
                            Some(body) => serde_json::json!({"body": body}),
                            None => serde_json::json!({}),
                        };
                        let logged = crate::recorded::log_value(&bare);
                        let text = crate::matcher::format_log_message(0, "Exception:{} transforming template:{} for request:{}", &[&m, &json, &logged]);
                        (Code::Internal, Some(text))
                    })?
                }
                None => json,
            };
            // `GrpcJsonMessageConverter.toProtobuf`'s GrpcException.
            let bytes = self.pool.from_json(&self.output_type, &json).map_err(|_| (Code::Internal, Some("Failed to convert JSON to protobuf".to_string())))?;
            self.tx.send(Bytes::from(encode_frame(&bytes))).await.map_err(|_| (Code::Internal, Some("stream closed".into())))?;
        }
        Ok(())
    }

    /// `emitSequential` (HTTP/3): the messages up to the first delayed one now, the rest as a chain of their own.
    async fn emit_chain(self: &Arc<Self>, messages: Vec<serde_json::Value>, inbound: Option<String>, chains: &mut tokio::task::JoinSet<Result<(), Failure>>) -> Result<(), Failure> {
        let delayed = |m: &serde_json::Value| m.get("delay").filter(|d| !d.is_null()).and_then(crate::action::delay).is_some_and(|d| !d.fixed.is_zero());
        let now = messages.iter().position(delayed).unwrap_or(messages.len());
        self.emit(&messages[..now], inbound.as_deref()).await?;
        if now < messages.len() {
            let (this, rest) = (self.clone(), messages[now..].to_vec());
            chains.spawn(async move { this.emit(&rest, inbound.as_deref()).await });
        }
        Ok(())
    }
}

/// The messages of a bidi stream: the configured opening messages, then the rule responses to each inbound message
/// as it completes, until the client half-closes and every response is written.
async fn bidi_session(
    state: &State,
    config: &serde_json::Value,
    emitter: &Arc<Emitter>,
    input_type: &str,
    mut body: BidiBody,
    held: Option<&crate::breakpoint::HeldStream>,
    transport: BidiTransport,
) -> Result<(), Failure> {
    use serde_json::Value;
    let concurrent = transport == BidiTransport::Http3;
    let mut chains = tokio::task::JoinSet::new();
    let action_delay = config.get("delay").filter(|d| !d.is_null()).and_then(crate::action::delay).map(|d| d.fixed);
    let opening: Vec<Value> = config.get("messages").and_then(Value::as_array).cloned().unwrap_or_default();
    match action_delay {
        // HTTP/3 delays only the opening messages; inbound messages are answered meanwhile.
        Some(delay) if concurrent => {
            let this = emitter.clone();
            chains.spawn(async move {
                tokio::time::sleep(delay).await;
                this.emit(&opening, None).await
            });
        }
        _ if concurrent => emitter.emit_chain(opening, None, &mut chains).await?,
        delay => {
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            emitter.emit(&opening, None).await?;
        }
    }
    let joined = |done: Result<Result<(), Failure>, tokio::task::JoinError>| done.unwrap_or_else(|e| Err((Code::Internal, Some(e.to_string()))));
    let rules: Vec<Value> = config.get("rules").and_then(Value::as_array).cloned().unwrap_or_default();
    let pool = &emitter.pool;
    let mut decoder = IncrementalDecoder::new(state);
    loop {
        let chunk = tokio::select! {
            Some(done) = chains.join_next() => {
                joined(done)?;
                continue;
            }
            chunk = body.recv() => match chunk {
                Some(chunk) => chunk,
                None => break,
            },
        };
        // A held stream parks each DATA frame (before any decoding) until its client decides.
        let Some(pieces) = crate::breakpoint::pass_bytes(held, chunk).await else {
            return Err((Code::Cancelled, Some("stream closed by breakpoint".into())));
        };
        for chunk in pieces {
            // `GrpcBidiStreamHandler.channelRead`: a GrpcException ends the stream RESOURCE_EXHAUSTED only for the
            // buffer cap ("exceeded maximum"), INTERNAL for everything else, whatever status the exception carries.
            let messages = decoder.feed(&chunk).map_err(|e| {
                (if e.message.contains("exceeded maximum") { Code::ResourceExhausted } else { Code::Internal }, Some(e.message))
            })?;
            for m in messages {
                // `GrpcJsonMessageConverter.toJson`'s GrpcException.
                let inbound = pool.to_json(input_type, &m).map_err(|_| (Code::Internal, Some("Failed to convert protobuf to JSON".to_string())))?;
                if let Some(rule) = rules.iter().find(|r| bidi_rule_matches(r, &inbound)) {
                    let responses: Vec<Value> = rule.get("responses").and_then(Value::as_array).cloned().unwrap_or_default();
                    if concurrent {
                        emitter.emit_chain(responses, Some(inbound), &mut chains).await?;
                    } else {
                        emitter.emit(&responses, Some(&inbound)).await?;
                    }
                }
            }
        }
    }
    // `maybeFinish`: the trailers wait for every response still being written.
    while let Some(done) = chains.join_next().await {
        joined(done)?;
    }
    Ok(())
}

/// `GrpcBidiRuleMatcher.matches`: the inbound JSON equal to `matchJson`, else a full (`DOTALL`) regex match.
fn bidi_rule_matches(rule: &serde_json::Value, inbound: &str) -> bool {
    let (pattern, not) = match rule.get("matchJson") {
        Some(serde_json::Value::String(s)) if s.starts_with('!') => (s[1..].to_string(), true),
        Some(serde_json::Value::String(s)) => (s.clone(), false),
        Some(serde_json::Value::Object(o)) => (o.get("value").and_then(serde_json::Value::as_str).unwrap_or_default().to_string(), o.get("not").and_then(serde_json::Value::as_bool).unwrap_or(false)),
        _ => return true,
    };
    if pattern.is_empty() {
        return true;
    }
    let matched = inbound == pattern || fancy_regex::Regex::new(&format!("(?s)^(?:{pattern})$")).is_ok_and(|r| r.is_match(inbound).unwrap_or(false));
    matched != not
}


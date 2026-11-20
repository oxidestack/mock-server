//! Per-request dispatch: control plane first, then data plane (§1.1 "Dispatch order"). Transport adapters
//! (`http1`, and hyper for HTTP/2 in `server`) build the [`HttpRequest`] and write the [`Reply`].

use std::net::SocketAddr;
use std::sync::Arc;

use crate::reply::Reply;
use crate::request::{self, HttpRequest};
use crate::state::State;
use crate::{control, dataplane};

#[derive(Clone)]
pub struct Connection {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// The TLS client's certificate chain, as `clientCertificateChain` entries (empty when none was sent).
    pub client_certificates: std::sync::Arc<Vec<crate::tls::client_cert::ClientCertificate>>,
    /// Inside a `CONNECT` (or SOCKS) tunnel: its target (`REMOTE_SOCKET`).
    pub proxy_target: Option<(String, u16)>,
    /// The client a PROXY protocol header named (`PROXY_PROTOCOL_SOURCE`), which [`Connection::client_address`]
    /// reports in place of `remote`.
    pub client: Option<SocketAddr>,
    /// The TCP socket underneath, for chaos that resets the connection.
    pub socket: crate::chaos::io::Socket,
    /// The worker event loop serving it (`crate::server::OpenConnections`), whose thread stamps entries with a port
    /// only once it has handled an HTTP request.
    pub event_loop: usize,
    /// What the connection carries, for `responseWriteStallTimeoutMillis` (`crate::write_stall`).
    pub write_stall: crate::write_stall::Kind,
    /// What the connection is doing, for `inboundConnectionIdleTimeoutMillis` (`crate::inbound`).
    pub idle: crate::inbound::Activity,
    /// The server name a TLS client's ClientHello asked for (`SniHandler.getSniHostname`), which the binary relay's
    /// own TLS with its upstream names in place of an address.
    pub sni: Option<String>,
    /// The host name `PortUnificationHandler.getLocalAddresses` gave the local address's `InetAddress`, when this was
    /// the first connection on that address ([`crate::server::name_first_local_address`]); `localAddress` then
    /// prints `<name>/<ip>:<port>`.
    pub local_name: Option<Arc<str>>,
}

impl Connection {
    /// `SocketAddresses.clientAddress`: the source a PROXY protocol header named, else the connection's own peer.
    pub fn client_address(&self) -> SocketAddr {
        self.client.unwrap_or(self.remote)
    }
}

pub enum Outcome {
    /// Already finalized for the request.
    Respond(Reply),
    /// Bytes written verbatim (`httpError.responseBytes`), then the connection is closed if `close`.
    Raw { bytes: bytes::Bytes, close: bool },
    DropConnection,
    /// `httpError.resetConnection`: write `bytes` if any, then reset the whole connection (`SO_LINGER 0`, a TCP RST, no
    /// TLS `close_notify`); HTTP/2 resets the whole connection, HTTP/3 closes QUIC with `H3_INTERNAL_ERROR`.
    ResetConnection { bytes: Option<bytes::Bytes> },
    /// Write nothing and keep the connection open until the client gives up (empty `httpError`).
    Hang,
    /// Relay the WebSocket upgrade `request` to `host:port` (`crate::ws_relay`), taking over the connection.
    /// `guarded`: relayed by a forward expectation, so the forward loop guard applies (`crate::forward_loop`).
    WebSocketRelay { request: Box<crate::request::HttpRequest>, host: String, port: u16, tls: bool, guarded: bool },
    /// Serve the mocked WebSocket session `response` (`httpWebSocketResponse`) on the connection (`crate::ws_mock`).
    WebSocket { request: Box<crate::request::HttpRequest>, response: Box<serde_json::Value> },
    /// Reset the HTTP/2 stream with this error code (`httpError.streamError`); HTTP/1.1 drops the connection.
    Reset(u32),
    /// A response whose body is written as it is produced: `head` as is (no framing added), then each chunk as it
    /// arrives (HTTP/1.1 chunked, HTTP/2 DATA frames), then the trailers if any are sent before the body ends, then
    /// the end; an HTTP/1.1 connection is closed after when `close`, or when `cut` is set by the time the body ends
    /// (a RESPONSE_STREAM breakpoint's CLOSE, `breakpoint::hold_chunks`).
    Stream {
        head: Reply,
        chunks: tokio::sync::mpsc::Receiver<bytes::Bytes>,
        close: bool,
        trailers: Option<tokio::sync::oneshot::Receiver<Vec<(String, String)>>>,
        cut: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
        /// How the forwarded stream this body relays ended: one that ended aborted
        /// ([`crate::client::StreamEnd::is_aborted`]: cut, idle or over the header limit) gets no terminating chunk, as
        /// on the fixed image (upstream c9fb69fd5 with a78886b4d): HTTP/1.1 closes the connection, HTTP/2 resets the
        /// stream.
        upstream_end: Option<std::sync::Arc<crate::client::StreamEnd>>,
        /// `Some(n)`: the body is exactly `n` chunks and the last one ends it (a `LastHttpContent` carrying data, as
        /// `writeChunkedResponseWithDelay` writes): HTTP/2 sets END_STREAM on it, or on its trailers.
        chunk_count: Option<usize>,
    },
    /// Send an HTTP/2 GOAWAY first (`Http2GoAwayEmitter`; nothing on HTTP/1.1), advertising `last_stream_id` or,
    /// when `None`, the connection's last stream, then carry on with `then`.
    GoAway { last_stream_id: Option<u32>, error_code: u32, then: Box<Outcome> },
}

/// A request head as `EarlyMatchingHandler` sees it (no body yet), behind `HttpContentDecompressor`: a coding it
/// decodes (see [`coding`]) turns a `Content-Length` into `transfer-encoding: chunked`, at the end, and removes the
/// `Content-Encoding`; then the aggregator's `Content-Length` is added unless the request is chunked.
pub fn complete_head(request: &mut HttpRequest) {
    if let Some(coding) = coding(request) {
        let mut head = vec![("content-encoding".to_string(), coding)];
        if let Ok(Some(_)) = crate::client::decoding::Decoder::for_head(&mut head, false) {
            let headers = &mut request.headers;
            if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
                headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("transfer-encoding"));
                headers.push(("transfer-encoding".into(), vec!["chunked".into()]));
            }
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-encoding"));
        }
    }
    if request::first(&request.headers, "content-length").is_none() && request::first(&request.headers, "transfer-encoding").is_none() {
        request.headers.push(("content-length".into(), vec![request.body.len().to_string()]));
    }
    request.cookies = request::parse_cookies(&request.headers);
}

/// MockServer's view of a received request, completed the way the inbound pipeline leaves it:
/// `PreserveHeadersNettyRemoves` keeps the `Content-Encoding` and `Transfer-Encoding` values and the wire body,
/// `HttpContentDecompressor` decodes the body (removing `Content-Encoding`, and turning a `Content-Length` into
/// `Transfer-Encoding: chunked`), `HttpObjectAggregator` drops `chunked` and sets the decoded `content-length` last, and
/// `FullHttpRequestToMockServerHttpRequest` leaves `content-length` out of a request that arrived with a
/// `Transfer-Encoding` and appends what the pipeline removed under its lower-case name. The coding may come from the
/// `Transfer-Encoding` ([`coding`]); the wire bytes are then not kept, as `PreserveHeadersNettyRemoves` keeps them only
/// for a `Content-Encoding`. `max_body` is `maxRequestBodySize`, which bounds a raw snappy block's declared size and
/// the decoded body (`HttpObjectAggregator` counts what the decompressor passes on): a longer one is refused
/// ([`DecodeFailure::too_large`]).
pub fn complete(request: &mut HttpRequest, max_body: usize) -> Result<(), DecodeFailure> {
    let preserved = |name: &str| -> Option<Vec<String>> {
        let values: Vec<String> = request.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).flat_map(|(_, v)| v.iter().cloned()).collect();
        request.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name)).then_some(values)
    };
    let (content_encoding, transfer_encoding) = (preserved("content-encoding"), preserved("transfer-encoding"));
    let decoded = decode(request, max_body)?;
    if decoded.as_ref().is_some_and(|decoded| decoded.len() > max_body) {
        return Err(DecodeFailure { faults: Vec::new(), too_large: true });
    }
    let headers = &mut request.headers;
    if let Some(decoded) = decoded {
        // The wire bytes are kept only when they differ from the decoded body.
        let raw = std::mem::replace(&mut request.body, decoded);
        if content_encoding.is_some() && !raw.is_empty() && raw != request.body {
            request.original_body = Some(raw);
        }
        if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("transfer-encoding"));
            headers.push(("transfer-encoding".into(), vec!["chunked".into()]));
        }
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-encoding"));
    }
    // `HttpUtil.setTransferEncodingChunked(m, false)`: values that are exactly `chunked` go; the others are `set`
    // again, under the lower-case name at the end, or the header goes when none is left.
    let remaining: Vec<String> = headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding")).flat_map(|(_, v)| v.iter()).filter(|v| !v.eq_ignore_ascii_case("chunked")).cloned().collect();
    if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding")) {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("transfer-encoding"));
        if !remaining.is_empty() {
            headers.push(("transfer-encoding".into(), remaining));
        }
    }
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
        headers.push(("content-length".into(), vec![request.body.len().to_string()]));
    }
    if transfer_encoding.is_some() {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
    }
    for (name, values) in [("content-encoding", content_encoding), ("transfer-encoding", transfer_encoding)] {
        if let Some(values) = values.filter(|_| !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))) {
            headers.push((name.into(), values));
        }
    }
    request.cookies = request::parse_cookies(&request.headers);
    Ok(())
}

/// A request body the decompressor failed on. Nothing is answered: the HTTP/1.1 connection is closed, an HTTP/2
/// stream reset with CANCEL. See [`decode_failed`]. Or, when [`too_large`](Self::too_large), a body longer than
/// `maxRequestBodySize` once decoded, which the aggregator refuses with a `413` (nothing logged): HTTP/1.1 closes the
/// connection after it, keep-alive or not, as the oversized message is the aggregated one (`TOO_LARGE_CLOSE`).
#[derive(Debug)]
pub struct DecodeFailure {
    /// Each `DecoderException` the pipeline throws, in order.
    faults: Vec<String>,
    too_large: bool,
}

impl DecodeFailure {
    /// No decoder fault: a request cut short for another reason (Netty's direct-memory limit).
    pub fn cut_short() -> DecodeFailure {
        DecodeFailure { faults: Vec::new(), too_large: false }
    }

    pub fn too_large(&self) -> bool {
        self.too_large
    }
}

/// What a [`DecodeFailure`] logs (`CallbackWebSocketServerHandler.exceptionCaught`, the last inbound handler): a WARN
/// for each decoder fault, then an ERROR for the `PrematureChannelClosureException` the aggregator throws as the
/// channel closes mid-message.
pub fn decode_failed(state: &State, failure: &DecodeFailure) {
    use crate::recorded::{Level, LogEntry};
    log_decoder_faults(state, failure);
    let closed = "shaded_package.io.netty.handler.codec.PrematureChannelClosureException: Channel closed while still aggregating message";
    crate::log::error_event(state, LogEntry::at(Level::Error, "web socket server caught exception").throwable(closed));
}

fn log_decoder_faults(state: &State, failure: &DecodeFailure) {
    use crate::recorded::{Level, LogEntry};
    for fault in &failure.faults {
        crate::log::warn_event(state, LogEntry::at(Level::Warn, "web socket server caught SSL or decoder fault").throwable(fault));
    }
}

/// [`decode_failed`] on an HTTP/1.1 connection: the WARN for each decoder fault, then, for a body whose head the
/// aggregator holds, `Http1RequestCutShort`'s INFO entry in place of the `PrematureChannelClosureException`: the
/// request's method, path, query string and headers as the aggregator holds them (`NettyMessageForLog.request`).
/// `request` is the request as read, before [`complete`].
pub fn http1_decode_failed(state: &State, failure: &DecodeFailure, request: &HttpRequest, remote: crate::recorded::Arg) {
    use crate::recorded::{Level, LogEntry};
    log_decoder_faults(state, failure);
    let mut held = HttpRequest { method: request.method.clone(), path: request.path.clone(), query: request.query.clone(), raw_query: request.raw_query.clone(), headers: request.headers.clone(), ..HttpRequest::default() };
    // `HttpContentDecompressor` on the head: a `Content-Length` becomes `transfer-encoding: chunked`, the
    // `Content-Encoding` goes; then `HttpObjectAggregator.beginAggregation` drops `chunked`.
    if let Some(coding) = coding(&held) {
        let mut head = vec![("content-encoding".to_string(), coding)];
        if !matches!(crate::client::decoding::Decoder::for_head(&mut head, false), Ok(None)) {
            let headers = &mut held.headers;
            if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
                headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("transfer-encoding"));
                headers.push(("transfer-encoding".into(), vec!["chunked".into()]));
            }
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-encoding"));
        }
    }
    let headers = &mut held.headers;
    let remaining: Vec<String> = headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding")).flat_map(|(_, v)| v.iter()).filter(|v| !v.eq_ignore_ascii_case("chunked")).cloned().collect();
    if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding")) {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("transfer-encoding"));
        if !remaining.is_empty() {
            headers.push(("transfer-encoding".into(), remaining));
        }
    }
    // `NettyMessageForLog.request`: always without credentials (upstream 29a26d650), whether or not the half-received
    // request was meant for the control plane
    let masked_values = crate::credential_redaction::masked_values(&held);
    let held = crate::credential_redaction::without_credentials(&held).unwrap_or(held);
    let mut logged = serde_json::Map::new();
    if let serde_json::Value::Object(full) = crate::recorded::logged(&held) {
        for key in ["method", "path", "queryStringParameters", "headers"] {
            if let Some(value) = full.get(key) {
                logged.insert(key.into(), value.clone());
            }
        }
    }
    let logged = serde_json::Value::Object(logged);
    let mut entry = LogEntry::at(Level::Info, "HTTP/1.1 request from:{}ended with its connection before it was complete:{}")
        .request_json(logged.clone())
        .args([remote, crate::recorded::Arg::from(&logged)]);
    entry.masked_values.extend(masked_values);
    crate::log::info_event_about(state, entry, &held);
}

/// `RelayConnectHandler`'s loopback leg, which reads back what MockServer writes into a CONNECT or SOCKS tunnel
/// (`configureHttp1LoopbackPipeline`: `BoundedZstdHttpContentDecompressor` then an aggregator at `maxRequestBodySize`;
/// HTTP/2: `LoopbackAggregatingListener`'s `BoundedZstdDecompressorFrameListener`): a whole response in a coding the
/// decompressor decodes reaches the client decoded, without its `Content-Encoding`, with its decoded `content-length`
/// last (scenario `connect_loopback_decoding`). `Err` when it cannot be decoded or decodes past `max`: HTTP/1.1
/// answers [`loopback_failure`], HTTP/2 resets the stream.
pub fn loopback_decoded(mut reply: Reply, max: usize) -> Result<Reply, ()> {
    let mut headers = reply.headers.clone();
    let mut decoder = match crate::client::decoding::Decoder::for_head(&mut headers, true) {
        Ok(Some(decoder)) => decoder,
        Ok(None) => return Ok(reply),
        Err(_) => return Err(()),
    };
    let body = decoder.push_pieces(&reply.body, max).map_err(|_| ())?.concat();
    if body.len() > max {
        return Err(());
    }
    crate::client::decoding::Decoder::finish_headers(&mut headers, body.len());
    reply.headers = headers;
    reply.body = body.into();
    reply.chunk_size = None;
    reply.chunked_for_trailers = false;
    Ok(reply)
}

/// `StreamingAwareHttpObjectAggregator.requestExpectsStreamingResponse`, which `UpstreamProxyRelayHandler` asks of each
/// request it relays into the tunnel's loopback: `Accept: text/event-stream`, Gemini's streaming method, or a JSON body
/// (read decoded, as `decodedBodyRequestsStreaming` scans a compressed one) asking for `"stream": true`.
pub fn loopback_stream_intent(request: &HttpRequest) -> bool {
    static STREAM_TRUE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r#""stream"\s*:\s*true"#).expect("valid"));
    let header = |name: &str| request.first_header(name).map(str::to_ascii_lowercase);
    header("accept").is_some_and(|a| a.contains("text/event-stream"))
        || request.path.to_ascii_lowercase().contains(":streamgeneratecontent")
        || (header("content-type").is_some_and(|c| c.contains("json")) && STREAM_TRUE.is_match(&String::from_utf8_lossy(&request.body)))
}

/// Whether the HTTP/1.1 loopback relays a response as it reads it rather than aggregating it
/// (`StreamingAwareHttpObjectAggregator`, relay-only: `isStreamingResponse` or the request's intent).
pub fn loopback_streams(state: &State, headers: &[(String, String)], intent: bool) -> bool {
    let content_type = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.to_ascii_lowercase());
    state.config.bool_property("streamingResponsesEnabled", true)
        && (intent
            || content_type.is_some_and(|c| c.contains("text/event-stream") || c.contains("application/vnd.amazon.eventstream") || c.contains("application/x-ndjson")))
}

/// The HTTP/1.1 loopback's decompressor on a response it streams (`BoundedZstdHttpContentDecompressor` ahead of the
/// relay-only aggregator): each content `LoopbackHttpClientCodec` reads (at most `maxChunkSize` bytes) is decoded on its
/// own and relayed as one chunk per piece; the decoded bytes of one content are bounded by `maxRequestBodySize`
/// (`DownstreamProxyRelayHandler`'s unwritten bytes), past which, or on a decode failure, the stream is aborted.
pub struct LoopbackDecoder {
    decoder: crate::client::decoding::Decoder,
    max: usize,
    content: usize,
}

impl LoopbackDecoder {
    /// The decoder for a streamed head, whose headers are edited as the decompressor edits them (`content-length` goes,
    /// `transfer-encoding: chunked`, no `content-encoding`); `Ok(None)` for a coding it leaves alone.
    pub fn for_head(state: &State, headers: &mut Vec<(String, String)>) -> Result<Option<LoopbackDecoder>, ()> {
        let Some(decoder) = crate::client::decoding::Decoder::for_head(headers, false).map_err(|_| ())? else { return Ok(None) };
        let max = usize::try_from(state.config.int_property("maxRequestBodySize", 10_485_760)).unwrap_or(usize::MAX);
        let content = usize::try_from(state.config.int_property("maxChunkSize", 8192)).unwrap_or(8192).max(1);
        Ok(Some(LoopbackDecoder { decoder, max, content }))
    }

    /// The decoded pieces of `input`, as the loopback reads it; `Err` when it fails to decode or one content decodes
    /// past the bound.
    pub fn push(&mut self, input: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
        let mut out = Vec::new();
        for content in input.chunks(self.content) {
            let pieces = self.decoder.push_pieces(content, self.max).map_err(|_| ())?;
            if pieces.iter().map(Vec::len).sum::<usize>() > self.max {
                return Err(());
            }
            out.extend(pieces.into_iter().filter(|p| !p.is_empty()));
        }
        Ok(out)
    }
}

/// `LoopbackHttp1ResponseErrorHandler`: a response the HTTP/1.1 loopback could not read back is answered 502 to the
/// tunnel's client, and the tunnel closes.
pub fn loopback_failure() -> Reply {
    let mut reply = Reply::status(502);
    reply.headers = vec![("content-length".into(), "0".into()), ("connection".into(), "close".into())];
    reply.close = true;
    reply
}

/// The framing format's stream identifier chunk, which starts a framed snappy body.
const SNAPPY_STREAM_IDENTIFIER: &[u8] = b"\xff\x06\x00\x00sNaPpY";

/// The request body decoded by its first `Content-Encoding` value, as `HttpContentDecompressor` decodes it
/// (`client::decoding`, shared with the forwarding client), or `None` for a coding it leaves alone. A gzip or
/// deflate body that fails does so twice (`JdkZlibDecoder` fails again on `decodeLast`). A snappy body that does not
/// open with the stream identifier is one raw block (upstream fix cc8fb880a, after 8.0.0: `SnappyBlockOrFrameDecoder`; 8.0.0's `SnappyFrameDecoder`
/// rejects it, `docs/divergences.md`).
pub fn decode(request: &HttpRequest, max_body: usize) -> Result<Option<bytes::Bytes>, DecodeFailure> {
    let Some(coding) = coding(request) else { return Ok(None) };
    let failure = |faults| DecodeFailure { faults, too_large: false };
    let body = &request.body;
    if coding == "snappy" && !body.starts_with(SNAPPY_STREAM_IDENTIFIER) {
        return snappy_block(body, max_body).map(|b| Some(b.into())).map_err(|fault| failure(vec![fault]));
    }
    let mut head = vec![("content-encoding".to_string(), coding.clone())];
    let mut decoder = match crate::client::decoding::Decoder::for_head(&mut head, true) {
        Ok(Some(decoder)) => decoder,
        Ok(None) => return Ok(None),
        Err(fault) => return Err(failure(vec![fault])),
    };
    let zlib = matches!(coding.as_str(), "gzip" | "x-gzip" | "deflate" | "x-deflate");
    // zstd stops once past `max_body`, which `complete` then refuses (`HttpObjectAggregator` after the decompressor).
    decoder.push_pieces(body, max_body).map(|pieces| Some(pieces.concat().into())).map_err(|fault| failure(vec![fault; if zlib { 2 } else { 1 }]))
}

/// `HttpContentDecoder`'s coding, lower-cased: the first `Content-Encoding` value, else the first `Transfer-Encoding`
/// value up to its first comma (`Transfer-Encoding: gzip, chunked` is decoded as gzip).
fn coding(request: &HttpRequest) -> Option<String> {
    let coding = match request::first(&request.headers, "content-encoding") {
        Some(coding) => coding,
        None => request::first(&request.headers, "transfer-encoding")?.split(',').next().unwrap_or_default(),
    };
    Some(coding.trim().to_ascii_lowercase())
}

/// `SnappyBlockOrFrameDecoder.decodeBlock` (cc8fb880a): one raw snappy block, refused as corrupt when its preamble
/// declares more than `max` bytes or more than 22 times its own length, or the block is longer than its declared
/// size allows.
fn snappy_block(body: &[u8], max: usize) -> Result<Vec<u8>, String> {
    let fault = |message: String| format!("shaded_package.io.netty.handler.codec.compression.DecompressionException: {message}");
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let mut size = 0u64;
    let mut declared = None;
    for (i, b) in body.iter().take(4).enumerate() {
        size |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            if size > max as u64 {
                return Err(fault(format!("snappy block declares {size} decoded bytes, more than the limit of {max}")));
            }
            declared = Some(size);
            break;
        }
    }
    let Some(declared) = declared else {
        return Err(fault(if body.len() >= 4 { "snappy block size preamble is longer than 4 bytes".into() } else { "snappy block ends inside its size preamble".into() }));
    };
    let length = body.len() as u64;
    if length > 32 + declared + declared / 6 {
        return Err(fault(format!("snappy block is longer than its declared decoded size of {declared} bytes allows")));
    }
    if declared > 22 * length {
        return Err(fault(format!("snappy block declares {declared} decoded bytes, more than its {length} bytes can hold")));
    }
    snap::raw::Decoder::new().decompress_vec(body).map_err(|e| fault(e.to_string()))
}

/// Counts a request as in flight while it is handled (`InFlightRequest`); `PUT /mockserver/stop` completes its own
/// token first, so the drain it starts does not wait for itself.
struct InFlight<'a>(&'a State, bool);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if self.1 {
            self.0.request_completed();
        }
    }
}

/// The W3C trace context a channel carries between its requests (`TraceContextHandler.TRACE_CONTEXT`): one per
/// HTTP/1.1 connection, one per HTTP/2 stream.
pub type TraceChannel = parking_lot::Mutex<Option<crate::telemetry::TraceContext>>;

/// The `http_server_*` measurement of a request a transport is about to [`dispatch`] (`None` while neither the scrape
/// nor the OTLP export is on), its protocol version from the request's.
pub fn observe(state: &State, request: &HttpRequest) -> Option<crate::metrics::HttpServerRequest> {
    let version = match request.protocol {
        "HTTP_2" => "2",
        "HTTP_3" => "3",
        _ => "1.1",
    };
    crate::metrics::HttpServerRequest::start(&state.config, &request.method, request.secure, version)
}

/// What an outcome sent, for its [`observe`]d request on `protocol` (the request's): the status code and the
/// control-plane route when a response went out, else why none did (`error_type`): `connection_dropped` (HTTP/1.1
/// closed without one), `stream_reset` (an HTTP/2 or HTTP/3 stream reset instead) or `timeout` (nothing sent until
/// the client gave up). Raw bytes reach an HTTP/1.1 client only; on HTTP/2 they are dropped and the stream stays
/// open unless they close it, on HTTP/3 the stream is reset. WebSocket outcomes reset a multiplexed stream.
pub fn answered(observed: &mut Option<crate::metrics::HttpServerRequest>, outcome: &Outcome, protocol: &str) {
    if let Some(observed) = observed {
        let (status, route, error) = answer(outcome, protocol);
        observed.answered(status, route, error);
    }
}

fn answer(outcome: &Outcome, protocol: &str) -> (Option<u32>, Option<&'static str>, Option<&'static str>) {
    let http1 = protocol != "HTTP_2" && protocol != "HTTP_3";
    match outcome {
        Outcome::GoAway { then, .. } => answer(then, protocol),
        Outcome::Respond(reply) => (Some(reply.status), reply.route, None),
        Outcome::Stream { head, .. } => (Some(head.status), head.route, None),
        // `httpError.responseBytes`: whatever status line they carry
        Outcome::Raw { bytes, .. } if http1 => (raw_status(bytes), None, None),
        Outcome::Raw { close: false, .. } if protocol == "HTTP_2" => (None, None, Some("timeout")),
        Outcome::WebSocket { request, .. } if http1 && crate::ws_mock::unsupported_version(request) => (Some(426), None, None),
        Outcome::WebSocket { .. } if http1 => (Some(101), None, None),
        // the upstream answers the upgrade
        Outcome::WebSocketRelay { .. } if http1 => (None, None, None),
        Outcome::DropConnection | Outcome::Reset(_) | Outcome::ResetConnection { .. } if http1 => (None, None, Some("connection_dropped")),
        Outcome::Raw { .. } | Outcome::WebSocket { .. } | Outcome::WebSocketRelay { .. } | Outcome::Reset(_) | Outcome::DropConnection | Outcome::ResetConnection { .. } => (None, None, Some("stream_reset")),
        Outcome::Hang => (None, None, Some("timeout")),
    }
}

/// The status code of raw response bytes that start with an HTTP/1.x status line.
fn raw_status(bytes: &[u8]) -> Option<u32> {
    let line = bytes.strip_prefix(b"HTTP/1.")?.get(2..5)?;
    std::str::from_utf8(line).ok()?.parse().ok()
}

pub async fn dispatch(state: &Arc<State>, request: HttpRequest, channel: &TraceChannel) -> Outcome {
    // `TimeService`: what the request reads as now is this server's clock. Boxed: the handling future is large.
    crate::clock::scope(state.clock.clone(), Box::pin(dispatch_scoped(state, request, channel))).await
}

/// [`dispatch`] on a task of its own, as HTTP/2 answers each stream: the request's handling (a forward's outbound
/// TLS handshake included) starts at the bottom of a worker's stack instead of on top of the connection's frames
/// ([`crate::boxed`]). `early` is the expectation `EarlyMatchingHandler` already matched for it. The
/// connection's gRPC pipeline flag goes with it; dropping the returned future aborts the task, and a panic in it
/// unwinds here, as it did when the handling ran inline.
pub async fn dispatch_detached(state: &Arc<State>, request: HttpRequest, channel: &Arc<TraceChannel>, early: Option<crate::store::Found>) -> Outcome {
    struct AbortOnDrop(tokio::task::AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let (state, channel) = (state.clone(), channel.clone());
    let work = async move {
        let dispatched = dispatch(&state, request, &channel);
        match early {
            Some(found) => crate::dataplane::with_early_match(found, dispatched).await,
            None => dispatched.await,
        }
    };
    // on the connection's event loop, as the handling it is detached from
    let work = crate::server::on_worker(crate::server::current_worker(), work);
    let task = match crate::grpc_plane::PIPELINE.try_with(|grpc| *grpc) {
        Ok(grpc) => tokio::spawn(crate::grpc_plane::PIPELINE.scope(grpc, work)),
        Err(_) => tokio::spawn(work),
    };
    let _abort = AbortOnDrop(task.abort_handle());
    match task.await {
        Ok(outcome) => outcome,
        Err(failed) => match failed.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            // cancelled only as the runtime shuts down
            Err(_) => Outcome::DropConnection,
        },
    }
}

async fn dispatch_scoped(state: &Arc<State>, request: HttpRequest, channel: &TraceChannel) -> Outcome {
    // `McpStreamableHttpHandler` sits before `HttpRequestHandler`: not counted, not logged, not decorated.
    if crate::mcp::serves(state, &request.path) {
        // handled on the MCP session manager's executor, off the worker event loop
        let mut reply = crate::server::on_worker(None, crate::recorded::portless(crate::mcp::handle(state, &request))).await;
        reply.route = Some("/mockserver/mcp");
        return Outcome::Respond(reply);
    }
    // `GrpcToHttpRequestHandler` / `GrpcToHttpResponseHandler` wrap the HTTP handling of a gRPC request.
    // Boxed: the HTTP handling future is large, and nesting it here twice over would exhaust a worker's stack.
    match Box::pin(crate::grpc_plane::dispatch(state, request, channel)).await {
        Ok(outcome) => outcome,
        Err(request) => Box::pin(dispatch_http(state, *request, channel)).await,
    }
}

/// The HTTP handling of a request (gRPC ones arrive here converted).
pub async fn dispatch_http(state: &Arc<State>, request: HttpRequest, channel: &TraceChannel) -> Outcome {
    if let Some(event_loop) = crate::server::current_worker() {
        state.connections.requested_http(event_loop);
    }
    crate::telemetry::inbound(state, &request, channel);
    let context = channel.lock().clone();
    let tcp = request.protocol != "HTTP_3";
    let mut outcome = crate::telemetry::with_channel(context, handle(state, request)).await;
    decorated(state, &mut outcome, channel, tcp);
    outcome
}

/// The response written passes `AltSvcHeaderHandler` (TCP only) and `TraceContextHandler`.
fn decorated(state: &State, outcome: &mut Outcome, channel: &TraceChannel, tcp: bool) {
    match outcome {
        Outcome::Respond(reply) => {
            if tcp {
                alt_svc(state, reply);
            }
            crate::telemetry::outbound(state, reply, channel);
        }
        Outcome::GoAway { then, .. } => decorated(state, then, channel, tcp),
        _ => {}
    }
}

/// `AltSvcHeaderHandler`: with `http3Port` configured (whether or not it is listening) and `http3AdvertiseAltSvc`,
/// TCP responses advertise it, unless they already carry an `Alt-Svc`.
fn alt_svc(state: &State, reply: &mut Reply) {
    let port = state.config.int_property("http3Port", 0);
    if port > 0 && state.config.bool_property("http3AdvertiseAltSvc", true) && reply.header("alt-svc").is_none() {
        let max_age = state.config.int_property("http3AltSvcMaxAge", 86400);
        // After `connection`, before what the encoder adds (`content-length`, `set-cookie`), as on the oracle.
        let at = reply.model_headers_end.map_or(reply.headers.len(), |end| end.min(reply.headers.len()));
        reply.headers.insert(at, ("alt-svc".into(), format!("h3=\":{port}\"; ma={max_age}")));
    }
}

/// Boxed: its future is large ([`crate::boxed`]).
fn handle(state: &Arc<State>, request: HttpRequest) -> crate::boxed::Boxed<'_, Outcome> {
    Box::pin(handle_inline(state, request))
}

async fn handle_inline(state: &Arc<State>, request: HttpRequest) -> Outcome {
    let stop = request.method == "PUT" && matches!(request.path.as_str(), "/mockserver/stop" | "/stop");
    if !stop {
        state.request_started();
    }
    let _in_flight = InFlight(state, !stop);
    let metrics = crate::metrics::enabled(&state.config);
    if metrics {
        state.config.metrics.increment(crate::metrics::Count::RequestsReceived);
    }
    let started = std::time::Instant::now();
    // `HttpRequestHandler`: the preemption cordon turns new data-plane exchanges away before anything else.
    if let Some(decision) = state.chaos.preemption.decide(state, &request) {
        let then = match decision.reject {
            Some(reply) => Outcome::Respond(reply),
            None => serve(state, request, metrics, started).await,
        };
        return match decision.go_away {
            Some(last_stream_id) => Outcome::GoAway { last_stream_id, error_code: 0, then: Box::new(then) },
            None => then,
        };
    }
    serve(state, request, metrics, started).await
}

/// Boxed: its future is large ([`crate::boxed`]).
fn serve(state: &Arc<State>, request: HttpRequest, metrics: bool, started: std::time::Instant) -> crate::boxed::Boxed<'_, Outcome> {
    Box::pin(serve_inline(state, request, metrics, started))
}

async fn serve_inline(state: &Arc<State>, mut request: HttpRequest, metrics: bool, started: std::time::Instant) -> Outcome {
    // `HttpRequestHandler`: every request gets its log correlation id, which the entries about it carry.
    if request.log_correlation_id.is_empty() {
        request.log_correlation_id = uuid::Uuid::new_v4().to_string();
    }
    // `HttpState.handle`, at TRACE: every request it is given, the control plane's too, before anything handles it
    // (an early match never reaches it).
    if state.log_level == "TRACE" && !crate::dataplane::serving_early_match() {
        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Trace, "received request:{}").args([crate::recorded::Arg::from(crate::recorded::logged(&request))]);
        crate::log::entry(state, &entry);
        state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(request.clone())));
    }
    let host = request.first_header("host").map(str::to_string);
    let method = request.method.clone();
    // `HttpRequestHandler.channelRead0`: every exchange's `Host` header grows the leaf's SAN set, not only
    // CONNECT/SOCKS targets (confirmed against the oracle: a plain HTTP request with an unseen `Host` shows up
    // on a later, unrelated TLS handshake). `Tls::add_subject_alternative_name` normalises/validates/caps it.
    if let Some(host) = &host && let Some(tls) = state.tls.as_ref() {
        tls.add_subject_alternative_name(host);
    }
    let outcome = crate::wasm::scope(state.clone(), async {
        // A control-plane reply names its operation (`http_route`).
        let control = |mut reply: Reply| {
            reply.route = Some(if reply.status_path { "/mockserver/status" } else { control::operation_route(&request.path) });
            Outcome::Respond(reply.finalize(&request, &state.config))
        };
        // `HttpState.handle`: a request the control plane serves with a browser `Origin` it does not allow is refused
        // before any handler or expectation runs (9.1.0, upstream #220).
        if crate::cors_origin::is_refused(&request, &state.config) {
            return control(crate::cors_origin::refusal(state, &request));
        }
        if let Some(reply) = control::unable_to_schedule(state, &request) {
            return control(reply);
        }
        if let Some(reply) = crate::contract_test::route(state, &request).await {
            return control(reply);
        }
        if let Some(reply) = crate::replay::route(state, &request).await {
            return control(reply);
        }
        if let Some(reply) = control::route(state, &request) {
            return control(reply);
        }
        dataplane::handle(state, request).await
    })
    .await;
    if metrics {
        let seconds = started.elapsed().as_secs_f64();
        state.config.metrics.request_handled(seconds);
        if state.config.bool_startup_property("metricsRequestDurationRouteLabels", false) {
            state.config.metrics.request_handled_by_method(&method, seconds);
        }
    }
    match host.and_then(|h| crate::chaos::lifecycle_profile(state, &h)) {
        Some(profile) => crate::chaos::apply_lifecycle(state, &profile, outcome),
        None => outcome,
    }
}

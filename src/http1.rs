//! HTTP/1.x connections, parsed with `httparse` so header names keep their case and order both ways, as
//! MockServer's Netty server does.

use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::handler::{self, Connection, Outcome};
use crate::reply::Reply;
use crate::request::{self, HttpRequest, MultiMap};
use crate::state::State;

const MAX_HEAD: usize = 1024 * 1024;
/// Netty's `HttpObjectAggregator` answers to a body over its limit.
const TOO_LARGE: &[u8] = b"HTTP/1.1 413 Request Entity Too Large\r\ncontent-length: 0\r\n\r\n";
const TOO_LARGE_CLOSE: &[u8] = b"HTTP/1.1 413 Request Entity Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
const TOO_LARGE_EXPECTATION: &[u8] = b"HTTP/1.1 417 Expectation Failed\r\ncontent-length: 0\r\n\r\n";
const MAX_BODY: usize = 256 * 1024 * 1024;

enum Error {
    Closed,
    Malformed,
    /// A chunked body grew past `maxRequestBodySize`.
    TooLarge,
    /// A chunk-size line Netty's decoder rejects: the message of its `DecoderResult` failure.
    BadChunk(String),
    /// A request Netty's decoder could not read, refused by `HttpChunkLineLimiter`: the status it is answered with
    /// (`400`, `414` for a request line over `maxInitialLineLength`, `431` for headers over `maxHeaderSize`) and the
    /// message of the decoder's failure.
    Refused(u16, String),
    /// A chunk-size line (with its extensions) or trailer section still unended past `MAX_CHUNK_LINE_BYTES`.
    ChunkLine,
}

/// `HttpChunkLineLimiter.MAX_CHUNK_LINE_BYTES`, plus the CRLF ending the chunk before it that it counts with the line
/// (`CHUNK_DELIMITER_BYTES`): bytes of a chunk-size line or trailer section that may wait for their end.
const MAX_CHUNK_LINE_BYTES: usize = 8192;
const CHUNK_DELIMITER_BYTES: usize = 2;

struct Head {
    method: String,
    target: String,
    http10: bool,
    /// Exactly HTTP/1.1 (Netty's `HttpVersion.HTTP_1_1`), which alone may carry a `Transfer-Encoding`.
    http11: bool,
    headers: MultiMap,
    /// The message of the `DecoderResult` failure Netty's decoder attached to the request: such a request is
    /// refused, never dispatched (`Error::Refused`).
    decode_error: Option<String>,
}

/// `maxInitialLineLength` and `maxHeaderSize` (Netty's `HttpObjectDecoder` limits; 64 KiB and 256 KiB by default).
struct Limits {
    initial_line: usize,
    headers: usize,
}

pub async fn serve<S>(state: Arc<State>, mut conn: Connection, stream: S, buf: BytesMut, secure: bool)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    crate::server::name_first_local_address(&mut conn, secure).await;
    // `PortUnificationHandler` adds the gRPC handlers when it sets the connection up, if descriptors are loaded then.
    let grpc = state.grpc.has_services();
    conn.write_stall.set(crate::write_stall::Protocol::Http1);
    // `MockServerHttpServerCodec` is built with the client's certificates
    if secure {
        crate::server::log_no_client_certificate(&state, &conn);
    }
    let worker = Some(conn.event_loop);
    crate::boxed::connection(crate::server::on_worker(worker, crate::grpc_plane::PIPELINE.scope(grpc, serve_connection(state, conn, stream, buf, secure, true, true)))).await
}

/// Whether what is buffered holds the whole head of another request: one pipelined behind the exchange being served.
fn head_buffered(buf: &BytesMut) -> bool {
    let start = buf.iter().take_while(|b| matches!(b, b'\r' | b'\n')).count();
    buf[start..].windows(4).any(|w| w == b"\r\n\r\n")
}

/// Whether a request whose head is read has its whole body in `buf` already (a chunked one: its last chunk).
fn held_request_complete(head: &Head, buf: &BytesMut) -> bool {
    if request::first(&head.headers, "transfer-encoding").is_some() {
        return buf.windows(5).any(|w| w == b"0\r\n\r\n");
    }
    let length = request::first(&head.headers, "content-length").and_then(|l| l.trim().parse::<usize>().ok()).unwrap_or(0);
    buf.len() >= length
}

/// `Http1PipeliningGate`'s backstop: held requests behind a response that makes no progress for
/// `inboundConnectionIdleTimeoutMillis` close the connection (this returns), counted in
/// `mock_server_http1_pipelining_wedged_connections_total`; with the timeout 0 the connection is only counted, after
/// 300 seconds, and left open (this never returns). A task on the connection's `event_loop`, run late while a runtime
/// LLM call blocks it.
async fn wedge_backstop(state: &State, event_loop: usize) {
    let timeout = state.config.int_property("inboundConnectionIdleTimeoutMillis", 300_000);
    if timeout > 0 {
        state.connections.loop_timer(event_loop, std::time::Duration::from_millis(timeout as u64)).await;
        state.config.metrics.http1_pipelining_wedged_connection();
        return;
    }
    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
    state.config.metrics.http1_pipelining_wedged_connection();
    std::future::pending::<()>().await;
}

/// A closed connection's other end: reads end at once and writes go nowhere, as Netty's writes to a closed channel.
struct Spent;

impl AsyncRead for Spent {
    fn poll_read(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>, _: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Spent {
    fn poll_write(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>, bytes: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// The requests already read behind one whose response closed the connection. Netty's `HttpObjectDecoder` decodes
/// every message in what one `channelRead` brought, after the close too: each is received, logged, matched and counts
/// against `times`, and its response is written to the closed channel, which drops it (8.0.0 oracle, scenario
/// `http1_pipelined_after_close`).
fn serve_spent(state: Arc<State>, conn: Connection, buf: BytesMut, secure: bool) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(serve_connection(state, conn, Spent, buf, secure, false, false))
}

/// What the answer to one request needs once it is written: the request's own view of its exchange.
struct Flight {
    head_only: bool,
    tunnel: bool,
    stream_intent: bool,
    observed: Option<crate::metrics::HttpServerRequest>,
    exchange: crate::inbound::Busy,
    decoded: std::time::Instant,
}

/// `live` is false for [`serve_spent`]'s closed connection.
async fn serve_connection<S>(state: Arc<State>, conn: Connection, mut stream: S, mut buf: BytesMut, secure: bool, mut first: bool, live: bool)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let limit = |value: i64| usize::try_from(value).unwrap_or(usize::MAX);
    let limits = Limits {
        initial_line: limit(crate::config::max_initial_line_length(&state.config)),
        headers: limit(crate::config::max_header_size(&state.config)),
    };
    let trace = Arc::new(handler::TraceChannel::default());
    let measured = crate::metrics::enabled(&state.config);
    // `Http1PipeliningGate` (9.2.0, #84): a request whose head was already read while the one before it was being
    // answered is a held one; set by the iteration that dispatches the request before it.
    let mut pending_held = false;
    // `http1PipeliningInOrder=false` (deprecated upstream), read when the connection is set up: no gate, the requests
    // pipelined on the connection are handled concurrently and answered in the order they complete
    let out_of_order = !state.config.bool_property("http1PipeliningInOrder", true);
    type InFlight = std::pin::Pin<Box<dyn std::future::Future<Output = (Outcome, Flight)> + Send>>;
    let mut in_flight: futures_util::stream::FuturesUnordered<InFlight> = futures_util::stream::FuturesUnordered::new();
    // A delayed close (`closeSocketDelay`, a chaos `slowCloseDelay`) written with nothing behind it: when the connection
    // closes. Until then `Http1PipeliningGate` answers a request sent without pipelining, as it would without the gate,
    // and holds one pipelined behind it until the close (9.2.0).
    let mut closing_at: Option<tokio::time::Instant> = None;
    // the connection's addresses as its requests record them (`localAddress`, `remoteAddress`), formatted once
    let local_address = crate::server::java_local_address(&conn);
    let remote_address = crate::server::java_socket_address(conn.client_address());
    // Netty's direct-memory limit, which only the process's environment sets
    let direct_memory = crate::config::netty_max_direct_memory(&state.config);
    'conn: loop {
        if let Some(at) = closing_at.filter(|at| !buf.is_empty() || tokio::time::Instant::now() >= *at) {
            tokio::time::sleep_until(at).await;
            log_socket_closed(&state, &conn);
            let _ = stream.shutdown().await;
            if !buf.is_empty() {
                serve_spent(state, conn, buf, secure).await;
            }
            return;
        }
        let (mut outcome, flight) = 'got: {
            // `http1PipeliningInOrder=false`: answered as they complete; nothing is read while none is buffered behind one in flight
            if !in_flight.is_empty() && !head_buffered(&buf) {
                break 'got in_flight.next().await.expect("one in flight");
            }
            let held = std::mem::take(&mut pending_held);
            let mut read_started = None;
            // the idle close, asked of the connection while it waits for a request: the stream is shut down, which a TLS
            // one precedes with its `close_notify`
            let read = {
                let closer = conn.idle.closer();
                // built only when polled, which it is only with a close pending: a timer made for every request
                // cloned the runtime's handle each time
                let closes = async {
                    match closing_at {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    read = read_head(&mut stream, &mut buf, &limits, &mut read_started) => Some(read),
                    _ = closer.requested(), if live => None,
                    _ = closes, if closing_at.is_some() => {
                        log_socket_closed(&state, &conn);
                        None
                    }
                }
            };
            let Some(read) = read else {
                let _ = stream.shutdown().await;
                return;
            };
            let head = match read {
                Ok(h) => h,
                Err(Error::Closed) => {
                    if let Some(at) = closing_at {
                        // the delayed close still runs, and logs, once the client has gone
                        tokio::time::sleep_until(at).await;
                        log_socket_closed(&state, &conn);
                    }
                    return;
                }
                Err(Error::Refused(status, message)) => {
                    refuse(&state, &conn, &mut stream, live, status, &message).await;
                    return;
                }
                Err(Error::Malformed | Error::TooLarge | Error::BadChunk(_) | Error::ChunkLine) => {
                    let reply = Reply { close: true, ..Reply::status(400) };
                    let _ = stream.write_all(&reply.encode_http1(false)).await;
                    return;
                }
            };
            // nothing is read on an event loop a runtime LLM call blocks
            state.connections.loop_free(conn.event_loop).await;
            // `HttpExchangeTracker`: from the decoded head to the last byte of its response, or until the exchange is
            // abandoned; the connection is not idle meanwhile
            let exchange = conn.idle.exchange();
            // `mock_server_request_read_to_decode_duration_seconds`, and the start of the transport duration
            let decoded = std::time::Instant::now();
            if let Some(started) = read_started.filter(|_| measured) {
                state.config.metrics.request_read_to_decode(decoded.duration_since(started).as_secs_f64());
            }
            // `EarlyMatchingHandler` sees only the connection's first request (it detaches itself after it, and passes a
            // CONNECT straight through); since b765b8271 it maps nothing either while no `respondBeforeBody` expectation
            // is registered.
            let early_matching = std::mem::take(&mut first) && !head.method.eq_ignore_ascii_case("CONNECT") && state.store.has_early_expectations();
            if early_matching && secure {
                // and so is the request's head
                crate::server::log_no_client_certificate(&state, &conn);
            }
            let mut head = head;
            // A held request that arrived whole loses its `Expect` header: the client sent the body already, so the
            // aggregator's `100 Continue` would be spurious when the gate releases it.
            if held && request::first(&head.headers, "expect").is_some() && held_request_complete(&head, &buf) {
                head.headers.retain(|(name, _)| !name.eq_ignore_ascii_case("expect"));
            }
            let expects_continue = request::first(&head.headers, "expect").is_some_and(|e| e.eq_ignore_ascii_case("100-continue"));
            // Any `Transfer-Encoding` left on a request the decoder accepted ends with `chunked`.
            let chunked = request::first(&head.headers, "transfer-encoding").is_some();
            let length = request::first(&head.headers, "content-length").and_then(|l| l.trim().parse::<usize>().ok());
            let connection = request::first(&head.headers, "connection").map(str::to_ascii_lowercase);
            let keep_alive = if head.http10 {
                connection.as_deref().is_some_and(|c| c.contains("keep-alive"))
            } else {
                !connection.as_deref().is_some_and(|c| c.contains("close"))
            };
            // `EarlyMatchingHandler`: the connection's first request may be answered from its head alone, by a
            // `respondBeforeBody` expectation; everything after it on the connection is then discarded.
            if early_matching {
                let mut headers = head.headers.clone();
                let (path, query) = split_target(&head.target, &mut headers);
                let mut early = HttpRequest {
                    method: head.method.clone(),
                    path,
                    query: query.as_deref().map(request::parse_target_query).unwrap_or_default(),
                    raw_query: query.clone(),
                    headers,
                    keep_alive,
                    secure,
                    protocol: "HTTP_1_1",
                    local_address: local_address.clone(),
                    remote_address: remote_address.clone(),
                    client_certificates: conn.client_certificates.clone(),
                    ..HttpRequest::default()
                };
                // `mapHeadersOnlyHttpRequestToMockServerRequest`: the head as it arrived, before the aggregator, so a
                // request without framing headers (a bodiless `GET`) has no `content-length` (recorded from the oracle)
                let framed = early.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("transfer-encoding"));
                handler::complete_head(&mut early);
                if !framed {
                    early.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
                }
                early.socket_address = host_socket_address(&early, conn.local.port(), secure);
                early.log_correlation_id = crate::request::new_correlation_id();
                // `firstMatchingEarlyExpectation`: a request the control plane serves never is (`isControlPlaneRequest`).
                // `EarlyMatchingHandler` checks data-plane credentials first, since the match uses up `Times` and moves
                // scenarios: without them the request falls through to the gate's 401 (upstream 6dcc66b58).
                let (found, evaluated) = if crate::cors_origin::is_control_plane_request(&early, &state.config)
                    || !crate::auth::has_data_plane_credentials_if_required(&state.config, &early)
                {
                    (None, Vec::new())
                } else {
                    state.store.first_early_match(&early, crate::namespace::of_request(&state, &early).as_deref())
                };
                crate::dataplane::log_early_evaluations(&state, &early, &evaluated);
                if let Some(found) = found {
                    let head_only = early.method.eq_ignore_ascii_case("HEAD");
                    let mut observed = handler::observe(&state, &early);
                    let outcome = handler::dispatch_early(&state, early, &trace, found).await;
                    handler::answered(&mut observed, &outcome, "HTTP_1_1");
                    match outcome {
                        Outcome::Respond(mut reply) => {
                            // `EarlyNettyResponseWriter.sendResponse`: the connection is always closed, whatever
                            // `closeSocket` says, after `connectionOptions.closeSocketDelay` when one is set; the body
                            // still arriving meanwhile is discarded.
                            reply.say_connection_closes();
                            let written = stream.write_all(&reply.encode_http1(head_only)).await.is_ok();
                            drop(observed.take());
                            if written {
                                if let Some(delay) = reply.close_delay {
                                    // `scheduler.schedule(close, false, closeSocketDelay)`: an unbounded delayed task
                                    state.overload.unbounded_delay(delay);
                                    let _ = stream.flush().await;
                                    let mut sink = vec![0u8; 8192];
                                    let drain = async {
                                        while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
                                    };
                                    let _ = tokio::time::timeout(delay, drain).await;
                                }
                                // logged at once, ahead of the linger (`LingeringClose`)
                                linger_close_then(&mut stream, || log_early_socket_closed(&state, &conn)).await;
                            }
                            return;
                        }
                        Outcome::Raw { bytes, close } => {
                            let written = stream.write_all(&bytes).await.is_ok();
                            drop(observed.take());
                            if written && close {
                                linger_close(&mut stream).await;
                                return;
                            }
                        }
                        Outcome::ResetConnection { bytes } => {
                            if let Some(bytes) = bytes {
                                let _ = stream.write_all(&bytes).await;
                                let _ = stream.flush().await;
                            }
                            drop(observed.take());
                            conn.socket.reset_on_close();
                            return;
                        }
                        Outcome::DropConnection => return,
                        _ => {}
                    }
                    let mut sink = vec![0u8; 8192];
                    while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
                    return;
                }
            }
            // `HttpObjectAggregator(maxRequestBodySize)`, read per request so a limit set at runtime applies.
            let max_body = usize::try_from(state.config.int_property("maxRequestBodySize", 10_485_760)).unwrap_or(usize::MAX);
            if let Some(length) = length.filter(|l| !chunked && *l > max_body) {
                if expects_continue {
                    // `newContinueResponse`: the client is told not to send the body.
                    if stream.write_all(TOO_LARGE_EXPECTATION).await.is_err() {
                        return;
                    }
                    continue 'conn;
                }
                // The announced body is discarded; without keep-alive the connection is closed, with a lingering close
                // (upstream fix 01c7517d2, after 8.0.0: the 8.0.0 oracle closes at once and the client gets a reset).
                // A held request is refused with a closing 413 whatever it asked (9.2.0, #84): what follows it on the
                // connection is not answered.
                if !keep_alive || held {
                    if stream.write_all(TOO_LARGE_CLOSE).await.is_ok() {
                        linger_close(&mut stream).await;
                    }
                    return;
                }
                if stream.write_all(TOO_LARGE).await.is_err() || discard(&mut stream, &mut buf, length).await.is_err() {
                    return;
                }
                continue 'conn;
            }
            if expects_continue && (chunked || length.is_some_and(|l| l > 0)) && stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await.is_err() {
                return;
            }
            let mut headers = head.headers;
            let (path, query) = split_target(&head.target, &mut headers);
            // What the aggregator holds of a request whose connection ends before its body is complete
            // (`Http1RequestCutShort`): the head as read.
            let cut_short = |state: &State| {
                let held = HttpRequest {
                    method: head.method.clone(),
                    path: path.clone(),
                    query: query.as_deref().map(request::parse_target_query).unwrap_or_default(),
                    raw_query: query.clone(),
                    headers: headers.clone(),
                    ..HttpRequest::default()
                };
                handler::http1_decode_failed(state, &handler::DecodeFailure::cut_short(), &held, socket_address_arg(conn.remote));
            };
            let body = if chunked {
                match read_chunked(&mut stream, &mut buf, max_body).await {
                    Ok(b) => b,
                    Err(Error::BadChunk(message)) => {
                        // The decoder fails the content: refused like an unreadable head.
                        refuse(&state, &conn, &mut stream, live, 400, &message).await;
                        return;
                    }
                    Err(Error::ChunkLine) => {
                        // `HttpChunkLineLimiter.rejectChunkLine`
                        let entry = crate::recorded::LogEntry::at(
                            crate::recorded::Level::Warn,
                            "closing connection from:{}because a chunk-size line (with its chunk extensions) or trailer section in a chunked request body is longer than 8192 bytes",
                        )
                        .args([socket_address_arg(conn.remote)]);
                        refuse_logged(&state, &mut stream, live, 400, entry).await;
                        return;
                    }
                    Err(Error::TooLarge) => {
                        // The rest of the body cannot be told from the next request: closed, lingering (01c7517d2).
                        if stream.write_all(TOO_LARGE_CLOSE).await.is_ok() {
                            linger_close(&mut stream).await;
                        }
                        return;
                    }
                    Err(Error::Closed) => {
                        cut_short(&state);
                        return;
                    }
                    Err(_) => return,
                }
            } else {
                match read_exact(&mut stream, &mut buf, length.unwrap_or(0)).await {
                    Ok(b) => b,
                    Err(Error::Closed) => {
                        cut_short(&state);
                        return;
                    }
                    Err(_) => return,
                }
            };

            // every field given: a default request's empty certificate chain is an allocation of its own
            let mut http_request = HttpRequest {
                method: head.method,
                path,
                path_parameters: MultiMap::new(),
                query: query.as_deref().map(request::parse_target_query).unwrap_or_default(),
                raw_query: query,
                headers,
                cookies: Vec::new(),
                body,
                original_body: None,
                body_kind: request::BodyKind::default(),
                empty_body_given: false,
                keep_alive,
                keep_alive_null: false,
                secure,
                protocol: "HTTP_1_1",
                local_address: local_address.clone(),
                remote_address: remote_address.clone(),
                client_certificates: conn.client_certificates.clone(),
                remote_target: conn.proxy_target.clone(),
                socket_address: None,
                log_correlation_id: String::new(),
                trusted: false,
            };
            // Netty's direct-memory limit (`io.netty.maxDirectMemory`): the aggregator's buffers outgrow it, the
            // pool's ERROR is logged, the request is reported cut short and the connection closes without an answer.
            if let Some((used, max)) = direct_memory.and_then(|max| crate::client::request_direct_memory_refusal(http_request.body.len(), max)) {
                let channel = crate::server::channel_description(&conn);
                let reached = format!("direct memory limit (io.netty.maxDirectMemory) reached - raise it with -XX:MaxDirectMemorySize or -Dio.netty.maxDirectMemory - closing connection {channel} - failed to allocate 65536 byte(s) of direct memory (used: {used}, max: {max})");
                crate::log::error_event(&state, crate::recorded::LogEntry::at(crate::recorded::Level::Error, reached));
                handler::http1_decode_failed(&state, &handler::DecodeFailure::cut_short(), &http_request, socket_address_arg(conn.remote));
                return;
            }
            if let Err(failure) = handler::complete(&mut http_request, max_body) {
                if failure.too_large() {
                    // Longer than `maxRequestBodySize` once decoded: refused, closed (lingering, 01c7517d2).
                    if stream.write_all(TOO_LARGE_CLOSE).await.is_ok() {
                        linger_close(&mut stream).await;
                    }
                    return;
                }
                // The decompressor failed the body: nothing is answered and the connection is closed.
                handler::http1_decode_failed(&state, &failure, &http_request, socket_address_arg(conn.remote));
                return;
            }
            if http_request.method == "CONNECT" {
                // `HttpRequestHandler`: CONNECT is answered here, never matched or recorded.
                if let Some(mut reply) = crate::auth::proxy_rejection(&state.config, &http_request) {
                    let logged = serde_json::json!({
                        "statusCode": 407,
                        "headers": {"proxy-authenticate": [reply.header("proxy-authenticate").unwrap_or_default()]},
                    });
                    // The oracle's 407 to a CONNECT carries no `connection` header at all (confirmed against the
                    // oracle, scenario auth_proxy): a proxy tunnel negotiation failure, not an ordinary keep-alive
                    // response.
                    reply.suppress_connection_header = true;
                    let reply = reply.finalize(&http_request, &state.config);
                    if state.info_enabled() {
                        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::AuthenticationFailed, "proxy authentication failed so returning response:{}for forwarded request:{}")
                            .request(&http_request)
                            .response(logged.clone())
                            .expectation(serde_json::json!({"httpRequest": crate::recorded::logged(&http_request), "httpResponse": logged.clone()}))
                            .args([crate::recorded::Arg::from(&logged), crate::recorded::logged(&http_request).into()]);
                        state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(http_request.clone())));
                    }
                    if stream.write_all(&reply.encode_http1(false)).await.is_err() || reply.close {
                        return;
                    }
                    continue 'conn;
                }
                // A port-less CONNECT target defaults to 443, CONNECT being historically an HTTPS tunnel; the tunnelled
                // protocol itself is decided by its first bytes (`server::serve_tunnel`).
                let (host, port) = connect_target(&http_request.path);
                // `RelayConnectHandler` dials the server itself for the tunnel's loopback leg; refused by
                // `maxInboundConnections`, it fails the CONNECT (`HttpConnectHandler.failureResponse`) and the connection
                let Some(loopback_leg) = state.connections.loopback_leg(&state, conn.remote) else {
                    let mut reply = Reply::status(502);
                    reply.suppress_connection_header = true;
                    let reply = reply.finalize(&http_request, &state.config);
                    if stream.write_all(&reply.encode_http1(false)).await.is_ok() {
                        let _ = stream.shutdown().await;
                    }
                    return;
                };
                if let Some(tls) = state.tls.as_ref() {
                    tls.add_subject_alternative_name(&host);
                }
                // `HttpConnectHandler.successResponse` is written by the relay, not `HttpRequestHandler`: no `connection`
                // header (seen on the 8.0.0 oracle, scenario connect_cleartext_tunnel).
                let mut reply = Reply::status(200);
                reply.suppress_connection_header = true;
                let reply = reply.finalize(&http_request, &state.config);
                if stream.write_all(&reply.encode_http1(false)).await.is_err() {
                    return;
                }
                let io = crate::rewind::Rewind { prefix: std::mem::take(&mut buf), inner: stream };
                let tunnel = Connection { proxy_target: Some((host, port)), event_loop: loopback_leg.event_loop, ..conn };
                // the tunnel's own exchanges are tracked as they come; the CONNECT's has ended
                drop(exchange);
                crate::server::serve_tunnel(state.clone(), tunnel, Box::new(io), secure).await;
                drop(loopback_leg);
                return;
            }
            if crate::dashboard::is_channel(&http_request) {
                let io = crate::rewind::Rewind { prefix: std::mem::take(&mut buf), inner: stream };
                conn.write_stall.set(crate::write_stall::Protocol::WebSocket);
                conn.idle.long_lived();
                crate::dashboard::serve(state.clone(), &http_request, io).await;
                return;
            }
            if crate::callback::is_upgrade(&http_request) {
                let mut io = crate::rewind::Rewind { prefix: std::mem::take(&mut buf), inner: stream };
                // `ControlPlaneWebSocketUpgradeGate.admitUpgrade(…, "callback")`: the origin first
                if !crate::cors_origin::upgrade_origin_allowed(&state, &http_request, "callback", &mut io).await {
                    return;
                }
                // then control-plane authentication, which names the caller for a client-id takeover
                // the gate maps the upgrade with the local port (`FullHttpRequestToMockServerHttpRequest`), so the request its
                // log entries show has a socket address
                let gated = HttpRequest { socket_address: host_socket_address(&http_request, conn.local.port(), secure), ..http_request.clone() };
                let Some(identity) = crate::auth::upgrade_authenticated(&state, &gated, "callback", &mut io).await else {
                    return;
                };
                conn.write_stall.set(crate::write_stall::Protocol::WebSocket);
                conn.idle.long_lived();
                // `WebSocketClientRegistry.unregisterClient`: the client's breakpoints go with it, unless its id is
                // registered to another connection by then.
                if let Some(client_id) = state.callbacks.serve(&state, &http_request, io, identity).await {
                    state.breakpoints.remove_client(&client_id);
                }
                return;
            }
            let head_only = http_request.method.eq_ignore_ascii_case("HEAD");
            // inside a CONNECT or SOCKS tunnel the loopback leg reads each response back, decoding its coding
            let tunnel = !head_only && conn.write_stall.get() == crate::write_stall::Protocol::Tunnel;
            let stream_intent = tunnel && handler::loopback_stream_intent(&http_request);
            // observed until this iteration ends, once the response is written (or the client gives up on a hang)
            let observed = handler::observe(&state, &http_request);
            // `Http1PipeliningGate`: another request is already waiting behind this one
            let held_behind = head_buffered(&buf);
            pending_held = held_behind && !out_of_order;
            if out_of_order {
                // `http1PipeliningInOrder=false`: no gate; each request is handled as it arrives, and answered as it completes
                let (trace_flight, state_flight) = (trace.clone(), state.clone());
                let flight = Flight { head_only, tunnel, stream_intent, observed, exchange, decoded };
                in_flight.push(Box::pin(async move { (handler::dispatch_detached(&state_flight, http_request, &trace_flight).await, flight) }));
                continue 'conn;
            }
            // handled on the connection's task, its deep, rarely taken branches boxed where they are entered ([`crate::boxed`])
            let outcome = if held_behind {
                tokio::select! {
                    outcome = handler::dispatch(&state, http_request, &trace) => outcome,
                    _ = wedge_backstop(&state, conn.event_loop) => {
                        // the held requests wait behind a response that makes no progress: the connection is closed, and
                        // `Http1PipeliningGate.channelInactive` then hands what it holds on, as a decoder's `decodeLast`:
                        // the held requests are handled (and logged) on the closed connection (9.2.0)
                        let _ = stream.shutdown().await;
                        drop(exchange);
                        if !buf.is_empty() {
                            serve_spent(state, conn, buf, secure).await;
                        }
                        return;
                    }
                }
            } else {
                // pinned where it is built: awaiting it by value moved the whole future (14 KiB) once per request
                std::pin::pin!(handler::dispatch(&state, http_request, &trace)).await
            };
            (outcome, Flight { head_only, tunnel, stream_intent, observed, exchange, decoded })
        };
        let Flight { head_only, tunnel, stream_intent, mut observed, exchange, decoded } = flight;
        let transported = || {
            if measured {
                state.config.metrics.request_transport(decoded.elapsed().as_secs_f64());
            }
        };
        // a response is written on the connection's event loop, once a runtime LLM call no longer blocks it
        state.connections.loop_free(conn.event_loop).await;
        handler::answered(&mut observed, &outcome, "HTTP_1_1");
        // HTTP/1.1 has no GOAWAY.
        while let Outcome::GoAway { then, .. } = outcome {
            outcome = *then;
        }
        if tunnel {
            outcome = match loopback_streamed(&state, outcome, stream_intent) {
                Ok(outcome) => outcome,
                Err(streamed) => {
                    let close = streamed.0.close;
                    // boxed: the HTTP/1.1 loop's future is deep already
                    if Box::pin(relay_decoded(&mut stream, &conn, streamed)).await {
                        transported();
                        if !close {
                            continue;
                        }
                    }
                    let _ = stream.shutdown().await;
                    return;
                }
            };
        }
        match outcome {
            Outcome::GoAway { .. } => unreachable!("unwrapped above"),
            Outcome::Respond(reply) if reply.has_unencodable_header() => {
                let _ = stream.write_all(&reply.status_line_only()).await;
                let mut sink = vec![0u8; 4096];
                while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
                return;
            }
            Outcome::Respond(reply) => {
                let reply = if tunnel {
                    let max = usize::try_from(state.config.int_property("maxRequestBodySize", 10_485_760)).unwrap_or(usize::MAX);
                    Box::new(handler::loopback_decoded(*reply, max).unwrap_or_else(|()| handler::loopback_failure()))
                } else {
                    reply
                };
                if stream.write_all(&reply.encode_http1(head_only)).await.is_err() {
                    // `ReadAfterFailedWrite` (after 8.0.0): the output has ended, not the connection, which is read on
                    // to the end of its input (`crate::write_stall::WriteStallIo`)
                    continue;
                }
                transported();
                if reply.status == 101 {
                    // `HttpExchangeTracker.write`: any `101 Switching Protocols` written makes the connection
                    // long-lived, directly or on a tunnel's client leg
                    conn.idle.long_lived();
                }
                if reply.reset_connection {
                    // `forceReset`: SO_LINGER 0, then close, so the client sees a RST rather than a FIN.
                    let _ = stream.flush().await;
                    conn.socket.reset_on_close();
                    return;
                }
                if reply.close {
                    // written: the close and the requests pipelined behind it are not this request's
                    drop(observed.take());
                    if let Some(delay) = reply.close_delay {
                        // `scheduler.schedule(close, false, closeSocketDelay)`: an unbounded delayed task
                        state.overload.unbounded_delay(delay);
                        let _ = stream.flush().await;
                        if live && buf.is_empty() && closing_at.is_none() {
                            // nothing pipelined behind it: the connection serves what is sent meanwhile until the close
                            closing_at = Some(tokio::time::Instant::now() + delay);
                            continue 'conn;
                        }
                        tokio::time::sleep(delay).await;
                    }
                    // logged before the close, so the entry is in the log once the client sees the connection end
                    log_socket_closed(&state, &conn);
                    let _ = stream.shutdown().await;
                    if !buf.is_empty() {
                        serve_spent(state, conn, buf, secure).await;
                    }
                    return;
                }
            }
            Outcome::Raw { bytes, close } => {
                if stream.write_all(&bytes).await.is_err() {
                    return;
                }
                transported();
                if close {
                    return;
                }
            }
            Outcome::ResetConnection { bytes } => {
                if let Some(bytes) = bytes {
                    if stream.write_all(&bytes).await.is_err() {
                        return;
                    }
                    transported();
                    let _ = stream.flush().await;
                }
                // `ConnectionReset.reset`: SO_LINGER 0 and no `close_notify`, so the client (a tunnel's client leg too: the
                // tunnel is served on the client's own socket) sees a RST
                conn.socket.reset_on_close();
                return;
            }
            Outcome::DropConnection | Outcome::Reset(_) => return,
            Outcome::Stream { head, mut chunks, close, trailers, cut, upstream_end, .. } if head_only => {
                // A HEAD response is its head alone: Netty's `HttpObjectEncoder` writes no content after a head to HEAD
                // (as the 8.0.0 oracle does), so the chunks and trailers produced after it are discarded and the
                // producer runs to completion before the next request on the connection is read.
                if stream.write_all(&head.encode_http1(true)).await.is_err() || stream.flush().await.is_err() {
                    return;
                }
                while chunks.recv().await.is_some() {}
                if let Some(trailers) = trailers {
                    let _ = trailers.await;
                }
                if close || cut.is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst)) || upstream_end.is_some_and(|e| e.is_aborted()) {
                    let _ = stream.shutdown().await;
                    return;
                }
            }
            Outcome::Stream { head, mut chunks, close, trailers, cut, upstream_end, chunk_count } => {
                // Chunked framing, each chunk flushed as it is produced.
                if stream.write_all(&head.encode_http1(true)).await.is_err() || stream.flush().await.is_err() {
                    return;
                }
                while let Some(chunk) = chunks.recv().await {
                    if chunk.is_empty() {
                        continue;
                    }
                    let mut framed = format!("{:x}\r\n", chunk.len()).into_bytes();
                    framed.extend_from_slice(&chunk);
                    framed.extend_from_slice(b"\r\n");
                    if stream.write_all(&framed).await.is_err() || stream.flush().await.is_err() || conn.write_stall.output_ended() {
                        // the client has gone: the producer is dropped with its receiver, and a forward's upstream
                        // with it, rather than run to its end (`StreamedResponseAbandonIntegrationTest`)
                        let _ = stream.shutdown().await;
                        return;
                    }
                }
                if upstream_end.is_some_and(|e| e.is_aborted()) {
                    // An aborted forward ends without the terminating chunk, so the client sees an incomplete response.
                    let _ = stream.shutdown().await;
                    return;
                }
                let mut end = b"0\r\n".to_vec();
                if let Some(trailers) = trailers {
                    for (name, value) in trailers.await.unwrap_or_default() {
                        end.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
                    }
                }
                end.extend_from_slice(b"\r\n");
                let cut = cut.is_some_and(|c| c.load(std::sync::atomic::Ordering::SeqCst));
                let failed = stream.write_all(&end).await.is_err() || stream.flush().await.is_err();
                if !failed {
                    transported();
                }
                if failed || close || cut {
                    // a `chunkDelay` response (`writeChunkedResponseWithDelay`) closes as an ordinary one does
                    if close && !failed && chunk_count.is_some() {
                        log_socket_closed(&state, &conn);
                    }
                    let _ = stream.shutdown().await;
                    return;
                }
            }
            Outcome::WebSocket { request, .. } if crate::ws_mock::unsupported_version(&request) => {
                // no handshaker for the version: a 426, and the connection stays HTTP
                if stream.write_all(crate::ws_mock::UNSUPPORTED_VERSION).await.is_err() {
                    return;
                }
                transported();
            }
            Outcome::WebSocket { request, response } => {
                let io = crate::rewind::Rewind { prefix: std::mem::take(&mut buf), inner: stream };
                conn.write_stall.set(crate::write_stall::Protocol::WebSocket);
                conn.idle.long_lived();
                crate::ws_mock::serve(state.clone(), *request, *response, io, conn.write_stall.clone(), conn.sni.clone()).await;
                return;
            }
            Outcome::WebSocketRelay { request, host, port, tls, guarded } => {
                let io = crate::rewind::Rewind { prefix: std::mem::take(&mut buf), inner: stream };
                conn.write_stall.set(crate::write_stall::Protocol::WebSocket);
                conn.idle.long_lived();
                crate::ws_relay::relay(state.clone(), *request, io, host, port, tls, guarded).await;
                return;
            }
            Outcome::Hang => {
                // Nothing is written and the connection stays open: the exchange is abandoned
                // (`HttpExchangeEndedEvent`), so the connection can now be closed as idle, and the requests pipelined
                // behind it or sent later are still answered.
                drop(exchange);
            }
        }
    }
}

/// A response the tunnel's loopback relays as it reads it and decodes on the way (`handler::LoopbackDecoder`): its head
/// as relayed, the decoder, and its body, whole or as the chunks still to come. A response the loopback aggregates, or
/// one in a coding it leaves alone, is the outcome as it was.
type LoopbackStream = (Reply, handler::LoopbackDecoder, Bytes, Option<tokio::sync::mpsc::Receiver<Bytes>>);

fn loopback_streamed(state: &State, outcome: Outcome, intent: bool) -> Result<Outcome, Box<LoopbackStream>> {
    match outcome {
        Outcome::Respond(reply) if !reply.body.is_empty() && handler::loopback_streams(state, &reply.headers, intent) => {
            let mut head = reply;
            match handler::LoopbackDecoder::for_head(state, &mut head.headers) {
                Ok(Some(decoder)) => {
                    let body = std::mem::take(&mut head.body);
                    Err(Box::new((*head, decoder, body, None)))
                }
                Ok(None) => Ok(Outcome::Respond(head)),
                Err(()) => Ok(Outcome::respond(handler::loopback_failure())),
            }
        }
        Outcome::Stream { head, chunks, close, trailers, cut, upstream_end, chunk_count } if handler::loopback_streams(state, &head.headers, intent) => {
            let mut edited = head.clone();
            match handler::LoopbackDecoder::for_head(state, &mut edited.headers) {
                Ok(Some(decoder)) => {
                    edited.close |= close;
                    Err(Box::new((*edited, decoder, Bytes::new(), Some(chunks))))
                }
                _ => Ok(Outcome::Stream { head, chunks, close, trailers, cut, upstream_end, chunk_count }),
            }
        }
        outcome => Ok(outcome),
    }
}

/// Writes a [`LoopbackStream`] chunked, each decoded piece a chunk; `false` when it was aborted (a decode failure, a
/// content decoded past the bound, or the client gone) before its terminating chunk, and the connection must close
/// (`LoopbackHttp1ResponseErrorHandler`: the head has gone, so the only signal left is an incomplete response).
async fn relay_decoded<S: AsyncWrite + Unpin>(stream: &mut S, conn: &Connection, head: Box<LoopbackStream>) -> bool {
    let (head, mut decoder, body, mut chunks) = *head;
    if stream.write_all(&head.encode_http1(true)).await.is_err() || stream.flush().await.is_err() {
        return false;
    }
    let mut next = Some(body);
    loop {
        let input = match next.take() {
            Some(input) => input,
            None => match chunks.as_mut() {
                Some(chunks) => match chunks.recv().await {
                    Some(chunk) => chunk,
                    None => break,
                },
                None => break,
            },
        };
        let Ok(pieces) = decoder.push(&input) else { return false };
        for piece in pieces {
            let mut framed = format!("{:x}\r\n", piece.len()).into_bytes();
            framed.extend_from_slice(&piece);
            framed.extend_from_slice(b"\r\n");
            if stream.write_all(&framed).await.is_err() || stream.flush().await.is_err() || conn.write_stall.output_ended() {
                return false;
            }
        }
    }
    stream.write_all(b"0\r\n\r\n").await.is_ok() && stream.flush().await.is_ok()
}

/// `NettyResponseWriter.disconnectAndCloseChannel`, at TRACE: the socket closed after a response that closes the
/// connection (`closeSocket`, or a request without keep-alive), named by its local address.
fn log_socket_closed(state: &State, conn: &Connection) {
    if state.log_level != "TRACE" {
        return;
    }
    let local = crate::server::java_local_address(conn);
    let local = if conn.local_name.is_some() { local } else { format!("/{local}") };
    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Trace, format!("disconnected and closed socket {local}"));
    crate::log::entry(state, &entry);
    state.log.message(entry);
}

/// `EarlyNettyResponseWriter.disconnectAndCloseChannel`, at TRACE: `closing socket {} after early response`, the
/// local address as its argument.
fn log_early_socket_closed(state: &State, conn: &Connection) {
    if state.log_level != "TRACE" {
        return;
    }
    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Trace, "closing socket {} after early response").args([socket_address_arg(conn.local)]);
    crate::log::entry(state, &entry);
    state.log.message(entry);
}

/// `withSocketAddress(isSecure, host, port)`: the `Host` header's name with the local port.
pub(crate) fn host_socket_address(request: &HttpRequest, port: u16, secure: bool) -> Option<(String, u16, bool)> {
    request.first_header("host").filter(|h| !h.trim().is_empty()).map(|h| {
        let name = if let Some(bracketed) = h.strip_prefix('[') { bracketed.split(']').next().unwrap_or_default() } else { h.split(':').next().unwrap_or_default() };
        (name.to_string(), port, secure)
    })
}

/// A connection's socket address as a log argument: `InetSocketAddress.toString` (`/ip:port`) in the text, Jackson's
/// `ip:port` (IPv6 in brackets) in the entry's JSON.
pub(crate) fn socket_address_arg(address: std::net::SocketAddr) -> crate::recorded::Arg {
    let dashboard = crate::server::java_socket_address(address);
    crate::recorded::Arg::inet_socket_address(format!("/{dashboard}"), dashboard)
}

/// `HttpChunkLineLimiter.rejectUndecodable`: a request Netty's decoder could not read is never dispatched. It is
/// logged (WARN), answered with `status` and `connection: close`, and the connection is closed
/// `CLOSE_DELAY_MILLIS` later, what arrives meanwhile read and dropped so the close does not reset the connection
/// before the client reads the answer. A connection already closed ([`serve_spent`]) is not answered, and its entry is
/// at DEBUG, which the log leaves out.
async fn refuse<S: AsyncRead + AsyncWrite + Unpin>(state: &State, conn: &Connection, stream: &mut S, live: bool, status: u16, message: &str) {
    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "closing connection from:{}with status:{}because its request could not be decoded:{}")
        .args([socket_address_arg(conn.remote),serde_json::json!(status).into(), message.into()]);
    refuse_logged(state, stream, live, status, entry).await;
}

/// `HttpChunkLineLimiter.reject` after its WARN `entry`: `status` with `connection: close`, then the connection is read
/// and dropped for a moment before it is closed.
async fn refuse_logged<S: AsyncRead + AsyncWrite + Unpin>(state: &State, stream: &mut S, live: bool, status: u16, entry: crate::recorded::LogEntry) {
    if !live {
        return;
    }
    crate::log::warn_event(state, entry);
    let reason = match status {
        414 => "Request-URI Too Long",
        431 => "Request Header Fields Too Large",
        _ => "Bad Request",
    };
    let response = format!("HTTP/1.1 {status} {reason}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
    if stream.write_all(response.as_bytes()).await.is_err() || stream.flush().await.is_err() {
        return;
    }
    // On the heap, as every drain buffer here: a buffer in a future is stack in each frame that builds or polls it,
    // and the connection's task already runs a whole forward (TLS handshake included) on one worker stack.
    let mut sink = vec![0u8; 8192];
    let drain = async {
        while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
    };
    let _ = tokio::time::timeout(REFUSAL_CLOSE_DELAY, drain).await;
}

/// `HttpChunkLineLimiter.CLOSE_DELAY_MILLIS`.
const REFUSAL_CLOSE_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// How long a connection whose request body is still arriving keeps reading after its response (`linger_close`):
/// `LingeringClose.LINGER_MILLIS`.
const LINGER: std::time::Duration = std::time::Duration::from_secs(5);

/// Closes a connection whose request body is still arriving (after an early `respondBeforeBody` response, or a 413
/// that ends the connection): half-closes it (after a TLS `close_notify`), then reads and discards until the client
/// closes its side or `LINGER` passes. Closing a socket with received bytes unread makes the kernel send a RST, and a
/// client that has not yet read the response then loses it or reads `Connection reset` instead of the end of stream
///. Upstream's `LingeringClose` (fixes 88e72ebc7 and 01c7517d2, after 8.0.0); the 8.0.0 oracle closes
/// at once.
async fn linger_close<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
    linger_close_then(stream, || {}).await;
}

/// [`linger_close`], calling `closed` just before the connection is half-closed (so the client, seeing the close,
/// finds what it logs), ahead of the linger.
async fn linger_close_then<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, closed: impl FnOnce()) {
    closed();
    if stream.shutdown().await.is_err() {
        return;
    }
    let mut sink = vec![0u8; 8192];
    let drain = async {
        while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
    };
    let _ = tokio::time::timeout(LINGER, drain).await;
}

/// `HttpRequest.splitHostPort` of a CONNECT target (`host:port`, `[v6]:port`), 443 when no port is given.
fn connect_target(authority: &str) -> (String, u16) {
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !authority.ends_with(']') && (h.starts_with('[') || !h.contains(':')) => (h, p.parse().unwrap_or(443)),
        _ => (authority, 443),
    };
    (host.trim_start_matches('[').trim_end_matches(']').to_string(), port)
}

/// The path (`URLParser.returnPath`) and the raw query of a request target; absolute-form (proxy) targets also supply
/// a missing `Host`.
fn split_target(target: &str, headers: &mut MultiMap) -> (String, Option<String>) {
    if let Some(after_scheme) = target.strip_prefix("http://").or_else(|| target.strip_prefix("https://")) {
        let authority = &after_scheme[..after_scheme.find(['/', '?']).unwrap_or(after_scheme.len())];
        if request::first(headers, "host").is_none() {
            headers.insert(0, ("Host".into(), vec![authority.to_string()]));
        }
    }
    let query = target.split_once('?').map(|(_, q)| q.to_string());
    let path = return_path(target);
    (path.split('?').next().unwrap_or_default().to_string(), query)
}

/// `URLParser.returnPath` before its cut at `?`: for a full URL (`http://` or `https://`, a request line holds no line
/// terminator), every match of `https?://([A-Za-z0-9-_.:]*@)?[A-Za-z0-9-_.]*(:[0-9]*)?` removed; an empty result
/// is an empty path, which the received request shows without one..
fn return_path(target: &str) -> String {
    if !(target.starts_with("http://") || target.starts_with("https://")) {
        return target.to_string();
    }
    let host = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.');
    let bytes = target.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let mut copied = 0;
    while i < bytes.len() {
        let scheme = if bytes[i..].starts_with(b"http://") {
            7
        } else if bytes[i..].starts_with(b"https://") {
            8
        } else {
            i += 1;
            continue;
        };
        let mut end = i + scheme;
        let user = bytes[end..].iter().take_while(|&&c| host(c) || c == b':').count();
        if bytes.get(end + user) == Some(&b'@') {
            end += user + 1;
        }
        end += bytes[end..].iter().take_while(|&&c| host(c)).count();
        if bytes.get(end) == Some(&b':') {
            end += 1 + bytes[end + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
        }
        out.push_str(&target[copied..i]);
        copied = end;
        i = end;
    }
    out.push_str(&target[copied..]);
    out
}

async fn fill<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut BytesMut) -> Result<(), Error> {
    buf.reserve(16 * 1024);
    match stream.read_buf(buf).await {
        Ok(0) | Err(_) => Err(Error::Closed),
        Ok(_) => Ok(()),
    }
}

/// `read_started` is set to when the head's first bytes were read (`buf` holding some already counts as now).
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut BytesMut, limits: &Limits, read_started: &mut Option<std::time::Instant>) -> Result<Head, Error> {
    loop {
        if read_started.is_none() && !buf.is_empty() {
            *read_started = Some(std::time::Instant::now());
        }
        // `SKIP_INITIAL_LINE_CHARS` with strict line parsing: CR and LF bytes before a request line are skipped.
        let skip = buf.iter().take_while(|b| matches!(b, b'\r' | b'\n')).count();
        buf.advance(skip);
        if !buf.is_empty() {
            // `HttpChunkLineLimiter`: whatever the decoder failed on is refused; the rest of what was read is dropped.
            if let Some(refusal) = limit_fault(buf, limits) {
                buf.clear();
                return Err(refusal);
            }
            if let Some(head) = strict_line_fault(buf) {
                buf.clear();
                return Err(Error::Refused(400, head.decode_error.unwrap_or_else(|| LINE_SEPARATOR.into())));
            }
            match parse_head(buf) {
                Ok(Some((head, len))) => {
                    if let Some(message) = content_length_fault(&head) {
                        buf.clear();
                        return Err(Error::Refused(400, message));
                    }
                    buf.advance(len);
                    return Ok(head);
                }
                Ok(None) => {}
                Err(()) => {
                    // `httparse` is stricter than Netty's decoder: once the head is complete, read it as Netty does.
                    if let Some(end) = head_end(buf) {
                        let head = netty_head(&buf[..end]);
                        if let Some(message) = head.decode_error {
                            buf.clear();
                            return Err(Error::Refused(400, message));
                        }
                        buf.advance(end);
                        return Ok(head);
                    }
                }
            }
            if buf.len() > MAX_HEAD {
                return Err(Error::Malformed);
            }
        }
        fill(stream, buf).await?;
    }
}

/// `httparse`'s reading of the head at the start of `buf`: the head and its length, `None` while it is incomplete,
/// `Err` for one it rejects. Up to 128 headers are parsed into an array on this call's stack, more (up to 8,192) into
/// one on the heap; kept out of line, so the array is not part of the caller's frame.
#[inline(never)]
fn parse_head(buf: &[u8]) -> Result<Option<(Head, usize)>, ()> {
    const ON_STACK: usize = 128;
    // left uninitialised: httparse writes the headers it parses, and filling 4 KiB of empty ones cost every request
    let mut stack = [const { std::mem::MaybeUninit::<httparse::Header<'_>>::uninit() }; ON_STACK];
    let mut heap: Vec<std::mem::MaybeUninit<httparse::Header<'_>>>;
    let mut capacity = ON_STACK;
    loop {
        let headers: &mut [std::mem::MaybeUninit<httparse::Header<'_>>] = if capacity == ON_STACK {
            &mut stack
        } else {
            heap = std::iter::repeat_with(std::mem::MaybeUninit::uninit).take(capacity).collect();
            &mut heap
        };
        let mut req = httparse::Request::new(&mut []);
        match req.parse_with_uninit_headers(buf, headers) {
            Ok(httparse::Status::Complete(len)) => {
                // with room for the `content-length` the aggregator adds
                let mut map = MultiMap::with_capacity(req.headers.len() + 1);
                for h in req.headers.iter() {
                    request::append(&mut map, h.name, request::header_text(h.value));
                }
                let head = Head {
                    method: req.method.unwrap_or("GET").to_string(),
                    target: req.path.unwrap_or("/").to_string(),
                    http10: req.version == Some(0),
                    http11: req.version == Some(1),
                    headers: map,
                    decode_error: None,
                };
                return Ok(Some((head, len)));
            }
            Ok(httparse::Status::Partial) => return Ok(None),
            Err(httparse::Error::TooManyHeaders) if capacity < 8192 => capacity *= 4,
            Err(_) => return Err(()),
        }
    }
}

/// The end of the first head in `buf` (past its blank line), if it is complete.
fn head_end(buf: &[u8]) -> Option<usize> {
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Netty's `HttpObjectDecoder` on a head `httparse` rejected. A request line that does not split into method, target
/// and a `name/major.minor` version, or a header line it cannot accept, fails the decoder (`decode_error`). Anything
/// it does accept (several spaces, any version number) is an ordinary request.
fn netty_head(raw: &[u8]) -> Head {
    let mut head = netty_lines(raw);
    if head.decode_error.is_none() {
        head.decode_error = content_length_fault(&head);
    }
    head
}

/// `netty_head` without the checks `readHeaders` makes once every header is read.
fn netty_lines(raw: &[u8]) -> Head {
    let text = request::header_text(raw);
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let line = lines.next().unwrap_or_default();
    let invalid = netty_invalid;
    // `splitInitialLine`: three whitespace-separated parts, the last one running to the end of the line.
    let mut rest = line.trim_start();
    let mut token = |last: bool| -> Option<String> {
        if rest.is_empty() {
            return None;
        }
        if last {
            let all = rest.trim_end().to_string();
            rest = "";
            return Some(all);
        }
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let (word, tail) = rest.split_at(end);
        rest = tail.trim_start();
        Some(word.to_string())
    };
    let (Some(method), Some(target)) = (token(false), token(false)) else {
        return invalid("text is empty (possibly HTTP/0.9)".into());
    };
    let Some(version) = token(true).filter(|v| !v.is_empty()) else {
        return invalid("text is empty (possibly HTTP/0.9)".into());
    };
    let version = version.to_uppercase();
    let numbers = |v: &str| v.split_once('.').is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && a.bytes().all(|c| c.is_ascii_digit()) && b.bytes().all(|c| c.is_ascii_digit()));
    if !version.rsplit_once('/').is_some_and(|(name, digits)| !name.is_empty() && !name.contains(char::is_whitespace) && numbers(digits)) {
        return invalid(format!("invalid version format: {version}"));
    }
    let mut head = Head {
        method,
        target,
        http10: version == "HTTP/1.0",
        http11: version == "HTTP/1.1",
        headers: MultiMap::new(),
        decode_error: None,
    };
    let mut last: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        // A line starting with SP or HT is folded into the header before it; with none, `splitHeader` reads it.
        if last.is_some() && line.starts_with([' ', '\t']) {
            if let Some((_, values)) = last.as_ref().and_then(|name| head.headers.iter_mut().find(|(k, _)| k == name)) && let Some(value) = values.last_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            head.decode_error = Some("No colon found".into());
            break;
        };
        let bad_name = name.char_indices().find(|(_, c)| !(c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(*c)));
        if let Some((index, c)) = bad_name {
            head.decode_error = Some(format!("a header name can only contain \"token\" characters, but found invalid character 0x{:02x} at index {index} of header '{name}'.", c as u32));
            break;
        }
        let value = value.trim_matches([' ', '\t']);
        if value.chars().any(|c| (c < ' ' && c != '\t') || c == '\u{7f}') {
            head.decode_error = Some(format!("Validation failed for header '{name}'"));
            break;
        }
        request::append(&mut head.headers, name, value.to_string());
        last = Some(name.to_string());
    }
    head
}

/// `InvalidLineSeparatorException`'s message.
const LINE_SEPARATOR: &str = "Line Feed must be preceded by Carriage Return when terminating HTTP start- and header field-lines";

/// Netty 4.2's strict line parsing (`HttpDecoderConfig.isStrictLineParsing`, on by default) over a head whose leading
/// CR and LF bytes are skipped: a request starting with an ISO control character, or a line (the blank one too)
/// ended by a bare LF, fails the decoder. The failure is the first one Netty meets: a fault in a header line already
/// read wins, as does the `No colon found` of the header line still pending when the bare-LF line was read (Netty
/// splits a header line as it reads it, and adds and validates it once it reads the next line). `None` while every
/// line read so far is fine.
fn strict_line_fault(buf: &[u8]) -> Option<Head> {
    let control = |b: u8| b < 0x20 || (0x7f..=0x9f).contains(&b);
    if buf.first().is_some_and(|b| control(*b)) {
        return Some(netty_invalid(LINE_SEPARATOR.into()));
    }
    // A head whose lines all end with CRLF up to its blank line, or that is not complete yet, has no fault: told
    // without recording where its lines start, which only a fault's message needs.
    let (mut start, mut lines) = (0, 0);
    loop {
        let lf = start + buf[start..].iter().position(|b| *b == b'\n')?;
        if lf == start || buf[lf - 1] != b'\r' {
            break;
        }
        if lf == start + 1 && lines > 0 {
            return None;
        }
        lines += 1;
        start = lf + 1;
    }
    let mut starts = vec![0];
    loop {
        let start = *starts.last().unwrap_or(&0);
        let lf = start + buf[start..].iter().position(|b| *b == b'\n')?;
        if lf == start || buf[lf - 1] != b'\r' {
            let line = starts.len() - 1;
            if line == 0 {
                return Some(netty_invalid(LINE_SEPARATOR.into()));
            }
            // The pending header starts at the last line `splitHeader` read: a line folded into the one before (it
            // starts with SP or HT and a header precedes it) is not split. Its split ran before this line was read,
            // so its `No colon found` wins over the bare LF.
            let pending = (1..line).rev().find(|&p| p == 1 || !matches!(buf[starts[p]], b' ' | b'\t')).unwrap_or(1).min(line);
            let mut head = netty_lines(&buf[..starts[pending]]);
            if head.decode_error.is_none() {
                let split = &buf[starts[pending]..starts.get(pending + 1).copied().unwrap_or(lf)];
                head.decode_error = Some(if pending < line && !split.contains(&b':') { "No colon found" } else { LINE_SEPARATOR }.into());
            }
            return Some(head);
        }
        if lf == start + 1 && starts.len() > 1 {
            return None;
        }
        starts.push(lf + 1);
    }
}

/// Netty's invalid message for a request line it cannot read.
fn netty_invalid(message: String) -> Head {
    Head {
        method: "GET".into(),
        target: "/bad-request".into(),
        http10: true,
        http11: false,
        headers: MultiMap::new(),
        decode_error: Some(message),
    }
}

/// `HttpObjectDecoder`'s `LineParser` and `HeaderParser` limits on the first head in `buf`, complete or not: a request
/// line longer than `maxInitialLineLength` fails the decoder with `TooLongHttpLineException` (refused with `414`), and
/// header lines longer than `maxHeaderSize` together (each without its line end) with `TooLongHttpHeaderException`
/// (`431`). A line still arriving counts once it is longer than what is left, without a CR that ends what has been
/// read: `HttpLineEndSplitGuard` holds that CR back until the next read, so the decoder sees it with its LF and a line
/// of exactly the limit passes however the reads split it. Lines past one ended by a bare LF are not read: strict line
/// parsing fails there first.
fn limit_fault(buf: &[u8], limits: &Limits) -> Option<Error> {
    let line_too_long = || Error::Refused(414, format!("An HTTP line is larger than {} bytes.", limits.initial_line));
    let headers_too_large = || Error::Refused(431, format!("HTTP header is larger than {} bytes.", limits.headers));
    let mut start = 0;
    let mut header_bytes = 0usize;
    let mut first = true;
    loop {
        let (max, too_long): (usize, &dyn Fn() -> Error) = if first { (limits.initial_line, &line_too_long) } else { (limits.headers - header_bytes, &headers_too_large) };
        let rest = &buf[start..];
        let Some(lf) = rest.iter().take(max.saturating_add(2)).position(|b| *b == b'\n') else {
            let arrived = rest.len() - usize::from(rest.ends_with(b"\r"));
            return (arrived > max).then(too_long);
        };
        if lf == 0 || rest[lf - 1] != b'\r' {
            return None;
        }
        let length = lf - 1;
        if length == 0 && !first {
            return None;
        }
        if length > max {
            return Some(too_long());
        }
        if !first {
            header_bytes += length;
        }
        first = false;
        start += lf + 1;
    }
}

/// `HttpObjectDecoder.readHeaders` (Netty 4.2.19) once every header is read: the message of the failure it reports
/// for a `Content-Length` that is not one number, or a `Transfer-Encoding` on anything but HTTP/1.1, whose final coding
/// is not `chunked`, with `chunked` more than once, or together with a `Content-Length`.
fn content_length_fault(head: &Head) -> Option<String> {
    let lengths: Vec<&String> = head.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("content-length")).flat_map(|(_, v)| v.iter()).collect();
    let codings: Vec<&String> = head.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding")).flat_map(|(_, v)| v.iter()).collect();
    // `HttpUtil.normalizeAndGetContentLength`, duplicates not allowed
    if let Some(first) = lengths.first() {
        if lengths.len() > 1 || first.contains(',') {
            return Some(format!("Multiple Content-Length values found: [{}]", lengths.iter().map(|l| l.as_str()).collect::<Vec<_>>().join(", ")));
        }
        if !first.starts_with(|c: char| c.is_ascii_digit()) || first.parse::<i64>().is_err() {
            return Some(format!("Content-Length value is not a number: {first}"));
        }
    }
    if codings.is_empty() {
        return None;
    }
    if !head.http11 {
        // `TRANSFER_ENCODING_NOT_ALLOWED` (`io.netty.handler.codec.http.rfc9112TransferEncoding`, on by default).
        return Some("The Transfer-Encoding header is only allowed in HTTP/1.1 or newer".into());
    }
    let tokens = || codings.iter().flat_map(|v| v.split(',')).map(|c| c.trim_matches([' ', '\t']));
    // `HttpUtil.isTransferEncodingChunked`
    if !tokens().any(|c| c.eq_ignore_ascii_case("chunked")) {
        return Some("The final transfer coding must be chunked for HTTP requests".into());
    }
    // `isLastTransferEncodingChunked`
    let mut seen = false;
    let mut last = false;
    for coding in tokens().filter(|c| !c.is_empty()) {
        last = coding.eq_ignore_ascii_case("chunked");
        if last && std::mem::replace(&mut seen, true) {
            return Some("chunked transfer coding must not be applied more than once".into());
        }
    }
    if !last {
        return Some("chunked must be the last encoding present in the Transfer-Encoding header".into());
    }
    if !lengths.is_empty() {
        return Some("Content-Length are not allowed in HTTP/1.1 messages that contains a Transfer-Encoding header.".into());
    }
    None
}

async fn read_exact<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut BytesMut, n: usize) -> Result<Bytes, Error> {
    if n > MAX_BODY {
        return Err(Error::Malformed);
    }
    while buf.len() < n {
        fill(stream, buf).await?;
    }
    // Copy rather than split: a split `Bytes` pins the whole connection buffer for as long as the request log
    // keeps the request.
    let body = Bytes::copy_from_slice(&buf[..n]);
    buf.advance(n);
    Ok(body)
}

/// Reads and drops `n` body bytes.
async fn discard<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut BytesMut, mut n: usize) -> Result<(), Error> {
    loop {
        let take = n.min(buf.len());
        buf.advance(take);
        n -= take;
        if n == 0 {
            return Ok(());
        }
        fill(stream, buf).await?;
    }
}

/// A line of a chunked body's framing, which `HttpChunkLineLimiter` refuses to wait for past `MAX_CHUNK_LINE_BYTES`
/// (`ChunkLine`); `section` is how much of a trailer section came before it, which counts too.
async fn read_chunk_line<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut BytesMut, section: usize) -> Result<String, Error> {
    loop {
        if let Some(i) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = String::from_utf8_lossy(&buf[..i]).into_owned();
            buf.advance(i + 2);
            return Ok(line);
        }
        if section + buf.len() > MAX_CHUNK_LINE_BYTES + CHUNK_DELIMITER_BYTES {
            return Err(Error::ChunkLine);
        }
        fill(stream, buf).await?;
    }
}

/// A chunked body; `TooLarge` when it grows past `max` bytes.
async fn read_chunked<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut BytesMut, max: usize) -> Result<Bytes, Error> {
    let mut body = BytesMut::new();
    loop {
        let line = read_chunk_line(stream, buf, 0).await?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).map_err(|_| Error::BadChunk("Invalid character in chunk size".into()))?;
        if size == 0 {
            // Trailers, up to the blank line.
            let mut section = 0;
            loop {
                let line = read_chunk_line(stream, buf, section).await?;
                if line.is_empty() {
                    return Ok(body.freeze());
                }
                section += line.len() + 2;
            }
        }
        if body.len() + size > max {
            return Err(Error::TooLarge);
        }
        if body.len() + size > MAX_BODY {
            return Err(Error::Malformed);
        }
        let chunk = read_exact(stream, buf, size).await?;
        body.extend_from_slice(&chunk);
        read_exact(stream, buf, 2).await?;
    }
}

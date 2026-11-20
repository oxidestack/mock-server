//! `httpWebSocketResponse` (`HttpWebSocketResponseActionHandler`): the upgrade is completed on the connection, the
//! scripted `messages` are sent one after another (each after its delay), inbound frames are answered by the first
//! matching `matchers` entry, and the connection is closed with a normal closure once the script is done (unless
//! `closeConnection` is `false` or there are matchers to serve). With a GraphQL subprotocol and a
//! `graphqlSubscriptionFilter`, the connection speaks `graphql-transport-ws` / `graphql-ws` instead
//! (`GraphQLSubscriptionHandler`).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role};

use crate::breakpoint::StreamPhase;
use crate::request::HttpRequest;
use crate::state::State;

/// What the writer task puts on the wire.
enum Out {
    /// A frame; a scripted message's last frame carries what `writeWebSocketFrame`'s listener reports once it is written.
    Frame(Message, Option<Scripted>),
    /// `handshaker.close(NORMAL_CLOSURE)`: the close frame, then the connection is closed.
    Close,
    /// `handshaker.close` with another close frame.
    CloseWith(Message),
    /// The peer closed: the echo of its close frame (queued by tungstenite) goes out, then the connection closes.
    Flush,
}

/// A scripted message's write, as `writeWebSocketFrame`'s listener sees it complete: the `sent` entry and the next
/// message, or the entry of a failed write and the end of the script.
struct Scripted {
    number: usize,
    total: usize,
    /// False for an INJECT decision's pair of frames, which upstream writes without either entry.
    logged: bool,
    /// Told once the write has succeeded; dropped when it failed.
    written: tokio::sync::oneshot::Sender<()>,
}

/// Why a write failed, as `ExceptionHandling.causeDescription` names Netty's cause. Both count as the client gone
/// (`clientGoneException`), so neither is the WARN `async write failure for WebSocket message {} for request:{}`.
#[derive(Clone, Copy)]
enum WriteFailure {
    /// The channel closed under the write: the client's input ended or failed, or `WriteStallTimeoutHandler` cut it.
    Closed,
    /// The socket refused the write (a reset): `ReadAfterFailedWrite` turns Netty's close into an output shutdown.
    OutputShutdown,
    /// The frame's payload copy did not fit Netty's direct-memory limit: `OutOfDirectMemoryError`, which
    /// is not a client gone, so the WARN `async write failure …`, and the connection is closed by `finishWebSocket`.
    DirectMemory { needed: usize, max: u64 },
}

impl WriteFailure {
    fn description(self) -> String {
        match self {
            WriteFailure::Closed => "StacklessClosedChannelException".into(),
            WriteFailure::OutputShutdown => "ChannelOutputShutdownException: Channel output shutdown".into(),
            WriteFailure::DirectMemory { needed, max } => format!("shaded_package.io.netty.util.internal.OutOfDirectMemoryError: failed to allocate {needed} byte(s) of direct memory (used: 0, max: {max})"),
        }
    }
}

/// A TLS read failure on a mocked WebSocket session, which `CallbackWebSocketServerHandler.exceptionCaught` (the last
/// inbound handler once the handshake is done) logs as an SSL or decoder fault, then closes the channel.
#[derive(Clone, Copy)]
enum TlsFault {
    /// A record that did not decrypt (rustls `DecryptError`): `SslHandler` fails with the JDK engine's `bad_record_mac`,
    /// and when the channel goes inactive `ByteToMessageDecoder.channelInputClosed` decodes the record it kept once more,
    /// a second fault (`NotSslRecordException`), so the entry is written twice (recorded from the oracle).
    BadRecordMac,
}

/// The WARN entries of a [`TlsFault`]: `web socket server caught SSL or decoder fault` with `sniDescription`.
fn log_tls_fault(state: &State, sni: Option<&str>, fault: TlsFault) {
    use crate::recorded::{Level, LogEntry};
    let message = format!("web socket server caught SSL or decoder fault{}", sni.map(|name| format!(" (SNI: {name})")).unwrap_or_default());
    let throwables: [&str; 2] = match fault {
        TlsFault::BadRecordMac => [
            "shaded_package.io.netty.handler.codec.DecoderException: javax.net.ssl.SSLException: (bad_record_mac) Tag mismatch",
            // Netty's message counts the record's bytes, which rustls does not report
            "shaded_package.io.netty.handler.codec.DecoderException: shaded_package.io.netty.handler.ssl.NotSslRecordException: not an SSL/TLS record",
        ],
    };
    for throwable in throwables {
        crate::log::warn_event(state, LogEntry::at(Level::Warn, message.clone()).throwable(throwable));
    }
}

/// `normalClosure()`: Netty's `NORMAL_CLOSURE` carries the reason `Bye`.
fn normal_closure() -> Message {
    Message::Close(Some(CloseFrame { code: CloseCode::Normal, reason: "Bye".into() }))
}

/// `WebSocketCloseStatus.TRY_AGAIN_LATER`: a refused reply set (`WebSocketReplySender.refused`).
fn try_again_later() -> Message {
    Message::Close(Some(CloseFrame { code: CloseCode::Again, reason: "Try Again Later".into() }))
}

/// A scripted frame: text (possibly templated) or binary, with its delay. A template that fails to render is the
/// `Err` (upstream's `StreamTemplateRenderer` throws).
fn frame(state: &State, message: &Value, template: Option<crate::templates::Engine>, request: &HttpRequest) -> Option<Result<Message, String>> {
    if let Some(binary) = message.get("binary").and_then(Value::as_str) {
        return Some(Ok(Message::binary(base64::engine::general_purpose::STANDARD.decode(binary).unwrap_or_default())));
    }
    let text = message.get("text").and_then(Value::as_str)?;
    let text = match template {
        Some(engine) => {
            if engine == crate::templates::Engine::Velocity {
                crate::foreign::velocity_sandboxed(state);
            }
            match crate::templates::render_text(state, &state.velocity_engines.websocket, engine, text, request) {
                Ok(text) => text,
                Err(e) => {
                    if engine == crate::templates::Engine::JavaScript {
                        crate::templates::log_graaljs_missing(state, request);
                    }
                    return Some(Err(e));
                }
            }
        }
        None => text.to_string(),
    };
    Some(Ok(Message::text(text)))
}

fn delay_of(message: &Value) -> Option<Duration> {
    message.get("delay").filter(|d| !d.is_null()).and_then(crate::action::delay).map(|d| d.fixed)
}

/// `WebSocketServerHandshaker.selectSubprotocol`: the first requested subprotocol the response offers.
fn select_subprotocol(offered: Option<&str>, requested: Option<&str>) -> Option<String> {
    let offered: Vec<&str> = offered?.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    requested?
        .split(',')
        .map(str::trim)
        .find(|r| offered.iter().any(|o| *o == "*" || o == r))
        .map(str::to_string)
}

/// `WebSocketServerHandshakerFactory.newHandshaker` returns no handshaker for a `Sec-WebSocket-Version` other than 13, 8
/// or 7 (a request without one goes on to the handshake and its errors); `HttpWebSocketResponseActionHandler` then
/// writes `sendUnsupportedVersionResponse` and the exchange ends, so the connection serves the next request.
pub fn unsupported_version(request: &HttpRequest) -> bool {
    request.first_header("sec-websocket-version").is_some_and(|v| !matches!(v, "13" | "8" | "7"))
}

/// `sendUnsupportedVersionResponse` as `HttpServerCodec` writes it.
pub const UNSUPPORTED_VERSION: &[u8] = b"HTTP/1.1 426 Upgrade Required\r\nsec-websocket-version: 13\r\ncontent-length: 0\r\n\r\n";

/// Completes the handshake on `stream` and serves the mocked session until either side closes.
pub async fn serve<S>(state: Arc<State>, request: HttpRequest, response: Value, mut stream: S, output: crate::write_stall::Kind, sni: Option<String>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let graphql_protocol = matches!(response.get("subprotocol").and_then(Value::as_str), Some("graphql-transport-ws" | "graphql-ws"));
    let filter = response.get("graphqlSubscriptionFilter").filter(|f| f.is_object()).cloned();
    let graphql = graphql_protocol && filter.is_some();
    // Stream-frame breakpoints, looked up once for the session: RESPONSE_STREAM holds what the mock sends,
    // INBOUND_STREAM what the client sends (`<logCorrelationId>-ws-stream`, `<logCorrelationId>-ws-inbound`).
    let correlation = crate::breakpoint::correlation(&request);
    let outbound = crate::breakpoint::stream(&state, &request, StreamPhase::Response, format!("{correlation}-ws-stream"), &request.method, &request.path).map(Arc::new);
    let inbound_method = if graphql { "GQL-INBOUND" } else { "WS-INBOUND" };
    let inbound = crate::breakpoint::stream(&state, &request, StreamPhase::Inbound, format!("{correlation}-ws-inbound"), inbound_method, "/");
    let has = |name: &str, needle: &str| request.first_header(name).is_some_and(|v| v.to_lowercase().contains(needle));
    if !has("upgrade", "websocket") {
        // `WebSocketServerHandshaker.handshake` throws; the action handler logs it and closes the channel.
        crate::log::info(&state, "not a WebSocket handshake request: missing upgrade");
        let _ = stream.shutdown().await;
        return;
    }
    let key = request.first_header("sec-websocket-key").unwrap_or_default();
    let subprotocol = select_subprotocol(response.get("subprotocol").and_then(Value::as_str), request.first_header("sec-websocket-protocol"));
    let mut head = format!(
        "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-accept: {}\r\n",
        derive_accept_key(key.as_bytes())
    );
    if let Some(p) = &subprotocol {
        head.push_str(&format!("sec-websocket-protocol: {p}\r\n"));
    }
    head.push_str("\r\n");
    // Netty closes a channel whose client has closed (no half-closure), so the handshake's write of the `101` fails
    // once the client is gone, e.g. during the action's delay; a write to our socket would still succeed.
    let (early, gone) = read_ready(&mut stream);
    let raw = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut stream = RawTail { inner: crate::rewind::Rewind { prefix: early, inner: stream }, raw: raw.clone(), written: 0 };
    if gone || stream.write_all(head.as_bytes()).await.is_err() || stream.flush().await.is_err() {
        log_handshake_failed(&state, &request);
        let _ = stream.shutdown().await;
        return;
    }
    // `CrossProtocolEventBus.fire(WEBSOCKET_CONNECT, path)` once the handshake succeeded
    state.bus().fire(crate::scenario::Trigger::WebSocketConnect, &request.path);
    let ws = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
    let (mut sink, mut source) = ws.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Out>();
    // Set once the close frame is out: the reader stops, and dropping both halves closes the connection.
    let closed = Arc::new(tokio::sync::Notify::new());
    let closed_w = closed.clone();
    // Set once the channel would be closed under the writer (the client's input ended): a write in progress then fails
    // (`client left before …`), and one not yet begun is not attempted (`scheduleMessages`' `isActive()` check).
    let (gone, mut gone_w) = tokio::sync::watch::channel(None::<WriteFailure>);
    let (state_w, request_w) = (state.clone(), request.clone());
    // Netty's direct-memory limit and whether `finishWebSocket` closes the connection after a failed write.
    let direct_limit = crate::config::netty_max_direct_memory(&state.config);
    let close_after_failure = response.get("closeConnection").and_then(Value::as_bool).unwrap_or(true);
    let writer = tokio::spawn(async move {
        while let Some(out) = rx.recv().await {
            if gone_w.borrow().is_some() {
                return;
            }
            match out {
                Out::Frame(message, scripted) => {
                    let direct = scripted.as_ref().filter(|s| s.logged).and_then(|_| direct_memory_failure(direct_limit, &message));
                    if let Some((header, failure)) = direct {
                        // the encoder's header buffer is written, then the payload's direct copy fails
                        raw.lock().expect("raw tail").extend_from_slice(&header);
                        let _ = sink.flush().await;
                        if let Some(scripted) = scripted {
                            log_async_write_failure(&state_w, &request_w, scripted.number, failure);
                        }
                        if close_after_failure {
                            let _ = sink.send(normal_closure()).await;
                            closed_w.notify_one();
                        }
                        return;
                    }
                    let failed = tokio::select! {
                        sent = sink.send(message) => match sent {
                            // a reset is taken as written by `WriteStallIo`, which ends the output instead
                            _ if output.output_ended() => Some(WriteFailure::OutputShutdown),
                            Ok(()) => None,
                            Err(_) => Some(WriteFailure::Closed),
                        },
                        gone = gone_w.wait_for(Option::is_some) => gone.map_or(Some(WriteFailure::Closed), |gone| *gone),
                    };
                    if let Some(scripted) = scripted {
                        match failed {
                            None => {
                                if scripted.logged {
                                    log_sent(&state_w, &request_w, scripted.number, scripted.total);
                                }
                                let _ = scripted.written.send(());
                            }
                            Some(failure) if scripted.logged => log_client_left(&state_w, &request_w, scripted.number, failure),
                            Some(_) => {}
                        }
                    }
                    if failed.is_some() {
                        return;
                    }
                }
                Out::Close => {
                    let _ = sink.send(normal_closure()).await;
                    closed_w.notify_one();
                    return;
                }
                Out::CloseWith(frame) => {
                    let _ = sink.send(frame).await;
                    closed_w.notify_one();
                    return;
                }
                Out::Flush => {
                    let _ = sink.flush().await;
                    return;
                }
            }
        }
    });

    let template = match response.get("templateType").and_then(Value::as_str) {
        Some("VELOCITY") => Some(crate::templates::Engine::Velocity),
        Some("MUSTACHE") => Some(crate::templates::Engine::Mustache),
        Some("JAVASCRIPT") => Some(crate::templates::Engine::JavaScript),
        _ => None,
    };
    let messages: Vec<Value> = response.get("messages").and_then(Value::as_array).cloned().unwrap_or_default();
    let matchers: Vec<Value> = response.get("matchers").and_then(Value::as_array).cloned().unwrap_or_default();
    let close_when_done = response.get("closeConnection").and_then(Value::as_bool).unwrap_or(true);
    // An INBOUND_STREAM CLOSE on a plain session closes the connection without a close frame (`ctx.close()`).
    let mut cut = false;
    // Whether the client closed with a close frame (echoed, then the connection closes) rather than leaving.
    let mut peer_closed = false;
    // How the client left, as a write in progress then fails.
    let mut left = WriteFailure::Closed;
    // A TLS record that did not decrypt ended the session (`TlsFault`), logged before the write in progress fails.
    let mut fault = None;
    // What the session runs besides reading (the script, the matchers' responses, subscriptions): ended with it.
    let mut tasks = tokio::task::JoinSet::new();

    if let (true, Some(filter)) = (graphql, filter.as_ref()) {
        let mut session = GraphQlSession::new(&state, filter, messages, subprotocol.as_deref() == Some("graphql-ws"), tx.clone(), outbound.clone());
        while let Some(message) = next_message(&mut source, &closed, &mut left, &mut fault).await {
            match message {
                // `GraphQLSubscriptionHandler.channelRead0`: the text is held before the protocol sees it.
                Message::Text(text) => match crate::breakpoint::pass(inbound.as_ref(), text.to_string(), |t| t.clone().into_bytes(), |_, b| String::from_utf8_lossy(&b).into_owned()).await {
                    Some(texts) => texts.iter().for_each(|t| session.process(t)),
                    None => session.close(),
                },
                Message::Close(_) => {
                    peer_closed = true;
                    let _ = tx.send(Out::Flush);
                    break;
                }
                _ => {}
            }
        }
        drop(session);
    } else {
        // The script, each message after the previous one (and its own delay).
        let script_tx = tx.clone();
        let (state_s, request_s) = (state.clone(), request.clone());
        let has_matchers = !matchers.is_empty();
        let script_held = outbound.clone();
        tasks.spawn(async move {
            let total = messages.len();
            for (index, message) in messages.iter().enumerate() {
                if let Some(delay) = delay_of(message) {
                    // `scheduler.schedule(writeMessage, false, delay)`: an unbounded delayed task
                    state_s.overload.unbounded_delay(delay);
                    tokio::time::sleep(delay).await;
                }
                let frame = match frame(&state_s, message, template, &request_s) {
                    None => continue,
                    Some(Ok(frame)) => frame,
                    Some(Err(_)) => {
                        // `scheduleMessages`' catch: a WARN entry, then `finishWebSocket`.
                        log_send_failed(&state_s, &request_s, index + 1);
                        if close_when_done {
                            let _ = script_tx.send(Out::Close);
                        }
                        return;
                    }
                };
                if script_held.is_some() && script_tx.is_closed() {
                    return;
                }
                let Some(frames) = pass_outbound(script_held.as_deref(), frame).await else {
                    // `finishWebSocket`: the script ends, closed unless `closeConnection` is false.
                    if close_when_done {
                        let _ = script_tx.send(Out::Close);
                    }
                    return;
                };
                if frames.is_empty() {
                    // DROP: the next message, nothing written
                    continue;
                }
                // `writeWebSocketFrame`: the next message once this one is written (logged by the writer)
                let (written, sent) = tokio::sync::oneshot::channel();
                let mut scripted = Some(Scripted { number: index + 1, total, logged: frames.len() == 1, written });
                let last = frames.len().saturating_sub(1);
                for (i, frame) in frames.into_iter().enumerate() {
                    if script_tx.send(Out::Frame(frame, if i == last { scripted.take() } else { None })).is_err() {
                        return;
                    }
                }
                if scripted.is_some() || sent.await.is_err() {
                    return;
                }
            }
            if !has_matchers && close_when_done {
                let _ = script_tx.send(Out::Close);
            }
        });
        // The matchers' responses (`FrameSender.send`), held and written one after another in the order they are
        // sent; a delayed one joins the queue once its delay is over.
        let (respond, mut responses) = mpsc::unbounded_channel::<Message>();
        let (responder_tx, responder_held) = (tx.clone(), outbound.clone());
        tasks.spawn(async move {
            while let Some(frame) = responses.recv().await {
                if responder_held.is_some() && responder_tx.is_closed() {
                    return;
                }
                let Some(frames) = pass_outbound(responder_held.as_deref(), frame).await else {
                    let _ = responder_tx.send(Out::Close);
                    return;
                };
                for frame in frames {
                    let _ = responder_tx.send(Out::Frame(frame, None));
                }
            }
        });
        // `BidirectionalWebSocketFrameHandler`, installed only with matchers: each inbound frame is held first.
        let inbound = inbound.filter(|_| has_matchers);
        // `WebSocketReplySender.closing`: once a reply set was refused, no further set is sent.
        let mut refused = false;
        // `WebSocketReplySender.pendingReplySets` and `readsPaused`: past `PAUSE_READS_ABOVE` pending sets the
        // connection stops reading until they are down to `RESUME_READS_AT`.
        let pending = Arc::new(ReplySets::default());
        let mut paused = false;
        loop {
            if paused {
                tokio::select! {
                    _ = pending.drained() => paused = false,
                    _ = closed.notified() => break,
                }
            }
            let Some(message) = next_message(&mut source, &closed, &mut left, &mut fault).await else { break };
            if matches!(message, Message::Close(_)) {
                peer_closed = true;
                let _ = tx.send(Out::Flush);
                break;
            }
            let Some(received) = crate::breakpoint::pass(inbound.as_ref(), message, payload, rebuilt).await else {
                cut = true;
                break;
            };
            for message in received {
                if refused {
                    break;
                }
                let Some(matcher) = matchers.iter().find(|m| frame_matches(m, &message)) else { continue };
                // Matcher responses are sent as they are (`FrameSender`: no templating).
                let set: Vec<(Message, Option<Duration>)> = matcher
                    .get("responses")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|response| match frame(&state, response, None, &request) {
                        Some(Ok(frame)) => Some((frame, delay_of(response))),
                        _ => None,
                    })
                    .collect();
                // `Scheduler.scheduleReplySet`: the set's delayed frames are admitted together, or the whole set is
                // refused and the WebSocket closed with 1013 TRY_AGAIN_LATER.
                let delayed = set.iter().filter(|(_, d)| d.is_some_and(|d| d.as_millis() > 0)).count();
                let permits = match delayed {
                    0 => Vec::new(),
                    n => match state.overload.admit(&state, crate::overload::Reason::WebSocketReplies, n) {
                        Some(permit) => permit.into_singles(),
                        None => {
                            refused = true;
                            let _ = tx.send(Out::CloseWith(try_again_later()));
                            break;
                        }
                    },
                };
                // `WebSocketReplySender.sendAll`: the frames in order of their delay (stable), each measured from the
                // match; the undelayed ones at once, the rest by one task the set stays pending on until its last frame.
                let start = tokio::time::Instant::now();
                let mut set: Vec<(Message, Duration)> = set.into_iter().map(|(frame, delay)| (frame, delay.unwrap_or_default())).collect();
                set.sort_by_key(|(_, delay)| delay.as_millis());
                let now = set.iter().take_while(|(_, delay)| delay.as_millis() == 0).count();
                let later = set.split_off(now);
                for (frame, _) in set {
                    let _ = respond.send(frame);
                }
                if later.is_empty() {
                    continue;
                }
                let (respond, sets) = (respond.clone(), pending.clone());
                let mut permits = permits;
                let count = sets.started();
                tasks.spawn(async move {
                    for (frame, delay) in later {
                        tokio::time::sleep_until(start + delay).await;
                        drop(permits.pop());
                        let _ = respond.send(frame);
                    }
                    sets.finished();
                });
                // `pauseReadsIfTooManyPending`
                if !paused && count > PAUSE_READS_ABOVE {
                    paused = true;
                    if crate::metrics::enabled(&state.config) {
                        state.config.metrics.websocket_read_paused();
                    }
                }
            }
        }
    }
    if let Some(fault) = fault {
        log_tls_fault(&state, sni.as_deref(), fault);
    }
    if !peer_closed || cut {
        // the client left (or an INBOUND_STREAM CLOSE closed the channel): a write in progress fails
        let _ = gone.send(Some(if cut { WriteFailure::Closed } else { left }));
    }
    tasks.abort_all();
    drop(tx);
    let _ = writer.await;
}

/// `WebSocketReplySender.PAUSE_READS_ABOVE_PENDING_REPLY_SETS` and `RESUME_READS_AT_PENDING_REPLY_SETS`.
const PAUSE_READS_ABOVE: usize = 128;
const RESUME_READS_AT: usize = PAUSE_READS_ABOVE / 2;

/// The reply sets of one connection still waiting for a delayed frame.
#[derive(Default)]
struct ReplySets {
    pending: std::sync::atomic::AtomicUsize,
    resumed: tokio::sync::Notify,
}

impl ReplySets {
    /// A set starts: the pending count with it.
    fn started(&self) -> usize {
        self.pending.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
    }

    /// `replySetFinished`: wakes a paused reader once the count is down to `RESUME_READS_AT`.
    fn finished(&self) {
        if self.pending.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) - 1 <= RESUME_READS_AT {
            self.resumed.notify_one();
        }
    }

    /// `resumeReadsIfDrained`: returns once at most `RESUME_READS_AT` sets are pending.
    async fn drained(&self) {
        while self.pending.load(std::sync::atomic::Ordering::SeqCst) > RESUME_READS_AT {
            self.resumed.notified().await;
        }
    }
}

/// `writeWebSocketFrame`'s DEBUG entry once a scripted message is written.
fn log_sent(state: &State, request: &HttpRequest, number: usize, total: usize) {
    use crate::recorded::{Arg, Kind, Level, LogEntry};
    if !crate::log::debug_enabled(state) {
        return;
    }
    let entry = LogEntry::new(Kind::ExpectationResponse, "sent WebSocket message {} of {} for request:{}")
        .level(Level::Debug)
        .request(request)
        .args([Arg::from(serde_json::json!(number)), Arg::from(serde_json::json!(total)), crate::recorded::logged(request).into()]);
    state.log.message(entry);
}

/// The bytes of a data frame's header, and the failure, when the frame's payload (copied into direct memory by the
/// channel's write) is more than Netty's direct-memory limit holds (`PlatformDependent.incrementMemoryCounter`).
/// What the pool and other connections hold already moves the line a little below the limit; this one is the limit.
fn direct_memory_failure(limit: Option<u64>, message: &Message) -> Option<(Vec<u8>, WriteFailure)> {
    let (opcode, size) = match message {
        Message::Text(text) => (0x81u8, text.len()),
        Message::Binary(bytes) => (0x82, bytes.len()),
        _ => return None,
    };
    let max = limit?;
    if (size as u64) <= max {
        return None;
    }
    // `WebSocket08FrameEncoder`: 2, 4 or 10 header bytes, the server's frame unmasked
    let mut header = vec![opcode];
    match size {
        0..=125 => header.push(size as u8),
        126..=65535 => header.extend([126, (size >> 8) as u8, size as u8]),
        _ => {
            header.push(127);
            header.extend((size as u64).to_be_bytes());
        }
    }
    Some((header, WriteFailure::DirectMemory { needed: size, max }))
}

/// `writeWebSocketFrame`'s WARN entry for a scripted message whose write failed for a cause that is not a client gone.
fn log_async_write_failure(state: &State, request: &HttpRequest, number: usize, failure: WriteFailure) {
    use crate::recorded::{Arg, Level, LogEntry};
    let entry = LogEntry::at(Level::Warn, "async write failure for WebSocket message {} for request:{}")
        .request(request)
        .args([Arg::from(serde_json::json!(number)), crate::recorded::logged(request).into()])
        .throwable(failure.description());
    crate::log::warn_event(state, entry);
}

/// A stream whose owner can slip raw bytes in between the frames the WebSocket codec writes: what is queued in `raw`
/// goes out at the next flush, ahead of anything the codec has not yet flushed. A frame header that announces more than
/// its payload ever delivers (Netty's, when the payload's write failed) is such a write.
struct RawTail<S> {
    inner: S,
    raw: Arc<std::sync::Mutex<Vec<u8>>>,
    /// How much of `raw` is already written.
    written: usize,
}

impl<S: AsyncRead + Unpin> AsyncRead for RawTail<S> {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, out: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RawTail<S> {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        loop {
            let pending = {
                let raw = self.raw.lock().expect("raw tail");
                raw[self.written..].to_vec()
            };
            if pending.is_empty() {
                break;
            }
            match std::pin::Pin::new(&mut self.inner).poll_write(cx, &pending) {
                std::task::Poll::Ready(Ok(n)) => self.written += n,
                other => return other.map(|r| r.map(|_| ())),
            }
        }
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// `writeWebSocketFrame`'s DEBUG entry for a scripted message whose write failed because the client has gone
/// (`clientGoneException`); the session then ends, as `finishWebSocket` finds the channel closed.
fn log_client_left(state: &State, request: &HttpRequest, number: usize, failure: WriteFailure) {
    use crate::recorded::{Arg, Level, LogEntry};
    if !crate::log::debug_enabled(state) {
        return;
    }
    let entry = LogEntry::at(Level::Debug, "client left before WebSocket message {} was sent:{}for request:{}")
        .request(request)
        .args([Arg::from(serde_json::json!(number)), Arg::from(failure.description()), crate::recorded::logged(request).into()]);
    state.log.message(entry);
}

/// The WARN entry of a scripted message that could not be sent (its exception is the entry's throwable upstream, not
/// part of its message).
fn log_send_failed(state: &State, request: &HttpRequest, number: usize) {
    use crate::recorded::{Arg, Level, LogEntry};
    let entry = LogEntry::at(Level::Warn, "exception sending WebSocket message {} for request:{}")
        .request(request)
        .args([Arg::from(serde_json::json!(number)), crate::recorded::logged(request).into()]);
    crate::log::warn_event(state, entry);
}

/// What the client has already sent without waiting, and whether it has closed (end of stream or a read error): the
/// state Netty's channel would be in, as it reads all the while.
fn read_ready<S: AsyncRead + Unpin>(stream: &mut S) -> (bytes::BytesMut, bool) {
    let mut early = bytes::BytesMut::new();
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let mut buf = [0u8; 8192];
    // bounded: what is past it is read later by the session
    while early.len() < 1 << 20 {
        let mut read = tokio::io::ReadBuf::new(&mut buf);
        match std::pin::Pin::new(&mut *stream).poll_read(&mut cx, &mut read) {
            std::task::Poll::Ready(Ok(())) if read.filled().is_empty() => return (early, true),
            std::task::Poll::Ready(Ok(())) => early.extend_from_slice(read.filled()),
            std::task::Poll::Ready(Err(_)) => return (early, true),
            std::task::Poll::Pending => break,
        }
    }
    (early, false)
}

/// The handshake future's failure (`WebSocket handshake failed for request:{}`): its exception is the entry's
/// throwable upstream, not part of its message.
fn log_handshake_failed(state: &State, request: &HttpRequest) {
    use crate::recorded::{Level, LogEntry};
    let entry = LogEntry::at(Level::Warn, "WebSocket handshake failed for request:{}")
        .request(request)
        .args([crate::recorded::Arg::from(crate::recorded::logged(request))]);
    crate::log::warn_event(state, entry);
}

/// A frame's payload, as a stream-frame breakpoint sees it.
fn payload(message: &Message) -> Vec<u8> {
    match message {
        Message::Text(text) => text.as_bytes().to_vec(),
        Message::Binary(b) | Message::Ping(b) | Message::Pong(b) => b.to_vec(),
        Message::Frame(f) => f.payload().to_vec(),
        Message::Close(_) => Vec::new(),
    }
}

/// `reconstructFrame` for an inbound frame: the same kind of frame around other bytes (text read lossily, as Netty's
/// `frame.text()` does).
fn rebuilt(message: &Message, bytes: Vec<u8>) -> Message {
    match message {
        Message::Binary(_) => Message::binary(bytes),
        Message::Ping(_) => Message::Ping(bytes.into()),
        Message::Pong(_) => Message::Pong(bytes.into()),
        _ => Message::text(String::from_utf8_lossy(&bytes).into_owned()),
    }
}

/// An outbound frame through the RESPONSE_STREAM breakpoint: a modified or injected frame keeps the held one's kind,
/// and a text frame carries the client's bytes as they are (`new TextWebSocketFrame(wrappedBuffer(bytes))`), valid
/// UTF-8 or not. `None` for CLOSE.
async fn pass_outbound(held: Option<&crate::breakpoint::HeldStream>, frame: Message) -> Option<Vec<Message>> {
    use tokio_tungstenite::tungstenite::protocol::frame::coding::{Data, OpCode};
    use tokio_tungstenite::tungstenite::protocol::frame::Frame;
    crate::breakpoint::pass(held, frame, payload, |frame, bytes| match frame {
        Message::Binary(_) => Message::binary(bytes),
        _ => match String::from_utf8(bytes) {
            Ok(text) => Message::text(text),
            Err(e) => Message::Frame(Frame::message(e.into_bytes(), OpCode::Data(Data::Text), true)),
        },
    })
    .await
}

/// The next inbound message, or `None` once the peer is gone or the close frame has been sent. A client that reset the
/// connection sets `left`: Netty's epoll loop handles the socket's error as writable first, so the write in progress
/// fails before the read does (`ChannelOutputShutdownException`); an end of input or any other read failure closes the
/// channel under it (`StacklessClosedChannelException`).
/// A record that does not decrypt sets `fault` (`TlsFault`).
async fn next_message<S>(source: &mut futures_util::stream::SplitStream<WebSocketStream<S>>, closed: &tokio::sync::Notify, left: &mut WriteFailure, fault: &mut Option<TlsFault>) -> Option<Message>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio_tungstenite::tungstenite::Error;
    tokio::select! {
        message = source.next() => match message {
            Some(Ok(message)) => Some(message),
            Some(Err(Error::Io(e))) if matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionAborted) => {
                *left = WriteFailure::OutputShutdown;
                None
            }
            Some(Err(Error::Io(e))) if matches!(e.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()), Some(rustls::Error::DecryptError)) => {
                *fault = Some(TlsFault::BadRecordMac);
                None
            }
            _ => None,
        },
        _ = closed.notified() => None,
    }
}

/// `BidirectionalWebSocketFrameHandler.matches`: the frame type, then the text (equal, else a full regex match).
fn frame_matches(matcher: &Value, message: &Message) -> bool {
    let kind = match message {
        Message::Text(_) => "TEXT",
        Message::Binary(_) => "BINARY",
        Message::Ping(_) => "PING",
        Message::Pong(_) => "PONG",
        _ => return false,
    };
    match matcher.get("frameType").and_then(Value::as_str) {
        None | Some("ANY") => {}
        Some(expected) if expected == kind => {}
        Some(_) => return false,
    }
    // `textMatcher` is a `NottableString`: a string, or `{"not": true, "value": …}`.
    let (pattern, not) = match matcher.get("textMatcher") {
        Some(Value::String(s)) => (s.clone(), s.starts_with('!')),
        Some(Value::Object(o)) => (o.get("value").and_then(Value::as_str).unwrap_or_default().to_string(), o.get("not").and_then(Value::as_bool).unwrap_or(false)),
        _ => return true,
    };
    let pattern = if not && pattern.starts_with('!') { pattern[1..].to_string() } else { pattern };
    if pattern.is_empty() {
        return true;
    }
    let Message::Text(text) = message else { return false };
    let text = text.as_str();
    let matched = text == pattern || fancy_regex::Regex::new(&format!("^(?:{pattern})$")).is_ok_and(|r| r.is_match(text).unwrap_or(false));
    not != matched
}

/// `GraphQLSubscriptionHandler`: `connection_init` → `connection_ack`, `ping` → `pong`, a `subscribe` (`start`) whose
/// query matches the filter gets each scripted payload as `next` (`data`) and then `complete`; anything else is an
/// `error` or closes the connection.
struct GraphQlSession {
    state: Arc<State>,
    matcher: crate::matcher::graphql::AstMatcher,
    payloads: Arc<Vec<Value>>,
    legacy: bool,
    tx: mpsc::UnboundedSender<Out>,
    initialised: bool,
    active: Arc<parking_lot::Mutex<HashSet<String>>>,
    /// The RESPONSE_STREAM breakpoint holding each `next` message.
    held: Option<Arc<crate::breakpoint::HeldStream>>,
    /// The subscriptions' pushes, ended with the session.
    pushes: tokio::task::JoinSet<()>,
}

impl GraphQlSession {
    fn new(state: &Arc<State>, filter: &Value, payloads: Vec<Value>, legacy: bool, tx: mpsc::UnboundedSender<Out>, held: Option<Arc<crate::breakpoint::HeldStream>>) -> GraphQlSession {
        let query = filter.get("query").and_then(Value::as_str).unwrap_or_default();
        let fields: Vec<String> = filter.get("fields").and_then(Value::as_array).map(|f| f.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default();
        // `normaliseSubscriptionBody`: without a selection-set mode, the filter matches as `AST_SUBSET`.
        let mode = crate::matcher::graphql::Mode::parse(filter.get("selectionSetMatchType").and_then(Value::as_str)).unwrap_or(crate::matcher::graphql::Mode::AstSubset);
        GraphQlSession {
            state: state.clone(),
            matcher: crate::matcher::graphql::AstMatcher::new(query, mode, &fields),
            payloads: Arc::new(payloads),
            legacy,
            tx,
            initialised: false,
            active: Default::default(),
            held,
            pushes: tokio::task::JoinSet::new(),
        }
    }

    fn send(&self, value: Value) {
        let _ = self.tx.send(Out::Frame(Message::text(value.to_string()), None));
    }

    fn close(&self) {
        let _ = self.tx.send(Out::Close);
    }

    fn process(&mut self, text: &str) {
        let Ok(message) = serde_json::from_str::<Value>(text) else {
            self.close();
            return;
        };
        let text_of = |v: &Value| v.as_str().map_or_else(|| v.to_string(), str::to_string);
        match message.get("type").map(text_of).as_deref().unwrap_or_default() {
            "connection_init" => {
                self.initialised = true;
                self.send(json!({"type": "connection_ack"}));
            }
            "ping" => self.send(json!({"type": "pong"})),
            "subscribe" | "start" => self.subscribe(&message),
            "complete" | "stop" => {
                if let Some(id) = message.get("id").map(text_of) {
                    self.active.lock().remove(&id);
                }
            }
            "connection_terminate" => self.close(),
            _ => {}
        }
    }

    fn subscribe(&mut self, message: &Value) {
        let text_of = |v: &Value| v.as_str().map_or_else(|| v.to_string(), str::to_string);
        if !self.initialised {
            return self.close();
        }
        let Some(id) = message.get("id").map(text_of).filter(|id| !id.is_empty()) else { return self.close() };
        if self.active.lock().contains(&id) {
            return self.close();
        }
        let query = message.pointer("/payload/query").map(text_of).unwrap_or_default();
        if query.is_empty() {
            return self.error(&id, "No query provided in subscribe message");
        }
        if !self.matcher.matches(&query) {
            return self.error(&id, &format!("No matching subscription expectation found for query: {query}"));
        }
        self.active.lock().insert(id.clone());
        let (payloads, active, tx, legacy) = (self.payloads.clone(), self.active.clone(), self.tx.clone(), self.legacy);
        let (held, state) = (self.held.clone(), self.state.clone());
        self.pushes.spawn(async move {
            for (index, payload) in payloads.iter().enumerate() {
                // `pushNextSequence` hands the first payload to the scheduler within `handleSubscribe` itself, so a
                // `complete`/`stop` that arrives while this task has not run yet still lets it through (the cancel
                // stops the sequence advancing, as checked before each later payload).
                if index > 0 && !active.lock().contains(&id) {
                    return;
                }
                let Some(data) = payload.get("text").and_then(Value::as_str) else { continue };
                if let Some(delay) = delay_of(payload) {
                    // the frame sender's `scheduler.schedule(writeAction, false, delay)`: an unbounded delayed task
                    state.overload.unbounded_delay(delay);
                    tokio::time::sleep(delay).await;
                }
                let data = serde_json::from_str::<Value>(data).unwrap_or_else(|_| Value::String(data.to_string()));
                let next = Message::text(json!({"id": id, "type": if legacy { "data" } else { "next" }, "payload": {"data": data}}).to_string());
                if held.is_some() && tx.is_closed() {
                    return;
                }
                let Some(frames) = pass_outbound(held.as_deref(), next).await else {
                    // CLOSE: no `complete`, the connection closes.
                    let _ = tx.send(Out::Close);
                    return;
                };
                for frame in frames {
                    if tx.send(Out::Frame(frame, None)).is_err() {
                        return;
                    }
                }
            }
            if active.lock().remove(&id) {
                let _ = tx.send(Out::Frame(Message::text(json!({"id": id, "type": "complete"}).to_string()), None));
            }
        });
    }

    fn error(&self, id: &str, message: &str) {
        let payload = if self.legacy { json!({"message": message}) } else { json!([{"message": message}]) };
        self.send(json!({"id": id, "type": "error", "payload": payload}));
    }
}

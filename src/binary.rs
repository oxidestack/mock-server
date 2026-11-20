//! Connections that are not HTTP, TLS or SOCKS (`BinaryRequestProxyingHandler`): each chunk read is forwarded to
//! the connection's remote socket and the first chunk that comes back is returned; without one, a binary
//! expectation answers or the connection is refused with upstream's message.

mod replies;

use std::sync::Arc;

use base64::Engine;
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::client::Error as ClientError;
use crate::handler::Connection;
use crate::server::Io;
use crate::state::State;

const UNKNOWN_FORMAT: &str = "unknown message format, only HTTP requests are supported for mocking or HTTP & binary requests for proxying, but request is not being proxied and request is not valid HTTP";

/// `PortUnificationHandler.isHttp`: the first eight bytes start with one of these.
const METHODS: &[&[u8]] = &[b"GET ", b"POST ", b"PUT ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"DELETE ", b"TRACE ", b"CONNECT "];

/// Whether the first bytes are HTTP/1.x; `None` while they are the start of a method name and could still become one
/// (`PortUnificationHandler.startsWithAny`): bytes that cannot are not HTTP at once.
pub fn is_http(buf: &[u8]) -> Option<bool> {
    let head = &buf[..buf.len().min(8)];
    if METHODS.iter().any(|m| head.starts_with(m)) {
        return Some(true);
    }
    if METHODS.iter().any(|m| m.starts_with(head)) {
        return None;
    }
    Some(false)
}

/// `StringFormatter.formatBytes`: the hex dump in 64-character lines.
fn format_bytes(bytes: &[u8]) -> String {
    let hex = hex(bytes);
    hex.as_bytes().chunks(64).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("\n")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `maxLoggedBodyBytes`: how many of a binary message's bytes its log entries show (0: all).
fn max_logged(state: &State) -> usize {
    state.config.int_property("maxLoggedBodyBytes", 0).max(0) as usize
}

/// The bytes a log entry shows, and `StringFormatter.bytesLeftOut` when some were left out.
fn logged_part<'a>(state: &State, bytes: &'a [u8]) -> (&'a [u8], String) {
    match max_logged(state) {
        max if max > 0 && bytes.len() > max => (&bytes[..max], format!("...({} bytes, only the first {max} logged, maxLoggedBodyBytes)", bytes.len())),
        _ => (bytes, String::new()),
    }
}

/// `StringFormatter.formatBytes(bytes, maxLoggedBodyBytes)`.
fn format_for_log(state: &State, bytes: &[u8]) -> String {
    let (shown, left_out) = logged_part(state, bytes);
    format_bytes(shown) + &left_out
}

/// `StringFormatter.hexDumpForLog(bytes, maxLoggedBodyBytes)`.
fn hex_for_log(state: &State, bytes: &[u8]) -> String {
    let (shown, left_out) = logged_part(state, bytes);
    hex(shown) + &left_out
}

/// `StringFormatter.utf8ForLog(bytes, maxLoggedBodyBytes)`.
fn utf8_for_log(state: &State, bytes: &[u8]) -> String {
    let (shown, left_out) = logged_part(state, bytes);
    String::from_utf8_lossy(shown).into_owned() + &left_out
}

/// An entry of no type of its own: the event log does not print those, so it goes through `log::info_event`, which
/// writes the console line the oracle prints for it too. The arguments are payloads (`SensitiveLogValue`, upstream
/// c76143e4a): masked under `redactSecretsInLog`.
fn log(state: &State, cid: &str, message: &str, arguments: &[&str]) {
    crate::log::info_event(state, crate::recorded::LogEntry::new(crate::recorded::Kind::Info, message).correlation(cid).args(arguments.iter().map(|a| crate::recorded::Arg::sensitive(*a))));
}

/// [`log`] for an entry of its own type: upstream types "received binary request" `RECEIVED_REQUEST` and the
/// "returning binary ..." entries `FORWARDED_REQUEST`; the rest set no type. The arguments are payloads, as in [`log`].
/// `cid` is the exchange's log correlation id (`UUIDService.getUUID()` per received chunk). A `RECEIVED_REQUEST` is
/// kept whatever the `logLevel` (`MockServerLogger.logEvent`, and its caller asks no level first).
fn log_as(state: &State, cid: &str, kind: crate::recorded::Kind, message: &str, arguments: &[&str]) {
    if state.info_enabled() || kind == crate::recorded::Kind::ReceivedRequest {
        state.log.message(crate::recorded::LogEntry::new(kind, message).correlation(cid).args(arguments.iter().map(|a| crate::recorded::Arg::sensitive(*a))));
    }
}

/// `BinaryRequestProxyingHandler`'s received entry: logged at every level once the message was matched, with its
/// binary definition (`{"binaryData": …}`, cut to `maxLoggedBodyBytes` as `truncateBodiesForLog` cuts it) as its request
/// and the id of the expectation that answered it, one with a binary response (upstream #97, #101): verify and retrieve
/// find it.
fn log_received(state: &State, cid: &str, request: &[u8], answered: Option<&str>) {
    use crate::recorded::{Arg, Kind, LogEntry, Subject};
    let definition = binary_definition(state, request);
    let mut entry = LogEntry::new(Kind::ReceivedRequest, "received binary request:{}")
        .correlation(cid)
        .request_json(definition.clone())
        .args([Arg::sensitive(hex_for_log(state, request))]);
    if let Some(id) = answered {
        entry = entry.expectation_id(id);
    }
    state.log.message_about(entry, Subject::Definition(definition));
}

/// A binary message's definition as its log entries carry it: `{"binaryData": …}` of the bytes cut to
/// `maxLoggedBodyBytes` (`truncateBodiesForLog`).
fn binary_definition(state: &State, request: &[u8]) -> serde_json::Value {
    serde_json::json!({"binaryData": base64::engine::general_purpose::STANDARD.encode(logged_part(state, request).0)})
}

/// The id [`log_received`] names: the matched expectation's, when it has a binary response.
fn answering_id(expectation: Option<&Arc<crate::store::Expectation>>) -> Option<&str> {
    expectation.filter(|e| e.input.get("binaryResponse").is_some_and(|r| !r.is_null())).map(|e| e.id.as_str())
}

/// An address argument: `json` is its Jackson form (`host:port`, also what the dashboard shows), `text` its `toString`.
fn with_object(json: String, text: String) -> crate::recorded::Arg {
    let mut argument = crate::recorded::Arg::with_text(json.clone().into(), text);
    argument.object = Some(json);
    argument
}

/// `new InetSocketAddress(host, port)` as an argument: its `toString` is `host/ip:port` (no host for a literal
/// address), its Jackson form, which the dashboard shows, `host:port` (the address alone for a literal one).
fn inet_socket_address(host: &str, port: u16) -> crate::recorded::Arg {
    let (json, text) = inet_socket_address_forms(host, port);
    with_object(json, text)
}

/// [`inet_socket_address`]'s Jackson form and `toString`, worked out once for a connection's every entry.
fn inet_socket_address_forms(host: &str, port: u16) -> (String, String) {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => {
            let json = crate::server::java_socket_address(std::net::SocketAddr::new(ip, port));
            (json.clone(), format!("/{json}"))
        }
        Err(_) => {
            // Java resolves to an IPv4 address first (`java.net.preferIPv6Addresses` is false).
            let resolved = crate::inet_address::lookup_blocking(host, port).ok().and_then(|a| a.into_iter().min_by_key(std::net::SocketAddr::is_ipv6));
            let text = resolved.map_or_else(|| format!("{host}/<unresolved>:{port}"), |a| format!("{host}/{}:{port}", crate::server::java_host_address(a.ip())));
            (format!("{host}:{port}"), text)
        }
    }
}

/// The client's `channel.remoteAddress()` as an argument.
fn client_address(remote: std::net::SocketAddr) -> crate::recorded::Arg {
    let json = crate::server::java_socket_address(remote);
    with_object(json.clone(), format!("/{json}"))
}

/// `BinaryRequestPropertiesMatcher.matches`' log lines for each binary expectation the request was matched against,
/// and the closest one when none matched (`matched 0/1 fields`). Every one is about the request definition
/// `{"binaryData": …}`, so only a binary filter or none shows them (`LogEntry.matches`).
fn log_evaluations(state: &State, request: &[u8], evaluated: &[crate::store::DnsEvaluated], matched: bool, correlation: &str) {
    use crate::recorded::{Kind, LogEntry, Subject};
    // INFO entries (`firstMatchingExpectation` asks the level first)
    if !state.info_enabled() {
        return;
    }
    let definition = binary_definition(state, request);
    let subject = || Subject::Definition(definition.clone());
    // `maxLoggedMatchFailures`: did-not-match entries past the request's budget are left out, and counted.
    let mut budget = crate::dataplane::NotMatchedLogBudget::of(state);
    for e in evaluated.iter().filter(|e| e.dns) {
        if !e.matched && !budget.admit() {
            continue;
        }
        let expectation = crate::canonical::logged_matched_expectation(&e.snapshot, e.expectation.end_date_millis());
        let (kind, format) = if e.matched { (Kind::ExpectationMatched, "request:{}matched expectation:{}") } else { (Kind::ExpectationNotMatched, "request:{}didn't match expectation") };
        // `LogEntry.updateBody` passes a binary definition through (upstream #102): the entry's own `httpRequest`.
        let entry = LogEntry::new(kind, format).correlation(correlation).request_json(definition.clone()).expectation(expectation.clone()).args([&definition, &expectation]);
        state.log.message_about(entry, subject());
    }
    if matched {
        return;
    }
    // Fewest recorded differences wins, in match order: an expectation of another kind records none against a binary
    // request, so it is closest, `matched 1/1` (upstream 9.1.0); a used-up or expired one never is.
    if let Some(closest) = evaluated.iter().filter(|e| e.active && !e.matched).min_by_key(|e| e.differences) {
        let expectation = crate::canonical::logged_matched_expectation(&closest.expectation.current(), closest.expectation.end_date_millis());
        let matched_fields = 1 - closest.differences.min(1);
        let entry = LogEntry::new(Kind::ExpectationNotMatched, format!("closest expectation:{{}}matched {matched_fields}/1 fields for request:{{}}{}", budget.note()))
            .correlation(correlation)
            .request_json(definition.clone())
            .expectation(expectation.clone())
            .args([&expectation, &definition]);
        state.log.message_about(entry, subject());
    }
}

/// `BinaryProxyListener.onProxy`: one proxied binary exchange (`Configuration.binaryProxyListener`).
pub struct BinaryExchange {
    pub request: bytes::Bytes,
    /// The upstream's answer, when it comes.
    pub response: BinaryResponse,
    /// The upstream's address, `host:port`.
    pub server_address: String,
    pub client_address: std::net::SocketAddr,
}

/// The `CompletableFuture<BinaryMessage>` a listener gets: the upstream's first chunk, or `None` when there was none.
#[derive(Clone, Default)]
pub struct BinaryResponse(Arc<(parking_lot::Mutex<Option<Option<bytes::Bytes>>>, parking_lot::Condvar)>);

impl BinaryResponse {
    fn complete(&self, response: Option<bytes::Bytes>) {
        *self.0.0.lock() = Some(response);
        self.0.1.notify_all();
    }

    /// `get(timeout)`: blocks until the upstream has answered; `None` on timeout or when there was no answer.
    pub fn wait(&self, timeout: std::time::Duration) -> Option<bytes::Bytes> {
        let mut slot = self.0.0.lock();
        if slot.is_none() {
            self.0.1.wait_for(&mut slot, timeout);
        }
        slot.clone().flatten()
    }
}

#[derive(Clone)]
pub struct BinaryProxyListener(pub Arc<dyn Fn(BinaryExchange) + Send + Sync>);

impl std::fmt::Debug for BinaryProxyListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BinaryProxyListener")
    }
}

/// Calls the configured listener off the async workers (it may block on the response).
fn notify(state: &State, request: &bytes::Bytes, response: &BinaryResponse, server: String, client: std::net::SocketAddr) {
    if let Some(listener) = state.config.binary_proxy_listener.clone() {
        let exchange = BinaryExchange { request: request.clone(), response: response.clone(), server_address: server, client_address: client };
        tokio::task::spawn_blocking(move || (listener.0)(exchange));
    }
}

/// What a binary expectation does with a message on a relayed connection, as its binary response's `upstream` says.
enum LocalAnswer {
    /// ANSWER_ONLY: the reply written here (empty: nothing) after its delay, the message not forwarded.
    Answer(bytes::Bytes, std::time::Duration),
    /// ANSWER_AND_FORWARD: answered as ANSWER_ONLY, and forwarded with the upstream's reply dropped.
    AnswerAndForward(bytes::Bytes, std::time::Duration),
    /// FORWARD_AND_REPLACE: forwarded, with these bytes written in place of the upstream's reply once it has ended,
    /// not before the delay.
    Replace(bytes::Bytes, std::time::Duration),
}

/// `BinaryRequestProxyingHandler.answeredByExpectation` (`matchBinaryExpectationsWhenProxying`) on a connection
/// relayed on one upstream connection: what the binary expectation the message matches does with it, or `None` to
/// forward the message as it is. A message no expectation matches adds no match entries to the log. The binary
/// response's `upstream` other than ANSWER_ONLY needs the upstream's replies told apart (`tracks`: PostgreSQL framing
/// whose tracking has not been lost); without that it answers as ANSWER_ONLY and says so once per connection
/// (`untracked_warned`, `upstreamOf`).
fn local_answer(state: &State, conn: &Connection, request: &[u8], cid: &str, target: (&str, u16), tracks: bool, untracked_warned: &mut bool) -> Option<LocalAnswer> {
    use crate::recorded::{Arg, Kind, Level, LogEntry};
    let (found, evaluated) = state.store.first_binary_match(request);
    if found.is_some() {
        log_evaluations(state, request, &evaluated, true, cid);
    }
    log_received(state, cid, request, answering_id(found.as_ref()));
    let expectation = found?;
    let Some(binary_response) = expectation.input.get("binaryResponse") else {
        if state.store.post_process(&expectation) {
            crate::control::log_removals(state, std::slice::from_ref(&expectation), &uuid::Uuid::new_v4().to_string());
        }
        let entry = LogEntry::at(Level::Warn, "forwarding binary request:{}to:{}because the expectation it matched has no binary response:{}")
            .correlation(cid)
            .args([Arg::sensitive(format_for_log(state, request)), inet_socket_address(target.0, target.1), Arg::from(serde_json::Value::String(expectation.id.clone()))]);
        crate::log::warn_event(state, entry);
        return None;
    };
    let mut upstream = binary_response.get("upstream").and_then(serde_json::Value::as_str).unwrap_or("ANSWER_ONLY");
    if upstream != "ANSWER_ONLY" && !tracks {
        if !std::mem::replace(untracked_warned, true) {
            let entry = LogEntry::at(Level::Warn, "answering binary connection from:{}as ANSWER_ONLY where binary expectation:{}asks for:{}because nothing says where the upstream's reply to a message ends on it; that needs binaryMessageFraming POSTGRESQL")
                .correlation(cid)
                .args([client_address(conn.remote), Arg::from(serde_json::Value::String(expectation.id.clone())), Arg::from(serde_json::Value::String(upstream.to_string()))]);
            crate::log::warn_event(state, entry);
        }
        upstream = "ANSWER_ONLY";
    }
    // before the write, so a client that has its reply finds the expectation's state already updated
    if state.store.post_process(&expectation) {
        crate::control::log_removals(state, std::slice::from_ref(&expectation), &uuid::Uuid::new_v4().to_string());
    }
    let data = binary_response.get("binaryData").and_then(serde_json::Value::as_str).unwrap_or_default();
    let reply = bytes::Bytes::from(base64::engine::general_purpose::STANDARD.decode(data).unwrap_or_default());
    let delay = || binary_response.get("delay").and_then(crate::action::delay).map(|d| d.sample()).unwrap_or_default();
    if upstream == "FORWARD_AND_REPLACE" {
        let entry = LogEntry::new(Kind::Info, "forwarding binary request:{}to:{}to write binary mock response:{}in place of its response")
            .correlation(cid)
            .args([Arg::sensitive(format_for_log(state, request)), inet_socket_address(target.0, target.1), Arg::sensitive(format_for_log(state, &reply))]);
        crate::log::info_event(state, entry);
        return Some(LocalAnswer::Replace(reply, delay()));
    }
    let answer = if reply.is_empty() {
        log_as(state, cid, Kind::ForwardedRequest, "returning nothing, as the binary mock response is empty, for binary request:{}", &[&format_for_log(state, request)]);
        (reply, std::time::Duration::ZERO)
    } else {
        log_as(state, cid, Kind::ForwardedRequest, "returning binary mock response:{}for binary request:{}", &[&format_for_log(state, &reply), &format_for_log(state, request)]);
        (reply, delay())
    };
    Some(match upstream {
        "ANSWER_AND_FORWARD" => LocalAnswer::AnswerAndForward(answer.0, answer.1),
        _ => LocalAnswer::Answer(answer.0, answer.1),
    })
}

/// A relay's upstream connection: in the clear, or TLS (from its first byte, or since the client turned TLS on).
enum Upstream {
    Plain(tokio::net::TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl tokio::io::AsyncRead for Upstream {
    fn poll_read(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Upstream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Upstream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Upstream {
    fn poll_write(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Upstream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Upstream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Upstream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            Upstream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Upstream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Upstream::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

type UpstreamHalves = (tokio::io::ReadHalf<Upstream>, tokio::io::WriteHalf<Upstream>);

/// Reads the upstream once it is open; never ready before.
async fn read_upstream(upstream: Option<&mut tokio::io::ReadHalf<Upstream>>, buf: &mut BytesMut) -> std::io::Result<usize> {
    match upstream {
        Some(upstream) => upstream.read_buf(buf).await,
        None => std::future::pending().await,
    }
}

/// Writes what waits for the upstream once it is open; never ready before.
async fn write_upstream(upstream: Option<&mut tokio::io::WriteHalf<Upstream>>, buf: &mut BytesMut) -> std::io::Result<usize> {
    match upstream {
        Some(upstream) => upstream.write_buf(buf).await,
        None => std::future::pending().await,
    }
}

/// The relay's target and its `InetSocketAddress` forms, worked out once for the connection's every entry.
struct RelayTarget {
    host: String,
    port: u16,
    json: String,
    text: String,
}

impl RelayTarget {
    fn arg(&self) -> crate::recorded::Arg {
        with_object(self.json.clone(), self.text.clone())
    }
}

/// `BinaryRelay.connect`: the upstream connection, TLS from its first byte when `tls`, or `None` with the failure
/// logged (`refuse`, `connectCompleted`, `upstreamTlsFailed`).
async fn open_upstream(state: &Arc<State>, conn: &Connection, target: &RelayTarget, tls: bool, cid: &str) -> Option<Upstream> {
    use crate::recorded::{Arg, Level, LogEntry};
    let (host, port) = (target.host.as_str(), target.port);
    // `InetAddressValidator.validateForwardTarget` in `connectBinaryRelay`: refused before any connection is made (`refuse`)
    if let Some(reason) = crate::ws_relay::blocked(state, host).await {
        let entry = LogEntry::at(Level::Warn, "closing binary connection from:{}which cannot be forwarded to:{}because:{}")
            .correlation(cid)
            .args([client_address(conn.remote), target.arg(), Arg::from(serde_json::Value::String(reason))]);
        crate::log::warn_event(state, entry);
        return None;
    }
    // `connectTo`: the TLS handler is made before connecting, so a refused upstream builds the client context too
    if tls && let Some(context) = state.tls.as_ref() {
        context.client_context_needed(state);
    }
    let tcp = match connect_relay(state, host, port, tls).await {
        Ok(tcp) => tcp,
        Err(e) => {
            // `connectCompleted`: a failure of the upstream connection itself is named without a stack trace; a proxy's
            // CONNECT answer over maxHeaderSize was logged as a warning where it was refused, so this is below one
            let message = match &e {
                ClientError::Refused(address) => format!("finishConnect(..) failed with error(-111): Connection refused: {address}"),
                ClientError::HeaderLimit(reason, _) => reason.clone(),
                _ => e.exception_message().unwrap_or_default(),
            };
            let level = if matches!(e, ClientError::HeaderLimit(..)) { Level::Info } else { Level::Warn };
            let entry = LogEntry::at(level, "unable to connect to:{}for binary connection from:{}closing connection:{}")
                .correlation(cid)
                .args([target.arg(), client_address(conn.remote), Arg::from(serde_json::Value::String(message))]);
            match &e {
                ClientError::HeaderLimit(reason, _) => {
                    header_limit_refused(state, target, reason);
                    crate::log::info_event(state, entry);
                }
                _ => crate::log::warn_event(state, entry),
            }
            return None;
        }
    };
    if !tls {
        return Some(Upstream::Plain(tcp));
    }
    match crate::client::binary_relay_tls_connect(&state.config, host, conn.sni.as_deref(), tcp, state.forward_identity(host)).await {
        Ok(tls) => Some(Upstream::Tls(Box::new(tls))),
        Err(e) => {
            upstream_tls_failed(state, conn, target, cid, &e);
            None
        }
    }
}

/// `ForwardHeaderLimit.refuse`: the WARN about an upstream proxy's CONNECT answer over `maxHeaderSize`, naming the
/// upstream connection's remote socket.
fn header_limit_refused(state: &State, target: &RelayTarget, reason: &str) {
    use crate::recorded::{Arg, Level, LogEntry};
    let entry = LogEntry::at(Level::Warn, "failing forward to:{}because:{}").args([target.arg(), Arg::from(serde_json::Value::String(reason.to_string()))]);
    crate::log::warn_event(state, entry);
}

/// `BinaryRelay.upstreamTlsFailed`: the handshake future's cause is the JDK's `SSLHandshakeException` itself, not
/// Netty's `DecoderException` around it.
fn upstream_tls_failed(state: &State, conn: &Connection, target: &RelayTarget, cid: &str, e: &ClientError) {
    use crate::recorded::{Arg, Level, LogEntry};
    let message = match e {
        ClientError::TlsDecoder(message) => message.clone(),
        _ => e.exception_message().unwrap_or_default(),
    };
    let entry = LogEntry::at(Level::Warn, "unable to start TLS with upstream:{}for binary connection from:{}closing both:{}")
        .correlation(cid)
        .args([target.arg(), client_address(conn.remote), Arg::from(serde_json::Value::String(message.clone()))])
        .throwable_bean(serde_json::json!({"localizedMessage": message, "message": message, "stackTrace": []}));
    crate::log::warn_event(state, entry);
}

/// `MAX_PENDING_REPLACED_REPLIES`: the client is not read while more replies than this wait to be dropped or replaced,
/// and is read again once no more than half as many do.
const MAX_PENDING_REPLACED_REPLIES: usize = 1024;

/// The latest message forwarded (`BinaryRelay.latest`): the future its listener call was given, its log correlation
/// id, and whether the out-of-order WARN has been said about it.
struct Latest {
    request: bytes::Bytes,
    response: BinaryResponse,
    cid: String,
    overtaken_warned: bool,
}

/// What waits for the client behind a replacement whose delay has not passed.
enum Held {
    Relayed(bytes::Bytes),
    Replacement { bytes: bytes::Bytes, due: tokio::time::Instant, cid: String, request: bytes::Bytes },
}

/// `BinaryRelay.ToClient`: the upstream's bytes on their way to the client when its replies are tracked: relayed,
/// dropped, or replaced once the reply has ended. A replacement whose delay has not passed holds back everything after
/// it, so the client gets the upstream's bytes and the replacements in the upstream's order; while it waits the
/// upstream is not read.
#[derive(Default)]
struct ToClient {
    held: std::collections::VecDeque<Held>,
    /// the run of the current read relayed and not yet written
    relayed: Option<std::ops::Range<usize>>,
    /// the message the current read answers, named by the log entry of the first bytes relayed from it
    answered: Option<bytes::Bytes>,
    /// the upstream read being handed on
    read: Option<bytes::Bytes>,
}

impl ToClient {
    /// When the replacement at the head is due.
    fn due(&self) -> Option<tokio::time::Instant> {
        match self.held.front() {
            Some(Held::Replacement { due, .. }) => Some(*due),
            _ => None,
        }
    }
}

/// [`ToClient`] with what it writes to and logs against, for one call.
struct ToClientSink<'a> {
    side: &'a mut ToClient,
    state: &'a State,
    target: &'a RelayTarget,
    /// `latestCorrelationId`
    cid: &'a str,
    out: &'a mut BytesMut,
    client_gone: bool,
}

impl ToClientSink<'_> {
    /// `relay`: written now, or after what is held.
    fn relay(&mut self, bytes: bytes::Bytes) {
        if !self.side.held.is_empty() {
            self.side.held.push_back(Held::Relayed(bytes));
        } else if !self.client_gone {
            self.out.extend_from_slice(&bytes);
        }
    }

    /// `writeRelayed`: the run relayed so far, logged as the upstream's response.
    fn write_relayed(&mut self) {
        if let Some(range) = self.side.relayed.take()
            && let Some(read) = self.side.read.as_ref()
        {
            let bytes = read.slice(range);
            log_relayed(self.state, self.target, self.cid, &bytes, self.side.answered.take().as_deref());
            self.relay(bytes);
        }
    }

    fn write(&mut self, bytes: &[u8], cid: &str, request: &[u8]) {
        if self.client_gone {
            return;
        }
        write_replacement(self.state, self.target, bytes, cid, request);
        self.out.extend_from_slice(bytes);
    }

    /// `writeDue`: everything held up to the next replacement not yet due (all of it once the upstream has ended).
    fn write_due(&mut self, upstream_ended: bool) {
        let now = tokio::time::Instant::now();
        while let Some(next) = self.side.held.front() {
            if let Held::Replacement { due, .. } = next
                && *due > now
                && !upstream_ended
            {
                return;
            }
            match self.side.held.pop_front().expect("held") {
                Held::Replacement { bytes, cid, request, .. } => self.write(&bytes, &cid, &request),
                Held::Relayed(bytes) if !self.client_gone => self.out.extend_from_slice(&bytes),
                Held::Relayed(_) => {}
            }
        }
    }
}

impl replies::Output for ToClientSink<'_> {
    fn bytes(&mut self, reply: Option<&replies::Reply>, read: &bytes::Bytes, range: std::ops::Range<usize>) {
        debug_assert!(self.side.read.as_ref().is_some_and(|current| current.as_ptr() == read.as_ptr()));
        if range.is_empty() {
            return;
        }
        if reply.is_none_or(|reply| reply.handling().relayed()) {
            match self.side.relayed.as_mut() {
                Some(relayed) if relayed.end == range.start => relayed.end = range.end,
                _ => {
                    self.write_relayed();
                    self.side.relayed = Some(range);
                }
            }
            return;
        }
        let reply = reply.expect("a dropped reply");
        self.write_relayed();
        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Info, "dropping binary response:{}from:{}for binary request:{}as a binary expectation answers or replaces it")
            .correlation(reply.correlation_id())
            .args([crate::recorded::Arg::sensitive(format_for_log(self.state, &read[range])), self.target.arg(), crate::recorded::Arg::sensitive(format_for_log(self.state, reply.request()))]);
        crate::log::info_event(self.state, entry);
    }

    fn ended(&mut self, reply: replies::Reply) {
        let Some(replacement) = reply.handling().replacement().cloned() else { return };
        if self.client_gone {
            return;
        }
        if self.side.held.is_empty() && tokio::time::Instant::now() >= reply.due() {
            // what was relayed before the end goes first
            self.write_relayed();
            self.write(&replacement, reply.correlation_id(), reply.request());
        } else {
            self.write_relayed();
            self.side.held.push_back(Held::Replacement { bytes: replacement, due: reply.due(), cid: reply.correlation_id().to_string(), request: bytes::Bytes::copy_from_slice(reply.request()) });
        }
    }
}

/// `BinaryRelay.logRelayed`: a `FORWARDED_REQUEST`, kept whatever the `logLevel` (it asks none).
fn log_relayed(state: &State, target: &RelayTarget, cid: &str, response: &[u8], answered: Option<&[u8]>) {
    use crate::recorded::{Arg, Kind, LogEntry};
    let entry = match answered {
        Some(request) => LogEntry::new(Kind::ForwardedRequest, "returning binary response:{}from:{}for forwarded binary request:{}")
            .args([Arg::sensitive(format_for_log(state, response)), target.arg(), Arg::sensitive(format_for_log(state, request))]),
        None => LogEntry::new(Kind::ForwardedRequest, "returning binary response:{}from:{}").args([Arg::sensitive(format_for_log(state, response)), target.arg()]),
    };
    state.log.message(entry.correlation(cid));
}

/// `ToClient.write`: a replacement written in place of the upstream's reply.
fn write_replacement(state: &State, target: &RelayTarget, bytes: &[u8], cid: &str, request: &[u8]) {
    use crate::recorded::{Arg, Kind, LogEntry};
    if state.info_enabled() {
        let entry = LogEntry::new(Kind::ForwardedRequest, "returning binary mock response:{}in place of the response from:{}for binary request:{}")
            .correlation(cid)
            .args([Arg::sensitive(format_for_log(state, bytes)), target.arg(), Arg::sensitive(format_for_log(state, request))]);
        state.log.message(entry);
    }
}

/// `BinaryRelay.repliedLocally`: MockServer has written its own reply to a message; nothing orders it against what the
/// upstream still owes the latest message forwarded, which is warned about once per message, unless that message is
/// the one answered (ANSWER_AND_FORWARD).
fn replied_locally(state: &State, conn: &Connection, target: &RelayTarget, latest: Option<&mut Latest>, cid: &str) {
    use crate::recorded::{Arg, Level, LogEntry};
    let Some(latest) = latest else { return };
    if latest.overtaken_warned || latest.cid == cid || matches!(state.log_level.as_str(), "OFF" | "ERROR") {
        return;
    }
    latest.overtaken_warned = true;
    let entry = LogEntry::at(Level::Warn, "binary mock response written to binary connection from:{}while forwarded binary request:{}has had no response from:{}the two may reach the client out of order")
        .correlation(cid)
        .args([client_address(conn.remote), Arg::sensitive(format_for_log(state, &latest.request)), target.arg()]);
    crate::log::warn_event(state, entry);
}

/// Ready at `at`; never without one.
async fn until(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// `BinaryRelay`: every binary connection with a forward target gets one upstream connection
/// for its life, opened at its first forwarded message (TLS from the start when the client's is), or at once for a
/// client that has sent nothing (`forwardBinaryServerFirstWaitMillis`, an empty `buf`). Bytes are relayed both ways as
/// they arrive; neither side is read while what was read from it waits to be written to the other, and each side is
/// written while the other is read, so neither waits on a peer that is not reading. Each client message is logged,
/// reported to the listener and written upstream; each upstream read is logged as the response to the latest message
/// written and not yet answered (or alone) and written back. A client that turns TLS on part way (PostgreSQL's
/// SSLRequest) has its handshake answered here, and the upstream connection is upgraded with MockServer's own. The
/// upstream closing closes the client; the client leaving ends the upstream's output once what it sent is written, and
/// the upstream connection is closed when the upstream closes it or at the linger limit.
async fn relay(state: Arc<State>, mut conn: Connection, stream: Box<dyn Io>, buf: BytesMut, secure: bool, host: String, port: u16) {
    use crate::recorded::{Level, LogEntry};
    let (json, text) = inet_socket_address_forms(&host, port);
    let target = RelayTarget { host, port, json, text };
    let match_expectations = state.config.bool_property("matchBinaryExpectationsWhenProxying", true);
    let mut untracked_warned = false;
    let server_first = buf.is_empty();
    let mut messages = Messages::new(&state, !secure, buf);
    // `PostgresqlReplies`, with binaryMessageFraming POSTGRESQL only: nothing else says where a reply ends
    let mut tracker = (messages.framer.as_ref().map(crate::binary_framing::Framer::name) == Some("PostgreSQL")).then(replies::PostgresqlReplies::default);
    let mut to_client_side = ToClient::default();
    // `REPLIES_PENDING`: the client is not read while too many replies wait to be dropped or replaced
    let mut replies_hold = false;
    // `BinaryLocalReplies`: MockServer's own replies waiting for their delay, each with its message's correlation id
    let mut local: std::collections::VecDeque<(bytes::Bytes, tokio::time::Instant, String)> = std::collections::VecDeque::new();
    let (mut client_reader, mut client_writer) = tokio::io::split(stream);
    let mut upstream: Option<UpstreamHalves> = None;
    // the client's connection is TLS: from its first byte, or since it turned TLS on
    let mut client_tls = secure;
    let mut to_upstream = BytesMut::new();
    let mut to_client = BytesMut::new();
    let mut from_upstream = BytesMut::with_capacity(16 * 1024);
    // the latest message forwarded and the future its listener call was given, and whether it has been written
    let mut latest: Option<Latest> = None;
    let mut latest_written = false;
    let mut cid = uuid::Uuid::new_v4().to_string();
    let mut client_reading = true;
    let mut client_gone = false;
    let mut upstream_output_ended = false;
    // `LingeringClose.LINGER_MILLIS`: once the client has left, the upstream is given this long to close too
    let linger = tokio::time::sleep(std::time::Duration::MAX);
    tokio::pin!(linger);
    if server_first {
        match open_upstream(&state, &conn, &target, client_tls, &cid).await {
            Some(opened) => upstream = Some(tokio::io::split(opened)),
            None => {
                let _ = client_writer.shutdown().await;
                return;
            }
        }
    }
    loop {
        let (upstream_reader, upstream_writer) = match upstream.as_mut() {
            Some((reader, writer)) => (Some(reader), Some(writer)),
            None => (None, None),
        };
        let mut client_left = false;
        tokio::select! {
            event = messages.next(&mut client_reader), if client_reading && to_upstream.is_empty() && !replies_hold => match event {
                Event::Message(request) => {
                    cid = uuid::Uuid::new_v4().to_string();
                    let mut handling = replies::UpstreamReply::RELAY;
                    if !match_expectations {
                        log_received(&state, &cid, &request, None);
                    } else {
                        let tracks = tracker.as_ref().is_some_and(|t| !t.lost());
                        // `BinaryLocalReplies.write`: now, unless its delay or an earlier reply still waits
                        let mut answer_locally = |reply: bytes::Bytes, delay: std::time::Duration, latest: Option<&mut Latest>| {
                            if reply.is_empty() {
                                return;
                            }
                            if local.is_empty() && delay.is_zero() {
                                to_client.extend_from_slice(&reply);
                                replied_locally(&state, &conn, &target, latest, &cid);
                            } else {
                                local.push_back((reply, tokio::time::Instant::now() + delay, cid.clone()));
                            }
                        };
                        match local_answer(&state, &conn, &request, &cid, (&target.host, target.port), tracks, &mut untracked_warned) {
                            None => {}
                            Some(LocalAnswer::Answer(reply, delay)) => {
                                answer_locally(reply, delay, latest.as_mut());
                                continue;
                            }
                            Some(LocalAnswer::AnswerAndForward(reply, delay)) => {
                                // answered first, so a reply written now is checked against the message forwarded before this one
                                answer_locally(reply, delay, latest.as_mut());
                                handling = replies::UpstreamReply::dropped();
                            }
                            Some(LocalAnswer::Replace(replacement, delay)) => handling = replies::UpstreamReply::replace_with(replacement, delay),
                        }
                    }
                    // a message forwarded before the last one was answered leaves that one's response empty
                    if let Some(previous) = latest.take() {
                        previous.response.complete(None);
                    }
                    let response = BinaryResponse::default();
                    notify(&state, &request, &response, format!("{}:{}", target.host, target.port), conn.client_address());
                    if upstream.is_none() {
                        match open_upstream(&state, &conn, &target, client_tls, &cid).await {
                            Some(opened) => upstream = Some(tokio::io::split(opened)),
                            None => {
                                response.complete(None);
                                let _ = client_writer.shutdown().await;
                                return;
                            }
                        }
                    }
                    if let Some(tracker) = tracker.as_mut().filter(|t| !t.lost()) {
                        let due = tokio::time::Instant::now() + handling.delay();
                        let mut sink = ToClientSink { side: &mut to_client_side, state: &state, target: &target, cid: &cid, out: &mut to_client, client_gone };
                        tracker.forwarded(&request, handling, &cid, due, &mut sink);
                        if tracker.not_relayed() > MAX_PENDING_REPLACED_REPLIES {
                            replies_hold = true;
                        }
                    }
                    latest = Some(Latest { request: request.clone(), response, cid: cid.clone(), overtaken_warned: false });
                    latest_written = false;
                    to_upstream.extend_from_slice(&request);
                }
                Event::StartTls(prefix) => {
                    // the replies to what was sent in the clear are written in the clear, before TLS is turned on
                    if !to_client.is_empty() && !client_gone && (client_writer.write_all(&to_client).await.is_err() || client_writer.flush().await.is_err()) {
                        return;
                    }
                    to_client.clear();
                    let stream = client_reader.unsplit(client_writer);
                    let Some(tls) = crate::server::accept_binary_tls(&state, &mut conn, stream, prefix).await else { return };
                    (client_reader, client_writer) = tokio::io::split(tls);
                    client_tls = true;
                    messages.in_clear = false;
                    // `upgradeUpstreamToTls`: an upstream connection not yet open is opened TLS from its first byte
                    if let Some((reader, writer)) = upstream.take() {
                        let mut opened = reader.unsplit(writer);
                        if opened.write_all(&to_upstream).await.is_err() || opened.flush().await.is_err() {
                            break;
                        }
                        to_upstream.clear();
                        latest_written = latest.is_some();
                        let tcp = match opened {
                            Upstream::Plain(tcp) => tcp,
                            tls => {
                                upstream = Some(tokio::io::split(tls));
                                continue;
                            }
                        };
                        if crate::log::debug_enabled(&state) {
                            let entry = LogEntry::at(Level::Debug, "binary connection from:{}turned TLS on, upgrading its upstream connection to:{}to TLS")
                                .correlation(&cid)
                                .args([client_address(conn.remote), target.arg()]);
                            crate::log::entry(&state, &entry);
                            state.log.message(entry);
                        }
                        match crate::client::binary_relay_tls_connect(&state.config, &target.host, conn.sni.as_deref(), tcp, state.forward_identity(&target.host)).await {
                            Ok(tls) => upstream = Some(tokio::io::split(Upstream::Tls(Box::new(tls)))),
                            Err(e) => {
                                upstream_tls_failed(&state, &conn, &target, &cid, &e);
                                break;
                            }
                        }
                    }
                }
                Event::Refused(declared) => {
                    refused(&state, &conn, &declared, messages.framer.as_ref().map_or("", |f| f.name()));
                    let _ = client_writer.shutdown().await;
                    client_gone = true;
                    to_client.clear();
                    client_left = true;
                }
                Event::Closed => client_left = true,
            },
            written = write_upstream(upstream_writer, &mut to_upstream), if !to_upstream.is_empty() => {
                if written.is_err() {
                    break;
                }
                if to_upstream.is_empty() {
                    if let Some((_, writer)) = upstream.as_mut()
                        && writer.flush().await.is_err()
                    {
                        break;
                    }
                    latest_written = latest.is_some();
                    if !client_reading {
                        client_left = true;
                    }
                }
            },
            read = read_upstream(upstream_reader, &mut from_upstream), if to_client.is_empty() && to_client_side.held.is_empty() => match read {
                Ok(n) if n > 0 => {
                    let response = from_upstream.split().freeze();
                    let answered = if latest_written { latest.take() } else { None };
                    let mut sink = ToClientSink { side: &mut to_client_side, state: &state, target: &target, cid: &cid, out: &mut to_client, client_gone };
                    match tracker.as_mut().filter(|t| !t.lost()) {
                        Some(tracker) => {
                            // logs and writes each piece as the reply it belongs to says
                            sink.side.answered = answered.as_ref().map(|a| a.request.clone());
                            sink.side.read = Some(response.clone());
                            tracker.read(&response, &mut sink);
                            sink.write_relayed();
                            sink.side.answered = None;
                            sink.side.read = None;
                            if tracker.lost() {
                                replies_hold = false;
                                let entry = LogEntry::at(Level::Warn, "upstream:{}of binary connection from:{}sent a message PostgreSQL message framing (binaryMessageFraming) cannot read; its replies are relayed as they are from now on, none dropped or replaced")
                                    .correlation(&cid)
                                    .args([target.arg(), client_address(conn.remote)]);
                                crate::log::warn_event(&state, entry);
                            } else if tracker.not_relayed() <= MAX_PENDING_REPLACED_REPLIES / 2 {
                                replies_hold = false;
                            }
                        }
                        None => {
                            log_relayed(&state, &target, &cid, &response, answered.as_ref().map(|a| a.request.as_ref()));
                            // behind any replacement still waiting from before tracking was given up
                            sink.relay(response.clone());
                        }
                    }
                    if let Some(answered) = answered {
                        answered.response.complete(Some(response));
                    }
                }
                _ => break,
            },
            _ = until(local.front().map(|(_, due, _)| *due)) => {
                let now = tokio::time::Instant::now();
                while local.front().is_some_and(|(_, due, _)| *due <= now) {
                    let (reply, _, reply_cid) = local.pop_front().expect("a reply");
                    to_client.extend_from_slice(&reply);
                    replied_locally(&state, &conn, &target, latest.as_mut(), &reply_cid);
                }
            },
            _ = until(to_client_side.due()) => {
                ToClientSink { side: &mut to_client_side, state: &state, target: &target, cid: &cid, out: &mut to_client, client_gone }.write_due(false);
            },
            written = client_writer.write_buf(&mut to_client), if !to_client.is_empty() && !client_gone => match written {
                Ok(_) => {
                    if to_client.is_empty() && client_writer.flush().await.is_err() {
                        client_gone = true;
                        client_left = true;
                    }
                }
                Err(_) => {
                    // the client has gone: what the upstream sends from now on is read and dropped
                    client_gone = true;
                    to_client.clear();
                    client_left = true;
                }
            },
            _ = &mut linger => break,
        }
        if client_left {
            // `clientClosed`: the upstream's output is ended once what the client sent has been written to it
            if client_reading {
                client_reading = false;
                linger.as_mut().reset(tokio::time::Instant::now() + std::time::Duration::from_millis(5_000));
            }
            match upstream.as_mut() {
                None => break,
                Some((_, writer)) if to_upstream.is_empty() && !upstream_output_ended => {
                    upstream_output_ended = true;
                    let _ = writer.shutdown().await;
                }
                Some(_) => {}
            }
        }
    }
    // what the upstream sent before it closed is delivered first, and a replacement waiting for its delay with what
    // waits behind it is written now: the upstream has ended
    ToClientSink { side: &mut to_client_side, state: &state, target: &target, cid: &cid, out: &mut to_client, client_gone }.write_due(true);
    if let Some(latest) = latest {
        latest.response.complete(None);
    }
    if !client_gone && !to_client.is_empty() {
        let _ = client_writer.write_all(&to_client).await;
    }
    let _ = client_writer.flush().await;
    let _ = client_writer.shutdown().await;
}

/// `BinaryAwareRecvByteBufAllocator.BINARY_READ_SIZE`: every read of a binary connection is given this much, so that
/// a message is not cut by a buffer that has followed small messages down.
const BINARY_READ_SIZE: usize = 64 * 1024;

/// `TLS_CLIENT_HELLO_START_LENGTH`: the bytes that tell whether a read opens a TLS handshake.
const TLS_CLIENT_HELLO_START_LENGTH: usize = 6;

/// `PortUnificationHandler.startsTlsClientHello`.
#[derive(Debug, PartialEq)]
enum Hello {
    Yes,
    /// The start of one, too short to say: more bytes are waited for.
    Maybe,
    No,
}

/// A handshake record of TLS 3.0 to 3.4, of a length a record can have, whose first byte says ClientHello.
fn client_hello(bytes: &[u8]) -> Hello {
    let available = bytes.len().min(TLS_CLIENT_HELLO_START_LENGTH);
    let could_be_one = bytes.first() == Some(&0x16)
        && (available < 2 || bytes[1] == 3)
        && (available < 3 || bytes[2] <= 4)
        && (available < 4 || bytes[3] <= (16_384 >> 8) as u8)
        && (available < 5 || (1..=16_384).contains(&u16::from_be_bytes([bytes[3], bytes[4]])))
        && (available < 6 || bytes[5] == 1);
    match (could_be_one, available < TLS_CLIENT_HELLO_START_LENGTH) {
        (true, true) => Hello::Maybe,
        (true, false) => Hello::Yes,
        _ => Hello::No,
    }
}

/// What a binary connection's reads make: a message, a TLS handshake beginning (its first bytes), a refusal by the
/// framing, or the client's close.
#[derive(Debug)]
enum Event {
    Message(bytes::Bytes),
    StartTls(BytesMut),
    Refused(String),
    Closed,
}

/// The client side of a binary connection: `PortUnificationHandler` while the connection is in the clear (a TLS
/// handshake may begin at the start of a read), then the framer (`BinaryMessageFramer`) or, without one,
/// `BinaryMessageGatherer` (what one read brings is one message).
struct Messages {
    framer: Option<crate::binary_framing::Framer>,
    /// `binaryInTheClear`: no TLS yet, so a handshake may begin.
    in_clear: bool,
    /// The bytes of the connection's first read, which `switchToBinaryRequestProxying` passes on without looking for a
    /// handshake (they were found not to start one).
    first: bool,
    /// `heldAsStartOfHandshake`: bytes that could open a handshake, waiting for the rest.
    held: usize,
    /// While bytes are held: when the client's silence makes them a message (`UNDECIDED_PROTOCOL_WAIT_MILLIS`).
    undecided_until: Option<tokio::time::Instant>,
    /// Read and not yet looked at.
    pending: BytesMut,
    /// What one read delivered without a framer, so far.
    gathered: BytesMut,
    ready: std::collections::VecDeque<Event>,
}

impl Messages {
    fn new(state: &State, in_clear: bool, first: BytesMut) -> Messages {
        Messages {
            framer: crate::binary_framing::Framer::for_config(&state.config),
            in_clear,
            first: true,
            held: 0,
            undecided_until: None,
            pending: first,
            gathered: BytesMut::new(),
            ready: std::collections::VecDeque::new(),
        }
    }

    /// The next event. Cancel-safe: bytes read are kept until looked at.
    async fn next<S: tokio::io::AsyncRead + Unpin + ?Sized>(&mut self, stream: &mut S) -> Event {
        loop {
            if let Some(event) = self.ready.pop_front() {
                return event;
            }
            if self.first {
                // Netty's read loop (`continueReading`): a read that filled its buffer is followed by another in the
                // same loop, up to `maxMessagesPerRead` (16), so a message larger than the connection's first buffer
                // (the bytes the protocol was sniffed from) is gathered whole, not cut at it.
                let mut reads = 1;
                while reads < 16 && !self.pending.is_empty() && self.pending.len() == self.pending.capacity() {
                    self.pending.reserve(BINARY_READ_SIZE);
                    let room = self.pending.capacity() - self.pending.len();
                    match futures_util::FutureExt::now_or_never(stream.read_buf(&mut self.pending)) {
                        Some(Ok(n)) if n > 0 => {
                            reads += 1;
                            if n < room {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
                self.look(false);
                continue;
            }
            self.pending.reserve(BINARY_READ_SIZE);
            let read = match self.undecided_until {
                Some(until) => tokio::time::timeout_at(until, stream.read_buf(&mut self.pending)).await.ok(),
                None => Some(stream.read_buf(&mut self.pending).await),
            };
            match read {
                Some(Ok(n)) if n > 0 => self.look(false),
                // the client fell silent while bytes were held: they are taken as they are
                None => self.look(true),
                // `decodeLast`: the client has closed, so the bytes held are all there will be
                Some(_) => {
                    self.look(true);
                    self.ready.push_back(Event::Closed);
                }
            }
        }
    }

    /// `PortUnificationHandler.decode` on the bytes of one read, then `channelReadComplete`.
    fn look(&mut self, take_as_they_are: bool) {
        let mut first = std::mem::take(&mut self.first);
        self.undecided_until = None;
        while !self.pending.is_empty() {
            if self.in_clear && !take_as_they_are {
                if !first {
                    let may_start = self.framer.as_ref().is_none_or(crate::binary_framing::Framer::tls_may_start_here);
                    let hello = if may_start { client_hello(&self.pending) } else { Hello::No };
                    match hello {
                        Hello::Yes => {
                            // what this read brought before the handshake is a message sent in the clear
                            self.held = 0;
                            self.read_complete();
                            self.ready.push_back(Event::StartTls(self.pending.split()));
                            return;
                        }
                        Hello::Maybe => {
                            self.held = self.pending.len();
                            self.undecided_until = Some(tokio::time::Instant::now() + crate::server::UNDECIDED_PROTOCOL_WAIT);
                            self.read_complete();
                            return;
                        }
                        Hello::No => {}
                    }
                    let held = std::mem::take(&mut self.held);
                    if held > 0 && held < self.pending.len() {
                        // what was held turned out to be a message of its own, sent before the bytes that settled it;
                        // those are looked at next, as the start of a read
                        let message = self.pending.split_to(held);
                        self.deliver(&message);
                        self.read_complete();
                        continue;
                    }
                }
                let before_tls = self.framer.as_ref().map_or(0, |f| f.bytes_before_tls_may_start(&self.pending));
                if before_tls > 0 {
                    let message = self.pending.split_to(before_tls);
                    self.deliver(&message);
                    first = false;
                    continue;
                }
            }
            let rest = self.pending.split();
            self.deliver(&rest);
        }
        self.held = 0;
        self.read_complete();
    }

    /// Bytes passed on: framed into messages, or gathered into the read's one message.
    fn deliver(&mut self, bytes: &[u8]) {
        match self.framer.as_mut() {
            Some(framer) => {
                let decoded = framer.decode(bytes);
                // `refuse` logs and closes within the decode: the messages it took before are still handled, on a
                // closed connection, and nothing after them is read
                let refused = decoded.refused.is_some();
                if let Some(declared) = decoded.refused {
                    self.ready.push_back(Event::Refused(declared));
                }
                self.ready.extend(decoded.messages.into_iter().map(Event::Message));
                if refused {
                    self.ready.push_back(Event::Closed);
                }
            }
            None => self.gathered.extend_from_slice(bytes),
        }
    }

    /// `BinaryMessageGatherer.channelReadComplete`: what the read delivered is one message.
    fn read_complete(&mut self) {
        if !self.gathered.is_empty() {
            self.ready.push_back(Event::Message(self.gathered.split().freeze()));
        }
    }
}

/// `BinaryLocalReplies`: the replies MockServer writes itself on one binary connection, in the order of the messages
/// they answer. A reply with a delay is written once that delay, counted from when its message was handled, has passed
/// and every earlier reply has been written.
#[derive(Default)]
struct LocalReplies {
    waiting: std::collections::VecDeque<(bytes::Bytes, tokio::time::Instant, bool)>,
    /// `closing`: a reply that closes the connection is waiting, so what the client sends after it is not answered.
    closing: bool,
}

impl LocalReplies {
    fn add(&mut self, reply: bytes::Bytes, delay: std::time::Duration, close_after: bool) {
        self.closing |= close_after;
        self.waiting.push_back((reply, tokio::time::Instant::now() + delay, close_after));
    }

    fn next_due(&self) -> Option<tokio::time::Instant> {
        self.waiting.front().map(|(_, due, _)| *due)
    }

    /// Writes every reply that is due, in order. `Err` once the connection is to close (written or failed).
    async fn write_due<S: tokio::io::AsyncWrite + Unpin + ?Sized>(&mut self, stream: &mut S) -> Result<(), ()> {
        let now = tokio::time::Instant::now();
        while let Some((_, due, _)) = self.waiting.front() {
            if *due > now {
                break;
            }
            let (reply, _, close_after) = self.waiting.pop_front().expect("a reply");
            if stream.write_all(&reply).await.is_err() || stream.flush().await.is_err() || close_after {
                return Err(());
            }
        }
        Ok(())
    }

    /// Every waiting reply, each once due.
    async fn drain<S: tokio::io::AsyncWrite + Unpin + ?Sized>(&mut self, stream: &mut S) -> Result<(), ()> {
        while let Some(due) = self.next_due() {
            tokio::time::sleep_until(due).await;
            self.write_due(stream).await?;
        }
        Ok(())
    }
}

/// `BinaryRequestProxyingHandler` logs on the connection's event loop, whose thread-local port is set only once it has
/// handled an HTTP request: before that, the connection's entries carry no port.
pub async fn serve<S: Io + 'static>(state: Arc<State>, conn: Connection, stream: S, buf: BytesMut, secure: bool) {
    // `addBinaryRequestProxying`: a raw TCP protocol may legitimately stay silent for long periods
    conn.idle.binary();
    // nothing is read on an event loop a runtime LLM call blocks
    state.connections.loop_free(conn.event_loop).await;
    if state.connections.has_served_http(conn.event_loop) {
        serve_on_event_loop(state, conn, stream, buf, secure).await
    } else {
        crate::recorded::portless(serve_on_event_loop(state, conn, stream, buf, secure)).await
    }
}

/// `PortUnificationHandler.startServerFirstWait` (`forwardBinaryServerFirstWaitMillis`): how long a connection whose
/// client has sent nothing is waited on before it is taken as binary and its upstream connection opened, for a server
/// that speaks first. `None` for a connection nothing would be relayed for: one with no forward target.
pub(crate) fn server_first_wait(state: &State, conn: &Connection) -> Option<std::time::Duration> {
    let millis = state.config.int_property("forwardBinaryServerFirstWaitMillis", 0);
    if millis <= 0 || state.config.bool_property("assumeAllRequestsAreHttp", false) {
        return None;
    }
    conn.proxy_target.as_ref().or(state.config.port_forward.as_ref())?;
    Some(std::time::Duration::from_millis(millis as u64))
}

/// `connectForServerThatSpeaksFirst`: the client sent nothing within [`server_first_wait`], so the connection is binary
/// and its upstream connection is opened now, before the client speaks.
pub(crate) async fn serve_server_first<S: Io + 'static>(state: Arc<State>, conn: Connection, stream: S, waited: std::time::Duration) {
    if crate::log::debug_enabled(&state)
        && let Some((host, port)) = conn.proxy_target.clone().or_else(|| state.config.port_forward.clone())
    {
        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Debug, "client of connection from:{}sent nothing for:{}ms (forwardBinaryServerFirstWaitMillis), opening its upstream connection to:{}for a server that speaks first")
            .args([client_address(conn.remote), crate::recorded::Arg::from(serde_json::Value::from(waited.as_millis() as u64)), inet_socket_address(&host, port)]);
        crate::log::entry(&state, &entry);
        state.log.message(entry);
    }
    serve(state, conn, stream, BytesMut::new(), false).await
}

async fn serve_on_event_loop<S: Io + 'static>(state: Arc<State>, conn: Connection, stream: S, buf: BytesMut, secure: bool) {
    // `BinaryRequestProxyingHandler.channelRead0`: a connection with a forward target is relayed (9.1.0, upstream
    // 64b856d9d: there is no per-message forwarding any more)
    if let Some((host, port)) = conn.proxy_target.clone().or_else(|| state.config.port_forward.clone()) {
        return relay(state, conn, Box::new(stream), buf, secure, host, port).await;
    }
    serve_messages(state, conn, Box::new(stream), buf, secure).await
}

/// A binary connection with no forward target, whose messages are each answered by a binary expectation or with the
/// unknown-format message, which closes it. A TLS handshake that begins while the connection is in the clear turns
/// TLS on (a protocol that upgrades part way through, as PostgreSQL's SSLRequest does); what is decrypted from then on
/// is binary too.
async fn serve_messages(state: Arc<State>, mut conn: Connection, mut stream: Box<dyn Io>, buf: BytesMut, secure: bool) {
    let mut messages = Messages::new(&state, !secure, buf);
    let mut replies = LocalReplies::default();
    // refused by the framing: what is still handled writes nothing
    let mut closed = false;
    loop {
        let event = match replies.next_due() {
            Some(due) => tokio::select! {
                event = messages.next(&mut stream), if !replies.closing => event,
                _ = tokio::time::sleep_until(due) => {
                    if replies.write_due(&mut stream).await.is_err() {
                        let _ = stream.shutdown().await;
                        return;
                    }
                    continue;
                }
            },
            None => messages.next(&mut stream).await,
        };
        let request = match event {
            Event::Message(request) => request,
            Event::StartTls(prefix) => {
                // the replies to what was sent in the clear are written in the clear, before TLS is turned on
                if replies.drain(&mut stream).await.is_err() {
                    let _ = stream.shutdown().await;
                    return;
                }
                match crate::server::accept_binary_tls(&state, &mut conn, stream, prefix).await {
                    Some(tls) => stream = tls,
                    None => return,
                }
                messages.in_clear = false;
                continue;
            }
            Event::Refused(declared) => {
                refused(&state, &conn, &declared, messages.framer.as_ref().map_or("", |f| f.name()));
                let _ = stream.shutdown().await;
                closed = true;
                continue;
            }
            Event::Closed => {
                let _ = stream.shutdown().await;
                return;
            }
        };
        if replies.closing {
            // the connection closes once the replies before this message are written, so this one is not answered
            continue;
        }
        let cid = uuid::Uuid::new_v4().to_string();
        let answering = {
            let (found, evaluated) = state.store.first_binary_match(&request);
            log_evaluations(&state, &request, &evaluated, found.is_some(), &cid);
            log_received(&state, &cid, &request, answering_id(found.as_ref()));
            // `httpState.postProcess(matchedExpectation)` before the reply is written: an expectation its `Times`
            // have used up is removed at once.
            if let Some(e) = &found
                && state.store.post_process(e)
            {
                crate::control::log_removals(&state, std::slice::from_ref(e), &uuid::Uuid::new_v4().to_string());
            }
            // `matchedExpectation.getBinaryResponse() != null`: a match without one is no answer.
            found.filter(|e| e.input.get("binaryResponse").is_some())
        };
        match answering {
            Some(e) => {
                let binary_response = &e.input["binaryResponse"];
                let data = binary_response.get("binaryData").and_then(serde_json::Value::as_str).unwrap_or_default();
                let response = base64::engine::general_purpose::STANDARD.decode(data).unwrap_or_default();
                if response.is_empty() {
                    // a message that has no reply: null and empty data mean the same
                    log_as(&state, &cid, crate::recorded::Kind::ForwardedRequest, "returning nothing, as the binary mock response is empty, for binary request:{}", &[&format_for_log(&state, &request)]);
                    continue;
                }
                log_as(&state, &cid, crate::recorded::Kind::ForwardedRequest, "returning binary mock response:{}for binary request:{}", &[&format_for_log(&state, &response), &format_for_log(&state, &request)]);
                let delay = binary_response.get("delay").and_then(crate::action::delay).map(|d| d.sample()).unwrap_or_default();
                replies.add(response.into(), delay, false);
            }
            None => {
                log(&state, &cid, "no matching binary expectation for binary request:{}", &[&hex_for_log(&state, &request)]);
                log(
                    &state,
                    &cid,
                    &format!("{UNKNOWN_FORMAT}, found request in binary: {{}} in utf8 text: {{}}"),
                    &[&hex_for_log(&state, &request), &utf8_for_log(&state, &request)],
                );
                // behind any reply still waiting for its delay, which is written before the connection closes
                replies.add(bytes::Bytes::from_static(UNKNOWN_FORMAT.as_bytes()), std::time::Duration::ZERO, true);
            }
        }
        if closed {
            replies = LocalReplies::default();
            continue;
        }
        if replies.write_due(&mut stream).await.is_err() {
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
            return;
        }
    }
}

/// `BinaryMessageFramer.refuse`: a connection that declared what its framing does not accept is closed.
fn refused(state: &State, conn: &Connection, declared: &str, framing: &str) {
    use crate::recorded::{Arg, Level, LogEntry};
    let entry = LogEntry::at(Level::Warn, "closing binary connection from:{}because it declared{}which{}message framing (binaryMessageFraming) does not accept")
        .args([client_address(conn.remote), Arg::from(serde_json::Value::String(declared.to_string())), Arg::from(serde_json::Value::String(framing.to_string()))]);
    crate::log::warn_event(state, entry);
}

/// A forward socket is connected within `socketConnectionTimeoutInMillis`, with `forwardSocketKeepAlive*` applied
/// (`NettyHttpClient.applyForwardSocketKeepAlive`); a failure is the exception Netty's connect fails with.
fn connect_timeout(state: &State) -> std::time::Duration {
    std::time::Duration::from_millis(state.config.int_property("socketConnectionTimeoutInMillis", 20_000).max(1) as u64)
}

/// `NettyHttpClient.connectBinaryRelay`: connected directly, or through the tunnel proxy `binaryRelayTunnel` names, whose
/// failure to be reached is `proxyFailure(tunnel, …)`: a WARN once per proxy address for the server's lifetime.
async fn connect_relay(state: &State, host: &str, port: u16, secure: bool) -> Result<tokio::net::TcpStream, ClientError> {
    let connect_timeout = connect_timeout(state);
    let on_event = |event: &crate::client::ClientEvent| {
        if let crate::client::ClientEvent::ProxyUnreachable { proxy, property, cause } = event {
            crate::forward::proxy_failure(state, proxy, property, cause);
        }
    };
    crate::client::on_tls(&on_event, crate::client::connect_binary_relay(&state.config, host, port, secure, connect_timeout)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    /// A real upstream socket made by the binary relay's connect, with `config`'s keep-alive settings.
    async fn forward_socket(config: Config) -> (tokio::net::TcpStream, tokio::net::TcpListener) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = State::new(config, vec![0]);
        let stream = crate::client::connect_binary_relay(&state.config, "127.0.0.1", port, false, connect_timeout(&state)).await.expect("connected");
        (stream, listener)
    }

    #[test]
    fn should_tell_a_client_hello_from_its_first_six_bytes_and_wait_while_fewer_could_be_one() {
        assert_eq!(client_hello(&[22]), Hello::Maybe);
        assert_eq!(client_hello(&[22, 3, 1, 0]), Hello::Maybe);
        assert_eq!(client_hello(&[22, 3, 1, 0, 200, 1]), Hello::Yes);
        assert_eq!(client_hello(&[22, 3, 3, 0, 5, 2, 0, 0, 1, 0]), Hello::No, "a ServerHello");
        assert_eq!(client_hello(&[22, 3, 5]), Hello::No, "no TLS version");
        assert_eq!(client_hello(&[22, 3, 1, 0x41]), Hello::No, "longer than a record");
        assert_eq!(client_hello(&[22, 3, 1, 0, 0]), Hello::No, "an empty record");
        assert_eq!(client_hello(b"xxx"), Hello::No);
    }

    #[tokio::test]
    async fn should_set_so_keepalive_on_binary_forward_socket_when_enabled() {
        let (stream, _l) = forward_socket(Config::for_tests()).await;
        assert!(socket2::SockRef::from(&stream).keepalive().unwrap());
    }

    #[tokio::test]
    async fn should_not_set_keepalive_on_binary_forward_socket_when_disabled() {
        let (stream, _l) = forward_socket(Config::for_tests().with_property("forwardSocketKeepAlive", "false")).await;
        assert!(!socket2::SockRef::from(&stream).keepalive().unwrap());
    }

    #[tokio::test]
    async fn should_apply_configured_keepalive_timers_clamped_to_at_least_one() {
        let (stream, _l) = forward_socket(
            Config::for_tests()
                .with_property("forwardSocketKeepAliveIdleSeconds", "61")
                .with_property("forwardSocketKeepAliveIntervalSeconds", "0")
                .with_property("forwardSocketKeepAliveCount", "-3"),
        )
        .await;
        let socket = socket2::SockRef::from(&stream);
        assert_eq!(socket.tcp_keepalive_time().unwrap(), std::time::Duration::from_secs(61));
        assert_eq!(socket.tcp_keepalive_interval().unwrap(), std::time::Duration::from_secs(1));
        assert_eq!(socket.tcp_keepalive_retries().unwrap(), 1);
    }
}

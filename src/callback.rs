//! The object-callback WebSocket (`/_mockserver_callback_websocket`, §1.5): clients register, the server sends
//! matched requests and waits for the client's response, correlated by the `WebSocketCorrelationId` header.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;

use crate::json;
use crate::request::HttpRequest;

pub const PATH: &str = "/_mockserver_callback_websocket";
pub const CORRELATION_HEADER: &str = "WebSocketCorrelationId";
const REGISTRATION_HEADER: &str = "X-CLIENT-REGISTRATION-ID";
const HTTP_REQUEST: &str = "org.mockserver.model.HttpRequest";
const HTTP_RESPONSE: &str = "org.mockserver.model.HttpResponse";
const HTTP_REQUEST_AND_RESPONSE: &str = "org.mockserver.model.HttpRequestAndHttpResponse";
const CLIENT_ID: &str = "org.mockserver.serialization.model.WebSocketClientIdDTO";
const ERROR: &str = "org.mockserver.serialization.model.WebSocketErrorDTO";
const PAUSED_FRAME: &str = "org.mockserver.serialization.model.PausedStreamFrameDTO";
const FRAME_DECISION: &str = "org.mockserver.serialization.model.StreamFrameDecisionDTO";

/// Why a hold ended without an answer.
pub enum Unanswered {
    /// The client is not connected (`sendStreamFrameMessage` failed).
    NotConnected,
    /// `breakpointTimeoutMillis` passed.
    TimedOut,
    /// The client left or the holds were reset (`autoCompleteForClient`).
    Released,
}

type Held = Arc<Mutex<HashMap<String, (String, oneshot::Sender<Reply>)>>>;

/// A hold's entry, removed when its wait ends. A wait given up early (its stream went away) leaves the entry in
/// flight until the client answers or `deadline` passes, as upstream's in-flight dispatch outlives the stream.
struct Parked {
    held: Held,
    correlation: String,
    deadline: tokio::time::Instant,
    ended: bool,
}

impl Drop for Parked {
    fn drop(&mut self) {
        let (held, correlation) = (self.held.clone(), std::mem::take(&mut self.correlation));
        if self.ended {
            held.lock().remove(&correlation);
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let deadline = self.deadline;
            runtime.spawn(async move {
                tokio::time::sleep_until(deadline).await;
                held.lock().remove(&correlation);
            });
        }
    }
}

/// How long a matched request waits for its client before giving up with a 404.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// `CallbackClientIdClaim.LIVENESS_TIMEOUT_MILLIS`: how long a registered connection has to answer the ping of a
/// connection claiming its client id.
const LIVENESS_TIMEOUT: Duration = Duration::from_millis(2000);

/// What a client's connection is told to do, in order.
enum Outgoing {
    /// A text frame.
    Text(String),
    /// A ping frame, for a claim's liveness check.
    Ping,
    /// Close the connection (no close frame: Netty's `channel.close()`).
    Close,
    /// The client id was taken over by the same caller: the connection stays open, unregistered (upstream leaves it).
    Detach,
}

/// A registered client's connection.
#[derive(Clone)]
struct Client {
    tx: mpsc::UnboundedSender<Outgoing>,
    /// Which connection this is, to tell a successor under the same client id from it.
    connection: u64,
    /// `CallbackClientIdClaim.PRINCIPAL_IDENTITY`: the authenticated caller that registered it, if one was named.
    identity: Option<String>,
    /// Told of every pong the connection receives (`CallbackClientIdClaim.pongReceived`).
    pong: Arc<tokio::sync::Notify>,
}

/// `CallbackClientIdClaim.Decision`
#[derive(Clone, Copy, PartialEq, Debug)]
enum Decision {
    Allow,
    AllowAndCloseUnresponsive,
    RefuseOtherPrincipal,
    RefuseRegisteredConnectionAnswers,
}

/// A client id reserved for a connection taking it over (`WebSocketClientRegistry.reserveTakeover`), released when
/// dropped (`releaseTakeover`).
struct Reservation<'a> {
    registry: &'a Registry,
    client_id: String,
    connection: u64,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        let mut taking_over = self.registry.taking_over.lock();
        if taking_over.get(&self.client_id) == Some(&self.connection) {
            taking_over.remove(&self.client_id);
        }
    }
}

#[derive(Default)]
pub struct Registry {
    clients: Mutex<HashMap<String, Client>>,
    /// The connection numbers handed out so far.
    connections: std::sync::atomic::AtomicU64,
    /// Client ids being taken over, by the connection taking each over (one at a time per id).
    taking_over: Mutex<HashMap<String, u64>>,
    /// The clients' registration order, eldest first (the `LinkedHashMap` order of upstream's `CircularHashMap`).
    order: Mutex<std::collections::VecDeque<String>>,
    /// `maxWebSocketExpectations` (init-only), `None` for no bound: registering a client past it evicts the eldest,
    /// whose channel then closes.
    max_clients: Option<usize>,
    /// Requests waiting for their client's answer, and whether each waits as a forward handler.
    pending: Mutex<HashMap<String, (bool, oneshot::Sender<Reply>)>>,
    /// Breakpoint holds waiting for their client (`BreakpointCallbackDispatcher`), by correlation id: the client, and
    /// where its typed answer goes.
    held: Held,
    /// `LocalCallbackRegistry`: callbacks in this process, answered directly instead of over a WebSocket.
    local: Mutex<HashMap<String, crate::class_callback::CallbackClass>>,
}

/// What a client answered for a correlation id.
pub enum Reply {
    /// The `value` JSON of an `HttpResponse` (or `HttpRequest` for forward callbacks) message.
    Message(Value),
    /// A `WebSocketErrorDTO`: upstream answers 404 with the message as body.
    Error(String),
    /// A breakpoint client's `HttpRequest` answer (the `value` JSON): continue with this request.
    Request(Value),
}

fn envelope(kind: &str, value: &Value) -> String {
    json::pretty(&json!({"type": kind, "value": json::pretty(value)}))
}

/// `WebSocketMessageSerializer.serialize` for a type without a serializer of its own (`WebSocketClientIdDTO`,
/// `PausedStreamFrameDTO`): the value is the plain `ObjectMapper`'s compact JSON (oracle).
fn compact_envelope(kind: &str, value: &Value) -> String {
    json::pretty(&json!({"type": kind, "value": value.to_string()}))
}

pub fn is_upgrade(request: &HttpRequest) -> bool {
    request.path == PATH
        && request.first_header("upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
        && request.first_header("sec-websocket-key").is_some()
}

impl Registry {
    /// Sends `request` (with a fresh correlation header) to `client_id` and waits for its answer.
    /// `None` when the client is not connected or never answers.
    pub async fn call(&self, client_id: &str, request: Value) -> Option<Reply> {
        if let Some(callback) = self.local(client_id).and_then(|c| c.response()) {
            return Some(local(move || callback.handle(&request)).await);
        }
        self.exchange(client_id, request, None, false).await
    }

    /// A forward callback's first leg: the client answers with the request to forward.
    pub async fn call_forward(&self, client_id: &str, request: Value) -> Option<Reply> {
        if let Some(class) = self.local(client_id) {
            return match (class.forward(), class.forward_and_response()) {
                (Some(f), _) => Some(local(move || f.handle(&request)).await),
                (None, Some(f)) => Some(local(move || f.handle(&request)).await),
                (None, None) => None,
            };
        }
        self.exchange(client_id, request, None, true).await
    }

    /// Registers an in-process object callback under `client_id` (`LocalCallbackRegistry.registerCallback`).
    pub fn register_local(&self, client_id: &str, callbacks: crate::class_callback::CallbackClass) {
        self.local.lock().insert(client_id.to_string(), callbacks);
    }

    fn local(&self, client_id: &str) -> Option<crate::class_callback::CallbackClass> {
        self.local.lock().get(client_id).cloned()
    }

    /// A forward callback's second leg (`sendClientMessage` with a response): the request that was sent and the
    /// response it got, as an `HttpRequestAndHttpResponse`; the client answers with the response to return.
    pub async fn call_with_response(&self, client_id: &str, request: Value, response: Value) -> Option<Reply> {
        if let Some(callback) = self.local(client_id).and_then(|c| c.forward_and_response()) {
            return Some(local(move || callback.handle_response(&request, &response)).await);
        }
        self.exchange(client_id, request, Some(response), false).await
    }

    /// `(clients, response handlers, forward handlers)` for the WebSocket callback metrics: registered clients, and
    /// the requests waiting for an answer, a forward callback's first leg being a forward handler.
    pub fn counts(&self) -> (usize, usize, usize) {
        let pending = self.pending.lock();
        let forward = pending.values().filter(|(f, _)| *f).count();
        (self.clients.lock().len(), pending.len() - forward, forward)
    }

    /// `WebSocketClientRegistry.reset`: every client leaves the registry (its connection closes).
    pub fn reset(&self) {
        let mut clients = self.clients.lock();
        clients.clear();
        self.order.lock().clear();
    }

    /// A registry bounded by `maxWebSocketExpectations` (`WebSocketClientRegistry`'s `CircularHashMap`).
    pub fn with_max_clients(max_clients: usize) -> Registry {
        Registry { max_clients: Some(max_clients), ..Default::default() }
    }

    /// `clientRegistry.put`: a new id goes last (a known one keeps its place), then the eldest clients past
    /// `maxWebSocketExpectations` are evicted, which drops their senders and so closes their channels. The connection
    /// the id was registered to before, if any.
    fn add_client(&self, client_id: &str, client: Client) -> Option<Client> {
        let mut clients = self.clients.lock();
        let mut order = self.order.lock();
        let previous = clients.insert(client_id.to_string(), client);
        if previous.is_none() {
            order.push_back(client_id.to_string());
        }
        if let Some(max) = self.max_clients {
            while clients.len() > max {
                let Some(eldest) = order.pop_front() else { break };
                clients.remove(&eldest);
            }
        }
        previous
    }

    /// `unregisterClient(clientId, channel)`: removes the id when it is still registered to `connection`; false when
    /// it is registered to another connection meanwhile, whose state (breakpoints, holds) is then left alone.
    fn remove_client(&self, client_id: &str, connection: u64) -> bool {
        let mut clients = self.clients.lock();
        match clients.get(client_id) {
            Some(c) if c.connection != connection => false,
            Some(_) => {
                clients.remove(client_id);
                self.order.lock().retain(|id| id != client_id);
                true
            }
            None => true,
        }
    }

    /// `registeredChannel`: the open connection `client_id` is registered to.
    fn registered(&self, client_id: &str) -> Option<Client> {
        self.clients.lock().get(client_id).filter(|c| !c.tx.is_closed()).cloned()
    }

    /// `reserveTakeover`: false when another connection is taking `client_id` over.
    fn reserve(&self, client_id: &str, connection: u64) -> Option<Reservation<'_>> {
        let mut taking_over = self.taking_over.lock();
        match taking_over.get(client_id) {
            Some(&other) if other != connection => None,
            _ => {
                taking_over.insert(client_id.to_string(), connection);
                Some(Reservation { registry: self, client_id: client_id.to_string(), connection })
            }
        }
    }

    /// `CallbackClientIdClaim.decide`: whether a connection authenticated as `identity` may take over the client id
    /// `registered` holds. The same named caller at once; otherwise only once `registered` is gone: closed, or silent
    /// for [`LIVENESS_TIMEOUT`] after a ping. When it answers, another named caller is refused as such.
    async fn decide(registered: &Client, identity: Option<&str>) -> Decision {
        let both_named = identity.is_some() && registered.identity.is_some();
        if both_named && registered.identity.as_deref() == identity {
            return Decision::Allow;
        }
        let answered = if both_named { Decision::RefuseOtherPrincipal } else { Decision::RefuseRegisteredConnectionAnswers };
        let pong = registered.pong.notified();
        if registered.tx.send(Outgoing::Ping).is_err() {
            return Decision::Allow;
        }
        tokio::select! {
            _ = pong => answered,
            _ = registered.tx.closed() => Decision::Allow,
            _ = tokio::time::sleep(LIVENESS_TIMEOUT) => Decision::AllowAndCloseUnresponsive,
        }
    }

    /// `CallbackWebSocketServerHandler.claimClientId` / `takeOver`: waits until this connection may take `client_id`;
    /// the reservation to hold until it is registered and the connection to close then, or the refusal's status and
    /// reason.
    async fn claim(&self, client_id: &str, connection: u64, identity: Option<&str>) -> Result<(Reservation<'_>, Option<Client>), (u16, &'static str)> {
        loop {
            let registered = self.registered(client_id);
            let decision = match &registered {
                None => Decision::Allow,
                Some(r) => Self::decide(r, identity).await,
            };
            match decision {
                Decision::RefuseOtherPrincipal => return Err((403, "registered to an open connection, authenticated as another caller, that answered a ping")),
                Decision::RefuseRegisteredConnectionAnswers => return Err((409, "registered to an open connection that answered a ping")),
                Decision::Allow | Decision::AllowAndCloseUnresponsive => {}
            }
            let Some(reservation) = self.reserve(client_id, connection) else {
                return Err((409, "being taken over by another connection"));
            };
            // read again under the reservation: a connection that registered meanwhile is decided against instead
            let decided_against = registered.as_ref().map(|r| r.connection);
            if self.registered(client_id).is_some_and(|now| Some(now.connection) != decided_against) {
                drop(reservation);
                continue;
            }
            let replaced = registered.filter(|_| decision == Decision::AllowAndCloseUnresponsive);
            return Ok((reservation, replaced));
        }
    }

    async fn exchange(&self, client_id: &str, mut request: Value, response: Option<Value>, forward: bool) -> Option<Reply> {
        let correlation = uuid::Uuid::new_v4().to_string();
        let headers = request.as_object_mut()?.entry("headers").or_insert_with(|| json!({}));
        if let Some(h) = headers.as_object_mut() {
            h.insert(CORRELATION_HEADER.into(), json!([correlation]));
        }
        let message = match response {
            None => envelope(HTTP_REQUEST, &request),
            Some(response) => envelope(HTTP_REQUEST_AND_RESPONSE, &json!({"httpRequest": request, "httpResponse": response})),
        };
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(correlation.clone(), (forward, tx));
        let sent = self.clients.lock().get(client_id).is_some_and(|c| c.tx.send(Outgoing::Text(message)).is_ok());
        let reply = if sent { tokio::time::timeout(RESPONSE_TIMEOUT, rx).await.ok().and_then(Result::ok) } else { None };
        self.pending.lock().remove(&correlation);
        reply
    }

    /// A breakpoint hold (`dispatchRequest` / `dispatchResponse`): sends the request (with the `correlation`, breakpoint
    /// id and timestamp headers), or the request and response, to `client_id` and waits up to `timeout` for its answer.
    /// `on_sent` runs once the message is on its way (the dispatcher's future exists), before the wait.
    #[allow(clippy::too_many_arguments)]
    pub async fn hold(&self, client_id: &str, correlation: String, mut request: Value, extra_headers: &[(&str, String)], response: Option<Value>, timeout: Duration, on_sent: impl FnOnce()) -> Result<Reply, Unanswered> {
        let headers = request.as_object_mut().ok_or(Unanswered::Released)?.entry("headers").or_insert_with(|| json!({}));
        if let Some(h) = headers.as_object_mut() {
            // The oracle lists the hold's headers last added first: timestamp, breakpoint id, correlation.
            for (name, value) in extra_headers.iter().rev() {
                h.insert((*name).into(), json!([value]));
            }
            h.insert(CORRELATION_HEADER.into(), json!([correlation]));
        }
        let message = match response {
            None => envelope(HTTP_REQUEST, &request),
            Some(response) => envelope(HTTP_REQUEST_AND_RESPONSE, &json!({"httpRequest": request, "httpResponse": response})),
        };
        self.park(client_id, correlation, message, timeout, on_sent).await
    }

    /// The ids of the connected callback clients.
    pub fn client_ids(&self) -> Vec<String> {
        self.clients.lock().keys().cloned().collect()
    }

    /// A stream-frame hold (`StreamFrameCallbackDispatcher.dispatchFrame`): sends `frame` (a `PausedStreamFrameDTO`
    /// without its correlation id) under `correlation` and waits for the client's `StreamFrameDecisionDTO`.
    pub async fn hold_frame(&self, client_id: &str, correlation: String, mut frame: serde_json::Map<String, Value>, timeout: Duration, on_sent: impl FnOnce()) -> Result<Value, Unanswered> {
        frame.insert("correlationId".into(), json!(correlation));
        frame.sort_keys();
        let message = compact_envelope(PAUSED_FRAME, &Value::Object(frame));
        match self.park(client_id, correlation, message, timeout, on_sent).await? {
            Reply::Message(v) => Ok(v),
            _ => Err(Unanswered::Released),
        }
    }

    /// Sends `message` to `client_id` and waits up to `timeout` for the answer correlated by `correlation`. The hold
    /// is forgotten when this ends (see [`Parked`] for a wait dropped with its stream).
    async fn park(&self, client_id: &str, correlation: String, message: String, timeout: Duration, on_sent: impl FnOnce()) -> Result<Reply, Unanswered> {
        let (tx, rx) = oneshot::channel();
        self.held.lock().insert(correlation.clone(), (client_id.to_string(), tx));
        let deadline = tokio::time::Instant::now() + timeout;
        let mut parked = Parked { held: self.held.clone(), correlation, deadline, ended: true };
        if !self.clients.lock().get(client_id).is_some_and(|c| c.tx.send(Outgoing::Text(message)).is_ok()) {
            return Err(Unanswered::NotConnected);
        }
        on_sent();
        parked.ended = false;
        let answer = tokio::time::timeout_at(deadline, rx).await;
        parked.ended = true;
        match answer {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => Err(Unanswered::Released),
            Err(_) => Err(Unanswered::TimedOut),
        }
    }

    /// Breakpoint holds in flight (`BreakpointCallbackDispatcher.inFlightCount`).
    pub fn held_count(&self) -> usize {
        self.held.lock().len()
    }

    /// `BreakpointCallbackDispatcher.reset` / `autoCompleteForClient`: holds end as if auto-continued.
    pub fn release_held(&self, client_id: Option<&str>) {
        self.held.lock().retain(|_, (client, _)| client_id.is_some_and(|c| c != client));
    }

    fn received(&self, text: &str) {
        let Ok(message) = serde_json::from_str::<Value>(text) else { return };
        let kind = message.get("type").and_then(Value::as_str).unwrap_or_default();
        let Some(value) = message.get("value").and_then(Value::as_str).and_then(|v| serde_json::from_str::<Value>(v).ok()) else {
            return;
        };
        if matches!(kind, HTTP_RESPONSE | HTTP_REQUEST) && let Some((_, tx)) = correlation_id(&value).and_then(|c| self.held.lock().remove(&c)) {
            let _ = tx.send(if kind == HTTP_REQUEST { Reply::Request(value) } else { Reply::Message(value) });
            return;
        }
        if kind == FRAME_DECISION {
            if let Some((_, tx)) = value.get("correlationId").and_then(Value::as_str).and_then(|c| self.held.lock().remove(c)) {
                let _ = tx.send(Reply::Message(value));
            }
            return;
        }
        if kind == ERROR {
            let correlation = value.get("webSocketCorrelationId").and_then(Value::as_str);
            if let Some((_, tx)) = correlation.and_then(|c| self.held.lock().remove(c)) {
                let _ = tx.send(Reply::Error(value.get("message").and_then(Value::as_str).unwrap_or_default().to_string()));
                return;
            }
        }
        let (correlation, reply) = match kind {
            HTTP_RESPONSE | HTTP_REQUEST => (correlation_id(&value), Reply::Message(value)),
            ERROR => (
                value.get("webSocketCorrelationId").and_then(Value::as_str).map(str::to_string),
                Reply::Error(value.get("message").and_then(Value::as_str).unwrap_or_default().to_string()),
            ),
            _ => return,
        };
        if let Some((_, tx)) = correlation.and_then(|c| self.pending.lock().remove(&c)) {
            let _ = tx.send(reply);
        }
    }

    /// Completes the upgrade on `stream` and serves the client until it disconnects. Its frames are read and written on
    /// the connection's event loop, which a runtime LLM call may block (`connections`). `identity` names the caller
    /// control-plane authentication admitted ([`crate::auth::principal_identity`]). The client's id once the
    /// connection ends, unless the id was refused or is registered to another connection by then (whose state stays).
    pub async fn serve<S>(&self, state: &crate::state::State, request: &HttpRequest, mut stream: S, identity: Option<String>) -> Option<String>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let connections = &state.connections;
        let client_id = request.first_header(REGISTRATION_HEADER).map(str::to_string).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let connection = self.connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (reservation, replaced) = match self.claim(&client_id, connection, identity.as_deref()).await {
            Ok(claimed) => claimed,
            Err((status, reason)) => {
                if state.info_enabled() {
                    let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Info, "callback web socket upgrade rejected with status {} - client id {} is {}")
                        .args([status.to_string(), crate::cors_origin::escape_for_log(&client_id), reason.to_string()]);
                    state.log.message(entry);
                }
                let reason_phrase = if status == 403 { "Forbidden" } else { "Conflict" };
                let _ = stream.write_all(format!("HTTP/1.1 {status} {reason_phrase}\r\ncontent-length: 0\r\n\r\n").as_bytes()).await;
                let _ = stream.shutdown().await;
                return None;
            }
        };
        let accept = derive_accept_key(request.first_header("sec-websocket-key").unwrap_or_default().as_bytes());
        // Netty's handshaker writes the extra headers it is given ahead of its own
        let head = format!(
            "HTTP/1.1 101 Switching Protocols\r\n{REGISTRATION_HEADER}: {client_id}\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-accept: {accept}\r\n\r\n"
        );
        if stream.write_all(head.as_bytes()).await.is_err() {
            return None;
        }
        let ws = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
        let (mut sink, mut source) = ws.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Outgoing>();
        let pong = Arc::new(tokio::sync::Notify::new());
        let previous = self.add_client(&client_id, Client { tx, connection, identity, pong: pong.clone() });
        drop(reservation);
        // the connection decided against, closed once this one has the id; one replaced by the same caller stays open
        match (replaced, previous) {
            (Some(replaced), previous) => {
                let _ = replaced.tx.send(Outgoing::Close);
                if let Some(previous) = previous.filter(|p| p.connection != replaced.connection) {
                    let _ = previous.tx.send(Outgoing::Detach);
                }
            }
            (None, Some(previous)) => {
                let _ = previous.tx.send(Outgoing::Detach);
            }
            (None, None) => {}
        }
        // the client has seen its id only once it is registered: a second claim made right after the frame must find it
        if sink.send(Message::text(compact_envelope(CLIENT_ID, &json!({"clientId": client_id})))).await.is_err() {
            self.remove_client(&client_id, connection);
            return None;
        }
        let mut detached = false;
        let worker = crate::server::current_worker();
        let loop_free = || async move {
            if let Some(event_loop) = worker {
                connections.loop_free(event_loop).await;
            }
        };
        loop {
            tokio::select! {
                outgoing = rx.recv(), if !detached => match outgoing {
                    Some(Outgoing::Text(text)) => {
                        loop_free().await;
                        if sink.send(Message::text(text)).await.is_err() { break }
                    }
                    Some(Outgoing::Ping) => {
                        if sink.send(Message::Ping(Default::default())).await.is_err() { break }
                    }
                    Some(Outgoing::Detach) => detached = true,
                    Some(Outgoing::Close) | None => break,
                },
                incoming = source.next() => {
                    loop_free().await;
                    match incoming {
                        Some(Ok(Message::Text(text))) => self.received(&text),
                        Some(Ok(Message::Ping(p))) => { let _ = sink.send(Message::Pong(p)).await; }
                        Some(Ok(Message::Pong(_))) => pong.notify_waiters(),
                        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                        Some(Ok(_)) => break,
                    }
                }
            }
        }
        if !self.remove_client(&client_id, connection) {
            return None;
        }
        self.release_held(Some(&client_id));
        Some(client_id)
    }
}

/// Runs an in-process callback off the async workers; an `Err` is answered as the client's error would be.
async fn local(work: impl FnOnce() -> Result<Value, crate::class_callback::CallbackError> + Send + 'static) -> Reply {
    match crate::class_callback::run(work).await {
        Ok(value) => Reply::Message(value),
        Err(error) => Reply::Error(error.to_string()),
    }
}

/// The frame a client's `HttpResponse` answer arrived in, as `WebSocketMessageSerializer` writes it.
pub fn received_text(value: &Value) -> String {
    json!({"type": HTTP_RESPONSE, "value": value.to_string()}).to_string()
}

fn correlation_id(value: &Value) -> Option<String> {
    let headers = value.get("headers")?;
    let map = match headers {
        Value::Object(o) => o.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Vec<_>>(),
        Value::Array(entries) => entries
            .iter()
            .filter_map(|e| Some((e.get("name")?.as_str()?.to_string(), e.get("values")?.clone())))
            .collect(),
        _ => return None,
    };
    map.into_iter().find(|(k, _)| k.eq_ignore_ascii_case(CORRELATION_HEADER)).and_then(|(_, v)| match v {
        Value::Array(vs) => vs.first().and_then(Value::as_str).map(str::to_string),
        Value::String(s) => Some(s),
        _ => None,
    })
}

/// Drops the correlation header from a client's response before it is written (`removeHeader`).
pub fn strip_correlation(mut value: Value) -> Value {
    match value.get_mut("headers") {
        Some(Value::Object(o)) => {
            o.retain(|k, _| !k.eq_ignore_ascii_case(CORRELATION_HEADER));
        }
        Some(Value::Array(entries)) => {
            entries.retain(|e| !e.get("name").and_then(Value::as_str).is_some_and(|n| n.eq_ignore_ascii_case(CORRELATION_HEADER)));
        }
        _ => {}
    }
    value
}


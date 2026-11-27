//! HTTP/3 over QUIC (`Http3Server`, `Http3MockServerHandler`, `Http3RequestBridge`, `Http3ResponseWriter`): with
//! `http3Port` set, a UDP listener serves the same expectations and control plane as the TCP ports, with MockServer's
//! TLS certificate and ALPN `h3`. The QUIC transport takes `http3MaxIdleTimeout`, `http3InitialMaxData`,
//! `http3InitialMaxStreamDataBidirectional` and `http3InitialMaxStreamsBidirectional`. `/mockserver/http3status`
//! reports the port and the open connections. With `http3ConnectUdpEnabled`, an extended CONNECT with
//! `:protocol connect-udp` opens a UDP relay (`Http3ConnectUdpHandler`, see `connect_udp`).
//!
//! gRPC bidirectional streams (`Http3GrpcBidiStreamHandler`, with `grpcBidiStreamingEnabled`) are answered as their
//! messages arrive, through the same session and `INBOUND_STREAM` frame holds as HTTP/2 (`grpc_plane::open_bidi`).
//!
//! A request stream whose client takes none of its response for `responseWriteStallTimeoutMillis` is reset
//! (`Http3StreamWriteStallHandler`, `write_stall::Http3Bidi`, wrapped around each accepted stream by `raw_headers`).
//!
//! `Alt-Svc` advertising on the TCP ports is `handler::alt_svc`. Not built yet: a QPACK dynamic table
//! (`http3QpackMaxTableCapacity` is accepted, the encoder never uses one).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};

use crate::handler::{self, Outcome};
use crate::reply::Reply;
use crate::request::{self, HttpRequest, MultiMap};
use crate::state::State;
use crate::udp_start::{UdpListener, UdpStartFailure};

mod peer_grants;
mod raw_headers;

/// The running listener.
pub struct Http3 {
    pub port: u16,
    active: Arc<AtomicUsize>,
    /// Taken by [`Http3::stop`], so the endpoint's driver can end once its accept loop and connections have.
    endpoint: std::sync::Mutex<Option<quinn::Endpoint>>,
    /// The endpoint's socket, closed when the last of quinn's references to it is dropped.
    socket: std::sync::Weak<dyn quinn::AsyncUdpSocket>,
}

/// `Http3Server.STOP_TIMEOUT_SECONDS`.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

impl Http3 {
    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    /// `Http3Server.stop`: the port is free for a restart when the stop returns (`channel.close().sync()` and the
    /// event loop's termination upstream). quinn closes the socket only when its endpoint driver, the accept loop and
    /// every connection have let go of it, so the stop waits for that, up to [`STOP_TIMEOUT`].
    pub async fn stop(&self) {
        let endpoint = self.endpoint.lock().unwrap().take();
        let Some(endpoint) = endpoint else { return };
        endpoint.close(quinn::VarInt::from_u32(0), b"");
        drop(endpoint);
        let deadline = std::time::Instant::now() + STOP_TIMEOUT;
        while self.socket.strong_count() > 0 && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        if self.socket.strong_count() > 0 {
            tracing::warn!("HTTP/3 (QUIC) event loop did not terminate within {}s, so UDP port {} may still be bound", STOP_TIMEOUT.as_secs(), self.port);
        }
    }
}

/// `GET /mockserver/http3status`.
pub fn status_json(state: &State) -> String {
    let (port, active) = match state.http3.get() {
        Some(h3) => (i64::from(h3.port), h3.active_connections()),
        None => (-1, 0),
    };
    format!("{{\"enabled\":{},\"port\":{port},\"activeConnections\":{active}}}", port > 0)
}

/// `Http3Server.start`: binds `http3Port` (UDP) when it is positive. A start that fails refuses the server's start
/// (`MockServer.startHttp3Server`, `Http3StartupException`), a port above 65535 included.
pub fn start(state: &Arc<State>) -> Result<(), UdpStartFailure> {
    let configured = state.config.hot_int(crate::config::Hot::Http3Port, 0);
    if configured <= 0 {
        return Ok(());
    }
    use crate::recorded::{Kind, LogEntry};
    // `Http3Server.buildQuicSslContext`, before the UDP port is bound (and before a port is stamped on entries): a
    // key-and-certificate factory of its own loads the CA.
    crate::tls::log_authority_loaded(state, true);
    // It reads a fixed `privateKeyPath`/`x509CertificatePath` pair first, eagerly too.
    if let Some(causes) = state.tls.as_ref().and_then(|tls| tls.quic_fixed_pair_causes(&state.config)) {
        return Err(UdpStartFailure::caused_by(UdpListener::Http3, configured, &causes));
    }
    // `buildQuicSslContext` reads `tlsMutualAuthenticationCertificateChain` eagerly (the TCP path only at a handshake),
    // so a chain that cannot be read refuses the start, before the port is checked.
    if let Some(causes) = crate::tls::mutual_authentication_chain_causes(&state.config) {
        return Err(UdpStartFailure::caused_by(UdpListener::Http3, configured, &causes));
    }
    let port = u16::try_from(configured).map_err(|_| UdpStartFailure::out_of_range(UdpListener::Http3, configured))?;
    let h3 = bind(state, port)?;
    // Logged while the server starts, before a port is stamped on entries (`MockServer.startHttp3Server`).
    let entry = LogEntry::new(Kind::ServerConfiguration, "HTTP/3 (QUIC) server started on UDP port: {}").args([serde_json::json!(h3.port)]).without_port();
    crate::log::info_event(state, entry);
    state.add_local_port(h3.port);
    let _ = state.http3.set(h3);
    Ok(())
}

fn bind(state: &Arc<State>, port: u16) -> Result<Http3, UdpStartFailure> {
    let other = |e: &dyn std::fmt::Display| UdpStartFailure::other(UdpListener::Http3, i64::from(port), e.to_string());
    let tls = state.tls.as_ref().ok_or_else(|| other(&"no TLS configuration"))?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls.quic_config()).map_err(|e| other(&e))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(peer_grants::GrantsServerConfig(Arc::new(crypto))));
    let long = |name: &str, default: i64| state.config.int_property(name, default).max(0) as u64;
    let var = |v: u64| quinn::VarInt::from_u64(v).unwrap_or(quinn::VarInt::MAX);
    let mut transport = quinn::TransportConfig::default();
    let idle = long("http3MaxIdleTimeout", 5000);
    transport.max_idle_timeout(if idle == 0 { None } else { quinn::IdleTimeout::try_from(Duration::from_millis(idle)).ok() });
    transport.receive_window(var(long("http3InitialMaxData", 10_000_000)));
    transport.stream_receive_window(var(long("http3InitialMaxStreamDataBidirectional", 1_000_000)));
    transport.max_concurrent_bidi_streams(var(long("http3InitialMaxStreamsBidirectional", 100)));
    server.transport_config(Arc::new(transport));
    let socket = bind_port(state, port)?;
    let runtime = Arc::new(quinn::TokioRuntime);
    let socket = quinn::Runtime::wrap_udp_socket(&*runtime, socket).map_err(|e| other(&e))?;
    let weak_socket = Arc::downgrade(&socket);
    let endpoint = quinn::Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), Some(server), socket, runtime).map_err(|e| other(&e))?;
    let port = endpoint.local_addr().map_err(|e| other(&e))?.port();
    let active = Arc::new(AtomicUsize::new(0));
    // `Http3Server.start` reads `http3ConnectUdpEnabled` once: the SETTINGS frame and the per-stream handler agree.
    let connect_udp = state.config.bool_property("http3ConnectUdpEnabled", false);
    tokio::spawn(accept_loop(state.clone(), endpoint.clone(), active.clone(), connect_udp));
    Ok(Http3 { port, active, endpoint: std::sync::Mutex::new(Some(endpoint)), socket: weak_socket })
}

/// `Http3Server.bindExplicitPort` and the check after it: the listener binds `localBoundIP` when it is set
/// (`Ipv4UdpPortProbe.listenerAddress`), and a port another application holds on the IPv4 wildcard, which macOS would
/// let this dual-stack socket share while delivering its localhost datagrams to that application, is refused before
/// anything is bound, or after the bind when it was taken in between.
fn bind_port(state: &State, port: u16) -> Result<std::net::UdpSocket, UdpStartFailure> {
    let unavailable = |e: &std::io::Error| UdpStartFailure::bind(UdpListener::Http3, i64::from(port), e);
    let address = crate::udp_probe::listener_address(&state.config, port).map_err(|e| unavailable(&e))?;
    if crate::udp_probe::shadowed_on_ipv4_probed(&state.config, address, port) {
        return Err(UdpStartFailure::ipv4_wildcard_conflict(UdpListener::Http3, port));
    }
    let socket = crate::udp_probe::bind(address, port).map_err(|e| unavailable(&e))?;
    // a QUIC client resends what reached the listener during the check
    if crate::udp_probe::loopback_reaches_another_socket(&socket, &mut Vec::new()) {
        return Err(UdpStartFailure::ipv4_wildcard_conflict(UdpListener::Http3, port));
    }
    Ok(socket)
}

/// A dual-stack wildcard socket (`new InetSocketAddress(port)`), else IPv4 only where IPv6 is unavailable. A port the
/// dual-stack bind finds in use is not tried again on IPv4 alone: macOS would let that bind share the port with the
/// socket holding it.
pub(crate) fn udp_socket(port: u16) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let v6 = || -> std::io::Result<std::net::UdpSocket> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(false)?;
        socket.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())?;
        Ok(socket.into())
    };
    v6().or_else(|e| match e.kind() {
        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied => Err(e),
        _ => std::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port))),
    })
}

async fn accept_loop(state: Arc<State>, endpoint: quinn::Endpoint, active: Arc<AtomicUsize>, connect_udp: bool) {
    while let Some(incoming) = endpoint.accept().await {
        let (state, active) = (state.clone(), active.clone());
        tokio::spawn(async move {
            // the QUIC handshake, TLS 1.3 inside it, timed as the TCP listeners time theirs
            let started = std::time::Instant::now();
            let connection = incoming.await;
            let outcome = match &connection {
                Ok(_) => Ok(Some("1.3")),
                Err(quinn::ConnectionError::TimedOut) => Err("timeout"),
                Err(quinn::ConnectionError::VersionMismatch) => Err("peer_incompatible"),
                Err(quinn::ConnectionError::TransportError(_)) => Err("transport_error"),
                Err(_) => Err("connection_closed"),
            };
            crate::metrics::tls_handshake(&state.config, started.elapsed().as_secs_f64(), outcome);
            let Ok(connection) = connection else { return };
            let _measured = crate::metrics::ServerConnection::open(&state.config, "udp", true);
            active.fetch_add(1, Ordering::SeqCst);
            serve_connection(state, connection, connect_udp).await;
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

async fn serve_connection(state: Arc<State>, connection: quinn::Connection, connect_udp: bool) {
    let client_certificates = Arc::new(peer_certificates(&connection));
    let quic = connection.clone();
    // `Http3Server`: SETTINGS_ENABLE_CONNECT_PROTOCOL is advertised only with CONNECT-UDP enabled.
    let mut builder = h3::server::builder();
    builder.enable_extended_connect(connect_udp);
    // Netty's HTTP/3 codec sends no reserved ("GREASE") frames or settings; h3 would by default.
    builder.send_grease(false);
    // `Http3Server`: SETTINGS_MAX_FIELD_SECTION_SIZE is `maxHeaderSize`, the header section limit of every protocol;
    // `raw_headers` enforces it as Netty does, before h3's own check (a `431`) is reached.
    let limit = crate::config::max_header_size(&state.config) as u64;
    builder.max_field_section_size(limit);
    // CONNECT-UDP reads `:protocol` and `:authority` as sent, which h3 alone would refuse (`raw_headers`).
    let raw_authorities = connect_udp.then(raw_headers::RawAuthorities::default);
    let refusals = raw_headers::Refusals::default();
    let sections = raw_headers::Sections { limit, raw: raw_authorities.clone(), refusals: refusals.clone() };
    let mut h3 = match builder.build::<_, Bytes>(raw_headers::Connection::new(connection, sections, state.clone())).await {
        Ok(h3) => h3,
        Err(_) => return,
    };
    while let Ok(Some(resolver)) = h3.accept().await {
        let (state, quic, client_certificates) = (state.clone(), quic.clone(), client_certificates.clone());
        let (raw_authorities, refusals) = (raw_authorities.clone(), refusals.clone());
        tokio::spawn(async move {
            let Ok((head, mut stream)) = resolver.resolve_request().await else { return };
            // a header section over the limit: h3 resolved a stand-in, which is not served
            let refusal = refusals.lock().unwrap().remove(&stream.id().into_inner());
            if let Some(refusal) = refusal {
                return refuse_section(&state, &quic, &mut stream, refusal).await;
            }
            let raw_authority = raw_authorities.and_then(|raw| raw.lock().unwrap().remove(&stream.id().into_inner()));
            let remote = quic.remote_address();
            let remote = SocketAddr::new(remote.ip().to_canonical(), remote.port());
            let peer = Peer { client_certificates, refusals, remote };
            serve_request(state, quic, peer, head, stream, connect_udp, raw_authority).await;
        });
    }
    // Wait for the peer's close so the connection counts as open until then.
    quic.closed().await;
}

/// The TLS client's certificate chain, as `clientCertificateChain` entries (`captureClientCertificates`).
fn peer_certificates(connection: &quinn::Connection) -> Vec<crate::tls::client_cert::ClientCertificate> {
    connection
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>().ok())
        .map(|chain| chain.iter().filter_map(|c| crate::tls::client_cert::describe(c)).collect())
        .unwrap_or_default()
}

struct Peer {
    client_certificates: Arc<Vec<crate::tls::client_cert::ClientCertificate>>,
    /// The connection's field sections over `maxHeaderSize` (`raw_headers`): a request whose trailers are among them
    /// is not served.
    refusals: raw_headers::Refusals,
    /// The client's address, which a request for a control-plane path carries as its `remoteAddress`.
    remote: SocketAddr,
}

impl Peer {
    fn refusal(&self, id: h3::quic::StreamId) -> Option<raw_headers::Refusal> {
        self.refusals.lock().unwrap().remove(&id.into_inner())
    }
}

/// `Http3MockServerHandler.exceptionCaught` for a header or trailer section over `maxHeaderSize`: one WARN naming the
/// client, then, as Netty's codec has it, the request stream ended (`ctx.close()`: a FIN, nothing written) and the
/// connection closed with `H3_EXCESSIVE_LOAD` and the codec's message. Quinn's close abandons stream data not yet
/// transmitted, so the close waits (up to 100 ms) until the connection has sent a STREAM frame since the FIN, then
/// 20 ms more, as in [`interim_then_reset`].
async fn refuse_section<S: h3::quic::SendStream<Bytes>>(state: &State, quic: &quinn::Connection, stream: &mut h3::server::RequestStream<S, Bytes>, refusal: raw_headers::Refusal) {
    let format = if refusal.trailers {
        "closing HTTP/3 connection from:{}because a request's trailer section is larger than maxHeaderSize:{}"
    } else {
        "closing HTTP/3 connection from:{}because a request's header section is larger than maxHeaderSize:{}"
    };
    let remote = quic.remote_address();
    let remote = SocketAddr::new(remote.ip().to_canonical(), remote.port());
    let limit = crate::config::max_header_size(&state.config);
    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Warn, format).args([crate::http1::socket_address_arg(remote), crate::recorded::Arg::from(serde_json::json!(limit))]);
    crate::log::warn_event(state, entry);
    let sent_before = quic.stats().frame_tx.stream;
    if stream.finish().await.is_ok() {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(100);
        while quic.stats().frame_tx.stream == sent_before && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // H3_EXCESSIVE_LOAD
    quic.close(quinn::VarInt::from_u32(0x107), refusal.reason.as_bytes());
}

type Stream = h3::server::RequestStream<raw_headers::Peeked<crate::write_stall::Http3Bidi>, Bytes>;

async fn serve_request(state: Arc<State>, quic: quinn::Connection, peer: Peer, head: http::Request<()>, mut stream: Stream, connect_udp_enabled: bool, raw_authority: Option<String>) {
    // `Http3ConnectUdpHandler` sits before the mock handler; a plain CONNECT passes through to it. The method and
    // `:protocol` are compared case-insensitively, the latter lower-cased by `raw_headers` for h3.
    if connect_udp_enabled
        && head.method().as_str().eq_ignore_ascii_case("CONNECT")
        && head.extensions().get::<h3::ext::Protocol>() == Some(&h3::ext::Protocol::CONNECT_UDP)
    {
        return connect_udp(state, quic, head, stream, raw_authority).await;
    }
    // A response to `HEAD` is its header section alone (upstream cb56f3115, after 8.0.0): no DATA, no trailers.
    let head_only = head.method().as_str().eq_ignore_ascii_case("HEAD");
    // `maxRequestBodySize`, as the aggregator caps the TCP paths.
    let max = state.config.hot_int(crate::config::Hot::MaxRequestBodySize, i64::from(i32::MAX)).max(0) as usize;
    if let Some((outcome, body)) = open_bidi(&state, &head, &peer) {
        serve_bidi(state, &quic, &peer, stream, outcome, body, max).await;
        return;
    }
    let mut body = BytesMut::new();
    loop {
        match stream.recv_data().await {
            Ok(Some(mut chunk)) => {
                if max > 0 && body.len() + chunk.remaining() > max {
                    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "HTTP/3 request body size {} exceeds maxRequestBodySize {} -- rejecting with 413");
                    crate::log::entry(&state, &entry.args([serde_json::json!(body.len() + chunk.remaining()), serde_json::json!(max)]));
                    let body = Bytes::from_static(b"{\"error\":\"request body too large\"}");
                    let headers = vec![
                        ("content-type".to_string(), "application/json; charset=utf-8".to_string()),
                        ("content-length".into(), body.len().to_string()),
                        ("server".into(), "mockserver-http3".into()),
                    ];
                    let _ = send(&mut stream, 413, &headers, (!head_only).then_some(body)).await;
                    return;
                }
                while chunk.has_remaining() {
                    let piece = chunk.chunk();
                    body.extend_from_slice(piece);
                    let n = piece.len();
                    chunk.advance(n);
                }
                // Netty's direct-memory limit (`io.netty.maxDirectMemory`): the QUIC codec's next 16 KiB
                // buffer is refused while the aggregator holds the body; the handler's `exceptionCaught` logs it at
                // WARN and `ctx.close()` ends the request stream with a FIN, nothing written.
                if let Some((used, max)) = crate::config::netty_max_direct_memory(&state.config).and_then(|max| crate::client::h3_request_direct_memory_refusal(body.len(), max)) {
                    let message = format!("failed to allocate {} byte(s) of direct memory (used: {used}, max: {max})", crate::client::H3_DIRECT_MEMORY_BUFFER);
                    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "exception in HTTP/3 request handler: {}");
                    crate::log::warn_event(&state, entry.args([serde_json::json!(message)]));
                    let _ = stream.finish().await;
                    return;
                }
            }
            Ok(None) => break,
            Err(_) => return,
        }
    }
    // trailers over `maxHeaderSize`: `raw_headers` ended the body there, and the request is not served
    if let Some(refusal) = peer.refusal(stream.id()) {
        return refuse_section(&state, &quic, &mut stream, refusal).await;
    }
    let mut request = to_request(&head, body.freeze(), &peer);
    if !decompress(&state, &mut request, max, &mut stream, head_only).await {
        return;
    }
    // `handleMcpOverHttp3`: MCP is answered before the pipeline, with its own framing.
    if crate::mcp::is_mcp_path(&request.path) {
        let mut observed = handler::observe(&state, &request);
        let result = crate::mcp::result(&state, &request).await;
        if let Some(observed) = observed.as_mut() {
            observed.answered(Some(result.status), Some("/mockserver/mcp"), None);
        }
        let mut headers = vec![("server".to_string(), "mockserver-http3".to_string())];
        if result.body.is_some() {
            headers.push(("content-type".into(), "application/json".into()));
        }
        if let Some(session) = result.session {
            headers.push(("mcp-session-id".into(), session));
        }
        if let Some(origin) = request.first_header("origin").filter(|o| !o.is_empty()) {
            headers.extend(crate::mcp::cors(&state, &request, origin.to_string()));
        }
        let _ = send(&mut stream, result.status, &headers, result.body.filter(|_| !head_only).map(Bytes::from)).await;
        return;
    }
    // `HttpState.setPort(request)` reads the request's socket address, which an HTTP/3 request lacks: the QUIC event
    // loop's thread-local port stays null, so what handling it logs carries no port.
    let mut observed = handler::observe(&state, &request);
    let mut outcome = crate::recorded::portless(handler::dispatch(&state, Arc::new(request), &Default::default())).await;
    handler::answered(&mut observed, &outcome, "HTTP_3");
    while let Outcome::GoAway { then, .. } = outcome {
        outcome = *then;
    }
    match outcome {
        // `FinalInformationalResponseWarning`: a 1xx (a 101 too, HTTP/3 has no upgrade) can only be an interim response
        // (RFC 9114 section 4.1), so its header section goes out alone and the stream is reset with H3_NO_ERROR; no
        // body or trailers follow it, whatever the method
        Outcome::Respond(reply) if crate::dataplane::is_final_informational("HTTP_3", reply.status) => {
            interim_then_reset(&quic, &mut stream, &reply).await;
        }
        Outcome::Stream { head, mut chunks, .. } if crate::dataplane::is_final_informational("HTTP_3", head.status) => {
            interim_then_reset(&quic, &mut stream, &head).await;
            while chunks.recv().await.is_some() {}
        }
        Outcome::Respond(reply) => {
            let body = (!head_only && !reply.body.is_empty()).then(|| reply.body.clone());
            let trailers: &[(String, String)] = if head_only { &[] } else { &reply.trailers };
            let _ = send_with_trailers(&mut stream, reply.status, &fields(&reply, false), body, trailers).await;
        }
        // HTTP/1.1 objects written straight to the stream's channel (a mocked SSE or streamed LLM response), turned into
        // frames by `Http3HttpObjectEncoder` (upstream 18b3a36e7): the head, each event as it falls due, then the last
        // content (`EMPTY_LAST_CONTENT`) as an empty DATA frame and the end of the stream, whether or not the response
        // keeps the connection. HEAD alike: this path never reaches the response writer.
        Outcome::Stream { head, chunks, .. } if head.written_as_http1_objects => {
            let _ = send_encoded(&mut stream, &head, chunks).await;
        }
        // `writeResponseToHead`: the headers end the stream; dropping the chunks closes the producer (`closeUpstream`).
        // Not a `grpcStreamResponse` answering a non-gRPC request (upstream 18b3a36e7): that one is written as HTTP
        // objects whatever the method, so a `HEAD` still gets its DATA frames and status trailers.
        Outcome::Stream { head, trailers: None, .. } if head_only => {
            let _ = send(&mut stream, head.status, &fields(&head, true), None).await;
        }
        Outcome::Stream { head, chunks, trailers, .. } => {
            let _ = send_stream(&mut stream, &head, chunks, trailers).await;
        }
        Outcome::Hang => {
            quic.closed().await;
        }
        Outcome::ResetConnection { .. } => quic.close(quinn::VarInt::from_u32(0x102), b""),
        Outcome::Reset(code) => stream.stop_stream(h3::error::Code::from(u64::from(code))),
        Outcome::Raw { .. } | Outcome::DropConnection | Outcome::WebSocketRelay { .. } | Outcome::WebSocket { .. } => stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED),
        Outcome::GoAway { .. } => unreachable!("unwrapped above"),
    }
}

/// `Http3MockServerHandler.decompress` with `Http3RequestBridge.headersAfterDecompression`: a `Content-Encoding` body
/// is decompressed as HTTP/1.1 and HTTP/2 decompress it. The decompressed bytes become the body and the wire bytes its
/// original body (when they differ); a `content-length` is replaced by the decompressed size and moved last, then the
/// `content-encoding`. One that decompresses past `maxRequestBodySize` is answered `413`; a corrupt one closes the
/// stream without a response. `false`: the request was refused and is not handled.
async fn decompress(state: &State, request: &mut HttpRequest, max: usize, stream: &mut Stream, head_only: bool) -> bool {
    if !request.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-encoding")) {
        return true;
    }
    let limit = if max > 0 { max } else { usize::MAX };
    let decoded = match handler::decode(request, limit) {
        Ok(None) => return true,
        Ok(Some(decoded)) if decoded.len() <= limit => decoded,
        Ok(Some(_)) => return too_large_decoded(state, stream, limit, head_only).await,
        Err(failure) if failure.too_large() => return too_large_decoded(state, stream, limit, head_only).await,
        Err(_) => {
            let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Warn, format!("HTTP/3 request body could not be decompressed -- closing stream {}", stream.id().into_inner()));
            crate::log::warn_event(state, entry);
            // `ctx.close()` on the request stream ends it with a FIN, nothing written
            let _ = stream.finish().await;
            return false;
        }
    };
    let had_length = request.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
    let encodings: Vec<(String, Vec<String>)> = request.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("content-encoding")).cloned().collect();
    request.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("content-encoding"));
    if had_length {
        request.headers.push(("content-length".into(), vec![decoded.len().to_string()]));
    }
    request.headers.extend(encodings);
    let raw = std::mem::replace(&mut request.body, decoded);
    if !raw.is_empty() && raw != request.body {
        request.original_body = Some(raw);
    }
    true
}

/// `sendPayloadTooLarge` after a body decompressed past `maxRequestBodySize`.
async fn too_large_decoded(state: &State, stream: &mut Stream, limit: usize, head_only: bool) -> bool {
    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "HTTP/3 decompressed request body size {} exceeds maxRequestBodySize {} -- rejecting with 413");
    crate::log::entry(state, &entry.args([serde_json::json!(limit + 1), serde_json::json!(limit)]));
    let body = Bytes::from_static(b"{\"error\":\"request body too large\"}");
    let headers = vec![
        ("content-type".to_string(), "application/json; charset=utf-8".to_string()),
        ("content-length".into(), body.len().to_string()),
        ("server".into(), "mockserver-http3".into()),
    ];
    let _ = send(stream, 413, &headers, (!head_only).then_some(body)).await;
    false
}

/// A final 1xx: its header section, then the stream reset with H3_NO_ERROR. Quinn's reset abandons stream data not
/// yet transmitted, where Netty flushes the header section before it resets, so the reset waits (up to 100 ms) until
/// the connection has sent a STREAM frame since the section was handed over, then 20 ms more, as that frame may have
/// been another stream's (the control stream's, early on a connection), and a client's QUIC stack may drop what it has
/// received but not yet read once the reset arrives.
async fn interim_then_reset(quic: &quinn::Connection, stream: &mut Stream, reply: &crate::reply::Reply) {
    let sent_before = quic.stats().frame_tx.stream;
    if stream.send_response(response(reply.status, &fields(reply, false))).await.is_ok() {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(100);
        while quic.stats().frame_tx.stream == sent_before && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    stream.stop_stream(h3::error::Code::H3_NO_ERROR);
}

/// `tryBeginGrpcBidi`: a gRPC bidi request that a `grpcBidiResponse` expectation matches is served as its DATA
/// arrives; the outcome, and where that DATA goes. `None` leaves the request to the accumulate-then-dispatch path.
fn open_bidi(state: &Arc<State>, head: &http::Request<()>, peer: &Peer) -> Option<(Outcome, tokio::sync::mpsc::UnboundedSender<Bytes>)> {
    use crate::grpc_plane::BidiTransport;
    let content_type = head.headers().get("content-type").map(|v| request::header_text(v.as_bytes()));
    let (body_tx, body_rx) = crate::grpc_plane::bidi_channel(state, BidiTransport::Http3, head.uri().path(), content_type.as_deref())?;
    let outcome = crate::grpc_plane::open_bidi(state, &to_request(head, Bytes::new(), peer), body_rx, BidiTransport::Http3).ok()?;
    Some((outcome, body_tx))
}

/// `Http3GrpcBidiStreamHandler`: inbound DATA feeds the session as it arrives (the client's FIN half-closes it) while
/// its messages are written as they are produced, then the trailers. Upstream's `onChannelInactive` (the stream reset,
/// the connection lost) and a body past `max` both end the session at once by dropping the response: the former
/// writes nothing more, the latter ends our side of the stream without trailers (`shutdownOutput`).
///
/// Trailers over `maxHeaderSize`: Netty's handler answers each DATA frame as it is decoded, before the
/// trailer section after it is refused, so the session keeps its input open (no half-close) and the response goes on
/// for up to [`REFUSED_BIDI_GRACE`] before it is dropped and the section refused.
async fn serve_bidi(state: Arc<State>, quic: &quinn::Connection, peer: &Peer, stream: Stream, outcome: Outcome, body: tokio::sync::mpsc::UnboundedSender<Bytes>, max: usize) {
    enum Inbound {
        Fin,
        Reset,
        TooLarge,
        Refused(raw_headers::Refusal, tokio::sync::mpsc::UnboundedSender<Bytes>),
    }
    let Outcome::Stream { head, chunks, trailers, .. } = outcome else { return };
    let id = stream.id();
    let (mut send, mut recv) = stream.split();
    let limit = crate::grpc_plane::max_message_size(&state);
    let reader_state = state.clone();
    let mut reader = Box::pin(async move {
        let state = reader_state;
        // Owned here, so the session sees the half-close as soon as this ends.
        let body = body;
        let (mut total, mut frame) = (0, BytesMut::new());
        loop {
            match recv.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let bytes = chunk.copy_to_bytes(chunk.remaining());
                    total += bytes.len();
                    if max > 0 && total > max {
                        let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "HTTP/3 bidi stream body size {} exceeds maxRequestBodySize {} -- resetting stream");
                        crate::log::entry(&state, &entry.args([serde_json::json!(total), serde_json::json!(max)]));
                        return Inbound::TooLarge;
                    }
                    frame.extend_from_slice(&bytes);
                    if !inside_message(&frame, limit) {
                        let _ = body.send(frame.split().freeze());
                    }
                }
                Ok(None) => {
                    if !frame.is_empty() {
                        let _ = body.send(frame.split().freeze());
                    }
                    if let Some(refusal) = peer.refusal(id) {
                        return Inbound::Refused(refusal, body);
                    }
                    return Inbound::Fin;
                }
                Err(_) => return Inbound::Reset,
            }
        }
    });
    let mut writer = Box::pin(send_stream(&mut send, &head, chunks, trailers));
    tokio::select! {
        // The response is done: nothing more is read.
        _ = &mut writer => return,
        inbound = &mut reader => match inbound {
            Inbound::Fin => {}
            Inbound::Reset => return,
            Inbound::TooLarge => {
                drop(writer);
                let _ = send.finish().await;
                return;
            }
            Inbound::Refused(refusal, open_input) => {
                let _ = tokio::time::timeout(REFUSED_BIDI_GRACE, &mut writer).await;
                drop(writer);
                drop(open_input);
                refuse_section(&state, quic, &mut send, refusal).await;
                return;
            }
        },
    }
    drop(reader);
    let _ = writer.await;
}

/// How long a gRPC bidi response goes on after the request's trailer section was refused (see [`serve_bidi`]).
const REFUSED_BIDI_GRACE: std::time::Duration = std::time::Duration::from_millis(100);

/// Whether `data`, the DATA received since the last hold unit, ends inside a gRPC message whose length prefix it has:
/// h3 hands a DATA frame's payload over in pieces as QUIC delivers them, so the pieces of one message are put back
/// together and a stream held at a breakpoint parks one DATA frame per message, as Netty's client sends them.
/// Anything else (a truncated prefix, a length past `limit`) goes on as it came.
fn inside_message(data: &[u8], limit: usize) -> bool {
    let mut rest = data;
    while rest.len() >= 5 {
        let length = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;
        if rest.len() < 5 + length {
            return length <= limit;
        }
        rest = &rest[5 + length..];
    }
    false
}

/// A streamed outcome: the head (without `content-length`), each chunk as it is produced, the trailers if any.
async fn send_stream<S: h3::quic::SendStream<Bytes>>(stream: &mut h3::server::RequestStream<S, Bytes>, head: &Reply, mut chunks: tokio::sync::mpsc::Receiver<Bytes>, trailers: Option<tokio::sync::oneshot::Receiver<Vec<(String, String)>>>) -> Result<(), h3::error::StreamError> {
    stream.send_response(response(head.status, &fields(head, true))).await?;
    while let Some(chunk) = chunks.recv().await {
        stream.send_data(chunk).await?;
    }
    if let Some(trailers) = trailers {
        let trailers = trailers.await.unwrap_or_default();
        if !trailers.is_empty() {
            stream.send_trailers(header_map(&trailers)).await?;
        }
    }
    stream.finish().await
}

/// `Http3HttpObjectEncoder`: the response head as a HEADERS frame (without `content-length`), each content as a DATA
/// frame, the terminal empty content as an empty DATA frame, then `shutdownOutput`.
async fn send_encoded(stream: &mut Stream, head: &Reply, mut chunks: tokio::sync::mpsc::Receiver<Bytes>) -> Result<(), h3::error::StreamError> {
    stream.send_response(response(head.status, &fields(head, true))).await?;
    while let Some(chunk) = chunks.recv().await {
        stream.send_data(chunk).await?;
    }
    stream.send_data(Bytes::new()).await?;
    stream.finish().await
}

fn header_map(pairs: &[(String, String)]) -> http::HeaderMap {
    let mut map = http::HeaderMap::new();
    for (name, value) in pairs {
        if let (Ok(n), Ok(v)) = (http::HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()), http::HeaderValue::from_str(value)) {
            map.append(n, v);
        }
    }
    map
}

/// `Http3RequestBridge.toHttpRequest`: `:authority` becomes the first `host` header; the query string is split on `&`
/// and `=` without decoding; no `content-length` is added, and nothing is decompressed.
fn to_request(head: &http::Request<()>, body: Bytes, peer: &Peer) -> HttpRequest {
    let target = head.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target, None),
    };
    let mut headers = MultiMap::new();
    if let Some(authority) = head.uri().authority() {
        request::push(&mut headers, "host", authority.as_str().to_string());
    }
    for (name, value) in head.headers() {
        request::push(&mut headers, name.as_str(), request::header_text(value.as_bytes()));
    }
    // `Http3MockServerHandler`: only a request for a control-plane path candidate gets the peer as its remote address
    // (Basic throttles guesses per peer; upstream 29a26d650), whoever then serves it
    let remote_address = if crate::cors_origin::is_control_plane_path_candidate(&path) { crate::server::java_socket_address(peer.remote) } else { String::new() };
    HttpRequest {
        method: head.method().as_str().to_string(),
        path: if path.is_empty() { "/".into() } else { path },
        query: query.as_deref().map(raw_query).unwrap_or_default(),
        raw_query: query.filter(|q| !q.is_empty()),
        headers,
        body,
        // `BODY_DECODER.bytesToBody(body, contentType)`: typed by its content type exactly as HTTP/1.1 and HTTP/2 type it.
        body_kind: request::BodyKind::Received,
        // `toHttpRequest` sets neither keep-alive nor the local address (the remote one only as above): logged as absent (`recorded.rs`), and
        // `false` decides as a null keep-alive does (`!(keepAlive != null && keepAlive)`), e.g. an SSE response's close.
        keep_alive: false,
        secure: true,
        protocol: "HTTP_3",
        client_certificates: peer.client_certificates.clone(),
        remote_address,
        ..HttpRequest::default()
    }
}

/// `Http3RequestBridge.parseQueryString`.
fn raw_query(query: &str) -> MultiMap {
    let mut map = MultiMap::new();
    for param in query.split('&') {
        match param.split_once('=') {
            Some((name, value)) => request::push(&mut map, name, value.to_string()),
            None if !param.is_empty() => request::push(&mut map, param, String::new()),
            None => {}
        }
    }
    map
}

/// `Http3RequestBridge.toHttp3HeadersFrame`: `server: mockserver-http3`, then the reply's headers lower-cased,
/// without the connection-specific ones (nor `content-length` when streaming).
fn fields(reply: &Reply, streaming: bool) -> Vec<(String, String)> {
    let mut fields = vec![("server".to_string(), "mockserver-http3".to_string())];
    // a gRPC answer (`GrpcHttp3Adapter.buildInitialHeadersFrame`, `buildTrailersOnlyFrame`): its `content-type` first
    let mut lead = reply.grpc_http3.then(|| reply.headers.iter().position(|(n, _)| n.eq_ignore_ascii_case("content-type"))).flatten();
    if let Some(at) = lead {
        fields.insert(0, ("content-type".to_string(), reply.headers[at].1.clone()));
    }
    for (index, (name, value)) in reply.headers.iter().enumerate() {
        let lower = name.to_ascii_lowercase();
        if lead == Some(index) {
            lead = None;
            continue;
        }
        let forbidden = matches!(lower.as_str(), "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade")
            || (lower == "te" && !value.eq_ignore_ascii_case("trailers"))
            || (streaming && lower == "content-length")
            || lower.starts_with(':');
        if !forbidden {
            fields.push((lower, value.clone()));
        }
    }
    fields
}

fn response(status: u32, fields: &[(String, String)]) -> http::Response<()> {
    let mut response = http::Response::new(());
    *response.status_mut() = u16::try_from(status).ok().and_then(|s| http::StatusCode::from_u16(s).ok()).unwrap_or(http::StatusCode::OK);
    for (name, value) in fields {
        if let (Ok(name), Ok(value)) = (http::HeaderName::from_bytes(name.as_bytes()), http::HeaderValue::from_str(value)) {
            response.headers_mut().append(name, value);
        }
    }
    response
}

async fn send(stream: &mut Stream, status: u32, fields: &[(String, String)], body: Option<Bytes>) -> Result<(), h3::error::StreamError> {
    send_with_trailers(stream, status, fields, body, &[]).await
}

/// The response, its body, then a trailing HEADERS frame when there are trailers.
async fn send_with_trailers(stream: &mut Stream, status: u32, fields: &[(String, String)], body: Option<Bytes>, trailers: &[(String, String)]) -> Result<(), h3::error::StreamError> {
    stream.send_response(response(status, fields)).await?;
    if let Some(body) = body {
        stream.send_data(body).await?;
    }
    if !trailers.is_empty() {
        stream.send_trailers(header_map(trailers)).await?;
    }
    stream.finish().await
}

/// `Http3ConnectUdpHandler.handleConnectUdp` (RFC 9298, as upstream simplifies it): the target comes from
/// `:authority`, is checked against `http3ConnectUdpAllowedTargets` and the `forwardProxyBlockPrivateNetworks` block
/// on the one resolved address, then a connected UDP socket relays each request DATA frame as one datagram and each
/// datagram back as one DATA frame (no HTTP Datagrams or capsules).
/// `raw_authority`: the `:authority` as sent, when `raw_headers` had to hide it from h3.
async fn connect_udp(state: Arc<State>, quic: quinn::Connection, head: http::Request<()>, mut stream: Stream, raw_authority: Option<String>) {
    let authority = raw_authority.unwrap_or_else(|| head.uri().authority().map(|a| a.as_str().to_string()).unwrap_or_default());
    if authority.is_empty() {
        crate::log::warn(&state, "CONNECT-UDP error: 400 -- Missing :authority for CONNECT-UDP");
        return udp_error(&mut stream, 400, "Missing :authority for CONNECT-UDP").await;
    }
    let Some((host, port)) = parse_authority(&authority) else {
        let message = format!("Invalid :authority for CONNECT-UDP: {authority}");
        crate::log::warn(&state, &format!("CONNECT-UDP error: 400 -- {message}"));
        return udp_error(&mut stream, 400, &message).await;
    };
    // `sendTargetNotPermitted`: the reason stays in the log, the client gets the generic body.
    let log_refusal = |reason: String| crate::log::warn(&state, &format!("CONNECT-UDP target refused ({reason})"));
    let allowed = state.config.property("http3ConnectUdpAllowedTargets").unwrap_or_default();
    if !allowed.trim().is_empty() && !matches_allowlist(&allowed, &host, port) {
        log_refusal(format!("not in http3ConnectUdpAllowedTargets: {authority}"));
        return udp_error(&mut stream, 403, "CONNECT-UDP target not permitted").await;
    }
    // Resolved exactly once: the SSRF check and the connect use the same address. `new InetSocketAddress("", port)`
    // resolves through `InetAddress.getByName("")`, the loopback address (IPv4 unless IPv6 is preferred).
    let resolved = if host.is_empty() {
        Some(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)))
    } else {
        tokio::net::lookup_host((host.as_str(), port)).await.ok().and_then(|mut a| a.next())
    };
    let Some(address) = resolved else {
        log_refusal(format!("unresolved CONNECT-UDP target: {authority}"));
        return udp_error(&mut stream, 403, "CONNECT-UDP target not permitted").await;
    };
    // `validateForwardTarget(configuration, InetAddress)`: the host lists on the name the address was looked up by
    // (`nameOrAddress`: `localhost` for the empty host, the literal for an address), then the private-network block
    let named = match host.trim_start_matches('[').trim_end_matches(']') {
        "" => "localhost".to_string(),
        literal if literal.parse::<std::net::IpAddr>().is_ok() => crate::ws_relay::java_host_address(address.ip()),
        name => name.to_string(),
    };
    let refused = crate::forward_target_policy::of(&state.config)
        .and_then(|policy| policy.check(&named, Some(address.ip())))
        .or_else(|| state.config.hot_bool(crate::config::Hot::ForwardProxyBlockPrivateNetworks, false).then(|| crate::ws_relay::blocked_address(address.ip(), &address.ip().to_string())).flatten());
    if let Some(reason) = refused {
        log_refusal(format!("SSRF block for {authority}: {reason}"));
        return udp_error(&mut stream, 403, "CONNECT-UDP target not permitted").await;
    }
    crate::log::info(&state, &format!("CONNECT-UDP tunnel requested to {address} -- establishing UDP relay"));
    let local: SocketAddr = if address.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { (std::net::Ipv6Addr::UNSPECIFIED, 0).into() };
    let udp = match tokio::net::UdpSocket::bind(local).await {
        Ok(udp) => udp,
        Err(e) => {
            crate::log::error(&state, &format!("CONNECT-UDP relay unavailable (bind failed for {address}): {e}"));
            return udp_error(&mut stream, 502, "CONNECT-UDP relay unavailable").await;
        }
    };
    if let Err(e) = udp.connect(address).await {
        crate::log::error(&state, &format!("CONNECT-UDP relay unavailable (connect failed for {address}): {e}"));
        return udp_error(&mut stream, 502, "CONNECT-UDP relay unavailable").await;
    }
    crate::log::info(&state, &format!("CONNECT-UDP tunnel established to {address} -- relaying datagrams"));
    if stream.send_response(response(200, &[("server".to_string(), "mockserver-http3-masque".to_string())])).await.is_err() {
        return;
    }
    relay_udp(state, quic, stream, udp).await;
}

/// The established tunnel. Client DATA frames go out as datagrams (`relayToTarget`); datagrams come back as DATA
/// frames (`UdpRelayHandler`). A UDP error (e.g. ICMP port unreachable) closes the socket: later frames are dropped
/// with a warning. The client finishing its side does not end the relay; the stream failing or the connection closing
/// does (`channelInactive`, `exceptionCaught`). The response side is never finished, as upstream.
async fn relay_udp(state: Arc<State>, quic: quinn::Connection, stream: Stream, udp: tokio::net::UdpSocket) {
    let udp = Arc::new(udp);
    let udp_open = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let (mut send, mut recv) = stream.split();
    let mut client = tokio::spawn({
        let (state, udp, udp_open) = (state.clone(), udp.clone(), udp_open.clone());
        async move {
            loop {
                match recv.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        let payload = chunk.copy_to_bytes(chunk.remaining());
                        if !udp_open.load(Ordering::SeqCst) {
                            crate::log::warn(&state, "CONNECT-UDP relay: UDP channel not active, dropping data frame");
                        } else if !payload.is_empty() {
                            let _ = udp.send(&payload).await;
                        }
                    }
                    // input closed: replies keep flowing
                    Ok(None) => return true,
                    Err(e) => {
                        crate::log::warn(&state, &format!("CONNECT-UDP handler exception: {e}"));
                        return false;
                    }
                }
            }
        }
    });
    let mut client_done = false;
    let mut buf = vec![0u8; 65_535];
    loop {
        tokio::select! {
            ended = &mut client, if !client_done => {
                client_done = true;
                if !matches!(ended, Ok(true)) {
                    break;
                }
            }
            received = udp.recv(&mut buf), if udp_open.load(Ordering::SeqCst) => match received {
                Ok(0) => {}
                Ok(n) => {
                    if send.send_data(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    crate::log::warn(&state, &format!("CONNECT-UDP relay UDP handler exception: {e}"));
                    udp_open.store(false, Ordering::SeqCst);
                }
            },
            _ = quic.closed() => break,
        }
    }
    client.abort();
}

/// `Http3ConnectUdpHandler.writeErrorResponse`: a JSON `{"error": ...}` body, then the stream's end.
async fn udp_error(stream: &mut Stream, status: u32, message: &str) {
    let body = format!("{{\"error\":\"{}\"}}", crate::ws_relay::escape_json(message));
    let headers = vec![
        ("content-type".to_string(), "application/json; charset=utf-8".to_string()),
        ("content-length".into(), body.len().to_string()),
        ("server".into(), "mockserver-http3-masque".into()),
    ];
    let _ = send(stream, status, &headers, Some(Bytes::from(body))).await;
}

/// `Integer.parseInt` (an optional sign, ASCII digits) of a port, kept only in 1..=65535.
fn parse_port(value: &str) -> Option<u16> {
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse::<i32>().ok().filter(|p| (1..=65_535).contains(p)).map(|p| p as u16)
}

/// `[ipv6]...`: the bracketed host and what follows the `]`; `None` without brackets, `Some(None)` when unclosed.
fn bracketed(value: &str) -> Option<Option<(&str, &str)>> {
    let rest = value.strip_prefix('[')?;
    Some(rest.find(']').map(|close| (&rest[..close], &rest[close + 1..])))
}

/// `Http3ConnectUdpHandler.parseAuthority`: `host:port` or `[ipv6]:port`, the port required and in 1..=65535.
fn parse_authority(authority: &str) -> Option<(String, u16)> {
    let (host, port) = match bracketed(authority) {
        Some(inner) => {
            let (host, after) = inner?;
            (host, after.strip_prefix(':')?)
        }
        None => authority.rsplit_once(':')?,
    };
    Some((host.to_string(), parse_port(port)?))
}

/// `Http3ConnectUdpHandler.matchesAllowlist`: comma-separated `host`, `host:port` or `[ipv6]` / `[ipv6]:port`
/// entries; the host compared case-insensitively, a port-less entry matching any port.
fn matches_allowlist(allowed: &str, host: &str, port: u16) -> bool {
    allowed.split(',').map(str::trim).filter(|e| !e.is_empty()).any(|entry| {
        let (entry_host, entry_port) = match bracketed(entry) {
            Some(None) => return false,
            Some(Some((h, after))) => match after.strip_prefix(':') {
                Some(p) => match parse_port(p.trim()) {
                    Some(p) => (h, Some(p)),
                    None => return false,
                },
                None => (h, None),
            },
            None => match entry.rsplit_once(':').and_then(|(h, p)| parse_port(p.trim()).map(|p| (h, p))) {
                Some((h, p)) => (h, Some(p)),
                None => (entry, None),
            },
        };
        entry_host.eq_ignore_ascii_case(host) && entry_port.is_none_or(|p| p == port)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_needs_a_port_in_range() {
        assert_eq!(parse_authority("127.0.0.1:53"), Some(("127.0.0.1".into(), 53)));
        assert_eq!(parse_authority("[::1]:443"), Some(("::1".into(), 443)));
        assert_eq!(parse_authority("no-port-authority"), None);
        assert_eq!(parse_authority("host:"), None);
        assert_eq!(parse_authority("host:0"), None);
        assert_eq!(parse_authority("host:65536"), None);
        assert_eq!(parse_authority("[::1]"), None);
    }

    #[test]
    fn allowlist_entries() {
        assert!(matches_allowlist("127.0.0.1", "127.0.0.1", 9));
        assert!(matches_allowlist(" x , Allowed.example.com:443", "allowed.EXAMPLE.com", 443));
        assert!(!matches_allowlist("allowed.example.com:443", "allowed.example.com", 80));
        assert!(!matches_allowlist("allowed.example.com:443", "127.0.0.1", 443));
        assert!(matches_allowlist("[::1]:53", "::1", 53));
        assert!(!matches_allowlist("[::1", "::1", 53));
    }
}

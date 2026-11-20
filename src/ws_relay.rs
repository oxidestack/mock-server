//! `WebSocketProxyRelayHandler`: an unmatched WebSocket upgrade in proxy mode is relayed to the real upstream — its
//! handshake first, then every frame both ways — and recorded as a forwarded request whose `101` response carries
//! the transcript of relayed frames.
//!
//! Frames are relayed as they arrive (a client's frames stay masked, an upstream's unmasked) and parsed only to be
//! recorded, so a ping reaches the other side and its pong comes back from there, as Netty's relay does.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use bytes::BytesMut;
use parking_lot::Mutex;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;

use crate::reply::Reply;
use crate::request::{self, HttpRequest};
use crate::state::State;

/// `MAX_RECORDED_FRAME_BYTES`: a recorded frame payload is cut to this many bytes.
const MAX_RECORDED_FRAME_BYTES: usize = 32 * 1024;
/// `MAX_TRANSCRIPT_JSON_CHARS`: past this, frames are relayed but no longer recorded.
const MAX_TRANSCRIPT_JSON_CHARS: usize = 8 * 1024 * 1024;

/// `isWebSocketUpgrade`: GET with `Upgrade: websocket`, `Connection: upgrade` and a `Sec-WebSocket-Key`.
pub fn is_upgrade(request: &HttpRequest) -> bool {
    let has = |name: &str, needle: &str| request.first_header(name).is_some_and(|v| v.to_lowercase().contains(needle));
    (request.method.is_empty() || request.method.eq_ignore_ascii_case("GET"))
        && has("upgrade", "websocket")
        && has("connection", "upgrade")
        && request.first_header("sec-websocket-key").is_some_and(|k| !k.is_empty())
}

/// `InetAddressValidator.validateForwardTarget`: why `host` may not be forwarded to, under `forwardProxyAllowedHosts`
/// and `forwardProxyDeniedHosts` ([`crate::forward_target_policy`]) and then `forwardProxyBlockPrivateNetworks`.
pub async fn blocked(state: &State, host: &str) -> Option<String> {
    let (name, block, policy) = gated(state, host)?;
    let address = match java_literal(name) {
        _ if !block && !policy.as_ref().is_some_and(|p| p.matches_addresses()) => return policy?.check(host, None),
        Literal::Address(address) => Some(address),
        Literal::Unresolvable => None,
        Literal::Name => crate::inet_address::lookup(name, 0).await.ok().and_then(|found| prefer_ipv4(found.into_iter().map(|a| a.ip()))),
    };
    verdict(address, host, block, policy.as_deref())
}

/// `InetAddressValidator.isActive`: a forward target check is on (`forwardProxyBlockPrivateNetworks`, or a host list).
pub fn checks_active(state: &State) -> bool {
    state.config.bool_property("forwardProxyBlockPrivateNetworks", false) || crate::forward_target_policy::of(&state.config).is_some()
}

/// [`blocked`] for a caller off the async runtime (the name lookup blocks).
pub fn blocked_blocking(state: &State, host: &str) -> Option<String> {
    let block = state.config.bool_property("forwardProxyBlockPrivateNetworks", false);
    blocked_by(block, crate::forward_target_policy::of(&state.config), host)
}

/// [`blocked_blocking`] under checks taken from a configuration earlier: `forwardProxyBlockPrivateNetworks` (`block`)
/// and the host lists (`policy`).
pub fn blocked_by(block: bool, policy: Option<std::sync::Arc<crate::forward_target_policy::Policy>>, host: &str) -> Option<String> {
    if (!block && policy.is_none()) || host.trim().is_empty() {
        return None;
    }
    let name = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    let address = match java_literal(name) {
        _ if !block && !policy.as_ref().is_some_and(|p| p.matches_addresses()) => return policy?.check(host, None),
        Literal::Address(address) => Some(address),
        Literal::Unresolvable => None,
        Literal::Name => crate::inet_address::lookup_blocking(name, 0).ok().and_then(|found| prefer_ipv4(found.into_iter().map(|a| a.ip()))),
    };
    verdict(address, host, block, policy.as_deref())
}

/// The name [`blocked`] resolves (`stripBrackets`) and the checks that apply, or `None` when none does or `host` is
/// blank.
fn gated<'a>(state: &State, host: &'a str) -> Option<(&'a str, bool, Option<std::sync::Arc<crate::forward_target_policy::Policy>>)> {
    let block = state.config.bool_property("forwardProxyBlockPrivateNetworks", false);
    let policy = crate::forward_target_policy::of(&state.config);
    if (!block && policy.is_none()) || host.trim().is_empty() {
        return None;
    }
    Some((host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host), block, policy))
}

/// Whether [`blocked`] looks a target name up (`forwardProxyBlockPrivateNetworks`, or host lists with address entries).
fn looks_up(state: &State) -> bool {
    state.config.bool_property("forwardProxyBlockPrivateNetworks", false) || crate::forward_target_policy::of(&state.config).is_some_and(|p| p.matches_addresses())
}

/// `reject`: the host lists first, then the private-network block.
fn verdict(address: Option<std::net::IpAddr>, host: &str, block: bool, policy: Option<&crate::forward_target_policy::Policy>) -> Option<String> {
    let Some(address) = address else {
        return Some(format!("Forward target host \"{host}\" could not be resolved"));
    };
    policy.and_then(|p| p.check(host, Some(address))).or_else(|| block.then(|| blocked_address(address, host)).flatten())
}

/// `InetAddress.getByName`'s first answer to a name lookup: IPv4 first (`java.net.preferIPv6Addresses=false`).
fn prefer_ipv4(found: impl Iterator<Item = std::net::IpAddr>) -> Option<std::net::IpAddr> {
    let addresses: Vec<std::net::IpAddr> = found.map(|a| a.to_canonical()).collect();
    addresses.iter().find(|a| a.is_ipv4()).or(addresses.first()).copied()
}

enum Literal {
    Address(std::net::IpAddr),
    Unresolvable,
    Name,
}

/// `InetAddress.getByName` before any lookup: an IPv4 literal as `IPAddressUtil.textToNumericFormatV4` reads it (1 to
/// 4 decimal parts, the last filling the remaining bytes, so `127.1` and `2130706433` are loopback but `0177.0.0.1`
/// is 177.0.0.1), an IPv6 literal (an IPv4-mapped one becomes the IPv4 address; a malformed one does not resolve), the
/// empty string (what `[]` leaves) as loopback; digits and dots that make no valid literal do not resolve. Anything
/// else is a name to look up.
fn java_literal(host: &str) -> Literal {
    use std::net::IpAddr;
    let Some(first) = host.chars().next() else {
        return Literal::Address(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    };
    if first.is_ascii_hexdigit() || first == ':' {
        if let Some(v4) = java_ipv4_literal(host) {
            return Literal::Address(IpAddr::V4(v4));
        }
        if host.contains(':') {
            let literal = host.split_once('%').map_or(host, |(address, _scope)| address);
            return match literal.parse::<std::net::Ipv6Addr>() {
                Ok(v6) => Literal::Address(IpAddr::V6(v6).to_canonical()),
                Err(_) => Literal::Unresolvable,
            };
        }
        if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return Literal::Unresolvable;
        }
    }
    Literal::Name
}

/// `IPAddressUtil.textToNumericFormatV4`.
fn java_ipv4_literal(src: &str) -> Option<std::net::Ipv4Addr> {
    if src.is_empty() || src.len() > 15 {
        return None;
    }
    let mut bytes = [0u8; 4];
    let (mut current, mut value, mut new_octet) = (0usize, 0u64, true);
    for c in src.chars() {
        if c == '.' {
            if new_octet || value > 0xff || current == 3 {
                return None;
            }
            bytes[current] = value as u8;
            current += 1;
            value = 0;
            new_octet = true;
        } else {
            value = value * 10 + u64::from(c.to_digit(10)?);
            new_octet = false;
        }
    }
    if new_octet || value >= 1u64 << ((4 - current) * 8) {
        return None;
    }
    for (i, byte) in bytes.iter_mut().enumerate().skip(current) {
        *byte = (value >> ((3 - i) * 8)) as u8;
    }
    Some(std::net::Ipv4Addr::from(bytes))
}

/// `InetAddress.getHostAddress`: an IPv6 address in full, each group in hex without leading zeros (never `::`).
pub fn java_host_address(address: std::net::IpAddr) -> String {
    match address.to_canonical() {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => v6.segments().iter().map(|s| format!("{s:x}")).collect::<Vec<_>>().join(":"),
    }
}

/// `InetAddressValidator.validateForwardTarget(Configuration, InetAddress)`: the block checks on an already resolved
/// `address` (named `host` in the reason), without the `forwardProxyBlockPrivateNetworks` gate. An IPv4-mapped IPv6
/// address is checked as its IPv4 address, which is what Java resolves it to.
pub fn blocked_address(address: std::net::IpAddr, host: &str) -> Option<String> {
    let suffix = " (set mockserver.forwardProxyBlockPrivateNetworks=false to allow)";
    let address = address.to_canonical();
    // Compared as `getHostAddress` prints it, so the compressed `fd00:ec2::254` never matches upstream's constant:
    // that address is reported as unique-local.
    let ip = java_host_address(address);
    let kind = if ip == "169.254.169.254" || ip.eq_ignore_ascii_case("fd00:ec2::254") {
        "cloud metadata endpoint"
    } else if address.is_loopback() {
        "loopback address"
    } else if match address {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    } {
        "link-local address"
    } else if match address {
        // `isSiteLocalAddress`: 10/8, 172.16/12, 192.168/16; IPv6 fec0::/10 and unique-local fc00::/7.
        std::net::IpAddr::V4(v4) => v4.is_private(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfec0 || (v6.segments()[0] & 0xfe00) == 0xfc00,
    } {
        "private network"
    } else if matches!(address, std::net::IpAddr::V4(v4) if v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64) {
        // `isCarrierGradeNat`: RFC 6598 shared address space 100.64.0.0/10 (an IPv4-mapped one is canonical here).
        "carrier-grade NAT address"
    } else if address.is_unspecified() {
        "wildcard address"
    } else {
        return None;
    };
    Some(format!("Forward to {kind} blocked: {host}{suffix}"))
}

/// `relay`: connects to `host:port` (over TLS when `tls`), performs the upstream handshake, answers the client's
/// with `101`, then relays frames until either side ends or sends a close frame; then the other side is sent what was
/// on its way to it and that close frame (or 1001, going away), and both are ended as `LingeringClose` ends a socket.
/// Any failure before that answers the client `502` with the reason and closes.
/// `guarded`: an upgrade a forward expectation relays counts against `forwardLoopMaxHops` and carries
/// `x-mockserver-forwarded-by` ([`crate::forward_loop`]); the unmatched proxy path's does not.
pub async fn relay<S>(state: Arc<State>, request: HttpRequest, mut client: S, host: String, port: u16, tls: bool, guarded: bool)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(reason) = blocked(&state, &host).await {
        return fail(&state, &request, &mut client, &reason).await;
    }
    // an upgrade relayed back here matches the same forward again, as a forwarded request does
    if guarded && let Some(body) = crate::forward_loop::refuse(&state, &request, crate::forward_loop::Route::Forward) {
        return answer_and_close(&state, &request, &mut client, crate::forward_loop::LOOP_DETECTED, Some("Loop Detected".into()), body).await;
    }
    // the handshake sent upstream carries the guard's entries; a hop further on that refused the loop answers 508
    let mut sent = request.clone();
    let relays_loop_detected = guarded && crate::forward_loop::forwarded_entries(&state, &request).is_some();
    if guarded {
        crate::forward_loop::mark(&state, &request, &mut sent);
    }
    // The relay's `ChannelInitializer` builds the client's TLS context (loading the CA the first time) as the channel
    // is registered, before it connects: a refused upstream loads it too (scenario log_ca_load_client_websocket_relay)
    if tls && let Some(context) = state.tls.as_ref() {
        context.client_context_needed(&state);
    }
    let timeout = Duration::from_millis(state.config.int_property("socketConnectionTimeoutInMillis", 20_000).max(1) as u64);
    // A failed connect is named by the exception Netty fails it with (`Connection refused: host/ip:port`).
    let tcp = match crate::client::connect_timed_named(host.trim_start_matches('[').trim_end_matches(']'), port, timeout, looks_up(&state)).await {
        Ok(tcp) => tcp,
        Err(e) => {
            let reason = e.exception_message().unwrap_or_default();
            return fail(&state, &request, &mut client, &format!("unable to connect to upstream WebSocket server {host}:{port} - {reason}")).await;
        }
    };
    let peer = tcp.peer_addr().ok();
    let _ = tcp.set_nodelay(true);
    // `UpstreamHandshakeHandler` (master): from the TCP connection on, so over a TLS handshake too, the
    // handshake response is waited for as a forward's response is, `maxSocketTimeout` capped by `maxFutureTimeout`;
    // a client that closes its connection meanwhile ends the wait and the upstream connection, unreported.
    let (wait, wait_name) = handshake_timeout(&state);
    let handshake = async {
        let upstream: Box<dyn Io> = if tls {
            match crate::client::websocket_tls_connect(&state.config, &host, tcp, state.forward_identity(&host)).await {
                Ok(stream) => stream,
                Err(crate::client::Error::TlsFailure(description)) => return Err(format!("TLS with the upstream failed: {description}").into()),
                Err(_) => return Err("upstream WebSocket error: TLS handshake failed".to_string().into()),
            }
        } else {
            Box::new(tcp)
        };
        handshake_upstream(&state, upstream, &sent, &host, port, tls, relays_loop_detected).await
    };
    let timed = async {
        match wait {
            Some(wait) => tokio::time::timeout(wait, handshake)
                .await
                .unwrap_or_else(|_| Err(format!("upstream WebSocket handshake response was not received within {wait_name} ({} ms)", wait.as_millis()).into())),
            None => handshake.await,
        }
    };
    // Bytes the client sends before its `101` (none, from a conforming client) go upstream after the handshake.
    let mut early = BytesMut::new();
    tokio::pin!(timed);
    let outcome = tokio::select! {
        outcome = &mut timed => outcome,
        read = client.read_buf(&mut early) => match read {
            // no longer watched for a close: the handshake is waited for as it is
            Ok(n) if n > 0 => timed.await,
            _ => return,
        },
    };
    let (mut upstream, upstream_buf, subprotocol, response_headers) = match outcome {
        Ok(done) => done,
        Err(HandshakeFailed::Reason(reason)) => return fail(&state, &request, &mut client, &reason).await,
        Err(HandshakeFailed::LoopDetected { phrase, body }) => {
            log_failure(&state, &request, &format!("upstream answered the WebSocket handshake with 508 Loop Detected: {body}"));
            return answer_and_close(&state, &request, &mut client, crate::forward_loop::LOOP_DETECTED, phrase, body).await;
        }
    };

    // `WebSocketServerHandshaker13`: the downstream half of the handshake, with the upstream's response headers that
    // are neither hop-by-hop nor the handshake's own first (`buildDownstreamResponseHeaders`).
    let key = request.first_header("sec-websocket-key").unwrap_or_default();
    let mut head = "HTTP/1.1 101 Switching Protocols\r\n".to_string();
    for (name, value) in &response_headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("upgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-accept: {}\r\n", derive_accept_key(key.as_bytes())));
    if let Some(p) = &subprotocol {
        head.push_str(&format!("sec-websocket-protocol: {p}\r\n"));
    }
    head.push_str("\r\n");
    if client.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    state.bus().fire(crate::scenario::Trigger::WebSocketConnect, &request.path);
    if state.info_enabled() {
        // Jackson's `InetSocketAddress` form (what the dashboard shows): the host name, or the address without one, and the port.
        let upstream_json = peer.map(|p| if host.parse::<std::net::IpAddr>().is_ok() { p.to_string() } else { format!("{host}:{}", p.port()) }).unwrap_or_default();
        let upstream_address = peer.map(|p| if host.parse::<std::net::IpAddr>().is_ok() { format!("/{p}") } else { format!("{host}/{p}") }).unwrap_or_default();
        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Info, "relaying WebSocket passthrough for request:{}to upstream:{}")
            .args([crate::recorded::Arg::from(crate::recorded::logged(&request)), crate::recorded::Arg::socket_address_as(upstream_address, upstream_json)]);
        state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(request.clone())));
    }

    let transcript = Arc::new(Mutex::new(Transcript::new(state.config.int_property("webSocketProxyMaxRecordedFrames", 1000))));
    let activity = Arc::new(Mutex::new(Instant::now()));
    let idle = state.config.int_property("webSocketProxyIdleTimeoutSeconds", 0);
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(&mut upstream);
    let mut to_upstream_state = Pump::new(early);
    let mut to_client_state = Pump::new(upstream_buf);
    let reaper = async {
        if idle <= 0 {
            return std::future::pending::<()>().await;
        }
        let period = Duration::from_secs(idle as u64);
        loop {
            let since = activity.lock().elapsed();
            if since >= period {
                return;
            }
            tokio::time::sleep(period - since).await;
        }
    };
    tokio::pin!(reaper);
    // `FrameRelayHandler`: a side that sends a close frame or ends ends both legs (`endAfterFlush`). A failed write
    // to the upstream closes it (Netty's `autoClose`); one to the client ends only the client's output, and the
    // client is read on (`ReadAfterFailedWrite`) until its input ends or for `LINGER` at the most.
    let mut client_linger: Option<tokio::time::Instant> = None;
    let ending = loop {
        let linger = async move {
            match client_linger {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        let to_upstream = pump(&mut client_read, &mut upstream_write, &mut to_upstream_state, Direction::ClientToUpstream, &transcript, &activity);
        let to_client = pump(&mut upstream_read, &mut client_write, &mut to_client_state, Direction::UpstreamToClient, &transcript, &activity);
        break tokio::select! {
            ended = to_upstream => match ended {
                Ended::WriteFailed => Some((Direction::UpstreamToClient, Ended::Input)),
                ended => Some((Direction::ClientToUpstream, ended)),
            },
            ended = to_client => match ended {
                Ended::WriteFailed => {
                    client_linger = Some(tokio::time::Instant::now() + LINGER);
                    continue;
                }
                ended => Some((Direction::UpstreamToClient, ended)),
            },
            _ = linger => Some((Direction::ClientToUpstream, Ended::Input)),
            _ = &mut reaper => None,
        };
    };
    let in_flight = |state: &Pump| if state.failed { Vec::new() } else { state.out[state.written..].to_vec() };
    match ending {
        // the idle reaper closes both channels
        None => {
            let _ = client_write.shutdown().await;
            let _ = upstream_write.shutdown().await;
        }
        // the side that sent the close frame is ended once what is on its way to it is written; the other was sent
        // the close frame
        Some((Direction::ClientToUpstream, Ended::Close)) => {
            let (to_client, to_upstream) = (in_flight(&to_client_state), in_flight(&to_upstream_state));
            tokio::join!(end_leg(&mut client_read, &mut client_write, to_client, None), end_leg(&mut upstream_read, &mut upstream_write, to_upstream, None));
        }
        Some((Direction::UpstreamToClient, Ended::Close)) => {
            let (to_client, to_upstream) = (in_flight(&to_client_state), in_flight(&to_upstream_state));
            tokio::join!(end_leg(&mut upstream_read, &mut upstream_write, to_upstream, None), end_leg(&mut client_read, &mut client_write, to_client, None));
        }
        // a side that ended without a close frame is closed; the other is sent what is on its way to it and 1001
        // (going away)
        Some((Direction::ClientToUpstream, _)) => {
            let pending = in_flight(&to_upstream_state);
            end_leg(&mut upstream_read, &mut upstream_write, pending, Some(going_away(true))).await
        }
        Some((Direction::UpstreamToClient, _)) => {
            let pending = in_flight(&to_client_state);
            end_leg(&mut client_read, &mut client_write, pending, Some(going_away(false))).await
        }
    }
    record(&state, &request, subprotocol.as_deref(), &response_headers, &transcript.lock());
}

/// `LingeringClose.LINGER_MILLIS`: how long an ended leg waits for the other end to close.
const LINGER: Duration = Duration::from_millis(5_000);

/// `endAfterFlush` and `LingeringClose`: writes what is still on its way to this leg and `last`, then ends its
/// output; meanwhile what it sends is read and dropped. Returns at the end of its input, or [`LINGER`] after it was
/// called, written or not, so that the socket closes then.
async fn end_leg<R, W>(read: &mut R, write: &mut W, pending: Vec<u8>, last: Option<Vec<u8>>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let output = async {
        let written = async {
            write.write_all(&pending).await?;
            if let Some(last) = &last {
                write.write_all(last).await?;
            }
            write.flush().await?;
            write.shutdown().await
        };
        let _ = written.await;
        std::future::pending::<()>().await
    };
    let drain = async {
        let mut discarded = vec![0u8; 16 * 1024];
        while let Ok(n) = read.read(&mut discarded).await {
            if n == 0 {
                break;
            }
        }
    };
    tokio::select! {
        _ = output => {}
        _ = drain => {}
        _ = tokio::time::sleep(LINGER) => {}
    }
}

/// `new CloseWebSocketFrame(WebSocketCloseStatus.ENDPOINT_UNAVAILABLE)`: 1001 with its reason text, masked towards the
/// upstream as a client's frames are.
fn going_away(masked: bool) -> Vec<u8> {
    let mut payload = 1001u16.to_be_bytes().to_vec();
    payload.extend_from_slice(b"Endpoint unavailable");
    let mut frame = vec![0x88, payload.len() as u8];
    if masked {
        let mut mask = [0u8; 4];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut mask);
        frame[1] |= 0x80;
        frame.extend_from_slice(&mask);
        payload.iter_mut().enumerate().for_each(|(i, b)| *b ^= mask[i % 4]);
    }
    frame.extend_from_slice(&payload);
    frame
}

pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// `WebSocketClientHandshaker.websocketOriginValue` for `ws(s)://host:port`.
fn origin_value(host: &str, port: u16, tls: bool) -> String {
    let (scheme, default_port) = if tls { ("https://", 443) } else { ("http://", 80) };
    let host = host.to_lowercase();
    let host = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host };
    if port == default_port { format!("{scheme}{host}") } else { format!("{scheme}{host}:{port}") }
}

/// How long the relay waits for the upstream's handshake response, and the setting that says so
/// (`WebSocketProxyRelayHandler.relay`, master): `maxSocketTimeout`, unless `maxFutureTimeout` is positive and either
/// shorter or the socket timeout is off (0 or less); `None` when neither applies.
fn handshake_timeout(state: &State) -> (Option<Duration>, &'static str) {
    let socket = state.config.int_property("maxSocketTimeoutInMillis", 20_000);
    let future = state.config.int_property("maxFutureTimeoutInMillis", 90_000);
    let (millis, name) = match future > 0 && (socket <= 0 || future < socket) {
        true => (future, "maxFutureTimeout"),
        false => (socket, "maxSocketTimeout"),
    };
    ((millis > 0).then(|| Duration::from_millis(millis as u64)), name)
}

/// `buildDownstreamResponseHeaders`: the upstream's handshake response headers the client is answered with, all but
/// the hop-by-hop ones (and those its `Connection` names), `Content-Length` and the handshake's own `Sec-WebSocket-*`.
fn downstream_response_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let named: Vec<String> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(',').map(|t| t.trim().to_lowercase()).collect::<Vec<_>>())
        .collect();
    let relayed = |name: &str| {
        let lower = name.to_lowercase();
        !matches!(lower.as_str(), "connection" | "upgrade" | "keep-alive" | "transfer-encoding" | "te" | "trailer" | "content-length")
            && !lower.starts_with("proxy-")
            && !lower.starts_with("sec-websocket-")
            && !named.contains(&lower)
    };
    headers.iter().filter(|(k, _)| relayed(k)).cloned().collect()
}

/// `WebSocketClientHandshaker13`: the upstream handshake request (the client's headers except those the handshaker
/// sets itself) and the checks on its answer. Returns the stream, bytes read past the answer, the negotiated
/// subprotocol and the response headers the client is answered with.
/// Why the upstream handshake did not complete.
enum HandshakeFailed {
    /// Answered `502` with the reason ([`fail`]).
    Reason(String),
    /// A hop further on refused a forward loop: its `508` is relayed, as a forward relays it.
    LoopDetected { phrase: Option<String>, body: String },
}

impl From<String> for HandshakeFailed {
    fn from(reason: String) -> Self {
        HandshakeFailed::Reason(reason)
    }
}

async fn handshake_upstream(
    state: &State,
    mut upstream: Box<dyn Io>,
    request: &HttpRequest,
    host: &str,
    port: u16,
    tls: bool,
    relays_loop_detected: bool,
) -> Result<(Box<dyn Io>, BytesMut, Option<String>, Vec<(String, String)>), HandshakeFailed> {
    const MANAGED: &[&str] =
        &["host", "upgrade", "connection", "sec-websocket-key", "sec-websocket-version", "sec-websocket-protocol", "sec-websocket-extensions", "content-length"];
    let mut target = if request.path.starts_with('/') { request.path.clone() } else { format!("/{}", request.path) };
    if !request.query.is_empty() {
        let pairs: Vec<String> = request
            .query
            .iter()
            .flat_map(|(k, vs)| vs.iter().map(move |v| format!("{}={}", url_encode(k), url_encode(v))))
            .collect();
        target = format!("{target}?{}", pairs.join("&"));
    }
    let mut key_bytes = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut key_bytes);
    let key = base64::engine::general_purpose::STANDARD.encode(key_bytes);
    let host_value = crate::forward::host_header(host, port, tls);
    let mut head = format!("GET {target} HTTP/1.1\r\n");
    for (name, values) in &request.headers {
        if MANAGED.iter().any(|m| name.eq_ignore_ascii_case(m)) || name.eq_ignore_ascii_case("x-mockserver-response-index") {
            continue;
        }
        for v in values {
            head.push_str(&format!("{name}: {v}\r\n"));
        }
    }
    head.push_str(&format!("host: {host_value}\r\nupgrade: websocket\r\nconnection: upgrade\r\nsec-websocket-key: {key}\r\n"));
    // `WebSocketClientHandshaker13.newHandshakeRequest`: an `origin` is generated when the client sent none
    // (`websocketOriginValue`: http/https by scheme, lower-cased host, the port unless it is the scheme's default).
    if request.first_header("origin").is_none() {
        head.push_str(&format!("origin: {}\r\n", origin_value(host, port, tls)));
    }
    let requested = request.first_header("sec-websocket-protocol").filter(|p| !p.is_empty()).map(str::to_string);
    if let Some(p) = &requested {
        head.push_str(&format!("sec-websocket-protocol: {p}\r\n"));
    }
    head.push_str("sec-websocket-version: 13\r\n\r\n");
    upstream.write_all(head.as_bytes()).await.map_err(|e| HandshakeFailed::Reason(format!("upstream WebSocket error: {e}")))?;

    // The relay's `HttpClientCodec` (master): the status line under Netty's 4096 bytes, the header lines
    // under `maxHeaderSize`, a head it cannot decode reported with the decoder's message.
    let mut buf = BytesMut::new();
    let (status, reason_phrase, headers) = match crate::client::read_websocket_handshake_head(&state.config, &mut upstream, &mut buf).await {
        (_, Ok(head)) => head,
        (max, Err(crate::client::Error::HeaderLimit(..))) => return Err(HandshakeFailed::Reason(format!("upstream WebSocket handshake response headers are larger than maxHeaderSize ({max} bytes)"))),
        (_, Err(crate::client::Error::Undecodable(fault))) => {
            // `getMessage()`, without the exception's class
            let message = fault.split_once(": ").map_or(fault.as_str(), |(_, message)| message);
            return Err(HandshakeFailed::Reason(format!("upstream WebSocket handshake response could not be read: {message}")));
        }
        (_, Err(crate::client::Error::TlsFailure(description))) => return Err(HandshakeFailed::Reason(format!("TLS with the upstream failed: {description}"))),
        (_, Err(_)) => return Err(HandshakeFailed::Reason("upstream WebSocket connection closed before handshake completed".into())),
    };
    let header = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone());
    if status == crate::forward_loop::LOOP_DETECTED && relays_loop_detected {
        let length = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.trim().parse::<usize>().ok()).unwrap_or(0);
        while buf.len() < length {
            match upstream.read_buf(&mut buf).await {
                Ok(n) if n > 0 => {}
                _ => break,
            }
        }
        let body = String::from_utf8_lossy(&buf[..length.min(buf.len())]).into_owned();
        return Err(HandshakeFailed::LoopDetected { phrase: Some(reason_phrase).filter(|p| !p.is_empty()), body });
    }
    if status != 101 {
        return Err(HandshakeFailed::Reason(format!("upstream WebSocket handshake failed: Invalid handshake response getStatus: {status}")));
    }
    if !header("upgrade").is_some_and(|u| u.eq_ignore_ascii_case("websocket")) {
        return Err(HandshakeFailed::Reason(format!("upstream WebSocket handshake failed: Invalid handshake response upgrade: {}", header("upgrade").unwrap_or_default())));
    }
    if !header("connection").is_some_and(|c| c.to_lowercase().contains("upgrade")) {
        return Err(HandshakeFailed::Reason(format!("upstream WebSocket handshake failed: Invalid handshake response connection: {}", header("connection").unwrap_or_default())));
    }
    let expected = derive_accept_key(key.as_bytes());
    if header("sec-websocket-accept").as_deref() != Some(expected.as_str()) {
        return Err(HandshakeFailed::Reason(format!(
            "upstream WebSocket handshake failed: Invalid handshake response sec-websocket-accept: {}, expected: {expected}",
            header("sec-websocket-accept").unwrap_or_default()
        )));
    }
    let negotiated = header("sec-websocket-protocol").filter(|p| !p.is_empty());
    let relayed = downstream_response_headers(&headers);
    Ok((upstream, buf, negotiated, relayed))
}

/// `URLEncoder.encode(value, "UTF-8")`.
fn url_encode(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// `failClient`: logged at WARN, answered `502` with the reason as its body, then closed.
async fn fail<S: AsyncWrite + Unpin>(state: &State, request: &HttpRequest, client: &mut S, message: &str) {
    log_failure(state, request, message);
    answer_and_close(state, request, client, 502, None, message.to_string()).await
}

/// `logFailure`: a WARN about the request.
fn log_failure(state: &State, request: &HttpRequest, message: &str) {
    // In the event log too (`retrieve?type=LOGS`), as 8.0.0's `MockServerLogger.logEvent` writes it.
    let entry = crate::recorded::LogEntry::at(crate::recorded::Level::Warn, "WebSocket proxy passthrough failed:{}").args([message]).request(request);
    crate::log::entry(state, &entry);
    // about the request, so a `clear` that matches it removes the entry
    state.log.message_about(entry, crate::recorded::Subject::Request(Arc::new(request.clone())));
}

/// `answerClientAndClose`: the response written straight to the channel, which is then closed.
async fn answer_and_close<S: AsyncWrite + Unpin>(state: &State, request: &HttpRequest, client: &mut S, status: u32, reason: Option<String>, body: String) {
    let mut reply = Reply::status(status);
    reply.reason = reason;
    reply.body = bytes::Bytes::from(body);
    // Written straight to the channel and closed: no `Connection` header.
    reply.suppress_connection_header = true;
    let mut reply = reply.finalize(request, &state.config);
    reply.close = true;
    let _ = client.write_all(&reply.encode_http1(false)).await;
    let _ = client.shutdown().await;
}

#[derive(Clone, Copy)]
enum Direction {
    ClientToUpstream,
    UpstreamToClient,
}

/// How one direction of the relay ended.
enum Ended {
    /// A close frame was read, and written on unless writes to that side had failed.
    Close,
    /// The side read from ended, or its read failed, without a close frame.
    Input,
    /// A write to the destination failed; the pump, polled again, reads on and drops what it reads.
    WriteFailed,
}

/// One direction's state, kept outside [`pump`] so that the frame on its way when the relay ends is still known.
struct Pump {
    /// Read from the source, not yet parsed into a frame.
    buf: BytesMut,
    /// The frame being written, and how much of it has been.
    out: Vec<u8>,
    written: usize,
    /// A write to the destination failed: frames are read on, and dropped.
    failed: bool,
    /// The frame being written is a close frame.
    closing: bool,
}

impl Pump {
    fn new(buf: BytesMut) -> Pump {
        Pump { buf, out: Vec::new(), written: 0, failed: false, closing: false }
    }
}

/// Relays frames from `from` to `to` until a close frame has been passed on, `from` ends or a write fails; polled
/// again, it first finishes the frame on its way. After a failed write, what `from` sends is read on and dropped.
async fn pump<R, W>(from: &mut R, to: &mut W, state: &mut Pump, direction: Direction, transcript: &Mutex<Transcript>, activity: &Mutex<Instant>) -> Ended
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        if !state.failed && state.written < state.out.len() {
            // written piece by piece, so that the relay ending meanwhile knows what is left of it
            while state.written < state.out.len() {
                match to.write(&state.out[state.written..]).await {
                    Ok(0) | Err(_) => {
                        state.failed = true;
                        return Ended::WriteFailed;
                    }
                    Ok(n) => state.written += n,
                }
            }
            if to.flush().await.is_err() {
                state.failed = true;
                return Ended::WriteFailed;
            }
        }
        if state.closing {
            return Ended::Close;
        }
        let frame = loop {
            if let Some(frame) = parse_frame(&mut state.buf) {
                break frame;
            }
            state.buf.reserve(16 * 1024);
            match from.read_buf(&mut state.buf).await {
                Ok(0) | Err(_) => return Ended::Input,
                Ok(_) => {}
            }
        };
        *activity.lock() = Instant::now();
        transcript.lock().record(direction, &frame);
        state.closing = frame.opcode == 0x8;
        if !state.failed {
            (state.out, state.written) = (frame.raw, 0);
        }
    }
}

struct Frame {
    opcode: u8,
    /// The frame as received, header included.
    raw: Vec<u8>,
    /// Unmasked payload.
    payload: Vec<u8>,
}

/// One whole frame off the front of `buf` (RFC 6455 §5.2), or `None` until it has arrived.
fn parse_frame(buf: &mut BytesMut) -> Option<Frame> {
    if buf.len() < 2 {
        return None;
    }
    let opcode = buf[0] & 0x0f;
    let masked = buf[1] & 0x80 != 0;
    let (length, mut offset) = match buf[1] & 0x7f {
        126 if buf.len() >= 4 => (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4),
        127 if buf.len() >= 10 => (u64::from_be_bytes(buf[2..10].try_into().ok()?) as usize, 10),
        126 | 127 => return None,
        n => (n as usize, 2),
    };
    let mask = if masked {
        if buf.len() < offset + 4 {
            return None;
        }
        let m = [buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]];
        offset += 4;
        Some(m)
    } else {
        None
    };
    if buf.len() < offset + length {
        return None;
    }
    let raw = buf.split_to(offset + length).to_vec();
    let mut payload = raw[offset..].to_vec();
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i % 4];
        }
    }
    Some(Frame { opcode, raw, payload })
}

/// `FrameTranscript`: at most `max_frames` frames, payloads cut to [`MAX_RECORDED_FRAME_BYTES`], text frames as
/// UTF-8 and the rest as base64.
struct Transcript {
    max_frames: i64,
    json: String,
    recorded: i64,
    truncated: bool,
}

impl Transcript {
    fn new(max_frames: i64) -> Transcript {
        Transcript { max_frames, json: "[".into(), recorded: 0, truncated: false }
    }

    fn record(&mut self, direction: Direction, frame: &Frame) {
        // Recording disabled (`webSocketProxyMaxRecordedFrames=0`) is not truncation.
        if self.max_frames <= 0 {
            return;
        }
        if self.recorded >= self.max_frames || self.json.len() >= MAX_TRANSCRIPT_JSON_CHARS {
            self.truncated = true;
            return;
        }
        let kept = &frame.payload[..frame.payload.len().min(MAX_RECORDED_FRAME_BYTES)];
        let (field, value) = match frame.opcode {
            0x1 => ("text", String::from_utf8_lossy(kept).into_owned()),
            _ => ("base64", base64::engine::general_purpose::STANDARD.encode(kept)),
        };
        let opcode = match frame.opcode {
            0x0 => "CONTINUATION",
            0x1 => "TEXT",
            0x2 => "BINARY",
            0x8 => "CLOSE",
            0x9 => "PING",
            0xa => "PONG",
            _ => "CONTINUATION",
        };
        if self.recorded > 0 {
            self.json.push(',');
        }
        let direction = match direction {
            Direction::ClientToUpstream => "CLIENT_TO_UPSTREAM",
            Direction::UpstreamToClient => "UPSTREAM_TO_CLIENT",
        };
        self.json.push_str(&format!(
            "{{\"direction\":\"{direction}\",\"opcode\":\"{opcode}\",\"{field}\":\"{}\",\"length\":{},\"truncated\":{}}}",
            escape_json(&value),
            frame.payload.len(),
            frame.payload.len() > kept.len()
        ));
        self.recorded += 1;
    }

    fn to_json(&self) -> String {
        format!("{}]", self.json)
    }
}

/// `FrameTranscript.escapeJson`, also `Http3ConnectUdpHandler.escapeJsonString`.
pub(crate) fn escape_json(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 16);
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// `recordUpgrade`: the upgrade request with a `101` carrying the transcript, as a forwarded request, and the
/// upstream's response headers the client was answered with (`HttpHeaders.names()` in order, each with `getAll`'s
/// values appended), but for the relay's own `x-mockserver-websocket-*` recording headers.
fn record(state: &State, request: &HttpRequest, subprotocol: Option<&str>, response_headers: &[(String, String)], transcript: &Transcript) {
    let mut headers: request::MultiMap = vec![
        ("Upgrade".into(), vec!["websocket".into()]),
        ("Connection".into(), vec!["Upgrade".into()]),
        ("x-mockserver-websocket-frames".into(), vec![transcript.recorded.to_string()]),
        ("x-mockserver-websocket-transcript-truncated".into(), vec![transcript.truncated.to_string()]),
    ];
    if let Some(p) = subprotocol {
        headers.push(("Sec-WebSocket-Protocol".into(), vec![p.to_string()]));
    }
    let mut names: Vec<&str> = Vec::new();
    for (name, _) in response_headers {
        if names.contains(&name.as_str()) || name.to_ascii_lowercase().starts_with("x-mockserver-websocket-") {
            continue;
        }
        names.push(name);
        let values = response_headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone());
        match headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
            Some((_, existing)) => existing.extend(values),
            None => headers.push((name.clone(), values.collect())),
        }
    }
    let body = transcript.to_json();
    let response = json!({
        "statusCode": 101,
        "reasonPhrase": "Switching Protocols",
        "headers": crate::recorded::map_value(&headers, false),
        "body": body,
    });
    let input_response = json!({
        "statusCode": 101,
        "reasonPhrase": "Switching Protocols",
        "headers": crate::recorded::list_form(&headers),
        "body": body,
    });
    let recorded = json!({
        "httpRequest": crate::recorded::ordered_with(request, crate::recorded::BodyForm::Recorded),
        "httpResponse": response,
        "id": uuid::Uuid::new_v4().to_string(),
        "priority": 0,
        "timeToLive": {"unlimited": true},
        "times": {"remainingTimes": 1},
    });
    let recorded_input = json!({
        "httpRequest": crate::recorded::input_request(request),
        "httpResponse": input_response,
        "times": {"remainingTimes": 1},
        "timeToLive": {"unlimited": true},
    });
    let message = state.info_enabled().then(|| {
        crate::recorded::LogEntry::new(crate::recorded::Kind::ForwardedRequest, "relayed WebSocket passthrough with {} frame(s) for forwarded upgrade request:{}")
            .args([crate::recorded::Arg::with_text(transcript.recorded.into(), transcript.recorded.to_string()), crate::recorded::logged(request).into()])
    });
    state.log.record_forwarded(request.clone(), response, Some((recorded, recorded_input)), None, message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_parse_masked_and_unmasked_with_extended_lengths() {
        let mut buf = BytesMut::from(&[0x81u8, 0x85, 1, 2, 3, 4, b'h' ^ 1, b'e' ^ 2, b'l' ^ 3, b'l' ^ 4, b'o' ^ 1][..]);
        let frame = parse_frame(&mut buf).unwrap();
        assert_eq!((frame.opcode, frame.payload.as_slice(), frame.raw.len()), (1, &b"hello"[..], 11));
        assert!(buf.is_empty());

        let mut long = vec![0x82u8, 126, 0x01, 0x00];
        long.extend(std::iter::repeat_n(7u8, 256));
        let mut buf = BytesMut::from(&long[..long.len() - 1]);
        assert!(parse_frame(&mut buf).is_none());
        buf.extend_from_slice(&[7]);
        assert_eq!(parse_frame(&mut buf).unwrap().payload.len(), 256);
    }

    #[test]
    fn transcript_records_text_and_base64_and_flags_truncation() {
        let mut t = Transcript::new(1);
        t.record(Direction::ClientToUpstream, &Frame { opcode: 1, raw: vec![], payload: b"a\"b".to_vec() });
        t.record(Direction::UpstreamToClient, &Frame { opcode: 2, raw: vec![], payload: vec![1] });
        assert_eq!(t.to_json(), r#"[{"direction":"CLIENT_TO_UPSTREAM","opcode":"TEXT","text":"a\"b","length":3,"truncated":false}]"#);
        assert!(t.truncated);
        let mut off = Transcript::new(0);
        off.record(Direction::ClientToUpstream, &Frame { opcode: 1, raw: vec![], payload: vec![] });
        assert!(!off.truncated && off.recorded == 0);
    }
}

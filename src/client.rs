//! Outbound HTTP/1.1 for forwarding, written by hand so header names keep their case and order on the way to
//! the upstream, as MockServer's Netty client does.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use parking_lot::Mutex;
use rustls::client::ResolvesClientCert;
use rustls::sign::CertifiedKey;
use crate::Config;
use crate::tls::ForwardIdentity;
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone)]
pub struct Outbound {
    pub method: String,
    /// Path plus `?query`, as it goes on the request line.
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// Sent as HTTP/2 when the upstream negotiates `h2` over TLS (`NettyHttpClient` downgrades it otherwise).
    pub http2: bool,
    /// A streaming response may be relayed as it arrives (`streamingResponsesEnabled`, for callers that relay).
    pub may_stream: bool,
    /// The body as MockServer holds it, decoded, when `body` is it in its `Content-Encoding`: the streaming intent is
    /// read from it (`requestExpectsStreamingResponse` reads `getBodyAsString`).
    pub decoded_body: Option<Bytes>,
}

impl Outbound {
    /// `requestExpectsStreamingResponse`: `Accept: text/event-stream`, Gemini's streaming method
    /// (`isStreamingRequestPath`: a JSON array sent an element at a time), or a JSON body asking for `"stream": true`.
    fn expects_streaming(&self) -> bool {
        static STREAM_TRUE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| regex::Regex::new(r#""stream"\s*:\s*true"#).expect("valid"));
        let header = |n: &str| self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.to_ascii_lowercase());
        let path = self.target.split_once('?').map_or(self.target.as_str(), |(p, _)| p);
        header("accept").is_some_and(|a| a.contains("text/event-stream"))
            || path.to_ascii_lowercase().contains(":streamgeneratecontent")
            || (header("content-type").is_some_and(|c| c.contains("json")) && STREAM_TRUE.is_match(&String::from_utf8_lossy(self.decoded_body.as_ref().unwrap_or(&self.body))))
    }

    /// Whether a response with these headers is relayed as it arrives (`StreamingAwareHttpObjectAggregator`): a
    /// stream of events (`isStreamingResponse`: Server-Sent Events, the AWS event stream, newline-delimited JSON), or a
    /// response to a request that asked for one.
    fn streams(&self, headers: &[(String, String)]) -> bool {
        let event_stream = |v: &String| {
            let v = v.to_ascii_lowercase();
            v.contains("text/event-stream") || v.contains("application/vnd.amazon.eventstream") || v.contains("application/x-ndjson")
        };
        self.may_stream && (headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("content-type") && event_stream(v)) || self.expects_streaming())
    }
}

#[derive(Default)]
pub struct Upstream {
    pub status: u32,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// A streamed body (`StreamingAwareHttpObjectAggregator` switched to relaying): `body` is empty and the chunks
    /// arrive here as the upstream sends them.
    pub stream: Option<tokio::sync::mpsc::Receiver<Bytes>>,
    pub timing: Timing,
    /// The body is text whatever its content type says (a gRPC response decoded to JSON is a `StringBody`).
    pub text_body: bool,
    /// The logged `x-mockserver-response-time-ms` when it is not the client's round trip (a streamed exchange logs
    /// the whole stream's duration).
    pub response_time: Option<i64>,
    /// Headers the log appends after the forward's own edits (`attachStreamingHeaders` on a completed stream).
    pub streamed_headers: Vec<(String, String)>,
    /// How `stream` ended, set before it closes.
    pub stream_end: Arc<StreamEnd>,
    /// MockServer answered for the upstream (the forward circuit breaker's 503): the client measured nothing, so the
    /// log shows no `timing`.
    pub untimed: bool,
    /// The forward loop guard's `508` (`crate::forward_loop`): its future carries no response function, so no
    /// override, modifier, response template or response callback class applies to it.
    pub loop_detected: bool,
}

/// How a streamed body ended: by an error rather than its last content (`StreamingBody.error`: the log marks the
/// capture truncated), and whether `StreamIdleTimeoutHandler` closed the connection first.
#[derive(Default)]
pub struct StreamEnd {
    cut: std::sync::atomic::AtomicBool,
    idle: OnceLock<String>,
    header_limit: OnceLock<String>,
    /// The HTTP/2 stream the body came on, for an HTTP/2 upstream.
    h2_stream: Option<u32>,
}

impl StreamEnd {
    fn cut(&self) {
        self.cut.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// The stream ended by an error (the connection closed or failed before its last content).
    pub fn is_cut(&self) -> bool {
        self.cut.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// `streamIdleTimeoutSeconds` passed without a read and the connection was closed: its `Channel.toString`.
    pub fn idle_channel(&self) -> Option<&str> {
        self.idle.get().map(String::as_str)
    }

    /// The trailers were over `maxHeaderSize` and the connection was closed (`ForwardHeaderLimit.Http1Response`,
    /// upstream a78886b4d, after 8.0.0): the refusal's reason, which the forward logs.
    pub fn header_limit(&self) -> Option<&str> {
        self.header_limit.get().map(String::as_str)
    }

    /// The stream ended aborted (`StreamingBody.StreamAbortedException`, upstream c9fb69fd5 with a78886b4d, after
    /// 8.0.0): the fixed image's writers end such a response without its terminating chunk (HTTP/2: a reset stream).
    /// It aborts on a header-limit refusal of the trailers, an upstream that closes or fails before the last content,
    /// content it cannot decode (an invalid chunk size, a coding that fails) and the idle timeout, a close-delimited
    /// body's included; 8.0.0 ends each of them with the terminating chunk. Only a body the upstream delimits by
    /// closing its connection completes. A read whose decoded content is over `maxResponseBodySize` aborts too
    /// (`UnwrittenBytesLimitExceededException`, master, [`decode_bounded`]).
    pub fn is_aborted(&self) -> bool {
        self.header_limit.get().is_some() || self.is_cut() || self.idle.get().is_some()
    }

    /// The HTTP/2 stream an HTTP/2 upstream answered on: `Http2StreamFrameToHttpObjectCodec` gives the streamed head an
    /// `x-http2-stream-id` header, which the logged response keeps (only `FullHttpResponseToMockServerHttpResponse`, the
    /// aggregated path, drops the `x-http2-*` family) and the client's head does not get.
    pub fn h2_stream(&self) -> Option<u32> {
        self.h2_stream
    }
}

/// `HttpResponse.timing` (epoch milliseconds), what the forwarding client measured.
#[derive(Debug, Clone, Copy, Default)]
pub struct Timing {
    pub request_started: i64,
    pub connection_established: i64,
    pub first_byte: i64,
    pub response_received: i64,
    /// The chaos latency MockServer adds before writing the forwarded response.
    pub injected_chaos_latency: Option<i64>,
    /// Sent on a pooled connection: its first-byte handler already removed itself, so no time to first byte.
    pub reused: bool,
}

impl Timing {
    /// The `timing` object as `HttpResponse` serialises it (properties alphabetical).
    pub fn json(&self) -> serde_json::Value {
        let mut o = serde_json::json!({
            "connectionEstablishedMillis": self.connection_established,
            "connectionTimeInMillis": self.connection_established - self.request_started,
            "requestStartedMillis": self.request_started,
            "responseReceivedMillis": self.response_received,
            "timeToFirstByteInMillis": self.first_byte - self.request_started,
            "totalTimeInMillis": self.response_received - self.request_started,
        });
        if self.reused && let Some(map) = o.as_object_mut() {
            map.remove("timeToFirstByteInMillis");
        }
        if let (Some(latency), Some(map)) = (self.injected_chaos_latency, o.as_object_mut()) {
            map.insert("injectedChaosLatencyMillis".into(), latency.into());
            map.sort_keys();
        }
        o
    }
}

fn now_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// The message of the `ConnectException` a refused connect fails with in the oracle image, which runs Netty's native
/// epoll transport (b765b8271; 8.0.0 on NIO read plain `Connection refused`): `Errors.newConnectException0`'s
/// `<method>(..) failed with error(<-errno>): <strerror>`. Netty's `AnnotatedConnectException` appends `: <address>`.
pub const CONNECT_REFUSED: &str = "finishConnect(..) failed with error(-111): Connection refused";

#[derive(Debug)]
pub enum Error {
    /// The connection could not be made for another reason (a proxy's handshake, a name TLS cannot use).
    Connect,
    /// The upstream refused the connection: the address as Java prints an `InetSocketAddress` (`host/ip:port`).
    Refused(String),
    /// The host did not resolve (`UnknownHostException`): the host, its port, and the resolver's reason (empty when
    /// the JDK's negative cache answered, whose exception carries the host alone).
    Resolve { host: String, port: u16, reason: String },
    /// A `forwardHttpsProxy` or `forwardSocksProxy` whose name did not resolve: the tunnel's channel connects with a
    /// no-op resolver (`resolveAtTunnelProxy`) to the address read at start, still unresolved, and NIO refuses it
    /// (`UnresolvedAddressException`, which has no message).
    UnresolvedAddress,
    /// No connection within `socketConnectionTimeoutInMillis` (Netty's `ConnectTimeoutException`): its message.
    ConnectTimeout(String),
    /// Nothing read within `maxSocketTimeoutInMillis` (`ReadTimeoutException`, which has no message).
    ReadTimeout,
    /// The TLS handshake with the upstream failed.
    Tls,
    /// The TLS handshake of a plain `java.net.HttpURLConnection` failed with this JSSE message.
    Jdk(String),
    /// The upstream closed the connection or sent something that is not a response.
    Protocol,
    /// The response body exceeded `maxResponseBodySize`: Netty's `TooLongHttpContentException` text.
    TooLarge(String),
    /// No response head within `maxFutureTimeoutInMillis` (`orTimeout`'s `TimeoutException`, which has no message;
    /// upstream 89d8a61c9, after 8.0.0).
    FutureTimeout,
    /// The response's headers were over `maxHeaderSize` (`HeaderLimitExceededException`, upstream a78886b4d, after
    /// 8.0.0): the reason, which is also the 502's body; and, for an upstream proxy's CONNECT reply, the message of the
    /// `ProxyConnectException` that carries it, which is what the failed future is logged with.
    HeaderLimit(String, Option<String>),
    /// TLS with the upstream failed for a reason upstream names (7a8b8c424, after 8.0.0): the fault's description,
    /// such as `NotSslRecordException: not an SSL/TLS record: 66 bytes`.
    TlsFailure(String),
    /// The upstream's HTTP/2 connection failed with an error upstream names (7a8b8c424, after 8.0.0): its error code and
    /// Netty's message, such as `FRAME_SIZE_ERROR: Frame length 5 invalid.`.
    Http2Failure(String),
    /// The connection could not be set up from the configuration (`ClientConfigurationException`, 7a8b8c424, after
    /// 8.0.0): the top-level cause, such as `RuntimeException: Exception creating SSL context for client`.
    SetUp(String),
    /// The response's content could not be decoded (`HttpContentDecompressor`): the exception's `toString`, such as
    /// `…DecompressionException: Input is not in the GZIP format`.
    Decode(String),
    /// The TLS handshake of a connection without an HTTP codec (the binary proxy) failed in `SslHandler.decode`: a
    /// `DecoderException` around the JDK's `SSLHandshakeException`, whose message this is (`(certificate_expired) PKIX
    /// path validation failed: …`).
    TlsDecoder(String),
    /// Netty's HTTP/1.1 decoder failed on the response (`UndecodableResponseException`, upstream c990e4a20, after
    /// 8.0.0): the decoder exception's simple class name and bounded message, such as `IllegalArgumentException:
    /// invalid version format: FOO`. 8.0.0 relayed what it had read (status 999 for a status line it could not read).
    Undecodable(String),
    /// The connection could not be made because there is no route to the address (`NoRouteToHostException`): its
    /// message.
    Unreachable(String),
    /// The connection could not be made because MockServer ran out of local ports or open files (`BindException`,
    /// `Cannot assign requested address`, `Too many open files`): its message.
    OutOfLocal(String),
    /// `UpstreamProxyUnreachableException` (upstream 48b7e14d2, 9.1.0): the connection to the upstream proxy `property`
    /// set failed with `cause`. It reads as its cause everywhere but in the 502's reason.
    ProxyUnreachable { property: &'static str, cause: Box<Error> },
    /// `PooledConnectionClosedException` (upstream 48b7e14d2, 9.1.0): a request whose method is not idempotent failed
    /// because the upstream closed the reused pooled connection it was sent on before any answer, `cause`; it was not
    /// sent again. It reads as its cause everywhere but in the 502's reason.
    PooledClosed { method: String, cause: Box<Error> },
    /// An upstream proxy answered a `CONNECT` with this status (code and reason phrase) rather than 200: Netty's
    /// `HttpProxyConnectException`, read as [`Error::Connect`] by every caller but the binary relay's.
    ConnectStatus(String),
    /// `NettyHttpClient.tunnelRefused` (9.1.0): the binary relay's `CONNECT` was answered with another status than
    /// 200; the `ConnectException`'s message, which names the proxy, its property and the status.
    TunnelRefused(String),
    /// Netty's direct-memory limit (`io.netty.maxDirectMemory`) refused the buffer that would have held
    /// more of the response: `OutOfDirectMemoryError`. `channel` is the upstream connection's `Channel.toString`.
    DirectMemory { channel: String, used: u64, max: u64 },
}

/// The direct memory the oracle's pool held besides the response's buffers when its read failed (measured at 76 bytes
/// on a fresh 9.2.0 oracle); the response's body is read in 64 KiB buffers.
const DIRECT_MEMORY_BASE_USED: u64 = 76;
const DIRECT_MEMORY_BUFFER: u64 = 65_536;

/// What a forward's read of `body_len` bytes asks of a direct-memory pool bounded by `max`: `(used, max)` when the
/// buffer for the next bytes does not fit. Each read is one 64 KiB buffer, kept until the aggregated message is done,
/// so the buffer after the last that fits is the one that fails (`used` is what the pool holds then).
pub(crate) fn direct_memory_refusal(body_len: usize, max: u64) -> Option<(u64, u64)> {
    let fitting = max.checked_sub(DIRECT_MEMORY_BASE_USED)? / DIRECT_MEMORY_BUFFER;
    (body_len as u64 > fitting * DIRECT_MEMORY_BUFFER).then_some((DIRECT_MEMORY_BASE_USED + fitting * DIRECT_MEMORY_BUFFER, max))
}

/// `UpstreamConnectFailure`'s causes (upstream 48b7e14d2, 9.1.0).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ConnectCause {
    Unresolved,
    Refused,
    TimedOut,
    Unreachable,
    OutOfLocal,
}

impl ConnectCause {
    fn for_proxy(self) -> &'static str {
        match self {
            ConnectCause::Unresolved => "its host name could not be resolved",
            ConnectCause::Refused => "it refused the connection",
            ConnectCause::TimedOut => "the connection timed out",
            ConnectCause::Unreachable => "there is no route to it",
            ConnectCause::OutOfLocal => "MockServer ran out of local ports or open files",
        }
    }
}

/// `UpstreamConnectFailure`'s texts: the cause of a forward's failed connection and what to change.
pub const UNRESOLVED_REASON: &str = "upstream host name could not be resolved: check it is spelled correctly and resolves where MockServer runs (its DNS, hosts file or container network)";
pub const REFUSED_REASON: &str = "upstream refused the connection: check the upstream is running and listening on the port forwarded to";
pub const TIMED_OUT_REASON: &str = "connection to the upstream timed out: check the upstream is reachable from where MockServer runs (firewall, routing, VPN or an upstream proxy it must go through)";
pub const TIMED_OUT_CONFIGURABLE_SUFFIX: &str = ", or raise socketConnectionTimeoutInMillis if it is slow to accept connections";
pub const UNREACHABLE_REASON: &str = "upstream address could not be reached (no route to it): check the address, and the network, VPN or upstream proxy MockServer needs to reach it";
pub const OUT_OF_LOCAL_REASON: &str = "MockServer ran out of local ports or open files to connect to the upstream: a forward whose target is MockServer itself repeats until this happens, so check the forward's host and port; otherwise lower the number of concurrent forwards or raise the open-file limit";
pub const FORWARD_LOOP_HINT: &str = "the forward's target is the address MockServer received the request on, so the request may have been forwarded back to MockServer itself, where it can match the same expectation again and loop: check the forward's host and port";

/// `UpstreamConnectFailure.targetsReceivingAddress`: whether a forward to `host`:`port` goes back to the address the
/// request was received on (`local_address` as a request records it, `127.0.0.1:1080`). A loopback or any-address
/// target counts whatever the request arrived on; names are compared as text.
pub fn targets_receiving_address(host: &str, port: u16, local_address: &str) -> bool {
    let Some((local_host, local_port)) = local_address.rsplit_once(':').filter(|(h, _)| !h.is_empty()) else { return false };
    if local_port != port.to_string() {
        return false;
    }
    let unbracket = |h: &str| h.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(h).to_string();
    let target = unbracket(host);
    let lower = target.to_ascii_lowercase();
    lower == "localhost" || lower.starts_with("127.") || lower == "::1" || lower == "0:0:0:0:0:0:0:1" || lower == "0.0.0.0" || target.eq_ignore_ascii_case(&unbracket(local_host))
}

impl Error {
    /// The failure under a [`Error::ProxyUnreachable`] or [`Error::PooledClosed`], which read as it; itself otherwise.
    /// [`Error::ConnectStatus`] as every caller but the binary relay's reads it: [`Error::Connect`].
    fn status_unnamed(self) -> Error {
        match self {
            Error::ConnectStatus(_) => Error::Connect,
            e => e,
        }
    }

    pub fn underlying(&self) -> &Error {
        match self {
            Error::ProxyUnreachable { cause, .. } | Error::PooledClosed { cause, .. } => cause.underlying(),
            _ => self,
        }
    }

    fn connect_cause(&self) -> Option<ConnectCause> {
        match self.underlying() {
            Error::Resolve { .. } | Error::UnresolvedAddress => Some(ConnectCause::Unresolved),
            Error::Refused(_) => Some(ConnectCause::Refused),
            Error::ConnectTimeout(_) => Some(ConnectCause::TimedOut),
            Error::Unreachable(_) => Some(ConnectCause::Unreachable),
            Error::OutOfLocal(_) => Some(ConnectCause::OutOfLocal),
            _ => None,
        }
    }

    /// `UpstreamConnectFailure.reason` (upstream 48b7e14d2, 9.1.0): why the forward's connection could not be made, or
    /// was lost before the response, and what to change; `None` for any other failure. `configurable`: the connect
    /// timeout is `socketConnectionTimeoutInMillis`, so a timeout's fix names it.
    pub fn connect_failure_reason(&self, configurable: bool) -> Option<String> {
        match self {
            Error::ProxyUnreachable { property, cause } => Some(format!(
                "upstream proxy set by {property} could not be reached ({}): check the proxy is running and its host and port are correct",
                cause.connect_cause().map_or("the connection failed", ConnectCause::for_proxy)
            )),
            Error::PooledClosed { method, .. } => Some(format!(
                "upstream closed the pooled keep-alive connection the request was sent on without answering, and a {method} is not sent again in case the upstream acted on it: if the upstream closes idle connections, set forwardConnectionPoolIdleTimeoutMillis below its keep-alive timeout or set forwardConnectionPoolEnabled to false; otherwise the upstream may have closed the connection to reject the request"
            )),
            _ => self.connect_cause().map(|cause| match cause {
                ConnectCause::Unresolved => UNRESOLVED_REASON.to_string(),
                ConnectCause::Refused => REFUSED_REASON.to_string(),
                ConnectCause::TimedOut if configurable => format!("{TIMED_OUT_REASON}{TIMED_OUT_CONFIGURABLE_SUFFIX}"),
                ConnectCause::TimedOut => TIMED_OUT_REASON.to_string(),
                ConnectCause::Unreachable => UNREACHABLE_REASON.to_string(),
                ConnectCause::OutOfLocal => OUT_OF_LOCAL_REASON.to_string(),
            }),
        }
    }

    /// `Throwable.getMessage()` of the exception upstream's client completes the response future with; `None` for
    /// one without a message.
    pub fn exception_message(&self) -> Option<String> {
        Some(match self.underlying() {
            Error::Connect | Error::ConnectStatus(_) => "failed to connect to remote socket while forwarding request".into(),
            Error::TunnelRefused(message) => message.clone(),
            Error::Refused(address) => format!("{CONNECT_REFUSED}: {address}"),
            Error::Resolve { host, reason, .. } if reason.is_empty() => host.clone(),
            Error::Resolve { host, reason, .. } => format!("{host}: {reason}"),
            Error::UnresolvedAddress => return None,
            Error::ConnectTimeout(message) | Error::TooLarge(message) => message.clone(),
            Error::ReadTimeout => return None,
            Error::Tls => "TLS handshake exception while forwarding request".into(),
            Error::Jdk(message) => message.clone(),
            Error::Protocol => "Channel handler removed before valid response has been received".into(),
            Error::FutureTimeout => return None,
            Error::HeaderLimit(reason, _) => reason.clone(),
            Error::TlsFailure(description) => format!("TLS with the upstream failed: {description}"),
            Error::Http2Failure(description) => format!("HTTP/2 error from the upstream: {description}"),
            Error::SetUp(description) => format!("connection to the upstream could not be set up: {description}"),
            Error::Decode(exception) => exception.clone(),
            Error::TlsDecoder(message) => format!("javax.net.ssl.SSLHandshakeException: {message}"),
            Error::Undecodable(description) => format!("response from the upstream could not be decoded: {description}"),
            Error::Unreachable(message) | Error::OutOfLocal(message) => message.clone(),
            Error::DirectMemory { used, max, .. } => format!("failed to allocate {DIRECT_MEMORY_BUFFER} byte(s) of direct memory (used: {used}, max: {max})"),
            Error::ProxyUnreachable { .. } | Error::PooledClosed { .. } => unreachable!("underlying"),
        })
    }

    /// The body of the 502 a failed forward is answered with: the reason, for the failures upstream names one for
    /// (`returnedHeaderLimitFailure`, `upstreamFailureReason`), or the cause of a connection that could not be made
    /// (`UpstreamConnectFailure.reason`, upstream 48b7e14d2, 9.1.0; `configurable` as there); none (an empty 502) for
    /// any other.
    pub fn bad_gateway_body(&self, configurable: bool) -> Option<String> {
        match self.underlying() {
            Error::HeaderLimit(..) => self.exception_message(),
            _ if self.is_named_failure() => self.exception_message(),
            _ => self.connect_failure_reason(configurable),
        }
    }

    /// What `handleProxyPass` reports after `proxy pass forwarding failed for <target>: `: `throwable.getMessage()` of the
    /// `ExecutionException` the response future's `get` throws, which is its cause's `toString` (8.0.0): `…AnnotatedConnectException: Connection refused: host/ip:port`,
    /// `java.net.UnknownHostException: host: reason`, or for a failed TLS handshake 8.0.0's closed-channel
    /// `SocketConnectionException`. A failure upstream names (7a8b8c424, after 8.0.0) is the exception the fixed image
    /// wraps it in, naming the target `host:port` (`TLS handshake with h:p failed: …`). The future's own timeout
    /// (`TimeoutException`, not wrapped) has no message: `null`.
    pub fn proxy_pass_cause(&self, host: &str, port: u16) -> String {
        const CONNECTION: &str = "org.mockserver.httpclient.SocketConnectionException";
        match self.underlying() {
            Error::FutureTimeout => "null".into(),
            Error::Tls => Error::Protocol.exception_string(),
            Error::TlsFailure(description) => format!("{CONNECTION}: TLS handshake with {host}:{port} failed: {description}"),
            Error::Http2Failure(description) => format!("{CONNECTION}: HTTP/2 connection to {host}:{port} failed: {description}"),
            Error::SetUp(description) => format!("org.mockserver.httpclient.ClientConfigurationException: connection to {host}:{port} could not be set up: {description}"),
            Error::Undecodable(description) => format!("org.mockserver.httpclient.UndecodableResponseException: response from {host}:{port} could not be decoded: {description}"),
            _ => self.exception_string(),
        }
    }

    /// Whether upstream's `upstreamFailureReason` names it (7a8b8c424, after 8.0.0): a configuration error, a TLS fault,
    /// an HTTP/2 error or an undecodable response (c990e4a20), answered with the reason and logged once at ERROR with
    /// the request.
    pub fn is_named_failure(&self) -> bool {
        matches!(self.underlying(), Error::TlsFailure(_) | Error::Http2Failure(_) | Error::SetUp(_) | Error::Undecodable(_))
    }

    /// The exception's class as the (shaded) server names it.
    pub fn exception_class(&self) -> &'static str {
        match self.underlying() {
            Error::Connect | Error::ConnectStatus(_) | Error::Protocol => "org.mockserver.httpclient.SocketConnectionException",
            Error::TunnelRefused(_) => "java.net.ConnectException",
            Error::Refused(_) => "shaded_package.io.netty.channel.AbstractChannel$AnnotatedConnectException",
            Error::Resolve { .. } => "java.net.UnknownHostException",
            Error::UnresolvedAddress => "java.nio.channels.UnresolvedAddressException",
            Error::ConnectTimeout(_) => "shaded_package.io.netty.channel.ConnectTimeoutException",
            Error::ReadTimeout => "shaded_package.io.netty.handler.timeout.ReadTimeoutException",
            Error::Tls | Error::Jdk(_) => "javax.net.ssl.SSLHandshakeException",
            Error::TooLarge(_) => "shaded_package.io.netty.handler.codec.TooLongFrameException",
            Error::FutureTimeout => "java.util.concurrent.TimeoutException",
            Error::HeaderLimit(..) => "org.mockserver.httpclient.HeaderLimitExceededException",
            Error::TlsFailure(_) | Error::Http2Failure(_) => "org.mockserver.httpclient.SocketConnectionException",
            Error::SetUp(_) => "org.mockserver.httpclient.ClientConfigurationException",
            Error::Decode(_) | Error::TlsDecoder(_) => "shaded_package.io.netty.handler.codec.DecoderException",
            Error::Undecodable(_) => "org.mockserver.httpclient.UndecodableResponseException",
            Error::Unreachable(_) => "java.net.NoRouteToHostException",
            Error::OutOfLocal(_) => "java.net.BindException",
            Error::DirectMemory { .. } => "shaded_package.io.netty.util.internal.OutOfDirectMemoryError",
            Error::ProxyUnreachable { .. } | Error::PooledClosed { .. } => unreachable!("underlying"),
        }
    }

    /// `Throwable.toString()`: the class, then the message when there is one.
    pub fn exception_string(&self) -> String {
        if let Error::Decode(exception) = self.underlying() {
            return exception.clone();
        }
        match self.exception_message() {
            Some(message) => format!("{}: {message}", self.exception_class()),
            None => self.exception_class().to_string(),
        }
    }

    /// The message the client logs when the exception reaches it: the message, or the simple class name without one.
    pub fn logged_message(&self) -> String {
        self.exception_message().unwrap_or_else(|| self.simple_class().to_string())
    }

    /// `ExceptionHandling.boundedFaultDescription`: the simple class name, then the message cut to 256 characters.
    pub fn fault_description(&self) -> String {
        match self.exception_message().filter(|m| !m.is_empty()) {
            Some(message) => fault(self.simple_class(), &message),
            None => self.simple_class().to_string(),
        }
    }

    fn simple_class(&self) -> &'static str {
        self.exception_class().rsplit(['.', '$']).next().unwrap_or_default()
    }

    /// Whether upstream's `connectionException` classifies it as a failure to connect (`SocketConnectionException`,
    /// `ConnectException`), which a forward reports as `failed to connect to remote socket while forwarding request`.
    pub fn is_connection_failure(&self) -> bool {
        matches!(self.underlying(), Error::Connect | Error::Refused(_) | Error::Unreachable(_) | Error::OutOfLocal(_))
    }

    /// `NettyHttpClient.sendRequest(request, timeout, unit)`'s failure: the exception a blocking send throws.
    pub fn send_failure(&self) -> String {
        match self.underlying() {
            Error::Refused(address) => format!("Unable to connect to socket {address}"),
            Error::ConnectTimeout(message) => format!("Unable to connect to socket {}", message.rsplit(": ").next().unwrap_or_default()),
            Error::Resolve { host, port, .. } => format!("Unable to resolve host {host}/<unresolved>:{port}"),
            // Neither an `IOException` nor a `ConnectException`: `RuntimeException("Exception while sending request - "
            // + ex.getMessage())`, the `ExecutionException`'s message being its cause's `toString`.
            Error::UnresolvedAddress => format!("Exception while sending request - {}", self.exception_string()),
            Error::ReadTimeout => "Exception while sending request - io.netty.handler.timeout.ReadTimeoutException".into(),
            Error::TooLarge(message) => message.clone(),
            Error::Tls => "javax.net.ssl.SSLHandshakeException".into(),
            Error::Jdk(message) => message.clone(),
            Error::Connect | Error::ConnectStatus(_) => "connection timed out".into(),
            Error::TunnelRefused(message) => message.clone(),
            Error::Protocol => "Connection closed".into(),
            Error::FutureTimeout => "java.util.concurrent.TimeoutException".into(),
            Error::HeaderLimit(reason, _) => reason.clone(),
            Error::TlsFailure(_) | Error::Http2Failure(_) | Error::SetUp(_) | Error::Undecodable(_) => self.exception_message().unwrap_or_default(),
            Error::Decode(exception) => exception.clone(),
            Error::TlsDecoder(_) => self.exception_string(),
            Error::Unreachable(_) | Error::OutOfLocal(_) => self.exception_message().unwrap_or_default(),
            Error::DirectMemory { .. } => self.exception_string(),
            Error::ProxyUnreachable { .. } | Error::PooledClosed { .. } => unreachable!("underlying"),
        }
    }
}

/// The same for a request body the server reads: the aggregator also keeps what the socket's reads left over in their
/// buffers, so the read fails earlier, and where depends on the sizes the reads came in (the oracle read 6.2 MB and
/// 6.6 MB in full and cut 6.8 MB once in two tries, 6.4 MB and 6.6 MB once each, 7 MB and over every time at an 8 MiB
/// limit): the line is drawn at four fifths of the limit, inside that band. `used` is what the pool holds
/// at the cut, which differs from run to run.
pub(crate) fn request_direct_memory_refusal(body_len: usize, max: u64) -> Option<(u64, u64)> {
    if (body_len as u64) <= max / 5 * 4 {
        return None;
    }
    direct_memory_refusal(usize::MAX, max)
}

/// The read buffer an HTTP/2 connection asks the pool for when its DATA outgrows the limit.
pub(crate) const H2_DIRECT_MEMORY_BUFFER: u64 = 131_072;

/// The same for an HTTP/2 request body: each DATA frame's payload is a slice that keeps its whole read
/// buffer, of up to 128 KiB, until the stream's aggregator is done. At an 8 MiB limit the oracle read 7.0 MB in full
/// and cut 7.5 MB, twice each (5-8 MB in half-megabyte steps): the line is drawn at seven eighths of the limit.
pub(crate) fn h2_request_direct_memory_refusal(body_len: usize, max: u64) -> Option<(u64, u64)> {
    if (body_len as u64) <= max / 8 * 7 {
        return None;
    }
    let fitting = max.checked_sub(DIRECT_MEMORY_BASE_USED)? / H2_DIRECT_MEMORY_BUFFER;
    Some((DIRECT_MEMORY_BASE_USED + fitting * H2_DIRECT_MEMORY_BUFFER, max))
}

/// The buffer the QUIC codec asks the pool for when an HTTP/3 request body outgrows the limit.
pub(crate) const H3_DIRECT_MEMORY_BUFFER: u64 = 16_384;

/// The same for an HTTP/3 request body: at an 8 MiB limit the oracle read 7.0 MB in full and cut 7.5 MB,
/// twice each (5-8 MB in half-megabyte steps), as over HTTP/2: the line is drawn at seven eighths of the limit.
pub(crate) fn h3_request_direct_memory_refusal(body_len: usize, max: u64) -> Option<(u64, u64)> {
    if (body_len as u64) <= max / 8 * 7 {
        return None;
    }
    let fitting = max.checked_sub(DIRECT_MEMORY_BASE_USED)? / H3_DIRECT_MEMORY_BUFFER;
    Some((DIRECT_MEMORY_BASE_USED + fitting * H3_DIRECT_MEMORY_BUFFER, max))
}

/// `socketConnectionTimeoutInMillis` default.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// `socketConnectionTimeoutInMillis`: how long a forward waits for its connection.
pub fn connect_timeout(config: &Config) -> Duration {
    Duration::from_millis(config.int_property("socketConnectionTimeoutInMillis", 20_000).max(1) as u64)
}

/// A read timeout that never fires (about thirty years), for `maxSocketTimeoutInMillis` 0.
const NO_READ_TIMEOUT: Duration = Duration::from_secs(30 * 365 * 24 * 3600);

/// `maxSocketTimeoutInMillis` (the client's `ReadTimeoutHandler`): how long a response may take to arrive.
fn read_timeout(config: &Config) -> Duration {
    // `ReadTimeoutHandler(0)` (an `IdleStateHandler`) reads no timeout at all from 0 or less: the response is waited
    // for as long as the forward's `maxFutureTimeoutInMillis` backstop allows (`forward::send_via`).
    match config.int_property("maxSocketTimeoutInMillis", 20_000) {
        millis if millis <= 0 => NO_READ_TIMEOUT,
        millis => Duration::from_millis(millis as u64),
    }
}

/// What bounds one exchange: the aggregated body's size and the wait for the response.
struct Limits {
    max_body: usize,
    read_timeout: Duration,
    /// `maxHeaderSize`: the response's header lines together (upstream a78886b4d, after 8.0.0; Netty's 8 KiB before).
    max_header: usize,
    /// `streamIdleTimeoutSeconds`, which replaces `read_timeout` once the response streams.
    stream_idle: Option<Duration>,
    /// The connection's `Channel.toString`, for the idle timeout's log entry.
    channel: String,
    /// `io.netty.maxDirectMemory`, which bounds the response a forward collects.
    direct_memory: Option<u64>,
}

fn limits(config: &Config, channel: String) -> Limits {
    Limits { max_body: max_body(config), read_timeout: read_timeout(config), max_header: max_header(config), stream_idle: stream_idle(config), channel, direct_memory: crate::config::netty_max_direct_memory(config) }
}

/// `streamIdleTimeoutSeconds` (default 60, floored at 0): how long a streamed response may go without a read before
/// `StreamIdleTimeoutHandler` closes its connection; 0 leaves it unbounded.
fn stream_idle(config: &Config) -> Option<Duration> {
    let seconds = config.int_property("streamIdleTimeoutSeconds", 60).max(0) as u64;
    (seconds > 0).then(|| Duration::from_secs(seconds))
}

/// Netty's `Channel.toString` for a forwarding connection: `[id: 0x…, L:/local - R:host/remote]`; the remote
/// `InetSocketAddress` prints the host name it was resolved from before the slash (nothing for an address literal).
fn channel_description(stream: &TcpStream, host: &str) -> String {
    let id = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
    let address = |a: std::io::Result<std::net::SocketAddr>| a.map(crate::server::java_socket_address).unwrap_or_default();
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let name = if host.parse::<std::net::IpAddr>().is_ok() { "" } else { host };
    format!("[id: 0x{id}, L:/{} - R:{name}/{}]", address(stream.local_addr()), address(stream.peer_addr()))
}

/// Sends `request` to `host:port`, over TLS when `secure`: like upstream's default
/// `forwardProxyTLSX509CertificatesTrustManagerType=ANY`, any server certificate is accepted.
/// `identity` is the client certificate offered when the upstream asks for one. `forwardHttpProxy`,
/// `forwardHttpsProxy` and `forwardSocksProxy` route it through another proxy (`HttpClientInitializer`).
pub async fn send(
    config: &Config,
    host: &str,
    port: u16,
    secure: bool,
    request: &Outbound,
    identity: Option<ForwardIdentity>,
    connect_timeout: Duration,
) -> Result<Upstream, Error> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if secure {
        set_up(config, host)?;
    } else {
        negotiated(config, host, false, false).await;
    }
    // `NettyHttpClient.upstreamProxiesFor`: none for a destination on `noProxyHosts`, which is connected to directly.
    let proxies = UpstreamProxies::for_destination(config, host);
    // `NettyHttpClient.sendRequest`: a plain request goes to the HTTP proxy in absolute form, with
    // `Proxy-Authorization` when credentials are configured.
    if let Some(proxy) = proxies.http.as_ref().filter(|_| !secure) {
        let stream = connect_proxy(config, proxy, false, connect_timeout).await?;
        let channel = channel_description(&stream, &proxy.host);
        let mut request = request.clone();
        let authority = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| format!("{host}:{port}"));
        request.target = format!("http://{authority}{}", request.target);
        // `ProxyConfiguration.addProxyAuthenticationHeader` appends it to the request's own headers, which
        // `MockServerHttpRequestToFullHttpRequest` writes before `host`, `accept-encoding`, `content-length` and the
        // rest it sets (each of the first two only when there is one).
        if let Some(authorization) = proxy.authorization() {
            const SET: &[&str] = &["host", "accept-encoding", "content-length"];
            let at = request.headers.iter().position(|(k, _)| SET.iter().any(|s| k.eq_ignore_ascii_case(s))).unwrap_or(request.headers.len());
            request.headers.insert(at, ("proxy-authorization".into(), authorization));
        }
        return exchange(stream, &request, limits(config, channel)).await.map(|(upstream, _)| upstream);
    }
    // Through an HTTPS or SOCKS proxy the destination's name is left to the proxy (`resolveAtTunnelProxy`: a no-op
    // resolver; `unresolvedUnlessIpLiteral`): sent by name in the `CONNECT` or SOCKS5 request, an IP literal as an
    // address.
    let (stream, channel) = match (&proxies.https, &proxies.socks) {
        (Some(proxy), _) if secure => {
            let mut stream = connect_proxy(config, proxy, true, connect_timeout).await?;
            http_connect(&mut stream, proxy, host, port, max_header(config)).await.map_err(Error::status_unnamed)?;
            let channel = channel_description(&stream, &proxy.host);
            (stream, channel)
        }
        (_, Some(proxy)) => {
            let mut stream = connect_proxy(config, proxy, true, connect_timeout).await?;
            socks5_connect(&mut stream, proxy, host, port).await?;
            let channel = channel_description(&stream, &proxy.host);
            (stream, channel)
        }
        _ => {
            let stream = connect_forward(config, host, port, connect_timeout).await?;
            let channel = channel_description(&stream, host);
            (stream, channel)
        }
    };
    let _ = stream.set_nodelay(true);
    if !secure {
        return exchange(stream, request, limits(config, channel)).await.map(|(upstream, _)| upstream);
    }
    // `HttpClientInitializer`: the proxy's handler first, then TLS offering `h2` inside the tunnel; a connection
    // through an upstream proxy is never pooled.
    if request.http2 {
        return h2_over(config, host, port, stream, channel, request, identity).await.map(|(upstream, _)| upstream);
    }
    let name = ServerName::try_from(host.to_string()).map_err(|_| Error::Connect)?;
    let connector = tokio_rustls::TlsConnector::from(tls_config(Some(config), identity, host));
    let tls = handshake(config, &connector, name, stream).await?;
    negotiated(config, host, true, false).await;
    exchange(tls, request, limits(config, channel)).await.map(|(upstream, _)| upstream)
}

/// How [`send_with_timeout`] reaches its target.
pub enum Route<'a> {
    /// `NettyHttpClient.sendRequest(request, timeout, unit)`: the configured client (upstream proxies, TLS identity
    /// aside), the whole exchange bounded by the timeout.
    Configured(&'a Config),
    /// A plain `java.net.HttpURLConnection`: no proxy, the connection and each read bounded by the timeout.
    Direct,
}

/// One request sent within `timeout`: `None` when a [`Route::Configured`] exchange did not complete in time (a
/// [`Route::Direct`] one reports [`Error::ConnectTimeout`] or [`Error::ReadTimeout`] instead).
pub async fn send_with_timeout(route: Route<'_>, host: &str, port: u16, secure: bool, request: &Outbound, timeout: Duration) -> Option<Result<Upstream, Error>> {
    match route {
        Route::Configured(config) => tokio::time::timeout(timeout, send(config, host, port, secure, request, None, connect_timeout(config))).await.ok(),
        Route::Direct => Some(send_direct(host, port, secure, request, timeout).await),
    }
}

async fn send_direct(host: &str, port: u16, secure: bool, request: &Outbound, timeout: Duration) -> Result<Upstream, Error> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let stream = connect_timed(host, port, timeout).await?;
    let _ = stream.set_nodelay(true);
    let limits = Limits { max_body: usize::MAX, read_timeout: timeout, max_header: usize::MAX, stream_idle: None, channel: String::new(), direct_memory: None };
    let upstream = if secure {
        let name = ServerName::try_from(host.to_string()).map_err(|_| Error::Connect)?;
        let connector = tokio_rustls::TlsConnector::from(jdk_tls_config(jdk_sni(host)));
        let tls = match tokio::time::timeout(timeout, connector.connect(name, stream)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(jdk_handshake_failure(&e)),
            Err(_) => return Err(Error::Tls),
        };
        exchange(tls, request, limits).await?.0
    } else {
        exchange(stream, request, limits).await?.0
    };
    Ok(upstream)
}

thread_local! {
    /// The hook of the [`OnTls`] being polled on this thread: a `*const &(dyn Fn(&ClientEvent) + Sync)`, set only for
    /// the duration of one poll of the future it wraps.
    static ON_TLS: std::cell::Cell<Option<*const ()>> = const { std::cell::Cell::new(None) };
}

/// What the client tells the hook of the [`OnTls`] it runs in.
pub enum ClientEvent<'a> {
    /// A fresh TLS connection to an upstream is being set up, before it resolves or connects: where
    /// `HttpClientInitializer.initChannel` builds the client's TLS context (its CA load is logged, for a
    /// refused connection too).
    TlsConnecting,
    /// `HttpClientInitializer.recordForwardUpstreamProtocol`: a new upstream connection's protocol, once
    /// its pipeline is configured: at channel set-up for a plain connection (before it connects, so a refused one
    /// too), after the handshake's ALPN for a TLS one. `host` is the `REMOTE_SOCKET`'s host string, which for a TLS
    /// connection to an address literal is its reverse-lookup name (`createClientSslContext` asked `getHostName()`).
    Negotiated { host: &'a str, http2: bool },
    /// `NettyHttpClient.proxyFailure`: the connection to an upstream proxy failed (its name did not resolve, or it
    /// refused or did not answer), so the target behind it was never contacted. `proxy` is its `host:port` as
    /// configured, `property` the one that set it, `cause` the failure the forward fails with.
    ProxyUnreachable { proxy: &'a str, property: &'static str, cause: &'a Error },
}

/// `fut`, with `hook` told of the client's [`ClientEvent`]s while it runs.
pub fn on_tls<'a, T>(hook: &'a (dyn Fn(&ClientEvent) + Sync), fut: impl std::future::Future<Output = T> + Send + 'a) -> OnTls<'a, T> {
    OnTls { hook, inner: Box::pin(fut) }
}

pub struct OnTls<'a, T> {
    hook: &'a (dyn Fn(&ClientEvent) + Sync),
    inner: std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>,
}

impl<T> std::future::Future for OnTls<'_, T> {
    type Output = T;
    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<T> {
        /// Puts back the hook that was in place before this poll, when the poll returns or unwinds.
        struct Restore(Option<*const ()>);
        impl Drop for Restore {
            fn drop(&mut self) {
                ON_TLS.set(self.0);
            }
        }
        let this = &mut *self;
        let hook: *const &(dyn Fn(&ClientEvent) + Sync) = &this.hook;
        let _restore = Restore(ON_TLS.replace(Some(hook.cast())));
        this.inner.as_mut().poll(cx)
    }
}

#[cfg(test)]
mod on_tls_tests {
    use std::future::Future;

    /// A panic in the wrapped future leaves no pointer into the `OnTls` behind on the thread (tokio keeps the worker).
    #[test]
    fn on_tls_restores_the_previous_hook_when_its_future_panics() {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let hook = |_: &super::ClientEvent| {};
        let mut fut = super::on_tls(&hook, async { panic!("inner future panics") });
        let before = super::ON_TLS.get();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| std::pin::Pin::new(&mut fut).poll(&mut cx)));
        assert!(unwound.is_err());
        assert_eq!(super::ON_TLS.get(), before);
        assert_eq!(before, None);
    }
}

/// Tells the hook of the [`OnTls`] being polled, if any, of `event`.
fn client_event(event: &ClientEvent) {
    if let Some(hook) = ON_TLS.get() {
        // SAFETY: set by `OnTls::poll` to its own `hook` field only while it polls its inner future, which is what
        // is running here on this thread; the reference it points at outlives that poll. A drop guard restores the
        // previous value when the poll returns or unwinds, so no pointer outlives it even after a panic.
        let hook = unsafe { *hook.cast::<&(dyn Fn(&ClientEvent) + Sync)>() };
        hook(event);
    }
}

fn tls_connecting() {
    client_event(&ClientEvent::TlsConnecting);
}

/// `HttpClientInitializer.recordForwardUpstreamProtocol` for a new connection to `host`: the metric and
/// [`ClientEvent::Negotiated`]. A plain connection counts as its pipeline is built, before it connects (so a refused
/// one counts too), a TLS one once ALPN has picked the protocol.
async fn negotiated(config: &Config, host: &str, secure: bool, http2: bool) {
    if crate::metrics::enabled(config) {
        config.metrics.upstream_connection(host.trim_start_matches('[').trim_end_matches(']'), http2);
    }
    if ON_TLS.get().is_none() {
        return;
    }
    let host = if secure { crate::mcp::spec_tools::url_host(host).await } else { host.trim_start_matches('[').trim_end_matches(']').to_string() };
    client_event(&ClientEvent::Negotiated { host: &host, http2 });
}

/// [`send`] through the forward connection pool (`forwardConnectionPoolEnabled`, on by default): a direct upstream
/// connection left open by a complete keep-alive response is reused for the next request to the same host, port,
/// scheme and client certificate. A pooled connection the upstream has closed while idle is dropped from the pool and replaced by a new one.
/// A request that fails on a reused HTTP/1.1 connection before any byte of a response (the upstream closed or reset
/// it, what a stale connection looks like) is sent once more on a new connection when it is idempotent
/// (`isRetryableReusedConnectionFailure`), and whatever its method when the connection was found closed before
/// anything of it was written.
/// `connections` is the forwarding server's own pool ([`ForwardConnections`]).
#[allow(clippy::too_many_arguments, reason = "the route, target and request of one forward, each its own argument as at every call site")]
pub async fn send_pooled(
    config: &Config,
    connections: &ForwardConnections,
    host: &str,
    port: u16,
    secure: bool,
    request: &Outbound,
    identity: Option<ForwardIdentity>,
    connect_timeout: Duration,
) -> Result<Upstream, Error> {
    let started = now_millis();
    let clock = std::time::Instant::now();
    let result = send_pooled_untimed(config, connections, host, port, secure, request, identity, connect_timeout, None).await;
    if crate::metrics::enabled(config) && let Ok(upstream) = &result {
        config.metrics.forwarded(host, clock.elapsed().as_secs_f64(), upstream.status);
    }
    // `recordForwardMetrics`: an SLO sample per answered forward, whatever `metricsEnabled` says.
    if let Ok(upstream) = &result {
        let latency = if upstream.timing.response_received > 0 { upstream.timing.response_received - started } else { clock.elapsed().as_millis() as i64 };
        config.slo.record(config, latency, upstream.status >= 500, crate::slo::Scope::Forward, host.trim_start_matches('[').trim_end_matches(']'));
    }
    let mut upstream = result?;
    upstream.timing.request_started = started;
    if upstream.timing.connection_established == 0 {
        upstream.timing.connection_established = started;
    }
    if upstream.timing.first_byte == 0 {
        upstream.timing.first_byte = upstream.timing.response_received.max(started);
    }
    if upstream.timing.response_received == 0 {
        upstream.timing.response_received = now_millis();
    }
    Ok(upstream)
}

/// Which connection a pooled HTTP/1.1 exchange goes out on, as [`send_pooled_traced`] picks it.
pub enum Carrier<'a> {
    /// A new connection, before it is registered and connects.
    New,
    /// That new connection, connected: its `Channel.toString`.
    Connected(&'a str),
    /// An idle pooled connection, reused: its `Channel.toString`.
    Reused(&'a str),
}

/// Told which connection carries a request; may answer an instant before which that connection's event loop runs
/// nothing ([`send_pooled_traced`]).
type CarrierHook<'a> = dyn Fn(Carrier<'_>) -> Option<tokio::time::Instant> + Sync + 'a;

/// [`send_pooled`] without the forward's metrics, SLO samples and timing fill-ins (a client of the server's own, such
/// as a runtime LLM client's `NettyHttpClient`), telling `carrier` which connection carries the request. `carrier`
/// may answer with an instant before which the connection's event loop runs nothing: the request is written (and a
/// new connection's connect completed) only then, as the loop's queued `writeAndFlush` and connect listener are.
#[allow(clippy::too_many_arguments, reason = "the route, target and request of one forward, each its own argument as at every call site")]
pub async fn send_pooled_traced(
    config: &Config,
    connections: &ForwardConnections,
    host: &str,
    port: u16,
    secure: bool,
    request: &Outbound,
    connect_timeout: Duration,
    carrier: &CarrierHook<'_>,
) -> Result<Upstream, Error> {
    send_pooled_untimed(config, connections, host, port, secure, request, None, connect_timeout, Some(carrier)).await
}

#[allow(clippy::too_many_arguments)]
async fn send_pooled_untimed(
    config: &Config,
    connections: &ForwardConnections,
    host: &str,
    port: u16,
    secure: bool,
    request: &Outbound,
    identity: Option<ForwardIdentity>,
    connect_timeout: Duration,
    carrier: Option<&CarrierHook<'_>>,
) -> Result<Upstream, Error> {
    let carried = |c: Carrier<'_>| carrier.and_then(|carrier| carrier(c));
    let held = |until: Option<tokio::time::Instant>| async move {
        if let Some(until) = until {
            tokio::time::sleep_until(until).await;
        }
    };
    if secure {
        // `HttpClientInitializer.initChannel` builds the client's TLS context as the channel is registered: before
        // the target resolves or connects (a refused forward loads the CA too), and before the context's key and
        // chain are read
        tls_connecting();
        set_up(config, host.trim_start_matches('[').trim_end_matches(']'))?;
    }
    // `poolable` (and HTTP/2) only for a connection through no upstream proxy: a destination on `noProxyHosts` is one.
    let proxied = UpstreamProxies::for_destination(config, host.trim_start_matches('[').trim_end_matches(']')).any();
    if request.http2 && secure && !proxied {
        if !config.bool_property("forwardConnectionPoolEnabled", true) {
            return send_h2(config, host, port, request, identity, connect_timeout).await;
        }
        return send_h2_pooled(config, connections, host, port, request, identity, connect_timeout).await;
    }
    if proxied || !config.bool_property("forwardConnectionPoolEnabled", true) {
        held(carried(Carrier::New)).await;
        return send(config, host, port, secure, request, identity, connect_timeout).await;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let pool = ForwardPool::configured(config, connections);
    let key = ForwardPool::key_for(host, port, secure, identity.as_ref());
    if let Some((mut stream, channel, measured)) = pool.acquire_described(&key).await {
        // `reused.isActive()` at dispatch: a connection closed since it was handed out has carried nothing, so the
        // request goes on a new one whatever its method.
        if still_open(&mut stream) {
            held(carried(Carrier::Reused(&channel))).await;
            let read = Arc::new(std::sync::atomic::AtomicBool::new(false));
            match exchange(Watched { inner: stream, read: read.clone() }, request, limits(config, channel.clone())).await {
                Ok((mut upstream, reusable)) => {
                    if let Some(Reusable::Clean(watched)) = reusable {
                        let _ = pool.release_described(&key, watched.inner, channel, measured);
                    }
                    upstream.timing.reused = true;
                    return Ok(upstream);
                }
                // closed or reset before a response (`SocketConnectionException`, `Connection reset`, `Broken pipe`);
                // a read timeout, a TLS or decoding failure, or anything after the first byte goes to the caller
                Err(Error::Protocol | Error::Connect) if !read.load(std::sync::atomic::Ordering::SeqCst) && (request.method.is_empty() || crate::forward_breaker::is_idempotent(&request.method)) => {}
                // `closedWithoutAnswer` (upstream 48b7e14d2, 9.1.0): a request that is not sent again is
                // `PooledConnectionClosedException`, which the 502 names
                Err(error @ (Error::Protocol | Error::Connect)) if !read.load(std::sync::atomic::Ordering::SeqCst) => {
                    return Err(Error::PooledClosed { method: request.method.clone(), cause: Box::new(error) });
                }
                Err(error) => return Err(error),
            }
        }
    }
    if !secure {
        negotiated(config, host, false, false).await;
    }
    let hold = carried(Carrier::New);
    let stream = connect_forward(config, host, port, connect_timeout).await?;
    let channel = channel_description(&stream, host);
    carried(Carrier::Connected(&channel));
    held(hold).await;
    let connected = now_millis();
    // `http_client_open_connections` while the connection lives, active now
    let measured = if connections.unmeasured { None } else { crate::metrics::ForwardConnection::open(config, host, port) };
    let _ = stream.set_nodelay(true);
    let stream: Box<dyn crate::server::Io> = if secure {
        let name = ServerName::try_from(host.to_string()).map_err(|_| Error::Connect)?;
        let connector = tokio_rustls::TlsConnector::from(tls_config(Some(config), identity, host));
        let tls = handshake(config, &connector, name, stream).await?;
        negotiated(config, host, true, false).await;
        Box::new(tls)
    } else {
        Box::new(stream)
    };
    let (mut upstream, reusable) = exchange(stream, request, limits(config, channel.clone())).await?;
    upstream.timing.connection_established = connected;
    if let Some(stream) = reusable {
        let _ = pool.release_described(&key, stream.into_idle(), channel, measured);
    }
    Ok(upstream)
}

/// An HTTP/2 forward on a connection of its own (the forward connection pool is off): TLS offering `h2` then
/// `http/1.1`; the request goes out as HTTP/2 when the upstream picks `h2`, else as HTTP/1.1 on the same connection.
async fn send_h2(config: &Config, host: &str, port: u16, request: &Outbound, identity: Option<ForwardIdentity>, connect_timeout: Duration) -> Result<Upstream, Error> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let stream = connect_forward(config, host, port, connect_timeout).await?;
    let channel = channel_description(&stream, host);
    h2_over(config, host, port, stream, channel, request, identity).await.map(|(upstream, _)| upstream)
}

/// TLS offering `h2` then `http/1.1` over `stream` (direct, or a tunnel through an upstream proxy), then the request:
/// as HTTP/2 when the upstream picks `h2`, with the connection when it can carry another request; else as HTTP/1.1.
async fn h2_over(config: &Config, host: &str, port: u16, stream: TcpStream, channel: String, request: &Outbound, identity: Option<ForwardIdentity>) -> Result<(Upstream, Option<crate::h2::ClientConnection>), Error> {
    let _ = stream.set_nodelay(true);
    let name = ServerName::try_from(host.to_string()).map_err(|_| Error::Connect)?;
    let connector = tokio_rustls::TlsConnector::from(tls_config_alpn(Some(config), identity, true, jdk_sni(host)));
    let tls = handshake(config, &connector, name, stream).await?;
    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    negotiated(config, host, true, h2).await;
    if !h2 {
        return exchange(tls, request, limits(config, channel)).await.map(|(upstream, _)| (upstream, None));
    }
    let connection = crate::h2::ClientConnection::start(tls);
    let upstream = receive_h2(config, &connection, request, &h2_authority(request, host, port), channel).await.map_err(H2Failure::into_error)?;
    let reusable = reusable_after(&connection, &upstream);
    Ok((upstream, reusable.then_some(connection)))
}

fn h2_authority(request: &Outbound, host: &str, port: u16) -> String {
    request.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.clone()).unwrap_or_else(|| format!("{host}:{port}"))
}

/// `HttpClientHandler.tryReleaseHttp2ParentToPool`: a whole (not streamed) response in the HTTP range, on the
/// client's own stream, without `Connection: close` (`permitsKeepAlive`), leaves its connection fit for another.
fn reusable_after(connection: &crate::h2::ClientConnection, upstream: &Upstream) -> bool {
    let closes = upstream.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("connection")).is_some_and(|(_, v)| v.to_ascii_lowercase().contains("close"));
    upstream.stream.is_none() && (100..=599).contains(&upstream.status) && connection.reusable() && !closes
}

/// A pooled HTTP/2 forward (master's `HttpForwardConnectionPool` with HTTP/2 parents, keyed apart from HTTP/1.1): an
/// idle connection to the upstream carries the request on a new stream, and goes back to the pool once a whole
/// response has come back on it. A request that fails on a reused connection before any answer (the upstream closed
/// it or sent GOAWAY, what a stale connection looks like) is sent once more on a new connection when it is idempotent
/// (`isRetryableReusedConnectionFailure`), and whatever its method when nothing of it was sent.
async fn send_h2_pooled(config: &Config, connections: &ForwardConnections, host: &str, port: u16, request: &Outbound, identity: Option<ForwardIdentity>, connect_timeout: Duration) -> Result<Upstream, Error> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let key = format!("{}:h2", ForwardPool::key_for(host, port, true, identity.as_ref()));
    if let Some((connection, channel)) = connections.acquire_h2(&key) {
        match receive_h2(config, &connection, request, &h2_authority(request, host, port), channel.clone()).await {
            Ok(mut upstream) => {
                if reusable_after(&connection, &upstream) {
                    connections.release_h2(config, &key, connection, channel);
                }
                upstream.timing.reused = true;
                return Ok(upstream);
            }
            Err(H2Failure::NotSent) => {}
            Err(H2Failure::Closed) if request.method.is_empty() || crate::forward_breaker::is_idempotent(&request.method) => {}
            // `closedWithoutAnswer` (upstream 48b7e14d2, 9.1.0): not sent again, and named in the 502
            Err(H2Failure::Closed) => return Err(Error::PooledClosed { method: request.method.clone(), cause: Box::new(Error::Protocol) }),
            Err(failure) => return Err(failure.into_error()),
        }
    }
    let stream = connect_forward(config, host, port, connect_timeout).await?;
    let channel = channel_description(&stream, host);
    let connected = now_millis();
    let (mut upstream, connection) = h2_over(config, host, port, stream, channel.clone(), request, identity).await?;
    upstream.timing.connection_established = connected;
    if let Some(connection) = connection {
        connections.release_h2(config, &key, connection, channel);
    }
    Ok(upstream)
}

/// Why [`receive_h2`] has no response.
enum H2Failure {
    /// The connection had already ended: nothing was sent.
    NotSent,
    /// The connection ended, or the stream was reset, before a response.
    Closed,
    Failed(Error),
}

impl H2Failure {
    fn into_error(self) -> Error {
        match self {
            H2Failure::NotSent | H2Failure::Closed => Error::Protocol,
            H2Failure::Failed(error) => error,
        }
    }
}

impl From<Error> for H2Failure {
    fn from(error: Error) -> H2Failure {
        H2Failure::Failed(error)
    }
}

/// `Http2Error.PROTOCOL_ERROR`.
const PROTOCOL_ERROR_CODE: u32 = 0x1;

/// A header-limit refusal on `connection` (`ForwardHeaderLimit.Http2Stream` / `Http2Connection`): a block more than a
/// quarter over the limit is a connection error, which Netty answers with `GOAWAY(PROTOCOL_ERROR)` naming the limit
/// it applied; a list over the limit is a stream error, which resets the stream, and the forward then closes the
/// connection (`GOAWAY(NO_ERROR)`: the stream's child channel closes its parent).
fn refuse_h2(connection: &crate::h2::ClientConnection, refusal: Result<(), Error>, max: usize) -> Result<(), Error> {
    if let Err(Error::HeaderLimit(reason, _)) = &refusal {
        if reason.starts_with(HEADER_BLOCK) {
            connection.go_away(PROTOCOL_ERROR_CODE, &format!("Header size exceeded max allowed size ({})", max.saturating_add(max >> 2)));
        } else {
            connection.reset(PROTOCOL_ERROR_CODE);
            connection.go_away(0, "");
        }
    }
    refusal
}

/// One HTTP/2 exchange on `connection`: the response, with its trailers merged into the headers as
/// `FullHttpResponseToMockServerHttpResponse` does.
async fn receive_h2(config: &Config, connection: &crate::h2::ClientConnection, request: &Outbound, authority: &str, channel: String) -> Result<Upstream, H2Failure> {
    let response = tokio::time::timeout(read_timeout(config), connection.send(&request.method, authority, &request.target, &request.headers, request.body.clone()))
        .await
        .map_err(|_| Error::ReadTimeout)?
        .map_err(|failure| match failure {
            crate::h2::ClientFailure::NotSent => H2Failure::NotSent,
            crate::h2::ClientFailure::Closed => H2Failure::Closed,
            crate::h2::ClientFailure::Error(error) => H2Failure::Failed(Error::Http2Failure(error)),
        })?;
    let crate::h2::ClientResponse { status, mut headers, body, trailers, block_len, ended, stream } = response;
    // `SETTINGS_MAX_HEADER_LIST_SIZE` of `maxHeaderSize` (upstream a78886b4d, after 8.0.0): the header list as HPACK
    // sizes it, 32 octets over each name and value, `:status` included.
    let head_size = 32 + ":status".len() + 3 + list_size(&headers);
    refuse_h2(connection, h2_header_limit(block_len, head_size, "upstream response headers are", max_header(config)), max_header(config))?;
    // `HttpConversionUtil.addHttp2ToHttpHeaders`: the HTTP/1.1 response a stream's head becomes has no
    // `transfer-encoding` and no `trailer` header.
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case("transfer-encoding") && !k.eq_ignore_ascii_case("trailer"));
    // The stream's pipeline decodes content as HTTP/1.1's does (`Http2ForwardStreamChildInitializer`). A head ending
    // the stream is a whole response (`Http2StreamFrameToHttpObjectCodec`: a `FullHttpResponse`), never streamed.
    let streams = !ended && request.streams(&headers);
    let decoder = decoding::Decoder::for_head(&mut headers, !streams).map_err(Error::Decode)?;
    if streams {
        let end = Arc::new(StreamEnd { h2_stream: Some(stream), ..Default::default() });
        let body = trailer_bounded(body, trailers, max_header(config), end.clone());
        // The idle timeout runs on the stream's child channel: `AbstractHttp2StreamChannel.toString`, the parent's
        // description, the child's index on it (one child per request, the first on stream 3) and the stream id.
        let channel = format!("{channel}/{} (H2 - {stream})", (stream - 1) / 2);
        let mut body = idle_bounded(body, stream_idle(config), end.clone(), channel);
        let body = match decoder {
            None => body,
            Some(mut decoder) => {
                let (tx, rx) = tokio::sync::mpsc::channel(64);
                let failed = end.clone();
                let max_unwritten = max_body(config);
                tokio::spawn(async move {
                    while let Some(chunk) = body.recv().await {
                        // A content that cannot be decoded, or a read decoded past the bound of decoded bytes waiting
                        // for the client (`StreamingBody`, as over HTTP/1.1, [`decode_bounded`]), ends the stream with
                        // the error (`StreamingBody.error`): recorded truncated, the upstream stream dropped.
                        let Some(reads) = decode_bounded(&mut decoder, &chunk, max_unwritten) else { return failed.cut() };
                        for decoded in reads.into_iter().filter(|d| !d.is_empty()) {
                            if tx.send(Bytes::from(decoded)).await.is_err() {
                                return;
                            }
                        }
                    }
                });
                rx
            }
        };
        return Ok(Upstream { status, reason: String::new(), headers, body: Bytes::new(), stream: Some(body), stream_end: end, ..Default::default() });
    }
    let body = aggregate_h2(config, status, stream, &mut headers, body, decoder).await?;
    if let Ok(Ok((trailers, block_len))) = tokio::time::timeout(Duration::from_millis(100), trailers).await {
        // A trailer block is measured on its own, as a header block of the stream (`ForwardHeaderLimit.Http2Stream`).
        refuse_h2(connection, h2_header_limit(block_len, list_size(&trailers), TRAILERS, max_header(config)), max_header(config))?;
        headers.extend(trailers);
    }
    Ok(Upstream { status, reason: String::new(), headers, body, stream: None, ..Default::default() })
}

/// `HttpObjectAggregator` after the stream's `Http2StreamFrameToHttpObjectCodec` (which adds `x-http2-stream-id` to the
/// head) and content decoder, at `maxResponseBodySize` (8.0.0):
/// a `content-length` over the limit fails on the head alone, before any content; otherwise each DATA frame that
/// decodes to something is one component, and the first that would take the aggregate past the limit fails it with
/// what was aggregated before it. The decoded body gets its decoded `content-length`.
async fn aggregate_h2(
    config: &Config,
    status: u32,
    stream: u32,
    headers: &mut Vec<(String, String)>,
    mut body: tokio::sync::mpsc::Receiver<Bytes>,
    mut decoder: Option<decoding::Decoder>,
) -> Result<Bytes, Error> {
    let limit = max_body(config);
    let described = |headers: &[(String, String)], message: String| {
        let mut lines: Vec<String> = headers.iter().map(|(k, v)| format!("{k}: {v}")).collect();
        lines.push(format!("x-http2-stream-id: {stream}"));
        Error::TooLarge(format!(
            "shaded_package.io.netty.handler.codec.http.TooLongHttpContentException: Response entity too large: {message}\nHTTP/1.1 {status} {}\n{}",
            crate::status::reason_phrase(status),
            lines.join("\n")
        ))
    };
    let declared = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.trim().parse::<usize>().ok());
    if declared.is_some_and(|n| n > limit) {
        return Err(described(headers, "DefaultHttpResponse(decodeResult: success, version: HTTP/1.1)".into()));
    }
    let (mut aggregated, mut components) = (BytesMut::new(), 0);
    while let Some(chunk) = tokio::time::timeout(read_timeout(config), body.recv()).await.map_err(|_| Error::ReadTimeout)? {
        let contents = match decoder.as_mut() {
            None => vec![chunk.to_vec()],
            Some(decoder) => decoder.push_pieces(&chunk, limit.saturating_sub(aggregated.len())).map_err(Error::Decode)?,
        };
        for content in contents.into_iter().filter(|c| !c.is_empty()) {
            if aggregated.len() + content.len() > limit {
                let n = aggregated.len();
                return Err(described(headers, format!("HttpObjectAggregator$AggregatedFullHttpResponse(decodeResult: success, version: HTTP/1.1, content: CompositeByteBuf(ridx: 0, widx: {n}, cap: {n}, components={components}))")));
            }
            aggregated.extend_from_slice(&content);
            components += 1;
        }
    }
    if decoder.is_some() {
        decoding::Decoder::finish_headers(headers, aggregated.len());
    }
    Ok(aggregated.freeze())
}

/// A streamed HTTP/2 body whose trailer block, when one ends it, is measured as a header block of the stream
/// (`ForwardHeaderLimit.Http2Stream` / `Http2Connection`, upstream a78886b4d, after 8.0.0): over `maxHeaderSize` the stream ends aborted with the refusal,
/// which the forward logs. The trailers are not relayed either way, as on 8.0.0.
fn trailer_bounded(
    mut body: tokio::sync::mpsc::Receiver<Bytes>,
    mut trailers: tokio::sync::oneshot::Receiver<(Vec<(String, String)>, usize)>,
    max: usize,
    end: Arc<StreamEnd>,
) -> tokio::sync::mpsc::Receiver<Bytes> {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        while let Some(chunk) = body.recv().await {
            if tx.send(chunk).await.is_err() {
                return;
            }
        }
        // The client sends the trailers before it ends the body, so they are here when there are any.
        if let Ok((fields, block_len)) = trailers.try_recv() && let Err(Error::HeaderLimit(reason, _)) = h2_header_limit(block_len, list_size(&fields), TRAILERS, max) {
            let _ = end.header_limit.set(reason);
            end.cut();
        }
    });
    rx
}

/// HPACK's size of a header list: 32 octets over each name and value.
fn list_size(headers: &[(String, String)]) -> usize {
    headers.iter().map(|(k, v)| 32 + k.len() + v.len()).sum()
}

/// Netty's HTTP/2 limits on a header block with `SETTINGS_MAX_HEADER_LIST_SIZE` of `maxHeaderSize` (upstream
/// a78886b4d, after 8.0.0): an encoded block over the limit plus a quarter
/// (`Http2CodecUtil.calculateMaxHeaderListSizeGoAway`) is a connection error (`ForwardHeaderLimit.Http2Connection`);
/// a decoded list over the limit fails the stream, as `what`.
fn h2_header_limit(block_len: usize, list_size: usize, what: &str, max: usize) -> Result<(), Error> {
    if block_len > max.saturating_add(max >> 2) {
        return Err(header_limit(HEADER_BLOCK, max));
    }
    if list_size > max {
        return Err(header_limit(what, max));
    }
    Ok(())
}

/// `StreamIdleTimeoutHandler` on an HTTP/2 stream: `idle` without a frame closes it, the stream ending cut.
fn idle_bounded(mut body: tokio::sync::mpsc::Receiver<Bytes>, idle: Option<Duration>, end: Arc<StreamEnd>, channel: String) -> tokio::sync::mpsc::Receiver<Bytes> {
    let Some(idle) = idle else { return body };
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        loop {
            match tokio::time::timeout(idle, body.recv()).await {
                Ok(Some(chunk)) => {
                    if tx.send(chunk).await.is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(_) => {
                    let _ = end.idle.set(channel);
                    end.cut();
                    return;
                }
            }
        }
    });
    rx
}

type IdleConnection = Box<dyn crate::server::Io>;

/// An idle connection's slot in the pool: the way to take its stream back from the task that watches it.
struct IdleSlot {
    id: u64,
    take: tokio::sync::oneshot::Sender<tokio::sync::oneshot::Sender<Pooled>>,
}

/// An idle connection as the pool hands it out: the stream, its `Channel.toString`, and its place in
/// `http_client_open_connections` (dropped with the stream wherever that ends).
type Pooled = (IdleConnection, String, Option<crate::metrics::ForwardConnection>);

type IdleMap = Arc<Mutex<HashMap<String, std::collections::VecDeque<IdleSlot>>>>;

/// `HttpForwardConnectionPool`: the keyed pool of idle HTTP/1.1 keep-alive upstream connections. Connections are keyed
/// `host:port:secure` (plus the client certificate offered, so one is never reused for another identity). A released
/// connection waits at the tail of its key's deque and [`acquire`](Self::acquire) polls the head, as upstream's
/// `addLast`/`pollFirst` do (oldest first). Each idle connection is watched by a task of its own, the counterpart of
/// Netty's close listener and its `idleTimeoutMillis` eviction on the channel's event loop: the server closing (or
/// writing to) an idle connection removes it, and so does the idle timeout, which also closes it; taking it back
/// cancels both. The pool performs no other I/O.
#[derive(Clone)]
struct ForwardPool {
    idle: IdleMap,
    /// Set once the owning server has stopped: nothing is pooled any more.
    closed: Arc<std::sync::atomic::AtomicBool>,
    max_idle_per_key: usize,
    idle_timeout: Duration,
    keep_alive: bool,
    max_total_per_key: usize,
}

/// One server's forward connections: upstream's `HttpForwardConnectionPool` belongs to the `NettyHttpClient` of each
/// MockServer's `HttpActionHandler`, its channels on that server's event loop group. Two servers in one process never
/// reuse each other's connections, and a stopped server's idle ones are closed with it ([`close`](Self::close)).
#[derive(Default)]
pub struct ForwardConnections {
    idle: IdleMap,
    closed: Arc<std::sync::atomic::AtomicBool>,
    /// The forward actions' per-upstream circuit breakers (`ForwardCircuitBreaker`).
    pub breaker: crate::forward_breaker::Breaker,
    /// `NettyHttpClient.unreachableProxiesReported`: the upstream proxies (`host:port`) whose failure to be reached
    /// was logged, each once for the server's lifetime (a reset keeps them).
    unreachable_proxies_reported: parking_lot::Mutex<std::collections::HashSet<String>>,
    /// Idle HTTP/2 connections by pool key, oldest first.
    h2_idle: Arc<Mutex<HashMap<String, std::collections::VecDeque<IdleH2>>>>,
    /// Not the forwarding client's pool: its connections are not in `http_client_open_connections`.
    unmeasured: bool,
}

/// An idle pooled HTTP/2 connection, with its `Channel.toString`.
struct IdleH2 {
    id: u64,
    connection: crate::h2::ClientConnection,
    channel: String,
}

impl ForwardConnections {
    /// The connections of a server started with `config`. As `ProxyConfiguration.proxyConfiguration` builds each
    /// configured upstream proxy's `new InetSocketAddress(host, port)` when the server starts, its name is looked up
    /// then: one that does not resolve is in the JDK's negative cache, so a forward through it soon after fails with
    /// `UnknownHostException(host)` alone, without the resolver's reason.
    pub fn for_config(config: &Config) -> ForwardConnections {
        let proxies = UpstreamProxies::from(config);
        for proxy in [&proxies.http, &proxies.https, &proxies.socks].into_iter().flatten() {
            let _ = crate::inet_address::lookup_blocking(&proxy.host, proxy.port);
        }
        ForwardConnections::default()
    }

    /// The pool of a client of the server's own (a runtime LLM client's `NettyHttpClient` and its
    /// `HttpForwardConnectionPool`), apart from the forwarding client's and unmeasured.
    pub fn unmeasured() -> ForwardConnections {
        ForwardConnections { unmeasured: true, ..Default::default() }
    }

    /// Whether `proxy` (`host:port`) is reported unreachable for the first time: `unreachableProxiesReported.add`.
    pub fn first_unreachable_report(&self, proxy: &str) -> bool {
        self.unreachable_proxies_reported.lock().insert(proxy.to_string())
    }

    /// The event loop group's shutdown: every idle connection is closed (dropping its slot ends the task that holds
    /// it), and a connection released by a forward still in flight is closed instead of pooled.
    pub fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        let slots = std::mem::take(&mut *self.idle.lock());
        drop(slots);
        let h2 = std::mem::take(&mut *self.h2_idle.lock());
        drop(h2);
    }

    /// The oldest idle HTTP/2 connection for `key` that is still open; closed ones are dropped.
    fn acquire_h2(&self, key: &str) -> Option<(crate::h2::ClientConnection, String)> {
        let mut idle = self.h2_idle.lock();
        let queue = idle.get_mut(key)?;
        while let Some(slot) = queue.pop_front() {
            if slot.connection.reusable() {
                return Some((slot.connection, slot.channel));
            }
        }
        None
    }

    /// `HttpForwardConnectionPool.release` of an HTTP/2 parent: kept idle for the next request to `key` up to
    /// `forwardConnectionPoolMaxIdlePerKey` (raised to `...MaxTotalPerKey` by keep-warm retention), and closed after
    /// `forwardConnectionPoolIdleTimeoutMillis` unused; closed at once when the pool is full or the server stopped.
    fn release_h2(&self, config: &Config, key: &str, connection: crate::h2::ClientConnection, channel: String) {
        let pool = ForwardPool::configured(config, self);
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let id = NEXT_SLOT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        {
            let mut idle = self.h2_idle.lock();
            let queue = idle.entry(key.to_string()).or_default();
            queue.retain(|slot| slot.connection.is_open());
            if queue.len() >= pool.ceiling() {
                return;
            }
            queue.push_back(IdleH2 { id, connection, channel });
        }
        if pool.idle_timeout > Duration::ZERO {
            let (idle, key, timeout) = (Arc::downgrade(&self.h2_idle), key.to_string(), pool.idle_timeout);
            tokio::spawn(async move {
                tokio::time::sleep(timeout).await;
                let Some(idle) = idle.upgrade() else { return };
                let evicted = {
                    let mut idle = idle.lock();
                    let queue = idle.get_mut(&key);
                    queue.and_then(|q| q.iter().position(|slot| slot.id == id).and_then(|at| q.remove(at)))
                };
                drop(evicted);
            });
        }
    }
}

static NEXT_SLOT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl ForwardPool {
    /// A pool of its own (`new HttpForwardConnectionPool(maxIdlePerKey, idleTimeoutMillis, keepAlive, maxTotalPerKey)`).
    fn new(max_idle_per_key: usize, idle_timeout: Duration, keep_alive: bool, max_total_per_key: usize) -> ForwardPool {
        let max_idle_per_key = max_idle_per_key.max(1);
        ForwardPool { idle: Default::default(), closed: Default::default(), max_idle_per_key, idle_timeout, keep_alive, max_total_per_key: max_total_per_key.max(max_idle_per_key) }
    }

    /// The server's `connections`, sized by `forwardConnectionPoolMaxIdlePerKey`, `...IdleTimeoutMillis`,
    /// `...KeepAlive` and `...MaxTotalPerKey`.
    fn configured(config: &Config, connections: &ForwardConnections) -> ForwardPool {
        let mut pool = ForwardPool::new(
            usize::try_from(config.int_property("forwardConnectionPoolMaxIdlePerKey", 8)).unwrap_or(0),
            Duration::from_millis(config.int_property("forwardConnectionPoolIdleTimeoutMillis", 30_000).max(0) as u64),
            config.bool_property("forwardConnectionPoolKeepAlive", false),
            usize::try_from(config.int_property("forwardConnectionPoolMaxTotalPerKey", 2000)).unwrap_or(0),
        );
        pool.idle = connections.idle.clone();
        pool.closed = connections.closed.clone();
        pool
    }

    /// `keyFor(address, secure)`, with the client certificate (when one is offered) appended.
    fn key_for(host: &str, port: u16, secure: bool, identity: Option<&ForwardIdentity>) -> String {
        let mut key = format!("{}:{port}:{secure}", host.to_ascii_lowercase());
        if let Some(cert) = identity.and_then(|i| i.key.end_entity_cert().ok()) {
            key.push(':');
            key.extend(cert.iter().map(|b| format!("{b:02x}")));
        }
        key
    }

    /// The per-key ceiling on idle connections: `maxIdlePerKey`, raised to `maxTotalPerKey` by keep-warm retention.
    fn ceiling(&self) -> usize {
        if self.keep_alive { self.max_total_per_key } else { self.max_idle_per_key }
    }

    /// The oldest idle connection for `key` that is still open, or `None`. Stale ones are dropped.
    #[cfg(test)]
    async fn acquire(&self, key: &str) -> Option<IdleConnection> {
        self.acquire_described(key).await.map(|(stream, _, _)| stream)
    }

    /// [`acquire`](Self::acquire), with the connection's `Channel.toString` as it was released.
    async fn acquire_described(&self, key: &str) -> Option<Pooled> {
        loop {
            let slot = {
                let mut idle = self.idle.lock();
                let deque = idle.get_mut(key)?;
                let slot = deque.pop_front();
                if deque.is_empty() {
                    idle.remove(key);
                }
                slot?
            };
            let (reply, stream) = tokio::sync::oneshot::channel();
            if slot.take.send(reply).is_err() {
                continue; // its watcher has just seen it close
            }
            if let Ok((stream, channel, mut measured)) = stream.await {
                if let Some(measured) = measured.as_mut() {
                    measured.idle(false);
                }
                return Some((stream, channel, measured));
            }
        }
    }

    /// Offers an idle, reusable connection back. Rejected (handed back for the caller to close) when it has already
    /// been closed by the server or the key is at its ceiling.
    #[cfg(test)]
    fn release(&self, key: &str, stream: IdleConnection) -> Result<(), IdleConnection> {
        self.release_described(key, stream, String::new(), None)
    }

    /// [`release`](Self::release), keeping the connection's `Channel.toString` for its next taker.
    /// A refused connection's `measured` is dropped here: the caller closes it.
    fn release_described(&self, key: &str, mut stream: IdleConnection, channel: String, mut measured: Option<crate::metrics::ForwardConnection>) -> Result<(), IdleConnection> {
        if !still_open(&mut stream) {
            return Err(stream);
        }
        let id = NEXT_SLOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (take, taken) = tokio::sync::oneshot::channel();
        {
            let mut idle = self.idle.lock();
            if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(stream);
            }
            let deque = idle.entry(key.to_string()).or_default();
            if deque.len() >= self.ceiling() {
                return Err(stream);
            }
            deque.push_back(IdleSlot { id, take });
        }
        if let Some(measured) = measured.as_mut() {
            measured.idle(true);
        }
        let (idle, key, timeout) = (self.idle.clone(), key.to_string(), self.idle_timeout);
        let deadline = tokio::time::Instant::now() + timeout;
        tokio::spawn(async move {
            let mut taken = taken;
            let mut probe = [0u8; 1];
            let evict = async {
                if timeout.is_zero() {
                    std::future::pending::<()>().await
                } else {
                    tokio::time::sleep_until(deadline).await
                }
            };
            // Closed by the server (or talking out of turn) while idle, or idle for too long: out of the pool.
            // A taker that already holds the slot still gets the connection.
            let gone = tokio::select! {
                taker = &mut taken => {
                    if let Ok(reply) = taker {
                        let _ = reply.send((stream, channel, measured));
                    }
                    return;
                }
                _ = evict => true,
                _ = stream.read(&mut probe) => false,
            };
            let removed = remove_idle(&idle, &key, id);
            if gone && !removed && let Ok(reply) = taken.await {
                let _ = reply.send((stream, channel, measured));
            }
        });
        Ok(())
    }
}

/// `channel.isActive()` for an idle connection: the server has neither closed it nor sent anything unasked.
fn still_open(stream: &mut IdleConnection) -> bool {
    use std::future::Future;
    let mut probe = [0u8; 1];
    let mut read = std::pin::pin!(stream.read(&mut probe));
    read.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop())).is_pending()
}

fn remove_idle(idle: &IdleMap, key: &str, id: u64) -> bool {
    let mut idle = idle.lock();
    let Some(deque) = idle.get_mut(key) else { return false };
    let before = deque.len();
    deque.retain(|slot| slot.id != id);
    let removed = deque.len() != before;
    if deque.is_empty() {
        idle.remove(key);
    }
    removed
}

/// A configured upstream proxy (`ProxyConfiguration`) with `forwardProxyAuthenticationUsername`/`Password`.
struct Proxy {
    host: String,
    port: u16,
    credentials: Option<(String, String)>,
    /// The property that set it (`NettyHttpClient.propertyFor`).
    property: &'static str,
}

impl Proxy {
    /// `NettyHttpClient.hostAndPort`: the address as configured, without the `/<unresolved>` Java adds.
    fn host_and_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    fn authorization(&self) -> Option<String> {
        use base64::Engine;
        self.credentials
            .as_ref()
            .map(|(u, p)| format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))))
    }
}

/// `ProxyConfiguration.proxyConfiguration(configuration)`: HTTP and HTTPS proxies, or a SOCKS5 proxy.
struct UpstreamProxies {
    http: Option<Proxy>,
    https: Option<Proxy>,
    socks: Option<Proxy>,
}

/// `ProxyConfiguration.proxyConfiguration`'s refusal of an HTTP or HTTPS proxy together with a SOCKS proxy, as the server
/// started with them. `Main` answers it with the usage text and exit code 0; an embedder's `Server::start` returns it.
pub const PROXY_CONFLICT: &str = "Invalid proxy configuration it is not possible to configure HTTP or HTTPS proxy at the same time as a SOCKS proxy, please choose either HTTP(S) proxy OR a SOCKS proxy";

pub fn proxy_conflict(config: &Config) -> bool {
    let set = |name: &str| config.startup_property(name).is_some_and(|v| !v.trim().is_empty());
    (set("forwardHttpProxy") || set("forwardHttpsProxy")) && set("forwardSocksProxy")
}

impl UpstreamProxies {
    /// The list upstream builds once when the server starts (`proxyConfiguration(configuration)` in the `MockServer`
    /// constructor): a later `PUT /mockserver/configuration` of these properties does not reroute forwards.
    fn from(config: &Config) -> UpstreamProxies {
        let non_blank = |name: &str| config.startup_property(name).filter(|v| !v.trim().is_empty());
        let credentials = non_blank("forwardProxyAuthenticationUsername").zip(non_blank("forwardProxyAuthenticationPassword"));
        let proxy = |name: &'static str| {
            let address = non_blank(name)?;
            let (host, port) = address.trim().rsplit_once(':')?;
            Some(Proxy {
                host: host.trim_start_matches('[').trim_end_matches(']').to_string(),
                port: port.parse().ok()?,
                credentials: credentials.clone(),
                property: name,
            })
        };
        let (http, https) = (proxy("forwardHttpProxy"), proxy("forwardHttpsProxy"));
        // A SOCKS proxy is refused alongside an HTTP(S) one.
        let socks = if http.is_none() && https.is_none() { proxy("forwardSocksProxy") } else { None };
        UpstreamProxies { http, https, socks }
    }

    /// `NettyHttpClient.upstreamProxiesFor(destinationHost)`: [`UpstreamProxies::from`], or none at all for a host on
    /// `noProxyHosts`.
    fn for_destination(config: &Config, host: &str) -> UpstreamProxies {
        let proxies = UpstreamProxies::from(config);
        match proxies.any() && on_no_proxy_list(config, host) {
            true => UpstreamProxies { http: None, https: None, socks: None },
            false => proxies,
        }
    }

    fn any(&self) -> bool {
        self.http.is_some() || self.https.is_some() || self.socks.is_some()
    }
}

/// `connect_forward` to an upstream proxy, as `NettyHttpClient.proxyFailure` reports a failure: one to resolve, or to
/// connect to, the proxy (a `SocketException`, `UnknownHostException` or `UnresolvedAddressException`) is told to the
/// [`OnTls`] hook as [`ClientEvent::ProxyUnreachable`] before the forward fails with it. `tunnel`: a
/// `forwardHttpsProxy`/`forwardSocksProxy` connection, whose unresolved proxy name is `UnresolvedAddressException`.
async fn connect_proxy(config: &Config, proxy: &Proxy, tunnel: bool, timeout: Duration) -> Result<TcpStream, Error> {
    let error = match connect_forward(config, &proxy.host, proxy.port, timeout).await {
        Ok(stream) => return Ok(stream),
        Err(Error::Resolve { .. }) if tunnel => Error::UnresolvedAddress,
        Err(error) => error,
    };
    // Netty's `ConnectTimeoutException` is a `ConnectException`, so a proxy that does not answer counts too.
    if matches!(error, Error::Refused(_) | Error::Resolve { .. } | Error::UnresolvedAddress | Error::ConnectTimeout(_) | Error::Connect) {
        client_event(&ClientEvent::ProxyUnreachable { proxy: &proxy.host_and_port(), property: proxy.property, cause: &error });
    }
    Err(error)
}

/// `NettyHttpClient.connectBinaryRelay`: the upstream connection of a binary relay (`src/binary.rs`), connected
/// directly, or tunnelled through `binaryRelayTunnel`'s proxy (`tunnelProxy`, else `forwardHttpsProxy`, else
/// `forwardHttpProxy`: both HTTP proxies are asked to open a `CONNECT` tunnel, which carries any bytes) by
/// `connectThroughTunnel`: the destination is sent to the proxy by name, a proxy that cannot be reached is
/// `proxyFailure(tunnel, …)` ([`ClientEvent::ProxyUnreachable`]), and a `CONNECT` the proxy answers with another
/// status than 200 is `tunnelRefused` ([`Error::TunnelRefused`]).
pub(crate) async fn connect_binary_relay(config: &Config, host: &str, port: u16, secure: bool, timeout: Duration) -> Result<TcpStream, Error> {
    let proxies = UpstreamProxies::for_destination(config, host);
    let tunnel = match (&proxies.https, &proxies.socks) {
        (Some(https), _) if secure => Some(https),
        (_, Some(socks)) => Some(socks),
        (https, None) => https.as_ref().or(proxies.http.as_ref()),
    };
    let Some(proxy) = tunnel else {
        return connect_forward(config, host, port, timeout).await;
    };
    if proxy.property == "forwardSocksProxy" {
        return connect_through_tunnel(config, proxy, host, port, timeout).await;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let mut stream = connect_proxy(config, proxy, true, timeout).await?;
    match http_connect(&mut stream, proxy, host, port, max_header(config)).await {
        Err(Error::ConnectStatus(status)) => {
            // `tunnelRefused`: the destination as `hostAndPort` prints the unresolved address it was given
            let destination = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
            let hint = match (status.starts_with("407 "), proxy.credentials.is_some()) {
                (false, _) => "",
                (true, true) => ", check forwardProxyAuthenticationUsername and forwardProxyAuthenticationPassword",
                (true, false) => ", it asks for credentials: set forwardProxyAuthenticationUsername and forwardProxyAuthenticationPassword",
            };
            Err(Error::TunnelRefused(format!("upstream proxy {} set by {} refused to open a CONNECT tunnel to {destination} with status {status}{hint}", proxy.host_and_port(), proxy.property)))
        }
        Err(e) => Err(e),
        Ok(()) => Ok(stream),
    }
}

/// A tunnel to `host` through `proxy`: `CONNECT` for `forwardHttpsProxy`, SOCKS5 for `forwardSocksProxy`.
async fn connect_through_tunnel(config: &Config, proxy: &Proxy, host: &str, port: u16, timeout: Duration) -> Result<TcpStream, Error> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let mut stream = connect_proxy(config, proxy, true, timeout).await?;
    match proxy.property {
        "forwardHttpsProxy" => http_connect(&mut stream, proxy, host, port, max_header(config)).await.map_err(Error::status_unnamed)?,
        _ => socks5_connect(&mut stream, proxy, host, port).await?,
    }
    Ok(stream)
}

/// `NoProxyHostsUtils.isHostOnNoProxyList` over the `noProxyHosts` property, as curl and the JVM match `no_proxy`: a
/// host name, exactly, case-insensitively; a domain suffix (`*.example.com` or `.example.com`), which also covers the
/// domain itself; or an IP address, which matches only a host given as that address (compared as addresses, so `::1`
/// matches `0:0:0:0:0:0:0:1`). No name is looked up. Read by the proxying of unmatched requests
/// (`potentiallyHttpProxy`, by `Host` header value), and by `NettyHttpClient.upstreamProxiesFor`: a listed destination
/// bypasses `forwardHttpProxy`, `forwardHttpsProxy` and `forwardSocksProxy` alike.
pub(crate) fn on_no_proxy_list(config: &Config, host: &str) -> bool {
    host_on_no_proxy_list(host, &config.property("noProxyHosts").unwrap_or_default())
}

fn host_on_no_proxy_list(host: &str, no_proxy_hosts: &str) -> bool {
    if no_proxy_hosts.trim().is_empty() || host.trim().is_empty() {
        return false;
    }
    let host_only = no_proxy_host(host);
    let host = host_only.to_lowercase();
    let address = ip_address_bytes(host_only);
    no_proxy_hosts.split(',').map(str::trim).filter(|p| !p.is_empty()).any(|pattern| {
        let pattern_lower = pattern.to_lowercase();
        if pattern_lower.starts_with("*.") || pattern_lower.starts_with('.') {
            let domain = &pattern_lower[pattern_lower.find('.').map_or(0, |dot| dot + 1)..];
            return host.ends_with(&format!(".{domain}")) || host == domain;
        }
        match &address {
            Some(address) => ip_address_bytes(pattern).as_ref() == Some(address),
            None => host == pattern_lower,
        }
    })
}

/// `NetUtil.createByteArrayFromIpAddressString`: the bytes of an IPv4 or IPv6 literal (brackets and an IPv6 scope id
/// allowed), an IPv4-mapped IPv6 one as its IPv4 bytes; `None` for anything else.
fn ip_address_bytes(value: &str) -> Option<Vec<u8>> {
    if let Ok(v4) = value.parse::<std::net::Ipv4Addr>() {
        return Some(v4.octets().to_vec());
    }
    let value = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')).unwrap_or(value);
    let value = value.split_once('%').map_or(value, |(address, _scope)| address);
    let v6 = value.parse::<std::net::Ipv6Addr>().ok()?;
    Some(match v6.to_ipv4_mapped() {
        Some(v4) => v4.octets().to_vec(),
        None => v6.octets().to_vec(),
    })
}

/// `NoProxyHostsUtils.extractHost`: a `Host` header value without its port; the brackets of an IPv6 literal are dropped, and
/// an unbracketed value with more than one colon is an IPv6 literal as it stands.
fn no_proxy_host(value: &str) -> &str {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        return rest.find(']').map_or(rest, |close| &rest[..close]);
    }
    if value.matches(':').count() > 1 {
        return value;
    }
    match value.rfind(':') {
        Some(colon) if colon > 0 && value[colon + 1..].parse::<i32>().is_ok() => &value[..colon],
        _ => value,
    }
}

/// Resolves `host` and connects to its addresses (IPv4 first), each attempt bounded by `timeout`. The failure is
/// the first address's, named as Java prints an `InetSocketAddress` (`host/ip:port`, no host for a literal address).
/// [`connect_timed`] for a forward (also the binary proxy's, `src/binary.rs`): the socket gets `forwardSocketKeepAlive`
/// (`NettyHttpClient.applyForwardSocketKeepAlive`).
pub(crate) async fn connect_forward(config: &Config, host: &str, port: u16, timeout: Duration) -> Result<TcpStream, Error> {
    let stream = connect_timed(host, port, timeout).await?;
    apply_forward_keep_alive(config, &stream);
    Ok(stream)
}

/// `applyForwardSocketKeepAlive` with `config`'s `forwardSocketKeepAlive*` properties; shared by the HTTP forwarding
/// client and the binary-proxy forward sockets (`src/binary.rs`).
pub(crate) fn apply_forward_keep_alive(config: &Config, stream: &TcpStream) {
    apply_socket_keep_alive(
        stream,
        config.bool_property("forwardSocketKeepAlive", true),
        config.int_property("forwardSocketKeepAliveIdleSeconds", 60),
        config.int_property("forwardSocketKeepAliveIntervalSeconds", 15),
        config.int_property("forwardSocketKeepAliveCount", 4),
    );
}

/// `applyForwardSocketKeepAlive`: when `enabled`, `SO_KEEPALIVE` with the idle time, probe interval and probe count
/// (each clamped to at least 1, as upstream does for the native transport the oracle runs on). Nothing is set when
/// disabled, so the OS default (no keep-alive) applies.
fn apply_socket_keep_alive(stream: &TcpStream, enabled: bool, idle_seconds: i64, interval_seconds: i64, count: i64) {
    if !enabled {
        return;
    }
    let seconds = |v: i64| Duration::from_secs(v.max(1) as u64);
    let keep_alive = socket2::TcpKeepalive::new().with_time(seconds(idle_seconds)).with_interval(seconds(interval_seconds)).with_retries(count.clamp(1, i64::from(u32::MAX)) as u32);
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&keep_alive);
}

/// The addresses of `host`, IPv4 first; a name that does not resolve is `UnknownHostException`.
async fn resolve(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, Error> {
    let mut addresses: Vec<std::net::SocketAddr> = match crate::inet_address::lookup(host, port).await {
        Ok(addresses) => addresses,
        // The JDK's negative cache answered: `UnknownHostException(host)`, no reason.
        Err(e) if crate::inet_address::is_cached_lookup_failure(&e) => {
            return Err(Error::Resolve { host: host.to_string(), port, reason: String::new() });
        }
        Err(e) => {
            // The resolver's reason (`gai_strerror`), as `UnknownHostException` carries it after the host.
            let reason = e.to_string();
            let reason = reason.strip_prefix("failed to lookup address information: ").unwrap_or(&reason).to_string();
            return Err(Error::Resolve { host: host.to_string(), port, reason });
        }
    };
    addresses.sort_by_key(|a| a.is_ipv6());
    Ok(addresses)
}

/// Connects to the first address of `host` that accepts, IPv4 addresses first, as the JVM orders them by default
/// (`java.net.preferIPv6Addresses=false`): `localhost` is `127.0.0.1` before `::1`.
/// Tries each address, IPv4 first; the error comes with the first address, the one Netty's client would have used.
pub(crate) async fn connect_timed(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, Error> {
    connect_timed_named(host, port, timeout, false).await
}

/// [`connect_timed`]; `named` connects as to the address `InetAddressValidator.validateForwardTarget` returns for an
/// unresolved target it looked up (`InetAddress.getByAddress(host, …)`), which carries the host as given, an address
/// literal too, so a failure names it (`127.0.0.1/127.0.0.1:port`).
pub(crate) async fn connect_timed_named(host: &str, port: u16, timeout: Duration, named: bool) -> Result<TcpStream, Error> {
    let addresses = resolve(host, port).await?;
    let named = if !named && host.parse::<std::net::IpAddr>().is_ok() { String::new() } else { host.to_string() };
    let mut first: Option<Error> = None;
    for address in addresses {
        let failure = match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                Error::Refused(format!("{named}/{}:{port}", crate::server::java_host_address(address.ip())))
            }
            // `UpstreamConnectFailure` names these (upstream 48b7e14d2, 9.1.0); the messages follow Netty's epoll
            // `newConnectException0` with the address its annotated exceptions append (not checked against the oracle,
            // which no scenario can make reach them)
            Ok(Err(e)) if matches!(e.kind(), std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::NetworkUnreachable) => {
                let (errno, text) = if e.kind() == std::io::ErrorKind::HostUnreachable { (113, "No route to host") } else { (101, "Network is unreachable") };
                Error::Unreachable(format!("finishConnect(..) failed with error(-{errno}): {text}: {named}/{}:{port}", crate::server::java_host_address(address.ip())))
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::AddrNotAvailable || matches!(e.raw_os_error(), Some(23 | 24)) => {
                let text = if e.kind() == std::io::ErrorKind::AddrNotAvailable { "Cannot assign requested address" } else { "Too many open files" };
                Error::OutOfLocal(format!("connect(..) failed: {text}"))
            }
            Ok(Err(_)) => Error::Connect,
            Err(_) => Error::ConnectTimeout(format!(
                "connection timed out after {} ms: {named}/{}:{port}",
                timeout.as_millis(),
                crate::server::java_host_address(address.ip())
            )),
        };
        first.get_or_insert(failure);
    }
    Err(first.unwrap_or(Error::Connect))
}

/// Netty's `HttpProxyHandler`: `CONNECT host:port`, answered `200` before the tunnel is used. Its headers are read up
/// to `maxHeaderSize` (`HttpConnectProxyHandler`, upstream a78886b4d, after 8.0.0), with no other limit.
async fn http_connect(stream: &mut TcpStream, proxy: &Proxy, host: &str, port: u16, max_header: usize) -> Result<(), Error> {
    let authority = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let mut head = format!("CONNECT {authority} HTTP/1.1\r\nhost: {authority}\r\n");
    if let Some(authorization) = proxy.authorization() {
        head.push_str(&format!("proxy-authorization: {authorization}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.map_err(|_| Error::Connect)?;
    let mut buf = BytesMut::new();
    let mut capacity = 64;
    loop {
        let mut headers = vec![httparse::EMPTY_HEADER; capacity];
        let mut response = httparse::Response::new(&mut headers);
        let parsed = response.parse(&buf);
        // `ForwardHeaderLimit.responseOverLimit` with the CONNECT reply's name, thrown from `handleResponse`, so that
        // `ProxyHandler.setConnectFailure` wraps it: `protocol, authScheme, proxyAddress => destinationAddress, cause`.
        let complete = match parsed {
            Ok(httparse::Status::Complete(len)) => Some(len),
            _ => None,
        };
        let counted = header_bytes(&buf[..complete.unwrap_or(buf.len())]);
        if counted > max_header {
            let Error::HeaderLimit(reason, _) = header_limit(CONNECT_HEADERS, max_header) else { unreachable!() };
            let proxy_address = match (stream.peer_addr(), proxy.host.parse::<std::net::IpAddr>()) {
                (Ok(address), Ok(_)) => format!("/{}:{}", crate::server::java_host_address(address.ip()), address.port()),
                (Ok(address), Err(_)) => format!("{}/{}:{}", proxy.host, crate::server::java_host_address(address.ip()), address.port()),
                (Err(_), _) => format!("{}/<unresolved>:{}", proxy.host, proxy.port),
            };
            let scheme = if proxy.credentials.is_some() { "basic" } else { "none" };
            let connect = format!("http, {scheme}, {proxy_address} => {host}/<unresolved>:{port}, org.mockserver.httpclient.HeaderLimitExceededException: {reason}");
            return Err(Error::HeaderLimit(reason, Some(connect)));
        }
        match parsed {
            Err(httparse::Error::TooManyHeaders) => {
                capacity *= 4;
                continue;
            }
            Ok(httparse::Status::Complete(len)) => {
                if response.code != Some(200) {
                    // `HttpConnectProxyHandler.refusedWith`: the status as Netty's `HttpResponseStatus` prints it
                    return Err(Error::ConnectStatus(format!("{} {}", response.code.unwrap_or(0), response.reason.unwrap_or(""))));
                }
                let length = response
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h| std::str::from_utf8(h.value).ok()?.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                // The tunnel starts after the response (and any body it announced).
                while buf.len() < len + length {
                    if tokio::time::timeout(CONNECT_TIMEOUT, stream.read_buf(&mut buf)).await.ok().and_then(Result::ok).unwrap_or(0) == 0 {
                        return Err(Error::Connect);
                    }
                }
                return if buf.len() == len + length { Ok(()) } else { Err(Error::Protocol) };
            }
            Ok(httparse::Status::Partial) => {
                if tokio::time::timeout(CONNECT_TIMEOUT, stream.read_buf(&mut buf)).await.ok().and_then(Result::ok).unwrap_or(0) == 0 {
                    return Err(Error::Connect);
                }
            }
            Err(_) => return Err(Error::Connect),
        }
    }
}

/// Netty's `Socks5ProxyHandler`: NO_AUTH (and PASSWORD with credentials) offered, then CONNECT to an IPv4, IPv6
/// or domain destination.
async fn socks5_connect(stream: &mut TcpStream, proxy: &Proxy, host: &str, port: u16) -> Result<(), Error> {
    async fn read_exact(stream: &mut TcpStream, n: usize) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; n];
        match tokio::time::timeout(CONNECT_TIMEOUT, stream.read_exact(&mut out)).await {
            Ok(Ok(_)) => Ok(out),
            _ => Err(Error::Connect),
        }
    }
    let greeting: &[u8] = if proxy.credentials.is_some() { &[5, 2, 0, 2] } else { &[5, 1, 0] };
    stream.write_all(greeting).await.map_err(|_| Error::Connect)?;
    match read_exact(stream, 2).await?.as_slice() {
        [5, 0] => {}
        [5, 2] => {
            let (username, password) = proxy.credentials.clone().ok_or(Error::Connect)?;
            let mut auth = vec![1, username.len() as u8];
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            stream.write_all(&auth).await.map_err(|_| Error::Connect)?;
            if read_exact(stream, 2).await?[1] != 0 {
                return Err(Error::Connect);
            }
        }
        _ => return Err(Error::Connect),
    }
    let mut command = vec![5, 1, 0];
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            command.push(1);
            command.extend_from_slice(&v4.octets());
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            command.push(4);
            command.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            command.push(3);
            command.push(host.len() as u8);
            command.extend_from_slice(host.as_bytes());
        }
    }
    command.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&command).await.map_err(|_| Error::Connect)?;
    let reply = read_exact(stream, 5).await?;
    if reply[1] != 0 {
        return Err(Error::Connect);
    }
    // The bound address that follows (its first byte is already read).
    let rest = match reply[3] {
        1 => 4 - 1 + 2,
        3 => reply[4] as usize + 2,
        4 => 16 - 1 + 2,
        _ => return Err(Error::Protocol),
    };
    read_exact(stream, rest).await.map(|_| ())
}

/// `HttpClientInitializer.initChannel` for a secure connection (upstream 7a8b8c424, after 8.0.0): a client TLS context
/// that cannot be built from the configured forward-proxy key and chain fails the request before the upstream is
/// reached, with `NettySslContextFactory`'s exception.
fn set_up(config: &Config, host: &str) -> Result<(), Error> {
    match crate::tls::forward_identity_unusable(config, host) {
        true => Err(Error::SetUp("RuntimeException: Exception creating SSL context for client".into())),
        false => Ok(()),
    }
}

/// Netty's `SslHandler` handshake timeout, which the 8.0.0 client keeps at its default; the binary proxy and the
/// WebSocket relay keep it after upstream 4180cbdb4 too.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(10_000);

/// The forwarding client's handshake timeout (upstream 4180cbdb4, after 8.0.0): `socketConnectionTimeoutInMillis`
/// when positive, else Netty's default. 8.0.0 bounds every forward's handshake by the default alone. The handshakes
/// the server terminates are bounded the same way (upstream 9f8deba46, `server::inbound_handshake`).
pub(crate) fn handshake_timeout(config: &Config) -> Duration {
    match config.int_property("socketConnectionTimeoutInMillis", 20_000) {
        millis if millis > 0 => Duration::from_millis(millis as u64),
        _ => HANDSHAKE_TIMEOUT,
    }
}

/// The forwarding client's TLS handshake. A failure is a [`Error::TlsFailure`] naming the JDK's exception (upstream
/// 7a8b8c424, after 8.0.0) when the upstream closed the connection before answering, its first bytes are no TLS
/// record, the handshake timed out, the upstream's certificate is not trusted or names another host, or the upstream
/// sent a fatal alert; and [`Error::Tls`] otherwise.
async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    config: &Config,
    connector: &tokio_rustls::TlsConnector,
    name: ServerName<'static>,
    stream: S,
) -> Result<tokio_rustls::client::TlsStream<Seen<S>>, Error> {
    let seen = Arc::new(Mutex::new((0usize, Vec::new())));
    let stream = Seen { inner: stream, seen: seen.clone() };
    let timeout = handshake_timeout(config);
    let error = match tokio::time::timeout(timeout, Box::pin(connector.connect(name, stream))).await {
        Ok(Ok(s)) => return Ok(s),
        Ok(Err(e)) => e,
        Err(_) => return Err(Error::TlsFailure(format!("SslHandshakeTimeoutException: handshake timed out after {}ms", timeout.as_millis()))),
    };
    let (read, first) = seen.lock().clone();
    // `SslUtils.getEncryptedPacketLength`: a record's content type is 20..=24 and its major version 3.
    if first.len() >= 2 && (!(20..=24).contains(&first[0]) || first[1] != 3) {
        return Err(Error::TlsFailure(format!("NotSslRecordException: not an SSL/TLS record: {read} bytes")));
    }
    if let Some(description) = error.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()).and_then(jdk_handshake_exception) {
        return Err(Error::TlsFailure(description));
    }
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, UnexpectedEof};
    // `ExceptionHandling.upstreamHandshakeFailure`: an upstream that read the ClientHello and closed (FIN) is Netty's
    // `ClosedChannelException` with the handshake's `SSLHandshakeException` suppressed, reported as the upstream
    // closing the connection; a reset is an `IOException`, a connection failure
    if read == 0 && error.kind() == UnexpectedEof {
        return Err(Error::TlsFailure("SSLHandshakeException: upstream closed the connection during the TLS handshake".into()));
    }
    if read == 0 && matches!(error.kind(), UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe) {
        return Err(Error::Connect);
    }
    Err(Error::Tls)
}

/// The JDK's `SSLHandshakeException` for a failed handshake, as `boundedFaultDescriptionWithRootCause` describes it:
/// its message, then `; caused by` the root cause when the message does not already quote it. `None` for a failure
/// whose JDK text is not known here.
fn jdk_handshake_exception(error: &rustls::Error) -> Option<String> {
    let (message, root) = jdk_handshake_message(error)?;
    Some(match root {
        Some(root) => format!("SSLHandshakeException: {message}; caused by {root}"),
        None => format!("SSLHandshakeException: {message}"),
    })
}

/// The JDK's `SSLHandshakeException` message for a failed handshake, and its root cause (`SimpleName: message`) when
/// the message does not already quote it: an untrusted certificate (`PKIX path building failed`, whose root cause
/// `SunCertPathBuilderException` it quotes), one for another host (`HostnameChecker`), a fatal alert received, and
/// (read off the 8.0.0 image and the fixed snapshot) an expired, not
/// yet valid or badly signed one (`PKIX path validation failed`, the `CertificateException` or `SignatureException`
/// behind it the root cause).
fn jdk_handshake_message(error: &rustls::Error) -> Option<(String, Option<String>)> {
    use rustls::CertificateError::{BadSignature, Expired, ExpiredContext, InvalidPurpose, InvalidPurposeContext, NotValidForName, NotValidForNameContext, NotValidYet, NotValidYetContext, Other, UnknownIssuer};
    // webpki refuses a self-signed (CA) certificate as a leaf before looking for its issuer; the JDK finds no path.
    let untrusted_ca = |other: &rustls::OtherError| format!("{other:?}") == "OtherError(CaUsedAsEndEntity)";
    // An intermediate certificate that is not a CA (read off the 9.2.0 oracle).
    let not_ca = |other: &rustls::OtherError| format!("{other:?}") == "OtherError(EndEntityUsedAsCa)";
    const NO_PATH: &str = "(certificate_unknown) PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target";
    const VALIDITY: &str = "PKIX path validation failed: java.security.cert.CertPathValidatorException: validity check failed";
    Some(match error {
        rustls::Error::InvalidCertificate(UnknownIssuer) => (NO_PATH.to_string(), None),
        rustls::Error::InvalidCertificate(Other(other)) if untrusted_ca(other) => (NO_PATH.to_string(), None),
        // `EndEntityChecker.checkTLSServer`: a leaf whose extended key usage excludes serverAuth, a
        // `sun.security.validator.ValidatorException`.
        rustls::Error::InvalidCertificate(InvalidPurpose | InvalidPurposeContext { .. }) => {
            ("(certificate_unknown) Extended key usage does not permit use for TLS server authentication".to_string(), None)
        }
        rustls::Error::InvalidCertificate(Other(other)) if not_ca(other) => (
            "(certificate_unknown) PKIX path validation failed: java.security.cert.CertPathValidatorException: basic constraints check failed: this is not a CA certificate".to_string(),
            None,
        ),
        rustls::Error::InvalidCertificate(NotValidForNameContext { expected, presented }) => {
            let any_dns = presented.iter().any(|name| name.starts_with("DnsName"));
            let mismatch = match expected {
                ServerName::IpAddress(_) if presented.is_empty() => "No subject alternative names present".to_string(),
                ServerName::IpAddress(ip) => format!("No subject alternative names matching IP address {} found", std::net::IpAddr::from(*ip)),
                ServerName::DnsName(name) if any_dns => format!("No subject alternative DNS name matching {} found.", name.as_ref()),
                ServerName::DnsName(name) => format!("No name matching {} found", name.as_ref()),
                _ => return None,
            };
            (format!("(certificate_unknown) {mismatch}"), None)
        }
        rustls::Error::InvalidCertificate(NotValidForName | Expired | NotValidYet) => return None,
        // `X509CertImpl.checkValidity`: the date as `java.util.Date.toString` prints it, in the image's GMT.
        rustls::Error::InvalidCertificate(ExpiredContext { not_after, .. }) => {
            (format!("(certificate_expired) {VALIDITY}"), Some(format!("CertificateExpiredException: NotAfter: {}", java_date(*not_after)?)))
        }
        rustls::Error::InvalidCertificate(NotValidYetContext { not_before, .. }) => {
            (format!("(bad_certificate) {VALIDITY}"), Some(format!("CertificateNotYetValidException: NotBefore: {}", java_date(*not_before)?)))
        }
        rustls::Error::InvalidCertificate(BadSignature) => (
            "(bad_certificate) PKIX path validation failed: java.security.cert.CertPathValidatorException: signature check failed".to_string(),
            Some("SignatureException: Signature does not match.".to_string()),
        ),
        rustls::Error::AlertReceived(alert) => (format!("Received fatal alert: {}", jdk_alert_name(*alert)?), None),
        _ => return None,
    })
}

/// `java.util.Date.toString()` in GMT (the oracle image's zone): `Thu Oct 01 15:26:28 GMT 2026`.
fn java_date(time: UnixTime) -> Option<String> {
    let at = chrono::DateTime::from_timestamp(i64::try_from(time.as_secs()).ok()?, 0)?;
    Some(at.format("%a %b %d %H:%M:%S GMT %Y").to_string())
}

/// The JDK's name of a TLS alert (`Alert.description`).
fn jdk_alert_name(alert: rustls::AlertDescription) -> Option<&'static str> {
    use rustls::AlertDescription as A;
    Some(match alert {
        A::CloseNotify => "close_notify",
        A::UnexpectedMessage => "unexpected_message",
        A::BadRecordMac => "bad_record_mac",
        A::RecordOverflow => "record_overflow",
        A::HandshakeFailure => "handshake_failure",
        A::BadCertificate => "bad_certificate",
        A::UnsupportedCertificate => "unsupported_certificate",
        A::CertificateRevoked => "certificate_revoked",
        A::CertificateExpired => "certificate_expired",
        A::CertificateUnknown => "certificate_unknown",
        A::IllegalParameter => "illegal_parameter",
        A::UnknownCA => "unknown_ca",
        A::AccessDenied => "access_denied",
        A::DecodeError => "decode_error",
        A::DecryptError => "decrypt_error",
        A::ProtocolVersion => "protocol_version",
        A::InsufficientSecurity => "insufficient_security",
        A::InternalError => "internal_error",
        A::InappropriateFallback => "inappropriate_fallback",
        A::UserCanceled => "user_canceled",
        A::MissingExtension => "missing_extension",
        A::UnsupportedExtension => "unsupported_extension",
        A::UnrecognisedName => "unrecognized_name",
        A::BadCertificateStatusResponse => "bad_certificate_status_response",
        A::UnknownPSKIdentity => "unknown_psk_identity",
        A::CertificateRequired => "certificate_required",
        A::NoApplicationProtocol => "no_application_protocol",
        _ => return None,
    })
}

/// A stream that remembers how many bytes were read through it and the first few of them.
pub struct Seen<S> {
    inner: S,
    seen: Arc<Mutex<(usize, Vec<u8>)>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Seen<S> {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        let new = &buf.filled()[before..];
        if !new.is_empty() {
            let mut seen = self.seen.lock();
            seen.0 += new.len();
            let room = 5usize.saturating_sub(seen.1.len());
            seen.1.extend_from_slice(&new[..room.min(new.len())]);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Seen<S> {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// `NettyHttpClient.newBinaryRelaySslHandler` (master): the binary relay's TLS with its upstream, from the first byte
/// or started part way on the connection it already has. The name the client asked MockServer for stands in for an
/// upstream given as an address, and the handshake is bounded by `socketConnectionTimeoutInMillis`.
pub(crate) async fn binary_relay_tls_connect<S: AsyncRead + AsyncWrite + Unpin>(
    config: &Config,
    host: &str,
    client_server_name: Option<&str>,
    stream: S,
    identity: Option<ForwardIdentity>,
) -> Result<tokio_rustls::client::TlsStream<S>, Error> {
    let mut host = host.trim_start_matches('[').trim_end_matches(']');
    if let Some(name) = client_server_name.filter(|n| !n.trim().is_empty())
        && host.parse::<std::net::IpAddr>().is_ok()
    {
        host = name;
    }
    let name = ServerName::try_from(host.to_string()).map_err(|_| Error::Tls)?;
    let connector = tokio_rustls::TlsConnector::from(tls_config(Some(config), identity, host));
    match tokio::time::timeout(handshake_timeout(config), connector.connect(name, stream)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => match error.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()).and_then(jdk_handshake_message) {
            Some((message, _)) => Err(Error::TlsDecoder(message)),
            None => Err(Error::Tls),
        },
        Err(_) => Err(Error::Tls),
    }
}

/// The WebSocket relay's TLS handshake with its upstream (`WebSocketProxyRelayHandler`, master): the forwarding
/// client's trust and client certificate, bounded by `socketConnectionTimeoutInMillis`, a failure the JDK names
/// reported as [`Error::TlsFailure`].
pub(crate) async fn websocket_tls_connect(config: &Config, host: &str, stream: TcpStream, identity: Option<ForwardIdentity>) -> Result<Box<dyn crate::ws_relay::Io>, Error> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let name = ServerName::try_from(host.to_string()).map_err(|_| Error::Tls)?;
    let connector = tokio_rustls::TlsConnector::from(tls_config(Some(config), identity, host));
    Ok(Box::new(handshake(config, &connector, name, stream).await?))
}

/// A WebSocket handshake response's head read as the relay's `HttpClientCodec` reads it (the status line under Netty's
/// 4096 bytes, the header lines under `maxHeaderSize`, master): its status, its headers as they arrived, and
/// `maxHeaderSize`; the bytes past it stay in `buf`.
pub(crate) async fn read_websocket_handshake_head<S: AsyncRead + Unpin>(config: &Config, stream: &mut S, buf: &mut BytesMut) -> (usize, Result<(u32, String, Vec<(String, String)>), Error>) {
    let max = max_header(config);
    (max, read_head(stream, buf, max).await.map(|head| (head.status, head.reason, head.headers)))
}

/// `maxHeaderSize`, which bounds a forwarded response's headers since upstream a78886b4d.
fn max_header(config: &Config) -> usize {
    usize::try_from(crate::config::max_header_size(config)).unwrap_or(usize::MAX)
}

/// `ForwardHeaderLimit`'s names for what was over the limit.
const HEADERS_AND_TRAILERS: &str = "upstream response headers and trailers are together";
const TRAILERS: &str = "upstream response trailers are";
const HEADER_BLOCK: &str = "an upstream response header block is more than a quarter";
const CONNECT_HEADERS: &str = "the upstream proxy's CONNECT response headers are";

/// `ForwardHeaderLimit.responseOverLimit`: the reason a response over `maxHeaderSize` is refused with.
fn header_limit(what: &str, max: usize) -> Error {
    Error::HeaderLimit(format!("{what} larger than maxHeaderSize ({max} bytes)"), None)
}

/// `maxResponseBodySize` (default 50 MiB), the forwarding client's aggregator limit.
fn max_body(config: &Config) -> usize {
    usize::try_from(config.int_property("maxResponseBodySize", 52_428_800)).unwrap_or(usize::MAX)
}

/// Writes `request` and reads the response; the stream comes back when the connection can carry another request.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(mut stream: S, request: &Outbound, limits: Limits) -> Result<(Upstream, Option<Reusable<S>>), Error> {
    let mut head = format!("{} {} HTTP/1.1\r\n", request.method, request.target);
    for (name, value) in &request.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(&request.body);
    stream.write_all(&out).await.map_err(|_| Error::Connect)?;
    let head_only = request.method.eq_ignore_ascii_case("HEAD");
    let mut buf = BytesMut::with_capacity(16 * 1024);
    let head = tokio::time::timeout(limits.read_timeout, read_head(&mut stream, &mut buf, limits.max_header)).await.map_err(|_| Error::ReadTimeout)??;
    let first_byte = now_millis();
    let closing = |headers: &[(String, String)]| {
        headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.to_ascii_lowercase().contains("close"))
    };
    let mut head = head;
    if let Some(failure) = rejected_head(&head, head_only) {
        // `HttpObjectDecoder.readHeaders` threw: `ForwardHeaderLimit.Http1Response` fails the forward with the reason and
        // closes the connection, streamed or not (upstream c990e4a20, after 8.0.0). 8.0.0 relayed the head with no
        // content (aggregated: `content-length: 0`, the connection pooled with its decoder in `BAD_MESSAGE`) and logged
        // `exception decoding response <message>`.
        return Err(Error::Undecodable(failure));
    }
    if head_only && request.streams(&head.headers) {
        // `StreamingAwareHttpObjectAggregator` relays the head of a streaming response to HEAD too; the decoder ends
        // its content at once (`isContentAlwaysEmpty`), so the relayed stream is empty and the connection stays usable.
        let (_, rx) = tokio::sync::mpsc::channel(1);
        let Head { status, reason, headers, http11, .. } = head;
        let timing = Timing { first_byte, response_received: now_millis(), ..Timing::default() };
        let reusable = http11 && buf.is_empty() && !closing(&headers) && !closing(&request.headers);
        return Ok((Upstream { status, reason, headers, body: Bytes::new(), stream: Some(rx), timing, ..Default::default() }, reusable.then_some(Reusable::Clean(stream))));
    }
    if !head_only && request.streams(&head.headers) {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let chunked = head.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"));
        let length = head.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.trim().parse::<usize>().ok());
        let end = Arc::new(StreamEnd::default());
        let decoder = decoding::Decoder::for_head(&mut head.headers, false).map_err(Error::Decode)?;
        let relay = Relay { idle: limits.stream_idle, channel: limits.channel, end: end.clone(), max_header: limits.max_header, header_size: head.header_size, max_unwritten: limits.max_body };
        tokio::spawn(relay_body(stream, buf, chunked, length, decoder, tx, relay));
        let Head { status, reason, headers, .. } = head;
        let timing = Timing { first_byte, response_received: now_millis(), ..Timing::default() };
        return Ok((Upstream { status, reason, headers, body: Bytes::new(), stream: Some(rx), stream_end: end, timing, ..Default::default() }, None));
    }
    let mut decoded_headers = head.headers.clone();
    let decoder = decoding::Decoder::for_head(&mut decoded_headers, true).map_err(Error::Decode)?.map(|decoder| (decoder, decoded_headers));
    // A decoded response is aggregated from the decompressor's heap buffers, each raw read released once decoded: the
    // direct-memory limit never meets it (a gzip response decoding to 10 MiB passed at an 8 MiB limit).
    let direct_memory = limits.direct_memory.filter(|_| decoder.is_none());
    let (mut upstream, reusable) = tokio::time::timeout(limits.read_timeout, read_body(&mut stream, buf, head, head_only, (limits.max_body, limits.max_header), decoder)).await.map_err(|_| Error::ReadTimeout)??;
    if let Some((used, max)) = direct_memory.and_then(|max| direct_memory_refusal(upstream.body.len(), max)) {
        return Err(Error::DirectMemory { channel: limits.channel, used, max });
    }
    upstream.timing.first_byte = first_byte;
    upstream.timing.response_received = now_millis();
    let reusable = reusable && !closing(&upstream.headers) && !closing(&request.headers);
    Ok((upstream, reusable.then_some(Reusable::Clean(stream))))
}

/// Whether Netty 4.2's `HttpObjectDecoder.readHeaders` (RFC 9112 transfer-encoding on, duplicate lengths not allowed)
/// throws on this head, in its order, and the message of what it throws (the same texts as for a request,
/// `http1::content_length_fault`; the last on the 8.0.0 image):
/// - `HttpUtil.normalizeAndGetContentLength` fails (before `isContentAlwaysEmpty`, so on any status or method; since
///   Netty 4.2.19 on any version, HTTP/1.0 included): `Multiple Content-Length values found: [..]` or
///   `Content-Length value is not a number: ..`;
/// - then, for a response that may have content (not to HEAD, not 1xx, 204 or 304), any `Transfer-Encoding` on a
///   version other than HTTP/1.1 (`TransferEncodingNotAllowedException`, whose message is not known here: `None`);
/// - with `chunked` among the encodings (`HttpUtil.isTransferEncodingChunked`, comma-separated, any case):
///   `isLastTransferEncodingChunked` (Netty 4.2.19) over every token of every line, in order: a second `chunked`
///   ("must not be applied more than once"), or a last token other than `chunked` ("chunked must be the last
///   encoding"); then any `Content-Length` beside it (`ContentLengthNotAllowedException`).
fn rejected_head(head: &Head, head_only: bool) -> Option<String> {
    let header = |name: &'static str| head.headers.iter().filter(move |(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str());
    let lengths: Vec<&str> = header("content-length").collect();
    if !lengths.is_empty() && content_length(&lengths).is_none() {
        let multiple = lengths.len() > 1 || lengths[0].contains(',');
        return Some(fault("IllegalArgumentException", &match multiple {
            true => format!("Multiple Content-Length values found: [{}]", lengths.join(", ")),
            false => format!("Content-Length value is not a number: {}", lengths[0]),
        }));
    }
    if head_only || matches!(head.status, 100..=199 | 204 | 304) || header("transfer-encoding").next().is_none() {
        return None;
    }
    if !head.http11 {
        // `TRANSFER_ENCODING_NOT_ALLOWED` (`rfc9112TransferEncoding`), as for a request (`http1::content_length_fault`).
        return Some(fault("TransferEncodingNotAllowedException", "The Transfer-Encoding header is only allowed in HTTP/1.1 or newer"));
    }
    if !header("transfer-encoding").any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("chunked"))) {
        return None;
    }
    let (mut chunked_seen, mut last_chunked) = (false, false);
    for token in header("transfer-encoding").flat_map(|v| v.split(',')).map(|t| t.trim_matches([' ', '\t'])).filter(|t| !t.is_empty()) {
        last_chunked = token.eq_ignore_ascii_case("chunked");
        if last_chunked && std::mem::replace(&mut chunked_seen, true) {
            return Some(fault("IllegalArgumentException", "chunked transfer coding must not be applied more than once"));
        }
    }
    if !last_chunked {
        return Some(fault("IllegalArgumentException", "chunked must be the last encoding present in the Transfer-Encoding header"));
    }
    (!lengths.is_empty()).then(|| fault("ContentLengthNotAllowedException", "Content-Length are not allowed in HTTP/1.1 messages that contains a Transfer-Encoding header."))
}

/// `ExceptionHandling.boundedFaultDescription`: the exception's simple class name and its message cut to 256
/// characters (`StringUtils.abbreviate`: 253 and `...`).
fn fault(class: &str, message: &str) -> String {
    let message = match message.chars().count() > 256 {
        true => format!("{}...", message.chars().take(253).collect::<String>()),
        false => message.to_string(),
    };
    format!("{class}: {message}")
}

/// What [`parse_head`] made of the bytes read so far.
enum Parsed {
    /// More bytes are needed. `in_headers`: the status line was read (`State.READ_HEADER`), so a close now is
    /// `decodeLast`'s `PrematureChannelClosureException`.
    Partial { in_headers: bool },
    /// The head (any `1xx` included) and the bytes it took.
    Complete(Head, usize),
    /// What Netty's decoder threw, as `ExceptionHandling.boundedFaultDescription` names it.
    Failed(String),
}

/// `InvalidLineSeparatorException`: strict line parsing (`defaultStrictLineParsing`) refuses a bare LF.
fn line_separator_fault() -> String {
    fault("InvalidLineSeparatorException", "Line Feed must be preceded by Carriage Return when terminating HTTP start- and header field-lines")
}

/// `Character.isWhitespace` on a byte (Netty's `LATIN_WHITESPACE`, which only sets ASCII entries).
fn java_whitespace(b: u8) -> bool {
    matches!(b, b'\t'..=b'\r' | 0x1c..=0x1f | b' ')
}

/// `isOWS`: SP or HTAB.
fn ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// `findEndOfString`: the end of `line` without its trailing OWS (`0` when `line[1..]` is all OWS).
fn end_of_string(line: &[u8], start: usize) -> usize {
    (start + 1..line.len()).rev().find(|i| !ows(line[*i])).map_or(0, |i| i + 1)
}

/// Netty 4.2's `HttpResponseDecoder` reading a response head (`HttpObjectDecoder.decode`, states `SKIP_INITIAL_LINE_CHARS`
/// to `READ_HEADER`), as lenient and as strict as it is: lines end with CRLF (a bare LF throws), empty
/// lines before the status line are skipped, the status line splits on lenient SP (`splitInitialLine`), its version is
/// `HttpVersion.valueOf(text, true)` (any case, `HTTP/d.d`), its status `Integer.parseInt`, a header name ends at its
/// colon or at the first SP/HTAB (`splitHeader`: `Bad Header: x` is `Bad: x`), an obs-fold line joins the value with one
/// space, and a name is validated (token characters, not empty) when its header is added. `readHeaders`' checks after
/// the head are [`rejected_head`]'s.
fn parse_head(buf: &[u8]) -> Parsed {
    // `SKIP_INITIAL_LINE_CHARS` with the strict check: CR and LF are skipped, an ISO control character after them throws.
    let Some(mut pos) = buf.iter().position(|b| *b != b'\r' && *b != b'\n') else { return Parsed::Partial { in_headers: false } };
    if buf[pos] < 0x20 || (0x7f..=0x9f).contains(&buf[pos]) {
        return Parsed::Failed(line_separator_fault());
    }
    // `LineParser`/`HeaderParser.parse`: the next line without its CRLF, and where the one after it starts.
    let next_line = |pos: usize| -> Option<Result<(&[u8], usize), String>> {
        let lf = pos + buf[pos..].iter().position(|b| *b == b'\n')?;
        Some(match lf > pos && buf[lf - 1] == b'\r' {
            true => Ok((&buf[pos..lf - 1], lf + 1)),
            false => Err(line_separator_fault()),
        })
    };
    let (line, next) = match next_line(pos) {
        None => return Parsed::Partial { in_headers: false },
        Some(Err(failure)) => return Parsed::Failed(failure),
        Some(Ok(line)) => line,
    };
    pos = next;
    let (version, status, reason) = match status_line(line) {
        Ok(parts) => parts,
        Err(failure) => return Parsed::Failed(failure),
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut pending: Option<(Vec<u8>, Vec<u8>)> = None;
    let mut header_size = 0;
    let add = |headers: &mut Vec<(String, String)>, (name, value): (Vec<u8>, Vec<u8>)| -> Result<(), String> {
        validate_header_name(&name)?;
        headers.push((String::from_utf8_lossy(&name).into_owned(), String::from_utf8_lossy(&value).into_owned()));
        Ok(())
    };
    loop {
        let (line, next) = match next_line(pos) {
            None => return Parsed::Partial { in_headers: true },
            Some(Err(failure)) => return Parsed::Failed(failure),
            Some(Ok(line)) => line,
        };
        pos = next;
        if line.is_empty() {
            break;
        }
        header_size += line.len();
        match pending.as_mut() {
            Some((_, value)) if ows(line[0]) => {
                // `String.trim`: every character up to SP goes at both ends.
                let start = line.iter().position(|b| *b > b' ').unwrap_or(line.len());
                let end = line.iter().rposition(|b| *b > b' ').map_or(start, |i| i + 1);
                value.push(b' ');
                value.extend_from_slice(&line[start..end]);
            }
            _ => {
                if let Some(header) = pending.take() && let Err(failure) = add(&mut headers, header) {
                    return Parsed::Failed(failure);
                }
                match split_header(line) {
                    Ok(header) => pending = Some(header),
                    Err(failure) => return Parsed::Failed(failure),
                }
            }
        }
    }
    if let Some(header) = pending && let Err(failure) = add(&mut headers, header) {
        return Parsed::Failed(failure);
    }
    // HTTP/1.0 is no longer read differently: Netty 4.2.19 refuses its duplicate `Content-Length`s too.
    let (http11, _http10) = version;
    Parsed::Complete(Head { status, reason, headers, http11, header_size }, pos)
}

/// A status line's version: whether it is the `HTTP_1_1` constant, and whether it is HTTP/1.0 or earlier.
type HttpVersion = (bool, bool);

/// `splitInitialLine` and `HttpResponseDecoder.createMessage`: the version (whether it is the `HTTP_1_1` constant, and
/// whether it is HTTP/1.0 or earlier), the status and the reason phrase.
fn status_line(line: &[u8]) -> Result<(HttpVersion, u32, String), String> {
    let illegal = |b: u8| b < 0x20 || b == 0x7f || b == b' ';
    let last = line[line.len() - 1];
    if illegal(last) && !ows(last) {
        return Err(fault("IllegalArgumentException", &format!("Illegal character in request line: 0x{last:x}")));
    }
    let lenient_sp = |b: u8| matches!(b, b' ' | b'\t' | 0x0b | 0x0c | b'\r');
    let non_sp = |from: usize| -> Result<usize, String> {
        for (i, b) in line.iter().enumerate().skip(from) {
            if lenient_sp(*b) {
                continue;
            }
            if java_whitespace(*b) {
                return Err(fault("IllegalArgumentException", "Invalid separator"));
            }
            return Ok(i);
        }
        Ok(line.len())
    };
    let sp = |from: usize| (from..line.len()).find(|i| lenient_sp(line[*i])).unwrap_or(line.len());
    let a_start = non_sp(0)?;
    let a_end = sp(a_start);
    let b_start = non_sp(a_end)?;
    let b_end = sp(b_start);
    let c_start = non_sp(b_end)?;
    let c_end = end_of_string(line, c_start.saturating_sub(1));
    let latin1 = |bytes: &[u8]| bytes.iter().map(|b| *b as char).collect::<String>();
    let version = http_version(&latin1(&line[a_start..a_end]))?;
    let status = java_parse_int(&latin1(&line[b_start..b_end]))?;
    let reason = if c_start < c_end { &line[c_start..c_end] } else { &[][..] };
    // `HttpResponseStatus.valueOf(code, reasonPhrase)`'s constructor: `checkPositiveOrZero(code, "code")`, then no CR or
    // LF in the reason phrase (observed on the snapshot image; 8.0.0 answered 999 `Unknown` for both).
    if status < 0 {
        return Err(fault("IllegalArgumentException", &format!("code : {status} (expected: >= 0)")));
    }
    if reason.contains(&b'\r') {
        return Err(fault("IllegalArgumentException", &format!("reasonPhrase contains one of the following prohibited characters: \\r\\n: {}", latin1(reason))));
    }
    // Any `int` from 0 up is a status, relayed as it is (`HTTP/1.1 70000 Big` on 8.0.0).
    Ok((version, status as u32, String::from_utf8_lossy(reason).into_owned()))
}

/// `HttpVersion.valueOf(text, true)`: `HTTP/1.1` and `HTTP/1.0` are the constants; any other text is upper-cased and
/// must be `HTTP/d.d`. Whether it is the `HTTP_1_1` constant, and whether it is HTTP/1.0 or earlier.
fn http_version(text: &str) -> Result<(bool, bool), String> {
    match text {
        "HTTP/1.1" => return Ok((true, false)),
        "HTTP/1.0" => return Ok((false, true)),
        "" => return Err(fault("IllegalArgumentException", "text is empty (possibly HTTP/0.9)")),
        _ => {}
    }
    let upper: Vec<char> = text.to_uppercase().chars().collect();
    let text: String = upper.iter().collect();
    if upper.len() != 8 || !text.starts_with("HTTP/") || upper[6] != '.' {
        return Err(fault("IllegalArgumentException", &format!("invalid version format: {text}")));
    }
    let digit = |c: char| match c.to_digit(10).filter(|_| c.is_ascii_digit()) {
        Some(d) => Ok(d),
        None => Err(fault("IllegalArgumentException", &format!("Invalid version number, only 0-9 (0x30-0x39) allowed, but received a '{c}' (0x{:x})", c as u32))),
    };
    let (major, minor) = (digit(upper[5])?, digit(upper[7])?);
    Ok((false, major < 1 || (major == 1 && minor == 0)))
}

/// `Integer.parseInt(text)`: an optional sign and decimal digits within `int`, else `NumberFormatException`.
fn java_parse_int(text: &str) -> Result<i64, String> {
    let failure = || fault("NumberFormatException", &format!("For input string: \"{text}\""));
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(failure());
    }
    text.parse::<i32>().map(i64::from).map_err(|_| failure())
}

/// `splitHeader` for a response: the name ends at the colon or at the first SP/HTAB, the value starts after the next
/// colon (if any) and its leading OWS, and ends before its trailing OWS.
fn split_header(line: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let Some(name_end) = line.iter().position(|b| *b == b':' || ows(*b)) else {
        return Err(fault("IllegalArgumentException", "No colon found"));
    };
    let colon_end = (name_end..line.len()).find(|i| line[*i] == b':').map_or(line.len(), |i| i + 1);
    // `findNonWhitespace`: only OWS may come before the value.
    let mut value_start = line.len();
    for (i, b) in line.iter().enumerate().skip(colon_end) {
        if !java_whitespace(*b) {
            value_start = i;
            break;
        }
        if !ows(*b) {
            return Err(fault("IllegalArgumentException", &format!("Invalid separator, only a single space or horizontal tab allowed, but received a '{b}' (0x{b:x})")));
        }
    }
    let value = match value_start == line.len() {
        true => Vec::new(),
        false => line[value_start..end_of_string(line, 0)].to_vec(),
    };
    Ok((line[..name_end].to_vec(), value))
}

/// `DefaultHttpHeadersFactory`'s name validation when a header is added: not empty, token characters only.
fn validate_header_name(name: &[u8]) -> Result<(), String> {
    let text: String = name.iter().map(|b| *b as char).collect();
    if name.is_empty() {
        return Err(fault("IllegalArgumentException", &format!("empty headers are not allowed [{text}]")));
    }
    let token = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    match text.char_indices().find(|(_, c)| !token(*c)) {
        Some((index, c)) => Err(fault("IllegalArgumentException", &format!("a header name can only contain \"token\" characters, but found invalid character 0x{:x} at index {index} of header '{text}'.", c as u32))),
        None => Ok(()),
    }
}

/// `HttpUtil.normalizeAndGetContentLength(values, isHttp10OrEarlier, false)`: more than one value (lines, or a comma
/// in the first) fails unless HTTP/1.0, which then reads the first line; that must start with a digit and parse as a
/// non-negative `long`.
fn content_length(values: &[&str]) -> Option<i64> {
    let first = values.first()?.trim();
    if values.len() > 1 || first.contains(',') {
        return None;
    }
    if !first.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    first.parse::<i64>().ok()
}

/// A reused connection's stream, noting whether any byte of the response has been read from it (upstream's
/// `FIRST_BYTE_MILLIS`, which keeps a failure after the first byte from being retried).
struct Watched<S> {
    inner: S,
    read: Arc<std::sync::atomic::AtomicBool>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.read.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A connection [`exchange`] hands back for another request.
enum Reusable<S> {
    Clean(S),
}

impl Reusable<IdleConnection> {
    fn into_idle(self) -> IdleConnection {
        match self {
            Reusable::Clean(stream) => stream,
        }
    }
}

async fn fill<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut BytesMut) -> Result<usize, Error> {
    buf.reserve(16 * 1024);
    stream.read_buf(buf).await.map_err(|e| tls_read_failure(&e).unwrap_or(Error::Protocol))
}

/// A TLS fault the JDK names that ends a read of the response (an `SSLException`, `upstreamFailureReason`): over TLS
/// 1.3 an upstream refusing the client certificate does so after the client's handshake has finished, with an alert
/// in the first record the client reads (`ForwardWithCustomClientCertificateIntegrationTest`).
fn tls_read_failure(error: &std::io::Error) -> Option<Error> {
    let tls = error.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>())?;
    jdk_handshake_exception(tls).map(Error::TlsFailure)
}

/// `maxInitialLineLength`, the longest status line the forwarding client's decoder reads.
const INITIAL_LINE_LIMIT: usize = 4096;

/// A response head, the real one after any `1xx`.
struct Head {
    status: u32,
    reason: String,
    headers: Vec<(String, String)>,
    /// The version is the `HttpVersion.HTTP_1_1` constant (the text `HTTP/1.1` exactly; `http/1.1` and `HTTP/1.2` are
    /// other instances), which `readHeaders` compares by identity.
    http11: bool,
    /// The bytes of its header lines as `HeaderParser` counts them, which a chunked body's trailers count on top of.
    header_size: usize,
}

/// `HeaderParser`: the bytes of a head's header lines (not the status line, not the line ends), counted together.
fn header_bytes(head: &[u8]) -> usize {
    head.split(|b| *b == b'\n').skip(1).map(|l| l.strip_suffix(b"\r").unwrap_or(l).len()).sum()
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut BytesMut, max_header: usize) -> Result<Head, Error> {
    loop {
        // `HttpClientCodec`'s `maxInitialLineLength` (4096, the line without its CRLF): a longer status line fails the
        // forward (upstream c990e4a20, after 8.0.0; 8.0.0 answered 999 `Unknown`). `HttpClientInitializer`'s
        // `HttpLineEndSplitGuard` holds back a CR that ends a read, so an unfinished line counts without it.
        let line_end = buf.iter().position(|b| *b == b'\n');
        let line = line_end.map_or(buf.len() - usize::from(buf.ends_with(b"\r")), |i| i - usize::from(i > 0 && buf[i - 1] == b'\r'));
        if line > INITIAL_LINE_LIMIT {
            return Err(Error::Undecodable(fault("TooLongHttpLineException", "An HTTP line is larger than 4096 bytes.")));
        }
        let (head, len) = match parse_head(buf) {
            Parsed::Complete(head, _) if head.header_size > max_header => return Err(header_limit("upstream response headers are", max_header)),
            Parsed::Complete(head, len) => (head, len),
            // `ForwardHeaderLimit.Http1Response` fails the forward with what the decoder failed with (upstream
            // c990e4a20, after 8.0.0)
            Parsed::Failed(failure) => return Err(Error::Undecodable(failure)),
            Parsed::Partial { in_headers } => {
                if fill(stream, buf).await? == 0 {
                    // `decodeLast` in `READ_HEADER`: 8.0.0 relayed the head read so far with no content and logged
                    // `exception decoding response Connection closed before received headers`; upstream c990e4a20
                    // fails the forward with it. A close inside the status line is an empty 502 on both.
                    return Err(match in_headers {
                        true => Error::Undecodable(fault("PrematureChannelClosureException", "Connection closed before received headers")),
                        false => Error::Protocol,
                    });
                }
                continue;
            }
        };
        buf.advance(len);
        if (100..200).contains(&head.status) && head.status != 101 {
            continue; // 100 Continue and friends precede the real response
        }
        return Ok(head);
    }
}

/// What a streamed body's relay reports beyond its chunks: the idle bound that replaces the socket timeout once the
/// response streams (`switchToStreamingMode`), and how the stream ended.
struct Relay {
    idle: Option<Duration>,
    /// The connection's `Channel.toString`, for `StreamIdleTimeoutHandler`'s log entry.
    channel: String,
    end: Arc<StreamEnd>,
    /// `maxHeaderSize`, and the head's share of it, which trailers count on top of.
    max_header: usize,
    header_size: usize,
    /// `maxResponseBodySize`, the decoded bytes one upstream read may queue for the client (0: no bound).
    max_unwritten: usize,
}

/// Netty's largest read of a socket (`AdaptiveRecvByteBufAllocator`'s maximum): what one decoder call is handed.
const MAX_READ: usize = 64 * 1024;

/// The slices a decoder is pushed at a time, so that a hostile coding is never expanded far past the bound before
/// the check.
const DECODE_SLICE: usize = 8 * 1024;

/// One read's worth of content (`chunk`, cut into [`MAX_READ`] reads) decoded: `None` when a read decodes to more
/// than `max_unwritten` bytes (`StreamingBody.UnwrittenBytesLimitExceededException`, upstream, master: decoded bytes
/// waiting for the client are bounded, and only a single read can pass the bound, since the upstream is read again
/// only once they drain), or when the content cannot be decoded.
fn decode_bounded(decoder: &mut decoding::Decoder, chunk: &[u8], max_unwritten: usize) -> Option<Vec<Vec<u8>>> {
    let mut reads = Vec::new();
    for read in chunk.chunks(MAX_READ) {
        let mut decoded = Vec::new();
        for slice in read.chunks(DECODE_SLICE) {
            let cap = if max_unwritten > 0 { max_unwritten.saturating_sub(decoded.len()) } else { usize::MAX };
            decoded.extend(decoder.push_pieces(slice, cap).ok()?.concat());
            if max_unwritten > 0 && decoded.len() > max_unwritten {
                return None;
            }
        }
        reads.push(decoded);
    }
    Some(reads)
}

/// `IdleStateHandler(0, 0, streamIdleTimeoutSeconds)` firing: nothing was read within the idle bound, and
/// `StreamIdleTimeoutHandler` closes the connection.
struct Idle;

/// [`fill`], bounded by the stream's idle timeout when there is one.
async fn idle_fill<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut BytesMut, idle: Option<Duration>) -> Result<Result<usize, Error>, Idle> {
    match idle {
        None => Ok(fill(stream, buf).await),
        Some(idle) => tokio::time::timeout(idle, fill(stream, buf)).await.map_err(|_| Idle),
    }
}

/// A streamed body relayed chunk by chunk (as read, or per chunk of a chunked body) until it ends, decoded first when
/// `decoder` is given (a content it cannot decode ends the stream). A chunked or length-delimited body whose
/// connection closes (or is closed for idling) before its last content ends cut (`HttpObjectDecoder.decodeLast`'s
/// premature closure); one delimited by the close itself ends complete.
async fn relay_body<S: AsyncRead + Unpin>(mut stream: S, mut buf: BytesMut, chunked: bool, length: Option<usize>, decoder: Option<decoding::Decoder>, tx: tokio::sync::mpsc::Sender<Bytes>, relay: Relay) {
    let (inner, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let tx = match decoder {
        None => tx,
        Some(mut decoder) => {
            let failed = relay.end.clone();
            let max_unwritten = relay.max_unwritten;
            tokio::spawn(async move {
                // a receiver that is gone (the client's stream was reset) ends the reading side too
                while let Some(chunk) = tokio::select! { chunk = rx.recv() => chunk, _ = tx.closed() => None } {
                    // A content that cannot be decoded, or a read decoded past the bound, ends the stream with the
                    // error (`StreamingBody.error`): recorded truncated, the upstream connection closed (dropping
                    // `rx` ends the reading side).
                    let Some(reads) = decode_bounded(&mut decoder, &chunk, max_unwritten) else { return failed.cut() };
                    for decoded in reads.into_iter().filter(|d| !d.is_empty()) {
                        if tx.send(Bytes::from(decoded)).await.is_err() {
                            return;
                        }
                    }
                }
            });
            inner
        }
    };
    let Relay { idle, channel, end, max_header, header_size, .. } = relay;
    // `Ok(true)`: more bytes in `buf`; `Ok(false)`: the connection closed (or failed), or the receiver is gone (the
    // client's stream was reset or its connection closed: a quiet upstream is closed then, not at its idle timeout);
    // `Err`: closed for idling.
    let more = async |stream: &mut S, buf: &mut BytesMut| tokio::select! {
        read = idle_fill(stream, buf, idle) => match read {
            Ok(read) => Ok(matches!(read, Ok(n) if n > 0)),
            Err(Idle) => Err(Idle),
        },
        _ = tx.closed() => Ok(false),
    };
    let closed = |idled: Result<bool, Idle>, premature: bool| {
        if tx.is_closed() {
            return;
        }
        if idled.is_err() {
            let _ = end.idle.set(channel.clone());
        }
        if premature {
            end.cut();
        }
    };
    if chunked {
        loop {
            let line = loop {
                if let Some(i) = buf.windows(2).position(|w| w == b"\r\n") {
                    let line = String::from_utf8_lossy(&buf[..i]).into_owned();
                    buf.advance(i + 2);
                    break line;
                }
                let read = more(&mut stream, &mut buf).await;
                if !matches!(read, Ok(true)) {
                    return closed(read, true);
                }
            };
            // An invalid chunk size: `StreamedResponseDecoderResultGuard` turns the codec's failed last content into
            // the abort (upstream c9fb69fd5, after 8.0.0, whose 8.0.0 ended the stream clean).
            let Ok(size) = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16) else { return end.cut() };
            if size == 0 {
                // The trailer section, up to its blank line: the last content. Trailers over what the head left of
                // `maxHeaderSize` fail it, and the connection is closed (`ForwardHeaderLimit.Http1Response`).
                let mut counted = header_size;
                loop {
                    let line = loop {
                        if let Some(i) = buf.windows(2).position(|w| w == b"\r\n") {
                            let length = i;
                            buf.advance(i + 2);
                            break length;
                        }
                        let read = more(&mut stream, &mut buf).await;
                        if !matches!(read, Ok(true)) {
                            return closed(read, true);
                        }
                    };
                    if line == 0 {
                        return;
                    }
                    counted += line;
                    if counted > max_header {
                        if let Error::HeaderLimit(reason, _) = header_limit(HEADERS_AND_TRAILERS, max_header) {
                            let _ = end.header_limit.set(reason);
                        }
                        end.cut();
                        return;
                    }
                }
            }
            while buf.len() < size + 2 {
                let read = more(&mut stream, &mut buf).await;
                if !matches!(read, Ok(true)) {
                    return closed(read, true);
                }
            }
            let chunk = buf.split_to(size).freeze();
            buf.advance(2);
            if tx.send(chunk).await.is_err() {
                return;
            }
        }
    }
    let mut remaining = length.unwrap_or(usize::MAX);
    loop {
        if !buf.is_empty() {
            let n = buf.len().min(remaining);
            remaining -= n;
            if tx.send(buf.split_to(n).freeze()).await.is_err() || remaining == 0 {
                return;
            }
        }
        let read = more(&mut stream, &mut buf).await;
        if !matches!(read, Ok(true)) {
            return closed(read, length.is_some());
        }
    }
}

/// The response body, and whether it ended where the connection can carry another (HTTP/1.1, a delimited body,
/// nothing read beyond it).
/// `decoded`: the content decoder for this head and the headers as it leaves them.
/// `(max_body, max_header)`: `maxResponseBodySize` and `maxHeaderSize`.
async fn read_body<S: AsyncRead + Unpin>(stream: &mut S, mut buf: BytesMut, head: Head, head_only: bool, (max_body, max_header): (usize, usize), decoded: Option<(decoding::Decoder, Vec<(String, String)>)>) -> Result<(Upstream, bool), Error> {
    let Head { status, reason, mut headers, http11, header_size, .. } = head;
    let mut chunked_trailers = Vec::new();
    // With a content decoder the aggregator after it counts decoded bytes (`HttpContentDecompressor` sits before
    // `HttpObjectAggregator`): the received content is not limited, and the chunks it arrived in are kept.
    let raw_max = if decoded.is_some() { usize::MAX } else { max_body };
    let mut chunk_sizes = Vec::new();
    {
        let header = |n: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str());
        let no_body = head_only || status == 204 || status == 304;
        let mut delimited = true;
        let body = if no_body {
            if head_only && header("content-length").is_none() {
                // `HttpObjectAggregator` on the empty content of a HEAD response: `beginAggregation` strips `chunked`
                // and `finishAggregation` adds `content-length: 0`.
                headers.retain(|(k, v)| !(k.eq_ignore_ascii_case("transfer-encoding") && v.trim().eq_ignore_ascii_case("chunked")));
                headers.push(("content-length".into(), "0".into()));
            }
            Bytes::new()
        } else if header("transfer-encoding").is_some_and(|t| t.to_ascii_lowercase().contains("chunked")) {
            match read_chunked(stream, &mut buf, raw_max, (header_size, max_header)).await.map(|(body, trailers, sizes)| {
                // `FullHttpResponseToMockServerHttpResponse`: trailing headers join the response headers.
                chunked_trailers = trailers;
                chunk_sizes = sizes;
                // `HttpObjectAggregator`: the aggregated message loses `Transfer-Encoding: chunked` and gains a
                // `content-length`, which a response keeping all its hop-by-hop headers writes.
                if headers.iter().all(|(k, _)| !k.eq_ignore_ascii_case("content-length")) {
                    headers.retain(|(k, v)| !(k.eq_ignore_ascii_case("transfer-encoding") && v.trim().eq_ignore_ascii_case("chunked")));
                    headers.push(("content-length".into(), body.len().to_string()));
                }
                body
            }) {
                Err(Error::TooLarge(content)) => {
                    // The aggregator drops `Transfer-Encoding` from the message it reports.
                    let kept: Vec<String> = headers.iter().filter(|(k, _)| !k.eq_ignore_ascii_case("transfer-encoding")).map(|(k, v)| format!("{k}: {v}")).collect();
                    return Err(Error::TooLarge(format!(
                        "shaded_package.io.netty.handler.codec.http.TooLongHttpContentException: Response entity too large: HttpObjectAggregator$AggregatedFullHttpResponse(decodeResult: success, version: HTTP/1.1, content: {content})\nHTTP/1.1 {status} {reason}\n{}",
                        kept.join("\n")
                    )));
                }
                other => other?,
            }
        } else if let Some(n) = header("content-length").and_then(|l| l.trim().parse::<usize>().ok()) {
            if n > raw_max {
                let all: Vec<String> = headers.iter().map(|(k, v)| format!("{k}: {v}")).collect();
                return Err(Error::TooLarge(format!(
                    "shaded_package.io.netty.handler.codec.http.TooLongHttpContentException: Response entity too large: DefaultHttpResponse(decodeResult: success, version: HTTP/1.1)\nHTTP/1.1 {status} {reason}\n{}",
                    all.join("\n")
                )));
            }
            while buf.len() < n {
                if fill(stream, &mut buf).await? == 0 {
                    return Err(Error::Protocol);
                }
            }
            buf.split_to(n).freeze()
        } else {
            delimited = false;
            while fill(stream, &mut buf).await? > 0 {}
            buf.split().freeze()
        };
        let reusable = http11 && delimited && status != 101 && buf.is_empty();
        let body = match decoded {
            None => body,
            Some((mut decoder, decoded_headers)) => {
                // Each content the decoder is given (a chunk, or a fixed-length body, in pieces of at most
                // `maxChunkSize` 8192) that decodes to something is one component of the aggregated content, which
                // may not grow past `maxResponseBodySize`. A content that cannot be decoded fails the exchange, and
                // the channel is closed.
                if chunk_sizes.is_empty() {
                    chunk_sizes.push(body.len());
                }
                let (mut decoded, mut components, mut at) = (Vec::new(), 0, 0);
                for size in chunk_sizes {
                    for piece in body[at..at + size].chunks(8192) {
                        for more in decoder.push_pieces(piece, max_body.saturating_sub(decoded.len())).map_err(Error::Decode)? {
                            if decoded.len() + more.len() > max_body {
                                let kept: Vec<String> = decoded_headers.iter().map(|(k, v)| format!("{k}: {v}")).collect();
                                let n = decoded.len();
                                return Err(Error::TooLarge(format!(
                                    "shaded_package.io.netty.handler.codec.http.TooLongHttpContentException: Response entity too large: HttpObjectAggregator$AggregatedFullHttpResponse(decodeResult: success, version: HTTP/1.1, content: CompositeByteBuf(ridx: 0, widx: {n}, cap: {n}, components={components}))\nHTTP/1.1 {status} {reason}\n{}",
                                    kept.join("\n")
                                )));
                            }
                            decoded.extend_from_slice(&more);
                            components += 1;
                        }
                    }
                    at += size;
                }
                let body = decoded;
                headers = decoded_headers;
                decoding::Decoder::finish_headers(&mut headers, body.len());
                Bytes::from(body)
            }
        };
        headers.extend(chunked_trailers);
        Ok((Upstream { status, reason, headers, body, stream: None, ..Default::default() }, reusable))
    }
}

/// A chunked body; past `max` bytes `TooLarge` carries the aggregated buffer as Netty describes it. `(counted,
/// max_header)`: the head's header bytes and `maxHeaderSize`, which the trailer lines count on top of (upstream
/// a78886b4d, after 8.0.0).
/// Also returns each chunk's size.
async fn read_chunked<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut BytesMut, max: usize, (mut counted, max_header): (usize, usize)) -> Result<(Bytes, Vec<(String, String)>, Vec<usize>), Error> {
    let mut body = BytesMut::new();
    let mut chunks = 0;
    let mut sizes = Vec::new();
    async fn line<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut BytesMut) -> Result<String, Error> {
        loop {
            if let Some(i) = buf.windows(2).position(|w| w == b"\r\n") {
                let line = String::from_utf8_lossy(&buf[..i]).into_owned();
                buf.advance(i + 2);
                return Ok(line);
            }
            if fill(stream, buf).await? == 0 {
                return Err(Error::Protocol);
            }
        }
    }
    loop {
        let size_line = line(stream, buf).await?;
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16).map_err(|_| chunk_size_failure(&size_line))?;
        if size == 0 {
            // The trailer section, up to its blank line (`LastHttpContent.trailingHeaders`).
            let mut trailers = Vec::new();
            loop {
                let trailer = line(stream, buf).await?;
                if trailer.is_empty() {
                    return Ok((body.freeze(), trailers, sizes));
                }
                counted += trailer.len();
                if counted > max_header {
                    return Err(header_limit(HEADERS_AND_TRAILERS, max_header));
                }
                if let Some((name, value)) = trailer.split_once(':') {
                    trailers.push((name.trim().to_string(), value.trim().to_string()));
                }
            }
        }
        if body.len() + size > max {
            let n = body.len();
            return Err(Error::TooLarge(format!("CompositeByteBuf(ridx: 0, widx: {n}, cap: {n}, components={})", chunks + 1)));
        }
        while buf.len() < size + 2 {
            if fill(stream, buf).await? == 0 {
                return Err(Error::Protocol);
            }
        }
        chunks += 1;
        sizes.push(size);
        body.extend_from_slice(&buf[..size]);
        buf.advance(size + 2);
    }
}

/// `HttpObjectDecoder.getChunkSize` refusing a chunk-size line: the forward fails with it (upstream c990e4a20, after
/// 8.0.0), `NumberFormatException: Invalid character in chunk size` for a character that is no hex digit,
/// `Empty chunk size` when the size is missing before its extension, `Chunk size overflow: N` past `int`; a line of
/// whitespace alone is `NumberFormatException` with no message.
fn chunk_size_failure(line: &str) -> Error {
    let digits = line.trim_start_matches([' ', '\t']);
    if digits.is_empty() {
        return Error::Undecodable("NumberFormatException".into());
    }
    let mut size: u64 = 0;
    for (i, c) in digits.char_indices() {
        let Some(digit) = c.to_digit(16) else {
            if c == ';' || c.is_ascii_control() || c.is_ascii_whitespace() {
                if i == 0 {
                    return Error::Undecodable(fault("NumberFormatException", "Empty chunk size"));
                }
                break;
            }
            return Error::Undecodable(fault("NumberFormatException", "Invalid character in chunk size"));
        };
        size = size * 16 + u64::from(digit);
        if size > i32::MAX as u64 {
            return Error::Undecodable(fault("NumberFormatException", &format!("Chunk size overflow: {size}")));
        }
    }
    Error::Protocol
}

/// The outbound TLS configuration: HTTP/1.1 only, the server certificate checked as `config`'s
/// `forwardProxyTLSX509CertificatesTrustManagerType` says (none when `config` is `None`), `identity` offered to an
/// upstream that asks for a client certificate. One configuration per identity and trust, keyed by its leaf
/// certificate and fallback flag. `host` decides only whether the ClientHello names it ([`jdk_sni`]).
fn tls_config(config: Option<&Config>, identity: Option<ForwardIdentity>, host: &str) -> Arc<rustls::ClientConfig> {
    tls_config_alpn(config, identity, false, jdk_sni(host))
}

/// Whether the JDK's client puts a `server_name` extension naming `host` in its ClientHello
/// (`sun.security.ssl.Utilities.rawToSNIHostName`, the default `SSLParameters` server names): one trailing dot
/// dropped, then only a name with a dot past its first character that is no IP literal. A dotless name such as
/// `localhost` goes without SNI; rustls leaves IP addresses out itself. The one home of this rule: the
/// JWKS fetch (`src/jwks.rs`) and the broker dials (`asyncapi::tls::handshake`, [`crate::asyncapi::tls::Sni::Jdk`]) call
/// it too.
pub(crate) fn jdk_sni(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    host.find('.').is_some_and(|dot| dot > 0) && !host.ends_with('.') && host.parse::<std::net::IpAddr>().is_err()
}

/// The `JVM` trust manager's roots: `lib/security/cacerts` of the oracle image's JDK
/// (`/usr/lib/jvm/temurin25-trimmed`), exported with `keytool -list -rfc`.
pub(crate) const JDK_CACERTS: &str = include_str!("tls/jdk-cacerts.pem");

/// The TLS configuration of a plain `java.net.HttpURLConnection` (`Route::Direct`): the JDK's default trust manager,
/// so the `cacerts` roots alone (not MockServer's own certificate authority) and the host name always checked.
fn jdk_tls_config(sni: bool) -> Arc<rustls::ClientConfig> {
    static CONFIGS: [OnceLock<Arc<rustls::ClientConfig>>; 2] = [OnceLock::new(), OnceLock::new()];
    CONFIGS[sni as usize]
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut store = rustls::RootCertStore::empty();
            store.add_parsable_certificates(crate::tls::client_cert::pem_chain(JDK_CACERTS).into_iter().map(CertificateDer::from));
            let verifier = Arc::new(ValidatingServerCertificate { provider: provider.clone(), roots: Arc::new(store), exact: Vec::new() });
            let mut config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("ring supports the default protocol versions")
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            config.enable_sni = sni;
            Arc::new(config)
        })
        .clone()
}

/// The `SSLHandshakeException` message the JDK gives a handshake `error` of [`jdk_tls_config`]: an untrusted
/// issuer is read off the oracle (a peer whose certificate no `cacerts` root vouches for).
fn jdk_handshake_failure(error: &std::io::Error) -> Error {
    match error.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()) {
        Some(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)) => Error::Jdk(
            "(certificate_unknown) PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target".into(),
        ),
        _ => Error::Tls,
    }
}

/// What the forwarding client trusts: `ANY` (nothing is checked), or the certificates `JVM` / `CUSTOM` accept.
enum Trust {
    Any,
    /// The roots, and the certificates that are trusted as themselves (a trusted leaf is no issuer).
    Validating { roots: Vec<CertificateDer<'static>>, jvm: bool, exact: Vec<CertificateDer<'static>> },
}

impl Trust {
    /// `createClientSslContext`'s trust manager: `ANY`; `JVM`: the JVM's roots, MockServer's own certificate
    /// authority and leaf; `CUSTOM`: MockServer's own certificates and those of `forwardProxyTLSCustomTrustX509Certificates`.
    fn of(config: &Config) -> Trust {
        let kind = config.property("forwardProxyTLSX509CertificatesTrustManagerType").unwrap_or_default();
        let jvm = match kind.trim().to_ascii_uppercase().as_str() {
            "JVM" => true,
            "CUSTOM" => false,
            _ => return Trust::Any,
        };
        let mut exact: Vec<CertificateDer<'static>> = crate::tls::certificate_authority_der(config).into_iter().map(CertificateDer::from).collect();
        if !jvm {
            // `customCAX509TrustCertificates` reads the file through `x509ChainFromPEMFile`, a byte stream into
            // `CertificateFactory.generateCertificates`: PEM blocks, DER, a PKCS#7 bundle, indefinite lengths.
            let path = config.property("forwardProxyTLSCustomTrustX509Certificates").unwrap_or_default();
            let bytes = crate::class_path::read_or_file(path.trim()).unwrap_or_default();
            let certificates = crate::tls::x509::generate_certificates(&bytes).unwrap_or_default();
            exact.extend(certificates.into_iter().map(|c| CertificateDer::from(c.der)));
        }
        Trust::Validating { roots: exact.clone(), jvm, exact }
    }

    fn key(&self) -> Vec<u8> {
        match self {
            Trust::Any => vec![0],
            Trust::Validating { jvm, exact, .. } => {
                let mut key = vec![1, *jvm as u8];
                for cert in exact {
                    key.extend_from_slice(&(cert.len() as u32).to_be_bytes());
                    key.extend_from_slice(cert);
                }
                key
            }
        }
    }
}

/// `JVM` / `CUSTOM`: a PKIX check of the upstream's chain against the trusted certificates, then (always, whatever
/// `forwardProxyTLSHostnameVerificationEnabled` says: the oracle's endpoint identification is not switched off by
/// it) the host name against the certificate's subject alternative names.
#[derive(Debug)]
struct ValidatingServerCertificate {
    provider: Arc<rustls::crypto::CryptoProvider>,
    roots: Arc<rustls::RootCertStore>,
    exact: Vec<CertificateDer<'static>>,
}

impl ServerCertVerifier for ValidatingServerCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
        if !self.exact.iter().any(|trusted| trusted.as_ref() == end_entity.as_ref()) {
            rustls::client::verify_server_cert_signed_by_trust_anchor(&cert, &self.roots, intermediates, now, self.provider.signature_verification_algorithms.all)?;
        }
        rustls::client::verify_server_name(&cert, server_name)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// [`tls_config`], offering `h2` before `http/1.1` when `h2`, naming the host in the ClientHello when `sni`.
fn tls_config_alpn(config: Option<&Config>, identity: Option<ForwardIdentity>, h2: bool, sni: bool) -> Arc<rustls::ClientConfig> {
    static CONFIGS: OnceLock<Mutex<HashMap<Vec<u8>, Arc<rustls::ClientConfig>>>> = OnceLock::new();
    let trust = config.map(Trust::of).unwrap_or(Trust::Any);
    let mut key = identity
        .as_ref()
        .and_then(|i| i.key.end_entity_cert().ok().map(|c| c.to_vec()))
        .unwrap_or_default();
    key.push(h2 as u8);
    key.push(sni as u8);
    key.extend(trust.key());
    let configs = CONFIGS.get_or_init(Default::default);
    if let Some(found) = configs.lock().get(&key) {
        return found.clone();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier: Arc<dyn ServerCertVerifier> = match trust {
        Trust::Any => Arc::new(AnyServerCertificate(provider.clone())),
        Trust::Validating { roots, jvm, exact } => {
            let mut store = rustls::RootCertStore::empty();
            if jvm {
                // The oracle's JVM roots: the `cacerts` of its Temurin 25 image (118 certificates).
                store.add_parsable_certificates(crate::tls::client_cert::pem_chain(JDK_CACERTS).into_iter().map(CertificateDer::from));
            }
            store.add_parsable_certificates(roots);
            Arc::new(ValidatingServerCertificate { provider: provider.clone(), roots: Arc::new(store), exact })
        }
    };
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = match identity {
        Some(identity) => builder.with_client_cert_resolver(Arc::new(Identity(identity))),
        None => builder.with_no_client_auth(),
    };
    // `createClientSslContext` configures ALPN only for an HTTP/2 request: an HTTP/1.1 forward, the binary proxy and
    // the WebSocket relay offer none (8.0.0's server logs no `found ALPN protocol` for them).
    config.alpn_protocols = if h2 { vec![b"h2".to_vec(), b"http/1.1".to_vec()] } else { Vec::new() };
    config.enable_sni = sni;
    let config = Arc::new(config);
    let mut configs = configs.lock();
    // Rotated forward-proxy keys would otherwise pile up.
    if configs.len() > 64 {
        configs.clear();
    }
    configs.insert(key, config.clone());
    config
}

/// Netty's client `keyManager` (the JDK's `SunX509KeyManagerImpl.chooseClientAlias`): its one certificate to an
/// upstream that requests one naming no issuers (MockServer's own server, trusting any certificate, names none), or
/// naming the issuer of some certificate of the chain; otherwise none (scenarios `tls_data_plane_chain_*_foreign_withheld`).
#[derive(Debug)]
struct Identity(ForwardIdentity);

impl ResolvesClientCert for Identity {
    fn resolve(&self, issuers: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        if issuers.is_empty() {
            return Some(self.0.key.clone());
        }
        // A requested issuer is an X.500 `Name`, with its outer SEQUENCE or (as rustls may hand it on) without.
        let named = |name: &[u8]| issuers.iter().any(|&issuer| issuer == name || name.get(der_header_len(name)..) == Some(issuer));
        let chain_issuers = self.0.key.cert.iter().filter_map(|c| x509_parser::parse_x509_certificate(c).ok().map(|(_, c)| c.issuer().as_raw().to_vec()));
        chain_issuers.into_iter().any(|name| named(&name)).then(|| self.0.key.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// The length of the tag and length octets of the DER element `der` begins with (its whole length when malformed).
fn der_header_len(der: &[u8]) -> usize {
    match der.get(1) {
        Some(&n) if n < 0x80 => 2,
        Some(&n) => 2 + (n & 0x7f) as usize,
        None => der.len(),
    }
}

/// `ForwardProxyTLSX509CertificatesTrustManager.ANY`: signatures are still checked, the chain is not.
#[derive(Debug)]
struct AnyServerCertificate(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyServerCertificate {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// `HttpContentDecompressor` in the forwarding client's pipeline (`HttpClientInitializer`, before the aggregator):
/// an upstream response in a coding Netty decodes reaches MockServer decoded, without its `Content-Encoding`.
pub(crate) mod decoding {
    const DECOMPRESSION_EXCEPTION: &str = "shaded_package.io.netty.handler.codec.compression.DecompressionException";

    fn failure(message: impl std::fmt::Display) -> String {
        format!("{DECOMPRESSION_EXCEPTION}: {message}")
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Coding {
        Gzip,
        Deflate,
        Snappy,
        Zstd,
    }

    /// `HttpContentDecoder.decode` on a message head: the first `Content-Encoding` value trimmed, else the first
    /// `Transfer-Encoding` token, names the coding; `newContentDecoder` knows gzip/x-gzip, deflate/x-deflate, snappy
    /// and zstd, ignoring case (`br` is not there: Brotli is not available in the oracle). Anything else, a list of
    /// codings included, passes through untouched.
    fn coding(headers: &[(String, String)]) -> Option<Coding> {
        let first = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str());
        let name = match first("content-encoding") {
            Some(encoding) => encoding.trim(),
            None => first("transfer-encoding")?.split(',').next().unwrap_or_default().trim(),
        };
        match name.to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Some(Coding::Gzip),
            "deflate" | "x-deflate" => Some(Coding::Deflate),
            "snappy" => Some(Coding::Snappy),
            "zstd" => Some(Coding::Zstd),
            _ => None,
        }
    }

    /// `HttpContentDecoder.decode`'s edits to the head: the decoded length is not the received one, so
    /// `Content-Length` goes and the message becomes chunked (`set`, so other transfer codings go too); the coding is
    /// removed (its target is identity). `aggregated`: `HttpObjectAggregator` then drops the values that are exactly
    /// `chunked` (`HttpUtil.setTransferEncodingChunked(m, false)`).
    fn edit(headers: &mut Vec<(String, String)>, aggregated: bool) {
        if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("transfer-encoding"));
            headers.push(("transfer-encoding".into(), "chunked".into()));
        }
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-encoding"));
        if aggregated {
            headers.retain(|(k, v)| !(k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked")));
        }
    }

    /// A response body decoder, fed the content as it arrives (`EmbeddedChannel.writeInbound`); an error is the
    /// exception's `toString`.
    pub struct Decoder {
        state: State,
        pending: Vec<u8>,
    }

    /// `BoundedZstdHttpContentDecompressor.ZSTD_MAX_ALLOCATION`: the largest buffer a zstd decoder fills before it
    /// passes it on.
    const ZSTD_MAX_ALLOCATION: usize = 64 * 1024;

    /// `ZstdDecoder.DEFAULT_MAX_WINDOW_LOG`, set on its stream (`setLongMax`): a frame declaring a larger window is
    /// refused before anything is allocated for it.
    const ZSTD_MAX_WINDOW_LOG: u32 = 27;

    enum State {
        /// `ZstdDecoder(ZSTD_MAX_ALLOCATION)` over zstd-jni's `ZstdInputStreamNoFinalizer` in continuous mode: libzstd's
        /// streaming decoder, frames back to back, a truncated frame the end of the content rather than an error. Its
        /// memory is the frame's window, never the content size a frame header declares.
        Zstd(Box<zstd::zstd_safe::DCtx<'static>>),
        GzipHeader,
        GzipBody(Box<flate2::Decompress>, flate2::Crc),
        GzipFooter(flate2::Crc, u64),
        /// `ZlibWrapper.ZLIB_OR_NONE`: zlib when the first two bytes look like a zlib header, else raw deflate.
        DeflateDecide,
        Deflate(Box<flate2::Decompress>),
        Snappy { started: bool },
        /// The stream has ended: whatever follows is skipped.
        Finished,
    }

    impl Decoder {
        /// The decoder for this head, if any; the head's headers are edited as `HttpContentDecoder` and then
        /// `HttpObjectAggregator` leave them (`aggregated`: the body is collected whole, which gains a `content-length`
        /// set by [`Decoder::finish_headers`]). Errors when the decoder cannot be created.
        pub fn for_head(headers: &mut Vec<(String, String)>, aggregated: bool) -> Result<Option<Decoder>, String> {
            let Some(coding) = coding(headers) else { return Ok(None) };
            let state = match coding {
                Coding::Gzip => State::GzipHeader,
                Coding::Deflate => State::DeflateDecide,
                Coding::Snappy => State::Snappy { started: false },
                Coding::Zstd => {
                    let mut context = zstd::zstd_safe::DCtx::create();
                    context.set_parameter(zstd::zstd_safe::DParameter::WindowLogMax(ZSTD_MAX_WINDOW_LOG)).map_err(zstd_failure)?;
                    State::Zstd(Box::new(context))
                }
            };
            edit(headers, aggregated);
            Ok(Some(Decoder { state, pending: Vec::new() }))
        }

        /// `finishAggregation`: the aggregated message has no `content-length` (the decoder removed it), so it gets
        /// the decoded one, at the end.
        pub fn finish_headers(headers: &mut Vec<(String, String)>, length: usize) {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
            headers.push(("content-length".into(), length.to_string()));
        }

        /// The whole body at once.
        #[cfg(test)]
        pub fn decode_all(mut self, body: &[u8]) -> Result<Vec<u8>, String> {
            self.push(body)
        }

        /// Decodes what `input` completes; input the coding needs more of waits for the next call. A body that ends
        /// early (a truncated stream) is not an error: what was decoded is all there is. The tests' entry; the
        /// server's readers take [`Decoder::push_pieces`].
        #[cfg(test)]
        pub fn push(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
            Ok(self.push_pieces(input, usize::MAX)?.concat())
        }

        /// `Decoder::push` as the buffers the decoder passes on, each one component of an aggregated message: zstd's
        /// are [`ZSTD_MAX_ALLOCATION`] bytes each but the last; the other codings pass on one per content. zstd stops
        /// decoding once its buffers hold more than `cap` bytes, keeping the rest of the input for the next call, so a
        /// few bytes of input never expand much past what the caller can take.
        pub fn push_pieces(&mut self, input: &[u8], cap: usize) -> Result<Vec<Vec<u8>>, String> {
            if let State::Zstd(context) = &mut self.state {
                self.pending.extend_from_slice(input);
                let decoded = zstd_decode(context, &self.pending, cap);
                return match decoded {
                    Ok((pieces, consumed)) => {
                        self.pending.drain(..consumed);
                        Ok(pieces)
                    }
                    // `ZstdDecoder`: `CORRUPTED`, whatever follows is skipped.
                    Err(failure) => {
                        self.state = State::Finished;
                        self.pending.clear();
                        Err(failure)
                    }
                };
            }
            let out = self.push_whole(input)?;
            Ok(if out.is_empty() { Vec::new() } else { vec![out] })
        }

        fn push_whole(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
            let mut out = Vec::new();
            if matches!(self.state, State::Finished) {
                return Ok(out);
            }
            self.pending.extend_from_slice(input);
            loop {
                let progressed = match &mut self.state {
                    State::Zstd(_) => false,
                    State::Finished => {
                        self.pending.clear();
                        false
                    }
                    State::GzipHeader => match gzip_header(&self.pending)? {
                        Some(length) => {
                            self.pending.drain(..length);
                            self.state = State::GzipBody(Box::new(flate2::Decompress::new(false)), flate2::Crc::new());
                            true
                        }
                        None => false,
                    },
                    State::GzipBody(inflater, crc) => {
                        let start = out.len();
                        let (consumed, ended) = inflate(inflater, &self.pending, &mut out)?;
                        crc.update(&out[start..]);
                        self.pending.drain(..consumed);
                        if ended {
                            let total = inflater.total_out();
                            let crc = std::mem::replace(crc, flate2::Crc::new());
                            self.state = State::GzipFooter(crc, total);
                            true
                        } else {
                            false
                        }
                    }
                    State::GzipFooter(crc, total) => {
                        if self.pending.len() < 8 {
                            false
                        } else {
                            let expected = u32::from_le_bytes(self.pending[..4].try_into().unwrap_or_default());
                            if expected != crc.sum() {
                                return Err(failure(format!("CRC value mismatch. Expected: {expected}, Got: {}", crc.sum())));
                            }
                            let size = i32::from_le_bytes(self.pending[4..8].try_into().unwrap_or_default());
                            let got = *total as i32;
                            if size != got {
                                return Err(failure(format!("Number of bytes mismatch. Expected: {size}, Got: {got}")));
                            }
                            self.state = State::Finished;
                            true
                        }
                    }
                    State::DeflateDecide => {
                        if self.pending.len() < 2 {
                            false
                        } else {
                            // `looksLikeZlib(in.getShort(...))`, Java's signed short arithmetic.
                            let header = i16::from_be_bytes([self.pending[0], self.pending[1]]);
                            let zlib = (header & 0x7800) == 0x7800 && header % 31 == 0;
                            self.state = State::Deflate(Box::new(flate2::Decompress::new(zlib)));
                            true
                        }
                    }
                    State::Deflate(inflater) => {
                        let (consumed, ended) = inflate(inflater, &self.pending, &mut out)?;
                        self.pending.drain(..consumed);
                        if ended {
                            self.state = State::Finished;
                        }
                        ended
                    }
                    State::Snappy { started } => match snappy_chunk(&self.pending, started, &mut out)? {
                        Some(length) => {
                            self.pending.drain(..length);
                            true
                        }
                        None => false,
                    },
                };
                if !progressed {
                    return Ok(out);
                }
            }
        }
    }

    /// `ZstdDecoder.decode` wrapping zstd-jni's `ZstdIOException`, whose message is libzstd's error name.
    fn zstd_failure(code: usize) -> String {
        failure(format!("com.github.luben.zstd.ZstdIOException: {}", zstd::zstd_safe::get_error_name(code)))
    }

    /// `ZstdDecoder.decode` with `maximumAllocationSize` [`ZSTD_MAX_ALLOCATION`]: `input` through libzstd's streaming
    /// decoder into buffers of at most that size, each passed on once full, the last when the decoder has nothing more
    /// to give; stops early once the buffers hold more than `cap` bytes. The buffers and how much of `input` was used.
    fn zstd_decode(context: &mut zstd::zstd_safe::DCtx<'static>, input: &[u8], cap: usize) -> Result<(Vec<Vec<u8>>, usize), String> {
        use zstd::zstd_safe::{InBuffer, OutBuffer};
        let (mut pieces, mut total, mut used) = (Vec::new(), 0usize, 0usize);
        let mut piece = vec![0u8; ZSTD_MAX_ALLOCATION];
        let mut filled = 0;
        loop {
            let mut source = InBuffer::around(&input[used..]);
            let mut sink = OutBuffer::around_pos(&mut piece[..], filled);
            context.decompress_stream(&mut sink, &mut source).map_err(zstd_failure)?;
            let produced = sink.pos() - filled;
            filled = sink.pos();
            let consumed = source.pos();
            used += consumed;
            total += produced;
            if filled == ZSTD_MAX_ALLOCATION {
                pieces.push(std::mem::replace(&mut piece, vec![0u8; ZSTD_MAX_ALLOCATION]));
                filled = 0;
                if total > cap {
                    return Ok((pieces, used));
                }
                continue;
            }
            // room left in the buffer and nothing more came out: the decoder needs more input
            if produced == 0 && (consumed == 0 || used == input.len()) {
                break;
            }
        }
        if filled > 0 {
            piece.truncate(filled);
            pieces.push(piece);
        }
        Ok((pieces, used))
    }

    /// `JdkZlibDecoder.readGZIPHeader`: the header's length once all of it is there.
    fn gzip_header(input: &[u8]) -> Result<Option<usize>, String> {
        if input.len() < 10 {
            return Ok(None);
        }
        if input[0] != 0x1f || input[1] != 0x8b {
            return Err(failure("Input is not in the GZIP format"));
        }
        if input[2] != 8 {
            return Err(failure(format!("Unsupported compression method {} in the GZIP header", input[2])));
        }
        let flags = input[3];
        if flags & 0xe0 != 0 {
            return Err(failure("Reserved flags are set in the GZIP header"));
        }
        let mut at = 10;
        if flags & 0x04 != 0 {
            if input.len() < at + 2 {
                return Ok(None);
            }
            let length = usize::from(input[at]) | usize::from(input[at + 1]) << 8;
            at += 2 + length;
            if input.len() < at {
                return Ok(None);
            }
        }
        for flag in [0x08, 0x10] {
            if flags & flag != 0 {
                match input[at..].iter().position(|b| *b == 0) {
                    Some(end) => at += end + 1,
                    None => return Ok(None),
                }
            }
        }
        if flags & 0x02 != 0 {
            if input.len() < at + 2 {
                return Ok(None);
            }
            let expected = u16::from(input[at]) | u16::from(input[at + 1]) << 8;
            let mut crc = flate2::Crc::new();
            crc.update(&input[..at]);
            let got = (crc.sum() & 0xffff) as u16;
            if expected != got {
                return Err(failure(format!("CRC16 value mismatch. Expected: {expected}, Got: {got}")));
            }
            at += 2;
        }
        Ok(Some(at))
    }

    /// `Inflater.inflate` until it needs input or the stream ends: (input consumed, ended).
    fn inflate(inflater: &mut flate2::Decompress, input: &[u8], out: &mut Vec<u8>) -> Result<(usize, bool), String> {
        let before = inflater.total_in();
        loop {
            let (consumed, produced) = (inflater.total_in(), inflater.total_out());
            out.reserve(16 * 1024);
            let status = inflater.decompress_vec(&input[(consumed - before) as usize..], out, flate2::FlushDecompress::None).map_err(|e| {
                if e.needs_dictionary().is_some() {
                    failure("decompression failure, unable to set dictionary as non was specified")
                } else {
                    failure("decompression failure")
                }
            })?;
            let used = (inflater.total_in() - before) as usize;
            if status == flate2::Status::StreamEnd {
                return Ok((used, true));
            }
            if inflater.total_in() == consumed && inflater.total_out() == produced {
                return Ok((used, false));
            }
        }
    }

    /// `SnappyFrameDecoder.decode` (checksums not validated): one whole chunk of `input`, its decoded data appended to
    /// `out`, or `None` until the chunk is complete.
    fn snappy_chunk(input: &[u8], started: &mut bool, out: &mut Vec<u8>) -> Result<Option<usize>, String> {
        if input.len() < 4 {
            return Ok(None);
        }
        let kind = input[0];
        let length = usize::from(input[1]) | usize::from(input[2]) << 8 | usize::from(input[3]) << 16;
        let whole = |out: &mut Vec<u8>, data: &[u8]| -> Option<usize> {
            out.extend_from_slice(data);
            Some(4 + length)
        };
        match kind {
            0xff => {
                if length != 6 {
                    return Err(failure(format!("Unexpected length of stream identifier: {length}")));
                }
                if input.len() < 10 {
                    return Ok(None);
                }
                if &input[4..10] != b"sNaPpY" {
                    return Err(failure("Unexpected stream identifier contents. Mismatched snappy protocol version?"));
                }
                *started = true;
                Ok(Some(10))
            }
            0x80..=0xfe => {
                if !*started {
                    return Err(failure("Received RESERVED_SKIPPABLE tag before STREAM_IDENTIFIER"));
                }
                Ok((input.len() >= 4 + length).then_some(4 + length))
            }
            0x01 => {
                if !*started {
                    return Err(failure("Received UNCOMPRESSED_DATA tag before STREAM_IDENTIFIER"));
                }
                if length > 65540 {
                    return Err(failure("Received UNCOMPRESSED_DATA larger than 65540 bytes"));
                }
                if length < 4 {
                    return Err(failure(format!("Received UNCOMPRESSED_DATA with invalid chunk length: {length}")));
                }
                if input.len() < 4 + length {
                    return Ok(None);
                }
                Ok(whole(out, &input[8..4 + length]))
            }
            0x00 => {
                if !*started {
                    return Err(failure("Received COMPRESSED_DATA tag before STREAM_IDENTIFIER"));
                }
                if length < 5 {
                    return Err(failure(format!("Received COMPRESSED_DATA with invalid chunk length: {length}")));
                }
                if input.len() < 4 + length {
                    return Ok(None);
                }
                let data = &input[8..4 + length];
                // `Snappy.getPreamble`, then the buffer it sizes (`alloc().buffer(preamble, 65536)`).
                let preamble = snappy_preamble(data)?.map_or(0, |(value, _)| value);
                if preamble > 65536 {
                    return Err(failure("Received COMPRESSED_DATA that contains uncompressed data that exceeds 65536 bytes"));
                }
                let decoded = snappy_block(data)?;
                Ok(whole(out, &decoded))
            }
            other => Err(failure(format!("Found reserved unskippable chunk type: 0x{other:x}"))),
        }
    }

    /// `Snappy.readPreamble`: the varint uncompressed length and its byte count; `None` when the input ends inside it
    /// (Netty reads that as 0).
    fn snappy_preamble(data: &[u8]) -> Result<Option<(usize, usize)>, String> {
        let mut length = 0usize;
        for (index, byte) in data.iter().enumerate() {
            length |= usize::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                return Ok(Some((length, index + 1)));
            }
            if index + 1 >= 4 {
                return Err(failure("Preamble is greater than 4 bytes"));
            }
        }
        Ok(None)
    }

    /// The `PooledDirectByteBuf` a compressed chunk decodes into (`alloc().buffer(preamble, 65536)`): what its
    /// capacity does as `Snappy.decode` writes, since a copy may only fill it and a literal grows it.
    struct SnappyOut {
        bytes: Vec<u8>,
        capacity: usize,
        /// The pooled allocation behind it (`PooledByteBuf.maxLength`): the preamble's size class, which a literal
        /// grows into before a new allocation.
        allocated: usize,
    }

    /// `ByteBuf.maxCapacity` of that buffer.
    const SNAPPY_MAX_CAPACITY: usize = 65536;

    impl SnappyOut {
        fn new(preamble: usize) -> SnappyOut {
            SnappyOut { bytes: Vec::new(), capacity: preamble, allocated: size_class(preamble) }
        }

        fn describe(&self, reader: usize) -> String {
            format!("PooledDirectByteBuf(ridx: {reader}, widx: {}, cap: {}/{SNAPPY_MAX_CAPACITY})", self.bytes.len(), self.capacity)
        }

        /// `writeBytes(in, length)` of a literal: `ensureWritable0`, growing into the allocation when it fits, else to
        /// `calculateNewCapacity` (64, doubled up to the need).
        fn literal(&mut self, data: &[u8]) -> Result<(), String> {
            let (writer, wanted) = (self.bytes.len(), data.len());
            if writer + wanted > self.capacity {
                if wanted > SNAPPY_MAX_CAPACITY - writer {
                    return Err(format!(
                        "shaded_package.io.netty.handler.codec.DecoderException: java.lang.IndexOutOfBoundsException: writerIndex({writer}) + minWritableBytes({wanted}) exceeds maxCapacity({SNAPPY_MAX_CAPACITY}): {}",
                        self.describe(0)
                    ));
                }
                if self.allocated - writer >= wanted {
                    self.capacity = self.allocated;
                } else {
                    let mut capacity = 64;
                    while capacity < writer + wanted {
                        capacity <<= 1;
                    }
                    self.capacity = capacity.min(SNAPPY_MAX_CAPACITY);
                    self.allocated = size_class(self.capacity);
                }
            }
            self.bytes.extend_from_slice(data);
            Ok(())
        }

        /// `out.readerIndex(start); out.readBytes(out, length)` of a copy: it may only fill the capacity there is.
        fn copy(&mut self, start: usize, length: usize) -> Result<(), String> {
            let writable = self.capacity - self.bytes.len();
            if length > writable {
                return Err(format!(
                    "shaded_package.io.netty.handler.codec.DecoderException: java.lang.IndexOutOfBoundsException: length({length}) exceeds dst.writableBytes({writable}) where dst is: {}",
                    self.describe(start)
                ));
            }
            for i in 0..length {
                self.bytes.push(self.bytes[start + i]);
            }
            Ok(())
        }
    }

    /// `SizeClasses` of Netty's pooled arena (`LOG2_QUANTUM` 4, four classes per doubling): the size a small or normal
    /// allocation of `size` bytes takes.
    fn size_class(size: usize) -> usize {
        if size <= 64 {
            return size.max(1).div_ceil(16) * 16;
        }
        let delta = 1usize << ((usize::BITS - (size - 1).leading_zeros() - 1) - 2);
        size.div_ceil(delta) * delta
    }

    /// Netty's `Snappy.decode` on one compressed chunk's data, fresh per chunk (`Snappy.reset`): the preamble only
    /// sizes the buffer; input that ends inside an element ends the output there (`NOT_ENOUGH_INPUT`); a copy is
    /// checked against what this chunk has written (`validateOffset`).
    fn snappy_block(data: &[u8]) -> Result<Vec<u8>, String> {
        let Some((preamble, mut at)) = snappy_preamble(data)? else { return Ok(Vec::new()) };
        if preamble == 0 {
            return Ok(Vec::new());
        }
        let mut out = SnappyOut::new(preamble);
        let le = |bytes: &[u8]| bytes.iter().rev().fold(0u32, |n, b| n << 8 | u32::from(*b));
        while at < data.len() {
            let tag = data[at];
            at += 1;
            let rest = &data[at..];
            if tag & 3 == 0 {
                // `decodeLiteral`: the length in the tag, or in the 1 to 4 bytes after it, plus one.
                let (length, header) = match (tag >> 2) & 63 {
                    n @ 60..=63 => {
                        let size = usize::from(n - 59);
                        if rest.len() < size {
                            break;
                        }
                        ((le(&rest[..size]) as i32).wrapping_add(1), size)
                    }
                    n => (i32::from(n) + 1, 0),
                };
                if length < 0 {
                    return Err(format!("shaded_package.io.netty.handler.codec.DecoderException: java.lang.IllegalArgumentException: minWritableBytes : {length} (expected: >= 0)"));
                }
                let length = length as usize;
                if rest.len() - header < length {
                    break;
                }
                out.literal(&rest[header..header + length])?;
                at += header + length;
                continue;
            }
            // `decodeCopyWith1ByteOffset`, `…2ByteOffset`, `…4ByteOffset`.
            let (length, offset, size) = match tag & 3 {
                1 => {
                    if rest.is_empty() {
                        break;
                    }
                    (4 + usize::from((tag & 0x1c) >> 2), (i64::from(tag & 0xe0) << 8 >> 5) | i64::from(rest[0]), 1)
                }
                2 => {
                    if rest.len() < 2 {
                        break;
                    }
                    (1 + usize::from((tag >> 2) & 63), i64::from(le(&rest[..2])), 2)
                }
                _ => {
                    if rest.len() < 4 {
                        break;
                    }
                    (1 + usize::from((tag >> 2) & 63), i64::from(le(&rest[..4]) as i32), 4)
                }
            };
            at += size;
            let written = out.bytes.len();
            if offset == 0 {
                return Err(failure("Offset is less than minimum permissible value"));
            }
            if offset < 0 {
                return Err(failure("Offset is greater than maximum value supported by this implementation"));
            }
            let offset = offset as usize;
            if offset > written {
                return Err(failure("Offset exceeds size of chunk"));
            }
            // The pattern is copied `offset` bytes at a time, then the remainder, each from `written - offset`.
            let start = written - offset;
            if offset < length {
                for _ in 0..length / offset {
                    out.copy(start, offset)?;
                }
                if length % offset != 0 {
                    out.copy(start, length % offset)?;
                }
            } else {
                out.copy(start, length)?;
            }
        }
        Ok(out.bytes)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Write;

        const TEXT: &[u8] = b"hello compressed world, hello compressed world";

        fn gzip(data: &[u8]) -> Vec<u8> {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }

        fn decoder(coding: &str) -> Decoder {
            let mut headers = vec![("Content-Encoding".to_string(), coding.to_string())];
            Decoder::for_head(&mut headers, true).unwrap().unwrap()
        }

        #[test]
        fn gzip_fed_byte_by_byte_decodes_like_the_whole() {
            let compressed = gzip(TEXT);
            let mut d = decoder("gzip");
            let mut out = Vec::new();
            for b in &compressed {
                out.extend(d.push(&[*b]).unwrap());
            }
            assert_eq!(out, TEXT);
            assert_eq!(decoder("x-gzip").decode_all(&compressed).unwrap(), TEXT);
        }

        #[test]
        fn gzip_failures_are_netty_messages() {
            assert_eq!(decoder("gzip").decode_all(b"not gzip at all").unwrap_err(), failure("Input is not in the GZIP format"));
            let mut bad_crc = gzip(TEXT);
            let n = bad_crc.len();
            bad_crc[n - 8] ^= 1;
            assert!(decoder("gzip").decode_all(&bad_crc).unwrap_err().contains("CRC value mismatch. Expected: "));
            let truncated = gzip(TEXT);
            assert_eq!(decoder("gzip").decode_all(&truncated[..20]).unwrap(), b"hello com");
        }

        #[test]
        fn deflate_with_and_without_a_zlib_wrapper() {
            let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            z.write_all(TEXT).unwrap();
            assert_eq!(decoder("deflate").decode_all(&z.finish().unwrap()).unwrap(), TEXT);
            let mut r = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            r.write_all(TEXT).unwrap();
            assert_eq!(decoder("x-deflate").decode_all(&r.finish().unwrap()).unwrap(), TEXT);
        }

        #[test]
        fn snappy_frames() {
            let mut framed = snap::write::FrameEncoder::new(Vec::new());
            framed.write_all(TEXT).unwrap();
            assert_eq!(decoder("snappy").decode_all(&framed.into_inner().unwrap()).unwrap(), TEXT);
        }

        #[test]
        fn heads_are_edited_as_the_decoder_and_aggregator_leave_them() {
            let mut headers = vec![
                ("Content-Type".to_string(), "text/plain".to_string()),
                ("Content-Encoding".to_string(), "GZIP".to_string()),
                ("Content-Encoding".to_string(), "identity".to_string()),
                ("Content-Length".to_string(), "47".to_string()),
            ];
            assert!(Decoder::for_head(&mut headers, true).unwrap().is_some());
            assert_eq!(headers, vec![("Content-Type".to_string(), "text/plain".to_string())]);
            let mut streamed = vec![("Content-Encoding".to_string(), "gzip".to_string()), ("Content-Length".to_string(), "47".to_string())];
            assert!(Decoder::for_head(&mut streamed, false).unwrap().is_some());
            assert_eq!(streamed, vec![("transfer-encoding".to_string(), "chunked".to_string())]);
            let mut other = vec![("Content-Encoding".to_string(), "gzip, identity".to_string())];
            assert!(Decoder::for_head(&mut other, true).unwrap().is_none());
            let mut te = vec![("Transfer-Encoding".to_string(), "gzip, chunked".to_string())];
            assert!(Decoder::for_head(&mut te, true).unwrap().is_some());
            let mut zstd = vec![("Content-Encoding".to_string(), "zstd".to_string()), ("Content-Length".to_string(), "9".to_string())];
            assert!(Decoder::for_head(&mut zstd, false).unwrap().is_some());
            assert_eq!(zstd, vec![("transfer-encoding".to_string(), "chunked".to_string())]);
        }

        // `ZstdResponseAllocationBoundIntegrationTest.DECLARES_TWO_GIB`: a frame header declaring 2^31 - 1 bytes of
        // content (1 KiB window) and one empty last raw block.
        const DECLARES_TWO_GIB: [u8; 17] = [0x28, 0xB5, 0x2F, 0xFD, 0xC0, 0x00, 0xFF, 0xFF, 0xFF, 0x7F, 0, 0, 0, 0, 0x01, 0x00, 0x00];

        /// `plain()` of the upstream tests: 300 KiB of letters.
        fn plain() -> Vec<u8> {
            (0..300 * 1024).map(|i: usize| b'a' + ((i * 7 + i / 1024) % 26) as u8).collect()
        }

        #[test]
        fn zstd_declared_size_is_never_allocated_and_decodes_to_nothing() {
            assert_eq!(decoder("zstd").decode_all(&DECLARES_TWO_GIB).unwrap(), b"");
            // a streamed body: the declaring frame, then one holding an event, fed as it might arrive
            let mut body = DECLARES_TWO_GIB.to_vec();
            body.extend(zstd::bulk::compress(b"data: hello\n\n", 3).unwrap());
            let mut d = decoder("ZSTD");
            let mut out = Vec::new();
            for piece in body.chunks(5) {
                out.extend(d.push(piece).unwrap());
            }
            assert_eq!(out, b"data: hello\n\n");
        }

        #[test]
        fn zstd_decodes_frames_byte_for_byte_in_bounded_pieces() {
            let plain = plain();
            let compressed = zstd::bulk::compress(&plain, 3).unwrap();
            assert_eq!(decoder("zstd").decode_all(&compressed).unwrap(), plain);
            // `ZstdDecoder(64 KiB)` passes each buffer on as soon as it is full
            let pieces = decoder("zstd").push_pieces(&compressed, usize::MAX).unwrap();
            assert_eq!(pieces.iter().map(Vec::len).collect::<Vec<_>>(), vec![65536, 65536, 65536, 65536, 45056]);
            // a cap stops decoding once passed, keeping the rest of the input for the next push
            let mut d = decoder("zstd");
            let first = d.push_pieces(&compressed, 100_000).unwrap();
            assert_eq!(first.iter().map(Vec::len).sum::<usize>(), 131072);
            let rest: Vec<u8> = d.push_pieces(&[], usize::MAX).unwrap().concat();
            assert_eq!([first.concat(), rest].concat(), plain);
        }

        #[test]
        fn zstd_streamed_output_is_not_held_back_until_the_frame_ends() {
            let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3).unwrap();
            encoder.write_all(b"data: one\n\n").unwrap();
            encoder.flush().unwrap();
            let flushed = encoder.get_ref().len();
            let mut d = decoder("zstd");
            assert_eq!(d.push(&encoder.get_ref()[..flushed]).unwrap(), b"data: one\n\n");
            encoder.write_all(b"data: two\n\n").unwrap();
            let all = encoder.finish().unwrap();
            assert_eq!(d.push(&all[flushed..]).unwrap(), b"data: two\n\n");
        }

        #[test]
        fn zstd_failures_are_zstd_jni_exceptions_and_a_truncated_frame_is_not_one() {
            let unknown = format!("{DECOMPRESSION_EXCEPTION}: com.github.luben.zstd.ZstdIOException: Unknown frame descriptor");
            assert_eq!(decoder("zstd").decode_all(b"not zstd at all").unwrap_err(), unknown);
            let compressed = zstd::bulk::compress(&plain(), 3).unwrap();
            assert_eq!(decoder("zstd").decode_all(&compressed[..compressed.len() / 2]).map(|d| d.len() < plain().len()), Ok(true));
            // a window over `ZstdDecoder.DEFAULT_MAX_WINDOW_LOG` (27): window descriptor 0x98, 2^(10 + 19) bytes
            let window = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x98, 0x01, 0x00, 0x00];
            let refused = format!("{DECOMPRESSION_EXCEPTION}: com.github.luben.zstd.ZstdIOException: Frame requires too much memory for decoding");
            assert_eq!(decoder("zstd").decode_all(&window).unwrap_err(), refused);
        }
    }
}

/// Ports of upstream's `HttpForwardConnectionPoolTest`. Netty's `EmbeddedChannel` becomes an in-memory duplex stream
/// whose far end (the "server") is kept by the test: dropping it is the server closing the connection, and a read
/// returning end-of-file is the pool having closed ours. Time is tokio's paused clock, so eviction is exact.
///
/// Not ported, because Rust's types rule them out: `shouldReturnNullKeyForNullAddress` and
/// `shouldRejectNullKeyAndNullChannel` (a key and a stream cannot be null here).
#[cfg(test)]
mod jdk_roots_tests {
    use super::*;

    /// The embedded `JVM` roots are the oracle image's `cacerts` (118 entries, `keytool -list`): every one parses as a
    /// trust anchor.
    #[test]
    fn jdk_cacerts_are_all_usable_trust_anchors() {
        let certificates = crate::tls::client_cert::pem_chain(JDK_CACERTS);
        assert_eq!(certificates.len(), 118);
        let mut store = rustls::RootCertStore::empty();
        let (added, ignored) = store.add_parsable_certificates(certificates.into_iter().map(CertificateDer::from));
        assert_eq!((added, ignored), (118, 0));
    }
}

/// `NoProxyHostsUtils.isHostOnNoProxyList` at the oracle's commit: names, `.suffix`/`*.suffix`, addresses by value.
#[cfg(test)]
mod no_proxy_tests {
    use super::host_on_no_proxy_list as listed;

    #[test]
    fn matches_names_suffixes_and_addresses_without_lookups() {
        assert!(listed("LocalHost:8080", "localhost"));
        assert!(listed("api.internal.corp", ".internal.corp") && listed("internal.corp", ".internal.corp"));
        assert!(listed("a.b.example.com", "*.example.com") && !listed("badexample.com", "*.example.com"));
        assert!(listed("[0:0:0:0:0:0:0:1]:1080", "::1") && listed("::1", "0:0:0:0:0:0:0:1"));
        assert!(listed("127.0.0.1", " other , 127.0.0.1 "));
        // an IP-address entry matches only a destination given as that address
        assert!(!listed("localhost", "127.0.0.1"));
        assert!(!listed("127.0.0.1", "localhost") && !listed("", "localhost") && !listed("localhost", " "));
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;
    use tokio::io::DuplexStream;

    const KEY: &str = "localhost:1080:false";
    const IDLE: Duration = Duration::from_millis(30_000);

    /// The server's end of a connection handed to the pool.
    struct Conn {
        peer: DuplexStream,
    }

    fn conn() -> (IdleConnection, Conn) {
        let (client, peer) = tokio::io::duplex(1024);
        (Box::new(client), Conn { peer })
    }

    impl Conn {
        /// Whether the pool has closed its end (the server end reads end-of-file).
        async fn closed_by_pool(&mut self) -> bool {
            let mut byte = [0u8; 1];
            matches!(tokio::time::timeout(Duration::from_millis(1), self.peer.read(&mut byte)).await, Ok(Ok(0)))
        }

        /// Whether `stream` is this connection: what it writes arrives at this end.
        async fn is_behind(&mut self, stream: &mut IdleConnection) -> bool {
            stream.write_all(b"x").await.unwrap();
            let mut byte = [0u8; 1];
            matches!(tokio::time::timeout(Duration::from_millis(1), self.peer.read(&mut byte)).await, Ok(Ok(1)))
        }
    }

    /// Lets the watcher tasks run.
    async fn settle() {
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }

    async fn advance(by: Duration) {
        tokio::time::advance(by).await;
        settle().await;
    }

    fn pool(max_idle: usize) -> ForwardPool {
        ForwardPool::new(max_idle, IDLE, false, 0)
    }

    // ---- key derivation ----

    #[test]
    fn should_build_key_from_host_port_and_secure_flag() {
        assert_eq!(ForwardPool::key_for("example.com", 8443, true, None), "example.com:8443:true");
        assert_eq!(ForwardPool::key_for("example.com", 8443, false, None), "example.com:8443:false");
    }

    #[test]
    fn should_distinguish_keys_by_port_and_secure_flag() {
        assert_ne!(ForwardPool::key_for("host", 1, false, None), ForwardPool::key_for("host", 2, false, None));
        assert_ne!(ForwardPool::key_for("host", 1, true, None), ForwardPool::key_for("host", 1, false, None));
    }

    // ---- reuse ----

    #[tokio::test(start_paused = true)]
    async fn should_reuse_released_channel_on_next_acquire_for_same_key() {
        let pool = pool(4);
        let (stream, mut server) = conn();
        assert!(pool.release(KEY, stream).is_ok(), "a still-active channel should be accepted into the pool");
        let mut again = pool.acquire(KEY).await.expect("pooled");
        assert!(server.is_behind(&mut again).await, "the same channel comes back");
    }

    #[tokio::test(start_paused = true)]
    async fn should_not_reuse_channel_for_a_different_key() {
        let pool = pool(4);
        let (stream, mut server) = conn();
        assert!(pool.release(KEY, stream).is_ok());
        assert!(pool.acquire("otherhost:1080:false").await.is_none(), "a channel pooled under one key is never handed to another");
        let mut again = pool.acquire(KEY).await.expect("the original key still has it");
        assert!(server.is_behind(&mut again).await);
    }

    #[tokio::test(start_paused = true)]
    async fn should_return_none_when_acquiring_from_unknown_or_empty_key() {
        let pool = pool(4);
        assert!(pool.acquire(KEY).await.is_none(), "never-seen key");
        let (stream, mut server) = conn();
        assert!(pool.release(KEY, stream).is_ok());
        let mut again = pool.acquire(KEY).await.expect("pooled");
        assert!(server.is_behind(&mut again).await);
        assert!(pool.acquire(KEY).await.is_none(), "draining the only pooled channel leaves nothing to acquire");
    }

    /// Upstream's `release` adds to the tail and `acquire` polls the head: the oldest idle connection first
    /// (first-in-first-out, as the class and its test show).
    #[tokio::test(start_paused = true)]
    async fn should_acquire_in_first_in_first_out_order() {
        let pool = pool(4);
        let (first, mut first_server) = conn();
        let (second, mut second_server) = conn();
        assert!(pool.release(KEY, first).is_ok());
        assert!(pool.release(KEY, second).is_ok());
        let mut a = pool.acquire(KEY).await.expect("first");
        let mut b = pool.acquire(KEY).await.expect("second");
        assert!(first_server.is_behind(&mut a).await);
        assert!(second_server.is_behind(&mut b).await);
        assert!(pool.acquire(KEY).await.is_none());
    }

    // ---- saturation ----

    #[tokio::test(start_paused = true)]
    async fn should_reject_release_when_key_is_saturated() {
        let pool = pool(2);
        let (one, _s1) = conn();
        let (two, _s2) = conn();
        assert!(pool.release(KEY, one).is_ok(), "1st within capacity");
        assert!(pool.release(KEY, two).is_ok(), "2nd within capacity");
        let (surplus, mut server) = conn();
        let mut rejected = pool.release(KEY, surplus).expect_err("3rd is over per-key capacity -> caller must close it");
        assert!(server.is_behind(&mut rejected).await, "the rejected channel was NOT closed by the pool (caller owns it)");
    }

    #[tokio::test(start_paused = true)]
    async fn should_saturate_independently_per_key() {
        let pool = pool(1);
        let (a1, _k1) = conn();
        let (a2, _k2) = conn();
        let (b1, _k3) = conn();
        assert!(pool.release("hostA:80:false", a1).is_ok());
        assert!(pool.release("hostA:80:false", a2).is_err(), "second under same key over capacity");
        assert!(pool.release("hostB:80:false", b1).is_ok(), "a different upstream key has its own capacity");
    }

    #[tokio::test(start_paused = true)]
    async fn should_treat_non_positive_capacity_as_at_least_one() {
        let pool = ForwardPool::new(0, IDLE, false, 0);
        let (one, _s1) = conn();
        let (two, _s2) = conn();
        assert!(pool.release(KEY, one).is_ok(), "at least one channel is always poolable");
        assert!(pool.release(KEY, two).is_err(), "second exceeds the clamped capacity of one");
    }

    // ---- stale / closed discard ----

    #[tokio::test(start_paused = true)]
    async fn should_reject_release_of_an_inactive_channel() {
        let pool = pool(4);
        let (stream, server) = conn();
        drop(server);
        assert!(pool.release(KEY, stream).is_err(), "a closed channel must not be accepted into the pool");
        assert!(pool.acquire(KEY).await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn should_discard_stale_channel_and_return_the_next_active_one() {
        let pool = pool(4);
        let (will_go_stale, stale_server) = conn();
        let (still_active, mut active_server) = conn();
        assert!(pool.release(KEY, will_go_stale).is_ok());
        assert!(pool.release(KEY, still_active).is_ok());
        drop(stale_server); // the server closes the first connection while it sits idle
        settle().await;
        let mut got = pool.acquire(KEY).await.expect("the still-active one");
        assert!(active_server.is_behind(&mut got).await, "acquire skips the stale head");
    }

    #[tokio::test(start_paused = true)]
    async fn should_return_none_when_all_pooled_channels_are_stale() {
        let pool = pool(4);
        let (one, s1) = conn();
        let (two, s2) = conn();
        assert!(pool.release(KEY, one).is_ok());
        assert!(pool.release(KEY, two).is_ok());
        drop(s1);
        drop(s2);
        settle().await;
        assert!(pool.acquire(KEY).await.is_none(), "a pool of only-stale channels yields nothing");
    }

    /// A server that writes to an idle connection unasked has left it in a state nothing can be reused on.
    #[tokio::test(start_paused = true)]
    async fn should_discard_a_channel_the_server_wrote_to_while_idle() {
        let pool = pool(4);
        let (stream, mut server) = conn();
        assert!(pool.release(KEY, stream).is_ok());
        server.peer.write_all(b"junk").await.unwrap();
        settle().await;
        assert!(pool.acquire(KEY).await.is_none());
    }

    // ---- idle eviction ----

    #[tokio::test(start_paused = true)]
    async fn should_evict_and_close_an_idle_channel_after_the_idle_timeout() {
        let pool = pool(4);
        let (stream, mut server) = conn();
        assert!(pool.release(KEY, stream).is_ok());
        assert!(!server.closed_by_pool().await, "channel is alive before the idle timeout elapses");
        advance(IDLE).await;
        assert!(server.closed_by_pool().await, "an idle channel is closed once the idle timeout elapses");
        assert!(pool.acquire(KEY).await.is_none(), "an evicted channel is no longer acquirable");
    }

    #[tokio::test(start_paused = true)]
    async fn should_not_evict_before_the_idle_timeout_elapses() {
        let pool = pool(4);
        let (stream, mut server) = conn();
        assert!(pool.release(KEY, stream).is_ok());
        advance(IDLE - Duration::from_millis(2)).await; // the helper's probe waits 1ms of paused time itself
        assert!(!server.closed_by_pool().await, "channel must survive until the full idle timeout");
        let mut got = pool.acquire(KEY).await.expect("still acquirable before eviction fires");
        assert!(server.is_behind(&mut got).await);
    }

    #[tokio::test(start_paused = true)]
    async fn should_cancel_idle_eviction_when_channel_is_re_acquired() {
        let pool = pool(4);
        let (stream, mut server) = conn();
        assert!(pool.release(KEY, stream).is_ok());
        let mut got = pool.acquire(KEY).await.expect("pooled");
        advance(IDLE * 2).await;
        assert!(server.is_behind(&mut got).await, "re-acquiring a channel cancels its pending idle eviction");
        assert!(!server.closed_by_pool().await);
    }

    #[tokio::test(start_paused = true)]
    async fn should_reschedule_eviction_on_each_release() {
        let pool = pool(4);
        let (stream, mut server) = conn();
        assert!(pool.release(KEY, stream).is_ok());
        advance(IDLE - Duration::from_millis(3)).await;
        let stream = pool.acquire(KEY).await.expect("re-acquired just before the timeout");
        // second lifecycle: a fresh eviction is scheduled relative to "now"
        assert!(pool.release(KEY, stream).is_ok());
        advance(IDLE - Duration::from_millis(3)).await;
        assert!(!server.closed_by_pool().await, "each release reschedules a fresh idle eviction");
        // crossing the rescheduled deadline finally evicts
        advance(Duration::from_millis(3)).await;
        assert!(server.closed_by_pool().await, "the rescheduled eviction fires once its own deadline passes");
    }

    #[tokio::test(start_paused = true)]
    async fn should_not_schedule_eviction_when_idle_timeout_is_non_positive() {
        let pool = ForwardPool::new(4, Duration::ZERO, false, 0);
        let (stream, mut server) = conn();
        assert!(pool.release(KEY, stream).is_ok());
        advance(Duration::from_secs(3600)).await;
        assert!(!server.closed_by_pool().await, "with eviction disabled the channel is retained indefinitely");
        let mut got = pool.acquire(KEY).await.expect("retained");
        assert!(server.is_behind(&mut got).await);
    }

    // ---- close-listener path ----

    #[tokio::test(start_paused = true)]
    async fn should_remove_channel_from_pool_when_it_closes_while_idle() {
        let pool = pool(4);
        let (stream, server) = conn();
        assert!(pool.release(KEY, stream).is_ok());
        drop(server);
        settle().await;
        assert!(pool.idle.lock().get(KEY).is_none(), "removed by the close watcher, not left for acquire");
        assert!(pool.acquire(KEY).await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn should_remain_consistent_after_many_release_reuse_cycles_then_close() {
        let pool = pool(4);
        let (mut stream, server) = conn();
        for _ in 0..5 {
            assert!(pool.release(KEY, stream).is_ok());
            stream = pool.acquire(KEY).await.expect("reused");
        }
        assert!(pool.release(KEY, stream).is_ok());
        drop(server);
        settle().await;
        assert!(pool.acquire(KEY).await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn should_not_double_remove_when_acquired_channel_later_closes() {
        let pool = pool(4);
        let (stream, server) = conn();
        assert!(pool.release(KEY, stream).is_ok());
        let _in_use = pool.acquire(KEY).await.expect("pooled");
        drop(server);
        settle().await;
        assert!(pool.acquire(KEY).await.is_none(), "the pool stays consistent and empty for the key");
    }

    // ---- keep-warm retention (opt-in; default off) ----

    #[tokio::test(start_paused = true)]
    async fn should_close_surplus_at_max_idle_when_keep_alive_off() {
        let pool = ForwardPool::new(2, IDLE, false, 2000);
        let (one, _s1) = conn();
        let (two, _s2) = conn();
        assert!(pool.release(KEY, one).is_ok());
        assert!(pool.release(KEY, two).is_ok());
        let (surplus, mut server) = conn();
        let mut rejected = pool.release(KEY, surplus).expect_err("with keep-warm OFF the 3rd is over maxIdle");
        assert!(server.is_behind(&mut rejected).await, "rejected surplus is left to the caller");
    }

    #[tokio::test(start_paused = true)]
    async fn should_retain_beyond_max_idle_up_to_max_total_when_keep_alive_on() {
        let pool = ForwardPool::new(2, IDLE, true, 5);
        let mut servers = Vec::new();
        for i in 0..5 {
            let (stream, server) = conn();
            servers.push(server);
            assert!(pool.release(KEY, stream).is_ok(), "channel {i} retained (would have been closed at maxIdle=2 with keep-warm off)");
        }
        let (over_cap, mut server) = conn();
        let mut rejected = pool.release(KEY, over_cap).expect_err("over maxTotal=5 the warm set is bounded");
        assert!(server.is_behind(&mut rejected).await);
        for i in 0..5 {
            assert!(pool.acquire(KEY).await.is_some(), "retained warm channel {i} is reused");
        }
        assert!(pool.acquire(KEY).await.is_none(), "warm set fully drained after five reuses");
    }

    #[tokio::test(start_paused = true)]
    async fn should_simulate_fast_turnover_reusing_warm_set_without_churn_when_keep_alive_on() {
        let concurrency = 16;
        let pool = ForwardPool::new(2, IDLE, true, 2000);
        let mut servers = Vec::new();
        let mut inflight = Vec::new();
        for _ in 0..concurrency {
            assert!(pool.acquire(KEY).await.is_none(), "cold pool: every acquire misses");
            let (stream, server) = conn();
            servers.push(server);
            inflight.push(stream);
        }
        for stream in inflight {
            assert!(pool.release(KEY, stream).is_ok(), "keep-warm retains the released channel instead of closing it");
        }
        let mut fresh_connects = concurrency;
        let mut total_requests = concurrency;
        for _ in 0..50 {
            let mut leased = Vec::new();
            for _ in 0..concurrency {
                total_requests += 1;
                match pool.acquire(KEY).await {
                    Some(stream) => leased.push(stream),
                    None => {
                        let (stream, server) = conn();
                        servers.push(server);
                        leased.push(stream);
                        fresh_connects += 1;
                    }
                }
            }
            for stream in leased {
                let _ = pool.release(KEY, stream);
            }
        }
        assert_eq!(fresh_connects, concurrency, "steady state opens NO new connections -- only the cold-start set");
        assert!(total_requests as f64 / fresh_connects as f64 > 40.0, "requests-per-connection is high (no per-request churn)");
    }

    #[tokio::test(start_paused = true)]
    async fn should_evict_warm_retained_channels_after_idle_timeout_when_load_stops() {
        let pool = ForwardPool::new(2, IDLE, true, 2000);
        let mut servers = Vec::new();
        for _ in 0..6 {
            let (stream, server) = conn();
            servers.push(server);
            assert!(pool.release(KEY, stream).is_ok());
        }
        advance(IDLE).await;
        for (i, server) in servers.iter_mut().enumerate() {
            assert!(server.closed_by_pool().await, "warm channel {i} is reaped by the idle timeout once load stops");
        }
        assert!(pool.acquire(KEY).await.is_none(), "the keep-warm pool drains to empty -- no leak");
    }
}

/// Ports of upstream's `NettyHttpClientConnectionPoolTest`, `NettyHttpClientErrorHandlingTest` and
/// `NettyHttpClientKeepAliveTest`: real sockets against a local scripted upstream on an ephemeral port that counts
/// the connections it accepts. Where a Java test went over TLS (the echo server) these run in plain TCP, which
/// changes nothing about the framing being checked.
#[cfg(test)]
mod socket_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// What the upstream does.
    enum Mode {
        /// `CountingUpstreamServer`: `200 OK` with `X-Marker` echoed, keep-alive unless told otherwise.
        Counting,
        /// `ScriptedFirstResponseUpstreamServer` and its siblings: the first connection answers with raw `script`
        /// (to every request on it, or only the first); every later connection is a [`Mode::Counting`] one.
        Scripted { script: &'static [u8], every_request: bool },
        /// `StallOnReusedRequestUpstreamServer`: the first request on a connection is answered, later ones never.
        Stalls,
        /// `CloseOnReusedRequestUpstream`: the first request on a connection is answered, a later one is read and the
        /// connection closed without a response.
        ClosesReused,
    }

    struct Shared {
        mode: Mode,
        accepted: AtomicUsize,
        connection_close: AtomicBool,
        close_next_after_responding: AtomicBool,
        closed: tokio::sync::Notify,
        /// The body of every request read, in order.
        bodies: std::sync::Mutex<Vec<String>>,
    }

    struct Fixture {
        port: u16,
        shared: Arc<Shared>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Fixture {
        async fn start(mode: Mode) -> Fixture {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let shared = Arc::new(Shared {
                mode,
                accepted: AtomicUsize::new(0),
                connection_close: AtomicBool::new(false),
                close_next_after_responding: AtomicBool::new(false),
                closed: tokio::sync::Notify::new(),
                bodies: Default::default(),
            });
            let task = tokio::spawn({
                let shared = shared.clone();
                async move {
                    while let Ok((socket, _)) = listener.accept().await {
                        let index = shared.accepted.fetch_add(1, Ordering::SeqCst) + 1;
                        tokio::spawn(serve(socket, index, shared.clone()));
                    }
                }
            });
            Fixture { port, shared, task }
        }

        fn accepted(&self) -> usize {
            self.shared.accepted.load(Ordering::SeqCst)
        }
    }

    /// Reads one body-less request head; `None` when the peer closed first.
    async fn read_request(socket: &mut TcpStream, buf: &mut Vec<u8>) -> Option<String> {
        loop {
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                buf.drain(..end + 4);
                return Some(head);
            }
            let mut chunk = [0u8; 4096];
            match socket.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Reads the `Content-Length` body that follows `head`; `None` when the peer closed first.
    async fn read_request_body(socket: &mut TcpStream, buf: &mut Vec<u8>, head: &str) -> Option<String> {
        let length = head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("content-length")).map(|(_, v)| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
        while buf.len() < length {
            let mut chunk = [0u8; 4096];
            match socket.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        Some(String::from_utf8_lossy(&buf.drain(..length).collect::<Vec<u8>>()).into_owned())
    }

    async fn serve(mut socket: TcpStream, index: usize, shared: Arc<Shared>) {
        let mut buf = Vec::new();
        let mut requests = 0;
        while let Some(head) = read_request(&mut socket, &mut buf).await {
            requests += 1;
            let Some(body) = read_request_body(&mut socket, &mut buf, &head).await else { break };
            shared.bodies.lock().unwrap().push(body);
            match &shared.mode {
                Mode::Scripted { script, every_request } if index == 1 => {
                    if *every_request || requests == 1 {
                        let _ = socket.write_all(script).await;
                    }
                    continue;
                }
                Mode::Stalls if requests > 1 => continue,
                Mode::ClosesReused if requests > 1 => break,
                _ => {}
            }
            let marker = head.lines().find_map(|l| l.strip_prefix("X-Marker: ")).map(str::to_string);
            let closing = shared.connection_close.load(Ordering::SeqCst);
            let close_now = shared.close_next_after_responding.swap(false, Ordering::SeqCst) || closing;
            let mut response = format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: {}\r\n", if closing { "close" } else { "keep-alive" });
            if let Some(marker) = marker {
                response.push_str(&format!("X-Marker: {marker}\r\n"));
            }
            response.push_str("\r\nOK");
            let _ = socket.write_all(response.as_bytes()).await;
            if close_now {
                let _ = socket.shutdown().await;
            }
        }
        shared.closed.notify_one();
    }

    fn outbound(port: u16) -> Outbound {
        Outbound {
            method: "GET".into(),
            target: "/".into(),
            headers: vec![("Host".into(), format!("127.0.0.1:{port}"))],
            body: Bytes::new(),
            http2: false,
            may_stream: false,
            decoded_body: None,
        }
    }

    /// A forwarding server's side of the client: its configuration and its own pool.
    #[derive(Clone)]
    struct Client {
        config: Config,
        connections: Arc<ForwardConnections>,
    }

    impl Client {
        fn new(config: Config) -> Client {
            Client { config, connections: Default::default() }
        }

        fn with_property(self, name: &str, value: &str) -> Client {
            Client { config: self.config.with_property(name, value), ..self }
        }
    }

    fn pooled() -> Client {
        Client::new(Config::for_tests().with_property("forwardConnectionPoolEnabled", "true"))
    }

    async fn get(client: &Client, port: u16) -> Result<super::Upstream, Error> {
        send_pooled(&client.config, &client.connections, "127.0.0.1", port, false, &outbound(port), None, Duration::from_secs(10)).await
    }

    async fn get_ok(config: &Client, port: u16) -> u32 {
        get(config, port).await.expect("a response").status
    }

    // ---- NettyHttpClientConnectionPoolTest ----

    #[tokio::test]
    async fn should_reuse_single_connection_for_sequential_burst_when_pooling_enabled() {
        let upstream = Fixture::start(Mode::Counting).await;
        let config = pooled();
        for _ in 0..5 {
            assert_eq!(get_ok(&config, upstream.port).await, 200);
        }
        assert_eq!(upstream.accepted(), 1, "keep-alive reuse");
    }

    #[tokio::test]
    async fn should_open_fresh_connection_per_request_when_pooling_disabled() {
        let upstream = Fixture::start(Mode::Counting).await;
        let config = Client::new(Config::for_tests().with_property("forwardConnectionPoolEnabled", "false"));
        for _ in 0..5 {
            assert_eq!(get_ok(&config, upstream.port).await, 200);
        }
        assert_eq!(upstream.accepted(), 5, "historical behaviour preserved");
    }

    #[tokio::test]
    async fn should_not_reuse_connection_when_upstream_returns_connection_close() {
        let upstream = Fixture::start(Mode::Counting).await;
        upstream.shared.connection_close.store(true, Ordering::SeqCst);
        let config = pooled();
        for _ in 0..3 {
            assert_eq!(get_ok(&config, upstream.port).await, 200);
        }
        assert_eq!(upstream.accepted(), 3, "a fresh connection per request");
    }

    #[tokio::test]
    async fn should_not_reuse_channel_the_server_closed_after_responding() {
        let upstream = Fixture::start(Mode::Counting).await;
        upstream.shared.close_next_after_responding.store(true, Ordering::SeqCst);
        let config = pooled();
        assert_eq!(get_ok(&config, upstream.port).await, 200);
        tokio::time::timeout(Duration::from_secs(10), upstream.shared.closed.notified()).await.expect("server connection closed within timeout");
        // Unlike Netty's client, which can still hold the channel until it has read the FIN, the pool's watcher has
        // seen it by now (or sees it before the next request), so the second request is a plain success.
        assert_eq!(get_ok(&config, upstream.port).await, 200);
        assert!(upstream.accepted() >= 2, "the server-closed channel was never reused");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn should_not_corrupt_responses_under_concurrent_same_upstream_load() {
        let upstream = Fixture::start(Mode::Counting).await;
        let config = pooled();
        let (threads, per_thread) = (8, 25);
        let mut tasks = Vec::new();
        for t in 0..threads {
            let config = config.clone();
            let port = upstream.port;
            tasks.push(tokio::spawn(async move {
                let mut failures = 0;
                for i in 0..per_thread {
                    let marker = format!("thread-{t}-req-{i}");
                    let mut request = outbound(port);
                    request.headers.push(("X-Marker".into(), marker.clone()));
                    match send_pooled(&config.config, &config.connections, "127.0.0.1", port, false, &request, None, Duration::from_secs(20)).await {
                        Ok(r) if r.status == 200 && r.headers.iter().any(|(k, v)| k == "X-Marker" && *v == marker) => {}
                        _ => failures += 1,
                    }
                }
                failures
            }));
        }
        let mut failures = 0;
        for task in tasks {
            failures += task.await.unwrap();
        }
        assert_eq!(failures, 0, "no corrupted or cross-talked responses");
        assert!(upstream.accepted() < threads * per_thread, "reuse actually happened");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn should_retain_and_reuse_warm_connections_under_sustained_load_when_keep_alive_on() {
        let upstream = Fixture::start(Mode::Counting).await;
        let config = pooled()
            .with_property("forwardConnectionPoolMaxIdlePerKey", "1")
            .with_property("forwardConnectionPoolKeepAlive", "true")
            .with_property("forwardConnectionPoolMaxTotalPerKey", "64");
        let (concurrency, bursts) = (8, 10);
        for _ in 0..bursts {
            let mut tasks = Vec::new();
            for _ in 0..concurrency {
                let (config, port) = (config.clone(), upstream.port);
                tasks.push(tokio::spawn(async move { get_ok(&config, port).await }));
            }
            for task in tasks {
                assert_eq!(task.await.unwrap(), 200);
            }
        }
        let total = concurrency * bursts;
        assert!(upstream.accepted() <= concurrency * 2, "warm set bounded by concurrency, not by request count: {}", upstream.accepted());
        assert!(total as f64 / upstream.accepted() as f64 > 4.0, "requests-per-connection is high under sustained load");
    }

    /// A malformed, non-HTTP reply leaves the connection undecodable: it must never be pooled, so the next request
    /// opens a fresh connection and completes. The garbage fails the request with the decoder's reason (upstream
    /// c990e4a20's `NettyHttpClientConnectionPoolTest`, after 8.0.0); 8.0.0 surfaced it as a response with status 999
    /// `Unknown`, as the `forward_pooled_upstream_framing` scenario records from the oracle.
    #[tokio::test]
    async fn should_not_reuse_channel_after_malformed_non_http_response() {
        let upstream = Fixture::start(Mode::Scripted { script: b"some_random_bytes\r\n", every_request: true }).await;
        let config = pooled();
        let first = get(&config, upstream.port).await.err().map(|e| e.exception_message().unwrap_or_default());
        assert_eq!(first.as_deref(), Some("response from the upstream could not be decoded: IllegalArgumentException: invalid version format: SOME_RANDOM_BYTES"));
        assert_eq!(get_ok(&config, upstream.port).await, 200);
        assert!(upstream.accepted() >= 2, "the malformed channel was never reused");
    }

    /// The decoder failures of upstream c990e4a20's `ForwardHeaderLimitTest` and `ForwardUndecodableResponseIntegrationTest`
    /// as the fixed image names them: an invalid header name, a
    /// status that is no number, a status line over 4096 bytes, a chunk size that is no number, and a head Netty's
    /// `readHeaders` refuses.
    #[test]
    fn undecodable_responses_are_named_as_the_decoder_names_them() {
        let head = |bytes: &[u8]| match parse_head(bytes) {
            Parsed::Failed(failure) => Some(failure),
            _ => None,
        };
        assert_eq!(head(b"HTTP/1.1 200 OK\r\nx-bad(header): value\r\ncontent-length: 2\r\n\r\n").as_deref(), Some("IllegalArgumentException: a header name can only contain \"token\" characters, but found invalid character 0x28 at index 5 of header 'x-bad(header)'."));
        assert_eq!(head(b"FOO bar baz\r\n\r\n").as_deref(), Some("IllegalArgumentException: invalid version format: FOO"));
        assert_eq!(head(b"HTTP/1.1 abc OK\r\n\r\n").as_deref(), Some("NumberFormatException: For input string: \"abc\""));
        assert_eq!(head(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"), None);
        assert_eq!(head(b"HTTP/1.1 200 OK\nx: 1\n\n").as_deref(), Some("InvalidLineSeparatorException: Line Feed must be preceded by Carriage Return when terminating HTTP start- and header field-lines"));
        assert_eq!(head(b"HTTP/1.1 200 OK\r\nNoColon\r\n\r\n").as_deref(), Some("IllegalArgumentException: No colon found"));
        assert_eq!(head(b"HTTP/1.1 -5 A\rB\r\n\r\n").as_deref(), Some("IllegalArgumentException: code : -5 (expected: >= 0)"));
        assert_eq!(head(b"HTTP/1.1 200 O\rK\r\n\r\n").as_deref(), Some("IllegalArgumentException: reasonPhrase contains one of the following prohibited characters: \\r\\n: O\rK"));
        assert_eq!(head(b"HTTP/1.1 -0 Zero\r\n\r\n"), None);
        // Any `int` is a status; one past `Integer.MAX_VALUE` fails `parseInt`.
        assert!(matches!(parse_head(b"HTTP/1.1 70000 Big\r\n\r\n"), Parsed::Complete(Head { status: 70000, .. }, _)));
        assert!(matches!(parse_head(b"HTTP/1.1 2147483647 Max\r\n\r\n"), Parsed::Complete(Head { status: 2_147_483_647, .. }, _)));
        assert_eq!(head(b"HTTP/1.1 2147483648 Over\r\n\r\n").as_deref(), Some("NumberFormatException: For input string: \"2147483648\""));
        assert_eq!(head(b"HTTP/1.x 200 OK\r\n\r\n").as_deref(), Some("IllegalArgumentException: Invalid version number, only 0-9 (0x30-0x39) allowed, but received a 'X' (0x58)"));
        // Netty's leniency: a name ends at OWS, any-case `HTTP/d.d`, obs-fold, empty lines first.
        let Parsed::Complete(lenient, len) = parse_head(b"\r\nhttp/1.2 200 OK\r\nBad Header: x \r\nx-f: a\r\n\t b\r\n\r\nrest") else { panic!("not complete") };
        assert_eq!((lenient.status, lenient.http11, len), (200, false, 50));
        assert_eq!(lenient.headers, vec![("Bad".to_string(), "x".to_string()), ("x-f".to_string(), "a b".to_string())]);
        assert!(matches!(parse_head(b"HTTP/1.1 200 OK\r\nx-a: 1\r\n"), Parsed::Partial { in_headers: true }));
        assert!(matches!(parse_head(b"HTTP/1.1 20"), Parsed::Partial { in_headers: false }));
        let chunk = |line: &str| chunk_size_failure(line).exception_message().unwrap_or_default();
        assert_eq!(chunk("zz"), "response from the upstream could not be decoded: NumberFormatException: Invalid character in chunk size");
        assert_eq!(chunk(";x"), "response from the upstream could not be decoded: NumberFormatException: Empty chunk size");
        assert_eq!(chunk("fffffffff"), "response from the upstream could not be decoded: NumberFormatException: Chunk size overflow: 4294967295");
        let http10 = Head { status: 200, reason: "OK".into(), headers: vec![("Transfer-Encoding".into(), "chunked".into())], http11: false, header_size: 0 };
        assert_eq!(rejected_head(&http10, false).as_deref(), Some("TransferEncodingNotAllowedException: The Transfer-Encoding header is only allowed in HTTP/1.1 or newer"));
        // Netty 4.2.19: duplicate lengths are refused on HTTP/1.0 too, and `chunked` must be the very last token, once.
        let with = |name: &str, lines: &[&str], http11: bool| Head { status: 200, reason: "OK".into(), headers: lines.iter().map(|v| (name.to_string(), v.to_string())).collect(), http11, header_size: 0 };
        assert_eq!(rejected_head(&with("Content-Length", &["5", "6"], false), false).as_deref(), Some("IllegalArgumentException: Multiple Content-Length values found: [5, 6]"));
        let te = |lines: &[&str]| rejected_head(&with("Transfer-Encoding", lines, true), false);
        assert_eq!(te(&["chunked", "gzip"]).as_deref(), Some("IllegalArgumentException: chunked must be the last encoding present in the Transfer-Encoding header"));
        assert_eq!(te(&["chunked, chunked"]).as_deref(), Some("IllegalArgumentException: chunked transfer coding must not be applied more than once"));
        assert_eq!(te(&["gzip", " Chunked\t"]), None);
        assert_eq!(fault("X", &"a".repeat(300)), format!("X: {}...", "a".repeat(253)));
    }

    #[tokio::test]
    async fn should_not_reuse_channel_after_in_range_status_but_dirty_framing() {
        let upstream = Fixture::start(Mode::Scripted { script: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOKEXTRA", every_request: true }).await;
        let config = pooled();
        assert_eq!(get_ok(&config, upstream.port).await, 200);
        assert_eq!(get_ok(&config, upstream.port).await, 200);
        assert!(upstream.accepted() >= 2, "the dirty channel was never reused");
    }

    #[tokio::test]
    async fn should_reuse_channel_after_no_body_204_response() {
        let upstream = Fixture::start(Mode::Scripted { script: b"HTTP/1.1 204 No Content\r\n\r\n", every_request: true }).await;
        let config = pooled();
        for _ in 0..3 {
            assert_eq!(get_ok(&config, upstream.port).await, 204);
        }
        assert_eq!(upstream.accepted(), 1, "the no-body channel is clean and was reused");
    }

    #[tokio::test]
    async fn should_reuse_channel_after_properly_terminated_chunked_response() {
        let upstream = Fixture::start(Mode::Scripted { script: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\n\r\n", every_request: true }).await;
        let config = pooled();
        for _ in 0..3 {
            assert_eq!(get_ok(&config, upstream.port).await, 200);
        }
        assert_eq!(upstream.accepted(), 1, "the cleanly-terminated channel was reused");
    }

    #[tokio::test]
    async fn should_not_reuse_channel_after_wrong_content_length_response() {
        // Content-Length 6 over a body of "OK": the client borrows "HTTP" from the pipelined second response to fill
        // it and is left with the rest of that response undecoded.
        let upstream = Fixture::start(Mode::Scripted {
            script: b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nOKHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
            every_request: false,
        })
        .await;
        let config = pooled();
        assert_eq!(get_ok(&config, upstream.port).await, 200);
        assert_eq!(get_ok(&config, upstream.port).await, 200);
        assert!(upstream.accepted() >= 2, "the desynced channel was not reused");
    }

    #[tokio::test]
    async fn should_not_reuse_channel_after_pipelined_extra_response() {
        let upstream = Fixture::start(Mode::Scripted {
            script: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOKHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
            every_request: true,
        })
        .await;
        let config = pooled();
        assert_eq!(get_ok(&config, upstream.port).await, 200);
        assert_eq!(get_ok(&config, upstream.port).await, 200);
        assert!(upstream.accepted() >= 2, "the channel with leftover bytes was not reused");
    }

    /// A reused connection whose upstream has gone silent times out on `maxSocketTimeoutInMillis` instead of hanging,
    /// and does not fall back to a fresh connection.
    #[tokio::test]
    async fn should_time_out_a_stalled_reused_pooled_connection_instead_of_hanging() {
        let upstream = Fixture::start(Mode::Stalls).await;
        let config = pooled().with_property("maxSocketTimeoutInMillis", "1500");
        assert_eq!(get_ok(&config, upstream.port).await, 200);
        assert_eq!(upstream.accepted(), 1, "first connection was pooled");
        let started = std::time::Instant::now();
        let second = get(&config, upstream.port).await;
        assert!(matches!(second, Err(Error::ReadTimeout)), "expected the stalled reused connection to time out");
        assert!(started.elapsed() < Duration::from_secs(8), "the read timeout fired promptly");
        assert_eq!(upstream.accepted(), 1, "the stalled request reused the pooled connection (no fresh accept)");
    }

    async fn send_method(client: &Client, port: u16, method: &str, body: &'static str) -> Result<super::Upstream, Error> {
        let mut request = outbound(port);
        request.method = method.into();
        request.headers.push(("Content-Length".into(), body.len().to_string()));
        request.body = Bytes::from_static(body.as_bytes());
        send_pooled(&client.config, &client.connections, "127.0.0.1", port, false, &request, None, Duration::from_secs(10)).await
    }

    /// A GET on a reused connection the upstream closes before responding (the stale-connection race) is sent once
    /// more on a fresh connection.
    #[tokio::test]
    async fn should_retry_idempotent_request_on_fresh_connection_when_reused_connection_closed_before_response() {
        let upstream = Fixture::start(Mode::ClosesReused).await;
        let config = pooled();
        assert_eq!(get_ok(&config, upstream.port).await, 200);
        let second = get(&config, upstream.port).await.expect("retried on a fresh connection");
        assert_eq!(second.status, 200);
        assert!(!second.timing.reused, "answered on the fresh connection");
        assert!(upstream.accepted() >= 2, "the reused connection was closed and a fresh one opened for the retry");
    }

    #[tokio::test]
    async fn should_retry_idempotent_put_with_body_on_fresh_connection_when_reused_connection_closed_before_response() {
        let upstream = Fixture::start(Mode::ClosesReused).await;
        let config = pooled();
        let payload = "{\"id\":1,\"name\":\"retried\"}";
        assert_eq!(send_method(&config, upstream.port, "PUT", payload).await.expect("a response").status, 200);
        assert_eq!(send_method(&config, upstream.port, "PUT", payload).await.expect("retried on a fresh connection").status, 200);
        // the first request, the reused attempt the upstream dropped, then the retry: every copy of the body intact
        assert_eq!(*upstream.shared.bodies.lock().unwrap(), vec![payload; 3]);
    }

    /// A POST is not sent again (it could be submitted twice): the failure goes to the caller.
    #[tokio::test]
    async fn should_not_retry_non_idempotent_request_when_reused_connection_closed_before_response() {
        let upstream = Fixture::start(Mode::ClosesReused).await;
        let config = pooled();
        assert_eq!(send_method(&config, upstream.port, "POST", "payload").await.expect("a response").status, 200);
        let second = send_method(&config, upstream.port, "POST", "payload").await;
        // `PooledConnectionClosedException` (upstream 48b7e14d2, 9.1.0): reads as the close, and names it in the 502
        assert!(matches!(&second, Err(Error::PooledClosed { method, cause }) if method == "POST" && matches!(**cause, Error::Protocol)), "expected the closed reused connection's failure, got {:?}", second.as_ref().err());
        assert_eq!(upstream.accepted(), 1, "no fresh connection");
        assert_eq!(upstream.shared.bodies.lock().unwrap().len(), 2, "sent once on each attempt the caller made");
    }

    // ---- NettyHttpClientErrorHandlingTest ----

    #[tokio::test]
    async fn should_report_connection_refused_for_connect_exception() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let error = get(&pooled(), port).await.err().expect("connection refused");
        assert!(error.is_connection_failure());
        let message = error.exception_message().unwrap();
        assert!(message.contains(&format!("Connection refused: /127.0.0.1:{port}")), "{message}");
    }

    #[tokio::test]
    async fn should_handle_connection_closure() {
        // accepts and closes without answering
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
        });
        let error = get(&pooled(), port).await.err().expect("closed before a response");
        acceptor.abort();
        let message = error.exception_message().unwrap();
        assert!(
            ["Connection reset", "Channel set as inactive before valid response has been received", "Channel handler removed before valid response has been received"].iter().any(|m| message.contains(m)),
            "{message}"
        );
    }

    #[tokio::test]
    async fn should_handle_smaller_content_length_header() {
        // 11 of the 23 body bytes are declared; the rest is not part of the response
        let upstream = Fixture::start(Mode::Scripted {
            script: b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\nContent-Length: 11\r\n\r\nthis is an example body",
            every_request: true,
        })
        .await;
        let response = get(&pooled(), upstream.port).await.expect("a response");
        assert_eq!(response.status, 200);
        assert_eq!(response.reason, "OK");
        assert_eq!(response.body, Bytes::from_static(b"this is an "));
        assert!(response.headers.contains(&("Content-Length".into(), "11".into())));
        assert!(response.headers.contains(&("Content-Type".into(), "text/plain".into())));
    }

    // ---- NettyHttpClientKeepAliveTest ----

    /// A real forward connection, made by the forwarding client's own connect, with `config`'s keep-alive settings.
    async fn forward_socket(config: &Config) -> (TcpStream, tokio::net::TcpListener) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stream = connect_forward(config, "127.0.0.1", port, Duration::from_secs(5)).await.expect("connected");
        (stream, listener)
    }

    #[tokio::test]
    async fn should_set_so_keepalive_on_forward_socket_when_enabled() {
        let (stream, _listener) = forward_socket(&Config::for_tests()).await; // forwardSocketKeepAlive defaults to true
        assert!(socket2::SockRef::from(&stream).keepalive().unwrap(), "SO_KEEPALIVE is enabled on the forward socket when keepalive is on");
    }

    #[tokio::test]
    async fn should_not_set_any_keepalive_option_when_disabled() {
        let (stream, _listener) = forward_socket(&Config::for_tests().with_property("forwardSocketKeepAlive", "false")).await;
        assert!(!socket2::SockRef::from(&stream).keepalive().unwrap(), "no SO_KEEPALIVE when keepalive is disabled: the historical behaviour");
    }

    #[tokio::test]
    async fn should_apply_the_configured_keepalive_timers_clamped_to_at_least_one() {
        let (stream, _listener) = forward_socket(
            &Config::for_tests()
                .with_property("forwardSocketKeepAliveIdleSeconds", "61")
                .with_property("forwardSocketKeepAliveIntervalSeconds", "0")
                .with_property("forwardSocketKeepAliveCount", "-3"),
        )
        .await;
        let socket = socket2::SockRef::from(&stream);
        assert_eq!(socket.tcp_keepalive_time().unwrap(), Duration::from_secs(61));
        assert_eq!(socket.tcp_keepalive_interval().unwrap(), Duration::from_secs(1));
        assert_eq!(socket.tcp_keepalive_retries().unwrap(), 1);
    }
}

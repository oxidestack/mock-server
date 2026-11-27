//! Turning a [`Reply`] into bytes on the wire the way MockServer's `ResponseWriter` does (§1.1, §8.6).

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Response, StatusCode};

use crate::request::{HttpRequest, Protocol};

pub const DEFAULT_CORS_METHODS: &str = "CONNECT, DELETE, GET, HEAD, OPTIONS, POST, PUT, PATCH, TRACE";
pub const DEFAULT_CORS_HEADERS: &str =
    "Allow, Content-Encoding, Content-Length, Content-Type, ETag, Expires, Last-Modified, Location, Server, Vary, Authorization";

/// `DefaultResponseHeaders.parse`: `name=value` pairs separated by `|`, split at the first `=`, both sides trimmed as
/// Java's `String.trim` does; a segment without `=`, or with a blank name, is skipped.
fn default_response_headers(configured: Option<&str>) -> Vec<(&str, &str)> {
    fn trim(s: &str) -> &str {
        s.trim_matches(|c: char| c <= ' ')
    }
    configured
        .into_iter()
        .flat_map(|v| v.split('|'))
        .filter_map(|segment| match segment.find('=') {
            Some(i) if i > 0 => Some((trim(&segment[..i]), trim(&segment[i + 1..]))),
            _ => None,
        })
        .filter(|(name, _)| !name.is_empty())
        .collect()
}

/// A response before connection-level decoration.
#[derive(Debug, Clone, Default)]
pub struct Reply {
    pub status: u32,
    pub reason: Option<String>,
    /// Header names keep the case they were given in; order is preserved.
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// Control-plane responses always get CORS headers and, for legacy aliases, the `deprecated` header.
    pub api: bool,
    /// Answers the configured `livenessHttpGetPath`, which carries no `deprecated` header whatever its prefix.
    pub status_path: bool,
    /// The control-plane operation that answered ([`crate::control::operation_route`]), the `http_route` of the
    /// request's `http_server_request_duration_seconds`; `None` for the data plane.
    pub route: Option<&'static str>,
    /// Omit the computed `Content-Length` (`connectionOptions.suppressContentLengthHeader`).
    pub suppress_content_length: bool,
    /// Write this `Content-Length` instead of the real one (`connectionOptions.contentLengthHeaderOverride`).
    pub content_length_override: Option<u64>,
    /// Omit the `Connection` header (`connectionOptions.suppressConnectionHeader`).
    pub suppress_connection_header: bool,
    /// Force keep-alive on or off (`connectionOptions.keepAliveOverride`): the `Connection` header only.
    pub keep_alive_override: Option<bool>,
    /// `connectionOptions.closeSocket`: whether to close the connection after writing, whatever the request asked.
    pub close_socket: Option<bool>,
    /// `connectionOptions.chunkSize`: the body goes out chunked, in pieces of this many bytes.
    pub chunk_size: Option<usize>,
    /// `connectionOptions.chunkDelay`: with `chunk_size`, each piece is written this long after the previous one.
    /// Boxed: a `Delay` is most of a reply's size, and a reply is moved through every layer of the request path.
    pub chunk_delay: Option<Box<crate::action::Delay>>,
    /// Set by [`Reply::finalize`]: close the connection after writing.
    pub close: bool,
    /// The body's content type, written after `connection` unless a `Content-Type` header is set
    /// (`MockServerHttpResponseToFullHttpResponse.setHeaders`).
    pub default_content_type: Option<String>,
    /// `set-cookie` values written last (`setCookies`).
    pub set_cookies: Vec<String>,
    /// How long to wait before closing, when the connection is closed after this response
    /// (`connectionOptions.closeSocketDelay`, else a TCP chaos `slowCloseDelay`).
    pub close_delay: Option<std::time::Duration>,
    /// TCP chaos `resetMidResponse`: once written, the connection is reset (RST), on HTTP/2 the whole connection.
    pub reset_connection: bool,
    /// Response `trailers`: on HTTP/1.1 they force chunked framing and follow the terminating chunk.
    pub trailers: Vec<(String, String)>,
    /// Set by [`Reply::finalize`]: the body goes out as one chunk, then the terminating chunk (and the trailers):
    /// for `trailers`, or for headers that say chunked without a `chunk_size`.
    pub chunked_for_trailers: bool,
    /// Where the model's own headers end and the encoder's (content type from the body, framing, `set-cookie`)
    /// begin, set by `finalize`: `AltSvcHeaderHandler` appends to the model, so `alt-svc` goes here.
    pub model_headers_end: Option<usize>,
    /// Set by [`Reply::finalize`] on HTTP/1.1 for a status Netty's encoder treats as always empty (1xx, 204, 205,
    /// 304): nothing after the head is written, not even chunk framing.
    pub omit_body: bool,
    /// The response is written as HTTP/1.1 objects straight to the request's channel (`HttpSseResponseActionHandler`),
    /// which on HTTP/3 `Http3HttpObjectEncoder` turns into frames: the head and events whatever the method, then the
    /// last content as an empty DATA frame and the end of the stream (`src/http3.rs`).
    pub written_as_http1_objects: bool,
    /// The `defaultResponseHeaders` read when the request arrived, for an answer whose handling changes them
    /// (`PUT /mockserver/configuration`); `None` reads the configuration in force when the reply is finalised.
    pub default_response_headers: Option<String>,
    /// The `content-type` header was the body's media type (`withBody(json(…))`, `withBody(…, MediaType)`), which
    /// the HTTP/1.1 and HTTP/2 encoders write and `Http3ResponseWriter` does not.
    pub content_type_from_body: bool,
    /// A gRPC answer over HTTP/3: `GrpcHttp3Adapter` writes its header fields as `:status`, `content-type`, `server`,
    /// then the response's own, where `Http3RequestBridge` leads with `server` (`src/http3.rs`).
    pub grpc_http3: bool,
}

impl Reply {
    pub fn status(status: u32) -> Reply {
        Reply { status, ..Reply::default() }
    }

    /// `notFoundResponse()`: a 404 with its reason phrase set (which a gRPC transport failure reports).
    pub fn not_found() -> Reply {
        Reply { status: 404, reason: Some("Not Found".into()), ..Reply::default() }
    }

    /// A control-plane response with no body.
    pub fn api(status: u32) -> Reply {
        Reply { status, api: true, ..Reply::default() }
    }

    /// A control-plane response with a body whose media type is the body's (`HttpState`'s
    /// `response().withBody(…, MediaType)`): `content-type` (with `; charset=utf-8` appended like MockServer does)
    /// is written by the encoder after the model's headers, i.e. after CORS, `version` and `connection`, and not over
    /// HTTP/3 (`MockServerHttpResponseToFullHttpResponse.setHeaders`). An empty body names no type.
    pub fn api_body(status: u32, content_type: &str, body: impl Into<Bytes>) -> Reply {
        let body = body.into();
        let mut reply = Reply::api(status);
        if !body.is_empty() {
            reply.default_content_type = Some(format!("{content_type}; charset=utf-8"));
        }
        reply.body = body;
        reply
    }

    /// A control-plane response written by `ResponseWriter.writeResponse(request, status, body, contentType)`:
    /// `replaceHeader(content-type)` makes it the model's first header, ahead of CORS, `version` and `connection`
    ///; an empty body names no type.
    pub fn api_header(status: u32, content_type: &str, body: impl Into<Bytes>) -> Reply {
        let body = body.into();
        let mut reply = Reply::api(status);
        if !body.is_empty() {
            reply.headers.push(("content-type".into(), format!("{content_type}; charset=utf-8")));
        }
        reply.body = body;
        reply
    }

    /// A control-plane response that names its body's content type even when the body is empty, written after the
    /// model's headers as [`Reply::api_body`]'s.
    pub fn api_typed(status: u32, content_type: &str, body: impl Into<Bytes>) -> Reply {
        let mut reply = Reply::api(status);
        reply.default_content_type = Some(format!("{content_type}; charset=utf-8"));
        reply.body = body.into();
        reply
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn set_if_absent(&mut self, name: &str, value: String) {
        if self.header(name).is_none() {
            self.headers.push((name.to_string(), value));
        }
    }

    /// `CORSHeaders.addCORSHeaders` with `corsAllowOrigin`, `corsAllowMethods`, `corsAllowHeaders`,
    /// `corsAllowCredentials` and `corsMaxAgeInSeconds`: every header is only set when absent.
    pub fn add_cors_headers(&mut self, request: &HttpRequest, config: &crate::Config) {
        let allow_origin = config.property("corsAllowOrigin").filter(|v| !v.is_empty());
        let credentials = config.bool_property("corsAllowCredentials", false);
        match request.first_header("origin").filter(|o| !o.is_empty()) {
            Some("null") => self.set_if_absent("access-control-allow-origin", "null".into()),
            Some(origin) if credentials => {
                self.set_if_absent("access-control-allow-origin", origin.to_string());
                self.set_if_absent("access-control-allow-credentials", "true".into());
            }
            Some(origin) => {
                self.set_if_absent("access-control-allow-origin", allow_origin.unwrap_or_else(|| origin.to_string()));
                self.set_if_absent("access-control-allow-credentials", credentials.to_string());
            }
            None => {
                let origin = allow_origin.unwrap_or_else(|| "*".into());
                let with_credentials = !(origin == "*" && credentials);
                self.set_if_absent("access-control-allow-origin", origin);
                if with_credentials {
                    self.set_if_absent("access-control-allow-credentials", credentials.to_string());
                }
            }
        }
        self.add_allow_methods_and_headers(request, config);
    }

    /// `CORSHeaders.addControlPlaneCORSHeaders` (9.1.0): a response from MockServer's own API, dashboard or metrics
    /// endpoint reflects the `Origin` only when the control-plane origin policy allows it ([`crate::cors_origin`]);
    /// any other, `null` included, gets no CORS headers at all; no `Origin` gets `*`. `corsAllowOrigin` is not used.
    pub fn add_control_plane_cors_headers(&mut self, request: &HttpRequest, config: &crate::Config) {
        let credentials = config.bool_property("corsAllowCredentials", false);
        match request.first_header("origin").filter(|o| !o.is_empty()) {
            None => {
                self.set_if_absent("access-control-allow-origin", "*".into());
                if !credentials {
                    self.set_if_absent("access-control-allow-credentials", "false".into());
                }
            }
            Some(origin) if crate::cors_origin::allowed_by_config(config, Some(origin), crate::cors_origin::request_host(request).as_deref()) => {
                self.set_if_absent("access-control-allow-origin", origin.to_string());
                self.set_if_absent("access-control-allow-credentials", credentials.to_string());
            }
            Some(_) => return,
        }
        self.add_allow_methods_and_headers(request, config);
    }

    fn add_allow_methods_and_headers(&mut self, request: &HttpRequest, config: &crate::Config) {
        let non_blank = |name: &str| config.property(name).filter(|v| !v.is_empty());
        self.set_if_absent("access-control-allow-methods", non_blank("corsAllowMethods").unwrap_or_else(|| DEFAULT_CORS_METHODS.into()));
        let requested = request.first_header("access-control-request-headers").filter(|h| !h.is_empty());
        let allow_headers = match (non_blank("corsAllowHeaders"), requested) {
            (Some(configured), Some(requested)) => format!("{configured}, {requested}"),
            (Some(configured), None) => configured,
            (None, Some(requested)) => requested.to_string(),
            (None, None) => DEFAULT_CORS_HEADERS.to_string(),
        };
        self.set_if_absent("access-control-allow-headers", allow_headers.clone());
        self.set_if_absent("access-control-expose-headers", allow_headers);
        self.set_if_absent("access-control-max-age", config.int_property("corsMaxAgeInSeconds", 0).to_string());
    }

    /// Applies MockServer's `ResponseWriter` decoration: CORS and `deprecated` for the control plane, the
    /// `Connection` header, `Content-Length`. Afterwards `close` says whether to close the connection.
    /// The first step of `ResponseWriter.writeResponse`, which mutates the `HttpResponse` the event log holds: the
    /// CORS headers, then the configured `defaultResponseHeaders`. Returns the headers it added, in order; a second
    /// call adds nothing.
    pub fn add_writer_headers(&mut self, request: &HttpRequest, config: &crate::Config) -> Vec<(String, String)> {
        let before = self.headers.len();
        // Control-plane responses get the control-plane origin policy; mocked and proxied ones the `corsAllowOrigin`
        // policy, under `enableCORSForAllResponses`.
        if self.api {
            self.add_control_plane_cors_headers(request, config);
        } else if config.bool_property("enableCORSForAllResponses", false) {
            self.add_cors_headers(request, config);
        }
        // `DefaultResponseHeaders.addDefaultResponseHeaders`: the configured `defaultResponseHeaders`, each only when
        // absent, on mocked, proxied and control-plane responses alike.
        let configured = self.default_response_headers.clone().or_else(|| config.property("defaultResponseHeaders"));
        for (name, value) in default_response_headers(configured.as_deref()) {
            self.set_if_absent(name, value.to_string());
        }
        self.headers[before..].to_vec()
    }

    pub fn finalize(mut self, request: &HttpRequest, config: &crate::Config) -> Reply {
        self.add_writer_headers(request, config);
        if self.api {
            self.headers.push(("version".into(), crate::control::VERSION.into()));
            if !request.path.starts_with("/mockserver") && !self.status_path {
                let path = &request.path;
                self.headers.push(("deprecated".into(), format!("\"{path}\" is deprecated use \"/mockserver{path}\" instead")));
            }
        }
        // 9.2.0 (#83): `closeSocket: true` answers `connection: close` whatever the request asked; `keepAliveOverride`
        // still decides when set.
        let keep_alive = self.keep_alive_override.unwrap_or(request.keep_alive && self.close_socket != Some(true));
        // `NettyResponseWriter`: `closeSocket` decides, otherwise the request's keep-alive.
        self.close = self.close_socket.unwrap_or(!request.keep_alive);
        if !self.suppress_connection_header {
            self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("connection"));
            self.headers.push(("connection".into(), if keep_alive { "keep-alive" } else { "close" }.into()));
        }
        let transport = request.transport();
        // `Http2StreamIds.stamp`: an `x-http2-stream-id` the model carries as an ordinary header is removed (over
        // HTTP/1.1 there is no stream id to stamp back; upstream's `MockServerHttpResponseToFullHttpResponseTest.shouldNotEmitLeakedStreamIdHeaderWhenNoStreamIdField`).
        if transport == Protocol::Http1 {
            self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("x-http2-stream-id"));
        }
        if transport == Protocol::Http3 && self.content_type_from_body {
            self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-type"));
        }
        self.model_headers_end = Some(self.headers.len());
        if transport == Protocol::Http3 {
            // `Http3RequestBridge.toHttp3HeadersFrame`: the model's headers only (no content type from the body, no
            // framing headers); the body is written whatever the status (`toHttp3DataFrame`), the trailers as a
            // trailing HEADERS frame. `connectionOptions` framing (`chunkSize`, `chunkDelay`, the length options) is
            // not implemented there (`Http3ResponseWriter.unimplementedOnHttp3`), chaos's slow dribble included.
            // Source-checked only: the oracle image has no native QUIC transport. Only the model's headers: the
            // expectation's `cookies` become `set-cookie` in the HTTP/1.1 and HTTP/2 encoders alone
            // (`MockServerHttpResponseToFullHttpResponse`), so over HTTP/3 they are not sent.
            self.chunk_size = None;
            self.chunk_delay = None;
            self.set_cookies.clear();
            return self;
        }
        if let Some(ct) = self.default_content_type.take() && self.header("content-type").is_none() {
            self.headers.push(("content-type".into(), ct));
        }
        // `HttpContentLengthRemover`: a `Content-Length` with an empty value (any of several) is dropped, whole, and the
        // length is then computed as if none had been set.
        if self.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("content-length") && v.is_empty()) {
            self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
        }
        let user_content_length = self.header("content-length").is_some();
        // `setHeaders`: without a `Content-Length`, a model `Transfer-Encoding` of any value (gzip, identity, empty)
        // means chunked encoding: no computed length, the header replaced by `transfer-encoding: chunked` at the end.
        let user_transfer_encoding =
            !user_content_length && self.chunk_size.is_none() && self.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
        if let Some(len) = self.content_length_override {
            // As the oracle: the header says `len` and the whole body is still written, whatever `len` is. A client
            // reading by length stops early on a smaller one; on a larger one it waits for bytes that never come, or
            // takes the next answer on the connection as the rest (scenario `content_length_override_larger`).
            self.headers.push(("content-length".into(), len.to_string()));
        } else if !self.suppress_content_length && !user_content_length && self.chunk_size.is_none() && !user_transfer_encoding {
            self.headers.push(("content-length".into(), self.body.len().to_string()));
        }
        if user_transfer_encoding {
            // `headers().set(TRANSFER_ENCODING, CHUNKED)`; a `contentLengthHeaderOverride` written above stays.
            self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("transfer-encoding"));
            self.headers.push(("transfer-encoding".into(), "chunked".into()));
        }
        // Netty's `HttpObjectEncoder` frames a full response as one chunk and the terminating chunk whenever its
        // headers say chunked (`HttpUtil.isTransferEncodingChunked`: a `chunked` token in any `Transfer-Encoding`,
        // any case), a user `Content-Length` beside it or not.
        if self.chunk_size.is_none() && (user_transfer_encoding || (user_content_length && self.transfer_encoding_chunked())) {
            self.chunked_for_trailers = true;
        }
        if self.chunk_size.is_some() {
            // `HttpUtil.setTransferEncodingChunked`: replaces any `Content-Length`, appended after the others.
            self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("transfer-encoding"));
            self.headers.push(("transfer-encoding".into(), "chunked".into()));
        }
        // `mapResponseWithTrailers`: trailers need chunked framing, except on a status that never has a body.
        let body_less = (100..200).contains(&self.status) || matches!(self.status, 204 | 205 | 304);
        if !self.trailers.is_empty() && self.chunk_size.is_none() && !body_less {
            self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length") && !k.eq_ignore_ascii_case("transfer-encoding"));
            self.headers.push(("transfer-encoding".into(), "chunked".into()));
            self.chunked_for_trailers = true;
        }
        // `addTrailerHeader`: announces the trailer names unless a `Trailer` header is already set.
        if !self.trailers.is_empty() && (self.chunk_size.is_some() || self.chunked_for_trailers) && self.header("trailer").is_none() {
            let mut names: Vec<&str> = Vec::new();
            for (name, _) in &self.trailers {
                if !names.contains(&name.as_str()) {
                    names.push(name);
                }
            }
            let names = names.join(", ");
            self.headers.push(("trailer".into(), names));
        }
        for cookie in std::mem::take(&mut self.set_cookies) {
            self.headers.push(("set-cookie".into(), cookie));
        }
        // `HttpResponseEncoder.isContentAlwaysEmpty`: a 101 counts as always empty only with a `Sec-WebSocket-Version`
        // (a draft-00 WebSocket handshake has a body), so a mocked 101 without one keeps its framing and body
        let switching_with_content = self.status == 101 && self.header("sec-websocket-version").is_none();
        if transport == Protocol::Http1 && body_less && !switching_with_content {
            self.sanitize_always_empty();
        }
        self
    }

    /// `HttpResponseEncoder.sanitizeHeadersBeforeEncode` for a status whose content is always empty: a 1xx or 204
    /// loses `Content-Length` and `Transfer-Encoding` (whoever set them), a 205 loses `Transfer-Encoding` and gets
    /// `Content-Length: 0`, a 304 keeps its headers; none gets a body or chunk framing (`ST_CONTENT_ALWAYS_EMPTY`).
    fn sanitize_always_empty(&mut self) {
        let framing = |k: &str| k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("transfer-encoding");
        if (100..200).contains(&self.status) || self.status == 204 {
            self.headers.retain(|(k, _)| !framing(k));
        } else if self.status == 205 {
            self.headers.retain(|(k, _)| !framing(k));
            self.headers.push(("content-length".into(), "0".into()));
        }
        self.omit_body = true;
        self.chunk_size = None;
        self.chunk_delay = None;
        self.chunked_for_trailers = false;
    }

    /// `HttpUtil.isTransferEncodingChunked`: any `Transfer-Encoding` value lists the `chunked` token.
    fn transfer_encoding_chunked(&self) -> bool {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
            .any(|(_, v)| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("chunked")))
    }

    /// The terminating chunk and the trailer block.
    fn last_chunk(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(b"0\r\n");
        for (name, value) in &self.trailers {
            crate::request::push_header_bytes(out, name);
            out.extend_from_slice(b": ");
            crate::request::push_header_bytes(out, value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
    }

    /// `EarlyNettyResponseWriter.addConnectionHeader` (upstream fix 88e72ebc7, after 8.0.0; `docs/divergences.md`): an
    /// early (`respondBeforeBody`) response always ends its connection, so it says `connection: close` whatever the
    /// request asked, unless `suppressConnectionHeader` or `keepAliveOverride: true` decided the header. Called on a
    /// finalized reply; the header keeps its place. The 8.0.0 oracle follows the request's keep-alive.
    pub fn say_connection_closes(&mut self) {
        if self.suppress_connection_header || self.keep_alive_override == Some(true) {
            return;
        }
        for (_, value) in self.headers.iter_mut().filter(|(k, _)| k.eq_ignore_ascii_case("connection")) {
            *value = "close".into();
        }
    }

    /// The status line, headers (in their original case) and body, for HTTP/1.1.
    /// A header value with a control character other than tab, CR and LF: Netty's header validation rejects the
    /// response, so only its status line goes out and the connection is left open (see `http1::serve`).
    pub fn has_unencodable_header(&self) -> bool {
        self.headers.iter().any(|(_, v)| v.bytes().any(|b| (b < 0x20 && !matches!(b, b'\t' | b'\r' | b'\n')) || b == 0x7f))
    }

    /// The status line alone, which is all the oracle writes for a response it cannot encode.
    pub fn status_line_only(&self) -> Vec<u8> {
        let reason = self.reason.clone().filter(|r| !r.is_empty()).unwrap_or_else(|| crate::status::reason_phrase(self.status));
        format!("HTTP/1.1 {} {reason}\r\n\r\n", self.status).into_bytes()
    }

    pub fn encode_http1(&self, head_only: bool) -> Vec<u8> {
        use std::io::Write;
        let reason = match self.reason.as_deref().filter(|r| !r.is_empty()) {
            Some(reason) => std::borrow::Cow::Borrowed(reason),
            None => crate::status::reason(self.status),
        };
        // the status line (`HTTP/1.1 `, the status, a space, CRLF), every header (with `: ` and CRLF; a header's bytes
        // are at most its text's), the blank line and an unchunked body
        let head = 9 + 10 + 1 + reason.len() + 2 + self.headers.iter().map(|(name, value)| name.len() + value.len() + 4).sum::<usize>() + 2;
        let mut out = Vec::with_capacity(head + self.body.len());
        let _ = write!(out, "HTTP/1.1 {} {reason}\r\n", self.status);
        for (name, value) in &self.headers {
            if name.bytes().any(|b| b == b'\r' || b == b'\n' || b == b':') || value.bytes().any(|b| b == b'\r' || b == b'\n') {
                continue;
            }
            crate::request::push_header_bytes(&mut out, name);
            out.extend_from_slice(b": ");
            crate::request::push_header_bytes(&mut out, value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        if head_only || self.omit_body {
            return out;
        }
        match self.chunk_size {
            Some(size) => {
                for chunk in self.body.chunks(size) {
                    out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                    out.extend_from_slice(chunk);
                    out.extend_from_slice(b"\r\n");
                }
                self.last_chunk(&mut out);
            }
            None if self.chunked_for_trailers => {
                if !self.body.is_empty() {
                    out.extend_from_slice(format!("{:x}\r\n", self.body.len()).as_bytes());
                    out.extend_from_slice(&self.body);
                    out.extend_from_slice(b"\r\n");
                }
                self.last_chunk(&mut out);
            }
            None => out.extend_from_slice(&self.body),
        }
        out
    }

    /// A hyper response (HTTP/2), after [`Reply::finalize`]. Connection-specific headers are dropped.
    pub fn into_hyper(self) -> Response<Full<Bytes>> {
        let mut builder = Response::builder().status(u16::try_from(self.status).ok().and_then(|s| StatusCode::from_u16(s).ok()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("keep-alive") {
                continue;
            }
            let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_bytes(&crate::request::header_bytes(value))) else {
                continue;
            };
            builder = builder.header(name, value);
        }
        builder.body(Full::new(self.body)).expect("status and headers were validated")
    }
}

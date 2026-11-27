//! A data-plane or control-plane request as MockServer models it: decoded, with multi-valued parameters.

use bytes::Bytes;

/// Ordered multi-valued map; names keep their original case and compare case-insensitively.
pub type MultiMap = Vec<(String, Vec<String>)>;

#[derive(Debug, Clone, Default)]
pub struct HttpRequest {
    pub method: String,
    /// Path as sent (not percent-decoded, matching the oracle), without the query string.
    pub path: String,
    /// `pathParameters`: empty on arrival; a data-plane match sets those the matched expectation extracted
    /// (`HttpRequestPropertiesMatcher` calls `withPathParameters` when the expectation declares any), in
    /// extraction order. Log entries, `REQUEST_RESPONSES` and verification read them back.
    pub path_parameters: MultiMap,
    pub query: MultiMap,
    /// `Parameters.rawParameterString`: the query string as received, forwarded unchanged until `query` is modified.
    pub raw_query: Option<String>,
    pub headers: MultiMap,
    pub cookies: Vec<(String, String)>,
    pub body: Bytes,
    /// The body as received when Netty's decompressor inflated it (`Content-Encoding: gzip|deflate`).
    pub original_body: Option<Bytes>,
    pub body_kind: BodyKind,
    /// A request definition's body given as an empty string (`StringBody("")`, a `debugMismatch` probe): the body
    /// matchers read `""` where a received request's empty body is null.
    pub empty_body_given: bool,
    pub keep_alive: bool,
    /// A request definition without `keepAlive` (a `debugMismatch` probe): `isKeepAlive()` is null.
    pub keep_alive_null: bool,
    pub secure: bool,
    /// `HTTP_1_1` or `HTTP_2`.
    pub protocol: &'static str,
    pub local_address: String,
    pub remote_address: String,
    /// `clientCertificateChain`: the TLS client's certificates, as serialised.
    pub client_certificates: std::sync::Arc<Vec<crate::tls::client_cert::ClientCertificate>>,
    /// The connection's `REMOTE_SOCKET`: the `CONNECT` (or SOCKS) target unmatched requests are proxied to.
    pub remote_target: Option<(String, u16)>,
    /// `socketAddress` (host, port, secure): set only on a request matched from its head (`respondBeforeBody`).
    pub socket_address: Option<(String, u16, bool)>,
    /// `logCorrelationId`: given on arrival at the data plane, shared by the request's log entries (empty before).
    pub log_correlation_id: String,
    /// Built in-process on behalf of an already authorised caller (an MCP tool calling `httpState` directly), so
    /// control-plane authentication and authorization do not apply again. Never set from a parsed request.
    pub trusted: bool,
}

/// The transport a request arrived on, for decisions that differ by protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http1,
    Http2,
    Http3,
}

/// How the body is classified when the request is logged or retrieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BodyKind {
    /// By its `Content-Type`, as MockServer's decoder classifies a received body.
    #[default]
    Received,
    /// A `StringBody` without a content type (`withBody(String)`): a gRPC request converted to JSON.
    PlainString,
    /// A `BinaryBody` without a content type (`withBody(byte[])`): a body cut by `maxLoggedBodyBytes`.
    Binary,
}

impl HttpRequest {
    /// [`HttpRequest::protocol`] as a [`Protocol`]; a request without one (built from JSON) counts as HTTP/1.1.
    pub fn transport(&self) -> Protocol {
        match self.protocol {
            "HTTP_2" => Protocol::Http2,
            "HTTP_3" => Protocol::Http3,
            _ => Protocol::Http1,
        }
    }

    /// `HttpRequest.isKeepAlive()` as matchers and templates read it: `None` (null upstream) for an HTTP/3 request,
    /// which `Http3RequestBridge` never gives one, and for a request definition that does not give one.
    pub fn keep_alive_flag(&self) -> Option<bool> {
        (self.transport() != Protocol::Http3 && !self.keep_alive_null).then_some(self.keep_alive)
    }

    /// The content type the body is classified by: `None` for a [`BodyKind::PlainString`] or [`BodyKind::Binary`] body.
    pub fn body_content_type(&self) -> Option<&str> {
        match self.body_kind {
            BodyKind::Received => self.first_header("content-type"),
            BodyKind::PlainString | BodyKind::Binary => None,
        }
    }

    pub fn first_header(&self, name: &str) -> Option<&str> {
        first(&self.headers, name)
    }

    /// `getBodyAsString()`: the body as upstream decodes a received one (`BodyDecoderEncoder.bytesToBody`), in the
    /// charset its `Content-Type` names or defaults to (ISO-8859-1 for string types other than JSON and XML), or,
    /// for a binary type, its base64; empty when there is no body.
    pub fn body_str(&self) -> std::borrow::Cow<'_, str> {
        if self.body_kind == BodyKind::Binary {
            use base64::Engine;
            return std::borrow::Cow::Owned(base64::engine::general_purpose::STANDARD.encode(&self.body));
        }
        crate::media_type::body_as_string(&self.body, self.body_content_type())
    }

    /// `getBodyAsJsonOrXmlString()`, what most control-plane handlers parse: a string-typed body read back as UTF-8
    /// (`text/plain` or a form carrying JSON), otherwise [`HttpRequest::body_str`].
    pub fn body_json_or_xml_str(&self) -> std::borrow::Cow<'_, str> {
        crate::media_type::body_as_json_or_xml_string(&self.body, self.body_content_type())
    }
}

pub fn first<'a>(map: &'a MultiMap, name: &str) -> Option<&'a str> {
    map.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.first())
        .map(String::as_str)
}

/// Appends `value` under `name`, merging with an existing entry of the same (case-insensitive) name.
pub fn push(map: &mut MultiMap, name: &str, value: String) {
    match map.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
        Some((_, values)) => values.push(value),
        None => map.push((name.to_string(), vec![value])),
    }
}

/// Appends `value` under `name` as upstream's `KeysToMultiValues` keys its entries: by the exact name, so names that
/// differ only in case stay distinct entries (`Host: h1` and `host: h2` are two), each grouped in first-occurrence
/// order (`getEntries()`). What message ingest uses (`FullHttpRequestToMockServerHttpRequest.setHeadersFromNettyRequest`,
/// `Headers.appendLiteral`); matching compares names case-insensitively pair by pair, and the template view merges
/// them again (`templates::model`, `CaseInsensitiveHeaderMap`).
pub fn append(map: &mut MultiMap, name: &str, value: String) {
    match map.iter_mut().find(|(k, _)| k == name) {
        Some((_, values)) => values.push(value),
        None => map.push((name.to_string(), vec![value])),
    }
}

/// A new `logCorrelationId`: a random UUID, written straight into its string rather than through `Display`.
pub fn new_correlation_id() -> String {
    let mut text = [0u8; uuid::fmt::Hyphenated::LENGTH];
    uuid::Uuid::new_v4().hyphenated().encode_lower(&mut text).to_string()
}

/// A header value as Netty reads it: one char per byte (`AsciiString.b2c`).
pub fn header_text(bytes: &[u8]) -> String {
    bytes.iter().map(|b| *b as char).collect()
}

/// A header value as Netty writes it: one byte per char, `?` for chars above U+00FF (`AsciiString.c2b`).
pub fn header_bytes(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    push_header_bytes(&mut out, text);
    out
}

/// [`header_bytes`] of `text`, appended to `out`.
pub fn push_header_bytes(out: &mut Vec<u8>, text: &str) {
    if text.is_ascii() {
        out.extend_from_slice(text.as_bytes());
    } else {
        out.extend(text.chars().map(|c| if (c as u32) > 0xff { b'?' } else { c as u8 }));
    }
}

/// `MockServerHttpRequestToFullHttpRequest.getURI`: the path with the raw query when there is one, else with the
/// parameters encoded.
pub fn uri(request: &HttpRequest) -> String {
    match request.raw_query.as_deref().filter(|q| !q.trim().is_empty()) {
        Some(raw) => format!("{}?{raw}", request.path),
        None if request.query.is_empty() => request.path.clone(),
        None => {
            let mut encoded = form_urlencoded::Serializer::new(String::new());
            for (k, values) in &request.query {
                for v in values {
                    encoded.append_pair(k, v);
                }
            }
            format!("{}?{}", request.path, encoded.finish())
        }
    }
}

/// The parameters of a request target's raw query: Netty's `QueryStringDecoder` stops at a `#` (the raw query keeps
/// it)..
pub fn parse_target_query(query: &str) -> MultiMap {
    parse_query(query.split('#').next().unwrap_or_default())
}

pub fn parse_query(query: &str) -> MultiMap {
    let mut map = MultiMap::new();
    for (k, v) in form_urlencoded::parse(query.as_bytes()) {
        push(&mut map, &k, v.into_owned());
    }
    map
}

/// Cookies as upstream's decoder builds them: each `Cookie` header through Netty's `ServerCookieDecoder`
/// (a set ordered by name that keeps the first of a repeated name), then into an insertion-ordered map where a
/// later header's value replaces an earlier one in place.
pub fn parse_cookies(headers: &MultiMap) -> Vec<(String, String)> {
    let mut cookies: Vec<(String, String)> = Vec::new();
    for (name, values) in headers {
        if !name.eq_ignore_ascii_case("cookie") {
            continue;
        }
        for header in values {
            let mut decoded = server_cookie_decoder_lax(header);
            decoded.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            for (k, v) in decoded {
                match cookies.iter_mut().find(|(c, _)| *c == k) {
                    Some((_, existing)) => *existing = v,
                    None => cookies.push((k, v)),
                }
            }
        }
    }
    cookies
}

/// One `Cookie` header through Netty 4.2's `ServerCookieDecoder.LAX` (`decode` and `CookieDecoder.initCookie`), in
/// header order, the first of a repeated name kept (its `TreeSet` keyed by name): separators (whitespace, `,`, `;`)
/// before a name are skipped; a value runs to the next `;` and keeps its spaces; a pair without `=` is dropped, and so
/// is a value whose opening quote is unbalanced, while a balanced pair of quotes is removed; the name is trimmed
/// (`DefaultCookie`), and a header starting `$Version` (any case) is RFC 2965 style: its first pair is skipped and so
/// are the names starting `$Path`, `$Domain` or `$Port`..
fn server_cookie_decoder_lax(header: &str) -> Vec<(String, String)> {
    let h: Vec<char> = header.chars().collect();
    let len = h.len();
    let mut decoded: Vec<(String, String)> = Vec::new();
    let mut i = 0;
    let rfc2965 = len >= 8 && h[..8].iter().collect::<String>().eq_ignore_ascii_case("$Version");
    if rfc2965 {
        i = h.iter().position(|&c| c == ';').map_or(0, |p| p + 1);
    }
    loop {
        while i < len && matches!(h[i], '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | ',' | ';') {
            i += 1;
        }
        if i == len {
            break;
        }
        let name_begin = i;
        let (name_end, value) = loop {
            match h[i] {
                ';' => break (i, None),
                '=' => {
                    let name_end = i;
                    i += 1;
                    if i == len {
                        break (name_end, Some((0, 0)));
                    }
                    let begin = i;
                    i = h[i..].iter().position(|&c| c == ';').map_or(len, |p| i + p);
                    break (name_end, Some((begin, i)));
                }
                _ => i += 1,
            }
            if i == len {
                break (len, None);
            }
        };
        let name: String = h[name_begin..name_end].iter().collect();
        if rfc2965 && (name.starts_with("$Path") || name.starts_with("$Domain") || name.starts_with("$Port")) {
            continue;
        }
        let Some((begin, end)) = value else { continue };
        if name_begin == name_end {
            continue;
        }
        let raw = &h[begin..end];
        let value: String = match raw.first() {
            Some('"') if raw.len() >= 2 && raw[raw.len() - 1] == '"' => raw[1..raw.len() - 1].iter().collect(),
            Some('"') => continue,
            _ => raw.iter().collect(),
        };
        let name = name.trim_matches(|c: char| c <= ' ').to_string(); // String.trim
        if !name.is_empty() && !decoded.iter().any(|(d, _)| *d == name) {
            decoded.push((name, value));
        }
    }
    decoded
}

/// The cookie of one `Set-Cookie` value through Netty 4.2's `ClientCookieDecoder.LAX.decode` (its name and value; the
/// attributes play no part here): separators before the name are skipped, a `,` there ends the header with no cookie,
/// the value runs to the next `;` less one trailing `,`, and `CookieDecoder.initCookie` drops a pair without `=` or
/// with an unbalanced opening quote, removes balanced quotes and trims the name (upstream's
/// `MockServerHttpToNettyHttpResponseEncoderCookieHeaderTest`).
pub fn client_cookie_decoder_lax(header: &str) -> Option<(String, String)> {
    let h: Vec<char> = header.chars().collect();
    let len = h.len();
    let mut i = 0;
    loop {
        if i == len || h[i] == ',' {
            return None;
        }
        if !matches!(h[i], '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | ';') {
            break;
        }
        i += 1;
    }
    let name_begin = i;
    let (name_end, begin, mut end) = loop {
        match h[i] {
            ';' => return None,
            '=' => {
                let name_end = i;
                i += 1;
                if i == len {
                    break (name_end, 0, 0);
                }
                let begin = i;
                let end = h[i..].iter().position(|&c| c == ';').map_or(len, |p| i + p);
                break (name_end, begin, end);
            }
            _ => i += 1,
        }
        if i == len {
            return None;
        }
    };
    if end > 0 && h[end - 1] == ',' {
        end -= 1;
    }
    if name_begin == name_end {
        return None;
    }
    let raw = &h[begin.min(end)..end];
    let value: String = match raw.first() {
        Some('"') if raw.len() >= 2 && raw[raw.len() - 1] == '"' => raw[1..raw.len() - 1].iter().collect(),
        Some('"') => return None,
        _ => raw.iter().collect(),
    };
    let name: String = h[name_begin..name_end].iter().collect();
    Some((name.trim_matches(|c: char| c <= ' ').to_string(), value))
}

/// Inflates a `gzip`/`x-gzip`/`deflate` body the way Netty's `HttpContentDecompressor` does; `None` when the
/// encoding is absent, unknown or the data is not valid.
pub fn decompress(encoding: Option<&str>, body: &[u8]) -> Option<Bytes> {
    use std::io::Read;
    let encoding = encoding?.trim().to_ascii_lowercase();
    let mut out = Vec::new();
    let ok = match encoding.as_str() {
        "gzip" | "x-gzip" => flate2::read::MultiGzDecoder::new(body).read_to_end(&mut out).is_ok(),
        "deflate" | "x-deflate" => {
            flate2::read::ZlibDecoder::new(body).read_to_end(&mut out).is_ok()
                || {
                    out.clear();
                    flate2::read::DeflateDecoder::new(body).read_to_end(&mut out).is_ok()
                }
        }
        _ => false,
    };
    ok.then(|| Bytes::from(out))
}

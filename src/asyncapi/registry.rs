//! `SchemaRegistryClient`: the two Confluent Schema Registry calls the Avro adapters make (`GET
//! /schemas/ids/{id}`, `POST /subjects/{subject}/versions`), cached, over a small HTTP/1.1 client that sends what
//! the JDK's `HttpClient` sends (including its `h2c` upgrade offer, continuing over HTTP/2 when the registry takes it)
//! and trusts what the JDK trusts by default.

use std::collections::HashMap;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::broker::Error;

/// `TIMEOUT`: connect and request.
const TIMEOUT: Duration = Duration::from_secs(5);
/// The JDK `HttpClient` the oracle image runs.
const USER_AGENT: &str = "Java-http-client/26.0.2";
const HTTP2_SETTINGS: &str = "AAEAAEAAAAIAAAAAAAMAAAAAAAQBAAAAAAUAAEAAAAYABgAA";

pub struct SchemaRegistryClient {
    base_url: String,
    schemas: Mutex<HashMap<i32, String>>,
    registrations: Mutex<HashMap<String, i32>>,
}

struct Response {
    status: u16,
    body: String,
}

impl SchemaRegistryClient {
    /// `new SchemaRegistryClient(baseUrl)`.
    pub fn new(base_url: &str) -> Result<Self, Error> {
        if base_url.trim().is_empty() {
            return Err(Error::illegal("Schema Registry URL must not be blank"));
        }
        let base_url = base_url.strip_suffix('/').unwrap_or(base_url).to_string();
        Ok(SchemaRegistryClient { base_url, schemas: Mutex::new(HashMap::new()), registrations: Mutex::new(HashMap::new()) })
    }

    /// `getSchemaById`.
    pub async fn schema_by_id(&self, id: i32) -> Result<String, Error> {
        if let Some(cached) = self.schemas.lock().get(&id) {
            return Ok(cached.clone());
        }
        let response = self
            .send("GET", &format!("{}/schemas/ids/{id}", self.base_url), None)
            .await
            .map_err(|e| match e {
                Failure::Runtime(e) => e,
                Failure::Io(m) => Error::new(format!("Failed to fetch schema id {id} from Schema Registry: {m}")),
            })?;
        if response.status != 200 {
            return Err(Error::new(format!("Schema Registry returned status {} for schema id {id}: {}", response.status, response.body)));
        }
        let node: serde_json::Value = serde_json::from_str(&response.body).map_err(|e| Error::new(format!("Failed to fetch schema id {id} from Schema \
            Registry: {e}")))?;
        let schema = match node.get("schema") {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => return Err(Error::new(format!("Schema Registry response for id {id} has no 'schema' field"))),
        };
        self.schemas.lock().insert(id, schema.clone());
        Ok(schema)
    }

    /// `register(subject, schemaJson)`: the id the registry answers, cached per subject and schema.
    pub async fn register(&self, subject: &str, schema_json: &str) -> Result<i32, Error> {
        let key = format!("{subject} {schema_json}");
        if let Some(id) = self.registrations.lock().get(&key) {
            return Ok(*id);
        }
        let body = serde_json::json!({"schema": schema_json, "schemaType": "AVRO"}).to_string();
        let url = format!("{}/subjects/{}/versions", self.base_url, encode_path_segment(subject));
        let response = self.send("POST", &url, Some(&body)).await.map_err(|e| match e {
            Failure::Runtime(e) => e,
            Failure::Io(m) => Error::new(format!("Failed to register schema under subject '{subject}': {m}")),
        })?;
        if response.status != 200 {
            return Err(Error::new(format!("Schema Registry returned status {} registering subject '{subject}': {}", response.status, response.body)));
        }
        let node: serde_json::Value = serde_json::from_str(&response.body).map_err(|e| Error::new(format!("Failed to register schema under subject \
            '{subject}': {e}")))?;
        let Some(id) = node.get("id") else {
            return Err(Error::new(format!("Schema Registry registration response has no 'id' field: {}", response.body)));
        };
        let id = match id {
            serde_json::Value::Number(n) => n.as_i64().map(|i| i as i32).unwrap_or_else(|| n.as_f64().unwrap_or(0.0) as i32),
            serde_json::Value::String(s) => s.trim().parse().unwrap_or(0),
            serde_json::Value::Bool(b) => *b as i32,
            _ => 0,
        };
        self.registrations.lock().insert(key, id);
        Ok(id)
    }

    async fn send(&self, method: &str, url: &str, body: Option<&str>) -> Result<Response, Failure> {
        // `URI.create` then `HttpRequest.newBuilder(uri)`: their `IllegalArgumentException`s pass through as is.
        let uri = crate::java_uri::parse(url).map_err(|e| Failure::Runtime(Error::new(e)))?;
        let scheme = match uri.scheme.as_deref().map(str::to_ascii_lowercase) {
            None => return Err(Failure::Runtime(Error::new("URI with undefined scheme"))),
            Some(s) if s == "http" || s == "https" => s,
            Some(s) => return Err(Failure::Runtime(Error::new(format!("invalid URI scheme {s}")))),
        };
        let Some(host) = uri.host.clone() else { return Err(Failure::Runtime(Error::new(format!("unsupported URI {url}")))) };
        let secure = scheme == "https";
        let port = if uri.port >= 0 { uri.port as u16 } else if secure { 443 } else { 80 };
        let mut target = uri.raw_path.clone().filter(|p| !p.is_empty()).unwrap_or_else(|| "/".into());
        if let Some(q) = &uri.raw_query {
            target.push('?');
            target.push_str(q);
        }
        let authority = if uri.port >= 0 { format!("{host}:{port}") } else { host.clone() };
        let mut head = format!("{method} {target} HTTP/1.1\r\n");
        if !secure {
            head.push_str("Connection: Upgrade, HTTP2-Settings\r\n");
        }
        if let Some(body) = body {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str(&format!("Host: {authority}\r\n"));
        if !secure {
            head.push_str(&format!("HTTP2-Settings: {HTTP2_SETTINGS}\r\nUpgrade: h2c\r\n"));
        }
        head.push_str(&format!("User-Agent: {USER_AGENT}\r\n"));
        if body.is_some() {
            head.push_str("Content-Type: application/vnd.schemaregistry.v1+json\r\n");
        }
        head.push_str("\r\n");
        let mut request = head.into_bytes();
        request.extend_from_slice(body.unwrap_or("").as_bytes());
        let tls = if secure {
            let refusal = super::tls::Refusal::default();
            let tls = super::tls::ClientTls { refusal: Some(refusal.clone()), ..Default::default() };
            Some((tls.config().map_err(|e| Failure::Io(e.message))?, refusal))
        } else {
            None
        };
        let exchange = async {
            // `java.net.http.HttpClient` names every host but an IP literal in SNI, `localhost` too.
            let stream = super::tls::dial_alertless(&host, port, TIMEOUT, tls).await.map_err(|e| match e {
                super::tls::DialError::Timeout => Failure::Io("HTTP connect timed out".into()),
                super::tls::DialError::Connect(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Failure::Io("Connection refused".into()),
                super::tls::DialError::Handshake(e) => Failure::Io(jsse_handshake_message(&e)),
                // `UnresolvedAddressException` has no message.
                super::tls::DialError::Lookup(_) | super::tls::DialError::Connect(_) => Failure::Io("null".into()),
            })?;
            round_trip(stream, &request).await
        };
        match tokio::time::timeout(TIMEOUT, exchange).await {
            Err(_) => Err(Failure::Io("request timed out".into())),
            Ok(r) => r,
        }
    }
}

enum Failure {
    /// A `RuntimeException` upstream rethrows unwrapped.
    Runtime(Error),
    /// An `IOException`: wrapped with the operation.
    Io(String),
}

/// JSSE's text for a server certificate the default trust does not accept; rustls' otherwise.
fn jsse_handshake_message(e: &std::io::Error) -> String {
    match e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
        Some(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)) => {
            "(certificate_unknown) PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification \
                path to requested target".into()
        }
        _ => super::tls::jsse_message(e),
    }
}

/// `jdk.http.maxHeaderSize`'s default (`Http1HeaderParser`).
const MAX_HEADER_SIZE: usize = 384 * 1024;

/// `Http1HeaderParser`'s size accounting over a response head received so far (`data`, up to its blank line when
/// `complete`): the status line and each header count 32 bytes over their text (a header its name and trimmed value),
/// a line still being read its raw length. `ProtocolException`'s text once the total passes the limit.
fn check_header_size(data: &[u8], complete: bool) -> Result<(), String> {
    let too_big = |s: usize| Err(format!("Header size too big: {s} > {MAX_HEADER_SIZE}"));
    let mut size = 0usize;
    // A line in progress: once it begins, its first char counts (`checkMaxHeaderSize(1)` may report more than one
    // over), then every further char up to one over.
    let open = |size: usize, length: usize| if size + 33 > MAX_HEADER_SIZE { too_big(size + 33) } else if size + length + 32 > MAX_HEADER_SIZE { too_big(MAX_HEADER_SIZE + 1) } else { Ok(()) };
    let mut lines = data.split(|b| *b == b'\n').peekable();
    let Some(status) = lines.next() else { return Ok(()) };
    let status = status.strip_suffix(b"\r").unwrap_or(status);
    if status.len() + 32 > MAX_HEADER_SIZE {
        return too_big(MAX_HEADER_SIZE + 1);
    }
    if lines.peek().is_none() {
        return Ok(());
    }
    size += 32 + status.len();
    // The header being folded (continuation lines join it with one space).
    let mut header: Vec<u8> = Vec::new();
    let flush = |size: &mut usize, header: &mut Vec<u8>| {
        if let Some(colon) = header.iter().position(|b| *b == b':').filter(|i| *i > 0) {
            let value = String::from_utf8_lossy(&header[colon + 1..]).trim().len();
            *size += colon + value + 32;
        }
        header.clear();
    };
    while let Some(line) = lines.next() {
        let last = lines.peek().is_none();
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() && !last {
            break;
        }
        if line.is_empty() {
            return Ok(());
        }
        if matches!(line[0], b' ' | b'\t') && !header.is_empty() {
            header.push(b' ');
            header.extend(line[1..].iter().map(|b| if *b == b'\t' { b' ' } else { *b }));
            if size + header.len() + 32 > MAX_HEADER_SIZE {
                return too_big(MAX_HEADER_SIZE + 1);
            }
        } else {
            flush(&mut size, &mut header);
            header.extend(line.iter().map(|b| if *b == b'\t' { b' ' } else { *b }));
            open(size, header.len())?;
        }
        if size > MAX_HEADER_SIZE {
            return too_big(size);
        }
    }
    if complete {
        flush(&mut size, &mut header);
        if size > MAX_HEADER_SIZE {
            return too_big(size);
        }
    }
    Ok(())
}

/// Writes the request and reads one response (by `Content-Length`, chunked, or to the end); a `101` to the `h2c`
/// offer continues over HTTP/2, the response then coming on stream 1 (`Http2Connection.createAsync` of an upgrade).
/// The body is read whole, as `BodyHandlers.ofString` does.
async fn round_trip<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, request: &[u8]) -> Result<Response, Failure> {
    let io = |e: std::io::Error| Failure::Io(if e.kind() == std::io::ErrorKind::ConnectionReset { "Connection reset".into() } else { e.to_string() });
    stream.write_all(request).await.map_err(io)?;
    stream.flush().await.map_err(io)?;
    let mut data = Vec::new();
    let mut buf = [0u8; 8192];
    // Where the search for the end of the head resumes.
    let mut searched: usize = 0;
    loop {
        let head_end = data[searched.saturating_sub(3)..].windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + searched.saturating_sub(3));
        searched = data.len();
        check_header_size(&data[..head_end.map_or(data.len(), |end| end + 4)], head_end.is_some()).map_err(Failure::Io)?;
        if let Some(end) = head_end {
            let head = String::from_utf8_lossy(&data[..end]).into_owned();
            let mut lines = head.split("\r\n");
            let status: u16 = lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse().ok()).unwrap_or(0);
            if status == 101 {
                data.drain(..end + 4);
                return h2c::response(stream, data).await;
            }
            if (100..200).contains(&status) {
                data.drain(..end + 4);
                searched = 0;
                continue;
            }
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())))
                .collect();
            let header = |n: &str| headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
            let mut body = data[end + 4..].to_vec();
            if let Some(length) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
                while body.len() < length {
                    let n = stream.read(&mut buf).await.map_err(io)?;
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&buf[..n]);
                }
                body.truncate(length);
            } else if header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
                let mut chunks = Dechunker::default();
                loop {
                    if chunks.feed(&body) {
                        break;
                    }
                    let n = stream.read(&mut buf).await.map_err(io)?;
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&buf[..n]);
                }
                body = chunks.out;
            } else {
                loop {
                    let n = stream.read(&mut buf).await.map_err(io)?;
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&buf[..n]);
                }
            }
            return Ok(Response { status, body: String::from_utf8_lossy(&body).into_owned() });
        }
        let n = stream.read(&mut buf).await.map_err(io)?;
        if n == 0 {
            return Err(Failure::Io("HTTP/1.1 header parser received no bytes".into()));
        }
        data.extend_from_slice(&buf[..n]);
    }
}

/// The JDK client's side of a connection the registry upgraded to HTTP/2 (`h2c`): the request went out as HTTP/1.1
/// and is stream 1, half-closed; the client sends its preface (the settings its `HTTP2-Settings` offered and a
/// connection window update) and reads the response off stream 1, opening the windows as it consumes DATA.
mod h2c {
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use super::{Failure, HTTP2_SETTINGS, Response};

    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const DATA: u8 = 0x0;
    const HEADERS: u8 = 0x1;
    const RST_STREAM: u8 = 0x3;
    const SETTINGS: u8 = 0x4;
    const PING: u8 = 0x6;
    const GOAWAY: u8 = 0x7;
    const CONTINUATION: u8 = 0x9;
    const END_STREAM: u8 = 0x1;
    const ACK: u8 = 0x1;
    const END_HEADERS: u8 = 0x4;
    const PADDED: u8 = 0x8;
    const PRIORITY: u8 = 0x20;
    /// The connection window the JDK opens to (`jdk.httpclient.connectionWindowSize`, 32 MiB).
    const CONNECTION_WINDOW: u32 = 32 * 1024 * 1024;
    /// `SETTINGS_MAX_FRAME_SIZE` as offered.
    const MAX_FRAME: usize = 16384;

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + payload.len());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        out.push(kind);
        out.push(flags);
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn window_update(stream: u32, increment: u32) -> Vec<u8> {
        frame(0x8, 0, stream, &increment.to_be_bytes())
    }

    /// The offered settings (`HTTP2-Settings` is their payload, base64url).
    fn settings() -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(HTTP2_SETTINGS).expect("static settings")
    }

    pub(super) async fn response<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, mut data: Vec<u8>) -> Result<Response, Failure> {
        let io = |e: std::io::Error| Failure::Io(if e.kind() == std::io::ErrorKind::ConnectionReset { "Connection reset".into() } else { e.to_string() });
        let closed = || Failure::Io("EOF reached while reading".into());
        let mut hello = PREFACE.to_vec();
        hello.extend(frame(SETTINGS, 0, 0, &settings()));
        hello.extend(window_update(0, CONNECTION_WINDOW - 65535));
        stream.write_all(&hello).await.map_err(io)?;
        stream.flush().await.map_err(io)?;
        let mut decoder = loona_hpack::Decoder::new();
        let mut block: Vec<u8> = Vec::new();
        let mut block_ends_stream = false;
        let mut status: Option<u16> = None;
        let mut body: Vec<u8> = Vec::new();
        let mut buf = [0u8; 16384];
        loop {
            while data.len() < 9 || data.len() < 9 + (((data[0] as usize) << 16) | ((data[1] as usize) << 8) | data[2] as usize) {
                if data.len() >= 9 && (((data[0] as usize) << 16) | ((data[1] as usize) << 8) | data[2] as usize) > MAX_FRAME {
                    return Err(Failure::Io("Protocol error: frame too large".into()));
                }
                let n = stream.read(&mut buf).await.map_err(io)?;
                if n == 0 {
                    return Err(closed());
                }
                data.extend_from_slice(&buf[..n]);
            }
            let length = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | data[2] as usize;
            let (kind, flags) = (data[3], data[4]);
            let id = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) & 0x7fff_ffff;
            let mut payload: Vec<u8> = data[9..9 + length].to_vec();
            data.drain(..9 + length);
            let mut reply = Vec::new();
            let mut ended = false;
            match kind {
                SETTINGS if flags & ACK == 0 => reply.extend(frame(SETTINGS, ACK, 0, &[])),
                PING if flags & ACK == 0 => reply.extend(frame(PING, ACK, 0, &payload)),
                GOAWAY => return Err(closed()),
                RST_STREAM if id == 1 => {
                    let code = payload.get(..4).map_or(0, |c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
                    return Err(Failure::Io(format!("Stream 1 cancelled ({code})")));
                }
                HEADERS | CONTINUATION if id == 1 => {
                    if kind == HEADERS {
                        block_ends_stream = flags & END_STREAM != 0;
                        let mut pad = 0;
                        if flags & PADDED != 0 && !payload.is_empty() {
                            pad = payload.remove(0) as usize;
                        }
                        if flags & PRIORITY != 0 && payload.len() >= 5 {
                            payload.drain(..5);
                        }
                        payload.truncate(payload.len().saturating_sub(pad));
                        block.clear();
                    }
                    block.extend_from_slice(&payload);
                    if flags & END_HEADERS != 0 {
                        let fields = decoder.decode(&block).map_err(|e| Failure::Io(format!("{e:?}")))?;
                        let code = fields.iter().find(|(n, _)| n == b":status").and_then(|(_, v)| std::str::from_utf8(v).ok()?.parse::<u16>().ok());
                        // An interim head is skipped; a block after the final one is trailers.
                        if status.is_none() {
                            status = code.filter(|s| !(100..200).contains(s));
                        }
                        ended = block_ends_stream;
                    }
                }
                DATA if id == 1 => {
                    let flow = payload.len() as u32;
                    if flags & PADDED != 0 && !payload.is_empty() {
                        let pad = payload.remove(0) as usize;
                        payload.truncate(payload.len().saturating_sub(pad));
                    }
                    body.extend_from_slice(&payload);
                    ended = flags & END_STREAM != 0;
                    if flow > 0 && !ended {
                        reply.extend(window_update(0, flow));
                        reply.extend(window_update(1, flow));
                    }
                }
                _ => {}
            }
            if ended {
                let Some(status) = status else { return Err(closed()) };
                return Ok(Response { status, body: String::from_utf8_lossy(&body).into_owned() });
            }
            if !reply.is_empty() {
                stream.write_all(&reply).await.map_err(io)?;
                stream.flush().await.map_err(io)?;
            }
        }
    }
}

/// A chunked body decoded as it arrives: each call resumes where the last complete chunk ended.
#[derive(Default)]
struct Dechunker {
    at: usize,
    out: Vec<u8>,
}

impl Dechunker {
    /// Decodes what `data` (the whole body so far) holds past the last complete chunk; true at the last chunk or
    /// on a malformed size line.
    fn feed(&mut self, data: &[u8]) -> bool {
        loop {
            let Some(line_end) = data[self.at..].windows(2).position(|w| w == b"\r\n").map(|i| i + self.at) else { return false };
            let line = String::from_utf8_lossy(&data[self.at..line_end]);
            let Ok(size) = usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16) else { return true };
            if size == 0 {
                return true;
            }
            let start = line_end + 2;
            let Some(end) = start.checked_add(size).filter(|end| data.len() >= end + 2) else { return false };
            self.out.extend_from_slice(&data[start..end]);
            self.at = end + 2;
        }
    }
}

/// `encodePathSegment`: `URLEncoder.encode` (UTF-8) with `+` turned into `%20`.
fn encode_path_segment(segment: &str) -> String {
    let mut out = String::new();
    for b in segment.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => out.push(b as char),
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subjects_are_encoded_as_url_encoder_does() {
        assert_eq!(encode_path_segment("orders/created-value"), "orders%2Fcreated-value");
        assert_eq!(encode_path_segment("a b~c"), "a%20b%7Ec");
        assert_eq!(SchemaRegistryClient::new("  ").err().unwrap().message, "Schema Registry URL must not be blank");
    }

    #[test]
    fn chunked_bodies_are_decoded_as_they_arrive() {
        let mut chunks = Dechunker::default();
        assert!(!chunks.feed(b"3\r\nab"));
        assert!(!chunks.feed(b"3\r\nabc\r\n2\r"));
        assert_eq!(chunks.out, b"abc");
        assert!(chunks.feed(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"));
        assert_eq!(chunks.out, b"abcde");
        let mut huge = Dechunker::default();
        assert!(!huge.feed(b"ffffffffffffffff\r\n"), "a size past the address space waits instead of overflowing");
    }

    /// The bounds JDK 25's `HttpClient` showed against a stand-in: `X-Big` values of 393083 bytes pass, 393084 do
    /// not (status line 15 + 32, `X-Big` 5 + value + 32, then the `Content-Length: 2` line read raw, 17 + 32).
    #[test]
    fn response_heads_are_bounded_as_the_jdk_bounds_them() {
        let head = |size: usize| format!("HTTP/1.1 200 OK\r\nX-Big: {}\r\nContent-Length: 2\r\n\r\n", "a".repeat(size)).into_bytes();
        assert_eq!(check_header_size(&head(393083), true), Ok(()));
        assert_eq!(check_header_size(&head(393084), true), Err("Header size too big: 393217 > 393216".into()));
        // While the head is still arriving.
        let partial = head(400000);
        assert_eq!(check_header_size(&partial[..393300], false), Err("Header size too big: 393217 > 393216".into()));
        assert_eq!(check_header_size(&partial[..300000], false), Ok(()));
        // A line that begins past the limit reports where it began.
        let mut lines = b"HTTP/1.1 200 OK\r\n".to_vec();
        lines.extend(format!("X: {}\r\nY: 1\r\n\r\n", "a".repeat(MAX_HEADER_SIZE - 47 - 32 - 1 - 2)).bytes());
        assert_eq!(check_header_size(&lines, true), Err(format!("Header size too big: {} > 393216", MAX_HEADER_SIZE - 2 + 33)));
    }
}

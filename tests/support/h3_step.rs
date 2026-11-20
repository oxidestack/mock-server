//! An `"h3"` step's client for replay (tests/oracle.rs, `send_h3`): one HTTP/3 request on a fresh QUIC
//! connection, written and read as raw HTTP/3 frames over quinn, so that whatever the server sends (even DATA before
//! any HEADERS, or nothing at all before FIN) is seen as sent. Recording uses the same exchange written in Python over
//! aioquic (`h3_step.py`), run in a sidecar sharing the oracle container's network namespace. Both report
//! [`Exchange`] as the same JSON.
//!
//! The request's field section is QPACK with static-table indexed lines and literals without Huffman coding; the client advertises no dynamic
//! table (an empty SETTINGS frame), so the answer's field sections are decoded with the static table alone.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

/// One request: pseudo-headers from `method`, `path` and `authority` (scheme `https`), then `headers` in order.
pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub authority: &'a str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// A trailer section sent after the body, when not empty.
    pub trailers: Vec<(String, String)>,
    /// How long to wait, once the stream has ended, for the server to close the connection.
    pub close_wait: Duration,
    /// The client grants the request stream [`STALL_WINDOW`] bytes and reads nothing (so grants no more)
    /// for this long, as a client that stopped reading; then it reads as usual.
    pub stall: Option<Duration>,
}

/// The stream credit a stalling client grants (`Http3ResponseWriteStallTimeoutIntegrationTest.STREAM_CREDIT_BYTES`).
pub const STALL_WINDOW: u32 = 64 * 1024;

/// What a stalling client reads of the stream: under an eighth of [`STALL_WINDOW`], so no credit is returned.
const STALL_HEAD: usize = 4096;

/// What came back on the request stream: `{"frames": [{"headers": [[name, value], …]} | {"data": base64} |
/// {"frame": type}], "end": "fin" | "reset <code>" | "connection closed" | "timeout"}`, plus
/// `"settings": {"<id>": value, …}`, the server's SETTINGS frame, and, when the server closed the connection (waiting
/// up to the request's `close_wait` after the stream ended), `"closed":
/// {"application": bool, "code": n, "reason": text}`.
pub type Exchange = Value;

pub async fn exchange(port: u16, tls: rustls::ClientConfig, request: &Request<'_>, timeout: Duration) -> Exchange {
    // Keep-alive PINGs while the server works on an answer. The server's idle timeout
    // (`http3MaxIdleTimeout`, 5 s by default) also bounds a silent wait for the response, and a replay's server
    // resolves names through the host's resolver: a CONNECT-UDP target that does not resolve was answered by
    // macOS's mDNSResponder in exactly 5.00 s under load, so the connection idled out before the 403 came back.
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(1)));
    if request.stall.is_some() {
        // quinn grants a stream more credit only as the application reads it
        transport.stream_receive_window(STALL_WINDOW.into());
    }
    let Some((endpoint, connection)) = connect(port, tls, transport, timeout).await else {
        return json!({"frames": [], "end": "no connection"});
    };
    // The client's control stream: its type, then an empty SETTINGS frame (no QPACK dynamic table).
    let mut control = connection.open_uni().await.expect("h3 step: control stream");
    let _ = control.write_all(&[0x00, 0x04, 0x00]).await;
    let settings = tokio::spawn(server_settings(connection.clone()));
    let (mut send, mut recv) = connection.open_bi().await.expect("h3 step: request stream");
    let _ = send.write_all(&request_bytes(request)).await;
    let _ = send.finish();
    let mut received = Vec::new();
    let mut stalled_end = None;
    if let Some(stall) = request.stall {
        // Up to STALL_HEAD bytes are read during the stall, enough for the HEADERS frame and the start of DATA: quinn
        // returns credit only once an eighth of the window has been read, and drops what is unread when the stream is
        // reset.
        let _ = tokio::time::timeout(stall, async {
            let mut buf = [0u8; STALL_HEAD];
            while received.len() < STALL_HEAD {
                match recv.read(&mut buf[..STALL_HEAD - received.len()]).await {
                    Ok(Some(n)) => received.extend_from_slice(&buf[..n]),
                    Ok(None) => return stalled_end = Some("fin".to_string()),
                    Err(quinn::ReadError::Reset(code)) => return stalled_end = Some(format!("reset {}", code.into_inner())),
                    Err(_) => return stalled_end = Some("connection closed".to_string()),
                }
            }
            std::future::pending::<()>().await;
        })
        .await;
    }
    let end = tokio::time::timeout(timeout, async {
        if let Some(end) = stalled_end {
            return end;
        }
        let mut buf = [0u8; 16384];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => received.extend_from_slice(&buf[..n]),
                Ok(None) => return "fin".to_string(),
                Err(quinn::ReadError::Reset(code)) => return format!("reset {}", code.into_inner()),
                Err(_) => return "connection closed".to_string(),
            }
        }
    })
    .await
    .unwrap_or_else(|_| "timeout".to_string());
    let wait = if end == "connection closed" { request.close_wait.max(Duration::from_secs(1)) } else { request.close_wait };
    let closed = tokio::time::timeout(wait, connection.closed()).await.ok().and_then(|e| close_error(&e));
    let settings = tokio::time::timeout(Duration::from_millis(200), settings).await.ok().and_then(Result::ok).unwrap_or_default();
    connection.close(0u32.into(), b"");
    endpoint.close(0u32.into(), b"");
    let mut out = json!({"frames": frames(&received), "end": end, "settings": settings});
    if let Some(closed) = closed {
        out["closed"] = closed;
    }
    out
}

/// How the server closed the connection: `{"application": bool, "code": n, "reason": text}`.
fn close_error(error: &quinn::ConnectionError) -> Option<Value> {
    match error {
        quinn::ConnectionError::ApplicationClosed(close) => {
            Some(json!({"application": true, "code": close.error_code.into_inner(), "reason": String::from_utf8_lossy(&close.reason)}))
        }
        quinn::ConnectionError::ConnectionClosed(close) => {
            Some(json!({"application": false, "code": u64::from(close.error_code), "reason": String::from_utf8_lossy(&close.reason)}))
        }
        _ => None,
    }
}

/// The SETTINGS frame on the server's control stream, as `{"<id>": value}`.
async fn server_settings(connection: quinn::Connection) -> serde_json::Map<String, Value> {
    let mut settings = serde_json::Map::new();
    while let Ok(mut uni) = connection.accept_uni().await {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            // the stream type, then SETTINGS (type 0x04) and its length
            if let Some((0x00, at)) = varint(&buf, 0) {
                if let Some((0x04, at)) = varint(&buf, at) {
                    if let Some((length, at)) = varint(&buf, at) && buf.len() >= at + length as usize {
                        let mut at2 = at;
                        while at2 < at + length as usize {
                            let Some((id, next)) = varint(&buf, at2) else { break };
                            let Some((value, next)) = varint(&buf, next) else { break };
                            settings.insert(id.to_string(), json!(value));
                            at2 = next;
                        }
                        return settings;
                    }
                } else if buf.len() > 1 {
                    break;
                }
            } else if !buf.is_empty() {
                break;
            }
            match uni.read(&mut chunk).await {
                Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
                _ => break,
            }
        }
    }
    settings
}

/// A request stream's bytes as `[{"headers": [[name, value], …]} | {"data": base64} | {"frame": type}]`.
fn frames(received: &[u8]) -> Vec<Value> {
    use base64::Engine;
    let mut frames = Vec::new();
    let mut at = 0;
    while at < received.len() {
        let Some((kind, next)) = varint(received, at) else { break };
        let Some((length, next)) = varint(received, next) else { break };
        let payload = &received[next..(next + length as usize).min(received.len())];
        at = next + length as usize;
        frames.push(match kind {
            0x01 => json!({"headers": decode_field_section(payload).into_iter().map(|(n, v)| json!([n, v])).collect::<Vec<_>>()}),
            0x00 => json!({"data": base64::engine::general_purpose::STANDARD.encode(payload)}),
            other => json!({"frame": other}),
        });
    }
    frames
}

/// The connection credit a client stalling a connection grants: more than a holder stream takes in
/// `holderBytes` (half the smaller grant, 48 KiB here), less than a stream may take.
pub const CONNECTION_STALL_WINDOW: u32 = 96 * 1024;

/// The stream credit a client stalling a connection grants: more than the connection's.
pub const CONNECTION_STALL_STREAM_WINDOW: u32 = 1024 * 1024;

/// The pause between a stream's first bytes and the next request of [`exchange_streams`], for the server to send
/// what the connection's credit allows.
const NEXT_STREAM_PAUSE: Duration = Duration::from_millis(50);

/// Several requests on one QUIC connection, each sent [`NEXT_STREAM_PAUSE`] after the first bytes of the
/// one before arrived, so an earlier stream may hold the connection's credit. With `stall`, the client grants the
/// connection [`CONNECTION_STALL_WINDOW`] bytes and each stream [`CONNECTION_STALL_STREAM_WINDOW`], and reads at most
/// [`STALL_HEAD`] bytes of each stream (so returns no credit) until `stall` after the first request; then it reads as
/// usual. quinn also returns the credit a reset stream held at once, as it drops what is unread. `{"streams":
/// [Exchange, …]}`, in request order.
pub async fn exchange_streams(port: u16, tls: rustls::ClientConfig, requests: &[Request<'_>], stall: Option<Duration>, timeout: Duration) -> Value {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(1)));
    if stall.is_some() {
        transport.receive_window(CONNECTION_STALL_WINDOW.into());
        transport.stream_receive_window(CONNECTION_STALL_STREAM_WINDOW.into());
    }
    let Some((endpoint, connection)) = connect(port, tls, transport, timeout).await else {
        return json!({"streams": requests.iter().map(|_| json!({"frames": [], "end": "no connection"})).collect::<Vec<_>>()});
    };
    let mut control = connection.open_uni().await.expect("h3 step: control stream");
    let _ = control.write_all(&[0x00, 0x04, 0x00]).await;
    let stall_ends = stall.map(|stall| tokio::time::Instant::now() + stall);
    let mut readers = Vec::new();
    for (i, request) in requests.iter().enumerate() {
        let (mut send, mut recv) = connection.open_bi().await.expect("h3 step: request stream");
        let _ = send.write_all(&request_bytes(request)).await;
        let _ = send.finish();
        let mut head = Vec::new();
        let mut early_end = None;
        if i + 1 < requests.len() {
            let mut buf = [0u8; STALL_HEAD];
            match tokio::time::timeout(timeout, recv.read(&mut buf)).await {
                Ok(Ok(Some(n))) => head.extend_from_slice(&buf[..n]),
                Ok(Ok(None)) => early_end = Some("fin".to_string()),
                Ok(Err(e)) => early_end = Some(read_error(e)),
                Err(_) => early_end = Some("timeout".to_string()),
            }
            tokio::time::sleep(NEXT_STREAM_PAUSE).await;
        }
        readers.push(tokio::spawn(read_stream(recv, head, early_end, stall_ends, timeout)));
    }
    let mut streams = Vec::new();
    for reader in readers {
        let (received, end) = reader.await.expect("h3 step: stream reader");
        streams.push(json!({"frames": frames(&received), "end": end}));
    }
    connection.close(0u32.into(), b"");
    endpoint.close(0u32.into(), b"");
    json!({"streams": streams})
}

/// One stream of [`exchange_streams`]: until `stall_ends` at most [`STALL_HEAD`] bytes are read, then up to its end.
async fn read_stream(mut recv: quinn::RecvStream, mut received: Vec<u8>, early_end: Option<String>, stall_ends: Option<tokio::time::Instant>, timeout: Duration) -> (Vec<u8>, String) {
    if let Some(end) = early_end {
        return (received, end);
    }
    let mut stalled_end = None;
    if let Some(until) = stall_ends {
        let _ = tokio::time::timeout_at(until, async {
            let mut buf = [0u8; STALL_HEAD];
            while received.len() < STALL_HEAD {
                match recv.read(&mut buf[..STALL_HEAD - received.len()]).await {
                    Ok(Some(n)) => received.extend_from_slice(&buf[..n]),
                    Ok(None) => return stalled_end = Some("fin".to_string()),
                    Err(e) => return stalled_end = Some(read_error(e)),
                }
            }
            std::future::pending::<()>().await;
        })
        .await;
    }
    if let Some(end) = stalled_end {
        return (received, end);
    }
    let end = tokio::time::timeout(timeout, async {
        let mut buf = [0u8; 16384];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => received.extend_from_slice(&buf[..n]),
                Ok(None) => return "fin".to_string(),
                Err(e) => return read_error(e),
            }
        }
    })
    .await
    .unwrap_or_else(|_| "timeout".to_string());
    (received, end)
}

fn read_error(e: quinn::ReadError) -> String {
    match e {
        quinn::ReadError::Reset(code) => format!("reset {}", code.into_inner()),
        _ => "connection closed".to_string(),
    }
}

async fn connect(port: u16, mut tls: rustls::ClientConfig, transport: quinn::TransportConfig, timeout: Duration) -> Option<(quinn::Endpoint, quinn::Connection)> {
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("h3 step: a TLS 1.3 client config");
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("h3 step: client endpoint");
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    client.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client);
    match tokio::time::timeout(timeout, endpoint.connect(([127, 0, 0, 1], port).into(), "localhost").expect("h3 step: connect")).await {
        Ok(Ok(c)) => Some((endpoint, c)),
        _ => None,
    }
}

/// The request's HEADERS frame, then its body as one DATA frame, then its trailers as a second HEADERS frame.
fn request_bytes(request: &Request<'_>) -> Vec<u8> {
    let pseudo = [(":method", request.method), (":scheme", "https"), (":authority", request.authority), (":path", request.path)];
    let fields: Vec<(String, String)> = pseudo.iter().map(|(n, v)| (n.to_string(), v.to_string())).chain(request.headers.iter().cloned()).collect();
    let mut bytes = frame(0x01, &field_section(&fields));
    if !request.body.is_empty() {
        bytes.extend(frame(0x00, &request.body));
    }
    if !request.trailers.is_empty() {
        bytes.extend(frame(0x01, &field_section(&request.trailers)));
    }
    bytes
}

/// A field section: a field the static table holds whole as an indexed line, any other as a literal field line
/// without Huffman coding. `h3_step.py`'s `field_section` writes the same bytes, so a section is as long
/// on the wire whichever client sends it.
fn field_section(fields: &[(String, String)]) -> Vec<u8> {
    let mut block = vec![0, 0];
    for (name, value) in fields {
        let name = name.to_ascii_lowercase();
        match STATIC.iter().position(|(n, v)| *n == name && *v == value) {
            Some(index) => encode_integer(&mut block, 0xc0, 6, index),
            None => literal(&mut block, name.as_bytes(), value.as_bytes()),
        }
    }
    block
}

fn frame(kind: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = encode_varint(kind);
    out.extend(encode_varint(payload.len() as u64));
    out.extend(payload);
    out
}

fn encode_varint(n: u64) -> Vec<u8> {
    match n {
        0..0x40 => vec![n as u8],
        0x40..0x4000 => ((n as u16) | 0x4000).to_be_bytes().to_vec(),
        0x4000..0x4000_0000 => ((n as u32) | 0x8000_0000).to_be_bytes().to_vec(),
        _ => (n | 0xc000_0000_0000_0000).to_be_bytes().to_vec(),
    }
}

fn varint(buf: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *buf.get(at)?;
    let size = 1usize << (first >> 6);
    let bytes = buf.get(at..at + size)?;
    let value = bytes[1..].iter().fold(u64::from(first & 0x3f), |v, b| (v << 8) | u64::from(*b));
    Some((value, at + size))
}

/// A QPACK prefixed integer (RFC 7541 section 5.1) with `prefix` bits in its first byte, whose upper bits are `flags`.
fn encode_integer(out: &mut Vec<u8>, flags: u8, prefix: u8, value: usize) {
    let max = (1usize << prefix) - 1;
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    let mut rest = value - max;
    while rest >= 0x80 {
        out.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

fn decode_integer(buf: &[u8], at: &mut usize, prefix: u8) -> Option<usize> {
    let max = (1usize << prefix) - 1;
    let mut value = (*buf.get(*at)? as usize) & max;
    *at += 1;
    if value < max {
        return Some(value);
    }
    let mut shift = 0;
    loop {
        let b = *buf.get(*at)?;
        *at += 1;
        value += ((b & 0x7f) as usize) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Some(value);
        }
    }
}

/// A literal field line with a literal name (`001N H` + 3-bit length), the value without Huffman coding.
fn literal(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    encode_integer(out, 0x20, 3, name.len());
    out.extend(name);
    encode_integer(out, 0x00, 7, value.len());
    out.extend(value);
}

/// A string literal whose H flag is `huffman_bit` of its first byte and whose length has `prefix` bits.
fn decode_string(buf: &[u8], at: &mut usize, prefix: u8) -> Option<String> {
    let huffman = (*buf.get(*at)? >> prefix) & 1 == 1;
    let length = decode_integer(buf, at, prefix)?;
    let raw = buf.get(*at..*at + length)?;
    *at += length;
    let bytes = if huffman { loona_hpack::huffman::HuffmanDecoder::new().decode(raw).ok()? } else { raw.to_vec() };
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// A field section: its prefix (required insert count, base) skipped, then indexed lines and literals against the
/// static table. A dynamic reference (never sent to a client that advertises no table) reads as `<dynamic N>`.
fn decode_field_section(block: &[u8]) -> Vec<(String, String)> {
    let mut at = 0;
    let mut fields = Vec::new();
    if decode_integer(block, &mut at, 8).is_none() || decode_integer(block, &mut at, 7).is_none() {
        return fields;
    }
    let entry = |dynamic: bool, index: usize| -> (String, String) {
        match (dynamic, STATIC.get(index)) {
            (false, Some((n, v))) => (n.to_string(), v.to_string()),
            _ => (format!("<dynamic {index}>"), String::new()),
        }
    };
    while at < block.len() {
        let first = block[at];
        let line = if first & 0x80 != 0 {
            // indexed field line: 1 T index(6)
            let dynamic = first & 0x40 == 0;
            decode_integer(block, &mut at, 6).map(|i| entry(dynamic, i))
        } else if first & 0x40 != 0 {
            // literal with name reference: 01 N T index(4)
            let dynamic = first & 0x10 == 0;
            decode_integer(block, &mut at, 4).and_then(|i| decode_string(block, &mut at, 7).map(|v| (entry(dynamic, i).0, v)))
        } else if first & 0x20 != 0 {
            // literal with literal name: 001 N H length(3)
            decode_string(block, &mut at, 3).and_then(|n| decode_string(block, &mut at, 7).map(|v| (n, v)))
        } else if first & 0x10 != 0 {
            // indexed field line with post-base index: 0001 index(4)
            decode_integer(block, &mut at, 4).map(|i| entry(true, i))
        } else {
            // literal with post-base name reference: 0000 N index(3)
            decode_integer(block, &mut at, 3).and_then(|i| decode_string(block, &mut at, 7).map(|v| (entry(true, i).0, v)))
        };
        match line {
            Some(line) => fields.push(line),
            None => break,
        }
    }
    fields
}

/// RFC 9204 Appendix A.
const STATIC: [(&str, &str); 99] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

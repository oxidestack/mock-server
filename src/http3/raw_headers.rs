//! What sits between quinn and h3 on each request stream, reading its frames before h3 does.
//!
//! Field section limits: `Http3Server` advertises `maxHeaderSize` as `SETTINGS_MAX_FIELD_SECTION_SIZE`,
//! and Netty's `Http3FrameCodec` closes the whole connection with `H3_EXCESSIVE_LOAD` for a HEADERS frame longer than
//! that (before reading it), as `Http3HeadersSink` does for a field section whose size as RFC 9114 section 4.2.2
//! counts it (each field's name and value plus 32 bytes, pseudo-headers included) is over it; trailers alike. h3 alone
//! would answer `431` inside `ResolvedRequest::resolve`, before the caller sees anything. So every HEADERS frame is
//! checked here first; one over the limit is noted in [`Refusals`] under the stream's id and its request is not handed
//! on (h3 sees a stand-in request, [`REFUSED_SECTION`], or the end of the stream after its DATA), for `http3.rs` to
//! end the stream and close the connection as Netty does.
//!
//! The raw pseudo-headers of a CONNECT-UDP request. `Http3ConnectUdpHandler` reads Netty's `Http3Headers` as sent: it
//! compares `:protocol` with `connect-udp` case-insensitively and splits `:authority` itself (`parseAuthority`). The
//! `h3` crate parses `:protocol` into `h3::ext::Protocol`, which knows only lower-case `connect-udp`, and `:authority`
//! into `http::uri::Authority`, and resets the stream with `H3_MESSAGE_ERROR` on anything else. So in an extended
//! CONNECT whose `:protocol` is `connect-udp` in any case, the protocol is lower-cased, and an `:authority` h3 would
//! reject is swapped for [`PLACEHOLDER_AUTHORITY`] while the raw value waits in [`RawAuthorities`] under the stream's
//! id for `connect_udp`. Every other request, and any field section that refers to a QPACK dynamic table, passes
//! untouched.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes, BytesMut};
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId};

use crate::write_stall::{Http3Bidi, Http3Send, Http3Stalls};

/// Raw `:authority` values swapped out of CONNECT-UDP requests, by QUIC stream id.
pub(super) type RawAuthorities = Arc<Mutex<HashMap<u64, String>>>;

/// Field sections refused for their size, by QUIC stream id.
pub(super) type Refusals = Arc<Mutex<HashMap<u64, Refusal>>>;

/// A request's header or trailer section over `maxHeaderSize`.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Refusal {
    /// A section after the request's headers: its trailers.
    pub(super) trailers: bool,
    /// Netty's message, the reason the connection is closed with.
    pub(super) reason: String,
}

/// What h3 sees in place of an `:authority` it would reject.
const PLACEHOLDER_AUTHORITY: &str = "raw-authority.invalid:1";

/// What h3 sees in place of a refused header section: `GET https://refused.invalid/` (static-table lines, then
/// `:authority` by name reference), which h3 resolves as a request and `http3.rs` never serves.
const REFUSED_SECTION: &[u8] = b"\x00\x00\xd1\xd7\xc1\x50\x0frefused.invalid";

/// The HEADERS frame type.
const HEADERS: u64 = 0x01;

/// What every request stream of a connection checks its field sections against, and where it notes what it finds.
#[derive(Clone)]
pub(super) struct Sections {
    /// `maxHeaderSize`.
    pub(super) limit: u64,
    /// `None` with CONNECT-UDP disabled: nothing is rewritten.
    pub(super) raw: Option<RawAuthorities>,
    pub(super) refusals: Refusals,
}

/// `h3_quinn::Connection` whose request streams pass through [`Peeked`], their send sides watched for write stalls
/// (`write_stall::Http3Bidi`).
pub(super) struct Connection {
    inner: h3_quinn::Connection,
    sections: Sections,
    state: Arc<crate::state::State>,
    stalls: Http3Stalls,
}

impl Connection {
    pub(super) fn new(connection: quinn::Connection, sections: Sections, state: Arc<crate::state::State>) -> Self {
        // `Http3StreamWriteStallHandler` reads the grants from `peerTransportParameters()`
        let grants = super::peer_grants::of(&connection);
        let holder_bytes = grants.map_or(0, |g| crate::write_stall::http3_holder_bytes(g.initial_max_data, g.initial_max_stream_data_bidi_local));
        Connection { inner: h3_quinn::Connection::new(connection), sections, state, stalls: Http3Stalls::new(holder_bytes) }
    }
}

impl quic::Connection<Bytes> for Connection {
    type RecvStream = h3_quinn::RecvStream;
    type OpenStreams = Opener;

    fn poll_accept_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        quic::Connection::<Bytes>::poll_accept_recv(&mut self.inner, cx)
    }

    fn poll_accept_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        let stream = ready!(quic::Connection::<Bytes>::poll_accept_bidi(&mut self.inner, cx))?;
        let frames = Frames::new(self.sections.clone(), quic::RecvStream::recv_id(&stream));
        let (state, stalls) = (&self.state, &self.stalls);
        Poll::Ready(Ok(Peeked { inner: Http3Bidi::new(stream, |id| stalls.stream(state, id)), frames: Some(frames) }))
    }

    fn opener(&self) -> Self::OpenStreams {
        Opener(quic::Connection::<Bytes>::opener(&self.inner))
    }
}

impl quic::OpenStreams<Bytes> for Connection {
    type BidiStream = Peeked<Http3Bidi>;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        let stream = ready!(quic::OpenStreams::<Bytes>::poll_open_bidi(&mut self.inner, cx))?;
        Poll::Ready(Ok(Peeked { inner: Http3Bidi::new(stream, |_| None), frames: None }))
    }

    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<Bytes>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<Bytes>::close(&mut self.inner, code, reason)
    }
}

/// The connection's stream opener; streams it opens are never read here.
pub(super) struct Opener(h3_quinn::OpenStreams);

impl quic::OpenStreams<Bytes> for Opener {
    type BidiStream = Peeked<Http3Bidi>;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        let stream = ready!(quic::OpenStreams::<Bytes>::poll_open_bidi(&mut self.0, cx))?;
        Poll::Ready(Ok(Peeked { inner: Http3Bidi::new(stream, |_| None), frames: None }))
    }

    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<Bytes>::poll_open_send(&mut self.0, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<Bytes>::close(&mut self.0, code, reason)
    }
}

/// A stream whose frames are read here before h3 sees them; `frames` is `None` on a stream the server opened.
pub(super) struct Peeked<S> {
    inner: S,
    frames: Option<Frames>,
}

/// A request stream's frames as they pass: each HEADERS frame is collected whole and checked (the first maybe
/// rewritten), any other frame passes through as it arrives.
struct Frames {
    sections: Sections,
    /// The stream's id, read once: h3-quinn's stream has none to give while a read is in progress.
    id: StreamId,
    /// Bytes read from the stream and not yet handed on.
    buf: BytesMut,
    /// What is left of the frame passing through (its header included).
    pass: u64,
    /// The request's header section has been handed on: a later HEADERS frame is its trailers.
    headers_seen: bool,
    /// The stream has ended.
    ended: bool,
    /// A section was refused: nothing more is handed on.
    refused: bool,
}

impl Frames {
    fn new(sections: Sections, id: StreamId) -> Self {
        Frames { sections, id, buf: BytesMut::new(), pass: 0, headers_seen: false, ended: false, refused: false }
    }

    /// The next bytes to hand h3 (`None`: the end of the stream), or `Err` when more must be read first.
    fn next(&mut self) -> Result<Option<Bytes>, ()> {
        let id = self.id;
        loop {
            if self.refused {
                return Ok(None);
            }
            if self.pass > 0 && !self.buf.is_empty() {
                let n = self.buf.len().min(usize::try_from(self.pass).unwrap_or(usize::MAX));
                self.pass -= n as u64;
                return Ok(Some(self.buf.split_to(n).freeze()));
            }
            if self.buf.is_empty() {
                return if self.ended { Ok(None) } else { Err(()) };
            }
            let header = varint(&self.buf, 0).and_then(|(kind, at)| varint(&self.buf, at).map(|(length, at)| (kind, length, at)));
            let Some((kind, length, at)) = header else {
                // a frame header cut short by the stream's end is h3's to refuse
                return if self.ended { Ok(Some(self.buf.split().freeze())) } else { Err(()) };
            };
            if kind != HEADERS {
                self.pass = at as u64 + length;
                continue;
            }
            let limit = self.sections.limit;
            if length > limit {
                // `Http3FrameCodec.enforceMaxPayloadLength`, before the frame is read
                return Ok(self.refuse(id, format!("Received an invalid frame len {length} for frame of type 1.")));
            }
            let end = at + length as usize;
            if self.buf.len() < end {
                return if self.ended { Ok(Some(self.buf.split().freeze())) } else { Err(()) };
            }
            let frame = self.buf.split_to(end).freeze();
            if section_size(&frame[at..], limit).is_some_and(|size| size > limit) {
                // `Http3HeadersSink.finish`
                return Ok(self.refuse(id, format!("Header size exceeded max allowed size ({limit})")));
            }
            let first = !self.headers_seen;
            self.headers_seen = true;
            return Ok(Some(match &self.sections.raw {
                Some(raw) if first => connect_udp_frame(frame, at, raw, id),
                _ => frame,
            }));
        }
    }

    /// Notes the refusal, and what h3 is handed instead: a stand-in request for a header section, the stream's end
    /// for its trailers.
    fn refuse(&mut self, id: StreamId, reason: String) -> Option<Bytes> {
        self.refused = true;
        self.buf.clear();
        let trailers = self.headers_seen;
        self.sections.refusals.lock().unwrap().insert(id.into_inner(), Refusal { trailers, reason });
        if trailers {
            return None;
        }
        let mut out = BytesMut::new();
        put_varint(&mut out, HEADERS);
        put_varint(&mut out, REFUSED_SECTION.len() as u64);
        out.extend_from_slice(REFUSED_SECTION);
        Some(out.freeze())
    }
}

impl<S: quic::RecvStream> quic::RecvStream for Peeked<S> {
    type Buf = Bytes;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        let Some(frames) = &mut self.frames else {
            let chunk = ready!(self.inner.poll_data(cx))?;
            return Poll::Ready(Ok(chunk.map(|mut c| c.copy_to_bytes(c.remaining()))));
        };
        loop {
            if let Ok(out) = frames.next() {
                return Poll::Ready(Ok(out));
            }
            match ready!(self.inner.poll_data(cx))? {
                Some(mut chunk) => {
                    // the middle of a frame passing through goes on as it came
                    if frames.buf.is_empty() && chunk.remaining() as u64 <= frames.pass {
                        frames.pass -= chunk.remaining() as u64;
                        return Poll::Ready(Ok(Some(chunk.copy_to_bytes(chunk.remaining()))));
                    }
                    while chunk.has_remaining() {
                        let piece = chunk.chunk();
                        frames.buf.extend_from_slice(piece);
                        let n = piece.len();
                        chunk.advance(n);
                    }
                }
                None => frames.ended = true,
            }
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.inner.stop_sending(error_code)
    }

    fn recv_id(&self) -> StreamId {
        self.inner.recv_id()
    }
}

impl<S: quic::SendStream<Bytes>> quic::SendStream<Bytes> for Peeked<S> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.inner.poll_ready(cx)
    }

    fn send_data<T: Into<h3::quic::WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.inner.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.inner.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.inner.reset(reset_code)
    }

    fn send_id(&self) -> StreamId {
        self.inner.send_id()
    }
}

impl<S: quic::SendStreamUnframed<Bytes>> quic::SendStreamUnframed<Bytes> for Peeked<S> {
    fn poll_send<D: Buf>(&mut self, cx: &mut Context<'_>, buf: &mut D) -> Poll<Result<usize, StreamErrorIncoming>> {
        self.inner.poll_send(cx, buf)
    }
}

impl quic::BidiStream<Bytes> for Peeked<Http3Bidi> {
    type SendStream = Http3Send<h3_quinn::SendStream<Bytes>>;
    type RecvStream = Peeked<h3_quinn::RecvStream>;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = self.inner.split();
        (send, Peeked { inner: recv, frames: self.frames })
    }
}

/// A request's first HEADERS frame (its section starting at `at`), rewritten when it is a CONNECT-UDP request.
fn connect_udp_frame(frame: Bytes, at: usize, raw: &RawAuthorities, id: StreamId) -> Bytes {
    let Some((section, authority)) = rewrite(&frame[at..]) else { return frame };
    if let Some(authority) = authority {
        raw.lock().unwrap().insert(id.into_inner(), authority);
    }
    let mut out = BytesMut::new();
    put_varint(&mut out, HEADERS);
    put_varint(&mut out, section.len() as u64);
    out.extend_from_slice(&section);
    out.freeze()
}

/// A field section's size as RFC 9114 section 4.2.2 counts it (`QpackHeaderField.sizeOf` summed), counted until it
/// passes `limit`; `None` for a section that refers to the dynamic table (never advertised, so h3's to refuse) or is
/// malformed.
fn section_size(section: &[u8], limit: u64) -> Option<u64> {
    let (required_insert_count, at) = integer(section, 0, 8)?;
    if required_insert_count != 0 {
        return None;
    }
    let (_delta_base, mut at) = integer(section, at, 7)?;
    let mut size = 0u64;
    while at < section.len() && size <= limit {
        let (field, next) = field_line(section, at)?;
        let (name, value) = field?;
        size += (name.len() + value.len()) as u64 + 32;
        at = next;
    }
    Some(size)
}

/// One field line of a field section: where it lies, and its name and value when this shim can tell them.
struct Line {
    span: std::ops::Range<usize>,
    field: Option<(Vec<u8>, Vec<u8>)>,
}

/// The field section of a CONNECT-UDP request with `:protocol` lower-cased and an `:authority` h3 would reject
/// swapped for the placeholder (with that raw value); `None` for any other section, left as it was.
fn rewrite(section: &[u8]) -> Option<(Vec<u8>, Option<String>)> {
    let (required_insert_count, at) = integer(section, 0, 8)?;
    if required_insert_count != 0 {
        return None;
    }
    let (_delta_base, mut at) = integer(section, at, 7)?;
    let start = at;
    let mut lines = Vec::new();
    while at < section.len() {
        let (field, next) = field_line(section, at)?;
        lines.push(Line { span: at..next, field });
        at = next;
    }
    let find = |name: &[u8]| lines.iter().position(|l| l.field.as_ref().is_some_and(|(n, _)| n == name));
    let value = |i: usize| lines[i].field.as_ref().map(|(_, v)| v.as_slice()).unwrap_or_default();
    let method = find(b":method")?;
    let protocol = find(b":protocol")?;
    if !value(method).eq_ignore_ascii_case(b"CONNECT") || !value(protocol).eq_ignore_ascii_case(b"connect-udp") {
        return None;
    }
    let mut replace = HashMap::new();
    if value(protocol) != b"connect-udp" {
        replace.insert(protocol, (":protocol", "connect-udp"));
    }
    let mut raw = None;
    if let Some(authority) = find(b":authority") {
        let text = std::str::from_utf8(value(authority)).ok();
        if text.and_then(|t| t.parse::<http::uri::Authority>().ok()).is_none() {
            raw = Some(String::from_utf8_lossy(value(authority)).into_owned());
            replace.insert(authority, (":authority", PLACEHOLDER_AUTHORITY));
        }
    }
    if replace.is_empty() {
        return None;
    }
    let mut out = section[..start].to_vec();
    for (i, line) in lines.iter().enumerate() {
        match replace.get(&i) {
            Some((name, value)) => literal(&mut out, name.as_bytes(), value.as_bytes()),
            None => out.extend_from_slice(&section[line.span.clone()]),
        }
    }
    Some((out, raw))
}

/// A field line's name and value.
type FieldLine = (Vec<u8>, Vec<u8>);

/// One field line at `at` (RFC 9204 section 4.5): its name and value when it is static-table indexed or a literal
/// (`None` for an index past the static table), and where the next line starts. `None` for a reference to
/// the dynamic table or a malformed line.
fn field_line(section: &[u8], at: usize) -> Option<(Option<FieldLine>, usize)> {
    let first = *section.get(at)?;
    if first & 0x80 != 0 {
        // indexed field line; T must say static
        if first & 0x40 == 0 {
            return None;
        }
        let (index, next) = integer(section, at, 6)?;
        return Some((static_entry(index).map(|(n, v)| (n.to_vec(), v.to_vec())), next));
    }
    if first & 0xc0 == 0x40 {
        // literal field line with a name reference
        if first & 0x10 == 0 {
            return None;
        }
        let (index, next) = integer(section, at, 4)?;
        let (value, next) = string(section, next, 7)?;
        return Some((static_entry(index).map(|(n, _)| (n.to_vec(), value)), next));
    }
    if first & 0xe0 == 0x20 {
        // literal field line with a literal name
        let (name, next) = string(section, at, 3)?;
        let (value, next) = string(section, next, 7)?;
        return Some((Some((name, value)), next));
    }
    None
}

/// A static-table entry (RFC 9204 appendix A).
fn static_entry(index: u64) -> Option<(&'static [u8], &'static [u8])> {
    STATIC.get(usize::try_from(index).ok()?).map(|(n, v)| (n.as_bytes(), v.as_bytes()))
}

/// A string literal whose Huffman flag sits just above its `prefix`-bit length.
fn string(section: &[u8], at: usize, prefix: u8) -> Option<(Vec<u8>, usize)> {
    let huffman = section.get(at)? & (1 << prefix) != 0;
    let (length, at) = integer(section, at, prefix)?;
    let end = at.checked_add(usize::try_from(length).ok()?)?;
    let bytes = section.get(at..end)?;
    let value = if huffman { loona_hpack::huffman::HuffmanDecoder::new().decode(bytes).ok()? } else { bytes.to_vec() };
    Some((value, end))
}

/// A prefixed integer (RFC 7541 section 5.1) in the low `prefix` bits of the byte at `at`.
fn integer(buf: &[u8], at: usize, prefix: u8) -> Option<(u64, usize)> {
    let max = (1u64 << prefix) - 1;
    let mut value = u64::from(*buf.get(at)?) & max;
    let mut at = at + 1;
    if value < max {
        return Some((value, at));
    }
    let mut shift = 0;
    loop {
        let byte = *buf.get(at)?;
        at += 1;
        value = value.checked_add(u64::from(byte & 0x7f).checked_shl(shift)?)?;
        if byte & 0x80 == 0 {
            return Some((value, at));
        }
        shift += 7;
        if shift > 56 {
            return None;
        }
    }
}

fn put_integer(out: &mut Vec<u8>, flags: u8, prefix: u8, value: usize) {
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

/// A literal field line with a literal name, neither Huffman-coded.
fn literal(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    put_integer(out, 0x20, 3, name.len());
    out.extend_from_slice(name);
    put_integer(out, 0x00, 7, value.len());
    out.extend_from_slice(value);
}

/// A QUIC variable-length integer (RFC 9000 section 16).
fn varint(buf: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *buf.get(at)?;
    let size = 1usize << (first >> 6);
    let bytes = buf.get(at..at + size)?;
    let value = bytes[1..].iter().fold(u64::from(first & 0x3f), |v, b| (v << 8) | u64::from(*b));
    Some((value, at + size))
}

fn put_varint(out: &mut BytesMut, n: u64) {
    match n {
        0..0x40 => out.extend_from_slice(&[n as u8]),
        0x40..0x4000 => out.extend_from_slice(&((n as u16) | 0x4000).to_be_bytes()),
        0x4000..0x4000_0000 => out.extend_from_slice(&((n as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(n | 0xc000_0000_0000_0000).to_be_bytes()),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn section(fields: &[(&str, &str)]) -> Vec<u8> {
        let mut out = vec![0, 0];
        for (name, value) in fields {
            literal(&mut out, name.as_bytes(), value.as_bytes());
        }
        out
    }

    fn fields(section: &[u8]) -> Vec<(String, String)> {
        let (_, at) = integer(section, 0, 8).unwrap();
        let (_, mut at) = integer(section, at, 7).unwrap();
        let mut out = Vec::new();
        while at < section.len() {
            let (field, next) = field_line(section, at).unwrap();
            let (n, v) = field.unwrap();
            out.push((String::from_utf8(n).unwrap(), String::from_utf8(v).unwrap()));
            at = next;
        }
        out
    }

    #[test]
    fn upper_case_protocol_is_lower_cased() {
        let s = section(&[(":method", "CONNECT"), (":scheme", "https"), (":authority", "h:53"), (":path", "/"), (":protocol", "CONNECT-UDP")]);
        let (out, raw) = rewrite(&s).unwrap();
        assert_eq!(raw, None);
        assert_eq!(fields(&out)[4], (":protocol".into(), "connect-udp".into()));
        assert_eq!(fields(&out)[2], (":authority".into(), "h:53".into()));
    }

    #[test]
    fn an_authority_h3_rejects_is_swapped() {
        for authority in ["bad host:53", "host:80:90", "::1:53", ""] {
            let s = section(&[(":method", "CONNECT"), (":authority", authority), (":protocol", "connect-udp")]);
            let (out, raw) = rewrite(&s).unwrap();
            assert_eq!(raw.as_deref(), Some(authority));
            assert_eq!(fields(&out)[1], (":authority".into(), PLACEHOLDER_AUTHORITY.into()));
        }
    }

    #[test]
    fn other_requests_pass_untouched() {
        assert!(rewrite(&section(&[(":method", "CONNECT"), (":authority", "h:53"), (":protocol", "connect-udp")])).is_none());
        assert!(rewrite(&section(&[(":method", "GET"), (":authority", "a b"), (":protocol", "CONNECT-UDP")])).is_none());
        assert!(rewrite(&section(&[(":method", "CONNECT"), (":authority", "a b"), (":protocol", "websocket")])).is_none());
        // a static-table `:method CONNECT` and a Huffman-coded `:protocol` value (`connect-udp` upper-cased)
        let mut s = vec![0, 0, 0xc0 | 15];
        // `CONNECT-UDP` Huffman-coded (RFC 7541 appendix B)
        let encoded = [0xbd, 0xab, 0x4e, 0x9c, 0x17, 0xb7, 0xad, 0xc2, 0xfe, 0xbf];
        literal_name_huffman_value(&mut s, b":protocol", &encoded);
        let (out, _) = rewrite(&s).unwrap();
        assert_eq!(fields(&out), vec![(":method".into(), "CONNECT".into()), (":protocol".into(), "connect-udp".into())]);
    }

    fn literal_name_huffman_value(out: &mut Vec<u8>, name: &[u8], encoded: &[u8]) {
        put_integer(out, 0x20, 3, name.len());
        out.extend_from_slice(name);
        put_integer(out, 0x80, 7, encoded.len());
        out.extend_from_slice(encoded);
    }
}

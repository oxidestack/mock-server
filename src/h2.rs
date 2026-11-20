//! HTTP/2 server connections (prior-knowledge h2c, or TLS with ALPN `h2`), written by hand like the HTTP/1.1 loop:
//! header bytes are taken as sent (Netty's codec accepts values the `http` crate refuses), a streamed body goes out
//! as DATA frames while it is produced, and a stream can be reset with the error code an action names.
//!
//! One reader task parses frames and starts a task per complete request; one writer task owns the HPACK encoder,
//! the send windows and the socket's write half, so frames of concurrent streams interleave in the order produced.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::handler::{self, Connection, Outcome};
use crate::reply::Reply;
use crate::request::{self, HttpRequest, MultiMap};
use crate::state::State;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;

const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

const NO_ERROR: u32 = 0x0;
const PROTOCOL_ERROR: u32 = 0x1;
pub const INTERNAL_ERROR: u32 = 0x2;
const FLOW_CONTROL_ERROR: u32 = 0x3;
const STREAM_CLOSED: u32 = 0x5;
pub const CANCEL: u32 = 0x8;
const FRAME_SIZE_ERROR: u32 = 0x6;
const COMPRESSION_ERROR: u32 = 0x9;

const DEFAULT_WINDOW: i64 = 65_535;
/// The largest flow-control window (RFC 9113 section 6.9.1).
const MAX_WINDOW: i64 = 0x7fff_ffff;
const DEFAULT_MAX_FRAME: usize = 16_384;
/// The largest frame accepted from the peer (`SETTINGS_MAX_FRAME_SIZE`'s upper bound).
const MAX_FRAME_ACCEPTED: usize = 16_777_215;

/// Headers a response must not carry over HTTP/2 (`HttpConversionUtil`'s connection-specific headers).
const CONNECTION_SPECIFIC: &[&str] = &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "host"];

/// Work for the writer task.
enum Out {
    Headers { stream: u32, fields: Vec<(Vec<u8>, Vec<u8>)>, end: bool },
    Data { stream: u32, data: Bytes, end: bool },
    /// The trailing HEADERS (ending the stream), sent once the stream's queued DATA is out.
    Trailers { stream: u32, fields: Vec<(Vec<u8>, Vec<u8>)> },
    Reset { stream: u32, code: u32 },
    /// A header list over `maxHeaderSize` (`Http2ConnectionHandler.onStreamError`): `431` ending the stream while no
    /// final response head has been sent on it, written by `handleServerHeaderDecodeSizeError` without a tunnel's
    /// priority fields, then `RST_STREAM PROTOCOL_ERROR` either way.
    RefuseHeaderList { stream: u32 },
    /// A control frame, already encoded.
    Frame(Vec<u8>),
    /// A SETTINGS frame's entries; `last_stream`: the last stream the client had opened when it arrived.
    PeerSettings { initial_window: Option<u32>, max_frame: Option<u32>, table_size: Option<u32>, last_stream: u32 },
    /// A WINDOW_UPDATE; `open`: on a stream the client has opened and not yet seen answered or reset.
    PeerWindow { stream: u32, increment: u32, open: bool },
    /// The peer reset the stream: whatever is still queued for it is dropped.
    Forget(u32),
    /// Write what can be written, then reset the whole TCP connection (chaos `resetMidResponse`).
    Kill,
    /// Shut the stream down once everything before it is written, and stop.
    Shutdown,
    /// Write what is queued before it, then stop: the reader has ended, and the connection closes.
    Close,
    /// `Http2GoAwayEmitter.emit`: a GOAWAY advertising `last` (`None`: `Integer.MAX_VALUE`, Netty's "every stream so
    /// far") with `code`, as `Http2ConnectionHandler.goAway` sends it (see [`write_loop`]).
    GoAway { last: Option<u32>, code: u32 },
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = payload.len() as u32;
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&length.to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Queued behind the flow-control windows: DATA, or the trailers that follow it.
enum Pending {
    Data(Bytes, bool),
    Trailers(Vec<(Vec<u8>, Vec<u8>)>),
}

/// A HEADERS frame (and CONTINUATIONs) for `fields`. `priority`: the frame carries Netty's default priority (no
/// dependency, weight 16), as `HttpToHttp2ConnectionHandler` writes every header block on a CONNECT tunnel's HTTP/2.
fn headers_frames(encoder: &mut crate::hpack::Encoder, priority: bool, max_frame: usize, stream: u32, fields: &[(Vec<u8>, Vec<u8>)], end: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let block = encoder.encode(fields.iter().map(|(n, v)| (n.as_slice(), v.as_slice())));
    // `DefaultHttp2FrameWriter.writeHeadersInternal`: the priority fields take room from the first fragment
    let first_length = if priority { max_frame - 5 } else { max_frame }.min(block.len());
    let (first, rest) = block.split_at(first_length);
    let mut chunks = rest.chunks(max_frame).peekable();
    let last = chunks.peek().is_none();
    let flags = (if end { END_STREAM } else { 0 }) | (if last { END_HEADERS } else { 0 }) | (if priority { PRIORITY } else { 0 });
    if priority {
        let mut payload = vec![0, 0, 0, 0, 15];
        payload.extend_from_slice(first);
        out.extend(frame(HEADERS, flags, stream, &payload));
    } else {
        out.extend(frame(HEADERS, flags, stream, first));
    }
    while let Some(chunk) = chunks.next() {
        out.extend(frame(CONTINUATION, if chunks.peek().is_none() { END_HEADERS } else { 0 }, stream, chunk));
    }
    out
}

fn window_update(stream: u32, increment: u32) -> Vec<u8> {
    frame(WINDOW_UPDATE, 0, stream, &increment.to_be_bytes())
}

/// `maxRequestBodySize`, read when a connection or stream opens so a limit set at runtime applies to the next one.
fn max_request_body(state: &State) -> i64 {
    state.config.int_property("maxRequestBodySize", 10_485_760)
}

/// `maxHeaderSize` (default 262144 since upstream's request-limit change, after 8.0.0), announced as
/// `SETTINGS_MAX_HEADER_LIST_SIZE`; Netty's `Http2Settings` takes it as an unsigned 32-bit value.
fn max_header_size(state: &State) -> u32 {
    state.config.int_property("maxHeaderSize", 262_144).clamp(0, i64::from(u32::MAX)) as u32
}

/// Serves an HTTP/2 connection until either side closes it. `relay`: the HTTP/2 of a CONNECT or SOCKS tunnel, which
/// upstream serves on `RelayConnectHandler`'s own handler rather than the port's (see [`headers_frames`]).
/// Why a connection's reading stopped.
enum Ended {
    /// The client closed or reset it, or a protocol error ended it.
    Read,
    /// The writer killed it (a GOAWAY with an error code, a `resetMidResponse`).
    Killed,
    /// `inboundConnectionIdleTimeoutMillis`.
    Idle,
}

pub async fn serve<S>(state: Arc<State>, mut conn: Connection, io: S, secure: bool, relay: bool)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    crate::server::name_first_local_address(&mut conn, secure).await;
    conn.write_stall.set(crate::write_stall::Protocol::Http2);
    let (mut reader, writer_half) = tokio::io::split(io);
    let (tx, rx) = mpsc::unbounded_channel();
    let killed = Arc::new(tokio::sync::Notify::new());
    let go_away_last = Arc::new(std::sync::atomic::AtomicU32::new(u32::MAX));
    let stalls = crate::write_stall::StreamStalls::new(&state, conn.remote);
    let tasks = Tasks::default();
    let backlog = Arc::new(Backlog::default());
    let writer = tokio::spawn(write_loop(writer_half, rx, conn.socket, killed.clone(), go_away_last.clone(), relay, stalls, tasks.clone(), backlog.clone(), (state.connections.clone(), conn.event_loop)));
    // The server's SETTINGS, as Netty's `Http2FrameCodec` as configured by MockServer announces them: 100 concurrent
    // streams, frames up to `maxRequestBodySize` (within the protocol's 16 KiB..16 MiB), and a header list of
    // `maxHeaderSize` (`Http2RequestHeaderLimit.serverSettings`, after 8.0.0, which announced Netty's 8 KiB). A tunnel's
    // (`Http2RequestHeaderLimit.tunnelServerHandler`) leaves the frame size at its default, unannounced.
    let max_frame = max_request_body(&state).clamp(DEFAULT_MAX_FRAME as i64, 0xff_ffff) as u32;
    let mut settings = Vec::new();
    let announced = [(0x3u16, 100u32), (0x5, max_frame), (0x6, max_header_size(&state))];
    for (id, value) in announced.into_iter().filter(|(id, _)| !relay || *id != 0x5) {
        settings.extend(id.to_be_bytes());
        settings.extend(value.to_be_bytes());
    }
    // sent as the codec is added, before the client's preface is read: a client may wait for it (over TLS, the
    // handshake alone selects HTTP/2)
    let _ = tx.send(Out::Frame(frame(SETTINGS, 0, 0, &settings)));
    let mut buf = BytesMut::with_capacity(32 * 1024);
    if fill_to(&mut reader, &mut buf, PREFACE.len()).await.is_err() || !buf.starts_with(PREFACE) {
        return;
    }
    buf.advance(PREFACE.len());
    let max_header_list = max_header_size(&state);
    let mut connection = Reader {
        state,
        backlog,
        conn,
        secure,
        tx: tx.clone(),
        decoder: loona_hpack::Decoder::new(),
        streams: HashMap::new(),
        tasks,
        go_away_last,
        unreturned_conn: 0,
        unreturned_stream: HashMap::new(),
        grpc: false,
        last_stream: 0,
        max_header_list,
        relay,
    };
    // `Http2MultiplexChildInitializer` installs the gRPC handlers once per connection, if descriptors are loaded.
    connection.grpc = connection.state.grpc.has_services();
    let grpc = connection.grpc;
    // `Http2ConnectionHandler.close` on the idle close: a GOAWAY naming the last stream the client
    // opened, then the stream is shut down (inside TLS, `close_notify` before the FIN)
    let closer = connection.conn.idle.closer();
    let ended = tokio::select! {
        _ = crate::grpc_plane::PIPELINE.scope(grpc, connection.run(&mut reader, &mut buf)) => Ended::Read,
        _ = killed.notified() => Ended::Killed,
        _ = closer.requested() => Ended::Idle,
    };
    drop(closer);
    match ended {
        Ended::Idle => {
            let _ = tx.send(Out::GoAway { last: Some(connection.last_stream), code: NO_ERROR });
            let _ = tx.send(Out::Shutdown);
        }
        // The client left (or its connection failed): what is queued is written, then the channel closes. The requests
        // it had sent in full go on being handled, as Netty's stream channels hand theirs on before the close reaches
        // them: each is received and logged, and its response goes nowhere (`ReadAfterFailedWrite`, after 8.0.0).
        Ended::Read => {
            let _ = tx.send(Out::Close);
            connection.tasks.clear();
        }
        Ended::Killed => {}
    }
    for (_, task) in connection.tasks.drain() {
        task.abort();
    }
    drop(connection);
    drop(tx);
    let _ = writer.await;
}

async fn fill_to<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut BytesMut, n: usize) -> std::io::Result<()> {
    while buf.len() < n {
        if reader.read_buf(buf).await? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
    }
    Ok(())
}

/// A request being received on a stream.
#[derive(Default)]
struct Incoming {
    fields: Vec<(Vec<u8>, Vec<u8>)>,
    body: BytesMut,
    /// A header block still waiting for CONTINUATION frames, and whether it ends the stream.
    pending_block: Option<(Vec<u8>, bool)>,
    dispatched: bool,
    /// The request ended with its HEADERS frame, so no body was ever aggregated.
    headers_only: bool,
    /// A gRPC bidirectional stream served as it arrives: its DATA goes here instead of `body`.
    bidi: Option<mpsc::UnboundedSender<Bytes>>,
    /// The `Content-Length` the request announced; a body of another length is cancelled.
    declared: Option<u64>,
    /// `maxRequestBodySize` when the stream opened: a longer body is answered `413`.
    limit: u64,
}

/// The tasks answering a connection's streams, shared by the reader (a reset from the client aborts its stream's
/// task) and the writer (a stream reset for a write stall aborts it too, which drops a streamed response's producer
/// and so closes a quiet upstream: `Http2StreamWriteStallHandler` closes the stream's child channel).
#[derive(Clone, Default)]
struct Tasks(Arc<std::sync::Mutex<HashMap<u32, tokio::task::AbortHandle>>>);

impl Tasks {
    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<u32, tokio::task::AbortHandle>> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn insert(&self, stream: u32, task: tokio::task::AbortHandle) {
        self.map().insert(stream, task);
    }

    fn remove(&self, stream: &u32) -> Option<tokio::task::AbortHandle> {
        self.map().remove(stream)
    }

    fn contains(&self, stream: u32) -> bool {
        self.map().contains_key(&stream)
    }

    fn forget_finished(&self) {
        self.map().retain(|_, t| !t.is_finished());
    }

    fn clear(&self) {
        self.map().clear();
    }

    fn drain(&self) -> Vec<(u32, tokio::task::AbortHandle)> {
        self.map().drain().collect()
    }
}

/// The most of a streamed response's data handed to the writer and not yet written that its producer may run ahead
/// by: a stream its client is not taking stops being writable, as Netty's stream channel does, so the producer (and a
/// forward's upstream) is held back rather than buffered here.
const BACKLOG_HIGH_WATER: usize = 64 * 1024;

/// Each stream's data handed to the writer and not yet written, shared by the streams' tasks and the writer.
/// A stream the writer is done with (ended, reset, forgotten, or the writer gone) is closed: nothing waits on it.
#[derive(Default)]
struct Backlog {
    streams: std::sync::Mutex<BacklogStreams>,
    changed: tokio::sync::Notify,
}

#[derive(Default)]
struct BacklogStreams {
    queued: HashMap<u32, usize>,
    closed: HashSet<u32>,
    all_closed: bool,
}

impl Backlog {
    fn lock(&self) -> std::sync::MutexGuard<'_, BacklogStreams> {
        self.streams.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn handed(&self, stream: u32, bytes: usize) {
        let mut streams = self.lock();
        if !streams.all_closed && !streams.closed.contains(&stream) {
            *streams.queued.entry(stream).or_default() += bytes;
        }
    }

    fn written(&self, stream: u32, bytes: usize) {
        if let Some(queued) = self.lock().queued.get_mut(&stream) {
            *queued = queued.saturating_sub(bytes);
        }
        self.changed.notify_waiters();
    }

    fn close(&self, stream: u32) {
        {
            let mut streams = self.lock();
            streams.queued.remove(&stream);
            streams.closed.insert(stream);
        }
        self.changed.notify_waiters();
    }

    fn close_all(&self) {
        {
            let mut streams = self.lock();
            streams.queued.clear();
            streams.all_closed = true;
        }
        self.changed.notify_waiters();
    }

    /// Until `ready` holds for `stream`'s queued bytes, or the stream is closed.
    async fn until(&self, stream: u32, ready: impl Fn(usize) -> bool) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let streams = self.lock();
                if streams.all_closed || streams.closed.contains(&stream) || ready(streams.queued.get(&stream).copied().unwrap_or(0)) {
                    return;
                }
            }
            changed.await;
        }
    }
}

/// Closes every stream of the [`Backlog`] once the writer is gone, however it ended.
struct BacklogGuard(Arc<Backlog>);

impl Drop for BacklogGuard {
    fn drop(&mut self) {
        self.0.close_all();
    }
}

struct Reader {
    state: Arc<State>,
    backlog: Arc<Backlog>,
    conn: Connection,
    secure: bool,
    tx: mpsc::UnboundedSender<Out>,
    decoder: loona_hpack::Decoder<'static>,
    streams: HashMap<u32, Incoming>,
    tasks: Tasks,
    /// The last stream of the GOAWAY sent on this connection (`u32::MAX`: none sent): Netty's decoder ignores frames
    /// for any stream above it.
    go_away_last: Arc<std::sync::atomic::AtomicU32>,
    /// Bytes consumed but not yet returned to the peer, on the connection and per stream: Netty returns them in
    /// one WINDOW_UPDATE once half the window is used.
    unreturned_conn: i64,
    unreturned_stream: HashMap<u32, i64>,
    /// Whether the gRPC handlers were installed for this connection (see [`crate::grpc_plane::PIPELINE`]).
    grpc: bool,
    /// The highest stream the client opened (`lastStreamCreated` of the remote endpoint).
    last_stream: u32,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` as announced: `maxHeaderSize` when the connection opened.
    max_header_list: u32,
    /// The HTTP/2 of a CONNECT or SOCKS tunnel (`Http2RequestHeaderLimit.tunnelServerHandler`).
    relay: bool,
}


impl Reader {
    async fn run<R: AsyncRead + Unpin>(&mut self, reader: &mut R, buf: &mut BytesMut) -> Result<(), ()> {
        loop {
            fill_to(reader, buf, 9).await.map_err(|_| ())?;
            let length = ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | buf[2] as usize;
            let (kind, flags) = (buf[3], buf[4]);
            let stream = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
            if length > MAX_FRAME_ACCEPTED {
                self.go_away(FRAME_SIZE_ERROR);
                return Err(());
            }
            fill_to(reader, buf, 9 + length).await.map_err(|_| ())?;
            buf.advance(9);
            let payload = buf.split_to(length).freeze();
            self.tasks.forget_finished();
            if matches!(kind, HEADERS | CONTINUATION | DATA) && stream > self.go_away_last.load(std::sync::atomic::Ordering::SeqCst) {
                continue;
            }
            match kind {
                SETTINGS if flags & ACK == 0 => {
                    let (mut initial_window, mut max_frame, mut table_size) = (None, None, None);
                    for setting in payload.as_chunks::<6>().0 {
                        let value = u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]);
                        match u16::from_be_bytes([setting[0], setting[1]]) {
                            0x1 => table_size = Some(value),
                            0x4 => initial_window = Some(value),
                            0x5 => max_frame = Some(value),
                            _ => {}
                        }
                    }
                    let _ = self.tx.send(Out::PeerSettings { initial_window, max_frame, table_size, last_stream: self.last_stream });
                    let _ = self.tx.send(Out::Frame(frame(SETTINGS, ACK, 0, &[])));
                }
                PING if flags & ACK == 0 => {
                    let _ = self.tx.send(Out::Frame(frame(PING, ACK, 0, &payload)));
                }
                WINDOW_UPDATE if payload.len() >= 4 => {
                    let increment = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff;
                    // a stream the client opened has a send window from then on, before its response starts
                    let open = stream != 0 && (self.streams.contains_key(&stream) || self.tasks.contains(stream));
                    let _ = self.tx.send(Out::PeerWindow { stream, increment, open });
                }
                HEADERS if stream != 0 => {
                    let mut block = payload;
                    let mut pad = 0;
                    if flags & PADDED != 0 && !block.is_empty() {
                        pad = block[0] as usize;
                        block.advance(1);
                    }
                    if flags & PRIORITY != 0 && block.len() >= 5 {
                        block.advance(5);
                    }
                    if pad > block.len() {
                        self.go_away(PROTOCOL_ERROR);
                        return Err(());
                    }
                    let block = block.slice(..block.len() - pad);
                    let end_stream = flags & END_STREAM != 0;
                    if block.len() as u64 > self.header_block_limit() {
                        self.header_block_too_large();
                        return Err(());
                    }
                    if flags & END_HEADERS != 0 {
                        self.header_block(stream, &block, end_stream)?;
                    } else {
                        self.streams.entry(stream).or_default().pending_block = Some((block.to_vec(), end_stream));
                    }
                }
                CONTINUATION if stream != 0 => {
                    let block_limit = self.header_block_limit();
                    let Some(incoming) = self.streams.get_mut(&stream) else { continue };
                    let Some((mut block, end_stream)) = incoming.pending_block.take() else { continue };
                    if (block.len() + payload.len()) as u64 > block_limit {
                        self.header_block_too_large();
                        return Err(());
                    }
                    block.extend_from_slice(&payload);
                    if flags & END_HEADERS != 0 {
                        self.header_block(stream, &block, end_stream)?;
                    } else {
                        incoming.pending_block = Some((block, end_stream));
                    }
                }
                DATA if stream != 0 => {
                    let flow = payload.len() as u32;
                    let mut data = payload;
                    if flags & PADDED != 0 && !data.is_empty() {
                        let pad = data[0] as usize;
                        data.advance(1);
                        data.truncate(data.len().saturating_sub(pad));
                    }
                    let end_stream = flags & END_STREAM != 0;
                    if flow > 0 {
                        // Whatever arrives is consumed at once; Netty returns it once half the window is used.
                        let threshold = DEFAULT_WINDOW - DEFAULT_WINDOW / 2;
                        let mut update = Vec::new();
                        self.unreturned_conn += flow as i64;
                        if self.unreturned_conn >= threshold {
                            update.extend(window_update(0, self.unreturned_conn as u32));
                            self.unreturned_conn = 0;
                        }
                        let unreturned = self.unreturned_stream.entry(stream).or_default();
                        *unreturned += flow as i64;
                        if end_stream {
                            self.unreturned_stream.remove(&stream);
                        } else if *unreturned >= threshold {
                            update.extend(window_update(stream, *unreturned as u32));
                            *unreturned = 0;
                        }
                        if !update.is_empty() {
                            let _ = self.tx.send(Out::Frame(update));
                        }
                    }
                    if !self.streams.contains_key(&stream) && self.tasks.contains(stream) {
                        // `DefaultHttp2ConnectionDecoder.onDataRead` on a stream whose request has ended (half-closed
                        // remote, its answer still to come): a STREAM_CLOSED stream error, which resets it alone; its
                        // answer goes nowhere and the connection carries on
                        self.unreturned_stream.remove(&stream);
                        let _ = self.tx.send(Out::Reset { stream, code: STREAM_CLOSED });
                        continue;
                    }
                    if let Some(incoming) = self.streams.get_mut(&stream) {
                        if let Some(bidi) = &incoming.bidi {
                            let _ = bidi.send(data);
                            if end_stream {
                                self.streams.remove(&stream);
                            }
                            continue;
                        }
                        incoming.body.extend_from_slice(&data);
                        if let Some((used, max)) = crate::config::netty_max_direct_memory(&self.state.config).and_then(|max| crate::client::h2_request_direct_memory_refusal(incoming.body.len(), max)) {
                            self.direct_memory_cut(stream, used, max);
                            return Err(());
                        }
                        if incoming.body.len() as u64 > incoming.limit {
                            self.too_large(stream);
                            continue;
                        }
                        if let Some(declared) = incoming.declared {
                            let length = incoming.body.len() as u64;
                            if length > declared || (end_stream && length < declared) {
                                // `DefaultHttp2ConnectionDecoder`'s content-length check is a stream error, whose
                                // stream is reset with its own code (`Http2StreamFaults`, after 8.0.0: `CANCEL` before).
                                self.streams.remove(&stream);
                                let _ = self.tx.send(Out::Reset { stream, code: PROTOCOL_ERROR });
                                continue;
                            }
                        }
                    }
                    if end_stream {
                        self.dispatch(stream);
                    }
                }
                RST_STREAM => {
                    self.streams.remove(&stream);
                    self.unreturned_stream.remove(&stream);
                    if let Some(task) = self.tasks.remove(&stream) {
                        task.abort();
                    }
                    let _ = self.tx.send(Out::Forget(stream));
                }
                GOAWAY => return Ok(()),
                _ => {}
            }
        }
    }

    /// Netty's direct-memory limit (`io.netty.maxDirectMemory`) refused the connection's next read buffer
    /// while a stream's aggregator held the request's DATA: the pool's ERROR, then, as the connection closes,
    /// `Http2StreamFaults.logEndedWithConnection` for the stream (the caller ends the connection).
    fn direct_memory_cut(&mut self, stream: u32, used: u64, max: u64) {
        use crate::recorded::{Arg, Level, LogEntry};
        let channel = crate::server::channel_description(&self.conn);
        let reached = format!("direct memory limit (io.netty.maxDirectMemory) reached - raise it with -XX:MaxDirectMemorySize or -Dio.netty.maxDirectMemory - closing connection {channel} - failed to allocate {} byte(s) of direct memory (used: {used}, max: {max})", crate::client::H2_DIRECT_MEMORY_BUFFER);
        crate::log::error_event(&self.state, LogEntry::at(Level::Error, reached));
        self.streams.remove(&stream);
        let entry = LogEntry::at(Level::Info, "HTTP/2 stream:{}from:{}ended with its connection before its request was complete")
            .args([Arg::from(serde_json::json!(stream)), crate::http1::socket_address_arg(self.conn.remote)]);
        crate::log::info_event(&self.state, entry);
    }

    /// `HttpObjectAggregator.handleOversizedMessage` on the stream's child channel: `413` with `content-length: 0`,
    /// ending the stream; the request is never handled and what else arrives for it is ignored.
    fn too_large(&mut self, stream: u32) {
        self.streams.remove(&stream);
        let fields = vec![(b":status".to_vec(), b"413".to_vec()), (b"content-length".to_vec(), b"0".to_vec())];
        let _ = self.tx.send(Out::Headers { stream, fields, end: true });
    }

    fn go_away(&self, code: u32) {
        let last = self.streams.keys().copied().max().unwrap_or(0);
        let mut payload = last.to_be_bytes().to_vec();
        payload.extend_from_slice(&code.to_be_bytes());
        let _ = self.tx.send(Out::Frame(frame(GOAWAY, 0, 0, &payload)));
    }

    /// `Http2CodecUtil.calculateMaxHeaderListSizeGoAway`: a header block whose encoded bytes exceed the header list
    /// limit plus a quarter is a connection error (`DefaultHttp2FrameReader.HeadersBlockBuilder.addFragment`).
    fn header_block_limit(&self) -> u64 {
        let limit = u64::from(self.max_header_list);
        limit + (limit >> 2)
    }

    /// `Http2CodecUtil.headerListSizeExceeded(long)`: `GOAWAY PROTOCOL_ERROR` naming every stream, with Netty's message
    /// as its debug data, then the connection closes; `Http2RequestHeaderLimit.logRefusal` logs it.
    fn header_block_too_large(&self) {
        use crate::recorded::{Arg, Level, LogEntry};
        let entry = LogEntry::at(Level::Warn, "closing HTTP/2 connection from:{}because a request's header block is more than a quarter larger than maxHeaderSize:{}")
            .args([crate::http1::socket_address_arg(self.conn.remote), Arg::from(serde_json::json!(self.max_header_list))]);
        crate::log::warn_event(&self.state, entry);
        let mut payload = 0x7fff_ffffu32.to_be_bytes().to_vec();
        payload.extend_from_slice(&PROTOCOL_ERROR.to_be_bytes());
        payload.extend_from_slice(format!("Header size exceeded max allowed size ({})", self.header_block_limit()).as_bytes());
        let _ = self.tx.send(Out::Frame(frame(GOAWAY, 0, 0, &payload)));
    }

    /// A header list over `SETTINGS_MAX_HEADER_LIST_SIZE` once decoded (`HpackDecoder`'s `Http2HeadersSink`, which
    /// stops keeping fields once over and decodes the rest only to keep its table): a `HeaderListSizeException`, a
    /// stream error. On a stream the connection has not seen it is a request's headers, answered `431` and reset
    /// (`Http2ConnectionHandler.onStreamError`); on one it has seen, the request's trailers, which reset the stream and
    /// stop its response (on a direct connection the stream's own pipeline does, `LenientInboundHttp2StreamFrameCodec`;
    /// a tunnel answers `431` first while no response has started).
    fn header_list_too_large(&mut self, stream: u32) {
        use crate::recorded::{Arg, Level, LogEntry};
        let known = stream <= self.last_stream;
        self.last_stream = self.last_stream.max(stream);
        let message = if known {
            "resetting HTTP/2 stream:{}from:{}because the request's trailers are larger than maxHeaderSize:{}"
        } else {
            "refusing request on HTTP/2 stream:{}from:{}because its header list is larger than maxHeaderSize:{}"
        };
        let entry = LogEntry::at(Level::Warn, message).args([
            Arg::from(serde_json::json!(stream)),
            crate::http1::socket_address_arg(self.conn.remote),
            Arg::from(serde_json::json!(self.max_header_list)),
        ]);
        crate::log::warn_event(&self.state, entry);
        let bidi = self.streams.remove(&stream).is_some_and(|incoming| incoming.bidi.is_some());
        self.unreturned_stream.remove(&stream);
        if let Some(task) = self.tasks.remove(&stream) {
            task.abort();
        }
        if bidi && !self.relay {
            // a gRPC bidi stream's own handler takes the error (`GrpcBidiStreamHandler.exceptionCaught`): the response
            // ends with grpc-status INTERNAL and the exception's message, and the stream is not reset
            let message = format!("Header size exceeded max allowed size ({})", self.max_header_list);
            let fields = vec![(b"grpc-status".to_vec(), b"13".to_vec()), (b"grpc-message".to_vec(), message.into_bytes())];
            let _ = self.tx.send(Out::Trailers { stream, fields });
        } else if !known || self.relay {
            let _ = self.tx.send(Out::RefuseHeaderList { stream });
        } else {
            let _ = self.tx.send(Out::Reset { stream, code: PROTOCOL_ERROR });
        }
    }

    fn header_block(&mut self, stream: u32, block: &[u8], end_stream: bool) -> Result<(), ()> {
        let limit = u64::from(self.max_header_list);
        let mut size = 0u64;
        let mut fields = Vec::new();
        let decoded = self.decoder.decode_with_cb(block, |name, value| {
            size += (name.len() + value.len() + 32) as u64;
            if size <= limit {
                fields.push((name.into_owned(), value.into_owned()));
            }
        });
        if decoded.is_err() {
            self.go_away(COMPRESSION_ERROR);
            return Err(());
        }
        if size > limit {
            self.header_list_too_large(stream);
            return Ok(());
        }
        // No request header is refused: the multiplex codec's inbound validation is off (Netty 4.2.18 upgrade, after
        // 8.0.0), so upper-case names, connection-specific headers and `TE` other than `trailers` are accepted.
        self.last_stream = self.last_stream.max(stream);
        let first = self.streams.get(&stream).is_none_or(|i| i.fields.is_empty());
        let limit = max_request_body(&self.state).max(0) as u64;
        let incoming = self.streams.entry(stream).or_default();
        // A second block on a stream is its trailers.
        if first {
            incoming.declared = fields
                .iter()
                .find(|(n, _)| n.as_slice() == b"content-length")
                .and_then(|(_, v)| std::str::from_utf8(v).ok()?.trim().parse().ok());
            incoming.limit = limit;
            if incoming.declared.is_some_and(|declared| declared > limit) {
                // `HttpObjectAggregator` refuses a request announcing more than `maxRequestBodySize` on its head.
                self.too_large(stream);
                return Ok(());
            }
            // `HttpObjectAggregator.newContinueResponse` on a request whose HEADERS frame leaves the stream open: `100`
            // for `Expect: 100-continue`, which is then removed from the request, and `417` (the request never handled)
            // for any other expectation. A request that ended with its HEADERS frame is whole and keeps its `Expect`.
            let expect = fields.iter().find(|(n, _)| n.eq_ignore_ascii_case(b"expect")).map(|(_, v)| v.clone());
            if let Some(expect) = expect.filter(|_| !end_stream) {
                if !expect.eq_ignore_ascii_case(b"100-continue") {
                    self.streams.remove(&stream);
                    let fields = vec![(b":status".to_vec(), b"417".to_vec()), (b"content-length".to_vec(), b"0".to_vec())];
                    let _ = self.tx.send(Out::Headers { stream, fields, end: true });
                    return Ok(());
                }
                let _ = self.tx.send(Out::Headers { stream, fields: vec![(b":status".to_vec(), b"100".to_vec())], end: false });
                fields.retain(|(n, _)| !n.eq_ignore_ascii_case(b"expect"));
            }
            incoming.fields = fields;
            incoming.headers_only = end_stream;
        }
        if let Some(bidi) = incoming.bidi.take().filter(|_| end_stream) {
            // The client's trailers half-close a bidi stream.
            drop(bidi);
            self.streams.remove(&stream);
            return Ok(());
        }
        if first {
            // `GrpcBidiRouterHandler` decides on the first HEADERS frame, whether or not it ends the stream.
            self.open_bidi(stream);
        }
        if end_stream {
            if self.streams.get_mut(&stream).and_then(|incoming| incoming.bidi.take()).is_some() {
                // A bidi stream half-closed by its HEADERS frame: no message will arrive.
                self.streams.remove(&stream);
                return Ok(());
            }
            self.dispatch(stream);
        }
        Ok(())
    }

    /// `GrpcBidiRouterHandler` (with `grpcBidiStreamingEnabled`): a request for a bidirectional-streaming gRPC method
    /// is answered as its messages arrive; without a matching `grpcBidiResponse` it is handled whole once complete.
    /// A reset stream or a lost connection aborts the stream's task, which drops the response and so ends the session.
    fn open_bidi(&mut self, stream: u32) {
        use crate::grpc_plane::BidiTransport;
        let Some(incoming) = self.streams.get_mut(&stream) else { return };
        let header = |name: &[u8]| incoming.fields.iter().find(|(n, _)| n == name).map(|(_, v)| String::from_utf8_lossy(v).into_owned());
        let path = header(b":path").unwrap_or_default();
        let path = path.split('?').next().unwrap_or_default();
        let Some((body_tx, body_rx)) = crate::grpc_plane::bidi_channel(&self.state, BidiTransport::Http2, path, header(b"content-type").as_deref()) else {
            return;
        };
        incoming.bidi = Some(body_tx);
        let head = to_request(Incoming { fields: incoming.fields.clone(), headers_only: incoming.headers_only, ..Default::default() }, &self.conn, self.secure, None)
            .expect("a head is not decoded");
        let bidi_head = bidi_request(&incoming.fields, path);
        let (state, tx, backlog, event_loop) = (self.state.clone(), self.tx.clone(), self.backlog.clone(), self.conn.event_loop);
        // an active stream keeps the connection busy (`Http2ConnectionHandler.numActiveStreams`)
        let active = self.conn.idle.exchange();
        let task = tokio::spawn(crate::server::on_worker(Some(self.conn.event_loop), crate::grpc_plane::PIPELINE.scope(self.grpc, async move {
            let _active = active;
            state.connections.loop_free(event_loop).await;
            match crate::grpc_plane::open_bidi(&state, &bidi_head, body_rx, BidiTransport::Http2) {
                Ok(outcome) => write_outcome(tx, &backlog, stream, outcome, false).await,
                Err(mut body_rx) => {
                    // No bidi expectation: the request is collected and handled as any other.
                    let mut request = head;
                    let mut body = BytesMut::new();
                    while let Some(chunk) = body_rx.recv().await {
                        body.extend_from_slice(&chunk);
                    }
                    request.body = body.freeze();
                    if let Some((_, v)) = request.headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case("content-length")) {
                        *v = vec![request.body.len().to_string()];
                    }
                    respond(state, tx, &backlog, stream, request, false).await;
                }
            }
        })));
        self.tasks.insert(stream, task.abort_handle());
    }

    /// The request on `stream` is complete: it is answered by a task of its own.
    fn dispatch(&mut self, stream: u32) {
        let Some(incoming) = self.streams.get_mut(&stream) else { return };
        if incoming.dispatched {
            return;
        }
        incoming.dispatched = true;
        let mut incoming = self.streams.remove(&stream).expect("present");
        if self.relay {
            // A tunnel's client leg reads the request whole with `InboundHttp2ToHttpAdapter`, whose `fireChannelRead`
            // sets its `Content-Length` (`HttpUtil.setContentLength`) before the relay sends it on to MockServer.
            let length = incoming.body.len().to_string().into_bytes();
            match incoming.fields.iter_mut().find(|(n, _)| n.as_slice() == b"content-length") {
                Some((_, value)) => *value = length,
                None => incoming.fields.push((b"content-length".to_vec(), length)),
            }
        }
        let max_body = usize::try_from(self.state.config.int_property("maxRequestBodySize", 10_485_760)).unwrap_or(usize::MAX);
        let request = match to_request(incoming, &self.conn, self.secure, Some(max_body)) {
            Ok(request) => request,
            Err(failure) if failure.too_large() => {
                // Longer than `maxRequestBodySize` once decoded: the aggregator answers 413.
                self.too_large(stream);
                return;
            }
            Err(failure) => {
                // The decompressor failed the body: the stream's child channel closes, which resets it with CANCEL.
                handler::decode_failed(&self.state, &failure);
                let _ = self.tx.send(Out::Reset { stream, code: CANCEL });
                return;
            }
        };
        let (state, tx, backlog, relay, event_loop) = (self.state.clone(), self.tx.clone(), self.backlog.clone(), self.relay, self.conn.event_loop);
        let active = self.conn.idle.exchange();
        let task = tokio::spawn(crate::server::on_worker(Some(self.conn.event_loop), crate::grpc_plane::PIPELINE.scope(self.grpc, async move {
            let _active = active;
            // nothing is read on an event loop a runtime LLM call blocks
            state.connections.loop_free(event_loop).await;
            respond(state, tx, &backlog, stream, request, relay).await
        })));
        self.tasks.insert(stream, task.abort_handle());
    }
}

/// `GrpcBidiRouterHandler.synthesiseBidiRequest`: what a bidi stream is matched and logged as, `POST` to its path
/// with the HEADERS frame's non-pseudo fields only (no `host`, scheme or stream id, no keep-alive, protocol or TLS
/// flags), `content-type: application/grpc` when it carried none (`grpc_plane::open_bidi` adds the derived ones).
fn bidi_request(fields: &[(Vec<u8>, Vec<u8>)], path: &str) -> HttpRequest {
    let mut headers = MultiMap::new();
    for (name, value) in fields {
        if !name.is_empty() && name[0] != b':' {
            request::append(&mut headers, &request::header_text(name), request::header_text(value));
        }
    }
    HttpRequest { method: "POST".into(), path: path.to_string(), headers, ..HttpRequest::default() }
}

/// The request as MockServer models an HTTP/2 one: `:authority` as the `Host` header, header values one char per
/// byte, protocol `HTTP_2`. Netty's conversion leaves the stream id and the scheme on the request as `x-http2-`
/// extension headers, which `FullHttpRequestToMockServerHttpRequest` drops (`Http2ExtensionHeaders`, after 8.0.0),
/// with any of that family the peer sent. A request that ended with its HEADERS frame reaches the handler without
/// the aggregator's `Content-Length: 0`; a body sent without a `Content-Length` reaches it with
/// `Transfer-Encoding: chunked` and no `Content-Length`.
fn to_request(incoming: Incoming, conn: &Connection, secure: bool, max_body: Option<usize>) -> Result<HttpRequest, handler::DecodeFailure> {
    let mut method = String::new();
    let mut target = String::from("/");
    let mut headers = MultiMap::new();
    // `HttpConversionUtil.addHttp2ToHttpHeaders`: the fields in arrival order, `:authority` as `host` where it arrives;
    // it removes `Transfer-Encoding` and `Trailer`, and `HttpUtil.setKeepAlive` the `Connection` header, whatever their
    // case (the request headers are not validated, so a client can send any of them).
    for (name, value) in &incoming.fields {
        match name.as_slice() {
            b":method" => method = request::header_text(value),
            b":path" => target = request::header_text(value),
            b":authority" => request::append(&mut headers, "host", request::header_text(value)),
            n if n.starts_with(b":") || is_extension_header(n) => {}
            n if [&b"transfer-encoding"[..], b"trailer", b"connection"].iter().any(|r| r.eq_ignore_ascii_case(n)) => {}
            n => request::append(&mut headers, &request::header_text(n), request::header_text(value)),
        }
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target, None),
    };
    let sent_framing = request::first(&headers, "content-length").is_some() || request::first(&headers, "transfer-encoding").is_some();
    // `Http2StreamFrameToHttpObjectCodec`: a request whose HEADERS frame did not end the stream and announced no length
    // is chunked, whatever body follows; one that ended with its HEADERS frame has no framing
    // header at all. `PreserveHeadersNettyRemoves` sees it so, ahead of the decompressor and the aggregator.
    if !sent_framing && !incoming.headers_only {
        request::push(&mut headers, "transfer-encoding", "chunked".into());
    }
    let mut request = HttpRequest {
        method,
        path,
        query: query.as_deref().map(request::parse_target_query).unwrap_or_default(),
        raw_query: query,
        headers,
        body: incoming.body.freeze(),
        keep_alive: true,
        secure,
        protocol: "HTTP_2",
        local_address: crate::server::java_local_address(conn),
        remote_address: crate::server::java_socket_address(conn.client_address()),
        client_certificates: conn.client_certificates.clone(),
        remote_target: conn.proxy_target.clone(),
        ..HttpRequest::default()
    };
    match max_body {
        Some(max_body) => handler::complete(&mut request, max_body)?,
        None => handler::complete_head(&mut request),
    }
    if !sent_framing && incoming.headers_only {
        request.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
    }
    Ok(request)
}

/// Netty's `HttpConversionUtil.ExtensionHeaderNames`, compared ignoring case (`Http2ExtensionHeaders.isExtensionHeader`).
fn is_extension_header(name: &[u8]) -> bool {
    const NAMES: [&[u8]; 6] = [
        b"x-http2-stream-id",
        b"x-http2-scheme",
        b"x-http2-path",
        b"x-http2-stream-promise-id",
        b"x-http2-stream-dependency-id",
        b"x-http2-stream-weight",
    ];
    NAMES.iter().any(|n| n.eq_ignore_ascii_case(name))
}

/// `:status` then the reply's headers, lower-cased, without the connection-specific ones.
fn response_fields(reply: &Reply) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut fields = vec![(b":status".to_vec(), reply.status.to_string().into_bytes())];
    // A `content-length` beside a `Transfer-Encoding` is the model's own or its `contentLengthHeaderOverride`
    // (`Reply::finalize` drops every computed one), and HTTP/2 conversion keeps it.
    for (name, value) in &reply.headers {
        let lower = name.to_ascii_lowercase();
        if CONNECTION_SPECIFIC.contains(&lower.as_str()) || lower.starts_with(':') {
            continue;
        }
        fields.push((lower.into_bytes(), request::header_bytes(value)));
    }
    fields
}

/// An RFC 7230 `token`, the only form of header name HTTP/2 conversion lets through.
fn is_token(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// WebSocket endpoints cannot be reached over HTTP/2 (no upgrade on a stream).
const WEBSOCKET_PATHS: &[&str] = &["/_mockserver_callback_websocket", "/_mockserver_ui_websocket"];

/// `relay`: the stream is a tunnel's, whose loopback leg reads the response back ([`handler::loopback_decoded`]): one
/// it cannot decode resets the stream (`LoopbackHttp2StreamErrorHandler`, INTERNAL_ERROR).
async fn respond(state: Arc<State>, tx: mpsc::UnboundedSender<Out>, backlog: &Backlog, stream: u32, request: HttpRequest, relay: bool) {
    let head_only = request.method.eq_ignore_ascii_case("HEAD");
    if WEBSOCKET_PATHS.contains(&request.path.as_str()) {
        let mut reply = Reply::status(501).finalize(&request, &state.config);
        reply.headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
        let _ = tx.send(Out::Headers { stream, fields: response_fields(&reply), end: true });
        return;
    }
    // observed until its outcome is written (dropped unanswered with the task when the client resets the stream)
    let mut observed = handler::observe(&state, &request);
    let decoded = std::time::Instant::now();
    let outcome = handler::dispatch(&state, request, &Default::default()).await;
    // a response is written on the connection's event loop, once a runtime LLM call no longer blocks it
    if let Some(event_loop) = crate::server::current_worker() {
        state.connections.loop_free(event_loop).await;
    }
    handler::answered(&mut observed, &outcome, "HTTP_2");
    let outcome = match outcome {
        Outcome::Respond(reply) if relay && !head_only => {
            let max = usize::try_from(state.config.int_property("maxRequestBodySize", 10_485_760)).unwrap_or(usize::MAX);
            match handler::loopback_decoded(reply, max) {
                Ok(reply) => Outcome::Respond(reply),
                Err(()) => {
                    let _ = tx.send(Out::Reset { stream, code: INTERNAL_ERROR });
                    return;
                }
            }
        }
        // `LoopbackHttp2ResponseStreamer`: a response of undeclared length is relayed frame by frame unless it is in a
        // coding the loopback decodes, which is held whole (nothing else bounds what it decodes to) and decoded
        Outcome::Stream { head, chunks, trailers, .. } if relay && !head_only && loopback_holds_whole(&head.headers) => {
            let max = usize::try_from(state.config.int_property("maxRequestBodySize", 10_485_760)).unwrap_or(usize::MAX);
            match Box::pin(loopback_aggregated(head, chunks, trailers, max)).await {
                Some(reply) => Outcome::Respond(reply),
                None => {
                    let _ = tx.send(Out::Reset { stream, code: INTERNAL_ERROR });
                    return;
                }
            }
        }
        outcome => outcome,
    };
    write_outcome(tx, backlog, stream, outcome, head_only).await;
    // `mock_server_request_transport_duration_seconds`: until the response's last frame is handed to the writer
    if crate::metrics::enabled(&state.config) {
        state.config.metrics.request_transport(decoded.elapsed().as_secs_f64());
    }
}

/// Whether the HTTP/2 loopback holds a streamed response whole: no `content-length` and a coding it decodes
/// (`BoundedZstdHttpContentDecompressor.decodes`).
fn loopback_holds_whole(headers: &[(String, String)]) -> bool {
    let mut probe: Vec<(String, String)> = headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("content-encoding")).cloned().collect();
    !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-length")) && !probe.is_empty() && matches!(crate::client::decoding::Decoder::for_head(&mut probe, true), Ok(Some(_)) | Err(_))
}

/// `LoopbackAggregatingListener` on a streamed response: decoded as it arrives (`BoundedZstdDecompressorFrameListener`),
/// aggregated up to `max` decoded bytes; `None` when it fails to decode or decodes past `max` (the stream is reset).
async fn loopback_aggregated(
    mut head: crate::reply::Reply,
    mut chunks: mpsc::Receiver<Bytes>,
    trailers: Option<tokio::sync::oneshot::Receiver<Vec<(String, String)>>>,
    max: usize,
) -> Option<crate::reply::Reply> {
    let mut headers = head.headers.clone();
    let mut decoder = crate::client::decoding::Decoder::for_head(&mut headers, true).ok()??;
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = chunks.recv().await {
        for piece in decoder.push_pieces(&chunk, max.saturating_sub(body.len())).ok()? {
            body.extend_from_slice(&piece);
        }
        if body.len() > max {
            return None;
        }
    }
    if let Some(trailers) = trailers {
        head.trailers = trailers.await.unwrap_or_default();
    }
    crate::client::decoding::Decoder::finish_headers(&mut headers, body.len());
    head.headers = headers;
    head.body = body.into();
    head.chunk_size = None;
    head.chunked_for_trailers = false;
    Some(head)
}

/// Until a streamed response's last frame is written (or the stream or connection is gone): the stream stays active,
/// so a connection with response data still waiting for its client is not closed as idle.
async fn written_out(tx: &mpsc::UnboundedSender<Out>, backlog: &Backlog, stream: u32) {
    tokio::select! {
        _ = backlog.until(stream, |_| false) => {}
        _ = tx.closed() => {}
    }
}

/// Writes a handled request's outcome on its stream.
async fn write_outcome(tx: mpsc::UnboundedSender<Out>, backlog: &Backlog, stream: u32, mut outcome: Outcome, head_only: bool) {
    while let Outcome::GoAway { last_stream_id, error_code, then } = outcome {
        let _ = tx.send(Out::GoAway { last: last_stream_id, code: error_code });
        outcome = *then;
    }
    match outcome {
        Outcome::GoAway { .. } => unreachable!("unwrapped above"),
        Outcome::Respond(reply) if crate::dataplane::is_final_informational("HTTP_2", reply.status) => {
            // `NettyResponseWriter.writeWhole`: a final 1xx goes out as an interim response, its head alone, which may
            // not end a stream (RFC 9113 section 8.1), so the stream is then reset with NO_ERROR.
            let _ = tx.send(Out::Headers { stream, fields: response_fields(&reply), end: false });
            let _ = tx.send(Out::Reset { stream, code: NO_ERROR });
        }
        Outcome::Respond(reply) if reply.headers.iter().any(|(name, _)| !is_token(name)) => {
            // Netty's HTTP/2 header validation refuses a name that is not an RFC 7230 token: what reaches the client is
            // the status alone, and the stream ends there.
            let _ = tx.send(Out::Headers { stream, fields: vec![(b":status".to_vec(), reply.status.to_string().into_bytes())], end: true });
        }
        Outcome::Respond(reply) => {
            let empty = reply.body.is_empty() || head_only;
            // A response to HEAD is its header block alone, which ends the stream: no DATA and no trailers (RFC 9110
            // section 9.3.2). Upstream fix c4e2b8985, after 8.0.0, whose codec sends both (`docs/divergences.md`).
            let trailers: Vec<(Vec<u8>, Vec<u8>)> = if head_only {
                Vec::new()
            } else {
                reply.trailers.iter().map(|(n, v)| (n.to_ascii_lowercase().into_bytes(), request::header_bytes(v))).collect()
            };
            let _ = tx.send(Out::Headers { stream, fields: response_fields(&reply), end: empty && trailers.is_empty() });
            if !empty {
                let _ = tx.send(Out::Data { stream, data: reply.body.clone(), end: trailers.is_empty() });
            }
            if !trailers.is_empty() {
                let _ = tx.send(Out::Trailers { stream, fields: trailers });
            }
            if reply.reset_connection {
                let _ = tx.send(Out::Kill);
            }
        }
        Outcome::Stream { head, mut chunks, trailers, .. } if head_only => {
            // The header block ends a HEAD's stream; the body and trailers produced after it are discarded, as
            // upstream's codec releases what is written after the block (fix c4e2b8985), so the producer runs on.
            let _ = tx.send(Out::Headers { stream, fields: response_fields(&head), end: true });
            while chunks.recv().await.is_some() {}
            if let Some(rx) = trailers {
                let _ = rx.await;
            }
        }
        Outcome::Stream { head, mut chunks, trailers, chunk_count, upstream_end, .. } => {
            let _ = tx.send(Out::Headers { stream, fields: response_fields(&head), end: false });
            let mut trailers = trailers;
            let mut sent = 0;
            loop {
                // a connection that has closed takes nothing more: the producer (and a forward's upstream) is dropped;
                // one whose client is not taking this stream holds the producer back
                let chunk = tokio::select! {
                    chunk = async {
                        backlog.until(stream, |queued| queued <= BACKLOG_HIGH_WATER).await;
                        chunks.recv().await
                    } => chunk,
                    _ = tx.closed() => return,
                };
                let Some(chunk) = chunk else { break };
                sent += 1;
                if chunk_count == Some(sent) {
                    // The last chunk ends the stream, unless trailers follow it.
                    let fields = match trailers.take() {
                        Some(rx) => rx.await.unwrap_or_default(),
                        None => Vec::new(),
                    };
                    backlog.handed(stream, chunk.len());
                    let _ = tx.send(Out::Data { stream, data: chunk, end: fields.is_empty() });
                    if !fields.is_empty() {
                        let fields = fields.iter().map(|(n, v)| (n.to_ascii_lowercase().into_bytes(), request::header_bytes(v))).collect();
                        let _ = tx.send(Out::Trailers { stream, fields });
                    }
                    return written_out(&tx, backlog, stream).await;
                }
                backlog.handed(stream, chunk.len());
                if !chunk.is_empty() && tx.send(Out::Data { stream, data: chunk, end: false }).is_err() {
                    return;
                }
            }
            if upstream_end.is_some_and(|e| e.is_aborted()) {
                // An aborted forward ends without its last frame: the stream is reset (upstream c9fb69fd5).
                let _ = tx.send(Out::Reset { stream, code: CANCEL });
                return;
            }
            let trailers = match trailers {
                Some(rx) => rx.await.unwrap_or_default(),
                None => Vec::new(),
            };
            if trailers.is_empty() {
                let _ = tx.send(Out::Data { stream, data: Bytes::new(), end: true });
            } else {
                let fields = trailers.iter().map(|(n, v)| (n.to_ascii_lowercase().into_bytes(), request::header_bytes(v))).collect();
                let _ = tx.send(Out::Trailers { stream, fields });
            }
            written_out(&tx, backlog, stream).await;
        }
        Outcome::Reset(code) => {
            let _ = tx.send(Out::Reset { stream, code });
        }
        // A dropped connection closes the stream's child channel, which Netty answers with RST_STREAM CANCEL.
        // `ConnectionReset.reset` on the parent connection: every stream on it dies with the RST, no response is sent.
        Outcome::ResetConnection { .. } => {
            let _ = tx.send(Out::Kill);
        }
        Outcome::DropConnection | Outcome::Raw { close: true, .. } => {
            let _ = tx.send(Out::Reset { stream, code: CANCEL });
        }
        // Deliberately nothing: raw bytes written to a child channel never reach the client, and without a close the
        // stream stays open (as a hang does) until the client resets it or gives up; the oracle sends no frame either.
        Outcome::Raw { close: false, .. } | Outcome::Hang => {}
        Outcome::WebSocketRelay { .. } | Outcome::WebSocket { .. } => {
            let _ = tx.send(Out::Reset { stream, code: INTERNAL_ERROR });
        }
    }
}

/// Writes frames in the order they are produced, holding DATA back while the peer's windows are exhausted.
#[allow(clippy::too_many_arguments)]
async fn write_loop<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut rx: mpsc::UnboundedReceiver<Out>,
    socket: crate::chaos::io::Socket,
    killed: Arc<tokio::sync::Notify>,
    go_away_last: Arc<std::sync::atomic::AtomicU32>,
    relay: bool,
    mut stalls: Option<crate::write_stall::StreamStalls>,
    tasks: Tasks,
    backlog: Arc<Backlog>,
    event_loop: (crate::server::OpenConnections, usize),
) {
    let _backlog = BacklogGuard(backlog.clone());
    let backlog = &*backlog;
    let mut kill = false;
    let mut shutdown = false;
    // A GOAWAY with an error code closes the connection once it is written (`Http2ConnectionHandler.goAway`).
    let mut close = false;
    // The last stream of the GOAWAY sent, if any: Netty's `goAwaySent` closes every stream above it, so nothing more
    // is written on those.
    let mut sent_last: Option<u32> = None;
    let mut encoder = crate::hpack::Encoder::new();
    let mut connection_window = DEFAULT_WINDOW;
    let mut initial_window = DEFAULT_WINDOW;
    let mut max_frame = DEFAULT_MAX_FRAME;
    let mut windows: HashMap<u32, i64> = HashMap::new();
    let mut pending: VecDeque<(u32, Pending)> = VecDeque::new();
    // Streams the client reset (or that were reset here): nothing more is written on them, whatever a late producer
    // still sends.
    let mut closed: HashSet<u32> = HashSet::new();
    // A tunnel's streams whose final response head has been written (`Http2Stream.isHeadersSent`; a 1xx is not one).
    let mut heads_sent: HashSet<u32> = HashSet::new();
    loop {
        // while DATA waits on a window, a write-stall check is due even if nothing else arrives
        let first = match stalls.as_ref().and_then(|s| s.next_check()) {
            Some(at) => tokio::select! {
                message = rx.recv() => message.map(Some),
                _ = tokio::time::sleep_until(at.into()) => Some(None),
            },
            None => rx.recv().await.map(Some),
        };
        let Some(first) = first else { break };
        // nothing is written, and no write-stall check runs, while a runtime LLM call blocks the connection's loop
        event_loop.0.loop_free(event_loop.1).await;
        let mut out: Vec<u8> = Vec::new();
        let mut batch: Vec<Out> = first.into_iter().collect();
        while let Ok(more) = rx.try_recv() {
            batch.push(more);
        }
        for message in batch {
            if close {
                break;
            }
            match message {
                Out::Headers { stream, .. } | Out::Data { stream, .. } | Out::Trailers { stream, .. }
                    if closed.contains(&stream) || sent_last.is_some_and(|last| stream > last) =>
                {
                    backlog.close(stream);
                }
                Out::Headers { stream, fields, end } => {
                    let informational = fields.iter().any(|(n, v)| n.as_slice() == b":status" && v.len() == 3 && v[0] == b'1');
                    if relay && !informational {
                        heads_sent.insert(stream);
                    }
                    windows.entry(stream).or_insert(initial_window);
                    // a tunnel's interim `100` goes out without the priority fields its response heads carry
                    out.extend(headers_frames(&mut encoder, relay && !informational, max_frame, stream, &fields, end));
                    if end {
                        windows.remove(&stream);
                    }
                }
                Out::Data { stream, data, end } => pending.push_back((stream, Pending::Data(data, end))),
                Out::Trailers { stream, fields } => pending.push_back((stream, Pending::Trailers(fields))),
                Out::Reset { stream, code } => {
                    closed.insert(stream);
                    pending.retain(|(s, _)| *s != stream);
                    end_stream(&mut windows, &mut stalls, backlog, stream);
                    out.extend(frame(RST_STREAM, 0, stream, &code.to_be_bytes()));
                }
                Out::RefuseHeaderList { stream } => {
                    if !heads_sent.contains(&stream) && !closed.contains(&stream) {
                        out.extend(headers_frames(&mut encoder, false, max_frame, stream, &[(b":status".to_vec(), b"431".to_vec())], true));
                    }
                    closed.insert(stream);
                    pending.retain(|(s, _)| *s != stream);
                    end_stream(&mut windows, &mut stalls, backlog, stream);
                    out.extend(frame(RST_STREAM, 0, stream, &PROTOCOL_ERROR.to_be_bytes()));
                }
                Out::Forget(stream) => {
                    closed.insert(stream);
                    pending.retain(|(s, _)| *s != stream);
                    end_stream(&mut windows, &mut stalls, backlog, stream);
                }
                Out::Frame(bytes) => out.extend(bytes),
                Out::Kill => kill = true,
                Out::Shutdown => shutdown = true,
                Out::Close => close = true,
                Out::GoAway { last, code } => {
                    let last = last.unwrap_or(0x7fff_ffff);
                    // `DefaultHttp2Connection.goAwaySent`: a GOAWAY that does not lower the last stream already
                    // advertised is not sent again.
                    if sent_last.is_none_or(|previous| last < previous) {
                        let mut payload = last.to_be_bytes().to_vec();
                        payload.extend_from_slice(&code.to_be_bytes());
                        out.extend(frame(GOAWAY, 0, 0, &payload));
                        sent_last = Some(last);
                        go_away_last.store(last, std::sync::atomic::Ordering::SeqCst);
                        for &(s, _) in pending.iter().filter(|(s, _)| *s > last) {
                            backlog.close(s);
                        }
                        pending.retain(|(s, _)| *s <= last);
                        close = code != 0;
                        if close {
                            pending.clear();
                        }
                    }
                }
                Out::PeerSettings { initial_window: window, max_frame: frame_size, table_size, last_stream } => {
                    if let Some(window) = window {
                        let delta = window as i64 - initial_window;
                        if delta > 0 && windows.values().any(|w| *w > MAX_WINDOW - delta) {
                            // `DefaultHttp2RemoteFlowController.initialWindowSize`: a rise that takes a stream's window
                            // past 2^31-1 is a FLOW_CONTROL_ERROR (RFC 9113 section 6.9.2), which closes the connection
                            // with a GOAWAY naming the last stream the client opened
                            let mut payload = last_stream.to_be_bytes().to_vec();
                            payload.extend_from_slice(&FLOW_CONTROL_ERROR.to_be_bytes());
                            out.extend(frame(GOAWAY, 0, 0, &payload));
                            sent_last = Some(last_stream);
                            go_away_last.store(last_stream, std::sync::atomic::Ordering::SeqCst);
                            pending.clear();
                            close = true;
                            continue;
                        }
                        for w in windows.values_mut() {
                            *w += delta;
                        }
                        initial_window = window as i64;
                    }
                    if let Some(size) = frame_size {
                        max_frame = (size as usize).clamp(DEFAULT_MAX_FRAME, MAX_FRAME_ACCEPTED);
                    }
                    if let Some(size) = table_size {
                        encoder.set_max_table_size(size as usize);
                    }
                }
                Out::PeerWindow { stream, increment, open } => {
                    // what the client returns orders which timed-out stream is reset first (`WrittenBytesFlowController`)
                    if let Some(stalls) = stalls.as_mut() {
                        stalls.window_returned(stream, increment as u64);
                    }
                    if stream == 0 {
                        connection_window += increment as i64;
                    } else if let Some(w) = windows.get_mut(&stream) {
                        *w += increment as i64;
                    } else if open && !closed.contains(&stream) {
                        windows.insert(stream, initial_window + increment as i64);
                    }
                }
            }
        }
        // DATA as far as the windows allow; a stream's later data waits behind its blocked earlier data.
        let mut blocked: HashSet<u32> = HashSet::new();
        let mut i = 0;
        while i < pending.len() {
            let stream = pending[i].0;
            if blocked.contains(&stream) {
                i += 1;
                continue;
            }
            if let Pending::Trailers(fields) = &pending[i].1 {
                out.extend(headers_frames(&mut encoder, relay, max_frame, stream, fields, true));
                end_stream(&mut windows, &mut stalls, backlog, stream);
                pending.remove(i);
                continue;
            }
            let window = windows.get(&stream).copied().unwrap_or(initial_window);
            let Pending::Data(data, end) = &mut pending[i].1 else { unreachable!("trailers handled above") };
            if data.is_empty() {
                out.extend(frame(DATA, if *end { END_STREAM } else { 0 }, stream, &[]));
                if *end {
                    end_stream(&mut windows, &mut stalls, backlog, stream);
                }
                pending.remove(i);
                continue;
            }
            let n = data.len().min(max_frame).min(window.max(0) as usize).min(connection_window.max(0) as usize);
            if n == 0 {
                blocked.insert(stream);
                i += 1;
                continue;
            }
            let chunk = data.split_to(n);
            if let Some(stalls) = stalls.as_mut() {
                stalls.written(stream, n as u64);
            }
            backlog.written(stream, n);
            connection_window -= n as i64;
            if let Some(w) = windows.get_mut(&stream) {
                *w -= n as i64;
            }
            let finished = data.is_empty();
            out.extend(frame(DATA, if finished && *end { END_STREAM } else { 0 }, stream, &chunk));
            if finished {
                if *end {
                    end_stream(&mut windows, &mut stalls, backlog, stream);
                }
                pending.remove(i);
            }
        }
        // `Http2StreamWriteStallHandler`: streams whose data waited for the timeout with none of it taken are reset
        if let Some(stalls) = stalls.as_mut() {
            let window = |stream: u32| windows.get(&stream).copied().unwrap_or(initial_window);
            for stream in stalls.check(pending.iter().map(|(stream, _)| *stream), window, connection_window) {
                closed.insert(stream);
                pending.retain(|(s, _)| *s != stream);
                windows.remove(&stream);
                backlog.close(stream);
                out.extend(frame(RST_STREAM, 0, stream, &CANCEL.to_be_bytes()));
                if let Some(task) = tasks.remove(&stream) {
                    task.abort();
                }
            }
        }
        if !out.is_empty() && (writer.write_all(&out).await.is_err() || writer.flush().await.is_err()) {
            return;
        }
        if kill {
            // `forceReset` on the parent connection: every stream on it dies with the RST.
            socket.reset_on_close();
            killed.notify_one();
            return;
        }
        if close {
            killed.notify_one();
            return;
        }
        if shutdown {
            let _ = writer.shutdown().await;
            return;
        }
    }
}

/// A stream that ended or was reset: no window is kept for it, the write-stall watcher forgets it, and nothing waits
/// on its backlog.
fn end_stream(windows: &mut HashMap<u32, i64>, stalls: &mut Option<crate::write_stall::StreamStalls>, backlog: &Backlog, stream: u32) {
    windows.remove(&stream);
    backlog.close(stream);
    if let Some(stalls) = stalls.as_mut() {
        stalls.closed(stream);
    }
}

/// A response received by [`send`]: its head, then the body as the upstream sends it.
pub struct ClientResponse {
    pub status: u32,
    pub headers: Vec<(String, String)>,
    pub body: mpsc::Receiver<Bytes>,
    /// The trailing headers, once the body has ended (none when the stream ended without them), with the length of
    /// their header block as received.
    pub trailers: tokio::sync::oneshot::Receiver<(Vec<(String, String)>, usize)>,
    /// The length of the head's header block as received (HPACK-encoded, across its CONTINUATION frames).
    pub block_len: usize,
    /// The head's HEADERS frame ended the stream: there is no body (an HTTP/2 answer to HEAD, upstream c4e2b8985).
    pub ended: bool,
    /// The client's stream the request went out on (3 on a new connection, 5 on its second request, …).
    pub stream: u32,
}

/// The stream the forwarding client sends its request on: the oracle's `Http2StreamChannelBootstrap` opens stream 3 on
/// a fresh connection (the upstream logs `x-http2-stream-id: 3`, scenario `forward_h2_stream_idle_timeout`).
pub const CLIENT_STREAM: u32 = 3;

/// One HTTP/2 request on a connection of its own (stream [`CLIENT_STREAM`]), closed with `GOAWAY(NO_ERROR)` once the
/// response has ended. `Err` when the connection fails or the stream is reset before a response, with the connection
/// error Netty's frame reader raises on what the upstream sent (`FRAME_SIZE_ERROR: …`), if any.
#[cfg(test)]
pub async fn send<S>(io: S, method: &str, authority: &str, path: &str, headers: &[(String, String)], body: Bytes) -> Result<ClientResponse, Option<String>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    ClientConnection::start(io).send(method, authority, path, headers, body).await.map_err(ClientFailure::into_error)
}

/// Why a [`ClientConnection::send`] got no response.
#[derive(Debug)]
pub enum ClientFailure {
    /// The connection had already ended: nothing of the request was written.
    NotSent,
    /// The connection ended, or the stream was reset, before a response head: what a stale pooled connection looks
    /// like (`SocketConnectionException`, closed without a response).
    Closed,
    /// The connection failed with the error Netty's frame reader raises on what the upstream sent.
    Error(String),
}

impl ClientFailure {
    /// The connection error, if the upstream caused one.
    #[cfg(test)]
    pub fn into_error(self) -> Option<String> {
        match self {
            ClientFailure::Error(error) => Some(error),
            ClientFailure::NotSent | ClientFailure::Closed => None,
        }
    }
}

enum Command {
    Request { fields: Vec<(Vec<u8>, Vec<u8>)>, body: Bytes, reply: tokio::sync::oneshot::Sender<Result<ClientResponse, ClientFailure>> },
    /// `RST_STREAM` with this code on the stream in flight, which is then forgotten.
    Reset(u32),
    /// `GOAWAY` with this code and debug data, then the connection closes.
    GoAway(u32, Vec<u8>),
}

/// The forwarding client's side of an HTTP/2 connection (Netty's `Http2FrameCodec` under `Http2MultiplexHandler`, one
/// `Http2StreamChannel` per request), as lenient as Netty's codec about what the upstream sends. Requests go out one
/// at a time, each on a stream of its own (3, 5, 7, …: `Http2StreamChannelBootstrap` opens stream 3 first), so a
/// connection can be pooled between them; header blocks are written by Netty's `HpackEncoder`, whose dynamic table
/// lives as long as the connection. Dropping it closes the connection with `GOAWAY(NO_ERROR)` once the stream in
/// flight has ended (`Http2ConnectionHandler.close`).
pub struct ClientConnection {
    commands: mpsc::UnboundedSender<Command>,
    open: Arc<std::sync::atomic::AtomicBool>,
    /// The upstream answered on a stream of its own, so the request/response pairing holds only for this connection's
    /// first request (`tryReleaseHttp2ParentToPool`).
    foreign: Arc<std::sync::atomic::AtomicBool>,
    /// The connection error that ended it, if the upstream caused one.
    failure: Arc<parking_lot::Mutex<Option<String>>>,
}

impl ClientConnection {
    /// The connection's preface and settings go out at once; its frames are read from then on.
    pub fn start<S>(io: S) -> ClientConnection
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (commands, rx) = mpsc::unbounded_channel();
        let open = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let foreign = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let failure = Arc::new(parking_lot::Mutex::new(None));
        tokio::spawn(client_loop(io, rx, open.clone(), foreign.clone(), failure.clone()));
        ClientConnection { commands, open, foreign, failure }
    }

    /// Neither side has ended the connection.
    pub fn is_open(&self) -> bool {
        self.open.load(std::sync::atomic::Ordering::SeqCst) && !self.commands.is_closed()
    }

    /// Open, and fit to carry another request.
    pub fn reusable(&self) -> bool {
        self.is_open() && !self.foreign.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// One request on a new stream: its response head, then the body as the upstream sends it.
    pub async fn send(&self, method: &str, authority: &str, path: &str, headers: &[(String, String)], body: Bytes) -> Result<ClientResponse, ClientFailure> {
        let mut fields: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b":method".to_vec(), method.as_bytes().to_vec()),
            (b":scheme".to_vec(), b"https".to_vec()),
            (b":authority".to_vec(), authority.as_bytes().to_vec()),
            (b":path".to_vec(), path.as_bytes().to_vec()),
        ];
        for (name, value) in headers {
            let lower = name.to_ascii_lowercase();
            // Netty's HTTP/1-to-HTTP/2 conversion drops its own extension headers (`HTTP_TO_HTTP2_HEADER_BLACKLIST`).
            let extension = matches!(lower.as_str(), "x-http2-stream-id" | "x-http2-scheme" | "x-http2-path" | "x-http2-authority" | "x-http2-stream-weight" | "x-http2-stream-dependency-id");
            if !CONNECTION_SPECIFIC.contains(&lower.as_str()) && lower != "te" && !extension {
                fields.push((lower.into_bytes(), request::header_bytes(value)));
            }
        }
        let (reply, response) = tokio::sync::oneshot::channel();
        if !self.open.load(std::sync::atomic::Ordering::SeqCst) || self.commands.send(Command::Request { fields, body, reply }).is_err() {
            // A connection the upstream broke before the request went out fails it with that error.
            return Err(self.failure.lock().clone().map_or(ClientFailure::NotSent, ClientFailure::Error));
        }
        response.await.unwrap_or(Err(ClientFailure::Closed))
    }

    /// A stream error on the stream in flight: `RST_STREAM` with `code`.
    pub fn reset(&self, code: u32) {
        let _ = self.commands.send(Command::Reset(code));
    }

    /// Closes the connection with `GOAWAY(code)`, `debug` as its debug data.
    pub fn go_away(&self, code: u32, debug: &str) {
        self.open.store(false, std::sync::atomic::Ordering::SeqCst);
        let _ = self.commands.send(Command::GoAway(code, debug.as_bytes().to_vec()));
    }
}

/// A response's trailer fields and their size.
type Trailers = (Vec<(String, String)>, usize);

/// The request in flight on a [`ClientConnection`].
struct Active {
    stream: u32,
    head: Option<tokio::sync::oneshot::Sender<Result<ClientResponse, ClientFailure>>>,
    body: Option<mpsc::Sender<Bytes>>,
    trailers: Option<tokio::sync::oneshot::Sender<Trailers>>,
    /// What of the request body the windows have not let out yet.
    pending: Bytes,
    window: i64,
}

impl Active {
    fn fail(&mut self, failure: ClientFailure) {
        if let Some(head) = self.head.take() {
            let _ = head.send(Err(failure));
        }
    }
}

/// What the connection does after a frame.
enum Next {
    Continue,
    /// The connection is over: with Netty's connection error on what the upstream sent, if that is why.
    End(Option<String>),
}

struct ClientState {
    encoder: crate::hpack::Encoder,
    decoder: loona_hpack::Decoder<'static>,
    active: Option<Active>,
    next_stream: u32,
    connection_window: i64,
    peer_initial_window: i64,
    max_frame: usize,
    first: bool,
    /// A header block still waiting for CONTINUATION frames: its stream, bytes and whether its HEADERS ended the stream.
    block: Option<(u32, Vec<u8>, bool)>,
    /// The upstream sent GOAWAY: the connection ends when the stream in flight does.
    going_away: bool,
    foreign: Arc<std::sync::atomic::AtomicBool>,
}

async fn client_loop<S>(io: S, mut commands: mpsc::UnboundedReceiver<Command>, open: Arc<std::sync::atomic::AtomicBool>, foreign: Arc<std::sync::atomic::AtomicBool>, shared_failure: Arc<parking_lot::Mutex<Option<String>>>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(io);
    let mut state = ClientState {
        encoder: crate::hpack::Encoder::new(),
        decoder: loona_hpack::Decoder::new(),
        active: None,
        next_stream: CLIENT_STREAM,
        connection_window: DEFAULT_WINDOW,
        peer_initial_window: DEFAULT_WINDOW,
        max_frame: DEFAULT_MAX_FRAME,
        first: true,
        block: None,
        going_away: false,
        foreign,
    };
    // Windows opened wide at once, so the upstream never waits for this side.
    let mut hello = PREFACE.to_vec();
    let mut settings = Vec::new();
    settings.extend_from_slice(&0x2u16.to_be_bytes());
    settings.extend_from_slice(&0u32.to_be_bytes());
    settings.extend_from_slice(&0x4u16.to_be_bytes());
    settings.extend_from_slice(&0x7fff_ffffu32.to_be_bytes());
    hello.extend(frame(SETTINGS, 0, 0, &settings));
    hello.extend(window_update(0, 0x7fff_ffff - DEFAULT_WINDOW as u32));
    let mut failure = None;
    let mut buf = BytesMut::with_capacity(32 * 1024);
    let mut handle_dropped = false;
    if writer.write_all(&hello).await.is_ok() && writer.flush().await.is_ok() {
        'connection: loop {
            if state.flush_body(&mut writer).await.is_err() {
                break;
            }
            // The handle is gone: nothing more will be sent. A response being relayed is read to its end; one nobody
            // waits for any more is cancelled.
            if handle_dropped {
                if let Some(active) = state.active.as_ref().filter(|a| a.head.as_ref().is_some_and(|h| h.is_closed())) {
                    let _ = writer.write_all(&frame(RST_STREAM, 0, active.stream, &CANCEL.to_be_bytes())).await;
                    state.active = None;
                }
                if state.active.is_none() {
                    let _ = writer.write_all(&go_away_frame(0, NO_ERROR, &[])).await;
                    let _ = writer.flush().await;
                    let _ = writer.shutdown().await;
                    break;
                }
            }
            if state.going_away && state.active.is_none() {
                break;
            }
            let watch = state.active.as_ref().and_then(|a| a.body.clone());
            tokio::select! {
                command = commands.recv(), if !handle_dropped => match command {
                    None => handle_dropped = true,
                    Some(Command::Request { fields, body, reply }) => {
                        if state.active.is_some() || state.going_away {
                            let _ = reply.send(Err(ClientFailure::NotSent));
                            continue;
                        }
                        let stream = state.next_stream;
                        state.next_stream += 2;
                        let out = headers_frames(&mut state.encoder, false, state.max_frame, stream, &fields, body.is_empty());
                        state.active = Some(Active { stream, head: Some(reply), body: None, trailers: None, pending: body, window: state.peer_initial_window });
                        if writer.write_all(&out).await.is_err() || writer.flush().await.is_err() {
                            break;
                        }
                    }
                    Some(Command::Reset(code)) => {
                        if let Some(mut active) = state.active.take() {
                            active.fail(ClientFailure::Closed);
                            if writer.write_all(&frame(RST_STREAM, 0, active.stream, &code.to_be_bytes())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Command::GoAway(code, debug)) => {
                        let _ = writer.write_all(&go_away_frame(0, code, &debug)).await;
                        let _ = writer.flush().await;
                        let _ = writer.shutdown().await;
                        break;
                    }
                },
                () = async move { match watch { Some(body) => body.closed().await, None => std::future::pending().await } } => {
                    // Nobody reads the response any more: the stream is cancelled, as closing its child channel does.
                    if let Some(active) = state.active.take() && writer.write_all(&frame(RST_STREAM, 0, active.stream, &CANCEL.to_be_bytes())).await.is_err() {
                        break;
                    }
                }
                read = reader.read_buf(&mut buf) => {
                    if !matches!(read, Ok(n) if n > 0) {
                        break;
                    }
                    loop {
                        match state.next_frame(&mut buf, &mut writer).await {
                            Ok(None) => break,
                            Ok(Some(Next::Continue)) => {}
                            Ok(Some(Next::End(error))) => {
                                failure = error;
                                break 'connection;
                            }
                            Err(_) => break 'connection,
                        }
                    }
                }
            }
        }
    }
    *shared_failure.lock() = failure.clone();
    open.store(false, std::sync::atomic::Ordering::SeqCst);
    if let Some(mut active) = state.active.take() {
        active.fail(failure.clone().map_or(ClientFailure::Closed, ClientFailure::Error));
    }
    commands.close();
    while let Ok(command) = commands.try_recv() {
        if let Command::Request { reply, .. } = command {
            let _ = reply.send(Err(failure.clone().map_or(ClientFailure::NotSent, ClientFailure::Error)));
        }
    }
}

fn go_away_frame(last: u32, code: u32, debug: &[u8]) -> Vec<u8> {
    let mut payload = last.to_be_bytes().to_vec();
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(debug);
    frame(GOAWAY, 0, 0, &payload)
}

impl ClientState {
    /// Whatever of the request body the windows allow.
    async fn flush_body<W: AsyncWrite + Unpin>(&mut self, writer: &mut W) -> std::io::Result<()> {
        let Some(active) = self.active.as_mut() else { return Ok(()) };
        while !active.pending.is_empty() && self.connection_window > 0 && active.window > 0 {
            let n = active.pending.len().min(self.max_frame).min(self.connection_window as usize).min(active.window as usize);
            let chunk = active.pending.split_to(n);
            self.connection_window -= n as i64;
            active.window -= n as i64;
            let flags = if active.pending.is_empty() { END_STREAM } else { 0 };
            writer.write_all(&frame(DATA, flags, active.stream, &chunk)).await?;
            writer.flush().await?;
        }
        Ok(())
    }

    /// Whether a frame on `stream` belongs to the request in flight: its own stream, or one the upstream opened
    /// (Netty's HTTP/1-to-HTTP/2 converter on a server may allocate a stream of its own for the response).
    fn owns(&self, stream: u32) -> bool {
        match &self.active {
            Some(active) if stream == active.stream => true,
            // any stream but one of this connection's earlier requests, whose late frames are dropped
            Some(active) if stream != 0 && (stream.is_multiple_of(2) || stream < CLIENT_STREAM || stream > active.stream) => {
                self.foreign.store(true, std::sync::atomic::Ordering::SeqCst);
                true
            }
            _ => false,
        }
    }

    /// The stream in flight has ended: its body and trailers are complete.
    fn end_active(&mut self) {
        self.active = None;
    }

    /// The next complete frame in `buf`, handled; `None` until one has arrived whole.
    async fn next_frame<W: AsyncWrite + Unpin>(&mut self, buf: &mut BytesMut, writer: &mut W) -> std::io::Result<Option<Next>> {
        if buf.len() < 9 {
            return Ok(None);
        }
        let length = ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | buf[2] as usize;
        let (kind, flags) = (buf[3], buf[4]);
        let stream = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
        // Netty's `PrefaceDecoder` and `DefaultHttp2FrameReader` checks, which end the connection with an error.
        let error = if self.first && kind != SETTINGS {
            let dump: String = buf[..5].iter().map(|b| format!("{b:02x}")).collect();
            Some(format!("PROTOCOL_ERROR: First received frame was not SETTINGS. Hex dump for first 5 bytes: {dump}"))
        } else if length > DEFAULT_MAX_FRAME {
            Some(format!("FRAME_SIZE_ERROR: Frame length: {length} exceeds maximum: {DEFAULT_MAX_FRAME}"))
        } else if kind == SETTINGS && stream != 0 {
            Some("PROTOCOL_ERROR: A stream ID must be zero.".to_string())
        } else if kind == SETTINGS && flags & ACK != 0 && length > 0 {
            Some("FRAME_SIZE_ERROR: Ack settings frame must have an empty payload.".to_string())
        } else if kind == SETTINGS && !length.is_multiple_of(6) {
            Some(format!("FRAME_SIZE_ERROR: Frame length {length} invalid."))
        } else {
            None
        };
        self.first = false;
        if let Some(error) = error {
            return Ok(Some(Next::End(Some(error))));
        }
        if buf.len() < 9 + length {
            return Ok(None);
        }
        buf.advance(9);
        let mut payload = buf.split_to(length).freeze();
        let mut reply: Vec<u8> = Vec::new();
        match kind {
            SETTINGS if flags & ACK == 0 => {
                for setting in payload.as_chunks::<6>().0 {
                    let value = u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]);
                    match u16::from_be_bytes([setting[0], setting[1]]) {
                        0x1 => self.encoder.set_max_table_size(value as usize),
                        0x4 => {
                            if let Some(active) = self.active.as_mut() {
                                active.window += value as i64 - self.peer_initial_window;
                            }
                            self.peer_initial_window = value as i64;
                        }
                        0x5 => self.max_frame = (value as usize).clamp(DEFAULT_MAX_FRAME, MAX_FRAME_ACCEPTED),
                        _ => {}
                    }
                }
                reply.extend(frame(SETTINGS, ACK, 0, &[]));
            }
            PING if flags & ACK == 0 => reply.extend(frame(PING, ACK, 0, &payload)),
            WINDOW_UPDATE if payload.len() >= 4 => {
                let increment = (u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff) as i64;
                if stream == 0 {
                    self.connection_window += increment;
                } else if let Some(active) = self.active.as_mut().filter(|a| a.stream == stream) {
                    active.window += increment;
                }
            }
            HEADERS | CONTINUATION if stream != 0 => {
                if kind == HEADERS {
                    let mut pad = 0;
                    if flags & PADDED != 0 && !payload.is_empty() {
                        pad = payload[0] as usize;
                        payload.advance(1);
                    }
                    if flags & PRIORITY != 0 && payload.len() >= 5 {
                        payload.advance(5);
                    }
                    payload.truncate(payload.len().saturating_sub(pad));
                    self.block = Some((stream, Vec::new(), flags & END_STREAM != 0));
                }
                if let Some((_, block, _)) = self.block.as_mut() {
                    block.extend_from_slice(&payload);
                }
                if flags & END_HEADERS != 0 {
                    let Some((block_stream, block, ends_stream)) = self.block.take() else { return Ok(Some(Next::Continue)) };
                    // Decoded whatever stream it is on, so the table stays in step.
                    let Ok(fields) = self.decoder.decode(&block) else { return Ok(Some(Next::End(None))) };
                    if self.owns(block_stream) {
                        self.header_block(fields, block.len(), ends_stream);
                    }
                }
            }
            DATA if stream != 0 => {
                let flow = payload.len() as u32;
                if flags & PADDED != 0 && !payload.is_empty() {
                    let pad = payload[0] as usize;
                    payload.advance(1);
                    payload.truncate(payload.len().saturating_sub(pad));
                }
                let owned = self.owns(stream);
                if owned {
                    let body = self.active.as_ref().and_then(|a| a.body.clone());
                    if let Some(body) = body && !payload.is_empty() && body.send(payload).await.is_err() {
                        // Nobody reads the response any more: the stream is cancelled.
                        reply.extend(frame(RST_STREAM, 0, stream, &CANCEL.to_be_bytes()));
                        self.end_active();
                    }
                    if flags & END_STREAM != 0 {
                        self.end_active();
                    }
                }
                if flow > 0 {
                    reply.extend(window_update(0, flow));
                    if owned && self.active.is_some() {
                        reply.extend(window_update(stream, flow));
                    }
                }
            }
            RST_STREAM if self.active.as_ref().is_some_and(|a| a.stream == stream) => {
                if let Some(mut active) = self.active.take() {
                    active.fail(ClientFailure::Closed);
                }
            }
            GOAWAY if payload.len() >= 8 => {
                // Streams up to the last one it names are still answered; any later one never will be.
                let last = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff;
                self.going_away = true;
                if self.active.as_ref().is_some_and(|a| a.stream > last) && let Some(mut active) = self.active.take() {
                    active.fail(ClientFailure::Closed);
                }
                if self.active.is_none() {
                    return Ok(Some(Next::End(None)));
                }
            }
            _ => {}
        }
        if !reply.is_empty() {
            writer.write_all(&reply).await?;
            writer.flush().await?;
        }
        Ok(Some(Next::Continue))
    }

    /// A complete header block on the stream in flight: the first final head is the response, a later block without
    /// `:status` its trailers.
    fn header_block(&mut self, fields: Vec<(Vec<u8>, Vec<u8>)>, block_len: usize, ends_stream: bool) {
        let Some(active) = self.active.as_mut() else { return };
        let status = fields.iter().find(|(n, _)| n == b":status").and_then(|(_, v)| std::str::from_utf8(v).ok()?.parse::<u32>().ok());
        let final_status = status.filter(|s| !(100..200).contains(s));
        if let Some(status) = final_status.filter(|_| active.head.is_some()) {
            let headers = fields.iter().filter(|(n, _)| !n.starts_with(b":")).map(|(n, v)| (request::header_text(n), request::header_text(v))).collect();
            let (btx, brx) = mpsc::channel(64);
            let (ttx, trx) = tokio::sync::oneshot::channel();
            active.body = Some(btx);
            active.trailers = Some(ttx);
            let head = active.head.take().expect("checked above");
            if head.send(Ok(ClientResponse { status, headers, body: brx, trailers: trx, block_len, ended: ends_stream, stream: active.stream })).is_err() {
                self.end_active();
                return;
            }
        } else if active.head.is_none() && status.is_none() {
            let trailers = fields.iter().map(|(n, v)| (request::header_text(n), request::header_text(v))).collect();
            if let Some(tx) = active.trailers.take() {
                let _ = tx.send((trailers, block_len));
            }
        }
        if ends_stream && self.active.as_ref().is_some_and(|a| a.head.is_none()) {
            self.end_active();
        }
    }
}

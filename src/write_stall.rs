//! `WriteStallTimeoutHandler`: a connection whose client takes none of the bytes waiting for it for
//! `responseWriteStallTimeoutMillis` is closed, so a client that stops reading cannot hold what is queued for it
//! indefinitely; the response in progress ends incomplete and `mock_server_response_write_stalls_total` counts it
//! under what the connection carried.
//!
//! [`WriteStallIo`] wraps the accepted socket itself, below TLS, as upstream installs its handler first on accept.
//! Bytes are waiting while a write or a flush to the socket is pending; progress is the socket taking any of them,
//! and the clock starts at the first pending write after the last progress. A connection that is not writing is never
//! timed. On Linux, unless `useNativeTransport` is false, the kernel's own record of when it last sent the client data
//! (`TCP_INFO`'s `tcpi_last_data_sent`) counts as progress too, as upstream reads it on its epoll transport: a slow
//! reader's socket wakes a writer only once a share of the send buffer is free, which can take longer than the timeout.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::state::State;

/// What a connection carries, as `WriteStallTimeoutHandler.kind` reads it off the pipeline when it is cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    /// Not yet known (a TLS handshake, a SOCKS handshake) or not HTTP (binary).
    Other = 0,
    Http1 = 1,
    Http2 = 2,
    WebSocket = 3,
    /// A CONNECT or SOCKS relay, whatever it relays.
    Tunnel = 4,
}

impl Protocol {
    /// The `protocol` label of `Metrics.ResponseWriteStall`'s connection kinds.
    fn label(self) -> &'static str {
        match self {
            Protocol::Other => "other",
            Protocol::Http1 => "http1_1",
            Protocol::Http2 => "http2",
            Protocol::WebSocket => "websocket",
            Protocol::Tunnel => "tunnel",
        }
    }
}

/// The bit of [`Kind`] that [`Kind::output_ended`] reads.
const OUTPUT_ENDED: u8 = 0x80;

/// A connection's [`Protocol`], shared between the transports that learn it and the socket wrapper that reports it.
#[derive(Clone, Debug, Default)]
pub struct Kind(Arc<AtomicU8>);

impl Kind {
    /// A tunnel stays a tunnel: its relay's pipeline also holds the codec of the protocol it relays, and upstream asks
    /// for the relay first.
    pub fn set(&self, protocol: Protocol) {
        // set only by the connection's own task, one step after another
        let current = self.0.load(Ordering::Acquire);
        if current & !OUTPUT_ENDED != Protocol::Tunnel as u8 {
            self.0.store(protocol as u8 | (current & OUTPUT_ENDED), Ordering::Release);
        }
    }

    /// Whether a write to the connection's socket has failed ([`WriteStallIo`]): what produces a response for it should
    /// stop, as Netty's writes to a shut-down output fail.
    pub fn output_ended(&self) -> bool {
        self.0.load(Ordering::Acquire) & OUTPUT_ENDED != 0
    }

    fn end_output(&self) {
        self.0.fetch_or(OUTPUT_ENDED, Ordering::AcqRel);
    }

    pub(crate) fn get(&self) -> Protocol {
        match self.0.load(Ordering::Acquire) & !OUTPUT_ENDED {
            1 => Protocol::Http1,
            2 => Protocol::Http2,
            3 => Protocol::WebSocket,
            4 => Protocol::Tunnel,
            _ => Protocol::Other,
        }
    }
}

/// The accepted socket, cut when a write to it stalls for the configured timeout.
pub struct WriteStallIo {
    inner: TcpStream,
    watch: Option<Watch>,
    kind: Kind,
    /// Set by the first write the socket failed: `ReadAfterFailedWrite` (after 8.0.0), see [`WriteStallIo::failed`].
    output_ended: Option<Pin<Box<tokio::time::Sleep>>>,
}

struct Watch {
    state: Arc<State>,
    kind: Kind,
    /// The connection's event loop, whose timers a runtime LLM call blocking it holds (`OpenConnections::block_loop`).
    event_loop: usize,
    timeout: Duration,
    /// Set by the first pending write since the socket last took bytes.
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    stalled: bool,
    /// The bytes of the last write the socket did not take: what waits for the client.
    waiting: usize,
    /// `NettyTransport.useNativeTransport`: Netty's epoll transport, whose `EpollTcpInfo` the handler reads.
    kernel_progress: bool,
}

impl WriteStallIo {
    /// `MockServerUnificationInitializer`: watched when `responseWriteStallTimeoutMillis` (read on accept) is above 0.
    pub fn new(state: &Arc<State>, kind: &Kind, event_loop: usize, inner: TcpStream) -> WriteStallIo {
        let millis = state.config.int_property("responseWriteStallTimeoutMillis", 60_000).max(0) as u64;
        let watch = (millis > 0).then(|| Watch { state: state.clone(), kind: kind.clone(), event_loop, timeout: Duration::from_millis(millis), deadline: None, stalled: false, waiting: 0, kernel_progress: cfg!(target_os = "linux") && state.config.bool_property("useNativeTransport", true) });
        WriteStallIo { inner, watch, kind: kind.clone(), output_ended: None }
    }

    /// `ReadAfterFailedWrite`: a write the socket fails (a client that reset the connection) ends the output, not the
    /// connection. Writes are taken as done from then on, so the layers above (a TLS handshake's last flight, a relay)
    /// carry on and the connection goes on being read: a request the client sent before it left is still decoded,
    /// recorded and matched. Reads end with the input, or `LingeringClose.LINGER_MILLIS` after the failure, when writes
    /// fail too.
    fn failed<T>(&mut self, result: Poll<std::io::Result<T>>, written: T) -> Poll<std::io::Result<T>> {
        match result {
            Poll::Ready(Err(e)) if self.output_ended.is_none() && !is_stall(&e) => {
                self.output_ended = Some(Box::pin(tokio::time::sleep(OUTPUT_ENDED_LINGER)));
                self.kind.end_output();
                let _ = socket2::SockRef::from(&self.inner).shutdown(std::net::Shutdown::Write);
                Poll::Ready(Ok(written))
            }
            result => result,
        }
    }

    /// Once the output has ended, the answer to a write: taken as done until the linger is over, then the error.
    /// What produces a stream asks [`Kind::output_ended`] instead, to stop at once.
    fn ended<T>(&mut self, cx: &mut Context<'_>, written: T) -> Option<Poll<std::io::Result<T>>> {
        let linger = self.output_ended.as_mut()?;
        Some(Poll::Ready(match linger.as_mut().poll(cx) {
            Poll::Ready(()) => Err(std::io::ErrorKind::BrokenPipe.into()),
            Poll::Pending => Ok(written),
        }))
    }

    /// Whether the socket took bytes (`Ready`) or the stall timed out (an error): a pending write of `waiting` bytes (0
    /// for a flush, which waits on the last write's) starts or continues the clock.
    fn watched<T>(&mut self, cx: &mut Context<'_>, result: Poll<std::io::Result<T>>, waiting: usize, progressed: impl Fn(&T) -> bool) -> Poll<std::io::Result<T>> {
        let Some(watch) = self.watch.as_mut() else { return result };
        if watch.stalled {
            return Poll::Ready(Err(stall_error()));
        }
        match &result {
            Poll::Ready(Ok(value)) if progressed(value) => watch.deadline = None,
            Poll::Ready(_) => {}
            Poll::Pending => {
                if waiting > 0 {
                    watch.waiting = waiting;
                }
                let timeout = watch.timeout;
                let deadline = watch.deadline.get_or_insert_with(|| Box::pin(tokio::time::sleep(timeout)));
                let mut due = deadline.as_mut().poll(cx).is_ready();
                // the handler's timer, due while its loop is blocked, runs once the loop is free
                if due && let Some(until) = watch.state.connections.blocked_until(watch.event_loop) {
                    deadline.as_mut().reset(until);
                    due = deadline.as_mut().poll(cx).is_ready();
                }
                // `kernelSentDataSince`: the kernel sent the client data within the timeout, so the clock runs from then
                if due && watch.kernel_progress && let Some(since) = since_kernel_sent(&self.inner) && since < timeout {
                    deadline.as_mut().reset(tokio::time::Instant::now() + (timeout - since));
                    due = deadline.as_mut().poll(cx).is_ready();
                }
                if due {
                    watch.stalled = true;
                    watch.deadline = None;
                    stalled(watch, &self.inner);
                    return Poll::Ready(Err(stall_error()));
                }
            }
        }
        result
    }
}

/// `EpollTcpInfo.sentDataWithinMillis`: how long ago the kernel last sent the socket's peer data (`tcpi_last_data_sent`;
/// a zero-window probe is not data), `None` where it is not reported.
#[cfg(target_os = "linux")]
fn since_kernel_sent(socket: &TcpStream) -> Option<Duration> {
    use std::os::fd::AsRawFd;
    // SAFETY: `tcp_info` is plain integers, for which all zeroes is a valid value; getsockopt writes at most `len` bytes
    // into it and reports how many it wrote.
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let result = unsafe { libc::getsockopt(socket.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_INFO, (&raw mut info).cast(), &mut len) };
    let reported = std::mem::offset_of!(libc::tcp_info, tcpi_last_data_sent) + std::mem::size_of::<u32>();
    (result == 0 && len as usize >= reported).then(|| Duration::from_millis(info.tcpi_last_data_sent.into()))
}

#[cfg(not(target_os = "linux"))]
fn since_kernel_sent(_: &TcpStream) -> Option<Duration> {
    None
}

fn stall_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "responseWriteStallTimeoutMillis")
}

fn is_stall(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::TimedOut && error.to_string() == "responseWriteStallTimeoutMillis"
}

/// `LingeringClose.LINGER_MILLIS`: how long a connection whose output ended on a failed write reads on, at most.
const OUTPUT_ENDED_LINGER: Duration = Duration::from_secs(5);

/// `WriteStallTimeoutHandler.stalled`: the WARN, the count, and the socket closed under the connection, both ways, so
/// whatever task still reads it ends too.
fn stalled(watch: &Watch, socket: &TcpStream) {
    use crate::recorded::{Arg, Level, LogEntry};
    let state = &watch.state;
    if !matches!(state.log_level.as_str(), "OFF" | "ERROR") {
        let remote = socket.peer_addr().map(crate::http1::socket_address_arg);
        // `ChannelOutboundBuffer.totalPendingWriteBytes` counts what the pipeline has written that the socket has not
        // taken, plus 96 bytes of Netty's bookkeeping per message. Ours is the rest of the write the socket refused; what
        // the kernel's send buffer holds is not counted, as it is not there (it is not reported portably either).
        let entry = LogEntry::at(
            Level::Warn,
            "closing connection from:{}because its client took none of the{}bytes waiting for it for:{}ms (responseWriteStallTimeoutMillis), so the response in progress ends incomplete",
        )
        .args([remote.unwrap_or_else(|_| Arg::from("")), Arg::from(serde_json::json!(watch.waiting)), Arg::from(serde_json::json!(watch.timeout.as_millis() as u64))]);
        crate::log::warn_event(state, entry);
    }
    state.config.metrics.response_write_stalled(watch.kind.get().label(), "connection");
    let _ = socket2::SockRef::from(socket).shutdown(std::net::Shutdown::Both);
}

impl AsyncRead for WriteStallIo {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if let Some(linger) = self.output_ended.as_mut() && linger.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for WriteStallIo {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if let Some(ended) = self.ended(cx, buf.len()) {
            return ended;
        }
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        let result = self.watched(cx, result, buf.len(), |n| *n > 0);
        self.failed(result, buf.len())
    }

    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[std::io::IoSlice<'_>]) -> Poll<std::io::Result<usize>> {
        let waiting = bufs.iter().map(|buf| buf.len()).sum();
        if let Some(ended) = self.ended(cx, waiting) {
            return ended;
        }
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        let result = self.watched(cx, result, waiting, |n| *n > 0);
        self.failed(result, waiting)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Some(ended) = self.ended(cx, ()) {
            return ended;
        }
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        let result = self.watched(cx, result, 0, |_| false);
        self.failed(result, ())
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.output_ended.is_some() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// `Http2StreamWriteStallHandler`: an HTTP/2 stream whose response has data waiting that its client has taken none of
/// for `responseWriteStallTimeoutMillis` is reset with CANCEL, and counted as an `http2` `stream` stall. A client can
/// stop granting one stream flow-control window while it keeps reading the connection, so this is invisible to
/// [`WriteStallIo`], which covers a socket that stops taking bytes (the connection's writer then waits in its write).
///
/// The writer of an HTTP/2 connection reports the DATA it writes ([`StreamStalls::written`]), the window its client
/// returns ([`StreamStalls::window_returned`]) and the streams that end ([`StreamStalls::closed`]); after each pass
/// [`StreamStalls::check`] names the streams to reset, every `checkIntervalMillis` while any has data waiting.
///
/// Progress is data written: for the stream itself, and for a stream whose own window is open also data written for
/// any stream. While the connection window is closed, the timed-out streams holding the most of it (written less
/// returned) are reset first, and that release gives each other open-windowed stream one fresh period; a stream holding
/// less than its client once returned for it at once is passed over for one that alone holds more than half of what
/// the connection has out ("Response Write-Stall Timeout" in upstream's docs/code/netty-pipeline.md). Upstream also
/// counts an unwritable socket under a `WriteStallTimeoutHandler` as progress for open-windowed streams; here the
/// check never runs while the writer waits on the socket, and the write that ends that wait is progress.
pub struct StreamStalls {
    state: Arc<State>,
    remote: std::net::SocketAddr,
    timeout: Duration,
    interval: Duration,
    /// Kept from the first data written for a stream until it ends (`sentKey`).
    sent: std::collections::HashMap<u32, StreamData>,
    /// Kept while a stream has data waiting (`progressKey`).
    progress: std::collections::HashMap<u32, StreamWriteProgress>,
    connection_written: u64,
    last_connection_written: u64,
    connection_unreturned: u64,
    next_check: Option<std::time::Instant>,
}

/// `StreamData`.
#[derive(Default)]
struct StreamData {
    written: u64,
    /// Written, less the window its client has since returned for it: the most of it the client can be holding.
    unreturned: u64,
    /// The least its client has returned for it at once, 0 until it returns any.
    smallest_return: u64,
}

/// `StreamWriteProgress`.
struct StreamWriteProgress {
    window: i64,
    written: u64,
    held: u64,
    /// Holds less than its client has left unreturned on it before returning, as a stream being consumed does.
    explained: bool,
    last_progress: std::time::Instant,
    resetting: bool,
    /// Equal to `last_progress` while the stream's current period is the fresh one given for a reset.
    release_granted: Option<std::time::Instant>,
}

impl StreamStalls {
    /// `None` when `responseWriteStallTimeoutMillis` is 0 (read when the connection is set up).
    pub fn new(state: &Arc<State>, remote: std::net::SocketAddr) -> Option<StreamStalls> {
        let millis = state.config.int_property("responseWriteStallTimeoutMillis", 60_000).max(0) as u64;
        (millis > 0).then(|| StreamStalls {
            state: state.clone(),
            remote,
            timeout: Duration::from_millis(millis),
            interval: Duration::from_millis(check_interval_millis(millis)),
            sent: Default::default(),
            progress: Default::default(),
            connection_written: 0,
            last_connection_written: 0,
            connection_unreturned: 0,
            next_check: None,
        })
    }

    /// When the next check is due, while any stream has data waiting.
    pub fn next_check(&self) -> Option<std::time::Instant> {
        self.next_check
    }

    /// `bytes` of `stream`'s data were written.
    pub fn written(&mut self, stream: u32, bytes: u64) {
        let sent = self.sent.entry(stream).or_default();
        sent.written += bytes;
        sent.unreturned += bytes;
        self.connection_written += bytes;
        self.connection_unreturned += bytes;
    }

    /// A `WINDOW_UPDATE` of `bytes` for `stream` (0: the connection). Window granted beyond the data sent returns
    /// nothing, so a grant cannot hide what a stream holds.
    pub fn window_returned(&mut self, stream: u32, bytes: u64) {
        if stream == 0 {
            self.connection_unreturned -= bytes.min(self.connection_unreturned);
            return;
        }
        let Some(sent) = self.sent.get_mut(&stream) else { return };
        let returned = bytes.min(sent.unreturned);
        if returned > 0 {
            sent.unreturned -= returned;
            if sent.smallest_return == 0 || returned < sent.smallest_return {
                sent.smallest_return = returned;
            }
        }
    }

    /// `stream` ended or was reset: it is no longer watched.
    pub fn closed(&mut self, stream: u32) {
        self.sent.remove(&stream);
        self.progress.remove(&stream);
    }

    /// After a pass of the writer: `waiting` are the streams with data still waiting (repeats allowed), `window(stream)`
    /// their send windows and `connection_window` the connection's. At a due check, the streams to reset, each logged
    /// and counted (`Http2StreamWriteStallHandler.run`); a check is scheduled while any stream waits.
    pub fn check(&mut self, waiting: impl Iterator<Item = u32>, window: impl Fn(u32) -> i64, connection_window: i64) -> Vec<u32> {
        let now = std::time::Instant::now();
        let waiting: std::collections::BTreeSet<u32> = waiting.collect();
        if self.next_check.is_none_or(|at| now < at) {
            if self.next_check.is_none() && !waiting.is_empty() {
                self.next_check = Some(now + self.interval);
            }
            return Vec::new();
        }
        // data written for any stream, including one that has since closed
        let any_progress = self.connection_written != self.last_connection_written;
        self.last_connection_written = self.connection_written;
        self.progress.retain(|stream, _| waiting.contains(stream));
        let mut holder_waiting = false;
        let mut unmoved: Vec<u32> = Vec::new();
        for &stream in &waiting {
            let window = window(stream);
            let sent = self.sent.get(&stream);
            let written = sent.map_or(0, |s| s.written);
            let Some(progress) = self.progress.get_mut(&stream) else {
                self.progress.insert(
                    stream,
                    StreamWriteProgress { window, written, held: 0, explained: false, last_progress: now, resetting: false, release_granted: None },
                );
                holder_waiting |= written > 0;
                continue;
            };
            let moved = written != progress.written;
            progress.window = window;
            progress.written = written;
            progress.held = sent.map_or(0, |s| s.unreturned);
            progress.explained = sent.is_some_and(|s| s.unreturned < s.smallest_return);
            if moved {
                progress.last_progress = now;
            } else {
                unmoved.push(stream);
                // only a stream that has been sent data can hold connection window, and data cannot be faked by a client
                holder_waiting |= written > 0 && now - progress.last_progress < self.timeout;
            }
        }
        let stalled = self.select_stalled_streams(now, &unmoved, connection_window, any_progress, holder_waiting);
        for &stream in &stalled {
            self.closed(stream);
            self.reset(stream);
        }
        self.next_check = waiting.iter().any(|stream| !stalled.contains(stream)).then(|| now + self.interval);
        stalled
    }

    /// `selectStalledStreams`: while the connection window is closed, a reset that should release it (a closed-window
    /// stream, or those holding the most of it) gives each of the others one fresh period, and not another until it is
    /// refreshed for any other reason.
    fn select_stalled_streams(&mut self, now: std::time::Instant, unmoved: &[u32], connection_window: i64, any_progress: bool, holder_waiting: bool) -> Vec<u32> {
        let timeout = self.timeout;
        let open_windows_refreshed = any_progress;
        // a stream waiting for a closed connection window is not reset before the streams that may hold it time out
        let open_windows_timed = !open_windows_refreshed && !(connection_window <= 0 && holder_waiting);
        let timed_out = |progress: &StreamWriteProgress| now - progress.last_progress >= timeout && (progress.window <= 0 || open_windows_timed);
        let mut most_held = i64::MIN;
        let mut most_held_unexplained = i64::MIN;
        for stream in unmoved {
            let progress = self.progress.get_mut(stream).expect("unmoved streams are watched");
            progress.resetting = false;
            most_held = most_held.max(progress.held as i64);
            if !progress.explained {
                most_held_unexplained = most_held_unexplained.max(progress.held as i64);
            }
        }
        // one stream alone, not several together: a stream being consumed can have up to half a window unreturned before
        // its first return, so only more than half of what the connection has out marks a stream as stalled
        let pass_over_explained = most_held_unexplained > (self.connection_unreturned / 2) as i64;
        if pass_over_explained {
            most_held = most_held_unexplained;
        }
        let mut stalled = Vec::new();
        let mut window_released = false;
        for stream in unmoved {
            let progress = self.progress.get_mut(stream).expect("unmoved streams are watched");
            // streams holding the same cannot be told apart, so all are reset and the stalled one is among them
            if timed_out(progress) && (progress.window <= 0 || (progress.held as i64 == most_held && !(pass_over_explained && progress.explained))) {
                progress.resetting = true;
                stalled.push(*stream);
                // a stream sent nothing holds no connection window, so resetting one never extends another's time
                window_released |= connection_window <= 0 && progress.held > 0;
            }
        }
        for stream in unmoved {
            let progress = self.progress.get_mut(stream).expect("unmoved streams are watched");
            if progress.window <= 0 || progress.resetting {
                continue;
            }
            if open_windows_refreshed {
                progress.last_progress = now;
            } else if window_released && progress.release_granted != Some(progress.last_progress) {
                progress.last_progress = now;
                progress.release_granted = Some(now);
            } else if timed_out(progress) {
                stalled.push(*stream);
            }
        }
        stalled
    }

    fn reset(&self, stream: u32) {
        use crate::recorded::{Arg, Level, LogEntry};
        let state = &self.state;
        if !matches!(state.log_level.as_str(), "OFF" | "ERROR") {
            let entry = LogEntry::at(
                Level::Warn,
                "resetting HTTP/2 stream:{}from:{}because its client took none of the response waiting for it for:{}ms (responseWriteStallTimeoutMillis), so the response ends incomplete",
            )
            .args([Arg::from(serde_json::json!(stream)), crate::http1::socket_address_arg(self.remote), Arg::from(serde_json::json!(self.timeout.as_millis() as u64))]);
            crate::log::warn_event(state, entry);
        }
        state.config.metrics.response_write_stalled("http2", "stream");
    }
}

/// `WriteStallTimeoutHandler.checkIntervalMillis`: often enough that a stall is noticed soon after the timeout, never
/// more than once a second.
fn check_interval_millis(timeout_millis: u64) -> u64 {
    (timeout_millis / 2).clamp(10, 1000)
}

/// `Http3StreamWriteStallHandler.MAX_WRITE_BYTES`: QUIC reports a write only once it has taken all of it, so writes go
/// to it in parts this large, and a slow reader of one large frame shows progress.
const HTTP3_MAX_WRITE_BYTES: usize = 32 * 1024;

/// `RESET_STREAM H3_INTERNAL_ERROR`, as `Http3StreamWriteStallHandler.stalled` shuts a stalled stream's output.
const H3_INTERNAL_ERROR: u64 = 0x102;

/// `Http3ConnectionWriteStallWatcher`: one per QUIC connection, created by its first watched request stream, which times
/// the streams that have writes waiting and resets each whose client has taken none of its data for
/// `responseWriteStallTimeoutMillis` (WARN, `http3` `stream` stall, `RESET_STREAM H3_INTERNAL_ERROR`).
///
/// Streams share the connection's credit, so upstream gives a stream sent under `holderBytes` (half the smaller of
/// the client's initial connection and stream grants, [`http3_holder_bytes`]) a fresh period, or one period of
/// waiting, while a stream that may hold that credit is reset or still moving. The second field is `holderBytes`.
#[derive(Clone, Default)]
pub struct Http3Stalls(Arc<std::sync::Mutex<Option<Http3Watcher>>>, u64);

/// `Http3StreamWriteStallHandler.holderBytes`: the bytes a stream must have been sent before it could be what holds
/// the connection's credit, half the smaller of the client's initial connection and stream grants (a client may
/// return credit only once it has read half a window); 0, which leaves every stream to its own clock, when the grant
/// is unknown or half a window is under one write.
pub fn http3_holder_bytes(initial_max_data: u64, initial_max_stream_data_bidi_local: u64) -> u64 {
    let half_window = initial_max_data.min(initial_max_stream_data_bidi_local) / 2;
    if half_window < HTTP3_MAX_WRITE_BYTES as u64 { 0 } else { half_window }
}

struct Http3Watcher {
    state: Arc<State>,
    timeout: Duration,
    interval: Duration,
    holder_bytes: u64,
    streams: std::collections::HashMap<u64, Http3StreamWrites>,
    /// The streams being timed, in the order they started waiting.
    watched: Vec<u64>,
    check_scheduled: bool,
}

/// `Http3ConnectionWriteStallWatcher.Stream`.
struct Http3StreamWrites {
    /// Sizes of the parts QUIC has not taken all of, oldest first.
    waiting: std::collections::VecDeque<usize>,
    taken_bytes: u64,
    moved: std::time::Instant,
    spared: Option<std::time::Instant>,
    /// Has had its one period of waiting for a moving stream since its own data last moved or a holder was reset.
    waited: bool,
    watched: bool,
    /// Reset by a check: the writer resets the QUIC stream and fails.
    stalled: bool,
    writer: Option<std::task::Waker>,
}

impl Http3StreamWrites {
    fn moved_within(&self, now: std::time::Instant, timeout: Duration) -> bool {
        now - self.moved < timeout
    }

    fn stalled(&self, now: std::time::Instant, timeout: Duration) -> bool {
        !self.moved_within(now, timeout) && !self.spared.is_some_and(|at| now - at < timeout)
    }

    fn spare(&mut self, now: std::time::Instant, waiting: bool) {
        self.spared = Some(now);
        self.waited = waiting;
    }
}

impl Http3Stalls {
    /// A connection's watch, given its `holderBytes`.
    pub fn new(holder_bytes: u64) -> Self {
        Http3Stalls(Default::default(), holder_bytes)
    }

    /// `Http3Server`'s stream initializer: request stream `id` is watched when `responseWriteStallTimeoutMillis`, read
    /// as it opens, is above 0; the connection's streams are all timed with the timeout its first watched stream read.
    pub fn stream(&self, state: &Arc<State>, id: u64) -> Option<Http3StreamStall> {
        let millis = state.config.int_property("responseWriteStallTimeoutMillis", 60_000).max(0) as u64;
        if millis == 0 {
            return None;
        }
        let mut watcher = self.0.lock().unwrap();
        let watcher = watcher.get_or_insert_with(|| Http3Watcher {
            state: state.clone(),
            timeout: Duration::from_millis(millis),
            interval: Duration::from_millis(check_interval_millis(millis)),
            holder_bytes: self.1,
            streams: Default::default(),
            watched: Vec::new(),
            check_scheduled: false,
        });
        let writes = Http3StreamWrites {
            waiting: Default::default(),
            taken_bytes: 0,
            moved: std::time::Instant::now(),
            spared: None,
            waited: false,
            watched: false,
            stalled: false,
            writer: None,
        };
        watcher.streams.insert(id, writes);
        Some(Http3StreamStall { stalls: self.clone(), id })
    }
}

/// One watched request stream's handle on its connection's [`Http3Stalls`]; dropped when the stream is.
pub struct Http3StreamStall {
    stalls: Http3Stalls,
    id: u64,
}

impl Http3StreamStall {
    fn with<T>(&self, f: impl FnOnce(&mut Http3Watcher, &mut Http3StreamWrites) -> T) -> Option<T> {
        let mut guard = self.stalls.0.lock().unwrap();
        let watcher = guard.as_mut()?;
        let mut writes = watcher.streams.remove(&self.id)?;
        let result = f(watcher, &mut writes);
        watcher.streams.insert(self.id, writes);
        Some(result)
    }

    /// `writing`: before a part is passed on (QUIC may take it at once).
    fn writing(&self, bytes: usize) {
        self.with(|_, writes| {
            if writes.waiting.is_empty() {
                writes.moved = std::time::Instant::now();
            }
            writes.waiting.push_back(bytes);
        });
    }

    /// `written`: QUIC took the oldest waiting part whole, or failed it.
    fn written(&self, taken: bool) {
        self.with(|_, writes| {
            if let Some(bytes) = writes.waiting.pop_front().filter(|_| taken) {
                writes.taken_bytes += bytes as u64;
                writes.moved = std::time::Instant::now();
                writes.waited = false;
            }
        });
    }

    /// `watch`: after a part is passed on and QUIC has not taken all of it; `writer` is woken by a reset.
    fn watch(&self, writer: &std::task::Waker) {
        let schedule = self.with(|watcher, writes| {
            writes.writer = Some(writer.clone());
            if writes.waiting.is_empty() || writes.watched {
                return false;
            }
            writes.watched = true;
            watcher.watched.push(self.id);
            !std::mem::replace(&mut watcher.check_scheduled, true)
        });
        if schedule == Some(true) {
            tokio::spawn(run_http3_checks(self.stalls.clone()));
        }
    }

    fn is_stalled(&self) -> bool {
        self.with(|_, writes| writes.stalled).unwrap_or(false)
    }
}

impl Drop for Http3StreamStall {
    /// `closed`: the stream is gone, so it has nothing waiting and is no longer reset.
    fn drop(&mut self) {
        if let Some(watcher) = self.stalls.0.lock().unwrap().as_mut() {
            watcher.streams.remove(&self.id);
        }
    }
}

/// `Http3ConnectionWriteStallWatcher.run`: a check every `checkIntervalMillis` while any stream is watched.
async fn run_http3_checks(stalls: Http3Stalls) {
    loop {
        let interval = match stalls.0.lock().unwrap().as_ref() {
            Some(watcher) => watcher.interval,
            None => return,
        };
        tokio::time::sleep(interval).await;
        let mut guard = stalls.0.lock().unwrap();
        let Some(watcher) = guard.as_mut() else { return };
        watcher.check(std::time::Instant::now());
        if watcher.watched.is_empty() {
            watcher.check_scheduled = false;
            return;
        }
    }
}

impl Http3Watcher {
    /// `Http3ConnectionWriteStallWatcher.check`.
    fn check(&mut self, now: std::time::Instant) {
        let timeout = self.timeout;
        let streams = &mut self.streams;
        let mut any_overdue = false;
        self.watched.retain(|id| match streams.get_mut(id) {
            Some(writes) if !writes.waiting.is_empty() => {
                any_overdue |= !writes.moved_within(now, timeout);
                true
            }
            Some(writes) => {
                writes.watched = false;
                false
            }
            None => false,
        });
        if !any_overdue {
            return;
        }
        let holder = self.holder_bytes;
        let (mut holder_waiting, mut holder_stalled, mut sent_to_the_rest) = (false, false, 0);
        for writes in self.watched.iter().filter_map(|id| streams.get(id)) {
            if writes.taken_bytes >= holder {
                holder_waiting = true;
                holder_stalled |= !writes.moved_within(now, timeout);
            } else {
                sent_to_the_rest += writes.taken_bytes;
            }
        }
        // sent that much between them, the rest could hold the credit themselves: every stream on its own clock
        let rest_may_hold_credit = sent_to_the_rest >= holder;
        let mut resets = Vec::new();
        self.watched.retain(|id| {
            let writes = streams.get_mut(id).expect("watched streams are open");
            let own_clock = rest_may_hold_credit || writes.taken_bytes >= holder;
            let overdue = if own_clock { !writes.moved_within(now, timeout) } else { writes.stalled(now, timeout) };
            if !own_clock && holder_stalled {
                // a stream that may hold the credit is reset in this check: time for what it returns to arrive
                writes.spare(now, false);
            } else if overdue {
                if !own_clock && holder_waiting && !writes.waited {
                    writes.spare(now, true);
                } else {
                    writes.watched = false;
                    resets.push(*id);
                    return false;
                }
            }
            true
        });
        for id in resets {
            self.reset(id);
        }
    }

    /// `Http3StreamWriteStallHandler.stalled`: the WARN, the count, and the stream's writer told to reset it.
    fn reset(&mut self, id: u64) {
        use crate::recorded::{Arg, Level, LogEntry};
        let Some(writes) = self.streams.get_mut(&id) else { return };
        writes.stalled = true;
        if let Some(writer) = writes.writer.take() {
            writer.wake();
        }
        let state = &self.state;
        if !matches!(state.log_level.as_str(), "OFF" | "ERROR") {
            // the stream channel's `toString`: Netty's random channel id and the QUIC stream id
            let channel_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
            let channel = format!("[id: 0x{channel_id}, QuicStreamAddress{{streamId={id}}}]");
            let entry = LogEntry::at(
                Level::Warn,
                "resetting HTTP/3 stream:{}because its client took none of the response waiting for it for:{}ms (responseWriteStallTimeoutMillis), so the response ends incomplete",
            )
            .args([Arg::from(channel), Arg::from(serde_json::json!(self.timeout.as_millis() as u64))]);
            crate::log::warn_event(state, entry);
        }
        state.config.metrics.response_write_stalled("http3", "stream");
    }
}

/// A request stream's send side under `Http3StreamWriteStallHandler`: what h3 writes goes to QUIC in parts of at most
/// [`HTTP3_MAX_WRITE_BYTES`], each timed until QUIC has taken it whole; a stalled stream is reset with
/// `H3_INTERNAL_ERROR` and its write fails. Unwatched, writes pass straight through.
pub struct Http3Send<S> {
    inner: S,
    stall: Option<Http3StreamStall>,
    writing: Option<h3::quic::WriteBuf<bytes::Bytes>>,
    /// What is left of the part being passed on.
    part_left: usize,
}

impl<S> Http3Send<S> {
    pub fn new(inner: S, stall: Option<Http3StreamStall>) -> Self {
        Http3Send { inner, stall, writing: None, part_left: 0 }
    }
}

impl<S: h3::quic::SendStream<bytes::Bytes> + h3::quic::SendStreamUnframed<bytes::Bytes>> h3::quic::SendStream<bytes::Bytes> for Http3Send<S> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
        use bytes::Buf;
        let Some(stall) = &self.stall else { return self.inner.poll_ready(cx) };
        if stall.is_stalled() {
            self.writing = None;
            self.inner.reset(H3_INTERNAL_ERROR);
            return Poll::Ready(Err(h3::quic::StreamErrorIncoming::Unknown(Box::new(stall_error()))));
        }
        let Some(data) = self.writing.as_mut() else { return Poll::Ready(Ok(())) };
        while data.has_remaining() {
            if self.part_left == 0 {
                self.part_left = data.remaining().min(HTTP3_MAX_WRITE_BYTES);
                stall.writing(self.part_left);
            }
            let mut part = Buf::take(&mut *data, self.part_left);
            match self.inner.poll_send(cx, &mut part) {
                Poll::Ready(Ok(n)) => {
                    self.part_left -= n;
                    if self.part_left == 0 {
                        stall.written(true);
                    }
                }
                Poll::Ready(Err(e)) => {
                    self.part_left = 0;
                    stall.written(false);
                    self.writing = None;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    stall.watch(cx.waker());
                    return Poll::Pending;
                }
            }
        }
        self.writing = None;
        Poll::Ready(Ok(()))
    }

    fn send_data<T: Into<h3::quic::WriteBuf<bytes::Bytes>>>(&mut self, data: T) -> Result<(), h3::quic::StreamErrorIncoming> {
        if self.stall.is_none() {
            return self.inner.send_data(data);
        }
        if self.writing.is_some() {
            return Err(h3::quic::StreamErrorIncoming::Unknown("send_data while a write is waiting".into()));
        }
        self.writing = Some(data.into());
        Ok(())
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
        self.inner.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.inner.reset(reset_code)
    }

    fn send_id(&self) -> h3::quic::StreamId {
        self.inner.send_id()
    }
}

/// A request stream as h3 sees it: its send side under [`Http3Send`].
pub struct Http3Bidi {
    send: Http3Send<h3_quinn::SendStream<bytes::Bytes>>,
    recv: h3_quinn::RecvStream,
}

impl Http3Bidi {
    /// `stall`: the stream's watch, given its QUIC stream id.
    pub fn new(stream: h3_quinn::BidiStream<bytes::Bytes>, stall: impl FnOnce(u64) -> Option<Http3StreamStall>) -> Self {
        use h3::quic::{BidiStream, SendStream};
        let id = stream.send_id().into_inner();
        let (send, recv) = stream.split();
        Http3Bidi { send: Http3Send::new(send, stall(id)), recv }
    }
}

impl h3::quic::BidiStream<bytes::Bytes> for Http3Bidi {
    type SendStream = Http3Send<h3_quinn::SendStream<bytes::Bytes>>;
    type RecvStream = h3_quinn::RecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

impl h3::quic::SendStream<bytes::Bytes> for Http3Bidi {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<h3::quic::WriteBuf<bytes::Bytes>>>(&mut self, data: T) -> Result<(), h3::quic::StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code)
    }

    fn send_id(&self) -> h3::quic::StreamId {
        self.send.send_id()
    }
}

impl h3::quic::RecvStream for Http3Bidi {
    type Buf = bytes::Bytes;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<bytes::Bytes>, h3::quic::StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code)
    }

    fn recv_id(&self) -> h3::quic::StreamId {
        self.recv.recv_id()
    }
}

//! `InboundConnectionIdleHandler` and `InboundConnectionActivity` (b765b8271): a connection that has read and written
//! nothing for `inboundConnectionIdleTimeoutMillis` (read on accept; default 5 minutes, 0 disables it) and has nothing
//! in progress is closed, logged at DEBUG and counted in `mock_server_inbound_connections_idle_closed_total`. A busy
//! connection is left alone and checked again after another full period.
//!
//! [`Activity`] is what a connection is doing, shared by the transports that know it: an HTTP exchange in progress
//! ([`Activity::exchange`], `HttpExchangeTracker`: from a decoded request head to the last byte of its response, or an
//! HTTP/2 stream being answered), a TLS handshake under way ([`Activity::handshake`]), or a connection that has become
//! long-lived ([`Activity::long_lived`]: a WebSocket, a binary relay), which is never timed again. [`IdleIo`] wraps the
//! socket and counts its reads and writes as activity, above the write-stall watch, as upstream installs
//! `inbound-idle` first and `write-stall` in front of it. Upstream's handler sits behind the TLS and SOCKS handlers and
//! sees decrypted bytes; here it sees the records themselves, which come and go together. A SOCKS handshake is not
//! activity, its handlers reading and answering it in front of the idle handler, and a TLS ClientHello still
//! arriving is not either (`SniHandler` is in front of the handler), and the handshake that follows is covered as
//! busy and restarts the period when it completes. A CONNECT or SOCKS tunnel is served on the connection that carried
//! it, so its client leg is timed with the exchanges it carries, and the loopback leg upstream closes with it does not
//! exist.
//!
//! The close is `ctx.channel().close()`, which runs through the pipeline: a transport waiting on the connection holds a
//! [`Closer`] and closes it itself when asked, so the HTTP/1.1 loop and a TLS stream waiting for its first bytes shut
//! the stream down (a TLS one sends its `close_notify` before the FIN) and HTTP/2 sends a GOAWAY first.
//! A connection no transport waits on (a SOCKS handshake, a tunnelled binary relay) is shut down under every task
//! that holds it (`OpenConnections::shut_down`), as is one that has not closed itself within the `SslHandler`'s
//! `closeNotifyFlushTimeout`.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::state::State;

/// What a connection is doing, for its idle timeout; inert when the timeout is off.
#[derive(Clone, Default)]
pub struct Activity(Option<Arc<Inner>>);

struct Inner {
    timeout: Duration,
    started: Instant,
    /// Nanoseconds from `started` to the last read or write.
    last: AtomicU64,
    /// Exchanges and handshakes in progress.
    busy: AtomicUsize,
    long_lived: AtomicBool,
    /// Served as a CONNECT or SOCKS tunnel: a binary relay inside it stays timed (only upstream's loopback leg is
    /// exempt), a WebSocket does not.
    tunnel: AtomicBool,
    /// Off while the SOCKS handlers, which sit in front of the idle handler, read and answer the handshake.
    counting: AtomicBool,
    /// [`Closer`]s alive: transports waiting on the connection that close it themselves when asked.
    closers: AtomicUsize,
    /// The idle close was requested, and [`Inner::close`] notified.
    closing: AtomicBool,
    close: tokio::sync::Notify,
}

/// `SslHandler`'s default `closeNotifyFlushTimeoutMillis`: how long a close asked of a transport may take before the
/// socket is shut down under it.
const CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_millis(3000);

impl Activity {
    /// `MockServerUnificationInitializer.handlerAdded`: watched when `inboundConnectionIdleTimeoutMillis` is above 0.
    pub fn new(state: &State) -> Activity {
        let millis = state.config.int_property("inboundConnectionIdleTimeoutMillis", 300_000).max(0) as u64;
        Activity((millis > 0).then(|| {
            Arc::new(Inner {
                timeout: Duration::from_millis(millis),
                started: Instant::now(),
                last: AtomicU64::new(0),
                busy: AtomicUsize::new(0),
                long_lived: AtomicBool::new(false),
                tunnel: AtomicBool::new(false),
                counting: AtomicBool::new(true),
                closers: AtomicUsize::new(0),
                closing: AtomicBool::new(false),
                close: tokio::sync::Notify::new(),
            })
        }))
    }

    /// The connection read or wrote something: the period starts again.
    pub fn touch(&self) {
        if let Some(inner) = self.0.as_ref().filter(|inner| inner.counting.load(Ordering::Acquire)) {
            inner.last.store(inner.started.elapsed().as_nanos() as u64, Ordering::Release);
        }
    }

    /// A SOCKS handshake is under way: its bytes never reach the idle handler, so the period runs on from the accept.
    pub fn socks_handshake(&self) {
        if let Some(inner) = &self.0 {
            inner.counting.store(false, Ordering::Release);
        }
    }

    /// The SOCKS handshake is over (the tunnel is relayed, or the bytes are classified afresh): traffic counts again.
    pub fn socks_done(&self) {
        if let Some(inner) = &self.0 {
            inner.counting.store(true, Ordering::Release);
        }
    }

    /// An HTTP exchange in progress until the guard drops.
    pub fn exchange(&self) -> Busy {
        if let Some(inner) = &self.0 {
            inner.busy.fetch_add(1, Ordering::AcqRel);
        }
        Busy(self.0.clone())
    }

    /// A TLS handshake in progress until the guard drops; [`Busy::completed`] restarts the period
    /// (`resetReadTimeout` on a successful `SslHandshakeCompletionEvent`).
    pub fn handshake(&self) -> Busy {
        self.exchange()
    }

    /// `InboundConnectionActivity.markLongLived`: a WebSocket, whose silences are legitimate, is not timed again.
    pub fn long_lived(&self) {
        if let Some(inner) = &self.0 {
            inner.long_lived.store(true, Ordering::Release);
        }
    }

    /// A raw binary relay is long-lived, except inside a tunnel, whose client leg stays timed by the bytes it carries.
    pub fn binary(&self) {
        if self.0.as_ref().is_some_and(|inner| !inner.tunnel.load(Ordering::Acquire)) {
            self.long_lived();
        }
    }

    /// The connection now carries a CONNECT or SOCKS tunnel.
    pub fn tunnel(&self) {
        if let Some(inner) = &self.0 {
            inner.tunnel.store(true, Ordering::Release);
        }
    }

    /// A transport waiting on the connection, which closes it itself when [`Closer::requested`] completes (the idle
    /// close running through the pipeline).
    pub fn closer(&self) -> Closer {
        if let Some(inner) = &self.0 {
            inner.closers.fetch_add(1, Ordering::AcqRel);
        }
        Closer(self.0.clone())
    }

    /// The socket, its reads and writes counted as activity.
    pub fn wrap<S>(&self, inner: S) -> IdleIo<S> {
        IdleIo { inner, activity: self.clone() }
    }

    /// `InboundConnectionIdleHandler.channelIdle`, run on its own task: the connection `id` of
    /// [`crate::server::OpenConnections`] is shut down once idle, and the task ends when the connection does or becomes
    /// long-lived. `portless`: whether what the connection's event loop logs carries no port.
    ///
    /// The handler is an `IdleStateHandler` on the connection's event loop: added as the connection registers, so on a
    /// loop a runtime LLM call blocks (`OpenConnections::block_loop`) the period starts only once the loop is free,
    /// and a timer due while it is blocked runs only after it, behind the reads that arrived meanwhile (scenario
    /// `llm_worker_stall_idle`).
    pub fn watch(&self, state: &Arc<State>, id: u64, remote: std::net::SocketAddr, event_loop: usize) {
        let Some(inner) = &self.0 else { return };
        // weak, so a connection gone (or a server stopped) is not kept for the rest of a period
        let weak = Arc::downgrade(inner);
        let weak_state = Arc::downgrade(state);
        let loops = state.connections.clone();
        tokio::spawn(async move {
            // `handlerAdded` at registration, which a blocked loop runs once it is free
            if loops.loop_free(event_loop).await {
                let Some(inner) = weak.upgrade() else { return };
                inner.last.store(inner.started.elapsed().as_nanos() as u64, Ordering::Release);
            }
            loop {
                let wait = {
                    let (Some(inner), Some(state)) = (weak.upgrade(), weak_state.upgrade()) else { return };
                    if inner.long_lived.load(Ordering::Acquire) || !state.connections.is_open(id) {
                        return;
                    }
                    let last = Duration::from_nanos(inner.last.load(Ordering::Acquire));
                    let quiet = inner.started.elapsed().saturating_sub(last);
                    if quiet < inner.timeout {
                        inner.timeout - quiet
                    } else if state.connections.is_blocked(event_loop) {
                        // the timer task runs once the loop is free, after the reads that arrived meanwhile
                        Duration::ZERO
                    } else if inner.busy.load(Ordering::Acquire) > 0 {
                        inner.timeout
                    } else {
                        idle_closed(&state, remote, inner.timeout, event_loop);
                        if inner.closers.load(Ordering::Acquire) == 0 {
                            state.connections.shut_down(id);
                            return;
                        }
                        inner.closing.store(true, Ordering::Release);
                        inner.close.notify_waiters();
                        break;
                    }
                };
                if wait.is_zero() {
                    loops.loop_free(event_loop).await;
                    tokio::task::yield_now().await;
                    continue;
                }
                tokio::time::sleep(wait).await;
            }
            // the transport closes the connection; one that has not within the flush timeout is shut down under it
            tokio::time::sleep(CLOSE_FLUSH_TIMEOUT).await;
            if let Some(state) = weak_state.upgrade().filter(|state| state.connections.is_open(id)) {
                state.connections.shut_down(id);
            }
        });
    }
}

/// The DEBUG entry and the count of an idle connection closed.
fn idle_closed(state: &State, remote: std::net::SocketAddr, timeout: Duration, event_loop: usize) {
    use crate::recorded::{Level, LogEntry};
    if crate::log::debug_enabled(state) {
        let entry = LogEntry::at(Level::Debug, "closing idle inbound connection from:{}after:{}ms with nothing in progress")
            .args([crate::http1::socket_address_arg(remote), serde_json::json!(timeout.as_millis() as u64).into()]);
        let entry = if state.connections.has_served_http(event_loop) { entry } else { entry.without_port() };
        crate::log::entry(state, &entry);
        state.log.message(entry);
    }
    state.config.metrics.inbound_connection_idle_closed();
}

/// A transport waiting on a connection, counted until dropped: the idle close is asked of it instead of shutting the
/// socket down under it.
pub struct Closer(Option<Arc<Inner>>);

impl Closer {
    /// Completes once the connection is closed as idle (never when the timeout is off): the transport closes it.
    pub async fn requested(&self) {
        let Some(inner) = &self.0 else { return std::future::pending().await };
        loop {
            let notified = inner.close.notified();
            if inner.closing.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for Closer {
    fn drop(&mut self) {
        if let Some(inner) = &self.0 {
            inner.closers.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Something in progress on a connection, until dropped.
pub struct Busy(Option<Arc<Inner>>);

impl Busy {
    /// The handshake succeeded: the client has a whole period from now for its first request.
    pub fn completed(self) {
        if let Some(inner) = &self.0 {
            inner.last.store(inner.started.elapsed().as_nanos() as u64, Ordering::Release);
        }
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        if let Some(inner) = &self.0 {
            inner.busy.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// A connection's socket whose traffic restarts its idle period.
pub struct IdleIo<S> {
    inner: S,
    activity: Activity,
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleIo<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.touch();
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleIo<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            self.activity.touch();
        }
        result
    }

    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[std::io::IoSlice<'_>]) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            self.activity.touch();
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// `InboundConnectionLimiter.logRejection`'s rate limit: one WARN at most every 10 seconds, naming how many refusals
/// went unlogged since the last.
#[derive(Default)]
pub struct RejectionLog {
    next: Option<Instant>,
    unlogged: u64,
}


impl RejectionLog {
    /// `Some(suppressed)` when this refusal is logged.
    pub fn refused(&mut self) -> Option<u64> {
        let now = Instant::now();
        if self.next.is_none_or(|next| now >= next) {
            self.next = Some(now + Duration::from_secs(10));
            Some(std::mem::take(&mut self.unlogged))
        } else {
            self.unlogged += 1;
            None
        }
    }
}

/// `InboundConnectionLimiter.reject`'s WARN, without a port: the limiter runs on the acceptor's event loop.
pub fn log_refused(state: &State, remote: std::net::SocketAddr, max: i64, suppressed: u64) {
    use crate::recorded::{Level, LogEntry};
    let entry = LogEntry::at(
        Level::Warn,
        "refused inbound connection from:{}because maxInboundConnections:{}connections are already open; {}further connections were refused since the last message, which is repeated at most every 10 seconds",
    )
    .args([crate::http1::socket_address_arg(remote), serde_json::json!(max).into(), serde_json::json!(suppressed).into()])
    .without_port();
    crate::log::warn_event(state, entry);
}

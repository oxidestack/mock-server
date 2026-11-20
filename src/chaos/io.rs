//! `TcpChaosHandler`: connect-time TCP faults on a connection's bytes, keyed on the client's address.
//!
//! The wrapper is armed when the connection is switched to HTTP and some profile is active, as upstream adds its
//! handler to the pipeline only then; once armed it looks the profile up again on every read, so faults registered
//! or cleared later apply to the next bytes. Read faults are tried in upstream's order: down, reset peer, data limit,
//! slicer, bandwidth, latency. Close faults (slow close, timeout) apply when the connection is dropped.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use super::{HostProfile, TcpChaosProfile};
use crate::state::State;

/// The raw socket under a connection, for forcing a TCP RST (`SO_LINGER 0`) before it is closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct Socket(#[cfg(unix)] Option<std::os::fd::RawFd>);

impl Socket {
    #[cfg(unix)]
    pub fn of(stream: &tokio::net::TcpStream) -> Socket {
        use std::os::fd::AsRawFd;
        Socket(Some(stream.as_raw_fd()))
    }

    #[cfg(not(unix))]
    pub fn of(_: &tokio::net::TcpStream) -> Socket {
        Socket()
    }

    /// `SO_LINGER 0`: closing the socket now sends a RST instead of a FIN. The caller must still own the socket.
    pub fn reset_on_close(&self) {
        #[cfg(unix)]
        if let Some(fd) = self.0 {
            // SAFETY: the fd belongs to a stream that the caller still holds open.
            let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
            let _ = socket2::SockRef::from(&fd).set_linger(Some(Duration::ZERO));
        }
    }
}

/// `InetSocketAddress.getHostString()` of an accepted connection: the literal address, IPv6 uncompressed.
pub fn java_host_string(ip: std::net::IpAddr) -> String {
    match ip.to_canonical() {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => v6.segments().iter().map(|s| format!("{s:x}")).collect::<Vec<_>>().join(":"),
    }
}

pub struct ChaosIo<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    inner: Option<S>,
    /// `None`: not armed, every call passes straight through.
    armed: Option<(Arc<State>, String)>,
    socket: Socket,
    consumed: u64,
    /// Bytes read but not yet delivered (delayed, or being sliced).
    held: BytesMut,
    slice: Option<usize>,
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
    /// Lives as long as the socket does, a held one included: the connection's metrics guard and its entry
    /// in the stop-time close registry, `server::OpenConnection`.
    guard: Option<Box<dyn Send + Sync>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> ChaosIo<S> {
    /// Armed when a TCP chaos profile is active (`TcpChaosRegistry.activeCount() > 0`).
    pub fn new(state: &Arc<State>, remote: std::net::SocketAddr, socket: Socket, inner: S) -> ChaosIo<S> {
        let armed = (state.chaos.tcp.active_count() > 0).then(|| (state.clone(), java_host_string(remote.ip())));
        ChaosIo { inner: Some(inner), armed, socket, consumed: 0, held: BytesMut::new(), slice: None, delay: None, guard: None }
    }

    /// The loopback leg of a CONNECT or SOCKS tunnel: upstream relays to MockServer's own port over a connection from
    /// `127.0.0.1`, whose `TcpChaosHandler` reads the registry at every read, so a profile for the loopback host put
    /// after the tunnel opened applies. Armed at once, and the RST it forces lands on the client's own socket
    /// (`socket`), the tunnel being served on it.
    pub fn loopback(state: &Arc<State>, socket: Socket, inner: S) -> ChaosIo<S> {
        let armed = Some((state.clone(), "127.0.0.1".to_string()));
        ChaosIo { inner: Some(inner), armed, socket, consumed: 0, held: BytesMut::new(), slice: None, delay: None, guard: None }
    }

    /// Keeps `guard` until the socket closes: with this wrapper, or in the task a slow close or a timeout hands the
    /// socket to when the wrapper is dropped.
    pub fn holding<G: Send + Sync + 'static>(mut self, guard: Option<G>) -> ChaosIo<S> {
        self.guard = guard.map(|g| Box::new(g) as Box<dyn Send + Sync>);
        self
    }

    fn profile(&self) -> Option<TcpChaosProfile> {
        let (state, host) = self.armed.as_ref()?;
        state.chaos.tcp.get(host).filter(TcpChaosProfile::has_any_fault)
    }

    fn inner(&mut self) -> Pin<&mut S> {
        Pin::new(self.inner.as_mut().expect("present until dropped"))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncRead for ChaosIo<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        if this.armed.is_none() {
            return this.inner().poll_read(cx, buf);
        }
        loop {
            if let Some(delay) = this.delay.as_mut() {
                ready!(delay.as_mut().poll(cx));
                this.delay = None;
            }
            if !this.held.is_empty() {
                let n = this.held.len().min(buf.remaining()).min(this.slice.unwrap_or(usize::MAX));
                buf.put_slice(&this.held[..n]);
                this.held.advance(n);
                return Poll::Ready(Ok(()));
            }
            this.slice = None;
            let mut scratch = vec![0u8; buf.remaining().max(1)];
            let mut read = ReadBuf::new(&mut scratch);
            ready!(this.inner().poll_read(cx, &mut read))?;
            let data = read.filled();
            if data.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let Some(profile) = this.profile() else {
                buf.put_slice(data);
                return Poll::Ready(Ok(()));
            };
            if profile.down == Some(true) {
                continue;
            }
            if profile.reset_peer == Some(true) {
                this.socket.reset_on_close();
                return Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()));
            }
            if let Some(limit) = profile.limit_data_bytes.filter(|l| *l > 0) {
                if this.consumed >= limit as u64 {
                    return Poll::Ready(Ok(()));
                }
                this.consumed += data.len() as u64;
            }
            this.held.extend_from_slice(data);
            if let Some(chunk) = profile.slicer_chunk_size.filter(|c| *c > 0) {
                this.slice = Some(chunk as usize);
                continue;
            }
            if let Some(rate) = profile.bandwidth_bytes_per_sec.filter(|r| *r > 0) {
                let millis = this.held.len() as u64 * 1000 / rate as u64;
                if millis > 0 {
                    this.delay = Some(Box::pin(tokio::time::sleep(Duration::from_millis(millis))));
                    continue;
                }
            }
            if let Some(latency) = profile.latency_ms.filter(|l| *l > 0) {
                this.delay = Some(Box::pin(tokio::time::sleep(Duration::from_millis(latency as u64))));
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncWrite for ChaosIo<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        self.inner().poll_write(cx, buf)
    }

    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[std::io::IoSlice<'_>]) -> Poll<std::io::Result<usize>> {
        self.inner().poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.as_ref().is_some_and(|i| i.is_write_vectored())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner().poll_flush(cx)
    }

    /// A slow close or a timeout holds the FIN back; the drop decides when (or whether) the socket closes.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.profile().is_some_and(|p| p.slow_close == Some(true) || p.timeout == Some(true)) {
            return Poll::Ready(Ok(()));
        }
        self.inner().poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Drop for ChaosIo<S> {
    fn drop(&mut self) {
        let Some(profile) = self.profile() else { return };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
        let Some(mut inner) = self.inner.take() else { return };
        if profile.slow_close == Some(true) {
            // `slow_close`: the FIN goes out 2 seconds late.
            let guard = self.guard.take();
            runtime.spawn(async move {
                tokio::time::sleep(Duration::from_secs(2)).await;
                drop(inner);
                drop(guard);
            });
        } else if profile.timeout == Some(true) {
            // `timeout`: no FIN at all; the socket stays open until the client gives up.
            let guard = self.guard.take();
            runtime.spawn(async move {
                let mut sink = [0u8; 4096];
                while matches!(inner.read(&mut sink).await, Ok(n) if n > 0) {}
                drop(inner);
                drop(guard);
            });
        } else {
            self.inner = Some(inner);
        }
    }
}

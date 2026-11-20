//! A server TLS stream that flushes what rustls has queued while the connection waits for the client.
//!
//! `tokio-rustls` writes only on a write or a flush, never on a read. A record that rustls queues in answer to a read
//! (the `no_renegotiation` warning for a ClientHello after the handshake, a `close_notify` reply) would otherwise sit in
//! the session until the next response, and the client would wait out its own timeout. Netty's `SslHandler` writes such
//! an answer as soon as it has produced it.
//!
//! The socket keeps one write waker only, the last one a pending write registered (`TcpStream::poll_write_ready`). A
//! flush on read that the socket leaves pending would take it from a writer parked on the same socket (a split stream's
//! write half, blocked on a client that stopped reading), and the writer would never learn that the client reset the
//! connection. So the flush on read registers a waker that wakes the parked writer too.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;

pub struct FlushOnRead<S> {
    stream: TlsStream<S>,
    /// The waker of the last write, flush or shutdown the socket left pending; `None` once one completed.
    writer: Option<Waker>,
}

impl<S> FlushOnRead<S> {
    pub fn new(stream: TlsStream<S>) -> Self {
        Self { stream, writer: None }
    }

    pub fn get_ref(&self) -> (&S, &rustls::ServerConnection) {
        self.stream.get_ref()
    }

    /// Remembers whose write waits on the socket.
    fn writing<T>(&mut self, cx: &Context<'_>, poll: Poll<T>) -> Poll<T> {
        match &poll {
            Poll::Pending => match &mut self.writer {
                Some(writer) => writer.clone_from(cx.waker()),
                None => self.writer = Some(cx.waker().clone()),
            },
            Poll::Ready(_) => self.writer = None,
        }
        poll
    }
}

/// The reader's waker and the parked writer's, both woken by whatever the flush on read waits for.
struct Both(Waker, Waker);

impl Wake for Both {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.wake_by_ref();
        self.1.wake_by_ref();
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for FlushOnRead<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let read = Pin::new(&mut this.stream).poll_read(cx, buf);
        if this.stream.get_ref().1.wants_write() {
            // a failed write surfaces on the next read or write; a pending one wakes this task, and the parked writer,
            // when the socket drains or fails
            match this.writer.take() {
                Some(writer) if !writer.will_wake(cx.waker()) => {
                    let both = Waker::from(Arc::new(Both(cx.waker().clone(), writer.clone())));
                    if Pin::new(&mut this.stream).poll_flush(&mut Context::from_waker(&both)).is_ready() {
                        // what the writer waited on has gone out, or failed: it looks again
                        writer.wake();
                    } else {
                        this.writer = Some(writer);
                    }
                }
                writer => {
                    this.writer = writer;
                    let _ = Pin::new(&mut this.stream).poll_flush(cx);
                }
            }
        }
        read
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for FlushOnRead<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.stream).poll_write(cx, buf);
        self.writing(cx, poll)
    }

    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.stream).poll_write_vectored(cx, bufs);
        self.writing(cx, poll)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.stream).poll_flush(cx);
        self.writing(cx, poll)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.stream).poll_shutdown(cx);
        self.writing(cx, poll)
    }
}

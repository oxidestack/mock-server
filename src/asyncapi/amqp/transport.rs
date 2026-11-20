//! The byte stream lapin speaks AMQP over, and the runtime kit that hands it to lapin: TCP, or TLS over it
//! (`useSslProtocol()`, done here with the shared dialer rather than by lapin), watched until the handshake ends.
//!
//! lapin does not settle a handshake the broker ends after `connection.open` (an unknown virtual host: RabbitMQ
//! answers `connection.close`); the Java client fails at once. The watch parses the frames the broker sends: a
//! `connection.close` (other than 403, which lapin reports as an authentication failure) or the connection ending
//! before `connection.open-ok` refuses the handshake, and a later `connection.close` is kept, since lapin reports
//! a closed connection without the broker's reason.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use async_compat::Compat;
use async_rs::traits::{Executor, Reactor, RuntimeKit};
use futures_io::{AsyncRead, AsyncWrite};
use parking_lot::Mutex;

/// What the watch learns of the broker's frames: whether it refused the handshake, and the `connection.close` it
/// sent, if any (lapin reports a closed connection without the broker's reason).
#[derive(Default)]
pub struct Watch {
    buffer: Mutex<Vec<u8>>,
    open: AtomicBool,
    done: AtomicBool,
    refused: AtomicBool,
    notify: tokio::sync::Notify,
    closed_by_broker: Mutex<Option<BrokerClose>>,
}

/// A `connection.close` from the broker: reply code and text, and the class and method that caused it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerClose {
    pub code: u16,
    pub text: String,
    pub class: u16,
    pub method: u16,
}

impl Watch {
    /// Waits until the broker refused the handshake.
    pub async fn refused(&self) {
        loop {
            let notified = self.notify.notified();
            if self.refused.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    /// The `connection.close` the broker sent.
    pub fn closed_by_broker(&self) -> Option<BrokerClose> {
        self.closed_by_broker.lock().clone()
    }

    fn refuse(&self) {
        if !self.done.swap(true, Ordering::SeqCst) {
            self.refused.store(true, Ordering::SeqCst);
            self.notify.notify_waiters();
        }
    }

    /// Frames from the broker: `connection.open-ok` (class 10, method 41) ends the handshake; `connection.close`
    /// (10, 50) is remembered and, during the handshake, refuses it unless its reply code is 403 (which lapin
    /// reports as an authentication failure).
    fn received(&self, bytes: &[u8]) {
        let mut buffer = self.buffer.lock();
        buffer.extend_from_slice(bytes);
        // A broker refusing our protocol header answers its own.
        if !self.open.load(Ordering::SeqCst) && buffer.starts_with(b"AMQP") && buffer.len() >= 8 {
            buffer.drain(..8);
        }
        while buffer.len() >= 7 {
            let size = u32::from_be_bytes([buffer[3], buffer[4], buffer[5], buffer[6]]) as usize;
            let Some(frame_end) = size.checked_add(8).filter(|end| buffer.len() >= *end) else { return };
            let (kind, payload) = (buffer[0], &buffer[7..7 + size]);
            if kind == 1 && payload.len() >= 4 {
                match (u16::from_be_bytes([payload[0], payload[1]]), u16::from_be_bytes([payload[2], payload[3]])) {
                    (10, 41) => {
                        self.open.store(true, Ordering::SeqCst);
                        self.done.store(true, Ordering::SeqCst);
                    }
                    (10, 50) => {
                        let close = parse_close(&payload[4..]);
                        let code = close.as_ref().map(|c| c.code);
                        *self.closed_by_broker.lock() = close;
                        if code == Some(403) {
                            self.done.store(true, Ordering::SeqCst);
                        } else {
                            self.refuse();
                        }
                    }
                    _ => {}
                }
            }
            buffer.drain(..frame_end);
        }
    }
}

/// `connection.close`'s arguments: reply-code, reply-text (a short string), class-id, method-id.
fn parse_close(args: &[u8]) -> Option<BrokerClose> {
    let code = u16::from_be_bytes([*args.first()?, *args.get(1)?]);
    let length = *args.get(2)? as usize;
    let text = String::from_utf8_lossy(args.get(3..3 + length)?).into_owned();
    let rest = args.get(3 + length..3 + length + 4)?;
    Some(BrokerClose { code, text, class: u16::from_be_bytes([rest[0], rest[1]]), method: u16::from_be_bytes([rest[2], rest[3]]) })
}

enum Inner {
    Plain(Compat<tokio::net::TcpStream>),
    Tls(Box<Compat<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>),
}

/// A connection to the broker as lapin reads and writes it.
pub struct Stream {
    inner: Inner,
    handshake: Option<Arc<Watch>>,
}

impl Stream {
    pub fn plain(tcp: tokio::net::TcpStream, handshake: Option<Arc<Watch>>) -> Stream {
        Stream { inner: Inner::Plain(Compat::new(tcp)), handshake }
    }

    pub fn tls(tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>, handshake: Option<Arc<Watch>>) -> Stream {
        Stream { inner: Inner::Tls(Box::new(Compat::new(tls))), handshake }
    }
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = match &mut this.inner {
            Inner::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Inner::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        };
        if let (Some(watch), Poll::Ready(outcome)) = (&this.handshake, &result) {
            match outcome {
                Ok(0) | Err(_) => watch.refuse(),
                Ok(n) => watch.received(&buf[..*n]),
            }
        }
        result
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            Inner::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Inner::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            Inner::Plain(s) => Pin::new(s).poll_flush(cx),
            Inner::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            Inner::Plain(s) => Pin::new(s).poll_close(cx),
            Inner::Tls(s) => Pin::new(s.as_mut()).poll_close(cx),
        }
    }
}

/// async-rs's tokio kit, with [`Stream`] as its TCP stream so lapin's connector can return one.
#[derive(Clone, Debug, Default)]
pub struct Kit(async_rs::Tokio);

impl Kit {
    pub fn current() -> Kit {
        Kit(async_rs::Tokio::current())
    }
}

impl RuntimeKit for Kit {}

impl Executor for Kit {
    type Task<T: Send + 'static> = <async_rs::Tokio as Executor>::Task<T>;

    fn block_on<T, F: Future<Output = T>>(&self, f: F) -> T {
        self.0.block_on(f)
    }

    fn spawn<T: Send + 'static, F: Future<Output = T> + Send + 'static>(&self, f: F) -> async_rs::util::Task<Self::Task<T>> {
        self.0.spawn(f)
    }

    fn spawn_blocking<T: Send + 'static, F: FnOnce() -> T + Send + 'static>(&self, f: F) -> async_rs::util::Task<Self::Task<T>> {
        self.0.spawn_blocking(f)
    }
}

impl Reactor for Kit {
    type TcpStream = Stream;
    type Sleep = <async_rs::Tokio as Reactor>::Sleep;

    fn register<H: io::Read + io::Write + std::os::fd::AsFd + std::os::fd::AsRawFd + Send + 'static>(
        &self,
        socket: H,
    ) -> io::Result<impl AsyncRead + AsyncWrite + Send + Unpin + 'static> {
        self.0.register(socket)
    }

    fn sleep(&self, dur: std::time::Duration) -> Self::Sleep {
        self.0.sleep(dur)
    }

    fn interval(&self, dur: std::time::Duration) -> impl futures_util::Stream<Item = std::time::Instant> + Send + 'static {
        self.0.interval(dur)
    }

    /// Not used: the connector dials itself.
    #[allow(clippy::manual_async_fn, reason = "`Reactor` asks for a 'static future; an async fn would borrow `self`")]
    fn tcp_connect_addr(&self, addr: std::net::SocketAddr) -> impl Future<Output = io::Result<Stream>> + Send + 'static {
        async move { Ok(Stream::plain(tokio::net::TcpStream::connect(addr).await?, None)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method(class: u16, method: u16, rest: &[u8]) -> Vec<u8> {
        let mut payload = [class.to_be_bytes(), method.to_be_bytes()].concat();
        payload.extend_from_slice(rest);
        let mut frame = vec![1, 0, 0];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        frame.push(0xCE);
        frame
    }

    #[test]
    fn a_close_before_open_ok_refuses_the_handshake() {
        let watch = Watch::default();
        let start = method(10, 10, &[0; 40]);
        watch.received(&start[..10]);
        watch.received(&start[10..]);
        assert!(!watch.refused.load(Ordering::SeqCst));
        watch.received(&method(10, 50, &[0x02, 0x12, 5, b'N', b'O', b'T', b'_', b'A', 0, 10, 0, 40]));
        assert!(watch.refused.load(Ordering::SeqCst));
        assert_eq!(watch.closed_by_broker(), Some(BrokerClose { code: 530, text: "NOT_A".into(), class: 10, method: 40 }));
    }

    #[test]
    fn open_ok_ends_the_watch_and_403_is_left_to_lapin() {
        let watch = Watch::default();
        watch.received(&method(10, 50, &[0x01, 0x93, 0, 0, 0, 0, 0]));
        watch.refuse();
        assert!(!watch.refused.load(Ordering::SeqCst), "403: an authentication failure lapin reports itself, then the end");
        let watch = Watch::default();
        watch.received(&method(10, 41, &[0]));
        watch.received(&method(10, 50, &[0x01, 0x40, 2, b'N', b'O', 0, 0, 0, 0]));
        watch.refuse();
        assert!(!watch.refused.load(Ordering::SeqCst), "the handshake is over after connection.open-ok");
        assert_eq!(watch.closed_by_broker().map(|c| c.code), Some(320), "a later close is kept");
    }
}

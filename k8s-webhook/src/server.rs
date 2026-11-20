//! `WebhookServer`: the HTTPS endpoint the API server calls. The HTTP/1.1 side is the JDK's own `HttpsServer`
//! (`sun.net.httpserver`, JDK 17) as upstream's image runs it, byte for byte where a client can see it:
//!
//! * two contexts: `/inject` (`POST` an `AdmissionReview`, get the review back with its response, fail-open: an
//!   unreadable review is allowed with a `status.message`; other methods get 405) and `/healthz` (200 `ok`);
//! * a context matches every request path it is a string prefix of (`/injector` reaches `/inject`), after
//!   percent-decoding, also in absolute form (`GET http://host/healthz`);
//! * a path under neither context gets the JDK's 404 page, and an unparsable request line its 400 page, each
//!   followed by closing the connection;
//! * handler responses carry `Date`, `Content-type` and `Content-length` in that order and case, plus a leading
//!   `Connection: close` for an HTTP/1.0 request; a HEAD response has no `Content-length` and no body;
//! * `Expect: 100-continue` is answered with `100 Continue` before the handler runs; chunked request bodies are read;
//! * keep-alive connections stay open until the client closes them, asks to (`Connection: close`), or idles 30s.

use crate::admission::AdmissionReviewHandler;
use crate::config::SidecarInjectionConfig;
use crate::java::equals_ignore_case;
use crate::log;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, oneshot};
use tokio::task::{JoinHandle, JoinSet};

const CLASS: &str = "org.mockserver.webhook.WebhookServer";
/// `sun.net.httpserver.idleInterval`
const IDLE: Duration = Duration::from_secs(30);
/// `sun.net.httpserver.maxReqHeaders`
const MAX_HEADERS: usize = 200;

pub struct WebhookServer {
    listener: Option<TcpListener>,
    local_addr: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    handler: Arc<AdmissionReviewHandler>,
    running: Option<(oneshot::Sender<Duration>, JoinHandle<()>)>,
}

impl WebhookServer {
    /// `new WebhookServer(bindAddress, sslContext, config)`: binds, but serves only after [`WebhookServer::start`].
    pub async fn bind(addr: SocketAddr, tls: Arc<rustls::ServerConfig>, config: SidecarInjectionConfig) -> std::io::Result<WebhookServer> {
        WebhookServer::from_listener(TcpListener::bind(addr).await?, tls, config)
    }

    /// A server on a listener already bound (`main` binds the dual-stack wildcard as the JVM does).
    pub fn from_listener(listener: TcpListener, tls: Arc<rustls::ServerConfig>, config: SidecarInjectionConfig) -> std::io::Result<WebhookServer> {
        let local_addr = listener.local_addr()?;
        Ok(WebhookServer {
            listener: Some(listener),
            local_addr,
            tls,
            handler: Arc::new(AdmissionReviewHandler::new(config)),
            running: None,
        })
    }

    /// `start()`
    pub fn start(&mut self) {
        let Some(listener) = self.listener.take() else {
            return;
        };
        let (stop_tx, stop_rx) = oneshot::channel();
        let task = tokio::spawn(serve(listener, self.tls.clone(), self.handler.clone(), stop_rx));
        self.running = Some((stop_tx, task));
        log::info(CLASS, "start", &format!("webhook server started on {}:{}", host_string(self.local_addr.ip()), self.local_addr.port()));
    }

    /// `getPort()`
    pub fn port(&self) -> u16 {
        self.local_addr.port()
    }

    /// `stop(delaySeconds)`: closes the listener, waits up to `delay` for exchanges in progress, then closes every
    /// connection.
    pub async fn stop(mut self, delay: Duration) {
        log::info(CLASS, "stop", "stopping webhook server");
        if let Some((stop_tx, task)) = self.running.take() {
            let _ = stop_tx.send(delay);
            let _ = task.await;
        }
    }
}

/// `InetAddress.getHostAddress()`: IPv6 as eight uncompressed hex groups (`0:0:0:0:0:0:0:0`).
fn host_string(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => v6.segments().iter().map(|s| format!("{s:x}")).collect::<Vec<_>>().join(":"),
    }
}

/// Exchanges in progress, for `stop`'s drain.
#[derive(Default)]
struct InFlight {
    count: AtomicUsize,
    idle: Notify,
}

impl InFlight {
    fn enter(self: &Arc<Self>) -> InFlightGuard {
        self.count.fetch_add(1, Ordering::SeqCst);
        InFlightGuard(self.clone())
    }

    async fn drained(&self) {
        loop {
            let notified = self.idle.notified();
            if self.count.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct InFlightGuard(Arc<InFlight>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

async fn serve(listener: TcpListener, acceptor: Arc<rustls::ServerConfig>, handler: Arc<AdmissionReviewHandler>, mut stop: oneshot::Receiver<Duration>) {
    let in_flight = Arc::new(InFlight::default());
    let mut connections = JoinSet::new();
    let delay = loop {
        tokio::select! {
            delay = &mut stop => break delay.unwrap_or(Duration::ZERO),
            accepted = listener.accept() => {
                let Ok((tcp, _)) = accepted else { continue };
                let (acceptor, handler, in_flight) = (acceptor.clone(), handler.clone(), in_flight.clone());
                connections.spawn(async move {
                    let Ok(Ok(tls)) = tokio::time::timeout(IDLE, handshake(tcp, acceptor)).await else { return };
                    connection(tls, &handler, &in_flight).await;
                });
                while connections.try_join_next().is_some() {}
            }
        }
    };
    drop(listener);
    let _ = tokio::time::timeout(delay, in_flight.drained()).await;
    connections.abort_all();
}

/// The server side of a TLS handshake. When the key store's entry resolves no certificate (a key that cannot sign
/// for its certificate's type), the JDK's `SSLEngine` gives up without sending an alert and the connection is closed;
/// so is it here, right after the ClientHello.
async fn handshake(tcp: TcpStream, config: Arc<rustls::ServerConfig>) -> std::io::Result<tokio_rustls::server::TlsStream<TcpStream>> {
    let mut tcp = tcp;
    let dsa = crate::dsa::is_dsa_resolver(&*config.cert_resolver);
    let peeked = if dsa { peek_client_hello(&tcp).await } else { crate::tls13::Reassembled::NotHello };
    let (hello, consumed) = match &peeked {
        crate::tls13::Reassembled::Hello { message, consumed } => (Some(message.as_slice()), *consumed),
        crate::tls13::Reassembled::Alert(description) => {
            // a record or message the JDK refuses, whole or in pieces (`tls13::reassemble`)
            crate::tls13::alert_and_close(&mut tcp, *description).await?;
            return Err(std::io::Error::other("a ClientHello the JDK refuses"));
        }
        _ => (None, 0),
    };
    let info = hello.and_then(crate::dsa::HelloInfo::parse);
    if let Some(offer) = hello.and_then(crate::tls13::ClientHello::parse).filter(|h| h.offers_tls13()) {
        // a DSA key serves TLS 1.2 only; the JDK runs a TLS 1.3 handshake as far as it can and fails it (`tls13.rs`)
        crate::tls13::answer(&mut tcp, &offer, consumed).await?;
        return Err(std::io::Error::other("a client offering TLS 1.3, and a DSA key"));
    }
    let start = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp).await?;
    let Some(resolved) = config.cert_resolver.resolve(start.client_hello()) else {
        return Err(std::io::Error::other("no certificate resolved"));
    };
    // a DSA key signs with the DSA scheme the client lists first, which rustls hides from its own signing step
    // (`dsa.rs`); the handshake's first flight is made synchronously inside `into_stream`
    crate::dsa::remember_client_schemes(start.client_hello().signature_schemes());
    let accepted = start.into_stream(config);
    crate::dsa::forget_client_schemes();
    match accepted.into_fallible().await {
        Ok(stream) => Ok(stream),
        Err((error, mut tcp)) => {
            // the JDK's `internal_error` for a DSA key it cannot sign with comes after its ServerHello and Certificate;
            // rustls cannot send that alert and queues nothing of the flight, so all of it is written here
            if error.get_ref().is_some_and(|e| e.to_string().contains(crate::dsa::INTERNAL_ERROR_MARKER)) {
                if let Some(flight) = info.as_ref().and_then(|h| crate::dsa::internal_error_flight(h, &resolved.cert)) {
                    let _ = write(&mut tcp, &flight).await;
                }
                let _ = tcp.shutdown().await;
            }
            Err(error)
        }
    }
}

/// The ClientHello the client sent, in one handshake record or several, peeked without consuming it; `NotHello` when it
/// is not one or does not arrive whole in `tls13::MAX_HELLO_BYTES` (the handshake's own timeout bounds the wait).
async fn peek_client_hello(tcp: &TcpStream) -> crate::tls13::Reassembled {
    use crate::tls13::{MAX_HELLO_BYTES, Reassembled, reassemble};
    let mut buf = vec![0u8; MAX_HELLO_BYTES];
    let mut wait = Duration::from_millis(2);
    loop {
        let Ok(n) = tcp.peek(&mut buf).await else {
            return Reassembled::NotHello;
        };
        if n == 0 {
            return Reassembled::NotHello;
        }
        match reassemble(&buf[..n]) {
            Reassembled::Incomplete if n == buf.len() => return Reassembled::NotHello,
            Reassembled::Incomplete => {}
            done => return done,
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(Duration::from_millis(250));
    }
}

/// One parsed request head.
struct Head {
    method: String,
    target: String,
    http10: bool,
    headers: Vec<(String, String)>,
    /// bytes of the buffer the head took
    len: usize,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

enum Parsed {
    Head(Head),
    Partial,
    Bad,
}

fn parse_head(buf: &[u8]) -> Parsed {
    let mut headers = vec![httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(buf) {
        Ok(httparse::Status::Complete(len)) => Parsed::Head(Head {
            method: request.method.unwrap_or_default().to_string(),
            target: request.path.unwrap_or_default().to_string(),
            http10: request.version == Some(0),
            headers: request.headers.iter().map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned())).collect(),
            len,
        }),
        Ok(httparse::Status::Partial) => Parsed::Partial,
        Err(_) => Parsed::Bad,
    }
}

/// Serves requests on one connection until it closes.
async fn connection<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, handler: &AdmissionReviewHandler, in_flight: &Arc<InFlight>) {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let head = loop {
            if !buf.is_empty() {
                match parse_head(&buf) {
                    Parsed::Head(head) => break head,
                    Parsed::Bad => {
                        let _ = write(&mut stream, &reject(400, "Bad Request", "Bad request line")).await;
                        return;
                    }
                    Parsed::Partial => {}
                }
            }
            match tokio::time::timeout(IDLE, read_more(&mut stream, &mut buf)).await {
                Ok(Ok(true)) => {}
                _ => return,
            }
        };
        buf.drain(..head.len);
        let _exchange = in_flight.enter();

        let path = request_path(&head.target);
        let context = if path.starts_with("/inject") {
            Context::Inject
        } else if path.starts_with("/healthz") {
            Context::Healthz
        } else {
            let _ = write(&mut stream, &reject(404, "Not Found", "No context found for request")).await;
            return;
        };

        if !head.http10 && head.header("Expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) && write(&mut stream, b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n").await.is_err() {
            return;
        }
        let Some(body) = read_body(&mut stream, &mut buf, &head).await else {
            return;
        };

        let (status, content_type, payload) = match context {
            Context::Healthz => (200, "text/plain", b"ok".to_vec()),
            Context::Inject => handle_inject(&head.method, &body, handler),
        };
        let close = head.http10 || head.header("Connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
        let response = respond(status, content_type, &payload, head.http10, head.method.eq_ignore_ascii_case("HEAD"));
        if write(&mut stream, &response).await.is_err() || close {
            return;
        }
    }
}

enum Context {
    Inject,
    Healthz,
}

/// `URI.getPath()` of the request target: origin form up to `?`/`#`, the path of an absolute form, percent-decoded.
fn request_path(target: &str) -> String {
    let after_authority = match target.find("://") {
        Some(scheme_end) if !target.starts_with('/') => {
            let rest = &target[scheme_end + 3..];
            rest.find('/').map(|i| &rest[i..]).unwrap_or("")
        }
        _ => target,
    };
    let path = after_authority.split(['?', '#']).next().unwrap_or("");
    percent_encoding::percent_decode_str(path).decode_utf8_lossy().into_owned()
}

/// Reads more bytes into `buf`; false at end of stream.
async fn read_more<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>) -> std::io::Result<bool> {
    let mut chunk = [0u8; 16 * 1024];
    let n = stream.read(&mut chunk).await?;
    buf.extend_from_slice(&chunk[..n]);
    Ok(n > 0)
}

/// The request body: chunked, `Content-Length`, or none. `None` when the connection fails or closes early.
async fn read_body<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>, head: &Head) -> Option<Vec<u8>> {
    if head.header("Transfer-Encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        let mut body = Vec::new();
        loop {
            let line = read_line(stream, buf).await?;
            let size_text = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_text, 16).ok()?;
            if size == 0 {
                // trailers up to the empty line
                while !read_line(stream, buf).await?.is_empty() {}
                return Some(body);
            }
            while buf.len() < size + 2 {
                if !read_more(stream, buf).await.ok()? {
                    return None;
                }
            }
            body.extend_from_slice(&buf[..size]);
            buf.drain(..size + 2);
        }
    }
    let length: usize = match head.header("Content-Length") {
        Some(v) => v.trim().parse().ok()?,
        None => 0,
    };
    while buf.len() < length {
        if !read_more(stream, buf).await.ok()? {
            return None;
        }
    }
    Some(buf.drain(..length).collect())
}

async fn read_line<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(end) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = String::from_utf8_lossy(&buf[..end]).into_owned();
            buf.drain(..end + 2);
            return Some(line);
        }
        if !read_more(stream, buf).await.ok()? {
            return None;
        }
    }
}

async fn write<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> std::io::Result<()> {
    stream.write_all(bytes).await?;
    stream.flush().await
}

/// `handleInject(HttpExchange)`: (status, content type, body).
fn handle_inject(method: &str, body: &[u8], handler: &AdmissionReviewHandler) -> (u16, &'static str, Vec<u8>) {
    if !equals_ignore_case("POST", method) {
        return (405, "text/plain", b"Method Not Allowed".to_vec());
    }
    if body.is_empty() {
        return (200, "application/json", handler.create_allow_with_message("", "empty request body"));
    }
    let reply = match handler.handle_admission_review_bytes(body) {
        Ok(reply) => reply,
        Err(e) => {
            log::warn_thrown(CLASS, "handleInject", "failed to process admission review, allowing pod", &e);
            handler.create_allow_with_message("", &format!("webhook error: {}", e.message_text()))
        }
    };
    (200, "application/json", reply)
}

/// `ExchangeImpl.sendResponseHeaders` and the body.
fn respond(status: u16, content_type: &str, body: &[u8], http10: bool, head: bool) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    if http10 {
        out.push_str("Connection: close\r\n");
    }
    out.push_str(&format!("Date: {}\r\nContent-type: {content_type}\r\n", http_date(SystemTime::now())));
    if !head {
        out.push_str(&format!("Content-length: {}\r\n", body.len()));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    if !head {
        bytes.extend_from_slice(body);
    }
    bytes
}

/// `ServerImpl.reject`: the JDK's own error page; the connection is closed after it.
fn reject(status: u16, reason: &str, message: &str) -> Vec<u8> {
    let text = format!("<h1>{status} {reason}</h1>{message}");
    format!("HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n{text}", text.len()).into_bytes()
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    }
}

/// RFC 1123 in GMT, as the JDK's `Date` header.
fn http_date(now: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let secs = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = log::civil_from_days(days);
    format!(
        "{}, {d:02} {} {y} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(m - 1) as usize],
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

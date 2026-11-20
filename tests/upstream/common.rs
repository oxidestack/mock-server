//! What the ports share: an in-process server and a plain HTTP/1.1 client.

use std::io::{Read, Write};

pub struct Running {
    pub server: mock_server::Server,
    pub port: u16,
}

/// A server with MockServer's defaults plus `properties` (names without the `mockserver.` prefix).
pub async fn start(properties: &[(&str, &str)]) -> Running {
    start_with(mock_server::Config::for_tests(), properties).await
}

/// A server whose callback classes are the integration-testing ones, registered in-process, as upstream's tests
/// have them on the server's class path.
pub async fn start_with_callback_classes(properties: &[(&str, &str)]) -> Running {
    let config = mock_server_integration_testing_callbacks::classes()
        .into_iter()
        .fold(mock_server::Config::for_tests(), |c, (name, class)| c.with_callback_class(&name, class));
    start_with(config, properties).await
}

/// `startMockServer` with `http3Port`: a server with `properties` and a free UDP port for its HTTP/3 listener, and that
/// port. Started again with a fresh port while the start fails on a port another process took ([`crate::udp_port`]), never on one this process holds.
pub async fn start_with_http3(properties: &[(&str, &str)]) -> (Running, u16) {
    let mut attempt = 1;
    loop {
        let udp = crate::udp_port::free_udp_port().to_string();
        let mut all = vec![("http3Port", udp.as_str())];
        all.extend_from_slice(properties);
        crate::scratch_cwd::enter();
        let config = all.iter().fold(mock_server::Config::for_tests(), |c, (k, v)| c.with_property(k, v));
        match mock_server::Server::start(config).await {
            Ok(server) => {
                let port = server.ports()[0];
                let h3 = server.http3_port().expect("a started server has its HTTP/3 listener");
                return (Running { server, port }, h3);
            }
            Err(e) if crate::udp_port::retry_taken_meanwhile(&e, attempt) => attempt += 1,
            Err(e) => panic!("server starts with HTTP/3 (attempt {attempt}): {e}"),
        }
    }
}

pub async fn start_with(config: mock_server::Config, properties: &[(&str, &str)]) -> Running {
    let config = properties.iter().fold(config, |c, (k, v)| c.with_property(k, v));
    crate::scratch_cwd::enter();
    let server = mock_server::Server::start(config).await.expect("server starts");
    let port = server.ports()[0];
    Running { server, port }
}

pub struct Response {
    pub status: u16,
    pub head: String,
    pub body: String,
}

/// One request on its own connection (`Connection: close`). A failure names the request, the connection's source
/// port, what had been read and who listens on the port then, so a reset says which request it hit and whether this
/// server still answers `127.0.0.1:port` (on macOS a later `127.0.0.1` bind with `SO_REUSEADDR` takes
/// the loopback connections of a dual-stack `[::]` listener).
pub async fn send(port: u16, method: &str, path: &str, body: &str) -> Response {
    let (method, path, body) = (method.to_string(), path.to_string(), body.to_string());
    tokio::task::spawn_blocking(move || {
        let request = format!("{method} {path} to 127.0.0.1:{port}");
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap_or_else(|e| panic!("{request}: connect failed: {e}; {}", listeners(port)));
        let source = s.local_addr().map(|a| a.port()).unwrap_or(0);
        write!(s, "{method} {path} HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap_or_else(|e| panic!("{request} from port {source}: write failed: {e}; {}", listeners(port)));
        let mut raw = Vec::new();
        if let Err(e) = s.read_to_end(&mut raw) {
            panic!("{request} from port {source}: read failed after {} bytes ({:?}): {e}; {}", raw.len(), String::from_utf8_lossy(&raw[..raw.len().min(200)]), listeners(port));
        }
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status = head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        Response { status, head: head.to_string(), body: body.to_string() }
    })
    .await
    .unwrap()
}

/// Who listens on TCP `port` now (`lsof`), for a failed [`send`]: this test process (its pid given), or another one
/// that took `127.0.0.1:port` from it.
fn listeners(port: u16) -> String {
    let lsof = std::process::Command::new("lsof").args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN"]).output();
    let found = match lsof {
        Ok(out) => String::from_utf8_lossy(&out.stdout).lines().skip(1).collect::<Vec<_>>().join(" | "),
        Err(e) => format!("lsof failed: {e}"),
    };
    format!("listening on port {port} (this pid {}): [{found}]", std::process::id())
}

/// `PUT /mockserver/expectation`.
pub async fn expect(port: u16, expectation: &serde_json::Value) {
    let r = send(port, "PUT", "/mockserver/expectation", &expectation.to_string()).await;
    assert_eq!(r.status, 201, "expectation accepted: {}", r.body);
}

/// `retrieve?type=LOGS`: the event log's messages.
pub async fn logs(port: u16) -> String {
    send(port, "PUT", "/mockserver/retrieve?type=LOGS", "").await.body
}

/// How a port's client reaches the server: upstream's `makeRequest` over plain HTTP, over TLS, or over TLS as HTTP/2
/// (`HTTP2*` classes' `getRequestModifier`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Http,
    Https,
    Http2,
}

pub struct Exchange {
    pub status: u16,
    /// The HTTP/1.1 reason phrase; HTTP/2 has none.
    pub reason: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: bytes::Bytes,
}

impl Exchange {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Accepts any server certificate, as upstream's test clients trust MockServer's CA.
#[derive(Debug)]
struct AnyCertificate(std::sync::Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A TLS client trusting any server certificate, offering `alpn` (none when empty).
pub fn tls_client_config(alpn: &[u8]) -> std::sync::Arc<rustls::ClientConfig> {
    tls_client_config_for(alpn, rustls::DEFAULT_VERSIONS)
}

/// [`tls_client_config`] presenting `chain` (leaf first) with `key` as its client certificate.
pub fn tls_client_config_with_client_auth(alpn: &[u8], chain: Vec<rustls_pki_types::CertificateDer<'static>>, key: rustls_pki_types::PrivateKeyDer<'static>) -> std::sync::Arc<rustls::ClientConfig> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AnyCertificate(provider)))
        .with_client_auth_cert(chain, key)
        .unwrap();
    if !alpn.is_empty() {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    std::sync::Arc::new(config)
}

/// [`tls_client_config`] offering only `versions`.
pub fn tls_client_config_for(alpn: &[u8], versions: &[&'static rustls::SupportedProtocolVersion]) -> std::sync::Arc<rustls::ClientConfig> {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AnyCertificate(provider)))
        .with_no_client_auth();
    if !alpn.is_empty() {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    std::sync::Arc::new(config)
}

async fn tls(port: u16, alpn: &[u8]) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    tokio_rustls::TlsConnector::from(tls_client_config(alpn)).connect(name, tcp).await.unwrap()
}

/// One request over `transport` on its own connection.
pub async fn exchange(port: u16, transport: Transport, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Exchange {
    use http_body_util::BodyExt;
    let mut builder = hyper::Request::builder().method(method).uri(path);
    if transport != Transport::Http2 {
        builder = builder.header("host", format!("localhost:{port}"));
    } else {
        builder = builder.uri(format!("https://localhost:{port}{path}"));
    }
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let request = builder.body(http_body_util::Full::new(bytes::Bytes::from(body.to_string()))).unwrap();
    let response = match transport {
        Transport::Http => {
            let io = hyper_util::rt::TokioIo::new(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap());
            let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await.unwrap();
            tokio::spawn(connection);
            sender.send_request(request).await.unwrap()
        }
        Transport::Https => {
            let io = hyper_util::rt::TokioIo::new(tls(port, b"http/1.1").await);
            let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await.unwrap();
            tokio::spawn(connection);
            sender.send_request(request).await.unwrap()
        }
        Transport::Http2 => {
            let io = hyper_util::rt::TokioIo::new(tls(port, b"h2").await);
            let (mut sender, connection) = hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io).await.unwrap();
            tokio::spawn(connection);
            sender.send_request(request).await.unwrap()
        }
    };
    let status = response.status().as_u16();
    // hyper keeps a reason phrase only when it is not the status's canonical one.
    let reason = match transport {
        Transport::Http2 => None,
        _ => response
            .extensions()
            .get::<hyper::ext::ReasonPhrase>()
            .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned())
            .or_else(|| response.status().canonical_reason().map(str::to_string)),
    };
    let headers = response.headers().iter().map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or_default().to_string())).collect();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Exchange { status, reason, headers, body }
}

/// A WebSocket callback client (`WebSocketClient` of the Java client): registers on
/// `/_mockserver_callback_websocket` and answers each request the server sends with `answer`, which gets the
/// message type (`org.mockserver.model.HttpRequest` or `…HttpRequestAndHttpResponse`) and its value, and returns
/// the reply's type and value. The correlation header is carried over.
pub struct CallbackClient {
    pub id: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for CallbackClient {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub type Answer = std::sync::Arc<dyn Fn(&str, &serde_json::Value) -> (String, serde_json::Value) + Send + Sync>;

pub async fn callback_client(port: u16, answer: Answer) -> CallbackClient {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/_mockserver_callback_websocket")).await.expect("callback websocket");
    let (mut sink, mut source) = ws.split();
    let first = source.next().await.expect("registration").expect("registration message");
    let envelope: serde_json::Value = serde_json::from_str(first.to_text().unwrap()).unwrap();
    let value: serde_json::Value = serde_json::from_str(envelope["value"].as_str().unwrap()).unwrap();
    let id = value["clientId"].as_str().unwrap().to_string();
    let task = tokio::spawn(async move {
        while let Some(Ok(Message::Text(text))) = source.next().await {
            let envelope: serde_json::Value = serde_json::from_str(&text).unwrap();
            let kind = envelope["type"].as_str().unwrap_or_default().to_string();
            let value: serde_json::Value = serde_json::from_str(envelope["value"].as_str().unwrap_or("null")).unwrap();
            let request = if kind.ends_with("HttpRequestAndHttpResponse") { &value["httpRequest"] } else { &value };
            let correlation = request["headers"]
                .as_object()
                .and_then(|h| h.iter().find(|(k, _)| k.eq_ignore_ascii_case("WebSocketCorrelationId")))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let answer = answer.clone();
            let (reply_kind, mut reply) = tokio::task::spawn_blocking(move || answer(&kind, &value)).await.unwrap();
            let headers = reply.as_object_mut().unwrap().entry("headers").or_insert_with(|| serde_json::json!({}));
            headers.as_object_mut().unwrap().insert("WebSocketCorrelationId".into(), correlation);
            let out = serde_json::json!({"type": reply_kind, "value": reply.to_string()});
            if sink.send(Message::text(out.to_string())).await.is_err() {
                break;
            }
        }
    });
    CallbackClient { id, task }
}

/// Polls `condition` for up to five seconds (`tryWaitForSuccess`).
pub async fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !condition() {
        if std::time::Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    true
}

/// [`eventually`] for an async probe: its first `Some` within five seconds.
pub async fn eventually_async<T, F: std::future::Future<Output = Option<T>>>(mut probe: impl FnMut() -> F) -> Option<T> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(found) = probe().await {
            return Some(found);
        }
        if std::time::Instant::now() > deadline {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

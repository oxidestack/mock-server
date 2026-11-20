//! Ports of master's binary relay classes: `BinaryPersistentRelayIntegrationTest`,
//! `BinaryRelayEndOfConnectionIntegrationTest`, `BinaryInBandTlsUpgradeProxyIntegrationTest`,
//! `BinaryTlsFromTheStartProxyIntegrationTest`, `BinaryServerFirstIntegrationTest`,
//! `BinaryRelayThroughUpstreamProxyIntegrationTest` and
//! `BinaryForwardConnectHeaderLimitIntegrationTest`, the cases that did not pass on rs-process. Each upstream is a
//! socket server in the test, as upstream's are; `StartTlsUpstream` is rebuilt here over rustls.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::common;

const TLS: &str = "upstream/mockserver/mockserver/mockserver-netty/src/test/resources/org/mockserver/netty/integration/tls";

const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f];
const STARTUP: [u8; 23] = [0, 0, 0, 23, 0, 3, 0, 0, b'u', b's', b'e', b'r', 0, b'p', b'o', b's', b't', b'g', b'r', b'e', b's', 0, 0];
const AUTHENTICATION_OK_AND_READY: [u8; 15] = [b'R', 0, 0, 0, 8, 0, 0, 0, 0, b'Z', 0, 0, 0, 5, b'I'];
const QUERY: [u8; 14] = [b'Q', 0, 0, 0, 13, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'1', 0];
const SYNC: [u8; 5] = [b'S', 0, 0, 0, 4];
const READY: [u8; 6] = [b'Z', 0, 0, 0, 5, b'I'];

fn tls_file(name: &str) -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(TLS).join(name).display().to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A server port-forwarding to `upstream_port` on 127.0.0.1 (`new MockServer(configuration, upstreamPort,
/// "127.0.0.1", 0)`).
async fn forwarding_to(upstream_port: u16, properties: &[(&str, &str)]) -> common::Running {
    let mut config = mock_server::Config::for_tests();
    config.port_forward = Some(("127.0.0.1".into(), upstream_port));
    common::start_with(config, properties).await
}

async fn connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.set_nodelay(true).unwrap();
    stream
}

async fn read_exactly<S: tokio::io::AsyncRead + Unpin>(stream: &mut S, n: usize) -> Vec<u8> {
    let mut buf = vec![0; n];
    tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut buf)).await.expect("answered in time").expect("answered");
    buf
}

async fn exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(stream: &mut S, message: &[u8], expected: &[u8]) {
    stream.write_all(message).await.unwrap();
    stream.flush().await.unwrap();
    assert_eq!(hex(&read_exactly(stream, expected.len()).await), hex(expected), "reply to {}", hex(message));
}

/// `readAfterClose`: what a refused or closed connection gives a reader.
async fn read_after_close<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut one = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(20), stream.read(&mut one)).await {
        Ok(Ok(0)) | Ok(Err(_)) => "closed".into(),
        Ok(Ok(_)) => format!("read {}", one[0]),
        Err(_) => "still open".into(),
    }
}

/// `StartTlsUpstream.startTlsAsClient(socket, "127.0.0.1", "TLSv1.3", false)`: the JDK's TLS, no server name.
async fn start_tls(stream: TcpStream, server_name: Option<&str>) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let name = match server_name {
        Some(name) => rustls_pki_types::ServerName::try_from(name.to_string()).unwrap(),
        None => rustls_pki_types::ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()),
    };
    let config = common::tls_client_config_for(&[], &[&rustls::version::TLS13]);
    tokio_rustls::TlsConnector::from(config).connect(name, stream).await
}

/// One `StartTlsUpstream` connection, as its test reads it.
#[derive(Default, Debug, Clone)]
struct Seen {
    messages: Vec<String>,
    in_the_clear: Vec<u8>,
    over_tls: Vec<u8>,
    server_names: Vec<String>,
    client_certificate_issuer: Option<String>,
    ended: bool,
    /// `Connection.push`.
    push: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
}

/// Accepts any client certificate and asks for one, as `requiringClientCertificate()` with a trust-all manager does.
#[derive(Debug)]
struct AnyClientCertificate(Arc<rustls::crypto::CryptoProvider>);

impl rustls::server::danger::ClientCertVerifier for AnyClientCertificate {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(&self, _: &rustls_pki_types::CertificateDer<'_>, _: &[rustls_pki_types::CertificateDer<'_>], _: rustls_pki_types::UnixTime) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &rustls_pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &rustls_pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// One connection's entry in what the upstream has seen.
struct Recorder {
    all: Arc<Mutex<Vec<Seen>>>,
    index: usize,
}

impl Recorder {
    fn update(&self, f: impl FnOnce(&mut Seen)) {
        f(&mut self.all.lock().unwrap()[self.index]);
    }
}

#[derive(Clone, Copy, Default)]
struct StartTlsOptions {
    /// `answeringSslRequestWith('N')`.
    refuse_tls: bool,
    /// `startingWithTls()`.
    tls_from_the_start: bool,
    /// `requiringClientCertificate()`.
    require_client_certificate: bool,
}

/// What a `StartTlsUpstream` answers: each message (`answering(message, answer)`) with its answer.
type Answers = Arc<Vec<(Vec<u8>, Vec<u8>)>>;

/// `StartTlsUpstream`: an SSLRequest the connection opens with answered `S` (TLS on the same connection) or `N`, then
/// every known message at the start of what it has received answered (`session()`'s: STARTUP, QUERY and SYNC), and
/// bytes that can begin none noted as `unanswered`.
struct StartTlsUpstream {
    port: u16,
    connections: Arc<Mutex<Vec<Seen>>>,
}

impl StartTlsUpstream {
    async fn start(options: StartTlsOptions) -> StartTlsUpstream {
        Self::answering(options, &[(&STARTUP, &AUTHENTICATION_OK_AND_READY), (&QUERY, &READY), (&SYNC, &READY)]).await
    }

    async fn answering(options: StartTlsOptions, answers: &[(&[u8], &[u8])]) -> StartTlsUpstream {
        use rustls_pki_types::pem::PemObject;
        let answers: Answers = Arc::new(answers.iter().map(|(m, a)| (m.to_vec(), a.to_vec())).collect());
        let chain = rustls_pki_types::CertificateDer::pem_file_iter(tls_file("leaf-cert.pem")).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        let key = rustls_pki_types::PrivateKeyDer::from_pem_file(tls_file("leaf-key-pkcs8.pem")).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().unwrap();
        let config = match options.require_client_certificate {
            true => builder.with_client_cert_verifier(Arc::new(AnyClientCertificate(provider))).with_single_cert(chain, key).unwrap(),
            false => builder.with_no_client_auth().with_single_cert(chain, key).unwrap(),
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let all = connections.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (push, pushed) = tokio::sync::mpsc::unbounded_channel();
                let index = {
                    let mut all = all.lock().unwrap();
                    all.push(Seen { push: Some(push), ..Seen::default() });
                    all.len() - 1
                };
                let (all, acceptor, answers) = (all.clone(), acceptor.clone(), answers.clone());
                tokio::spawn(async move {
                    let seen = Recorder { all, index };
                    converse(tcp, acceptor, options, Conversation { answers, pushed }, &seen).await;
                    seen.update(|s| s.ended = true);
                });
            }
        });
        StartTlsUpstream { port, connections }
    }

    fn connections(&self) -> Vec<Seen> {
        self.connections.lock().unwrap().clone()
    }

    async fn await_connection(&self) -> Seen {
        assert!(common::eventually(|| !self.connections().is_empty()).await, "an upstream connection");
        self.connections()[0].clone()
    }

    async fn await_ended(&self) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while std::time::Instant::now() < deadline {
            if self.connections().first().is_some_and(|c| c.ended) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    /// `awaitUpstreamMessage`: the first connection has received `message`.
    async fn await_message(&self, message: &str) {
        assert!(common::eventually(|| self.connections().first().is_some_and(|c| c.messages.iter().any(|m| m == message))).await, "the upstream never received {message}, only {:?}", self.connections());
    }

    /// `Connection.push`: bytes nobody asked for, over TLS once the connection has upgraded.
    fn push(&self, bytes: &[u8]) {
        self.connections()[0].push.as_ref().expect("a connection").send(bytes.to_vec()).expect("the connection is open");
    }
}

/// A connection's answers and the bytes the test pushes on it.
struct Conversation {
    answers: Answers,
    pushed: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
}

/// `Connection.answer`: answers every message at the start of what is pending; bytes that can begin none are dropped.
fn answer_pending(pending: &mut Vec<u8>, answers: &Answers, how: &str, seen: &Recorder) -> Vec<u8> {
    let could_begin = |bytes: &[u8]| answers.iter().any(|(m, _)| m.starts_with(bytes) || bytes.starts_with(m));
    let mut replies = Vec::new();
    let mut start = 0;
    let mut progress = true;
    while progress && start < pending.len() {
        progress = false;
        let rest = &pending[start..];
        if let Some((message, answer)) = answers.iter().find(|(m, _)| rest.starts_with(m)) {
            seen.update(|s| s.messages.push(format!("{how} {}", hex(message))));
            replies.extend_from_slice(answer);
            start += message.len();
            progress = true;
        } else if !could_begin(rest) {
            // skipped up to where a message it knows could begin
            let mut skip = 1;
            while skip < rest.len() && !could_begin(&rest[skip..]) {
                skip += 1;
            }
            seen.update(|s| s.messages.push(format!("{} unanswered {}", how.to_lowercase(), hex(&rest[..skip]))));
            start += skip;
            progress = true;
        }
    }
    pending.drain(..start);
    replies
}

async fn answer_each<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(stream: &mut S, how: &str, mut pending: Vec<u8>, conversation: &mut Conversation, seen: &Recorder) {
    let mut buf = vec![0u8; 16 * 1024];
    let tls = how == "TLS";
    let mut replies = answer_pending(&mut pending, &conversation.answers, how, seen);
    loop {
        if !replies.is_empty() && (stream.write_all(&replies).await.is_err() || stream.flush().await.is_err()) {
            return;
        }
        replies.clear();
        tokio::select! {
            read = stream.read(&mut buf) => {
                let n = match read {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };
                seen.update(|s| if tls { s.over_tls.extend_from_slice(&buf[..n]) } else { s.in_the_clear.extend_from_slice(&buf[..n]) });
                pending.extend_from_slice(&buf[..n]);
                replies = answer_pending(&mut pending, &conversation.answers, how, seen);
            }
            pushed = conversation.pushed.recv() => match pushed {
                Some(bytes) => replies = bytes,
                None => std::future::pending::<()>().await,
            },
        }
    }
}

async fn converse(mut tcp: TcpStream, acceptor: tokio_rustls::TlsAcceptor, options: StartTlsOptions, mut conversation: Conversation, seen: &Recorder) {
    let mut pending = Vec::new();
    if !options.tls_from_the_start {
        // read only as far as it takes to tell whether the connection opens with an SSLRequest
        while pending.len() < SSL_REQUEST.len() && SSL_REQUEST.starts_with(&pending) {
            let mut buf = [0u8; 8];
            let wanted = SSL_REQUEST.len() - pending.len();
            let n = match tcp.read(&mut buf[..wanted]).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };
            pending.extend_from_slice(&buf[..n]);
            seen.update(|s| s.in_the_clear.extend_from_slice(&buf[..n]));
        }
        if pending != SSL_REQUEST {
            return answer_each(&mut tcp, "clear", pending, &mut conversation, seen).await;
        }
        seen.update(|s| s.messages.push(format!("clear {}", hex(&SSL_REQUEST))));
        pending.clear();
        let go_ahead = if options.refuse_tls { b'N' } else { b'S' };
        if tcp.write_all(&[go_ahead]).await.is_err() {
            return;
        }
        if options.refuse_tls {
            return answer_each(&mut tcp, "clear", pending, &mut conversation, seen).await;
        }
    }
    let Ok(mut tls) = acceptor.accept(tcp).await else { return };
    let (_, session) = tls.get_ref();
    let name = session.server_name().map(str::to_string);
    let issuer = session.peer_certificates().and_then(|chain| chain.first()).map(|cert| {
        let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
        parsed.issuer().to_string()
    });
    seen.update(|s| {
        s.server_names.extend(name.clone());
        s.client_certificate_issuer = issuer.clone();
    });
    answer_each(&mut tls, "TLS", pending, &mut conversation, seen).await;
}

/// `BinaryPersistentRelayIntegrationTest.shouldRelayMoreThanOneReadEachWayWholeAndInOrder`: 2 MiB echoed back
/// through the relay while the client is still sending, whole and in order, on one upstream connection.
#[tokio::test(flavor = "multi_thread")]
async fn should_relay_more_than_one_read_each_way_whole_and_in_order() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = connections.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut reader, mut writer) = socket.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    let server = forwarding_to(upstream_port, &[("logLevel", "INFO")]).await;
    let byte_at = |position: usize| (position.wrapping_mul(31).wrapping_add(position >> 11)) as u8;
    let length = 2 * 1024 * 1024;
    let (mut reader, mut writer) = connect(server.port).await.into_split();
    let sending = tokio::spawn(async move {
        let mut sent = 0;
        while sent < length {
            let size = (length - sent).min(70_000);
            let chunk: Vec<u8> = (sent..sent + size).map(byte_at).collect();
            writer.write_all(&chunk).await.unwrap();
            sent += size;
        }
        writer
    });
    let mut received = 0;
    let mut buf = vec![0u8; 64 * 1024];
    while received < length {
        let n = tokio::time::timeout(Duration::from_secs(20), reader.read(&mut buf)).await.expect("more within 20 s").unwrap();
        assert_ne!(n, 0, "the connection stays open until everything is back, got {received}");
        let out_of_order = (0..n).find(|i| buf[*i] != byte_at(received + i));
        assert_eq!(out_of_order, None, "every byte came back in the order it was sent, from {received}");
        received += n;
    }
    tokio::time::timeout(Duration::from_secs(20), sending).await.unwrap().unwrap();
    assert_eq!(connections.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// `BinaryRelayEndOfConnectionIntegrationTest.shouldCloseTheUpstreamConnectionWithinTheLingerLimitWhenTheClientLeavesAndTheUpstreamNeverReads`.
#[tokio::test(flavor = "multi_thread")]
async fn should_close_the_upstream_connection_within_the_linger_limit_when_the_client_leaves_and_the_upstream_never_reads() {
    let upstream = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    upstream.set_recv_buffer_size(16 * 1024).unwrap();
    upstream.bind(&std::net::SocketAddr::from(([127, 0, 0, 1], 0)).into()).unwrap();
    upstream.listen(50).unwrap();
    let upstream: std::net::TcpListener = upstream.into();
    let upstream_port = upstream.local_addr().unwrap().port();
    let server = forwarding_to(upstream_port, &[("logLevel", "WARN"), ("responseWriteStallTimeoutMillis", "300000")]).await;
    let accepted = std::thread::spawn(move || upstream.accept().unwrap().0);
    let client = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    client.set_send_buffer_size(16 * 1024).unwrap();
    client.connect(&std::net::SocketAddr::from(([127, 0, 0, 1], server.port)).into()).unwrap();
    let client: std::net::TcpStream = client.into();
    let flooded = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter = flooded.clone();
    let mut writer = client.try_clone().unwrap();
    std::thread::spawn(move || {
        use std::io::Write;
        let chunk = vec![b'x'; 16 * 1024];
        while writer.write_all(&chunk).is_ok() {
            counter.fetch_add(chunk.len() as u64, std::sync::atomic::Ordering::SeqCst);
        }
    });
    let mut upstream_end = accepted.join().unwrap();
    // `awaitStalled`
    let (mut last, mut stable_since) = (u64::MAX, std::time::Instant::now());
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(std::time::Instant::now() < deadline, "the client's writes never stopped going through");
        let now = flooded.load(std::sync::atomic::Ordering::SeqCst);
        if now != last {
            (last, stable_since) = (now, std::time::Instant::now());
        } else if now > 0 && stable_since.elapsed() > Duration::from_secs(1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    socket2::SockRef::from(&client).set_linger(Some(Duration::ZERO)).unwrap();
    client.shutdown(std::net::Shutdown::Both).ok();
    drop(client);
    let closed = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while std::time::Instant::now() < deadline {
            if upstream_end.write_all(b"u").and_then(|_| upstream_end.flush()).is_err() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    })
    .await
    .unwrap();
    assert!(closed, "the upstream's connection was closed within 20 seconds");
}

/// `BinaryPersistentRelayIntegrationTest.shouldNeverSendUpstreamInTheClearWhatAClientSendsAfterTurningTlsOn`: the
/// upstream answers the SSLRequest and then only reads; MockServer answers the client's handshake itself.
#[tokio::test(flavor = "multi_thread")]
async fn should_never_send_upstream_in_the_clear_what_a_client_sends_after_turning_tls_on() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let all = received.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let index = {
                let mut all = all.lock().unwrap();
                all.push(Vec::new());
                all.len() - 1
            };
            let all = all.clone();
            tokio::spawn(async move {
                let mut first = [0u8; 8];
                if socket.read_exact(&mut first).await.is_err() {
                    return;
                }
                all.lock().unwrap()[index].extend_from_slice(&first);
                if first == SSL_REQUEST {
                    let _ = socket.write_all(b"S").await;
                }
                let mut buf = [0u8; 4096];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    all.lock().unwrap()[index].extend_from_slice(&buf[..n]);
                }
            });
        }
    });
    let server = forwarding_to(upstream_port, &[("logLevel", "INFO")]).await;
    let mut client = connect(server.port).await;
    client.write_all(&SSL_REQUEST).await.unwrap();
    assert_eq!(read_exactly(&mut client, 1).await, b"S", "the upstream's go-ahead is relayed");
    let mut tls = start_tls(client, None).await.expect("MockServer answers the client's handshake");
    tls.write_all(b"secret startup message").await.unwrap();
    tls.flush().await.unwrap();
    let handshake_follows = || received.lock().unwrap().first().is_some_and(|r| r.len() > SSL_REQUEST.len() && r[SSL_REQUEST.len()] == 22);
    assert!(common::eventually(handshake_follows).await, "a TLS handshake follows on the same connection");
    let received = received.lock().unwrap().clone();
    assert_eq!(received.len(), 1, "and no other connection is opened");
    assert!(!String::from_utf8_lossy(&received[0]).contains("secret startup message"));
}

/// `BinaryInBandTlsUpgradeProxyIntegrationTest.shouldPresentMockServersClientCertificateToAnUpstreamThatRequiresOne`.
#[tokio::test(flavor = "multi_thread")]
async fn should_present_mock_servers_client_certificate_to_an_upstream_that_requires_one() {
    let upstream = StartTlsUpstream::start(StartTlsOptions { require_client_certificate: true, ..Default::default() }).await;
    let server = forwarding_to(upstream.port, &[]).await;
    let mut client = connect(server.port).await;
    exchange(&mut client, &SSL_REQUEST, b"S").await;
    let mut tls = start_tls(client, None).await.unwrap();
    exchange(&mut tls, &STARTUP, &AUTHENTICATION_OK_AND_READY).await;
    let issuer = upstream.await_connection().await.client_certificate_issuer.expect("a client certificate");
    assert!(issuer.contains("MockServer"), "{issuer}");
}

/// `BinaryInBandTlsUpgradeProxyIntegrationTest.shouldUpgradeTheUpstreamWhenTheFirstMessageOverTlsIsAnsweredLocally`.
#[tokio::test(flavor = "multi_thread")]
async fn should_upgrade_the_upstream_when_the_first_message_over_tls_is_answered_locally() {
    let answered_locally = [b'R', 0, 0, 0, 8, 0, 0, 0, 3];
    let upstream = StartTlsUpstream::start(StartTlsOptions::default()).await;
    let server = forwarding_to(upstream.port, &[("matchBinaryExpectationsWhenProxying", "true")]).await;
    use base64::Engine;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    common::expect(server.port, &json!({"httpRequest": {"binaryData": b64(&STARTUP)}, "binaryResponse": {"binaryData": b64(&answered_locally)}})).await;
    let mut client = connect(server.port).await;
    exchange(&mut client, &SSL_REQUEST, b"S").await;
    let mut tls = start_tls(client, None).await.unwrap();
    exchange(&mut tls, &STARTUP, &answered_locally).await;
    exchange(&mut tls, &QUERY, &READY).await;
    let connection = upstream.await_connection().await;
    assert_eq!(upstream.connections().len(), 1);
    assert_eq!(hex(&connection.in_the_clear), hex(&SSL_REQUEST), "only the SSLRequest in the clear");
    assert_eq!(connection.messages, vec![format!("clear {}", hex(&SSL_REQUEST)), format!("TLS {}", hex(&QUERY))]);
}

/// `BinaryInBandTlsUpgradeProxyIntegrationTest.shouldCloseBothConnectionsWhenTheClientStartsTlsAfterTheUpstreamRefusedIt`.
#[tokio::test(flavor = "multi_thread")]
async fn should_close_both_connections_when_the_client_starts_tls_after_the_upstream_refused_it() {
    let upstream = StartTlsUpstream::start(StartTlsOptions { refuse_tls: true, ..Default::default() }).await;
    let server = forwarding_to(upstream.port, &[("socketConnectionTimeoutInMillis", "3000")]).await;
    let mut client = connect(server.port).await;
    exchange(&mut client, &SSL_REQUEST, b"N").await;
    let outcome = match start_tls(client, None).await {
        Ok(mut tls) => {
            let _ = tls.write_all(&STARTUP).await;
            let _ = tls.flush().await;
            read_after_close(&mut tls).await
        }
        Err(_) => "closed".into(),
    };
    assert_eq!(outcome, "closed");
    assert!(upstream.await_ended().await, "the upstream connection is ended");
    let connection = upstream.connections()[0].clone();
    assert!(connection.messages[1].contains("clear unanswered 16"), "it saw MockServer's handshake in the clear: {:?}", connection.messages);
    assert_eq!(connection.in_the_clear[..SSL_REQUEST.len()], SSL_REQUEST);
    assert!(!hex(&connection.in_the_clear).contains(&hex(&STARTUP)));
}

/// `BinaryTlsFromTheStartProxyIntegrationTest.shouldNameAnUpstreamGivenAsAnAddressAsTheClientNamedMockServer`.
#[tokio::test(flavor = "multi_thread")]
async fn should_name_an_upstream_given_as_an_address_as_the_client_named_mock_server() {
    let upstream = StartTlsUpstream::start(StartTlsOptions { tls_from_the_start: true, ..Default::default() }).await;
    let server = forwarding_to(upstream.port, &[]).await;
    let mut tls = start_tls(connect(server.port).await, Some("db.example.test")).await.unwrap();
    exchange(&mut tls, &STARTUP, &AUTHENTICATION_OK_AND_READY).await;
    assert_eq!(upstream.await_connection().await.server_names, vec!["db.example.test".to_string()]);
}

/// `BinaryTlsFromTheStartProxyIntegrationTest.shouldAnswerAMatchedMessageAndRelayTheRestOverTlsOnOneUpstreamConnection`.
#[tokio::test(flavor = "multi_thread")]
async fn should_answer_a_matched_message_and_relay_the_rest_over_tls_on_one_upstream_connection() {
    let answered_locally = [b'R', 0, 0, 0, 8, 0, 0, 0, 3];
    let upstream = StartTlsUpstream::start(StartTlsOptions { tls_from_the_start: true, ..Default::default() }).await;
    let server = forwarding_to(upstream.port, &[("matchBinaryExpectationsWhenProxying", "true"), ("logLevel", "DEBUG")]).await;
    use base64::Engine;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    common::expect(server.port, &json!({"httpRequest": {"binaryData": b64(&QUERY)}, "binaryResponse": {"binaryData": b64(&answered_locally)}})).await;
    let mut tls = start_tls(connect(server.port).await, None).await.unwrap();
    exchange(&mut tls, &STARTUP, &AUTHENTICATION_OK_AND_READY).await;
    exchange(&mut tls, &QUERY, &answered_locally).await;
    exchange(&mut tls, &SYNC, &READY).await;
    let connection = upstream.await_connection().await;
    assert_eq!(upstream.connections().len(), 1);
    assert_eq!(connection.messages, vec![format!("TLS {}", hex(&STARTUP)), format!("TLS {}", hex(&SYNC))]);
    assert!(!common::logs(server.port).await.contains("binary expectations are not matched"), "matching applies to this connection");
}

/// `BinaryServerFirstIntegrationTest.shouldRelayTheGreetingOfAServerThatSpeaksFirstToAClientThatSendsNothing`.
#[tokio::test(flavor = "multi_thread")]
async fn should_relay_the_greeting_of_a_server_that_speaks_first_to_a_client_that_sends_nothing() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = listener.local_addr().unwrap().port();
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = connections.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let (reader, mut writer) = socket.into_split();
                let _ = writer.write_all(b"220 ready\n").await;
                let mut lines = tokio::io::BufReader::new(reader);
                let mut line = String::new();
                while tokio::io::AsyncBufReadExt::read_line(&mut lines, &mut line).await.is_ok_and(|n| n > 0) {
                    let _ = writer.write_all(format!("250 {line}").as_bytes()).await;
                    line.clear();
                }
            });
        }
    });
    let server = forwarding_to(upstream_port, &[("forwardBinaryServerFirstWaitMillis", "200")]).await;
    let mut client = connect(server.port).await;
    assert_eq!(read_exactly(&mut client, 10).await, b"220 ready\n", "the client has sent nothing");
    exchange(&mut client, b"HELO client\n", b"250 HELO client\n").await;
    exchange(&mut client, b"NOOP\n", b"250 NOOP\n").await;
    assert_eq!(connections.load(std::sync::atomic::Ordering::SeqCst), 1, "the whole session is on the connection the greeting came on");
}

/// The text log's entries after the last `received binary request` (`entriesAfterTheMessagesRecord`).
async fn entries_after_the_last_received(port: u16) -> Vec<String> {
    // `retrieveLogMessagesArray`: the text log split at `HttpState.LOG_SEPARATOR`
    let text = common::logs(port).await;
    let logged: Vec<String> = text.split("\n------------------------------------\n").map(str::to_string).collect();
    let last = logged.iter().rposition(|e| e.contains("received binary request")).expect("the message's own record");
    logged[last + 1..].to_vec()
}

/// `BinaryRelayThroughUpstreamProxyIntegrationTest.shouldNotTunnelToADestinationThatMayNotBeForwardedTo`.
#[tokio::test(flavor = "multi_thread")]
async fn should_not_tunnel_to_a_destination_that_may_not_be_forwarded_to() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = asked.clone();
    tokio::spawn(async move {
        while proxy.accept().await.is_ok() {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    let upstream = StartTlsUpstream::start(StartTlsOptions::default()).await;
    let socks = format!("127.0.0.1:{proxy_port}");
    let server = forwarding_to(upstream.port, &[("forwardSocksProxy", &socks), ("forwardProxyBlockPrivateNetworks", "true")]).await;
    let mut client = connect(server.port).await;
    client.write_all(&STARTUP).await.unwrap();
    assert_eq!(read_after_close(&mut client).await, "closed", "the client is closed");
    assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 0, "nothing asked of the proxy");
    assert!(upstream.connections().is_empty(), "nothing reached the upstream");
}

/// `ConnectProxy`: a `forwardHttpsProxy` answering each `CONNECT` with a `200` whose header line is `size` bytes,
/// then tunnelling.
async fn connect_proxy(size: Arc<std::sync::atomic::AtomicUsize>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let size = size.load(std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if socket.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let authority = text.split(' ').nth(1).unwrap_or_default().to_string();
                // "x-proxy: " is 9 bytes
                let answer = format!("HTTP/1.1 200 Connection established\r\nx-proxy: {}\r\n\r\n", "a".repeat(size - 9));
                if socket.write_all(answer.as_bytes()).await.is_err() {
                    return;
                }
                let Ok(mut target) = TcpStream::connect(authority).await else { return };
                let _ = tokio::io::copy_bidirectional(&mut socket, &mut target).await;
            });
        }
    });
    port
}

/// `TlsEchoUpstream`: each message read over TLS answered `echo:` and the message.
async fn tls_echo_upstream(messages: Arc<Mutex<Vec<String>>>) -> u16 {
    use rustls_pki_types::pem::PemObject;
    let chain = rustls_pki_types::CertificateDer::pem_file_iter(tls_file("leaf-cert.pem")).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(tls_file("leaf-key-pkcs8.pem")).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(chain, key).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, messages) = (acceptor.clone(), messages.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let mut buf = [0u8; 1024];
                while let Ok(n) = tls.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                    let message = String::from_utf8_lossy(&buf[..n]).into_owned();
                    messages.lock().unwrap().push(message.clone());
                    if tls.write_all(format!("echo:{message}").as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

/// `send(mockServer)`: the message over TLS, and what comes back (nothing when the connection is closed instead).
async fn send_over_tls(port: u16) -> String {
    const MESSAGE: &str = "Hello not world!\n";
    let mut tls = start_tls(connect(port).await, None).await.unwrap();
    tls.write_all(MESSAGE.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
    let expected = "echo:".len() + MESSAGE.len();
    let mut received = Vec::new();
    let mut buf = [0u8; 256];
    while received.len() < expected {
        match tokio::time::timeout(Duration::from_secs(15), tls.read(&mut buf)).await.expect("no read waits 15 s") {
            Ok(n) if n > 0 => received.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&received).into_owned()
}

/// `assertRefusedOnce`: after the refused message's own record, the refusal is the only entry.
async fn assert_refused_once(port: u16, limit: usize) {
    let entries = entries_after_the_last_received(port).await;
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert!(entries[0].contains("failing forward"), "{}", entries[0]);
    assert!(entries[0].contains(&format!("the upstream proxy's CONNECT response headers are larger than maxHeaderSize ({limit} bytes)")), "{}", entries[0]);
}

/// `BinaryForwardConnectHeaderLimitIntegrationTest.shouldLimitTheConnectResponseByAMaxHeaderSizeBelowTheDefault`;
/// `shouldReadAConnectResponseOverTheDefaultWhenMaxHeaderSizeIsAboveIt` differs only in the limit.
#[tokio::test(flavor = "multi_thread")]
async fn should_limit_the_connect_response_by_max_header_size_and_log_a_refusal_once() {
    const SMALL_LIMIT: usize = 16 * 1024;
    let size = Arc::new(std::sync::atomic::AtomicUsize::new(SMALL_LIMIT));
    let messages: Arc<Mutex<Vec<String>>> = Arc::default();
    let upstream_port = tls_echo_upstream(messages.clone()).await;
    let proxy = format!("127.0.0.1:{}", connect_proxy(size.clone()).await);
    let limit = SMALL_LIMIT.to_string();
    let common_properties = [("logLevel", "WARN"), ("forwardHttpsProxy", proxy.as_str()), ("maxHeaderSize", limit.as_str())];
    let small = forwarding_to(upstream_port, &common_properties).await;

    assert_eq!(send_over_tls(small.port).await, "echo:Hello not world!\n", "a CONNECT answer at the limit");
    size.store(SMALL_LIMIT + 1, std::sync::atomic::Ordering::SeqCst);
    messages.lock().unwrap().clear();
    let started = std::time::Instant::now();
    assert_eq!(send_over_tls(small.port).await, "", "closed with no answer");
    assert!(started.elapsed() < Duration::from_secs(5), "without waiting out the proxy connect timeout");
    assert_refused_once(small.port, SMALL_LIMIT).await;
    assert!(messages.lock().unwrap().is_empty(), "nothing was forwarded");
}

// `BinaryResponseUpstreamIntegrationTest`: a binary expectation's `upstream` on a connection relayed to a
// PostgreSQL-like upstream. Its six cases that do not pass on rs-process unmodified: two did not at first,
// four assert on the in-JVM server's log entries (`skips/in-jvm/`), read here from the event log.

const MOCKED_QUERY: [u8; 14] = [b'Q', 0, 0, 0, 13, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'2', 0];
// the upstream's reply to MOCKED_QUERY, which it sends in two parts: a RowDescription, then a DataRow onwards
const UPSTREAM_ROWS: [u8; 7] = [b'T', 0, 0, 0, 6, 0, 0];
const UPSTREAM_REST: [u8; 27] = [b'D', 0, 0, 0, 6, 0, 0, b'C', 0, 0, 0, 13, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'2', 0, b'Z', 0, 0, 0, 5, b'I'];
const CANNED: [u8; 20] = [b'C', 0, 0, 0, 13, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'9', 0, b'Z', 0, 0, 0, 5, b'I'];

/// `postgresqlFraming()`.
const POSTGRESQL_FRAMING: &[(&str, &str)] = &[("logLevel", "INFO"), ("matchBinaryExpectationsWhenProxying", "true"), ("binaryMessageFraming", "POSTGRESQL")];

/// `postgresLikeUpstream()`.
async fn postgres_like_upstream() -> StartTlsUpstream {
    StartTlsUpstream::answering(StartTlsOptions::default(), &[(&STARTUP, &AUTHENTICATION_OK_AND_READY), (&QUERY, &READY), (&MOCKED_QUERY, &UPSTREAM_ROWS)]).await
}

/// `mock(request, binaryResponse(reply).withUpstream(upstream)[.withDelay(milliseconds(delay))])`.
async fn mock_upstream(port: u16, request: &[u8], reply: &[u8], upstream: &str, delay_millis: u64) {
    use base64::Engine;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let mut response = json!({"binaryData": b64(reply), "upstream": upstream});
    if delay_millis > 0 {
        response["delay"] = json!({"timeUnit": "MILLISECONDS", "value": delay_millis});
    }
    common::expect(port, &json!({"httpRequest": {"binaryData": b64(request)}, "binaryResponse": response})).await;
}

async fn send_all(client: &mut TcpStream, messages: &[&[u8]]) {
    client.write_all(&messages.concat()).await.unwrap();
    client.flush().await.unwrap();
}

async fn expect_bytes<S: tokio::io::AsyncRead + Unpin>(client: &mut S, expected: &[u8]) {
    assert_eq!(hex(&read_exactly(client, expected.len()).await), hex(expected));
}

/// How many of the event log's entries contain `containing`.
async fn logged(port: u16, containing: &str) -> usize {
    common::logs(port).await.split("\n------------------------------------\n").filter(|entry| entry.contains(containing)).count()
}

async fn await_logged(port: u16, containing: &str, count: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let found = logged(port, containing).await;
        if found >= count {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "expected {count} log entries containing {containing:?} but found {found}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn expect_nothing_for(client: &mut TcpStream, millis: u64) {
    let mut one = [0u8; 1];
    if let Ok(read) = tokio::time::timeout(Duration::from_millis(millis), client.read(&mut one)).await {
        panic!("expected nothing, but read {read:?} {}", one[0]);
    }
}

/// `BinaryResponseUpstreamIntegrationTest.shouldAnswerForwardAndDropTheUpstreamsReplyAcrossReadsWhenAnswerAndForward`.
#[tokio::test(flavor = "multi_thread")]
async fn should_answer_forward_and_drop_the_upstreams_reply_across_reads_when_answer_and_forward() {
    let upstream = postgres_like_upstream().await;
    let server = forwarding_to(upstream.port, POSTGRESQL_FRAMING).await;
    mock_upstream(server.port, &MOCKED_QUERY, &CANNED, "ANSWER_AND_FORWARD", 0).await;
    let mut client = connect(server.port).await;

    exchange(&mut client, &STARTUP, &AUTHENTICATION_OK_AND_READY).await;
    exchange(&mut client, &MOCKED_QUERY, &CANNED).await;
    upstream.await_message(&format!("clear {}", hex(&MOCKED_QUERY))).await;
    await_logged(server.port, "dropping binary response", 1).await;
    upstream.push(&UPSTREAM_REST);
    await_logged(server.port, "dropping binary response", 2).await;

    // neither part of the upstream's reply reached the client: the next bytes are the next query's reply
    exchange(&mut client, &QUERY, &READY).await;
    assert_eq!(upstream.connections()[0].messages, [format!("clear {}", hex(&STARTUP)), format!("clear {}", hex(&MOCKED_QUERY)), format!("clear {}", hex(&QUERY))]);
}

/// `BinaryResponseUpstreamIntegrationTest.shouldNotWarnThatADelayedAnswerOvertakesTheMessageForwardedForIt`.
#[tokio::test(flavor = "multi_thread")]
async fn should_not_warn_that_a_delayed_answer_overtakes_the_message_forwarded_for_it() {
    let upstream = StartTlsUpstream::answering(StartTlsOptions::default(), &[(&STARTUP, &AUTHENTICATION_OK_AND_READY), (&QUERY, &READY)]).await;
    let server = forwarding_to(upstream.port, POSTGRESQL_FRAMING).await;
    mock_upstream(server.port, &MOCKED_QUERY, &CANNED, "ANSWER_AND_FORWARD", 200).await;
    let mut client = connect(server.port).await;

    exchange(&mut client, &STARTUP, &AUTHENTICATION_OK_AND_READY).await;
    exchange(&mut client, &MOCKED_QUERY, &CANNED).await;

    // the forwarded message has had no reply yet, but it is the answered message itself, not one it overtook
    assert_eq!(logged(server.port, "may reach the client out of order").await, 0);
    // the upstream replies only to a message it has received: the connection exists since the startup, so waiting for
    // it would let the pushed reply come before the forwarded message was written (a race under load): the startup
    // and the forwarded query are the two messages it records
    assert!(common::eventually(|| upstream.connections().first().is_some_and(|c| c.messages.len() >= 2)).await, "the upstream never received the forwarded message");
    upstream.push(&UPSTREAM_ROWS);
    upstream.push(&UPSTREAM_REST);
    exchange(&mut client, &QUERY, &READY).await;
}

/// `BinaryResponseUpstreamIntegrationTest.shouldForwardAndWriteTheReplacementOnceTheUpstreamsReplyHasEndedWhenForwardAndReplace`.
#[tokio::test(flavor = "multi_thread")]
async fn should_forward_and_write_the_replacement_once_the_upstreams_reply_has_ended_when_forward_and_replace() {
    let upstream = postgres_like_upstream().await;
    let server = forwarding_to(upstream.port, POSTGRESQL_FRAMING).await;
    mock_upstream(server.port, &MOCKED_QUERY, &CANNED, "FORWARD_AND_REPLACE", 0).await;
    let mut client = connect(server.port).await;

    exchange(&mut client, &STARTUP, &AUTHENTICATION_OK_AND_READY).await;
    send_all(&mut client, &[&MOCKED_QUERY]).await;
    upstream.await_connection().await;
    await_logged(server.port, "dropping binary response", 1).await;
    expect_nothing_for(&mut client, 300).await;
    upstream.push(&UPSTREAM_REST);
    expect_bytes(&mut client, &CANNED).await;

    exchange(&mut client, &QUERY, &READY).await;
    assert_eq!(upstream.connections()[0].messages, [format!("clear {}", hex(&STARTUP)), format!("clear {}", hex(&MOCKED_QUERY)), format!("clear {}", hex(&QUERY))]);
    assert_eq!(logged(server.port, "in place of the response from").await, 1);
}

/// `BinaryResponseUpstreamIntegrationTest.shouldHoldTheUpstreamsLaterRepliesBehindADelayedReplacement`.
#[tokio::test(flavor = "multi_thread")]
async fn should_hold_the_upstreams_later_replies_behind_a_delayed_replacement() {
    let upstream = StartTlsUpstream::answering(StartTlsOptions::default(), &[(&STARTUP, &AUTHENTICATION_OK_AND_READY), (&QUERY, &READY), (&MOCKED_QUERY, &CANNED)]).await;
    let server = forwarding_to(upstream.port, POSTGRESQL_FRAMING).await;
    let replacement = [b'C', 0, 0, 0, 13, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'7', 0, b'Z', 0, 0, 0, 5, b'T'];
    mock_upstream(server.port, &MOCKED_QUERY, &replacement, "FORWARD_AND_REPLACE", 500).await;
    let mut client = connect(server.port).await;

    exchange(&mut client, &STARTUP, &AUTHENTICATION_OK_AND_READY).await;
    let sent = std::time::Instant::now();
    send_all(&mut client, &[&MOCKED_QUERY, &QUERY]).await;

    expect_bytes(&mut client, &replacement).await;
    assert!(sent.elapsed() >= Duration::from_millis(450), "{:?}", sent.elapsed());
    expect_bytes(&mut client, &READY).await;
}

/// `BinaryResponseUpstreamIntegrationTest.shouldReplaceAReplyOverTlsAfterRelayingTheSslRequestsOneByteAnswer`.
#[tokio::test(flavor = "multi_thread")]
async fn should_replace_a_reply_over_tls_after_relaying_the_ssl_requests_one_byte_answer() {
    let upstream = postgres_like_upstream().await;
    let server = forwarding_to(upstream.port, POSTGRESQL_FRAMING).await;
    mock_upstream(server.port, &MOCKED_QUERY, &CANNED, "FORWARD_AND_REPLACE", 0).await;
    let mut client = connect(server.port).await;

    exchange(&mut client, &SSL_REQUEST, b"S").await;
    let mut tls = start_tls(client, None).await.unwrap();
    exchange(&mut tls, &STARTUP, &AUTHENTICATION_OK_AND_READY).await;
    tls.write_all(&MOCKED_QUERY).await.unwrap();
    tls.flush().await.unwrap();
    upstream.await_connection().await;
    await_logged(server.port, "dropping binary response", 1).await;
    upstream.push(&UPSTREAM_REST);
    expect_bytes(&mut tls, &CANNED).await;
    exchange(&mut tls, &QUERY, &READY).await;

    assert_eq!(upstream.connections()[0].messages, [format!("clear {}", hex(&SSL_REQUEST)), format!("TLS {}", hex(&STARTUP)), format!("TLS {}", hex(&MOCKED_QUERY)), format!("TLS {}", hex(&QUERY))]);
}

/// `BinaryResponseUpstreamIntegrationTest.shouldAnswerWithoutForwardingAndWarnOnceWithoutPostgresqlFraming`.
#[tokio::test(flavor = "multi_thread")]
async fn should_answer_without_forwarding_and_warn_once_without_postgresql_framing() {
    let upstream = postgres_like_upstream().await;
    let server = forwarding_to(upstream.port, &[("logLevel", "INFO"), ("matchBinaryExpectationsWhenProxying", "true")]).await;
    mock_upstream(server.port, &MOCKED_QUERY, &CANNED, "FORWARD_AND_REPLACE", 0).await;
    let mut client = connect(server.port).await;

    exchange(&mut client, &STARTUP, &AUTHENTICATION_OK_AND_READY).await;
    exchange(&mut client, &MOCKED_QUERY, &CANNED).await;
    exchange(&mut client, &MOCKED_QUERY, &CANNED).await;
    exchange(&mut client, &QUERY, &READY).await;

    assert_eq!(upstream.await_connection().await.messages, [format!("clear {}", hex(&STARTUP)), format!("clear {}", hex(&QUERY))]);
    assert_eq!(logged(server.port, "as ANSWER_ONLY where binary expectation").await, 1);
}

// `BinaryRelayThroughUpstreamProxyIntegrationTest`'s `forwardHttpProxy` cases (9.1.0, upstream 64b856d9d):
// a binary connection whose only upstream proxy is `forwardHttpProxy` is relayed through a `CONNECT` tunnel.

/// `RecordingUpstreamProxy(CONNECT)`: each `CONNECT` tunnelled to its target and recorded (`destinations`), or, when
/// credentials are required and the `proxy-authorization` header does not carry them, answered `407` and recorded as
/// refused.
struct RecordingConnectProxy {
    port: u16,
    destinations: Arc<Mutex<Vec<String>>>,
    refused: Arc<Mutex<Vec<String>>>,
}

async fn recording_connect_proxy(credentials: Option<(&str, &str)>) -> RecordingConnectProxy {
    use base64::Engine;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    type Seen = Arc<Mutex<Vec<String>>>;
    let (destinations, refused): (Seen, Seen) = Default::default();
    let required = credentials.map(|(user, password)| format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))));
    let (d, r) = (destinations.clone(), refused.clone());
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let (d, r, required) = (d.clone(), r.clone(), required.clone());
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if socket.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let authority = text.split(' ').nth(1).unwrap_or_default().to_string();
                let authorization = text.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("proxy-authorization").then(|| value.trim().to_string())
                });
                if required.is_some() && authorization != required {
                    r.lock().unwrap().push(authority);
                    let _ = socket.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nproxy-authenticate: Basic realm=\"proxy\"\r\ncontent-length: 0\r\n\r\n").await;
                    return;
                }
                d.lock().unwrap().push(authority.clone());
                if socket.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_err() {
                    return;
                }
                let Ok(mut target) = TcpStream::connect(authority).await else { return };
                let _ = tokio::io::copy_bidirectional(&mut socket, &mut target).await;
            });
        }
    });
    RecordingConnectProxy { port, destinations, refused }
}

/// The three messages of `runSession`, each answered.
async fn run_session<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(client: &mut S) {
    exchange(client, &STARTUP, &AUTHENTICATION_OK_AND_READY).await;
    exchange(client, &QUERY, &READY).await;
    exchange(client, &SYNC, &READY).await;
}

fn session_messages(how: &str) -> Vec<String> {
    [&STARTUP[..], &QUERY[..], &SYNC[..]].iter().map(|m| format!("{how} {}", hex(m))).collect()
}

/// `shouldRelayASessionOnOneConnectionTunnelledWithConnectThroughForwardHttpProxy`.
#[tokio::test(flavor = "multi_thread")]
async fn should_relay_a_session_on_one_connection_tunnelled_with_connect_through_forward_http_proxy() {
    let proxy = recording_connect_proxy(None).await;
    let upstream = StartTlsUpstream::start(StartTlsOptions::default()).await;
    let address = format!("127.0.0.1:{}", proxy.port);
    let server = forwarding_to(upstream.port, &[("forwardHttpProxy", &address)]).await;
    let mut client = connect(server.port).await;
    run_session(&mut client).await;
    let connection = upstream.await_connection().await;
    assert_eq!(upstream.connections().len(), 1, "one upstream connection for the session");
    assert_eq!(connection.messages, session_messages("clear"));
    assert_eq!(*proxy.destinations.lock().unwrap(), vec![format!("127.0.0.1:{}", upstream.port)], "one tunnel, to the target");
}

/// `shouldSendTheForwardProxyCredentialsWithTheConnectThroughForwardHttpProxy`.
#[tokio::test(flavor = "multi_thread")]
async fn should_send_the_forward_proxy_credentials_with_the_connect_through_forward_http_proxy() {
    let proxy = recording_connect_proxy(Some(("proxy-user", "proxy-password"))).await;
    let upstream = StartTlsUpstream::start(StartTlsOptions::default()).await;
    let address = format!("127.0.0.1:{}", proxy.port);
    let server = forwarding_to(
        upstream.port,
        &[("forwardHttpProxy", &address), ("forwardProxyAuthenticationUsername", "proxy-user"), ("forwardProxyAuthenticationPassword", "proxy-password")],
    )
    .await;
    let mut client = connect(server.port).await;
    run_session(&mut client).await;
    assert_eq!(upstream.await_connection().await.messages, session_messages("clear"));
    assert_eq!(*proxy.destinations.lock().unwrap(), vec![format!("127.0.0.1:{}", upstream.port)]);
    assert!(proxy.refused.lock().unwrap().is_empty());
}

/// `shouldCloseTheClientAndSayWhyWhenForwardHttpProxyRefusesTheTunnel`.
#[tokio::test(flavor = "multi_thread")]
async fn should_close_the_client_and_say_why_when_forward_http_proxy_refuses_the_tunnel() {
    let proxy = recording_connect_proxy(Some(("proxy-user", "proxy-password"))).await;
    let upstream = StartTlsUpstream::start(StartTlsOptions::default()).await;
    let address = format!("127.0.0.1:{}", proxy.port);
    let server = forwarding_to(upstream.port, &[("logLevel", "WARN"), ("forwardHttpProxy", &address)]).await;
    let mut client = connect(server.port).await;
    client.write_all(&STARTUP).await.unwrap();
    assert_eq!(read_after_close(&mut client).await, "closed", "the client is closed");
    assert_eq!(*proxy.refused.lock().unwrap(), vec![format!("127.0.0.1:{}", upstream.port)], "the proxy refused the tunnel");
    assert!(upstream.connections().is_empty(), "nothing reached the upstream");
    let text = common::logs(server.port).await;
    let warnings: Vec<&str> = text.split("\n------------------------------------\n").filter(|e| e.contains("refused to open a CONNECT tunnel")).collect();
    assert_eq!(warnings.len(), 1, "said once: {warnings:?}");
    assert!(warnings[0].contains("unable to connect to"), "{}", warnings[0]);
    assert!(
        warnings[0].contains(&format!("set by forwardHttpProxy refused to open a CONNECT tunnel to 127.0.0.1:{} with status 407 Proxy Authentication Required", upstream.port)),
        "{}",
        warnings[0]
    );
    assert!(warnings[0].contains("it asks for credentials: set forwardProxyAuthenticationUsername and forwardProxyAuthenticationPassword"), "{}", warnings[0]);
}

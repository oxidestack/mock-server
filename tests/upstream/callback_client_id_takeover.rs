//! `CallbackClientIdTakeoverIntegrationTest` (9.1.0, upstream #220/#229): a callback WebSocket that registers with a
//! client id already in use takes it over only from a connection that is gone (closed, or silent for 2 s after a
//! ping), or, with control-plane authentication, from the same caller; `CallbackWebSocketJWTAuthenticationIntegrationTest`
//! and `ControlPlaneOriginIntegrationTest`'s refusal of an unauthenticated callback upgrade. Upstream drives a raw
//! socket that answers pings or not; so do these. The scenarios `callback_websocket_takeover` and
//! `callback_websocket_upgrade_auth` check the same rules against the oracle where its harness can (it has no socket
//! that answers pings while other steps run).
//!
//! The JWTs (`tests/files/jwt/callback_takeover_tokens.json`, subjects alice, mallory, alice-renewed, valid until 2100)
//! are signed by the key of `tests/files/jwt/callback_takeover_jwk.json`. The client certificates are issued at run
//! time by `tests/files/tls/private-ca`, whose `forward-client` leaf is the registered caller.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::common;

/// `CallbackClientIdClaim.LIVENESS_TIMEOUT_MILLIS`
const LIVENESS_TIMEOUT_MILLIS: u128 = 2000;
const FILES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/files");

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// `RawCallbackSocket`: a callback WebSocket over a plain (or TLS) socket, so a test controls whether it answers pings.
struct RawSocket {
    status: u16,
    registration: Option<String>,
    tcp: TcpStream,
    stream: Option<Box<dyn Stream>>,
    reader_saw_close: Option<mpsc::Receiver<()>>,
}

impl RawSocket {
    fn open(port: u16, client_id: &str, authorization: Option<&str>, answer_pings: bool) -> RawSocket {
        let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        RawSocket::open_on(Box::new(tcp.try_clone().unwrap()), tcp, port, client_id, authorization, answer_pings)
    }

    fn open_tls(port: u16, client_id: &str, chain: Vec<Vec<u8>>, key: Vec<u8>, answer_pings: bool) -> RawSocket {
        let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let chain = chain.into_iter().map(rustls_pki_types::CertificateDer::from).collect();
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(key.into());
        let config = common::tls_client_config_with_client_auth(b"http/1.1", chain, key);
        let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let connection = rustls::ClientConnection::new(config, name).unwrap();
        let mut tls = rustls::StreamOwned::new(connection, tcp.try_clone().unwrap());
        tls.flush().unwrap();
        RawSocket::open_on(Box::new(tls), tcp, port, client_id, None, answer_pings)
    }

    fn open_on(mut stream: Box<dyn Stream>, tcp: TcpStream, port: u16, client_id: &str, authorization: Option<&str>, answer_pings: bool) -> RawSocket {
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let key = *uuid::Uuid::new_v4().as_bytes();
        use base64::Engine;
        let upgrade = format!(
            "GET /_mockserver_callback_websocket HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nX-CLIENT-REGISTRATION-ID: {client_id}\r\n{}\r\n",
            base64::engine::general_purpose::STANDARD.encode(key),
            authorization.map(|a| format!("Authorization: {a}\r\n")).unwrap_or_default()
        );
        stream.write_all(upgrade.as_bytes()).unwrap();
        stream.flush().unwrap();
        let head = read_head(&mut stream).unwrap_or_else(|e| panic!("upgrade response: {e}"));
        let status = head.split(' ').nth(1).and_then(|s| s.parse().ok()).expect("a status line");
        let registration = (status == 101).then(|| String::from_utf8(read_frame(&mut stream).unwrap().1).unwrap());
        let mut socket = RawSocket { status, registration, tcp, stream: Some(stream), reader_saw_close: None };
        if status == 101 && answer_pings {
            let mut stream = socket.stream.take().unwrap();
            socket.tcp.set_read_timeout(None).unwrap();
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                loop {
                    match read_frame(&mut stream) {
                        Ok((0x9, payload)) => {
                            if write_masked_frame(&mut stream, 0xA, &payload).is_err() {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                let _ = tx.send(());
            });
            socket.reader_saw_close = Some(rx);
        }
        socket
    }

    fn closed_by_server_within(&mut self, millis: u64) -> bool {
        if let Some(rx) = &self.reader_saw_close {
            return rx.recv_timeout(Duration::from_millis(millis)).is_ok();
        }
        self.tcp.set_read_timeout(Some(Duration::from_millis(millis))).unwrap();
        let stream = self.stream.as_mut().unwrap();
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => return true,
                Ok(_) => {}
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return false,
                Err(_) => return true,
            }
        }
    }

    fn close(&self) {
        let _ = self.tcp.shutdown(std::net::Shutdown::Both);
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        self.close();
    }
}

fn read_head(stream: &mut Box<dyn Stream>) -> std::io::Result<String> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8];
        if stream.read(&mut byte)? == 0 {
            return Err(std::io::Error::other(format!("connection closed during the upgrade response: {}", String::from_utf8_lossy(&head))));
        }
        head.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// A frame's opcode and payload.
fn read_frame(stream: &mut Box<dyn Stream>) -> std::io::Result<(u8, Vec<u8>)> {
    let mut two = [0u8; 2];
    stream.read_exact(&mut two)?;
    let mut length = (two[1] & 0x7F) as u64;
    if length == 126 {
        let mut b = [0u8; 2];
        stream.read_exact(&mut b)?;
        length = u16::from_be_bytes(b) as u64;
    } else if length == 127 {
        let mut b = [0u8; 8];
        stream.read_exact(&mut b)?;
        length = u64::from_be_bytes(b);
    }
    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload)?;
    Ok((two[0] & 0x0F, payload))
}

fn write_masked_frame(stream: &mut Box<dyn Stream>, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mask: [u8; 4] = uuid::Uuid::new_v4().as_bytes()[..4].try_into().unwrap();
    let mut frame = vec![0x80 | opcode, 0x80 | payload.len() as u8];
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    stream.write_all(&frame)?;
    stream.flush()
}

fn client_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn bearer(subject: &str) -> String {
    let tokens: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(format!("{FILES}/jwt/callback_takeover_tokens.json")).unwrap()).unwrap();
    format!("Bearer {}", tokens[subject].as_str().expect("a token for the subject"))
}

async fn open_server() -> common::Running {
    common::start(&[]).await
}

async fn jwt_server() -> common::Running {
    let jwk = format!("{FILES}/jwt/callback_takeover_jwk.json");
    common::start(&[("controlPlaneJWTAuthenticationRequired", "true"), ("controlPlaneJWTAuthenticationJWKSource", &jwk)]).await
}

async fn mtls_server() -> common::Running {
    let chain = format!("{FILES}/tls/private-ca/ca-cert.pem");
    common::start(&[("controlPlaneTLSMutualAuthenticationRequired", "true"), ("controlPlaneTLSMutualAuthenticationCAChain", &chain)]).await
}

/// Runs a blocking test body beside the in-process server.
async fn blocking(body: impl FnOnce() + Send + 'static) {
    tokio::task::spawn_blocking(body).await.unwrap();
}

fn pem_der(path: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(format!("{FILES}/{path}")).unwrap();
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(body).unwrap()
}

/// The registered caller: the private CA's `forward-client` leaf and its key (PKCS#8).
fn leaf() -> (Vec<u8>, Vec<u8>) {
    (pem_der("tls/private-ca/forward-client-cert.pem"), pem_der("tls/private-ca/forward-client-key.pem"))
}

/// A client certificate for `common_name`, `organisation` with a fresh (P-256) key, issued by the private CA, or self-signed under the
/// CA's name when `spoof`; its DER and key.
fn certificate(common_name: &str, organisation: &str, spoof: bool) -> (Vec<u8>, Vec<u8>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
    params.distinguished_name.push(rcgen::DnType::OrganizationName, organisation);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let ca_pem = std::fs::read_to_string(format!("{FILES}/tls/private-ca/ca-cert.pem")).unwrap();
    let certificate = if spoof {
        let mut ca_name = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_name.distinguished_name = rcgen::DistinguishedName::new();
        ca_name.distinguished_name.push(rcgen::DnType::OrganizationName, "Fixture");
        ca_name.distinguished_name.push(rcgen::DnType::CommonName, "Private Test CA");
        params.signed_by(&key, &rcgen::Issuer::new(ca_name, &key)).unwrap()
    } else {
        let ca_key = rcgen::KeyPair::from_pem(&std::fs::read_to_string(format!("{FILES}/tls/private-ca/ca-key.pem")).unwrap()).unwrap();
        params.signed_by(&key, &rcgen::Issuer::from_ca_cert_pem(&ca_pem, ca_key).unwrap()).unwrap()
    };
    (certificate.der().to_vec(), key.serialize_der())
}

#[tokio::test(flavor = "multi_thread")]
async fn should_let_the_registered_connection_close_during_the_liveness_check() {
    let server = open_server().await;
    let port = server.port;
    blocking(move || {
        let id = client_id();
        let half_open = RawSocket::open(port, &id, None, false);
        assert_eq!(half_open.status, 101);
        let start = Instant::now();
        let claim = {
            let id = id.clone();
            std::thread::spawn(move || RawSocket::open(port, &id, None, true))
        };
        std::thread::sleep(Duration::from_millis(300));
        half_open.close();
        let reconnected = claim.join().unwrap();
        assert_eq!(reconnected.status, 101);
        assert!(start.elapsed().as_millis() < LIVENESS_TIMEOUT_MILLIS, "allowed once the registered connection closed, before the ping timed out");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_let_only_one_of_two_concurrent_claims_take_over_a_half_open_connection() {
    let server = open_server().await;
    let port = server.port;
    blocking(move || {
        let id = client_id();
        let half_open = RawSocket::open(port, &id, None, false);
        assert_eq!(half_open.status, 101);
        let claims: Vec<_> = (0..2)
            .map(|_| {
                let id = id.clone();
                std::thread::spawn(move || RawSocket::open(port, &id, None, true))
            })
            .collect();
        let sockets: Vec<RawSocket> = claims.into_iter().map(|c| c.join().unwrap()).collect();
        let mut statuses: Vec<u16> = sockets.iter().map(|s| s.status).collect();
        statuses.sort();
        assert_eq!(statuses, vec![101, 409]);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_a_takeover_while_the_registered_connection_answers_pings() {
    let server = open_server().await;
    let port = server.port;
    blocking(move || {
        let id = client_id();
        let mut registered = RawSocket::open(port, &id, None, true);
        let hijacker = RawSocket::open(port, &id, None, true);
        assert_eq!(registered.status, 101);
        assert_eq!(hijacker.status, 409);
        assert!(!registered.closed_by_server_within(500));
    })
    .await;
    let logs = common::logs(server.port).await;
    assert!(logs.contains("callback web socket upgrade rejected with status") && logs.contains("registered to an open connection that answered a ping"), "{logs}");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_allow_a_reconnect_once_the_registered_connection_has_closed() {
    let server = open_server().await;
    let port = server.port;
    blocking(move || {
        let id = client_id();
        let dropped = RawSocket::open(port, &id, None, true);
        assert_eq!(dropped.status, 101);
        drop(dropped);
        let reconnected = RawSocket::open(port, &id, None, true);
        assert_eq!(reconnected.status, 101);
        assert!(reconnected.registration.as_deref().unwrap().contains(&id));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_replace_a_half_open_connection_once_it_fails_to_answer_a_ping() {
    let server = open_server().await;
    let port = server.port;
    blocking(move || {
        let id = client_id();
        let mut half_open = RawSocket::open(port, &id, None, false);
        assert_eq!(half_open.status, 101);
        let start = Instant::now();
        let reconnected = RawSocket::open(port, &id, None, true);
        assert_eq!(reconnected.status, 101);
        assert!(reconnected.registration.as_deref().unwrap().contains(&id));
        assert!(start.elapsed().as_millis() >= LIVENESS_TIMEOUT_MILLIS - 100);
        assert!(half_open.closed_by_server_within(5000), "the unresponsive connection is closed");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_a_takeover_by_another_authenticated_caller() {
    let server = jwt_server().await;
    let port = server.port;
    blocking(move || {
        let id = client_id();
        let mut registered = RawSocket::open(port, &id, Some(&bearer("alice")), true);
        let hijacker = RawSocket::open(port, &id, Some(&bearer("mallory")), true);
        assert_eq!(registered.status, 101);
        assert_eq!(hijacker.status, 403);
        assert!(!registered.closed_by_server_within(500));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_let_another_authenticated_caller_replace_a_connection_that_no_longer_answers() {
    let server = jwt_server().await;
    let port = server.port;
    blocking(move || {
        let id = client_id();
        let mut half_open = RawSocket::open(port, &id, Some(&bearer("alice")), false);
        assert_eq!(half_open.status, 101);
        let start = Instant::now();
        let renewed = RawSocket::open(port, &id, Some(&bearer("alice-renewed")), true);
        assert_eq!(renewed.status, 101);
        assert!(start.elapsed().as_millis() >= LIVENESS_TIMEOUT_MILLIS - 100);
        assert!(half_open.closed_by_server_within(5000), "the unresponsive connection is closed");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_let_the_same_authenticated_caller_reconnect_while_its_old_connection_looks_open() {
    let server = jwt_server().await;
    let port = server.port;
    blocking(move || {
        let id = client_id();
        let registered = RawSocket::open(port, &id, Some(&bearer("alice")), true);
        let start = Instant::now();
        let reconnected = RawSocket::open(port, &id, Some(&bearer("alice")), true);
        assert_eq!(registered.status, 101);
        assert_eq!(reconnected.status, 101);
        assert!(start.elapsed().as_millis() < LIVENESS_TIMEOUT_MILLIS, "the same caller takes over without a liveness check");
        assert!(reconnected.registration.as_deref().unwrap().contains(&id));
    })
    .await;
}

/// Also `CallbackWebSocketJWTAuthenticationIntegrationTest.callbackWebSocketShouldBeRefusedWithoutTheControlPlaneJWT`
/// and `ControlPlaneOriginIntegrationTest.shouldRequireControlPlaneAuthenticationForTheCallbackWebSocket`.
#[tokio::test(flavor = "multi_thread")]
async fn should_still_refuse_a_callback_upgrade_without_credentials() {
    let server = jwt_server().await;
    let port = server.port;
    blocking(move || {
        let anonymous = RawSocket::open(port, &client_id(), None, true);
        assert_eq!(anonymous.status, 401);
    })
    .await;
    let logs = common::send(server.port, "PUT", "/mockserver/retrieve?type=LOGS", "").await;
    assert_eq!(logs.status, 401, "the log needs the JWT too");
}

#[tokio::test(flavor = "multi_thread")]
async fn should_let_the_same_client_certificate_take_over_while_its_old_connection_answers_pings() {
    let server = mtls_server().await;
    let port = server.port;
    blocking(move || {
        let id = client_id();
        let (cert, key) = leaf();
        let registered = RawSocket::open_tls(port, &id, vec![cert.clone()], key.clone(), true);
        let reconnected = RawSocket::open_tls(port, &id, vec![cert], key, true);
        assert_eq!(registered.status, 101);
        assert_eq!(reconnected.status, 101, "the same caller takes over without a liveness check");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_a_takeover_by_another_client_certificate() {
    let server = mtls_server().await;
    let port = server.port;
    blocking(move || {
        let id = client_id();
        let (cert, key) = leaf();
        let (other, other_key) = certificate("other-client", "MockServer", false);
        let registered = RawSocket::open_tls(port, &id, vec![cert], key, true);
        let hijacker = RawSocket::open_tls(port, &id, vec![other], other_key, true);
        assert_eq!(registered.status, 101);
        assert_eq!(hijacker.status, 403);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_let_a_renewed_client_certificate_replace_a_connection_that_no_longer_answers() {
    let server = mtls_server().await;
    let port = server.port;
    blocking(move || {
        let id = client_id();
        let (cert, key) = leaf();
        let (renewed, renewed_key) = certificate("forward-client.example", "Fixture", false);
        let mut half_open = RawSocket::open_tls(port, &id, vec![cert], key, false);
        assert_eq!(half_open.status, 101);
        let start = Instant::now();
        let reconnected = RawSocket::open_tls(port, &id, vec![renewed], renewed_key, true);
        assert_eq!(reconnected.status, 101);
        assert!(start.elapsed().as_millis() >= LIVENESS_TIMEOUT_MILLIS - 100);
        assert!(half_open.closed_by_server_within(5000), "the unresponsive connection is closed");
    })
    .await;
}

/// A self-signed leaf copying the registered certificate's names, followed by that certificate, neither
/// authenticates nor takes the client id over.
#[tokio::test(flavor = "multi_thread")]
async fn should_refuse_a_spoofed_leaf_that_copies_the_registered_certificates_names() {
    let server = mtls_server().await;
    let port = server.port;
    blocking(move || {
        let id = client_id();
        let (victim, key) = leaf();
        let (spoof, spoof_key) = certificate("forward-client.example", "Fixture", true);
        let registered = RawSocket::open_tls(port, &id, vec![victim.clone()], key, true);
        let hijacker = RawSocket::open_tls(port, &id, vec![spoof, victim], spoof_key, true);
        assert_eq!(registered.status, 101);
        assert_eq!(hijacker.status, 401);
    })
    .await;
}

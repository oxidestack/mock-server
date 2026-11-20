//! A DSA key with a DSA certificate: the image's JDK completes a TLS 1.2 handshake with a client offering
//! a DHE-DSS suite (`openssl s_client -tls1_2 -cipher DHE-DSS-AES128-GCM-SHA256:@SECLEVEL=0` against
//! `mockserver/mockserver-webhook:9.2.0`: `dsa_sha224` or `dsa_sha256`, the first the client lists, over ffdhe2048)
//! and ends every other handshake with a `handshake_failure` alert. The DHE-DSS clients are `openssl s_client`
//! (OpenSSL 3, on the PATH): rustls' client refuses a signature scheme it has no name for. The tests fail where it is
//! missing.

use k8s_webhook::dsa::DsaKey;
use k8s_webhook::{SidecarInjectionConfig, WebhookServer, tls};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls_pki_types::pem::PemObject;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;

async fn serve(cert_pem: &str, key_pem: &str) -> WebhookServer {
    k8s_webhook::log::silence();
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>().unwrap();
    let server_config = tls::server_config(certs, tls::load_private_key(key_pem).unwrap().der).unwrap();
    let mut server = WebhookServer::bind("127.0.0.1:0".parse().unwrap(), server_config, SidecarInjectionConfig::default()).await.unwrap();
    server.start();
    server
}

/// What `openssl s_client -tls1_2 -cipher <cipher>:@SECLEVEL=0 -sigalgs <sigalgs>` prints after `GET /healthz`.
async fn s_client(port: u16, cipher: &str, sigalgs: &str) -> String {
    s_client_with(port, cipher, sigalgs, &["-tls1_2"]).await
}

/// The same with other `s_client` arguments in place of `-tls1_2` (a group list, a protocol version).
async fn s_client_with(port: u16, cipher: &str, sigalgs: &str, extra: &[&str]) -> String {
    let (cipher, sigalgs) = (format!("{cipher}:@SECLEVEL=0"), sigalgs.to_string());
    let extra: Vec<String> = extra.iter().map(|a| a.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new("openssl")
            .args(["s_client", "-connect", &format!("127.0.0.1:{port}"), "-cipher", &cipher, "-sigalgs", &sigalgs, "-ign_eof"])
            .args(&extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("openssl s_client is needed on the PATH");
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
        drop(stdin);
        let out = child.wait_with_output().unwrap();
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn k8s_webhook_dsa_pair_serves_a_dhe_dss_client() {
    for (cert, key) in [(CERT_1024, KEY_1024), (CERT_2048, KEY_2048_PKCS8)] {
        let server = serve(cert, key).await;
        for (cipher, sigalgs, signature) in [
            ("DHE-DSS-AES128-GCM-SHA256", "DSA+SHA224:RSA+SHA256", "dsa_sha224"),
            ("DHE-DSS-AES128-GCM-SHA256", "DSA+SHA256:RSA+SHA256", "dsa_sha256"),
            // both listed: the JDK signs with the first
            ("DHE-DSS-AES128-GCM-SHA256", "DSA+SHA256:DSA+SHA224:RSA+SHA256", "dsa_sha256"),
            ("DHE-DSS-AES128-GCM-SHA256", "DSA+SHA224:DSA+SHA256:RSA+SHA256", "dsa_sha224"),
            ("DHE-DSS-AES256-GCM-SHA384", "DSA+SHA224:DSA+SHA256:RSA+SHA256", "dsa_sha224"),
        ] {
            let out = s_client(server.port(), cipher, sigalgs).await;
            assert!(out.contains(&format!("Cipher is {cipher}")), "{cipher} {sigalgs}: {out}");
            assert!(out.contains(&format!("Peer signature type: {signature}")), "{cipher} {sigalgs}: {out}");
            assert!(out.contains("Peer Temp Key: DH, 2048 bits"), "{cipher} {sigalgs}: {out}");
            assert!(out.contains("HTTP/1.1 200") && out.contains("\nok"), "{cipher} {sigalgs}: {out}");
        }
        // a client listing only DSA schemes (rustls dropped them from the list it works with)
        for (cipher, sigalgs, signature) in [
            ("DHE-DSS-AES128-GCM-SHA256", "DSA+SHA256", "dsa_sha256"),
            ("DHE-DSS-AES128-SHA", "DSA+SHA224", "dsa_sha224"),
            ("DHE-DSS-AES256-SHA256", "DSA+SHA224:DSA+SHA256", "dsa_sha224"),
        ] {
            let out = s_client(server.port(), cipher, sigalgs).await;
            assert!(out.contains(&format!("Cipher is {cipher}")), "{cipher} {sigalgs}: {out}");
            assert!(out.contains(&format!("Peer signature type: {signature}")), "{cipher} {sigalgs}: {out}");
            assert!(out.contains("HTTP/1.1 200") && out.contains("\nok"), "{cipher} {sigalgs}: {out}");
        }
        // the image serves ffdhe2048 whatever groups the client offers
        for groups in ["ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192", "ffdhe2048:ffdhe3072", "ffdhe8192:ffdhe4096"] {
            let out = s_client_with(server.port(), "DHE-DSS-AES128-SHA", "DSA+SHA256:RSA+SHA256", &["-tls1_2", "-groups", groups]).await;
            assert!(out.contains("Cipher is DHE-DSS-AES128-SHA"), "{groups}: {out}");
            assert!(out.contains("Peer Temp Key: DH, 2048 bits"), "{groups}: {out}");
            assert!(out.contains("HTTP/1.1 200") && out.contains("\nok"), "{groups}: {out}");
        }
        // the CBC suites: MAC-then-encrypt records both ways, with a body large enough for several blocks
        for cipher in ["DHE-DSS-AES128-SHA", "DHE-DSS-AES256-SHA", "DHE-DSS-AES128-SHA256", "DHE-DSS-AES256-SHA256"] {
            let out = s_client(server.port(), cipher, "DSA+SHA256:RSA+SHA256").await;
            assert!(out.contains(&format!("Cipher is {cipher}")), "{cipher}: {out}");
            assert!(out.contains("Peer signature type: dsa_sha256"), "{cipher}: {out}");
            assert!(out.contains("Peer Temp Key: DH, 2048 bits"), "{cipher}: {out}");
            assert!(out.contains("HTTP/1.1 200") && out.contains("\nok"), "{cipher}: {out}");
        }
        // a DHE-DSS suite and no usable DSA scheme: the JDK sends `internal_error` after its Certificate when the client lists
        // a scheme the JDK knows (RSA, RSASSA-PSS, ECDSA, EdDSA, any hash but SHA-1), `handshake_failure` before its
        // ServerHello otherwise (probed against the image)
        for sigalgs in ["DSA+SHA1:RSA+SHA256", "DSA+SHA384:RSA+SHA256", "DSA+SHA1:ECDSA+SHA384", "DSA+SHA1:ed25519", "DSA+SHA1:RSA-PSS+SHA256", "DSA+SHA1:RSA+SHA224"] {
            let out = s_client(server.port(), "DHE-DSS-AES128-SHA", sigalgs).await;
            assert!(out.contains("alert internal error"), "{sigalgs}: {out}");
            assert!(!out.contains("HTTP/1.1"), "{sigalgs}: {out}");
        }
        for sigalgs in ["DSA+SHA1", "DSA+SHA1:RSA+SHA1", "DSA+SHA1:ECDSA+SHA1", "DSA+SHA384:DSA+SHA512:RSA+SHA1"] {
            let out = s_client(server.port(), "DHE-DSS-AES128-GCM-SHA256", sigalgs).await;
            assert!(out.contains("alert handshake failure"), "{sigalgs}: {out}");
        }
        // the internal_error comes after the ServerHello and the Certificate, in the clear
        let out = s_client_with(server.port(), "DHE-DSS-AES128-SHA", "DSA+SHA1:RSA+SHA256", &["-tls1_2", "-msg"]).await;
        let at = |needle: &str| out.find(needle).unwrap_or_else(|| panic!("{needle}: {out}"));
        assert!(at("ServerHello") < at("], Certificate") && at("], Certificate") < at("fatal internal_error"), "{out}");
        assert!(!out.contains("ServerKeyExchange"), "{out}");
        // a DSA scheme but no DHE-DSS suite
        let out = s_client(server.port(), "ECDHE-RSA-AES128-GCM-SHA256", "DSA+SHA256:RSA+SHA256").await;
        assert!(out.contains("alert handshake failure"), "{out}");
        server.stop(std::time::Duration::ZERO).await;
    }
}

/// A client offering TLS 1.3 only gets `handshake_failure`, as the JDK sends (rustls alone would answer
/// `protocol_version`), after the TLS 1.3 prefix of `k8s-webhook/src/tls13.rs`.
#[tokio::test]
async fn k8s_webhook_dsa_pair_refuses_a_tls13_only_client_with_handshake_failure() {
    let server = serve(CERT_2048, KEY_2048_PKCS8).await;
    for sigalgs in ["RSA+SHA256", "RSA-PSS+SHA256:ECDSA+SHA256"] {
        let out = s_client_with(server.port(), "DHE-DSS-AES128-SHA", sigalgs, &["-tls1_3"]).await;
        assert!(out.contains("alert handshake failure"), "{sigalgs}: {out}");
    }
    server.stop(std::time::Duration::ZERO).await;
}

/// The messages `openssl s_client -msg` reads from the server, as `(direction, text)` lines: `<<< TLS 1.3, Handshake
/// [length 007a], ServerHello` becomes `Handshake 007a ServerHello`, the encrypted ones by their inner type.
fn server_messages(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.strip_prefix("<<< TLS 1.3, ").or_else(|| l.strip_prefix("<<< TLS 1.2, ")))
        .filter(|l| !l.starts_with("InnerContent") && !l.starts_with("RecordHeader"))
        .map(|l| l.replace("[length ", "").replace("], ", " ").replace(", ", " ").replace(']', ""))
        .collect()
}

/// The TLS 1.3 prefix of a client that offers TLS 1.3 and a scheme TLS 1.3 allows, probed against
/// `mockserver-webhook` 9.2.0 with OpenSSL 3.5 `s_client -msg`: a ServerHello whose length shows the group of the
/// client's first usable key share, the compatibility ChangeCipherSpec, an encrypted EncryptedExtensions of 34 bytes
/// (its `supported_groups`) and an encrypted fatal `handshake_failure`.
#[tokio::test]
async fn k8s_webhook_dsa_pair_answers_a_tls13_client_as_far_as_the_image_does() {
    let server = serve(CERT_2048, KEY_2048_PKCS8).await;
    // (groups argument, ServerHello length the image sends, the group s_client reports)
    for (groups, hello, temp_key) in [
        ("x25519", "007a", "X25519, 253 bits"),
        ("secp256r1", "009b", "ECDH, prime256v1, 256 bits"),
        ("secp384r1", "00bb", "ECDH, secp384r1, 384 bits"),
        ("secp521r1", "00df", "ECDH, secp521r1, 521 bits"),
        ("x448", "0092", "X448, 448 bits"),
        ("ffdhe2048", "015a", "DH, 2048 bits"),
        ("ffdhe3072", "01da", "DH, 3072 bits"),
        ("ffdhe4096", "025a", "DH, 4096 bits"),
        ("ffdhe6144", "035a", "DH, 6144 bits"),
        ("ffdhe8192", "045a", "DH, 8192 bits"),
        ("X25519MLKEM768", "04ba", "X25519MLKEM768"),
        // the first key share the image supports: s_client sends a share for every group marked `*`
        ("*SecP256r1MLKEM768:*x25519", "007a", "X25519, 253 bits"),
        ("*MLKEM768:*secp384r1", "00bb", "ECDH, secp384r1, 384 bits"),
        ("*secp521r1:*ffdhe3072:*x25519", "00df", "ECDH, secp521r1, 521 bits"),
    ] {
        let out = s_client_with(server.port(), "DHE-DSS-AES128-SHA", "RSA-PSS+SHA256", &["-tls1_3", "-groups", groups, "-msg"]).await;
        assert_eq!(
            server_messages(&out),
            [format!("Handshake {hello} ServerHello"), "ChangeCipherSpec 0001".to_string(), "Handshake 0022 EncryptedExtensions".to_string(), "Alert 0002 fatal handshake_failure".to_string()],
            "{groups}: {out}"
        );
        assert!(out.contains(temp_key), "{groups}: {out}");
        assert!(out.contains("alert handshake failure"), "{groups}: {out}");
    }
}

fn ext(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// A TLS 1.3 ClientHello record by hand: `groups` for `supported_groups`, `shares` for `key_share` (`None`: no such
/// extension), one scheme and one suite.
fn client_hello(groups: &[u16], shares: Option<&[(u16, Vec<u8>)]>, scheme: u16, suite: u16, session_id: &[u8]) -> Vec<u8> {
    client_hello_with(groups, shares, scheme, suite, session_id, 0x22, None)
}

/// The same with a fill byte for the `random` and a cookie (a second ClientHello).
fn client_hello_with(groups: &[u16], shares: Option<&[(u16, Vec<u8>)]>, scheme: u16, suite: u16, session_id: &[u8], random: u8, cookie: Option<&[u8]>) -> Vec<u8> {
    client_hello_padded(groups, shares, scheme, suite, session_id, random, cookie, 0)
}

/// The same with `pad` bytes of a `padding` extension's contents (0: none) to make the message as long as a test needs.
#[allow(clippy::too_many_arguments)]
fn client_hello_padded(groups: &[u16], shares: Option<&[(u16, Vec<u8>)]>, scheme: u16, suite: u16, session_id: &[u8], random: u8, cookie: Option<&[u8]>, pad: usize) -> Vec<u8> {
    let list = |items: &[u16]| items.iter().flat_map(|i| i.to_be_bytes()).collect::<Vec<u8>>();
    let sized = |items: Vec<u8>| [(items.len() as u16).to_be_bytes().to_vec(), items].concat();
    let mut extensions = ext(0x002b, &[2, 0x03, 0x04]);
    extensions.extend(ext(0x000a, &sized(list(groups))));
    extensions.extend(ext(0x000d, &sized(list(&[scheme]))));
    if let Some(shares) = shares {
        let body: Vec<u8> = shares.iter().flat_map(|(g, d)| [g.to_be_bytes().to_vec(), sized(d.clone())].concat()).collect();
        extensions.extend(ext(0x0033, &sized(body)));
    }
    if let Some(cookie) = cookie {
        extensions.extend(ext(0x002c, &sized(cookie.to_vec())));
    }
    if pad > 0 {
        extensions.extend(ext(0x0015, &vec![0; pad]));
    }
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[random; 32]);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&sized(suite.to_be_bytes().to_vec()));
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&sized(extensions));
    let mut message = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
    message.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(message.len() as u16).to_be_bytes());
    record.extend_from_slice(&message);
    record
}

/// Sends `bytes` and reads until the server closes: the records as `(type, length)`, and the last alert's description.
async fn records_after(port: u16, bytes: Vec<u8>) -> (Vec<(u8, usize)>, Option<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tcp.write_all(&bytes).await.unwrap();
    let mut got = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), tcp.read_to_end(&mut got)).await;
    let (mut records, mut alert, mut rest) = (Vec::new(), None, &got[..]);
    while rest.len() >= 5 {
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        records.push((rest[0], len));
        if rest[0] == 21 && len == 2 {
            alert = Some(rest[6]);
        }
        rest = &rest[(5 + len).min(rest.len())..];
    }
    (records, alert)
}

/// What the image does with a share it cannot use, a ClientHello it cannot serve and a client without a ChangeCipherSpec
/// to answer (hand-made ClientHellos, probed against `mockserver-webhook` 9.2.0).
#[tokio::test]
async fn k8s_webhook_dsa_pair_tls13_edge_cases_end_as_the_image_ends_them() {
    let server = serve(CERT_2048, KEY_2048_PKCS8).await;
    let port = server.port();
    let sid = [0x11u8; 32];
    let flight = |hello: usize| vec![(22, hello), (20, 1), (23, 67), (23, 35)];
    let p2048 = rustls::ffdhe_groups::FFDHE2048.p.to_vec();
    let mut p_minus_1 = p2048.clone();
    *p_minus_1.last_mut().unwrap() -= 1;
    type Records = Vec<(u8, usize)>;
    let cases: Vec<(&str, Vec<u8>, Records, Option<u8>)> = vec![
        // an x25519 or x448 value of any length is read as a number; all zero fails after the ServerHello
        ("x25519 zero", client_hello(&[29], Some(&[(29, vec![0; 32])]), 0x0804, 0x1302, &sid), vec![(22, 122), (21, 2)], Some(80)),
        ("x25519 31 bytes", client_hello(&[29], Some(&[(29, vec![1; 31])]), 0x0804, 0x1302, &sid), flight(122), None),
        ("x25519 33 bytes", client_hello(&[29], Some(&[(29, vec![1; 33])]), 0x0804, 0x1302, &sid), flight(122), None),
        ("x448 55 bytes", client_hello(&[30], Some(&[(30, vec![1; 55])]), 0x0804, 0x1302, &sid), flight(146), None),
        ("x448 zero", client_hello(&[30], Some(&[(30, vec![0; 56])]), 0x0804, 0x1302, &sid), vec![(22, 146), (21, 2)], Some(80)),
        ("empty share", client_hello(&[29], Some(&[(29, vec![])]), 0x0804, 0x1302, &sid), vec![(21, 2)], Some(50)),
        // a point must be an uncompressed one of its length; off the curve it fails after the ServerHello
        ("p256 off the curve", client_hello(&[23], Some(&[(23, [vec![4], vec![1; 64]].concat())]), 0x0804, 0x1302, &sid), vec![(22, 155), (21, 2)], Some(80)),
        ("p256 compressed", client_hello(&[23], Some(&[(23, [vec![2], vec![1; 32]].concat())]), 0x0804, 0x1302, &sid), vec![(21, 2)], Some(80)),
        ("p384 off the curve", client_hello(&[24], Some(&[(24, [vec![4], vec![1; 96]].concat())]), 0x0804, 0x1302, &sid), vec![(22, 187), (21, 2)], Some(80)),
        ("p521 off the curve", client_hello(&[25], Some(&[(25, [vec![4], vec![1; 132]].concat())]), 0x0804, 0x1302, &sid), vec![(22, 223), (21, 2)], Some(80)),
        // an ffdhe value of any length is read as a number; 1, p-1 and p fail after the ServerHello
        ("ffdhe2048 one", client_hello(&[256], Some(&[(256, [vec![0; 255], vec![1]].concat())]), 0x0804, 0x1302, &sid), vec![(22, 346), (21, 2)], Some(80)),
        ("ffdhe2048 p-1", client_hello(&[256], Some(&[(256, p_minus_1)]), 0x0804, 0x1302, &sid), vec![(22, 346), (21, 2)], Some(80)),
        ("ffdhe2048 p", client_hello(&[256], Some(&[(256, p2048)]), 0x0804, 0x1302, &sid), vec![(22, 346), (21, 2)], Some(80)),
        ("ffdhe2048 255 bytes", client_hello(&[256], Some(&[(256, vec![7; 255])]), 0x0804, 0x1302, &sid), flight(346), None),
        ("hybrid short", client_hello(&[0x11ec], Some(&[(0x11ec, vec![1; 100])]), 0x0804, 0x1302, &sid), vec![(21, 2)], Some(80)),
        ("hybrid 1216 bytes", client_hello(&[0x11ec], Some(&[(0x11ec, vec![1; 1216])]), 0x0804, 0x1302, &sid), flight(1210), None),
        // other ClientHellos
        ("no session id, no ChangeCipherSpec", client_hello(&[29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1302, &[]), vec![(22, 90), (23, 67), (23, 35)], None),
        ("an unknown group's share first", client_hello(&[29], Some(&[(0x9999, vec![1; 5]), (29, vec![1; 32])]), 0x0804, 0x1302, &sid), flight(122), None),
        ("a share of a group not in supported_groups", client_hello(&[30], Some(&[(29, vec![1; 32])]), 0x0804, 0x1302, &sid), flight(122), None),
        ("no key_share extension", client_hello(&[29], None, 0x0804, 0x1302, &sid), vec![(21, 2)], Some(109)),
        ("no suite in common", client_hello(&[29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1304, &sid), vec![(21, 2)], Some(40)),
        ("no scheme TLS 1.3 allows", client_hello(&[29], Some(&[(29, vec![1; 32])]), 0x0202, 0x1302, &sid), vec![(21, 2)], Some(40)),
        ("no group in common, none usable", client_hello(&[0x11eb], Some(&[(0x11eb, vec![1; 100])]), 0x0804, 0x1302, &sid), vec![(21, 2)], Some(10)),
    ];
    for (name, hello, records, alert) in cases {
        assert_eq!(records_after(port, hello).await, (records, alert), "{name}");
    }
    server.stop(std::time::Duration::ZERO).await;
}

/// A HelloRetryRequest for a client whose first key share the image cannot use (a ChangeCipherSpec after it, a 3 + 2h byte
/// cookie, and after the second ClientHello the full flight, a ChangeCipherSpec after the second ServerHello too), for
/// each suite's hash and for a retry that names ffdhe3072 and secp384r1.
#[tokio::test]
async fn k8s_webhook_dsa_pair_retries_a_tls13_client_without_a_usable_share() {
    let server = serve(CERT_2048, KEY_2048_PKCS8).await;
    for (groups, second, hello, temp_key) in [
        ("SecP256r1MLKEM768:x25519", "007a", "00c1", "X25519, 253 bits"),
        ("SecP256r1MLKEM768:secp256r1:x25519", "009b", "00c1", "ECDH, prime256v1, 256 bits"),
        ("SecP256r1MLKEM768:ffdhe3072:secp384r1", "01da", "00c1", "DH, 3072 bits"),
        ("SecP256r1MLKEM768:secp521r1", "00df", "00c1", "ECDH, secp521r1, 521 bits"),
        ("SecP256r1MLKEM768:x448", "0092", "00c1", "X448, 448 bits"),
    ] {
        let out = s_client_with(server.port(), "DHE-DSS-AES128-SHA", "RSA-PSS+SHA256", &["-tls1_3", "-groups", groups, "-msg"]).await;
        let messages = server_messages(&out);
        assert_eq!(
            messages,
            [
                format!("Handshake {hello} ServerHello"),
                "ChangeCipherSpec 0001".to_string(),
                format!("Handshake {second} ServerHello"),
                "ChangeCipherSpec 0001".to_string(),
                "Handshake 0022 EncryptedExtensions".to_string(),
                "Alert 0002 fatal handshake_failure".to_string()
            ],
            "{groups}: {out}"
        );
        assert!(out.contains(temp_key), "{groups}: {out}");
    }
    // the cookie is 3 + 2h bytes for h the suite's hash length
    for (suite, hello) in [("TLS_AES_256_GCM_SHA384", "00c1"), ("TLS_AES_128_GCM_SHA256", "00a1"), ("TLS_CHACHA20_POLY1305_SHA256", "00a1")] {
        let out = s_client_with(server.port(), "DHE-DSS-AES128-SHA", "RSA-PSS+SHA256", &["-tls1_3", "-groups", "SecP256r1MLKEM768:x25519", "-ciphersuites", suite, "-msg"]).await;
        assert!(server_messages(&out).first().is_some_and(|m| m == &format!("Handshake {hello} ServerHello")), "{suite}: {out}");
        assert!(out.contains("alert handshake failure"), "{suite}: {out}");
    }
    server.stop(std::time::Duration::ZERO).await;
}

/// The cookie of a HelloRetryRequest record in `bytes` (its `cookie` extension's contents).
fn retry_cookie(bytes: &[u8]) -> Vec<u8> {
    let body = &bytes[5 + 4..];
    let at = 2 + 32 + 1 + body[34] as usize + 2 + 1;
    let (mut rest, end) = (at + 2, at + 2 + u16::from_be_bytes([body[at], body[at + 1]]) as usize);
    while rest < end {
        let (kind, len) = (u16::from_be_bytes([body[rest], body[rest + 1]]), u16::from_be_bytes([body[rest + 2], body[rest + 3]]) as usize);
        if kind == 0x002c {
            return body[rest + 6..rest + 4 + len].to_vec();
        }
        rest += 4 + len;
    }
    panic!("no cookie: {bytes:?}");
}

/// The second ClientHello after a HelloRetryRequest, checked as the image checks it (hand-made ones, probed against
/// `mockserver-webhook` 9.2.0): another random, session id, suite list or cookie is `unexpected_message`, no cookie
/// is fine, no key share extension `missing_extension`, no usable share `handshake_failure`, and the first usable share
/// wins whatever group the retry asked for.
#[tokio::test]
async fn k8s_webhook_dsa_pair_checks_the_second_client_hello_after_a_retry_as_the_image_does() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = serve(CERT_2048, KEY_2048_PKCS8).await;
    let sid = [0x11u8; 32];
    let ccs = [0x14u8, 3, 3, 0, 1, 1];
    // (name, second ClientHello given the cookie, records expected, alert)
    type Second = Box<dyn Fn(&[u8]) -> Vec<u8>>;
    type Records = Vec<(u8, usize)>;
    let cases: Vec<(&str, Second, Records, Option<u8>)> = vec![
        ("the cookie echoed", Box::new(|c| client_hello_with(&[29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1302, &[0x11; 32], 0x22, Some(c))), vec![(22, 122), (20, 1), (23, 67), (23, 35)], None),
        ("no cookie", Box::new(|_| client_hello_with(&[29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1302, &[0x11; 32], 0x22, None)), vec![(22, 122), (20, 1), (23, 67), (23, 35)], None),
        ("a share of another group", Box::new(|c| client_hello_with(&[29], Some(&[(30, vec![1; 56])]), 0x0804, 0x1302, &[0x11; 32], 0x22, Some(c))), vec![(22, 146), (20, 1), (23, 67), (23, 35)], None),
        ("another cookie", Box::new(|c| client_hello_with(&[29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1302, &[0x11; 32], 0x22, Some(&c[1..]))), vec![(21, 2)], Some(10)),
        ("another random", Box::new(|c| client_hello_with(&[29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1302, &[0x11; 32], 0x33, Some(c))), vec![(21, 2)], Some(10)),
        ("another session id", Box::new(|c| client_hello_with(&[29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1302, &[0x44; 32], 0x22, Some(c))), vec![(21, 2)], Some(10)),
        ("another suite list", Box::new(|c| client_hello_with(&[29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1301, &[0x11; 32], 0x22, Some(c))), vec![(21, 2)], Some(10)),
        ("no shares", Box::new(|c| client_hello_with(&[29], Some(&[]), 0x0804, 0x1302, &[0x11; 32], 0x22, Some(c))), vec![(21, 2)], Some(40)),
        ("no key share extension", Box::new(|c| client_hello_with(&[29], None, 0x0804, 0x1302, &[0x11; 32], 0x22, Some(c))), vec![(21, 2)], Some(109)),
    ];
    for (name, second, records, alert) in cases {
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", server.port())).await.unwrap();
        tcp.write_all(&client_hello(&[29], Some(&[]), 0x0804, 0x1302, &sid)).await.unwrap();
        // the HelloRetryRequest (193 bytes) and the ChangeCipherSpec
        let mut first = vec![0u8; 5 + 193 + 6];
        tcp.read_exact(&mut first).await.unwrap();
        assert_eq!(&first[..5], &[0x16, 3, 3, 0, 193], "{name}");
        assert_eq!(&first[5 + 193..], &ccs, "{name}");
        let cookie = retry_cookie(&first);
        assert_eq!(cookie.len(), 99, "{name}");
        tcp.write_all(&[ccs.to_vec(), second(&cookie)].concat()).await.unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), tcp.read_to_end(&mut got)).await;
        let (mut seen, mut last_alert, mut rest) = (Vec::new(), None, &got[..]);
        while rest.len() >= 5 {
            let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
            seen.push((rest[0], len));
            if rest[0] == 21 && len == 2 {
                last_alert = Some(rest[6]);
            }
            rest = &rest[(5 + len).min(rest.len())..];
        }
        assert_eq!((seen, last_alert), (records, alert), "{name}");
    }
    server.stop(std::time::Duration::ZERO).await;
}

/// One ClientHello of `tests/files/k8s-webhook-tls13/probe.py`'s matrix, by its dimensions (see that file's header).
struct MatrixHello<'a>(Vec<(&'a str, &'a str)>);

impl MatrixHello<'_> {
    fn get(&self, key: &str) -> &str {
        self.0.iter().find(|(k, _)| *k == key).map(|(_, v)| *v).unwrap_or_else(|| panic!("no {key}"))
    }

    fn record(&self, issued: &[u8]) -> Vec<u8> {
        let sized = |items: Vec<u8>| [(items.len() as u16).to_be_bytes().to_vec(), items].concat();
        let list = |items: &[u16]| items.iter().flat_map(|i| i.to_be_bytes()).collect::<Vec<u8>>();
        let groups: &[u16] = match self.get("gr") {
            "29" => &[29],
            "empty" => &[],
            _ => &[99],
        };
        let scheme = if self.get("sc") == "ok" { 0x0804 } else { 0x0401 };
        let suite: u16 = match self.get("su") {
            "same" => 0x1302,
            "other" => 0x1301,
            _ => 0x1304,
        };
        let shares: Option<Vec<(u16, Vec<u8>)>> = match self.get("sh") {
            "usable" => Some(vec![(29, vec![1; 32])]),
            "other" => Some(vec![(30, vec![1; 56])]),
            "empty" => Some(vec![]),
            "unknown" => Some(vec![(99, b"a".to_vec())]),
            "both" => Some(vec![(99, b"a".to_vec()), (29, vec![1; 32])]),
            _ => None,
        };
        let mut extensions = ext(0x002b, &[2, 3, 4]);
        extensions.extend(ext(0x000a, &sized(list(groups))));
        extensions.extend(ext(0x000d, &sized(list(&[scheme]))));
        if let Some(shares) = shares {
            let body: Vec<u8> = shares.iter().flat_map(|(g, d)| [g.to_be_bytes().to_vec(), sized(d.clone())].concat()).collect();
            extensions.extend(ext(0x0033, &sized(body)));
        }
        match self.get("ck") {
            "echo" => extensions.extend(ext(0x002c, &sized(issued.to_vec()))),
            "other" => extensions.extend(ext(0x002c, &sized(vec![0; 99]))),
            "empty" => extensions.extend(ext(0x002c, &sized(vec![]))),
            "raw1" => extensions.extend(ext(0x002c, &[0])),
            "trunc" => extensions.extend(ext(0x002c, &[0, 5, b'a', b'b', b'c'])),
            _ => {}
        }
        let sid: Vec<u8> = match self.get("sd") {
            "same" => vec![0x11; 32],
            "other" => vec![0x44; 32],
            _ => vec![],
        };
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[if self.get("rn") == "same" { 0x22 } else { 0x33 }; 32]);
        body.push(sid.len() as u8);
        body.extend_from_slice(&sid);
        body.extend_from_slice(&sized(suite.to_be_bytes().to_vec()));
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&sized(extensions));
        let mut message = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        message.extend_from_slice(&body);
        record_of(22, &message)
    }
}

/// What the image's `probe.py` prints for a reply: the alert, the retry, or the flight's ServerHello suite and session id and
/// the record lengths.
fn matrix_outcome(got: &[u8]) -> String {
    let (mut records, mut rest) = (Vec::new(), got);
    while rest.len() >= 5 {
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        let end = (5 + len).min(rest.len());
        records.push((rest[0], len, rest[5..end].to_vec()));
        rest = &rest[end..];
    }
    let lengths = records.iter().map(|r| r.1.to_string()).collect::<Vec<_>>().join(",");
    match records.first() {
        Some((21, ..)) if records.last().is_some_and(|r| r.0 == 21 && r.1 == 2) => format!("alert {}", records.last().unwrap().2[1]),
        Some((22, _, body)) => {
            let hello = &body[4..];
            let sid_len = hello[34] as usize;
            if hello[2..34] == [0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c] {
                return format!("retry {lengths}");
            }
            let suite = &hello[35 + sid_len..37 + sid_len];
            let sid: String = hello[35..36.min(35 + sid_len)].iter().map(|b| format!("{b:02x}")).collect();
            format!("flight suite={:02x}{:02x} sid={sid}/{sid_len} {lengths}", suite[0], suite[1])
        }
        _ => format!("other {}", records.iter().map(|r| format!("{}/{}", r.0, r.1)).collect::<Vec<_>>().join(",")),
    }
}

/// Every ClientHello of the matrix the image answered (`tests/files/k8s-webhook-tls13/second_hello.txt`, recorded by
/// `probe.py` from `mockserver-webhook` 9.2.0): a first ClientHello with or without a cookie, and a second
/// one after a HelloRetryRequest that sends no cookie (checked and answered as a first one, whatever its random, session
/// id and suites), echoes the cookie (random, session id and suites must be the first's), or sends another, an empty or
/// a cut one, against our server.
#[tokio::test]
async fn k8s_webhook_dsa_pair_answers_the_client_hello_matrix_as_the_image_does() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = serve(CERT_2048, KEY_2048_PKCS8).await;
    let first = MatrixHello(vec![("ck", "none"), ("sh", "empty"), ("sc", "ok"), ("su", "same"), ("gr", "29"), ("rn", "same"), ("sd", "same")]);
    let (mut wrong, mut total) = (Vec::new(), 0);
    for line in include_str!("../files/k8s-webhook-tls13/second_hello.txt").lines() {
        let (case, expected) = line.split_once(" => ").unwrap();
        let mut words = case.split(' ');
        let kind = words.next().unwrap();
        let dims = MatrixHello(words.map(|w| w.split_once('=').unwrap()).collect());
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", server.port())).await.unwrap();
        let mut got = Vec::new();
        if kind == "first" {
            tcp.write_all(&dims.record(&[])).await.unwrap();
        } else {
            tcp.write_all(&first.record(&[])).await.unwrap();
            let mut head = vec![0u8; 5 + 193 + 6];
            tcp.read_exact(&mut head).await.unwrap();
            let cookie = retry_cookie(&head);
            tcp.write_all(&[vec![0x14, 3, 3, 0, 1, 1], dims.record(&cookie)].concat()).await.unwrap();
            got.extend_from_slice(&head);
        }
        // an idle second ends the read: a HelloRetryRequest leaves the server waiting for the second ClientHello
        loop {
            let mut chunk = [0u8; 4096];
            match tokio::time::timeout(std::time::Duration::from_secs(if expected.starts_with("retry") { 1 } else { 5 }), tcp.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => got.extend_from_slice(&chunk[..n]),
                _ => break,
            }
        }
        if kind == "second" {
            got.drain(..5 + 193 + 6);
        }
        total += 1;
        let actual = matrix_outcome(&got);
        if actual != expected {
            wrong.push(format!("{line}\n    ours: {actual}"));
        }
    }
    server.stop(std::time::Duration::ZERO).await;
    assert!(wrong.is_empty(), "{} of {total} differ from the image:\n{}", wrong.len(), wrong.join("\n"));
}

/// The image's suite order, TLS_AES_256_GCM_SHA384 > TLS_AES_128_GCM_SHA256 > TLS_CHACHA20_POLY1305_SHA256 whatever the client's;
/// a client with only another suite, or only the schemes TLS 1.2 has, gets the plain alert; a TLS 1.2 DHE-DSS suite listed
/// beside TLS 1.3 does not bring the TLS 1.2 handshake back; every scheme TLS 1.3 allows brings the encrypted one.
#[tokio::test]
async fn k8s_webhook_dsa_pair_picks_the_tls13_suite_and_scheme_as_the_image_does() {
    let server = serve(CERT_2048, KEY_2048_PKCS8).await;
    for (suites, picked) in [
        ("TLS_CHACHA20_POLY1305_SHA256", "TLS_CHACHA20_POLY1305_SHA256"),
        ("TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"),
        ("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384"),
        ("TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"),
    ] {
        let out = s_client_with(server.port(), "DHE-DSS-AES128-SHA", "ed25519", &["-tls1_3", "-ciphersuites", suites, "-msg"]).await;
        assert!(out.contains(&format!("Cipher is {picked}")), "{suites}: {out}");
        assert_eq!(server_messages(&out).last().map(String::as_str), Some("Alert 0002 fatal handshake_failure"), "{suites}: {out}");
    }
    for sigalgs in ["RSA-PSS+SHA256", "RSA-PSS+SHA384", "RSA-PSS+SHA512", "rsa_pss_pss_sha256", "ECDSA+SHA256", "ECDSA+SHA384", "ECDSA+SHA512", "ed25519", "ed448", "RSA+SHA256:ed448"] {
        let out = s_client_with(server.port(), "DHE-DSS-AES128-SHA", sigalgs, &["-tls1_3", "-msg"]).await;
        let messages = server_messages(&out);
        assert!(messages.iter().any(|m| m.ends_with("EncryptedExtensions")) && messages.last().is_some_and(|m| m.ends_with("fatal handshake_failure")), "{sigalgs}: {out}");
    }
    // the plain alert: no suite, or only TLS 1.2's schemes (also with TLS 1.2 DHE-DSS listed and its DSA scheme)
    for (sigalgs, args) in [
        ("RSA-PSS+SHA256", vec!["-tls1_3", "-ciphersuites", "TLS_AES_128_CCM_SHA256"]),
        ("RSA+SHA256", vec!["-tls1_3"]),
        ("DSA+SHA256:RSA+SHA256", vec![]),
        ("DSA+SHA256:ECDSA+SHA1", vec![]),
    ] {
        let out = s_client_with(server.port(), "DHE-DSS-AES128-SHA", sigalgs, &[args, vec!["-msg"]].concat()).await;
        assert_eq!(server_messages(&out), ["Alert 0002 fatal handshake_failure"], "{sigalgs}: {out}");
    }
    // a TLS 1.3 scheme in the list brings the TLS 1.3 handshake, not the DSA one, to a client offering both versions
    let out = s_client_with(server.port(), "DHE-DSS-AES128-SHA", "DSA+SHA256:RSA-PSS+SHA256", &["-msg"]).await;
    assert!(server_messages(&out).iter().any(|m| m.ends_with("EncryptedExtensions")), "{out}");
    server.stop(std::time::Duration::ZERO).await;
}

/// A client offering no DHE-DSS suite (rustls' default: TLS 1.3 and the ECDHE suites) gets a `handshake_failure` alert,
/// as the JDK sends, not a closed connection.
#[tokio::test]
async fn k8s_webhook_dsa_pair_refuses_other_clients_with_handshake_failure() {
    let server = serve(CERT_1024, KEY_1024).await;
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", server.port())).await.unwrap();
    let e = tokio_rustls::TlsConnector::from(Arc::new(client)).connect(ServerName::try_from("localhost").unwrap(), tcp).await.map(|_| ()).unwrap_err();
    assert!(format!("{e:?}").contains("HandshakeFailure"), "{e:?}");
    server.stop(std::time::Duration::ZERO).await;
}

/// The handshake message of a ClientHello record, split at `cuts` (offsets into the message) over as many handshake
/// records, each its own TLS record.
fn fragment(hello_record: &[u8], cuts: &[usize]) -> Vec<Vec<u8>> {
    let message = &hello_record[5..];
    let points: Vec<usize> = std::iter::once(0).chain(cuts.iter().copied()).chain(std::iter::once(message.len())).collect();
    points.windows(2).map(|w| record_of(22, &message[w[0]..w[1]])).collect()
}

fn record_of(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind, 3, 1];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn parse_records(got: &[u8]) -> (Vec<(u8, usize)>, Option<u8>) {
    let (mut records, mut alert, mut rest) = (Vec::new(), None, got);
    while rest.len() >= 5 {
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        records.push((rest[0], len));
        if rest[0] == 21 && len == 2 {
            alert = Some(rest[6]);
        }
        rest = &rest[(5 + len).min(rest.len())..];
    }
    (records, alert)
}

/// Sends `chunks` with `pause` between them (the server waits for the rest of a hello that arrives in pieces), then
/// reads until the server closes.
async fn records_after_chunks(port: u16, chunks: &[Vec<u8>], pause: std::time::Duration) -> (Vec<(u8, usize)>, Option<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    for chunk in chunks {
        // an alert may close the connection before the last chunk is written
        if tcp.write_all(chunk).await.is_err() {
            break;
        }
        tokio::time::sleep(pause).await;
    }
    let mut got = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), tcp.read_to_end(&mut got)).await;
    parse_records(&got)
}

/// A TLS 1.2 ClientHello record by hand (no `supported_versions`): one DHE-DSS CBC suite, ffdhe2048, the given schemes.
fn client_hello_12(schemes: &[u16]) -> Vec<u8> {
    let sized = |items: Vec<u8>| [(items.len() as u16).to_be_bytes().to_vec(), items].concat();
    let mut extensions = ext(0x000d, &sized(schemes.iter().flat_map(|s| s.to_be_bytes()).collect()));
    extensions.extend(ext(0x000a, &sized(256u16.to_be_bytes().to_vec())));
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x22; 32]);
    body.push(0);
    body.extend_from_slice(&sized(0x0032u16.to_be_bytes().to_vec()));
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&sized(extensions));
    let mut message = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
    message.extend_from_slice(&body);
    record_of(22, &message)
}

/// A ClientHello split over 2 and 3 records, with the handshake header itself cut (after 1 to 5 bytes), one byte per
/// record, and arriving in pieces with pauses, is answered as the whole one for each outcome of the suite, scheme and
/// group tests (hand-made ClientHellos, probed against `mockserver-webhook` 9.2.0).
#[tokio::test]
async fn k8s_webhook_dsa_pair_reads_a_client_hello_split_over_records_as_a_whole_one() {
    let server = serve(CERT_2048, KEY_2048_PKCS8).await;
    let port = server.port();
    let sid = [0x11u8; 32];
    let flight = |hello: usize| (vec![(22, hello), (20, 1), (23, 67), (23, 35)], None);
    // (records expected, alert)
    type Expected = (Vec<(u8, usize)>, Option<u8>);
    let hellos: Vec<(&str, Vec<u8>, Expected)> = vec![
        ("x25519", client_hello(&[29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1302, &sid), flight(122)),
        ("x25519 without a session id", client_hello(&[29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1302, &[]), (vec![(22, 90), (23, 67), (23, 35)], None)),
        ("hybrid 1216 bytes", client_hello(&[0x11ec], Some(&[(0x11ec, vec![1; 1216])]), 0x0804, 0x1302, &sid), flight(1210)),
        ("ffdhe2048", client_hello(&[256], Some(&[(256, vec![7; 255])]), 0x0804, 0x1302, &sid), flight(346)),
        ("x25519 zero", client_hello(&[29], Some(&[(29, vec![0; 32])]), 0x0804, 0x1302, &sid), (vec![(22, 122), (21, 2)], Some(80))),
        ("p256 off the curve", client_hello(&[23], Some(&[(23, [vec![4], vec![1; 64]].concat())]), 0x0804, 0x1302, &sid), (vec![(22, 155), (21, 2)], Some(80))),
        ("empty share", client_hello(&[29], Some(&[(29, vec![])]), 0x0804, 0x1302, &sid), (vec![(21, 2)], Some(50))),
        ("no key_share extension", client_hello(&[29], None, 0x0804, 0x1302, &sid), (vec![(21, 2)], Some(109))),
        ("no suite in common", client_hello(&[29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1304, &sid), (vec![(21, 2)], Some(40))),
        ("no scheme TLS 1.3 allows", client_hello(&[29], Some(&[(29, vec![1; 32])]), 0x0202, 0x1302, &sid), (vec![(21, 2)], Some(40))),
        ("no group in common", client_hello(&[0x11eb], Some(&[(0x11eb, vec![1; 100])]), 0x0804, 0x1302, &sid), (vec![(21, 2)], Some(10))),
        // TLS 1.2: the DSA pre-checks read the reassembled hello too
        ("TLS 1.2 handshake_failure", client_hello_12(&[0x0202]), (vec![(21, 2)], Some(40))),
        // the flight is ServerHello and Certificate: 1212 bytes with this test's certificate (1210 with the probe's)
        ("TLS 1.2 internal_error", client_hello_12(&[0x0202, 0x0401]), (vec![(22, 1212), (21, 2)], Some(80))),
    ];
    for (name, hello, expected) in hellos {
        assert_eq!(records_after(port, hello.clone()).await, expected, "{name}: whole");
        let len = hello.len() - 5;
        let mut cuts: Vec<Vec<usize>> = vec![vec![len / 2], vec![len - 1], vec![1], vec![2], vec![3], vec![4], vec![5], vec![1, 2], vec![2, 5], vec![3, len / 2], vec![len / 3, 2 * len / 3], vec![1, 2, 3, 4]];
        cuts.push((1..len).collect());
        for cut in cuts {
            let chunks = fragment(&hello, &cut);
            let got = records_after_chunks(port, &[chunks.concat()], std::time::Duration::ZERO).await;
            assert_eq!(got, expected, "{name}: {} records, one write", cut.len() + 1);
        }
        // one record per write, the rest of the hello late
        let got = records_after_chunks(port, &fragment(&hello, &[3, len / 2]), std::time::Duration::from_millis(150)).await;
        assert_eq!(got, expected, "{name}: pieces with pauses");
        // a hello cut in the middle of a record
        let chunks = fragment(&hello, &[len / 2]).concat();
        let got = records_after_chunks(port, &[chunks[..9].to_vec(), chunks[9..chunks.len() - 3].to_vec(), chunks[chunks.len() - 3..].to_vec()], std::time::Duration::from_millis(100)).await;
        assert_eq!(got, expected, "{name}: cut inside a record");
    }
    server.stop(std::time::Duration::ZERO).await;
}

/// What the image does with the records of a split ClientHello that no client sends (probed against 9.2.0): a record
/// of no bytes, or of any type but handshake, between the pieces is `unexpected_message`; a hello message of more than
/// 32768 bytes, or a record of more than 33088, is `unexpected_message` as soon as its length is read; a ClientHello
/// takes up to 32768 bytes in any number of records; what follows it in its last record or after it is ignored.
#[tokio::test]
async fn k8s_webhook_dsa_pair_bounds_a_split_client_hello_as_the_image_does() {
    let server = serve(CERT_2048, KEY_2048_PKCS8).await;
    let port = server.port();
    let sid = [0x11u8; 32];
    let flight = (vec![(22, 122), (20, 1), (23, 67), (23, 35)], None);
    let alert10 = (vec![(21, 2)], Some(10));
    let plain = client_hello(&[29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1302, &sid);
    let message = plain[5..].to_vec();
    let no_pause = std::time::Duration::ZERO;
    let padded = |body_len: usize| {
        // the padding extension adds 4 bytes of header
        let pad = body_len - (message.len() - 4) - 4;
        client_hello_padded(&[29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1302, &sid, 0x22, None, pad)
    };
    let (a, b) = message.split_at(50);
    for (name, chunks) in [
        ("an empty record first", vec![record_of(22, &[]), record_of(22, &message)]),
        ("an empty record between", vec![record_of(22, a), record_of(22, &[]), record_of(22, b)]),
        ("a ChangeCipherSpec between", vec![record_of(22, a), record_of(20, &[1]), record_of(22, b)]),
        ("an alert between", vec![record_of(22, a), record_of(21, &[1, 0]), record_of(22, b)]),
        ("application data between", vec![record_of(22, a), record_of(23, b"xx"), record_of(22, b)]),
    ] {
        assert_eq!(records_after_chunks(port, &[chunks.concat()], no_pause).await, alert10, "{name}");
    }
    // the message body at the 32768 cap in 1, 2 and 3 records, and one byte over
    for body in [32768usize, 32769] {
        let hello = padded(body);
        let expected = if body == 32768 { flight.clone() } else { alert10.clone() };
        for cuts in [vec![], vec![16000], vec![10000, 20000], vec![3, 40]] {
            let got = records_after_chunks(port, &[fragment(&hello, &cuts).concat()], no_pause).await;
            assert_eq!(got, expected, "body {body} in {} records", cuts.len() + 1);
        }
    }
    // the length alone decides, before the rest arrives
    let got = records_after_chunks(port, &[record_of(22, &[1, 0, 0x80, 1])], no_pause).await;
    assert_eq!(got, alert10, "header claiming 32769");
    // a record past 33088 bytes is refused from its header; at 33088 (the message and trailing bytes) it is read
    let got = records_after_chunks(port, &[vec![22, 3, 1, 0x81, 0x41, 1, 0]], no_pause).await;
    assert_eq!(got, alert10, "record of 33089");
    let mut long = message.clone();
    long.resize(33088, 0);
    assert_eq!(records_after_chunks(port, &[record_of(22, &long)], no_pause).await, flight, "record of 33088");
    let mut long = message.clone();
    long.resize(16385, 0);
    assert_eq!(records_after_chunks(port, &[record_of(22, &long)], no_pause).await, flight, "record of 16385");
    // one byte per record
    let tiny: Vec<u8> = message.iter().flat_map(|b| record_of(22, &[*b])).collect();
    assert_eq!(records_after_chunks(port, &[tiny], no_pause).await, flight, "one byte per record");
    // what follows the hello is ignored
    let mut trailing = b.to_vec();
    trailing.extend_from_slice(&[0x14, 0, 0, 0]);
    assert_eq!(records_after_chunks(port, &[[record_of(22, a), record_of(22, &trailing)].concat()], no_pause).await, flight, "trailing in the last record");
    assert_eq!(records_after_chunks(port, &[[record_of(22, a), record_of(22, b), record_of(22, &[0x14, 0, 0, 0])].concat()], no_pause).await, flight, "a record after the hello");
    // a first record that is not a handshake record is not read as a hello: rustls answers as before
    let (records, _) = records_after_chunks(port, &[record_of(23, b"hello?")], no_pause).await;
    assert!(records.iter().all(|r| r.0 == 21), "{records:?}");
    server.stop(std::time::Duration::ZERO).await;
}

/// The second ClientHello of a retry arrives in pieces too (probed against 9.2.0): one ChangeCipherSpec at most, ahead of
/// it, and the same record rules as the first.
#[tokio::test]
async fn k8s_webhook_dsa_pair_reads_a_split_second_client_hello_after_a_retry() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = serve(CERT_2048, KEY_2048_PKCS8).await;
    let sid = [0x11u8; 32];
    let second = client_hello_with(&[0x11eb, 29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1302, &sid, 0x22, None);
    let message = second[5..].to_vec();
    let ccs = record_of(20, &[1]);
    let flight = (vec![(22, 193), (20, 1), (22, 122), (20, 1), (23, 67), (23, 35)], None);
    let alert10 = (vec![(22, 193), (20, 1), (21, 2)], Some(10));
    let (a, b) = message.split_at(50);
    let mut oversize = client_hello_padded(&[0x11eb, 29], Some(&[(29, vec![1; 32])]), 0x0804, 0x1302, &sid, 0x22, None, 40000)[5..].to_vec();
    oversize.truncate(40000 + 100);
    let mut trailing = b.to_vec();
    trailing.extend_from_slice(&[0x14, 0, 0, 0]);
    // (records expected, alert)
    type Expected = (Vec<(u8, usize)>, Option<u8>);
    let cases: Vec<(&str, Vec<Vec<u8>>, Expected)> = vec![
        ("whole", vec![ccs.clone(), record_of(22, &message)], flight.clone()),
        ("2 records", [vec![ccs.clone()], fragment(&second, &[50])].concat(), flight.clone()),
        ("3 records", [vec![ccs.clone()], fragment(&second, &[1, 60])].concat(), flight.clone()),
        ("header cut after 2", [vec![ccs.clone()], fragment(&second, &[2])].concat(), flight.clone()),
        ("header cut after 1 and 3", [vec![ccs.clone()], fragment(&second, &[1, 3])].concat(), flight.clone()),
        ("no ChangeCipherSpec, 2 records", fragment(&second, &[50]), flight.clone()),
        ("one byte per record", [vec![ccs.clone()], message.iter().map(|b| record_of(22, &[*b])).collect()].concat(), flight.clone()),
        ("trailing in the last record", vec![ccs.clone(), record_of(22, a), record_of(22, &trailing)], flight.clone()),
        ("a ChangeCipherSpec between the pieces", vec![ccs.clone(), record_of(22, a), ccs.clone(), record_of(22, b)], alert10.clone()),
        ("an empty record between the pieces", vec![ccs.clone(), record_of(22, a), record_of(22, &[]), record_of(22, b)], alert10.clone()),
        ("two ChangeCipherSpecs", vec![ccs.clone(), ccs.clone(), record_of(22, &message)], alert10.clone()),
        ("a ChangeCipherSpec of another body", vec![record_of(20, &[2]), record_of(22, &message)], alert10.clone()),
        ("a message of 40000 bytes", vec![ccs.clone(), record_of(22, &oversize[..16000]), record_of(22, &oversize[16000..])], alert10.clone()),
    ];
    for (name, chunks, expected) in cases {
        for pause in [std::time::Duration::ZERO, std::time::Duration::from_millis(60)] {
            let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", server.port())).await.unwrap();
            tcp.write_all(&client_hello(&[0x11eb, 29], Some(&[(0x11eb, vec![1; 100])]), 0x0804, 0x1302, &sid)).await.unwrap();
            let mut first = vec![0u8; 5 + 193 + 6];
            tcp.read_exact(&mut first).await.unwrap();
            for chunk in &chunks {
                if tcp.write_all(chunk).await.is_err() {
                    break;
                }
                tokio::time::sleep(pause).await;
            }
            let mut got = first;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), tcp.read_to_end(&mut got)).await;
            assert_eq!(parse_records(&got), expected, "{name} (pause {pause:?})");
        }
    }
    server.stop(std::time::Duration::ZERO).await;
}

fn key_der(pem: &str) -> Vec<u8> {
    match tls::load_private_key(pem).unwrap().der {
        rustls_pki_types::PrivateKeyDer::Pkcs1(der) => der.secret_pkcs1_der().to_vec(),
        rustls_pki_types::PrivateKeyDer::Pkcs8(der) => der.secret_pkcs8_der().to_vec(),
        _ => unreachable!(),
    }
}

/// Both parse forms (traditional and PKCS#8) of DSA keys sign what the key's public half verifies.
#[test]
fn k8s_webhook_dsa_key_forms_sign_and_verify() {
    use k8s_webhook::dsa::{DSA_SHA224, DSA_SHA256};
    for pem in [KEY_1024, KEY_2048_PKCS8] {
        let key = DsaKey::from_der(&key_der(pem)).unwrap();
        for scheme in [DSA_SHA224, DSA_SHA256] {
            let signature = key.sign_with_system_random(scheme, b"message").unwrap();
            assert!(key.verify(scheme, b"message", &signature));
            assert!(!key.verify(scheme, b"other message", &signature));
        }
    }
    // an EC key's PKCS#8 form is not a DSA key
    assert!(DsaKey::from_der(&key_der(&rcgen::KeyPair::generate().unwrap().serialize_pem())).is_none());
}

const KEY_1024: &str = "-----BEGIN DSA PRIVATE KEY-----
MIIBygIBAAKBgQD1rBoR+/buicyJjyzbwH2yUOvLt4Vo8/FFl8CCA+VNZ0RNNm7J
McoZiZ+1Li4y3kQjSs9NfqCM4zA/wYLUw2HA0Ng4oCrW4Z3iqc1F5KRPP4oLF5z5
hA/ZueqHJ7lFJkKWXW3RjgYRQJ9L6kM3h5Q66gdWVZY8odluQE0EWY+HSwIdAJP1
pYofTK0rDcc1KN4Z/iVtNqdMvaZUY6YF22ECgYB6CDQYWm2rpUBVNYqMq5nWFq27
TbOycfH40wAfBB72bym5O23G1usMxVfoxLN0tVyXILLOSEmuY8ARHlpXQNwbeiLx
SUC3YQkFxNR2XOJZaWIz10lsVzdKQJDb+YEy7SPXdh4qqIF/84jHOhoUWMEr0Vjs
H7wo+9DvX8yTV73jzAKBgBCoYtHL65J2+7DbuitU0VYDHFK6JXH+gAw0LiFV+ijZ
B3H2KzovfdH+oKgmuiYJztsqSX+iIMPPgALIi/sU8gJ3H4S9ufztiApCTuMuJXu+
ZuG0lWUTfwDnK/17JLVf67Ft5quBteMZhwM86NOSIv7s6muHp/J1R/TOICWhL/aL
Ahwt6s63bcOW10YXnkOLzdQiMESYFY1hPY42nyXy
-----END DSA PRIVATE KEY-----
";
const CERT_1024: &str = "-----BEGIN CERTIFICATE-----
MIIC3zCCAo2gAwIBAgIUXWhDBJwwVzSIjV+r5zX4VLUAbr4wCwYJYIZIAWUDBAMC
MBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAgFw0yNjExMDcwNzMxNDFaGA8yMTI2MTAx
NDA3MzE0MVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBvjCCATMGByqGSM44BAEw
ggEmAoGBAPWsGhH79u6JzImPLNvAfbJQ68u3hWjz8UWXwIID5U1nRE02bskxyhmJ
n7UuLjLeRCNKz01+oIzjMD/BgtTDYcDQ2DigKtbhneKpzUXkpE8/igsXnPmED9m5
6ocnuUUmQpZdbdGOBhFAn0vqQzeHlDrqB1ZVljyh2W5ATQRZj4dLAh0Ak/Wlih9M
rSsNxzUo3hn+JW02p0y9plRjpgXbYQKBgHoINBhabaulQFU1ioyrmdYWrbtNs7Jx
8fjTAB8EHvZvKbk7bcbW6wzFV+jEs3S1XJcgss5ISa5jwBEeWldA3Bt6IvFJQLdh
CQXE1HZc4llpYjPXSWxXN0pAkNv5gTLtI9d2HiqogX/ziMc6GhRYwSvRWOwfvCj7
0O9fzJNXvePMA4GEAAKBgBCoYtHL65J2+7DbuitU0VYDHFK6JXH+gAw0LiFV+ijZ
B3H2KzovfdH+oKgmuiYJztsqSX+iIMPPgALIi/sU8gJ3H4S9ufztiApCTuMuJXu+
ZuG0lWUTfwDnK/17JLVf67Ft5quBteMZhwM86NOSIv7s6muHp/J1R/TOICWhL/aL
o1MwUTAdBgNVHQ4EFgQUYZNTZtAdm0o2uDRa0rJTlv5mGGowHwYDVR0jBBgwFoAU
YZNTZtAdm0o2uDRa0rJTlv5mGGowDwYDVR0TAQH/BAUwAwEB/zALBglghkgBZQME
AwIDPwAwPAIcYZGcpLFq3rBmgjU+NEczN9fJDrpaAe7mR846pAIcQiaVQ8ImVfbZ
MsQQW/9rlTYVX/O9QYjLPmOeHQ==
-----END CERTIFICATE-----
";
const KEY_2048_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIICXQIBADCCAjUGByqGSM44BAEwggIoAoIBAQDKC+vuzZG68j4iEWjmqkelIXqE
vTD4e9KYfrpBpdIAdyEfeam7h9oPqVAnlTEee4bP3VL2el+rkpiVcRC3EYnjJXbu
Xh1E839qBHo5KQor4yWNzYugThsddpFRZraE1btIsP+CkpOlb06aXXm2u3FAFYtf
Nvo9fn1EPg9NQvopbpQDmqL8W3MPl2M0oA98FgTcUBNLWuo5Dt0KeUHfRCDgUEbB
DG94NeM6UcMXe/86gT3YchlrNq9BRkT1YfFrnWEm6hADPIPhVD3C3bJQ9cgUzo3e
HWZThMEqXlsHdlwjB/CYy8KnioKZdfivd8H0BFrF/cMxBSJYKDy/2BGbQteTAh0A
0YzFCIsXvKL0E3wS6f0QrkVcwxrdlB0w6dE4OwKCAQBx9wMQrGnRi+s8HYAlfh+d
5emG+skHJx6Kc8epVy6P2kBN1vVH97XMVn8gPVsPkyD+ZY1I9/f+cZJQItD4XqMo
UeSNzZIokfG6GWKoPglte+1hgKEL/yZpboieBRYUxPfQBgCZj2rCkN+3rrspniNc
xgBUmVKJdHY91jHv2iehlmdzLxO1cEj6JIEJZMOwcBghatMIC+5jckuWYbzRh1GE
l7ZHVhajCHoMphyvsl06H+uj0RAkvi4bqQaGIgq2V7bCMB6r132EHPKFrlYGNTIL
3hHKWZmxc5mTyztlNHfeksm3RkpsLcHy6xUV9oFyXT/JLjiTJNn26h6uKD9axpU9
BB8CHQC52MeIsM+J8rPfiVcELyC4H3e7P8oa7VvI6hjd
-----END PRIVATE KEY-----
";
const CERT_2048: &str = "-----BEGIN CERTIFICATE-----
MIIEZDCCBBGgAwIBAgIUetY8Z8tzVKtKNH7/xP8SzZb2lXwwCwYJYIZIAWUDBAMC
MBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAgFw0yNjExMDcwNzMxNDFaGA8yMTI2MTAx
NDA3MzE0MVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIDQjCCAjUGByqGSM44BAEw
ggIoAoIBAQDKC+vuzZG68j4iEWjmqkelIXqEvTD4e9KYfrpBpdIAdyEfeam7h9oP
qVAnlTEee4bP3VL2el+rkpiVcRC3EYnjJXbuXh1E839qBHo5KQor4yWNzYugThsd
dpFRZraE1btIsP+CkpOlb06aXXm2u3FAFYtfNvo9fn1EPg9NQvopbpQDmqL8W3MP
l2M0oA98FgTcUBNLWuo5Dt0KeUHfRCDgUEbBDG94NeM6UcMXe/86gT3YchlrNq9B
RkT1YfFrnWEm6hADPIPhVD3C3bJQ9cgUzo3eHWZThMEqXlsHdlwjB/CYy8KnioKZ
dfivd8H0BFrF/cMxBSJYKDy/2BGbQteTAh0A0YzFCIsXvKL0E3wS6f0QrkVcwxrd
lB0w6dE4OwKCAQBx9wMQrGnRi+s8HYAlfh+d5emG+skHJx6Kc8epVy6P2kBN1vVH
97XMVn8gPVsPkyD+ZY1I9/f+cZJQItD4XqMoUeSNzZIokfG6GWKoPglte+1hgKEL
/yZpboieBRYUxPfQBgCZj2rCkN+3rrspniNcxgBUmVKJdHY91jHv2iehlmdzLxO1
cEj6JIEJZMOwcBghatMIC+5jckuWYbzRh1GEl7ZHVhajCHoMphyvsl06H+uj0RAk
vi4bqQaGIgq2V7bCMB6r132EHPKFrlYGNTIL3hHKWZmxc5mTyztlNHfeksm3Rkps
LcHy6xUV9oFyXT/JLjiTJNn26h6uKD9axpU9A4IBBQACggEAHrfzXb+FI+tQqkFI
10+M0S4F+NEV9VUO2lO2HPvrW0cwnFabLaSgTMaIiZ8OUp9KUK96nMiBPeDjvti0
6izVurwEyRmfEFB/VNt9Pq7X4qTDaANJFhP0/4nCXx9fIxajYK3PFpGfxpSz8N4/
4AnSIau/JwMu1lrXZmn/wbTrLo9Kp/ZBjlGWCJOOlI6K9uvY227ODuL3n17EI8F2
Ax/05LdfyprRX9XGRCECijyBscjS3hQNHLh4+xaAyEIZBP9rfviwuPgOP/dy1TEf
xGOL/ncjBsnVp5ih2BWOH/R1Fm062w3hT4/jBEK7rKgh4xDPllSvxAzY4SG3qzco
N/NVwqNTMFEwHQYDVR0OBBYEFAk9kz7kwiTQFVNpNu/dxKd8U2VeMB8GA1UdIwQY
MBaAFAk9kz7kwiTQFVNpNu/dxKd8U2VeMA8GA1UdEwEB/wQFMAMBAf8wCwYJYIZI
AWUDBAMCA0AAMD0CHHy80V8J+AGPF6VLMMMQXvQDM6K2delzEcMNbbICHQC5Rpge
/9pyX75bgr8HFo9LAZJ4Kf9/AXA/QFHe
-----END CERTIFICATE-----
";

/// The CBC record layer on its own: what one side seals the other opens, any tampering (a flipped ciphertext bit, a
/// truncated or extended record, a wrong MAC, a wrong padding byte) is the one `DecryptError`, and a record of the
/// largest fragment survives.
#[test]
fn k8s_webhook_cbc_records_round_trip_and_reject_tampering_alike() {
    use k8s_webhook::cbc::{AES_128_CBC_SHA, AES_256_CBC_SHA256, AesCbc};
    use rustls::crypto::cipher::{InboundOpaqueMessage, OutboundChunks, OutboundPlainMessage};
    use rustls::{ContentType, ProtocolVersion};

    fn record(alg: &AesCbc, mac_key: &[u8], aes_key: &[u8], seq: u64, body: &[u8], tamper: impl Fn(&mut Vec<u8>)) -> Result<Vec<u8>, rustls::Error> {
        let mut sealer = alg.sealer(mac_key, aes_key);
        let mut opener = alg.opener(mac_key, aes_key);
        let chunks = [body];
        let sealed = sealer.encrypt(
            OutboundPlainMessage { typ: ContentType::ApplicationData, version: ProtocolVersion::TLSv1_2, payload: OutboundChunks::new(&chunks) },
            seq,
        )?;
        let encoded = sealed.encode();
        assert_eq!(sealer.encrypted_payload_len(body.len()), encoded.len() - 5);
        let mut wire = encoded[5..].to_vec();
        tamper(&mut wire);
        let opened = opener.decrypt(InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, &mut wire), seq)?;
        Ok(opened.payload.to_vec())
    }

    for (alg, mac_len, key_len) in [(&AES_128_CBC_SHA, 20, 16), (&AES_256_CBC_SHA256, 32, 32)] {
        let (mac_key, aes_key) = (vec![7u8; mac_len], vec![9u8; key_len]);
        // every length from empty across the block boundaries, and the largest fragment
        for len in (0..=70).chain([255, 256, 257, 16384]) {
            let body: Vec<u8> = (0..len).map(|i| i as u8).collect();
            assert_eq!(record(alg, &mac_key, &aes_key, 3, &body, |_| {}).unwrap(), body, "length {len}");
        }
        let body = vec![0x41u8; 100];
        let bad = |what: &str, tamper: &dyn Fn(&mut Vec<u8>)| {
            let e = record(alg, &mac_key, &aes_key, 3, &body, tamper).unwrap_err();
            assert!(matches!(e, rustls::Error::DecryptError), "{what}: {e:?}");
        };
        // a flipped bit anywhere: the IV, a data block, the MAC's block, the last (padding) block
        let total = record(alg, &mac_key, &aes_key, 3, &body, |_| {}).map(|_| 16 + (100 + mac_len + 1).div_ceil(16) * 16).unwrap();
        for at in [0, 5, 16, 50, total - mac_len - 1, total - 17, total - 1] {
            bad("bit flip", &|w| w[at] ^= 1);
        }
        bad("truncated by a block", &|w| w.truncate(w.len() - 16));
        bad("extended by a block", &|w| w.extend_from_slice(&[0u8; 16]));
        bad("not a whole number of blocks", &|w| w.truncate(w.len() - 1));
        bad("only the IV", &|w| w.truncate(16));
        bad("empty", &|w| w.clear());
        // another sequence number is another MAC
        let mut sealer = alg.sealer(&mac_key, &aes_key);
        let mut opener = alg.opener(&mac_key, &aes_key);
        let chunks = [&body[..]];
        let sealed = sealer
            .encrypt(OutboundPlainMessage { typ: ContentType::ApplicationData, version: ProtocolVersion::TLSv1_2, payload: OutboundChunks::new(&chunks) }, 1)
            .unwrap();
        let mut wire = sealed.encode()[5..].to_vec();
        assert!(matches!(
            opener.decrypt(InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, &mut wire), 2),
            Err(rustls::Error::DecryptError)
        ));
    }
}

/// The MAC of the CBC opener does the same number of hash compressions whatever the padding length (and for a bad
/// padding, which counts as none), and equals HMAC (Lucky13). Boundary lengths are those where the data
/// crosses a 64-byte block edge of the inner hash.
#[test]
fn k8s_webhook_cbc_mac_compressions_do_not_depend_on_the_padding() {
    use k8s_webhook::cbc::{AES_128_CBC_SHA, AES_256_CBC_SHA256, compressions};
    let aad = [7u8; 13];
    for (alg, key) in [(&AES_128_CBC_SHA, vec![3u8; 20]), (&AES_256_CBC_SHA256, vec![5u8; 32])] {
        // n is the record's plaintext length before the tag: data, padding; sizes around block edges of the inner hash
        for total in [48usize, 64 - 13, 64 - 12, 64 - 21, 64 - 22, 128 - 13, 128 - 21, 128 - 22, 300, 301, 1024 + 43, 1024 + 44] {
            let data: Vec<u8> = (0..total).map(|i| i as u8).collect();
            let mut counts = Vec::new();
            // data_len = total (a bad padding) and every valid padding length (1..=256) that leaves data
            for padding in std::iter::once(0).chain(1..=256usize) {
                if padding > total {
                    break;
                }
                let data_len = total - padding;
                let before = compressions();
                let mac = alg.constant_time_mac(&key, &aad, &data, data_len);
                counts.push(compressions() - before);
                let expected = alg.reference_mac(&key, &aad, &data[..data_len]);
                assert_eq!(mac, expected, "total {total} padding {padding}");
            }
            assert!(counts.windows(2).all(|w| w[0] == w[1]), "total {total}: compression counts differ: {counts:?}");
        }
    }
}

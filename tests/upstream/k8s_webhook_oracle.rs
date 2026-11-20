//! The admission webhook against upstream's own image: `k8s-webhook/oracle/exchanges.golden.json` holds what the
//! webhook oracle (`ORACLE_WEBHOOK_IMAGE` of `oracle.env`, `mockserver/mockserver-webhook:9.2.0`)
//! answered to each request of `k8s-webhook/oracle/cases.json` (recorded by `k8s-webhook/oracle/record.sh`, one
//! container per environment configuration; a case's body is `body` as UTF-8 or `bodyHex` as raw bytes). Each
//! request is replayed against
//! the `k8s-webhook` crate's server, configured from the same environment, and the status, the headers (all but
//! `Date`, names in their wire case, in order) and the body must be the same bytes.

use k8s_webhook::{SidecarInjectionConfig, WebhookServer, config, tls};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn load(name: &str) -> Value {
    let path = format!("{}/k8s-webhook/oracle/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

async fn start(env: &HashMap<String, String>) -> (WebhookServer, Arc<rustls::ClientConfig>) {
    k8s_webhook::log::silence();
    let sidecar: SidecarInjectionConfig = config::config_from_env(&|name| env.get(name).cloned());
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap().self_signed(&key).unwrap();
    let server_config = tls::server_config(vec![cert.der().clone()], tls::load_private_key(&key.serialize_pem()).unwrap().der).unwrap();
    let mut server = WebhookServer::bind("127.0.0.1:0".parse().unwrap(), server_config, sidecar).await.unwrap();
    server.start();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (server, Arc::new(client))
}

/// The request as `record.py` sends it, and the response as it keeps it: (status, headers without `Date`, body).
async fn exchange(port: u16, client: &Arc<rustls::ClientConfig>, case: &Value) -> (u64, Vec<(String, String)>, String) {
    let method = case["method"].as_str().unwrap();
    let path = case["path"].as_str().unwrap();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n").into_bytes();
    let body: Option<Vec<u8>> = match case["bodyHex"].as_str() {
        Some(hex) => Some((0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()),
        None => case["body"].as_str().map(|b| b.as_bytes().to_vec()),
    };
    match body {
        Some(body) => {
            request.extend_from_slice(format!("Content-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes());
            request.extend_from_slice(&body);
        }
        None => request.extend_from_slice(b"\r\n"),
    }
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let mut stream = tokio_rustls::TlsConnector::from(client.clone()).connect(name, tcp).await.unwrap();
    stream.write_all(&request).await.unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw).await;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("response head");
    let head = String::from_utf8(raw[..split].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
    let headers: Vec<(String, String)> = lines
        .map(|l| l.split_once(": ").unwrap())
        .filter(|(k, _)| !k.eq_ignore_ascii_case("date"))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    (status, headers, String::from_utf8(raw[split + 4..].to_vec()).unwrap())
}

#[tokio::test]
async fn k8s_webhook_answers_as_upstream_image() {
    let cases = load("cases.json");
    let golden = load("exchanges.golden.json");
    let by_name: HashMap<&str, &Value> = cases["cases"].as_array().unwrap().iter().map(|c| (c["name"].as_str().unwrap(), c)).collect();
    // `k8s-webhook/oracle/skips-rs.txt`: `<config>/<case>  # <reason>`, exchanges that do not
    // match the oracle yet; a listed exchange must still differ.
    let skips: HashMap<String, String> = std::fs::read_to_string(format!("{}/k8s-webhook/oracle/skips-rs.txt", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (entry, reason) = l.split_once('#').unwrap_or_else(|| panic!("skips-rs.txt: no `# <reason>` on {l:?}"));
            (entry.trim().to_string(), reason.trim().to_string())
        })
        .collect();
    let mut failures = Vec::new();
    let mut checked = 0;
    for (config_name, env) in cases["configs"].as_object().unwrap() {
        let env: HashMap<String, String> = env.as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect();
        let (server, client) = start(&env).await;
        for recorded in golden.as_array().unwrap().iter().filter(|e| e["config"] == config_name.as_str()) {
            let name = recorded["name"].as_str().unwrap();
            let (status, headers, body) = exchange(server.port(), &client, by_name[name]).await;
            let expected = &recorded["response"];
            let expected_headers: Vec<(String, String)> = expected["headers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| (h[0].as_str().unwrap().to_string(), h[1].as_str().unwrap().to_string()))
                .collect();
            let differs = status != expected["status"].as_u64().unwrap() || headers != expected_headers || body != expected["body"].as_str().unwrap();
            if let Some(reason) = skips.get(&format!("{config_name}/{name}")) {
                if !differs {
                    failures.push(format!("{config_name}/{name} matches now: remove it from skips-rs.txt ({reason})"));
                }
            } else if differs {
                failures.push(format!(
                    "{config_name}/{name}:\n  expected {} {:?} {}\n  actual   {status} {headers:?} {body}",
                    expected["status"], expected_headers, expected["body"]
                ));
            }
            checked += 1;
        }
        server.stop(std::time::Duration::ZERO).await;
    }
    assert!(checked >= 30, "only {checked} exchanges replayed");
    assert!(failures.is_empty(), "{} of {checked} exchanges differ:\n{}", failures.len(), failures.join("\n"));
}

/// A server whose key store holds `key_pem` for a fresh self-signed EC certificate, and a client trusting that
/// certificate: the outcome of one handshake.
async fn handshake_with_key(key_pem: &str) -> std::io::Result<()> {
    k8s_webhook::log::silence();
    let cert_key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap().self_signed(&cert_key).unwrap();
    let server_config = tls::server_config(vec![cert.der().clone()], tls::load_private_key(key_pem).unwrap().der).unwrap();
    let mut server = WebhookServer::bind("127.0.0.1:0".parse().unwrap(), server_config, SidecarInjectionConfig::default()).await.unwrap();
    server.start();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", server.port())).await.unwrap();
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let outcome = tokio_rustls::TlsConnector::from(Arc::new(client)).connect(name, tcp).await.map(|_| ());
    server.stop(std::time::Duration::ZERO).await;
    outcome
}

/// As the image's PKCS12 key store, nothing checks that the key belongs to the certificate: an EC key that is not
/// the EC certificate's signs the handshake, and the client rejects the signature (OpenSSL: `bad signature`).
#[tokio::test]
async fn k8s_webhook_key_of_another_certificate_signs_and_the_client_rejects_it() {
    let other = rcgen::KeyPair::generate().unwrap();
    let e = handshake_with_key(&other.serialize_pem()).await.unwrap_err();
    let text = format!("{e:?}");
    assert!(text.contains("BadSignature"), "{text}");
}

/// A key of another type than the certificate's (here PKCS#1 RSA for an EC certificate) loads; the image's
/// `SSLEngine` then finds no usable entry and closes the connection without an alert.
#[tokio::test]
async fn k8s_webhook_key_of_another_type_loads_and_each_handshake_is_closed() {
    let e = handshake_with_key(RSA_1024).await.unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof, "{e:?}");
}

/// A traditional DSA key loads (BouncyCastle reads it, the PKCS12 key store takes it), and every handshake is closed
/// without an alert, as the image's are for a client offering no DHE-DSS suite.
#[tokio::test]
async fn k8s_webhook_dsa_key_loads_and_each_handshake_is_closed() {
    assert_eq!(tls::load_private_key(DSA_1024).unwrap().algorithm, "DSA");
    let e = handshake_with_key(DSA_1024).await.unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof, "{e:?}");
}

const RSA_1024: &str = "-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDMp4bWnowyXfypN9WVmhmzGu9BYFkRvAS4pkcgX5VanfPDYmYe
buoPfmd5k+S73f9kX6SNO4BRUbimESytK7uaE3DO8jxwyzLdRZNLWDrzUhE8zBIv
Kg5FeKH4UncOjIPSZGjDNa0x4Iz01vWMqFb/+/YMs3EnzE9trQqac8yGtwIDAQAB
AoGARiby+KS2iBlhn5vtEfAV+Sg1dWKShZq+v5D39qftKXfVdFdJjAsXHqKE088X
bDKn9f83B9aqoLVzpzFh8CZ6krOkb+nveCi6e650omLuviGGANHS7vuaV130tAXb
b9mmkv1+s13CzaVvKEJLT2mlXJdqJY06nQ2hgBd80+8xsrECQQD6Sh2zRBytnT7m
iV48a0KH754aa/dvC9CSs5y3o7hPVQA1mRQcMbHiljtvu9cB4TyV5KwFGQ7halW4
tGHybRYpAkEA0VLdzFOvbOyM3lKtSZARmk2IxV3HV4jYGqJuCUy5oSxxhoDROUv2
9VnbcqYMysqciuaww6y0qyRjKjc1cJGR3wJBAOs/CldaJ5JO/7XzWy1yqx/Vakbv
P6uR8UJRq3U3Xp7CB+ZYsPwnAUk1ZzwH03ii2S0Rt1U7Ti80oMlwUbdoLLECQQCc
To7FRzBV3AYM9hvkNKqQWJlrF+4FFXCZ4vTcCOkMy40ybPrPGESfTawq3ofq3oUq
y7zvQQXgTlmmaneDSZBtAkAkRTk29ezEYWgC2Za9XLS5gyTAC34437jBnJizxh5n
JIB1kXlAP4XxWngegFfhFOOhMKaNCeIISR7ZWlgce5AS
-----END RSA PRIVATE KEY-----
";

const DSA_1024: &str = "-----BEGIN DSA PRIVATE KEY-----
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

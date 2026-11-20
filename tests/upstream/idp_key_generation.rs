//! Not a port: an OIDC or SAML provider's signing key is generated while the control-plane request is
//! handled, which takes a 4096-bit RSA key up to a second. That work must leave the async worker, so the server's
//! other connections are still answered meanwhile. The server runs on a runtime with a single worker: had the
//! generation stayed on it, nothing else could be answered until it finished.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// One request on its own connection; the instant its answer was read in full.
fn call(port: u16, path: &str, body: &str) -> Instant {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "PUT {path} HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw);
    assert!(text.starts_with("HTTP/1.1 20"), "{path} answered {text}");
    Instant::now()
}

/// While `path` generates its key, status calls keep being answered: the longest stretch without an answer, from the
/// generating call's start to its end, against that call's duration.
fn stall_during(port: u16, path: &'static str, body: &'static str) -> (Duration, Duration) {
    let start = Instant::now();
    let generating = std::thread::spawn(move || call(port, path, body));
    let mut answered = vec![start];
    while !generating.is_finished() {
        answered.push(call(port, "/mockserver/status", ""));
    }
    let end = generating.join().unwrap();
    answered.retain(|at| *at <= end);
    answered.push(end);
    let longest = answered.windows(2).map(|w| w[1] - w[0]).max().unwrap();
    (longest, end - start)
}

async fn assert_answers_meanwhile(path: &'static str, body: &'static str) {
    let running = crate::common::start(&[]).await;
    let port = running.port;
    let rounds = tokio::task::spawn_blocking(move || {
        // A busy machine can stall a status call on its own: one round in three with no stall is enough, while a
        // generation on the worker stalls every round for nearly its whole duration.
        let mut rounds = Vec::new();
        for _ in 0..3 {
            let (longest, total) = stall_during(port, path, body);
            rounds.push((longest, total));
            if longest * 2 < total {
                break;
            }
        }
        rounds
    })
    .await
    .unwrap();
    running.server.shutdown().await;
    assert!(rounds.iter().any(|(longest, total)| *longest * 2 < *total), "{path}: no status answer while the key was generated (longest gap, call duration): {rounds:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn oidc_key_generation_leaves_the_worker() {
    assert_answers_meanwhile("/mockserver/oidc", r#"{"signingAlgorithm": "RS512"}"#).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn saml_key_generation_leaves_the_worker() {
    assert_answers_meanwhile("/mockserver/saml", r#"{"signingAlgorithm": "RS512"}"#).await;
}

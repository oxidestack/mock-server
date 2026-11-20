//! Ports of mockserver-core's `OidcAuthenticationHandlerTest` cases that need a remote key source: an
//! in-process mock-server server stands in for the identity provider that the upstream test serves with the JDK's
//! `HttpServer`, and the handler is exercised through the control plane of a second server.

use base64::Engine;
use p256::ecdsa::signature::Signer;
use serde_json::json;

use crate::common;

const AUDIENCE: &str = "mockserver-control-plane";
const KID: &str = "oidc-test-key";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn signing_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap()
}

/// `JWKGenerator.generateJWK`: the public key as a one-key JWK set.
fn jwks() -> serde_json::Value {
    let point = signing_key().verifying_key().to_encoded_point(false);
    json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": KID, "x": b64(point.x().unwrap()), "y": b64(point.y().unwrap())}]})
}

/// `JWTGenerator.signJWT(baseClaims())` with `iss` set to `issuer`.
fn token(issuer: &str) -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let header = json!({"alg": "ES256", "kid": KID, "typ": "JWT"});
    let claims = json!({
        "exp": now + 3600, "iat": now - 3600, "nbf": now - 3600, "iss": issuer, "aud": AUDIENCE,
        "sub": "service-account-ci", "scope": "mockserver.read mockserver.write"
    });
    let input = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
    let signature: p256::ecdsa::Signature = signing_key().sign(input.as_bytes());
    format!("{input}.{}", b64(&signature.to_bytes()))
}

/// A control-plane call with `Authorization: Bearer <token>`: its status and body.
async fn authenticated_call(port: u16, token: &str) -> (u16, String) {
    let token = token.to_string();
    tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let body = r#"{"httpRequest": {"path": "/x"}, "httpResponse": {"body": "x"}}"#;
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(
            s,
            "PUT /mockserver/expectation HTTP/1.1\r\nHost: localhost:{port}\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        (head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0), body.to_string())
    })
    .await
    .unwrap()
}

/// The identity provider: the discovery document at `/.well-known/openid-configuration` and the JWK set at `/jwks`.
async fn identity_provider() -> (common::Running, String) {
    let idp = common::start(&[]).await;
    let issuer = format!("http://127.0.0.1:{}", idp.port);
    common::expect(idp.port, &json!({
        "httpRequest": {"method": "GET", "path": "/.well-known/openid-configuration"},
        "httpResponse": {"headers": {"Content-Type": ["application/json"]}, "body": json!({"issuer": issuer, "jwks_uri": format!("{issuer}/jwks")}).to_string()}
    }))
    .await;
    common::expect(idp.port, &json!({
        "httpRequest": {"method": "GET", "path": "/jwks"},
        "httpResponse": {"headers": {"Content-Type": ["application/json"]}, "body": jwks().to_string()}
    }))
    .await;
    (idp, issuer)
}

/// `OidcAuthenticationHandlerTest.discoveryDocumentResolvesJwksUri`: with `controlPlaneOidcJwksUri` blank the handler
/// reads `jwks_uri` from the issuer's discovery document (plaintext `http` allowed to a loopback host) and verifies a
/// token signed by a key of that remote set.
#[tokio::test(flavor = "multi_thread")]
async fn discovery_document_resolves_jwks_uri() {
    let (_idp, issuer) = identity_provider().await;
    let server = common::start(&[
        ("controlPlaneOidcAuthenticationRequired", "true"),
        ("controlPlaneOidcIssuer", &issuer),
        ("controlPlaneOidcAudience", AUDIENCE),
    ])
    .await;
    let (status, body) = authenticated_call(server.port, &token(&issuer)).await;
    assert_eq!(status, 201, "authenticated through the discovered remote JWK set: {body}");
    let (status, body) = authenticated_call(server.port, &token("http://someone.else")).await;
    assert_eq!((status, body.as_str()), (401, "Unauthorized for control plane"), "the issuer claim is still checked");
}

/// A remote `controlPlaneOidcJwksUri` on a loopback host is fetched directly, without discovery.
#[tokio::test(flavor = "multi_thread")]
async fn loopback_remote_jwks_uri_verifies() {
    let (_idp, issuer) = identity_provider().await;
    let server = common::start(&[
        ("controlPlaneOidcAuthenticationRequired", "true"),
        ("controlPlaneOidcJwksUri", &format!("{issuer}/jwks")),
        ("controlPlaneOidcIssuer", "https://idp.example.com"),
        ("controlPlaneOidcAudience", AUDIENCE),
    ])
    .await;
    let (status, body) = authenticated_call(server.port, &token("https://idp.example.com")).await;
    assert_eq!(status, 201, "authenticated through the remote JWK set: {body}");
}

/// `OidcAuthenticationHandlerTest.plaintextRemoteJwksUriFailsClosed`: `http://` to a non-loopback host fails the
/// handler's construction, so every request is refused.
#[tokio::test(flavor = "multi_thread")]
async fn plaintext_remote_jwks_uri_fails_closed() {
    let server = common::start(&[
        ("controlPlaneOidcAuthenticationRequired", "true"),
        ("controlPlaneOidcJwksUri", "http://idp.example.com/jwks"),
        ("controlPlaneOidcIssuer", "https://idp.example.com"),
        ("controlPlaneOidcAudience", AUDIENCE),
    ])
    .await;
    let (status, body) = authenticated_call(server.port, &token("https://idp.example.com")).await;
    assert_eq!((status, body.as_str()), (401, "Unauthorized for control plane"));
}

/// `OidcAuthenticationHandlerTest.plaintextRemoteIssuerFailsClosed`: an `http://` issuer on a non-loopback host fails
/// the construction even with a valid file JWK set (here the token's `iss` matches, so nothing else could refuse it).
#[tokio::test(flavor = "multi_thread")]
async fn plaintext_remote_issuer_fails_closed() {
    let file = std::env::temp_dir().join(format!("mock-server-oidc-jwks-{}.json", std::process::id()));
    std::fs::write(&file, jwks().to_string()).unwrap();
    let file_path = file.to_string_lossy().to_string();
    let with_issuer = |issuer: &'static str| {
        [
            ("controlPlaneOidcAuthenticationRequired", "true"),
            ("controlPlaneOidcJwksUri", file_path.as_str()),
            ("controlPlaneOidcIssuer", issuer),
            ("controlPlaneOidcAudience", AUDIENCE),
        ]
    };
    let secure = common::start(&with_issuer("https://idp.example.com")).await;
    let (status, body) = authenticated_call(secure.port, &token("https://idp.example.com")).await;
    assert_eq!(status, 201, "the same file JWK set and token pass with an https issuer: {body}");
    let plaintext = common::start(&with_issuer("http://idp.example.com")).await;
    let (status, body) = authenticated_call(plaintext.port, &token("http://idp.example.com")).await;
    assert_eq!((status, body.as_str()), (401, "Unauthorized for control plane"));
    let _ = std::fs::remove_file(file);
}

//! `JwtTemplateHelper`: RS256 JWTs signed with one RSA-2048 key per process, and that key as a JWK set. Tokens
//! differ on every call upstream too (random key, `sub` and timestamps); only their shape is reproducible.

use std::sync::LazyLock;

use base64::Engine;
use java_compat::lang::{JMap, JValue, MapKind};
use serde_json::{Map, Value, json};

struct Key {
    id: String,
    pair: ring::signature::RsaKeyPair,
    n: Vec<u8>,
    e: Vec<u8>,
}

static KEY: LazyLock<Key> = LazyLock::new(|| {
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;
    let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("RSA key generation");
    let der = private.to_pkcs8_der().expect("PKCS#8 encoding");
    let pair = ring::signature::RsaKeyPair::from_pkcs8(der.as_bytes()).expect("ring accepts its own PKCS#8");
    Key { id: uuid::Uuid::new_v4().to_string(), pair, n: private.n().to_bytes_be(), e: private.e().to_bytes_be() }
});

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// A JSON object whose members iterate like the `HashMap` Nimbus builds.
fn hash_ordered(entries: Vec<(&str, Value)>) -> Value {
    let order = JMap::new(MapKind::Hash);
    for (k, _) in &entries {
        order.put_str(k, JValue::Null);
    }
    let mut out = Map::new();
    for (k, _) in order.entries() {
        let k = k.to_java_string();
        if let Some((_, v)) = entries.iter().find(|(e, _)| *e == k) {
            out.insert(k, v.clone());
        }
    }
    Value::Object(out)
}

fn sign(header: &Value, payload: &str) -> String {
    let input = format!("{}.{}", b64url(serde_json::to_string(header).unwrap_or_default().as_bytes()), b64url(payload.as_bytes()));
    let mut signature = vec![0u8; KEY.pair.public().modulus_len()];
    KEY.pair
        .sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), input.as_bytes(), &mut signature)
        .expect("RSA signing");
    format!("{input}.{}", b64url(&signature))
}

/// `generate()` (`JWTGenerator.generateJWT`) or `generate(claims)` (`signJWT`).
pub fn generate(claims: Option<&JMap>) -> String {
    match claims {
        None => {
            let now = chrono::Utc::now().timestamp();
            let header = hash_ordered(vec![("alg", json!("RS256")), ("kid", json!(KEY.id)), ("typ", json!("JWT"))]);
            let payload = json!({
                "sub": uuid::Uuid::new_v4().to_string(),
                "aud": "https://www.mock-server.com",
                "iss": "https://www.mock-server.com",
                "nbf": now - 4 * 3600,
                "exp": now + 4 * 3600,
                "iat": now,
            });
            sign(&header, &serde_json::to_string(&payload).unwrap_or_default())
        }
        Some(claims) => {
            // Claims are copied into a `HashMap` and written by Jackson's pretty printer.
            let copy = JMap::from_entries(MapKind::Hash, claims.entries());
            let payload: Map<String, Value> = copy.entries().iter().map(|(k, v)| (k.to_java_string(), claim(v))).collect();
            let header = hash_ordered(vec![("alg", json!("RS256")), ("kid", json!(KEY.id))]);
            sign(&header, &crate::json::pretty(&Value::Object(payload)))
        }
    }
}

fn claim(v: &JValue) -> Value {
    match v {
        JValue::Null => Value::Null,
        JValue::Bool(b) => Value::Bool(*b),
        JValue::Int(_) | JValue::Long(_) | JValue::Double(_) | JValue::Float(_) | JValue::BigInteger(_) | JValue::BigDecimal(_) => {
            crate::model::number(&v.to_java_string())
        }
        JValue::List(l) => Value::Array(l.items().iter().map(claim).collect()),
        JValue::Map(m) => Value::Object(m.entries().iter().map(|(k, v)| (k.to_java_string(), claim(v))).collect()),
        other => Value::String(other.to_java_string()),
    }
}

/// `jwks()`: `{"keys": [<the public key as a JWK>]}`, pretty-printed.
pub fn jwks() -> String {
    let key = hash_ordered(vec![
        ("kty", json!("RSA")),
        ("use", json!("sig")),
        ("alg", json!("RS256")),
        ("kid", json!(KEY.id)),
        ("n", json!(b64url(&KEY.n))),
        ("e", json!(b64url(&KEY.e))),
    ]);
    crate::json::pretty(&json!({"keys": [key]}))
}

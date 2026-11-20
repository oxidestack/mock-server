//! A mock OpenID Connect provider (`org.mockserver.oidc`): `PUT /mockserver/oidc` registers a provider (its signing
//! key supplied as a JWK or PEM, or generated) and adds expectations for discovery, JWKS, authorize, token, userinfo,
//! introspection, revocation, logout and device authorization, answered by built-in callback classes. Codes, device
//! codes, opaque tokens and revocations live until `reset`.

use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use base64::Engine;
use parking_lot::Mutex;
use serde_json::{Map, Value, json};

use crate::class_callback::{CallbackClass, CallbackError, ResponseCallback};
use crate::keys::{Algorithm, Curve, EcKey, JdkRsaFailure, JdkRsaKey, PublicKey, Signer, not_blank};
use crate::recorded::Failure;
use crate::request::HttpRequest;
use crate::state::State;

const JSON: &str = "application/json; charset=utf-8";
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const LOGOUT_PATH: &str = "/logout";
const CODE_TTL_MILLIS: i64 = 60_000;
const DEVICE_CODE_TTL_MILLIS: i64 = 300_000;
const MAX_OUTSTANDING: usize = 10_000;
const CLOCK_SKEW_SECONDS: i64 = 60;
const ERROR_URI: &str = "https://www.mock-server.com/mock_server/mock_openid_connect_provider.html";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

const CLASSES: &[(&str, Endpoint)] = &[
    ("org.mockserver.oidc.OidcDiscoveryCallback", Endpoint::Discovery),
    ("org.mockserver.oidc.OidcTokenCallback", Endpoint::Token),
    ("org.mockserver.oidc.OidcAuthorizationCodeCallback", Endpoint::Authorize),
    ("org.mockserver.oidc.OidcUserinfoCallback", Endpoint::Userinfo),
    ("org.mockserver.oidc.OidcIntrospectionCallback", Endpoint::Introspect),
    ("org.mockserver.oidc.OidcRevocationCallback", Endpoint::Revoke),
    ("org.mockserver.oidc.OidcLogoutCallback", Endpoint::Logout),
    ("org.mockserver.oidc.OidcDeviceAuthorizationCallback", Endpoint::DeviceAuthorization),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    Discovery,
    Token,
    Authorize,
    Userinfo,
    Introspect,
    Revoke,
    Logout,
    DeviceAuthorization,
}

fn now_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

// ---------------------------------------------------------------------------------------------------------------
// Configuration (`OidcProviderConfiguration`)
// ---------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Config {
    issuer: Option<String>,
    jwks_path: String,
    token_path: String,
    authorize_path: String,
    userinfo_path: String,
    introspect_path: String,
    revoke_path: String,
    device_authorization_path: String,
    subject: String,
    client_id: String,
    client_secret: Option<String>,
    audience: String,
    scopes: Vec<String>,
    token_expiry_seconds: i64,
    additional_claims: Vec<(String, Value)>,
    device_code_pending_polls: i32,
    enforce_client_authentication: bool,
    opaque_access_token: bool,
    signing_algorithm: Option<String>,
    private_key_pem: Option<String>,
    certificate_pem: Option<String>,
    jwk_json: Option<String>,
    key_id: Option<String>,
    issue_expired_token: bool,
    wrong_issuer: bool,
    tampered_signature: bool,
}

fn bind(body: &str) -> Result<Config, Failure> {
    let tree = if body.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        crate::chaos::read_tree(body, false).map_err(|e| crate::chaos::bind::parse_failure(body, &e))?
    };
    if tree.is_null() {
        // Jackson reads a `null` body as a null configuration, which the generator rejects
        return Err("OIDC provider configuration is required".into());
    }
    let source = |e: crate::chaos::bind::BindError| e.failure(body);
    let b = crate::chaos::bind::Bean::of(&tree, "org.mockserver.oidc.OidcProviderConfiguration").map_err(source)?;
    let text = |name: &str, default: &str| -> Result<String, Failure> { Ok(b.string(name).map_err(source)?.unwrap_or_else(|| default.to_string())) };
    // `List<String>`, a lone value read as a list of one
    let scopes = match b.map().iter().rfind(|(k, _)| k.eq_ignore_ascii_case("scopes")).map(|(_, v)| v) {
        None => vec!["openid".into(), "profile".into(), "email".into()],
        Some(Value::Null) => Vec::new(),
        Some(_) => b.string_list("scopes").map_err(source)?.unwrap_or_default().into_iter().map(Option::unwrap_or_default).collect(),
    };
    let additional_claims = match b.object("additionalClaims", "java.util.LinkedHashMap<java.lang.String,java.io.Serializable>").map_err(source)? {
        None => Vec::new(),
        Some(o) => o.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
    };
    Ok(Config {
        issuer: b.string("issuer").map_err(source)?,
        jwks_path: text("jwksPath", "/.well-known/jwks.json")?,
        token_path: text("tokenPath", "/token")?,
        authorize_path: text("authorizePath", "/authorize")?,
        userinfo_path: text("userinfoPath", "/userinfo")?,
        introspect_path: text("introspectPath", "/introspect")?,
        revoke_path: text("revokePath", "/revoke")?,
        device_authorization_path: text("deviceAuthorizationPath", "/device_authorization")?,
        subject: text("subject", "mock-user")?,
        client_id: text("clientId", "mock-client")?,
        client_secret: match b.get("clientSecret") {
            None => Some("mock-client-secret".into()),
            Some(_) => b.string("clientSecret").map_err(source)?,
        },
        audience: text("audience", "mock-audience")?,
        scopes,
        token_expiry_seconds: b.primitive_int("tokenExpirySeconds").map_err(source)?.map_or(3600, i64::from),
        additional_claims,
        device_code_pending_polls: b.primitive_int("deviceCodePendingPolls").map_err(source)?.unwrap_or(0),
        enforce_client_authentication: b.primitive_boolean("enforceClientAuthentication").map_err(source)?.unwrap_or(false),
        opaque_access_token: b.primitive_boolean("opaqueAccessToken").map_err(source)?.unwrap_or(false),
        signing_algorithm: match b.get("signingAlgorithm") {
            None => Some("RS256".into()),
            Some(_) => b.string("signingAlgorithm").map_err(source)?,
        },
        private_key_pem: b.string("privateKeyPem").map_err(source)?,
        certificate_pem: b.string("certificatePem").map_err(source)?,
        jwk_json: b.string("jwkJson").map_err(source)?,
        key_id: b.string("keyId").map_err(source)?,
        issue_expired_token: b.primitive_boolean("issueExpiredToken").map_err(source)?.unwrap_or(false),
        wrong_issuer: b.primitive_boolean("wrongIssuer").map_err(source)?.unwrap_or(false),
        tampered_signature: b.primitive_boolean("tamperedSignature").map_err(source)?.unwrap_or(false),
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Keys (`OidcKeyProvider`, `JWKGenerator`, `JWTGenerator`)
// ---------------------------------------------------------------------------------------------------------------

/// `parseAlgorithm`.
fn parse_algorithm(value: Option<&str>) -> Result<Algorithm, String> {
    let Some(value) = value.filter(|v| !v.trim().is_empty()) else { return Ok(Algorithm::Rs256) };
    Algorithm::from_jwt(value).ok_or_else(|| format!("unsupported signingAlgorithm \"{value}\" - supported values are RS256, RS384, RS512, ES256, ES384, ES512"))
}

/// The key pair a provider signs with and publishes. The halves need not belong together, as upstream's `KeyPair`
/// of a JWK's own public members (or a certificate's key) and its private ones: tokens are signed with the private
/// half and verified against the public one.
struct Key {
    id: String,
    algorithm: Algorithm,
    signer: Signing,
    public: PublicKey,
}

enum Signing {
    Signer(Signer),
    /// a JWK's RSA components, signed with as the JDK does
    Jdk(JdkRsaKey),
    /// a JWK's EC `d` that is no private scalar of the algorithm's curve
    Unusable,
    /// a PEM EC key on a curve SunEC does not sign on: its `ECParameterSpec` text
    Curve(String),
    /// a PEM GOST R 34.10 key, an `ECPrivateKey` whose encoding SunEC's key factory cannot translate
    Gost,
    /// a PEM GOST R 34.10 key on implicitlyCA X9.62 parameters, which SunEC cannot translate either
    Implicit,
}

impl Key {
    /// `JWTGenerator.signJWT`'s signer; its failure is the `Exception signing JWT` it throws, wrapping the signer's
    /// exception. The JDK's CRT check fails in `RSACore.crtCrypt`, which `RSASignature.engineSign` and nimbus'
    /// `RSASSASigner.sign` wrap in turn; nimbus' `RSASSASigner` constructor refuses a modulus under 2048
    /// bits; an EC `d` outside [1, n - 1] is built unchecked and refused by `ECDSASignature.engineInitSign`
    /// (`ECUtil.checkPrivateKey`), whose message nimbus rethrows. PEM RSA keys sign as JWK ones; a PEM EC
    /// key on another curve than P-256, P-384 or P-521 reaches `ECDSASignature.engineSign`, whose `SignatureException`
    /// nimbus' `ECDSASigner.sign` rethrows.
    fn sign(&self, input: &[u8]) -> Result<Vec<u8>, CallbackError> {
        const JOSE: &str = "shaded_package.com.nimbusds.jose.JOSEException";
        let failed = || CallbackError::new("Exception signing JWT");
        match &self.signer {
            Signing::Signer(s) => s.sign_jws(self.algorithm, input).ok_or_else(failed),
            Signing::Jdk(k) => k.sign(self.algorithm, input).map_err(|failure| match failure {
                JdkRsaFailure::CrtCheck => failed().caused_by(
                    CallbackError::of(JOSE, "RSA signature exception: Could not sign data").caused_by(
                        CallbackError::of("java.security.SignatureException", "Could not sign data")
                            .caused_by(CallbackError::of("javax.crypto.BadPaddingException", "RSA private key operation failed")),
                    ),
                ),
                JdkRsaFailure::KeySize => failed().caused_by(CallbackError::of("java.lang.IllegalArgumentException", "The RSA key size must be at least 2048 bits")),
                JdkRsaFailure::NotRsa | JdkRsaFailure::TooShort => failed(),
            }),
            Signing::Curve(spec) => {
                let message = format!("Curve not supported: {spec}");
                Err(failed().caused_by(CallbackError::of(JOSE, &message).caused_by(CallbackError::of("java.security.SignatureException", &message))))
            }
            Signing::Gost => {
                const INVALID: &str = "Invalid EC private key";
                let converting = format!("Exception converting private key for algorithm \"EC\" java.security.InvalidKeyException: {INVALID}");
                let invalid = CallbackError::of("java.security.InvalidKeyException", INVALID).caused_by(CallbackError::of("java.io.IOException", "Not a SEQUENCE"));
                let translating = CallbackError::of("java.security.InvalidKeyException", format!("java.security.InvalidKeyException: {INVALID}")).caused_by(invalid);
                Err(failed().caused_by(CallbackError::of(JOSE, &converting).caused_by(translating)))
            }
            Signing::Implicit => {
                const IMPLICIT: &str = "EC domain parameters must be encoded in the algorithm identifier";
                let converting = format!("Exception converting private key for algorithm \"EC\" java.security.InvalidKeyException: {IMPLICIT}");
                let translating = CallbackError::of("java.security.InvalidKeyException", format!("java.security.InvalidKeyException: {IMPLICIT}"))
                    .caused_by(CallbackError::of("java.security.InvalidKeyException", IMPLICIT));
                Err(failed().caused_by(CallbackError::of(JOSE, &converting).caused_by(translating)))
            }
            Signing::Unusable => {
                const RANGE: &str = "The private key must be within the range [1, n - 1]";
                Err(failed().caused_by(CallbackError::of(JOSE, RANGE).caused_by(CallbackError::of("java.security.InvalidKeyException", RANGE))))
            }
        }
    }

    fn verify(&self, input: &[u8], signature: &[u8]) -> bool {
        self.public.verify(self.algorithm, input, signature)
    }

    /// `JWKGenerator.generateJWK`: the public key as a one-key JWK set, in nimbus' member order. nimbus' `ECKey`
    /// builder takes the algorithm's curve and refuses coordinates off it, which `generateJWK` rethrows. A certificate
    /// key of the other family fails before, in the algorithm's key factory.
    fn jwks(&self) -> Result<Value, Failure> {
        let creating = |cause: Failure| Failure::of("java.lang.RuntimeException", "Exception creating JWK", vec![("cause", cause.bean)], &cause.classes);
        self.public.convert(self.algorithm.is_rsa()).map_err(creating)?;
        let key = match (&self.public, self.algorithm.curve()) {
            (PublicKey::Ec { x, y }, Some(curve)) => {
                let (crv, len) = match curve {
                    Curve::P256 => ("P-256", 32),
                    Curve::P384 => ("P-384", 48),
                    Curve::P521 => ("P-521", 66),
                };
                let coordinates = crate::keys::fixed_len(x, len).zip(crate::keys::fixed_len(y, len));
                let Some((x, y)) = coordinates.filter(|(x, y)| on_curve(crv, x, y)) else {
                    let message = format!("Invalid EC JWK: The 'x' and 'y' public coordinates are not on the {crv} curve");
                    let illegal = Failure::illegal(message.clone());
                    let state = Failure::of("java.lang.IllegalStateException", message, vec![("cause", illegal.bean)], &illegal.classes);
                    return Err(creating(state));
                };
                json!({"kty": "EC", "use": "sig", "crv": crv, "kid": self.id, "x": B64.encode(x), "y": B64.encode(y), "alg": self.algorithm.jwt()})
            }
            (PublicKey::Rsa { n, e }, None) => json!({"kty": "RSA", "e": B64.encode(e), "use": "sig", "kid": self.id, "alg": self.algorithm.jwt(), "n": B64.encode(n)}),
            _ => return Err(Failure::of("java.lang.RuntimeException", "Exception creating JWK", Vec::new(), &[])),
        };
        Ok(json!({"keys": [key]}))
    }

    /// `JWTGenerator.signJWT`: the claims pretty-printed, as MockServer's object writer writes them.
    fn sign_claims(&self, claims: &Map<String, Value>) -> Result<String, CallbackError> {
        // nimbus writes the header from a `HashMap`, in bucket order: `kid` (bucket 7 of 16) before `alg` (13), as the
        // oracle's tokens show (B4-idp goldens).
        let header = json!({"kid": self.id, "alg": self.algorithm.jwt()});
        let input = format!("{}.{}", B64.encode(header.to_string()), B64.encode(crate::json::pretty(&Value::Object(claims.clone()))));
        let signature = self.sign(input.as_bytes())?;
        Ok(format!("{input}.{}", B64.encode(signature)))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// nimbus-jose-jwt's `JWK.parse`, as far as the OIDC provider reaches it: the member reads, constructor checks and
// their order, each failure a `ParseException` (errorOffset 0) with nimbus' text.
// ---------------------------------------------------------------------------------------------------------------

enum Jwk {
    /// `crt` is `[p, q, dp, dq, qi]` when the second private representation is complete.
    Rsa { n: Vec<u8>, e: Vec<u8>, d: Option<Vec<u8>>, crt: Option<Vec<Vec<u8>>> },
    /// on P-256, P-384, P-521 or secp256k1, which nimbus reads but no algorithm here signs with
    Ec { x: Vec<u8>, y: Vec<u8>, d: Option<Vec<u8>> },
    Oct,
    Okp { private: bool },
}

impl Jwk {
    /// `JWK.isPrivate`.
    fn is_private(&self) -> bool {
        match self {
            Jwk::Rsa { d, crt, .. } => d.is_some() || crt.is_some(),
            Jwk::Ec { d, .. } => d.is_some(),
            Jwk::Oct => true,
            Jwk::Okp { private } => *private,
        }
    }

    /// `JWK.getKeyType()`.
    fn kty(&self) -> &'static str {
        match self {
            Jwk::Rsa { .. } => "RSA",
            Jwk::Ec { .. } => "EC",
            Jwk::Oct => "oct",
            Jwk::Okp { .. } => "OKP",
        }
    }
}

/// `JSONObjectUtils.getString`: absent and `null` are both no value.
fn jwk_string<'a>(o: &'a Map<String, Value>, name: &str) -> Result<Option<&'a str>, String> {
    match o.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("Unexpected type of JSON object member {name}")),
    }
}

/// `JSONObjectUtils.getBase64URL` and `Base64URL.decode`, which skips characters outside both alphabets and drops
/// the bits of an incomplete last byte.
fn jwk_base64(o: &Map<String, Value>, name: &str) -> Result<Option<Vec<u8>>, String> {
    Ok(jwk_string(o, name)?.map(|text| {
        let (mut bits, mut count, mut out) = (0u32, 0u32, Vec::new());
        for c in text.bytes() {
            let digit = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' | b'-' => 62,
                b'/' | b'_' => 63,
                _ => continue,
            };
            bits = (bits << 6) | u32::from(digit);
            count += 6;
            if count >= 8 {
                count -= 8;
                out.push((bits >> count) as u8);
                bits &= (1 << count) - 1;
            }
        }
        out
    }))
}

/// `Curve.parse` of the `crv` member (blank is refused); the name as given.
fn jwk_curve(o: &Map<String, Value>) -> Result<String, String> {
    match jwk_string(o, "crv")? {
        Some(s) if !s.trim().is_empty() => Ok(s.to_string()),
        _ => Err("The cryptographic curve string must not be null or empty".into()),
    }
}

/// `ECChecks.isPointOnCurve`: `y² = x³ + ax + b (mod p)` over the curve's parameters, without range checks.
fn on_curve(name: &str, x: &[u8], y: &[u8]) -> bool {
    use rsa::BigUint;
    let hex = |s: &str| BigUint::parse_bytes(s.as_bytes(), 16).expect("curve constant");
    let (p, a, b) = match name {
        "P-256" => (
            hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
            None,
            hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
        ),
        "P-384" => (
            hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
            None,
            hex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
        ),
        "P-521" => (
            (BigUint::from(1u8) << 521usize) - BigUint::from(1u8),
            None,
            hex("51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"),
        ),
        _ => (hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"), Some(BigUint::from(0u8)), BigUint::from(7u8)),
    };
    // the NIST curves have a = p - 3
    let a = a.unwrap_or_else(|| &p - BigUint::from(3u8));
    let (x, y) = (BigUint::from_bytes_be(x), BigUint::from_bytes_be(y));
    (&y * &y) % &p == (&x * &x * &x + &a * &x + &b) % &p
}

/// `JWK.parse(String)` of a JSON object.
fn parse_jwk(o: &Map<String, Value>) -> Result<Jwk, String> {
    let kty = jwk_string(o, "kty")?.ok_or("Missing key type \"kty\" parameter")?;
    let jwk = match kty {
        "RSA" => {
            let n = jwk_base64(o, "n")?;
            let e = jwk_base64(o, "e")?;
            let d = jwk_base64(o, "d")?;
            let mut crt = Vec::new();
            for name in ["p", "q", "dp", "dq", "qi"] {
                crt.push(jwk_base64(o, name)?);
            }
            jwk_metadata(o)?;
            // the `RSAKey` constructor
            let n = n.ok_or("The modulus value must not be null")?;
            let e = e.ok_or("The public exponent value must not be null")?;
            let crt = if crt.iter().all(Option::is_some) {
                Some(crt.into_iter().flatten().collect())
            } else if crt.iter().all(Option::is_none) {
                None
            } else {
                const PARTS: [&str; 5] = ["first prime factor", "second prime factor", "first factor CRT exponent", "second factor CRT exponent", "first CRT coefficient"];
                let missing = crt.iter().position(Option::is_none).unwrap_or_default();
                return Err(format!("Incomplete second private (CRT) representation: The {} must not be null", PARTS[missing]));
            };
            Jwk::Rsa { n, e, d, crt }
        }
        "EC" => {
            let crv = jwk_curve(o)?;
            let x = jwk_base64(o, "x")?;
            let y = jwk_base64(o, "y")?;
            let d = jwk_base64(o, "d")?;
            jwk_metadata(o)?;
            // the `ECKey` constructor and `ensurePublicCoordinatesOnCurve`
            let x = x.ok_or("The x coordinate must not be null")?;
            let y = y.ok_or("The y coordinate must not be null")?;
            if !["P-256", "P-384", "P-521", "secp256k1"].contains(&crv.as_str()) {
                return Err(format!("Unknown / unsupported curve: {crv}"));
            }
            if !on_curve(&crv, &x, &y) {
                return Err(format!("Invalid EC JWK: The 'x' and 'y' public coordinates are not on the {crv} curve"));
            }
            Jwk::Ec { x, y, d }
        }
        "oct" => {
            let k = jwk_base64(o, "k")?;
            jwk_metadata(o)?;
            k.ok_or("The key value must not be null")?;
            Jwk::Oct
        }
        "OKP" => {
            let crv = jwk_curve(o)?;
            let x = jwk_base64(o, "x")?;
            let d = jwk_base64(o, "d")?;
            jwk_metadata(o)?;
            x.ok_or("The x parameter must not be null")?;
            if !["Ed25519", "Ed448", "X25519", "X448"].contains(&crv.as_str()) {
                return Err(format!("Unknown / unsupported curve: {crv}"));
            }
            Jwk::Okp { private: d.is_some() }
        }
        other => return Err(format!("Unsupported key type \"kty\" parameter: {other}")),
    };
    Ok(jwk)
}

/// `JWKMetadata`'s string members, read after the key material: a wrong type fails the parse.
fn jwk_metadata(o: &Map<String, Value>) -> Result<(), String> {
    for name in ["use", "alg", "kid", "x5u", "x5t", "x5t#S256"] {
        jwk_string(o, name)?;
    }
    Ok(())
}

fn mismatch(source: &str, supplied: &str, algorithm: Algorithm) -> String {
    format!(
        "supplied {source} contains a {supplied} key but signingAlgorithm \"{}\" requires a {} key - choose a matching signingAlgorithm (RS* for RSA keys, ES* for EC keys)",
        algorithm.jwt(),
        algorithm.family()
    )
}

/// `OidcKeyProvider.resolveKeyPair`. A key off the algorithm's curve passes here; `generateJWK` refuses it next
/// ([`Key::jwks`]).
fn resolve_key(config: &Config) -> Result<Key, Failure> {
    let algorithm = parse_algorithm(config.signing_algorithm.as_deref())?;
    let key_id = || not_blank(&config.key_id).map(str::to_string);
    if let Some(jwk_json) = not_blank(&config.jwk_json) {
        const PARSE: &str = "failed to parse supplied jwkJson: ";
        let parse_exception = |message: String| Failure::illegal_caused(format!("{PARSE}{message}"), Failure::of("java.text.ParseException", message, vec![("errorOffset", Value::from(0))], &[]));
        let object: Map<String, Value> = match serde_json::from_str(jwk_json) {
            Ok(Value::Object(o)) => o,
            _ => return Err(parse_exception("Invalid JSON object".into())),
        };
        let jwk = parse_jwk(&object).map_err(parse_exception)?;
        if !jwk.is_private() {
            return Err("supplied jwkJson must contain a private key to sign tokens".into());
        }
        let (signer, public) = match jwk {
            Jwk::Rsa { d: None, .. } => {
                // `toPrivateKey()` is null without d: the family check dereferences it
                const NPE: &str = "Cannot invoke \"java.security.PrivateKey.getAlgorithm()\" because the return value of \"java.security.KeyPair.getPrivate()\" is null";
                return Err(Failure::illegal_caused(format!("{PARSE}{NPE}"), Failure::of("java.lang.NullPointerException", NPE, Vec::new(), &[])));
            }
            Jwk::Rsa { n, e, d: Some(d), crt } => {
                if !algorithm.is_rsa() {
                    return Err(mismatch("jwkJson", "RSA", algorithm).into());
                }
                // the JDK builds the key without checking its components; signing finds out
                (Signing::Jdk(JdkRsaKey::new(&n, &e, &d, crt.as_deref())), PublicKey::rsa(&n, &e))
            }
            Jwk::Ec { x, y, d: Some(d) } => {
                if algorithm.is_rsa() {
                    return Err(mismatch("jwkJson", "EC", algorithm).into());
                }
                // d need not be the private key of x/y; off the algorithm's curve `jwks` refuses the key
                let curve = algorithm.curve().expect("an EC algorithm");
                let len = match curve {
                    Curve::P256 => 32,
                    Curve::P384 => 48,
                    Curve::P521 => 66,
                };
                let key = crate::keys::fixed_len(&d, len).and_then(|d| EcKey::from_scalar(curve, &d));
                (key.map_or(Signing::Unusable, |k| Signing::Signer(Signer::Ec(k))), PublicKey::Ec { x, y })
            }
            other => return Err(format!("unsupported jwkJson key type: {}", other.kty()).into()),
        };
        let id = key_id().or_else(|| object.get("kid").and_then(Value::as_str).map(str::to_string)).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        return Ok(Key { id, algorithm, signer, public });
    }
    if let Some(pem) = not_blank(&config.private_key_pem) {
        const PARSE: &str = "failed to parse supplied privateKeyPem/certificatePem: ";
        let caused = |cause: Failure| Failure::illegal_caused(format!("{PARSE}{}", cause.message), cause);
        let signer = crate::keys::private_key_from_pem(pem).map_err(caused)?;
        // the public key comes from the certificate when one is given, else from an RSA CRT key; a certificate of
        // the other family or curve than the private key is taken as it is, and `jwks` refuses it
        let public = if let Some(certificate) = not_blank(&config.certificate_pem) {
            let der = crate::keys::certificate_from_pem(certificate).map_err(caused)?;
            PublicKey::from_certificate(&der).unwrap_or_else(|| signer.public_key())
        } else if let Some((n, e)) = signer.rsa_public() {
            PublicKey::rsa(&n, &e)
        } else {
            return Err("certificatePem is required to derive the public key when privateKeyPem is an EC or non-CRT RSA key".into());
        };
        if signer.family() != algorithm.family() {
            return Err(mismatch("privateKeyPem", &signer.family(), algorithm).into());
        }
        let id = key_id().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let signer = match signer {
            Signer::Jdk(key) => Signing::Jdk(key),
            Signer::UnsupportedCurve(spec, _) => Signing::Curve(spec),
            // only a GOST key's family is EC (`ECGOST3410...`): SunEC translates it as its parameters allow
            Signer::Other(key) => match key.sun_ec {
                crate::keys::SunEc::Encoding => Signing::Gost,
                crate::keys::SunEc::Nist(key) => Signing::Signer(Signer::Ec(*key)),
                crate::keys::SunEc::Unsupported(spec) => Signing::Curve(spec),
                crate::keys::SunEc::Implicit => Signing::Implicit,
            },
            signer => Signing::Signer(signer),
        };
        return Ok(Key { id, algorithm, signer, public });
    }
    let id = key_id().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let signer = Signer::generate(algorithm)?;
    Ok(Key { id, algorithm, public: signer.public_key(), signer: Signing::Signer(signer) })
}

// ---------------------------------------------------------------------------------------------------------------
// Store (`OidcAuthorizationStore`)
// ---------------------------------------------------------------------------------------------------------------

struct Provider {
    config: Config,
    key: Key,
}

struct AuthorizationCode {
    redirect_uri: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    scope: Option<String>,
    nonce: Option<String>,
    issued_at: i64,
}

struct DeviceCode {
    scope: Option<String>,
    pending_polls: AtomicI32,
    issued_at: i64,
}

struct OpaqueToken {
    claims: Map<String, Value>,
    expires_at_seconds: i64,
}

impl OpaqueToken {
    fn is_expired(&self, now_millis: i64) -> bool {
        self.expires_at_seconds > 0 && now_millis / 1000 >= self.expires_at_seconds
    }
}

#[derive(Default)]
pub struct Oidc {
    providers: Mutex<Vec<Arc<Provider>>>,
    codes: Mutex<Vec<(String, AuthorizationCode)>>,
    device_codes: Mutex<Vec<(String, Arc<DeviceCode>)>>,
    opaque_tokens: Mutex<Vec<(String, Arc<OpaqueToken>)>>,
    revoked: Mutex<std::collections::HashSet<String>>,
}

impl Oidc {
    pub fn reset(&self) {
        self.providers.lock().clear();
        self.codes.lock().clear();
        self.device_codes.lock().clear();
        self.opaque_tokens.lock().clear();
        self.revoked.lock().clear();
    }

    fn find(&self, matches: impl Fn(&Provider) -> bool) -> Option<Arc<Provider>> {
        self.providers.lock().iter().find(|p| matches(p)).cloned()
    }

    /// `registerProvider`: a provider with the same authorize, token or device path is replaced; the newest first.
    fn register(&self, provider: Provider) {
        let mut providers = self.providers.lock();
        let c = &provider.config;
        providers.retain(|p| p.config.authorize_path != c.authorize_path && p.config.token_path != c.token_path && p.config.device_authorization_path != c.device_authorization_path);
        providers.insert(0, Arc::new(provider));
    }

    fn put_code(&self, code: String, value: AuthorizationCode) {
        let now = now_millis();
        let mut codes = self.codes.lock();
        codes.retain(|(_, c)| now - c.issued_at <= CODE_TTL_MILLIS);
        while codes.len() >= MAX_OUTSTANDING {
            codes.remove(0);
        }
        codes.push((code, value));
    }

    fn consume_code(&self, code: Option<&str>) -> Option<AuthorizationCode> {
        let code = code?;
        let mut codes = self.codes.lock();
        let index = codes.iter().position(|(k, _)| k == code)?;
        let (_, value) = codes.remove(index);
        (now_millis() - value.issued_at <= CODE_TTL_MILLIS).then_some(value)
    }

    fn put_device_code(&self, code: String, value: DeviceCode) {
        let now = now_millis();
        let mut codes = self.device_codes.lock();
        codes.retain(|(_, c)| now - c.issued_at <= DEVICE_CODE_TTL_MILLIS);
        while codes.len() >= MAX_OUTSTANDING {
            codes.remove(0);
        }
        codes.push((code, Arc::new(value)));
    }

    fn peek_device_code(&self, code: Option<&str>) -> Option<Arc<DeviceCode>> {
        let code = code?;
        let mut codes = self.device_codes.lock();
        let index = codes.iter().position(|(k, _)| k == code)?;
        if now_millis() - codes[index].1.issued_at > DEVICE_CODE_TTL_MILLIS {
            codes.remove(index);
            return None;
        }
        Some(codes[index].1.clone())
    }

    fn consume_device_code(&self, code: Option<&str>) -> Option<Arc<DeviceCode>> {
        let code = code?;
        let mut codes = self.device_codes.lock();
        let index = codes.iter().position(|(k, _)| k == code)?;
        let (_, value) = codes.remove(index);
        (now_millis() - value.issued_at <= DEVICE_CODE_TTL_MILLIS).then_some(value)
    }

    fn put_opaque_token(&self, token: String, value: OpaqueToken) {
        let now = now_millis();
        let mut tokens = self.opaque_tokens.lock();
        tokens.retain(|(_, t)| !t.is_expired(now));
        while tokens.len() >= MAX_OUTSTANDING {
            tokens.remove(0);
        }
        tokens.push((token, Arc::new(value)));
    }

    fn lookup_opaque_token(&self, token: &str) -> Option<Arc<OpaqueToken>> {
        let mut tokens = self.opaque_tokens.lock();
        let index = tokens.iter().position(|(k, _)| k == token)?;
        let value = tokens[index].1.clone();
        if value.is_expired(now_millis()) {
            tokens.remove(index);
        }
        Some(value)
    }

    fn revoke(&self, token: &str) {
        if token.is_empty() {
            return;
        }
        self.opaque_tokens.lock().retain(|(k, _)| k != token);
        let mut revoked = self.revoked.lock();
        if revoked.len() >= MAX_OUTSTANDING && let Some(first) = revoked.iter().next().cloned() {
            revoked.remove(&first);
        }
        revoked.insert(revocation_key(token));
    }

    fn is_revoked(&self, token: &str) -> bool {
        self.revoked.lock().contains(&revocation_key(token))
    }
}

/// `revocationKey`: the token without characters a JWT cannot contain.
fn revocation_key(token: &str) -> String {
    token.chars().filter(|c| *c == '.' || c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Tokens (`OidcTokenMinter`, `OidcTokenResolver`)
// ---------------------------------------------------------------------------------------------------------------

impl Provider {
    /// `mintTokenResponse`.
    fn mint(&self, oidc: &Oidc, requested_scope: Option<&str>, nonce: Option<&str>, include_refresh: bool, issuer: &str) -> Result<String, CallbackError> {
        let c = &self.config;
        let scope = requested_scope.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).unwrap_or_else(|| c.scopes.join(" "));
        let scopes: Vec<&str> = scope.split_whitespace().collect();
        let now = chrono::Utc::now().timestamp();
        let exp = if c.issue_expired_token { now - 3600 } else { now + c.token_expiry_seconds };
        let issuer = if c.wrong_issuer { format!("{issuer}/wrong") } else { issuer.to_string() };
        let mut access = Map::new();
        access.insert("iss".into(), issuer.clone().into());
        access.insert("sub".into(), c.subject.clone().into());
        access.insert("aud".into(), c.audience.clone().into());
        access.insert("iat".into(), now.into());
        access.insert("nbf".into(), now.into());
        access.insert("exp".into(), exp.into());
        access.insert("scope".into(), scope.clone().into());
        access.insert("client_id".into(), c.client_id.clone().into());
        for (k, v) in &c.additional_claims {
            access.insert(k.clone(), v.clone());
        }
        let mut access_token = if c.opaque_access_token {
            let token = format!("mock-opaque-{}", uuid::Uuid::new_v4());
            oidc.put_opaque_token(token.clone(), OpaqueToken { claims: access.clone(), expires_at_seconds: exp });
            token
        } else {
            self.key.sign_claims(&access)?
        };
        let mut id_token = None;
        if scopes.contains(&"openid") {
            let mut claims = Map::new();
            claims.insert("iss".into(), issuer.clone().into());
            claims.insert("sub".into(), c.subject.clone().into());
            claims.insert("aud".into(), c.client_id.clone().into());
            claims.insert("iat".into(), now.into());
            claims.insert("nbf".into(), now.into());
            claims.insert("exp".into(), exp.into());
            if let Some(nonce) = nonce.filter(|n| !n.is_empty()) {
                claims.insert("nonce".into(), nonce.into());
            }
            claims.insert("at_hash".into(), at_hash(&access_token, self.key.algorithm).into());
            let copy = |claims: &mut Map<String, Value>, keys: &[&str]| {
                for key in keys {
                    if let Some((_, v)) = c.additional_claims.iter().find(|(k, _)| k == key) {
                        claims.insert((*key).into(), v.clone());
                    }
                }
            };
            if scopes.contains(&"profile") {
                copy(&mut claims, &["name", "given_name", "family_name", "preferred_username", "picture"]);
            }
            if scopes.contains(&"email") {
                copy(&mut claims, &["email", "email_verified"]);
            }
            for (k, v) in &c.additional_claims {
                claims.insert(k.clone(), v.clone());
            }
            id_token = Some(self.key.sign_claims(&claims)?);
        }
        if c.tampered_signature {
            if !c.opaque_access_token {
                access_token = tamper(&access_token);
            }
            id_token = id_token.map(|t| tamper(&t));
        }
        let mut response = Map::new();
        response.insert("access_token".into(), access_token.into());
        if let Some(id_token) = id_token {
            response.insert("id_token".into(), id_token.into());
        }
        response.insert("token_type".into(), "Bearer".into());
        response.insert("expires_in".into(), c.token_expiry_seconds.into());
        response.insert("scope".into(), scope.into());
        if include_refresh {
            response.insert("refresh_token".into(), format!("mock-refresh-{}", uuid::Uuid::new_v4()).into());
        }
        Ok(crate::json::pretty(&Value::Object(response)))
    }

    /// `verifyAccessToken`: the claims of one of this provider's valid, unexpired tokens.
    fn verify(&self, token: &str) -> Option<Map<String, Value>> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        let signature = B64.decode(parts[2].trim_end_matches('=')).ok()?;
        if !self.key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature) {
            return None;
        }
        let claims: Map<String, Value> = match serde_json::from_slice(&B64.decode(parts[1].trim_end_matches('=')).ok()?).ok()? {
            Value::Object(o) => o,
            _ => return None,
        };
        let seconds = |v: Option<&Value>| match v? {
            Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
            Value::String(s) => s.trim().parse().ok(),
            _ => None,
        };
        let now = chrono::Utc::now().timestamp();
        let exp = seconds(claims.get("exp"))?;
        if now > exp + CLOCK_SKEW_SECONDS {
            return None;
        }
        if seconds(claims.get("nbf")).is_some_and(|nbf| now + CLOCK_SKEW_SECONDS < nbf) {
            return None;
        }
        if seconds(claims.get("iat")).is_some_and(|iat| now + CLOCK_SKEW_SECONDS < iat) {
            return None;
        }
        Some(claims)
    }
}

/// `computeAtHash`.
fn at_hash(access_token: &str, algorithm: Algorithm) -> String {
    let digest = match algorithm.jwt() {
        a if a.ends_with("384") => ring::digest::digest(&ring::digest::SHA384, access_token.as_bytes()),
        a if a.ends_with("512") => ring::digest::digest(&ring::digest::SHA512, access_token.as_bytes()),
        _ => ring::digest::digest(&ring::digest::SHA256, access_token.as_bytes()),
    };
    let bytes = digest.as_ref();
    B64.encode(&bytes[..bytes.len() / 2])
}

/// `tamperSignature`.
fn tamper(jwt: &str) -> String {
    let Some(dot) = jwt.rfind('.') else { return jwt.to_string() };
    let signature = &jwt[dot + 1..];
    let Some(first) = signature.chars().next() else { return jwt.to_string() };
    format!("{}{}{}", &jwt[..=dot], if first == 'A' { 'B' } else { 'A' }, &signature[first.len_utf8()..])
}

/// `OidcTokenResolver.resolveActiveClaims`.
fn active_claims(oidc: &Oidc, provider: Option<&Provider>, token: &str) -> Option<Map<String, Value>> {
    let provider = provider?;
    if token.is_empty() || oidc.is_revoked(token) {
        return None;
    }
    if let Some(opaque) = oidc.lookup_opaque_token(token) {
        return (!opaque.is_expired(now_millis())).then(|| opaque.claims.clone());
    }
    if provider.config.opaque_access_token {
        return None;
    }
    provider.verify(token)
}

/// `bearerToken`.
fn bearer(authorization: Option<&str>) -> Option<String> {
    let trimmed = authorization?.trim();
    if trimmed.len() <= 7 || !trimmed[..7].eq_ignore_ascii_case("Bearer ") {
        return None;
    }
    Some(trimmed[7..].trim().to_string()).filter(|t| !t.is_empty())
}

// ---------------------------------------------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------------------------------------------

/// The built-in OIDC callback classes, answering from `oidc`'s providers.
pub fn callback_class(oidc: &Arc<Oidc>, class: &str) -> Option<CallbackClass> {
    let endpoint = CLASSES.iter().find(|(name, _)| *name == class)?.1;
    Some(CallbackClass::new().with_response(Callback { oidc: oidc.clone(), endpoint }))
}

struct Callback {
    oidc: Arc<Oidc>,
    endpoint: Endpoint,
}

impl ResponseCallback for Callback {
    fn handle(&self, request: &Value) -> Result<Value, CallbackError> {
        let request = crate::forward::request_from_json(request);
        let oidc = &self.oidc;
        Ok(match self.endpoint {
            Endpoint::Discovery => discovery(oidc, &request),
            Endpoint::Token => token(oidc, &request)?,
            Endpoint::Authorize => authorize(oidc, &request),
            Endpoint::Userinfo => userinfo(oidc, &request),
            Endpoint::Introspect => introspect(oidc, &request),
            Endpoint::Revoke => {
                if let Some(token) = form(&request).get("token").filter(|t| !t.is_empty()) {
                    oidc.revoke(token);
                }
                json!({"statusCode": 200, "headers": {"cache-control": ["no-store"], "pragma": ["no-cache"]}, "body": ""})
            }
            Endpoint::Logout => logout(&request),
            Endpoint::DeviceAuthorization => device_authorization(oidc, &request),
        })
    }
}

fn response(status: u32, headers: &[(&str, &str)], body: impl Into<Value>) -> Value {
    let mut map = Map::new();
    for (name, value) in headers {
        map.insert((*name).into(), json!([value]));
    }
    let mut response = json!({"statusCode": status, "headers": map});
    let body = body.into();
    if !body.is_null() {
        response["body"] = body;
    }
    response
}

fn no_store(status: u32, content_type: &str, body: impl Into<Value>) -> Value {
    response(status, &[("content-type", content_type), ("cache-control", "no-store"), ("pragma", "no-cache")], body)
}

fn query<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    request.query.iter().find(|(k, _)| k == name).and_then(|(_, v)| v.first()).map(String::as_str)
}

/// `parseFormBody`.
fn form(request: &HttpRequest) -> std::collections::HashMap<String, String> {
    let mut form = std::collections::HashMap::new();
    for pair in request.body_str().split('&').filter(|p| !p.is_empty()) {
        match pair.split_once('=') {
            Some((k, v)) => form.insert(url_decode(k), url_decode(v)),
            None => form.insert(url_decode(pair), String::new()),
        };
    }
    form
}

/// `URLDecoder.decode`: `+` is a space.
fn url_decode(s: &str) -> String {
    crate::chaos::url_decode(&s.replace('+', " "))
}

/// `URLEncoder.encode`.
fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => out.push(b as char),
            b' ' => out.push('+'),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// `OidcIssuerResolver.resolve`.
fn issuer(config: &Config, request: &HttpRequest) -> String {
    if let Some(issuer) = not_blank(&config.issuer) {
        return issuer.trim().trim_end_matches('/').to_string();
    }
    let Some(host) = request.first_header("host").filter(|h| !h.trim().is_empty()) else { return "http://localhost:1080".into() };
    let forwarded = request.first_header("x-forwarded-proto").filter(|p| !p.trim().is_empty()).map(|p| p.split(',').next().unwrap_or_default().trim().to_lowercase());
    let scheme = match forwarded.as_deref() {
        Some(s @ ("https" | "http")) => s.to_string(),
        _ => if request.secure { "https".into() } else { "http".into() },
    };
    format!("{scheme}://{}", host.trim().trim_end_matches('/'))
}

fn discovery(oidc: &Oidc, request: &HttpRequest) -> Value {
    let Some(provider) = oidc.providers.lock().first().cloned() else {
        return response(404, &[("content-type", JSON)], "{\"error\":\"no OIDC provider configured\"}");
    };
    let c = &provider.config;
    let issuer = issuer(c, request);
    let body = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}{}", c.authorize_path),
        "token_endpoint": format!("{issuer}{}", c.token_path),
        "userinfo_endpoint": format!("{issuer}{}", c.userinfo_path),
        "jwks_uri": format!("{issuer}{}", c.jwks_path),
        "introspection_endpoint": format!("{issuer}{}", c.introspect_path),
        "revocation_endpoint": format!("{issuer}{}", c.revoke_path),
        "end_session_endpoint": format!("{issuer}{LOGOUT_PATH}"),
        "device_authorization_endpoint": format!("{issuer}{}", c.device_authorization_path),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token", DEVICE_CODE_GRANT],
        "code_challenge_methods_supported": ["S256", "plain"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "id_token_signing_alg_values_supported": [provider.key.algorithm.jwt()],
        "scopes_supported": c.scopes,
        "subject_types_supported": ["public"],
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "nbf", "nonce", "at_hash", "name", "preferred_username", "email", "email_verified", "scope"],
    });
    response(200, &[("content-type", JSON)], crate::json::pretty(&body))
}

fn authorize(oidc: &Oidc, request: &HttpRequest) -> Value {
    let non_empty = |name: &str| query(request, name).filter(|v| !v.is_empty()).map(str::to_string);
    let Some(redirect_uri) = non_empty("redirect_uri") else {
        return response(400, &[("content-type", JSON)], "{\"error\":\"invalid_request\",\"error_description\":\"redirect_uri is required\"}");
    };
    // `getFirstQueryStringParameter` answers "" for an absent parameter, so the redirect always carries `state`.
    let state = query(request, "state").unwrap_or("");
    let redirect = |param: &str, value: &str| {
        let mut location = format!("{redirect_uri}{}{param}={}", if redirect_uri.contains('?') { '&' } else { '?' }, url_encode(value));
        location.push_str(&format!("&state={}", url_encode(state)));
        response(302, &[("location", &location)], Value::Null)
    };
    if non_empty("response_type").is_some_and(|t| t != "code") {
        return redirect("error", "unsupported_response_type");
    }
    if oidc.find(|p| p.config.authorize_path == request.path).is_none() {
        return response(404, &[("content-type", JSON)], "{\"error\":\"server_error\",\"error_description\":\"no OIDC provider registered for this authorize endpoint\"}");
    }
    let code = format!("mock-auth-code-{}", uuid::Uuid::new_v4());
    oidc.put_code(
        code.clone(),
        AuthorizationCode {
            redirect_uri: redirect_uri.clone(),
            code_challenge: non_empty("code_challenge"),
            code_challenge_method: non_empty("code_challenge_method"),
            scope: non_empty("scope"),
            nonce: non_empty("nonce"),
            issued_at: now_millis(),
        },
    );
    redirect("code", &code)
}

fn token_error(error: &str, description: &str) -> Value {
    no_store(400, JSON, format!("{{\"error\":\"{error}\",\"error_description\":\"{description}\",\"error_uri\":\"{ERROR_URI}\"}}"))
}

/// The minted tokens; a signing failure is the exception `OidcTokenCallback` throws (404, logged).
fn token_success(result: Result<String, CallbackError>) -> Result<Value, CallbackError> {
    result.map(|body| no_store(200, JSON, body))
}

fn invalid_client() -> Value {
    response(
        401,
        &[("content-type", JSON), ("WWW-Authenticate", "Basic"), ("cache-control", "no-store"), ("pragma", "no-cache")],
        "{\"error\":\"invalid_client\",\"error_description\":\"client authentication failed\"}",
    )
}

/// `validateClientAuthentication`.
fn client_authenticated(request: &HttpRequest, form: &std::collections::HashMap<String, String>, config: &Config) -> Result<(), Value> {
    let mut credentials: Option<(Option<String>, Option<String>)> = None;
    if let Some(authorization) = request.first_header("authorization").filter(|a| a.len() >= 6 && a[..6].eq_ignore_ascii_case("Basic ")) {
        let decoded = base64::engine::general_purpose::STANDARD.decode(authorization[6..].trim()).map_err(|_| invalid_client())?;
        let decoded = String::from_utf8_lossy(&decoded).into_owned();
        if let Some((id, secret)) = decoded.split_once(':') {
            credentials = Some((Some(url_decode(id)), Some(url_decode(secret))));
        }
    }
    let (id, secret) = credentials.unwrap_or_else(|| (form.get("client_id").cloned(), form.get("client_secret").cloned()));
    match (id, secret, config.client_secret.as_deref()) {
        (Some(id), Some(secret), Some(expected)) if id == config.client_id && crate::auth::constant_time_eq(secret.as_bytes(), expected.as_bytes()) => Ok(()),
        _ => Err(invalid_client()),
    }
}

fn token(oidc: &Oidc, request: &HttpRequest) -> Result<Value, CallbackError> {
    let form = form(request);
    let Some(provider) = oidc.find(|p| p.config.token_path == request.path) else { return Ok(response(200, &[("content-type", JSON)], "{}")) };
    if provider.config.enforce_client_authentication && let Err(failure) = client_authenticated(request, &form, &provider.config) {
        return Ok(failure);
    }
    let issuer = issuer(&provider.config, request);
    let grant_type = form.get("grant_type").map(String::as_str);
    if grant_type == Some(DEVICE_CODE_GRANT) {
        let code = form.get("device_code").map(String::as_str);
        let expired = || Ok(token_error("expired_token", "device_code is unknown, expired, or already redeemed"));
        let Some(pending) = oidc.peek_device_code(code) else { return expired() };
        if pending.pending_polls.fetch_sub(1, Ordering::SeqCst) > 0 {
            return Ok(token_error("authorization_pending", "the user has not yet approved the device"));
        }
        let Some(approved) = oidc.consume_device_code(code) else { return expired() };
        return token_success(provider.mint(oidc, approved.scope.as_deref(), None, true, &issuer));
    }
    if grant_type != Some("authorization_code") {
        return token_success(provider.mint(oidc, form.get("scope").map(String::as_str), None, grant_type == Some("refresh_token"), &issuer));
    }
    let Some(code) = oidc.consume_code(form.get("code").map(String::as_str)) else {
        return Ok(token_error("invalid_grant", "authorization code is invalid, expired, or already used"));
    };
    if form.get("redirect_uri") != Some(&code.redirect_uri) {
        return Ok(token_error("invalid_grant", "redirect_uri does not match the authorization request"));
    }
    if let Some(challenge) = &code.code_challenge {
        let Some(verifier) = form.get("code_verifier").filter(|v| !v.is_empty()) else {
            return Ok(token_error("invalid_grant", "code_verifier is required for PKCE"));
        };
        let method = code.code_challenge_method.as_deref().filter(|m| !m.is_empty()).unwrap_or("S256");
        let valid = if method.eq_ignore_ascii_case("plain") {
            challenge == verifier
        } else {
            B64.encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes())) == *challenge
        };
        if !valid {
            return Ok(token_error("invalid_grant", "PKCE verification failed"));
        }
    }
    token_success(provider.mint(oidc, code.scope.as_deref(), code.nonce.as_deref(), true, &issuer))
}

fn userinfo(oidc: &Oidc, request: &HttpRequest) -> Value {
    let provider = oidc.find(|p| p.config.userinfo_path == request.path);
    let unauthorized = |challenge: &str, body: &str| {
        response(401, &[("content-type", JSON), ("WWW-Authenticate", challenge), ("cache-control", "no-store"), ("pragma", "no-cache")], body)
    };
    let Some(token) = bearer(request.first_header("authorization")) else { return unauthorized("Bearer", "") };
    let Some(claims) = active_claims(oidc, provider.as_deref(), &token) else {
        return unauthorized(
            "Bearer error=\"invalid_token\", error_description=\"the access token is expired, revoked, malformed, or invalid\"",
            "{\"error\":\"invalid_token\"}",
        );
    };
    let provider = provider.expect("claims imply a provider");
    let mut info = Map::new();
    info.insert("sub".into(), claims.get("sub").cloned().unwrap_or_else(|| provider.config.subject.clone().into()));
    for (k, v) in &provider.config.additional_claims {
        info.insert(k.clone(), v.clone());
    }
    no_store(200, JSON, crate::json::pretty(&Value::Object(info)))
}

fn introspect(oidc: &Oidc, request: &HttpRequest) -> Value {
    let provider = oidc.find(|p| p.config.introspect_path == request.path);
    let Some(token) = form(request).get("token").filter(|t| !t.is_empty()).cloned() else {
        return no_store(400, JSON, crate::json::pretty(&json!({"error": "invalid_request", "error_description": "the 'token' parameter is REQUIRED (RFC 7662 section 2.1)"})));
    };
    let mut body = Map::new();
    match active_claims(oidc, provider.as_deref(), &token) {
        Some(claims) => {
            body.insert("active".into(), true.into());
            body.extend(claims);
        }
        None => {
            body.insert("active".into(), false.into());
        }
    }
    no_store(200, JSON, crate::json::pretty(&Value::Object(body)))
}

fn logout(request: &HttpRequest) -> Value {
    if let Some(uri) = query(request, "post_logout_redirect_uri").filter(|u| !u.is_empty()) {
        let mut location = uri.to_string();
        if let Some(state) = query(request, "state").filter(|s| !s.is_empty()) {
            location.push(if uri.contains('?') { '&' } else { '?' });
            location.push_str(&format!("state={state}"));
        }
        return response(302, &[("location", &location)], Value::Null);
    }
    response(200, &[("content-type", "text/html; charset=utf-8")], "<html><body>Logged out</body></html>")
}

fn device_authorization(oidc: &Oidc, request: &HttpRequest) -> Value {
    let Some(provider) = oidc.find(|p| p.config.device_authorization_path == request.path) else {
        return response(404, &[("content-type", JSON)], "{\"error\":\"server_error\",\"error_description\":\"no OIDC provider registered for this device endpoint\"}");
    };
    let scope = form(request).get("scope").filter(|s| !s.is_empty()).cloned();
    let device_code = format!("mock-device-code-{}", uuid::Uuid::new_v4());
    const ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
    let mut user_code = String::new();
    for i in 0..8 {
        if i == 4 {
            user_code.push('-');
        }
        let mut byte = [0u8; 1];
        let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut byte);
        user_code.push(ALPHABET[byte[0] as usize % ALPHABET.len()] as char);
    }
    oidc.put_device_code(device_code.clone(), DeviceCode { scope, pending_polls: AtomicI32::new(provider.config.device_code_pending_polls.max(0)), issued_at: now_millis() });
    let issuer = issuer(&provider.config, request);
    let verification = format!("{issuer}/device");
    let body = json!({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification,
        "verification_uri_complete": format!("{verification}?user_code={user_code}"),
        "expires_in": DEVICE_CODE_TTL_MILLIS / 1000,
        "interval": 5,
    });
    response(200, &[("content-type", JSON)], crate::json::pretty(&body))
}

// ---------------------------------------------------------------------------------------------------------------
// `PUT /mockserver/oidc` (`OidcProviderGenerator`)
// ---------------------------------------------------------------------------------------------------------------

/// The expectations (input form) a provider configuration generates; the provider is registered. A failure is the
/// generator's `IllegalArgumentException` (wrapping nimbus', BouncyCastle's or the JDK's exception where a supplied
/// key cannot be read) or the exception `ObjectMapper` throws binding the configuration.
pub fn generate(state: &State, body: &str) -> Result<Vec<Value>, Failure> {
    let config = bind(body)?;
    let key = resolve_key(&config)?;
    let jwks = key.jwks()?;
    let callback = |id: &str, method: &str, path: &str, class: &str| {
        json!({"id": id, "httpRequest": {"method": method, "path": path}, "httpResponseClassCallback": {"callbackClass": class}})
    };
    let expectations = vec![
        callback("oidc.discovery", "GET", "/.well-known/openid-configuration", "org.mockserver.oidc.OidcDiscoveryCallback"),
        json!({
            "id": "oidc.jwks",
            "httpRequest": {"method": "GET", "path": config.jwks_path},
            "httpResponse": {"statusCode": 200, "headers": {"content-type": [JSON]}, "body": crate::json::pretty(&jwks)},
        }),
        callback("oidc.token", "POST", &config.token_path, "org.mockserver.oidc.OidcTokenCallback"),
        callback("oidc.authorize", "GET", &config.authorize_path, "org.mockserver.oidc.OidcAuthorizationCodeCallback"),
        callback("oidc.userinfo", "GET", &config.userinfo_path, "org.mockserver.oidc.OidcUserinfoCallback"),
        callback("oidc.introspect", "POST", &config.introspect_path, "org.mockserver.oidc.OidcIntrospectionCallback"),
        callback("oidc.revoke", "POST", &config.revoke_path, "org.mockserver.oidc.OidcRevocationCallback"),
        callback("oidc.logout", "GET", LOGOUT_PATH, "org.mockserver.oidc.OidcLogoutCallback"),
        callback("oidc.deviceAuthorization", "POST", &config.device_authorization_path, "org.mockserver.oidc.OidcDeviceAuthorizationCallback"),
    ];
    state.oidc.register(Provider { config, key });
    Ok(expectations)
}

//! Remote JWK sets for control-plane authentication: nimbus-jose-jwt 10.9.1's `RemoteJWKSet` with its
//! `DefaultJWKSetCache`, fetched through MockServer's `BoundedResourceRetriever` (a `DefaultResourceRetriever` over
//! `HttpURLConnection` with 3 s connect/read timeouts and a 50 KiB body limit), and `JWKSet.parse` with the error
//! texts the oracle answers with. Upstream keeps one `RemoteJWKSet` per authentication handler, and `HttpState`
//! rebuilds the handler (dropping its cache) whenever the authentication configuration changes; [`Handlers`] is that
//! derived state, keyed by the configuration signature.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use parking_lot::Mutex;
use serde_json::{Map, Value};

pub type Jwk = Map<String, Value>;

/// `BoundedResourceRetriever.CONNECT_TIMEOUT_MILLIS` / `READ_TIMEOUT_MILLIS`
const CONNECT_TIMEOUT: Duration = Duration::from_millis(3000);
const READ_TIMEOUT: Duration = Duration::from_millis(3000);
/// `BoundedResourceRetriever.SIZE_LIMIT_BYTES`
const SIZE_LIMIT: usize = 50 * 1024;
/// `DefaultJWKSetCache.DEFAULT_LIFESPAN_MINUTES` / `DEFAULT_REFRESH_TIME_MINUTES`
const LIFESPAN: Duration = Duration::from_secs(15 * 60);
const REFRESH: Duration = Duration::from_secs(5 * 60);
/// `HttpURLConnection`'s `http.maxRedirects` default.
const MAX_REDIRECTS: usize = 20;

/// The state of the handlers `HttpState.getControlPlaneAuthenticationHandler` derives from the configuration, shared
/// by a `Config`'s clones: rebuilt (dropping every cached set and resolved URL) when the signature changes.
#[derive(Clone, Default)]
pub struct Handlers(Arc<Mutex<Option<Derived>>>);

struct Derived {
    signature: String,
    sets: HashMap<&'static str, Arc<RemoteJwkSet>>,
    oidc_jwks_uri: Option<Result<String, String>>,
}

impl std::fmt::Debug for Handlers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Handlers")
    }
}

impl Handlers {
    fn with<T>(&self, signature: &str, f: impl FnOnce(&mut Derived) -> T) -> T {
        let mut slot = self.0.lock();
        if slot.as_ref().is_none_or(|d| d.signature != signature) {
            *slot = Some(Derived { signature: signature.to_string(), sets: HashMap::new(), oidc_jwks_uri: None });
        }
        f(slot.as_mut().expect("just set"))
    }

    /// The `RemoteJWKSet` of handler `role` (`"jwt"`, `"oidc"`) for `url`, as built under `signature`.
    pub fn remote(&self, signature: &str, role: &'static str, url: &str) -> Arc<RemoteJwkSet> {
        self.with(signature, |d| {
            let set = d.sets.entry(role).or_insert_with(|| Arc::new(RemoteJwkSet::new(url)));
            if set.url != url {
                *set = Arc::new(RemoteJwkSet::new(url));
            }
            set.clone()
        })
    }

    /// The OIDC handler's resolved JWK set location (or why its construction failed), computed once per signature:
    /// the constructor's discovery fetch happens when the handler is built, not per request.
    pub fn oidc_jwks_uri(&self, signature: &str, resolve: impl FnOnce() -> Result<String, String>) -> Result<String, String> {
        if let Some(known) = self.with(signature, |d| d.oidc_jwks_uri.clone()) {
            return known;
        }
        // Resolved outside the lock: a discovery document served by this same server must still be answerable.
        let resolved = resolve();
        self.with(signature, |d| d.oidc_jwks_uri.get_or_insert(resolved).clone())
    }
}

/// `RemoteJWKSet` with a `DefaultJWKSetCache`.
pub struct RemoteJwkSet {
    url: String,
    cache: Mutex<Option<(Arc<Vec<Jwk>>, Instant)>>,
}

impl RemoteJwkSet {
    fn new(url: &str) -> RemoteJwkSet {
        RemoteJwkSet { url: url.to_string(), cache: Mutex::new(None) }
    }

    /// `RemoteJWKSet.get`: the keys of the (cached, or refreshed) set that `matches` accepts. With none, a `kid` the
    /// cached set does not hold at all forces a refetch, whose failure is the answer; a failed refresh of a set still
    /// within its lifespan keeps the cached one.
    pub fn get(&self, kid: Option<&str>, matches: impl Fn(&Jwk) -> bool) -> Result<Vec<Jwk>, String> {
        let mut cache = self.cache.lock();
        let now = Instant::now();
        // `DefaultJWKSetCache.get` (null once expired) and `requiresRefresh`
        let mut set = cache.as_ref().filter(|(_, at)| now.duration_since(*at) <= LIFESPAN).map(|(s, _)| s.clone());
        let refresh = cache.as_ref().is_some_and(|(_, at)| now.duration_since(*at) > REFRESH);
        if refresh || set.is_none() {
            match self.update(&mut cache) {
                Ok(fresh) => set = Some(fresh),
                Err(e) if set.is_none() => return Err(e),
                Err(_) => {}
            }
        }
        let set = set.expect("set or returned");
        let found: Vec<Jwk> = set.iter().filter(|k| matches(k)).cloned().collect();
        if !found.is_empty() {
            return Ok(found);
        }
        let Some(kid) = kid else { return Ok(Vec::new()) };
        if set.iter().any(|k| k.get("kid").and_then(Value::as_str) == Some(kid)) {
            return Ok(Vec::new());
        }
        let set = self.update(&mut cache)?;
        Ok(set.iter().filter(|k| matches(k)).cloned().collect())
    }

    /// `RemoteJWKSet.updateJWKSetFromURL`
    fn update(&self, cache: &mut Option<(Arc<Vec<Jwk>>, Instant)>) -> Result<Arc<Vec<Jwk>>, String> {
        let text = retrieve(&self.url).map_err(|e| format!("Couldn't retrieve remote JWK set: {e}"))?;
        let set = Arc::new(parse_set(&text).map_err(|e| format!("Couldn't parse remote JWK set: {e}"))?);
        *cache = Some((set.clone(), Instant::now()));
        Ok(set)
    }
}

/// `URLParser.isFullUrl`
pub fn is_full_url(s: &str) -> bool {
    // `uri.matches("https?://.*")`: `.` matches no line terminator
    (s.starts_with("http://") || s.starts_with("https://")) && !s.contains(['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}'])
}

/// `URI.getHost()` of a full URL, without IPv6 brackets.
pub fn host_of(url: &str) -> Option<String> {
    target(url).ok().map(|t| t.host).filter(|h| !h.is_empty())
}

/// `BoundedResourceRetriever.create().retrieveResource(url).getContent()`: the body as UTF-8, or the `IOException`
/// message.
pub fn retrieve(url: &str) -> Result<String, String> {
    let blocking = || retrieve_blocking(url);
    if tokio::runtime::Handle::try_current().is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread) {
        tokio::task::block_in_place(blocking)
    } else {
        blocking()
    }
}

struct Target {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

fn target(url: &str) -> Result<Target, String> {
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(format!("unknown protocol: {}", url.split(':').next().unwrap_or_default()));
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let mut path = rest[end..].split('#').next().unwrap_or_default().to_string();
    if path.is_empty() || path.starts_with('?') {
        path.insert(0, '/');
    }
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => {
            let (h, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
            (h, after.strip_prefix(':'))
        }
        None => match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        },
    };
    let port = match port.filter(|p| !p.is_empty()) {
        Some(p) => p.parse::<u16>().map_err(|_| format!("For input string: \"{p}\""))?,
        None => if https { 443 } else { 80 },
    };
    Ok(Target { https, host: host.to_string(), port, path })
}

/// The `java.net` message of an I/O error.
fn java_message(e: &std::io::Error, connecting: bool) -> String {
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => "Connection refused".into(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => if connecting { "Connect timed out" } else { "Read timed out" }.into(),
        std::io::ErrorKind::ConnectionReset => "Connection reset".into(),
        _ if crate::asyncapi::tls::is_tls_failure(e) => crate::asyncapi::tls::jsse_message(e),
        _ => {
            let text = e.to_string();
            text.split(" (os error").next().unwrap_or(&text).to_string()
        }
    }
}

trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}

fn connect(t: &Target) -> Result<Box<dyn Stream>, String> {
    // `UnknownHostException`'s message is the host name.
    let addresses = crate::inet_address::lookup_blocking(&t.host, t.port).map_err(|_| t.host.clone())?;
    let mut last = None;
    let mut tcp = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let tcp = match tcp {
        Some(tcp) => tcp,
        None => return Err(last.map_or_else(|| t.host.clone(), |e| java_message(&e, true))),
    };
    let _ = tcp.set_read_timeout(Some(READ_TIMEOUT));
    let _ = tcp.set_write_timeout(Some(READ_TIMEOUT));
    if !t.https {
        return Ok(Box::new(tcp));
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(crate::asyncapi::tls::jdk_roots())
        .with_no_client_auth();
    // nimbus' `DefaultResourceRetriever` is an `HttpsURLConnection`: the JDK's SNI rule, no SNI for `localhost`
    // (`tests/scenarios/tls_jwks_localhost_no_sni.json`).
    config.enable_sni = crate::client::jdk_sni(&t.host);
    let name = rustls_pki_types::ServerName::try_from(t.host.clone()).map_err(|e| e.to_string())?;
    let connection = rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    let mut stream = rustls::StreamOwned::new(connection, tcp);
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock).map_err(|e| match e.kind() {
            // the peer closing mid-handshake: JSSE's `SSLHandshakeException`
            std::io::ErrorKind::UnexpectedEof => "Remote host terminated the handshake".into(),
            _ => java_message(&e, false),
        })?;
    }
    Ok(Box::new(stream))
}

struct Response {
    status: u32,
    reason: String,
    headers: Vec<(String, String)>,
    /// What follows the head: the body (or its start) as read so far.
    rest: Vec<u8>,
}

fn read_head(stream: &mut dyn Stream) -> Result<Response, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_string();
            let rest = buf[end + 4..].to_vec();
            let mut lines = head.split("\r\n");
            let status_line = lines.next().unwrap_or_default();
            let mut parts = status_line.splitn(3, ' ');
            let _version = parts.next();
            let status = parts.next().and_then(|s| s.parse().ok()).ok_or_else(|| "Invalid Http response".to_string())?;
            let reason = parts.next().unwrap_or_default().to_string();
            let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
            return Ok(Response { status, reason, headers, rest });
        }
        let n = stream.read(&mut chunk).map_err(|e| java_message(&e, false))?;
        if n == 0 {
            return Err("Unexpected end of file from server".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

/// Reads the body after the head, failing once it exceeds the size limit (`BoundedInputStream`).
fn read_body(stream: &mut dyn Stream, response: Response) -> Result<Vec<u8>, String> {
    let exceeded = || format!("Exceeded configured input limit of {SIZE_LIMIT} bytes");
    if response.status == 204 || response.status == 304 {
        return Ok(Vec::new());
    }
    let chunked = response.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let length = response.header("content-length").and_then(|v| v.parse::<usize>().ok());
    let mut raw = response.rest;
    let mut chunk = [0u8; 8192];
    let mut more = |raw: &mut Vec<u8>| -> Result<bool, String> {
        let n = stream.read(&mut chunk).map_err(|e| java_message(&e, false))?;
        raw.extend_from_slice(&chunk[..n]);
        Ok(n > 0)
    };
    if chunked {
        let mut body = Vec::new();
        let mut at = 0;
        loop {
            let line_end = loop {
                if let Some(p) = raw[at..].windows(2).position(|w| w == b"\r\n") {
                    break at + p;
                }
                if !more(&mut raw)? {
                    return Err("Premature EOF".into());
                }
            };
            let size_text = String::from_utf8_lossy(&raw[at..line_end]).to_string();
            let size = usize::from_str_radix(size_text.split(';').next().unwrap_or_default().trim(), 16).map_err(|_| "Bad chunk header".to_string())?;
            at = line_end + 2;
            if size == 0 {
                return Ok(body);
            }
            while raw.len() < at + size + 2 {
                if body.len() + raw.len() - at > SIZE_LIMIT {
                    return Err(exceeded());
                }
                if !more(&mut raw)? {
                    return Err("Premature EOF".into());
                }
            }
            body.extend_from_slice(&raw[at..at + size]);
            if body.len() > SIZE_LIMIT {
                return Err(exceeded());
            }
            at += size + 2;
        }
    }
    loop {
        if raw.len() > SIZE_LIMIT {
            return Err(exceeded());
        }
        if length.is_some_and(|l| raw.len() >= l) {
            raw.truncate(length.unwrap_or_default());
            return Ok(raw);
        }
        if !more(&mut raw)? {
            return Ok(raw);
        }
    }
}

fn retrieve_blocking(url: &str) -> Result<String, String> {
    let mut url = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let t = target(&url)?;
        let mut stream = connect(&t)?;
        let host = if (t.https && t.port == 443) || (!t.https && t.port == 80) { t.host.clone() } else { format!("{}:{}", t.host, t.port) };
        let request = format!("GET {} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n\r\n", t.path);
        stream.write_all(request.as_bytes()).map_err(|e| java_message(&e, false))?;
        stream.flush().map_err(|e| java_message(&e, false))?;
        let mut response = read_head(stream.as_mut())?;
        while (100..200).contains(&response.status) {
            let rest = std::mem::take(&mut response.rest);
            response = read_head(&mut ChainedRead { first: std::io::Cursor::new(rest), second: stream.as_mut() })?;
        }
        // `HttpURLConnection` follows a redirect within the same protocol.
        if matches!(response.status, 301 | 302 | 303 | 307 | 308) && let Some(location) = response.header("location") {
            let next = if is_full_url(location) {
                location.to_string()
            } else if location.starts_with('/') {
                format!("{}://{}{}", if t.https { "https" } else { "http" }, host, location)
            } else {
                location.to_string()
            };
            if next.starts_with("https://") == t.https && is_full_url(&next) {
                url = next;
                continue;
            }
        }
        // `HttpURLConnection.getInputStream` throws before the body is read for an error status.
        match response.status {
            404 | 410 => return Err(url),
            400.. => return Err(format!("Server returned HTTP response code: {} for URL: {url}", response.status)),
            _ => {}
        }
        let (status, reason) = (response.status, response.reason.clone());
        let body = read_body(stream.as_mut(), response)?;
        if !(200..=299).contains(&status) {
            return Err(format!("HTTP {status}: {reason}"));
        }
        return Ok(String::from_utf8_lossy(&body).into_owned());
    }
    Err(format!("Server redirected too many  times ({MAX_REDIRECTS})"))
}

struct ChainedRead<'a> {
    first: std::io::Cursor<Vec<u8>>,
    second: &'a mut dyn Stream,
}

impl Read for ChainedRead<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.first.read(buf)?;
        if n > 0 { Ok(n) } else { self.second.read(buf) }
    }
}

impl Write for ChainedRead<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.second.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.second.flush()
    }
}

/// `JWKSet.parse(String)`: the keys of a JWK set document, keys of an unsupported `kty` skipped.
pub fn parse_set(text: &str) -> Result<Vec<Jwk>, String> {
    // `JSONObjectUtils.parse` (Gson to a `Map`; an array reads as a map of `[key, value]` pairs)
    let object = match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(o)) => o,
        Ok(Value::Array(pairs)) => {
            let mut o = Map::new();
            for pair in pairs {
                match pair.as_array().map(Vec::as_slice) {
                    Some([Value::String(k), v]) => {
                        o.insert(k.clone(), v.clone());
                    }
                    _ => return Err("Invalid JSON object".into()),
                }
            }
            o
        }
        _ => return Err("Invalid JSON object".into()),
    };
    let keys = match object.get("keys") {
        None | Some(Value::Null) => return Err("Missing required \"keys\" member".into()),
        Some(Value::Array(keys)) => keys,
        Some(_) => return Err("Unexpected type of JSON object member keys".into()),
    };
    let mut out = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        let Some(key) = key.as_object() else { return Err("The \"keys\" JSON array must contain JSON objects only".into()) };
        match parse_jwk(key) {
            Ok(Some(k)) => out.push(k.clone()),
            Ok(None) => {}
            Err(e) => return Err(format!("Invalid JWK at position {i}: {e}")),
        }
    }
    Ok(out)
}

fn string_member<'a>(o: &'a Jwk, name: &str) -> Result<Option<&'a str>, String> {
    match o.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("Unexpected type of JSON object member {name}")),
    }
}

/// `JWK.parse`: `None` for an unsupported key type (which `JWKSet.parse` skips).
fn parse_jwk(o: &Jwk) -> Result<Option<&Jwk>, String> {
    let kty = string_member(o, "kty")?.ok_or_else(|| "Missing key type \"kty\" parameter".to_string())?;
    let curve = |o: &Jwk| -> Result<String, String> {
        match string_member(o, "crv")? {
            Some(c) if !c.trim().is_empty() => Ok(c.to_string()),
            _ => Err("The cryptographic curve string must not be null or empty".into()),
        }
    };
    let metadata = |o: &Jwk| -> Result<(), String> {
        for name in ["use", "alg", "kid", "x5u", "x5t", "x5t#S256"] {
            string_member(o, name)?;
        }
        match o.get("key_ops") {
            None | Some(Value::Null) => {}
            Some(Value::Array(ops)) if ops.iter().all(Value::is_string) => {}
            Some(_) => return Err("Unexpected type of JSON object member key_ops".into()),
        }
        Ok(())
    };
    match kty {
        "EC" => {
            let crv = curve(o)?;
            let x = string_member(o, "x")?;
            let y = string_member(o, "y")?;
            string_member(o, "d")?;
            metadata(o)?;
            let x = x.ok_or("The x coordinate must not be null")?;
            let y = y.ok_or("The y coordinate must not be null")?;
            if !["P-256", "secp256k1", "P-384", "P-521"].contains(&crv.as_str()) {
                return Err(format!("Unknown / unsupported curve: {crv}"));
            }
            if !on_curve(&crv, x, y) {
                return Err(format!("Invalid EC JWK: The 'x' and 'y' public coordinates are not on the {crv} curve"));
            }
        }
        "RSA" => {
            let n = string_member(o, "n")?;
            let e = string_member(o, "e")?;
            metadata(o)?;
            n.ok_or("The modulus value must not be null")?;
            e.ok_or("The public exponent value must not be null")?;
        }
        "oct" => {
            let k = string_member(o, "k")?;
            metadata(o)?;
            k.ok_or("The key value must not be null")?;
        }
        "OKP" => {
            let crv = curve(o)?;
            let x = string_member(o, "x")?;
            metadata(o)?;
            if !["Ed25519", "Ed448", "X25519", "X448"].contains(&crv.as_str()) {
                return Err(format!("Unknown / unsupported curve: {crv}"));
            }
            x.ok_or("The x parameter must not be null")?;
        }
        _ => return Ok(None),
    }
    Ok(Some(o))
}

/// `ECChecks.isPointOnCurve` for the curves this server can check (secp256k1 is taken on trust).
fn on_curve(crv: &str, x: &str, y: &str) -> bool {
    let decode = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).unwrap_or_default();
    let (x, y) = (decode(x), decode(y));
    // `Base64URL.decodeToBigInteger`: leading zero bytes carry no value.
    let fit = |v: &[u8], size: usize| -> Option<Vec<u8>> {
        let v = &v[v.iter().position(|b| *b != 0).unwrap_or(v.len())..];
        (v.len() <= size).then(|| [vec![0u8; size - v.len()], v.to_vec()].concat())
    };
    let point = |size: usize| -> Option<Vec<u8>> { Some([vec![4u8], fit(&x, size)?, fit(&y, size)?].concat()) };
    match crv {
        "P-256" => point(32).is_some_and(|p| p256::PublicKey::from_sec1_bytes(&p).is_ok()),
        "P-384" => point(48).is_some_and(|p| p384::PublicKey::from_sec1_bytes(&p).is_ok()),
        "P-521" => point(66).is_some_and(|p| p521::PublicKey::from_sec1_bytes(&p).is_ok()),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_messages_the_oracle_answers_with() {
        assert_eq!(parse_set("not a JWK set").unwrap_err(), "Invalid JSON object");
        assert_eq!(parse_set("[]").unwrap_err(), "Missing required \"keys\" member");
        assert_eq!(parse_set(r#"{"keys": [{"kty": "XYZ"}]}"#).unwrap().len(), 0);
        assert_eq!(parse_set(r#"{"keys": [{"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "AAAA"}]}"#).unwrap_err(), "Invalid JWK at position 0: Invalid EC JWK: The 'x' and 'y' public coordinates are not on the P-256 curve");
        let set = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/files/jwt/jwk_algorithms.json")).unwrap();
        assert_eq!(parse_set(&set).unwrap().len(), 4, "the fixture's P-256, P-384, RSA and Ed25519 keys are valid");
    }

    #[test]
    fn splits_urls_as_java_net_url() {
        let t = target("http://127.0.0.1:8080/jwks?x=1#frag").unwrap();
        assert_eq!((t.https, t.host.as_str(), t.port, t.path.as_str()), (false, "127.0.0.1", 8080, "/jwks?x=1"));
        let t = target("https://idp.example.com").unwrap();
        assert_eq!((t.https, t.host.as_str(), t.port, t.path.as_str()), (true, "idp.example.com", 443, "/"));
        let t = target("http://[::1]:9/x").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("::1", 9));
    }
}

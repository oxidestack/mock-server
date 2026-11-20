//! Control-plane HTTP Basic authentication (upstream #56 and #62, 9.2.0): `controlPlaneBasicAuthenticationRequired`
//! with users from `controlPlaneBasicAuthenticationCredentials` and `controlPlaneBasicAuthenticationUsersFile`
//! (`BasicAuthenticationCredentials`), checked against bcrypt, argon2 or PBKDF2 hashes (`PasswordHash`), throttled per
//! source address (`BasicAuthenticationThrottle`) by `BasicAuthenticationHandler`.

use std::sync::OnceLock;

use base64::Engine;
use parking_lot::Mutex;
use regex::Regex;

use crate::request::HttpRequest;

/// `HttpState.BASIC_CHALLENGE`: the `WWW-Authenticate` value of a control-plane 401 that invites Basic credentials.
pub const CHALLENGE: &str = "Basic realm=\"MockServer control plane\", charset=\"UTF-8\"";

/// `BasicAuthenticationHandler.PRINCIPAL_SOURCE`
pub const PRINCIPAL_SOURCE: &str = "verified-basic";

const BASIC_PREFIX: &str = "basic ";
const UNKNOWN_SOURCE: &str = "unknown";
const FAILURE_LOG_INTERVAL_MILLIS: i64 = 10_000;
const MAX_REMEMBERED_CREDENTIALS: usize = 256;

/// Java's `String.trim()`: every character up to U+0020 at either end.
fn java_trim(value: &str) -> &str {
    value.trim_matches(|c: char| c <= ' ')
}

/// `String.split(regex)` without a limit: the pieces between matches, trailing empty ones removed.
fn java_split<'a>(value: &'a str, separator: &Regex) -> Vec<&'a str> {
    let mut pieces: Vec<&str> = separator.split(value).collect();
    // a positive-width match at the start leaves a leading empty piece, as in Java
    while pieces.last().is_some_and(|p| p.is_empty()) {
        pieces.pop();
    }
    pieces
}

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid pattern"))
}

/// `PasswordHash`: a stored hash a presented password is checked against.
#[derive(Clone)]
pub enum PasswordHash {
    Bcrypt { hash: String, cost: u32 },
    Argon2 { algorithm: argon2::Algorithm, name: &'static str, version: u32, memory_kib: u32, iterations: u32, parallelism: u32, salt: Vec<u8>, expected: Vec<u8> },
    Pbkdf2 { sha512: bool, iterations: u32, salt: Vec<u8>, expected: Vec<u8> },
}

/// `Integer.parseInt` of a run of ASCII digits: `NumberFormatException`'s message when it does not fit.
fn parse_int(digits: &str) -> Result<u32, String> {
    digits.parse::<i32>().map(|n| n as u32).map_err(|_| format!("For input string: \"{digits}\""))
}

/// `PasswordHash.decode`: `Base64.getDecoder()` over the passlib alphabet (`.` for `+`), padding optional.
fn decode(value: &str) -> Result<Vec<u8>, String> {
    let value = value.replace('.', "+");
    let value = value.trim_end_matches('=');
    if value.len() % 4 == 1 {
        return Err("Last unit does not have enough valid bits".into());
    }
    const LENIENT: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true).with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    LENIENT.decode(value).map_err(|e| e.to_string())
}

impl PasswordHash {
    /// `PasswordHash.parse`: the message never contains the hash.
    pub fn parse(hash: &str) -> Result<PasswordHash, String> {
        if hash.trim().is_empty() {
            return Err("password hash is empty".into());
        }
        let trimmed = java_trim(hash);
        static BCRYPT: OnceLock<Regex> = OnceLock::new();
        static ARGON2: OnceLock<Regex> = OnceLock::new();
        static PBKDF2: OnceLock<Regex> = OnceLock::new();
        if regex(&BCRYPT, r"^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$").is_match(trimmed) {
            let cost = parse_int(&trimmed[4..6])?;
            if !(4..=16).contains(&cost) {
                return Err(format!("bcrypt password hash has cost {cost}, it must be between 4 and 16"));
            }
            return Ok(PasswordHash::Bcrypt { hash: trimmed.to_string(), cost });
        }
        let argon2 = regex(&ARGON2, r"^\$(argon2id|argon2i|argon2d)\$(?:v=([0-9]+)\$)?m=([0-9]+),t=([0-9]+),p=([0-9]+)\$([A-Za-z0-9+/.]+=*)\$([A-Za-z0-9+/.]+=*)$");
        if let Some(c) = argon2.captures(trimmed) {
            let (algorithm, name) = match &c[1] {
                "argon2id" => (argon2::Algorithm::Argon2id, "argon2id"),
                "argon2i" => (argon2::Algorithm::Argon2i, "argon2i"),
                _ => (argon2::Algorithm::Argon2d, "argon2d"),
            };
            let version = match c.get(2) {
                Some(v) => parse_int(v.as_str())?,
                None => 0x10,
            };
            let (memory_kib, iterations, parallelism) = (parse_int(&c[3])?, parse_int(&c[4])?, parse_int(&c[5])?);
            let (salt, expected) = (decode(&c[6])?, decode(&c[7])?);
            let signed = |n: u32| n as i32 as i64;
            if signed(iterations) < 1 || signed(parallelism) < 1 || signed(memory_kib) < 8 * signed(parallelism) || salt.len() < 8 || expected.len() < 4 {
                return Err("argon2 password hash has unusable parameters".into());
            }
            if memory_kib > 262_144 || iterations > 16 || parallelism > 16 || expected.len() > 64 {
                return Err("argon2 password hash parameters are too large to check on each request, use at most m=262144,t=16,p=16".into());
            }
            return Ok(PasswordHash::Argon2 { algorithm, name, version, memory_kib, iterations, parallelism, salt, expected });
        }
        let pbkdf2 = regex(&PBKDF2, r"^\$pbkdf2-(sha256|sha512)\$(?:i=)?([0-9]+)(?:,l=[0-9]+)?\$([A-Za-z0-9+/.]+=*)\$([A-Za-z0-9+/.]+=*)$");
        if let Some(c) = pbkdf2.captures(trimmed) {
            let iterations = parse_int(&c[2])?;
            let (salt, expected) = (decode(&c[3])?, decode(&c[4])?);
            if !(10_000..=10_000_000).contains(&(iterations as i32)) {
                return Err(format!("PBKDF2 password hash has {} iterations, it must have between 10000 and 10000000", iterations as i32));
            }
            if salt.len() < 8 || expected.len() < 16 || expected.len() > 64 {
                return Err("PBKDF2 password hash needs a salt of at least 8 bytes and a derived key of 16 to 64 bytes".into());
            }
            return Ok(PasswordHash::Pbkdf2 { sha512: &c[1] == "sha512", iterations, salt, expected });
        }
        Err("password hash is not a bcrypt ($2a$, $2b$, $2y$), argon2 ($argon2id$, $argon2i$, $argon2d$) or PBKDF2 ($pbkdf2-sha256$, $pbkdf2-sha512$) hash - plain text passwords are not accepted".into())
    }

    /// `matches`: the derived values compared in constant time.
    pub fn matches(&self, password: &str) -> bool {
        match self {
            // `OpenBSDBCrypt.checkPassword`: the UTF-8 password, NUL-terminated and cut at 72 bytes, as the crate does
            PasswordHash::Bcrypt { hash, .. } => bcrypt::verify(password.as_bytes(), hash).unwrap_or(false),
            PasswordHash::Argon2 { algorithm, version, memory_kib, iterations, parallelism, salt, expected, .. } => {
                let version = if *version == 0x10 { argon2::Version::V0x10 } else { argon2::Version::V0x13 };
                let Ok(params) = argon2::Params::new(*memory_kib, *iterations, *parallelism, Some(expected.len())) else { return false };
                let mut derived = vec![0u8; expected.len()];
                if argon2::Argon2::new(*algorithm, version, params).hash_password_into(password.as_bytes(), salt, &mut derived).is_err() {
                    return false;
                }
                crate::auth::constant_time_eq(expected, &derived)
            }
            PasswordHash::Pbkdf2 { sha512, iterations, salt, expected } => {
                let algorithm = if *sha512 { ring::pbkdf2::PBKDF2_HMAC_SHA512 } else { ring::pbkdf2::PBKDF2_HMAC_SHA256 };
                let mut derived = vec![0u8; expected.len()];
                let Some(iterations) = std::num::NonZeroU32::new(*iterations) else { return false };
                ring::pbkdf2::derive(algorithm, iterations, salt, password.as_bytes(), &mut derived);
                crate::auth::constant_time_eq(expected, &derived)
            }
        }
    }

    fn algorithm(&self) -> String {
        match self {
            PasswordHash::Bcrypt { .. } => "bcrypt".into(),
            PasswordHash::Argon2 { name, .. } => (*name).into(),
            PasswordHash::Pbkdf2 { sha512, .. } => if *sha512 { "pbkdf2-sha512" } else { "pbkdf2-sha256" }.into(),
        }
    }

    /// `costKey`: equal for two hashes that take the same time to check.
    fn cost_key(&self) -> String {
        match self {
            PasswordHash::Bcrypt { cost, .. } => format!("bcrypt:{cost}"),
            PasswordHash::Argon2 { name, version, memory_kib, iterations, parallelism, expected, .. } => {
                format!("{name}:{version}:{memory_kib}:{iterations}:{parallelism}:{}", expected.len())
            }
            PasswordHash::Pbkdf2 { iterations, expected, .. } => format!("{}:{iterations}:{}", self.algorithm(), expected.len()),
        }
    }

    /// `weakness`: why the work factors are below current OWASP guidance.
    pub fn weakness(&self) -> Option<String> {
        match self {
            PasswordHash::Bcrypt { cost, .. } => (*cost < 10).then(|| format!("cost {cost} is below the 10 recommended for bcrypt")),
            PasswordHash::Argon2 { memory_kib, iterations, .. } => ((*memory_kib as i64) * (*iterations as i64) < 19_456 * 2)
                .then(|| format!("m={memory_kib},t={iterations} is below the m=19456,t=2 recommended for argon2")),
            PasswordHash::Pbkdf2 { sha512, iterations, .. } => {
                let recommended = if *sha512 { 210_000 } else { 600_000 };
                (*iterations < recommended).then(|| format!("{iterations} iterations is below the {recommended} recommended for {}", self.algorithm()))
            }
        }
    }
}

/// One configured user.
#[derive(Clone)]
pub struct User {
    pub username: String,
    pub hash: PasswordHash,
    pub scopes: Vec<String>,
}

/// `BasicAuthenticationCredentials`: the users, in configuration order.
#[derive(Clone)]
pub struct Credentials {
    pub users: Vec<User>,
}

impl Credentials {
    /// `BasicAuthenticationCredentials.parse`: every error names the entry by position and user, never its hash.
    pub fn parse(inline: Option<&str>, file: Option<&str>) -> Result<Credentials, String> {
        let mut users = Vec::new();
        static INLINE: OnceLock<Regex> = OnceLock::new();
        static LINES: OnceLock<Regex> = OnceLock::new();
        if let Some(inline) = inline.filter(|v| !v.trim().is_empty()) {
            add_entries(&mut users, &java_split(inline, regex(&INLINE, "[;\r\n]+")), "controlPlaneBasicAuthenticationCredentials")?;
        }
        if let Some(file) = file.filter(|v| !v.trim().is_empty()) {
            let content = crate::class_path::read_or_file(file).map_err(|_| format!("controlPlaneBasicAuthenticationUsersFile \"{file}\" cannot be read"))?;
            let content = String::from_utf8_lossy(&content);
            add_entries(&mut users, &java_split(&content, regex(&LINES, "\r?\n")), "controlPlaneBasicAuthenticationUsersFile")?;
        }
        if users.is_empty() {
            return Err("controlPlaneBasicAuthenticationRequired is true but no users are configured, set controlPlaneBasicAuthenticationCredentials or controlPlaneBasicAuthenticationUsersFile".into());
        }
        Ok(Credentials { users })
    }

    fn user(&self, username: &str) -> Option<&User> {
        self.users.iter().find(|u| u.username == username)
    }
}

fn add_entries(users: &mut Vec<User>, entries: &[&str], source: &str) -> Result<(), String> {
    static SCOPES: OnceLock<Regex> = OnceLock::new();
    for (index, raw) in entries.iter().enumerate() {
        let position = index + 1;
        let entry = java_trim(raw);
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = entry.splitn(3, ':').collect();
        if parts.len() < 2 || java_trim(parts[0]).is_empty() {
            return Err(format!("{source} entry {position} is not username:passwordHash[:scopes]"));
        }
        let username = java_trim(parts[0]).to_string();
        let hash = PasswordHash::parse(parts[1]).map_err(|invalid| format!("{source} entry {position} for user \"{username}\": {invalid}"))?;
        let mut scopes: Vec<String> = Vec::new();
        if let Some(listed) = parts.get(2) {
            for scope in java_split(listed, regex(&SCOPES, r"[\s,]+")).into_iter().map(java_trim).filter(|s| !s.is_empty()) {
                if !scopes.iter().any(|s| s == scope) {
                    scopes.push(scope.to_string());
                }
            }
        }
        if users.iter().any(|u: &User| u.username == username) {
            return Err(format!("{source} entry {position} repeats user \"{username}\""));
        }
        users.push(User { username, hash, scopes });
    }
    Ok(())
}

/// `ControlPlaneAuthenticationHandlerFactory.requireUsableControlPlaneBasicAuthentication`: `Err` with the message a
/// start is refused with, else the WARNs to log (each weak hash, then `AllowInsecure`), as format and arguments.
pub fn startup_check(config: &crate::config::Config) -> Result<Vec<(&'static str, Vec<String>)>, String> {
    if !config.bool_property("controlPlaneBasicAuthenticationRequired", false) {
        return Ok(Vec::new());
    }
    let credentials = configured(config)?;
    let mut warnings = Vec::new();
    for user in &credentials.users {
        if let Some(weakness) = user.hash.weakness() {
            warnings.push(("control plane Basic authentication user {} has a weak password hash: {}, so a leaked hash is cheap to crack - re-hash the password with a higher work factor", vec![user.username.clone(), weakness]));
        }
    }
    if config.bool_property("controlPlaneBasicAuthenticationAllowInsecure", false) {
        warnings.push(("controlPlaneBasicAuthenticationAllowInsecure is true, so control plane Basic passwords are accepted without TLS where anyone on the network path can read them - use this only in tests", Vec::new()));
    }
    Ok(warnings)
}

/// The configured users.
pub fn configured(config: &crate::config::Config) -> Result<Credentials, String> {
    Credentials::parse(config.property("controlPlaneBasicAuthenticationCredentials").as_deref(), config.property("controlPlaneBasicAuthenticationUsersFile").as_deref())
}

/// `hasBasicAuthorization`: some `Authorization` value starts with `Basic ` in any case.
pub fn has_basic_authorization(request: &HttpRequest) -> bool {
    basic_authorization_header(request).is_some()
}

fn basic_authorization_header(request: &HttpRequest) -> Option<&str> {
    request
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .flat_map(|(_, vs)| vs.iter())
        .find(|v| v.len() >= BASIC_PREFIX.len() && v.is_char_boundary(BASIC_PREFIX.len()) && v[..BASIC_PREFIX.len()].eq_ignore_ascii_case(BASIC_PREFIX))
        .map(|v| v[BASIC_PREFIX.len()..].trim())
}

/// `decode`: the user and password of the base64 `user:password`, `None` when it is not base64 or has no user.
fn decode_credentials(encoded: &str) -> Option<(String, String)> {
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8_lossy(&decoded).into_owned();
    let colon = decoded.find(':').filter(|&c| c > 0)?;
    Some((decoded[..colon].to_string(), decoded[colon + 1..].to_string()))
}

/// `sourceOf`: the remote address without its port (and without IPv6 brackets).
fn source_of(request: &HttpRequest) -> String {
    let mut address = request.remote_address.trim_start_matches('/');
    if address.is_empty() {
        return UNKNOWN_SOURCE.to_string();
    }
    if let Some(colon) = address.rfind(':') && colon > 0 && colon < address.len() - 1 && address[colon + 1..].bytes().all(|b| b.is_ascii_digit()) {
        address = &address[..colon];
    }
    match address.strip_prefix('[').and_then(|a| a.strip_suffix(']')) {
        Some(inner) => inner.to_string(),
        None => address.to_string(),
    }
}

fn now_millis() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or_default()
}

/// `BasicAuthenticationThrottle`: five free failures per source, then a block doubling from one second up to a
/// minute; forgotten on a success or after fifteen minutes without a failure; at most 4096 sources, least recently
/// seen dropped first.
#[derive(Default)]
struct Throttle {
    failures: std::collections::HashMap<String, Failures>,
    sequence: u64,
}

struct Failures {
    count: u32,
    last_failure_millis: i64,
    blocked_until_millis: i64,
    seen: u64,
}

impl Throttle {
    const FREE_FAILURES: u32 = 5;
    const MAX_BACKOFF_MILLIS: i64 = 60_000;
    const FORGET_AFTER_MILLIS: i64 = 15 * 60_000;
    const MAX_TRACKED_SOURCES: usize = 4_096;

    fn current(&mut self, source: &str, now: i64) -> Option<&mut Failures> {
        if self.failures.get(source).is_some_and(|r| now - r.last_failure_millis > Self::FORGET_AFTER_MILLIS) {
            self.failures.remove(source);
            return None;
        }
        self.sequence += 1;
        let sequence = self.sequence;
        let r = self.failures.get_mut(source)?;
        r.seen = sequence;
        Some(r)
    }

    fn retry_after_millis(&mut self, source: &str) -> i64 {
        let now = now_millis();
        self.current(source, now).map_or(0, |r| (r.blocked_until_millis - now).max(0))
    }

    fn failed(&mut self, source: &str) {
        let now = now_millis();
        if self.current(source, now).is_none() {
            self.sequence += 1;
            self.failures.insert(source.to_string(), Failures { count: 0, last_failure_millis: now, blocked_until_millis: 0, seen: self.sequence });
            if self.failures.len() > Self::MAX_TRACKED_SOURCES && let Some(eldest) = self.failures.iter().min_by_key(|(_, r)| r.seen).map(|(k, _)| k.clone()) {
                self.failures.remove(&eldest);
            }
        }
        let record = self.failures.get_mut(source).expect("just inserted");
        record.count += 1;
        record.last_failure_millis = now;
        if record.count >= Self::FREE_FAILURES {
            let doublings = (record.count - Self::FREE_FAILURES).min(16);
            record.blocked_until_millis = now + (1_000i64 << doublings).min(Self::MAX_BACKOFF_MILLIS);
        }
    }

    fn succeeded(&mut self, source: &str) {
        self.failures.remove(source);
    }
}

/// `BasicAuthenticationHandler`, built once per configuration (its throttle and remembered credentials live with it).
pub struct Handler {
    credentials: Credentials,
    allow_insecure: bool,
    throttle: Mutex<Throttle>,
    /// one user of each distinct cost, so every check takes as long whichever user it names
    cost_representatives: Vec<usize>,
    remember_key: ring::hmac::Key,
    /// fingerprint → user, most recently used last
    remembered: Mutex<Vec<(Vec<u8>, String)>>,
    /// when a failure was last logged, and how many were not logged since
    failure_log: Mutex<(Option<i64>, u32)>,
}

impl Handler {
    pub fn new(credentials: Credentials, allow_insecure: bool) -> Handler {
        let mut keys: Vec<String> = Vec::new();
        let mut cost_representatives = Vec::new();
        for (index, user) in credentials.users.iter().enumerate() {
            let key = user.hash.cost_key();
            if !keys.contains(&key) {
                keys.push(key);
                cost_representatives.push(index);
            }
        }
        let mut key = [0u8; 32];
        let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut key);
        Handler {
            credentials,
            allow_insecure,
            throttle: Mutex::new(Throttle::default()),
            cost_representatives,
            remember_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key),
            remembered: Mutex::new(Vec::new()),
            failure_log: Mutex::new((None, 0)),
        }
    }

    /// `authenticate`: the user and its scopes, or the client-safe reason it failed.
    pub fn authenticate(&self, state: &crate::state::State, request: &HttpRequest) -> Result<(String, Vec<String>), String> {
        let Some(header) = basic_authorization_header(request) else {
            return Err("no basic authorization header found".into());
        };
        let source = source_of(request);
        let escaped_source = crate::cors_origin::escape_for_log(&source);
        if !self.allow_insecure && !request.secure {
            if let Some(unlogged) = self.failures_to_log() {
                self.warn(state, "control plane request sent basic credentials without TLS from {} - refused, use https or rotate the password if this connection crossed an untrusted network ({} earlier failures not logged)", vec![escaped_source.into(), unlogged.into()]);
            }
            return Err("basic authentication requires TLS".into());
        }
        let Some((username, password)) = decode_credentials(header) else {
            return Err("basic authorization header is invalid format".into());
        };
        let user = self.credentials.user(&username);
        let fingerprint = self.fingerprint(&username, &password);
        let remembered = user.is_some() && self.is_remembered(&fingerprint, &username);
        let retry_after = if remembered { 0 } else { self.throttle.lock().retry_after_millis(&source) };
        if retry_after > 0 {
            if let Some(unlogged) = self.failures_to_log() {
                self.warn(state, "control plane basic authentication refused for {} - too many failed attempts ({} earlier failures not logged)", vec![escaped_source.into(), unlogged.into()]);
            }
            return Err(format!("too many failed basic authentication attempts, retry in {} seconds", (retry_after + 999) / 1000));
        }
        let verified = remembered || self.verify(user, &password);
        if !verified {
            self.throttle.lock().failed(&source);
            if let Some(unlogged) = self.failures_to_log() {
                let escaped_user = crate::cors_origin::escape_for_log(&username);
                self.warn(state, "control plane basic authentication failed for user \"{}\" from {} ({} earlier failures not logged)", vec![escaped_user.into(), escaped_source.into(), unlogged.into()]);
            }
            return Err("control plane request failed basic authentication".into());
        }
        if !remembered {
            // a remembered admit must not clear the record, or a guesser sharing the address would get fresh guesses
            self.throttle.lock().succeeded(&source);
        }
        self.remember(fingerprint, &username);
        let user = user.expect("verified");
        Ok((user.username.clone(), user.scopes.clone()))
    }

    /// The user a request's Basic credentials name when this handler already verified them (no hashing): the
    /// principal of a request it admitted.
    pub fn verified_user(&self, request: &HttpRequest) -> Option<String> {
        let (username, password) = decode_credentials(basic_authorization_header(request)?)?;
        let fingerprint = self.fingerprint(&username, &password);
        self.remembered.lock().iter().any(|(f, u)| *f == fingerprint && *u == username).then_some(username)
    }

    /// `verify`: one hash of each distinct cost, the user's own for its cost.
    fn verify(&self, user: Option<&User>, password: &str) -> bool {
        let own = user.map(|u| u.hash.cost_key());
        let mut matches = false;
        for &index in &self.cost_representatives {
            let representative = &self.credentials.users[index].hash;
            if Some(representative.cost_key()) == own {
                matches = user.is_some_and(|u| u.hash.matches(password));
            } else {
                representative.matches(password);
            }
        }
        user.is_some() && matches
    }

    fn fingerprint(&self, username: &str, password: &str) -> Vec<u8> {
        let mut data = username.as_bytes().to_vec();
        data.push(0);
        data.extend_from_slice(password.as_bytes());
        ring::hmac::sign(&self.remember_key, &data).as_ref().to_vec()
    }

    fn is_remembered(&self, fingerprint: &[u8], username: &str) -> bool {
        let mut remembered = self.remembered.lock();
        match remembered.iter().position(|(f, _)| f == fingerprint) {
            Some(index) => {
                let entry = remembered.remove(index);
                let hit = entry.1 == username;
                remembered.push(entry);
                hit
            }
            None => false,
        }
    }

    fn remember(&self, fingerprint: Vec<u8>, username: &str) {
        let mut remembered = self.remembered.lock();
        remembered.retain(|(f, _)| *f != fingerprint);
        remembered.push((fingerprint, username.to_string()));
        if remembered.len() > MAX_REMEMBERED_CREDENTIALS {
            remembered.remove(0);
        }
    }

    /// `failuresToLog`: `None` within ten seconds of the last logged failure (this one counted instead), else how many
    /// went unlogged since.
    fn failures_to_log(&self) -> Option<u32> {
        let now = now_millis();
        let mut log = self.failure_log.lock();
        if log.0.is_some_and(|last| now - last < FAILURE_LOG_INTERVAL_MILLIS) {
            log.1 += 1;
            return None;
        }
        log.0 = Some(now);
        Some(std::mem::take(&mut log.1))
    }

    fn warn(&self, state: &crate::state::State, format: &str, args: Vec<serde_json::Value>) {
        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::AuthenticationFailed, format).args(args);
        crate::log::warn_event(state, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // generated with htpasswd -B, the argon2 reference CLI and Python's hashlib.pbkdf2_hmac
    const ALICE: &str = "$2y$04$uSFHeslOj8BIBnGIAGgQMOKxhtgDmVPZWDmiBpBfNm4fSHvYLrajS";
    const BOB: &str = "$pbkdf2-sha256$10000$c2FsdHNhbHRzYWx0MTIzNA$uiY/07IzO/sTdlAdTo+62emL5jyvq3AWAy/+BZsA0WY";
    const CAROL: &str = "$argon2id$v=19$m=64,t=1,p=1$c29tZXNhbHRzYWx0$KAgr7adyXIxiF4XivPcTX1DrntZc3VUJ/j+sKDui3IY";
    const DAVE: &str = "$pbkdf2-sha512$i=10000$c2FsdHNhbHRzYWx0MTIzNA==$s0FA/KKsp/8VrkDW9LNjKMxP5717ajhDO5Hm0umoBUA=";

    #[test]
    fn each_hash_family_checks_its_password() {
        for (hash, password) in [(ALICE, "secret"), (BOB, "hunter2"), (CAROL, "carolpw"), (DAVE, "davepw")] {
            let parsed = PasswordHash::parse(hash).unwrap_or_else(|e| panic!("{e}"));
            assert!(parsed.matches(password), "{hash}");
            assert!(!parsed.matches("wrong"), "{hash}");
        }
        assert!(PasswordHash::parse(&ALICE.replace("$2y$", "$2b$")).unwrap().matches("secret"));
    }

    #[test]
    fn plain_text_and_out_of_bounds_hashes_are_refused_without_the_hash() {
        let plain = PasswordHash::parse("secret").err().unwrap();
        assert!(plain.ends_with("plain text passwords are not accepted") && !plain.contains("secret"), "{plain}");
        assert_eq!(PasswordHash::parse(&ALICE.replace("$04$", "$03$")).err().unwrap(), "bcrypt password hash has cost 3, it must be between 4 and 16");
        assert_eq!(PasswordHash::parse(&BOB.replace("$10000$", "$9999$")).err().unwrap(), "PBKDF2 password hash has 9999 iterations, it must have between 10000 and 10000000");
        assert_eq!(PasswordHash::parse(&CAROL.replace("m=64", "m=300000")).err().unwrap(), "argon2 password hash parameters are too large to check on each request, use at most m=262144,t=16,p=16");
        assert_eq!(PasswordHash::parse(" ").err().unwrap(), "password hash is empty");
    }

    #[test]
    fn entries_are_named_by_position_and_user() {
        let parse = |inline: &str| Credentials::parse(Some(inline), None).err().unwrap();
        assert_eq!(parse(";; # c\nbob:secret"), "controlPlaneBasicAuthenticationCredentials entry 3 for user \"bob\": password hash is not a bcrypt ($2a$, $2b$, $2y$), argon2 ($argon2id$, $argon2i$, $argon2d$) or PBKDF2 ($pbkdf2-sha256$, $pbkdf2-sha512$) hash - plain text passwords are not accepted");
        assert_eq!(parse("nocolon"), "controlPlaneBasicAuthenticationCredentials entry 1 is not username:passwordHash[:scopes]");
        assert_eq!(parse(&format!("a:{ALICE};a:{BOB}")), "controlPlaneBasicAuthenticationCredentials entry 2 repeats user \"a\"");
        assert_eq!(Credentials::parse(None, Some(" ")).err().unwrap(), "controlPlaneBasicAuthenticationRequired is true but no users are configured, set controlPlaneBasicAuthenticationCredentials or controlPlaneBasicAuthenticationUsersFile");
        let users = Credentials::parse(Some(&format!("alice:{ALICE}:a, b,,a c")), None).unwrap();
        assert_eq!(users.users[0].scopes, ["a", "b", "c"]);
    }

    #[test]
    fn the_throttle_blocks_after_five_failures_and_doubles() {
        let mut throttle = Throttle::default();
        for _ in 0..4 {
            throttle.failed("h");
        }
        assert_eq!(throttle.retry_after_millis("h"), 0);
        throttle.failed("h");
        assert!((990..=1000).contains(&throttle.retry_after_millis("h")));
        throttle.failed("h");
        assert!((1990..=2000).contains(&throttle.retry_after_millis("h")));
        throttle.succeeded("h");
        assert_eq!(throttle.retry_after_millis("h"), 0);
    }

    #[test]
    fn the_source_drops_the_port_and_brackets() {
        let source = |address: &str| source_of(&HttpRequest { remote_address: address.into(), ..HttpRequest::default() });
        assert_eq!(source("127.0.0.1:5000"), "127.0.0.1");
        assert_eq!(source("[::1]:5000"), "::1");
        assert_eq!(source(""), "unknown");
    }
}

//! Control-plane authentication (`HttpState.controlPlaneRequestAuthenticated`): with
//! `controlPlaneJWTAuthenticationRequired`, every control-plane call but `status` needs an
//! `Authorization: Bearer <JWT>` that `JWTValidator` (nimbus-jose-jwt's `DefaultJWTProcessor` with MockServer's
//! claims verifier) accepts; otherwise the answer is 401 `Unauthorized for control plane - <reason>`.

use base64::Engine;
use serde_json::{Map, Value};

use crate::config::Config;
use crate::request::HttpRequest;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// `DefaultJWTClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS`
const MAX_CLOCK_SKEW: i64 = 60;

/// An installed control-plane authentication handler (`HttpState.setControlPlaneAuthenticationHandler`): the scopes
/// of an authenticated request, `None` for an unauthenticated one. It replaces the configured handlers.
pub type Authenticator = std::sync::Arc<dyn Fn(&HttpRequest) -> Option<Vec<String>> + Send + Sync>;

/// Where `Config` keeps the installed [`Authenticator`], shared by its clones, and what the configured handler chain
/// was last derived from (`HttpState.derivedControlPlaneAuthenticationHandler`).
#[derive(Clone, Default)]
pub struct AuthenticatorSlot(std::sync::Arc<parking_lot::RwLock<Option<Authenticator>>>, std::sync::Arc<parking_lot::Mutex<Option<Derived>>>);

/// A derived handler chain: the [`handler_signature`] it was built from, and whether it denies everything
/// (`DenyAllAuthenticationHandler`, built when the chain could not be).
struct Derived {
    signature: String,
    deny_all: bool,
    /// `BasicAuthenticationHandler`, with its throttle and remembered credentials
    basic: Option<std::sync::Arc<crate::auth_basic::Handler>>,
}

impl AuthenticatorSlot {
    pub fn set(&self, authenticator: Option<Authenticator>) {
        *self.0.write() = authenticator;
    }

    fn get(&self) -> Option<Authenticator> {
        self.0.read().clone()
    }
}

impl std::fmt::Debug for AuthenticatorSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.read().is_some() { "AuthenticatorSlot(installed)" } else { "AuthenticatorSlot(none)" })
    }
}

/// `evaluateControlPlaneAuthentication`: `None` when the request may proceed, else the status and text body —
/// 401 when authentication fails (the reason shown for mTLS and JWT failures; OIDC failures are not client-safe,
/// `AuthenticationException(message, false)`), 403 when `controlPlaneAuthorizationEnabled` finds the principal's
/// roles short of what the operation needs.
pub fn control_plane_rejection(state: &crate::state::State, request: &HttpRequest) -> Option<(u32, String)> {
    let config = &state.config;
    if request.trusted {
        return None;
    }
    match authenticate(state, request) {
        Err(Some(reason)) => Some((401, format!("Unauthorized for control plane - {reason}"))),
        Err(None) => Some((401, "Unauthorized for control plane".to_string())),
        Ok(scopes) if config.bool_property("controlPlaneAuthorizationEnabled", false) && !authorized(config, &scopes, is_read(request)) => {
            if state.info_enabled() {
                let granted: Vec<&str> = granted_roles(config, &scopes).into_iter().map(|r| ROLES[r]).collect();
                let required = if is_read(request) { "READ" } else { "MUTATE" };
                let reason = format!("principal granted roles [{}] do not satisfy required role {required} for {} {}", granted.join(", "), request.method, operation(request));
                let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::Info, "control plane request forbidden:{}").args([reason]);
                state.log.message_about(entry, crate::recorded::Subject::Request(std::sync::Arc::new(request.clone())));
            }
            crate::audit::record(state, request, true);
            Some((403, "Forbidden for control plane".to_string()))
        }
        Ok(_) => {
            crate::audit::record(state, request, false);
            None
        }
    }
}

/// Whether an embedding application installed its own [`Authenticator`] (its principal is never verified).
pub fn authenticator_installed(config: &Config) -> bool {
    config.control_plane_authenticator.get().is_some()
}

/// `AuthenticationHandler.authenticate`: the verified scopes, or why authentication failed (`None` when the reason
/// is not client-safe).
pub fn authenticate(state: &crate::state::State, request: &HttpRequest) -> Result<Vec<String>, Option<String>> {
    let config = &state.config;
    if let Some(authenticator) = config.control_plane_authenticator.get() {
        return authenticator(request).ok_or(None);
    }
    // `ControlPlaneAuthenticationHandlerFactory.build`: mTLS, then JWT, then OIDC; the first failure answers and the
    // scopes of all are united (`ChainedAuthenticationHandler`). Only OIDC grants scopes. Each flag as it is now, a
    // `PUT /mockserver/configuration` included (upstream 0e8566814; the 8.0.0 process kept its startup value).
    if deny_all(state) {
        return Err(Some("control plane authentication is enabled but incorrectly configured".to_string()));
    }
    // `AnyOfAuthenticationHandler` (9.2.0): Basic or the other mechanisms (all of them, chained), the one the request's
    // `Authorization: Basic` names first; when neither admits it, the first one's reason.
    if let Some(basic) = basic_handler(config) {
        let others_required = ["controlPlaneTLSMutualAuthenticationRequired", "controlPlaneJWTAuthenticationRequired", "controlPlaneOidcAuthenticationRequired"]
            .iter()
            .any(|p| config.bool_property(p, false));
        let by_basic = || basic.authenticate(state, request).map(|(_, scopes)| scopes).map_err(Some);
        if !others_required {
            return by_basic();
        }
        return if crate::auth_basic::has_basic_authorization(request) {
            by_basic().or_else(|first| other_mechanisms(state, request).map_err(|_| first))
        } else {
            other_mechanisms(state, request).or_else(|first| by_basic().map_err(|_| first))
        };
    }
    other_mechanisms(state, request)
}

/// The configured Basic handler, when `controlPlaneBasicAuthenticationRequired` and its users are usable.
fn basic_handler(config: &Config) -> Option<std::sync::Arc<crate::auth_basic::Handler>> {
    if !config.bool_property("controlPlaneBasicAuthenticationRequired", false) {
        return None;
    }
    let signature = handler_signature(config);
    config.control_plane_authenticator.1.lock().as_ref().filter(|d| d.signature == signature).and_then(|d| d.basic.clone())
}

/// The user a request's verified Basic credentials name (`verified-basic`), for the audit's principal.
pub fn basic_principal(config: &Config, request: &HttpRequest) -> Option<String> {
    if request.trusted || authenticator_installed(config) {
        return None;
    }
    basic_handler(config)?.verified_user(request)
}

/// `HttpState.evaluateControlPlaneAuthentication`'s `basicChallenge`: no installed handler, Basic required, and TLS or
/// `controlPlaneBasicAuthenticationAllowInsecure` (never invite a browser to send a password in the clear).
fn basic_challenge(config: &Config, request: &HttpRequest) -> bool {
    !authenticator_installed(config)
        && config.bool_property("controlPlaneBasicAuthenticationRequired", false)
        && (request.secure || config.bool_property("controlPlaneBasicAuthenticationAllowInsecure", false))
}

/// [`control_plane_rejection`] as the text response `controlPlaneRequestAuthenticated` writes: a 401 that may be
/// answered with Basic credentials carries `WWW-Authenticate` (before its `content-type`).
pub fn control_plane_refusal(state: &crate::state::State, request: &HttpRequest) -> Option<crate::reply::Reply> {
    let (status, body) = control_plane_rejection(state, request)?;
    let mut reply = crate::reply::Reply::api_header(status, "text/plain", body);
    if status == 401 && basic_challenge(&state.config, request) {
        reply.headers.insert(0, ("www-authenticate".into(), crate::auth_basic::CHALLENGE.into()));
    }
    Some(reply)
}

/// mTLS, then JWT, then OIDC (`ChainedAuthenticationHandler`).
fn other_mechanisms(state: &crate::state::State, request: &HttpRequest) -> Result<Vec<String>, Option<String>> {
    let config = &state.config;
    if config.bool_property("controlPlaneTLSMutualAuthenticationRequired", false) && let Some(reason) = mtls_rejection(config, request) {
        return Err(Some(reason));
    }
    if config.bool_property("controlPlaneJWTAuthenticationRequired", false) {
        jwt_authenticated(state, request).map_err(Some)?;
    }
    if config.bool_property("controlPlaneOidcAuthenticationRequired", false) {
        return oidc(config, request).map_err(|_| None);
    }
    Ok(Vec::new())
}

/// `JWTAuthenticationHandler.validatedClaims`: the first `Authorization` header, when its scheme (up to its first
/// space) is `Bearer`, in any case, is validated; a missing header, or one with no scheme, a blank one or another
/// one, fails with the ERROR `logAuthorisationFailure` logs before the 401.
fn jwt_authenticated(state: &crate::state::State, request: &HttpRequest) -> Result<(), String> {
    // every branch of upstream's loop over the headers returns or throws, so only the first is read
    let Some(header) = request.first_header("authorization") else {
        return Err(jwt_failure(state, request, "no authorization header found"));
    };
    let reason = match header.find(' ') {
        None | Some(0) => "authorization header is invalid format",
        Some(index) if header[..index].trim().is_empty() => "authorization type must be specified for authorization header",
        Some(index) if header[..index].eq_ignore_ascii_case("Bearer") => {
            return validate(&Policy::jwt(&state.config), header[index + 1..].trim()).map(|_| ());
        }
        Some(_) => "only \"Bearer\" supported for authorization header",
    };
    Err(jwt_failure(state, request, reason))
}

/// `JWTAuthenticationHandler.logAuthorisationFailure`: the ERROR `JWT control plane request failed:{}for request:{}`
/// about the request; the reason is the 401's.
fn jwt_failure(state: &crate::state::State, request: &HttpRequest, reason: &str) -> String {
    use crate::recorded::{Level, LogEntry};
    let entry = LogEntry::at(Level::Error, "JWT control plane request failed:{}for request:{}")
        .request(request)
        .args([Value::String(reason.to_string()), crate::recorded::logged(request)]);
    crate::log::error_event(state, entry);
    reason.to_string()
}

/// `AuthenticationHandler.principalIdentity` of the configured chain (`ChainedAuthenticationHandler`: each handler's
/// identity, joined with ` & `), for a request [`authenticate`] accepted: a stable name for its caller, used to tell
/// whether two callback WebSocket upgrades come from the same caller (upstream #220, 9.1.0). mTLS names the verified
/// leaf's SHA-256 fingerprint, JWT the token's issuer and subject, OIDC its subject; `None` when no handler can name
/// one (an installed [`Authenticator`] never does).
pub fn principal_identity(config: &Config, request: &HttpRequest) -> Option<String> {
    if authenticator_installed(config) {
        return None;
    }
    // `AnyOfAuthenticationHandler.principalIdentity`: a request Basic admitted is named by its user alone
    if crate::auth_basic::has_basic_authorization(request) && let Some(user) = basic_handler(config).and_then(|basic| basic.verified_user(request)) {
        return Some(format!("basic:{user}"));
    }
    let mut identities: Vec<String> = Vec::new();
    if config.bool_property("controlPlaneTLSMutualAuthenticationRequired", false) && let Ok(leaf) = mtls_verified_leaf(config, request) {
        let digest = ring::digest::digest(&ring::digest::SHA256, &leaf.der);
        identities.push(format!("mtls:sha256:{}", digest.as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>()));
    }
    let bearer = || request.first_header("authorization").and_then(|v| v.split_once(' ')).filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer")).map(|(_, jwt)| jwt.trim());
    if config.bool_property("controlPlaneJWTAuthenticationRequired", false) && let Some(claims) = bearer().and_then(|jwt| validate(&Policy::jwt(config), jwt).ok()) && let Some(subject) = claims.get("sub").and_then(Value::as_str) {
        let issuer = claims.get("iss").and_then(Value::as_str).unwrap_or("null");
        identities.push(format!("jwt:{issuer}|{subject}"));
    }
    if config.bool_property("controlPlaneOidcAuthenticationRequired", false) && oidc(config, request).is_ok() {
        // the default `principalIdentity`: `<principal source>:<principal>`, the subject
        let subject = bearer().and_then(|jwt| jwt.split('.').nth(1)).and_then(decode_json).and_then(|c| c.get("sub").and_then(Value::as_str).map(str::to_string));
        if let Some(subject) = subject {
            identities.push(format!("verified-oidc:{subject}"));
        }
    }
    identities.dedup();
    (!identities.is_empty()).then(|| identities.join(" & "))
}

/// `ControlPlaneWebSocketUpgradeGate.authenticated`: a control-plane WebSocket upgrade (`description` names the
/// socket in the log, e.g. "callback") passes control-plane authentication. A refused one gets the INFO entry and a
/// raw `401` (credentials) or `403` (role), then the connection closes: `None`. An admitted one gets the caller's
/// [`principal_identity`] (`Some(None)` when no handler names one).
pub async fn upgrade_authenticated<S>(state: &crate::state::State, request: &HttpRequest, description: &str, stream: &mut S) -> Option<Option<String>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let Some((status, _)) = control_plane_rejection(state, request) else {
        return Some(if request.trusted { None } else { principal_identity(&state.config, request) });
    };
    if state.info_enabled() {
        let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::AuthenticationFailed, "{} web socket upgrade rejected with status {} - control plane authentication required")
            .args([description.to_string(), status.to_string()]);
        state.log.message(entry);
    }
    let reason = if status == 403 { "Forbidden" } else { "Unauthorized" };
    let _ = stream.write_all(format!("HTTP/1.1 {status} {reason}\r\ncontent-length: 0\r\n\r\n").as_bytes()).await;
    let _ = stream.shutdown().await;
    None
}

/// `ControlPlaneAuthorizer.isAuthorized`: some role mapped from the scopes (`controlPlaneScopeMapping`,
/// `scope=read|mutate|admin` pairs) satisfies READ for a read, MUTATE otherwise.
pub fn authorized(config: &Config, scopes: &[String], read: bool) -> bool {
    let required = if read { 0 } else { 1 };
    granted_roles(config, scopes).iter().any(|&role| role >= required)
}

/// `ControlPlaneRole` names, by rank.
pub const ROLES: [&str; 3] = ["READ", "MUTATE", "ADMIN"];

/// `ControlPlaneAuthorizer.grantedRoles`: the ranks of the roles the scopes map to, in rank order.
pub fn granted_roles(config: &Config, scopes: &[String]) -> Vec<usize> {
    let mapping = config.property("controlPlaneScopeMapping").unwrap_or_default();
    // `parseScopeMapping`: a later pair for the same scope replaces an earlier one.
    let mut roles: Vec<(String, usize)> = Vec::new();
    for pair in mapping.split(',') {
        let Some(eq) = pair.find('=').filter(|&eq| eq > 0 && eq < pair.len() - 1) else { continue };
        let role = match pair[eq + 1..].trim().to_ascii_lowercase().as_str() {
            "read" => 0,
            "mutate" => 1,
            "admin" => 2,
            _ => continue,
        };
        let value = pair[..eq].trim().to_string();
        if value.is_empty() {
            continue;
        }
        match roles.iter_mut().find(|(v, _)| *v == value) {
            Some(entry) => entry.1 = role,
            None => roles.push((value, role)),
        }
    }
    let mut granted: Vec<usize> = roles.iter().filter(|(v, _)| scopes.contains(v)).map(|(_, r)| *r).collect();
    granted.sort_unstable();
    granted.dedup();
    granted
}

/// `isControlPlaneRead`: any GET, and the PUTs that only read; a retrieve that writes recorded bodies to files
/// (`extractBodiesLargerThan`) or repoints unmatched forwarding (`forwardUnmatchedTo`) is not one.
pub(crate) fn is_read(request: &HttpRequest) -> bool {
    let repoints = || crate::request::first(&request.query, "forwardUnmatchedTo").is_some_and(|v| !v.trim().is_empty());
    if operation(request) == "retrieve" && (crate::import::body_files::writes_files(request) || repoints()) {
        return false;
    }
    const READ_PUTS: &[&str] = &["retrieve", "verify", "verifySequence", "verifySLO", "diff", "explainUnmatched", "explain", "debugMismatch", "lint", "files/retrieve", "files/list"];
    request.method.eq_ignore_ascii_case("GET") || (request.method.eq_ignore_ascii_case("PUT") && READ_PUTS.contains(&operation(request)))
}

/// `auditOperation`: the path without `/mockserver/` (or the leading `/`).
pub(crate) fn operation(request: &HttpRequest) -> &str {
    let path = request.path.split('?').next().unwrap_or_default();
    path.strip_prefix("/mockserver/").or_else(|| path.strip_prefix('/')).unwrap_or(path)
}

/// `DataPlaneAuthenticationGate.isAuthenticated`: with `dataPlaneAuthenticationRequired`, a request that reaches
/// expectation matching needs data-plane credentials ([`data_plane_unauthenticated`]) whatever its path: every caller
/// runs it only after the control plane declined the request, so an unrouted `/mockserver/…` path, `/mockserverfoo` or
/// the liveness path with another method is gated too (upstream 6dcc66b58). The one exception is a CORS preflight for
/// a request the control plane serves, which `processAction` answers before matching: a browser never sends
/// credentials on a preflight.
pub fn data_plane_rejection(config: &Config, request: &HttpRequest) -> Option<Option<String>> {
    if !config.bool_property("dataPlaneAuthenticationRequired", false) {
        return None;
    }
    if crate::cors_origin::is_cors_preflight(request) && crate::cors_origin::is_control_plane_request(request, config) {
        return None;
    }
    data_plane_unauthenticated(config, request)
}

/// `DataPlaneAuthenticationGate.hasCredentialsIfRequired`: for a path that matches an expectation before the gate
/// runs (HTTP/1.1 `respondBeforeBody`, gRPC bidi streams), checked before the consuming match; without credentials
/// the request falls through to the dispatch whose gate refuses it.
pub fn has_data_plane_credentials_if_required(config: &Config, request: &HttpRequest) -> bool {
    !config.bool_property("dataPlaneAuthenticationRequired", false) || data_plane_unauthenticated(config, request).is_none()
}

/// `DataPlaneAuthenticator.authenticate`: with `dataPlaneAuthenticationRequired`, one of the configured Basic, Bearer
/// or API-key credentials (any one; none configured rejects everything). `None` lets the request through, otherwise
/// the `WWW-Authenticate` challenge (if any) to send.
pub fn data_plane_unauthenticated(config: &Config, request: &HttpRequest) -> Option<Option<String>> {
    if !config.bool_property("dataPlaneAuthenticationRequired", false) {
        return None;
    }
    let non_blank = |name: &str| config.property(name).filter(|v| !v.trim().is_empty());
    let (user, password) = (non_blank("dataPlaneBasicAuthenticationUsername"), non_blank("dataPlaneBasicAuthenticationPassword"));
    let bearer = non_blank("dataPlaneBearerAuthenticationToken");
    let (api_header, api_value) = (non_blank("dataPlaneApiKeyAuthenticationHeader"), non_blank("dataPlaneApiKeyAuthenticationValue"));
    let authorization = request.first_header("authorization").filter(|h| !h.trim().is_empty());
    let scheme = |prefix: &str| {
        authorization.filter(|h| h.len() >= prefix.len() && h[..prefix.len()].eq_ignore_ascii_case(prefix)).map(|h| h[prefix.len()..].trim()).filter(|t| !t.is_empty())
    };
    let basic = user.as_ref().zip(password.as_ref()).map(|(u, p)| base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}")));
    if basic.as_deref().is_some_and(|expected| scheme("Basic ") == Some(expected)) {
        return None;
    }
    if bearer.as_deref().is_some_and(|expected| scheme("Bearer ") == Some(expected)) {
        return None;
    }
    if let (Some(header), Some(expected)) = (&api_header, &api_value) && request.first_header(header).filter(|v| !v.trim().is_empty()) == Some(expected.as_str()) {
        return None;
    }
    let challenge = if basic.is_some() {
        let realm = non_blank("dataPlaneBasicAuthenticationRealm").unwrap_or_else(|| "MockServer".into());
        Some(format!("Basic realm=\"{}\", charset=\"UTF-8\"", realm.replace('\\', "\\\\").replace('"', "\\\"")))
    } else {
        bearer.is_some().then(|| "Bearer".to_string())
    };
    Some(challenge)
}

/// What a bearer token must satisfy: its signing keys and `DefaultJWTClaimsVerifier`-style claim rules.
struct Policy {
    keys: Keys,
    audience: Option<String>,
    required: std::collections::BTreeSet<String>,
    matching: Vec<(String, String)>,
    /// OIDC only: the expected `iss`, and the scope claim with the scopes it must grant.
    issuer: Option<String>,
    scopes: Option<(String, Vec<String>)>,
}

/// A handler's `JWKSource`: an `ImmutableJWKSet` loaded from a file, or a `RemoteJWKSet` for a URL.
enum Keys {
    File(Vec<Map<String, Value>>),
    Remote(std::sync::Arc<crate::jwks::RemoteJwkSet>),
}

impl Keys {
    /// `JWKSourceBuilder`-free construction as upstream's handlers do it: a full URL is a remote set, kept per handler
    /// (`role`) until the authentication configuration changes; anything else a file.
    fn of(config: &Config, role: &'static str, source: Option<&str>) -> Keys {
        match source.filter(|s| crate::jwks::is_full_url(s)) {
            Some(url) => Keys::Remote(config.control_plane_jwks.remote(&handler_signature(config), role, url)),
            None => Keys::File(jwk_file(source)),
        }
    }

    /// `JWSVerificationKeySelector.selectJWSKeys` over this source: the keys `matches` accepts.
    fn select(&self, kid: Option<&str>, matches: impl Fn(&Map<String, Value>) -> bool) -> Result<Vec<Map<String, Value>>, String> {
        match self {
            Keys::File(keys) => Ok(keys.iter().filter(|k| matches(k)).cloned().collect()),
            Keys::Remote(set) => set.get(kid, matches),
        }
    }
}

/// `ControlPlaneAuthenticationHandlerFactory.signature`: the configuration a derived handler was built from; a change
/// rebuilds it (`HttpState.getControlPlaneAuthenticationHandler`), which drops its cached remote JWK sets.
fn handler_signature(config: &Config) -> String {
    const PROPERTIES: [&str; 17] = [
        "controlPlaneTLSMutualAuthenticationRequired",
        "controlPlaneTLSMutualAuthenticationCAChain",
        "controlPlaneJWTAuthenticationRequired",
        "controlPlaneJWTAuthenticationJWKSource",
        "controlPlaneJWTAuthenticationExpectedAudience",
        "controlPlaneJWTAuthenticationMatchingClaims",
        "controlPlaneJWTAuthenticationRequiredClaims",
        "controlPlaneOidcAuthenticationRequired",
        "controlPlaneOidcJwksUri",
        "controlPlaneOidcIssuer",
        "controlPlaneOidcAudience",
        "controlPlaneOidcScopeClaim",
        "controlPlaneOidcRequiredScopes",
        "controlPlaneBasicAuthenticationRequired",
        "controlPlaneBasicAuthenticationCredentials",
        "controlPlaneBasicAuthenticationUsersFile",
        "controlPlaneBasicAuthenticationAllowInsecure",
    ];
    PROPERTIES.iter().map(|p| config.property(p).unwrap_or_default()).collect::<Vec<_>>().join("|")
}

impl Policy {
    /// `JWTAuthenticationHandler`
    fn jwt(config: &Config) -> Policy {
        let non_blank = |name: &str| config.property(name).filter(|v| !v.trim().is_empty());
        Policy {
            keys: Keys::of(config, "jwt", non_blank("controlPlaneJWTAuthenticationJWKSource").as_deref()),
            audience: non_blank("controlPlaneJWTAuthenticationExpectedAudience"),
            required: config
                .list_property("controlPlaneJWTAuthenticationRequiredClaims")
                .map(|v| v.into_iter().flatten().filter(|c| !c.is_empty()).collect())
                .unwrap_or_default(),
            matching: matching_claims(config),
            issuer: None,
            scopes: None,
        }
    }
}

/// `OidcAuthenticationHandler`: a bearer token signed by a key of `controlPlaneOidcJwksUri`, with the expected
/// issuer, audience and scopes and an `exp`.
/// `OidcAuthenticationHandler.authenticate`: the token's scopes (`controlPlaneOidcScopeClaim`), or why it failed.
fn oidc(config: &Config, request: &HttpRequest) -> Result<Vec<String>, String> {
    let non_blank = |name: &str| config.property(name).filter(|v| !v.trim().is_empty());
    let issuer = non_blank("controlPlaneOidcIssuer");
    let audience = non_blank("controlPlaneOidcAudience");
    let jwks = non_blank("controlPlaneOidcJwksUri");
    // Construction failures (no issuer or audience, a plaintext remote URL, a failed discovery) leave the handler
    // uninitialised, which rejects every request. The construction runs once per handler, so its outcome is kept.
    if issuer.is_none() && audience.is_none() {
        return Err("OIDC validator is not initialised".into());
    }
    let resolved = config.control_plane_jwks.oidc_jwks_uri(&handler_signature(config), || {
        require_secure_remote_url(jwks.as_deref())?;
        require_secure_remote_url(issuer.as_deref())?;
        let resolved = resolve_jwks_uri(jwks.as_deref(), issuer.as_deref())?;
        require_secure_remote_url(Some(&resolved))?;
        Ok(resolved)
    });
    let Ok(resolved) = resolved else { return Err("OIDC validator is not initialised".into()) };
    let values = request.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("authorization")).flat_map(|(_, vs)| vs.iter()).collect::<Vec<_>>();
    let Some(value) = values.first() else { return Err("no authorization header found".into()) };
    let token = match value.find(' ') {
        None | Some(0) => return Err("authorization header is invalid format".into()),
        Some(i) if value[..i].trim().is_empty() => return Err("authorization type must be specified for authorization header".into()),
        Some(i) if value[..i].eq_ignore_ascii_case("Bearer") => value[i + 1..].trim(),
        Some(_) => return Err("only \"Bearer\" supported for authorization header".into()),
    };
    let scope_claim = non_blank("controlPlaneOidcScopeClaim").unwrap_or_else(|| "scope".into());
    let required_scopes: Vec<String> = config
        .list_property("controlPlaneOidcRequiredScopes")
        .map(|v| v.into_iter().flatten().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    let policy = Policy {
        keys: Keys::of(config, "oidc", Some(&resolved)),
        audience,
        required: ["exp".to_string()].into_iter().collect(),
        matching: Vec::new(),
        issuer,
        scopes: Some((scope_claim.clone(), required_scopes)),
    };
    validate(&policy, token).map(|claims| scopes(claims.get(&scope_claim)))
}

/// `OidcAuthenticationHandler.requireSecureRemoteUrl`: a full URL must be `https`, or `http` to a loopback host.
fn require_secure_remote_url(url: Option<&str>) -> Result<(), String> {
    let Some(url) = url.filter(|u| crate::jwks::is_full_url(u)) else { return Ok(()) };
    if url.starts_with("https://") {
        return Ok(());
    }
    // `isLoopbackHost`: `localhost`, else `InetAddress.getByName(host).isLoopbackAddress()`
    let loopback = crate::jwks::host_of(url).is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || match host.parse::<std::net::IpAddr>() {
                Ok(ip) => ip.is_loopback(),
                Err(_) => std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 0)).ok().and_then(|mut a| a.next()).is_some_and(|a| a.ip().is_loopback()),
            }
    });
    if loopback { Ok(()) } else { Err(format!("must use https:// for a remote host (plaintext http:// is only permitted to localhost/loopback); was: {url}")) }
}

/// `OidcAuthenticationHandler.resolveJwksUri`: the configured JWK set location, else the `jwks_uri` of the issuer's
/// discovery document.
fn resolve_jwks_uri(jwks: Option<&str>, issuer: Option<&str>) -> Result<String, String> {
    if let Some(jwks) = jwks {
        return Ok(jwks.to_string());
    }
    let Some(issuer) = issuer else { return Err("controlPlaneOidcJwksUri or controlPlaneOidcIssuer must be configured".into()) };
    let discovery = if issuer.ends_with('/') { format!("{issuer}.well-known/openid-configuration") } else { format!("{issuer}/.well-known/openid-configuration") };
    let text = crate::jwks::retrieve(&discovery)?;
    let document = crate::json::parse_lenient(text.as_bytes()).map_err(|e| e.to_string())?;
    match document.get("jwks_uri") {
        Some(Value::String(uri)) if !uri.trim().is_empty() => Ok(uri.clone()),
        _ => Err(format!("OIDC discovery document at {discovery} did not contain a jwks_uri")),
    }
}

/// `ControlPlaneMutualTlsConfigurationException`'s message: control-plane mTLS without a CA chain while MockServer's
/// CA is the bundled one, which names both fixes.
pub const CONTROL_PLANE_MTLS_REFUSED: &str = "controlPlaneTLSMutualAuthenticationRequired is enabled without controlPlaneTLSMutualAuthenticationCAChain while MockServer's CA certificate is the default CA bundled with MockServer, which must not be trusted for control-plane client certificates: set controlPlaneTLSMutualAuthenticationCAChain to the CA chain that signs your control-plane client certificates, or configure MockServer's own CA with certificateAuthorityCertificate and certificateAuthorityPrivateKey";

/// `ControlPlaneMutualTlsConfigurationException.BUNDLED_CA_IN_CHAIN_MESSAGE`: the control-plane CA chain holds a
/// certificate for the bundled CA's key (upstream eef1d8e8b, 9.1.0).
pub const CONTROL_PLANE_MTLS_BUNDLED_CA_IN_CHAIN: &str = "controlPlaneTLSMutualAuthenticationCAChain contains the default CA bundled with MockServer, whose private key is published in the MockServer jar, so anyone could create a client certificate the control plane accepts: remove it from controlPlaneTLSMutualAuthenticationCAChain and use the CA chain that signs your control-plane client certificates";

/// `ControlPlaneAuthenticationHandlerFactory.requireUsableControlPlaneMutualTls`: the message MockServer refuses to
/// start with, and `PUT /mockserver/configuration` answers 400 with, when control-plane mTLS is required and would
/// trust the bundled CA: a CA chain holding it, or no chain, no dynamic CA and MockServer's CA certificate the bundled
/// one. Each argument is the value in force (`None` for a property never set).
pub fn control_plane_mtls_refusal(mutual_tls_required: bool, ca_chain: Option<&str>, dynamic_authority: bool, authority_certificate: Option<&str>) -> Option<&'static str> {
    if !mutual_tls_required {
        return None;
    }
    match ca_chain.filter(|c| !c.trim().is_empty()) {
        Some(chain) => crate::tls::chain_contains_bundled_authority(Some(chain)).then_some(CONTROL_PLANE_MTLS_BUNDLED_CA_IN_CHAIN),
        None => (!dynamic_authority && crate::tls::is_bundled_authority_certificate(authority_certificate)).then_some(CONTROL_PLANE_MTLS_REFUSED),
    }
}

/// [`control_plane_mtls_refusal`] for a configuration as it stands: what `MockServer`'s constructor checks first,
/// before anything is bound.
pub fn unusable_control_plane_mtls(config: &Config) -> Option<&'static str> {
    control_plane_mtls_refusal(
        config.bool_property("controlPlaneTLSMutualAuthenticationRequired", false),
        config.property("controlPlaneTLSMutualAuthenticationCAChain").as_deref(),
        crate::tls::dynamic_authority(config),
        config.property("certificateAuthorityCertificate").as_deref(),
    )
}

/// `NettySslContextFactory.controlPlaneTrustCertificates`: the certificates of the control-plane CA chain file, as DER,
/// read as `CertificateFactory.generateCertificates` reads it (PEM blocks, DER, a PKCS#7 bundle, indefinite lengths);
/// `None` when it cannot be read.
fn chain_certificates(path: &str) -> Option<Vec<Vec<u8>>> {
    let bytes = crate::class_path::read_or_file(path.trim()).ok()?;
    let certificates = crate::tls::x509::generate_certificates(&bytes).ok()?;
    Some(certificates.into_iter().map(|c| c.der).collect())
}

/// `ControlPlaneAuthenticationHandlerFactory.controlPlaneClientCertificateTrust`: the certificates of
/// `controlPlaneTLSMutualAuthenticationCAChain`, or, without one, MockServer's own CA certificate.
fn control_plane_trust(config: &Config) -> Vec<Vec<u8>> {
    match config.property("controlPlaneTLSMutualAuthenticationCAChain").filter(|p| !p.trim().is_empty()) {
        Some(path) => chain_certificates(&path).unwrap_or_default(),
        None => crate::tls::certificate_authority_der(config).into_iter().collect(),
    }
}

/// `MTLSAuthenticationHandler.authenticate` (upstream eef1d8e8b, 9.1.0): only the client's own certificate, the first
/// one presented (the handshake proved its key), authenticates; the others serve only as untrusted intermediates of
/// its path to the control-plane trust ([`control_plane_trust`]). The verified leaf, or why the request is refused.
fn mtls_verified_leaf<'r>(config: &Config, request: &'r HttpRequest) -> Result<&'r crate::tls::client_cert::ClientCertificate, &'static str> {
    let anchors = control_plane_trust(config);
    if anchors.is_empty() {
        return Err("control plane request failed authentication no control plane CA specified");
    }
    let Some(leaf) = request.client_certificates.first() else {
        return Err("control plane request failed authentication no client certificates found");
    };
    // `MAXIMUM_INTERMEDIATES`
    let intermediates: Vec<&[u8]> = request.client_certificates.iter().skip(1).take(10).map(|c| c.der.as_slice()).collect();
    if crate::tls::client_cert::leaf_validates(&leaf.der, &intermediates, &anchors) {
        Ok(leaf)
    } else {
        Err("control plane request failed authentication no client certificates can be validated by control plane CA")
    }
}

fn mtls_rejection(config: &Config, request: &HttpRequest) -> Option<String> {
    mtls_verified_leaf(config, request).err().map(str::to_string)
}

/// `MTLSAuthenticationHandler.authenticatedResult`: the audit principal of a control-plane request mTLS verified, the
/// leaf's subject (`X500Principal.getName()`), or `sha256:<fingerprint>` when that is empty.
pub fn mtls_principal(config: &Config, request: &HttpRequest) -> Option<String> {
    let leaf = mtls_verified_leaf(config, request).ok()?;
    let subject = leaf.model.get("subjectDistinguishedName").and_then(Value::as_str).unwrap_or_default();
    if !subject.is_empty() {
        return Some(subject.to_string());
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, &leaf.der);
    Some(format!("sha256:{}", digest.as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>()))
}

/// `JWTValidator.validate`
/// The token's claims when it is valid.
fn validate(policy: &Policy, jwt: &str) -> Result<Map<String, Value>, String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 3 {
        return Err("Invalid JWT serialization: Missing dot delimiter(s)".into());
    }
    let header: Map<String, Value> = decode_json(parts[0]).ok_or_else(|| "Invalid JWT header".to_string())?;
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or_default();
    if alg == "none" {
        return Err("Unsecured (plain) JWTs are rejected, extend class to handle".into());
    }
    if parts.len() != 3 {
        return Err("Invalid serialized unsecured/JWS/JWE object: Too many part delimiters".into());
    }
    if let Some(typ) = header.get("typ").and_then(Value::as_str) && !["at+jwt", "JOSE", "JOSE+JSON", "JWT"].iter().any(|t| t.eq_ignore_ascii_case(typ)) {
        return Err(format!("JOSE header typ (type) {typ} not allowed"));
    }
    let claims: Map<String, Value> = decode_json(parts[1]).ok_or_else(|| "Payload of JWS object is not a valid JSON object".to_string())?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let kid = header.get("kid").and_then(Value::as_str);
    // `JWSVerificationKeySelector`: an algorithm outside `JWS_ALGORITHMS` selects nothing without asking the source;
    // otherwise the source (a remote set may be fetched here, and its failure is the answer) is asked for the keys
    // `JWKMatcher.forJWSHeader` accepts.
    let allowed = matches!(alg, "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "ES256" | "ES256K" | "ES384" | "ES512" | "EdDSA");
    let candidates: Vec<Map<String, Value>> = if allowed {
        policy.keys.select(kid, |k| kid.is_none_or(|kid| k.get("kid").and_then(Value::as_str) == Some(kid)) && key_supports(k, alg))?
    } else {
        Vec::new()
    };
    // RSA (PKCS#1 and PSS) and ECDSA P-256/P-384 verify against the oracle (confirmed by hand-signing a
    // token of each and diffing oracle vs mock-server). ES512 (P-521) has no verification support in
    // `ring`. `JWSAlgorithm.EdDSA` is in the oracle's declared algorithm set (`JWTValidator.JWS_ALGORITHMS`)
    // but the oracle rejects a correctly EdDSA-signed, correctly matching-`kid` JWT with "Another algorithm
    // expected, or no matching key(s) found" regardless (confirmed empirically; nimbus-jose-jwt's
    // `JWSVerificationKeySelector` apparently cannot resolve an OKP/Ed25519 JWK in the version MockServer
    // 8.0.0 bundles) — the oracle wins, so EdDSA is treated as unrecognised here too. See
    // docs/divergences.md.
    let recognized = matches!(alg, "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "ES256" | "ES384");
    if candidates.is_empty() || !recognized {
        return Err("Signed JWT rejected: Another algorithm expected, or no matching key(s) found".into());
    }
    // `DefaultJWTProcessor.process`: each candidate in the set's order. An EC key's verifier (`ECDSAVerifier`) supports
    // only its own curve's algorithm, and refuses any other with an exception that ends the search.
    let signature = B64.decode(parts[2].trim_end_matches('=')).ok();
    for key in &candidates {
        if let Some(own) = ec_curve_algorithm(key).filter(|own| *own != alg) {
            return Err(format!("Unsupported JWS algorithm {alg}, must be {own}"));
        }
        if signature.as_ref().is_some_and(|s| verify(key, alg, signing_input.as_bytes(), s)) {
            verify_claims(policy, &claims)?;
            return Ok(claims);
        }
    }
    Err("Signed JWT rejected: Invalid signature".into())
}

/// `ECDSA.resolveAlgorithm(curve)`: the one algorithm an EC key's verifier supports.
fn ec_curve_algorithm(key: &Map<String, Value>) -> Option<&'static str> {
    if key.get("kty").and_then(Value::as_str) != Some("EC") {
        return None;
    }
    match key.get("crv").and_then(Value::as_str)? {
        "P-256" => Some("ES256"),
        "secp256k1" => Some("ES256K"),
        "P-384" => Some("ES384"),
        "P-521" => Some("ES512"),
        _ => None,
    }
}

fn decode_json(part: &str) -> Option<Map<String, Value>> {
    let bytes = B64.decode(part.trim_end_matches('=')).ok()?;
    serde_json::from_slice::<Value>(&bytes).ok()?.as_object().cloned()
}

/// `HttpState.getControlPlaneAuthenticationHandler`: whether the handler chain derived from the configuration denies
/// everything. With some authentication required, the chain is built again when [`handler_signature`] changed since
/// the last build (never per request: a key file that becomes readable later is not seen until then). `build` catches
/// a chain that cannot be constructed, logs it at ERROR and denies everything (`DenyAllAuthenticationHandler`): an
/// mTLS CA chain `NettySslContextFactory.trustCertificateChain` cannot read (which ends the build before any JWT
/// handler), or a JWT key source `JWKSet.load` cannot read, whose constructor logs its own ERROR first and leaves no
/// validator for the next setter. A `PUT` can reach this too (upstream 0e8566814), e.g. turning JWT on without a key
/// source.
fn deny_all(state: &crate::state::State) -> bool {
    use crate::recorded::{Level, LogEntry};
    let config = &state.config;
    let required = |name: &str| config.bool_property(name, false);
    if !required("controlPlaneTLSMutualAuthenticationRequired")
        && !required("controlPlaneJWTAuthenticationRequired")
        && !required("controlPlaneOidcAuthenticationRequired")
        && !required("controlPlaneBasicAuthenticationRequired")
    {
        return false;
    }
    let signature = handler_signature(config);
    let mut derived = config.control_plane_authenticator.1.lock();
    if let Some(derived) = derived.as_ref().filter(|d| d.signature == signature) {
        return derived.deny_all;
    }
    let mut failure = None;
    if required("controlPlaneTLSMutualAuthenticationRequired") {
        // `controlPlaneClientCertificateTrust`: `isNotBlank`, then `PEMToFile.x509ChainFromPEMFile` of the name as
        // given, refused when it holds the bundled CA (by key); without a chain, MockServer's own CA unless that is the
        // bundled one
        match config.property("controlPlaneTLSMutualAuthenticationCAChain").filter(|p| !p.trim().is_empty()) {
            Some(path) => {
                failure = ca_chain_load_error(&path);
                if failure.is_none() && chain_certificates(&path).is_some_and(|chain| crate::tls::contains_bundled_authority(&chain)) {
                    failure = Some(format!("org.mockserver.authentication.ControlPlaneMutualTlsConfigurationException: {CONTROL_PLANE_MTLS_BUNDLED_CA_IN_CHAIN}"));
                }
            }
            None if crate::tls::contains_bundled_authority(&control_plane_trust(config)) => {
                failure = Some(format!("org.mockserver.authentication.ControlPlaneMutualTlsConfigurationException: {CONTROL_PLANE_MTLS_REFUSED}"));
            }
            None => {}
        }
    }
    if failure.is_none() && required("controlPlaneJWTAuthenticationRequired") {
        let source = config.property("controlPlaneJWTAuthenticationJWKSource").unwrap_or_default();
        if let Some(trace) = jwk_load_error(&source) {
            log_error(state, LogEntry::at(Level::Error, "exception building JWT validator for:{}").args([source]), &trace);
            failure = Some("java.lang.NullPointerException: Cannot invoke \"org.mockserver.authentication.jwt.JWTValidator.withExpectedAudience(String)\" because \"this.jwtValidator\" is null".to_string());
        }
    }
    // `new BasicAuthenticationHandler(..., BasicAuthenticationCredentials.parse(...), ...)`, last
    let mut basic = None;
    if failure.is_none() && required("controlPlaneBasicAuthenticationRequired") {
        match crate::auth_basic::configured(config) {
            Ok(credentials) => basic = Some(std::sync::Arc::new(crate::auth_basic::Handler::new(credentials, required("controlPlaneBasicAuthenticationAllowInsecure")))),
            Err(message) => failure = Some(format!("java.lang.IllegalArgumentException: {message}")),
        }
    }
    if let Some(trace) = &failure {
        let text = "control plane authentication is enabled but the authentication handler could not be created - denying all control plane requests until the configuration is corrected";
        log_error(state, LogEntry::at(Level::Error, text), trace);
    }
    let deny_all = failure.is_some();
    *derived = Some(Derived { signature, deny_all, basic });
    deny_all
}

/// What `PEMToFile.x509ChainFromPEMFile(path)` throws, as the console prints a throwable without its frames (the
/// outermost first, then each `Caused by:`), `None` when it reads the chain: `FileReader.openStreamToFileFromClassPathOrPath`
/// (the class path resource, else the file), then `CertificateFactory.generateCertificates` (JDK `X509Factory`).
fn ca_chain_load_error(path: &str) -> Option<String> {
    let reading = format!("java.lang.RuntimeException: Exception reading X509 from PEM file {path}");
    if let Some(bytes) = crate::class_path::locate(path).and_then(|resource| resource.read().ok()) {
        return ca_chain_parse_error(&reading, &bytes);
    }
    // `new FileInputStream(new File(path).getCanonicalFile())`
    let canonical = java_canonical_path(path);
    let not_found = |reason: &str| Some(format!("{reading}\nCaused by: java.io.FileNotFoundException: {canonical} ({reason})"));
    if std::fs::metadata(&canonical).is_ok_and(|m| m.is_dir()) {
        return not_found("Is a directory");
    }
    let bytes = match std::fs::read(&canonical) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return not_found("No such file or directory"),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return not_found("Permission denied"),
        Err(e) => return not_found(e.to_string().split(" (os error").next().unwrap_or_default()),
    };
    ca_chain_parse_error(&reading, &bytes)
}

/// What `CertificateFactory.generateCertificates` throws for a chain file's bytes, under `reading` (the outermost).
fn ca_chain_parse_error(reading: &str, bytes: &[u8]) -> Option<String> {
    let error = crate::tls::x509::generate_certificates(bytes).err()?;
    let mut trace = vec![reading.to_string(), "java.lang.RuntimeException: Exception creating X509 from PEM".to_string()];
    trace.extend(error.chain());
    Some(trace.join("\nCaused by: "))
}

/// `File.getCanonicalPath`: absolute against the working directory, with symbolic links resolved as far as the path
/// exists.
fn java_canonical_path(path: &str) -> String {
    let absolute = std::env::current_dir().unwrap_or_default().join(path);
    if let Ok(canonical) = std::fs::canonicalize(&absolute) {
        return canonical.display().to_string();
    }
    let mut normal = std::path::PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::ParentDir => {
                normal.pop();
            }
            std::path::Component::CurDir => {}
            other => normal.push(other),
        }
    }
    match (normal.parent().and_then(|p| std::fs::canonicalize(p).ok()), normal.file_name()) {
        (Some(parent), Some(name)) => parent.join(name).display().to_string(),
        _ => normal.display().to_string(),
    }
}

/// An ERROR `logEvent` with a throwable: the console line with the throwable after it, and the event log entry.
fn log_error(state: &crate::state::State, entry: crate::recorded::LogEntry, trace: &str) {
    if !crate::log::error_enabled(state) {
        return;
    }
    let entry = entry.throwable(trace);
    crate::log::error_with_throwable(state, &entry, None, trace);
    state.log.message(entry);
}

/// What `JWTAuthenticationHandler`'s constructor throws for `source` (the first line of its stack trace), `None` when
/// it builds a validator: a full URL is fetched later; anything else is `JWKSet.load(new File(
/// FilePath.absolutePathFromClassPathOrPath(source)))`: the class path resource's URL path (a jar entry's
/// `file:<jar>!/<entry>` names no file), else the name against the working directory.
fn jwk_load_error(source: &str) -> Option<String> {
    if crate::jwks::is_full_url(source) {
        return None;
    }
    let path = jwk_path(source);
    // `FileInputStream.open`'s `FileNotFoundException`: the path and the OS's reason
    let not_found = |reason: &str| Some(format!("java.io.FileNotFoundException: {path} ({reason})"));
    if std::fs::metadata(&path).is_ok_and(|m| m.is_dir()) {
        return not_found("Is a directory");
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return not_found("No such file or directory"),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return not_found("Permission denied"),
        Err(e) => return not_found(e.to_string().split(" (os error").next().unwrap_or_default()),
    };
    jwk_set_parse_error(&bytes)
}

/// `new File(FilePath.absolutePathFromClassPathOrPath(source))` as a path: `File.getAbsolutePath` of an empty name is
/// the working directory.
fn jwk_path(source: &str) -> String {
    if source.is_empty() {
        return std::env::current_dir().unwrap_or_default().display().to_string();
    }
    crate::class_path::absolute_path(source)
}

/// What `JWKSet.parse` throws for a key file's bytes (the first line of its stack trace), `None` when it reads them.
fn jwk_set_parse_error(bytes: &[u8]) -> Option<String> {
    // `JWKSet.parse`: `JSONObjectUtils.parse` (a blank string is refused before Gson; `null` parses to no map at all),
    // then a `keys` array whose every entry `JWK.parse` must accept (keys of an unsupported type are skipped)
    let parse = |message: &str| Some(format!("java.text.ParseException: {message}"));
    let text = String::from_utf8_lossy(bytes);
    if text.trim().is_empty() {
        return parse("Invalid JSON object");
    }
    let object = match crate::json::parse_lenient(bytes) {
        Ok(Value::Object(object)) => object,
        Ok(Value::Null) => return Some(NULL_MAP.into()),
        _ => return parse("Invalid JSON object"),
    };
    match object.get("keys") {
        None | Some(Value::Null) => parse("Missing required \"keys\" member"),
        Some(Value::Array(keys)) => {
            for (i, key) in keys.iter().enumerate() {
                match key {
                    Value::Null => return Some(NULL_MAP.into()),
                    Value::Object(key) => match jwk::parse(key) {
                        Ok(()) => {}
                        Err(jwk::Error::Parse(m)) if m.starts_with("Unsupported key type") => {}
                        Err(jwk::Error::Parse(m)) => return parse(&format!("Invalid JWK at position {i}: {m}")),
                        Err(jwk::Error::Throwable(trace)) => return Some(trace),
                    },
                    _ => return parse("The \"keys\" JSON array must contain JSON objects only"),
                }
            }
            None
        }
        Some(_) => parse("Unexpected type of JSON object member keys"),
    }
}

/// `JSONObjectUtils.getGeneric` on a `null` map: `JWKSet.parse(null)` and `JWK.parse(null)` both end here.
const NULL_MAP: &str = "java.lang.NullPointerException: Cannot invoke \"java.util.Map.get(Object)\" because \"o\" is null";

/// nimbus-jose-jwt 10.9.1's `JWK.parse`, as far as it can fail: the per-type `parse` reads its own members, then the
/// metadata (`JWKMetadata`, in argument order), then the constructors check (`JWK`, then the key type's own): the
/// `x5c` certificates are read as the JDK reads them (`crate::tls::x509`), and an RSA or EC key must match the first.
mod jwk {
    use crate::tls::x509::PublicKey;
    use num_bigint::BigUint;
    use serde_json::{Map, Value};

    pub enum Error {
        /// A `ParseException` (or an `IllegalArgumentException` / `NullPointerException` re-thrown as one).
        Parse(String),
        /// Anything else, which escapes `JWKSet.parse`: the throwable's first line.
        Throwable(String),
    }

    impl From<String> for Error {
        fn from(message: String) -> Error {
            Error::Parse(message)
        }
    }

    impl From<&str> for Error {
        fn from(message: &str) -> Error {
            Error::Parse(message.to_string())
        }
    }

    type Result<T> = std::result::Result<T, Error>;

    /// `JSONObjectUtils.getGeneric`: absent and `null` are `None`; a value of another type is refused.
    fn generic<'a>(o: &'a Map<String, Value>, name: &str, is: fn(&Value) -> bool) -> Result<Option<&'a Value>> {
        match o.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(v) if is(v) => Ok(Some(v)),
            Some(_) => Err(format!("Unexpected type of JSON object member {name}").into()),
        }
    }

    fn string<'a>(o: &'a Map<String, Value>, name: &str) -> Result<Option<&'a str>> {
        Ok(generic(o, name, Value::is_string)?.and_then(Value::as_str))
    }

    fn array<'a>(o: &'a Map<String, Value>, name: &str) -> Result<Option<&'a Vec<Value>>> {
        Ok(generic(o, name, Value::is_array)?.and_then(Value::as_array))
    }

    /// `JSONObjectUtils.getLong`
    fn long(o: &Map<String, Value>, name: &str) -> Result<()> {
        match generic(o, name, Value::is_number)? {
            Some(_) => Ok(()),
            None => Err(format!("JSON object member {name} is missing or null").into()),
        }
    }

    pub fn parse(o: &Map<String, Value>) -> Result<()> {
        let Some(kty) = string(o, "kty")? else { return Err("Missing key type \"kty\" parameter".into()) };
        match kty {
            "EC" => ec(o),
            "RSA" => rsa(o),
            "oct" => {
                let k = string(o, "k")?;
                metadata(o)?;
                k.map(|_| ()).ok_or_else(|| "The key value must not be null".into())
            }
            "OKP" => okp(o),
            other => Err(format!("Unsupported key type \"kty\" parameter: {other}").into()),
        }
    }

    /// `Curve.parse` of the `crv` member.
    fn curve(o: &Map<String, Value>) -> Result<&str> {
        string(o, "crv")?.filter(|c| !c.trim().is_empty()).ok_or_else(|| "The cryptographic curve string must not be null or empty".into())
    }

    fn ec(o: &Map<String, Value>) -> Result<()> {
        let crv = curve(o)?;
        let (x, y, _d) = (string(o, "x")?, string(o, "y")?, string(o, "d")?);
        let chain = metadata(o)?;
        let x = x.ok_or("The x coordinate must not be null")?;
        let y = y.ok_or("The y coordinate must not be null")?;
        // `ensurePublicCoordinatesOnCurve`
        let Some((p, a, b)) = curve_parameters(crv) else { return Err(format!("Unknown / unsupported curve: {crv}").into()) };
        let (x, y) = (BigUint::from_bytes_be(&base64_url(x)), BigUint::from_bytes_be(&base64_url(y)));
        if y.pow(2) % &p != (x.pow(3) + &a * &x + &b) % &p {
            return Err(format!("Invalid EC JWK: The 'x' and 'y' public coordinates are not on the {crv} curve").into());
        }
        ensure_matches(chain, |key| matches!(key, PublicKey::Ec { x: kx, y: ky } if *kx == x && *ky == y))
    }

    /// `ECKey.SUPPORTED_CURVES`: the field prime and the coefficients `a` and `b` of `y² = x³ + ax + b`.
    fn curve_parameters(crv: &str) -> Option<(BigUint, BigUint, BigUint)> {
        let hex = |h: &str| BigUint::parse_bytes(h.as_bytes(), 16).expect("curve constant");
        let (p, a, b) = match crv {
            "P-256" => (hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"), None, hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")),
            "secp256k1" => (hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"), Some(BigUint::ZERO), BigUint::from(7u8)),
            "P-384" => (
                hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
                None,
                hex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
            ),
            "P-521" => (
                (BigUint::from(1u8) << 521u32) - 1u8,
                None,
                hex("51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"),
            ),
            _ => return None,
        };
        // the NIST curves' `a` is `p - 3`
        let a = a.unwrap_or_else(|| &p - 3u8);
        Some((p, a, b))
    }

    fn rsa(o: &Map<String, Value>) -> Result<()> {
        let n = string(o, "n")?;
        let e = string(o, "e")?;
        string(o, "d")?;
        let crt: Vec<bool> = ["p", "q", "dp", "dq", "qi"].iter().map(|m| string(o, m).map(|v| v.is_some())).collect::<Result<_>>()?;
        if o.contains_key("oth") && let Some(entries) = array(o, "oth")? {
            for entry in entries.iter().filter_map(Value::as_object) {
                // `OtherPrimesInfo`'s message-less `Objects.requireNonNull`, which nothing catches
                let present: Vec<bool> = ["r", "d", "t"].iter().map(|m| string(entry, m).map(|v| v.is_some())).collect::<Result<_>>()?;
                if present.contains(&false) {
                    return Err(Error::Throwable("java.lang.NullPointerException".into()));
                }
            }
        }
        let chain = metadata(o)?;
        let n = n.ok_or("The modulus value must not be null")?;
        let e = e.ok_or("The public exponent value must not be null")?;
        let (n, e) = (BigUint::from_bytes_be(&base64_url(n)), BigUint::from_bytes_be(&base64_url(e)));
        ensure_matches(chain, |key| matches!(key, PublicKey::Rsa { modulus, exponent } if *exponent == e && *modulus == n))?;
        // complete or absent (`oth` alone included); a partial set names the first missing part
        if crt.contains(&true) && crt.contains(&false) {
            const PARTS: [&str; 4] = ["first prime factor", "second prime factor", "first factor CRT exponent", "second factor CRT exponent"];
            let part = crt.iter().position(|present| !present).and_then(|i| PARTS.get(i)).copied().unwrap_or("first CRT coefficient");
            return Err(format!("Incomplete second private (CRT) representation: The {part} must not be null").into());
        }
        Ok(())
    }

    fn okp(o: &Map<String, Value>) -> Result<()> {
        let crv = curve(o)?;
        let (x, _d) = (string(o, "x")?, string(o, "d")?);
        metadata(o)?;
        if !["Ed25519", "Ed448", "X25519", "X448"].contains(&crv) {
            return Err(format!("Unknown / unsupported curve: {crv}").into());
        }
        x.map(|_| ()).ok_or_else(|| "The x parameter must not be null".into())
    }

    /// The `JWKMetadata` arguments in order, then the `JWK` constructor's checks.
    fn metadata(o: &Map<String, Value>) -> Result<Chain> {
        // `KeyUse.parse`
        let usage = string(o, "use")?;
        if usage.is_some_and(|u| u.trim().is_empty()) {
            return Err("JWK use value must not be empty or blank".into());
        }
        // `getStringList` (`toArray(new String[0])`), then `KeyOperation.parse`
        let mut ops: Option<Vec<&str>> = None;
        if let Some(items) = array(o, "key_ops")? {
            if items.iter().any(|i| !i.is_string() && !i.is_null()) {
                return Err("JSON object member key_ops is not an array of strings".into());
            }
            const OPERATIONS: [&str; 8] = ["sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"];
            let names: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
            if let Some(unknown) = names.iter().find(|n| !OPERATIONS.contains(n)) {
                return Err(format!("Invalid JWK operation: {unknown}").into());
            }
            ops = Some(names);
        }
        string(o, "alg")?;
        string(o, "kid")?;
        if let Some(url) = string(o, "x5u")? {
            crate::java_uri::parse(url)?;
        }
        string(o, "x5t")?;
        string(o, "x5t#S256")?;
        // `X509CertChainUtils.toBase64List`; an empty chain counts as none
        let mut chain: Vec<&str> = Vec::new();
        for (i, item) in array(o, "x5c")?.into_iter().flatten().enumerate() {
            match item {
                Value::Null => return Err(format!("The X.509 certificate at position {i} must not be null").into()),
                Value::String(s) => chain.push(s),
                _ => return Err(format!("The X.509 certificate at position {i} must be encoded as a Base64 string").into()),
            }
        }
        for name in ["exp", "nbf", "iat"] {
            if o.get(name).is_some_and(|v| !v.is_null()) {
                long(o, name)?;
            }
        }
        if o.get("revoked").is_some_and(|v| !v.is_null()) {
            // `KeyRevocation.parse`
            let revoked = generic(o, "revoked", Value::is_object)?.and_then(Value::as_object).expect("checked non-null");
            long(revoked, "revoked_at")?;
            string(revoked, "reason")?;
        }
        // `KeyUseAndOpsConsistency.areConsistent`
        let allowed: Option<&[&str]> = match usage {
            Some("sig") => Some(&["sign", "verify"]),
            Some("enc") => Some(&["encrypt", "decrypt", "wrapKey", "unwrapKey"]),
            _ => None,
        };
        if let (Some(allowed), Some(ops)) = (allowed, &ops) && ops.iter().any(|op| !allowed.contains(op)) {
            return Err("The key use \"use\" and key options \"key_ops\" parameters are not consistent, see RFC 7517, section 4.3".into());
        }
        // `X509CertChainUtils.parse`: `X509CertUtils.parseWithException` of each entry (none for one that decodes to
        // no bytes); a `CertificateException` names its position, anything else escapes as it is
        if chain.is_empty() {
            return Ok(None);
        }
        let mut keys = Vec::new();
        for (i, encoded) in chain.iter().enumerate() {
            let der = base64_url(encoded);
            if der.is_empty() {
                keys.push(None);
                continue;
            }
            match crate::tls::x509::generate_certificate(&der) {
                Ok(certificate) => keys.push(Some(certificate.public_key)),
                Err(e) if e.class.starts_with("java.security.cert.") => {
                    return Err(format!("Invalid X.509 certificate chain \"x5c\": Invalid X.509 certificate at position {i}: {}", e.message()).into());
                }
                Err(e) => return Err(e.message().into()),
            }
        }
        Ok(Some(keys))
    }

    /// The parsed `x5c` chain: each certificate's public key, `None` for an entry that decoded to no bytes.
    type Chain = Option<Vec<Option<PublicKey>>>;

    /// `ensureMatches` / the RSA constructor's check: the first certificate's key must be the JWK's own (an entry
    /// that decoded to nothing fails on the `null` certificate).
    fn ensure_matches(chain: Chain, matches: impl Fn(&PublicKey) -> bool) -> Result<()> {
        match chain.as_deref().and_then(<[_]>::first) {
            None => Ok(()),
            Some(None) => Err("Cannot invoke \"java.security.cert.X509Certificate.getPublicKey()\" because the return value of \"java.util.List.get(int)\" is null".into()),
            Some(Some(key)) if matches(key) => Ok(()),
            Some(Some(_)) => Err("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters".into()),
        }
    }

    /// `Base64Codec.decode`: characters outside both alphabets are skipped, and a final group of two or three
    /// characters yields its whole bytes.
    pub(super) fn base64_url(text: &str) -> Vec<u8> {
        let digit = |c: u8| match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        };
        let digits: Vec<u32> = text.bytes().filter_map(digit).map(u32::from).collect();
        let mut out = Vec::with_capacity(digits.len() * 3 / 4);
        for group in digits.chunks(4) {
            let bits = group.iter().enumerate().fold(0u32, |bits, (j, d)| bits | d << (18 - 6 * j));
            let bytes = [(bits >> 16) as u8, (bits >> 8) as u8, bits as u8];
            out.extend_from_slice(&bytes[..group.len().saturating_sub(1)]);
        }
        out
    }
}

/// The keys of a JWK set file (or of one JWK, which [`jwk_load_error`] refuses first).
fn jwk_file(source: Option<&str>) -> Vec<Map<String, Value>> {
    let Some(source) = source else { return Vec::new() };
    let text = std::fs::read_to_string(jwk_path(source.trim())).unwrap_or_default();
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let keys = v.get("keys").and_then(Value::as_array).cloned().unwrap_or_else(|| if v.is_object() { vec![v.clone()] } else { Vec::new() });
    keys.into_iter().filter_map(|k| k.as_object().cloned()).collect()
}

fn key_supports(key: &Map<String, Value>, alg: &str) -> bool {
    let kty = key.get("kty").and_then(Value::as_str).unwrap_or_default();
    let family = match alg {
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => "RSA",
        "ES256" | "ES256K" | "ES384" | "ES512" => "EC",
        "EdDSA" => "OKP",
        _ => return false,
    };
    // `JWKMatcher.forJWSHeader`: the key type, `use` signature or unset, `alg` the header's or unset
    kty == family
        && key.get("use").and_then(Value::as_str).is_none_or(|u| u == "sig")
        && key.get("alg").and_then(Value::as_str).is_none_or(|a| a == alg)
}

fn verification_algorithm(alg: &str) -> Option<&'static ring::signature::RsaParameters> {
    use ring::signature::*;
    Some(match alg {
        "RS256" => &RSA_PKCS1_2048_8192_SHA256,
        "RS384" => &RSA_PKCS1_2048_8192_SHA384,
        "RS512" => &RSA_PKCS1_2048_8192_SHA512,
        "PS256" => &RSA_PSS_2048_8192_SHA256,
        "PS384" => &RSA_PSS_2048_8192_SHA384,
        "PS512" => &RSA_PSS_2048_8192_SHA512,
        _ => return None,
    })
}

/// Verifies `signature` over `message` with `key` (a JWK) under `alg`. RSA (PKCS#1 and PSS) uses the raw
/// modulus/exponent (`n`, `e`) via `RsaPublicKeyComponents`; ECDSA (`ES256`/`ES384`, P-256/P-384) builds an
/// uncompressed SEC1 point (`0x04 || x || y`) from the JWK's `x`/`y`. `alg` is assumed recognized (see
/// `validate`'s `recognized` check) by the caller — EdDSA is deliberately not handled here, see its comment.
fn verify(key: &Map<String, Value>, alg: &str, message: &[u8], signature: &[u8]) -> bool {
    let component = |name: &str| key.get(name).and_then(Value::as_str).and_then(|v| B64.decode(v.trim_end_matches('=')).ok());
    match alg {
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
            let Some(algorithm) = verification_algorithm(alg) else { return false };
            let (Some(n), Some(e)) = (component("n"), component("e")) else { return false };
            ring::signature::RsaPublicKeyComponents { n: &n, e: &e }.verify(algorithm, message, signature).is_ok()
        }
        "ES256" | "ES384" => {
            let (Some(x), Some(y)) = (component("x"), component("y")) else { return false };
            let algorithm: &dyn ring::signature::VerificationAlgorithm =
                if alg == "ES256" { &ring::signature::ECDSA_P256_SHA256_FIXED } else { &ring::signature::ECDSA_P384_SHA384_FIXED };
            let mut point = Vec::with_capacity(1 + x.len() + y.len());
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            ring::signature::UnparsedPublicKey::new(algorithm, point).verify(message, signature).is_ok()
        }
        _ => false,
    }
}

/// `CustomJWTClaimsVerifier` over nimbus' `DefaultJWTClaimsVerifier`: audience, required claims, exact matches,
/// then the time window.
fn verify_claims(policy: &Policy, claims: &Map<String, Value>) -> Result<(), String> {
    // `OidcJWTClaimsVerifier.verify`: issuer, then scopes, then the base verifier.
    if let Some(expected) = &policy.issuer {
        let issuer = claims.get("iss").and_then(Value::as_str);
        if issuer != Some(expected.as_str()) {
            return Err(format!("JWT iss claim has value {}, must be {expected}", issuer.unwrap_or("null")));
        }
    }
    if let Some((claim, required)) = &policy.scopes {
        let granted = scopes(claims.get(claim));
        let mut missing: Vec<&String> = required.iter().filter(|s| !granted.contains(s)).collect();
        if !missing.is_empty() {
            missing.sort();
            return Err(format!("JWT missing required scopes: [{}]", missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
        }
    }
    if let Some(expected) = policy.audience.clone() {
        let audience: Vec<String> = match claims.get("aud") {
            Some(Value::String(a)) => vec![a.clone()],
            Some(Value::Array(items)) => items.iter().filter_map(|a| a.as_str().map(str::to_string)).collect(),
            _ => Vec::new(),
        };
        if audience.is_empty() {
            return Err("JWT missing required audience".into());
        }
        if !audience.contains(&expected) {
            return Err(format!("JWT audience rejected: [{}]", audience.join(", ")));
        }
    }
    let missing: Vec<&String> = policy.required.iter().filter(|c| !claims.contains_key(c.as_str())).collect();
    if !missing.is_empty() {
        return Err(format!("JWT missing required claims: [{}]", missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }
    for (name, expected) in &policy.matching {
        match claims.get(name) {
            None => return Err(format!("JWT missing required claims: [{name}]")),
            Some(actual) if actual.as_str() != Some(expected.as_str()) => {
                let shown = actual.as_str().map(str::to_string).unwrap_or_else(|| actual.to_string());
                return Err(format!("JWT {name} claim has value {shown}, must be {expected}"));
            }
            _ => {}
        }
    }
    let now = chrono::Utc::now().timestamp();
    if let Some(exp) = claims.get("exp").and_then(Value::as_i64) && exp + MAX_CLOCK_SKEW < now {
        return Err("Expired JWT".into());
    }
    if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64) && nbf - MAX_CLOCK_SKEW > now {
        return Err("JWT before use time".into());
    }
    Ok(())
}

/// `controlPlaneJWTAuthenticationMatchingClaims`: `name=value` pairs separated by commas.
fn matching_claims(config: &Config) -> Vec<(String, String)> {
    config
        .property("controlPlaneJWTAuthenticationMatchingClaims")
        .map(|v| v.split(',').filter_map(|pair| pair.split_once('=').map(|(k, v)| (k.to_string(), v.to_string()))).collect())
        .unwrap_or_default()
}

/// `OidcScopeParser.parseScopes`: a space-separated string, or a list of them.
fn scopes(value: Option<&Value>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    fn add(out: &mut Vec<String>, v: &Value) {
        match v {
            Value::String(s) => {
                for part in s.split_whitespace() {
                    if !out.iter().any(|o| o == part) {
                        out.push(part.to_string());
                    }
                }
            }
            Value::Array(items) => items.iter().for_each(|i| add(out, i)),
            Value::Null => {}
            other => {
                let text = other.to_string();
                if !out.contains(&text) {
                    out.push(text);
                }
            }
        }
    }
    if let Some(v) = value {
        add(&mut out, v);
    }
    out
}

/// `ProxyAuthenticationValidator`: with `proxyAuthenticationUsername` and `proxyAuthenticationPassword` set, a proxy
/// request needs `Proxy-Authorization: Basic base64(username:password)`; otherwise the `407` to answer.
pub fn proxy_rejection(config: &Config, request: &HttpRequest) -> Option<crate::reply::Reply> {
    let non_blank = |name: &str| config.property(name).filter(|v| !v.trim().is_empty());
    let (username, password) = (non_blank("proxyAuthenticationUsername")?, non_blank("proxyAuthenticationPassword")?);
    let expected = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}")));
    let supplied = request.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization")).flat_map(|(_, v)| v.iter());
    if supplied.fold(false, |ok, v| ok | constant_time_eq(v.as_bytes(), expected.as_bytes())) {
        return None;
    }
    let realm = config.property("proxyAuthenticationRealm").unwrap_or_else(|| "MockServer HTTP Proxy".into());
    let mut reply = crate::reply::Reply::status(407);
    reply.headers.push(("proxy-authenticate".into(), format!("Basic realm=\"{}\", charset=\"UTF-8\"", java_compat::escape_java(&realm))));
    Some(reply)
}

/// `ConstantTimeEquals.equals`.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

/// `ConstantTimeEqualsTest`. Upstream's helper has `String`/`byte[]` overloads and treats two nulls as equal; here
/// the compare takes bytes, and the callers (`proxy_rejection`, JWT/OIDC checks) never hold a null, so the null
/// overloads have no Rust counterpart. The timing property itself is structural (every byte of the longer input is
/// visited whatever the first difference), which `visits_every_position` pins without a wall-clock threshold.
#[cfg(test)]
mod constant_time_tests {
    use super::constant_time_eq;

    #[test]
    fn matches_equal_strings() {
        assert!(constant_time_eq(b"correct-secret", b"correct-secret"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn does_not_match_different_strings() {
        assert!(!constant_time_eq(b"correct-secret", b"wrong-secret"));
        // same length, single byte difference
        assert!(!constant_time_eq(b"secret", b"secreT"));
        // prefix of the other (different length), both ways round
        assert!(!constant_time_eq(b"secret", b"secret-longer"));
        assert!(!constant_time_eq(b"secret-longer", b"secret"));
        // an empty input against a non-empty one, and a trailing NUL against a shorter input
        assert!(!constant_time_eq(b"", b"x"));
        assert!(!constant_time_eq(b"secret", b"secret\0"));
    }

    #[test]
    fn matches_utf8_bytes() {
        assert!(constant_time_eq("naïve-Ω".as_bytes(), "naïve-Ω".as_bytes()));
        assert!(!constant_time_eq("naïve-Ω".as_bytes(), "naive-Ω".as_bytes()));
    }

    /// The side-channel property without timing: the verdict depends on every position, so a difference in the
    /// first byte, the last byte or only the length each flips it, and no early exit can leave a position unread.
    #[test]
    fn visits_every_position() {
        let base = b"0123456789abcdef".to_vec();
        for i in 0..base.len() {
            let mut other = base.clone();
            other[i] ^= 0x01;
            assert!(!constant_time_eq(&base, &other), "difference at {i} must be seen");
            assert!(!constant_time_eq(&other, &base), "difference at {i} must be seen, reversed");
        }
        assert!(!constant_time_eq(&base, &base[..base.len() - 1]));
    }
}

/// Differential vectors from the oracle's JDK (Temurin 26.0.2's `sun.security` sources, run as openjdk 26.0.2 with
/// nimbus-jose-jwt 10.9.1 and BouncyCastle registered last, as MockServer does): `tests/files/x509/Gen.java` mutates
/// the base certificates' DER trees and records what `CertificateFactory.generateCertificates` (a CA chain file) and
/// `JWKSet.parse` (the certificate as `x5c[0]` of the base's own key) answer, in `vectors.tsv`. The mutations are
/// replayed here with the same tree rules.
#[cfg(test)]
mod x509_vectors {
    use crate::tls::x509::{generate_certificate, generate_certificates, PublicKey};
    use base64::Engine;
    use num_bigint::BigUint;

    #[derive(Clone)]
    struct Node {
        tag: u8,
        kids: Option<Vec<Node>>,
        raw: Option<Vec<u8>>,
        /// 1: an OCTET STRING holding one value, 2: a BIT STRING (`00` then one value)
        encap: u8,
        indef: bool,
    }

    fn read_tl(b: &[u8], at: usize) -> Option<(u8, usize, usize)> {
        if at + 2 > b.len() || b[at] & 0x1f == 0x1f {
            return None;
        }
        let (l, mut p) = (b[at + 1], at + 2);
        let len = if l < 0x80 {
            usize::from(l)
        } else {
            let c = usize::from(l & 0x7f);
            if c == 0 || c > 3 || p + c > b.len() {
                return None;
            }
            let v = b[p..p + c].iter().fold(0usize, |v, x| v << 8 | usize::from(*x));
            p += c;
            v
        };
        (p + len <= b.len()).then_some((b[at], p, len))
    }

    fn parse_all(b: &[u8]) -> Option<Vec<Node>> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < b.len() {
            let (tag, p, len) = read_tl(b, at)?;
            let content = &b[p..p + len];
            let node = if tag & 0x20 != 0 {
                Node { tag, kids: Some(parse_all(content)?), raw: None, encap: 0, indef: false }
            } else {
                Node { tag, kids: None, raw: Some(content.to_vec()), encap: 0, indef: false }
            };
            out.push(node);
            at = p + len;
        }
        Some(out)
    }

    fn encapsulate(n: &mut Node) {
        let Some(kids) = n.kids.as_mut() else { return };
        kids.iter_mut().for_each(encapsulate);
        let size = kids.len();
        if n.tag == 0x30 && (size == 2 || size == 3) && kids[0].tag == 0x06 {
            let last = &mut kids[size - 1];
            if last.tag == 0x04 && let Some(mut inner) = last.raw.as_deref().and_then(parse_all).filter(|i| i.len() == 1) {
                encapsulate(&mut inner[0]);
                last.kids = Some(inner);
                last.raw = None;
                last.encap = 1;
            }
        }
        if n.tag == 0x30 && size == 2 && kids[0].tag == 0x30 {
            let bits = &mut kids[1];
            if bits.tag == 0x03 && bits.raw.as_ref().is_some_and(|r| r.len() > 1 && r[0] == 0) && let Some(mut inner) = parse_all(&bits.raw.as_ref().expect("raw")[1..]).filter(|i| i.len() == 1 && i[0].tag == 0x30) {
                encapsulate(&mut inner[0]);
                bits.kids = Some(inner);
                bits.raw = None;
                bits.encap = 2;
            }
        }
    }

    fn content(n: &Node) -> Vec<u8> {
        if let Some(raw) = &n.raw {
            return raw.clone();
        }
        let mut body = Vec::new();
        if n.encap == 2 {
            body.push(0);
        }
        for k in n.kids.as_ref().expect("kids") {
            body.extend(encode(k));
        }
        body
    }

    fn encode(n: &Node) -> Vec<u8> {
        let body = content(n);
        let mut out = vec![n.tag];
        if n.indef && n.raw.is_none() {
            out.push(0x80);
            out.extend(body);
            out.extend([0, 0]);
            return out;
        }
        let len = body.len();
        match len {
            0..=0x7f => out.push(len as u8),
            0x80..=0xff => out.extend([0x81, len as u8]),
            0x100..=0xffff => out.extend([0x82, (len >> 8) as u8, len as u8]),
            _ => out.extend([0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]),
        }
        out.extend(body);
        out
    }

    fn hex(h: &str) -> Vec<u8> {
        (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).expect("hex")).collect()
    }

    fn at<'a>(root: &'a mut Node, path: &[usize]) -> &'a mut Node {
        path.iter().fold(root, |n, &i| &mut n.kids.as_mut().expect("kids")[i])
    }

    /// `Gen.apply`; `None` where the generator's own mutation failed (it skips those).
    fn apply(base: &Node, ops: &str) -> Option<Vec<u8>> {
        let mut root = base.clone();
        let mut whole: Option<Vec<u8>> = None;
        for op in ops.split(' ').filter(|o| !o.is_empty()) {
            let (p, what) = op.split_once(':')?;
            if p == "file" {
                let w = whole.get_or_insert_with(|| encode(&root));
                if let Some(t) = what.strip_prefix("trunc=") {
                    w.truncate(t.parse().ok()?);
                } else if let Some(a) = what.strip_prefix("append=") {
                    w.extend(hex(a));
                }
                continue;
            }
            let path: Vec<usize> = if p == "r" { Vec::new() } else { p.split('.').map(|i| i.parse().expect("index")).collect() };
            if let Some(t) = what.strip_prefix("tag=") {
                let n = at(&mut root, &path);
                let c = content(n);
                *n = Node { tag: u8::from_str_radix(t, 16).ok()?, kids: None, raw: Some(c), encap: 0, indef: n.indef };
            } else if what == "empty" {
                let n = at(&mut root, &path);
                n.raw = Some(Vec::new());
                n.kids = None;
                n.encap = 0;
            } else if what == "del" || what == "dup" {
                let (last, parent) = path.split_last()?;
                let parent = at(&mut root, parent);
                let kids = parent.kids.as_mut()?;
                if what == "del" {
                    kids.remove(*last);
                } else {
                    let copy = kids[*last].clone();
                    kids.insert(last + 1, copy);
                }
            } else if what == "shrink" {
                at(&mut root, &path).raw.as_mut()?.pop();
            } else if what == "grow" {
                at(&mut root, &path).raw.as_mut()?.push(0);
            } else if let Some(h) = what.strip_prefix("set=") {
                let n = at(&mut root, &path);
                n.raw = Some(hex(h));
                n.kids = None;
                n.encap = 0;
            } else if what == "indef" {
                at(&mut root, &path).indef = true;
            }
        }
        Some(whole.unwrap_or_else(|| encode(&root)))
    }

    fn unescape(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('u') => {
                    let code: String = chars.by_ref().take(4).collect();
                    out.push(char::from_u32(u32::from_str_radix(&code, 16).expect("hex")).expect("char"));
                }
                Some(other) => out.push(other),
                None => {}
            }
        }
        out
    }

    fn b64url(v: &BigUint) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_bytes_be())
    }

    #[test]
    fn match_the_jdk() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/x509");
        let mut bases = std::collections::HashMap::new();
        for name in ["rsa_v3", "ec_v3", "rsa_v1", "p7b"] {
            let der = std::fs::read(dir.join(format!("{name}.der"))).expect("base");
            let mut node = parse_all(&der).expect("base parses").remove(0);
            encapsulate(&mut node);
            assert_eq!(encode(&node), der, "round trip of {name}");
            bases.insert(name, node);
        }
        let key = |name: &str| match generate_certificate(&encode(&bases[name])).expect("base certificate").public_key {
            PublicKey::Rsa { modulus, exponent } => format!("\"kty\":\"RSA\",\"n\":\"{}\",\"e\":\"{}\"", b64url(&modulus), b64url(&exponent)),
            PublicKey::Ec { x, y } => format!("\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{}\",\"y\":\"{}\"", b64url(&x), b64url(&y)),
            PublicKey::Other => panic!("base key"),
        };
        let keys: std::collections::HashMap<&str, String> = [("rsa_v3", key("rsa_v3")), ("rsa_v1", key("rsa_v3")), ("p7b", key("rsa_v3")), ("pem", key("rsa_v3")), ("ec_v3", key("ec_v3"))].into();
        const PREFIX: &str = "java.text.ParseException: Invalid JWK at position 0: Invalid X.509 certificate chain \"x5c\": Invalid X.509 certificate at position 0: ";
        let text = std::fs::read_to_string(dir.join("vectors.tsv")).expect("vectors");
        let (mut failures, mut count) = (Vec::new(), 0);
        let standard = |name: &str| base64::engine::general_purpose::STANDARD.encode(encode(&bases[name]));
        // `Base64.getMimeEncoder(64, "\n")`
        let mime = |name: &str| standard(name).as_bytes().chunks(64).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("\n");
        let pem = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", mime("rsa_v3"));
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let fields: Vec<&str> = line.split('\t').collect();
            let [base, ops, ca, jwk] = fields[..] else { panic!("line {line}") };
            if base == "jwk" {
                let json = unescape(ops)
                    .replace("{RSA_KEY}", &keys["rsa_v3"])
                    .replace("{EC_KEY}", &keys["ec_v3"])
                    .replace("{RSA_PEM}", &base64::engine::general_purpose::STANDARD.encode(&pem))
                    .replace("{RSA}", &standard("rsa_v3"))
                    .replace("{EC}", &standard("ec_v3"));
                count += 1;
                let actual = super::jwk_set_parse_error(json.as_bytes()).unwrap_or_else(|| "OK".into());
                if actual != unescape(jwk) {
                    failures.push(format!("jwk {ops}\n  want: {}\n  got:  {actual}", unescape(jwk)));
                }
                continue;
            }
            let data = if base == "pem" {
                // the template's characters as ISO-8859-1 bytes
                unescape(ops).replace("{C}", &mime("rsa_v3")).replace("{E}", &mime("ec_v3")).chars().map(|c| c as u32 as u8).collect()
            } else {
                apply(&bases[base], ops).unwrap_or_else(|| panic!("{base} {ops}: the mutation does not apply"))
            };
            count += 1;
            let actual_ca = match generate_certificates(&data) {
                Ok(certificates) => format!("OK {}", certificates.len()),
                Err(e) => e.chain().join("\nCaused by: "),
            };
            if actual_ca != unescape(ca) {
                failures.push(format!("{base} {ops}\n  ca want: {}\n  ca got:  {actual_ca}", unescape(ca)));
            }
            let json = format!("{{\"keys\":[{{{},\"x5c\":[\"{}\"]}}]}}", keys[base], base64::engine::general_purpose::STANDARD.encode(&data));
            let actual_jwk = super::jwk_set_parse_error(json.as_bytes()).unwrap_or_else(|| "OK".into());
            let want_jwk = unescape(jwk).strip_prefix('~').map(|m| format!("{PREFIX}{m}")).unwrap_or_else(|| unescape(jwk));
            if actual_jwk != want_jwk {
                failures.push(format!("{base} {ops}\n  x5c want: {want_jwk}\n  x5c got:  {actual_jwk}"));
            }
        }
        assert!(count > 2000, "{count} vectors replayed");
        assert!(failures.is_empty(), "{} of {count} vectors differ:\n{}", failures.len(), failures.join("\n"));
    }

    /// `tests/files/x509/More.java`: the extension classes, key algorithms, PKCS#7 signer attributes and
    /// CRLs past `Gen.java`'s bases, each base in `more/<base>.der` with the JWK members of its `x5c` column on an `@`
    /// line of `more.tsv`.
    #[test]
    fn match_the_jdk_past_the_first_bases() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/x509");
        const PREFIX: &str = "java.text.ParseException: Invalid JWK at position 0: Invalid X.509 certificate chain \"x5c\": Invalid X.509 certificate at position 0: ";
        let text = std::fs::read_to_string(dir.join("more.tsv")).expect("vectors");
        let (mut bases, mut keys) = (std::collections::HashMap::new(), std::collections::HashMap::new());
        let (mut failures, mut count) = (Vec::new(), 0);
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            if let Some(key) = line.strip_prefix('@') {
                let (base, members) = key.split_once('\t').expect("key line");
                let der = std::fs::read(dir.join("more").join(format!("{base}.der"))).expect("base");
                let mut node = parse_all(&der).expect("base parses").remove(0);
                encapsulate(&mut node);
                assert_eq!(encode(&node), der, "round trip of {base}");
                bases.insert(base.to_string(), node);
                keys.insert(base.to_string(), members.to_string());
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            let [base, ops, ca, jwk] = fields[..] else { panic!("line {line}") };
            let data = apply(&bases[base], ops).unwrap_or_else(|| panic!("{base} {ops}: the mutation does not apply"));
            count += 1;
            let actual_ca = match generate_certificates(&data) {
                Ok(certificates) => format!("OK {}", certificates.len()),
                Err(e) => e.chain().join("\nCaused by: "),
            };
            if actual_ca != unescape(ca) {
                failures.push(format!("{base} {ops}\n  ca want: {}\n  ca got:  {actual_ca}", unescape(ca)));
            }
            let json = format!("{{\"keys\":[{{{},\"x5c\":[\"{}\"]}}]}}", keys[base], base64::engine::general_purpose::STANDARD.encode(&data));
            let actual_jwk = super::jwk_set_parse_error(json.as_bytes()).unwrap_or_else(|| "OK".into());
            let want_jwk = unescape(jwk).strip_prefix('~').map(|m| format!("{PREFIX}{m}")).unwrap_or_else(|| unescape(jwk));
            if actual_jwk != want_jwk {
                failures.push(format!("{base} {ops}\n  x5c want: {want_jwk}\n  x5c got:  {actual_jwk}"));
            }
        }
        assert!(count > 1000, "{count} vectors replayed");
        assert!(failures.is_empty(), "{} of {count} vectors differ:\n{}", failures.len(), failures.join("\n"));
    }
}

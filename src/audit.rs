//! Control-plane audit (`HttpState.recordAudit`, `AuditStore`, `AuditFileSink`): with `controlPlaneAuditEnabled`,
//! every control-plane operation that passes (`AUTHORIZED`) or fails authorization (`FORBIDDEN`) is kept as
//! structural metadata in a bounded ring, newest last, read back newest first by `GET /mockserver/audit`. Reads are
//! skipped unless `controlPlaneAuditReads` (a denial is always kept); `auditLogFile` appends each entry as NDJSON.

use std::collections::VecDeque;
use std::io::Write;

use serde_json::{json, Value};

use crate::request::HttpRequest;
use crate::state::State;

/// One `AuditEntry`, in Jackson's alphabetical property order.
#[derive(Clone)]
pub struct Entry {
    epoch_time_ms: i64,
    method: String,
    operation: String,
    outcome: &'static str,
    path: String,
    principal: String,
    principal_source: String,
    source_address: String,
    summary: String,
}

impl Entry {
    fn json(&self) -> Value {
        json!({
            "epochTimeMs": self.epoch_time_ms,
            "method": self.method,
            "operation": self.operation,
            "outcome": self.outcome,
            "path": self.path,
            "principal": self.principal,
            "principalSource": self.principal_source,
            "sourceAddress": self.source_address,
            "summary": self.summary,
        })
    }
}

/// `HttpState.auditSummary`: a fixed description built from the method and operation only (`AUDIT_SUMMARIES`, else
/// a verb and the operation).
fn summary(method: &str, operation: &str) -> String {
    let fixed = match operation {
        "expectation" => "Created or updated expectations",
        "clear" => "Cleared expectations or recorded requests",
        "reset" => "Reset all expectations, recorded requests and state",
        "configuration" => "Changed the configuration",
        "openapi" => "Imported expectations from an OpenAPI spec",
        "wsdl" => "Imported expectations from a WSDL",
        "import" => "Imported expectations",
        "pact/import" => "Imported expectations from a Pact contract",
        "recordings/promote" => "Promoted recorded traffic to expectations",
        "retrieve" => "Retrieved recorded requests, expectations or logs",
        "verify" => "Verified received requests",
        "verifySequence" => "Verified a sequence of received requests",
        "mode" => "Changed the server mode",
        "stop" => "Stopped MockServer",
        _ => "",
    };
    if !fixed.is_empty() {
        return fixed.to_string();
    }
    let verb = if method.eq_ignore_ascii_case("GET") {
        "Read"
    } else if method.eq_ignore_ascii_case("DELETE") {
        "Deleted"
    } else {
        "Changed"
    };
    format!("{verb} {}", if operation.is_empty() { "control plane" } else { operation })
}

/// `AuditFileSink`: opened on the first entry from the `auditLogFile` then in force; an empty path or an I/O
/// error leaves it a permanent no-op.
enum Sink {
    Unopened,
    Disabled,
    Open(std::fs::File),
}

/// `AuditStore` plus its file sink.
pub struct Audit {
    entries: parking_lot::Mutex<VecDeque<Entry>>,
    sink: parking_lot::Mutex<Sink>,
    /// The capacity a `PUT /mockserver/configuration` set (`setMaxSize`); 0 until one did.
    max_size: std::sync::atomic::AtomicUsize,
    /// `AUTHORIZED_RESET_AUDIT_ENTRY`: the entry of the authorized `PUT /mockserver/reset` being handled.
    reset_entry: parking_lot::Mutex<Option<(Entry, usize)>>,
}

impl Default for Audit {
    fn default() -> Audit {
        Audit { entries: parking_lot::Mutex::new(VecDeque::new()), sink: parking_lot::Mutex::new(Sink::Unopened), max_size: Default::default(), reset_entry: Default::default() }
    }
}

impl Audit {
    /// The authorized reset's own entry, taken before the reset clears the trail ([`Audit::clear`] keeps it).
    pub fn take_reset_entry(&self) -> Option<(Entry, usize)> {
        self.reset_entry.lock().take()
    }

    /// `AuditStore.clear`, on `PUT /mockserver/reset`; the record of who reset it stays, as its first entry.
    pub fn clear(&self, kept: Option<(Entry, usize)>) {
        self.entries.lock().clear();
        if let Some((entry, capacity)) = kept {
            self.add(entry, capacity);
        }
    }

    /// `AuditStore.setMaxSize(configuration.controlPlaneAuditMaxEntries())`, after every `PUT /mockserver/configuration`
    /// (`HttpState.applyConfigurationUpdate`): a shrink discards the oldest entries at once; a non-positive value is
    /// ignored. On the 8.0.0 process this read the startup copy and changed nothing (upstream 0e8566814).
    pub fn apply_configuration(&self, config: &crate::config::Config) {
        let Some(max) = config.property("controlPlaneAuditMaxEntries").and_then(|v| v.trim().parse::<i64>().ok()).filter(|&n| n > 0) else { return };
        let max = max.min(i64::from(i32::MAX)) as usize;
        let mut entries = self.entries.lock();
        self.max_size.store(max, std::sync::atomic::Ordering::Relaxed);
        while entries.len() > max {
            entries.pop_front();
        }
    }

    fn add(&self, entry: Entry, capacity: usize) {
        let mut entries = self.entries.lock();
        while entries.len() >= capacity {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    fn write(&self, entry: &Entry, configured: Option<String>) {
        let mut sink = self.sink.lock();
        if matches!(*sink, Sink::Unopened) {
            *sink = match configured.map(|p| p.trim().to_string()).filter(|p| !p.is_empty()) {
                None => Sink::Disabled,
                Some(path) => {
                    let path = std::path::PathBuf::from(path);
                    let opened = path.parent().filter(|p| !p.as_os_str().is_empty()).map_or(Ok(()), std::fs::create_dir_all).and_then(|_| std::fs::OpenOptions::new().create(true).append(true).open(&path));
                    opened.map_or(Sink::Disabled, Sink::Open)
                }
            };
        }
        if let Sink::Open(file) = &mut *sink && writeln!(file, "{}", entry.json()).and_then(|_| file.flush()).is_err() {
            *sink = Sink::Disabled;
        }
    }
}

/// `recordAudit(request, authenticationResult, outcome)`; `forbidden` gives `FORBIDDEN`, else `AUTHORIZED`.
pub fn record(state: &State, request: &HttpRequest, forbidden: bool) {
    let config = &state.config;
    if !config.bool_property("controlPlaneAuditEnabled", false) {
        return;
    }
    let operation = crate::auth::operation(request).to_string();
    if !forbidden && !config.bool_property("controlPlaneAuditReads", false) && crate::auth::is_read(request) {
        return;
    }
    let source_address = if request.remote_address.is_empty() { "unknown".to_string() } else { request.remote_address.clone() };
    // `ChainedAuthenticationHandler.authenticate`: a verified principal other than mTLS's first, then mTLS's
    // `AnyOfAuthenticationHandler`: Basic's verified user when Basic admitted the request
    let (principal, principal_source) = crate::auth::basic_principal(config, request)
        .map(|p| (p, crate::auth_basic::PRINCIPAL_SOURCE.to_string()))
        .or_else(|| verified_principal(config, request).map(|p| (p, "verified-oidc".to_string())))
        .or_else(|| verified_mtls_principal(config, request).map(|p| (p, "verified-mtls".to_string())))
        .unwrap_or_else(|| best_effort_principal(request));
    let outcome = if forbidden { "FORBIDDEN" } else { "AUTHORIZED" };
    let entry = Entry {
        epoch_time_ms: chrono::Utc::now().timestamp_millis(),
        method: request.method.clone(),
        summary: summary(&request.method, &operation),
        operation,
        outcome,
        path: request.path.clone(),
        principal,
        principal_source,
        source_address,
    };
    // The singleton's capacity: read from the properties (`AuditStore.maxFromConfig`, non-positive as 1000) until a
    // configuration update resizes it.
    let capacity = match state.audit.max_size.load(std::sync::atomic::Ordering::Relaxed) {
        0 => config.startup_property("controlPlaneAuditMaxEntries").and_then(|v| v.trim().parse::<i64>().ok()).filter(|&n| n > 0).unwrap_or(1000) as usize,
        max => max,
    };
    state.audit.add(entry.clone(), capacity);
    if entry.operation == "reset" && !forbidden {
        *state.audit.reset_entry.lock() = Some((entry.clone(), capacity));
    }
    state.audit.write(&entry, config.property("auditLogFile"));
    if state.info_enabled() {
        let argument = format!(" {} {} from {} as {} ({}) -> {outcome}", entry.method, entry.operation, entry.source_address, entry.principal, entry.principal_source);
        let logged = crate::recorded::LogEntry::new(crate::log_entry::Kind::ServerConfiguration, "control-plane audit{}").args([argument]).default_request();
        crate::log::log_entry(state, crate::recorded::Level::Info, logged.kind, logged.message_text(), &|| logged.compact_text(), logged.portless || crate::recorded::in_portless_scope());
        state.log.message_about(logged, crate::recorded::Subject::Request(std::sync::Arc::new(HttpRequest { method: String::new(), ..HttpRequest::default() })));
    }
}

/// `handleAuditGet`: the newest `limit` entries first (`?limit=`, default 200, at most 1000; not a number keeps
/// the default), pretty-printed.
pub fn get(state: &State, request: &HttpRequest) -> crate::reply::Reply {
    let limit = crate::request::first(&request.query, "limit").filter(|v| !v.is_empty()).and_then(|v| v.parse::<i32>().ok()).map_or(200, |n| n.min(1000));
    let entries: Vec<Value> = state.audit.entries.lock().iter().rev().take(limit.max(0) as usize).map(Entry::json).collect();
    crate::reply::Reply::api_body(200, "application/json", crate::json::pretty(&Value::Array(entries)))
}

/// The OIDC handler's verified principal: the `sub` of the token it just accepted (`claims.getSubject()`).
fn verified_principal(config: &crate::config::Config, request: &HttpRequest) -> Option<String> {
    if request.trusted || !config.bool_property("controlPlaneOidcAuthenticationRequired", false) || crate::auth::authenticator_installed(config) {
        return None;
    }
    let value = request.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("authorization")).flat_map(|(_, vs)| vs.iter()).next()?;
    let token = value[value.find(' ')? + 1..].trim();
    subject(token)
}

/// The mTLS handler's verified principal (`MTLSAuthenticationHandler.PRINCIPAL_SOURCE`, upstream eef1d8e8b).
fn verified_mtls_principal(config: &crate::config::Config, request: &HttpRequest) -> Option<String> {
    if request.trusted || !config.bool_property("controlPlaneTLSMutualAuthenticationRequired", false) || crate::auth::authenticator_installed(config) {
        return None;
    }
    crate::auth::mtls_principal(config, request)
}

/// `bestEffortPrincipal`: an unverified bearer JWT's textual `sub` (`jwt`), else an mTLS client certificate's
/// subject CN (`mtls`), else `anonymous` (`none`).
fn best_effort_principal(request: &HttpRequest) -> (String, String) {
    if let Some(authorization) = request.first_header("authorization") && authorization.len() >= 7 && authorization.is_char_boundary(7) && authorization[..7].eq_ignore_ascii_case("Bearer ") && let Some(sub) = subject(authorization[7..].trim()) {
        return (sub, "jwt".into());
    }
    if let Some(cn) = request.client_certificates.first().and_then(|c| common_name(c.model.get("subjectDistinguishedName")?.as_str()?)) {
        return (cn, "mtls".into());
    }
    ("anonymous".into(), "none".into())
}

/// A JWT's payload `sub`, when it is a non-empty string.
fn subject(token: &str) -> Option<String> {
    use base64::Engine;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("sub")?.as_str().filter(|s| !s.is_empty()).map(str::to_string)
}

/// `extractCommonName`: the first `CN=` part of a distinguished name.
fn common_name(dn: &str) -> Option<String> {
    dn.split(',').map(str::trim).find(|p| p.len() >= 3 && p[..3].eq_ignore_ascii_case("CN=")).map(|p| p[3..].to_string()).filter(|cn| !cn.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: i64) -> Entry {
        Entry {
            epoch_time_ms: n,
            method: "PUT".into(),
            operation: "clear".into(),
            outcome: "AUTHORIZED",
            path: "/mockserver/clear".into(),
            principal: "anonymous".into(),
            principal_source: "none".into(),
            source_address: "127.0.0.1:5000".into(),
            summary: "Cleared expectations or recorded requests".into(),
        }
    }

    /// `AuditFileSink`: Jackson's compact writer, one line per entry, appended; the ring's bound does not apply.
    #[test]
    fn file_sink_appends_one_compact_line_per_entry() {
        let dir = std::env::temp_dir().join(format!("msrs-audit-{}", std::process::id()));
        let path = dir.join("nested/audit.ndjson");
        let audit = Audit::default();
        for n in [1, 2] {
            audit.add(entry(n), 1);
            audit.write(&entry(n), Some(format!(" {} ", path.display())));
        }
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let line = |n| format!(r#"{{"epochTimeMs":{n},"method":"PUT","operation":"clear","outcome":"AUTHORIZED","path":"/mockserver/clear","principal":"anonymous","principalSource":"none","sourceAddress":"127.0.0.1:5000","summary":"Cleared expectations or recorded requests"}}"#);
        assert_eq!(text, format!("{}\n{}\n", line(1), line(2)));
        assert_eq!(audit.entries.lock().len(), 1);
    }

    /// An empty `auditLogFile` disables the sink for good, even if a path is configured later.
    #[test]
    fn file_sink_without_a_path_stays_off() {
        let audit = Audit::default();
        audit.write(&entry(1), Some("  ".into()));
        assert!(matches!(*audit.sink.lock(), Sink::Disabled));
    }

    #[test]
    fn principal_from_a_certificate_common_name() {
        assert_eq!(common_name("O=Org, cn=client.example, C=UK").as_deref(), Some("client.example"));
        assert_eq!(common_name("O=Org"), None);
    }
}

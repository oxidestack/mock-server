//! Namespaces (tenants): an expectation with a `namespace` serves only requests whose `matchNamespaceHeader`
//! header (default `X-MockServer-Namespace`) carries exactly that value; expectations without one are global and
//! serve every request. A request without the header sees only global expectations. The control plane scopes
//! `retrieve?type=ACTIVE_EXPECTATIONS` and `clear` by `?namespace=` or the same header; nothing else (the event
//! log, verification) is namespaced.

use crate::request::HttpRequest;
use crate::state::State;

const DEFAULT_HEADER: &str = "X-MockServer-Namespace";

/// `RequestMatchers.extractRequestNamespace`: the namespace a data-plane request belongs to, by the
/// `Configuration.matchNamespaceHeader` header (none when that is set blank).
pub fn of_request(state: &State, request: &HttpRequest) -> Option<String> {
    // the header's name read where the configuration holds it: every data-plane request asks
    state.config.read_property("matchNamespaceHeader", |name| {
        let name = name.unwrap_or(DEFAULT_HEADER);
        if name.trim().is_empty() {
            return None;
        }
        request.first_header(name).filter(|v| !v.trim().is_empty()).map(str::to_string)
    })
}

/// `HttpState.resolveNamespaceFilter`: a control-plane request's `?namespace=`, else its namespace header.
pub fn filter(state: &State, request: &HttpRequest) -> Option<String> {
    if let Some(ns) = crate::request::first(&request.query, "namespace").filter(|v| !v.trim().is_empty()) {
        return Some(ns.to_string());
    }
    of_request(state, request)
}

/// `RequestMatchers.matchesNamespace`: a global expectation admits every request, a namespaced one only requests
/// of its namespace.
pub fn admits(expectation: Option<&str>, request: Option<&str>) -> bool {
    match expectation {
        None => true,
        Some(ns) => request == Some(ns),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `RequestMatchersNamespaceTest`: isolation between tenants and the global namespace.
    #[test]
    fn global_expectations_admit_everyone_and_tenants_only_themselves() {
        assert!(admits(None, None));
        assert!(admits(None, Some("team-a")));
        assert!(admits(Some("team-a"), Some("team-a")));
        assert!(!admits(Some("team-a"), Some("team-b")));
        assert!(!admits(Some("team-a"), None));
        assert!(!admits(Some("team-a"), Some("TEAM-A")));
    }
}

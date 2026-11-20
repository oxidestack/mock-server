//! `SidecarInjectionConfig` and `WebhookServer.configFromEnv`: what gets injected, from the chart's env vars.

use crate::java::parse_int;
use crate::log;

pub const INJECT_ANNOTATION: &str = "mockserver.org/inject";
pub const INJECTED_ANNOTATION: &str = "mockserver.org/injected";
pub const STATUS_ANNOTATION: &str = "mockserver.org/status";
pub const INJECT_ENABLED: &str = "true";
pub const INJECTED_VALUE: &str = "true";

pub const ENV_PORT: &str = "WEBHOOK_PORT";
pub const ENV_TLS_CERT: &str = "WEBHOOK_TLS_CERT_FILE";
pub const ENV_TLS_KEY: &str = "WEBHOOK_TLS_KEY_FILE";
pub const ENV_MOCKSERVER_IMAGE: &str = "MOCKSERVER_IMAGE";
pub const ENV_IPTABLES_IMAGE: &str = "IPTABLES_IMAGE";
pub const ENV_MOCKSERVER_PORT: &str = "MOCKSERVER_PORT";
pub const ENV_REDIRECT_PORTS: &str = "REDIRECT_PORTS";
pub const ENV_EXCLUDE_UID: &str = "EXCLUDE_UID";
pub const ENV_LOG_LEVEL: &str = "LOG_LEVEL";

pub const DEFAULT_PORT: i32 = 8443;
pub const DEFAULT_CERT_PATH: &str = "/etc/webhook/tls/tls.crt";
pub const DEFAULT_KEY_PATH: &str = "/etc/webhook/tls/tls.key";

/// The sidecar injection settings; the defaults are upstream's (its image default is a stale override-me value the
/// chart always replaces through `MOCKSERVER_IMAGE`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarInjectionConfig {
    pub mockserver_image: String,
    pub iptables_image: String,
    pub server_port: i32,
    pub redirect_ports: String,
    pub run_as_user: i32,
    pub log_level: String,
}

impl Default for SidecarInjectionConfig {
    fn default() -> SidecarInjectionConfig {
        SidecarInjectionConfig {
            mockserver_image: "mockserver/mockserver:mockserver-6.1.1-SNAPSHOT".to_string(),
            iptables_image: "alpine:3.19".to_string(),
            server_port: 1080,
            redirect_ports: "80,443".to_string(),
            run_as_user: 65534,
            log_level: "INFO".to_string(),
        }
    }
}

const SERVER_CLASS: &str = "org.mockserver.webhook.WebhookServer";

/// `WebhookServer.configFromEnv()`, reading variables through `env` (empty counts as unset); an unparsable integer is
/// logged and leaves the default.
pub fn config_from_env(env: &dyn Fn(&str) -> Option<String>) -> SidecarInjectionConfig {
    let mut config = SidecarInjectionConfig::default();
    let get = |name: &str| env(name).filter(|v| !v.is_empty());
    if let Some(image) = get(ENV_MOCKSERVER_IMAGE) {
        config.mockserver_image = image;
    }
    if let Some(image) = get(ENV_IPTABLES_IMAGE) {
        config.iptables_image = image;
    }
    if let Some(port) = get(ENV_MOCKSERVER_PORT) {
        match parse_int(&port) {
            Ok(p) => config.server_port = p,
            Err(e) => invalid_integer(ENV_MOCKSERVER_PORT, &port, config.server_port, "configFromEnv", &e),
        }
    }
    if let Some(ports) = get(ENV_REDIRECT_PORTS) {
        config.redirect_ports = ports;
    }
    if let Some(uid) = get(ENV_EXCLUDE_UID) {
        match parse_int(&uid) {
            Ok(u) => config.run_as_user = u,
            Err(e) => invalid_integer(ENV_EXCLUDE_UID, &uid, config.run_as_user, "configFromEnv", &e),
        }
    }
    if let Some(level) = get(ENV_LOG_LEVEL) {
        config.log_level = level;
    }
    config
}

/// `LOG.warn("invalid integer for {}={}, using default {}", name, value, default, e)`
pub fn invalid_integer(name: &str, value: &str, default: i32, method: &str, e: &crate::java::JavaException) {
    log::warn_thrown(SERVER_CLASS, method, &format!("invalid integer for {name}={value}, using default {default}"), e);
}

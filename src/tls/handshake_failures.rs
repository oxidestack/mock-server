//! `ClientTlsHandshakeFailureLog` (b765b8271): a client's failed inbound TLS handshake is logged at WARN the first
//! time its address fails on a transport, with a hint about the likely cause, and at DEBUG each later time, so a
//! client that retries, or a scan, does not fill the log. The server remembers at most [`MAX_CLIENT_ADDRESSES`]
//! addresses, forgetting the one whose handshake failed least recently; a `reset` keeps them (the memory belongs to
//! the server's `LifeCycle`).

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};

use parking_lot::Mutex;

use crate::recorded::{Level, LogEntry};
use crate::state::State;

/// `ClientTlsHandshakeFailureLog.MAX_CLIENT_ADDRESSES`.
const MAX_CLIENT_ADDRESSES: usize = 1024;
/// `ClientTlsHandshakeFailureLog.TRUST_HINT`.
const TRUST_HINT: &str = "the client does not trust MockServer's Certificate Authority";
const LATER_AT_DEBUG: &str = "later failed handshakes from this client address are logged at DEBUG";

/// The transports a failed handshake is remembered per (`ClientTlsHandshakeFailureLog.TCP`, `.HTTP3`). Only TCP's
/// failed handshakes are logged here so far, not the HTTP/3 listener's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    Tcp,
}

impl Transport {
    fn name(self) -> &'static str {
        match self {
            Transport::Tcp => "TCP",
        }
    }
}

/// The client addresses whose handshake failed, least recently failed first (the access-ordered `LinkedHashMap`).
#[derive(Default)]
pub struct HandshakeFailures {
    clients: Mutex<VecDeque<(Transport, IpAddr)>>,
}

impl HandshakeFailures {
    /// `firstFailureFrom`: whether this is the first failure remembered from `client`'s host (any port) on
    /// `transport`; either way the address becomes the most recently failed one.
    pub fn first_failure_from(&self, transport: Transport, client: IpAddr) -> bool {
        let mut clients = self.clients.lock();
        let key = (transport, client);
        let first = match clients.iter().position(|k| *k == key) {
            Some(at) => {
                clients.remove(at);
                false
            }
            None => true,
        };
        clients.push_back(key);
        if clients.len() > MAX_CLIENT_ADDRESSES {
            clients.pop_front();
        }
        first
    }

    /// `ClientTlsHandshakeFailureLog.log`: `reason` is the exception's bounded message (the `DecoderException`'s, which
    /// is its JDK cause's `toString`), `cause_text` every message of its cause chain, which the probable cause is read
    /// from.
    pub fn log(&self, state: &State, transport: Transport, client: SocketAddr, reason: &str, cause_text: &str) {
        let first = self.first_failure_from(transport, client.ip());
        let enabled = if first { !matches!(state.log_level.as_str(), "OFF" | "ERROR") } else { crate::log::debug_enabled(state) };
        if !enabled {
            return;
        }
        let format = format!(
            "TLS handshake failed on {} connection from:{{}}reason:{{}}probable cause:{{}}to make a client trust MockServer's Certificate Authority see https://mock-server.com/mock_server/HTTPS_TLS.html, MockServer's certificates are configured as:{{}}{}",
            transport.name(),
            if first { LATER_AT_DEBUG } else { "" }
        );
        // the client's `InetSocketAddress`: its `toString` in the text, Jackson's `ip:port` among the entry's arguments
        // (read off the oracle)
        let entry = LogEntry::at(if first { Level::Warn } else { Level::Debug }, format).args([
            crate::recorded::Arg::inet_socket_address(java_socket_address(client), crate::server::java_socket_address(client)),
            reason.into(),
            probable_cause(cause_text).into(),
            configured_certificates(&state.config).into(),
        ]);
        if first {
            crate::log::warn_event(state, entry);
        } else {
            crate::log::entry(state, &entry);
            state.log.message(entry);
        }
    }
}

/// `InetSocketAddress.toString` of an accepted connection's peer: no host name, so `/<address>:<port>`.
fn java_socket_address(address: SocketAddr) -> String {
    format!("/{}", crate::server::java_socket_address(address))
}

/// `probableCause`: read from the lower-cased messages of the exception and its causes.
fn probable_cause(cause_text: &str) -> &'static str {
    let messages = cause_text.to_lowercase();
    let any = |names: &[&str]| names.iter().any(|name| messages.contains(name));
    if any(&["certificate_unknown", "unknown_ca"]) {
        TRUST_HINT
    } else if any(&["bad_certificate", "unsupported_certificate", "certificate_revoked", "certificate_expired"]) {
        "the client rejected MockServer's certificate: it may not trust MockServer's Certificate Authority, or the certificate has expired or does not name the host the client asked for"
    } else if any(&["no_application_protocol"]) {
        "the client offered no application protocol (ALPN) that MockServer serves on this port"
    } else if any(&["handshake_failure"]) {
        "the client and MockServer share no TLS protocol version or cipher suite"
    } else if any(&["no_certificate", "certificate_required"]) {
        "the client sent no certificate, which mutual TLS requires"
    } else {
        "unknown"
    }
}

/// `configuredCertificates`: `ServerTlsSettings`' certificate path and CA certificate.
fn configured_certificates(config: &crate::Config) -> String {
    format!(
        "x509CertificatePath=\"{}\" certificateAuthorityCertificate=\"{}\"",
        config.property("x509CertificatePath").unwrap_or_default(),
        config.property("certificateAuthorityCertificate").unwrap_or_else(|| "org/mockserver/socket/CertificateAuthorityCertificate.pem".into())
    )
}

/// The JDK's name of a TLS alert (`sun.security.ssl.Alert`), and whether it is `handshakeOnly`: received during a
/// handshake, such an alert fails it with an `SSLHandshakeException`, any other with an `SSLException`
/// (`unexpected_message` with an `SSLProtocolException`).
pub fn jdk_alert(code: u8) -> Option<(&'static str, bool)> {
    Some(match code {
        0 => ("close_notify", false),
        10 => ("unexpected_message", false),
        20 => ("bad_record_mac", false),
        21 => ("decryption_failed", false),
        22 => ("record_overflow", false),
        30 => ("decompression_failure", false),
        40 => ("handshake_failure", true),
        41 => ("no_certificate", true),
        42 => ("bad_certificate", true),
        43 => ("unsupported_certificate", true),
        44 => ("certificate_revoked", true),
        45 => ("certificate_expired", true),
        46 => ("certificate_unknown", true),
        47 => ("illegal_parameter", true),
        48 => ("unknown_ca", true),
        49 => ("access_denied", true),
        50 => ("decode_error", true),
        51 => ("decrypt_error", true),
        60 => ("export_restriction", true),
        70 => ("protocol_version", true),
        71 => ("insufficient_security", true),
        80 => ("internal_error", false),
        86 => ("inappropriate_fallback", false),
        90 => ("user_canceled", false),
        100 => ("no_renegotiation", true),
        109 => ("missing_extension", true),
        110 => ("unsupported_extension", true),
        111 => ("certificate_unobtainable", true),
        112 => ("unrecognized_name", true),
        113 => ("bad_certificate_status_response", true),
        114 => ("bad_certificate_hash_value", true),
        115 => ("unknown_psk_identity", true),
        116 => ("certificate_required", true),
        120 => ("no_application_protocol", true),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_address_fails_first_once() {
        let failures = HandshakeFailures::default();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(failures.first_failure_from(Transport::Tcp, a));
        assert!(!failures.first_failure_from(Transport::Tcp, a));
        assert!(failures.first_failure_from(Transport::Tcp, "10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn the_least_recently_failed_address_is_forgotten_beyond_the_cap() {
        let failures = HandshakeFailures::default();
        let address = |i: usize| IpAddr::from([10, 1, (i / 256) as u8, (i % 256) as u8]);
        for i in 0..MAX_CLIENT_ADDRESSES {
            assert!(failures.first_failure_from(Transport::Tcp, address(i)));
        }
        // touching the first makes the second the least recently failed one
        assert!(!failures.first_failure_from(Transport::Tcp, address(0)));
        assert!(failures.first_failure_from(Transport::Tcp, address(MAX_CLIENT_ADDRESSES)));
        assert!(!failures.first_failure_from(Transport::Tcp, address(0)));
        assert!(failures.first_failure_from(Transport::Tcp, address(1)));
    }

    #[test]
    fn the_probable_cause_is_read_from_the_alert_names() {
        assert_eq!(probable_cause("javax.net.ssl.SSLHandshakeException: (unknown_ca) Received fatal alert: unknown_ca "), TRUST_HINT);
        assert_eq!(probable_cause("(handshake_failure) Received handshake warning: unknown_ca"), TRUST_HINT);
        assert_eq!(probable_cause("(decode_error) Illegal handshake message: client_hello"), "unknown");
    }
}

//! JGroups stacks: the protocol list of a `clusterTransportConfig` file. Clustering is
//! supported wire-compatibly, but only the ported protocols run (`jgroups::stack::supported_protocols`); each other
//! one is reported with the supported equivalent.

use super::rules;
use super::{Finding, Severity};

/// Whether `text` is a JGroups stack document.
pub fn is_jgroups(text: &str) -> bool {
    text.contains("urn:org:jgroups") || (text.contains("<config") && (text.contains("<TCP") || text.contains("<UDP")) && text.contains("pbcast."))
}

/// The supported protocol that does what this one does, when there is one.
fn equivalent(short: &str) -> Option<&'static str> {
    Some(match short {
        "UDP" | "TUNNEL" => "TCP",
        "MPING" | "JDBC_PING" | "JDBC_PING2" | "FILE_PING" | "S3_PING" | "NATIVE_S3_PING" | "GOOGLE_PING2" | "AZURE_PING" => "TCPPING or dns.DNS_PING",
        "KUBE_PING" => "dns.DNS_PING",
        "MERGE2" => "MERGE3",
        "FD" | "FD_ALL" | "FD_ALL2" | "FD_SOCK" | "FD_SOCK2" => "FD_ALL3",
        "VERIFY_SUSPECT" => "VERIFY_SUSPECT2",
        "UNICAST" | "UNICAST2" => "UNICAST3",
        "NAKACK" => "pbcast.NAKACK2",
        "FRAG" | "FRAG3" | "FRAG4" => "FRAG2",
        "FC" => "UFC and MFC",
        _ => return None,
    })
}

/// The findings of one stack file: a warning per protocol jgroups-rs does not run.
pub fn scan(text: &str) -> Vec<Finding> {
    let Ok(protocols) = jgroups::conf::xml::parse_stack(text) else {
        return vec![Finding::new(rules::CLUSTER_TRANSPORT, Severity::Warn, 1, "JGroups stack", "the stack does not parse: the server would refuse it at startup")];
    };
    let mut findings = Vec::new();
    let mut cursor = 0;
    for protocol in &protocols {
        let tag = format!("<{}", protocol.name);
        let at = text[cursor..].find(&tag).map(|i| cursor + i);
        if let Some(at) = at {
            cursor = at + tag.len();
        }
        let line = at.map_or(1, |at| super::line_of(text, at));
        let short = protocol.short_name();
        if jgroups::stack::is_supported_protocol(short) {
            continue;
        }
        let verdict = match equivalent(short) {
            Some(instead) => format!("not ported: startup fails with `unsupported protocol {}`; use {instead}", protocol.name),
            None => format!("not ported: startup fails with `unsupported protocol {}`; remove it (supported: {})", protocol.name, jgroups::stack::supported_protocols().join(", ")),
        };
        findings.push(Finding::new(rules::CLUSTER_TRANSPORT, Severity::Warn, line, protocol.name.clone(), verdict).key(protocol.name.clone()));
    }
    if findings.is_empty() {
        findings.push(Finding::new(rules::CLUSTER_TRANSPORT, Severity::Info, 1, "JGroups stack", "every protocol is ported: a mock-server node joins a Java cluster on this stack"));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_protocols_are_named() {
        let text = "<config xmlns=\"urn:org:jgroups\">\n  <UDP/>\n  <PING/>\n  <MPING/>\n  <MERGE3/>\n  <pbcast.NAKACK2/>\n  <pbcast.GMS/>\n</config>\n";
        assert!(is_jgroups(text));
        let found: Vec<(usize, String)> = scan(text).into_iter().map(|f| (f.line, f.found)).collect();
        assert_eq!(found, [(2, "UDP".to_string()), (3, "PING".into()), (4, "MPING".into())]);
        assert!(scan(text)[0].verdict.ends_with("use TCP"));
    }

    #[test]
    fn a_ported_stack_is_info() {
        let found = scan("<config><TCP/><dns.DNS_PING/><MERGE3/><FD_ALL3/><pbcast.NAKACK2/><UNICAST3/><pbcast.STABLE/><pbcast.GMS/></config>");
        assert_eq!(found.iter().map(|f| f.severity).collect::<Vec<_>>(), [Severity::Info]);
    }
}

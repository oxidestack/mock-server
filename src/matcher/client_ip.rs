//! `ClientIpMatcher` (9.2.0): an expectation's `clientIp`, an IP address or CIDR range (IPv4 or IPv6, optionally in
//! `[…]`, optionally negated), against the request's TCP peer address (`remoteAddress`), never a header. An
//! IPv4-mapped IPv6 address is compared as the IPv4 address it carries; an IPv4 peer meets an IPv6 range as
//! `::ffff:a.b.c.d`. A request without a peer address (HTTP/3, a definition) matches no criterion, negated or not.

use serde_json::Value;

use super::{Difference, format_log_message};
use crate::model::NString;

#[derive(Debug)]
pub struct ClientIpMatcher {
    /// The range's address with the bits past the prefix cleared: 4 or 16 bytes.
    network: Vec<u8>,
    prefix: usize,
    not: bool,
    /// `toString()`: `!` when negated, then the trimmed value as given.
    description: String,
}

impl ClientIpMatcher {
    /// `ClientIpMatcher.compile`: the criterion of a `clientIp` value, or the message of the
    /// `IllegalArgumentException` it throws.
    pub fn compile(v: &Value) -> Result<ClientIpMatcher, String> {
        let given = NString::from_json(v).unwrap_or_else(|| NString::parse(""));
        if given.schema.is_some() || given.optional || given.parameter_style.is_some() {
            return Err(format!("clientIp must be an IP address or CIDR range, optionally negated, but was \"{}\"", given.marked()));
        }
        let value = given.value.as_deref().unwrap_or_default().trim().to_string();
        let (address, prefix_text) = match value.find('/') {
            Some(slash) => (&value[..slash], Some(&value[slash + 1..])),
            None => (value.as_str(), None),
        };
        let address = match address.strip_prefix('[').and_then(|a| a.strip_suffix(']')) {
            Some(inner) if address.len() > 2 => inner,
            _ => address,
        };
        let mut bytes = (!address.is_empty()).then(|| ip_bytes(address)).flatten().ok_or_else(|| {
            format!("clientIp \"{value}\" is not an IP address or CIDR range; host names are not supported")
        })?;
        let maximum = bytes.len() * 8;
        let mut prefix = maximum;
        if let Some(text) = prefix_text {
            let invalid = || format!("clientIp \"{value}\" has an invalid prefix length, it must be between 0 and {maximum}");
            if text.is_empty() || text.len() > 3 || !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
            prefix = text.parse().map_err(|_| invalid())?;
            if prefix > maximum {
                return Err(invalid());
            }
        }
        if is_ipv4_mapped(&bytes) && prefix >= 96 {
            bytes = bytes[12..].to_vec();
            prefix -= 96;
        }
        for bit in prefix..bytes.len() * 8 {
            bytes[bit / 8] &= !(0x80u8 >> (bit % 8));
        }
        let description = format!("{}{value}", if given.not { "!" } else { "" });
        Ok(ClientIpMatcher { network: bytes, prefix, not: given.not, description })
    }

    /// `matches(context, request)`: `None` when the peer address `remote_address` (`host:port` as the request
    /// records it, empty when it has none) satisfies the criterion, else the difference upstream records.
    pub fn difference(&self, remote_address: &str) -> Option<Difference> {
        let actual = remote_address_bytes(remote_address);
        let matched = actual.as_deref().is_some_and(|a| self.in_range(a) != self.not);
        let found = if remote_address.is_empty() { "null" } else { remote_address };
        (!matched).then(|| Difference::Text(format_log_message(1, "client ip match failed expected:{} found:{}", &[&self.description, found])))
    }

    fn in_range(&self, actual: &[u8]) -> bool {
        if actual.len() != self.network.len() && !(actual.len() == 4 && self.network.len() == 16) {
            return false;
        }
        // an IPv4 address read as the IPv4-mapped IPv6 address `::ffff:a.b.c.d` when the range is IPv6
        let byte_at = |i: usize| match actual.len() == self.network.len() {
            true => actual[i],
            false if i < 10 => 0,
            false if i < 12 => 0xFF,
            false => actual[i - 12],
        };
        let full = self.prefix / 8;
        if (0..full).any(|i| byte_at(i) != self.network[i]) {
            return false;
        }
        let remaining = self.prefix % 8;
        if remaining == 0 {
            return true;
        }
        let mask = (0xFFu16 << (8 - remaining)) as u8;
        byte_at(full) & mask == self.network[full] & mask
    }
}

/// `ClientIpMatcher.parseRemoteAddress`: the address bytes of `127.0.0.1:52000`, `[::1]:52000` or
/// `host/10.0.0.1:52000`, IPv4-mapped addresses as IPv4; `None` when it holds no IP literal. Never resolves a name.
fn remote_address_bytes(remote_address: &str) -> Option<Vec<u8>> {
    if remote_address.is_empty() {
        return None;
    }
    let mut host = &remote_address[remote_address.rfind('/').map_or(0, |i| i + 1)..];
    if let Some(rest) = host.strip_prefix('[') {
        host = rest.find(']').map_or(rest, |end| &rest[..end]);
    } else if let Some(colon) = host.find(':')
        && !host[colon + 1..].contains(':')
    {
        host = &host[..colon];
    }
    // an unbracketed IPv6 address followed by a port, as a servlet container's "host:port" produces
    let bytes = ip_bytes(host).or_else(|| host.rfind(':').filter(|i| *i > 0).and_then(|i| ip_bytes(&host[..i])))?;
    Some(if is_ipv4_mapped(&bytes) { bytes[12..].to_vec() } else { bytes })
}

/// Netty's `NetUtil.createByteArrayFromIpAddressString`: 4 bytes for a dotted quad (words of one to three digits,
/// leading zeros allowed), 16 for an IPv6 literal (optionally bracketed, a `%scope` dropped, an IPv4-compatible
/// `::a.b.c.d` read as IPv4-mapped); `None` for anything else.
fn ip_bytes(text: &str) -> Option<Vec<u8>> {
    if let Some(v4) = ipv4_bytes(text) {
        return Some(v4.to_vec());
    }
    if !text.contains(':') {
        return None;
    }
    let mut text = text;
    if let Some(inner) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        text = inner;
    }
    if let Some(percent) = text.find('%') {
        text = &text[..percent];
    }
    let mut bytes = text.parse::<std::net::Ipv6Addr>().ok()?.octets().to_vec();
    if text.contains('.') && bytes[..12].iter().all(|b| *b == 0) {
        bytes[10] = 0xFF;
        bytes[11] = 0xFF;
    }
    Some(bytes)
}

/// `NetUtil.isValidIpV4Address` and `validIpV4ToBytes`.
fn ipv4_bytes(text: &str) -> Option<[u8; 4]> {
    let words: Vec<&str> = text.split('.').collect();
    if words.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (slot, word) in out.iter_mut().zip(words) {
        if word.is_empty() || word.len() > 3 || !word.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = u8::try_from(word.parse::<u16>().ok()?).ok()?;
    }
    Some(out)
}

fn is_ipv4_mapped(address: &[u8]) -> bool {
    address.len() == 16 && address[10] == 0xFF && address[11] == 0xFF && address[..10].iter().all(|b| *b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn matches(criterion: &str, remote: &str) -> bool {
        ClientIpMatcher::compile(&json!(criterion)).expect("valid").difference(remote).is_none()
    }

    #[test]
    fn ipv4_and_cidr() {
        assert!(matches("10.0.0.0/8", "10.1.2.3:5000"));
        assert!(!matches("10.0.0.0/8", "11.1.2.3:5000"));
        assert!(matches("192.168.1.10", "192.168.1.10:1"));
        assert!(matches("172.16.0.0/12", "172.31.255.1:1"));
        assert!(!matches("172.16.0.0/12", "172.32.0.1:1"));
        assert!(matches("0.0.0.0/0", "8.8.8.8:53"));
        assert!(matches("010.0.0.1", "10.0.0.1:1"));
    }

    #[test]
    fn negation_and_missing_address() {
        assert!(matches("!10.0.0.0/8", "127.0.0.1:1"));
        assert!(!matches("!127.0.0.0/8", "127.0.0.1:1"));
        assert!(!matches("!10.0.0.0/8", ""));
        assert!(ClientIpMatcher::compile(&json!({"not": true, "value": "::1"})).expect("valid").difference("[::1]:9").is_some());
    }

    #[test]
    fn ipv6_and_mapped() {
        assert!(matches("::1", "[::1]:80"));
        assert!(matches("[::1]", "/0:0:0:0:0:0:0:1:80"));
        assert!(matches("2001:db8::/32", "[2001:db8:1::5]:80"));
        assert!(matches("::/0", "127.0.0.1:1"));
        assert!(matches("::ffff:10.0.0.0/104", "10.9.9.9:1"));
        assert!(matches("10.0.0.0/8", "[::ffff:10.1.1.1]:1"));
        assert!(!matches("::1", "127.0.0.1:1"));
    }

    #[test]
    fn invalid_values() {
        let error = |v: Value| ClientIpMatcher::compile(&v).expect_err("invalid");
        assert_eq!(error(json!("10.0.0.0/33")), "clientIp \"10.0.0.0/33\" has an invalid prefix length, it must be between 0 and 32");
        assert_eq!(error(json!("::/129")), "clientIp \"::/129\" has an invalid prefix length, it must be between 0 and 128");
        assert_eq!(error(json!("10.0.0.0/")), "clientIp \"10.0.0.0/\" has an invalid prefix length, it must be between 0 and 32");
        assert_eq!(error(json!("localhost")), "clientIp \"localhost\" is not an IP address or CIDR range; host names are not supported");
        assert_eq!(error(json!("")), "clientIp \"\" is not an IP address or CIDR range; host names are not supported");
        assert_eq!(error(json!("?10.0.0.1")), "clientIp must be an IP address or CIDR range, optionally negated, but was \"?10.0.0.1\"");
    }

    #[test]
    fn difference_text() {
        let m = ClientIpMatcher::compile(&json!("10.0.0.0/8")).expect("valid");
        let Some(Difference::Text(t)) = m.difference("") else { panic!("a difference") };
        assert_eq!(t, "  client ip match failed expected:\n\n    10.0.0.0/8\n\n   found:\n\n    null\n");
    }
}

//! `ForwardTargetHostPolicy`: the parsed `forwardProxyAllowedHosts` and `forwardProxyDeniedHosts` lists, which
//! [`crate::ws_relay::blocked`] applies to every forward, proxy, replay and webhook target ahead of
//! `forwardProxyBlockPrivateNetworks`.
//!
//! Each list is comma-separated; an entry is a host name, matched exactly; a domain suffix (`*.example.com` or
//! `.example.com`), which matches the domain and every name under it; an IP address; or a CIDR block. Names are
//! matched without case and without a trailing dot. Addresses and blocks match the address a target resolves to, as
//! well as a target given as an address. A denied target is refused; when an allow list is set, a target on neither
//! its name nor its address part is refused too. A list that cannot be parsed refuses every target.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

pub struct Policy {
    allowed: Option<HostList>,
    denied: Option<HostList>,
    invalid: Option<String>,
}

/// `InetAddressValidator.hostPolicy`: the policy of the server's lists, or `None` when both are blank. Parsed once
/// per distinct pair of lists (`reuseOrParse`).
pub fn of(config: &crate::config::Config) -> Option<Arc<Policy>> {
    // asked of every unmatched request: nothing is copied while neither list is set
    if config.read_property("forwardProxyAllowedHosts", |v| v.is_none_or(str::is_empty)) && config.read_property("forwardProxyDeniedHosts", |v| v.is_none_or(str::is_empty)) {
        return None;
    }
    let allowed = config.property("forwardProxyAllowedHosts").unwrap_or_default();
    let denied = config.property("forwardProxyDeniedHosts").unwrap_or_default();
    if allowed.is_empty() && denied.is_empty() {
        return None;
    }
    // the last (allow list, deny list) read and the policy built from them
    type Last = (String, String, Option<Arc<Policy>>);
    static LAST: std::sync::Mutex<Option<Last>> = std::sync::Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((a, d, policy)) = last.as_ref() && *a == allowed && *d == denied {
        return policy.clone();
    }
    let policy = Policy::parse(&allowed, &denied);
    let policy = (!policy.is_empty()).then(|| Arc::new(policy));
    *last = Some((allowed, denied, policy.clone()));
    policy
}

impl Policy {
    fn parse(allowed: &str, denied: &str) -> Policy {
        let parsed = HostList::parse("forwardProxyAllowedHosts", allowed).and_then(|a| Ok((a, HostList::parse("forwardProxyDeniedHosts", denied)?)));
        match parsed {
            Ok((allowed, denied)) => Policy { allowed, denied, invalid: None },
            Err(reason) => Policy { allowed: None, denied: None, invalid: Some(reason) },
        }
    }

    fn is_empty(&self) -> bool {
        self.invalid.is_none() && self.allowed.is_none() && self.denied.is_none()
    }

    /// `matchesAddresses`: whether a target's resolved address can change the outcome, so it is worth looking up.
    pub fn matches_addresses(&self) -> bool {
        self.invalid.is_some() || self.allowed.as_ref().is_some_and(|l| !l.cidrs.is_empty()) || self.denied.as_ref().is_some_and(|l| !l.cidrs.is_empty())
    }

    /// `check`: why `requested` (the target as given) may not be sent to, given the address it resolved to (`None`
    /// when it was not looked up).
    pub fn check(&self, requested: &str, address: Option<IpAddr>) -> Option<String> {
        if let Some(invalid) = &self.invalid {
            return Some(format!("Forward to {requested} refused because {invalid}"));
        }
        let name = normalise_name(requested);
        let bytes = match address {
            Some(address) => Some(octets(address)),
            None => netty_address(&name),
        };
        if let Some(denied) = &self.denied && (denied.matches_name(&name) || denied.matches_any_spelling(bytes.as_deref()) || denied.covers_this_host(bytes.as_deref())) {
            return Some(format!("Forward to host denied by forwardProxyDeniedHosts: {}", describe(requested, address)));
        }
        if let Some(allowed) = &self.allowed && !allowed.matches_name(&name) && !allowed.matches_address(bytes.as_deref()) {
            return Some(format!("Forward to host not in forwardProxyAllowedHosts: {}", describe(requested, address)));
        }
        None
    }
}

/// `describe`: the target as given, and the address it resolved to when that is spelled differently.
fn describe(requested: &str, address: Option<IpAddr>) -> String {
    match address {
        Some(address) => {
            let printed = crate::ws_relay::java_host_address(address);
            if printed == strip_brackets(requested) {
                requested.to_string()
            } else {
                format!("{requested} ({printed})")
            }
        }
        None => requested.to_string(),
    }
}

fn normalise_name(host: &str) -> String {
    let name = strip_brackets(host);
    name.strip_suffix('.').unwrap_or(name).to_lowercase()
}

fn strip_brackets(host: &str) -> &str {
    if host.len() >= 2 && host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

fn octets(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// `NetUtil.createByteArrayFromIpAddressString`: a strict IPv4 dotted quad or an IPv6 literal (a `%scope` dropped,
/// brackets allowed), else `None`.
fn netty_address(text: &str) -> Option<Vec<u8>> {
    let text = strip_brackets(text);
    if let Some(v4) = netty_ipv4(text) {
        return Some(v4.to_vec());
    }
    if text.contains(':') {
        let literal = text.split_once('%').map_or(text, |(address, _scope)| address);
        return literal.parse::<std::net::Ipv6Addr>().ok().map(|v6| v6.octets().to_vec());
    }
    None
}

/// `NetUtil.isValidIpV4Address`: four decimal parts of one to three digits, each at most 255.
fn netty_ipv4(text: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut bytes = [0u8; 4];
    for (byte, part) in bytes.iter_mut().zip(parts) {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *byte = u8::try_from(part.parse::<u16>().ok()?).ok()?;
    }
    Some(bytes)
}

/// `canonical`: an IPv4-mapped (`::ffff:a.b.c.d`) or IPv4-compatible (`::a.b.c.d`, not `::` or `::1`) address as the
/// IPv4 address it carries.
fn canonical(address: &[u8]) -> Vec<u8> {
    if address.len() == 16 && address[..10].iter().all(|b| *b == 0) {
        let mapped = address[10] == 0xff && address[11] == 0xff;
        let compatible = address[10] == 0 && address[11] == 0 && (address[12] != 0 || address[13] != 0 || address[14] != 0 || (address[15] & 0xfe) != 0);
        if mapped || compatible {
            return address[12..].to_vec();
        }
    }
    address.to_vec()
}

const IPV4_LOOPBACK: [u8; 4] = [127, 0, 0, 1];
const IPV6_LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// `isThisHost`: loopback in either family, or the wildcard address.
fn is_this_host(canonical: &[u8]) -> bool {
    if canonical.len() == 4 {
        return canonical[0] == 127 || canonical.iter().all(|b| *b == 0);
    }
    canonical[..15].iter().all(|b| *b == 0) && (canonical[15] & 0xfe) == 0
}

fn invalid_entry(property: &str, entry: &str) -> String {
    format!("{property} entry \"{}\" is not a host name, *.domain, IP address or CIDR block", entry.trim())
}

struct HostList {
    names: HashSet<String>,
    domains: Vec<String>,
    cidrs: Vec<Cidr>,
    lists_this_host: bool,
    has_ipv6_blocks: bool,
}

impl HostList {
    fn parse(property: &str, hosts: &str) -> Result<Option<HostList>, String> {
        let (mut names, mut domains, mut cidrs) = (HashSet::new(), Vec::new(), Vec::new());
        for raw in hosts.split(',') {
            let mut entry = java_trim(raw).to_lowercase();
            if entry.is_empty() {
                continue;
            }
            if let Some(slash) = entry.find('/') {
                cidrs.push(Cidr::parse(property, &entry, slash)?);
                continue;
            }
            if let Some(literal) = netty_address(&entry) {
                let address = canonical(&literal);
                let prefix = address.len() * 8;
                cidrs.push(Cidr { network: address, prefix });
                continue;
            }
            if entry.ends_with('.') {
                entry.pop();
            }
            if entry.starts_with("*.") || entry.starts_with('.') {
                let domain = entry[entry.find('.').unwrap_or(0) + 1..].to_string();
                require_host_name(property, raw, &domain)?;
                domains.push(format!(".{domain}"));
                names.insert(domain);
                continue;
            }
            require_host_name(property, raw, &entry)?;
            if entry.bytes().all(|c| c == b'.' || c.is_ascii_digit()) {
                // 127.1 or 2130706433: an address the JDK resolves but Netty does not parse, so never a name
                return Err(invalid_entry(property, raw));
            }
            names.insert(entry);
        }
        if names.is_empty() && cidrs.is_empty() {
            return Ok(None);
        }
        let mut list = HostList { names, domains, cidrs, lists_this_host: false, has_ipv6_blocks: false };
        list.lists_this_host = list.matches_address(Some(&IPV4_LOOPBACK)) || list.matches_address(Some(&IPV6_LOOPBACK));
        list.has_ipv6_blocks = list.cidrs.iter().any(|c| c.network.len() == 16);
        Ok(Some(list))
    }

    fn matches_name(&self, name: &str) -> bool {
        self.names.contains(name) || self.domains.iter().any(|d| name.ends_with(d.as_str()))
    }

    /// `matchesAddress`: the address as given and as the IPv4 address an IPv4-mapped or -compatible one carries.
    fn matches_address(&self, address: Option<&[u8]>) -> bool {
        let Some(address) = address else { return false };
        let canonical_address = canonical(address);
        let folded = canonical_address.len() != address.len();
        self.cidrs.iter().any(|c| c.matches(&canonical_address) || (folded && c.matches(address)))
    }

    /// `matchesAnySpelling`: also an IPv4 address against IPv6 blocks in its mapped and compatible spellings.
    fn matches_any_spelling(&self, address: Option<&[u8]>) -> bool {
        if self.matches_address(address) {
            return true;
        }
        let Some(canonical_address) = address.map(canonical) else { return false };
        if canonical_address.len() != 4 || !self.has_ipv6_blocks {
            return false;
        }
        let mut compatible = [0u8; 16];
        compatible[12..].copy_from_slice(&canonical_address);
        let mut mapped = compatible;
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        self.cidrs.iter().any(|c| c.matches(&compatible) || c.matches(&mapped))
    }

    /// `coversThisHost`: a list holding a loopback address holds every address that reaches this host.
    fn covers_this_host(&self, address: Option<&[u8]>) -> bool {
        self.lists_this_host && address.is_some_and(|a| is_this_host(&canonical(a)))
    }
}

fn require_host_name(property: &str, raw: &str, name: &str) -> Result<(), String> {
    if name.is_empty() || !name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.' || c == b'_') {
        return Err(invalid_entry(property, raw));
    }
    Ok(())
}

/// `String.trim`: every leading and trailing char at or below U+0020.
fn java_trim(text: &str) -> &str {
    text.trim_matches(|c: char| c <= ' ')
}

struct Cidr {
    network: Vec<u8>,
    prefix: usize,
}

impl Cidr {
    fn parse(property: &str, entry: &str, slash: usize) -> Result<Cidr, String> {
        let literal = netty_address(&entry[..slash]).ok_or_else(|| invalid_entry(property, entry))?;
        let digits = &entry[slash + 1..];
        // `Integer.parseInt`: an optional sign, then decimal digits
        let unsigned = digits.strip_prefix(['+', '-']).unwrap_or(digits);
        if unsigned.is_empty() || !unsigned.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid_entry(property, entry));
        }
        let prefix: i64 = digits.parse().map_err(|_| invalid_entry(property, entry))?;
        if prefix < 0 || prefix > (literal.len() * 8) as i64 {
            return Err(invalid_entry(property, entry));
        }
        let mut prefix = prefix as usize;
        let mut network = literal.clone();
        if literal.len() == 16 && canonical(&literal).len() == 4 {
            // ::ffff:a.b.c.d/n is the IPv4 block a.b.c.d/(n - 96)
            if prefix < 96 {
                return Err(invalid_entry(property, entry));
            }
            network = canonical(&literal);
            prefix -= 96;
        }
        Ok(Cidr { network, prefix })
    }

    fn matches(&self, address: &[u8]) -> bool {
        if address.len() != self.network.len() {
            return false;
        }
        let whole = self.prefix / 8;
        if address[..whole] != self.network[..whole] {
            return false;
        }
        let remaining = self.prefix % 8;
        if remaining == 0 {
            return true;
        }
        let mask = 0xffu8 << (8 - remaining);
        (address[whole] & mask) == (self.network[whole] & mask)
    }
}

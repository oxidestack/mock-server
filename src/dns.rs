//! DNS mocking (`dnsEnabled`, `dnsPort`): a UDP listener answering queries from expectations whose `httpRequest` is
//! a DNS request definition (`dnsName`, `dnsType`, `dnsClass`, `not`) and whose action is a `dnsResponse`
//! (`MockServer.bindDnsPort`, `DnsRequestHandler`). The wire codec follows Netty's (`DatagramDnsQueryDecoder`,
//! `DatagramDnsResponseEncoder`): names are never compressed, only the first question is answered and echoed,
//! record names go through `java.net.IDN.toASCII` as `DefaultDnsRecord` does, and decoding failures answer nothing
//! but log the exception text Netty's would have.

use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::recorded::{Arg, Kind, Level, LogEntry};
use crate::state::State;
use crate::udp_start::{UdpListener, UdpStartFailure};

/// `FixedRecvByteBufAllocator`'s 2048-byte datagram buffer.
const RECEIVE_BUFFER: usize = 2048;
const MAX_LABEL_LENGTH: usize = 63;
const MAX_NAME_LENGTH: usize = 255;
const MAX_CHARACTER_STRING_LENGTH: usize = 255;
const MAX_RDATA_LENGTH: usize = 0xFFFF;
const DNS_HEADER_LENGTH: usize = 12;
const DEFAULT_MAX_UDP_PAYLOAD_SIZE: usize = 512;
const RECORD_FIXED_OVERHEAD: usize = 10;
const QUESTION_FIXED_OVERHEAD: usize = 4;

/// Wire values of the record types the codec itself looks at (`NS` is not one of MockServer's `DnsRecordType`s, so a
/// query for it has no type, but its data is still decoded as a name).
const RTYPE_CNAME: u16 = 5;
const RTYPE_NS: u16 = 2;
const RTYPE_PTR: u16 = 12;
const RTYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;
const RCODE_FORMERR: u16 = 1;
const RCODE_SERVFAIL: u16 = 2;
const RCODE_NXDOMAIN: u16 = 3;
/// The ADDITIONAL section's index among a message's four count fields.
const SECTION_ADDITIONAL: usize = 3;

/// `DnsRecordType` (MockServer's), by wire value.
const TYPES: &[(&str, u16)] = &[("A", 1), ("AAAA", 28), ("CNAME", 5), ("MX", 15), ("SRV", 33), ("TXT", 16), ("PTR", 12)];
/// `DnsRecordClass`.
const CLASSES: &[(&str, u16)] = &[("IN", 1), ("CH", 3), ("HS", 4), ("ANY", 255)];
/// `DnsResponseCode`.
const CODES: &[(&str, u16)] = &[("NOERROR", 0), ("FORMERR", 1), ("SERVFAIL", 2), ("NXDOMAIN", 3), ("NOTIMP", 4), ("REFUSED", 5)];

fn name_of(table: &[(&'static str, u16)], value: u16) -> Option<&'static str> {
    table.iter().find(|(_, v)| *v == value).map(|(n, _)| *n)
}

fn value_of(table: &[(&str, u16)], name: &str) -> Option<u16> {
    table.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// The bound DNS listener.
pub struct Dns {
    pub port: u16,
    /// The task serving the socket, which owns it; taken by the stop that waits for it.
    serving: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Dns {
    /// Waits for the serving task to see `closing` and drop its socket, so the port is free when a stop returns.
    pub async fn stop(&self) {
        let serving = self.serving.lock().unwrap().take();
        if let Some(serving) = serving {
            let _ = serving.await;
        }
    }
}

/// Binds the listener when `dnsEnabled` (`MockServer.startDnsServer`), on `localBoundIP` when it is set
/// (`Ipv4UdpPortProbe.listenerAddress`). A port that cannot be bound, or one above 65535, refuses the start
/// (`DnsStartupException`); `dnsPort` 0 or below lets the server choose one.
pub fn start(state: &Arc<State>) -> Result<(), UdpStartFailure> {
    if !state.config.bool_property("dnsEnabled", false) {
        return Ok(());
    }
    let configured = state.config.int_property("dnsPort", 0).max(0);
    let port = u16::try_from(configured).map_err(|_| UdpStartFailure::out_of_range(UdpListener::Dns, configured))?;
    let (socket, early) = if port > 0 { bind_explicit_port(&state.config, port)? } else { bind_chosen_port(&state.config)? };
    let socket = socket
        .set_nonblocking(true)
        .and_then(|()| tokio::net::UdpSocket::from_std(socket))
        .and_then(|s| Ok((s.local_addr()?.port(), s)));
    let (port, socket) = socket.map_err(|e| UdpStartFailure::other(UdpListener::Dns, configured, e.to_string()))?;
    // Logged while the server starts, before a port is stamped on entries.
    let entry = LogEntry::new(Kind::ServerConfiguration, "DNS mock server started on port: {}").args([json!(port)]).without_port();
    crate::log::info_event(state, entry);
    let serving = tokio::spawn(serve(state.clone(), Arc::new(socket), early));
    let _ = state.dns.set(Dns { port, serving: std::sync::Mutex::new(Some(serving)) });
    Ok(())
}

/// Queries that reached the listener while its start checked the port, served before any other.
type Early = Vec<(Vec<u8>, std::net::SocketAddr)>;

/// `MockServer.bindExplicitDnsPort`: refused before anything is bound where macOS would let the listener share the
/// port with a socket holding it on IPv4 (which would get the queries sent to localhost); a socket that takes the port
/// between the probe and the bind is caught after the bind.
fn bind_explicit_port(config: &crate::config::Config, port: u16) -> Result<(std::net::UdpSocket, Early), UdpStartFailure> {
    let unavailable = |e: &std::io::Error| UdpStartFailure::bind(UdpListener::Dns, i64::from(port), e);
    let address = crate::udp_probe::listener_address(config, port).map_err(|e| unavailable(&e))?;
    if crate::udp_probe::shadowed_on_ipv4_probed(config, address, port) {
        return Err(UdpStartFailure::ipv4_wildcard_conflict(UdpListener::Dns, port));
    }
    let socket = crate::udp_probe::bind(address, port).map_err(|e| unavailable(&e))?;
    let mut early = Vec::new();
    if crate::udp_probe::loopback_reaches_another_socket(&socket, &mut early) {
        return Err(UdpStartFailure::ipv4_wildcard_conflict(UdpListener::Dns, port));
    }
    Ok((socket, early))
}

/// `MockServer.DNS_PORT_CANDIDATES`.
const PORT_CANDIDATES: usize = 10;

/// `MockServer.bindChosenDnsPort`: the dual-stack allocator on macOS can choose a port another socket holds on IPv4,
/// so the port is taken from the IPv4 allocator and bound as an explicit one would be; a candidate refused, or taken
/// before it is bound, is replaced.
fn bind_chosen_port(config: &crate::config::Config) -> Result<(std::net::UdpSocket, Early), UdpStartFailure> {
    let mut last = UdpStartFailure::other(UdpListener::Dns, 0, "no port was tried");
    for _ in 0..PORT_CANDIDATES {
        // 0, which lets the operating system choose, where IPv4 is unavailable
        let candidate = crate::udp_probe::port_free_on_ipv4();
        let address = match crate::udp_probe::listener_address(config, candidate) {
            Ok(address) => address,
            Err(e) => {
                last = UdpStartFailure::bind(UdpListener::Dns, 0, &e);
                continue;
            }
        };
        if candidate > 0 && crate::udp_probe::shadowed_on_ipv4_probed(config, address, candidate) {
            last = UdpStartFailure::ipv4_wildcard_conflict(UdpListener::Dns, candidate);
            continue;
        }
        match crate::udp_probe::bind(address, candidate) {
            Err(e) => last = UdpStartFailure::bind(UdpListener::Dns, i64::from(candidate), &e),
            Ok(socket) => {
                let mut early = Vec::new();
                if crate::udp_probe::loopback_reaches_another_socket(&socket, &mut early) {
                    let bound = socket.local_addr().map(|a| a.port()).unwrap_or(candidate);
                    last = UdpStartFailure::ipv4_wildcard_conflict(UdpListener::Dns, bound);
                } else {
                    return Ok((socket, early));
                }
            }
        }
    }
    Err(last.no_chosen_port())
}

async fn serve(state: Arc<State>, socket: Arc<tokio::net::UdpSocket>, early: Early) {
    let mut closing = state.closing.subscribe();
    for (packet, peer) in early {
        if let Some(answer) = handle(&state, &packet[..packet.len().min(RECEIVE_BUFFER)]) {
            let _ = socket.send_to(&answer, peer).await;
        }
    }
    let mut buf = vec![0u8; RECEIVE_BUFFER];
    loop {
        let (n, peer) = tokio::select! {
            received = socket.recv_from(&mut buf) => match received {
                Ok(r) => r,
                Err(_) => continue,
            },
            _ = closing.wait_for(|s| *s) => return,
        };
        if let Some(answer) = handle(&state, &buf[..n]) {
            let _ = socket.send_to(&answer, peer).await;
        }
    }
}

/// One datagram in, the answer out (`None`: nothing is sent back).
pub fn handle(state: &State, packet: &[u8]) -> Option<Vec<u8>> {
    let query = match decode(packet) {
        Ok(q) => q,
        Err(message) => {
            // `DnsRequestHandler.exceptionCaught`.
            crate::log::error_event(state, LogEntry::at(Level::Error, "exception caught by DNS handler -> {}").args([message]));
            return None;
        }
    };
    let Some(question) = &query.question else { return error_response(&query, RCODE_FORMERR) };
    let qtype = name_of(TYPES, question.qtype);
    let qclass = name_of(CLASSES, question.qclass);
    // `logCorrelationId`: every entry about this query carries it.
    let correlation = uuid::Uuid::new_v4().to_string();
    let mut request = Map::new();
    if let Some(c) = qclass {
        request.insert("dnsClass".into(), c.into());
    }
    request.insert("dnsName".into(), question.name.clone().into());
    if let Some(t) = qtype {
        request.insert("dnsType".into(), t.into());
    }
    let request = Value::Object(request);
    let (matched, evaluated) = state.store.first_dns_match(&request);
    if state.info_enabled() && !evaluated.is_empty() {
        log_evaluations(state, &request, &evaluated, matched.is_some(), &correlation);
    }
    // `DnsRequestHandler`: the received entry is logged at every level with the query's definition, once matched, so it
    // names the expectation that answered it (upstream #97, #101): verify and retrieve find it.
    let answered = matched.as_ref().filter(|e| e.input.get("dnsResponse").is_some_and(|r| !r.is_null()));
    let mut entry = LogEntry::new(Kind::ReceivedRequest, "received DNS query for name:{} type:{} class:{}")
        .correlation(&correlation)
        .request_json(request.clone())
        .args([
            Arg::from(question.name.as_str()),
            // `DnsRecordType` and `DnsRecordClass` constants (shown `json: true` on the dashboard)
            Arg::enum_name(qtype.unwrap_or_default()),
            Arg::enum_name(qclass.unwrap_or_default()),
        ]);
    if let Some(e) = answered {
        entry = entry.expectation_id(e.id.clone());
    }
    state.log.message_about(entry, crate::recorded::Subject::Definition(request.clone()));
    // What the scan dropped as expired (`scheduleLazyRemoval`), logged as removed.
    crate::control::log_lazy_removals(state, None);
    match matched.and_then(|e| e.input.get("dnsResponse").filter(|r| r.is_object()).cloned()) {
        Some(response) => respond(state, &query, question, &response, &correlation),
        None => error_response(&query, RCODE_NXDOMAIN),
    }
}

/// `DnsRequestPropertiesMatcher`: an expectation's DNS request definition.
#[derive(Debug, Clone)]
pub struct DnsMatcher {
    name: Option<String>,
    qtype: Option<String>,
    qclass: Option<String>,
    not: bool,
}

impl DnsMatcher {
    /// From a DNS request definition (an object with `dnsName`).
    pub fn compile(definition: &Value) -> Option<DnsMatcher> {
        let o = definition.as_object().filter(|o| o.contains_key("dnsName"))?;
        let text = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_string);
        Some(DnsMatcher { name: text("dnsName"), qtype: text("dnsType"), qclass: text("dnsClass"), not: o.get("not").and_then(Value::as_bool).unwrap_or(false) })
    }

    /// `matchesDns` against a DNS request definition (a query, or another expectation's definition treated as
    /// one): whether it matches, and the field whose difference was recorded (name, then type, then class).
    pub fn evaluate(&self, request: &Value) -> (bool, Option<&'static str>) {
        let field = |k: &str| request.get(k).and_then(Value::as_str);
        let strip = |s: &str| s.strip_suffix('.').unwrap_or(s).to_string();
        let mut difference = None;
        let name_ok = match &self.name {
            Some(expected) => field("dnsName").is_some_and(|actual| java_equals_ignore_case(&strip(expected), &strip(actual))),
            None => true,
        };
        if !name_ok {
            difference = Some("dnsName");
        }
        let type_ok = !name_ok || self.qtype.as_deref().is_none_or(|t| field("dnsType") == Some(t));
        if !type_ok {
            difference = Some("dnsType");
        }
        let class_ok = !name_ok || !type_ok || self.qclass.as_deref().is_none_or(|c| field("dnsClass") == Some(c));
        if !class_ok {
            difference = Some("dnsClass");
        }
        let request_not = request.get("not").and_then(Value::as_bool).unwrap_or(false);
        (((name_ok && type_ok && class_ok) != self.not) != request_not, difference)
    }
}

/// `String.equalsIgnoreCase`: char by char, equal when equal upper- or lower-cased.
pub(crate) fn java_equals_ignore_case(a: &str, b: &str) -> bool {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    a.len() == b.len()
        && a.iter().zip(&b).all(|(x, y)| x == y || x.to_uppercase().eq(y.to_uppercase()) || x.to_lowercase().eq(y.to_lowercase()))
}

/// `DnsRequestHandler`'s log lines for each expectation the query was matched against, and the closest one when
/// none matched (only a DNS filter or none shows them: the lines are about the query).
pub fn log_evaluations(state: &State, request: &Value, evaluated: &[crate::store::DnsEvaluated], matched: bool, correlation: &str) {
    let subject = || crate::recorded::Subject::Definition(request.clone());
    // `maxLoggedMatchFailures`: did-not-match entries past the request's budget are left out, and counted.
    let mut budget = crate::dataplane::NotMatchedLogBudget::of(state);
    for e in evaluated.iter().filter(|e| e.dns) {
        if !e.matched && !budget.admit() {
            continue;
        }
        let expectation = crate::canonical::logged_matched_expectation(&e.snapshot, e.expectation.end_date_millis());
        let (kind, format) = if e.matched { (Kind::ExpectationMatched, "request:{}matched expectation:{}") } else { (Kind::ExpectationNotMatched, "request:{}didn't match expectation") };
        let entry = LogEntry::new(kind, format).correlation(correlation).request_json(request.clone()).expectation(expectation.clone()).args([request, &expectation]);
        state.log.message_about(entry, subject());
    }
    if matched {
        return;
    }
    // Strictly fewer recorded differences wins, in match order; `DNS_APPLICABLE_FIELDS` counts three.
    let mut closest: Option<&crate::store::DnsEvaluated> = None;
    for e in evaluated.iter().filter(|e| !e.matched && e.active) {
        if closest.is_none_or(|c| e.differences < c.differences) {
            closest = Some(e);
        }
    }
    if let Some(c) = closest {
        let expectation = crate::canonical::logged_matched_expectation(&c.expectation.current(), c.expectation.end_date_millis());
        let format = format!("closest expectation:{{}}matched {}/3 fields for request:{{}}{}", 3 - c.differences.min(3), budget.note());
        let entry = LogEntry::new(Kind::ExpectationNotMatched, format).correlation(correlation).request_json(request.clone()).expectation(expectation.clone()).args([&expectation, request]);
        state.log.message_about(entry, subject());
    }
}

// ---------------------------------------------------------------------------------------------------- decoding

struct Question {
    name: String,
    qtype: u16,
    qclass: u16,
}

struct Query {
    id: u16,
    recursion_desired: bool,
    question: Option<Question>,
    /// The first EDNS(0) OPT record's CLASS (its advertised payload size).
    edns_payload: Option<u16>,
}

/// Netty's `ByteBuf` reads over the received datagram: since Netty 4.2.19 (b765b8271) the decoder reads a retained
/// slice of the pooled receive buffer, which an out-of-bounds read names with the buffer it wraps.
struct Reader<'a> {
    buf: &'a [u8],
    index: usize,
}

impl Reader<'_> {
    fn out_of_bounds(&self, length: usize) -> String {
        let (index, written) = (self.index, self.buf.len());
        format!(
            "java.lang.IndexOutOfBoundsException: readerIndex({index}) + length({length}) exceeds writerIndex({written}): PooledSlicedByteBuf(ridx: {index}, widx: {written}, cap: {written}/{written}, unwrapped: PooledDirectByteBuf(ridx: 0, widx: {written}, cap: {RECEIVE_BUFFER}))"
        )
    }

    fn u16(&mut self) -> Result<u16, String> {
        let bytes = self.buf.get(self.index..self.index + 2).ok_or_else(|| self.out_of_bounds(2))?;
        self.index += 2;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes = self.buf.get(self.index..self.index + 4).ok_or_else(|| self.out_of_bounds(4))?;
        self.index += 4;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// `DnsCodecUtil.decodeDomainName` over `buf[..end]` from `start`: the name (with a trailing dot, `.` for the
/// root) and where reading continues.
fn decode_name(buf: &[u8], start: usize, end: usize) -> Result<(String, usize), String> {
    let mut index = start;
    let mut position: Option<usize> = None;
    let mut checked = 0;
    if end <= start {
        return Ok((".".into(), index));
    }
    let mut name = String::new();
    while index < end {
        let len = buf[index] as usize;
        index += 1;
        if len & 0xc0 == 0xc0 {
            if position.is_none() {
                position = Some(index + 1);
            }
            if index >= end {
                return Err("truncated pointer in a name".into());
            }
            let next = (len & 0x3f) << 8 | buf[index] as usize;
            if next >= end {
                return Err("name has an out-of-range pointer".into());
            }
            index = next;
            checked += 2;
            if checked >= end {
                return Err("name contains a loop.".into());
            }
        } else if len != 0 {
            if end - index < len {
                return Err("truncated label in a name".into());
            }
            // Netty 4.2's `TooLongFrameException`s, which also bound the work a datagram of pointers can cause.
            if len > MAX_LABEL_LENGTH {
                return Err(format!("label must be <= {MAX_LABEL_LENGTH} but was {len}"));
            }
            name.push_str(&String::from_utf8_lossy(&buf[index..index + len]));
            name.push('.');
            index += len;
            let length = name.encode_utf16().count();
            if length > MAX_NAME_LENGTH {
                return Err(format!("domain name must be <= {MAX_NAME_LENGTH} but was {length}"));
            }
        } else {
            break;
        }
    }
    if let Some(p) = position {
        index = p;
    }
    if name.is_empty() {
        return Ok((".".into(), index));
    }
    if !name.ends_with('.') {
        name.push('.');
    }
    Ok((name, index))
}

/// `DatagramDnsQueryDecoder`: the header, every question (the first is kept) and every record (the first OPT's
/// class is kept); a record that does not fit ends its section, as Netty treats a truncated message.
fn decode(packet: &[u8]) -> Result<Query, String> {
    let packet = &packet[..packet.len().min(RECEIVE_BUFFER)];
    let mut r = Reader { buf: packet, index: 0 };
    let id = r.u16()?;
    let flags = r.u16()?;
    if flags >> 15 == 1 {
        return Err("not a query".into());
    }
    let counts = [r.u16()?, r.u16()?, r.u16()?, r.u16()?];
    let mut question = None;
    for _ in 0..counts[0] {
        let (name, next) = decode_name(packet, r.index, packet.len())?;
        r.index = next;
        let qtype = r.u16()?;
        let qclass = r.u16()?;
        let name = idn_to_ascii(&name).map_err(illegal_argument)?;
        if question.is_none() {
            question = Some(Question { name, qtype, qclass });
        }
    }
    let mut edns_payload = None;
    for (section, count) in counts.iter().enumerate().skip(1) {
        for _ in 0..*count {
            match decode_record(packet, &mut r)? {
                Some((rtype, class)) => {
                    if section == SECTION_ADDITIONAL && rtype == RTYPE_OPT && edns_payload.is_none() {
                        edns_payload = Some(class);
                    }
                }
                None => break,
            }
        }
    }
    Ok(Query { id, recursion_desired: flags >> 8 & 1 == 1, question, edns_payload })
}

/// `DefaultDnsRecordDecoder.decodeRecord`: `None` (and the reader back at the record) when it does not fit.
fn decode_record(packet: &[u8], r: &mut Reader) -> Result<Option<(u16, u16)>, String> {
    let start = r.index;
    let (name, next) = decode_name(packet, r.index, packet.len())?;
    r.index = next;
    if packet.len() - r.index < 10 {
        r.index = start;
        return Ok(None);
    }
    let rtype = r.u16()?;
    let class = r.u16()?;
    r.u32()?;
    let length = r.u16()? as usize;
    let offset = r.index;
    if packet.len() - offset < length {
        r.index = start;
        return Ok(None);
    }
    // PTR, CNAME and NS data are names, read (and so checked) within the record.
    if matches!(rtype, RTYPE_PTR | RTYPE_CNAME | RTYPE_NS) {
        decode_name(packet, offset, offset + length)?;
    }
    idn_to_ascii(&name).map_err(illegal_argument)?;
    r.index = offset + length;
    Ok(Some((rtype, class)))
}

/// A `DecoderException` wrapping an `IllegalArgumentException`: its message is the cause's `toString()`.
fn illegal_argument(message: String) -> String {
    format!("java.lang.IllegalArgumentException: {message}")
}

/// `java.net.IDN.toASCII(name)`, as `DefaultDnsRecord` applies it, with a trailing dot added (`appendTrailingDot`):
/// ASCII labels pass unchanged; others go through the JDK's IDNA2003 nameprep on Unicode 3.2 (unassigned code points
/// refused) and Punycode, ported in datafaker-rs (`datafaker::idn`). The error is the `IllegalArgumentException`
/// message.
pub fn idn_to_ascii(input: &str) -> Result<String, String> {
    let mut out = datafaker::idn::to_ascii(input).map_err(|e| e.message().to_string())?;
    if !out.ends_with('.') {
        out.push('.');
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------------- encoding

/// `DnsCodecUtil.encodeDomainName` (Netty 4.2): the labels, then the root label. `Err` is its
/// `IllegalArgumentException`, which fails the whole write, so nothing is sent.
fn encode_domain_name(name: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    if name == "." {
        out.push(0);
        return Ok(out);
    }
    let labels = java_split_dots(name);
    let mut total = 0;
    for (i, label) in labels.iter().enumerate() {
        let length = label.chars().count();
        if length == 0 {
            if i == labels.len() - 1 {
                break;
            }
            return Err(format!("DNS name contains empty label: {name}"));
        }
        if length > MAX_LABEL_LENGTH {
            return Err(format!("DNS label length {length} exceeds maximum of {MAX_LABEL_LENGTH}: {name}"));
        }
        if let Some(at) = label.chars().position(|c| c == '\0') {
            return Err(format!("DNS label contains null byte at index {at}"));
        }
        total += 1 + length;
        if total > MAX_NAME_LENGTH {
            return Err(format!("DNS name exceeds maximum length of {MAX_NAME_LENGTH}: {name}"));
        }
        out.push(length as u8);
        // `ByteBufUtil.writeAscii`: one byte per char.
        out.extend(label.chars().map(|c| if (c as u32) < 0x100 { c as u32 as u8 } else { b'?' }));
    }
    out.push(0);
    Ok(out)
}

/// `DnsRequestHandler.encodeDnsName`: an RDATA name in uncompressed wire form, within RFC 1035's limits.
fn encode_dns_name(name: &str) -> Result<Vec<u8>, String> {
    let name = if name.ends_with('.') { name.to_string() } else { format!("{name}.") };
    let labels: Vec<&str> = java_split_dots(&name);
    let mut total = 1;
    for label in labels.iter().filter(|l| !l.is_empty()) {
        if label.len() > MAX_LABEL_LENGTH {
            return Err(format!("DNS label \"{label}\" is {} octets which exceeds the maximum label length of {MAX_LABEL_LENGTH}", label.len()));
        }
        total += 1 + label.len();
    }
    if total > MAX_NAME_LENGTH {
        return Err(format!("DNS name \"{name}\" encodes to {total} octets which exceeds the maximum name length of {MAX_NAME_LENGTH}"));
    }
    let mut out = Vec::with_capacity(total);
    for label in labels.iter().filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(out)
}

/// `String.split("\\.")`: trailing empty strings are dropped.
fn java_split_dots(s: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = s.split('.').collect();
    while parts.last() == Some(&"") {
        parts.pop();
    }
    parts
}

/// `encodedNameLength`: a name's wire length, without validating it.
fn encoded_name_length(name: &str) -> usize {
    if name.is_empty() {
        return 1;
    }
    let terminated = if name.ends_with('.') { name.to_string() } else { format!("{name}.") };
    1 + java_split_dots(&terminated).iter().filter(|l| !l.is_empty()).map(|l| 1 + l.len()).sum::<usize>()
}

/// One encoded record: its owner name (after `IDN.toASCII`) and its wire bytes.
struct Encoded {
    name: String,
    rtype: u16,
    class: u16,
    ttl: u32,
    data: Vec<u8>,
}

impl Encoded {
    /// `DefaultDnsRecordEncoder.encodeRecord`: the owner name, type, class, TTL and data.
    fn wire(&self) -> Result<Vec<u8>, String> {
        let mut wire = encode_domain_name(&self.name)?;
        wire.extend_from_slice(&self.rtype.to_be_bytes());
        wire.extend_from_slice(&self.class.to_be_bytes());
        wire.extend_from_slice(&self.ttl.to_be_bytes());
        wire.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        wire.extend_from_slice(&self.data);
        Ok(wire)
    }
}

/// `DnsRequestHandler.encodeRecord`: `None` for a record without type or value (skipped); `Err` for one that
/// cannot be represented on the wire.
fn encode_record(record: &Value, qname: &str) -> Result<Option<Encoded>, String> {
    let text = |k: &str| record.get(k).and_then(Value::as_str);
    let int = |k: &str| record.get(k).and_then(Value::as_i64);
    let (Some(kind), Some(value)) = (text("type"), text("value")) else { return Ok(None) };
    let Some(rtype) = value_of(TYPES, kind) else { return Ok(None) };
    let name = text("name").filter(|n| !n.is_empty()).unwrap_or(qname);
    encode_dns_name(name)?;
    let ttl = int("ttl").unwrap_or(300) as u32;
    let class = text("dnsClass").and_then(|c| value_of(CLASSES, c)).unwrap_or(CLASS_IN);
    let u16_of = |v: i64| ((v & 0xFFFF) as u16).to_be_bytes();
    let data = match kind {
        "A" | "AAAA" => {
            let address = ip_address_bytes(value).ok_or_else(|| format!("invalid IP address for DNS {kind} record: {value}"))?;
            let expected = if kind == "A" { 4 } else { 16 };
            if address.len() != expected {
                return Err(format!("DNS {kind} record requires a {} address but was configured with: {value}", if expected == 4 { "IPv4" } else { "IPv6" }));
            }
            address
        }
        "CNAME" | "PTR" => encode_dns_name(value)?,
        "MX" => {
            let mut data = u16_of(int("priority").unwrap_or(10)).to_vec();
            data.extend(encode_dns_name(value)?);
            data
        }
        "SRV" => {
            let target = encode_dns_name(value)?;
            let mut data = Vec::with_capacity(6 + target.len());
            for field in ["priority", "weight", "port"] {
                data.extend(u16_of(int(field).unwrap_or(0)));
            }
            data.extend(target);
            data
        }
        "TXT" => character_strings(value)?,
        _ => return Ok(None),
    };
    // `DefaultDnsRawRecord`'s constructor: `IDN.toASCII` on the owner name.
    let owner = idn_to_ascii(name)?;
    Ok(Some(Encoded { name: owner, rtype, class, ttl, data }))
}

/// `encodeCharacterStrings`: TXT data as 255-octet character-strings, split rather than truncated.
fn character_strings(value: &str) -> Result<Vec<u8>, String> {
    let text = value.as_bytes();
    let chunks = text.len().div_ceil(MAX_CHARACTER_STRING_LENGTH).max(1);
    let total = text.len() + chunks;
    if total > MAX_RDATA_LENGTH {
        return Err(format!("DNS TXT record value encodes to {total} octets which exceeds the maximum RDATA length of {MAX_RDATA_LENGTH}"));
    }
    let mut out = Vec::with_capacity(total);
    if text.is_empty() {
        out.push(0);
    }
    for chunk in text.chunks(MAX_CHARACTER_STRING_LENGTH) {
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
    Ok(out)
}

/// `NetUtil.createByteArrayFromIpAddressString`: a dotted quad (Netty allows leading zeros) or an IPv6 literal
/// (optionally bracketed, with a scope), else `None`.
fn ip_address_bytes(value: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit())) {
        let octets: Vec<u16> = parts.iter().map(|p| p.parse().unwrap_or(256)).collect();
        if octets.iter().all(|o| *o <= 255) {
            return Some(octets.into_iter().map(|o| o as u8).collect());
        }
        return None;
    }
    let inner = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')).unwrap_or(value);
    let inner = inner.split('%').next().unwrap_or(inner);
    inner.parse::<std::net::Ipv6Addr>().ok().map(|a| a.octets().to_vec())
}

fn ip_of(bytes: Vec<u8>) -> Option<std::net::IpAddr> {
    match bytes.len() {
        4 => Some(std::net::IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        16 => Some(std::net::IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?)),
        _ => None,
    }
}

/// `DnsIntentRegistry`: answered address → the name it was answered for (without its trailing dot), the latest
/// answer winning, the oldest entry evicted past 10 000.
#[derive(Default)]
struct Intents {
    names: std::collections::HashMap<std::net::IpAddr, String>,
    order: std::collections::VecDeque<std::net::IpAddr>,
}

static INTENTS: std::sync::LazyLock<parking_lot::Mutex<Intents>> = std::sync::LazyLock::new(Default::default);
const MAX_INTENTS: usize = 10_000;

fn record_intent(ip: std::net::IpAddr, name: &str) {
    let name = name.strip_suffix('.').unwrap_or(name).to_string();
    let mut intents = INTENTS.lock();
    if intents.names.insert(ip, name).is_none() {
        intents.order.push_back(ip);
        if intents.order.len() > MAX_INTENTS && let Some(eldest) = intents.order.pop_front() {
            intents.names.remove(&eldest);
        }
    }
}

/// `DnsIntentRegistry.recover`: the name a DNS answer gave `ip` for.
pub fn intent(ip: std::net::IpAddr) -> Option<String> {
    INTENTS.lock().names.get(&ip).cloned()
}

/// The response header (`DnsMessageUtil.encodeHeader`): QR, opcode QUERY, AA, TC, RD from the query, RA, Z 0.
fn header(query: &Query, truncated: bool, code: u16, counts: [usize; 4]) -> Vec<u8> {
    let mut flags: u16 = 0x8000 | 0x0400 | 0x0080 | (code & 0xF);
    if truncated {
        flags |= 0x0200;
    }
    if query.recursion_desired {
        flags |= 0x0100;
    }
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&query.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    for c in counts {
        out.extend_from_slice(&(c as u16).to_be_bytes());
    }
    out
}

/// The question as Netty's encoder writes it back: the name (after `IDN.toASCII`), the type and class as sent.
fn question_wire(q: &Question) -> Result<Vec<u8>, String> {
    let mut wire = encode_domain_name(&q.name)?;
    wire.extend_from_slice(&q.qtype.to_be_bytes());
    wire.extend_from_slice(&q.qclass.to_be_bytes());
    Ok(wire)
}

/// `sendErrorResponse`: the question (if any) and the code, nothing else; `None` when the encoder fails.
fn error_response(query: &Query, code: u16) -> Option<Vec<u8>> {
    let mut out = header(query, false, code, [query.question.is_some() as usize, 0, 0, 0]);
    if let Some(q) = &query.question {
        out.extend(question_wire(q).ok()?);
    }
    Some(out)
}

/// `sendDnsResponse`: every record encoded up front (any failure is a SERVFAIL), then added while the message fits
/// the client's UDP payload limit, TC set when one had to be dropped (later, smaller records may still fit).
/// `None` when the encoder fails on a name (a NUL in a label), which leaves the query unanswered.
fn respond(state: &State, query: &Query, question: &Question, response: &Value, correlation: &str) -> Option<Vec<u8>> {
    let mut sections: [Vec<Encoded>; 3] = Default::default();
    for (i, key) in ["answerRecords", "authorityRecords", "additionalRecords"].iter().enumerate() {
        for record in response.get(*key).and_then(Value::as_array).into_iter().flatten() {
            if record.is_null() {
                continue;
            }
            match encode_record(record, &question.name) {
                Ok(Some(e)) => sections[i].push(e),
                Ok(None) => {}
                Err(message) => {
                    let entry = LogEntry::at(Level::Error, "cannot encode configured DNS response, returning SERVFAIL -> {}").correlation(correlation).args([message]);
                    crate::log::error_event(state, entry);
                    return error_response(query, RCODE_SERVFAIL);
                }
            }
        }
    }
    let code = response.get("responseCode").and_then(Value::as_str).and_then(|c| value_of(CODES, c)).unwrap_or(0);
    let budget = match query.edns_payload {
        // `min(dnsClass, MAX_RDATA_LENGTH)` never binds: the class is 16 bits.
        Some(size) => DEFAULT_MAX_UDP_PAYLOAD_SIZE.max(size as usize),
        None => DEFAULT_MAX_UDP_PAYLOAD_SIZE,
    };
    let mut used = DNS_HEADER_LENGTH + encoded_name_length(&question.name) + QUESTION_FIXED_OVERHEAD;
    let mut truncated = false;
    let mut kept: [Vec<&Encoded>; 3] = Default::default();
    for (i, records) in sections.iter().enumerate() {
        for record in records {
            let length = encoded_name_length(&record.name) + RECORD_FIXED_OVERHEAD + record.data.len();
            if used + length > budget {
                truncated = true;
                continue;
            }
            used += length;
            kept[i].push(record);
        }
    }
    if truncated {
        let format = "DNS response exceeds the {} byte UDP payload limit, returning a truncated response with the TC bit set";
        crate::log::warn_event(state, LogEntry::at(Level::Warn, format).correlation(correlation).args([json!(budget)]));
    }
    if state.info_enabled() {
        let entry = LogEntry::at(Level::Info, "returning DNS response with {} answer records").correlation(correlation).args([json!(kept[0].len())]);
        state.log.message(entry);
    }
    // `recordDnsIntentMappings`: every configured A/AAAA answer (dropped by truncation or not), for the transparent
    // proxy's DNS-intent resolver.
    for record in response.get("answerRecords").and_then(Value::as_array).into_iter().flatten() {
        if matches!(record.get("type").and_then(Value::as_str), Some("A" | "AAAA")) && let Some(ip) = record.get("value").and_then(Value::as_str).and_then(ip_address_bytes).and_then(ip_of) {
            record_intent(ip, &question.name);
        }
    }
    let mut out = header(query, truncated, code, [1, kept[0].len(), kept[1].len(), kept[2].len()]);
    out.extend(question_wire(question).ok()?);
    for record in kept.iter().flatten() {
        out.extend(record.wire().ok()?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request_json(name: &str, qtype: &str) -> Value {
        json!({"dnsClass": "IN", "dnsName": name, "dnsType": qtype})
    }

    #[test]
    fn names_decode_as_netty_does() {
        let packet = [3, b'a', b'b', b'c', 0];
        assert_eq!(decode_name(&packet, 0, 5).unwrap(), ("abc.".to_string(), 5));
        assert_eq!(decode_name(&[0], 0, 1).unwrap().0, ".");
        assert_eq!(decode_name(&[0xc0, 0], 0, 2).unwrap_err(), "name contains a loop.");
        assert_eq!(decode_name(&[5, b'a'], 0, 2).unwrap_err(), "truncated label in a name");
        assert_eq!(decode_name(&[0xc0], 0, 1).unwrap_err(), "truncated pointer in a name");
        assert_eq!(decode_name(&[0xc0, 9], 0, 2).unwrap_err(), "name has an out-of-range pointer");
        let mut long_label = vec![64u8];
        long_label.extend([b'a'; 64]);
        long_label.push(0);
        assert_eq!(decode_name(&long_label, 0, long_label.len()).unwrap_err(), "label must be <= 63 but was 64");
        let mut long_name: Vec<u8> = (0..4).flat_map(|_| std::iter::once(63u8).chain([b'b'; 63])).collect();
        long_name.extend([1, b'a', 0]);
        assert_eq!(decode_name(&long_name, 0, long_name.len()).unwrap_err(), "domain name must be <= 255 but was 256");
    }

    #[test]
    fn names_encode_as_netty_4_2_does() {
        assert_eq!(encode_domain_name("a.b.").unwrap(), vec![1, b'a', 1, b'b', 0]);
        assert_eq!(encode_domain_name(".").unwrap(), vec![0]);
        assert_eq!(encode_domain_name("a\0b.").unwrap_err(), "DNS label contains null byte at index 1");
    }

    #[test]
    fn short_packets_fail_like_netty_buffers() {
        assert_eq!(
            decode(&[0x12, 0x34]).err().unwrap(),
            "java.lang.IndexOutOfBoundsException: readerIndex(2) + length(2) exceeds writerIndex(2): PooledSlicedByteBuf(ridx: 2, widx: 2, cap: 2/2, unwrapped: PooledDirectByteBuf(ridx: 0, widx: 2, cap: 2048))"
        );
        assert_eq!(decode(&[0x12, 0x34, 0x81, 0, 0, 0, 0, 0, 0, 0, 0, 0]).err().unwrap(), "not a query");
    }

    #[test]
    fn idn_to_ascii_as_the_jdk() {
        assert_eq!(idn_to_ascii("A.Example.com").unwrap(), "A.Example.com.");
        assert_eq!(idn_to_ascii(".").unwrap(), ".");
        assert_eq!(idn_to_ascii("a..b").unwrap_err(), "Empty label is not a legal name");
        assert_eq!(idn_to_ascii(&"a".repeat(64)).unwrap_err(), "The label in the input is too long");
        assert_eq!(idn_to_ascii("bücher.example").unwrap(), "xn--bcher-kva.example.");
        assert_eq!(idn_to_ascii("a\u{FFFD}b").unwrap_err(), "java.text.ParseException: A prohibited code point was found in the inputa\u{FFFD}b");
        assert_eq!(idn_to_ascii("Straße.example").unwrap(), "strasse.example.");
        assert_eq!(idn_to_ascii("\u{1F600}.example").unwrap_err(), "java.text.ParseException: An unassigned code point was found in the input \u{1F600}");
    }

    #[test]
    fn ip_addresses_as_netty_parses_them() {
        assert_eq!(ip_address_bytes("10.0.0.1"), Some(vec![10, 0, 0, 1]));
        assert_eq!(ip_address_bytes("010.0.0.1"), Some(vec![10, 0, 0, 1]));
        assert_eq!(ip_address_bytes("256.0.0.1"), None);
        assert_eq!(ip_address_bytes("[::1]").map(|b| b.len()), Some(16));
        assert_eq!(ip_address_bytes("not-an-ip"), None);
    }

    #[test]
    fn txt_values_split_into_character_strings() {
        assert_eq!(character_strings("").unwrap(), vec![0]);
        let long = character_strings(&"x".repeat(300)).unwrap();
        assert_eq!((long[0], long[256], long.len()), (255, 45, 302));
    }

    #[test]
    fn dns_matcher_follows_upstream_not_operators() {
        let m = DnsMatcher::compile(&json!({"dnsName": "api.example.com", "dnsType": "A"})).unwrap();
        assert_eq!(m.evaluate(&request_json("API.example.com.", "A")), (true, None));
        assert_eq!(m.evaluate(&request_json("api.example.com.", "TXT")), (false, Some("dnsType")));
        assert_eq!(m.evaluate(&request_json("other.example.com.", "TXT")), (false, Some("dnsName")));
        let negated = DnsMatcher::compile(&json!({"dnsName": "api.example.com", "not": true})).unwrap();
        assert!(negated.evaluate(&request_json("other.example.com.", "A")).0);
    }
}

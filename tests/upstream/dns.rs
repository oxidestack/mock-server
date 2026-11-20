//! DNS mocking over real UDP datagrams: ports of mockserver-netty's `DnsRequestHandlerWireTest` and
//! `DnsRequestHandlerTest`, plus answers and event-log lines recorded from the oracle (`mockserver/mockserver:8.0.0`
//! with `MOCKSERVER_DNS_ENABLED=true`, queried from inside its container; `tests/files/dns/`).

use std::net::UdpSocket;
use std::time::Duration;

use serde_json::{Value, json};

use crate::common;

async fn start() -> (common::Running, u16) {
    let running = common::start(&[("dnsEnabled", "true"), ("dnsPort", "0")]).await;
    let port = running.server.dns_port().expect("DNS listener bound");
    (running, port)
}

/// How long a query that must be answered waits for its datagram (one second flaked on a machine at
/// load 40+). Each exchange uses a socket of its own, so a late answer never reaches another query.
const ANSWER_WAIT: Duration = Duration::from_secs(15);

/// How long a query the server must leave unanswered (a malformed one) waits before counting as silence.
const SILENCE_WAIT: Duration = Duration::from_millis(1000);

/// Sends one datagram; the answer, or `None` when nothing comes back within `wait`.
async fn exchange(port: u16, packet: Vec<u8>, wait: Duration) -> Option<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(wait)).unwrap();
        socket.send_to(&packet, ("127.0.0.1", port)).unwrap();
        let mut buf = vec![0u8; 65535];
        socket.recv(&mut buf).ok().map(|n| buf[..n].to_vec())
    })
    .await
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// A query for `name`/`qtype` (class IN), RD as given, with an EDNS(0) OPT record when `edns` is given.
fn query(id: u16, name: &str, qtype: u16, rd: bool, edns: Option<u16>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(if rd { 0x0100u16 } else { 0 }).to_be_bytes());
    for c in [1u16, 0, 0, edns.is_some() as u16] {
        out.extend_from_slice(&c.to_be_bytes());
    }
    out.extend(encode_name(name));
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    if let Some(size) = edns {
        out.push(0);
        out.extend_from_slice(&41u16.to_be_bytes());
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    }
    out
}

/// A resource record: its section, name, type, class, TTL and data.
type Record = (usize, String, u16, u16, u32, Vec<u8>);

/// A parsed answer: the header fields, and each record's section, owner name, type, class, TTL and data.
#[derive(Debug)]
struct Message {
    flags: u16,
    rcode: u16,
    counts: [u16; 4],
    records: Vec<Record>,
    length: usize,
}

impl Message {
    fn flag(&self, mask: u16) -> bool {
        self.flags & mask != 0
    }

    fn answers(&self) -> Vec<&Record> {
        self.records.iter().filter(|r| r.0 == 1).collect()
    }
}

/// Reads a name (compression pointers followed) at `at`: the dotted name and the offset after it.
fn read_name(buf: &[u8], mut at: usize) -> (String, usize) {
    let mut labels = Vec::new();
    let mut end = None;
    loop {
        let len = buf[at] as usize;
        if len & 0xc0 == 0xc0 {
            end.get_or_insert(at + 2);
            at = (len & 0x3f) << 8 | buf[at + 1] as usize;
            continue;
        }
        if len == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(&buf[at + 1..at + 1 + len]).into_owned());
        at += 1 + len;
    }
    (labels.join(".") + ".", end.unwrap_or(at + 1))
}

/// An independent RFC 1035 reader, standing in for upstream's dnsjava.
fn parse(buf: &[u8]) -> Message {
    let u16_at = |i: usize| u16::from_be_bytes([buf[i], buf[i + 1]]);
    let flags = u16_at(2);
    let counts = [u16_at(4), u16_at(6), u16_at(8), u16_at(10)];
    let mut at = 12;
    for _ in 0..counts[0] {
        at = read_name(buf, at).1 + 4;
    }
    let mut records = Vec::new();
    for (section, count) in counts.iter().enumerate().skip(1) {
        for _ in 0..*count {
            let (name, next) = read_name(buf, at);
            let (rtype, class) = (u16_at(next), u16_at(next + 2));
            let ttl = u32::from_be_bytes([buf[next + 4], buf[next + 5], buf[next + 6], buf[next + 7]]);
            let length = u16_at(next + 8) as usize;
            records.push((section, name, rtype, class, ttl, buf[next + 10..next + 10 + length].to_vec()));
            at = next + 10 + length;
        }
    }
    assert_eq!(at, buf.len(), "trailing bytes");
    Message { flags, rcode: flags & 0xF, counts, records, length: buf.len() }
}

/// TXT data as its character-strings.
fn strings(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let len = data[at] as usize;
        out.push(data[at + 1..at + 1 + len].to_vec());
        at += 1 + len;
    }
    out
}

struct Wire {
    running: common::Running,
    port: u16,
    next_id: u16,
}

impl Wire {
    async fn new() -> Wire {
        let (running, port) = start().await;
        Wire { running, port, next_id: 1 }
    }

    async fn expect(&self, name: &str, response: Value) {
        common::expect(self.running.port, &json!({"httpRequest": {"dnsName": name}, "dnsResponse": response})).await;
    }

    async fn query_with(&mut self, name: &str, qtype: u16, rd: bool, edns: Option<u16>) -> Message {
        self.next_id += 1;
        let answer = exchange(self.port, query(self.next_id, name, qtype, rd, edns), ANSWER_WAIT).await.expect("handler emitted no response datagram");
        assert_eq!(u16::from_be_bytes([answer[0], answer[1]]), self.next_id);
        parse(&answer)
    }

    async fn query(&mut self, name: &str, qtype: u16) -> Message {
        self.query_with(name, qtype, true, None).await
    }
}

fn a(name: &str, ip: &str) -> Value {
    json!({"name": name, "type": "A", "value": ip})
}

const NOERROR: u16 = 0;
const SERVFAIL: u16 = 2;
const NXDOMAIN: u16 = 3;

/// `MockServer.bindDnsPort`'s startup line, as the oracle's event log renders it.
#[tokio::test]
async fn logs_the_dns_port_at_startup() {
    let (running, port) = start().await;
    let logs = common::logs(running.port).await;
    assert!(logs.contains(&format!(" - DNS mock server started on port: \n\n  {port}\n")), "{logs}");
}

// ---------------------------------------------------------------------------------- DnsRequestHandlerWireTest

#[tokio::test]
async fn should_emit_an_a_record_a_real_resolver_can_parse() {
    let mut w = Wire::new().await;
    w.expect("api.example.com.", json!({"answerRecords": [a("api.example.com.", "10.0.0.1")]})).await;
    let m = w.query("api.example.com.", 1).await;
    assert_eq!(m.rcode, NOERROR);
    let answers = m.answers();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].1, "api.example.com.");
    assert_eq!((answers[0].2, answers[0].4, answers[0].5.clone()), (1, 300, vec![10, 0, 0, 1]));
}

#[tokio::test]
async fn should_emit_a_cname_record_a_real_resolver_can_parse() {
    let mut w = Wire::new().await;
    w.expect("alias.example.com.", json!({"answerRecords": [{"name": "alias.example.com.", "type": "CNAME", "value": "real.example.com."}]})).await;
    let m = w.query("alias.example.com.", 5).await;
    assert_eq!(read_name(&m.answers()[0].5, 0).0, "real.example.com.");
}

async fn cname_rcode(target: &str) -> u16 {
    let mut w = Wire::new().await;
    w.expect("alias.example.com.", json!({"answerRecords": [{"name": "alias.example.com.", "type": "CNAME", "value": target}]})).await;
    let m = w.query("alias.example.com.", 5).await;
    if m.rcode == SERVFAIL {
        assert_eq!(m.answers().len(), 0);
    }
    m.rcode
}

#[tokio::test]
async fn should_return_servfail_rather_than_emit_a_label_long_enough_to_look_like_a_compression_pointer() {
    assert_eq!(cname_rcode(&format!("{}.example.com.", "a".repeat(200))).await, SERVFAIL);
}

#[tokio::test]
async fn should_return_servfail_for_a_label_just_over_the_sixty_three_octet_limit() {
    assert_eq!(cname_rcode(&format!("{}.example.com.", "a".repeat(64))).await, SERVFAIL);
}

#[tokio::test]
async fn should_accept_a_label_of_exactly_sixty_three_octets() {
    let label = "a".repeat(63);
    let mut w = Wire::new().await;
    w.expect("alias.example.com.", json!({"answerRecords": [{"name": "alias.example.com.", "type": "CNAME", "value": format!("{label}.example.com.")}]})).await;
    let m = w.query("alias.example.com.", 5).await;
    assert_eq!(m.rcode, NOERROR);
    assert_eq!(read_name(&m.answers()[0].5, 0).0, format!("{label}.example.com."));
}

#[tokio::test]
async fn should_return_servfail_for_a_name_exceeding_two_hundred_and_fifty_five_octets() {
    let long = ['a', 'b', 'c', 'd', 'e'].iter().map(|c| c.to_string().repeat(60)).collect::<Vec<_>>().join(".") + ".example.com.";
    assert_eq!(cname_rcode(&long).await, SERVFAIL);
}

#[tokio::test]
async fn should_return_servfail_for_an_owner_name_with_an_over_long_label() {
    let mut w = Wire::new().await;
    w.expect("api.example.com.", json!({"answerRecords": [a(&format!("{}.example.com.", "a".repeat(64)), "10.0.0.1")]})).await;
    assert_eq!(w.query("api.example.com.", 1).await.rcode, SERVFAIL);
}

#[tokio::test]
async fn should_return_servfail_for_an_owner_name_over_two_hundred_and_fifty_five_octets_with_legal_labels() {
    let owner = format!("{}example.com.", format!("{}.", "b".repeat(60)).repeat(6));
    assert!(owner.split('.').all(|l| l.len() <= 63) && owner.len() > 255);
    let mut w = Wire::new().await;
    w.expect("api.example.com.", json!({"answerRecords": [a(&owner, "10.0.0.1")]})).await;
    assert_eq!(w.query("api.example.com.", 1).await.rcode, SERVFAIL);
}

async fn txt(value: &str) -> Vec<Vec<u8>> {
    let mut w = Wire::new().await;
    w.expect("txt.example.com.", json!({"answerRecords": [{"name": "txt.example.com.", "type": "TXT", "value": value}]})).await;
    strings(&w.query("txt.example.com.", 16).await.answers()[0].5)
}

#[tokio::test]
async fn should_split_a_txt_value_longer_than255_octets_across_character_strings() {
    let value = "x".repeat(300);
    let chunks = txt(&value).await;
    assert_eq!(chunks.iter().map(Vec::len).collect::<Vec<_>>(), vec![255, 45]);
    assert_eq!(chunks.concat(), value.as_bytes());
}

#[tokio::test]
async fn should_round_trip_a_dkim_sized_txt_value() {
    let value = format!("v=DKIM1; k=rsa; p={}", "A".repeat(392));
    assert_eq!(txt(&value).await.concat(), value.as_bytes());
}

#[tokio::test]
async fn should_emit_a_txt_value_of_exactly255_octets_as_a_single_character_string() {
    let value = "x".repeat(255);
    assert_eq!(txt(&value).await, vec![value.into_bytes()]);
}

#[tokio::test]
async fn should_not_corrupt_multi_byte_utf8_in_a_long_txt_value() {
    let value = format!("{}é", "e".repeat(254));
    let chunks = txt(&value).await;
    assert_eq!(chunks.iter().map(Vec::len).collect::<Vec<_>>(), vec![255, 1]);
    assert_eq!(String::from_utf8(chunks.concat()).unwrap(), value);
}

async fn single_rcode(kind: &str, value: &str, qtype: u16) -> u16 {
    let mut w = Wire::new().await;
    w.expect("bad.example.com.", json!({"answerRecords": [{"name": "bad.example.com.", "type": kind, "value": value}]})).await;
    w.query("bad.example.com.", qtype).await.rcode
}

#[tokio::test]
async fn should_return_servfail_for_an_a_record_configured_with_an_ipv6_address() {
    assert_eq!(single_rcode("A", "2001:db8::1", 1).await, SERVFAIL);
}

#[tokio::test]
async fn should_return_servfail_for_an_aaaa_record_configured_with_an_ipv4_address() {
    assert_eq!(single_rcode("AAAA", "10.0.0.1", 28).await, SERVFAIL);
}

#[tokio::test]
async fn should_return_servfail_for_an_unparseable_ip_address() {
    assert_eq!(single_rcode("A", "not-an-ip", 1).await, SERVFAIL);
}

#[tokio::test]
async fn should_default_an_absent_owner_name_to_the_queried_name() {
    let mut w = Wire::new().await;
    w.expect("api.example.com.", json!({"answerRecords": [{"type": "A", "value": "10.0.0.1"}]})).await;
    assert_eq!(w.query("api.example.com.", 1).await.answers()[0].1, "api.example.com.");
}

#[tokio::test]
async fn should_prefer_an_explicit_owner_name_over_the_queried_name() {
    let mut w = Wire::new().await;
    w.expect("api.example.com.", json!({"answerRecords": [a("other.example.com.", "10.0.0.1")]})).await;
    assert_eq!(w.query("api.example.com.", 1).await.answers()[0].1, "other.example.com.");
}

#[tokio::test]
async fn should_set_recursion_available_and_authoritative_answer() {
    let mut w = Wire::new().await;
    w.expect("api.example.com.", json!({"answerRecords": [a("api.example.com.", "10.0.0.1")]})).await;
    let m = w.query("api.example.com.", 1).await;
    assert!(m.flag(0x0080), "RA");
    assert!(m.flag(0x0400), "AA");
    assert!(m.flag(0x8000), "QR");
}

#[tokio::test]
async fn should_echo_recursion_desired_from_the_query() {
    let mut w = Wire::new().await;
    w.expect("api.example.com.", json!({"answerRecords": [a("api.example.com.", "10.0.0.1")]})).await;
    assert!(w.query_with("api.example.com.", 1, true, None).await.flag(0x0100));
    assert!(!w.query_with("api.example.com.", 1, false, None).await.flag(0x0100));
}

#[tokio::test]
async fn should_set_flags_on_nxdomain_responses_too() {
    let mut w = Wire::new().await;
    let m = w.query("unknown.example.com.", 1).await;
    assert_eq!(m.rcode, NXDOMAIN);
    assert!(m.flag(0x0080));
}

fn forty_a_records() -> Value {
    json!({"answerRecords": (1..=40).map(|i| a("api.example.com.", &format!("10.0.0.{i}"))).collect::<Vec<_>>()})
}

#[tokio::test]
async fn should_set_the_truncated_bit_when_the_response_exceeds_the_udp_payload_limit() {
    let mut w = Wire::new().await;
    w.expect("api.example.com.", forty_a_records()).await;
    let m = w.query("api.example.com.", 1).await;
    assert!(m.flag(0x0200), "TC");
    assert!(m.length <= 512);
    assert!(!m.answers().is_empty());
}

#[tokio::test]
async fn should_not_set_the_truncated_bit_when_the_response_fits() {
    let mut w = Wire::new().await;
    w.expect("api.example.com.", json!({"answerRecords": [a("api.example.com.", "10.0.0.1")]})).await;
    assert!(!w.query("api.example.com.", 1).await.flag(0x0200));
}

#[tokio::test]
async fn should_honour_an_edns_advertised_payload_size_before_truncating() {
    let mut w = Wire::new().await;
    w.expect("api.example.com.", forty_a_records()).await;
    let m = w.query_with("api.example.com.", 1, true, Some(4096)).await;
    assert!(!m.flag(0x0200));
    assert_eq!((m.answers().len(), m.counts[1]), (40, 40));
}

// -------------------------------------------------------------------------------------- DnsRequestHandlerTest
// `DnsIntentRegistry` is process-wide (as upstream's singleton), so each test uses addresses of its own.

async fn answer_for(name: &str, qtype: u16, response: Value) {
    let mut w = Wire::new().await;
    w.expect(name, response).await;
    w.query(name, qtype).await;
}

#[tokio::test]
async fn should_record_a_record_in_dns_intent_registry() {
    let (running, _) = start().await;
    answer_for("api.example.com.", 1, json!({"answerRecords": [a("api.example.com.", "10.77.0.1")]})).await;
    assert_eq!(running.server.dns_intent("10.77.0.1".parse().unwrap()).as_deref(), Some("api.example.com"));
}

#[tokio::test]
async fn should_record_aaaa_record_in_dns_intent_registry() {
    let (running, _) = start().await;
    answer_for("ipv6.example.com.", 28, json!({"answerRecords": [{"name": "ipv6.example.com.", "type": "AAAA", "value": "2001:db8::77"}]})).await;
    assert_eq!(running.server.dns_intent("2001:db8::77".parse().unwrap()).as_deref(), Some("ipv6.example.com"));
}

#[tokio::test]
async fn should_not_record_for_nxdomain() {
    let mut w = Wire::new().await;
    assert_eq!(w.query("unknown-intent.example.com.", 1).await.rcode, NXDOMAIN);
    assert_eq!(w.running.server.dns_intent("10.77.0.9".parse().unwrap()), None);
}

#[tokio::test]
async fn should_not_record_non_address_records() {
    let mut w = Wire::new().await;
    w.expect("alias-intent.example.com.", json!({"answerRecords": [{"type": "CNAME", "value": "10.77.0.3"}]})).await;
    w.query("alias-intent.example.com.", 5).await;
    assert_eq!(w.running.server.dns_intent("10.77.0.3".parse().unwrap()), None);
}

#[tokio::test]
async fn should_record_multiple_a_records() {
    let (running, _) = start().await;
    answer_for("multi.example.com.", 1, json!({"answerRecords": [a("multi.example.com.", "10.77.0.4"), a("multi.example.com.", "10.77.0.5")]})).await;
    for ip in ["10.77.0.4", "10.77.0.5"] {
        assert_eq!(running.server.dns_intent(ip.parse().unwrap()).as_deref(), Some("multi.example.com"));
    }
}

// ---------------------------------------------------------------------- DnsIntentOriginalDestinationResolverTest
// The resolver as the transparent proxy consults it on each connection: the address the client connected to, looked
// up in the DNS-intent registry, names the original destination, so an unmatched request is forwarded there (the
// name unresolved, with the connection's port). `shouldReturnNullWhenNoRegistryEntry` is the Host-header fallback of
// `tests/scenarios/transparent_proxy_host_fallback.json`; `shouldResolveIPv6Address` needs a connection to an IPv6
// local address, which the IPv4-bound listener cannot accept here (the registry side is
// `should_record_aaaa_record_in_dns_intent_registry`); a non-IP local address cannot occur on a TCP listener.
// The registry is process-wide: 127.0.0.1 is named by no other test.

#[tokio::test]
async fn should_resolve_hostname_from_dns_intent() {
    let running = common::start(&[("dnsEnabled", "true"), ("dnsPort", "0"), ("transparentProxyEnabled", "true")]).await;
    let dns_port = running.server.dns_port().expect("DNS listener bound");
    let name = "intent-resolver.invalid.";
    common::expect(running.port, &json!({"httpRequest": {"dnsName": name}, "dnsResponse": {"answerRecords": [a(name, "127.0.0.1")]}})).await;
    exchange(dns_port, query(1, name, 1, true, None), ANSWER_WAIT).await.expect("DNS answer");
    assert_eq!(running.server.dns_intent("127.0.0.1".parse().unwrap()).as_deref(), Some("intent-resolver.invalid"));
    // the connection's local address is 127.0.0.1: the request goes to intent-resolver.invalid:<port>, which no
    // resolver knows, so the forward fails
    let response = common::send(running.port, "GET", "/unmatched-behind-intent", "").await;
    assert_eq!(response.status, 502, "{}", response.head);
    let logs = common::logs(running.port).await;
    // without the intent the local Host header would not be forwarded at all (404)
    assert!(logs.contains("intent-resolver.invalid"), "{logs}");
}

// ------------------------------------------------------------------------------------------------ the oracle

fn vectors() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files/dns/oracle_vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Each case (a reset, its expectations, then its queries in order) answers byte for byte what the oracle
/// answered, including the queries it answers nothing to (malformed ones), and its event log, read through each
/// filter, lists what the oracle's did.
#[tokio::test]
async fn answers_and_event_log_match_the_oracle() {
    let v = vectors();
    for case in v["cases"].as_array().unwrap() {
        let note = case["note"].as_str().unwrap();
        let (running, port) = start().await;
        assert_eq!(common::send(running.port, "PUT", "/mockserver/reset", "").await.status, 200);
        common::expect(running.port, &case["expectations"]).await;
        for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let wait = if step["answer"].is_string() { ANSWER_WAIT } else { SILENCE_WAIT };
            let answer = exchange(port, unhex(step["query"].as_str().unwrap()), wait).await;
            assert_eq!(answer.map(|a| hex(&a)), step["answer"].as_str().map(str::to_string), "{note}: query {i}: {}", step["query"]);
        }
        for log in case["logs"].as_array().into_iter().flatten() {
            let body = if log["filter"].is_null() { String::new() } else { log["filter"].to_string() };
            let logs = common::send(running.port, "PUT", "/mockserver/retrieve?type=LOGS", &body).await.body;
            let entries: Vec<String> = logs
                .split("\n------------------------------------\n")
                .map(|e| e.get(26..).unwrap_or_default().trim_end_matches('\n').to_string())
                .filter(|e| !e.is_empty() && !e.starts_with("retrieved logs"))
                .collect();
            let expected: Vec<String> = log["entries"].as_array().unwrap().iter().map(|e| e.as_str().unwrap().to_string()).collect();
            assert_eq!(entries.join("\n----\n"), expected.join("\n----\n"), "{note}: log through {}", log["filter"]);
        }
    }
}

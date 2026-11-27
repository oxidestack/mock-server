//! `BinaryMessageFramer` and its protocols (`binaryMessageFraming`): a binary connection cut into the messages a client
//! sends, so that each is matched, forwarded and logged as one message however it was read. At most
//! `maxRequestBodySize` bytes are held; a connection that declares a longer message, or sends bytes its protocol does
//! not allow, is refused (closed, and the rest of what it sends dropped).

use bytes::{Bytes, BytesMut};

use crate::config::Config;

/// What one batch of bytes gave: the whole messages taken, in order, and the refusal that followed them, if any
/// (what the connection declared, as upstream's WARN words it).
#[derive(Debug, Default, PartialEq)]
pub struct Decoded {
    pub messages: Vec<Bytes>,
    pub refused: Option<String>,
}

#[derive(Debug)]
enum Protocol {
    /// `typed`: from the startup message on, a message is a type byte then an int32 length (itself included).
    Postgresql { typed: bool },
    /// `ssl_requested`: the last message taken was an SSLRequest, so a TLS handshake may follow it.
    Mysql { ssl_requested: bool },
    Redis,
    LengthPrefix { offset: usize, prefix_bytes: usize, little_endian: bool, includes_prefix: bool },
}

/// One connection's framer.
#[derive(Debug)]
pub struct Framer {
    protocol: Protocol,
    max: usize,
    held: BytesMut,
    refused: bool,
}

impl Framer {
    /// `BinaryMessageFramer.forConfiguration`: the framer `binaryMessageFraming` names, or `None` for RAW.
    pub fn for_config(config: &Config) -> Option<Framer> {
        let framing = config.property("binaryMessageFraming").map(|v| v.trim().to_uppercase()).unwrap_or_default();
        let protocol = match framing.as_str() {
            "POSTGRESQL" => Protocol::Postgresql { typed: false },
            "MYSQL" => Protocol::Mysql { ssl_requested: false },
            "REDIS" => Protocol::Redis,
            "LENGTH_PREFIX" => Protocol::LengthPrefix {
                offset: config.int_property("binaryMessageLengthPrefixOffset", 0).max(0) as usize,
                prefix_bytes: Some(config.int_property("binaryMessageLengthPrefixBytes", 4)).filter(|b| [1, 2, 4, 8].contains(b)).unwrap_or(4) as usize,
                little_endian: config.property("binaryMessageLengthPrefixByteOrder").is_some_and(|v| v.trim().eq_ignore_ascii_case("LITTLE_ENDIAN")),
                includes_prefix: config.bool_property("binaryMessageLengthIncludesPrefix", false),
            },
            _ => return None,
        };
        let max = config.hot_int(crate::config::Hot::MaxRequestBodySize, 10_485_760).clamp(1, i64::from(i32::MAX)) as usize;
        Some(Framer { protocol, max, held: BytesMut::new(), refused: false })
    }

    /// The protocol's name in the refusal's WARN.
    pub fn name(&self) -> &'static str {
        match self.protocol {
            Protocol::Postgresql { .. } => "PostgreSQL",
            Protocol::Mysql { .. } => "MySQL",
            Protocol::Redis => "Redis",
            Protocol::LengthPrefix { .. } => "length-prefix",
        }
    }

    /// True when no part of a message is held: what is read next starts a message.
    pub fn at_message_boundary(&self) -> bool {
        !self.refused && self.held.is_empty()
    }

    /// Whether a TLS handshake may begin with the next byte read: only at a message boundary, and only where the
    /// protocol lets one begin (MySQL: straight after an SSLRequest).
    pub fn tls_may_start_here(&self) -> bool {
        self.at_message_boundary()
            && match self.protocol {
                Protocol::Mysql { ssl_requested } => ssl_requested,
                _ => true,
            }
    }

    /// How many of `input`'s bytes, read in the clear, end a message after which a client may start a TLS handshake
    /// without waiting for a reply, when more bytes follow; otherwise 0. MySQL's SSLRequest is the one such message.
    pub fn bytes_before_tls_may_start(&self, input: &[u8]) -> usize {
        match self.protocol {
            Protocol::Mysql { .. } if self.at_message_boundary() && input.len() > MYSQL_SSL_REQUEST_BYTES && is_mysql_ssl_request(input) => MYSQL_SSL_REQUEST_BYTES,
            _ => 0,
        }
    }

    /// `decode`: the bytes read are added to those held, and every whole message is taken. After a refusal nothing
    /// more is taken.
    pub fn decode(&mut self, input: &[u8]) -> Decoded {
        let mut decoded = Decoded::default();
        if self.refused {
            return decoded;
        }
        self.held.extend_from_slice(input);
        while !self.held.is_empty() {
            let length = match self.message_bytes() {
                Err(declared) => return self.refuse(decoded, declared),
                Ok(None) if self.held.len() > self.max => {
                    let declared = format!("more than {} bytes (maxRequestBodySize) without the end of a message", self.max);
                    return self.refuse(decoded, declared);
                }
                Ok(None) => return decoded,
                Ok(Some(length)) => length,
            };
            if length > self.max as u64 {
                let declared = format!("a message of {length} bytes, over the limit of {} bytes (maxRequestBodySize)", self.max);
                return self.refuse(decoded, declared);
            }
            if (self.held.len() as u64) < length {
                return decoded;
            }
            let message = self.held.split_to(length as usize).freeze();
            self.message_taken(&message);
            decoded.messages.push(message);
        }
        decoded
    }

    fn refuse(&mut self, mut decoded: Decoded, declared: String) -> Decoded {
        self.refused = true;
        self.held.clear();
        decoded.refused = Some(declared);
        decoded
    }

    /// How many bytes the message that starts the held bytes has, `None` while they cannot say yet, or what makes the
    /// connection refused.
    fn message_bytes(&self) -> Result<Option<u64>, String> {
        let input = &self.held[..];
        match self.protocol {
            Protocol::Postgresql { typed: true } => {
                if input.len() < 5 {
                    return Ok(None);
                }
                let length = i32::from_be_bytes([input[1], input[2], input[3], input[4]]);
                if length < 4 {
                    return Err(format!("a length of {length} after type byte {}", input[0]));
                }
                Ok(Some(1 + length as u64))
            }
            Protocol::Postgresql { typed: false } => {
                if input.len() < 4 {
                    return Ok(None);
                }
                let length = i32::from_be_bytes([input[0], input[1], input[2], input[3]]);
                if length < 8 {
                    return Err(format!("a startup-phase length of {length}"));
                }
                Ok(Some(length as u64))
            }
            Protocol::Mysql { .. } => mysql_message_bytes(input, self.max),
            Protocol::Redis => redis_message_bytes(input, self.max),
            Protocol::LengthPrefix { offset, prefix_bytes, little_endian, includes_prefix } => {
                let header = offset + prefix_bytes;
                if input.len() < header {
                    return Ok(None);
                }
                let mut field = [0u8; 8];
                let bytes = &input[offset..header];
                if little_endian {
                    field[..prefix_bytes].copy_from_slice(bytes);
                } else {
                    field[8 - prefix_bytes..].copy_from_slice(bytes);
                }
                let length = if little_endian { u64::from_le_bytes(field) } else { u64::from_be_bytes(field) };
                // Java reads an 8-byte field as a signed long
                if length > i64::MAX as u64 {
                    return Err(format!("a length of {length} bytes, over the limit of {} bytes (maxRequestBodySize)", self.max));
                }
                if includes_prefix {
                    if length < header as u64 {
                        return Err(format!("a length of {length}, less than the {header} bytes before the body that it counts"));
                    }
                    return Ok(Some(length));
                }
                Ok(Some(if length > i64::MAX as u64 - header as u64 { i64::MAX as u64 } else { header as u64 + length }))
            }
        }
    }

    /// `messageTaken`: what a whole message tells about the next.
    fn message_taken(&mut self, message: &[u8]) {
        match &mut self.protocol {
            Protocol::Postgresql { typed } if !*typed => {
                let code = i32::from_be_bytes([message[4], message[5], message[6], message[7]]);
                *typed = ![POSTGRESQL_SSL_REQUEST_CODE, POSTGRESQL_GSSENC_REQUEST_CODE, POSTGRESQL_CANCEL_REQUEST_CODE].contains(&code);
            }
            Protocol::Mysql { ssl_requested } => *ssl_requested = message.len() == MYSQL_SSL_REQUEST_BYTES && is_mysql_ssl_request(message),
            _ => {}
        }
    }
}

const POSTGRESQL_SSL_REQUEST_CODE: i32 = 80_877_103;
const POSTGRESQL_GSSENC_REQUEST_CODE: i32 = 80_877_104;
const POSTGRESQL_CANCEL_REQUEST_CODE: i32 = 80_877_102;

const MYSQL_HEADER_BYTES: usize = 4;
const MYSQL_MAX_PACKET_PAYLOAD: u64 = 0xFF_FFFF;
const MYSQL_SSL_REQUEST_PAYLOAD: u32 = 32;
const MYSQL_CLIENT_SSL: u32 = 0x0000_0800;
const MYSQL_SSL_REQUEST_BYTES: usize = MYSQL_HEADER_BYTES + MYSQL_SSL_REQUEST_PAYLOAD as usize;

fn medium_le(bytes: &[u8]) -> u32 {
    u32::from(bytes[0]) | u32::from(bytes[1]) << 8 | u32::from(bytes[2]) << 16
}

/// An SSLRequest: a 32-byte payload, sequence id 1, with the CLIENT_SSL capability.
fn is_mysql_ssl_request(bytes: &[u8]) -> bool {
    bytes.len() >= MYSQL_HEADER_BYTES + 4
        && medium_le(bytes) == MYSQL_SSL_REQUEST_PAYLOAD
        && bytes[3] == 1
        && u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) & MYSQL_CLIENT_SSL != 0
}

/// `MysqlMessageFramer.messageBytes`: a packet is a 3-byte little-endian payload length, a sequence id, then the
/// payload; a payload of 0xFFFFFF bytes is continued by the next packet, and the packets up to a shorter one are one
/// message.
fn mysql_message_bytes(input: &[u8], max: usize) -> Result<Option<u64>, String> {
    let mut offset = 0usize;
    let mut previous_sequence: Option<u8> = None;
    while input.len() >= offset + MYSQL_HEADER_BYTES {
        let payload = u64::from(medium_le(&input[offset..]));
        let sequence = input[offset + 3];
        if let Some(previous) = previous_sequence
            && sequence != previous.wrapping_add(1)
        {
            return Err(format!("a continuation packet with sequence id {sequence} after sequence id {previous}"));
        }
        let packet_end = offset as u64 + MYSQL_HEADER_BYTES as u64 + payload;
        if payload < MYSQL_MAX_PACKET_PAYLOAD {
            return Ok(Some(packet_end));
        }
        if packet_end + MYSQL_HEADER_BYTES as u64 > max as u64 {
            return Err(format!("a message of more than {packet_end} bytes, over the limit of {max} bytes (maxRequestBodySize)"));
        }
        offset = packet_end as usize;
        previous_sequence = Some(sequence);
    }
    Ok(None)
}

const REDIS_MAX_DEPTH: usize = 64;
const REDIS_MAX_NUMBER_DIGITS: usize = 18;
// the shortest RESP value, a type byte then CRLF
const REDIS_MIN_VALUE_BYTES: u64 = 3;

fn is_redis_value_type(t: u8) -> bool {
    matches!(t, b'+' | b'-' | b':' | b'$' | b'*' | b'_' | b'#' | b',' | b'(' | b'!' | b'=' | b'%' | b'~' | b'>' | b'|')
}

/// A RESP length or count.
enum RedisNumber {
    Value(u64),
    /// RESP2's `-1`.
    Null,
}

/// `RedisMessageFramer.messageBytes`, parsed from the start of the held bytes each time (upstream keeps its place
/// between reads; the answer is the same): one complete top-level value with everything nested in it, or, when the
/// first byte names no RESP type, one inline command up to and including its line feed.
fn redis_message_bytes(input: &[u8], max: usize) -> Result<Option<u64>, String> {
    let mut parsed = 0usize;
    let mut started = false;
    let mut complete = false;
    let mut in_streamed_string = false;
    // the aggregates open around the next value: how many values each still expects (`None`: streamed), and
    // whether it is an attribute
    let mut open: Vec<(Option<u64>, bool)> = Vec::new();
    // a value ended: the aggregates it completes are closed; `true` once the top-level value is whole
    let value_complete = |open: &mut Vec<(Option<u64>, bool)>| -> bool {
        while let Some((remaining, attribute)) = open.last_mut() {
            match remaining {
                None => return false,
                Some(n) => {
                    *n -= 1;
                    if *n > 0 {
                        return false;
                    }
                }
            }
            let attribute = *attribute;
            open.pop();
            if attribute {
                // an attribute's map has ended: the value it describes follows, in the attribute's place
                return false;
            }
        }
        true
    };
    let number = |line: &[u8], null_allowed: bool| -> Result<RedisNumber, String> {
        if null_allowed && line == b"-1" {
            return Ok(RedisNumber::Null);
        }
        if line.is_empty() || line.len() > REDIS_MAX_NUMBER_DIGITS {
            return Err(format!("a length or count of {} characters", line.len()));
        }
        let mut value = 0u64;
        for digit in line {
            if !digit.is_ascii_digit() {
                return Err("a length or count that is not a non-negative number".to_string());
            }
            value = value * 10 + u64::from(digit - b'0');
        }
        Ok(RedisNumber::Value(value))
    };
    while !complete {
        let Some(line_end) = input[parsed..].iter().position(|b| *b == b'\n').map(|i| parsed + i) else { return Ok(None) };
        let kind = input[parsed];
        if !started && !in_streamed_string && !is_redis_value_type(kind) {
            // an inline command: its line is the message
            return Ok(Some(line_end as u64 + 1));
        }
        started = true;
        if line_end < parsed + 2 || input[line_end - 1] != b'\r' {
            return Err("a line not ended by CRLF".to_string());
        }
        let line = &input[parsed + 1..line_end - 1];
        let next = line_end + 1;
        // a bulk body of `length` bytes and its CRLF from `next`: `Ok(false)` while not all of it has arrived
        let bulk = |length: u64| -> Result<Option<usize>, String> {
            let end = next as u64 + length + 2;
            if end > max as u64 {
                return Err(format!("a bulk string of {length} bytes, so a message of at least {end} bytes, over the limit of {max} bytes (maxRequestBodySize)"));
            }
            if (input.len() as u64) < end {
                return Ok(None);
            }
            let end = end as usize;
            if input[end - 2] != b'\r' || input[end - 1] != b'\n' {
                return Err(format!("a bulk string of {length} bytes not followed by CRLF"));
            }
            Ok(Some(end))
        };
        if in_streamed_string {
            if kind != b';' {
                return Err(format!("type byte {kind} in a streamed string, not a ';' chunk"));
            }
            let RedisNumber::Value(chunk) = number(line, false)? else { unreachable!() };
            if chunk == 0 {
                in_streamed_string = false;
                parsed = next;
                complete = value_complete(&mut open);
            } else {
                match bulk(chunk)? {
                    Some(end) => parsed = end,
                    None => return Ok(None),
                }
            }
            continue;
        }
        match kind {
            b'$' | b'!' | b'=' => {
                if kind == b'$' && line == b"?" {
                    in_streamed_string = true;
                    parsed = next;
                    continue;
                }
                match number(line, kind == b'$')? {
                    RedisNumber::Null => {
                        parsed = next;
                        complete = value_complete(&mut open);
                    }
                    RedisNumber::Value(length) => match bulk(length)? {
                        Some(end) => {
                            parsed = end;
                            complete = value_complete(&mut open);
                        }
                        None => return Ok(None),
                    },
                }
            }
            b'*' | b'~' | b'>' | b'%' | b'|' => {
                let streamed = kind != b'|' && line == b"?";
                let count = if streamed { None } else { Some(number(line, kind == b'*')?) };
                if matches!(count, Some(RedisNumber::Null) | Some(RedisNumber::Value(0))) {
                    parsed = next;
                    if kind != b'|' {
                        complete = value_complete(&mut open);
                    }
                    continue;
                }
                let values = match count {
                    None => None,
                    Some(RedisNumber::Value(n)) if kind == b'%' || kind == b'|' => Some(2 * n),
                    Some(RedisNumber::Value(n)) => Some(n),
                    Some(RedisNumber::Null) => unreachable!(),
                };
                if let Some(values) = values {
                    let least = next as u64 + values * REDIS_MIN_VALUE_BYTES;
                    if least > max as u64 {
                        return Err(format!("an aggregate of {values} values, so a message of at least {least} bytes, over the limit of {max} bytes (maxRequestBodySize)"));
                    }
                }
                if open.len() == REDIS_MAX_DEPTH {
                    return Err(format!("values nested more than {REDIS_MAX_DEPTH} deep"));
                }
                open.push((values, kind == b'|'));
                parsed = next;
            }
            b'.' => {
                if !matches!(open.last(), Some((None, _))) {
                    return Err("an end marker '.' outside a streamed aggregate".to_string());
                }
                open.pop();
                parsed = next;
                complete = value_complete(&mut open);
            }
            _ => {
                if !is_redis_value_type(kind) {
                    return Err(format!("type byte {kind}, which names no RESP type, inside an aggregate"));
                }
                // a simple string, error, integer, null, boolean, double or big number: its line is the value
                parsed = next;
                complete = value_complete(&mut open);
            }
        }
    }
    Ok(Some(parsed as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framer(properties: &[(&str, &str)]) -> Framer {
        let mut config = Config::for_tests();
        for (name, value) in properties {
            config = config.with_property(name, value);
        }
        Framer::for_config(&config).expect("a framing")
    }

    fn mysql_packet(sequence: u8, payload: usize, fill: u8) -> Vec<u8> {
        let mut packet = vec![fill; 4 + payload];
        packet[..3].copy_from_slice(&(payload as u32).to_le_bytes()[..3]);
        packet[3] = sequence;
        packet
    }

    fn redis(arguments: &[&str]) -> Vec<u8> {
        let mut command = format!("*{}\r\n", arguments.len());
        for a in arguments {
            command.push_str(&format!("${}\r\n{a}\r\n", a.len()));
        }
        command.into_bytes()
    }

    #[test]
    fn raw_has_no_framer() {
        assert!(Framer::for_config(&Config::for_tests()).is_none());
        assert!(Framer::for_config(&Config::for_tests().with_property("binaryMessageFraming", "nonsense")).is_none());
    }

    #[test]
    fn should_take_a_mysql_packet_written_in_two_parts_as_one_message_and_packets_written_together_one_by_one() {
        let mut f = framer(&[("binaryMessageFraming", "mysql")]);
        let query = mysql_packet(0, 3000, b'q');
        assert!(f.decode(&query[..1500]).messages.is_empty());
        assert!(!f.at_message_boundary());
        assert_eq!(f.decode(&query[1500..]).messages, vec![Bytes::from(query.clone())]);
        let (a, b) = (mysql_packet(0, 40, b'p'), mysql_packet(0, 20, b'e'));
        assert_eq!(f.decode(&[a.clone(), b.clone()].concat()).messages, vec![Bytes::from(a), Bytes::from(b)]);
    }

    #[test]
    fn should_allow_tls_only_after_a_mysql_ssl_request() {
        let mut f = framer(&[("binaryMessageFraming", "MYSQL")]);
        assert!(!f.tls_may_start_here());
        let mut ssl_request = mysql_packet(1, 32, 0);
        ssl_request[4] = 0x0d;
        ssl_request[5] = 0xaa;
        assert_eq!(f.bytes_before_tls_may_start(&[ssl_request.clone(), vec![22, 3, 1]].concat()), 36);
        f.decode(&ssl_request);
        assert!(f.tls_may_start_here());
    }

    #[test]
    fn should_join_mysql_continuation_packets() {
        let mut f = framer(&[("binaryMessageFraming", "MYSQL"), ("maxRequestBodySize", "33554432")]);
        let first = mysql_packet(0, 0xFF_FFFF, b'a');
        let last = mysql_packet(1, 2, b'b');
        let decoded = f.decode(&[first.clone(), last.clone()].concat());
        assert_eq!(decoded.messages.len(), 1);
        assert_eq!(decoded.messages[0].len(), first.len() + last.len());
        let decoded = f.decode(&[mysql_packet(0, 0xFF_FFFF, b'a'), mysql_packet(3, 2, b'b')].concat());
        assert_eq!(decoded.refused.as_deref(), Some("a continuation packet with sequence id 3 after sequence id 0"));
    }

    #[test]
    fn should_take_redis_commands_one_by_one_and_inline_commands_by_their_line() {
        let mut f = framer(&[("binaryMessageFraming", "REDIS")]);
        let set = redis(&["SET", "key", &"v".repeat(3000)]);
        assert!(f.decode(&set[..1500]).messages.is_empty());
        assert_eq!(f.decode(&set[1500..]).messages, vec![Bytes::from(set)]);
        let (incr, get) = (redis(&["INCR", "counter"]), redis(&["GET", "counter"]));
        let decoded = f.decode(&[incr.clone(), get.clone(), b"PING\r\n".to_vec()].concat());
        assert_eq!(decoded.messages, vec![Bytes::from(incr), Bytes::from(get), Bytes::from_static(b"PING\r\n")]);
    }

    #[test]
    fn should_take_nested_resp3_values_whole() {
        let mut f = framer(&[("binaryMessageFraming", "REDIS")]);
        let value = b"%1\r\n+k\r\n*2\r\n:1\r\n$-1\r\n|1\r\n+a\r\n+b\r\n:2\r\n".to_vec();
        let decoded = f.decode(&value);
        assert_eq!(decoded.messages.len(), 2, "{decoded:?}");
        // an attribute is part of the value it describes
        assert_eq!(&decoded.messages[1][..], b"|1\r\n+a\r\n+b\r\n:2\r\n");
        let streamed = b"*?\r\n:1\r\n.\r\n$?\r\n;2\r\nab\r\n;0\r\n".to_vec();
        let decoded = f.decode(&streamed);
        assert_eq!(decoded.messages.len(), 2, "{decoded:?}");
        assert_eq!(&decoded.messages[1][..], b"$?\r\n;2\r\nab\r\n;0\r\n");
    }

    #[test]
    fn should_refuse_what_a_redis_client_may_not_send() {
        let mut f = framer(&[("binaryMessageFraming", "REDIS")]);
        assert_eq!(f.decode(b"*1\n").refused.as_deref(), Some("a line not ended by CRLF"));
        let mut f = framer(&[("binaryMessageFraming", "REDIS")]);
        assert_eq!(f.decode(b"*x\r\n").refused.as_deref(), Some("a length or count that is not a non-negative number"));
        let mut f = framer(&[("binaryMessageFraming", "REDIS"), ("maxRequestBodySize", "1024")]);
        assert_eq!(f.decode(b"*1\r\n$1019\r\n").refused.as_deref(), Some("a bulk string of 1019 bytes, so a message of at least 1032 bytes, over the limit of 1024 bytes (maxRequestBodySize)"));
        assert!(f.decode(b"PING\r\n").messages.is_empty(), "nothing is taken after a refusal");
    }

    #[test]
    fn should_take_length_prefixed_messages() {
        let mut f = framer(&[("binaryMessageFraming", "LENGTH_PREFIX"), ("binaryMessageLengthPrefixBytes", "2"), ("binaryMessageLengthPrefixByteOrder", "LITTLE_ENDIAN")]);
        let message = [&3000u16.to_le_bytes()[..], &[b'l'; 3000][..]].concat();
        assert!(f.decode(&message[..1501]).messages.is_empty());
        assert_eq!(f.decode(&message[1501..]).messages.len(), 1);
        let decoded = f.decode(&[0, 0, 1, 0, b'x']);
        assert_eq!(decoded.messages, vec![Bytes::from_static(&[0, 0]), Bytes::from_static(&[1, 0, b'x'])]);
        let mut f = framer(&[("binaryMessageFraming", "LENGTH_PREFIX"), ("binaryMessageLengthPrefixOffset", "1"), ("binaryMessageLengthIncludesPrefix", "true")]);
        assert_eq!(f.decode(&[9, 0, 0, 0, 6, b'a']).messages, vec![Bytes::from_static(&[9, 0, 0, 0, 6, b'a'])]);
        assert_eq!(f.decode(&[9, 0, 0, 0, 4]).refused.as_deref(), Some("a length of 4, less than the 5 bytes before the body that it counts"));
    }

    #[test]
    fn should_refuse_a_declared_length_over_max_request_body_size() {
        let cases: [(&str, Vec<u8>, &str); 3] = [
            ("MYSQL", mysql_packet(0, 1021, b'q')[..4].to_vec(), "a message of 1025 bytes, over the limit of 1024 bytes (maxRequestBodySize)"),
            ("LENGTH_PREFIX", 1023u16.to_le_bytes().to_vec(), "a message of 1025 bytes, over the limit of 1024 bytes (maxRequestBodySize)"),
            ("POSTGRESQL", vec![0, 0, 4, 1], "a message of 1025 bytes, over the limit of 1024 bytes (maxRequestBodySize)"),
        ];
        for (framing, header, declared) in cases {
            let mut f = framer(&[("binaryMessageFraming", framing), ("maxRequestBodySize", "1024"), ("binaryMessageLengthPrefixBytes", "2"), ("binaryMessageLengthPrefixByteOrder", "LITTLE_ENDIAN")]);
            assert_eq!(f.decode(&header).refused.as_deref(), Some(declared), "{framing}");
        }
    }

    #[test]
    fn should_type_postgresql_messages_from_the_startup_message_on() {
        let mut f = framer(&[("binaryMessageFraming", "POSTGRESQL")]);
        let ssl_request = [0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f];
        assert_eq!(f.decode(&ssl_request).messages.len(), 1);
        let startup = [&[0u8, 0, 0, 23, 0, 3, 0, 0][..], b"user\0postgres\0\0"].concat();
        assert_eq!(f.decode(&startup).messages.len(), 1);
        let sync = [b'S', 0, 0, 0, 4];
        let query = [&[b'Q', 0, 0, 0, 13][..], b"SELECT 1\0"].concat();
        let decoded = f.decode(&[&query[..], &sync[..]].concat());
        assert_eq!(decoded.messages, vec![Bytes::from(query), Bytes::from_static(&[b'S', 0, 0, 0, 4])]);
        assert_eq!(f.decode(&[b'X', 0, 0, 0, 3]).refused.as_deref(), Some("a length of 3 after type byte 88"));
    }
}

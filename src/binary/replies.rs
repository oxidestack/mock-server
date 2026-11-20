//! `PostgresqlReplies` and `UpstreamReply`: what a relay with `binaryMessageFraming` POSTGRESQL does with the upstream's
//! reply to each message it forwards. The tracker follows what a PostgreSQL server (frontend/backend protocol version
//! 3) sends on a relayed connection, to tell which forwarded message each byte answers and where each reply ends, so a
//! reply can be dropped or replaced. Nothing is held: each read is handed on in pieces, each piece with the reply it
//! belongs to.
//!
//! A reply ends where the protocol says the server is waiting for the client again, not at a message: after one byte
//! for SSLRequest and GSSENCRequest; at ReadyForQuery for a simple Query, a FunctionCall and a Sync; for the startup
//! message and a password or SASL message, at ReadyForQuery, an ErrorResponse, or an authentication request the client
//! must answer. Parse, Bind, Describe, Execute, Close and Flush have no reply of their own: those up to a Sync share
//! the Sync's (or a Query's or FunctionCall's sent before any Sync). CancelRequest, CopyData, CopyDone, CopyFail and
//! Terminate get none, so what follows a CopyData belongs to the Query that started the copy. Backend messages that
//! answer no message (a notice between replies) are handed on with no reply. One per relayed connection.

use std::collections::VecDeque;
use std::ops::Range;
use std::time::Duration;

use bytes::Bytes;
use tokio::time::Instant;

const SSL_REQUEST_CODE: u32 = 80_877_103;
const GSSENC_REQUEST_CODE: u32 = 80_877_104;
const CANCEL_REQUEST_CODE: u32 = 80_877_102;
const TYPED_HEADER_BYTES: usize = 5;
const AUTHENTICATION_HEADER_BYTES: usize = 9;

/// What a relay does with the upstream's reply to one message it forwards: relays it to the client (the default),
/// drops it, or drops it and writes other bytes to the client in its place once it has ended.
#[derive(Clone, Debug, Default)]
pub(crate) struct UpstreamReply {
    dropped: bool,
    replacement: Option<Bytes>,
    delay: Duration,
}

impl UpstreamReply {
    pub(crate) const RELAY: UpstreamReply = UpstreamReply { dropped: false, replacement: None, delay: Duration::ZERO };

    /// `UpstreamReply.drop()`.
    pub(crate) fn dropped() -> UpstreamReply {
        UpstreamReply { dropped: true, replacement: None, delay: Duration::ZERO }
    }

    /// `replaceWith`: `replacement` is written in place of the reply (empty writes nothing, so the reply is only
    /// dropped), not before `delay` after its message was read.
    pub(crate) fn replace_with(replacement: Bytes, delay: Duration) -> UpstreamReply {
        UpstreamReply { dropped: true, replacement: (!replacement.is_empty()).then_some(replacement), delay }
    }

    pub(crate) fn relayed(&self) -> bool {
        !self.dropped
    }

    pub(crate) fn replacement(&self) -> Option<&Bytes> {
        self.replacement.as_ref()
    }

    pub(crate) fn delay(&self) -> Duration {
        self.delay
    }

    /// One reply standing for several messages' (PostgreSQL's extended-query messages up to their Sync): dropped if
    /// any is, and with the replacements of each in message order.
    fn and(&self, next: &UpstreamReply) -> UpstreamReply {
        if !next.dropped {
            return self.clone();
        }
        if !self.dropped {
            return next.clone();
        }
        let replacement = match (&self.replacement, &next.replacement) {
            (Some(first), Some(second)) => Some([first.as_ref(), second.as_ref()].concat().into()),
            (first, second) => first.clone().or_else(|| second.clone()),
        };
        UpstreamReply { dropped: true, replacement, delay: self.delay.max(next.delay) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Ends {
    /// one byte: the answer to SSLRequest or GSSENCRequest
    OneByte,
    /// at ReadyForQuery
    ReadyForQuery,
    /// at ReadyForQuery, an ErrorResponse, or an authentication request the client must answer
    Authentication,
    /// no reply: ends as soon as the replies before it have
    NoReply,
}

/// Where what is read goes.
pub(crate) trait Output {
    /// Bytes of one read that belong to `reply`, or, when it is `None`, answer no tracked message.
    fn bytes(&mut self, reply: Option<&Reply>, read: &Bytes, range: Range<usize>);

    /// A reply to be dropped or replaced has ended; it is no longer pending.
    fn ended(&mut self, reply: Reply);
}

/// The upstream's reply to one or more forwarded messages, and what to do with it.
#[derive(Debug)]
pub(crate) struct Reply {
    id: u64,
    ends: Ends,
    handling: UpstreamReply,
    request: Option<Bytes>,
    correlation_id: String,
    due: Instant,
    /// replies relayed as they are, back to back, are one entry
    count: u32,
    /// extended-query messages not yet followed by their Sync
    open_batch: bool,
}

impl Reply {
    pub(crate) fn handling(&self) -> &UpstreamReply {
        &self.handling
    }

    /// The message whose reply this is; `None` for a relayed one.
    pub(crate) fn request(&self) -> &[u8] {
        self.request.as_deref().unwrap_or_default()
    }

    pub(crate) fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// Its replacement is not written before this.
    pub(crate) fn due(&self) -> Instant {
        self.due
    }

    fn join(&mut self, next: &UpstreamReply, next_request: &Bytes, next_correlation_id: &str, next_due: Instant) {
        if !next.relayed() && self.handling.relayed() {
            self.request = Some(next_request.clone());
            self.correlation_id = next_correlation_id.to_string();
        }
        self.handling = self.handling.and(next);
        self.due = self.due.max(next_due);
    }
}

/// One relayed connection's tracker.
#[derive(Default)]
pub(crate) struct PostgresqlReplies {
    pending: VecDeque<Reply>,
    next_id: u64,
    header: [u8; AUTHENTICATION_HEADER_BYTES],
    header_bytes: usize,
    body_left: i64,
    in_message: bool,
    owner: Option<u64>,
    not_relayed: usize,
    lost: bool,
    /// the read being handed on, and the run of it not yet handed on (its owner, from, to)
    current: Option<Bytes>,
    piece: Option<(Option<u64>, usize, usize)>,
}

impl PostgresqlReplies {
    /// Records a message just forwarded, in the order messages are written upstream. A message without a reply that is
    /// to be replaced ends, and so has its replacement written, once the replies before it have.
    pub(crate) fn forwarded(&mut self, message: &Bytes, handling: UpstreamReply, correlation_id: &str, due: Instant, output: &mut dyn Output) {
        if self.lost || message.is_empty() {
            return;
        }
        let open_batch = self.pending.back().is_some_and(|tail| tail.open_batch);
        match message[0] {
            0 => {
                let code = if message.len() >= 8 { int_at(message, 4) } else { 0 };
                match code {
                    SSL_REQUEST_CODE | GSSENC_REQUEST_CODE => self.add(Ends::OneByte, handling, message, correlation_id, due, false),
                    CANCEL_REQUEST_CODE => self.add_without_reply(handling, message, correlation_id, due, output),
                    _ => self.add(Ends::Authentication, handling, message, correlation_id, due, false),
                }
            }
            b'p' => self.add(Ends::Authentication, handling, message, correlation_id, due, false),
            b'P' | b'B' | b'D' | b'E' | b'C' | b'H' => match open_batch {
                true => self.join_open_batch(handling, message, correlation_id, due),
                false => self.add(Ends::ReadyForQuery, handling, message, correlation_id, due, true),
            },
            // a simple Query or FunctionCall after extended-query messages without a Sync shares their ReadyForQuery
            b'S' | b'Q' | b'F' => match open_batch {
                true => {
                    self.join_open_batch(handling, message, correlation_id, due);
                    self.pending.back_mut().expect("the batch").open_batch = false;
                }
                false => self.add(Ends::ReadyForQuery, handling, message, correlation_id, due, false),
            },
            _ => self.add_without_reply(handling, message, correlation_id, due, output),
        }
    }

    /// Hands on one read from the upstream, in order, in pieces: each the longest run of bytes that belongs to one
    /// reply, or to none.
    pub(crate) fn read(&mut self, read: &Bytes, output: &mut dyn Output) {
        self.current = Some(read.clone());
        let end = read.len();
        let mut i = 0;
        while i < end {
            if self.lost {
                self.piece(None, i, end, output);
                break;
            }
            if !self.in_message {
                self.end_replies_without_reply(output);
                if let Some(head) = self.pending.front()
                    && head.ends == Ends::OneByte
                {
                    let id = head.id;
                    self.piece(Some(id), i, i + 1, output);
                    i += 1;
                    self.end_head(output);
                    continue;
                }
                self.in_message = true;
                self.owner = self.pending.front().map(|head| head.id);
                self.header_bytes = 0;
                self.body_left = 0;
            }
            let mut start = i;
            let mut complete = false;
            while i < end && !complete && !self.lost {
                if self.header_bytes < TYPED_HEADER_BYTES {
                    self.header[self.header_bytes] = read[i];
                    self.header_bytes += 1;
                    i += 1;
                    if self.header_bytes == TYPED_HEADER_BYTES {
                        let length = int_at(&self.header, 1) as i32;
                        if length < 4 {
                            self.piece(self.owner, start, i, output);
                            start = i;
                            self.lose(output);
                        }
                        self.body_left = i64::from(length) - 4;
                    }
                } else if self.header[0] == b'R' && self.header_bytes < AUTHENTICATION_HEADER_BYTES && self.body_left > 0 {
                    // an authentication request's code says whether the client must answer it
                    self.header[self.header_bytes] = read[i];
                    self.header_bytes += 1;
                    i += 1;
                    self.body_left -= 1;
                } else {
                    let skipped = self.body_left.min((end - i) as i64);
                    i += skipped as usize;
                    self.body_left -= skipped;
                }
                complete = !self.lost && self.header_bytes >= TYPED_HEADER_BYTES && self.body_left == 0;
            }
            if self.lost {
                continue;
            }
            self.piece(self.owner, start, i, output);
            if complete {
                self.in_message = false;
                if let Some(answered) = self.owner.take()
                    && let Some(ends) = self.pending.iter().find(|reply| reply.id == answered).map(|reply| reply.ends)
                    && self.ends_reply(ends)
                {
                    self.end_head(output);
                }
            }
        }
        if !self.in_message {
            self.end_replies_without_reply(output);
        }
        self.flush_piece(output);
        self.current = None;
    }

    /// How many replies pending are to be dropped or replaced.
    pub(crate) fn not_relayed(&self) -> usize {
        self.not_relayed
    }

    /// Whether a malformed backend message stopped the tracking: everything is relayed from then on.
    pub(crate) fn lost(&self) -> bool {
        self.lost
    }

    fn piece(&mut self, owner: Option<u64>, from: usize, to: usize, output: &mut dyn Output) {
        if from == to {
            return;
        }
        if let Some((piece_owner, _, piece_to)) = self.piece.as_mut()
            && *piece_owner == owner
            && *piece_to == from
        {
            *piece_to = to;
            return;
        }
        self.flush_piece(output);
        self.piece = Some((owner, from, to));
    }

    fn flush_piece(&mut self, output: &mut dyn Output) {
        if let Some((owner, from, to)) = self.piece.take()
            && to > from
            && let Some(read) = self.current.as_ref()
        {
            let reply = owner.and_then(|id| self.pending.iter().find(|reply| reply.id == id));
            output.bytes(reply, read, from..to);
        }
    }

    fn ends_reply(&self, ends: Ends) -> bool {
        let kind = self.header[0];
        match ends {
            Ends::ReadyForQuery => kind == b'Z',
            Ends::Authentication => kind == b'Z' || kind == b'E' || kind == b'R' && self.header_bytes == AUTHENTICATION_HEADER_BYTES && asks_the_client(int_at(&self.header, 5)),
            _ => false,
        }
    }

    fn new_reply(&mut self, ends: Ends, handling: UpstreamReply, message: &Bytes, correlation_id: &str, due: Instant, open_batch: bool) -> Reply {
        self.next_id += 1;
        let request = (!handling.relayed()).then(|| message.clone());
        Reply { id: self.next_id, ends, handling, request, correlation_id: correlation_id.to_string(), due, count: 1, open_batch }
    }

    fn add(&mut self, ends: Ends, handling: UpstreamReply, message: &Bytes, correlation_id: &str, due: Instant, open_batch: bool) {
        if let Some(tail) = self.pending.back_mut()
            && handling.relayed()
            && tail.ends == ends
            && ends == Ends::ReadyForQuery
            && tail.handling.relayed()
            && !tail.open_batch
        {
            tail.count += 1;
            tail.open_batch = open_batch;
            return;
        }
        if !handling.relayed() {
            self.not_relayed += 1;
        }
        let reply = self.new_reply(ends, handling, message, correlation_id, due, open_batch);
        self.pending.push_back(reply);
    }

    /// Joins a message to the open batch at the tail; the batch stays the tail.
    fn join_open_batch(&mut self, handling: UpstreamReply, message: &Bytes, correlation_id: &str, due: Instant) {
        let tail = self.pending.back_mut().expect("an open batch");
        if handling.relayed() || !tail.handling.relayed() {
            if !handling.relayed() {
                tail.join(&handling, message, correlation_id, due);
            }
            return;
        }
        if tail.count == 1 {
            tail.join(&handling, message, correlation_id, due);
            self.not_relayed += 1;
            return;
        }
        // the batch was counted with relayed replies before it: it becomes an entry of its own
        tail.count -= 1;
        tail.open_batch = false;
        let batch = self.new_reply(Ends::ReadyForQuery, handling, message, correlation_id, due, true);
        self.pending.push_back(batch);
        self.not_relayed += 1;
    }

    fn add_without_reply(&mut self, handling: UpstreamReply, message: &Bytes, correlation_id: &str, due: Instant, output: &mut dyn Output) {
        if handling.replacement().is_none() {
            // nothing to drop and nothing to write
            return;
        }
        let reply = self.new_reply(Ends::NoReply, handling, message, correlation_id, due, false);
        self.pending.push_back(reply);
        self.not_relayed += 1;
        if !self.in_message {
            self.end_replies_without_reply(output);
        }
    }

    fn end_replies_without_reply(&mut self, output: &mut dyn Output) {
        while self.pending.front().is_some_and(|head| head.ends == Ends::NoReply) {
            self.end_head(output);
        }
    }

    /// `end(reply)`: the reply ended is always the one at the head.
    fn end_head(&mut self, output: &mut dyn Output) {
        let head = self.pending.front_mut().expect("a pending reply");
        head.count -= 1;
        if head.count > 0 {
            return;
        }
        // the bytes up to the end go first
        self.flush_piece(output);
        let reply = self.pending.pop_front().expect("a pending reply");
        if !reply.handling.relayed() {
            self.not_relayed -= 1;
            output.ended(reply);
        }
    }

    fn lose(&mut self, output: &mut dyn Output) {
        // the piece before the malformed length still names the reply it belonged to
        self.flush_piece(output);
        self.lost = true;
        self.in_message = false;
        self.owner = None;
        self.pending.clear();
        self.not_relayed = 0;
    }
}

/// Kerberos V5, cleartext, MD5, GSS, GSS continue, SSPI, SASL and SASL continue wait for the client; OK and SASL final
/// do not.
fn asks_the_client(authentication_code: u32) -> bool {
    matches!(authentication_code, 2 | 3 | 5 | 7 | 8 | 9 | 10 | 11)
}

fn int_at(bytes: &[u8], index: usize) -> u32 {
    u32::from_be_bytes([bytes[index], bytes[index + 1], bytes[index + 2], bytes[index + 3]])
}

/// `PostgresqlRepliesTest`: which forwarded message each byte a PostgreSQL server sends belongs to, and where each
/// reply ends, however the server's bytes are split into reads.
#[cfg(test)]
mod tests {
    use super::*;

    const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f];
    const CANCEL_REQUEST: [u8; 16] = [0, 0, 0, 16, 4, 0xd2, 0x16, 0x2e, 0, 0, 0, 1, 0, 0, 0, 2];
    const STARTUP: [u8; 23] = [0, 0, 0, 23, 0, 3, 0, 0, b'u', b's', b'e', b'r', 0, b'p', b'o', b's', b't', b'g', b'r', b'e', b's', 0, 0];

    #[derive(Default)]
    struct Events(Vec<String>);

    impl Output for Events {
        fn bytes(&mut self, reply: Option<&Reply>, read: &Bytes, range: Range<usize>) {
            let to = match reply {
                None => "none".to_string(),
                Some(reply) if reply.handling().relayed() => "relay".to_string(),
                Some(reply) => format!("drop {}", reply.correlation_id()),
            };
            self.0.push(format!("{to} {}", hex(&[&read[range]])));
        }

        fn ended(&mut self, reply: Reply) {
            let with = reply.handling().replacement().map(|r| format!(" with {}", String::from_utf8_lossy(r))).unwrap_or_default();
            self.0.push(format!("end {}{with}", reply.correlation_id()));
        }
    }

    #[derive(Default)]
    struct Harness {
        replies: PostgresqlReplies,
        events: Events,
    }

    impl Harness {
        fn forwarded(&mut self, message: &[u8], name: &str, handling: UpstreamReply) {
            self.replies.forwarded(&Bytes::copy_from_slice(message), handling, name, Instant::now(), &mut self.events);
        }

        fn read(&mut self, parts: &[&[u8]]) {
            self.replies.read(&Bytes::from(parts.concat()), &mut self.events);
        }

        fn read_byte_by_byte(&mut self, parts: &[&[u8]]) {
            for b in parts.concat() {
                self.read(&[&[b]]);
            }
        }

        fn events(&self) -> Vec<&str> {
            self.events.0.iter().map(String::as_str).collect()
        }
    }

    fn typed(kind: u8, body: &str) -> Vec<u8> {
        let mut message = vec![kind];
        message.extend_from_slice(&(4 + body.len() as u32).to_be_bytes());
        message.extend_from_slice(body.as_bytes());
        message
    }

    fn ready() -> Vec<u8> {
        typed(b'Z', "I")
    }

    fn authentication(code: u32) -> Vec<u8> {
        let mut message = vec![b'R', 0, 0, 0, 8];
        message.extend_from_slice(&code.to_be_bytes());
        message
    }

    fn hex(parts: &[&[u8]]) -> String {
        parts.concat().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn replace(bytes: &str) -> UpstreamReply {
        UpstreamReply::replace_with(Bytes::copy_from_slice(bytes.as_bytes()), Duration::ZERO)
    }

    #[test]
    fn should_drop_a_query_reply_up_to_its_ready_for_query_across_reads() {
        let mut h = Harness::default();
        let rows = [typed(b'T', "row description"), typed(b'D', "row")].concat();
        let complete = typed(b'C', "SELECT 1");
        h.forwarded(&typed(b'Q', "SELECT 1"), "q", UpstreamReply::dropped());

        h.read(&[&rows]);
        h.read(&[&complete, &ready(), &typed(b'N', "notice")]);

        assert_eq!(h.events(), [format!("drop q {}", hex(&[&rows])), format!("drop q {}", hex(&[&complete, &ready()])), "end q".into(), format!("none {}", hex(&[&typed(b'N', "notice")]))]);
        assert_eq!(h.replies.not_relayed(), 0);
    }

    #[test]
    fn should_follow_messages_split_at_every_byte() {
        let mut h = Harness::default();
        let reply = [typed(b'C', "SELECT 1"), ready()].concat();
        h.forwarded(&typed(b'Q', "SELECT 1"), "q", replace("x"));

        h.read_byte_by_byte(&[&reply, &ready()]);

        assert_eq!(h.events()[reply.len()], "end q with x");
        assert!(h.events()[reply.len() + 1..].iter().all(|event| event.starts_with("none ")), "the ReadyForQuery after it answers nothing tracked");
    }

    #[test]
    fn should_give_each_pipelined_query_its_own_reply() {
        let mut h = Harness::default();
        h.forwarded(&typed(b'Q', "one"), "one", UpstreamReply::RELAY);
        h.forwarded(&typed(b'Q', "two"), "two", UpstreamReply::dropped());
        h.forwarded(&typed(b'Q', "three"), "three", UpstreamReply::RELAY);
        let first = [typed(b'C', "1"), ready()].concat();
        let second = [typed(b'C', "2"), ready()].concat();
        let third = [typed(b'C', "3"), ready()].concat();

        h.read(&[&first, &second, &third]);

        assert_eq!(h.events(), [format!("relay {}", hex(&[&first])), format!("drop two {}", hex(&[&second])), "end two".into(), format!("relay {}", hex(&[&third]))]);
    }

    #[test]
    fn should_share_one_reply_across_extended_query_messages_up_to_their_sync() {
        let mut h = Harness::default();
        h.forwarded(&typed(b'P', "parse"), "parse", replace("canned"));
        h.forwarded(&typed(b'B', "bind"), "bind", UpstreamReply::RELAY);
        h.forwarded(&typed(b'E', "execute"), "execute", UpstreamReply::RELAY);
        h.forwarded(&typed(b'S', ""), "sync", UpstreamReply::RELAY);
        h.forwarded(&typed(b'Q', "after"), "after", UpstreamReply::RELAY);
        let batch = [typed(b'1', ""), typed(b'2', ""), typed(b'D', "row"), typed(b'C', "SELECT 1"), ready()].concat();
        let after = [typed(b'C', "after"), ready()].concat();

        h.read(&[&batch, &after]);

        assert_eq!(h.events(), [format!("drop parse {}", hex(&[&batch])), "end parse with canned".into(), format!("relay {}", hex(&[&after]))]);
    }

    #[test]
    fn should_split_a_batch_counted_with_relayed_replies_when_a_later_message_of_it_is_replaced() {
        let mut h = Harness::default();
        h.forwarded(&typed(b'Q', "before"), "before", UpstreamReply::RELAY);
        h.forwarded(&typed(b'P', "parse"), "parse", UpstreamReply::RELAY);
        h.forwarded(&typed(b'B', "bind"), "bind", UpstreamReply::dropped());
        h.forwarded(&typed(b'S', ""), "sync", UpstreamReply::RELAY);
        let before = [typed(b'C', "before"), ready()].concat();
        let batch = [typed(b'1', ""), typed(b'2', ""), ready()].concat();

        h.read(&[&before, &batch]);

        assert_eq!(h.events(), [format!("relay {}", hex(&[&before])), format!("drop bind {}", hex(&[&batch])), "end bind".into()]);
    }

    #[test]
    fn should_join_replacements_of_one_batch_in_message_order() {
        let mut h = Harness::default();
        h.forwarded(&typed(b'P', "parse"), "parse", replace("a"));
        h.forwarded(&typed(b'E', "execute"), "execute", replace("b"));
        h.forwarded(&typed(b'S', ""), "sync", UpstreamReply::RELAY);

        h.read(&[&typed(b'1', ""), &ready()]);

        assert_eq!(*h.events().last().unwrap(), "end parse with ab");
    }

    #[test]
    fn should_give_a_query_sent_before_any_sync_the_batch_reply() {
        let mut h = Harness::default();
        h.forwarded(&typed(b'P', "parse"), "parse", UpstreamReply::RELAY);
        h.forwarded(&typed(b'Q', "query"), "query", UpstreamReply::dropped());
        h.forwarded(&typed(b'Q', "next"), "next", UpstreamReply::RELAY);
        let shared = [typed(b'1', ""), typed(b'C', "query"), ready()].concat();
        let next = [typed(b'C', "next"), ready()].concat();

        h.read(&[&shared, &next]);

        assert_eq!(h.events(), [format!("drop query {}", hex(&[&shared])), "end query".into(), format!("relay {}", hex(&[&next]))]);
    }

    #[test]
    fn should_take_one_byte_as_the_answer_to_an_ssl_request() {
        let mut h = Harness::default();
        h.forwarded(&SSL_REQUEST, "ssl", replace("N"));
        h.forwarded(&STARTUP, "startup", UpstreamReply::RELAY);
        let startup_reply = [authentication(0), typed(b'S', "server_version\u{0}17\u{0}"), ready()].concat();

        h.read(&[b"S", &startup_reply]);

        assert_eq!(h.events(), ["drop ssl 53".to_string(), "end ssl with N".into(), format!("relay {}", hex(&[&startup_reply]))]);
    }

    #[test]
    fn should_end_an_authentication_reply_where_the_server_asks_the_client_even_with_its_code_split_across_reads() {
        let mut h = Harness::default();
        h.forwarded(&STARTUP, "startup", UpstreamReply::dropped());
        let mut sasl = [authentication(10), b"SCRAM-SHA-256\0\0".to_vec()].concat();
        sasl[4] = (sasl.len() - 1) as u8;

        h.read(&[&sasl[..7]]);
        h.read(&[&sasl[7..], &typed(b'N', "unprompted")]);

        assert_eq!(h.events()[2], "end startup");
        assert_eq!(h.events()[3], format!("none {}", hex(&[&typed(b'N', "unprompted")])));
    }

    #[test]
    fn should_carry_an_authentication_reply_past_authentication_ok_and_sasl_final_to_ready_for_query() {
        let mut h = Harness::default();
        h.forwarded(&typed(b'p', "sasl response"), "password", UpstreamReply::dropped());
        let reply = [authentication(12), authentication(0), typed(b'K', "12345678"), ready()].concat();

        h.read(&[&reply]);

        assert_eq!(h.events(), [format!("drop password {}", hex(&[&reply])), "end password".into()]);
    }

    #[test]
    fn should_end_an_authentication_reply_at_an_error_response() {
        let mut h = Harness::default();
        h.forwarded(&typed(b'p', "wrong password"), "password", UpstreamReply::dropped());

        h.read(&[&typed(b'E', "SFATAL"), &typed(b'N', "after")]);

        assert_eq!(h.events(), [format!("drop password {}", hex(&[&typed(b'E', "SFATAL")])), "end password".into(), format!("none {}", hex(&[&typed(b'N', "after")]))]);
    }

    #[test]
    fn should_leave_what_a_copy_brings_with_the_query_that_started_it() {
        let mut h = Harness::default();
        h.forwarded(&typed(b'Q', "COPY t FROM STDIN"), "copy", UpstreamReply::dropped());
        let copy_in = typed(b'G', "\u{0}\u{0}\u{0}");
        h.read(&[&copy_in]);
        h.forwarded(&typed(b'd', "1\n"), "data", UpstreamReply::RELAY);
        h.forwarded(&typed(b'c', ""), "done", UpstreamReply::RELAY);
        let complete = [typed(b'C', "COPY 1"), ready()].concat();

        h.read(&[&complete]);

        assert_eq!(h.events(), [format!("drop copy {}", hex(&[&copy_in])), format!("drop copy {}", hex(&[&complete])), "end copy".into()]);
    }

    #[test]
    fn should_end_a_replaced_message_without_a_reply_once_the_replies_before_it_have() {
        let mut h = Harness::default();
        h.forwarded(&typed(b'Q', "first"), "first", UpstreamReply::RELAY);
        h.forwarded(&CANCEL_REQUEST, "cancel", replace("x"));
        assert!(h.events().is_empty(), "waits for the reply before it");

        let first = [typed(b'C', "first"), ready()].concat();
        h.read(&[&first]);

        assert_eq!(h.events(), [format!("relay {}", hex(&[&first])), "end cancel with x".into()]);
    }

    #[test]
    fn should_end_a_replaced_message_without_a_reply_at_once_when_nothing_is_pending() {
        let mut h = Harness::default();
        h.forwarded(&typed(b'd', "data"), "data", replace("x"));

        assert_eq!(h.events(), ["end data with x"]);
    }

    #[test]
    fn should_not_end_a_replaced_message_without_a_reply_in_the_middle_of_an_unprompted_message() {
        let mut h = Harness::default();
        let notice = typed(b'N', "a notice");
        h.read(&[&notice[..4]]);
        h.forwarded(&typed(b'd', "data"), "data", replace("x"));
        assert_eq!(h.events(), [format!("none {}", hex(&[&notice[..4]]))]);

        h.read(&[&notice[4..]]);

        assert_eq!(h.events(), [format!("none {}", hex(&[&notice[..4]])), format!("none {}", hex(&[&notice[4..]])), "end data with x".into()]);
    }

    #[test]
    fn should_not_track_a_message_without_a_reply_that_is_only_dropped() {
        let mut h = Harness::default();
        h.forwarded(&typed(b'X', ""), "terminate", UpstreamReply::dropped());

        assert_eq!(h.replies.not_relayed(), 0);
        assert!(h.events().is_empty());
    }

    #[test]
    fn should_relay_everything_once_a_message_length_is_malformed() {
        let mut h = Harness::default();
        h.forwarded(&typed(b'Q', "one"), "one", UpstreamReply::dropped());
        h.forwarded(&typed(b'Q', "two"), "two", UpstreamReply::dropped());
        let malformed = [b'C', 0, 0, 0, 2];

        h.read(&[&malformed, &ready()]);
        h.forwarded(&typed(b'Q', "three"), "three", UpstreamReply::dropped());
        h.read(&[&ready()]);

        assert!(h.replies.lost());
        assert_eq!(h.replies.not_relayed(), 0);
        assert_eq!(h.events(), [format!("drop one {}", hex(&[&malformed])), format!("none {}", hex(&[&ready()])), format!("none {}", hex(&[&ready()]))]);
    }

    #[test]
    fn should_count_the_replies_to_be_dropped_or_replaced() {
        let mut h = Harness::default();
        h.forwarded(&typed(b'Q', "one"), "one", UpstreamReply::dropped());
        h.forwarded(&typed(b'Q', "two"), "two", UpstreamReply::RELAY);
        h.forwarded(&typed(b'Q', "three"), "three", replace("x"));
        assert_eq!(h.replies.not_relayed(), 2);

        h.read(&[&ready(), &ready()]);

        assert_eq!(h.replies.not_relayed(), 1);
    }
}

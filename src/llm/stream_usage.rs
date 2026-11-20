//! `LlmStreamUsageScanner`: reads the token usage out of an LLM response as its bytes pass, without holding the
//! response. It follows the stream's framing (Server-Sent Events, newline-delimited or concatenated JSON, AWS event
//! stream) and skims the JSON inside, keeping only the raw value of a few named fields near the top of each document:
//! the usage object, the model and the stop reason.
//!
//! Bounded whatever the stream sends: one captured value of at most [`MAX_VALUE_BYTES`] (a larger one is dropped), a
//! merged usage of at most [`MAX_USAGE_FIELDS`] fields, each a count or an object of at most
//! [`MAX_USAGE_DETAIL_FIELDS`] counts, under names of at most [`MAX_USAGE_NAME_CHARS`] characters, plus Bedrock's
//! invocation metrics. [`Scanner::accept`] never fails.

use serde_json::{Map, Value};

/// The most bytes kept of one captured value; a larger value is dropped, not truncated.
pub const MAX_VALUE_BYTES: usize = 8 * 1024;
const MAX_NAME_BYTES: usize = 32;
/// The most fields kept in the merged usage; a known field is replaced, a further new one is refused.
pub const MAX_USAGE_FIELDS: usize = 32;
/// The most whole numbers kept of one object inside the usage, such as a token details breakdown.
pub const MAX_USAGE_DETAIL_FIELDS: usize = 16;
/// The longest field name kept in the merged usage.
pub const MAX_USAGE_NAME_CHARS: usize = 64;
/// The longest model name or stop reason kept; a longer one is ignored.
pub const MAX_TEXT_CHARS: usize = 128;
// a count sent as text is parsed only up to this length
const MAX_COUNT_TEXT_CHARS: usize = 32;
// Long.MAX_VALUE has 19 digits
const MAX_COUNT_WHOLE_DIGITS: i64 = 19;
// an AWS event stream message is at most 16 MiB of payload and 128 KiB of headers
const MAX_EVENT_STREAM_MESSAGE_BYTES: i64 = 16 * 1024 * 1024 + 128 * 1024 + 16;
const SSE_DATA_FIELD: &[u8] = b"data";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Framing {
    Unknown,
    Json,
    Sse,
    EventStream,
    Unreadable,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Name {
    Usage,
    UsageMetadata,
    PromptEvalCount,
    EvalCount,
    InvocationMetrics,
    Bytes,
    Model,
    Id,
    ModelVersion,
    FinishReason,
    StopReason,
    Status,
    FinishReasonCamel,
    DoneReason,
    StopReasonCamel,
    Response,
    Message,
    XGroq,
    Choices,
    Delta,
    Candidates,
}

const NAMES: &[(Name, &str)] = &[
    (Name::Usage, "usage"),
    (Name::UsageMetadata, "usageMetadata"),
    (Name::PromptEvalCount, "prompt_eval_count"),
    (Name::EvalCount, "eval_count"),
    // exactly MAX_NAME_BYTES long
    (Name::InvocationMetrics, "amazon-bedrock-invocationMetrics"),
    (Name::Bytes, "bytes"),
    (Name::Model, "model"),
    (Name::Id, "id"),
    (Name::ModelVersion, "modelVersion"),
    (Name::FinishReason, "finish_reason"),
    (Name::StopReason, "stop_reason"),
    (Name::Status, "status"),
    (Name::FinishReasonCamel, "finishReason"),
    (Name::DoneReason, "done_reason"),
    (Name::StopReasonCamel, "stopReason"),
    (Name::Response, "response"),
    (Name::Message, "message"),
    (Name::XGroq, "x_groq"),
    (Name::Choices, "choices"),
    (Name::Delta, "delta"),
    (Name::Candidates, "candidates"),
];

impl Name {
    fn of(bytes: &[u8]) -> Option<Name> {
        NAMES.iter().find(|(_, text)| text.as_bytes() == bytes).map(|(name, _)| *name)
    }

    fn text(self) -> &'static str {
        NAMES.iter().find(|(name, _)| *name == self).map_or("", |(_, text)| text)
    }
}

/// What the stream has said so far, which the skimmers report to.
#[derive(Default)]
struct Found {
    usage: Option<Map<String, Value>>,
    invocation_metrics: Option<Map<String, Value>>,
    final_usage_seen: bool,
    usage_on_every_chunk: bool,
    finish_reason_seen: bool,
    model: Option<String>,
    response_id: Option<String>,
    stop_reason: Option<String>,
    json_documents: u32,
}

/// `LlmStreamUsageScanner`. Not thread-safe.
pub struct Scanner {
    json: Skimmer,
    nested_json: Option<Skimmer>,
    framing: Framing,
    failed: bool,
    // Server-Sent Events
    sse_line_empty: bool,
    sse_after_carriage_return: bool,
    sse_field_matched: usize,
    sse_in_data: bool,
    sse_skip_line: bool,
    // AWS event stream
    prelude: [u8; 12],
    prelude_length: usize,
    header_bytes_left: i64,
    payload_bytes_left: i64,
    checksum_bytes_left: i64,
    found: Found,
}

impl Default for Scanner {
    fn default() -> Self {
        Scanner::new()
    }
}

impl Scanner {
    pub fn new() -> Scanner {
        Scanner {
            json: Skimmer::new(false),
            nested_json: None,
            framing: Framing::Unknown,
            failed: false,
            sse_line_empty: true,
            sse_after_carriage_return: false,
            sse_field_matched: 0,
            sse_in_data: false,
            sse_skip_line: false,
            prelude: [0; 12],
            prelude_length: 0,
            header_bytes_left: 0,
            payload_bytes_left: 0,
            checksum_bytes_left: 0,
            found: Found::default(),
        }
    }

    /// Feed the next bytes of the response.
    pub fn accept(&mut self, bytes: &[u8]) {
        if self.failed {
            return;
        }
        for &b in bytes {
            self.accept_byte(b);
        }
    }

    /// The usage the stream reported, in the provider's own field names and merged across events (a later event's
    /// fields replace an earlier one's), or `None` when it reported none. A Bedrock InvokeModelWithResponseStream
    /// stream with no usage object gives the counts of its last chunk's `amazon-bedrock-invocationMetrics` instead.
    pub fn usage(&self) -> Option<Value> {
        self.found.usage.clone().or_else(|| self.found.invocation_metrics.clone()).map(Value::Object)
    }

    /// False when the only usage seen came from an event that opens a response (Anthropic's `message_start`), or from
    /// chunks that each repeat the counts so far (Gemini) with no finish reason yet, so the stream may have ended
    /// before its final counts.
    pub fn final_usage_seen(&self) -> bool {
        self.found.final_usage_seen || (self.found.usage_on_every_chunk && self.found.finish_reason_seen)
    }

    /// True when every chunk carries the counts so far (Gemini), so a stream that completes without a finish reason
    /// is still whole and only one that was cut off is missing counts.
    pub fn usage_on_every_chunk(&self) -> bool {
        self.found.usage_on_every_chunk
    }

    pub fn model(&self) -> Option<&str> {
        self.found.model.as_deref()
    }

    /// The id of the OpenAI Responses API response the stream's events describe (`response.id`). Read by upstream to
    /// count a background response once (`countedPolledCompletionIds`), which is not ported.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn response_id(&self) -> Option<&str> {
        self.found.response_id.as_deref()
    }

    pub fn stop_reason(&self) -> Option<&str> {
        self.found.stop_reason.as_deref()
    }

    /// True when the bytes were a stream of events rather than a single JSON document.
    pub fn streamed(&self) -> bool {
        matches!(self.framing, Framing::Sse | Framing::EventStream) || self.found.json_documents > 1
    }

    fn accept_byte(&mut self, b: u8) {
        match self.framing {
            Framing::Unknown => self.detect_framing(b),
            Framing::Json => self.json.accept(b, &mut self.found, Framing::Json, &mut self.nested_json),
            Framing::Sse => self.accept_server_sent_event_byte(b),
            Framing::EventStream => self.accept_event_stream_byte(b),
            Framing::Unreadable => {}
        }
    }

    fn detect_framing(&mut self, b: u8) {
        // leading whitespace and a UTF-8 byte order mark say nothing about the framing
        if is_whitespace(b) || b == 0xEF || b == 0xBB || b == 0xBF {
            return;
        }
        self.framing = if b == 0 {
            // an AWS event stream message opens with its big-endian length, well under 2^24
            Framing::EventStream
        } else if b == b'{' || b == b'[' {
            Framing::Json
        } else {
            Framing::Sse
        };
        self.accept_byte(b);
    }

    fn accept_server_sent_event_byte(&mut self, b: u8) {
        if b == b'\n' && self.sse_after_carriage_return {
            self.sse_after_carriage_return = false;
            return;
        }
        self.sse_after_carriage_return = b == b'\r';
        if b == b'\n' || b == b'\r' {
            if self.sse_line_empty {
                // a blank line ends the event, and with it any JSON left unfinished
                self.json.reset();
            }
            self.sse_line_empty = true;
            self.sse_field_matched = 0;
            self.sse_in_data = false;
            self.sse_skip_line = false;
            return;
        }
        self.sse_line_empty = false;
        if self.sse_in_data {
            self.json.accept(b, &mut self.found, Framing::Sse, &mut self.nested_json);
        } else if !self.sse_skip_line {
            if b == b':' && self.sse_field_matched == SSE_DATA_FIELD.len() {
                self.sse_in_data = true;
            } else if self.sse_field_matched < SSE_DATA_FIELD.len() && b == SSE_DATA_FIELD[self.sse_field_matched] {
                self.sse_field_matched += 1;
            } else {
                self.sse_skip_line = true;
            }
        }
    }

    fn accept_event_stream_byte(&mut self, b: u8) {
        if self.prelude_length < self.prelude.len() {
            self.prelude[self.prelude_length] = b;
            self.prelude_length += 1;
            if self.prelude_length == self.prelude.len() {
                let total_length = read_int(&self.prelude, 0) as i64;
                let headers_length = read_int(&self.prelude, 4) as i64;
                if !(16..=MAX_EVENT_STREAM_MESSAGE_BYTES).contains(&total_length) || headers_length < 0 || headers_length > total_length - 16 {
                    self.framing = Framing::Unreadable;
                    return;
                }
                self.header_bytes_left = headers_length;
                self.payload_bytes_left = total_length - headers_length - 16;
                self.checksum_bytes_left = 4;
                self.json.reset();
            }
            return;
        }
        if self.header_bytes_left > 0 {
            self.header_bytes_left -= 1;
        } else if self.payload_bytes_left > 0 {
            self.payload_bytes_left -= 1;
            self.json.accept(b, &mut self.found, Framing::EventStream, &mut self.nested_json);
        } else {
            self.checksum_bytes_left -= 1;
            if self.checksum_bytes_left == 0 {
                self.prelude_length = 0;
            }
        }
    }
}

/// A Java `int` read big-endian.
fn read_int(bytes: &[u8], offset: usize) -> i32 {
    i32::from_be_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

fn is_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\n' | b'\r' | b'\t')
}

fn is_short_text(value: &Value) -> Option<&str> {
    value.as_str().filter(|s| !s.is_empty() && s.encode_utf16().count() <= MAX_TEXT_CHARS)
}

impl Found {
    fn on_value(&mut self, name: Name, parent: Option<Name>, raw: &[u8], nested: bool, framing: Framing, nested_json: &mut Option<Skimmer>) {
        // serde_json's own nesting limit (128) bounds a hostile value; the lenient fallback has none
        let Ok(value) = serde_json::from_slice::<Value>(raw) else { return };
        if value.is_null() {
            return;
        }
        match name {
            Name::Usage => {
                if let Value::Object(update) = &value && self.merge_usage(update) && parent != Some(Name::Message) {
                    self.final_usage_seen = true;
                }
            }
            Name::UsageMetadata => {
                if let Value::Object(update) = &value && self.merge_usage(update) {
                    self.usage_on_every_chunk = true;
                }
            }
            Name::InvocationMetrics => {
                // sent only on the last chunk of the stream
                if let Some(metrics) = counts(&value) {
                    self.invocation_metrics = Some(metrics);
                    self.final_usage_seen = true;
                }
            }
            Name::PromptEvalCount | Name::EvalCount => {
                if let Some(count) = count(&value) && self.keep(name.text(), count) {
                    self.final_usage_seen = true;
                }
            }
            Name::Bytes => {
                if let (Some(text), false) = (value.as_str(), nested) {
                    self.accept_nested(text, framing, nested_json);
                }
            }
            Name::Model | Name::ModelVersion => {
                if let Some(text) = is_short_text(&value) {
                    self.model = Some(text.to_string());
                }
            }
            Name::Id => {
                if let Some(text) = is_short_text(&value) {
                    self.response_id = Some(text.to_string());
                }
            }
            _ => {
                if let Some(text) = is_short_text(&value) {
                    self.stop_reason = Some(text.to_string());
                    self.finish_reason_seen |= name == Name::FinishReasonCamel;
                }
            }
        }
    }

    // a field already kept is replaced; a new one is refused once the usage is full
    fn keep(&mut self, field: &str, value: Value) -> bool {
        if field.encode_utf16().count() > MAX_USAGE_NAME_CHARS {
            return false;
        }
        let usage = self.usage.get_or_insert_with(Map::new);
        if !usage.contains_key(field) && usage.len() >= MAX_USAGE_FIELDS {
            return false;
        }
        usage.insert(field.to_string(), value);
        true
    }

    /// Merge one usage event into the usage kept for the stream. Only counts are kept, as whole numbers, directly or
    /// one object down: a null, text or array field is ignored and leaves the value an earlier event gave.
    fn merge_usage(&mut self, update: &Map<String, Value>) -> bool {
        let mut merged = false;
        for (field, value) in update {
            let counted = count(value).or_else(|| counts(value).map(Value::Object));
            if let Some(counted) = counted && self.keep(field, counted) {
                merged = true;
            }
        }
        merged
    }

    // Bedrock InvokeModelWithResponseStream wraps each model event as base64 in {"bytes": "..."}
    fn accept_nested(&mut self, base64_text: &str, _framing: Framing, nested_json: &mut Option<Skimmer>) {
        use base64::Engine;
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(base64_text) else { return };
        let skimmer = nested_json.get_or_insert_with(|| Skimmer::new(true));
        skimmer.reset();
        let mut none = None;
        for b in decoded {
            skimmer.accept(b, self, Framing::EventStream, &mut none);
        }
    }
}

/// A token count as a whole number, read as the whole-response path reads it (`JsonNode.asInt()`): a decimal is
/// truncated and a numeric string is parsed. Anything else is not a count.
fn count(value: &Value) -> Option<Value> {
    match value {
        Value::Number(n) => {
            let text = n.to_string();
            if !text.contains(['.', 'e', 'E']) {
                // `canConvertToLong`
                return text.parse::<i64>().ok().map(Value::from);
            }
            // a decimal is a Java double: `BigDecimal.valueOf(double)`
            let double: f64 = text.parse().ok()?;
            if !double.is_finite() {
                return None;
            }
            whole(&java_double_text(double))
        }
        Value::String(s) if s.trim().chars().count() <= MAX_COUNT_TEXT_CHARS => whole(s.trim()),
        _ => None,
    }
}

/// `Double.toString`'s digits, enough for [`whole`]: the shortest round-trip decimal.
fn java_double_text(double: f64) -> String {
    format!("{double:e}")
}

/// `new BigDecimal(text)` truncated to a whole `long`: 0 below one, `None` past 19 whole digits or out of range.
fn whole(text: &str) -> Option<Value> {
    let bytes = text.as_bytes();
    let mut i = 0;
    let negative = match bytes.first() {
        Some(b'-') => {
            i = 1;
            true
        }
        Some(b'+') => {
            i = 1;
            false
        }
        _ => false,
    };
    let mut digits = String::new();
    let mut point: Option<usize> = None;
    while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
        if bytes[i] == b'.' {
            if point.is_some() {
                return None;
            }
            point = Some(digits.len());
        } else {
            digits.push(bytes[i] as char);
        }
        i += 1;
    }
    if digits.is_empty() {
        return None;
    }
    let mut exponent: i64 = 0;
    if i < bytes.len() {
        if bytes[i] != b'e' && bytes[i] != b'E' {
            return None;
        }
        let rest = &text[i + 1..];
        let unsigned = rest.strip_prefix(['+', '-']).unwrap_or(rest);
        if unsigned.is_empty() || !unsigned.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // BigDecimal refuses an exponent past an int
        exponent = rest.parse::<i64>().ok().filter(|e| i32::try_from(*e).is_ok())?;
    }
    let integer_digits = point.unwrap_or(digits.len()) as i64;
    let leading_zeros = digits.bytes().take_while(|&b| b == b'0').count() as i64;
    if leading_zeros as usize == digits.len() {
        return Some(Value::from(0));
    }
    // the digits of the whole part, after the exponent moves the point
    let whole_digits = integer_digits + exponent - leading_zeros;
    if whole_digits <= 0 {
        return Some(Value::from(0));
    }
    if whole_digits > MAX_COUNT_WHOLE_DIGITS {
        return None;
    }
    let significant = &digits[leading_zeros as usize..];
    let mut whole_text: String = significant.chars().take(whole_digits as usize).collect();
    while (whole_text.len() as i64) < whole_digits {
        whole_text.push('0');
    }
    let magnitude: i128 = whole_text.parse().ok()?;
    let value = if negative { -magnitude } else { magnitude };
    i64::try_from(value).ok().map(Value::from)
}

// the counts of an object inside the usage, such as prompt_tokens_details, or None when it has none
fn counts(details: &Value) -> Option<Map<String, Value>> {
    let Value::Object(fields) = details else { return None };
    let mut counts = Map::new();
    for (field, value) in fields {
        if counts.len() >= MAX_USAGE_DETAIL_FIELDS {
            break;
        }
        if let Some(count) = count(value) && field.encode_utf16().count() <= MAX_USAGE_NAME_CHARS {
            counts.insert(field.clone(), count);
        }
    }
    (!counts.is_empty()).then_some(counts)
}

/// Skims JSON one byte at a time, tracking only its depth and the current field name, and capturing the raw value of
/// a wanted field. Malformed JSON cannot make it fail.
struct Skimmer {
    nested: bool,
    name_buffer: [u8; MAX_NAME_BYTES],
    // -1: not a wanted name
    name_length: i32,
    object_depth: i32,
    array_depth: i32,
    in_string: bool,
    escaped: bool,
    after_string: bool,
    top_level_name: Option<Name>,
    armed_name: Option<Name>,
    armed_parent: Option<Name>,
    capturing: bool,
    capturing_string: bool,
    capturing_bare_value: bool,
    capture_dropped: bool,
    capture_base_depth: i32,
    capture: Vec<u8>,
}

impl Skimmer {
    fn new(nested: bool) -> Skimmer {
        Skimmer {
            nested,
            name_buffer: [0; MAX_NAME_BYTES],
            name_length: 0,
            object_depth: 0,
            array_depth: 0,
            in_string: false,
            escaped: false,
            after_string: false,
            top_level_name: None,
            armed_name: None,
            armed_parent: None,
            capturing: false,
            capturing_string: false,
            capturing_bare_value: false,
            capture_dropped: false,
            capture_base_depth: 0,
            capture: Vec::new(),
        }
    }

    fn reset(&mut self) {
        self.name_length = 0;
        self.object_depth = 0;
        self.array_depth = 0;
        self.in_string = false;
        self.escaped = false;
        self.after_string = false;
        self.top_level_name = None;
        self.armed_name = None;
        self.capturing = false;
        self.capturing_string = false;
        self.capturing_bare_value = false;
    }

    fn accept(&mut self, b: u8, found: &mut Found, framing: Framing, nested_json: &mut Option<Skimmer>) {
        if self.capturing_bare_value {
            if !ends_bare_value(b) {
                self.capture_byte(b);
                return;
            }
            self.capturing_bare_value = false;
            self.deliver(found, framing, nested_json);
        }
        if self.capturing {
            self.capture_byte(b);
        }
        if self.in_string {
            self.accept_string_byte(b, found, framing, nested_json);
            return;
        }
        if self.after_string {
            if is_whitespace(b) {
                return;
            }
            self.after_string = false;
            if b == b':' {
                if !self.capturing {
                    self.field_name_read(framing);
                }
                return;
            }
        }
        if self.armed_name.is_some() && !self.capturing {
            if is_whitespace(b) {
                return;
            }
            if ends_bare_value(b) {
                self.armed_name = None;
            } else {
                self.start_capture(b);
                if b != b'{' && b != b'[' {
                    return;
                }
            }
        }
        match b {
            b'"' => {
                self.in_string = true;
                self.escaped = false;
                self.name_length = 0;
            }
            b'{' => self.object_depth += 1,
            b'[' => self.array_depth += 1,
            b'}' => {
                if self.object_depth > 0 {
                    self.object_depth -= 1;
                }
                self.value_closed(true, found, framing, nested_json);
            }
            b']' => {
                if self.array_depth > 0 {
                    self.array_depth -= 1;
                }
                self.value_closed(false, found, framing, nested_json);
            }
            _ => {}
        }
    }

    fn accept_string_byte(&mut self, b: u8, found: &mut Found, framing: Framing, nested_json: &mut Option<Skimmer>) {
        if self.escaped {
            self.escaped = false;
        } else if b == b'\\' {
            self.escaped = true;
            // no wanted field name needs an escape
            self.name_length = -1;
        } else if b == b'"' {
            self.in_string = false;
            if self.capturing_string {
                self.capturing_string = false;
                self.deliver(found, framing, nested_json);
            } else {
                self.after_string = true;
            }
        } else if self.name_length >= 0 {
            if (self.name_length as usize) < self.name_buffer.len() {
                self.name_buffer[self.name_length as usize] = b;
                self.name_length += 1;
            } else {
                self.name_length = -1;
            }
        }
    }

    fn field_name_read(&mut self, framing: Framing) {
        if self.object_depth < 1 || self.object_depth > 2 {
            return;
        }
        let name = if self.name_length > 0 { Name::of(&self.name_buffer[..self.name_length as usize]) } else { None };
        let parent = if self.object_depth == 1 {
            self.top_level_name = name;
            None
        } else {
            self.top_level_name
        };
        if let Some(name) = name.filter(|&n| self.wanted(n, parent, framing)) {
            self.armed_name = Some(name);
            self.armed_parent = parent;
        }
    }

    // a wanted field is at the top of a document, or one object down inside a known field; arrays do not count as
    // depth, so choices[0].finish_reason is one object down
    fn wanted(&self, name: Name, parent: Option<Name>, framing: Framing) -> bool {
        let top = self.object_depth == 1;
        match name {
            // under delta: Cohere v2's message-end event
            Name::Usage => top || matches!(parent, Some(Name::Response | Name::Message | Name::XGroq | Name::Delta)),
            Name::Model => top || matches!(parent, Some(Name::Response | Name::Message)),
            Name::Id => parent == Some(Name::Response),
            Name::UsageMetadata | Name::PromptEvalCount | Name::EvalCount | Name::ModelVersion | Name::DoneReason | Name::StopReasonCamel => top,
            Name::Bytes => top && !self.nested && framing == Framing::EventStream,
            Name::InvocationMetrics => top && self.nested,
            Name::FinishReason => matches!(parent, Some(Name::Choices | Name::Delta)),
            Name::StopReason => parent == Some(Name::Delta),
            Name::Status => parent == Some(Name::Response),
            Name::FinishReasonCamel => parent == Some(Name::Candidates),
            _ => false,
        }
    }

    fn start_capture(&mut self, first: u8) {
        self.capturing = true;
        self.capture_dropped = false;
        self.capture.clear();
        self.capture_byte(first);
        if first == b'"' {
            self.capturing_string = true;
            self.in_string = true;
            self.escaped = false;
            self.name_length = -1;
        } else if first == b'{' || first == b'[' {
            self.capture_base_depth = self.object_depth + self.array_depth;
        } else {
            self.capturing_bare_value = true;
        }
    }

    fn capture_byte(&mut self, b: u8) {
        if self.capture_dropped {
            return;
        }
        if self.capture.len() >= MAX_VALUE_BYTES {
            self.capture_dropped = true;
            return;
        }
        self.capture.push(b);
    }

    fn value_closed(&mut self, object: bool, found: &mut Found, framing: Framing, nested_json: &mut Option<Skimmer>) {
        if self.capturing && !self.capturing_string && !self.capturing_bare_value && self.object_depth + self.array_depth == self.capture_base_depth {
            self.deliver(found, framing, nested_json);
        }
        // an object at the top, or directly inside a top-level array, is one document of the stream
        if object && self.object_depth == 0 && self.array_depth <= 1 && !self.nested && found.json_documents < 2 {
            found.json_documents += 1;
        }
    }

    fn deliver(&mut self, found: &mut Found, framing: Framing, nested_json: &mut Option<Skimmer>) {
        let name = self.armed_name.take();
        self.capturing = false;
        if let (false, Some(name)) = (self.capture_dropped, name) {
            found.on_value(name, self.armed_parent, &self.capture, self.nested, framing, nested_json);
        }
    }
}

fn ends_bare_value(b: u8) -> bool {
    b == b',' || b == b'}' || b == b']' || is_whitespace(b)
}

// ---------------------------------------------------------------------------------------------------------------
// LlmStreamUsageScannerTest (upstream/mockserver/.../llm/client/LlmStreamUsageScannerTest.java), one #[test] per
// method, over ProviderStreamFixtures (tests/files/llm/provider_stream_fixtures.json). The message CRCs of the AWS
// event stream fixtures are zero: the scanner never reads them.
// ---------------------------------------------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{parse_usage, Usage};
    use base64::Engine;

    fn fixture(name: &str) -> String {
        static FIXTURES: std::sync::LazyLock<Value> =
            std::sync::LazyLock::new(|| serde_json::from_str(include_str!("../../tests/files/llm/provider_stream_fixtures.json")).expect("fixtures"));
        FIXTURES[name].as_str().expect(name).to_string()
    }

    fn scan(chunks: &[&[u8]]) -> Scanner {
        let mut scanner = Scanner::new();
        for chunk in chunks {
            scanner.accept(chunk);
        }
        scanner
    }

    fn usage(provider: &str, scanner: &Scanner) -> Option<Usage> {
        scanner.usage().and_then(|u| parse_usage(provider, Some(&u)))
    }

    fn expected(input: Option<i64>, output: Option<i64>, cached: Option<i64>, creation: Option<i64>, reasoning: Option<i64>) -> Option<Usage> {
        Some(Usage { input_tokens: input, output_tokens: output, cached_input_tokens: cached, cache_creation_tokens: creation, reasoning_tokens: reasoning })
    }

    fn assert_usage_however_chunked(provider: &str, stream: &[u8], expected: Option<Usage>, model: Option<&str>, stop_reason: Option<&str>) {
        let whole = scan(&[stream]);
        assert_eq!(usage(provider, &whole), expected, "whole");
        assert_eq!(whole.model(), model);
        assert_eq!(whole.stop_reason(), stop_reason);
        assert!(whole.final_usage_seen());
        let mut byte_at_a_time = Scanner::new();
        for b in stream {
            byte_at_a_time.accept(&[*b]);
        }
        assert_eq!(usage(provider, &byte_at_a_time), expected, "one byte at a time");
        assert_eq!(byte_at_a_time.model(), model);
        assert_eq!(byte_at_a_time.stop_reason(), stop_reason);
        for split in 1..stream.len() {
            let two = scan(&[&stream[..split], &stream[split..]]);
            assert_eq!(usage(provider, &two), expected, "split at {split}");
        }
    }

    /// `ProviderStreamFixtures.writeEventStreamMessage`.
    fn event_stream_message(out: &mut Vec<u8>, event_type: &str, payload: &str) {
        let mut headers = Vec::new();
        for (name, value) in [(":event-type", event_type), (":content-type", "application/json"), (":message-type", "event")] {
            headers.push(name.len() as u8);
            headers.extend_from_slice(name.as_bytes());
            headers.push(7);
            headers.extend_from_slice(&(value.len() as u16).to_be_bytes());
            headers.extend_from_slice(value.as_bytes());
        }
        let total = 12 + headers.len() + payload.len() + 4;
        out.extend_from_slice(&(total as u32).to_be_bytes());
        out.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&headers);
        out.extend_from_slice(payload.as_bytes());
        out.extend_from_slice(&[0; 4]);
    }

    fn bedrock_converse_stream() -> Vec<u8> {
        let mut out = Vec::new();
        event_stream_message(&mut out, "messageStart", r#"{"p":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW","role":"assistant"}"#);
        event_stream_message(&mut out, "contentBlockDelta", r#"{"contentBlockIndex":0,"delta":{"text":"Hello"},"p":"abcdefghijklmnopqrstuvwxyzABCD"}"#);
        event_stream_message(&mut out, "contentBlockStop", r#"{"contentBlockIndex":0,"p":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR"}"#);
        event_stream_message(&mut out, "messageStop", r#"{"p":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJK","stopReason":"end_turn"}"#);
        event_stream_message(
            &mut out,
            "metadata",
            r#"{"metrics":{"latencyMs":623},"p":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN","usage":{"cacheReadInputTokens":6,"cacheWriteInputTokens":0,"inputTokens":25,"outputTokens":15,"totalTokens":46}}"#,
        );
        out
    }

    fn bedrock_chunks(events: &[String]) -> Vec<u8> {
        let mut out = Vec::new();
        for json in events {
            let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
            event_stream_message(&mut out, "chunk", &format!(r#"{{"bytes":"{b64}","p":"abcdefghijklmnopqrstuvwxyzABCDEFGH"}}"#));
        }
        out
    }

    fn anthropic_events(sse: &str) -> Vec<String> {
        sse.split("\n\n").filter(|e| !e.is_empty()).map(|e| e[e.find("data: ").expect("data") + 6..].to_string()).collect()
    }

    fn bedrock_invoke_with_response_stream() -> Vec<u8> {
        bedrock_chunks(&anthropic_events(&fixture("ANTHROPIC_MESSAGES")))
    }

    fn bedrock_invoke_with_response_stream_and_invocation_metrics() -> Vec<u8> {
        bedrock_chunks(&anthropic_events(&fixture("ANTHROPIC_MESSAGES").replace(
            r#"{"type":"message_stop"}"#,
            r#"{"type":"message_stop","amazon-bedrock-invocationMetrics":{"inputTokenCount":25,"outputTokenCount":15,"invocationLatency":623,"firstByteLatency":211}}"#,
        )))
    }

    fn bedrock_invoke_with_response_stream_of_llama() -> Vec<u8> {
        bedrock_chunks(&[
            r#"{"generation":"Hello","prompt_token_count":8,"generation_token_count":1,"stop_reason":null}"#.to_string(),
            r#"{"generation":" there","prompt_token_count":null,"generation_token_count":5,"stop_reason":"stop","amazon-bedrock-invocationMetrics":{"inputTokenCount":8,"outputTokenCount":5,"invocationLatency":300,"firstByteLatency":100}}"#.to_string(),
        ])
    }

    #[test]
    fn should_read_open_ai_chat_usage_chunk_sent_with_include_usage() {
        assert_usage_however_chunked("OPENAI", fixture("OPENAI_CHAT_WITH_USAGE").as_bytes(), expected(Some(19), Some(10), Some(4), None, Some(3)), Some("gpt-4o-2024-08-06"), Some("stop"));
    }

    #[test]
    fn should_read_the_response_id_of_an_open_ai_responses_stream_only() {
        assert_eq!(scan(&[fixture("OPENAI_RESPONSES").as_bytes()]).response_id(), Some("resp_67c9fdcecf488190bdd9a0409de3a1ec07b8b0ad4e5eb654"));
        assert_eq!(scan(&[fixture("OPENAI_CHAT_WITH_USAGE").as_bytes()]).response_id(), None);
        assert_eq!(scan(&[br#"data: {"type":"response.output_item.added","item":{"id":"msg_1","type":"message"}}

"#]).response_id(), None);
    }

    #[test]
    fn should_find_no_usage_in_open_ai_chat_stream_sent_without_include_usage() {
        let scanner = scan(&[fixture("OPENAI_CHAT_WITHOUT_USAGE").as_bytes()]);
        assert_eq!(scanner.usage(), None);
        assert!(!scanner.final_usage_seen());
        assert_eq!(scanner.model(), Some("gpt-4o-2024-08-06"));
        assert!(scanner.streamed());
    }

    #[test]
    fn should_read_usage_that_open_ai_compatible_providers_send_without_opt_in() {
        assert_usage_however_chunked("MISTRAL", fixture("MISTRAL_CHAT").as_bytes(), expected(Some(16), Some(18), None, None, None), Some("mistral-small-latest"), Some("stop"));
        assert_usage_however_chunked("OPENROUTER", fixture("OPENROUTER_CHAT").as_bytes(), expected(Some(14), Some(9), Some(0), None, Some(0)), Some("openai/gpt-4o"), Some("stop"));
    }

    #[test]
    fn should_read_groq_usage_from_x_groq() {
        assert_usage_however_chunked("GROQ", fixture("GROQ_CHAT").as_bytes(), expected(Some(18), Some(25), None, None, None), Some("llama-3.3-70b-versatile"), Some("stop"));
    }

    #[test]
    fn should_read_open_ai_responses_usage_from_response_completed() {
        assert_usage_however_chunked("OPENAI_RESPONSES", fixture("OPENAI_RESPONSES").as_bytes(), expected(Some(37), Some(11), Some(5), None, Some(2)), Some("gpt-4o-2024-08-06"), Some("completed"));
    }

    #[test]
    fn should_merge_anthropic_message_start_and_message_delta_usage() {
        assert_usage_however_chunked("ANTHROPIC", fixture("ANTHROPIC_MESSAGES").as_bytes(), expected(Some(25), Some(15), Some(7), Some(3), None), Some("claude-sonnet-4-5-20250929"), Some("end_turn"));
    }

    #[test]
    fn should_take_cumulative_counts_from_an_anthropic_message_delta_that_repeats_them() {
        let stream = fixture("ANTHROPIC_MESSAGES").replace(
            r#""usage":{"output_tokens":15}"#,
            r#""usage":{"input_tokens":25,"cache_creation_input_tokens":3,"cache_read_input_tokens":9,"output_tokens":15,"server_tool_use":null}"#,
        );
        assert_eq!(usage("ANTHROPIC", &scan(&[stream.as_bytes()])), expected(Some(25), Some(15), Some(9), Some(3), None));
    }

    #[test]
    fn should_read_gemini_usage_metadata_from_the_last_sse_chunk() {
        assert_usage_however_chunked("GEMINI", fixture("GEMINI_SSE").as_bytes(), expected(Some(8), Some(39), None, None, Some(27)), Some("gemini-2.5-flash"), Some("STOP"));
    }

    #[test]
    fn should_read_gemini_usage_metadata_from_a_streamed_json_array() {
        assert_usage_however_chunked("GEMINI", fixture("GEMINI_JSON_ARRAY").as_bytes(), expected(Some(8), Some(39), None, None, Some(27)), Some("gemini-2.5-flash"), Some("STOP"));
        assert!(scan(&[fixture("GEMINI_JSON_ARRAY").as_bytes()]).streamed());
    }

    #[test]
    fn should_count_a_gemini_stream_exactly_as_the_same_usage_in_a_whole_response() {
        let last_chunk = r#"{"candidates":[{"content":{"parts":[{"text":"Hello there"}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":8,"candidatesTokenCount":12,"totalTokenCount":47,"thoughtsTokenCount":27},"modelVersion":"gemini-2.5-flash"}"#;
        let whole = crate::telemetry::parse_completion("GEMINI", last_chunk.as_bytes()).expect("parsed").usage();
        assert_eq!(usage("GEMINI", &scan(&[fixture("GEMINI_SSE").as_bytes()])), Some(whole));
    }

    #[test]
    fn should_read_ollama_counts_from_the_done_line() {
        assert_usage_however_chunked("OLLAMA", fixture("OLLAMA_CHAT").as_bytes(), expected(Some(26), Some(282), None, None, None), Some("llama3.2"), Some("stop"));
        assert!(scan(&[fixture("OLLAMA_CHAT").as_bytes()]).streamed());
    }

    #[test]
    fn should_read_bedrock_converse_stream_usage_from_the_metadata_event() {
        assert_usage_however_chunked("BEDROCK", &bedrock_converse_stream(), expected(Some(25), Some(15), Some(6), Some(0), None), None, Some("end_turn"));
    }

    #[test]
    fn should_not_read_bedrock_guardrail_usage_as_token_usage() {
        let mut stream = Vec::new();
        event_stream_message(
            &mut stream,
            "metadata",
            r#"{"metrics":{"latencyMs":623},"usage":{"inputTokens":25,"outputTokens":15,"totalTokens":40},"trace":{"guardrail":{"inputAssessment":{"gr-1":{"invocationMetrics":{"guardrailProcessingLatency":21,"usage":{"inputTokens":777,"outputTokens":777,"contentPolicyUnits":1,"topicPolicyUnits":1}}}}}}}"#,
        );
        assert_eq!(usage("BEDROCK", &scan(&[&stream])), expected(Some(25), Some(15), None, None, None));
    }

    #[test]
    fn should_read_anthropic_events_wrapped_by_bedrock_invoke_with_response_stream() {
        assert_usage_however_chunked("BEDROCK", &bedrock_invoke_with_response_stream(), expected(Some(25), Some(15), Some(7), Some(3), None), Some("claude-sonnet-4-5-20250929"), Some("end_turn"));
    }

    #[test]
    fn should_read_the_invocation_metrics_of_a_bedrock_invoke_with_response_stream_that_sends_no_usage() {
        assert_usage_however_chunked("BEDROCK", &bedrock_invoke_with_response_stream_of_llama(), expected(Some(8), Some(5), None, None, None), None, None);
    }

    #[test]
    fn should_prefer_anthropic_usage_to_the_invocation_metrics_of_the_same_bedrock_stream() {
        let stream = bedrock_invoke_with_response_stream_and_invocation_metrics();
        assert!(stream.len() > bedrock_invoke_with_response_stream().len(), "the fixture carries invocation metrics");
        assert_usage_however_chunked("BEDROCK", &stream, expected(Some(25), Some(15), Some(7), Some(3), None), Some("claude-sonnet-4-5-20250929"), Some("end_turn"));
    }

    #[test]
    fn should_read_invocation_metrics_only_at_the_top_of_the_event_inside_a_bedrock_chunk() {
        let metrics = r#""amazon-bedrock-invocationMetrics":{"inputTokenCount":9,"outputTokenCount":9}"#;
        let mut outside = Vec::new();
        event_stream_message(&mut outside, "chunk", &format!("{{{metrics}}}"));
        let mut deeper = Vec::new();
        let inner = base64::engine::general_purpose::STANDARD.encode(format!(r#"{{"generation":"Hi","tool":{{{metrics}}}}}"#));
        event_stream_message(&mut deeper, "chunk", &format!(r#"{{"bytes":"{inner}"}}"#));
        assert_eq!(scan(&[&outside]).usage(), None);
        assert_eq!(scan(&[&deeper]).usage(), None);
        assert_eq!(scan(&[format!("data: {{{metrics}}}\n\n").as_bytes()]).usage(), None);
    }

    #[test]
    fn should_report_only_opening_counts_when_an_anthropic_stream_is_cut_off_before_message_delta() {
        let scanner = scan(&[fixture("ANTHROPIC_MESSAGES_CUT_OFF").as_bytes()]);
        assert_eq!(usage("ANTHROPIC", &scanner), expected(Some(25), Some(1), Some(7), Some(3), None));
        assert!(!scanner.final_usage_seen());
    }

    #[test]
    fn should_find_no_usage_in_a_stream_cut_off_before_its_usage_event() {
        let open_ai = fixture("OPENAI_CHAT_WITH_USAGE");
        let ollama = fixture("OLLAMA_CHAT");
        let bedrock = bedrock_converse_stream();
        assert_eq!(scan(&[&open_ai.as_bytes()[..open_ai.find(r#""completion_tokens":10"#).unwrap()]]).usage(), None);
        assert_eq!(scan(&[&ollama.as_bytes()[..ollama.find(r#""done":true"#).unwrap()]]).usage(), None);
        assert_eq!(scan(&[&bedrock[..bedrock.len() - 60]]).usage(), None);
        assert_eq!(scan(&[fixture("OPENAI_RESPONSES_CUT_OFF").as_bytes()]).usage(), None);
    }

    #[test]
    fn should_not_read_usage_from_a_server_sent_event_stream_that_is_not_an_llm_response() {
        let metrics = concat!(
            "retry: 3000\n\n",
            "event: metric\nid: 1\ndata: {\"host\":\"web-1\",\"usage\":\"87%\",\"cpu\":{\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":6}}}\n\n",
            "event: metric\nid: 2\ndata: {\"hosts\":[{\"name\":\"web-2\",\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":8}}],\"usage\":[1,2,3]}\n\n",
            "event: tick\ndata: usage: {\"prompt_tokens\":9}\n\n",
            "data: plain text, not JSON\n\n",
        );
        let json_rpc = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"{\\\"usage\\\":{\\\"input_tokens\\\":5}}\"}],\"isError\":false}}\n\n";
        assert_eq!(scan(&[metrics.as_bytes()]).usage(), None);
        assert_eq!(scan(&[json_rpc.as_bytes()]).usage(), None);
    }

    #[test]
    fn should_count_nothing_when_a_usage_object_has_none_of_the_providers_token_fields() {
        let scanner = scan(&[b"data: {\"usage\":{\"cpu\":87,\"memory\":40}}\n\n"]);
        assert_eq!(usage("OPENAI", &scanner), expected(None, None, None, None, None));
        assert_eq!(scan(&[b"data: {\"usage\":{\"cpu\":\"87%\",\"tier\":\"gold\",\"hosts\":[1,2],\"none\":null,\"empty\":{}}}\n\n"]).usage(), None);
    }

    #[test]
    fn should_keep_an_earlier_count_when_a_later_event_sends_null_for_it() {
        let stream = fixture("ANTHROPIC_MESSAGES").replace(
            r#""usage":{"output_tokens":15}"#,
            r#""usage":{"input_tokens":null,"cache_creation_input_tokens":null,"cache_read_input_tokens":null,"output_tokens":15}"#,
        );
        assert_eq!(usage("ANTHROPIC", &scan(&[stream.as_bytes()])), expected(Some(25), Some(15), Some(7), Some(3), None));
    }

    #[test]
    fn should_keep_a_bounded_usage_however_many_distinct_fields_the_stream_sends() {
        let mut scanner = Scanner::new();
        scanner.accept(fixture("MISTRAL_CHAT").as_bytes());
        let mut key = 0;
        for event in 0..2_000 {
            let mut usage = String::from("data: {\"usage\":{");
            usage.push_str(&format!("\"details{event}\":{{"));
            for _ in 0..200 {
                usage.push_str(&format!("\"d{key}\":1,"));
                key += 1;
            }
            usage.push_str(&format!("\"{}\":1}},", "n".repeat(200)));
            usage.push_str(&format!("\"{}{event}\":1,", "n".repeat(200)));
            usage.push_str(&format!("\"huge{event}\":{},", "9".repeat(400)));
            for _ in 0..200 {
                usage.push_str(&format!("\"k{key}\":1,"));
                key += 1;
            }
            usage.push_str(&format!("\"completion_tokens\":{event}}}}}\n\n"));
            scanner.accept(usage.as_bytes());
        }
        let kept = scanner.usage().expect("usage");
        let kept = kept.as_object().expect("object");
        assert_eq!(kept.len(), MAX_USAGE_FIELDS);
        for value in kept.values() {
            assert!(value.as_object().map_or(0, Map::len) <= MAX_USAGE_DETAIL_FIELDS);
        }
        assert!(serde_json::to_string(kept).unwrap().len() < 64 * 1024);
        assert_eq!(usage("MISTRAL", &scanner), expected(Some(16), Some(1_999), None, None, None));
    }

    #[test]
    fn should_ignore_a_model_name_or_stop_reason_longer_than_the_bound() {
        let long_name = "m".repeat(MAX_TEXT_CHARS + 1);
        let scanner = scan(&[format!("data: {{\"model\":\"{long_name}\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"{long_name}\"}}]}}\n\n").as_bytes()]);
        assert_eq!(scanner.model(), None);
        assert_eq!(scanner.stop_reason(), None);
    }

    #[test]
    fn should_not_treat_gemini_counts_as_final_before_the_chunk_that_carries_the_finish_reason() {
        let stream = fixture("GEMINI_SSE");
        let cut_off = scan(&[&stream.as_bytes()[..stream.find("\r\n\r\n").unwrap() + 4]]);
        assert_eq!(usage("GEMINI", &cut_off), expected(Some(8), None, None, None, None));
        assert!(cut_off.usage_on_every_chunk());
        assert!(!cut_off.final_usage_seen());
        assert!(scan(&[stream.as_bytes()]).final_usage_seen());
    }

    #[test]
    fn should_drop_a_usage_value_larger_than_the_bound() {
        let mut padding = String::new();
        while padding.len() < MAX_VALUE_BYTES {
            padding.push_str("0123456789abcdef");
        }
        let oversized = format!("data: {{\"usage\":{{\"prompt_tokens\":19,\"completion_tokens\":10,\"note\":\"{padding}\"}}}}\n\n");
        assert_eq!(scan(&[oversized.as_bytes()]).usage(), None);
        assert_eq!(usage("OPENAI", &scan(&[oversized.as_bytes(), fixture("MISTRAL_CHAT").as_bytes()])), expected(Some(16), Some(18), None, None, None));
    }

    #[test]
    fn should_read_usage_after_an_event_far_larger_than_any_buffer_it_keeps() {
        let text = vec![b'x'; 4 * 1024 * 1024];
        let scanner = scan(&[
            br#"data: {"id":"chatcmpl-1","model":"gpt-4o-2024-08-06","choices":[{"index":0,"delta":{"content":""#,
            &text,
            b"\"},\"finish_reason\":null}],\"usage\":null}\n\n",
            fixture("OPENAI_CHAT_WITH_USAGE").as_bytes(),
        ]);
        assert_eq!(usage("OPENAI", &scanner), expected(Some(19), Some(10), Some(4), None, Some(3)));
    }

    #[test]
    fn should_recover_at_the_next_event_from_json_left_unfinished() {
        let stream = format!("data: {{\"choices\":[{{\"delta\":{{\"content\":\"never closed\n\n{}", fixture("MISTRAL_CHAT"));
        assert_eq!(usage("MISTRAL", &scan(&[stream.as_bytes()])), expected(Some(16), Some(18), None, None, None));
    }

    #[test]
    fn should_never_throw_on_malformed_or_hostile_bytes() {
        // java.util.Random(42) is not reproduced: any noise will do
        let mut seed: u64 = 42;
        let noise: Vec<u8> = (0..64 * 1024)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (seed >> 33) as u8
            })
            .collect();
        let nesting = vec![b'['; 256 * 1024];
        let nested_usage = format!("{{\"usage\":{}{}}}", "[".repeat(3000), "]".repeat(3000));
        let absurd: &[u8] = &[0, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 1, 2, 3, 4, b'{', b'"', b'u', b's'];
        let headers_longer: &[u8] = &[0, 0, 0, 32, 0, 0, 1, 0, 1, 2, 3, 4, b'{', b'}'];
        assert_eq!(scan(&[&noise]).usage(), None);
        assert_eq!(scan(&[&nesting]).usage(), None);
        assert_eq!(scan(&[nested_usage.as_bytes()]).usage(), None);
        assert_eq!(scan(&[absurd, &noise]).usage(), None);
        assert_eq!(scan(&[headers_longer, &noise]).usage(), None);
        assert_eq!(scan(&[b"data: {\"usage\":}\n\ndata: {\"usage\":{\"prompt_tokens\":\n\ndata: {\"usage\":{{{{\n\n"]).usage(), None);
        assert_eq!(scan(&[b"{\"prompt_eval_count\":\"twenty-six\",\"eval_count\":{\"n\":282}}\n"]).usage(), None);
        assert_eq!(scan(&[b""]).usage(), None);
    }

    #[test]
    fn should_ignore_base64_that_is_not_an_event_in_a_bedrock_chunk() {
        let mut stream = Vec::new();
        event_stream_message(&mut stream, "chunk", r#"{"bytes":"not base64 !!"}"#);
        event_stream_message(&mut stream, "chunk", r#"{"bytes":"AAEC/w=="}"#);
        assert_eq!(scan(&[&stream]).usage(), None);
    }

    #[test]
    fn should_not_treat_a_single_json_document_as_a_stream() {
        let scanner = scan(&[br#"{"model":"gpt-4o","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":2}}"#]);
        assert!(!scanner.streamed());
        assert_eq!(usage("OPENAI", &scanner), expected(Some(1), Some(2), None, None, None));
    }

    #[test]
    fn should_keep_a_usage_field_named_up_to_the_bound_and_drop_a_longer_one() {
        let at = "t".repeat(MAX_USAGE_NAME_CHARS);
        let over = "t".repeat(MAX_USAGE_NAME_CHARS + 1);
        let scanner = scan(&[format!("data: {{\"usage\":{{\"{at}\":5,\"{over}\":6,\"prompt_tokens_details\":{{\"{at}\":7,\"{over}\":8}},\"prompt_tokens\":3}}}}\n\n").as_bytes()]);
        let usage = scanner.usage().expect("usage");
        assert!(usage.get(&at).is_some());
        assert!(usage.get(&over).is_none());
        assert!(usage["prompt_tokens_details"].get(&at).is_some());
        assert!(usage["prompt_tokens_details"].get(&over).is_none());
        assert_eq!(usage["prompt_tokens"].as_i64(), Some(3));
        assert_eq!(scan(&[format!("{{\"{over}\":9}}\n").as_bytes()]).usage(), None);
    }

    #[test]
    fn should_read_a_decimal_or_numeric_string_count_as_the_whole_response_path_does() {
        for count in ["12.0", "12.7", "\"150\"", "\" 7 \"", "\"1e3\"", "0.4", "\"1e-100000000\""] {
            let usage_json = format!("\"usage\":{{\"prompt_tokens\":{count},\"completion_tokens\":{count},\"prompt_tokens_details\":{{\"cached_tokens\":{count}}}}}");
            let whole = crate::telemetry::parse_completion(
                "OPENAI",
                format!("{{\"model\":\"gpt-4o\",\"choices\":[{{\"index\":0,\"message\":{{\"role\":\"assistant\",\"content\":\"hi\"}},\"finish_reason\":\"stop\"}}],{usage_json}}}").as_bytes(),
            )
            .expect("parsed")
            .usage();
            let streamed = usage("OPENAI", &scan(&[format!("data: {{\"model\":\"gpt-4o\",\"choices\":[],{usage_json}}}\n\ndata: [DONE]\n\n").as_bytes()]));
            assert_eq!(streamed, Some(whole), "{count}");
        }
        let ollama_whole = crate::telemetry::parse_completion(
            "OLLAMA",
            br#"{"model":"llama3.2","message":{"role":"assistant","content":""},"done":true,"prompt_eval_count":"26","eval_count":282.0}"#,
        )
        .expect("parsed")
        .usage();
        let ollama_streamed = usage("OLLAMA", &scan(&[b"{\"model\":\"llama3.2\",\"done\":false}\n{\"model\":\"llama3.2\",\"done\":true,\"prompt_eval_count\":\"26\",\"eval_count\":282.0}\n"]));
        assert_eq!(ollama_streamed, expected(Some(26), Some(282), None, None, None));
        assert_eq!(ollama_streamed, Some(ollama_whole));
    }

    #[test]
    fn should_not_read_a_string_that_is_not_a_number_or_a_count_too_large_to_hold() {
        let scanner = scan(&[format!("data: {{\"usage\":{{\"prompt_tokens\":\"many\",\"completion_tokens\":1e300,\"total_tokens\":\"{}\",\"cached\":\"\"}}}}\n\n", "9".repeat(40)).as_bytes()]);
        assert_eq!(scanner.usage(), None);
    }

    #[test]
    fn should_reject_a_count_with_a_huge_exponent_without_expanding_it() {
        let started = std::time::Instant::now();
        let scanner = scan(&[b"data: {\"usage\":{\"prompt_tokens\":\"1e30000000\",\"completion_tokens\":\"-1e30000000\"}}\n\n"]);
        assert_eq!(scanner.usage(), None);
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
    }

    #[test]
    fn should_read_a_count_with_a_huge_negative_exponent_as_zero_without_expanding_it() {
        let started = std::time::Instant::now();
        let scanner = scan(&[b"data: {\"usage\":{\"prompt_tokens\":\"1e-100000000\",\"completion_tokens\":1e-100000000}}\n\n"]);
        let usage = scanner.usage().expect("usage");
        assert_eq!(usage["prompt_tokens"].as_i64(), Some(0));
        assert_eq!(usage["completion_tokens"].as_i64(), Some(0));
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
    }
}

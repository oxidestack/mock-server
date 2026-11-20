//! `OpenAiResponsesStore`: responses issued for the OpenAI Responses API (unless the request says `"store": false`),
//! kept with their conversation so a later request's `previous_response_id` continues it and
//! `GET …/responses/{id}` returns it. One per process, bounded (least recently used dropped) by count,
//! `MAX_RESPONSES`, and by an estimated byte budget, `maxOpenAiResponsesSizeInBytes`.

use std::sync::LazyLock;

use parking_lot::Mutex;
use serde_json::Value;

use super::conversation::{Message, Role, ToolCall};

const MAX_RESPONSES: usize = 10_000;

/// Per-entry (record, map node, conversation list) and per-message costs on top of the characters held, on the same
/// basis as the expectation and event-log weighers.
const ENTRY_OVERHEAD_BYTES: u64 = 256;
const MESSAGE_OVERHEAD_BYTES: u64 = 128;
/// `Long.BYTES`: the conversation list's reference to each message.
const MESSAGE_REFERENCE_BYTES: u64 = 8;

/// `StoredResponse`: an issued, stored response, its full conversation as of this turn and the raw response body.
struct Stored {
    id: String,
    conversation: Vec<Message>,
    body: String,
    estimated_size: u64,
}

impl Stored {
    fn new(id: &str, conversation: Vec<Message>, body: &str) -> Stored {
        Stored { id: id.to_string(), conversation, body: body.to_string(), estimated_size: 0 }
    }
}

struct Entries {
    /// Most recently used last.
    stored: Vec<Stored>,
    total_bytes: u64,
    /// 0: only the count bound.
    max_size_in_bytes: u64,
}

/// The store; the process holds one ([`STORE`]), tests build their own.
pub struct ResponsesStore {
    max_responses: usize,
    entries: Mutex<Entries>,
}

static STORE: LazyLock<ResponsesStore> = LazyLock::new(|| ResponsesStore::new(MAX_RESPONSES));

impl ResponsesStore {
    fn new(max_responses: usize) -> ResponsesStore {
        ResponsesStore { max_responses, entries: Mutex::new(Entries { stored: Vec::new(), total_bytes: 0, max_size_in_bytes: 0 }) }
    }

    /// [`ResponsesStore::put_chained`] with no previous response, as the tests store one.
    #[cfg(test)]
    fn put(&self, record: Stored) {
        self.put_chained(record, None);
    }

    /// `put(record, chainedFrom)`: charges the byte budget only for the messages `record` does not share with the
    /// response its request chained from (`get(previousId)`, which makes that one most recently used first).
    fn put_chained(&self, mut record: Stored, previous_id: Option<&str>) {
        if record.id.is_empty() {
            return;
        }
        let mut entries = self.entries.lock();
        let chained_from = previous_id.and_then(|id| touch(&mut entries.stored, id));
        record.estimated_size = estimated_size(&record, chained_from.map(|i| &entries.stored[i]));
        if let Some(i) = entries.stored.iter().position(|s| s.id == record.id) {
            let replaced = entries.stored.remove(i);
            entries.total_bytes -= replaced.estimated_size;
        }
        entries.total_bytes += record.estimated_size;
        entries.stored.push(record);
        self.evict_over_bounds(&mut entries);
    }

    /// `get`: the stored conversation, the response made most recently used.
    fn get(&self, id: &str) -> Option<Vec<Message>> {
        self.read(id, |s| s.conversation.clone())
    }

    fn read<R>(&self, id: &str, f: impl FnOnce(&Stored) -> R) -> Option<R> {
        if id.is_empty() {
            return None;
        }
        let mut entries = self.entries.lock();
        let i = touch(&mut entries.stored, id)?;
        Some(f(&entries.stored[i]))
    }

    /// `setMaxSizeInBytes`: bounds the total estimated size (0 leaves only the count bound); a lower budget evicts
    /// least recently used responses at once.
    fn set_max_size_in_bytes(&self, max_size_in_bytes: u64) {
        let mut entries = self.entries.lock();
        entries.max_size_in_bytes = max_size_in_bytes;
        self.evict_over_bounds(&mut entries);
    }

    #[cfg(test)]
    fn max_size_in_bytes(&self) -> u64 {
        self.entries.lock().max_size_in_bytes
    }

    #[cfg(test)]
    fn total_bytes(&self) -> u64 {
        self.entries.lock().total_bytes
    }

    #[cfg(test)]
    fn size(&self) -> usize {
        self.entries.lock().stored.len()
    }

    fn reset(&self) {
        let mut entries = self.entries.lock();
        entries.stored.clear();
        entries.total_bytes = 0;
    }

    /// `evictOverBounds`: the most recently stored response is kept even when it alone exceeds the byte budget, so
    /// the turn a client chains from next is never the one evicted.
    fn evict_over_bounds(&self, entries: &mut Entries) {
        while entries.stored.len() > 1
            && (entries.stored.len() > self.max_responses || (entries.max_size_in_bytes > 0 && entries.total_bytes > entries.max_size_in_bytes))
        {
            let evicted = entries.stored.remove(0);
            entries.total_bytes -= evicted.estimated_size;
        }
    }

    /// `recordIfStored`: the response (by the `id` in its body) with the conversation so far and its reply.
    fn record_if_stored(&self, request_body: &str, chained: Vec<Message>, completion: &super::Completion, encoded: &str) {
        if field(request_body, "store").and_then(|v| v.as_bool()) == Some(false) {
            return;
        }
        let Some(id) = text_field(encoded, "id") else { return };
        let mut conversation = chained;
        drop_leading_instructions(request_body, &mut conversation);
        // `assistantMessage`: the tool calls carry the `call_id` issued in the encoded body, so a chained turn's
        // `function_call_output` correlates to them.
        let issued = issued_tool_calls(encoded);
        conversation.push(Message {
            role: Role::Assistant,
            text: completion.text.clone().unwrap_or_default(),
            tool_calls: if issued.is_empty() {
                completion.tool_calls.iter().map(|t| ToolCall { id: t.id.clone(), name: t.name.clone(), arguments: t.arguments.clone().unwrap_or_default() }).collect()
            } else {
                issued
            },
            tool_results: Vec::new(),
        });
        let previous_id = text_field(request_body, "previous_response_id");
        self.put_chained(Stored::new(&id, conversation, encoded), previous_id.as_deref());
    }
}

/// Moves the response `id` to the most recently used end; its new index.
fn touch(stored: &mut Vec<Stored>, id: &str) -> Option<usize> {
    let i = stored.iter().position(|s| s.id == id)?;
    let entry = stored.remove(i);
    stored.push(entry);
    Some(stored.len() - 1)
}

/// `estimatedSize(record, chainedFrom)`: the entry overhead and the body, and per message its reference, plus, unless
/// the message is one of `chained_from`'s, the message overhead and the characters it holds. Upstream recognises those
/// by identity; here they are the chained-from conversation where the codec's decode puts it, at the start or after
/// the request's `instructions`.
fn estimated_size(record: &Stored, chained_from: Option<&Stored>) -> u64 {
    let mut size = ENTRY_OVERHEAD_BYTES + length(&record.body);
    let shared = chained_from.map(|c| shared_range(&record.conversation, &c.conversation)).unwrap_or(0..0);
    for (i, message) in record.conversation.iter().enumerate() {
        size += MESSAGE_REFERENCE_BYTES;
        if shared.contains(&i) {
            continue;
        }
        size += MESSAGE_OVERHEAD_BYTES + length(&message.text);
        for call in &message.tool_calls {
            size += call.id.as_deref().map_or(0, length) + length(&call.name) + length(&call.arguments);
        }
        for (key, value) in &message.tool_results {
            size += length(key) + length(value);
        }
    }
    size
}

/// Where `prior` sits in `conversation` as the decode prepends it: at index 0, or 1 behind a leading instructions
/// message.
fn shared_range(conversation: &[Message], prior: &[Message]) -> std::ops::Range<usize> {
    if prior.is_empty() {
        return 0..0;
    }
    for offset in [0, 1] {
        if conversation.get(offset..offset + prior.len()) == Some(prior) {
            return offset..offset + prior.len();
        }
    }
    0..0
}

/// `String.length()`: UTF-16 code units.
fn length(value: &str) -> u64 {
    value.encode_utf16().count() as u64
}

fn field(body: &str, key: &str) -> Option<Value> {
    serde_json::from_str::<Value>(body).ok()?.get(key).filter(|v| !v.is_null()).cloned()
}

fn text_field(body: &str, key: &str) -> Option<String> {
    field(body, key).map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string)).filter(|i| !i.is_empty())
}

/// `priorMessagesFor`: the conversation the request's `previous_response_id` names, oldest first.
pub fn prior_messages(body: &str) -> Vec<Message> {
    let Some(id) = text_field(body, "previous_response_id") else { return Vec::new() };
    STORE.get(&id).unwrap_or_default()
}

/// `Configuration.maxOpenAiResponsesSizeInBytes` of the server recording a response, as `HttpState` sets it on the
/// process's store at start and on every configuration update. Each record applies it too, so with several servers
/// in one process a response is evicted by the budget of the server that stored it last, whichever server started
/// last.
pub fn apply_configuration(config: &crate::config::Config) {
    STORE.set_max_size_in_bytes(crate::config::max_open_ai_responses_size_in_bytes(config));
}

/// `recordIfStored`: the response (by the `id` in its body) with the conversation so far and its reply.
pub fn record_if_stored(config: &crate::config::Config, request_body: &str, chained: Vec<Message>, completion: &super::Completion, encoded: &str) {
    apply_configuration(config);
    STORE.record_if_stored(request_body, chained, completion, encoded);
}

/// `recordStreamedIfStored`: as [`record_if_stored`] for a streamed turn, the stored body being the response object
/// of the stream's `response.completed` event (what `GET …/responses/{id}` returns for it). Recorded from the full
/// stream, before chaos truncation.
pub fn record_streamed_if_stored(config: &crate::config::Config, request_body: &str, chained: Vec<Message>, completion: &super::Completion, events: &[crate::action::SseEvent]) {
    // `response.completed` ends the stream, so search from the end and parse only candidates
    for data in events.iter().rev().filter_map(|e| e.data.as_deref()).filter(|d| d.contains("response.completed")) {
        let Ok(data) = serde_json::from_str::<Value>(data) else { return };
        if data.get("type").and_then(Value::as_str) == Some("response.completed") && let Some(response) = data.get("response").filter(|r| r.is_object()) {
            record_if_stored(config, request_body, chained, completion, &response.to_string());
            return;
        }
    }
}

/// `dropLeadingInstructions`: the request's `instructions` (decoded as a leading system message) are not carried
/// over to a chained turn, so they are not stored.
fn drop_leading_instructions(request_body: &str, messages: &mut Vec<Message>) {
    if messages.first().is_none_or(|m| m.role != Role::System) {
        return;
    }
    if field(request_body, "instructions").as_ref().and_then(Value::as_str) == Some(messages[0].text.as_str()) {
        messages.remove(0);
    }
}

/// `issuedToolCalls`: the `function_call` items of the encoded body, with the `call_id` each was issued.
fn issued_tool_calls(encoded: &str) -> Vec<ToolCall> {
    let Ok(root) = serde_json::from_str::<Value>(encoded) else { return Vec::new() };
    let Some(output) = root.get("output").and_then(Value::as_array) else { return Vec::new() };
    output
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
        .map(|item| {
            let text = |k: &str, default: &str| item.get(k).and_then(Value::as_str).unwrap_or(default).to_string();
            let call_id = text("call_id", "");
            ToolCall { id: (!call_id.is_empty()).then_some(call_id), name: text("name", ""), arguments: text("arguments", "{}") }
        })
        .collect()
}

/// `retrievalResponseOrNull`: the stored body a `GET …/responses/{id}` asks for.
pub fn retrieve(method: &str, path: &str) -> Option<String> {
    if !method.eq_ignore_ascii_case("GET") {
        return None;
    }
    static PATH: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(?:^|/)responses/([^/?#]+)$").expect("valid"));
    let id = PATH.captures(path)?.get(1)?.as_str().to_string();
    STORE.read(&id, |s| s.body.clone())
}

pub fn reset() {
    STORE.reset();
}

/// `OpenAiResponsesStoreByteBudgetTest` (mockserver-core): the byte budget, each test on a store of its own.
#[cfg(test)]
mod tests {
    use super::*;

    fn message(role: Role, text: &str) -> Message {
        Message { role, text: text.to_string(), tool_calls: Vec::new(), tool_results: Vec::new() }
    }

    fn response(id: &str, body: &str) -> Stored {
        Stored::new(id, vec![message(Role::User, "hello"), message(Role::Assistant, "hi")], body)
    }

    fn body(id: &str) -> String {
        format!("{{\"id\":\"{id}\",\"tools\":\"{}\"}}", "t".repeat(50_000))
    }

    fn size_of(id: &str) -> u64 {
        estimated_size(&response(id, &body(id)), None)
    }

    #[test]
    fn weighs_the_echoed_body_and_the_conversation() {
        let size = size_of("resp_1");

        assert!(size > body("resp_1").len() as u64);
        assert!(size <= body("resp_1").len() as u64 + 1_000);
    }

    #[test]
    fn evicts_least_recently_used_once_over_the_byte_budget() {
        let store = ResponsesStore::new(10_000);
        store.set_max_size_in_bytes(2 * size_of("resp_1") + 100);

        store.put(response("resp_1", &body("resp_1")));
        store.put(response("resp_2", &body("resp_2")));
        store.put(response("resp_3", &body("resp_3")));

        assert!(store.get("resp_1").is_none());
        assert!(store.get("resp_2").is_some());
        assert!(store.get("resp_3").is_some());
        assert!(store.total_bytes() <= store.max_size_in_bytes());
    }

    #[test]
    fn reading_a_response_makes_it_most_recently_used() {
        let store = ResponsesStore::new(10_000);
        store.set_max_size_in_bytes(2 * size_of("resp_1") + 100);

        store.put(response("resp_1", &body("resp_1")));
        store.put(response("resp_2", &body("resp_2")));
        store.get("resp_1");
        store.put(response("resp_3", &body("resp_3")));

        assert!(store.get("resp_1").is_some());
        assert!(store.get("resp_2").is_none());
    }

    #[test]
    fn keeps_the_most_recent_response_even_when_it_alone_exceeds_the_budget() {
        let store = ResponsesStore::new(10_000);
        store.set_max_size_in_bytes(1_000);

        store.put(response("resp_1", &body("resp_1")));
        store.put(response("resp_2", &body("resp_2")));

        assert_eq!(store.size(), 1);
        assert!(store.get("resp_2").is_some());
        assert_eq!(store.total_bytes(), size_of("resp_2"));
    }

    #[test]
    fn lowering_the_budget_evicts_at_once() {
        let store = ResponsesStore::new(10_000);
        for i in 0..5 {
            store.put(response(&format!("resp_{i}"), &body(&format!("resp_{i}"))));
        }
        assert_eq!(store.size(), 5);

        store.set_max_size_in_bytes(2 * size_of("resp_1") + 100);

        assert_eq!(store.size(), 2);
        assert!(store.get("resp_3").is_some());
        assert!(store.get("resp_4").is_some());
    }

    #[test]
    fn zero_budget_bounds_by_count_only() {
        let store = ResponsesStore::new(3);
        store.set_max_size_in_bytes(0);

        for i in 0..5 {
            store.put(response(&format!("resp_{i}"), &body(&format!("resp_{i}"))));
        }

        assert_eq!(store.size(), 3);
        assert!(store.get("resp_1").is_none());
        assert!(store.get("resp_2").is_some());
        assert_eq!(store.total_bytes(), 3 * size_of("resp_1"));
    }

    #[test]
    fn replacing_a_response_recharges_it() {
        let store = ResponsesStore::new(10_000);

        store.put(response("resp_1", &body("resp_1")));
        store.put(response("resp_1", "{\"id\":\"resp_1\"}"));

        assert_eq!(store.size(), 1);
        assert_eq!(store.total_bytes(), estimated_size(&response("resp_1", "{\"id\":\"resp_1\"}"), None));
    }

    #[test]
    fn reset_releases_the_charged_bytes() {
        let store = ResponsesStore::new(10_000);
        store.put(response("resp_1", &body("resp_1")));

        store.reset();

        assert_eq!(store.size(), 0);
        assert_eq!(store.total_bytes(), 0);
    }

    #[test]
    fn chained_turn_is_charged_only_for_the_messages_it_adds() {
        let store = ResponsesStore::new(10_000);
        let long_tool_output = "o".repeat(20_000);
        let completion = crate::llm::Completion::default();
        store.record_if_stored("{\"input\":\"first\"}", vec![message(Role::User, &long_tool_output)], &completion, "{\"id\":\"resp_1\"}");
        let after_first = store.total_bytes();
        assert!(after_first > 20_000);

        // the codec's decode of a chained turn starts with the stored turn's messages
        let mut chained = store.get("resp_1").unwrap();
        chained.push(message(Role::User, "next"));
        store.record_if_stored("{\"input\":\"next\",\"previous_response_id\":\"resp_1\"}", chained, &completion, "{\"id\":\"resp_2\"}");

        let charged_for_second = store.total_bytes() - after_first;
        assert!(charged_for_second <= 2_000);
    }

    /// Not upstream's: a chained turn behind a request's (array-valued, so kept) instructions message is still
    /// charged only for what it adds, as the decode puts the prior conversation after it.
    #[test]
    fn chained_turn_behind_instructions_is_charged_only_for_the_messages_it_adds() {
        let store = ResponsesStore::new(10_000);
        let completion = crate::llm::Completion::default();
        store.record_if_stored("{\"input\":\"first\"}", vec![message(Role::User, &"o".repeat(20_000))], &completion, "{\"id\":\"resp_1\"}");
        let after_first = store.total_bytes();

        let mut chained = vec![message(Role::System, "be brief")];
        chained.extend(store.get("resp_1").unwrap());
        chained.push(message(Role::User, "next"));
        store.record_if_stored("{\"input\":\"next\",\"previous_response_id\":\"resp_1\"}", chained, &completion, "{\"id\":\"resp_2\"}");

        assert!(store.total_bytes() - after_first <= 2_000);
    }
}

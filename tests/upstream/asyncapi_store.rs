//! `BoundedMessageStoreTest` and `MqttTopicFilterTest` (mockserver-async): a channel's consumed messages and MQTT
//! topic filters (MQTT 3.1.1 §4.7).

use mock_server::asyncapi::store::{
    BoundedMessageStore, ConsumedMessage, ConsumedMessages, DEFAULT_MAX_RECORDED_MESSAGES, contains_wildcard, is_valid_filter, topic_matches,
};

fn msg(channel: &str, payload: &str) -> ConsumedMessage {
    ConsumedMessage::new(channel, None, Some(payload.to_string()), Vec::new())
}

fn payload(m: &ConsumedMessage) -> &str {
    m.payload.as_deref().unwrap_or_default()
}

// ---- BoundedMessageStoreTest ----

#[test]
fn should_store_messages_up_to_capacity() {
    let store = BoundedMessageStore::new(3).unwrap();
    store.add(msg("ch", "p0"));
    store.add(msg("ch", "p1"));
    store.add(msg("ch", "p2"));
    assert_eq!(store.size(), 3);
    let snapshot = store.snapshot();
    assert_eq!(snapshot.len(), 3);
    assert_eq!(payload(&snapshot[0]), "p0");
    assert_eq!(payload(&snapshot[2]), "p2");
}

#[test]
fn should_evict_oldest_when_cap_reached() {
    let store = BoundedMessageStore::new(3).unwrap();
    for p in ["p0", "p1", "p2", "p3", "p4"] {
        store.add(msg("ch", p));
    }
    assert_eq!(store.size(), 3);
    let snapshot = store.snapshot();
    assert_eq!(snapshot.iter().map(payload).collect::<Vec<_>>(), ["p2", "p3", "p4"]);
}

#[test]
fn should_return_empty_snapshot_when_empty() {
    let store = BoundedMessageStore::new(10).unwrap();
    assert!(store.snapshot().is_empty());
    assert_eq!(store.size(), 0);
}

#[test]
fn should_clear_all_messages() {
    let store = BoundedMessageStore::new(10).unwrap();
    store.add(msg("ch", "p0"));
    store.add(msg("ch", "p1"));
    store.clear();
    assert_eq!(store.size(), 0);
    assert!(store.snapshot().is_empty());
}

#[test]
fn snapshot_should_be_independent_of_store() {
    let store = BoundedMessageStore::new(10).unwrap();
    store.add(msg("ch", "p0"));
    let snapshot = store.snapshot();
    store.add(msg("ch", "p1"));
    assert_eq!(snapshot.len(), 1, "the snapshot does not reflect the newly added message");
    assert_eq!(store.size(), 2);
}

#[test]
fn should_reject_zero_max_size() {
    assert_eq!(BoundedMessageStore::new(0).unwrap_err(), "maxSize must be positive, got: 0");
}

/// A `usize` capacity cannot be negative; a negative `maxRecordedMessages` reaches the store through a subscriber's
/// consumed messages (`subscribe` makes the channel's store), which fail as the constructor does.
#[test]
fn should_reject_negative_max_size() {
    assert_eq!(ConsumedMessages::new(-1).ensure("ch").unwrap_err(), "maxSize must be positive, got: -1");
}

#[test]
fn should_work_with_capacity_of_one() {
    let store = BoundedMessageStore::new(1).unwrap();
    store.add(msg("ch", "p0"));
    assert_eq!(payload(&store.snapshot()[0]), "p0");
    store.add(msg("ch", "p1"));
    assert_eq!(store.size(), 1);
    assert_eq!(payload(&store.snapshot()[0]), "p1");
}

#[test]
fn should_use_default_capacity() {
    let store = BoundedMessageStore::default();
    for i in 0..DEFAULT_MAX_RECORDED_MESSAGES + 10 {
        store.add(msg("ch", &format!("p{i}")));
    }
    assert_eq!(store.size(), DEFAULT_MAX_RECORDED_MESSAGES);
    assert_eq!(payload(&store.snapshot()[0]), "p10", "the oldest 10 were evicted");
}

// ---- MqttTopicFilterTest ----

fn assert_matches(filter: &str, topic: &str) {
    assert!(topic_matches(filter, topic), "filter '{filter}' should match topic '{topic}'");
}

fn assert_does_not_match(filter: &str, topic: &str) {
    assert!(!topic_matches(filter, topic), "filter '{filter}' should NOT match topic '{topic}'");
}

#[test]
fn should_match_identical_topic() {
    assert_matches("sport/tennis/player1", "sport/tennis/player1");
    assert_does_not_match("sport/tennis/player1", "sport/tennis/player2");
}

#[test]
fn multi_level_wildcard_should_match_descendants() {
    assert_matches("sport/tennis/player1/#", "sport/tennis/player1");
    assert_matches("sport/tennis/player1/#", "sport/tennis/player1/ranking");
    assert_matches("sport/tennis/player1/#", "sport/tennis/player1/score/wimbledon");
}

#[test]
fn multi_level_wildcard_should_include_the_parent_level() {
    assert_matches("sport/#", "sport");
    assert_matches("sport/#", "sport/tennis");
}

#[test]
fn lone_multi_level_wildcard_should_match_every_topic() {
    assert_matches("#", "sport");
    assert_matches("#", "sport/tennis/player1");
    assert_matches("#", "a");
}

#[test]
fn multi_level_wildcard_should_not_match_a_sibling_prefix() {
    assert_does_not_match("sport/tennis/#", "sport/tennisball");
    assert_does_not_match("sport/#", "sportsdirect");
}

#[test]
fn single_level_wildcard_should_match_exactly_one_level() {
    assert_matches("sport/tennis/+", "sport/tennis/player1");
    assert_matches("sport/tennis/+", "sport/tennis/player2");
    assert_does_not_match("sport/tennis/+", "sport/tennis/player1/ranking");
}

#[test]
fn single_level_wildcard_should_not_match_the_parent_level() {
    assert_does_not_match("sport/+", "sport");
    assert_matches("sport/+", "sport/");
}

#[test]
fn lone_single_level_wildcard_should_match_only_top_level_topics() {
    assert_matches("+", "sport");
    assert_does_not_match("+", "sport/tennis");
}

#[test]
fn single_level_wildcard_should_match_at_any_position() {
    assert_matches("+/tennis/#", "sport/tennis/player1");
    assert_matches("sport/+/player1", "sport/tennis/player1");
}

#[test]
fn wildcard_should_not_match_reserved_dollar_topics() {
    assert_does_not_match("#", "$SYS/broker/uptime");
    assert_does_not_match("+/monitor/clients", "$SYS/monitor/clients");
}

#[test]
fn explicit_dollar_prefix_should_match_reserved_topics() {
    assert_matches("$SYS/#", "$SYS/broker/uptime");
    assert_matches("$SYS/monitor/+", "$SYS/monitor/clients");
    assert_matches("$SYS/broker/uptime", "$SYS/broker/uptime");
}

#[test]
fn malformed_filters_should_not_match() {
    // '#' must occupy an entire level and be last.
    assert_does_not_match("sport/tennis#", "sport/tennis/player1");
    assert_does_not_match("sport/#/ranking", "sport/tennis/ranking");
    // '+' must occupy an entire level.
    assert_does_not_match("sport+", "sport/tennis");
}

/// `isValidFilter(null)` has no Rust counterpart (a `&str` is never null).
#[test]
fn should_report_filter_validity() {
    assert!(is_valid_filter("sport/+/player1"));
    assert!(is_valid_filter("sport/#"));
    assert!(is_valid_filter("#"));
    assert!(!is_valid_filter("sport/tennis#"));
    assert!(!is_valid_filter("sport/#/ranking"));
    assert!(!is_valid_filter("sport+"));
    assert!(!is_valid_filter(""));
}

/// `containsWildcard(null)` has no Rust counterpart (a `&str` is never null).
#[test]
fn should_detect_wildcard_presence() {
    assert!(!contains_wildcard("sport/tennis"));
    assert!(contains_wildcard("sport/+"));
    assert!(contains_wildcard("sport/#"));
}

/// A `&str` is never null; the nearest inputs are empty filters and topics, which match nothing else either.
#[test]
fn should_handle_nulls_without_matching() {
    assert!(!topic_matches("", "sport"));
    assert!(!topic_matches("sport", ""));
}

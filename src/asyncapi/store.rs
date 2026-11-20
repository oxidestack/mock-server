//! What subscribers keep of what they consume (upstream's `RecordedMessage`, one `BoundedMessageStore` per
//! channel) and `MqttTopicFilter`.

use std::collections::VecDeque;
use std::time::SystemTime;

use parking_lot::Mutex;

/// `BoundedMessageStore.DEFAULT_MAX_RECORDED_MESSAGES`.
pub const DEFAULT_MAX_RECORDED_MESSAGES: usize = 1000;

/// `RecordedMessage`: a message a subscriber consumed, stamped when it arrived.
#[derive(Clone, Debug)]
pub struct ConsumedMessage {
    pub channel: String,
    pub key: Option<String>,
    pub payload: Option<String>,
    /// In arrival order; a repeated name keeps its first position and its last value (`LinkedHashMap.put`).
    pub headers: Vec<(String, Option<String>)>,
    pub timestamp: SystemTime,
}

impl ConsumedMessage {
    pub fn new(channel: &str, key: Option<String>, payload: Option<String>, headers: Vec<(String, Option<String>)>) -> Self {
        let mut merged: Vec<(String, Option<String>)> = Vec::with_capacity(headers.len());
        for (name, value) in headers {
            match merged.iter_mut().find(|(n, _)| *n == name) {
                Some(existing) => existing.1 = value,
                None => merged.push((name, value)),
            }
        }
        ConsumedMessage { channel: channel.to_string(), key, payload, headers: merged, timestamp: SystemTime::now() }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).and_then(|(_, v)| v.as_deref())
    }

    /// `Instant.toString()`: ISO-8601 in UTC with the fraction in groups of three digits, trailing zero groups
    /// dropped.
    pub fn timestamp_text(&self) -> String {
        instant_text(self.timestamp)
    }
}

/// `Instant.toString()` of a system time.
pub fn instant_text(time: SystemTime) -> String {
    let since = time.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    // Java's clock on Linux ticks in microseconds.
    let micros = since.subsec_micros();
    let at = chrono::DateTime::<chrono::Utc>::from_timestamp(since.as_secs() as i64, 0).unwrap_or_default();
    let base = at.format("%Y-%m-%dT%H:%M:%S").to_string();
    if micros == 0 {
        format!("{base}Z")
    } else if micros.is_multiple_of(1000) {
        format!("{base}.{:03}Z", micros / 1000)
    } else {
        format!("{base}.{micros:06}Z")
    }
}

/// `BoundedMessageStore`: the newest `max` messages of one channel.
#[derive(Debug)]
pub struct BoundedMessageStore {
    max: usize,
    messages: Mutex<VecDeque<ConsumedMessage>>,
}

impl BoundedMessageStore {
    pub fn new(max: usize) -> Result<Self, String> {
        if max == 0 {
            return Err("maxSize must be positive, got: 0".into());
        }
        Ok(BoundedMessageStore { max, messages: Mutex::new(VecDeque::new()) })
    }

    pub fn add(&self, message: ConsumedMessage) {
        let mut messages = self.messages.lock();
        if messages.len() >= self.max {
            messages.pop_front();
        }
        messages.push_back(message);
    }

    pub fn snapshot(&self) -> Vec<ConsumedMessage> {
        self.messages.lock().iter().cloned().collect()
    }

    pub fn size(&self) -> usize {
        self.messages.lock().len()
    }

    pub fn clear(&self) {
        self.messages.lock().clear();
    }
}

/// `new BoundedMessageStore()`: [`DEFAULT_MAX_RECORDED_MESSAGES`] messages.
impl Default for BoundedMessageStore {
    fn default() -> Self {
        BoundedMessageStore { max: DEFAULT_MAX_RECORDED_MESSAGES, messages: Mutex::new(VecDeque::new()) }
    }
}

/// A subscriber's consumed messages: one store per channel (or concrete MQTT topic), in the order they appeared.
#[derive(Debug)]
pub struct ConsumedMessages {
    max: i64,
    stores: Mutex<Vec<(String, std::sync::Arc<BoundedMessageStore>)>>,
}

impl ConsumedMessages {
    pub fn new(max: i64) -> Self {
        ConsumedMessages { max, stores: Mutex::new(Vec::new()) }
    }

    fn capacity(&self) -> Result<usize, String> {
        if self.max <= 0 {
            return Err(format!("maxSize must be positive, got: {}", self.max));
        }
        Ok(self.max as usize)
    }

    /// `putIfAbsent(channel, new BoundedMessageStore(max))`: fails as the constructor does for a non-positive size.
    pub fn ensure(&self, channel: &str) -> Result<(), String> {
        let capacity = self.capacity()?;
        let mut stores = self.stores.lock();
        if !stores.iter().any(|(c, _)| c == channel) {
            stores.push((channel.to_string(), std::sync::Arc::new(BoundedMessageStore::new(capacity)?)));
        }
        Ok(())
    }

    /// `computeIfAbsent(channel, …).add(message)`.
    pub fn record(&self, message: ConsumedMessage) {
        let Ok(capacity) = self.capacity() else { return };
        let store = {
            let mut stores = self.stores.lock();
            match stores.iter().find(|(c, _)| *c == message.channel) {
                Some((_, s)) => s.clone(),
                None => {
                    let Ok(store) = BoundedMessageStore::new(capacity) else { return };
                    let store = std::sync::Arc::new(store);
                    stores.push((message.channel.clone(), store.clone()));
                    store
                }
            }
        };
        store.add(message);
    }

    /// The messages recorded under exactly this channel.
    pub fn exact(&self, channel: &str) -> Vec<ConsumedMessage> {
        self.stores.lock().iter().find(|(c, _)| c == channel).map(|(_, s)| s.snapshot()).unwrap_or_default()
    }

    /// The messages of every store whose name `filter` matches, oldest first (`MqttMessageSubscriber`).
    pub fn matching(&self, filter: &str) -> Vec<ConsumedMessage> {
        let mut out: Vec<ConsumedMessage> = self.stores.lock().iter().filter(|(c, _)| topic_matches(filter, c)).flat_map(|(_, s)| s.snapshot()).collect();
        out.sort_by_key(|m| m.timestamp);
        out
    }

    /// `getAllRecordedMessages`: every store's messages, oldest first.
    pub fn all(&self) -> Vec<ConsumedMessage> {
        let mut out: Vec<ConsumedMessage> = self.stores.lock().iter().flat_map(|(_, s)| s.snapshot()).collect();
        out.sort_by_key(|m| m.timestamp);
        out
    }

    pub fn clear(&self) {
        self.stores.lock().clear();
    }
}

/// `MqttTopicFilter.containsWildcard`.
pub fn contains_wildcard(filter: &str) -> bool {
    filter.contains(['+', '#'])
}

/// `MqttTopicFilter.isValidFilter`: `#` only as the whole last level, `+` only as a whole level.
pub fn is_valid_filter(filter: &str) -> bool {
    if filter.is_empty() {
        return false;
    }
    let levels: Vec<&str> = filter.split('/').collect();
    levels.iter().enumerate().all(|(i, level)| {
        !(level.contains('#') && (*level != "#" || i != levels.len() - 1)) && !(level.contains('+') && *level != "+")
    })
}

/// `MqttTopicFilter.matches` (MQTT 3.1.1 §4.7): whether a concrete topic falls under a filter.
pub fn topic_matches(filter: &str, topic: &str) -> bool {
    if filter == topic {
        return true;
    }
    if !contains_wildcard(filter) || !is_valid_filter(filter) {
        return false;
    }
    let filter_levels: Vec<&str> = filter.split('/').collect();
    let topic_levels: Vec<&str> = topic.split('/').collect();
    if topic_levels[0].starts_with('$') && matches!(filter_levels[0], "+" | "#") {
        return false;
    }
    for (i, level) in filter_levels.iter().enumerate() {
        if *level == "#" {
            return true;
        }
        let Some(topic_level) = topic_levels.get(i) else { return false };
        if *level != "+" && level != topic_level {
            return false;
        }
    }
    filter_levels.len() == topic_levels.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty levels are levels too (the MQTT 3.1.1 §4.7.1.3 examples `+/+` and `/+` against `/finance`).
    #[test]
    fn empty_levels_are_levels() {
        assert!(topic_matches("+/+", "/finance"));
        assert!(topic_matches("/+", "/finance"));
        assert!(!topic_matches("+", "/finance"));
    }

    #[test]
    fn instant_text_trims_groups() {
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_micros(1_500_000);
        assert_eq!(instant_text(t), "1970-01-01T00:00:01.500Z");
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_micros(1_000_001);
        assert_eq!(instant_text(t), "1970-01-01T00:00:01.000001Z");
        assert_eq!(instant_text(SystemTime::UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }
}

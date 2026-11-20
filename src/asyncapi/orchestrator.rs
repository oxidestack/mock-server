//! `AsyncApiMockOrchestrator`: publishes each channel's example messages through a publisher, once or on a
//! fixed-rate schedule, injecting generated correlation ids where a message's `correlationId.location` says.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::Value;

use super::broker::{Counters, Error, PublishOptions, Publisher};
use super::spec::{Channel, Message, Spec};

const HEADER_LOCATION_PREFIX: &str = "$message.header#/";
const PAYLOAD_LOCATION_PREFIX: &str = "$message.payload#";

type IdSupplier = Arc<dyn Fn() -> String + Send + Sync>;

/// A running schedule: its stop signal and task.
struct Schedule {
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

pub struct Orchestrator {
    spec: Arc<Spec>,
    publisher: Arc<dyn Publisher>,
    counters: Counters,
    correlation_ids: IdSupplier,
    last_failure: Arc<Mutex<Option<String>>>,
    schedule: Mutex<Option<Schedule>>,
}

impl Orchestrator {
    pub fn new(spec: Arc<Spec>, publisher: Arc<dyn Publisher>, counters: Counters) -> Self {
        Orchestrator::with_correlation_ids(spec, publisher, counters, Arc::new(|| uuid::Uuid::new_v4().to_string()))
    }

    /// With a fixed correlation-id supplier (upstream's test constructor).
    pub fn with_correlation_ids(spec: Arc<Spec>, publisher: Arc<dyn Publisher>, counters: Counters, correlation_ids: IdSupplier) -> Self {
        Orchestrator { spec, publisher, counters, correlation_ids, last_failure: Arc::new(Mutex::new(None)), schedule: Mutex::new(None) }
    }

    /// `publishAll`: every message of every channel; a failing message does not stop the others. Delivery is
    /// confirmed (`flush`) before the published channels are counted.
    pub async fn publish_all(&self) -> Result<(), Error> {
        publish_all(&self.spec, self.publisher.as_ref(), &self.counters, &self.correlation_ids).await
    }

    /// `startPublishing(intervalMillis)`: a cycle now and then every interval (fixed rate); a failed cycle is
    /// remembered and the next one retries.
    pub fn start_publishing(&self, interval_millis: u64) {
        let mut schedule = self.schedule.lock();
        if schedule.is_some() {
            return;
        }
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let (spec, publisher, counters, ids, last_failure) =
            (self.spec.clone(), self.publisher.clone(), self.counters.clone(), self.correlation_ids.clone(), self.last_failure.clone());
        let task = super::broker::spawn(async move {
            let mut ticks = tokio::time::interval(Duration::from_millis(interval_millis.max(1)));
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
            loop {
                tokio::select! {
                    _ = ticks.tick() => {}
                    _ = stopped.changed() => return,
                }
                if *stopped.borrow() {
                    return;
                }
                let outcome = publish_all(&spec, publisher.as_ref(), &counters, &ids).await;
                *last_failure.lock() = outcome.err().map(|e| e.message);
            }
        });
        *schedule = Some(Schedule { stop, task });
    }

    /// `getLastPublishFailure`.
    pub fn last_publish_failure(&self) -> Option<String> {
        self.last_failure.lock().clone()
    }

    /// `stop`: cancels the schedule and waits (up to 5 s) for a cycle in flight.
    pub async fn stop(&self) {
        let schedule = self.schedule.lock().take();
        if let Some(Schedule { stop, task }) = schedule {
            let _ = stop.send(true);
            super::broker::join_or_abort(Some(task), Duration::from_secs(5)).await;
        }
    }
}

/// `describe`: an exception's message, never a bare `null`.
fn describe(e: &Error) -> String {
    if e.message.trim().is_empty() { "RuntimeException".into() } else { e.message.clone() }
}

async fn publish_all(spec: &Spec, publisher: &dyn Publisher, counters: &Counters, ids: &IdSupplier) -> Result<(), Error> {
    let mut published: Vec<String> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for channel in &spec.channels {
        for message in channel.messages() {
            let mut payload = super::spec::example(&message.examples, message.payload_schema.as_ref());
            if payload.trim().is_empty() {
                continue;
            }
            let mut correlation_headers = Vec::new();
            if let Some(location) = &message.correlation_id_location {
                let id = ids();
                if let Some(header) = location.strip_prefix(HEADER_LOCATION_PREFIX) {
                    if !header.is_empty() {
                        correlation_headers.push((header.to_string(), id));
                    }
                } else if let Some(pointer) = location.strip_prefix(PAYLOAD_LOCATION_PREFIX) {
                    payload = inject_into_payload(&payload, pointer, &id);
                }
            }
            let options = publish_options(channel, &message, correlation_headers);
            match publisher.publish(&channel.name, &payload, &options).await {
                Ok(()) => published.push(channel.name.clone()),
                Err(e) => failures.push(format!("{}: {}", channel.name, describe(&e))),
            }
        }
    }
    if !published.is_empty() {
        match publisher.flush().await {
            Ok(()) => published.iter().for_each(|c| counters.published(c)),
            Err(e) => failures.push(format!("delivery confirmation failed: {}", describe(&e))),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Error::new(format!("Publish cycle completed with {} failure(s): {}", failures.len(), failures.join("; "))))
    }
}

/// `buildPublishOptions`: the message's Kafka key, the channel's MQTT bindings and the correlation headers.
fn publish_options(channel: &Channel, message: &Message, headers: Vec<(String, String)>) -> PublishOptions {
    PublishOptions { key: message.kafka_key.clone(), qos: channel.mqtt_qos, retain: channel.mqtt_retain, headers }
}

/// `injectIntoPayload`: sets the id at a JSON Pointer in an object payload, creating intermediate objects; any
/// other payload, an empty or root pointer, or a malformed one leaves the payload as it was.
pub fn inject_into_payload(payload: &str, pointer: &str, value: &str) -> String {
    if pointer.is_empty() || pointer == "/" || !pointer.starts_with('/') {
        return payload.to_string();
    }
    let Ok(mut root) = serde_json::from_str::<Value>(payload) else { return payload.to_string() };
    if !root.is_object() {
        return payload.to_string();
    }
    let segments: Vec<String> = pointer[1..].split('/').map(|s| s.replace("~1", "/").replace("~0", "~")).collect();
    let mut current = &mut root;
    for segment in &segments[..segments.len() - 1] {
        let object = current.as_object_mut().expect("an object");
        if !object.get(segment).is_some_and(Value::is_object) {
            object.insert(segment.clone(), Value::Object(serde_json::Map::new()));
        }
        current = object.get_mut(segment).expect("just inserted");
    }
    current.as_object_mut().expect("an object").insert(segments[segments.len() - 1].clone(), Value::String(value.to_string()));
    crate::model::jackson_tree(&root).to_string()
}

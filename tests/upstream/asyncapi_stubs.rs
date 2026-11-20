//! Stand-ins for the Mockito mocks and stubs of mockserver-async's unit tests: a publisher that remembers what it is
//! asked to do and can be told to fail or take its time, and a subscriber holding messages put into it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mock_server::asyncapi::broker::{BoxFuture, Error, PublishOptions, Publisher, Subscriber};
use mock_server::asyncapi::store::ConsumedMessage;
use parking_lot::Mutex;

/// The mocked `MessagePublisher`: each call is remembered; a channel can be told to fail, or the first calls.
#[derive(Default)]
pub struct StubPublisher {
    pub calls: Mutex<Vec<(String, String, PublishOptions)>>,
    pub flushes: AtomicUsize,
    pub closes: AtomicUsize,
    pub failing: Mutex<Vec<String>>,
    /// Fail this many calls first, whatever the channel.
    pub fail_first: AtomicUsize,
    pub delay: Mutex<Option<Duration>>,
}

impl Publisher for StubPublisher {
    fn publish<'a>(&'a self, channel: &'a str, payload: &'a str, options: &'a PublishOptions) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            let delay = *self.delay.lock();
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }
            self.calls.lock().push((channel.to_string(), payload.to_string(), options.clone()));
            let early = self.fail_first.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok();
            if early || self.failing.lock().iter().any(|c| c == channel) {
                return Err(Error::new("was not routed to any queue"));
            }
            Ok(())
        })
    }

    fn flush(&self) -> BoxFuture<'_, Result<(), Error>> {
        self.flushes.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {})
    }
}

/// `AsyncApiControlPlaneVerifyTest.StubSubscriber`: keeps the messages added to it per channel, in order, without a
/// broker; closing it drops them.
#[derive(Default)]
pub struct StubSubscriber {
    messages: Mutex<Vec<(String, Vec<ConsumedMessage>)>>,
    pub closes: AtomicUsize,
}

impl StubSubscriber {
    pub fn with(messages: Vec<ConsumedMessage>) -> Self {
        let stub = StubSubscriber::default();
        for m in messages {
            stub.add(m);
        }
        stub
    }

    pub fn add(&self, message: ConsumedMessage) {
        let mut channels = self.messages.lock();
        match channels.iter_mut().find(|(c, _)| *c == message.channel) {
            Some((_, list)) => list.push(message),
            None => channels.push((message.channel.clone(), vec![message])),
        }
    }
}

impl Subscriber for StubSubscriber {
    fn subscribe<'a>(&'a self, channel: &'a str) -> BoxFuture<'a, Result<(), Error>> {
        let mut channels = self.messages.lock();
        if !channels.iter().any(|(c, _)| c == channel) {
            channels.push((channel.to_string(), Vec::new()));
        }
        Box::pin(async { Ok(()) })
    }

    fn recorded(&self, channel: &str) -> Vec<ConsumedMessage> {
        self.messages.lock().iter().find(|(c, _)| c == channel).map(|(_, l)| l.clone()).unwrap_or_default()
    }

    fn all_recorded(&self) -> Vec<ConsumedMessage> {
        self.messages.lock().iter().flat_map(|(_, l)| l.clone()).collect()
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        self.messages.lock().clear();
        Box::pin(async {})
    }
}

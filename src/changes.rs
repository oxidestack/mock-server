//! A change signal: a counter that goes up whenever the event log or the expectations change, which the dashboard's
//! push channel waits on (upstream's `MockServerLogListener` / `MockServerMatcherListener`) instead of polling.

use tokio::sync::watch;

/// Cheap to bump from any thread; a subscriber sees that something changed since it last looked, not what.
pub struct ChangeSignal(watch::Sender<u64>);

impl Default for ChangeSignal {
    fn default() -> ChangeSignal {
        ChangeSignal(watch::channel(0).0)
    }
}

impl ChangeSignal {
    /// Announces a change to every subscriber.
    ///
    /// Without a subscriber it does nothing: a subscriber only waits for changes after it subscribed, and a send takes
    /// the channel's write lock and wakes its notifier shards, which every logged request paid once per entry, a
    /// measurable share of the CPU at INFO. A change racing a new subscription happened before it, and the subscriber
    /// reads the state afresh.
    pub fn touch(&self) {
        if self.0.receiver_count() == 0 {
            return;
        }
        self.0.send_modify(|version| *version = version.wrapping_add(1));
    }

    /// [`ChangeSignal::touch`] for `n` changes at once: the signal's value goes up by `n`, so a subscriber that counts
    /// changes (`outputMemoryUsageCsv`, once per expectation as upstream's matcher listener) sees each of them.
    pub fn touch_n(&self, n: u64) {
        if n == 0 || self.0.receiver_count() == 0 {
            return;
        }
        self.0.send_modify(|version| *version = version.wrapping_add(n));
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.subscribe()
    }
}

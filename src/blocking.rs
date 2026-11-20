//! Synchronous network reads made while a request is handled (a spec URL, an external `$ref`), and long synchronous
//! work (a queued template render, an RSA key's prime search): polled inline, such work holds up every timer and
//! socket of the runtime once its other workers are idle, since none of them turns the driver until it ends (a 10-million iteration Velocity loop stalled every replayed server's delays for 45 s).

/// Runs `f`, which blocks this thread on a socket or computes for long, without stalling the runtime. On a server's
/// multi-threaded runtime the worker first hands its queued tasks to another thread, so a document served by this
/// same server can still be answered (as the oracle does); otherwise the new connection's task would wait in this
/// worker's queue until the read times out. On a current-thread runtime, or outside one, `f` simply runs. Thread-locals
/// survive: `f` runs on the calling thread either way.
pub fn off_worker<R>(f: impl FnOnce() -> R) -> R {
    let multi_thread = tokio::runtime::Handle::try_current().is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
    if multi_thread { tokio::task::block_in_place(f) } else { f() }
}

/// The body size from which [`off_worker_when_large`] hands the worker on: canonicalising, matching and printing a
/// body is linear in its size, about a second per few MiB in an unoptimised build.
pub const LARGE_BODY: usize = 256 * 1024;

/// [`off_worker`] when `len` (the size of the body `f` works on) is [`LARGE_BODY`] or more, else `f` inline (a 10 MiB expectation's canonical body and a 10 MiB request's log entries stalled every timer of the process
/// for seconds).
pub fn off_worker_when_large<R>(len: usize, f: impl FnOnce() -> R) -> R {
    if len >= LARGE_BODY { off_worker(f) } else { f() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// On a one-worker runtime, a timer set before a large body's work fires on time while the work holds the thread;
    /// below the threshold the same work holds the worker and the timer waits for it.
    #[test]
    fn a_large_body_leaves_the_timers_running() {
        let lag = |len: usize| {
            let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
            runtime.block_on(async move {
                // The timer is spawned by the work task itself, just before the work: it cannot be polled (and its
                // deadline cannot start) until the work has begun, so a late-scheduled work task never loses the race.
                let (done, timer_done) = tokio::sync::oneshot::channel();
                tokio::spawn(async move {
                    let started = Instant::now();
                    let timer = tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        started.elapsed()
                    });
                    off_worker_when_large(len, || std::thread::sleep(Duration::from_millis(600)));
                    done.send(timer.await.unwrap()).unwrap();
                })
                .await
                .unwrap();
                timer_done.await.unwrap()
            })
        };
        let (large, small) = (lag(LARGE_BODY), lag(LARGE_BODY - 1));
        assert!(large < Duration::from_millis(400), "{large:?}");
        assert!(small >= Duration::from_millis(500), "{small:?}");
    }
}

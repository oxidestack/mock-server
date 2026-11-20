//! `Scheduler`'s overload bounds (upstream master b765b8271): the work a server holds waiting is bounded.
//! A delayed response, error, forward or callback (an action delay, `globalResponseDelayMillis`, a chaos latency) is
//! admitted while fewer than `maxPendingDelayedResponses` are waiting for their delays, else answered at once with the
//! [`refused`] 503; a template render likewise against `maxQueuedTemplateActions` renders waiting for a template
//! thread. An undelayed task is never refused. Three budgets of the same size are kept apart so that a backlog of one
//! kind never refuses another: delayed responses, delayed side actions, and WebSocket reply frames (a whole reply set
//! at a time). The limits are read on every admission, so `PUT /mockserver/configuration` applies at once; zero or less
//! is unbounded. Each refusal reason is logged at WARN at most once per 10 s, with the count refused since the last line.
//!
//! Blocking file reads (`staticFilesDirectory` files and matched `FILE` response bodies, upstream #35/#40) run on a
//! pool of their own, [`FILE_READ_THREADS`] threads with at most [`MAX_QUEUED_FILE_READS`] reads waiting for one, a
//! fixed limit: a read beyond it is refused (`static_files`, `file_bodies`) and answered with [`file_reads_refused`].

use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::reply::Reply;
use crate::state::State;

/// The body of the 503 a refused task is answered with (`HttpActionHandler.overloadResponse`).
pub const REFUSED_BODY: &str = "MockServer is overloaded, too many delayed or templated responses are already waiting";

const LOG_INTERVAL: Duration = Duration::from_secs(10);

/// `Scheduler.FILE_READ_THREADS`: the file reads that run at once.
pub const FILE_READ_THREADS: usize = 4;
/// `Scheduler.MAX_QUEUED_FILE_READS`: the file reads that may wait for a file read thread, a fixed limit.
pub const MAX_QUEUED_FILE_READS: usize = 1000;

/// `Scheduler.OverloadReason`: why a task was refused and what happened instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    DelayedResponses,
    DelaySkipped,
    SideActions,
    WebSocketReplies,
    TemplateActions,
    StaticFiles,
    FileBodies,
}

impl Reason {
    fn index(self) -> usize {
        self as usize
    }

    /// `metricLabel`: the `reason` label of `mock_server_overload_rejections`.
    fn metric_label(self) -> &'static str {
        match self {
            Reason::DelayedResponses => "delayed_responses",
            Reason::DelaySkipped => "delay_skipped",
            Reason::SideActions => "side_actions",
            Reason::WebSocketReplies => "websocket_replies",
            Reason::TemplateActions => "template_actions",
            Reason::StaticFiles => "static_files",
            Reason::FileBodies => "file_bodies",
        }
    }

    /// The configuration property whose limit was exceeded.
    fn property(self) -> &'static str {
        match self {
            Reason::TemplateActions => "maxQueuedTemplateActions",
            Reason::StaticFiles | Reason::FileBodies => "the file read queue",
            _ => "maxPendingDelayedResponses",
        }
    }

    /// `fixedLimit`: the limit is no property, so the WARN line does not advise raising one.
    fn fixed_limit(self) -> bool {
        matches!(self, Reason::StaticFiles | Reason::FileBodies)
    }

    fn description(self) -> &'static str {
        match self {
            Reason::DelayedResponses => "responses waiting for a configured delay",
            Reason::DelaySkipped => "forwarded responses waiting for chaos latency",
            Reason::SideActions => "delayed side actions (after-actions, secondary actions, step side effects)",
            Reason::WebSocketReplies => "WebSocket reply frames waiting for their delays",
            Reason::TemplateActions => "template renders waiting for a template thread",
            Reason::StaticFiles => "static file reads waiting for a file read thread",
            Reason::FileBodies => "FILE response body reads waiting for a file read thread",
        }
    }

    fn outcome(self) -> &'static str {
        match self {
            Reason::DelayedResponses | Reason::TemplateActions | Reason::StaticFiles | Reason::FileBodies => "answered 503 Service Unavailable",
            Reason::DelaySkipped => "sent at once without the injected latency",
            Reason::SideActions => "dropped",
            Reason::WebSocketReplies => "refused a whole reply set at a time, closing the WebSocket with 1013 Try Again Later",
        }
    }
}

/// `Scheduler.OverloadLog`: the refusals of one reason, and when the next WARN line may be written.
#[derive(Default)]
struct OverloadLog {
    total: AtomicU64,
    since_last_line: AtomicU64,
    /// Milliseconds since `Overload::epoch` before which no line is written; negative before the first line.
    next_line_at: AtomicI64,
}

/// The scheduler's admission state, one per server.
pub struct Overload {
    delayed_responses: Arc<AtomicUsize>,
    side_actions: Arc<AtomicUsize>,
    websocket_reply_frames: Arc<AtomicUsize>,
    /// `pendingUnboundedDelayedTasks`: delayed tasks never refused (an SSE stream's next event, a timed scenario
    /// transition), counted only for `getPendingDelayedTaskCount`.
    unbounded_delayed: Arc<AtomicUsize>,
    template_actions: Arc<AtomicUsize>,
    /// `templateActionExecutor`'s threads: `actionHandlerThreadCount` renders run at once, the rest wait their turn.
    template_threads: tokio::sync::Semaphore,
    /// `actionHandlerThreadCount`, the template threads there are.
    template_threads_total: usize,
    /// `queuedFileReads`: file reads admitted and still waiting for a file read thread.
    file_reads: Arc<AtomicUsize>,
    /// `fileReadExecutor`'s threads.
    file_read_threads: Arc<tokio::sync::Semaphore>,
    /// `maxQueuedFileReads`: [`MAX_QUEUED_FILE_READS`], lowered only by tests.
    max_queued_file_reads: AtomicUsize,
    logs: [OverloadLog; 7],
    epoch: Instant,
}

impl Overload {
    pub fn new(config: &crate::config::Config) -> Overload {
        let logs: [OverloadLog; 7] = Default::default();
        for log in &logs {
            log.next_line_at.store(-1, Ordering::Relaxed);
        }
        // fixed when the pool is built
        let threads = action_handler_threads(config);
        Overload {
            delayed_responses: Default::default(),
            side_actions: Default::default(),
            websocket_reply_frames: Default::default(),
            unbounded_delayed: Default::default(),
            template_actions: Default::default(),
            template_threads: tokio::sync::Semaphore::new(threads),
            template_threads_total: threads,
            file_reads: Default::default(),
            file_read_threads: Arc::new(tokio::sync::Semaphore::new(FILE_READ_THREADS)),
            max_queued_file_reads: AtomicUsize::new(MAX_QUEUED_FILE_READS),
            logs,
            epoch: Instant::now(),
        }
    }
}

/// `actionHandlerThreadCount()`: the threads of the action scheduler and of the template pool, default max(5, the
/// configuration's processors, [`crate::config::available_processors`]).
pub fn action_handler_threads(config: &crate::config::Config) -> usize {
    match config.int_property("actionHandlerThreadCount", 0) {
        n if n > 0 => usize::try_from(n).unwrap_or(usize::MAX).min(tokio::sync::Semaphore::MAX_PERMITS),
        _ => crate::config::default_action_handler_thread_count(config) as usize,
    }
}

/// A template render admitted to the template queue (`executeTemplateAction`), waiting for a template thread.
#[must_use]
pub struct QueuedRender {
    queued: Permit,
}

impl QueuedRender {
    /// Waits for a template thread; the render leaves the queue once it has one, and holds it while rendering.
    pub async fn start(self, overload: &Overload) -> tokio::sync::SemaphorePermit<'_> {
        let thread = overload.template_threads.acquire().await.expect("never closed");
        drop(self.queued);
        thread
    }
}

/// Admitted work: holds its slots until dropped (the delay elapsed, or the render started).
#[must_use]
pub struct Permit {
    budget: Arc<AtomicUsize>,
    permits: usize,
}

impl Permit {
    /// One permit per slot, each released on its own (a reply set's frames, as each one's delay elapses).
    pub fn into_singles(mut self) -> Vec<Permit> {
        let singles = (0..self.permits).map(|_| Permit { budget: self.budget.clone(), permits: 1 }).collect();
        // the slots now belong to the singles; dropping this one releases none
        self.permits = 0;
        singles
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.budget.fetch_sub(self.permits, Ordering::AcqRel);
    }
}

/// A limit of zero or less, or none, is unbounded (`limitOrUnbounded`).
fn limit(state: &State, property: &str) -> usize {
    match state.config.int_property(property, crate::config::default_max_pending_actions(&state.config)) {
        l if l <= 0 => usize::MAX,
        l => usize::try_from(l).unwrap_or(usize::MAX),
    }
}

impl Overload {
    fn budget(&self, reason: Reason) -> &Arc<AtomicUsize> {
        match reason {
            Reason::DelayedResponses | Reason::DelaySkipped => &self.delayed_responses,
            Reason::SideActions => &self.side_actions,
            Reason::WebSocketReplies => &self.websocket_reply_frames,
            Reason::TemplateActions => &self.template_actions,
            Reason::StaticFiles | Reason::FileBodies => &self.file_reads,
        }
    }

    /// `submitFileRead`: runs a blocking file read on the file read pool once a file read thread is free, or refuses
    /// it (`None`, counted and logged under `reason`; the caller answers [`file_reads_refused`]) while
    /// [`MAX_QUEUED_FILE_READS`] reads are already waiting. A read is queued from its admission until it has a thread.
    pub async fn file_read<T: Send + 'static>(&self, state: &State, reason: Reason, read: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let limit = self.max_queued_file_reads.load(Ordering::Acquire);
        let mut queued = self.file_reads.load(Ordering::Acquire);
        loop {
            if queued >= limit {
                self.refused(state, reason, limit);
                return None;
            }
            match self.file_reads.compare_exchange_weak(queued, queued + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(now) => queued = now,
            }
        }
        let waiting = Permit { budget: self.file_reads.clone(), permits: 1 };
        let thread = self.file_read_threads.clone().acquire_owned().await.expect("never closed");
        drop(waiting);
        let read = tokio::task::spawn_blocking(move || {
            let _thread = thread;
            read()
        });
        Some(read.await.unwrap_or_else(|panic| std::panic::resume_unwind(panic.into_panic())))
    }

    /// `maxQueuedFileReads(n)`: lowers the file read queue's bound, for tests.
    #[cfg(test)]
    fn max_queued_file_reads(&self, limit: usize) {
        self.max_queued_file_reads.store(limit, Ordering::Release);
    }

    /// `tryAdmit`: adds `permits` while fewer than the limit are held; a refused task never raises the count. A
    /// refusal is counted and logged here, and its fallback is the caller's.
    pub fn admit(&self, state: &State, reason: Reason, permits: usize) -> Option<Permit> {
        let limit = limit(state, reason.property());
        let budget = self.budget(reason);
        let mut held = budget.load(Ordering::Acquire);
        while held < limit {
            match budget.compare_exchange_weak(held, held + permits, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(Permit { budget: budget.clone(), permits }),
                Err(now) => held = now,
            }
        }
        self.refused(state, reason, limit);
        None
    }

    /// `executeTemplateAction`'s admission: a response or forward template render joins the template queue while
    /// fewer than `maxQueuedTemplateActions` wait there, else it is refused (the caller answers the 503).
    pub fn queue_render(&self, state: &State) -> Option<QueuedRender> {
        self.admit(state, Reason::TemplateActions, 1).map(|queued| QueuedRender { queued })
    }

    /// `Scheduler.sheddable` side action: a delay of a millisecond or more holds a slot of its own budget while it
    /// waits; `Err` when that budget is full and the side action is to be dropped. Undelayed ones are never shed.
    pub fn side_action(&self, state: &State, delay: Option<Duration>) -> Result<Option<Permit>, ()> {
        match delay.filter(|d| d.as_millis() > 0) {
            Some(_) => self.admit(state, Reason::SideActions, 1).map(Some).ok_or(()),
            None => Ok(None),
        }
    }

    /// `scheduleAfterDelay` without a rejectable wrapper, or `scheduleCancellable`: a delayed task that is never
    /// refused, counted while the permit is held (until its delay elapses, or its task is cancelled).
    pub fn unbounded_delayed(&self) -> Permit {
        self.unbounded_delayed.fetch_add(1, Ordering::AcqRel);
        Permit { budget: self.unbounded_delayed.clone(), permits: 1 }
    }

    /// `scheduler.schedule(command, false, delay)` with no rejectable wrapper: one unbounded delayed task counted for
    /// the whole of `delay` (from a millisecond up), whatever becomes of its waiter meanwhile, as the scheduled task
    /// stays queued until it fires even once its stream or channel is gone (a gRPC stream's next message, a WebSocket
    /// response's next message or GraphQL frame, the close-socket delay). The caller waits the delay itself.
    pub fn unbounded_delay(&self, delay: Duration) {
        if delay.as_millis() > 0 {
            let pending = self.unbounded_delayed();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                drop(pending);
            });
        }
    }

    /// `getPendingDelayedTaskCount`: delayed responses, side actions and WebSocket reply frames admitted whose delay
    /// has not elapsed, and the unbounded delayed tasks.
    pub fn pending_delayed(&self) -> usize {
        [&self.delayed_responses, &self.side_actions, &self.websocket_reply_frames, &self.unbounded_delayed].iter().map(|b| b.load(Ordering::Acquire)).sum()
    }

    /// `getQueuedTemplateActionCount`: renders admitted to the template queue still waiting for a template thread.
    pub fn queued_template_actions(&self) -> usize {
        self.template_actions.load(Ordering::Acquire)
    }

    /// [`crate::Server::scheduler_count`]'s names that this state answers alone.
    pub fn count(&self, name: &str) -> Option<usize> {
        let held = |budget: &AtomicUsize| budget.load(Ordering::Acquire);
        match name {
            "delayedResponses" => Some(held(&self.delayed_responses)),
            "sideActions" => Some(held(&self.side_actions)),
            "pendingDelayed" => Some(self.pending_delayed()),
            "templateQueued" => Some(self.queued_template_actions()),
            "templateRunning" => Some(self.template_threads_total - self.template_threads.available_permits()),
            "fileReadsQueued" => Some(self.file_reads.load(Ordering::Acquire)),
            _ => None,
        }
    }

    /// `getOverloadRejectionCount` of each reason that has refused a task: the `mock_server_overload_rejections`
    /// series, by its `reason` label, in label order.
    pub fn rejections(&self) -> Vec<(&'static str, u64)> {
        [Reason::DelaySkipped, Reason::DelayedResponses, Reason::FileBodies, Reason::SideActions, Reason::StaticFiles, Reason::TemplateActions, Reason::WebSocketReplies]
            .into_iter()
            .map(|reason| (reason.metric_label(), self.logs[reason.index()].total.load(Ordering::Acquire)))
            .filter(|(_, total)| *total > 0)
            .collect()
    }

    /// `rejectForOverload`'s count and its WARN line, at most one per reason every 10 s.
    fn refused(&self, state: &State, reason: Reason, limit: usize) {
        let log = &self.logs[reason.index()];
        let total = log.total.fetch_add(1, Ordering::AcqRel) + 1;
        log.since_last_line.fetch_add(1, Ordering::AcqRel);
        let now = self.epoch.elapsed().as_millis() as i64;
        let next = log.next_line_at.load(Ordering::Acquire);
        if (next >= 0 && now < next) || log.next_line_at.compare_exchange(next, now + LOG_INTERVAL.as_millis() as i64, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return;
        }
        let count = log.since_last_line.swap(0, Ordering::AcqRel);
        let limit = if limit == usize::MAX { i64::from(i32::MAX) } else { limit as i64 };
        use crate::recorded::{Arg, LogEntry};
        let format = match reason.fixed_limit() {
            true => "overloaded:{}task(s) that were:{}exceeded:{}which has a fixed limit of:{}so they were:{}in total since startup:{}reduce the request rate; this is logged at most every 10 seconds per reason",
            false => "overloaded:{}task(s) that were:{}exceeded:{}which has a limit of:{}so they were:{}in total since startup:{}raise that property or reduce the request rate; this is logged at most every 10 seconds per reason",
        };
        let entry = LogEntry::new(crate::recorded::Kind::Warn, format)
        .args([
            Arg::from(serde_json::json!(count)),
            Arg::from(reason.description()),
            Arg::from(reason.property()),
            Arg::from(serde_json::json!(limit)),
            Arg::from(reason.outcome()),
            Arg::from(serde_json::json!(total)),
        ]);
        crate::log::warn_event(state, entry);
    }
}

/// `overloadResponse`: the answer in place of a refused delayed or templated action, written directly, so no chaos,
/// rate limit or delay applies to it, and not logged as the expectation's response.
pub fn refused() -> Reply {
    let mut reply = Reply::status(503);
    reply.reason = Some("Service Unavailable".into());
    reply.headers.push(("Retry-After".into(), "1".into()));
    reply.body = bytes::Bytes::from_static(REFUSED_BODY.as_bytes());
    reply
}

/// The 503 a refused static file read is answered with (`serveStaticFileOrReturnNotFound`).
pub const STATIC_FILES_REFUSED_BODY: &str = "MockServer is overloaded, too many static file reads are already waiting";
/// The 503 a refused `FILE` body read is answered with (`submitFileBodyResponse`).
pub const FILE_BODIES_REFUSED_BODY: &str = "MockServer is overloaded, too many file reads are already waiting";

/// The answer in place of a file read the file read queue refused, written directly as [`refused`] is.
pub fn file_reads_refused(reason: Reason) -> Reply {
    let mut reply = Reply::status(503);
    reply.reason = Some("Service Unavailable".into());
    reply.headers.push(("Retry-After".into(), "1".into()));
    reply.body = bytes::Bytes::from_static(match reason {
        Reason::StaticFiles => STATIC_FILES_REFUSED_BODY,
        _ => FILE_BODIES_REFUSED_BODY,
    }.as_bytes());
    reply
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Scheduler.submitFileRead`: with every file read thread busy, reads queue up to the bound; the next is refused,
    /// counted under its reason, and a freed thread runs the queued ones (upstream `SchedulerTest` file read cases).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn file_reads_beyond_the_queue_bound_are_refused() {
        let state = State::new(crate::Config::for_tests(), Vec::new());
        assert_eq!(MAX_QUEUED_FILE_READS, 1000);
        state.overload.max_queued_file_reads(2);
        let gate = Arc::new(std::sync::Barrier::new(FILE_READ_THREADS + 1));
        let mut busy = Vec::new();
        for _ in 0..FILE_READ_THREADS {
            let (state, gate) = (state.clone(), gate.clone());
            busy.push(tokio::spawn(async move { state.overload.file_read(&state, Reason::StaticFiles, move || { gate.wait(); "busy" }).await }));
        }
        let wait_for = |name: &'static str, n: usize| {
            let state = state.clone();
            async move {
                for _ in 0..500 {
                    if name == "running" && state.overload.file_read_threads.available_permits() == FILE_READ_THREADS - n {
                        return;
                    }
                    if name == "queued" && state.overload.count("fileReadsQueued") == Some(n) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                panic!("{name} never reached {n}");
            }
        };
        wait_for("running", FILE_READ_THREADS).await;
        let mut queued = Vec::new();
        for reason in [Reason::FileBodies, Reason::StaticFiles] {
            let state = state.clone();
            queued.push(tokio::spawn(async move { state.overload.file_read(&state, reason, || "queued").await }));
        }
        wait_for("queued", 2).await;
        assert_eq!(state.overload.file_read(&state, Reason::FileBodies, || "refused").await, None);
        assert_eq!(state.overload.file_read(&state, Reason::StaticFiles, || "refused").await, None);
        assert_eq!(state.overload.file_read(&state, Reason::FileBodies, || "refused").await, None);
        assert_eq!(state.overload.rejections(), vec![("file_bodies", 2), ("static_files", 1)]);
        gate.wait();
        for task in busy.into_iter().chain(queued) {
            assert!(task.await.expect("joined").is_some());
        }
        assert_eq!(state.overload.count("fileReadsQueued"), Some(0));
        assert_eq!(state.overload.file_read(&state, Reason::FileBodies, || "admitted").await, Some("admitted"));
    }

    #[test]
    fn a_refused_file_read_is_answered_503_with_retry_after() {
        let reply = file_reads_refused(Reason::FileBodies);
        assert_eq!((reply.status, reply.reason.as_deref()), (503, Some("Service Unavailable")));
        assert_eq!(reply.headers, vec![("Retry-After".to_string(), "1".to_string())]);
        assert_eq!(&reply.body[..], b"MockServer is overloaded, too many file reads are already waiting");
        assert_eq!(&file_reads_refused(Reason::StaticFiles).body[..], b"MockServer is overloaded, too many static file reads are already waiting");
    }
}

//! Stack headroom on the request path.
//!
//! An unoptimised build gives every temporary of an `async fn`'s poll function its own stack slot, so a poll frame
//! that awaits a future of N bytes reserves a few copies of it: the future built, moved and pinned. A task-local
//! scope's poll frame does the same with the future it wraps. Futures nest, so the frames of the layers that hold one
//! another (connection, dispatch, data plane, forward, client) add up to most of a tokio worker's 2 MiB before the
//! outbound TLS handshake starts. Two kinds of entry keep them apart:
//!
//! - The deep, rarely taken branches (MCP, gRPC, forwards and proxies, callbacks, templates, the contract-test and
//!   replay endpoints) are entered through a plain function returning a [`Boxed`] future, in every build: the future
//!   is built in that function's short-lived frame and moved to the heap, and every frame above holds only the box.
//! - The layers of the common path (dispatch, HTTP handling, the data plane, a mock response) are entered through a
//!   plain function returning [`layer`] of their future: boxed the same way in an unoptimised build, the future itself
//!   in an optimised one, whose frames keep no such copies. An optimised build thus answers an HTTP/1.1 request on its
//!   connection's task with no allocation for its handling's futures.
//!
//! The guard is `tests/upstream/forward_client_certificate.rs::forward_with_a_client_certificate_fits_in_half_a_worker_stack`.

/// A heap-allocated future, as the deep branches of the request path return it.
pub type Boxed<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// A layer of the request path's common branch: boxed in an unoptimised build, where awaiting it in place would put
/// copies of it in each frame above ([`crate::boxed`]).
#[cfg(debug_assertions)]
pub fn layer<'a, F: std::future::Future + Send + 'a>(future: F) -> Boxed<'a, F::Output> {
    Box::pin(future)
}

/// A layer of the request path's common branch: awaited in place in an optimised build ([`crate::boxed`]).
#[cfg(not(debug_assertions))]
pub fn layer<F: std::future::Future + Send>(future: F) -> F {
    future
}

/// An HTTP/1.1 connection's serving, which answers its requests in place: in an unoptimised build on a task of its
/// own, so that its requests start near the bottom of a worker's stack instead of on top of the frames that set the
/// connection up (protocol detection, the inbound TLS handshake: hundreds of KiB unoptimised). Dropping the returned
/// future aborts the task, and a panic in it unwinds here, as it does in place.
#[cfg(debug_assertions)]
pub async fn connection(serving: impl std::future::Future<Output = ()> + Send + 'static) {
    struct AbortOnDrop(tokio::task::AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let task = tokio::spawn(serving);
    let _abort = AbortOnDrop(task.abort_handle());
    if let Err(failed) = task.await
        && let Ok(panic) = failed.try_into_panic()
    {
        std::panic::resume_unwind(panic);
    }
}

/// An HTTP/1.1 connection's serving: awaited in place in an optimised build ([`connection`] in an unoptimised one).
#[cfg(not(debug_assertions))]
pub fn connection<F: std::future::Future<Output = ()> + Send + 'static>(serving: F) -> F {
    serving
}

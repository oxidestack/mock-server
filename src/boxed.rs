//! Stack headroom on the request path.
//!
//! An unoptimised build gives every temporary of an `async fn`'s poll function its own stack slot, so a poll frame
//! that awaits a future of N bytes reserves a few copies of it: the future built, moved and pinned. Futures nest, so
//! the frames of the layers that hold one another (connection, dispatch, data plane, forward, client) add up to most
//! of a tokio worker's 2 MiB before the outbound TLS handshake starts. The big layers on that path are therefore
//! entered through a plain function returning a [`Boxed`] future: the future is built in that function's short-lived
//! frame and moved to the heap, and every frame above holds only the box. An HTTP/1.1 request is also handled on a
//! task of its own (`handler::dispatch_detached`), off the connection's frames, as each HTTP/2 stream is. The guard is
//! `tests/upstream/forward_client_certificate.rs::forward_with_a_client_certificate_fits_in_half_a_worker_stack`.

/// A heap-allocated future, as the layers of the request path return it.
pub type Boxed<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

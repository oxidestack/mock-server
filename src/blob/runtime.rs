//! The cloud SDKs are async and `BlobStore` is not (upstream's SDK clients block their calling thread). Every call
//! runs on one runtime the stores share, which lives as long as the process: the SDK clients keep connection pools
//! bound to the runtime they first ran on, and a runtime dropped inside a server's async context would panic.

use std::future::Future;
use std::sync::OnceLock;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("MockServer-blobStore").enable_all().build().expect("blob store runtime")
    })
}

/// Runs `future` to completion on the blob stores' runtime from any thread, a server's runtime worker included (the
/// worker hands its queued tasks on first, `crate::blocking::off_worker`).
pub fn block_on<F: Future + Send>(future: F) -> F::Output
where
    F::Output: Send,
{
    crate::blocking::off_worker(|| std::thread::scope(|scope| scope.spawn(|| runtime().block_on(future)).join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))))
}

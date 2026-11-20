//! The foreign-runtime seam. Some behaviour exists only because MockServer shares a JVM with user code,
//! and it goes through a runtime that hosts that code. The JVM, run as a sidecar, is the first such runtime
//!. None is implemented yet, so `State::foreign` is always `None`.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::state::State;

pub trait ForeignRuntime: Send + Sync {
    /// Renders `template` on the runtime's own Velocity without `SecureUberspector`
    /// (`velocityDisallowClassLoading=false`). `request` is the request as template input JSON.
    fn render_unsandboxed_velocity(&self, template: &str, request: &serde_json::Value) -> Result<String, String>;
}

/// Whether the warning for the current `velocityDisallowClassLoading=false` period has been logged.
#[derive(Default)]
pub struct SandboxWarning(AtomicBool);

pub const NO_RUNTIME_FOR_CLASS_LOADING: &str = "Velocity template class loading is enabled (mockserver.velocityDisallowClassLoading=false) but needs a JVM foreign runtime, which is not configured, so Velocity templates stay sandboxed.";

/// `velocityDisallowClassLoading`, read live as upstream reads it. With `false` and no foreign runtime, the
/// warning is logged once each time the property turns `false`, where upstream logs as it rebuilds the engine.
pub fn velocity_sandboxed(state: &State) -> bool {
    let disallow = state.config.bool_property("velocityDisallowClassLoading", true);
    let warned = &state.velocity_sandbox_warning.0;
    if disallow {
        warned.store(false, Ordering::Relaxed);
        return true;
    }
    if state.foreign.is_some() {
        return false;
    }
    if !warned.swap(true, Ordering::Relaxed) {
        crate::log::warn(state, NO_RUNTIME_FOR_CLASS_LOADING);
        state.log.message(crate::recorded::LogEntry::at(crate::recorded::Level::Warn, NO_RUNTIME_FOR_CLASS_LOADING));
    }
    true
}

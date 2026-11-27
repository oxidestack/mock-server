//! Locks around a collection that every request asks whether it is empty (the breakpoints, the CRUD resources, the
//! chaos hosts, the preemption cordon, the span processor) and that is nearly always empty. Taking the lock only to
//! find that out wrote the lock's cache line on every request, and the request workers bounced it between their
//! cores. Here the emptiness is kept beside the lock, updated as each writer releases it, and read without the lock.
//! A reader that sees it empty while a writer is filling it is ordered before that writer, as it was when it waited
//! for the lock.

use std::sync::atomic::{AtomicBool, Ordering};

/// A collection that can say whether it holds anything.
pub trait Emptiness {
    fn is_empty(&self) -> bool;
}

impl<T> Emptiness for Vec<T> {
    fn is_empty(&self) -> bool {
        Vec::is_empty(self)
    }
}

impl<K, V, S> Emptiness for std::collections::HashMap<K, V, S> {
    fn is_empty(&self) -> bool {
        std::collections::HashMap::is_empty(self)
    }
}

impl<T> Emptiness for Option<T> {
    fn is_empty(&self) -> bool {
        self.is_none()
    }
}

/// A [`parking_lot::Mutex`] whose emptiness is read without locking.
pub struct WatchedMutex<C> {
    inner: parking_lot::Mutex<C>,
    filled: AtomicBool,
}

impl<C: Emptiness + Default> Default for WatchedMutex<C> {
    fn default() -> Self {
        WatchedMutex::new(C::default())
    }
}

impl<C: Emptiness> WatchedMutex<C> {
    pub fn new(value: C) -> Self {
        let filled = AtomicBool::new(!value.is_empty());
        WatchedMutex { inner: parking_lot::Mutex::new(value), filled }
    }

    pub fn lock(&self) -> WatchedGuard<'_, parking_lot::MutexGuard<'_, C>> {
        WatchedGuard { guard: self.inner.lock(), filled: &self.filled }
    }

    /// Whether the collection was empty when its last writer released it.
    pub fn is_empty(&self) -> bool {
        !self.filled.load(Ordering::Acquire)
    }
}

/// A [`parking_lot::RwLock`] whose emptiness is read without locking.
pub struct WatchedRwLock<C> {
    inner: parking_lot::RwLock<C>,
    filled: AtomicBool,
}

impl<C: Emptiness + Default> Default for WatchedRwLock<C> {
    fn default() -> Self {
        WatchedRwLock::new(C::default())
    }
}

impl<C: Emptiness> WatchedRwLock<C> {
    pub fn new(value: C) -> Self {
        let filled = AtomicBool::new(!value.is_empty());
        WatchedRwLock { inner: parking_lot::RwLock::new(value), filled }
    }

    pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, C> {
        self.inner.read()
    }

    pub fn write(&self) -> WatchedGuard<'_, parking_lot::RwLockWriteGuard<'_, C>> {
        WatchedGuard { guard: self.inner.write(), filled: &self.filled }
    }

    /// Whether the collection was empty when its last writer released it.
    pub fn is_empty(&self) -> bool {
        !self.filled.load(Ordering::Acquire)
    }
}

/// A write guard that records the collection's emptiness as it is released, before the lock is.
pub struct WatchedGuard<'a, G: std::ops::DerefMut<Target: Emptiness>> {
    guard: G,
    filled: &'a AtomicBool,
}

impl<G: std::ops::DerefMut<Target: Emptiness>> Drop for WatchedGuard<'_, G> {
    fn drop(&mut self) {
        // runs before `guard` is dropped, so under the lock
        self.filled.store(!self.guard.is_empty(), Ordering::Release);
    }
}

impl<G: std::ops::DerefMut<Target: Emptiness>> std::ops::Deref for WatchedGuard<'_, G> {
    type Target = G::Target;
    fn deref(&self) -> &G::Target {
        &self.guard
    }
}

impl<G: std::ops::DerefMut<Target: Emptiness>> std::ops::DerefMut for WatchedGuard<'_, G> {
    fn deref_mut(&mut self) -> &mut G::Target {
        &mut self.guard
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emptiness_follows_each_writer() {
        let m: WatchedMutex<Vec<u8>> = WatchedMutex::default();
        assert!(m.is_empty());
        m.lock().push(1);
        assert!(!m.is_empty());
        m.lock().clear();
        assert!(m.is_empty());
        let r = WatchedRwLock::new(Some(1));
        assert!(!r.is_empty());
        *r.write() = None;
        assert!(r.is_empty());
        assert_eq!(*r.read(), None);
    }
}

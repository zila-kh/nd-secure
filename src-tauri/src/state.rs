use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
};

use parking_lot::Mutex;

use crate::{
    credentials::CredentialRepository, gallery::GalleryRepository, media_server::MediaServer,
    session::SessionState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrackedClipboard {
    generation: u64,
    digest: [u8; 32],
}

pub struct ClipboardTracker {
    next_generation: AtomicU64,
    tracked: Mutex<Option<TrackedClipboard>>,
    operation: Mutex<()>,
}

impl ClipboardTracker {
    fn new() -> Self {
        Self { next_generation: AtomicU64::new(0), tracked: Mutex::new(None), operation: Mutex::new(()) }
    }

    pub fn with_operation<T>(&self, operation: impl FnOnce() -> T) -> T {
        let _guard = self.operation.lock();
        operation()
    }

    pub fn track(&self, digest: [u8; 32]) -> u64 {
        let generation = self.next_generation.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        *self.tracked.lock() = Some(TrackedClipboard { generation, digest });
        generation
    }

    pub fn current(&self) -> Option<(u64, [u8; 32])> {
        self.tracked.lock().map(|tracked| (tracked.generation, tracked.digest))
    }

    pub fn is_current(&self, generation: u64) -> bool {
        self.tracked.lock().is_some_and(|tracked| tracked.generation == generation)
    }

    pub fn clear_if_generation(&self, generation: u64) {
        let mut tracked = self.tracked.lock();
        if tracked.is_some_and(|value| value.generation == generation) {
            *tracked = None;
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub session: Arc<SessionState>,
    pub gallery: Arc<GalleryRepository>,
    pub credentials: Arc<CredentialRepository>,
    pub media_server: Arc<MediaServer>,
    pub clipboard: Arc<ClipboardTracker>,
    protocol_active: Arc<AtomicUsize>,
    protocol_limit: usize,
}

impl AppState {
    pub fn new(
        session: Arc<SessionState>,
        gallery: Arc<GalleryRepository>,
        credentials: Arc<CredentialRepository>,
        media_server: Arc<MediaServer>,
    ) -> Self {
        Self {
            session,
            gallery,
            credentials,
            media_server,
            clipboard: Arc::new(ClipboardTracker::new()),
            protocol_active: Arc::new(AtomicUsize::new(0)),
            protocol_limit: if cfg!(target_os = "android") { 2 } else { 4 },
        }
    }

    pub fn try_protocol_permit(&self) -> Option<ProtocolPermit> {
        loop {
            let current = self.protocol_active.load(Ordering::Acquire);
            if current >= self.protocol_limit {
                return None;
            }
            if self
                .protocol_active
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(ProtocolPermit { active: Arc::clone(&self.protocol_active) });
            }
        }
    }
}

pub struct ProtocolPermit {
    active: Arc<AtomicUsize>,
}

impl Drop for ProtocolPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::ClipboardTracker;

    #[test]
    fn clipboard_tracker_only_clears_the_current_generation() {
        let tracker = ClipboardTracker::new();
        let first = tracker.track([1_u8; 32]);
        let second = tracker.track([2_u8; 32]);

        assert!(!tracker.is_current(first));
        assert!(tracker.is_current(second));
        assert_eq!(tracker.current(), Some((second, [2_u8; 32])));

        tracker.clear_if_generation(first);
        assert!(tracker.is_current(second));
        tracker.clear_if_generation(second);
        assert_eq!(tracker.current(), None);
    }
}

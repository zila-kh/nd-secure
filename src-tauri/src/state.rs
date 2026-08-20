use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use crate::{
    credentials::CredentialRepository, gallery::GalleryRepository, media_server::MediaServer,
    session::SessionState,
};

#[derive(Clone)]
pub struct AppState {
    pub session: Arc<SessionState>,
    pub gallery: Arc<GalleryRepository>,
    pub credentials: Arc<CredentialRepository>,
    pub media_server: Arc<MediaServer>,
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

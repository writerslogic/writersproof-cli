// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared CGEventTap singleton with broadcast distribution.
//!
//! Owns the keystroke tap at app-level lifetime (independent of sentinel).
//! Multiple consumers subscribe via `tokio::sync::broadcast`.

use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc, Mutex, OnceLock,
};

use crate::platform::{KeystrokeCapture, KeystrokeEvent};

const BROADCAST_CAPACITY: usize = 1024;
static INIT_LOCK: Mutex<()> = Mutex::new(());


pub(crate) struct SharedKeystrokeTap {
    broadcast_tx: tokio::sync::broadcast::Sender<KeystrokeEvent>,
    running: Arc<AtomicBool>,
    subscriber_count: Arc<AtomicU32>,
    #[allow(dead_code)]
    bridge_handle: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

static SHARED_TAP: OnceLock<Arc<SharedKeystrokeTap>> = OnceLock::new();


pub(crate) fn get_or_start_shared_tap() -> crate::error::Result<Arc<SharedKeystrokeTap>> {
    if let Some(tap) = SHARED_TAP.get() {
        return Ok(Arc::clone(tap));
    }

    let _guard = INIT_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    // Re-check after acquiring lock (another thread may have initialized)
    if let Some(tap) = SHARED_TAP.get() {
        return Ok(Arc::clone(tap));
    }

    let mut capture = super::keystroke::MacOSKeystrokeCapture::new()
        .map_err(|e| crate::error::Error::platform(format!("create keystroke capture: {e}")))?;
    let sync_rx = capture
        .start()
        .map_err(|e| crate::error::Error::platform(format!("start keystroke capture: {e}")))?;

    let (broadcast_tx, _) = tokio::sync::broadcast::channel(BROADCAST_CAPACITY);
    let running = Arc::new(AtomicBool::new(true));
    let bridge_running = Arc::clone(&running);
    let bridge_tx = broadcast_tx.clone();

    let handle = std::thread::Builder::new()
        .name("shared-tap-bridge".into())
        .spawn(move || {
            let mut _capture = capture; // own the capture to keep tap alive
            while bridge_running.load(Ordering::SeqCst) {
                match sync_rx.recv_timeout(std::time::Duration::from_millis(100)) {
                    Ok(event) => {
                        // Ignore send errors (no subscribers is fine)
                        let _ = bridge_tx.send(event);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
        .map_err(|e| crate::error::Error::platform(format!("spawn bridge thread: {e}")))?;

    let tap = Arc::new(SharedKeystrokeTap {
        broadcast_tx,
        running,
        subscriber_count: Arc::new(AtomicU32::new(0)),
        bridge_handle: std::sync::Mutex::new(Some(handle)),
    });

    SHARED_TAP.set(Arc::clone(&tap)).ok();
    Ok(tap)
}


#[allow(dead_code)]
pub(crate) fn get_shared_tap() -> Option<Arc<SharedKeystrokeTap>> {
    SHARED_TAP.get().cloned()
}

impl SharedKeystrokeTap {
    pub(crate) fn subscribe(
        &self,
    ) -> tokio::sync::broadcast::Receiver<KeystrokeEvent> {
        self.subscriber_count.fetch_add(1, Ordering::SeqCst);
        self.broadcast_tx.subscribe()
    }

    #[allow(dead_code)]
    pub(crate) fn unsubscribe(&self) {
        self.subscriber_count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_sub(1))
            })
            .ok();
    }

    #[allow(dead_code)]
    pub(crate) fn subscriber_count(&self) -> u32 {
        self.subscriber_count.load(Ordering::SeqCst)
    }

    #[allow(dead_code)]
    pub(crate) fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    #[allow(dead_code)]
    pub(crate) fn is_bridge_alive(&self) -> bool {
        match self.bridge_handle.lock() {
            Ok(guard) => guard.as_ref().is_some_and(|h| !h.is_finished()),
            Err(p) => p.into_inner().as_ref().is_some_and(|h| !h.is_finished()),
        }
    }
}

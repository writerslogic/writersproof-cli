// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Shared CGEventTap singleton with broadcast distribution.
//!
//! Owns the keystroke tap at app-level lifetime (independent of sentinel).
//! Multiple consumers subscribe via `tokio::sync::broadcast`.

use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc, OnceLock,
};

use crate::platform::{KeystrokeCapture, KeystrokeEvent};


const BROADCAST_CAPACITY: usize = 1024;


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

    // OnceLock race: another thread might have initialized first.
    // get_or_init is not suitable since init is fallible, but since
    // we already succeeded, just try to set and return whichever won.
    match SHARED_TAP.set(Arc::clone(&tap)) {
        Ok(()) => Ok(tap),
        Err(_) => {
            // Another thread won the race; stop our duplicate and return theirs.
            tap.running.store(false, Ordering::SeqCst);
            Ok(Arc::clone(SHARED_TAP.get().unwrap()))
        }
    }
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
        let _ = self.subscriber_count.fetch_sub(1, Ordering::SeqCst).min(1);
    }

    #[allow(dead_code)]
    pub(crate) fn subscriber_count(&self) -> u32 {
        self.subscriber_count.load(Ordering::SeqCst)
    }

    #[allow(dead_code)]
    pub(crate) fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

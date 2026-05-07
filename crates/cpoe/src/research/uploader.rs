// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::collector::ResearchCollector;
use super::types::{UploadResult, DEFAULT_UPLOAD_INTERVAL_SECS};

#[derive(Debug)]
/// Background task that periodically uploads buffered research sessions.
pub struct ResearchUploader {
    collector: Arc<tokio::sync::Mutex<ResearchCollector>>,
    running: Arc<AtomicBool>,
    upload_interval: Duration,
}

impl ResearchUploader {
    /// Create an uploader with the default upload interval.
    pub fn new(collector: Arc<tokio::sync::Mutex<ResearchCollector>>) -> Self {
        Self {
            collector,
            running: Arc::new(AtomicBool::new(false)),
            upload_interval: Duration::from_secs(DEFAULT_UPLOAD_INTERVAL_SECS),
        }
    }

    /// Create an uploader with a custom upload interval.
    pub fn with_interval(
        collector: Arc<tokio::sync::Mutex<ResearchCollector>>,
        interval: Duration,
    ) -> Self {
        Self {
            collector,
            running: Arc::new(AtomicBool::new(false)),
            upload_interval: interval,
        }
    }

    /// Spawn the periodic upload loop as a Tokio task.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let collector = Arc::clone(&self.collector);
        let running = Arc::clone(&self.running);
        let interval = self.upload_interval;

        running.store(true, Ordering::SeqCst);

        tokio::spawn(async move {
            while running.load(Ordering::SeqCst) {
                tokio::time::sleep(interval).await;

                if !running.load(Ordering::SeqCst) {
                    break;
                }

                let export = {
                    let guard = collector.lock().await;
                    guard.take_export_if_ready()
                };
                if let Some(export) = export {
                    match ResearchCollector::send_export(&export).await {
                        Ok(result) => {
                            if result.sessions_uploaded > 0 {
                                let mut guard = collector.lock().await;
                                guard.clear_after_upload();
                                log::info!(
                                    "[research] Uploaded {} sessions ({} samples)",
                                    result.sessions_uploaded,
                                    result.samples_uploaded
                                );
                            } else {
                                log::warn!(
                                    "[research] Server acknowledged upload but reported 0 sessions uploaded"
                                );
                            }
                        }
                        Err(e) => {
                            log::error!("[research] Upload failed: {}", e);
                            let guard = collector.lock().await;
                            if let Err(save_err) = guard.save() {
                                log::warn!("[research] Failed to persist sessions after upload error: {save_err}");
                            }
                        }
                    }
                }
            }
        })
    }

    /// Signal the background upload loop to stop.
    ///
    /// This is advisory: it sets a flag that the loop checks on its next iteration.
    /// Any in-progress upload completes before the task exits. Call the returned
    /// `JoinHandle` from [`start`](Self::start) to await full task completion.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Return `true` if the background upload loop is active.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Trigger an immediate upload outside the periodic schedule.
    pub async fn upload_now(&self) -> Result<UploadResult, String> {
        let export = {
            let guard = self.collector.lock().await;
            guard.take_export_if_ready()
        };
        let Some(export) = export else {
            return Ok(UploadResult {
                sessions_uploaded: 0,
                samples_uploaded: 0,
                message: "Upload conditions not met".to_string(),
            });
        };
        let result = ResearchCollector::send_export(&export).await?;
        if result.sessions_uploaded > 0 {
            let mut guard = self.collector.lock().await;
            guard.clear_after_upload();
        }
        Ok(result)
    }
}

// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Directory-level file watcher for active document sessions.
//!
//! Unlike [`BundleMonitor`] which watches bundle-internal subtrees (`.scriv`),
//! this module watches the parent directories of all actively-tracked regular
//! files.  File-save events are correlated with the owning typing session,
//! closing the gap for apps that don't emit AXDocument or whose titles lag
//! behind the actual file state.
//!
//! Watches are reference-counted: multiple sessions in the same directory share
//! a single OS-level watcher, and the watcher is removed only when the last
//! session in that directory ends.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};

use super::types::{ChangeEvent, ChangeEventType};

/// Watches parent directories of active document sessions.
///
/// Each directory is watched non-recursively so that only direct file changes
/// (saves, renames, deletions) in session directories are reported. This avoids
/// flooding the change channel with events from nested subdirectories.
pub struct DocumentDirectoryWatcher {
    watcher: RecommendedWatcher,
    /// Maps watched directory → set of session file paths within it.
    dir_sessions: HashMap<PathBuf, HashSet<PathBuf>>,
}

impl DocumentDirectoryWatcher {
    /// Create a new watcher that sends events on `change_tx`.
    pub fn new(change_tx: tokio::sync::mpsc::Sender<ChangeEvent>) -> anyhow::Result<Self> {
        let tx = change_tx.clone();
        let watcher = RecommendedWatcher::new(
            move |res: notify::Result<notify::Event>| {
                let Ok(event) = res else { return };
                for path in &event.paths {
                    let change_type = match event.kind {
                        notify::EventKind::Create(_) => ChangeEventType::Created,
                        notify::EventKind::Remove(_) => ChangeEventType::Deleted,
                        notify::EventKind::Modify(notify::event::ModifyKind::Name(
                            notify::event::RenameMode::To,
                        )) => ChangeEventType::Modified,
                        notify::EventKind::Modify(_) => ChangeEventType::Modified,
                        _ => continue,
                    };
                    if tx.blocking_send(ChangeEvent {
                        event_type: change_type,
                        path: path.to_string_lossy().into_owned(),
                        hash: None,
                        size: None,
                        timestamp: SystemTime::now(),
                    }).is_err() {
                        log::error!("document_watcher: event loop closed, dropping FS event");
                        return;
                    }
                }
            },
            Config::default(),
        )?;

        Ok(Self {
            watcher,
            dir_sessions: HashMap::new(),
        })
    }

    /// Register a document file for directory-level watching.
    ///
    /// The file's parent directory is watched. If the directory is already
    /// watched (another session shares it), only the reference count increases.
    pub fn watch_document(&mut self, doc_path: &Path) -> anyhow::Result<()> {
        let dir = match doc_path.parent() {
            Some(d) if d.is_dir() => d.to_path_buf(),
            _ => return Ok(()), // No valid parent directory
        };

        let doc = doc_path.to_path_buf();

        if !self.dir_sessions.contains_key(&dir) {
            // First session in this directory — register the OS watcher.
            if let Err(e) = self.watcher.watch(&dir, RecursiveMode::NonRecursive) {
                log::warn!("document_watcher: failed to watch {dir:?}: {e}");
                return Err(e.into());
            }
            log::debug!("document_watcher: watching directory {dir:?}");
        }

        self.dir_sessions.entry(dir).or_default().insert(doc);
        Ok(())
    }

    /// Unregister a document file. If no other sessions remain in its parent
    /// directory, the OS-level watcher is removed.
    pub fn unwatch_document(&mut self, doc_path: &Path) {
        let dir = match doc_path.parent() {
            Some(d) => d.to_path_buf(),
            None => return,
        };

        if let Some(sessions) = self.dir_sessions.get_mut(&dir) {
            sessions.remove(doc_path);
            if sessions.is_empty() {
                self.dir_sessions.remove(&dir);
                if let Err(e) = self.watcher.unwatch(&dir) {
                    log::debug!("document_watcher: unwatch {dir:?} failed: {e}");
                }
                log::debug!("document_watcher: stopped watching {dir:?}");
            }
        }
    }

    /// Returns the set of actively-watched directories.
    #[cfg(test)]
    pub fn watched_dirs(&self) -> Vec<PathBuf> {
        self.dir_sessions.keys().cloned().collect()
    }
}

impl std::fmt::Debug for DocumentDirectoryWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentDirectoryWatcher")
            .field("watched_dirs", &self.dir_sessions.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    fn make_watcher() -> (DocumentDirectoryWatcher, tokio::sync::mpsc::Receiver<ChangeEvent>) {
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        let watcher = DocumentDirectoryWatcher::new(tx).expect("watcher creation");
        (watcher, rx)
    }

    #[test]
    fn test_watch_unwatch_lifecycle() {
        let (mut watcher, _rx) = make_watcher();
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.md");
        fs::write(&file, "hello").unwrap();

        // Watch should succeed.
        watcher.watch_document(&file).unwrap();
        assert_eq!(watcher.watched_dirs().len(), 1);

        // Second file in same dir — should not add another OS watcher.
        let file2 = dir.path().join("other.txt");
        fs::write(&file2, "world").unwrap();
        watcher.watch_document(&file2).unwrap();
        assert_eq!(watcher.watched_dirs().len(), 1);

        // Remove first file — dir still watched (file2 remains).
        watcher.unwatch_document(&file);
        assert_eq!(watcher.watched_dirs().len(), 1);

        // Remove second file — dir no longer watched.
        watcher.unwatch_document(&file2);
        assert_eq!(watcher.watched_dirs().len(), 0);
    }

    #[test]
    fn test_unwatch_nonexistent_is_noop() {
        let (mut watcher, _rx) = make_watcher();
        // Should not panic or error.
        watcher.unwatch_document(Path::new("/nonexistent/file.txt"));
    }

    #[test]
    fn test_watch_no_parent_is_noop() {
        let (mut watcher, _rx) = make_watcher();
        // Root path or empty path has no valid parent dir.
        assert!(watcher.watch_document(Path::new("/")).is_ok());
        assert_eq!(watcher.watched_dirs().len(), 0);
    }

    #[tokio::test]
    async fn test_file_save_produces_change_event() {
        let (mut watcher, mut rx) = make_watcher();
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("essay.md");
        fs::write(&file, "draft 1").unwrap();

        watcher.watch_document(&file).unwrap();

        // Modify the file — should produce a ChangeEvent.
        // Give the watcher a moment to register.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut f = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&file)
            .unwrap();
        f.write_all(b"draft 2").unwrap();
        f.flush().unwrap();
        drop(f);

        // Wait for the event (with timeout).
        let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await;
        assert!(
            event.is_ok(),
            "should receive a change event within 5 seconds"
        );
        let event = event.unwrap().expect("channel should not be closed");
        assert!(
            event.path.contains("essay.md"),
            "event path should reference our file"
        );
    }
}

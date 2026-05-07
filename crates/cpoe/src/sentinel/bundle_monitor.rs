// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Recursive FSEvents watcher for bundle-based writing app documents.
//!
//! Writing apps like Scrivener store their projects as macOS package directories
//! (`.scriv`).  The sentinel tracks the bundle root as the session key, but edits
//! happen inside sub-files.  This module registers a recursive `notify` watcher
//! on the bundle's internal content subtree so per-chapter changes arrive as
//! [`ChangeEvent`]s attributed to the parent session.

use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio::sync::mpsc;

use super::types::{ChangeEvent, ChangeEventType};

/// Extensions that identify a macOS package/bundle document.
const BUNDLE_EXTENSIONS: &[&str] = &["scriv", "ulysses"];

/// Path suffixes inside a bundle that contain prose content.
///
/// The watcher is registered on the first of these that exists inside the bundle
/// root, falling back to the bundle root itself.
const CONTENT_SUBDIRS: &[&str] = &["Files/Data", "Files/Docs", "Files"];

/// A running recursive file watcher attached to a single bundle document.
///
/// Dropping this value unregisters the watcher and joins the background thread.
#[derive(Debug)]
pub struct BundleMonitor {
    /// The bundle root path being watched (e.g. `/Users/me/Novel.scriv`).
    pub bundle_root: PathBuf,
    /// The subdirectory actually passed to the watcher (bundle root or content subdir).
    pub watch_path: PathBuf,
    // The watcher must be kept alive; dropping it unregisters the FSEvents stream.
    _watcher: notify::RecommendedWatcher,
}

/// Return `true` if `path` has a bundle document extension (case-insensitive).
pub fn is_bundle_document(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| {
            let lower = e.to_ascii_lowercase();
            BUNDLE_EXTENSIONS.contains(&lower.as_str())
        })
        .unwrap_or(false)
}

/// Start a recursive [`notify`] watcher on the internal content subtree of
/// `bundle_path`.
///
/// Each file-system event is translated to a [`ChangeEvent`] and sent on
/// `change_tx`.  The `path` field of each event is the full absolute path of
/// the changed sub-file, so callers can strip the bundle root prefix to obtain
/// the bundle-relative path used in [`SessionSegment`].
///
/// Returns a [`BundleMonitor`] that keeps the watcher alive.  Dropping it
/// unregisters the FSEvents stream.
///
/// [`SessionSegment`]: super::types::SessionSegment
pub fn start_bundle_monitor(
    bundle_path: &Path,
    change_tx: mpsc::Sender<ChangeEvent>,
) -> anyhow::Result<BundleMonitor> {
    use notify::{Config, RecursiveMode, Watcher};

    // Prefer a specific content subdir so we don't fire on Scrivener's internal
    // metadata (search indexes, ui-state, etc.) that live outside Files/.
    let watch_path = CONTENT_SUBDIRS
        .iter()
        .map(|sub| bundle_path.join(sub))
        .find(|p| p.is_dir())
        .unwrap_or_else(|| bundle_path.to_path_buf());

    let tx = change_tx;
    let mut watcher = notify::RecommendedWatcher::new(
        move |res: notify::Result<notify::Event>| {
            let Ok(event) = res else { return };
            for path in &event.paths {
                let path_str = path.to_string_lossy().into_owned();
                let change_type = match event.kind {
                    notify::EventKind::Create(_) => ChangeEventType::Created,
                    notify::EventKind::Remove(_) => ChangeEventType::Deleted,
                    notify::EventKind::Modify(notify::event::ModifyKind::Name(
                        notify::event::RenameMode::To,
                    )) => {
                        // Use the destination path; already in `path`.
                        ChangeEventType::Modified
                    }
                    notify::EventKind::Modify(_) => ChangeEventType::Modified,
                    _ => continue,
                };
                let _ = tx.try_send(ChangeEvent {
                    event_type: change_type,
                    path: path_str,
                    hash: None,
                    size: None,
                    timestamp: SystemTime::now(),
                });
            }
        },
        Config::default(),
    )?;

    watcher.watch(&watch_path, RecursiveMode::Recursive)?;

    log::debug!(
        "bundle_monitor: watching {:?} for {:?}",
        watch_path,
        bundle_path
    );

    Ok(BundleMonitor {
        bundle_root: bundle_path.to_path_buf(),
        watch_path,
        _watcher: watcher,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_bundle_document() {
        assert!(is_bundle_document(Path::new("/Users/me/Novel.scriv")));
        assert!(is_bundle_document(Path::new("/Users/me/Sheet.ulysses")));
        assert!(is_bundle_document(Path::new("/Users/me/Note.SCRIV")));
        assert!(!is_bundle_document(Path::new("/Users/me/doc.docx")));
        assert!(!is_bundle_document(Path::new("/Users/me/script.fdx")));
        assert!(!is_bundle_document(Path::new("/Users/me/noext")));
    }

    #[test]
    fn test_content_subdirs_order() {
        // Files/Data takes priority over Files/Docs over Files.
        let dirs = CONTENT_SUBDIRS;
        assert_eq!(dirs[0], "Files/Data");
        assert_eq!(dirs[1], "Files/Docs");
    }
}

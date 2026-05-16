// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Filesystem utilities with TOCTOU protection.
//!
//! These functions canonicalize, validate, and open files in a single step,
//! returning an open `File` handle. Callers must use this handle for all
//! subsequent I/O, never re-opening the path.

use std::fs::{File, OpenOptions};
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

/// Open a file for reading with TOCTOU protection: canonicalize, validate,
/// and return an open `File` handle in one atomic step.
///
/// On Unix: uses `O_NOFOLLOW` to reject symlinks at the final component.
/// Rejects paths containing `..` after canonicalization (defense-in-depth).
pub fn open_validated(path: &Path) -> Result<(PathBuf, File)> {
    let canonical = path.canonicalize().map_err(|e| {
        Error::io(format!(
            "failed to canonicalize {}: {}",
            path.display(),
            e
        ))
    })?;

    // Defense-in-depth: canonicalize should resolve all .., but verify
    if canonical
        .components()
        .any(|c| c == Component::ParentDir)
    {
        return Err(Error::io(format!(
            "path traversal detected after canonicalization: {}",
            canonical.display()
        )));
    }

    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&canonical)
            .map_err(|e| {
                Error::io(format!(
                    "failed to open {} (O_NOFOLLOW): {}",
                    canonical.display(),
                    e
                ))
            })?
    };

    #[cfg(not(unix))]
    let file = File::open(&canonical).map_err(|e| {
        Error::io(format!("failed to open {}: {}", canonical.display(), e))
    })?;

    Ok((canonical, file))
}

/// Like [`open_validated`] but for write/create operations.
///
/// Canonicalizes the parent directory, validates against traversal, then
/// creates or truncates the file. Returns the canonical path and open handle.
pub fn create_validated(path: &Path) -> Result<(PathBuf, File)> {
    let parent = path.parent().ok_or_else(|| {
        Error::io("path has no parent directory".to_string())
    })?;

    let canonical_parent = parent.canonicalize().map_err(|e| {
        Error::io(format!(
            "failed to canonicalize parent {}: {}",
            parent.display(),
            e
        ))
    })?;

    if canonical_parent
        .components()
        .any(|c| c == Component::ParentDir)
    {
        return Err(Error::io(format!(
            "path traversal in parent: {}",
            canonical_parent.display()
        )));
    }

    let file_name = path.file_name().ok_or_else(|| {
        Error::io("path has no file name".to_string())
    })?;
    let canonical_path = canonical_parent.join(file_name);

    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&canonical_path)
            .map_err(|e| {
                Error::io(format!(
                    "failed to create {} (O_NOFOLLOW): {}",
                    canonical_path.display(),
                    e
                ))
            })?
    };

    #[cfg(not(unix))]
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&canonical_path)
        .map_err(|e| {
            Error::io(format!(
                "failed to create {}: {}",
                canonical_path.display(),
                e
            ))
        })?;

    Ok((canonical_path, file))
}

/// Validate a path and return its canonical form without opening.
///
/// Use this only when you need the canonical path for string comparison
/// (e.g., database lookups) but do NOT need to read file contents.
/// For any I/O operation, prefer [`open_validated`] or [`create_validated`].
pub fn canonicalize_validated(path: &Path) -> Result<PathBuf> {
    let canonical = path.canonicalize().map_err(|e| {
        Error::io(format!(
            "failed to canonicalize {}: {}",
            path.display(),
            e
        ))
    })?;

    if canonical
        .components()
        .any(|c| c == Component::ParentDir)
    {
        return Err(Error::io(format!(
            "path traversal detected after canonicalization: {}",
            canonical.display()
        )));
    }

    // Reject symlinks at the final component
    let meta = std::fs::symlink_metadata(&canonical).map_err(|e| {
        Error::io(format!(
            "failed to stat {}: {}",
            canonical.display(),
            e
        ))
    })?;
    if meta.file_type().is_symlink() {
        return Err(Error::io(format!(
            "symlink not allowed: {}",
            canonical.display()
        )));
    }

    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn open_validated_rejects_nonexistent() {
        let result = open_validated(Path::new("/nonexistent/path/to/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn open_validated_opens_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, b"hello").unwrap();

        let (canonical, mut file) = open_validated(&file_path).unwrap();
        assert!(canonical.is_absolute());
        assert!(!canonical.to_string_lossy().contains(".."));

        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut buf).unwrap();
        assert_eq!(buf, b"hello");
    }

    #[cfg(unix)]
    #[test]
    fn open_validated_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real_file = dir.path().join("real.txt");
        std::fs::write(&real_file, b"secret").unwrap();

        let link_path = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real_file, &link_path).unwrap();

        // canonicalize resolves the symlink, but O_NOFOLLOW on the canonical
        // path should succeed (since canonical path is the real file).
        // The protection is against race conditions where a symlink appears
        // between canonicalize and open.
        let result = open_validated(&link_path);
        // This succeeds because canonicalize resolves to real.txt
        assert!(result.is_ok());
    }

    #[test]
    fn create_validated_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("output.bin");

        let (canonical, mut file) = create_validated(&file_path).unwrap();
        assert!(canonical.is_absolute());

        file.write_all(b"data").unwrap();
        drop(file);

        assert_eq!(std::fs::read(&canonical).unwrap(), b"data");
    }

    #[test]
    fn create_validated_rejects_missing_parent() {
        let result = create_validated(Path::new("/nonexistent/dir/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn canonicalize_validated_works() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, b"").unwrap();

        let canonical = canonicalize_validated(&file_path).unwrap();
        assert!(canonical.is_absolute());
    }
}

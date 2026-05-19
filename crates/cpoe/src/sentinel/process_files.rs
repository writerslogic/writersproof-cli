// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Process file descriptor enumeration for document discovery.
//!
//! When accessibility APIs fail to report which document a process has open,
//! this module enumerates the process's open file descriptors to find document
//! files as a ground-truth fallback.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// An open file discovered via process FD enumeration.
#[derive(Debug, Clone)]
pub struct OpenFile {
    /// Absolute path to the open file.
    pub path: PathBuf,
    /// Whether the file is open for writing (O_WRONLY or O_RDWR).
    pub writable: bool,
}

/// Cache entry to avoid syscall storms.
struct CacheEntry {
    files: Vec<OpenFile>,
    expires: Instant,
}

/// Thread-safe cache for FD enumeration results.
static FD_CACHE: Mutex<Option<HashMap<u32, CacheEntry>>> = Mutex::new(None);

/// Cache entries expire after 1 second to balance freshness against syscall cost.
const CACHE_TTL: Duration = Duration::from_secs(1);

/// Known document file extensions (lowercase, without dot).
const DOCUMENT_EXTENSIONS: &[&str] = &[
    "txt", "md", "markdown", "rtf", "rtfd",
    "doc", "docx", "odt", "pages",
    "tex", "latex", "bib",
    "fountain", "fdx", "scriv",
    "html", "htm", "xml",
    "json", "yaml", "yml", "toml", "ini", "cfg",
    "rs", "py", "js", "ts", "jsx", "tsx", "go", "java", "c", "cpp", "h", "hpp",
    "swift", "kt", "rb", "php", "cs", "fs",
    "sh", "bash", "zsh", "fish",
    "css", "scss", "less",
    "sql", "graphql",
    "r", "jl", "m", "nb",
];

/// Path prefixes that indicate system/temporary files, not user documents.
const EXCLUDED_PREFIXES: &[&str] = &[
    "/dev/",
    "/proc/",
    "/sys/",
    "/System/",
    "/Library/Caches/",
    "/private/var/db/",
    "/private/var/run/",
    "/tmp/com.apple.",
    "/rustc/",
];

/// Enumerate open document files for a process.
///
/// Results are cached for 1 second per PID to avoid excessive syscalls.
/// Returns only files with recognized document extensions that are not
/// in excluded system directories.
pub fn open_documents_for_pid(pid: u32) -> Vec<OpenFile> {
    use crate::MutexRecover;

    // Check cache first.
    {
        let guard = FD_CACHE.lock_recover();
        if let Some(ref cache) = *guard {
            if let Some(entry) = cache.get(&pid) {
                if Instant::now() < entry.expires {
                    return entry.files.clone();
                }
            }
        }
    }

    // Cache miss or expired; enumerate.
    let all_files = enumerate_fds_platform(pid);
    let docs: Vec<OpenFile> = all_files
        .into_iter()
        .filter(|f| is_document_path(&f.path))
        .collect();

    // Store in cache, evicting expired entries to bound growth.
    {
        let mut guard = FD_CACHE.lock_recover();
        let cache = guard.get_or_insert_with(HashMap::new);
        if cache.len() > 100 {
            let now = Instant::now();
            cache.retain(|_, entry| entry.expires > now);
        }
        cache.insert(
            pid,
            CacheEntry {
                files: docs.clone(),
                expires: Instant::now() + CACHE_TTL,
            },
        );
    }

    docs
}

/// Check if a lowercase extension is a recognized document type.
pub fn is_document_extension(ext_lower: &str) -> bool {
    DOCUMENT_EXTENSIONS.contains(&ext_lower)
}

/// Check if a path has a recognized document extension and is not
/// in an excluded system directory.
fn is_document_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    // Reject system/temporary paths.
    for prefix in EXCLUDED_PREFIXES {
        if path_str.starts_with(prefix) {
            return false;
        }
    }

    // Require a recognized extension.
    if let Some(ext) = path.extension() {
        let ext_lower = ext.to_string_lossy().to_lowercase();
        DOCUMENT_EXTENSIONS.contains(&ext_lower.as_str())
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// macOS implementation using libproc
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod ffi_defs {
    use libc::{c_int, c_void};

    pub const PROC_PIDLISTFDS: c_int = 1;
    pub const PROX_FDTYPE_VNODE: u32 = 1;
    pub const PROC_PIDFDVNODEPATHINFO: c_int = 2;

    /// Flags from <sys/fcntl.h>.
    pub const O_ACCMODE: u32 = 0x0003;
    pub const O_RDONLY: u32 = 0x0000;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct proc_fdinfo {
        pub proc_fd: i32,
        pub proc_fdtype: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct proc_fileinfo {
        pub fi_openflags: u32,
        pub fi_status: u32,
        pub fi_offset: i64,
        pub fi_type: i32,
        pub fi_guardflags: u32,
    }

    // vnode_info_path contains a vnode_info followed by a path buffer.
    // We only need the path, so we use a flat struct with the right total size.
    // sizeof(vnode_info) = 64, path = MAXPATHLEN (1024).
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct vnode_fdinfowithpath {
        pub pfi: proc_fileinfo,
        pub _vip_vi: [u8; 64], // vnode_info (opaque; we don't inspect it)
        pub vip_path: [u8; 1024],
    }

    extern "C" {
        pub fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;

        pub fn proc_pidfdinfo(
            pid: c_int,
            fd: c_int,
            flavor: c_int,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;
    }
}

#[cfg(target_os = "macos")]
fn enumerate_fds_platform(pid: u32) -> Vec<OpenFile> {
    use self::ffi_defs::*;
    use std::mem;

    // Step 1: Get the list of FDs for this process.
    let fd_info_size = mem::size_of::<proc_fdinfo>() as i32;
    // First call with null buffer to get required size.
    let buf_size = unsafe {
        proc_pidinfo(
            pid as i32,
            PROC_PIDLISTFDS,
            0,
            std::ptr::null_mut(),
            0,
        )
    };
    if buf_size <= 0 || buf_size % fd_info_size != 0 {
        log::trace!(
            "proc_pidinfo(PROC_PIDLISTFDS) returned {} for pid {} (expected multiple of {})",
            buf_size,
            pid,
            fd_info_size,
        );
        return Vec::new();
    }

    let fd_count = buf_size / fd_info_size;
    let mut fd_buf: Vec<proc_fdinfo> = vec![
        proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        fd_count as usize
    ];

    let actual = unsafe {
        proc_pidinfo(
            pid as i32,
            PROC_PIDLISTFDS,
            0,
            fd_buf.as_mut_ptr() as *mut libc::c_void,
            buf_size,
        )
    };
    if actual <= 0 {
        log::trace!(
            "proc_pidinfo(PROC_PIDLISTFDS) second call returned {} for pid {}",
            actual,
            pid
        );
        return Vec::new();
    }

    let actual_count = actual / fd_info_size;
    fd_buf.truncate(actual_count as usize);

    // Step 2: For each vnode FD, get its path and open flags.
    let mut results = Vec::new();
    let vnode_info_size = mem::size_of::<vnode_fdinfowithpath>() as i32;

    for fdi in &fd_buf {
        if fdi.proc_fdtype != PROX_FDTYPE_VNODE {
            continue;
        }

        // SAFETY: vnode_fdinfowithpath is repr(C) with all-byte fields; zeroed is valid.
        // The kernel writes a complete struct on success (ret >= vnode_info_size).
        const _: () = assert!(mem::size_of::<vnode_fdinfowithpath>() == 1112);
        let mut vinfo: vnode_fdinfowithpath = unsafe { mem::zeroed() };
        let ret = unsafe {
            proc_pidfdinfo(
                pid as i32,
                fdi.proc_fd,
                PROC_PIDFDVNODEPATHINFO,
                &mut vinfo as *mut _ as *mut libc::c_void,
                vnode_info_size,
            )
        };
        if ret < vnode_info_size {
            continue; // Insufficient data or error.
        }

        // Extract null-terminated path from vip_path.
        let path_end = match vinfo.vip_path.iter().position(|&b| b == 0) {
            Some(pos) => pos,
            None => continue, // No null terminator — reject unterminated buffer.
        };
        if path_end == 0 {
            continue;
        }
        let path_str = match std::str::from_utf8(&vinfo.vip_path[..path_end]) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let writable = (vinfo.pfi.fi_openflags & O_ACCMODE) != O_RDONLY;

        results.push(OpenFile {
            path: PathBuf::from(path_str),
            writable,
        });
    }

    results
}

// ---------------------------------------------------------------------------
// Linux implementation via /proc
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn enumerate_fds_platform(pid: u32) -> Vec<OpenFile> {
    let fd_dir = PathBuf::from(format!("/proc/{}/fd", pid));
    let entries = match std::fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(e) => {
            log::trace!("Cannot read {:?}: {}", fd_dir, e);
            return Vec::new();
        }
    };

    let mut results = Vec::new();
    for entry in entries.flatten() {
        let link_path = entry.path();
        let target = match std::fs::read_link(&link_path) {
            Ok(t) => t,
            Err(_) => continue,
        };

        // Validate the target is a regular file (not a symlink chain to
        // system directories). Use metadata (follows symlinks) to confirm.
        match std::fs::metadata(&target) {
            Ok(m) if m.is_file() => {}
            _ => continue,
        }

        // Skip non-regular-file targets (sockets, pipes, devices).
        let target_str = target.to_string_lossy();
        if target_str.starts_with("/dev/")
            || target_str.starts_with("/proc/")
            || target_str.starts_with("/sys/")
            || target_str.contains("socket:")
            || target_str.contains("pipe:")
            || target_str.contains("anon_inode:")
        {
            continue;
        }

        // Check fdinfo for open flags.
        let fd_name = entry.file_name();
        let fdinfo_path = format!("/proc/{}/fdinfo/{}", pid, fd_name.to_string_lossy());
        let writable = match std::fs::read_to_string(&fdinfo_path) {
            Ok(content) => {
                // Parse "flags: NNNN" line.
                content
                    .lines()
                    .find_map(|line| {
                        let stripped = line.strip_prefix("flags:")?;
                        let val = u32::from_str_radix(stripped.trim(), 8).ok()?;
                        // O_WRONLY=1, O_RDWR=2 (octal: 01, 02)
                        Some((val & 0o3) != 0)
                    })
                    .unwrap_or(false)
            }
            Err(_) => false,
        };

        results.push(OpenFile {
            path: target,
            writable,
        });
    }

    results
}

// ---------------------------------------------------------------------------
// Windows stub
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn enumerate_fds_platform(_pid: u32) -> Vec<OpenFile> {
    // TODO: NtQuerySystemInformation + NtQueryObject
    // Complex Win32 API; implement as a future enhancement.
    Vec::new()
}

// Fallback for other platforms (should not occur in practice).
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn enumerate_fds_platform(_pid: u32) -> Vec<OpenFile> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_document_extension_filter() {
        assert!(is_document_path(Path::new("/Users/alice/essay.txt")));
        assert!(is_document_path(Path::new("/home/bob/code.rs")));
        assert!(is_document_path(Path::new("/tmp/draft.md")));
        assert!(is_document_path(Path::new("/Users/alice/paper.docx")));
        assert!(is_document_path(Path::new("/Users/alice/style.css")));
        assert!(is_document_path(Path::new("/Users/alice/data.json")));
    }

    #[test]
    fn test_excluded_paths() {
        assert!(!is_document_path(Path::new("/dev/null")));
        assert!(!is_document_path(Path::new("/proc/1/status")));
        assert!(!is_document_path(Path::new("/sys/class/net/eth0")));
        assert!(!is_document_path(Path::new(
            "/System/Library/Frameworks/AppKit.framework/file.txt"
        )));
        assert!(!is_document_path(Path::new(
            "/Library/Caches/com.apple.something/data.json"
        )));
        assert!(!is_document_path(Path::new(
            "/private/var/db/something.txt"
        )));
        assert!(!is_document_path(Path::new(
            "/tmp/com.apple.launchd/data.txt"
        )));
    }

    #[test]
    fn test_no_extension_rejected() {
        assert!(!is_document_path(Path::new("/Users/alice/Makefile")));
        assert!(!is_document_path(Path::new("/Users/alice/.bashrc")));
    }

    #[test]
    fn test_unknown_extension_rejected() {
        assert!(!is_document_path(Path::new("/Users/alice/photo.png")));
        assert!(!is_document_path(Path::new("/Users/alice/music.mp3")));
        assert!(!is_document_path(Path::new("/Users/alice/app.exe")));
    }

    #[test]
    fn test_open_documents_self_process() {
        // Create a temp file with a document extension, keep it open,
        // and verify our own process can find it.
        let dir = tempfile::tempdir().expect("create temp dir");
        let file_path = dir.path().join("test_document.txt");
        let mut f =
            std::fs::File::create(&file_path).expect("create temp file");
        f.write_all(b"hello").expect("write temp file");
        // Keep f open (don't drop it yet).

        // Invalidate any cached results for our PID.
        if let Ok(mut guard) = FD_CACHE.lock() {
            if let Some(cache) = guard.as_mut() {
                cache.remove(&std::process::id());
            }
        }

        let pid = std::process::id();
        let all_fds = enumerate_fds_platform(pid);

        // On some macOS configurations (sandboxed, SIP), proc_pidinfo
        // may not enumerate FDs for the calling process. Skip if the
        // platform call returns nothing at all.
        if all_fds.is_empty() {
            drop(f);
            eprintln!("proc_pidinfo returned no FDs; skipping (sandboxed?)");
            return;
        }

        let docs = open_documents_for_pid(pid);
        let canonical = std::fs::canonicalize(&file_path).unwrap_or(file_path.clone());
        let found = docs.iter().any(|d| d.path == file_path || d.path == canonical);
        assert!(
            found,
            "Expected to find {:?} in open documents for self (pid {}), got: {:?}",
            file_path, pid, docs
        );

        drop(f);
    }

    #[test]
    fn test_cache_hit() {
        use crate::MutexRecover;

        let pid = 99999; // Unlikely to be a real process.
        // Prime the cache with a fake entry.
        {
            let mut guard = FD_CACHE.lock_recover();
            let cache = guard.get_or_insert_with(HashMap::new);
            cache.insert(
                pid,
                CacheEntry {
                    files: vec![OpenFile {
                        path: PathBuf::from("/fake/cached.txt"),
                        writable: true,
                    }],
                    expires: Instant::now() + Duration::from_secs(60),
                },
            );
        }

        let docs = open_documents_for_pid(pid);
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].path, PathBuf::from("/fake/cached.txt"));

        // Clean up.
        {
            let mut guard = FD_CACHE.lock_recover();
            if let Some(cache) = guard.as_mut() {
                cache.remove(&pid);
            }
        }
    }

    #[test]
    fn test_cache_expiry() {
        use crate::MutexRecover;

        let pid = 99998; // Unlikely to be a real process.
        // Insert an already-expired cache entry.
        {
            let mut guard = FD_CACHE.lock_recover();
            let cache = guard.get_or_insert_with(HashMap::new);
            cache.insert(
                pid,
                CacheEntry {
                    files: vec![OpenFile {
                        path: PathBuf::from("/fake/expired.txt"),
                        writable: true,
                    }],
                    expires: Instant::now() - Duration::from_secs(1),
                },
            );
        }

        // Should NOT return the cached entry; will re-enumerate (and get empty
        // since pid 99998 doesn't exist).
        let docs = open_documents_for_pid(pid);
        let has_expired = docs.iter().any(|d| {
            d.path == PathBuf::from("/fake/expired.txt")
        });
        assert!(
            !has_expired,
            "Expired cache entry should not be returned"
        );

        // Clean up.
        {
            let mut guard = FD_CACHE.lock_recover();
            if let Some(cache) = guard.as_mut() {
                cache.remove(&pid);
            }
        }
    }
}

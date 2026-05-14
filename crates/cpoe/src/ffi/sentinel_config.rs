// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI functions for reading and modifying sentinel configuration
//! (excluded paths, allowed extensions) persisted in writersproof.json.

use super::helpers::get_data_dir;
use super::types::{catch_ffi_panic, FfiResult};
use std::path::PathBuf;

/// Load the config, apply a mutation, persist, and return success/error.
fn with_config_mut(f: impl FnOnce(&mut crate::config::CpopConfig)) -> FfiResult {
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => return FfiResult::err("Cannot determine data directory"),
    };
    let mut config = match crate::config::CpopConfig::load_or_default(&data_dir) {
        Ok(c) => c,
        Err(e) => return FfiResult::err(format!("Failed to load config: {e}")),
    };
    f(&mut config);
    match config.persist() {
        Ok(()) => FfiResult::ok("Settings saved"),
        Err(e) => FfiResult::err(format!("Failed to save config: {e}")),
    }
}

/// Load the current config (read-only).
fn load_config() -> Result<crate::config::CpopConfig, String> {
    let data_dir = get_data_dir().ok_or_else(|| "Cannot determine data directory".to_string())?;
    crate::config::CpopConfig::load_or_default(&data_dir)
        .map_err(|e| format!("Failed to load config: {e}"))
}

// ── Excluded Paths ──────────────────────────────────────────────────

/// Get the list of excluded directory paths.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_config_get_excluded_paths() -> Vec<String> {
    catch_ffi_panic!(Vec::new(), {
    log::debug!("ffi_config_get_excluded_paths called");
    match load_config() {
        Ok(c) => c
            .sentinel
            .excluded_paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
        Err(e) => {
            log::warn!("ffi_config_get_excluded_paths: {e}");
            Vec::new()
        }
    }
    })
}

/// Add a path to the excluded directories list.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_config_add_excluded_path(path: String) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_config_add_excluded_path: path={}", path);
    if path.is_empty() {
        return FfiResult::err("Path cannot be empty");
    }
    if path.len() > 4096 {
        return FfiResult::err("Path too long");
    }
    let new_path = PathBuf::from(&path);
    with_config_mut(|config| {
        if !config
            .sentinel
            .excluded_paths
            .iter()
            .any(|p| p == &new_path)
        {
            config.sentinel.excluded_paths.push(new_path);
        }
    })
    })
}

/// Remove a path from the excluded directories list.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_config_remove_excluded_path(path: String) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_config_remove_excluded_path: path={}", path);
    let target = PathBuf::from(&path);
    with_config_mut(|config| {
        config.sentinel.excluded_paths.retain(|p| p != &target);
    })
    })
}

// ── Allowed Extensions ──────────────────────────────────────────────

/// Get the list of allowed file extensions.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_config_get_allowed_extensions() -> Vec<String> {
    catch_ffi_panic!(Vec::new(), {
    log::debug!("ffi_config_get_allowed_extensions called");
    match load_config() {
        Ok(c) => c.sentinel.allowed_extensions,
        Err(e) => {
            log::warn!("ffi_config_get_allowed_extensions: {e}");
            Vec::new()
        }
    }
    })
}

/// Add a file extension to the allowed list (without leading dot).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_config_add_allowed_extension(extension: String) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_config_add_allowed_extension: extension={}", extension);
    let ext = extension.trim_start_matches('.').to_lowercase();
    if ext.is_empty() {
        return FfiResult::err("Extension cannot be empty");
    }
    with_config_mut(|config| {
        if !config
            .sentinel
            .allowed_extensions
            .iter()
            .any(|e| e.eq_ignore_ascii_case(&ext))
        {
            config.sentinel.allowed_extensions.push(ext);
        }
    })
    })
}

/// Remove a file extension from the allowed list.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_config_remove_allowed_extension(extension: String) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_config_remove_allowed_extension: extension={}", extension);
    let ext = extension.trim_start_matches('.').to_lowercase();
    with_config_mut(|config| {
        config
            .sentinel
            .allowed_extensions
            .retain(|e| !e.eq_ignore_ascii_case(&ext));
    })
    })
}

// ── Research Opt-In ─────────────────────────────────────────────────

/// Get the current research contribution opt-in status.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_config_get_research_enabled() -> bool {
    catch_ffi_panic!(false, {
    log::debug!("ffi_config_get_research_enabled called");
    match load_config() {
        Ok(c) => c.research.contribute_to_research,
        Err(_) => false,
    }
    })
}

/// Enable or disable anonymous research data contribution.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_config_set_research_enabled(enabled: bool) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_config_set_research_enabled: enabled={}", enabled);
    with_config_mut(|config| {
        config.research.contribute_to_research = enabled;
    })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_excluded_paths_roundtrip() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let tmp = std::env::temp_dir().join("cpoe_config_test");
        let _ = std::fs::create_dir_all(&tmp);
        std::env::set_var("CPOE_DATA_DIR", tmp.to_str().expect("temp dir path is not valid UTF-8"));

        // Add a path
        let result = ffi_config_add_excluded_path("/usr/local/exclude_me".to_string());
        assert!(result.success, "add failed: {:?}", result.error_message);

        // Verify it's in the list
        let paths = ffi_config_get_excluded_paths();
        assert!(
            paths.iter().any(|p| p == "/usr/local/exclude_me"),
            "path not found in list: {paths:?}"
        );

        // Remove it
        let result = ffi_config_remove_excluded_path("/usr/local/exclude_me".to_string());
        assert!(result.success, "remove failed: {:?}", result.error_message);

        // Verify it's gone
        let paths = ffi_config_get_excluded_paths();
        assert!(
            !paths.iter().any(|p| p == "/usr/local/exclude_me"),
            "path still in list after removal"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_allowed_extensions_roundtrip() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let tmp = std::env::temp_dir().join("cpoe_config_test_ext");
        let _ = std::fs::create_dir_all(&tmp);
        std::env::set_var("CPOE_DATA_DIR", tmp.to_str().expect("temp dir path is not valid UTF-8"));

        // Add an extension
        let result = ffi_config_add_allowed_extension(".xyz".to_string());
        assert!(result.success, "add failed: {:?}", result.error_message);

        let exts = ffi_config_get_allowed_extensions();
        assert!(
            exts.iter().any(|e| e == "xyz"),
            "extension not found: {exts:?}"
        );

        // Remove it
        let result = ffi_config_remove_allowed_extension("xyz".to_string());
        assert!(result.success);

        let exts = ffi_config_get_allowed_extensions();
        assert!(!exts.iter().any(|e| e == "xyz"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_add_empty_path_rejected() {
        let result = ffi_config_add_excluded_path(String::new());
        assert!(!result.success);
    }

    #[test]
    fn test_add_empty_extension_rejected() {
        let result = ffi_config_add_allowed_extension(String::new());
        assert!(!result.success);
    }

    #[test]
    fn test_duplicate_path_idempotent() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let tmp = std::env::temp_dir().join("cpoe_config_test_dup");
        let _ = std::fs::create_dir_all(&tmp);
        std::env::set_var("CPOE_DATA_DIR", tmp.to_str().expect("temp dir path is not valid UTF-8"));

        ffi_config_add_excluded_path("/tmp/dup_test".to_string());
        ffi_config_add_excluded_path("/tmp/dup_test".to_string());

        let paths = ffi_config_get_excluded_paths();
        let count = paths.iter().filter(|p| *p == "/tmp/dup_test").count();
        assert_eq!(count, 1, "duplicate path should not be added twice");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}

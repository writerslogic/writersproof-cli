// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI functions for the user writing-app registry: probe, add, remove, list.

use super::helpers::get_data_dir;
use super::types::{catch_ffi_panic, FfiResult};

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiProbeResult {
    pub success: bool,
    pub display_name: String,
    pub storage: String,
    pub container_paths: Vec<String>,
    pub needs_title_inference: bool,
    pub confidence: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiUserApp {
    pub bundle_id: String,
    pub display_name: String,
    pub storage: String,
    pub container_paths: Vec<String>,
    pub needs_title_inference: bool,
    pub confidence: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiUserAppListResult {
    pub success: bool,
    pub apps: Vec<FfiUserApp>,
    pub error_message: Option<String>,
}

// ---------------------------------------------------------------------------
// FFI functions
// ---------------------------------------------------------------------------

/// Probe an app by bundle ID. Returns auto-discovered metadata and confidence.
/// Does not persist anything.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_probe_app(bundle_id: String) -> FfiProbeResult {
    catch_ffi_panic!(FfiProbeResult {
        success: false,
        display_name: String::new(),
        storage: String::new(),
        container_paths: Vec::new(),
        needs_title_inference: false,
        confidence: String::new(),
        error_message: Some("engine internal error".to_string()),
    }, {
    log::debug!("ffi_probe_app: bundle_id={}", bundle_id);
    let result = crate::sentinel::app_discovery::probe_app(&bundle_id);
    FfiProbeResult {
        success: true,
        display_name: result.display_name,
        storage: storage_to_str(result.storage),
        container_paths: result.container_paths,
        needs_title_inference: result.needs_title_inference,
        confidence: confidence_to_str(result.confidence),
        error_message: None,
    }
    })
}

/// Add a user app to the registry. Persists immediately.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_add_user_writing_app(
    bundle_id: String,
    display_name: String,
    storage: String,
    container_paths: Vec<String>,
    needs_title_inference: bool,
    confidence: String,
) -> FfiResult {
    catch_ffi_panic!(@err FfiResult, {
    log::debug!("ffi_add_user_writing_app: bundle_id={}, display_name={}", bundle_id, display_name);
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => return FfiResult::err("Cannot determine data directory"),
    };
    let storage_pat = match str_to_storage(&storage) {
        Some(s) => s,
        None => return FfiResult::err(format!("Unknown storage pattern: {storage}")),
    };
    let probe_confidence = str_to_confidence(&confidence);
    let app = crate::sentinel::app_registry::UserWritingApp {
        bundle_id,
        display_name,
        storage: storage_pat,
        container_paths,
        needs_title_inference,
        added_at: std::time::SystemTime::now(),
        probe_confidence,
        witnessing_mode: crate::sentinel::app_registry::WitnessingMode::default(),
    };
    let mut registry = crate::sentinel::app_registry::AppRegistry::load(&data_dir);
    match registry.add_user_app(app) {
        Ok(()) => FfiResult::ok("App added"),
        Err(e) => FfiResult::err(format!("{e}")),
    }
    })
}

/// Remove a user app by bundle ID. Persists immediately.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_remove_user_writing_app(bundle_id: String) -> FfiResult {
    catch_ffi_panic!(@err FfiResult, {
    log::debug!("ffi_remove_user_writing_app: bundle_id={}", bundle_id);
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => return FfiResult::err("Cannot determine data directory"),
    };
    let mut registry = crate::sentinel::app_registry::AppRegistry::load(&data_dir);
    match registry.remove_user_app(&bundle_id) {
        Ok(true) => FfiResult::ok("App removed"),
        Ok(false) => FfiResult::err(format!("No user app with bundle ID '{bundle_id}'")),
        Err(e) => FfiResult::err(format!("{e}")),
    }
    })
}

/// List all user-added apps (does not include built-in).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_list_user_writing_apps() -> FfiUserAppListResult {
    catch_ffi_panic!(FfiUserAppListResult {
        success: false,
        apps: Vec::new(),
        error_message: Some("engine internal error".to_string()),
    }, {
    log::debug!("ffi_list_user_writing_apps");
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => {
            return FfiUserAppListResult {
                success: false,
                apps: Vec::new(),
                error_message: Some("Cannot determine data directory".to_string()),
            }
        }
    };
    let registry = crate::sentinel::app_registry::AppRegistry::load(&data_dir);
    let apps = registry
        .user_apps()
        .iter()
        .map(|a| FfiUserApp {
            bundle_id: a.bundle_id.clone(),
            display_name: a.display_name.clone(),
            storage: storage_to_str(a.storage),
            container_paths: a.container_paths.clone(),
            needs_title_inference: a.needs_title_inference,
            confidence: confidence_to_str(a.probe_confidence),
        })
        .collect();
    FfiUserAppListResult {
        success: true,
        apps,
        error_message: None,
    }
    })
}

/// Discover recently modified documents in ~/Documents, ~/Desktop, ~/Downloads.
///
/// Scans for files matching the configured `allowed_extensions` that were
/// modified within `max_age_hours`. Returns up to 20 paths sorted by
/// modification time (most recent first).
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_discover_recent_documents(max_age_hours: u64) -> Vec<String> {
    catch_ffi_panic!(Vec::new(), {
    log::debug!("ffi_discover_recent_documents: max_age_hours={}", max_age_hours);
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };

    let scan_dirs = [
        home.join("Documents"),
        home.join("Desktop"),
        home.join("Downloads"),
    ];
    let dir_refs: Vec<&std::path::Path> = scan_dirs.iter().map(|d| d.as_path()).collect();

    let config = crate::config::SentinelConfig::default();
    let results = crate::sentinel::app_discovery::discover_recent_documents(
        &dir_refs,
        max_age_hours,
        &config.allowed_extensions,
    );

    results
        .into_iter()
        .filter_map(|p| p.to_str().map(String::from))
        .collect()
    })
}

// ---------------------------------------------------------------------------
// String ↔ enum conversions (FFI boundary uses strings, not enums)
// ---------------------------------------------------------------------------

fn storage_to_str(s: crate::sentinel::app_registry::StoragePattern) -> String {
    use crate::sentinel::app_registry::StoragePattern::*;
    match s {
        FileBased => "file_based",
        ContainerBased => "container_based",
        CloudLibrary => "cloud_library",
        DatabaseBacked => "database_backed",
        BundleBased => "bundle_based",
    }
    .to_string()
}

fn str_to_storage(s: &str) -> Option<crate::sentinel::app_registry::StoragePattern> {
    use crate::sentinel::app_registry::StoragePattern::*;
    match s {
        "file_based" => Some(FileBased),
        "container_based" => Some(ContainerBased),
        "cloud_library" => Some(CloudLibrary),
        "database_backed" => Some(DatabaseBacked),
        "bundle_based" => Some(BundleBased),
        _ => None,
    }
}

fn confidence_to_str(c: crate::sentinel::app_registry::ProbeConfidence) -> String {
    use crate::sentinel::app_registry::ProbeConfidence::*;
    match c {
        High => "high",
        Medium => "medium",
        Low => "low",
    }
    .to_string()
}

fn str_to_confidence(s: &str) -> crate::sentinel::app_registry::ProbeConfidence {
    use crate::sentinel::app_registry::ProbeConfidence::*;
    match s {
        "high" => High,
        "medium" => Medium,
        _ => Low,
    }
}

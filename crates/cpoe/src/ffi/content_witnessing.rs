// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! FFI bindings for content-level witnessing: mode/granularity configuration,
//! content segmentation, paragraph MMR witnessing, and derivation proofs.

use super::helpers::get_data_dir;
use super::types::{catch_ffi_panic, try_ffi, FfiResult};
use crate::content::mmr::ContentMmr;
use crate::sentinel::app_registry::{ContentGranularity, WitnessingMode};

// ---------------------------------------------------------------------------
// FFI types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiWitnessingConfig {
    pub success: bool,
    pub witnessing_mode: String,
    pub content_granularity: String,
    pub error_message: Option<String>,
}

crate::ffi::types::impl_ffi_err!(FfiWitnessingConfig);

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiWitnessResult {
    pub success: bool,
    pub segments_witnessed: u64,
    pub mmr_root_hex: String,
    pub mmr_leaf_count: u64,
    pub error_message: Option<String>,
}

crate::ffi::types::impl_ffi_err!(FfiWitnessResult);

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiDerivationProofResult {
    pub success: bool,
    pub session_id: String,
    pub granularity: String,
    pub mmr_root_hex: String,
    pub matched_count: u64,
    pub derived_total: u64,
    pub coverage: f64,
    pub verified: bool,
    pub error_message: Option<String>,
}

crate::ffi::types::impl_ffi_err!(FfiDerivationProofResult);

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiResolvedMode {
    pub success: bool,
    pub resolved_mode: String,
    pub error_message: Option<String>,
}

crate::ffi::types::impl_ffi_err!(FfiResolvedMode);

// ---------------------------------------------------------------------------
// Configuration FFI
// ---------------------------------------------------------------------------

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_witnessing_config() -> FfiWitnessingConfig {
    catch_ffi_panic!(@err FfiWitnessingConfig, {
    log::debug!("ffi_get_witnessing_config called");
    let data_dir = try_ffi!(
        get_data_dir().ok_or("Cannot determine data directory"),
        FfiWitnessingConfig
    );
    let config = try_ffi!(
        crate::config::CpopConfig::load_or_default(&data_dir),
        FfiWitnessingConfig
    );
    FfiWitnessingConfig {
        success: true,
        witnessing_mode: config.sentinel.default_witnessing_mode.as_str().to_string(),
        content_granularity: config.sentinel.default_content_granularity.as_str().to_string(),
        error_message: None,
    }
    })
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_set_witnessing_mode(mode: String) -> FfiResult {
    catch_ffi_panic!(@err FfiResult, {
    log::debug!("ffi_set_witnessing_mode: mode={}", mode);
    let parsed = match mode.parse::<WitnessingMode>() {
        Ok(m) => m,
        Err(()) => return FfiResult::err(format!(
            "Invalid witnessing mode: {mode}. Valid: auto, file_level, content_level, hybrid"
        )),
    };
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => return FfiResult::err("Cannot determine data directory"),
    };
    let mut config = match crate::config::CpopConfig::load_or_default(&data_dir) {
        Ok(c) => c,
        Err(e) => return FfiResult::err(format!("Failed to load config: {e}")),
    };
    config.sentinel.default_witnessing_mode = parsed;
    match config.persist() {
        Ok(()) => FfiResult::ok("Witnessing mode saved"),
        Err(e) => FfiResult::err(format!("Failed to save config: {e}")),
    }
    })
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_set_content_granularity(granularity: String) -> FfiResult {
    catch_ffi_panic!(@err FfiResult, {
    log::debug!("ffi_set_content_granularity: granularity={}", granularity);
    let parsed = match granularity.parse::<ContentGranularity>() {
        Ok(g) => g,
        Err(()) => return FfiResult::err(format!(
            "Invalid granularity: {granularity}. Valid: paragraph, sentence, block"
        )),
    };
    let data_dir = match get_data_dir() {
        Some(d) => d,
        None => return FfiResult::err("Cannot determine data directory"),
    };
    let mut config = match crate::config::CpopConfig::load_or_default(&data_dir) {
        Ok(c) => c,
        Err(e) => return FfiResult::err(format!("Failed to load config: {e}")),
    };
    config.sentinel.default_content_granularity = parsed;
    match config.persist() {
        Ok(()) => FfiResult::ok("Content granularity saved"),
        Err(e) => FfiResult::err(format!("Failed to save config: {e}")),
    }
    })
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_resolve_witnessing_mode(bundle_id: String, document_path: String) -> FfiResolvedMode {
    catch_ffi_panic!(@err FfiResolvedMode, {
    log::debug!("ffi_resolve_witnessing_mode: bundle_id={} path={}", bundle_id, document_path);

    let data_dir = try_ffi!(
        get_data_dir().ok_or("Cannot determine data directory"),
        FfiResolvedMode
    );
    let config = try_ffi!(
        crate::config::CpopConfig::load_or_default(&data_dir),
        FfiResolvedMode
    );

    let registry = crate::sentinel::app_registry::AppRegistry::load(&data_dir);
    let (app_mode, storage) = if let Some(user_app) = registry.lookup_user(&bundle_id) {
        (user_app.witnessing_mode, user_app.storage)
    } else if let Some(builtin) = crate::sentinel::app_registry::lookup(&bundle_id) {
        (builtin.witnessing_mode, builtin.storage)
    } else {
        // Unknown app: infer from file extension, falling back to FileLevel.
        let inferred = WitnessingMode::infer_from_extension(&document_path);
        (inferred, crate::sentinel::app_registry::StoragePattern::FileBased)
    };

    // If app has Auto, check global override
    let effective_mode = if app_mode == WitnessingMode::Auto {
        let global = config.sentinel.default_witnessing_mode;
        if global != WitnessingMode::Auto {
            global
        } else {
            app_mode.resolve(storage)
        }
    } else {
        app_mode
    };

    FfiResolvedMode {
        success: true,
        resolved_mode: effective_mode.as_str().to_string(),
        error_message: None,
    }
    })
}

// ---------------------------------------------------------------------------
// Content Witnessing FFI
// ---------------------------------------------------------------------------

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_content_witness_text(
    session_id: String,
    text: String,
    granularity: String,
) -> FfiWitnessResult {
    catch_ffi_panic!(FfiWitnessResult {
        success: false,
        error_message: Some("engine internal error".to_string()),
        ..Default::default()
    }, {
    log::debug!(
        "ffi_content_witness_text: session_id={}, text_len={}, granularity={}",
        session_id,
        text.len(),
        granularity
    );

    let gran = match granularity.parse::<ContentGranularity>() {
        Ok(g) => g,
        Err(()) => return FfiWitnessResult {
            success: false,
            error_message: Some(format!("Invalid granularity: {granularity}")),
            ..Default::default()
        },
    };

    let mmr_dir = match ContentMmr::default_mmr_dir() {
        Ok(d) => d,
        Err(e) => return FfiWitnessResult {
            success: false,
            error_message: Some(format!("MMR dir error: {e}")),
            ..Default::default()
        },
    };

    let mmr = match ContentMmr::open(&mmr_dir, &session_id, gran) {
        Ok(m) => m,
        Err(e) => return FfiWitnessResult {
            success: false,
            error_message: Some(format!("Failed to open content MMR: {e}")),
            ..Default::default()
        },
    };

    let witnessed = match mmr.witness_text(&text) {
        Ok(w) => w,
        Err(e) => return FfiWitnessResult {
            success: false,
            error_message: Some(format!("Failed to witness text: {e}")),
            ..Default::default()
        },
    };

    let root = match mmr.root() {
        Ok(r) => hex::encode(r),
        Err(e) => return FfiWitnessResult {
            success: false,
            error_message: Some(format!("Failed to get MMR root: {e}")),
            ..Default::default()
        },
    };

    FfiWitnessResult {
        success: true,
        segments_witnessed: witnessed.len() as u64,
        mmr_root_hex: root,
        mmr_leaf_count: mmr.leaf_count(),
        error_message: None,
    }
    })
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_generate_derivation_proof(
    session_id: String,
    derived_text: String,
    granularity: String,
) -> FfiDerivationProofResult {
    catch_ffi_panic!(FfiDerivationProofResult {
        success: false,
        error_message: Some("engine internal error".to_string()),
        ..Default::default()
    }, {
    log::debug!(
        "ffi_generate_derivation_proof: session_id={}, derived_len={}, granularity={}",
        session_id,
        derived_text.len(),
        granularity
    );

    let gran = match granularity.parse::<ContentGranularity>() {
        Ok(g) => g,
        Err(()) => return FfiDerivationProofResult {
            success: false,
            error_message: Some(format!("Invalid granularity: {granularity}")),
            ..Default::default()
        },
    };

    let mmr_dir = match ContentMmr::default_mmr_dir() {
        Ok(d) => d,
        Err(e) => return FfiDerivationProofResult {
            success: false,
            error_message: Some(format!("MMR dir error: {e}")),
            ..Default::default()
        },
    };

    let mmr = match ContentMmr::open(&mmr_dir, &session_id, gran) {
        Ok(m) => m,
        Err(e) => return FfiDerivationProofResult {
            success: false,
            error_message: Some(format!("Failed to open content MMR: {e}")),
            ..Default::default()
        },
    };

    let proof = match mmr.generate_derivation_proof(&derived_text) {
        Ok(p) => p,
        Err(e) => return FfiDerivationProofResult {
            success: false,
            error_message: Some(format!("Failed to generate proof: {e}")),
            ..Default::default()
        },
    };

    let verified = proof.verify();
    FfiDerivationProofResult {
        success: true,
        session_id: proof.session_id,
        granularity: proof.granularity.as_str().to_string(),
        mmr_root_hex: hex::encode(proof.mmr_root),
        matched_count: proof.matches.len() as u64,
        derived_total: proof.derived_total as u64,
        coverage: proof.coverage,
        verified,
        error_message: None,
    }
    })
}

// ---------------------------------------------------------------------------
// Active window text capture FFI
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "ffi", derive(uniffi::Record))]
pub struct FfiCapturedText {
    pub success: bool,
    pub text: String,
    pub error_message: Option<String>,
}

crate::ffi::types::impl_ffi_err!(FfiCapturedText);

/// Capture the current text content from an application's focused window.
///
/// Used at export time for virtual (`title://`) sessions to retrieve the
/// compose window text for proof block generation. The `bundle_id` identifies
/// the target application (e.g. `com.apple.mail`). When `window_title` is
/// non-empty, targets that specific window instead of the focused one.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_capture_window_text(bundle_id: String, window_title: String) -> FfiCapturedText {
    catch_ffi_panic!(FfiCapturedText {
        success: false,
        error_message: Some("engine internal error".to_string()),
        ..Default::default()
    }, {
    log::debug!("ffi_capture_window_text: bundle_id={}, title={}", bundle_id, window_title);

    let title = if window_title.is_empty() { None } else { Some(window_title.as_str()) };
    let result = crate::platform::window_text::WindowTextCapture::capture_text_for_bundle_id_and_title(
        &bundle_id, title,
    );

    match result {
        Some(text) if !text.is_empty() => FfiCapturedText {
            success: true,
            text,
            error_message: None,
        },
        _ => FfiCapturedText {
            success: false,
            text: String::new(),
            error_message: Some(
                "Could not capture text. Ensure the compose window is still open."
                    .to_string(),
            ),
        },
    }
    })
}

// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::open_store;
use crate::ffi::types::{catch_ffi_panic, try_ffi, FfiResult};

use super::evidence::device_identity;

/// Create a manual checkpoint for a file, hashing its current content.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_create_checkpoint(path: String, message: String) -> FfiResult {
    catch_ffi_panic!(@err FfiResult, {
    log::debug!("ffi_create_checkpoint: path={} message_len={}", path, message.len());
    // Truncate at a char boundary to avoid panicking on multi-byte UTF-8 sequences.
    let message = if message.len() > 4096 {
        message.chars().take(4096).collect()
    } else {
        message
    };
    let file_path = try_ffi!(
        crate::sentinel::helpers::validate_path(&path).map_err(|e| e.to_string()),
        FfiResult
    );
    let mut store = try_ffi!(open_store(), FfiResult);
    // Unsaved/virtual documents (title://, shadow://, ephemeral://) have no file on
    // disk to hash; bind the checkpoint to the document identifier instead so that
    // pasting/checkpointing into an unsaved doc still records the event (file_size
    // already degrades to 0 below for the same reason).
    let content_hash = if file_path.exists() {
        try_ffi!(
            crate::crypto::hash_file(&file_path).map_err(|e| format!("Failed to hash file: {e}")),
            FfiResult
        )
    } else {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(file_path.to_string_lossy().as_bytes());
        hasher.finalize().into()
    };

    let file_size = std::fs::metadata(&file_path)
        .map(|m| m.len() as i64)
        .unwrap_or(0);

    let context_note = if message.is_empty() {
        None
    } else {
        Some(message)
    };

    let (dev_id, mach_id) = device_identity();
    // Use canonicalized path so export/log lookups match
    let mut event = crate::store::SecureEvent::new(
        file_path.to_string_lossy().to_string(),
        content_hash,
        file_size,
        context_note,
    );
    event.device_id = dev_id;
    event.machine_id = mach_id.clone();

    match store.add_secure_event(&mut event) {
        Ok(_) => FfiResult::ok(format!(
            "Checkpoint created: {}",
            crate::utils::short_hex_id(&content_hash)
        )),
        Err(e) => FfiResult::err(format!("Failed to create checkpoint: {}", e)),
    }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::evidence_export::ffi_get_compact_ref;
    use crate::ffi::system::ffi_init;
    use tempfile::TempDir;

    fn setup_temp_data_dir() -> TempDir {
        let dir = TempDir::new().expect("create temp dir");
        std::env::set_var("CPOE_DATA_DIR", dir.path());
        dir
    }

    #[test]
    fn checkpoint_success_returns_hash() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success, "init failed: {:?}", init.error_message);

        let file_path = dir.path().join("doc.txt");
        std::fs::write(&file_path, "Hello, CPoE!").expect("write test file");

        let result = ffi_create_checkpoint(file_path.to_string_lossy().to_string(), String::new());
        assert!(
            result.success,
            "checkpoint failed: {:?}",
            result.error_message
        );
        // Message should contain the hex-encoded content hash prefix.
        let msg = result.message.unwrap();
        assert!(
            msg.starts_with("Checkpoint created:"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn checkpoint_missing_file_returns_error() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success);

        let bogus = dir.path().join("nonexistent.txt");
        let result = ffi_create_checkpoint(bogus.to_string_lossy().to_string(), String::new());
        assert!(!result.success);
        assert!(result.error_message.is_some());
    }

    #[test]
    fn checkpoint_with_tool_declaration_message() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success, "init failed: {:?}", init.error_message);

        let file_path = dir.path().join("assisted.txt");
        std::fs::write(&file_path, "Content created with AI tools").expect("write file");

        let result = ffi_create_checkpoint(
            file_path.to_string_lossy().to_string(),
            "[tool:ai:ChatGPT]".to_string(),
        );
        assert!(
            result.success,
            "checkpoint with tool declaration failed: {:?}",
            result.error_message
        );
    }

    #[test]
    fn compact_ref_empty_before_checkpoint() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success);

        let file_path = dir.path().join("no_checkpoints.txt");
        std::fs::write(&file_path, "nothing yet").expect("write file");

        let compact = ffi_get_compact_ref(file_path.to_string_lossy().to_string());
        assert!(
            compact.is_empty(),
            "expected empty compact ref, got: {compact}"
        );
    }

    #[test]
    fn compact_ref_nonempty_after_checkpoint() {
        let _lock = crate::ffi::helpers::lock_ffi_env();
        let _data_dir = setup_temp_data_dir();

        let init = ffi_init();
        assert!(init.success);

        // Use a separate temp file outside the data dir to avoid path canonicalization issues
        let file_dir = TempDir::new().expect("create file dir");
        let file_path = file_dir.path().join("tracked.txt");
        std::fs::write(&file_path, "tracked content").expect("write file");

        let canonical = file_path.canonicalize().expect("canonicalize");
        let path_str = canonical.to_string_lossy().to_string();

        let cp = ffi_create_checkpoint(path_str.clone(), "initial".to_string());
        assert!(cp.success, "checkpoint failed: {:?}", cp.error_message);

        let compact = ffi_get_compact_ref(path_str);
        assert!(
            compact.starts_with("cpoe-ref:writerslogic:"),
            "expected compact ref prefix, got: {compact}"
        );
    }
}

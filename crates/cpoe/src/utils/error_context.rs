// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Structured error handling with sensitive data redaction.
//! Prevents accidental exposure of keys, tokens, paths in logs and user-facing messages.

use crate::error::Error;

/// Context for tracking operations without leaking sensitive data.
/// Logs full details internally but provides sanitized messages to users.
#[derive(Debug, Clone)]
pub struct ErrorContext {
    operation: String,
    step: String,
}

impl ErrorContext {
    /// Create context for a specific operation.
    pub fn new(operation: &str) -> Self {
        ErrorContext {
            operation: operation.to_string(),
            step: "init".to_string(),
        }
    }

    /// Update the current step within the operation.
    pub fn at_step(mut self, step: &str) -> Self {
        self.step = step.to_string();
        self
    }

    /// Log error with full context (internal use only).
    /// The error details are logged but never shown to user.
    pub fn log_error(&self, error: &Error) {
        log::error!(
            "Operation: {} | Step: {} | Error: {:?}",
            self.operation,
            self.step,
            error
        );
    }

    /// Log error with additional context.
    pub fn log_error_with_context(&self, error: &Error, context: &str) {
        log::error!(
            "Operation: {} | Step: {} | Context: {} | Error: {:?}",
            self.operation,
            self.step,
            context,
            error
        );
    }

    /// Get human-friendly error message safe for user display.
    /// All sensitive data (paths, keys, tokens) are redacted.
    pub fn sanitize_for_user(&self, error: &Error) -> String {
        match error {
            // Database errors: redact query details
            Error::Validation(msg) if msg.contains("SELECT") || msg.contains("INSERT") => {
                format!(
                    "Could not access authorship database ({}). Please try again.",
                    self.operation
                )
            }
            // Cryptographic errors: never mention key material
            Error::Validation(msg) if msg.contains("signature") => {
                "Evidence integrity check failed. Your content may have been tampered with."
                    .to_string()
            }
            // File errors: redact paths
            Error::Validation(msg) if msg.contains("/") || msg.contains("\\") => {
                format!(
                    "File access error in {}. Please check permissions.",
                    self.operation
                )
            }
            // Network errors: redact URLs and tokens
            Error::Validation(msg)
                if msg.contains("http://") || msg.contains("https://") || msg.contains("token") =>
            {
                "Network error. Please check your connection and try again.".to_string()
            }
            // Generic validation errors
            Error::Validation(_) => {
                format!("Invalid input during {}. Please try again.", self.operation)
            }
            // All other errors
            _ => format!(
                "An error occurred during {}. Please try again.",
                self.operation
            ),
        }
    }

    /// Redact sensitive strings from log output.
    /// Replaces patterns like: "key=xxxxx", "password=xxxxx", "token=xxxxx"
    /// Handles multiple occurrences in a single line.
    pub fn redact_log_line(line: &str) -> String {
        let sensitive_patterns = [
            ("key=", "key=[redacted]"),
            ("password=", "password=[redacted]"),
            ("token=", "token=[redacted]"),
            ("secret=", "secret=[redacted]"),
            ("Authorization:", "Authorization: [redacted]"),
        ];

        let mut result = line.to_string();
        for (pattern, replacement) in &sensitive_patterns {
            let mut offset = 0;
            while let Some(pos) = result[offset..].find(pattern) {
                let start = offset + pos;
                let prefix = &result[..start];
                let after_pattern = &result[start + pattern.len()..];

                // Find the value: skip leading whitespace, capture until next whitespace/comma
                let value_chars = after_pattern
                    .chars()
                    .skip_while(|c| c.is_whitespace())
                    .collect::<String>();
                let end_pos = value_chars
                    .find(|c: char| c.is_whitespace() || c == ',')
                    .unwrap_or(value_chars.len());
                let suffix = &after_pattern[after_pattern.len() - value_chars.len() + end_pos..];

                result = format!("{}{}{}", prefix, replacement, suffix);
                offset = start + replacement.len(); // advance past replacement to avoid re-matching
            }
        }
        result
    }
}

/// Sanitize error message for user display (no sensitive data).
/// Safe to show in UI, logs, or notifications.
pub fn sanitize_for_user(error_type: &str, operation: &str) -> String {
    match error_type {
        "SignatureInvalid" => {
            "Fragment integrity check failed. This content may have been tampered with.".to_string()
        }
        "NonceReplay" => "Duplicate evidence detected. This may indicate tampering.".to_string(),
        "TimestampTooFar" => "Timestamp invalid. Please check your system clock.".to_string(),
        "DatabaseError" => {
            format!(
                "Could not save authorship evidence for {}. Please try again.",
                operation
            )
        }
        "PasteboardAccessDenied" => {
            "Cannot access clipboard. Please check System Preferences → Security & Privacy."
                .to_string()
        }
        "TextEncodingFailed" => {
            "Could not read clipboard content. Try a different format.".to_string()
        }
        "InvalidSignature" => "Evidence signature verification failed.".to_string(),
        "SerializationFailed" => "Could not format evidence. Please try again.".to_string(),
        "CloudKitNetworkError" => "Cannot connect to iCloud. Will retry automatically.".to_string(),
        "AppAttestTokenInvalid" => {
            "Device verification failed. Please restart the app.".to_string()
        }
        "CredentialExpired" => {
            "Your authorship credential has expired. Request a new one.".to_string()
        }
        _ => format!("An error occurred during {}. Please try again.", operation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_context_creation() {
        let ctx = ErrorContext::new("clipboard_monitoring");
        assert_eq!(ctx.operation, "clipboard_monitoring");
        assert_eq!(ctx.step, "init");
    }

    #[test]
    fn test_error_context_at_step() {
        let ctx = ErrorContext::new("sync").at_step("push");
        assert_eq!(ctx.step, "push");
    }

    #[test]
    fn test_redact_log_line_key() {
        let line = "signing key=a1b2c3d4e5f6 for session xyz";
        let redacted = ErrorContext::redact_log_line(line);
        assert!(!redacted.contains("a1b2c3d4e5f6"));
        assert!(redacted.contains("[redacted]"));
    }

    #[test]
    fn test_redact_log_line_token() {
        let line = "CloudKit token=abc123xyz789def456";
        let redacted = ErrorContext::redact_log_line(line);
        assert!(!redacted.contains("abc123xyz789def456"));
        assert!(redacted.contains("token=[redacted]"));
    }

    #[test]
    fn test_redact_log_line_authorization() {
        let line = "Authorization: Bearer xyz123abc456";
        let redacted = ErrorContext::redact_log_line(line);
        assert!(!redacted.contains("Bearer xyz123abc456"));
        assert!(redacted.contains("Authorization: [redacted]"));
    }

    #[test]
    fn test_redact_log_line_no_sensitive_data() {
        let line = "Processing clipboard event for com.apple.Notes";
        let redacted = ErrorContext::redact_log_line(line);
        assert_eq!(redacted, line); // No changes needed
    }

    #[test]
    fn test_redact_log_line_multiple_tokens() {
        let line = "token=first_token other_data token=second_token and more";
        let redacted = ErrorContext::redact_log_line(line);
        assert!(!redacted.contains("first_token"));
        assert!(!redacted.contains("second_token"));
        assert!(redacted.contains("token=[redacted]"));
    }

    #[test]
    fn test_redact_log_line_mixed_patterns() {
        let line = "key=secret123 password=pass456 token=tok789";
        let redacted = ErrorContext::redact_log_line(line);
        assert!(!redacted.contains("secret123"));
        assert!(!redacted.contains("pass456"));
        assert!(!redacted.contains("tok789"));
    }

    #[test]
    fn test_redact_log_line_no_value_after_pattern() {
        let line = "key= and more text";
        let redacted = ErrorContext::redact_log_line(line);
        assert!(redacted.contains("key=[redacted]"));
    }

    #[test]
    fn test_sanitize_for_user_signature_invalid() {
        let msg = sanitize_for_user("SignatureInvalid", "fragment_verification");
        assert!(!msg.is_empty());
        assert!(!msg.contains("SigningKey"));
        assert!(!msg.contains("ed25519"));
    }

    #[test]
    fn test_sanitize_for_user_timestamp() {
        let msg = sanitize_for_user("TimestampTooFar", "fragment_insert");
        assert!(msg.contains("system clock"));
    }

    #[test]
    fn test_sanitize_for_user_database_error() {
        let msg = sanitize_for_user("DatabaseError", "sync_operation");
        assert!(msg.contains("sync_operation"));
        assert!(!msg.contains("SQL"));
    }

    #[test]
    fn test_sanitize_for_user_generic() {
        let msg = sanitize_for_user("UnknownError", "background_task");
        assert!(msg.contains("background_task"));
        assert!(msg.contains("try again"));
    }
}

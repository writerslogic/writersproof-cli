// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::messages::IpcMessage;
use serde::{Deserialize, Serialize};

/// Role-based access control for IPC clients.
///
/// The default role is `ReadOnly` (fail-closed). Callers must explicitly
/// elevate to `User` or `Admin` after authentication.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IpcRole {
    /// Can only read status and query information.
    #[default]
    ReadOnly = 0,
    /// Can start/stop witnessing, create checkpoints, export evidence.
    User = 1,
    /// Can change configuration, manage keys and identity.
    Admin = 2,
}

/// Return the minimum role required to process the given message.
pub fn required_role(msg: &IpcMessage) -> IpcRole {
    match msg {
        // Read-only: status queries, heartbeats, handshakes, responses
        IpcMessage::Handshake { .. }
        | IpcMessage::GetStatus
        | IpcMessage::GetAttestationNonce
        | IpcMessage::Heartbeat
        | IpcMessage::VerifyFile { .. }
        | IpcMessage::VerifyWithNonce { .. }
        | IpcMessage::GetFileForensics { .. }
        | IpcMessage::ComputeProcessScore { .. }
        // All response types are read-only (server-originated)
        | IpcMessage::Ok { .. }
        | IpcMessage::Error { .. }
        | IpcMessage::HandshakeAck { .. }
        | IpcMessage::HeartbeatAck { .. }
        | IpcMessage::StatusResponse { .. }
        | IpcMessage::AttestationNonceResponse { .. }
        | IpcMessage::NonceExportResponse { .. }
        | IpcMessage::NonceVerifyResponse { .. }
        | IpcMessage::VerifyFileResponse { .. }
        | IpcMessage::ExportFileResponse { .. }
        | IpcMessage::ForensicsResponse { .. }
        | IpcMessage::ProcessScoreResponse { .. }
        | IpcMessage::CheckpointResponse { .. } => IpcRole::ReadOnly,

        // User: witnessing lifecycle, checkpoints, export, pulse, alerts
        IpcMessage::StartWitnessing { .. }
        | IpcMessage::StopWitnessing { .. }
        | IpcMessage::ExportWithNonce { .. }
        | IpcMessage::ExportFile { .. }
        | IpcMessage::Pulse(_)
        | IpcMessage::CheckpointCreated { .. }
        | IpcMessage::CreateFileCheckpoint { .. }
        | IpcMessage::SystemAlert { .. }
        | IpcMessage::BrowserKeystroke { .. }
        | IpcMessage::BrowserKeystrokeBatch { .. } => IpcRole::User,
    }
}

/// Check whether `client_role` is sufficient for the `required` role level.
pub fn check_authorization(client_role: IpcRole, required: IpcRole) -> bool {
    client_role >= required
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_readonly_messages_require_readonly() {
        let msgs = vec![
            IpcMessage::GetStatus,
            IpcMessage::Heartbeat,
            IpcMessage::GetAttestationNonce,
            IpcMessage::VerifyFile {
                path: PathBuf::from("/tmp/test"),
            },
            IpcMessage::GetFileForensics {
                path: PathBuf::from("/tmp/test"),
            },
            IpcMessage::ComputeProcessScore {
                path: PathBuf::from("/tmp/test"),
            },
        ];
        for msg in &msgs {
            assert_eq!(
                required_role(msg),
                IpcRole::ReadOnly,
                "Expected ReadOnly for {:?}",
                msg
            );
        }
    }

    #[test]
    fn test_user_messages_require_user() {
        let msgs = vec![
            IpcMessage::StartWitnessing {
                file_path: PathBuf::from("/tmp/test"),
            },
            IpcMessage::StopWitnessing { file_path: None },
            IpcMessage::ExportFile {
                path: PathBuf::from("/tmp/test"),
                tier: "gold".to_string(),
                output: PathBuf::from("/tmp/out"),
            },
            IpcMessage::CreateFileCheckpoint {
                path: PathBuf::from("/tmp/test"),
                message: "test".to_string(),
            },
        ];
        for msg in &msgs {
            assert_eq!(
                required_role(msg),
                IpcRole::User,
                "Expected User for {:?}",
                msg
            );
        }
    }

    #[test]
    fn test_check_authorization_hierarchy() {
        // ReadOnly can access ReadOnly
        assert!(check_authorization(IpcRole::ReadOnly, IpcRole::ReadOnly));
        // ReadOnly cannot access User
        assert!(!check_authorization(IpcRole::ReadOnly, IpcRole::User));
        // ReadOnly cannot access Admin
        assert!(!check_authorization(IpcRole::ReadOnly, IpcRole::Admin));

        // User can access ReadOnly and User
        assert!(check_authorization(IpcRole::User, IpcRole::ReadOnly));
        assert!(check_authorization(IpcRole::User, IpcRole::User));
        // User cannot access Admin
        assert!(!check_authorization(IpcRole::User, IpcRole::Admin));

        // Admin can access everything
        assert!(check_authorization(IpcRole::Admin, IpcRole::ReadOnly));
        assert!(check_authorization(IpcRole::Admin, IpcRole::User));
        assert!(check_authorization(IpcRole::Admin, IpcRole::Admin));
    }

    #[test]
    fn test_default_role_is_readonly() {
        assert_eq!(IpcRole::default(), IpcRole::ReadOnly);
    }

    #[test]
    fn test_response_messages_are_readonly() {
        let msgs = vec![
            IpcMessage::Ok {
                message: Some("ok".to_string()),
            },
            IpcMessage::Error {
                code: crate::ipc::IpcErrorCode::Unknown,
                message: "err".to_string(),
            },
            IpcMessage::StatusResponse {
                running: true,
                tracked_files: vec![],
                uptime_secs: 0,
            },
            IpcMessage::HeartbeatAck { timestamp_ns: 0 },
        ];
        for msg in &msgs {
            assert_eq!(
                required_role(msg),
                IpcRole::ReadOnly,
                "Expected ReadOnly for response {:?}",
                msg
            );
        }
    }

    #[test]
    fn test_status_message_requires_readonly() {
        assert_eq!(required_role(&IpcMessage::GetStatus), IpcRole::ReadOnly);
        // ReadOnly role should be sufficient.
        assert!(check_authorization(IpcRole::ReadOnly, IpcRole::ReadOnly));
    }

    #[test]
    fn test_start_witnessing_requires_user() {
        let msg = IpcMessage::StartWitnessing {
            file_path: PathBuf::from("/tmp/doc.txt"),
        };
        assert_eq!(required_role(&msg), IpcRole::User);
    }

    #[test]
    fn test_admin_can_access_user_operations() {
        // Admin should be able to perform User-level operations.
        assert!(check_authorization(IpcRole::Admin, IpcRole::User));
        assert!(check_authorization(IpcRole::Admin, IpcRole::ReadOnly));

        // Verify with actual messages.
        let user_msg = IpcMessage::StartWitnessing {
            file_path: PathBuf::from("/tmp/test"),
        };
        let required = required_role(&user_msg);
        assert!(check_authorization(IpcRole::Admin, required));
    }

    #[test]
    fn test_readonly_cannot_access_user() {
        assert!(!check_authorization(IpcRole::ReadOnly, IpcRole::User));

        // ReadOnly client should be denied StartWitnessing.
        let msg = IpcMessage::StartWitnessing {
            file_path: PathBuf::from("/tmp/test"),
        };
        let required = required_role(&msg);
        assert!(!check_authorization(IpcRole::ReadOnly, required));
    }

    #[test]
    fn test_handshake_is_readonly() {
        let msg = IpcMessage::Handshake {
            version: "1.0".to_string(),
        };
        assert_eq!(required_role(&msg), IpcRole::ReadOnly);
    }

    #[test]
    fn test_pulse_requires_user() {
        let sample = crate::jitter::SimpleJitterSample {
            timestamp_ns: 1_000_000,
            duration_since_last_ns: 50_000,
            zone: 2,
            ..Default::default()
        };
        let msg = IpcMessage::Pulse(sample);
        assert_eq!(required_role(&msg), IpcRole::User);
    }

    #[test]
    fn test_system_alert_requires_user() {
        let msg = IpcMessage::SystemAlert {
            level: "warning".to_string(),
            message: "test alert".to_string(),
        };
        assert_eq!(required_role(&msg), IpcRole::User);
    }

    #[test]
    fn test_role_ordering() {
        assert!(IpcRole::ReadOnly < IpcRole::User);
        assert!(IpcRole::User < IpcRole::Admin);
        assert!(IpcRole::ReadOnly < IpcRole::Admin);
    }
}

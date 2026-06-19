// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Transport-agnostic WritersProof API trait.
//!
//! Abstracts over REST and gRPC transports so callers (sentinel, FFI, queue)
//! can swap implementations at runtime via `Arc<dyn WritersProofApi>`.

use super::types::{
    AnchorRequest, AnchorResponse, BeaconResponse, ChallengeResponse, CredentialIssueRequest,
    CredentialIssueResponse, CredentialStatusResponse, EnrollRequest, EnrollResponse, Hex64,
    PublishRequest, PublishResponse, PulseResponse, TextAttestationRequest, TextAttestationResponse,
};
use crate::error::Result;

#[async_trait::async_trait]
pub trait WritersProofApi: Send + Sync {
    async fn enroll(&self, req: EnrollRequest) -> Result<EnrollResponse>;
    async fn get_certificate(&self, id: &str) -> Result<Vec<u8>>;
    async fn get_crl(&self) -> Result<Vec<u8>>;
    async fn anchor(&self, req: AnchorRequest) -> Result<AnchorResponse>;
    async fn submit_text_attestation(
        &self,
        req: TextAttestationRequest,
    ) -> Result<TextAttestationResponse>;
    async fn publish(&self, req: PublishRequest) -> Result<PublishResponse>;
    async fn fetch_beacon(
        &self,
        checkpoint_hash: &str,
        timeout_secs: u64,
    ) -> Result<BeaconResponse>;
    async fn start_session(&self, session_id: &Hex64, initial_hash: &Hex64) -> Result<()>;
    async fn update_session_hash(&self, session_id: &Hex64, current_hash: &Hex64) -> Result<()>;
    async fn end_session(&self, session_id: &Hex64, final_hash: &Hex64) -> Result<()>;
    async fn request_challenge(&self, session_id: &Hex64) -> Result<ChallengeResponse>;
    async fn pulse(&self, session_id: &Hex64, current_hash: &Hex64) -> Result<PulseResponse>;
    async fn confirm_nonce(
        &self,
        session_id: &Hex64,
        nonce_id: &str,
        checkpoint_hash: &Hex64,
    ) -> Result<()>;
    async fn issue_credential(
        &self,
        req: CredentialIssueRequest,
    ) -> Result<CredentialIssueResponse>;
    async fn get_credential_status(&self, id: &str) -> Result<CredentialStatusResponse>;
    async fn revoke_credential(&self, credential_id: &str) -> Result<()>;
    async fn is_online(&self) -> bool;
}

#[async_trait::async_trait]
impl WritersProofApi for super::WritersProofClient {
    async fn enroll(&self, req: EnrollRequest) -> Result<EnrollResponse> {
        self.enroll(req).await
    }
    async fn get_certificate(&self, id: &str) -> Result<Vec<u8>> {
        self.get_certificate(id).await
    }
    async fn get_crl(&self) -> Result<Vec<u8>> {
        self.get_crl().await
    }
    async fn anchor(&self, req: AnchorRequest) -> Result<AnchorResponse> {
        self.anchor(req).await
    }
    async fn submit_text_attestation(
        &self,
        req: TextAttestationRequest,
    ) -> Result<TextAttestationResponse> {
        self.submit_text_attestation(req).await
    }
    async fn publish(&self, req: PublishRequest) -> Result<PublishResponse> {
        self.publish(req).await
    }
    async fn fetch_beacon(
        &self,
        checkpoint_hash: &str,
        timeout_secs: u64,
    ) -> Result<BeaconResponse> {
        self.fetch_beacon(checkpoint_hash, timeout_secs).await
    }
    async fn start_session(&self, session_id: &Hex64, initial_hash: &Hex64) -> Result<()> {
        self.start_session(session_id, initial_hash).await
    }
    async fn update_session_hash(&self, session_id: &Hex64, current_hash: &Hex64) -> Result<()> {
        self.update_session_hash(session_id, current_hash).await
    }
    async fn end_session(&self, session_id: &Hex64, final_hash: &Hex64) -> Result<()> {
        self.end_session(session_id, final_hash).await
    }
    async fn request_challenge(&self, session_id: &Hex64) -> Result<ChallengeResponse> {
        self.request_challenge(session_id).await
    }
    async fn pulse(&self, session_id: &Hex64, current_hash: &Hex64) -> Result<PulseResponse> {
        self.pulse(session_id, current_hash).await
    }
    async fn confirm_nonce(
        &self,
        session_id: &Hex64,
        nonce_id: &str,
        checkpoint_hash: &Hex64,
    ) -> Result<()> {
        self.confirm_nonce(session_id, nonce_id, checkpoint_hash)
            .await
    }
    async fn issue_credential(
        &self,
        req: CredentialIssueRequest,
    ) -> Result<CredentialIssueResponse> {
        self.issue_credential(req).await
    }
    async fn get_credential_status(&self, id: &str) -> Result<CredentialStatusResponse> {
        self.get_credential_status(id).await
    }
    async fn revoke_credential(&self, credential_id: &str) -> Result<()> {
        self.revoke_credential(credential_id).await
    }
    async fn is_online(&self) -> bool {
        self.is_online().await
    }
}

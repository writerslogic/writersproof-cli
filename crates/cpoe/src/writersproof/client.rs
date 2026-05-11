// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! HTTP client for the WritersProof attestation API.

use ed25519_dalek::{Signer, SigningKey};
use reqwest::Client;
use zeroize::Zeroizing;

use super::types::{
    AnchorRequest, AnchorResponse, AttestResponse, BeaconRequest, BeaconResponse,
    ChallengeResponse, ConfirmNonceRequest, CredentialIssueRequest, CredentialIssueResponse,
    CredentialStatusResponse, EnrollRequest, EnrollResponse, Hex64, NonceResponse, PulseRequest,
    PulseResponse, VerifyResponse,
};
use crate::error::{Error, Result};

/// Default WritersProof API base URL.
pub const DEFAULT_API_URL: &str = "https://api.writersproof.com";

#[derive(Debug)]
/// WritersProof API client.
pub struct WritersProofClient {
    base_url: String,
    jwt: Option<Zeroizing<String>>,
    client: Client,
}

impl WritersProofClient {
    /// Create a client targeting the given API base URL.
    ///
    /// `base_url` must use HTTPS to protect JWT tokens and evidence data
    /// in transit. Non-HTTPS URLs are unconditionally rejected.
    pub fn new(base_url: &str) -> Result<Self> {
        let url = base_url.trim_end_matches('/').to_string();
        if !url.starts_with("https://") {
            return Err(Error::crypto(format!(
                "WritersProof base_url must use HTTPS: {}",
                &url[..(0..=url.len().min(40)).rev().find(|&i| url.is_char_boundary(i)).unwrap_or(0)]
            )));
        }
        Ok(Self {
            base_url: url,
            jwt: None,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| Error::crypto(format!("HTTP client build failed: {e}")))?,
        })
    }

    /// Set the JWT token for authenticated requests.
    pub fn with_jwt(mut self, token: Zeroizing<String>) -> Self {
        self.jwt = Some(token);
        self
    }

    /// Request a fresh nonce from the verifier.
    ///
    /// `POST /v1/nonce`
    pub async fn request_nonce(&self, hardware_key_id: &str) -> Result<NonceResponse> {
        let url = format!("{}/v1/nonce", self.base_url);
        let body = serde_json::json!({ "hardwareKeyId": hardware_key_id });
        let mut req = self.client.post(&url).json(&body);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("nonce request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "nonce request failed: HTTP {}",
                resp.status()
            )));
        }

        Self::json_response::<NonceResponse>(resp).await
    }

    /// Enroll a device with WritersProof.
    ///
    /// `POST /v1/enroll`
    pub async fn enroll(&self, req: EnrollRequest) -> Result<EnrollResponse> {
        let url = format!("{}/v1/enroll", self.base_url);
        let mut http_req = self.client.post(&url).json(&req);
        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt.as_str());
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("enroll request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "enroll request failed: HTTP {}",
                resp.status()
            )));
        }

        Self::json_response::<EnrollResponse>(resp).await
    }

    /// Submit evidence for attestation.
    ///
    /// `POST /v1/attest`
    ///
    /// The evidence CBOR is sent as the request body. Nonce, hardware key ID,
    /// and signature are sent as custom headers.
    pub async fn attest(
        &self,
        evidence_cbor: &[u8],
        nonce: &[u8; 32],
        hardware_key_id: &str,
        signing_key: &SigningKey,
    ) -> Result<AttestResponse> {
        let hkid_bytes = hardware_key_id.as_bytes();
        let mut sign_payload = zeroize::Zeroizing::new(Vec::with_capacity(
            4 + nonce.len() + 4 + hkid_bytes.len() + 4 + evidence_cbor.len(),
        ));
        sign_payload.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
        sign_payload.extend_from_slice(nonce);
        sign_payload.extend_from_slice(&(hkid_bytes.len() as u32).to_be_bytes());
        sign_payload.extend_from_slice(hkid_bytes);
        sign_payload.extend_from_slice(&(evidence_cbor.len() as u32).to_be_bytes());
        sign_payload.extend_from_slice(evidence_cbor);
        let signature = signing_key.sign(&sign_payload);
        let url = format!("{}/v1/attest", self.base_url);

        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/cbor")
            .header("X-CPoE-Nonce", hex::encode(nonce))
            .header("X-CPoE-Hardware-Key-Id", hardware_key_id)
            .header(
                "X-CPoE-Signature",
                crate::utils::crypto_types::Ed25519Sig::from(signature).to_hex(),
            )
            .body(evidence_cbor.to_vec());

        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("attest request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "attest request failed: HTTP {}",
                resp.status()
            )));
        }

        Self::json_response::<AttestResponse>(resp).await
    }

    /// Get an attestation certificate by ID.
    ///
    /// `GET /v1/certificates/:id`
    pub async fn get_certificate(&self, id: &str) -> Result<Vec<u8>> {
        // Validate certificate ID to prevent path traversal (e.g., "../../admin/keys")
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Error::crypto(format!(
                "invalid certificate ID: must be alphanumeric/dash/underscore, got: {}",
                &id[..(0..=id.len().min(32)).rev().find(|&i| id.is_char_boundary(i)).unwrap_or(0)]
            )));
        }
        let url = format!("{}/v1/certificates/{}", self.base_url, id);
        let mut req = self.client.get(&url);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("certificate request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "certificate request failed: HTTP {}",
                resp.status()
            )));
        }

        const MAX_CERT_SIZE: u64 = 10_000_000; // 10 MB
        if let Some(cl) = resp.content_length() {
            if cl > MAX_CERT_SIZE {
                return Err(Error::crypto(format!(
                    "certificate Content-Length too large: {cl} bytes (max {MAX_CERT_SIZE})"
                )));
            }
        }
        let mut body: Vec<u8> = Vec::new();
        let mut resp = resp;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| Error::crypto(format!("certificate response read failed: {e}")))?
        {
            if body.len() as u64 + chunk.len() as u64 > MAX_CERT_SIZE {
                return Err(Error::crypto(format!(
                    "certificate response too large (max {MAX_CERT_SIZE} bytes)"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Get the certificate revocation list.
    ///
    /// `GET /v1/crl`
    pub async fn get_crl(&self) -> Result<Vec<u8>> {
        let url = format!("{}/v1/crl", self.base_url);
        let mut req = self.client.get(&url);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("CRL request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "CRL request failed: HTTP {}",
                resp.status()
            )));
        }

        const MAX_CRL_SIZE: u64 = 50_000_000; // 50 MB
        if let Some(cl) = resp.content_length() {
            if cl > MAX_CRL_SIZE {
                return Err(Error::crypto(format!(
                    "CRL Content-Length too large: {cl} bytes (max {MAX_CRL_SIZE})"
                )));
            }
        }
        let mut body: Vec<u8> = Vec::new();
        let mut resp = resp;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| Error::crypto(format!("CRL response read failed: {e}")))?
        {
            if body.len() as u64 + chunk.len() as u64 > MAX_CRL_SIZE {
                return Err(Error::crypto(format!(
                    "CRL response too large (max {MAX_CRL_SIZE} bytes)"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Anchor an evidence packet hash in the transparency log.
    ///
    /// `POST /v1/anchor`
    pub async fn anchor(&self, req: AnchorRequest) -> Result<AnchorResponse> {
        let url = format!("{}/v1/anchor", self.base_url);
        let mut http_req = self.client.post(&url).json(&req);
        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt.as_str());
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("anchor request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "anchor request failed: HTTP {}",
                resp.status()
            )));
        }

        Self::json_response::<AnchorResponse>(resp).await
    }

    /// Submit a text attestation to WritersProof for public verification.
    ///
    /// `POST /v1/text-attestation`
    pub async fn submit_text_attestation(
        &self,
        req: super::types::TextAttestationRequest,
    ) -> Result<super::types::TextAttestationResponse> {
        if req.content_hash.len() != 64 || !req.content_hash.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(Error::crypto("content_hash must be 64 hex characters"));
        }
        if req.signature_hex.len() != 128 {
            return Err(Error::crypto("signature_hex must be 128 hex characters"));
        }
        if req.public_key_hex.len() != 64 {
            return Err(Error::crypto("public_key_hex must be 64 hex characters"));
        }

        let url = format!("{}/v1/text-attestation", self.base_url);
        let mut http_req = self.client.post(&url).json(&req);
        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt.as_str());
        } else {
            return Err(Error::crypto(
                "text attestation submission requires authentication",
            ));
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("text-attestation request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "text-attestation request failed: HTTP {}",
                resp.status()
            )));
        }

        Self::json_response::<super::types::TextAttestationResponse>(resp).await
    }

    /// Publish evidence to WritersProof and receive a canonical URL.
    ///
    /// `POST /v1/publish`
    pub async fn publish(
        &self,
        req: super::types::PublishRequest,
    ) -> Result<super::types::PublishResponse> {
        let url = format!("{}/v1/publish", self.base_url);
        let mut http_req = self.client.post(&url).json(&req);
        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt.as_str());
        } else {
            return Err(Error::crypto("publish requires authentication".to_string()));
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("publish request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|e| format!("[unreadable: {e}]"));
            return Err(Error::crypto(format!(
                "publish failed: HTTP {status}: {body}"
            )));
        }

        Self::json_response::<super::types::PublishResponse>(resp).await
    }

    /// Fetch temporal beacon attestation from WritersProof.
    ///
    /// WritersProof fetches the latest drand round and NIST pulse server-side,
    /// then counter-signs the bundle. The returned `wp_signature` is included
    /// in the H2 seal computation, cryptographically binding the beacon values
    /// to the evidence packet.
    ///
    /// `POST /v1/beacon`
    pub async fn fetch_beacon(
        &self,
        checkpoint_hash: &str,
        timeout_secs: u64,
    ) -> Result<BeaconResponse> {
        let url = format!("{}/v1/beacon", self.base_url);
        let req = BeaconRequest {
            checkpoint_hash: checkpoint_hash.to_string(),
        };

        let effective_timeout = timeout_secs.max(1); // Enforce minimum 1s timeout
        let mut http_req = self
            .client
            .post(&url)
            .json(&req)
            .timeout(std::time::Duration::from_secs(effective_timeout));

        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt.as_str());
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("beacon request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "beacon request failed: HTTP {}",
                resp.status()
            )));
        }

        Self::json_response::<BeaconResponse>(resp).await
    }

    /// Start a tracking session on the server with an initial hash.
    pub async fn start_session(&self, session_id: &Hex64, initial_hash: &Hex64) -> Result<()> {
        let url = format!("{}/v1/sessions/{}", self.base_url, session_id);
        let req = serde_json::json!({
            "action": "start",
            "initial_hash": initial_hash.as_str()
        });
        self.send_session_update(&url, &req).await
    }

    /// Update the server with the current document hash for real-time comparison.
    pub async fn update_session_hash(
        &self,
        session_id: &Hex64,
        current_hash: &Hex64,
    ) -> Result<()> {
        let url = format!("{}/v1/sessions/{}", self.base_url, session_id);
        let req = serde_json::json!({
            "action": "update",
            "current_hash": current_hash.as_str()
        });
        self.send_session_update(&url, &req).await
    }

    /// Signal the end of tracking and request the server to wipe the session hashes.
    pub async fn end_session(&self, session_id: &Hex64, final_hash: &Hex64) -> Result<()> {
        let url = format!("{}/v1/sessions/{}", self.base_url, session_id);
        let req = serde_json::json!({
            "action": "end",
            "final_hash": final_hash.as_str()
        });
        self.send_session_update(&url, &req).await
    }

    async fn send_session_update(&self, url: &str, body: &serde_json::Value) -> Result<()> {
        let mut req = self.client.post(url).json(body);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("session update failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "session update failed: HTTP {}",
                resp.status()
            )));
        }
        Ok(())
    }

    /// Request a timeline challenge nonce for a session.
    ///
    /// `POST /v1/sessions/:id/challenge`
    ///
    /// Returns a 30-second TTL nonce that must be bound into the next
    /// checkpoint hash to prove the checkpoint was built in real time.
    pub async fn request_challenge(&self, session_id: &Hex64) -> Result<ChallengeResponse> {
        let url = format!("{}/v1/sessions/{}/challenge", self.base_url, session_id);
        let mut req = self.client.post(&url);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("challenge request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "challenge request failed: HTTP {}",
                resp.status()
            )));
        }

        Self::json_response::<ChallengeResponse>(resp).await
    }

    /// Send a pulse: atomically log current hash and fetch fresh 30-second nonce.
    ///
    /// Combines `update_session_hash` + `request_challenge` into a single atomic call.
    /// The server logs both the hash and issued nonce to the heartbeat log for
    /// later correlation.
    ///
    /// `POST /v1/sessions/:id/pulse`
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session ID (64-char hex string)
    /// * `current_hash` - Current document hash (64-char hex SHA-256)
    ///
    /// # Returns
    ///
    /// A `PulseResponse` containing the fresh nonce, its ID, and TTL.
    pub async fn pulse(&self, session_id: &Hex64, current_hash: &Hex64) -> Result<PulseResponse> {
        let url = format!("{}/v1/sessions/{}/pulse", self.base_url, session_id);
        let body = PulseRequest {
            current_hash: current_hash.as_str().to_owned(),
        };
        let mut req = self.client.post(&url).json(&body);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("pulse request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "pulse request failed: HTTP {}",
                resp.status()
            )));
        }

        Self::json_response::<PulseResponse>(resp).await
    }

    /// Verify an evidence packet.
    ///
    /// `POST /v1/verify`
    pub async fn verify(&self, evidence_cbor: &[u8]) -> Result<VerifyResponse> {
        let url = format!("{}/v1/verify", self.base_url);
        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/vnd.writersproof.cpoe+cbor")
            .body(evidence_cbor.to_vec());

        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("verify request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "verify request failed: HTTP {}",
                resp.status()
            )));
        }

        let mut response = Self::json_response::<VerifyResponse>(resp).await?;
        response.sanitize();
        Ok(response)
    }

    /// Close the nonce handshake loop after a checkpoint commit.
    ///
    /// `POST /v1/sessions/:id/confirm`
    ///
    /// Sends the checkpoint hash back to the server so it can record that
    /// `nonce_id` was consumed by `checkpoint_hash`, enabling verifiers to
    /// confirm the checkpoint was built within the nonce's 30-second window.
    /// Failures are non-fatal — the checkpoint is already committed locally.
    pub async fn confirm_nonce(
        &self,
        session_id: &Hex64,
        nonce_id: &str,
        checkpoint_hash: &Hex64,
    ) -> Result<()> {
        let url = format!("{}/v1/sessions/{}/confirm", self.base_url, session_id);
        let body = ConfirmNonceRequest {
            nonce_id: nonce_id.to_string(),
            checkpoint_hash: checkpoint_hash.as_str().to_owned(),
        };
        let mut req = self.client.post(&url).json(&body);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("confirm_nonce request failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "confirm_nonce failed: HTTP {}",
                resp.status()
            )));
        }
        Ok(())
    }

    /// Deserialize a JSON response with a hard body-size cap.
    ///
    /// Checks `Content-Length` before downloading and verifies the actual body
    /// size after download. Rejects responses larger than 1 MB to prevent
    /// memory exhaustion from malicious or misconfigured servers.
    async fn json_response<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
        const MAX_JSON_BYTES: u64 = 1_000_000; // 1 MB
        if let Some(cl) = resp.content_length() {
            if cl > MAX_JSON_BYTES {
                return Err(Error::crypto(format!(
                    "response too large: {cl} bytes (max {MAX_JSON_BYTES})"
                )));
            }
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Error::crypto(format!("response read failed: {e}")))?;
        if bytes.len() as u64 > MAX_JSON_BYTES {
            return Err(Error::crypto(format!(
                "response too large: {} bytes (max {MAX_JSON_BYTES})",
                bytes.len()
            )));
        }
        serde_json::from_slice(&bytes)
            .map_err(|e| Error::crypto(format!("response parse failed: {e}")))
    }

    /// Issue an authorship credential via WritersProof.
    ///
    /// `POST /v1/credentials/issue`
    #[allow(dead_code)]
    pub async fn issue_credential(
        &self,
        req: CredentialIssueRequest,
    ) -> Result<CredentialIssueResponse> {
        let url = format!("{}/v1/credentials/issue", self.base_url);
        let mut http_req = self.client.post(&url).json(&req);
        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt.as_str());
        } else {
            return Err(Error::crypto("credential issuance requires authentication"));
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("credential issue request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|e| format!("[unreadable: {e}]"));
            return Err(Error::crypto(format!(
                "credential issue failed: HTTP {status}: {body}"
            )));
        }

        Self::json_response::<CredentialIssueResponse>(resp).await
    }

    /// Get the status of an issued credential.
    ///
    /// `GET /v1/credentials/:id/status`
    #[allow(dead_code)]
    pub async fn get_credential_status(
        &self,
        credential_id: &str,
    ) -> Result<CredentialStatusResponse> {
        if !credential_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Error::crypto(format!(
                "invalid credential ID: must be alphanumeric/dash/underscore, got: {}",
                &credential_id[..(0..=credential_id.len().min(32)).rev().find(|&i| credential_id.is_char_boundary(i)).unwrap_or(0)]
            )));
        }

        let url = format!("{}/v1/credentials/{}/status", self.base_url, credential_id);
        let mut req = self.client.get(&url);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("credential status request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "credential status request failed: HTTP {}",
                resp.status()
            )));
        }

        Self::json_response::<CredentialStatusResponse>(resp).await
    }

    /// Revoke an issued credential.
    ///
    /// `POST /v1/credentials/:id/revoke`
    #[allow(dead_code)]
    pub async fn revoke_credential(&self, credential_id: &str) -> Result<()> {
        if !credential_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Error::crypto(format!(
                "invalid credential ID: must be alphanumeric/dash/underscore, got: {}",
                &credential_id[..(0..=credential_id.len().min(32)).rev().find(|&i| credential_id.is_char_boundary(i)).unwrap_or(0)]
            )));
        }

        let url = format!("{}/v1/credentials/{}/revoke", self.base_url, credential_id);
        let mut req = self.client.post(&url);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        } else {
            return Err(Error::crypto(
                "credential revocation requires authentication",
            ));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::crypto(format!("credential revoke request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::crypto(format!(
                "credential revoke failed: HTTP {}",
                resp.status()
            )));
        }

        Ok(())
    }

    /// Check if the WritersProof service is reachable.
    ///
    /// `GET /health`
    pub async fn is_online(&self) -> bool {
        let url = format!("{}/health", self.base_url);
        match self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(r) => r.status().is_success(),
            Err(e) => {
                log::debug!("Health check failed: {e}");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_construction() {
        let client = WritersProofClient::new("https://api.writersproof.com").unwrap();
        assert_eq!(client.base_url, "https://api.writersproof.com");
        assert!(client.jwt.is_none());
    }

    #[test]
    fn test_client_with_jwt() {
        let client = WritersProofClient::new("https://api.writersproof.com")
            .unwrap()
            .with_jwt(zeroize::Zeroizing::new("test-token".to_string()));
        assert!(client
            .jwt
            .as_ref()
            .is_some_and(|j| j.as_str() == "test-token"));
    }

    #[test]
    fn test_trailing_slash_stripped() {
        let client = WritersProofClient::new("https://api.writersproof.com/").unwrap();
        assert_eq!(client.base_url, "https://api.writersproof.com");
    }
}

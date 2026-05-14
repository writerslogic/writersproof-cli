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
        log::debug!("request_nonce: hardware_key_id={hardware_key_id}");
        let url = format!("{}/v1/nonce", self.base_url);
        let body = serde_json::json!({ "hardwareKeyId": hardware_key_id });
        let mut req = self.client.post(&url).json(&body);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| {
                log::warn!("request_nonce: failed: {e}");
                Error::crypto(format!("nonce request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("request_nonce: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "nonce request failed: HTTP {}",
                status
            )));
        }

        let result = Self::json_response::<NonceResponse>(resp).await?;
        log::debug!("request_nonce: success");
        Ok(result)
    }

    /// Enroll a device with WritersProof.
    ///
    /// `POST /v1/enroll`
    pub async fn enroll(&self, req: EnrollRequest) -> Result<EnrollResponse> {
        log::debug!("enroll: starting enrollment");
        let url = format!("{}/v1/enroll", self.base_url);
        let mut http_req = self.client.post(&url).json(&req);
        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt.as_str());
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| {
                log::warn!("enroll: failed: {e}");
                Error::crypto(format!("enroll request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("enroll: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "enroll request failed: HTTP {}",
                status
            )));
        }

        let result = Self::json_response::<EnrollResponse>(resp).await?;
        log::debug!("enroll: success");
        Ok(result)
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
        log::debug!(
            "attest: session evidence_len={}, hardware_key_id={hardware_key_id}",
            evidence_cbor.len()
        );
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
            .map_err(|e| {
                log::warn!("attest: failed: {e}");
                Error::crypto(format!("attest request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("attest: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "attest request failed: HTTP {}",
                status
            )));
        }

        let result = Self::json_response::<AttestResponse>(resp).await?;
        log::debug!("attest: success");
        Ok(result)
    }

    /// Get an attestation certificate by ID.
    ///
    /// `GET /v1/certificates/:id`
    pub async fn get_certificate(&self, id: &str) -> Result<Vec<u8>> {
        log::debug!("get_certificate: id={id}");
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
            .map_err(|e| {
                log::warn!("get_certificate: failed: {e}");
                Error::crypto(format!("certificate request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("get_certificate: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "certificate request failed: HTTP {}",
                status
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
        log::debug!("get_certificate: success, {} bytes", body.len());
        Ok(body)
    }

    /// Get the certificate revocation list.
    ///
    /// `GET /v1/crl`
    pub async fn get_crl(&self) -> Result<Vec<u8>> {
        log::debug!("get_crl: requesting revocation list");
        let url = format!("{}/v1/crl", self.base_url);
        let mut req = self.client.get(&url);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| {
                log::warn!("get_crl: failed: {e}");
                Error::crypto(format!("CRL request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("get_crl: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "CRL request failed: HTTP {}",
                status
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
        log::debug!("get_crl: success, {} bytes", body.len());
        Ok(body)
    }

    /// Anchor an evidence packet hash in the transparency log.
    ///
    /// `POST /v1/anchor`
    pub async fn anchor(&self, req: AnchorRequest) -> Result<AnchorResponse> {
        log::debug!("anchor: submitting anchor request");
        let url = format!("{}/v1/anchor", self.base_url);
        let mut http_req = self.client.post(&url).json(&req);
        if let Some(ref jwt) = self.jwt {
            http_req = http_req.bearer_auth(jwt.as_str());
        }

        let resp = http_req
            .send()
            .await
            .map_err(|e| {
                log::warn!("anchor: failed: {e}");
                Error::crypto(format!("anchor request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("anchor: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "anchor request failed: HTTP {}",
                status
            )));
        }

        let result = Self::json_response::<AnchorResponse>(resp).await?;
        log::debug!("anchor: success");
        Ok(result)
    }

    /// Submit a text attestation to WritersProof for public verification.
    ///
    /// `POST /v1/text-attestation`
    pub async fn submit_text_attestation(
        &self,
        req: super::types::TextAttestationRequest,
    ) -> Result<super::types::TextAttestationResponse> {
        log::debug!("submit_text_attestation: content_hash={}", req.content_hash);
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
            .map_err(|e| {
                log::warn!("submit_text_attestation: failed: {e}");
                Error::crypto(format!("text-attestation request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("submit_text_attestation: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "text-attestation request failed: HTTP {}",
                status
            )));
        }

        let result = Self::json_response::<super::types::TextAttestationResponse>(resp).await?;
        log::debug!("submit_text_attestation: success");
        Ok(result)
    }

    /// Publish evidence to WritersProof and receive a canonical URL.
    ///
    /// `POST /v1/publish`
    pub async fn publish(
        &self,
        req: super::types::PublishRequest,
    ) -> Result<super::types::PublishResponse> {
        log::debug!("publish: submitting publish request");
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
            .map_err(|e| {
                log::warn!("publish: failed: {e}");
                Error::crypto(format!("publish request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|e| format!("[unreadable: {e}]"));
            let truncated = &body[..(0..=body.len().min(200)).rev().find(|&i| body.is_char_boundary(i)).unwrap_or(0)];
            log::warn!("publish: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "publish failed: HTTP {status}: {truncated}"
            )));
        }

        let result = Self::json_response::<super::types::PublishResponse>(resp).await?;
        log::debug!("publish: success");
        Ok(result)
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
        log::debug!("fetch_beacon: timeout_secs={timeout_secs}");
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
            .map_err(|e| {
                log::warn!("fetch_beacon: failed: {e}");
                Error::crypto(format!("beacon request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("fetch_beacon: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "beacon request failed: HTTP {}",
                status
            )));
        }

        let result = Self::json_response::<BeaconResponse>(resp).await?;
        log::debug!("fetch_beacon: success");
        Ok(result)
    }

    /// Start a tracking session on the server with an initial hash.
    pub async fn start_session(&self, session_id: &Hex64, initial_hash: &Hex64) -> Result<()> {
        log::debug!("start_session: session_id={session_id}");
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
        log::debug!("update_session_hash: session_id={session_id}");
        let url = format!("{}/v1/sessions/{}", self.base_url, session_id);
        let req = serde_json::json!({
            "action": "update",
            "current_hash": current_hash.as_str()
        });
        self.send_session_update(&url, &req).await
    }

    /// Signal the end of tracking and request the server to wipe the session hashes.
    pub async fn end_session(&self, session_id: &Hex64, final_hash: &Hex64) -> Result<()> {
        log::debug!("end_session: session_id={session_id}");
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
            .map_err(|e| {
                log::warn!("send_session_update: failed: {e}");
                Error::crypto(format!("session update failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("send_session_update: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "session update failed: HTTP {}",
                status
            )));
        }
        log::debug!("send_session_update: success");
        Ok(())
    }

    /// Request a timeline challenge nonce for a session.
    ///
    /// `POST /v1/sessions/:id/challenge`
    ///
    /// Returns a 30-second TTL nonce that must be bound into the next
    /// checkpoint hash to prove the checkpoint was built in real time.
    pub async fn request_challenge(&self, session_id: &Hex64) -> Result<ChallengeResponse> {
        log::debug!("request_challenge: session_id={session_id}");
        let url = format!("{}/v1/sessions/{}/challenge", self.base_url, session_id);
        let mut req = self.client.post(&url);
        if let Some(ref jwt) = self.jwt {
            req = req.bearer_auth(jwt.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| {
                log::warn!("request_challenge: failed: {e}");
                Error::crypto(format!("challenge request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("request_challenge: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "challenge request failed: HTTP {}",
                status
            )));
        }

        let result = Self::json_response::<ChallengeResponse>(resp).await?;
        log::debug!("request_challenge: success");
        Ok(result)
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
        log::debug!("pulse: session_id={session_id}");
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
            .map_err(|e| {
                log::warn!("pulse: failed: {e}");
                Error::crypto(format!("pulse request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("pulse: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "pulse request failed: HTTP {}",
                status
            )));
        }

        let result = Self::json_response::<PulseResponse>(resp).await?;
        log::debug!("pulse: success");
        Ok(result)
    }

    /// Verify an evidence packet.
    ///
    /// `POST /v1/verify`
    pub async fn verify(&self, evidence_cbor: &[u8]) -> Result<VerifyResponse> {
        log::debug!("verify: evidence_len={}", evidence_cbor.len());
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
            .map_err(|e| {
                log::warn!("verify: failed: {e}");
                Error::crypto(format!("verify request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("verify: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "verify request failed: HTTP {}",
                status
            )));
        }

        let mut response = Self::json_response::<VerifyResponse>(resp).await?;
        response.sanitize();
        log::debug!("verify: success");
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
        log::debug!("confirm_nonce: session_id={session_id}");
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
            .map_err(|e| {
                log::warn!("confirm_nonce: failed: {e}");
                Error::crypto(format!("confirm_nonce request failed: {e}"))
            })?;
        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("confirm_nonce: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "confirm_nonce failed: HTTP {}",
                status
            )));
        }
        log::debug!("confirm_nonce: success");
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
        if let Some(ct) = resp.headers().get(reqwest::header::CONTENT_TYPE) {
            if let Ok(ct_str) = ct.to_str() {
                if !ct_str.contains("json") {
                    log::warn!(
                        "json_response: unexpected Content-Type: {ct_str}; parsing as JSON anyway"
                    );
                }
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
        log::debug!("issue_credential: requesting credential issuance");
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
            .map_err(|e| {
                log::warn!("issue_credential: failed: {e}");
                Error::crypto(format!("credential issue request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|e| format!("[unreadable: {e}]"));
            let truncated = &body[..(0..=body.len().min(200)).rev().find(|&i| body.is_char_boundary(i)).unwrap_or(0)];
            log::warn!("issue_credential: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "credential issue failed: HTTP {status}: {truncated}"
            )));
        }

        let result = Self::json_response::<CredentialIssueResponse>(resp).await?;
        log::debug!("issue_credential: success");
        Ok(result)
    }

    /// Get the status of an issued credential.
    ///
    /// `GET /v1/credentials/:id/status`
    #[allow(dead_code)]
    pub async fn get_credential_status(
        &self,
        credential_id: &str,
    ) -> Result<CredentialStatusResponse> {
        log::debug!("get_credential_status: credential_id={credential_id}");
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
            .map_err(|e| {
                log::warn!("get_credential_status: failed: {e}");
                Error::crypto(format!("credential status request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("get_credential_status: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "credential status request failed: HTTP {}",
                status
            )));
        }

        let result = Self::json_response::<CredentialStatusResponse>(resp).await?;
        log::debug!("get_credential_status: success");
        Ok(result)
    }

    /// Revoke an issued credential.
    ///
    /// `POST /v1/credentials/:id/revoke`
    #[allow(dead_code)]
    pub async fn revoke_credential(&self, credential_id: &str) -> Result<()> {
        log::debug!("revoke_credential: credential_id={credential_id}");
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
            .map_err(|e| {
                log::warn!("revoke_credential: failed: {e}");
                Error::crypto(format!("credential revoke request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            log::warn!("revoke_credential: failed: HTTP {status}");
            return Err(Error::crypto(format!(
                "credential revoke failed: HTTP {}",
                status
            )));
        }

        log::debug!("revoke_credential: success");
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

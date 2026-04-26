// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::cpoe_jitter_bridge::doc_tracker::DocumentTracker;
use crate::cpoe_jitter_bridge::types::{
    EntropyQuality, HybridEvidence, HybridSample, HybridSessionData,
};
use crate::cpoe_jitter_bridge::zone_engine::ZoneTrackingEngine;
use crate::jitter::{Evidence, Parameters, Statistics};
use crate::DateTimeNanosExt;
use chrono::{DateTime, Utc};
use cpoe_jitter::{
    derive_session_secret, EvidenceChain as PhysEvidenceChain, Session as PhysSession,
};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

/// Verify hash chain integrity, timestamp monotonicity, and keystroke count monotonicity.
fn verify_sample_chain(samples: &[HybridSample]) -> Result<(), String> {
    use subtle::ConstantTimeEq;
    for (i, sample) in samples.iter().enumerate() {
        if !bool::from(sample.compute_hash().ct_eq(&sample.hash)) {
            return Err(format!("sample {i}: hash mismatch"));
        }
        if i > 0 {
            let prev = &samples[i - 1];
            if !bool::from(sample.previous_hash.ct_eq(&prev.hash)) {
                return Err(format!("sample {i}: broken chain link"));
            }
            if sample.timestamp <= prev.timestamp {
                return Err(format!("sample {i}: timestamp not monotonic"));
            }
            if sample.keystroke_count <= prev.keystroke_count {
                return Err(format!("sample {i}: keystroke count not monotonic"));
            }
        } else if !bool::from(sample.previous_hash.ct_eq(&[0u8; 32])) {
            return Err("sample 0: non-zero previous hash".to_string());
        }
    }
    Ok(())
}

/// Combined jitter + zone-tracking session for a single document.
#[derive(Debug)]
pub struct HybridJitterSession {
    pub(crate) cpoe_jitter_session: PhysSession,
    pub(crate) zone_engine: ZoneTrackingEngine,
    pub(crate) document_tracker: DocumentTracker,
    pub id: String,
    pub document_path: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub params: Parameters,
    pub(crate) samples: Vec<HybridSample>,
    pub(crate) keystroke_count: u64,
    pub(crate) last_jitter: u32,
    unique_doc_hashes: std::collections::HashSet<[u8; 32]>,
    loaded_readonly: bool,
    loaded_cpoe_jitter_evidence: Option<String>,
    chain_valid_cache: Option<bool>,
    id_arc: Arc<str>,
}

impl HybridJitterSession {
    pub fn new(
        document_path: impl AsRef<Path>,
        params: Option<Parameters>,
        key_material: Option<[u8; 32]>,
    ) -> Result<Self, String> {
        let params = params.unwrap_or_else(crate::jitter::default_parameters);

        if params.sample_interval == 0 {
            return Err("sample_interval must be > 0".to_string());
        }

        let document_tracker = DocumentTracker::new(document_path.as_ref())?;
        let document_path_str = document_tracker.path.clone();

        let mut material = Zeroizing::new(if let Some(k) = key_material {
            k
        } else {
            let mut k = [0u8; 32];
            getrandom::getrandom(&mut k)
                .map_err(|e| format!("failed to generate key material: {e}"))?;
            k
        });

        let mut secret = derive_session_secret(material.as_ref(), b"cpoe-hybrid-session-v1", None)
            .map_err(|e| e.to_string())?;
        material.zeroize();
        let cpoe_jitter_session = PhysSession::new(&secret);
        secret.zeroize();

        let id = hex::encode(rand::random::<[u8; 8]>());
        let id_arc: Arc<str> = Arc::from(id.as_str());
        Ok(Self {
            cpoe_jitter_session,
            zone_engine: ZoneTrackingEngine::new(),
            document_tracker,
            id,
            document_path: document_path_str,
            started_at: Utc::now(),
            ended_at: None,
            params,
            samples: Vec::new(),
            keystroke_count: 0,
            last_jitter: 0,
            unique_doc_hashes: std::collections::HashSet::new(),
            loaded_readonly: false,
            loaded_cpoe_jitter_evidence: None,
            chain_valid_cache: None,
            id_arc,
        })
    }

    pub fn new_with_id(
        document_path: impl AsRef<Path>,
        params: Option<Parameters>,
        session_id: impl Into<String>,
    ) -> Result<Self, String> {
        let mut session = Self::new(document_path, params, None)?;
        session.id = session_id.into();
        session.id_arc = Arc::from(session.id.as_str());
        Ok(session)
    }

    pub fn record_keystroke(&mut self, keycode: u16) -> Result<(u32, bool), String> {
        if self.loaded_readonly {
            return Err(
                "cannot record keystrokes on a loaded session; PhysSession state was not restored"
                    .into(),
            );
        }
        self.keystroke_count += 1;

        if self.keystroke_count % self.params.sample_interval != 0 {
            self.zone_engine.record_keycode(keycode);
            return Ok((0, false));
        }

        let doc_hash = self.document_tracker.hash()?;
        let now = Utc::now();
        let zone_transition = self.zone_engine.record_keycode(keycode).unwrap_or_else(|| {
            log::trace!("unknown zone for keycode {keycode}");
            0xFF
        });

        // Fixed-size buffer avoids per-keystroke heap allocation.
        let mut input = [0u8; 49]; // 8 (count) + 32 (hash) + 1 (zone) + 8 (timestamp)
        input[..8].copy_from_slice(&self.keystroke_count.to_be_bytes());
        input[8..40].copy_from_slice(&doc_hash);
        input[40] = zone_transition;
        input[41..49].copy_from_slice(&now.timestamp_nanos_safe().to_be_bytes());

        let jitter = self
            .cpoe_jitter_session
            .sample(&input)
            .map_err(|e| format!("cpoe_jitter sample failed: {e}"))?;

        let is_phys = self
            .cpoe_jitter_session
            .evidence()
            .records()
            .last()
            .map(|e| e.is_phys())
            .unwrap_or(false);

        let previous_hash = self.samples.last().map(|s| s.hash).unwrap_or([0u8; 32]);
        let mut sample = HybridSample {
            timestamp: now,
            keystroke_count: self.keystroke_count,
            document_hash: doc_hash,
            jitter_micros: jitter,
            zone_transition,
            hash: [0u8; 32],
            previous_hash,
            is_phys,
            session_id: Arc::clone(&self.id_arc),
        };
        sample.hash = sample.compute_hash();

        self.unique_doc_hashes.insert(doc_hash);
        self.samples.push(sample);
        self.last_jitter = jitter;
        self.chain_valid_cache = None;

        Ok((jitter, true))
    }

    pub fn end(&mut self) {
        self.ended_at = Some(Utc::now());
    }

    pub fn keystroke_count(&self) -> u64 {
        self.keystroke_count
    }

    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    fn effective_end(&self) -> DateTime<Utc> {
        self.ended_at.unwrap_or_else(Utc::now)
    }

    pub fn duration(&self) -> Duration {
        let end = self.effective_end();
        match end.signed_duration_since(self.started_at).to_std() {
            Ok(d) => d,
            Err(_) => {
                log::warn!(
                    "negative session duration: started_at={} effective_end={}; returning 0",
                    self.started_at,
                    end
                );
                Duration::from_secs(0)
            }
        }
    }

    pub fn phys_ratio(&self) -> f64 {
        self.cpoe_jitter_session.phys_ratio()
    }

    pub fn entropy_quality(&self) -> EntropyQuality {
        if self.loaded_readonly {
            if let Some(ref json) = self.loaded_cpoe_jitter_evidence {
                match serde_json::from_str::<PhysEvidenceChain>(json) {
                    Ok(chain) => {
                        return EntropyQuality {
                            phys_ratio: chain.phys_ratio(),
                            total_samples: chain.records().len(),
                            phys_samples: chain.phys_count(),
                            pure_samples: chain.pure_count(),
                        };
                    }
                    Err(e) => {
                        log::warn!("failed to parse loaded cpoe_jitter evidence: {e}");
                    }
                }
            }
        }

        let evidence = self.cpoe_jitter_session.evidence();
        let phys_samples = evidence.phys_count();
        let pure_samples = evidence.pure_count();

        EntropyQuality {
            phys_ratio: evidence.phys_ratio(),
            total_samples: evidence.records().len(),
            phys_samples,
            pure_samples,
        }
    }

    pub fn profile(&self) -> &crate::jitter::TypingProfile {
        self.zone_engine.profile()
    }

    pub fn samples(&self) -> &[HybridSample] {
        &self.samples
    }

    pub fn verify_chain(&self) -> Result<(), String> {
        verify_sample_chain(&self.samples)
    }

    pub fn export(&self) -> HybridEvidence {
        let end = self.effective_end();
        let statistics = self.compute_stats();
        let entropy_quality = self.entropy_quality();

        HybridEvidence {
            session_id: self.id.clone(),
            started_at: self.started_at,
            ended_at: end,
            document_path: self.document_path.clone(),
            params: self.params,
            samples: self.samples.clone(),
            statistics,
            entropy_quality,
            typing_profile: *self.profile(),
            cpoe_jitter_evidence: if self.loaded_readonly {
                self.loaded_cpoe_jitter_evidence.clone()
            } else {
                match self.cpoe_jitter_session.export_json() {
                    Ok(v) => Some(v),
                    Err(e) => {
                        log::error!("failed to export cpoe_jitter evidence JSON: {e}");
                        None
                    }
                }
            },
        }
    }

    pub fn export_standard(&self) -> Evidence {
        let end = self.effective_end();

        let samples: Vec<crate::jitter::Sample> = self
            .samples
            .iter()
            .map(|hs| crate::jitter::Sample {
                timestamp: hs.timestamp,
                keystroke_count: hs.keystroke_count,
                document_hash: hs.document_hash,
                jitter_micros: hs.jitter_micros,
                hash: hs.hash,
                previous_hash: hs.previous_hash,
            })
            .collect();

        Evidence {
            session_id: self.id.clone(),
            started_at: self.started_at,
            ended_at: end,
            document_path: self.document_path.clone(),
            params: self.params,
            samples,
            statistics: self.compute_stats(),
        }
    }

    fn compute_stats(&self) -> Statistics {
        let end = self.effective_end();
        let duration = end
            .signed_duration_since(self.started_at)
            .to_std()
            .unwrap_or(Duration::from_secs(0));

        let keystrokes_per_min = {
            let secs = duration.as_secs_f64();
            if secs > 0.0 {
                self.keystroke_count as f64 / (secs / 60.0)
            } else {
                0.0
            }
        };

        let total = i32::try_from(self.samples.len()).unwrap_or_else(|_| {
            log::warn!("sample count {} exceeds i32::MAX", self.samples.len());
            i32::MAX
        });
        let unique = i32::try_from(self.unique_doc_hashes.len()).unwrap_or_else(|_| {
            log::warn!(
                "unique_doc_hashes count {} exceeds i32::MAX",
                self.unique_doc_hashes.len()
            );
            i32::MAX
        });

        Statistics {
            total_keystrokes: self.keystroke_count,
            total_samples: total,
            duration,
            keystrokes_per_min,
            unique_doc_hashes: unique,
            chain_valid: self
                .chain_valid_cache
                .unwrap_or_else(|| self.verify_chain().is_ok()),
        }
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let data = HybridSessionData {
            id: self.id.clone(),
            started_at: self.started_at,
            ended_at: self.ended_at,
            document_path: self.document_path.clone(),
            params: self.params,
            samples: self.samples.clone(),
            keystroke_count: self.keystroke_count,
            last_jitter: self.last_jitter,
            zone_engine: self.zone_engine.clone(),
            cpoe_jitter_evidence: if self.loaded_readonly {
                self.loaded_cpoe_jitter_evidence.clone()
            } else {
                match self.cpoe_jitter_session.export_json() {
                    Ok(v) => Some(v),
                    Err(e) => {
                        log::warn!("failed to export cpoe_jitter evidence for session save: {e}");
                        None
                    }
                }
            },
        };

        let bytes = serde_json::to_vec_pretty(&data).map_err(|e| e.to_string())?;

        let parent = path.as_ref().parent().unwrap_or(Path::new("."));
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        crate::crypto::atomic_write(path.as_ref(), &bytes)
            .map_err(|e| format!("failed to persist session file: {e}"))?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>, key_material: Option<[u8; 32]>) -> Result<Self, String> {
        let meta = fs::metadata(path.as_ref()).map_err(|e| e.to_string())?;
        if meta.len() > 20 * 1024 * 1024 {
            return Err(format!(
                "session file is {} MB, exceeds 20 MB limit",
                meta.len() / (1024 * 1024)
            ));
        }
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        let data: HybridSessionData = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;

        if data.params.sample_interval == 0 {
            return Err("sample_interval must be > 0".into());
        }

        // Verify hash chain integrity of loaded samples
        verify_sample_chain(&data.samples).map_err(|e| format!("{e} in loaded data"))?;

        // A PhysSession requires a secret even though this loaded session is read-only
        // and will never record new samples. The key material is not security-critical here.
        let mut material = Zeroizing::new(if let Some(k) = key_material {
            k
        } else {
            let mut k = [0u8; 32];
            getrandom::getrandom(&mut k)
                .map_err(|e| format!("failed to generate key material: {e}"))?;
            k
        });

        let mut secret = derive_session_secret(material.as_ref(), b"cpoe-hybrid-session-v1", None)
            .map_err(|e| e.to_string())?;
        material.zeroize();

        let document_tracker = DocumentTracker {
            path: data.document_path.clone(),
            last_mtime: None,
            last_size: None,
            last_hash: None,
        };

        let cpoe_jitter_session = PhysSession::new(&secret);
        secret.zeroize();

        let unique_doc_hashes: std::collections::HashSet<[u8; 32]> =
            data.samples.iter().map(|s| s.document_hash).collect();
        let id_arc: Arc<str> = Arc::from(data.id.as_str());
        Ok(Self {
            cpoe_jitter_session,
            zone_engine: data.zone_engine,
            document_tracker,
            id: data.id,
            document_path: data.document_path,
            started_at: data.started_at,
            ended_at: data.ended_at,
            params: data.params,
            samples: data.samples,
            keystroke_count: data.keystroke_count,
            last_jitter: data.last_jitter,
            unique_doc_hashes,
            loaded_readonly: true,
            loaded_cpoe_jitter_evidence: data.cpoe_jitter_evidence,
            chain_valid_cache: Some(true),
            id_arc,
        })
    }
}

impl HybridEvidence {
    pub fn verify(&self) -> Result<(), String> {
        verify_sample_chain(&self.samples)?;

        if let Some(ref cpoe_jitter_json) = self.cpoe_jitter_evidence {
            self.verify_cpoe_jitter_evidence(cpoe_jitter_json)?;
        }

        Ok(())
    }

    fn verify_cpoe_jitter_evidence(&self, json: &str) -> Result<(), String> {
        let chain: PhysEvidenceChain = serde_json::from_str(json)
            .map_err(|e| format!("cpoe_jitter evidence parse error: {e}"))?;

        if !chain.validate_sequences() {
            return Err("cpoe_jitter evidence: sequence numbers not monotonic".to_string());
        }

        if !chain.validate_timestamps() {
            return Err("cpoe_jitter evidence: timestamps not monotonic".to_string());
        }

        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec_pretty(self).map_err(|e| e.to_string())
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(data).map_err(|e| e.to_string())
    }

    pub fn typing_rate(&self) -> f64 {
        if self.statistics.duration.as_secs_f64() > 0.0 {
            self.statistics.total_keystrokes as f64
                / (self.statistics.duration.as_secs_f64() / 60.0)
        } else {
            0.0
        }
    }

    const MIN_PLAUSIBLE_RATE_KPM: f64 = 10.0;
    const MAX_PLAUSIBLE_RATE_KPM: f64 = 1000.0;
    const LOW_RATE_KEYSTROKE_THRESHOLD: u64 = 100;
    const MIN_UNIQUE_DOC_HASHES: i32 = 2;
    const DOC_HASH_KEYSTROKE_THRESHOLD: u64 = 500;

    pub fn is_plausible_human_typing(&self) -> bool {
        let rate = self.typing_rate();
        if rate < Self::MIN_PLAUSIBLE_RATE_KPM
            && self.statistics.total_keystrokes > Self::LOW_RATE_KEYSTROKE_THRESHOLD
        {
            return false;
        }
        if rate > Self::MAX_PLAUSIBLE_RATE_KPM {
            return false;
        }
        if self.statistics.unique_doc_hashes < Self::MIN_UNIQUE_DOC_HASHES
            && self.statistics.total_keystrokes > Self::DOC_HASH_KEYSTROKE_THRESHOLD
        {
            return false;
        }
        true
    }

    pub fn entropy_source(&self) -> &'static str {
        if self.entropy_quality.phys_ratio > 0.9 {
            "hardware (TSC-based)"
        } else if self.entropy_quality.phys_ratio > 0.5 {
            "hybrid (hardware + HMAC)"
        } else if self.entropy_quality.phys_ratio > 0.0 {
            "mostly HMAC (limited hardware)"
        } else {
            "pure HMAC (no hardware entropy)"
        }
    }
}

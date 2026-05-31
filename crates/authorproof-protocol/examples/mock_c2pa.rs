// Generate a mock .c2pa file with realistic forensic signals for portal testing.

use authorproof_protocol::c2pa::{
    C2paManifestBuilder, CadenceCorrections, CadenceDwell, CadenceFatigue, CadenceSpectral,
    CadenceTiming, CognitiveLoadSignals, CognitiveMarkersAssertion, EditMetricSignals,
    ErrorEcologySignals, EvidenceChainAssertion, FocusSignals, ForensicSignalScores, JitterSeal,
    KeystrokeCadenceAssertion, LikelihoodModelSignals, RevisionTopologySignals,
    RevisionTypeBreakdown, SessionStatsSignals,
};
use authorproof_protocol::rfc::{
    AttestationTier, Checkpoint, DocumentRef, EvidencePacket, HashAlgorithm, HashValue,
};
use ed25519_dalek::SigningKey;

fn main() {
    let key = SigningKey::from_bytes(&[42u8; 32]);

    let base_ts: u64 = 1_716_800_000_000;
    let checkpoints: Vec<Checkpoint> = (0..12)
        .map(|i| {
            let mut prev = vec![0u8; 32];
            if i > 0 {
                prev[0] = (i - 1) as u8;
            }
            Checkpoint {
                sequence: i,
                checkpoint_id: {
                    let mut id = vec![0u8; 16];
                    id[0] = i as u8;
                    id
                },
                timestamp: base_ts + i * 30_000,
                content_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: { let mut h = vec![0u8; 32]; h[0] = i as u8; h[1] = 0xCC; h },
                },
                char_count: 120 + i * 85,
                prev_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: prev,
                },
                checkpoint_hash: HashValue {
                    algorithm: HashAlgorithm::Sha256,
                    digest: { let mut h = vec![0u8; 32]; h[0] = i as u8; h[1] = 0xDD; h },
                },
                jitter_hash: None,
            }
        })
        .collect();

    let packet = EvidencePacket {
        version: 1,
        profile_uri: "urn:ietf:params:pop:profile:1.0".to_string(),
        packet_id: vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ],
        created: base_ts,
        document: DocumentRef {
            content_hash: HashValue {
                algorithm: HashAlgorithm::Sha256,
                digest: vec![0xAB; 32],
            },
            filename: Some("Research Paper - Human Authorship.txt".to_string()),
            byte_length: 14_832,
            char_count: 12_650,
        },
        checkpoints,
        attestation_tier: Some(AttestationTier::AttestedSoftware),
        baseline_verification: None,
    };

    let evidence_bytes = b"mock-evidence-cbor-payload-for-portal-testing".to_vec();
    let doc_hash = [0xABu8; 32];

    let forensic_signals = ForensicSignalScores {
        cognitive_load: 0.92,
        revision_topology: 0.88,
        error_ecology: 0.95,
        likelihood_model: 0.97,
        composition_mode: 0.94,
    };

    let keystroke_cadence = KeystrokeCadenceAssertion {
        version: 1,
        keystroke_count: 12_650,
        session_duration_sec: 360.0,
        timing: CadenceTiming {
            mean_iki_ms: 142.0,
            median_iki_ms: 128.0,
            coefficient_of_variation: 0.68,
            iki_percentiles: [45.0, 85.0, 128.0, 195.0, 380.0],
            burst_count: 47,
            avg_burst_length: 6.2,
            pause_count: 34,
            avg_pause_duration_ms: 2_150.0,
            pause_depth_distribution: [0.45, 0.30, 0.25],
        },
        dwell: CadenceDwell {
            mean_dwell_ms: 78.0,
            dwell_cv: 0.42,
            mean_flight_ms: 64.0,
            flight_cv: 0.55,
        },
        corrections: CadenceCorrections {
            correction_ratio: 0.08,
            cross_hand_timing_ratio: 0.62,
            post_pause_cv: 0.71,
            iki_autocorrelation: 0.35,
        },
        fatigue: Some(CadenceFatigue {
            phase: 2,
            trajectory_residual: 0.12,
        }),
        spectral: Some(CadenceSpectral {
            slope: -1.2,
            noise_type: "pink".to_string(),
        }),
        hurst_exponent: Some(0.72),
        biological_cadence_score: Some(0.91),
    };

    let cognitive_markers = CognitiveMarkersAssertion {
        version: 1,
        cognitive_load: Some(CognitiveLoadSignals {
            iki_surprisal_rho: 0.45,
            sentence_arc_r_squared: 0.38,
            structural_pause_concentration: 0.72,
            composite_score: 0.92,
            deep_pause_count: 18,
            boundary_count: 24,
            word_count: 2_530,
        }),
        revision_topology: Some(RevisionTopologySignals {
            mean_branching_factor: 2.1,
            mean_revisit_depth: 1.8,
            mean_frontier_distance: 45.0,
            active_region_count: 6,
            detour_ratio: 0.15,
            leading_edge_divergence: 0.22,
            insertion_point_entropy: 3.8,
            revision_types: RevisionTypeBreakdown {
                sub_word_motor_pct: 0.35,
                word_substitution_pct: 0.28,
                clause_restructuring_pct: 0.22,
                positional_insertion_pct: 0.15,
                total_revisions: 89,
            },
            composite_score: 0.88,
        }),
        error_ecology: Some(ErrorEcologySignals {
            rapid_self_correction_pct: 0.42,
            immediate_small_correction_pct: 0.25,
            delayed_correction_pct: 0.18,
            bulk_correction_pct: 0.08,
            false_start_pct: 0.07,
            total_corrections: 89,
            correction_rate: 0.08,
            jsd_from_cognitive: 0.05,
            jsd_from_transcriptive: 0.82,
            composite_score: 0.95,
        }),
        likelihood_model: Some(LikelihoodModelSignals {
            session_llr: 28.5,
            session_p_cognitive: 0.97,
            window_count: 24,
            cognitive_window_count: 23,
            transcriptive_window_count: 1,
            mean_window_llr: 1.19,
            llr_std_dev: 0.45,
            composite_score: 0.97,
        }),
        focus: Some(FocusSignals {
            switch_count: 3,
            out_of_focus_ratio: 0.02,
            ai_app_switch_count: 0,
            mid_typing_switch_ratio: 0.01,
        }),
        edit_metrics: Some(EditMetricSignals {
            monotonic_append_ratio: 0.65,
            edit_entropy: 4.2,
            timing_entropy: 3.8,
            pause_entropy: 3.5,
            positive_negative_ratio: 0.88,
            deletion_clustering: 0.15,
        }),
    };

    let evidence_chain = EvidenceChainAssertion {
        version: 1,
        checkpoint_count: 12,
        chain_duration_sec: 330.0,
        seals: (0..12)
            .map(|i| JitterSeal {
                sequence: i,
                timestamp: base_ts + i * 30_000,
                seal_hash: format!("{:064x}", i * 0x1111),
            })
            .collect(),
        session_stats: Some(SessionStatsSignals {
            session_count: 1,
            avg_session_duration_sec: 360.0,
            total_editing_time_sec: 330.0,
            time_span_sec: 360.0,
        }),
    };

    let jumbf = C2paManifestBuilder::new(packet, evidence_bytes, doc_hash)
        .document_filename("Research Paper - Human Authorship.txt")
        .title("Research Paper - Human Authorship")
        .format("text/plain")
        .forensic_signals(
            forensic_signals,
            Some("original_composition".to_string()),
            Some("cognitive".to_string()),
        )
        .keystroke_cadence(keystroke_cadence)
        .cognitive_markers(cognitive_markers)
        .evidence_chain(evidence_chain)
        .build_jumbf(&key)
        .expect("Failed to build JUMBF");

    let desktop = std::path::PathBuf::from(std::env::var("HOME").unwrap()).join("Desktop");
    let out_path = desktop.join("mock.c2pa");
    std::fs::write(&out_path, &jumbf).expect("Failed to write file");
    println!("Wrote {} bytes to {}", jumbf.len(), out_path.display());
}

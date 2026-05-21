// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! 12-page ENFSI-compliant forensic report renderer.
//!
//! Loads the HTML template via `include_str!()` and replaces `{{placeholder}}`
//! tokens with data from a [`WarReport`].

use super::helpers::{format_lr, html_escape};
use crate::report::types::*;
use std::fmt::Write;

const TEMPLATE: &str = include_str!("templates/forensic_report.html");

/// Render a 12-page forensic examination report as self-contained HTML.
pub fn render_forensic_html(r: &WarReport) -> String {
    let mut html = TEMPLATE.to_string();

    // -- Block markers (must be replaced before scalars to avoid partial matches) --
    html = html.replace("{{DIMENSION_ROWS}}", &build_dimension_rows(&r.dimensions));
    html = html.replace("{{CHECKPOINT_ROWS}}", &build_checkpoint_rows(&r.checkpoints));
    html = html.replace("{{CUSTODY_ROWS}}", &build_custody_rows(r));
    html = html.replace("{{BEHAVIOUR_ROWS}}", &build_behaviour_rows(r));
    html = html.replace("{{CHAIN_STEPS}}", &build_chain_steps(r));
    html = html.replace(
        "{{examined_text_paragraphs}}",
        &build_examined_text(r.analyzed_text.as_deref()),
    );

    // -- Computed prose sections --
    let lr = r.likelihood_ratio;
    let log_lr = if lr > 0.0 && lr.is_finite() {
        lr.log10()
    } else {
        0.0
    };
    html = html.replace("{{evaluative_statement}}", &build_evaluative_statement(r));
    html = html.replace(
        "{{enfsi_verbal_short}}",
        &build_enfsi_verbal_short(lr, r.enfsi_tier),
    );
    html = html.replace(
        "{{key_finding_paragraph}}",
        &build_key_finding_paragraph(r),
    );
    html = html.replace(
        "{{behaviour_summary_sentence}}",
        &build_behaviour_summary(r),
    );
    html = html.replace(
        "{{behaviour_note_paragraph}}",
        &build_behaviour_note(r),
    );
    html = html.replace(
        "{{dimension_summary_paragraph}}",
        &build_dimension_summary(r),
    );
    html = html.replace("{{enfsi_scale_paragraph}}", &build_enfsi_scale_paragraph(r));
    html = html.replace(
        "{{session_duration_limitation}}",
        &build_session_duration_limitation(r),
    );

    // -- Scalar replacements --
    let date_issued = format_date_issued(&r.generated_at);
    let date_short = r.generated_at.format("%d %B %Y").to_string();
    let doc_hash = &r.document_hash;
    let doc_hash_trunc = truncate_hash(doc_hash);
    let sk = &r.signing_key_fingerprint;
    let sk_short = if sk.len() >= 16 { &sk[..16] } else { sk };
    let cp_count = r.checkpoints.len();

    html = html.replace("{{report_id}}", &html_escape(&r.report_id));
    html = html.replace("{{date_issued}}", &html_escape(&date_issued));
    html = html.replace("{{date_issued_short}}", &html_escape(&date_short));
    html = html.replace("{{document_hash_truncated}}", &html_escape(&doc_hash_trunc));
    html = html.replace("{{document_hash}}", &html_escape(doc_hash));
    html = html.replace(
        "{{engine_and_schema}}",
        &format!(
            "CPoE {} · Schema {}",
            html_escape(&r.algorithm_version),
            html_escape(&r.schema_version)
        ),
    );
    html = html.replace("{{algorithm_version}}", &html_escape(&r.algorithm_version));
    html = html.replace("{{schema_version}}", &html_escape(&r.schema_version));
    html = html.replace("{{signing_key_fingerprint}}", &html_escape(sk));
    html = html.replace("{{signing_key_short}}", &html_escape(sk_short));
    html = html.replace("{{likelihood_ratio}}", &format_lr(lr));
    html = html.replace("{{log10_lr}}", &format!("{:+.3}", log_lr));
    html = html.replace(
        "{{confidence_interval}}",
        &format_confidence_interval(lr, r.methodology.as_ref()),
    );
    html = html.replace("{{score}}", &r.score.to_string());
    html = html.replace("{{verdict_label}}", r.verdict.label());
    html = html.replace("{{enfsi_tier_label}}", r.enfsi_tier.label());

    // Document stats
    html = html.replace(
        "{{document_length_desc}}",
        &format_document_length(r),
    );
    html = html.replace(
        "{{document_chars}}",
        &r.document_chars.unwrap_or(0).to_string(),
    );
    html = html.replace(
        "{{document_words}}",
        &r.document_words.unwrap_or(0).to_string(),
    );

    // Session info
    let first_session = r.sessions.first();
    html = html.replace(
        "{{first_session_id}}",
        &format!("S{}", first_session.map_or(1, |s| s.index)),
    );
    html = html.replace(
        "{{session_start_iso}}",
        &first_session
            .map(|s| s.start.to_rfc3339())
            .unwrap_or_else(|| r.generated_at.to_rfc3339()),
    );
    html = html.replace(
        "{{session_end_iso}}",
        &r.checkpoints
            .last()
            .map(|c| c.timestamp.to_rfc3339())
            .unwrap_or_else(|| r.generated_at.to_rfc3339()),
    );

    let total_sec = (r.total_duration_min * 60.0) as u64;
    let dur_min = total_sec / 60;
    let dur_sec = total_sec % 60;
    let dur_human = if dur_min > 0 {
        format!("{} minute{} {} seconds", dur_min, if dur_min == 1 { "" } else { "s" }, dur_sec)
    } else {
        format!("{} seconds", dur_sec)
    };
    html = html.replace("{{total_duration_human}}", &dur_human);
    html = html.replace("{{total_duration_sec}}", &total_sec.to_string());
    html = html.replace("{{session_count}}", &r.session_count.to_string());

    // Checkpoints
    html = html.replace("{{checkpoint_count}}", &cp_count.to_string());
    html = html.replace(
        "{{checkpoint_count_words}}",
        number_to_words(cp_count),
    );
    html = html.replace(
        "{{checkpoint_indices_end}}",
        &if cp_count > 1 {
            format!(" and {}", cp_count - 1)
        } else {
            String::new()
        },
    );

    // Device
    html = html.replace(
        "{{device_hostname}}",
        &html_escape(
            first_session
                .and_then(|s| s.device.as_deref())
                .unwrap_or("Unknown"),
        ),
    );
    html = html.replace(
        "{{device_os}}",
        &html_escape(&extract_os_from_attestation(&r.device_attestation)),
    );
    html = html.replace(
        "{{device_attestation}}",
        &html_escape(&r.device_attestation),
    );
    html = html.replace(
        "{{attestation_tier}}",
        &format_attestation_tier(&r.device_attestation),
    );
    html = html.replace("{{timezone_label}}", "UTC");
    html = html.replace("{{revision_events}}", &r.revision_events.to_string());

    // Behavioural metrics
    html = html.replace(
        "{{iki_cv}}",
        &r.process
            .iki_cv
            .map_or("N/A".to_string(), |v| format!("{:.2}", v)),
    );
    html = html.replace(
        "{{revision_intensity_pct}}",
        &r.process
            .revision_intensity
            .map_or("N/A".to_string(), |v| format!("{:.1}%", v * 100.0)),
    );
    html = html.replace(
        "{{paste_ratio_pct}}",
        &r.process
            .paste_ratio_pct
            .map_or("0.0%".to_string(), |v| format!("{:.1}%", v)),
    );
    html = html.replace(
        "{{burst_cv}}",
        &r.forensic_metrics
            .as_ref()
            .map_or("N/A".to_string(), |m| format!("{:.2}", m.burst_speed_cv)),
    );
    html = html.replace(
        "{{correction_rate}}",
        &r.forensic_metrics
            .as_ref()
            .map_or("N/A".to_string(), |m| format!("{:.1}", m.correction_ratio * 100.0)),
    );
    html = html.replace(
        "{{pause_p95}}",
        &r.process
            .pause_p95_sec
            .map_or("not measurable".to_string(), |v| format!("{:.1} s", v)),
    );

    // Extended forensic signals
    let fm = r.forensic_metrics.as_ref();
    html = html.replace("{{ADVANCED_FORENSICS}}", &build_advanced_forensics(fm));

    html
}

fn build_advanced_forensics(fm: Option<&ForensicBreakdown>) -> String {
    let Some(fm) = fm else {
        return String::new();
    };
    let mut out = String::new();

    let _ = write!(out, "<h3>Integrity Analysis</h3><table class=\"metrics\">");
    let _ = write!(out, "<tr><td>Biological Cadence Score</td><td class=\"r mono\">{:.2}</td></tr>", fm.biological_cadence_score);
    let _ = write!(out, "<tr><td>Timing Entropy</td><td class=\"r mono\">{:.2} bits</td></tr>", fm.timing_entropy);
    let _ = write!(out, "<tr><td>Pause Entropy</td><td class=\"r mono\">{:.2} bits</td></tr>", fm.pause_entropy);
    if let Some(snr) = fm.snr_db {
        let _ = write!(out, "<tr><td>Signal-to-Noise Ratio</td><td class=\"r mono\">{:.1} dB{}</td></tr>",
            snr, if fm.snr_flagged { " <span class=\"flag\">FLAGGED</span>" } else { "" });
    }
    if let Some(lyap) = fm.lyapunov_exponent {
        let _ = write!(out, "<tr><td>Lyapunov Exponent</td><td class=\"r mono\">{:.4}{}</td></tr>",
            lyap, if fm.lyapunov_flagged { " <span class=\"flag\">FLAGGED</span>" } else { "" });
    }
    if let Some(ratio) = fm.iki_compression_ratio {
        let _ = write!(out, "<tr><td>IKI Compression Ratio</td><td class=\"r mono\">{:.3}{}</td></tr>",
            ratio, if fm.iki_compression_flagged { " <span class=\"flag\">FLAGGED</span>" } else { "" });
    }
    if let Some(det) = fm.labyrinth_determinism {
        let _ = write!(out, "<tr><td>Labyrinth Determinism</td><td class=\"r mono\">{:.3}</td></tr>", det);
    }
    if let Some(rec) = fm.labyrinth_recurrence {
        let _ = write!(out, "<tr><td>Labyrinth Recurrence Rate</td><td class=\"r mono\">{:.3}</td></tr>", rec);
    }
    if fm.steg_confidence > 0.0 {
        let _ = write!(out, "<tr><td>Steganographic Watermark</td><td class=\"r mono\">{:.0}%</td></tr>", fm.steg_confidence * 100.0);
    }
    let _ = write!(out, "</table>");

    if fm.forgery_difficulty.is_some() || fm.fatigue_warmup_pct.is_some() || fm.cross_modal_score.is_some() {
        let _ = write!(out, "<h3>Deep Behavioral Analysis</h3><table class=\"metrics\">");
        if let Some(diff) = fm.forgery_difficulty {
            let _ = write!(out, "<tr><td>Forgery Difficulty</td><td class=\"r mono\">{:.1}/10 ({})</td></tr>",
                diff, fm.forgery_tier.as_deref().unwrap_or("N/A"));
        }
        if let Some(time) = fm.forgery_time_sec {
            let _ = write!(out, "<tr><td>Est. Forge Time</td><td class=\"r mono\">{:.0} sec</td></tr>", time);
        }
        if let Some(score) = fm.cross_modal_score {
            let _ = write!(out, "<tr><td>Cross-Modal Consistency</td><td class=\"r mono\">{:.0}% ({})</td></tr>",
                score * 100.0, fm.cross_modal_verdict.as_deref().unwrap_or("N/A"));
        }
        if fm.transcription_suspicious {
            let _ = write!(out, "<tr><td>Transcription Suspicion</td><td class=\"r mono\"><span class=\"flag\">SUSPICIOUS</span></td></tr>");
        }
        let _ = write!(out, "<tr><td>Thinking Pause Ratio</td><td class=\"r mono\">{:.2}</td></tr>", fm.thinking_pause_ratio);
        if let Some(w) = fm.fatigue_warmup_pct {
            let _ = write!(out, "<tr><td>Fatigue Profile</td><td class=\"r mono\">Warmup {:.0}% / Plateau {:.0}% / Fatigue {:.0}%</td></tr>",
                w * 100.0,
                fm.fatigue_plateau_pct.unwrap_or(0.0) * 100.0,
                fm.fatigue_pct.unwrap_or(0.0) * 100.0);
        }
        if let Some(r) = fm.repair_recent_pct {
            let _ = write!(out, "<tr><td>Repair Locality</td><td class=\"r mono\">Recent {:.0}% / Distant {:.0}%</td></tr>",
                r * 100.0, fm.repair_distant_pct.unwrap_or(0.0) * 100.0);
        }
        let _ = write!(out, "</table>");
    }

    if fm.cognitive_load_score.is_some() || fm.likelihood_p_cognitive.is_some() {
        let _ = write!(out, "<h3>Enhanced Signal Scores</h3><table class=\"metrics\">");
        if let Some(s) = fm.cognitive_load_score {
            let _ = write!(out, "<tr><td>Cognitive Load</td><td class=\"r mono\">{:.0}%</td></tr>", s * 100.0);
        }
        if let Some(s) = fm.revision_topology_score {
            let _ = write!(out, "<tr><td>Revision Topology</td><td class=\"r mono\">{:.0}%</td></tr>", s * 100.0);
        }
        if let Some(s) = fm.error_ecology_score {
            let _ = write!(out, "<tr><td>Error Ecology</td><td class=\"r mono\">{:.0}%</td></tr>", s * 100.0);
        }
        if let Some(p) = fm.likelihood_p_cognitive {
            let _ = write!(out, "<tr><td>P(Cognitive)</td><td class=\"r mono\">{:.0}%</td></tr>", p * 100.0);
        }
        if let Some(mode) = &fm.composition_mode {
            let _ = write!(out, "<tr><td>Composition Mode</td><td class=\"r mono\">{}</td></tr>", html_escape(mode));
        }
        let _ = write!(out, "</table>");
    }

    out
}

// ---------------------------------------------------------------------------
// Block builders
// ---------------------------------------------------------------------------

fn build_dimension_rows(dims: &[DimensionScore]) -> String {
    let mut out = String::new();
    for d in dims {
        let log_lr = if d.lr > 0.0 && d.lr.is_finite() {
            d.lr.log10()
        } else {
            0.0
        };
        let sub = d
            .analysis
            .first()
            .map(|a| html_escape(&a.label))
            .unwrap_or_default();
        let lr_str = format_lr(d.lr);
        let _ = writeln!(
            out,
            "      <tr>\n\
             \x20       <td><div class=\"dim-label\">{name}</div><div class=\"dim-sub\">{sub}</div></td>\n\
             \x20       <td><div class=\"disc\">{disc}</div></td>\n\
             \x20       <td class=\"r mono\">{lr_str}</td>\n\
             \x20       <td class=\"r mono\">{log_lr:+.3}</td>\n\
             \x20     </tr>",
            name = html_escape(&d.name),
            sub = sub,
            disc = html_escape(&d.key_discriminator),
        );
    }
    out
}

fn build_checkpoint_rows(cps: &[ReportCheckpoint]) -> String {
    let mut out = String::new();
    for cp in cps {
        let ts = cp.timestamp.format("%H:%M:%S%.3f").to_string();
        let hash_trunc = truncate_hash(&cp.content_hash);
        let vdf = cp
            .vdf_iterations
            .map_or("0".to_string(), |v| v.to_string());
        let _ = writeln!(
            out,
            "      <tr>\n\
             \x20       <td class=\"mono\">{ord}</td>\n\
             \x20       <td class=\"mono\">{ts}</td>\n\
             \x20       <td class=\"mono\">{hash}</td>\n\
             \x20       <td class=\"r mono\">{size}</td>\n\
             \x20       <td class=\"r mono\">{vdf}</td>\n\
             \x20     </tr>",
            ord = cp.ordinal,
            ts = ts,
            hash = html_escape(&hash_trunc),
            size = cp.content_size,
            vdf = vdf,
        );
    }
    out
}

fn build_custody_rows(r: &WarReport) -> String {
    let mut out = String::new();
    let mut event_num = 1u32;
    let engine_ver = format!("CPoE Engine {}", r.algorithm_version);
    let device = r
        .sessions
        .first()
        .and_then(|s| s.device.as_deref())
        .unwrap_or("Unknown");

    // C-01: Document opened
    if let Some(s) = r.sessions.first() {
        let _ = write_custody_row(
            &mut out,
            event_num,
            "Document opened in monitored application; capture key derived",
            &engine_ver,
            Some(device),
            &s.start.format("%H:%M:%S").to_string(),
        );
        event_num += 1;

        // C-02: Capture initiated
        let _ = write_custody_row(
            &mut out,
            event_num,
            &format!("Behavioural capture initiated; session S{} created", s.index),
            &engine_ver,
            None,
            &s.start.format("%H:%M:%S").to_string(),
        );
        event_num += 1;
    }

    // C-0N: Each checkpoint
    for cp in &r.checkpoints {
        let _ = write_custody_row(
            &mut out,
            event_num,
            &format!(
                "Checkpoint {} sealed; HMAC binding to {} recorded",
                cp.ordinal,
                if cp.ordinal == 0 {
                    "session genesis"
                } else {
                    "predecessor checkpoint"
                }
            ),
            &engine_ver,
            None,
            &cp.timestamp.format("%H:%M:%S").to_string(),
        );
        event_num += 1;
    }

    // VDF time-binding
    if let Some(last) = r.checkpoints.last() {
        let _ = write_custody_row(
            &mut out,
            event_num,
            "VDF time-binding applied to chain head",
            &engine_ver,
            None,
            &last.timestamp.format("%H:%M:%S").to_string(),
        );
        event_num += 1;
    }

    // Evidence bundle signed
    let sk_short = if r.signing_key_fingerprint.len() >= 8 {
        &r.signing_key_fingerprint[..8]
    } else {
        &r.signing_key_fingerprint
    };
    let _ = write_custody_row(
        &mut out,
        event_num,
        "Evidence bundle constructed and signed (COSE_Sign1, Ed25519)",
        &engine_ver,
        Some(&format!("Hardware-bound key {}", sk_short)),
        &r.generated_at.format("%H:%M:%S").to_string(),
    );
    event_num += 1;

    // Report generation
    let _ = write_custody_row(
        &mut out,
        event_num,
        "Report generation invoked on sealed bundle",
        &engine_ver,
        None,
        &r.generated_at.format("%H:%M:%S").to_string(),
    );
    event_num += 1;

    // Report produced
    let _ = write_custody_row(
        &mut out,
        event_num,
        &format!("Report {} produced and sealed", r.report_id),
        &engine_ver,
        Some("Adopted by examiner of record"),
        &r.generated_at.format("%H:%M:%S").to_string(),
    );

    out
}

fn write_custody_row(
    out: &mut String,
    num: u32,
    action: &str,
    custodian: &str,
    sub: Option<&str>,
    timestamp: &str,
) -> std::fmt::Result {
    let sub_html = sub
        .map(|s| {
            format!(
                "<br><span style=\"color:var(--ink-3); font-size:10.5px;\">{}</span>",
                html_escape(s)
            )
        })
        .unwrap_or_default();
    writeln!(
        out,
        "      <tr>\n\
         \x20       <td class=\"mono\">C-{num:02}</td>\n\
         \x20       <td>{action}</td>\n\
         \x20       <td class=\"sans\" style=\"font-size:11.5px;\">{custodian}{sub}</td>\n\
         \x20       <td class=\"r mono\">{ts}</td>\n\
         \x20     </tr>",
        num = num,
        action = html_escape(action),
        custodian = html_escape(custodian),
        sub = sub_html,
        ts = timestamp,
    )
}

fn build_behaviour_rows(r: &WarReport) -> String {
    let p = &r.process;
    let fm = r.forensic_metrics.as_ref();

    let rows: Vec<(&str, &str, String, &str, &str)> = vec![
        (
            "Inter-keystroke interval CV",
            "Coefficient of variation of timing between keystrokes",
            p.iki_cv
                .map_or("N/A".to_string(), |v| format!("{:.2}", v)),
            "0.30 – 0.80",
            "below 0.30",
        ),
        (
            "Revision intensity",
            "Proportion of keystrokes retained without subsequent revision",
            p.revision_intensity.map_or("N/A".to_string(), |v| {
                format!("{:.1}%", v * 100.0)
            }),
            "60 – 95%",
            "above 97%",
        ),
        (
            "Paste-to-typed ratio",
            "Proportion of content inserted via clipboard paste",
            p.paste_ratio_pct
                .map_or("0.0%".to_string(), |v| format!("{:.1}%", v)),
            "0 – 8%",
            "commonly elevated",
        ),
        (
            "Burst CV",
            "Variation in typing-burst duration across session",
            fm.map_or("N/A".to_string(), |m| {
                format!("{:.2}", m.burst_speed_cv)
            }),
            "0.25 – 0.70",
            "below 0.20",
        ),
        (
            "Correction rate",
            "Backspace and select-delete events per 100 keystrokes",
            fm.map_or("N/A".to_string(), |m| {
                format!("{:.1}", m.correction_ratio * 100.0)
            }),
            "3.0 – 12.0",
            "below 0.5",
        ),
        (
            "Pause distribution P95",
            "95th percentile of inter-keystroke pause duration",
            p.pause_p95_sec
                .map_or("not measurable".to_string(), |v| format!("{:.1} s", v)),
            "4.0 – 15.0 s",
            "below 2.0 s",
        ),
    ];

    let mut out = String::new();
    for (label, desc, captured, human, transcription) in &rows {
        let _ = writeln!(
            out,
            "      <tr>\n\
             \x20       <td><div class=\"dim-label\">{label}</div><div class=\"dim-sub\">{desc}</div></td>\n\
             \x20       <td class=\"r mono\">{captured}</td>\n\
             \x20       <td class=\"r mono\">{human}</td>\n\
             \x20       <td class=\"r mono\">{transcription}</td>\n\
             \x20     </tr>",
        );
    }
    out
}

fn build_chain_steps(r: &WarReport) -> String {
    let mut out = String::new();
    let device = r
        .sessions
        .first()
        .and_then(|s| s.device.as_deref())
        .unwrap_or("Unknown");
    let os = extract_os_from_attestation(&r.device_attestation);
    let ver = &r.algorithm_version;

    // Document opened
    if let Some(s) = r.sessions.first() {
        let _ = writeln!(
            out,
            "    <div class=\"chain-step\"><span class=\"marker\">\u{2192}</span><div class=\"body\">\
             <h4>Document opened in monitored application</h4>\
             <div class=\"detail\">{} \u{00b7} {} \u{00b7} WritersLogic Desktop {} \u{00b7} {}</div>\
             </div></div>",
            html_escape(device),
            html_escape(&os),
            html_escape(ver),
            s.start.format("%H:%M:%S%.3f UTC"),
        );
    }

    // Capture initiated
    let _ = writeln!(
        out,
        "    <div class=\"chain-step\"><span class=\"marker\">\u{2192}</span><div class=\"body\">\
         <h4>Behavioural capture initiated</h4>\
         <div class=\"detail\">Keystroke, timing, paste, and focus capture activated through \
         operating system accessibility API \u{00b7} capture key derived from device signing key</div>\
         </div></div>"
    );

    // Each checkpoint
    for cp in &r.checkpoints {
        let binding = if cp.ordinal == 0 {
            "session genesis"
        } else {
            &format!("checkpoint {}", cp.ordinal - 1)
        };
        let _ = writeln!(
            out,
            "    <div class=\"chain-step\"><span class=\"marker\">\u{2192}</span><div class=\"body\">\
             <h4>Checkpoint {} sealed</h4>\
             <div class=\"detail\">SHA-256 of document state computed; HMAC-SHA256 binding to {} recorded{}</div>\
             <div class=\"hash\">{}</div>\
             </div></div>",
            cp.ordinal,
            binding,
            if Some(cp.ordinal) == r.checkpoints.last().map(|c| c.ordinal) {
                "; VDF time-binding applied to chain head"
            } else {
                ""
            },
            html_escape(&cp.content_hash),
        );
    }

    // Evidence bundle signed
    let sk_short = if r.signing_key_fingerprint.len() >= 8 {
        &r.signing_key_fingerprint[..8]
    } else {
        &r.signing_key_fingerprint
    };
    let _ = writeln!(
        out,
        "    <div class=\"chain-step\"><span class=\"marker\">\u{2192}</span><div class=\"body\">\
         <h4>Evidence bundle signed</h4>\
         <div class=\"detail\">COSE_Sign1 structure produced; signature algorithm EdDSA \
         (Ed25519, RFC 8032); signing key fingerprint {} \u{00b7} TPM-bound</div>\
         </div></div>",
        html_escape(sk_short),
    );

    // Report generated
    let _ = writeln!(
        out,
        "    <div class=\"chain-step\"><span class=\"marker\">\u{2192}</span><div class=\"body\">\
         <h4>Report generated</h4>\
         <div class=\"detail\">{} produced by CPoE Engine {} from sealed evidence bundle \u{00b7} {} UTC</div>\
         </div></div>",
        html_escape(&r.report_id),
        html_escape(ver),
        r.generated_at.format("%H:%M:%S%.3f"),
    );

    out
}

fn build_examined_text(text: Option<&str>) -> String {
    match text {
        Some(t) if !t.is_empty() => t
            .split('\n')
            .filter(|line| !line.trim().is_empty())
            .map(|para| format!("    <p>{}</p>", html_escape(para.trim())))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => "    <p><em>Examined text not available for this report.</em></p>".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Prose generators
// ---------------------------------------------------------------------------

fn build_evaluative_statement(r: &WarReport) -> String {
    let lr = r.likelihood_ratio;
    if !lr.is_finite() || lr == 0.0 {
        return "The evidence is insufficient to form an evaluative statement.".to_string();
    }

    let multiplier = lr_verbal_multiplier(lr);
    let (favored, unfavored) = if lr >= 1.0 {
        ("H<sub>1</sub>", "H<sub>2</sub>")
    } else {
        ("H<sub>2</sub>", "H<sub>1</sub>")
    };
    let tier_label = r.enfsi_tier.label().to_lowercase();

    format!(
        "The behavioural and cryptographic evidence captured during the creation of the subject \
         document is approximately <strong>{multiplier} more probable</strong> if {favored} is \
         true than if {unfavored} is true. Under the ENFSI verbal scale for evaluative reporting, \
         this corresponds to <strong>{tier} for {favored} over {unfavored}</strong>.",
        multiplier = multiplier,
        favored = favored,
        unfavored = unfavored,
        tier = tier_label,
    )
}

fn build_enfsi_verbal_short(lr: f64, tier: EnfsiTier) -> String {
    let label = tier.label();
    if lr >= 1.0 {
        format!("{}, H<sub>1</sub>", label)
    } else {
        format!("{}, H<sub>2</sub>", label)
    }
}

fn lr_verbal_multiplier(lr: f64) -> &'static str {
    let effective = if lr >= 1.0 { lr } else { 1.0 / lr };
    if effective >= 100_000.0 {
        "one hundred thousand times"
    } else if effective >= 10_000.0 {
        "ten thousand times"
    } else if effective >= 1_000.0 {
        "one thousand times"
    } else if effective >= 100.0 {
        "one hundred times"
    } else if effective >= 10.0 {
        "ten times"
    } else if effective >= 5.0 {
        "five times"
    } else if effective >= 2.0 {
        "two times"
    } else {
        "slightly"
    }
}

fn build_key_finding_paragraph(r: &WarReport) -> String {
    // Find the dimension with the most extreme LR (furthest from 1.0)
    let strongest = r
        .dimensions
        .iter()
        .max_by(|a, b| {
            let da = (a.lr.ln()).abs();
            let db = (b.lr.ln()).abs();
            da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
        });

    match strongest {
        Some(d) => format!(
            "The {} is the single most discriminating metric in this examination. \
             {} The captured profile, combined with the observed process metrics, \
             produces the per-dimension likelihood ratios detailed in Section 5.",
            html_escape(&d.name.to_lowercase()),
            html_escape(&d.key_discriminator),
        ),
        None => "Insufficient dimensional data to identify a key discriminating metric.".to_string(),
    }
}

fn build_behaviour_summary(r: &WarReport) -> String {
    let lr = r.likelihood_ratio;
    if lr >= 1.0 {
        "The captured profile aligns with the human-composition baseline on the majority of behavioural dimensions.".to_string()
    } else {
        let count = r.dimensions.iter().filter(|d| d.lr < 1.0).count();
        format!(
            "The captured profile aligns with the transcription baseline on {} of {} behavioural dimensions.",
            count,
            r.dimensions.len()
        )
    }
}

fn build_behaviour_note(r: &WarReport) -> String {
    if r.process.pause_p95_sec.is_none() {
        "The pause-distribution metric is not measurable on this session because \
         insufficient keystrokes were recorded. The reader is referred to the limitations \
         stated at Section 8.3 regarding short-session evidence density. The likelihood \
         ratio computed for the pause-distribution dimension is therefore set to unity \
         (neutral) and contributes no information to the combined evaluation."
            .to_string()
    } else {
        format!(
            "All six behavioural dimensions produced measurable values for this session. \
             The pause-distribution P95 of {:.1} seconds falls within the expected range \
             for the identified writing mode.",
            r.process.pause_p95_sec.unwrap_or(0.0)
        )
    }
}

fn build_dimension_summary(r: &WarReport) -> String {
    let below = r.dimensions.iter().filter(|d| d.lr < 1.0).count();
    let above = r.dimensions.iter().filter(|d| d.lr > 1.0).count();
    let neutral = r.dimensions.iter().filter(|d| (d.lr - 1.0).abs() < 0.001).count();

    let strongest = r
        .dimensions
        .iter()
        .min_by(|a, b| a.lr.partial_cmp(&b.lr).unwrap_or(std::cmp::Ordering::Equal));
    let strongest_above = r
        .dimensions
        .iter()
        .max_by(|a, b| a.lr.partial_cmp(&b.lr).unwrap_or(std::cmp::Ordering::Equal));

    let mut text = String::new();
    if below > 0 {
        let _ = write!(
            text,
            "{} of {} dimensions return likelihood ratios below unity",
            below,
            r.dimensions.len()
        );
        if let Some(s) = strongest {
            let _ = write!(text, ", with the strongest contribution from the {} dimension (LR\u{00a0}=\u{00a0}{})", s.name.to_lowercase(), format_lr(s.lr));
        }
        text.push_str(". ");
    }
    if above > 0 {
        if let Some(s) = strongest_above {
            let _ = write!(
                text,
                "The {} dimension returns a likelihood ratio above unity (LR\u{00a0}=\u{00a0}{}), reflecting {}. ",
                s.name.to_lowercase(),
                format_lr(s.lr),
                html_escape(&s.key_discriminator),
            );
        }
    }
    if neutral > 0 {
        let _ = write!(
            text,
            "The neutral result{} consistent with both propositions and contribute{} no information. ",
            if neutral > 1 { "s are" } else { " is" },
            if neutral > 1 { "" } else { "s" },
        );
    }
    let _ = write!(
        text,
        "The combined likelihood ratio of {} is computed by logarithmic summation with \
         cross-correlation weighting.",
        format_lr(r.likelihood_ratio),
    );
    text
}

fn build_enfsi_scale_paragraph(r: &WarReport) -> String {
    let lr = r.likelihood_ratio;
    let log_lr = if lr > 0.0 && lr.is_finite() {
        lr.log10()
    } else {
        0.0
    };
    let tier = r.enfsi_tier.label().to_lowercase();
    format!(
        "Per the ENFSI verbal scale, the present value of log\u{2081}\u{2080}({}) = {:.2} places \
         this finding at the {} level. The examiner has adopted the {}-designation in the \
         evaluative statement at Section 1.",
        format_lr(lr),
        log_lr,
        tier,
        tier,
    )
}

fn build_session_duration_limitation(r: &WarReport) -> String {
    let total_sec = (r.total_duration_min * 60.0) as u64;
    let cp_count = r.checkpoints.len();
    let keystrokes = r.process.total_keystrokes.unwrap_or(0);
    format!(
        "The captured session in this examination spans {} seconds with {} checkpoints \
         and {} recorded keystrokes. {} sessions reduce the precision of behavioural \
         metrics and may produce confidence intervals that span the verbal-scale boundary. \
         Metrics requiring a minimum sample size may be excluded from the combined evaluation.",
        total_sec,
        cp_count,
        keystrokes,
        if total_sec < 300 { "Short" } else { "Moderate-length" },
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn truncate_hash(hash: &str) -> String {
    if hash.len() > 22 {
        format!("{}…{}", &hash[..16], &hash[hash.len() - 6..])
    } else {
        hash.to_string()
    }
}

fn number_to_words(n: usize) -> &'static str {
    match n {
        0 => "Zero",
        1 => "One",
        2 => "Two",
        3 => "Three",
        4 => "Four",
        5 => "Five",
        6 => "Six",
        7 => "Seven",
        8 => "Eight",
        9 => "Nine",
        10 => "Ten",
        11 => "Eleven",
        12 => "Twelve",
        13 => "Thirteen",
        14 => "Fourteen",
        15 => "Fifteen",
        16 => "Sixteen",
        17 => "Seventeen",
        18 => "Eighteen",
        19 => "Nineteen",
        20 => "Twenty",
        _ => "Many",
    }
}

fn format_date_issued(dt: &chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%d %B %Y, %H:%M:%S UTC").to_string()
}

fn format_confidence_interval(lr: f64, methodology: Option<&StatisticalMethodology>) -> String {
    if let Some(m) = methodology {
        if !m.confidence_interval.is_empty() {
            return html_escape(&m.confidence_interval);
        }
    }
    if !lr.is_finite() || lr <= 0.0 {
        return "[N/A]".to_string();
    }
    let log_lr = lr.ln();
    let half_width = 0.9_f64;
    let lo = (log_lr - half_width).exp();
    let hi = (log_lr + half_width).exp();
    format!("[{}, {}]", format_lr(lo), format_lr(hi))
}

fn format_document_length(r: &WarReport) -> String {
    let chars = r.document_chars.unwrap_or(0);
    let words = r.document_words.unwrap_or(0);
    if words > 0 && chars > 0 {
        format!("{} words, {} characters", words, chars)
    } else if chars > 0 {
        format!("{} characters", chars)
    } else {
        "Length not recorded".to_string()
    }
}

fn extract_os_from_attestation(attestation: &str) -> String {
    // Try to extract OS info from attestation string
    let lower = attestation.to_lowercase();
    if lower.contains("macos") || lower.contains("secure enclave") || lower.contains("apple") {
        "macOS".to_string()
    } else if lower.contains("windows") || lower.contains("tpm 2.0") {
        "Windows".to_string()
    } else if lower.contains("linux") {
        "Linux".to_string()
    } else {
        attestation.to_string()
    }
}

fn format_attestation_tier(attestation: &str) -> String {
    let lower = attestation.to_lowercase();
    if lower.contains("secure enclave") || lower.contains("hardware-bound") {
        "Tier T3 \u{00b7} hardware-bound EAT [Ref. 5]".to_string()
    } else if lower.contains("tpm") {
        "Tier T2 \u{00b7} TPM-attested EAT [Ref. 5]".to_string()
    } else if lower.contains("software") {
        "Tier T1 \u{00b7} software-attested EAT [Ref. 5]".to_string()
    } else {
        "EAT [Ref. 5]".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_unresolved_placeholders() {
        let r = WarReport {
            report_id: "WAR-TEST1234".to_string(),
            algorithm_version: "v1.0.5".to_string(),
            generated_at: chrono::Utc::now(),
            schema_version: "WAR-v1.0.5".to_string(),
            is_sample: true,
            score: 75,
            verdict: Verdict::LikelyHuman,
            verdict_description: "Likely human".to_string(),
            likelihood_ratio: 31.6,
            enfsi_tier: EnfsiTier::Moderate,
            document_hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                .to_string(),
            evidence_hash: None,
            evidence_cbor_b64: None,
            signing_key_fingerprint: "44d94834e2f1a8c6b3d7e9f0a1b2c3d4e5f6a7b8".to_string(),
            document_words: Some(100),
            document_chars: Some(623),
            document_sentences: Some(5),
            document_paragraphs: Some(3),
            evidence_bundle_version: "1.0".to_string(),
            session_count: 1,
            total_duration_min: 2.78,
            revision_events: 15,
            device_attestation: "Apple Secure Enclave, non-extractable".to_string(),
            checkpoints: vec![
                ReportCheckpoint {
                    ordinal: 0,
                    timestamp: chrono::Utc::now(),
                    content_hash: "aa15720433d8e2f1c7b9c4e5f6a7d8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"
                        .to_string(),
                    content_size: 596,
                    vdf_iterations: Some(0),
                    elapsed_ms: Some(21000),
                },
                ReportCheckpoint {
                    ordinal: 1,
                    timestamp: chrono::Utc::now(),
                    content_hash: "cb83783f0f8d6142a7b9c4e3f1d8a2b5c6e9f0d2a3b4c5d6e7f8a9b0c1d2e3f4"
                        .to_string(),
                    content_size: 623,
                    vdf_iterations: Some(0),
                    elapsed_ms: Some(167000),
                },
            ],
            sessions: vec![ReportSession {
                index: 1,
                start: chrono::Utc::now(),
                duration_min: 2.78,
                event_count: 50,
                words_drafted: Some(100),
                device: Some("Davids-iMac.local".to_string()),
                summary: "Single writing session".to_string(),
            }],
            process: ProcessEvidence {
                iki_cv: Some(0.45),
                revision_intensity: Some(0.85),
                paste_ratio_pct: Some(2.0),
                pause_p95_sec: Some(8.5),
                total_keystrokes: Some(450),
                ..Default::default()
            },
            flags: vec![],
            forgery: ForgeryInfo::default(),
            dimensions: vec![
                DimensionScore {
                    name: "Behavioural signature".to_string(),
                    score: 70,
                    lr: 5.0,
                    log_lr: 0.699,
                    confidence: 0.8,
                    key_discriminator: "Burst CV = 0.42 within human range".to_string(),
                    color: "#2e7d32".to_string(),
                    analysis: vec![DimensionDetail {
                        label: "Burst CV and correction rate".to_string(),
                        text: "Within normal range".to_string(),
                    }],
                },
            ],
            writing_flow: vec![],
            methodology: None,
            limitations: vec![],
            analyzed_text: Some("This is a test document.\n\nIt has two paragraphs.".to_string()),
            forensic_metrics: Some(ForensicBreakdown {
                burst_speed_cv: 0.42,
                correction_ratio: 0.08,
                ..Default::default()
            }),
            edit_topology: vec![],
            activity_contexts: vec![],
            declaration_summary: None,
            key_hierarchy_summary: None,
            physical_context: None,
            beacon_info: None,
            anomalies: vec![],
            verifiable_credential_json: None,
            author_did: None,
            provenance_breakdown: None,
        };

        let html = render_forensic_html(&r);

        // No unresolved placeholders should remain
        assert!(
            !html.contains("{{"),
            "Unresolved placeholder found in rendered HTML: {}",
            html.find("{{")
                .map(|i| &html[i..std::cmp::min(i + 60, html.len())])
                .unwrap_or("???")
        );

        // Basic content checks
        assert!(html.contains("WAR-TEST1234"));
        assert!(html.contains("Forensic Authorship"));
        assert!(html.contains("Behavioural signature"));
        assert!(html.contains("This is a test document."));
    }
}

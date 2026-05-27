// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;

pub(in crate::report::html) fn write_embedded_evidence(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    if let Some(ref b64) = r.evidence_cbor_b64 {
        writeln!(
            html,
            r#"<script type="application/vnd.writerslogic.cpoe+cbor">{}</script>"#,
            html_escape(b64),
        )?;
    }
    if let Some(ref vc_json) = r.verifiable_credential_json {
        writeln!(
            html,
            r#"<script type="application/ld+json">{}</script>"#,
            html_escape(vc_json),
        )?;
    }
    Ok(())
}

pub(in crate::report::html) fn write_verifiable_credential(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    let vc_json = match r.verifiable_credential_json {
        Some(ref j) => j,
        None => return Ok(()),
    };

    let vc: serde_json::Value = match serde_json::from_str(vc_json) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("Failed to parse verifiable credential JSON: {e}");
            return Ok(());
        }
    };

    html.push_str(r#"<div class="info-box" style="margin-top:16px">"#);
    html.push_str(r#"<h3 style="margin:0 0 8px">W3C Verifiable Credential 2.0</h3>"#);
    html.push_str(
        "<p style=\"font-size:var(--size-detail);margin:0 0 8px\">\
         This report includes a signed W3C Verifiable Credential that can be \
         independently verified using any VC 2.0 compliant verifier.</p>",
    );

    html.push_str(r#"<table class="data-table" style="margin:8px 0">"#);
    if let Some(issuer) = vc["issuer"].as_str() {
        write!(
            html,
            "<tr><td style=\"font-weight:600;width:180px\">Issuer</td>\
             <td><code>{}</code></td></tr>",
            html_escape(issuer)
        )?;
    }
    if let Some(subject_id) = vc["credentialSubject"]["id"].as_str() {
        write!(
            html,
            "<tr><td style=\"font-weight:600\">Subject (Author DID)</td>\
             <td><code>{}</code></td></tr>",
            html_escape(subject_id)
        )?;
    }
    if let Some(valid_from) = vc["validFrom"].as_str() {
        write!(
            html,
            "<tr><td style=\"font-weight:600\">Valid From</td>\
             <td>{}</td></tr>",
            html_escape(valid_from)
        )?;
    }
    if let Some(status) = vc["credentialSubject"]["processAttestation"]["status"].as_str() {
        let (display_label, badge_color) = match status {
            "affirming" => ("Verified", "#3d7a4a"),
            "warning" => ("Insufficient Evidence", "#b45309"),
            "contraindicated" => ("Not Verified", "#b71c1c"),
            "none" => ("Not Evaluated", "#666"),
            _ => (status, "#666"),
        };
        write!(
            html,
            "<tr><td style=\"font-weight:600\">Attestation Status</td>\
             <td><span style=\"background:{};color:#fff;padding:2px 8px;\
             border-radius:2px;font-size:10px;font-weight:700;\
             text-transform:uppercase\">{}</span></td></tr>",
            badge_color,
            html_escape(display_label)
        )?;
    }
    if let Some(tier) = vc["credentialSubject"]["processAttestation"]["attestationTier"].as_str() {
        write!(
            html,
            "<tr><td style=\"font-weight:600\">Attestation Tier</td>\
             <td>{}</td></tr>",
            html_escape(tier)
        )?;
    }
    if let Some(dur) = vc["credentialSubject"]["processAttestation"]["chainDuration"].as_str() {
        write!(
            html,
            "<tr><td style=\"font-weight:600\">Chain Duration</td>\
             <td>{}</td></tr>",
            html_escape(dur)
        )?;
    }
    if let Some(doc_ref) = vc["credentialSubject"]["processAttestation"]["documentRef"].as_str() {
        let short = if doc_ref.len() > 16 {
            let start = doc_ref.get(..8).unwrap_or(doc_ref);
            let end = doc_ref.get(doc_ref.len().saturating_sub(8)..).unwrap_or("");
            format!("{start}...{end}")
        } else {
            doc_ref.to_string()
        };
        write!(
            html,
            "<tr><td style=\"font-weight:600\">Document Reference</td>\
             <td><code>{}</code></td></tr>",
            html_escape(&short)
        )?;
    }

    if let Some(proof) = vc.get("proof") {
        if let Some(suite) = proof["cryptosuite"].as_str() {
            write!(
                html,
                "<tr><td style=\"font-weight:600\">Proof Type</td>\
                 <td>DataIntegrityProof ({}) \
                 <span style=\"color:#3d7a4a;font-weight:700\">&#x2713; Signed</span></td></tr>",
                html_escape(suite)
            )?;
        }
        if let Some(vm) = proof["verificationMethod"].as_str() {
            write!(
                html,
                "<tr><td style=\"font-weight:600\">Verification Method</td>\
                 <td><code style=\"font-size:10px\">{}</code></td></tr>",
                html_escape(vm)
            )?;
        }
    }
    html.push_str("</table>");

    if let Some(tv) = vc["credentialSubject"]["processAttestation"]["trustVector"].as_object() {
        html.push_str(r#"<h4 style="margin:12px 0 6px;font-size:12px">AR4SI Trust Vector</h4>"#);
        html.push_str(r#"<div class="metric-grid">"#);
        for (key, val) in tv.iter().take(100) {
            let v = val.as_i64().unwrap_or(0);
            let (label, color) = match v as i8 {
                2 => ("Verified", "#3d7a4a"),
                32 => ("Insufficient Evidence", "#b45309"),
                96 => ("Not Verified", "#b71c1c"),
                _ => ("Not Evaluated", "#999"),
            };
            let mut display_key = String::with_capacity(key.len());
            let mut capitalize_next = true;
            for ch in key.chars() {
                if ch == '_' || ch == ' ' {
                    display_key.push(' ');
                    capitalize_next = true;
                } else if capitalize_next {
                    display_key.extend(ch.to_uppercase());
                    capitalize_next = false;
                } else {
                    display_key.push(ch);
                }
            }
            write!(
                html,
                r#"<div class="metric-card"><div class="metric-label">{}</div><div class="metric-value" style="color:{}">{}</div></div>"#,
                html_escape(&display_key),
                color,
                label,
            )?;
        }
        html.push_str("</div>");
    }

    html.push_str(
        r#"<details style="margin-top:10px"><summary style="cursor:pointer;font-weight:600;font-size:12px">Raw Credential JSON-LD</summary>"#,
    );
    write!(
        html,
        r#"<pre style="font-size:10px;max-height:300px;overflow:auto;background:var(--bg-card);padding:10px;border:1px solid var(--border);margin-top:6px">{}</pre>"#,
        html_escape(vc_json),
    )?;
    html.push_str("</details></div>");
    Ok(())
}

pub(in crate::report::html) fn write_forensic_breakdown(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    let fm = match r.forensic_metrics {
        Some(ref m) => m,
        None => return Ok(()),
    };

    write!(html, r#"<h3>Forensic Breakdown</h3>"#)?;

    let badge_color = match fm.writing_mode.as_str() {
        "cognitive" => "#3d7a4a",
        "transcriptive" => "#b45309",
        _ => "#2c5282",
    };
    write!(
        html,
        r#"<p><strong>Writing Mode:</strong> <span style="display:inline-block;background:{color};color:#fff;font-family:var(--sans);font-size:10px;font-weight:700;padding:2px 8px;border-radius:2px;letter-spacing:0.5px;text-transform:uppercase">{mode}</span> <span style="color:var(--text-muted);font-size:12px">(confidence: {conf:.0}%)</span></p>"#,
        color = badge_color,
        mode = html_escape(&fm.writing_mode),
        conf = finite_or(fm.writing_mode_confidence * 100.0, 0.0),
    )?;

    let cog_pct = finite_or(fm.cognitive_score * 100.0, 0.0).clamp(0.0, 100.0);
    let cog_color = if cog_pct >= 60.0 {
        "#3d7a4a"
    } else if cog_pct >= 30.0 {
        "#b45309"
    } else {
        "#b71c1c"
    };
    write!(
        html,
        r#"<p style="font-size:12px;margin-bottom:2px"><strong>Cognitive Score:</strong> {cog:.0}/100</p>
<div class="writing-gauge"><div class="writing-gauge-fill" style="width:{cog:.0}%;background:{color}"></div></div>"#,
        cog = cog_pct,
        color = cog_color,
    )?;

    write!(html, r#"<div class="metric-grid">"#)?;
    write!(
        html,
        r#"<div class="metric-card"><div class="metric-label">Mean IKI</div><div class="metric-value">{:.0} ms</div></div>"#,
        finite_or(fm.mean_iki_ms, 0.0),
    )?;
    write!(
        html,
        r#"<div class="metric-card"><div class="metric-label">Coefficient of Variation</div><div class="metric-value">{:.3}</div></div>"#,
        finite_or(fm.coefficient_of_variation, 0.0),
    )?;
    write!(
        html,
        r#"<div class="metric-card"><div class="metric-label">Burst Count</div><div class="metric-value">{}</div></div>"#,
        fm.burst_count,
    )?;
    write!(
        html,
        r#"<div class="metric-card"><div class="metric-label">Pause Count</div><div class="metric-value">{}</div></div>"#,
        fm.pause_count,
    )?;
    write!(
        html,
        r#"<div class="metric-card"><div class="metric-label">Correction Ratio</div><div class="metric-value">{:.3}</div></div>"#,
        finite_or(fm.correction_ratio, 0.0),
    )?;
    write!(
        html,
        r#"<div class="metric-card"><div class="metric-label">Burst Speed CV</div><div class="metric-value">{:.3}</div></div>"#,
        finite_or(fm.burst_speed_cv, 0.0),
    )?;
    if let Some(d) = fm.detour_ratio {
        write!(
            html,
            r#"<div class="metric-card"><div class="metric-label">Detour Ratio</div><div class="metric-value">{:.3}</div></div>"#,
            finite_or(d, 0.0),
        )?;
    }
    if let Some(l) = fm.leading_edge_divergence {
        write!(
            html,
            r#"<div class="metric-card"><div class="metric-label">Leading-Edge Div.</div><div class="metric-value">{:.1}%</div></div>"#,
            finite_or(l * 100.0, 0.0),
        )?;
    }
    if let Some(e) = fm.insertion_point_entropy {
        write!(
            html,
            r#"<div class="metric-card"><div class="metric-label">Insertion Entropy</div><div class="metric-value">{:.2} bits</div></div>"#,
            finite_or(e, 0.0),
        )?;
    }
    write!(html, r#"</div>"#)?;

    if let Some(h) = fm.hurst_exponent.filter(|v| v.is_finite()) {
        let interp = if h < 0.5 {
            "anti-persistent (mean-reverting)"
        } else if h < 0.6 {
            "approximately random"
        } else if h < 0.8 {
            "long-range dependent (human-like)"
        } else {
            "highly persistent (deterministic)"
        };
        write!(
            html,
            r#"<p style="font-size:12.5px;margin:8px 0"><strong>Hurst Exponent:</strong> {:.3} ({interp})</p>"#,
            h,
        )?;
    }

    let d = &fm.pause_depth;
    let total = d[0] + d[1] + d[2];
    if total > 0.0 {
        let s_pct = d[0] / total * 100.0;
        let p_pct = d[1] / total * 100.0;
        let t_pct = d[2] / total * 100.0;
        write!(
            html,
            r#"<p style="font-size:12.5px;margin:8px 0 2px"><strong>Pause Depth Distribution:</strong></p>
<div class="pause-depth-bar">
<div class="pause-depth-seg" style="width:{s:.1}%;background:#b45309" title="Sentence: {s:.1}%"></div>
<div class="pause-depth-seg" style="width:{p:.1}%;background:#2c5282" title="Paragraph: {p:.1}%"></div>
<div class="pause-depth-seg" style="width:{t:.1}%;background:#5b3c8b" title="Deep thought: {t:.1}%"></div>
</div>
<p style="font-size:11px;color:var(--text-muted)"><span style="color:#b45309">Sentence {s:.0}%</span> | <span style="color:#2c5282">Paragraph {p:.0}%</span> | <span style="color:#5b3c8b">Deep thought {t:.0}%</span></p>"#,
            s = s_pct,
            p = p_pct,
            t = t_pct,
        )?;
    }

    let risk_color = match fm.risk_level.as_str() {
        "Low" => "#3d7a4a",
        "Medium" => "#b45309",
        _ => "#b71c1c",
    };
    write!(
        html,
        r#"<p style="font-size:12.5px;margin:8px 0"><strong>Assessment:</strong> {score:.0}/100 | <strong>Risk:</strong> <span style="color:{color};font-weight:600">{risk}</span> | <strong>Revision Cycles:</strong> {rev}</p>
<p style="font-size:12.5px;margin:4px 0"><strong>Throughput:</strong> {mean:.1} mean BPS, {max:.1} max BPS</p>"#,
        score = finite_or(fm.assessment_score * 100.0, 0.0),
        color = risk_color,
        risk = html_escape(&fm.risk_level),
        rev = fm.revision_cycle_count,
        mean = finite_or(fm.mean_bps, 0.0),
        max = finite_or(fm.max_bps, 0.0),
    )
}

pub(in crate::report::html) fn write_edit_topology(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    if r.edit_topology.is_empty() {
        return Ok(());
    }

    write!(html, r#"<h3>Edit Topology</h3>"#)?;

    let mut bins_ins = [0i64; 20];
    let mut bins_del = [0i64; 20];
    for region in &r.edit_topology {
        let start_bin = ((region.start_pct / 100.0 * 20.0).floor() as usize).min(19);
        let end_bin = ((region.end_pct / 100.0 * 20.0).ceil() as usize).min(20);
        for b in start_bin..end_bin {
            if region.delta_sign > 0 {
                bins_ins[b] += region.byte_count.unsigned_abs() as i64;
            } else if region.delta_sign < 0 {
                bins_del[b] += region.byte_count.unsigned_abs() as i64;
            }
        }
    }

    let max_val = bins_ins
        .iter()
        .chain(bins_del.iter())
        .copied()
        .max()
        .unwrap_or(1)
        .max(1);

    write!(html, r#"<div class="topology-bar">"#)?;
    for i in 0..20 {
        let ins = bins_ins[i];
        let del = bins_del[i];
        let dominant = if ins >= del { ins } else { del };
        let opacity = (dominant as f64 / max_val as f64 * 0.9 + 0.1).min(1.0);
        let color = if ins >= del { "#3d7a4a" } else { "#b71c1c" };
        write!(
            html,
            r#"<div class="topology-segment" style="flex:1;background:{color};opacity:{op:.2}"></div>"#,
            color = color,
            op = opacity,
        )?;
    }
    write!(html, "</div>")?;
    write!(
        html,
        r#"<p style="font-size:11px;color:var(--text-muted)">{} edit regions across the document. <span style="color:#3d7a4a">Green = insertions</span>, <span style="color:#b71c1c">red = deletions</span>.</p>"#,
        r.edit_topology.len(),
    )
}

pub(in crate::report::html) fn write_activity_contexts(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    if r.activity_contexts.is_empty() {
        return Ok(());
    }

    write!(html, r#"<h3>Activity Contexts</h3>"#)?;

    let total_min: f64 = r.activity_contexts.iter().map(|a| a.duration_min).sum();
    if total_min <= 0.0 {
        return Ok(());
    }

    write!(html, r#"<div class="context-timeline">"#)?;
    for ctx in &r.activity_contexts {
        let pct = ctx.duration_min / total_min * 100.0;
        let color = match ctx.period_type.as_str() {
            "focused" => "#3d7a4a",
            "break" => "#999",
            "research" => "#2c5282",
            "revision" => "#e65100",
            "assisted" => "#7b1fa2",
            "external" => "#b71c1c",
            "idle" => "#ddd",
            _ => "#6b6b6b",
        };
        write!(
            html,
            r#"<div class="context-segment" style="flex:{pct:.2};background:{color}"></div>"#,
        )?;
    }
    write!(html, "</div>")?;

    let types = [
        ("focused", "#3d7a4a"),
        ("break", "#999"),
        ("research", "#2c5282"),
        ("revision", "#e65100"),
        ("assisted", "#7b1fa2"),
        ("external", "#b71c1c"),
        ("idle", "#ddd"),
    ];
    write!(html, r#"<div class="context-legend">"#)?;
    for (label, color) in &types {
        let present = r.activity_contexts.iter().any(|a| a.period_type == *label);
        if present {
            write!(
                html,
                r#"<span class="context-legend-item"><span class="context-legend-swatch" style="background:{color}"></span>{label}</span>"#,
            )?;
        }
    }
    write!(html, "</div>")?;

    write!(
        html,
        r#"<table class="data" style="margin-top:10px"><thead><tr><th>Type</th><th>Duration</th><th>Percentage</th></tr></thead><tbody>"#,
    )?;
    let mut agg: Vec<(String, f64)> = Vec::new();
    for ctx in &r.activity_contexts {
        if let Some(entry) = agg.iter_mut().find(|(t, _)| *t == ctx.period_type) {
            entry.1 += ctx.duration_min;
        } else {
            agg.push((ctx.period_type.clone(), ctx.duration_min));
        }
    }
    for (ptype, dur) in &agg {
        let pct = dur / total_min * 100.0;
        write!(
            html,
            "<tr><td>{}</td><td>{:.1} min</td><td>{:.1}%</td></tr>",
            html_escape(ptype),
            dur,
            pct,
        )?;
    }
    writeln!(html, "</tbody></table>")
}

pub(in crate::report::html) fn write_declaration_summary(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    let decl = match r.declaration_summary {
        Some(ref d) => d,
        None => return Ok(()),
    };

    write!(html, r#"<h3>Author Declaration</h3>"#)?;

    write!(
        html,
        r#"<div class="declaration-quote">{}</div>"#,
        html_escape(&decl.statement),
    )?;

    write!(
        html,
        r#"<p style="font-size:12.5px"><strong>Document Title:</strong> {}</p>"#,
        html_escape(&decl.title),
    )?;

    if !decl.ai_tools.is_empty() {
        write!(
            html,
            r#"<p style="font-size:12.5px"><strong>AI Tools Declared:</strong> "#
        )?;
        for (i, tool) in decl.ai_tools.iter().enumerate() {
            if i > 0 {
                html.push(' ');
            }
            write!(
                html,
                r#"<span style="display:inline-block;background:var(--navy-muted);font-family:var(--sans);font-size:10px;padding:2px 6px;border-radius:2px">{}</span>"#,
                html_escape(tool),
            )?;
        }
        write!(html, "</p>")?;
    }

    if !decl.input_modalities.is_empty() {
        let modalities: Vec<String> = decl
            .input_modalities
            .iter()
            .map(|m| html_escape(m))
            .collect();
        write!(
            html,
            r#"<p style="font-size:12.5px"><strong>Input Modalities:</strong> {}</p>"#,
            modalities.join(", "),
        )?;
    }

    let sig_icon = if decl.signature_valid {
        r#"<span style="color:#3d7a4a">&#10003; Valid</span>"#
    } else {
        r#"<span style="color:#b71c1c">&#10007; Invalid</span>"#
    };
    write!(
        html,
        r#"<p style="font-size:12.5px"><strong>Collaborators:</strong> {} | <strong>Signature:</strong> {} | <strong>Declared:</strong> {}</p>"#,
        decl.collaborator_count,
        sig_icon,
        decl.created_at.format("%B %-d, %Y %H:%M UTC"),
    )
}

pub(in crate::report::html) fn write_key_hierarchy(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    let kh = match r.key_hierarchy_summary {
        Some(ref k) => k,
        None => return Ok(()),
    };

    write!(html, r#"<h3>Key Hierarchy</h3>"#)?;
    write!(html, r#"<div class="info-box"><table>"#)?;

    let master_short = if kh.master_fingerprint.len() > 16 {
        format!(
            "{}...{}",
            &kh.master_fingerprint[..8],
            &kh.master_fingerprint[kh.master_fingerprint.len().saturating_sub(8)..],
        )
    } else {
        kh.master_fingerprint.clone()
    };
    row(html, "Master Fingerprint", &master_short)?;

    let dev_short = if kh.device_id.len() > 16 {
        format!(
            "{}...{}",
            &kh.device_id[..8],
            &kh.device_id[kh.device_id.len().saturating_sub(8)..],
        )
    } else {
        kh.device_id.clone()
    };
    row(html, "Device ID", &dev_short)?;

    let sess_short = if kh.session_id.len() > 16 {
        format!(
            "{}...{}",
            &kh.session_id[..8],
            &kh.session_id[kh.session_id.len().saturating_sub(8)..],
        )
    } else {
        kh.session_id.clone()
    };
    row(html, "Session ID", &sess_short)?;
    row(html, "Ratchet Count", &kh.ratchet_count.to_string())?;
    row(
        html,
        "Checkpoint Signatures",
        &kh.checkpoint_signatures.to_string(),
    )?;
    row(
        html,
        "Session Started",
        &kh.session_started
            .format("%B %-d, %Y %H:%M UTC")
            .to_string(),
    )?;

    writeln!(html, "</table></div>")
}

pub(in crate::report::html) fn write_hardware_attestation(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    if r.physical_context.is_none() && r.beacon_info.is_none() {
        return Ok(());
    }

    write!(html, r#"<h3>Hardware Attestation</h3>"#)?;

    if let Some(ref pc) = r.physical_context {
        write!(html, r#"<div class="info-box"><table>"#)?;
        row(
            html,
            "Clock Skew",
            &format!("{} ns", format_number(pc.clock_skew_ns)),
        )?;
        row(html, "Thermal Proxy", &pc.thermal_proxy.to_string())?;
        let puf_short = if pc.silicon_puf_hash.len() > 16 {
            format!(
                "{}...{}",
                &pc.silicon_puf_hash[..8],
                &pc.silicon_puf_hash[pc.silicon_puf_hash.len().saturating_sub(8)..],
            )
        } else {
            pc.silicon_puf_hash.clone()
        };
        row(html, "Silicon PUF Hash", &puf_short)?;
        row(
            html,
            "IO Latency",
            &format!("{} ns", format_number(pc.io_latency_ns)),
        )?;
        writeln!(html, "</table></div>")?;
    }

    if let Some(ref bi) = r.beacon_info {
        write!(
            html,
            r#"<p style="font-size:12.5px;margin:8px 0"><strong>Temporal Beacons:</strong></p>"#,
        )?;
        write!(html, r#"<div class="info-box"><table>"#)?;
        row(html, "drand Round", &format_number(bi.drand_round))?;
        row(
            html,
            "NIST Pulse Index",
            &format_number(bi.nist_pulse_index),
        )?;
        row(html, "Fetched At", &html_escape(&bi.fetched_at))?;
        if let Some(ref kid) = bi.wp_key_id {
            row(html, "WP Key ID", &html_escape(kid))?;
        }
        writeln!(html, "</table></div>")?;
    }

    Ok(())
}

pub(in crate::report::html) fn write_anomalies_detail(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    if r.anomalies.is_empty() {
        return Ok(());
    }

    write!(html, r#"<h3>Anomaly Details</h3>"#)?;
    write!(
        html,
        r#"<table class="data"><thead><tr><th>Severity</th><th>Type</th><th>Description</th></tr></thead><tbody>"#,
    )?;
    for a in &r.anomalies {
        let sev_class = match a.severity.as_str() {
            "Alert" => "severity-alert",
            "Warning" => "severity-warning",
            _ => "severity-info",
        };
        write!(
            html,
            r#"<tr><td class="{cls}">{sev}</td><td>{typ}</td><td>{desc}</td></tr>"#,
            cls = sev_class,
            sev = html_escape(&a.severity),
            typ = html_escape(&a.anomaly_type),
            desc = html_escape(&a.description),
        )?;
    }
    writeln!(html, "</tbody></table>")
}

pub(in crate::report::html) fn write_footer(html: &mut String, r: &WarReport) -> fmt::Result {
    write!(
        html,
        r#"<div class="report-footer">
<p class="certification">This report was generated by an automated forensic examination system using standardized, reproducible methodology. Applying the same algorithm version to the same evidence will produce identical results. This report documents process analysis only; it does not constitute legal advice, and the determination herein should be evaluated alongside all other available evidence by the trier of fact.</p>
<p>Forensic Authorship Examination Report &ensp;|&ensp; {id} &ensp;|&ensp; Algorithm {alg} &ensp;|&ensp; Schema {schema}<br>
&copy; {year} WritersLogic, LLC. All rights reserved. CPoE Protocol per draft-condrey-rats-pop.</p>
</div>
"#,
        id = html_escape(&r.report_id),
        alg = html_escape(&r.algorithm_version),
        schema = html_escape(&r.schema_version),
        year = r.generated_at.format("%Y"),
    )
}

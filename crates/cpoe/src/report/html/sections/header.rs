// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;

pub(in crate::report::html) fn write_header(html: &mut String, r: &WarReport) -> fmt::Result {
    let sample = if r.is_sample {
        r#"<span class="sample-badge">SAMPLE</span>"#
    } else {
        ""
    };
    write!(
        html,
        r#"<h1>{title}{sample}</h1>
<p class="subtitle">
  Report {id} &ensp;|&ensp; Algorithm {alg} &ensp;|&ensp;
  Issued {ts} &ensp;|&ensp; Schema {schema}
</p>
"#,
        title = REPORT_TITLE,
        id = html_escape(&r.report_id),
        alg = html_escape(&r.algorithm_version),
        ts = r.generated_at.format("%B %-d, %Y at %H:%M:%S UTC"),
        schema = html_escape(&r.schema_version),
    )
}

pub(in crate::report::html) fn write_examination_metadata(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    let doc_hash_short = if r.document_hash.len() > 16 {
        format!(
            "{}...{}",
            &r.document_hash[..8],
            &r.document_hash[r.document_hash.len().saturating_sub(8)..],
        )
    } else {
        r.document_hash.clone()
    };
    write!(
        html,
        r#"<div class="exam-meta">
<div><span class="meta-label">Report Reference</span><span class="meta-value">{id}</span></div>
<div><span class="meta-label">Date of Report</span><span class="meta-value">{date}</span></div>
<div><span class="meta-label">Examination System</span><span class="meta-value">CPoE Forensic Engine {alg}</span></div>
<div><span class="meta-label">Document Fingerprint</span><span class="meta-value"><code>{hash}</code></span></div>
<div><span class="meta-label">Evidence Sessions</span><span class="meta-value">{sessions} session{s_plural}, {dur:.0} min total</span></div>
<div><span class="meta-label">Reporting Standard</span><span class="meta-value">ENFSI Guideline for Evaluative Reporting (2015)</span></div>
</div>
"#,
        id = html_escape(&r.report_id),
        date = r.generated_at.format("%B %-d, %Y"),
        alg = html_escape(&r.algorithm_version),
        hash = html_escape(&doc_hash_short),
        sessions = r.session_count,
        s_plural = if r.session_count == 1 { "" } else { "s" },
        dur = r.total_duration_min,
    )
}

pub(in crate::report::html) fn write_executive_summary(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    let strength = match r.enfsi_tier {
        EnfsiTier::VeryStrong => "very strongly supports",
        EnfsiTier::Strong => "strongly supports",
        EnfsiTier::ModeratelyStrong => "moderately supports",
        EnfsiTier::Moderate => "provides moderate support for",
        EnfsiTier::Weak => "provides limited support for",
        EnfsiTier::Against => "does not support",
        EnfsiTier::Inconclusive => "is inconclusive regarding",
    };

    let human_flags = r
        .flags
        .iter()
        .filter(|f| f.signal == FlagSignal::Human)
        .count();
    let synthetic_flags = r
        .flags
        .iter()
        .filter(|f| f.signal == FlagSignal::Synthetic)
        .count();

    let duration_desc = if r.total_duration_min < 1.0 {
        "less than one minute".to_string()
    } else if r.total_duration_min < 60.0 {
        format!("approximately {:.0} minutes", r.total_duration_min)
    } else {
        let hours = r.total_duration_min / 60.0;
        format!("approximately {:.1} hours", hours)
    };

    let keystrokes_desc = r
        .process
        .total_keystrokes
        .map(|k| format!(", with {} keystrokes captured", format_number(k)))
        .unwrap_or_default();

    let checkpoint_desc = if r.checkpoints.is_empty() {
        String::new()
    } else {
        format!(
            " {} cryptographic checkpoints were recorded and verified.",
            r.checkpoints.len()
        )
    };

    let flag_desc = if synthetic_flags > 0 {
        format!(
            " The analysis identified {} behavioral indicator{} consistent with human authorship \
             and {} indicator{} of potential synthetic generation.",
            human_flags,
            if human_flags == 1 { "" } else { "s" },
            synthetic_flags,
            if synthetic_flags == 1 { "" } else { "s" },
        )
    } else if human_flags > 0 {
        format!(
            " The analysis identified {} behavioral indicator{} consistent with human authorship \
             and no indicators of synthetic generation.",
            human_flags,
            if human_flags == 1 { "" } else { "s" },
        )
    } else {
        String::new()
    };

    write!(
        html,
        r#"<div class="executive-summary">
<p>Based on forensic examination of the submitted document, the evidence {strength} the proposition that the text was composed through a human writing process. The document was produced across {sessions} writing session{s_plural} spanning {duration}{keystrokes}.{checkpoints}{flags}</p>
</div>
"#,
        sessions = r.session_count,
        s_plural = if r.session_count == 1 { "" } else { "s" },
        duration = duration_desc,
        keystrokes = keystrokes_desc,
        checkpoints = checkpoint_desc,
        flags = flag_desc,
    )
}

// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::helpers::html_escape;
use crate::report::types::*;
use std::fmt::{self, Write};

const CSS_BASE: &str = include_str!("templates/base.css");
const CSS_COMPONENTS: &str = include_str!("templates/components.css");
const CSS_LAYOUT: &str = include_str!("templates/layout.css");

fn build_jsonld(r: &WarReport) -> String {
    let report_id = &r.report_id;
    let doc_hash = &r.document_hash;
    let schema = &r.schema_version;
    let alg = &r.algorithm_version;
    let key_fp = &r.signing_key_fingerprint;
    let ts_iso = r.generated_at.to_rfc3339();
    let cp_count = r.checkpoints.len();
    let session_count = r.session_count;

    let lr_value: serde_json::Value = if r.likelihood_ratio.is_finite() {
        serde_json::json!(r.likelihood_ratio)
    } else {
        serde_json::Value::Null
    };
    let log_lr_value: serde_json::Value =
        if r.likelihood_ratio.is_finite() && r.likelihood_ratio > 0.0 {
            serde_json::json!(r.likelihood_ratio.log10())
        } else {
            serde_json::Value::Null
        };

    let graph = serde_json::json!({
        "@context": {
            "prov": "http://www.w3.org/ns/prov#",
            "cpoe": "https://writerslogic.com/ns/cpoe#",
            "xsd": "http://www.w3.org/2001/XMLSchema#"
        },
        "@graph": [
            {
                "@id": format!("urn:cpoe:report:{report_id}"),
                "@type": ["cpoe:AuthorshipReport", "prov:Entity"],
                "cpoe:reportId": report_id,
                "cpoe:schemaVersion": schema,
                "cpoe:engineVersion": alg,
                "cpoe:protocolVersion": "cpoe-v1",
                "cpoe:assessmentScore": r.score,
                "cpoe:likelihoodRatio": lr_value,
                "cpoe:logLikelihoodRatio": log_lr_value,
                "cpoe:enfsiTier": r.enfsi_tier.label(),
                "cpoe:checkpointCount": cp_count,
                "cpoe:sessionCount": session_count,
                "cpoe:evidenceType": "behavioral-process-evidence",
                "cpoe:assertionMethod": "automated",
                "prov:generatedAtTime": {
                    "@type": "xsd:dateTime",
                    "@value": ts_iso
                },
                "prov:wasGeneratedBy": {
                    "@id": format!("urn:cpoe:examination:{report_id}")
                },
                "prov:qualifiedDerivation": {
                    "@type": "prov:Derivation",
                    "prov:entity": { "@id": format!("urn:cpoe:evidence:sha256:{doc_hash}") },
                    "prov:hadActivity": { "@id": format!("urn:cpoe:examination:{report_id}") }
                },
                "prov:wasDerivedFrom": {
                    "@id": format!("urn:cpoe:evidence:sha256:{doc_hash}")
                }
            },
            {
                "@id": format!("urn:cpoe:examination:{report_id}"),
                "@type": ["cpoe:ForensicExamination", "prov:Activity"],
                "prov:wasAssociatedWith": {
                    "@id": format!("urn:cpoe:engine:{alg}")
                },
                "prov:used": {
                    "@id": format!("urn:cpoe:evidence:sha256:{doc_hash}")
                },
                "prov:generated": {
                    "@id": format!("urn:cpoe:report:{report_id}")
                }
            },
            {
                "@id": format!("urn:cpoe:engine:{alg}"),
                "@type": ["cpoe:ForensicEngine", "prov:SoftwareAgent"],
                "cpoe:engineName": "CPoE Forensic Engine",
                "cpoe:engineVersion": alg,
                "cpoe:protocolSpec": "draft-condrey-rats-pop"
            },
            {
                "@id": format!("urn:cpoe:evidence:sha256:{doc_hash}"),
                "@type": ["cpoe:EvidencePacket", "prov:Entity"],
                "cpoe:documentHash": doc_hash,
                "cpoe:documentHashAlgorithm": "SHA-256",
                "cpoe:signingKeyFingerprint": key_fp,
                "cpoe:checkpointCount": cp_count,
                "cpoe:sessionCount": session_count
            },
            {
                "@id": format!("urn:cpoe:document:sha256:{doc_hash}"),
                "@type": ["cpoe:DocumentArtifact", "prov:Entity"],
                "cpoe:sha256": doc_hash,
                "cpoe:documentHashAlgorithm": "SHA-256"
            }
        ]
    });

    serde_json::to_string_pretty(&graph)
        .unwrap_or_else(|_| "{}".to_string())
        .replace("</", "<\\/") // Prevent </script> injection in JSON-LD block
}

/// Write the `<!DOCTYPE>` through opening `<div class="report">`, including
/// `<style>`, cryptographic `<meta>` anchors, PROV-O/CPoE JSON-LD, and CSS.
pub(super) fn write_head(html: &mut String, r: &WarReport) -> fmt::Result {
    let report_id = html_escape(&r.report_id);
    let doc_hash = html_escape(&r.document_hash);
    let evidence_hash = r
        .evidence_hash
        .as_deref()
        .map(html_escape)
        .unwrap_or_default();
    let schema = html_escape(&r.schema_version);
    let alg = html_escape(&r.algorithm_version);
    let key_fp = html_escape(&r.signing_key_fingerprint);
    let ts_iso = r.generated_at.to_rfc3339();
    let score = r.score;
    let lr_log10 = if r.likelihood_ratio.is_finite() && r.likelihood_ratio > 0.0 {
        r.likelihood_ratio.log10()
    } else {
        0.0
    };
    let enfsi = r.enfsi_tier.label();
    let cp_count = r.checkpoints.len();

    let jsonld = build_jsonld(r);

    write!(
        html,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Forensic Authorship Examination Report — {report_id}</title>

<!-- Cryptographic anchor tags (machine-readable, for automated verification) -->
<meta name="cpoe-report-id" content="{report_id}">
<meta name="cpoe-schema" content="{schema}">
<meta name="cpoe-document-hash" content="{doc_hash}">
<meta name="cpoe-document-hash-algorithm" content="SHA-256">
<meta name="cpoe-evidence-hash" content="{evidence_hash}">
<meta name="cpoe-evidence-hash-algorithm" content="SHA-256">
<meta name="cpoe-engine-version" content="{alg}">
<meta name="cpoe-generated" content="{ts_iso}">
<meta name="cpoe-key-fingerprint" content="{key_fp}">
<meta name="cpoe-score" content="{score}">
<meta name="cpoe-log-lr" content="{lr_log10:.4}">
<meta name="cpoe-enfsi-tier" content="{enfsi}">
<meta name="cpoe-checkpoints" content="{cp_count}">
<meta name="cpoe-report-version" content="1.0">
<meta name="cpoe-protocol-version" content="cpoe-v1">
<meta name="cpoe-media-type" content="application/c2pa">

<!-- W3C PROV-O + CPoE domain ontology (canonical machine-readable provenance) -->
<script type="application/ld+json">
{jsonld}
</script>

<style>
{css_base}
{css_components}
{css_layout}
</style>

<!-- Integrity: rendered fields digest (verifier compares visible values against signed payload) -->
<meta name="cpoe-signature-algorithm" content="Ed25519">
<meta name="cpoe-signing-key-fingerprint" content="{key_fp}">
</head>
<body class="cpoe-report">
<div class="report">
"#,
        css_base = CSS_BASE,
        css_components = CSS_COMPONENTS,
        css_layout = CSS_LAYOUT,
    )
}

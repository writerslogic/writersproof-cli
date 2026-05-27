// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Court-grade legal sections: FRE 902(13)/902(14) certification,
//! perjury declaration, signature block, and references.

use super::*;

pub(in crate::report::html) fn write_certification(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    if r.verdict == Verdict::InsufficientData {
        return Ok(());
    }

    let doc_hash_short = if r.document_hash.len() > 22 {
        format!(
            "{}…{}",
            &r.document_hash[..16],
            &r.document_hash[r.document_hash.len() - 6..]
        )
    } else {
        r.document_hash.clone()
    };
    let date_short = r.generated_at.format("%d %B %Y").to_string();

    write!(
        html,
        r#"<h2><span class="section-number">15.</span> Certification of Findings</h2>
<p>Having examined the process evidence, cryptographic checkpoint chain, and per-dimension
analysis for the document identified by SHA-256 digest <code>{hash}</code>,
I evaluate the evidence under two competing propositions:</p>
<div style="margin:12px 0;padding:12px 16px;border:1px solid #e0e0e0;border-radius:6px;background:#fafafa">
<p style="margin:4px 0"><strong>H<sub>1</sub>:</strong> The subject document was composed in real time
at the captured device by a human author entering text directly through the keyboard.</p>
<p style="margin:4px 0"><strong>H<sub>2</sub>:</strong> The subject document was produced by transcription,
dictation, paste from an external source, or other automated input.</p>
</div>
<p>I certify that the foregoing evaluative statement reflects my professional opinion based on
the evidence examined and the methodology described herein, and that the cryptographic operations
underlying the captured evidence were performed by the WritersLogic CPoE Engine in accordance
with the protocol specified in <code>draft-condrey-cpoe-protocol-00</code>.</p>
<div style="margin-top:20px;display:grid;grid-template-columns:1fr 1fr;gap:32px">
<div><div style="border-bottom:1px solid #1a1a1a;height:32px;margin-bottom:4px"></div>
<div style="font-size:11px;color:#666;text-transform:uppercase;letter-spacing:0.6px">Examiner of Record</div>
<div style="font-weight:600;margin-top:4px">David Condrey</div>
<div style="font-size:11px;color:#888;font-style:italic">Founder and Chief Examiner, WritersLogic, Inc.</div></div>
<div><div style="border-bottom:1px solid #1a1a1a;height:32px;margin-bottom:4px"></div>
<div style="font-size:11px;color:#666;text-transform:uppercase;letter-spacing:0.6px">Date</div>
<div style="font-weight:600;margin-top:4px">{date}</div></div>
</div>
"#,
        hash = html_escape(&doc_hash_short),
        date = html_escape(&date_short),
    )
}

pub(in crate::report::html) fn write_fre_certification(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    if r.verdict == Verdict::InsufficientData {
        return Ok(());
    }

    let date_short = r.generated_at.format("%d %B %Y").to_string();
    let sk_short = if r.signing_key_fingerprint.len() >= 8 {
        &r.signing_key_fingerprint[..8]
    } else {
        &r.signing_key_fingerprint
    };

    write!(
        html,
        r#"<h2><span class="section-number">16.</span> Certificate of Cryptographic Proof</h2>
<div style="margin:12px 0;padding:16px;border:1px solid #1a1a1a;border-radius:4px">
<div style="font-size:11px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;color:#666;margin-bottom:8px">
Federal Rule of Evidence 902(13) Certification</div>
<p style="font-size:12px;line-height:1.6;text-align:justify">I, David Condrey, certify under
Federal Rule of Evidence 902(13) that the record annexed hereto as Report {report_id} was
produced by an electronic process or system that, when working properly, produces an accurate
result. The system is the WritersLogic CPoE Engine, version {version}, implementing the protocol
specified in Internet-Draft <code>draft-condrey-cpoe-protocol-00</code>. The system was operating
properly at the time the record was generated, as confirmed by successful verification of the
cryptographic chain.</p>
<p style="font-size:12px;line-height:1.6;text-align:justify">I further certify under Federal
Rule of Evidence 902(14) that the data referenced in this record were copied from an electronic
device or electronic file by a process of digital identification, namely SHA-256 hashing combined
with HMAC-SHA256 chain binding, and that the resulting digital identification matches the digital
identification stated in this report.</p>
</div>
<div style="margin:16px 0;padding:16px;border:2px solid #1a1a1a;border-radius:4px;background:#fafafa">
<div style="font-size:11px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:8px">
Declaration Under Penalty of Perjury · 28 U.S.C. § 1746</div>
<p style="font-size:12px;line-height:1.6;text-align:justify">I declare under penalty of perjury
under the laws of the United States of America that the foregoing is true and correct. Executed
on {date}, in the City of San Diego, State of California.</p>
</div>
<div style="margin-top:16px">
<p style="font-size:12px"><strong>Independent verification:</strong></p>
<ol style="font-size:12px;margin:8px 0 0 20px;line-height:1.6">
<li>Compute the SHA-256 digest of the subject document and compare against the digest in this report.</li>
<li>Obtain the sealed evidence bundle and replay the checkpoint chain using the open-source
<code>cpoe-engine</code> reference implementation.</li>
<li>Verify the COSE_Sign1 signature over the chain head against the Ed25519 public key bearing
fingerprint <code>{sk}</code>.</li>
<li>For escalation or dispute, contact <code>verify@writerslogic.com</code> citing this report identifier.</li>
</ol>
</div>
"#,
        report_id = html_escape(&r.report_id),
        version = html_escape(&r.algorithm_version),
        date = html_escape(&date_short),
        sk = html_escape(sk_short),
    )
}

pub(in crate::report::html) fn write_references(
    html: &mut String,
    r: &WarReport,
) -> fmt::Result {
    if r.verdict == Verdict::InsufficientData {
        return Ok(());
    }

    write!(
        html,
        r#"<h2><span class="section-number">17.</span> References</h2>
<ol style="font-size:12px;line-height:1.6;margin-left:20px">
<li>European Network of Forensic Science Institutes. <em>ENFSI Guideline for Evaluative Reporting
in Forensic Science.</em> ENFSI, March 2015.</li>
<li>National Institute of Standards and Technology. <em>FIPS PUB 180-4: Secure Hash Standard (SHS).</em>
NIST, August 2015.</li>
<li>Krawczyk, H., Bellare, M., and Canetti, R. <em>RFC 2104: HMAC: Keyed-Hashing for Message
Authentication.</em> IETF, February 1997.</li>
<li>Josefsson, S. and Liusvaara, I. <em>RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA).</em>
IETF, January 2017.</li>
<li>Lundblade, L. et al. <em>RFC 9711: The Entity Attestation Token (EAT).</em> IETF RATS WG,
October 2024.</li>
<li>Condrey, D. <em>Cryptographic Proof of Effort Protocol.</em> Internet-Draft
<code>draft-condrey-cpoe-protocol-00</code>, IETF, March 2026.</li>
<li>Boneh, D. et al. <em>Verifiable Delay Functions.</em> CRYPTO 2018, LNCS vol. 10991, Springer.</li>
<li>Condrey, D. <em>Calibration and Error-Rate Analysis of the CPoE Authorship Examination
Methodology.</em> WritersLogic Technical Report, 2026.</li>
<li>Federal Rules of Evidence, Rule 902(13) and 902(14).</li>
<li>28 U.S.C. § 1746: Unsworn declarations under penalty of perjury.</li>
<li><em>Daubert v. Merrell Dow Pharmaceuticals,</em> 509 U.S. 579 (1993); <em>Kumho Tire Co. v. Carmichael,</em>
526 U.S. 137 (1999).</li>
</ol>
"#,
    )
}

# Frequently Asked Questions

## General

### What is CPoE?
CPoE is a cryptographic authorship witnessing system. It creates a "Proof-of-Process" (PoP) — a tamper-evident record proving that you created a document over time through real effort, rather than generating it instantly or backdating it.

### Why would I need this?
It is used by writers, researchers, and developers to prove original authorship, protect intellectual property, and meet compliance requirements for "self-authenticating" electronic records.

### How is this different from Git or Dropbox?
While Git tracks changes, it doesn't prove *when* those changes happened (timestamps can be faked) or *how* they were created. CPoE uses **[[Glossary#VDF|Verifiable Delay Functions (VDFs)]]** to prove real-world time elapsed and **[[Behavioral Metrics|Behavioral Metrics]]** to prove human effort.

---

## Privacy & Security

### Does CPoE record what I type?
**No.** CPoE does NOT capture what you type, screen content, or clipboard data. It only records the *count* and *timing jitter* of keystrokes to prove human activity.

### Where is my data stored?
All data stays on your machine. CPoE is "offline-first." Nothing is sent to any server unless you choose to export and share an evidence packet. For a detailed breakdown of external interactions, see **[[Privacy & External Interactions]]**.

### What is in an evidence packet?
A `.c2pa` file contains content hashes, timing proofs, keystroke statistics, and your public cryptographic identity. It does NOT contain your document's text unless you explicitly choose to include it.

---

## Technical

### What is a VDF?
A Verifiable Delay Function is a math problem that takes a specific amount of time to solve and cannot be sped up by faster computers or parallel processing. It serves as a "cryptographic clock."

### What is the "Identity" in CPoE?
Your identity is an [[Glossary#Ed25519|Ed25519]] public key tied to your device's hardware (via [[Glossary#PUF|PUF]] or [[Glossary#TPM|TPM]]). This ensures that the evidence is linked to a specific author and device.

---

*For more details, see the **[[Glossary]]** or **[[Troubleshooting]]**.*

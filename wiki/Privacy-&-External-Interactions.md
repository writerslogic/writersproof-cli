# Privacy & External Interactions

CPoE is built on the principle of **computational privacy**. We believe that proving authorship should not require invasive surveillance or the surrender of your creative content to a third party.

---

## 🔒 Offline-First Architecture

By default, **CPoE is a strictly local application.**

*   **Keystroke Capture:** Keystroke counting and timing analysis happen entirely within the `cpoe` process memory.
*   **Content Hashing:** Document content is hashed locally. The raw text never leaves your device.
*   **Database:** Your history of creative effort is stored in a local, encrypted-at-rest SQLite database (`~/.writersproof/events.db`).
*   **Key Management:** Your cryptographic identity (private keys) is generated on-device and is never shared with our servers.

---

## 🌐 External Interactions

While core functionality is offline, CPoE interacts with **WritersProof** and **CPoE** domains to provide enhanced verification and attestation services.

### 1. Online Verification (`writerslogic.com/verify`)
The desktop applications generate links and QR codes that point to our verification portal.
*   **How it works:** When you open an evidence packet in this portal, the verification logic runs **locally in your browser** using WebAssembly.
*   **Privacy:** Your evidence packet (`.c2pa`) and document content are **never uploaded** to our servers. The portal acts as a "dumb" host for the verification scripts.

### 2. Cloud Attestation API (`writerslogic.com/api`)
For high-stakes evidence (Tiers 3 and 4), CPoE can leverage a cloud trust anchor.
*   **Anti-Replay Nonces:** The engine requests fresh cryptographic nonces to prove that evidence was created *now*, not replayed from the past.
*   **Remote Attestation:** If you request a cloud-signed certificate, the engine submits an evidence summary (hashes and metadata, not content) to receive a signature from the WritersProof root authority.
*   **Offline Queue:** Attestation requests are queued locally and only transmitted when you have an active internet connection.

### 3. Protocol & Identity (`protocol.writerslogic.com`)
This domain serves as the technical backbone for the **Proof-of-Process (PoP)** protocol.
*   **JSON Schemas:** Standardizes the format of evidence packets across different implementations.
*   **DID Resolution:** Provides lookup for author identities that have been optionally published to the decentralized registry.

### 4. Browser Extension Infrastructure
The browser extensions use `cpoe@writerslogic.com` as a unique identifier to communicate securely with the local `cpoe` daemon. This enables witnessing in web-based editors like Google Docs and Overleaf.

---

## Administrative & Support
We use `writerslogic.com` for the following administrative tasks:
*   **Licensing:** Commercial license inquiries and Contributor License Agreements (CLAs).
*   **Support:** Handling bug reports and feature requests via `support@writerslogic.com`.
*   **Security:** Reporting vulnerabilities to `security@writerslogic.com`.

---

## Conclusion
Our interaction with external domains is limited to **cryptographic synchronization** and **convenient verification tools**. At no point in the process does CPoE have access to the contents of your documents or your private creative environment.

*For more information, see our official [Privacy Policy](https://writerslogic.com/privacy).*

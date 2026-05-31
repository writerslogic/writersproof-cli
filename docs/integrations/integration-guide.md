# Vendor Integration Guide

**Version:** 1.0.0
**Status:** Stable
**Last Updated:** 2026-05-27

## Overview

CPoE is designed to be integrated into third-party applications (editors, IDEs, LMS platforms) to provide native authorship witnessing. This guide outlines the two primary integration paths: **Direct FFI** (preferred for native apps) and **IPC/CLI** (preferred for web or sandbox-constrained environments).

## 1. Direct FFI Integration (UniFFI)

The `cpoe_engine` crate exports a C-compatible FFI layer using **UniFFI**. This allows native apps (macOS/Swift, Windows/C#, Linux/Kotlin) to call the engine directly without the overhead of subprocesses.

### Available Bindings
- **Swift:** Bundled in `cpoe_macos` as `CPoEEngineFFI.xcframework`.
- **C# / WinUI:** Integrated via the `CPoECoreFFI.dll`.
- **Kotlin:** Generated bindings available for Linux desktop integrations.

### Key API Pattern
```swift
// Example: Creating a checkpoint from a native app
import CPoEEngineFFI

func performCheckpoint(path: String) {
    let result = ffiCreateCheckpoint(path: path, message: "Manual save")
    if result.success {
        print("Checkpoint created: \(result.message ?? "")")
    } else {
        handleError(result.errorMessage)
    }
}
```

## 2. IPC Integration (Daemon-Mode)

For web applications or sandboxed apps that cannot link native libraries, the `cpoe` daemon provides a local Unix Socket (or Named Pipe on Windows) for asynchronous communication.

- **Address:** `~/.writersproof/cpoe.sock` (Unix) or `\.\pipe\writerslogic` (Windows).
- **Format:** JSON-RPC over the socket.

### Lifecycle Management
Vendors should generally use the **Sentinel** to handle background capture:
1. `StartWitnessing(path)`: Tells the daemon to begin monitoring a specific file.
2. `StopWitnessing(path)`: Ends the capture session and flushes the WAL.

## 3. Web-App Integration (Browser Extension)

If you are a vendor building a web-based editor (e.g., Google Docs, Notion):
1. **Native Messaging:** Utilize the `writerslogic-native-messaging-host` to bridge your web app to the local daemon.
2. **PostMessage API:** The CPoE browser extension exposes a `window.postMessage` interface that web apps can use to signal "Save" or "Checkpoint" events without direct daemon access.

## 4. Best Practices for Vendors

### Do:
- **Call `calibrate` once:** Ensure the user's machine is calibrated for SWF proofs before starting their first session.
- **Trigger Checkpoints on Save:** While the sentinel auto-checkpoints, calling `checkpoint` manually on a user's "Save" action creates a semantic milestone in the evidence.
- **Use the Forensic Score:** Display the real-time Authorship Score in your UI to give users immediate feedback on their evidence integrity.

### Don't:
- **Don't store keys yourself:** Let the CPoE engine handle the Tier 0-2 key hierarchy and hardware binding.
- **Don't modify the data directory:** All integrity checks rely on the engine's ownership of `~/.writersproof`.

## 5. Security & Privacy Disclosure

When integrating CPoE, vendors should be aware of the following external domain interactions:

- **Local-First:** Core witnessing and authorship capture are strictly local and offline-first. Content never leaves the user's device.
- **Verification:** Verification of evidence packets typically occurs at `writerslogic.com/verify`, which uses a client-side (WASM) engine to maintain privacy.
- **Attestation:** Enhanced evidence (Tiers 3/4) periodically interacts with `writerslogic.com/api` for nonces and attestation certificates.

Vendors are encouraged to link to the **[[Privacy & External Interactions]]** page in their own documentation to provide transparency to users.

---

*For interpreting the resulting evidence, see [[Evidence Interpretation Guide]].*
